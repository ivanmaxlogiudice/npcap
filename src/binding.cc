#include <node_api.h>
#include <pcap/pcap.h>
#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <string>

#include "common.h"
#include "session.h"

static void loadNpcap(napi_env env) {
    char path[MAX_PATH] = {0};

    assert_message_void(env, GetSystemDirectoryA(path, MAX_PATH) != 0, "Failed to get the system directory.");

    strcat(path, "\\Npcap");

    assert_message_void(env, SetDllDirectoryA(path) != 0, "Failed to set the NPCap directory.");
    assert_message_void(
        env, 
        LoadLibraryA("wpcap.dll") != 0,
        "\n"
        "  ERROR! Failed to load 'wpcap.dll'\n"
        "  Have you installed the Npcap library? See https://npcap.com/#download\n"
        "\n"
    );
}

static const char* GetIpAddress(const struct sockaddr* addr) {
    char buffer[INET6_ADDRSTRLEN] = {0};
    const char* address = nullptr;

    switch (addr->sa_family) {
        case AF_INET:
            address = inet_ntop(AF_INET, &reinterpret_cast<const struct sockaddr_in *>(addr)->sin_addr, buffer, INET_ADDRSTRLEN);
            break;
        case AF_INET6:
            address = inet_ntop(AF_INET6, &reinterpret_cast<const struct sockaddr_in6 *>(addr)->sin6_addr, buffer, INET6_ADDRSTRLEN);
            break;
    }

    return address;
}

static void SetAddrStringHelper(napi_env env, napi_value addressObj, const char* key, sockaddr *addr) {
    if (addr == nullptr) return;

    const char* address = GetIpAddress(addr);

    if (address) {
        napi_value temp;
        napi_create_string_utf8(env, address, strlen(address), &temp);
        napi_set_named_property(env, addressObj, key, temp);
    }
}

/**
 * @brief Retrieves the version of the Npcap.
*/
napi_value libVersion(napi_env env, napi_callback_info info) {
    napi_value version;
    assert_call(env, napi_create_string_utf8(env, pcap_lib_version(), NAPI_AUTO_LENGTH, &version));

    return version;
}

/**
 * @brief Retrieves a list of network devices along with their properties.
*/
napi_value deviceList(napi_env env, napi_callback_info info) {
    char error[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *alldevs, *cur_dev;

    if (pcap_findalldevs(&alldevs, error) == -1) {
        napi_throw_error(env, NULL, error);
        return nullptr;
    }

    assert_message(env, alldevs != NULL, "Error: Unable to find any devices.");

    napi_value list;
    assert_call(env, napi_create_array(env, &list));
        
    int i = 0, j = 0;
    pcap_addr_t *cur_addr;
    for (cur_dev = alldevs ; cur_dev != NULL ; cur_dev = cur_dev->next, i++) {
        napi_value device;
        napi_create_object(env, &device);

        napi_value name, description, flags;
        napi_create_string_utf8(env, cur_dev->name, NAPI_AUTO_LENGTH, &name);
        napi_set_named_property(env, device, "name", name);

        napi_create_string_utf8(env, cur_dev->description, NAPI_AUTO_LENGTH, &description);
        napi_set_named_property(env, device, "description", description);

        {
            napi_value addresses;
            napi_create_array(env, &addresses);

            for (j = 0, cur_addr = cur_dev->addresses; cur_addr != NULL; cur_addr = cur_addr->next) {
                if (cur_addr->addr == nullptr) continue;

                int family = cur_addr->addr->sa_family;
                if (family == AF_INET || family == AF_INET6) {
                    napi_value address;
                    napi_create_object(env, &address);

                    SetAddrStringHelper(env, address, "addr", cur_addr->addr);
                    SetAddrStringHelper(env, address, "netmask", cur_addr->netmask);
                    SetAddrStringHelper(env, address, "broadaddr", cur_addr->broadaddr);
                    SetAddrStringHelper(env, address, "dstaddr", cur_addr->dstaddr);

                    napi_set_element(env, addresses, j++, address);
                }
            }

            napi_set_named_property(env, device, "addresses", addresses);
        }

        if (cur_dev->flags & PCAP_IF_LOOPBACK) {
            napi_get_boolean(env, true, &flags);
            napi_set_named_property(env, device, "loopback", flags);
        }

        napi_set_element(env, list, i, device);
    }

    pcap_freealldevs(alldevs);
    return list;
}

napi_value findDevice(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1], device;
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    assert_message(env, argc >= 1, "Invalid number of arguments. Must provide 1 argument." );

    napi_valuetype type;
    napi_typeof(env, args[0], &type);
    assert_message(env, napi_string == type, "The argument must be a string.");
    
    const char* ip = GetStringFromArg(env, args[0]);

    char error[PCAP_ERRBUF_SIZE] = {0}, name[INET6_ADDRSTRLEN] = {0};
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, error) == -1) {
        napi_throw_error(env, NULL, error);
        return nullptr;
    }

    assert_message(env, alldevs != NULL, "Error: Unable to find any devices.");

    bool found = false;
    pcap_if_t *cur_dev = nullptr;
    pcap_addr_t *cur_addr = nullptr;

    for (cur_dev = alldevs; cur_dev != nullptr; cur_dev = cur_dev->next) {
        if (cur_dev->addresses == nullptr) continue;

        for (cur_addr = cur_dev->addresses; cur_addr != nullptr; cur_addr = cur_addr->next) {
            if (cur_addr->addr == nullptr) continue;

            int family = cur_addr->addr->sa_family;
            if (family != AF_INET && family != AF_INET6) continue;

            const char *ipAddress = GetIpAddress(cur_addr->addr);
            if (strcmp(ip, ipAddress) != 0) continue;

            napi_create_string_utf8(env, cur_dev->name, strlen(cur_dev->name), &device);
            found = true;
            break;
        }

        if (found) break;
    }

    pcap_freealldevs(alldevs);
    return device;
}

napi_value Init(napi_env env, napi_value exports) {
    loadNpcap(env);

    Session::Init(env, exports);
    
    napi_value fnLibVersion, fnDeviceList, fnFindDevice;

    // libVersion
    if (napi_ok != napi_create_function(env, "libVersion", NAPI_AUTO_LENGTH, libVersion, NULL, &fnLibVersion)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "libVersion", fnLibVersion)) return NULL;

    // deviceList
    if (napi_ok != napi_create_function(env, "deviceList", NAPI_AUTO_LENGTH, deviceList, NULL, &fnDeviceList)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "deviceList", fnDeviceList)) return NULL;

    // findDevice
    if (napi_ok != napi_create_function(env, "findDevice", NAPI_AUTO_LENGTH, findDevice, NULL, &fnFindDevice)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "findDevice", fnFindDevice)) return NULL;

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
