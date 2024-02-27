#include <node_api.h>
#include <pcap/pcap.h>
#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <string>
#include <vector>

#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

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
        assert_call_void(env, napi_create_string_utf8(env, address, strlen(address), &temp));
        assert_call_void(env, napi_set_named_property(env, addressObj, key, temp));
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

    assert_message(env, pcap_findalldevs(&alldevs, error) != -1, error);
    assert_message(env, alldevs != NULL, "Error: Unable to find any devices.");

    napi_value list;
    assert_call(env, napi_create_array(env, &list));
        
    int i = 0, j = 0;
    pcap_addr_t *cur_addr;
    for (cur_dev = alldevs ; cur_dev != NULL ; cur_dev = cur_dev->next, i++) {
        napi_value device;
        assert_call(env, napi_create_object(env, &device));

        napi_value name, description, flags;
        assert_call(env, napi_create_string_utf8(env, cur_dev->name, NAPI_AUTO_LENGTH, &name));
        assert_call(env, napi_set_named_property(env, device, "name", name));

        assert_call(env, napi_create_string_utf8(env, cur_dev->description, NAPI_AUTO_LENGTH, &description));
        assert_call(env, napi_set_named_property(env, device, "description", description));

        {
            napi_value addresses;
            napi_create_array(env, &addresses);

            for (j = 0, cur_addr = cur_dev->addresses; cur_addr != NULL; cur_addr = cur_addr->next) {
                if (cur_addr->addr == nullptr) continue;

                int family = cur_addr->addr->sa_family;
                if (family == AF_INET || family == AF_INET6) {
                    napi_value address;
                    assert_call(env, napi_create_object(env, &address));

                    SetAddrStringHelper(env, address, "addr", cur_addr->addr);
                    SetAddrStringHelper(env, address, "netmask", cur_addr->netmask);
                    SetAddrStringHelper(env, address, "broadaddr", cur_addr->broadaddr);
                    SetAddrStringHelper(env, address, "dstaddr", cur_addr->dstaddr);

                    assert_call(env, napi_set_element(env, addresses, j++, address));
                }
            }

            assert_call(env, napi_set_named_property(env, device, "addresses", addresses));
        }

        if (cur_dev->flags & PCAP_IF_LOOPBACK) {
            assert_call(env, napi_get_boolean(env, true, &flags));
            assert_call(env, napi_set_named_property(env, device, "loopback", flags));
        }

        assert_call(env, napi_set_element(env, list, i, device));
    }

    pcap_freealldevs(alldevs);
    return list;
}

napi_value findDevice(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1], device;
    assert_call(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr));

    assert_message(env, argc >= 1, "Invalid number of arguments. Must provide 1 argument." );

    napi_valuetype type;
    assert_call(env, napi_typeof(env, args[0], &type));
    assert_message(env, napi_string == type, "The argument must be a string.");
    
    const char* ip = GetStringFromArg(env, args[0]);

    char error[PCAP_ERRBUF_SIZE] = {0}, name[INET6_ADDRSTRLEN] = {0};
    pcap_if_t *alldevs;

    assert_message(env, pcap_findalldevs(&alldevs, error) != -1, error);
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

            assert_call(env, napi_create_string_utf8(env, cur_dev->name, strlen(cur_dev->name), &device));
            found = true;
            break;
        }

        if (found) break;
    }

    pcap_freealldevs(alldevs);
    return device;
}

bool isValidAdapter(PIP_ADAPTER_ADDRESSES adapter) {
    if (adapter->OperStatus != IfOperStatusUp)
        return false;

    if (adapter->FirstGatewayAddress == nullptr)
        return false;

    PIP_ADAPTER_UNICAST_ADDRESS address = adapter->FirstUnicastAddress;
    while (address != nullptr) {
        if (address->Address.lpSockaddr->sa_family == AF_INET) {
            if (!(address->Flags & IP_ADAPTER_ADDRESS_DNS_ELIGIBLE) 
              || (address->Flags & IP_ADAPTER_ADDRESS_TRANSIENT))
                continue;

            return true;
        }

        address = address->Next;
    }

    return false;
}

char* convertWCharToChar(const wchar_t* wcharString) {
    // Determine the size of the required buffer
    size_t bufferSize = wcstombs(nullptr, wcharString, 0);
    
    // Allocate memory for the char* buffer
    char* charString = new char[bufferSize + 1]; // +1 for null terminator
    
    // Convert wchar_t* to char*
    wcstombs(charString, wcharString, bufferSize);
    
    // Null-terminate the char* string
    charString[bufferSize] = '\0';
    
    return charString;
}

napi_value defaultDevice(napi_env env, napi_callback_info info) {
    // Get the list of devices
    char error[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *devices, *dev;

    assert_message(env, pcap_findalldevs(&devices, error) != -1, error);
    assert_message(env, devices != NULL, "Error: Unable to find any devices.");
    
    // Get the list of adapters
    ULONG bufferLength = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferLength);

    std::vector<uint8_t> buffer(bufferLength);
    assert_message(
        env, 
        GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, 0, reinterpret_cast<IP_ADAPTER_ADDRESSES *>(&buffer[0]), &bufferLength) == ERROR_SUCCESS, 
        ""
    );

    PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&buffer[0]);
    for (auto pAddress = pAddresses; pAddress != nullptr; pAddress = pAddress->Next) {
        if (!isValidAdapter(pAddress)) continue;

        for (dev = devices ; dev != NULL ; dev = dev->next) {
            if (dev->addresses == NULL || (dev->flags & PCAP_IF_LOOPBACK))
                continue;
            
            printf("Device: %s in %s (%wS): %d\n", pAddress->AdapterName, dev->name, pAddress->FriendlyName, strstr(dev->name, convertWCharToChar(pAddress->FriendlyName)));
        }
    }

    pcap_freealldevs(devices);
    return nullptr;
}

napi_value Init(napi_env env, napi_value exports) {
    loadNpcap(env);

    Session::Init(env, exports);
    
    napi_value fnLibVersion, fnDeviceList, fnFindDevice, fnDefaultDevice;

    // libVersion
    if (napi_ok != napi_create_function(env, "libVersion", NAPI_AUTO_LENGTH, libVersion, NULL, &fnLibVersion)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "libVersion", fnLibVersion)) return NULL;

    // deviceList
    if (napi_ok != napi_create_function(env, "deviceList", NAPI_AUTO_LENGTH, deviceList, NULL, &fnDeviceList)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "deviceList", fnDeviceList)) return NULL;

    // findDevice
    if (napi_ok != napi_create_function(env, "findDevice", NAPI_AUTO_LENGTH, findDevice, NULL, &fnFindDevice)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "findDevice", fnFindDevice)) return NULL;

    // defaultDevice
    if (napi_ok != napi_create_function(env, "defaultDevice", NAPI_AUTO_LENGTH, defaultDevice, NULL, &fnDefaultDevice)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "defaultDevice", fnDefaultDevice)) return NULL;

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
