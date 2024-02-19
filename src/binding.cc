#include <node_api.h>
#include <pcap/pcap.h>
#include <windows.h>
#include <stdio.h>
#include <winsock2.h>

static void loadNpcap(napi_env env) {
    char path[MAX_PATH] = {0};

    if (GetSystemDirectoryA(path, MAX_PATH) == 0)
        napi_throw_error(env, NULL, "Failed to get the system directory.");

    strcat(path, "\\Npcap");

    if (SetDllDirectoryA(path) == 0)
        napi_throw_error(env, NULL, "Failed to set the NPCap directory.");

    if (LoadLibraryA("wpcap.dll") == 0)
        napi_throw_error(env, NULL, 
            "\n"
            "  ERROR! Failed to load 'wpcap.dll'\n"
            "  Have you installed the Npcap library? See https://npcap.com/#download\n"
            "\n"
        );

    // Notify Npcap version.
    printf("** %s\n", pcap_lib_version());
}

static void SetAddrStringHelper(napi_env env, napi_value addressObj, const char* key, sockaddr *addr) {
    if (addr == nullptr) return;

    char dst_addr[INET6_ADDRSTRLEN] = {0};
    const char* address = nullptr;

    if (addr->sa_family == AF_INET) {
        address = inet_ntop(AF_INET, &(((struct sockaddr_in*)addr)->sin_addr), dst_addr, INET_ADDRSTRLEN);
    } else {
        address = inet_ntop(AF_INET6, &(((struct sockaddr_in6*)addr)->sin6_addr), dst_addr, INET6_ADDRSTRLEN);
    }

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
    napi_status status;

    status = napi_create_string_utf8(env, pcap_lib_version(), NAPI_AUTO_LENGTH, &version);
    if (status != napi_ok) return nullptr;
    return version;
}

/**
 * @brief Retrieves a list of network devices along with their properties.
*/
napi_value deviceList(napi_env env, napi_callback_info info) {
    char error[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *alldevs, *cur_dev;

    if (pcap_findalldevs(&alldevs, error) == -1 || alldevs == NULL)
        napi_throw_error(env, NULL, error);

    napi_value list;
    if (napi_ok != napi_create_array(env, &list))
        napi_throw_error(env, NULL, "Failed to create array for deviceList.");
        
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

napi_value Init(napi_env env, napi_value exports) {
    loadNpcap(env);
    
    napi_value fnLibVersion, fnDeviceList;

    // libVersion
    if (napi_ok != napi_create_function(env, "libVersion", NAPI_AUTO_LENGTH, libVersion, NULL, &fnLibVersion)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "libVersion", fnLibVersion)) return NULL;

    // deviceList
    if (napi_ok != napi_create_function(env, "deviceList", NAPI_AUTO_LENGTH, deviceList, NULL, &fnDeviceList)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "deviceList", fnDeviceList)) return NULL;

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
