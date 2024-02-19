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

napi_value libVersion(napi_env env, napi_callback_info info) {
    napi_value version;
    napi_status status;

    status = napi_create_string_utf8(env, pcap_lib_version(), NAPI_AUTO_LENGTH, &version);
    if (status != napi_ok) return nullptr;
    return version;
}

napi_value deviceList(napi_env env, napi_callback_info info) {
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *cur_dev;

    if (pcap_findalldevs(&alldevs, error) == -1 || alldevs == NULL)
        napi_throw_error(env, NULL, error);

    napi_value list;
    if (napi_ok != napi_create_array(env, &list))
        napi_throw_error(env, NULL, "Failed to create array for deviceList.");
        
    int i = 0, j = 0;
    for (cur_dev = alldevs ; cur_dev != NULL ; cur_dev = cur_dev->next, i++) {
        napi_value device;
        napi_create_object(env, &device);

        napi_value name, description, flags;
        napi_create_string_utf8(env, cur_dev->name, NAPI_AUTO_LENGTH, &name);
        napi_set_named_property(env, device, "name", name);

        napi_create_string_utf8(env, cur_dev->description, NAPI_AUTO_LENGTH, &description);
        napi_set_named_property(env, device, "description", description);

        // Addresses
        {
            napi_value addresses;
            napi_create_array(env, &addresses);

            for (struct pcap_addr *addr = cur_dev->addresses; addr != NULL; addr = addr->next) {
                napi_value address;
                napi_create_object(env, &address);

                // Add address family
                napi_value family;
                napi_create_int32(env, addr->addr->sa_family, &family);
                napi_set_named_property(env, address, "family", family);

                // Add address (you need to handle IPv4 and IPv6 addresses accordingly)
                // For simplicity, let's assume you have IPv4 addresses
                char ipAddr[INET_ADDRSTRLEN];
                if (addr->addr->sa_family == AF_INET) {
                    inet_ntop(AF_INET, &(((struct sockaddr_in *)addr->addr)->sin_addr), ipAddr, INET_ADDRSTRLEN);
                    napi_value ip;
                    napi_create_string_utf8(env, ipAddr, NAPI_AUTO_LENGTH, &ip);
                    napi_set_named_property(env, address, "ip", ip);
                }

                // Push the address object into the addresses array
                napi_set_element(env, addresses, j++, address);
            }

            napi_set_named_property(env, device, "addresses", addresses);
        }

        napi_create_uint32(env, cur_dev->flags, &flags);
        napi_set_named_property(env, device, "flags", flags);

        napi_set_element(env, list, i, device);
    }

    return list;
}

napi_value bench(napi_env env, napi_callback_info info) {
    napi_value array;
    napi_create_array(env, &array);

    napi_value foo, bar, hi;
    napi_create_string_utf8(env, "foo", NAPI_AUTO_LENGTH, &foo);
    napi_create_string_utf8(env, "bar", NAPI_AUTO_LENGTH, &bar);
    napi_create_string_utf8(env, "hi", NAPI_AUTO_LENGTH, &hi);

    napi_value obj;
    napi_create_object(env, &obj);
        
    for (int i = 0; i < 100000; i++) {
        napi_set_named_property(env, obj, "foo", foo);
        napi_set_named_property(env, obj, "bar", bar);
        napi_set_named_property(env, obj, "hi", hi);

        napi_set_element(env, array, i, obj);
    }

    return NULL;
}

napi_value Init(napi_env env, napi_value exports) {
    loadNpcap(env);
    
    napi_value fnLibVersion, fnDeviceList, fnBench;

    // libVersion(): string
    if (napi_ok != napi_create_function(env, "libVersion", NAPI_AUTO_LENGTH, libVersion, NULL, &fnLibVersion)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "libVersion", fnLibVersion)) return NULL;

    // deviceList(): ??
    if (napi_ok != napi_create_function(env, "deviceList", NAPI_AUTO_LENGTH, deviceList, NULL, &fnDeviceList)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "deviceList", fnDeviceList)) return NULL;

    if (napi_ok != napi_create_function(env, "bench", NAPI_AUTO_LENGTH, bench, NULL, &fnBench)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "bench", fnBench)) return NULL;

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
