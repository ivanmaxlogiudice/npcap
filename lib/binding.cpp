#include "common.h"
#include "session.h"

#if defined(__unix__)
#include <dlfcn.h>
#endif

#if defined(_WIN32)
#include <vector>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

#if defined(_WIN32)
void loadNpcap(napi_env env) {

    char path[MAX_PATH] = {0};
   
    ASSERT_MESSAGE_VOID(env, GetSystemDirectoryA(path, MAX_PATH) != 0, "Failed to get the system directory.");

    strcat(path, "\\Npcap");

    ASSERT_MESSAGE_VOID(env, SetDllDirectoryA(path) != 0, "Failed to set the NPCap directory.");
    ASSERT_MESSAGE_VOID(
        env, 
        LoadLibraryA("wpcap.dll") != 0,
        "\n"
        "  ERROR! Failed to load 'wpcap.dll'\n"
        "  Have you installed the Npcap library? See https://npcap.com/#download\n"
        "\n"
    );
}

bool isValidAdapter(PIP_ADAPTER_ADDRESSES adapter) {
    if (adapter->OperStatus != IfOperStatusUp || adapter->FirstGatewayAddress == nullptr)
        return false;

    for (auto address = adapter->FirstUnicastAddress; address != nullptr; address = address->Next) {
        if (!(address->Flags & IP_ADAPTER_ADDRESS_DNS_ELIGIBLE) || (address->Flags & IP_ADAPTER_ADDRESS_TRANSIENT))
                continue;
        
        if (address->Address.lpSockaddr->sa_family == AF_INET)
            return true;
    }

    return false;
}
#else
void loadNpcap(napi_env env) {
    void* handle = dlopen("libpcap.so", RTLD_LAZY);
    if (handle) {
        dlclose(handle);
        return;
    }

    ASSERT_CALL_VOID(env, napi_throw_error(env, nullptr, 
        "\n"
        "  ERROR! Failed to load 'libpcap.so'\n"
        "  Have you installed the library? sudo apt install libpcap-dev\n" // Need to install libpcap-dev??
        "\n"
    ))
}

bool isValidDevice(pcap_if_t* device) {
    if (device->addresses == NULL || (device->flags & PCAP_IF_LOOPBACK))
        return false;

    for (auto addr = device->addresses; addr != nullptr; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET) {
            return true;
        }
    }

    return false;
}
#endif

const char* GetIpAddress(const struct sockaddr* addr) {
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

void SetAddrStringHelper(napi_env env, napi_value addressObj, const char* key, sockaddr *addr) {
    if (addr == nullptr) return;

    const char* address = GetIpAddress(addr);

    if (address) {
        napi_value temp;
        ASSERT_CALL_VOID(env, napi_create_string_utf8(env, address, strlen(address), &temp));
        ASSERT_CALL_VOID(env, napi_set_named_property(env, addressObj, key, temp));
    }
}

/**
 * @brief Retrieves the version of the Npcap.
*/
napi_value libVersion(napi_env env, napi_callback_info info) {
    napi_value version;
    ASSERT_CALL(env, napi_create_string_utf8(env, pcap_lib_version(), NAPI_AUTO_LENGTH, &version));

    return version;
}

/**
 * @brief Retrieves a list of network devices along with their properties.
*/
napi_value deviceList(napi_env env, napi_callback_info info) {
    char error[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *alldevs, *cur_dev;

    ASSERT_MESSAGE(env, pcap_findalldevs(&alldevs, error) != -1, error);
    ASSERT_MESSAGE(env, alldevs != NULL, "Error: Unable to find any devices.");

    napi_value list;
    ASSERT_CALL(env, napi_create_array(env, &list));
        
    int i = 0, j = 0;
    pcap_addr_t *cur_addr;
    for (cur_dev = alldevs ; cur_dev != NULL ; cur_dev = cur_dev->next, i++) {
        napi_value device;
        ASSERT_CALL(env, napi_create_object(env, &device));

        napi_value name, description, flags;
        ASSERT_CALL(env, napi_create_string_utf8(env, cur_dev->name, NAPI_AUTO_LENGTH, &name));
        ASSERT_CALL(env, napi_set_named_property(env, device, "name", name));

        if (cur_dev->description != nullptr) {
            ASSERT_CALL(env, napi_create_string_utf8(env, cur_dev->description, NAPI_AUTO_LENGTH, &description));
            ASSERT_CALL(env, napi_set_named_property(env, device, "description", description));
        }

        {
            napi_value addresses;
            napi_create_array(env, &addresses);

            for (j = 0, cur_addr = cur_dev->addresses; cur_addr != NULL; cur_addr = cur_addr->next) {
                if (cur_addr->addr == nullptr) continue;

                int family = cur_addr->addr->sa_family;
                if (family == AF_INET || family == AF_INET6) {
                    napi_value address;
                    ASSERT_CALL(env, napi_create_object(env, &address));

                    SetAddrStringHelper(env, address, "addr", cur_addr->addr);
                    SetAddrStringHelper(env, address, "netmask", cur_addr->netmask);
                    SetAddrStringHelper(env, address, "broadaddr", cur_addr->broadaddr);
                    SetAddrStringHelper(env, address, "dstaddr", cur_addr->dstaddr);

                    ASSERT_CALL(env, napi_set_element(env, addresses, j++, address));
                }
            }

            ASSERT_CALL(env, napi_set_named_property(env, device, "addresses", addresses));
        }

        if (cur_dev->flags & PCAP_IF_LOOPBACK) {
            ASSERT_CALL(env, napi_get_boolean(env, true, &flags));
            ASSERT_CALL(env, napi_set_named_property(env, device, "loopback", flags));
        }

        ASSERT_CALL(env, napi_set_element(env, list, i, device));
    }

    pcap_freealldevs(alldevs);
    return list;
}

napi_value findDevice(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1], device;
    ASSERT_CALL(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr));

    ASSERT_MESSAGE(env, argc >= 1, "Invalid number of arguments. Must provide 1 argument." );

    napi_valuetype type;
    ASSERT_CALL(env, napi_typeof(env, args[0], &type));
    ASSERT_MESSAGE(env, napi_string == type, "The argument must be a string.");
    
    std::string ip = GetStringFromArg(env, args[0]);

    char error[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *alldevs;

    ASSERT_MESSAGE(env, pcap_findalldevs(&alldevs, error) != -1, error);
    ASSERT_MESSAGE(env, alldevs != NULL, "Error: Unable to find any devices.");

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
            if (strcmp(ip.c_str(), ipAddress) != 0) continue;

            ASSERT_CALL(env, napi_create_string_utf8(env, cur_dev->name, strlen(cur_dev->name), &device));
            found = true;
            break;
        }

        if (found) break;
    }

    pcap_freealldevs(alldevs);
    return device;
}

napi_value defaultDevice(napi_env env, napi_callback_info info) {
    // Get devices list
    char error[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *devices;

    ASSERT_MESSAGE(env, pcap_findalldevs(&devices, error) != -1, error);
    ASSERT_MESSAGE(env, devices != NULL, "Error: Unable to find any devices.");

    napi_value defaultDevice = nullptr;

#if defined(_WIN32)
    // Get the list of adapters
    ULONG bufferLength = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, nullptr, nullptr, &bufferLength);

    std::vector<uint8_t> buffer(bufferLength);
    ASSERT_MESSAGE(env, 
        GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX, 0, reinterpret_cast<IP_ADAPTER_ADDRESSES *>(&buffer[0]), &bufferLength) == ERROR_SUCCESS, 
        "Failed to get network interfaces with GetAdaptersAddresses"
    );

    bool found = false;
    auto addresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(&buffer[0]);
    for (auto address = addresses; address != nullptr; address = address->Next) {
        if (!isValidAdapter(address)) continue;

        // Find the device that match with the adapter.
        for (auto dev = devices; dev != nullptr; dev = dev->next) {
            if (dev->addresses == NULL || (dev->flags & PCAP_IF_LOOPBACK))
                continue;

            char* adapterName = static_cast<char*>(address->AdapterName);
            if (strstr(dev->name, adapterName) != nullptr) {
                ASSERT_CALL(env, napi_create_string_utf8(env, dev->name, NAPI_AUTO_LENGTH, &defaultDevice));
                found = true;
                break;
            }
        }

        if (found) break;
    }
#else
    // Search the first device that is not a loopback and has addresses.
    for (auto dev = devices; dev != NULL ; dev = dev->next) {
        if (!isValidDevice(dev)) continue;

        ASSERT_CALL(env, napi_create_string_utf8(env, dev->name, strlen(dev->name), &defaultDevice));
        break;
    }
#endif

    pcap_freealldevs(devices);
    return defaultDevice;
}

napi_value Init(napi_env env, napi_value exports) {   
    loadNpcap(env);

    Session::Init(env, exports);
    
    napi_value fn;

    // libVersion
    if (napi_ok != napi_create_function(env, "libVersion", NAPI_AUTO_LENGTH, libVersion, NULL, &fn)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "libVersion", fn)) return NULL;

    // deviceList
    if (napi_ok != napi_create_function(env, "deviceList", NAPI_AUTO_LENGTH, deviceList, NULL, &fn)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "deviceList", fn)) return NULL;

    // findDevice
    if (napi_ok != napi_create_function(env, "findDevice", NAPI_AUTO_LENGTH, findDevice, NULL, &fn)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "findDevice", fn)) return NULL;

    // findDevice
    if (napi_ok != napi_create_function(env, "defaultDevice", NAPI_AUTO_LENGTH, defaultDevice, NULL, &fn)) return NULL;
    if (napi_ok != napi_set_named_property(env, exports, "defaultDevice", fn)) return NULL;

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
