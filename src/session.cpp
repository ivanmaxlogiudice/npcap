#include <pcap.h>

#include "session.h"
#include "common.h"

napi_value Session::Init(napi_env env, napi_value exports) {
    napi_property_descriptor properties[] = {
        DECLARE_METHOD("openLive", OpenLive),
        DECLARE_METHOD("openOffline", OpenOffline),
        DECLARE_METHOD("stats", Stats),
        DECLARE_METHOD("inject", Inject),
        DECLARE_METHOD("close", Close)
    };
    
    napi_value cons;
    ASSERT_CALL(env, napi_define_class(env, "session", NAPI_AUTO_LENGTH, New, NULL, sizeof(properties) / sizeof(properties[0]), properties, &cons));

    /**
     * We will need the constructor `cons` later during the life cycle of the session,
     * so we store a persistent reference to it as the instance data.
     * 
     * This will enable us to use `napi_get_instance_data` at any point during the
     * life cycle of our session and retrieve it.
     * 
     * We cannot simply store it as a global static variable, because that will render
     * our addon unable to support Node.js worker threads and multiple contexts on a
     * single thread.
    */
    napi_ref* constructor;
    ASSERT_CALL(env, napi_create_reference(env, cons, 1, constructor));
    ASSERT_CALL(env, napi_set_instance_data(env, constructor, [](napi_env env, void* data, void* hint) {
        napi_ref* constructor = static_cast<napi_ref*>(data);
        napi_delete_reference(env, *constructor);
        delete constructor;
    }, nullptr));

    ASSERT_CALL(env, napi_set_named_property(env, exports, "Session", cons));
    return exports;
}

Session::Session(): env_(nullptr), wrapper_(nullptr) {
    pcapHandle = nullptr;
    pcapDumpHandle = nullptr;

    onPacketRef = nullptr;

    headerData = nullptr;
    bufferData = nullptr;
    bufferLength = 0;

    closing = false;
    handlingPackets = false;

#if defined(_WIN32)
    pollWait = nullptr;
#endif
}

Session::~Session() {
    ASSERT_CALL_VOID(env_, napi_delete_reference(env_, wrapper_));
    ASSERT_CALL_VOID(env_, napi_delete_reference(env_, onPacketRef));
}

napi_value Session::New(napi_env env, napi_callback_info info) {
    napi_value target;
    ASSERT_CALL(env, napi_get_new_target(env, info, &target));

    if (target == nullptr) {
        // Invoked as plain function `Session(...)`, turn it into a constructor call.
        napi_value instance;
        ASSERT_CALL(env, napi_new_instance(env, Constructor(env), 0, 0, &instance));

        return instance;
    }

    // Invoked as constructor `new Session(...)`
    ASSERT_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &target, nullptr));

    auto session = new Session();
    session->env_ = env;
    
    napi_wrap(env, target, reinterpret_cast<void*>(session), Session::Destructor, nullptr, &session->wrapper_);
    return target;
}

napi_value Session::Constructor(napi_env env) {
    void* data = nullptr;
    ASSERT_CALL(env, napi_get_instance_data(env, &data));

    napi_value cons;
    ASSERT_CALL(env, napi_get_reference_value(env, reinterpret_cast<napi_ref>(data), &cons));
    return cons;
}

void Session::Destructor(napi_env env, void* nativeObject, void* /* finalizeHint */) {
    reinterpret_cast<Session*>(nativeObject)->~Session();
}

napi_value Session::Open(napi_env env, napi_callback_info info, bool live) {
    size_t argc = 12;
    napi_value argv[12], thisArg;
    ASSERT_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, nullptr));

    // Verifiy arguments
    napi_valuetype type;
    
    // argv[0]: { device: string }
    ASSERT_CALL(env, napi_typeof(env, argv[0], &type));
    ASSERT_MESSAGE(env, type == napi_string, "The argument `device` must be a String.");

    // argv[1]: { onPacket: (buffer: Buffer) => void }
    ASSERT_CALL(env, napi_typeof(env, argv[1], &type));
    ASSERT_MESSAGE(env, type == napi_function, "The argument `onPacket` must be a Function (like: (buffer: Buffer) => void).");

    // argv[2]: { filter: string }
    ASSERT_CALL(env, napi_typeof(env, argv[2], &type));
    ASSERT_MESSAGE(env, type == napi_string, "The argument `filter` must be a String.");

    // argv[3]: { bufferSize: number }
    ASSERT_CALL(env, napi_typeof(env, argv[3], &type));
    ASSERT_MESSAGE(env, type == napi_number, "The argument `bufferSize` must be a Number.");

    // argv[4]: { header: Buffer }
    bool isBuffer;
    ASSERT_CALL(env, napi_is_buffer(env, argv[4], &isBuffer));
    ASSERT_MESSAGE(env, isBuffer == true, "The parameter `header` must be a Buffer.");

    // argv[5]: { buffer: Buffer}
    ASSERT_CALL(env, napi_is_buffer(env, argv[5], &isBuffer));
    ASSERT_MESSAGE(env, isBuffer == true, "The parameter `buffer` must be a Buffer.");

    // argv[6]: { snapLen: number }
    napi_typeof(env, argv[6], &type);
    ASSERT_MESSAGE(env, type == napi_number, "The argument `snapLen` must be a Number.");

    // argv[7]: { outFile: string }
    ASSERT_CALL(env, napi_typeof(env, argv[7], &type));
    ASSERT_MESSAGE(env, type == napi_string, "The argument `outFile` must be a String.");

    // argv[8]: { monitor: boolean }
    ASSERT_CALL(env, napi_typeof(env, argv[8], &type));
    ASSERT_MESSAGE(env, type == napi_boolean, "The argument `monitor` must be a Boolean.");

    // argv[9]: { timeout: number }
    ASSERT_CALL(env, napi_typeof(env, argv[9], &type));
    ASSERT_MESSAGE(env, type == napi_number, "The argument `timeout` must be a Number.");

    // argv[10]: { warningHandler: (message: string) => void  }
    ASSERT_CALL(env, napi_typeof(env, argv[10], &type));
    ASSERT_MESSAGE(env, type == napi_function, "The argument `warningHandler` must be a Function `(message: string) => void`.");

    // argv[11]: { promiscuous: boolean }
    ASSERT_CALL(env, napi_typeof(env, argv[11], &type));
    ASSERT_MESSAGE(env, type == napi_boolean, "The argument `promiscuous` must be a Boolean.");

    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    ASSERT_CALL(env, napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)));

    // Close previously open session.
    if (session->pcapHandle != nullptr)
        session->Close(env, info);

    // Get the header & buffer.
    ASSERT_CALL(env, napi_get_buffer_info(env, argv[4], reinterpret_cast<void**>(&session->headerData), nullptr));
    ASSERT_CALL(env, napi_get_buffer_info(env, argv[5], reinterpret_cast<void**>(&session->bufferData), &session->bufferLength));

    auto device = GetStringFromArg(env, argv[0]);
    auto filter = GetStringFromArg(env, argv[2]);
    auto snapLen = GetNumberFromArg(env, argv[6]);
    auto outFile = GetStringFromArg(env, argv[7]);
    auto timeout = GetNumberFromArg(env, argv[9]);

    char errorBuffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    if (live) {
        if (pcap_lookupnet(device, &net, &mask, errorBuffer) == -1) {
            net = 0;
            mask = 0;

            napi_value errorMessage, result;
            ASSERT_CALL(env, napi_create_string_utf8(env, errorBuffer, strlen(errorBuffer), &errorMessage));
            ASSERT_CALL(env, napi_call_function(env, argv[10], argv[10], 1, &errorMessage, &result)); // TODO: Test this, if crash use napi_get_global and replace second argument.
        }

        session->pcapHandle = pcap_create(device, errorBuffer);
        ASSERT_MESSAGE(env, session->pcapHandle != nullptr, errorBuffer);

        // 64KB is the max IPv4 packet size
        ASSERT_MESSAGE(env, pcap_set_snaplen(session->pcapHandle, 1) == 0, "Error with the setting 'snapLen'.");

        // promiscuous?
        if (GetBooleanFromArg(env, argv[11])) {
            ASSERT_MESSAGE(env, pcap_set_promisc(session->pcapHandle, 1) == 0, "Can't set promiscuous mode.");
        }

        ASSERT_MESSAGE(env, pcap_set_buffer_size(session->pcapHandle, GetNumberFromArg(env, argv[3])) == 0, "Can't set the bufferSize.");

        if (timeout > 0) {
            // set "timeout" on read, even though we are also setting nonblock below. On Linux this is required.
            ASSERT_MESSAGE(env, pcap_set_timeout(session->pcapHandle, timeout) == 0, "Can't set the read timeout.");
        }

        // timeout <= 0 is undefined behaviour, we'll set immediate mode instead. (timeout is ignored in immediate mode)
        ASSERT_MESSAGE(env, pcap_set_immediate_mode(session->pcapHandle, (timeout <= 0)) == 0, "Can't set the immediate mode.");

        // Monitor?
        if (GetBooleanFromArg(env, argv[8])) {
            ASSERT_MESSAGE(env, pcap_set_rfmon(session->pcapHandle, 1) == 0, pcap_geterr(session->pcapHandle));
        }

        ASSERT_MESSAGE(env, pcap_activate(session->pcapHandle) == 0, pcap_geterr(session->pcapHandle));

        if (strlen(outFile) > 0) {
            session->pcapDumpHandle = pcap_dump_open(session->pcapHandle, outFile);
            ASSERT_MESSAGE(env, session->pcapDumpHandle != nullptr, "Can't open output dump file.");
        }

        ASSERT_MESSAGE(env, pcap_setnonblock(session->pcapHandle, 1, errorBuffer) != -1, errorBuffer);
    } else {
        // Device is the path to the savefile
        session->pcapHandle = pcap_open_offline(device, errorBuffer);
        ASSERT_MESSAGE(env, session->pcapHandle != nullptr, errorBuffer);
    }

    if (strlen(filter) > 0) {
        struct bpf_program fp;

        ASSERT_MESSAGE(env, pcap_compile(session->pcapHandle, &fp, filter, 1, net) != -1, pcap_geterr(session->pcapHandle));
        ASSERT_MESSAGE(env, pcap_setfilter(session->pcapHandle, &fp) != -1, pcap_geterr(session->pcapHandle));

        pcap_freecode(&fp);
    }

    int linkType = pcap_datalink(session->pcapHandle);
    napi_value returnValue;

    switch (linkType) {
        case DLT_NULL:
            ASSERT_CALL(env, napi_create_string_utf8(env, "LINKTYPE_NULL", NAPI_AUTO_LENGTH, &returnValue));
            break;
        case DLT_EN10MB: // Most wifi interfaces pretend to be "ethernet"
            ASSERT_CALL(env, napi_create_string_utf8(env, "LINKTYPE_ETHERNET", NAPI_AUTO_LENGTH, &returnValue));
            break;
        case DLT_IEEE802_11_RADIO: // 802.11 "monitor mode"
            ASSERT_CALL(env, napi_create_string_utf8(env, "LINKTYPE_IEEE802_11_RADIO", NAPI_AUTO_LENGTH, &returnValue));
            break;
        case DLT_RAW: // "raw IP"
            ASSERT_CALL(env, napi_create_string_utf8(env, "LINKTYPE_RAW", NAPI_AUTO_LENGTH, &returnValue));
            break;
        case DLT_LINUX_SLL:
            ASSERT_CALL(env, napi_create_string_utf8(env, "LINKTYPE_LINUX_SLL", NAPI_AUTO_LENGTH, &returnValue));
            break;
        default:
            char errorBuffer[PCAP_ERRBUF_SIZE];
            snprintf(errorBuffer, PCAP_ERRBUF_SIZE, "Unknown linktype %d", linkType);
            ASSERT_CALL(env, napi_create_string_utf8(env, errorBuffer, NAPI_AUTO_LENGTH, &returnValue));
            break;
    }

    // Create a reference to the onPacket function
    ASSERT_CALL(env, napi_create_reference(env, argv[1], 1, &session->onPacketRef));

#if defined(_WIN32)
    ASSERT(env, uv_async_init(uv_default_loop(), &session->pollAsync, (uv_async_cb) CallbackPacket) == 0);
    session->pollAsync.data = session;

    if (!RegisterWaitForSingleObject(
        &session->pollWait,
        pcap_getevent(session->pcapHandle),
        OnPacket,
        &session->pollAsync,
        INFINITE,
        WT_EXECUTEINWAITTHREAD
    )) {
        char* errorMessage = nullptr;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            GetLastError(),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&errorMessage,
            0,
            nullptr
        );

        ASSERT_CALL(env, napi_throw_error(env, nullptr, errorMessage));
        return nullptr;
    }
#else
    session->fd = pcap_get_selectable_fd(session->pcapHandle);
    ASSERT(env, uv_poll_init(uv_default_loop(), &session->pollHandle, session->fd) == 0);
    ASSERT(env, uv_poll_start(&session->pollHandle, UV_READABLE, CallbackPacket) == 0);
    session->pollHandle.data = session;
#endif

    return returnValue;
}

napi_value Session::OpenLive(napi_env env, napi_callback_info info) {
    return Open(env, info, true);
}

napi_value Session::OpenOffline(napi_env env, napi_callback_info info) {
    return Open(env, info, false);
}

napi_value Session::Stats(napi_env env, napi_callback_info info) {
    napi_value thisArg;
    ASSERT_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, nullptr));

    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    ASSERT_CALL(env, napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)));
    ASSERT_MESSAGE(env, session->pcapHandle != nullptr, "The Session is closed.");

    struct pcap_stat ps;
    ASSERT_MESSAGE(env, pcap_stats(session->pcapHandle, &ps) != 1, pcap_geterr(session->pcapHandle));

    napi_value stats, value;
    ASSERT_CALL(env, napi_create_object(env, &stats));

    ASSERT_CALL(env, napi_create_int32(env, ps.ps_recv, &value));
    ASSERT_CALL(env, napi_set_named_property(env, stats, "ps_recv", value));

    ASSERT_CALL(env, napi_create_int32(env, ps.ps_drop, &value));
    ASSERT_CALL(env, napi_set_named_property(env, stats, "ps_drop", value));

    ASSERT_CALL(env, napi_create_int32(env, ps.ps_ifdrop, &value));
    ASSERT_CALL(env, napi_set_named_property(env, stats, "ps_ifdrop", value));

    return stats;
}

napi_value Session::Inject(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1], thisArg;

    ASSERT_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, nullptr));
    ASSERT_MESSAGE(env, argc == 1, "Expecting 1 argument.");

    bool isBuffer;
    ASSERT_CALL(env, napi_is_buffer(env, argv[0], &isBuffer));
    ASSERT_MESSAGE(env, isBuffer == true, "The parameter `data` must be a Buffer.");

    Session* session;
    ASSERT_CALL(env, napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)));
    ASSERT_MESSAGE(env, session->pcapHandle != nullptr, "The Session is closed.");

    char* bufferData = nullptr;
    size_t bufferLength = 0;
    ASSERT_CALL(env, napi_get_buffer_info(env, argv[0], reinterpret_cast<void**>(&bufferData), &bufferLength));
    ASSERT_MESSAGE(env, bufferLength > 0, "The buffer `data` can't be empty.");

    ASSERT_MESSAGE(env, pcap_inject(session->pcapHandle, bufferData, bufferLength) == (int)(bufferLength), pcap_geterr(session->pcapHandle));
    return ReturnBoolean(env, true);
}

napi_value Session::Close(napi_env env, napi_callback_info info) {
    napi_value thisArg;
    ASSERT_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, nullptr));

    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    ASSERT_CALL(env, napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)));

    if (session->pcapHandle && !session->closing) {
        if (session->pcapDumpHandle != nullptr) {
            pcap_dump_close(session->pcapDumpHandle);
            session->pcapDumpHandle = nullptr;
        }

#if defined(_WIN32)
        if (session->pollWait) {
            UnregisterWait(session->pollWait);
            session->pollWait = nullptr;
        }

        uv_close(reinterpret_cast<uv_handle_t*>(&session->pollAsync), CallbackClose);
#endif

        session->closing = true;
        session->Cleanup();

        return ReturnBoolean(env, true);
    }

    return ReturnBoolean(env, false);
}

void Session::Cleanup() {
    if (pcapHandle && !handlingPackets) {
        pcap_close(pcapHandle);
        
        pcapHandle = nullptr;

        headerData = nullptr;
        bufferData = nullptr;
        bufferLength = 0;
    }
}

#if defined(_WIN32)
void Session::CallbackPacket(uv_async_t* handle) {
    auto session = reinterpret_cast<Session*>(handle->data);

    if (session->closing)
        return session->Cleanup();

    session->handlingPackets = true;

    int packetCount;
    do {
        packetCount = pcap_dispatch(
            session->pcapHandle,
            1,
            Session::EmitPacket,
            reinterpret_cast<u_char*>(session)
        );
    } while (packetCount > 0 && !session->closing);

    session->handlingPackets = false;

    if (session->closing)
        session->Cleanup();
}


void Session::OnPacket(void* data, boolean didTimeout) {
    auto session = reinterpret_cast<Session*>(data);

    ASSERT_VOID(session->env_, !didTimeout);
    int response = uv_async_send(reinterpret_cast<uv_async_t*>(data));
    ASSERT_VOID(session->env_, response == 0);
}

void Session::CallbackClose(uv_handle_t* handle) {
    
}
#else
void Session::CallbackPacket(uv_poll_t* handle, int status, int events) {
    auto session = reinterpret_cast<Session*>(handle->data);
    ASSERT_VOID(session->env_, status == 0);

    if (session->closing)
        return session->Cleanup();

    if (!(events & UV_READABLE))
        return
    
    session->handlingPackets = true;

    int packetCount;
    do {
        packetCount = pcap_dispatch(
            session->pcapHandle,
            1,
            Session::EmitPacket,
            reinterpret_cast<u_char*>(session)
        );
    } while (packetCount > 0 && !session->closing);

    session->handlingPackets = false;

    if (session->closing)
        session->Cleanup();
}
#endif

void Session::EmitPacket(u_char *s, const struct pcap_pkthdr* pkt_hdr, const u_char* packet) {
    auto session = reinterpret_cast<Session*>(s);

    if (session->pcapDumpHandle != nullptr) {
        pcap_dump(reinterpret_cast<u_char*>(session->pcapDumpHandle), pkt_hdr, packet);
    }

    bool truncated = false;
    size_t copyLen = pkt_hdr->caplen;
    if (copyLen > session->bufferLength) {
        copyLen = session->bufferLength;
        truncated = true;
    }

    // Copy header data
    memcpy(session->headerData, &(pkt_hdr->ts.tv_sec), 4);
    memcpy(session->headerData + 4, &(pkt_hdr->ts.tv_usec), 4);
    memcpy(session->headerData + 8, &(pkt_hdr->caplen), 4);
    memcpy(session->headerData + 12, &(pkt_hdr->len), 4);

    // Copy buffer data
    memcpy(session->bufferData, packet, copyLen);

    napi_handle_scope scope;
    ASSERT_CALL_VOID(session->env_, napi_open_handle_scope(session->env_, &scope));

    napi_value global, fn;
    // napi_create_double(session->env_, copyLen, &args[0]);
    // napi_create_int32(session->env_, truncated, &args[1]);

    ASSERT_CALL_VOID(session->env_, napi_get_global(session->env_, &global));
    ASSERT_CALL_VOID(session->env_, napi_get_reference_value(session->env_, session->onPacketRef, &fn));
    ASSERT_CALL_VOID(session->env_, napi_call_function(session->env_, global, fn, 0, nullptr, nullptr));
    
    ASSERT_CALL_VOID(session->env_, napi_close_handle_scope(session->env_, scope));
}
