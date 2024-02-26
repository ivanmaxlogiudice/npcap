#include <stdio.h>
#include <pcap/pcap.h>
#include "session.h"
#include "common.h"

static napi_ref constructor;

Session::Session() {};
Session::~Session() {
    napi_delete_reference(env_, wrapper_);
    napi_delete_reference(env_, onPacketRef);
}

void Session::Destructor(napi_env env, void* nativeObject, void* /* finalizeHint */) {
    reinterpret_cast<Session*>(nativeObject)->~Session();
}

napi_value Session::Init(napi_env env, napi_value exports) {
    napi_property_descriptor properties[] = {
        declare_method("openLive", OpenLive),
        declare_method("openOffline", OpenOffline),
        declare_method("stats", Stats),
        declare_method("inject", Inject),
        declare_method("close", Close)
    };

    napi_value cons;
    assert_call(env, napi_define_class(env, "session", NAPI_AUTO_LENGTH, New, nullptr, sizeof(properties) / sizeof(properties[0]), properties, &cons));

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
    napi_ref* constructor = new napi_ref;
    assert_call(env, napi_create_reference(env, cons, 1, constructor));
    assert_call(env, napi_set_instance_data(
        env,
        constructor,
        [](napi_env env, void* data, void* hint) {
            napi_ref* constructor = static_cast<napi_ref*>(data);
            assert_call_void(env, napi_delete_reference(env, *constructor));
            delete constructor;
        },
        nullptr
    ));

    assert_call(env, napi_set_named_property(env, exports, "Session", cons));
    return exports;
}

napi_value Session::Constructor(napi_env env) {
    void* instanceData = nullptr;
    assert_call(env, napi_get_instance_data(env, &instanceData));

    napi_ref* constructor = static_cast<napi_ref*>(instanceData);

    napi_value cons;
    assert_call(env, napi_get_reference_value(env, *constructor, &cons));
    return cons;
}

napi_value Session::New(napi_env env, napi_callback_info info) {
    napi_value target;
    assert_call(env, napi_get_new_target(env, info, &target));

    if (target != nullptr) {
        // Invoked as constructor: `new Session(...)`
        napi_value thisArg;
        assert_call(env, napi_get_cb_info(env, info, NULL, NULL, &thisArg, NULL));
        
        Session* session = new Session();
        session->env_ = env;

        assert_call(env, napi_wrap(env, thisArg, reinterpret_cast<void*>(session), Session::Destructor, NULL, &session->wrapper_));
        return thisArg;
    } else {
        // Invoked as plain function `Session(...)`, turn into construct call.
        napi_value instance;
        assert_call(env, napi_new_instance(env, Constructor(env), 0, 0, &instance));

        return instance;
    } 
}

void Session::Cleanup() {
    if (pcapHandle && !handlingPackets) {
        pcap_close(pcapHandle);
        
        pcapHandle = nullptr;
        headerData = nullptr;
        bufferData = nullptr;
        bufferLength = 0;

        // Unref???
    }
}

void Session::EmitPacket(u_char *s, const struct pcap_pkthdr* pkt_hdr, const u_char* packet) {
    Session *session = reinterpret_cast<Session*>(s);

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
    assert_call_void(session->env_, napi_open_handle_scope(session->env_, &scope));

    napi_value global, fn;
    // napi_create_double(session->env_, copyLen, &args[0]);
    // napi_create_int32(session->env_, truncated, &args[1]);

    assert_call_void(session->env_, napi_get_global(session->env_, &global));
    assert_call_void(session->env_, napi_get_reference_value(session->env_, session->onPacketRef, &fn));
    assert_call_void(session->env_, napi_call_function(session->env_, global, fn, 0, nullptr, nullptr));
    
    assert_call_void(session->env_, napi_close_handle_scope(session->env_, scope));
}

static void CallbackPacket(uv_async_t* handle) {
    Session *session = reinterpret_cast<Session*>(handle->data);

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
    } while(packetCount > 0 && !session->closing);

    session->handlingPackets = false;
    
    if (session->closing)
        session->Cleanup();
}

static void CallbackClose(uv_handle_t* handle) {

}

static void OnPacket(void* data, BOOLEAN didTimeout) {
    Session *session = reinterpret_cast<Session*>(data);

    assert_void(session->env_, !didTimeout);
    int response = uv_async_send(reinterpret_cast<uv_async_t*>(data));
    assert_void(session->env_, response == 0);
}

napi_value Session::Open(napi_env env, napi_callback_info info, bool live) {
    size_t argc = 12;
    napi_value args[12], thisArg;

    napi_get_cb_info(env, info, &argc, args, &thisArg, nullptr);
    assert_message(env, argc == 12, "Session::Open: Expecting 12 arguments.");

    // Verify arguments
    napi_valuetype valueType;

    // args[0]: { device: string }
    napi_typeof(env, args[0], &valueType);
    assert_message(env, napi_string == valueType, "Session::Open: The argument `device` must be a String.");

    // args[1]: { onPacket: (buffer: Buffer) => void }
    napi_typeof(env, args[1], &valueType);
    assert_message(env, napi_function == valueType, "Session::Open: The argument `onPacket` must be a Function (like: (buffer: Buffer) => void).");

    // args[2]: { filter: string }
    napi_typeof(env, args[2], &valueType);
    assert_message(env, napi_string == valueType, "Session::Open: The argument `filter` must be a String.");

    // args[3]: { bufferSize: number }
    napi_typeof(env, args[3], &valueType);
    assert_message(env, napi_number == valueType, "Session::Open: The argument `bufferSize` must be a Number.");

    // args[4]: { header: Buffer }
    bool isBuffer;
    assert_call(env, napi_is_buffer(env, args[4], &isBuffer));
    assert_message(env, isBuffer == true, "Session::Open: The parameter `header` must be a Buffer.");

    // args[5]: { buffer: Buffer}
    assert_call(env, napi_is_buffer(env, args[5], &isBuffer));
    assert_message(env, isBuffer == true, "Session::Open: The parameter `buffer` must be a Buffer.");

    // args[6]: { snapLen: number }
    napi_typeof(env, args[6], &valueType);
    assert_message(env, napi_number == valueType, "Session::Open: The argument `snapLen` must be a Number.");

    // args[7]: { outFile: string }
    napi_typeof(env, args[7], &valueType);
    assert_message(env, napi_string == valueType, "Session::Open: The argument `outFile` must be a String.");

    // args[8]: { monitor: boolean }
    napi_typeof(env, args[8], &valueType);
    assert_message(env, napi_boolean == valueType, "Session::Open: The argument `monitor` must be a Boolean.");

    // args[9]: { timeout: number }
    napi_typeof(env, args[9], &valueType);
    assert_message(env, napi_number == valueType, "Session::Open: The argument `timeout` must be a Number.");

    // args[10]: { warningHandler: (message: string) => void  }
    napi_typeof(env, args[10], &valueType);
    assert_message(env, napi_function == valueType, "Session::Open: The argument `warningHandler` must be a Function (like: (message: string) => void).");

    // args[11]: { promiscuous: boolean }
    napi_typeof(env, args[11], &valueType);
    assert_message(env, napi_boolean == valueType, "Session::Open: The argument `promiscuous` must be a Boolean.");
    
    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    assert_message(env, napi_ok == napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)), "Session::Open: Can't unwrap the Session.");
   
    // Close previously open session.
    if (session->pcapHandle != nullptr)
        session->Close(env, info);
    
    // Get the header & buffer
    assert_call(env, napi_get_buffer_info(env, args[4], reinterpret_cast<void**>(&session->headerData), nullptr));
    assert_call(env, napi_get_buffer_info(env, args[5], reinterpret_cast<void**>(&session->bufferData), &session->bufferLength));
    
    const char* device = GetStringFromArg(env, args[0]);
    const char* filter = GetStringFromArg(env, args[2]);
    int bufferSize = GetNumberFromArg(env, args[3]);
    int snapLen = GetNumberFromArg(env, args[6]);
    const char* outFile = GetStringFromArg(env, args[7]);
    bool monitor = GetBooleanFromArg(env, args[8]);
    int timeout = GetNumberFromArg(env, args[9]);
    bool promiscuous = GetNumberFromArg(env, args[11]);
    
    char errorBuffer[PCAP_ERRBUF_SIZE];
    if (live) {
        if (pcap_lookupnet(device, &session->net, &session->mask, errorBuffer) == -1) {
            session->net = 0;
            session->mask = 0;

            napi_value global, errorMessage, result;
            assert_call(env, napi_get_global(env, &global));
            assert_call(env, napi_create_string_utf8(env, errorBuffer, strlen(errorBuffer), &errorMessage));
            assert_call(env, napi_call_function(env, global, args[10], 1, &errorMessage, &result));
        }

        session->pcapHandle = pcap_create(device, errorBuffer);
        assert_message(env, session->pcapHandle != nullptr, errorBuffer);

        // 64KB is the max IPv4 packet size
        assert_message(env, pcap_set_snaplen(session->pcapHandle, snapLen) == 0, "Session::Open: Error with the setting 'snapLen'.");

        if (promiscuous) {
            assert_message(env, pcap_set_promisc(session->pcapHandle, 1) == 0, "Session::Open: Can't set promiscuous mode.");
        }

        assert_message(env, pcap_set_buffer_size(session->pcapHandle, bufferSize) == 0, "Session::Open: Can't set the bufferSize.");

        if (timeout > 0) {
            // set "timeout" on read, even though we are also setting nonblock below. On Linux this is required.
            assert_message(env, pcap_set_timeout(session->pcapHandle, timeout) == 0, "Session::Open: Can't set the read timeout.");
        }

        // timeout <= 0 is undefined behaviour, we'll set immediate mode instead. (timeout is ignored in immediate mode)
        assert_message(env, pcap_set_immediate_mode(session->pcapHandle, (timeout <= 0)) == 0, "Session::Open: Can't set the immediate mode.");

        if (monitor) {
            assert_message(env, pcap_set_rfmon(session->pcapHandle, 1) == 0, pcap_geterr(session->pcapHandle));
        }

        assert_message(env, pcap_activate(session->pcapHandle) == 0, pcap_geterr(session->pcapHandle));

        if (strlen(outFile) > 0) {
            session->pcapDumpHandle = pcap_dump_open(session->pcapHandle, outFile);
            assert_message(env, session->pcapDumpHandle != nullptr, "Session::Open: Can't open output dump file.");
        }

        if (pcap_setnonblock(session->pcapHandle, 1, errorBuffer) == -1) {
            napi_throw_error(env, NULL, errorBuffer);
            return nullptr;
        }
    } else {
        // Device is the path to the savefile
        session->pcapHandle = pcap_open_offline(device, errorBuffer);
        assert_message(env, session->pcapHandle != nullptr, errorBuffer);
    }

    if (strlen(filter) > 0) {
        struct bpf_program fp;

        assert_message(env, pcap_compile(session->pcapHandle, &fp, filter, 1, session->net) != -1, pcap_geterr(session->pcapHandle));
        assert_message(env, pcap_setfilter(session->pcapHandle, &fp) != -1, pcap_geterr(session->pcapHandle));

        pcap_freecode(&fp);
    }

    int linkType = pcap_datalink(session->pcapHandle);
    napi_value returnValue;
    
    switch (linkType) {
        case DLT_NULL:
            napi_create_string_utf8(env, "LINKTYPE_NULL", NAPI_AUTO_LENGTH, &returnValue);
            break;
        case DLT_EN10MB: // Most wifi interfaces pretend to be "ethernet"
            napi_create_string_utf8(env, "LINKTYPE_ETHERNET", NAPI_AUTO_LENGTH, &returnValue);
            break;
        case DLT_IEEE802_11_RADIO: // 802.11 "monitor mode"
            napi_create_string_utf8(env, "LINKTYPE_IEEE802_11_RADIO", NAPI_AUTO_LENGTH, &returnValue);
            break;
        case DLT_RAW: // "raw IP"
            napi_create_string_utf8(env, "LINKTYPE_RAW", NAPI_AUTO_LENGTH, &returnValue);
            break;
        case DLT_LINUX_SLL:
            napi_create_string_utf8(env, "LINKTYPE_LINUX_SLL", NAPI_AUTO_LENGTH, &returnValue);
            break;
        default:
            char errorBuffer[PCAP_ERRBUF_SIZE];
            snprintf(errorBuffer, PCAP_ERRBUF_SIZE, "Unknown linktype %d", linkType);
            napi_create_string_utf8(env, errorBuffer, NAPI_AUTO_LENGTH, &returnValue);
            break;
    }

    // Create a reference to the onPacket function
    assert_call(env, napi_create_reference(env, args[1], 1, &session->onPacketRef));
    
    assert(env, uv_async_init(uv_default_loop(), &session->pollAsync, (uv_async_cb) CallbackPacket) == 0);
    session->pollAsync.data = session;
        
    if (!RegisterWaitForSingleObject(
        &session->pollWait,
        pcap_getevent(session->pcapHandle),
        OnPacket,
        &session->pollAsync,
        INFINITE,
        WT_EXECUTEINWAITTHREAD
    )) {
        char *errmsg = nullptr;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
                      | FORMAT_MESSAGE_FROM_SYSTEM
                      | FORMAT_MESSAGE_IGNORE_INSERTS,
                      nullptr,
                      GetLastError(),
                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                      (LPTSTR)&errmsg,
                      0,
                      nullptr);
        
        napi_throw_error(env, NULL, errmsg);
        return nullptr;
    }
    
    // Obj->Ref(); ???
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
    assert_call(env, napi_get_cb_info(env, info, NULL, NULL, &thisArg, NULL));
    
    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    assert_message(env, napi_ok == napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)), "Session::Open: Can't unwrap the Session.");
    assert_message(env, session->pcapHandle != nullptr, "Session::Stats: The session is closed.");

    struct pcap_stat ps;
    assert_message(env, pcap_stats(session->pcapHandle, &ps) != 1, pcap_geterr(session->pcapHandle));
    
    napi_value stats, value;
    assert_call(env, napi_create_object(env, &stats));

    assert_call(env, napi_create_int32(env, ps.ps_recv, &value));
    assert_call(env, napi_set_named_property(env, stats, "ps_recv", value));

    assert_call(env, napi_create_int32(env, ps.ps_drop, &value));
    assert_call(env, napi_set_named_property(env, stats, "ps_drop", value));

    assert_call(env, napi_create_int32(env, ps.ps_ifdrop, &value));
    assert_call(env, napi_set_named_property(env, stats, "ps_ifdrop", value));

    return stats;
}

napi_value Session::Inject(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1], thisArg;

    napi_get_cb_info(env, info, &argc, args, &thisArg, nullptr);
    assert_message(env, argc == 1, "Session::Inject: Expecting 1 arguments.");

    bool isBuffer;
    assert_call(env, napi_is_buffer(env, args[0], &isBuffer));
    assert_message(env, isBuffer == true, "Session::Inject: The parameter `data` must be a Buffer.");

    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    assert_message(env, napi_ok == napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)), "Session::Inject: Can't unwrap the Session.");
    assert_message(env, session->pcapHandle != nullptr, "Session::Inject: The session is closed.");

    char *bufferData = nullptr;
    size_t bufferLength = 0;
    assert_call(env, napi_get_buffer_info(env, args[0], reinterpret_cast<void**>(&bufferData), &bufferLength));
    
    assert_message(env, bufferLength > 0, "Session:Inject: The length of the buffer `data` must be greater than zero.");

    assert_message(env, pcap_inject(session->pcapHandle, bufferData, bufferLength) == (int)bufferLength, pcap_geterr(session->pcapHandle));
    return ReturnBoolean(env, true);
}

napi_value Session::Close(napi_env env, napi_callback_info info) {
    napi_value thisArg, returnValue;
    assert_call(env, napi_get_cb_info(env, info, NULL, NULL, &thisArg, NULL));
    
    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    assert_message(env, napi_ok == napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)), "Session::Open: Can't unwrap the Session.");
    
    if (session->pcapHandle && !session->closing) {
        if (session->pollWait) {
            UnregisterWait(session->pollWait);
            session->pollWait = nullptr;
        }
        
        if (session->pcapDumpHandle != NULL) {
            pcap_dump_close(session->pcapDumpHandle);
            session->pcapDumpHandle = NULL;
        }
        
        uv_close(reinterpret_cast<uv_handle_t*>(&session->pollAsync), CallbackClose);
        
        session->closing = true;
        session->Cleanup();
        
        napi_create_int32(env, 1, &returnValue);
    } else {
        napi_create_int32(env, 0, &returnValue);
    }
    
    return returnValue;
}
