#include <stdio.h>
#include <pcap/pcap.h>
#include "session.h"
#include "common.h"

static napi_ref constructor;

Session::Session() {};
Session::~Session() {
    napi_delete_reference(env_, wrapper_);
}

void Session::Destructor(napi_env env, void* nativeObject, void* /* finalizeHint */) {
    reinterpret_cast<Session*>(nativeObject)->~Session();
}

napi_value Session::Init(napi_env env, napi_value exports) {
    napi_property_descriptor properties[] = {
        declare_method("openLive", OpenLive),
        declare_method("openOffline", OpenOffline),
        declare_method("dispatch", Dispatch),
        declare_method("startPolling", StartPolling),

        declare_method("close", Close)
    };

    napi_value cons;
    assert(env, napi_ok == napi_define_class(env, "session", NAPI_AUTO_LENGTH, New, nullptr, sizeof(properties) / sizeof(properties[0]), properties, &cons));

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
    assert(env, napi_ok == napi_create_reference(env, cons, 1, constructor));
    assert(env, napi_ok == napi_set_instance_data(
        env,
        constructor,
        [](napi_env env, void* data, void* hint) {
            napi_ref* constructor = static_cast<napi_ref*>(data);
            assert_void(env, napi_ok == napi_delete_reference(env, *constructor));
            delete constructor;
        },
        nullptr
    ));

    assert(env, napi_ok == napi_set_named_property(env, exports, "Session", cons));
    return exports;
}

napi_value Session::Constructor(napi_env env) {
    void* instanceData = nullptr;
    assert(env, napi_ok == napi_get_instance_data(env, &instanceData));

    napi_ref* constructor = static_cast<napi_ref*>(instanceData);

    napi_value cons;
    assert(env, napi_ok == napi_get_reference_value(env, *constructor, &cons));
    return cons;
}

napi_value Session::New(napi_env env, napi_callback_info info) {
    napi_value target;
    assert(env, napi_ok == napi_get_new_target(env, info, &target));

    if (target != nullptr) {
        // Invoked as constructor: `new Session(...)`
        napi_value thisArg;
        assert(env, napi_ok == napi_get_cb_info(env, info, NULL, NULL, &thisArg, NULL));

        Session* obj = new Session();
        obj->env_ = env;

        assert(env, napi_ok == napi_wrap(env, thisArg, reinterpret_cast<void*>(obj), Session::Destructor, NULL, &obj->wrapper_));
        return thisArg;
    } else {
        // Invoked as plain function `Session(...)`, turn into construct call.
        napi_value instance;
        assert(env, napi_ok == napi_new_instance(env, Constructor(env), 0, 0, &instance));

        return instance;
    } 
}

napi_value Session::Open(napi_env env, napi_callback_info info, bool live) {
    size_t argc = 10;
    napi_value args[10], thisArg;

    napi_get_cb_info(env, info, &argc, args, &thisArg, nullptr);
    assert_message(env, argc == 10, "Session::Open: Expecting 10 arguments.");

    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    assert_message(env, napi_ok == napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)), "Session::Open: Can't unwrap the Session.");

    // Close previously open session.
    if (session->pcapHandle)
        session->Close(env, info);

    // Verify arguments
    napi_valuetype valueType;

    // args[0]: { device: string }
    napi_typeof(env, args[0], &valueType);
    assert_message(env, napi_string == valueType, "Session::Open: The argument `device` must be a String.");

    // args[1]: { filter: string }
    napi_typeof(env, args[1], &valueType);
    assert_message(env, napi_string == valueType, "Session::Open: The argument `filter` must be a String.");

    // args[2]: { bufferSize: number }
    napi_typeof(env, args[2], &valueType);
    assert_message(env, napi_number == valueType, "Session::Open: The argument `bufferSize` must be a Number.");

    // args[3]: { snapLength: number }
    napi_typeof(env, args[3], &valueType);
    assert_message(env, napi_number == valueType, "Session::Open: The argument `snapLength` must be a Number.");

    // args[4]: { outFile: string }
    napi_typeof(env, args[4], &valueType);
    assert_message(env, napi_string == valueType, "Session::Open: The argument `outFile` must be a String.");

    // args[5]: { onPacketReady: Function }
    napi_typeof(env, args[5], &valueType);
    assert_message(env, napi_function == valueType, "Session::Open: The argument `onPacketReady` must be a Function.");

    // args[6]: { monitor: boolean }
    napi_typeof(env, args[6], &valueType);
    assert_message(env, napi_boolean == valueType, "Session::Open: The argument `monitor` must be a Boolean.");

    // args[7]: { bufferTimeout: number }
    napi_typeof(env, args[7], &valueType);
    assert_message(env, napi_number == valueType, "Session::Open: The argument `bufferTimeout` must be a Number.");

    // args[8]: { warningHandler: Function }
    napi_typeof(env, args[8], &valueType);
    assert_message(env, napi_function == valueType, "Session::Open: The argument `warningHandler` must be a Function.");

    // args[9]: { promiscuous: boolean }
    napi_typeof(env, args[9], &valueType);
    assert_message(env, napi_boolean == valueType, "Session::Open: The argument `promiscuous` must be a Boolean.");
    
    const char* device = GetStringFromArg(env, args[0]);
    const char* filter = GetStringFromArg(env, args[1]);
    int bufferSize = GetNumberFromArg(env, args[2]);
    int snapLength = GetNumberFromArg(env, args[3]);
    const char* outFile = GetStringFromArg(env, args[4]);
    // onPacketReady: function
    bool monitor = GetBooleanFromArg(env, args[6]);
    int bufferTimeout = GetNumberFromArg(env, args[7]);
    bool promiscuous = GetNumberFromArg(env, args[9]);

    napi_create_reference(env, args[5], 1, &session->packetReadyCb);
    session->pcapDumpHandle = nullptr;
   
    char errorBuffer[PCAP_ERRBUF_SIZE];
    if (live) {
        if (pcap_lookupnet(device, &session->net, &session->mask, errorBuffer) == -1) {
            session->net = 0;
            session->mask = 0;

            napi_value global, errorMessage, result;
            assert(env, napi_ok == napi_get_global(env, &global));
            assert(env, napi_ok == napi_create_string_utf8(env, errorBuffer, strlen(errorBuffer), &errorMessage));
            assert(env, napi_ok == napi_call_function(env, global, args[8], 1, &errorMessage, &result));
        }

        session->pcapHandle = pcap_create(device, errorBuffer);
        assert_message(env, session->pcapHandle != nullptr, errorBuffer);

        // 64KB is the max IPv4 packet size
        assert_message(env, pcap_set_snaplen(session->pcapHandle, snapLength) == 0, "Session::Open: Error with the setting 'snapLength'.");

        if (promiscuous) {
            assert_message(env, pcap_set_promisc(session->pcapHandle, 1) == 0, "Session::Open: Can't set promiscuous mode.");
        }

        assert_message(env, pcap_set_buffer_size(session->pcapHandle, bufferSize) == 0, "Session::Open: Can't set the bufferSize.");

        if (bufferTimeout > 0) {
            // set "timeout" on read, even though we are also setting nonblock below. On Linux this is required.
            assert_message(env, pcap_set_timeout(session->pcapHandle, bufferTimeout) == 0, "Session::Open: Can't set the read timeout.");
        }

        // timeout <= 0 is undefined behaviour, we'll set immediate mode instead. (timeout is ignored in immediate mode)
        assert_message(env, pcap_set_immediate_mode(session->pcapHandle, (bufferTimeout <= 0)) == 0, "Session::Open: Can't set the immediate mode.");

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
        assert_message(env, pcap_compile(session->pcapHandle, &session->fp, filter, 1, session->net) != -1, pcap_geterr(session->pcapHandle));
        assert_message(env, pcap_setfilter(session->pcapHandle, &session->fp) != -1, pcap_geterr(session->pcapHandle));

        pcap_freecode(&session->fp);
    }

    int linkType = pcap_datalink(session->pcapHandle);
    napi_value returnValue;
    
    switch (linkType) {
        case DLT_NULL:
            napi_create_string_utf8(env, "LINKTYPE_NULL", NAPI_AUTO_LENGTH, &returnValue);
            break;
        case DLT_EN10MB:
            napi_create_string_utf8(env, "LINKTYPE_ETHERNET", NAPI_AUTO_LENGTH, &returnValue);
            break;
        case DLT_IEEE802_11_RADIO:
            napi_create_string_utf8(env, "LINKTYPE_IEEE802_11_RADIO", NAPI_AUTO_LENGTH, &returnValue);
            break;
        case DLT_RAW:
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

    return returnValue;
}

napi_value Session::OpenLive(napi_env env, napi_callback_info info) {
    return Open(env, info, true);
}

napi_value Session::OpenOffline(napi_env env, napi_callback_info info) {
    return Open(env, info, false);
}

napi_value Session::Close(napi_env env, napi_callback_info info) {
    napi_value thisArg;
    assert(env, napi_ok == napi_get_cb_info(env, info, NULL, NULL, &thisArg, NULL));

    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    assert_message(env, napi_ok == napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)), "Session::Open: Can't unwrap the Session.");

    if (session->pcapDumpHandle != NULL) {
        pcap_dump_close(session->pcapDumpHandle);
        session->pcapDumpHandle = NULL;
    }

    if (session->pcapHandle != NULL) {
        pcap_breakloop(session->pcapHandle);
    }

    return nullptr;
}

napi_value Session::Dispatch(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2], thisArg;
    
    // Get the arguments and validate the amount.
    assert_call(env, napi_get_cb_info(env, info, &argc, args, &thisArg, nullptr));
    assert_message(env, argc == 2, "Session::Dispatch: Expecting 2 arguments.");
    
    // Validate arguments
    bool isBuffer;
    assert_call(env, napi_is_buffer(env, args[0], &isBuffer));
    assert_message(env, isBuffer == true, "Session::Dispatch: The parameter `buffer` must be a Buffer.");
    
    assert_call(env, napi_is_buffer(env, args[1], &isBuffer));
    assert_message(env, isBuffer == true, "Session::Dispatch: The parameter `header` must be a Buffer.");
    
    size_t bufferLength;
    char *bufferData, *headerData;
    assert_call(env, napi_get_buffer_info(env, args[0], reinterpret_cast<void**>(&bufferData), &bufferLength));
    assert_call(env, napi_get_buffer_info(env, args[1], reinterpret_cast<void**>(&headerData), nullptr));
    
    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    assert_message(env, napi_ok == napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)), "Session::Dispatch: Can't unwrap the Session.");
    
    session->bufferData = bufferData;
    session->bufferLength = bufferLength;
    session->headerData = headerData;
    
    // TODO: Loop Starvation: https://github.com/node-pcap/node_pcap/issues/255
    int packetCount;
    do {
        packetCount = pcap_dispatch(session->pcapHandle, 1, PacketReady, (u_char *)session);
        printf("packetCount: %d\n", packetCount);
        if (packetCount == -2) {
            FinalizeClose(env, session);
        }
    } while (packetCount > 0);
    
    napi_value count;
    assert_call(env, napi_create_int32(env, packetCount, &count));
    
    return count;
}

void Session::FinalizeClose(napi_env env, Session *session) {
    if (session->poolInit) {
        uv_poll_stop(&session->pollHandle);
        uv_unref((uv_handle_t*) &session->pollHandle);
        
        session->poolInit = false;

        napi_delete_async_work(env, session->pollResource);
        session->pollResource = nullptr;
    }

    pcap_close(session->pcapHandle);
    session->pcapHandle = nullptr;

    napi_delete_reference(env, session->packetReadyCb);
    session->packetReadyCb = nullptr;
}

static void CALLBACK OnPacket(void *data, BOOLEAN didTimeout) {
    printf("Receive OnPacket\n");
    if (didTimeout) {
        printf("Warning: OnPacket timeout!");
        return;
    }

    uv_async_t *async = (uv_async_t *)data;

    if (uv_async_send(async) != 0) {
        printf("Warning: OnPacket failed uv_async_send!");
        return;
    }
}

napi_value Session::StartPolling(napi_env env, napi_callback_info info) {
    // Get context
    napi_value thisArg;
    assert_call(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisArg, nullptr));

    // Unwrap the `this` object to get the Session pointer.
    Session* session;
    assert_message(env, napi_ok == napi_unwrap(env, thisArg, reinterpret_cast<void**>(&session)), "Session::StartPolling: Can't unwrap the Session.");

    if (session->poolInit) return nullptr;

    if (session->pcapHandle == nullptr) {
        napi_throw_error(env, nullptr, "Session:StartPolling: Session already closed.");
        return nullptr;
    }

    // TODO: Implements polling like https://github.com/mscdex/cap/blob/master/src/binding.cc#L400 ??
    // Implementation for Windows
    assert(env, uv_async_init(uv_default_loop(), &session->pollAsync, (uv_async_cb)PollHandler) == 0);
    session->pollAsync.data = session;

    RegisterWaitForSingleObject(
        &session->pollWait,
        pcap_getevent(session->pcapHandle),
        OnPacket,
        &session->pollAsync,
        INFINITE,
        WT_EXECUTEINWAITTHREAD
    );

    return nullptr;
}

void Session::PollHandler(uv_async_t *handle, int status) {
    printf("Receive Packet\n");
}

void Session::PacketReady(u_char *s, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    printf("PacketReady called\n");
}

