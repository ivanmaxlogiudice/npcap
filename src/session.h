#ifndef NPCAP_SESSION_H
#define NPCAP_SESSION_H

#include <node_api.h>

#if defined(_WIN32)
#include <uv.h>
#endif

class Session {
    public:
        static napi_value Init(napi_env env, napi_value exports);
        static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);
        static void EmitPacket(u_char *s, const struct pcap_pkthdr* pkthdr, const u_char* packet);

        void Cleanup();
    private:
        Session();
        ~Session();

        static inline napi_value Constructor(napi_env env);
        static napi_value New(napi_env env, napi_callback_info info);

        static napi_value Open(napi_env env, napi_callback_info info, bool live);
        static napi_value OpenLive(napi_env env, napi_callback_info info);
        static napi_value OpenOffline(napi_env env, napi_callback_info info);
        static napi_value Stats(napi_env env, napi_callback_info info);
        static napi_value Inject(napi_env env, napi_callback_info info);
        static napi_value Close(napi_env env, napi_callback_info info);

    #if defined(_WIN32)
        static void OnPacket(void* data, boolean didTimeout);
        static void CallbackPacket(uv_async_t* handle);
        static void CallbackClose(uv_handle_t* handle);
    #else
        static void CallbackPacket(uv_poll_t* handle, int status, int events);
    #endif

    private:
        napi_env env_;
        napi_ref wrapper_;

        napi_ref onPacketRef;

        pcap_t* pcapHandle;
        pcap_dumper_t* pcapDumpHandle;

        char* headerData;
        char* bufferData;
        size_t bufferLength;

        bool closing;
        bool handlingPackets;

    #if defined(_WIN32)
        uv_async_t pollAsync;
        HANDLE pollWait;
    #endif
};

#endif;
