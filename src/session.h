#ifndef NPCAP_SESSION_H
#define NPCAP_SESSION_H

#include <uv.h>
#include <node_api.h>

class Session {
public:
    bool closing = false;
    bool handlingPackets = false;

    napi_env env_;
    napi_ref wrapper_;
    napi_ref onPacketRef = nullptr;

    pcap_t *pcapHandle = nullptr;
    pcap_dumper_t *pcapDumpHandle = nullptr;

    static napi_value Init(napi_env env, napi_value exports);
    static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);
    static void EmitPacket(u_char *s, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    void Cleanup();

private:
    Session();
    ~Session();

    static napi_value New(napi_env env, napi_callback_info info);
    static napi_value Open(napi_env env, napi_callback_info info, bool live);
    static napi_value OpenLive(napi_env env, napi_callback_info info);
    static napi_value OpenOffline(napi_env env, napi_callback_info info);
    static napi_value Stats(napi_env env, napi_callback_info info);
    static napi_value Close(napi_env env, napi_callback_info info);
    
    static inline napi_value Constructor(napi_env env);
    
    bpf_u_int32 net;
    bpf_u_int32 mask;

    char *headerData = nullptr;
    char *bufferData = nullptr;
    size_t bufferLength = 0;

    bool poolInit = false;
    uv_poll_t pollHandle;
    napi_async_work pollResource;

    HANDLE pollWait = nullptr;
    uv_async_t pollAsync;
};

#endif;
