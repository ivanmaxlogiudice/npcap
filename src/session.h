#ifndef NPCAP_SESSION_H
#define NPCAP_SESSION_H

#include <node_api.h>

class Session {
public:
    static napi_value Init(napi_env env, napi_value exports);
    static void Destructor(napi_env env, void* nativeObject, void* finalizeHint);

private:
    Session();
    ~Session();

    static napi_value New(napi_env env, napi_callback_info info);
    static napi_value Open(napi_env env, napi_callback_info info, bool live);
    static napi_value OpenLive(napi_env env, napi_callback_info info);
    static napi_value OpenOffline(napi_env env, napi_callback_info info);
    static napi_value Close(napi_env env, napi_callback_info info);
    static void PacketReady(u_char *callback_p, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    static inline napi_value Constructor(napi_env env);

    napi_env env_;
    napi_ref wrapper_;
    napi_ref packetReadyCb;
    
    bpf_u_int32 net;
    bpf_u_int32 mask;

    pcap_t *pcapHandle;
    pcap_dumper_t *pcapDumpHandle;

    struct bpf_program fp;
};

#endif;
