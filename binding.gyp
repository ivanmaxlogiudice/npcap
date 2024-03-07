{
    "targets": [
        {
            "target_name": "node-npcap",
            "win_delay_load_hook": "true",
            "sources": [
                "lib/common.cpp",
                "lib/binding.cpp", 
                "lib/session.cpp"
            ],
            "conditions": [
                ["OS=='win'", {
                    "sources": [
                        '<(node_gyp_dir)/src/win_delay_load_hook.cc',
                    ],
                    "include_dirs": [
                        "deps/Npcap/Include"
                    ],
                    "link_settings": {
                        "libraries": [
                            "ws2_32.lib",
                            "<(module_root_dir)/deps/Npcap/Lib/x64/Packet.lib",
                            "<(module_root_dir)/deps/Npcap/Lib/x64/wpcap.lib"
                        ],
                    },
                    'msvs_settings': {
                    'VCLinkerTool': {
                        'DelayLoadDLLs': [ '<(node_host_binary)<(EXECUTABLE_SUFFIX)','wpcap.dll' ],
                        # Don't print a linker warning when no imports from either .exe
                        # are used.
                        'AdditionalOptions': [ '/ignore:4199' ],
                        },
                    },
                }, {
                    "link_settings": {
                        "libraries": ["-lpcap"]
                    }
                }]
            ]
        }
    ]
}
