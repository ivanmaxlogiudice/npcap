{
    "targets": [
        {
            "target_name": "npcap",
            "sources": [
                "src/common.cpp",
                "src/binding.cpp", 
                "src/session.cpp"
            ],
            "conditions": [
                ["OS=='win'", {
                    "include_dirs": [
                        "deps/Npcap/Include"
                    ],
                    "link_settings": {
                        "libraries": [
                            "ws2_32.lib",
                            "<(module_root_dir)/deps/Npcap/Lib/x64/Packet.lib",
                            "<(module_root_dir)/deps/Npcap/Lib/x64/wpcap.lib"
                        ],
                    }
                }, {
                    "link_settings": {
                        "libraries": ["-lpcap"]
                    }
                }]
            ]
        }
    ]
}
