{
    "targets": [
        {
            "target_name": "npcap",
            "sources": [ "src/binding.cc" ],
            "include_dirs": ["deps/Npcap/Include"],
            "libraries": [
                "<(module_root_dir)/deps/Npcap/Lib/x64/Packet.lib",
                "<(module_root_dir)/deps/Npcap/Lib/x64/wpcap.lib"
            ]
        }
    ]
}
