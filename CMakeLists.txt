cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(ZeekPluginBinary)

include(ZeekPlugin)

zeek_plugin_begin(ICSNPP OPCUA_Binary)
    zeek_plugin_cc(src/OPCUA_Binary.cc src/Plugin.cc)
    zeek_plugin_bif(src/types.bif src/events.bif)
    zeek_plugin_dist_files(README.md CHANGES COPYING VERSION)
    zeek_plugin_pac(src/opcua_binary.pac src/opcua_binary-analyzer.pac src/opcua_binary-protocol.pac)
zeek_plugin_end()
