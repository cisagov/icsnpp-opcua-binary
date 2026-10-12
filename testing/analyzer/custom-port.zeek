# @TEST-EXEC: mkdir unconfigured environment redef
# @TEST-EXEC: cd unconfigured && zeek -r ${TRACES}/open62541_client-server_mainloop-no-handshake-12345.pcap %INPUT
# @TEST-EXEC: test ! -e unconfigured/opcua_binary.log
# @TEST-EXEC: cd environment && ZEEK_OPCUA_BINARY_PORTS="12345/tcp" zeek -r ${TRACES}/open62541_client-server_mainloop-no-handshake-12345.pcap %INPUT
# @TEST-EXEC: cd redef && zeek -r ${TRACES}/open62541_client-server_mainloop-no-handshake-12345.pcap %INPUT -e 'redef ICSNPP_OPCUA_Binary::ports += { 12345/tcp };'
# @TEST-EXEC: zeek-cut id.orig_p id.resp_p msg_type < environment/opcua_binary.log | head -n 3 > custom-port.log
# @TEST-EXEC: zeek-cut id.orig_p id.resp_p msg_type < redef/opcua_binary.log | head -n 3 >> custom-port.log
# @TEST-EXEC: btest-diff custom-port.log

# Load main directly so the test isolates port registration from DPD.
@load icsnpp/opcua-binary/main

# @TEST-DOC: Test configured OPC UA Binary TCP ports, including direction
# inference for a midstream capture whose first packet comes from the server.
