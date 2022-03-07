# @TEST-EXEC: zeek -C -r ${TRACES}/open62541_client-server_mainloop.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff opcua-binary-get-endpoints-user-token.log
# @TEST-EXEC: btest-diff opcua-binary-get-endpoints.log
# @TEST-EXEC: btest-diff opcua-binary-opensecure-channel.log
# @TEST-EXEC: btest-diff opcua-binary-status-code-detail.log
# @TEST-EXEC: btest-diff opcua-binary.log
#
# @TEST-DOC: Test OPCUA-binary analyzer with small trace.

@load icsnpp/opcua-binary
