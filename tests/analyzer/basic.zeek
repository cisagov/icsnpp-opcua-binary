# @TEST-EXEC: zeek -C -r ${TRACES}/open62541_client-server_mainloop.pcap %INPUT
# @TEST-EXEC: zeek-cut -n user_token_id < opcua-binary-get-endpoints-user-token.log > opcua-binary-get-endpoints-user-token.tmp && mv opcua-binary-get-endpoints-user-token.tmp opcua-binary-get-endpoints-user-token.log
# @TEST-EXEC: zeek-cut -n opcua_id < opcua-binary-get-endpoints.log > opcua-binary-get-endpoints.tmp && mv opcua-binary-get-endpoints.tmp opcua-binary-get-endpoints.log
# @TEST-EXEC: zeek-cut -n opcua_id < opcua-binary-opensecure-channel.log > opcua-binary-opensecure-channel.tmp && mv opcua-binary-opensecure-channel.tmp opcua-binary-opensecure-channel.log
# @TEST-EXEC: zeek-cut -n opcua_id < opcua-binary-status-code-detail.log > opcua-binary-status-code-detail.tmp && mv opcua-binary-status-code-detail.tmp opcua-binary-status-code-detail.log
# @TEST-EXEC: zeek-cut -n opcua_id < opcua-binary.log > opcua-binary.tmp && mv opcua-binary.tmp opcua-binary.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff opcua-binary-get-endpoints-user-token.log
# @TEST-EXEC: btest-diff opcua-binary-get-endpoints.log
# @TEST-EXEC: btest-diff opcua-binary-opensecure-channel.log
# @TEST-EXEC: btest-diff opcua-binary-status-code-detail.log
# @TEST-EXEC: btest-diff opcua-binary.log
#
# @TEST-DOC: Test OPCUA-binary analyzer with small trace.

@load icsnpp/opcua-binary
