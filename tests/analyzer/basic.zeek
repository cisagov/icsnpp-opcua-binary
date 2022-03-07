# @TEST-EXEC: zeek -C -r ${TRACES}/open62541_client-server_mainloop.pcap %INPUT
# @TEST-EXEC: zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p user_token_policy_id user_token_type user_token_issued_type user_token_endpoint_url user_token_sec_policy_uri < opcua-binary-get-endpoints-user-token.log > opcua-binary-get-endpoints-user-token.tmp && mv opcua-binary-get-endpoints-user-token.tmp opcua-binary-get-endpoints-user-token.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff opcua-binary-get-endpoints-user-token.log
# @TEST-EXEC: btest-diff opcua-binary-get-endpoints.log
# @TEST-EXEC: btest-diff opcua-binary-opensecure-channel.log
# @TEST-EXEC: btest-diff opcua-binary-status-code-detail.log
# @TEST-EXEC: btest-diff opcua-binary.log
#
# @TEST-DOC: Test OPCUA-binary analyzer with small trace.

@load icsnpp/opcua-binary
