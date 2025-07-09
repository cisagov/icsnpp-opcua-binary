# @TEST-EXEC: zeek -C -r ${TRACES}/opcua_with-gap.pcap %INPUT
# @TEST-EXEC: zeek-cut -n opcua_link_id < opcua_binary_opensecure_channel.log > opcua_binary_opensecure_channel.tmp && mv opcua_binary_opensecure_channel.tmp opcua_binary_opensecure_channel.log
# @TEST-EXEC: zeek-cut -n status_code_link_id < opcua_binary_status_code_detail.log > opcua_binary_status_code_detail.tmp && mv opcua_binary_status_code_detail.tmp opcua_binary_status_code_detail.log
# @TEST-EXEC: zeek-cut -n opcua_link_id req_opcua_link_id res_opcua_link_id status_code_link_id < opcua_binary.log > opcua_binary.tmp && mv opcua_binary.tmp opcua_binary.log
# @TEST-EXEC: zeek-cut -n opcua_link_id  discovery_profile_link_id endpoint_link_id < opcua_binary_create_session.log > opcua_binary_create_session.tmp && mv opcua_binary_create_session.tmp opcua_binary_create_session.log
# @TEST-EXEC: btest-diff opcua_binary_opensecure_channel.log
# @TEST-EXEC: btest-diff opcua_binary_status_code_detail.log
# @TEST-EXEC: btest-diff opcua_binary.log
# @TEST-EXEC: btest-diff opcua_binary_create_session.log

#
# @TEST-DOC: Test OPCUA-binary analyzer with a trace file that contains a gap in the transmitted data.

@load icsnpp/opcua-binary
