# @TEST-EXEC: zeek -C -r ${TRACES}/opcua_with-gap.pcap %INPUT
# @TEST-EXEC: zeek-cut -n opcua_link_id < opcua-binary-opensecure-channel.log > opcua-binary-opensecure-channel.tmp && mv opcua-binary-opensecure-channel.tmp opcua-binary-opensecure-channel.log
# @TEST-EXEC: zeek-cut -n status_code_link_id < opcua-binary-status-code-detail.log > opcua-binary-status-code-detail.tmp && mv opcua-binary-status-code-detail.tmp opcua-binary-status-code-detail.log
# @TEST-EXEC: zeek-cut -n opcua_link_id status_code_link_id < opcua-binary.log > opcua-binary.tmp && mv opcua-binary.tmp opcua-binary.log
# @TEST-EXEC: zeek-cut -n opcua_link_id  discovery_profile_link_id endpoint_link_id < opcua-binary-create-session.log > opcua-binary-create-session.tmp && mv opcua-binary-create-session.tmp opcua-binary-create-session.log
# @TEST-EXEC: btest-diff opcua-binary-opensecure-channel.log
# @TEST-EXEC: btest-diff opcua-binary-status-code-detail.log
# @TEST-EXEC: btest-diff opcua-binary.log
# @TEST-EXEC: btest-diff opcua-binary-create-session.log

#
# @TEST-DOC: Test OPCUA-binary analyzer with a trace file that contains a gap in the transmitted data.

@load icsnpp/opcua-binary
