# @TEST-EXEC: zeek -C -r ${TRACES}/open62541_client-server_mainloop.pcap %INPUT
# @TEST-EXEC: zeek-cut -n user_token_link_id < opcua_binary_get_endpoints_user_token.log > opcua_binary_get_endpoints_user_token.tmp && mv opcua_binary_get_endpoints_user_token.tmp opcua_binary_get_endpoints_user_token.log
# @TEST-EXEC: zeek-cut -n opcua_link_id locale_link_id profile_uri_link_id endpoint_description_link_id < opcua_binary_get_endpoints.log > opcua_binary_get_endpoints.tmp && mv opcua_binary_get_endpoints.tmp opcua_binary_get_endpoints.log
# @TEST-EXEC: zeek-cut -n endpoint_description_link_id user_token_link_id < opcua_binary_get_endpoints_description.log > opcua_binary_get_endpoints_description.tmp && mv opcua_binary_get_endpoints_description.tmp opcua_binary_get_endpoints_description.log
# @TEST-EXEC: zeek-cut -n opcua_link_id < opcua_binary_opensecure_channel.log > opcua_binary_opensecure_channel.tmp && mv opcua_binary_opensecure_channel.tmp opcua_binary_opensecure_channel.log
# @TEST-EXEC: zeek-cut -n status_code_link_id < opcua_binary_status_code_detail.log > opcua_binary_status_code_detail.tmp && mv opcua_binary_status_code_detail.tmp opcua_binary_status_code_detail.log
# @TEST-EXEC: zeek-cut -n opcua_link_id req_opcua_link_id res_opcua_link_id status_code_link_id < opcua_binary.log > opcua_binary.tmp && mv opcua_binary.tmp opcua_binary.log
# @TEST-EXEC: zeek-cut -n opcua_link_id client_software_cert_link_id opcua_locale_link_id activate_session_diag_info_link_id status_code_link_id < opcua_binary_activate_session.log > opcua_binary_activate_session.tmp && mv opcua_binary_activate_session.tmp opcua_binary_activate_session.log
# @TEST-EXEC: zeek-cut -n browse_description_link_id < opcua_binary_browse_description.log > opcua_binary_browse_description.tmp && mv opcua_binary_browse_description.tmp opcua_binary_browse_description.log
# @TEST-EXEC: zeek-cut -n browse_reference_link_id  < opcua_binary_browse_response_references.log > opcua_binary_browse_response_references.tmp && mv opcua_binary_browse_response_references.tmp opcua_binary_browse_response_references.log
# @TEST-EXEC: zeek-cut -n browse_response_link_id status_code_link_id browse_reference_link_id < opcua_binary_browse_result.log > opcua_binary_browse_result.tmp && mv opcua_binary_browse_result.tmp opcua_binary_browse_result.log
# @TEST-EXEC: zeek-cut -n opcua_link_id browse_description_link_id browse_next_link_id browse_response_link_id browse_diag_info_link_id < opcua_binary_browse.log > opcua_binary_browse.tmp && mv opcua_binary_browse.tmp opcua_binary_browse.log
# @TEST-EXEC: zeek-cut -n endpoint_link_id user_token_link_id < opcua_binary_create_session_endpoints.log > opcua_binary_create_session_endpoints.tmp && mv opcua_binary_create_session_endpoints.tmp opcua_binary_create_session_endpoints.log
# @TEST-EXEC: zeek-cut -n user_token_link_id < opcua_binary_create_session_user_token.log > opcua_binary_create_session_user_token.tmp && mv opcua_binary_create_session_user_token.tmp opcua_binary_create_session_user_token.log
# @TEST-EXEC: zeek-cut -n opcua_link_id < opcua_binary_create_subscription.log > opcua_binary_create_subscription.tmp && mv opcua_binary_create_subscription.tmp opcua_binary_create_subscription.log
# @TEST-EXEC: zeek-cut -n nodes_to_read_link_id < opcua_binary_read_nodes_to_read.log > opcua_binary_read_nodes_to_read.tmp && mv opcua_binary_read_nodes_to_read.tmp opcua_binary_read_nodes_to_read.log
# @TEST-EXEC: zeek-cut -n results_link_id status_code_link_id read_results_variant_metadata_link_id  < opcua_binary_read_results.log > opcua_binary_read_results.tmp && mv opcua_binary_read_results.tmp opcua_binary_read_results.log
# @TEST-EXEC: zeek-cut -n opcua_link_id nodes_to_read_link_id read_results_link_id diag_info_link_id < opcua_binary_read.log > opcua_binary_read.tmp && mv opcua_binary_read.tmp opcua_binary_read.log
# @TEST-EXEC: zeek-cut -n opcua_link_id create_monitored_items_diag_info_link_id create_item_link_id  < opcua_binary_create_monitored_items.log > opcua_binary_create_monitored_items.tmp && mv opcua_binary_create_monitored_items.tmp opcua_binary_create_monitored_items.log
# @TEST-EXEC: zeek-cut -n create_item_link_id filter_info_details_link_id monitoring_parameters_status_code_link_id  < opcua_binary_create_monitored_items_create_item.log > opcua_binary_create_monitored_items_create_item.tmp && mv opcua_binary_create_monitored_items_create_item.tmp opcua_binary_create_monitored_items_create_item.log
# @TEST-EXEC: zeek-cut -n opcua_link_id  < opcua_binary_close_session.log > opcua_binary_close_session.tmp && mv opcua_binary_close_session.tmp opcua_binary_close_session.log
# @TEST-EXEC: zeek-cut -n opcua_link_id  discovery_profile_link_id endpoint_link_id < opcua_binary_create_session.log > opcua_binary_create_session.tmp && mv opcua_binary_create_session.tmp opcua_binary_create_session.log
# @TEST-EXEC: zeek-cut -n opcua_link_id req_status_code_link_id write_results_variant_metadata_link_id res_status_code_link_id diag_info_link_id < opcua_binary_write.log > opcua_binary_write.tmp && mv opcua_binary_write.tmp opcua_binary_write.log
# @TEST-EXEC: btest-diff opcua_binary_get_endpoints_user_token.log
# @TEST-EXEC: btest-diff opcua_binary_get_endpoints.log
# @TEST-EXEC: btest-diff opcua_binary_get_endpoints_description.log
# @TEST-EXEC: btest-diff opcua_binary_opensecure_channel.log
# @TEST-EXEC: btest-diff opcua_binary_status_code_detail.log
# @TEST-EXEC: btest-diff opcua_binary.log
# @TEST-EXEC: btest-diff opcua_binary_activate_session.log
# @TEST-EXEC: btest-diff opcua_binary_browse_description.log
# @TEST-EXEC: btest-diff opcua_binary_browse_response_references.log
# @TEST-EXEC: btest-diff opcua_binary_browse_result.log
# @TEST-EXEC: btest-diff opcua_binary_browse.log
# @TEST-EXEC: btest-diff opcua_binary_create_session_endpoints.log
# @TEST-EXEC: btest-diff opcua_binary_create_session_user_token.log
# @TEST-EXEC: btest-diff opcua_binary_create_subscription.log
# @TEST-EXEC: btest-diff opcua_binary_read_nodes_to_read.log
# @TEST-EXEC: btest-diff opcua_binary_read_results.log
# @TEST-EXEC: btest-diff opcua_binary_read.log
# @TEST-EXEC: btest-diff opcua_binary_create_monitored_items.log
# @TEST-EXEC: btest-diff opcua_binary_create_monitored_items_create_item.log
# @TEST-EXEC: btest-diff opcua_binary_close_session.log
# @TEST-EXEC: btest-diff opcua_binary_create_session.log
# @TEST-EXEC: btest-diff opcua_binary_write.log

#
# @TEST-DOC: Test OPCUA-binary analyzer with small trace.

@load icsnpp/opcua-binary
