# @TEST-EXEC: zeek -C -r ${TRACES}/open62541_client-server_mainloop.pcap %INPUT
# @TEST-EXEC: zeek-cut -n user_token_link_id < opcua-binary-get-endpoints-user-token.log > opcua-binary-get-endpoints-user-token.tmp && mv opcua-binary-get-endpoints-user-token.tmp opcua-binary-get-endpoints-user-token.log
# @TEST-EXEC: zeek-cut -n opcua_link_id locale_link_id profile_uri_link_id endpoint_description_link_id < opcua-binary-get-endpoints.log > opcua-binary-get-endpoints.tmp && mv opcua-binary-get-endpoints.tmp opcua-binary-get-endpoints.log
# @TEST-EXEC: zeek-cut -n endpoint_description_link_id user_token_link_id < opcua-binary-get-endpoints-description.log > opcua-binary-get-endpoints-description.tmp && mv opcua-binary-get-endpoints-description.tmp opcua-binary-get-endpoints-description.log
# @TEST-EXEC: zeek-cut -n opcua_link_id < opcua-binary-opensecure-channel.log > opcua-binary-opensecure-channel.tmp && mv opcua-binary-opensecure-channel.tmp opcua-binary-opensecure-channel.log
# @TEST-EXEC: zeek-cut -n status_code_link_id < opcua-binary-status-code-detail.log > opcua-binary-status-code-detail.tmp && mv opcua-binary-status-code-detail.tmp opcua-binary-status-code-detail.log
# @TEST-EXEC: zeek-cut -n opcua_link_id status_code_link_id < opcua-binary.log > opcua-binary.tmp && mv opcua-binary.tmp opcua-binary.log
# @TEST-EXEC: zeek-cut -n opcua_link_id client_software_cert_link_id opcua_locale_link_id activate_session_diag_info_link_id status_code_link_id < opcua-binary-activate-session.log > opcua-binary-activate-session.tmp && mv opcua-binary-activate-session.tmp opcua-binary-activate-session.log
# @TEST-EXEC: zeek-cut -n browse_description_link_id < opcua-binary-browse-description.log > opcua-binary-browse-description.tmp && mv opcua-binary-browse-description.tmp opcua-binary-browse-description.log
# @TEST-EXEC: zeek-cut -n browse_reference_link_id  < opcua-binary-browse-response-references.log > opcua-binary-browse-response-references.tmp && mv opcua-binary-browse-response-references.tmp opcua-binary-browse-response-references.log
# @TEST-EXEC: zeek-cut -n browse_response_link_id status_code_link_id browse_reference_link_id < opcua-binary-browse-result.log > opcua-binary-browse-result.tmp && mv opcua-binary-browse-result.tmp opcua-binary-browse-result.log
# @TEST-EXEC: zeek-cut -n opcua_link_id browse_description_link_id browse_next_link_id browse_response_link_id browse_diag_info_link_id < opcua-binary-browse.log > opcua-binary-browse.tmp && mv opcua-binary-browse.tmp opcua-binary-browse.log
# @TEST-EXEC: zeek-cut -n endpoint_link_id user_token_link_id < opcua-binary-create-session-endpoints.log > opcua-binary-create-session-endpoints.tmp && mv opcua-binary-create-session-endpoints.tmp opcua-binary-create-session-endpoints.log
# @TEST-EXEC: zeek-cut -n user_token_link_id < opcua-binary-create-session-user-token.log > opcua-binary-create-session-user-token.tmp && mv opcua-binary-create-session-user-token.tmp opcua-binary-create-session-user-token.log
# @TEST-EXEC: zeek-cut -n opcua_link_id < opcua-binary-create-subscription.log > opcua-binary-create-subscription.tmp && mv opcua-binary-create-subscription.tmp opcua-binary-create-subscription.log
# @TEST-EXEC: zeek-cut -n nodes_to_read_link_id < opcua-binary-read-nodes-to-read.log > opcua-binary-read-nodes-to-read.tmp && mv opcua-binary-read-nodes-to-read.tmp opcua-binary-read-nodes-to-read.log
# @TEST-EXEC: zeek-cut -n results_link_id status_code_link_id read_results_variant_metadata_link_id  < opcua-binary-read-results.log > opcua-binary-read-results.tmp && mv opcua-binary-read-results.tmp opcua-binary-read-results.log
# @TEST-EXEC: zeek-cut -n opcua_link_id nodes_to_read_link_id read_results_link_id diag_info_link_id < opcua-binary-read.log > opcua-binary-read.tmp && mv opcua-binary-read.tmp opcua-binary-read.log
# @TEST-EXEC: zeek-cut -n opcua_link_id create_monitored_items_diag_info_link_id create_item_link_id  < opcua-binary-create-monitored-items.log > opcua-binary-create-monitored-items.tmp && mv opcua-binary-create-monitored-items.tmp opcua-binary-create-monitored-items.log
# @TEST-EXEC: zeek-cut -n create_item_link_id filter_info_details_link_id monitoring_parameters_status_code_link_id  < opcua-binary-create-monitored-items-create-item.log > opcua-binary-create-monitored-items-create-item.tmp && mv opcua-binary-create-monitored-items-create-item.tmp opcua-binary-create-monitored-items-create-item.log
# @TEST-EXEC: zeek-cut -n opcua_link_id  < opcua-binary-close-session.log > opcua-binary-close-session.tmp && mv opcua-binary-close-session.tmp opcua-binary-close-session.log
# @TEST-EXEC: zeek-cut -n opcua_link_id  discovery_profile_link_id endpoint_link_id < opcua-binary-create-session.log > opcua-binary-create-session.tmp && mv opcua-binary-create-session.tmp opcua-binary-create-session.log
# @TEST-EXEC: btest-diff opcua-binary-get-endpoints-user-token.log
# @TEST-EXEC: btest-diff opcua-binary-get-endpoints.log
# @TEST-EXEC: btest-diff opcua-binary-get-endpoints-description.log
# @TEST-EXEC: btest-diff opcua-binary-opensecure-channel.log
# @TEST-EXEC: btest-diff opcua-binary-status-code-detail.log
# @TEST-EXEC: btest-diff opcua-binary.log
# @TEST-EXEC: btest-diff opcua-binary-activate-session.log
# @TEST-EXEC: btest-diff opcua-binary-browse-description.log
# @TEST-EXEC: btest-diff opcua-binary-browse-response-references.log
# @TEST-EXEC: btest-diff opcua-binary-browse-result.log
# @TEST-EXEC: btest-diff opcua-binary-browse.log
# @TEST-EXEC: btest-diff opcua-binary-create-session-endpoints.log
# @TEST-EXEC: btest-diff opcua-binary-create-session-user-token.log
# @TEST-EXEC: btest-diff opcua-binary-create-subscription.log
# @TEST-EXEC: btest-diff opcua-binary-read-nodes-to-read.log
# @TEST-EXEC: btest-diff opcua-binary-read-results.log
# @TEST-EXEC: btest-diff opcua-binary-read.log
# @TEST-EXEC: btest-diff opcua-binary-create-monitored-items.log
# @TEST-EXEC: btest-diff opcua-binary-create-monitored-items-create-item.log
# @TEST-EXEC: btest-diff opcua-binary-close-session.log
# @TEST-EXEC: btest-diff opcua-binary-create-session.log

#
# @TEST-DOC: Test OPCUA-binary analyzer with small trace.

@load icsnpp/opcua-binary
