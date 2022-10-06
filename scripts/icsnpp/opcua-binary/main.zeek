## main.zeek
##
## OPCUA Binary Protocol Analyzer
##
## Base script layer functionality for processing events emitted from
## the analyzer.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

module ICSNPP_OPCUA_Binary;

export {
	redef enum Log::ID += { LOG, LOG_STATUS_CODE, LOG_DIAG_INFO, LOG_OPENSECURE_CHANNEL, 
                            LOG_GET_ENDPOINTS, LOG_GET_ENDPOINTS_DESCRIPTION, LOG_GET_ENDPOINTS_DISCOVERY,
                            LOG_GET_ENDPOINTS_USER_TOKEN, LOG_GET_ENDPOINTS_LOCALE_ID, LOG_GET_ENDPOINTS_PROFILE_URI,
                            LOG_CREATE_SESSION, LOG_CREATE_SESSION_DISCOVERY, LOG_CREATE_SESSION_ENDPOINTS, LOG_CREATE_SESSION_USER_TOKEN,
                            LOG_ACTIVATE_SESSION, LOG_ACTIVATE_SESSION_CLIENT_SOFTWARE_CERT, LOG_ACTIVATE_SESSION_LOCALE_ID, LOG_ACTIVATE_SESSION_DIAGNOSTIC_INFO, 
                            LOG_BROWSE, LOG_BROWSE_DESCRIPTION, LOG_BROWSE_REQUEST_CONTINUATION_POINT, LOG_BROWSE_RESULT, LOG_BROWSE_RESPONSE_REFERENCES,
                            LOG_BROWSE_DIAGNOSTIC_INFO, LOG_CREATE_SUBSCRIPTION, LOG_CREATE_MONITORED_ITEMS , LOG_CREATE_MONITORED_ITEMS_CREATE_ITEM, 
                            LOG_DATA_CHANGE_FILTER, LOG_AGGREGATE_FILTER, LOG_EVENT_FILTER, LOG_EVENT_FILTER_SELECT_CLAUSE, 
                            LOG_EVENT_FILTER_SELECT_CLAUSE_BROWSE_PATHS, LOG_EVENT_FILTER_CONTENT_FILTER, LOG_EVENT_FILTER_CONTENT_FILTER_ELEMENT,
                            LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND, LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATHS, LOG_EVENT_FILTER_ATTRIBUTE_OPERAND, 
                            LOG_EVENT_FILTER_ATTRIBUTE_OPERAND_BROWSE_PATHS, LOG_EVENT_FILTER_ELEMENT_OPERAND};
}

# Port-based detection
const ports = { 4840/tcp };
redef likely_server_ports += { ports };

event zeek_init() &priority=5
   {
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG,                          [$columns=OPCUA_Binary::Info,                  $path="opcua-binary"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_STATUS_CODE,              [$columns=OPCUA_Binary::StatusCodeDetail,      $path="opcua-binary-status-code-detail"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_DIAG_INFO,                [$columns=OPCUA_Binary::DiagnosticInfoDetail,  $path="opcua-binary-diag-info-detail"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_OPENSECURE_CHANNEL,       [$columns=OPCUA_Binary::OpenSecureChannel,     $path="opcua-binary-opensecure-channel"]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS,             [$columns=OPCUA_Binary::GetEndpoints,            $path="opcua-binary-get-endpoints"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_DESCRIPTION, [$columns=OPCUA_Binary::GetEndpointsDescription, $path="opcua-binary-get-endpoints-description"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_DISCOVERY,   [$columns=OPCUA_Binary::GetEndpointsDiscovery,   $path="opcua-binary-get-endpoints-discovery"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_USER_TOKEN,  [$columns=OPCUA_Binary::GetEndpointsUserToken,   $path="opcua-binary-get-endpoints-user-token"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_LOCALE_ID,   [$columns=OPCUA_Binary::GetEndpointsLocaleId,    $path="opcua-binary-get-endpoints-locale_id"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_PROFILE_URI, [$columns=OPCUA_Binary::GetEndpointsProfileUri,  $path="opcua-binary-get-endpoints-profile_uri"]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION,            [$columns=OPCUA_Binary::CreateSession,          $path="opcua-binary-create-session"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION_DISCOVERY,  [$columns=OPCUA_Binary::CreateSessionDiscovery, $path="opcua-binary-create-session-discovery"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION_ENDPOINTS,  [$columns=OPCUA_Binary::CreateSessionEndpoints, $path="opcua-binary-create-session-endpoints"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION_USER_TOKEN, [$columns=OPCUA_Binary::CreateSessionUserToken, $path="opcua-binary-create-session-user-token"]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION,                       [$columns=OPCUA_Binary::ActivateSession,                   $path="opcua-binary-activate-session"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION_CLIENT_SOFTWARE_CERT,  [$columns=OPCUA_Binary::ActivateSessionClientSoftwareCert, $path="opcua-binary-activate-session-client-software-cert"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION_LOCALE_ID,             [$columns=OPCUA_Binary::ActivateSessionLocaleId,           $path="opcua-binary-activate-session-locale-id"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION_DIAGNOSTIC_INFO,       [$columns=OPCUA_Binary::ActivateSessionDiagnosticInfo,     $path="opcua-binary-activate-session-diagnostic-info"]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE,                            [$columns=OPCUA_Binary::Browse,                         $path="opcua-binary-browse"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE_DESCRIPTION,                [$columns=OPCUA_Binary::BrowseDescription,              $path="opcua-binary-browse-description"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE_REQUEST_CONTINUATION_POINT, [$columns=OPCUA_Binary::BrowseRequestContinuationPoint, $path="opcua-binary-browse-request-continuation-point"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE_RESULT,                     [$columns=OPCUA_Binary::BrowseResult,                   $path="opcua-binary-browse-result"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE_RESPONSE_REFERENCES,        [$columns=OPCUA_Binary::BrowseReference,                $path="opcua-binary-browse-response-references"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE_DIAGNOSTIC_INFO,            [$columns=OPCUA_Binary::BrowseDiagnosticInfo,           $path="opcua-binary-browse-diagnostic-info"]);
    
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_SUBSCRIPTION,        [$columns=OPCUA_Binary::CreateSubscription, $path="opcua-binary-create-subscription"]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_MONITORED_ITEMS,              [$columns=OPCUA_Binary::CreateMonitoredItems, $path="opcua-binary-create-monitored-items"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_MONITORED_ITEMS_CREATE_ITEM,  [$columns=OPCUA_Binary::CreateItemRequest, $path="opcua-binary-create-monitored-items-create-item"]);
   
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_DATA_CHANGE_FILTER,                                 [$columns=OPCUA_Binary::DataChangeFilter, $path="opcua-binary-data-change-filters"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_AGGREGATE_FILTER,                                   [$columns=OPCUA_Binary::AggregateFilter, $path="opcua-binary-aggregate-filters"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER,                                       [$columns=OPCUA_Binary::EventFilter, $path="opcua-binary-event-filters"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SELECT_CLAUSE,                         [$columns=OPCUA_Binary::SimpleAttributeOperand, $path="opcua-binary-event-filters-select-clause"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SELECT_CLAUSE_BROWSE_PATHS,            [$columns=OPCUA_Binary::SimpleAttributeOperandBrowsePaths, $path="opcua-binary-event-filters-select-clause-browse-paths"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_CONTENT_FILTER,                        [$columns=OPCUA_Binary::ContentFilter, $path="opcua-binary-event-filters-where-clause"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_CONTENT_FILTER_ELEMENT,                [$columns=OPCUA_Binary::ContentFilterElement, $path="opcua-binary-event-filters-where-clause-elements"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND,              [$columns=OPCUA_Binary::SimpleAttributeOperand, $path="opcua-binary-event-filters-simple-attribute-operand"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATHS, [$columns=OPCUA_Binary::SimpleAttributeOperandBrowsePaths, $path="opcua-binary-event-filters-simple-attribute-operand-browse-paths"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ATTRIBUTE_OPERAND,                     [$columns=OPCUA_Binary::AttributeOperand, $path="opcua-binary-event-filters-attribute-operand"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ATTRIBUTE_OPERAND_BROWSE_PATHS,        [$columns=OPCUA_Binary::AttributeOperandBrowsePathElement, $path="opcua-binary-event-filters-attribute-operand-browse-paths"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ELEMENT_OPERAND,                       [$columns=OPCUA_Binary::ElementOperand, $path="opcua-binary-event-filters-element-operand"]);

   Analyzer::register_for_ports(Analyzer::ANALYZER_ICSNPP_OPCUA_BINARY, ports);
   }

function set_service(c: connection, service: string) {
  # Ensure that conn.log:service is set if it has not already been
  if ((!c?$service) || (|c$service| == 0))
    add c$service[service];
}

event opcua_binary_event(c: connection, info: OPCUA_Binary::Info)
   {
       set_service(c, "opcua-binary");
       info$ts  = network_time();
       info$uid = c$uid;
       info$id  = c$id;
       Log::write(ICSNPP_OPCUA_Binary::LOG, info);
    }

event opcua_binary_status_code_event(c: connection, status: OPCUA_Binary::StatusCodeDetail)
   {
       set_service(c, "opcua-binary");
       status$ts  = network_time();
       status$uid = c$uid;
       status$id  = c$id;
       Log::write(ICSNPP_OPCUA_Binary::LOG_STATUS_CODE, status);

    }

event opcua_binary_diag_info_event(c: connection, diag_info: OPCUA_Binary::DiagnosticInfoDetail)
   {
       set_service(c, "opcua-binary");
       diag_info$ts  = network_time();
       diag_info$uid = c$uid;
       diag_info$id  = c$id;
       Log::write(ICSNPP_OPCUA_Binary::LOG_DIAG_INFO, diag_info);

    }

event opcua_binary_opensecure_channel_event(c: connection, opensecure_channel: OPCUA_Binary::OpenSecureChannel)
   {
       set_service(c, "opcua-binary");
       opensecure_channel$ts  = network_time();
       opensecure_channel$uid = c$uid;
       opensecure_channel$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_OPENSECURE_CHANNEL, opensecure_channel);

    }

event opcua_binary_get_endpoints_event(c: connection, get_endpoints: OPCUA_Binary::GetEndpoints)
   {
       set_service(c, "opcua-binary");
       get_endpoints$ts  = network_time();
       get_endpoints$uid = c$uid;
       get_endpoints$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS, get_endpoints);

    }

event opcua_binary_get_endpoints_description_event(c: connection, get_endpoints_description: OPCUA_Binary::GetEndpointsDescription)
   {
       set_service(c, "opcua-binary");
       get_endpoints_description$ts  = network_time();
       get_endpoints_description$uid = c$uid;
       get_endpoints_description$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_DESCRIPTION, get_endpoints_description);

    }

event opcua_binary_get_endpoints_discovery_event(c: connection, get_endpoints_discovery: OPCUA_Binary::GetEndpointsDiscovery)
   {
       set_service(c, "opcua-binary");
       get_endpoints_discovery$ts  = network_time();
       get_endpoints_discovery$uid = c$uid;
       get_endpoints_discovery$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_DISCOVERY, get_endpoints_discovery);

    }

event opcua_binary_get_endpoints_user_token_event(c: connection, get_endpoints_user_token: OPCUA_Binary::GetEndpointsUserToken)
   {
       set_service(c, "opcua-binary");
       get_endpoints_user_token$ts  = network_time();
       get_endpoints_user_token$uid = c$uid;
       get_endpoints_user_token$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_USER_TOKEN, get_endpoints_user_token);

    }

event opcua_binary_get_endpoints_locale_id_event(c: connection, get_endpoints_locale_id: OPCUA_Binary::GetEndpointsLocaleId)
   {
       set_service(c, "opcua-binary");
       get_endpoints_locale_id$ts  = network_time();
       get_endpoints_locale_id$uid = c$uid;
       get_endpoints_locale_id$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_LOCALE_ID, get_endpoints_locale_id);

    }

event opcua_binary_get_endpoints_profile_uri_event(c: connection, get_endpoints_profile_uri: OPCUA_Binary::GetEndpointsProfileUri)
   {
       set_service(c, "opcua-binary");
       get_endpoints_profile_uri$ts  = network_time();
       get_endpoints_profile_uri$uid = c$uid;
       get_endpoints_profile_uri$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_PROFILE_URI, get_endpoints_profile_uri);

    }

event opcua_binary_create_session_event(c: connection, create_session: OPCUA_Binary::CreateSession)
   {
       set_service(c, "opcua-binary");
       create_session$ts  = network_time();
       create_session$uid = c$uid;
       create_session$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION, create_session);
   }

event opcua_binary_create_session_discovery_event(c: connection, create_session_discovery: OPCUA_Binary::CreateSessionDiscovery)
   {
       set_service(c, "opcua-binary");
       create_session_discovery$ts  = network_time();
       create_session_discovery$uid = c$uid;
       create_session_discovery$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION_DISCOVERY, create_session_discovery);
   }


event opcua_binary_create_session_endpoints_event(c: connection, create_session_endpoints: OPCUA_Binary::CreateSessionEndpoints)
   {
       set_service(c, "opcua-binary");
       create_session_endpoints$ts  = network_time();
       create_session_endpoints$uid = c$uid;
       create_session_endpoints$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION_ENDPOINTS, create_session_endpoints);
   }

event opcua_binary_create_session_user_token_event(c: connection, create_session_user_token: OPCUA_Binary::CreateSessionUserToken)
   {
       set_service(c, "opcua-binary");
       create_session_user_token$ts  = network_time();
       create_session_user_token$uid = c$uid;
       create_session_user_token$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION_USER_TOKEN, create_session_user_token);
   }

event opcua_binary_activate_session_event(c: connection, activate_session: OPCUA_Binary::ActivateSession)
    {
       set_service(c, "opcua-binary");
       activate_session$ts  = network_time();
       activate_session$uid = c$uid;
       activate_session$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION, activate_session);
    }

event opcua_binary_activate_session_client_software_cert_event(c: connection, activate_session_client_software_cert: OPCUA_Binary::ActivateSessionClientSoftwareCert)
    {
       set_service(c, "opcua-binary");
       activate_session_client_software_cert$ts  = network_time();
       activate_session_client_software_cert$uid = c$uid;
       activate_session_client_software_cert$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION_CLIENT_SOFTWARE_CERT, activate_session_client_software_cert);
    }

event opcua_binary_activate_session_locale_id_event(c: connection, activate_session_locale_id: OPCUA_Binary::ActivateSessionLocaleId)
    {
       set_service(c, "opcua-binary");
       activate_session_locale_id$ts  = network_time();
       activate_session_locale_id$uid = c$uid;
       activate_session_locale_id$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION_LOCALE_ID, activate_session_locale_id);
    }

event opcua_binary_activate_session_diagnostic_info_event(c: connection, activate_session_diagnostic_info: OPCUA_Binary::ActivateSessionDiagnosticInfo)
    {
       set_service(c, "opcua-binary");
       activate_session_diagnostic_info$ts  = network_time();
       activate_session_diagnostic_info$uid = c$uid;
       activate_session_diagnostic_info$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION_DIAGNOSTIC_INFO, activate_session_diagnostic_info);
    }
event opcua_binary_browse_event(c: connection, browse_event: OPCUA_Binary::Browse)
   {
       set_service(c, "opcua-binary");
       browse_event$ts  = network_time();
       browse_event$uid = c$uid;
       browse_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_BROWSE, browse_event);
   }

event opcua_binary_browse_description_event(c: connection, browse_description_event: OPCUA_Binary::BrowseDescription)
   {
       set_service(c, "opcua-binary");
       browse_description_event$ts  = network_time();
       browse_description_event$uid = c$uid;
       browse_description_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_BROWSE_DESCRIPTION, browse_description_event);
   }

event opcua_binary_browse_request_continuation_point_event(c: connection, browse_request_continuation_point: OPCUA_Binary::BrowseRequestContinuationPoint)
    {
       set_service(c, "opcua-binary");
       browse_request_continuation_point$ts  = network_time();
       browse_request_continuation_point$uid = c$uid;
       browse_request_continuation_point$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_BROWSE_REQUEST_CONTINUATION_POINT, browse_request_continuation_point);
    }

event opcua_binary_browse_result_event(c: connection, browse_result_event: OPCUA_Binary::BrowseResult)
    {
       set_service(c, "opcua-binary");
       browse_result_event$ts  = network_time();
       browse_result_event$uid = c$uid;
       browse_result_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_BROWSE_RESULT, browse_result_event);
   }


event opcua_binary_browse_reference_event(c: connection, browse_reference_event: OPCUA_Binary::BrowseReference)
   {
       set_service(c, "opcua-binary");
       browse_reference_event$ts  = network_time();
       browse_reference_event$uid = c$uid;
       browse_reference_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_BROWSE_RESPONSE_REFERENCES, browse_reference_event);
   }

event opcua_binary_browse_diagnostic_info_event(c: connection, browse_diagnostic_info: OPCUA_Binary::BrowseDiagnosticInfo)
   {
       set_service(c, "opcua-binary");
       browse_diagnostic_info$ts  = network_time();
       browse_diagnostic_info$uid = c$uid;
       browse_diagnostic_info$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_BROWSE_DIAGNOSTIC_INFO, browse_diagnostic_info);
    }

event opcua_binary_create_subscription_event(c: connection, create_subscription_event: OPCUA_Binary::CreateSubscription)
   {
       set_service(c, "opcua-binary");
       create_subscription_event$ts  = network_time();
       create_subscription_event$uid = c$uid;
       create_subscription_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CREATE_SUBSCRIPTION, create_subscription_event);
   }

event opcua_binary_create_monitored_items_event(c: connection, create_monitored_items_event: OPCUA_Binary::CreateMonitoredItems)
   {
       set_service(c, "opcua-binary");
       create_monitored_items_event$ts  = network_time();
       create_monitored_items_event$uid = c$uid;
       create_monitored_items_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CREATE_MONITORED_ITEMS, create_monitored_items_event);
   }
event opcua_binary_create_monitored_items_create_item_event(c: connection, create_monitored_items_create_item_event: OPCUA_Binary::CreateItemRequest)
    {
       set_service(c, "opcua-binary");
       create_monitored_items_create_item_event$ts  = network_time();
       create_monitored_items_create_item_event$uid = c$uid;
       create_monitored_items_create_item_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CREATE_MONITORED_ITEMS_CREATE_ITEM, create_monitored_items_create_item_event);
    }
event opcua_binary_data_change_filter_event(c: connection, data_change_filter_event: OPCUA_Binary::DataChangeFilter){
       set_service(c, "opcua-binary");
       data_change_filter_event$ts  = network_time();
       data_change_filter_event$uid = c$uid;
       data_change_filter_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_DATA_CHANGE_FILTER, data_change_filter_event);
}
event opcua_binary_aggregate_filter_event(c: connection, aggregate_filter_event: OPCUA_Binary::AggregateFilter){
       set_service(c, "opcua-binary");
       aggregate_filter_event$ts  = network_time();
       aggregate_filter_event$uid = c$uid;
       aggregate_filter_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_AGGREGATE_FILTER, aggregate_filter_event);
}
event opcua_binary_event_filter_event(c: connection, event_filter_details_event: OPCUA_Binary::EventFilter){
       set_service(c, "opcua-binary");
       event_filter_details_event$ts  = network_time();
       event_filter_details_event$uid = c$uid;
       event_filter_details_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER, event_filter_details_event);
}
event opcua_binary_event_filter_select_clauses_event(c: connection, select_clause_event: OPCUA_Binary::SimpleAttributeOperand){
       set_service(c, "opcua-binary");
       select_clause_event$ts  = network_time();
       select_clause_event$uid = c$uid;
       select_clause_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SELECT_CLAUSE, select_clause_event);
}
event opcua_binary_event_filter_select_clauses_browse_path_event(c: connection, select_clause_browse_path_event: OPCUA_Binary::SimpleAttributeOperandBrowsePaths){
       set_service(c, "opcua-binary");
       select_clause_browse_path_event$ts  = network_time();
       select_clause_browse_path_event$uid = c$uid;
       select_clause_browse_path_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SELECT_CLAUSE_BROWSE_PATHS, select_clause_browse_path_event);
}
event opcua_binary_event_filter_content_filter_event(c: connection, content_filter_event: OPCUA_Binary::ContentFilter){
       set_service(c, "opcua-binary");
       content_filter_event$ts  = network_time();
       content_filter_event$uid = c$uid;
       content_filter_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_CONTENT_FILTER, content_filter_event);
}
event opcua_binary_event_filter_content_filter_element_event(c: connection, content_filter_element_event: OPCUA_Binary::ContentFilterElement){
       set_service(c, "opcua-binary");
       content_filter_element_event$ts  = network_time();
       content_filter_element_event$uid = c$uid;
       content_filter_element_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_CONTENT_FILTER_ELEMENT, content_filter_element_event);
}
event opcua_binary_event_filter_simple_attribute_operand_event(c: connection, simple_attribute_operand_event: OPCUA_Binary::SimpleAttributeOperand){
       set_service(c, "opcua-binary");
       simple_attribute_operand_event$ts  = network_time();
       simple_attribute_operand_event$uid = c$uid;
       simple_attribute_operand_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND, simple_attribute_operand_event);
}
event opcua_binary_event_filter_simple_attribute_operand_browse_path_event(c: connection, simple_attribute_operand_browse_path_event: OPCUA_Binary::SimpleAttributeOperandBrowsePaths){
       set_service(c, "opcua-binary");
       simple_attribute_operand_browse_path_event$ts  = network_time();
       simple_attribute_operand_browse_path_event$uid = c$uid;
       simple_attribute_operand_browse_path_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATHS, simple_attribute_operand_browse_path_event);
}
event opcua_binary_event_filter_attribute_operand_event(c: connection, attribute_operand_event: OPCUA_Binary::AttributeOperand){
       set_service(c, "opcua-binary");
       attribute_operand_event$ts  = network_time();
       attribute_operand_event$uid = c$uid;
       attribute_operand_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ATTRIBUTE_OPERAND, attribute_operand_event);
}
event opcua_binary_event_filter_attribute_operand_browse_path_element_event(c: connection, attribute_operand_browse_path_event: OPCUA_Binary::AttributeOperandBrowsePathElement){
       set_service(c, "opcua-binary");
       attribute_operand_browse_path_event$ts  = network_time();
       attribute_operand_browse_path_event$uid = c$uid;
       attribute_operand_browse_path_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ATTRIBUTE_OPERAND_BROWSE_PATHS, attribute_operand_browse_path_event);
}
event opcua_binary_event_filter_element_operand_event(c: connection, element_operand_event: OPCUA_Binary::ElementOperand){
       set_service(c, "opcua-binary");
       element_operand_event$ts  = network_time();
       element_operand_event$uid = c$uid;
       element_operand_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ELEMENT_OPERAND, element_operand_event);
}