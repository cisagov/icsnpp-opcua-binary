##! main.zeek
##!
##! OPCUA Binary Protocol Analyzer
##!
##! Base script layer functionality for processing events emitted from
##! the analyzer.
##!
##! Author:   Kent Kvarfordt
##! Contact:  kent.kvarfordt@inl.gov
##!
##! Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

module ICSNPP_OPCUA_Binary;

export {
	redef enum Log::ID += { LOG,                                                     LOG_STATUS_CODE,                                         LOG_DIAG_INFO,
                           LOG_AGGREGATE_FILTER,                                    LOG_DATA_CHANGE_FILTER,                                  LOG_EVENT_FILTER,
                           LOG_EVENT_FILTER_ATTRIBUTE_OPERAND,                      LOG_EVENT_FILTER_ATTRIBUTE_OPERAND_BROWSE_PATHS,         LOG_EVENT_FILTER_CONTENT_FILTER,
                           LOG_EVENT_FILTER_CONTENT_FILTER_ELEMENT,                 LOG_EVENT_FILTER_ELEMENT_OPERAND,                        LOG_EVENT_FILTER_LITERAL_OPERAND,
                          	LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND,               LOG_EVENT_FILTER_SELECT_CLAUSE,                          LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATHS,
                           LOG_VARIANT_ARRAY_DIMS,                                  LOG_VARIANT_DATA,                                        LOG_VARIANT_DATA_VALUE,
                           LOG_VARIANT_EXTENSION_OBJECT,                            LOG_VARIANT_METADATA,                                    LOG_ACTIVATE_SESSION,
                           LOG_ACTIVATE_SESSION_CLIENT_SOFTWARE_CERT,               LOG_ACTIVATE_SESSION_LOCALE_ID,                          LOG_BROWSE,
                           LOG_BROWSE_DESCRIPTION,                                  LOG_BROWSE_RESPONSE_REFERENCES,                          LOG_BROWSE_REQUEST_CONTINUATION_POINT,
                           LOG_BROWSE_RESULT,                                       LOG_CLOSE_SESSION,                                       LOG_CREATE_MONITORED_ITEMS,
                           LOG_CREATE_MONITORED_ITEMS_CREATE_ITEM,                  LOG_CREATE_SESSION,                                      LOG_CREATE_SESSION_DISCOVERY,
                           LOG_CREATE_SESSION_ENDPOINTS,                            LOG_CREATE_SESSION_USER_TOKEN,                           LOG_CREATE_SUBSCRIPTION,
                           LOG_GET_ENDPOINTS,                                       LOG_GET_ENDPOINTS_DESCRIPTION,                           LOG_GET_ENDPOINTS_DISCOVERY,
                           LOG_GET_ENDPOINTS_USER_TOKEN,                            LOG_GET_ENDPOINTS_LOCALE_ID,                             LOG_GET_ENDPOINTS_PROFILE_URI,
                           LOG_READ,                                                LOG_READ_NODES_TO_READ,                                  LOG_READ_RESULTS,
                           LOG_WRITE,                                               LOG_OPENSECURE_CHANNEL
                         };

   ## Log policies, for log filtering.
   global log_policy_opcua_binary: Log::PolicyHook;
   global log_policy_diag_info_detail: Log::PolicyHook;
   global log_policy_status_code_detail: Log::PolicyHook;
   global log_policy_aggregate_filter: Log::PolicyHook;
   global log_policy_data_change_filter: Log::PolicyHook;

   global log_policy_event_filter: Log::PolicyHook;
   global log_policy_event_filter_attribute_operand: Log::PolicyHook;
   global log_policy_event_filter_attribute_operand_browse_paths: Log::PolicyHook;
   global log_policy_event_filter_where_clause: Log::PolicyHook;
   global log_policy_event_filter_where_clause_elements: Log::PolicyHook;
   global log_policy_event_filter_element_operand: Log::PolicyHook;
   global log_policy_event_filter_literal_operand: Log::PolicyHook;
   global log_policy_event_filter_select_clause: Log::PolicyHook;
   global log_policy_event_filter_simple_attribute_operand: Log::PolicyHook;
   global log_policy_event_filter_simple_attribute_operand_browse_paths: Log::PolicyHook;

   global log_policy_variant_array_dims: Log::PolicyHook;
   global log_policy_variant_data: Log::PolicyHook;
   global log_policy_variant_data_value: Log::PolicyHook;
   global log_policy_variant_extension_object: Log::PolicyHook;
   global log_policy_variant_metadata: Log::PolicyHook;

   global log_policy_activate_session: Log::PolicyHook;
   global log_policy_activate_session_client_software_cert: Log::PolicyHook;
   global log_policy_activate_session_locale_id: Log::PolicyHook;

   global log_policy_browse: Log::PolicyHook;
   global log_policy_browse_description: Log::PolicyHook;
   global log_policy_browse_request_continuation_point: Log::PolicyHook;
   global log_policy_browse_result: Log::PolicyHook;
   global log_policy_browse_response_references: Log::PolicyHook;

   global log_policy_close_session: Log::PolicyHook;

   global log_policy_create_monitored_items: Log::PolicyHook;
   global log_policy_create_monitored_items_create_item: Log::PolicyHook;

   global log_policy_create_session: Log::PolicyHook;
   global log_policy_create_session_discovery: Log::PolicyHook;
   global log_policy_create_session_endpoints: Log::PolicyHook;
   global log_policy_create_session_user_token: Log::PolicyHook;

   global log_policy_create_subscription: Log::PolicyHook;

   global log_policy_get_endpoints: Log::PolicyHook;
   global log_policy_get_endpoints_description: Log::PolicyHook;
   global log_policy_get_endpoints_discovery: Log::PolicyHook;
   global log_policy_get_endpoints_user_token: Log::PolicyHook;
   global log_policy_get_endpoints_locale_id: Log::PolicyHook;
   global log_policy_get_endpoints_profile_uri: Log::PolicyHook;

   global log_policy_read: Log::PolicyHook;
   global log_policy_read_nodes_to_read: Log::PolicyHook;
   global log_policy_read_results: Log::PolicyHook;

   global log_policy_write: Log::PolicyHook;

   global log_policy_opensecure_channel: Log::PolicyHook;

   type State: record {
		## Pending requests, keyed by opcua request_id. See types.zeek for more information.
		pending_requests:  table[count] of OPCUA_Binary::Info;
		## Pending responses, keyed by opcua request_id. See types.zeek for more information.
		pending_responses: table[count] of OPCUA_Binary::Info;
	};
}

# Port-based detection
const ports = { 4840/tcp, 4843/tcp };
redef likely_server_ports += { ports };

redef record connection += {
	opcua_binary_state:  State &optional;
};

# Whether or not we are mapping request and response fields to the log record
# If we are we will omit the response timestamp from the log record
const MAPPING_REQ_RES = T;

const MAX_PENDING_REQUESTS = 256; # Arbitrary number
const MAX_PENDING_RESPONSES = 256; # Arbitrary number
const REQUEST_IDENTIFIER = "Request";
const RESPONSE_IDENTIFIER = "Response";
global GLOBAL_PENDING_REQUESTS_COUNT = 0;
global GLOBAL_PENDING_RESPONSES_COUNT = 0;

# Description: Determines if incoming message is a request or response
# Returns: bool
function check_message_type(info: OPCUA_Binary::Info, message_type: string) : bool
{
   if ( message_type == REQUEST_IDENTIFIER ) {
      if (info?$identifier_str && REQUEST_IDENTIFIER in info$identifier_str) {
         return T;
      }
   }
   else if ( message_type == RESPONSE_IDENTIFIER ) {
      if (info?$identifier_str && RESPONSE_IDENTIFIER in info$identifier_str) {
         return T;
      }
   }

   return F;
}

# Description: Adds a pending request to the connection's pending requests table, return true
# If we have too many pending requests, return false
# Returns: bool
function add_pending_request(c: connection, info: OPCUA_Binary::Info) : bool
{
   if ( GLOBAL_PENDING_REQUESTS_COUNT >= MAX_PENDING_REQUESTS ) {
      return F;
   }

   if ( info$request_id in c$opcua_binary_state$pending_requests ) {
      return F;
   }
   ++GLOBAL_PENDING_REQUESTS_COUNT;
   c$opcua_binary_state$pending_requests[info$request_id] = info;
   return T;
}

# Description: Adds a pending response to the connection's pending responses table, return true
# If we have too many pending responses, return false
# Returns: bool
function add_pending_response(c: connection, info: OPCUA_Binary::Info) : bool
{
   if ( GLOBAL_PENDING_RESPONSES_COUNT >= MAX_PENDING_RESPONSES ) {
      return F;
   }
   ++GLOBAL_PENDING_RESPONSES_COUNT;
   if ( info$request_id in c$opcua_binary_state$pending_responses ) {
      return F;
   }
   c$opcua_binary_state$pending_responses[info$request_id] = info;
   return T;
}

# Description: Copies common data from an info object to a logging record
# Returns: OPCUA_Binary::Info_Log
function copy_common_data_to_logging_record(info: OPCUA_Binary::Info): OPCUA_Binary::Info_Log
{
   local log_info = OPCUA_Binary::Info_Log(
      $ts               = info$ts,
      $uid              = info$uid,
      $id               = info$id,
      $msg_type         = info$msg_type,
      $is_final         = info$is_final,
      $total_size       = info$msg_size
   );

   return log_info;
}

# Description: Logs a message
function log_message(c: connection, info: OPCUA_Binary::Info)
{
   local log_info = copy_common_data_to_logging_record(info);

   if (info?$error) {log_info$error = info$error;}
   if (info?$reason) {log_info$reason = info$reason;}
   if (info?$version) {log_info$version = info$version;}
   if (info?$rcv_buf_size) {log_info$rcv_buf_size = info$rcv_buf_size;}
   if (info?$snd_buf_size) {log_info$snd_buf_size = info$snd_buf_size;}
   if (info?$max_msg_size) {log_info$max_msg_size = info$max_msg_size;}
   if (info?$max_chunk_cnt) {log_info$max_chunk_cnt = info$max_chunk_cnt;}
   if (info?$endpoint_url) {log_info$endpoint_url = info$endpoint_url;}

   Log::write(ICSNPP_OPCUA_Binary::LOG, log_info);
}


# Description: Determines if incoming message is a request or response and adds it to the corresponding pending requests or responses table
# If we have too many pending requests or responses then log the message immediately
function handle_add_pending(c: connection, info: OPCUA_Binary::Info)
{
   if (check_message_type(info, REQUEST_IDENTIFIER)) {
      if ( !add_pending_request(c, info) ) {
         log_message(c, info);
      }
   }
   else {
      if ( !add_pending_response(c, info) ) {
         log_message(c, info);
      }
   }
}

# Description: Removes a pending request from the connection's pending requests table, return true
# If the request is not in the table, return false
# Returns: bool
function remove_pending_request(c: connection, request_info: OPCUA_Binary::Info) : bool
{
   if ( request_info$request_id in c$opcua_binary_state$pending_requests ) {
      delete c$opcua_binary_state$pending_requests[request_info$request_id];
      --GLOBAL_PENDING_REQUESTS_COUNT;
      return T;
   }
   return F;
}

# Description: Removes a pending response from the connection's pending responses table, return true
# If the response is not in the table, return false
# Returns: bool
function remove_pending_response(c: connection, response_info: OPCUA_Binary::Info) : bool
{
   if ( response_info$request_id in c$opcua_binary_state$pending_responses ) {
      delete c$opcua_binary_state$pending_responses[response_info$request_id];
      --GLOBAL_PENDING_RESPONSES_COUNT;
      return T;
   }
   return F;
}

# Description: Performs a deep comparison of two conn_ids
# Returns: bool
function compare_conn_ids(conn_id1: conn_id, conn_id2: conn_id): bool
{
   return (conn_id1$orig_h == conn_id2$orig_h)
          && (conn_id1$orig_p == conn_id2$orig_p)
          && (conn_id1$resp_h == conn_id2$resp_h)
          && (conn_id1$resp_p == conn_id2$resp_p);
}

# Description: Strips the trailing "Request" or "Response" from an identifier string and returns the identifier without the trailing "Request" or "Response"
# Example: "WriteRequest" -> "Write", "ReadResponse" -> "Read"
# Returns: string
function strip_identifier(identifier: string, is_request: bool): string
{
   local REQUEST_SIZE = |REQUEST_IDENTIFIER|;
   local RESPONSE_SIZE = |RESPONSE_IDENTIFIER|;

   if (is_request) {
      return identifier[:(|identifier| - REQUEST_SIZE)];
   }
   return identifier[:(|identifier| - RESPONSE_SIZE)];
}

# Description: Performs a string comparison of two stripped identifiers
# Returns: bool
function compare_stripped_identifiers(identifier1: string, identifier2: string): bool
{
   return strip_identifier(identifier1, T) == strip_identifier(identifier2, F);
}

# Description: Performs a deep comparison of a request info object and a response info object on all fields except for the response timestamp
# Returns: bool
function check_matching_common(request_info: OPCUA_Binary::Info, response_info: OPCUA_Binary::Info): bool
{
   if (!compare_stripped_identifiers(request_info$identifier_str, response_info$identifier_str)) {
      return F;
   }
   if (request_info$uid != response_info$uid) {
      return F;
   }
   if (!compare_conn_ids(request_info$id, response_info$id)) {
      return F;
   }
   if (request_info$msg_type != response_info$msg_type) {
      return F;
   }
   if (request_info$is_final != response_info$is_final) {
      return F;
   }
   return T;
}

# Description: Maps response fields to a logging record
# Returns: OPCUA_Binary::Info_Log
function map_response(response_info: OPCUA_Binary::Info, log_info: OPCUA_Binary::Info_Log, mapping_req_res: bool): OPCUA_Binary::Info_Log
{
   if (response_info?$opcua_link_id){
      log_info$res_opcua_link_id = response_info$opcua_link_id;
   }
   if (response_info?$msg_size){
      log_info$res_msg_size = response_info$msg_size;
   }
   if (response_info?$seq_number){
      log_info$res_seq_number = response_info$seq_number;
   }
   if (response_info?$encoding_mask){
      log_info$res_encoding_mask = response_info$encoding_mask;
   }
   if (response_info?$namespace_idx){
      log_info$res_namespace_idx = response_info$namespace_idx;
   }
   if (response_info?$identifier){
      log_info$res_identifier = response_info$identifier;
   }
   if (response_info?$identifier_str){
      log_info$res_identifier_str = response_info$identifier_str;
   }
   # if we are mapping both req and res use the req's timestamp as the sole timestamp, else log the res's timestamp
   if ( !mapping_req_res && response_info?$res_hdr_timestamp){
      log_info$res_hdr_timestamp = response_info$res_hdr_timestamp;
   }
   if (response_info?$res_hdr_request_handle){
      log_info$res_hdr_request_handle = response_info$res_hdr_request_handle;
   }
   if (response_info?$status_code_link_id){
      log_info$status_code_link_id = response_info$status_code_link_id;
   }
   if (response_info?$res_hdr_service_diag_encoding){
      log_info$res_hdr_service_diag_encoding = response_info$res_hdr_service_diag_encoding;
   }
   if (response_info?$res_hdr_add_hdr_type_id){
      log_info$res_hdr_add_hdr_type_id = response_info$res_hdr_add_hdr_type_id;
   }
   if (response_info?$res_hdr_add_hdr_enc_mask){
      log_info$res_hdr_add_hdr_enc_mask = response_info$res_hdr_add_hdr_enc_mask;
   }
   return log_info;
}

# Description: Maps request fields to a logging record
# Returns: OPCUA_Binary::Info_Log
function map_request(request_info: OPCUA_Binary::Info, log_info: OPCUA_Binary::Info_Log): OPCUA_Binary::Info_Log
{
   if (request_info?$opcua_link_id){
      log_info$req_opcua_link_id = request_info$opcua_link_id;
   }
   if (request_info?$msg_size){
      log_info$req_msg_size = request_info$msg_size;
   }
   if (request_info?$seq_number){
      log_info$req_seq_number = request_info$seq_number;
   }
   if (request_info?$encoding_mask){
      log_info$req_encoding_mask = request_info$encoding_mask;
   }
   if (request_info?$namespace_idx){
      log_info$req_namespace_idx = request_info$namespace_idx;
   }
   if (request_info?$identifier){
      log_info$req_identifier = request_info$identifier;
   }
   if (request_info?$identifier_str){
      log_info$req_identifier_str = request_info$identifier_str;
   }
   if (request_info?$req_hdr_node_id_type){
      log_info$req_hdr_node_id_type = request_info$req_hdr_node_id_type;
   }
   if (request_info?$req_hdr_node_id_namespace_idx){
      log_info$req_hdr_node_id_namespace_idx = request_info$req_hdr_node_id_namespace_idx;
   }
   if (request_info?$req_hdr_node_id_numeric){
      log_info$req_hdr_node_id_numeric = request_info$req_hdr_node_id_numeric;
   }
   if (request_info?$req_hdr_node_id_string){
      log_info$req_hdr_node_id_string = request_info$req_hdr_node_id_string;
   }
   if (request_info?$req_hdr_node_id_guid){
      log_info$req_hdr_node_id_guid = request_info$req_hdr_node_id_guid;
   }
   if (request_info?$req_hdr_node_id_opaque){
      log_info$req_hdr_node_id_opaque = request_info$req_hdr_node_id_opaque;
   }
   if (request_info?$req_hdr_timestamp){
      log_info$req_hdr_timestamp = request_info$req_hdr_timestamp;
   }
   if (request_info?$req_hdr_request_handle){
      log_info$req_hdr_request_handle = request_info$req_hdr_request_handle;
   }
   if (request_info?$req_hdr_return_diag){
      log_info$req_hdr_return_diag = request_info$req_hdr_return_diag;
   }
   if (request_info?$req_hdr_audit_entry_id){
      log_info$req_hdr_audit_entry_id = request_info$req_hdr_audit_entry_id;
   }
   if (request_info?$req_hdr_timeout_hint){
      log_info$req_hdr_timeout_hint = request_info$req_hdr_timeout_hint;
   }
   if (request_info?$req_hdr_add_hdr_type_id){
      log_info$req_hdr_add_hdr_type_id = request_info$req_hdr_add_hdr_type_id;
   }
   if (request_info?$req_hdr_add_hdr_enc_mask){
      log_info$req_hdr_add_hdr_enc_mask = request_info$req_hdr_add_hdr_enc_mask;
   }
   return log_info;
}

# Description: Maps request and response fields to a logging record
# Returns: OPCUA_Binary::Info_Log
function map_request_response(request_info: OPCUA_Binary::Info, response_info: OPCUA_Binary::Info): OPCUA_Binary::Info_Log
{
   # calculate total size
   local total_size = request_info$msg_size + response_info$msg_size;

   # create log info
   local log_info = copy_common_data_to_logging_record(request_info);
   log_info$total_size = total_size;

   # map fields from request and response
   log_info = map_request(request_info, log_info);
   log_info = map_response(response_info, log_info, MAPPING_REQ_RES);

   return log_info;
}

function set_service(c: connection, service: string)
{
   # Ensure that conn.log:service is set if it has not already been
   if ((!c?$service) || (|c$service| == 0))
   add c$service[service];
}

# Description: Processes a pending request from the State table
function handle_pending_request(c: connection, response_info: OPCUA_Binary::Info)
{
   local request_info = c$opcua_binary_state$pending_requests[response_info$request_id];

   local log_info = copy_common_data_to_logging_record(request_info);
   log_info = map_request_response(request_info, response_info);
   Log::write(ICSNPP_OPCUA_Binary::LOG, log_info);
   remove_pending_request(c, c$opcua_binary_state$pending_requests[response_info$request_id]);
}

# Description: Processes a pending response from the State table
function handle_pending_response(c: connection, request_info: OPCUA_Binary::Info)
{
   local response_info = c$opcua_binary_state$pending_responses[request_info$request_id];
   local log_info = copy_common_data_to_logging_record(request_info);
   log_info = map_request_response(request_info, response_info);
   Log::write(ICSNPP_OPCUA_Binary::LOG, log_info);
   remove_pending_response(c, c$opcua_binary_state$pending_responses[request_info$request_id]);
}

event zeek_init() &priority=5
{
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG,                                                     [$columns=OPCUA_Binary::Info_Log,                           $path="opcua_binary",                                                    $policy=log_policy_opcua_binary]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_DIAG_INFO,                                           [$columns=OPCUA_Binary::DiagnosticInfoDetail,               $path="opcua_binary_diag_info_detail",                                   $policy=log_policy_diag_info_detail]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_STATUS_CODE,                                         [$columns=OPCUA_Binary::StatusCodeDetail,                   $path="opcua_binary_status_code_detail",                                 $policy=log_policy_status_code_detail]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_AGGREGATE_FILTER,                                    [$columns=OPCUA_Binary::AggregateFilter,                    $path="opcua_binary_aggregate_filter",                                   $policy=log_policy_aggregate_filter]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_DATA_CHANGE_FILTER,                                  [$columns=OPCUA_Binary::DataChangeFilter,                   $path="opcua_binary_data_change_filter",                                 $policy=log_policy_data_change_filter]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER,                                        [$columns=OPCUA_Binary::EventFilter,                        $path="opcua_binary_event_filter",                                       $policy=log_policy_event_filter]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ATTRIBUTE_OPERAND,                      [$columns=OPCUA_Binary::AttributeOperand,                   $path="opcua_binary_event_filter_attribute_operand",                     $policy=log_policy_event_filter_attribute_operand]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ATTRIBUTE_OPERAND_BROWSE_PATHS,         [$columns=OPCUA_Binary::AttributeOperandBrowsePathElement,  $path="opcua_binary_event_filter_attribute_operand_browse_paths",        $policy=log_policy_event_filter_attribute_operand_browse_paths]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_CONTENT_FILTER,                         [$columns=OPCUA_Binary::ContentFilter,                      $path="opcua_binary_event_filter_where_clause",                          $policy=log_policy_event_filter_where_clause]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_CONTENT_FILTER_ELEMENT,                 [$columns=OPCUA_Binary::ContentFilterElement,               $path="opcua_binary_event_filter_where_clause_elements",                 $policy=log_policy_event_filter_where_clause_elements]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ELEMENT_OPERAND,                        [$columns=OPCUA_Binary::ElementOperand,                     $path="opcua_binary_event_filter_element_operand",                       $policy=log_policy_event_filter_element_operand]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_LITERAL_OPERAND,                        [$columns=OPCUA_Binary::LiteralOperand,                     $path="opcua_binary_event_filter_literal_operand",                       $policy=log_policy_event_filter_literal_operand]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SELECT_CLAUSE,                          [$columns=OPCUA_Binary::SelectClause,                       $path="opcua_binary_event_filter_select_clause",                         $policy=log_policy_event_filter_select_clause]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND,               [$columns=OPCUA_Binary::SimpleAttributeOperand,             $path="opcua_binary_event_filter_simple_attribute_operand",              $policy=log_policy_event_filter_simple_attribute_operand]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATHS,  [$columns=OPCUA_Binary::SimpleAttributeOperandBrowsePaths,  $path="opcua_binary_event_filter_simple_attribute_operand_browse_paths", $policy=log_policy_event_filter_simple_attribute_operand_browse_paths]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_VARIANT_ARRAY_DIMS,                                  [$columns=OPCUA_Binary::VariantArrayDims,                   $path="opcua_binary_variant_array_dims",                                 $policy=log_policy_variant_array_dims]) ;
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_VARIANT_DATA,                                        [$columns=OPCUA_Binary::VariantData,                        $path="opcua_binary_variant_data",                                       $policy=log_policy_variant_data]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_VARIANT_DATA_VALUE,                                  [$columns=OPCUA_Binary::VariantDataValue,                   $path="opcua_binary_variant_data_value",                                 $policy=log_policy_variant_data_value]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_VARIANT_EXTENSION_OBJECT,                            [$columns=OPCUA_Binary::VariantExtensionObject,             $path="opcua_binary_variant_extension_object",                           $policy=log_policy_variant_extension_object]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_VARIANT_METADATA,                                    [$columns=OPCUA_Binary::VariantMetadata,                    $path="opcua_binary_variant_metadata",                                   $policy=log_policy_variant_metadata]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION,                                    [$columns=OPCUA_Binary::ActivateSession,                    $path="opcua_binary_activate_session",                                   $policy=log_policy_activate_session]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION_CLIENT_SOFTWARE_CERT,               [$columns=OPCUA_Binary::ActivateSessionClientSoftwareCert,  $path="opcua_binary_activate_session_client_software_cert",              $policy=log_policy_activate_session_client_software_cert]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_ACTIVATE_SESSION_LOCALE_ID,                          [$columns=OPCUA_Binary::ActivateSessionLocaleId,            $path="opcua_binary_activate_session_locale_id",                         $policy=log_policy_activate_session_locale_id]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE,                                              [$columns=OPCUA_Binary::Browse,                             $path="opcua_binary_browse",                                             $policy=log_policy_browse]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE_DESCRIPTION,                                  [$columns=OPCUA_Binary::BrowseDescription,                  $path="opcua_binary_browse_description",                                 $policy=log_policy_browse_description]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE_REQUEST_CONTINUATION_POINT,                   [$columns=OPCUA_Binary::BrowseRequestContinuationPoint,     $path="opcua_binary_browse_request_continuation_point",                  $policy=log_policy_browse_request_continuation_point]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE_RESULT,                                       [$columns=OPCUA_Binary::BrowseResult,                       $path="opcua_binary_browse_result",                                      $policy=log_policy_browse_result]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_BROWSE_RESPONSE_REFERENCES,                          [$columns=OPCUA_Binary::BrowseReference,                    $path="opcua_binary_browse_response_references",                         $policy=log_policy_browse_response_references]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CLOSE_SESSION,                                       [$columns=OPCUA_Binary::CloseSession,                       $path="opcua_binary_close_session",                                      $policy=log_policy_close_session]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_MONITORED_ITEMS,                              [$columns=OPCUA_Binary::CreateMonitoredItems,               $path="opcua_binary_create_monitored_items",                             $policy=log_policy_create_monitored_items]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_MONITORED_ITEMS_CREATE_ITEM,                  [$columns=OPCUA_Binary::CreateMonitoredItemsItem,           $path="opcua_binary_create_monitored_items_create_item",                 $policy=log_policy_create_monitored_items_create_item]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION,                                      [$columns=OPCUA_Binary::CreateSession,                      $path="opcua_binary_create_session",                                     $policy=log_policy_create_session]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION_DISCOVERY,                            [$columns=OPCUA_Binary::CreateSessionDiscovery,             $path="opcua_binary_create_session_discovery",                           $policy=log_policy_create_session_discovery]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION_ENDPOINTS,                            [$columns=OPCUA_Binary::CreateSessionEndpoints,             $path="opcua_binary_create_session_endpoints",                           $policy=log_policy_create_session_endpoints]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_SESSION_USER_TOKEN,                           [$columns=OPCUA_Binary::CreateSessionUserToken,             $path="opcua_binary_create_session_user_token",                          $policy=log_policy_create_session_user_token]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_CREATE_SUBSCRIPTION,                                 [$columns=OPCUA_Binary::CreateSubscription,                 $path="opcua_binary_create_subscription",                                $policy=log_policy_create_subscription]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS,                                       [$columns=OPCUA_Binary::GetEndpoints,                       $path="opcua_binary_get_endpoints",                                      $policy=log_policy_get_endpoints]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_DESCRIPTION,                           [$columns=OPCUA_Binary::GetEndpointsDescription,            $path="opcua_binary_get_endpoints_description",                          $policy=log_policy_get_endpoints_description]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_DISCOVERY,                             [$columns=OPCUA_Binary::GetEndpointsDiscovery,              $path="opcua_binary_get_endpoints_discovery",                            $policy=log_policy_get_endpoints_discovery]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_USER_TOKEN,                            [$columns=OPCUA_Binary::GetEndpointsUserToken,              $path="opcua_binary_get_endpoints_user_token",                           $policy=log_policy_get_endpoints_user_token]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_LOCALE_ID,                             [$columns=OPCUA_Binary::GetEndpointsLocaleId,               $path="opcua_binary_get_endpoints_locale_id",                            $policy=log_policy_get_endpoints_locale_id]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_PROFILE_URI,                           [$columns=OPCUA_Binary::GetEndpointsProfileUri,             $path="opcua_binary_get_endpoints_profile_uri",                          $policy=log_policy_get_endpoints_profile_uri]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_READ,                                                [$columns=OPCUA_Binary::Read,                               $path="opcua_binary_read",                                               $policy=log_policy_read]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_READ_NODES_TO_READ,                                  [$columns=OPCUA_Binary::ReadNodesToRead,                    $path="opcua_binary_read_nodes_to_read",                                 $policy=log_policy_read_nodes_to_read]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_READ_RESULTS,                                        [$columns=OPCUA_Binary::ReadResults,                        $path="opcua_binary_read_results",                                       $policy=log_policy_read_results]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_WRITE,                                               [$columns=OPCUA_Binary::Write,                              $path="opcua_binary_write",                                              $policy=log_policy_write]);

   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_OPENSECURE_CHANNEL,                                  [$columns=OPCUA_Binary::OpenSecureChannel,                  $path="opcua_binary_opensecure_channel",                                 $policy=log_policy_opensecure_channel]);

   Analyzer::register_for_ports(Analyzer::ANALYZER_ICSNPP_OPCUA_BINARY, ports);
}

event opcua_binary_event(c: connection, info: OPCUA_Binary::Info)
   {
      # if the connection does not have a state, create state
      if ( !c?$opcua_binary_state ) {
         c$opcua_binary_state = State();
      }

      # Fix hello, acknowledge, opcua_link_id
      local log_immediately_msg_types = set("HEL", "ACK", "ERR", "OPN", "CLO");
      set_service(c, "opcua-binary");
      info$ts  = network_time();
      info$uid = c$uid;
      info$id  = c$id;

      # if message type is in log_immediately_msg_types, log immediately
      if (info$msg_type in log_immediately_msg_types) {
         log_message(c, info);
      }

      # else see if this message is a request and has a match in responses
      else if (info$request_id in c$opcua_binary_state$pending_responses && check_message_type(info, REQUEST_IDENTIFIER)) {
         if ( check_matching_common(info, c$opcua_binary_state$pending_responses[info$request_id]) ) {
            handle_pending_response(c, info);
         }
         else {
            handle_add_pending(c, info);
         }
      }
      # else see if this message is a response and has a match in requests
      else if (info$request_id in c$opcua_binary_state$pending_requests && check_message_type(info, RESPONSE_IDENTIFIER)) {
         if ( check_matching_common(c$opcua_binary_state$pending_requests[info$request_id], info) ) {
            handle_pending_request(c, info);
         }
         else {
            handle_add_pending(c, info);
         }
      }
      else {
         handle_add_pending(c, info);
      }
   }

event opcua_binary_diag_info_event(c: connection, diag_info: OPCUA_Binary::DiagnosticInfoDetail)
   {
       set_service(c, "opcua-binary");
       diag_info$ts  = network_time();
       diag_info$uid = c$uid;
       diag_info$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_DIAG_INFO, diag_info);
   }

event opcua_binary_status_code_event(c: connection, status: OPCUA_Binary::StatusCodeDetail)
   {
       set_service(c, "opcua-binary");
       status$ts  = network_time();
       status$uid = c$uid;
       status$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_STATUS_CODE, status);
   }

event opcua_binary_aggregate_filter_event(c: connection, aggregate_filter_event: OPCUA_Binary::AggregateFilter)
   {
       set_service(c, "opcua-binary");
       aggregate_filter_event$ts  = network_time();
       aggregate_filter_event$uid = c$uid;
       aggregate_filter_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_AGGREGATE_FILTER, aggregate_filter_event);
   }

event opcua_binary_data_change_filter_event(c: connection, data_change_filter_event: OPCUA_Binary::DataChangeFilter)
   {
       set_service(c, "opcua-binary");
       data_change_filter_event$ts  = network_time();
       data_change_filter_event$uid = c$uid;
       data_change_filter_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_DATA_CHANGE_FILTER, data_change_filter_event);
   }

event opcua_binary_event_filter_event(c: connection, event_filter_details_event: OPCUA_Binary::EventFilter)
   {
       set_service(c, "opcua-binary");
       event_filter_details_event$ts  = network_time();
       event_filter_details_event$uid = c$uid;
       event_filter_details_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER, event_filter_details_event);
   }

event opcua_binary_event_filter_attribute_operand_event(c: connection, attribute_operand_event: OPCUA_Binary::AttributeOperand)
   {
       set_service(c, "opcua-binary");
       attribute_operand_event$ts  = network_time();
       attribute_operand_event$uid = c$uid;
       attribute_operand_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ATTRIBUTE_OPERAND, attribute_operand_event);
   }

event opcua_binary_event_filter_attribute_operand_browse_path_element_event(c: connection, attribute_operand_browse_path_event: OPCUA_Binary::AttributeOperandBrowsePathElement)
   {
       set_service(c, "opcua-binary");
       attribute_operand_browse_path_event$ts  = network_time();
       attribute_operand_browse_path_event$uid = c$uid;
       attribute_operand_browse_path_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ATTRIBUTE_OPERAND_BROWSE_PATHS, attribute_operand_browse_path_event);
   }

event opcua_binary_event_filter_content_filter_event(c: connection, content_filter_event: OPCUA_Binary::ContentFilter)
   {
       set_service(c, "opcua-binary");
       content_filter_event$ts  = network_time();
       content_filter_event$uid = c$uid;
       content_filter_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_CONTENT_FILTER, content_filter_event);
   }

event opcua_binary_event_filter_content_filter_element_event(c: connection, content_filter_element_event: OPCUA_Binary::ContentFilterElement)
   {
       set_service(c, "opcua-binary");
       content_filter_element_event$ts  = network_time();
       content_filter_element_event$uid = c$uid;
       content_filter_element_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_CONTENT_FILTER_ELEMENT, content_filter_element_event);
   }

event opcua_binary_event_filter_element_operand_event(c: connection, element_operand_event: OPCUA_Binary::ElementOperand)
   {
       set_service(c, "opcua-binary");
       element_operand_event$ts  = network_time();
       element_operand_event$uid = c$uid;
       element_operand_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_ELEMENT_OPERAND, element_operand_event);
   }

event opcua_binary_event_filter_literal_operand_event(c: connection, literal_operand_event: OPCUA_Binary::LiteralOperand)
   {
       set_service(c, "opcua-binary");
       literal_operand_event$ts  = network_time();
       literal_operand_event$uid = c$uid;
       literal_operand_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_LITERAL_OPERAND, literal_operand_event);
   }

event opcua_binary_event_filter_select_clause_event(c: connection, select_clause_event: OPCUA_Binary::SelectClause)
   {
       set_service(c, "opcua-binary");
       select_clause_event$ts  = network_time();
       select_clause_event$uid = c$uid;
       select_clause_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SELECT_CLAUSE, select_clause_event);
   }

event opcua_binary_event_filter_simple_attribute_operand_event(c: connection, simple_attribute_operand_event: OPCUA_Binary::SimpleAttributeOperand)
   {
       set_service(c, "opcua-binary");
       simple_attribute_operand_event$ts  = network_time();
       simple_attribute_operand_event$uid = c$uid;
       simple_attribute_operand_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND, simple_attribute_operand_event);
   }

event opcua_binary_event_filter_simple_attribute_operand_browse_path_event(c: connection, simple_attribute_operand_browse_path_event: OPCUA_Binary::SimpleAttributeOperandBrowsePaths)
   {

       set_service(c, "opcua-binary");
       simple_attribute_operand_browse_path_event$ts  = network_time();
       simple_attribute_operand_browse_path_event$uid = c$uid;
       simple_attribute_operand_browse_path_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_EVENT_FILTER_SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATHS, simple_attribute_operand_browse_path_event);
   }

event opcua_binary_variant_array_dims_event(c: connection, event_to_log: OPCUA_Binary::VariantArrayDims)
   {
       set_service(c, "opcua-binary");
       event_to_log$ts  = network_time();
       event_to_log$uid = c$uid;
       event_to_log$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_VARIANT_ARRAY_DIMS, event_to_log);
   }

event opcua_binary_variant_data_event(c: connection, event_to_log: OPCUA_Binary::VariantData)
   {
       set_service(c, "opcua-binary");
       event_to_log$ts  = network_time();
       event_to_log$uid = c$uid;
       event_to_log$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_VARIANT_DATA, event_to_log);
   }

event opcua_binary_variant_data_value_event(c: connection, event_to_log: OPCUA_Binary::VariantDataValue)
   {
       set_service(c, "opcua-binary");
       event_to_log$ts  = network_time();
       event_to_log$uid = c$uid;
       event_to_log$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_VARIANT_DATA_VALUE, event_to_log);
   }

event opcua_binary_variant_extension_object_event(c: connection, event_to_log: OPCUA_Binary::VariantExtensionObject)
   {
       set_service(c, "opcua-binary");
       event_to_log$ts  = network_time();
       event_to_log$uid = c$uid;
       event_to_log$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_VARIANT_EXTENSION_OBJECT, event_to_log);
   }

event opcua_binary_variant_metadata_event(c: connection, event_to_log: OPCUA_Binary::VariantMetadata)
   {
       set_service(c, "opcua-binary");
       event_to_log$ts  = network_time();
       event_to_log$uid = c$uid;
       event_to_log$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_VARIANT_METADATA, event_to_log);
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

event opcua_binary_browse_reference_event(c: connection, browse_reference_event: OPCUA_Binary::BrowseReference)
   {
       set_service(c, "opcua-binary");
       browse_reference_event$ts  = network_time();
       browse_reference_event$uid = c$uid;
       browse_reference_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_BROWSE_RESPONSE_REFERENCES, browse_reference_event);
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

event opcua_binary_close_session_event(c: connection, event_to_log: OPCUA_Binary::CloseSession)
   {
       set_service(c, "opcua-binary");
       event_to_log$ts  = network_time();
       event_to_log$uid = c$uid;
       event_to_log$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CLOSE_SESSION, event_to_log);
   }

event opcua_binary_create_monitored_items_event(c: connection, create_monitored_items_event: OPCUA_Binary::CreateMonitoredItems)
   {
       set_service(c, "opcua-binary");
       create_monitored_items_event$ts  = network_time();
       create_monitored_items_event$uid = c$uid;
       create_monitored_items_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CREATE_MONITORED_ITEMS, create_monitored_items_event);
   }

event opcua_binary_create_monitored_items_create_item_event(c: connection, create_monitored_items_create_item_event: OPCUA_Binary::CreateMonitoredItemsItem)
   {
       set_service(c, "opcua-binary");
       create_monitored_items_create_item_event$ts  = network_time();
       create_monitored_items_create_item_event$uid = c$uid;
       create_monitored_items_create_item_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CREATE_MONITORED_ITEMS_CREATE_ITEM, create_monitored_items_create_item_event);
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

event opcua_binary_create_subscription_event(c: connection, create_subscription_event: OPCUA_Binary::CreateSubscription)
   {
       set_service(c, "opcua-binary");
       create_subscription_event$ts  = network_time();
       create_subscription_event$uid = c$uid;
       create_subscription_event$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_CREATE_SUBSCRIPTION, create_subscription_event);
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

event opcua_binary_get_endpoints_user_token_event(c: connection, get_endpoints_user_token: OPCUA_Binary::GetEndpointsUserToken)
   {
       set_service(c, "opcua-binary");
       get_endpoints_user_token$ts  = network_time();
       get_endpoints_user_token$uid = c$uid;
       get_endpoints_user_token$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_USER_TOKEN, get_endpoints_user_token);
   }

event opcua_binary_read_event(c: connection, event_to_log: OPCUA_Binary::Read)
   {
       set_service(c, "opcua-binary");
       event_to_log$ts  = network_time();
       event_to_log$uid = c$uid;
       event_to_log$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_READ, event_to_log);
   }

event opcua_binary_read_nodes_to_read_event(c: connection, event_to_log: OPCUA_Binary::ReadNodesToRead)
   {
       set_service(c, "opcua-binary");
       event_to_log$ts  = network_time();
       event_to_log$uid = c$uid;
       event_to_log$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_READ_NODES_TO_READ, event_to_log);
   }

event opcua_binary_read_results_event(c: connection, event_to_log: OPCUA_Binary::ReadResults)
   {
       set_service(c, "opcua-binary");
       event_to_log$ts  = network_time();
       event_to_log$uid = c$uid;
       event_to_log$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_READ_RESULTS, event_to_log);
   }

event opcua_binary_write_event(c: connection, event_to_log: OPCUA_Binary::Write)
   {
       set_service(c, "opcua-binary");
       event_to_log$ts  = network_time();
       event_to_log$uid = c$uid;
       event_to_log$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_WRITE, event_to_log);
   }

event opcua_binary_opensecure_channel_event(c: connection, opensecure_channel: OPCUA_Binary::OpenSecureChannel)
   {
       set_service(c, "opcua-binary");
       opensecure_channel$ts  = network_time();
       opensecure_channel$uid = c$uid;
       opensecure_channel$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_OPENSECURE_CHANNEL, opensecure_channel);
   }

event connection_state_remove(c: connection)
   {

      if ( !c?$opcua_binary_state ) {
         return;
      }

      local log_info: OPCUA_Binary::Info_Log;
      # if the connection has a state and there are pending requests, log them
      if ( |c$opcua_binary_state$pending_requests| > 0 )
      {
         for ( request_id, request_info in c$opcua_binary_state$pending_requests )
         {
            log_info = copy_common_data_to_logging_record(request_info);
            log_info = map_request(request_info, log_info);
            Log::write(ICSNPP_OPCUA_Binary::LOG, log_info);
         }
      }

      # if the connection has a state and there are pending responses, log them
      if ( |c$opcua_binary_state$pending_responses| > 0 )
      {
         for ( response_id, response_info in c$opcua_binary_state$pending_responses )
         {
            log_info = copy_common_data_to_logging_record(response_info);
            log_info = map_response(response_info, log_info, (!MAPPING_REQ_RES));
            Log::write(ICSNPP_OPCUA_Binary::LOG, log_info);
         }
      }
   }
