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
	redef enum Log::ID += { LOG, LOG_STATUS_CODE, LOG_DIAG_INFO, LOG_OPENSECURE_CHANNEL, LOG_GET_ENDPOINTS, LOG_GET_ENDPOINTS_DISCOVERY,  LOG_GET_ENDPOINTS_USER_TOKEN };
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
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS,            [$columns=OPCUA_Binary::GetEndpoints,          $path="opcua-binary-get-endpoints"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_DISCOVERY,  [$columns=OPCUA_Binary::GetEndpointsDiscovery, $path="opcua-binary-get-endpoints-discovery"]);
   Log::create_stream(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_USER_TOKEN, [$columns=OPCUA_Binary::GetEndpointsUserToken, $path="opcua-binary-get-endpoints-user-token"]);

   Analyzer::register_for_ports(Analyzer::ANALYZER_ICSNPP_OPCUA_BINARY, ports);
   }

event opcua_binary_event(c: connection, info: OPCUA_Binary::Info)
   {
       info$ts  = network_time();
       info$uid = c$uid;
       info$id  = c$id;
       Log::write(ICSNPP_OPCUA_Binary::LOG, info);
    }

event opcua_binary_status_code_event(c: connection, status: OPCUA_Binary::StatusCodeDetail)
   {
       status$ts  = network_time();
       status$uid = c$uid;
       status$id  = c$id;
       Log::write(ICSNPP_OPCUA_Binary::LOG_STATUS_CODE, status);

    }

event opcua_binary_diag_info_event(c: connection, diag_info: OPCUA_Binary::DiagnosticInfoDetail)
   {
       diag_info$ts  = network_time();
       diag_info$uid = c$uid;
       diag_info$id  = c$id;
       Log::write(ICSNPP_OPCUA_Binary::LOG_DIAG_INFO, diag_info);

    }

event opcua_binary_opensecure_channel_event(c: connection, opensecure_channel: OPCUA_Binary::OpenSecureChannel)
   {
       opensecure_channel$ts  = network_time();
       opensecure_channel$uid = c$uid;
       opensecure_channel$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_OPENSECURE_CHANNEL, opensecure_channel);

    }

event opcua_binary_get_endpoints_event(c: connection, get_endpoints: OPCUA_Binary::GetEndpoints)
   {
       get_endpoints$ts  = network_time();
       get_endpoints$uid = c$uid;
       get_endpoints$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS, get_endpoints);

    }

event opcua_binary_get_endpoints_discovery_event(c: connection, get_endpoints_discovery: OPCUA_Binary::GetEndpointsDiscovery)
   {
       get_endpoints_discovery$ts  = network_time();
       get_endpoints_discovery$uid = c$uid;
       get_endpoints_discovery$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_DISCOVERY, get_endpoints_discovery);

    }

event opcua_binary_get_endpoints_user_token_event(c: connection, get_endpoints_user_token: OPCUA_Binary::GetEndpointsUserToken)
   {
       get_endpoints_user_token$ts  = network_time();
       get_endpoints_user_token$uid = c$uid;
       get_endpoints_user_token$id  = c$id;

       Log::write(ICSNPP_OPCUA_Binary::LOG_GET_ENDPOINTS_USER_TOKEN, get_endpoints_user_token);

    }
