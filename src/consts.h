// consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_CONSTS_H
#define OPCUA_BINARY_CONSTS_H

//
// Index constants for setting values in OPCUC_Binary::Info
//

// OpcUA_ID  
// While this id is NOT part of the OpcUA documented spec, we use it to tie nested log files
// together - e.g. any nested log files such as the status code detail log will contain
// this id which can be used to reference back to the primary OpcUA log file.
//
#define OPCUA_ID_IDX                      3

// Msg Header
#define MSG_TYPE_IDX                      4
#define IS_FINAL_IDX                      5
#define MSG_SIZE_IDX                      6

// Msg_ERR
#define ERROR_IDX                         7
#define REASON_IDX                        8

// Msg_HEL and Msg_ACK
#define VERSION_IDX                       9
#define RCV_BUF_SIZE_IDX                  10
#define SND_BUF_SIZE_IDX                  11
#define MAX_MSG_SIZE_IDX                  12
#define MAX_CHUNK_CNT_IDX                 13
#define ENDPOINT_URL_IDX                  14 // Msg_HEL

// Msg Body
#define SEC_CHANNEL_ID_IDX                15
#define SEC_POLICY_URI_LEN_IDX            16
#define SEC_POLICY_URI_IDX                17
#define SND_CERT_LEN_IDX                  18
#define SND_CERT_IDX                      19
#define RCV_CERT_LEN_IDX                  20
#define RCV_CERT_IDX                      21
#define SEQ_NUMBER_IDX                    22
#define REQUEST_ID_IDX                    23
#define ENCODING_MASK_IDX                 24
#define NAMESPACE_IDX                     25
#define IDENTIFIER_IDX                    26
#define IDENTIFIER_STR_IDX                27

// Request Header
#define REQ_HDR_NODE_ID_TYPE_IDX          28
#define REQ_HDR_NODE_ID_NAMESPACE_IDX     29
#define REQ_HDR_NODE_ID_NUMERIC_IDX       30
#define REQ_HDR_NODE_ID_STRING_IDX        31 
#define REQ_HDR_NODE_ID_GUID_IDX          32 
#define REQ_HDR_NODE_ID_OPAQUE_IDX        33 
#define REQ_HDR_TIMESTAMP_IDX             34
#define REQ_HDR_HANDLE_IDX                35
#define REQ_HDR_RET_DIAG_IDX              36
#define REQ_HDR_AUDIT_ENTRY_IDX           37
#define REQ_HDR_TIMEOUT_HINT_IDX          38
#define REQ_HDR_ADD_HDR_TYPE_ID_IDX       39
#define REQ_HDR_ADD_HDR_ENC_MASK_IDX      40

// Response Header
#define RES_HDR_TIMESTAMP_IDX             41
#define RES_HDR_HANDLE_IDX                42
#define RES_HDR_SERVICE_RESULT_IDX        43
#define RES_HDR_SERVICE_DIAG_ENCODING_IDX 44
#define RES_HDR_ADD_HDR_TYPE_ID_IDX       45
#define RES_HDR_ADD_HDR_ENC_MASK_IDX      46

//
// Index constants for setting values in OPCUA_Binary::StatusCodeDetail
//
#define STAT_CODE_OPCUA_ID_LINK_IDX   3
#define SOURCE_IDX                    4
#define SOURCE_STR_IDX                5
#define STATUS_CODE_IDX               6
#define SEVERITY_IDX                  7
#define SEVERITY_STR_IDX              8
#define SUBCODE_IDX                   9
#define SUBCODE_STR_IDX               10
#define STRUCTURE_CHANGED_IDX         11
#define SEMANTICS_CHANGED_IDX         12
#define INFO_TYPE_IDX                 13
#define INFO_TYPE_STR_IDX             14
#define LIMIT_BITS_IDX                15
#define LIMIT_BITS_STR_IDX            16
#define OVERFLOW_IDX                  17
#define HISTORIAN_BITS_IDX            18
#define HISTORIAN_BITS_STR_IDX        19
#define HISTORIAN_BITS_PARTIAL_IDX    20
#define HISTORIAN_BITS_EXTRADATA_IDX  21
#define HISTORIAN_BITS_MULTIVALUE_IDX 22

//
// Index constants for setting values in OPCUA_Binary::DiagnosticInfoDetail
//
#define DIAG_INFO_DETAIL_OPCUA_ID_LINK_IDX 3
#define INNER_DIAG_LEVEL_IDX               4
#define HAS_SYMBOLIC_ID_IDX                5
#define SYMBOLIC_ID_IDX                    6
#define SYMBOLIC_ID_STR_IDX                7
#define HAS_NAMESPACE_URI_IDX              8
#define NAMESPACE_URI_IDX                  9
#define NAMESPACE_URI_STR_IDX              10
#define HAS_LOCALE_IDX                     11
#define LOCALE_IDX                         12
#define LOCALE_STR_IDX                     13
#define HAS_LOCALE_TXT_IDX                 14
#define LOCALE_TXT_IDX                     15
#define LOCALE_TXT_STR_IDX                 16
#define HAS_ADDL_INFO_IDX                  17
#define ADDL_INFO_IDX                      18
#define HAS_INNER_STAT_CODE_IDX            19
#define INNER_STAT_CODE_IDX                20
#define HAS_INNER_DIAG_INFO_IDX            21

//
// Index constants for setting values in OPCUA_Binary::OpenSecureChannel
//
#define OPENSECURE_CHANNEL_OPCUA_ID_LINK_IDX 3

// OpenSecureChannel Request
#define CLIENT_PROTO_VER_IDX                 4
#define SECURITY_TOKEN_REQ_TYPE_IDX          5
#define MESSAGE_SECURITY_MODE_IDX            6
#define CLIENT_NONCE_IDX                     7
#define REQ_LIFETIME_IDX                     8

// OpenSecureChannel Response
#define SERVER_PROTO_VER_IDX                 9

//
// Secure Channel Id & Secure Token Id.
// Returned by the server when processing the
// OpenSecureChannel Service.  Used down stream
// by other services to secure the Message
//
#define SEC_TOKEN_CHANNEL_ID_IDX             10
#define SEC_TOKEN_ID_IDX                     11 

#define SEC_TOKEN_CREATED_AT_IDX             12
#define SEC_TOKEN_REVISED_LIFETIME_IDX       13
#define SERVER_NONCE_IDX                     14


//
// Index constants for setting values in OPCUA_Binary::GetEndpoints
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_OPCUA_ID_LINK_IDX             3
#define GET_ENDPOINT_URL_IDX                       4
#define GET_ENDPOINT_REQ_LOCALE_ID_IDX             5
#define GET_ENDPOINT_REQ_PROFILE_URI_IDX           6
#define GET_ENDPOINT_RES_APPLICATION_URI_IDX       7
#define GET_ENDPOINT_RES_PRODUCT_URI_IDX           8
#define GET_ENDPOINT_RES_ENCODING_MASK_IDX         9
#define GET_ENDPOINT_RES_LOCALE_IDX                10
#define GET_ENDPOINT_RES_TEXT_IDX                  11
#define GET_ENDPOINT_RES_APPLICATION_TYPE_IDX      12
#define GET_ENDPOINT_RES_GW_SERVER_URI_IDX         13
#define GET_ENDPOINT_RES_DISCOVERY_PROFILE_ID_IDX  14
#define GET_ENDPOINT_RES_CERT_SIZE_IDX             15
#define GET_ENDPOINT_RES_SERVER_CERT_IDX           16
#define GET_ENDPOINT_RES_MSG_SECURITY_MODE_IDX     17
#define GET_ENDPOINT_RES_SECURITY_POLICY_URI_IDX   18
#define GET_ENDPOINT_RES_USER_TOKEN_ID_IDX         19
#define GET_ENDPOINT_RES_TRANSPORT_PROFILE_URI_IDX 20
#define GET_ENDPOINT_RES_SECURITY_LEVEL_IDX        21

//
// Index constants for setting values in OPCUA_Binary::GetEndpointsDiscovery
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_RES_DISCOVERY_PROFILE_ID_LINK_IDX 3
#define GET_ENDPOINT_RES_DISCOVERY_URI_IDX             4
#define GET_ENDPOINT_RES_DISCOVORY_URL_IDX             5

//
// Index constants for setting values in OPCUA_Binary::GetEndpointsUserToken
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_RES_USER_TOKEN_ID_LINK_IDX             3
#define GET_ENDPOINT_RES_USER_TOKEN_POLICY_ID_IDX           4
#define GET_ENDPOINT_RES_USER_TOKEN_TYPE_IDX                5
#define GET_ENDPOINT_RES_USER_TOKEN_ISSUED_TYPE_IDX         6
#define GET_ENDPOINT_RES_USER_TOKEN_ISSUER_ENDPOINT_URL_IDX 7
#define GET_ENDPOINT_RES_USER_TOKEN_SECURITY_POLICY_URI_IDX 8


#endif

