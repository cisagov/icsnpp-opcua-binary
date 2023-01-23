// Create Session consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_CREATE_SESSION_CONSTS_H
#define OPCUA_BINARY_CREATE_SESSION_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::CreateSessions
// based on the parsed values from Create_Session_Req and Create_Session_Res
//

// Request
#define CREATE_SESSION_OPCUA_LINK_ID_DST_IDX                   3  // Id back into OCPUA_Binary::Info
#define CREATE_SESSION_REQ_APPLICATION_URI_IDX                 4
#define CREATE_SESSION_REQ_PRODUCT_URI_IDX                     5
#define CREATE_SESSION_REQ_ENCODING_MASK_IDX                   6
#define CREATE_SESSION_REQ_LOCALE_IDX                          7
#define CREATE_SESSION_REQ_TEXT_IDX                            8
#define CREATE_SESSION_REQ_APPLICATON_TYPE_IDX                 9
#define CREATE_SESSION_REQ_GATEWAY_SERVER_URI_IDX             10
#define CREATE_SESSION_REQ_DISCOVERY_PROFILE_URI_IDX          11
#define CREATE_SESSION_REQ_DISCOVERY_PROFILE_LINK_ID_SRC_IDX  12 // Id into OPCUA_Binary::CreateSessionDiscovery
#define CREATE_SESSION_REQ_SERVER_URI_IDX                     13
#define CREATE_SESSION_REQ_ENDPOINT_URI_IDX                   14
#define CREATE_SESSION_REQ_SESSION_NAME_IDX                   15
#define CREATE_SESSION_REQ_CLIENT_NONCE_IDX                   16
#define CREATE_SESSION_REQ_CLIENT_CERT_SIZE_IDX               17
#define CREATE_SESSION_REQ_CLIENT_CERT_IDX                    18
#define CREATE_SESSION_REQ_SESSION_TIMEOUT_IDX                19
#define CREATE_SESSION_REQ_MAX_RES_MSG_SIZE_IDX               20

// Response
#define CREATE_SESSION_ID_ENCODING_MASK_IDX                   21
#define CREATE_SESSION_ID_NAMESPACE_IDX                       22
#define CREATE_SESSION_ID_NUMERIC_IDX                         23
#define CREATE_SESSION_ID_STRING_IDX                          24
#define CREATE_SESSION_ID_GUID_IDX                            25
#define CREATE_SESSION_ID_OPAQUE_IDX                          26

#define CREATE_SESSION_AUTH_TOKEN_ENCODING_MASK_IDX           27
#define CREATE_SESSION_AUTH_TOKEN_NAMESPACE_IDX               28 
#define CREATE_SESSION_AUTH_TOKEN_NUMERIC_IDX                 29
#define CREATE_SESSION_AUTH_TOKEN_STRING_IDX                  30 
#define CREATE_SESSION_AUTH_TOKEN_GUID_IDX                    31
#define CREATE_SESSION_AUTH_TOKEN_OPAQUE_IDX                  32

#define CREATE_SESSION_RES_REVISED_SESSION_TIMEOUT_IDX        33
#define CREATE_SESSION_RES_SERVER_NONCE_IDX                   34
#define CREATE_SESSION_RES_SERVER_CERT_SIZE_IDX               35
#define CREATE_SESSION_RES_SERVER_CERT_IDX                    36
#define CREATE_SESSION_RES_ENDPOINT_LINK_ID_SRC_IDX           37 // Id into OPCUA_Binary::CreateSessionEndpoints
#define CREATE_SESSION_RES_ALGORITHM_IDX                      38
#define CREATE_SESSION_RES_SIGNATURE_IDX                      39
#define CREATE_SESSION_RES_MAX_REQ_MSG_SIZE_IDX               40

//
// Index constants for setting values in OPCUA_Binary::CreateSessionDiscovery
// based on the parsed values from Create_Session_Req and Create_Session_Res
//
// Note: Both Create Session Request and Create Session Response have discovery information.
//
#define CREATE_SESSION_DISCOVERY_PROFILE_LINK_ID_DST_IDX 3 // Id back into OPCUA_Binary::CreateSessions & OPCUA_Binary::CreateSessionEndpoints
#define CREATE_SESSION_DISCOVERY_URI_IDX                 4
#define CREATE_SESSION_DISCOVORY_URL_IDX                 5

//
// Index constants for setting values in OPCUA_Binary::CreateSessionEndpoints
// based on the parsed values from Create_Session_Req and Create_Session_Res
//
#define CREATE_SESSION_RES_ENDPOINT_LINK_ID_DST_IDX                     3 // Id back into OPCUA_Binary::CreateSessions
#define CREATE_SESSION_RES_ENDPOINT_URL_IDX                             4
#define CREATE_SESSION_RES_ENDPOINT_APPLICATION_URI_IDX                 5
#define CREATE_SESSION_RES_ENDPOINT_PRODUCT_URI_IDX                     6
#define CREATE_SESSION_RES_ENDPOINT_ENCODING_MASK_IDX                   7
#define CREATE_SESSION_RES_ENDPOINT_LOCALE_IDX                          8 
#define CREATE_SESSION_RES_ENDPOINT_TEXT_IDX                            9
#define CREATE_SESSION_RES_ENDPOINT_APPLICATION_TYPE_IDX               10
#define CREATE_SESSION_RES_ENDPOINT_GATEWAY_SERVER_URI_IDX             11
#define CREATE_SESSION_RES_ENDPOINT_DISCOVERY_PROFILE_URI_IDX          12
#define CREATE_SESSION_RES_ENDPOINT_DISCOVERY_PROFILE_LINK_ID_SRC_IDX  13 // Id into OPCUA_Binary::CreateSessionDiscovery
#define CREATE_SESSION_RES_ENDPOINT_CERT_SIZE_IDX                      14
#define CREATE_SESSION_RES_ENDPOINT_SERVER_CERT_IDX                    15
#define CREATE_SESSION_RES_ENDPOINT_MSG_SECURITY_MODE_IDX              16
#define CREATE_SESSION_RES_ENDPOINT_SECURITY_POLICY_URI_IDX            17
#define CREATE_SESSION_RES_ENDPOINT_USER_TOKEN_LINK_ID_SRC_IDX          18 // Id into OPCUA_Binary::CreateSessionUserToken 
#define CREATE_SESSION_RES_ENDPOINT_TRANSPORT_PROFILE_URI_IDX          19
#define CREATE_SESSION_RES_ENDPOINT_SECURITY_LEVEL_IDX                 20 

//
// Index constants for setting values in OPCUA_Binary::CreateSessionUserToken
// based on the parsed values from Create_Session_Req and Create_Session_Res
//
#define CREATE_SESSION_RES_ENDPOINT_USER_TOKEN_LINK_ID_DST_IDX         3 // Id back into OPCUA_Binary::CreateSessionEndpoints
#define CREATE_SESSION_RES_ENDPOINT_USER_TOKEN_POLICY_ID_IDX           4
#define CREATE_SESSION_RES_ENDPOINT_USER_TOKEN_TYPE_IDX                5
#define CREATE_SESSION_RES_ENDPOINT_USER_TOKEN_ISSUED_TYPE_IDX         6
#define CREATE_SESSION_RES_ENDPOINT_USER_TOKEN_ENDPOINT_URL_IDX        7
#define CREATE_SESSION_RES_ENDPOINT_USER_TOKEN_SECURITY_POLICY_URI_IDX 8

#endif

