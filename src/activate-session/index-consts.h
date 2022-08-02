// Activate Session consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_ACTIVATE_SESSION_CONSTS_H
#define OPCUA_BINARY_ACTIVATE_SESSION_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::ActivateSession
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//

// Request
#define ACTIVATE_SESSION_OPCUA_ID_LINK_IDX                     3  // Id back into OCPUA_Binary::Info log
#define ACTIVATE_SESSION_REQ_CLIENT_ALGORITHM_IDX              4
#define ACTIVATE_SESSION_REQ_CLIENT_SIGNATURE_IDX              5
#define ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_ID_IDX       6  // Id into OPCUA_Binary::ActivateSessionClientSoftwareCert log
#define ACTIVATE_SESSION_REQ_OPCUA_LOCAL_ID_IDX                7  // Id into OPCUA_Binary::ActivateSessionLocaleId log

#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_ENCODING_IDX      8
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_NUMERIC_IDX       9
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_NAMESPACE_IDX    10 
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_STRING_IDX       11
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_GUID_IDX         12 
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_OPAQUE_IDX       13 

#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_STR_IDX          14 

#define ACTIVATE_SESSION_REQ_EXT_OBJ_ENCODING_IDX             15
#define ACTIVATE_SESSION_REQ_EXT_OBJ_POLICY_ID_IDX            16
#define ACTIVATE_SESSION_REQ_EXT_OBJ_USERNAME_IDX             17
#define ACTIVATE_SESSION_REQ_EXT_OBJ_PASSWORD_IDX             18
#define ACTIVATE_SESSION_REQ_EXT_OBJ_ENCRYPTION_ALGORITHM_IDX 19
#define ACTIVATE_SESSION_REQ_EXT_OBJ_CERT_DATA_IDX            20 
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TOKEN_DATA_IDX           21

#define ACTIVATE_SESSION_REQ_USER_TOKEN_ALGORITHM_IDX         22
#define ACTIVATE_SESSION_REQ_USER_TOKEN_SIGNATURE_IDX         23

// Response
#define ACTIVATE_SESSION_RES_SERVER_NONCE_IDX                 24 
#define ACTIVATE_SESSION_RES_RESULT_ID_IDX                    25 // Id into OPCUA_Binary::StatusCodeDetail log
#define ACTIVATE_SESSION_RES_DIAG_INFO_ID_IDX                 26 // Id into OPCUA_Binary::DiagnosticInfoDetail log



//
// Index constants for setting values in OPCUA_Binary::ActivateSessionClientSoftwareCert
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//
#define ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_LINK_IDX      3 // Id back into OPCUA_Binary::ActivateSession
#define ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_DATA_IDX      4
#define ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_SIGNATURE_IDX 5

//
// Index constants for setting values in OPCUA_Binary::ActivateSessionLocaleId
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//
#define ACTIVATE_SESSION_REQ_OPCUA_LOCAL_LINK_IDX 3 // Id back into OPCUA_Binary::ActivateSession
#define ACTIVATE_SESSION_REQ_LOCALE_ID_IDX        4

//
// Index constants for setting values in OPCUA_Binary::ActivateSessionDignosticInfo
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//
#define ACTIVATE_SESSION_RES_DIAGNOSTIC_INFO_LINK_IDX 3 // Id back into OPCUA_Binary::ActivateSession
#define ACTIVATE_SESSION_RES_DIAGNOSTIC_INFO_IDX      4 // Id into OPCUA_Binary::DiagnosticInfoDetail


#endif

