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
#define ACTIVATE_SESSION_OPCUA_LINK_ID_DST_IDX                    8  // Id back into OCPUA_Binary::Info log
#define ACTIVATE_SESSION_REQ_CLIENT_ALGORITHM_IDX                 9
#define ACTIVATE_SESSION_REQ_CLIENT_SIGNATURE_IDX                 10
#define ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_LINK_ID_SRC_IDX 11  // Id into OPCUA_Binary::ActivateSessionClientSoftwareCert log
#define ACTIVATE_SESSION_REQ_OPCUA_LOCAL_LINK_ID_SRC_IDX          12  // Id into OPCUA_Binary::ActivateSessionLocaleId log

#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_ENCODING_IDX         13
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_NAMESPACE_IDX        14
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_NUMERIC_IDX          15
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_STRING_IDX           16
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_GUID_IDX             17 
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_OPAQUE_IDX           18 

#define ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_STR_IDX              19 

#define ACTIVATE_SESSION_REQ_EXT_OBJ_ENCODING_IDX                 20
#define ACTIVATE_SESSION_REQ_EXT_OBJ_POLICY_ID_IDX                21
#define ACTIVATE_SESSION_REQ_EXT_OBJ_USERNAME_IDX                 22
#define ACTIVATE_SESSION_REQ_EXT_OBJ_PASSWORD_IDX                 23
#define ACTIVATE_SESSION_REQ_EXT_OBJ_ENCRYPTION_ALGORITHM_IDX     24
#define ACTIVATE_SESSION_REQ_EXT_OBJ_CERT_DATA_IDX                25 
#define ACTIVATE_SESSION_REQ_EXT_OBJ_TOKEN_DATA_IDX               26

#define ACTIVATE_SESSION_REQ_USER_TOKEN_ALGORITHM_IDX             27
#define ACTIVATE_SESSION_REQ_USER_TOKEN_SIGNATURE_IDX             28

// Response
#define ACTIVATE_SESSION_RES_SERVER_NONCE_IDX                     29 
#define ACTIVATE_SESSION_RES_STATUS_CODE_LINK_ID_SRC_IDX          30 // Id into OPCUA_Binary::StatusCodeDetail log
#define ACTIVATE_SESSION_RES_DIAG_INFO_LINK_ID_SRC_IDX            31 // Id into OPCUA_Binary::ActivateSessionDignosticInfo log


//
// Index constants for setting values in OPCUA_Binary::ActivateSessionClientSoftwareCert
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//
#define ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_LINK_ID_DST_IDX 8 // Id back into OPCUA_Binary::ActivateSession
#define ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_DATA_IDX        9
#define ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_SIGNATURE_IDX   10

//
// Index constants for setting values in OPCUA_Binary::ActivateSessionLocaleId
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//
#define ACTIVATE_SESSION_REQ_OPCUA_LOCAL_LINK_ID_DST_IDX 8 // Id back into OPCUA_Binary::ActivateSession
#define ACTIVATE_SESSION_REQ_LOCALE_ID_IDX               9

//
// Index constants for setting values in OPCUA_Binary::ActivateSessionDignosticInfo
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//
#define ACTIVATE_SESSION_RES_DIAG_INFO_LINK_ID_DST_IDX 8 // Id back into OPCUA_Binary::ActivateSession
#define ACTIVATE_SESSION_DIAG_INFO_LINK_ID_SRC_IDX     9 // Id into OPCUA_Binary::DiagnosticInfoDetail


#endif

