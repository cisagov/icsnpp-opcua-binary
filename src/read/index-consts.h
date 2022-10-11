// Activate Session consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_READ_CONSTS_H
#define OPCUA_BINARY_READ_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::ActivateSession
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//

// Request
#define READ_OPCUA_LINK_ID_DST_IDX                    3  // Id back into OCPUA_Binary::Info log
#define READ_REQ_CLIENT_ALGORITHM_IDX                 4
#define READ_REQ_CLIENT_SIGNATURE_IDX                 5
#define READ_REQ_CLIENT_SOFTWARE_CERT_LINK_ID_SRC_IDX 6  // Id into OPCUA_Binary::ActivateSessionClientSoftwareCert log
#define READ_REQ_OPCUA_LOCAL_LINK_ID_SRC_IDX          7  // Id into OPCUA_Binary::ActivateSessionLocaleId log

#define READ_REQ_EXT_OBJ_TYPE_ID_ENCODING_IDX         8
#define READ_REQ_EXT_OBJ_TYPE_ID_NAMESPACE_IDX        9 
#define READ_REQ_EXT_OBJ_TYPE_ID_NUMERIC_IDX         10
#define READ_REQ_EXT_OBJ_TYPE_ID_STRING_IDX          11
#define READ_REQ_EXT_OBJ_TYPE_ID_GUID_IDX            12 
#define READ_REQ_EXT_OBJ_TYPE_ID_OPAQUE_IDX          13 

#define READ_REQ_EXT_OBJ_TYPE_ID_STR_IDX             14 

#define READ_REQ_EXT_OBJ_ENCODING_IDX                15
#define READ_REQ_EXT_OBJ_POLICY_ID_IDX               16
#define READ_REQ_EXT_OBJ_USERNAME_IDX                17
#define READ_REQ_EXT_OBJ_PASSWORD_IDX                18
#define READ_REQ_EXT_OBJ_ENCRYPTION_ALGORITHM_IDX    19
#define READ_REQ_EXT_OBJ_CERT_DATA_IDX               20 
#define READ_REQ_EXT_OBJ_TOKEN_DATA_IDX              21

#define READ_REQ_USER_TOKEN_ALGORITHM_IDX            22
#define READ_REQ_USER_TOKEN_SIGNATURE_IDX            23

// Response
#define READ_RES_SERVER_NONCE_IDX                    24 
#define READ_RES_STATUS_CODE_LINK_ID_SRC_IDX         25 // Id into OPCUA_Binary::StatusCodeDetail log
#define READ_RES_DIAG_INFO_LINK_ID_SRC_IDX           26 // Id into OPCUA_Binary::ActivateSessionDignosticInfo log



//
// Index constants for setting values in OPCUA_Binary::ActivateSessionClientSoftwareCert
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//
#define READ_REQ_CLIENT_SOFTWARE_CERT_LINK_ID_DST_IDX 3 // Id back into OPCUA_Binary::ActivateSession
#define READ_REQ_CLIENT_SOFTWARE_CERT_DATA_IDX        4
#define READ_REQ_CLIENT_SOFTWARE_CERT_SIGNATURE_IDX   5

//
// Index constants for setting values in OPCUA_Binary::ActivateSessionLocaleId
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//
#define READ_REQ_OPCUA_LOCAL_LINK_ID_DST_IDX 3 // Id back into OPCUA_Binary::ActivateSession
#define READ_REQ_LOCALE_ID_IDX               4

//
// Index constants for setting values in OPCUA_Binary::ActivateSessionDignosticInfo
// based on the parsed values from Activate_Session_Req and Activate_Session_Res
//
#define READ_RES_DIAG_INFO_LINK_ID_DST_IDX 3 // Id back into OPCUA_Binary::ActivateSession
#define READ_DIAG_INFO_LINK_ID_SRC_IDX     4 // Id into OPCUA_Binary::DiagnosticInfoDetail


#endif
