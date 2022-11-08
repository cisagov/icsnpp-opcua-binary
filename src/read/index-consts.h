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
// Index constants for setting values in OPCUA_Binary::Read
// based on the parsed values from Read_Req and Read_Res
//
    #define READ_OPCUA_LINK_ID_DST_IDX             3  // Id back into OCPUA_Binary::Info log

    // Request
    #define READ_REQ_MAX_AGE_IDX                   4
    #define READ_REQ_TIMESTAMPS_TO_RETURN_IDX      5
    #define READ_REQ_TIMESTAMPS_TO_RETURN_STR_IDX  6  
    #define READ_REQ_NODES_TO_READ_LINK_ID_SRC_IDX 7  // Id into OPCUA_Binary::NoesToRead log

    // Response
    #define READ_RES_RESULTS_LINK_ID_SRC_IDX       8 // Id into OPCUA_Binary::ReadResults
    #define READ_RES_DIAG_INFO_LINK_ID_SRC_IDX     9 // Id into OPCUA_Binary::ReadDiagnosticInfo log

//
// Index constants for setting values in OPCUA_Binary::NodesToRead
// based on the parsed values from Read_Req
//
    #define READ_REQ_NODES_TO_READ_LINK_ID_DST_IDX 3  // Id back into OPCUA_Binary::Read log

    // OpcUA_NodeId
    #define READ_REQ_NODE_ID_ENCODING_MASK_IDX     4
    #define READ_REQ_NODE_ID_NAMESPACE_ID_IDX      5
    #define READ_REQ_NODE_ID_NUMERIC_IDX           6
    #define READ_REQ_NODE_ID_STRING_IDX            7
    #define READ_REQ_NODE_ID_GUID_IDX              8
    #define READ_REQ_NODE_ID_OPAQUE_IDX            9

    #define READ_REQ_ATTRIBUTE_ID_IDX             10
    #define READ_REQ_ATTRIBUTE_ID_STR_IDX         11
    #define READ_REQ_INDEX_RANGE_IDX              12

    // QualifiedName
    #define READ_REQ_DATA_ENCODING_NAME_ID_IDX    13
    #define READ_REQ_DATA_ENCODING_NAME_IDX       14

//
// Index constants for setting values in OPCUA_Binary::ReadResultsLink
// based on the parsed values from Read_Res
//
    #define READ_RES_RESULTS_LINK_ID_DST_IDX 3 // Id back into OPCUA_Binary::Read log
    #define READ_RES_LINK_ID_SRC_IDX         4 // Id into OPCUA_Binary::ReadResults

//
// Index constants for setting values in OPCUA_Binary::ReadResults
// based on the parsed values from Read_Res
//
    #define READ_RES_LINK_ID_DST_IDX                       3 // Id back into OPCUA_Binary::ReadResultsLink
    #define READ_RES_LEVEL_IDX                             4
    #define READ_RES_DATA_VALUE_ENCODING_MASK_IDX          5
    #define READ_RES_STATUS_CODE_LINK_ID_SRC_IDX           6 // Id into OPCUA_Binary::StatusCodeDetail log
    #define READ_RES_SOURCE_TIMESTAMP_IDX                  7
    #define READ_RES_SOURCE_PICO_SEC_IDX                   8
    #define READ_RES_SERVER_TIMESTAMP_IDX                  9
    #define READ_RES_SERVER_PICO_SEC_IDX                  10 
    #define READ_RES_DATA_VARIANT_ENCODING_MASK_IDX       11
    #define READ_RES_DATA_VARIANT_TYPE_IDX                12
    #define READ_RES_DATA_VARIANT_TYPE_STR_IDX            13
    #define READ_RES_BUILT_IN_DATA_TYPE_IDX               14
    #define READ_RES_BUILT_IN_DATA_TYPE_STR_IDX           15
    #define READ_RES_RESULTS_VARIANT_DATA_LINK_ID_SRC_IDX 16 // Id into OPCUA_Binary::ReadVariantDataLink

//
// Index constants for setting values in OPCUA_Binary::ReadVariantDataLink
// based on the parsed values from Read_Res
//
    #define READ_RES_RESULTS_VARIANT_DATA_LINK_ID_DST_IDX 3 // Id back into OPCUA_Binary::ReadVariantDataLink
    #define READ_RES_VARIANT_DATA_LINK_ID_SRC_IDX         4 // Id into OPCUA_Binary::ReadVariantData

//
// Index constants for setting values in OPCUA_Binary::ReadVariantData
// based on the parsed values from Read_Res
//
    #define READ_RES_VARIANT_DATA_LINK_ID_DST_IDX              3 // Id back into OPCUA_Binary::ReadVariantDataLink

    // Signed numerics - e.g. int8, int16, etc
    #define READ_RES_VARIANT_DATA_VALUE_SIGNED_NUMERIC_IDX     4    

    // Unsigned numerics - e.g. uint8, uint16, etc
    #define READ_RES_VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX   5    

    // OpcUA_String, OpcUA_Guid, OpcUA_ByteString, etc
    #define READ_RES_VARIANT_DATA_VALUE_STRING_IDX             6    

    // OpcUA_NodeId & OpcUA_ExpandedNodeId
    #define READ_RES_VARIANT_DATA_NODE_ID_ENCODING_MASK_IDX    7
    #define READ_RES_VARIANT_DATA_NODE_ID_NAMESPACE_IDX        8
    #define READ_RES_VARIANT_DATA_NODE_ID_NUMERIC_IDX          9
    #define READ_RES_VARIANT_DATA_NODE_ID_STRING_IDX           10
    #define READ_RES_VARIANT_DATA_NODE_ID_GUID_IDX             11
    #define READ_RES_VARIANT_DATA_NODE_ID_OPAQUE_IDX           12
    #define READ_RES_VARIANT_DATA_NODE_ID_NAMESPACE_URI_IDX    13
    #define READ_RES_VARIANT_DATA_NODE_ID_SERVER_IDX           14

    // OpcUA_DateTime
    #define READ_RES_VARIANT_DATA_VALUE_TIME_IDX               15

    // OpcUA_QualifiedName
    #define READ_RES_VARIANT_DATA_ENCODING_NAME_ID_IDX         16    
    #define READ_RES_VARIANT_DATA_ENCODING_NAME_IDX            17

    // OpcUA_LocalizedText
    #define READ_RES_VARIANT_DATA_MASK_IDX                     18    
    #define READ_RES_VARIANT_DATA_LOCALE_IDX                   19    
    #define READ_RES_VARIANT_DATA_TEXT_IDX                     20

    // OpcUA_Float & OpcUA_Double
    #define READ_RES_VARIANT_DATA_VALUE_DECIMAL_IDX            21    

    // OpcUA_StatusCode
    #define READ_RES_VARIANT_DATA_STATUS_CODE_LINK_ID_SRC_IDX  22 // Link into OPCUA_Binary::ReadStatusCode log 

    // OpcUA_DiagInfo
    #define READ_RES_VARIANT_DATA_DIAG_INFO_LINK_ID_SRC_IDX    23 // Link into OPCUA_Binary::ReadDiagnosticInfo log
    
    // Array Dimensions
    #define READ_RES_VARIANT_DATA_ARRAY_DIM_IDX                24 
    #define READ_RES_VARIANT_DATA_ARRAY_LINK_ID_SRC_IDX        25 // Link into OPCUA_Binary::ReadArrayDimsLink

    // OpcUA_ExtensionObject
    #define READ_RES_VARIANT_DATA_EXT_OBJ_LINK_ID_SRC_IDX      26 // Link into OPCUA_Binary::ReadExtensionObjectLink

    // OpcUA_DataValue
    #define READ_RES_VARIANT_DATA_DATA_VALUE_LINK_ID_SRC_IDX   27 // Link into OPCUA_Binary::ReadVariantDataLink

//
// Index constants for setting values in OPCUA_Binary::ReadArrayDimsLink
// based on the parsed values from Read_Res
//
    #define READ_RES_VARIANT_DATA_ARRAY_LINK_ID_DST_IDX 3 // Link back into OPCUA_Binary::ReadVariantData
    #define READ_RES_ARRAY_LINK_ID_SRC_IDX              4 // Link into OPCUA_Binary::ReadArrayDims

//
// Index constants for setting values in OPCUA_Binary::ReadArrayDims
// based on the parsed values from Read_Res
//
    #define READ_RES_ARRAY_LINK_ID_DST_IDX 3 // Link back into OPCUA_Binary::ReadArrayDimsLink
    #define READ_RES_DIMENSION_IDX         4 

//
// Index constants for setting values in OPCUA_Binary::ReadDiagnosticInfo
// based on the parsed values from Read_Res
//
    #define READ_RES_DIAG_INFO_LINK_ID_DST_IDX 3 // Link back into OCPUA_Binary::Read or OPCUA_Binary::ReadVariantData
    #define READ_DIAG_INFO_LINK_ID_SRC_IDX     4 // Link into OPCUA_Binary::DiagnosticInfoDetail

//
// Index constants for setting values in OPCUA_Binary::ReadStatusCode
// based on the parsed values from Read_Res
//
    #define READ_RES_VARIANT_DATA_STATUS_CODE_LINK_ID_DST_IDX 3 // Link back into OPCUA_Binary::ReadVariantData
    #define READ_STATUS_CODE_LINK_ID_SRC_IDX                  4 // Id into OPCUA_Binary::StatusCodeDetail log

//
// Index constants for setting values in OPCUA_Binary::ReadExtensionObjectLink
// based on the parsed values from Read_Res
//
    #define READ_RES_VARIANT_DATA_EXT_OBJ_LINK_ID_DST_IDX 3 // Link back into OPCUA_Binary::ReadVariantData
    #define READ_RES_EXT_OBJ_LINK_ID_SRC_IDX              4 // Id into OPCUA_Binary::ReadExtensionObject log

//
// Index constants for setting values in OPCUA_Binary::ReadExtensionObject
// based on the parsed values from Read_Res
//
    #define READ_RES_EXT_OBJ_LINK_ID_DST_IDX        3 // Link back into OPCUA_Binary::ReadExtensionObjectLink

    #define READ_RES_EXT_OBJ_NODE_ID_ENCODING_MASK  4
    #define READ_RES_EXT_OBJ_NODE_ID_NAMESPACE_IDX  5
    #define READ_RES_EXT_OBJ_NODE_ID_NUMERIC        6
    #define READ_RES_EXT_OBJ_NODE_ID_STRING         7 
    #define READ_RES_EXT_OBJ_NODE_ID_GUID           8 
    #define READ_RES_EXT_OBJ_NODE_ID_OPAQUE         9 

    #define READ_RES_EXT_OBJ_TYPE_ID_STR_IDX        10
    #define READ_RES_EXT_OBJ_ENCODING_IDX           11
    #define READ_RES_IDENTITY_TOKEN_LINK_ID_SRC_IDX 12 // Link into OPCUA_Binary::ReadExtensionObjectIdentityToken

//
// Index constants for setting values in OPCUA_Binary::ReadExtensionObjectIdentityToken
// based on the parsed values from Read_Res
//
    #define READ_RES_IDENTITY_TOKEN_LINK_ID_DST_IDX 3 // Link back into OPCUA_Binary::ReadExtensionObject

    // Common among all IdentityTokens; Only field for AnonymousIdentityToken
    #define READ_RES_EXT_OBJ_POLICY_ID_IDX          4

    // UsernameIdentityToken
    #define READ_RES_EXT_OBJ_USER_NAME_IDX          5
    #define READ_RES_EXT_OBJ_PASSWORD_IDX           6  
    #define READ_RES_EXT_OBJ_ENCRYPT_ALG_IDX        7 

    // Common in X509IdentityToken and IssuedIdentityToken
    #define READ_RES_EXT_OBJ_CERT_DATA_IDX          8 

    // IssuedIdentityToken
    #define READ_RES_EXT_OBJ_TOKEN_DATA_IDX         9

#endif
