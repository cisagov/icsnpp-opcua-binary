// Variant consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_VARIANT_CONSTS_H
#define OPCUA_BINARY_VARIANT_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::VariantMetadata
// based on the parsed values from an OPCUA Variant
//
    #define VARIANT_DATA_SOURCE_LINK_ID_IDX         8
    #define VARIANT_DATA_SOURCE_IDX                 9
    #define VARIANT_DATA_SOURCE_STR_IDX             10
    #define VARIANT_ENCODING_MASK_IDX               11
    #define VARIANT_TYPE_IDX                        12
    #define VARIANT_TYPE_STR_IDX                    13
    #define VARIANT_BUILT_IN_DATA_TYPE_IDX          14
    #define VARIANT_BUILT_IN_DATA_TYPE_STR_IDX      15
    #define VARIANT_DATA_LINK_ID_SRC_IDX            16 // Id into OPCUA_Binary::VariantData
    #define VARIANT_DATA_ARRAY_DIM_IDX              17 
    #define VARIANT_DATA_ARRAY_LINK_ID_SRC_IDX      18 // Link into OPCUA_Binary::VariantArrayDims

//
// Index constants for setting values in OPCUA_Binary::VariantData
// based on the parsed values from an OPCUA Variant
//
    #define VARIANT_DATA_LINK_ID_DST_IDX              8 // Id back into OPCUA_Binary::VariantMetadata

    // Signed numerics - e.g. int8, int16, etc
    #define VARIANT_DATA_VALUE_SIGNED_NUMERIC_IDX     9    

    // Unsigned numerics - e.g. uint8, uint16, etc
    #define VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX   10

    // OpcUA_String, OpcUA_Guid, OpcUA_ByteString, etc
    #define VARIANT_DATA_VALUE_STRING_IDX             11

    // OpcUA_NodeId & OpcUA_ExpandedNodeId
    #define VARIANT_DATA_NODE_ID_ENCODING_MASK_IDX    12
    #define VARIANT_DATA_NODE_ID_NAMESPACE_IDX        13
    #define VARIANT_DATA_NODE_ID_NUMERIC_IDX          14
    #define VARIANT_DATA_NODE_ID_STRING_IDX           15
    #define VARIANT_DATA_NODE_ID_GUID_IDX             16
    #define VARIANT_DATA_NODE_ID_OPAQUE_IDX           17
    #define VARIANT_DATA_NODE_ID_NAMESPACE_URI_IDX    18
    #define VARIANT_DATA_NODE_ID_SERVER_IDX           19

    // OpcUA_DateTime
    #define VARIANT_DATA_VALUE_TIME_IDX               20

    // OpcUA_QualifiedName
    #define VARIANT_DATA_ENCODING_NAME_ID_IDX         21
    #define VARIANT_DATA_ENCODING_NAME_IDX            22

    // OpcUA_LocalizedText
    #define VARIANT_DATA_MASK_IDX                     23
    #define VARIANT_DATA_LOCALE_IDX                   24
    #define VARIANT_DATA_TEXT_IDX                     25

    // OpcUA_Float & OpcUA_Double
    #define VARIANT_DATA_VALUE_DECIMAL_IDX            26    

    // OpcUA_StatusCode
    #define VARIANT_DATA_STATUS_CODE_LINK_ID_SRC_IDX  27 // Link into OPCUA_Binary::ReadStatusCode log 

    // OpcUA_DiagInfo
    #define VARIANT_DATA_DIAG_INFO_LINK_ID_SRC_IDX    28 // Link into OPCUA_Binary::ReadDiagnosticInfo log
    
    // OpcUA_ExtensionObject
    #define VARIANT_DATA_EXT_OBJ_LINK_ID_SRC_IDX      29 // Link into OPCUA_Binary::ReadExtensionObjectLink

    //
    // OpcUA_DataValue
    // Note: A OpcUA_DataVariant that is itself of type OpcUA_DataVariant is handled by recursively calling the read variant
    // data processing and linking into the OPCUA_Binary::VariantMetadata
    //
    #define VARIANT_DATA_VARIANT_LINK_ID_SRC_IDX      30 // Link into OPCUA_Binary::VariantMetadata

    #define VARIANT_DATA_VALUE_LINK_ID_SRC_IDX        31


//
// Index constants for setting values in OPCUA_Binary::VariantArrayDims
// based on the parsed values from the variant
//
    #define VARIANT_ARRAY_LINK_ID_DST_IDX 3 // Link back into OPCUA_Binary::VariantMetadata
    #define VARIANT_DIMENSION_IDX         4 
//
// Index constants for setting values in OPCUA_Binary::VariantExtensionObject
// based on the parsed values from the variant object
//
    #define VARIANT_EXT_OBJ_LINK_ID_DST_IDX        3 // Link back into OPCUA_Binary::VariantData

    #define VARIANT_EXT_OBJ_NODE_ID_ENCODING_MASK  4
    #define VARIANT_EXT_OBJ_NODE_ID_NAMESPACE_IDX  5
    #define VARIANT_EXT_OBJ_NODE_ID_NUMERIC        6
    #define VARIANT_EXT_OBJ_NODE_ID_STRING         7 
    #define VARIANT_EXT_OBJ_NODE_ID_GUID           8 
    #define VARIANT_EXT_OBJ_NODE_ID_OPAQUE         9 

    #define VARIANT_EXT_OBJ_TYPE_ID_STR_IDX        10
    #define VARIANT_EXT_OBJ_ENCODING_IDX           11

//
// Index constants for setting values in OPCUA_Binary::VariantDataValue
// based on the parsed values from the variant object
//
    #define VARIANT_DATA_VALUE_LINK_ID_DST_IDX                  3 // Id back into OPCUA_Binary::DataVariant
    #define VARIANT_DATA_VALUE_ENCODING_MASK_IDX                4
    #define VARIANT_STATUS_CODE_LINK_ID_SRC_IDX                 5 // Id into OPCUA_Binary::StatusCodeDetail log
    #define VARIANT_SOURCE_TIMESTAMP_IDX                        6
    #define VARIANT_SOURCE_PICO_SEC_IDX                         7
    #define VARIANT_SERVER_TIMESTAMP_IDX                        8
    #define VARIANT_SERVER_PICO_SEC_IDX                         9 

#endif
