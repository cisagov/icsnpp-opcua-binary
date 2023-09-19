// Read consts.h
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
    #define READ_OPCUA_LINK_ID_DST_IDX              8  // Id back into OCPUA_Binary::Info log

    // Request
    #define READ_REQ_MAX_AGE_IDX                    9
    #define READ_REQ_TIMESTAMPS_TO_RETURN_IDX      10
    #define READ_REQ_TIMESTAMPS_TO_RETURN_STR_IDX  11
    #define READ_REQ_NODES_TO_READ_LINK_ID_SRC_IDX 12  // Id into OPCUA_Binary::NoesToRead log

    // Response
    #define READ_RES_RESULTS_LINK_ID_SRC_IDX       13 // Id into OPCUA_Binary::ReadResults
    #define READ_RES_DIAG_INFO_LINK_ID_SRC_IDX     14 // Id into OPCUA_Binary::ReadDiagnosticInfo log

//
// Index constants for setting values in OPCUA_Binary::NodesToRead
// based on the parsed values from Read_Req
//
    #define READ_REQ_NODES_TO_READ_LINK_ID_DST_IDX 8  // Id back into OPCUA_Binary::Read log

    // OpcUA_NodeId
    #define READ_REQ_NODE_ID_ENCODING_MASK_IDX     9
    #define READ_REQ_NODE_ID_NAMESPACE_ID_IDX     10
    #define READ_REQ_NODE_ID_NUMERIC_IDX          11
    #define READ_REQ_NODE_ID_STRING_IDX           12
    #define READ_REQ_NODE_ID_GUID_IDX             13
    #define READ_REQ_NODE_ID_OPAQUE_IDX           14

    #define READ_REQ_ATTRIBUTE_ID_IDX             15
    #define READ_REQ_ATTRIBUTE_ID_STR_IDX         16
    #define READ_REQ_INDEX_RANGE_IDX              17

    // QualifiedName
    #define READ_REQ_DATA_ENCODING_NAME_ID_IDX    18
    #define READ_REQ_DATA_ENCODING_NAME_IDX       19


//
// Index constants for setting values in OPCUA_Binary::ReadResults
// based on the parsed values from Read_Res
//
    #define READ_RES_LINK_ID_DST_IDX                             8 // Id back into OPCUA_Binary::ReadResultsLink
    #define READ_RES_LEVEL_IDX                                   9
    #define READ_RES_DATA_VALUE_ENCODING_MASK_IDX               10
    #define READ_RES_STATUS_CODE_LINK_ID_SRC_IDX                11 // Id into OPCUA_Binary::StatusCodeDetail log
    #define READ_RES_SOURCE_TIMESTAMP_IDX                       12
    #define READ_RES_SOURCE_PICO_SEC_IDX                        13
    #define READ_RES_SERVER_TIMESTAMP_IDX                       14
    #define READ_RES_SERVER_PICO_SEC_IDX                        15
    #define READ_RES_VARIANT_DATA_LINK_IDX                      16


#endif
