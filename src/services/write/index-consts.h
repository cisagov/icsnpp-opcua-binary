// Write consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Jason Rush
// Contact:  jason.rush@inl.gov
//
// Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_WRITE_CONSTS_H
#define OPCUA_BINARY_WRITE_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::Write
// based on the parsed values from Write_Req and Write_Res
//
    #define WRITE_OPCUA_LINK_ID_DST_IDX               8   // Id back into OCPUA_Binary::Info log

    // Request
    #define WRITE_REQ_NODES_TO_WRITE_LINK_ID_SRC_IDX  9   // Id into OPCUA_Binary::NodesToWrite log

    // Response
    #define WRITE_RES_RESULTS_LINK_ID_SRC_IDX        10   // Id into OPCUA_Binary::StatusCodeDetail log
    #define WRITE_RES_DIAG_INFO_LINK_ID_SRC_IDX      11   // Id into OPCUA_Binary::WriteDiagnosticInfo log

//
// Index constants for setting values in OPCUA_Binary::NodesToWrite
// based on the parsed values from Write_Req
//
    #define WRITE_REQ_NODES_TO_WRITE_LINK_ID_DST_IDX  8  // Id back into OPCUA_Binary::Write log

    // OpcUA_NodeId
    #define WRITE_REQ_NODE_ID_ENCODING_MASK_IDX       9
    #define WRITE_REQ_NODE_ID_NAMESPACE_ID_IDX       10
    #define WRITE_REQ_NODE_ID_NUMERIC_IDX            11
    #define WRITE_REQ_NODE_ID_STRING_IDX             12
    #define WRITE_REQ_NODE_ID_GUID_IDX               13
    #define WRITE_REQ_NODE_ID_OPAQUE_IDX             14
  
    #define WRITE_REQ_ATTRIBUTE_ID_IDX               15
    #define WRITE_REQ_ATTRIBUTE_ID_STR_IDX           16
    #define WRITE_REQ_INDEX_RANGE_IDX                17

#endif
