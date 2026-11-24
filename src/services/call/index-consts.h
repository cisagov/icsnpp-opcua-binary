// Call consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   John B Joseph
//

#ifndef OPCUA_BINARY_CALL_CONSTS_H
#define OPCUA_BINARY_CALL_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::Call
// based on the parsed values from Call_Req and Call_Res
//
    #define CALL_OPCUA_LINK_ID_DST_IDX                          8   // Id back into OCPUA_Binary::Info log

    // Request - one OPCUA_Binary::Call record per CallMethodRequest

    // ObjectId : OpcUA_NodeId
    #define CALL_REQ_OBJECT_ID_ENCODING_MASK_IDX                9
    #define CALL_REQ_OBJECT_ID_NAMESPACE_ID_IDX                10
    #define CALL_REQ_OBJECT_ID_NUMERIC_IDX                     11
    #define CALL_REQ_OBJECT_ID_STRING_IDX                      12
    #define CALL_REQ_OBJECT_ID_GUID_IDX                        13
    #define CALL_REQ_OBJECT_ID_OPAQUE_IDX                      14

    // MethodId : OpcUA_NodeId
    #define CALL_REQ_METHOD_ID_ENCODING_MASK_IDX               15
    #define CALL_REQ_METHOD_ID_NAMESPACE_ID_IDX                16
    #define CALL_REQ_METHOD_ID_NUMERIC_IDX                     17
    #define CALL_REQ_METHOD_ID_STRING_IDX                      18
    #define CALL_REQ_METHOD_ID_GUID_IDX                        19
    #define CALL_REQ_METHOD_ID_OPAQUE_IDX                      20

    #define CALL_REQ_INPUT_ARGUMENTS_VARIANT_LINK_ID_SRC_IDX   21   // Id into OPCUA_Binary::VariantMetadata log

    // Response - one OPCUA_Binary::Call record per CallMethodResult
    #define CALL_RES_STATUS_CODE_LINK_ID_SRC_IDX               22   // Id into OPCUA_Binary::StatusCodeDetail log
    #define CALL_RES_INPUT_ARG_RESULTS_LINK_ID_SRC_IDX         23   // Id into OPCUA_Binary::StatusCodeDetail log
    #define CALL_RES_INPUT_ARG_DIAG_INFO_LINK_ID_SRC_IDX       24   // Id into OPCUA_Binary::DiagnosticInfoDetail log
    #define CALL_RES_OUTPUT_ARGUMENTS_VARIANT_LINK_ID_SRC_IDX  25   // Id into OPCUA_Binary::VariantMetadata log
    #define CALL_RES_DIAG_INFO_LINK_ID_SRC_IDX                 26   // Id into OPCUA_Binary::DiagnosticInfoDetail log

#endif
