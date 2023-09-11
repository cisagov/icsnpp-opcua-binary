//  Browse consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Melanie Pierce
// Contact:  Melanie.Pierce@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_BROWSE_CONSTS_H
#define OPCUA_BINARY_BROWSE_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::Browse
// based on the parsed values from Browse_Req and Browse_Res
//
#define BROWSE_OPCUA_LINK_ID_DST_IDX                            8
#define BROWSE_SERVICE_TYPE_IDX                                 9
// The ID_ENCODING_MASK is also used as the offset
#define BROWSE_VIEW_ID_ENCODING_MASK_IDX                       10
#define BROWSE_VIEW_ID_NAMESPACE_IDX                           11
#define BROWSE_VIEW_ID_NUMERIC_IDX                             12
#define BROWSE_VIEW_ID_STRING_IDX                              13
#define BROWSE_VIEW_ID_GUID_IDX                                14
#define BROWSE_VIEW_ID_OPAQUE_IDX                              15

#define BROWSE_VIEW_DESCRIPTION_TIMESTAMP_IDX                  16 
#define BROWSE_VIEW_DESCRIPTION_VIEW_VERSION_IDX               17 
#define BROWSE_REQ_MAX_REFS_IDX                                18
#define BROWSE_DESCRTIPTION_LINK_ID_SRC_IDX                    19 // Id into OPCUA_Binary::BrowseDescription log

#define BROWSE_NEXT_RELEASE_CONTINUATION_POINTS_IDX            20 
#define BROWSE_NEXT_LINK_ID_SRC_IDX                            21 // Id into OPCUA_Binary::BrowseRequestContinuationPoint

#define BROWSE_RESPONSE_LINK_ID_SRC_IDX                        22
#define BROWSE_RESPONSE_DIAG_INFO_LINK_ID_SRC_IDX              23 // Id into OPCUA_Binary::BrowseDiagnosticInfo log

//Browse Description Constants

#define BROWSE_DESCRIPTION_LINK_ID_DST_IDX                      8
#define BROWSE_DESCRIPTION_ID_ENCODING_MASK_IDX                 9
#define BROWSE_DESCRIPTION_ID_NAMESPACE_IDX                    10 
#define BROWSE_DESCRIPTION_ID_NUMERIC_IDX                      11
#define BROWSE_DESCRIPTION_ID_STRING_IDX                       12
#define BROWSE_DESCRIPTION_ID_GUID_IDX                         13
#define BROWSE_DESCRIPTION_ID_OPAQUE_IDX                       14

#define BROWSE_DIRECTION_ID_IDX                                15

#define BROWSE_DESCRIPTION_REF_ID_ENCODING_MASK_IDX            16
#define BROWSE_DESCRIPTION_REF_ID_NAMESPACE_IDX                17
#define BROWSE_DESCRIPTION_REF_ID_NUMERIC_IDX                  18
#define BROWSE_DESCRIPTION_REF_ID_STRING_IDX                   19
#define BROWSE_DESCRIPTION_REF_ID_GUID_IDX                     20
#define BROWSE_DESCRIPTION_REF_ID_OPAQUE_IDX                   21

#define BROWSE_DESCRIPTION_INCLUDE_SUBTYPES_IDX                22
#define BROWSE_DESCRIPTION_NODE_CLASS_MASK_IDX                 23
#define BROWSE_DESCRIPTION_RESULT_MASK_IDX                     24

//Browse Response Objects

#define BROWSE_RESPONSE_LINK_ID_DST_IDX                         8
#define BROWSE_RESPONSE_STATUS_CODE_LINK_ID_SRC_IDX             9 // Id into OPCUA_Binary::StatusCodeDetail log
#define BROWSE_RESPONSE_CONTINUATION_POINT_IDX                 10
#define BROWSE_RESPONSE_REFERENCE_LINK_ID_SRC_IDX              11

// Browse Continuation Points

#define BROWSE_NEXT_LINK_ID_DST_IDX                             8
#define BROWSE_CONTINUATION_POINT_IDX                           9

// Log reference events in a separate file

#define BROWSE_RESPONSE_REFERENCE_LINK_ID_DST_IDX               8
#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_ENCODING_MASK_IDX     9
#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_NAMESPACE_IDX        10
#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_NUMERIC_IDX          11
#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_STRING_IDX           12
#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_GUID_IDX             13
#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_OPAQUE_IDX           14

#define BROWSE_RESPONSE_IS_FWD_IDX                             15      

//Expanded Node IDs are very similar to standard NodeIDs.
//However, Expanded Node IDs require two extra indexes
#define BROWSE_RESPONSE_TARGET_ID_ENCODING_MASK_IDX            16
#define BROWSE_RESPONSE_TARGET_ID_NAMESPACE_IDX                17 
#define BROWSE_RESPONSE_TARGET_ID_NUMERIC_IDX                  18           
#define BROWSE_RESPONSE_TARGET_ID_STRING_IDX                   19             
#define BROWSE_RESPONSE_TARGET_ID_GUID_IDX                     20
#define BROWSE_RESPONSE_TARGET_ID_OPAQUE_IDX                   21
#define BROWSE_RESPONSE_TARGET_ID_NAMESPACE_URI_IDX            22
#define BROWSE_RESPONSE_TARGET_ID_SERVER_IDX_IDX               23

#define BROWSE_RESPONSE_BROWSE_NAMESPACE_IDX_IDX               24
#define BROWSE_RESPONSE_BROWSE_NAME_IDX                        25
#define BROWSE_RESPONSE_DISPLAY_NAME_ENCODING_IDX              26
#define BROWSE_RESPONSE_DISPLAY_NAME_LOCALE_IDX                27
#define BROWSE_RESPONSE_DISPLAY_NAME_TEXT_IDX                  28
#define BROWSE_RESPONSE_NODE_CLASS_IDX                         29

#define BROWSE_RESPONSE_TYPE_DEF_ENCODING_MASK_IDX             30
#define BROWSE_RESPONSE_TYPE_DEF_NAMESPACE_IDX                 31
#define BROWSE_RESPONSE_TYPE_DEF_NUMERIC_IDX                   32
#define BROWSE_RESPONSE_TYPE_DEF_STRING_IDX                    33
#define BROWSE_RESPONSE_TYPE_DEF_GUID_IDX                      34
#define BROWSE_RESPONSE_TYPE_DEF_OPAQUE_IDX                    35 
#define BROWSE_RESPONSE_TYPE_DEF_NAMESPACE_URI_IDX             36  
#define BROWSE_RESPONSE_TYPE_DEF_SERVER_IDX_IDX                37  

// Diagnostic Info Constants
#define BROWSE_RESPONSE_DIAG_INFO_LINK_ID_DST_IDX              8 // Id back into OPCUA_Binary::Browse
#define BROWSE_DIAG_INFO_LINK_ID_SRC_IDX                       9 // Id into OPCUA_Binary::DiagnosticInfoDetail

#endif
