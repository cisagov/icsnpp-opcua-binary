// Get Endpoints consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_BROWSE_CONSTS_H
#define OPCUA_BINARY_BROWSE_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::Browse
// based on the parsed values from Browse_Req and Browse_Res
//
#define BROWSE_OPCUA_ID_LINK_IDX                                3
// The ID_ENCODING_MASK is also used as the offset
#define BROWSE_VIEW_ID_ENCODING_MASK_IDX                        4
#define BROWSE_VIEW_ID_NAMESPACE_IDX                            5
#define BROWSE_VIEW_ID_NUMERIC_IDX                              6
#define BROWSE_VIEW_ID_STRING_IDX                               7
#define BROWSE_VIEW_ID_GUID_IDX                                 8
#define BROWSE_VIEW_ID_OPAQUE_IDX                               9

#define BROWSE_VIEW_DESCRIPTION_TIMESTAMP_IDX                  10 
#define BROWSE_VIEW_DESCRIPTION_VIEW_VERSION_IDX               11 
#define BROWSE_REQ_MAX_REFS_IDX                                12 

#define BROWSE_DESCRIPTION_ID_ENCODING_MASK_IDX                13
#define BROWSE_DESCRIPTION_ID_NAMESPACE_IDX                    14
#define BROWSE_DESCRIPTION_ID_NUMERIC_IDX                      15
#define BROWSE_DESCRIPTION_ID_STRING_IDX                       16
#define BROWSE_DESCRIPTION_ID_GUID_IDX                         17
#define BROWSE_DESCRIPTION_ID_OPAQUE_IDX                       18

#define BROWSE_DIRECTION_ID_IDX                                19

#define BROWSE_DESCRIPTION_REF_ID_ENCODING_MASK_IDX            20
#define BROWSE_DESCRIPTION_REF_ID_NAMESPACE_IDX                21
#define BROWSE_DESCRIPTION_REF_ID_NUMERIC_IDX                  22
#define BROWSE_DESCRIPTION_REF_ID_STRING_IDX                   23
#define BROWSE_DESCRIPTION_REF_ID_GUID_IDX                     24
#define BROWSE_DESCRIPTION_REF_ID_OPAQUE_IDX                   25

#define BROWSE_DESCRIPTION_INCLUDE_SUBTYPES_IDX                26 
#define BROWSE_DESCRIPTION_NODE_CLASS_MASK_IDX                 27
#define BROWSE_DESCRIPTION_RESULT_MASK_IDX                     28

#define BROWSE_RESPONSE_STATUS_CODE_IDX                        29
#define BROWSE_RESPONSE_CONTINUATION_POINT_IDX                 30
#define BROWSE_RESPONSE_NUM_REFERENCES_IDX                     31


// Log reference events in a separate file

#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_ENCODING_MASK_IDX    4
#define BBROWSE_RESPONSE_REFERENCE_TYPE_ID_NAMESPACE_IDX       5
#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_NUMERIC_IDX          6                 
#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_STRING_IDX           7                   
#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_GUID_IDX             8                    
#define BROWSE_RESPONSE_REFERENCE_TYPE_ID_OPAQUE_IDX           9 

#define BROWSE_RESPONSE_IS_FWD_IDX                             10      

//Expanded Node IDs are very similar to standard NodeIDs.
//However, Expanded Node IDs require two extra indexes
#define BROWSE_RESPONSE_TARGET_ID_ENCODING_MASK_IDX           11
#define BBROWSE_RESPONSE_TARGET_ID_NAMESPACE_IDX              12 
#define BROWSE_RESPONSE_TARGET_ID_NUMERIC_IDX                 13           
#define BROWSE_RESPONSE_TARGET_ID_STRING_IDX                  14             
#define BROWSE_RESPONSE_TARGET_ID_GUID_IDX                    15              
#define BROWSE_RESPONSE_TARGET_ID_OPAQUE_IDX                  16 
#define BROWSE_RESPONSE_TARGET_ID_NAMESPACE_URI_IDX           17  
#define BROWSE_RESPONSE_TARGET_ID_SERVER_IDX_IDX              18  

#define BROWSE_RESPONSE_BROWSE_NAMESPACE_IDX_IDX              19
#define BROWSE_RESPONSE_BROWSE_NAME_IDX                       20
#define BROWSE_RESPONSE_DISPLAY_NAME_ENCODING_IDX             21
#define BROWSE_RESPONSE_DISPLAY_NAME_LOCALE_IDX               22
#define BROWSE_RESPONSE_DISPLAY_NAME_TEXT_IDX                 23
#define BROWSE_RESPONSE_NODE_CLASS_IDX                        24

#define BROWSE_RESPONSE_TYPE_DEF_ENCODING_MASK_IDX            25
#define BBROWSE_RESPONSE_TYPE_DEF_NAMESPACE_IDX               26 
#define BROWSE_RESPONSE_TYPE_DEF_NUMERIC_IDX                  27           
#define BROWSE_RESPONSE_TYPE_DEF_STRING_IDX                   28             
#define BROWSE_RESPONSE_TYPE_DEF_GUID_IDX                     29              
#define BROWSE_RESPONSE_TYPE_DEF_OPAQUE_IDX                   30 
#define BROWSE_RESPONSE_TYPE_DEF_NAMESPACE_URI_IDX            31  
#define BROWSE_RESPONSE_TYPE_DEF_SERVER_IDX_IDX               32  

#endif