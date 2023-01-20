//  Filter consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Melanie Pierce
// Contact:  Melanie.Pierce@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_FILTER_CONSTS_H
#define OPCUA_FILTER_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::Filters

// Data Change Filter Parameter Indexes
#define DATA_CHANGE_FILTER_REQ_LINK_ID_DST_IDX                                      3
#define DATA_CHANGE_FILTER_REQ_TRIGGER_IDX                                          4
#define DATA_CHANGE_FILTER_REQ_DEADBAND_TYPE_IDX                                    5
#define DATA_CHANGE_FILTER_REQ_DEADBAND_VALUE                                       6

// Aggregate Filter Parameter Indexes
#define AGGREGATE_FILTER_LINK_ID_DST_IDX                                            3
#define AGGREGATE_FILTER_START_TIME_IDX                                             4
#define AGGREGATE_FILTER_START_TIME_STR_IDX                                         5
#define AGGREGATE_FILTER_AGGREGATE_TYPE_ID_ENCODING_MASK_IDX                        6
#define AGGREGATE_FILTER_AGGREGATE_TYPE_ID_NAMESPACE_IDX                            7
#define AGGREGATE_FILTER_AGGREGATE_TYPE_ID_NUMERIC_IDX                              8          
#define AGGREGATE_FILTER_AGGREGATE_TYPE_ID_STRING_IDX                               9            
#define AGGREGATE_FILTER_AGGREGATE_TYPE_ID_GUID_IDX                                10             
#define AGGREGATE_FILTER_AGGREGATE_TYPE_ID_OPAQUE_IDX                              11 
#define AGGREGATE_FILTER_PROCESSING_INTERVAL_IDX                                   12
#define AGGREGATE_FILTER_CONFIGURATION_USE_SERVER_CAPABILITES_DEFAULT_IDX          13
#define AGGREGATE_FILTER_CONFIGURATION_TREAT_UNCERTAIN_AS_BAD_IDX                  14
#define AGGREGATE_FILTER_CONFIGURATION_PERCENT_DATA_GOOD_IDX                       15
#define AGGREGATE_FILTER_CONFIGURATION_PERCENT_DATA_BAD_IDX                        16
#define AGGREGATE_FILTER_CONFIGURATION_USE_SLOPED_EXTRAPOLATION_IDX                17
#define AGGREGATE_FILTER_REVISED_START_TIME_IDX                                    18
#define AGGREGATE_FILTER_REVISED_START_TIME_STR_IDX                                19
#define AGGREGATE_FILTER_REVISED_PROCESSING_INTERVAL_IDX                           20
#define AGGREGATE_FILTER_REVISED_CONFIGURATION_USE_SERVER_CAPABILITES_DEFAULT_IDX  21
#define AGGREGATE_FILTER_REVISED_CONFIGURATION_TREAT_UNCERTAIN_AS_BAD_IDX          22
#define AGGREGATE_FILTER_REVISED_CONFIGURATION_PERCENT_DATA_GOOD_IDX               23
#define AGGREGATE_FILTER_REVISED_CONFIGURATION_PERCENT_DATA_BAD_IDX                24
#define AGGREGATE_FILTER_REVISED_CONFIGURATION_USE_SLOPED_EXTRAPOLATION_IDX        25

// Event Filter Parameter Indexes
#define EVENT_FILTER_LINK_ID_DST_IDX                                                3
#define EVENT_FILTER_SELECT_CLAUSES_LINK_ID_SRC_IDX                                 4
#define EVENT_FILTER_CONTENT_FILTER_LINK_ID_SRC_IDX                                 5
#define EVENT_FILTER_RESULT_DIAG_INFO_LINK_ID_SRC_IDX                               6

// Select Clause Parameter Indexes
#define SELECT_CLAUSE_LINK_ID_DST_IDX                                               3
#define SELECT_CLAUSE_TYPE_ID_ENCODING_MASK_IDX                                     4
#define SELECT_CLAUSE_TYPE_ID_NAMESPACE_IDX                                         5
#define SELECT_CLAUSE_TYPE_ID_NUMERIC_IDX                                           6
#define SELECT_CLAUSE_TYPE_ID_STRING_IDX                                            7
#define SELECT_CLAUSE_TYPE_ID_GUID_IDX                                              8
#define SELECT_CLAUSE_TYPE_ID_OPAQUE_IDX                                            9
#define SELECT_CLAUSE_BROWSE_PATH_LINK_ID_SRC_IDX                                  10
#define SELECT_CLAUSE_ATTRIBUTE_ID_IDX                                             11
#define SELECT_CLAUSE_INDEX_RANGE_IDX                                              12
#define SELECT_CLAUSE_RESULT_STATUS_CODE_LINK_ID_SRC_IDX                           13
#define SELECT_CLAUSE_RESULT_DIAGNOSTIC_INFO_LINK_ID_SRC_IDX                       14


// Content Filter Parameter Indexes
#define EVENT_FILTER_CONTENT_FILTER_LINK_ID_DST_IDX                                 3
#define CONTENT_FILTER_ELEMENT_LINK_ID_SRC_IDX                                      4
#define CONTENT_FILTER_RESULT_STATUS_CODE_LINK_ID_SRC_IDX                           5
#define CONTENT_FILTER_RESULT_DIAG_INFO_LINK_ID_SRC_IDX                             6

// Content Filter Element Parameter Indexes
#define CONTENT_FILTER_LINK_ID_DST_IDX                                              3
#define CONTENT_FILTER_FILTER_OPERATOR_IDX                                          4
#define CONTENT_FILTER_FILTER_OPERAND_EXT_OBJ_TYPE_ID_ENCODING_MASK_IDX             5
#define CONTENT_FILTER_FILTER_OPERAND_EXT_OBJ_TYPE_ID_NAMESPACE_IDX                 6
#define CONTENT_FILTER_FILTER_OPERAND_EXT_OBJ_TYPE_ID_NUMERIC_IDX                   7         
#define CONTENT_FILTER_FILTER_OPERAND_EXT_OBJ_TYPE_ID_STRING_IDX                    8           
#define CONTENT_FILTER_FILTER_OPERAND_EXT_OBJ_TYPE_ID_GUID_IDX                      9             
#define CONTENT_FILTER_FILTER_OPERAND_EXT_OBJ_TYPE_ID_OPAQUE_IDX                   10 
#define CONTENT_FILTER_FILTER_OPERAND_EXT_OBJ_TYPE_ID_STR_IDX                      11
#define CONTENT_FILTER_FILTER_OPERAND_EXT_OBJ_ENCODING_IDX                         12
#define CONTENT_FILTER_FILTER_OPERANDS_LINK_ID_SRC_IDX                             13
#define OPERAND_RESULT_STATUS_CODE_LINK_ID_SRC_IDX                                 14
#define OPERAND_RESULT_DIAG_INFO_LINK_ID_SRC_IDX                                   15

// Element Operand Parameter Indexes
#define ELEMENT_OPERAND_LINK_ID_DST_IDX                                             3
#define ELEMENT_OPERAND_INDEX_IDX                                                   4

// Literal Operand Parameter Indexes: Left Blank for now
#define LITERAL_OPERAND_LINK_ID_DST_IDX                                             3
#define LITERAL_OPERAND_VARIANT_LINK_IDX                                            4

// Attribute Operand Parmeter Indexes
#define ATTRIBUTE_OPERAND_LINK_ID_IDX                                               3
#define ATTRIBUTE_OPERAND_NODE_ID_ENCODING_MASK_IDX                                 4
#define ATTRIBUTE_OPERAND_NODE_ID_NAMESPACE_IDX                                     5
#define ATTRIBUTE_OPERAND_NODE_ID_NUMERIC_IDX                                       6
#define ATTRIBUTE_OPERAND_NODE_ID_STRING_IDX                                        7
#define ATTRIBUTE_OPERAND_NODE_ID_GUID_IDX                                          8
#define ATTRIBUTE_OPERAND_NODE_ID_OPAQUE_IDX                                        9
#define ATTRIBUTE_OPERAND_ALIAS_IDX                                                10
#define ATTRIBUTE_OPERAND_BROWSE_PATH_ELEMENT_LINK_ID_SRC_IDX                      11
#define ATTRIBUTE_OPERAND_ATTRIBUTE_IDX                                            12
#define ATTRIBUTE_OPERAND_INDEX_RANGE_IDX                                          13

// Browse Path Parameter Indexes
#define BROWSE_PATH_ELEMENT_LINK_ID_DST_IDX                                         3
#define BROWSE_PATH_ELEMENT_REFERENCE_TYPE_ID_ENCODING_MASK_IDX                     4
#define BROWSE_PATH_ELEMENT_REFERENCE_TYPE_ID_NAMESPACE_IDX                         5
#define BROWSE_PATH_ELEMENT_REFERENCE_TYPE_ID_NUMERIC_IDX                           6
#define BROWSE_PATH_ELEMENT_REFERENCE_TYPE_ID_STRING_IDX                            7
#define BROWSE_PATH_ELEMENT_REFERENCE_TYPE_ID_GUID_IDX                              8
#define BROWSE_PATH_ELEMENT_REFERENCE_TYPE_ID_OPAQUE_IDX                            9
#define BROWSE_PATH_ELEMENT_IS_INVERSE_IDX                                         10
#define BROWSE_PATH_ELEMENT_INCLUDE_SUBTYPES_IDX                                   11
#define BROWSE_PATH_ELEMENT_TARGET_NAME_NAMESPACE_IDX                              12
#define BROWSE_PATH_ELEMENT_TARGET_NAME_IDX                                        13

// Simple Attribute Operand Indexes
#define SIMPLE_ATTRIBUTE_OPERAND_LINK_ID_DST_IDX                                    3
#define SIMPLE_ATTRIBUTE_OPERAND_TYPE_ID_ENCODING_MASK_IDX                          4
#define SIMPLE_ATTRIBUTE_OPERAND_TYPE_ID_NAMESPACE_IDX                              5
#define SIMPLE_ATTRIBUTE_OPERAND_TYPE_ID_NUMERIC_IDX                                6
#define SIMPLE_ATTRIBUTE_OPERAND_TYPE_ID_STRING_IDX                                 7
#define SIMPLE_ATTRIBUTE_OPERAND_TYPE_ID_GUID_IDX                                   8
#define SIMPLE_ATTRIBUTE_OPERAND_TYPE_ID_OPAQUE_IDX                                 9
#define SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_LINK_ID_SRC_IDX                       10
#define SIMPLE_ATTRIBUTE_OPERAND_ATTRIBUTE_ID_IDX                                  11
#define SIMPLE_ATTRIBUTE_INDEX_RANGE_IDX                                           12

// Simple Attribute Operand Browse Path Indexes
#define SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_LINK_ID_DST_IDX                        3 
#define SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_SRC_LINK_ID_IDX                        4
#define SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_NAMSESPACE_IDX_IDX                     5
#define SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_NAME_IDX                               6

// Select Clause in Event Filter Diagnostic Info link file
#define EVENT_FILTER_RESPONSE_DIAG_INFO_LINK_ID_DST_IDX                             3 // Id back into OPCUA_Binary::SelectClause
#define EVENT_FILTER_DIAG_INFO_LINK_ID_SRC_IDX                                      4 // Id into OPCUA_Binary::DiagnosticInfoDetail

// Content Filter Elements Diagnostic Info link file
#define CONTENT_FILTER_RESPONSE_DIAG_INFO_LINK_ID_DST_IDX                           3 // Id back into OPCUA_Binary::ContentFilter
#define CONTENT_FILTER_DIAG_INFO_LINK_ID_SRC_IDX                                    4 // Id into OPCUA_Binary::DiagnosticInfoDetail

// Content Filter Elements Diagnostic Info link file
#define OPERAND_DIAG_INFO_LINK_ID_DST_IDX                                              3 // Id back into OPCUA_Binary::ContentFilterElementOperandResult
#define OPERAND_DIAG_INFO_LINK_ID_SRC_IDX                                           4 // Id into OPCUA_Binary::DiagnosticInfoDetail

#endif