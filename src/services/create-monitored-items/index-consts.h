
//  CreateMonitoredItems Request/Response consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Melanie Pierce
// Contact:  Melanie.Pierce@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_CREATE_MONITORED_ITEMS_CONSTS_H
#define OPCUA_CREATE_MONITORED_ITEMS_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::CreateMonitoredItems
// based on the parsed values from CreateMonitoredItems_Req and CreateMonitoredItems_Res
//
#define CREATE_MONITORED_ITEMS_OPCUA_ID_LINK_IDX                                3 // Id back into OCPUA_Binary::Info log
#define CREATE_MONITORED_ITEMS_SUBSCRIPTION_ID_IDX                              4
#define CREATE_MONITORED_ITEMS_TIMESTAMPS_TO_RETURN_IDX                         5
#define CREATE_MONITORED_ITEMS_TIMESTAMPS_TO_RETURN_STR_IDX                     6
#define CREATE_MONITORED_ITEMS_MONITORED_ITEM_LINK_ID_SRC_IDX                   7 // Id into Monitored Item
#define CREATE_MONITORED_ITEMS_RESPONSE_DIAG_INFO_LINK_ID_SRC_IDX               8 // Id into DiagnosticInfo detail


// Monitored Item Indexes
#define MONITORED_ITEM_LINK_ID_DST_IDX                                          3
#define ITEM_TO_MONITOR_NODE_ID_ENCODING_MASK_IDX                               4
#define ITEM_TO_MONITOR_NODE_ID_NAMESPACE_IDX                                   5
#define ITEM_TO_MONITOR_NODE_ID_NUMERIC_IDX                                     6
#define ITEM_TO_MONITOR_NODE_ID_STRING_IDX                                      7
#define ITEM_TO_MONITOR_NODE_ID_IDX                                             8
#define ITEM_TO_MONITOR_NODE_ID_OPAQUE_IDX                                      9
#define ITEM_TO_MONITOR_ATTRIBUTE_ID_IDX                                       10
#define ITEM_TO_MONITOR_INDEX_RANGE_IDX                                        11
#define ITEM_TO_MONITOR_DATA_ENCODING_NAMESPACE_INDEX_IDX                      12
#define ITEM_TO_MONITOR_DATA_ENCODING_NAME_IDX                                 13
#define MONITORED_ITEM_MONITORING_MODE_IDX                                     14
#define MONITORING_PARAMETERS_CLIENT_HANDLE_IDX                                15 
#define MONITORING_PARAMETERS_SAMPLING_INTERVAL_IDX                            16
#define MONITORING_PARAMETERS_QUEUE_SIZE_IDX                                   17
#define MONITORING_PARAMETERS_DISCARD_OLDEST_IDX                               18
#define MONITORING_PARAMETERS_FILTER_INFO_EXT_OBJ_TYPE_ID_ENCODING_MASK_IDX    19
#define MONITORING_PARAMETERS_FILTER_INFO_EXT_OBJ_TYPE_ID_NAMESPACE_IDX        20 
#define MONITORING_PARAMETERS_FILTER_INFO_EXT_OBJ_TYPE_ID_NUMERIC_IDX          21          
#define MONITORING_PARAMETERS_FILTER_INFO_EXT_OBJ_TYPE_ID_STRING_IDX           22             
#define MONITORING_PARAMETERS_FILTER_INFO_EXT_OBJ_TYPE_ID_GUID_IDX             23              
#define MONITORING_PARAMETERS_FILTER_INFO_EXT_OBJ_TYPE_ID_OPAQUE_IDX           24 
#define MONITORING_PARAMETERS_FILTER_INFO_EXT_OBJ_TYPE_ID_STR_IDX              25
#define MONITORING_PARAMETERS_FILTER_INFO_EXT_OBJ_ENCODING_IDX                 26
#define MONITORING_PARAMETERS_FILTER_INFO_LINK_ID_SRC_IDX                      27
#define MONITORED_ITEM_STATUS_CODE_LINK_ID_SRC_IDX                             28
#define MONTORED_ITEM_INDEX_ID_IDX                                             29
#define MONITORING_PARAMETERS_REVISED_SAMPLING_INTERVAL_IDX                    30
#define MONITORING_PARAMETERS_REVISED_QUEUE_SIZE_IDX                           31

// Diagnostic Info link file
#define CREATE_MONITORED_ITEMS_RESPONSE_DIAG_INFO_LINK_ID_DST_IDX               3 // Id back into OPCUA_Binary::CreateMonitoredItems
#define CREATE_MONITORED_ITEMS_DIAG_INFO_LINK_ID_SRC_IDX                        4 // Id into OPCUA_Binary::DiagnosticInfoDetail

#endif