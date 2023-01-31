## create-monitored-items-types.zeek
##
## OPCUA Binary Protocol Analyzer
##
## Zeek script type/record definitions describing the information
## that will be written to the log files.
##
## Author:   Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

module ICSNPP_OPCUA_Binary;

export {
    type OPCUA_Binary::CreateMonitoredItems: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;
        opcua_link_id               : string  &log;       # Id back into OCPUA_Binary::Info

        subscription_id                             : count &log &optional;
        timestamps_to_return                        : count &log &optional;
        timestamps_to_return_str                    : string &log &optional;
        create_item_link_id                         : string &log &optional; #Id into OPCUA_Binary::CreateMonitoredItemsItem
        create_monitored_items_diag_info_link_id    : string &log &optional; #Id into OPCUA_Binary::DiagnosticInfoDetail log
    };
    type OPCUA_Binary::CreateMonitoredItemsItem: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;
        create_item_link_id         : string &log; #Id back into OPCUA_Binary::CreateMonitoredItems

        item_to_monitor_node_id_encoding_mask   : string &log &optional;
        item_to_monitor_node_id_namespace_idx   : count  &log &optional;
        item_to_monitor_node_id_numeric         : count  &log &optional;
        item_to_monitor_node_id_string          : string &log &optional;
        item_to_monitor_node_id_guid            : string &log &optional;
        item_to_monitor_node_id_opaque          : string &log &optional;
        item_to_monitor_attribute_id            : string &log &optional;
        item_to_monitor_index_range             : string &log &optional;
        item_to_monitor_namespace_idx           : count  &log &optional;
        item_to_monitor_name                    : string &log &optional; 
        monitoring_mode                         : string &log &optional;
        monitoring_parameters_client_handle     : count  &log &optional;
        monitoring_parameters_sampling_interval : double &log &optional;
        monitoring_parameters_queue_size        : count  &log &optional;
        monitoring_parameters_discard_oldest    : bool   &log &optional;

        monitoring_parameters_filter_info_type_id_node_id_encoding_mask : string &log &optional;
        monitoring_parameters_filter_info_type_id_node_id_namespace_idx : count  &log &optional;
        monitoring_parameters_filter_info_type_id_node_id_numeric       : count  &log &optional;
        monitoring_parameters_filter_info_type_id_node_id_string        : string &log &optional;
        monitoring_parameters_filter_info_type_id_node_id_guid          : string &log &optional;
        monitoring_parameters_filter_info_type_id_node_id_opaque        : string &log &optional;
        monitoring_parameters_filter_info_type_id_string                : string &log &optional;
        monitoring_parameters_filter_info_type_id_encoding              : string &log &optional;   

        filter_info_details_link_id  : string &log &optional;  # Link into the filter details file as indicated by monitoring_parameters_filter_info_type_id_string

        monitoring_parameters_status_code_link_id       : string &log &optional; # Link into OPCUA_Binary::StatusCodeDetails
        monitored_item_index_id                         : count  &log &optional;
        monitoring_parameters_revised_sampling_interval : double &log &optional;
        monitoring_parameters_revised_queue_size        : count  &log &optional;
    };
}