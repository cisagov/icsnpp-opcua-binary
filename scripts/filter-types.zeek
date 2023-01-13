## filter-types.zeek
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
    type OPCUA_Binary::DataChangeFilter: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        monitored_parameters_link_id    : string &log;
        trigger                         : string &log &optional;
        deadband_type                   : string &log &optional;
        deadband_value                  : double &log &optional;
    };
    type OPCUA_Binary::AggregateFilter: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        monitored_parameters_link_id    : string &log;
        start_time                      : time   &log &optional;
        aggregate_type_encoding_mask    : string &log &optional;
        aggregate_type_namespace_idx    : count  &log &optional;
        aggregate_type_numeric          : count  &log &optional;
        aggregate_type_string           : string &log &optional;
        aggregate_type_guid             : string &log &optional;
        aggregate_type_opaque           : string &log &optional;
        processing_interval             : double &log &optional;

        use_server_capabilities_default : bool  &log &optional;
        treat_uncertain_as_bad          : bool  &log &optional;
        percent_data_good               : count &log &optional;
        percent_data_bad                : count &log &optional;
        use_slopped_extrapolation       : bool  &log &optional;

        revised_start_time                      : time   &log &optional;
        revised_processing_interval             : double &log &optional;
        revised_use_server_capabilities_default : bool   &log &optional;
        revised_treat_uncertain_as_bad          : bool   &log &optional;
        revised_percent_data_good               : count  &log &optional;
        revised_percent_data_bad                : count  &log &optional;
        revised_use_slopped_extrapolation       : bool   &log &optional;
    };
    type OPCUA_Binary::EventFilter: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        monitored_parameters_link_id            : string &log;
        select_clauses_link_id                  : string &log &optional;
        where_clause_link_id                    : string &log &optional;
        select_clause_diagnostic_info_link_id   : string &log &optional;
    };
    type OPCUA_Binary::ContentFilter: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        where_clause_link_id                    : string &log;
        content_filter_element_link_id          : string &log &optional;
        content_filter_element_result_link_id   : string &log &optional;
        content_filter_diag_info_link_id        : string &log &optional;
    };
    type OPCUA_Binary::ContentFilterElement: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        content_filter_element_link_id                        : string &log;
        filter_operator                                       : string &log &optional;
        content_filter_filter_operand_type_id_encoding_mask   : string &log &optional;
        content_filter_filter_operand_type_id_namespace_idx   : count  &log &optional;
        content_filter_filter_operand_type_id_numeric         : count  &log &optional;
        content_filter_filter_operand_type_id_string          : string &log &optional;
        content_filter_filter_operand_type_id_guid            : string &log &optional;
        content_filter_filter_operand_type_id_opaque          : string &log &optional;
        content_filter_filter_operand_type_id_string          : string &log &optional;
        content_filter_filter_operand_type_id_encoding        : string &log &optional;
        content_filter_filter_operand_link_id                 : string &log &optional;
        content_filter_status_code_link_id                    : string &log &optional;
        content_filter_operand_status_code_link_id            : string &log &optional;
        content_filter_operand_diag_info_link_id              : string &log &optional;
    };
    type OPCUA_Binary::SelectClause: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        simple_attribute_operand_link_id  : string &log;
        type_id_encoding_mask             : string &log &optional;
        type_id_namespace_idx             : count  &log &optional;
        type_id_numeric                   : count  &log &optional;
        type_id_string                    : string &log &optional;
        type_id_guid                      : string &log &optional;
        type_id_opaque                    : string &log &optional;

        select_clause_browse_path_link_id       : string &log &optional;
        attribute_id                            : string &log &optional;
        index_range                             : string &log &optional;
        select_clause_status_code_link_id       : string &log &optional;
    };
    type OPCUA_Binary::SimpleAttributeOperand: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        simple_attribute_operand_link_id  : string &log;
        type_id_encoding_mask             : string &log &optional;
        type_id_namespace_idx             : count  &log &optional;
        type_id_numeric                   : count  &log &optional;
        type_id_string                    : string &log &optional;
        type_id_guid                      : string &log &optional;
        type_id_opaque                    : string &log &optional;

        simple_attribute_operand_browse_path_link_id    : string &log &optional;
        attribute_id                                    : string &log &optional;
        index_range                                     : string &log &optional;
    };
    type OPCUA_Binary::SimpleAttributeOperandBrowsePaths: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        simple_attribute_operand_browse_path_link_id    : string &log;
        namespace_index                                 : count  &log &optional;
        name                                            : string &log &optional;
    };
    type OPCUA_Binary::AttributeOperand: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        content_filter_filter_operand_link_id   : string &log;
        node_id_encoding_mask                   : string &log &optional;
        node_id_namespace_idx                   : count  &log &optional;
        node_id_numeric                         : count  &log &optional;
        node_id_string                          : string &log &optional;
        node_id_guid                            : string &log &optional;
        node_id_opaque                          : string &log &optional;
        alias                                   : string &log &optional;
        browse_path_element_link_id             : string &log &optional;
        attribute                               : string &log &optional;
        index_range                             : string &log &optional;
    };
    type OPCUA_Binary::AttributeOperandBrowsePathElement: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        browse_path_element_link_id : string &log;
        type_id_encoding_mask       : string &log &optional;
        type_id_namespace_idx       : count  &log &optional;
        type_id_numeric             : count  &log &optional;
        type_id_string              : string &log &optional;
        type_id_guid                : string &log &optional;
        type_id_opaque              : string &log &optional;
        is_inverse                  : bool   &log &optional;
        include_subtypes            : bool   &log &optional;    
        target_name_namespace_idx   : count  &log &optional;
        target_name                 : string &log &optional;
    };
    type OPCUA_Binary::ElementOperand: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;

        content_filter_filter_operand_link_id   : string &log;
        element_index                           : count  &log &optional;

    };
    type OPCUA_Binary::EventFilterDiagnosticInfo: record {
        ts                                          : time    &log;
        uid                                         : string  &log;
        id                                          : conn_id &log;
        
        event_filter_select_clauses_diag_info_link_id   : string  &log;  # Id back into OCPUA_Binary::EventFilter
        diag_info_link_id                               : string  &log;  # Id into OPCUA_Binary::DiagnosticInfoDetail
    };
    type OPCUA_Binary::ContentFilterElementDiagnosticInfo: record {
        ts                                          : time    &log;
        uid                                         : string  &log;
        id                                          : conn_id &log;
        
        content_filter_diag_info_link_id            : string  &log;  # Id back into OCPUA_Binary::ContentFilter
        diag_info_link_id                           : string  &log;  # Id into OPCUA_Binary::DiagnosticInfoDetail
    };
    type OPCUA_Binary::OperandDiagnosticInfo: record {
        ts                                          : time    &log;
        uid                                         : string  &log;
        id                                          : conn_id &log;
        
        content_filter_elements_operand_diag_info_link_id   : string  &log;  # Id back into OCPUA_Binary::ContentFilterElement
        diag_info_link_id                                   : string  &log;  # Id into OPCUA_Binary::DiagnosticInfoDetail
    };
}