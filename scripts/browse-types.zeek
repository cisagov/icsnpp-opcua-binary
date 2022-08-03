## create-browse_view-types.zeek
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
    type OPCUA_Binary::Browse: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;
        opcua_id                 : string  &log;       # Id back into OCPUA_Binary::Info
        
        browse_service_type          : string  &log &optional;
        browse_view_id_encoding_mask : string  &log &optional;
        browse_view_id_namespace_idx : count   &log &optional;
        browse_view_id_numeric       : count   &log &optional;
        browse_view_id_string        : string  &log &optional;
        browse_view_id_guid          : string  &log &optional;
        browse_view_id_opaque        : string  &log &optional;

        browse_view_description_timestamp    : count &log &optional;
        browse_view_description_view_version : count &log &optional;

        req_max_ref_nodes            : count &log &optional;
        browse_description_id        : string &log &optional; # Id into OPCUA::BrowseDescription

        browse_next_release_continuation_point  : bool &log &optional;
        browse_next_id                          : string &log &optional;

        browse_result_id             : string &log &optional; # Id into OPCUA::BrowseResult

        browse_response_diag_info_id : string  &log &optional; # Id into OPCUA_Binary::BrowseDiagnosticInfo log
    };

    type OPCUA_Binary::BrowseDescription: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;
        browse_link_id           : string  &log; # Id back into OCPUA_Binary::Browse

        browse_description_encoding_mask : string   &log &optional;
        browse_description_namespace_idx : count   &log &optional;
        browse_description_numeric       : count   &log &optional;
        browse_description_string        : string  &log &optional;
        browse_description_guid          : string  &log &optional;
        browse_description_opaque        : string  &log &optional;

        browse_direction                 : string &log &optional;

        browse_description_ref_encoding_mask : string   &log &optional;
        browse_description_ref_namespace_idx : count   &log &optional;
        browse_description_ref_numeric       : count   &log &optional;
        browse_description_ref_string        : string  &log &optional;
        browse_description_ref_guid          : string  &log &optional;
        browse_description_ref_opaque        : string  &log &optional;

        browse_description_include_subtypes : bool &log &optional;
        browse_node_class_mask              : string &log &optional;
        browse_result_mask                  : string &log &optional;
    };

    type OPCUA_Binary::BrowseRequestContinuationPoint: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;
        browse_resp_link_id      : string  &log; # Id back into OCPUA_Binary::Browse

        continuation_point       : string &log &optional;
    };

    type OPCUA_Binary::BrowseResult: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;
        browse_resp_link_id      : string  &log; # Id back into OCPUA_Binary::Browse

        browse_result_status_code_id          : string &log &optional; # Id into OPCUA_Binary::StatusCodeDetail log
        browse_result_continuation_point      : string &log &optional;
        browse_reference_id                   : string &log &optional;

    };

    type OPCUA_Binary::BrowseReference: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;
        browse_result_link_id    : string  &log;       # Id back into OCPUA_Binary::BrowseResult

	    browse_response_ref_encoding_mask    : string &log &optional;
        browse_response_ref_namespace_idx    : count  &log &optional;
        browse_response_ref_numeric          : count  &log &optional;
        browse_response_ref_string           : string &log &optional;
        browse_response_ref_guid             : string &log &optional;
        browse_response_ref_opaque           : string &log &optional;   

        browse_response_is_forward           : bool &log &optional;

        browse_response_ref_type_encoding_mask    : string &log &optional;
        browse_response_ref_type_namespace_idx    : count  &log &optional;
        browse_response_ref_type_numeric          : count  &log &optional;
        browse_response_ref_type_string           : string &log &optional;
        browse_response_ref_type_guid             : string &log &optional;
        browse_response_ref_type_opaque           : string &log &optional; 
        browse_response_ref_type_namespace_uri    : string &log &optional;
        browse_response_ref_type_server_idx       : count  &log &optional; 

        browse_response_ref_name_idx        : count &log &optional;
        browse_response_ref_name            : string &log &optional;
        browse_response_display_name_mask   : string &log &optional;
        browse_response_display_name_locale : string &log &optional;
        browse_response_display_name_text   : string &log &optional;
        browse_response_node_class          : string &log &optional;

        browse_response_type_def_encoding_mask    : string &log &optional;
        browse_response_type_def_namespace_idx    : count  &log &optional;
        browse_response_type_def_numeric          : count  &log &optional;
        browse_response_type_def_string           : string &log &optional;
        browse_response_type_def_guid             : string &log &optional;
        browse_response_type_def_opaque           : string &log &optional; 
        browse_response_type_def_namespace_uri    : string &log &optional;
        browse_response_type_def_server_idx       : count  &log &optional;   
    };

    type OPCUA_Binary::BrowseDiagnosticInfo: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;
        diagnostic_info_link_id   : string  &log;  # Id back into OCPUA_Binary::Browse
        diagnostic_info_id        : string  &log;  # Id into OPCUA_Binary::DiagnosticInfoDetail
    };
}