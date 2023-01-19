## read-types.zeek
##
## OPCUA Binary Protocol Analyzer
##
## Zeek script type/record definitions describing the information
## that will be written to the log files.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

module ICSNPP_OPCUA_Binary;
export {
    type OPCUA_Binary::Read: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;
        opcua_link_id            : string  &log; # Link back into OPCUA_Binary::Info:

        # Request
        max_age                  : count  &log &optional;
        timestamps_to_return     : count  &log &optional;
        timestamps_to_return_str : string &log &optional;
        nodes_to_read_link_id    : string &log &optional; # Link into OPCUA_Binary::NodesToRead

        # Response
        read_results_link_id :  string &log &optional; # Link into OPCUA_Binary::ReadResultsLink
        diag_info_link_id    : string  &log &optional; # Link into OPCUA_Binary::ReadDiagnosticInfo log
    };

    type OPCUA_Binary::ReadNodesToRead: record {
        ts                    : time    &log;
        uid                   : string  &log;
        id                    : conn_id &log;
        nodes_to_read_link_id : string  &log; # Link back into OPCUA_Binary::Read

        # node_id : OpcUA_NodeId
        node_id_encoding_mask : string &log &optional;
        node_id_namespace_idx : count  &log &optional;
        node_id_numeric       : count  &log &optional;
        node_id_string        : string &log &optional;
        node_id_guid          : string &log &optional;
        node_id_opaque        : string &log &optional;

        attribute_id     : count  &log;
        attribute_id_str : string &log;
        index_range      : string &log;

        # data_encoding : QualifiedName
        data_encoding_name_idx : count  &log &optional;
        data_encoding_name     : string &log &optional;
    };
    
    type OPCUA_Binary::ReadResults: record {
        ts                   : time    &log;
        uid                  : string  &log;
        id                   : conn_id &log;
        results_link_id      : string  &log; 
        level                : count   &log;

        data_value_encoding_mask : string &log;

        status_code_link_id  : string &log &optional; # Id into OPCUA_Binary::StatusCodeDetail log

        source_timestamp     : time  &log &optional;
        source_pico_sec      : count &log &optional;

        server_timestamp     : time  &log &optional;
        server_pico_sec      : count &log &optional;

        read_results_variant_metadata_link_id  : string &log &optional; # Link into OPCUA_Binary::VariantMetadata log
    };
}
