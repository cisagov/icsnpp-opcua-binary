##! write-types.zeek
##!
##! OPCUA Binary Protocol Analyzer
##!
##! Zeek script type/record definitions describing the information
##! that will be written to the log files.
##!
##! Author:   Jason Rush
##! Contact:  jason.rush@inl.gov
##!
##! Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

module ICSNPP_OPCUA_Binary;
export {
    type OPCUA_Binary::Write: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;

        is_orig                  : bool    &log;
        source_h                 : addr    &log;   # Source IP Address
        source_p                 : port    &log;   # Source Port
        destination_h            : addr    &log;   # Destination IP Address
        destination_p            : port    &log;   # Destination Port

        opcua_link_id            : string  &log; # Link back into OPCUA_Binary::Info

        # Request
        nodes_to_write_link_id   : string &log &optional; # Link into OPCUA_Binary::NodesToWrite

        # Response
        status_code_link_id   :  string &log &optional; # Id into OPCUA_Binary::StatusCodeDetail log
        diag_info_link_id     :  string &log &optional; # Link into OPCUA_Binary::DiagnosticInfoDetail log
    };

    type OPCUA_Binary::WriteNodesToWrite: record {
        ts                   : time    &log;
        uid                  : string  &log;
        id                   : conn_id &log;

        is_orig              : bool    &log;
        source_h             : addr    &log;   # Source IP Address
        source_p             : port    &log;   # Source Port
        destination_h        : addr    &log;   # Destination IP Address
        destination_p        : port    &log;   # Destination Port

        level                : count   &log;

        data_value_encoding_mask : string &log;

        status_code_link_id  : string &log &optional; # Id into OPCUA_Binary::StatusCodeDetail log

        source_timestamp     : time  &log &optional;
        server_timestamp     : time  &log &optional;

        source_pico_sec      : count &log &optional;
        server_pico_sec      : count &log &optional;

        read_results_variant_metadata_link_id  : string &log &optional; # Link into OPCUA_Binary::VariantMetadata log
    };
}
