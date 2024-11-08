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

        #
        # Request
        #

        #
        # See opcua_binary-read_analyzer.pac: deliver_Svc_ReadReq for an example how to handle
        # flattenOpcUA_NodeId, attrubutes and index_range
        #
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

        #
        # See opcua_binary-read_analyzer.pac: deliver_Svc_ReadRes for an example how to handle
        # flattenOpcUA_DataValue
        #
        data_value_encoding_mask : string &log;

        req_status_code_link_id  : string &log &optional; # Request status code link Id into OPCUA_Binary::StatusCodeDetail log

        source_timestamp     : time  &log &optional;
        source_pico_sec      : count &log &optional;

        server_timestamp     : time  &log &optional;
        server_pico_sec      : count &log &optional;


        write_results_variant_metadata_link_id  : string &log &optional; # Link into OPCUA_Binary::VariantMetadata log

        #
        # Response
        #

        #
        # See opcua_binary-activate_session_analyzer.pac: deliver_Svc_ActivateSessionRes for an example of how to handle
        # an array of StatusCode(s) and an array of DiagnosticInfo(s)
        # 
        # See statuscode-diagnostic-source-consts.h for the *Key(s) to use with generateDisgInfoEvent and generateStatusCodeEvent
        #
        res_status_code_link_id   :  string &log &optional; # Response status code link Id into OPCUA_Binary::StatusCodeDetail log
        diag_info_link_id     :  string &log &optional; # Link into OPCUA_Binary::DiagnosticInfoDetail log

    };
}
