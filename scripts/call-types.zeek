##! call-types.zeek
##!
##! OPCUA Binary Protocol Analyzer
##!
##! Zeek script type/record definitions describing the information
##! that will be written to the log files.
##!
##! Author:   John B Joseph
##!

module ICSNPP_OPCUA_Binary;
export {
    type OPCUA_Binary::Call: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;

        is_orig                  : bool    &log;
        source_h                 : addr    &log;   ##< Source IP Address
        source_p                 : port    &log;   ##< Source Port
        destination_h            : addr    &log;   ##< Destination IP Address
        destination_p            : port    &log;   ##< Destination Port

        opcua_link_id            : string  &log; ##< Link back into OPCUA_Binary::Info

        #
        # Request: one record per CallMethodRequest
        #

        # object_id : OpcUA_NodeId - the Object or ObjectType on which the method is called
        object_id_encoding_mask : string &log &optional;
        object_id_namespace_idx : count  &log &optional;
        object_id_numeric       : count  &log &optional;
        object_id_string        : string &log &optional;
        object_id_guid          : string &log &optional;
        object_id_opaque        : string &log &optional;

        # method_id : OpcUA_NodeId - the Method to call
        method_id_encoding_mask : string &log &optional;
        method_id_namespace_idx : count  &log &optional;
        method_id_numeric       : count  &log &optional;
        method_id_string        : string &log &optional;
        method_id_guid          : string &log &optional;
        method_id_opaque        : string &log &optional;

        input_arguments_variant_metadata_link_id  : string &log &optional; ##< Link into OPCUA_Binary::VariantMetadata log

        #
        # Response: one record per CallMethodResult
        #
        status_code_link_id                       : string &log &optional; ##< Method status code link Id into OPCUA_Binary::StatusCodeDetail log
        input_argument_results_link_id            : string &log &optional; ##< Input argument status codes link Id into OPCUA_Binary::StatusCodeDetail log
        input_argument_diag_info_link_id          : string &log &optional; ##< Input argument diagnostics link Id into OPCUA_Binary::DiagnosticInfoDetail log
        output_arguments_variant_metadata_link_id : string &log &optional; ##< Link into OPCUA_Binary::VariantMetadata log
        diag_info_link_id                         : string &log &optional; ##< Link into OPCUA_Binary::DiagnosticInfoDetail log
    };
}
