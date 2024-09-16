##! statuscode-diagnostic-types.zeek
##!
##! OPCUA Binary Protocol Analyzer
##!
##! Zeek script type/record definitions describing the information
##! that will be written to the log files.
##!
##! Author:   Kent Kvarfordt
##! Contact:  kent.kvarfordt@inl.gov
##!
##! Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

module ICSNPP_OPCUA_Binary;
export {
    type OPCUA_Binary::StatusCodeDetail: record {
        ts                  : time    &log;
        uid                 : string  &log;
        id                  : conn_id &log;

        is_orig             : bool    &log;
        source_h            : addr    &log; # Source IP Address
        source_p            : port    &log; # Source Port
        destination_h       : addr    &log; # Destination IP Address
        destination_p       : port    &log; # Destination Port

        status_code_link_id : string  &log;
        source              : count   &log;
        source_str          : string  &log;
        source_level        : count   &log;
        status_code         : string  &log;
        severity            : count   &log;
        severity_str        : string  &log;
        sub_code            : count   &log;
        sub_code_str        : string  &log;
        structure_changed   : bool    &log;
        semantics_changed   : bool    &log;
        info_type           : count   &log;
        info_type_str       : string  &log;
        limit_bits          : count   &log;
        limit_bits_str      : string  &log;
        overflow            : bool    &log;
        historian_bits      : count   &log;
        historian_bits_str  : string  &log;
        historianPartial    : bool    &log;
        historianExtraData  : bool    &log;
        historianMultiValue : bool    &log;
    };

    type OPCUA_Binary::DiagnosticInfoDetail: record {
        ts                  : time    &log;
        uid                 : string  &log;
        id                  : conn_id &log;

        is_orig             : bool    &log;
        source_h            : addr    &log; # Source IP Address
        source_p            : port    &log; # Source Port
        destination_h       : addr    &log; # Destination IP Address
        destination_p       : port    &log; # Destination Port

        diag_info_link_id   : string  &log;
        root_object_id      : string  &log; # This connects inner objects with the root object
        source              : count   &log;
        source_str          : string  &log;
        inner_diag_level    : count   &log;
        has_symbolic_id     : bool    &log;
        symbolic_id         : count   &log &optional;
        symbolic_id_str     : string  &log &optional;
        has_namespace_uri   : bool    &log;
        namespace_uri       : count   &log &optional;
        namespace_uri_str   : string  &log &optional;
        has_locale          : bool    &log;
        locale              : count   &log &optional;
        locale_str          : string  &log &optional;
        has_locale_txt      : bool    &log;
        locale_txt          : count   &log &optional;
        locale_txt_str      : string  &log &optional;
        has_addl_info       : bool    &log;
        addl_info           : string  &log &optional;
        has_inner_stat_code : bool    &log;
        inner_stat_code     : string  &log &optional;
        has_inner_diag_info : bool    &log;
    };
}
