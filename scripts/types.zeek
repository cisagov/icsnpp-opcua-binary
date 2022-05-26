## types.zeek
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
    type OPCUA_Binary::Info: record {
        ts                            : time    &log;
        uid                           : string  &log;
        id                            : conn_id &log;

        # Msg Header
        opcua_id                      : string  &log;
        msg_type                      : string  &log;
        is_final                      : string  &log;
        msg_size                      : count   &log;

        # Msg_ERR
        error                         : count   &log &optional;
        reason                        : string  &log &optional;

        # Msg_HEL and Msg_ACK
        version                       : count   &log &optional;
        rcv_buf_size                  : count   &log &optional;
        snd_buf_size                  : count   &log &optional;
        max_msg_size                  : count   &log &optional;
        max_chunk_cnt                 : count   &log &optional;
        endpoint_url                  : string  &log &optional;

        # Msg Body
        sec_channel_id                : count   &log &optional;
        sec_policy_uri_len            : int     &log &optional;
        sec_policy_uri                : string  &log &optional;
        snd_cert_len                  : int     &log &optional;
        snd_cert                      : string  &log &optional;
        rcv_cert_len                  : int     &log &optional;
        rcv_cert                      : string  &log &optional;
        seq_number                    : count   &log &optional;
        request_id                    : count   &log &optional;
        encoding_mask                 : count   &log &optional;
        namespace_idx                 : count   &log &optional;
        identifier                    : count   &log &optional;
        identifier_str                : string  &log &optional;

        # Request Header
        req_hdr_node_id_type          : string  &log &optional;
        req_hdr_node_id_namespace_idx : count   &log &optional;
        req_hdr_node_id_numeric       : count   &log &optional;
        req_hdr_node_id_string        : string  &log &optional;
        req_hdr_node_id_guid          : string  &log &optional;
        req_hdr_node_id_opaque        : string  &log &optional;
        req_hdr_timestamp             : time    &log &optional;
        req_hdr_request_handle        : count   &log &optional;
        req_hdr_return_diag           : count   &log &optional;
        req_hdr_audit_entry_id        : string  &log &optional;
        req_hdr_timeout_hint          : time    &log &optional;
        req_hdr_add_hdr_type_id       : count   &log &optional;
        req_hdr_add_hdr_enc_mask      : count   &log &optional;

        # Response Header
        res_hdr_timestamp             : time    &log &optional;
        res_hdr_request_handle        : count   &log &optional;
        res_hdr_service_result        : count   &log &optional;
        res_hdr_service_diag_encoding : count   &log &optional;
        res_hdr_add_hdr_type_id       : count   &log &optional;
        res_hdr_add_hdr_enc_mask      : count   &log &optional;

    };
}
