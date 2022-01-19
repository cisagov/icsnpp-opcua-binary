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

    type OPCUA_Binary::OpenSecureChannel: record {
        ts                            : time    &log;
        uid                           : string  &log;
        id                            : conn_id &log;
        opcua_id                      : string  &log;

        # OpenSecureChannel Request
        client_proto_ver              : count   &log &optional;
        sec_token_request_type        : count   &log &optional;
        message_security_mode         : count   &log &optional;
        client_nonce                  : string  &log &optional;
        req_lifetime                  : count   &log &optional;

        # OpenSecureChannel Response
        server_proto_ver              : count   &log &optional;
        sec_token_sec_channel_id      : count   &log &optional;
        sec_token_id                  : count   &log &optional;
        sec_token_created_at          : time    &log &optional;
        sec_token_revised_time        : count   &log &optional;
        server_nonce                  : string  &log &optional;
    };

    type OPCUA_Binary::StatusCodeDetail: record {
        ts                  : time    &log;
        uid                 : string  &log;
        id                  : conn_id &log;
        opcua_id            : string  &log;
        source              : count   &log;
        source_str          : string  &log;
        status_code         : string   &log;
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
        opcua_id            : string  &log;
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

    type OPCUA_Binary::GetEndpoints: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;
        opcua_id                  : string  &log;
        endpoint_url              : string  &log;
        locale_id                 : string  &log &optional;
        profile_uri               : string  &log &optional;
        application_uri           : string  &log &optional;
        product_uri               : string  &log &optional;
        encoding_mask             : count   &log &optional;
        locale                    : string  &log &optional;
        text                      : string  &log &optional;
        application_type          : count   &log &optional;
        gateway_server_uri        : string  &log &optional;
        discovery_profile_id      : string  &log &optional;
        cert_size                 : count   &log &optional;
        server_cert               : string  &log &optional;
        message_security_mode     : count   &log &optional;
        security_policy_uri       : string  &log &optional;
        user_token_id             : string  &log &optional;
        transport_profile_uri     : string  &log &optional;
        security_level            : count   &log &optional;
    };

    type OPCUA_Binary::GetEndpointsDiscovery: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;
        discovery_profile_id      : string  &log;
        discovery_profile_uri     : string  &log;
        discovery_profile_url     : string  &log;
    };

    type OPCUA_Binary::GetEndpointsUserToken: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;
        user_token_id             : string  &log;
        user_token_policy_id      : string  &log;
        user_token_type           : count   &log;
        user_token_issued_type    : string  &log &optional;
        user_token_endpoint_url   : string  &log &optional;
        user_token_sec_policy_uri : string  &log &optional;
    };
}
