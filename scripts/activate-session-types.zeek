##! activate-session-types.zeek
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
    type OPCUA_Binary::ActivateSession: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;

        is_orig                  : bool      &log;
        source_h                 : addr      &log;   # Source IP Address
        source_p                 : port      &log;   # Source Port
        destination_h            : addr      &log;   # Destination IP Address
        destination_p            : port      &log;   # Destination Port

        opcua_link_id            : string  &log;     # Id back into OCPUA_Binary::Info

        #
        # Request
        #

        # Client Signature Data
        client_algorithm : string &log &optional;
        client_signature : string &log &optional;

        # Client Software Certificate
        client_software_cert_link_id : string  &log &optional;  # Id into OCPUA_Binary::ActivateSessionClientSoftwareCert

        # Locale Id
        opcua_locale_link_id : string &log &optional;   # Id into OPCUA_Binary::ActivateSessionLocaleId

        # Extension Object
        ext_obj_type_id_encoding_mask : string   &log &optional;
        ext_obj_type_id_namespace_idx : count   &log &optional;
        ext_obj_type_id_numeric       : count   &log &optional;
        ext_obj_type_id_string        : string  &log &optional;
        ext_obj_type_id_guid          : string  &log &optional;
        ext_obj_type_id_opaque        : string  &log &optional;

        ext_obj_type_id_str : string &log &optional; # String representation of type id (AnonymousIdentityToken, UserNameIdentityToken, X509IdentityToken, etc.)
        ext_obj_encoding    : string &log &optional;

        # Common among all IdentityTokens; Only field for AnonymousIdentityToken
        ext_obj_policy_id : string &log &optional;

        # UsernameIdentityToken
        ext_obj_user_name             : string &log &optional;
        ext_obj_password              : string &log &optional;
        ext_obj_encryption_algorithom : string &log &optional;

        # Common in X509IdentityToken and IssuedIdentityToken
        ext_obj_certificate_data : string &log &optional;

        # IssuedIdentityToken
        ext_obj_token_data : string &log &optional;

        # User Token Signature Data
        user_token_algorithm : string &log &optional;
        user_token_signature : string &log &optional;

        #
        # Response
        #
        server_nonce                       : string  &log &optional;
        status_code_link_id                : string  &log &optional; # Id into OPCUA_Binary::StatusCodeDetail log
        activate_session_diag_info_link_id : string  &log &optional; # Id into OPCUA_Binary::DiagnosticInfoDetail log
        
    };

    type OPCUA_Binary::ActivateSessionClientSoftwareCert: record {
        ts                           : time    &log;
        uid                          : string  &log;
        id                           : conn_id &log;

        is_orig                  : bool      &log;
        source_h                 : addr      &log;   # Source IP Address
        source_p                 : port      &log;   # Source Port
        destination_h            : addr      &log;   # Destination IP Address
        destination_p            : port      &log;   # Destination Port

        client_software_cert_link_id : string  &log;  # Id back into OCPUA_Binary::ActivateSession
        cert_data                    : string  &log;
        cert_signature               : string  &log;
    };

    type OPCUA_Binary::ActivateSessionLocaleId: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;

        is_orig                  : bool      &log;
        source_h                 : addr      &log;   # Source IP Address
        source_p                 : port      &log;   # Source Port
        destination_h            : addr      &log;   # Destination IP Address
        destination_p            : port      &log;   # Destination Port

        opcua_locale_link_id      : string  &log;  # Id back into OCPUA_Binary::ActivateSession
        local_id                  : string  &log;
    };

}
