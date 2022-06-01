## create-session-types.zeek
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
    type OPCUA_Binary::CreateSession: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;
        opcua_id                 : string  &log;       # Id back into OCPUA_Binary::Info

        #
        # Request
        #
        application_uri          : string  &log &optional;
        product_uri              : string  &log &optional;

        # Application Name
        encoding_mask            : count   &log &optional;
        locale                   : string  &log &optional;
        text                     : string  &log &optional;

        application_type         : count   &log &optional;
        gateway_server_uri       : string  &log &optional;
        discovery_profile_uri    : string  &log &optional;

        discovery_profile_id     : string  &log &optional; # Id into OCPUA_Binary::CreateSessionDiscovery

        server_uri               : string  &log &optional;
        endpoint_url             : string  &log &optional;
        session_name             : string  &log &optional;
        client_nonce             : string  &log &optional;

        # Client Certificate
        client_cert_size         : count   &log &optional;
        client_cert              : string  &log &optional;

        req_session_timeout      : time &log &optional;
        max_res_msg_size         : count &log &optional;

        #
        # Response
        #
        
        # Session Id
        session_id_encoding_mask : string   &log &optional;
        session_id_namespace_idx : count   &log &optional;
        session_id_numeric       : count   &log &optional;
        session_id_string        : string  &log &optional;
        session_id_guid          : string  &log &optional;
        session_id_opaque        : string  &log &optional;

        # Auth Token
        auth_token_encoding_mask : string   &log &optional;
        auth_token_namespace_idx : count   &log &optional;
        auth_token_numeric       : count   &log &optional;
        auth_token_string        : string  &log &optional;
        auth_token_guid          : string  &log &optional;
        auth_token_opaque        : string  &log &optional;

        revised_session_timeout  : time &log &optional;
        server_nonce             : string  &log &optional;

        # Server Certificate
        server_cert_size         : count   &log &optional;
        server_cert              : string  &log &optional;

        endpoint_id              : string &log &optional;

        #
        # From Table 15 - CreateSession Service Parameters: Response
        #
        # Description: serverSoftwareCertificates:
        #
        # This parameter is deprecated and the array shall be empty.  Note: Based on sample
        # packet capture data, the server_software_cert_size is present, but always set to -1.
        # For this reason, we parse it, but do not log it.
        #
        # server_software_cert_size : int32;
        # server_software_cert      : SignedSoftwareCertificate

        # Server Signature Data
        algorithm                : string &log &optional;
        signature                : string &log &optional;

        # Max Request Message Size
        max_req_msg_size         : count &log &optional;
    };

    type OPCUA_Binary::CreateSessionDiscovery: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;
        discovery_profile_id      : string  &log;  # Id back into OCPUA_Binary::CreateSession
        discovery_profile_uri     : string  &log;
        discovery_profile_url     : string  &log;
    };

    type OPCUA_Binary::CreateSessionEndpoints: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log; 
        endpoint_id               : string  &log; # Id back into OPCUA_Binary::CreateSession
        endpoint_url              : string  &log;
        application_uri           : string  &log &optional;
        product_uri               : string  &log &optional;
        encoding_mask             : count   &log &optional;
        locale                    : string  &log &optional;
        text                      : string  &log &optional;
        application_type          : count   &log &optional;
        gateway_server_uri        : string  &log &optional;
        discovery_profile_uri     : string  &log &optional;
        discovery_profile_id      : string  &log &optional;
        cert_size                 : count   &log &optional;
        server_cert               : string  &log &optional;
        message_security_mode     : count   &log &optional;
        security_policy_uri       : string  &log &optional;
        user_token_id             : string  &log &optional; # Id into OPCUA_Binary::CreateSessionUserToken
        transport_profile_uri     : string  &log &optional;
        security_level            : count   &log &optional;
    };

    type OPCUA_Binary::CreateSessionUserToken: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;
        user_token_id             : string  &log; # Id back into OPCUA_Binary::CreateSessionEndpoints
        user_token_policy_id      : string  &log;
        user_token_type           : count   &log;
        user_token_issued_type    : string  &log &optional;
        user_token_endpoint_url   : string  &log &optional;
        user_token_sec_policy_uri : string  &log &optional;
    };
}
