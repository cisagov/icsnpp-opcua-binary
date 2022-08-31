## get-endpoints-types.zeek
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
    type OPCUA_Binary::GetEndpoints: record {
        ts                           : time    &log;
        uid                          : string  &log;
        id                           : conn_id &log;
        opcua_link_id                : string  &log; # Link back into OPCUA_Binary::Info:
        endpoint_url                 : string  &log;
        locale_link_id               : string  &log &optional; # Link into OPCUA_Binary::GetEndpointsLocaleId
        profile_uri_link_id          : string  &log &optional; # Link into OPCUA_Binary::GetEndpointsProfileUri
        endpoint_description_link_id : string &log &optional;  # Link into OPCUA_Binary::GetEndpointsDescription

    };

    type OPCUA_Binary::GetEndpointsDescription: record {
        ts                           : time    &log;
        uid                          : string  &log;
        id                           : conn_id &log;
        endpoint_description_link_id : string  &log; # Link back into OPCUA_Binary::GetEndpoints
        endpoint_uri                 : string  &log &optional;
        
        # OpcUA_ApplicationDescription
        application_uri           : string  &log &optional;
        product_uri               : string  &log &optional;
        encoding_mask             : count   &log &optional;
        locale                    : string  &log &optional;
        text                      : string  &log &optional;
        application_type          : count   &log &optional;
        gateway_server_uri        : string  &log &optional;
        discovery_profile_uri     : string  &log &optional;

        # OpcUA_ApplicationDescription array of OpcUA_String
        discovery_profile_link_id : string  &log &optional; # Link into OPCUA_Binary::GetEndpointsDiscovery

        # OpcUA_ApplicationInstanceCertificate
        cert_size                 : count   &log &optional;
        server_cert               : string  &log &optional;

        message_security_mode     : count   &log &optional;
        security_policy_uri       : string  &log &optional;

        # Array of OpcUA_UserTokenPolicy
        user_token_link_id        : string  &log &optional; # Link into OPCUA_Binary::GetEndpointsUserToken

        transport_profile_uri     : string  &log &optional;
        security_level            : count   &log &optional;
    };

    type OPCUA_Binary::GetEndpointsDiscovery: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;
        discovery_profile_link_id : string  &log; # Link back into OPCUA_Binary::GetEndpointsDescription
        discovery_profile_url     : string  &log;
    };

    type OPCUA_Binary::GetEndpointsUserToken: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;
        user_token_link_id        : string  &log; # Link back into OPCUA_Binary::GetEndpointsDescription
        user_token_policy_id      : string  &log;
        user_token_type           : count   &log;
        user_token_issued_type    : string  &log &optional;
        user_token_endpoint_url   : string  &log &optional;
        user_token_sec_policy_uri : string  &log &optional;
    };

    type OPCUA_Binary::GetEndpointsLocaleId: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;
        locale_link_id            : string  &log; # Link back into OPCUA_Binary::GetEndpoints
        locale_id                 : string  &log;
    };

    type OPCUA_Binary::GetEndpointsProfileUri: record {
        ts                        : time    &log;
        uid                       : string  &log;
        id                        : conn_id &log;
        profile_uri_link_id       : string  &log; # Link back into OPCUA_Binary::GetEndpoints
        profile_uri               : string  &log;
    };

}
