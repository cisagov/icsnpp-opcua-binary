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
