## secure-channel-types.zeek
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

    type OPCUA_Binary::OpenSecureChannel: record {
        ts                            : time    &log;
        uid                           : string  &log;
        id                            : conn_id &log;

        is_orig                       : bool    &log;
        source_h                      : addr    &log; # Source IP Address
        source_p                      : port    &log; # Source Port
        destination_h                 : addr    &log; # Destination IP Address
        destination_p                 : port    &log; # Destination Port

        opcua_link_id                 : string  &log; # Link back into OPCUA_Binary::Info

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
}
