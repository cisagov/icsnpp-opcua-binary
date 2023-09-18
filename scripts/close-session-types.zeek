## close-session-types.zeek
##
## OPCUA Binary Protocol Analyzer
##
## Zeek script type/record definitions describing the information
## that will be written to the log files.
##
## Author:   Christian Weelborg
## Contact:  Christian.Weelborg@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

module ICSNPP_OPCUA_Binary;
export {
    type OPCUA_Binary::CloseSession: record {
        ts                  : time &log;
        uid                 : string &log;
        id                  : conn_id &log;

        is_orig             : bool &log;
        source_h            : addr &log;   # Source IP Address
        source_p            : port &log;   # Source Port
        destination_h       : addr &log;   # Destination IP Address
        destination_p       : port &log;   # Destination Port

        opcua_link_id       : string &log; # Link back into OPCUA_Binary::Info
        
        # CloseSession Request
        del_subscriptions   : bool &log &optional;

        # CloseSession Response
        # Nothing besides header
    };
}