## create-monitored-items-types.zeek
##
## OPCUA Binary Protocol Analyzer
##
## Zeek script type/record definitions describing the information
## that will be written to the log files.
##
## Author:   Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

module ICSNPP_OPCUA_Binary;

export {
    type OPCUA_Binary::CreateMonitoredItems: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;
        opcua_id                 : string  &log;       # Id back into OCPUA_Binary::Info

        subscription_id             : count &log &optional;
        timestamps_to_return        : string &log &optional;
        create_monitored_item_create_id    : string &log &optional; #Id into OPCUA_Binary:MonitoredItemCreate
    };
}