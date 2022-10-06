## create-subscription-types.zeek
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
    type OPCUA_Binary::CreateSubscription: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;
        opcua_link_id            : string  &log;       # Id back into OCPUA_Binary::Info

        requested_publishing_interval   : double &log &optional;
        requested_lifetime_count        : count &log &optional;
        requested_max_keep_alive_count  : count &log &optional;
        max_notifications_per_publish   : count &log &optional;
        publishing_enabled              : bool  &log &optional;
        priority                        : count &log &optional;

        subscription_id                 : count  &log &optional;
        revised_publishing_interval     : double &log &optional;
        revised_lifetime_count          : count  &log &optional;
        revised_max_keep_alive_count    : count  &log &optional;
    };
}