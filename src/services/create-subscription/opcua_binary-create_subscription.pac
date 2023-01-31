## opcua_binary-create_subscription.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the create subscription service.
##
## Author:   Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.


#
# UA Specification Part 4 - Services 1.04.pdf - Create Subscription
# 5.13.2.2 - Table 88 - CreateSubscription Service Parameters
#

type Create_Subscription_Req(service: Service) = record {
    req_hdr                         : Request_Header;
    req_publishing_interval         : OpcUA_Duration;
    req_lifetime_count              : uint32;
    req_max_keep_alive_count        : uint32;
    max_notifications_per_publish   : uint32;
    publishing_enabled              : OpcUA_Boolean;
    priority                        : uint8;
} &let {
    deliver: bool = $context.flow.deliver_Svc_CreateSubscriptionReq(this);
} &byteorder=littleendian;

type Create_Subscription_Res(service: Service) = record {
    res_hdr                             : Response_Header;
    subscription_id                     : uint32;
    revised_publishing_interval         : OpcUA_Duration;
    revised_lifetime_count              : uint32;
    revised_max_keep_alive_count        : uint32;
} &let {
    deliver: bool = $context.flow.deliver_Svc_CreateSubscriptionRes(this);
} &byteorder=littleendian; 