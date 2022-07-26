## opcua_binary-create_subscription_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing the browse service.
##
## Author:   Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printCreateSubscriptionReq(CreateSubscription_Req *msg);
    void printCreateSubscriptionRes(CreateSubscription_Res *msg);
%}

%code{
    void printCreateSubscriptionReq(CreateSubscription_Req *msg){
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header()); 
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printReqHdr(msg->req_hdr());

        printf("%s RequestedPublishingInterval: %f\n", indent(3).c_str(), bytestringToDouble(msg->req_publishing_interval()->duration()));
        printf("%s RequestedLifetimeCount: %d\n", indent(3).c_str(), msg->req_lifetime_count());
        printf("%s RequestedMaxKeepAliveCount: %d\n", indent(3).c_str(), msg->req_max_keep_alive_count());
        printf("%s MaxNotificationsPerPublish: %d\n", indent(3).c_str(), msg->max_notifications_per_publish());
        if (msg->publishing_enabled() == 1){
            printf("%s PublishingEnabled: True\n",indent(3).c_str());
        } else {
            printf("%s PublishingEnabled: False\n", indent(3).c_str());
        }
        printf("%s Priority: %d\n", indent(3).c_str(), msg->priority());
    }
    void printCreateSubscriptionRes(CreateSubscription_Res *msg){
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header()); 
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printResHdr(msg->res_hdr());

        printf("%s SubscriptionId: %d\n", indent(3).c_str(), msg->subscription_id());
        printf("%s RevisedPublishingInterval: %f\n", indent(3).c_str(), bytestringToDouble(msg->revised_publishing_interval()->duration()));
        printf("%s RevisedLifetimeCount: %d\n", indent(3).c_str(), msg->revised_lifetime_count());
        printf("%s RevisedMaxKeepAliveCount: %d\n", indent(3).c_str(), msg->revised_max_keep_alive_count());
    }
%}