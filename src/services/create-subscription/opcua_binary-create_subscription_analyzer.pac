## opcua_binary-create_subscription_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the create subscription service.
##
## Author:  Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {
    #
    # CreateSubscription Request
    #
    function deliver_Svc_CreateSubscriptionReq(msg: Create_Subscription_Req): bool
        %{
        // Debug printf("deliver_Svc_CreateSubscriptionReq - begin\n");
        // Debug printCreateSubscriptionReq(msg);
        // Debug printf("deliver_Svc_CreateSubscriptionReq - end\n");

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());
        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr create_subscription_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateSubscription);

        // Source & Destination
        Msg_Header *msg_header = msg->service()->msg_body()->header();
        const zeek::RecordValPtr conn_val = connection()->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        create_subscription_req = assignSourceDestination(msg_header->is_orig(), create_subscription_req, id_val);

        // OpcUA_id
        create_subscription_req->Assign(CREATE_SUB_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        create_subscription_req->Assign(CREATE_SUB_REQ_PUB_INT_IDX, zeek::val_mgr->Count(bytestringToDouble(msg->req_publishing_interval()->duration())));
        create_subscription_req->Assign(CREATE_SUB_REQ_LIFETIME_COUNT_IDX, zeek::val_mgr->Count(msg->req_lifetime_count()));
        create_subscription_req->Assign(CREATE_SUB_REQ_MAX_KEEP_ALIVE_IDX, zeek::val_mgr->Count(msg->req_max_keep_alive_count()));
        create_subscription_req->Assign(CREATE_SUB_MAX_NOTIFICATIONS_PER_PUBLISH_IDX, zeek::val_mgr->Count(msg->max_notifications_per_publish()));
        create_subscription_req->Assign(CREATE_SUB_PUBLISHING_ENABLED_IDX, zeek::val_mgr->Bool(msg->publishing_enabled()));
        create_subscription_req->Assign(CREATE_SUB_PRIORITY_IDX, zeek::val_mgr->Count(msg->priority()));

        zeek::BifEvent::enqueue_opcua_binary_create_subscription_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   create_subscription_req);

        return true;

    %}

    function deliver_Svc_CreateSubscriptionRes(msg: Create_Subscription_Res): bool
        %{
        // Debug printf("deliver_Svc_CreateSubscriptionRes - begin\n");
        // Debug printCreateSubscriptionRes(msg);
        // Debug printf("deliver_Svc_CreateSubscriptionRes - end\n");

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr(), msg->service()->msg_body()->header()->is_orig());
        info = assignService(info, msg->service());
        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr create_subscription_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateSubscription);

        // Source & Destination
        Msg_Header *msg_header = msg->service()->msg_body()->header();
        const zeek::RecordValPtr conn_val = connection()->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        create_subscription_res = assignSourceDestination(msg_header->is_orig(), create_subscription_res, id_val);

        // OpcUA_id
        create_subscription_res->Assign(CREATE_SUB_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        create_subscription_res->Assign(CREATE_SUB_SUB_ID_IDX, zeek::val_mgr->Count(msg->subscription_id()));
        create_subscription_res->Assign(CREATE_SUB_REV_PUB_INT_IDX, zeek::val_mgr->Count(bytestringToDouble(msg->revised_publishing_interval()->duration())));
        create_subscription_res->Assign(CREATE_SUB_REV_LIFETIME_COUNT_IDX, zeek::val_mgr->Count(msg->revised_lifetime_count()));
        create_subscription_res->Assign(CREATE_SUB_REV_MAX_KEEP_ALIVE_IDX, zeek::val_mgr->Count(msg->revised_max_keep_alive_count()));

        zeek::BifEvent::enqueue_opcua_binary_create_subscription_event(connection()->bro_analyzer(),
                                                                       connection()->bro_analyzer()->Conn(),
                                                                       create_subscription_res);

        return true;

    %}
} 