## opcua_binary-create_monitored_items_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the create monitored items service.
##
## Author:  Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {
    #
    # CreateMonitoredItemsRequest
    #
    function deliver_Svc_CreateMonitoredItemsReq(msg: CreateMonitoredItems_Req): bool
        %{
            // Debug printf("deliver_Svc_BrowseReq - begin\n");
            // Debug 
            printCreateMonitoredItemsReq(msg);
            // Debug printf("deliver_Svc_BrowseReq - end\n");

            zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

            info = assignMsgHeader(info, msg->service()->msg_body()->header());
            info = assignMsgType(info, msg->service()->msg_body()->header());
            info = assignReqHdr(info, msg->req_hdr());
            info = assignService(info, msg->service());
            zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    info);
            zeek::RecordValPtr create_monitored_items_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateMonitoredItems);
            create_monitored_items_req->Assign(BROWSE_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_ID_IDX));

            create_monitored_items_req->Assign(CREATE_MONITORED_ITEMS_SUBSCRIPTION_ID_IDX, zeek::val_mgr->Count(msg->subscription_id()));
            create_monitored_items_req->Assign(CREATE_MONITORED_ITEMS_TIMESTAMPS_TO_RETURN_IDX, zeek::make_intrusive<zeek::StringVal>(TIMESTAMPS_TO_RETURN_MAP.find(msg->timestamps_to_return())->second));

            int32_t num_items_to_create = msg->num_items_to_create();
            
            if (num_items_to_create > 0){
                std::string monitored_items_id = generateId();
                create_monitored_items_req->Assign(CREATE_MONITORED_ITEMS_MONITORED_ITEM_ID_IDX, zeek::make_intrusive<zeek::StringVal>(monitored_items_id));
            }

            zeek::BifEvent::enqueue_opcua_binary_create_monitored_items_event(connection()->bro_analyzer(),
                                                                              connection()->bro_analyzer()->Conn(),
                                                                              create_monitored_items_req);

            return true;
        %}
    #
    # CreateMonitoredItemsResponse
    #
    function deliver_Svc_CreateMonitoredItemsRes(msg: CreateMonitoredItems_Res): bool
        %{
            // Debug printf("deliver_Svc_BrowseRes - begin\n");
            // Debug printBrowseRes(msg);
            // Debug printf("deliver_Svc_BrowseRes - end\n");
            zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

            info = assignMsgHeader(info, msg->service()->msg_body()->header());
            info = assignMsgType(info, msg->service()->msg_body()->header());
            info = assignResHdr(connection(), info, msg->res_hdr());
            info = assignService(info, msg->service());

            zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                       connection()->bro_analyzer()->Conn(),
                                                       info);
            return true;       
        %}
}