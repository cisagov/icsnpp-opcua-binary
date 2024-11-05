## opcua_binary-services.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for identifying the service being invoked and mapping to the 
## appropriate record.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022-2024 Battelle Energy Alliance, LLC.  All rights reserved.

type Service(msg_body: Msg_Body) = record {
    namespace_idx : uint8;
    identifier    : uint16;
    body          : case(identifier) of {
        OpenSecureChannelRequest     -> opn_sec_chnl_req     : Opn_Sec_Chnl_Req(this);
        OpenSecureChannelResponse    -> opn_sec_chnl_res     : Opn_Sec_Chnl_Res(this);

        CloseSecureChannelRequest    -> clo_sec_chnl_req     : Clo_Sec_Chnl_Req(this);
        CloseSecureChannelResponse   -> clo_sec_chnl_res     : Clo_Sec_Chnl_Res(this);

        GetEndpointsRequest          -> get_endpoints_req    : Get_Endpoints_Req(this);
        GetEndpointsResponse         -> get_endpoints_res    : Get_Endpoints_Res(this);

        CreateSessionRequest         -> create_session_req   : Create_Session_Req(this);
        CreateSessionResponse        -> create_session_res   : Create_Session_Res(this);

        ActivateSessionRequest       -> activate_session_req : Activate_Session_Req(this);
        ActivateSessionResponse      -> activate_session_res : Activate_Session_Res(this);

        FindServersRequest           -> find_server_req      : Stubbed_Out_Req(this);
        FindServersResponse          -> find_server_res      : Stubbed_Out_Res(this);

        FindServersOnNetworkRequest  -> find_server_on_network_req : Stubbed_Out_Req(this);
        FindServersOnNetworkResponse -> find_server_on_network_res : Stubbed_Out_Res(this);

        RegisterServerRequest  -> register_server_req : Stubbed_Out_Req(this);
        RegisterServerResponse -> register_server_res : Stubbed_Out_Res(this);

        RegisterServer2Request  -> register_server_2_req : Stubbed_Out_Req(this);
        RegisterServer2Response -> register_server_2_res : Stubbed_Out_Res(this);

        CloseSessionRequest  -> close_session_req : Close_Session_Req(this);
        CloseSessionResponse -> close_session_res : Close_Session_Res(this);

        CancelRequest  -> cancel_req : Stubbed_Out_Req(this);
        CancelResponse -> cancel_res : Stubbed_Out_Res(this);

        AddNodesRequest  -> add_nodes_req : Stubbed_Out_Req(this);
        AddNodesResponse -> add_nodes_res : Stubbed_Out_Res(this);

        AddReferencesRequest  -> add_reference_req : Stubbed_Out_Req(this);
        AddReferencesResponse -> add_reference_res : Stubbed_Out_Res(this);

        DeleteNodesRequest  -> delete_nodes_req : Stubbed_Out_Req(this);
        DeleteNodesResponse -> delete_nodes_res : Stubbed_Out_Res(this);

        DeleteReferencesRequest  -> delete_reference_req : Stubbed_Out_Req(this);
        DeleteReferencesResponse -> delete_reference_res : Stubbed_Out_Res(this);
        
        BrowseRequest  -> browse_req : Browse_Req(this);
        BrowseResponse -> browse_res : Browse_Res(this);

        BrowseNextRequest  -> browse_next_req : Browse_Next_Req(this);
        BrowseNextResponse -> browse_next_res : Browse_Res(this);

        TranslateBrowsePathsToNodeIdsRequest  -> translate_browse_paths_to_node_ids_req : Stubbed_Out_Req(this);
        TranslateBrowsePathsToNodeIdsResponse -> translate_browse_paths_to_node_ids_res : Stubbed_Out_Res(this);

        RegisterNodesRequest  -> register_node_req : Stubbed_Out_Req(this);
        RegisterNodesResponse -> register_node_res : Stubbed_Out_Res(this);

        UnregisterNodesRequest  -> unregister_node_req : Stubbed_Out_Req(this);
        UnregisterNodesResponse -> unregister_node_res : Stubbed_Out_Res(this);

        QueryFirstRequest  -> query_first_req : Stubbed_Out_Req(this);
        QueryFirstResponse -> query_first_res : Stubbed_Out_Res(this);

        QueryNextRequest  -> query_next_req : Stubbed_Out_Req(this);
        QueryNextResponse -> query_next_res : Stubbed_Out_Res(this);

        ReadRequest  -> read_req : Read_Req(this);
        ReadResponse -> read_res : Read_Res(this);

        HistoryReadRequest  -> history_read_req : Stubbed_Out_Req(this);
        HistoryReadResponse -> history_read_res : Stubbed_Out_Res(this);

        WriteRequest  -> write_req : Stubbed_Out_Req(this);
        WriteResponse -> write_res : Stubbed_Out_Res(this);

        HistoryUpdateRequest  -> history_update_req : Stubbed_Out_Req(this);
        HistoryUpdateResponse -> history_update_res : Stubbed_Out_Res(this);

        CallRequest  -> call_req : Stubbed_Out_Req(this);
        CallResponse -> call_res : Stubbed_Out_Res(this);

        CreateMonitoredItemsRequest  -> create_monitored_items_req : Create_Monitored_Items_Req(this);
        CreateMonitoredItemsResponse -> create_monitored_items_res : Create_Monitored_Items_Res(this);

        ModifyMonitoredItemsRequest  -> modify_monitored_items_req : Stubbed_Out_Req(this);
        ModifyMonitoredItemsResponse -> modify_monitored_items_res : Stubbed_Out_Res(this);

        SetMonitoringModeRequest  -> set_monitoring_mode_req : Stubbed_Out_Req(this);
        SetMonitoringModeResponse -> set_monitoring_mode_res : Stubbed_Out_Res(this);

        SetTriggeringRequest  -> set_triggering_req : Stubbed_Out_Req(this);
        SetTriggeringResponse -> set_triggering_res : Stubbed_Out_Res(this);

        DeleteMonitoredItemsRequest  -> delete_monitored_items_req : Stubbed_Out_Req(this);
        DeleteMonitoredItemsResponse -> delete_monitored_items_res : Stubbed_Out_Res(this);

        CreateSubscriptionRequest  -> create_subscription_req : Create_Subscription_Req(this);
        CreateSubscriptionResponse -> create_subscription_res : Create_Subscription_Res(this);

        ModifySubscriptionRequest  -> modify_subscription_req : Stubbed_Out_Req(this);
        ModifySubscriptionResponse -> modify_subscription_res : Stubbed_Out_Res(this);

        SetPublishingModeRequest  -> set_publishing_mode_req : Stubbed_Out_Req(this);
        SetPublishingModeResponse -> set_publishing_mode_res : Stubbed_Out_Res(this);

        PublishRequest  -> publish_req : Stubbed_Out_Req(this);
        PublishResponse -> publish_res : Stubbed_Out_Res(this);

        RepublishRequest  -> republish_req : Stubbed_Out_Req(this);
        RepublishResponse -> republish_res : Stubbed_Out_Res(this);

        TransferSubscriptionsRequest  -> transfer_subscriptions_req : Stubbed_Out_Req(this);
        TransferSubscriptionsResponse -> transfer_subscriptions_res : Stubbed_Out_Res(this);

        DeleteSubscriptionsRequest  -> delete_subscriptions_req : Stubbed_Out_Req(this);
        DeleteSubscriptionsResponse -> delete_subscriptions_res : Stubbed_Out_Res(this);

        TestStackRequest  -> test_stack_req : Stubbed_Out_Req(this);
        TestStackResponse -> test_stack_res : Stubbed_Out_Res(this);

        TestStackExRequest  -> test_stack_ex_req : Stubbed_Out_Req(this);
        TestStackExResponse -> test_stack_ex_res : Stubbed_Out_Res(this);

        # UA Specification Part 4 - Services: Table 172
        ServiceFault -> service_fault_res : Service_Fault_Res(this);

        default                    -> data                 : bytestring &restofdata;
    };
} &byteorder=littleendian;
