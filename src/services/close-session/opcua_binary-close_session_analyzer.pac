## opcua_binary-create_sessions_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the get endpoints service.
##
## Author:   Christian Weelborg
## Contact:  Christian.Weelborg@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {
    # CloseSessionRequest
    function deliver_Svc_CloseSessionReq(msg : Close_Session_Req): bool
    %{
        /* Debug 
        printf("deliver_Svc_CloseSessionReq - begin\n");
        printCloseSessionReq(msg); 
        printf("deliver_Svc_CloseSessionReq - end\n");
        */

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);
        
        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());
        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr close_session_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CloseSession);

        Msg_Header *msg_header = msg->service()->msg_body()->header();
        const zeek::RecordValPtr conn_val = connection()->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        // Source & Destination
        close_session_req = assignSourceDestination(msg_header->is_orig(), close_session_req, id_val);

        // OpcUA_id
        close_session_req->Assign(CLOSE_SESSION_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        close_session_req->Assign(CLOSE_SESSION_DEL_SUBSCRIPTIONS_IDX, zeek::val_mgr->Bool(msg->del_subscriptions()));

        zeek::BifEvent::enqueue_opcua_binary_close_session_event(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), close_session_req);

        return true;
    %}

    function deliver_Svc_CloseSessionRes(msg : Close_Session_Res): bool
    %{
        /* Debug
        printf("deliver_Svc_CloseSessionRes - begin\n");
        printCloseSessionRes(msg); 
        printf("deliver_Svc_CloseSessionRes - end\n");
        */

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr(), msg->service()->msg_body()->header()->is_orig());
        info = assignService(info, msg->service());
        
        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), info);

        return true;
    %}
}