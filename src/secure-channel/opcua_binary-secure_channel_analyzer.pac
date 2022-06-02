## opcua_binary-secure_channel_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the secure channel service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {

    #
    # OpenSecureChannelRequest
    #
    function deliver_Svc_OpnSecChnlReq(msg : Opn_Sec_Chnl_Req): bool
        %{
        //Debug printOpnSecChnlReq(msg);

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        //
        // Open Secure Channel Request
        //
        zeek::RecordValPtr opensecure_channel_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::OpenSecureChannel);

        // OpcUA_id
        opensecure_channel_req->Assign(OPENSECURE_CHANNEL_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_ID_IDX));

        opensecure_channel_req->Assign(CLIENT_PROTO_VER_IDX,        zeek::val_mgr->Count(msg->service()->opn_sec_chnl_req()->client_proto_ver()));
        opensecure_channel_req->Assign(SECURITY_TOKEN_REQ_TYPE_IDX, zeek::val_mgr->Count(msg->service()->opn_sec_chnl_req()->req_type()));
        opensecure_channel_req->Assign(MESSAGE_SECURITY_MODE_IDX,   zeek::val_mgr->Count(msg->service()->opn_sec_chnl_req()->sec_mode()));
        opensecure_channel_req->Assign(CLIENT_NONCE_IDX,            zeek::make_intrusive<zeek::StringVal>(std_str(msg->service()->opn_sec_chnl_req()->client_nonce()->byteString())));
        opensecure_channel_req->Assign(REQ_LIFETIME_IDX,            zeek::val_mgr->Count(msg->service()->opn_sec_chnl_req()->req_lifetime()));

        zeek::BifEvent::enqueue_opcua_binary_opensecure_channel_event(connection()->bro_analyzer(),
                                                                     connection()->bro_analyzer()->Conn(),
                                                                     opensecure_channel_req);

        return true;
        %}

    #
    # OpenSecureChannelResponse
    #
    function deliver_Svc_OpnSecChnlRes(msg : Opn_Sec_Chnl_Res): bool
        %{
        //Debug printOpnSecChnlRes(msg);

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        //
        // Open Secure Channel Response
        //
        zeek::RecordValPtr opensecure_channel_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::OpenSecureChannel);

        // OpcUA_id
        opensecure_channel_res->Assign(OPENSECURE_CHANNEL_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_ID_IDX));

        opensecure_channel_res->Assign(SERVER_PROTO_VER_IDX,           zeek::val_mgr->Count(msg->server_proto_ver()));
        opensecure_channel_res->Assign(SEC_TOKEN_CHANNEL_ID_IDX,       zeek::val_mgr->Count(msg->security_token()->secure_channel_id()));
        opensecure_channel_res->Assign(SEC_TOKEN_ID_IDX,               zeek::val_mgr->Count(msg->security_token()->token_id()));

        double unix_timestamp = winFiletimeToUnixTime(msg->security_token()->created_at());
        opensecure_channel_res->Assign(SEC_TOKEN_CREATED_AT_IDX,       zeek::make_intrusive<zeek::TimeVal>(unix_timestamp));

        opensecure_channel_res->Assign(SEC_TOKEN_REVISED_LIFETIME_IDX, zeek::val_mgr->Count(msg->security_token()->revised_lifetime()));
        opensecure_channel_res->Assign(SERVER_NONCE_IDX,               zeek::make_intrusive<zeek::StringVal>(std_str(msg->server_nonce()->byteString())));

        zeek::BifEvent::enqueue_opcua_binary_opensecure_channel_event(connection()->bro_analyzer(),
                                                                      connection()->bro_analyzer()->Conn(),
                                                                      opensecure_channel_res);

        return true;
        %}

    #
    # CloseSecureChannelRequest
    #
    function deliver_Svc_CloSecChnlReq(msg : Clo_Sec_Chnl_Req): bool
        %{
        //Debug printCloSecChnlReq(msg);

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        return true;
        %}

    #
    # CloseSecureChannelResponse
    #
    function deliver_Svc_CloSecChnlRes(msg : Clo_Sec_Chnl_Res): bool
        %{
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

};
