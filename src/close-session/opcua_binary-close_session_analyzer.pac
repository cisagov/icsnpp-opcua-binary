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
    function deliver_Svc_CloseSessionReq(close_session_req : Close_Session_Req): bool
    %{
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info->Assign(3, zeek::make_intrusive<zeek::bool>(close_session_req->del_subscriptions()));

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), info);

        return true;
    %}

    function deliver_Svc_CloseSessionRes(close_session_res : Close_Session_Res): bool
    %{
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), info);

        return true;
    %}
}