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
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info->Assign();
        
    %}

    function deliver_Svc_CloseSessionRes(msg : Close_Session_Res): bool
    %{
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info->Assign();
    %}
}