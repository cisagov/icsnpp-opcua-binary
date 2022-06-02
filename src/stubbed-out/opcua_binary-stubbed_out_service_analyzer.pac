## opcua_binary-stubbed_out_service_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Placeholder analyzer code for processing services that have yet to be implemented.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {

    #
    # Process a generic request used of a stubbed out service.  Log
    # the request header which includes the service identifier.
    #
    function deliver_Stubbed_Out_Req(request: Stubbed_Out_Req): bool
        %{
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, request->service()->msg_body()->header());
        info = assignMsgType(info, request->service()->msg_body()->header());
        info = assignReqHdr(info, request->req_hdr());
        info = assignService(info, request->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        return true;
        %}

    #
    # Process a generic response of a stubbed out services.  Log
    # the response header which includes the service identifier.
    #
    function deliver_Stubbed_Out_Res(response: Stubbed_Out_Res): bool
        %{
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, response->service()->msg_body()->header());
        info = assignMsgType(info, response->service()->msg_body()->header());
        info = assignResHdr(connection(), info, response->res_hdr());
        info = assignService(info, response->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        return true;
        %}

};
