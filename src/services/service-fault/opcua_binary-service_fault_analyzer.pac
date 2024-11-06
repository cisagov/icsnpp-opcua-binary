## opcua_binary-service_fault.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the service fault.
##
## Author:   Jason Rush
## Contact:  jason.rush@inl.gov
##
## Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {

    #
    # ServiceFaultResponse
    #
    function deliver_Svc_ServiceFaultRes(msg: Service_Fault_Res): bool
    %{
        /* Debug
        printf("deliver_Svc_ServiceFaultRes - begin\n");
        printServiceFaultRes(msg);
        printf("deliver_Svc_ServiceFaultRes - end\n");
        */

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr(), msg->service()->msg_body()->header()->is_orig());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        return true;
    %}
}