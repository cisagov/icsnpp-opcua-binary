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

%header{
    void printServiceFaultRes(Service_Fault_Res *msg);
%}

%code{
    void printServiceFaultRes(Service_Fault_Res *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());
        printResHdr(msg->res_hdr());

        return;
    }
%}