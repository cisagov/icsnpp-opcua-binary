## opcua_binary-stubbed_out_service_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Placeholder debug code for processing services that have yet to be implemented.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printStubbedOutRes(Stubbed_Out_Res *msg);
    void printStubbedOutReq(Stubbed_Out_Req *msg);
%}

%code{

    void printStubbedOutReq(Stubbed_Out_Req *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());
        printReqHdr(msg->req_hdr());

        // Details need implemented

        return;
    }

    void printStubbedOutRes(Stubbed_Out_Res *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());
        printResHdr(msg->res_hdr());

        // Details need implemented

        return;
    }
%}