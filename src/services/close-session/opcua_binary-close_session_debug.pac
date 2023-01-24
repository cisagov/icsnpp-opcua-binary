## opcua_binary-close-session_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing the close session service.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printCloseSessionReq(Close_Session_Req *msg);
    void printCloseSessionItemsRes(Close_Session_Res *msg);
%}

%code{
    void printCloseSessionReq(Close_Session_Req *msg){
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header()); 
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printReqHdr(msg->req_hdr());

    }
    void printCloseSessionItemsRes(Close_Session_Res *msg){
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header());
        printService(msg->service());   

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printResHdr(msg->res_hdr());
    }
%}