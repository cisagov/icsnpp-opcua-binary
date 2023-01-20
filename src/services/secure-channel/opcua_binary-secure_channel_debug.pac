## opcua_binary-secure_channel_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing the secure channel service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printOpnSecChnlReq(Opn_Sec_Chnl_Req *msg);
    void printOpnSecChnlRes(Opn_Sec_Chnl_Res *msg);
    void printCloSecChnlReq(Clo_Sec_Chnl_Req *msg);
%}

%code{

    void printOpnSecChnlReq(Opn_Sec_Chnl_Req *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());
        printReqHdr(msg->req_hdr());

        // Details need implemented

        return;
    }

    void printOpnSecChnlRes(Opn_Sec_Chnl_Res *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());
        printResHdr(msg->res_hdr());

        // Details need implemented

        return;
    }

    void printCloSecChnlReq(Clo_Sec_Chnl_Req *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());
        printReqHdr(msg->req_hdr());

        // Details need implemented

        return;
    }
%}