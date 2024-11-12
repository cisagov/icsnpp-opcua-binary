## opcua_binary-write_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing the write service.
##
## Author:   Jason Rush
## Contact:  jason.rush@inl.gov
##
## Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printWriteReq(Write_Req *msg);
    void printWriteRes(Write_Res *msg);
%}

%code{

    void printWriteReq(Write_Req *msg) {
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header());
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printReqHdr(msg->req_hdr());

        // Nodes to write
        printf("%s NodesToWrite: Array of WriteValue\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->nodes_to_write_size());
        for (int i = 0; i < msg->nodes_to_write_size(); i++) {
            printf("%s [%d]: WriteValue\n", indent(4).c_str(), i);
            printOpcUA_WriteValue(5, msg->nodes_to_write()->at(i));
        }
    }

    void printWriteRes(Write_Res *msg) {
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header());
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printResHdr(msg->res_hdr());

        printf("%s Results: Array of StatusCode\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->results_size());
        for (int i = 0; i < msg->results_size(); i++) {
            printf("%s [%d]: Results: 0x%08x [%s]\n", indent(4).c_str(), i, msg->results()->at(i), STATUS_CODE_MAP.find(msg->results()->at(i))->second.c_str());
        }

        // Array of DiagnosticInfo(s)
        printf("%s DiagnosticInfos: Array of DiagnosticInfo\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->diagnostic_info_size());
        for (int i = 0; i < msg->diagnostic_info_size(); i++) {
            printf("%s [%d]: DiagnosticInfo\n", indent(4).c_str(), i);
            printOpcUA_DiagInfo(5, msg->diagnostic_info()->at(i));
        }

    }
%}