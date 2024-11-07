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

        // Max Age
        printf("%s MaxAge: %f\n", indent(3).c_str(), bytestringToDouble(msg->max_age()->duration()));

        // Timestamps to return
        if (msg->timestamps_to_return() == 0) {
            printf("%s TimestampsToReturn: Source (0x%08x)\n", indent(3).c_str(), msg->timestamps_to_return());
        } else if (msg->timestamps_to_return() == 1) {
            printf("%s TimestampsToReturn: Server (0x%08x)\n", indent(3).c_str(), msg->timestamps_to_return());
        } else if (msg->timestamps_to_return() == 1) {
            printf("%s TimestampsToReturn: Both (0x%08x)\n", indent(3).c_str(), msg->timestamps_to_return());
        } else if (msg->timestamps_to_return() == 1) {
            printf("%s TimestampsToReturn: Neither (0x%08x)\n", indent(3).c_str(), msg->timestamps_to_return());
        }

        // Nodes to write
        printf("%s NodesToWrite: Array of WriteValueId\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->nodes_to_write_size());
        for (int i = 0; i < msg->nodes_to_write_size(); i++) {
            printf("%s [%d]: WriteValueId\n", indent(4).c_str(), i);
            printOpcUA_WriteValueId(5, msg->nodes_to_write()->at(i));
        }
    }

    void printWriteRes(Write_Res *msg) {
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header());
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printResHdr(msg->res_hdr());

        // Array of DataValue(s)
        printf("%s Results: Array of DataValue\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->results_size());
        for (int i = 0; i < msg->results_size(); i++) {
            printf("%s [%d]: DataValue\n", indent(4).c_str(), i);
            printOpcUA_DataValue(5, msg->results()->at(i));
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