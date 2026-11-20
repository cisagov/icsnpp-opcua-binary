## opcua_binary-call_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing the call service.
##
## Author:   John B Joseph
##

%header{
    void printCallReq(Call_Req *msg);
    void printCallRes(Call_Res *msg);
%}

%code{

    void printCallReq(Call_Req *msg) {
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header());
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printReqHdr(msg->req_hdr());

        // Methods to call
        printf("%s MethodsToCall: Array of CallMethodRequest\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->methods_to_call_size());
        for (int i = 0; i < msg->methods_to_call_size(); i++) {
            OpcUA_CallMethodRequest *method = msg->methods_to_call()->at(i);
            printf("%s [%d]: CallMethodRequest\n", indent(4).c_str(), i);
            printf("%s ObjectId: NodeId\n", indent(5).c_str());
            printOpcUA_NodeId(6, method->object_id());
            printf("%s MethodId: NodeId\n", indent(5).c_str());
            printOpcUA_NodeId(6, method->method_id());
            printf("%s InputArguments: Array of Variant\n", indent(5).c_str());
            printf("%s ArraySize: %d\n", indent(6).c_str(), method->input_arguments_size());
            for (int j = 0; j < method->input_arguments_size(); j++) {
                printf("%s [%d]: Variant\n", indent(6).c_str(), j);
                printOpcUA_Variant(7, method->input_arguments()->at(j));
            }
        }
    }

    void printCallRes(Call_Res *msg) {
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header());
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printResHdr(msg->res_hdr());

        printf("%s Results: Array of CallMethodResult\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->results_size());
        for (int i = 0; i < msg->results_size(); i++) {
            OpcUA_CallMethodResult *result = msg->results()->at(i);
            printf("%s [%d]: CallMethodResult\n", indent(4).c_str(), i);
            printf("%s StatusCode: 0x%08x [%s]\n", indent(5).c_str(), result->status_code(), STATUS_CODE_MAP.find(result->status_code())->second.c_str());

            printf("%s InputArgumentResults: Array of StatusCode\n", indent(5).c_str());
            printf("%s ArraySize: %d\n", indent(6).c_str(), result->input_argument_results_size());
            for (int j = 0; j < result->input_argument_results_size(); j++) {
                printf("%s [%d]: StatusCode: 0x%08x [%s]\n", indent(6).c_str(), j, result->input_argument_results()->at(j), STATUS_CODE_MAP.find(result->input_argument_results()->at(j))->second.c_str());
            }

            printf("%s InputArgumentDiagnosticInfos: Array of DiagnosticInfo\n", indent(5).c_str());
            printf("%s ArraySize: %d\n", indent(6).c_str(), result->input_argument_diagnostic_infos_size());
            for (int j = 0; j < result->input_argument_diagnostic_infos_size(); j++) {
                printf("%s [%d]: DiagnosticInfo\n", indent(6).c_str(), j);
                printOpcUA_DiagInfo(7, result->input_argument_diagnostic_infos()->at(j));
            }

            printf("%s OutputArguments: Array of Variant\n", indent(5).c_str());
            printf("%s ArraySize: %d\n", indent(6).c_str(), result->output_arguments_size());
            for (int j = 0; j < result->output_arguments_size(); j++) {
                printf("%s [%d]: Variant\n", indent(6).c_str(), j);
                printOpcUA_Variant(7, result->output_arguments()->at(j));
            }
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
