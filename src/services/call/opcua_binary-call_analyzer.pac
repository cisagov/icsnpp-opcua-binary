## opcua_binary-call_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the call service.
##
## Author:   John B Joseph
##

refine flow OPCUA_Binary_Flow += {

    #
    # CallRequest
    #
    # One OPCUA_Binary::Call record is logged per CallMethodRequest: the object, the method,
    # and a link to the input arguments in the OPCUA_Binary::VariantMetadata log.
    #
    function deliver_Svc_CallReq(msg : Call_Req): bool
        %{
        /* Debug
        printf("deliver_Svc_CallReq - begin\n");
        printCallReq(msg);
        printf("deliver_Svc_CallReq - end\n");
        */

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        // Source & Destination
        Msg_Header *msg_header = msg->service()->msg_body()->header();
        const zeek::RecordValPtr conn_val = connection()->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        // Methods to Call
        for (int i = 0; i < msg->methods_to_call_size(); i++) {
            OpcUA_CallMethodRequest *method = msg->methods_to_call()->at(i);
            zeek::RecordValPtr call_request = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Call);

            // OpcUA_id
            call_request->Assign(CALL_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

            // Source & Destination
            call_request = assignSourceDestination(msg_header->is_orig(), call_request, id_val);

            // Object Id and Method Id
            flattenOpcUA_NodeId(call_request, method->object_id(), CALL_REQ_OBJECT_ID_ENCODING_MASK_IDX);
            flattenOpcUA_NodeId(call_request, method->method_id(), CALL_REQ_METHOD_ID_ENCODING_MASK_IDX);

            // Input Arguments - each argument is logged in OPCUA_Binary::VariantMetadata under one link id
            if (method->input_arguments_size() > 0) {
                string input_arguments_link_id = generateId();
                call_request->Assign(CALL_REQ_INPUT_ARGUMENTS_VARIANT_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(input_arguments_link_id));
                for (int j = 0; j < method->input_arguments_size(); j++) {
                    flattenOpcUA_DataVariant(connection(), method->input_arguments()->at(j), input_arguments_link_id, Variant_Call_Input_Key, msg_header->is_orig());
                }
            }

            // Enqueue the OCPUA_Binary::Call event.
            zeek::BifEvent::enqueue_opcua_binary_call_event(connection()->bro_analyzer(),
                                                            connection()->bro_analyzer()->Conn(),
                                                            call_request);
        }

        return true;
        %}

    #
    # CallResponse
    #
    # One OPCUA_Binary::Call record is logged per CallMethodResult. The DiagnosticInfos array
    # of the response is ordered like the results array, so DiagnosticInfo[i] is linked from
    # the record for result i. A response with no results still logs one record.
    #
    function deliver_Svc_CallRes(msg : Call_Res): bool
        %{
        /* Debug
        printf("deliver_Svc_CallRes - begin\n");
        printCallRes(msg);
        printf("deliver_Svc_CallRes - end\n");
        */

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr(), msg->service()->msg_body()->header()->is_orig());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        // Source & Destination
        Msg_Header *msg_header = msg->service()->msg_body()->header();
        bool is_orig = msg_header->is_orig();
        const zeek::RecordValPtr conn_val = connection()->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        int num_records = (msg->results_size() > 0) ? msg->results_size() : 1;
        for (int i = 0; i < num_records; i++) {
            zeek::RecordValPtr call_response = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Call);

            call_response = assignSourceDestination(is_orig, call_response, id_val);

            // OpcUA_id
            call_response->Assign(CALL_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

            if (i < msg->results_size()) {
                OpcUA_CallMethodResult *result = msg->results()->at(i);

                // StatusCode of the method call
                uint32_t status_code_level = 0;
                string status_code_link_id = generateId();
                call_response->Assign(CALL_RES_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(status_code_link_id));
                generateStatusCodeEvent(connection(), call_response->GetField(CALL_RES_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_Call_Key, result->status_code(), status_code_level, is_orig);

                // InputArgumentResults: Array of StatusCode
                if (result->input_argument_results_size() > 0) {
                    string input_arg_results_link_id = generateId();
                    call_response->Assign(CALL_RES_INPUT_ARG_RESULTS_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(input_arg_results_link_id));
                    for (int j = 0; j < result->input_argument_results_size(); j++) {
                        generateStatusCodeEvent(connection(), call_response->GetField(CALL_RES_INPUT_ARG_RESULTS_LINK_ID_SRC_IDX), StatusCode_Call_InputArgument_Key, result->input_argument_results()->at(j), status_code_level, is_orig);
                    }
                }

                // InputArgumentDiagnosticInfos: Array of DiagnosticInfo
                if (result->input_argument_diagnostic_infos_size() > 0) {
                    string input_arg_diag_info_link_id = generateId();
                    call_response->Assign(CALL_RES_INPUT_ARG_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(input_arg_diag_info_link_id));
                    uint32 innerDiagLevel = 0;
                    vector<OpcUA_String *> *stringTable = NULL;
                    for (int j = 0; j < result->input_argument_diagnostic_infos_size(); j++) {
                        generateDiagInfoEvent(connection(), call_response->GetField(CALL_RES_INPUT_ARG_DIAG_INFO_LINK_ID_SRC_IDX), result->input_argument_diagnostic_infos()->at(j), stringTable, innerDiagLevel, StatusCode_Call_InputArgument_DiagInfo_Key, DiagInfo_Call_InputArgument_Key, is_orig);
                    }
                }

                // OutputArguments: Array of Variant, logged in OPCUA_Binary::VariantMetadata under one link id
                if (result->output_arguments_size() > 0) {
                    string output_arguments_link_id = generateId();
                    call_response->Assign(CALL_RES_OUTPUT_ARGUMENTS_VARIANT_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(output_arguments_link_id));
                    for (int j = 0; j < result->output_arguments_size(); j++) {
                        flattenOpcUA_DataVariant(connection(), result->output_arguments()->at(j), output_arguments_link_id, Variant_Call_Output_Key, is_orig);
                    }
                }
            }

            // DiagnosticInfos: DiagnosticInfo[i] belongs to result i. Any surplus entries are
            // linked from the last record so that none are dropped.
            int diag_first = i;
            int diag_last  = (i == num_records - 1) ? msg->diagnostic_info_size() - 1 : i;
            if (diag_first < msg->diagnostic_info_size()) {
                string diag_info_link_id = generateId();
                call_response->Assign(CALL_RES_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diag_info_link_id));
                uint32 innerDiagLevel = 0;
                vector<OpcUA_String *> *stringTable = NULL;
                for (int j = diag_first; j <= diag_last; j++) {
                    generateDiagInfoEvent(connection(), call_response->GetField(CALL_RES_DIAG_INFO_LINK_ID_SRC_IDX), msg->diagnostic_info()->at(j), stringTable, innerDiagLevel, StatusCode_Call_DiagInfo_Key, DiagInfo_Call_Key, is_orig);
                }
            }

            // Enqueue the OCPUA_Binary::Call event.
            zeek::BifEvent::enqueue_opcua_binary_call_event(connection()->bro_analyzer(),
                                                            connection()->bro_analyzer()->Conn(),
                                                            call_response);
        }

        return true;
        %}
};
