## opcua_binary-write_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the write service.
##
## Author:   Jason Rush
## Contact:  jason.rush@inl.gov
##
## Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {

    #
    # WriteRequest
    #
    function deliver_Svc_WriteReq(msg : Write_Req): bool
        %{
        /* Debug
        printf("deliver_Svc_WriteReq - begin\n");
        printWriteReq(msg);
        printf("deliver_Svc_WriteReq - end\n");
        */

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr write_request = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Write);

        // Source & Destination
        Msg_Header *msg_header = msg->service()->msg_body()->header();
        const zeek::RecordValPtr conn_val = connection()->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        // OpcUA_id
        write_request->Assign(WRITE_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        // Nodes to Write
        /*if (msg->nodes_to_write_size() > 0) {
            // Link into OpcUA_Binary::WriteNodesToWrite
            std::string nodes_to_write_link_id = generateId();
            write_request->Assign(WRITE_REQ_NODES_TO_WRITE_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(nodes_to_write_link_id));

            for (int i = 0; i < msg->nodes_to_write_size(); i++) {
                zeek::RecordValPtr nodes_to_write = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::WriteNodesToWrite);

                // Source & Destination
                nodes_to_write = assignSourceDestination(msg_header->is_orig(), nodes_to_write, id_val);

                // Link back into OpcUA_Binary::Write
                nodes_to_write->Assign(WRITE_REQ_NODES_TO_WRITE_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(nodes_to_write_link_id));

                // Node Id
                flattenOpcUA_NodeId(nodes_to_write, msg->nodes_to_write()->at(i)->node_id(), WRITE_REQ_NODE_ID_ENCODING_MASK_IDX);

                // Attribute Id
                nodes_to_write->Assign(WRITE_REQ_ATTRIBUTE_ID_IDX, zeek::val_mgr->Count(msg->nodes_to_write()->at(i)->attribute_id()));
                nodes_to_write->Assign(WRITE_REQ_ATTRIBUTE_ID_STR_IDX, zeek::make_intrusive<zeek::StringVal>(ATTRIBUTE_ID_MAP.find(msg->nodes_to_write()->at(i)->attribute_id())->second));

                // Index Range
                if (msg->nodes_to_write()->at(i)->index_range()->length() > 0) {
                    nodes_to_write->Assign(WRITE_REQ_INDEX_RANGE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->nodes_to_write()->at(i)->index_range()->string())));
                }

                // DataValue
                OpcUA_DataValue* data_value = msg->nodes_to_write()->at(i);
                zeek::RecordValPtr nodes_to_write = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::WriteNodesToWrite);

                // Source & Destination
                nodes_to_write = assignSourceDestination(msg_header->is_orig(), nodes_to_write, id_val);

                // Assign the linkage int the OPCUA_Binary::Write and OPCUA_Binary::WriteNodesToWrite
                nodes_to_write->Assign(WRITE_REQ_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(write_results_link_id));

                // Level
                nodes_to_write->Assign(WRITE_REQ_LEVEL_IDX, zeek::val_mgr->Count(i));

                flattenOpcUA_DataValue(connection(), data_value, nodes_to_write, WRITE_REQ_DATA_VALUE_ENCODING_MASK_IDX, StatusCode_Write_Key, Variant_Write_Key, msg_header->is_orig());

                /* Fire event
                zeek::BifEvent::enqueue_opcua_binary_nodes_to_write_event(connection()->bro_analyzer(),
                                                                        connection()->bro_analyzer()->Conn(),
                                                                        nodes_to_write);
                }

                // Fire event
                zeek::BifEvent::enqueue_opcua_binary_write_nodes_to_write_event(connection()->bro_analyzer(),
                                                                              connection()->bro_analyzer()->Conn(),
                                                                              nodes_to_write);
            }

        }

        // Enqueue the OCPUA_Binary::WriteRequest event.
        zeek::BifEvent::enqueue_opcua_binary_write_event(connection()->bro_analyzer(),
                                                            connection()->bro_analyzer()->Conn(),
                                                            write_request);*/

        return true;
        %}

    #
    # WriteResponse
    #
    function deliver_Svc_WriteRes(msg : Write_Res): bool
        %{
        // Debug
        printf("deliver_Svc_WriteRes - begin\n");
        printWriteRes(msg);
        printf("deliver_Svc_WriteRes - end\n");
        //

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr(), msg->service()->msg_body()->header()->is_orig());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr write_response = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Write);
        
        // Source & Destination
        Msg_Header *msg_header = msg->service()->msg_body()->header();

        // OpcUA_id
        write_response->Assign(WRITE_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));
        
        // StatusCode Results
        if (msg->results_size() > 0) {
            uint32_t status_code_level = 0;
            string result_idx = generateId();
            write_response->Assign(WRITE_RES_RESULTS_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(result_idx));
            for (int i = 0; i < msg->results_size(); i++) {
                generateStatusCodeEvent(connection(), write_response->GetField(WRITE_RES_RESULTS_LINK_ID_SRC_IDX), StatusCode_Write_Key, msg->results()->at(i), status_code_level, msg_header->is_orig());
            }
        }

        // Diagnostic information
        if (msg->diagnostic_info_size() > 0) {
            string diagnostic_info_id_link = generateId(); // Link to tie OCPUA_Binary::WriteResponse and OPCUA_Binary:WriteResponseDiagnosticInfo together
            string diagnostic_info_id      = generateId(); // Link to tie OCPUA_Binary::WriteResponseDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together

            // Assign the linkage in the OCPUA_Binary::WriteResponse
            write_response->Assign(WRITE_RES_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id_link));

            uint32 innerDiagLevel = 0;
            vector<OpcUA_String *>  *stringTable = NULL;
            for (int i = 0; i < msg->diagnostic_info_size(); i++) {
                // Process the details of the Diagnostic Information
                generateDiagInfoEvent(connection(), write_response->GetField(WRITE_RES_DIAG_INFO_LINK_ID_SRC_IDX), msg->diagnostic_info()->at(i), stringTable, innerDiagLevel, StatusCode_Write_DiagInfo_Key, msg_header->is_orig(), DiagInfo_Write_Key);
            }
        }

        // Enqueue the OCPUA_Binary::WriteResponse event.
        zeek::BifEvent::enqueue_opcua_binary_write_event(connection()->bro_analyzer(),
                                                            connection()->bro_analyzer()->Conn(),
                                                            write_response);

        return true;
        %}
};
