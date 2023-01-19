## opcua_binary-read_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the read service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {

    #
    # ReadRequest
    #
    function deliver_Svc_ReadReq(msg : Read_Req): bool
        %{
        /* Debug
        printf("deliver_Svc_ReadReq - begin\n");
        printReadReq(msg);
        printf("deliver_Svc_ReadReq - end\n");
        */

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr read_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Read);

        // OpcUA_id
        read_req->Assign(READ_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        // Max Age
        read_req->Assign(READ_REQ_MAX_AGE_IDX, zeek::val_mgr->Count(bytestringToDouble(msg->max_age()->duration())));

        // Timestamps to Return
        read_req->Assign(READ_REQ_TIMESTAMPS_TO_RETURN_IDX, zeek::val_mgr->Count(msg->timestamps_to_return()));
        read_req->Assign(READ_REQ_TIMESTAMPS_TO_RETURN_STR_IDX, zeek::make_intrusive<zeek::StringVal>(unixTimestampToString(msg->timestamps_to_return())));

        // Nodes to Read
        if (msg->nodes_to_read_size() > 0) {
            // Link into OpcUA_Binary::ReadNodesToRead
            std::string nodes_to_read_link_id = generateId();
            read_req->Assign(READ_REQ_NODES_TO_READ_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(nodes_to_read_link_id));

            for (int i = 0; i < msg->nodes_to_read_size(); i++) {
                zeek::RecordValPtr nodes_to_read = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadNodesToRead);

                // Link back into OpcUA_Binary::Read
                nodes_to_read->Assign(READ_REQ_NODES_TO_READ_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(nodes_to_read_link_id));

                // Node Id
                flattenOpcUA_NodeId(nodes_to_read, msg->nodes_to_read()->at(i)->node_id(), READ_REQ_NODE_ID_ENCODING_MASK_IDX);

                // Attribute Id
                nodes_to_read->Assign(READ_REQ_ATTRIBUTE_ID_IDX, zeek::val_mgr->Count(msg->nodes_to_read()->at(i)->attribute_id()));
                nodes_to_read->Assign(READ_REQ_ATTRIBUTE_ID_STR_IDX, zeek::make_intrusive<zeek::StringVal>(ATTRIBUTE_ID_MAP.find(msg->nodes_to_read()->at(i)->attribute_id())->second));

                // Index Range
                if (msg->nodes_to_read()->at(i)->index_range()->length() > 0) {
                    nodes_to_read->Assign(READ_REQ_INDEX_RANGE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->nodes_to_read()->at(i)->index_range()->string())));
                }

                // Qualified Name
                nodes_to_read->Assign(READ_REQ_DATA_ENCODING_NAME_ID_IDX, zeek::val_mgr->Count(msg->nodes_to_read()->at(i)->data_encoding()->namespace_index()));
                nodes_to_read->Assign(READ_REQ_DATA_ENCODING_NAME_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->nodes_to_read()->at(i)->data_encoding()->name()->string())));

                // Fire event
                zeek::BifEvent::enqueue_opcua_binary_read_nodes_to_read_event(connection()->bro_analyzer(),
                                                                              connection()->bro_analyzer()->Conn(),
                                                                              nodes_to_read);
            }

        }

        // Fire event
        zeek::BifEvent::enqueue_opcua_binary_read_event(connection()->bro_analyzer(),
                                                        connection()->bro_analyzer()->Conn(),
                                                        read_req);

        return true;
        %}

    #
    # ReadResponse
    #
    function deliver_Svc_ReadRes(msg : Read_Res): bool
        %{
        /* Debug */
        printf("deliver_Svc_ReadRes - begin\n");
        printReadRes(msg);
        printf("deliver_Svc_ReadRes - end\n");

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr read_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Read);

        // OpcUA_id
        read_res->Assign(READ_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        // Results
        if (msg->results_size() > 0) {
            string read_results_link_id = generateId(); // Link to tie OCPUA_Binary::Read and OPCUA_Binary::ReadResults together

            // Assign the linkage in the OCPUA_Binary::Read and OPCUA_Binary::Results
            read_res->Assign(READ_RES_RESULTS_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(read_results_link_id));

            for (int i = 0; i < msg->results_size(); i++) {
                OpcUA_DataValue* data_value = msg->results()->at(i);
                zeek::RecordValPtr read_results = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadResults);

                // Assign the linkage int the OPCUA_Binary::Read and OPCUA_Binary::ReadResults
                read_results->Assign(READ_RES_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(read_results_link_id));

                // Level
                read_results->Assign(READ_RES_LEVEL_IDX, zeek::val_mgr->Count(i));

                flattenOpcUA_DataValue(connection(), data_value, read_results, READ_RES_DATA_VALUE_ENCODING_MASK_IDX, StatusCode_Read_Key, Variant_Read_Key);

                // Fire event
                zeek::BifEvent::enqueue_opcua_binary_read_results_event(connection()->bro_analyzer(),
                                                                        connection()->bro_analyzer()->Conn(),
                                                                        read_results);
            }

        }

        // Diagnostic Information
        if (msg->diagnostic_info_size() > 0) {
            string diagnostic_info_id_link = generateId(); // Link to tie OCPUA_Binary::Read and OPCUA_Binary::DiagnosticInfoDetail together

            // Assign the linkage in the OCPUA_Binary::Read
            read_res->Assign(READ_RES_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id_link));

            uint32 innerDiagLevel = 0;
            vector<OpcUA_String *>  *stringTable = NULL;
            for (int i = 0; i < msg->diagnostic_info_size(); i++) {

                // Process the details of the Diagnostic Information
                generateDiagInfoEvent(connection(), read_res->GetField(READ_RES_DIAG_INFO_LINK_ID_SRC_IDX), msg->diagnostic_info()->at(i), stringTable, innerDiagLevel, StatusCode_Read_DiagInfo_Key, DiagInfo_Read_Key);

            }
        }

        // Fire event
        zeek::BifEvent::enqueue_opcua_binary_read_event(connection()->bro_analyzer(),
                                                        connection()->bro_analyzer()->Conn(),
                                                        read_res);

        return true;
    %}
};
