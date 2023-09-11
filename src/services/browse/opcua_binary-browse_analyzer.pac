## opcua_binary-browse_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the browse service.
##
## Author:  Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {
    #
    # BrowseRequest
    #
    function deliver_Svc_BrowseReq(msg: Browse_Req): bool
        %{
        // Debug printf("deliver_Svc_BrowseReq - begin\n");
        // Debug printBrowseReq(msg);
        // Debug printf("deliver_Svc_BrowseReq - end\n");

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());
        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr browse_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Browse);

        Msg_Header *msg_header = msg->service()->msg_body()->header();
        const zeek::RecordValPtr conn_val = connection()->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        // Source & Destination
        browse_req = assignSourceDestination(msg_header->is_orig(), browse_req, id_val);

        // OpcUA_id
        browse_req->Assign(BROWSE_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        // Include if Service is Browse or BrowseNext
        browse_req->Assign(BROWSE_SERVICE_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second));

        // View Description Flattening

        flattenOpcUA_NodeId(browse_req, msg->view_description()->view_id(), BROWSE_VIEW_ID_ENCODING_MASK_IDX);

        
        browse_req->Assign(BROWSE_VIEW_DESCRIPTION_TIMESTAMP_IDX, zeek::make_intrusive<zeek::TimeVal>(msg->view_description()->timestamp()));
        

        browse_req->Assign(BROWSE_VIEW_DESCRIPTION_VIEW_VERSION_IDX, zeek::val_mgr->Count(msg->view_description()->view_version()));

        browse_req->Assign(BROWSE_REQ_MAX_REFS_IDX, zeek::val_mgr->Count(msg->req_max_refs_per_node()));

        int32_t num_nodes_to_browse = (msg->num_nodes_to_browse());

        if (num_nodes_to_browse > 0){
            std::string browse_description_idx = generateId();
            browse_req->Assign(BROWSE_DESCRTIPTION_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(browse_description_idx));
            // Flatten each browse request
            for (int32_t i=0; i < num_nodes_to_browse; i++){
                zeek::RecordValPtr browse_description = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::BrowseDescription);

                // Source & Destination
                browse_description = assignSourceDestination(msg_header->is_orig(), browse_description, id_val);

                browse_description->Assign(BROWSE_DESCRIPTION_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(browse_description_idx));
                flattenOpcUA_NodeId(browse_description, msg->nodes_to_browse()->at(i)->node_id(), BROWSE_DESCRIPTION_ID_ENCODING_MASK_IDX);

                if ((msg->nodes_to_browse()->at(i)->browse_direction_id()) == 0){
                    browse_description->Assign(BROWSE_DIRECTION_ID_IDX, zeek::make_intrusive<zeek::StringVal>("FWD"));
                } else if ((msg->nodes_to_browse()->at(i)->browse_direction_id()) == 1){
                    browse_description->Assign(BROWSE_DIRECTION_ID_IDX, zeek::make_intrusive<zeek::StringVal>("INVERSE"));
                } else if ((msg->nodes_to_browse()->at(i)->browse_direction_id()) == 2){
                    browse_description->Assign(BROWSE_DIRECTION_ID_IDX, zeek::make_intrusive<zeek::StringVal>("BOTH"));
                }

                flattenOpcUA_NodeId(browse_description, msg->nodes_to_browse()->at(i)->ref_type_id(), BROWSE_DESCRIPTION_REF_ID_ENCODING_MASK_IDX);

                browse_description->Assign(BROWSE_DESCRIPTION_INCLUDE_SUBTYPES_IDX, zeek::val_mgr->Bool(msg->nodes_to_browse()->at(i)->include_subtypes()));
                
                browse_description->Assign(BROWSE_DESCRIPTION_NODE_CLASS_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_CLASSES_MAP.find(msg->nodes_to_browse()->at(i)->node_class_mask())->second));
                
                browse_description->Assign(BROWSE_DESCRIPTION_RESULT_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(uint32ToHexstring(msg->nodes_to_browse()->at(i)->result_mask())));

                zeek::BifEvent::enqueue_opcua_binary_browse_description_event(connection()->bro_analyzer(),
                                                                                     connection()->bro_analyzer()->Conn(),
                                                                                     browse_description);
            }
        }
        zeek::BifEvent::enqueue_opcua_binary_browse_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   browse_req);

        return true;
    %}
    #
    # BrowseResponse and BrowseNextResponse
    #
    function deliver_Svc_BrowseRes(msg: Browse_Res): bool
        %{
        // Debug printf("deliver_Svc_BrowseRes - begin\n");
        // Debug printBrowseRes(msg);
        // Debug printf("deliver_Svc_BrowseRes - end\n");
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);
        
        
        int32_t num_results = msg->results_table_size();

        zeek::RecordValPtr browse_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Browse);

        Msg_Header *msg_header = msg->service()->msg_body()->header();
        const zeek::RecordValPtr conn_val = connection()->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        // Source & Destination
        browse_res = assignSourceDestination(msg_header->is_orig(), browse_res, id_val);

        browse_res->Assign(BROWSE_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));
        // Include if Service is Browse or BrowseNext
        browse_res->Assign(BROWSE_SERVICE_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second));

        if (num_results > 0){
            std::string browse_res_id = generateId();
            browse_res->Assign(BROWSE_RESPONSE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(browse_res_id));
            // Loop through the Reference Description Array
            for (int32_t i=0; i < num_results; i++){
                zeek::RecordValPtr browse_result = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::BrowseResult);

                // Source & Destination
                browse_result = assignSourceDestination(msg_header->is_orig(), browse_result, id_val);

                browse_result->Assign(BROWSE_RESPONSE_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(browse_res_id));

                // Status Code
                uint32_t status_code_level = 0;
                std::string status_code_id = generateId();
                browse_result->Assign(BROWSE_RESPONSE_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(status_code_id));
                generateStatusCodeEvent(connection(), browse_result->GetField(BROWSE_RESPONSE_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_Browse_Key, msg->results()->at(i)->status_code(), status_code_level);

                if (msg->results()->at(i)->continuation_point()->length() > 0){
                    browse_result->Assign(BROWSE_RESPONSE_CONTINUATION_POINT_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->results()->at(i)->continuation_point()->byteString())));
                }

                int32_t num_references = msg->results()->at(i)->num_references();
                if (num_references > 0){
                    std::string browse_reference_id = generateId();
                    browse_result->Assign(BROWSE_RESPONSE_REFERENCE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(browse_reference_id));

                    // References are logged in a separate file for clarity
                    for (int32_t j=0; j < num_references; j++){
                        zeek::RecordValPtr browse_ref = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::BrowseReference);

                        // Source & Destination
                        browse_ref = assignSourceDestination(msg_header->is_orig(), browse_ref, id_val);

                        browse_ref->Assign(BROWSE_RESPONSE_REFERENCE_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(browse_reference_id));

                        flattenOpcUA_NodeId(browse_ref, msg->results()->at(i)->references()->at(j)->ref_type_id(), BROWSE_RESPONSE_REFERENCE_TYPE_ID_ENCODING_MASK_IDX);

                        browse_ref->Assign(BROWSE_RESPONSE_IS_FWD_IDX, zeek::val_mgr->Bool(msg->results()->at(i)->references()->at(j)->is_forward()));

                        flattenOpcUA_ExpandedNodeId(browse_ref, msg->results()->at(i)->references()->at(j)->target_node_id(), BROWSE_RESPONSE_TARGET_ID_ENCODING_MASK_IDX);

                        if (msg->results()->at(i)->references()->at(j)->browse_name()->namespace_index()!= 0){
                            browse_ref->Assign(BROWSE_RESPONSE_BROWSE_NAMESPACE_IDX_IDX, zeek::val_mgr->Count(msg->results()->at(i)->references()->at(j)->browse_name()->namespace_index()));
                        }
                        if (msg->results()->at(i)->references()->at(j)->browse_name()->name()->length() > 0){
                            browse_ref->Assign(BROWSE_RESPONSE_BROWSE_NAME_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->results()->at(i)->references()->at(j)->browse_name()->name()->string())));
                        }

                        browse_ref->Assign(BROWSE_RESPONSE_DISPLAY_NAME_ENCODING_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(msg->results()->at(i)->references()->at(j)->display_name()->encoding_mask())));
                        if (isBitSet(msg->results()->at(i)->references()->at(j)->display_name()->encoding_mask(), localizedTextHasLocale) && msg->results()->at(i)->references()->at(j)->display_name()->locale()->length() > 0) {
                            browse_ref->Assign(BROWSE_RESPONSE_DISPLAY_NAME_LOCALE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->results()->at(i)->references()->at(j)->display_name()->locale()->string())));
                        }
                        
                        if (isBitSet(msg->results()->at(i)->references()->at(j)->display_name()->encoding_mask(), localizedTextHasText) && msg->results()->at(i)->references()->at(j)->display_name()->text()->length() > 0) {
                            browse_ref->Assign(BROWSE_RESPONSE_DISPLAY_NAME_TEXT_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->results()->at(i)->references()->at(j)->display_name()->text()->string())));
                        }

                        if (msg->results()->at(i)->references()->at(j)->node_class() != 0){
                            browse_ref->Assign(BROWSE_RESPONSE_NODE_CLASS_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_CLASSES_MAP.find(msg->results()->at(i)->references()->at(j)->node_class())->second));
                        }
                        
                        flattenOpcUA_ExpandedNodeId(browse_ref, msg->results()->at(i)->references()->at(j)->type_definition(), BROWSE_RESPONSE_TYPE_DEF_ENCODING_MASK_IDX);
                        zeek::BifEvent::enqueue_opcua_binary_browse_reference_event(connection()->bro_analyzer(),
                                                            connection()->bro_analyzer()->Conn(),
                                                            browse_ref);
                    }
                }
                zeek::BifEvent::enqueue_opcua_binary_browse_result_event(connection()->bro_analyzer(),
                                                            connection()->bro_analyzer()->Conn(),
                                                            browse_result);                                 
                
            }
        }
        zeek::BifEvent::enqueue_opcua_binary_browse_event(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    browse_res);


        // Diagnostic Information
        if (msg->diag_info_size() > 0) {
            string diagnostic_info_link_id = generateId(); // Link to tie OCPUA_Binary::BrowseSession and OPCUA_Binary::BrowseDiagnosticInfo together
            string diagnostic_info_id      = generateId(); // Link to tie OCPUA_Binary::BrowseDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together

            // Assign the linkage in the OCPUA_Binary::Browse
            browse_res->Assign(BROWSE_RESPONSE_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_link_id));

            uint32 innerDiagLevel = 0;
            vector<OpcUA_String *>  *stringTable = NULL;
            for (int i = 0; i < msg->diag_info_size(); i++) {
                // Process the details of the Diagnostic Information
                generateDiagInfoEvent(connection(), browse_res->GetField(BROWSE_RESPONSE_DIAG_INFO_LINK_ID_SRC_IDX), msg->diag_info()->at(i), stringTable, innerDiagLevel, StatusCode_Browse_DiagInfo_Key, DiagInfo_Browse_Key);
            }
        }

        return true;

    %}

    #
    # BrowseNextRequest
    #
    function deliver_Svc_BrowseNextReq(msg: Browse_Next_Req): bool
        %{
        // Debug printf("deliver_Svc_BrowseNextReq - begin\n");
        // Debug printBrowseNextReq(msg);
        // Debug printf("deliver_Svc_BrowseNextReq - end\n");

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());
        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);


        int32_t num_continuation_points = msg->num_continuation_points();

        zeek::RecordValPtr browse_next_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Browse);

        Msg_Header *msg_header = msg->service()->msg_body()->header();
        const zeek::RecordValPtr conn_val = connection()->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        // Source & Destination
        browse_next_req = assignSourceDestination(msg_header->is_orig(), browse_next_req, id_val);

        browse_next_req->Assign(BROWSE_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        // Include if Service is Browse or BrowseNext
        browse_next_req->Assign(BROWSE_SERVICE_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second));

        browse_next_req->Assign(BROWSE_NEXT_RELEASE_CONTINUATION_POINTS_IDX, zeek::val_mgr->Bool(msg->release_continuation_points()));

        if (num_continuation_points > 0){
            std::string browse_continuation_points_id = generateId();
            browse_next_req->Assign(BROWSE_NEXT_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(browse_continuation_points_id));
            for (int32_t i=0; i < num_continuation_points; i++){
                zeek::RecordValPtr browse_continuation_point = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::BrowseRequestContinuationPoint);

                // Source & Destination
                browse_continuation_point = assignSourceDestination(msg_header->is_orig(), browse_continuation_point, id_val);

                browse_continuation_point->Assign(BROWSE_NEXT_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(browse_continuation_points_id));
                browse_continuation_point->Assign(BROWSE_CONTINUATION_POINT_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->continuation_points()->at(i)->byteString())));
                zeek::BifEvent::enqueue_opcua_binary_browse_request_continuation_point_event(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    browse_continuation_point);
            }
        }
        zeek::BifEvent::enqueue_opcua_binary_browse_event(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    browse_next_req);
       
        return true;
    %}
};
