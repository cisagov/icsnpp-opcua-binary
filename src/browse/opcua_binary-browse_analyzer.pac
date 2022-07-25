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

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());
        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        int32_t num_nodes_to_browse = (msg->num_nodes_to_browse());

        // Flatten each browse request
        for (int32_t i=0; i < num_nodes_to_browse; i++) {
            zeek::RecordValPtr browse_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Browse);

            // OpcUA_id
            browse_req->Assign(BROWSE_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_ID_IDX));

            // Include if Service is Browse or BrowseNext
            browse_req->Assign(BROWSE_SERVICE_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second));

            // View Description Flattening

            flattenNodeId(browse_req, msg->view_description()->view_id(), BROWSE_VIEW_ID_ENCODING_MASK_IDX);

            
            browse_req->Assign(BROWSE_VIEW_DESCRIPTION_TIMESTAMP_IDX, zeek::val_mgr->Count(msg->view_description()->timestamp()));
            

            browse_req->Assign(BROWSE_VIEW_DESCRIPTION_VIEW_VERSION_IDX, zeek::val_mgr->Count(msg->view_description()->view_version()));

            browse_req->Assign(BROWSE_REQ_MAX_REFS_IDX, zeek::val_mgr->Count(msg->req_max_refs_per_node()));

            flattenNodeId(browse_req, msg->nodes_to_browse()->at(i)->node_id(), BROWSE_DESCRIPTION_ID_ENCODING_MASK_IDX);


            if ((msg->nodes_to_browse()->at(i)->browse_direction_id()) == 0){
                browse_req->Assign(BROWSE_DIRECTION_ID_IDX, zeek::make_intrusive<zeek::StringVal>("FWD"));
            } else if ((msg->nodes_to_browse()->at(i)->browse_direction_id()) == 1){
                browse_req->Assign(BROWSE_DIRECTION_ID_IDX, zeek::make_intrusive<zeek::StringVal>("INVERSE"));
            } else if ((msg->nodes_to_browse()->at(i)->browse_direction_id()) == 2){
                browse_req->Assign(BROWSE_DIRECTION_ID_IDX, zeek::make_intrusive<zeek::StringVal>("BOTH"));
            }

            flattenNodeId(browse_req, msg->nodes_to_browse()->at(i)->ref_type_id(), BROWSE_DESCRIPTION_ID_ENCODING_MASK_IDX);

            browse_req->Assign(BROWSE_DESCRIPTION_INCLUDE_SUBTYPES_IDX, zeek::val_mgr->Bool(msg->nodes_to_browse()->at(i)->include_subtypes()));
            
            browse_req->Assign(BROWSE_DESCRIPTION_NODE_CLASS_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_CLASSES_MAP.find(msg->nodes_to_browse()->at(i)->node_class_mask())->second));
            
            browse_req->Assign(BROWSE_DESCRIPTION_RESULT_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(uint32ToHexstring(msg->nodes_to_browse()->at(i)->result_mask())));

            zeek::BifEvent::enqueue_opcua_binary_browse_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   browse_req);

        }

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

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);
        
        
        int32_t num_results = msg->results_table_size();

        // Loop through the Reference Description Array
        for (int32_t i=0; i < num_results; i++){
            zeek::RecordValPtr browse_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Browse);

            browse_res->Assign(BROWSE_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_ID_IDX));

            // Include if Service is Browse or BrowseNext
            browse_res->Assign(BROWSE_SERVICE_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second));

            if (msg->results()->at(i)->status_code() == 0){
                 browse_res->Assign(BROWSE_RESPONSE_STATUS_CODE_IDX, zeek::make_intrusive<zeek::StringVal>("Good"));
            } else {
                browse_res->Assign(BROWSE_RESPONSE_STATUS_CODE_IDX, zeek::make_intrusive<zeek::StringVal>(STATUS_CODE_MAP.find(msg->results()->at(i)->status_code())->second));
            }

            if (msg->results()->at(i)->continuation_point()->length() > 0){
                browse_res->Assign(BROWSE_RESPONSE_CONTINUATION_POINT_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->results()->at(i)->continuation_point()->byteString())));
            }

            int32_t num_references = msg->results()->at(i)->num_references();
            if (num_references <= 0){
                browse_res->Assign(BROWSE_RESPONSE_NUM_REFERENCES_IDX, zeek::val_mgr->Count(0));
            } else {
                browse_res->Assign(BROWSE_RESPONSE_NUM_REFERENCES_IDX, zeek::val_mgr->Count(num_references));
            }

            zeek::BifEvent::enqueue_opcua_binary_browse_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   browse_res);
                                        
            // References are logged in a separate file for clarity
            for (int32_t j=0; j < num_references; j++){
                zeek::RecordValPtr browse_ref = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::BrowseReference);

                browse_ref->Assign(BROWSE_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_ID_IDX));

                flattenNodeId(browse_ref, msg->results()->at(i)->references()->at(j)->ref_type_id(), BROWSE_RESPONSE_REFERENCE_TYPE_ID_ENCODING_MASK_IDX);

                browse_ref->Assign(BROWSE_RESPONSE_IS_FWD_IDX, zeek::val_mgr->Bool(msg->results()->at(i)->references()->at(j)->is_forward()));

                flattenExpandedNodeId(browse_ref, msg->results()->at(i)->references()->at(j)->target_node_id(), BROWSE_RESPONSE_TARGET_ID_ENCODING_MASK_IDX);

                if (msg->results()->at(i)->references()->at(j)->browse_name()->namespace_index()!= 0){
                    browse_ref->Assign(BROWSE_RESPONSE_BROWSE_NAMESPACE_IDX_IDX, zeek::val_mgr->Count(msg->results()->at(i)->references()->at(j)->browse_name()->namespace_index()));
                    browse_ref->Assign(BROWSE_RESPONSE_BROWSE_NAME_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->results()->at(i)->references()->at(j)->browse_name()->name()->string())));
                }

                browse_ref->Assign(BROWSE_RESPONSE_DISPLAY_NAME_ENCODING_IDX, zeek::val_mgr->Count(msg->results()->at(i)->references()->at(j)->display_name()->encoding_mask()));
                if (isBitSet(msg->results()->at(i)->references()->at(j)->display_name()->encoding_mask(), localizedTextHasLocale) && msg->results()->at(i)->references()->at(j)->display_name()->locale()->length() > 0) {
                    browse_ref->Assign(BROWSE_RESPONSE_DISPLAY_NAME_LOCALE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->results()->at(i)->references()->at(j)->display_name()->locale()->string())));
                }
                
                if (isBitSet(msg->results()->at(i)->references()->at(j)->display_name()->encoding_mask(), localizedTextHasText) && msg->results()->at(i)->references()->at(j)->display_name()->text()->length() > 0) {
                    browse_ref->Assign(BROWSE_RESPONSE_DISPLAY_NAME_TEXT_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->results()->at(i)->references()->at(j)->display_name()->text()->string())));
                }

                if (msg->results()->at(i)->references()->at(j)->node_class() != 0){
                    browse_ref->Assign(BROWSE_RESPONSE_NODE_CLASS_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_CLASSES_MAP.find(msg->results()->at(i)->references()->at(j)->node_class())->second));
                }
                
                flattenExpandedNodeId(browse_ref, msg->results()->at(i)->references()->at(j)->type_definition(), BROWSE_RESPONSE_TYPE_DEF_ENCODING_MASK_IDX);
                zeek::BifEvent::enqueue_opcua_binary_browse_reference_event(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    browse_ref);
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

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());
        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);


        int32_t num_continuation_points = msg->num_continuation_points();

        for (int32_t i=0; i < num_continuation_points; i++){
            zeek::RecordValPtr browse_next_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Browse);

            browse_next_req->Assign(BROWSE_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_ID_IDX));
            
            // Include if Service is Browse or BrowseNext
            browse_next_req->Assign(BROWSE_SERVICE_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second));

            browse_next_req->Assign(BROWSE_NEXT_RELEASE_CONTINUATION_POINTS_IDX, zeek::val_mgr->Bool(msg->release_continuation_points()));
            browse_next_req->Assign(BROWSE_NEXT_CONTINUATION_POINT_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->continuation_points()->at(i)->byteString())));
            zeek::BifEvent::enqueue_opcua_binary_browse_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                    browse_next_req);
        }
       
        return true;
    %}
};
