## opcua_binary-create_monitored_items_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the create monitored items service.
##
## Author:  Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {
    #
    # CreateMonitoredItemsRequest
    #
    function deliver_Svc_CreateMonitoredItemsReq(msg: Create_Monitored_Items_Req): bool
        %{
            /* Debug 
            printf("deliver_Svc_CreateMonitoredItemsReq - begin\n");
            printCreateMonitoredItemsReq(msg); 
            printf("deliver_Svc_CreateMonitoredItemsReq - end\n");*/

            zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

            info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
            info = assignMsgType(info, msg->service()->msg_body()->header());
            info = assignReqHdr(info, msg->req_hdr());
            info = assignService(info, msg->service());
            zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                    connection()->bro_analyzer()->Conn(),
                                                    info);
            zeek::RecordValPtr create_monitored_items_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateMonitoredItems);
            create_monitored_items_req->Assign(CREATE_MONITORED_ITEMS_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

            create_monitored_items_req->Assign(CREATE_MONITORED_ITEMS_SUBSCRIPTION_ID_IDX, zeek::val_mgr->Count(msg->subscription_id()));
            create_monitored_items_req->Assign(CREATE_MONITORED_ITEMS_TIMESTAMPS_TO_RETURN_IDX, zeek::val_mgr->Count(msg->timestamps_to_return()));
            create_monitored_items_req->Assign(CREATE_MONITORED_ITEMS_TIMESTAMPS_TO_RETURN_STR_IDX, zeek::make_intrusive<zeek::StringVal>(TIMESTAMPS_TO_RETURN_MAP.find(msg->timestamps_to_return())->second));
            int32_t num_items_to_create = msg->num_items_to_create();
            
            if (num_items_to_create > 0){
                std::string monitored_items_id = generateId();
                create_monitored_items_req->Assign(CREATE_MONITORED_ITEMS_MONITORED_ITEM_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(monitored_items_id));
                for (int i=0; i < num_items_to_create; i++){
                    zeek::RecordValPtr monitored_item_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateMonitoredItemsItem);
                    monitored_item_req->Assign(MONITORED_ITEM_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(monitored_items_id));
                    flattenOpcUA_ReadValueId(monitored_item_req, msg->items_to_create()->at(i)->item_to_monitor(), ITEM_TO_MONITOR_NODE_ID_ENCODING_MASK_IDX);
                    switch(msg->items_to_create()->at(i)->monitoring_mode()){
                        case 0:
                            monitored_item_req->Assign(MONITORED_ITEM_MONITORING_MODE_IDX, zeek::make_intrusive<zeek::StringVal>("Disabled"));
                            break;
                        case 1:
                            monitored_item_req->Assign(MONITORED_ITEM_MONITORING_MODE_IDX, zeek::make_intrusive<zeek::StringVal>("Sampling"));
                            break;
                        case 2:
                            monitored_item_req->Assign(MONITORED_ITEM_MONITORING_MODE_IDX, zeek::make_intrusive<zeek::StringVal>("Reporting"));
                            break;
                    }
                    monitored_item_req->Assign(MONITORING_PARAMETERS_CLIENT_HANDLE_IDX, zeek::val_mgr->Count(msg->items_to_create()->at(i)->requested_parameters()->client_handle()));
                    monitored_item_req->Assign(MONITORING_PARAMETERS_SAMPLING_INTERVAL_IDX, zeek::make_intrusive<zeek::DoubleVal>(bytestringToDouble((msg->items_to_create()->at(i)->requested_parameters()->sampling_interval()->duration()))));                
                    monitored_item_req->Assign(MONITORING_PARAMETERS_QUEUE_SIZE_IDX, zeek::val_mgr->Count(msg->items_to_create()->at(i)->requested_parameters()->queue_size()));
                    monitored_item_req->Assign(MONITORING_PARAMETERS_DISCARD_OLDEST_IDX, zeek::val_mgr->Bool(msg->items_to_create()->at(i)->requested_parameters()->discard_oldest()));
                    if (getExtensionObjectId(msg->items_to_create()->at(i)->requested_parameters()->filter()->type_id()) != NoneType_Key){
                        std::string filter_id = generateId();
                        monitored_item_req->Assign(MONITORING_PARAMETERS_FILTER_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(filter_id));\
                        flattenOpcUA_ExtensionObject(monitored_item_req, msg->items_to_create()->at(i)->requested_parameters()->filter(), MONITORING_PARAMETERS_FILTER_INFO_EXT_OBJ_TYPE_ID_ENCODING_MASK_IDX, filter_id, connection());
                    }
                   
                    zeek::BifEvent::enqueue_opcua_binary_create_monitored_items_create_item_event(connection()->bro_analyzer(),
                                                                                                  connection()->bro_analyzer()->Conn(),
                                                                                                  monitored_item_req);
                }
            }

            zeek::BifEvent::enqueue_opcua_binary_create_monitored_items_event(connection()->bro_analyzer(),
                                                                              connection()->bro_analyzer()->Conn(),
                                                                              create_monitored_items_req);

            return true;
        %}
    #
    # CreateMonitoredItemsResponse
    #
    function deliver_Svc_CreateMonitoredItemsRes(msg: Create_Monitored_Items_Res): bool
        %{
            /* Debug 
            printf("deliver_Svc_CreateMonitoredItemsRes - begin\n");
            printCreateMonitoredItemsRes(msg); 
            printf("deliver_Svc_CreateMonitoredItemsRes - end\n");*/

            zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

            info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
            info = assignMsgType(info, msg->service()->msg_body()->header());
            info = assignResHdr(connection(), info, msg->res_hdr());
            info = assignService(info, msg->service());

            zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                       connection()->bro_analyzer()->Conn(),
                                                       info);

            zeek::RecordValPtr create_monitored_items_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateMonitoredItems);
            int32_t num_results = msg->num_results();  
            if (num_results > 0){
                std::string monitored_items_id = generateId();
                create_monitored_items_res->Assign(CREATE_MONITORED_ITEMS_MONITORED_ITEM_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(monitored_items_id));
                for (int i=0; i < num_results; i++){
                    zeek::RecordValPtr monitored_item_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateMonitoredItemsItem);
                    monitored_item_res->Assign(MONITORED_ITEM_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(monitored_items_id));
                    uint32_t status_code_level = 0;
                    std::string status_code_id = generateId();
                    // create_monitored_items_res->Assign(MONITORED_ITEM_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(status_code_id));
                    generateStatusCodeEvent(connection(),  monitored_item_res->GetField(MONITORED_ITEM_LINK_ID_DST_IDX), StatusCode_CreateMonitoredItems_Key, msg->results()->at(i)->status_code(), status_code_level);
                    monitored_item_res->Assign(MONTORED_ITEM_INDEX_ID_IDX, zeek::val_mgr->Count(msg->results()->at(i)->monitored_item_id()));
                    monitored_item_res->Assign(MONITORING_PARAMETERS_REVISED_SAMPLING_INTERVAL_IDX, zeek::make_intrusive<zeek::DoubleVal>(bytestringToDouble((msg->results()->at(i)->revised_sampling_interval()->duration()))));                
                    monitored_item_res->Assign(MONITORING_PARAMETERS_REVISED_QUEUE_SIZE_IDX, zeek::val_mgr->Count(msg->results()->at(i)->revised_queue_size()));
                    if (getExtensionObjectId(msg->results()->at(i)->filter_result()->type_id()) != NoneType_Key){
                        std::string filter_id = generateId();
                        monitored_item_res->Assign(MONITORING_PARAMETERS_FILTER_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(filter_id)); 
                        flattenOpcUA_ExtensionObject(monitored_item_res, msg->results()->at(i)->filter_result(), MONITORING_PARAMETERS_FILTER_INFO_EXT_OBJ_TYPE_ID_ENCODING_MASK_IDX, filter_id, connection());
                    }
                    zeek::BifEvent::enqueue_opcua_binary_create_monitored_items_create_item_event(connection()->bro_analyzer(),
                                                                                                  connection()->bro_analyzer()->Conn(),
                                                                                                  monitored_item_res);
                }
            }
            if (msg->diag_info_size() > 0) {
                string diagnostic_info_link_id = generateId(); // Link to tie OCPUA_Binary::CreateMonitoredItems and OPCUA_Binary::CreateMonitoredItemsDiagnosticInfo together

                // Assign the linkage in the OCPUA_Binary::CreateMonitoredItems
                create_monitored_items_res->Assign(CREATE_MONITORED_ITEMS_RESPONSE_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_link_id));

                uint32 innerDiagLevel = 0;
                vector<OpcUA_String *>  *stringTable = NULL;
                for (int i = 0; i < msg->diag_info_size(); i++) {
                    // Process the details of the Diagnostic Information
                    generateDiagInfoEvent(connection(), create_monitored_items_res->GetField(CREATE_MONITORED_ITEMS_RESPONSE_DIAG_INFO_LINK_ID_SRC_IDX), msg->diag_info()->at(i), stringTable, innerDiagLevel, StatusCode_FilterOperand_DiagInfo_Key, DiagInfo_FilterOperand_Key);

                }
            }
            zeek::BifEvent::enqueue_opcua_binary_create_monitored_items_event(connection()->bro_analyzer(),
                                                                              connection()->bro_analyzer()->Conn(),
                                                                              create_monitored_items_res);

            return true;       
        %}
}