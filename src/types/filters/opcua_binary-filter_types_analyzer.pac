## opcua_binary-filter_types_ananlyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer utilitiy functions for the binary filter types.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void flattenOpcUA_DataChangeFilter(OpcUA_DataChangeFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_EventFilter(OpcUA_EventFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_EventFilterResult(OpcUA_EventFilterResult *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_AggregateFilter(OpcUA_AggregateFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_AggregateFilterResult(OpcUA_AggregateFilterResult *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection);
    void flattenOpcUA_ContentFilterElement(OpcUA_ContentFilterElement *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_ContentFilterElementResult(OpcUA_ContentFilterElementResult *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_ContentFilter(OpcUA_ContentFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_ContentFilterResult(OpcUA_ContentFilterResult *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_SimpleAttributeOperand(OpcUA_SimpleAttributeOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_AttributeOperand(OpcUA_AttributeOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_ElementOperand(OpcUA_ElementOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_LiteralOperand(OpcUA_LiteralOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
%}
%code{
    void flattenOpcUA_SimpleAttributeOperand_Internal(OpcUA_SimpleAttributeOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_operand, bool is_orig){
        /* Since a Select Clause is a Simmple Attribute Operand, they can share the same analyzer. 
        However, a select clause record may have a result while a Simple Attribute Operand does not. 
        Therefore, there is a separate SelectClause type.*/
        zeek::RecordValPtr simple_attribute_operand;
        if (is_operand){
            simple_attribute_operand = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::SimpleAttributeOperand);
        }
        else {
            simple_attribute_operand = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::SelectClause);
        }

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        simple_attribute_operand = assignSourceDestination(is_orig, simple_attribute_operand, id_val);

        simple_attribute_operand->Assign(SIMPLE_ATTRIBUTE_OPERAND_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        flattenOpcUA_NodeId(simple_attribute_operand, obj->type_id(), SIMPLE_ATTRIBUTE_OPERAND_TYPE_ID_ENCODING_MASK_IDX);
        int32_t num_browse_paths = obj->num_browse_paths();
        if (num_browse_paths > 0){
            std::string browse_path_id = generateId();
            simple_attribute_operand->Assign(SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(browse_path_id));
            for (int i=0; i < num_browse_paths; i++){
                zeek::RecordValPtr simple_attribute_operand_browse_path = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::SimpleAttributeOperandBrowsePaths);

                // Source & Destination
                const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
                const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

                simple_attribute_operand_browse_path = assignSourceDestination(is_orig, simple_attribute_operand_browse_path, id_val);

                simple_attribute_operand_browse_path->Assign(SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(browse_path_id));
                simple_attribute_operand_browse_path->Assign(SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_NAMSESPACE_IDX_IDX, zeek::val_mgr->Count(obj->browse_paths()->at(i)->namespace_index()));
                if (is_operand){
                    simple_attribute_operand_browse_path->Assign(SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_SRC_LINK_ID_IDX, zeek::make_intrusive<zeek::StringVal>("SimpleAttributeOperand"));
                }
                else {
                    simple_attribute_operand_browse_path->Assign(SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_SRC_LINK_ID_IDX, zeek::make_intrusive<zeek::StringVal>("SelectClause"));
                }
                if (obj->browse_paths()->at(i)->name()->length() > 0){
                     simple_attribute_operand_browse_path->Assign(SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_NAME_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(obj->browse_paths()->at(i)->name()->string())));
                }
                zeek::BifEvent::enqueue_opcua_binary_event_filter_simple_attribute_operand_browse_path_event(connection->bro_analyzer(),
                                                                                                             connection->bro_analyzer()->Conn(),
                                                                                                             simple_attribute_operand_browse_path);
            }
        }
        simple_attribute_operand->Assign(SIMPLE_ATTRIBUTE_OPERAND_ATTRIBUTE_ID_IDX, zeek::make_intrusive<zeek::StringVal>(ATTRIBUTE_ID_MAP.find(obj->attribute_id())->second));
        if (obj->index_range()->length() > 0){
            simple_attribute_operand->Assign(SIMPLE_ATTRIBUTE_INDEX_RANGE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(obj->index_range()->string())));
        }
        if (is_operand){
            zeek::BifEvent::enqueue_opcua_binary_event_filter_simple_attribute_operand_event(connection->bro_analyzer(),
                                                                                             connection->bro_analyzer()->Conn(),
                                                                                             simple_attribute_operand);
        }
        else {
            zeek::BifEvent::enqueue_opcua_binary_event_filter_select_clause_event(connection->bro_analyzer(),
                                                                                   connection->bro_analyzer()->Conn(),
                                                                                   simple_attribute_operand);
        }
    }
    void flattenOpcUA_DataChangeFilter(OpcUA_DataChangeFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        zeek::RecordValPtr data_change_filter_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::DataChangeFilter);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        data_change_filter_details = assignSourceDestination(is_orig, data_change_filter_details, id_val);

        data_change_filter_details->Assign(DATA_CHANGE_FILTER_REQ_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        data_change_filter_details->Assign(DATA_CHANGE_FILTER_REQ_TRIGGER_IDX, zeek::make_intrusive<zeek::StringVal>(DATA_CHANGE_TRIGGER_MAP.find(obj->trigger())->second));
        data_change_filter_details->Assign(DATA_CHANGE_FILTER_REQ_DEADBAND_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(DEADBAND_TYPE_MAP.find(obj->deadband_type())->second));
        data_change_filter_details->Assign(DATA_CHANGE_FILTER_REQ_DEADBAND_VALUE, zeek::make_intrusive<zeek::DoubleVal>(bytestringToDouble(obj->deadband_value())));
        zeek::BifEvent::enqueue_opcua_binary_data_change_filter_event(connection->bro_analyzer(),
                                                                      connection->bro_analyzer()->Conn(),
                                                                      data_change_filter_details);
    }
    void flattenOpcUA_EventFilter(OpcUA_EventFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        zeek::RecordValPtr event_filter_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::EventFilter);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        event_filter_details = assignSourceDestination(is_orig, event_filter_details, id_val);

        event_filter_details->Assign(EVENT_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        int32_t num_select_clauses = obj->num_select_clauses();
        if (num_select_clauses > 0){
            std::string select_clauses_id = generateId();
            event_filter_details->Assign(EVENT_FILTER_SELECT_CLAUSES_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(select_clauses_id));
            for (int i=0; i < num_select_clauses; i++){
                flattenOpcUA_SimpleAttributeOperand_Internal(obj->select_clauses()->at(i), select_clauses_id, connection, false, is_orig);
            }
        }
        std::string where_clause_id = generateId();
        event_filter_details->Assign(EVENT_FILTER_CONTENT_FILTER_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(where_clause_id));
        flattenOpcUA_ContentFilter(obj->where_clause(), where_clause_id, connection, is_orig);
        zeek::BifEvent::enqueue_opcua_binary_event_filter_event(connection->bro_analyzer(),
                                                                connection->bro_analyzer()->Conn(),
                                                                event_filter_details);

    }
    void flattenOpcUA_EventFilterResult(OpcUA_EventFilterResult *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        zeek::RecordValPtr event_filter_result_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::EventFilter);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        event_filter_result_details = assignSourceDestination(is_orig, event_filter_result_details, id_val);

        event_filter_result_details->Assign(EVENT_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        int32_t num_select_clause_results = obj->num_select_clause_results();
        zeek::RecordValPtr select_clause_result = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::SelectClause);

        select_clause_result = assignSourceDestination(is_orig, select_clause_result, id_val);

        std::string select_clauses_results_id = generateId();

        event_filter_result_details->Assign(EVENT_FILTER_SELECT_CLAUSES_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(select_clauses_results_id));
        select_clause_result->Assign(SELECT_CLAUSE_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(select_clauses_results_id));

        if (num_select_clause_results > 0){
            std::string select_clauses_status_code_link_id = generateId();
            uint32_t status_code_level = 0;
            for (int i=0; i < num_select_clause_results; i++){
                select_clause_result->Assign(SELECT_CLAUSE_RESULT_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(select_clauses_status_code_link_id));
                generateStatusCodeEvent(connection, select_clause_result->GetField(SELECT_CLAUSE_RESULT_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_SelectClause_Key, obj->select_clause_results()->at(i), status_code_level, is_orig);
            }
        }
        int32_t num_select_clause_diagnostic_infos = obj->num_select_clause_diag_infos();
        if (num_select_clause_diagnostic_infos > 0){
            string diagnostic_info_link_id = generateId(); // Link to tie OCPUA_Binary::SelectClause and OPCUA_Binary::DiagnosticInfoDetail together
            
            // Assign the linkage in the OCPUA_Binary::CreateMonitoredItems
            select_clause_result->Assign(SELECT_CLAUSE_RESULT_DIAGNOSTIC_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_link_id));

            uint32 innerDiagLevel = 0;
            vector<OpcUA_String *>  *stringTable = NULL;
            for (int i = 0; i < obj->num_select_clause_diag_infos(); i++) {
                // Process the details of the Diagnostic Information
                generateDiagInfoEvent(connection, select_clause_result->GetField(SELECT_CLAUSE_RESULT_DIAGNOSTIC_INFO_LINK_ID_SRC_IDX), obj->select_clause_diag_infos()->at(i), stringTable, innerDiagLevel, StatusCode_SelectClause_Key, is_orig, DiagInfo_SelectClause_Key);
            }
        }
        zeek::BifEvent::enqueue_opcua_binary_event_filter_select_clause_event(connection->bro_analyzer(),
                                                                              connection->bro_analyzer()->Conn(),
                                                                              select_clause_result);
        std::string where_clause_results_id = generateId();
        event_filter_result_details->Assign(EVENT_FILTER_CONTENT_FILTER_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(where_clause_results_id));
        flattenOpcUA_ContentFilterResult(obj->where_clause_result(), where_clause_results_id, connection, is_orig);
        zeek::BifEvent::enqueue_opcua_binary_event_filter_event(connection->bro_analyzer(),
                                                                connection->bro_analyzer()->Conn(),
                                                                event_filter_result_details);
    }
    void flattenOpcUA_AggregateFilter(OpcUA_AggregateFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        zeek::RecordValPtr aggregate_filter_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::AggregateFilter);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        aggregate_filter_details = assignSourceDestination(is_orig, aggregate_filter_details, id_val);

        aggregate_filter_details->Assign(AGGREGATE_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        aggregate_filter_details->Assign(AGGREGATE_FILTER_START_TIME_IDX, zeek::make_intrusive<zeek::TimeVal>(obj->start_time()));
        if (obj->start_time() != 0){
            double unix_timestamp = winFiletimeToUnixTime(obj->start_time());
            aggregate_filter_details->Assign(AGGREGATE_FILTER_START_TIME_STR_IDX, zeek::make_intrusive<zeek::StringVal>(unixTimestampToString(unix_timestamp)));
        }
        flattenOpcUA_NodeId(aggregate_filter_details, obj->aggregate_type(), AGGREGATE_FILTER_AGGREGATE_TYPE_ID_ENCODING_MASK_IDX);
        aggregate_filter_details->Assign(AGGREGATE_FILTER_PROCESSING_INTERVAL_IDX, zeek::make_intrusive<zeek::DoubleVal>(bytestringToDouble(obj->processing_interval()->duration())));
        aggregate_filter_details->Assign(AGGREGATE_FILTER_CONFIGURATION_USE_SERVER_CAPABILITES_DEFAULT_IDX, zeek::val_mgr->Bool(obj->aggregate_configuration()->use_server_capabilities_default()));
        aggregate_filter_details->Assign(AGGREGATE_FILTER_CONFIGURATION_TREAT_UNCERTAIN_AS_BAD_IDX, zeek::val_mgr->Bool(obj->aggregate_configuration()->treat_uncertain_as_bad()));
        aggregate_filter_details->Assign(AGGREGATE_FILTER_CONFIGURATION_PERCENT_DATA_GOOD_IDX, zeek::val_mgr->Count(obj->aggregate_configuration()->percent_data_good()));
        aggregate_filter_details->Assign(AGGREGATE_FILTER_CONFIGURATION_PERCENT_DATA_BAD_IDX, zeek::val_mgr->Count(obj->aggregate_configuration()->percent_data_bad()));
        aggregate_filter_details->Assign(AGGREGATE_FILTER_CONFIGURATION_USE_SLOPED_EXTRAPOLATION_IDX, zeek::val_mgr->Bool(obj->aggregate_configuration()->use_sloped_extrapolation()));
        zeek::BifEvent::enqueue_opcua_binary_aggregate_filter_event(connection->bro_analyzer(),
                                                                    connection->bro_analyzer()->Conn(),
                                                                    aggregate_filter_details);
    }
    void flattenOpcUA_AggregateFilterResult(OpcUA_AggregateFilterResult *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection){
        zeek::RecordValPtr aggregate_filter_result_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::AggregateFilter);
        aggregate_filter_result_details->Assign(AGGREGATE_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        aggregate_filter_result_details->Assign(AGGREGATE_FILTER_REVISED_START_TIME_IDX, zeek::make_intrusive<zeek::TimeVal>(obj->revised_start_time()));
        if (obj->revised_start_time() != 0){
            double unix_timestamp = winFiletimeToUnixTime(obj->revised_start_time());
            aggregate_filter_result_details->Assign(AGGREGATE_FILTER_REVISED_START_TIME_STR_IDX, zeek::make_intrusive<zeek::StringVal>(unixTimestampToString(unix_timestamp)));
        }
        aggregate_filter_result_details->Assign(AGGREGATE_FILTER_REVISED_PROCESSING_INTERVAL_IDX, zeek::make_intrusive<zeek::DoubleVal>(bytestringToDouble(obj->revised_processing_interval()->duration())));
        aggregate_filter_result_details->Assign(AGGREGATE_FILTER_REVISED_CONFIGURATION_USE_SERVER_CAPABILITES_DEFAULT_IDX, zeek::val_mgr->Bool(obj->revised_aggregate_configuration()->use_server_capabilities_default()));
        aggregate_filter_result_details->Assign(AGGREGATE_FILTER_REVISED_CONFIGURATION_TREAT_UNCERTAIN_AS_BAD_IDX, zeek::val_mgr->Bool(obj->revised_aggregate_configuration()->treat_uncertain_as_bad()));
        aggregate_filter_result_details->Assign(AGGREGATE_FILTER_REVISED_CONFIGURATION_PERCENT_DATA_GOOD_IDX, zeek::val_mgr->Count(obj->revised_aggregate_configuration()->percent_data_good()));
        aggregate_filter_result_details->Assign(AGGREGATE_FILTER_REVISED_CONFIGURATION_PERCENT_DATA_BAD_IDX, zeek::val_mgr->Count(obj->revised_aggregate_configuration()->percent_data_bad()));
        aggregate_filter_result_details->Assign(AGGREGATE_FILTER_REVISED_CONFIGURATION_USE_SLOPED_EXTRAPOLATION_IDX, zeek::val_mgr->Bool(obj->revised_aggregate_configuration()->use_sloped_extrapolation()));
        zeek::BifEvent::enqueue_opcua_binary_aggregate_filter_event(connection->bro_analyzer(),
                                                                    connection->bro_analyzer()->Conn(),
                                                                    aggregate_filter_result_details);
    }
    void flattenOpcUA_ContentFilter(OpcUA_ContentFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        zeek::RecordValPtr content_filter_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ContentFilter);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        content_filter_details = assignSourceDestination(is_orig, content_filter_details, id_val);

        content_filter_details->Assign(EVENT_FILTER_CONTENT_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        int32_t num_elements = obj->num_elements();
        if (num_elements > 0){
            std::string content_filter_element_id = generateId();
            content_filter_details->Assign(CONTENT_FILTER_ELEMENT_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(content_filter_element_id));
            for (int i=0; i < num_elements; i++){
                flattenOpcUA_ContentFilterElement(obj->elements()->at(i), content_filter_element_id, connection, is_orig);
            }
        }
        zeek::BifEvent::enqueue_opcua_binary_event_filter_content_filter_event(connection->bro_analyzer(),
                                                                               connection->bro_analyzer()->Conn(),
                                                                               content_filter_details);
    }
    void flattenOpcUA_ContentFilterResult(OpcUA_ContentFilterResult *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        zeek::RecordValPtr content_filter_result_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ContentFilter);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        content_filter_result_details = assignSourceDestination(is_orig, content_filter_result_details, id_val);

        content_filter_result_details->Assign(EVENT_FILTER_CONTENT_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        int32_t num_element_results = obj->num_element_results();
        if (num_element_results > 0){
            std::string element_results_id = generateId();
            std::string status_code_id = generateId();
            uint32_t status_code_level = 1;
            content_filter_result_details->Assign(CONTENT_FILTER_ELEMENT_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(element_results_id));
            content_filter_result_details->Assign(CONTENT_FILTER_RESULT_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(status_code_id));
            for (int i=0; i < num_element_results; i++){
                generateStatusCodeEvent(connection, content_filter_result_details->GetField(CONTENT_FILTER_RESULT_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_ContentFilterElement_Key, obj->elements_results()->at(i)->status_code(), status_code_level, is_orig);
                flattenOpcUA_ContentFilterElementResult(obj->elements_results()->at(i), element_results_id, connection, is_orig);
            }
        }
        
        int32_t num_element_diagnostic_infos = obj->num_element_diag_infos();
        if (num_element_diagnostic_infos > 0){
            string diagnostic_info_link_id = generateId(); // Link to tie OCPUA_Binary::ContentFilter and OPCUA_Binary::ContentFilterElementDiagnosticInfo together
            string diagnostic_info_id      = generateId(); // Link to tie OCPUA_Binary::ContentFilterElementDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together

            // Assign the linkage in the OCPUA_Binary::CreateMonitoredItems
            content_filter_result_details->Assign(CONTENT_FILTER_RESULT_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_link_id));

            uint32 innerDiagLevel = 0;
            vector<OpcUA_String *>  *stringTable = NULL;
            for (int i = 0; i < obj->num_element_diag_infos(); i++) {
                // Process the details of the Diagnostic Information
                generateDiagInfoEvent(connection, content_filter_result_details->GetField(CONTENT_FILTER_RESULT_DIAG_INFO_LINK_ID_SRC_IDX), obj->element_diag_infos()->at(i), stringTable, innerDiagLevel, StatusCode_ContentFilterElement_DiagInfo_Key, is_orig, DiagInfo_ContentFilterElement_Key);
            }
        }
        zeek::BifEvent::enqueue_opcua_binary_event_filter_content_filter_event(connection->bro_analyzer(),
                                                                               connection->bro_analyzer()->Conn(),
                                                                               content_filter_result_details);
    }
    void flattenOpcUA_ContentFilterElement(OpcUA_ContentFilterElement *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        int32_t num_filter_operands = obj->num_filter_operands();
        if (num_filter_operands > 0){
            for (int i=0; i < num_filter_operands; i++){
                zeek::RecordValPtr content_filter_element_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ContentFilterElement);

                // Source & Destination
                const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
                const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

                content_filter_element_details = assignSourceDestination(is_orig, content_filter_element_details, id_val);

                content_filter_element_details->Assign(CONTENT_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
                content_filter_element_details->Assign(CONTENT_FILTER_FILTER_OPERATOR_IDX, zeek::make_intrusive<zeek::StringVal>(FILTER_OPERATORS_MAP.find(obj->filter_operator())->second));
                std::string filter_operand_id = generateId();
                content_filter_element_details->Assign(CONTENT_FILTER_FILTER_OPERANDS_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(filter_operand_id));
                flattenOpcUA_ExtensionObject(content_filter_element_details, obj->filter_operands()->at(i), CONTENT_FILTER_FILTER_OPERAND_EXT_OBJ_TYPE_ID_ENCODING_MASK_IDX, filter_operand_id, connection, is_orig);
                zeek::BifEvent::enqueue_opcua_binary_event_filter_content_filter_element_event(connection->bro_analyzer(),
                                                                                               connection->bro_analyzer()->Conn(),
                                                                                               content_filter_element_details);
            }
        }
    }
    void flattenOpcUA_ContentFilterElementResult(OpcUA_ContentFilterElementResult *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        std::string element_status_code_id = generateId();
        uint32_t status_code_level = 0;
        zeek::RecordValPtr content_filter_element_result_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ContentFilterElement);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        content_filter_element_result_details = assignSourceDestination(is_orig, content_filter_element_result_details, id_val);

        content_filter_element_result_details->Assign(CONTENT_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        int32_t num_operand_status_codes = obj->num_operand_status_codes();
        if (num_operand_status_codes > 0){
            std::string operand_status_codes_id = generateId();
            content_filter_element_result_details->Assign(OPERAND_RESULT_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(operand_status_codes_id));
            for (int i=0; i < num_operand_status_codes; i++){
                generateStatusCodeEvent(connection, content_filter_element_result_details->GetField(OPERAND_RESULT_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_FilterOperand_Key, obj->operand_status_codes()->at(i), status_code_level, is_orig);
            }
        }
        int32_t num_operand_diag_infos = obj->num_operand_diag_infos();
        if (num_operand_diag_infos > 0){
            string diagnostic_info_link_id = generateId(); // Link to tie OCPUA_Binary::ContentFilterElement and OPCUA_Binary::OperandDiagnosticInfo together
            string diagnostic_info_id      = generateId(); // Link to tie OCPUA_Binary::OperandDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together

            // Assign the linkage in the OCPUA_Binary::CreateMonitoredItems
            content_filter_element_result_details->Assign(OPERAND_RESULT_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_link_id));

            uint32 innerDiagLevel = 0;
            vector<OpcUA_String *>  *stringTable = NULL;
            for (int i = 0; i < obj->num_operand_diag_infos(); i++) {
                // Process the details of the Diagnostic Information
                generateDiagInfoEvent(connection, content_filter_element_result_details->GetField(OPERAND_RESULT_DIAG_INFO_LINK_ID_SRC_IDX), obj->operand_diag_infos()->at(i), stringTable, innerDiagLevel, StatusCode_FilterOperand_DiagInfo_Key, is_orig, DiagInfo_FilterOperand_Key);
            }
        }
        zeek::BifEvent::enqueue_opcua_binary_event_filter_content_filter_element_event(connection->bro_analyzer(),
                                                                                       connection->bro_analyzer()->Conn(),
                                                                                       content_filter_element_result_details);
    }
    void flattenOpcUA_SimpleAttributeOperand(OpcUA_SimpleAttributeOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        flattenOpcUA_SimpleAttributeOperand_Internal(obj, link_id, connection, true, is_orig);
    }
    void flattenOpcUA_AttributeOperand(OpcUA_AttributeOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        zeek::RecordValPtr attribute_operand_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::AttributeOperand);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        attribute_operand_details = assignSourceDestination(is_orig, attribute_operand_details, id_val);

        attribute_operand_details->Assign(ATTRIBUTE_OPERAND_LINK_ID_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        flattenOpcUA_NodeId(attribute_operand_details, obj->node_id(), ATTRIBUTE_OPERAND_NODE_ID_ENCODING_MASK_IDX);
        if (obj->alias()->length() > 0){
            attribute_operand_details->Assign(ATTRIBUTE_OPERAND_ALIAS_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(obj->alias()->string())));
        }
        int32_t num_relative_path_elements = obj->browse_path()->num_elements();
        if (num_relative_path_elements > 0){
            std::string browse_path_element_id = generateId();
            attribute_operand_details->Assign(ATTRIBUTE_OPERAND_BROWSE_PATH_ELEMENT_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(browse_path_element_id));
            for (int i=0; i < num_relative_path_elements; i++){
                zeek::RecordValPtr relative_path_element_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::AttributeOperandBrowsePathElement);

                // Source & Destination
                const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
                const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

               relative_path_element_details = assignSourceDestination(is_orig, relative_path_element_details, id_val);

                relative_path_element_details->Assign(BROWSE_PATH_ELEMENT_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(browse_path_element_id));
                flattenOpcUA_RelativePathElement(relative_path_element_details, obj->browse_path()->elements()->at(i), BROWSE_PATH_ELEMENT_REFERENCE_TYPE_ID_ENCODING_MASK_IDX);
                zeek::BifEvent::enqueue_opcua_binary_event_filter_attribute_operand_browse_path_element_event(connection->bro_analyzer(),
                                                                                                              connection->bro_analyzer()->Conn(),
                                                                                                              relative_path_element_details);
            }
        }
        attribute_operand_details->Assign(ATTRIBUTE_OPERAND_ATTRIBUTE_IDX, zeek::make_intrusive<zeek::StringVal>(ATTRIBUTE_ID_MAP.find(obj->attribute_id())->second));
        if (obj->index_range()->length() > 0){
            attribute_operand_details->Assign(ATTRIBUTE_OPERAND_INDEX_RANGE_IDX , zeek::make_intrusive<zeek::StringVal>(std_str(obj->index_range()->string())));
        }
        zeek::BifEvent::enqueue_opcua_binary_event_filter_attribute_operand_event(connection->bro_analyzer(),
                                                                                  connection->bro_analyzer()->Conn(),
                                                                                  attribute_operand_details);
    }
    void flattenOpcUA_ElementOperand(OpcUA_ElementOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        zeek::RecordValPtr event_operand_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ElementOperand);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        event_operand_details = assignSourceDestination(is_orig, event_operand_details, id_val);

        event_operand_details->Assign(ELEMENT_OPERAND_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        event_operand_details->Assign(ELEMENT_OPERAND_INDEX_IDX, zeek::val_mgr->Count(obj->index()));
        zeek::BifEvent::enqueue_opcua_binary_event_filter_element_operand_event(connection->bro_analyzer(),
                                                                                connection->bro_analyzer()->Conn(),
                                                                                event_operand_details);
    }
    void flattenOpcUA_LiteralOperand(OpcUA_LiteralOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){
        zeek::RecordValPtr literal_operand_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::LiteralOperand);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        literal_operand_details = assignSourceDestination(is_orig, literal_operand_details, id_val);

        std::string literal_operand_data_link_id = generateId();
        literal_operand_details->Assign(LITERAL_OPERAND_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        literal_operand_details->Assign(LITERAL_OPERAND_VARIANT_LINK_IDX, zeek::make_intrusive<zeek::StringVal>(literal_operand_data_link_id));
        flattenOpcUA_DataVariant(connection, obj->value(), literal_operand_data_link_id, Variant_LiteralOperand_Key, is_orig);
        zeek::BifEvent::enqueue_opcua_binary_event_filter_literal_operand_event(connection->bro_analyzer(),
                                                                                connection->bro_analyzer()->Conn(),
                                                                                literal_operand_details);
    }
%}
