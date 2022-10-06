## opcua_binary-opcua_filter_types_ananlyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer utilitiy functions for the binary filter types.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%extern{
/*
Note: 
The binpac compiler generates one header file along with the associated source file so there
isn't a need to bring in additional headers here.  We'll just track header files in the
opcua_binary-analyzer.pac binpac file.  See the build/opcua_binary_pac.h and 
build/opcua_binary_pac.cc file(s) for details.
*/
%}

%header{
    void flattenOpcUA_DataChangeFilter(OpcUA_DataChangeFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection);
    void flattenOpcUA_EventFilter(OpcUA_EventFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection);
    void flattenOpcUA_AggregateFilter(OpcUA_AggregateFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection);
    void flattenOpcUA_ContentFilterElement(OpcUA_ContentFilterElement *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection);
    void flattenOpcUA_ContentFilter(OpcUA_ContentFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection);
    void flattenOpcUA_SimpleAttributeOperand(OpcUA_SimpleAttributeOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection);
    void flattenOpcUA_AttributeOperand(OpcUA_AttributeOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection);
    void flattenOpcUA_ElementOperand(OpcUA_ElementOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection);
%}
%code{
    void flattenOpcUA_SimpleAttributeOperand_Internal(OpcUA_SimpleAttributeOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_operand){
        zeek::RecordValPtr simple_attribute_operand = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::SimpleAttributeOperand);
        simple_attribute_operand->Assign(SIMPLE_ATTRIBUTE_OPERAND_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        flattenOpcUA_NodeId(simple_attribute_operand, obj->type_id(), SIMPLE_ATTRIBUTE_OPERAND_TYPE_ID_ENCODING_MASK_IDX);
        int32_t num_browse_paths = obj->num_browse_paths();
        if (num_browse_paths > 0){
            std::string browse_path_id = generateId();
            simple_attribute_operand->Assign(SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(browse_path_id));
            for (int i=0; i < num_browse_paths; i++){
                zeek::RecordValPtr simple_attribute_operand_browse_path = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::SimpleAttributeOperandBrowsePaths);
                simple_attribute_operand_browse_path->Assign(SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(browse_path_id));
                simple_attribute_operand_browse_path->Assign(SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_NAMSESPACE_IDX_IDX, zeek::val_mgr->Count(obj->browse_paths()->at(i)->namespace_index()));
                if (obj->browse_paths()->at(i)->name()->length() > 0){
                     simple_attribute_operand_browse_path->Assign(SIMPLE_ATTRIBUTE_OPERAND_BROWSE_PATH_NAME_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(obj->browse_paths()->at(i)->name()->string())));
                }
                if (is_operand){
                    zeek::BifEvent::enqueue_opcua_binary_event_filter_simple_attribute_operand_browse_path_event(connection->bro_analyzer(),
                                                                                                                 connection->bro_analyzer()->Conn(),
                                                                                                                 simple_attribute_operand_browse_path);
                }
                else {
                    zeek::BifEvent::enqueue_opcua_binary_event_filter_select_clauses_browse_path_event(connection->bro_analyzer(),
                                                                                                       connection->bro_analyzer()->Conn(),
                                                                                                       simple_attribute_operand_browse_path);
                }
            }
        }
        simple_attribute_operand->Assign(SIMPLE_ATTRIBUTE_OPERAND_ATTRIBUTE_ID_IDX, zeek::make_intrusive<zeek::StringVal>(ATTRIBUTE_IDENTIFIERS.find(obj->attribute_id())->second));
        if (obj->index_range()->numeric_range()->length() > 0){
            simple_attribute_operand->Assign(SIMPLE_ATTRIBUTE_INDEX_RANGE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(obj->index_range()->numeric_range()->string())));
        }
        if (is_operand){
            zeek::BifEvent::enqueue_opcua_binary_event_filter_simple_attribute_operand_event(connection->bro_analyzer(),
                                                                                             connection->bro_analyzer()->Conn(),
                                                                                             simple_attribute_operand);
        }
        else {
            zeek::BifEvent::enqueue_opcua_binary_event_filter_select_clauses_event(connection->bro_analyzer(),
                                                                                   connection->bro_analyzer()->Conn(),
                                                                                   simple_attribute_operand);
        }
    }
    void flattenOpcUA_DataChangeFilter(OpcUA_DataChangeFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection){
        zeek::RecordValPtr data_change_filter_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::DataChangeFilter);
        data_change_filter_details->Assign(DATA_CHANGE_FILTER_REQ_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        data_change_filter_details->Assign(DATA_CHANGE_FILTER_REQ_TRIGGER_IDX, zeek::make_intrusive<zeek::StringVal>(DATA_CHANGE_TRIGGER_MAP.find(obj->trigger())->second));
        data_change_filter_details->Assign(DATA_CHANGE_FILTER_REQ_DEADBAND_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(DEADBAND_TYPE_MAP.find(obj->deadband_type())->second));
        data_change_filter_details->Assign(DATA_CHANGE_FILTER_REQ_DEADBAND_VALUE, zeek::make_intrusive<zeek::DoubleVal>(bytestringToDouble(obj->deadband_value())));
        zeek::BifEvent::enqueue_opcua_binary_data_change_filter_event(connection->bro_analyzer(),
                                                                      connection->bro_analyzer()->Conn(),
                                                                      data_change_filter_details);
    }
    void flattenOpcUA_EventFilter(OpcUA_EventFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection){
        zeek::RecordValPtr event_filter_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::EventFilter);
        event_filter_details->Assign(EVENT_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        int32_t num_select_clauses = obj->num_select_clauses();
        if (num_select_clauses > 0){
            std::string select_clauses_id = generateId();
            event_filter_details->Assign(EVENT_FILTER_SELECT_CLAUSES_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(select_clauses_id));
            for (int i=0; i < num_select_clauses; i++){
                flattenOpcUA_SimpleAttributeOperand_Internal(obj->select_clauses()->at(i), select_clauses_id, connection, false);
            }
        }
        std::string where_clause_id = generateId();
        event_filter_details->Assign(EVENT_FILTER_CONTENT_FILTER_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(where_clause_id));
        flattenOpcUA_ContentFilter(obj->where_clause(), where_clause_id, connection);
        zeek::BifEvent::enqueue_opcua_binary_event_filter_event(connection->bro_analyzer(),
                                                                connection->bro_analyzer()->Conn(),
                                                                event_filter_details);

    }
    void flattenOpcUA_AggregateFilter(OpcUA_AggregateFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection){
        zeek::RecordValPtr aggregate_filter_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::AggregateFilter);
        aggregate_filter_details->Assign(AGGREGATE_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        aggregate_filter_details->Assign(AGGREGATE_FILTER_START_TIME_IDX, zeek::make_intrusive<zeek::TimeVal>(obj->start_time()));
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
    void flattenOpcUA_ContentFilter(OpcUA_ContentFilter *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection){
        zeek::RecordValPtr content_filter_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ContentFilter);
        content_filter_details->Assign(EVENT_FILTER_CONTENT_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        int32_t num_elements = obj->num_elements();
        if (num_elements > 0){
            std::string content_filter_element_id = generateId();
            content_filter_details->Assign(CONTENT_FILTER_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(content_filter_element_id));
            for (int i=0; i < num_elements; i++){
                flattenOpcUA_ContentFilterElement(obj->elements()->at(i), content_filter_element_id, connection);
            }
        }
        zeek::BifEvent::enqueue_opcua_binary_event_filter_content_filter_event(connection->bro_analyzer(),
                                                                               connection->bro_analyzer()->Conn(),
                                                                               content_filter_details);
    }
    void flattenOpcUA_ContentFilterElement(OpcUA_ContentFilterElement *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection){
        int32_t num_filter_operands = obj->num_filter_operands();
        printf("%d", num_filter_operands);
        if (num_filter_operands > 0){
            for (int i=0; i < num_filter_operands; i++){
                zeek::RecordValPtr content_filter_element_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ContentFilterElement);
                content_filter_element_details->Assign(CONTENT_FILTER_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
                content_filter_element_details->Assign(CONTENT_FILTER_FILTER_OPERATOR_IDX, zeek::make_intrusive<zeek::StringVal>(FILTER_OPERATORS_MAP.find(obj->filter_operator())->second));
                std::string filter_operand_id = generateId();
                content_filter_element_details->Assign(CONTENT_FILTER_FILTER_OPERANDS_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(filter_operand_id));
                flattenOpcUA_ExtensionObject(content_filter_element_details, obj->filter_operands()->at(i), CONTENT_FILTER_FILTER_OPERAND_EXT_OBJ_TYPE_ID_ENCODING_MASK_IDX, filter_operand_id, connection);
                zeek::BifEvent::enqueue_opcua_binary_event_filter_content_filter_element_event(connection->bro_analyzer(),
                                                                                               connection->bro_analyzer()->Conn(),
                                                                                               content_filter_element_details);
            }
        }
    }
    void flattenOpcUA_SimpleAttributeOperand(OpcUA_SimpleAttributeOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection){
        flattenOpcUA_SimpleAttributeOperand_Internal(obj, link_id, connection, true);
    }
    void flattenOpcUA_AttributeOperand(OpcUA_AttributeOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection){
        zeek::RecordValPtr attribute_operand_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::AttributeOperand);
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
                relative_path_element_details->Assign(BROWSE_PATH_ELEMENT_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(browse_path_element_id));
                flattenOpcUA_RelativePathElement(relative_path_element_details, obj->browse_path()->elements()->at(i), BROWSE_PATH_ELEMENT_REFERENCE_TYPE_ID_ENCODING_MASK_IDX);
                zeek::BifEvent::enqueue_opcua_binary_event_filter_attribute_operand_browse_path_element_event(connection->bro_analyzer(),
                                                                                                              connection->bro_analyzer()->Conn(),
                                                                                                              relative_path_element_details);
            }
        }
        attribute_operand_details->Assign(ATTRIBUTE_OPERAND_ATTRIBUTE_IDX, zeek::make_intrusive<zeek::StringVal>(ATTRIBUTE_IDENTIFIERS.find(obj->attribute_id())->second));
        if (obj->index_range()->numeric_range()->length() > 0){
            attribute_operand_details->Assign(ATTRIBUTE_OPERAND_INDEX_RANGE_IDX , zeek::make_intrusive<zeek::StringVal>(std_str(obj->index_range()->numeric_range()->string())));
        }
        zeek::BifEvent::enqueue_opcua_binary_event_filter_attribute_operand_event(connection->bro_analyzer(),
                                                                                  connection->bro_analyzer()->Conn(),
                                                                                  attribute_operand_details);
    }
    void flattenOpcUA_ElementOperand(OpcUA_ElementOperand *obj, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection){
        zeek::RecordValPtr event_operand_details = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ElementOperand);
        event_operand_details->Assign(ELEMENT_OPERAND_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(link_id));
        event_operand_details->Assign(ELEMENT_OPERAND_INDEX_IDX, zeek::val_mgr->Count(obj->index()));
        zeek::BifEvent::enqueue_opcua_binary_event_filter_element_operand_event(connection->bro_analyzer(),
                                                                                connection->bro_analyzer()->Conn(),
                                                                                event_operand_details);
    }
%}