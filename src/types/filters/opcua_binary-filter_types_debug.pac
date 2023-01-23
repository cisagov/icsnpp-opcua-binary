## opcua_binary-filter_types_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing monitoring filters.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printOpcUA_DataChangeFilter(int indent_width, OpcUA_DataChangeFilter *filter);
    void printOpcUA_EventFilter(int indent_width, OpcUA_EventFilter *filter);
    void printOpcUA_ContentFilter(int indent_width, OpcUA_ContentFilter *filter);
    void printOpcUA_ContentFilterElement(int indent_width, OpcUA_ContentFilterElement *element);
    void printOpcUA_ElementOperand(int indent_width, OpcUA_ElementOperand *operand);
    void printOpcUA_LiteralOperand(int indent_width, OpcUA_LiteralOperand *operand);
    void printOpcUA_AttributeOperand(int indent_width, OpcUA_AttributeOperand *operand);
    void printOpcUA_SimpleAttributeOperand(int indent_width, OpcUA_SimpleAttributeOperand *operand);
    void printOpcUA_AggregateFilter(int indent_width, OpcUA_AggregateFilter *filter);
    void printOpcUA_AggregateFilterResult(int indent_width, OpcUA_AggregateFilterResult *filter_result);
    void printOpcUA_EventFilterResult(int indent_width, OpcUA_EventFilterResult *filter_result);
    void printOpcUA_ContentFilterResult(int indent_width, OpcUA_ContentFilterResult* filter_result);
    void printOpcUA_ContentFilterElementResult(int indent_width, OpcUA_ContentFilterElementResult* element_result);
%}

%code{
    void printOpcUA_DataChangeFilter(int indent_width, OpcUA_DataChangeFilter *filter){
        printf("%s DataChangeFilter: DataChangeFilter\n", indent(indent_width).c_str());
        printf("%s DataChangeTrigger: %s (0x%08x)\n", indent(indent_width + 1).c_str(), DATA_CHANGE_TRIGGER_MAP.find(filter->trigger())->second.c_str(), filter->trigger());
        printf("%s DeadbandType: %s (0x%08x)\n", indent(indent_width + 1).c_str(), DEADBAND_TYPE_MAP.find(filter->deadband_type())->second.c_str(), filter->deadband_type());
        printf("%s DeadbandValue: %f\n", indent(indent_width + 1).c_str(), bytestringToDouble(filter->deadband_value()));
    }
    void printOpcUA_EventFilter(int indent_width, OpcUA_EventFilter *filter){
        printf("%s EventFilter: EventFilter\n", indent(indent_width).c_str());
        printf("%s SelectClauses: Array of SimpleAttributeOperand\n", indent(indent_width + 1).c_str());
        printf("%s ArraySize: %d\n", indent(indent_width + 2).c_str(), filter->num_select_clauses());
        for (int32_t i = 0; i < filter->num_select_clauses(); i++) {
            printf("%s [%d]: SimpleAttributeOperand\n", indent(indent_width + 2).c_str(), i);
            printOpcUA_SimpleAttributeOperand(indent_width + 3, filter->select_clauses()->at(i));
        }
        printf("%s WhereClause: ContentFilter\n", indent(indent_width + 1).c_str());
        printOpcUA_ContentFilter(indent_width + 2, filter->where_clause());
    }
    void printOpcUA_ContentFilter(int indent_width, OpcUA_ContentFilter *filter){
        printf("%s Elements: Array of ContentFilter\n", indent(indent_width).c_str());
        printf("%s ArraySize: %d\n", indent(indent_width + 1).c_str(), filter->num_elements());
        for (int32_t i = 0; i < filter->num_elements(); i++) {
            printf("%s [%d]: ContentFilterElement\n", indent(indent_width + 2).c_str(), i);
            printOpcUA_ContentFilterElement(indent_width + 3, filter->elements()->at(i));
        }
    }
    void printOpcUA_ContentFilterElement(int indent_width, OpcUA_ContentFilterElement *element){
        printf("%s Filter: %s (0x%08x)\n", indent(indent_width).c_str(), FILTER_OPERATORS_MAP.find(element->filter_operator ())->second.c_str(), element->filter_operator());
        printf("%s FilterOperands: Array of ExtensionObject\n", indent(indent_width).c_str());
        printf("%s ArraySize: %d\n", indent(indent_width + 1).c_str(), element->num_filter_operands());
        for (int32_t i = 0; i < element->num_filter_operands(); i++) {
            printf("%s [%d]: ExtensionObject\n", indent(indent_width + 1).c_str(), i);
            printOpcUA_ExtensionObject(indent_width + 2, element->filter_operands()->at(i));
        }
    }
    void printOpcUA_ElementOperand(int indent_width, OpcUA_ElementOperand *operand){
        printf("%s ElementOperand: ElementOperand\n", indent(indent_width).c_str());
        printf("%s Index: %d\n", indent(indent_width + 1).c_str(), operand->index());
    }
    void printOpcUA_LiteralOperand(int indent_width, OpcUA_LiteralOperand *operand){
        printf("%s LiteralOperand: LiteralOperand\n", indent(indent_width).c_str());
        printf("%s Value: Variant\n", indent(indent_width+ 1).c_str());
        printOpcUA_Variant(indent_width + 2, operand->value());
    }
    void printOpcUA_AttributeOperand(int indent_width, OpcUA_AttributeOperand *operand){
        printf("%s AttributeOperand: AttributeOperand\n", indent(indent_width).c_str());
        printf("%s NodeId: NodeId \n", indent(indent_width + 1).c_str());
        printOpcUA_NodeId(indent_width + 2, operand->node_id());
        if (operand->alias()->length() > 0) {
            printf("%s Alias: %s\n", indent(indent_width + 1).c_str(), std_str(operand->alias()->string()).c_str());
        } else {
            printf("%s Alias: [OpcUa Null String]\n", indent(indent_width + 1).c_str());
        }
        printf("%s BrowsePath: RelativePath\n", indent(indent_width + 1).c_str());
        printOpcUA_RelativePath(indent_width + 2, operand->browse_path());
        printf("%s AttributeId: %s (0x%08x)\n", indent(indent_width + 1).c_str(), ATTRIBUTE_ID_MAP.find(operand->attribute_id())->second.c_str(), operand->attribute_id());
        if (operand->index_range()->length() > 0) {
            printf("%s IndexRange: %s\n", indent(indent_width + 1).c_str(), std_str(operand->index_range()->string()).c_str());
        } else {
            printf("%s IndexRange: [OpcUa Null String]\n", indent(indent_width + 1).c_str());
        }
    }
    void printOpcUA_SimpleAttributeOperand(int indent_width, OpcUA_SimpleAttributeOperand *operand){
        printf("%s SimpleAttributeOperand: SimpleAttributeOperand\n", indent(indent_width).c_str());
        printf("%s TypeDefinitionId: NodeId \n", indent(indent_width + 1).c_str());
        printOpcUA_NodeId(indent_width + 2, operand->type_id());
        printf("%s BrowsePath: Array of QualifiedName \n", indent(indent_width + 1).c_str());
        printf("%s ArraySize: %d\n", indent(indent_width + 2).c_str(), operand->num_browse_paths());
        for (int32_t i = 0; i < operand->num_browse_paths(); i++) {
            printf("%s [%d]: QualifiedName \n", indent(indent_width + 2).c_str(), i);
            printOpcUA_QualifiedName(indent_width + 3, operand->browse_paths()->at(i));
        }
        printf("%s AttributeId: %s (0x%08x)\n", indent(indent_width + 1).c_str(), ATTRIBUTE_ID_MAP.find(operand->attribute_id())->second.c_str(), operand->attribute_id());
        if (operand->index_range()->length() > 0) {
            printf("%s IndexRange: %s\n", indent(indent_width + 1).c_str(), std_str(operand->index_range()->string()).c_str());
        } else {
            printf("%s IndexRange: [OpcUa Null String]\n", indent(indent_width + 1).c_str());
        }
    }
    void printOpcUA_AggregateFilter(int indent_width, OpcUA_AggregateFilter *filter){
        printf("%s AggregateFilter: AggregateFilter\n", indent(indent_width).c_str());
        if (filter->start_time() > 0){
            double unix_timestamp = winFiletimeToUnixTime(filter->start_time());
            printf("%s StartTime: %s\n", indent(indent_width + 1).c_str(), unixTimestampToString(unix_timestamp).c_str());
        } else {
            printf("%s StartTime: No time specified (0)\n", indent(indent_width + 1).c_str());
        }
        printf("%s AggregateType: NodeId\n", indent(indent_width + 1).c_str());
        printOpcUA_NodeId(indent_width + 2, filter->aggregate_type());
        printf("%s ProcessingInterval %f\n", indent(indent_width + 1).c_str(), bytestringToDouble(filter->processing_interval()->duration()));
        printf("%s AggregateConfiguration: AggregateConfiguration\n", indent(indent_width + 1).c_str());
        if (filter->aggregate_configuration()->use_server_capabilities_default() == 1){
            printf("%s UseServerCapabilitiesDefault: True \n", indent(indent_width + 2).c_str());
        } else {
            printf("%s UseServerCapabilitiesDefault: False \n", indent(indent_width + 2).c_str());
        }
        if (filter->aggregate_configuration()->treat_uncertain_as_bad() == 1){
            printf("%s TreatUncertainAsBad: True \n", indent(indent_width + 2).c_str());
        } else {
            printf("%s TreatUncertainAsBad: False \n", indent(indent_width + 2).c_str());
        }
        printf("%s PercentDataBad: %d\n", indent(indent_width + 2).c_str(), filter->aggregate_configuration()->percent_data_bad());
        printf("%s PercentDataGood: %d\n", indent(indent_width + 2).c_str(), filter->aggregate_configuration()->percent_data_good());
        if (filter->aggregate_configuration()->use_sloped_extrapolation() == 1){
            printf("%s UseSlopedExtrapolation: True \n", indent(indent_width + 2).c_str());
        } else {
            printf("%s UseSlopedExtrapolation: False \n", indent(indent_width + 2).c_str());
        }
    }
    void printOpcUA_AggregateFilterResult(int indent_width, OpcUA_AggregateFilterResult *filter_result){
        printf("%s AggregateFilterResult: AggregateFilterResult\n", indent(indent_width).c_str());
        if (filter_result->revised_start_time() > 0){
            double unix_timestamp = winFiletimeToUnixTime(filter_result->revised_start_time());
            printf("%s RevisedStartTime: %s\n", indent(indent_width + 1).c_str(), unixTimestampToString(unix_timestamp).c_str());
        } else {
            printf("%s RevisedStartTime: No time specified (0)\n", indent(indent_width + 1).c_str());
        }
        printf("%s RevisedProcessingInterval %f\n", indent(indent_width + 1).c_str(), bytestringToDouble(filter_result->revised_processing_interval()->duration()));
        printf("%s RevisedAggregateConfiguration: AggregateConfiguration\n", indent(indent_width + 1).c_str());
        if (filter_result->revised_aggregate_configuration()->use_server_capabilities_default() == 1){
            printf("%s UseServerCapabilitiesDefault: True \n", indent(indent_width + 2).c_str());
        } else {
            printf("%s UseServerCapabilitiesDefault: False \n", indent(indent_width + 2).c_str());
        }
        if (filter_result->revised_aggregate_configuration()->treat_uncertain_as_bad() == 1){
            printf("%s TreatUncertainAsBad: True \n", indent(indent_width + 2).c_str());
        } else {
            printf("%s TreatUncertainAsBad: False \n", indent(indent_width + 2).c_str());
        }
        printf("%s PercentDataBad: %d\n", indent(indent_width + 2).c_str(), filter_result->revised_aggregate_configuration()->percent_data_bad());
        printf("%s PercentDataGood: %d\n", indent(indent_width + 2).c_str(), filter_result->revised_aggregate_configuration()->percent_data_good());
        if (filter_result->revised_aggregate_configuration()->use_sloped_extrapolation() == 1){
            printf("%s UseSlopedExtrapolation: True \n", indent(indent_width + 2).c_str());
        } else {
            printf("%s UseSlopedExtrapolation: False \n", indent(indent_width + 2).c_str());
        }
    }
    void printOpcUA_EventFilterResult(int indent_width, OpcUA_EventFilterResult *filter_result){
        printf("%s EventFilterResult: EventFilterResult\n", indent(indent_width).c_str());
        printf("%s SelectClauseResult: Array of Status Code\n", indent(indent_width + 1).c_str());
        printf("%s Array Size: %d\n", indent(indent_width + 2).c_str(), filter_result->num_select_clause_results());
        for (int32_t i = 0; i < filter_result->num_select_clause_results(); i++) {
            printf("%s [%d]: SelectClauseResults: 0x%08x [%s]\n", indent(indent_width + 2).c_str(), i, filter_result->select_clause_results()->at(i), STATUS_CODE_MAP.find(filter_result->select_clause_results()->at(i))->second.c_str());
        }
        printf("%s SelectClauseDiagnosticInfos: Array of Diagnostic Info\n", indent(indent_width + 1).c_str());
        printf("%s Array Size: %d\n", indent(indent_width + 2).c_str(), filter_result->num_select_clause_diag_infos());
        for (int32_t i = 0; i < filter_result->num_select_clause_diag_infos(); i++) {
            printf("%s [%d]: DiagnosticInfo\n", indent(indent_width + 2).c_str(), i);
            printOpcUA_DiagInfo(indent_width + 3, filter_result->select_clause_diag_infos()->at(i));
        }
        printf("%s WhereClauseResult: ContentFilterResult\n", indent(indent_width + 1).c_str());
        printOpcUA_ContentFilterResult(indent_width + 2, filter_result->where_clause_result());
    }
    void printOpcUA_ContentFilterResult(int indent_width, OpcUA_ContentFilterResult* filter_result){
        printf("%s ElementResults: Array of ContentFilterElementResult\n", indent(indent_width).c_str());
        printf("%s ArraySize: %d\n", indent(indent_width + 1).c_str(), filter_result->num_element_results());
        for (int32_t i = 0; i < filter_result->num_element_results(); i++) {
            printf("%s [%d]: ContentFilterElementResult\n", indent(indent_width + 1).c_str(), i);
            printOpcUA_ContentFilterElementResult(indent_width + 2, filter_result->elements_results()->at(i));
        }
        printf("%s ElementDiganosticInfos: Array of DiagnosticInfo\n", indent(indent_width).c_str());
        printf("%s Array Size: %d\n", indent(indent_width + 1).c_str(), filter_result->num_element_diag_infos());
        for (int32_t i = 0; i < filter_result->num_element_diag_infos(); i++) {
            printf("%s [%d]: DiagnosticInfo\n", indent(indent_width + 2).c_str(), i);
            printOpcUA_DiagInfo(indent_width + 3, filter_result->element_diag_infos  ()->at(i));
        }
    }
    void printOpcUA_ContentFilterElementResult(int indent_width, OpcUA_ContentFilterElementResult* element_result){
        printf("%s StatusCode: 0x%08x [%s]\n", indent(indent_width).c_str(), element_result->status_code(), STATUS_CODE_MAP.find(element_result->status_code())->second.c_str());
        printf("%s OperandStatusCodes: Array of StatusCode\n", indent(indent_width).c_str());
        printf("%s Array Size: %d\n", indent(indent_width + 1).c_str(), element_result->num_operand_status_codes());
        for (int32_t i = 0; i < element_result->num_operand_status_codes(); i++) {
            printf("%s [%d]: OperandStatusCodes: 0x%08x [%s]\n", indent(indent_width + 1).c_str(), i, element_result->operand_status_codes()->at(i), STATUS_CODE_MAP.find(element_result->operand_status_codes()->at(i))->second.c_str());
        }
        printf("%s OperandDiganosticInfos: Array of DiagnosticInfo\n", indent(indent_width).c_str());
        printf("%s Array Size: %d\n", indent(indent_width + 1).c_str(), element_result->num_operand_diag_infos());
        for (int32_t i = 0; i < element_result->num_operand_diag_infos(); i++) {
            printf("%s [%d]: DiagnosticInfo\n", indent(indent_width + 2).c_str(), i);
            printOpcUA_DiagInfo(indent_width + 3, element_result->operand_diag_infos()->at(i));
        }
    }
%}