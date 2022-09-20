## opcua_binary-opcua_filter_types_debug.pac
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
    void printOpcUA_AttributeOperand(int indent_width, OpcUA_AttributeOperand *operand);
    void printOpcUA_SimpleAttributeOperand(int indent_width, OpcUA_SimpleAttributeOperand *operand);
    void printOpcUA_AggregateFilter(int indent_width, OpcUA_AggregateFilter *filter);
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
        printf("%s Index: %d", indent(indent_width + 1).c_str(), operand->index());
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
        printf("%s AttributeId: %s (0x%08x)\n", indent(indent_width + 1).c_str(), ATTRIBUTE_IDENTIFIERS.find(operand->attribute_id())->second.c_str(), operand->attribute_id());
        if (operand->index_range()->numeric_range()->length() > 0) {
            printf("%s IndexRange: %s\n", indent(indent_width + 1).c_str(), std_str(operand->index_range()->numeric_range()->string()).c_str());
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
        printf("%s AttributeId: %s (0x%08x)\n", indent(indent_width + 1).c_str(), ATTRIBUTE_IDENTIFIERS.find(operand->attribute_id())->second.c_str(), operand->attribute_id());
        if (operand->index_range()->numeric_range()->length() > 0) {
            printf("%s IndexRange: %s\n", indent(indent_width + 1).c_str(), std_str(operand->index_range()->numeric_range()->string()).c_str());
        } else {
            printf("%s IndexRange: [OpcUa Null String]\n", indent(indent_width + 1).c_str());
        }
    }
    void printOpcUA_AggregateFilter(int indent_width, OpcUA_AggregateFilter *filter){
        printf("%s AggregateConfiguration: AggregateConfiguration\n", indent(indent_width).c_str());
        if (filter->start_time() > 0){
            printf("%s StartTime: %lld\n", indent(indent_width + 1).c_str(), filter->start_time());
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
%}