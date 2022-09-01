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
    void printOpcUA_AggregateFilter(int indent_width, OpcUA_AggregateFilter *filter);
    void printOpcUA_SimpleAttributeOperand(int indent_width, OpcUA_SimpleAttributeOperand *operand);
    void printOpcUA_ContentFilterElement(int indent_width, OpcUA_ContentFilterElement *element); 
%}

%code{
    void printOpcUA_DataChangeFilter(int indent_width, OpcUA_DataChangeFilter *filter){
        printf("%s DataChangeFilter: DataChangeFilter\n", indent(indent_width).c_str());
        switch(filter()->trigger){
            case 0:
                printf("%s DataChangeTrigger: Status (0x%08x)\n", indent(indent_width + 1).c_str(), filter->trigger());
            case 1:
                printf("%s DataChangeTrigger: Status Value (0x%08x)\n", indent(indent_width + 1).c_str(), filter->trigger());
            case 2:
                printf("%s DataChangeTrigger: Status Value Timestamp (0x%08x)\n", indent(indent_width + 1).c_str(), filter->trigger());
        }
        switch(filter()->deadband_type()){
            case 0:
                printf("%s DeadbandType: None (0x%08x)\n", indent(indent_width + 1).c_str(), filter->deadband_type());
            case 1:
                printf("%s DeadbandType: Absolute (0x%08x)\n", indent(indent_width + 1).c_str(), filter->deadband_type());
            case 2:
                printf("%s DeadbandType: Percent (0x%08x)\n", indent(indent_width + 1).c_str(), filter->deadband_type());
        }
        printf("%s DeadbandValue: %f\n", indent(indent_width + 1).c_str(), bytestringToDouble(filter->deadband_value()));
    }
    void printOpcUA_EventFilter(int indent_width, OpcUA_EventFilter *filter){
        printf("%s EventFilter: EventFilter\n", indent(indent_width).c_str());
        printf("%s SelectClauses: Array of SimpleAttributeOperand\n", indent(indent_width + 1).c_str());
        printf("%s ArraySize: %d\n", indent(indent_width + 2).c_str(), filter->num_select_clauses());
        for (int32_t i = 0; i < filter->num_select_clauses(); i++) {
            printf("%s [%d]: SimpleAttributeOperand\n", indent(indent_width + 3).c_str(), i);
            printOpcUA_SimpleAttributeOperand(indent_width + 4, filter->select_clauses()->at(i));
        }
        printf("%s WhereClause: ContentFilter\n", indent(indent_width + 1).c_str());
        printOpcUA_ContentFilter(indent(indent_width + 2), filter->where_clause());
    }
    void printOpcUA_ContentFilter(int indent_width, OpcUA_ContentFilter *filter){
        printf("%s Elements: Array of ContentFilter\n", indent(indent_width).c_str());
        printf("%s ArraySize: %d\n", indent(indent_width + 1).c_str(), filter->num_elements());
        for (int32_t i = 0; i < filter->num_elements(); i++) {
            printf("%s [%d]: ContentFilterElement\n", indent(indent_width + 2).c_str(), i);
            printOpcUA_ContentFilterElement(indent_width + 3, filter->elements()-at(i));
        }
    }
    void printOpcUA_ContentFilterElement(int indent_width, OpcUA_ContentFilterElement *element){
        switch(element->filter_operators()){
            case 0:
                printf("%s Filter: None (0x%08x)\n", indent(indent_width).c_str(), element->filter_operator());
            case 1:
                printf("%s DeadbandType: Absolute (0x%08x)\n", indent(indent_width).c_str(), element->filter_operator());
            case 2:
                printf("%s DeadbandType: Percent (0x%08x)\n", indent(indent_width).c_str(), element->filter_operator());
        }
    }
%}