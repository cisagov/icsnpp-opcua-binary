## opcua_binary-filter_types.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing filter objects.
##
## Author:   Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.17.2 Table 141 - DataChangeFilter
#
type OpcUA_DataChangeFilter = record {
    trigger         : uint32;
    deadband_type   : uint32;
    deadband_value  : OpcUA_Double;
};

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.17.3 Table 142 - EventFilter Structure
#
type OpcUA_EventFilter = record {
    num_select_clauses  : int32;
    select_clauses      : OpcUA_SimpleAttributeOperand[$context.flow.bind_length(num_select_clauses)];
    where_clause        : OpcUA_ContentFilter;
};

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.17.3 Table 143 - EventFilterResult Structure
#
type OpcUA_EventFilterResult = record {
    num_select_clause_results       : int32;
    select_clause_results           : OpcUA_StatusCode[$context.flow.bind_length(num_select_clause_results)];
    num_select_clause_diag_infos    : int32;
    select_clause_diag_infos        : OpcUA_DiagInfo[$context.flow.bind_length(num_select_clause_diag_infos)];
    where_clause_result             : OpcUA_ContentFilterResult;
};

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.4.1 Table 115 - ContentFilter Structure
#
type OpcUA_ContentFilter = record {
    num_elements    : int32;
    elements        : OpcUA_ContentFilterElement[$context.flow.bind_length(num_elements)];
};

type OpcUA_ContentFilterElement = record {
    filter_operator     : uint32;
    num_filter_operands : int32;
    filter_operands     : OpcUA_ExtensionObject[$context.flow.bind_length(num_filter_operands)];
};

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.4.1 Table 116 - ContentFilterResult Structure
  
#
type OpcUA_ContentFilterResult = record {
    num_element_results     : int32;
    elements_results        : OpcUA_ContentFilterElementResult[$context.flow.bind_length(num_element_results)];
    num_element_diag_infos  : int32;
    element_diag_infos      : OpcUA_DiagInfo[$context.flow.bind_length(num_element_diag_infos)];
};

type OpcUA_ContentFilterElementResult = record {
    status_code                 : OpcUA_StatusCode;
    num_operand_status_codes    : int32;
    operand_status_codes        : OpcUA_StatusCode[$context.flow.bind_length(num_operand_status_codes)];
    num_operand_diag_infos      : int32;
    operand_diag_infos          : OpcUA_DiagInfo[$context.flow.bind_length(num_operand_diag_infos)];
};


#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.17.4 Table 145 - AggregateFilter Structure
#
type OpcUA_AggregateFilter = record {
    start_time              : OpcUA_DateTime; # Maybe change, proper type is UTC time
    aggregate_type          : OpcUA_NodeId;
    processing_interval     : OpcUA_Duration;
    aggregate_configuration : OpcUA_AggregateConfiguration;
};

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.17.4 Table 146 - AggregateFilterResult Structure
#
type OpcUA_AggregateFilterResult = record {
    revised_start_time              : OpcUA_DateTime; # Maybe change, proper type is UTC time
    revised_processing_interval     : OpcUA_Duration;
    revised_aggregate_configuration : OpcUA_AggregateConfiguration; # Not found in the documentation, found in open62541 code
};

#
# UA Specification Part 13 - Aggregates 1.04.pdf
#
# 4.2.1.2 Table 2 - AggregateConfigurationType Definition
#
type OpcUA_AggregateConfiguration = record {
    use_server_capabilities_default : OpcUA_Boolean;
    treat_uncertain_as_bad          : OpcUA_Boolean;
    percent_data_bad                : uint8;
    percent_data_good               : uint8;
    use_sloped_extrapolation        : OpcUA_Boolean;
};

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.4.4.5 Table 130 - SimpleAttributeOperand
#
type OpcUA_SimpleAttributeOperand = record {
    type_id             : OpcUA_NodeId;
    num_browse_paths    : uint32;
    browse_paths        : OpcUA_QualifiedName[$context.flow.bind_length(num_browse_paths)];
    attribute_id        : uint32;
    index_range         : OpcUA_NumericRange;
};

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.4.4.4 Table 129 - AttributeOperand
#
type OpcUA_AttributeOperand = record {
    node_id         : OpcUA_NodeId;
    alias           : OpcUA_String;
    browse_path     : OpcUA_RelativePath;
    attribute_id    : uint32;
    index_range     : OpcUA_NumericRange;
}; 

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.4.4.2 Table 127 - ElementOperand
#
type OpcUA_ElementOperand = record {
    index   : uint32;
}; 

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.4.4.2 Table 128 - LiteralOperand
#
type OpcUA_LiteralOperand = record {
    value   : OpcUA_Variant; 
}; 