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
%}

%code{
    void printOpcUA_DataChangeFilter(int indent_width, OpcUA_DataChangeFilter *filter){
        
    }
%}