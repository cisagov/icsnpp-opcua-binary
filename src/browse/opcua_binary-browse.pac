## opcua_binary-browse.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the get endpoints service.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.


#
# UA Specification Part 4 - Services 1.04.pdf - Browse
# 5.8.2.2 - Table 34 - Browse Service Parameters
#

type Browse_Req(service: Service) = record {
    req_hdr               : Request_Header;
    view_description      : OpcUA_ViewDescription;
    req_max_refs_per_node : uint32; # Full name is RequestedMaxReferencesPerNode
    num_nodes_to_browse   : int32; # Not documsented in UA Specifications, found in the open62541 source code
    nodes_to_browse       : Browse_Description[$context.flow.bind_length(num_nodes_to_browse)];
} &let {
    deliver: bool = $context.flow.deliver_Svc_BrowseReq(this);
} &byteorder=littleendian;

type Browse_Description = record {
    node_id             : OpcUA_NodeId;
    browse_direction_id : int32;
    ref_type_id         : OpcUA_NodeId;
    include_subtypes    : int8;
    node_class_mask     : uint32;
    result_mask         : uint32;
} &byteorder=littleendian;

type Browse_Res(service: Service) = record {
    res_hdr             : Response_Header;
    results_table_size  : int32;
    has_results         : case (results_table_size > 0) of {
        true    -> results       : BrowseResult[results_table_size];
        default -> empty_results_table : empty;
    };
    diag_info_size      : int32;
    has_diag_info       : case (diag_info_size > 0) of {
        true    -> diag_info       : OpcUA_DiagInfo[diag_info_size];
       default -> empty_diag_info_table : empty;
    };
} &let {
    deliver: bool = $context.flow.deliver_Svc_BrowseRes(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.25 - Table 167 - ReferenceDescription
#

type ReferenceDescription = record {
    ref_type_id      : OpcUA_NodeId;
    is_forward       : int8;
    target_node_id   : OpcUA_ExpandedNodeId;
    browse_name      : OpcUA_QualifiedName;
    display_name     : OpcUA_LocalizedText;
    node_class       : uint32;
    type_definition  : OpcUA_ExpandedNodeId;
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.39 - Table 114 - BrowseResult
#

type BrowseResult = record {
    status_code         : OpcUA_StatusCode;
    continuation_point  : OpcUA_ByteString;
    num_references      : int32;
    has_references      : case (num_references > 0) of {
        true    ->  references      : ReferenceDescription[$context.flow.bind_length(num_references)];
        default -> empty_references_table : empty;
    };
} &byteorder=littleendian;
