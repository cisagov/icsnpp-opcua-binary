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
    num_nodes_to_browse   : int32; # Not documented in UA Specifications, found in the open62541 source code
    nodes_to_browse       : Browse_Description[$context.flow.bind_length(num_nodes_to_browse)];
} &let {
    deliver: bool = $context.flow.deliver_Svc_BrowseReq(this);
} &byteorder=littleendian;

type Browse_Description = record {
    node_id             : OpcUA_NodeId;
    browse_direction_id : int32;
    ref_type_id         : OpcUA_NodeId;
    include_subtypes    : OpcUA_Boolean;
    node_class_mask     : uint32;
    result_mask         : uint32;
} &byteorder=littleendian;

type Browse_Res(service: Service) = record {
    res_hdr             : Response_Header;
    results_table_size  : int32;
    results             : Browse_Result[$context.flow.bind_length(results_table_size)];
    diag_info_size      : int32;
    diag_info           : OpcUA_DiagInfo[$context.flow.bind_length(diag_info_size)];
} &let {
    deliver: bool = $context.flow.deliver_Svc_BrowseRes(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - Browse
# 5.8.3.2 - Table 37 - BrowseNext Service Parameters
#

type Browse_Next_Req(service: Service) = record {
    req_hdr                     : Request_Header;
    release_continuation_points : OpcUA_Boolean;
    num_continuation_points     : int32;
    continuation_points         : OpcUA_ByteString[$context.flow.bind_length(num_continuation_points)];
} &let {
    deliver: bool = $context.flow.deliver_Svc_BrowseNextReq(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.25 - Table 167 - ReferenceDescription
#

type Browse_ReferenceDescription = record {
    ref_type_id      : OpcUA_NodeId;
    is_forward       : OpcUA_Boolean;
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

type Browse_Result = record {
    status_code         : OpcUA_StatusCode;
    continuation_point  : OpcUA_ByteString;
    num_references      : int32;
    references          : Browse_ReferenceDescription[$context.flow.bind_length(num_references)];
} &byteorder=littleendian;
