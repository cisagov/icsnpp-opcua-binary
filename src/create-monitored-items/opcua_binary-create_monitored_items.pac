## opcua_binary-create_monitored_items.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the create monitored items service.
##
## Author:   Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.


#
# UA Specification Part 4 - Services 1.04.pdf - Create Monitored Items
# 5.12.2.2 - Table 69 - CreateMonitoredItems Service Parameters
#

type CreateMonitoredItems_Req(service: Service) = record {
    req_hdr                         : Request_Header;
    subscription_id                 : uint32;
    timestamps_to_return            : uint32;
    num_items_to_create             : int32; # Not documented in UA Specifications, found in pcap captures
    items_to_create                 : MonitoredItem_Create_Request[$context.flow.bind_length(num_items_to_create)];
} &let {
    deliver: bool = $context.flow.deliver_Svc_CreateMonitoredItemsReq(this);
} &byteorder=littleendian;

type CreateMonitoredItems_Res(service: Service) = record {
    res_hdr             : Response_Header;
    num_results         : int32;
    results             : MonitoredItem_Create_Response[$context.flow.bind_length(num_results)];
    diag_info_size      : int32;
    diag_info           : OpcUA_DiagInfo[$context.flow.bind_length(diag_info_size)];
   
} &let {
    deliver: bool = $context.flow.deliver_Svc_CreateMonitoredItemsRes(this);
} &byteorder=littleendian;

type MonitoredItem_Create_Request = record {
    item_to_monitor         : OpcUA_ReadValueId;
    monitoring_mode         : uint32;
    requested_parameters    : Monitoring_Parameters;
} &byteorder=littleendian;

type MonitoredItem_Create_Response = record {
    status_code                 : OpcUA_StatusCode;
    monitored_item_id           : uint32;
    revised_sampling_interval   : OpcUA_Duration;
    revised_queue_size          : uint32;
    filter_result               : OpcUA_ExtensionObject;
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - Create Subscription
# 7.16 - Table 139 - MonitoringParameters
#

type Monitoring_Parameters = record {
    client_handle       : uint32;
    sampling_interval   : OpcUA_Duration;
    filter              : OpcUA_ExtensionObject;
    queue_size          : uint32; 
    discard_oldest      : int8;
} &byteorder=littleendian;