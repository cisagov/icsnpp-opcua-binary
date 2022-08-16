## opcua_binary-browse_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing the browse service.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printCreateMonitoredItemsReq(CreateMonitoredItems_Req *msg);
    void printCreateMonitoredItemsRes(CreateMonitoredItems_Res *msg);
%}

%code{
    void printCreateMonitoredItemsReq(CreateMonitoredItems_Req *msg){
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header()); 
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printReqHdr(msg->req_hdr());

        printf("%s SubscriptionId: %d\n", indent(3).c_str(), msg->subscription_id());
        printf("%s TimestampsToReturn: %s (0x%08x)\n", indent(3).c_str(), TIMESTAMPS_TO_RETURN_MAP.find(msg->timestamps_to_return())->second.c_str(), msg->timestamps_to_return());

        printf("%s ItemsToCreate: Array of MonitoredItemCreateRequest\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->num_items_to_create());
        for (int32_t i = 0; i < msg->num_items_to_create(); i++) {
            printf("%s [%d]: MonitoredItemCreateRequest\n", indent(4).c_str(), i);
            printf("%s ItemToMonitor: ReadValueId\n", indent(5).c_str());
            printOpcUA_ReadValueId(6, msg->items_to_create()->at(i)->item_to_monitor());
            switch(msg->items_to_create()->at(i)->monitoring_mode()){
                case 0:
                    printf("%s MonitoringMode: Disabled (0x%08x)\n", indent(5).c_str(), msg->items_to_create()->at(i)->monitoring_mode());
                    break;
                case 1:
                    printf("%s MonitoringMode: Sampling (0x%08x)\n", indent(5).c_str(), msg->items_to_create()->at(i)->monitoring_mode()); 
                    break;
                case 2:
                    printf("%s MonitoringMode: Reporting (0x%08x)\n", indent(5).c_str(), msg->items_to_create()->at(i)->monitoring_mode());
                    break;
            }
            printf("%s RequestedParameters: MonitoringParameters\n", indent(5).c_str());
            printf("%s ClientHandle: %d\n", indent(6).c_str(), msg->items_to_create()->at(i)->requested_parameters()->client_handle());
            printf("%s SamplingInterval: %lf\n", indent(6).c_str(), bytestringToDouble(msg->items_to_create()->at(i)->requested_parameters()->sampling_interval()->duration()));
            printOpcUA_ExtensionObject(6, msg->items_to_create()->at(i)->requested_parameters()->filter());
            printf("%s QueueSize: %d\n", indent(6).c_str(), msg->items_to_create()->at(i)->requested_parameters()->queue_size());
            if (msg->items_to_create()->at(i)->requested_parameters()->discard_oldest() == 1){
                printf("%s DiscardOldest: True \n", indent(6).c_str());
            } else {
                printf("%s DiscardOldest: False \n", indent(6).c_str());
            }
        }
        return;
    }
    void printCreateMonitoredItemsRes(CreateMonitoredItems_Res *msg){
        
    }
%}