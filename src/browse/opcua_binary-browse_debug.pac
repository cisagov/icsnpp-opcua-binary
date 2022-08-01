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
    void printBrowseReq(Browse_Req *msg);
    void printBrowseRes(Browse_Res *msg);
%}

%code{
    void printBrowseReq(Browse_Req *msg){
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header()); 
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printReqHdr(msg->req_hdr());

        printf("%s View: ViewDescription\n", indent(3).c_str());
        printf("%s ViewId: NodeId\n", indent(4).c_str());
        printOpcUaNodeId(5, msg->view_description()->view_id());
        if (msg->view_description()->timestamp() > 0){
            printf("%s Timestamp: %lld\n", indent(4).c_str(), msg->view_description()->timestamp());
        } else {
            printf("%s Timestamp: No time specified (0)\n", indent(4).c_str());
        }
        printf("%s ViewVersion: %d\n", indent(4).c_str(), msg->view_description()->view_version());
        printf("%s RequestedMaxReferencesPerNode: %d\n", indent(3).c_str(), msg->req_max_refs_per_node());
        printf("%s NodesToBrowse: Array of BrowseDescription\n", indent(3).c_str());

        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->num_nodes_to_browse());

        for (int32_t i = 0; i < msg->num_nodes_to_browse(); i++) {

            printf("%s [%d]: BrowseDescription\n", indent(4).c_str(), i);
            printf("%s NodeId: NodeId\n", indent(5).c_str());
            printOpcUaNodeId(6, msg->nodes_to_browse()->at(i)->node_id());
            printf("%s BrowseDirection: 0x%08x\n", indent(5).c_str(), msg->nodes_to_browse()->at(i)->browse_direction_id());
            printf("%s ReferenceTypeId: NodeId\n", indent(5).c_str());
            printOpcUaNodeId(6, msg->nodes_to_browse()->at(i)->ref_type_id());
            if (msg->nodes_to_browse()->at(i)->include_subtypes() == 1){
                printf("%s IncludeSubtypes: True\n",indent(5).c_str());
            } else {
                printf("%s IncludeSubtypes: False\n", indent(5).c_str());
            }
            printf("%s Node Class Mask: %s\n", indent(5).c_str(), NODE_CLASSES_MAP.find(msg->nodes_to_browse()->at(i)->node_class_mask())->second.c_str());
            printf("%s Result Mask: 0x%08x\n", indent(5).c_str(), msg->nodes_to_browse()->at(i)->result_mask());
        }
        return;
    }
    void printBrowseRes(Browse_Res *msg){
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header());
        printService(msg->service());   

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printResHdr(msg->res_hdr());

        printf("%s Results: Array of BrowseResult\n", indent(3).c_str());

        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->results_table_size());

        for (int32_t i = 0; i < msg->results_table_size(); i++) {
            printf("%s [%d]: BrowseResult\n", indent(4).c_str(), i);

            printf("%s StatusCode: 0x%08x\n", indent(5).c_str(), msg->results()->at(i)->status_code());
            printf("%s ContinuationPoint: %s\n", indent(5).c_str(), bytestringToHexstring(msg->results()->at(i)->continuation_point()->byteString()).c_str());

            printf("%s References: Array of ReferenceDescription\n", indent(5).c_str());
            printf("%s ArraySize: %d\n", indent(6).c_str(), msg->results()->at(i)->num_references());

            for (int32_t j = 0; j < msg->results()->at(i)->num_references(); j++) {
                printf("%s [%d]: ReferenceDescription\n", indent(6).c_str(), j);
                printf("%s ReferenceTypeId: NodeId\n", indent(7).c_str());
                printOpcUaNodeId(8, msg->results()->at(i)->references()->at(j)->ref_type_id());
                if (msg->results()->at(i)->references()->at(j)->is_forward() == 1){
                    printf("%s IsForward: True\n",indent(7).c_str());
                } else {
                    printf("%s IsForward: False\n", indent(7).c_str());
                }
                printf("%s NodeId: ExpandedNodeId\n", indent(7).c_str());
                printExpandedNodeID(8, msg->results()->at(i)->references()->at(j)->target_node_id());

                printf("%s BrowseName: QualifiedName\n", indent(7).c_str());
                printf("%s Id: %d\n", indent(8).c_str(), msg->results()->at(i)->references()->at(j)->browse_name()->namespace_index());
                printf("%s Name: %s\n", indent(8).c_str(), std_str(msg->results()->at(i)->references()->at(j)->browse_name()->name()->string()).c_str());

                printf("%s DisplayName: LocalizedText\n", indent(7).c_str());
                printf("%s EncodingMask: 0x%02x\n", indent(8).c_str(), msg->results()->at(i)->references()->at(j)->display_name()->encoding_mask());
                if (isBitSet(msg->results()->at(i)->references()->at(j)->display_name()->encoding_mask(), localizedTextHasLocale)) {
                    printf("%s Locale: %s\n", indent(8).c_str(), std_str(msg->results()->at(i)->references()->at(j)->display_name()->locale()->string()).c_str());
                }

                if (isBitSet(msg->results()->at(i)->references()->at(j)->display_name()->encoding_mask(), localizedTextHasText)) {
                    printf("%s Text: %s\n", indent(8).c_str(), std_str(msg->results()->at(i)->references()->at(j)->display_name()->text()->string()).c_str());
                }

                printf("%s NodeClass: %s (0x%08x)\n", indent(7).c_str(), NODE_CLASSES_MAP.find(msg->results()->at(i)->references()->at(j)->node_class())->second.c_str(), msg->results()->at(i)->references()->at(j)->node_class());
                printf("%s TypeDefinition: ExpandedNodeId\n", indent(7).c_str());
                printExpandedNodeID(8, msg->results()->at(i)->references()->at(j)->type_definition());
            }  

        }
         // Array of DiagnosticInfo(s)
        printf("%s Results: Array of DiagnosticInfo\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->diag_info_size());
        for (int i = 0; i < msg->diag_info_size(); i++) {
            printf("%s [%d]: DiagnosticInfo\n", indent(4).c_str(), i);
            printOpcUA_DiagInfo(5, msg->diag_info()->at(i));
        }
        
    }

    void printBrowseNextReq (Browse_Next_Req *msg){
        printMsgHeader(msg->service()->msg_body()->header());
        printMsgType(msg->service()->msg_body()->header());
        printService(msg->service());   

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printReqHdr(msg->req_hdr());

        if (msg->release_continuation_points() == 1){
            printf("%s ReleaseContinuationPoints: True\n",indent(3).c_str());
        } else {
            printf("%s ReleaseContinuationPoints: False\n", indent(3).c_str());
        }
        printf("%s ContinuationPoints: Array of ByteString\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->num_continuation_points());
        for (int32_t i = 0; i < msg->num_continuation_points(); i++) {
            printf("%s [%d]: ContinuationPoints: %s\n", indent(4).c_str(), i, bytestringToHexstring(msg->continuation_points()->at(i)->byteString()).c_str());
        }
    }
%}