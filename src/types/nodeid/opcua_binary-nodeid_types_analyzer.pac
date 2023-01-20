## opcua_binary-nodeid_types_ananlyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer utilitiy functions for the nodeid types.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%extern{
/*
Note: 
The binpac compiler generates one header file along with the associated source file so there
isn't a need to bring in additional headers here.  We'll just track header files in the
opcua_binary-analyzer.pac binpac file.  See the build/opcua_binary_pac.h and 
build/opcua_binary_pac.cc file(s) for details.
*/
%}

%header{
    void flattenOpcUA_NodeId(zeek::RecordValPtr service_object, OpcUA_NodeId *node_ptr, uint32 offset);
    void flattenOpcUA_ExpandedNodeId(zeek::RecordValPtr service_object, OpcUA_ExpandedNodeId *node_ptr, uint32 offset);
%}

%code{
 // Utility function to flatten NodeID objects
    void flattenOpcUA_NodeId(zeek::RecordValPtr service_object, OpcUA_NodeId *node_ptr, uint32 offset){
        uint8_t encoding = node_ptr->identifier_type();
        uint8_t node_id_encoding = encoding & 0x0f;

        service_object->Assign((offset+0), zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(encoding)));
        switch (node_id_encoding) {
            case node_encoding::TwoByte : service_object->Assign((offset+2), zeek::val_mgr->Count(node_ptr->two_byte_numeric()->numeric()));
                                        break;
            case node_encoding::FourByte :
                                        service_object->Assign((offset+1), zeek::val_mgr->Count(node_ptr->four_byte_numeric()->namespace_index()));
                                        service_object->Assign((offset+2), zeek::val_mgr->Count(node_ptr->four_byte_numeric()->numeric()));
                                        break;
            case node_encoding::Numeric :
                                        service_object->Assign((offset+1), zeek::val_mgr->Count(node_ptr->numeric()->namespace_index()));
                                        service_object->Assign((offset+2), zeek::val_mgr->Count(node_ptr->numeric()->numeric()));
                                        break;
            case node_encoding::String :
                                        service_object->Assign((offset+1), zeek::val_mgr->Count(node_ptr->string()->namespace_index()));
                                        service_object->Assign((offset+3), zeek::make_intrusive<zeek::StringVal>(std_str(node_ptr->string()->string()->string())));
                                        break;
            case node_encoding::GUID :
                                        service_object->Assign((offset+1), zeek::val_mgr->Count(node_ptr->guid()->namespace_index()));
                                        service_object->Assign((offset+4), zeek::make_intrusive<zeek::StringVal>(guidToGuidstring(node_ptr->guid()->guid()->data1(),
                                                                                                                                                    node_ptr->guid()->guid()->data2(),
                                                                                                                                                    node_ptr->guid()->guid()->data3(),
                                                                                                                                                    node_ptr->guid()->guid()->data4())));
                                        break;
            case node_encoding::Opaque :
                                        service_object->Assign((offset+1), zeek::val_mgr->Count(node_ptr->opaque()->namespace_index()));
                                        service_object->Assign((offset+5), zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(node_ptr->opaque()->opaque()->byteString())));
                                        break;
        }
    }

    // Utility function to flatten ExpandedNodeID objects
    void flattenOpcUA_ExpandedNodeId(zeek::RecordValPtr service_object, OpcUA_ExpandedNodeId *node_ptr, uint32 offset){
        flattenOpcUA_NodeId(service_object, node_ptr->node_id(), offset);
        if (isBitSet(node_ptr->node_id()->identifier_type(), NamespaceUriFlag)){
            service_object->Assign((offset+6), zeek::make_intrusive<zeek::StringVal>(std_str(node_ptr->namespace_uri()->string())));
        }
        if (isBitSet(node_ptr->node_id()->identifier_type(), ServerIndexFlag)){
            service_object->Assign((offset+7), zeek::val_mgr->Count(node_ptr->server_idx()));
        }
    }
%}
