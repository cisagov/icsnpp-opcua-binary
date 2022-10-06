## opcua_binary-types_ananlyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer utilitiy functions for the binary types.
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
    void flattenOpcUA_ExtensionObject(zeek::RecordValPtr service_object, OpcUA_ExtensionObject *obj, uint32 offset);
    void flattenOpcUA_ExtensionObject(zeek::RecordValPtr service_object, OpcUA_ExtensionObject *obj, uint32 offset, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection);
    void flattenOpcUA_AnonymousIdentityToken(zeek::RecordValPtr service_object, OpcUA_AnonymousIdentityToken *obj, uint32 offset);
    void flattenOpcUA_UserNameIdentityToken(zeek::RecordValPtr service_object, OpcUA_UserNameIdentityToken *obj, uint32 offset);
    void flattenOpcUA_X509IdentityToken(zeek::RecordValPtr service_object, OpcUA_X509IdentityToken *obj, uint32 offset);
    void flattenOpcUA_IssuedIdentityToken(zeek::RecordValPtr service_object, OpcUA_IssuedIdentityToken *obj, uint32 offset);
    void flattenOpcUA_ReadValueId(zeek::RecordValPtr service_object, OpcUA_ReadValueId *obj, uint32 offset);
    void flattenOpcUA_RelativePathElement(zeek::RecordValPtr service_object, OpcUA_RelativePathElement *obj, uint32 offset);
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

    //
    // UA Specification Part 6 - Mappings 1.04.pdf
    //
    // 5.2.2.15 Table 14 - ExtensionObject
    //
    void flattenOpcUA_ExtensionObject(zeek::RecordValPtr service_object, OpcUA_ExtensionObject *obj, uint32 offset) {
        flattenOpcUA_NodeId(service_object, obj->type_id(), offset);

        string ext_obj_type_id_str = EXTENSION_OBJECT_ID_MAP.find(getExtensionObjectId(obj->type_id()))->second;
        service_object->Assign(offset + 6, zeek::make_intrusive<zeek::StringVal>(ext_obj_type_id_str));

        // OpcUA_ExtensionObject encoding
        service_object->Assign(offset + 7, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(obj->encoding())));

        // See if there is an object body
        OpcUA_ObjectBody *object_body;
        if (isBitSet(obj->encoding(), hasBinaryEncoding)) {
            object_body = obj->binary_object_body();
        } else if (isBitSet(obj->encoding(), hasXMLEncoding)) {
            object_body = obj->xml_object_body();
        }

        // Check encoding
        if (isBitSet(obj->encoding(), hasBinaryEncoding) || 
            isBitSet(obj->encoding(), hasXMLEncoding) ) {

            // OpcUA_ExtensionObject token
            switch (getExtensionObjectId(obj->type_id())) {
                case AnonymousIdentityToken_Key: 
                    flattenOpcUA_AnonymousIdentityToken(service_object, object_body->anonymous_identity_token(), offset);
                    break;
                case UserNameIdentityToken_Key:  
                    flattenOpcUA_UserNameIdentityToken(service_object, object_body->username_identity_token(), offset);
                    break;
                case X509IdentityToken_Key:      
                    flattenOpcUA_X509IdentityToken(service_object, object_body->x509_identity_token(), offset);
                    break;
                case IssuedIdentityToken_Key:    
                    flattenOpcUA_IssuedIdentityToken(service_object, object_body->issued_identity_token(), offset);
                    break;
            }
        }
    }
    void flattenOpcUA_ExtensionObject(zeek::RecordValPtr service_object, OpcUA_ExtensionObject *obj, uint32 offset, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection){

        flattenOpcUA_NodeId(service_object, obj->type_id(), offset);

        string ext_obj_type_id_str = EXTENSION_OBJECT_ID_MAP.find(getExtensionObjectId(obj->type_id()))->second;
        service_object->Assign(offset + 6, zeek::make_intrusive<zeek::StringVal>(ext_obj_type_id_str));

        //OpcUA_ExtensionObject encoding
        service_object->Assign(offset + 7, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(obj->encoding())));

        // See if there is an object body
        OpcUA_ObjectBody *object_body;
        if (isBitSet(obj->encoding(), hasBinaryEncoding)) {
            object_body = obj->binary_object_body();
        } else if (isBitSet(obj->encoding(), hasXMLEncoding)) {
            object_body = obj->xml_object_body();
        }

        // Check encoding
        if (isBitSet(obj->encoding(), hasBinaryEncoding) || 
            isBitSet(obj->encoding(), hasXMLEncoding) ) {

            // OpcUA_ExtensionObject token
            switch (getExtensionObjectId(obj->type_id())) {
                case DataChangeFilter:
                    flattenOpcUA_DataChangeFilter(object_body->data_change_filter(), link_id, connection);
                    break;
                case EventFilter:
                    flattenOpcUA_EventFilter(object_body->event_filter(), link_id, connection);
                    break;
                case AggregateFilter:
                    flattenOpcUA_AggregateFilter(object_body->aggregate_filter(), link_id, connection);
                    break;
                case SimpleAttributeOperand:
                    flattenOpcUA_SimpleAttributeOperand(object_body->simple_attribute_operand(), link_id, connection);
                    break;
                case AttributeOperand:
                    flattenOpcUA_AttributeOperand(object_body->attribute_operand(), link_id, connection);
                    break;
                case ElementOperand:
                    flattenOpcUA_ElementOperand(object_body->element_operand(), link_id, connection);
                    break;
                default:
                    break;
            }
        }
    }
    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.3 Table 185 - AnonymousIdentityToken
    //
    void flattenOpcUA_AnonymousIdentityToken(zeek::RecordValPtr service_object, OpcUA_AnonymousIdentityToken *obj, uint32 offset) {
        // Policy Id
        if (obj->policy_id()->length() > 0) {
            service_object->Assign(offset + 8, zeek::make_intrusive<zeek::StringVal>(std_str(obj->policy_id()->string())));
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.4 Table 186 - UserNameIdentityToken
    //
    void flattenOpcUA_UserNameIdentityToken(zeek::RecordValPtr service_object, OpcUA_UserNameIdentityToken *obj, uint32 offset) {
        // Policy Id
        if (obj->policy_id()->length() > 0) {
            service_object->Assign(offset + 8, zeek::make_intrusive<zeek::StringVal>(std_str(obj->policy_id()->string())));
        }

        // Username
        if (obj->user_name()->length() > 0) {
            service_object->Assign(offset + 9, zeek::make_intrusive<zeek::StringVal>(std_str(obj->user_name()->string())));
        }

        // Password
        if (obj->password()->length() > 0) {
            service_object->Assign(offset + 10, zeek::make_intrusive<zeek::StringVal>(std_str(obj->password()->byteString())));
        }

        // Encryption Algorithm
        if (obj->encryption_algorithm()->length() > 0) {
            service_object->Assign(offset + 11, zeek::make_intrusive<zeek::StringVal>(std_str(obj->encryption_algorithm()->string())));
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.5 Table 188 - X509IdentityToken
    //
    void flattenOpcUA_X509IdentityToken(zeek::RecordValPtr service_object, OpcUA_X509IdentityToken *obj, uint32 offset) {
        // Policy Id
        if (obj->policy_id()->length() > 0) {
            service_object->Assign(offset + 8, zeek::make_intrusive<zeek::StringVal>(std_str(obj->policy_id()->string())));
        } 

        // Certificate Data
        if (obj->certificate_data()->length() > 0) {
            service_object->Assign(offset + 12, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(obj->certificate_data()->byteString())));
        } 
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.6 Table 189 - IssuedIdentityToken
    //
    void flattenOpcUA_IssuedIdentityToken(zeek::RecordValPtr service_object, OpcUA_IssuedIdentityToken *obj, uint32 offset) {
        // Policy Id
        if (obj->policy_id()->length() > 0) {
            service_object->Assign(offset + 8, zeek::make_intrusive<zeek::StringVal>(std_str(obj->policy_id()->string())));
        }

        // Token Data
        if (obj->token_data()->length() > 0) {
            service_object->Assign(offset + 13, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(obj->token_data()->byteString())));
        } 

        // Encryption Algorithm
        if (obj->encryption_algorithm()->length() > 0) {
            service_object->Assign(offset + 11, zeek::make_intrusive<zeek::StringVal>(std_str(obj->encryption_algorithm()->string())));
        }
    }

    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.24 Table 166 - ReadValueId
    //
    void flattenOpcUA_ReadValueId(zeek::RecordValPtr service_object, OpcUA_ReadValueId *obj, uint32 offset){
        flattenOpcUA_NodeId(service_object, obj->node_id(), offset);
        service_object->Assign(offset + 6, zeek::make_intrusive<zeek::StringVal>(ATTRIBUTE_IDENTIFIERS.find(obj->attribute_id())->second));
        if (obj->index_range()->numeric_range()->length() > 0){
            service_object->Assign(offset + 7, zeek::make_intrusive<zeek::StringVal>(std_str(obj->index_range()->numeric_range()->string())));
        }
        if (obj->data_encoding()->namespace_index()!= 0){
            service_object->Assign(offset + 8, zeek::val_mgr->Count(obj->data_encoding()->namespace_index()));
        }
        if (obj->data_encoding()->name()->length() > 0){
            service_object->Assign(offset + 9, zeek::make_intrusive<zeek::StringVal>(std_str(obj->data_encoding()->name()->string())));
        }
    }
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.26 Table 168 - RelativePath
    //
    void flattenOpcUA_RelativePathElement(zeek::RecordValPtr service_object, OpcUA_RelativePathElement *obj, uint32 offset){
        flattenOpcUA_NodeId(service_object, obj->reference_type_id(), offset);
        service_object->Assign(offset + 6, zeek::val_mgr->Bool(obj->is_inverse()));
        service_object->Assign(offset + 7, zeek::val_mgr->Bool(obj->include_subtypes()));
        service_object->Assign(offset + 8, zeek::val_mgr->Count(obj->target_name()->namespace_index()));
        if (obj->target_name()->name()->length() > 0){
            service_object->Assign(offset + 9, zeek::make_intrusive<zeek::StringVal>(std_str(obj->target_name()->name()->string())));
        }
    }

%}