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
    void flattenOpcUA_ExtensionObject(zeek::RecordValPtr service_object, OpcUA_ExtensionObject *obj, uint32 offset);
    void flattenOpcUA_ExtensionObject(zeek::RecordValPtr service_object, OpcUA_ExtensionObject *obj, uint32 offset, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig);
    void flattenOpcUA_AnonymousIdentityToken(zeek::RecordValPtr service_object, OpcUA_AnonymousIdentityToken *obj, uint32 offset);
    void flattenOpcUA_UserNameIdentityToken(zeek::RecordValPtr service_object, OpcUA_UserNameIdentityToken *obj, uint32 offset);
    void flattenOpcUA_X509IdentityToken(zeek::RecordValPtr service_object, OpcUA_X509IdentityToken *obj, uint32 offset);
    void flattenOpcUA_IssuedIdentityToken(zeek::RecordValPtr service_object, OpcUA_IssuedIdentityToken *obj, uint32 offset);
    void flattenOpcUA_ReadValueId(zeek::RecordValPtr service_object, OpcUA_ReadValueId *obj, uint32 offset);
    void flattenOpcUA_RelativePathElement(zeek::RecordValPtr service_object, OpcUA_RelativePathElement *obj, uint32 offset);
    void generateDiagInfoEvent(OPCUA_Binary_Conn *connection, zeek::ValPtr opcua_id, OpcUA_DiagInfo *diagInfo, vector<OpcUA_String *> *stringTable, uint32_t innerDiagLevel, uint32_t status_code_src, uint32_t diag_info_src, bool is_orig, std::string root_object_id = "");
    void generateStatusCodeEvent(OPCUA_Binary_Conn *connection, zeek::ValPtr opcua_id, uint32_t status_code_src, uint32_t status_code, uint32_t status_code_level, bool is_orig);
%}

%code{
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
    void flattenOpcUA_ExtensionObject(zeek::RecordValPtr service_object, OpcUA_ExtensionObject *obj, uint32 offset, std::string link_id, binpac::OPCUA_Binary::OPCUA_Binary_Conn* connection, bool is_orig){

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
                    flattenOpcUA_EventFilter(object_body->event_filter(), link_id, connection, is_orig);
                    break;
                case EventFilterResult:
                    flattenOpcUA_EventFilterResult(object_body->event_filter_result(), link_id, connection, is_orig);
                    break;
                case AggregateFilter:
                    flattenOpcUA_AggregateFilter(object_body->aggregate_filter(), link_id, connection);
                    break;
                case AggregateFilterResult:
                    flattenOpcUA_AggregateFilterResult(object_body->aggregate_filter_result(), link_id, connection);
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
                case LiteralOperand:
                    flattenOpcUA_LiteralOperand(object_body->literal_operand(), link_id, connection, is_orig);
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
        service_object->Assign(offset + 6, zeek::make_intrusive<zeek::StringVal>(ATTRIBUTE_ID_MAP.find(obj->attribute_id())->second));
        if (obj->index_range()->length() > 0){
            service_object->Assign(offset + 7, zeek::make_intrusive<zeek::StringVal>(std_str(obj->index_range()->string())));
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

    //
    // Common code used to generate a diagnostic information event.
    // NOTE: This function is called recursively to  process any 
    // nested inner diagnostic information.
    //
    void generateDiagInfoEvent(OPCUA_Binary_Conn *connection, zeek::ValPtr opcua_id, OpcUA_DiagInfo *diagInfo, vector<OpcUA_String *> *stringTable, uint32 innerDiagLevel, uint32_t status_code_src, uint32_t diag_info_src, bool is_orig, std::string root_object_id) {
        zeek::RecordValPtr diag_info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::DiagnosticInfoDetail);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

        diag_info = assignSourceDestination(is_orig, diag_info, id_val);

        // OpcUA_id
        diag_info->Assign(DIAG_INFO_LINK_ID_DST_IDX, opcua_id);

        // Diagnostic Info Source
        diag_info->Assign(DIAG_INFO_SOURCE_IDX,     zeek::val_mgr->Count(diag_info_src));
        diag_info->Assign(DIAG_INFO_SOURCE_STR_IDX, zeek::make_intrusive<zeek::StringVal>((DIAGNOSTIC_INFO_SRC_MAP.find(diag_info_src)->second)));
        if (root_object_id == "") {
            root_object_id = generateId();
        }
        diag_info->Assign(DIAG_INFO_ROOT_OBJECT_ID_IDX, zeek::make_intrusive<zeek::StringVal>(root_object_id));
        // Initialize the diagnostic info record
        diag_info->Assign(INNER_DIAG_LEVEL_IDX, zeek::val_mgr->Count(innerDiagLevel));
        diag_info->Assign(HAS_SYMBOLIC_ID_IDX,     zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_NAMESPACE_URI_IDX,   zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_LOCALE_IDX,          zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_LOCALE_TXT_IDX,      zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_ADDL_INFO_IDX,       zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_INNER_STAT_CODE_IDX, zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_INNER_DIAG_INFO_IDX, zeek::val_mgr->Bool(false));

        // Symbolic Id
        if (isBitSet(diagInfo->encoding_mask(), hasSymbolicId)) {
            int32 idx = diagInfo->symbolic_id();
            string str = std_str(stringTable->at(idx)->string());

            diag_info->Assign(HAS_SYMBOLIC_ID_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(SYMBOLIC_ID_IDX,     zeek::val_mgr->Count(idx));
            diag_info->Assign(SYMBOLIC_ID_STR_IDX, zeek::make_intrusive<zeek::StringVal>(str));
        }

        // Namespace URI
        if (isBitSet(diagInfo->encoding_mask(), hasNamespaceUri)) {
            int32 idx = diagInfo->namespace_uri();
            string str = std_str(stringTable->at(idx)->string());

            diag_info->Assign(HAS_NAMESPACE_URI_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(NAMESPACE_URI_IDX,     zeek::val_mgr->Count(idx));
            diag_info->Assign(NAMESPACE_URI_STR_IDX, zeek::make_intrusive<zeek::StringVal>(str));
        }

        // Localized Text
        if (isBitSet(diagInfo->encoding_mask(), hasLocalizedTxt)) {
            int32 idx = diagInfo->localized_txt();
            string str = std_str(stringTable->at(idx)->string());

            diag_info->Assign(HAS_LOCALE_TXT_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(LOCALE_TXT_IDX,     zeek::val_mgr->Count(idx));
            diag_info->Assign(LOCALE_TXT_STR_IDX, zeek::make_intrusive<zeek::StringVal>(str));
        }

        // Locale
        if (isBitSet(diagInfo->encoding_mask(), hasLocale)) {
            int32 idx = diagInfo->locale();
            string str = std_str(stringTable->at(idx)->string());

            diag_info->Assign(HAS_LOCALE_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(LOCALE_IDX,     zeek::val_mgr->Count(idx));
            diag_info->Assign(LOCALE_STR_IDX, zeek::make_intrusive<zeek::StringVal>(str));
        }

        // Additional Information
        if (isBitSet(diagInfo->encoding_mask(), hasAddlInfo)) {
            string str = std_str(diagInfo->addl_info()->string());

            diag_info->Assign(HAS_ADDL_INFO_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(ADDL_INFO_IDX,     zeek::make_intrusive<zeek::StringVal>(str));
        }

        // Inner Status Code
        if (isBitSet(diagInfo->encoding_mask(), hasInnerStatCode)) {
            diag_info->Assign(HAS_INNER_STAT_CODE_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(INNER_STAT_CODE_IDX,     zeek::make_intrusive<zeek::StringVal>(uint32ToHexstring(diagInfo->inner_stat_code())));
            generateStatusCodeEvent(connection, opcua_id, getInnerStatusCodeSource(diag_info_src), diagInfo->inner_stat_code(), innerDiagLevel, is_orig);
        }

        // Inner Diagnostic Info
        if (isBitSet(diagInfo->encoding_mask(), hasInnerDiagInfo)) {
            diag_info->Assign(HAS_INNER_DIAG_INFO_IDX, zeek::val_mgr->Bool(true));
            zeek::BifEvent::enqueue_opcua_binary_diag_info_event(connection->bro_analyzer(),
                                                            connection->bro_analyzer()->Conn(),
                                                            diag_info);

            generateDiagInfoEvent(connection, opcua_id, diagInfo->inner_diag_info(), stringTable, innerDiagLevel+=1, getInnerStatusCodeSource(status_code_src), getInnerDiagInfoSource(diag_info_src), is_orig, root_object_id);
        } else {
            zeek::BifEvent::enqueue_opcua_binary_diag_info_event(connection->bro_analyzer(),
                                                            connection->bro_analyzer()->Conn(),
                                                            diag_info);
        }

        return;
    }

    //
    // Common code used to generate a status code event.
    //
    void generateStatusCodeEvent(OPCUA_Binary_Conn *connection, zeek::ValPtr opcua_id, uint32_t status_code_src, uint32_t status_code, uint32_t status_code_level, bool is_orig) {
            StatusCodeDetail detail = StatusCodeDetail(status_code);
            zeek::RecordValPtr status = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::StatusCodeDetail);

            // Source & Destination
            const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
            const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);

            status = assignSourceDestination(is_orig, status, id_val);

            // OpcUA_id
            status->Assign(STATUS_CODE_LINK_ID_DST_IDX, opcua_id);

            status->Assign(STATUS_CODE_SOURCE_IDX,       zeek::val_mgr->Count(status_code_src));
            status->Assign(STATUS_CODE_SOURCE_STR_IDX,   zeek::make_intrusive<zeek::StringVal>((STATUS_CODE_SRC_MAP.find(status_code_src)->second)));
            status->Assign(STATUS_CODE_SOURCE_LEVEL_IDX, zeek::val_mgr->Count(status_code_level));
            status->Assign(STATUS_CODE_IDX,            zeek::make_intrusive<zeek::StringVal>(uint32ToHexstring(status_code)));
            status->Assign(SEVERITY_IDX,               zeek::val_mgr->Count(detail.severity));
            status->Assign(SEVERITY_STR_IDX,           zeek::make_intrusive<zeek::StringVal>(detail.severityStr));
            status->Assign(SUBCODE_IDX,                zeek::val_mgr->Count(detail.subCode));
            status->Assign(SUBCODE_STR_IDX,            zeek::make_intrusive<zeek::StringVal>(detail.subCodeStr));
            status->Assign(STRUCTURE_CHANGED_IDX,      zeek::val_mgr->Bool(detail.structureChanged));
            status->Assign(SEMANTICS_CHANGED_IDX,      zeek::val_mgr->Bool(detail.semanticsChanged));
            status->Assign(INFO_TYPE_IDX,              zeek::val_mgr->Count(detail.infoType));
            status->Assign(INFO_TYPE_STR_IDX,          zeek::make_intrusive<zeek::StringVal>(detail.infoTypeStr));

            if (detail.infoType != InfoType_NotUsed_Key) {
                status->Assign(LIMIT_BITS_IDX,         zeek::val_mgr->Count(detail.limitBits));
                status->Assign(LIMIT_BITS_STR_IDX,     zeek::make_intrusive<zeek::StringVal>(detail.limitBitsStr));
                status->Assign(OVERFLOW_IDX,           zeek::val_mgr->Bool(detail.overflow));

                status->Assign(HISTORIAN_BITS_IDX,            zeek::val_mgr->Count(detail.historianBits));
                status->Assign(HISTORIAN_BITS_STR_IDX,        zeek::make_intrusive<zeek::StringVal>(detail.historianBitsStr));
                status->Assign(HISTORIAN_BITS_PARTIAL_IDX,    zeek::val_mgr->Bool(detail.historianPartial));
                status->Assign(HISTORIAN_BITS_EXTRADATA_IDX,  zeek::val_mgr->Bool(detail.historianExtraData));
                status->Assign(HISTORIAN_BITS_MULTIVALUE_IDX, zeek::val_mgr->Bool(detail.historianMultiValue));
            }

            zeek::BifEvent::enqueue_opcua_binary_status_code_event(connection->bro_analyzer(),
                                                              connection->bro_analyzer()->Conn(),
                                                              status);
    }


%}
