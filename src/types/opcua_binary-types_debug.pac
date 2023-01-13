## opcua_binary-types_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debugging functions for generic OPCUA binary types.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printOpcUA_DiagInfo(int indent_width, OpcUA_DiagInfo *diagInfo);
    void printOpcUA_ViewDescription(int indent_width, OpcUA_ViewDescription *viewInfo);
    void printOpcUA_ExtensionObject(int indent_width, OpcUA_ExtensionObject *obj);
    void printOpcUA_ExtensionObjectVec(int indent_width, vector<OpcUA_ExtensionObject *> *obj);
    void printOpcUA_LocaleId(int indent_width, OpcUA_LocaleId *obj);
    void printOpcUA_LocaleIdVec(int indent_width, vector<OpcUA_LocaleId *> *obj);
    void printOpcUA_SignedSoftwareCertificate(int indent_width, OpcUA_SignedSoftwareCertificate *obj);
    void printOpcUA_SignedSoftwareCertificateVec(int indent_width, vector<OpcUA_SignedSoftwareCertificate *> *obj);
    void printOpcUA_SignatureData(int indent_width, string field, OpcUA_SignatureData *obj);
    void printOpcUA_AnonymousIdentityToken(int indent_width, OpcUA_AnonymousIdentityToken *obj);
    void printOpcUA_UserNameIdentityToken(int indent_width, OpcUA_UserNameIdentityToken *obj);
    void printOpcUA_X509IdentityToken(int indent_width, OpcUA_X509IdentityToken *obj);
    void printOpcUA_IssuedIdentityToken(int indent_width, OpcUA_IssuedIdentityToken *obj);
    void printOpcUA_DiagInfo(int indent_width, OpcUA_DiagInfo *diagInfo);
    void printOpcUA_ReadValueId(int indent_width, OpcUA_ReadValueId *readValueId);
    void printOpcUA_RelativePath(int indent_width, OpcUA_RelativePath *relativePath);
    void printOpcUA_DataValue(int indent_width, OpcUA_DataValue *obj);
    void printOpcUA_Variant(int indent_width, OpcUA_Variant *obj);
    void printOpcUA_VariantData(int indent_width, uint32_t built_in_type, OpcUA_VariantData *obj);
    void printOpcUA_VariantDataArray(int indent_width, uint8_t encoding_mask, OpcUA_VariantData_Array *obj);
    void printOpcUA_VariantDataMultiDimArray(int indent_width, uint8_t encoding_mask, OpcUA_VariantData_MultiDim_Array *obj);
    void printOpcUA_QualifiedName(int indent_width, OpcUA_QualifiedName *obj);
    void printOpcUA_LocalizedText(int indent_width, OpcUA_LocalizedText *obj);
%}

%code{
    void printOpcUA_DiagInfo(int indent_width, OpcUA_DiagInfo *diagInfo) {
        printf("%s EncodingMask: 0x%02x\n", indent(indent_width).c_str(), diagInfo->encoding_mask());

        // Symbolic Id
        if (isBitSet(diagInfo->encoding_mask(), hasSymbolicId)) {
            int32 idx = diagInfo->symbolic_id();
            printf("%s SymbolicId: %d\n", indent(indent_width).c_str(), idx);
        }

        // Namespace URI
        if (isBitSet(diagInfo->encoding_mask(), hasNamespaceUri)) {
            int32 idx = diagInfo->namespace_uri();
            printf("%s Namespace: %d\n", indent(indent_width).c_str(), idx);
        }

        // Localized Text
        if (isBitSet(diagInfo->encoding_mask(), hasLocalizedTxt)) {
            int32 idx = diagInfo->localized_txt();
            printf("%s LocalizedText: %d\n", indent(indent_width).c_str(), idx);
        }

        // Locale
        if (isBitSet(diagInfo->encoding_mask(), hasLocale)) {
            int32 idx = diagInfo->locale();
            printf("%s Locale: %d\n", indent(indent_width).c_str(), idx);
        }

        // Additional Information
        if (isBitSet(diagInfo->encoding_mask(), hasAddlInfo)) {
            string str = std_str(diagInfo->addl_info()->string());
            printf("%s AdditionalInfo: %s\n", indent(indent_width).c_str(), str.c_str());
        }

        // Inner Status Code
        if (isBitSet(diagInfo->encoding_mask(), hasInnerStatCode)) {
            printf("%s InnerStatusCode: 0x%08x [%s]\n", indent(indent_width).c_str(), diagInfo->inner_stat_code(), STATUS_CODE_MAP.find(diagInfo->inner_stat_code())->second.c_str());
        }

        // Inner Diagnostic Info
        if (isBitSet(diagInfo->encoding_mask(), hasInnerDiagInfo)) {
            printf("%s Inner DiagnosticInfo: DiagnosticInfo\n", indent(indent_width).c_str());
            printOpcUA_DiagInfo(indent_width + 1, diagInfo->inner_diag_info());
        }

        return;
    }


    void printOpcUA_ViewDescription(int indent_width, OpcUA_ViewDescription *viewInfo) {
        printf("%s View: ViewDescription\n", indent(indent_width).c_str());
        printf("%s ViewId: NodeId\n", indent(indent_width + 1).c_str());
        printOpcUA_NodeId(indent_width + 2,viewInfo->view_id());
        if (viewInfo->timestamp() > 0){
            printf("%s Timestamp: %lld\n", indent(indent_width + 1).c_str(), viewInfo->timestamp());
        } else {
            printf("%s Timestamp: No time specified (0)\n", indent(indent_width + 1).c_str());
        }
        printf("%s ViewVersion: %d\n", indent(indent_width + 1).c_str(), viewInfo->view_version());
    }


    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.32 Table 173 - SignatureData
    //
    void printOpcUA_SignatureData(int indent_width, string field, OpcUA_SignatureData *obj) {
        printf("%s %s: SignatureData\n", indent(indent_width).c_str(), field.c_str());
        if (obj->algorithm()->length() > 0) {
            printf("%s Algorithm: %s\n", indent(indent_width+1).c_str(), std_str(obj->algorithm()->string()).c_str());
        } else {
            printf("%s Algorithm: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        if (obj->signature()->length() > 0) {
            printf("%s Signature: %s\n", indent(indent_width+1).c_str(), bytestringToHexstring(obj->signature()->byteString()).c_str());
        } else {
            printf("%s Signature: <MISSING>[OpcUa Null ByteString]\n", indent(indent_width+1).c_str());
        }
    }

    //
    // UA Specification Part 3 - Address Space Model 1.04.pdf
    //
    // 8.4 LocaleId
    //
    void printOpcUA_LocaleId(int indent_width, OpcUA_LocaleId *obj) {
        printf("%s LocaleIds:  %s\n", indent(indent_width+1).c_str(), std_str(obj->locale_id()).c_str());
    }

    void printOpcUA_LocaleIdVec(int indent_width, vector<OpcUA_LocaleId *> *obj) {
        for (int i = 0; i < obj->size(); i++) {
            printf("%s [%d]: LocaleIds:  %s\n", indent(indent_width+1).c_str(), i, std_str(obj->at(i)->locale_id()).c_str());
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.33 Table 174 - SignedSoftwareCertificate
    //
    void printOpcUA_SignedSoftwareCertificate(int indent_width, OpcUA_SignedSoftwareCertificate *obj) {
        printf("%s CertificateDate:  %s\n", indent(indent_width).c_str(), std_str(obj->certificate_data()->byteString()).c_str());
        printf("%s Signature:  %s\n", indent(indent_width).c_str(), std_str(obj->signature()->byteString()).c_str());
    }

    void printOpcUA_SignedSoftwareCertificateVec(int indent_width, vector<OpcUA_SignedSoftwareCertificate *> *obj) {
        for (int i = 0; i < obj->size(); i++) {
            printf("%s [%d]: ClientSoftwareCert:\n", indent(indent_width+1).c_str(), i);
            printOpcUA_SignedSoftwareCertificate(indent_width+2, obj->at(i));
        }
    }

    //
    // UA Specification Part 6 - Mappings 1.04.pdf
    //
    // 5.2.2.15 Table 14 - ExtensionObject
    //
    void printOpcUA_ExtensionObject(int indent_width, OpcUA_ExtensionObject *obj) {
        string extension_obj_str = EXTENSION_OBJECT_ID_MAP.find(getExtensionObjectId(obj->type_id()))->second;
        printf("%s %s: ExtensionObject\n", indent(indent_width).c_str(), extension_obj_str.c_str());

        // TypeId
        printf("%s TypeId: NodeId\n", indent(indent_width+1).c_str());
        printOpcUA_NodeId(indent_width+2, obj->type_id());
        
        // Extension Object Encoding Mask
        OpcUA_ObjectBody *object_body;
        if (isBitSet(obj->encoding(), hasNoEncoding)) {
            printf("%s Encoding Mask: 0x%02x has no encoding\n", indent(indent_width+1).c_str(), obj->encoding());
        } else if (isBitSet(obj->encoding(), hasBinaryEncoding)) {
            printf("%s Encoding Mask: 0x%02x has binary body\n", indent(indent_width+1).c_str(), obj->encoding());
            object_body = obj->binary_object_body();
        } else if (isBitSet(obj->encoding(), hasXMLEncoding)) {
            printf("%s Encoding Mask: 0x%02x has XML body\n", indent(indent_width+1).c_str(), obj->encoding());
            object_body = obj->xml_object_body();
        }

        // Check encoding
        if (isBitSet(obj->encoding(), hasBinaryEncoding) || 
            isBitSet(obj->encoding(), hasXMLEncoding) ) {

            // Extension Object
            switch (getExtensionObjectId(obj->type_id())) {
                case AnonymousIdentityToken_Key: 
                    printOpcUA_AnonymousIdentityToken(indent_width+1, object_body->anonymous_identity_token());
                    break;
                case UserNameIdentityToken_Key:  
                    printOpcUA_UserNameIdentityToken(indent_width+1, object_body->username_identity_token());
                    break;
                case X509IdentityToken_Key:      
                    printOpcUA_X509IdentityToken(indent_width+1, object_body->x509_identity_token());
                    break;
                case IssuedIdentityToken_Key:    
                    printOpcUA_IssuedIdentityToken(indent_width+1, object_body->issued_identity_token());
                    break;
                case DataChangeFilter_Key:
                    printOpcUA_DataChangeFilter(indent_width+1, object_body->data_change_filter());
                    break;
                case EventFilter_Key:
                    printOpcUA_EventFilter(indent_width+1, object_body->event_filter());
                    break;
                case AggregateFilter_Key:
                    printOpcUA_AggregateFilter(indent_width+1, object_body->aggregate_filter());
                    break;
                case ElementOperand_Key:
                    printOpcUA_ElementOperand(indent_width+1, object_body->element_operand());
                    break;
                case LiteralOperand_Key:
                    printOpcUA_LiteralOperand(indent_width+1, object_body->literal_operand());
                    break;
                case AttributeOperand_Key:
                    printOpcUA_AttributeOperand(indent_width+1, object_body->attribute_operand());
                    break;
                case SimpleAttributeOperand_Key:
                    printOpcUA_SimpleAttributeOperand(indent_width+1, object_body->simple_attribute_operand());
                    break;
                case AggregateFilterResult_Key:
                    printOpcUA_AggregateFilterResult(indent_width+1, object_body->aggregate_filter_result());
                    break;
                case EventFilterResult_Key:
                    printOpcUA_EventFilterResult(indent_width+1, object_body->event_filter_result());
                    break;
            }
        }
    }

    void printOpcUA_ExtensionObjectVec(int indent_width, vector<OpcUA_ExtensionObject *> *obj) {
        for (int i = 0; i < obj->size(); i++) {
            printf("%s [%d]: ExtensionObject\n", indent(indent_width+1).c_str(), i);
            printOpcUA_ExtensionObject(indent_width+2, obj->at(i));
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.3 Table 185 - AnonymousIdentityToken
    //
    void printOpcUA_AnonymousIdentityToken(int indent_width, OpcUA_AnonymousIdentityToken *obj) {
        printf("%s AnonymousIdentityToken: AnonymousIdentityToken\n", indent(indent_width).c_str());

        // Policy Id
        if (obj->policy_id()->length() > 0) {
            printf("%s PolicyId: %s\n", indent(indent_width+1).c_str(), std_str(obj->policy_id()->string()).c_str());
        } else {
            printf("%s PolicyId: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.4 Table 186 - UserNameIdentityToken
    //
    void printOpcUA_UserNameIdentityToken(int indent_width, OpcUA_UserNameIdentityToken *obj) {
        printf("%s UserNameIdentityToken: UserNameIdentityToken\n", indent(indent_width).c_str());

        // Policy Id
        if (obj->policy_id()->length() > 0) {
            printf("%s PolicyId: %s\n", indent(indent_width+1).c_str(), std_str(obj->policy_id()->string()).c_str());
        } else {
            printf("%s PolicyId: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Username
        if (obj->user_name()->length() > 0) {
            printf("%s UserName: %s\n", indent(indent_width+1).c_str(), std_str(obj->user_name()->string()).c_str());
        } else {
            printf("%s UserName: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Password
        if (obj->password()->length() > 0) {
            printf("%s Password: %s\n", indent(indent_width+1).c_str(), std_str(obj->password()->byteString()).c_str());
        } else {
            printf("%s Password: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Encryption Algorithm
        if (obj->encryption_algorithm()->length() > 0) {
            printf("%s EncryptionAlgorithm: %s\n", indent(indent_width+1).c_str(), std_str(obj->encryption_algorithm()->string()).c_str());
        } else {
            printf("%s EncryptionAlgorithm: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.5 Table 188 - X509IdentityToken
    //
    void printOpcUA_X509IdentityToken(int indent_width, OpcUA_X509IdentityToken *obj) {
        printf("%s X509IdentityToken: X509IdentityToken\n", indent(indent_width).c_str());

        // Policy Id
        if (obj->policy_id()->length() > 0) {
            printf("%s PolicyId: %s\n", indent(indent_width+1).c_str(), std_str(obj->policy_id()->string()).c_str());
        } else {
            printf("%s PolicyId: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Certificate Data
        if (obj->certificate_data()->length() > 0) {
            printf("%s CertificateData: %s\n", indent(indent_width+1).c_str(), bytestringToHexstring(obj->certificate_data()->byteString()).c_str());
        } else {
            printf("%s CertificateData: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.6 Table 189 - IssuedIdentityToken
    //
    void printOpcUA_IssuedIdentityToken(int indent_width, OpcUA_IssuedIdentityToken *obj) {
        printf("%s IssuedIdentityToken: IssuedIdentityToken\n", indent(indent_width).c_str());

        // Policy Id
        if (obj->policy_id()->length() > 0) {
            printf("%s PolicyId: %s\n", indent(indent_width+1).c_str(), std_str(obj->policy_id()->string()).c_str());
        } else {
            printf("%s PolicyId: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Token Data
        if (obj->token_data()->length() > 0) {
            printf("%s TokenData: %s\n", indent(indent_width+1).c_str(), bytestringToHexstring(obj->token_data()->byteString()).c_str());
        } else {
            printf("%s TokenData: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Encryption Algorithm
        if (obj->encryption_algorithm()->length() > 0) {
            printf("%s EncryptionAlgorithm: %s\n", indent(indent_width+1).c_str(), std_str(obj->encryption_algorithm()->string()).c_str());
        } else {
            printf("%s EncryptionAlgorithm: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }
    }
    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.24 Table 166 - ReadValueId
    //
    void printOpcUA_ReadValueId(int indent_width, OpcUA_ReadValueId *readValueId){
        printf("%s NodeId: NodeId\n", indent(indent_width).c_str());
        printOpcUA_NodeId(indent_width + 1, readValueId->node_id());
        printf("%s AttributeId: %s (0x%08x)\n", indent(indent_width).c_str(), ATTRIBUTE_ID_MAP.find(readValueId->attribute_id())->second.c_str(), readValueId->attribute_id());
        if (readValueId->index_range()->length() > 0){
            printf("%s IndexRange: %s\n", indent(indent_width).c_str(), std_str(readValueId->index_range()->string()).c_str());
        }
        else {
            printf("%s IndexRange: [OpcUa Null String]\n", indent(indent_width).c_str());
        }
        printf("%s DataEncoding: QualifiedName\n", indent(indent_width).c_str());
        printOpcUA_QualifiedName((indent_width + 1), readValueId->data_encoding());
    }
    void printOpcUA_RelativePath(int indent_width, OpcUA_RelativePath *relativePath){
        printf("%s Elements: Array of RelativePathElement\n", indent(indent_width).c_str());
        printf("%s ArraySize: %d\n", indent(indent_width + 1).c_str(), relativePath->num_elements());
        for (int32_t i = 0; i < relativePath->num_elements(); i++) {
            printf("%s [%d]: RelativePathElement\n", indent(indent_width + 1).c_str(), i);
            printf("%s ReferenceTypeId: NodeId \n", indent(indent_width + 2).c_str());
            printOpcUA_NodeId(indent_width + 3, relativePath->elements()->at(i)->reference_type_id());
            if (relativePath->elements()->at(i)->is_inverse() == 1){
                printf("%s IsInverse: True \n", indent(indent_width + 2).c_str());
            } else {
                printf("%s IsInverse: False \n", indent(indent_width + 2).c_str());
            }
            if (relativePath->elements()->at(i)->include_subtypes() == 1){
                printf("%s IncludeSubtypes: True \n", indent(indent_width + 2).c_str());
            } else {
                printf("%s IncludeSubtypes: False \n", indent(indent_width + 2).c_str());
            }
            printf("%s TargetName: QualifiedName\n", indent(indent_width + 2).c_str());
            printOpcUA_QualifiedName(indent_width + 3, relativePath->elements()->at(i)->target_name());
        }
    }
    

    //
    // UA Specification Part 6 - Mappings 1.04.pdf
    //
    // 5.2.2.17 DataValue Table 16 - Data Value Binary DataEncoding
    //
    void printOpcUA_DataValue(int indent_width, OpcUA_DataValue *obj) {

        printf("%s EncodingMask: 0x%02x\n", indent(indent_width).c_str(), obj->encoding_mask());

        if (isBitSet(obj->encoding_mask(), dataValueHasValue)) {
            printOpcUA_Variant(indent_width, obj->value());
        }

        if (isBitSet(obj->encoding_mask(), dataValueHasStatusCode)) {
            printf("%s StatusCode: 0x%08x\n", indent(indent_width).c_str(), obj->status_code());
        }

        if (isBitSet(obj->encoding_mask(), dataValueHasSourceTimestamp)) {
            double unix_timestamp = winFiletimeToUnixTime(obj->source_timestamp());
            printf("%s SourceTimestamp: %s\n", indent(indent_width).c_str(), unixTimestampToString(unix_timestamp).c_str());

            // The number of 10 picosecond intervals for the SourceTimestamp.
            // Not present if the SourcePicoSeconds bit in the EncodingMask is 
            // False. If the Source timestamp is missing the picoseconds are ignored.
            if (isBitSet(obj->encoding_mask(), dataValueHasSourcePicoseconds)) {
                printf("%s SourcePicoSeconds: %d\n", indent(indent_width).c_str(), obj->source_pico_sec());
            }
        }


        if (isBitSet(obj->encoding_mask(), dataValueHasServerTimestamp)) {
            double unix_timestamp = winFiletimeToUnixTime(obj->server_timestamp());
            printf("%s ServerTimestamp: %s\n", indent(indent_width).c_str(), unixTimestampToString(unix_timestamp).c_str());

            // The number of 10 picosecond intervals for the ServerTimestamp.
            // Not present if the ServerPicoSeconds bit in the EncodingMask is 
            // False. If the Server timestamp is missing the picoseconds are ignored.
            if (isBitSet(obj->encoding_mask(), dataValueHasServerPicoseconds)) {
                printf("%s ServerPicoSeconds: %d\n", indent(indent_width).c_str(), obj->server_pico_sec());
            }
        }
    }

    // 
    // UA Specification Part 6 - Mappings 1.04.pdf
    //
    // 5.2.2.16 Variant Table 15 - Variant Binary DataEncoding and 5.1.6 Variant
    //
    void printOpcUA_Variant(int indent_width, OpcUA_Variant *obj) {

        uint32_t built_in_type = getVariantBuiltInDataType(obj->encoding_mask());
        string built_in_type_str = BUILT_IN_DATA_TYPES_MAP.find(built_in_type)->second;
        if (getVariantDataType(obj->encoding_mask()) == variantIsValue) {
            printf("%s Variant Type: %s (0x%02x)\n", indent(indent_width).c_str(), built_in_type_str.c_str(), obj->encoding_mask());
            printOpcUA_VariantData(indent_width, obj->encoding_mask(), obj->variant_value());
        }

        if (getVariantDataType(obj->encoding_mask()) == variantIsArray) {
            printf("%s Variant Type: Array of %s (0x%02x)\n", indent(indent_width).c_str(), built_in_type_str.c_str(), obj->encoding_mask());
            printf("%s %s: Array of %s\n", indent(indent_width).c_str(), built_in_type_str.c_str(), built_in_type_str.c_str());
            printf("%s ArraySize: %d\n", indent(indent_width+1).c_str(), obj->variant_array()->array_length());
            printOpcUA_VariantDataArray(indent_width + 1, obj->encoding_mask(), obj->variant_array());
        }

        if (getVariantDataType(obj->encoding_mask()) == variantIsMultiDimensionalArray) {
            printf("%s Variant Type: Matrix of %s (0x%02x)\n", indent(indent_width).c_str(), built_in_type_str.c_str(), obj->encoding_mask());
            printf("%s %s: Array of %s\n", indent(indent_width).c_str(), built_in_type_str.c_str(), built_in_type_str.c_str());
            printf("%s ArraySize: %d\n", indent(indent_width+1).c_str(), obj->variant_multidim_array()->array()->array_length());
            printOpcUA_VariantDataMultiDimArray(indent_width + 1, obj->encoding_mask(), obj->variant_multidim_array());
        }

    }

    void printOpcUA_VariantData(int indent_width, uint32_t built_in_type, OpcUA_VariantData *obj) {

        if (built_in_type == BuiltIn_Boolean) {
            printf("%s Boolean: %d\n", indent(indent_width).c_str(), obj->boolean_variant());
        }

        if (built_in_type == BuiltIn_SByte) {
            printf("%s SByte: %d\n", indent(indent_width).c_str(), obj->sbyte_variant());
        }

        if (built_in_type == BuiltIn_Byte) {
            printf("%s Byte: %d\n", indent(indent_width).c_str(), obj->byte_variant());
        }

        if (built_in_type == BuiltIn_Int16) {
            printf("%s Int16: %d\n", indent(indent_width).c_str(), obj->int16_variant());
        }

        if (built_in_type == BuiltIn_Uint16) {
            printf("%s UInt16: %d\n", indent(indent_width).c_str(), obj->uint16_variant());
        }

        if (built_in_type == BuiltIn_Int32) {
            printf("%s Int32: %d\n", indent(indent_width).c_str(), obj->int32_variant());
        }

        if (built_in_type == BuiltIn_Uint32) {
            printf("%s UInt32: %u\n", indent(indent_width).c_str(), obj->uint32_variant());
        }

        if (built_in_type == BuiltIn_Int64) {
            printf("%s Int64: %lld\n", indent(indent_width).c_str(), obj->int64_variant());
        }

        if (built_in_type == BuiltIn_Uint64) {
            printf("%s UInt64: %llu\n", indent(indent_width).c_str(), obj->uint64_variant());
        }

        if (built_in_type == BuiltIn_String) {
            printf("%s String: %s\n", indent(indent_width).c_str(), std_str(obj->string_variant()->string()).c_str());
        }

        if (built_in_type == BuiltIn_DateTime) {
            double unix_timestamp = winFiletimeToUnixTime(obj->datetime_variant());
            printf("%s DateTime: %s\n", indent(indent_width).c_str(), unixTimestampToString(unix_timestamp).c_str());
        }

        if (built_in_type == BuiltIn_Guid) {
            string guidToGuidstring(const_bytestring data1, const_bytestring data2, const_bytestring data3, const_bytestring data4);

            string guidAsString = guidToGuidstring(obj->guid_variant()->data1(),
                                                   obj->guid_variant()->data2(),
                                                   obj->guid_variant()->data3(),
                                                   obj->guid_variant()->data4());

            printf("%s Guid: %s\n", indent(indent_width).c_str(), guidAsString.c_str());
        }

        if (built_in_type == BuiltIn_ByteString) {
            printf("%s ByteString: %s\n", indent(indent_width).c_str(), bytestringToHexstring(obj->bytestring_variant()->byteString()).c_str());
        }

        if (built_in_type == BuiltIn_NodeId) {
            printf("%s NodeId:\n", indent(indent_width).c_str());
            printOpcUA_NodeId(indent_width + 1, obj->nodeid_variant());
        }

        if (built_in_type == BuiltIn_ExpandedNodeId) {
            printf("%s ExpandedNodeId:\n", indent(indent_width).c_str());
            printOpcUA_ExpandedNodeId(indent_width + 1, obj->expanded_nodeid_variant());
        }

        if (built_in_type == BuiltIn_StatusCode) {
            printf("%s StatusCode: 0x%08x\n", indent(indent_width).c_str(), obj->status_code_variant());
        }

        if (built_in_type == BuiltIn_QualifiedName) {
            printf("%s QualifiedName:\n", indent(indent_width).c_str());
            printOpcUA_QualifiedName(indent_width + 1, obj->qualified_name_variant());
        }

        if (built_in_type == BuiltIn_LocalizedText) {
            printf("%s LocalizedText:\n", indent(indent_width).c_str());
            printOpcUA_LocalizedText(indent_width + 1, obj->localized_text_variant());
        }

        if (built_in_type == BuiltIn_ExtensionObject) {
            printf("%s ExtensionObject:\n", indent(indent_width).c_str());
            printOpcUA_ExtensionObject(indent_width + 1, obj->extension_object_variant());
        }

        if (built_in_type == BuiltIn_DataValue) {
            printf("%s DataValue:\n", indent(indent_width).c_str());
            printOpcUA_DataValue(indent_width + 1, obj->datavalue_variant());
        }

        if (built_in_type == BuiltIn_DiagnosticInfo) {
            printf("%s DiagnosticInfo:\n", indent(indent_width).c_str());
            printOpcUA_DiagInfo(indent_width + 1, obj->diag_info_variant());
        }

        if (built_in_type == BuiltIn_Float) {
            printf("%s Float: %f\n", indent(indent_width).c_str(), bytestringToFloat(obj->float_variant()));
        }

        if (built_in_type == BuiltIn_Double) {
            printf("%s Double: %f\n", indent(indent_width).c_str(), bytestringToDouble(obj->double_variant()));
        }

    }

    void printOpcUA_VariantDataArray(int indent_width, uint8_t encoding_mask, OpcUA_VariantData_Array *obj) {
        for (int i = 0; i < obj->array_length(); i++) {
            printf("%s [%d]: ", indent(indent_width).c_str(), i);
            printOpcUA_VariantData(indent_width + 1, getVariantBuiltInDataType(encoding_mask), obj->array()->at(i));
        }
    }

    void printOpcUA_VariantDataMultiDimArray(int indent_width, uint8_t encoding_mask, OpcUA_VariantData_MultiDim_Array *obj) {
        // printf("%s VariantDataMultiDimArray:\n", indent(indent_width).c_str());

        printOpcUA_VariantDataArray(indent_width + 1, encoding_mask, obj->array());

        // Array Dimension
        printf("%s ArrayDimensions\n", indent(indent_width).c_str());
        printf("%s ArraySize: %d\n", indent(indent_width + 1).c_str(), obj->array_dimensions_length());
        for (int i = 0; i < obj->array_dimensions_length(); i++) {
            printf("%s Int32: %d\n", indent(indent_width + 1).c_str(), obj->array_dimensions()->at(i));
        }

    }

    void printOpcUA_QualifiedName(int indent_width, OpcUA_QualifiedName *obj) {
        printf("%s NamespaceIndex: %d\n", indent(indent_width).c_str(), obj->namespace_index());
        printf("%s Name: %s\n", indent(indent_width).c_str(), std_str(obj->name()->string()).c_str());
    }

    void printOpcUA_LocalizedText(int indent_width, OpcUA_LocalizedText *obj) {
        if (isBitSet(obj->encoding_mask(), localizedTextHasLocale)) {
            printf("%s Locale: %s\n", indent(indent_width).c_str(), std_str(obj->locale()->string()).c_str());
        } else {
            printf("%s Locale: Empty\n", indent(indent_width).c_str());
        }

        if (isBitSet(obj->encoding_mask(), localizedTextHasText)) {
            printf("%s Text: %s\n", indent(indent_width).c_str(), std_str(obj->text()->string()).c_str());
        } else {
            printf("%s Text: Empty\n", indent(indent_width).c_str());
        }
    }
%}