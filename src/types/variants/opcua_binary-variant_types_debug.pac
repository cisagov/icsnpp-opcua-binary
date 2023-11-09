## opcua_binary-variant_types_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debugging functions for generic OPCUA variant types.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printOpcUA_DataValue(int indent_width, OpcUA_DataValue *obj);
    void printOpcUA_Variant(int indent_width, OpcUA_Variant *obj);
    void printOpcUA_VariantData(int indent_width, uint32_t built_in_type, OpcUA_VariantData *obj);
    void printOpcUA_VariantDataArray(int indent_width, uint8_t encoding_mask, OpcUA_VariantData_Array *obj);
    void printOpcUA_VariantDataMultiDimArray(int indent_width, uint8_t encoding_mask, OpcUA_VariantData_MultiDim_Array *obj);
%}

%code{
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
            printf("%s Int64: %ld\n", indent(indent_width).c_str(), obj->int64_variant());
        }

        if (built_in_type == BuiltIn_Uint64) {
            printf("%s UInt64: %lu\n", indent(indent_width).c_str(), obj->uint64_variant());
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
%}
