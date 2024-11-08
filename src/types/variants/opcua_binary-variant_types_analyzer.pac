## opcua_binary-variant_types_ananlyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer utilitiy functions for the variants types.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void flattenOpcUA_DataValue(OPCUA_Binary_Conn *connection, OpcUA_DataValue *data_value, zeek::RecordValPtr service_object, uint32 offset, uint32 status_code_source, uint32 variant_source, bool is_orig);
    void flattenOpcUA_DataVariant(OPCUA_Binary_Conn *connection, OpcUA_Variant *data_variant, string service_object_variant_data_link_id, uint32 variant_source, bool is_orig);
%}

%code{
    void flattenOpcUA_DataValue(OPCUA_Binary_Conn *connection, OpcUA_DataValue *data_value, zeek::RecordValPtr service_object, uint32 offset, uint32 status_code_source, uint32 variant_source, bool is_orig) {

        // Data Value Encoding Mask
        service_object->Assign(offset, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(data_value->encoding_mask())));

        // DataValue
        if (data_value->has_value_case_index()) {
            std::string service_object_variant_data_link_id = generateId();
            service_object->Assign(offset + 6, zeek::make_intrusive<zeek::StringVal>(service_object_variant_data_link_id));
            flattenOpcUA_DataVariant(connection, data_value->value(), service_object_variant_data_link_id, variant_source, is_orig);
        }

        // StatusCode
        if (data_value->has_status_code_case_index()) {
            uint32_t status_code_level   = 0;
            string status_code_link_id = generateId();
            service_object->Assign(offset + 1, zeek::make_intrusive<zeek::StringVal>(status_code_link_id));
            generateStatusCodeEvent(connection, service_object->GetField(offset + 1), status_code_source, data_value->status_code(), status_code_level, is_orig);
        }

        // SourceTimestamp
        if (data_value->has_source_timestamp_case_index()) {
            double unix_timestamp = winFiletimeToUnixTime(data_value->source_timestamp());
            service_object->Assign(offset + 2, zeek::make_intrusive<zeek::TimeVal>(unix_timestamp));
        }

        // SourecePicoSeconds
        if (data_value->has_source_pico_sec_case_index()) {
            service_object->Assign(offset + 3, zeek::val_mgr->Count(data_value->source_pico_sec()));
        }

        // ServerTimeStamp
        if (data_value->has_server_timestamp_case_index()) {
            double unix_timestamp = winFiletimeToUnixTime(data_value->server_timestamp());
            service_object->Assign(offset + 4, zeek::make_intrusive<zeek::TimeVal>(unix_timestamp));
        }

        // ServerPicoSeconds
        if (data_value->has_server_pico_sec_case_index()) {
            service_object->Assign(offset + 5, zeek::val_mgr->Count(data_value->server_pico_sec()));
        }

        return;
    }

    void flattenOpcUA_DataVariant(OPCUA_Binary_Conn *connection, OpcUA_Variant *data_variant, string service_object_variant_data_link_id, uint32 variant_source, bool is_orig) {
        zeek::RecordValPtr variant_metadata = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::VariantMetadata);

        // Source & Destination
        const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
        const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);
        
        variant_metadata = assignSourceDestination(is_orig, variant_metadata, id_val);

        variant_metadata->Assign(VARIANT_DATA_SOURCE_LINK_ID_IDX, zeek::make_intrusive<zeek::StringVal>(service_object_variant_data_link_id));
        
        variant_metadata->Assign(VARIANT_DATA_SOURCE_IDX, zeek::val_mgr->Count(variant_source));
        variant_metadata->Assign(VARIANT_DATA_SOURCE_STR_IDX, zeek::make_intrusive<zeek::StringVal>(VARIANT_SRC_MAP.find(variant_source)->second));

        variant_metadata->Assign(VARIANT_ENCODING_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(data_variant->encoding_mask())));

        // Variant Type
        uint32_t variant_data_type = getVariantDataType(data_variant->encoding_mask());
        variant_metadata->Assign(VARIANT_TYPE_IDX, zeek::val_mgr->Count(variant_data_type));
        variant_metadata->Assign(VARIANT_TYPE_STR_IDX, zeek::make_intrusive<zeek::StringVal>(VARIANT_DATA_TYPES_MAP.find(variant_data_type)->second));
        
        // Built-in Type
        uint32_t built_in_data_type = getVariantBuiltInDataType(data_variant->encoding_mask());
        variant_metadata->Assign(VARIANT_BUILT_IN_DATA_TYPE_IDX, zeek::val_mgr->Count(built_in_data_type));
        variant_metadata->Assign(VARIANT_BUILT_IN_DATA_TYPE_STR_IDX, zeek::make_intrusive<zeek::StringVal>(BUILT_IN_DATA_TYPES_MAP.find(built_in_data_type)->second));
        
        //  Variant Data Link Id
        std::string variant_data_link_id = generateId();
        variant_metadata->Assign(VARIANT_DATA_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(variant_data_link_id));

        // Single-dimmensional array
        if (variant_data_type == variantIsArray) {
            variant_metadata->Assign(VARIANT_DATA_ARRAY_DIM_IDX, zeek::val_mgr->Count(data_variant->variant_array()->array_length()));
        }

        // Multi-dimensional array
        if (variant_data_type == VariantIsMultiDimensionalArray) {
            variant_metadata->Assign(VARIANT_DATA_ARRAY_DIM_IDX, zeek::val_mgr->Count(data_variant->variant_multidim_array()->array_dimensions_length()));

            // ReadArrayDimsLink
            string array_dim_link_id = generateId();
            variant_metadata->Assign(VARIANT_DATA_ARRAY_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(array_dim_link_id));

            // ReadArrayDims
            for (int j=0; j<data_variant->variant_multidim_array()->array_dimensions_length(); j++) {
                zeek::RecordValPtr variant_array_dims = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::VariantArrayDims);

                // Source & Destination
                const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
                const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);
        
                variant_array_dims = assignSourceDestination(is_orig, variant_array_dims, id_val);

                variant_array_dims->Assign(VARIANT_ARRAY_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(array_dim_link_id));
                variant_array_dims->Assign(VARIANT_DIMENSION_IDX, zeek::val_mgr->Count(data_variant->variant_multidim_array()->array_dimensions()->at(j)));

                zeek::BifEvent::enqueue_opcua_binary_variant_array_dims_event(connection->bro_analyzer(),
                                                                              connection->bro_analyzer()->Conn(),
                                                                              variant_array_dims);
            }

        }
        zeek::BifEvent::enqueue_opcua_binary_variant_metadata_event(connection->bro_analyzer(),
                                                                    connection->bro_analyzer()->Conn(),
                                                                    variant_metadata);

        int array_length = 1;
        vector<OpcUA_VariantData *> *variant_data_array = new vector<OpcUA_VariantData *>();
        if (variant_data_type == VariantIsValue_Key) {
            variant_data_array->push_back(data_variant->variant_value());
        }
        else if (variant_data_type == VariantIsArray_Key) { 
            array_length = data_variant->variant_array()->array_length();
            variant_data_array = data_variant->variant_array()->array();
        } else if (variant_data_type == VariantIsMultiDimensionalArray) {
            variant_data_array = data_variant->variant_multidim_array()->array()->array();
            array_length = data_variant->variant_multidim_array()->array()->array_length();
        }

        string variant_status_code_link_id  = generateId();
        string variant_diag_info_link_id    = generateId();
        string variant_data_ext_obj_link_id = generateId();
        for (int i=0;i<array_length;i++) {
            // Link up ReadVariantData
            zeek::RecordValPtr variant_data = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::VariantData);

            // Source & Destination
            const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
            const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);
        
            variant_data = assignSourceDestination(is_orig, variant_data, id_val);

            variant_data->Assign(VARIANT_DATA_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(variant_data_link_id));


            switch(built_in_data_type) {

                case Boolean_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->boolean_variant()));
                    break;
                case SByte_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_SIGNED_NUMERIC_IDX, zeek::val_mgr->Int(variant_data_array->at(i)->sbyte_variant()));
                    break;
                case Byte_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->byte_variant()));
                    break;
                case Int16_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_SIGNED_NUMERIC_IDX, zeek::val_mgr->Int(variant_data_array->at(i)->int16_variant()));
                    break;
                case Uint16_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->uint16_variant()));
                    break;
                case Int32_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_SIGNED_NUMERIC_IDX, zeek::val_mgr->Int(variant_data_array->at(i)->int32_variant()));
                    break;
                case Uint32_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->uint32_variant()));
                    break;
                case Int64_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_SIGNED_NUMERIC_IDX, zeek::val_mgr->Int(variant_data_array->at(i)->int64_variant()));
                    break;
                case Uint64_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->uint64_variant()));
                    break;
                case StatusCode_Key:{
                    // Src link for the variant_data
                    variant_data->Assign(VARIANT_DATA_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(variant_status_code_link_id));

                    // ReadStatusCode link log file
                    string status_code_link_id = generateId();
                

                    int status_code_level = 0;
                    generateStatusCodeEvent(connection, variant_data->GetField(VARIANT_DATA_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_Variant_Key, variant_data_array->at(i)->status_code_variant(), status_code_level, is_orig);

                    }
                    break;
                case DiagnosticInfo_Key: {
                    // Src link for the variant_data
                    variant_data->Assign(VARIANT_DATA_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(variant_diag_info_link_id));
            
                    uint32 innerDiagLevel = 0;
                    vector<OpcUA_String *>  *stringTable = NULL;
                    generateDiagInfoEvent(connection, variant_data->GetField(VARIANT_DATA_DIAG_INFO_LINK_ID_SRC_IDX), variant_data_array->at(i)->diag_info_variant(), stringTable, innerDiagLevel, StatusCode_Variant_DiagInfo_Key, is_orig, DiagInfo_Read_Key);
                    }
                    break;
                case Float_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_DECIMAL_IDX, zeek::make_intrusive<zeek::DoubleVal>(bytestringToFloat(variant_data_array->at(i)->float_variant())));
                    break;
                case Double_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_DECIMAL_IDX, zeek::make_intrusive<zeek::DoubleVal>(bytestringToDouble(variant_data_array->at(i)->double_variant())));
                    break;
                case DateTime_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_TIME_IDX, zeek::make_intrusive<zeek::TimeVal>(variant_data_array->at(i)->datetime_variant()));
                    break;
                case NodeId_Key:
                    flattenOpcUA_NodeId(variant_data, variant_data_array->at(i)->nodeid_variant(), VARIANT_DATA_NODE_ID_ENCODING_MASK_IDX);
                    break;
                case ExpandedNodeId_Key:
                    flattenOpcUA_ExpandedNodeId(variant_data, variant_data_array->at(i)->expanded_nodeid_variant(), VARIANT_DATA_NODE_ID_ENCODING_MASK_IDX);
                    break;
                case QualifiedName_Key:
                    variant_data->Assign(VARIANT_DATA_ENCODING_NAME_ID_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->qualified_name_variant()->namespace_index()));
                    variant_data->Assign(VARIANT_DATA_ENCODING_NAME_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(variant_data_array->at(i)->qualified_name_variant()->name()->string())));
                    break;
                case LocalizedText_Key:
                    variant_data->Assign(VARIANT_DATA_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(variant_data_array->at(i)->localized_text_variant()->encoding_mask())));
                    if (isBitSet(variant_data_array->at(i)->localized_text_variant()->encoding_mask(), localizedTextHasLocale) && variant_data_array->at(i)->localized_text_variant()->locale()->length() > 0) {
                        variant_data->Assign(VARIANT_DATA_LOCALE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(variant_data_array->at(i)->localized_text_variant()->locale()->string())));
                    }
                    if (isBitSet(variant_data_array->at(i)->localized_text_variant()->encoding_mask(), localizedTextHasText) && variant_data_array->at(i)->localized_text_variant()->text()->length() > 0) {
                        variant_data->Assign(VARIANT_DATA_TEXT_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(variant_data_array->at(i)->localized_text_variant()->text()->string())));
                    }
                    break;
                case ExtensionObject_Key: {
                    // Src link for the variant_data
                    variant_data->Assign(VARIANT_DATA_EXT_OBJ_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(variant_data_ext_obj_link_id));

                    // ReadExtensionObjectLink log file
                    string ext_object_link_id = generateId();

                    // ReadExtensionObject log file
                    OpcUA_ExtensionObject *obj = variant_data_array->at(i)->extension_object_variant();
                    zeek::RecordValPtr variant_extension_object = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::VariantExtensionObject);

                    // Source & Destination
                    const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
                    const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);
        
                    variant_extension_object = assignSourceDestination(is_orig, variant_extension_object, id_val);

                    variant_extension_object->Assign(VARIANT_EXT_OBJ_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(ext_object_link_id));

                    flattenOpcUA_NodeId(variant_extension_object, obj->type_id(), VARIANT_EXT_OBJ_NODE_ID_ENCODING_MASK);

                    string ext_obj_type_id_str = EXTENSION_OBJECT_ID_MAP.find(getExtensionObjectId(obj->type_id()))->second;
                    variant_extension_object->Assign(VARIANT_EXT_OBJ_TYPE_ID_STR_IDX, zeek::make_intrusive<zeek::StringVal>(ext_obj_type_id_str));

                    variant_extension_object->Assign(VARIANT_EXT_OBJ_ENCODING_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(obj->encoding())));

                    zeek::BifEvent::enqueue_opcua_binary_variant_extension_object_event(connection->bro_analyzer(),
                                                                                        connection->bro_analyzer()->Conn(),
                                                                                        variant_extension_object);

                    }
                    break;
                case DataValue_Key: {
                   
                    zeek::RecordValPtr variant_data_value = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::VariantDataValue);

                    // Source & Destination
                    const zeek::RecordValPtr conn_val = connection->bro_analyzer()->Conn()->GetVal();
                    const zeek::RecordValPtr id_val = conn_val->GetField<zeek::RecordVal>(0);
        
                    variant_data_value = assignSourceDestination(is_orig, variant_data_value, id_val);

                    // Set the link into OPCUA_Binary::VariantDataValue
                    string variant_data_value_link_id = generateId();
                    variant_data_value->Assign(VARIANT_DATA_VALUE_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(variant_data_value_link_id));

                    variant_data->Assign(VARIANT_DATA_VALUE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(variant_data_value_link_id));

                    // Recursively call ourselves
                    flattenOpcUA_DataValue(connection, variant_data_array->at(i)->datavalue_variant(), variant_data_value, VARIANT_DATA_VALUE_ENCODING_MASK_IDX, StatusCode_Variant_Key, getInnerVariantSource(variant_source), is_orig);
                    zeek::BifEvent::enqueue_opcua_binary_variant_data_value_event(connection->bro_analyzer(),
                                                                                  connection->bro_analyzer()->Conn(),
                                                                                  variant_data_value);
                    }
                    break;
                case Variant_Key: {
                // 
                    // The processing for a OpcUA_DataVariant that is itself an OpcUA_DataVariant is to recursively call the data value
                    // processing and link into the OPCUA_Binary::VariantMetadata log file.
                    // 

                    // Set the link into OPCUA_Binary::VariantMetadata
                    string variant_metadata_link_id = generateId();
                    variant_data->Assign(VARIANT_DATA_VARIANT_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(variant_metadata_link_id));


                    // Recursively call ourselves
                    flattenOpcUA_DataVariant(connection, variant_data_array->at(i)->datavalue_variant()->value(), variant_metadata_link_id, getInnerVariantSource(variant_source), is_orig);
                    }
                    break;
                case String_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_STRING_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(variant_data_array->at(i)->string_variant()->string())));
                    break;
                case Guid_Key: {
                    OpcUA_Guid *guid_ptr = variant_data_array->at(i)->guid_variant();
                    string guid_str = guidToGuidstring(guid_ptr->data1(), guid_ptr->data2(), guid_ptr->data3(), guid_ptr->data4());
                    variant_data->Assign(VARIANT_DATA_VALUE_STRING_IDX, zeek::make_intrusive<zeek::StringVal>(guid_str));
                    }
                    break;
                case ByteString_Key:
                    variant_data->Assign(VARIANT_DATA_VALUE_STRING_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(variant_data_array->at(i)->bytestring_variant()->byteString())));
                    break;
            }

        zeek::BifEvent::enqueue_opcua_binary_variant_data_event(connection->bro_analyzer(),
                                                                     connection->bro_analyzer()->Conn(),
                                                                     variant_data);
        
        }
    }

%}