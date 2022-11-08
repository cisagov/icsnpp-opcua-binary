
## opcua_binary-read_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the read service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void analyze_DataValue(OPCUA_Binary_Conn *connection, OpcUA_DataValue *data_value, zeek::RecordValPtr read_results) ;
    void analyze_DataVariant(OPCUA_Binary_Conn *connection, OpcUA_Variant *data_variant, string read_results_variant_data_link_id);
%}

%code{
    void analyze_DataValue(OPCUA_Binary_Conn *connection, OpcUA_DataValue *data_value, zeek::RecordValPtr read_results) {

        data_value->value()->encoding_mask();
        read_results->Assign(READ_RES_DATA_VARIANT_ENCODING_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(data_value->value()->encoding_mask())));

        // Variant Type
        uint32_t variant_data_type = getVariantDataType(data_value->value()->encoding_mask());
        read_results->Assign(READ_RES_DATA_VARIANT_TYPE_IDX, zeek::val_mgr->Count(variant_data_type));
        read_results->Assign(READ_RES_DATA_VARIANT_TYPE_STR_IDX, zeek::make_intrusive<zeek::StringVal>(VARIANT_DATA_TYPES_MAP.find(variant_data_type)->second));

        // Built-in Type
        uint32_t built_in_data_type = getVariantBuiltInDataType(data_value->value()->encoding_mask());
        read_results->Assign(READ_RES_BUILT_IN_DATA_TYPE_IDX, zeek::val_mgr->Count(built_in_data_type));
        read_results->Assign(READ_RES_BUILT_IN_DATA_TYPE_STR_IDX, zeek::make_intrusive<zeek::StringVal>(BUILT_IN_DATA_TYPES_MAP.find(built_in_data_type)->second));

        // Read Variant Data Link Id
        string read_results_variant_data_link_id = generateId();
        read_results->Assign(READ_RES_RESULTS_VARIANT_DATA_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(read_results_variant_data_link_id));

        analyze_DataVariant(connection, data_value->value(), read_results_variant_data_link_id);

        return;
    }

    void analyze_DataVariant(OPCUA_Binary_Conn *connection, OpcUA_Variant *data_variant, string read_results_variant_data_link_id) {
        // Variant Type
        uint32_t variant_data_type = getVariantDataType(data_variant->encoding_mask());

        // Built-in Type
        uint32_t built_in_data_type = getVariantBuiltInDataType(data_variant->encoding_mask());

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


        printf("read_results_variant_data_link_id: %s\n", read_results_variant_data_link_id.c_str());
        string read_status_code_link_id     = generateId();
        string read_diag_info_link_id       = generateId();
        string variant_data_ext_obj_link_id = generateId();
        for (int i=0;i<array_length;i++) {
            string read_variant_data_link_id = generateId();

            // Link up ReadVariantDataLink
            zeek::RecordValPtr read_variant_data_link = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadVariantDataLink);
            read_variant_data_link->Assign(READ_RES_RESULTS_VARIANT_DATA_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(read_results_variant_data_link_id));
            read_variant_data_link->Assign(READ_RES_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(read_variant_data_link_id));

            zeek::BifEvent::enqueue_opcua_binary_read_variant_data_link_event(connection->bro_analyzer(),
                                                                              connection->bro_analyzer()->Conn(),
                                                                              read_variant_data_link);

            // Link up ReadVariantData
            zeek::RecordValPtr read_variant_data = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadVariantData);
            read_variant_data->Assign(READ_RES_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(read_variant_data_link_id));

            // Multi-dimensional array
            if (variant_data_type == VariantIsMultiDimensionalArray) {
                read_variant_data->Assign(READ_RES_VARIANT_DATA_ARRAY_DIM_IDX, zeek::val_mgr->Count(data_variant->variant_multidim_array()->array_dimensions_length()));

                // ReadArrayDimsLink
                string variant_data_array_dim_link_id = generateId();
                string array_dim_link_id = generateId();
                read_variant_data->Assign(READ_RES_VARIANT_DATA_ARRAY_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(variant_data_array_dim_link_id));

                zeek::RecordValPtr read_array_dims_link = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadArrayDimsLink);
                read_array_dims_link->Assign(READ_RES_VARIANT_DATA_ARRAY_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(variant_data_array_dim_link_id));
                read_array_dims_link->Assign(READ_RES_ARRAY_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(array_dim_link_id));

                zeek::BifEvent::enqueue_opcua_binary_read_read_array_dims_link_event(connection->bro_analyzer(),
                                                                                     connection->bro_analyzer()->Conn(),
                                                                                     read_array_dims_link);

                // ReadArrayDims
                for (int j=0; j<data_variant->variant_multidim_array()->array_dimensions_length(); j++) {
                    zeek::RecordValPtr read_array_dims = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadArrayDims);
                    read_array_dims->Assign(READ_RES_ARRAY_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(array_dim_link_id));
                    read_array_dims->Assign(READ_RES_DIMENSION_IDX, zeek::val_mgr->Count(data_variant->variant_multidim_array()->array_dimensions()->at(j)));

                    zeek::BifEvent::enqueue_opcua_binary_read_read_array_dims_event(connection->bro_analyzer(),
                                                                                    connection->bro_analyzer()->Conn(),
                                                                                    read_array_dims);

                }
                

            }

// Array Dimensions
//    #define READ_RES_VARIANT_DATA_ARRAY_DIM_IDX                24 
//    #define READ_RES_VARIANT_DATA_ARRAY_LINK_ID_SRC_IDX        25 // Link into OPCUA_Binary::ReadArrayDimsLink
/*
        # Array Dimensions
        variant_data_array_dim         : count &log &optional;
        variant_data_array_dim_link_id : string &log &optional; # Link into OPCUA_Binary::ReadArrayDimsLink
    };

    type OPCUA_Binary::ReadArrayDimsLink: record {
        ts                             : time    &log;
        uid                            : string  &log;
        id                             : conn_id &log;
        variant_data_array_dim_link_id : string  &log; # Link back into OPCUA_Binary::ReadVariantData
        array_dim_link_id              : string  &log; # Link into OPCUA_Binary::ReadArrayDims
    };

    type OPCUA_Binary::ReadArrayDims: record {
        ts                : time    &log;
        uid               : string  &log;
        id                : conn_id &log;
        array_dim_link_id : string  &log; # Link back into OPCUA_Binary::ReadArrayDimsLink
        dimension         : count   &log; 
    };

type OpcUA_VariantData_MultiDim_Array(encoding_mask : uint8) = record {
    array        : OpcUA_VariantData_Array(encoding_mask);

    array_dimensions_length : int32;
    array_dimensions        : int32[$context.flow.bind_length(array_dimensions_length)];
}

*/


            switch(built_in_data_type) {

                case Boolean_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->boolean_variant()));
                    break;
                case SByte_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_SIGNED_NUMERIC_IDX, zeek::val_mgr->Int(variant_data_array->at(i)->sbyte_variant()));
                    break;
                case Byte_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->byte_variant()));
                    break;
                case Int16_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_SIGNED_NUMERIC_IDX, zeek::val_mgr->Int(variant_data_array->at(i)->int16_variant()));
                    break;
                case Uint16_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->uint16_variant()));
                    break;
                case Int32_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_SIGNED_NUMERIC_IDX, zeek::val_mgr->Int(variant_data_array->at(i)->int32_variant()));
                    break;
                case Uint32_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->uint32_variant()));
                    break;
                case Int64_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_SIGNED_NUMERIC_IDX, zeek::val_mgr->Int(variant_data_array->at(i)->int64_variant()));
                    break;
                case Uint64_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_UNSIGNED_NUMERIC_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->uint64_variant()));
                    break;
                case StatusCode_Key:{
                    // Src link for the read_variant_data
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(read_status_code_link_id));

                    // ReadStatusCode link log file
                    string status_code_link_id = generateId();
                    zeek::RecordValPtr read_status_code = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadStatusCode);
                    read_status_code->Assign(READ_RES_VARIANT_DATA_STATUS_CODE_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(read_status_code_link_id));
                    read_status_code->Assign(READ_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(status_code_link_id));
                    zeek::BifEvent::enqueue_opcua_binary_read_status_code_event(connection->bro_analyzer(),
                                                                                connection->bro_analyzer()->Conn(),
                                                                                read_status_code);

                    int status_code_level = 0;
                    generateStatusCodeEvent(connection, read_status_code->GetField(READ_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_Read_Key, variant_data_array->at(i)->status_code_variant(), status_code_level);

                    }
                    break;
                case DiagnosticInfo_Key: {
                    // Src link for the read_variant_data
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(read_diag_info_link_id));

                    // ReadDiagnosticInfo link log file
                    string diag_info_link_id = generateId();
                    zeek::RecordValPtr read_diagnostic_info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadDiagnosticInfo);
                    read_diagnostic_info->Assign(READ_RES_DIAG_INFO_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(read_diag_info_link_id));
                    read_diagnostic_info->Assign(READ_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diag_info_link_id));
                    zeek::BifEvent::enqueue_opcua_binary_read_diagnostic_info_event(connection->bro_analyzer(),
                                                                                    connection->bro_analyzer()->Conn(),
                                                                                    read_diagnostic_info);

                    uint32 innerDiagLevel = 0;
                    vector<OpcUA_String *>  *stringTable = NULL;
                    generateDiagInfoEvent(connection, read_diagnostic_info->GetField(READ_DIAG_INFO_LINK_ID_SRC_IDX), variant_data_array->at(i)->diag_info_variant(), stringTable, innerDiagLevel, StatusCode_Read_DiagInfo_Key, DiagInfo_Read_Key);
                    }
                    break;
                case Float_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_DECIMAL_IDX, zeek::make_intrusive<zeek::DoubleVal>(bytestringToFloat(variant_data_array->at(i)->float_variant())));
                    break;
                case Double_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_DECIMAL_IDX, zeek::make_intrusive<zeek::DoubleVal>(bytestringToDouble(variant_data_array->at(i)->double_variant())));
                    break;
                case DateTime_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_TIME_IDX, zeek::make_intrusive<zeek::TimeVal>(variant_data_array->at(i)->datetime_variant()));
                    break;
                case NodeId_Key:
                    flattenOpcUA_NodeId(read_variant_data, variant_data_array->at(i)->nodeid_variant(), READ_RES_VARIANT_DATA_NODE_ID_ENCODING_MASK_IDX);
                    break;
                case ExpandedNodeId_Key:
                    flattenOpcUA_ExpandedNodeId(read_variant_data, variant_data_array->at(i)->expanded_nodeid_variant(), READ_RES_VARIANT_DATA_NODE_ID_ENCODING_MASK_IDX);
                    break;
                case QualifiedName_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_ENCODING_NAME_ID_IDX, zeek::val_mgr->Count(variant_data_array->at(i)->qualified_name_variant()->namespace_index()));
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_ENCODING_NAME_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(variant_data_array->at(i)->qualified_name_variant()->name()->string())));
                    break;
                case LocalizedText_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(variant_data_array->at(i)->localized_text_variant()->encoding_mask())));
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_LOCALE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(variant_data_array->at(i)->localized_text_variant()->locale()->string())));
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_TEXT_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(variant_data_array->at(i)->localized_text_variant()->text()->string())));
                    break;
                case ExtensionObject_Key: {
                    // Src link for the read_variant_data
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_EXT_OBJ_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(variant_data_ext_obj_link_id));

                    // ReadExtensionObjectLink log file
                    string ext_object_link_id = generateId();
                    zeek::RecordValPtr read_extension_object_link = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadExtensionObjectLink);
                    read_extension_object_link->Assign(READ_RES_VARIANT_DATA_EXT_OBJ_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(variant_data_ext_obj_link_id));
                    read_extension_object_link->Assign(READ_RES_EXT_OBJ_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(ext_object_link_id));
                    zeek::BifEvent::enqueue_opcua_binary_read_extension_object_link_event(connection->bro_analyzer(),
                                                                                          connection->bro_analyzer()->Conn(),
                                                                                          read_extension_object_link);

                    // ReadExtensionObject log file
                    OpcUA_ExtensionObject *obj = variant_data_array->at(i)->extension_object_variant();
                    zeek::RecordValPtr read_extension_object = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadExtensionObject);

                    read_extension_object->Assign(READ_RES_EXT_OBJ_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(ext_object_link_id));

                    flattenOpcUA_NodeId(read_extension_object, obj->type_id(), READ_RES_EXT_OBJ_NODE_ID_ENCODING_MASK);

                    string ext_obj_type_id_str = EXTENSION_OBJECT_ID_MAP.find(getExtensionObjectId(obj->type_id()))->second;
                    read_extension_object->Assign(READ_RES_EXT_OBJ_TYPE_ID_STR_IDX, zeek::make_intrusive<zeek::StringVal>(ext_obj_type_id_str));

                    read_extension_object->Assign(READ_RES_EXT_OBJ_ENCODING_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(obj->encoding())));

                    zeek::BifEvent::enqueue_opcua_binary_read_extension_object_event(connection->bro_analyzer(),
                                                                                     connection->bro_analyzer()->Conn(),
                                                                                     read_extension_object);

                    }
                    break;
                case DataValue_Key: {
                    string data_value_link_id = generateId();
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_DATA_VALUE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(data_value_link_id));
                    printf("\tLOOK: %s\n", data_value_link_id.c_str());

                    // Recursively call ourselves
                    analyze_DataVariant(connection, variant_data_array->at(i)->datavalue_variant()->value(), data_value_link_id);
                    }
                    break;
                case String_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_STRING_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(variant_data_array->at(i)->string_variant()->string())));
                    break;
                case Guid_Key: {
                    OpcUA_Guid *guid_ptr = variant_data_array->at(i)->guid_variant();
                    string guid_str = guidToGuidstring(guid_ptr->data1(), guid_ptr->data2(), guid_ptr->data3(), guid_ptr->data4());
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_STRING_IDX, zeek::make_intrusive<zeek::StringVal>(guid_str));
                    }
                    break;
                case ByteString_Key:
                    read_variant_data->Assign(READ_RES_VARIANT_DATA_VALUE_STRING_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(variant_data_array->at(i)->bytestring_variant()->byteString())));
                    break;
            }

            zeek::BifEvent::enqueue_opcua_binary_read_variant_data_event(connection->bro_analyzer(),
                                                                         connection->bro_analyzer()->Conn(),
                                                                         read_variant_data);

            // If the built in data type is itself a DataValue; recurse?

        }
        printf("\n");
    }
/*
        read_results_variant_data_link_id  : string &log &optional; # Link into OPCUA_Binary::ReadVariantDataLink log
    };

    type OPCUA_Binary::ReadVariantDataLink: record {
        ts                     : time    &log;
        uid                    : string  &log;
        id                     : conn_id &log;
        read_results_variant_data_link_id : string  &log; # Link back into OPCUA_Binary::ReadResults
        read_variant_data_link_id         : string  &log; # Link into OPCUA_Binary::ReadVariantData
    };

    type OPCUA_Binary::ReadVariantData: record {
        ts                         : time    &log;
        uid                        : string  &log;
        id                         : conn_id &log;
        read_variant_data_link_id  : string  &log; # Link back into OPCUA_Binary::ReadResults

        # OpcUA_Boolean,  OpcUA_SByte,  OpcUA_Byte, etc
        variant_data_value_numeric : count &log &optional;

        # OpcUA_String, OpcUA_Guid, OpcUA_ByteString, etc
        variant_data_value_string  : count &log &optional;

        # OpcUA_NodeId & OpcUA_ExpandedNodeId
        variant_data_node_id_encoding_mask : string &log &optional;
        variant_data_node_id_namespace_idx : count  &log &optional;
        variant_data_node_id_numeric       : count  &log &optional;
        variant_data_node_id_string        : string &log &optional;
        variant_data_node_id_guid          : string &log &optional;
        variant_data_node_id_opaque        : string &log &optional;
        variant_data_node_id_namespace_uri : string &log &optional;
        variant_data_node_id_server_idx    : count  &log &optional; 

        #OpcUA_DateTime
        variant_data_value_time    : time  &log &optional;

        # OpcUA_QualifiedName
        variant_data_encoding_name_idx : count &log &optional;
        variant_data_encoding_name     : string &log &optional;

        # OpcUA_LocalizedText
        variant_data_mask   : string &log &optional;
        variant_data_locale : string &log &optional;
        variant_data_text   : string &log &optional;

        # OpcUA_Float & OpcUA_Double
        variant_data_value_decimal : double &log &optional;

        # OpcUA_StatusCode
        variant_data_status_code_link_id   : string &log &optional; # Link into OPCUA_Binary::ReadStatusCode log

        # OpcUA_DiagnosticInfo
        variant_data_diag_info_link_id     : string &log &optional; # Link into OPCUA_Binary::ReadDiagnosticInfo log

        # Array Dimensions
        variant_data_array_dim         : count &log &optional;
        variant_data_array_dim_link_id : string &log &optional; # Link into OPCUA_Binary::ReadArrayDimsLink

        variant_data_ext_obj_link_id   : string &log &optional; # Link into OPCUA_Binary::ReadExtensionObject
    };

    #define READ_RES_RESULTS_VARIANT_DATA_LINK_ID_SRC_IDX 13 // Id into OPCUA_Binary::ReadVariantDataLink

type OpcUA_Variant = record {
    encoding_mask : uint8;
    body : case($context.flow.get_variant_data_type(encoding_mask)) of {
        variantIsValue                 -> variant_value          : OpcUA_VariantData($context.flow.get_variant_data_built_in_type(encoding_mask));
        variantIsArray                 -> variant_array          : OpcUA_VariantData_Array($context.flow.get_variant_data_built_in_type(encoding_mask));
        variantIsMultiDimensionalArray -> variant_multidim_array : OpcUA_VariantData_MultiDim_Array($context.flow.get_variant_data_built_in_type(encoding_mask));
        default                        -> empty_variant          : empty;
    };
};

type OpcUA_VariantData(built_in_type : uint32) = record {
    body : case(built_in_type) of {
        BuiltIn_Boolean         -> boolean_variant          : OpcUA_Boolean; 
        BuiltIn_SByte           -> sbyte_variant            : int8;
        BuiltIn_Byte            -> byte_variant             : uint8;
        BuiltIn_Int16           -> int16_variant            : int16;
        BuiltIn_Uint16          -> uint16_variant           : uint16;
        BuiltIn_Int32           -> int32_variant            : int32;
        BuiltIn_Uint32          -> uint32_variant           : uint32;
        BuiltIn_Int64           -> int64_variant            : int64;
        BuiltIn_Uint64          -> uint64_variant           : uint64;
        BuiltIn_String          -> string_variant           : OpcUA_String;
        BuiltIn_DateTime        -> datetime_variant         : OpcUA_DateTime;
        BuiltIn_Guid            -> guid_variant             : OpcUA_Guid;
        BuiltIn_ByteString      -> bytestring_variant       : OpcUA_ByteString;
        BuiltIn_NodeId          -> nodeid_variant           : OpcUA_NodeId;
        BuiltIn_ExpandedNodeId  -> expanded_nodeid_variant  : OpcUA_ExpandedNodeId;
        BuiltIn_StatusCode      -> status_code_variant      : OpcUA_StatusCode;
        BuiltIn_QualifiedName   -> qualified_name_variant   : OpcUA_QualifiedName;
        BuiltIn_LocalizedText   -> localized_text_variant   : OpcUA_LocalizedText;
        BuiltIn_ExtensionObject -> extension_object_variant : OpcUA_ExtensionObject;
        BuiltIn_DataValue       -> datavalue_variant        : OpcUA_DataValue;
        BuiltIn_DiagnosticInfo  -> diag_info_variant        : OpcUA_DiagInfo;
        BuiltIn_Float           -> float_variant            : OpcUA_Float;
        BuiltIn_Double          -> double_variant           : OpcUA_Double;
        default                 -> empty_variant_data       : empty;
    };
}
type OpcUA_VariantData_Array(encoding_mask : uint8) = record {
    array_length : int32;
    array        : OpcUA_VariantData(encoding_mask)[$context.flow.bind_length(array_length)];
}

type OpcUA_VariantData_MultiDim_Array(encoding_mask : uint8) = record {
    array        : OpcUA_VariantData_Array(encoding_mask);

    array_dimensions_length : int32;
    array_dimensions        : int32[$context.flow.bind_length(array_dimensions_length)];
}

*/
%}

refine flow OPCUA_Binary_Flow += {

    #
    # ReadRequest
    #
    function deliver_Svc_ReadReq(msg : Read_Req): bool
        %{
        /* Debug
        printf("deliver_Svc_ReadReq - begin\n");
        printReadReq(msg);
        printf("deliver_Svc_ReadReq - end\n");
        */

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr read_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Read);

        // OpcUA_id
        read_req->Assign(READ_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        // Max Age
        read_req->Assign(READ_REQ_MAX_AGE_IDX, zeek::val_mgr->Count(bytestringToDouble(msg->max_age()->duration())));

        // Timestamps to Return
        read_req->Assign(READ_REQ_TIMESTAMPS_TO_RETURN_IDX, zeek::val_mgr->Count(msg->timestamps_to_return()));
        read_req->Assign(READ_REQ_TIMESTAMPS_TO_RETURN_STR_IDX, zeek::make_intrusive<zeek::StringVal>(unixTimestampToString(msg->timestamps_to_return())));

        // Nodes to Read
        if (msg->nodes_to_read_size() > 0) {
            // Link into OpcUA_Binary::ReadNodesToRead
            std::string nodes_to_read_link_id = generateId();
            read_req->Assign(READ_REQ_NODES_TO_READ_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(nodes_to_read_link_id));

            for (int i = 0; i < msg->nodes_to_read_size(); i++) {
                zeek::RecordValPtr nodes_to_read = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadNodesToRead);

                // Link back into OpcUA_Binary::Read
                nodes_to_read->Assign(READ_REQ_NODES_TO_READ_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(nodes_to_read_link_id));

                // Node Id
                flattenOpcUA_NodeId(nodes_to_read, msg->nodes_to_read()->at(i)->node_id(), READ_REQ_NODE_ID_ENCODING_MASK_IDX);

                // Attribute Id
                nodes_to_read->Assign(READ_REQ_ATTRIBUTE_ID_IDX, zeek::val_mgr->Count(msg->nodes_to_read()->at(i)->attribute_id()));
                nodes_to_read->Assign(READ_REQ_ATTRIBUTE_ID_STR_IDX, zeek::make_intrusive<zeek::StringVal>(ATTRIBUTE_ID_MAP.find(msg->nodes_to_read()->at(i)->attribute_id())->second));

                // Index Range
                if (msg->nodes_to_read()->at(i)->index_range()->length() > 0) {
                    nodes_to_read->Assign(READ_REQ_INDEX_RANGE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->nodes_to_read()->at(i)->index_range()->string())));
                }

                // Qualified Name
                nodes_to_read->Assign(READ_REQ_DATA_ENCODING_NAME_ID_IDX, zeek::val_mgr->Count(msg->nodes_to_read()->at(i)->data_encoding()->namespace_index()));
                nodes_to_read->Assign(READ_REQ_DATA_ENCODING_NAME_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->nodes_to_read()->at(i)->data_encoding()->name()->string())));

                // Fire event
                zeek::BifEvent::enqueue_opcua_binary_read_nodes_to_read_event(connection()->bro_analyzer(),
                                                                              connection()->bro_analyzer()->Conn(),
                                                                              nodes_to_read);
            }

        }

        // Fire event
        zeek::BifEvent::enqueue_opcua_binary_read_event(connection()->bro_analyzer(),
                                                        connection()->bro_analyzer()->Conn(),
                                                        read_req);

        return true;
        %}

    #
    # ReadResponse
    #
    function deliver_Svc_ReadRes(msg : Read_Res): bool
        %{
        /* Debug
        printf("deliver_Svc_ReadRes - begin\n");
        printReadRes(msg);
        printf("deliver_Svc_ReadRes - end\n");
        */
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr read_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Read);

        // OpcUA_id
        read_res->Assign(READ_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        // Results
        if (msg->results_size() > 0) {
            string read_results_link_id = generateId(); // Link to tie OCPUA_Binary::Read and OPCUA_Binary::ReadResultsLink together
            string results_link_id      = generateId(); // Link to tie OCPUA_Binary::ReadResultsLink and OPCUA_Binary::ReadResults together

            zeek::RecordValPtr read_results_link = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadResultsLink);


            // Assign the linkage in the OCPUA_Binary::Read and OPCUA_Binary::ResultsLink
            read_res->Assign(READ_RES_RESULTS_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(read_results_link_id));
            read_results_link->Assign(READ_RES_RESULTS_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(read_results_link_id));

            for (int i = 0; i < msg->results_size(); i++) {
                OpcUA_DataValue* data_value = msg->results()->at(i);
                zeek::RecordValPtr read_results = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadResults);

                // Assign the linkage int he OPCUA_Binary::ReadResultsLink and OPCUA_Binary::ReadResults
                read_results_link->Assign(READ_RES_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(results_link_id));
                read_results->Assign(READ_RES_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(results_link_id));

                // Level
                read_results->Assign(READ_RES_LEVEL_IDX, zeek::val_mgr->Count(i));

                // Data Value Encoding Mask
                read_results->Assign(READ_RES_DATA_VALUE_ENCODING_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(data_value->encoding_mask())));

                // DataValue
                if (data_value->has_value_case_index()) {
                    analyze_DataValue(connection(), data_value, read_results);
                }

                // StatusCode
                if (data_value->has_status_code_case_index()) {
                    uint32_t status_code_level   = 0;
                    string status_code_link_id = generateId();
                    read_results->Assign(READ_RES_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(status_code_link_id));
                    generateStatusCodeEvent(connection(), read_results->GetField(READ_RES_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_Read_Key, data_value->status_code(), status_code_level);
                }

                // SourceTimestamp
                if (data_value->has_source_timestamp_case_index()) {
                    double unix_timestamp = winFiletimeToUnixTime(data_value->source_timestamp());
                    read_results->Assign(READ_RES_SOURCE_TIMESTAMP_IDX, zeek::make_intrusive<zeek::TimeVal>(unix_timestamp));
                }

                // SourecePicoSeconds
                if (data_value->has_source_pico_sec_case_index()) {
                    read_results->Assign(READ_RES_SOURCE_PICO_SEC_IDX, zeek::val_mgr->Count(data_value->source_pico_sec()));
                }

                // ServerTimeStamp
                if (data_value->has_server_timestamp_case_index()) {
                    double unix_timestamp = winFiletimeToUnixTime(data_value->server_timestamp());
                    read_results->Assign(READ_RES_SERVER_TIMESTAMP_IDX, zeek::make_intrusive<zeek::TimeVal>(unix_timestamp));
                }

                // ServerPicoSeconds
                if (data_value->has_server_pico_sec_case_index()) {
                    read_results->Assign(READ_RES_SERVER_PICO_SEC_IDX, zeek::val_mgr->Count(data_value->server_pico_sec()));
                }

                // Fire event
                zeek::BifEvent::enqueue_opcua_binary_read_results_event(connection()->bro_analyzer(),
                                                                        connection()->bro_analyzer()->Conn(),
                                                                        read_results);

                results_link_id = generateId();
            }

            // Fire event
            zeek::BifEvent::enqueue_opcua_binary_read_results_link_event(connection()->bro_analyzer(),
                                                                         connection()->bro_analyzer()->Conn(),
                                                                         read_results_link);

        }
/*
*/


        // Diagnostic Information
        if (msg->diagnostic_info_size() > 0) {
            string diagnostic_info_id_link = generateId(); // Link to tie OCPUA_Binary::Read and OPCUA_Binary::ReadDiagnosticInfo together
            string diagnostic_info_id      = generateId(); // Link to tie OCPUA_Binary::ReadDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together

            // Assign the linkage in the OCPUA_Binary::Read
            read_res->Assign(READ_RES_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id_link));

            uint32 innerDiagLevel = 0;
            vector<OpcUA_String *>  *stringTable = NULL;
            for (int i = 0; i < msg->diagnostic_info_size(); i++) {

                // Assign the linkage in the OCPUA_Binary::ReadDiagnosticInfo and enqueue the logging event  
                zeek::RecordValPtr read_res_diagnostic_info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ReadDiagnosticInfo);
                read_res_diagnostic_info->Assign(READ_RES_DIAG_INFO_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id_link));
                read_res_diagnostic_info->Assign(READ_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id));
                zeek::BifEvent::enqueue_opcua_binary_read_diagnostic_info_event(connection()->bro_analyzer(),
                                                                                connection()->bro_analyzer()->Conn(),
                                                                                read_res_diagnostic_info);


                // Process the details of the Diagnostic Information
                generateDiagInfoEvent(connection(), read_res_diagnostic_info->GetField(READ_RES_DIAG_INFO_LINK_ID_SRC_IDX), msg->diagnostic_info()->at(i), stringTable, innerDiagLevel, StatusCode_Read_DiagInfo_Key, DiagInfo_Read_Key);

                // Generate an new link to tie OCPUA_Binary::ActivateSessionDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together
                diagnostic_info_id = generateId();

            }
        }

        // Fire event
        zeek::BifEvent::enqueue_opcua_binary_read_event(connection()->bro_analyzer(),
                                                        connection()->bro_analyzer()->Conn(),
                                                        read_res);


/*

    results_size : int32;
    results      : OpcUA_DataValue[$context.flow.bind_length(results_size)];

    diagnostic_info_size : int32;
    diagnostic_info      : OpcUA_DiagInfo[$context.flow.bind_length(diagnostic_info_size)];





        // Server Nonce
        activate_session_res->Assign(ACTIVATE_SESSION_RES_SERVER_NONCE_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->server_nonce()->byteString())));

        // StatusCode Results
        if (msg->result_size() > 0) {
            uint32_t status_code_level = 0;
            string result_idx = generateId();
            activate_session_res->Assign(ACTIVATE_SESSION_RES_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(result_idx));
            for (int i = 0; i < msg->result_size(); i++) {
                generateStatusCodeEvent(connection(), activate_session_res->GetField(ACTIVATE_SESSION_RES_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_ActivateSession_Key, msg->results()->at(i), status_code_level);
            }
        }

        // Diagnostic Information
        if (msg->diagnostic_info_size() > 0) {
            string diagnostic_info_id_link = generateId(); // Link to tie OCPUA_Binary::ActivateSession and OPCUA_Binary::ActivateSessionDiagnosticInfo together
            string diagnostic_info_id      = generateId(); // Link to tie OCPUA_Binary::ActivateSessionDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together

            // Assign the linkage in the OCPUA_Binary::ActivateSession
            activate_session_res->Assign(ACTIVATE_SESSION_RES_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id_link));

            uint32 innerDiagLevel = 0;
            vector<OpcUA_String *>  *stringTable = NULL;
            for (int i = 0; i < msg->diagnostic_info_size(); i++) {

                // Assign the linkage in the OCPUA_Binary::ActivateSessionDiagnosticInfo and enqueue the logging event  
                zeek::RecordValPtr activate_session_res_diagnostic_info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ActivateSessionDiagnosticInfo);
                activate_session_res_diagnostic_info->Assign(ACTIVATE_SESSION_RES_DIAG_INFO_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id_link));
                activate_session_res_diagnostic_info->Assign(ACTIVATE_SESSION_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id));
                zeek::BifEvent::enqueue_opcua_binary_activate_session_diagnostic_info_event(connection()->bro_analyzer(),
                                                                                            connection()->bro_analyzer()->Conn(),
                                                                                            activate_session_res_diagnostic_info);


                // Process the details of the Diagnostic Information
                generateDiagInfoEvent(connection(), activate_session_res_diagnostic_info->GetField(ACTIVATE_SESSION_DIAG_INFO_LINK_ID_SRC_IDX), msg->diagnostic_info()->at(i), stringTable, innerDiagLevel, StatusCode_ActivateSession_DiagInfo_Key, DiagInfo_ActivateSession_Key);

                // Generate an new link to tie OCPUA_Binary::ActivateSessionDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together
                diagnostic_info_id = generateId();
            }
        }

        // Enqueue the OCPUA_Binary::ActivateSession event.
        zeek::BifEvent::enqueue_opcua_binary_activate_session_event(connection()->bro_analyzer(),
                                                                    connection()->bro_analyzer()->Conn(),
                                                                    activate_session_res);

*/
        return true;
    %}
};
