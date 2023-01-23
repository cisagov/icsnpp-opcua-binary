## opcua_binary-variant_types.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing data variant objects.
##
## Author:   Melanie Pierce
## Contact:  Melanie.Pierce@inl.gov
##
## Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# 5.2.2.17 DataValue Table 16 - Data Value Binary DataEncoding
#
type OpcUA_DataValue = record {
    encoding_mask : uint8;

    has_value : case $context.flow.is_bit_set(encoding_mask, dataValueHasValue) of {
        true    -> value       : OpcUA_Variant;
        default -> empty_value : empty;
    };

    has_status_code : case $context.flow.is_bit_set(encoding_mask, dataValueHasStatusCode) of {
        true    -> status_code       : OpcUA_StatusCode;
        default -> empty_status_code : empty;
    };

    has_source_timestamp : case $context.flow.is_bit_set(encoding_mask, dataValueHasSourceTimestamp) of {
        true    -> source_timestamp       : OpcUA_DateTime;
        default -> empty_source_timestamp : empty;
    };

    has_source_pico_sec : case $context.flow.is_bit_set(encoding_mask, dataValueHasSourcePicoseconds) of {
        true    -> source_pico_sec       : uint16;
        default -> empty_source_pico_sec : empty;
    };

    has_server_timestamp : case $context.flow.is_bit_set(encoding_mask, dataValueHasServerTimestamp) of {
        true    -> server_timestamp       : OpcUA_DateTime;
        default -> empty_server_timestamp : empty;
    };

    has_server_pico_sec : case $context.flow.is_bit_set(encoding_mask, dataValueHasServerPicoseconds) of {
        true    -> server_pico_sec       : uint16;
        default -> empty_server_pico_sec : empty;
    };

}

#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# 5.2.2.16 Variant Table 15 - Variant Binary DataEncoding and 5.1.6 Variant
#
# A Variant is a union of all built-in data types including an ExtensionObject. Variants
# can also contain arrays of any of these built-in types. Variants are used to store any value
# or parameter with a data type of BaseDataType or one of its subtypes.
#
# Variants can be empty. An empty Variant is described as having a null value and should be 
# treated like a null column in a SQL database. A null value in a Variant may not be the same 
# as a null value for data types that support nulls such as Strings. Some DevelopmentPlatforms 
# may not be able to preserve the distinction between a null for a DataType and a null for a 
# Variant, therefore, applications shall not rely on this distinction. This requirement also 
# means that if an Attribute supports the writing of a null value it shall also support writing
# of an empty Variant and vice versa.
#
# Variants can contain arrays of Variants but they cannot directly contain another Variant.
#
# DiagnosticInfo types only have meaning when returned in a response message with an associated
# StatusCode and table of strings. As a result, Variants cannot contain instances of DiagnosticInfo.
#
# Values of Attributes are always returned in instances of DataValues. Therefore, the DataType of 
# an Attribute cannot be a DataValue. Variants can contain DataValue when used in other contexts 
# such as Method Arguments or PubSub Messages. The Variant in a DataValue cannot, directly or 
# indirectly, contain another DataValue.
#
# Variables with a DataType of BaseDataType are mapped to a Variant, however, the ValueRank and 
# ArrayDimensions Attributes place restrictions on what is allowed in the Variant. For example, if
# the ValueRank is Scalar then the Variant may only contain scalar values.
#
# ExtensionObjects and Variants allow unlimited nesting which could result in stack overflow errors 
# even if the message size is less than the maximum allowed. Decoders shall support at least 100 
# nesting levels. Decoders shall report an error if the number of nesting levels exceeds what 
# it supports.
#
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
