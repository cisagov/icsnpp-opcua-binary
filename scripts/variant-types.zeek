## variant-types.zeek
##
## OPCUA Binary Protocol Analyzer
##
## Zeek script type/record definitions describing the information
## that will be written to the log files.
##
## Author:   Melanie Pierce
## Contact:  melanie.pierce@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

module ICSNPP_OPCUA_Binary;
export {
    type OPCUA_Binary::VariantMetadata: record {
        ts                          : time    &log;
        uid                         : string  &log;
        id                          : conn_id &log;
        variant_data_link_id        : string  &log; # Link back into the Variant's source file
        
        variant_data_source         : count   &log;
        variant_data_source_str     : string  &log;

        # value : OpcUA_Variant
        dara_variant_encoding_mask : string &log &optional;
        data_variant_data_type     : count  &log &optional;
        data_variant_data_type_str : string &log &optional;

        built_in_data_type          : count  &log &optional;
        built_in_data_type_str      : string &log &optional;

        variant_data_link_id        : string &log &optional; # Link into OPCUA_Binary::VariantData log

        # Array Dimensions
        variant_data_array_dim                  : count &log &optional;
        variant_data_array_multi_dim_link_id    : string &log &optional; 
    };
    #
    # Note: The processing for a OpcUA_DataVariant that is itself of type OpcUA_DataVariant is to recursively call the
    # data processing and link back into the OPCUA_Binary::VariantMetadata log file.
    #
    type OPCUA_Binary::VariantData: record {
        ts                         : time    &log;
        uid                        : string  &log;
        id                         : conn_id &log;
        variant_data_link_id       : string  &log; # Link back into OPCUA_Binary::VariantMetadata

        # Signed numeric - e.g int8, int16, etc.
        variant_data_value_signed_numeric : int &log &optional;

        # Unsigned numeric - e.g uint8, uint16, etc.
        variant_data_value_unsigned_numeric : count &log &optional;

        # OpcUA_String, OpcUA_Guid, OpcUA_ByteString, etc
        variant_data_value_string  : string &log &optional;

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
        variant_data_status_code_link_id   : string &log &optional; # Link into OPCUA_Binary::StatusCodeDetail log

        # OpcUA_DiagnosticInfo
        variant_data_diag_info_link_id     : string &log &optional; # Link into OPCUA_Binary::DiagnosticInfoDetail log

        # OpcUA_ExtensionObject
        variant_data_ext_obj_link_id   : string &log &optional; # Link into OPCUA_Binary::VariantExtensionObject

        #
        # OpcUA_DataValue
        #
        # Note: A OpcUA_DataVariant that is itself of type OpcUA_DataVariant is handled by recursively calling the variant
        # data processing and linking into the OPCUA_Binary::VariantMetadata
        #
        variant_metadata_data_link_id : string &log &optional; #Link into OPCUA_Binary::VariantMetadata

        variant_data_value_link_id    : string &log &optional; # Link into OPCUA_Binary::VariantDataValue
    };

    type OPCUA_Binary::VariantArrayDims: record {
        ts                : time    &log;
        uid               : string  &log;
        id                : conn_id &log;
        array_dim_link_id : string  &log; # Link back into OPCUA_Binary::ReadArrayDimsLink
        dimension         : count   &log; 
    };

    type OPCUA_Binary::VariantExtensionObject: record {
        ts              : time    &log;
        uid             : string  &log;
        id              : conn_id &log;
        ext_obj_link_id : string &log; # Link into OPCUA_Binary::VariantData

        # NodeId
        ext_obj_node_id_encoding_mask : string &log &optional;
        ext_obj_node_id_namespace_idx : count  &log &optional;
        ext_obj_node_id_numeric       : count  &log &optional;
        ext_obj_node_id_string        : string &log &optional;
        ext_obj_node_id_guid          : string &log &optional;
        ext_obj_node_id_opaque        : string &log &optional;

        ext_obj_type_id_str : string &log; # String representation of type id (AnonymousIdentityToken, UserNameIdentityToken, X509IdentityToken, etc.)
        ext_obj_encoding    : string &log;
    };

    type OPCUA_Binary::VariantDataValue: record {
        ts                              : time    &log;
        uid                             : string  &log;
        id                              : conn_id &log;
        variant_data_value_source_link  : string &log;

        data_value_encoding_mask        : string &log;

        status_code_link_id     : string &log &optional; # Id into OPCUA_Binary::StatusCodeDetail log

        source_timestamp        : time  &log &optional;
        source_pico_sec         : count &log &optional;

        server_timestamp        : time  &log &optional;
        server_pico_sec         : count &log &optional;

        variant_metadata_link_id    : string &log &optional;
    };
}
