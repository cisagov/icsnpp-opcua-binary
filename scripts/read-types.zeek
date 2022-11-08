## read-types.zeek
##
## OPCUA Binary Protocol Analyzer
##
## Zeek script type/record definitions describing the information
## that will be written to the log files.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

module ICSNPP_OPCUA_Binary;
export {
    type OPCUA_Binary::Read: record {
        ts                       : time    &log;
        uid                      : string  &log;
        id                       : conn_id &log;
        opcua_link_id            : string  &log; # Link back into OPCUA_Binary::Info:

        # Request
        max_age                  : count  &log &optional;
        timestamps_to_return     : count  &log &optional;
        timestamps_to_return_str : string &log &optional;
        nodes_to_read_link_id    : string &log &optional; # Link into OPCUA_Binary::NodesToRead

        # Response
        read_results_link_id :  string &log &optional; # Link into OPCUA_Binary::ReadResultsLink
        diag_info_link_id    : string  &log &optional; # Link into OPCUA_Binary::ReadDiagnosticInfo log
    };

    type OPCUA_Binary::ReadNodesToRead: record {
        ts                    : time    &log;
        uid                   : string  &log;
        id                    : conn_id &log;
        nodes_to_read_link_id : string  &log; # Link back into OPCUA_Binary::Read

        # node_id : OpcUA_NodeId
        node_id_encoding_mask : string &log &optional;
        node_id_namespace_idx : count  &log &optional;
        node_id_numeric       : count  &log &optional;
        node_id_string        : string &log &optional;
        node_id_guid          : string &log &optional;
        node_id_opaque        : string &log &optional;

        attribute_id     : count  &log;
        attribute_id_str : string &log;
        index_range      : string &log;

        # data_encoding : QualifiedName
        data_encoding_name_idx : count  &log &optional;
        data_encoding_name     : string &log &optional;
    };

    type OPCUA_Binary::ReadResultsLink: record {
        ts                   : time    &log;
        uid                  : string  &log;
        id                   : conn_id &log;
        read_results_link_id : string  &log; # Link back into OCPUA_Binary::Read or OPCUA_Binary::Read
        results_link_id      : string  &log; # Link into OPCUA_Binary::ReadResults
    };

    type OPCUA_Binary::ReadResults: record {
        ts                   : time    &log;
        uid                  : string  &log;
        id                   : conn_id &log;
        results_link_id      : string  &log; # Link back into OPCUA_Binary::ReadResultsLink
        level                : count   &log;

        data_value_encoding_mask : string &log;

        status_code_link_id  : string &log &optional; # Id into OPCUA_Binary::StatusCodeDetail log

        source_timestamp     : time  &log &optional;
        source_pico_sec      : count &log &optional;

        server_timestamp     : time  &log &optional;
        server_pico_sec      : count &log &optional;

        # value : OpcUA_Variant
        data_variant_encoding_mask : string &log &optional;
        data_variant_data_type     : count  &log &optional;
        data_variant_data_type_str : string &log &optional;

        built_in_data_type          : count  &log &optional;
        built_in_data_type_str      : string &log &optional;

        read_results_variant_data_link_id  : string &log &optional; # Link into OPCUA_Binary::ReadVariantDataLink log
    };

    #
    # Note: The processing for a OpcUA_DataValue that is itself of type OpcUA_DataValue is to recursively call the read variant
    # data processing and link back into the OPCUA_Binary::ReadVariantDataLink log file.
    #
    type OPCUA_Binary::ReadVariantDataLink: record {
        ts                     : time    &log;
        uid                    : string  &log;
        id                     : conn_id &log;
        read_results_variant_data_link_id : string  &log; # Link back into OPCUA_Binary::ReadResults as well as link back into OPCUA_Binary::ReadVariantData
        read_variant_data_link_id         : string  &log; # Link into OPCUA_Binary::ReadVariantData
    };

    type OPCUA_Binary::ReadVariantData: record {
        ts                         : time    &log;
        uid                        : string  &log;
        id                         : conn_id &log;
        read_variant_data_link_id  : string  &log; # Link back into OPCUA_Binary::ReadVariantDataLink

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
        variant_data_status_code_link_id   : string &log &optional; # Link into OPCUA_Binary::ReadStatusCode log

        # OpcUA_DiagnosticInfo
        variant_data_diag_info_link_id     : string &log &optional; # Link into OPCUA_Binary::ReadDiagnosticInfo log

        # Array Dimensions
        variant_data_array_dim         : count &log &optional;
        variant_data_array_dim_link_id : string &log &optional; # Link into OPCUA_Binary::ReadArrayDimsLink

        variant_data_ext_obj_link_id   : string &log &optional; # Link into OPCUA_Binary::ReadExtensionObjectLink

        #
        # OpcUA_DataValue
        #
        # Note: A OpcUA_DataValue that is itself of type OpcUA_DataValue is handled by recursively calling the read variant
        # data processing and linking into the OPCUA_Binary::ReadVariantDataLink
        #
        read_results_variant_data_link_id : string &log &optional; #Link into OPCUA_Binary::ReadVariantDataLink
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


    type OPCUA_Binary::ReadDiagnosticInfo: record {
        ts                     : time    &log;
        uid                    : string  &log;
        id                     : conn_id &log;
        read_diag_info_link_id : string  &log; # Link back into OCPUA_Binary::Read or OPCUA_Binary::ReadVariantData
        diag_info_link_id      : string  &log; # Link into OPCUA_Binary::DiagnosticInfoDetail
    };

    type OPCUA_Binary::ReadStatusCode: record {
        ts                     : time    &log;
        uid                    : string  &log;
        id                     : conn_id &log;
        read_status_code_link_id : string  &log; # Link back into OPCUA_Binary::ReadVariantData
        status_code_link_id      : string  &log; # Link into OPCUA_Binary::StatusCodeDetail
    };

    type OPCUA_Binary::ReadExtensionObjectLink: record {
        ts                           : time    &log;
        uid                          : string  &log;
        id                           : conn_id &log;
        variant_data_ext_obj_link_id : string  &log; # Link back into OPCUA_Binary::ReadVariantData
        ext_obj_link_id              : string  &log; # Link into OPCUA_Binary::ReadExtensionObject
    };

    type OPCUA_Binary::ReadExtensionObject: record {
        ts              : time    &log;
        uid             : string  &log;
        id              : conn_id &log;
        ext_obj_link_id : string &log; # Link into OPCUA_Binary::ReadExtensionObjectLink

        # NodeId
        ext_obj_node_id_encoding_mask : string &log &optional;
        ext_obj_node_id_namespace_idx : count  &log &optional;
        ext_obj_node_id_numeric       : count  &log &optional;
        ext_obj_node_id_string        : string &log &optional;
        ext_obj_node_id_guid          : string &log &optional;
        ext_obj_node_id_opaque        : string &log &optional;

        ext_obj_type_id_str : string &log; # String representation of type id (AnonymousIdentityToken, UserNameIdentityToken, X509IdentityToken, etc.)
        ext_obj_encoding    : string &log;

        identity_token_link_id : string &log &optional; # Link into OPCUA_Binary::ReadExtensionObjectIdentityToken
    };
}
