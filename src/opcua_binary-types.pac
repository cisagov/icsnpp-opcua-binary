## opcua_binary-types.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac type mappings for types defined in the OPCUA specifications
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#
# Remap some of the primitive types
#
type OpcUA_SecurityTokenReqType = uint32;

#
# Not specifically called out in the documentaion, but uint32 determined
# from sample packet captures.  Values defined in:
#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.15 - Table 138 - MessageSecurityMode
#
type OpcUA_MessageSecurityMode  = uint32;

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.14 IntegerId
# This primitive data type is a UInt32 that is used as an identifier, such as a
# handle. All values, except for 0, are valid.
#
type OpcUA_IntegerId = uint32;

#
#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# 5.2.2.5 DateTime
# A DateTime value shall be encoded as a 64-bit signed integer (see Clause
# 5.2.2.2) which represents the number of 100 nanosecond intervals since
# January 1, 1601 (UTC).
#
type OpcUA_DateTime  = int64;

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.34 StatusCode
# The StatusCode is a 32-bit unsigned integer. The top 16 bits represent the
# numeric value of the code that shall be used for detecting specific errors
# or conditions. The bottom 16 bits are bit flags that contain additional
# information but do not affect the meaning of the StatusCode.
#
type OpcUA_StatusCode = uint32;

#
# Complex Types
#

#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# 5.2.2.12 DiagnosticInfo; Table 11
#
type OpcUA_DiagInfo = record {
    encoding_mask   : uint8;

    has_symbolic_id : case $context.flow.is_bit_set(encoding_mask, hasSymbolicId) of {
        true    -> symbolic_id       : int32;
        default -> empty_symbolic_id : empty;
    };

    has_namespace_uri : case $context.flow.is_bit_set(encoding_mask, hasNamespaceUri) of {
        true     -> namespace_uri       : int32;
        default  -> empty_namespace_uri : empty;
    };

    has_locale : case $context.flow.is_bit_set(encoding_mask, hasLocale) of {
        true     -> locale       : int32;
        default  -> empty_locale : empty;
    };

    has_localized_txt : case $context.flow.is_bit_set(encoding_mask, hasLocalizedTxt) of {
        true     -> localized_txt       : int32;
        default  -> empty_localized_txt : empty;
    };

    has_addl_info : case $context.flow.is_bit_set(encoding_mask, hasAddlInfo) of {
        true     -> addl_info       : OpcUA_String;
        default  -> empty_addl_info : empty;
    };

    has_inner_stat_code : case $context.flow.is_bit_set(encoding_mask, hasInnerStatCode) of {
        true     -> inner_stat_code       : OpcUA_StatusCode;
        default  -> empty_inner_stat_code : empty;
    };

    has_inner_diag_info : case $context.flow.is_bit_set(encoding_mask, hasInnerDiagInfo) of {
        true     -> inner_diag_info       : OpcUA_DiagInfo;
        default  -> empty_inner_diag_info : empty;
    };
} &byteorder=littleendian;



#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# 5.1.3 Guid
# A Guid is a 16-byte globally unique identifier.  Guid values may be represented
# as a string in this form:
#    <Data1>-<Data2>-<Data3>-<Data4[0:1]>-<Data4[2:7]>
# Where Data1 is 8 characters wide, Data2 and Data3 are 4 characters wide and each
# Byte in Data4 is 2 characters wide. Each value is formatted as a hexadecimal
# number with padded zeros. A typical Guid value would look like this when
# formatted as a string:
#    C496578A-0DFE-4B8F-870A-745238C6AEAE
#
type OpcUA_Guid = record {
    data1 : bytestring &length = 4;
    data2 : bytestring &length = 2;
    data3 : bytestring &length = 2;
    data4 : bytestring &length = 8;
} &byteorder=littleendian;

#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# 5.2.2.4 String
# All String values are encoded as a sequence of UTF-8 characters without a null
# terminator and preceded by the length in bytes.  The length in bytes is encoded
# as Int32. A value of −1 is used to indicate a ‘null’ string.
#
type OpcUA_String = record {
    length : int32;
    string : bytestring &length = $context.flow.bind_length(length);
} &byteorder=littleendian;

#
# OpcUA_ByteString:
#
type OpcUA_ByteString = record {
    length     : int32;
    byteString : bytestring &length = $context.flow.bind_length(length);
} &byteorder=littleendian;

#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# Table 5 - NodeId components 
#
# The DataEncoding of a NodeId varies according to the contents of 
# the instance. For that reason, the first byte of the encoded form
# indicates the format of the rest of the encoded NodeId. The possible
# DataEncoding formats are shown in Table 6. The tables that follow
# describe the structure of each possible format (they exclude the byte
# which indicates the format).  See
#       Table 6 - NodeId DataEncoding Values 
#       Table 7 - Standard NodeId Binary DataEncoding     
#       Table 8 - Two Byte NodeId Binary DataEncoding
#       Table 9 - Four Byte NodeId Binary DataEncoding
#
type OpcUA_NodeId = record {
    identifier_type : uint8;
    identifier     : case(identifier_type) of {
       TwoByte  -> two_byte_numeric  : OpcUA_NodeId_TwoByte;
       FourByte -> four_byte_numeric : OpcUA_NodeId_FourByte;
       Numeric  -> numeric           : OpcUA_NodeId_Numeric;
       String   -> string            : OpcUA_NodeId_String;
       GUID     -> guid              : OpcUA_NodeId_Guid;
       Opaque   -> opaque            : OpcUA_NodeId_Opaque;
    };
} &byteorder=littleendian;

#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# Table 8 - Two Byte NodeId Binary DataEncoding
#
type OpcUA_NodeId_TwoByte = record {
    numeric  : uint8;
} &byteorder=littleendian;

#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# Table 9 - Four Byte NodeId Binary DataEncoding
#
type OpcUA_NodeId_FourByte = record {
    namespace_index : uint8;
    numeric         : uint16;
} &byteorder=littleendian;

#
# UA Specification Part 6 - Mappings 1.04.pdf 
#
# Table 7 - Standard NodeId Binary DataEncoding
#
type OpcUA_NodeId_Numeric = record {
    namespace_index : uint16;
    numeric         : uint32;
} &byteorder=littleendian;

#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# Figure 7 - A String NodeId
#
type OpcUA_NodeId_String = record {
    namespace_index : uint16;
    string          : OpcUA_String;
} &byteorder=littleendian;

#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# Table 7 - Standard NodeId Binary DataEncoding
#
type OpcUA_NodeId_Guid = record {
    namespace_index : uint16;
    guid            : OpcUA_Guid;
} &byteorder=littleendian;

#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# Table 7 - Standard NodeId Binary DataEncoding
#
type OpcUA_NodeId_Opaque = record {
    namespace_index : uint16;
    opaque          : OpcUA_ByteString;
} &byteorder=littleendian;

#
#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# Table 47 - OPC UA Secure Conversation OpenSecureChannel Service
#
# ChannelSecurityToken: Defined in-line with the indented fields in
# the Response.
#
type OpcUA_ChannelSecurityToken  = record {
    secure_channel_id : uint32;
    token_id          : uint32;
    created_at        : OpcUA_DateTime;
    revised_lifetime  : uint32;
} &byteorder=littleendian;

type OpcUA_LocaleId = OpcUA_String;

#
#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# 5.2.2.14 LocalizedText
# A LocalizedText structure contains two fields that could be missing.
# For that reason, the encoding uses a bit mask to indicate which fields
# are actually present in the encoded form.
#
# Table 13 - LocalizedText Binary DataEncoding
#
type OpcUA_LocalizedText = record {
    encoding_mask : uint8;

    has_locale : case $context.flow.is_bit_set(encoding_mask, localizedTextHasLocale) of {
        true    -> locale       : OpcUA_String;
        default -> empty_locale : empty;
    };

    has_text : case $context.flow.is_bit_set(encoding_mask, localizedTextHasText) of {
        true    -> text       : OpcUA_String;
        default -> empty_text : empty;
    };

} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.1 - Table 112 - ApplicationDescription
#
# Note:
#    application_type: defined as a enumeration in Table 112, but the actual type/size
#                      was not in the documentaion.  Sample packet capture showed it
#                      it is a uint32.
#
type OpcUA_ApplicationDescription = record {
    application_uri       : OpcUA_String;
    product_uri           : OpcUA_String;
    application_name      : OpcUA_LocalizedText;
    application_type      : uint32;
    gateway_server_uri    : OpcUA_String;
    discovery_profile_uri : OpcUA_String;
    discovery_urls_size   : int32;
    discovery_urls        : OpcUA_String[$context.flow.bind_length(discovery_urls_size)];
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.2 - Table 113 - ApplicationDescription
#
type OpcUA_ApplicationInstanceCert = record {
    cert_size : int32;
    cert      : bytestring &length = $context.flow.bind_length(cert_size);
 } &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.37 - Table 190 - UserTokenPolicy
#
# Note:
#    token_type: defined as a enumeration in Table 190, but the actual type/size
#                was not in the documentaion.  Sample packet capture showed it
#                it is a uint32.
#
type OpcUA_UserTokenPolicy = record {
    policy_id           : OpcUA_String;
    token_type          : uint32;
    issued_token_type   : OpcUA_String;
    issuer_endpoint_url : OpcUA_String;
    security_policy_uri : OpcUA_String;
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.10 - Table 135 - EndpointDescription
#
type OpcUA_EndpointDescription = record {
    endpoint_uri  : OpcUA_String;
    server        : OpcUA_ApplicationDescription;
    server_cert   : OpcUA_ApplicationInstanceCert;

    security_mode : OpcUA_MessageSecurityMode;

    security_policy_uri: OpcUA_String;

    user_identity_tokens_size : int32;
    user_identity_tokens      : OpcUA_UserTokenPolicy[$context.flow.bind_length(user_identity_tokens_size)];

    transport_profile_uri : OpcUA_String;
    security_level: uint8;
} &byteorder=littleendian;

#
#
# UA Specification Part 3 - Address Space Model 1.04.pdf
#
# 8.13 Duration
# This Simple DataType is a Double that defines an interval
# of time in milliseconds (fractions can be used to define
# sub-millisecond values). Negative values are generally invalid
# but may have special meanings where the Duration is used.
#
# NOTE: Binpac does not seem to have a double type so we will
# parse it as a bytestring with a length of 8 and convert it
# to a double in the analyzer
#
type OpcUA_Duration = record {
    duration : bytestring &length = 8;
} &byteorder=littleendian;
