## CreateMonitoredItemsItem.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac type mappings for nodeid types
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 6 - Mappings 1.04.pdf 
# Table 6 - NodeId DataEncoding:  
#
# Value Description
#  0x00 A numeric value that fits into the two-byte representation.
#  0x01 A numeric value that fits into the four-byte representation.
#  0x02 A numeric value that does not fit into the two or four byte representations.
#  0x03 A String value.
#  0x04 A Guid value.
#  0x05 An opaque (ByteString) value.
#  0x80 NamespaceUriFlag See discussion of ExpandedNodeId in 5.2.2.10.
#  0x40 ServerIndexFlag See discussion of ExpandedNodeId in 5.2.2.10.
#
enum node_encoding 
{
        TwoByte          = 0x00,
        FourByte         = 0x01,
        Numeric          = 0x02,
        String           = 0x03,
        GUID             = 0x04,
        Opaque           = 0x05,
        NamespaceUriFlag = 0x80,
        ServerIndexFlag  = 0x40
} 

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
    identifier     : case(identifier_type & 0x0f) of {
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
# UA Specification Part 6 - Mappings 1.04.pdf
#
# Table 10 - ExpandedNodeId Binary DataEncoding
#

type OpcUA_ExpandedNodeId = record {
    node_id  : OpcUA_NodeId;
    has_namespace_uri : case $context.flow.is_bit_set(node_id.identifier_type, NamespaceUriFlag) of {
        true     -> namespace_uri       : OpcUA_String;
        default  -> empty_namespace_uri : empty;
    };
    has_server_idx : case $context.flow.is_bit_set(node_id.identifier_type, ServerIndexFlag) of {
        true     -> server_idx          : uint32;
        default  -> empty_server_idx    : empty;
    };
} &byteorder=littleendian;
