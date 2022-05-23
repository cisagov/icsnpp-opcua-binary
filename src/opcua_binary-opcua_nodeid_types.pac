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
