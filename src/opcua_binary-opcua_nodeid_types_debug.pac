## opcua_binary-create_sessions_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing the create session service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printOpcUA_NodeId(int indent_width, OpcUA_NodeId *nodeId);
    void printOpcUA_NodeId_TwoByte(int indent_width, OpcUA_NodeId_TwoByte *nodeId);
    void printOpcUA_NodeId_FourByte(int indent_width, OpcUA_NodeId_FourByte *nodeId);
    void printOpcUA_NodeId_Numeric(int indent_width, OpcUA_NodeId_Numeric *nodeId);
    void printOpcUA_NodeId_String(int indent_width, OpcUA_NodeId_String *nodeId);
    void printOpcUA_NodeId_Guid(int indent_width, OpcUA_NodeId_Guid *nodeId);
    void printOpcUA_NodeId_Opaque(int indent_width, OpcUA_NodeId_Opaque *nodeId);
%}

%code{
    void printOpcUA_NodeId(int indent_width, OpcUA_NodeId *nodeId) {
    
        uint8_t encoding = nodeId->identifier_type();
        if (encoding == node_encoding::TwoByte) {
            printOpcUA_NodeId_TwoByte(indent_width, nodeId->two_byte_numeric());
            
        } else if (encoding == node_encoding::FourByte) {
            printOpcUA_NodeId_FourByte(indent_width, nodeId->four_byte_numeric());

        } else if (encoding == node_encoding::Numeric) {
            printOpcUA_NodeId_Numeric(indent_width, nodeId->numeric());

        } else if (encoding == node_encoding::String) {
            printOpcUA_NodeId_String(indent_width, nodeId->string());

        } else if (encoding == node_encoding::GUID) {
            printOpcUA_NodeId_Guid(indent_width, nodeId->guid());

        } else if (encoding == node_encoding::Opaque) {
            printOpcUA_NodeId_Opaque(indent_width, nodeId->opaque());
        }
    }

    void printOpcUA_NodeId_TwoByte(int indent_width, OpcUA_NodeId_TwoByte *nodeId) {
        printf("%s EncodingMask: TwoByte (0x%02x)\n", indent(indent_width).c_str(), node_encoding::TwoByte);
        printf("%s Identifier Numeric: %d\n", indent(indent_width).c_str(), nodeId->numeric());
    }

    void printOpcUA_NodeId_FourByte(int indent_width, OpcUA_NodeId_FourByte *nodeId) {
        printf("%s EncodingMask: FourByte (0x%02x)\n", indent(indent_width).c_str(), node_encoding::FourByte);
        printf("%s Namespace Index: %d\n", indent(indent_width).c_str(), nodeId->namespace_index());
        printf("%s Identifier Numeric: %d\n", indent(indent_width).c_str(), nodeId->numeric());
    }

    void printOpcUA_NodeId_Numeric(int indent_width, OpcUA_NodeId_Numeric *nodeId) {
        printf("%s EncodingMask: Numeric (0x%02x)\n", indent(indent_width).c_str(), node_encoding::Numeric);
        printf("%s Namespace Index: %d\n", indent(indent_width).c_str(), nodeId->namespace_index());
        printf("%s Identifier Numeric: %d\n", indent(indent_width).c_str(), nodeId->numeric());
    }

    void printOpcUA_NodeId_String(int indent_width, OpcUA_NodeId_String *nodeId) {
        printf("%s EncodingMask: String (0x%02x)\n", indent(indent_width).c_str(), node_encoding::String);
        printf("%s Namespace Index: %d\n", indent(indent_width).c_str(), nodeId->namespace_index());
        printf("%s Identifier String: %s\n", indent(indent_width).c_str(), std_str(nodeId->string()->string()).c_str());
    }

    void printOpcUA_NodeId_Guid(int indent_width, OpcUA_NodeId_Guid *nodeId) {
        printf("%s EncodingMask: GUID (0x%02x)\n", indent(indent_width).c_str(), node_encoding::GUID);
        printf("%s Namespace Index: %d\n", indent(indent_width).c_str(), nodeId->namespace_index());

        OpcUA_Guid *guid_ptr = nodeId->guid();
        string guid_str = guidToGuidstring(guid_ptr->data1(), guid_ptr->data2(), guid_ptr->data3(), guid_ptr->data4());
        printf("%s Identifier Guid: %s\n", indent(indent_width).c_str(), guid_str.c_str());
    }

    void printOpcUA_NodeId_Opaque(int indent_width, OpcUA_NodeId_Opaque *nodeId) {
        printf("%s EncodingMask: Opaque (0x%02x)\n", indent(indent_width).c_str(), node_encoding::Opaque);
        printf("%s Namespace Index: %d\n", indent(indent_width).c_str(), nodeId->namespace_index());
        printf("%s Identifier Opaque: %s\n", indent(indent_width).c_str(), bytestringToHexstring(nodeId->opaque()->byteString()).c_str());
    }
%}
