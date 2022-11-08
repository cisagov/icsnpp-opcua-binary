// built_in_data_types.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

//
// UA Specification Part 6 - Mappings 1.04.pdf 
//
// 5.1.2 Built-in Types Table 1 - Built-in Data Types
//

#ifndef OPCUA_BINARY_BUILT_IN_DATA_TYPES_H
#define OPCUA_BINARY_BUILT_IN_DATA_TYPES_H
#include <map>

const static uint32_t Boolean_Key         = 1;
const static uint32_t SByte_Key           = 2;
const static uint32_t Byte_Key            = 3;
const static uint32_t Int16_Key           = 4;
const static uint32_t Uint16_Key          = 5;
const static uint32_t Int32_Key           = 6;
const static uint32_t Uint32_Key          = 7;
const static uint32_t Int64_Key           = 8;
const static uint32_t Uint64_Key          = 9;
const static uint32_t Float_Key           = 10;
const static uint32_t Double_Key          = 11;
const static uint32_t String_Key          = 12;
const static uint32_t DateTime_Key        = 13;
const static uint32_t Guid_Key            = 14;
const static uint32_t ByteString_Key      = 15;
const static uint32_t XmlElement_Key      = 16;
const static uint32_t NodeId_Key          = 17;
const static uint32_t ExpandedNodeId_Key  = 18;
const static uint32_t StatusCode_Key      = 19;
const static uint32_t QualifiedName_Key   = 20;
const static uint32_t LocalizedText_Key   = 21;
const static uint32_t ExtensionObject_Key = 22;
const static uint32_t DataValue_Key       = 23;
const static uint32_t Variant_Key         = 24;
const static uint32_t DiagnosticInfo_Key  = 25;

static std::map<uint32_t, std::string> BUILT_IN_DATA_TYPES_MAP =
{
    { Boolean_Key,         "Boolean" },
    { SByte_Key,           "SByte" },
    { Byte_Key,            "Byte" },
    { Int16_Key,           "Int16" },
    { Uint16_Key,          "Uint16" },
    { Int32_Key,           "Int32" },
    { Uint32_Key,          "Uint32" },
    { Int64_Key,           "Int64" },
    { Uint64_Key,          "Uint64" },
    { Float_Key,           "Float" },
    { Double_Key,          "Double" },
    { String_Key,          "String" },
    { DateTime_Key,        "DateTime" },
    { Guid_Key,            "Guid" },
    { ByteString_Key,      "ByteString" },
    { XmlElement_Key,      "XmlElement" },
    { NodeId_Key,          "NodeId" },
    { ExpandedNodeId_Key,  "ExpandedNodeId" },
    { StatusCode_Key,      "StatusCode" },
    { QualifiedName_Key,   "QualifiedName" },
    { LocalizedText_Key,   "LocalizedText" },
    { ExtensionObject_Key, "ExtensionObject" },
    { DataValue_Key,       "DataValue" },
    { Variant_Key,         "Variant" },
    { DiagnosticInfo_Key,  "DiagnosticInfo" }
};

const static uint32_t VariantIsValue_Key             = 0;
const static uint32_t VariantIsArray_Key             = 1;
const static uint32_t VariantIsMultiDimensionalArray = 2;

static std::map<uint32_t, std::string> VARIANT_DATA_TYPES_MAP =
{
    { VariantIsValue_Key,             "Value" },
    { VariantIsArray_Key,             "Array" },
    { VariantIsMultiDimensionalArray, "MultiDimArray" }
};

#endif