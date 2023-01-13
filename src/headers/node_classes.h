// node_classes.h
//
// OPCUA Binary Protocol Analyzer
//
// Numeric Node Class Identifiers for OPCUA Binary protocol services. 
// The constants are used to process the supplied service identifier and
// map the identifier to a string representation for logging. 
//
// Author:   Melanie Pierce
// Contact:  melanie.pierce@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
#ifndef OPCUA_BINARY_NODE_CLASSES_H
#define OPCUA_BINARY_NODE_CLASSES_H
#include <map>
//
// UA Specification Part 3 - Address Space Model 1.04.pdf 
// Table 1 - NodeClass Values:  
//
// Value Description
//  0x01 An object NodeClass mask.
//  0x02 A variable NodeClass mask.
//  0x04 A method NodeClass mask.
//  0x08 An object type NodeClass mask.
//  0x10 A variable type NodeClass mask.
//  0x20 A reference type NodeClass mask.
//  0x40 A data type NodeClass mask.
//  0x80 A view NodeClass mask

static uint32_t AllClasses_Key          = 0;
static uint32_t ObjectClass_Key         = 1;
static uint32_t VariableClass_Key       = 2;
static uint32_t MethodClass_Key         = 4;
static uint32_t ObjectTypeClass_Key     = 8;
static uint32_t VariableTypeClass_Key   = 16;
static uint32_t ReferenceTypeClass_Key  = 32;
static uint32_t DataType_Key            = 64;
static uint32_t View_Key                = 128; 

static std::map<uint32_t, std::string> NODE_CLASSES_MAP =
{
   {   AllClasses_Key           , "All"},
   {   ObjectClass_Key          , "ObjectNodeClass" },
   {   VariableClass_Key        , "VariableNodeClass" },
   {   MethodClass_Key          , "MethodNodeClass" },
   {   ObjectTypeClass_Key      , "ObjectTypeNodeClass" },
   {   VariableTypeClass_Key    , "VariableTypeNodeClass" },
   {   ReferenceTypeClass_Key   , "ReferenceTypeNodeClass" },
   {   DataType_Key             , "DataTypeNodeClass" },
   {   View_Key                 , "ViewNodeClass" }
};

#endif
