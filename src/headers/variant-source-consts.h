// variant-source-consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Stores the constants used to indicate the service that generated Variant Events
//
// Author:   Melanie Pierce
// Contact:  melanie.pierce@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_VARIANT_SOURCE_CONSTS_H
#define OPCUA_BINARY_VARIANT_SOURCE_CONSTS_H
#include <map>

// Internal constants used to associate detailed status code information
// with the service/structure that generated the status code.
static const uint32_t Variant_Read_Key                               = 0; 
static const uint32_t Variant_Read_Inner_Key                         = 1; 
static const uint32_t Variant_LiteralOperand_Key                    = 2; 
static const uint32_t Variant_LiteralOperand_Inner_Key              = 3; 


static std::map<uint32_t, std::string> VARIANT_SRC_MAP =
{
   {Variant_Read_Key,                     "Read_Variant"},
   {Variant_Read_Inner_Key,               "Read_InnerVariant"},
   {Variant_LiteralOperand_Key,          "LiteralOperand_Variant"},
   {Variant_LiteralOperand_Inner_Key,    "LiteralOperand_InnerVariant"}
};
#endif 