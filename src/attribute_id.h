// attribute_id.h
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
// Annex A.1 - Attribute Ids; 
// Table A.1 Identifiers assigned to Attributes
//
#ifndef OPCUA_BINARY_ATTRIBUTE_ID_H
#define OPCUA_BINARY_ATTRIBUTE_ID_H
#include <map>

const static uint32_t Attr_NodeId_Key                  = 1;
const static uint32_t Attr_NodeClass_Key               = 2;
const static uint32_t Attr_BrowseName_Key              = 3;
const static uint32_t Attr_DisplayName_Key             = 4;
const static uint32_t Attr_Description_Key             = 5;
const static uint32_t Attr_WriteMask_Key               = 6;
const static uint32_t Attr_UserWriteMask_Key           = 7;
const static uint32_t Attr_IsAbstract_Key              = 8;
const static uint32_t Attr_Symmetric_Key               = 9;
const static uint32_t Attr_InverseName_Key             = 10;
const static uint32_t Attr_ContainsNoLoops_Key         = 11;
const static uint32_t Attr_EventNotifier_Key           = 12;
const static uint32_t Attr_Value_Key                   = 13;
const static uint32_t Attr_DataType_Key                = 14;
const static uint32_t Attr_ValueRank_Key               = 15;
const static uint32_t Attr_ArrayDimensions_Key         = 16;
const static uint32_t Attr_AccessLevel_Key             = 17;
const static uint32_t Attr_UserAccessLevel_Key         = 18;
const static uint32_t Attr_MinimumSamplingInterval_Key = 19;
const static uint32_t Attr_Historizing_Key             = 20;
const static uint32_t Attr_Executable_Key              = 21;
const static uint32_t Attr_UserExecutable_Key          = 22;
const static uint32_t Attr_DataTypeDefinition_Key      = 23;
const static uint32_t Attr_RolePermissions_Key         = 24;
const static uint32_t Attr_UserRolePermissions_Key     = 25;
const static uint32_t Attr_AccessRestrictions_Key      = 26;
const static uint32_t Attr_AccessLevelEx_Key           = 27;

static std::map<uint32_t, std::string> ATTRIBUTE_ID_MAP =
{
    { Attr_NodeId_Key                  , "NodeId" },
    { Attr_NodeClass_Key               , "NodeClass" },
    { Attr_BrowseName_Key              , "BrowseName" },
    { Attr_DisplayName_Key             , "DisplayName" },
    { Attr_Description_Key             , "Description" },
    { Attr_WriteMask_Key               , "WriteMask" },
    { Attr_UserWriteMask_Key           , "UserWriteMask" },
    { Attr_IsAbstract_Key              , "IsAbstract" },
    { Attr_Symmetric_Key               , "Symmetric" },
    { Attr_InverseName_Key             , "InverseName" },
    { Attr_ContainsNoLoops_Key         , "ContainsNoLoops" },
    { Attr_EventNotifier_Key           , "EventNotifier" },
    { Attr_Value_Key                   , "Value" },
    { Attr_DataType_Key                , "DataType" },
    { Attr_ValueRank_Key               , "ValueRank" },
    { Attr_ArrayDimensions_Key         , "ArrayDimensions" },
    { Attr_AccessLevel_Key             , "AccessLevel" },
    { Attr_UserAccessLevel_Key         , "UserAccessLevel" },
    { Attr_MinimumSamplingInterval_Key , "MinimumSamplingInterval" },
    { Attr_Historizing_Key             , "Historizing" },
    { Attr_Executable_Key              , "Executable" },
    { Attr_UserExecutable_Key          , "UserExcutable" },
    { Attr_DataTypeDefinition_Key      , "DataTypeDefinition" },
    { Attr_RolePermissions_Key         , "RolePermissions" },
    { Attr_UserRolePermissions_Key     , "UserRolePermissions" },
    { Attr_AccessRestrictions_Key      , "AccessRestrictions" },
    { Attr_AccessLevelEx_Key           , "AccessLevelEx" }
};

#endif

