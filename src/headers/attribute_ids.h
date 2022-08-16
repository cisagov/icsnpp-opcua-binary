// attribute_ids.h
//
// OPCUA Binary Protocol Analyzer
//
// Attribute Enumeration for OPCUA Binary protocol services. 
// The constants are used to process the supplied service identifier and
// map the identifier to a string representation for logging. 
//
// Author:   Melanie Pierce
// Contact:  melanie.pierce@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
#ifndef OPCUA_ATTRIBUTE_IDS_H
#define OPCUA_ATTRIBUTE_IDS_H
#include <map>
//
// UA Specification Part 6 - Mappings 1.04.pdf 
// Table A.1 - Identifiers assigned to Attributes:  
//
// Value Description
//  1 NodeId
//  2 NodeClass
//  3 BrowseName
//  4 DispalyName
//  5 Description
//  6 WriteMask
//  7 UserWriteMask
//  8 IsAbstract
//  9 Symmetric
// 10 InverseName
// 11 ContainsNoLoops
// 12 EventNotifier
// 13 Value
// 14 DataType
// 15 ValueRank
// 16 ArrayDimmensions
// 17 AccessLevel
// 18 UserAccessLevel
// 19 MinimumSamplingInterval
// 20 Historizing
// 21 Executable
// 22 UserExecutable
// 23 DataTypeDefinition
// 24 RolePermissions
// 25 UserRolePermissions
// 26 AccessRestrictions
// 27 AccessLevelEx

static uint32_t NodeId_Key                  = 1;
static uint32_t NodeClass_Key               = 2;
static uint32_t BrowseName_Key              = 3;
static uint32_t DisplayName_Key             = 4;
static uint32_t Description_Key             = 5;
static uint32_t WriteMask_Key               = 6;
static uint32_t UserWriteMask_Key           = 7;
static uint32_t IsAbstract_Key              = 8;
static uint32_t Symmetric_Key               = 9;
static uint32_t InverseName_Key             = 10;
static uint32_t ContainsNoLoops_Key         = 11;
static uint32_t EventNotifier_Key           = 12;
static uint32_t Value_Key                   = 13;
static uint32_t DataTypeAttribute_Key       = 14;
static uint32_t ValueRank_Key               = 15;
static uint32_t ArrayDimmensions_Key        = 16;
static uint32_t AccessLevel_Key             = 17;
static uint32_t UserAccessLevel_Key         = 18;
static uint32_t MinimumSamplingInterval_Key = 19;
static uint32_t Historizing_Key             = 20;
static uint32_t Executable_Key              = 21;
static uint32_t UserExecutable_Key          = 22;
static uint32_t DataTypeDefinitions_Key     = 23;
static uint32_t RolePermissions_Key         = 24;
static uint32_t UserRolePermissions_Key     = 25;
static uint32_t AccessRestrictions_Key      = 26;
static uint32_t AccessLevelEx_Key           = 27;


static std::map<uint32_t, std::string> ATTRIBUTE_IDENTIFIERS =
{
   {   NodeId_Key,                  "NodeId"},
   {   NodeClass_Key,               "NodeClass"},
   {   BrowseName_Key,              "BrowseName"},
   {   DisplayName_Key,             "DisplayName"},
   {   Description_Key,             "Description"},
   {   WriteMask_Key,               "WriteMask"},
   {   UserWriteMask_Key,           "UserWriteMask"},
   {   IsAbstract_Key,              "IsAbstract"},
   {   Symmetric_Key,               "Symmetric"},
   {   InverseName_Key,             "InverseName"},
   {   ContainsNoLoops_Key,         "ContainsNoLoops"},
   {   EventNotifier_Key,           "EventNotifier"},
   {   Value_Key,                   "Value"},
   {   DataTypeAttribute_Key,       "DataType"},
   {   ValueRank_Key,               "ValueRank"},
   {   ArrayDimmensions_Key,        "ArrayDimmensions"},
   {   AccessLevel_Key,             "AccessLevel"},
   {   UserAccessLevel_Key,         "UserAccessLevel"},
   {   MinimumSamplingInterval_Key, "MinimumSamplingInterval"},
   {   Historizing_Key,             "Historizing"},
   {   Executable_Key,              "Executable"},
   {   UserExecutable_Key,          "UserExecutable"},
   {   DataTypeDefinitions_Key,     "DataTypeDefinitions"},
   {   RolePermissions_Key,         "RolePermissions"},
   {   UserRolePermissions_Key,     "UserRolePermissions"},
   {   AccessRestrictions_Key,      "AccessRestrictions"},
   {   AccessLevelEx_Key,           "AccessLevelEx"}
  
  
};

#endif
