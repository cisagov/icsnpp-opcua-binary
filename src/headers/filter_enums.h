// filter_enums.h
//
// OPCUA Binary Protocol Analyzer
//
// Filter Enumerations for OPCUA Binary protocol services. 
// The constants are used to process the supplied service identifier and
// map the identifier to a string representation for logging. 
//
// Author:   Melanie Pierce
// Contact:  melanie.pierce@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_FILTER_ENUMS_H
#define OPCUA_FILTER_ENUMS_H
#include <map>

//
// UA Specification Part 4 - Address Space Model 1.04.pdf 
// Table 141 - DataChangeFilter
//
// Value Description
//  0 Report a notification only if the StatusCode changes.
//  1 Report a notification if the StatusCode or the value changes.
//  2 Report a notification if the StatusCode, the value or the Source Timestamp changes.

static uint32_t Status_Key                  = 0;
static uint32_t StatusValue_Key             = 1;
static uint32_t StatusValueTimestamp_Key    = 2;

static std::map<uint32_t, std::string> DATA_CHANGE_TRIGGER_MAP =
{
   {   Status_Key,                  "Status"},
   {   StatusValue_Key,             "StatusValue"},
   {   StatusValueTimestamp_Key,    "StatusValueTimestamp"}
  
};

//
// UA Specification Part 4 - Address Space Model 1.04.pdf 
// Table 141 - DataChangeFilter
//
// Value Description
//  0 No deadband calculation.
//  1 AbsoluteDeadband.
//  2 PercentDeadband.

static uint32_t None_Deadband_Key       = 0;
static uint32_t Absolute_Deadband_Key   = 1;
static uint32_t Percent_Deadband_Key    = 2;

static std::map<uint32_t, std::string> DEADBAND_TYPE_MAP =
{
   {   None_Deadband_Key,       "None"},
   {   Absolute_Deadband_Key,   "AbsoluteDeadband"},
   {   Percent_Deadband_Key,    "PercentDeadband"}
  
};





#endif