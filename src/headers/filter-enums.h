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
   {   Absolute_Deadband_Key,   "Absolute"},
   {   Percent_Deadband_Key,    "Percent"}
  
};

//
// UA Specification Part 4 - Address Space Model 1.04.pdf 
// Table 119 - Basic FilterOperator Definition
//
// Value Description
//  0 Equals: TRUE if operand[0] is equal to operand[1].
//  1 IsNull: TRUE if operand[0] is a null value.
//  2 GreaterThan: TRUE if operand[0] is greater than operand[1].
//  3 LessThan: TRUE if operand[0] is less than operand[1].
//  4 GreaterThanOrEqual: TRUE if operand[0] is greater than or equal to operand[1].
//  5 LessThanOrEqual: TRUE if operand[0] is less than or equal to operand[1].
//  6 Like: TRUE if operand[0] matches a pattern defined by operand[1].
//  7 Not: TRUE if operand[0] is FALSE.
//  8 Between: TRUE if operand[0] is greater or equal to operand[1] and less than or equal to operand[2].
//  9 InList: TRUE if operand[0] is equal to one or more of the remaining operands.
// 10 And: TRUE if operand[0] and operand[1] are TRUE.
// 11 Or: TRUE if operand[0] or operand[1] are TRUE
// 12 Cast: Converts operand[0] to a value with a data type with a NodeId identified by operand[1].
// 16 BitwiseAnd: The result is an integer which matches the size of the largest operand and contains a bitwise And operation of the two operands.
// 17 BitwiseOr: The result is an integer which matches the size of the largest operand and contains a bitwise Or operation of the two operands.
// Table 120 - Complex FilterOperator Definition
// 13 InView: TRUE if the target Node is contained in the View defined by operand[0].
// 14 OfType: TRUE if the target Node is of type operand[0] or of a subtype of operand[0].
// 15 RelatedTo: TRUE if the target Node is of type operand[0] and is related to a NodeId of the type defined in operand[1] by the Reference type defined in operand[2].

static uint32_t Equal_Key                 = 0;
static uint32_t Is_Null_Key               = 1;
static uint32_t Greater_Than_Key          = 2;
static uint32_t Less_Than_Key             = 3;
static uint32_t Greater_Than_Or_Equal_Key = 4;
static uint32_t Less_Than_Or_Equal_Key    = 5;
static uint32_t Like_Key                  = 6;
static uint32_t Not_Key                   = 7;
static uint32_t Between_Key               = 8;
static uint32_t In_List_Key               = 9;
static uint32_t And_Key                   = 10;
static uint32_t Or_Key                    = 11;
static uint32_t Cast_Key                  = 12;
static uint32_t In_View_Key               = 13;
static uint32_t Of_Type_Key               = 14;
static uint32_t Related_To_Key            = 15;
static uint32_t Bitwise_And_Key           = 16;
static uint32_t Bitwise_Or_Key            = 17;

static std::map<uint32_t, std::string>  FILTER_OPERATORS_MAP =
{
   {Equal_Key,                   "Equals"},
   {Is_Null_Key,                 "IsNull"},
   {Greater_Than_Key,            "GreaterThan"},
   {Less_Than_Key,               "LessThan"},
   {Greater_Than_Or_Equal_Key,   "GreaterThanOrEqual"},
   {Less_Than_Or_Equal_Key,      "LessThanOrEqual"},
   {Like_Key,                    "Like"},
   {Not_Key,                     "Not"},
   {Between_Key,                 "Between"},
   {In_List_Key,                 "InList"},
   {And_Key,                     "And"},
   {Or_Key,                      "OR"},
   {Cast_Key,                    "Cast"},
   {In_View_Key,                 "InView"},
   {Of_Type_Key,                 "OfType"},
   {Related_To_Key,              "RelatedTo"},
   {Bitwise_And_Key,             "BitwiseAnd"},
   {Bitwise_Or_Key,              "BitwiseOr"}
};

#endif