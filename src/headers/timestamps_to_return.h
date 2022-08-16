// timestamps_to-return.h
//
// OPCUA Binary Protocol Analyzer
//
// Timestamps to Return Enumeration for OPCUA Binary protocol services. 
// The constants are used to process the supplied service identifier and
// map the identifier to a string representation for logging. 
//
// Author:   Melanie Pierce
// Contact:  melanie.pierce@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
#ifndef OPCUA_TIMESTAMPS_TO_RETURN_H
#define OPCUA_TIMESTAMPS_TO_RETURN_H
#include <map>
//
// UA Specification Part 4 - Address Space Model 1.04.pdf 
// Table 179 - TimestampsToReturn Values:  
//
// Value Description
//  0 Return the source timestamp.
//  1 Return the server timestamp.
//  2 Return both source and server timestamps.
//  3 Return neither timestamp.

static uint32_t SourceTimestamp_Key     = 0;
static uint32_t ServerTimestamp_Key     = 1;
static uint32_t BothTimestamps_Key      = 2;
static uint32_t NeitherTimestamp_Key    = 3;


static std::map<uint32_t, std::string> TIMESTAMPS_TO_RETURN_MAP =
{
   {   SourceTimestamp_Key,   "Source"},
   {   ServerTimestamp_Key,   "Server"},
   {   BothTimestamps_Key,    "Both"},
   {   NeitherTimestamp_Key,  "Neither"}
  
};

#endif
