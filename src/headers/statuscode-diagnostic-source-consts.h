// statuscode-diagnostic-source-consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Stores the constants used to indicate the service that generated StatusCode and DiagnosticInfo Events
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_STATUSCODE_DIAGNOSTICS_SOURCE_CONSTS_H
#define OPCUA_BINARY_STATUSCODE_DIAGNOSTICS_SOURCE_CONSTS_H
#include <map>

// Internal constants used to associate detailed status code information
// with the service/structure that generated the status code.
static uint32_t StatusCode_ResponseHeader_Key                  = 0; 
static uint32_t StatusCode_ResponseHeader_DiagInfo_Key         = 1; 
static uint32_t StatusCode_Browse_Key                          = 2;
static uint32_t StatusCode_Browse_DiagInfo_Key                 = 3;
static uint32_t StatusCode_ActivateSession_Key                 = 4;
static uint32_t StatusCode_ActivateSession_DiagInfo_Key        = 5;
static uint32_t StatusCode_Read_Key                            = 6;
static uint32_t StatusCode_Read_DiagInfo_Key                   = 7;
static uint32_t StatusCode_CreateMonitoredItems_Key            = 8;
static uint32_t StatusCode_CreateMonitoredItems_DiagInfo_Key   = 9;
static uint32_t StatusCode_SelectClause_Key                    = 10;
static uint32_t StatusCode_SelectClause_DiagInfo_Key           = 11;
static uint32_t StatusCode_ContentFilterElement_Key            = 12;
static uint32_t StatusCode_ContentFilterElement_DiagInfo_Key   = 13;
static uint32_t StatusCode_FilterOperand_Key                   = 14;
static uint32_t StatusCode_FilterOperand_DiagInfo_Key          = 15;
static uint32_t StatusCode_Variant_Key                         = 16;
static uint32_t StatusCode_Variant_DiagInfo_Key                = 17;
static uint32_t StatusCode_Write_Key                           = 18;
static uint32_t StatusCode_Write_DiagInfo_Key                  = 19;


static std::map<uint32_t, std::string> STATUS_CODE_SRC_MAP =
{
   {StatusCode_ResponseHeader_Key,                 "ResponseHeader"},
   {StatusCode_ResponseHeader_DiagInfo_Key,        "ResponseHeader_DiagInfo"},
   {StatusCode_Browse_Key,                         "Browse"},
   {StatusCode_Browse_DiagInfo_Key,                "Browse_DiagInfo"},
   {StatusCode_ActivateSession_Key,                "ActivateSession"},
   {StatusCode_ActivateSession_DiagInfo_Key,       "ActivateSession_DiagInfo"},
   {StatusCode_Read_Key,                           "Read"},
   {StatusCode_Read_DiagInfo_Key,                  "Read_DiagInfo"},
   {StatusCode_CreateMonitoredItems_Key,           "CreateMonitoredItems"},
   {StatusCode_CreateMonitoredItems_DiagInfo_Key,  "CreateMonitoredItems_DiagInfo"},
   {StatusCode_SelectClause_Key,                   "EventFilterSelectClause"},
   {StatusCode_SelectClause_DiagInfo_Key,          "EventFilterSelectClause_DiagInfo"},
   {StatusCode_ContentFilterElement_Key,           "ContentFilterElement"},
   {StatusCode_ContentFilterElement_DiagInfo_Key,  "ContentFilterElement_DiagInfo"},
   {StatusCode_FilterOperand_Key,                  "ContentFilterElementOperand"},
   {StatusCode_FilterOperand_DiagInfo_Key,         "ContentFilterElementOperand_DiagInfo"},
   {StatusCode_Variant_Key,                        "Variant"},
   {StatusCode_Variant_DiagInfo_Key,               "Variant_DiagInfo"},
   {StatusCode_Write_Key,                          "Write"},
   {StatusCode_Write_DiagInfo_Key,                 "Write_DiagInfo"},
};

// Internal constants used to associate detailed diagnostic information
// with the service/structure that generated the diagnostic
static const uint32_t DiagInfo_ResponseHeader_Key              = 0; 
static const uint32_t DiagInfo_ResponseHeader_Inner_Key        = 1; 

static const uint32_t DiagInfo_Browse_Key                      = 2;
static const uint32_t DiagInfo_Browse_Inner_Key                = 3;

static const uint32_t DiagInfo_ActivateSession_Key             = 4; 
static const uint32_t DiagInfo_ActivateSession_Inner_Key       = 5; 

static const uint32_t DiagInfo_Read_Key                        = 6; 
static const uint32_t DiagInfo_Read_Inner_Key                  = 7; 

static const uint32_t DiagInfo_CreateMonitoredItems_Key        = 8;
static const uint32_t DiagInfo_CreateMonitoredItems_Inner_Key  = 9;

static const uint32_t DiagInfo_SelectClause_Key                = 10;
static const uint32_t DiagInfo_SelectClause_Inner_Key          = 11;

static const uint32_t DiagInfo_ContentFilterElement_Key        = 12;
static const uint32_t DiagInfo_ContentFilterElement_Inner_Key  = 13;

static const uint32_t DiagInfo_FilterOperand_Key               = 14;
static const uint32_t DiagInfo_FilterOperand_Inner_Key         = 15;

static const uint32_t DiagInfo_Variant_Key                     = 16;
static const uint32_t DiagInfo_Variant_Inner_Key               = 17;

static const uint32_t DiagInfo_Write_Key                       = 18; 
static const uint32_t DiagInfo_Write_Inner_Key                 = 19; 

static std::map<uint32_t, std::string> DIAGNOSTIC_INFO_SRC_MAP =
{
   {DiagInfo_ResponseHeader_Key,             "ResponseHeader_DiagInfo"},
   {DiagInfo_ResponseHeader_Inner_Key,       "ResponseHeader_InnerDiagInfo"},

   {DiagInfo_Browse_Key,                     "Browse_DiagInfo"},
   {DiagInfo_Browse_Inner_Key,               "Browse_InnerDiagInfo"},

   {DiagInfo_ActivateSession_Key,            "ActivateSession_DiagInfo"},
   {DiagInfo_ActivateSession_Inner_Key,      "ActivateSession_InnerDiagInfo"},

   {DiagInfo_Read_Key,                       "Read_DiagInfo"},
   {DiagInfo_Read_Inner_Key,                 "Read_InnerDiagInfo"},

   {DiagInfo_SelectClause_Key,               "EventFilterSelectClause_DiagInfo"},
   {DiagInfo_SelectClause_Inner_Key,         "EventFilterSelectClause_InnerDiagInfo"},

   {DiagInfo_ContentFilterElement_Key,       "ContentFilterElement_DiagInfo"},
   {DiagInfo_ContentFilterElement_Inner_Key, "ContentFilterElement_InnerDiagInfo"},

   {DiagInfo_FilterOperand_Key,              "ContentFilterElementOperand_DiagInfo"},
   {DiagInfo_FilterOperand_Inner_Key,        "ContentFilterElementOperand_InnerDiagInfo"},

   {DiagInfo_Variant_Key,                    "Variant_DiagInfo"},
   {DiagInfo_Variant_Inner_Key,              "Variant_InnerDiagInfo"},

   {DiagInfo_Write_Key,                      "Write_DiagInfo"},
   {DiagInfo_Write_Inner_Key,                "Write_InnerDiagInfo"},
};
#endif
