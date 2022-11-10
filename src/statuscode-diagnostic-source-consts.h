
#ifndef OPCUA_BINARY_STATUSCODE_DIAGNOSTICS_SOURCE_CONSTS_H
#define OPCUA_BINARY_STATUSCODE_DIAGNOSTICS_SOURCE_CONSTS_H
#include <map>

// Internal constants used to associate detailed status code information
// with the service/structure that generated the status code.
static uint32_t StatusCode_ResponseHeader_Key           = 0; 
static uint32_t StatusCode_ResponseHeader_DiagInfo_Key  = 1; 
static uint32_t StatusCode_Browse_Key                   = 2;
static uint32_t StatusCode_Browse_DiagInfo_Key          = 3;
static uint32_t StatusCode_ActivateSession_Key          = 4;
static uint32_t StatusCode_ActivateSession_DiagInfo_Key = 5;
static uint32_t StatusCode_Read_Key                     = 6;
static uint32_t StatusCode_Read_DiagInfo_Key            = 7;

static std::map<uint32_t, std::string> STATUS_CODE_SRC_MAP =
{
   {StatusCode_ResponseHeader_Key,           "ResponseHeader"},
   {StatusCode_ResponseHeader_DiagInfo_Key,  "ResponseHeader_DiagInfo"},
   {StatusCode_Browse_Key,                   "Browse"},
   {StatusCode_Browse_DiagInfo_Key,          "Browse_DiagInfo"},
   {StatusCode_ActivateSession_Key,          "ActivateSession"},
   {StatusCode_ActivateSession_DiagInfo_Key, "ActivateSession_DiagInfo"},
   {StatusCode_Read_Key,                     "Read"},
   {StatusCode_Read_DiagInfo_Key,            "Read_DiagInfo"}
};

// Internal constants used to associate detailed diagnostic information
// with the service/structure that generated the diagnostic
static const uint32_t DiagInfo_ResponseHeader_Key        = 0; 
static const uint32_t DiagInfo_ResponseHeader_Inner_Key  = 1; 

static const uint32_t DiagInfo_Browse_Key                = 2;
static const uint32_t DiagInfo_Browse_Inner_Key          = 3;

static const uint32_t DiagInfo_ActivateSession_Key       = 4; 
static const uint32_t DiagInfo_ActivateSession_Inner_Key = 5; 

static const uint32_t DiagInfo_Read_Key                  = 6; 
static const uint32_t DiagInfo_Read_Inner_Key            = 7; 

static std::map<uint32_t, std::string> DIAGNOSTIC_INFO_SRC_MAP =
{
   {DiagInfo_ResponseHeader_Key,        "ResponseHeader_DiagInfo"},
   {DiagInfo_ResponseHeader_Inner_Key,  "ResponseHeader_InnerDiagInfo"},

   {DiagInfo_Browse_Key,                "Browse_DiagInfo"},
   {DiagInfo_Browse_Inner_Key,          "Browse_InnerDiagInfo"},

   {DiagInfo_ActivateSession_Key,       "ActivateSession_DiagInfo"},
   {DiagInfo_ActivateSession_Inner_Key, "ActivateSession_InnerDiagInfo"},

   {DiagInfo_Read_Key,                  "Read_DiagInfo"},
   {DiagInfo_Read_Inner_Key,            "Read_InnerDiagInfo"}
};
#endif
