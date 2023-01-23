// statuscode-diagnostic-consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_STATUSCODE_DIAGNOSTICS_CONSTS_H
#define OPCUA_BINARY_STATUSCODE_DIAGNOSTICS_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::StatusCodeDetail
//
#define STATUS_CODE_LINK_ID_DST_IDX   3
#define STATUS_CODE_SOURCE_IDX        4
#define STATUS_CODE_SOURCE_STR_IDX    5
#define STATUS_CODE_SOURCE_LEVEL_IDX  6
#define STATUS_CODE_IDX               7
#define SEVERITY_IDX                  8
#define SEVERITY_STR_IDX              9
#define SUBCODE_IDX                   10
#define SUBCODE_STR_IDX               11
#define STRUCTURE_CHANGED_IDX         12
#define SEMANTICS_CHANGED_IDX         13
#define INFO_TYPE_IDX                 14
#define INFO_TYPE_STR_IDX             15
#define LIMIT_BITS_IDX                16
#define LIMIT_BITS_STR_IDX            17
#define OVERFLOW_IDX                  18
#define HISTORIAN_BITS_IDX            19
#define HISTORIAN_BITS_STR_IDX        20
#define HISTORIAN_BITS_PARTIAL_IDX    21
#define HISTORIAN_BITS_EXTRADATA_IDX  22
#define HISTORIAN_BITS_MULTIVALUE_IDX 23

//
// Index constants for setting values in OPCUA_Binary::DiagnosticInfoDetail
//
#define DIAG_INFO_LINK_ID_DST_IDX          3
#define DIAG_INFO_ROOT_OBJECT_ID_IDX       4
#define DIAG_INFO_SOURCE_IDX               5
#define DIAG_INFO_SOURCE_STR_IDX           6
#define INNER_DIAG_LEVEL_IDX               7
#define HAS_SYMBOLIC_ID_IDX                8
#define SYMBOLIC_ID_IDX                    9
#define SYMBOLIC_ID_STR_IDX                10
#define HAS_NAMESPACE_URI_IDX              11
#define NAMESPACE_URI_IDX                  12
#define NAMESPACE_URI_STR_IDX              13
#define HAS_LOCALE_IDX                     14
#define LOCALE_IDX                         15
#define LOCALE_STR_IDX                     16
#define HAS_LOCALE_TXT_IDX                 17
#define LOCALE_TXT_IDX                     18
#define LOCALE_TXT_STR_IDX                 19
#define HAS_ADDL_INFO_IDX                  20
#define ADDL_INFO_IDX                      21
#define HAS_INNER_STAT_CODE_IDX            22
#define INNER_STAT_CODE_IDX                23
#define HAS_INNER_DIAG_INFO_IDX            24

#endif

