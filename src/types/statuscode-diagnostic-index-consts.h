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
#define STATUS_CODE_LINK_ID_DST_IDX    8
#define STATUS_CODE_SOURCE_IDX         9
#define STATUS_CODE_SOURCE_STR_IDX    10
#define STATUS_CODE_SOURCE_LEVEL_IDX  11
#define STATUS_CODE_IDX               12
#define SEVERITY_IDX                  13
#define SEVERITY_STR_IDX              14
#define SUBCODE_IDX                   15
#define SUBCODE_STR_IDX               16
#define STRUCTURE_CHANGED_IDX         17
#define SEMANTICS_CHANGED_IDX         18
#define INFO_TYPE_IDX                 19
#define INFO_TYPE_STR_IDX             20
#define LIMIT_BITS_IDX                21
#define LIMIT_BITS_STR_IDX            22
#define OVERFLOW_IDX                  23
#define HISTORIAN_BITS_IDX            24
#define HISTORIAN_BITS_STR_IDX        25
#define HISTORIAN_BITS_PARTIAL_IDX    26
#define HISTORIAN_BITS_EXTRADATA_IDX  27
#define HISTORIAN_BITS_MULTIVALUE_IDX 28

//
// Index constants for setting values in OPCUA_Binary::DiagnosticInfoDetail
//
#define DIAG_INFO_LINK_ID_DST_IDX          8
#define DIAG_INFO_ROOT_OBJECT_ID_IDX       9
#define DIAG_INFO_SOURCE_IDX               10
#define DIAG_INFO_SOURCE_STR_IDX           11
#define INNER_DIAG_LEVEL_IDX               12
#define HAS_SYMBOLIC_ID_IDX                13
#define SYMBOLIC_ID_IDX                    14
#define SYMBOLIC_ID_STR_IDX                15
#define HAS_NAMESPACE_URI_IDX              16
#define NAMESPACE_URI_IDX                  17
#define NAMESPACE_URI_STR_IDX              18
#define HAS_LOCALE_IDX                     19
#define LOCALE_IDX                         20
#define LOCALE_STR_IDX                     21
#define HAS_LOCALE_TXT_IDX                 22
#define LOCALE_TXT_IDX                     23
#define LOCALE_TXT_STR_IDX                 24
#define HAS_ADDL_INFO_IDX                  25
#define ADDL_INFO_IDX                      26
#define HAS_INNER_STAT_CODE_IDX            27
#define INNER_STAT_CODE_IDX                28
#define HAS_INNER_DIAG_INFO_IDX            29

#endif

