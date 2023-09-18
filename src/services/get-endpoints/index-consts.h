// Get Endpoints consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_GET_ENDPOINTS_CONSTS_H
#define OPCUA_BINARY_GET_ENDPOINTS_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::GetEndpoints
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_OPCUA_LINK_ID_DST_IDX                     8
#define GET_ENDPOINT_URL_IDX                                   9
#define GET_ENDPOINT_REQ_LOCALE_LINK_ID_SRC_IDX               10 // Link into GetEndpointsLocalId log
#define GET_ENDPOINT_REQ_PROFILE_URI_LINK_ID_SRC_IDX          11 // Link into GetEndpointsProfileUri log
#define GET_ENDPOINT_RES_ENDPOINT_DESCRIPTION_LINK_ID_SRC_IDX 12 // Link into GetEndpointsDescription log

//
// Index constants for setting values in OPCUA_Binary::GetEndpointsDescription
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_RES_ENDPOINT_DESCRIPTION_LINK_ID_DST_IDX 8 // Link backinto GetEndpoints log
#define GET_ENDPOINT_RES_ENDPOINT_DESCRIPITON_URI_IDX         9
#define GET_ENDPOINT_RES_APPLICATION_URI_IDX                 10
#define GET_ENDPOINT_RES_PRODUCT_URI_IDX                     11
#define GET_ENDPOINT_RES_ENCODING_MASK_IDX                   12
#define GET_ENDPOINT_RES_LOCALE_IDX                          13
#define GET_ENDPOINT_RES_TEXT_IDX                            14
#define GET_ENDPOINT_RES_APPLICATION_TYPE_IDX                15
#define GET_ENDPOINT_RES_GW_SERVER_URI_IDX                   16
#define GET_ENDPOINT_RES_DISCOVERY_URI_IDX                   17
#define GET_ENDPOINT_RES_DISCOVERY_PROFILE_LINK_ID_SRC_IDX   18
#define GET_ENDPOINT_RES_CERT_SIZE_IDX                       19
#define GET_ENDPOINT_RES_SERVER_CERT_IDX                     20
#define GET_ENDPOINT_RES_MSG_SECURITY_MODE_IDX               21
#define GET_ENDPOINT_RES_SECURITY_POLICY_URI_IDX             22
#define GET_ENDPOINT_RES_USER_TOKEN_LINK_ID_SRC_IDX          23
#define GET_ENDPOINT_RES_TRANSPORT_PROFILE_URI_IDX           24
#define GET_ENDPOINT_RES_SECURITY_LEVEL_IDX                  25

//
// Index constants for setting values in OPCUA_Binary::GetEndpointsLocaleId
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_REQ_LOCALE_LINK_ID_DST_IDX 8 // Link back into GetEndpoints log
#define GET_ENDPOINT_REQ_LOCALE_ID_STR_IDX      9

//
// Index constants for setting values in OPCUA_Binary::GetEndpointsProfileUri
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_REQ_PROFILE_URI_LINK_ID_DST_IDX 8 // Link back into GetEndpoints log
#define GET_ENDPOINT_REQ_PROFILE_URI_IDX             9

//
// Index constants for setting values in OPCUA_Binary::GetEndpointsDiscovery
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_RES_DISCOVERY_PROFILE_LINK_ID_DST_IDX 8
#define GET_ENDPOINT_RES_DISCOVORY_URL_IDX                 9

//
// Index constants for setting values in OPCUA_Binary::GetEndpointsUserToken
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_RES_USER_TOKEN_LINK_ID_DST_IDX          8
#define GET_ENDPOINT_RES_USER_TOKEN_POLICY_ID_IDX            9
#define GET_ENDPOINT_RES_USER_TOKEN_TYPE_IDX                10
#define GET_ENDPOINT_RES_USER_TOKEN_ISSUED_TYPE_IDX         11
#define GET_ENDPOINT_RES_USER_TOKEN_ISSUER_ENDPOINT_URL_IDX 12
#define GET_ENDPOINT_RES_USER_TOKEN_SECURITY_POLICY_URI_IDX 13

#endif

