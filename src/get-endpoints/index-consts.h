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
#define GET_ENDPOINT_OPCUA_ID_LINK_IDX             3
#define GET_ENDPOINT_URL_IDX                       4
#define GET_ENDPOINT_REQ_LOCALE_ID_IDX             5
#define GET_ENDPOINT_REQ_PROFILE_URI_IDX           6
#define GET_ENDPOINT_RES_APPLICATION_URI_IDX       7
#define GET_ENDPOINT_RES_PRODUCT_URI_IDX           8
#define GET_ENDPOINT_RES_ENCODING_MASK_IDX         9
#define GET_ENDPOINT_RES_LOCALE_IDX                10
#define GET_ENDPOINT_RES_TEXT_IDX                  11
#define GET_ENDPOINT_RES_APPLICATION_TYPE_IDX      12
#define GET_ENDPOINT_RES_GW_SERVER_URI_IDX         13
#define GET_ENDPOINT_RES_DISCOVERY_PROFILE_ID_IDX  14
#define GET_ENDPOINT_RES_CERT_SIZE_IDX             15
#define GET_ENDPOINT_RES_SERVER_CERT_IDX           16
#define GET_ENDPOINT_RES_MSG_SECURITY_MODE_IDX     17
#define GET_ENDPOINT_RES_SECURITY_POLICY_URI_IDX   18
#define GET_ENDPOINT_RES_USER_TOKEN_ID_IDX         19
#define GET_ENDPOINT_RES_TRANSPORT_PROFILE_URI_IDX 20
#define GET_ENDPOINT_RES_SECURITY_LEVEL_IDX        21

//
// Index constants for setting values in OPCUA_Binary::GetEndpointsDiscovery
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_RES_DISCOVERY_PROFILE_ID_LINK_IDX 3
#define GET_ENDPOINT_RES_DISCOVERY_URI_IDX             4
#define GET_ENDPOINT_RES_DISCOVORY_URL_IDX             5

//
// Index constants for setting values in OPCUA_Binary::GetEndpointsUserToken
// based on the parsed values from Get_Endpoints_Req and Get_Endpoints_Res
//
#define GET_ENDPOINT_RES_USER_TOKEN_ID_LINK_IDX             3
#define GET_ENDPOINT_RES_USER_TOKEN_POLICY_ID_IDX           4
#define GET_ENDPOINT_RES_USER_TOKEN_TYPE_IDX                5
#define GET_ENDPOINT_RES_USER_TOKEN_ISSUED_TYPE_IDX         6
#define GET_ENDPOINT_RES_USER_TOKEN_ISSUER_ENDPOINT_URL_IDX 7
#define GET_ENDPOINT_RES_USER_TOKEN_SECURITY_POLICY_URI_IDX 8

#endif

