// Create Subscription consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Melanie Pierce
// Contact:  Melanie.Pierce@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_CREATE_SUBSCRIPTION_CONSTS_H
#define OPCUA_BINARY_CREATE_SUBSCRIPTION_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::CreateSubscription
// based on the parsed values from CreateSubscription_Req and CreateSubscription_Res
//
#define CREATE_SUB_OPCUA_ID_LINK_IDX                            3

#define CREATE_SUB_REQ_PUB_INT_IDX                              4
#define CREATE_SUB_REQ_LIFETIME_COUNT_IDX                       5
#define CREATE_SUB_REQ_MAX_KEEP_ALIVE_IDX                       6
#define CREATE_SUB_MAX_NOTIFICATIONS_PER_PUBLISH_IDX            7
#define CREATE_SUB_PUBLISHING_ENABLED_IDX                       8
#define CREATE_SUB_PRIORITY_IDX                                 9

#define CREATE_SUB_SUB_ID_IDX                                  10
#define CREATE_SUB_REV_PUB_INT_IDX                             11
#define CREATE_SUB_REV_LIFETIME_COUNT_IDX                      12
#define CREATE_SUB_REV_MAX_KEEP_ALIVE_IDX                      13

#endif