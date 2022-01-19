// node_identifiers.h
//
// OPCUA Binary Protocol Analyzer
//
// Numeric Node Identifiers for OPCUA Binary protocol services.  The
// constants are used to process the supplied service identifier and
// map the identifier to a string representation for logging. 
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_NODE_IDENTIFIERS_H
#define OPCUA_BINARY_NODE_IDENTIFIERS_H
#include <map>

static uint16_t  ServiceFault                          = 397;
static uint16_t  FindServersRequest                    = 422;
static uint16_t  FindServersResponse                   = 425;
static uint16_t  FindServersOnNetworkRequest           = 12208;
static uint16_t  FindServersOnNetworkResponse          = 12209;
static uint16_t  GetEndpointsRequest                   = 428;
static uint16_t  GetEndpointsResponse                  = 431;
static uint16_t  RegisterServerRequest                 = 437;
static uint16_t  RegisterServerResponse                = 440;
static uint16_t  RegisterServer2Request                = 12211;
static uint16_t  RegisterServer2Response               = 12212;
static uint16_t  OpenSecureChannelRequest              = 446;
static uint16_t  OpenSecureChannelResponse             = 449;
static uint16_t  CloseSecureChannelRequest             = 452;
static uint16_t  CloseSecureChannelResponse            = 455;
static uint16_t  CreateSessionRequest                  = 461;
static uint16_t  CreateSessionResponse                 = 464;
static uint16_t  ActivateSessionRequest                = 467;
static uint16_t  ActivateSessionResponse               = 470;
static uint16_t  CloseSessionRequest                   = 473;
static uint16_t  CloseSessionResponse                  = 476;
static uint16_t  CancelRequest                         = 479;
static uint16_t  CancelResponse                        = 482;
static uint16_t  AddNodesRequest                       = 488;
static uint16_t  AddNodesResponse                      = 491;
static uint16_t  AddReferencesRequest                  = 494;
static uint16_t  AddReferencesResponse                 = 497;
static uint16_t  DeleteNodesRequest                    = 500;
static uint16_t  DeleteNodesResponse                   = 503;
static uint16_t  DeleteReferencesRequest               = 506;
static uint16_t  DeleteReferencesResponse              = 509;
static uint16_t  BrowseRequest                         = 527;
static uint16_t  BrowseResponse                        = 530;
static uint16_t  BrowseNextRequest                     = 533;
static uint16_t  BrowseNextResponse                    = 536;
static uint16_t  TranslateBrowsePathsToNodeIdsRequest  = 554;
static uint16_t  TranslateBrowsePathsToNodeIdsResponse = 557;
static uint16_t  RegisterNodesRequest                  = 560;
static uint16_t  RegisterNodesResponse                 = 563;
static uint16_t  UnregisterNodesRequest                = 566;
static uint16_t  UnregisterNodesResponse               = 569;
static uint16_t  QueryFirstRequest                     = 615;
static uint16_t  QueryFirstResponse                    = 618;
static uint16_t  QueryNextRequest                      = 621;
static uint16_t  QueryNextResponse                     = 624;
static uint16_t  ReadRequest                           = 631;
static uint16_t  ReadResponse                          = 634;
static uint16_t  HistoryReadRequest                    = 664;
static uint16_t  HistoryReadResponse                   = 667;
static uint16_t  WriteRequest                          = 673;
static uint16_t  WriteResponse                         = 676;
static uint16_t  HistoryUpdateRequest                  = 700;
static uint16_t  HistoryUpdateResponse                 = 703;
static uint16_t  CallRequest                           = 712;
static uint16_t  CallResponse                          = 715;
static uint16_t  CreateMonitoredItemsRequest           = 751;
static uint16_t  CreateMonitoredItemsResponse          = 754;
static uint16_t  ModifyMonitoredItemsRequest           = 763;
static uint16_t  ModifyMonitoredItemsResponse          = 766;
static uint16_t  SetMonitoringModeRequest              = 769;
static uint16_t  SetMonitoringModeResponse             = 772;
static uint16_t  SetTriggeringRequest                  = 775;
static uint16_t  SetTriggeringResponse                 = 778;
static uint16_t  DeleteMonitoredItemsRequest           = 781;
static uint16_t  DeleteMonitoredItemsResponse          = 784;
static uint16_t  CreateSubscriptionRequest             = 787;
static uint16_t  CreateSubscriptionResponse            = 790;
static uint16_t  ModifySubscriptionRequest             = 793;
static uint16_t  ModifySubscriptionResponse            = 796;
static uint16_t  SetPublishingModeRequest              = 799;
static uint16_t  SetPublishingModeResponse             = 802;
static uint16_t  PublishRequest                        = 826;
static uint16_t  PublishResponse                       = 829;
static uint16_t  RepublishRequest                      = 832;
static uint16_t  RepublishResponse                     = 835;
static uint16_t  TransferSubscriptionsRequest          = 841;
static uint16_t  TransferSubscriptionsResponse         = 844;
static uint16_t  DeleteSubscriptionsRequest            = 847;
static uint16_t  DeleteSubscriptionsResponse           = 850;
static uint16_t  TestStackRequest                      = 410;
static uint16_t  TestStackResponse                     = 413;
static uint16_t  TestStackExRequest                    = 416;
static uint16_t  TestStackExResponse                   = 419;


//
// Mappging between node identifiers and string representations
//
static std::map<uint16_t, std::string> NODE_IDENTIFIER_MAP =
{
   {   ServiceFault                          , "ServiceFault" },
   {   FindServersRequest                    , "FindServersRequest" },
   {   FindServersResponse                   , "FindServersResponse" },
   {   FindServersOnNetworkRequest           , "FindServersOnNetworkRequest" },
   {   FindServersOnNetworkResponse          , "FindServersOnNetworkResponse" },
   {   GetEndpointsRequest                   , "GetEndpointsRequest" },
   {   GetEndpointsResponse                  , "GetEndpointsResponse" },
   {   RegisterServerRequest                 , "RegisterServerRequest" },
   {   RegisterServerResponse                , "RegisterServerResponse" },
   {   RegisterServer2Request                , "RegisterServer2Request" },
   {   RegisterServer2Response               , "RegisterServer2Response" },
   {   OpenSecureChannelRequest              , "OpenSecureChannelRequest" },
   {   OpenSecureChannelResponse             , "OpenSecureChannelResponse" },
   {   CloseSecureChannelRequest             , "CloseSecureChannelRequest" },
   {   CloseSecureChannelResponse            , "CloseSecureChannelResponse" },
   {   CreateSessionRequest                  , "CreateSessionRequest" },
   {   CreateSessionResponse                 , "CreateSessionResponse" },
   {   ActivateSessionRequest                , "ActivateSessionRequest" },
   {   ActivateSessionResponse               , "ActivateSessionResponse" },
   {   CloseSessionRequest                   , "CloseSessionRequest" },
   {   CloseSessionResponse                  , "CloseSessionResponse" },
   {   CancelRequest                         , "CancelRequest" },
   {   CancelResponse                        , "CancelResponse" },
   {   AddNodesRequest                       , "AddNodesRequest" },
   {   AddNodesResponse                      , "AddNodesResponse" },
   {   AddReferencesRequest                  , "AddReferencesRequest" },
   {   AddReferencesResponse                 , "AddReferencesResponse" },
   {   DeleteNodesRequest                    , "DeleteNodesRequest" },
   {   DeleteNodesResponse                   , "DeleteNodesResponse" },
   {   DeleteReferencesRequest               , "DeleteReferencesRequest" },
   {   DeleteReferencesResponse              , "DeleteReferencesResponse" },
   {   BrowseRequest                         , "BrowseRequest" },
   {   BrowseResponse                        , "BrowseResponse" },
   {   BrowseNextRequest                     , "BrowseNextRequest" },
   {   BrowseNextResponse                    , "BrowseNextResponse" },
   {   TranslateBrowsePathsToNodeIdsRequest  , "TranslateBrowsePathsToNodeIdsRequest" },
   {   TranslateBrowsePathsToNodeIdsResponse , "TranslateBrowsePathsToNodeIdsResponse" },
   {   RegisterNodesRequest                  , "RegisterNodesRequest" },
   {   RegisterNodesResponse                 , "RegisterNodesResponse" },
   {   UnregisterNodesRequest                , "UnregisterNodesRequest" },
   {   UnregisterNodesResponse               , "UnregisterNodesResponse" },
   {   QueryFirstRequest                     , "QueryFirstRequest" },
   {   QueryFirstResponse                    , "QueryFirstResponse" },
   {   QueryNextRequest                      , "QueryNextRequest" },
   {   QueryNextResponse                     , "QueryNextResponse" },
   {   ReadRequest                           , "ReadRequest" },
   {   ReadResponse                          , "ReadResponse" },
   {   HistoryReadRequest                    , "HistoryReadRequest" },
   {   HistoryReadResponse                   , "HistoryReadResponse" },
   {   WriteRequest                          , "WriteRequest" },
   {   WriteResponse                         , "WriteResponse" },
   {   HistoryUpdateRequest                  , "HistoryUpdateRequest" },
   {   HistoryUpdateResponse                 , "HistoryUpdateResponse" },
   {   CallRequest                           , "CallRequest" },
   {   CallResponse                          , "CallResponse" },
   {   CreateMonitoredItemsRequest           , "CreateMonitoredItemsRequest" },
   {   CreateMonitoredItemsResponse          , "CreateMonitoredItemsResponse" },
   {   ModifyMonitoredItemsRequest           , "ModifyMonitoredItemsRequest" },
   {   ModifyMonitoredItemsResponse          , "ModifyMonitoredItemsResponse" },
   {   SetMonitoringModeRequest              , "SetMonitoringModeRequest" },
   {   SetMonitoringModeResponse             , "SetMonitoringModeResponse" },
   {   SetTriggeringRequest                  , "SetTriggeringRequest" },
   {   SetTriggeringResponse                 , "SetTriggeringResponse" },
   {   DeleteMonitoredItemsRequest           , "DeleteMonitoredItemsRequest" },
   {   DeleteMonitoredItemsResponse          , "DeleteMonitoredItemsResponse" },
   {   CreateSubscriptionRequest             , "CreateSubscriptionRequest" },
   {   CreateSubscriptionResponse            , "CreateSubscriptionResponse" },
   {   ModifySubscriptionRequest             , "ModifySubscriptionRequest" },
   {   ModifySubscriptionResponse            , "ModifySubscriptionResponse" },
   {   SetPublishingModeRequest              , "SetPublishingModeRequest" },
   {   SetPublishingModeResponse             , "SetPublishingModeResponse" },
   {   PublishRequest                        , "PublishRequest" },
   {   PublishResponse                       , "PublishResponse" },
   {   RepublishRequest                      , "RepublishRequest" },
   {   RepublishResponse                     , "RepublishResponse" },
   {   TransferSubscriptionsRequest          , "TransferSubscriptionsRequest" },
   {   TransferSubscriptionsResponse         , "TransferSubscriptionsResponse" },
   {   DeleteSubscriptionsRequest            , "DeleteSubscriptionsRequest" },
   {   DeleteSubscriptionsResponse           , "DeleteSubscriptionsResponse" },
   {   TestStackRequest                      , "TestStackRequest" },
   {   TestStackResponse                     , "TestStackResponse" },
   {   TestStackExRequest                    , "TestStackExRequest" },
   {   TestStackExResponse                   , "TestStackExResponse" }
};

#endif
