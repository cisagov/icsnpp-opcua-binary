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

static uint16_t  ServiceFault_Key                          = 397;
static uint16_t  FindServersRequest_Key                    = 422;
static uint16_t  FindServersResponse_Key                   = 425;
static uint16_t  FindServersOnNetworkRequest_Key           = 12208;
static uint16_t  FindServersOnNetworkResponse_Key          = 12209;
static uint16_t  GetEndpointsRequest_Key                   = 428;
static uint16_t  GetEndpointsResponse_Key                  = 431;
static uint16_t  RegisterServerRequest_Key                 = 437;
static uint16_t  RegisterServerResponse_Key                = 440;
static uint16_t  RegisterServer2Request_Key                = 12211;
static uint16_t  RegisterServer2Response_Key               = 12212;
static uint16_t  OpenSecureChannelRequest_Key              = 446;
static uint16_t  OpenSecureChannelResponse_Key             = 449;
static uint16_t  CloseSecureChannelRequest_Key             = 452;
static uint16_t  CloseSecureChannelResponse_Key            = 455;
static uint16_t  CreateSessionRequest_Key                  = 461;
static uint16_t  CreateSessionResponse_Key                 = 464;
static uint16_t  ActivateSessionRequest_Key                = 467;
static uint16_t  ActivateSessionResponse_Key               = 470;
static uint16_t  CloseSessionRequest_Key                   = 473;
static uint16_t  CloseSessionResponse_Key                  = 476;
static uint16_t  CancelRequest_Key                         = 479;
static uint16_t  CancelResponse_Key                        = 482;
static uint16_t  AddNodesRequest_Key                       = 488;
static uint16_t  AddNodesResponse_Key                      = 491;
static uint16_t  AddReferencesRequest_Key                  = 494;
static uint16_t  AddReferencesResponse_Key                 = 497;
static uint16_t  DeleteNodesRequest_Key                    = 500;
static uint16_t  DeleteNodesResponse_Key                   = 503;
static uint16_t  DeleteReferencesRequest_Key               = 506;
static uint16_t  DeleteReferencesResponse_Key              = 509;
static uint16_t  BrowseRequest_Key                         = 527;
static uint16_t  BrowseResponse_Key                        = 530;
static uint16_t  BrowseNextRequest_Key                     = 533;
static uint16_t  BrowseNextResponse_Key                    = 536;
static uint16_t  TranslateBrowsePathsToNodeIdsRequest_Key  = 554;
static uint16_t  TranslateBrowsePathsToNodeIdsResponse_Key = 557;
static uint16_t  RegisterNodesRequest_Key                  = 560;
static uint16_t  RegisterNodesResponse_Key                 = 563;
static uint16_t  UnregisterNodesRequest_Key                = 566;
static uint16_t  UnregisterNodesResponse_Key               = 569;
static uint16_t  QueryFirstRequest_Key                     = 615;
static uint16_t  QueryFirstResponse_Key                    = 618;
static uint16_t  QueryNextRequest_Key                      = 621;
static uint16_t  QueryNextResponse_Key                     = 624;
static uint16_t  ReadRequest_Key                           = 631;
static uint16_t  ReadResponse_Key                          = 634;
static uint16_t  HistoryReadRequest_Key                    = 664;
static uint16_t  HistoryReadResponse_Key                   = 667;
static uint16_t  WriteRequest_Key                          = 673;
static uint16_t  WriteResponse_Key                         = 676;
static uint16_t  HistoryUpdateRequest_Key                  = 700;
static uint16_t  HistoryUpdateResponse_Key                 = 703;
static uint16_t  CallRequest_Key                           = 712;
static uint16_t  CallResponse_Key                          = 715;
static uint16_t  CreateMonitoredItemsRequest_Key           = 751;
static uint16_t  CreateMonitoredItemsResponse_Key          = 754;
static uint16_t  ModifyMonitoredItemsRequest_Key           = 763;
static uint16_t  ModifyMonitoredItemsResponse_Key          = 766;
static uint16_t  SetMonitoringModeRequest_Key              = 769;
static uint16_t  SetMonitoringModeResponse_Key             = 772;
static uint16_t  SetTriggeringRequest_Key                  = 775;
static uint16_t  SetTriggeringResponse_Key                 = 778;
static uint16_t  DeleteMonitoredItemsRequest_Key           = 781;
static uint16_t  DeleteMonitoredItemsResponse_Key          = 784;
static uint16_t  CreateSubscriptionRequest_Key             = 787;
static uint16_t  CreateSubscriptionResponse_Key            = 790;
static uint16_t  ModifySubscriptionRequest_Key             = 793;
static uint16_t  ModifySubscriptionResponse_Key            = 796;
static uint16_t  SetPublishingModeRequest_Key              = 799;
static uint16_t  SetPublishingModeResponse_Key             = 802;
static uint16_t  PublishRequest_Key                        = 826;
static uint16_t  PublishResponse_Key                       = 829;
static uint16_t  RepublishRequest_Key                      = 832;
static uint16_t  RepublishResponse_Key                     = 835;
static uint16_t  TransferSubscriptionsRequest_Key          = 841;
static uint16_t  TransferSubscriptionsResponse_Key         = 844;
static uint16_t  DeleteSubscriptionsRequest_Key            = 847;
static uint16_t  DeleteSubscriptionsResponse_Key           = 850;
static uint16_t  TestStackRequest_Key                      = 410;
static uint16_t  TestStackResponse_Key                     = 413;
static uint16_t  TestStackExRequest_Key                    = 416;
static uint16_t  TestStackExResponse_Key                   = 419;


//
// Mappging between node identifiers and string representations
//
static std::map<uint16_t, std::string> NODE_IDENTIFIER_MAP =
{
   {   ServiceFault_Key                          , "ServiceFault" },
   {   FindServersRequest_Key                    , "FindServersRequest" },
   {   FindServersResponse_Key                   , "FindServersResponse" },
   {   FindServersOnNetworkRequest_Key           , "FindServersOnNetworkRequest" },
   {   FindServersOnNetworkResponse_Key          , "FindServersOnNetworkResponse" },
   {   GetEndpointsRequest_Key                   , "GetEndpointsRequest" },
   {   GetEndpointsResponse_Key                  , "GetEndpointsResponse" },
   {   RegisterServerRequest_Key                 , "RegisterServerRequest" },
   {   RegisterServerResponse_Key                , "RegisterServerResponse" },
   {   RegisterServer2Request_Key                , "RegisterServer2Request" },
   {   RegisterServer2Response_Key               , "RegisterServer2Response" },
   {   OpenSecureChannelRequest_Key              , "OpenSecureChannelRequest" },
   {   OpenSecureChannelResponse_Key             , "OpenSecureChannelResponse" },
   {   CloseSecureChannelRequest_Key             , "CloseSecureChannelRequest" },
   {   CloseSecureChannelResponse_Key            , "CloseSecureChannelResponse" },
   {   CreateSessionRequest_Key                  , "CreateSessionRequest" },
   {   CreateSessionResponse_Key                 , "CreateSessionResponse" },
   {   ActivateSessionRequest_Key                , "ActivateSessionRequest" },
   {   ActivateSessionResponse_Key               , "ActivateSessionResponse" },
   {   CloseSessionRequest_Key                   , "CloseSessionRequest" },
   {   CloseSessionResponse_Key                  , "CloseSessionResponse" },
   {   CancelRequest_Key                         , "CancelRequest" },
   {   CancelResponse_Key                        , "CancelResponse" },
   {   AddNodesRequest_Key                       , "AddNodesRequest" },
   {   AddNodesResponse_Key                      , "AddNodesResponse" },
   {   AddReferencesRequest_Key                  , "AddReferencesRequest" },
   {   AddReferencesResponse_Key                 , "AddReferencesResponse" },
   {   DeleteNodesRequest_Key                    , "DeleteNodesRequest" },
   {   DeleteNodesResponse_Key                   , "DeleteNodesResponse" },
   {   DeleteReferencesRequest_Key               , "DeleteReferencesRequest" },
   {   DeleteReferencesResponse_Key              , "DeleteReferencesResponse" },
   {   BrowseRequest_Key                         , "BrowseRequest" },
   {   BrowseResponse_Key                        , "BrowseResponse" },
   {   BrowseNextRequest_Key                     , "BrowseNextRequest" },
   {   BrowseNextResponse_Key                    , "BrowseNextResponse" },
   {   TranslateBrowsePathsToNodeIdsRequest_Key  , "TranslateBrowsePathsToNodeIdsRequest" },
   {   TranslateBrowsePathsToNodeIdsResponse_Key , "TranslateBrowsePathsToNodeIdsResponse" },
   {   RegisterNodesRequest_Key                  , "RegisterNodesRequest" },
   {   RegisterNodesResponse_Key                 , "RegisterNodesResponse" },
   {   UnregisterNodesRequest_Key                , "UnregisterNodesRequest" },
   {   UnregisterNodesResponse_Key               , "UnregisterNodesResponse" },
   {   QueryFirstRequest_Key                     , "QueryFirstRequest" },
   {   QueryFirstResponse_Key                    , "QueryFirstResponse" },
   {   QueryNextRequest_Key                      , "QueryNextRequest" },
   {   QueryNextResponse_Key                     , "QueryNextResponse" },
   {   ReadRequest_Key                           , "ReadRequest" },
   {   ReadResponse_Key                          , "ReadResponse" },
   {   HistoryReadRequest_Key                    , "HistoryReadRequest" },
   {   HistoryReadResponse_Key                   , "HistoryReadResponse" },
   {   WriteRequest_Key                          , "WriteRequest" },
   {   WriteResponse_Key                         , "WriteResponse" },
   {   HistoryUpdateRequest_Key                  , "HistoryUpdateRequest" },
   {   HistoryUpdateResponse_Key                 , "HistoryUpdateResponse" },
   {   CallRequest_Key                           , "CallRequest" },
   {   CallResponse_Key                          , "CallResponse" },
   {   CreateMonitoredItemsRequest_Key           , "CreateMonitoredItemsRequest" },
   {   CreateMonitoredItemsResponse_Key          , "CreateMonitoredItemsResponse" },
   {   ModifyMonitoredItemsRequest_Key           , "ModifyMonitoredItemsRequest" },
   {   ModifyMonitoredItemsResponse_Key          , "ModifyMonitoredItemsResponse" },
   {   SetMonitoringModeRequest_Key              , "SetMonitoringModeRequest" },
   {   SetMonitoringModeResponse_Key             , "SetMonitoringModeResponse" },
   {   SetTriggeringRequest_Key                  , "SetTriggeringRequest" },
   {   SetTriggeringResponse_Key                 , "SetTriggeringResponse" },
   {   DeleteMonitoredItemsRequest_Key           , "DeleteMonitoredItemsRequest" },
   {   DeleteMonitoredItemsResponse_Key          , "DeleteMonitoredItemsResponse" },
   {   CreateSubscriptionRequest_Key             , "CreateSubscriptionRequest" },
   {   CreateSubscriptionResponse_Key            , "CreateSubscriptionResponse" },
   {   ModifySubscriptionRequest_Key             , "ModifySubscriptionRequest" },
   {   ModifySubscriptionResponse_Key            , "ModifySubscriptionResponse" },
   {   SetPublishingModeRequest_Key              , "SetPublishingModeRequest" },
   {   SetPublishingModeResponse_Key             , "SetPublishingModeResponse" },
   {   PublishRequest_Key                        , "PublishRequest" },
   {   PublishResponse_Key                       , "PublishResponse" },
   {   RepublishRequest_Key                      , "RepublishRequest" },
   {   RepublishResponse_Key                     , "RepublishResponse" },
   {   TransferSubscriptionsRequest_Key          , "TransferSubscriptionsRequest" },
   {   TransferSubscriptionsResponse_Key         , "TransferSubscriptionsResponse" },
   {   DeleteSubscriptionsRequest_Key            , "DeleteSubscriptionsRequest" },
   {   DeleteSubscriptionsResponse_Key           , "DeleteSubscriptionsResponse" },
   {   TestStackRequest_Key                      , "TestStackRequest" },
   {   TestStackResponse_Key                     , "TestStackResponse" },
   {   TestStackExRequest_Key                    , "TestStackExRequest" },
   {   TestStackExResponse_Key                   , "TestStackExResponse" }
};

#endif
