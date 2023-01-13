// extension_object_node_id.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

//
// UA Specification Part 6 - Mappings 1.04.pdf 
//
// Annex A.3 - Numeric Node Ids provides a link to the CSV that that contains
// extension object node identifiers.  This file contains ~14,000 node
// identifiers along with symbol names and node class.  
//
// The subset of identifiers defined below are based on the Wireshark
// OPCUA plugin code base.  Specifically the files opcua_extensionobjectids.h
// and opcua_extensionobjecttable.c.  Reviewing the headers of these files indicates
// the files are auto-generated.  For more information see the
// <wireshark code>/plugins/epan/opcua/README as well as the discussion at
// http://www.wireshark.org/lists/wireshark-dev/200704/msg00025.html
//
// References:
//   * https://www.wireshark.org/download/src/
//

#ifndef OPCUA_BINARY_EXTENSION_OBJECT_NODE_ID_H
#define OPCUA_BINARY_EXTENSION_OBJECT_NODE_ID_H
#include <map>

const static uint32_t NoneType_Key                            = 0;
const static uint32_t TrustListDataType_Key                   = 12680;
const static uint32_t Node_Key                                = 260;
const static uint32_t InstanceNode_Key                        = 11889;
const static uint32_t TypeNode_Key                            = 11890;
const static uint32_t ObjectNode_Key                          = 263;
const static uint32_t ObjectTypeNode_Key                      = 266;
const static uint32_t VariableNode_Key                        = 269;
const static uint32_t VariableTypeNode_Key                    = 272;
const static uint32_t ReferenceTypeNode_Key                   = 275;
const static uint32_t MethodNode_Key                          = 278;
const static uint32_t ViewNode_Key                            = 281;
const static uint32_t DataTypeNode_Key                        = 284;
const static uint32_t ReferenceNode_Key                       = 287;
const static uint32_t Argument_Key                            = 298;
const static uint32_t EnumValueType_Key                       = 8251;
const static uint32_t OptionSet_Key                           = 12765;
const static uint32_t TimeZoneDataType_Key                    = 8917;
const static uint32_t ApplicationDescription_Key              = 310;
const static uint32_t RequestHeader_Key                       = 391;
const static uint32_t ResponseHeader_Key                      = 394;
const static uint32_t ServerOnNetwork_Key                     = 12207;
const static uint32_t UserTokenPolicy_Key                     = 306;
const static uint32_t EndpointDescription_Key                 = 314;
const static uint32_t RegisteredServer_Key                    = 434;
const static uint32_t MdnsDiscoveryConfiguration_Key          = 12901;
const static uint32_t ChannelSecurityToken_Key                = 443;
const static uint32_t SignedSoftwareCertificate_Key           = 346;
const static uint32_t SignatureData_Key                       = 458;
const static uint32_t UserIdentityToken_Key                   = 318;
const static uint32_t AnonymousIdentityToken_Key              = 321;
const static uint32_t UserNameIdentityToken_Key               = 324;
const static uint32_t X509IdentityToken_Key                   = 327;
const static uint32_t KerberosIdentityToken_Key               = 12509;
const static uint32_t IssuedIdentityToken_Key                 = 940;
const static uint32_t NodeAttributes_Key                      = 351;
const static uint32_t ObjectAttributes_Key                    = 354;
const static uint32_t VariableAttributes_Key                  = 357;
const static uint32_t MethodAttributes_Key                    = 360;
const static uint32_t ObjectTypeAttributes_Key                = 363;
const static uint32_t VariableTypeAttributes_Key              = 366;
const static uint32_t ReferenceTypeAttributes_Key             = 369;
const static uint32_t DataTypeAttributes_Key                  = 372;
const static uint32_t ViewAttributes_Key                      = 375;
const static uint32_t AddNodesItem_Key                        = 378;
const static uint32_t AddNodesResult_Key                      = 485;
const static uint32_t AddReferencesItem_Key                   = 381;
const static uint32_t DeleteNodesItem_Key                     = 384;
const static uint32_t DeleteReferencesItem_Key                = 387;
const static uint32_t ViewDescription_Key                     = 513;
const static uint32_t BrowseDescription_Key                   = 516;
const static uint32_t ReferenceDescription_Key                = 520;
const static uint32_t BrowseResult_Key                        = 524;
const static uint32_t RelativePathElement_Key                 = 539;
const static uint32_t RelativePath_Key                        = 542;
const static uint32_t BrowsePath_Key                          = 545;
const static uint32_t BrowsePathTarget_Key                    = 548;
const static uint32_t BrowsePathResult_Key                    = 551;
const static uint32_t EndpointConfiguration_Key               = 333;
const static uint32_t SupportedProfile_Key                    = 337;
const static uint32_t SoftwareCertificate_Key                 = 343;
const static uint32_t QueryDataDescription_Key                = 572;
const static uint32_t NodeTypeDescription_Key                 = 575;
const static uint32_t QueryDataSet_Key                        = 579;
const static uint32_t NodeReference_Key                       = 582;
const static uint32_t ContentFilterElement_Key                = 585;
const static uint32_t ContentFilter_Key                       = 588;
const static uint32_t ElementOperand_Key                      = 594;
const static uint32_t LiteralOperand_Key                      = 597;
const static uint32_t AttributeOperand_Key                    = 600;
const static uint32_t SimpleAttributeOperand_Key              = 603;
const static uint32_t ContentFilterElementResult_Key          = 606;
const static uint32_t ContentFilterResult_Key                 = 609;
const static uint32_t ParsingResult_Key                       = 612;
const static uint32_t ReadValueId_Key                         = 628;
const static uint32_t HistoryReadValueId_Key                  = 637;
const static uint32_t HistoryReadResult_Key                   = 640;
const static uint32_t ReadEventDetails_Key                    = 646;
const static uint32_t ReadRawModifiedDetails_Key              = 649;
const static uint32_t ReadProcessedDetails_Key                = 652;
const static uint32_t ReadAtTimeDetails_Key                   = 655;
const static uint32_t HistoryData_Key                         = 658;
const static uint32_t ModificationInfo_Key                    = 11226;
const static uint32_t HistoryModifiedData_Key                 = 11227;
const static uint32_t HistoryEvent_Key                        = 661;
const static uint32_t WriteValue_Key                          = 670;
const static uint32_t HistoryUpdateDetails_Key                = 679;
const static uint32_t UpdateDataDetails_Key                   = 682;
const static uint32_t UpdateStructureDataDetails_Key          = 11300;
const static uint32_t UpdateEventDetails_Key                  = 685;
const static uint32_t DeleteRawModifiedDetails_Key            = 688;
const static uint32_t DeleteAtTimeDetails_Key                 = 691;
const static uint32_t DeleteEventDetails_Key                  = 694;
const static uint32_t HistoryUpdateResult_Key                 = 697;
const static uint32_t CallMethodRequest_Key                   = 706;
const static uint32_t CallMethodResult_Key                    = 709;
const static uint32_t DataChangeFilter_Key                    = 724;
const static uint32_t EventFilter_Key                         = 727;
const static uint32_t AggregateConfiguration_Key              = 950;
const static uint32_t AggregateFilter_Key                     = 730;
const static uint32_t EventFilterResult_Key                   = 736;
const static uint32_t AggregateFilterResult_Key               = 739;
const static uint32_t MonitoringParameters_Key                = 742;
const static uint32_t MonitoredItemCreateRequest_Key          = 745;
const static uint32_t MonitoredItemCreateResult_Key           = 748;
const static uint32_t MonitoredItemModifyRequest_Key          = 757;
const static uint32_t MonitoredItemModifyResult_Key           = 760;
const static uint32_t NotificationMessage_Key                 = 805;
const static uint32_t DataChangeNotification_Key              = 811;
const static uint32_t MonitoredItemNotification_Key           = 808;
const static uint32_t EventNotificationList_Key               = 916;
const static uint32_t EventFieldList_Key                      = 919;
const static uint32_t HistoryEventFieldList_Key               = 922;
const static uint32_t StatusChangeNotification_Key            = 820;
const static uint32_t SubscriptionAcknowledgement_Key         = 823;
const static uint32_t TransferResult_Key                      = 838;
const static uint32_t ScalarTestType_Key                      = 401;
const static uint32_t ArrayTestType_Key                       = 404;
const static uint32_t CompositeTestType_Key                   = 407;
const static uint32_t BuildInfo_Key                           = 340;
const static uint32_t RedundantServerDataType_Key             = 855;
const static uint32_t EndpointUrlListDataType_Key             = 11957;
const static uint32_t NetworkGroupDataType_Key                = 11958;
const static uint32_t SamplingIntervalDiagnosticsDataType_Key = 858;
const static uint32_t ServerDiagnosticsSummaryDataType_Key    = 861;
const static uint32_t ServerStatusDataType_Key                = 864;
const static uint32_t SessionDiagnosticsDataType_Key          = 867;
const static uint32_t SessionSecurityDiagnosticsDataType_Key  = 870;
const static uint32_t ServiceCounterDataType_Key              = 873;
const static uint32_t StatusResult_Key                        = 301;
const static uint32_t SubscriptionDiagnosticsDataType_Key     = 876;
const static uint32_t ModelChangeStructureDataType_Key        = 879;
const static uint32_t SemanticChangeStructureDataType_Key     = 899;
const static uint32_t Range_Key                               = 886;
const static uint32_t EUInformation_Key                       = 889;
const static uint32_t ComplexNumberType_Key                   = 12181;
const static uint32_t DoubleComplexNumberType_Key             = 12182;
const static uint32_t AxisInformation_Key                     = 12089;
const static uint32_t XVType_Key                              = 12090;
const static uint32_t ProgramDiagnosticDataType_Key           = 896;
const static uint32_t Annotation_Key                          = 893;

static std::map<uint32_t, std::string> EXTENSION_OBJECT_ID_MAP =
{
    { NoneType_Key,                            "NoneType"},
    { TrustListDataType_Key,                   "TrustListDataType" },
    { Node_Key,                                "Node" },
    { InstanceNode_Key,                        "InstanceNode" },
    { TypeNode_Key,                            "TypeNode" },
    { ObjectNode_Key,                          "ObjectNode" },
    { ObjectTypeNode_Key,                      "ObjectTypeNode" },
    { VariableNode_Key,                        "VariableNode" },
    { VariableTypeNode_Key,                    "VariableTypeNode" },
    { ReferenceTypeNode_Key,                   "ReferenceTypeNode" },
    { MethodNode_Key,                          "MethodNode" },
    { ViewNode_Key,                            "ViewNode" },
    { DataTypeNode_Key,                        "DataTypeNode" },
    { ReferenceNode_Key,                       "ReferenceNode" },
    { Argument_Key,                            "Argument" },
    { EnumValueType_Key,                       "EnumValueType" },
    { OptionSet_Key,                           "OptionSet" },
    { TimeZoneDataType_Key,                    "TimeZoneDataType" },
    { ApplicationDescription_Key,              "ApplicationDescription" },
    { RequestHeader_Key,                       "RequestHeader" },
    { ResponseHeader_Key,                      "ResponseHeader" },
    { ServerOnNetwork_Key,                     "ServerOnNetwork" },
    { UserTokenPolicy_Key,                     "UserTokenPolicy" },
    { EndpointDescription_Key,                 "EndpointDescription" },
    { RegisteredServer_Key,                    "RegisteredServer" },
    { MdnsDiscoveryConfiguration_Key,          "MdnsDiscoveryConfiguration" },
    { ChannelSecurityToken_Key,                "ChannelSecurityToken" },
    { SignedSoftwareCertificate_Key,           "SignedSoftwareCertificate" },
    { SignatureData_Key,                       "SignatureData" },
    { UserIdentityToken_Key,                   "UserIdentityToken" },
    { AnonymousIdentityToken_Key,              "AnonymousIdentityToken" },
    { UserNameIdentityToken_Key,               "UserNameIdentityToken" },
    { X509IdentityToken_Key,                   "X509IdentityToken" },
    { KerberosIdentityToken_Key,               "KerberosIdentityToken" },
    { IssuedIdentityToken_Key,                 "IssuedIdentityToken" },
    { NodeAttributes_Key,                      "NodeAttributes" },
    { ObjectAttributes_Key,                    "ObjectAttributes" },
    { VariableAttributes_Key,                  "VariableAttributes" },
    { MethodAttributes_Key,                    "MethodAttributes" },
    { ObjectTypeAttributes_Key,                "ObjectTypeAttributes" },
    { VariableTypeAttributes_Key,              "VariableTypeAttributes" },
    { ReferenceTypeAttributes_Key,             "ReferenceTypeAttributes" },
    { DataTypeAttributes_Key,                  "DataTypeAttributes" },
    { ViewAttributes_Key,                      "ViewAttributes" },
    { AddNodesItem_Key,                        "AddNodesItem" },
    { AddNodesResult_Key,                      "AddNodesResult" },
    { AddReferencesItem_Key,                   "AddReferencesItem" },
    { DeleteNodesItem_Key,                     "DeleteNodesItem" },
    { DeleteReferencesItem_Key,                "DeleteReferencesItem" },
    { ViewDescription_Key,                     "ViewDescription" },
    { BrowseDescription_Key,                   "BrowseDescription" },
    { ReferenceDescription_Key,                "ReferenceDescription" },
    { BrowseResult_Key,                        "BrowseResult" },
    { RelativePathElement_Key,                 "RelativePathElement" },
    { RelativePath_Key,                        "RelativePath" },
    { BrowsePath_Key,                          "BrowsePath" },
    { BrowsePathTarget_Key,                    "BrowsePathTarget" },
    { BrowsePathResult_Key,                    "BrowsePathResult" },
    { EndpointConfiguration_Key,               "EndpointConfiguration" },
    { SupportedProfile_Key,                    "SupportedProfile" },
    { SoftwareCertificate_Key,                 "SoftwareCertificate" },
    { QueryDataDescription_Key,                "QueryDataDescription" },
    { NodeTypeDescription_Key,                 "NodeTypeDescription" },
    { QueryDataSet_Key,                        "QueryDataSet" },
    { NodeReference_Key,                       "NodeReference" },
    { ContentFilterElement_Key,                "ContentFilterElement" },
    { ContentFilter_Key,                       "ContentFilter" },
    { ElementOperand_Key,                      "ElementOperand" },
    { LiteralOperand_Key,                      "LiteralOperand" },
    { AttributeOperand_Key,                    "AttributeOperand" },
    { SimpleAttributeOperand_Key,              "SimpleAttributeOperand" },
    { ContentFilterElementResult_Key,          "ContentFilterElementResult" },
    { ContentFilterResult_Key,                 "ContentFilterResult" },
    { ParsingResult_Key,                       "ParsingResult" },
    { ReadValueId_Key,                         "ReadValueId" },
    { HistoryReadValueId_Key,                  "HistoryReadValueId" },
    { HistoryReadResult_Key,                   "HistoryReadResult" },
    { ReadEventDetails_Key,                    "ReadEventDetails" },
    { ReadRawModifiedDetails_Key,              "ReadRawModifiedDetails" },
    { ReadProcessedDetails_Key,                "ReadProcessedDetails" },
    { ReadAtTimeDetails_Key,                   "ReadAtTimeDetails" },
    { HistoryData_Key,                         "HistoryData" },
    { ModificationInfo_Key,                    "ModificationInfo" },
    { HistoryModifiedData_Key,                 "HistoryModifiedData" },
    { HistoryEvent_Key,                        "HistoryEvent" },
    { WriteValue_Key,                          "WriteValue" },
    { HistoryUpdateDetails_Key,                "HistoryUpdateDetails" },
    { UpdateDataDetails_Key,                   "UpdateDataDetails" },
    { UpdateStructureDataDetails_Key,          "UpdateStructureDataDetails" },
    { UpdateEventDetails_Key,                  "UpdateEventDetails" },
    { DeleteRawModifiedDetails_Key,            "DeleteRawModifiedDetails" },
    { DeleteAtTimeDetails_Key,                 "DeleteAtTimeDetails" },
    { DeleteEventDetails_Key,                  "DeleteEventDetails" },
    { HistoryUpdateResult_Key,                 "HistoryUpdateResult" },
    { CallMethodRequest_Key,                   "CallMethodRequest" },
    { CallMethodResult_Key,                    "CallMethodResult" },
    { DataChangeFilter_Key,                    "Filter" },
    { EventFilter_Key,                         "Filter" },
    { AggregateConfiguration_Key,              "AggregateConfiguration" },
    { AggregateFilter_Key,                     "Filter" },
    { EventFilterResult_Key,                   "FilterResult" },
    { AggregateFilterResult_Key,               "FilterResult" },
    { MonitoringParameters_Key,                "MonitoringParameters" },
    { MonitoredItemCreateRequest_Key,          "MonitoredItemCreateRequest" },
    { MonitoredItemCreateResult_Key,           "MonitoredItemCreateResult" },
    { MonitoredItemModifyRequest_Key,          "MonitoredItemModifyRequest" },
    { MonitoredItemModifyResult_Key,           "MonitoredItemModifyResult" },
    { NotificationMessage_Key,                 "NotificationMessage" },
    { DataChangeNotification_Key,              "DataChangeNotification" },
    { MonitoredItemNotification_Key,           "MonitoredItemNotification" },
    { EventNotificationList_Key,               "EventNotificationList" },
    { EventFieldList_Key,                      "EventFieldList" },
    { HistoryEventFieldList_Key,               "HistoryEventFieldList" },
    { StatusChangeNotification_Key,            "StatusChangeNotification" },
    { SubscriptionAcknowledgement_Key,         "SubscriptionAcknowledgement" },
    { TransferResult_Key,                      "TransferResult" },
    { ScalarTestType_Key,                      "ScalarTestType" },
    { ArrayTestType_Key,                       "ArrayTestType" },
    { CompositeTestType_Key,                   "CompositeTestType" },
    { BuildInfo_Key,                           "BuildInfo" },
    { RedundantServerDataType_Key,             "RedundantServerDataType" },
    { EndpointUrlListDataType_Key,             "EndpointUrlListDataType" },
    { NetworkGroupDataType_Key,                "NetworkGroupDataType" },
    { SamplingIntervalDiagnosticsDataType_Key, "SamplingIntervalDiagnosticsDataType" },
    { ServerDiagnosticsSummaryDataType_Key,    "ServerDiagnosticsSummaryDataType" },
    { ServerStatusDataType_Key,                "ServerStatusDataType" },
    { SessionDiagnosticsDataType_Key,          "SessionDiagnosticsDataType" },
    { SessionSecurityDiagnosticsDataType_Key,  "SessionSecurityDiagnosticsDataType" },
    { ServiceCounterDataType_Key,              "ServiceCounterDataType" },
    { StatusResult_Key,                        "StatusResult" },
    { SubscriptionDiagnosticsDataType_Key,     "SubscriptionDiagnosticsDataType" },
    { ModelChangeStructureDataType_Key,        "ModelChangeStructureDataType" },
    { SemanticChangeStructureDataType_Key,     "SemanticChangeStructureDataType" },
    { Range_Key,                               "Range" },
    { EUInformation_Key,                       "EUInformation" },
    { ComplexNumberType_Key,                   "ComplexNumberType" },
    { DoubleComplexNumberType_Key,             "DoubleComplexNumberType" },
    { AxisInformation_Key,                     "AxisInformation" },
    { XVType_Key,                              "XVType" },
    { ProgramDiagnosticDataType_Key,           "ProgramDiagnosticDataType" },
    { Annotation_Key,                          "Annotation" }
};

#endif
