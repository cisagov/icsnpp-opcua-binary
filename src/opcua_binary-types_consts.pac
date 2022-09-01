## opcua_binary-types-consts.pac
##
## OPCUA Binary Protocol Analyzer
##
## Constants defined in the OPCUA Binary specifications.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 6 - Mappings 1.04.pdf
# Table 41 and Table 50 Message Types
#
# A three byte code that identifies the Message Type
#
enum msg_type
{
    HEL = 0x48454c,
    ACK = 0x41434b,
    ERR = 0x455252,
    RHE = 0x524845,
    MSG = 0x4d5347,
    OPN = 0x4f504e,
    CLO = 0x434c4f
}

#
# UA Specification Part 6 - Mappings 1.04.pdf
# Table 11 - DiagnosticInfo Encoding Mask
#
enum diag_info_mask
{
    hasSymbolicId    = 0x01,
    hasNamespaceUri  = 0x02,
    hasLocalizedTxt  = 0x04,
    hasLocale        = 0x08,
    hasAddlInfo      = 0x10,
    hasInnerStatCode = 0x20,
    hasInnerDiagInfo = 0x40
   
}

#
# UA Specification Part 6 - Mappings 1.04.pdf
# Table 14 - Extension Object Binary DataEncoding
#
enum extension_object_encoding
{
    hasNoEncoding     = 0x00,
    hasBinaryEncoding = 0x01,
    hasXMLEncoding    = 0x02
}

#
# Numeric Node Identifiers for OPCUA Binary protocol services.  The enumerations
# are used when parsing the protocol and determining the service based
# off the parsed identifier 
#
enum node_identifier
{
  ServiceFault                          = 397,
  FindServersRequest                    = 422,
  FindServersResponse                   = 425,
  FindServersOnNetworkRequest           = 12208,
  FindServersOnNetworkResponse          = 12209,
  GetEndpointsRequest                   = 428,
  GetEndpointsResponse                  = 431,
  RegisterServerRequest                 = 437,
  RegisterServerResponse                = 440,
  RegisterServer2Request                = 12211,
  RegisterServer2Response               = 12212,
  OpenSecureChannelRequest              = 446,
  OpenSecureChannelResponse             = 449,
  CloseSecureChannelRequest             = 452,
  CloseSecureChannelResponse            = 455,
  CreateSessionRequest                  = 461,
  CreateSessionResponse                 = 464,
  ActivateSessionRequest                = 467,
  ActivateSessionResponse               = 470,
  CloseSessionRequest                   = 473,
  CloseSessionResponse                  = 476,
  CancelRequest                         = 479,
  CancelResponse                        = 482,
  AddNodesRequest                       = 488,
  AddNodesResponse                      = 491,
  AddReferencesRequest                  = 494,
  AddReferencesResponse                 = 497,
  DeleteNodesRequest                    = 500,
  DeleteNodesResponse                   = 503,
  DeleteReferencesRequest               = 506,
  DeleteReferencesResponse              = 509,
  BrowseRequest                         = 527,
  BrowseResponse                        = 530,
  BrowseNextRequest                     = 533,
  BrowseNextResponse                    = 536,
  TranslateBrowsePathsToNodeIdsRequest  = 554,
  TranslateBrowsePathsToNodeIdsResponse = 557,
  RegisterNodesRequest                  = 560,
  RegisterNodesResponse                 = 563,
  UnregisterNodesRequest                = 566,
  UnregisterNodesResponse               = 569,
  QueryFirstRequest                     = 615,
  QueryFirstResponse                    = 618,
  QueryNextRequest                      = 621,
  QueryNextResponse                     = 624,
  ReadRequest                           = 631,
  ReadResponse                          = 634,
  HistoryReadRequest                    = 664,
  HistoryReadResponse                   = 667,
  WriteRequest                          = 673,
  WriteResponse                         = 676,
  HistoryUpdateRequest                  = 700,
  HistoryUpdateResponse                 = 703,
  CallRequest                           = 712,
  CallResponse                          = 715,
  CreateMonitoredItemsRequest           = 751,
  CreateMonitoredItemsResponse          = 754,
  ModifyMonitoredItemsRequest           = 763,
  ModifyMonitoredItemsResponse          = 766,
  SetMonitoringModeRequest              = 769,
  SetMonitoringModeResponse             = 772,
  SetTriggeringRequest                  = 775,
  SetTriggeringResponse                 = 778,
  DeleteMonitoredItemsRequest           = 781,
  DeleteMonitoredItemsResponse          = 784,
  CreateSubscriptionRequest             = 787,
  CreateSubscriptionResponse            = 790,
  ModifySubscriptionRequest             = 793,
  ModifySubscriptionResponse            = 796,
  SetPublishingModeRequest              = 799,
  SetPublishingModeResponse             = 802,
  PublishRequest                        = 826,
  PublishResponse                       = 829,
  RepublishRequest                      = 832,
  RepublishResponse                     = 835,
  TransferSubscriptionsRequest          = 841,
  TransferSubscriptionsResponse         = 844,
  DeleteSubscriptionsRequest            = 847,
  DeleteSubscriptionsResponse           = 850,
  TestStackRequest                      = 410,
  TestStackResponse                     = 413,
  TestStackExRequest                    = 416,
  TestStackExResponse                   = 419
}

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.1 - Table 112 - ApplicationDescription
#
enum application_type
{
    SERVER_0          = 0,
    CLIENT_1          = 1,
    CLIENTANDSERVER_2 = 2,
    DISCOVERYSERVER_3 = 3
}

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.15 - Table 138 - MessageSecurityMode
#
enum message_security_mode
{
    INVALID_0        = 0,
    NONE_1           = 1,
    SIGN_2           = 2,
    SIGNANDENCRYPT_3 = 3
}

#
# UA Specification Part 4 - Services 1.04.pdf
#
# 7.37 - Table 190 - UserTokenPolicy
#
enum user_token_policy
{
    ANONYMOUS_0   = 0,
    USERNAME_1    = 1,
    CERTIFICATE_2 = 2,
    ISSUEDTOKEN_3 = 3
}

#
# UA Specification Part 6 - Mappings 1.04.pdf
# Table 13 - LocalizedText Binary DataEncoding
#
enum localized_text_mask
{
    localizedTextHasLocale = 0x01,
    localizedTextHasText   = 0x02
}

#
# UA Specification Part 6 - Mappings 1.04.pdf 
#
# Annex A.3 - Numeric Node Ids provides a link to the CSV that that contains
# extension object node identifiers.  This file contains ~14,000 node
# identifiers along with symbol names and node class.  
#
# The subset of identifiers defined below are based on the Wireshark
# OPCUA plugin code base.  Specifically the files opcua_extensionobjectids.h
# and opcua_extensionobjecttable.c.  Reviewing the headers of these files indicates
# the files are auto-generated.  For more information see the
# <wireshark code>/plugins/epan/opcua/README as well as the discussion at
# http://www.wireshark.org/lists/wireshark-dev/200704/msg00025.html
#
# References:
#   * https://www.wireshark.org/download/src/
#
enum extension_object_node
{
    NoneType                            = 0,
    TrustListDataType                   = 12680,
    Node                                = 260,
    InstanceNode                        = 11889,
    TypeNode                            = 11890,
    ObjectNode                          = 263,
    ObjectTypeNode                      = 266,
    VariableNode                        = 269,
    VariableTypeNode                    = 272,
    ReferenceTypeNode                   = 275,
    MethodNode                          = 278,
    ViewNode                            = 281,
    DataTypeNode                        = 284,
    ReferenceNode                       = 287,
    Argument                            = 298,
    EnumValueType                       = 8251,
    OptionSet                           = 12765,
    TimeZoneDataType                    = 8917,
    ApplicationDescription              = 310,
    RequestHeader                       = 391,
    ResponseHeader                      = 394,
    ServerOnNetwork                     = 12207,
    UserTokenPolicy                     = 306,
    EndpointDescription                 = 314,
    RegisteredServer                    = 434,
    MdnsDiscoveryConfiguration          = 12901,
    ChannelSecurityToken                = 443,
    SignedSoftwareCertificate           = 346,
    SignatureData                       = 458,
    UserIdentityToken                   = 318,
    AnonymousIdentityToken              = 321,
    UserNameIdentityToken               = 324,
    X509IdentityToken                   = 327,
    KerberosIdentityToken               = 12509,
    IssuedIdentityToken                 = 940,
    NodeAttributes                      = 351,
    ObjectAttributes                    = 354,
    VariableAttributes                  = 357,
    MethodAttributes                    = 360,
    ObjectTypeAttributes                = 363,
    VariableTypeAttributes              = 366,
    ReferenceTypeAttributes             = 369,
    DataTypeAttributes                  = 372,
    ViewAttributes                      = 375,
    AddNodesItem                        = 378,
    AddNodesResult                      = 485,
    AddReferencesItem                   = 381,
    DeleteNodesItem                     = 384,
    DeleteReferencesItem                = 387,
    ViewDescription                     = 513,
    BrowseDescription                   = 516,
    ReferenceDescription                = 520,
    BrowseResult                        = 524,
    RelativePathElement                 = 539,
    RelativePath                        = 542,
    BrowsePath                          = 545,
    BrowsePathTarget                    = 548,
    BrowsePathResult                    = 551,
    EndpointConfiguration               = 333,
    SupportedProfile                    = 337,
    SoftwareCertificate                 = 343,
    QueryDataDescription                = 572,
    NodeTypeDescription                 = 575,
    QueryDataSet                        = 579,
    NodeReference                       = 582,
    ContentFilterElement                = 585,
    ContentFilter                       = 588,
    ElementOperand                      = 594,
    LiteralOperand                      = 597,
    AttributeOperand                    = 600,
    SimpleAttributeOperand              = 603,
    ContentFilterElementResult          = 606,
    ContentFilterResult                 = 609,
    ParsingResult                       = 612,
    ReadValueId                         = 628,
    HistoryReadValueId                  = 637,
    HistoryReadResult                   = 640,
    ReadEventDetails                    = 646,
    ReadRawModifiedDetails              = 649,
    ReadProcessedDetails                = 652,
    ReadAtTimeDetails                   = 655,
    HistoryData                         = 658,
    ModificationInfo                    = 11226,
    HistoryModifiedData                 = 11227,
    HistoryEvent                        = 661,
    WriteValue                          = 670,
    HistoryUpdateDetails                = 679,
    UpdateDataDetails                   = 682,
    UpdateStructureDataDetails          = 11300,
    UpdateEventDetails                  = 685,
    DeleteRawModifiedDetails            = 688,
    DeleteAtTimeDetails                 = 691,
    DeleteEventDetails                  = 694,
    HistoryUpdateResult                 = 697,
    CallMethodRequest                   = 706,
    CallMethodResult                    = 709,
    DataChangeFilter                    = 724,
    EventFilter                         = 727,
    AggregateConfiguration              = 950,
    AggregateFilter                     = 730,
    EventFilterResult                   = 736,
    AggregateFilterResult               = 739,
    MonitoringParameters                = 742,
    MonitoredItemCreateRequest          = 745,
    MonitoredItemCreateResult           = 748,
    MonitoredItemModifyRequest          = 757,
    MonitoredItemModifyResult           = 760,
    NotificationMessage                 = 805,
    DataChangeNotification              = 811,
    MonitoredItemNotification           = 808,
    EventNotificationList               = 916,
    EventFieldList                      = 919,
    HistoryEventFieldList               = 922,
    StatusChangeNotification            = 820,
    SubscriptionAcknowledgement         = 823,
    TransferResult                      = 838,
    ScalarTestType                      = 401,
    ArrayTestType                       = 404,
    CompositeTestType                   = 407,
    BuildInfo                           = 340,
    RedundantServerDataType             = 855,
    EndpointUrlListDataType             = 11957,
    NetworkGroupDataType                = 11958,
    SamplingIntervalDiagnosticsDataType = 858,
    ServerDiagnosticsSummaryDataType    = 861,
    ServerStatusDataType                = 864,
    SessionDiagnosticsDataType          = 867,
    SessionSecurityDiagnosticsDataType  = 870,
    ServiceCounterDataType              = 873,
    StatusResult                        = 301,
    SubscriptionDiagnosticsDataType     = 876,
    ModelChangeStructureDataType        = 879,
    SemanticChangeStructureDataType     = 899,
    Range                               = 886,
    EUInformation                       = 889,
    ComplexNumberType                   = 12181,
    DoubleComplexNumberType             = 12182,
    AxisInformation                     = 12089,
    XVType                              = 12090,
    ProgramDiagnosticDataType           = 896,
    Annotation                          = 893
}
