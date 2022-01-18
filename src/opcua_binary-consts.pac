## opcua_binary-consts.pac
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
# Table 6 - NodeId DataEncoding:  
#
# Value Description
#  0x00 A numeric value that fits into the two-byte representation.
#  0x01 A numeric value that fits into the four-byte representation.
#  0x02 A numeric value that does not fit into the two or four byte representations.
#  0x03 A String value.
#  0x04 A Guid value.
#  0x05 An opaque (ByteString) value.
#  0x80 NamespaceUriFlag See discussion of ExpandedNodeId in 5.2.2.10.
#  0x40 ServerIndexFlag See discussion of ExpandedNodeId in 5.2.2.10.
#
enum node_encoding 
{
        TwoByte          = 0x00,
        FourByte         = 0x01,
        Numeric          = 0x02,
        String           = 0x03,
        GUID             = 0x04,
        Opaque           = 0x05,
        NamespaceUriFlag = 0x80,
        ServerIndexFlag  = 0x40
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
