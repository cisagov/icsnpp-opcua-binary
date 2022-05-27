
// OPCUA_Binary.cc
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
//

// UA Specification Part 4 - Services 1.04.pdf
//
// 7.34 StatusCode
// A StatusCode in OPC UA is numerical value that is used to report the outcome of an operation performed 
// by an OPC UA Server.  This code may have associated diagnostic information that describes the status 
// in more detail; however, the code by itself is intended to provide Client applications with enough 
// information to make decisions on how to process the results of an OPC UA Service
//
// The StatusCode is a 32-bit unsigned integer.  The top 16 bits represent the numveric value of the code
// that shall be used for detecting specific errors or conditions.  The bottom 16 bits are bit flags that
// contain additional information but do not affect the meaning of the StatusCode.
// 
#ifndef OPCUA_BINARY_STATUS_CODES_H
#define OPCUA_BINARY_STATUS_CODES_H
#include <map>

//
// UA Specification Part 6 - Mappings 1.04.pdf
//
// A.2 StatusCode
// The CSV defining the numeric identifiers for all of the StatusCodes defined by the OPC UA Specificaion
// can be found here:
//    http://www.opcfoundation.org/UA/schemas/1.04/StatusCode.csv
//
static uint32_t StatusCode_Good                                                            = 0x00000000; // All is good.
static uint32_t StatusCode_BadUnexpectedError                                              = 0x80010000; // An unexpected error occurred.
static uint32_t StatusCode_BadInternalError                                                = 0x80020000; // An internal error occurred as a result of a programming or configuration error.
static uint32_t StatusCode_BadOutOfMemory                                                  = 0x80030000; // Not enough memory to complete the operation.
static uint32_t StatusCode_BadResourceUnavailable                                          = 0x80040000; // An operating system resource is not available.
static uint32_t StatusCode_BadCommunicationError                                           = 0x80050000; // A low level communication error occurred.
static uint32_t StatusCode_BadEncodingError                                                = 0x80060000; // Encoding halted because of invalid data in the objects being serialized.
static uint32_t StatusCode_BadDecodingError                                                = 0x80070000; // Decoding halted because of invalid data in the stream.
static uint32_t StatusCode_BadEncodingLimitsExceeded                                       = 0x80080000; // The message encoding/decoding limits imposed by the stack have been exceeded.
static uint32_t StatusCode_BadRequestTooLarge                                              = 0x80B80000; // The request message size exceeds limits set by the server.
static uint32_t StatusCode_BadResponseTooLarge                                             = 0x80B90000; // The response message size exceeds limits set by the client.
static uint32_t StatusCode_BadUnknownResponse                                              = 0x80090000; // An unrecognized response was received from the server.
static uint32_t StatusCode_BadTimeout                                                      = 0x800A0000; // The operation timed out.
static uint32_t StatusCode_BadServiceUnsupported                                           = 0x800B0000; // The server does not support the requested service.
static uint32_t StatusCode_BadShutdown                                                     = 0x800C0000; // The operation was cancelled because the application is shutting down.
static uint32_t StatusCode_BadServerNotConnected                                           = 0x800D0000; // The operation could not complete because the client is not connected to the server.
static uint32_t StatusCode_BadServerHalted                                                 = 0x800E0000; // The server has stopped and cannot process any requests.
static uint32_t StatusCode_BadNothingToDo                                                  = 0x800F0000; // There was nothing to do because the client passed a list of operations with no elements.
static uint32_t StatusCode_BadTooManyOperations                                            = 0x80100000; // The request could not be processed because it specified too many operations.
static uint32_t StatusCode_BadTooManyMonitoredItems                                        = 0x80DB0000; // The request could not be processed because there are too many monitored items in the subscription.
static uint32_t StatusCode_BadDataTypeIdUnknown                                            = 0x80110000; // The extension object cannot be (de)serialized because the data type id is not recognized.
static uint32_t StatusCode_BadCertificateInvalid                                           = 0x80120000; // The certificate provided as a parameter is not valid.
static uint32_t StatusCode_BadSecurityChecksFailed                                         = 0x80130000; // An error occurred verifying security.
static uint32_t StatusCode_BadCertificatePolicyCheckFailed                                 = 0x81140000; // The certificate does not meet the requirements of the security policy.
static uint32_t StatusCode_BadCertificateTimeInvalid                                       = 0x80140000; // The certificate has expired or is not yet valid.
static uint32_t StatusCode_BadCertificateIssuerTimeInvalid                                 = 0x80150000; // An issuer certificate has expired or is not yet valid.
static uint32_t StatusCode_BadCertificateHostNameInvalid                                   = 0x80160000; // The HostName used to connect to a server does not match a HostName in the certificate.
static uint32_t StatusCode_BadCertificateUriInvalid                                        = 0x80170000; // The URI specified in the ApplicationDescription does not match the URI in the certificate.
static uint32_t StatusCode_BadCertificateUseNotAllowed                                     = 0x80180000; // The certificate may not be used for the requested operation.
static uint32_t StatusCode_BadCertificateIssuerUseNotAllowed                               = 0x80190000; // The issuer certificate may not be used for the requested operation.
static uint32_t StatusCode_BadCertificateUntrusted                                         = 0x801A0000; // The certificate is not trusted.
static uint32_t StatusCode_BadCertificateRevocationUnknown                                 = 0x801B0000; // It was not possible to determine if the certificate has been revoked.
static uint32_t StatusCode_BadCertificateIssuerRevocationUnknown                           = 0x801C0000; // It was not possible to determine if the issuer certificate has been revoked.
static uint32_t StatusCode_BadCertificateRevoked                                           = 0x801D0000; // The certificate has been revoked.
static uint32_t StatusCode_BadCertificateIssuerRevoked                                     = 0x801E0000; // The issuer certificate has been revoked.
static uint32_t StatusCode_BadCertificateChainIncomplete                                   = 0x810D0000; // The certificate chain is incomplete.
static uint32_t StatusCode_BadUserAccessDenied                                             = 0x801F0000; // User does not have permission to perform the requested operation.
static uint32_t StatusCode_BadIdentityTokenInvalid                                         = 0x80200000; // The user identity token is not valid.
static uint32_t StatusCode_BadIdentityTokenRejected                                        = 0x80210000; // The user identity token is valid but the server has rejected it.
static uint32_t StatusCode_BadSecureChannelIdInvalid                                       = 0x80220000; // The specified secure channel is no longer valid.
static uint32_t StatusCode_BadInvalidTimestamp                                             = 0x80230000; // The timestamp is outside the range allowed by the server.
static uint32_t StatusCode_BadNonceInvalid                                                 = 0x80240000; // The nonce does appear to be not a random value or it is not the correct length.
static uint32_t StatusCode_BadSessionIdInvalid                                             = 0x80250000; // The session id is not valid.
static uint32_t StatusCode_BadSessionClosed                                                = 0x80260000; // The session was closed by the client.
static uint32_t StatusCode_BadSessionNotActivated                                          = 0x80270000; // The session cannot be used because ActivateSession has not been called.
static uint32_t StatusCode_BadSubscriptionIdInvalid                                        = 0x80280000; // The subscription id is not valid.
static uint32_t StatusCode_BadRequestHeaderInvalid                                         = 0x802A0000; // The header for the request is missing or invalid.
static uint32_t StatusCode_BadTimestampsToReturnInvalid                                    = 0x802B0000; // The timestamps to return parameter is invalid.
static uint32_t StatusCode_BadRequestCancelledByClient                                     = 0x802C0000; // The request was cancelled by the client.
static uint32_t StatusCode_BadTooManyArguments                                             = 0x80E50000; // Too many arguments were provided.
static uint32_t StatusCode_BadLicenseExpired                                               = 0x810E0000; // "The server requires a license to operate in general or to perform a service or operation
static uint32_t StatusCode_BadLicenseLimitsExceeded                                        = 0x810F0000; // "The server has limits on number of allowed operations / objects
static uint32_t StatusCode_BadLicenseNotAvailable                                          = 0x81100000; // The server does not have a license which is required to operate in general or to perform a service or operation.
static uint32_t StatusCode_GoodSubscriptionTransferred                                     = 0x002D0000; // The subscription was transferred to another session.
static uint32_t StatusCode_GoodCompletesAsynchronously                                     = 0x002E0000; // The processing will complete asynchronously.
static uint32_t StatusCode_GoodOverload                                                    = 0x002F0000; // Sampling has slowed down due to resource limitations.
static uint32_t StatusCode_GoodClamped                                                     = 0x00300000; // The value written was accepted but was clamped.
static uint32_t StatusCode_BadNoCommunication                                              = 0x80310000; // "Communication with the data source is defined
static uint32_t StatusCode_BadWaitingForInitialData                                        = 0x80320000; // Waiting for the server to obtain values from the underlying data source.
static uint32_t StatusCode_BadNodeIdInvalid                                                = 0x80330000; // The syntax of the node id is not valid.
static uint32_t StatusCode_BadNodeIdUnknown                                                = 0x80340000; // The node id refers to a node that does not exist in the server address space.
static uint32_t StatusCode_BadAttributeIdInvalid                                           = 0x80350000; // The attribute is not supported for the specified Node.
static uint32_t StatusCode_BadIndexRangeInvalid                                            = 0x80360000; // The syntax of the index range parameter is invalid.
static uint32_t StatusCode_BadIndexRangeNoData                                             = 0x80370000; // No data exists within the range of indexes specified.
static uint32_t StatusCode_BadDataEncodingInvalid                                          = 0x80380000; // The data encoding is invalid.
static uint32_t StatusCode_BadDataEncodingUnsupported                                      = 0x80390000; // The server does not support the requested data encoding for the node.
static uint32_t StatusCode_BadNotReadable                                                  = 0x803A0000; // The access level does not allow reading or subscribing to the Node.
static uint32_t StatusCode_BadNotWritable                                                  = 0x803B0000; // The access level does not allow writing to the Node.
static uint32_t StatusCode_BadOutOfRange                                                   = 0x803C0000; // The value was out of range.
static uint32_t StatusCode_BadNotSupported                                                 = 0x803D0000; // The requested operation is not supported.
static uint32_t StatusCode_BadNotFound                                                     = 0x803E0000; // A requested item was not found or a search operation ended without success.
static uint32_t StatusCode_BadObjectDeleted                                                = 0x803F0000; // The object cannot be used because it has been deleted.
static uint32_t StatusCode_BadNotImplemented                                               = 0x80400000; // Requested operation is not implemented.
static uint32_t StatusCode_BadMonitoringModeInvalid                                        = 0x80410000; // The monitoring mode is invalid.
static uint32_t StatusCode_BadMonitoredItemIdInvalid                                       = 0x80420000; // The monitoring item id does not refer to a valid monitored item.
static uint32_t StatusCode_BadMonitoredItemFilterInvalid                                   = 0x80430000; // The monitored item filter parameter is not valid.
static uint32_t StatusCode_BadMonitoredItemFilterUnsupported                               = 0x80440000; // The server does not support the requested monitored item filter.
static uint32_t StatusCode_BadFilterNotAllowed                                             = 0x80450000; // A monitoring filter cannot be used in combination with the attribute specified.
static uint32_t StatusCode_BadStructureMissing                                             = 0x80460000; // A mandatory structured parameter was missing or null.
static uint32_t StatusCode_BadEventFilterInvalid                                           = 0x80470000; // The event filter is not valid.
static uint32_t StatusCode_BadContentFilterInvalid                                         = 0x80480000; // The content filter is not valid.
static uint32_t StatusCode_BadFilterOperatorInvalid                                        = 0x80C10000; // An unrecognized operator was provided in a filter.
static uint32_t StatusCode_BadFilterOperatorUnsupported                                    = 0x80C20000; // "A valid operator was provided
static uint32_t StatusCode_BadFilterOperandCountMismatch                                   = 0x80C30000; // The number of operands provided for the filter operator was less then expected for the operand provided.
static uint32_t StatusCode_BadFilterOperandInvalid                                         = 0x80490000; // The operand used in a content filter is not valid.
static uint32_t StatusCode_BadFilterElementInvalid                                         = 0x80C40000; // The referenced element is not a valid element in the content filter.
static uint32_t StatusCode_BadFilterLiteralInvalid                                         = 0x80C50000; // The referenced literal is not a valid value.
static uint32_t StatusCode_BadContinuationPointInvalid                                     = 0x804A0000; // The continuation point provide is longer valid.
static uint32_t StatusCode_BadNoContinuationPoints                                         = 0x804B0000; // The operation could not be processed because all continuation points have been allocated.
static uint32_t StatusCode_BadReferenceTypeIdInvalid                                       = 0x804C0000; // The reference type id does not refer to a valid reference type node.
static uint32_t StatusCode_BadBrowseDirectionInvalid                                       = 0x804D0000; // The browse direction is not valid.
static uint32_t StatusCode_BadNodeNotInView                                                = 0x804E0000; // The node is not part of the view.
static uint32_t StatusCode_BadNumericOverflow                                              = 0x81120000; // The number was not accepted because of a numeric overflow.
static uint32_t StatusCode_BadServerUriInvalid                                             = 0x804F0000; // The ServerUri is not a valid URI.
static uint32_t StatusCode_BadServerNameMissing                                            = 0x80500000; // No ServerName was specified.
static uint32_t StatusCode_BadDiscoveryUrlMissing                                          = 0x80510000; // No DiscoveryUrl was specified.
static uint32_t StatusCode_BadSempahoreFileMissing                                         = 0x80520000; // The semaphore file specified by the client is not valid.
static uint32_t StatusCode_BadRequestTypeInvalid                                           = 0x80530000; // The security token request type is not valid.
static uint32_t StatusCode_BadSecurityModeRejected                                         = 0x80540000; // The security mode does not meet the requirements set by the server.
static uint32_t StatusCode_BadSecurityPolicyRejected                                       = 0x80550000; // The security policy does not meet the requirements set by the server.
static uint32_t StatusCode_BadTooManySessions                                              = 0x80560000; // The server has reached its maximum number of sessions.
static uint32_t StatusCode_BadUserSignatureInvalid                                         = 0x80570000; // The user token signature is missing or invalid.
static uint32_t StatusCode_BadApplicationSignatureInvalid                                  = 0x80580000; // The signature generated with the client certificate is missing or invalid.
static uint32_t StatusCode_BadNoValidCertificates                                          = 0x80590000; // The client did not provide at least one software certificate that is valid and meets the profile requirements for the server.
static uint32_t StatusCode_BadIdentityChangeNotSupported                                   = 0x80C60000; // The server does not support changing the user identity assigned to the session.
static uint32_t StatusCode_BadRequestCancelledByRequest                                    = 0x805A0000; // The request was cancelled by the client with the Cancel service.
static uint32_t StatusCode_BadParentNodeIdInvalid                                          = 0x805B0000; // The parent node id does not to refer to a valid node.
static uint32_t StatusCode_BadReferenceNotAllowed                                          = 0x805C0000; // The reference could not be created because it violates constraints imposed by the data model.
static uint32_t StatusCode_BadNodeIdRejected                                               = 0x805D0000; // The requested node id was reject because it was either invalid or server does not allow node ids to be specified by the client.
static uint32_t StatusCode_BadNodeIdExists                                                 = 0x805E0000; // The requested node id is already used by another node.
static uint32_t StatusCode_BadNodeClassInvalid                                             = 0x805F0000; // The node class is not valid.
static uint32_t StatusCode_BadBrowseNameInvalid                                            = 0x80600000; // The browse name is invalid.
static uint32_t StatusCode_BadBrowseNameDuplicated                                         = 0x80610000; // The browse name is not unique among nodes that share the same relationship with the parent.
static uint32_t StatusCode_BadNodeAttributesInvalid                                        = 0x80620000; // The node attributes are not valid for the node class.
static uint32_t StatusCode_BadTypeDefinitionInvalid                                        = 0x80630000; // The type definition node id does not reference an appropriate type node.
static uint32_t StatusCode_BadSourceNodeIdInvalid                                          = 0x80640000; // The source node id does not reference a valid node.
static uint32_t StatusCode_BadTargetNodeIdInvalid                                          = 0x80650000; // The target node id does not reference a valid node.
static uint32_t StatusCode_BadDuplicateReferenceNotAllowed                                 = 0x80660000; // The reference type between the nodes is already defined.
static uint32_t StatusCode_BadInvalidSelfReference                                         = 0x80670000; // The server does not allow this type of self reference on this node.
static uint32_t StatusCode_BadReferenceLocalOnly                                           = 0x80680000; // The reference type is not valid for a reference to a remote server.
static uint32_t StatusCode_BadNoDeleteRights                                               = 0x80690000; // The server will not allow the node to be deleted.
static uint32_t StatusCode_UncertainReferenceNotDeleted                                    = 0x40BC0000; // The server was not able to delete all target references.
static uint32_t StatusCode_BadServerIndexInvalid                                           = 0x806A0000; // The server index is not valid.
static uint32_t StatusCode_BadViewIdUnknown                                                = 0x806B0000; // The view id does not refer to a valid view node.
static uint32_t StatusCode_BadViewTimestampInvalid                                         = 0x80C90000; // The view timestamp is not available or not supported.
static uint32_t StatusCode_BadViewParameterMismatch                                        = 0x80CA0000; // The view parameters are not consistent with each other.
static uint32_t StatusCode_BadViewVersionInvalid                                           = 0x80CB0000; // The view version is not available or not supported.
static uint32_t StatusCode_UncertainNotAllNodesAvailable                                   = 0x40C00000; // The list of references may not be complete because the underlying system is not available.
static uint32_t StatusCode_GoodResultsMayBeIncomplete                                      = 0x00BA0000; // The server should have followed a reference to a node in a remote server but did not. The result set may be incomplete.
static uint32_t StatusCode_BadNotTypeDefinition                                            = 0x80C80000; // The provided Nodeid was not a type definition nodeid.
static uint32_t StatusCode_UncertainReferenceOutOfServer                                   = 0x406C0000; // One of the references to follow in the relative path references to a node in the address space in another server.
static uint32_t StatusCode_BadTooManyMatches                                               = 0x806D0000; // The requested operation has too many matches to return.
static uint32_t StatusCode_BadQueryTooComplex                                              = 0x806E0000; // The requested operation requires too many resources in the server.
static uint32_t StatusCode_BadNoMatch                                                      = 0x806F0000; // The requested operation has no match to return.
static uint32_t StatusCode_BadMaxAgeInvalid                                                = 0x80700000; // The max age parameter is invalid.
static uint32_t StatusCode_BadSecurityModeInsufficient                                     = 0x80E60000; // The operation is not permitted over the current secure channel.
static uint32_t StatusCode_BadHistoryOperationInvalid                                      = 0x80710000; // The history details parameter is not valid.
static uint32_t StatusCode_BadHistoryOperationUnsupported                                  = 0x80720000; // The server does not support the requested operation.
static uint32_t StatusCode_BadInvalidTimestampArgument                                     = 0x80BD0000; // The defined timestamp to return was invalid.
static uint32_t StatusCode_BadWriteNotSupported                                            = 0x80730000; // "The server does not support writing the combination of value
static uint32_t StatusCode_BadTypeMismatch                                                 = 0x80740000; // The value supplied for the attribute is not of the same type as the attribute's value.
static uint32_t StatusCode_BadMethodInvalid                                                = 0x80750000; // The method id does not refer to a method for the specified object.
static uint32_t StatusCode_BadArgumentsMissing                                             = 0x80760000; // The client did not specify all of the input arguments for the method.
static uint32_t StatusCode_BadNotExecutable                                                = 0x81110000; // The executable attribute does not allow the execution of the method.
static uint32_t StatusCode_BadTooManySubscriptions                                         = 0x80770000; // The server has reached its maximum number of subscriptions.
static uint32_t StatusCode_BadTooManyPublishRequests                                       = 0x80780000; // The server has reached the maximum number of queued publish requests.
static uint32_t StatusCode_BadNoSubscription                                               = 0x80790000; // There is no subscription available for this session.
static uint32_t StatusCode_BadSequenceNumberUnknown                                        = 0x807A0000; // The sequence number is unknown to the server.
static uint32_t StatusCode_BadMessageNotAvailable                                          = 0x807B0000; // The requested notification message is no longer available.
static uint32_t StatusCode_BadInsufficientClientProfile                                    = 0x807C0000; // The client of the current session does not support one or more Profiles that are necessary for the subscription.
static uint32_t StatusCode_BadStateNotActive                                               = 0x80BF0000; // The sub-state machine is not currently active.
static uint32_t StatusCode_BadAlreadyExists                                                = 0x81150000; // An equivalent rule already exists.
static uint32_t StatusCode_BadTcpServerTooBusy                                             = 0x807D0000; // The server cannot process the request because it is too busy.
static uint32_t StatusCode_BadTcpMessageTypeInvalid                                        = 0x807E0000; // The type of the message specified in the header invalid.
static uint32_t StatusCode_BadTcpSecureChannelUnknown                                      = 0x807F0000; // The SecureChannelId and/or TokenId are not currently in use.
static uint32_t StatusCode_BadTcpMessageTooLarge                                           = 0x80800000; // The size of the message specified in the header is too large.
static uint32_t StatusCode_BadTcpNotEnoughResources                                        = 0x80810000; // There are not enough resources to process the request.
static uint32_t StatusCode_BadTcpInternalError                                             = 0x80820000; // An internal error occurred.
static uint32_t StatusCode_BadTcpEndpointUrlInvalid                                        = 0x80830000; // The server does not recognize the QueryString specified.
static uint32_t StatusCode_BadRequestInterrupted                                           = 0x80840000; // The request could not be sent because of a network interruption.
static uint32_t StatusCode_BadRequestTimeout                                               = 0x80850000; // Timeout occurred while processing the request.
static uint32_t StatusCode_BadSecureChannelClosed                                          = 0x80860000; // The secure channel has been closed.
static uint32_t StatusCode_BadSecureChannelTokenUnknown                                    = 0x80870000; // The token has expired or is not recognized.
static uint32_t StatusCode_BadSequenceNumberInvalid                                        = 0x80880000; // The sequence number is not valid.
static uint32_t StatusCode_BadProtocolVersionUnsupported                                   = 0x80BE0000; // The applications do not have compatible protocol versions.
static uint32_t StatusCode_BadConfigurationError                                           = 0x80890000; // There is a problem with the configuration that affects the usefulness of the value.
static uint32_t StatusCode_BadNotConnected                                                 = 0x808A0000; // "The variable should receive its value from another variable
static uint32_t StatusCode_BadDeviceFailure                                                = 0x808B0000; // There has been a failure in the device/data source that generates the value that has affected the value.
static uint32_t StatusCode_BadSensorFailure                                                = 0x808C0000; // There has been a failure in the sensor from which the value is derived by the device/data source.
static uint32_t StatusCode_BadOutOfService                                                 = 0x808D0000; // The source of the data is not operational.
static uint32_t StatusCode_BadDeadbandFilterInvalid                                        = 0x808E0000; // The deadband filter is not valid.
static uint32_t StatusCode_UncertainNoCommunicationLastUsableValue                         = 0x408F0000; // Communication to the data source has failed. The variable value is the last value that had a good quality.
static uint32_t StatusCode_UncertainLastUsableValue                                        = 0x40900000; // Whatever was updating this value has stopped doing so.
static uint32_t StatusCode_UncertainSubstituteValue                                        = 0x40910000; // The value is an operational value that was manually overwritten.
static uint32_t StatusCode_UncertainInitialValue                                           = 0x40920000; // The value is an initial value for a variable that normally receives its value from another variable.
static uint32_t StatusCode_UncertainSensorNotAccurate                                      = 0x40930000; // The value is at one of the sensor limits.
static uint32_t StatusCode_UncertainEngineeringUnitsExceeded                               = 0x40940000; // The value is outside of the range of values defined for this parameter.
static uint32_t StatusCode_UncertainSubNormal                                              = 0x40950000; // The value is derived from multiple sources and has less than the required number of Good sources.
static uint32_t StatusCode_GoodLocalOverride                                               = 0x00960000; // The value has been overridden.
static uint32_t StatusCode_BadRefreshInProgress                                            = 0x80970000; // "This Condition refresh failed
static uint32_t StatusCode_BadConditionAlreadyDisabled                                     = 0x80980000; // This condition has already been disabled.
static uint32_t StatusCode_BadConditionAlreadyEnabled                                      = 0x80CC0000; // This condition has already been enabled.
static uint32_t StatusCode_BadConditionDisabled                                            = 0x80990000; // "Property not available
static uint32_t StatusCode_BadEventIdUnknown                                               = 0x809A0000; // The specified event id is not recognized.
static uint32_t StatusCode_BadEventNotAcknowledgeable                                      = 0x80BB0000; // The event cannot be acknowledged.
static uint32_t StatusCode_BadDialogNotActive                                              = 0x80CD0000; // The dialog condition is not active.
static uint32_t StatusCode_BadDialogResponseInvalid                                        = 0x80CE0000; // The response is not valid for the dialog.
static uint32_t StatusCode_BadConditionBranchAlreadyAcked                                  = 0x80CF0000; // The condition branch has already been acknowledged.
static uint32_t StatusCode_BadConditionBranchAlreadyConfirmed                              = 0x80D00000; // The condition branch has already been confirmed.
static uint32_t StatusCode_BadConditionAlreadyShelved                                      = 0x80D10000; // The condition has already been shelved.
static uint32_t StatusCode_BadConditionNotShelved                                          = 0x80D20000; // The condition is not currently shelved.
static uint32_t StatusCode_BadShelvingTimeOutOfRange                                       = 0x80D30000; // The shelving time not within an acceptable range.
static uint32_t StatusCode_BadNoData                                                       = 0x809B0000; // No data exists for the requested time range or event filter.
static uint32_t StatusCode_BadBoundNotFound                                                = 0x80D70000; // No data found to provide upper or lower bound value.
static uint32_t StatusCode_BadBoundNotSupported                                            = 0x80D80000; // The server cannot retrieve a bound for the variable.
static uint32_t StatusCode_BadDataLost                                                     = 0x809D0000; // Data is missing due to collection started/stopped/lost.
static uint32_t StatusCode_BadDataUnavailable                                              = 0x809E0000; // "Expected data is unavailable for the requested time range due to an un-mounted volume
static uint32_t StatusCode_BadEntryExists                                                  = 0x809F0000; // The data or event was not successfully inserted because a matching entry exists.
static uint32_t StatusCode_BadNoEntryExists                                                = 0x80A00000; // The data or event was not successfully updated because no matching entry exists.
static uint32_t StatusCode_BadTimestampNotSupported                                        = 0x80A10000; // The client requested history using a timestamp format the server does not support (i.e requested ServerTimestamp when server only supports SourceTimestamp).
static uint32_t StatusCode_GoodEntryInserted                                               = 0x00A20000; // The data or event was successfully inserted into the historical database.
static uint32_t StatusCode_GoodEntryReplaced                                               = 0x00A30000; // The data or event field was successfully replaced in the historical database.
static uint32_t StatusCode_UncertainDataSubNormal                                          = 0x40A40000; // The value is derived from multiple values and has less than the required number of Good values.
static uint32_t StatusCode_GoodNoData                                                      = 0x00A50000; // No data exists for the requested time range or event filter.
static uint32_t StatusCode_GoodMoreData                                                    = 0x00A60000; // The data or event field was successfully replaced in the historical database.
static uint32_t StatusCode_BadAggregateListMismatch                                        = 0x80D40000; // The requested number of Aggregates does not match the requested number of NodeIds.
static uint32_t StatusCode_BadAggregateNotSupported                                        = 0x80D50000; // The requested Aggregate is not support by the server.
static uint32_t StatusCode_BadAggregateInvalidInputs                                       = 0x80D60000; // The aggregate value could not be derived due to invalid data inputs.
static uint32_t StatusCode_BadAggregateConfigurationRejected                               = 0x80DA0000; // The aggregate configuration is not valid for specified node.
static uint32_t StatusCode_GoodDataIgnored                                                 = 0x00D90000; // The request specifies fields which are not valid for the EventType or cannot be saved by the historian.
static uint32_t StatusCode_BadRequestNotAllowed                                            = 0x80E40000; // The request was rejected by the server because it did not meet the criteria set by the server.
static uint32_t StatusCode_BadRequestNotComplete                                           = 0x81130000; // The request has not been processed by the server yet.
static uint32_t StatusCode_GoodEdited                                                      = 0x00DC0000; // The value does not come from the real source and has been edited by the server.
static uint32_t StatusCode_GoodPostActionFailed                                            = 0x00DD0000; // There was an error in execution of these post-actions.
static uint32_t StatusCode_UncertainDominantValueChanged                                   = 0x40DE0000; // The related EngineeringUnit has been changed but the Variable Value is still provided based on the previous unit.
static uint32_t StatusCode_GoodDependentValueChanged                                       = 0x00E00000; // A dependent value has been changed but the change has not been applied to the device.
static uint32_t StatusCode_BadDominantValueChanged                                         = 0x80E10000; // The related EngineeringUnit has been changed but this change has not been applied to the device. The Variable Value is still dependent on the previous unit but its status is currently Bad.
static uint32_t StatusCode_UncertainDependentValueChanged                                  = 0x40E20000; // A dependent value has been changed but the change has not been applied to the device. The quality of the dominant variable is uncertain.
static uint32_t StatusCode_BadDependentValueChanged                                        = 0x80E30000; // A dependent value has been changed but the change has not been applied to the device. The quality of the dominant variable is Bad.
static uint32_t StatusCode_GoodEdited_DependentValueChanged                                = 0x01160000; // It is delivered with a dominant Variable value when a dependent Variable has changed but the change has not been applied.
static uint32_t StatusCode_GoodEdited_DominantValueChanged                                 = 0x01170000; // It is delivered with a dependent Variable value when a dominant Variable has changed but the change has not been applied.
static uint32_t StatusCode_GoodEdited_DominantValueChanged_DependentValueChanged           = 0x01180000; // It is delivered with a dependent Variable value when a dominant or dependent Variable has changed but change has not been applied.
static uint32_t StatusCode_BadEdited_OutOfRange                                            = 0x81190000; // It is delivered with a Variable value when Variable has changed but the value is not legal.
static uint32_t StatusCode_BadInitialValue_OutOfRange                                      = 0x811A0000; // It is delivered with a Variable value when a source Variable has changed but the value is not legal.
static uint32_t StatusCode_BadOutOfRange_DominantValueChanged                              = 0x811B0000; // It is delivered with a dependent Variable value when a dominant Variable has changed and the value is not legal.
static uint32_t StatusCode_BadEdited_OutOfRange_DominantValueChanged                       = 0x811C0000; // "It is delivered with a dependent Variable value when a dominant Variable has changed
static uint32_t StatusCode_BadOutOfRange_DominantValueChanged_DependentValueChanged        = 0x811D0000; // It is delivered with a dependent Variable value when a dominant or dependent Variable has changed and the value is not legal.
static uint32_t StatusCode_BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged = 0x811E0000; // "It is delivered with a dependent Variable value when a dominant or dependent Variable has changed
static uint32_t StatusCode_GoodCommunicationEvent                                          = 0x00A70000; // The communication layer has raised an event.
static uint32_t StatusCode_GoodShutdownEvent                                               = 0x00A80000; // The system is shutting down.
static uint32_t StatusCode_GoodCallAgain                                                   = 0x00A90000; // The operation is not finished and needs to be called again.
static uint32_t StatusCode_GoodNonCriticalTimeout                                          = 0x00AA0000; // A non-critical timeout occurred.
static uint32_t StatusCode_BadInvalidArgument                                              = 0x80AB0000; // One or more arguments are invalid.
static uint32_t StatusCode_BadConnectionRejected                                           = 0x80AC0000; // Could not establish a network connection to remote server.
static uint32_t StatusCode_BadDisconnect                                                   = 0x80AD0000; // The server has disconnected from the client.
static uint32_t StatusCode_BadConnectionClosed                                             = 0x80AE0000; // The network connection has been closed.
static uint32_t StatusCode_BadInvalidState                                                 = 0x80AF0000; // "The operation cannot be completed because the object is closed
static uint32_t StatusCode_BadEndOfStream                                                  = 0x80B00000; // Cannot move beyond end of the stream.
static uint32_t StatusCode_BadNoDataAvailable                                              = 0x80B10000; // No data is currently available for reading from a non-blocking stream.
static uint32_t StatusCode_BadWaitingForResponse                                           = 0x80B20000; // The asynchronous operation is waiting for a response.
static uint32_t StatusCode_BadOperationAbandoned                                           = 0x80B30000; // The asynchronous operation was abandoned by the caller.
static uint32_t StatusCode_BadExpectedStreamToBlock                                        = 0x80B40000; // The stream did not return all data requested (possibly because it is a non-blocking stream).
static uint32_t StatusCode_BadWouldBlock                                                   = 0x80B50000; // Non blocking behaviour is required and the operation would block.
static uint32_t StatusCode_BadSyntaxError                                                  = 0x80B60000; // A value had an invalid syntax.
static uint32_t StatusCode_BadMaxConnectionsReached                                        = 0x80B70000; // The operation could not be finished because all available connections are in use.

static std::map<uint32_t, std::string> STATUS_CODE_MAP =
{
   {StatusCode_BadUnexpectedError                                             , "BadUnexpectedError"},
   {StatusCode_BadInternalError                                               , "BadInternalError"},
   {StatusCode_BadOutOfMemory                                                 , "BadOutOfMemory"},
   {StatusCode_BadResourceUnavailable                                         , "BadResourceUnavailable"},
   {StatusCode_BadCommunicationError                                          , "BadCommunicationError"},
   {StatusCode_BadEncodingError                                               , "BadEncodingError"},
   {StatusCode_BadDecodingError                                               , "BadDecodingError"},
   {StatusCode_BadEncodingLimitsExceeded                                      , "BadEncodingLimitsExceeded"},
   {StatusCode_BadRequestTooLarge                                             , "BadRequestTooLarge"},
   {StatusCode_BadResponseTooLarge                                            , "BadResponseTooLarge"},
   {StatusCode_BadUnknownResponse                                             , "BadUnknownResponse"},
   {StatusCode_BadTimeout                                                     , "BadTimeout"},
   {StatusCode_BadServiceUnsupported                                          , "BadServiceUnsupported"},
   {StatusCode_BadShutdown                                                    , "BadShutdown"},
   {StatusCode_BadServerNotConnected                                          , "BadServerNotConnected"},
   {StatusCode_BadServerHalted                                                , "BadServerHalted"},
   {StatusCode_BadNothingToDo                                                 , "BadNothingToDo"},
   {StatusCode_BadTooManyOperations                                           , "BadTooManyOperations"},
   {StatusCode_BadTooManyMonitoredItems                                       , "BadTooManyMonitoredItems"},
   {StatusCode_BadDataTypeIdUnknown                                           , "BadDataTypeIdUnknown"},
   {StatusCode_BadCertificateInvalid                                          , "BadCertificateInvalid"},
   {StatusCode_BadSecurityChecksFailed                                        , "BadSecurityChecksFailed"},
   {StatusCode_BadCertificatePolicyCheckFailed                                , "BadCertificatePolicyCheckFailed"},
   {StatusCode_BadCertificateTimeInvalid                                      , "BadCertificateTimeInvalid"},
   {StatusCode_BadCertificateIssuerTimeInvalid                                , "BadCertificateIssuerTimeInvalid"},
   {StatusCode_BadCertificateHostNameInvalid                                  , "BadCertificateHostNameInvalid"},
   {StatusCode_BadCertificateUriInvalid                                       , "BadCertificateUriInvalid"},
   {StatusCode_BadCertificateUseNotAllowed                                    , "BadCertificateUseNotAllowed"},
   {StatusCode_BadCertificateIssuerUseNotAllowed                              , "BadCertificateIssuerUseNotAllowed"},
   {StatusCode_BadCertificateUntrusted                                        , "BadCertificateUntrusted"},
   {StatusCode_BadCertificateRevocationUnknown                                , "BadCertificateRevocationUnknown"},
   {StatusCode_BadCertificateIssuerRevocationUnknown                          , "BadCertificateIssuerRevocationUnknown"},
   {StatusCode_BadCertificateRevoked                                          , "BadCertificateRevoked"},
   {StatusCode_BadCertificateIssuerRevoked                                    , "BadCertificateIssuerRevoked"},
   {StatusCode_BadCertificateChainIncomplete                                  , "BadCertificateChainIncomplete"},
   {StatusCode_BadUserAccessDenied                                            , "BadUserAccessDenied"},
   {StatusCode_BadIdentityTokenInvalid                                        , "BadIdentityTokenInvalid"},
   {StatusCode_BadIdentityTokenRejected                                       , "BadIdentityTokenRejected"},
   {StatusCode_BadSecureChannelIdInvalid                                      , "BadSecureChannelIdInvalid"},
   {StatusCode_BadInvalidTimestamp                                            , "BadInvalidTimestamp"},
   {StatusCode_BadNonceInvalid                                                , "BadNonceInvalid"},
   {StatusCode_BadSessionIdInvalid                                            , "BadSessionIdInvalid"},
   {StatusCode_BadSessionClosed                                               , "BadSessionClosed"},
   {StatusCode_BadSessionNotActivated                                         , "BadSessionNotActivated"},
   {StatusCode_BadSubscriptionIdInvalid                                       , "BadSubscriptionIdInvalid"},
   {StatusCode_BadRequestHeaderInvalid                                        , "BadRequestHeaderInvalid"},
   {StatusCode_BadTimestampsToReturnInvalid                                   , "BadTimestampsToReturnInvalid"},
   {StatusCode_BadRequestCancelledByClient                                    , "BadRequestCancelledByClient"},
   {StatusCode_BadTooManyArguments                                            , "BadTooManyArguments"},
   {StatusCode_BadLicenseExpired                                              , "BadLicenseExpired"},
   {StatusCode_BadLicenseLimitsExceeded                                       , "BadLicenseLimitsExceeded"},
   {StatusCode_BadLicenseNotAvailable                                         , "BadLicenseNotAvailable"},
   {StatusCode_GoodSubscriptionTransferred                                    , "GoodSubscriptionTransferred"},
   {StatusCode_GoodCompletesAsynchronously                                    , "GoodCompletesAsynchronously"},
   {StatusCode_GoodOverload                                                   , "GoodOverload"},
   {StatusCode_GoodClamped                                                    , "GoodClamped"},
   {StatusCode_BadNoCommunication                                             , "BadNoCommunication"},
   {StatusCode_BadWaitingForInitialData                                       , "BadWaitingForInitialData"},
   {StatusCode_BadNodeIdInvalid                                               , "BadNodeIdInvalid"},
   {StatusCode_BadNodeIdUnknown                                               , "BadNodeIdUnknown"},
   {StatusCode_BadAttributeIdInvalid                                          , "BadAttributeIdInvalid"},
   {StatusCode_BadIndexRangeInvalid                                           , "BadIndexRangeInvalid"},
   {StatusCode_BadIndexRangeNoData                                            , "BadIndexRangeNoData"},
   {StatusCode_BadDataEncodingInvalid                                         , "BadDataEncodingInvalid"},
   {StatusCode_BadDataEncodingUnsupported                                     , "BadDataEncodingUnsupported"},
   {StatusCode_BadNotReadable                                                 , "BadNotReadable"},
   {StatusCode_BadNotWritable                                                 , "BadNotWritable"},
   {StatusCode_BadOutOfRange                                                  , "BadOutOfRange"},
   {StatusCode_BadNotSupported                                                , "BadNotSupported"},
   {StatusCode_BadNotFound                                                    , "BadNotFound"},
   {StatusCode_BadObjectDeleted                                               , "BadObjectDeleted"},
   {StatusCode_BadNotImplemented                                              , "BadNotImplemented"},
   {StatusCode_BadMonitoringModeInvalid                                       , "BadMonitoringModeInvalid"},
   {StatusCode_BadMonitoredItemIdInvalid                                      , "BadMonitoredItemIdInvalid"},
   {StatusCode_BadMonitoredItemFilterInvalid                                  , "BadMonitoredItemFilterInvalid"},
   {StatusCode_BadMonitoredItemFilterUnsupported                              , "BadMonitoredItemFilterUnsupported"},
   {StatusCode_BadFilterNotAllowed                                            , "BadFilterNotAllowed"},
   {StatusCode_BadStructureMissing                                            , "BadStructureMissing"},
   {StatusCode_BadEventFilterInvalid                                          , "BadEventFilterInvalid"},
   {StatusCode_BadContentFilterInvalid                                        , "BadContentFilterInvalid"},
   {StatusCode_BadFilterOperatorInvalid                                       , "BadFilterOperatorInvalid"},
   {StatusCode_BadFilterOperatorUnsupported                                   , "BadFilterOperatorUnsupported"},
   {StatusCode_BadFilterOperandCountMismatch                                  , "BadFilterOperandCountMismatch"},
   {StatusCode_BadFilterOperandInvalid                                        , "BadFilterOperandInvalid"},
   {StatusCode_BadFilterElementInvalid                                        , "BadFilterElementInvalid"},
   {StatusCode_BadFilterLiteralInvalid                                        , "BadFilterLiteralInvalid"},
   {StatusCode_BadContinuationPointInvalid                                    , "BadContinuationPointInvalid"},
   {StatusCode_BadNoContinuationPoints                                        , "BadNoContinuationPoints"},
   {StatusCode_BadReferenceTypeIdInvalid                                      , "BadReferenceTypeIdInvalid"},
   {StatusCode_BadBrowseDirectionInvalid                                      , "BadBrowseDirectionInvalid"},
   {StatusCode_BadNodeNotInView                                               , "BadNodeNotInView"},
   {StatusCode_BadNumericOverflow                                             , "BadNumericOverflow"},
   {StatusCode_BadServerUriInvalid                                            , "BadServerUriInvalid"},
   {StatusCode_BadServerNameMissing                                           , "BadServerNameMissing"},
   {StatusCode_BadDiscoveryUrlMissing                                         , "BadDiscoveryUrlMissing"},
   {StatusCode_BadSempahoreFileMissing                                        , "BadSempahoreFileMissing"},
   {StatusCode_BadRequestTypeInvalid                                          , "BadRequestTypeInvalid"},
   {StatusCode_BadSecurityModeRejected                                        , "BadSecurityModeRejected"},
   {StatusCode_BadSecurityPolicyRejected                                      , "BadSecurityPolicyRejected"},
   {StatusCode_BadTooManySessions                                             , "BadTooManySessions"},
   {StatusCode_BadUserSignatureInvalid                                        , "BadUserSignatureInvalid"},
   {StatusCode_BadApplicationSignatureInvalid                                 , "BadApplicationSignatureInvalid"},
   {StatusCode_BadNoValidCertificates                                         , "BadNoValidCertificates"},
   {StatusCode_BadIdentityChangeNotSupported                                  , "BadIdentityChangeNotSupported"},
   {StatusCode_BadRequestCancelledByRequest                                   , "BadRequestCancelledByRequest"},
   {StatusCode_BadParentNodeIdInvalid                                         , "BadParentNodeIdInvalid"},
   {StatusCode_BadReferenceNotAllowed                                         , "BadReferenceNotAllowed"},
   {StatusCode_BadNodeIdRejected                                              , "BadNodeIdRejected"},
   {StatusCode_BadNodeIdExists                                                , "BadNodeIdExists"},
   {StatusCode_BadNodeClassInvalid                                            , "BadNodeClassInvalid"},
   {StatusCode_BadBrowseNameInvalid                                           , "BadBrowseNameInvalid"},
   {StatusCode_BadBrowseNameDuplicated                                        , "BadBrowseNameDuplicated"},
   {StatusCode_BadNodeAttributesInvalid                                       , "BadNodeAttributesInvalid"},
   {StatusCode_BadTypeDefinitionInvalid                                       , "BadTypeDefinitionInvalid"},
   {StatusCode_BadSourceNodeIdInvalid                                         , "BadSourceNodeIdInvalid"},
   {StatusCode_BadTargetNodeIdInvalid                                         , "BadTargetNodeIdInvalid"},
   {StatusCode_BadDuplicateReferenceNotAllowed                                , "BadDuplicateReferenceNotAllowed"},
   {StatusCode_BadInvalidSelfReference                                        , "BadInvalidSelfReference"},
   {StatusCode_BadReferenceLocalOnly                                          , "BadReferenceLocalOnly"},
   {StatusCode_BadNoDeleteRights                                              , "BadNoDeleteRights"},
   {StatusCode_UncertainReferenceNotDeleted                                   , "UncertainReferenceNotDeleted"},
   {StatusCode_BadServerIndexInvalid                                          , "BadServerIndexInvalid"},
   {StatusCode_BadViewIdUnknown                                               , "BadViewIdUnknown"},
   {StatusCode_BadViewTimestampInvalid                                        , "BadViewTimestampInvalid"},
   {StatusCode_BadViewParameterMismatch                                       , "BadViewParameterMismatch"},
   {StatusCode_BadViewVersionInvalid                                          , "BadViewVersionInvalid"},
   {StatusCode_UncertainNotAllNodesAvailable                                  , "UncertainNotAllNodesAvailable"},
   {StatusCode_GoodResultsMayBeIncomplete                                     , "GoodResultsMayBeIncomplete"},
   {StatusCode_BadNotTypeDefinition                                           , "BadNotTypeDefinition"},
   {StatusCode_UncertainReferenceOutOfServer                                  , "UncertainReferenceOutOfServer"},
   {StatusCode_BadTooManyMatches                                              , "BadTooManyMatches"},
   {StatusCode_BadQueryTooComplex                                             , "BadQueryTooComplex"},
   {StatusCode_BadNoMatch                                                     , "BadNoMatch"},
   {StatusCode_BadMaxAgeInvalid                                               , "BadMaxAgeInvalid"},
   {StatusCode_BadSecurityModeInsufficient                                    , "BadSecurityModeInsufficient"},
   {StatusCode_BadHistoryOperationInvalid                                     , "BadHistoryOperationInvalid"},
   {StatusCode_BadHistoryOperationUnsupported                                 , "BadHistoryOperationUnsupported"},
   {StatusCode_BadInvalidTimestampArgument                                    , "BadInvalidTimestampArgument"},
   {StatusCode_BadWriteNotSupported                                           , "BadWriteNotSupported"},
   {StatusCode_BadTypeMismatch                                                , "BadTypeMismatch"},
   {StatusCode_BadMethodInvalid                                               , "BadMethodInvalid"},
   {StatusCode_BadArgumentsMissing                                            , "BadArgumentsMissing"},
   {StatusCode_BadNotExecutable                                               , "BadNotExecutable"},
   {StatusCode_BadTooManySubscriptions                                        , "BadTooManySubscriptions"},
   {StatusCode_BadTooManyPublishRequests                                      , "BadTooManyPublishRequests"},
   {StatusCode_BadNoSubscription                                              , "BadNoSubscription"},
   {StatusCode_BadSequenceNumberUnknown                                       , "BadSequenceNumberUnknown"},
   {StatusCode_BadMessageNotAvailable                                         , "BadMessageNotAvailable"},
   {StatusCode_BadInsufficientClientProfile                                   , "BadInsufficientClientProfile"},
   {StatusCode_BadStateNotActive                                              , "BadStateNotActive"},
   {StatusCode_BadAlreadyExists                                               , "BadAlreadyExists"},
   {StatusCode_BadTcpServerTooBusy                                            , "BadTcpServerTooBusy"},
   {StatusCode_BadTcpMessageTypeInvalid                                       , "BadTcpMessageTypeInvalid"},
   {StatusCode_BadTcpSecureChannelUnknown                                     , "BadTcpSecureChannelUnknown"},
   {StatusCode_BadTcpMessageTooLarge                                          , "BadTcpMessageTooLarge"},
   {StatusCode_BadTcpNotEnoughResources                                       , "BadTcpNotEnoughResources"},
   {StatusCode_BadTcpInternalError                                            , "BadTcpInternalError"},
   {StatusCode_BadTcpEndpointUrlInvalid                                       , "BadTcpEndpointUrlInvalid"},
   {StatusCode_BadRequestInterrupted                                          , "BadRequestInterrupted"},
   {StatusCode_BadRequestTimeout                                              , "BadRequestTimeout"},
   {StatusCode_BadSecureChannelClosed                                         , "BadSecureChannelClosed"},
   {StatusCode_BadSecureChannelTokenUnknown                                   , "BadSecureChannelTokenUnknown"},
   {StatusCode_BadSequenceNumberInvalid                                       , "BadSequenceNumberInvalid"},
   {StatusCode_BadProtocolVersionUnsupported                                  , "BadProtocolVersionUnsupported"},
   {StatusCode_BadConfigurationError                                          , "BadConfigurationError"},
   {StatusCode_BadNotConnected                                                , "BadNotConnected"},
   {StatusCode_BadDeviceFailure                                               , "BadDeviceFailure"},
   {StatusCode_BadSensorFailure                                               , "BadSensorFailure"},
   {StatusCode_BadOutOfService                                                , "BadOutOfService"},
   {StatusCode_BadDeadbandFilterInvalid                                       , "BadDeadbandFilterInvalid"},
   {StatusCode_UncertainNoCommunicationLastUsableValue                        , "UncertainNoCommunicationLastUsableValue"},
   {StatusCode_UncertainLastUsableValue                                       , "UncertainLastUsableValue"},
   {StatusCode_UncertainSubstituteValue                                       , "UncertainSubstituteValue"},
   {StatusCode_UncertainInitialValue                                          , "UncertainInitialValue"},
   {StatusCode_UncertainSensorNotAccurate                                     , "UncertainSensorNotAccurate"},
   {StatusCode_UncertainEngineeringUnitsExceeded                              , "UncertainEngineeringUnitsExceeded"},
   {StatusCode_UncertainSubNormal                                             , "UncertainSubNormal"},
   {StatusCode_GoodLocalOverride                                              , "GoodLocalOverride"},
   {StatusCode_BadRefreshInProgress                                           , "BadRefreshInProgress"},
   {StatusCode_BadConditionAlreadyDisabled                                    , "BadConditionAlreadyDisabled"},
   {StatusCode_BadConditionAlreadyEnabled                                     , "BadConditionAlreadyEnabled"},
   {StatusCode_BadConditionDisabled                                           , "BadConditionDisabled"},
   {StatusCode_BadEventIdUnknown                                              , "BadEventIdUnknown"},
   {StatusCode_BadEventNotAcknowledgeable                                     , "BadEventNotAcknowledgeable"},
   {StatusCode_BadDialogNotActive                                             , "BadDialogNotActive"},
   {StatusCode_BadDialogResponseInvalid                                       , "BadDialogResponseInvalid"},
   {StatusCode_BadConditionBranchAlreadyAcked                                 , "BadConditionBranchAlreadyAcked"},
   {StatusCode_BadConditionBranchAlreadyConfirmed                             , "BadConditionBranchAlreadyConfirmed"},
   {StatusCode_BadConditionAlreadyShelved                                     , "BadConditionAlreadyShelved"},
   {StatusCode_BadConditionNotShelved                                         , "BadConditionNotShelved"},
   {StatusCode_BadShelvingTimeOutOfRange                                      , "BadShelvingTimeOutOfRange"},
   {StatusCode_BadNoData                                                      , "BadNoData"},
   {StatusCode_BadBoundNotFound                                               , "BadBoundNotFound"},
   {StatusCode_BadBoundNotSupported                                           , "BadBoundNotSupported"},
   {StatusCode_BadDataLost                                                    , "BadDataLost"},
   {StatusCode_BadDataUnavailable                                             , "BadDataUnavailable"},
   {StatusCode_BadEntryExists                                                 , "BadEntryExists"},
   {StatusCode_BadNoEntryExists                                               , "BadNoEntryExists"},
   {StatusCode_BadTimestampNotSupported                                       , "BadTimestampNotSupported"},
   {StatusCode_GoodEntryInserted                                              , "GoodEntryInserted"},
   {StatusCode_GoodEntryReplaced                                              , "GoodEntryReplaced"},
   {StatusCode_UncertainDataSubNormal                                         , "UncertainDataSubNormal"},
   {StatusCode_GoodNoData                                                     , "GoodNoData"},
   {StatusCode_GoodMoreData                                                   , "GoodMoreData"},
   {StatusCode_BadAggregateListMismatch                                       , "BadAggregateListMismatch"},
   {StatusCode_BadAggregateNotSupported                                       , "BadAggregateNotSupported"},
   {StatusCode_BadAggregateInvalidInputs                                      , "BadAggregateInvalidInputs"},
   {StatusCode_BadAggregateConfigurationRejected                              , "BadAggregateConfigurationRejected"},
   {StatusCode_GoodDataIgnored                                                , "GoodDataIgnored"},
   {StatusCode_BadRequestNotAllowed                                           , "BadRequestNotAllowed"},
   {StatusCode_BadRequestNotComplete                                          , "BadRequestNotComplete"},
   {StatusCode_GoodEdited                                                     , "GoodEdited"},
   {StatusCode_GoodPostActionFailed                                           , "GoodPostActionFailed"},
   {StatusCode_UncertainDominantValueChanged                                  , "UncertainDominantValueChanged"},
   {StatusCode_GoodDependentValueChanged                                      , "GoodDependentValueChanged"},
   {StatusCode_BadDominantValueChanged                                        , "BadDominantValueChanged"},
   {StatusCode_UncertainDependentValueChanged                                 , "UncertainDependentValueChanged"},
   {StatusCode_BadDependentValueChanged                                       , "BadDependentValueChanged"},
   {StatusCode_GoodEdited_DependentValueChanged                               , "GoodEdited_DependentValueChanged"},
   {StatusCode_GoodEdited_DominantValueChanged                                , "GoodEdited_DominantValueChanged"},
   {StatusCode_GoodEdited_DominantValueChanged_DependentValueChanged          , "GoodEdited_DominantValueChanged_DependentValueChanged"},
   {StatusCode_BadEdited_OutOfRange                                           , "BadEdited_OutOfRange"},
   {StatusCode_BadInitialValue_OutOfRange                                     , "BadInitialValue_OutOfRange"},
   {StatusCode_BadOutOfRange_DominantValueChanged                             , "BadOutOfRange_DominantValueChanged"},
   {StatusCode_BadEdited_OutOfRange_DominantValueChanged                      , "BadEdited_OutOfRange_DominantValueChanged"},
   {StatusCode_BadOutOfRange_DominantValueChanged_DependentValueChanged       , "BadOutOfRange_DominantValueChanged_DependentValueChanged"},
   {StatusCode_BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged, "BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged"},
   {StatusCode_GoodCommunicationEvent                                         , "GoodCommunicationEvent"},
   {StatusCode_GoodShutdownEvent                                              , "GoodShutdownEvent"},
   {StatusCode_GoodCallAgain                                                  , "GoodCallAgain"},
   {StatusCode_GoodNonCriticalTimeout                                         , "GoodNonCriticalTimeout"},
   {StatusCode_BadInvalidArgument                                             , "BadInvalidArgument"},
   {StatusCode_BadConnectionRejected                                          , "BadConnectionRejected"},
   {StatusCode_BadDisconnect                                                  , "BadDisconnect"},
   {StatusCode_BadConnectionClosed                                            , "BadConnectionClosed"},
   {StatusCode_BadInvalidState                                                , "BadInvalidState"},
   {StatusCode_BadEndOfStream                                                 , "BadEndOfStream"},
   {StatusCode_BadNoDataAvailable                                             , "BadNoDataAvailable"},
   {StatusCode_BadWaitingForResponse                                          , "BadWaitingForResponse"},
   {StatusCode_BadOperationAbandoned                                          , "BadOperationAbandoned"},
   {StatusCode_BadExpectedStreamToBlock                                       , "BadExpectedStreamToBlock"},
   {StatusCode_BadWouldBlock                                                  , "BadWouldBlock"},
   {StatusCode_BadSyntaxError                                                 , "BadSyntaxError"},
   {StatusCode_BadMaxConnectionsReached                                       , "BadMaxConnectionsReached"}
};

//
// UA Specification Part 4 - Services 1.04.pdf
//
// 7.34 StatusCode; Table 175 - StatusCode Bit Assignments & Table 176 DataValue InfoBits
//
//     Field          Bit Range
//     Severity          30-31
//     Reserved          29-29
//     Reserved          28-29
//     SubCode           16-27
//     StructureChanged  15-15
//     SemanticsChanged  14-14
//     Reserved          12-13
//     InfoType          10-11
//     LimitBits           8-9
//     Overflow            7-7
//     Reserved            5-6
//     HistorianBits       0-4

// Bitmasks
static uint32_t STATUS_CODE_MASK          = 0xFFFF0000; // Top 16 bits 
static uint32_t SUBCODE_MASK              = 0x0FFF0000; // Bit Range: 16-27
static uint32_t STRUCTURE_CHANGED_MASK    = 0x00008000; // Bit Range: 15-15
static uint32_t SEMANTICS_CHANGED_MASK    = 0x00004000; // Bit Range: 14-14
static uint32_t INFOTYPE_MASK             = 0x00000C00; // Bit Range: 10-11
static uint32_t LIMIT_BITS_MASK           = 0x00000300; // Bit Range:   8-9
static uint32_t OVERFLOW_MASK             = 0x00000080; // Bit Range:   7-7
static uint32_t HISTORIAN_MULTIVALUE_MASK = 0x00000010; // Bit Range:   4-4
static uint32_t HISTORIAN_EXTRADATA_MASK  = 0x00000008; // Bit Range:   3-3
static uint32_t HISTORIAN_PARTIAL_MASK    = 0x00000004; // Bit Range:   2-2
static uint32_t HISTORIAN_BITS_MASK       = 0x00000003; // Bit Range:   0-1

// String for identifying Reserved fields
static std::string RESERVED = "Reserved";

// Severity: Bit Range: 30-31
static uint8_t Severity_Good      = 0x00; // 00 - Indicates that the operation was successful and the associated results may be used.
static uint8_t Severity_Uncertain = 0x01; // 01 - Indicates that the operation was partially successful and that associated results might not be suitable for some purposes.
static uint8_t Severity_Bad       = 0x02; // 10 - Indicates that the operation failed and any associated results cannot be used.

static std::map<uint8_t, std::string> SEVERITY_MAP =
{
   {Severity_Good      , "Severity_Good"},
   {Severity_Uncertain , "Severity_Uncertain"},
   {Severity_Bad       , "Severity_Bad"}
};

// InfoType: Bit Range: 10-11
static uint8_t InfoType_NotUsed   = 0x00; // 00 - The info bits are not used and shall be set to zero
static uint8_t InfoType_DataValue = 0x01; // 01 - The StatusCode and its info bits are associated with a data value returned from the Server.

static std::map<uint8_t, std::string> INFO_TYPE_MAP =
{
   {InfoType_NotUsed   , "InfoType_NotUsed"},
   {InfoType_DataValue , "InfoType_DataValue"}
};

// LimitBits: Bit Range: 8-9
static uint8_t LimitBits_None     = 0x00; // 00 - The value is free to change. 
static uint8_t LimitBits_Low      = 0x01; // 01 - The value is at the lower limit for the data source. 
static uint8_t LimitBits_High     = 0x02; // 10 - The value is at the higher limit for the data source.
static uint8_t LimitBits_Constant = 0x03; // 11 - The value is constant and cannot change.

static std::map<uint8_t, std::string> LIMIT_BITS_MAP =
{
   {LimitBits_None     , "LimitBits_None"},
   {LimitBits_Low      , "LimitBits_Low"},
   {LimitBits_High     , "LimitBits_High"},
   {LimitBits_Constant , "LimitBits_Constant"}
};

// HistorianBits: Bit Range: 0-4
static uint8_t HistorianBits_Raw          = 0x00; // XXX00 - A raw data value.
static uint8_t HistorianBits_Calculated   = 0x01; // XXX01 - A data value which was calculated. 
static uint8_t HistorianBits_Interpolated = 0x02; // XXX10 - A data value which was interpolated.

static std::map<uint8_t, std::string> HISTORIAN_BITS_MAP =
{
   {HistorianBits_Raw          , "HistorianBits_Raw"},
   {HistorianBits_Calculated   , "HistorianBits_Calculated"},
   {HistorianBits_Interpolated , "HistorianBits_Interpolated"}
};

// Internal bit mask used to associate detailed status code information
// with the service/structure that generated the status code.
static uint32_t StatusCode_ResHdrServiceResult  = 0x00; 
static uint32_t StatusCode_DiagInfoInnerStatus  = 0x01; 

static std::map<uint32_t, std::string> STATUS_CODE_SRC_MAP =
{
   {StatusCode_ResHdrServiceResult , "ResponseHeaderServiceResult"},
   {StatusCode_DiagInfoInnerStatus , "DiagInfoInnerStatusCode"}
};

// Structure to hold details of a status code to include the masked off
// severity, subcode, etc.
typedef struct StatusCodeDetail {
   uint8_t     severity;
   std::string severityStr;
   uint8_t     subCode;
   std::string subCodeStr;
   bool        structureChanged;
   bool        semanticsChanged;
   uint8_t     infoType;
   std::string infoTypeStr;
   uint8_t     limitBits;
   std::string limitBitsStr;
   bool        overflow;
   uint8_t     historianBits;
   std::string historianBitsStr;
   bool        historianPartial;
   bool        historianExtraData;
   bool        historianMultiValue;

   StatusCodeDetail(uint32_t statusCode) {
      severity     = statusCode >> 30;
      severityStr = RESERVED;
      if (SEVERITY_MAP.find(severity) != SEVERITY_MAP.end()) {
         severityStr = SEVERITY_MAP.find(severity)->second;
      }
        
      subCode = (statusCode & SUBCODE_MASK) >> 16;

      // See if we can find the status code in the STATUS_CODE_MAP.  NOTE: Pre-defined 
      // status codes have the first two bits included in the definition.  Therefore, 
      // we only need to mask off the lower 16 bits to do the lookup STATUS_CODE_MAP.
      subCodeStr = "";
      if (STATUS_CODE_MAP.find(statusCode & STATUS_CODE_MASK) != STATUS_CODE_MAP.end()) {
         subCodeStr = STATUS_CODE_MAP.find(statusCode & STATUS_CODE_MASK)->second;
      }

      structureChanged = (statusCode & STRUCTURE_CHANGED_MASK) >> 15;
      semanticsChanged = (statusCode & SEMANTICS_CHANGED_MASK) >> 14;

      infoType = (statusCode & INFOTYPE_MASK) >> 10;
      infoTypeStr = RESERVED;
      if (INFO_TYPE_MAP.find(infoType) != INFO_TYPE_MAP.end()) {
         infoTypeStr = INFO_TYPE_MAP.find(infoType)->second;
      }

      limitBits    = (statusCode & LIMIT_BITS_MASK) >> 8;
      limitBitsStr = LIMIT_BITS_MAP.find(limitBits)->second;

      overflow = (statusCode & OVERFLOW_MASK) >> 7;

      historianBits = statusCode & HISTORIAN_BITS_MASK;
      historianBitsStr = RESERVED;
      if (HISTORIAN_BITS_MAP.find(historianBits) != HISTORIAN_BITS_MAP.end()) {
         historianBitsStr = HISTORIAN_BITS_MAP.find(historianBits)->second;
      }

      historianPartial    = (statusCode & HISTORIAN_PARTIAL_MASK)    >> 2;
      historianExtraData  = (statusCode & HISTORIAN_EXTRADATA_MASK)  >> 3;
      historianMultiValue = (statusCode & HISTORIAN_MULTIVALUE_MASK) >> 4;
   }

} StatusCodeDetail;

#endif
