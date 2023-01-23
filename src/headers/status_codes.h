// status_codes.h
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
static uint32_t StatusCode_Good_Key                                                            = 0x00000000; // All is good.
static uint32_t StatusCode_BadUnexpectedError_Key                                              = 0x80010000; // An unexpected error occurred.
static uint32_t StatusCode_BadInternalError_Key                                                = 0x80020000; // An internal error occurred as a result of a programming or configuration error.
static uint32_t StatusCode_BadOutOfMemory_Key                                                  = 0x80030000; // Not enough memory to complete the operation.
static uint32_t StatusCode_BadResourceUnavailable_Key                                          = 0x80040000; // An operating system resource is not available.
static uint32_t StatusCode_BadCommunicationError_Key                                           = 0x80050000; // A low level communication error occurred.
static uint32_t StatusCode_BadEncodingError_Key                                                = 0x80060000; // Encoding halted because of invalid data in the objects being serialized.
static uint32_t StatusCode_BadDecodingError_Key                                                = 0x80070000; // Decoding halted because of invalid data in the stream.
static uint32_t StatusCode_BadEncodingLimitsExceeded_Key                                       = 0x80080000; // The message encoding/decoding limits imposed by the stack have been exceeded.
static uint32_t StatusCode_BadRequestTooLarge_Key                                              = 0x80B80000; // The request message size exceeds limits set by the server.
static uint32_t StatusCode_BadResponseTooLarge_Key                                             = 0x80B90000; // The response message size exceeds limits set by the client.
static uint32_t StatusCode_BadUnknownResponse_Key                                              = 0x80090000; // An unrecognized response was received from the server.
static uint32_t StatusCode_BadTimeout_Key                                                      = 0x800A0000; // The operation timed out.
static uint32_t StatusCode_BadServiceUnsupported_Key                                           = 0x800B0000; // The server does not support the requested service.
static uint32_t StatusCode_BadShutdown_Key                                                     = 0x800C0000; // The operation was cancelled because the application is shutting down.
static uint32_t StatusCode_BadServerNotConnected_Key                                           = 0x800D0000; // The operation could not complete because the client is not connected to the server.
static uint32_t StatusCode_BadServerHalted_Key                                                 = 0x800E0000; // The server has stopped and cannot process any requests.
static uint32_t StatusCode_BadNothingToDo_Key                                                  = 0x800F0000; // There was nothing to do because the client passed a list of operations with no elements.
static uint32_t StatusCode_BadTooManyOperations_Key                                            = 0x80100000; // The request could not be processed because it specified too many operations.
static uint32_t StatusCode_BadTooManyMonitoredItems_Key                                        = 0x80DB0000; // The request could not be processed because there are too many monitored items in the subscription.
static uint32_t StatusCode_BadDataTypeIdUnknown_Key                                            = 0x80110000; // The extension object cannot be (de)serialized because the data type id is not recognized.
static uint32_t StatusCode_BadCertificateInvalid_Key                                           = 0x80120000; // The certificate provided as a parameter is not valid.
static uint32_t StatusCode_BadSecurityChecksFailed_Key                                         = 0x80130000; // An error occurred verifying security.
static uint32_t StatusCode_BadCertificatePolicyCheckFailed_Key                                 = 0x81140000; // The certificate does not meet the requirements of the security policy.
static uint32_t StatusCode_BadCertificateTimeInvalid_Key                                       = 0x80140000; // The certificate has expired or is not yet valid.
static uint32_t StatusCode_BadCertificateIssuerTimeInvalid_Key                                 = 0x80150000; // An issuer certificate has expired or is not yet valid.
static uint32_t StatusCode_BadCertificateHostNameInvalid_Key                                   = 0x80160000; // The HostName used to connect to a server does not match a HostName in the certificate.
static uint32_t StatusCode_BadCertificateUriInvalid_Key                                        = 0x80170000; // The URI specified in the ApplicationDescription does not match the URI in the certificate.
static uint32_t StatusCode_BadCertificateUseNotAllowed_Key                                     = 0x80180000; // The certificate may not be used for the requested operation.
static uint32_t StatusCode_BadCertificateIssuerUseNotAllowed_Key                               = 0x80190000; // The issuer certificate may not be used for the requested operation.
static uint32_t StatusCode_BadCertificateUntrusted_Key                                         = 0x801A0000; // The certificate is not trusted.
static uint32_t StatusCode_BadCertificateRevocationUnknown_Key                                 = 0x801B0000; // It was not possible to determine if the certificate has been revoked.
static uint32_t StatusCode_BadCertificateIssuerRevocationUnknown_Key                           = 0x801C0000; // It was not possible to determine if the issuer certificate has been revoked.
static uint32_t StatusCode_BadCertificateRevoked_Key                                           = 0x801D0000; // The certificate has been revoked.
static uint32_t StatusCode_BadCertificateIssuerRevoked_Key                                     = 0x801E0000; // The issuer certificate has been revoked.
static uint32_t StatusCode_BadCertificateChainIncomplete_Key                                   = 0x810D0000; // The certificate chain is incomplete.
static uint32_t StatusCode_BadUserAccessDenied_Key                                             = 0x801F0000; // User does not have permission to perform the requested operation.
static uint32_t StatusCode_BadIdentityTokenInvalid_Key                                         = 0x80200000; // The user identity token is not valid.
static uint32_t StatusCode_BadIdentityTokenRejected_Key                                        = 0x80210000; // The user identity token is valid but the server has rejected it.
static uint32_t StatusCode_BadSecureChannelIdInvalid_Key                                       = 0x80220000; // The specified secure channel is no longer valid.
static uint32_t StatusCode_BadInvalidTimestamp_Key                                             = 0x80230000; // The timestamp is outside the range allowed by the server.
static uint32_t StatusCode_BadNonceInvalid_Key                                                 = 0x80240000; // The nonce does appear to be not a random value or it is not the correct length.
static uint32_t StatusCode_BadSessionIdInvalid_Key                                             = 0x80250000; // The session id is not valid.
static uint32_t StatusCode_BadSessionClosed_Key                                                = 0x80260000; // The session was closed by the client.
static uint32_t StatusCode_BadSessionNotActivated_Key                                          = 0x80270000; // The session cannot be used because ActivateSession has not been called.
static uint32_t StatusCode_BadSubscriptionIdInvalid_Key                                        = 0x80280000; // The subscription id is not valid.
static uint32_t StatusCode_BadRequestHeaderInvalid_Key                                         = 0x802A0000; // The header for the request is missing or invalid.
static uint32_t StatusCode_BadTimestampsToReturnInvalid_Key                                    = 0x802B0000; // The timestamps to return parameter is invalid.
static uint32_t StatusCode_BadRequestCancelledByClient_Key                                     = 0x802C0000; // The request was cancelled by the client.
static uint32_t StatusCode_BadTooManyArguments_Key                                             = 0x80E50000; // Too many arguments were provided.
static uint32_t StatusCode_BadLicenseExpired_Key                                               = 0x810E0000; // "The server requires a license to operate in general or to perform a service or operation
static uint32_t StatusCode_BadLicenseLimitsExceeded_Key                                        = 0x810F0000; // "The server has limits on number of allowed operations / objects
static uint32_t StatusCode_BadLicenseNotAvailable_Key                                          = 0x81100000; // The server does not have a license which is required to operate in general or to perform a service or operation.
static uint32_t StatusCode_GoodSubscriptionTransferred_Key                                     = 0x002D0000; // The subscription was transferred to another session.
static uint32_t StatusCode_GoodCompletesAsynchronously_Key                                     = 0x002E0000; // The processing will complete asynchronously.
static uint32_t StatusCode_GoodOverload_Key                                                    = 0x002F0000; // Sampling has slowed down due to resource limitations.
static uint32_t StatusCode_GoodClamped_Key                                                     = 0x00300000; // The value written was accepted but was clamped.
static uint32_t StatusCode_BadNoCommunication_Key                                              = 0x80310000; // "Communication with the data source is defined
static uint32_t StatusCode_BadWaitingForInitialData_Key                                        = 0x80320000; // Waiting for the server to obtain values from the underlying data source.
static uint32_t StatusCode_BadNodeIdInvalid_Key                                                = 0x80330000; // The syntax of the node id is not valid.
static uint32_t StatusCode_BadNodeIdUnknown_Key                                                = 0x80340000; // The node id refers to a node that does not exist in the server address space.
static uint32_t StatusCode_BadAttributeIdInvalid_Key                                           = 0x80350000; // The attribute is not supported for the specified Node.
static uint32_t StatusCode_BadIndexRangeInvalid_Key                                            = 0x80360000; // The syntax of the index range parameter is invalid.
static uint32_t StatusCode_BadIndexRangeNoData_Key                                             = 0x80370000; // No data exists within the range of indexes specified.
static uint32_t StatusCode_BadDataEncodingInvalid_Key                                          = 0x80380000; // The data encoding is invalid.
static uint32_t StatusCode_BadDataEncodingUnsupported_Key                                      = 0x80390000; // The server does not support the requested data encoding for the node.
static uint32_t StatusCode_BadNotReadable_Key                                                  = 0x803A0000; // The access level does not allow reading or subscribing to the Node.
static uint32_t StatusCode_BadNotWritable_Key                                                  = 0x803B0000; // The access level does not allow writing to the Node.
static uint32_t StatusCode_BadOutOfRange_Key                                                   = 0x803C0000; // The value was out of range.
static uint32_t StatusCode_BadNotSupported_Key                                                 = 0x803D0000; // The requested operation is not supported.
static uint32_t StatusCode_BadNotFound_Key                                                     = 0x803E0000; // A requested item was not found or a search operation ended without success.
static uint32_t StatusCode_BadObjectDeleted_Key                                                = 0x803F0000; // The object cannot be used because it has been deleted.
static uint32_t StatusCode_BadNotImplemented_Key                                               = 0x80400000; // Requested operation is not implemented.
static uint32_t StatusCode_BadMonitoringModeInvalid_Key                                        = 0x80410000; // The monitoring mode is invalid.
static uint32_t StatusCode_BadMonitoredItemIdInvalid_Key                                       = 0x80420000; // The monitoring item id does not refer to a valid monitored item.
static uint32_t StatusCode_BadMonitoredItemFilterInvalid_Key                                   = 0x80430000; // The monitored item filter parameter is not valid.
static uint32_t StatusCode_BadMonitoredItemFilterUnsupported_Key                               = 0x80440000; // The server does not support the requested monitored item filter.
static uint32_t StatusCode_BadFilterNotAllowed_Key                                             = 0x80450000; // A monitoring filter cannot be used in combination with the attribute specified.
static uint32_t StatusCode_BadStructureMissing_Key                                             = 0x80460000; // A mandatory structured parameter was missing or null.
static uint32_t StatusCode_BadEventFilterInvalid_Key                                           = 0x80470000; // The event filter is not valid.
static uint32_t StatusCode_BadContentFilterInvalid_Key                                         = 0x80480000; // The content filter is not valid.
static uint32_t StatusCode_BadFilterOperatorInvalid_Key                                        = 0x80C10000; // An unrecognized operator was provided in a filter.
static uint32_t StatusCode_BadFilterOperatorUnsupported_Key                                    = 0x80C20000; // "A valid operator was provided
static uint32_t StatusCode_BadFilterOperandCountMismatch_Key                                   = 0x80C30000; // The number of operands provided for the filter operator was less then expected for the operand provided.
static uint32_t StatusCode_BadFilterOperandInvalid_Key                                         = 0x80490000; // The operand used in a content filter is not valid.
static uint32_t StatusCode_BadFilterElementInvalid_Key                                         = 0x80C40000; // The referenced element is not a valid element in the content filter.
static uint32_t StatusCode_BadFilterLiteralInvalid_Key                                         = 0x80C50000; // The referenced literal is not a valid value.
static uint32_t StatusCode_BadContinuationPointInvalid_Key                                     = 0x804A0000; // The continuation point provide is longer valid.
static uint32_t StatusCode_BadNoContinuationPoints_Key                                         = 0x804B0000; // The operation could not be processed because all continuation points have been allocated.
static uint32_t StatusCode_BadReferenceTypeIdInvalid_Key                                       = 0x804C0000; // The reference type id does not refer to a valid reference type node.
static uint32_t StatusCode_BadBrowseDirectionInvalid_Key                                       = 0x804D0000; // The browse direction is not valid.
static uint32_t StatusCode_BadNodeNotInView_Key                                                = 0x804E0000; // The node is not part of the view.
static uint32_t StatusCode_BadNumericOverflow_Key                                              = 0x81120000; // The number was not accepted because of a numeric overflow.
static uint32_t StatusCode_BadServerUriInvalid_Key                                             = 0x804F0000; // The ServerUri is not a valid URI.
static uint32_t StatusCode_BadServerNameMissing_Key                                            = 0x80500000; // No ServerName was specified.
static uint32_t StatusCode_BadDiscoveryUrlMissing_Key                                          = 0x80510000; // No DiscoveryUrl was specified.
static uint32_t StatusCode_BadSempahoreFileMissing_Key                                         = 0x80520000; // The semaphore file specified by the client is not valid.
static uint32_t StatusCode_BadRequestTypeInvalid_Key                                           = 0x80530000; // The security token request type is not valid.
static uint32_t StatusCode_BadSecurityModeRejected_Key                                         = 0x80540000; // The security mode does not meet the requirements set by the server.
static uint32_t StatusCode_BadSecurityPolicyRejected_Key                                       = 0x80550000; // The security policy does not meet the requirements set by the server.
static uint32_t StatusCode_BadTooManySessions_Key                                              = 0x80560000; // The server has reached its maximum number of sessions.
static uint32_t StatusCode_BadUserSignatureInvalid_Key                                         = 0x80570000; // The user token signature is missing or invalid.
static uint32_t StatusCode_BadApplicationSignatureInvalid_Key                                  = 0x80580000; // The signature generated with the client certificate is missing or invalid.
static uint32_t StatusCode_BadNoValidCertificates_Key                                          = 0x80590000; // The client did not provide at least one software certificate that is valid and meets the profile requirements for the server.
static uint32_t StatusCode_BadIdentityChangeNotSupported_Key                                   = 0x80C60000; // The server does not support changing the user identity assigned to the session.
static uint32_t StatusCode_BadRequestCancelledByRequest_Key                                    = 0x805A0000; // The request was cancelled by the client with the Cancel service.
static uint32_t StatusCode_BadParentNodeIdInvalid_Key                                          = 0x805B0000; // The parent node id does not to refer to a valid node.
static uint32_t StatusCode_BadReferenceNotAllowed_Key                                          = 0x805C0000; // The reference could not be created because it violates constraints imposed by the data model.
static uint32_t StatusCode_BadNodeIdRejected_Key                                               = 0x805D0000; // The requested node id was reject because it was either invalid or server does not allow node ids to be specified by the client.
static uint32_t StatusCode_BadNodeIdExists_Key                                                 = 0x805E0000; // The requested node id is already used by another node.
static uint32_t StatusCode_BadNodeClassInvalid_Key                                             = 0x805F0000; // The node class is not valid.
static uint32_t StatusCode_BadBrowseNameInvalid_Key                                            = 0x80600000; // The browse name is invalid.
static uint32_t StatusCode_BadBrowseNameDuplicated_Key                                         = 0x80610000; // The browse name is not unique among nodes that share the same relationship with the parent.
static uint32_t StatusCode_BadNodeAttributesInvalid_Key                                        = 0x80620000; // The node attributes are not valid for the node class.
static uint32_t StatusCode_BadTypeDefinitionInvalid_Key                                        = 0x80630000; // The type definition node id does not reference an appropriate type node.
static uint32_t StatusCode_BadSourceNodeIdInvalid_Key                                          = 0x80640000; // The source node id does not reference a valid node.
static uint32_t StatusCode_BadTargetNodeIdInvalid_Key                                          = 0x80650000; // The target node id does not reference a valid node.
static uint32_t StatusCode_BadDuplicateReferenceNotAllowed_Key                                 = 0x80660000; // The reference type between the nodes is already defined.
static uint32_t StatusCode_BadInvalidSelfReference_Key                                         = 0x80670000; // The server does not allow this type of self reference on this node.
static uint32_t StatusCode_BadReferenceLocalOnly_Key                                           = 0x80680000; // The reference type is not valid for a reference to a remote server.
static uint32_t StatusCode_BadNoDeleteRights_Key                                               = 0x80690000; // The server will not allow the node to be deleted.
static uint32_t StatusCode_UncertainReferenceNotDeleted_Key                                    = 0x40BC0000; // The server was not able to delete all target references.
static uint32_t StatusCode_BadServerIndexInvalid_Key                                           = 0x806A0000; // The server index is not valid.
static uint32_t StatusCode_BadViewIdUnknown_Key                                                = 0x806B0000; // The view id does not refer to a valid view node.
static uint32_t StatusCode_BadViewTimestampInvalid_Key                                         = 0x80C90000; // The view timestamp is not available or not supported.
static uint32_t StatusCode_BadViewParameterMismatch_Key                                        = 0x80CA0000; // The view parameters are not consistent with each other.
static uint32_t StatusCode_BadViewVersionInvalid_Key                                           = 0x80CB0000; // The view version is not available or not supported.
static uint32_t StatusCode_UncertainNotAllNodesAvailable_Key                                   = 0x40C00000; // The list of references may not be complete because the underlying system is not available.
static uint32_t StatusCode_GoodResultsMayBeIncomplete_Key                                      = 0x00BA0000; // The server should have followed a reference to a node in a remote server but did not. The result set may be incomplete.
static uint32_t StatusCode_BadNotTypeDefinition_Key                                            = 0x80C80000; // The provided Nodeid was not a type definition nodeid.
static uint32_t StatusCode_UncertainReferenceOutOfServer_Key                                   = 0x406C0000; // One of the references to follow in the relative path references to a node in the address space in another server.
static uint32_t StatusCode_BadTooManyMatches_Key                                               = 0x806D0000; // The requested operation has too many matches to return.
static uint32_t StatusCode_BadQueryTooComplex_Key                                              = 0x806E0000; // The requested operation requires too many resources in the server.
static uint32_t StatusCode_BadNoMatch_Key                                                      = 0x806F0000; // The requested operation has no match to return.
static uint32_t StatusCode_BadMaxAgeInvalid_Key                                                = 0x80700000; // The max age parameter is invalid.
static uint32_t StatusCode_BadSecurityModeInsufficient_Key                                     = 0x80E60000; // The operation is not permitted over the current secure channel.
static uint32_t StatusCode_BadHistoryOperationInvalid_Key                                      = 0x80710000; // The history details parameter is not valid.
static uint32_t StatusCode_BadHistoryOperationUnsupported_Key                                  = 0x80720000; // The server does not support the requested operation.
static uint32_t StatusCode_BadInvalidTimestampArgument_Key                                     = 0x80BD0000; // The defined timestamp to return was invalid.
static uint32_t StatusCode_BadWriteNotSupported_Key                                            = 0x80730000; // "The server does not support writing the combination of value
static uint32_t StatusCode_BadTypeMismatch_Key                                                 = 0x80740000; // The value supplied for the attribute is not of the same type as the attribute's value.
static uint32_t StatusCode_BadMethodInvalid_Key                                                = 0x80750000; // The method id does not refer to a method for the specified object.
static uint32_t StatusCode_BadArgumentsMissing_Key                                             = 0x80760000; // The client did not specify all of the input arguments for the method.
static uint32_t StatusCode_BadNotExecutable_Key                                                = 0x81110000; // The executable attribute does not allow the execution of the method.
static uint32_t StatusCode_BadTooManySubscriptions_Key                                         = 0x80770000; // The server has reached its maximum number of subscriptions.
static uint32_t StatusCode_BadTooManyPublishRequests_Key                                       = 0x80780000; // The server has reached the maximum number of queued publish requests.
static uint32_t StatusCode_BadNoSubscription_Key                                               = 0x80790000; // There is no subscription available for this session.
static uint32_t StatusCode_BadSequenceNumberUnknown_Key                                        = 0x807A0000; // The sequence number is unknown to the server.
static uint32_t StatusCode_BadMessageNotAvailable_Key                                          = 0x807B0000; // The requested notification message is no longer available.
static uint32_t StatusCode_BadInsufficientClientProfile_Key                                    = 0x807C0000; // The client of the current session does not support one or more Profiles that are necessary for the subscription.
static uint32_t StatusCode_BadStateNotActive_Key                                               = 0x80BF0000; // The sub-state machine is not currently active.
static uint32_t StatusCode_BadAlreadyExists_Key                                                = 0x81150000; // An equivalent rule already exists.
static uint32_t StatusCode_BadTcpServerTooBusy_Key                                             = 0x807D0000; // The server cannot process the request because it is too busy.
static uint32_t StatusCode_BadTcpMessageTypeInvalid_Key                                        = 0x807E0000; // The type of the message specified in the header invalid.
static uint32_t StatusCode_BadTcpSecureChannelUnknown_Key                                      = 0x807F0000; // The SecureChannelId and/or TokenId are not currently in use.
static uint32_t StatusCode_BadTcpMessageTooLarge_Key                                           = 0x80800000; // The size of the message specified in the header is too large.
static uint32_t StatusCode_BadTcpNotEnoughResources_Key                                        = 0x80810000; // There are not enough resources to process the request.
static uint32_t StatusCode_BadTcpInternalError_Key                                             = 0x80820000; // An internal error occurred.
static uint32_t StatusCode_BadTcpEndpointUrlInvalid_Key                                        = 0x80830000; // The server does not recognize the QueryString specified.
static uint32_t StatusCode_BadRequestInterrupted_Key                                           = 0x80840000; // The request could not be sent because of a network interruption.
static uint32_t StatusCode_BadRequestTimeout_Key                                               = 0x80850000; // Timeout occurred while processing the request.
static uint32_t StatusCode_BadSecureChannelClosed_Key                                          = 0x80860000; // The secure channel has been closed.
static uint32_t StatusCode_BadSecureChannelTokenUnknown_Key                                    = 0x80870000; // The token has expired or is not recognized.
static uint32_t StatusCode_BadSequenceNumberInvalid_Key                                        = 0x80880000; // The sequence number is not valid.
static uint32_t StatusCode_BadProtocolVersionUnsupported_Key                                   = 0x80BE0000; // The applications do not have compatible protocol versions.
static uint32_t StatusCode_BadConfigurationError_Key                                           = 0x80890000; // There is a problem with the configuration that affects the usefulness of the value.
static uint32_t StatusCode_BadNotConnected_Key                                                 = 0x808A0000; // "The variable should receive its value from another variable
static uint32_t StatusCode_BadDeviceFailure_Key                                                = 0x808B0000; // There has been a failure in the device/data source that generates the value that has affected the value.
static uint32_t StatusCode_BadSensorFailure_Key                                                = 0x808C0000; // There has been a failure in the sensor from which the value is derived by the device/data source.
static uint32_t StatusCode_BadOutOfService_Key                                                 = 0x808D0000; // The source of the data is not operational.
static uint32_t StatusCode_BadDeadbandFilterInvalid_Key                                        = 0x808E0000; // The deadband filter is not valid.
static uint32_t StatusCode_UncertainNoCommunicationLastUsableValue_Key                         = 0x408F0000; // Communication to the data source has failed. The variable value is the last value that had a good quality.
static uint32_t StatusCode_UncertainLastUsableValue_Key                                        = 0x40900000; // Whatever was updating this value has stopped doing so.
static uint32_t StatusCode_UncertainSubstituteValue_Key                                        = 0x40910000; // The value is an operational value that was manually overwritten.
static uint32_t StatusCode_UncertainInitialValue_Key                                           = 0x40920000; // The value is an initial value for a variable that normally receives its value from another variable.
static uint32_t StatusCode_UncertainSensorNotAccurate_Key                                      = 0x40930000; // The value is at one of the sensor limits.
static uint32_t StatusCode_UncertainEngineeringUnitsExceeded_Key                               = 0x40940000; // The value is outside of the range of values defined for this parameter.
static uint32_t StatusCode_UncertainSubNormal_Key                                              = 0x40950000; // The value is derived from multiple sources and has less than the required number of Good sources.
static uint32_t StatusCode_GoodLocalOverride_Key                                               = 0x00960000; // The value has been overridden.
static uint32_t StatusCode_BadRefreshInProgress_Key                                            = 0x80970000; // "This Condition refresh failed
static uint32_t StatusCode_BadConditionAlreadyDisabled_Key                                     = 0x80980000; // This condition has already been disabled.
static uint32_t StatusCode_BadConditionAlreadyEnabled_Key                                      = 0x80CC0000; // This condition has already been enabled.
static uint32_t StatusCode_BadConditionDisabled_Key                                            = 0x80990000; // "Property not available
static uint32_t StatusCode_BadEventIdUnknown_Key                                               = 0x809A0000; // The specified event id is not recognized.
static uint32_t StatusCode_BadEventNotAcknowledgeable_Key                                      = 0x80BB0000; // The event cannot be acknowledged.
static uint32_t StatusCode_BadDialogNotActive_Key                                              = 0x80CD0000; // The dialog condition is not active.
static uint32_t StatusCode_BadDialogResponseInvalid_Key                                        = 0x80CE0000; // The response is not valid for the dialog.
static uint32_t StatusCode_BadConditionBranchAlreadyAcked_Key                                  = 0x80CF0000; // The condition branch has already been acknowledged.
static uint32_t StatusCode_BadConditionBranchAlreadyConfirmed_Key                              = 0x80D00000; // The condition branch has already been confirmed.
static uint32_t StatusCode_BadConditionAlreadyShelved_Key                                      = 0x80D10000; // The condition has already been shelved.
static uint32_t StatusCode_BadConditionNotShelved_Key                                          = 0x80D20000; // The condition is not currently shelved.
static uint32_t StatusCode_BadShelvingTimeOutOfRange_Key                                       = 0x80D30000; // The shelving time not within an acceptable range.
static uint32_t StatusCode_BadNoData_Key                                                       = 0x809B0000; // No data exists for the requested time range or event filter.
static uint32_t StatusCode_BadBoundNotFound_Key                                                = 0x80D70000; // No data found to provide upper or lower bound value.
static uint32_t StatusCode_BadBoundNotSupported_Key                                            = 0x80D80000; // The server cannot retrieve a bound for the variable.
static uint32_t StatusCode_BadDataLost_Key                                                     = 0x809D0000; // Data is missing due to collection started/stopped/lost.
static uint32_t StatusCode_BadDataUnavailable_Key                                              = 0x809E0000; // "Expected data is unavailable for the requested time range due to an un-mounted volume
static uint32_t StatusCode_BadEntryExists_Key                                                  = 0x809F0000; // The data or event was not successfully inserted because a matching entry exists.
static uint32_t StatusCode_BadNoEntryExists_Key                                                = 0x80A00000; // The data or event was not successfully updated because no matching entry exists.
static uint32_t StatusCode_BadTimestampNotSupported_Key                                        = 0x80A10000; // The client requested history using a timestamp format the server does not support (i.e requested ServerTimestamp when server only supports SourceTimestamp).
static uint32_t StatusCode_GoodEntryInserted_Key                                               = 0x00A20000; // The data or event was successfully inserted into the historical database.
static uint32_t StatusCode_GoodEntryReplaced_Key                                               = 0x00A30000; // The data or event field was successfully replaced in the historical database.
static uint32_t StatusCode_UncertainDataSubNormal_Key                                          = 0x40A40000; // The value is derived from multiple values and has less than the required number of Good values.
static uint32_t StatusCode_GoodNoData_Key                                                      = 0x00A50000; // No data exists for the requested time range or event filter.
static uint32_t StatusCode_GoodMoreData_Key                                                    = 0x00A60000; // The data or event field was successfully replaced in the historical database.
static uint32_t StatusCode_BadAggregateListMismatch_Key                                        = 0x80D40000; // The requested number of Aggregates does not match the requested number of NodeIds.
static uint32_t StatusCode_BadAggregateNotSupported_Key                                        = 0x80D50000; // The requested Aggregate is not support by the server.
static uint32_t StatusCode_BadAggregateInvalidInputs_Key                                       = 0x80D60000; // The aggregate value could not be derived due to invalid data inputs.
static uint32_t StatusCode_BadAggregateConfigurationRejected_Key                               = 0x80DA0000; // The aggregate configuration is not valid for specified node.
static uint32_t StatusCode_GoodDataIgnored_Key                                                 = 0x00D90000; // The request specifies fields which are not valid for the EventType or cannot be saved by the historian.
static uint32_t StatusCode_BadRequestNotAllowed_Key                                            = 0x80E40000; // The request was rejected by the server because it did not meet the criteria set by the server.
static uint32_t StatusCode_BadRequestNotComplete_Key                                           = 0x81130000; // The request has not been processed by the server yet.
static uint32_t StatusCode_GoodEdited_Key                                                      = 0x00DC0000; // The value does not come from the real source and has been edited by the server.
static uint32_t StatusCode_GoodPostActionFailed_Key                                            = 0x00DD0000; // There was an error in execution of these post-actions.
static uint32_t StatusCode_UncertainDominantValueChanged_Key                                   = 0x40DE0000; // The related EngineeringUnit has been changed but the Variable Value is still provided based on the previous unit.
static uint32_t StatusCode_GoodDependentValueChanged_Key                                       = 0x00E00000; // A dependent value has been changed but the change has not been applied to the device.
static uint32_t StatusCode_BadDominantValueChanged_Key                                         = 0x80E10000; // The related EngineeringUnit has been changed but this change has not been applied to the device. The Variable Value is still dependent on the previous unit but its status is currently Bad.
static uint32_t StatusCode_UncertainDependentValueChanged_Key                                  = 0x40E20000; // A dependent value has been changed but the change has not been applied to the device. The quality of the dominant variable is uncertain.
static uint32_t StatusCode_BadDependentValueChanged_Key                                        = 0x80E30000; // A dependent value has been changed but the change has not been applied to the device. The quality of the dominant variable is Bad.
static uint32_t StatusCode_GoodEdited_DependentValueChanged_Key                                = 0x01160000; // It is delivered with a dominant Variable value when a dependent Variable has changed but the change has not been applied.
static uint32_t StatusCode_GoodEdited_DominantValueChanged_Key                                 = 0x01170000; // It is delivered with a dependent Variable value when a dominant Variable has changed but the change has not been applied.
static uint32_t StatusCode_GoodEdited_DominantValueChanged_DependentValueChanged_Key           = 0x01180000; // It is delivered with a dependent Variable value when a dominant or dependent Variable has changed but change has not been applied.
static uint32_t StatusCode_BadEdited_OutOfRange_Key                                            = 0x81190000; // It is delivered with a Variable value when Variable has changed but the value is not legal.
static uint32_t StatusCode_BadInitialValue_OutOfRange_Key                                      = 0x811A0000; // It is delivered with a Variable value when a source Variable has changed but the value is not legal.
static uint32_t StatusCode_BadOutOfRange_DominantValueChanged_Key                              = 0x811B0000; // It is delivered with a dependent Variable value when a dominant Variable has changed and the value is not legal.
static uint32_t StatusCode_BadEdited_OutOfRange_DominantValueChanged_Key                       = 0x811C0000; // "It is delivered with a dependent Variable value when a dominant Variable has changed
static uint32_t StatusCode_BadOutOfRange_DominantValueChanged_DependentValueChanged_Key        = 0x811D0000; // It is delivered with a dependent Variable value when a dominant or dependent Variable has changed and the value is not legal.
static uint32_t StatusCode_BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged_Key = 0x811E0000; // "It is delivered with a dependent Variable value when a dominant or dependent Variable has changed
static uint32_t StatusCode_GoodCommunicationEvent_Key                                          = 0x00A70000; // The communication layer has raised an event.
static uint32_t StatusCode_GoodShutdownEvent_Key                                               = 0x00A80000; // The system is shutting down.
static uint32_t StatusCode_GoodCallAgain_Key                                                   = 0x00A90000; // The operation is not finished and needs to be called again.
static uint32_t StatusCode_GoodNonCriticalTimeout_Key                                          = 0x00AA0000; // A non-critical timeout occurred.
static uint32_t StatusCode_BadInvalidArgument_Key                                              = 0x80AB0000; // One or more arguments are invalid.
static uint32_t StatusCode_BadConnectionRejected_Key                                           = 0x80AC0000; // Could not establish a network connection to remote server.
static uint32_t StatusCode_BadDisconnect_Key                                                   = 0x80AD0000; // The server has disconnected from the client.
static uint32_t StatusCode_BadConnectionClosed_Key                                             = 0x80AE0000; // The network connection has been closed.
static uint32_t StatusCode_BadInvalidState_Key                                                 = 0x80AF0000; // "The operation cannot be completed because the object is closed
static uint32_t StatusCode_BadEndOfStream_Key                                                  = 0x80B00000; // Cannot move beyond end of the stream.
static uint32_t StatusCode_BadNoDataAvailable_Key                                              = 0x80B10000; // No data is currently available for reading from a non-blocking stream.
static uint32_t StatusCode_BadWaitingForResponse_Key                                           = 0x80B20000; // The asynchronous operation is waiting for a response.
static uint32_t StatusCode_BadOperationAbandoned_Key                                           = 0x80B30000; // The asynchronous operation was abandoned by the caller.
static uint32_t StatusCode_BadExpectedStreamToBlock_Key                                        = 0x80B40000; // The stream did not return all data requested (possibly because it is a non-blocking stream).
static uint32_t StatusCode_BadWouldBlock_Key                                                   = 0x80B50000; // Non blocking behaviour is required and the operation would block.
static uint32_t StatusCode_BadSyntaxError_Key                                                  = 0x80B60000; // A value had an invalid syntax.
static uint32_t StatusCode_BadMaxConnectionsReached_Key                                        = 0x80B70000; // The operation could not be finished because all available connections are in use.

static std::map<uint32_t, std::string> STATUS_CODE_MAP =
{
   {StatusCode_Good_Key                                                           , "Good"},
   {StatusCode_BadUnexpectedError_Key                                             , "BadUnexpectedError"},
   {StatusCode_BadInternalError_Key                                               , "BadInternalError"},
   {StatusCode_BadOutOfMemory_Key                                                 , "BadOutOfMemory"},
   {StatusCode_BadResourceUnavailable_Key                                         , "BadResourceUnavailable"},
   {StatusCode_BadCommunicationError_Key                                          , "BadCommunicationError"},
   {StatusCode_BadEncodingError_Key                                               , "BadEncodingError"},
   {StatusCode_BadDecodingError_Key                                               , "BadDecodingError"},
   {StatusCode_BadEncodingLimitsExceeded_Key                                      , "BadEncodingLimitsExceeded"},
   {StatusCode_BadRequestTooLarge_Key                                             , "BadRequestTooLarge"},
   {StatusCode_BadResponseTooLarge_Key                                            , "BadResponseTooLarge"},
   {StatusCode_BadUnknownResponse_Key                                             , "BadUnknownResponse"},
   {StatusCode_BadTimeout_Key                                                     , "BadTimeout"},
   {StatusCode_BadServiceUnsupported_Key                                          , "BadServiceUnsupported"},
   {StatusCode_BadShutdown_Key                                                    , "BadShutdown"},
   {StatusCode_BadServerNotConnected_Key                                          , "BadServerNotConnected"},
   {StatusCode_BadServerHalted_Key                                                , "BadServerHalted"},
   {StatusCode_BadNothingToDo_Key                                                 , "BadNothingToDo"},
   {StatusCode_BadTooManyOperations_Key                                           , "BadTooManyOperations"},
   {StatusCode_BadTooManyMonitoredItems_Key                                       , "BadTooManyMonitoredItems"},
   {StatusCode_BadDataTypeIdUnknown_Key                                           , "BadDataTypeIdUnknown"},
   {StatusCode_BadCertificateInvalid_Key                                          , "BadCertificateInvalid"},
   {StatusCode_BadSecurityChecksFailed_Key                                        , "BadSecurityChecksFailed"},
   {StatusCode_BadCertificatePolicyCheckFailed_Key                                , "BadCertificatePolicyCheckFailed"},
   {StatusCode_BadCertificateTimeInvalid_Key                                      , "BadCertificateTimeInvalid"},
   {StatusCode_BadCertificateIssuerTimeInvalid_Key                                , "BadCertificateIssuerTimeInvalid"},
   {StatusCode_BadCertificateHostNameInvalid_Key                                  , "BadCertificateHostNameInvalid"},
   {StatusCode_BadCertificateUriInvalid_Key                                       , "BadCertificateUriInvalid"},
   {StatusCode_BadCertificateUseNotAllowed_Key                                    , "BadCertificateUseNotAllowed"},
   {StatusCode_BadCertificateIssuerUseNotAllowed_Key                              , "BadCertificateIssuerUseNotAllowed"},
   {StatusCode_BadCertificateUntrusted_Key                                        , "BadCertificateUntrusted"},
   {StatusCode_BadCertificateRevocationUnknown_Key                                , "BadCertificateRevocationUnknown"},
   {StatusCode_BadCertificateIssuerRevocationUnknown_Key                          , "BadCertificateIssuerRevocationUnknown"},
   {StatusCode_BadCertificateRevoked_Key                                          , "BadCertificateRevoked"},
   {StatusCode_BadCertificateIssuerRevoked_Key                                    , "BadCertificateIssuerRevoked"},
   {StatusCode_BadCertificateChainIncomplete_Key                                  , "BadCertificateChainIncomplete"},
   {StatusCode_BadUserAccessDenied_Key                                            , "BadUserAccessDenied"},
   {StatusCode_BadIdentityTokenInvalid_Key                                        , "BadIdentityTokenInvalid"},
   {StatusCode_BadIdentityTokenRejected_Key                                       , "BadIdentityTokenRejected"},
   {StatusCode_BadSecureChannelIdInvalid_Key                                      , "BadSecureChannelIdInvalid"},
   {StatusCode_BadInvalidTimestamp_Key                                            , "BadInvalidTimestamp"},
   {StatusCode_BadNonceInvalid_Key                                                , "BadNonceInvalid"},
   {StatusCode_BadSessionIdInvalid_Key                                            , "BadSessionIdInvalid"},
   {StatusCode_BadSessionClosed_Key                                               , "BadSessionClosed"},
   {StatusCode_BadSessionNotActivated_Key                                         , "BadSessionNotActivated"},
   {StatusCode_BadSubscriptionIdInvalid_Key                                       , "BadSubscriptionIdInvalid"},
   {StatusCode_BadRequestHeaderInvalid_Key                                        , "BadRequestHeaderInvalid"},
   {StatusCode_BadTimestampsToReturnInvalid_Key                                   , "BadTimestampsToReturnInvalid"},
   {StatusCode_BadRequestCancelledByClient_Key                                    , "BadRequestCancelledByClient"},
   {StatusCode_BadTooManyArguments_Key                                            , "BadTooManyArguments"},
   {StatusCode_BadLicenseExpired_Key                                              , "BadLicenseExpired"},
   {StatusCode_BadLicenseLimitsExceeded_Key                                       , "BadLicenseLimitsExceeded"},
   {StatusCode_BadLicenseNotAvailable_Key                                         , "BadLicenseNotAvailable"},
   {StatusCode_GoodSubscriptionTransferred_Key                                    , "GoodSubscriptionTransferred"},
   {StatusCode_GoodCompletesAsynchronously_Key                                    , "GoodCompletesAsynchronously"},
   {StatusCode_GoodOverload_Key                                                   , "GoodOverload"},
   {StatusCode_GoodClamped_Key                                                    , "GoodClamped"},
   {StatusCode_BadNoCommunication_Key                                             , "BadNoCommunication"},
   {StatusCode_BadWaitingForInitialData_Key                                       , "BadWaitingForInitialData"},
   {StatusCode_BadNodeIdInvalid_Key                                               , "BadNodeIdInvalid"},
   {StatusCode_BadNodeIdUnknown_Key                                               , "BadNodeIdUnknown"},
   {StatusCode_BadAttributeIdInvalid_Key                                          , "BadAttributeIdInvalid"},
   {StatusCode_BadIndexRangeInvalid_Key                                           , "BadIndexRangeInvalid"},
   {StatusCode_BadIndexRangeNoData_Key                                            , "BadIndexRangeNoData"},
   {StatusCode_BadDataEncodingInvalid_Key                                         , "BadDataEncodingInvalid"},
   {StatusCode_BadDataEncodingUnsupported_Key                                     , "BadDataEncodingUnsupported"},
   {StatusCode_BadNotReadable_Key                                                 , "BadNotReadable"},
   {StatusCode_BadNotWritable_Key                                                 , "BadNotWritable"},
   {StatusCode_BadOutOfRange_Key                                                  , "BadOutOfRange"},
   {StatusCode_BadNotSupported_Key                                                , "BadNotSupported"},
   {StatusCode_BadNotFound_Key                                                    , "BadNotFound"},
   {StatusCode_BadObjectDeleted_Key                                               , "BadObjectDeleted"},
   {StatusCode_BadNotImplemented_Key                                              , "BadNotImplemented"},
   {StatusCode_BadMonitoringModeInvalid_Key                                       , "BadMonitoringModeInvalid"},
   {StatusCode_BadMonitoredItemIdInvalid_Key                                      , "BadMonitoredItemIdInvalid"},
   {StatusCode_BadMonitoredItemFilterInvalid_Key                                  , "BadMonitoredItemFilterInvalid"},
   {StatusCode_BadMonitoredItemFilterUnsupported_Key                              , "BadMonitoredItemFilterUnsupported"},
   {StatusCode_BadFilterNotAllowed_Key                                            , "BadFilterNotAllowed"},
   {StatusCode_BadStructureMissing_Key                                            , "BadStructureMissing"},
   {StatusCode_BadEventFilterInvalid_Key                                          , "BadEventFilterInvalid"},
   {StatusCode_BadContentFilterInvalid_Key                                        , "BadContentFilterInvalid"},
   {StatusCode_BadFilterOperatorInvalid_Key                                       , "BadFilterOperatorInvalid"},
   {StatusCode_BadFilterOperatorUnsupported_Key                                   , "BadFilterOperatorUnsupported"},
   {StatusCode_BadFilterOperandCountMismatch_Key                                  , "BadFilterOperandCountMismatch"},
   {StatusCode_BadFilterOperandInvalid_Key                                        , "BadFilterOperandInvalid"},
   {StatusCode_BadFilterElementInvalid_Key                                        , "BadFilterElementInvalid"},
   {StatusCode_BadFilterLiteralInvalid_Key                                        , "BadFilterLiteralInvalid"},
   {StatusCode_BadContinuationPointInvalid_Key                                    , "BadContinuationPointInvalid"},
   {StatusCode_BadNoContinuationPoints_Key                                        , "BadNoContinuationPoints"},
   {StatusCode_BadReferenceTypeIdInvalid_Key                                      , "BadReferenceTypeIdInvalid"},
   {StatusCode_BadBrowseDirectionInvalid_Key                                      , "BadBrowseDirectionInvalid"},
   {StatusCode_BadNodeNotInView_Key                                               , "BadNodeNotInView"},
   {StatusCode_BadNumericOverflow_Key                                             , "BadNumericOverflow"},
   {StatusCode_BadServerUriInvalid_Key                                            , "BadServerUriInvalid"},
   {StatusCode_BadServerNameMissing_Key                                           , "BadServerNameMissing"},
   {StatusCode_BadDiscoveryUrlMissing_Key                                         , "BadDiscoveryUrlMissing"},
   {StatusCode_BadSempahoreFileMissing_Key                                        , "BadSempahoreFileMissing"},
   {StatusCode_BadRequestTypeInvalid_Key                                          , "BadRequestTypeInvalid"},
   {StatusCode_BadSecurityModeRejected_Key                                        , "BadSecurityModeRejected"},
   {StatusCode_BadSecurityPolicyRejected_Key                                      , "BadSecurityPolicyRejected"},
   {StatusCode_BadTooManySessions_Key                                             , "BadTooManySessions"},
   {StatusCode_BadUserSignatureInvalid_Key                                        , "BadUserSignatureInvalid"},
   {StatusCode_BadApplicationSignatureInvalid_Key                                 , "BadApplicationSignatureInvalid"},
   {StatusCode_BadNoValidCertificates_Key                                         , "BadNoValidCertificates"},
   {StatusCode_BadIdentityChangeNotSupported_Key                                  , "BadIdentityChangeNotSupported"},
   {StatusCode_BadRequestCancelledByRequest_Key                                   , "BadRequestCancelledByRequest"},
   {StatusCode_BadParentNodeIdInvalid_Key                                         , "BadParentNodeIdInvalid"},
   {StatusCode_BadReferenceNotAllowed_Key                                         , "BadReferenceNotAllowed"},
   {StatusCode_BadNodeIdRejected_Key                                              , "BadNodeIdRejected"},
   {StatusCode_BadNodeIdExists_Key                                                , "BadNodeIdExists"},
   {StatusCode_BadNodeClassInvalid_Key                                            , "BadNodeClassInvalid"},
   {StatusCode_BadBrowseNameInvalid_Key                                           , "BadBrowseNameInvalid"},
   {StatusCode_BadBrowseNameDuplicated_Key                                        , "BadBrowseNameDuplicated"},
   {StatusCode_BadNodeAttributesInvalid_Key                                       , "BadNodeAttributesInvalid"},
   {StatusCode_BadTypeDefinitionInvalid_Key                                       , "BadTypeDefinitionInvalid"},
   {StatusCode_BadSourceNodeIdInvalid_Key                                         , "BadSourceNodeIdInvalid"},
   {StatusCode_BadTargetNodeIdInvalid_Key                                         , "BadTargetNodeIdInvalid"},
   {StatusCode_BadDuplicateReferenceNotAllowed_Key                                , "BadDuplicateReferenceNotAllowed"},
   {StatusCode_BadInvalidSelfReference_Key                                        , "BadInvalidSelfReference"},
   {StatusCode_BadReferenceLocalOnly_Key                                          , "BadReferenceLocalOnly"},
   {StatusCode_BadNoDeleteRights_Key                                              , "BadNoDeleteRights"},
   {StatusCode_UncertainReferenceNotDeleted_Key                                   , "UncertainReferenceNotDeleted"},
   {StatusCode_BadServerIndexInvalid_Key                                          , "BadServerIndexInvalid"},
   {StatusCode_BadViewIdUnknown_Key                                               , "BadViewIdUnknown"},
   {StatusCode_BadViewTimestampInvalid_Key                                        , "BadViewTimestampInvalid"},
   {StatusCode_BadViewParameterMismatch_Key                                       , "BadViewParameterMismatch"},
   {StatusCode_BadViewVersionInvalid_Key                                          , "BadViewVersionInvalid"},
   {StatusCode_UncertainNotAllNodesAvailable_Key                                  , "UncertainNotAllNodesAvailable"},
   {StatusCode_GoodResultsMayBeIncomplete_Key                                     , "GoodResultsMayBeIncomplete"},
   {StatusCode_BadNotTypeDefinition_Key                                           , "BadNotTypeDefinition"},
   {StatusCode_UncertainReferenceOutOfServer_Key                                  , "UncertainReferenceOutOfServer"},
   {StatusCode_BadTooManyMatches_Key                                              , "BadTooManyMatches"},
   {StatusCode_BadQueryTooComplex_Key                                             , "BadQueryTooComplex"},
   {StatusCode_BadNoMatch_Key                                                     , "BadNoMatch"},
   {StatusCode_BadMaxAgeInvalid_Key                                               , "BadMaxAgeInvalid"},
   {StatusCode_BadSecurityModeInsufficient_Key                                    , "BadSecurityModeInsufficient"},
   {StatusCode_BadHistoryOperationInvalid_Key                                     , "BadHistoryOperationInvalid"},
   {StatusCode_BadHistoryOperationUnsupported_Key                                 , "BadHistoryOperationUnsupported"},
   {StatusCode_BadInvalidTimestampArgument_Key                                    , "BadInvalidTimestampArgument"},
   {StatusCode_BadWriteNotSupported_Key                                           , "BadWriteNotSupported"},
   {StatusCode_BadTypeMismatch_Key                                                , "BadTypeMismatch"},
   {StatusCode_BadMethodInvalid_Key                                               , "BadMethodInvalid"},
   {StatusCode_BadArgumentsMissing_Key                                            , "BadArgumentsMissing"},
   {StatusCode_BadNotExecutable_Key                                               , "BadNotExecutable"},
   {StatusCode_BadTooManySubscriptions_Key                                        , "BadTooManySubscriptions"},
   {StatusCode_BadTooManyPublishRequests_Key                                      , "BadTooManyPublishRequests"},
   {StatusCode_BadNoSubscription_Key                                              , "BadNoSubscription"},
   {StatusCode_BadSequenceNumberUnknown_Key                                       , "BadSequenceNumberUnknown"},
   {StatusCode_BadMessageNotAvailable_Key                                         , "BadMessageNotAvailable"},
   {StatusCode_BadInsufficientClientProfile_Key                                   , "BadInsufficientClientProfile"},
   {StatusCode_BadStateNotActive_Key                                              , "BadStateNotActive"},
   {StatusCode_BadAlreadyExists_Key                                               , "BadAlreadyExists"},
   {StatusCode_BadTcpServerTooBusy_Key                                            , "BadTcpServerTooBusy"},
   {StatusCode_BadTcpMessageTypeInvalid_Key                                       , "BadTcpMessageTypeInvalid"},
   {StatusCode_BadTcpSecureChannelUnknown_Key                                     , "BadTcpSecureChannelUnknown"},
   {StatusCode_BadTcpMessageTooLarge_Key                                          , "BadTcpMessageTooLarge"},
   {StatusCode_BadTcpNotEnoughResources_Key                                       , "BadTcpNotEnoughResources"},
   {StatusCode_BadTcpInternalError_Key                                            , "BadTcpInternalError"},
   {StatusCode_BadTcpEndpointUrlInvalid_Key                                       , "BadTcpEndpointUrlInvalid"},
   {StatusCode_BadRequestInterrupted_Key                                          , "BadRequestInterrupted"},
   {StatusCode_BadRequestTimeout_Key                                              , "BadRequestTimeout"},
   {StatusCode_BadSecureChannelClosed_Key                                         , "BadSecureChannelClosed"},
   {StatusCode_BadSecureChannelTokenUnknown_Key                                   , "BadSecureChannelTokenUnknown"},
   {StatusCode_BadSequenceNumberInvalid_Key                                       , "BadSequenceNumberInvalid"},
   {StatusCode_BadProtocolVersionUnsupported_Key                                  , "BadProtocolVersionUnsupported"},
   {StatusCode_BadConfigurationError_Key                                          , "BadConfigurationError"},
   {StatusCode_BadNotConnected_Key                                                , "BadNotConnected"},
   {StatusCode_BadDeviceFailure_Key                                               , "BadDeviceFailure"},
   {StatusCode_BadSensorFailure_Key                                               , "BadSensorFailure"},
   {StatusCode_BadOutOfService_Key                                                , "BadOutOfService"},
   {StatusCode_BadDeadbandFilterInvalid_Key                                       , "BadDeadbandFilterInvalid"},
   {StatusCode_UncertainNoCommunicationLastUsableValue_Key                        , "UncertainNoCommunicationLastUsableValue"},
   {StatusCode_UncertainLastUsableValue_Key                                       , "UncertainLastUsableValue"},
   {StatusCode_UncertainSubstituteValue_Key                                       , "UncertainSubstituteValue"},
   {StatusCode_UncertainInitialValue_Key                                          , "UncertainInitialValue"},
   {StatusCode_UncertainSensorNotAccurate_Key                                     , "UncertainSensorNotAccurate"},
   {StatusCode_UncertainEngineeringUnitsExceeded_Key                              , "UncertainEngineeringUnitsExceeded"},
   {StatusCode_UncertainSubNormal_Key                                             , "UncertainSubNormal"},
   {StatusCode_GoodLocalOverride_Key                                              , "GoodLocalOverride"},
   {StatusCode_BadRefreshInProgress_Key                                           , "BadRefreshInProgress"},
   {StatusCode_BadConditionAlreadyDisabled_Key                                    , "BadConditionAlreadyDisabled"},
   {StatusCode_BadConditionAlreadyEnabled_Key                                     , "BadConditionAlreadyEnabled"},
   {StatusCode_BadConditionDisabled_Key                                           , "BadConditionDisabled"},
   {StatusCode_BadEventIdUnknown_Key                                              , "BadEventIdUnknown"},
   {StatusCode_BadEventNotAcknowledgeable_Key                                     , "BadEventNotAcknowledgeable"},
   {StatusCode_BadDialogNotActive_Key                                             , "BadDialogNotActive"},
   {StatusCode_BadDialogResponseInvalid_Key                                       , "BadDialogResponseInvalid"},
   {StatusCode_BadConditionBranchAlreadyAcked_Key                                 , "BadConditionBranchAlreadyAcked"},
   {StatusCode_BadConditionBranchAlreadyConfirmed_Key                             , "BadConditionBranchAlreadyConfirmed"},
   {StatusCode_BadConditionAlreadyShelved_Key                                     , "BadConditionAlreadyShelved"},
   {StatusCode_BadConditionNotShelved_Key                                         , "BadConditionNotShelved"},
   {StatusCode_BadShelvingTimeOutOfRange_Key                                      , "BadShelvingTimeOutOfRange"},
   {StatusCode_BadNoData_Key                                                      , "BadNoData"},
   {StatusCode_BadBoundNotFound_Key                                               , "BadBoundNotFound"},
   {StatusCode_BadBoundNotSupported_Key                                           , "BadBoundNotSupported"},
   {StatusCode_BadDataLost_Key                                                    , "BadDataLost"},
   {StatusCode_BadDataUnavailable_Key                                             , "BadDataUnavailable"},
   {StatusCode_BadEntryExists_Key                                                 , "BadEntryExists"},
   {StatusCode_BadNoEntryExists_Key                                               , "BadNoEntryExists"},
   {StatusCode_BadTimestampNotSupported_Key                                       , "BadTimestampNotSupported"},
   {StatusCode_GoodEntryInserted_Key                                              , "GoodEntryInserted"},
   {StatusCode_GoodEntryReplaced_Key                                              , "GoodEntryReplaced"},
   {StatusCode_UncertainDataSubNormal_Key                                         , "UncertainDataSubNormal"},
   {StatusCode_GoodNoData_Key                                                     , "GoodNoData"},
   {StatusCode_GoodMoreData_Key                                                   , "GoodMoreData"},
   {StatusCode_BadAggregateListMismatch_Key                                       , "BadAggregateListMismatch"},
   {StatusCode_BadAggregateNotSupported_Key                                       , "BadAggregateNotSupported"},
   {StatusCode_BadAggregateInvalidInputs_Key                                      , "BadAggregateInvalidInputs"},
   {StatusCode_BadAggregateConfigurationRejected_Key                              , "BadAggregateConfigurationRejected"},
   {StatusCode_GoodDataIgnored_Key                                                , "GoodDataIgnored"},
   {StatusCode_BadRequestNotAllowed_Key                                           , "BadRequestNotAllowed"},
   {StatusCode_BadRequestNotComplete_Key                                          , "BadRequestNotComplete"},
   {StatusCode_GoodEdited_Key                                                     , "GoodEdited"},
   {StatusCode_GoodPostActionFailed_Key                                           , "GoodPostActionFailed"},
   {StatusCode_UncertainDominantValueChanged_Key                                  , "UncertainDominantValueChanged"},
   {StatusCode_GoodDependentValueChanged_Key                                      , "GoodDependentValueChanged"},
   {StatusCode_BadDominantValueChanged_Key                                        , "BadDominantValueChanged"},
   {StatusCode_UncertainDependentValueChanged_Key                                 , "UncertainDependentValueChanged"},
   {StatusCode_BadDependentValueChanged_Key                                       , "BadDependentValueChanged"},
   {StatusCode_GoodEdited_DependentValueChanged_Key                               , "GoodEdited_DependentValueChanged"},
   {StatusCode_GoodEdited_DominantValueChanged_Key                                , "GoodEdited_DominantValueChanged"},
   {StatusCode_GoodEdited_DominantValueChanged_DependentValueChanged_Key          , "GoodEdited_DominantValueChanged_DependentValueChanged"},
   {StatusCode_BadEdited_OutOfRange_Key                                           , "BadEdited_OutOfRange"},
   {StatusCode_BadInitialValue_OutOfRange_Key                                     , "BadInitialValue_OutOfRange"},
   {StatusCode_BadOutOfRange_DominantValueChanged_Key                             , "BadOutOfRange_DominantValueChanged"},
   {StatusCode_BadEdited_OutOfRange_DominantValueChanged_Key                      , "BadEdited_OutOfRange_DominantValueChanged"},
   {StatusCode_BadOutOfRange_DominantValueChanged_DependentValueChanged_Key       , "BadOutOfRange_DominantValueChanged_DependentValueChanged"},
   {StatusCode_BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged_Key, "BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged"},
   {StatusCode_GoodCommunicationEvent_Key                                         , "GoodCommunicationEvent"},
   {StatusCode_GoodShutdownEvent_Key                                              , "GoodShutdownEvent"},
   {StatusCode_GoodCallAgain_Key                                                  , "GoodCallAgain"},
   {StatusCode_GoodNonCriticalTimeout_Key                                         , "GoodNonCriticalTimeout"},
   {StatusCode_BadInvalidArgument_Key                                             , "BadInvalidArgument"},
   {StatusCode_BadConnectionRejected_Key                                          , "BadConnectionRejected"},
   {StatusCode_BadDisconnect_Key                                                  , "BadDisconnect"},
   {StatusCode_BadConnectionClosed_Key                                            , "BadConnectionClosed"},
   {StatusCode_BadInvalidState_Key                                                , "BadInvalidState"},
   {StatusCode_BadEndOfStream_Key                                                 , "BadEndOfStream"},
   {StatusCode_BadNoDataAvailable_Key                                             , "BadNoDataAvailable"},
   {StatusCode_BadWaitingForResponse_Key                                          , "BadWaitingForResponse"},
   {StatusCode_BadOperationAbandoned_Key                                          , "BadOperationAbandoned"},
   {StatusCode_BadExpectedStreamToBlock_Key                                       , "BadExpectedStreamToBlock"},
   {StatusCode_BadWouldBlock_Key                                                  , "BadWouldBlock"},
   {StatusCode_BadSyntaxError_Key                                                 , "BadSyntaxError"},
   {StatusCode_BadMaxConnectionsReached_Key                                       , "BadMaxConnectionsReached"}
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
static uint8_t Severity_Good_Key      = 0x00; // 00 - Indicates that the operation was successful and the associated results may be used.
static uint8_t Severity_Uncertain_Key = 0x01; // 01 - Indicates that the operation was partially successful and that associated results might not be suitable for some purposes.
static uint8_t Severity_Bad_Key       = 0x02; // 10 - Indicates that the operation failed and any associated results cannot be used.

static std::map<uint8_t, std::string> SEVERITY_MAP =
{
   {Severity_Good_Key      , "Severity_Good"},
   {Severity_Uncertain_Key , "Severity_Uncertain"},
   {Severity_Bad_Key       , "Severity_Bad"}
};

// InfoType: Bit Range: 10-11
static uint8_t InfoType_NotUsed_Key   = 0x00; // 00 - The info bits are not used and shall be set to zero
static uint8_t InfoType_DataValue_Key = 0x01; // 01 - The StatusCode and its info bits are associated with a data value returned from the Server.

static std::map<uint8_t, std::string> INFO_TYPE_MAP =
{
   {InfoType_NotUsed_Key   , "InfoType_NotUsed"},
   {InfoType_DataValue_Key , "InfoType_DataValue"}
};

// LimitBits: Bit Range: 8-9
static uint8_t LimitBits_None_Key     = 0x00; // 00 - The value is free to change. 
static uint8_t LimitBits_Low_Key      = 0x01; // 01 - The value is at the lower limit for the data source. 
static uint8_t LimitBits_High_Key     = 0x02; // 10 - The value is at the higher limit for the data source.
static uint8_t LimitBits_Constant_Key = 0x03; // 11 - The value is constant and cannot change.

static std::map<uint8_t, std::string> LIMIT_BITS_MAP =
{
   {LimitBits_None_Key     , "LimitBits_None"},
   {LimitBits_Low_Key      , "LimitBits_Low"},
   {LimitBits_High_Key     , "LimitBits_High"},
   {LimitBits_Constant_Key , "LimitBits_Constant"}
};

// HistorianBits: Bit Range: 0-4
static uint8_t HistorianBits_Raw_Key          = 0x00; // XXX00 - A raw data value.
static uint8_t HistorianBits_Calculated_Key   = 0x01; // XXX01 - A data value which was calculated. 
static uint8_t HistorianBits_Interpolated_Key = 0x02; // XXX10 - A data value which was interpolated.

static std::map<uint8_t, std::string> HISTORIAN_BITS_MAP =
{
   {HistorianBits_Raw_Key          , "HistorianBits_Raw"},
   {HistorianBits_Calculated_Key   , "HistorianBits_Calculated"},
   {HistorianBits_Interpolated_Key , "HistorianBits_Interpolated"}
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
