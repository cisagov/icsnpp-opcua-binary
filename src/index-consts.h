// consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_CONSTS_H
#define OPCUA_BINARY_CONSTS_H

//
// Index constants for setting values in OPCUC_Binary::Info
//

#define IS_ORIG_IDX                       3
#define SOURCE_H_IDX                      4
#define SOURCE_P_IDX                      5
#define DESTINATION_H_IDX                 6
#define DESTINATION_P_IDX                 7

// OpcUA_ID  
// While this id is NOT part of the OpcUA documented spec, we use it to tie nested log files
// together - e.g. any nested log files such as the status code detail log will contain
// this id which can be used to reference back to the primary OpcUA log file.
//
#define OPCUA_LINK_ID_SRC_IDX             8

// Msg Header
#define MSG_TYPE_IDX                      9
#define IS_FINAL_IDX                      10
#define MSG_SIZE_IDX                      11

// Msg_ERR
#define ERROR_IDX                         12
#define REASON_IDX                        13

// Msg_HEL and Msg_ACK
#define VERSION_IDX                       14
#define RCV_BUF_SIZE_IDX                  15
#define SND_BUF_SIZE_IDX                  16
#define MAX_MSG_SIZE_IDX                  17
#define MAX_CHUNK_CNT_IDX                 18
#define ENDPOINT_URL_IDX                  19 // Msg_HEL

// Msg Body
#define SEC_CHANNEL_ID_IDX                20
#define SEC_TOKEN_ID_IDX                  21
#define SEC_POLICY_URI_LEN_IDX            22
#define SEC_POLICY_URI_IDX                23
#define SND_CERT_LEN_IDX                  24
#define SND_CERT_IDX                      25
#define RCV_CERT_LEN_IDX                  26
#define RCV_CERT_IDX                      27
#define SEQ_NUMBER_IDX                    28
#define REQUEST_ID_IDX                    29
#define ENCODING_MASK_IDX                 30
#define NAMESPACE_IDX                     31
#define IDENTIFIER_IDX                    32
#define IDENTIFIER_STR_IDX                33

#endif

