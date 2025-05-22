// Secure Channel consts.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef OPCUA_BINARY_SECURE_CHANNEL_CONSTS_H
#define OPCUA_BINARY_SECURE_CHANNEL_CONSTS_H

//
// Index constants for setting values in OPCUA_Binary::OpenSecureChannel
//
#define OPENSECURE_CHANNEL_OPCUA_LINK_ID_DST_IDX 8

// OpenSecureChannel Request
#define CLIENT_PROTO_VER_IDX                     9
#define SECURITY_TOKEN_REQ_TYPE_IDX             10
#define MESSAGE_SECURITY_MODE_IDX               11
#define CLIENT_NONCE_IDX                        12
#define REQ_LIFETIME_IDX                        13

// OpenSecureChannel Response
#define SERVER_PROTO_VER_IDX                    14

//
// Secure Channel Id & Secure Token Id.
// Returned by the server when processing the
// OpenSecureChannel Service.  Used down stream
// by other services to secure the Message
//
#define SEC_CHNL_TOKEN_CHANNEL_ID_IDX            15
#define SEC_CHNL_TOKEN_ID_IDX                    16

#define SEC_TOKEN_CREATED_AT_IDX                 17
#define SEC_TOKEN_REVISED_LIFETIME_IDX           18
#define SERVER_NONCE_IDX                         19

#endif

