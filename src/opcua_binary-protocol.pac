## opcua_binary-protocol.pac
##
## OPCUA Binary Protocol Analyzer
##
## Top-level binpac file.  Defines flow and initial records.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%include opcua_binary-types.pac
%include opcua_binary-types_debug.pac
%include opcua_binary-types_consts.pac
%include opcua_binary-opcua_nodeid_types.pac
%include opcua_binary-opcua_nodeid_types_debug.pac
%include opcua_binary-services.pac
%include req-res-header/opcua_binary-req_res_header.pac
%include req-res-header/opcua_binary-req_res_header_debug.pac
%include secure-channel/opcua_binary-secure_channel.pac
%include secure-channel/opcua_binary-secure_channel_debug.pac
%include get-endpoints/opcua_binary-get_endpoints.pac
%include get-endpoints/opcua_binary-get_endpoints_debug.pac
%include create-session/opcua_binary-create_session.pac
%include browse/opcua_binary-browse.pac
%include browse/opcua_binary-browse_debug.pac
%include create-session/opcua_binary-create_session_debug.pac
%include activate-session/opcua_binary-activate_session.pac
%include activate-session/opcua_binary-activate_session_debug.pac
%include create-subscription/opcua_binary-create_subscription.pac
%include create-subscription/opcua_binary-create_subscription_debug.pac
%include stubbed-out/opcua_binary-stubbed_out_service.pac
%include stubbed-out/opcua_binary-stubbed_out_service_debug.pac
%include opcua_binary-protocol_debug.pac

#
# The below type definitions were taken from:
#
# UA Specification Part 6 - Mappings 1.04.pdf
#
# Message Types: HEL, ACK, ERR, RHE
# 7.1.2.2 Message Header       : Table 50 - OPC UA Connection Protocol Message Header
# 7.1.2.3 Hello Message        : Table 51 - OPC UA Connection Protocol Hello Message
# 7.1.2.4 Acknowledge Message  : Table 52 - OPC UA Connection Protocol Acknowledge Message
# 7.1.2.5 Error Message        : Table 53 - OPC UA Connection Protocol Error Message
# 7.1.2.6 ReverseHello Message : Table 54 - OPC UA Connection Protocol ReverseHello Message
#
#
# Message Types: OPN, CLO, MSG
#
# 6.7.2.2 Message Header  : Table 41 - OPC UA Secure Conversation Message Header
# 6.7.2.3 Security Header : Table 42 - Asymmetric Algorithm Security Header
#                           Table 43 - Symmetric Algorithm Security Header (Token Id)
#                           Table 44 - Sequence Header
#
# Note: The Token Id and Secure Channel Id are set during the OpenSecureChannel Service
#       and referenced by down stream MSG and CLO message types.
#
#type Msg_Header = record {
type Msg_Header(is_orig: bool) = record {
    msg_type   : uint8[3];
    is_final   : uint8;
    msg_size   : uint32;
    type       : case($context.flow.uint8_array_to_uint32(msg_type)) of {
        HEL  -> hel: Msg_HEL(this);
        ACK  -> ack: Msg_ACK(this);
        ERR  -> err: Msg_ERR(this);
        OPN  -> opn: Msg_OPN(this);
        MSG  -> msg: Msg_MSG(this);
        CLO  -> clo: Msg_CLO(this);
        #RHE  -> rhe: Msg_RHE(this);
    };
    unknown: bytestring &restofdata, &transient;
} &byteorder=littleendian, &length=msg_size;

type Msg_HEL(header: Msg_Header) = record {
    version       : uint32;
    rcv_buf_size  : uint32;
    snd_buf_size  : uint32;
    max_msg_size  : uint32;
    max_chunk_cnt : uint32;
    endpoint_url  : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.deliver_Msg_HEL(this);
} &byteorder=littleendian;

type Msg_ACK(header: Msg_Header) = record {
    version       : uint32;
    rcv_buf_size  : uint32;
    snd_buf_size  : uint32;
    max_msg_size  : uint32;
    max_chunk_cnt : uint32;
} &let {
    deliver: bool = $context.flow.deliver_Msg_ACK(this);
} &byteorder=littleendian;

type Msg_ERR(header: Msg_Header) = record {
    error  : uint32;
    reason : bytestring &restofdata;
} &let {
    deliver: bool = $context.flow.deliver_Msg_ERR(this);
} &byteorder=littleendian;

type Msg_OPN(header: Msg_Header) = record {
    sec_channel_id  : uint32;
    sec_header      : Sec_Header;
    seq_header      : Seq_Header;
    msg_body        : Msg_Body(header);
} &byteorder=littleendian;

type Msg_MSG(header: Msg_Header) = record {
    sec_channel_id : uint32;
    sec_token_id   : uint32;
    seq_header     : Seq_Header;
    msg_body       : Msg_Body(header);
} &byteorder=littleendian;

type Msg_CLO(header: Msg_Header) = record {
    sec_channel_id : uint32;
    sec_token_id   : uint32;
    seq_header     : Seq_Header;
    msg_body       : Msg_Body(header);
} &byteorder=littleendian;

type Sec_Header = record {
    # Security Policy URI
    sec_policy_uri_len : int32;
    sec_policy_uri : bytestring &length = $context.flow.bind_length(sec_policy_uri_len);
 
    # Sender Certificate
    snd_cert_len : int32;
    snd_cert     : bytestring &length =  $context.flow.bind_length(snd_cert_len);

    # Receiver Certificate Thumbprint
    rcv_cert_len : int32;
    rcv_cert     : bytestring &length =  $context.flow.bind_length(rcv_cert_len);

} &byteorder=littleendian, &exportsourcedata;

type Seq_Header = record {
    seq_number : uint32;
    request_id : uint32;
} &byteorder=littleendian;

type Msg_Body(header: Msg_Header) = record {
    encoding_mask : uint8;
    body: case $context.flow.valid_encoding(encoding_mask) of {
       true  -> service  : Service(this);
       false -> encrypted: bytestring &restofdata;
    };
} &let {
    deliver: bool = $context.flow.deliver_Msg_Body(this);
} &byteorder=littleendian;

