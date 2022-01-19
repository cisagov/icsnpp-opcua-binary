## opcua_binary-secure_channel_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the secure channel service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 6 - Mappings 1.04.pdf - OpenSecureChannel Service
#
# 6.7.4 Establishing a SecureChannel - Table 47
#
type Opn_Sec_Chnl_Req(service: Service) = record {
    req_hdr          : Request_Header;
    client_proto_ver : uint32;
    req_type         : OpcUA_SecurityTokenReqType;
    sec_mode         : OpcUA_MessageSecurityMode;
    client_nonce     : OpcUA_ByteString;
    req_lifetime     : uint32;
} &let {
    deliver: bool = $context.flow.deliver_Svc_OpnSecChnlReq(this);
} &byteorder=littleendian;

#
# UA Specification Part 6 - Mappings 1.04.pdf - OpenSecureChannel Service
#
# 6.7.4 Establishing a SecureChannel - Table 47
#
type Opn_Sec_Chnl_Res(service: Service) = record {
    res_hdr           : Response_Header;
    server_proto_ver  : uint32;
    security_token    : OpcUA_ChannelSecurityToken;
    server_nonce      : OpcUA_ByteString;
} &let {
    deliver: bool = $context.flow.deliver_Svc_OpnSecChnlRes(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - CloseSecureChannel
#
# 5.5.3.2 Parameters - Table 13
#
type Clo_Sec_Chnl_Req(service: Service) = record {
    req_hdr          : Request_Header;
} &let {
    deliver: bool = $context.flow.deliver_Svc_CloSecChnlReq(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - CloseSecureChannel
#
# 5.5.3.2 Parameters - Table 13
#
type Clo_Sec_Chnl_Res(service: Service) = record {
    res_hdr          : Response_Header;
} &let {
    deliver: bool = $context.flow.deliver_Svc_CloSecChnlRes(this);
} &byteorder=littleendian;
