## opcua_binary-create_sessions.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the get endpoints service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 4 - Services 1.04.pdf - GetEndpoints Service
#
# 5.6.2.2 - Table 15 - CreateSession Service Parameters
#
type Create_Session_Req(service: Service) = record {
    req_hdr             : Request_Header;
    client_description  : OpcUA_ApplicationDescription; 
    server_uri          : OpcUA_String;
    endpoint_url        : OpcUA_String;
    session_name        : OpcUA_String;
    client_nonce        : OpcUA_ByteString;
    client_cert         : OpcUA_ApplicationInstanceCert;
    req_session_timeout : OpcUA_Duration;
    max_res_msg_size    : uint32;

} &let {
    deliver: bool = $context.flow.deliver_Svc_CreateSessionReq(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - GetEndpoints Service
#
# 5.6.2.2 - Table 15 - CreateSession Service Parameters
#
type Create_Session_Res(service: Service) = record {
    res_hdr    : Response_Header;
    session_id : OpcUA_NodeId;

    # SessionAuthenticationToken: Section 7.31:  0x0000 un-encrypted; Opaque otherwise
    auth_token     : OpcUA_NodeId;

    revised_session_timeout : OpcUA_Duration;

    server_nonce : OpcUA_ByteString;
    server_cert  : OpcUA_ApplicationInstanceCert;
 
    endpoints_size : int32;
    endpoints      : OpcUA_EndpointDescription[$context.flow.bind_length(endpoints_size)];

    #
    # From Table 15 - CreateSession Service Parameters: Response
    #
    # Description: serverSoftwareCertificates:
    #
    # This parameter is deprecated and the array shall be empty.  Note: Based on sample
    # packet capture data, the server_software_cert_size is present, but always set to -1 
    # 
    server_software_cert_size : int32;
    # server_software_cert    : SignedSoftwareCertificate

    server_signature : OpcUA_SignatureData;
    max_req_msg_size : uint32;

} &let {
    deliver: bool = $context.flow.deliver_Svc_CreateSessionRes(this);
} &byteorder=littleendian;

