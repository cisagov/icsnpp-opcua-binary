## opcua_binary-activate_sessions.pac
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
# UA Specification Part 4 - Services 1.04.pdf - ActivateSession Service
#
# 5.6.3.2 - Table 17 - ActivateSession Service Parameters
#
type Activate_Session_Req(service: Service) = record {
    req_hdr           : Request_Header;
    client_signature  : OpcUA_SignatureData;

    client_software_size : int32;
    client_software_cert : OpcUA_SignedSoftwareCertificate[$context.flow.bind_length(client_software_size)];

    locale_id_size : int32;
    locale_id : OpcUA_LocaleId[$context.flow.bind_length(locale_id_size)];

    user_identity_token : OpcUA_ExtensionObject;

    user_token_signature : OpcUA_SignatureData;

} &let {
    deliver: bool = $context.flow.deliver_Svc_ActivateSessionReq(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - ActivateSession Service
#
# 5.6.3.2 - Table 17 - ActivateSession Service Parameters
#
type Activate_Session_Res(service: Service) = record {
    res_hdr      : Response_Header;

    server_nonce : OpcUA_ByteString;

    result_size  : int32;
    results      : OpcUA_StatusCode[$context.flow.bind_length(result_size)];

    diagnostic_info_size : int32;
    diagnostic_info      : OpcUA_DiagInfo[$context.flow.bind_length(diagnostic_info_size)];

} &let {
    deliver: bool = $context.flow.deliver_Svc_ActivateSessionRes(this);
} &byteorder=littleendian;

