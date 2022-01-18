## opcua_binary-get_endpoints.pac
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
# 5.4.4.2 - Table 5 - GetEndpoints Service Parameters
#
type Get_Endpoints_Req(service: Service) = record {
    req_hdr          : Request_Header;
    endpoint_url     : OpcUA_String;

    locale_id_size   : int32; # Not documented in UA Specifications; Found in the open62541 source code.
    locale_ids       : OpcUA_String[$context.flow.bind_length(locale_id_size)];

    profile_uri_size : int32; # Not documented in the UA Specifications; Found in the open62541 source code.
    profile_uris     : OpcUA_String[$context.flow.bind_length(profile_uri_size)];
} &let {
    deliver: bool = $context.flow.deliver_Svc_GetEndpointsReq(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - GetEndpoints Service
#
# 5.4.4.2 - Table 5 - GetEndpoints Service Parameters
#
type Get_Endpoints_Res(service: Service) = record {
    res_hdr        : Response_Header;
 
    endpoints_size : int32;
    endpoints      : OpcUA_EndpointDescription[$context.flow.bind_length(endpoints_size)];

} &let {
    deliver: bool = $context.flow.deliver_Svc_GetEndpointsRes(this);
} &byteorder=littleendian;

