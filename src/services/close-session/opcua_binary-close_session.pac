## opcua_binary-close_session.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the get endpoints service.
##
## Author:   Christian Weelborg
## Contact:  christian.weelborg@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 4 - Services 1.04.pdf - CloseSession Service
#
# 5.6.4.2 - Table 19 - CloseSession Service Parameters
#
type Close_Session_Req(service: Service) = record {
    req_hdr             : Request_Header;
    del_subscriptions   : OpcUA_Boolean;
} &let {
    deliver: bool = $context.flow.deliver_Svc_CloseSessionReq(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - CloseSession Service
#
# 5.6.4.2 - Table 19 - CloseSession Service Parameters
#
type Close_Session_Res(service: Service) = record {
    res_hdr     : Response_Header;
} &let {
    deliver: bool = $context.flow.deliver_Svc_CloseSessionRes(this);
} &byteorder=littleendian;
