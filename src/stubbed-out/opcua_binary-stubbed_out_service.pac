## opcua_binary-stubbed_out_service.pac
##
## OPCUA Binary Protocol Analyzer
##
## Placeholder binpac code for processing services that have yet to be implemented.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#
# A generic request used to stub out services and log
# the request header which includes the service identifier.
#
type Stubbed_Out_Req(service: Service) = record {
    req_hdr          : Request_Header;
} &let {
    deliver: bool = $context.flow.deliver_Stubbed_Out_Req(this);
} &byteorder=littleendian;

#
# A generic response used to stub out services and log
# the response header which includes the service identifier.
#
type Stubbed_Out_Res(service: Service) = record {
    res_hdr        : Response_Header;
} &let {
    deliver: bool = $context.flow.deliver_Stubbed_Out_Res(this);
} &byteorder=littleendian;

