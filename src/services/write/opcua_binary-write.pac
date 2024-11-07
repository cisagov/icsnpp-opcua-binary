## opcua_binary-write.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the write service.
##
## Author:   Jason Rush
## Contact:  jason.rush@inl.gov
##
## Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 4 - Services 1.04.pdf - Write Service
#
# 5.10.4.1 - Table 59 - Write Service Parameters
#
type Write_Req(service: Service) = record {
    req_hdr              : Request_Header;

    nodes_to_write_size  : int32;
    nodes_to_write       : OpcUA_WriteValueId[$context.flow.bind_length(nodes_to_write_size)];

} &let {
    deliver: bool = $context.flow.deliver_Svc_WriteReq(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - Write Service
#
# 5.10.4.1 - Table 59 - Read Service Parameters
#
type Write_Res(service: Service) = record {
    res_hdr      : Response_Header;

    results_size : int32;
    results      : OpcUA_StatusCode[$context.flow.bind_length(results_size)];

    diagnostic_info_size : int32;
    diagnostic_info      : OpcUA_DiagInfo[$context.flow.bind_length(diagnostic_info_size)];

} &let {
    deliver: bool = $context.flow.deliver_Svc_WriteRes(this);
} &byteorder=littleendian;

