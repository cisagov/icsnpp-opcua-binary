## opcua_binary-read.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the read service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 4 - Services 1.04.pdf - Read Service
#
# 5.10.2.2 - Table 53 - Read Service Parameters
#
type Read_Req(service: Service) = record {
    req_hdr              : Request_Header;

    max_age              : OpcUA_Duration;
    timestamps_to_return : uint32;
    nodes_to_read_size   : int32;
    nodes_to_read        : OpcUA_ReadValueId[$context.flow.bind_length(nodes_to_read_size)];

} &let {
    deliver: bool = $context.flow.deliver_Svc_ReadReq(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - Read Service
#
# 5.10.2.2 - Table 53 - Read Service Parameters
#
type Read_Res(service: Service) = record {
    res_hdr      : Response_Header;

    results_size : int32;
    results      : OpcUA_DataValue[$context.flow.bind_length(results_size)];

    diagnostic_info_size : int32;
    diagnostic_info      : OpcUA_DiagInfo[$context.flow.bind_length(diagnostic_info_size)];

} &let {
    deliver: bool = $context.flow.deliver_Svc_ReadRes(this);
} &byteorder=littleendian;

