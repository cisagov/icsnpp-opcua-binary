## opcua_binary-service_fault.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the service fault.
##
## Author:   Jason Rush
## Contact:  jason.rush@inl.gov
##
## Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 4 - Services 1.04.pdf - ServiceFault
#
# 7.30 - Table 172 - ServiceFault Parameters
type Service_Fault_Res(service: Service) = record {
    res_hdr      : Response_Header;
} &let {
    deliver: bool = $context.flow.deliver_Svc_ServiceFaultRes(this);
} &byteorder=littleendian;