## opcua_binary-call.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the call service.
##
## Author:   John B Joseph
##

#
# UA Specification Part 4 - Services 1.04.pdf - Call Service (Method Service Set)
#
# Call Service Parameters - Request
#
type Call_Req(service: Service) = record {
    req_hdr              : Request_Header;

    methods_to_call_size : int32;
    methods_to_call      : OpcUA_CallMethodRequest[$context.flow.bind_length(methods_to_call_size)];

} &let {
    deliver: bool = $context.flow.deliver_Svc_CallReq(this);
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf - Call Service (Method Service Set)
#
# Call Service Parameters - Response
#
type Call_Res(service: Service) = record {
    res_hdr      : Response_Header;

    results_size : int32;
    results      : OpcUA_CallMethodResult[$context.flow.bind_length(results_size)];

    diagnostic_info_size : int32;
    diagnostic_info      : OpcUA_DiagInfo(0)[$context.flow.bind_length(diagnostic_info_size)];

} &let {
    deliver: bool = $context.flow.deliver_Svc_CallRes(this);
} &byteorder=littleendian;
