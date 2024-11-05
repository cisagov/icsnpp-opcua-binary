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

refine flow OPCUA_Binary_Flow += {

    #
    # ServiceFaultResponse
    #
    function deliver_Svc_ServiceFaultRes(msg: Service_Fault_Res): bool
    %{
        // Debug
        printf("deliver_Svc_ServiceFaultRes - begin\n");
        // printServiceFaultRes(msg);
        printf("deliver_Svc_ServiceFaultRes - end\n");

        return true;
    %}
}