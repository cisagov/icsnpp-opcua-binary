## opcua_binary-req_res_header_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Binpac code for processing the request and response headers.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#
# UA Specification Part 4 - Services 1.04.pdf
#
# RequestHeader: Table 170
#
type Request_Header = record {
    # SessionAuthenticationToken: Section 7.31:  0x0000 un-encrypted; Opaque otherwise 
    auth_token     : OpcUA_NodeId; 

    timestamp      : OpcUA_DateTime;
    request_handle : OpcUA_IntegerId;
    return_diag    : uint32;
    audit_entry_id : OpcUA_String;
    timeout_hint   : uint32;
    additional_hdr : Additional_Header;
} &byteorder=littleendian;

#
# UA Specification Part 4 - Services 1.04.pdf
#
# ResponseHeader: Table 171
#
type Response_Header = record {
    timestamp      : OpcUA_DateTime;
    request_handle : OpcUA_IntegerId;
    service_result : OpcUA_StatusCode;
    service_diag   : OpcUA_DiagInfo;

    string_table_size : int32;
    has_string_table : case (string_table_size > 0) of {
        true    -> string_table       : OpcUA_String[string_table_size];
        default -> empty_string_table : empty;
    };

    additional_hdr : Additional_Header;
} &byteorder=littleendian;

type Additional_Header = record {
    type_id        : uint16;
    encoding_mask  : uint8; 
} &byteorder=littleendian;

