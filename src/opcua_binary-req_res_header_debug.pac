## opcua_binary-req_res_header_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for verifying the request and response headers.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.


%header{
    void printReqHdr(Request_Header *req_hdr);
    void printResHdr(Response_Header *res_hdr);
%}

%code{

   void printReqHdr(Request_Header *req_hdr) {
       // Stubbed out 
       return;
   }
 
   void printResHdr(Response_Header *res_hdr) {
       // Stubbed out 
       return;
   }
 
%}