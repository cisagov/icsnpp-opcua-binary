## opcua_binary-read_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing the read service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printReadReq(Read_Req *msg);
    void printReadRes(Read_Res *msg);
%}

%code{

    void printReadReq(Read_Req *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());

/*
        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printReqHdr(msg->req_hdr());

        // Client Signature
        printOpcUA_SignatureData(3, "ClientSignature", msg->client_signature());

        // Client Software Cert
        printf("%s ClientSoftwareCertificates: Array of SignedSoftwareCertificate\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->client_software_size());
        printOpcUA_SignedSoftwareCertificateVec(3, msg->client_software_cert());

        // Locale Id
        printf("%s LocaleIds: Array of String\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(),  msg->locale_id_size());
        printOpcUA_LocaleIdVec(3, msg->locale_id());

        // User Identity Token
        printf("%s UserIdentityToken: ExtensionObject\n", indent(3).c_str());
        printOpcUA_ExtensionObject(3, msg->user_identity_token());
        
        // User Token Signature
        printOpcUA_SignatureData(3, "UserTokenSignature", msg->user_token_signature());
*/

    }

    void printReadRes(Read_Res *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printResHdr(msg->res_hdr());

        // Array of DataValue(s)
        printf("%s Results: Array of DataValue\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->results_size());
        for (int i = 0; i < msg->results_size(); i++) {
            printf("%s [%d]: DataValue\n", indent(4).c_str(), i);
            printOpcUA_DataValue(5, msg->results()->at(i));
        }

        // Array of DiagnosticInfo(s)
        printf("%s DiagnosticInfos: Array of DiagnosticInfo\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->diagnostic_info_size());
        for (int i = 0; i < msg->diagnostic_info_size(); i++) {
            printf("%s [%d]: DiagnosticInfo\n", indent(4).c_str(), i);
            printOpcUA_DiagInfo(5, msg->diagnostic_info()->at(i));
        }

    }
%}