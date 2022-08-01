## opcua_binary-activate_sessions_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing the create session service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printActivateSessionReq(Activate_Session_Req *msg);
    void printActivateSessionRes(Activate_Session_Res *msg);
%}

%code{

    void printActivateSessionReq(Activate_Session_Req *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());

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
        printOpcUA_ExtensionObject(3, msg->user_identity_token());
        
        // User Token Signature
        printOpcUA_SignatureData(3, "UserTokenSignature", msg->user_token_signature());

    }

    void printActivateSessionRes(Activate_Session_Res *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printResHdr(msg->res_hdr());

        // Server Nonce
        if (msg->server_nonce()->length() > 0) {
            printf("%s ServerNonce: %s\n", indent(3).c_str(), bytestringToHexstring(msg->server_nonce()->byteString()).c_str());
        } else {
            printf("%s ServerNonce: [OpcUa Null ByteString]\n", indent(3).c_str());
        }

        // Array of StatusCode(s)
        printf("%s Results: Array of StatusCode\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->result_size());
        for (int i = 0; i < msg->result_size(); i++) {
            printf("%s [%d]: Results: 0x%08x [%s]\n", indent(4).c_str(), i, msg->results()->at(i), STATUS_CODE_MAP.find(msg->results()->at(i))->second.c_str());
        }

        // Array of DiagnosticInfo(s)
        printf("%s Results: Array of DiagnosticInfo\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->diagnostic_info_size());
        for (int i = 0; i < msg->diagnostic_info_size(); i++) {
            printf("%s [%d]: DiagnosticInfo\n", indent(4).c_str(), i);
            printOpcUA_DiagInfo(5, msg->diagnostic_info()->at(i));
        }
    }
%}