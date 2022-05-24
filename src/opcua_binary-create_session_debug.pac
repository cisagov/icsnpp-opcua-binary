## opcua_binary-create_sessions_debug.pac
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
    void printCreateSessionReq(Create_Session_Req *msg);
    void printCreateSessionRes(Create_Session_Res *msg);
%}

%code{

    void printCreateSessionReq(Create_Session_Req *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printReqHdr(msg->req_hdr());
        printf("%s ClientDescription: ApplicationDescription\n", indent(3).c_str());

        if (msg->client_description()->application_uri()->length() > 0) {
            printf("%s ApplicationUri: %s\n", indent(4).c_str(), std_str(msg->client_description()->application_uri()->string()).c_str());
        } else {
            printf("%s ApplicationUri: [OpcUa Null String]\n", indent(4).c_str());
        }

        if (msg->client_description()->product_uri()->length() > 0) {
            printf("%s ProductUri: %s\n", indent(4).c_str(), std_str(msg->client_description()->product_uri()->string()).c_str());
        } else {
            printf("%s ProductUri: [OpcUa Null String]\n", indent(4).c_str());
        }

        printf("%s ApplicationName: LocalizedText\n", indent(4).c_str());

        printf("%s EncodingMask: 0x%x\n", indent(5).c_str(), msg->client_description()->application_name()->encoding_mask());
        if (isBitSet(msg->client_description()->application_name()->encoding_mask(), localizedTextHasLocale)) {
            printf("%s Locale: %s\n", indent(5).c_str(), std_str(msg->client_description()->application_name()->locale()->string()).c_str());
        }

        if (isBitSet(msg->client_description()->application_name()->encoding_mask(), localizedTextHasText)) {
            printf("%s Text: %s\n", indent(5).c_str(), std_str(msg->client_description()->application_name()->text()->string()).c_str());
        }

        printf("%s ApplicationType: 0x%08x\n", indent(4).c_str(), msg->client_description()->application_type());

        if (msg->client_description()->gateway_server_uri()->length() > 0) {
            printf("%s GatewayServerUri: %s\n", indent(4).c_str(), std_str(msg->client_description()->gateway_server_uri()->string()).c_str());
        } else {
            printf("%s GatewayServerUri: [OpcUa Null String]\n", indent(4).c_str());
        }

        if (msg->client_description()->discovery_profile_uri()->length() > 0) {
            printf("%s DiscoveryProfileUri: %s\n", indent(4).c_str(), std_str(msg->client_description()->discovery_profile_uri()->string()).c_str());
        } else {
            printf("%s DiscoveryProfileUri: [OpcUa Null String]\n", indent(4).c_str());
        }

        printf("%s DiscoveryUrls: Array of String\n", indent(4).c_str());
        printf("%s ArraySize: %d\n", indent(5).c_str(), msg->client_description()->discovery_urls_size());
        for (int32_t j = 0; j < msg->client_description()->discovery_urls_size(); j++) {
            printf("%s [%d]: %s\n", indent(5).c_str(), j, std_str(msg->client_description()->discovery_urls()->at(j)->string()).c_str());
        }

        if (msg->server_uri()->length() > 0) {
            printf("%s ServerUri: %s\n", indent(4).c_str(), std_str(msg->server_uri()->string()).c_str());
        } else {
            printf("%s ServerUri: [OpcUa Null String]\n", indent(4).c_str());
        }

        if (msg->endpoint_url()->length() > 0) {
            printf("%s EndpointUrl: %s\n", indent(4).c_str(), std_str(msg->endpoint_url()->string()).c_str());
        } else {
            printf("%s EndpointUrl: [OpcUa Null String]\n", indent(4).c_str());
        }

        if (msg->session_name()->length() > 0) {
            printf("%s SessionName: %s\n", indent(4).c_str(), std_str(msg->session_name()->string()).c_str());
        } else {
            printf("%s SessionName: [OpcUa Null String]\n", indent(4).c_str());
        }

        if (msg->client_nonce()->length() > 0) {
            printf("%s ClientNonce: %s\n", indent(4).c_str(), bytestringToHexstring(msg->client_nonce()->byteString()).c_str());
        } else {
            printf("%s ClientNonce: [OpcUa Null ByteString]\n", indent(4).c_str());
        }

        if (msg->client_cert()->cert_size() > 0) {
            printf("%s CertificateSize: %d (0x%04x)\n", indent(4).c_str(), msg->client_cert()->cert_size(), msg->client_cert()->cert_size());
            printf("%s ClientCertificate: %s\n", indent(4).c_str(), bytestringToHexstring(msg->client_cert()->cert()).c_str());
        } else {
            printf("%s ClientCertificate: <MISSING>[OpcUa Null String]\n", indent(4).c_str());
        }

        printf("%s RequestedSessionTimeout: %f\n", indent(4).c_str(), bytestringToDouble(msg->req_session_timeout()->duration()));
        printf("%s MaxResponseMessageSize: %d\n", indent(4).c_str(), msg->max_res_msg_size());

        return;
    }

    void printCreateSessionRes(Create_Session_Res *msg) {

        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printResHdr(msg->res_hdr());

        printf("%s SessionId: NodeId\n", indent(3).c_str());
        printOpcUaNodeId(4, msg->session_id());

        printf("%s AuthenticationToken: NodeId\n", indent(3).c_str());
        printOpcUaNodeId(4, msg->auth_token());

        printf("%s RevisedSessionTimeout: %f\n", indent(3).c_str(), bytestringToDouble(msg->revised_session_timeout()->duration()));

        // Server Nonce
        if (msg->server_nonce()->length() > 0) {
            printf("%s ServerNonce: %s\n", indent(3).c_str(), bytestringToHexstring(msg->server_nonce()->byteString()).c_str());
        } else {
            printf("%s ServerNonce: [OpcUa Null ByteString]\n", indent(3).c_str());
        }

        // Server Certificate
        if (msg->server_cert()->cert_size() > 0) {
            printf("%s CertificateSize: %d (0x%04x)\n", indent(3).c_str(), msg->server_cert()->cert_size(), msg->server_cert()->cert_size());
            printf("%s ServerCertificate: %s\n", indent(3).c_str(), bytestringToHexstring(msg->server_cert()->cert()).c_str());
        } else {
            printf("%s ServerCertificate: <MISSING>[OpcUa Null String]\n", indent(3).c_str());
        }

        // Endpoints
        printf("%s ServerEndpoints: Array of EndpointDescription\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->endpoints_size());

        for (int32_t i = 0; i < msg->endpoints_size(); i++) {

            printf("%s [%d]: EndpointDescription\n", indent(4).c_str(), i);
            printf("%s EndpointUrl: %s\n", indent(5).c_str(), std_str(msg->endpoints()->at(i)->endpoint_uri()->string()).c_str());

            printf("%s Server: ApplicationDescription\n", indent(5).c_str());
            printf("%s ApplicationUri: %s\n", indent(6).c_str(), std_str(msg->endpoints()->at(i)->server()->application_uri()->string()).c_str());
            printf("%s ProductUri: %s\n", indent(6).c_str(), std_str(msg->endpoints()->at(i)->server()->product_uri()->string()).c_str());

            printf("%s ApplicationName: LocalizedText\n", indent(6).c_str());

            printf("%s EncodingMask: 0x%x\n", indent(7).c_str(), msg->endpoints()->at(i)->server()->application_name()->encoding_mask());
            if (isBitSet(msg->endpoints()->at(i)->server()->application_name()->encoding_mask(), localizedTextHasLocale)) {
                printf("%s Locale: %s\n", indent(7).c_str(), std_str(msg->endpoints()->at(i)->server()->application_name()->locale()->string()).c_str());
            }

            if (isBitSet(msg->endpoints()->at(i)->server()->application_name()->encoding_mask(), localizedTextHasText)) {
                printf("%s Text: %s\n", indent(7).c_str(), std_str(msg->endpoints()->at(i)->server()->application_name()->text()->string()).c_str());
            }

            printf("%s ApplicationType: 0x%04x\n", indent(6).c_str(), msg->endpoints()->at(i)->server()->application_type());

            if (msg->endpoints()->at(i)->server()->gateway_server_uri()->length() > 0) {
                printf("%s GatewayServerUri: %s\n", indent(6).c_str(), std_str(msg->endpoints()->at(i)->server()->gateway_server_uri()->string()).c_str());
            } else {
                printf("%s GatewayServerUri: [OpcUa Null String]\n", indent(6).c_str());
            }

            if (msg->endpoints()->at(i)->server()->discovery_profile_uri()->length() > 0) {
                printf("%s DiscoveryProfileUri: %s\n", indent(6).c_str(), std_str(msg->endpoints()->at(i)->server()->discovery_profile_uri()->string()).c_str());
            } else {
                printf("%s DiscoveryProfileUri: [OpcUa Null String]\n", indent(6).c_str());

            }

            printf("%s DiscoveryUrls: Array of String\n", indent(6).c_str());
            printf("%s ArraySize: %d\n", indent(7).c_str(), msg->endpoints()->at(i)->server()->discovery_urls_size());
            for (int32_t j = 0; j < msg->endpoints()->at(i)->server()->discovery_urls_size(); j++) {
                printf("%s [%d]: %s\n", indent(7).c_str(), j, std_str(msg->endpoints()->at(i)->server()->discovery_urls()->at(j)->string()).c_str());
            }

            if (msg->endpoints()->at(i)->server_cert()->cert_size() > 0) {
                printf("%s CertificateSize: %d (0x%04x)\n", indent(5).c_str(), msg->endpoints()->at(i)->server_cert()->cert_size(), msg->endpoints()->at(i)->server_cert()->cert_size());
                printf("%s ServerCertificate: %s\n", indent(5).c_str(), bytestringToHexstring(msg->endpoints()->at(i)->server_cert()->cert()).c_str());
            } else {
                printf("%s ServerCertificate: <MISSING>[OpcUa Null String]\n", indent(5).c_str());
            }

            printf("%s MessageSecurityMode: %d\n", indent(5).c_str(), msg->endpoints()->at(i)->security_mode());
            printf("%s SecurityPolicyUri: %s\n", indent(5).c_str(), std_str(msg->endpoints()->at(i)->security_policy_uri()->string()).c_str());

            printf("%s UserIdentityTokens: Array of UserTokenPolicy\n", indent(5).c_str());
            printf("%s ArraySize: %d\n", indent(6).c_str(), msg->endpoints()->at(i)->user_identity_tokens_size());
            for (int32_t k = 0; k < msg->endpoints()->at(i)->user_identity_tokens_size(); k++) {
                printf("%s [%d]: UserTokenPolicy\n", indent(7).c_str(), k);
                printf("%s PolicyId: %s\n", indent(8).c_str(), std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->policy_id()->string()).c_str());
                printf("%s UserTokenType: %d\n", indent(8).c_str(), msg->endpoints()->at(i)->user_identity_tokens()->at(k)->token_type());

                if (msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issued_token_type()->length() > 0) {
                    printf("%s IssuedTokenType:   %s\n", indent(8).c_str(), std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issued_token_type()->string()).c_str());
                } else {
                    printf("%s IssuedTokenType: [OpcUa Null String]\n", indent(8).c_str());
                }

                if (msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issuer_endpoint_url()->length() > 0) {
                    printf("%s IssuerEndpointUrl: %s\n", indent(8).c_str(), std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issuer_endpoint_url()->string()).c_str());
                } else {
                    printf("%s IssuerEndpointUrl: [OpcUa Null String]\n", indent(8).c_str());
                }

                if (msg->endpoints()->at(i)->user_identity_tokens()->at(k)->security_policy_uri()->length() > 0) {
                    printf("%s SecurityPolicyUri: %s\n", indent(8).c_str(), std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->security_policy_uri()->string()).c_str());
                } else {
                    printf("%s SecurityPolicyUri: [OpcUa Null String]\n", indent(8).c_str());
                }
            }

            printf("%s TransportProfileUri: %s\n", indent(5).c_str(), std_str(msg->endpoints()->at(i)->transport_profile_uri()->string()).c_str());
            printf("%s SecurityLevel: %d\n", indent(5).c_str(), msg->endpoints()->at(i)->security_level());

        }

        // Server Software Certificates
        // 
        // From Table 15 - CreateSession Service Parameters: Response
        //
        // Description: serverSoftwareCertificates:
        //
        // This parameter is deprecated and the array shall be empty.  Note: Based on sample
        // packet capture data, the server_software_cert_size is present, but always set to -1 
        // 
        printf("%s ServerSoftwareCertificates: Array of SignedSoftwareCertifcate\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->server_software_cert_size());

        // Server Signature
        printf("%s ServerSignature: SignatureData\n", indent(3).c_str());
        if (msg->server_signature()->algorithm()->length() > 0) {
            printf("%s Algorithm: %s\n", indent(4).c_str(), std_str(msg->server_signature()->algorithm()->string()).c_str());
        } else {
            printf("%s Algorithm: [OpcUa Null String]\n", indent(4).c_str());
        }

        if (msg->server_signature()->signature()->length() > 0) {
            printf("%s Signature: %s\n", indent(4).c_str(), bytestringToHexstring(msg->server_signature()->signature()->byteString()).c_str());
        } else {
            printf("%s Signature: [OpcUa Null ByteString]\n", indent(4).c_str());
        }

        printf("%s MaxRequestMessageSize: %d\n", indent(3).c_str(), msg->max_req_msg_size());
    }
%}