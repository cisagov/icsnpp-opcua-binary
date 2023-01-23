## opcua_binary-get_endpoints_debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Debug code for processing the get endpoints service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    void printGetEndpointsReq(Get_Endpoints_Req *msg);
    void printGetEndpointsRes(Get_Endpoints_Res *msg);
%}

%code{

    void printGetEndpointsReq(Get_Endpoints_Req *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());
        printReqHdr(msg->req_hdr());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printf("%s EndpointUrl: %s\n", indent(3).c_str(), std_str(msg->endpoint_url()->string()).c_str());

        printf("%s LocaleIds: Array of String\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->locale_id_size());
        for(int i=0; i < msg->locale_id_size(); i++) {
            printf("%s [%d]: LocaleIds: %s\n", indent(4).c_str(), i, std_str(msg->locale_ids()->at(i)->locale_id()).c_str());
        }

        printf("%s ProfileUris: Array of String\n", indent(3).c_str());
        printf("%s ArraySize: %d\n", indent(4).c_str(), msg->profile_uri_size());
        for(int i=0; i < msg->profile_uri_size(); i++) {
            printf("%s [%d]: ProfileUris: %s\n", indent(4).c_str(), i, std_str(msg->profile_uris()->at(i)->string()).c_str());
        }

        return;
    }

    void printGetEndpointsRes(Get_Endpoints_Res *msg) {
        printMsgHeader( msg->service()->msg_body()->header());
        printMsgType( msg->service()->msg_body()->header());
        printService(msg->service());
        printResHdr(msg->res_hdr());

        printf("%s %s\n", indent(2).c_str(), NODE_IDENTIFIER_MAP.find(msg->service()->identifier())->second.c_str());
        printf("%s Endpoints: Array of EndointDescription\n", indent(3).c_str());
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
    }
%}