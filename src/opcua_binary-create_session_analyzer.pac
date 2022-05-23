
## opcua_binary-create_sessions_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the get endpoints service.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

refine flow OPCUA_Binary_Flow += {

    #
    # CreateSessionRequest
    #
    function deliver_Svc_CreateSessionReq(msg : Create_Session_Req): bool
        %{
        printf("deliver_Svc_CreateSessionReq - begin\n");
        printCreateSessionReq(msg);
        printf("deliver_Svc_CreateSessionReq - end\n");

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr create_session_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateSession);

        // OpcUA_id
        create_session_req->Assign(CREATE_SESSION_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_ID_IDX));
                                                        
        // Application URI
        if (msg->client_description()->application_uri()->length() > 0) {
            create_session_req->Assign(CREATE_SESSION_REQ_APPLICATION_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_description()->application_uri()->string())));
        } 

        // Product URI
        if (msg->client_description()->product_uri()->length() > 0) {
            create_session_req->Assign(CREATE_SESSION_REQ_PRODUCT_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_description()->product_uri()->string())));
        }

        // Encoding Mask
        create_session_req->Assign(CREATE_SESSION_REQ_ENCODING_MASK_IDX, zeek::val_mgr->Count(msg->client_description()->application_name()->encoding_mask()));
        if (isBitSet(msg->client_description()->application_name()->encoding_mask(), localizedTextHasLocale)) {
            create_session_req->Assign(CREATE_SESSION_REQ_LOCALE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_description()->application_name()->locale()->string())));
        }
        if (isBitSet(msg->client_description()->application_name()->encoding_mask(), localizedTextHasText)) {
            create_session_req->Assign(CREATE_SESSION_REQ_TEXT_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_description()->application_name()->text()->string())));
        }

        // Application Type
        create_session_req->Assign(CREATE_SESSION_REQ_APPLICATON_TYPE_IDX, zeek::val_mgr->Count(msg->client_description()->application_type()));

        // Gateway Server URI
        if (msg->client_description()->gateway_server_uri()->length() > 0) {
            create_session_req->Assign(CREATE_SESSION_REQ_GATEWAY_SERVER_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_description()->gateway_server_uri()->string())));
        } 

        // Discovery Profile URI
        if (msg->client_description()->discovery_profile_uri()->length() > 0) {
            create_session_req->Assign(CREATE_SESSION_REQ_DISCOVERY_PROFILE_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_description()->discovery_profile_uri()->string())));
        } 

        // Discovery Urls
        if (msg->client_description()->discovery_urls_size() > 0) {

            // Discovery Profile Id into the CreateSessionDiscovery log
            string discovery_profile_id = generateId();
            create_session_req->Assign(CREATE_SESSION_REQ_DISCOVERY_PROFILE_ID_IDX, zeek::make_intrusive<zeek::StringVal>(discovery_profile_id));

            for (int32_t j = 0; j < msg->client_description()->discovery_urls_size(); j++) {
                zeek::RecordValPtr create_session_discovery = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateSessionDiscovery);

                // Discovery Profile Id back into the CreateSession log
                create_session_discovery->Assign(CREATE_SESSION_DISCOVERY_PROFILE_ID_LINK_IDX,  zeek::make_intrusive<zeek::StringVal>(discovery_profile_id));

                create_session_discovery->Assign(CREATE_SESSION_DISCOVERY_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_description()->discovery_profile_uri()->string())));
                create_session_discovery->Assign(CREATE_SESSION_DISCOVORY_URL_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_description()->discovery_urls()->at(j)->string())));

                // Create Session Discovery Event
                zeek::BifEvent::enqueue_opcua_binary_create_session_discovery_event(connection()->bro_analyzer(),
                                                                                    connection()->bro_analyzer()->Conn(),
                                                                                    create_session_discovery);
            }
        }

        // Server URI
        if (msg->server_uri()->length() > 0) {
            create_session_req->Assign(CREATE_SESSION_REQ_SERVER_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->server_uri()->string())));
        } 

        // Endpoint URL
        if (msg->endpoint_url()->length() > 0) {
            create_session_req->Assign(CREATE_SESSION_REQ_ENDPOINT_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoint_url()->string())));
        } 

        // Session Name
        if (msg->session_name()->length() > 0) {
            create_session_req->Assign(CREATE_SESSION_REQ_SESSION_NAME_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->session_name()->string())));
        }

        // Client Nonce
        if (msg->client_nonce()->length() > 0) {
            create_session_req->Assign(CREATE_SESSION_REQ_CLIENT_NONCE_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->client_nonce()->byteString())));
        }

        // Client Certificate
        if (msg->client_cert()->cert_size() > 0) {
            create_session_req->Assign(CREATE_SESSION_REQ_CLIENT_CERT_SIZE_IDX, zeek::val_mgr->Count(msg->client_cert()->cert_size()));
            create_session_req->Assign(CREATE_SESSION_REQ_CLIENT_CERT_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->client_cert()->cert())));
        }

        // Requested Session Timeout
        create_session_req->Assign(CREATE_SESSION_REQ_SESSION_TIMEOUT_IDX, zeek::make_intrusive<zeek::TimeVal>(bytestringToDouble(msg->req_session_timeout()->duration())));

        // Max Response Message Size
        create_session_req->Assign(CREATE_SESSION_REQ_MAX_RES_MSG_SIZE_IDX, zeek::val_mgr->Count(msg->max_res_msg_size()));

        // Create Session Event
        zeek::BifEvent::enqueue_opcua_binary_create_session_event(connection()->bro_analyzer(),
                                                                  connection()->bro_analyzer()->Conn(),
                                                                  create_session_req);

        return true;
        %}

    #
    # CreateSessionResponse
    #
    function deliver_Svc_CreateSessionRes(msg : Create_Session_Res): bool
        %{
        printf("deliver_Svc_CreateSessionRes - begin\n");
        printCreateSessionRes(msg);
        printf("deliver_Svc_CreateSessionRes - end\n");

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr create_session_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateSession);

        // OpcUA_id
        create_session_res->Assign(CREATE_SESSION_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_ID_IDX));

        // Session Id
        create_session_res->Assign(CREATE_SESSION_ID_ENCODING_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(msg->session_id()->identifier_type())));
        switch (msg->session_id()->identifier_type()) {
            case node_encoding::TwoByte : create_session_res->Assign(REQ_HDR_NODE_ID_NUMERIC_IDX, zeek::val_mgr->Count(msg->session_id()->two_byte_numeric()->numeric()));
                                          break;
            case node_encoding::FourByte :
                                        create_session_res->Assign(CREATE_SESSION_ID_NAMESPACE_IDX, zeek::val_mgr->Count(msg->session_id()->four_byte_numeric()->namespace_index()));
                                        create_session_res->Assign(CREATE_SESSION_ID_NUMERIC_IDX, zeek::val_mgr->Count(msg->session_id()->four_byte_numeric()->numeric()));
                                        break;
            case node_encoding::Numeric :
                                        create_session_res->Assign(CREATE_SESSION_ID_NAMESPACE_IDX, zeek::val_mgr->Count(msg->session_id()->numeric()->namespace_index()));
                                        create_session_res->Assign(CREATE_SESSION_ID_NUMERIC_IDX, zeek::val_mgr->Count(msg->session_id()->numeric()->numeric()));
                                        break;
            case node_encoding::String :
                                        create_session_res->Assign(CREATE_SESSION_ID_NAMESPACE_IDX, zeek::val_mgr->Count(msg->session_id()->string()->namespace_index()));
                                        create_session_res->Assign(CREATE_SESSION_ID_STRING_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->session_id()->string()->string()->string())));
                                        break;
            case node_encoding::GUID :
                                        create_session_res->Assign(CREATE_SESSION_ID_NAMESPACE_IDX, zeek::val_mgr->Count(msg->session_id()->guid()->namespace_index()));
                                        create_session_res->Assign(CREATE_SESSION_ID_GUID_IDX, zeek::make_intrusive<zeek::StringVal>(guidToGuidstring(msg->session_id()->guid()->guid()->data1(),
                                                                                                                                                      msg->session_id()->guid()->guid()->data2(),
                                                                                                                                                      msg->session_id()->guid()->guid()->data3(),
                                                                                                                                                      msg->session_id()->guid()->guid()->data4())));
                                        break;
            case node_encoding::Opaque :
                                        create_session_res->Assign(CREATE_SESSION_ID_NAMESPACE_IDX, zeek::val_mgr->Count(msg->session_id()->opaque()->namespace_index()));
                                        create_session_res->Assign(CREATE_SESSION_ID_OPAQUE_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->session_id()->opaque()->opaque()->byteString())));
                                        break;
        }

        // Authentication Token
        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_ENCODING_MASK_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(msg->auth_token()->identifier_type())));
        switch (msg->auth_token()->identifier_type()) {
            case node_encoding::TwoByte : create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_NUMERIC_IDX, zeek::val_mgr->Count(msg->auth_token()->two_byte_numeric()->numeric()));
                                          break;
            case node_encoding::FourByte :
                                        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_NAMESPACE_IDX, zeek::val_mgr->Count(msg->auth_token()->four_byte_numeric()->namespace_index()));
                                        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_NUMERIC_IDX, zeek::val_mgr->Count(msg->auth_token()->four_byte_numeric()->numeric()));
                                        break;
            case node_encoding::Numeric :
                                        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_NAMESPACE_IDX, zeek::val_mgr->Count(msg->auth_token()->numeric()->namespace_index()));
                                        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_NUMERIC_IDX, zeek::val_mgr->Count(msg->auth_token()->numeric()->numeric()));
                                        break;
            case node_encoding::String :
                                        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_NAMESPACE_IDX, zeek::val_mgr->Count(msg->auth_token()->string()->namespace_index()));
                                        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_STRING_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->auth_token()->string()->string()->string())));
                                        break;
            case node_encoding::GUID :
                                        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_NAMESPACE_IDX, zeek::val_mgr->Count(msg->auth_token()->guid()->namespace_index()));
                                        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_GUID_IDX, zeek::make_intrusive<zeek::StringVal>(guidToGuidstring(msg->auth_token()->guid()->guid()->data1(),
                                                                                                                                                              msg->auth_token()->guid()->guid()->data2(),
                                                                                                                                                              msg->auth_token()->guid()->guid()->data3(),
                                                                                                                                                              msg->auth_token()->guid()->guid()->data4())));
                                        break;
            case node_encoding::Opaque :
                                        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_NAMESPACE_IDX, zeek::val_mgr->Count(msg->auth_token()->opaque()->namespace_index()));
                                        create_session_res->Assign(CREATE_SESSION_AUTH_TOKEN_OPAQUE_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->auth_token()->opaque()->opaque()->byteString())));
                                        break;
        }

        // Revised Session Timeout
        create_session_res->Assign(CREATE_SESSION_RES_REVISED_SESSION_TIMEOUT_IDX, zeek::make_intrusive<zeek::TimeVal>(bytestringToDouble(msg->revised_session_timeout()->duration())));

        // Server Nonce
        if (msg->server_nonce()->length() > 0) {
            create_session_res->Assign(CREATE_SESSION_RES_SERVER_NONCE_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->server_nonce()->byteString())));
        }

        // Server Certificate
        if (msg->server_cert()->cert_size() > 0) {
            create_session_res->Assign(CREATE_SESSION_RES_SERVER_CERT_SIZE_IDX, zeek::val_mgr->Count(msg->server_cert()->cert_size()));
            create_session_res->Assign(CREATE_SESSION_RES_SERVER_CERT_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->server_cert()->cert())));
        }

        // Server Endpoint Id into CreateSessionEndpoints log
        std::string endpoint_idx = generateId();
        create_session_res->Assign(CREATE_SESSION_RES_ENDPOINT_ID_IDX, zeek::make_intrusive<zeek::StringVal>(endpoint_idx));

        // Server Endpoints
        for (int32_t i = 0; i < msg->endpoints_size(); i++) {
            zeek::RecordValPtr endpoint_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateSessionEndpoints);

            // Endpoint id link back into CreateSession Response
            endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_ID_LINK_IDX, zeek::make_intrusive<zeek::StringVal>(endpoint_idx));

            // Endpoint URL
            if (msg->endpoints()->at(i)->endpoint_uri()->length() > 0) {
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_URL_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->endpoint_uri()->string())));
            }

            // Application URI
            if (msg->endpoints()->at(i)->server()->application_uri()->length() > 0) {
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_APPLICATION_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->application_uri()->string())));
            }

            // Product URI
            if (msg->endpoints()->at(i)->server()->product_uri()->length() > 0) {
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_PRODUCT_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->product_uri()->string())));
            }

            // Encoding Mask
            endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_ENCODING_MASK_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->server()->application_name()->encoding_mask()));

            // Locale Encoding
            if (isBitSet(msg->endpoints()->at(i)->server()->application_name()->encoding_mask(), localizedTextHasLocale)) {
                if (msg->endpoints()->at(i)->server()->application_name()->locale()->length() > 0) {
                    endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_LOCALE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->application_name()->locale()->string())));
                }
            }

            // Text Encoding
            if (isBitSet(msg->endpoints()->at(i)->server()->application_name()->encoding_mask(), localizedTextHasText)) {
                if (msg->endpoints()->at(i)->server()->application_name()->text()->length()) {
                    endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_TEXT_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->application_name()->text()->string())));
                }
            }

            // Application Type
            endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_APPLICATION_TYPE_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->server()->application_type()));

            // Gateway Server URI
            if (msg->endpoints()->at(i)->server()->gateway_server_uri()->length() > 0) {
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_GATEWAY_SERVER_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->gateway_server_uri()->string())));
            }

            // Discovery Profile URI
            if (msg->endpoints()->at(i)->server()->discovery_profile_uri()->length() > 0) {
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_DISCOVERY_PROFILE_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->discovery_profile_uri()->string())));
            }

            // Discovery Profile
            if (msg->endpoints()->at(i)->server()->discovery_urls_size() > 0) {

                // Discovery Profile Id into the CreateSessionDiscovery log
                string discovery_profile_id = generateId();
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_DISCOVERY_PROFILE_ID_IDX, zeek::make_intrusive<zeek::StringVal>(discovery_profile_id));

                for (int32_t j = 0; j < msg->endpoints()->at(i)->server()->discovery_urls_size(); j++) {
                    zeek::RecordValPtr endpoint_discovery_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateSessionDiscovery);

                    // Discovery Profile Id back into the CreateSessionEndpoints log
                    endpoint_discovery_res->Assign(CREATE_SESSION_DISCOVERY_PROFILE_ID_LINK_IDX,  zeek::make_intrusive<zeek::StringVal>(discovery_profile_id));

                    endpoint_discovery_res->Assign(CREATE_SESSION_DISCOVERY_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->discovery_profile_uri()->string())));
                    endpoint_discovery_res->Assign(CREATE_SESSION_DISCOVORY_URL_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->discovery_urls()->at(j)->string())));

                    zeek::BifEvent::enqueue_opcua_binary_create_session_discovery_event(connection()->bro_analyzer(),
                                                                                        connection()->bro_analyzer()->Conn(),
                                                                                        endpoint_discovery_res);
                }
            }

            // Server Certificate
            if (msg->endpoints()->at(i)->server_cert()->cert_size() > 0) {
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_CERT_SIZE_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->server_cert()->cert_size()));
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_SERVER_CERT_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->endpoints()->at(i)->server_cert()->cert())));
            }

            // Message Security Mode
            endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_MSG_SECURITY_MODE_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->security_mode()));

            // Security Policy URI
            if (msg->endpoints()->at(i)->security_policy_uri()->length() > 0) {
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_SECURITY_POLICY_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->security_policy_uri()->string())));
            }

            // User Token
            if ( msg->endpoints()->at(i)->user_identity_tokens_size() > 0)
            {
                // User Token Id into the CreateSessionUserToken log
                string user_token_id = generateId();
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_USER_TOKEN_ID_IDX, zeek::make_intrusive<zeek::StringVal>(user_token_id));

                for (int32_t k = 0; k < msg->endpoints()->at(i)->user_identity_tokens_size(); k++) {
                    zeek::RecordValPtr endpoint_user_token_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::CreateSessionUserToken);

                    // User Token Id back into the CreateSessionEndpoints log
                    endpoint_user_token_res->Assign(CREATE_SESSION_RES_USER_TOKEN_ID_LINK_IDX, zeek::make_intrusive<zeek::StringVal>(user_token_id));

                    endpoint_user_token_res->Assign(CREATE_SESSION_RES_USER_TOKEN_POLICY_ID_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->policy_id()->string())));
                    endpoint_user_token_res->Assign(CREATE_SESSION_RES_USER_TOKEN_TYPE_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->token_type()));

                    if (msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issued_token_type()->length() > 0) {
                        endpoint_user_token_res->Assign(CREATE_SESSION_RES_USER_TOKEN_ISSUED_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issued_token_type()->string())));
                    }

                    if (msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issuer_endpoint_url()->length() > 0) {
                        endpoint_user_token_res->Assign(CREATE_SESSION_RES_USER_TOKEN_ENDPOINT_URL_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issuer_endpoint_url()->string())));
                    }

                    if (msg->endpoints()->at(i)->user_identity_tokens()->at(k)->security_policy_uri()->length() > 0) {
                        endpoint_user_token_res->Assign(CREATE_SESSION_RES_USER_TOKEN_SECURITY_POLICY_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->security_policy_uri()->string())));
                    }

                    zeek::BifEvent::enqueue_opcua_binary_create_session_user_token_event(connection()->bro_analyzer(),
                                                                                         connection()->bro_analyzer()->Conn(),
                                                                                         endpoint_user_token_res);
                }
            }

            // Transport Profile URI
            if (msg->endpoints()->at(i)->transport_profile_uri()->length() > 0) {
                endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_TRANSPORT_PROFILE_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->transport_profile_uri()->string())));
            }

            // Security Level
            endpoint_res->Assign(CREATE_SESSION_RES_ENDPOINT_SECURITY_LEVEL_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->security_level()));

            zeek::BifEvent::enqueue_opcua_binary_create_session_endpoints_event(connection()->bro_analyzer(),
                                                                                connection()->bro_analyzer()->Conn(),
                                                                                endpoint_res);
        }

        // 
        // From Table 15 - CreateSession Service Parameters: Response
        // 
        // Description: serverSoftwareCertificates:
        // 
        // This parameter is deprecated and the array shall be empty.  Note: Based on sample
        // packet capture data, the server_software_cert_size is present, but always set to -1 
        // No logging will be done for these parameters.
        //  
        // server_software_cert_size : int32;
        // server_software_cert    : SignedSoftwareCertificate
        //

        // Server Algorithm
        if (msg->server_signature()->algorithm()->length() > 0) {
            create_session_res->Assign(CREATE_SESSION_RES_ALGORITHM_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->server_signature()->algorithm()->string())));
        } 

        // Server Signature 
        if (msg->server_signature()->signature()->length() > 0) {
            create_session_res->Assign(CREATE_SESSION_RES_SIGNATURE_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->server_signature()->signature()->byteString())));
        }

        // Max Request Message Size
        create_session_res->Assign(CREATE_SESSION_RES_MAX_REQ_MSG_SIZE_IDX, zeek::val_mgr->Count(msg->max_req_msg_size()));

        zeek::BifEvent::enqueue_opcua_binary_create_session_event(connection()->bro_analyzer(),
                                                                  connection()->bro_analyzer()->Conn(),
                                                                  create_session_res);

        return true;
    %}
};
