
## opcua_binary-get_endpoints_analyzer.pac
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
    # GetEndpointsRequest
    #
    function deliver_Svc_GetEndpointsReq(msg : Get_Endpoints_Req): bool
        %{
        //Debug printf("deliver_Svc_GetEndpointsReq - begin\n");
        //Debug printGetEndpointsReq(msg);
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr endpoint_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::GetEndpoints);

        // OpcUA_id
        endpoint_req->Assign(GET_ENDPOINT_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        // Endpoint URL
        endpoint_req->Assign(GET_ENDPOINT_URL_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoint_url()->string())));

        // LocaleId
        if (msg->locale_id_size() > 0) {
            string locale_id = generateId();

            // Link into GetEndpointsLocaleId log
            endpoint_req->Assign(GET_ENDPOINT_REQ_LOCALE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(locale_id));

            for (int i =0; i < msg->locale_id_size(); i++) {
                zeek::RecordValPtr locale_id_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::GetEndpointsLocaleId);

                // Link back into GetEndpoints log
                locale_id_req->Assign(GET_ENDPOINT_REQ_LOCALE_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(locale_id));

                locale_id_req->Assign(GET_ENDPOINT_REQ_LOCALE_ID_STR_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->locale_ids()->at(i)->locale_id())));

                zeek::BifEvent::enqueue_opcua_binary_get_endpoints_locale_id_event(connection()->bro_analyzer(),
                                                                                   connection()->bro_analyzer()->Conn(),
                                                                                   locale_id_req);
            }
        }

        // Profile URI
        if (msg->profile_uri_size() > 0) {
            string profile_uri_id = generateId();

            // Link into GetEndpointsProfileUri log
            endpoint_req->Assign(GET_ENDPOINT_REQ_PROFILE_URI_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(profile_uri_id));

            for (int i =0; i < msg->profile_uri_size(); i++) {
                zeek::RecordValPtr profile_uri_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::GetEndpointsProfileUri);

                // Link back into GetEndpoints log
                profile_uri_req->Assign(GET_ENDPOINT_REQ_PROFILE_URI_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(profile_uri_id));

                profile_uri_req->Assign(GET_ENDPOINT_REQ_PROFILE_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->profile_uris()->at(i)->string())));

                zeek::BifEvent::enqueue_opcua_binary_get_endpoints_profile_uri_event(connection()->bro_analyzer(),
                                                                                     connection()->bro_analyzer()->Conn(),
                                                                                     profile_uri_req);
            }
        }

        zeek::BifEvent::enqueue_opcua_binary_get_endpoints_event(connection()->bro_analyzer(),
                                                                 connection()->bro_analyzer()->Conn(),
                                                                 endpoint_req);

        return true;
        %}

    #
    # GetEndpointsResponse
    #
    function deliver_Svc_GetEndpointsRes(msg : Get_Endpoints_Res): bool
        %{
        //Debug printGetEndpointsRes(msg);

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(connection(), info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr endpoint_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::GetEndpoints);

        // OpcUA_id
        endpoint_res->Assign(GET_ENDPOINT_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));

        if (msg->endpoints_size() > 0) {
            string endpoint_desc_id = generateId();

            // Link into GetEndpointsProfileUri log
            endpoint_res->Assign(GET_ENDPOINT_RES_ENDPOINT_DESCRIPTION_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(endpoint_desc_id));


            for (int32_t i = 0; i < msg->endpoints_size(); i++) {
                zeek::RecordValPtr endpoint_desc = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::GetEndpointsDescription);

                endpoint_desc->Assign(GET_ENDPOINT_RES_ENDPOINT_DESCRIPTION_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(endpoint_desc_id));

                if (msg->endpoints()->at(i)->endpoint_uri()->length() > 0) {
                    endpoint_desc->Assign(GET_ENDPOINT_RES_ENDPOINT_DESCRIPITON_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->endpoint_uri()->string())));
                }

                if (msg->endpoints()->at(i)->server()->application_uri()->length() > 0) {
                    endpoint_desc->Assign(GET_ENDPOINT_RES_APPLICATION_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->application_uri()->string())));
                }

                if (msg->endpoints()->at(i)->server()->product_uri()->length() > 0) {
                    endpoint_desc->Assign(GET_ENDPOINT_RES_PRODUCT_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->product_uri()->string())));
                }

                endpoint_desc->Assign(GET_ENDPOINT_RES_ENCODING_MASK_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->server()->application_name()->encoding_mask()));

                if (isBitSet(msg->endpoints()->at(i)->server()->application_name()->encoding_mask(), localizedTextHasLocale)) {
                    if (msg->endpoints()->at(i)->server()->application_name()->locale()->length() > 0) {
                        endpoint_desc->Assign(GET_ENDPOINT_RES_LOCALE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->application_name()->locale()->string())));
                    }
                }

                if (isBitSet(msg->endpoints()->at(i)->server()->application_name()->encoding_mask(), localizedTextHasText)) {
                    if (msg->endpoints()->at(i)->server()->application_name()->text()->length()) {
                        endpoint_desc->Assign(GET_ENDPOINT_RES_TEXT_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->application_name()->text()->string())));
                    }
                }

                endpoint_desc->Assign(GET_ENDPOINT_RES_APPLICATION_TYPE_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->server()->application_type()));

                if (msg->endpoints()->at(i)->server()->gateway_server_uri()->length() > 0) {
                    endpoint_desc->Assign(GET_ENDPOINT_RES_GW_SERVER_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->gateway_server_uri()->string())));
                }

                if (msg->endpoints()->at(i)->server()->discovery_profile_uri()->length() > 0) {
                        endpoint_desc->Assign(GET_ENDPOINT_RES_DISCOVERY_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->discovery_profile_uri()->string())));
                }

                if (msg->endpoints()->at(i)->server()->discovery_urls_size() > 0) {

                    string discovery_profile_id = generateId();
                    endpoint_desc->Assign(GET_ENDPOINT_RES_DISCOVERY_PROFILE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(discovery_profile_id));

                    for (int32_t j = 0; j < msg->endpoints()->at(i)->server()->discovery_urls_size(); j++) {
                        zeek::RecordValPtr endpoint_discovery_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::GetEndpointsDiscovery);

                        endpoint_discovery_res->Assign(GET_ENDPOINT_RES_DISCOVERY_PROFILE_LINK_ID_DST_IDX,  zeek::make_intrusive<zeek::StringVal>(discovery_profile_id));

                        endpoint_discovery_res->Assign(GET_ENDPOINT_RES_DISCOVORY_URL_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->server()->discovery_urls()->at(j)->string())));

                        zeek::BifEvent::enqueue_opcua_binary_get_endpoints_discovery_event(connection()->bro_analyzer(),
                                                                                           connection()->bro_analyzer()->Conn(),
                                                                                           endpoint_discovery_res);
                    }
                }

                if (msg->endpoints()->at(i)->server_cert()->cert_size() > 0) {
                    endpoint_desc->Assign(GET_ENDPOINT_RES_CERT_SIZE_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->server_cert()->cert_size()));
                    endpoint_desc->Assign(GET_ENDPOINT_RES_SERVER_CERT_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->endpoints()->at(i)->server_cert()->cert())));
                }

                endpoint_desc->Assign(GET_ENDPOINT_RES_MSG_SECURITY_MODE_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->security_mode()));

                if (msg->endpoints()->at(i)->security_policy_uri()->length() > 0) {
                    endpoint_desc->Assign(GET_ENDPOINT_RES_SECURITY_POLICY_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->security_policy_uri()->string())));
                }

                if ( msg->endpoints()->at(i)->user_identity_tokens_size() > 0)
                {
                    string user_token_id = generateId();
                    endpoint_desc->Assign(GET_ENDPOINT_RES_USER_TOKEN_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(user_token_id));

                    for (int32_t k = 0; k < msg->endpoints()->at(i)->user_identity_tokens_size(); k++) {
                        zeek::RecordValPtr endpoint_user_token_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::GetEndpointsUserToken);

                        endpoint_user_token_res->Assign(GET_ENDPOINT_RES_USER_TOKEN_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(user_token_id));

                        endpoint_user_token_res->Assign(GET_ENDPOINT_RES_USER_TOKEN_POLICY_ID_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->policy_id()->string())));
                        endpoint_user_token_res->Assign(GET_ENDPOINT_RES_USER_TOKEN_TYPE_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->token_type()));

                        if (msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issued_token_type()->length() > 0) {
                            endpoint_user_token_res->Assign(GET_ENDPOINT_RES_USER_TOKEN_ISSUED_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issued_token_type()->string())));
                        }

                        if (msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issuer_endpoint_url()->length() > 0) {
                            endpoint_user_token_res->Assign(GET_ENDPOINT_RES_USER_TOKEN_ISSUER_ENDPOINT_URL_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->issuer_endpoint_url()->string())));
                        }

                        if (msg->endpoints()->at(i)->user_identity_tokens()->at(k)->security_policy_uri()->length() > 0) {
                            endpoint_user_token_res->Assign(GET_ENDPOINT_RES_USER_TOKEN_SECURITY_POLICY_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->user_identity_tokens()->at(k)->security_policy_uri()->string())));
                        }

                        zeek::BifEvent::enqueue_opcua_binary_get_endpoints_user_token_event(connection()->bro_analyzer(),
                                                                                            connection()->bro_analyzer()->Conn(),
                                                                                            endpoint_user_token_res);
                    }
                }

                if (msg->endpoints()->at(i)->transport_profile_uri()->length() > 0) {
                    endpoint_desc->Assign(GET_ENDPOINT_RES_TRANSPORT_PROFILE_URI_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->endpoints()->at(i)->transport_profile_uri()->string())));
                }

                endpoint_desc->Assign(GET_ENDPOINT_RES_SECURITY_LEVEL_IDX, zeek::val_mgr->Count(msg->endpoints()->at(i)->security_level()));

                zeek::BifEvent::enqueue_opcua_binary_get_endpoints_description_event(connection()->bro_analyzer(),
                                                                                     connection()->bro_analyzer()->Conn(),
                                                                                     endpoint_desc);
            }
        }

        zeek::BifEvent::enqueue_opcua_binary_get_endpoints_event(connection()->bro_analyzer(),
                                                                 connection()->bro_analyzer()->Conn(),
                                                                 endpoint_res);

        return true;
    %}
};
