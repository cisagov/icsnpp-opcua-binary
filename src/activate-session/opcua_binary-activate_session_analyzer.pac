
## opcua_binary-activate_sessions_analyzer.pac
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
    # ActivateSessionRequest
    #
    function deliver_Svc_ActivateSessionReq(msg : Activate_Session_Req): bool
        %{
        /* Debug
        printf("deliver_Svc_ActivateSessionReq - begin\n");
        printActivateSessionReq(msg);
        printf("deliver_Svc_ActivateSessionReq - end\n");
        */

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignReqHdr(info, msg->req_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr activate_session_req = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ActivateSession);

        // OpcUA_id
        activate_session_req->Assign(ACTIVATE_SESSION_OPCUA_ID_LINK_IDX, info->GetField(OPCUA_ID_IDX));
        
        // Client Signature
        if (msg->client_signature()->algorithm()->length() > 0) {
            activate_session_req->Assign(ACTIVATE_SESSION_REQ_CLIENT_ALGORITHM_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_signature()->algorithm()->string())));
        }
        if (msg->client_signature()->signature()->length() > 0) {
            activate_session_req->Assign(ACTIVATE_SESSION_REQ_CLIENT_SIGNATURE_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->client_signature()->signature()->byteString())));
        }

        // Client Software Cert
        if (msg->client_software_cert()->size() > 0) {
            std::string cert_idx = generateId();
            activate_session_req->Assign(ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_ID_IDX, zeek::make_intrusive<zeek::StringVal>(cert_idx));
            for (int i = 0; i < msg->client_software_cert()->size(); i++) {
                zeek::RecordValPtr client_software_cert = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ActivateSessionClientSoftwareCert);
                client_software_cert->Assign(ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_LINK_IDX, zeek::make_intrusive<zeek::StringVal>(cert_idx));
                client_software_cert->Assign(ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_DATA_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_software_cert()->at(i)->certificate_data()->byteString())));
                client_software_cert->Assign(ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_SIGNATURE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->client_software_cert()->at(i)->signature()->byteString())));
                zeek::BifEvent::enqueue_opcua_binary_activate_session_client_software_cert_event(connection()->bro_analyzer(),
                                                                                                 connection()->bro_analyzer()->Conn(),
                                                                                                 client_software_cert);

            }
        }

        // Locale Id
        if (msg->locale_id()->size() > 0) {
            std::string locale_idx = generateId();
            activate_session_req->Assign(ACTIVATE_SESSION_REQ_OPCUA_LOCAL_ID_IDX, zeek::make_intrusive<zeek::StringVal>(locale_idx));
            for (int i = 0; i < msg->locale_id()->size(); i++) {
                zeek::RecordValPtr locale_id = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ActivateSessionLocaleId);
                locale_id->Assign(ACTIVATE_SESSION_REQ_OPCUA_LOCAL_LINK_IDX, zeek::make_intrusive<zeek::StringVal>(locale_idx));
                locale_id->Assign(ACTIVATE_SESSION_REQ_LOCALE_ID_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->locale_id()->at(i)->locale_id())));
                zeek::BifEvent::enqueue_opcua_binary_activate_session_locale_id_event(connection()->bro_analyzer(),
                                                                                      connection()->bro_analyzer()->Conn(),
                                                                                      locale_id);
            }
        }


        // User Identity Token of type OpcUA_ExtensionObject

        // OpcUA_ExtensionObject type_id
        flattenNodeId(activate_session_req, msg->user_identity_token()->type_id(), ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_ENCODING_IDX);

        string ext_obj_type_id_str = EXTENSION_OBJECT_ID_MAP.find(getExtensionObjectId(msg->user_identity_token()->type_id()))->second;
        activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_STR_IDX, zeek::make_intrusive<zeek::StringVal>(ext_obj_type_id_str));

        // OpcUA_ExtensionObject encoding
        activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_ENCODING_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(msg->user_identity_token()->encoding())));

        // OpcUA_ExtensionObject token
        switch (getExtensionObjectId(msg->user_identity_token()->type_id())) {
            case AnonymousIdentityToken_Key: 
                // Policy Id
                if (msg->user_identity_token()->anonymous_identity_token()->policy_id()->length() > 0) {
                    activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_POLICY_ID_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->user_identity_token()->anonymous_identity_token()->policy_id()->string())));
                }
                break;
            case UserNameIdentityToken_Key:  
                // Policy Id
                if (msg->user_identity_token()->username_identity_token()->policy_id()->length() > 0) {
                    activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_POLICY_ID_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->user_identity_token()->username_identity_token()->policy_id()->string())));
                }

                // Username
                if (msg->user_identity_token()->username_identity_token()->user_name()->length() > 0) {
                    activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_USERNAME_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->user_identity_token()->username_identity_token()->user_name()->string())));
                }

                // Password
                if (msg->user_identity_token()->username_identity_token()->password()->length() > 0) {
                    activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_PASSWORD_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->user_identity_token()->username_identity_token()->password()->byteString())));
                }

                // Encryption Algorithm
                if (msg->user_identity_token()->username_identity_token()->encryption_algorithm()->length() > 0) {
                    activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_ENCRYPTION_ALGORITHM_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->user_identity_token()->username_identity_token()->encryption_algorithm()->string())));
                }
                break;
            case X509IdentityToken_Key:      
                // Policy Id
                if (msg->user_identity_token()->x509_identity_token()->policy_id()->length() > 0) {
                    activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_POLICY_ID_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->user_identity_token()->x509_identity_token()->policy_id()->string())));
                } 

                // Certificate Data
                if (msg->user_identity_token()->x509_identity_token()->certificate_data()->length() > 0) {
                    activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_CERT_DATA_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->user_identity_token()->x509_identity_token()->certificate_data()->byteString())));
                } 
                break;
            case IssuedIdentityToken_Key:    

                // Policy Id
                if (msg->user_identity_token()->issued_identity_token()->policy_id()->length() > 0) {
                    activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_POLICY_ID_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->user_identity_token()->issued_identity_token()->policy_id()->string())));
                }

                // Token Data
                if (msg->user_identity_token()->issued_identity_token()->token_data()->length() > 0) {
                    activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_TOKEN_DATA_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->user_identity_token()->issued_identity_token()->token_data()->byteString())));
                } 

                // Encryption Algorithm
                if (msg->user_identity_token()->issued_identity_token()->encryption_algorithm()->length() > 0) {
                    activate_session_req->Assign(ACTIVATE_SESSION_REQ_EXT_OBJ_ENCRYPTION_ALGORITHM_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->user_identity_token()->issued_identity_token()->encryption_algorithm()->string())));
                }
                break;
        }

        // User Token Signature
        if (msg->user_token_signature()->algorithm()->length() > 0) {
            activate_session_req->Assign(ACTIVATE_SESSION_REQ_USER_TOKEN_ALGORITHM_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->user_token_signature()->algorithm()->string())));
        }
        if (msg->user_token_signature()->signature()->length() > 0) {
            activate_session_req->Assign(ACTIVATE_SESSION_REQ_USER_TOKEN_SIGNATURE_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->user_token_signature()->signature()->byteString())));
        }

        zeek::BifEvent::enqueue_opcua_binary_activate_session_event(connection()->bro_analyzer(),
                                                                    connection()->bro_analyzer()->Conn(),
                                                                    activate_session_req);

        return true;
        %}

    #
    # ActivateSessionResponse
    #
    function deliver_Svc_ActivateSessionRes(msg : Activate_Session_Res): bool
        %{
        /* Debug
        printf("deliver_Svc_ActivateSessionRes - begin\n");
        printActivateSessionRes(msg);
        printf("deliver_Svc_ActivateSessionRes - end\n");
        */

        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg->service()->msg_body()->header());
        info = assignMsgType(info, msg->service()->msg_body()->header());
        info = assignResHdr(connection(), info, msg->res_hdr());
        info = assignService(info, msg->service());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                                   connection()->bro_analyzer()->Conn(),
                                                   info);

        zeek::RecordValPtr activate_session_res = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ActivateSession);

        // Server Nonce
        activate_session_res->Assign(ACTIVATE_SESSION_RES_SERVER_NONCE_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg->server_nonce()->byteString())));

        // StatusCode Results
        if (msg->result_size() > 0) {
            string result_idx = generateId();
            activate_session_res->Assign(ACTIVATE_SESSION_RES_RESULT_ID_IDX, zeek::make_intrusive<zeek::StringVal>(result_idx));
            for (int i = 0; i < msg->result_size(); i++) {
                generateStatusCodeEvent(connection(), activate_session_res->GetField(ACTIVATE_SESSION_RES_RESULT_ID_IDX), StatusCode_ActivateSession_Key, msg->results()->at(i));
            }
        }

        // Diagnostic Information
        if (msg->diagnostic_info_size() > 0) {
            string diagnostic_info_link_id = generateId(); // Link to tie OCPUA_Binary::ActivateSession and OPCUA_Binary::ActivateSessionDiagnosticInfo together
            string diagnostic_info_id      = generateId(); // Link to tie OCPUA_Binary::ActivateSessionDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together

            // Assign the linkage in the OCPUA_Binary::ActivateSession
            activate_session_res->Assign(ACTIVATE_SESSION_RES_DIAG_INFO_ID_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_link_id));

            uint32 innerDiagLevel = 0;
            vector<OpcUA_String *>  *stringTable = NULL;
            for (int i = 0; i < msg->diagnostic_info_size(); i++) {

                // Assign the linkage in the OCPUA_Binary::ActivateSessionDiagnosticInfo and enqueue the logging event  
                zeek::RecordValPtr activate_session_res_diagnostic_info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ActivateSessionDiagnosticInfo);
                activate_session_res_diagnostic_info->Assign(ACTIVATE_SESSION_RES_DIAGNOSTIC_INFO_LINK_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_link_id));
                activate_session_res_diagnostic_info->Assign(ACTIVATE_SESSION_RES_DIAGNOSTIC_INFO_IDX,      zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id));
                zeek::BifEvent::enqueue_opcua_binary_activate_session_diagnostic_info_event(connection()->bro_analyzer(),
                                                                                            connection()->bro_analyzer()->Conn(),
                                                                                            activate_session_res_diagnostic_info);


                // Process the details of the Diagnostic Information
                generateDiagInfoEvent(connection(), activate_session_res_diagnostic_info->GetField(ACTIVATE_SESSION_RES_DIAGNOSTIC_INFO_IDX), msg->diagnostic_info()->at(i), stringTable, innerDiagLevel, StatusCode_ActivateSessionDiagInfo_Key);

                // Generate an new link to tie OCPUA_Binary::ActivateSessionDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together
                diagnostic_info_id = generateId();
            }
        }

        // Enqueue the OCPUA_Binary::ActivateSession event.
        zeek::BifEvent::enqueue_opcua_binary_activate_session_event(connection()->bro_analyzer(),
                                                                    connection()->bro_analyzer()->Conn(),
                                                                    activate_session_res);

        return true;
    %}
};
