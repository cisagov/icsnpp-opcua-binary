
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
        activate_session_req->Assign(ACTIVATE_SESSION_OPCUA_LINK_ID_DST_IDX, info->GetField(OPCUA_LINK_ID_SRC_IDX));
        
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
            activate_session_req->Assign(ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(cert_idx));
            for (int i = 0; i < msg->client_software_cert()->size(); i++) {
                zeek::RecordValPtr client_software_cert = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ActivateSessionClientSoftwareCert);
                client_software_cert->Assign(ACTIVATE_SESSION_REQ_CLIENT_SOFTWARE_CERT_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(cert_idx));
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
            activate_session_req->Assign(ACTIVATE_SESSION_REQ_OPCUA_LOCAL_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(locale_idx));
            for (int i = 0; i < msg->locale_id()->size(); i++) {
                zeek::RecordValPtr locale_id = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ActivateSessionLocaleId);
                locale_id->Assign(ACTIVATE_SESSION_REQ_OPCUA_LOCAL_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(locale_idx));
                locale_id->Assign(ACTIVATE_SESSION_REQ_LOCALE_ID_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg->locale_id()->at(i)->locale_id())));
                zeek::BifEvent::enqueue_opcua_binary_activate_session_locale_id_event(connection()->bro_analyzer(),
                                                                                      connection()->bro_analyzer()->Conn(),
                                                                                      locale_id);
            }
        }


        // User Identity Token of type OpcUA_ExtensionObject

        // OpcUA_ExtensionObject type_id
        flattenOpcUA_ExtensionObject(activate_session_req, msg->user_identity_token(), ACTIVATE_SESSION_REQ_EXT_OBJ_TYPE_ID_ENCODING_IDX);

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
            uint32_t status_code_level = 0;
            string result_idx = generateId();
            activate_session_res->Assign(ACTIVATE_SESSION_RES_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(result_idx));
            for (int i = 0; i < msg->result_size(); i++) {
                generateStatusCodeEvent(connection(), activate_session_res->GetField(ACTIVATE_SESSION_RES_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_ActivateSession_Key, msg->results()->at(i), status_code_level);
            }
        }

        // Diagnostic Information
        if (msg->diagnostic_info_size() > 0) {
            string diagnostic_info_id_link = generateId(); // Link to tie OCPUA_Binary::ActivateSession and OPCUA_Binary::ActivateSessionDiagnosticInfo together
            string diagnostic_info_id      = generateId(); // Link to tie OCPUA_Binary::ActivateSessionDiagnosticInfo and OPCUA_Binary::DiagnosticInfoDetail together

            // Assign the linkage in the OCPUA_Binary::ActivateSession
            activate_session_res->Assign(ACTIVATE_SESSION_RES_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id_link));

            uint32 innerDiagLevel = 0;
            vector<OpcUA_String *>  *stringTable = NULL;
            for (int i = 0; i < msg->diagnostic_info_size(); i++) {

                // Assign the linkage in the OCPUA_Binary::ActivateSessionDiagnosticInfo and enqueue the logging event  
                zeek::RecordValPtr activate_session_res_diagnostic_info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::ActivateSessionDiagnosticInfo);
                activate_session_res_diagnostic_info->Assign(ACTIVATE_SESSION_RES_DIAG_INFO_LINK_ID_DST_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id_link));
                activate_session_res_diagnostic_info->Assign(ACTIVATE_SESSION_DIAG_INFO_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(diagnostic_info_id));
                zeek::BifEvent::enqueue_opcua_binary_activate_session_diagnostic_info_event(connection()->bro_analyzer(),
                                                                                            connection()->bro_analyzer()->Conn(),
                                                                                            activate_session_res_diagnostic_info);


                // Process the details of the Diagnostic Information
                generateDiagInfoEvent(connection(), activate_session_res_diagnostic_info->GetField(ACTIVATE_SESSION_DIAG_INFO_LINK_ID_SRC_IDX), msg->diagnostic_info()->at(i), stringTable, innerDiagLevel, StatusCode_ActivateSession_DiagInfo_Key, DiagInfo_ActivateSession_Key);

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
