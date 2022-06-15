## opcua_binary-req_res_header_analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Analyzer code for processing the request and response headers.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    zeek::RecordValPtr assignReqHdr(zeek::RecordValPtr info, Request_Header *req_hdr);
    zeek::RecordValPtr assignResHdr(OPCUA_Binary_Conn *connection, zeek::RecordValPtr info, Response_Header *res_hdr);
    void generateDiagInfoEvent(OPCUA_Binary_Conn *connection, zeek::ValPtr opcua_id, OpcUA_DiagInfo *diagInfo, vector<OpcUA_String *> *stringTable, uint32 innerDiagLevel);
    void generateStatusCodeEvent(OPCUA_Binary_Conn *connection, zeek::ValPtr opcua_id, uint32_t status_code_src, uint32_t status_code);
%}

%code{

    //
    // Common code used to generate a status code event.
    //
    void generateStatusCodeEvent(OPCUA_Binary_Conn *connection, zeek::ValPtr opcua_id, uint32_t status_code_src, uint32_t status_code) {
            StatusCodeDetail detail = StatusCodeDetail(status_code);
            zeek::RecordValPtr status = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::StatusCodeDetail);

            // OpcUA_id
            status->Assign(STAT_CODE_OPCUA_ID_LINK_IDX, opcua_id);

            status->Assign(SOURCE_IDX,            zeek::val_mgr->Count(status_code_src));
            status->Assign(SOURCE_STR_IDX,        zeek::make_intrusive<zeek::StringVal>((STATUS_CODE_SRC_MAP.find(status_code_src)->second)));
            status->Assign(STATUS_CODE_IDX,       zeek::make_intrusive<zeek::StringVal>(uint32ToHexstring(status_code)));
            status->Assign(SEVERITY_IDX,          zeek::val_mgr->Count(detail.severity));
            status->Assign(SEVERITY_STR_IDX,      zeek::make_intrusive<zeek::StringVal>(detail.severityStr));
            status->Assign(SUBCODE_IDX,           zeek::val_mgr->Count(detail.subCode));
            status->Assign(SUBCODE_STR_IDX,       zeek::make_intrusive<zeek::StringVal>(detail.subCodeStr));
            status->Assign(STRUCTURE_CHANGED_IDX, zeek::val_mgr->Bool(detail.structureChanged));
            status->Assign(SEMANTICS_CHANGED_IDX, zeek::val_mgr->Bool(detail.semanticsChanged));
            status->Assign(INFO_TYPE_IDX,         zeek::val_mgr->Count(detail.infoType));
            status->Assign(INFO_TYPE_STR_IDX,     zeek::make_intrusive<zeek::StringVal>(detail.infoTypeStr));

            if (detail.infoType != InfoType_NotUsed_Key) {
                status->Assign(LIMIT_BITS_IDX,         zeek::val_mgr->Count(detail.limitBits));
                status->Assign(LIMIT_BITS_STR_IDX,     zeek::make_intrusive<zeek::StringVal>(detail.limitBitsStr));
                status->Assign(OVERFLOW_IDX,           zeek::val_mgr->Bool(detail.overflow));

                status->Assign(HISTORIAN_BITS_IDX,            zeek::val_mgr->Count(detail.historianBits));
                status->Assign(HISTORIAN_BITS_STR_IDX,        zeek::make_intrusive<zeek::StringVal>(detail.historianBitsStr));
                status->Assign(HISTORIAN_BITS_PARTIAL_IDX,    zeek::val_mgr->Bool(detail.historianPartial));
                status->Assign(HISTORIAN_BITS_EXTRADATA_IDX,  zeek::val_mgr->Bool(detail.historianExtraData));
                status->Assign(HISTORIAN_BITS_MULTIVALUE_IDX, zeek::val_mgr->Bool(detail.historianMultiValue));
            }

            zeek::BifEvent::enqueue_opcua_binary_status_code_event(connection->bro_analyzer(),
                                                              connection->bro_analyzer()->Conn(),
                                                              status);
    }

    //
    // Common code used to generate a diagnostic information event.
    // NOTE: This function is called recursively to  process any 
    // nested inner diagnostic information.
    //
    void generateDiagInfoEvent(OPCUA_Binary_Conn *connection, zeek::ValPtr opcua_id, OpcUA_DiagInfo *diagInfo, vector<OpcUA_String *> *stringTable, uint32 innerDiagLevel) {
        zeek::RecordValPtr diag_info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::DiagnosticInfoDetail);

        // OpcUA_id
        diag_info->Assign(DIAG_INFO_DETAIL_OPCUA_ID_LINK_IDX, opcua_id);

        // Initialize the diagnostic info record
        diag_info->Assign(INNER_DIAG_LEVEL_IDX, zeek::val_mgr->Count(innerDiagLevel));
        diag_info->Assign(HAS_SYMBOLIC_ID_IDX,     zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_NAMESPACE_URI_IDX,   zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_LOCALE_IDX,          zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_LOCALE_TXT_IDX,      zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_ADDL_INFO_IDX,       zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_INNER_STAT_CODE_IDX, zeek::val_mgr->Bool(false));
        diag_info->Assign(HAS_INNER_DIAG_INFO_IDX, zeek::val_mgr->Bool(false));

        // Symbolic Id
        if (isBitSet(diagInfo->encoding_mask(), hasSymbolicId)) {
            int32 idx = diagInfo->symbolic_id();
            string str = std_str(stringTable->at(idx)->string());

            diag_info->Assign(HAS_SYMBOLIC_ID_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(SYMBOLIC_ID_IDX,     zeek::val_mgr->Count(idx));
            diag_info->Assign(SYMBOLIC_ID_STR_IDX, zeek::make_intrusive<zeek::StringVal>(str));
        }

        // Namespace URI
        if (isBitSet(diagInfo->encoding_mask(), hasNamespaceUri)) {
            int32 idx = diagInfo->namespace_uri();
            string str = std_str(stringTable->at(idx)->string());

            diag_info->Assign(HAS_NAMESPACE_URI_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(NAMESPACE_URI_IDX,     zeek::val_mgr->Count(idx));
            diag_info->Assign(NAMESPACE_URI_STR_IDX, zeek::make_intrusive<zeek::StringVal>(str));
        }

        // Localized Text
        if (isBitSet(diagInfo->encoding_mask(), hasLocalizedTxt)) {
            int32 idx = diagInfo->localized_txt();
            string str = std_str(stringTable->at(idx)->string());

            diag_info->Assign(HAS_LOCALE_TXT_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(LOCALE_TXT_IDX,     zeek::val_mgr->Count(idx));
            diag_info->Assign(LOCALE_TXT_STR_IDX, zeek::make_intrusive<zeek::StringVal>(str));
        }

        // Locale
        if (isBitSet(diagInfo->encoding_mask(), hasLocale)) {
            int32 idx = diagInfo->locale();
            string str = std_str(stringTable->at(idx)->string());

            diag_info->Assign(HAS_LOCALE_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(LOCALE_IDX,     zeek::val_mgr->Count(idx));
            diag_info->Assign(LOCALE_STR_IDX, zeek::make_intrusive<zeek::StringVal>(str));
        }

        // Additional Information
        if (isBitSet(diagInfo->encoding_mask(), hasAddlInfo)) {
            string str = std_str(diagInfo->addl_info()->string());

            diag_info->Assign(HAS_ADDL_INFO_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(ADDL_INFO_IDX,     zeek::make_intrusive<zeek::StringVal>(str));
        }

        // Inner Status Code
        if (isBitSet(diagInfo->encoding_mask(), hasInnerStatCode)) {
            diag_info->Assign(HAS_INNER_STAT_CODE_IDX, zeek::val_mgr->Bool(true));
            diag_info->Assign(INNER_STAT_CODE_IDX,     zeek::make_intrusive<zeek::StringVal>(uint32ToHexstring(diagInfo->inner_stat_code())));
            generateStatusCodeEvent(connection, opcua_id, StatusCode_DiagInfoInnerStatus_Key, diagInfo->inner_stat_code());
        }

        // Inner Diagnostic Info
        if (isBitSet(diagInfo->encoding_mask(), hasInnerDiagInfo)) {
            diag_info->Assign(HAS_INNER_DIAG_INFO_IDX, zeek::val_mgr->Bool(true));
            zeek::BifEvent::enqueue_opcua_binary_diag_info_event(connection->bro_analyzer(),
                                                            connection->bro_analyzer()->Conn(),
                                                            diag_info);

            generateDiagInfoEvent(connection, opcua_id, diagInfo->inner_diag_info(), stringTable, innerDiagLevel+=1);
        } else {
            zeek::BifEvent::enqueue_opcua_binary_diag_info_event(connection->bro_analyzer(),
                                                            connection->bro_analyzer()->Conn(),
                                                            diag_info);
        }

        return;
    }

    //
    // Common code used to assign the request header information to a zeek::RecordValPtr
    // for future logging.
    //
    zeek::RecordValPtr assignReqHdr(zeek::RecordValPtr info, Request_Header *req_hdr) {

        info->Assign(REQ_HDR_NODE_ID_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(req_hdr->auth_token()->identifier_type())));

        switch (req_hdr->auth_token()->identifier_type()) {
            case node_encoding::TwoByte : info->Assign(REQ_HDR_NODE_ID_NUMERIC_IDX, zeek::val_mgr->Count(req_hdr->auth_token()->two_byte_numeric()->numeric()));
                                          break;
            case node_encoding::FourByte : 
                                        info->Assign(REQ_HDR_NODE_ID_NAMESPACE_IDX, zeek::val_mgr->Count(req_hdr->auth_token()->four_byte_numeric()->namespace_index()));
                                        info->Assign(REQ_HDR_NODE_ID_NUMERIC_IDX, zeek::val_mgr->Count(req_hdr->auth_token()->four_byte_numeric()->numeric()));
                                        break;
            case node_encoding::Numeric : 
                                        info->Assign(REQ_HDR_NODE_ID_NAMESPACE_IDX, zeek::val_mgr->Count(req_hdr->auth_token()->numeric()->namespace_index()));
                                        info->Assign(REQ_HDR_NODE_ID_NUMERIC_IDX, zeek::val_mgr->Count(req_hdr->auth_token()->numeric()->numeric()));
                                        break;
            case node_encoding::String : 
                                        info->Assign(REQ_HDR_NODE_ID_NAMESPACE_IDX, zeek::val_mgr->Count(req_hdr->auth_token()->string()->namespace_index()));
                                        info->Assign(REQ_HDR_NODE_ID_STRING_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(req_hdr->auth_token()->string()->string()->string())));
                                        break;
            case node_encoding::GUID : 
                                        info->Assign(REQ_HDR_NODE_ID_NAMESPACE_IDX, zeek::val_mgr->Count(req_hdr->auth_token()->guid()->namespace_index()));
                                        info->Assign(REQ_HDR_NODE_ID_GUID_IDX, zeek::make_intrusive<zeek::StringVal>(guidToGuidstring(req_hdr->auth_token()->guid()->guid()->data1(),
                                                                                                                                      req_hdr->auth_token()->guid()->guid()->data2(),
                                                                                                                                      req_hdr->auth_token()->guid()->guid()->data3(),
                                                                                                                                      req_hdr->auth_token()->guid()->guid()->data4())));
                                        break;
            case node_encoding::Opaque : 
                                        info->Assign(REQ_HDR_NODE_ID_NAMESPACE_IDX, zeek::val_mgr->Count(req_hdr->auth_token()->opaque()->namespace_index()));
                                        info->Assign(REQ_HDR_NODE_ID_OPAQUE_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(req_hdr->auth_token()->opaque()->opaque()->byteString())));
                                        break;
        }

        double unix_timestamp = winFiletimeToUnixTime(req_hdr->timestamp());
        info->Assign(REQ_HDR_TIMESTAMP_IDX, zeek::make_intrusive<zeek::TimeVal>(unix_timestamp));

        info->Assign(REQ_HDR_HANDLE_IDX, zeek::val_mgr->Count(req_hdr->request_handle()));
        info->Assign(REQ_HDR_RET_DIAG_IDX, zeek::val_mgr->Count(req_hdr->return_diag()));

        info->Assign(REQ_HDR_AUDIT_ENTRY_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(req_hdr->audit_entry_id()->string())));
        info->Assign(REQ_HDR_TIMEOUT_HINT_IDX, zeek::make_intrusive<zeek::TimeVal>((double)req_hdr->timeout_hint()));

        info->Assign(REQ_HDR_ADD_HDR_TYPE_ID_IDX,  zeek::val_mgr->Count(req_hdr->additional_hdr()->type_id()));
        info->Assign(REQ_HDR_ADD_HDR_ENC_MASK_IDX, zeek::val_mgr->Count(req_hdr->additional_hdr()->encoding_mask()));

        return info;
    }

    //
    // Common code used to assign the response header information to a zeek::RecordValPtr
    // for future logging.
    //
    zeek::RecordValPtr assignResHdr(OPCUA_Binary_Conn *connection, zeek::RecordValPtr info, Response_Header *res_hdr) {
        double unix_timestamp = winFiletimeToUnixTime(res_hdr->timestamp());
        info->Assign(RES_HDR_TIMESTAMP_IDX, zeek::make_intrusive<zeek::TimeVal>(unix_timestamp));
        info->Assign(RES_HDR_HANDLE_IDX, zeek::val_mgr->Count(res_hdr->request_handle()));
        info->Assign(RES_HDR_SERVICE_RESULT_IDX, zeek::val_mgr->Count(res_hdr->service_result()));
        info->Assign(RES_HDR_SERVICE_DIAG_ENCODING_IDX, zeek::val_mgr->Count(res_hdr->service_diag()->encoding_mask()));

        // If the status code is not "Good"; then log more detailed information
        if (res_hdr->service_result() != StatusCode_Good_Key) {
            generateStatusCodeEvent(connection, info->GetField(OPCUA_ID_IDX), StatusCode_ResHdrServiceResult_Key, res_hdr->service_result());
        }

        // If there is DiagnosticInfo - then log the detailed information.
        uint32 innerDiagLevel = 0;
        if (res_hdr->service_diag()->encoding_mask() != 0x00) {

            vector<OpcUA_String *>  *stringTable = NULL;
            if (res_hdr->string_table_size() > 0) {
                stringTable = res_hdr->string_table();
            }

            generateDiagInfoEvent(connection, info->GetField(OPCUA_ID_IDX), res_hdr->service_diag(), stringTable, innerDiagLevel);
        }

        // Log the Additional Header information
        info->Assign(RES_HDR_ADD_HDR_TYPE_ID_IDX,  zeek::val_mgr->Count(res_hdr->additional_hdr()->type_id()));
        info->Assign(RES_HDR_ADD_HDR_ENC_MASK_IDX, zeek::val_mgr->Count(res_hdr->additional_hdr()->encoding_mask()));

        return info;
    }

%}
