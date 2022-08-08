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
%}

%code{


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
            uint32_t status_code_level = 0;
            generateStatusCodeEvent(connection, info->GetField(OPCUA_ID_IDX), StatusCode_ResponseHeader_Key, res_hdr->service_result(), status_code_level);
        }

        // If there is DiagnosticInfo - then log the detailed information.
        uint32 innerDiagLevel = 0;
        if (res_hdr->service_diag()->encoding_mask() != 0x00) {

            vector<OpcUA_String *>  *stringTable = NULL;
            if (res_hdr->string_table_size() > 0) {
                stringTable = res_hdr->string_table();
            }

            generateDiagInfoEvent(connection, info->GetField(OPCUA_ID_IDX), res_hdr->service_diag(), stringTable, innerDiagLevel, StatusCode_ResponseHeader_DiagInfo_Key, DiagInfo_ResponseHeader_Key);
        }

        // Log the Additional Header information
        info->Assign(RES_HDR_ADD_HDR_TYPE_ID_IDX,  zeek::val_mgr->Count(res_hdr->additional_hdr()->type_id()));
        info->Assign(RES_HDR_ADD_HDR_ENC_MASK_IDX, zeek::val_mgr->Count(res_hdr->additional_hdr()->encoding_mask()));

        return info;
    }

%}
