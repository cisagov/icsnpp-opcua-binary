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
    zeek::RecordValPtr assignResHdr(OPCUA_Binary_Conn *connection, zeek::RecordValPtr info, Response_Header *res_hdr, bool is_orig);
%}

%code{


    //
    // Common code used to assign the request header information to a zeek::RecordValPtr
    // for future logging.
    //
    zeek::RecordValPtr assignReqHdr(zeek::RecordValPtr info, Request_Header *req_hdr) {

        // Auth token
        flattenOpcUA_NodeId(info, req_hdr->auth_token(), REQ_HDR_NODE_ID_TYPE_IDX);

        double unix_timestamp = winFiletimeToUnixTime(req_hdr->timestamp());
        info->Assign(REQ_HDR_TIMESTAMP_IDX, zeek::make_intrusive<zeek::TimeVal>(unix_timestamp));

        info->Assign(REQ_HDR_HANDLE_IDX, zeek::val_mgr->Count(req_hdr->request_handle()));
        info->Assign(REQ_HDR_RET_DIAG_IDX, zeek::val_mgr->Count(req_hdr->return_diag()));

        info->Assign(REQ_HDR_AUDIT_ENTRY_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(req_hdr->audit_entry_id()->string())));
        info->Assign(REQ_HDR_TIMEOUT_HINT_IDX, zeek::val_mgr->Count((double)req_hdr->timeout_hint()));

        info->Assign(REQ_HDR_ADD_HDR_TYPE_ID_IDX,  zeek::val_mgr->Count(req_hdr->additional_hdr()->type_id()));
        info->Assign(REQ_HDR_ADD_HDR_ENC_MASK_IDX, zeek::val_mgr->Count(req_hdr->additional_hdr()->encoding_mask()));

        return info;
    }

    //
    // Common code used to assign the response header information to a zeek::RecordValPtr
    // for future logging.
    //
    zeek::RecordValPtr assignResHdr(OPCUA_Binary_Conn *connection, zeek::RecordValPtr info, Response_Header *res_hdr, bool is_orig) {
        double unix_timestamp = winFiletimeToUnixTime(res_hdr->timestamp());
        info->Assign(RES_HDR_TIMESTAMP_IDX, zeek::make_intrusive<zeek::TimeVal>(unix_timestamp));
        info->Assign(RES_HDR_HANDLE_IDX, zeek::val_mgr->Count(res_hdr->request_handle()));

        // Service Result aka Status Code
        uint32_t status_code_level = 0;
        string service_result_idx = generateId();
        info->Assign(RES_HDR_STATUS_CODE_LINK_ID_SRC_IDX, zeek::make_intrusive<zeek::StringVal>(service_result_idx));
        generateStatusCodeEvent(connection, info->GetField(RES_HDR_STATUS_CODE_LINK_ID_SRC_IDX), StatusCode_ResponseHeader_Key, res_hdr->service_result(), status_code_level, is_orig);

        // If there is DiagnosticInfo - then log the detailed information.
        info->Assign(RES_HDR_SERVICE_DIAG_ENCODING_IDX, zeek::val_mgr->Count(res_hdr->service_diag()->encoding_mask()));
        uint32 innerDiagLevel = 0;
        if (res_hdr->service_diag()->encoding_mask() != 0x00) {

            vector<OpcUA_String *>  *stringTable = NULL;
            if (res_hdr->string_table_size() > 0) {
                stringTable = res_hdr->string_table();
            }

            generateDiagInfoEvent(connection, info->GetField(OPCUA_LINK_ID_SRC_IDX), res_hdr->service_diag(), stringTable, innerDiagLevel, StatusCode_ResponseHeader_DiagInfo_Key, is_orig, DiagInfo_ResponseHeader_Key);
        }

        // Log the Additional Header information
        info->Assign(RES_HDR_ADD_HDR_TYPE_ID_IDX,  zeek::val_mgr->Count(res_hdr->additional_hdr()->type_id()));
        info->Assign(RES_HDR_ADD_HDR_ENC_MASK_IDX, zeek::val_mgr->Count(res_hdr->additional_hdr()->encoding_mask()));

        return info;
    }

%}
