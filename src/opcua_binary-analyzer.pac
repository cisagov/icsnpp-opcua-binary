## opcua_binary-analyzer.pac
##
## OPCUA Binary Protocol Analyzer
##
## Message type processing and analyzer utilitiy functions.
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%extern{
#include <set>
#include <sstream>
#include <iomanip>
#include <random>
#include "types.bif.h"
#include "extension_object_node_id.h"
#include "index-consts.h"
#include "statuscode-diagnostic-index-consts.h"
#include "create-session/index-consts.h"
#include "activate-session/index-consts.h"
#include "create-subscription/index-consts.h"
#include "get-endpoints/index-consts.h"
#include "secure-channel/index-consts.h"
#include "req-res-header/index-consts.h"
#include "browse/index-consts.h"
#include "create-monitored-items/index-consts.h"
#include "status_codes.h"
#include "node_identifiers.h"
#include "node_classes.h"
#include "headers/timestamps_to_return.h"
#include "headers/attribute_ids.h"
#include "statuscode-diagnostic-source-consts.h"
%}

%header{
    zeek::RecordValPtr assignMsgHeader(zeek::RecordValPtr info, Msg_Header *msg_header);
    zeek::RecordValPtr assignMsgType(zeek::RecordValPtr info, Msg_Header *msg_header);
    zeek::RecordValPtr assignMsgHEL(zeek::RecordValPtr info, Msg_HEL *msg_hel);
    zeek::RecordValPtr assignMsgACK(zeek::RecordValPtr info, Msg_ACK *msg_ack);
    zeek::RecordValPtr assignMsgERR(zeek::RecordValPtr info, Msg_ERR *msg_err);
    zeek::RecordValPtr assignMsgOPN(zeek::RecordValPtr info, Msg_OPN *msg_opn);
    zeek::RecordValPtr assignMsgMSG(zeek::RecordValPtr info, Msg_MSG *msg_msg);
    zeek::RecordValPtr assignMsgCLO(zeek::RecordValPtr info, Msg_CLO *msg_clo);
    zeek::RecordValPtr assignService(zeek::RecordValPtr info, Service *service);
%}

%code{

    //
    // Common code used to assign the message header information to a zeek::RecordVal 
    // for future logging.
    //
    zeek::RecordValPtr assignMsgHeader(zeek::RecordValPtr info, Msg_Header *msg_header) {
        // OpcUA_id
        info->Assign(OPCUA_ID_IDX, zeek::make_intrusive<zeek::StringVal>(generateId()));

        // Msg header: msg_type
        stringstream ssMsgType;
        for ( uint8 i = 0; i < msg_header->msg_type()->size(); ++i ) {
            ssMsgType << msg_header->msg_type()->at(i);
        }
        info->Assign(MSG_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(ssMsgType.str()));

        // Msg header: is_final
        stringstream ssIsFinal;
        ssIsFinal << msg_header->is_final();
        info->Assign(IS_FINAL_IDX, zeek::make_intrusive<zeek::StringVal>(ssIsFinal.str()));

        // Msg header: msg_size
        info->Assign(MSG_SIZE_IDX, zeek::val_mgr->Count(msg_header->msg_size()));

        return info;
    }

    //
    // Common code used to determine the message type and assign the information to a zeek::RecordVal 
    // for future logging.
    //
    zeek::RecordValPtr assignMsgType(zeek::RecordValPtr info, Msg_Header *msg_header) {
        switch (uint8VectorToUint32(msg_header->msg_type())) {
            case HEL: info = assignMsgHEL(info, msg_header->hel());
                      break;
            case ACK: info = assignMsgACK(info, msg_header->ack());
                      break;
            case ERR: info = assignMsgERR(info, msg_header->err());
                      break;
            case OPN: info = assignMsgOPN(info, msg_header->opn());
                      break;
            case MSG: info = assignMsgMSG(info, msg_header->msg());
                      break;
            case CLO: info = assignMsgCLO(info, msg_header->clo());
                      break;
        }

        return info;
    }

    //
    // Common code used to assign the message HEL information to a zeek::RecordValPtr
    // for future logging.
    //
    zeek::RecordValPtr assignMsgHEL(zeek::RecordValPtr info, Msg_HEL *msg_hel) {
        info->Assign(VERSION_IDX,       zeek::val_mgr->Count(msg_hel->version()));
        info->Assign(RCV_BUF_SIZE_IDX,  zeek::val_mgr->Count(msg_hel->rcv_buf_size()));
        info->Assign(SND_BUF_SIZE_IDX,  zeek::val_mgr->Count(msg_hel->snd_buf_size()));
        info->Assign(MAX_MSG_SIZE_IDX,  zeek::val_mgr->Count(msg_hel->max_msg_size()));
        info->Assign(MAX_CHUNK_CNT_IDX, zeek::val_mgr->Count(msg_hel->max_chunk_cnt()));
        info->Assign(ENDPOINT_URL_IDX,  zeek::make_intrusive<zeek::StringVal>(getEndpointUrl(msg_hel->endpoint_url())));

        return info;
    }

    //
    // Common code used to assign the message ACK information to a zeek::RecordValPtr
    // for future logging.
    //
    zeek::RecordValPtr assignMsgACK(zeek::RecordValPtr info, Msg_ACK *msg_ack) {
        info->Assign(VERSION_IDX,       zeek::val_mgr->Count(msg_ack->version()));
        info->Assign(RCV_BUF_SIZE_IDX,  zeek::val_mgr->Count(msg_ack->rcv_buf_size()));
        info->Assign(SND_BUF_SIZE_IDX,  zeek::val_mgr->Count(msg_ack->snd_buf_size()));
        info->Assign(MAX_MSG_SIZE_IDX,  zeek::val_mgr->Count(msg_ack->max_msg_size()));
        info->Assign(MAX_CHUNK_CNT_IDX, zeek::val_mgr->Count(msg_ack->max_chunk_cnt()));

        return info;
    }

    //
    // Common code used to assign the message ERR information to a zeek::RecordValPtr
    // for future logging.
    //
    zeek::RecordValPtr assignMsgERR(zeek::RecordValPtr info, Msg_ERR *msg_err) {
        info->Assign(ERROR_IDX,  zeek::val_mgr->Count(msg_err->error()));
        info->Assign(REASON_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg_err->reason())));

        return info;
    }

    //
    // Common code used to assign the message OPN information to a zeek::RecordValPtr
    // for future logging.
    //
    zeek::RecordValPtr assignMsgOPN(zeek::RecordValPtr info, Msg_OPN *msg_opn) {

        info->Assign(SEC_CHANNEL_ID_IDX, zeek::val_mgr->Count(msg_opn->sec_channel_id()));

        // Security Header
        info->Assign(SEC_POLICY_URI_LEN_IDX, zeek::val_mgr->Int(msg_opn->sec_header()->sec_policy_uri_len()));
        info->Assign(SEC_POLICY_URI_IDX,     zeek::make_intrusive<zeek::StringVal>(std_str(msg_opn->sec_header()->sec_policy_uri())));
        info->Assign(SND_CERT_LEN_IDX,       zeek::val_mgr->Int(msg_opn->sec_header()->snd_cert_len()));

        if (msg_opn->sec_header()->snd_cert_len() > 0) {
            info->Assign(SND_CERT_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg_opn->sec_header()->snd_cert())));
        }

        info->Assign(RCV_CERT_LEN_IDX, zeek::val_mgr->Int(msg_opn->sec_header()->rcv_cert_len()));
        if (msg_opn->sec_header()->rcv_cert_len() > 0) {
            info->Assign(RCV_CERT_IDX, zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(msg_opn->sec_header()->rcv_cert())));
        }

        // Sequence Header
        info->Assign(SEQ_NUMBER_IDX, zeek::val_mgr->Count(msg_opn->seq_header()->seq_number()));
        info->Assign(REQUEST_ID_IDX, zeek::val_mgr->Count(msg_opn->seq_header()->request_id()));

        return info;
    }

    //
    // Common code used to assign the message CLO information to a zeek::RecordValPtr
    // for future logging.
    //
    zeek::RecordValPtr assignMsgCLO(zeek::RecordValPtr info, Msg_CLO *msg_clo) {

        // printf("assignMsgCLO\n");

        // Secure Channel Id and Secure Token Id
        info->Assign(SEC_CHANNEL_ID_IDX, zeek::val_mgr->Count(msg_clo->sec_channel_id()));
        info->Assign(SEC_TOKEN_ID_IDX, zeek::val_mgr->Count(msg_clo->sec_token_id()));

        // Sequence Header
        info->Assign(SEQ_NUMBER_IDX, zeek::val_mgr->Count(msg_clo->seq_header()->seq_number()));
        info->Assign(REQUEST_ID_IDX, zeek::val_mgr->Count(msg_clo->seq_header()->request_id()));

        return info;
    }

    //
    // Common code used to assign the message MSG information to a zeek::RecordValPtr
    // for future logging.
    //
    zeek::RecordValPtr assignMsgMSG(zeek::RecordValPtr info, Msg_MSG *msg_msg) {

        //Debug printf("assignMsgMSG - begin\n");

        // Secure Channel Id and Secure Token Id
        info->Assign(SEC_CHANNEL_ID_IDX, zeek::val_mgr->Count(msg_msg->sec_channel_id()));
        info->Assign(SEC_TOKEN_ID_IDX, zeek::val_mgr->Count(msg_msg->sec_channel_id()));

        // Sequence Header
        info->Assign(SEQ_NUMBER_IDX, zeek::val_mgr->Count(msg_msg->seq_header()->seq_number()));
        info->Assign(REQUEST_ID_IDX, zeek::val_mgr->Count(msg_msg->seq_header()->request_id()));

        //Debug printf("assignMsgMSG - end\n");
        return info;

    }

    zeek::RecordValPtr assignService(zeek::RecordValPtr info, Service *service) {
        info->Assign(ENCODING_MASK_IDX,  zeek::val_mgr->Count(service->msg_body()->encoding_mask()));
        info->Assign(NAMESPACE_IDX,      zeek::val_mgr->Count(service->namespace_idx()));
        info->Assign(IDENTIFIER_IDX,     zeek::val_mgr->Count(service->identifier()));
        info->Assign(IDENTIFIER_STR_IDX, zeek::make_intrusive<zeek::StringVal>(NODE_IDENTIFIER_MAP.find(service->identifier())->second));

        return info;
    }
%}


refine flow OPCUA_Binary_Flow += {

    #
    # Message Hello
    #
    function deliver_Msg_HEL(msg_hel: Msg_HEL): bool
        %{
        //Debug printf("\tdeliver_Msg_HEL - begin\n");
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg_hel->header());
        info = assignMsgType(info, msg_hel->header());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                              connection()->bro_analyzer()->Conn(),
                                              info);

        //Debug printf("\tdeliver_Msg_HEL - end\n");
        return true;
        %}

    #
    # Message Acknowledge
    #
    function deliver_Msg_ACK(msg_ack: Msg_ACK): bool
        %{
        //Debug printf("\tdeliver_Msg_ACK - begin\n");
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg_ack->header());
        info = assignMsgType(info, msg_ack->header());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                              connection()->bro_analyzer()->Conn(),
                                              info);
        //Debug printf("\tdeliver_Msg_ACK - end\n");
        return true;
        %}

    #
    # Message Error
    #
    function deliver_Msg_ERR(msg_err: Msg_ERR): bool
        %{
        //Debug printf("\tdeliver_Msg_ERR - begin\n");
        zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

        info = assignMsgHeader(info, msg_err->header());
        info = assignMsgType(info, msg_err->header());

        zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                              connection()->bro_analyzer()->Conn(),
                                              info);
        //Debug printf("\tdeliver_Msg_ERR - end\n");
        return true;
        %}

    #
    # Message Body 
    #
    function deliver_Msg_Body(msg_body: Msg_Body): bool
        %{
        //Debug printf("\tdeliver_Msg_Body - begin\n");
        // If the encoding mask is NOT valid, then dump out the message body
        // info we have so far
        if (! valid_encoding(msg_body->encoding_mask())) {
           zeek::RecordValPtr info = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::OPCUA_Binary::Info);

           info = assignMsgHeader(info, msg_body->header());
           info = assignMsgType(info, msg_body->header());

           zeek::BifEvent::enqueue_opcua_binary_event(connection()->bro_analyzer(),
                                              connection()->bro_analyzer()->Conn(),
                                              info);
        }
        //Debug printf("\tdeliver_Msg_Body - end\n");
        return true;
        %}
};
