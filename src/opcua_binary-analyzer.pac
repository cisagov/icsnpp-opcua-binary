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
#include "consts.h"
#include "status_codes.h"
#include "node_identifiers.h"
#include "types.h"
%}

%header{
    #define ID_LEN 9

    double winFiletimeToUnixTime(uint64 win_filetime);
    string bytestringToHexstring(const_bytestring data);
    string guidToGuidstring(const_bytestring data1, const_bytestring data2, const_bytestring data3, const_bytestring data4);
    string uint32ToHexstring(uint32_t data);
    string uint8ToHexstring(uint8_t data);
    string getEndpointUrl(const_bytestring endpoint_url);
    bool isBitSet(uint8_t encoding, uint8_t mask);
    bool validEncoding(uint8_t encoding);
    uint32_t bytestringToUint32(bytestring data);
    double bytestringToDouble(bytestring data);
    string generateId();

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
    // Utility function used to generate unique id associated with the OpcUA logs.  While
    // this id is NOT part of the OpcUA documented spec, we use it to tie nested log files
    // together - e.g. any nested log files such as the status code detail log will contain
    // this id which can be used to reference back to the primary OpcUA log file.
    //
    // The implemenation was taken from: https://lowrey.me/guid-generation-in-c-11/
    //
    std::string generateId() {
        std::stringstream ss;
        for (auto i = 0; i < ID_LEN; i++) {
            // Generate a random char
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            const auto rc = dis(gen);

            // Hex representaton of random char
            std::stringstream hexstream;
            hexstream << std::hex << rc;
            auto hex = hexstream.str();
            ss << (hex.length() < 2 ? '0' + hex : hex);
        }
        return ss.str();
    }

    //
    // Utility function to convert a bytestring to uint32
    // 
    uint32_t bytestringToUint32(bytestring data) {
        uint32 number = 0;
        for ( uint8 i = 0; i < data.length(); ++i ) {
            number <<= 8;
            number |= data[i];
        }
        return number;
    }

    //
    // Utility function to convert a bytestring to double
    // 
    double bytestringToDouble(bytestring data) {
        double d;
        memcpy(&d, data.begin(), sizeof(double));

        return d;
    }

    //
    // Utility function to validate the encoding mask
    // 
    bool validEncoding(uint8_t encoding) {
         if ((encoding == node_encoding::TwoByte)          || 
             (encoding == node_encoding::FourByte)         ||
             (encoding == node_encoding::Numeric)          ||
             (encoding == node_encoding::String)           ||
             (encoding == node_encoding::GUID)             ||
             (encoding == node_encoding::Opaque)           ||
             (encoding == node_encoding::NamespaceUriFlag) ||
             (encoding == node_encoding::ServerIndexFlag)) {
                return true;
        } else {
               return false;
        }
    }

    //
    // Convert from a Win32 FILETIME to UNIX time.  Under UNIX, file times
    // are maintained as the number of seconds since midnight January 1, 1970
    // UTC (UNIX epoch).  Under Win32 platforms, file times represent the number of
    // of 100-nanosecond intervals since January 1, 1601 UTC (Win32 epoch).
    //
    // Reference:
    //   https://stackoverflow.com/questions/6161776/convert-windows-filetime-to-second-in-unix-linux/6161842
    //   http://support.microsoft.com/kb/167296
    //   https://en.wikipedia.org/wiki/Unix_time
    //
    double winFiletimeToUnixTime(uint64 win_filetime) {
        double WINDOWS_TICK      = 10000000.0;

        // Number of seconds between Win32 epoch and UNIX epoch
        uint64 SEC_TO_UNIX_EPOCH = 11644473600;

        // Convert Win32 filetime to seconds, then adjust time to UNIX epoch.
        return((win_filetime / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH);
    }

    //
    // Convert a GUID to a GUID string representation based on  UA 
    // Specification Part 6 - Mappings 1.04.pdf.
    //
    // 5.1.3 Guid
    // A Guid is a 16-byte globally unique identifier.  Guid values may be represented
    // as a string in this form:
    //    <Data1>-<Data2>-<Data3>-<Data4[0:1]>-<Data4[2:7]>
    // Where Data1 is 8 characters wide, Data2 and Data3 are 4 characters wide and each
    // Byte in Data4 is 2 characters wide. Each value is formatted as a hexadecimal
    // number with padded zeros. A typical Guid value would look like this when
    // formatted as a string:
    //    C496578A-0DFE-4B8F-870A-745238C6AEAE
    //
    string guidToGuidstring(const_bytestring data1, const_bytestring data2, const_bytestring data3, const_bytestring data4) {
        stringstream ss;

        // Data 1
        ss << std::hex;
        for ( int i = 0; i < data1.length(); ++i ) {
            ss << std::setw(2) << std::setfill('0') << (int)data1[i];
        }

        // Data 1
        ss << "-";
        for ( int i = 0; i < data2.length(); ++i ) {
            ss << std::setw(2) << std::setfill('0') << (int)data2[i];
        }

        // Data 1
        ss << "-";
        for ( int i = 0; i < data3.length(); ++i ) {
            ss << std::setw(2) << std::setfill('0') << (int)data3[i];
        }

        // Data 4
        ss << "-";
        for ( int i = 0; i < data4.length(); ++i ) {
            if (i == 2) {
                ss << "-";
            }
            ss << std::setw(2) << std::setfill('0') << (int)data4[i];
        }

        return ss.str();
    }

    //
    // Convert a bytestring to a hex string representation
    //
    string bytestringToHexstring(const_bytestring data){
        stringstream ss;

        // Cap the length to 24 bytes ...
        uint8 max_byte_length = (data.length() < 24 ? data.length() : 24);

        ss << "0x";
        ss << std::hex;
        for ( int i = 0; i < max_byte_length; ++i ){
            ss << std::setw(2) << std::setfill('0') << (int)data[i];
        }

        if (data.length() > max_byte_length) {
            ss << "...";
        }
        return ss.str();
    }

    //
    // Convert a uint32_t value to hex string representation.
    //
    string uint32ToHexstring(uint32_t data) {
        stringstream ss;
        ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << data;
        return ss.str();
    }

    //
    // Convert a uint8_t value to hex string representation.
    //
    string uint8ToHexstring(uint8_t data) {
        stringstream ss;
        ss << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data);
        return ss.str();
    }

    //
    // Convert the bytestring endpoint_url to a string.
    //
    // NOTE: In some cases the endpoint_url have NULL bytes at the front
    //       of the bytestring.  Therefore, we loop over the bytestring
    //       back to front until a NULL byte is encountered - then reverse the
    //       string.
    //
    string getEndpointUrl(const_bytestring endpoint_url){
        string str = "";

        // Loop over the endpoint_url back to front
        for ( uint8 i = endpoint_url.length() - 1; i >= 0; i-- ) {
            if (endpoint_url[i] == 0) break;

            str += endpoint_url[i];
        }

        // Reverse the string
        int len = str.length();
        int n   = len -1;
        for (int i=0; i<(len/2); i++) {
            std::swap(str[i], str[n]);
            n = n -1;
        }

        return  str;
    }

    bool isBitSet(uint8_t encoding, uint8_t mask) {
        return((encoding & mask) > 0);
    }

    //
    // Common code used to assign the message header information to a zeek::RecordVal 
    // for future logging.
    //
    zeek::RecordValPtr assignMsgHeader(zeek::RecordValPtr info, Msg_Header *msg_header) {
        // OpcUA_id
        info->Assign(OPCUA_ID_IDX, zeek::make_intrusive<zeek::StringVal>(generateId()));

        // Msg header
        info->Assign(MSG_TYPE_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg_header->msg_type())));
        info->Assign(IS_FINAL_IDX, zeek::make_intrusive<zeek::StringVal>(std_str(msg_header->is_final())));
        info->Assign(MSG_SIZE_IDX, zeek::val_mgr->Count(msg_header->msg_size()));

        return info;
    }

    //
    // Common code used to determine the message type and assign the information to a zeek::RecordVal 
    // for future logging.
    //
    zeek::RecordValPtr assignMsgType(zeek::RecordValPtr info, Msg_Header *msg_header) {
        switch (bytestringToUint32(msg_header->msg_type())) {
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
    # See if the mask bit is set by ANDing the mask against the encoding.
    #
    function is_bit_set(encoding: uint8, mask: uint8): bool
    %{
        return(isBitSet(encoding, mask));
    %}

    #
    # Utility function to validate the encoding mask
    #
    function valid_encoding(encoding: uint8): bool
    %{
        return(validEncoding(encoding));
    %}

    #
    # Utility function to bind a binpac &length to 0 or more.  In the Opc UA
    # specification , a value of -1 is used in several places to indicate
    # a empty or 'null' value.  Unfortunately, binpac does not like it when a 
    # &length is set to -1; therefore, we bind the length to be 0 or more.
    #
    function bind_length(len: int): int
    %{
         return((len < 0) ? 0 : len);
    %}

    #
    # Utility function to convert a bytestring to uint32
    #
    function bytestring_to_uint32(data: bytestring): uint32
    %{
    /* Debug
        switch (bytestringToUint32(data)) {
            case HEL: printf("LOOK: HEL\n");
                      break;
            case ACK: printf("LOOK: ACK\n");
                      break;
            case ERR: printf("LOOK: ERR\n");
                      break;
            case OPN: printf("LOOK: OPN\n");
                      break;
            case MSG: printf("LOOK: MSG\n");
                      break;
            case CLO: printf("LOOK: CLO\n");
                      break;
            case RHE: printf("LOOK: RHE\n");
                      break;
        }
    */

        return(bytestringToUint32(data));
    %}

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
