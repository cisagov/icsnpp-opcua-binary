## opcua_binary-debug.pac
##
## OPCUA Binary Protocol Analyzer
##
## Development/Debug utilities 
##
## Author:   Kent Kvarfordt
## Contact:  kent.kvarfordt@inl.gov
##
## Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

%header{
    string indent(int level);
    void printMsgHeader( Msg_Header *msg_header);
    void printMsgHEL( Msg_HEL *msg_hel);
    void printMsgACK( Msg_ACK *msg_ack);
    void printMsgERR( Msg_ERR *msg_err);
    void printMsgOPN( Msg_OPN *msg_opn);
    void printMsgCLO( Msg_CLO *msg_clo);
    void printMsgMSG( Msg_MSG *msg_msg);
    void printMsgType( Msg_Header *msg_header);
    void printService(Service *service);

%}

%code{
    string indent(int level) {
        std::stringstream ss;
        int padding = 4;

        ss << setw(padding * level) << ' ';

        return ss.str();
    }

    void printMsgHeader( Msg_Header *msg_header) {
       // Stubbed out 
       return;
    }

    void printMsgHEL( Msg_HEL *msg_hel) {
       // Stubbed out 
       return;
    }

    void printMsgACK( Msg_ACK *msg_ack) {
       // Stubbed out 
       return;
    }

    void printMsgERR( Msg_ERR *msg_err) {
       // Stubbed out 
       return;
    }

    void printMsgOPN( Msg_OPN *msg_opn) {
       // Stubbed out 
       return;
    }

    void printMsgCLO( Msg_CLO *msg_clo) {
       // Stubbed out 
       return;
    }

    void printMsgMSG( Msg_MSG *msg_msg) {
       // Stubbed out 
       return;
    }

    void printMsgType( Msg_Header *msg_header) {
        switch (uint8VectorToUint32(msg_header->msg_type())) {
            case HEL: printMsgHEL( msg_header->hel());
                      break;
            case ACK: printMsgACK( msg_header->ack());
                      break;
            case ERR: printMsgERR( msg_header->err());
                      break;
            case OPN: printMsgOPN( msg_header->opn());
                      break;
            case MSG: printMsgMSG( msg_header->msg());
                      break;
            case CLO: printMsgCLO( msg_header->clo());
                      break;
        }

        return;
    }

    void printService(Service *service) {
        printf("%s TypeId: ExpandedNodeId\n", indent(2).c_str());
        printf("%s NodeId EncodingMask: 0x%x\n", indent(3).c_str(), service->msg_body()->encoding_mask());
        printf("%s NodeId Namespace Index: %d\n", indent(3).c_str(), service->namespace_idx());
        printf("%s NodeId Identifier Numeric: %s (%d)\n", indent(3).c_str(), NODE_IDENTIFIER_MAP.find(service->identifier())->second.c_str(), service->identifier());

        return;
    }

%}