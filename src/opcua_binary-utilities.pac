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
/*
Note: 
The binpac compiler generates one header file along with the associated source file so there
isn't a need to bring in additional headers here.  We'll just track header files in the
opcua_binary-analyzer.pac binpac file.  See the build/opcua_binary_pac.h and 
build/opcua_binary_pac.cc file(s) for details.
*/
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
    void flattenNodeId(zeek::RecordValPtr service_object, OpcUA_NodeId *node_ptr, uint32 offset);
    void flattenExpandedNodeId(zeek::RecordValPtr service_object, OpcUA_ExpandedNodeId *node_ptr, uint32 offset);
    bool validEncoding(uint8_t encoding);
    uint32_t uint8VectorToUint32(vector<binpac::uint8> *data);
    double bytestringToDouble(bytestring data);
    string generateId();
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
    uint32_t uint8VectorToUint32(vector<binpac::uint8> *data) {
        uint32 number = 0;
        for ( uint8 i = 0; i < data->size(); ++i ) {
            number <<= 8;
            number |= data->at(i);
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

    // Utility function to flatten NodeID objects
    void flattenNodeId(zeek::RecordValPtr service_object, OpcUA_NodeId *node_ptr, uint32 offset){
        service_object->Assign((offset+0), zeek::make_intrusive<zeek::StringVal>(uint8ToHexstring(node_ptr->identifier_type())));
        switch (node_ptr->identifier_type()) {
            case node_encoding::TwoByte : service_object->Assign((offset+1), zeek::val_mgr->Count(node_ptr->two_byte_numeric()->numeric()));
                                        break;
            case node_encoding::FourByte :
                                        service_object->Assign((offset+2), zeek::val_mgr->Count(node_ptr->four_byte_numeric()->namespace_index()));
                                        service_object->Assign((offset+1), zeek::val_mgr->Count(node_ptr->four_byte_numeric()->numeric()));
                                        break;
            case node_encoding::Numeric :
                                        service_object->Assign((offset+2), zeek::val_mgr->Count(node_ptr->numeric()->namespace_index()));
                                        service_object->Assign((offset+1), zeek::val_mgr->Count(node_ptr->numeric()->numeric()));
                                        break;
            case node_encoding::String :
                                        service_object->Assign((offset+2), zeek::val_mgr->Count(node_ptr->string()->namespace_index()));
                                        service_object->Assign((offset+3), zeek::make_intrusive<zeek::StringVal>(std_str(node_ptr->string()->string()->string())));
                                        break;
            case node_encoding::GUID :
                                        service_object->Assign((offset+2), zeek::val_mgr->Count(node_ptr->guid()->namespace_index()));
                                        service_object->Assign((offset+4), zeek::make_intrusive<zeek::StringVal>(guidToGuidstring(node_ptr->guid()->guid()->data1(),
                                                                                                                                                    node_ptr->guid()->guid()->data2(),
                                                                                                                                                    node_ptr->guid()->guid()->data3(),
                                                                                                                                                    node_ptr->guid()->guid()->data4())));
                                        break;
            case node_encoding::Opaque :
                                        service_object->Assign((offset+2), zeek::val_mgr->Count(node_ptr->opaque()->namespace_index()));
                                        service_object->Assign((offset+5), zeek::make_intrusive<zeek::StringVal>(bytestringToHexstring(node_ptr->opaque()->opaque()->byteString())));
                                        break;
        }
    }
    // Utility function to flatten ExpandedNodeID objects
    void flattenExpandedNodeId(zeek::RecordValPtr service_object, OpcUA_ExpandedNodeId *node_ptr, uint32 offset){
        flattenNodeId(service_object, node_ptr->node_id(), offset);
        if (isBitSet(node_ptr->node_id()->identifier_type(), NamespaceUriFlag)){
            service_object->Assign((offset+6), zeek::make_intrusive<zeek::StringVal>(std_str(node_ptr->namespace_uri()->string())));
        }
        if (isBitSet(node_ptr->node_id()->identifier_type(), ServerIndexFlag)){
            service_object->Assign((offset+7), zeek::val_mgr->Count(node_ptr->server_idx()));
        }
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
    function uint8_array_to_uint32(data: uint8[]): uint32
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

        return(uint8VectorToUint32(data));
    %}
};