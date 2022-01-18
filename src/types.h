// types.h
//
// OPCUA Binary Protocol Analyzer
//
// Type definitions to handle the details of status codes
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
//

#ifndef OPCUA_BINARY_TYPES_H
#define OPCUA_BINARY_TYPES_H

    typedef struct StatusCodeDetail {
        uint8_t     severity;
        std::string severityStr;
        uint8_t     subCode;
        std::string subCodeStr;
        bool        structureChanged;
        bool        semanticsChanged;
        uint8_t     infoType;
        std::string infoTypeStr;
        uint8_t     limitBits;
        std::string limitBitsStr;
        bool        overflow;
        uint8_t     historianBits;
        std::string historianBitsStr;
        bool        historianPartial;
        bool        historianExtraData;
        bool        historianMultiValue;

        StatusCodeDetail(uint32_t statusCode) {
            severity     = statusCode >> 30;
            severityStr = RESERVED;
            if (SEVERITY_MAP.find(severity) != SEVERITY_MAP.end()) {
                severityStr = SEVERITY_MAP.find(severity)->second;
            }
            
            subCode = (statusCode & SUBCODE_MASK) >> 16;

            // See if we can find the status code in the STATUS_CODE_MAP.  NOTE: Pre-defined 
            // status codes have the first two bits included in the definition.  Therefore, 
            // we only need to mask off the lower 16 bits to do the lookup STATUS_CODE_MAP.
            subCodeStr = "";
            if (STATUS_CODE_MAP.find(statusCode & STATUS_CODE_MASK) != STATUS_CODE_MAP.end()) {
                subCodeStr = STATUS_CODE_MAP.find(statusCode & STATUS_CODE_MASK)->second;
            }

            structureChanged = (statusCode & STRUCTURE_CHANGED_MASK) >> 15;
            semanticsChanged = (statusCode & SEMANTICS_CHANGED_MASK) >> 14;

            infoType = (statusCode & INFOTYPE_MASK) >> 10;
            infoTypeStr = RESERVED;
            if (INFO_TYPE_MAP.find(infoType) != INFO_TYPE_MAP.end()) {
                infoTypeStr = INFO_TYPE_MAP.find(infoType)->second;
            }

            limitBits    = (statusCode & LIMIT_BITS_MASK) >> 8;
            limitBitsStr = LIMIT_BITS_MAP.find(limitBits)->second;

            overflow = (statusCode & OVERFLOW_MASK) >> 7;

            historianBits = statusCode & HISTORIAN_BITS_MASK;
            historianBitsStr = RESERVED;
            if (HISTORIAN_BITS_MAP.find(historianBits) != HISTORIAN_BITS_MAP.end()) {
                historianBitsStr = HISTORIAN_BITS_MAP.find(historianBits)->second;
            }

            historianPartial    = (statusCode & HISTORIAN_PARTIAL_MASK)    >> 2;
            historianExtraData  = (statusCode & HISTORIAN_EXTRADATA_MASK)  >> 3;
            historianMultiValue = (statusCode & HISTORIAN_MULTIVALUE_MASK) >> 4;
        }

    } StatusCodeDetail;

#endif