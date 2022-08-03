%header{

    void printOpcUA_DiagInfo(int indent_width, OpcUA_DiagInfo *diagInfo);
    void printOpcUA_ViewDescription(int indent_width, OpcUA_ViewDescription *viewInfo);
    void printOpcUA_ExtensionObject(int indent_width, OpcUA_ExtensionObject *obj);
    void printOpcUA_LocaleId(int indent_width, OpcUA_LocaleId *obj);
    void printOpcUA_LocaleIdVec(int indent_width, vector<OpcUA_LocaleId *> *obj);
    void printOpcUA_SignedSoftwareCertificate(int indent_width, OpcUA_SignedSoftwareCertificate *obj);
    void printOpcUA_SignedSoftwareCertificateVec(int indent_width, vector<OpcUA_SignedSoftwareCertificate *> *obj);
    void printOpcUA_SignatureData(int indent_width, string field, OpcUA_SignatureData *obj);
    void printOpcUA_AnonymousIdentityToken(int indent_width, OpcUA_AnonymousIdentityToken *obj);
    void printOpcUA_UserNameIdentityToken(int indent_width, OpcUA_UserNameIdentityToken *obj);
    void printOpcUA_X509IdentityToken(int indent_width, OpcUA_X509IdentityToken *obj);
    void printOpcUA_IssuedIdentityToken(int indent_width, OpcUA_IssuedIdentityToken *obj);
    void printOpcUA_DiagInfo(int indent_width, OpcUA_DiagInfo *diagInfo);
%}

%code{
    void printOpcUA_DiagInfo(int indent_width, OpcUA_DiagInfo *diagInfo) {
        printf("%s EncodingMask: 0x%02x\n", indent(indent_width).c_str(), diagInfo->encoding_mask());

        // Symbolic Id
        if (isBitSet(diagInfo->encoding_mask(), hasSymbolicId)) {
            int32 idx = diagInfo->symbolic_id();
            printf("%s SymbolicId: %d\n", indent(indent_width).c_str(), idx);
        }

        // Namespace URI
        if (isBitSet(diagInfo->encoding_mask(), hasNamespaceUri)) {
            int32 idx = diagInfo->namespace_uri();
            printf("%s Namespace: %d\n", indent(indent_width).c_str(), idx);
        }

        // Localized Text
        if (isBitSet(diagInfo->encoding_mask(), hasLocalizedTxt)) {
            int32 idx = diagInfo->localized_txt();
            printf("%s LocalizedText: %d\n", indent(indent_width).c_str(), idx);
        }

        // Locale
        if (isBitSet(diagInfo->encoding_mask(), hasLocale)) {
            int32 idx = diagInfo->locale();
            printf("%s Locale: %d\n", indent(indent_width).c_str(), idx);
        }

        // Additional Information
        if (isBitSet(diagInfo->encoding_mask(), hasAddlInfo)) {
            string str = std_str(diagInfo->addl_info()->string());
            printf("%s AdditionalInfo: %s\n", indent(indent_width).c_str(), str.c_str());
        }

        // Inner Status Code
        if (isBitSet(diagInfo->encoding_mask(), hasInnerStatCode)) {
            printf("%s InnerStatusCode: 0x%08x [%s]\n", indent(indent_width).c_str(), diagInfo->inner_stat_code(), STATUS_CODE_MAP.find(diagInfo->inner_stat_code())->second.c_str());
        }

        // Inner Diagnostic Info
        if (isBitSet(diagInfo->encoding_mask(), hasInnerDiagInfo)) {
            printf("%s Inner DiagnosticInfo: DiagnosticInfo\n", indent(indent_width).c_str());
            printOpcUA_DiagInfo(indent_width + 1, diagInfo->inner_diag_info());
        }

        return;
    }


    void printOpcUA_ViewDescription(int indent_width, OpcUA_ViewDescription *viewInfo) {
        printf("%s View: ViewDescription\n", indent(indent_width).c_str());
        printf("%s ViewId: NodeId\n", indent(indent_width + 1).c_str());
        printOpcUA_NodeId(indent_width + 2,viewInfo->view_id());
        if (viewInfo->timestamp() > 0){
            printf("%s Timestamp: %lld\n", indent(indent_width + 1).c_str(), viewInfo->timestamp());
        } else {
            printf("%s Timestamp: No time specified (0)\n", indent(indent_width + 1).c_str());
        }
        printf("%s ViewVersion: %d\n", indent(indent_width + 1).c_str(), viewInfo->view_version());
    }


    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.32 Table 173 - SignatureData
    //
    void printOpcUA_SignatureData(int indent_width, string field, OpcUA_SignatureData *obj) {
        printf("%s %s: SignatureData\n", indent(indent_width).c_str(), field.c_str());
        if (obj->algorithm()->length() > 0) {
            printf("%s Algorithm: %s\n", indent(indent_width+1).c_str(), std_str(obj->algorithm()->string()).c_str());
        } else {
            printf("%s Algorithm: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        if (obj->signature()->length() > 0) {
            printf("%s Signature: %s\n", indent(indent_width+1).c_str(), bytestringToHexstring(obj->signature()->byteString()).c_str());
        } else {
            printf("%s Signature: <MISSING>[OpcUa Null ByteString]\n", indent(indent_width+1).c_str());
        }
    }

    //
    // UA Specification Part 3 - Address Space Model 1.04.pdf
    //
    // 8.4 LocaleId
    //
    void printOpcUA_LocaleId(int indent_width, OpcUA_LocaleId *obj) {
        printf("%s LocaleIds:  %s\n", indent(indent_width+1).c_str(), std_str(obj->locale_id()).c_str());
    }

    void printOpcUA_LocaleIdVec(int indent_width, vector<OpcUA_LocaleId *> *obj) {
        for (int i = 0; i < obj->size(); i++) {
            printf("%s [%d]: LocaleIds:  %s\n", indent(indent_width+1).c_str(), i, std_str(obj->at(i)->locale_id()).c_str());
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.33 Table 174 - SignedSoftwareCertificate
    //
    void printOpcUA_SignedSoftwareCertificate(int indent_width, OpcUA_SignedSoftwareCertificate *obj) {
        printf("%s CertificateDate:  %s\n", indent(indent_width).c_str(), std_str(obj->certificate_data()->byteString()).c_str());
        printf("%s Signature:  %s\n", indent(indent_width).c_str(), std_str(obj->signature()->byteString()).c_str());
    }

    void printOpcUA_SignedSoftwareCertificateVec(int indent_width, vector<OpcUA_SignedSoftwareCertificate *> *obj) {
        for (int i = 0; i < obj->size(); i++) {
            printf("%s [%d]: ClientSoftwareCert:\n", indent(indent_width+1).c_str(), i);
            printOpcUA_SignedSoftwareCertificate(indent_width+2, obj->at(i));
        }
    }

    //
    // UA Specification Part 6 - Mappings 1.04.pdf
    //
    // 5.2.2.15 Table 14 - ExtensionObject
    //
    void printOpcUA_ExtensionObject(int indent_width, OpcUA_ExtensionObject *obj) {
        string extension_obj_str = EXTENSION_OBJECT_ID_MAP.find(getExtensionObjectId(obj->type_id()))->second;
        printf("%s %s: ExtensionObject\n", indent(indent_width).c_str(), extension_obj_str.c_str());

        // TypeId
        printf("%s TypeId: ExpandedNodeId\n", indent(indent_width+1).c_str());
        printOpcUA_NodeId(indent_width+2, obj->type_id());
        
        // Extension Object Encoding Mask
        if (isBitSet(obj->encoding(), hasNoEncoding)) {
            printf("%s Encoding Mask: 0x%02x has no encoding\n", indent(indent_width+1).c_str(), obj->encoding());
        } else if (isBitSet(obj->encoding(), hasBinaryEncoding)) {
            printf("%s Encoding Mask: 0x%02x has binary body\n", indent(indent_width+1).c_str(), obj->encoding());
        } else if (isBitSet(obj->encoding(), hasXMLEncoding)) {
            printf("%s Encoding Mask: 0x%02x has XML body\n", indent(indent_width+1).c_str(), obj->encoding());
        }

        // Extension Object
        switch (getExtensionObjectId(obj->type_id())) {
            case AnonymousIdentityToken_Key: 
                printOpcUA_AnonymousIdentityToken(indent_width+1, obj->anonymous_identity_token());
                break;
            case UserNameIdentityToken_Key:  
                printOpcUA_UserNameIdentityToken(indent_width+1, obj->username_identity_token());
                break;
            case X509IdentityToken_Key:      
                printOpcUA_X509IdentityToken(indent_width+1, obj->x509_identity_token());
                break;
            case IssuedIdentityToken_Key:    
                printOpcUA_IssuedIdentityToken(indent_width+1, obj->issued_identity_token());
                break;
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.3 Table 185 - AnonymousIdentityToken
    //
    void printOpcUA_AnonymousIdentityToken(int indent_width, OpcUA_AnonymousIdentityToken *obj) {
        printf("%s AnonymousIdentityToken: AnonymousIdentityToken\n", indent(indent_width).c_str());

        // Policy Id
        if (obj->policy_id()->length() > 0) {
            printf("%s PolicyId: %s\n", indent(indent_width+1).c_str(), std_str(obj->policy_id()->string()).c_str());
        } else {
            printf("%s PolicyId: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.4 Table 186 - UserNameIdentityToken
    //
    void printOpcUA_UserNameIdentityToken(int indent_width, OpcUA_UserNameIdentityToken *obj) {
        printf("%s UserNameIdentityToken: UserNameIdentityToken\n", indent(indent_width).c_str());

        // Policy Id
        if (obj->policy_id()->length() > 0) {
            printf("%s PolicyId: %s\n", indent(indent_width+1).c_str(), std_str(obj->policy_id()->string()).c_str());
        } else {
            printf("%s PolicyId: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Username
        if (obj->user_name()->length() > 0) {
            printf("%s UserName: %s\n", indent(indent_width+1).c_str(), std_str(obj->user_name()->string()).c_str());
        } else {
            printf("%s UserName: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Password
        if (obj->password()->length() > 0) {
            printf("%s Password: %s\n", indent(indent_width+1).c_str(), std_str(obj->password()->byteString()).c_str());
        } else {
            printf("%s Password: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Encryption Algorithm
        if (obj->encryption_algorithm()->length() > 0) {
            printf("%s EncryptionAlgorithm: %s\n", indent(indent_width+1).c_str(), std_str(obj->encryption_algorithm()->string()).c_str());
        } else {
            printf("%s EncryptionAlgorithm: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.5 Table 188 - X509IdentityToken
    //
    void printOpcUA_X509IdentityToken(int indent_width, OpcUA_X509IdentityToken *obj) {
        printf("%s X509IdentityToken: X509IdentityToken\n", indent(indent_width).c_str());

        // Policy Id
        if (obj->policy_id()->length() > 0) {
            printf("%s PolicyId: %s\n", indent(indent_width+1).c_str(), std_str(obj->policy_id()->string()).c_str());
        } else {
            printf("%s PolicyId: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Certificate Data
        if (obj->certificate_data()->length() > 0) {
            printf("%s CertificateData: %s\n", indent(indent_width+1).c_str(), bytestringToHexstring(obj->certificate_data()->byteString()).c_str());
        } else {
            printf("%s CertificateData: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }
    }

    //
    // UA Specification Part 4 - Services 1.04.pdf
    //
    // 7.36.6 Table 189 - IssuedIdentityToken
    //
    void printOpcUA_IssuedIdentityToken(int indent_width, OpcUA_IssuedIdentityToken *obj) {
        printf("%s IssuedIdentityToken: IssuedIdentityToken\n", indent(indent_width).c_str());

        // Policy Id
        if (obj->policy_id()->length() > 0) {
            printf("%s PolicyId: %s\n", indent(indent_width+1).c_str(), std_str(obj->policy_id()->string()).c_str());
        } else {
            printf("%s PolicyId: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Token Data
        if (obj->token_data()->length() > 0) {
            printf("%s TokenData: %s\n", indent(indent_width+1).c_str(), bytestringToHexstring(obj->token_data()->byteString()).c_str());
        } else {
            printf("%s TokenData: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }

        // Encryption Algorithm
        if (obj->encryption_algorithm()->length() > 0) {
            printf("%s EncryptionAlgorithm: %s\n", indent(indent_width+1).c_str(), std_str(obj->encryption_algorithm()->string()).c_str());
        } else {
            printf("%s EncryptionAlgorithm: [OpcUa Null String]\n", indent(indent_width+1).c_str());
        }
    }

%}

