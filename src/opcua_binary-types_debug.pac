%header{
    void printOpcUA_DiagInfo(int indent_width, OpcUA_DiagInfo *diagInfo);
    void printOpcUA_ViewDescription(int indent_width, OpcUA_ViewDescription *viewInfo);
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
        printOpcUaNodeId(indent_width + 2,viewInfo->view_id());
        if (viewInfo->timestamp() > 0){
            printf("%s Timestamp: %lld\n", indent(indent_width + 1).c_str(), viewInfo->timestamp());
        } else {
            printf("%s Timestamp: No time specified (0)\n", indent(indent_width + 1).c_str());
        }
        printf("%s ViewVersion: %d\n", indent(indent_width + 1).c_str(), viewInfo->view_version());
    }

%}