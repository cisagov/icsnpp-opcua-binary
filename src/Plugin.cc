// Plugin.cc
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#include "Plugin.h"
#include "zeek/analyzer/Component.h"
#include "OPCUA_Binary.h"

namespace plugin { namespace ICSNPP_OPCUA_Binary { Plugin plugin; } }

using namespace plugin::ICSNPP_OPCUA_Binary;

zeek::plugin::Configuration Plugin::Configure()
   {
     AddComponent(new zeek::analyzer::Component("ICSNPP_OPCUA_BINARY",
                      ::analyzer::ICSNPP_OPCUA_Binary::OPCUA_Binary_Analyzer::InstantiateAnalyzer));

     zeek::plugin::Configuration config;
     config.name = "ICSNPP::OPCUA_Binary";
     config.description = "OPC Unified Architecture Binary Protocol analyzer";
     config.version.major = 0;
     config.version.minor = 1;
     config.version.patch = 0;
     return config;
   }
