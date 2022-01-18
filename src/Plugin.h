
// Plugin.h
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef BRO_PLUGIN_OPCUA_BINARY
#define BRO_PLUGIN_OPCUA_BINARY

#include <zeek/plugin/Plugin.h>

namespace plugin {
namespace ICSNPP_OPCUA_Binary {

class Plugin : public zeek::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
