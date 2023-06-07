// OPCUA_Binary.cc
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#ifndef ANALYZER_PROTOCOL_OPCUA_BINARY_H
#define ANALYZER_PROTOCOL_OPCUA_BINARY_H

#if __has_include(<zeek/zeek-version.h>)
#include <zeek/zeek-version.h>
#else
#include <zeek/zeek-config.h>
#endif

#include "events.bif.h"


#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "opcua_binary_pac.h"

namespace analyzer { namespace ICSNPP_OPCUA_Binary {

class OPCUA_Binary_Analyzer

: public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {

public:
	OPCUA_Binary_Analyzer(zeek::Connection* conn);
	virtual ~OPCUA_Binary_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64_t seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);
	

	static zeek::analyzer::Analyzer* InstantiateAnalyzer(zeek::Connection* conn)
		{ return new OPCUA_Binary_Analyzer(conn); }

protected:
	binpac::OPCUA_Binary::OPCUA_Binary_Conn* interp;
	
	bool had_gap;
	
};

} } // namespace analyzer::* 

#endif
