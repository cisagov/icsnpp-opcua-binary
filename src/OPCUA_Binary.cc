// OPCUA_Binary.cc
//
// OPCUA Binary Protocol Analyzer
//
// Author:   Kent Kvarfordt
// Contact:  kent.kvarfordt@inl.gov
//
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

#include "OPCUA_Binary.h"

#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

#include "zeek/Reporter.h"

#include "events.bif.h"

using namespace analyzer::ICSNPP_OPCUA_Binary;

OPCUA_Binary_Analyzer::OPCUA_Binary_Analyzer(zeek::Connection* c)

: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("ICSNPP_OPCUA_BINARY", c)

	{
	interp = new binpac::OPCUA_Binary::OPCUA_Binary_Conn(this);
	
	had_gap = false;
	
	}

OPCUA_Binary_Analyzer::~OPCUA_Binary_Analyzer()
	{
	delete interp;
	}

void OPCUA_Binary_Analyzer::Done()
	{
	
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	
	}

void OPCUA_Binary_Analyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void OPCUA_Binary_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());
	if ( TCP()->IsPartial() )
		return;

	if ( had_gap )
		// If only one side had a content gap, we could still try to
		// deliver data to the other side if the script layer can handle this.
		return;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{

		/* Debug
		printf("\n###############################\n");
		printf(" EXCEPTION:\n");
		printf("     %s \n", e.c_msg());
		printf("###############################\n\n");
		*/

		AnalyzerViolation(zeek::util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void OPCUA_Binary_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
	had_gap = true;
	interp->NewGap(orig, len);
	}
