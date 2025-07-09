#!/usr/bin/env bash
# Quick regression test for pending-table overflow logic.
# Returns 0 if expected debug messages are present in Zeek stdout.
set -euo pipefail

# Determine repository root (two directories up from this script)
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Ensure Zeek can find the OPCUA Binary scripts and compiled plugin without requiring installation
export ZEEKPATH="$REPO_ROOT/scripts:${ZEEKPATH:-}"
export ZEEK_PLUGIN_PATH="$REPO_ROOT/build:${ZEEK_PLUGIN_PATH:-}"

PCAP="$(dirname "$0")/../traces/pending_overflow.pcap"

if [[ ! -f "$PCAP" ]]; then
  echo "pcap not found: $PCAP" >&2
  exit 1
fi

OUTPUT=$(zeek icsnpp/opcua-binary/ -Cr "$PCAP" \
  -e "redef ICSNPP_OPCUA_Binary::DEBUG_MODE = T; \
  redef ICSNPP_OPCUA_Binary::MAX_PENDING_REQUESTS = 10; \
  redef ICSNPP_OPCUA_Binary::MAX_PENDING_RESPONSES = 10;")

# The pending_overflow.pcap has 12 requests and 12 responses none of which line up (all orphaned)
# That means when processing the pcap we should see 2 messages flushed when limit exceeded (both req & resp - meaning 4 messages in total)
# Finally upon cleanup we should see the remaining 10 requests and 10 responses logged
expected_leftover_req=10
expected_leftover_resp=10
expected_flush=2

# count leftover lines
leftover_req=$(printf '%s\n' "$OUTPUT" | grep -c 'Connection ending, leftover pending requests:')
leftover_resp=$(printf '%s\n' "$OUTPUT" | grep -c 'Connection ending, leftover flushing pending responses')

# count flush lines
flush_req=$(printf '%s\n' "$OUTPUT" | grep -c 'MAX_PENDING_REQUESTS reached, flushing pending request')
flush_resp=$(printf '%s\n' "$OUTPUT" | grep -c 'MAX_PENDING_RESPONSES reached, flushing pending response')

if [[ $leftover_req -eq $expected_leftover_req && $leftover_resp -eq $expected_leftover_resp && $flush_req -eq $expected_flush && $flush_resp -eq $expected_flush ]]; then
  echo "PASS: overflow logic behaved as expected." >&2

  # Clean up any log files generated during the test
  rm -f *.log
  exit 0
else
  echo "FAIL: counts did not match expectations" >&2
  echo "  leftover request lines: $leftover_req expected $expected_leftover_req" >&2
  echo "  leftover response lines: $leftover_resp expected $expected_leftover_resp" >&2
  echo "  flushed request lines: $flush_req expected $expected_flush" >&2
  echo "  flushed response lines: $flush_resp expected $expected_flush" >&2
  exit 1
fi

