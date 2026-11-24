#!/usr/bin/env python3
"""Generate opcua_call_service.pcap, a synthetic OPC UA Binary trace for the Call service.

Written with the help of Claude Code (model: claude-opus-5-5) and reviewed by hand.
It uses only the Python standard library and writes the same bytes on every run.

The trace has one IPv4 TCP connection to 4840/tcp (handshake, two MSG request/response
pairs, FIN). There are no HEL/ACK/OPN messages, like the *-no-handshake traces. It covers
the Call paths that open62541_client-server_mainloop.pcap does not reach:

  CallRequest  #1: two CallMethodRequests
                   [0] ObjectId ns=2;i=5001, MethodId ns=2;s="StartPump",
                       InputArguments [Int32 7, Double 2.5]
                   [1] ObjectId i=2253 (Server), MethodId i=11492 (GetMonitoredItems),
                       InputArguments [UInt32 array {1, 2}]
  CallResponse #1: two CallMethodResults
                   [0] Good, InputArgumentResults [Good, BadTypeMismatch],
                       InputArgumentDiagnosticInfos [empty, SymbolicId 3 + inner BadTypeMismatch],
                       OutputArguments [Int32 42, String "done"]
                   [1] BadMethodInvalid, all arrays null (-1)
                   DiagnosticInfos [SymbolicId 1, inner StatusCode BadMethodInvalid]
  CallRequest  #2: no MethodsToCall (empty array)
  CallResponse #2: ServiceResult BadNothingToDo, no Results,
                   DiagnosticInfos [SymbolicId 9, SymbolicId 10] (more entries than Results)

Usage: python3 opcua_call_service.pcap.py [output.pcap]
"""

import struct
import sys

CLIENT = (bytes([192, 168, 10, 20]), 50123)
SERVER = (bytes([192, 168, 10, 10]), 4840)
BASE_TS = 1_700_000_000

CALL_REQUEST = 712
CALL_RESPONSE = 715

GOOD = 0x00000000
BAD_NOTHING_TO_DO = 0x800F0000
BAD_TYPE_MISMATCH = 0x80740000
BAD_METHOD_INVALID = 0x80750000


def u8(v):
    return struct.pack("<B", v)


def u16(v):
    return struct.pack("<H", v)


def i32(v):
    return struct.pack("<i", v)


def u32(v):
    return struct.pack("<I", v)


def i64(v):
    return struct.pack("<q", v)


def ua_string(s):
    if s is None:
        return i32(-1)
    b = s.encode("utf-8")
    return i32(len(b)) + b


def nodeid_numeric(ns, ident):
    if ns == 0 and ident <= 0xFF:
        return u8(0x00) + u8(ident)  # TwoByte
    if ns <= 0xFF and ident <= 0xFFFF:
        return u8(0x01) + u8(ns) + u16(ident)  # FourByte
    return u8(0x02) + u16(ns) + u32(ident)  # Numeric


def nodeid_string(ns, s):
    return u8(0x03) + u16(ns) + ua_string(s)


def array(items):
    if items is None:
        return i32(-1)
    return i32(len(items)) + b"".join(items)


# Variant: encoding mask = built-in type id, 0x80 = array.
def variant_int32(v):
    return u8(6) + i32(v)


def variant_uint32_array(vals):
    return u8(0x80 | 7) + i32(len(vals)) + b"".join(u32(v) for v in vals)


def variant_double(v):
    return u8(11) + struct.pack("<d", v)


def variant_string(s):
    return u8(12) + ua_string(s)


# DiagnosticInfo: 0x01 SymbolicId, 0x20 InnerStatusCode (the masks this analyzer uses).
def diag_info(symbolic_id=None, inner_status=None):
    mask = 0
    body = b""
    if symbolic_id is not None:
        mask |= 0x01
        body += i32(symbolic_id)
    if inner_status is not None:
        mask |= 0x20
        body += u32(inner_status)
    return u8(mask) + body


FILETIME = 133_000_000_000_000_000  # 2022-06-22, Windows FILETIME


def request_header(handle):
    return (
        nodeid_numeric(0, 0)  # AuthenticationToken (null)
        + i64(FILETIME)  # Timestamp
        + u32(handle)  # RequestHandle
        + u32(0)  # ReturnDiagnostics
        + ua_string(None)  # AuditEntryId
        + u32(10000)  # TimeoutHint
        + nodeid_numeric(0, 0)
        + u8(0)  # AdditionalHeader: null ExtensionObject
    )


def response_header(handle, service_result=GOOD):
    return (
        i64(FILETIME)  # Timestamp
        + u32(handle)  # RequestHandle
        + u32(service_result)  # ServiceResult
        + u8(0)  # ServiceDiagnostics: empty DiagnosticInfo
        + array(None)  # StringTable
        + nodeid_numeric(0, 0)
        + u8(0)  # AdditionalHeader: null ExtensionObject
    )


def call_method_request(object_id, method_id, inputs):
    return object_id + method_id + array(inputs)


def call_method_result(status, arg_results, arg_diags, outputs):
    return (
        u32(status)
        + array(None if arg_results is None else [u32(s) for s in arg_results])
        + array(arg_diags)
        + array(outputs)
    )


def msg_chunk(request_id, seq, service_id, body):
    payload = (
        u32(1)  # SecureChannelId
        + u32(1)  # TokenId
        + u32(seq)  # SequenceNumber
        + u32(request_id)  # RequestId
        + nodeid_numeric(0, service_id)
        + body
    )
    return b"MSGF" + u32(8 + len(payload)) + payload


def build_messages():
    req1 = msg_chunk(
        1,
        51,
        CALL_REQUEST,
        request_header(1)
        + array(
            [
                call_method_request(
                    nodeid_numeric(2, 5001),
                    nodeid_string(2, "StartPump"),
                    [variant_int32(7), variant_double(2.5)],
                ),
                call_method_request(
                    nodeid_numeric(0, 2253),
                    nodeid_numeric(0, 11492),
                    [variant_uint32_array([1, 2])],
                ),
            ]
        ),
    )
    res1 = msg_chunk(
        1,
        51,
        CALL_RESPONSE,
        response_header(1)
        + array(
            [
                call_method_result(
                    GOOD,
                    [GOOD, BAD_TYPE_MISMATCH],
                    [diag_info(), diag_info(3, BAD_TYPE_MISMATCH)],
                    [variant_int32(42), variant_string("done")],
                ),
                call_method_result(BAD_METHOD_INVALID, None, None, None),
            ]
        )
        + array([diag_info(1), diag_info(inner_status=BAD_METHOD_INVALID)]),
    )
    req2 = msg_chunk(2, 52, CALL_REQUEST, request_header(2) + array([]))
    res2 = msg_chunk(
        2,
        52,
        CALL_RESPONSE,
        response_header(2, BAD_NOTHING_TO_DO) + array([]) + array([diag_info(9), diag_info(10)]),
    )
    return [(True, req1), (False, res1), (True, req2), (False, res2)]


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def tcp_packet(src, dst, seq, ack, flags, payload=b""):
    tcp_wo_sum = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = src[0] + dst[0] + struct.pack("!BBH", 0, 6, len(tcp_wo_sum) + len(payload))
    csum = checksum(pseudo + tcp_wo_sum + payload)
    tcp = tcp_wo_sum[:16] + struct.pack("!H", csum) + tcp_wo_sum[18:]
    total = 20 + len(tcp) + len(payload)
    ip_wo_sum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, 6, 0, src[0], dst[0])
    ip = ip_wo_sum[:10] + struct.pack("!H", checksum(ip_wo_sum)) + ip_wo_sum[12:]
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + ip + tcp + payload


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def build_packets():
    c_seq, s_seq = 1000, 5000
    pkts = [
        (CLIENT, SERVER, c_seq, 0, SYN, b""),
        (SERVER, CLIENT, s_seq, c_seq + 1, SYN | ACK, b""),
        (CLIENT, SERVER, c_seq + 1, s_seq + 1, ACK, b""),
    ]
    c_seq += 1
    s_seq += 1
    for from_client, data in build_messages():
        if from_client:
            pkts.append((CLIENT, SERVER, c_seq, s_seq, PSH | ACK, data))
            c_seq += len(data)
            pkts.append((SERVER, CLIENT, s_seq, c_seq, ACK, b""))
        else:
            pkts.append((SERVER, CLIENT, s_seq, c_seq, PSH | ACK, data))
            s_seq += len(data)
            pkts.append((CLIENT, SERVER, c_seq, s_seq, ACK, b""))
    pkts += [
        (CLIENT, SERVER, c_seq, s_seq, FIN | ACK, b""),
        (SERVER, CLIENT, s_seq, c_seq + 1, FIN | ACK, b""),
        (CLIENT, SERVER, c_seq + 1, s_seq + 1, ACK, b""),
    ]
    return [tcp_packet(*p) for p in pkts]


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for n, frame in enumerate(frames):
            f.write(struct.pack("<IIII", BASE_TS, n * 1000, len(frame), len(frame)))
            f.write(frame)


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "opcua_call_service.pcap"
    write_pcap(out, build_packets())
