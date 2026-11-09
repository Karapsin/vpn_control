"""Direct TUN traffic sampler: plain HTTP to the fixed benchmark address, with no SOCKS step.

The pattern of scripts/run_desktop_vpn_integration.py. It runs under the ordinary token only
while the row's own TUN is proven up, so each connection is captured by that TUN and answered
by the row's loopback upstream. It opens no listener and is never a negative control: without
the TUN this address would leave the guest. Standard library only.
"""
import json
import math
import socket
import sys
import time

TARGET = ("198.18.0.1", 80)
REQUEST = b"GET /probe HTTP/1.1\r\nHost: 198.18.0.1\r\nConnection: close\r\n\r\n"


def sample(expected, timeout, connect=socket.create_connection):
    with connect(TARGET, timeout=timeout) as stream:
        stream.settimeout(timeout)
        stream.sendall(REQUEST)
        raw = b""
        while len(raw) <= 65536 and (block := stream.recv(4096)):
            raw += block
    head, _, body = raw.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0] in (b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK") and body == expected


def run(value, emit, connect=socket.create_connection, sleep=time.sleep, monotonic=time.monotonic):
    if (type(value) is not dict or set(value) != {"schemaVersion", "expectedBodyHex", "sampleCount", "intervalSeconds", "ioTimeoutSeconds"}
            or value["schemaVersion"] != 1 or type(value["sampleCount"]) is not int or not 1 <= value["sampleCount"] <= 64
            or not all(type(value[key]) in (int, float) and math.isfinite(value[key]) and 0.02 <= value[key] <= 10
                       for key in ("intervalSeconds", "ioTimeoutSeconds"))
            or type(value["expectedBodyHex"]) is not str or not 0 < len(value["expectedBodyHex"]) <= 8192
            or value["expectedBodyHex"].strip("0123456789abcdef") or len(value["expectedBodyHex"]) % 2):
        raise ValueError("direct-sampler-input")
    expected, passed = bytes.fromhex(value["expectedBodyHex"]), 0
    for ordinal in range(value["sampleCount"]):
        started = monotonic()
        try:
            succeeded = sample(expected, value["ioTimeoutSeconds"], connect)
        except OSError as error:
            succeeded, reason = False, type(error).__name__
        else:
            reason = None if succeeded else "response"
        passed += succeeded
        emit({"kind": "sample", "ordinal": ordinal, "succeeded": succeeded, "reason": reason, "elapsedSeconds": monotonic() - started})
        if ordinal + 1 < value["sampleCount"]:
            sleep(value["intervalSeconds"])
    emit({"kind": "terminal", "sampleCount": value["sampleCount"], "allSamplesSucceeded": passed == value["sampleCount"]})
    return 0 if passed == value["sampleCount"] else 1


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--input":
        raise SystemExit(2)
    with open(sys.argv[2], "rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise SystemExit(2)
    raise SystemExit(run(json.loads(raw), lambda row: print(json.dumps(row, sort_keys=True, separators=(",", ":")), flush=True)))
