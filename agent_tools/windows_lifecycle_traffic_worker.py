"""Finite SOCKS traffic observer for an already admitted Windows product runtime.

This child starts no fixture, owner, GUI, VPN, or subprocess. Every network probe
goes to one literal loopback mixed listener and asks it for the fixed benchmark
address used by scripts/run_desktop_vpn_integration.py. The caller must admit the
no-egress upstream fixture and runtime independently. No native acceptance is
established by this module or its local parser checks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import socket
import time


TARGET_HOST = "198.18.0.1"
TARGET_PORT = 80
TARGET_PATH = "/probe"
MAX_HTTP = 65536


def require(value, reason):
    if not value:
        raise ValueError(reason)


def validate(value):
    require(type(value) is dict and set(value) == {"schemaVersion", "mixedPort",
            "expectedBodyHex", "sampleCount", "intervalSeconds", "ioTimeoutSeconds"},
            "traffic-input-fields")
    require(value["schemaVersion"] == 1 and type(value["mixedPort"]) is int
            and 1 <= value["mixedPort"] <= 65535, "traffic-loopback-port")
    require(type(value["sampleCount"]) is int and 4 <= value["sampleCount"] <= 1800,
            "finite-sample-count")
    for name in ("intervalSeconds", "ioTimeoutSeconds"):
        item = value[name]
        require(type(item) in (int, float) and math.isfinite(item)
                and 0.02 <= item <= 10, "finite-traffic-duration")
    body = bytes.fromhex(value["expectedBodyHex"])
    require(0 < len(body) <= 4096, "owned-fixture-body-bound")
    return value


def exact(stream, count):
    result = bytearray()
    while len(result) < count:
        block = stream.recv(count - len(result))
        require(bool(block), "peer-closed-before-frame")
        result.extend(block)
    return bytes(result)


def parse_http(raw):
    require(len(raw) <= MAX_HTTP and b"\r\n\r\n" in raw, "http-bound-or-header")
    header, body = raw.split(b"\r\n\r\n", 1)
    lines = header.split(b"\r\n")
    require(lines[0] in (b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"), "http-status")
    fields = {}
    for row in lines[1:]:
        require(b":" in row, "http-header-shape")
        key, item = row.split(b":", 1)
        key = key.lower()
        require(key not in fields, "duplicate-http-header")
        fields[key] = item.strip()
    require(b"transfer-encoding" not in fields, "unexpected-transfer-encoding")
    require(fields.get(b"content-length", b"").isdigit()
            and int(fields[b"content-length"]) == len(body), "http-content-length")
    return body


def probe(value, connector=socket.create_connection):
    with connector(("127.0.0.1", value["mixedPort"]),
                   timeout=value["ioTimeoutSeconds"]) as stream:
        stream.settimeout(value["ioTimeoutSeconds"])
        stream.sendall(b"\x05\x01\x00")
        require(exact(stream, 2) == b"\x05\x00", "mixed-socks-method")
        stream.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(TARGET_HOST)
                       + TARGET_PORT.to_bytes(2, "big"))
        prefix = exact(stream, 4)
        require(prefix[:3] == b"\x05\x00\x00", "mixed-socks-connect")
        lengths = {1: 4, 4: 16}
        count = exact(stream, 1)[0] if prefix[3] == 3 else lengths.get(prefix[3])
        require(type(count) is int and count > 0, "mixed-socks-address")
        exact(stream, count + 2)
        stream.sendall((f"GET {TARGET_PATH} HTTP/1.1\r\nHost: {TARGET_HOST}\r\n"
                        "Connection: close\r\n\r\n").encode("ascii"))
        result = bytearray()
        while True:
            block = stream.recv(min(4096, MAX_HTTP + 1 - len(result)))
            if not block:
                break
            result.extend(block)
            require(len(result) <= MAX_HTTP, "http-body-bound")
        body = parse_http(bytes(result))
        require(body == bytes.fromhex(value["expectedBodyHex"]), "fixture-response-bytes")
        return {"responseBytes": len(body), "responseSha256": hashlib.sha256(body).hexdigest()}


def collect(value, emit, now=time.time, monotonic=time.monotonic, sleep=time.sleep,
            sample=probe):
    validate(value)
    samples = []
    for ordinal in range(value["sampleCount"]):
        opening, tick = now(), monotonic()
        row = {"kind": "sample", "ordinal": ordinal, "startedAt": opening,
               "mixedPort": value["mixedPort"],
               "gapBeforeSeconds": max(0.0, opening - samples[-1]["finishedAt"]) if samples else 0.0}
        try:
            row.update(sample(value), succeeded=True)
        except (OSError, ValueError) as error:
            row.update(succeeded=False, errorClass=type(error).__name__, reason=str(error))
        row.update(finishedAt=now(), elapsedSeconds=monotonic() - tick)
        samples.append(row)
        emit(row)  # Every failure and gap remains in the original stdout stream.
        if ordinal + 1 < value["sampleCount"]:
            sleep(value["intervalSeconds"])
    result = {"kind": "terminal", "sampleCount": len(samples),
              "allSamplesSucceeded": all(row["succeeded"] for row in samples),
              "maxGapBeforeSeconds": max(row["gapBeforeSeconds"] for row in samples),
              "startedAt": samples[0]["startedAt"], "finishedAt": samples[-1]["finishedAt"],
              "nativeAcceptance": False, "fixtureAdmissionExternal": True}
    emit(result)
    return 0 if result["allSamplesSucceeded"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mixed-port", type=int)
    arguments = parser.parse_args()
    raw = arguments.input.read_bytes()
    require(len(raw) <= 8192, "traffic-input-byte-bound")
    value = json.loads(raw)
    if arguments.mixed_port is not None:
        value["mixedPort"] = arguments.mixed_port
    return collect(value, lambda row: print(json.dumps(row, sort_keys=True,
                   separators=(",", ":")), flush=True))


if __name__ == "__main__":
    raise SystemExit(main())
