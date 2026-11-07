"""Finite retained no-egress SOCKS fixture for installed GUI/update traffic.

Only the fixed repository FixtureServer is loaded. There is no forwarding target,
subprocess execution, VPN action, or timeout kill. The operator admits all sources,
private output-directory ACLs and original child ownership before invocation.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid


def require(value, reason):
    if not value:
        raise ValueError(reason)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    arguments = parser.parse_args()
    raw = arguments.input.read_bytes()
    require(len(raw) <= 16384, "socks-input-byte-bound")
    value = json.loads(raw)
    require(type(value) is dict and set(value) == {"schemaVersion", "socksSourcePath", "readyFile",
        "transcriptFile", "controlFile", "operationId", "maxServeSeconds", "token"}
        and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1,
        "socks-fixture-input-fields")
    require(str(uuid.UUID(value["operationId"])) == value["operationId"]
            and type(value["maxServeSeconds"]) in (int, float) and 30 <= value["maxServeSeconds"] <= 1800
            and type(value["token"]) is str and 0 < len(value["token"].encode()) <= 4096,
            "finite-socks-fixture-operation")
    outputs = [Path(value[key]) for key in ("readyFile", "transcriptFile", "controlFile")]
    require(len(set(outputs)) == 3 and len({item.parent for item in outputs}) == 1
            and not any(item.exists() for item in outputs), "fresh-owned-socks-fixture-outputs")
    name = "_owned_lifecycle_fixed_socks"
    require(name not in sys.modules, "socks-module-already-loaded")
    spec = importlib.util.spec_from_file_location(name, value["socksSourcePath"])
    source = importlib.util.module_from_spec(spec)
    sys.modules[name] = source
    spec.loader.exec_module(source)
    with Path(value["transcriptFile"]).open("xb"):
        pass
    server = source.FixtureServer("127.0.0.1", 0, value["token"],
                                  transcript_file=Path(value["transcriptFile"]))
    thread = threading.Thread(target=server.serve_forever, name="owned-fixed-socks", daemon=False)
    thread.start()
    require(thread.is_alive() and server.has_forwarding is False, "owned-no-egress-socks-listener")
    ready = {"operationId": value["operationId"], "host": "127.0.0.1", "port": server.server_address[1],
             "responseSha256": hashlib.sha256(value["token"].encode()).hexdigest(), "forwarding": False}
    with Path(value["readyFile"]).open("xb", buffering=0) as output:
        data = (json.dumps(ready, sort_keys=True) + "\n").encode()
        count = output.write(data)
        require(count == len(data), "socks-readiness-write")
        os.fsync(output.fileno())
    print(json.dumps({"kind": "fixture-ready", **ready, "nativeAcceptance": False}), flush=True)
    closing, deadline = "lease-expired", time.monotonic() + value["maxServeSeconds"]
    while time.monotonic() < deadline:
        control = Path(value["controlFile"])
        if control.exists():
            command = control.read_bytes()
            require(len(command) <= 1024 and json.loads(command) == {"schemaVersion": 1,
                "operationId": value["operationId"], "action": "stop-owned-fixture"},
                "exact-owned-socks-fixture-control")
            closing = "exact-control-record"
            break
        time.sleep(0.1)
    server.shutdown()
    server.server_close()
    thread.join(3)
    require(not thread.is_alive(), "owned-socks-listener-thread-still-live")
    print(json.dumps({"kind": "fixture-terminal", "operationId": value["operationId"],
                      "reason": closing, "onlyOwnedListenerStopped": True}), flush=True)
    return 0 if closing == "exact-control-record" else 1


if __name__ == "__main__":
    raise SystemExit(main())
