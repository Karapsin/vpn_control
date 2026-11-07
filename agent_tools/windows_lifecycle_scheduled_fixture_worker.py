"""Private finite HTTPS/SOCKS fixture with the scheduled collector's ledger.

Reuses the repository fixture unchanged through a small handler subclass. Starts
only on explicit main invocation in a retained ordinary Child. The child stops
only its own listeners after one exact control record or its declared finite
lease; it never stops product processes, VPNs, or a VM.
"""
from __future__ import annotations

import argparse
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


def row(timestamp, path, user_agent):
    require(type(timestamp) in (float, int) and timestamp >= 0 and path == "/subscription"
            and type(user_agent) is str and len(user_agent) <= 256, "fixture-ledger-fields")
    return {"timestamp": timestamp, "path": path, "userAgent": user_agent}


def module(path, name):
    require(name not in sys.modules, "fixture-source-module-name")
    spec = importlib.util.spec_from_file_location(name, path)
    source = importlib.util.module_from_spec(spec)
    sys.modules[name] = source
    spec.loader.exec_module(source)
    return source


def fixture_type(source):
    class Handler(source._SubscriptionHandler):
        def do_GET(self):
            if self.path != "/subscription":
                self.send_error(404)
                return
            user_agent = self.headers.get("User-Agent", "")
            if len(user_agent) > 256:
                self.send_error(431)
                return
            ledger = row(time.time(), self.path, user_agent)
            with self.server._lifecycle_ledger_lock:
                with self.server._lifecycle_ledger.open("ab", buffering=0) as output:
                    data = (json.dumps(ledger, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    offset = 0
                    while offset < len(data):
                        count = output.write(data[offset:])
                        require(count is not None and count > 0, "fixture-ledger-write-zero")
                        offset += count
                    os.fsync(output.fileno())
            super().do_GET()

    class LedgerFixture(source.HttpsSubscriptionRelayFixture):
        def __init__(self, *arguments, ledger, **options):
            self._lifecycle_ledger = ledger
            super().__init__(*arguments, **options)

        def _publish_readiness(self, ready):
            # Base starts listeners before publishing. Install the finite handler
            # before the ready file becomes visible to the product operator.
            self.https_server._lifecycle_ledger = self._lifecycle_ledger
            self.https_server._lifecycle_ledger_lock = threading.Lock()
            self.https_server.RequestHandlerClass = Handler
            super()._publish_readiness(ready)
    return LedgerFixture


def validate(value):
    require(type(value) is dict and set(value) == {"schemaVersion", "socksSourcePath",
        "httpsSourcePath", "certificatePath", "privateKeyPath", "readyFile", "ledgerFile",
        "controlFile", "operationId", "maxServeSeconds", "token"}
        and value["schemaVersion"] == 1, "fixture-input-fields")
    require(str(uuid.UUID(value["operationId"])) == value["operationId"], "fixture-operation-id")
    require(type(value["maxServeSeconds"]) in (int, float)
            and 360 <= value["maxServeSeconds"] <= 1800, "fixture-finite-lease")
    require(type(value["token"]) is str and 0 < len(value["token"].encode()) <= 4096,
            "fixture-response-body-bound")
    outputs = [Path(value[key]) for key in ("readyFile", "ledgerFile", "controlFile")]
    require(len(set(outputs)) == 3 and len({item.parent for item in outputs}) == 1
            and not any(item.exists() for item in outputs), "fresh-owned-fixture-output-population")
    return value


def stop_record(path, operation):
    """Incomplete/malformed publication is a read refusal, never a stop action."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(1025)
        return len(raw) <= 1024 and json.loads(raw) == {"schemaVersion": 1,
            "operationId": operation, "action": "stop-owned-fixture"}
    except (OSError, UnicodeError, ValueError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    arguments = parser.parse_args()
    raw = arguments.input.read_bytes()
    require(len(raw) <= 16384, "fixture-input-byte-bound")
    value = validate(json.loads(raw))
    module(value["socksSourcePath"], "socks_http_fixture")
    source = module(value["httpsSourcePath"], "_owned_lifecycle_https_fixture")
    with Path(value["ledgerFile"]).open("xb"):
        pass
    fixture = fixture_type(source)(Path(value["certificatePath"]), Path(value["privateKeyPath"]),
        Path(value["readyFile"]), value["token"], ledger=Path(value["ledgerFile"]))
    closing = "lease-expired"
    ready = fixture.start()
    print(json.dumps({"kind": "fixture-ready", "operationId": value["operationId"],
                      "ready": ready, "nativeAcceptance": False}), flush=True)
    deadline = time.monotonic() + value["maxServeSeconds"]
    while time.monotonic() < deadline:
        control = Path(value["controlFile"])
        if control.exists():
            if stop_record(control, value["operationId"]):
                closing = "exact-control-record"
                break
        time.sleep(0.1)
    fixture.stop()
    print(json.dumps({"kind": "fixture-terminal", "operationId": value["operationId"],
                      "reason": closing, "onlyOwnedListenersStopped": True}), flush=True)
    return 0 if closing == "exact-control-record" else 1


if __name__ == "__main__":
    raise SystemExit(main())
