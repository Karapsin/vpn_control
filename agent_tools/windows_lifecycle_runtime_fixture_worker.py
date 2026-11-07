"""Owned finite hybrid SOCKS/HTTPS fixture for real public runtime/Find Best calls.

It forwards only localhost:<its own HTTPS port>; the benchmark IPv4 target gets
the local fixed body. No upstream Internet destination is opened. TLS material
and all source roles must already be admitted by the original ordinary Owner.
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


def load(path, name):
    require(name not in sys.modules, "runtime-fixture-module-name")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def exact_json(path, maximum):
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "runtime-fixture-data-bound")
    return json.loads(raw)


def current_mode(directory, operation):
    selected = {"operationId": operation, "ordinal": 0, "mode": "ok"}
    for ordinal in range(1, 9):
        path = directory / f"mode-{ordinal:04d}.json"
        if not path.exists():
            break
        try:
            value = exact_json(path, 1024)
            require(type(value) is dict and set(value) == {"operationId", "ordinal", "mode"}
                    and value["operationId"] == operation and value["ordinal"] == ordinal
                    and value["mode"] in {"ok", "reject", "slow"}, "runtime-fixture-mode-record")
            selected = value
        except (OSError, UnicodeError, ValueError):
            # A partial/foreign input cannot be accepted as a successful test.
            return {"operationId": operation, "ordinal": ordinal, "mode": "unavailable"}
    return selected


def classes(source):
    original_socks = source.FixtureServer
    class HybridSocks(original_socks):
        @property
        def has_forwarding(self):
            # The unchanged handler's fallback is a local fixed response, not a
            # network connection. Explicit localhost forwarding is below.
            return False
        def should_forward(self, host, port):
            return host == "localhost" and port == self._forward_port

    class Handler(source._SubscriptionHandler):
        def do_GET(self):
            if self.path not in {"/subscription", "/traffic"}:
                self.send_error(404)
                return
            agent = self.headers.get("User-Agent", "")
            if len(agent) > 256:
                self.send_error(431)
                return
            mode = current_mode(self.server._owned_directory, self.server._owned_operation)
            status = 503 if self.path == "/traffic" and mode["mode"] in {"reject", "unavailable"} else 200
            row = {"timestamp": time.time(), "path": self.path, "userAgent": agent,
                   "status": status, "mode": mode["mode"], "modeOrdinal": mode["ordinal"]}
            with self.server._owned_ledger_lock:
                with self.server._owned_ledger.open("ab", buffering=0) as output:
                    data = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    offset = 0
                    while offset < len(data):
                        count = output.write(data[offset:])
                        require(count is not None and count > 0, "runtime-fixture-ledger-write")
                        offset += count
                    os.fsync(output.fileno())
            if self.path == "/traffic" and mode["mode"] == "slow":
                time.sleep(2)  # Declared fixture delay, no subprocess timeout/kill.
            body = self.server.subscription_body.encode() if self.path == "/subscription" else self.server._owned_body
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class Fixture(source.HttpsSubscriptionRelayFixture):
        def __init__(self, value):
            self._owned_value = value
            super().__init__(Path(value["certificatePath"]), Path(value["privateKeyPath"]),
                             Path(value["readyFile"]), value["token"])
        def _publish_readiness(self, ready):
            value = self._owned_value
            server = self.https_server
            server._owned_directory = Path(value["readyFile"]).parent
            server._owned_operation = value["operationId"]
            server._owned_ledger = Path(value["ledgerFile"])
            server._owned_ledger_lock = threading.Lock()
            server._owned_body = value["token"].encode()
            server.RequestHandlerClass = Handler
            actual = {**ready, "operationId": value["operationId"],
                "trafficUrl": f"https://localhost:{ready['httpsPort']}/traffic",
                "responseSha256": hashlib.sha256(value["token"].encode()).hexdigest()}
            destination = Path(value["readyFile"])
            temporary = destination.with_name("ready-" + uuid.uuid4().hex + ".tmp")
            raw = (json.dumps(actual, sort_keys=True, separators=(",", ":")) + "\n").encode()
            with temporary.open("xb", buffering=0) as output:
                offset = 0
                while offset < len(raw):
                    count = output.write(raw[offset:])
                    require(count is not None and count > 0, "runtime-fixture-readiness-write")
                    offset += count
                os.fsync(output.fileno())
            if os.name == "nt":
                os.rename(temporary, destination) # Atomic and refuses existing Windows destination.
            else:
                os.link(temporary, destination) # Local decision tests, atomic no-replace.
                temporary.unlink()
    source.FixtureServer = HybridSocks  # Private loaded module only, before start.
    return Fixture


def validate(value):
    require(type(value) is dict and set(value) == {"schemaVersion", "socksSourcePath", "httpsSourcePath",
        "certificatePath", "privateKeyPath", "readyFile", "ledgerFile", "controlFile", "operationId",
        "maxServeSeconds", "token"} and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1,
        "runtime-fixture-input-fields")
    require(str(uuid.UUID(value["operationId"])) == value["operationId"]
            and type(value["maxServeSeconds"]) is int and 360 <= value["maxServeSeconds"] <= 1800
            and type(value["token"]) is str and 0 < len(value["token"].encode()) <= 4096,
            "runtime-fixture-finite-input")
    outputs = [Path(value[key]) for key in ("readyFile", "ledgerFile", "controlFile")]
    require(len(set(outputs)) == 3 and len({path.parent for path in outputs}) == 1
            and not any(path.exists() for path in outputs), "fresh-runtime-fixture-outputs")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    arguments = parser.parse_args()
    value = validate(exact_json(arguments.input, 16384))
    load(value["socksSourcePath"], "socks_http_fixture")
    source = load(value["httpsSourcePath"], "_owned_runtime_https")
    with Path(value["ledgerFile"]).open("xb"):
        pass
    fixture = classes(source)(value)
    ready = fixture.start()
    print(json.dumps({"kind": "runtime-fixture-ready", "operationId": value["operationId"],
                      "ready": ready, "nativeAcceptance": False}), flush=True)
    deadline, reason = time.monotonic() + value["maxServeSeconds"], "lease-expired"
    while time.monotonic() < deadline:
        control = Path(value["controlFile"])
        if control.exists():
            try:
                record = exact_json(control, 1024)
                if type(record) is dict and type(record.get("schemaVersion")) is int and record == {
                    "schemaVersion": 1, "operationId": value["operationId"], "action": "stop-owned-fixture"}:
                    reason = "exact-control-record"
                    break
            except (OSError, UnicodeError, ValueError):
                pass  # Preserve live fixture on partial/foreign control.
        time.sleep(0.1)
    fixture.stop()
    print(json.dumps({"kind": "runtime-fixture-terminal", "operationId": value["operationId"],
                      "reason": reason, "onlyOwnedListenersStopped": True}), flush=True)
    return 0 if reason == "exact-control-record" else 1


if __name__ == "__main__":
    raise SystemExit(main())
