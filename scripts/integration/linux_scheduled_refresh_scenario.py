#!/usr/bin/env python3
"""Installed RPM scheduled-refresh acceptance in a disposable, owned Linux state.

Input and receipt are versioned JSON. This program never invokes a shell, changes
the process trust store, or stops a controller whose identity it did not create.
The bundler must stage socks_http_fixture.py beside this file.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import math
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Callable

from socks_http_fixture import FixtureServer
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from native_fixture_preflight import linux_scheduled_refresh


SCHEMA = "vpn-control.linux-scheduled-refresh.input"
RECEIPT_SCHEMA = "vpn-control.linux-scheduled-refresh.receipt"
SCENARIO = "linux-scheduled-refresh"
LAUNCHER = Path("/opt/vpn-control/bin/vpn-control")
JAR_DIR = Path("/opt/vpn-control/lib/app")
PRODUCT_AGENT = "VPNControlDesktop/1.0"


class ScenarioError(RuntimeError):
    pass


class OutcomeUnknown(ScenarioError):
    """An accepted mutation timed out; repeating it could duplicate the action."""


def _absolute(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ScenarioError(f"{label} must be an absolute path")
    path = Path(value)
    if ".." in path.parts or str(path) != value:
        raise ScenarioError(f"{label} is not canonical")
    return path


def validate_input(document: Any, receipt_path: Path) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {
        "schema", "schemaVersion", "scenarioId", "correlationId", "ownedWorkspaceRoot",
        "protectedStateDir", "protectedControllerId", "expectedPackageNevra",
        "expectedDesktopJarSha256", "mode", "scheduleHours", "maxObservationSeconds",
    }:
        raise ScenarioError("input keys do not match the version 1 schema")
    if (document["schema"], document["schemaVersion"], document["scenarioId"]) != (SCHEMA, 1, SCENARIO):
        raise ScenarioError("input schema or scenario identity mismatch")
    try:
        correlation = str(uuid.UUID(document["correlationId"]))
        protected_id = str(uuid.UUID(document["protectedControllerId"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise ScenarioError("controller and correlation identities must be UUIDs") from error
    if correlation != document["correlationId"] or protected_id != document["protectedControllerId"]:
        raise ScenarioError("UUIDs must use canonical lowercase form")
    root = _absolute(document["ownedWorkspaceRoot"], "ownedWorkspaceRoot")
    protected = _absolute(document["protectedStateDir"], "protectedStateDir")
    receipt = _absolute(str(receipt_path), "receipt")
    if root.is_symlink() or not root.is_dir() or root.resolve() != root or root.stat().st_uid != os.getuid():
        raise ScenarioError("ownedWorkspaceRoot must be an existing, locally owned real directory")
    if protected == root or root in protected.parents or protected in root.parents:
        raise ScenarioError("protected and owned workspaces overlap")
    if receipt == root or root in receipt.parents or receipt.exists():
        raise ScenarioError("receipt must be new and outside owned workspace")
    if (not receipt.parent.is_dir() or receipt.parent.is_symlink() or
            receipt.parent.resolve() != receipt.parent or receipt.parent.stat().st_uid != os.getuid() or
            receipt == protected or protected in receipt.parents):
        raise ScenarioError("receipt parent must be a separate, locally owned real directory")
    if document["mode"] not in {"refresh-only", "refresh-find-best"}:
        raise ScenarioError("unsupported mode")
    hours = document["scheduleHours"]
    duration = document["maxObservationSeconds"]
    if (type(hours) not in (int, float) or not 0.084 <= hours <= 1 or not math.isfinite(hours)
            or type(duration) not in (int, float) or not 0 < duration <= 3600
            or not math.isfinite(duration) or duration < hours * 3600 + 30):
        raise ScenarioError("schedule must be >= 0.084 hours with a bounded observation window")
    if not re.fullmatch(r"vpn-control-\d+\.\d+\.\d+-\d+\.x86_64", document["expectedPackageNevra"]):
        raise ScenarioError("expectedPackageNevra is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", document["expectedDesktopJarSha256"]):
        raise ScenarioError("expectedDesktopJarSha256 is invalid")
    return {**document, "ownedWorkspaceRoot": root, "protectedStateDir": protected,
            "receiptPath": receipt, "runRoot": root / f"vpn-scheduled-refresh-{correlation}"}


def require_measured_benchmark(document: dict[str, Any]) -> float:
    data = document.get("data", {})
    value = data.get("secondaryTotalMs") if isinstance(data, dict) else None
    if (not isinstance(data, dict) or data.get("secondaryStatus") != "ok"
            or not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0):
        raise ScenarioError("explicit benchmark had no measured secondary result")
    return float(value)


def require_refreshed_locations(document: dict[str, Any], count: int) -> list[dict[str, Any]]:
    rows = document.get("data", {}).get("locations", [])
    if not isinstance(rows, list) or len(rows) != count or not all(isinstance(row, dict) for row in rows):
        raise ScenarioError(f"expected {count} locations after explicit subscription refresh")
    return rows


def named_mixed_port(state: Path) -> int:
    config = json.loads((state / "runtime-config.json").read_text(encoding="utf-8"))
    inbounds = config.get("inbounds", [])
    matches = [row for row in inbounds if isinstance(row, dict) and row.get("type") == "mixed"
               and row.get("tag") == "mixed-in" and row.get("listen") == "127.0.0.1"]
    if len(matches) != 1 or not isinstance(matches[0].get("listen_port"), int):
        raise ScenarioError("expected exactly one named loopback mixed-in user listener")
    port = matches[0]["listen_port"]
    if not 1 <= port <= 65535:
        raise ScenarioError("invalid mixed-in user listener port")
    return port


def traffic_classification(old_port: int, new_port: int, samples: list[dict[str, Any]],
                           post_transition: dict[str, Any]) -> dict[str, Any]:
    def good(row: dict[str, Any]) -> bool:
        return row.get("returncode") == 0 and row.get("matchedFixtureBody") is True

    return {"oldUserListenerPort": old_port, "newUserListenerPort": new_port,
            "portMigrated": old_port != new_port, "oldPortContinuity": bool(samples) and
            all(good(row) for row in samples),
            "postTransitionTraffic": good(post_transition),
            "oldPortSamples": samples, "newPortSample": post_transition}


class _ForwardingFixture(FixtureServer):
    def should_forward(self, host: str, port: int) -> bool:
        return host in {"localhost", "127.0.0.1", "::1"} and port == self._forward_port


class _SubscriptionHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server: _SubscriptionServer = self.server  # type: ignore[assignment]
        row = {"timestamp": time.time(), "path": self.path, "userAgent": self.headers.get("User-Agent", "")}
        with server.ledger_lock:
            server.ledger.append(row)
        if self.path != "/subscription":
            self.send_error(404)
            return
        body = server.body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: Any) -> None:
        return


class _SubscriptionServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, body: bytes):
        super().__init__(("127.0.0.1", 0), _SubscriptionHandler)
        self.body = body
        self.ledger: list[dict[str, Any]] = []
        self.ledger_lock = threading.Lock()


class ScenarioRunner:
    def __init__(self, spec: dict[str, Any], *, run: Callable[..., Any] = subprocess.run,
                 popen: Callable[..., Any] = subprocess.Popen,
                 now: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep):
        self.spec, self.run, self.popen, self.now, self.sleep = spec, run, popen, now, sleep
        self.root: Path = spec["runRoot"]
        self.state = self.root / "state"
        self.owner: Any = None
        self.owner_id: str | None = None
        self.owner_env: dict[str, str] | None = None
        self.unknown_operation: dict[str, Any] | None = None
        self.tls: _SubscriptionServer | None = None
        self.relays: list[_ForwardingFixture] = []
        self.threads: list[threading.Thread] = []
        self.receipt: dict[str, Any] = {
            "schema": RECEIPT_SCHEMA, "schemaVersion": 1, "scenarioId": SCENARIO,
            "correlationId": spec["correlationId"], "mode": spec["mode"], "result": "failed",
            "cleanup": {"state": "not-started", "ownedPaths": [], "ownerStopped": False,
                        "protectedPreserved": False, "workspaceRemoved": False},
        }

    def command(self, argv: list[str], *, timeout: float = 30, env: dict[str, str] | None = None,
                mutation: bool = False) -> subprocess.CompletedProcess[str]:
        try:
            return self.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired as error:
            if mutation:
                self.unknown_operation = {"argvTail": argv[-3:], "reason": "client timeout"}
                raise OutcomeUnknown(f"mutation outcome unknown after timeout: {argv[-3:]}") from error
            raise ScenarioError(f"read-only command timed out: {argv[-3:]}") from error

    def cli(self, tail: list[str], *, mutation: bool = False, timeout: float = 30,
            allow_failure: bool = False) -> dict[str, Any]:
        args = [str(LAUNCHER), "--state-dir", str(self.state), "--json"]
        if self.owner_id:
            args.extend(["--controller-id", self.owner_id])
        args.extend(tail)
        result = self.command(args, timeout=timeout, env=self.owner_env, mutation=mutation)
        try:
            document = json.loads(result.stdout)
        except (ValueError, TypeError) as error:
            raise ScenarioError(f"CLI returned invalid JSON for {tail}") from error
        if not isinstance(document, dict) or (result.returncode != 0 or document.get("ok") is not True) and not allow_failure:
            if mutation and isinstance(document, dict) and document.get("code") == "TIMEOUT":
                self.unknown_operation = {"argvTail": tail, "operationId": document.get("operationId"),
                                          "reason": "accepted operation not terminal"}
                raise OutcomeUnknown(f"accepted mutation outcome unknown: {tail}")
            raise ScenarioError(f"CLI rejected {tail}: {document.get('code') if isinstance(document, dict) else 'invalid'}")
        if self.owner_id and document.get("controllerId") != self.owner_id:
            raise ScenarioError("owned controller identity changed")
        return document

    def _check_installed_package(self) -> None:
        if not LAUNCHER.is_file() or not os.access(LAUNCHER, os.X_OK):
            raise ScenarioError("installed launcher unavailable")
        if not Path("/usr/bin/curl").is_file() or not os.access("/usr/bin/curl", os.X_OK):
            raise ScenarioError("installed curl sampler unavailable")
        help_result = self.command([str(LAUNCHER), "--help"], timeout=15)
        required_usage = ("source set <", "subscriptions add <", "subscriptions refresh <",
                          "locations select <", "locations benchmark <", "settings set <",
                          "operations list", "operations wait <", "find-best", "serve", "quit",
                          "--state-dir", "--controller-id")
        if help_result.returncode or any(item not in help_result.stdout for item in required_usage):
            raise ScenarioError("installed CLI help does not admit the scenario command grammar")
        query = self.command(["rpm", "-q", "vpn-control"])
        actual = query.stdout.strip()
        verify = self.command(["rpm", "-V", "vpn-control"])
        jars = list(JAR_DIR.glob("desktopApp-*.jar"))
        if query.returncode or actual != self.spec["expectedPackageNevra"] or verify.returncode or verify.stdout.strip() or len(jars) != 1:
            raise ScenarioError("installed RPM identity or verification mismatch")
        digest = hashlib.sha256(jars[0].read_bytes()).hexdigest()
        if digest != self.spec["expectedDesktopJarSha256"]:
            raise ScenarioError("installed desktop jar fingerprint mismatch")
        self.receipt["package"] = {"nevra": actual, "desktopJarSha256": digest, "rpmVerifyClean": True,
                                   "launcher": str(LAUNCHER), "cliHelpGrammarAdmitted": True}

    def _protected_status(self) -> bool:
        args = [str(LAUNCHER), "--state-dir", str(self.spec["protectedStateDir"]), "--json", "status"]
        result = self.command(args, timeout=15)
        try:
            document = json.loads(result.stdout)
        except ValueError:
            return False
        return (result.returncode == 0 and document.get("controllerId") == self.spec["protectedControllerId"]
                and document.get("data", {}).get("runtimeRunning") is False)

    def _create_fixture(self) -> tuple[str, Path]:
        cert, key, trust = (self.root / name for name in ("cert.pem", "key.pem", "truststore.jks"))
        openssl = self.command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
                                "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                                "-keyout", str(key), "-out", str(cert)], timeout=30)
        if openssl.returncode:
            raise ScenarioError("owned HTTPS certificate creation failed")
        java_path = self.command(["readlink", "-f", "/usr/bin/java"])
        keytool = Path(java_path.stdout.strip()).parent / "keytool"
        if java_path.returncode or not keytool.is_file():
            raise ScenarioError("installed JDK keytool unavailable")
        imported = self.command([str(keytool), "-importcert", "-noprompt", "-alias", "owned-fixture",
                                 "-file", str(cert), "-keystore", str(trust), "-storepass", "changeit"])
        if imported.returncode:
            raise ScenarioError("private JVM trust store creation failed")
        self.owner_env = {**os.environ, "JAVA_TOOL_OPTIONS":
                          f"-Djavax.net.ssl.trustStore={trust} -Djavax.net.ssl.trustStorePassword=changeit"}
        count = 2 if self.spec["mode"] == "refresh-find-best" else 1
        self.tls = _SubscriptionServer(b"")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))
        self.tls.socket = context.wrap_socket(self.tls.socket, server_side=True)
        port = self.tls.server_address[1]
        for _ in range(count):
            relay = _ForwardingFixture("127.0.0.1", 0, "owned", self.root / "socks-ledger.jsonl",
                                       forward_host="localhost", forward_port=port)
            self.relays.append(relay)
        body = "".join(f"socks://127.0.0.1:{relay.server_address[1]}#owned-{index + 1}\n"
                       for index, relay in enumerate(self.relays)).encode()
        self.tls.body = body
        for server in [self.tls, *self.relays]:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            thread.start()
            self.threads.append(thread)
        source = f"https://localhost:{port}/subscription"
        self.receipt["source"] = {"url": source, "bodySha256": hashlib.sha256(body).hexdigest(),
                                  "certificateSha256": hashlib.sha256(cert.read_bytes()).hexdigest(),
                                  "relayCount": count}
        return source, cert

    def _start_owner(self) -> None:
        with (self.root / "owner.log").open("wb") as log:
            self.owner = self.popen([str(LAUNCHER), "--state-dir", str(self.state), "serve"],
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                    env=self.owner_env, start_new_session=True)
        deadline = self.now() + 30
        while self.now() < deadline:
            try:
                status = self.cli(["status"])
                owner_id = status.get("controllerId")
                if owner_id:
                    self.owner_id = str(owner_id)
                    self.receipt["ownerControllerId"] = self.owner_id
                    return
            except ScenarioError:
                pass
            if self.owner.poll() is not None:
                break
            self.sleep(0.2)
        raise ScenarioError("fresh owner did not become ready")

    def _preflight(self, source: str, cert: Path) -> None:
        result = linux_scheduled_refresh(source, 5, certificate_path=cert,
                                         workspace=self.state / "workspace.json",
                                         require_find_best=self.spec["mode"] == "refresh-find-best")
        self.receipt["preflight"] = result
        if result.get("ready") is not True:
            raise ScenarioError("owned fixture preflight failed")

    def _configure(self, source: str, cert: Path) -> dict[str, Any]:
        add = self.cli(["subscriptions", "add", "--source", source, "--name", "owned-scheduled"], mutation=True)
        sid = add.get("data", {}).get("id")
        if not sid:
            rows = self.cli(["subscriptions", "list"]).get("data", {}).get("subscriptions", [])
            sid = rows[0].get("id") if len(rows) == 1 else None
        if not isinstance(sid, str) or not sid:
            raise ScenarioError("subscription ID absent")
        self.receipt["source"]["subscriptionId"] = sid
        self.cli(["source", "set", "subscription", sid], mutation=True)
        self.cli(["subscriptions", "refresh", sid], mutation=True, timeout=90)
        count = 2 if self.spec["mode"] == "refresh-find-best" else 1
        require_refreshed_locations(self.cli(["locations", "list"]), count)
        self.cli(["locations", "select", "1"], mutation=True)
        self.cli(["settings", "set", "mode", "proxy-only"], mutation=True)
        self.cli(["settings", "set", "validation.test-url", source], mutation=True)
        self.cli(["settings", "set", "refresh.find-best-after-refresh", "true" if count == 2 else "false"], mutation=True)
        # Admit the saved settings before ON, but arm the short test interval only
        # after explicit Find Best so the scheduled operation cannot race setup.
        self.cli(["settings", "set", "refresh.custom-hours", "1"], mutation=True)
        self.cli(["settings", "set", "refresh.policy", "custom"], mutation=True)
        self._preflight(source, cert)
        self.cli(["on"], mutation=True, timeout=90)
        active = self.cli(["status"])
        if active.get("data", {}).get("runtimeRunning") is not True or not active.get("data", {}).get("runtimeId"):
            raise ScenarioError("proxy runtime did not start")
        explicit: dict[str, Any] = {"activeA": active.get("data")}
        self.receipt["explicit"] = explicit
        explicit["activeATraffic"] = self._prove_current_traffic(cert, source, "activeA")
        if count == 2:
            self.cli(["locations", "select", "2"], mutation=True)
            pending = self.cli(["status"])
            a, b = active.get("data", {}), pending.get("data", {})
            if (b.get("activeLocationId") != a.get("activeLocationId") or
                    b.get("runtimeId") != a.get("runtimeId") or
                    b.get("selectedLocationId") == a.get("activeLocationId")):
                raise ScenarioError("pending selection displaced active A before Find Best")
            explicit["pendingB"] = b
            benchmark = self.cli(["locations", "benchmark", "1"], mutation=True, timeout=90)
            explicit["benchmark"] = {"primaryStatus": benchmark.get("data", {}).get("primaryStatus"),
                                     "primaryTotalMs": benchmark.get("data", {}).get("primaryTotalMs"),
                                     "secondaryStatus": benchmark.get("data", {}).get("secondaryStatus"),
                                     "secondaryTotalMs": require_measured_benchmark(benchmark)}
            find_best = self.cli(["find-best"], mutation=True, timeout=240)
            explicit["findBest"] = {"code": find_best.get("code"), "data": find_best.get("data")}
            after = self.cli(["status"])
            if after.get("data", {}).get("runtimeRunning") is not True:
                raise ScenarioError("explicit Find Best left runtime stopped")
            explicit["afterFindBest"] = after.get("data")
            explicit["afterFindBestTraffic"] = self._prove_current_traffic(cert, source, "afterFindBest")
        self.cli(["settings", "set", "refresh.custom-hours", str(self.spec["scheduleHours"])], mutation=True)
        self.cli(["settings", "set", "refresh.policy", "custom"], mutation=True)
        self.receipt["explicit"] = explicit
        return explicit

    def _probe(self, port: int, cert: Path, source: str) -> dict[str, Any]:
        started = self.now()
        args = ["/usr/bin/curl", "--silent", "--show-error", "--fail", "--max-time", "3",
                "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{port}", "--cacert", str(cert), source]
        try:
            result = self.command(args, timeout=4)
            digest = hashlib.sha256(result.stdout.encode()).hexdigest()
            return {"startedAt": started, "finishedAt": self.now(), "port": port,
                    "returncode": result.returncode, "responseSha256": digest,
                    "matchedFixtureBody": digest == self.receipt["source"]["bodySha256"],
                    "stderr": result.stderr[-300:]}
        except ScenarioError as error:
            return {"startedAt": started, "finishedAt": self.now(), "port": port,
                    "returncode": None, "error": str(error)}

    def _prove_current_traffic(self, cert: Path, source: str, label: str) -> dict[str, Any]:
        deadline = self.now() + 15
        attempts: list[dict[str, Any]] = []
        while True:
            try:
                sample = self._probe(named_mixed_port(self.state), cert, source)
                attempts.append(sample)
                if sample.get("returncode") == 0 and sample.get("matchedFixtureBody") is True:
                    return {"sample": sample, "attempts": attempts}
            except (OSError, ValueError, ScenarioError):
                pass
            if self.now() >= deadline:
                self.receipt.setdefault("explicit", {})[f"{label}TrafficAttempts"] = attempts
                raise ScenarioError(f"{label} did not carry owned HTTPS traffic within 15 seconds")
            self.sleep(0.5)

    def _observe(self, source: str, cert: Path) -> None:
        opening = self.cli(["status"])
        opening_data = opening.get("data", {})
        if opening_data.get("runtimeRunning") is not True:
            raise ScenarioError("scheduled observation started with runtime stopped")
        old_port = named_mixed_port(self.state)
        baseline = self.cli(["operations", "list"]).get("data", {}).get("operations", [])
        previous_ids = {row.get("id") for row in baseline if isinstance(row, dict)}
        started = self.now()
        deadline = started + self.spec["maxObservationSeconds"]
        samples: list[dict[str, Any]] = []
        observed: dict[str, Any] | None = None
        while self.now() < deadline:
            samples.append(self._probe(old_port, cert, source))
            listing = self.cli(["operations", "list"]).get("data", {}).get("operations", [])
            candidates = [row for row in listing if isinstance(row, dict) and row.get("id") not in previous_ids
                          and str(row.get("requestId", "")).startswith("scheduled-refresh:")
                          and row.get("operation") == "subscriptions.refresh"]
            if len(candidates) > 1:
                raise ScenarioError("multiple fresh scheduled refresh operations")
            if candidates:
                if observed and observed.get("id") != candidates[0].get("id"):
                    raise ScenarioError("scheduled operation identity changed")
                observed = candidates[0]
                if observed.get("final") is True:
                    break
            self.sleep(1)
        if not observed or observed.get("final") is not True:
            raise ScenarioError("scheduled operation was not terminal within the observation window")
        terminal_at = self.now()
        samples.append(self._probe(old_port, cert, source))
        wait = self.cli(["operations", "wait", str(observed["id"])], allow_failure=True, timeout=15)
        if wait.get("operationId") != observed["id"] or wait.get("final") is not True:
            raise ScenarioError("terminal operation identity mismatch")
        self.receipt["scheduled"] = {"operation": observed, "wait": wait, "code": wait.get("code"),
                                     "opening": opening_data, "startedAt": started, "terminalAt": terminal_at}
        source_rows = wait.get("data", {}).get("sources", [])
        if (not isinstance(source_rows, list) or len(source_rows) != 1 or
                source_rows[0].get("id") != self.receipt["source"]["subscriptionId"] or
                source_rows[0].get("ok") is not True or
                source_rows[0].get("locationCount") != self.receipt["source"]["relayCount"]):
            raise ScenarioError("scheduled refresh did not successfully refresh the owned subscription")
        recovery_started = self.now()
        recovery_deadline = recovery_started + 15
        recovery_samples: list[dict[str, Any]] = []
        while True:
            closing = self.cli(["status"])
            closed = closing.get("data", {})
            if closed.get("runtimeRunning") is True:
                try:
                    new_port = named_mixed_port(self.state)
                    new_probe = self._probe(new_port, cert, source)
                    recovery_samples.append(new_probe)
                    if new_probe.get("returncode") == 0 and new_probe.get("matchedFixtureBody") is True:
                        break
                except (OSError, ValueError, ScenarioError):
                    pass
            if self.now() >= recovery_deadline:
                self.receipt["traffic"] = {"oldUserListenerPort": old_port, "oldPortSamples": samples,
                                           "newPortRecoverySamples": recovery_samples,
                                           "postTransitionTraffic": False}
                raise ScenarioError("new named user listener did not recover traffic within 15 seconds")
            samples.append(self._probe(old_port, cert, source))
            self.sleep(1)
        traffic = traffic_classification(old_port, new_port, samples, new_probe)
        traffic["recoverySeconds"] = self.now() - recovery_started
        traffic["newPortRecoverySamples"] = recovery_samples
        with self.tls.ledger_lock:  # type: ignore[union-attr]
            ledger = list(self.tls.ledger)  # type: ignore[union-attr]
        scheduled_hits = [row for row in ledger if row["path"] == "/subscription"
                          and row["userAgent"] == PRODUCT_AGENT and started <= row["timestamp"] <= self.now()]
        traffic_hits = [row for row in ledger if row["path"] == "/subscription"
                        and row["userAgent"].startswith("curl/")]
        self.receipt["scheduled"].update({"closing": closed, "productHttpHits": scheduled_hits,
                                          "trafficHttpHits": len(traffic_hits)})
        self.receipt["traffic"] = traffic
        if wait.get("code") != "OK" or not scheduled_hits or not traffic_hits or not traffic["postTransitionTraffic"]:
            raise ScenarioError("scheduled result or post-transition user traffic failed")
        if self.spec["mode"] == "refresh-only" and (
            opening_data.get("runtimeId") != closed.get("runtimeId") or old_port != new_port or
            not traffic["oldPortContinuity"]):
            raise ScenarioError("refresh-only runtime or listener continuity failed")
        self.receipt["result"] = "passed"

    def _cleanup(self) -> None:
        result = self.receipt["cleanup"]
        result["ownedPaths"] = [str(self.root)] if self.root.exists() else []
        if self.unknown_operation is not None:
            result["state"] = "preserved-for-recovery"
            result["unknownOperation"] = self.unknown_operation
            try:
                result["protectedPreserved"] = self._protected_status()
            except Exception:
                pass
            self.receipt["result"] = "failed"
            return
        try:
            if self.owner is not None:
                # Recheck the exact controller epoch before issuing any public stop.
                current = self.cli(["status"])
                if not self.owner_id or current.get("controllerId") != self.owner_id:
                    raise ScenarioError("cleanup refused: owned controller identity unavailable or changed")
                self.cli(["off"], mutation=True, timeout=30)
                self.cli(["quit"], mutation=True, timeout=30)
                self.owner.wait(timeout=20)
                result["ownerStopped"] = self.owner.poll() is not None
            else:
                result["ownerStopped"] = True
            result["protectedPreserved"] = self._protected_status()
            if result["ownerStopped"] and result["protectedPreserved"]:
                for server in [*self.relays, *([self.tls] if self.tls else [])]:
                    server.shutdown()
                    server.server_close()
                for thread in self.threads:
                    thread.join(timeout=3)
                if self.root.exists():
                    shutil.rmtree(self.root)
                result["workspaceRemoved"] = not self.root.exists()
                result["state"] = "complete" if result["workspaceRemoved"] else "incomplete"
            else:
                result["state"] = "preserved-for-recovery"
        except Exception as error:
            result["state"] = "preserved-for-recovery"
            result["error"] = str(error)
            try:
                result["protectedPreserved"] = self._protected_status()
            except Exception:
                pass
        if result["state"] != "complete":
            self.receipt["result"] = "failed"

    def execute(self) -> dict[str, Any]:
        try:
            if not self._protected_status():
                raise ScenarioError("protected owner identity/off state mismatch")
            self._check_installed_package()
            self.root.mkdir(mode=0o700)
            self.state.mkdir(mode=0o700)
            source, cert = self._create_fixture()
            self._start_owner()
            self._configure(source, cert)
            self._observe(source, cert)
        except Exception as error:
            self.receipt["failure"] = {"type": type(error).__name__, "message": str(error)}
        finally:
            self._cleanup()
            if "package" in self.receipt:
                try:
                    verify = self.command(["rpm", "-V", "vpn-control"], timeout=15)
                    clean = verify.returncode == 0 and not verify.stdout.strip()
                except (ScenarioError, OSError):
                    clean = False
                self.receipt["package"]["postCleanupRpmVerifyClean"] = clean
                if not clean:
                    self.receipt["result"] = "failed"
                    self.receipt.setdefault("failure", {"type": "PackageVerification",
                                                        "message": "installed RPM failed verification after cleanup"})
        return self.receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--receipt", required=True)
    args = parser.parse_args(argv)
    input_path = _absolute(args.input, "input")
    receipt_path = _absolute(args.receipt, "receipt")
    spec = validate_input(json.loads(input_path.read_text(encoding="utf-8")), receipt_path)
    receipt = ScenarioRunner(spec).execute()
    with receipt_path.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    print(json.dumps({"scenarioId": SCENARIO, "correlationId": spec["correlationId"],
                      "result": receipt["result"], "cleanup": receipt["cleanup"]["state"]}, sort_keys=True))
    return 0 if receipt["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
