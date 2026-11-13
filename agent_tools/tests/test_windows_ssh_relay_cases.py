"""The SSH relay case module against an in-memory product and in-memory relay, location and origin.

The product follows the product source: the stdin import (DesktopAndroidCli.readInput, DesktopHomeSshCredentialStore
and its owner-only ACL), the download route (SubscriptionDownloadRouteLogic, DesktopSubscriptionDownloadClient and its
bootstrap proxy's temporary files and process), the refresh result (DesktopSubscriptionService, desktopSubscriptionRefreshResponse,
DesktopOperationRunner.complete), the runtime's candidate folder and captured key (DesktopProxyRuntimeManager) and the
failure reason sing-box 1.13.4 and the JDK gave on loopback (CONNECTIVITY). The relay records what
windows_ssh_relay_fixture records, in its shapes. Nothing listens, no process starts and no Win32 call is made:
the three native reads of the module (file security, runtime census, origin TLS context) are this world's.
Each defect variant shows the oracle that catches it; the faithful product passes every group.
"""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import types
import unittest
from unittest import mock
import uuid

from agent_tools import windows_ssh_relay_cases as cases
from agent_tools import windows_ssh_relay_fixture as fixture

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
OWNER_ONLY = "O:" + SID + "D:P(A;;FA;;;" + SID + ")"
HEADERS = {"-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----",
           "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----"}
GUARDED = {"settings set", "settings apply", "ssh key import", "subscriptions add", "source set", "locations add",
           "locations select", "routing set"}
DEFAULTS = {"ssh.enabled": False, "ssh.host": "", "ssh.port": 22, "ssh.user": "", "ssh.relay-port": 10808, "ssh.host-keys": [],
            "refresh.policy": "every-hour", "refresh.find-best-after-refresh": True, "mode": "vpn",
            "validation.test-url": "https://www.gstatic.com/generate_204", "validation.retry-count": 1,
            "validation.batch-size": 4, "validation.active-verification-window-size": 3}
PORTS = iter(range(42000, 43000))


class Transport(Exception):
    """A fetch that never got an HTTP answer: what the JDK reads as an IOException (CONNECTIVITY)."""


class FakeRelay:
    by_port = {}

    def __init__(self, *, user, authorized_public, host_seed):
        self.user, self.authorized = user, fixture.ed25519_blob(authorized_public)
        self.host_public = fixture.ed25519_public(host_seed)
        self.sessions, self.socks, self.stopped, self.closed = [], [], False, False
        self.ssh_port = self.socks_port = None

    def start(self):
        self.ssh_port, self.socks_port = next(PORTS), next(PORTS)
        FakeRelay.by_port[self.ssh_port] = self
        return self

    def host_key_line(self, comment=None):
        return fixture.public_key_line(self.host_public, comment)

    def facts(self):
        return json.loads(json.dumps({"sessions": self.sessions, "socks": self.socks}))

    def stop_ssh(self, seconds=5.0):
        self.stopped = True
        for session in self.sessions:
            session["end"] = session["end"] or "stopped"
        return True

    def close(self, seconds=5.0):
        self.closed = True
        return True

    # What the product's ssh outbound does to the real relay, recorded in its shapes.
    def session(self, pinned, key_blob):
        if self.stopped or self.closed:
            raise Transport("connection refused")
        session = {"ordinal": len(self.sessions), "clientVersion": "SSH-2.0-OpenSSH_8.3", "kex": "curve25519-sha256",
                   "cipher": fixture.CIPHER, "strict": True, "keysExchanged": False, "auth": [], "authenticated": False,
                   "authenticatedKey": None, "channels": [], "end": None}
        self.sessions.append(session)
        if self.host_key_line() not in pinned:
            session["end"] = "peer-closed"
            raise Transport("host key mismatch")
        session["keysExchanged"] = True
        key = fixture.fingerprint(key_blob)
        session["auth"] = [{"user": self.user, "method": "none", "algorithm": None, "key": None, "signed": False, "result": "failure"}]
        if key_blob != self.authorized:
            session["auth"].append({"user": self.user, "method": "publickey", "algorithm": "ssh-ed25519", "key": key, "signed": False,
                                    "result": "failure"})
            session["end"] = "peer-closed"
            raise Transport("unable to authenticate")
        session["auth"] += [{"user": self.user, "method": "publickey", "algorithm": "ssh-ed25519", "key": key, "signed": signed,
                             "result": result} for signed, result in ((False, "pk-ok"), (True, "success"))]
        session.update(authenticated=True, authenticatedKey=key)
        return session

    def channel(self, session, port, host, target_port):
        session["channels"].append({"type": "direct-tcpip", "host": "127.0.0.1", "port": port,
                                    "result": "opened" if port == self.socks_port else "prohibited", "toTarget": 700, "fromTarget": 2000})
        if port != self.socks_port:
            raise Transport("channel refused")
        self.socks.append({"ordinal": len(self.socks), "host": host, "port": target_port, "result": "connected", "up": 690, "down": 1980})


class FakeOrigin:
    by_port = {}

    def __init__(self, context, path, body):
        self.context, self.path, self.body, self.requests, self.port = context, path, body, [], None

    def start(self):
        self.port = next(PORTS)
        FakeOrigin.by_port[self.port] = self
        return self

    def url(self):
        return "https://localhost:" + str(self.port) + self.path

    def served(self):
        return [dict(row) for row in self.requests]

    def close(self, seconds=5.0):
        return True

    def get(self, path):
        found = path == self.path
        self.requests.append({"method": "GET", "path": path, "status": 200 if found else 404, "bytes": len(self.body)})
        return self.body.decode("ascii") if found else None


class FakeLocation:
    by_port = {}

    def __init__(self, host, port, token, forward_host=None, forward_port=None):
        self.server_address, self.forward = ("127.0.0.1", next(PORTS)), (forward_host, forward_port)
        self.stop = threading.Event()
        FakeLocation.by_port[self.server_address[1]] = self

    def serve_forever(self, poll_interval=0.5):
        self.stop.wait(30)

    def shutdown(self):
        self.stop.set()

    def server_close(self):
        pass


def relay_module():
    return types.SimpleNamespace(**{name: getattr(fixture, name) for name in (
        "openssh_private_key", "ed25519_public", "ed25519_blob", "fingerprint", "public_key_line", "KEX", "CIPHER")},
        Relay=FakeRelay, HttpsOrigin=FakeOrigin)


class Refusal(Exception):
    def __init__(self, code, exit_code=1, bound=True):
        super().__init__(code)
        self.code, self.exit_code, self.bound = code, exit_code, bound


def public_blob(text):
    """The public key of an unencrypted OpenSSH container: what the runtime's ssh client authenticates with."""
    lines = text.strip().splitlines()
    body = fixture.Reader(base64.b64decode("".join(lines[1:-1]))[len(b"openssh-key-v1\0"):])
    body.string(), body.string(), body.string(), body.uint32()
    return body.string()


class Product:
    """One in-memory owner per workspace, answering in the recorded CLI shapes."""

    def __init__(self, defects=()):
        self.defects, self.owners, self.security, self.processes, self.calls = set(defects), {}, {}, {}, []
        self.next_pid = 5000

    def serve(self, workspace):
        Path(workspace).mkdir()
        state = {"id": str(uuid.uuid4()), "revision": 0, "workspace": Path(workspace), "key": None, "settings": dict(DEFAULTS),
                 "source": "all", "locations": [], "selected": None, "ignoreRules": False, "subscriptions": [], "runtime": None}
        self.owners[str(workspace)] = state
        self.persist(state)
        return state

    def persist(self, state):
        document = {"settings": state["settings"], "subscriptions": state["subscriptions"], "locations": state["locations"]}
        if "key-in-workspace" in self.defects and state["key"]:
            document["key"] = state["key"]
        (state["workspace"] / "workspace.json").write_bytes(json.dumps(document).encode("utf-8"))

    def commit(self, state, changed):
        if changed:
            state["revision"] += 1
        self.persist(state)

    @staticmethod
    def envelope(code, owner, revision, data):
        return {"schemaVersion": 1, "controllerId": owner, "requestId": str(uuid.uuid4()), "ok": code == "OK", "code": code,
                "message": "" if code == "OK" else code, "messageKey": None, "messageArgs": [], "final": True,
                "operationId": str(uuid.uuid4()), "configurationRevision": revision, "restartRequired": False, "data": data,
                "warnings": [] if owner else ["OWNER_METADATA_UNAVAILABLE"]}

    def reply(self, json_mode, exit_code, code, owner=None, revision=0, data=None):
        if json_mode:
            return subprocess.CompletedProcess([], exit_code, json.dumps(self.envelope(code, owner, revision, data or {})) + "\n", "")
        lines = [code, "Controller: " + owner, "Request: " + str(uuid.uuid4()), "Revision: " + str(revision), "Completion: final",
                 "Restart required: no"]
        return subprocess.CompletedProcess([], exit_code, "\n".join(lines) + "\n" if exit_code == 0 else "", "")

    def restrict(self, path, owner=SID):
        """DesktopHomeSshCredentialStore.restrictToCurrentUser: one explicit full-access ACE for the file owner."""
        sddl = "O:" + owner + "D:P(A;;FA;;;" + owner + ")"
        self.security[str(path)] = {"ownerSid": owner, "sddl": sddl}

    def security_of(self, path):
        return dict(self.security[str(path)])

    def runtimes(self, root):
        return sorted(pid for pid, image in self.processes.items() if str(image).casefold().startswith(str(root).casefold()))

    def invoke(self, workspace, *arguments, stdin=None):
        argv = list(arguments)
        json_mode = "--json" in argv
        argv = [item for item in argv if item != "--json"]
        guards = {}
        for name in ("--controller-id", "--if-revision"):
            if name in argv:
                index = argv.index(name)
                guards[name] = argv[index + 1]
                del argv[index:index + 2]
        command = " ".join(argv[:3] if argv[:2] == ["ssh", "key"] else argv[:2] if argv[0] not in ("status", "on", "off") else argv[:1])
        rest = argv[len(command.split()):]
        options = {}
        while any(item.startswith("--") for item in rest):
            index = next(number for number, item in enumerate(rest) if item.startswith("--"))
            options[rest[index]] = rest[index + 1]
            del rest[index:index + 2]
        self.calls.append((command, stdin is not None))
        state = self.owners[str(workspace)]
        try:
            if "--if-revision" in guards and command in GUARDED and int(guards["--if-revision"]) != state["revision"]:
                raise Refusal("CONFLICT")
            data, exit_code, code = self.dispatch(state, command, rest, options, stdin)
        except Refusal as refusal:
            return self.reply(json_mode, refusal.exit_code, refusal.code, state["id"] if refusal.bound else None,
                              state["revision"] if refusal.bound else 0)
        return self.reply(json_mode, exit_code, code, state["id"], state["revision"], data)

    @staticmethod
    def read_input(value, stdin, defects):
        if value == "-":
            if stdin is None or "stdin-ignored" in defects:
                return ""
            return Path(stdin).read_bytes().decode("utf-8")
        return Path(value).read_bytes().decode("utf-8")

    def dispatch(self, state, command, rest, options, stdin):
        settings = state["settings"]
        if command == "status":
            running = state["runtime"] is not None
            return {"runtimeRunning": running, "activeMode": "proxy-only" if running else None}, 0, "OK"
        if command == "ssh key status":
            return {"present": state["key"] is not None}, 0, "OK"
        if command == "ssh key import":
            return self.import_key(state, self.read_input(options["--input"], stdin, self.defects)), 0, "OK"
        if command == "settings show":
            return dict(settings), 0, "OK"
        if command in ("settings set", "settings apply"):
            if command == "settings apply":
                patch = json.loads(Path(options["--input"]).read_bytes())
            else:
                key, raw = rest
                patch = {key: raw if key in ("ssh.host", "ssh.user", "mode", "refresh.policy", "validation.test-url") else json.loads(raw)}
            proposed = {**settings, **patch}
            if proposed["ssh.enabled"] and (not proposed["ssh.host-keys"] or state["key"] is None):
                raise Refusal("INVALID_ARGUMENT")
            changed = proposed != settings
            state["settings"] = proposed
            self.commit(state, changed)
            return dict(patch), 0, "OK"
        if command == "logs --limit":
            return {"entries": []}, 0, "OK"
        if command == "diagnostics export":
            report = "VPN Control Desktop Diagnostics\nis_runtime_running=" + str(state["runtime"] is not None).lower() + "\n"
            if "key-in-diagnostics" in self.defects:
                report += state["key"]
            Path(options["--output"]).write_bytes(report.encode("utf-8"))
            return {"format": "text", "bytes": len(report)}, 0, "OK"
        if command == "subscriptions add":
            identifier = str(uuid.uuid4())
            state["subscriptions"].append({"id": identifier, "name": options["--name"], "source": options["--source"],
                                           "cachedLocations": [], "refreshStatus": "", "failureReason": None})
            self.commit(state, True)
            return {"id": identifier}, 0, "OK"
        if command == "subscriptions list":
            return {"subscriptions": [{"id": row["id"], "name": row["name"], "cachedLocations": len(row["cachedLocations"]),
                                       "refreshStatus": row["refreshStatus"], "failureReason": row["failureReason"]}
                                      for row in state["subscriptions"]]}, 0, "OK"
        if command == "subscriptions refresh":
            return self.refresh(state, rest[0])
        if command == "source set":
            changed = state["source"] != rest[0]
            state["source"] = rest[0]
            self.commit(state, changed)
            return {}, 0, "OK"
        if command == "locations add":
            if state["source"] != "current-locations":
                raise Refusal("READ_ONLY_SOURCE")
            link = Path(options["--input"]).read_bytes().decode("ascii").strip()
            address, name = link[len("socks://"):].split("#")
            host, port = address.split(":")
            state["locations"].append({"name": name.replace("%20", " "), "host": host, "port": int(port)})
            self.commit(state, True)
            return {}, 0, "OK"
        if command == "locations select":
            if rest[0] not in [location["name"] for location in state["locations"]]:
                raise Refusal("NOT_FOUND")
            changed = state["selected"] != rest[0]
            state["selected"] = rest[0]
            self.commit(state, changed)
            return {}, 0, "OK"
        if command == "routing set":
            changed = state["ignoreRules"] is not True
            state["ignoreRules"] = True
            self.commit(state, changed)
            return {}, 0, "OK"
        if command == "on":
            return self.connect(state)
        if command == "off":
            return self.disconnect(state)
        raise AssertionError("unmodelled command: " + command)

    def import_key(self, state, content):
        normalized = content.strip()
        header = normalized.splitlines()[0] if normalized else ""
        encrypted = header == "-----BEGIN ENCRYPTED PRIVATE KEY-----" or "Proc-Type: 4,ENCRYPTED" in normalized
        if not normalized or header not in HEADERS or encrypted and "encrypted-accepted" not in self.defects:
            raise Refusal("INVALID_ARGUMENT")
        changed = (state["key"] or "").strip() != normalized or "retry-bumps" in self.defects
        state["key"] = normalized + "\n"
        folder = state["workspace"] / "credentials"
        folder.mkdir(exist_ok=True)
        if "temp-left" in self.defects:
            (folder / "home-ssh-key-123.tmp").write_bytes(b"")
        target = folder / "home-ssh-private-key"
        target.write_bytes((normalized + ("\r\n" if "stored-crlf" in self.defects else "\n")).encode("utf-8"))
        self.restrict(target, "S-1-5-32-544" if "acl-other-owner" in self.defects else SID)
        if "acl-inherited" in self.defects:
            self.security[str(target)]["sddl"] = "O:" + SID + "D:AI(A;;FA;;;" + SID + ")(A;ID;FA;;;SY)"
        self.commit(state, changed)
        return {"echo": state["key"]} if "echo-key" in self.defects else {}

    # The download route of DesktopSubscriptionDownloadClient, through the in-memory relay.
    def route(self, state):
        running, ssh = state["runtime"] is not None, state["settings"]["ssh.enabled"]
        if running:
            return "DIRECT" if "connected-direct" in self.defects else "HOME_RELAY" if "connected-uses-bootstrap" in self.defects else "ACTIVE_SESSION"
        return "DIRECT" if not ssh or "home-relay-direct" in self.defects else "HOME_RELAY"

    def fetch(self, state, route, url):
        port, path = int(url.split(":")[2].split("/")[0]), "/" + url.split("/", 3)[3]
        origin = FakeOrigin.by_port[port]
        if route == "DIRECT":
            return origin.get(path)
        settings = state["settings"]
        relay = FakeRelay.by_port.get(settings["ssh.port"])
        if route == "ACTIVE_SESSION":
            runtime = state["runtime"]
            location = state["location"]
            relay.channel(runtime["session"], settings["ssh.relay-port"], "127.0.0.1", location["port"])
            return origin.get(path)
        workspace = state["workspace"] / "runtime"
        workspace.mkdir(exist_ok=True)
        files = [workspace / ("home-ssh-bootstrap-1." + suffix) for suffix in ("json", "log")]
        for item in files:
            item.write_bytes(b"{}")
        pid = self.start_process(state)
        try:
            if relay is None:
                raise Transport("connection refused")
            session = relay.session(settings["ssh.host-keys"], public_blob(state["key"]))
            egress = (("127.0.0.1", next(iter(FakeLocation.by_port))) if "home-egress-through-location" in self.defects
                      else ("localhost", port))
            relay.channel(session, settings["ssh.relay-port"], *egress)
            body = origin.get(path)
            session["end"] = "peer-closed"
            return body
        finally:
            if "bootstrap-files-left" not in self.defects:
                for item in files:
                    item.unlink()
            if "bootstrap-process-left" not in self.defects:
                del self.processes[pid]

    def start_process(self, state):
        self.next_pid += 4
        self.processes[self.next_pid] = state["workspace"] / "runtime" / "tools" / "sing-box.exe"
        return self.next_pid

    def refresh(self, state, identifier):
        row = next(row for row in state["subscriptions"] if row["id"] == identifier)
        route = self.route(state)
        try:
            try:
                body = self.fetch(state, route, row["source"])
            except Transport:
                if "stopped-fallback-direct" not in self.defects:
                    raise
                body = self.fetch(state, "DIRECT", row["source"])
            count = len([line for line in body.splitlines() if line.startswith("socks://")])
        except Transport:
            reason = "TLS" if "stopped-reason-tls" in self.defects else "CONNECTIVITY"
            row.update(refreshStatus="FAILED", failureReason=reason)
            if "stopped-cache-cleared" in self.defects:
                row["cachedLocations"] = []
            self.commit(state, False)
            code = "REFRESH_FAILED" if "failure-envelope-refresh-failed" in self.defects else "RUNTIME_FAILED"
            return {"code": "REFRESH_FAILED", "sources": [{"id": identifier, "ok": False, "locationCount": None,
                                                           "failureReason": reason}]}, 1, code
        row.update(cachedLocations=["socks"] * count, refreshStatus="OK", failureReason=None)
        self.commit(state, False)
        source = {"id": identifier, "ok": True, "locationCount": count, "failureReason": None}
        if "refresh-data-shape" in self.defects:
            del source["failureReason"]
        return {"code": "OK", "sources": [source]}, 0, "OK"

    def connect(self, state):
        settings = state["settings"]
        location = next(item for item in state["locations"] if item["name"] == state["selected"])
        if settings["mode"] != "proxy-only" or "on-fails" in self.defects:
            raise Refusal("RUNTIME_FAILED")
        runtime_folder = state["workspace"] / "runtime"
        runtime_folder.mkdir(exist_ok=True)
        candidate = runtime_folder / "candidate-7"
        candidate.mkdir()
        copy = candidate / "home-ssh-private-key"
        copy.write_bytes((state["key"].strip() + ("" if "key-copy-differs" in self.defects else "\n")).encode("ascii"))
        self.restrict(copy)
        if "key-copy-acl" in self.defects:
            self.security[str(copy)]["sddl"] = OWNER_ONLY + "(A;;FA;;;BA)"
        relay = FakeRelay.by_port[settings["ssh.port"]]
        session = relay.session(settings["ssh.host-keys"], public_blob(state["key"]))
        state["location"] = location
        state["runtime"] = {"session": session, "candidate": candidate, "pid": self.start_process(state)}
        # The start's own verification of validation.test-url goes through the chain too.
        relay.channel(session, settings["ssh.relay-port"], "127.0.0.1", location["port"])
        url = settings["validation.test-url"]
        FakeOrigin.by_port[int(url.split(":")[2].split("/")[0])].get("/" + url.split("/", 3)[3])
        return {}, 0, "OK"

    def disconnect(self, state):
        runtime = state["runtime"]
        if runtime is not None:
            runtime["session"]["end"] = "peer-closed"
            if "candidate-left" not in self.defects:
                (runtime["candidate"] / "home-ssh-private-key").unlink()
                runtime["candidate"].rmdir()
            if "runtime-left" not in self.defects:
                del self.processes[runtime["pid"]]
        state["runtime"] = None
        return {}, 0, "OK"


class Owner:
    def __init__(self, root, product, workspace):
        self.root, self.product, self.events = Path(root), product, []
        self.operation = str(uuid.uuid4())
        bundle = self.root / "bundle"
        bundle.mkdir()
        self.request = {"action": "disconnected-cli-config", "casesPath": str(bundle / "windows_ssh_relay_cases.py"),
                        "workspace": str(workspace), "context": {"ordinarySid": SID}}
        held = [bundle / leaf for leaf in ("windows_ssh_relay_cases.py", cases.RELAY_SOURCE, cases.SOCKS_SOURCE, cases.CERTIFICATE,
                                           cases.PRIVATE_KEY, cases.TRUST_STORE)]
        self.by_path = {str(path).casefold(): object() for path in held}
        self.environment, self.modules = {}, []

    def event(self, kind, value):
        self.events.append({"kind": kind, "value": json.loads(json.dumps(value))})

    def invoke(self, workspace, *arguments, timeout=30, stdin=None):
        return self.product.invoke(workspace, *arguments, stdin=stdin)

    def module(self, path, name):
        self.modules.append((Path(path).name, name))
        return relay_module() if Path(path).name == cases.RELAY_SOURCE else types.SimpleNamespace(FixtureServer=FakeLocation)


class CaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for kind in (FakeRelay, FakeOrigin, FakeLocation):
            kind.by_port = {}
        self.keys = []
        original = fixture.openssh_private_key

        def remember(*args, **kwargs):
            self.keys.append(original(*args, **kwargs))
            return self.keys[-1]
        self.enterContext(mock.patch.object(fixture, "openssh_private_key", remember))
        self.enterContext(mock.patch.object(cases, "ORIGIN_CONTEXT", lambda certificate, key: "origin-context"))
        self.enterContext(mock.patch.object(cases, "CENSUS_SECONDS", 0.3))  # A left runtime is refused at this bound.
        self.count = 0

    def run_cases(self, *defects):
        self.count += 1
        product = Product(defects)
        workspace = self.root / ("workspace-" + str(self.count))
        state = product.serve(workspace)
        operation = self.root / ("operation-" + str(self.count))
        operation.mkdir()
        owner = Owner(operation, product, workspace)
        self.owner, self.state, self.product = owner, state, product
        with mock.patch.object(cases, "SECURITY", product.security_of), mock.patch.object(cases, "RUNTIMES", product.runtimes):
            cases.run(owner, workspace, state["id"], {})
        return owner, state

    def assert_caught(self, defect, reason):
        with self.assertRaises(AssertionError) as caught:
            self.run_cases(defect)
        self.assertEqual(reason, str(caught.exception))

    def facts(self, owner, group):
        return next(event["value"]["facts"] for event in owner.events
                    if event["kind"] == "ssh-relay-group-complete" and event["value"]["group"] == group)

    def test_the_faithful_product_passes_every_group_in_order(self):
        owner, state = self.run_cases()
        groups = [event["value"]["group"] for event in owner.events if event["kind"] == "ssh-relay-group-complete"]
        self.assertEqual(list(cases.GROUPS), groups)
        self.assertEqual("ssh-relay-cases-complete", owner.events[-1]["kind"])
        self.assertEqual([], owner.events[-1]["value"]["remainingProcedures"])
        self.assertEqual({"committed": 2, "retryNoOp": 2, "refusedContents": 3, "replaced": True, "privateStorage": True,
                          "credentialAcl": {"ownerSid": "ordinary", "aces": 1},
                          "storedKeyFingerprint": fixture.fingerprint(public_blob(self.keys[1]))},
                         self.facts(owner, "ssh-stdin-key-import"))
        for group in ("ssh-relay-disconnected", "ssh-relay-after-disconnect"):
            self.assertEqual({"route": "HOME_RELAY", "sessions": 1, "channels": 1, "egress": "origin",
                              "leftovers": {"candidates": 0, "runtimes": 0}}, self.facts(owner, group))
        self.assertEqual({"route": "ACTIVE_SESSION", "startSessions": 1, "refreshSessions": 0, "channels": 1, "egress": "location",
                          "runtimeKeyCopyAcl": {"ownerSid": "ordinary", "aces": 1}, "afterOff": {"candidates": 0, "runtimes": 0}},
                         self.facts(owner, "ssh-relay-connected"))
        self.assertTrue(self.facts(owner, "ssh-relay-host-key-mismatch")["keyExchangeOnly"])
        self.assertEqual("CONNECTIVITY", self.facts(owner, "ssh-relay-stopped")["failureReason"])
        relay = next(iter(FakeRelay.by_port.values()))
        self.assertEqual([("localhost", "connected"), ("127.0.0.1", "connected"), ("127.0.0.1", "connected"), ("localhost", "connected")],
                         [(row["host"], row["result"]) for row in relay.socks], "start check, connected refresh, then the bootstrap again")
        self.assertTrue(relay.stopped and relay.closed)
        self.assertEqual([(cases.RELAY_SOURCE, "_owned_ssh_relay_fixture"), (cases.SOCKS_SOURCE, "_owned_ssh_relay_location")], owner.modules)
        self.assertIsNone(state["runtime"])
        self.assertEqual({}, self.product.processes)
        imports = [stdin for command, stdin in self.product.calls if command == "ssh key import"]
        self.assertEqual([True] * 7, imports, "every key import of this row reads stdin")

    def test_no_key_line_reaches_an_event_or_a_top_level_file(self):
        owner, _ = self.run_cases()
        events = json.dumps(owner.events)
        lines = [line for key in self.keys for line in cases.key_lines(key)]
        self.assertEqual(2, len(self.keys))
        self.assertTrue(lines)
        self.assertEqual([], [line for line in lines if line in events])
        top = [path for path in owner.root.iterdir() if path.is_file()]
        self.assertEqual([], [path for path in top if any(line.encode() in path.read_bytes() for line in lines)])
        inputs = [event["value"] for event in owner.events if event["kind"] == "ssh-relay-input" and event["value"].get("keyMaterial")]
        self.assertEqual(3, len(inputs))
        self.assertTrue(all(set(value) == {"name", "bytes", "keyMaterial"} for value in inputs), "no digest of key material")
        stdin = [event["value"]["stdin"] for event in owner.events if event["kind"] == "ssh-relay-command-intent" and "stdin" in event["value"]]
        self.assertEqual(7, len(stdin))
        self.assertTrue(all(name.endswith(".txt") for name in stdin), "an intent names its stdin file, never its bytes")

    def test_each_defect_is_caught_by_its_oracle(self):
        for defect, reason in (
                ("stdin-ignored", "json-exit-code"), ("retry-bumps", "json-commit-revision"),
                ("encrypted-accepted", "json-exit-code"), ("temp-left", "credential-folder-leftovers"),
                ("stored-crlf", "stored-key-differs"), ("acl-inherited", "credential-acl-dacl"),
                ("acl-other-owner", "credential-acl-owner"), ("key-in-workspace", "key-material-in-workspace-state"),
                ("key-in-diagnostics", "key-material-in-diagnostics"), ("echo-key", "key-material-in-cli-output"),
                ("home-relay-direct", "relay-bootstrap-session"), ("home-egress-through-location", "relay-bootstrap-egress"),
                ("bootstrap-files-left", "bootstrap-files-left"), ("bootstrap-process-left", "runtime-process-left"),
                ("refresh-data-shape", "relay-refresh-data"),
                ("on-fails", "json-exit-code"), ("key-copy-differs", "runtime-key-copy-differs"),
                ("key-copy-acl", "runtime-key-copy-acl-dacl"), ("connected-uses-bootstrap", "relay-connected-egress-not-through-location"),
                ("connected-direct", "relay-runtime-channel"), ("candidate-left", "runtime-candidates-left"),
                ("runtime-left", "runtime-process-left"), ("stopped-fallback-direct", "json-exit-code"),
                ("stopped-cache-cleared", "relay-pin-mismatch-row"), ("stopped-reason-tls", "relay-pin-mismatch-refresh-data"),
                ("failure-envelope-refresh-failed", "json-envelope-code")):
            with self.subTest(defect=defect):
                for kind in (FakeRelay, FakeOrigin, FakeLocation):
                    kind.by_port = {}
                self.assert_caught(defect, reason)
                relay = next(iter(FakeRelay.by_port.values()), None)
                self.assertTrue(relay is None or relay.closed, "the relay closes on every end")
                self.assertIsNone(self.state["runtime"], "a runtime this module started is off before the owner's closing")

    def test_a_failure_while_connected_turns_the_runtime_off_through_the_public_off(self):
        with self.assertRaises(AssertionError) as caught:
            self.run_cases("key-copy-acl")
        self.assertEqual("runtime-key-copy-acl-dacl", str(caught.exception))
        kinds = [event["kind"] for event in self.owner.events]
        self.assertIn("ssh-relay-runtime-off-intent", kinds)
        self.assertEqual(["on", "off"], [command for command, _ in self.product.calls if command in ("on", "off")])
        self.assertEqual("status", [command for command, _ in self.product.calls][-2], "the off follows a read of the owner")
        self.assertLess(kinds.index("ssh-relay-runtime-off-intent"), kinds.index("ssh-relay-fixtures-closed"))

    def closing_after(self, *defects):
        """The owner's own known-failure closing (windows_ordinary_process_owner.close_known_failure) right after the
        module failed: it quits the serve through the public quit and never parks, unless an owner is left running."""
        from agent_tools import windows_ordinary_process_owner as process_owner
        self.count += 1
        product = Product(defects)
        operation = self.root / ("closing-" + str(self.count))
        operation.mkdir()
        workspace = operation / "workspace"
        state = product.serve(workspace)
        owner = Owner(operation, product, workspace)
        owner.request["cliPath"] = "held-cli.exe"
        owner.parks = []

        def park(reason, error=None):
            owner.parks.append(reason)
            raise RuntimeError("parked:" + reason)
        owner.park = park

        class Serve:
            label, ordinal, pid, birth, new_console, terminal = "serve", 0, 4100, "inert-birth", False, None
            argv = ("held-cli.exe", "--state-dir", str(workspace), "serve")
            process = types.SimpleNamespace(poll=lambda: None)

            def observe(self):
                if state.get("quit") and self.terminal is None:
                    self.terminal = {"exitCode": 0}
                return self.terminal
        serve = Serve()
        owner.children = [serve]
        original = product.dispatch

        def dispatch(state_, command, rest, options, stdin):
            if command == "quit":
                state_["quit"] = True
                return {}, 0, "OK"
            return original(state_, command, rest, options, stdin)
        product.dispatch = dispatch
        with mock.patch.object(cases, "SECURITY", product.security_of), mock.patch.object(cases, "RUNTIMES", product.runtimes), \
                self.assertRaises(AssertionError) as caught:
            cases.run(owner, workspace, state["id"], {})
        try:
            process_owner.close_known_failure(owner, workspace, state["id"], serve, caught.exception)
        except RuntimeError as parked:
            return owner, state, serve, str(caught.exception), str(parked)
        return owner, state, serve, str(caught.exception), None

    def test_a_known_failure_while_connected_is_closed_by_the_owner_without_a_park(self):
        owner, state, serve, reason, parked = self.closing_after("key-copy-acl")
        self.assertEqual(("runtime-key-copy-acl-dacl", None, []), (reason, parked, owner.parks))
        self.assertEqual({"exitCode": 0}, serve.terminal)
        self.assertIsNone(state["runtime"])
        kinds = [event["kind"] for event in owner.events]
        self.assertLess(kinds.index("ssh-relay-runtime-off-intent"), kinds.index("known-failure-closing"))
        self.assertEqual("known-failure-closed", kinds[-1])

    def test_an_owner_left_connected_parks_the_closing_with_every_original_kept(self):
        # The control: had the module not turned the runtime off, the owner's quit admission would refuse and park.
        with mock.patch.object(cases, "close", lambda c, fixtures, error: fixtures.close()):
            owner, state, serve, reason, parked = self.closing_after("key-copy-acl")
        # A real park never returns; this peer's raises, so the closing's own catch-all parks a second time behind it.
        self.assertEqual(("runtime-key-copy-acl-dacl", ["known-failure-quit-admission"]), (reason, owner.parks[:1]))
        self.assertIsNotNone(parked)
        self.assertIsNotNone(state["runtime"])
        self.assertIsNone(serve.terminal)

    def test_a_start_the_product_refused_is_never_followed_by_an_off(self):
        with self.assertRaises(AssertionError):
            self.run_cases("on-fails")
        self.assertNotIn("off", [command for command, _ in self.product.calls])

    def test_a_loopback_endpoint_that_cannot_bind_is_a_known_failure(self):
        def refused(self):
            raise OSError("address unavailable")
        with mock.patch.object(FakeOrigin, "start", refused), self.assertRaises(AssertionError) as caught:
            self.run_cases()
        self.assertEqual("loopback-endpoint-unavailable", str(caught.exception))
        groups = [event["value"]["group"] for event in self.owner.events if event["kind"] == "ssh-relay-group-complete"]
        self.assertEqual(["ssh-stdin-key-import"], groups)

    def test_configure_launch_scopes_the_trust_store_to_the_serve(self):
        workspace = self.root / "launch-workspace"
        operation = self.root / "launch-operation"
        operation.mkdir()
        owner = Owner(operation, Product(), workspace)
        cases.configure_launch(owner, workspace)
        store = str(Path(owner.request["casesPath"]).with_name(cases.TRUST_STORE))
        self.assertEqual({"JAVA_TOOL_OPTIONS": '"-Djavax.net.ssl.trustStore=' + store + '" -Djavax.net.ssl.trustStorePassword=changeit'},
                         owner.environment)
        self.assertEqual([{"kind": "ssh-relay-trust-scoped", "value": {"trustStore": cases.TRUST_STORE, "scope": "original-serve-only"}}],
                         owner.events)
        for name, change, reason in (("preexisting", lambda o: o.environment.update(JAVA_TOOL_OPTIONS="-Dother"), "no-preexisting-owner-jvm-options"),
                                     ("unheld", lambda o: o.by_path.clear(), "ssh-relay-file-not-held:" + cases.TRUST_STORE),
                                     ("other-action", lambda o: o.request.update(action="streaming-client-interrupt"), "finite-case-action")):
            with self.subTest(name=name):
                folder = self.root / ("launch-" + name)
                folder.mkdir()
                owner = Owner(folder, Product(), workspace)
                change(owner)
                with self.assertRaises(AssertionError) as caught:
                    cases.configure_launch(owner, workspace)
                self.assertEqual(reason, str(caught.exception))
        with self.assertRaises(AssertionError) as caught:
            cases.run(owner, workspace, "id", {})
        self.assertEqual("finite-case-action", str(caught.exception))

    def test_the_module_is_plain_ascii_and_does_nothing_on_import(self):
        raw = Path(cases.__file__).read_bytes()
        self.assertTrue(all(byte < 128 for byte in raw))
        self.assertEqual("disconnected-cli-config", cases.ACTION)
        # The native reads are the module's own outside these tests (setUp replaces only the TLS context).
        self.assertEqual((cases._windows_security, cases._windows_runtimes), (cases.SECURITY, cases.RUNTIMES))
        self.assertEqual("changeit", __import__("agent_tools.windows_scenario_proxy", fromlist=["x"]).TRUST_PASSWORD)


if __name__ == "__main__":
    unittest.main()
