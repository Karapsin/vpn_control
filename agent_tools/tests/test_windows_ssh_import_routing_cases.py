"""The SSH import and routing case module against an in-memory product.

The product answers in the recorded CLI shapes (test_windows_cli_case_rules) and follows the product source's
rules: SSH key import (DesktopHomeSshCredentialStore, importControlSshKey), the SSH Routing truth table
(HomeSshRouteLogic.validate), routing import (RoutingRulesTransfer.import), the parser's refusals
(ControlCliParser) and the download route (SubscriptionDownloadRouteLogic). Nothing listens and no process
starts: in-memory peers stand in for the loopback endpoints, and the product "connects" to them by port.
Each defect variant shows the oracle that catches it; the faithful product passes every group.
"""
import base64
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import uuid

from agent_tools import windows_ssh_import_routing_cases as cases

GUARDED = {"settings set", "settings apply", "ssh key import", "subscriptions add", "subscriptions delete", "routing import", "quit"}
ASYNCHRONOUS = {"subscriptions refresh", "subscriptions add", "diagnostics export"}
OPTIONS = {"--input", "--output", "--source", "--name", "--limit", "--format"}
HEADERS = {"-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----",
           "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----"}
HOST_KEY_ALGORITHMS = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                       "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"}
PARSER_REFUSAL = "INVALID_ARGUMENT: invalid state directory or command.\n"


class Endpoint:
    """In-memory stand-in for LoopbackEndpoint: the product appends what a client would send first."""
    by_port = {}
    next_port = 41000

    def __init__(self, label, first):
        Endpoint.next_port += 1
        self.label, self.first, self.port = label, first, Endpoint.next_port
        self.connections, self.closed = [], False
        Endpoint.by_port[self.port] = self

    def seen(self):
        return list(self.connections)

    def close(self):
        self.closed = True


class Refusal(Exception):
    def __init__(self, code, exit_code=1, bound=True):
        super().__init__(code)
        self.code, self.exit_code, self.bound = code, exit_code, bound


def _host_key(raw):
    fields = raw.strip().split()
    index = next((number for number, field in enumerate(fields) if field.startswith(("ssh-", "ecdsa-", "sk-"))), -1)
    if len(fields) < 2 or index < 0 or index + 1 >= len(fields) or fields[index] not in HOST_KEY_ALGORITHMS:
        return None
    encoded = fields[index + 1]
    if len(encoded) < 16 or not all(c.isalnum() or c in "+/=" for c in encoded):
        return None
    return fields[index] + " " + encoded


class Product:
    """One in-memory owner per workspace, answering in the recorded output shapes."""

    def __init__(self, defects=()):
        self.defects, self.owners = set(defects), {}

    def serve(self, workspace):
        Path(workspace).mkdir()
        state = {"id": str(uuid.uuid4()), "revision": 0, "key": None, "workspace": Path(workspace), "subscriptions": [],
                 "settings": {"ssh.enabled": False, "ssh.host": "", "ssh.port": 22, "ssh.user": "", "ssh.relay-port": 10808,
                              "ssh.host-keys": [], "validation.batch-size": 4},
                 "rules": {"ignore_rules": False, "block_quic_udp_443": False, "proxy_packages": [], "direct_domain_suffixes": []}}
        self.owners[str(workspace)] = state
        self.persist(state)
        return state

    def persist(self, state):
        # Every file the product writes is bytes, as its own Files.writeString is: never platform text mode.
        document = {"settings": state["settings"], "rules": state["rules"], "subscriptions": state["subscriptions"]}
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
                "message": "" if code == "OK" else code, "messageKey": None, "messageArgs": [], "final": True, "operationId": None,
                "configurationRevision": revision, "restartRequired": False, "data": data,
                "warnings": [] if owner else ["OWNER_METADATA_UNAVAILABLE"]}

    def reply(self, json_mode, exit_code, code, owner=None, revision=0, data=None):
        if json_mode:
            return subprocess.CompletedProcess([], exit_code, json.dumps(self.envelope(code, owner, revision, data or {})) + "\n", "")
        if owner is None:
            return subprocess.CompletedProcess([], exit_code, "", PARSER_REFUSAL)
        lines = [code, "Controller: " + owner, "Request: " + str(uuid.uuid4()), "Revision: " + str(revision), "Completion: final",
                 "Restart required: no"]
        if data:
            lines.append("Data:")
            lines += ["  " + key + ": " + (value if type(value) is str else json.dumps(value)) for key, value in data.items()]
        text = "\n".join(lines) + "\n"
        return subprocess.CompletedProcess([], exit_code, text if exit_code == 0 else "", "" if exit_code == 0 else text)

    @staticmethod
    def read_input(value):
        if value == "-":
            return ""  # Every owner child's stdin is empty.
        try:
            return Path(value).read_text(encoding="utf-8")
        except OSError:
            raise Refusal("INVALID_ARGUMENT", bound=False) from None

    def invoke(self, workspace, *arguments, timeout=30):
        argv = list(arguments)
        switches = {name: name in argv for name in ("--json", "--async")}
        argv = [item for item in argv if item not in switches]
        guards = {}
        for name in ("--controller-id", "--if-revision"):
            if name in argv:
                index = argv.index(name)
                guards[name] = argv[index + 1]
                del argv[index:index + 2]
        json_mode = switches["--json"]
        command = " ".join(argv[:3] if argv[:2] == ["ssh", "key"] else argv[:2])
        positional = [item for item in argv[len(command.split()):]]
        options = {}
        while any(item.startswith("--") for item in positional):
            index = next(number for number, item in enumerate(positional) if item.startswith("--"))
            if positional[index] not in OPTIONS or index + 1 >= len(positional):
                return self.reply(json_mode, 1, "INVALID_ARGUMENT")
            options[positional[index]] = positional[index + 1]
            del positional[index:index + 2]
        if (("--if-revision" in guards and "--controller-id" not in guards) or ("--if-revision" in guards and command not in GUARDED)
                or (switches["--async"] and command not in ASYNCHRONOUS) or (json_mode and options.get("--output") == "-")):
            return self.reply(json_mode, 1, "INVALID_ARGUMENT")
        state = self.owners.get(str(workspace))
        if state is None:
            return self.reply(json_mode, 2, "UNAVAILABLE")
        try:
            data, exit_code, code = self.dispatch(state, command, positional, options, guards, json_mode)
        except Refusal as refusal:
            return self.reply(json_mode, refusal.exit_code, refusal.code, state["id"] if refusal.bound else None,
                              state["revision"] if refusal.bound else 0)
        if data is not None and type(data) is str:
            return subprocess.CompletedProcess([], 0, data, "")
        return self.reply(json_mode, exit_code, code, state["id"], state["revision"], data)

    def guard(self, state, command, guards):
        if command not in GUARDED:
            return
        if guards.get("--controller-id") not in (None, state["id"]):
            raise Refusal("CONFLICT")
        if "--if-revision" in guards and int(guards["--if-revision"]) != state["revision"] and not (
                command == "ssh key import" and "stale-accepted" in self.defects
                or command == "routing import" and "routing-stale-accepted" in self.defects):
            raise Refusal("CONFLICT")

    def dispatch(self, state, command, positional, options, guards, json_mode):
        content = self.read_input(options["--input"]) if "--input" in options else None
        self.guard(state, command, guards)
        if command == "status":
            return {"runtimeRunning": False}, 0, "OK"
        if command == "ssh key status":
            return {"present": state["key"] is not None}, 0, "OK"
        if command == "ssh key import":
            return self.import_key(state, content), 0, "OK"
        if command == "settings show":
            shown = dict(state["settings"])
            return ({positional[0]: shown[positional[0]]} if positional else shown), 0, "OK"
        if command in ("settings apply", "settings set"):
            if command == "settings apply":
                patch = json.loads(content)
            else:
                key, raw = positional
                patch = {key: raw if key in ("ssh.host", "ssh.user") else json.loads(raw)}
            return self.apply(state, patch), 0, "OK"
        if command == "routing show":
            if "routing-shape" in self.defects:
                return {"rules": state["rules"]}, 0, "OK"
            return {"routing": self.routing_document(state)}, 0, "OK"
        if command == "routing import":
            return self.import_routing(state, content), 0, "OK"
        if command == "routing export":
            text = json.dumps(self.routing_document(state))
            if options["--output"] == "-":
                return text + "\n", 0, "OK"
            target = Path(options["--output"])
            if target.exists() and "export-overwrites" not in self.defects:
                raise Refusal("PERSISTENCE_FAILED")
            target.write_bytes(text.encode("utf-8"))
            return {"bytes": len(text)}, 0, "OK"
        if command == "logs --limit":
            return {"entries": []}, 0, "OK"
        if command == "diagnostics export":
            report = "VPN Control Desktop Diagnostics\ngenerated_at=now\nis_runtime_running=false\n"
            if "key-in-diagnostics" in self.defects:
                report += state["key"]
            target = Path(options["--output"])
            if target.exists():
                raise Refusal("PERSISTENCE_FAILED")
            target.write_bytes(report.encode("utf-8"))
            return {"format": "text", "bytes": len(report)}, 0, "OK"
        if command == "subscriptions add":
            identifier = str(uuid.uuid4())
            state["subscriptions"].append({"id": identifier, "name": options["--name"], "source": options["--source"],
                                           "cachedLocations": 0, "refreshStatus": "", "failureReason": None})
            self.commit(state, True)
            return {"id": identifier}, 0, "OK"
        if command == "subscriptions list":
            return {"subscriptions": [{k: v for k, v in row.items() if k != "source"} for row in state["subscriptions"]]}, 0, "OK"
        if command == "subscriptions delete":
            state["subscriptions"] = [row for row in state["subscriptions"] if row["id"] != positional[0]]
            self.commit(state, True)
            return {}, 0, "OK"
        if command == "subscriptions refresh":
            return self.refresh(state, positional[0])
        raise AssertionError("unmodelled command: " + command)

    def import_key(self, state, content):
        normalized = content.strip()
        header = normalized.splitlines()[0] if normalized else ""
        encrypted = header == "-----BEGIN ENCRYPTED PRIVATE KEY-----" or "Proc-Type: 4,ENCRYPTED" in normalized
        if not normalized or header not in HEADERS or encrypted and "encrypted-accepted" not in self.defects:
            raise Refusal("INVALID_ARGUMENT")
        changed = (state["key"] or "").strip() != normalized or "retry-bumps" in self.defects
        state["key"] = normalized + "\n"
        credentials = state["workspace"] / "credentials"
        credentials.mkdir(exist_ok=True)
        (credentials / "home-ssh-private-key").write_bytes(state["key"].encode("utf-8"))
        self.commit(state, changed)
        return {"echo": state["key"]} if "echo-key" in self.defects else {}

    def apply(self, state, patch):
        if set(patch) - set(state["settings"]):
            raise Refusal("INVALID_ARGUMENT")
        proposed = {**state["settings"], **patch}
        if any(key.startswith("ssh.") for key in patch):
            host = proposed["ssh.host"].strip()
            if host.startswith("ssh://"):
                host = host[len("ssh://"):].rstrip("/")
            keys = [key for key in proposed["ssh.host-keys"] if key.strip()]
            normalized_keys = (keys if "host-keys-not-normalized" in self.defects
                               else list(dict.fromkeys(filter(None, map(_host_key, keys)))))
            user = proposed["ssh.user"].strip()
            if proposed["ssh.enabled"] and not (
                    keys and all(_host_key(key) for key in keys) and host and not any(c in host for c in "/@?#")
                    and host.count(":") != 1 and 1 <= proposed["ssh.port"] <= 65535 and user
                    and 1 <= proposed["ssh.relay-port"] <= 65535
                    and (state["key"] is not None or "enable-without-key" in self.defects)):
                raise Refusal("INVALID_ARGUMENT")
            proposed.update({"ssh.host": host, "ssh.user": user, "ssh.host-keys": normalized_keys})
        changed = proposed != state["settings"]
        state["settings"] = proposed
        self.commit(state, changed)
        return {key: proposed[key] for key in patch}

    @staticmethod
    def routing_document(state):
        return {"type": "vpn_control_routing_rules", "version": 7, "exportedAt": "now", "rules": dict(state["rules"])}

    def import_routing(self, state, content):
        try:
            root = json.loads(content)
            rules = root.get("rules", root)
            recognized = root.get("type") == "vpn_control_routing_rules" or any(
                key in rules for key in ("ignore_rules", "block_quic_udp_443", "proxy_packages", "direct_domain_suffixes"))
        except (ValueError, AttributeError):
            recognized = False
        if not recognized:
            raise Refusal("INVALID_ARGUMENT")
        imported = {"ignore_rules": rules.get("ignore_rules") is True, "block_quic_udp_443": rules.get("block_quic_udp_443") is True,
                    "proxy_packages": list(rules.get("proxy_packages", [])),
                    "direct_domain_suffixes": [item.lower() for item in rules.get("direct_domain_suffixes", [])]}
        changed = imported != state["rules"]
        state["rules"] = imported
        self.commit(state, changed)
        return {"rules": imported}

    def refresh(self, state, identifier):
        row = next(row for row in state["subscriptions"] if row["id"] == identifier)
        origin = Endpoint.by_port.get(int(row["source"].split(":")[2].split("/")[0]))
        if state["settings"]["ssh.enabled"]:
            endpoint = Endpoint.by_port.get(state["settings"]["ssh.port"])
            if endpoint is not None and "no-ssh-dial" not in self.defects:
                endpoint.connections.append(b"SSH-2.0-Go\r\n")  # The handshake fails: the endpoint answers nothing.
            if "fallback-direct" in self.defects and origin is not None:
                origin.connections.append(b"\x16\x03\x01\x02\x00")
            reason = "CONNECTIVITY"
        else:
            if origin is not None:
                origin.connections.append(b"\x16\x03\x01\x02\x00")  # A ClientHello the origin never answers.
            reason = "TLS"
        row.update(refreshStatus="FAILED", failureReason=reason)
        self.commit(state, False)
        return {"code": "REFRESH_FAILED", "sources": [{"id": identifier, "ok": False, "locationCount": None, "failureReason": reason}]}, 1, "REFRESH_FAILED"


class Owner:
    def __init__(self, root, product):
        self.root, self.product, self.events = Path(root), product, []
        self.request = {"action": "disconnected-cli-config"}

    def event(self, kind, value):
        self.events.append({"kind": kind, "value": json.loads(json.dumps(value))})

    def invoke(self, workspace, *arguments, timeout=30):
        return self.product.invoke(workspace, *arguments)


def parse_openssh(text):
    """The checks golang.org/x/crypto/ssh makes of an unencrypted ed25519 key before the runtime may dial."""
    lines = text.strip().splitlines()
    assert lines[0] == cases.KEY_HEADER and lines[-1] == cases.KEY_FOOTER
    body = base64.b64decode("".join(lines[1:-1]), validate=True)
    assert body.startswith(b"openssh-key-v1\0")
    rest = body[len(b"openssh-key-v1\0"):]

    def take(data):
        size = struct.unpack(">I", data[:4])[0]
        return data[4:4 + size], data[4 + size:]
    cipher, rest = take(rest)
    kdf, rest = take(rest)
    options, rest = take(rest)
    count, rest = struct.unpack(">I", rest[:4])[0], rest[4:]
    public, rest = take(rest)
    private, rest = take(rest)
    assert (cipher, kdf, options, count, rest) == (b"none", b"none", b"", 1, b"")
    first, second, private = private[:4], private[4:8], private[8:]
    assert first == second
    kind, private = take(private)
    pub, private = take(private)
    secret, private = take(private)
    comment, padding = take(private)
    assert kind == b"ssh-ed25519" and len(pub) == 32 and len(secret) == 64 and secret[32:] == pub
    assert padding == bytes(range(1, len(padding) + 1)) and (len(body) - len(padding)) > 0
    assert public == struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + pub
    return pub


class CaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        Endpoint.by_port, Endpoint.next_port = {}, 41000
        patcher = mock.patch.object(cases, "LISTENER", Endpoint)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.keys = []
        for name in ("run_time_key", "refused_key"):
            original = getattr(cases, name)

            def remember(*args, _original=original, **kwargs):
                value = _original(*args, **kwargs)
                self.keys.append(value)
                return value
            patcher = mock.patch.object(cases, name, remember)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cases(self, *defects):
        product = Product(defects)
        workspace = self.root / "workspace"
        state = product.serve(workspace)
        owner = Owner(self.root, product)
        try:
            cases.run(owner, workspace, state["id"], {})
        finally:
            self.owner, self.state = owner, state
        return owner, state

    def assert_caught(self, defect, reason):
        with self.assertRaises(AssertionError) as caught:
            self.run_cases(defect)
        self.assertEqual(reason, str(caught.exception))

    def test_the_faithful_product_passes_every_group_in_order(self):
        owner, state = self.run_cases()
        groups = [event["value"]["group"] for event in owner.events if event["kind"] == "ssh-routing-group-complete"]
        self.assertEqual(list(cases.GROUPS), groups)
        self.assertEqual("ssh-routing-cases-complete", owner.events[-1]["kind"])
        selection = next(event["value"]["facts"] for event in owner.events
                         if event["kind"] == "ssh-routing-group-complete" and event["value"]["group"] == "ssh-routing-selection")
        self.assertEqual((1, 1, False), (selection["sshDials"], selection["directConnections"], selection["positiveSshTransfer"]))
        self.assertEqual({"code": "REFRESH_FAILED", "failureReason": "CONNECTIVITY"}, selection["routedRefresh"])
        self.assertTrue(all(endpoint.closed for endpoint in Endpoint.by_port.values()))
        self.assertEqual(2, len(Endpoint.by_port))
        self.assertFalse(state["settings"]["ssh.enabled"])
        self.assertEqual([], state["subscriptions"])

    def test_the_fake_product_writes_bytes_as_the_product_does_on_every_platform(self):
        # The product writes "$normalized\n" as UTF-8 bytes (DesktopHomeSshCredentialStore), and stored_key compares exact
        # bytes. Text mode would add a CR before each LF on Windows, so the fake writes bytes; here Windows text mode is modelled.
        original = Path.write_text

        def windows_text(path, data, encoding=None, errors=None, newline=None):
            return original(path, data.replace("\n", "\r\n") if newline is None else data, encoding=encoding, errors=errors, newline="")
        with mock.patch.object(Path, "write_text", windows_text):
            owner, _ = self.run_cases()
        self.assertEqual("ssh-routing-cases-complete", owner.events[-1]["kind"])

    def test_no_key_line_reaches_an_event_or_a_top_level_file(self):
        owner, _ = self.run_cases()
        events = json.dumps(owner.events)
        lines = [line for key in self.keys for line in cases.key_lines(key)]
        self.assertGreaterEqual(len(self.keys), 4)
        self.assertTrue(lines)
        self.assertEqual([], [line for line in lines if line in events])
        # Evidence collects top-level files only: every key file sits in the fixture folder.
        top = [path for path in self.root.iterdir() if path.is_file()]
        self.assertEqual([], [path for path in top if any(line.encode() in path.read_bytes() for line in lines)])
        inputs = [event["value"] for event in owner.events if event["kind"] == "ssh-routing-input" and event["value"].get("keyMaterial")]
        self.assertEqual(4, len(inputs))
        self.assertTrue(all(set(value) == {"name", "bytes", "keyMaterial"} for value in inputs), "no digest of key material")

    def test_each_defect_is_caught_by_its_oracle(self):
        for defect, reason in (("echo-key", "key-material-in-cli-output"), ("stale-accepted", "json-exit-code"),
                               ("retry-bumps", "mutation-revision-not-exact"), ("enable-without-key", "json-exit-code"),
                               ("encrypted-accepted", "json-exit-code"), ("key-in-workspace", "key-material-in-workspace-state"),
                               ("key-in-diagnostics", "key-material-in-diagnostics"),
                               ("host-keys-not-normalized", "route-not-normalized"), ("routing-stale-accepted", "json-exit-code"),
                               ("export-overwrites", "json-exit-code"), ("fallback-direct", "ssh-route-fell-back-to-direct"),
                               ("no-ssh-dial", "ssh-route-not-dialled"),
                               ("routing-shape", "case-reply-unreadable:routing_import_cases")):
            with self.subTest(defect=defect):
                Endpoint.by_port = {}
                self.assert_caught(defect, reason)
                self.assertTrue(all(endpoint.closed for endpoint in Endpoint.by_port.values()), "listeners close on failure")
                self.root.joinpath("workspace").rename(self.root / ("workspace-" + defect))
                self.root.joinpath("SSH " + cases.TOKYO + " fixture files").rename(self.root / ("fixtures-" + defect))

    def test_a_loopback_endpoint_that_cannot_bind_is_a_known_failure(self):
        def refused(label, first):
            raise OSError("address unavailable")
        with mock.patch.object(cases, "LISTENER", refused), self.assertRaises(AssertionError) as caught:
            self.run_cases()
        self.assertEqual("loopback-endpoint-unavailable", str(caught.exception))
        groups = [event["value"]["group"] for event in self.owner.events if event["kind"] == "ssh-routing-group-complete"]
        self.assertEqual(list(cases.GROUPS[:-1]), groups, "every earlier group completed; nothing was sent for the last")

    def test_a_refusal_never_changes_the_revision_or_the_stored_key(self):
        _, state = self.run_cases()
        imports = [event for event in self.owner.events if event["kind"] == "ssh-routing-refusal-readback"
                   and event["value"]["argv"][:3] == ["ssh", "key", "import"]]
        # Stale revision, other epoch, then the bare guard, --secret, three contents, empty stdin and a missing file.
        self.assertEqual(["CONFLICT"] * 2 + ["INVALID_ARGUMENT"] * 7, [event["value"]["code"] for event in imports])
        self.assertEqual([True, True, False], [event["value"]["ownerAnswered"] for event in imports[:3]])
        self.assertEqual(self.keys[1].strip() + "\n", state["key"], "the replacement key is the stored one")

    def test_the_run_time_key_is_a_well_formed_container_and_fresh_every_time(self):
        first, second = cases.run_time_key(), cases.run_time_key()
        self.assertNotEqual(parse_openssh(first), parse_openssh(second))
        self.assertTrue(all(len(line) <= 70 for line in first.splitlines()))
        fixed = cases.run_time_key(lambda size: bytes(size))
        self.assertEqual(bytes(32), parse_openssh(fixed))
        pkcs8, pem = cases.refused_key("pkcs8"), cases.refused_key("pem")
        self.assertTrue(pkcs8.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"))
        self.assertEqual(["-----BEGIN RSA PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED"], pem.splitlines()[:2])
        self.assertTrue(pem.splitlines()[2].startswith("DEK-Info: AES-128-CBC,"))
        self.assertFalse(any(line.startswith(("Proc-Type", "DEK-Info")) for line in cases.key_lines(pem)))
        host = cases.host_key_line()
        algorithm, encoded, comment = host.split(" ")
        blob = base64.b64decode(encoded, validate=True)
        self.assertEqual(("ssh-ed25519", "fixture-host", 51), (algorithm, comment, len(blob)))
        self.assertEqual(algorithm + " " + encoded, _host_key(host))

    def test_the_loopback_endpoint_records_only_what_a_client_sends_first(self):
        class Connection:
            def __init__(self, chunks):
                self.chunks, self.closed = list(chunks), False

            def settimeout(self, value):
                self.timeout = value

            def recv(self, size):
                return self.chunks.pop(0)[:size] if self.chunks else b""

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.closed = True

        class Server:
            def __init__(self, endpoint, connections):
                self.endpoint, self.connections = endpoint, list(connections)

            def accept(self):
                if not self.connections:
                    self.endpoint.closed.set()
                    raise OSError("closed")
                return self.connections.pop(0), ("127.0.0.1", 1)

        for first, chunks, expected in ((255, [b"SSH-2.0-", b"Go\r\n", b"never read"], b"SSH-2.0-Go\r\n"),
                                        (5, [b"\x16\x03", b"\x01\x02\x00", b"never read"], b"\x16\x03\x01\x02\x00"),
                                        (255, [b"partial"], b"partial")):
            endpoint = object.__new__(cases.LoopbackEndpoint)
            endpoint.label, endpoint.first, endpoint.connections = "fake", first, []
            endpoint.lock, endpoint.closed = cases.threading.Lock(), cases.threading.Event()
            connection = Connection(chunks)
            endpoint.server = Server(endpoint, [connection])
            endpoint._serve()
            self.assertEqual([expected], endpoint.seen())
            self.assertTrue(connection.closed)

    def test_the_module_is_plain_ascii_and_does_nothing_on_import(self):
        raw = Path(cases.__file__).read_bytes()
        self.assertTrue(all(byte < 128 for byte in raw))
        self.assertEqual("disconnected-cli-config", cases.ACTION)
        with self.assertRaises(AssertionError) as caught:
            cases.run(type("Other", (), {"request": {"action": "streaming-client-interrupt"}})(), self.root, "id", {})
        self.assertEqual("finite-case-action", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
