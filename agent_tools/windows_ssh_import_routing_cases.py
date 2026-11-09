"""SSH key import, SSH Routing and routing import through the installed public Windows CLI.

The row ``windows-disconnected-cli-config.ssh-import-routing`` runs this module in place of the
disconnected cases, under the same owner action, so the planner and the owner admit it unchanged
and a case oracle failure closes known like theirs. No main, process launcher, timeout termination,
cleanup or replay lives here: ``owner.invoke`` keeps every original handle and raw stream.

Key material is made here at run time: fresh random bytes in an unencrypted OpenSSH container that
no server trusts. It is written only into this operation's fixture folder, which evidence never
collects; no event, assertion message or argument carries it, and every CLI reply is checked not to
echo it. The SSH endpoint and the subscription origin are loopback sockets of this worker process,
so all traffic stays in the guest and the owner's child custody is unchanged. Import does nothing.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import stat
import struct
import threading
import uuid


ACTION = "disconnected-cli-config"
GROUPS = ("ssh-routing-needs-key", "ssh-key-import", "ssh-routing-settings", "routing-import", "ssh-routing-selection")
KEY_HEADER, KEY_FOOTER = "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"
ROUTING_TYPE = "vpn_control_routing_rules"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_REPLY_BYTES = 64 * 1024
TOKYO = "\u6771\u4eac"
KEY = "\u9375"


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def _string(value):
    return struct.pack(">I", len(value)) + value


def _armored(header, body, footer):
    encoded = base64.b64encode(body).decode("ascii")
    return "\n".join([header, *(encoded[index:index + 70] for index in range(0, len(encoded), 70)), footer]) + "\n"


def run_time_key(random=os.urandom):
    """A well-formed unencrypted OpenSSH ed25519 container of fresh random bytes.

    Only its container has to parse: the runtime's SSH client reads the key before it dials. No
    handshake ever completes against the loopback endpoint, so nothing is ever signed with it.
    """
    public, check = random(32), random(4)
    private = (check + check + _string(b"ssh-ed25519") + _string(public) + _string(random(32) + public)
               + _string(b""))
    private += bytes(range(1, 1 + (-len(private)) % 8))
    body = (b"openssh-key-v1\0" + _string(b"none") + _string(b"none") + _string(b"") + struct.pack(">I", 1)
            + _string(_string(b"ssh-ed25519") + _string(public)) + _string(private))
    return _armored(KEY_HEADER, body, KEY_FOOTER)


def refused_key(kind, random=os.urandom):
    """Inputs the product must refuse unchanged: an encrypted PKCS#8 key and an encrypted PEM key."""
    if kind == "pkcs8":
        return _armored("-----BEGIN ENCRYPTED PRIVATE KEY-----", random(96), "-----END ENCRYPTED PRIVATE KEY-----")
    require(kind == "pem", "refused-key-kind")
    armored = _armored("-----BEGIN RSA PRIVATE KEY-----", random(96), "-----END RSA PRIVATE KEY-----").split("\n", 1)
    return (armored[0] + "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC," + random(16).hex().upper() + "\n\n"
            + armored[1])


def host_key_line(random=os.urandom):
    """A pinned host key line with a comment; the product keeps only `algorithm base64`."""
    blob = _string(b"ssh-ed25519") + _string(random(32))
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " fixture-host"


def key_lines(text):
    """The body lines of an armored key, which no reply, state file or report may contain."""
    return [line for line in text.splitlines()[1:-1] if len(line) >= 16 and not line.startswith(("Proc-Type:", "DEK-Info:"))]


def _json(text):
    if len(text) > MAX_REPLY_BYTES:
        return None
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return value if type(value) is dict else None


def metadata(body):
    return {key: body[key] for key in ("schemaVersion", "controllerId", "requestId", "operationId",
                                       "configurationRevision", "restartRequired", "code", "final") if key in body}


class LoopbackEndpoint:
    """One loopback listener of this worker. Each connection is kept until it sent ``first`` bytes or a line,
    then closed: it records only what a client sends first, and answers nothing."""

    def __init__(self, label, first):
        self.label, self.first = label, first
        self.lock, self.closed, self.connections = threading.Lock(), threading.Event(), []
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server.bind(("127.0.0.1", 0))
            self.server.listen(8)
            self.server.settimeout(0.5)
        except BaseException:
            self.server.close()
            raise
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, name="ssh-routing-" + label, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            data = b""
            with connection:
                connection.settimeout(5)
                try:
                    while len(data) < 255 and b"\n" not in data and len(data) < self.first:
                        chunk = connection.recv(255 - len(data))
                        if not chunk:
                            break
                        data += chunk
                except OSError:
                    pass
            with self.lock:
                self.connections.append(data)

    def seen(self):
        with self.lock:
            return list(self.connections)

    def close(self):
        self.closed.set()
        self.server.close()
        self.thread.join(5)


# The fixture's listener type; offline tests replace it, since nothing there may listen.
LISTENER = LoopbackEndpoint


def listen(label, first):
    """A loopback endpoint, or a known failure: nothing has been sent and no child is open when binding fails."""
    try:
        return LISTENER(label, first)
    except OSError:
        raise AssertionError("loopback-endpoint-unavailable") from None


class Cases:
    """Response helpers for the fixed case functions below; no stream text reaches an assertion."""

    def __init__(self, owner, workspace, identity, root):
        self.owner, self.workspace, self.identity, self.root = owner, Path(workspace), identity, Path(root)
        self.secrets = []

    def record(self, kind, value):
        self.owner.event("ssh-routing-" + kind, value)

    def call(self, *args, json_output=True, controller=True, revision=None):
        prefix = ["--json"] if json_output else []
        if controller:
            prefix += ["--controller-id", self.identity if controller is True else controller]
        if revision is not None:
            require(type(revision) is int and revision >= 0, "case-revision-type")
            prefix += ["--if-revision", str(revision)]
        argv = [*prefix, *args]
        self.record("command-intent", {"workspace": str(self.workspace), "argv": argv})
        result = self.owner.invoke(self.workspace, *argv)
        for secret in self.secrets:
            require(secret not in result.stdout and secret not in result.stderr, "key-material-in-cli-output")
        facts = {"exitCode": result.returncode, "stdoutBytes": len(result.stdout.encode("utf-8")),
                 "stderrBytes": len(result.stderr.encode("utf-8"))}
        body = _json(result.stdout) if json_output else None
        if body is not None:
            facts["response"] = metadata(body)
        self.record("command-terminal", facts)
        return result

    def body(self, result, expected_exit=0, expected_code="OK", bound=True):
        require(result.returncode == expected_exit, "json-exit-code")
        require(result.stderr == "", "json-stderr-not-empty")
        body = _json(result.stdout)
        require(body is not None and body.get("schemaVersion") == 1 and body.get("code") == expected_code
                and body.get("ok") is (expected_exit == 0), "json-envelope-code")
        require(type(body.get("configurationRevision")) is int and body["configurationRevision"] >= 0
                and type(body.get("restartRequired")) is bool and type(body.get("final")) is bool, "response-metadata-types")
        require(body.get("controllerId") == self.identity or not bound and body.get("controllerId") in (None, ""),
                "response-owner-epoch")
        return body

    def json(self, *args, revision=None):
        return self.body(self.call(*args, revision=revision))

    def human(self, *args, revision=None):
        result = self.call(*args, json_output=False, revision=revision)
        lines = result.stdout.splitlines()
        require(result.returncode == 0 and result.stderr == "" and lines[:1] == ["OK"]
                and "Controller: " + self.identity in lines and "Completion: final" in lines, "human-owner-metadata")
        return result

    def status(self):
        body = self.json("status")
        require(body["data"]["runtimeRunning"] is False and body["restartRequired"] is False, "disconnected-owner-changed")
        return body

    def revision(self):
        return self.status()["configurationRevision"]

    def mutate(self, *args, human=False, delta=1):
        revision = self.revision()
        result = (self.human if human else self.call)(*args, revision=revision)
        body = None if human else self.body(result)
        require(self.revision() == revision + delta, "mutation-revision-not-exact")
        if human:
            require("Revision: " + str(revision + delta) in result.stdout.splitlines(), "human-commit-revision")
        else:
            require(body["configurationRevision"] == revision + delta, "json-commit-revision")
        self.record("commit-readback", {"argv": list(args), "human": human, "before": revision, "delta": delta})
        return body

    def refused(self, *args, code, guard="current", controller=True):
        """One JSON refusal that changes nothing. A refusal the parser makes has no owner metadata."""
        revision = self.revision()
        result = self.call(*args, controller=controller, revision=revision if guard == "current" else guard)
        body = self.body(result, 1, code, bound=False)
        require(self.revision() == revision, "refusal-changed-revision")
        self.record("refusal-readback", {"argv": list(args), "code": code, "revision": revision,
                                         "ownerAnswered": body.get("controllerId") == self.identity})
        return body

    def file(self, name, content, *, secret=False):
        require(name not in ("", ".", "..") and Path(name).name == name, "fixture-name-not-leaf")
        path, value = self.root / name, content.encode("utf-8")
        with path.open("xb") as output:
            require(output.write(value) == len(value), "fixture-short-write")
        if secret:
            self.secrets.extend(key_lines(content))
            self.record("input", {"name": name, "bytes": len(value), "keyMaterial": True})
        else:
            self.record("input", {"name": name, "bytes": len(value)})
        return path

    def read(self, path):
        """One regular file's bytes, sized by the handle that read them: an atomic replace never splits a read."""
        path = Path(path)
        named = path.lstat()
        require(stat.S_ISREG(named.st_mode) and not getattr(named, "st_file_attributes", 0) & 0x400, "read-not-regular-file")
        with path.open("rb") as stream:
            held = os.fstat(stream.fileno())
            require(stat.S_ISREG(held.st_mode) and held.st_size <= MAX_FILE_BYTES, "read-not-regular-bounded-file")
            value = stream.read(MAX_FILE_BYTES + 1)
        require(len(value) == held.st_size, "read-changed-during-read")
        return value

    def clean(self, value, reason):
        for secret in self.secrets:
            require(secret.encode("ascii") not in value, reason)

    def group(self, name, **facts):
        require(name in GROUPS, "unexpected-case-group")
        self.status()
        self.record("group-complete", {"group": name, "facts": facts, "fullWindowsAcceptance": False})


def key_present(c, present):
    require(c.json("ssh", "key", "status")["data"] == {"present": present}, "ssh-key-status")
    lines = [line.strip() for line in c.human("ssh", "key", "status").stdout.splitlines()]
    require("present: " + ("true" if present else "false") in lines, "human-ssh-key-status")


def stored_key(c, key):
    """The product's private credential file holds exactly the last accepted key."""
    value = c.read(c.workspace / "credentials" / "home-ssh-private-key")
    require(value == (key.strip() + "\n").encode("ascii"), "stored-key-differs")


def route_settings(c):
    keys = ("ssh.enabled", "ssh.host", "ssh.port", "ssh.user", "ssh.relay-port", "ssh.host-keys")
    shown = c.json("settings", "show")["data"]
    return {key: shown[key] for key in keys}


def route_patch(port, host_key, **changes):
    patch = {"ssh.enabled": True, "ssh.host": "127.0.0.1", "ssh.port": port, "ssh.user": "fixture", "ssh.relay-port": 10808,
             "ssh.host-keys": [host_key]}
    patch.update(changes)
    return patch


def needs_key_cases(c):
    """Fresh owner: no key, and enabling SSH Routing without one is refused whole."""
    key_present(c, False)
    path = c.file("SSH route without key " + TOKYO + ".json", json.dumps(route_patch(22022, host_key_line())))
    c.refused("settings", "apply", "--input", str(path), code="INVALID_ARGUMENT")
    require(route_settings(c)["ssh.enabled"] is False, "route-enabled-without-key")
    c.group("ssh-routing-needs-key")


def key_import_cases(c):
    first, second = run_time_key(), run_time_key()
    one = c.file(KEY + " one " + TOKYO + ".txt", first, secret=True)
    two = c.file(KEY + " two " + TOKYO + ".txt", second, secret=True)
    opening = c.revision()
    c.mutate("ssh", "key", "import", "--input", str(one))
    key_present(c, True)
    stored_key(c, first)
    # A retry of the same key, JSON and human, is a successful no-op.
    c.mutate("ssh", "key", "import", "--input", str(one), delta=0)
    c.mutate("ssh", "key", "import", "--input", str(one), human=True, delta=0)
    # Guards: a stale revision, another owner epoch, and a bare revision the parser refuses.
    c.refused("ssh", "key", "import", "--input", str(two), code="CONFLICT", guard=opening)
    c.refused("ssh", "key", "import", "--input", str(two), code="CONFLICT", controller=str(uuid.uuid4()))
    c.refused("ssh", "key", "import", "--input", str(two), code="INVALID_ARGUMENT", controller=False)
    # Synchronous only, and a key never travels as an argument.
    c.refused("--async", "ssh", "key", "import", "--input", str(two), code="INVALID_ARGUMENT")
    c.refused("ssh", "key", "import", "--secret", "not-a-secret", code="INVALID_ARGUMENT")
    for name, text in (("not a key", "not an SSH private key\n"), ("encrypted pkcs8", refused_key("pkcs8")),
                       ("encrypted pem", refused_key("pem"))):
        path = c.file(name + " " + TOKYO + ".txt", text, secret=text.startswith("-----"))
        c.refused("ssh", "key", "import", "--input", str(path), code="INVALID_ARGUMENT")
    # Every owner child's stdin is empty, and a missing file is never read.
    c.refused("ssh", "key", "import", "--input", "-", code="INVALID_ARGUMENT")
    c.refused("ssh", "key", "import", "--input", str(c.root / ("absent " + KEY + ".txt")), code="INVALID_ARGUMENT")
    stored_key(c, first)
    # A different key replaces it, through the human renderer.
    c.mutate("ssh", "key", "import", "--input", str(two), human=True)
    key_present(c, True)
    stored_key(c, second)
    # Private storage: the workspace state, the settings, the log and a diagnostics report carry no key line.
    c.clean(c.read(c.workspace / "workspace.json"), "key-material-in-workspace-state")
    c.json("settings", "show")
    c.json("logs", "--limit", "200")
    report = c.root / ("diagnostics " + TOKYO + ".txt")
    c.json("diagnostics", "export", "--output", str(report))
    c.clean(c.read(report), "key-material-in-diagnostics")
    c.group("ssh-key-import", retryNoOp=True, guardRefusals=3, parserRefusals=2, refusedContents=5, replaced=True,
            privateStorage=True, positiveStdinImport=False)


def route_settings_cases(c):
    """The SSH Routing truth table, with a key present: each rule refuses the whole patch."""
    host_key = host_key_line()
    normalized = host_key.rsplit(" ", 1)[0]
    for name, change in (("no host key", {"ssh.host-keys": []}),
                         ("unsupported host key", {"ssh.host-keys": ["ssh-dss AAAAB3NzaC1kc3MAAACBAP"]}),
                         ("user in host", {"ssh.host": "fixture@127.0.0.1"}), ("port zero", {"ssh.port": 0}),
                         ("relay port range", {"ssh.relay-port": 70000}), ("blank user", {"ssh.user": " "})):
        path = c.file("SSH route " + name + " " + TOKYO + ".json", json.dumps(route_patch(22022, host_key, **change)))
        c.refused("settings", "apply", "--input", str(path), code="INVALID_ARGUMENT")
    require(route_settings(c)["ssh.enabled"] is False, "refused-route-changed-settings")
    # A scheme, a trailing slash, a comment and a duplicate key are saved normalized; the same patch again is a no-op.
    path = c.file("SSH route " + TOKYO + ".json", json.dumps(route_patch(
        22022, host_key, **{"ssh.host": "ssh://127.0.0.1/", "ssh.host-keys": [host_key, normalized]})))
    opening = c.revision()
    c.mutate("settings", "apply", "--input", str(path))
    expected = route_patch(22022, normalized)
    require(route_settings(c) == expected, "route-not-normalized")
    c.mutate("settings", "apply", "--input", str(path), delta=0)
    c.refused("settings", "set", "ssh.port", "22023", code="CONFLICT", guard=opening)
    require(c.json("settings", "show", "ssh.enabled")["data"] == {"ssh.enabled": True}, "route-single-read")
    c.mutate("settings", "set", "ssh.enabled", "false", human=True)
    require(route_settings(c) == dict(expected, **{"ssh.enabled": False}), "route-disable-readback")
    c.group("ssh-routing-settings", refusedPatches=6, normalized=True, retryNoOp=True, staleGuard=True)


def routing_rules(c):
    return c.json("routing", "show")["data"]["routing"]["rules"]


def routing_document(rules):
    return json.dumps({"type": ROUTING_TYPE, "version": 7, "rules": rules})


def routing_import_cases(c):
    first = {"ignore_rules": True, "block_quic_udp_443": False, "proxy_packages": [],
             "direct_domain_suffixes": ["ssh-route.example.test"]}
    second = {"ignore_rules": False, "block_quic_udp_443": True, "proxy_packages": [],
              "direct_domain_suffixes": ["second.example.test"]}
    require(routing_rules(c) != first, "fresh-routing-equals-first-document")
    one = c.file("routing one " + TOKYO + ".json", routing_document(first))
    two = c.file("routing two " + TOKYO + ".json", routing_document(second))
    opening = c.revision()
    c.mutate("routing", "import", "--input", str(one))
    require(routing_rules(c) == first, "routing-import-readback")
    c.mutate("routing", "import", "--input", str(one), delta=0)
    c.mutate("routing", "import", "--input", str(one), human=True, delta=0)
    c.refused("routing", "import", "--input", str(two), code="CONFLICT", guard=opening)
    c.refused("routing", "import", "--input", str(two), code="CONFLICT", controller=str(uuid.uuid4()))
    c.refused("routing", "import", "--input", str(two), code="INVALID_ARGUMENT", controller=False)
    for name, text in (("unrecognized", json.dumps({"type": "other", "version": 7, "rules": {"unknown": True}})),
                       ("malformed", "{"), ("plain text", "routing rules\n")):
        path = c.file("routing " + name + " " + TOKYO + ".json", text)
        c.refused("routing", "import", "--input", str(path), code="INVALID_ARGUMENT")
    c.refused("routing", "import", "--input", "-", code="INVALID_ARGUMENT")
    require(routing_rules(c) == first, "refused-routing-changed-rules")
    # Reads and exports: a private file, no overwrite, raw stdout, and the export imports back as a no-op.
    output = c.root / ("routing export " + TOKYO + ".json")
    c.json("routing", "export", "--output", str(output))
    saved = c.read(output)
    require(json.loads(saved)["rules"] == first, "routing-export-semantics")
    c.body(c.call("routing", "export", "--output", str(output)), 1, "PERSISTENCE_FAILED")
    require(c.read(output) == saved, "routing-export-overwrote")
    raw = c.call("routing", "export", "--output", "-", json_output=False)
    require(raw.returncode == 0 and raw.stderr == "" and json.loads(raw.stdout)["rules"] == first, "routing-raw-stdout")
    c.mutate("routing", "import", "--input", str(output), delta=0)
    c.mutate("routing", "import", "--input", str(two), human=True)
    require(routing_rules(c) == second, "routing-human-import-readback")
    c.group("routing-import", retryNoOp=True, guardRefusals=3, refusedDocuments=4, exportRoundTrip=True)


def subscription_row(c, identifier):
    rows = [row for row in c.json("subscriptions", "list")["data"]["subscriptions"] if row.get("id") == identifier]
    require(len(rows) == 1, "route-subscription-row")
    return rows[0]


def refresh_failed(c, identifier):
    """A refresh no endpoint answers: exit 1 and a FAILED row with nothing cached. Its code is recorded, not assumed."""
    result = c.call("subscriptions", "refresh", identifier)
    body = _json(result.stdout)
    require(result.returncode == 1 and body is not None and body.get("ok") is False, "route-refresh-not-failed")
    row = subscription_row(c, identifier)
    require(row.get("refreshStatus") == "FAILED" and row.get("cachedLocations") == 0, "route-refresh-status")
    return {"code": body.get("code"), "failureReason": row.get("failureReason")}


def route_selection_cases(c):
    """Without a session a refresh follows SSH Routing: on, it dials the SSH endpoint and never falls back to a
    direct fetch; off, it goes straight to the origin. Neither endpoint answers, so both refreshes fail."""
    ssh = listen("ssh", 255)
    try:
        origin = listen("origin", 5)
        try:
            host_key = host_key_line()
            source = "https://127.0.0.1:" + str(origin.port) + "/ssh-route-" + uuid.uuid4().hex + ".txt"
            identifier = c.mutate("subscriptions", "add", "--source", source, "--name", "SSH route " + TOKYO)["data"]["id"]
            path = c.file("SSH route selection " + TOKYO + ".json", json.dumps(route_patch(ssh.port, host_key)))
            c.mutate("settings", "apply", "--input", str(path))
            require(ssh.seen() == [] and origin.seen() == [], "route-endpoint-touched-before-refresh")
            routed = refresh_failed(c, identifier)
            dialled = ssh.seen()
            require(dialled and all(line.startswith(b"SSH-2.0-") for line in dialled), "ssh-route-not-dialled")
            require(origin.seen() == [], "ssh-route-fell-back-to-direct")
            c.mutate("settings", "set", "ssh.enabled", "false")
            direct = refresh_failed(c, identifier)
            fetched = origin.seen()
            require(fetched and all(data[:1] == b"\x16" and data[1:2] == b"\x03" for data in fetched), "direct-route-not-taken")
            require(len(ssh.seen()) == len(dialled), "direct-route-dialled-ssh")
            c.mutate("subscriptions", "delete", identifier)
        finally:
            origin.close()
    finally:
        ssh.close()
    c.group("ssh-routing-selection", sshDials=len(dialled), directConnections=len(fetched), routedRefresh=routed,
            directRefresh=direct, positiveSshTransfer=False)


def run(owner, workspace, identity, harness):
    require(owner.request["action"] == ACTION, "finite-case-action")
    require(type(harness) is dict, "held-harness-missing")
    root = Path(owner.root) / ("SSH " + TOKYO + " fixture files")
    root.mkdir(exist_ok=False)
    c = Cases(owner, workspace, identity, root)
    for group in (needs_key_cases, key_import_cases, route_settings_cases, routing_import_cases, route_selection_cases):
        try:
            group(c)
        except (KeyError, IndexError, TypeError, ValueError):
            # Every call here has ended before its reply is read, so a misread reply is a known failure, never a park.
            raise AssertionError("case-reply-unreadable:" + group.__name__) from None
    c.status()
    c.record("cases-complete", {"groups": list(GROUPS), "action": ACTION, "fullWindowsAcceptance": False,
                                "remainingProcedures": ["positive-ssh-relayed-transfer", "stdin-key-import"]})
