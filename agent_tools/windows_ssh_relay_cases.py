"""SSH key import from stdin and subscription refreshes through a real in-guest SSH relay, through the installed public Windows CLI.

The row ``windows-disconnected-cli-config.ssh-relay-transfer`` runs this module under the disconnected-cli-config
owner action, beside the ssh-import-routing row: the same owner, harness and known-failure closing. Its owner
scopes the serve's JVM to this operation's localhost trust store (``configure_launch``) and feeds a public call a
file the case wrote as stdin (``owner.invoke(..., stdin=path)``). No process launcher, timeout termination or
replay lives here.

The relay is windows_ssh_relay_fixture (an SSH server and the home SOCKS relay behind it), the selected location
is the pinned socks_http_fixture forwarding to the subscription origin, and the origin is the fixture's HTTPS
listener with the job's localhost certificate: all are loopback threads of this worker, so the owner's child
custody is unchanged and no byte leaves the guest. The key pair is made here at run time, written only into this
operation's fixture folder, which evidence never collects, and reaches the product only on a child's stdin; the
relay holds its public half. No event, argument or assertion message carries key material.

Groups, in order: the stdin import (positive, retry, refusals, replacement, stored bytes, owner-only ACL, private
storage); a refresh while disconnected (DesktopSubscriptionDownloadClient's HOME_RELAY: the bootstrap runtime's
own SSH session); a refresh while connected (ACTIVE_SESSION: the runtime's management inbound, the selected
location and the SSH chain); a refresh after disconnecting; a relay whose host key is not the pinned one; and,
with the relay stopped, a refresh that fails without a direct fallback and keeps the last good cache. Each
refresh is checked against the relay's own record, and the exact failure code comes from sing-box 1.13.4 and the
JDK on loopback (the ledger's SSH relay rows), not from a guess.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import ssl
import stat
import threading
import time


ACTION = "disconnected-cli-config"
GROUPS = ("ssh-stdin-key-import", "ssh-relay-disconnected", "ssh-relay-connected", "ssh-relay-after-disconnect",
          "ssh-relay-host-key-mismatch", "ssh-relay-stopped")
RELAY_SOURCE, SOCKS_SOURCE = "windows_ssh_relay_fixture.py", "socks_http_fixture.py"
CERTIFICATE, PRIVATE_KEY, TRUST_STORE = "ssh-relay-localhost.pem", "ssh-relay-localhost.key", "ssh-relay-trust.jks"
TRUST_PASSWORD = "changeit"  # windows_scenario_proxy.TRUST_PASSWORD, the store the job writes.
RELAY_USER = "fixture"
LOCATION = "SSH relay location"
RUNTIME_LEAF = "sing-box.exe"
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_REPLY_BYTES = 64 * 1024
CENSUS_SECONDS = 10
TOKYO = "\u6771\u4eac"
KEY = "\u9375"


def require(value, reason):
    if not value:
        raise AssertionError(reason)


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


def key_lines(text):
    """The body lines of an armored key, which no reply, state file or report may contain."""
    return [line for line in text.splitlines()[1:-1] if len(line) >= 16]


def sibling(owner, leaf):
    """A file this operation's job published beside the case module, held by the owner's own pins."""
    path = Path(owner.request["casesPath"]).with_name(leaf)
    require(str(path).casefold() in owner.by_path, "ssh-relay-file-not-held:" + leaf)
    return path


def configure_launch(owner, workspace):
    """Before the one serve starts: its JVM, and no later child, trusts this operation's localhost certificate.

    The owner removes the options again right after starting that serve, as for the responsive document row.
    """
    require(owner.request["action"] == ACTION and str(workspace) == owner.request["workspace"], "finite-case-action")
    store = str(sibling(owner, TRUST_STORE))
    require(not any(character in store for character in '\r\n\x00"'), "scoped-jvm-trust-path")
    require("JAVA_TOOL_OPTIONS" not in owner.environment, "no-preexisting-owner-jvm-options")
    owner.environment["JAVA_TOOL_OPTIONS"] = ('"-Djavax.net.ssl.trustStore=' + store + '" -Djavax.net.ssl.trustStorePassword='
                                              + TRUST_PASSWORD)
    owner.event("ssh-relay-trust-scoped", {"trustStore": TRUST_STORE, "scope": "original-serve-only"})


# ---- Native reads; offline tests replace these three, since nothing there is Windows ---------------------------

def _windows_security(path):
    """The owner SID and the owner+DACL SDDL of one file, read by name; each caller first read that name as a regular file."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    advapi.GetNamedSecurityInfoW.argtypes = (ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    code = advapi.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None, None, None, ctypes.byref(descriptor))
    require(code == 0 and owner.value and descriptor.value, "credential-security-unreadable")
    try:
        text, sid = ctypes.c_wchar_p(), ctypes.c_wchar_p()
        advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = (
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_void_p)
        advapi.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p))
        require(advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 5, ctypes.byref(text), None)
                and advapi.ConvertSidToStringSidW(owner, ctypes.byref(sid)), "credential-security-unreadable")
        try:
            return {"ownerSid": sid.value, "sddl": text.value}
        finally:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
            kernel.LocalFree(ctypes.cast(sid, ctypes.c_void_p))
    finally:
        kernel.LocalFree(descriptor)


class _ProcessEntry(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("usage", ctypes.c_uint32), ("pid", ctypes.c_uint32), ("heap", ctypes.c_size_t),
                ("module", ctypes.c_uint32), ("threads", ctypes.c_uint32), ("parent", ctypes.c_uint32), ("priority", ctypes.c_long),
                ("flags", ctypes.c_uint32), ("name", ctypes.c_wchar * 260)]


def _windows_runtimes(root):
    """Every live sing-box.exe whose image lies under ``root``: the product's runtime and bootstrap images there."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.QueryFullProcessImageNameW.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32))
    kernel.Process32FirstW.argtypes = kernel.Process32NextW.argtypes = (ctypes.c_void_p, ctypes.POINTER(_ProcessEntry))
    kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    require(snapshot not in (None, ctypes.c_void_p(-1).value), "runtime-census-unavailable")
    found, prefix = [], str(root).casefold().rstrip("\\") + "\\"
    try:
        entry = _ProcessEntry()
        entry.size = ctypes.sizeof(_ProcessEntry)
        more = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            if entry.name.casefold() == RUNTIME_LEAF:
                handle = kernel.OpenProcess(0x1000, False, entry.pid)
                if handle:
                    try:
                        buffer, size = ctypes.create_unicode_buffer(32768), ctypes.c_uint32(32768)
                        if kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)) and buffer.value.casefold().startswith(prefix):
                            found.append(entry.pid)
                    finally:
                        kernel.CloseHandle(handle)
            more = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    return sorted(found)


def _origin_context(certificate, private_key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(private_key))
    return context


SECURITY, RUNTIMES, ORIGIN_CONTEXT = _windows_security, _windows_runtimes, _origin_context


class Cases:
    """Response helpers for the fixed case functions below; no stream text reaches an assertion."""

    def __init__(self, owner, workspace, identity, root):
        self.owner, self.workspace, self.identity, self.root = owner, Path(workspace), identity, Path(root)
        self.secrets, self.on_requested = [], False

    def record(self, kind, value):
        self.owner.event("ssh-relay-" + kind, value)

    def call(self, *args, json_output=True, controller=True, revision=None, stdin=None):
        prefix = ["--json"] if json_output else []
        if controller:
            prefix += ["--controller-id", self.identity if controller is True else controller]
        if revision is not None:
            require(type(revision) is int and revision >= 0, "case-revision-type")
            prefix += ["--if-revision", str(revision)]
        argv = [*prefix, *args]
        intent = {"workspace": str(self.workspace), "argv": argv}
        if stdin is not None:
            intent["stdin"] = Path(stdin).name
        self.record("command-intent", intent)
        result = (self.owner.invoke(self.workspace, *argv) if stdin is None
                  else self.owner.invoke(self.workspace, *argv, stdin=str(stdin)))
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
        # Every call here is synchronous: an owner's answer is its final one.
        require(body["final"] is True or body.get("controllerId") in (None, ""), "response-not-final")
        return body

    def json(self, *args, revision=None):
        return self.body(self.call(*args, revision=revision))

    def status(self, running=False):
        body = self.json("status")
        require(body["data"]["runtimeRunning"] is running and body["restartRequired"] is False,
                "connected-owner-changed" if running else "disconnected-owner-changed")
        return body

    def revision(self):
        return self.status()["configurationRevision"]

    def mutate(self, *args, delta=1, human=False, stdin=None):
        revision = self.revision()
        if human:
            result = self.call(*args, json_output=False, revision=revision, stdin=stdin)
            lines = result.stdout.splitlines()
            require(result.returncode == 0 and result.stderr == "" and lines[:1] == ["OK"]
                    and "Controller: " + self.identity in lines and "Completion: final" in lines
                    and "Revision: " + str(revision + delta) in lines, "human-owner-metadata")
        else:
            body = self.body(self.call(*args, revision=revision, stdin=stdin))
            require(body["configurationRevision"] == revision + delta, "json-commit-revision")
        require(self.revision() == revision + delta, "mutation-revision-not-exact")
        self.record("commit-readback", {"argv": list(args), "human": human, "before": revision, "delta": delta,
                                        "stdin": stdin is not None})

    def configure(self, *args):
        """A setup mutation from a product default this module does not pin: guarded, answered by this owner, and
        the revision moved by exactly the reply's own count, 0 or 1."""
        revision = self.revision()
        body = self.body(self.call(*args, revision=revision))
        delta = body["configurationRevision"] - revision
        require(delta in (0, 1) and self.revision() == body["configurationRevision"], "setup-revision-not-exact")
        self.record("setup-readback", {"argv": list(args), "before": revision, "delta": delta})

    def refused(self, *args, code, stdin=None):
        revision = self.revision()
        body = self.body(self.call(*args, revision=revision, stdin=stdin), 1, code, bound=False)
        require(self.revision() == revision, "refusal-changed-revision")
        self.record("refusal-readback", {"argv": list(args), "code": code, "revision": revision, "stdin": stdin is not None,
                                         "ownerAnswered": body.get("controllerId") == self.identity})

    def file(self, name, content, *, secret=False):
        require(name not in ("", ".", "..") and Path(name).name == name, "fixture-name-not-leaf")
        path, value = self.root / name, content.encode("utf-8")
        with path.open("xb") as output:
            require(output.write(value) == len(value), "fixture-short-write")
        if secret:
            self.secrets.extend(key_lines(content))
        self.record("input", {"name": name, "bytes": len(value), **({"keyMaterial": True} if secret else {})})
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


# ---- The stdin key import --------------------------------------------------------------------------------------

def credentials(c):
    return c.workspace / "credentials"


def stored_key(c, key):
    """The product's private credential file holds exactly the last accepted key, and nothing else lies beside it."""
    folder = credentials(c)
    require(sorted(entry.name for entry in folder.iterdir()) == ["home-ssh-private-key"], "credential-folder-leftovers")
    require(c.read(folder / "home-ssh-private-key") == (key.strip() + "\n").encode("ascii"), "stored-key-differs")


def owner_only(c, path, reason):
    """DesktopHomeSshCredentialStore.restrictToCurrentUser on Windows: the file's owner is the ordinary user and
    its DACL is one explicit full-access ACE for that user, inherited from nothing."""
    sid = c.owner.request["context"]["ordinarySid"]
    security = SECURITY(path)
    sddl = security["sddl"] if type(security) is dict and type(security.get("sddl")) is str else ""
    require(security.get("ownerSid") == sid and sddl.startswith("O:" + sid + "D:"), reason + "-owner")
    dacl = sddl[len("O:" + sid + "D:"):]
    require(dacl[:dacl.find("(")] in ("", "P", "AI", "PAI", "AR", "PAR") and dacl.count("(") == 1
            and dacl[dacl.find("("):] == "(A;;FA;;;" + sid + ")", reason + "-dacl")
    return {"ownerSid": "ordinary", "aces": 1}


def key_present(c, present):
    require(c.json("ssh", "key", "status")["data"] == {"present": present}, "ssh-key-status")


def stdin_key_import_cases(c, fixtures):
    """``ssh key import --input -`` reads the key from the CLI's stdin: a commit, a retry no-op, refusals that change
    nothing, a replacement, the exact stored bytes under an owner-only ACL and no key line in private storage."""
    relay = fixtures.relay_module
    first_seed, second_seed = os.urandom(32), os.urandom(32)
    first = relay.openssh_private_key(first_seed)
    second = relay.openssh_private_key(second_seed)
    one = c.file(KEY + " one " + TOKYO + ".txt", first, secret=True)
    two = c.file(KEY + " two " + TOKYO + ".txt", second, secret=True)
    key_present(c, False)
    c.mutate("ssh", "key", "import", "--input", "-", stdin=one)
    key_present(c, True)
    stored_key(c, first)
    # The same key again on stdin, JSON and human, is a successful no-op.
    c.mutate("ssh", "key", "import", "--input", "-", stdin=one, delta=0)
    c.mutate("ssh", "key", "import", "--input", "-", stdin=one, human=True, delta=0)
    refusals = 0
    for name, text in (("not a key", "not an SSH private key\n"), ("empty", ""),
                       ("encrypted pkcs8", "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + os.urandom(48).hex() + "\n"
                                           "-----END ENCRYPTED PRIVATE KEY-----\n")):
        path = c.file(name + " " + TOKYO + ".txt", text, secret=text.startswith("-----"))
        c.refused("ssh", "key", "import", "--input", "-", code="INVALID_ARGUMENT", stdin=path)
        refusals += 1
    stored_key(c, first)
    # A different key replaces it, from stdin too.
    c.mutate("ssh", "key", "import", "--input", "-", stdin=two)
    key_present(c, True)
    stored_key(c, second)
    acl = owner_only(c, credentials(c) / "home-ssh-private-key", "credential-acl")
    c.clean(c.read(c.workspace / "workspace.json"), "key-material-in-workspace-state")
    c.json("settings", "show")
    c.json("logs", "--limit", "200")
    report = c.root / ("diagnostics " + TOKYO + ".txt")
    c.json("diagnostics", "export", "--output", str(report))
    c.clean(c.read(report), "key-material-in-diagnostics")
    fixtures.key = (second_seed, relay.ed25519_public(second_seed))
    c.group("ssh-stdin-key-import", committed=2, retryNoOp=2, refusedContents=refusals, replaced=True, credentialAcl=acl,
            privateStorage=True, storedKeyFingerprint=relay.fingerprint(relay.ed25519_blob(fixtures.key[1])))


# ---- The relay --------------------------------------------------------------------------------------------------

class Fixtures:
    """The relay, the location and the origin of one operation, started once and closed once."""

    def __init__(self, c):
        self.c = c
        owner = c.owner
        self.relay_module = owner.module(str(sibling(owner, RELAY_SOURCE)), "_owned_ssh_relay_fixture")
        self.socks_module = None
        self.key = self.relay = self.location = self.origin = self.thread = None
        self.closed = False

    def start(self):
        owner, relay = self.c.owner, self.relay_module
        require(self.key is not None and self.relay is None, "relay-key-before-start")
        self.socks_module = owner.module(str(sibling(owner, SOCKS_SOURCE)), "_owned_ssh_relay_location")
        context = ORIGIN_CONTEXT(sibling(owner, CERTIFICATE), sibling(owner, PRIVATE_KEY))
        try:
            self.origin = relay.HttpsOrigin(context, "/subscription/" + owner.operation, b"").start()
            self.location = self.socks_module.FixtureServer("127.0.0.1", 0, "ssh-relay-location-" + owner.operation,
                                                            forward_host="localhost", forward_port=self.origin.port)
            self.origin.body = ("socks://127.0.0.1:" + str(self.location.server_address[1]) + "#Relay%20subscription\n").encode("ascii")
            self.thread = threading.Thread(target=self.location.serve_forever, kwargs={"poll_interval": 0.1},
                                           daemon=True, name="ssh-relay-location")
            self.thread.start()
            self.relay = relay.Relay(user=RELAY_USER, authorized_public=self.key[1], host_seed=os.urandom(32)).start()
        except OSError:
            # Nothing has been sent and no child is open when a loopback listener cannot bind.
            raise AssertionError("loopback-endpoint-unavailable") from None
        self.c.record("fixtures-started", {"originPort": self.origin.port, "locationPort": self.location.server_address[1],
                                           "sshPort": self.relay.ssh_port, "socksPort": self.relay.socks_port})

    def snapshot(self):
        return {"relay": self.relay.facts(), "origin": self.origin.served()}

    def close(self):
        if self.closed:
            return
        self.closed = True
        ended = {}
        if self.relay is not None:
            ended["relay"] = self.relay.close()
        if self.location is not None:
            self.location.shutdown()
            self.location.server_close()
            self.thread.join(5)
            ended["location"] = not self.thread.is_alive()
        if self.origin is not None:
            ended["origin"] = self.origin.close()
        self.c.record("fixtures-closed", ended)


def subscription_row(c, identifier):
    rows = [row for row in c.json("subscriptions", "list")["data"]["subscriptions"] if row.get("id") == identifier]
    require(len(rows) == 1, "relay-subscription-row")
    return rows[0]


def runtime_entries(c):
    """Names under the workspace's runtime folder: the bootstrap's temporary files and the runtime's candidates."""
    folder = c.workspace / "runtime"
    return sorted(entry.name for entry in folder.iterdir()) if folder.is_dir() else []


def runtimes_settle(c, expected):
    """The product's live runtimes under this workspace, awaited until their count is ``expected`` within the bound."""
    until = time.monotonic() + CENSUS_SECONDS
    while True:
        found = RUNTIMES(c.workspace)
        if len(found) == expected or time.monotonic() >= until:
            return found
        time.sleep(0.25)


def leftovers(c, connected):
    """What a refresh left: no bootstrap file, no runtime candidate unless connected, and exactly the runtimes due."""
    entries = runtime_entries(c)
    require(not any(name.startswith("home-ssh-bootstrap-") for name in entries), "bootstrap-files-left")
    candidates = [name for name in entries if name.startswith("candidate-")]
    require(len(candidates) == (1 if connected else 0), "runtime-candidates-left" if not connected else "runtime-candidate-count")
    require(len(runtimes_settle(c, 1 if connected else 0)) == (1 if connected else 0),
            "runtime-process-left" if not connected else "connected-runtime-count")
    return {"candidates": len(candidates), "runtimes": 1 if connected else 0}


def window(before, after):
    """What the relay and the origin saw between two snapshots: new sessions, every new channel of any session,
    new SOCKS requests and new origin requests."""
    known = {session["ordinal"]: len(session["channels"]) for session in before["relay"]["sessions"]}
    sessions = [session for session in after["relay"]["sessions"] if session["ordinal"] not in known]
    channels = [channel for session in after["relay"]["sessions"] for channel in session["channels"][known.get(session["ordinal"], 0):]]
    return {"sessions": sessions, "channels": channels, "socks": after["relay"]["socks"][len(before["relay"]["socks"]):],
            "origin": after["origin"][len(before["origin"]):]}


def refresh_ok(c, fixtures, identifier):
    """One synchronous refresh that succeeds: the exact envelope and data, one origin GET, and the row's cache."""
    before = fixtures.snapshot()
    body = c.body(c.call("subscriptions", "refresh", identifier))
    require(body["data"] == {"code": "OK", "sources": [{"id": identifier, "ok": True, "locationCount": 1, "failureReason": None}]},
            "relay-refresh-data")
    seen = window(before, fixtures.snapshot())
    require([(row["method"], row["path"], row["status"]) for row in seen["origin"]]
            == [("GET", "/subscription/" + c.owner.operation, 200)], "relay-origin-requests")
    row = subscription_row(c, identifier)
    require((row.get("refreshStatus"), row.get("cachedLocations"), row.get("failureReason")) == ("OK", 1, None), "relay-refresh-row")
    return seen


def authenticated(fixtures, session):
    """A session of the product's ssh outbound that proved the imported key, as the configured user."""
    fingerprint = fixtures.relay_module.fingerprint(fixtures.relay_module.ed25519_blob(fixtures.key[1]))
    return (session["clientVersion"].startswith("SSH-2.0-") and session["kex"] in fixtures.relay_module.KEX
            and session["cipher"] == fixtures.relay_module.CIPHER and session["keysExchanged"] is True
            and session["authenticated"] is True and session["authenticatedKey"] == fingerprint
            and [entry["result"] for entry in session["auth"] if entry["method"] == "publickey"][-1:] == ["success"]
            and all(entry["user"] == RELAY_USER for entry in session["auth"]))


def channels_to_relay(fixtures, channels):
    return bool(channels) and all((channel["type"], channel["host"], channel["port"], channel["result"])
                                  == ("direct-tcpip", "127.0.0.1", fixtures.relay.socks_port, "opened") for channel in channels)


def egress(seen):
    return [(row["host"], row["port"], row["result"]) for row in seen["socks"]]


def disconnected_refresh(c, fixtures, identifier):
    """HOME_RELAY: a bootstrap runtime of its own dials the relay with the imported key; its SOCKS egress goes
    straight to the origin. Nothing falls back to a direct fetch, and the bootstrap leaves nothing behind."""
    seen = refresh_ok(c, fixtures, identifier)
    require(len(seen["sessions"]) == 1 and authenticated(fixtures, seen["sessions"][0]), "relay-bootstrap-session")
    require(channels_to_relay(fixtures, seen["channels"]) and seen["channels"] == seen["sessions"][0]["channels"],
            "relay-bootstrap-channel")
    require(egress(seen) == [("localhost", fixtures.origin.port, "connected")], "relay-bootstrap-egress")
    return {"sessions": 1, "channels": len(seen["channels"]), "egress": "origin", "leftovers": leftovers(c, False)}


def relay_disconnected_cases(c, fixtures):
    fixtures.start()
    # No scheduled refresh and no Find Best after one: each refresh below is the only work in its window.
    for key, value in (("refresh.policy", "off"), ("refresh.find-best-after-refresh", "false")):
        c.configure("settings", "set", key, value)
    revision = c.revision()
    body = c.body(c.call("subscriptions", "add", "--source", fixtures.origin.url(), "--name", "Relay " + TOKYO, revision=revision))
    identifier = body["data"]["id"]
    require(type(identifier) is str and identifier and c.revision() == revision + 1, "relay-subscription-added")
    patch = route_patch(fixtures, fixtures.relay.host_key_line())
    c.mutate("settings", "apply", "--input", str(c.file("SSH relay route " + TOKYO + ".json", json.dumps(patch))))
    require(fixtures.snapshot() == {"relay": {"sessions": [], "socks": []}, "origin": []}, "relay-touched-before-refresh")
    require(leftovers(c, False)["runtimes"] == 0, "runtime-before-refresh")
    fixtures.subscription = identifier
    facts = disconnected_refresh(c, fixtures, identifier)
    c.group("ssh-relay-disconnected", route="HOME_RELAY", **facts)


def relay_connected_cases(c, fixtures):
    """ACTIVE_SESSION: proxy-only through the selected location, which the runtime chains through the relay
    (CONFIG-004). The refresh rides the runtime's own SSH session to the location, never a bootstrap of its own,
    and the runtime's captured key copy is owner-only too. ``off`` retires the runtime and its candidate."""
    location = c.file(LOCATION + ".txt", "socks://127.0.0.1:" + str(fixtures.location.server_address[1]) + "#"
                      + LOCATION.replace(" ", "%20") + "\n")
    # windows_lifecycle_runtime_stages.start_runtime's own proxy-only setup, with this location and test URL.
    c.configure("source", "set", "current-locations")
    c.mutate("locations", "add", "--input", str(location))
    c.configure("locations", "select", LOCATION)
    c.configure("routing", "set", "ignore-rules", "true")
    for key, value in (("mode", "proxy-only"), ("validation.test-url", fixtures.origin.url()), ("validation.retry-count", "0"),
                       ("validation.batch-size", "1"), ("validation.active-verification-window-size", "1")):
        c.configure("settings", "set", key, value)
    before_on = fixtures.snapshot()
    c.on_requested = True
    c.body(c.call("on"))
    status = c.status(running=True)
    require(status["data"].get("activeMode") == "proxy-only", "relay-connected-mode")
    # Whatever the start verified went through the chain too: every session it opened proved the imported key.
    started = window(before_on, fixtures.snapshot())
    require(all(authenticated(fixtures, session) for session in started["sessions"])
            and all((row["host"], row["port"]) == ("127.0.0.1", fixtures.location.server_address[1]) for row in started["socks"]),
            "relay-runtime-start-route")
    entries = [name for name in runtime_entries(c) if name.startswith("candidate-")]
    require(len(entries) == 1, "runtime-candidate-count")
    candidate = c.workspace / "runtime" / entries[0] / "home-ssh-private-key"
    require(c.read(candidate) == c.read(credentials(c) / "home-ssh-private-key"), "runtime-key-copy-differs")
    acl = owner_only(c, candidate, "runtime-key-copy-acl")
    require(len(runtimes_settle(c, 1)) == 1, "connected-runtime-count")
    seen = refresh_ok(c, fixtures, fixtures.subscription)
    # The runtime's own session carries it, opened now or kept from the start; a bootstrap would egress to the origin.
    require(len(seen["sessions"]) <= 1 and all(authenticated(fixtures, session) for session in seen["sessions"]),
            "relay-refresh-not-through-runtime-session")
    require(channels_to_relay(fixtures, seen["channels"]), "relay-runtime-channel")
    require(egress(seen) == [("127.0.0.1", fixtures.location.server_address[1], "connected")],
            "relay-connected-egress-not-through-location")
    c.status(running=True)
    c.body(c.call("off"))
    c.on_requested = False
    c.status()
    off_facts = leftovers(c, False)
    c.group("ssh-relay-connected", route="ACTIVE_SESSION", startSessions=len(started["sessions"]), refreshSessions=len(seen["sessions"]),
            channels=len(seen["channels"]), egress="location", runtimeKeyCopyAcl=acl, afterOff=off_facts)


def relay_after_disconnect_cases(c, fixtures):
    facts = disconnected_refresh(c, fixtures, fixtures.subscription)
    c.group("ssh-relay-after-disconnect", route="HOME_RELAY", **facts)


def refresh_failed(c, fixtures, reason):
    """One refresh that fails without a direct fallback: the exact envelope and data, no origin request, and the row
    keeps its last good cache and states the failure. DesktopOperationRunner.complete: REFRESH_FAILED is no
    ControlCode, so the envelope says RUNTIME_FAILED with exit 1 and the data keeps the refresh's own code."""
    before = fixtures.snapshot()
    identifier = fixtures.subscription
    body = c.body(c.call("subscriptions", "refresh", identifier), 1, "RUNTIME_FAILED")
    require(body["data"] == {"code": "REFRESH_FAILED", "sources": [{"id": identifier, "ok": False, "locationCount": None,
                                                                   "failureReason": "CONNECTIVITY"}]}, reason + "-refresh-data")
    seen = window(before, fixtures.snapshot())
    require(seen["origin"] == [], reason + "-fell-back-to-direct")
    row = subscription_row(c, identifier)
    require((row.get("refreshStatus"), row.get("cachedLocations"), row.get("failureReason")) == ("FAILED", 1, "CONNECTIVITY"),
            reason + "-row")
    return seen


def route_patch(fixtures, host_key):
    return {"ssh.enabled": True, "ssh.host": "127.0.0.1", "ssh.port": fixtures.relay.ssh_port, "ssh.user": RELAY_USER,
            "ssh.relay-port": fixtures.relay.socks_port, "ssh.host-keys": [host_key]}


def relay_host_key_mismatch_cases(c, fixtures):
    """A relay whose host key is not the pinned one is never trusted: the bootstrap's SSH client stops at the key
    exchange, before any authentication or channel, and nothing falls back to a direct fetch (CONFIG-004)."""
    other = fixtures.relay_module.public_key_line(fixtures.relay_module.ed25519_public(os.urandom(32)))
    c.mutate("settings", "apply", "--input", str(c.file("SSH relay other pin " + TOKYO + ".json", json.dumps(route_patch(fixtures, other)))))
    seen = refresh_failed(c, fixtures, "relay-pin-mismatch")
    # sing-box: "ssh: handshake failed: host key mismatch"; the JDK then reads a closed CONNECT: CONNECTIVITY.
    require(len(seen["sessions"]) == 1 and seen["sessions"][0]["keysExchanged"] is False and seen["sessions"][0]["auth"] == []
            and seen["channels"] == [] and seen["socks"] == [], "relay-pin-mismatch-trusted")
    facts = leftovers(c, False)
    c.mutate("settings", "apply", "--input", str(c.file("SSH relay pin again " + TOKYO + ".json",
                                                        json.dumps(route_patch(fixtures, fixtures.relay.host_key_line())))))
    c.group("ssh-relay-host-key-mismatch", code="RUNTIME_FAILED", refreshCode="REFRESH_FAILED", failureReason="CONNECTIVITY",
            keyExchangeOnly=True, directFallback=False, leftovers=facts)


def relay_stopped_cases(c, fixtures):
    """The relay stopped: an inactive-session refresh fails on its own, reaches nothing and never falls back to a
    direct fetch; the row keeps its last good cache; the bootstrap leaves nothing behind (smoke step 11)."""
    require(fixtures.relay.stop_ssh(), "relay-stop-unconfirmed")
    # sing-box: "dial tcp ...: connect: connection refused"; the JDK then reads a closed CONNECT: CONNECTIVITY.
    seen = refresh_failed(c, fixtures, "relay-stopped")
    require(seen["sessions"] == [] and seen["channels"] == [] and seen["socks"] == [], "relay-stopped-yet-reached")
    facts = leftovers(c, False)
    c.group("ssh-relay-stopped", code="RUNTIME_FAILED", refreshCode="REFRESH_FAILED", failureReason="CONNECTIVITY",
            cacheKept=1, directFallback=False, leftovers=facts)


def close(c, fixtures, error):
    """On any end: a runtime this module started is turned off by the public ``off`` before anything closes, so the
    owner's closing finds the owner disconnected; then the fixtures close. An ``off`` that fails or a runtime still
    running leaves the owner's own closing to refuse its quit and park."""
    if c.on_requested:
        c.record("runtime-off-intent", {"reason": str(error)[:120] if error is not None else None, "replayAllowed": False})
        status = _json(c.call("status").stdout) or {}
        if (status.get("data") or {}).get("runtimeRunning") is True:
            c.call("off")
        c.on_requested = False
    fixtures.close()


def run(owner, workspace, identity, harness):
    require(owner.request["action"] == ACTION, "finite-case-action")
    require(type(harness) is dict, "held-harness-missing")
    require("JAVA_TOOL_OPTIONS" not in owner.environment, "scoped-trust-left-in-owner-environment")
    root = Path(owner.root) / ("SSH relay " + TOKYO + " fixture files")
    root.mkdir(exist_ok=False)
    c = Cases(owner, workspace, identity, root)
    fixtures = Fixtures(c)
    error = None
    try:
        for group in (stdin_key_import_cases, relay_disconnected_cases, relay_connected_cases, relay_after_disconnect_cases,
                      relay_host_key_mismatch_cases, relay_stopped_cases):
            try:
                group(c, fixtures)
            except (KeyError, IndexError, TypeError, ValueError, AttributeError):
                # Every call here has ended before its reply is read, so a misread reply is a known failure, never a park.
                raise AssertionError("case-reply-unreadable:" + group.__name__) from None
    except BaseException as failure:
        error = failure
        raise
    finally:
        close(c, fixtures, error)
    c.status()
    c.record("cases-complete", {"groups": list(GROUPS), "action": ACTION, "fullWindowsAcceptance": False,
                                "remainingProcedures": []})
