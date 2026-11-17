"""The two reserved scoped-VPN cases, dns-ws-ssh-cache-resources and pipe-storage-races, on the scoped-TUN route.

windows_tun_stages runs each row: active proxy A, pending VPN B, one async restart whose vpn-broker prompt only
windows-uac-decision answers. The dedicated driver loads this pinned module for three variants only and hands one
``Case`` to the stages and to its own grant steps; nothing here elevates, answers a prompt, kills a process or reads
anything the ordinary user cannot. What the protected broker stage holds is read by the TUN SYSTEM collector
(windows_tun_native_observer) into its ready record, which the stages hand to ``window``.

resources-grant (custom location ``Owned resources``):
  before the request: a custom config the ordinary capture must refuse (an ``external_ui`` path) is restarted into, and
  the product's own UNSUPPORTED ends it with A and pending B intact, no broker, no correlation journal and no stage;
  before the decision: the request's correlation journal ``.runtime-resource-job-<job>.json`` is in the workspace;
  in the window: the broker's stage is ``ProgramData\\vpn-control-vpn-<job>``; its captured config keeps ``path`` only
  in URL contexts (https and h3 DNS servers, ws, httpupgrade and http transports, the http outbound), with the original
  values, while the cache file and the local rule set run from the stage, whose rule-set copy holds the original's
  bytes as captured. The original then changes to reject the sampler's address, and the direct sampler still passes
  through the TUN. The broker's single-instance pipe refuses a second client of the same user (ERROR_PIPE_BUSY) and
  a same-name instance (ERROR_ACCESS_DENIED);
  after the off: the cache file is published back to the user's path (the closing census shows the stage removed).
ssh-grant (Owned B with the SSH chain of CONFIG-004 through the in-guest relay of windows_ssh_relay_fixture):
  the managed key reaches the broker inline (the stage's ssh outbound holds a ``private_key`` whose public half is the
  imported key's, and no ``private_key_path``) while the persisted runtime config keeps ``private_key_path`` and never gains
  ``private_key``; the direct sampler's traffic through the TUN rides an authenticated SSH session of the imported key
  and leaves the relay only towards the selected location.
stage-squat (custom ``Owned resources``, no collector): from the journal the ordinary user creates the broker's stage
  ``ProgramData\\vpn-control-vpn-<job>`` before the decision; the approved broker refuses with CONFLICT and leaves
  the squat folder and its canary as they were (not deleted, followed or written), with A and pending B intact. The
  case then removes its own folder before the closing census.
Both mutable rows read their own operation while the journal is awaited: a definite refusal before any journal ends
  the row as a known failure with the product's terminal (the stages check A, pending B and the census first); an end
  that leaves the outcome open, or an operation still pending at JOURNAL_SECONDS, parks with what was read.

A connect-first pipe racer before admission is not deterministic; the peer-PID checks stay with the product's tests.
No key material is ever an event, argument or assertion message: the key file lives in the fixture folder, which
evidence never collects, and reaches the product only on a child's stdin.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import time
import uuid

VARIANTS = frozenset({"resources-grant", "ssh-grant", "stage-squat"})
WINDOW_VARIANTS = frozenset({"resources-grant", "ssh-grant"})  # A TUN came up: the collector's ready record is handed over.
MUTABLE_VARIANTS = frozenset({"resources-grant", "stage-squat"})  # A cache file: a correlation journal names the job.
RESOURCES, REFUSED = "Owned resources", "Owned resources refused"
PENDING = {"resources-grant": RESOURCES, "stage-squat": RESOURCES, "ssh-grant": "Owned B"}
JOURNAL_PREFIX = ".runtime-resource-job-"  # DesktopWindowsWorkspaceResourceJournalRegistry's correlation files.
STAGE_PREFIX = "vpn-control-vpn-"  # windows-vpn-broker.cs: ProgramData\vpn-control-vpn-<job> for a mutable job.
FOLDER = "tun-resources"
CANARY = "owned-squat-canary.txt"
FIXED_UUID = "5d2f3b5e-7c1a-4b0e-9f3d-2a6c8e4b1f07"  # The unused outbounds' identity: never dialed.
UNUSED_PORT = 9
# (context, type, value): every `path` the capture keeps as the user wrote it (DesktopWindowsVpnConfigCapture urlContext).
URL_PATHS = (("dns.servers.*", "https", "/owned-doh-query"), ("dns.servers.*", "h3", "/owned-doh3-query"),
             ("outbounds.*.transport", "ws", "/owned-ws"), ("outbounds.*.transport", "httpupgrade", "/owned-upgrade"),
             ("outbounds.*.transport", "http", "/owned-h2"), ("outbounds.*", "http", "/owned-connect"))
SAMPLER_TARGET, DECOY = "198.18.0.1/32", "198.18.0.2/32"  # windows_tun_direct_sampler's benchmark address.
RELOAD_SECONDS = 3  # Longer than sing-box's local rule-set reload after a write to the file it reads.
JOURNAL_SECONDS = 120
# Between reads of the row's own operation while its journal is awaited: one public CLI read took about 3 s natively.
STATUS_SECONDS = 5
TERMINAL_SECONDS = 300
PUBLISH_SECONDS = 30
ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY = 5, 231
RELAY_USER = "fixture"
SSH_TAG = "vpn-control-home-ssh"  # HomeSshRouteConfigBuilder.SSH_OUTBOUND_TAG
# ControlCode's final codes this module reads and the public CLI's exit for each.
EXITS = {"OK": 0, "CANCELLED": 130, "CONFLICT": 1, "UNSUPPORTED": 1, "RUNTIME_FAILED": 1, "PERMISSION_DENIED": 1}
# ControlCode's definite refusals and their exits (windows_tun_stages.REFUSED_EXITS): a final one of these ended the
# operation. Its exit-2 codes (TIMEOUT, OUTCOME_UNKNOWN, UNAVAILABLE, INCOMPATIBLE_PROTOCOL) leave the outcome open.
REFUSALS = {**dict.fromkeys(("INVALID_ARGUMENT", "NOT_FOUND", "AMBIGUOUS_LOCATION", "READ_ONLY_SOURCE", "BUSY", "CONFLICT",
                             "UNSUPPORTED", "INTERACTION_REQUIRED", "PERMISSION_DENIED", "PERSISTENCE_FAILED", "RUNTIME_FAILED"), 1),
            "CANCELLED": 130}
_UUID = re.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def tun_inbound():
    """DesktopProxyConfigFactory.buildVpnConfig's TUN inbound: a custom config brings its own."""
    return {"type": "tun", "tag": "tun-in", "interface_name": "vpn-control", "address": ["172.19.250.1/30"], "mtu": 1400,
            "auto_route": True, "strict_route": True, "route_exclude_address": ["127.0.0.0/8"], "stack": "gvisor"}


def resources_config(socks_port, folder):
    """The resources location: every URL-context path, a cache file and a local rule set, routed to the owned upstream.

    The unused outbounds and DNS servers name a loopback port nothing listens on; no route reaches them."""
    require(type(socks_port) is int and 1 <= socks_port <= 65535, "reserved-socks-port")
    unused = {"server": "127.0.0.1", "server_port": UNUSED_PORT}
    return {"log": {"level": "error"},
            "dns": {"servers": [{"type": "https", "tag": "owned-doh", **unused, "path": "/owned-doh-query"},
                                {"type": "h3", "tag": "owned-doh3", **unused, "path": "/owned-doh3-query"}],
                    "final": "owned-doh"},
            "inbounds": [tun_inbound()],
            "outbounds": [{"type": "socks", "tag": "owned-upstream", "server": "127.0.0.1", "server_port": socks_port, "version": "5"},
                          {"type": "vless", "tag": "owned-ws", **unused, "uuid": FIXED_UUID,
                           "transport": {"type": "ws", "path": "/owned-ws"}},
                          {"type": "vmess", "tag": "owned-upgrade", **unused, "uuid": FIXED_UUID,
                           "transport": {"type": "httpupgrade", "path": "/owned-upgrade"}},
                          {"type": "vless", "tag": "owned-h2", **unused, "uuid": FIXED_UUID,
                           "transport": {"type": "http", "path": "/owned-h2"}},
                          {"type": "http", "tag": "owned-connect", **unused, "path": "/owned-connect"}],
            "route": {"rule_set": [{"type": "local", "tag": "owned-local", "format": "source", "path": str(folder / "rules.json")}],
                      "rules": [{"rule_set": "owned-local", "action": "reject"}], "final": "owned-upstream"},
            "experimental": {"cache_file": {"enabled": True, "path": str(folder / "cache.db")}}}


def refused_config(socks_port):
    """A valid config the ordinary capture refuses before any prompt: an external_ui path (UNSUPPORTED)."""
    require(type(socks_port) is int and 1 <= socks_port <= 65535, "reserved-socks-port")
    return {"log": {"level": "error"}, "inbounds": [tun_inbound()],
            "outbounds": [{"type": "socks", "tag": "owned-upstream", "server": "127.0.0.1", "server_port": socks_port, "version": "5"}],
            "route": {"final": "owned-upstream"}, "experimental": {"clash_api": {"external_ui": "owned-ui"}}}


def rules(cidr):
    return encoded({"version": 1, "rules": [{"ip_cidr": [cidr]}]})


def profile(config, name):
    return {"type": "custom", "remarks": name, "custom_config_json": json.dumps(config, separators=(",", ":"))}


def inside(path, folder):
    """``path`` names a file directly or deeper under ``folder`` (Windows names, case-insensitive)."""
    path, folder = ntpath.normcase(ntpath.normpath(str(path))), ntpath.normcase(ntpath.normpath(str(folder)))
    return path.startswith(folder + "\\")


def write_new(path, raw):
    """Create-only, no retry: a folder of this operation that no product or other case writes."""
    with open(path, "xb", buffering=0) as output:
        offset = 0
        while offset < len(raw):
            count = output.write(raw[offset:])
            require(count is not None and count > 0, "reserved-file-write")
            offset += count
        os.fsync(output.fileno())


def guarded(owner, state, runtime, *tail):
    before = runtime.result(owner, state["workspace"], state["identity"], "status")
    return runtime.result(owner, state["workspace"], state["identity"], "--if-revision", str(before["configurationRevision"]), *tail)


def journals(workspace):
    """The workspace's correlation journals by job: each names one mutable-resource job before its prompt."""
    found = {}
    for name in os.listdir(workspace):
        if name.startswith(JOURNAL_PREFIX) and name.endswith(".json"):
            job = name[len(JOURNAL_PREFIX):-len(".json")]
            require(_UUID.fullmatch(job) is not None, "reserved-journal-name")
            found[job] = name
    return found


def operation_status(owner, state, accepted):
    """One read of the row's own operation through operations status: its pending ACCEPTED or its final terminal.

    A read, never a resend. Anything not joined to this controller and operation fails."""
    require(type(accepted.get("operationId")) is str and accepted.get("controllerId") == state["identity"]
            and accepted.get("code") == "ACCEPTED" and accepted.get("final") is False, "reserved-original-accepted-operation")
    value = owner.invoke(state["workspace"], "--json", "--controller-id", state["identity"], "operations", "status",
                         accepted["operationId"])
    body = json.loads(value.stdout)
    require(value.stderr == "" and type(body) is dict and body.get("schemaVersion") == 1
            and body.get("controllerId") == state["identity"] and body.get("operationId") == accepted["operationId"],
            "reserved-operation-status-join")
    if body.get("final") is not True:
        require(body.get("code") == "ACCEPTED" and value.returncode == 0, "reserved-operation-pending-result")
    return body, value.returncode


def terminal(owner, state, accepted, codes, seconds=TERMINAL_SECONDS):
    """The final public terminal of the row's own operation, one of ``codes``, read through operations status.

    Never resent: a pending operation is read again until the bound, then the owner parks."""
    until = time.monotonic() + seconds
    while True:
        body, returncode = operation_status(owner, state, accepted)
        if body.get("final") is True:
            require(body.get("code") in codes and returncode == EXITS.get(body["code"])
                    and body.get("ok") is (returncode == 0), "reserved-operation-unexpected-terminal")
            owner.event("scoped-tun-reserved-terminal", {"accepted": accepted, "terminal": body, "replayAllowed": False})
            return body
        if time.monotonic() >= until:
            owner.park("scoped-tun-reserved-terminal-pending-no-replay")
        time.sleep(0.2)


class EndedBeforeJournal(Exception):
    """The row's own operation is final and refused, and no correlation journal was ever written.

    The product retains that journal before UAC and before every native input of a mutable job
    (DesktopWindowsVpnBroker.prepareCaptured), so a request that ended without one never reached a prompt or a broker.
    The stages close the row as a known failure only once A, pending B and the census show nothing open."""

    def __init__(self, terminal):
        super().__init__("scoped-tun-reserved-ended-before-journal")
        self.terminal = terminal


def _kernel32():
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _last_error():
    return ctypes.get_last_error()


def pipe_races(owner, pipe):
    """The broker's single-instance pipe during the session: a second client of the same user and a same-name
    instance are both refused. Either handle, if ever granted, is closed at once and fails the row."""
    require(type(pipe) is str and re.fullmatch(STAGE_PREFIX + _UUID.pattern, pipe), "reserved-pipe-name")
    from ctypes import wintypes as W
    k = _kernel32()
    invalid = ctypes.c_void_p(-1).value
    path = "\\\\.\\pipe\\" + pipe
    create = k.CreateFileW
    create.argtypes = (W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE)
    create.restype = W.HANDLE
    named = k.CreateNamedPipeW
    named.argtypes = (W.LPCWSTR, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.DWORD, W.LPVOID)
    named.restype = W.HANDLE
    close = k.CloseHandle
    close.argtypes, close.restype = (W.HANDLE,), W.BOOL
    found = {}
    # GENERIC_READ|GENERIC_WRITE, no sharing, OPEN_EXISTING, identification-only SQOS: the product's own client open.
    handle = create(path, 0xC0000000, 0, None, 3, 0x00110000, None)
    found["secondClient"] = _last_error() if handle in (None, invalid) else 0
    if handle not in (None, invalid):
        close(handle)
    # PIPE_ACCESS_DUPLEX, byte mode that rejects remote clients, one instance: the broker's own shape under its name.
    handle = named(path, 0x00000003, 0x00000008, 1, 4096, 4096, 0, None)
    found["sameNameInstance"] = _last_error() if handle in (None, invalid) else 0
    if handle not in (None, invalid):
        close(handle)
    owner.event("scoped-tun-pipe-races", {"pipe": pipe, **found, "replayAllowed": False})
    require(found == {"secondClient": ERROR_PIPE_BUSY, "sameNameInstance": ERROR_ACCESS_DENIED}, "reserved-pipe-race-admitted")
    return found


class Case:
    """One reserved row's case: built by the driver before the stages begin, used by them and by its grant steps."""
    REFUSED = REFUSED
    EndedBeforeJournal = EndedBeforeJournal

    def __init__(self, owner, variant, relay=None):
        require(variant in VARIANTS and (relay is not None) == (variant == "ssh-grant"), "reserved-variant-binding")
        self.owner, self.variant, self.relay_module = owner, variant, relay
        self.relay = self.key = None
        self.folder = Path(owner.root) / FOLDER
        self.job = self.squat = self.rules_sha256 = None
        self.journal_baseline = None
        self.closed = False

    @property
    def pending(self):
        return PENDING[self.variant]

    def terminal(self, state, accepted, codes):
        return terminal(self.owner, state, accepted, codes)

    @staticmethod
    def journals(workspace):
        return journals(workspace)

    # ---- before the request ------------------------------------------------------------------------------------
    def prepare(self, state, runtime):
        """Add the pending location this variant restarts into; nothing restarts here."""
        owner = self.owner
        self.journal_baseline = journals(state["workspace"])
        require(self.journal_baseline == {}, "reserved-journal-before-row")
        if self.variant in MUTABLE_VARIANTS:
            os.mkdir(self.folder)
            raw = rules(DECOY)
            write_new(self.folder / "rules.json", raw)
            self.rules_sha256 = hashlib.sha256(raw).hexdigest()
            port = state["ready"]["advertisedSocksPort"]
            documents = [(RESOURCES, resources_config(port, self.folder))]
            if self.variant == "resources-grant":
                documents.append((REFUSED, refused_config(port)))
            for name, config in documents:
                path = self.folder / (name.replace(" ", "-") + ".json")
                write_new(path, encoded(profile(config, name)))
                guarded(owner, state, runtime, "locations", "add", "--input", str(path))
                shown = runtime.result(owner, state["workspace"], state["identity"], "locations", "show", name)
                require(json.loads(shown["data"]["configuration"]) == config, "reserved-custom-readback")
            owner.event("scoped-tun-reserved-locations", {"variant": self.variant, "names": [name for name, _ in documents],
                        "rulesSha256": self.rules_sha256, "folder": str(self.folder), "replayAllowed": False})
        else:
            self.prepare_ssh(state, runtime)
        return self.pending

    def prepare_ssh(self, state, runtime):
        """The imported key, the in-guest relay and the SSH route patch: CONFIG-004 for every runtime after it."""
        owner, relay = self.owner, self.relay_module
        seed = os.urandom(32)
        self.key = relay.ed25519_public(seed)
        path = Path(state["inputs"]["fixtureRoot"]) / "tun-ssh-key.txt"
        write_new(path, relay.openssh_private_key(seed).encode("ascii"))
        del seed
        try:
            self.relay = relay.Relay(user=RELAY_USER, authorized_public=self.key, host_seed=os.urandom(32)).start()
        except OSError:
            raise AssertionError("loopback-endpoint-unavailable") from None
        before = runtime.result(owner, state["workspace"], state["identity"], "status")
        value = owner.invoke(state["workspace"], "--json", "--controller-id", state["identity"], "--if-revision",
                             str(before["configurationRevision"]), "ssh", "key", "import", "--input", "-", stdin=str(path))
        body = json.loads(value.stdout)
        require(value.returncode == 0 and value.stderr == "" and body.get("code") == "OK" and body.get("final") is True
                and body.get("controllerId") == state["identity"], "reserved-ssh-key-import")
        patch = {"ssh.enabled": True, "ssh.host": "127.0.0.1", "ssh.port": self.relay.ssh_port, "ssh.user": RELAY_USER,
                 "ssh.relay-port": self.relay.socks_port, "ssh.host-keys": [self.relay.host_key_line()]}
        route = Path(state["inputs"]["fixtureRoot"]) / "tun-ssh-route.json"
        write_new(route, encoded(patch))
        guarded(owner, state, runtime, "settings", "apply", "--input", str(route))
        require(self.relay.facts() == {"sessions": [], "socks": []}, "reserved-relay-touched-before-request")
        owner.event("scoped-tun-reserved-ssh-route", {"sshPort": self.relay.ssh_port, "relayPort": self.relay.socks_port,
                    "keyFingerprint": relay.fingerprint(relay.ed25519_blob(self.key)), "replayAllowed": False})

    # ---- between the request and the decision ------------------------------------------------------------------
    def before_prompt(self, state, accepted):
        """A mutable job's correlation journal is in the workspace before its prompt is answered; a squat row then
        creates that job's stage folder first. The decision answers only after this returns.

        While no journal is there, the row's own operation is read every STATUS_SECONDS. Once it is final and refused
        with still no journal, the product ended the request before anything it does ahead of UAC: EndedBeforeJournal,
        which the stages close as a known failure after their own checks. A final OK without a journal, a bad terminal,
        or an operation still pending at JOURNAL_SECONDS may hold a prompt or a broker: the owner parks, never resends.
        On 2.2.19 (b50d0425) the squat's restart was ACCEPTED, no journal came in 120 s, and the wait, which never read
        the operation, parked with the product's own outcome unread."""
        if self.variant not in MUTABLE_VARIANTS:
            return None
        start = time.monotonic()
        until, read_at, last, reads = start + JOURNAL_SECONDS, start + STATUS_SECONDS, None, 0
        while True:
            found = journals(state["workspace"])
            if found:
                break
            if time.monotonic() >= read_at:
                last, returncode = operation_status(self.owner, state, accepted)
                reads += 1
                read_at = time.monotonic() + STATUS_SECONDS
                if last.get("final") is True:
                    found = journals(state["workspace"])
                    if found:  # Retained, then ended: the stages' own terminal reads that outcome.
                        break
                    self.owner.event("scoped-tun-reserved-journal-wait", {"accepted": accepted, "lastStatus": last,
                                     "statusReads": reads, "journals": 0, "replayAllowed": False})
                    if not (last.get("code") in REFUSALS and returncode == REFUSALS[last["code"]] and last.get("ok") is False):
                        # OK with no journal, or a code that leaves the outcome open: nothing proves the request closed.
                        self.owner.park("scoped-tun-reserved-ended-outcome-open-no-replay")
                    raise EndedBeforeJournal(last)
            if time.monotonic() >= until:
                # Still pending: a prompt or broker may be up. What was read stays in the evidence beside the park.
                self.owner.event("scoped-tun-reserved-journal-wait", {"accepted": accepted, "lastStatus": last,
                                 "statusReads": reads, "journals": 0, "replayAllowed": False})
                self.owner.park("scoped-tun-reserved-journal-absent-no-replay")
            time.sleep(0.1)
        require(len(found) == 1, "reserved-one-correlation-journal")
        (self.job, name), = found.items()
        stat = os.stat(Path(state["workspace"]) / name)
        value = {"jobId": self.job, "journal": name, "sizeBytes": stat.st_size}
        if self.variant == "stage-squat":
            programs = os.environ["ProgramData"]
            stage = Path(programs) / (STAGE_PREFIX + self.job)
            os.mkdir(stage)
            canary = b"owned squat " + self.job.encode("ascii") + b"\n"
            write_new(stage / CANARY, canary)
            self.squat = {"path": stage, "identity": self.identity(stage), "canary": hashlib.sha256(canary).hexdigest()}
            value["squat"] = {"path": str(stage), "canarySha256": self.squat["canary"]}
        self.owner.event("scoped-tun-reserved-before-decision", {**value, "replayAllowed": False})
        return value

    @staticmethod
    def identity(stage):
        folder, canary = os.lstat(stage), os.lstat(stage / CANARY)
        require(not getattr(folder, "st_file_attributes", 0) & 0x400 and not getattr(canary, "st_file_attributes", 0) & 0x400,
                "reserved-squat-reparse")
        return {"folder": (folder.st_ino, folder.st_dev), "canary": (canary.st_ino, canary.st_size, canary.st_mtime_ns),
                "entries": sorted(os.listdir(stage))}

    def squat_kept_and_removed(self):
        """After the broker's CONFLICT: the squat folder and canary exactly as created, then removed by this case."""
        require(self.variant == "stage-squat" and self.squat is not None, "reserved-squat-stage")
        stage = self.squat["path"]
        require(self.identity(stage) == self.squat["identity"]
                and hashlib.sha256((stage / CANARY).read_bytes()).hexdigest() == self.squat["canary"],
                "reserved-squat-touched")
        os.remove(stage / CANARY)
        os.rmdir(stage)
        self.owner.event("scoped-tun-squat-refused-untouched", {"path": str(stage), "jobId": self.job,
                         "deleted": False, "followed": False, "written": False, "removedByCase": True})

    # ---- the window: the TUN is up --------------------------------------------------------------------------------
    def window(self, lease, tun):
        """Between the ready record and the product's off, after the stages' own sampler run."""
        require(self.variant in WINDOW_VARIANTS and lease.get("nativeReady") is not None and not lease.get("offRequested"),
                "reserved-window")
        ready = lease["nativeReady"]
        stage = ready["observations"]["stage"]
        require(stage["name"].casefold() == ntpath.basename(stage["path"]).casefold()
                and stage["name"].startswith(STAGE_PREFIX) and _UUID.fullmatch(stage["name"][len(STAGE_PREFIX):]),
                "reserved-stage-name")
        if self.variant == "resources-grant":
            return self.resources_window(lease, tun, ready, stage)
        return self.ssh_window(lease, tun, stage)

    def resources_window(self, lease, tun, ready, stage):
        owner = self.owner
        require(stage["name"] == STAGE_PREFIX + self.job, "reserved-stage-not-the-journal-job")
        rows = [(row["context"], row["type"], row["value"]) for row in stage["paths"]]
        key = lambda row: tuple(str(item) for item in row)  # A null type sorts beside the strings.
        urls = sorted((row for row in rows if row[0] not in ("experimental.cache_file", "route.rule_set.*")), key=key)
        require(urls == sorted(URL_PATHS, key=key), "reserved-path-outside-url-context")
        files = sorted((row for row in rows if row not in urls), key=key)
        require(len(files) == 2 and files[0][:2] == ("experimental.cache_file", None) and files[1][:2] == ("route.rule_set.*", "local")
                and all(inside(row[2], stage["path"]) for row in files), "reserved-file-path-not-staged")
        require(stage["cache"] == {"enabled": True, "path": files[0][2]}, "reserved-cache-not-staged")
        require(len(stage["ruleSets"]) == 1 and stage["ruleSets"][0]["tag"] == "owned-local"
                and stage["ruleSets"][0]["path"] == files[1][2] and stage["ruleSets"][0]["sha256"] == self.rules_sha256,
                "reserved-rule-set-not-captured")
        # The original now rejects the sampler's address: a runtime reading it would refuse every sample.
        changed = rules(SAMPLER_TARGET)
        path = self.folder / "rules.json"
        with open(path, "r+b", buffering=0) as output:
            output.truncate(0)
            output.write(changed)
            os.fsync(output.fileno())
        require(path.read_bytes() == changed, "reserved-original-rule-set-change")
        owner.event("scoped-tun-original-resource-changed", {"path": str(path), "before": self.rules_sha256,
                    "after": hashlib.sha256(changed).hexdigest(), "replayAllowed": False})
        time.sleep(RELOAD_SECONDS)
        tun.traffic(owner, lease)
        owner.event("scoped-tun-captured-resource-kept", {"stage": stage["name"], "ruleSetSha256": self.rules_sha256,
                    "samplerPassedAfterOriginalChange": True})
        return pipe_races(owner, ready["helperInvocation"]["pipeName"])

    def ssh_window(self, lease, tun, stage):
        owner, relay = self.owner, self.relay_module
        fingerprint = relay.fingerprint(relay.ed25519_blob(self.key))
        # The stage's ssh outbound holds the imported key inline (its public half is the one this case imported) and
        # no key path; the collector compared nothing secret and recorded only that public fingerprint.
        require(stage["ssh"] == [{"tag": SSH_TAG, "privateKeyInline": True, "privateKeyPath": False,
                                  "inlinePublicFingerprint": fingerprint}], "reserved-ssh-key-not-inline")
        persisted = json.loads(Path(lease["inputs"]["runtimeConfigPath"]).read_bytes())
        outbounds = [row for row in persisted.get("outbounds", []) if row.get("type") == "ssh"]
        require(len(outbounds) == 1 and outbounds[0].get("tag") == SSH_TAG and type(outbounds[0].get("private_key_path")) is str
                and "private_key" not in outbounds[0], "reserved-persisted-config-gained-key")
        before = self.relay.facts()
        rows = tun.traffic(owner, lease)
        after = self.relay.facts()
        port = lease["state"]["ready"]["advertisedSocksPort"]
        egress = after["socks"][len(before["socks"]):]
        sessions = after["sessions"]
        require(sessions and all(session["authenticated"] is True and session["authenticatedKey"] == fingerprint
                                 and all(item["user"] == RELAY_USER for item in session["auth"]) for session in sessions),
                "reserved-ssh-session-not-the-imported-key")
        channels = [channel for session in sessions for channel in session["channels"]]
        require(channels and all((channel["type"], channel["host"], channel["port"]) == ("direct-tcpip", "127.0.0.1", self.relay.socks_port)
                                 for channel in channels), "reserved-ssh-channel-not-to-relay")
        # Each sample is one connection through the TUN, so one relay egress towards the selected location at least.
        require(len(egress) >= len(rows) - 1 and all((row["host"], row["port"], row["result"]) == ("127.0.0.1", port, "connected")
                                                    for row in egress), "reserved-tun-traffic-not-through-ssh-chain")
        owner.event("scoped-tun-ssh-chain-observed", {"sessions": len(sessions), "channels": len(channels), "egress": len(egress),
                    "keyFingerprint": fingerprint, "persistedKeyPath": True, "persistedInlineKey": False, "stageInlineKey": True})
        return {"egress": len(egress)}

    # ---- after the off ---------------------------------------------------------------------------------------------
    def after_off(self, lease):
        """A resources row's cache file is the user's again once the broker ended; the closing census follows."""
        if self.variant != "resources-grant":
            return None
        require(lease.get("offFinished") is True, "reserved-after-exact-off")
        path = self.folder / "cache.db"
        until = time.monotonic() + PUBLISH_SECONDS
        while not path.exists():
            require(time.monotonic() < until, "reserved-cache-not-published")
            time.sleep(0.25)
        size = os.stat(path).st_size
        require(size > 0, "reserved-cache-empty")
        self.owner.event("scoped-tun-cache-published", {"path": str(path), "sizeBytes": size, "journals": sorted(journals(lease["state"]["workspace"]))})
        return size

    def close(self):
        """The relay, once: every thread of it ends with this process at the latest."""
        if self.closed:
            return
        self.closed = True
        if self.relay is not None:
            ended = self.relay.close()
            self.owner.event("scoped-tun-reserved-relay-closed", {"ended": ended})
