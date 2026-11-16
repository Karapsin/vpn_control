"""Cold and GUI-owner document cases on the installed package, through the public CLI only.

The shared worker's document-acceptance action loads this module as its cases module. Its
variant is the job's literal input beside it (document-cold-input.json, pinned like every
other file): one routing document is imported, exported and compared, the original serve
is quit, the same workspace is opened again by an independent owner, and the export is
compared again. No observed value is copied into an expected one: the job computes the
expected semantic digest from the same fixed recipe that produced the document.

- cold-reopen: the large routing document, reopened by a new serve (cold-independent-reopen).
- legacy-newline: a routing document whose domain entries are legacy newline-, CR-, tab- and
  comma-joined lists, normalized at import and read cold (protobuf-newline-compatibility, the
  Windows form of the shared newline token boundary).
- gui-owner: the large document, reopened by the installed GUI, which starts its own
  controller; the CLI then imports and exports it through that GUI-started owner. This is only
  the CLI half of gui-cli-transfer: the GUI's own import and export are not exercised, so it
  never stands for that scenario.
- gui-picker: the GUI half of gui-cli-transfer. Two small routing documents; the CLI imports and exports the first,
  the original serve is quit, and the installed GUI reopens the workspace on an owned private desktop
  (windows_document_gui_picker, beside windows_no_tray_desktop). Through its own file picker the GUI exports, which
  must be the CLI export's bytes but for exported_at; the CLI imports that GUI export; the GUI imports a CLI export of
  the second document, and the committed routing rules and export must then be those of the CLI's import of the same
  file. Every GUI step is a reviewed click (windows_document_gui_picker.PROFILE); a step without a review stops the
  row with its frame kept and no click.
- cache-bytes: the committed subscription cache. Before the serve exists the
  owner starts its own in-guest subscription source (windows_document_cache_fixture, loopback
  only), and the serve alone trusts its localhost certificate. The product adds that source and
  refreshes it through its normal subscription path; its committed cache in workspace.json is
  then compared, entry by entry and by newline digest, with the stored locations the job derived
  from the same recipe that made the source's body, and the product's own export of it too. The
  source is stopped, so nothing can be fetched again, the serve quit, the closed file read, and an
  independent serve must read the same cache back. Windows keeps this cache in the workspace JSON,
  with no product digest of its own (unlike the Android preference store's verified reuse), so the
  digest here is the harness's, over the committed bytes. Between the closed read and the reopen
  comes the closed-state corruption step, the other half of cache-digest-bytes: the scenario's
  Android anchor fails a read of bytes it cannot decode rather than serve a substitute, and the
  desktop store keeps such a workspace.json aside (PRODUCT-003). Three times, with the product closed,
  the committed file is changed (one byte of the first cached location made invalid UTF-8, the last
  byte cut, one byte appended); an independent serve opens it and must keep exactly those bytes aside
  under its own name, load the defaults, and return the typed status: the `status` warning and the
  one log entry naming the kept file. That serve is quit, the kept copy is moved out of the state
  folder, and the exact committed bytes are put back before the reopen reads the cache again. With
  both halves the matrix names this row for cache-digest-bytes.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

VARIANTS = ("cold-reopen", "legacy-newline", "gui-owner", "cache-bytes", "gui-picker")
CACHE = "cache-bytes"
PICKER = "gui-picker"
INPUT_LEAF = "document-cold-input.json"
INPUT_FIELDS = {"schemaVersion", "variant", "operationId", "routingInputPath", "expectedSemanticSha256", "expectedSuffixCount"}
CACHE_INPUT_FIELDS = {"schemaVersion", "variant", "operationId", "cache"}
PICKER_INPUT_FIELDS = {"schemaVersion", "variant", "operationId", "picker"}
PICKER_FIELDS = {"modulePath", "desktopPath", "firstInputPath", "secondInputPath", "firstSemanticSha256", "secondSemanticSha256",
                 "suffixCount"}
# The picker's two modules, loaded by their held paths: the GUI steps and the owned desktop they run on.
PICKER_LEAVES = {"modulePath": "windows_document_gui_picker.py", "desktopPath": "windows_no_tray_desktop.py"}
CACHE_FIELDS = {"fixtureWorkerPath", "runtimeStagesPath", "socksSourcePath", "httpsSourcePath", "certificatePath", "privateKeyPath",
                "trustStorePath", "bodyPath", "bodySha256", "bodyBytes", "subscriptionName", "expectedLocations", "expectedCount",
                "expectedNewlineBytes", "expectedNewlineSha256"}
# The cache source's code roles, held by name and digest as the owner and the planner hold the responsive work's.
CACHE_SOURCES = {
    "fixtureWorkerPath": ("windows_document_cache_fixture.py", "86731933d0db39fce1e88b98d1c5143c4aa3a1f7cc65a9973f488058094a6482"),
    "runtimeStagesPath": ("windows_lifecycle_runtime_stages.py", "0b6b6c7c4c261a8996c140661b7631fb234115ed215e3d3a4a72fd60e25e676e"),
    "socksSourcePath": ("socks_http_fixture.py", "50239b25bb1c63e7c86baaea8683f188426e87d6a1c6090b505c38d567e70210"),
    "httpsSourcePath": ("https_subscription_relay_fixture.py", "e62f262d9703eb63c0eeca9b823eaae9d1a5780aefdedadf8aebe211492651d4"),
}
# The cache variant's literal input carries the expected stored locations, so its bound is the cache's, not 64 KiB.
INPUT_LIMIT = 1024 * 1024
READY_SECONDS = {"serve": 30, "gui": 90}
CLOSE_SECONDS = 120
CACHE_FIXTURE_LABEL = "owned-document-cache-fixture"
# The source names each start step on its stdout before entering it (windows_document_cache_fixture.STEPS).
CACHE_STEPS = ("input", "sources", "body", "tls-context", "https-listen", "relay-listen", "listening", "certificate-digest",
               "ready-create", "ready-rename")
# Bounds, not measurements: the proxy rows' fixture, which makes the same two listeners, was ready 1.2 to 2.0 s after its start.
CACHE_READY_SECONDS = 30
CACHE_STOP_SECONDS = 30
CACHE_TERMINATE_SECONDS = 15
CACHE_JOURNAL_LIMIT = 1024 * 1024
PRODUCT_AGENT = "VPNControlDesktop/1.0"  # DesktopSubscriptionDownloadClient's own User-Agent.
# The closed-state corruption step, in this order. Each corruption is one no strict UTF-8 JSON decoder may accept: a
# printable change inside a string would still decode, and the product, like the Android anchor, then uses it as it is.
CORRUPTIONS = ("changed-byte", "truncated", "trailing-byte")
# DesktopStateStore.keptPath: <original name>.unreadable-<UTC yyyyMMddTHHmmssZ>-<8 hex>, in the state folder itself.
KEPT_NAME = re.compile(r"workspace\.json\.unreadable-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
KEPT_PREFIXES = ("workspace.json.unreadable-", "workspace-recovery.json.unreadable-")
RECOVERY_LEAF = "workspace-recovery.json"
KEPT_WARNING = "UNREADABLE_WORKSPACE_KEPT"  # DesktopStateStore's `status` warning while a kept copy remains.
DEFAULTS_LOADED = "SAVED_SETTINGS_UNREADABLE_DEFAULTS_LOADED"
UNREADABLE_PREFIX = "SAVED_SETTINGS_UNREADABLE_"
LOG_LIMIT = "200"
CODE_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789:_-")
NAME_CHARACTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")


def need(value, code):
    if not value:
        raise RuntimeError(code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def semantic_sha256(raw):
    """sha256 of the canonical type, version and rules of a routing document; exported_at never counts."""
    value = json.loads(raw.decode("utf-8", "strict"))
    need(type(value) is dict and value.get("type") == "vpn_control_routing_rules" and type(value.get("rules")) is dict,
         "document-cold-routing-shape")
    semantic = {key: value.get(key) for key in ("type", "version", "rules")}
    suffixes = value["rules"].get("direct_domain_suffixes")
    need(type(suffixes) is list, "document-cold-routing-suffixes")
    canonical = json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(canonical).hexdigest(), len(suffixes)


def newline_bytes(locations):
    """The cache's bytes as the document rows compare them: its stored locations joined by LF, UTF-8."""
    return "\n".join(locations).encode("utf-8", "strict")


def _held(owner, path):
    return str(Path(path)).casefold() in owner.by_path


def _cache_case(owner, cache):
    """Every path a held file in its fixed role, and the recipe's stored locations equal to their own digests."""
    need(type(cache) is dict and set(cache) == CACHE_FIELDS, "document-cold-input-schema")
    roles = ("fixtureWorkerPath", "runtimeStagesPath", "socksSourcePath", "httpsSourcePath", "certificatePath", "privateKeyPath",
             "trustStorePath", "bodyPath")
    need(all(type(cache[key]) is str and _held(owner, cache[key]) for key in roles)
         and len({str(Path(cache[key])).casefold() for key in roles}) == len(roles), "document-cold-input-schema")
    for key, (name, digest) in CACHE_SOURCES.items():
        pin = owner.by_path[str(Path(cache[key])).casefold()]
        need(Path(cache[key]).name == name and pin.record["sha256"] == digest, "document-cache-fixed-source-" + key)
    expected = cache["expectedLocations"]
    need(type(expected) is list and expected and all(type(item) is str and item for item in expected)
         and len(set(expected)) == len(expected) == cache["expectedCount"], "document-cold-input-schema")
    raw = newline_bytes(expected)
    need(cache["expectedNewlineBytes"] == len(raw) and cache["expectedNewlineSha256"] == sha256(raw)
         and owner.by_path[str(Path(cache["bodyPath"])).casefold()].record["sha256"] == cache["bodySha256"]
         and type(cache["bodyBytes"]) is int and cache["bodyBytes"] > 0
         and type(cache["subscriptionName"]) is str and 0 < len(cache["subscriptionName"]) <= 64
         and cache["subscriptionName"].isascii() and cache["subscriptionName"].isprintable(), "document-cold-input-schema")
    return cache


def _picker_case(owner, picker):
    """The picker's two held modules in their fixed roles and its two documents with their own digests."""
    need(type(picker) is dict and set(picker) == PICKER_FIELDS, "document-cold-input-schema")
    roles = ("modulePath", "desktopPath", "firstInputPath", "secondInputPath")
    need(all(type(picker[key]) is str and _held(owner, picker[key]) for key in roles)
         and len({str(Path(picker[key])).casefold() for key in roles}) == len(roles)
         and all(Path(picker[key]).name == leaf for key, leaf in PICKER_LEAVES.items())
         and all(type(picker[key]) is str and len(picker[key]) == 64 and set(picker[key]) <= set("0123456789abcdef")
                 for key in ("firstSemanticSha256", "secondSemanticSha256"))
         and picker["firstSemanticSha256"] != picker["secondSemanticSha256"]
         and type(picker["suffixCount"]) is int and picker["suffixCount"] > 0, "document-cold-input-schema")
    return picker


def literal_input(owner):
    path = Path(__file__).with_name(INPUT_LEAF)
    pin = owner.by_path[str(path).casefold()]
    value = json.loads(pin.digest(True, maximum=INPUT_LIMIT).decode("utf-8", "strict"))
    need(type(value) is dict and value.get("schemaVersion") == 1 and value.get("variant") in VARIANTS
         and value.get("operationId") == owner.operation, "document-cold-input-schema")
    if value["variant"] == CACHE:
        need(set(value) == CACHE_INPUT_FIELDS, "document-cold-input-schema")
        _cache_case(owner, value["cache"])
        return value
    if value["variant"] == PICKER:
        need(set(value) == PICKER_INPUT_FIELDS, "document-cold-input-schema")
        _picker_case(owner, value["picker"])
        return value
    need(set(value) == INPUT_FIELDS and type(value["expectedSuffixCount"]) is int
         and type(value["expectedSemanticSha256"]) is str and len(value["expectedSemanticSha256"]) == 64
         and str(value["routingInputPath"]).casefold() in owner.by_path, "document-cold-input-schema")
    return value


def _inputs(owner):
    inputs = owner.request["documentAcceptance"]
    need(type(inputs) is dict and inputs["schemaVersion"] == 1 and inputs["endpointPinBeforeObservation"] is None
         and type(inputs["contexts"]) is list and len(set(inputs["contexts"])) == 52
         and all(type(value) is str and str(uuid.UUID(value)) == value for value in inputs["contexts"]),
         "document-cold-action-input-schema")
    return inputs


# ---- The cache source: the owner's own child, started before the serve and ended by the owner -------------------------

class CacheLease:
    """The original source child, its published input and ready record, and whether a refresh may still be fetching."""

    def __init__(self, owner, child, config, runtime):
        self.owner, self.child, self.config, self.runtime = owner, child, config, runtime
        self.ready, self.closed = None, False
        # Set before the product's refresh starts, cleared once its answer is known final: while set, the product may
        # still be fetching from this source, so a failure keeps every original for the park.
        self.refresh_open = False

    def guard(self):
        self.runtime.data_guard(self.owner)
        need(not self.closed and self.child.process.poll() is None
             and self.owner.native.birth(int(self.child.process._handle)) == self.child.birth, "document-cache-fixture-live")


def _finite(value, characters=CODE_CHARACTERS, limit=80):
    """A code or name the source said, or None: never free text."""
    return value if type(value) is str and 0 < len(value) <= limit and set(value) <= characters else None


def fixture_said(owner, child):
    """What the cache source said on its stdout so far: its start steps in order, its own failure record, its terminal."""
    said = {"steps": [], "failure": None, "readySaid": False, "terminal": None, "stdoutBytes": child.counts["stdout"],
            "stderrBytes": child.counts["stderr"], "unreadable": None}
    try:
        with (Path(owner.root) / f"child-{child.ordinal:04d}.stdout.raw").open("rb") as stream:
            raw = stream.read(65536)
        for line in raw.split(b"\n")[:-1]:  # Only complete lines count.
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if type(row) is not dict:
                continue
            if row.get("kind") == "owned-cache-fixture-step" and row.get("step") in CACHE_STEPS and len(said["steps"]) < 2 * len(CACHE_STEPS):
                said["steps"].append(row["step"])
            elif row.get("kind") == "owned-cache-fixture-failed":
                said["failure"] = {"step": row.get("step") if row.get("step") in CACHE_STEPS else None,
                                   "errorClass": _finite(row.get("errorClass"), NAME_CHARACTERS, 64),
                                   **{name: row.get(name) if type(row.get(name)) is int else None for name in ("winerror", "errno")},
                                   "reason": _finite(row.get("reason")), "listenersStopped": row.get("listenersStopped") is True}
            elif row.get("kind") == "owned-cache-fixture-ready":
                said["readySaid"] = True
            elif row.get("kind") == "owned-cache-fixture-terminal":
                said["terminal"] = row
    except Exception as error:
        said["unreadable"] = type(error).__name__
    said["lastStep"] = said["steps"][-1] if said["steps"] else None
    return said


def _await_end(owner, child, seconds, reason):
    """The child's terminal and EOF within its bound, or a park that keeps every original."""
    until = time.monotonic() + seconds
    while child.observe() is None:
        if time.monotonic() >= until:
            owner.park(reason, {"child": child.ordinal, "pid": child.pid, "birthFileTimeUtc": child.birth, "replayAllowed": False})
        time.sleep(0.05)
    return child.terminal


def end_cache_source(owner, lease, error, reason):
    """End the owner's own cache source while no refresh of the product is fetching from it.

    What is there is journaled first: the child's pid and whether it lives, the ready file, the steps and the failure
    the source itself said. A live child then gets exactly one termination of its original Popen handle, never a tree,
    job or group signal, and is awaited to its terminal and EOF. What cannot be known parks, keeping every original."""
    child = lease.child
    need(child.owner is owner and owner.children[child.ordinal] is child and child.label == CACHE_FIXTURE_LABEL
         and not lease.refresh_open, "document-cache-same-original-fixture")
    alive = child.terminal is None and child.process.poll() is None
    if not alive:
        # A child that already ended is first read to its EOF, so everything it said is in its raw files.
        _await_end(owner, child, CACHE_TERMINATE_SECONDS, "document-cache-fixture-end-unknown")
    said = fixture_said(owner, child)
    ready = Path(lease.config["readyFile"])
    owner.event("document-cache-fixture-ending", {"reason": reason, "child": child.ordinal, "pid": child.pid,
        "birthFileTimeUtc": child.birth, "alive": alive, "exitCode": child.process.poll(), "errorClass": type(error).__name__,
        **{key: said[key] for key in ("steps", "lastStep", "failure", "readySaid", "stdoutBytes", "stderrBytes", "unreadable")},
        "readyExists": ready.exists(), "publishingExists": ready.with_name(ready.name + ".publishing").exists(), "replayAllowed": False})
    if alive:
        need(owner.native.birth(int(child.process._handle)) == child.birth, "document-cache-fixture-live-birth")
        owner.event("document-cache-fixture-terminate-intent", {"child": child.ordinal, "pid": child.pid,
            "birthFileTimeUtc": child.birth, "effect": "one-original-Popen.terminate", "groupOrJobSignal": False, "replayAllowed": False})
        child.process.terminate()  # Existing original Windows Popen handle only.
        _await_end(owner, child, CACHE_TERMINATE_SECONDS, "document-cache-fixture-end-unknown")
        said = fixture_said(owner, child)
    lease.closed = True
    owner.event("document-cache-fixture-closed", {"child": child.ordinal, "pid": child.pid, "reason": reason, "terminated": alive,
        "terminal": child.terminal, "steps": said["steps"], "failure": said["failure"], "replayAllowed": False})
    return said


def _await_ready(child, ready):
    """The source's ready file within its bound, or why the wait stopped: 'ended' or 'timeout'. Nothing parks here."""
    started = time.monotonic()
    while not ready.exists():
        if child.process.poll() is not None:
            return "ended", time.monotonic() - started
        if time.monotonic() - started >= CACHE_READY_SECONDS:
            return "timeout", time.monotonic() - started
        time.sleep(0.1)
    return None, time.monotonic() - started


def start_cache_source(owner, cache):
    """Before the serve exists: start the source, await its ready record, and give the coming serve alone its trust.

    The product takes no part in anything here. A source that is not ready within its bound, ends first or publishes a
    record an oracle refuses is journaled, ended and awaited, and the failure raised is known:
    document-cache-fixture-not-ready:<timeout|ended|refused>:..."""
    owner.guard()
    need("JAVA_TOOL_OPTIONS" not in owner.environment and not any(child.label == "serve" for child in owner.children),
         "document-cache-before-original-serve")
    suffix = owner.operation.replace("-", "")
    runtime = owner.module(cache["runtimeStagesPath"], "document_cache_runtime_" + suffix)
    root = Path(owner.root) / "fixture"
    need(not root.exists(), "document-cache-fresh-fixture-root")
    root.mkdir()
    runtime.OwnedData(owner, root, directory=True)
    config = {"schemaVersion": 1, "operationId": owner.operation,
              **{key: cache[key] for key in ("socksSourcePath", "httpsSourcePath", "certificatePath", "privateKeyPath", "bodyPath",
                                             "bodySha256")},
              "readyFile": str(root / "ready.json"), "controlFile": str(root / "stop.json"),
              "journalFile": str(root / "journal.jsonl"), "token": "owned-document-cache-" + owner.operation}
    source = runtime.publish(owner, Path(owner.root) / "document-cache-input.json", config)
    child = owner.child(CACHE_FIXTURE_LABEL, [owner.request["pythonRuntime"]["interpreterPath"], "-I", "-B",
                                              cache["fixtureWorkerPath"], "--input", str(source)])
    lease = owner.document_cache_lease = CacheLease(owner, child, config, runtime)
    reason, waited = _await_ready(child, Path(config["readyFile"]))
    try:
        need(reason is None, "document-cache-fixture-" + str(reason))
        ready = runtime.read_ready(owner, child, Path(config["readyFile"]), owner.operation)
        certificate = owner.by_path[str(Path(cache["certificatePath"])).casefold()].record["sha256"]
        need(ready.get("pid") == child.pid and ready.get("certificateSha256") == certificate
             and ready.get("cacheUrl") == "https://localhost:%d/subscription/cache/%s" % (ready["httpsPort"], owner.operation)
             and ready.get("bodySha256") == cache["bodySha256"] and ready.get("bodyBytes") == cache["bodyBytes"]
             and ready.get("scope") == "one-owned-subscription-source", "document-cache-fixture-ready-record")
    except Exception as error:
        said = end_cache_source(owner, lease, error, "not-ready")
        if reason == "timeout":
            code = "timeout:" + (said["lastStep"] or "none")
        elif reason == "ended":
            code = "ended:%s:%s" % (child.terminal["exitCode"], (said["failure"] or {}).get("step") or "none")
        else:
            code = "refused:" + (_finite(str(error)) or type(error).__name__)
        raise RuntimeError("document-cache-fixture-not-ready:" + code) from error
    lease.ready = ready
    # The owner removes these right after starting its original serve: no later child ever inherits them.
    owner.environment["JAVA_TOOL_OPTIONS"] = runtime.scoped_trust_options(cache["trustStorePath"])
    owner.event("document-cache-fixture-ready", {"child": child.ordinal, "pid": child.pid, "readySeconds": round(waited, 3),
        "boundSeconds": CACHE_READY_SECONDS, "cacheUrl": ready["cacheUrl"], "bodySha256": ready["bodySha256"],
        "bodyBytes": ready["bodyBytes"], "certificateSha256": ready["certificateSha256"]})
    return lease


def stop_cache_source(owner, lease):
    """After the refresh is known final: the exact stop record, the source's own terminal, and its complete journal.

    Every request it answered, the stdlib's own answers to other methods and malformed requests included, must be the
    product's own GET of the one owned path, answered whole with the recipe body."""
    lease.guard()
    need(not lease.refresh_open, "document-cache-refresh-open-at-stop")
    child, path = lease.child, "/subscription/cache/" + owner.operation
    lease.runtime.publish(owner, Path(lease.config["controlFile"]),
                          {"schemaVersion": 1, "operationId": owner.operation, "action": "stop-owned-fixture"})
    terminal = _await_end(owner, child, CACHE_STOP_SECONDS, "document-cache-fixture-stop-unknown")
    lease.closed = True
    said = fixture_said(owner, child)
    stderr = (Path(owner.root) / f"child-{child.ordinal:04d}.stderr.raw").read_bytes()
    entries = (said["terminal"] or {}).get("journalEntries")
    need(terminal["exitCode"] == 0 and stderr == b"" and type(entries) is int and said["terminal"] == {
         "kind": "owned-cache-fixture-terminal", "operationId": owner.operation, "journalEntries": entries,
         "onlyOriginalObjectsStopped": True}, "document-cache-fixture-stop-receipt")
    with Path(lease.config["journalFile"]).open("rb") as stream:
        raw = stream.read(CACHE_JOURNAL_LIMIT + 1)
    need(len(raw) <= CACHE_JOURNAL_LIMIT and (raw == b"" or raw.endswith(b"\n")), "document-cache-journal-bound")
    try:
        rows = [json.loads(line) for line in raw.split(b"\n")[:-1]]
    except ValueError:
        rows = None  # The source's own journal, read after its end: a line it did not write whole is its failure, known.
    need(rows is not None and len(rows) == entries and all(type(row) is dict for row in rows)
         and [row.get("ordinal") for row in rows] == list(range(len(rows))), "document-cache-journal-complete")
    requests = [row for row in rows if row.get("event") == "request"]
    answers = [row for row in rows if row.get("event") == "answer"]
    need(requests and len(requests) + len(answers) == len(rows) and len(answers) == len(requests)
         and all(row.get("method") == "GET" and row.get("path") == path and row.get("status") == 200
                 and row.get("userAgent") == PRODUCT_AGENT for row in requests)
         and all(row.get("status") == 200 and row.get("sent") is True and row.get("bodySha256") == lease.config["bodySha256"]
                 for row in answers), "document-cache-fixture-fetches")
    owner.event("document-cache-fixture-stopped", {"child": child.ordinal, "terminal": terminal, "productFetches": len(requests),
        "journalEntries": len(rows), "journalSha256": sha256(raw), "onlyOwnedListenersStopped": True})
    return len(requests)


def _show(call, subscription, url, name, count, status):
    shown = call("subscriptions", "show", subscription)["data"]
    need((shown.get("id"), shown.get("source"), shown.get("name"), shown.get("cachedLocations"), shown.get("refreshStatus"),
          shown.get("failureReason")) == (subscription, url, name, count, status, None), "document-cache-subscription-row")
    return shown


def committed_cache(owner, windows, workspace, subscription, url, cache, moment):
    """The committed cache in workspace.json, read by the document rows' own reader and by the location records.

    windows.cache_bytes reads the subscription's cached_locations and journals document-cache-bytes. A cold owner rebuilds
    that cache from the workspace's location records of the same source, so those are read too, from the same generation."""
    expected = cache["expectedLocations"]
    value = windows.cache_bytes(owner, workspace, subscription, expected)
    held = windows.Held(owner.native, Path(workspace) / "workspace.json")
    try:
        raw = held.bytes()
        held.current()
    finally:
        held.close()
    need(sha256(raw) == value["workspace"]["sha256"], "document-cache-workspace-generation")
    document = json.loads(raw.decode("utf-8", "strict"))
    state = document["persisted_state"]
    rows = [row for row in state["subscriptions"] if row.get("id") == subscription]
    need(len(rows) == 1 and rows[0].get("url") == url, "document-cache-committed-subscription")
    records = [row.get("raw_link") for row in document.get("locations", []) if type(row) is dict and row.get("source_url") == url]
    need(records == expected, "document-cache-location-records")
    need((value["cacheCount"], value["newlineBytes"], value["newlineSha256"])
         == (cache["expectedCount"], cache["expectedNewlineBytes"], cache["expectedNewlineSha256"]), "document-cache-recipe-digest")
    current = state.get("current_locations")
    observed = {"moment": moment, "subscriptionId": subscription, "cacheCount": value["cacheCount"],
                "newlineBytes": value["newlineBytes"], "newlineSha256": value["newlineSha256"],
                "recordsNewlineSha256": sha256(newline_bytes(records)), "workspaceSha256": sha256(raw), "workspaceBytes": len(raw),
                # Recorded, not compared: the visible list the GUI shows, derived from the same records.
                "currentLocations": None if type(current) is not list else {"count": len(current),
                    "newlineSha256": sha256(newline_bytes([str(item) for item in current]))}}
    owner.event("document-cache-committed", observed)
    return observed


def locations_export(owner, workspace, controller, harness, windows, leaf, expected):
    """The product's own export of the visible locations, which a cold owner reads from the cache; exported_at never counts."""
    destination = Path(owner.root) / leaf
    need(not destination.exists(), "document-cache-export-new-leaf")
    result = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", controller,
                                              "locations", "export", "--output", str(destination)))
    need(result["controllerId"] == controller and result["final"] is True, "document-cache-export-owner")
    held = windows.Held(owner.native, destination)
    try:
        raw = held.bytes(64 * 1024 * 1024)
    finally:
        held.close()
    value = json.loads(raw.decode("utf-8", "strict"))
    need(type(value) is dict and value.get("type") == "vpn_control_locations" and value.get("version") == 1
         and value.get("locations") == [json.loads(item) for item in expected]
         and result["data"].get("bytes") == len(raw), "document-cache-export-readback")
    semantic = {key: value[key] for key in ("type", "version", "locations")}
    return {"exportBytes": len(raw), "count": len(value["locations"]),
            "semanticSha256": sha256(json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"))}


# ---- The closed-state corruption step ---------------------------------------------------------------------------------

def corrupted(raw, kind):
    """The committed workspace bytes with one corruption, and the offset it is at.

    changed-byte: the first byte inside the first cached location string, its '{', becomes 0xFF, which is never valid
    UTF-8 anywhere. truncated: the document's closing brace, the last byte before any trailing whitespace, is cut with
    what follows it. trailing-byte: one non-whitespace byte after the document."""
    if kind == "changed-byte":
        key = raw.find(b'"cached_locations"')
        start = raw.find(b"[", key) if key >= 0 else -1
        offset = raw.find(b'"', start) + 1 if start >= 0 else 0
        need(key >= 0 and start > key and offset > start and raw[offset:offset + 1] == b"{", "document-cache-corruption-shape")
        return raw[:offset] + b"\xff" + raw[offset + 1:], offset
    if kind == "truncated":
        end = len(raw.rstrip(b" \t\r\n"))
        need(end > 1 and raw[end - 1:end] == b"}", "document-cache-corruption-shape")
        return raw[:end - 1], end - 1
    need(kind == "trailing-byte", "document-cache-corruption-kind")
    return raw + b"x", len(raw)


def _state_names(folder):
    return sorted(os.listdir(folder))


def _kept_names(folder):
    return [name for name in _state_names(folder) if name.startswith(KEPT_PREFIXES)]


def _read_held(owner, windows, path):
    held = windows.Held(owner.native, path)
    try:
        return held.bytes()
    finally:
        held.close()


def _place_workspace(owner, windows, folder, leaf, raw):
    """With the product closed, raw becomes workspace.json as the product itself replaces it: a new file in the state
    folder, flushed, then renamed over the workspace file. The held read back must be exactly raw."""
    temp = Path(folder) / leaf
    need(not temp.exists(), "document-cache-corruption-new-leaf")
    with temp.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, Path(folder) / "workspace.json")
    need(_read_held(owner, windows, Path(folder) / "workspace.json") == raw, "document-cache-corruption-placed")


def corrupt_closed(owner, workspace, harness, windows, kind, committed, previous):
    """One corruption of the closed committed workspace, opened by an independent serve, then the committed bytes back.

    The product must keep the exact bad bytes aside under its own kept name, load the defaults and save them at once,
    warn in `status` and name the kept file in its one typed log entry, and keep serving: nothing is accepted silently,
    nothing is written over the bad bytes, and nothing crashes. A product that writes its defaults over them (every
    build before the workspace-corruption fix) fails at the first oracle: document-cache-corruption-kept-aside:<kind>.
    Returns what was observed and the serve's controller, which the next owner of the workspace must differ from."""
    folder = Path(workspace)
    bad, offset = corrupted(committed, kind)
    need(not (folder / "activation.port").exists() and not (folder / RECOVERY_LEAF).exists() and not _kept_names(folder),
         "document-cache-corruption-closed-state")
    _place_workspace(owner, windows, folder, "document-cache-%s.tmp" % kind, bad)
    owner.event("document-cache-corruption-placed", {"kind": kind, "offset": offset, "committedBytes": len(committed),
        "committedSha256": sha256(committed), "corruptBytes": len(bad), "corruptSha256": sha256(bad), "productClosed": True})
    child = owner.child("document-cache-corrupt-serve", [owner.request["cliPath"], "--state-dir", str(workspace), "serve"])
    controller = _ready(owner, workspace, child, READY_SECONDS["serve"], previous)
    # From here a known failure quits this serve (close_known), as it does the reopened one.
    owner.document_reopened_owner = {"child": child, "controllerId": controller, "gui": False}
    owner.event("document-cache-corruption-opened", {"kind": kind, "child": child.ordinal, "controllerId": controller})

    def call(*tail):
        body = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", controller, *tail))
        need(body["controllerId"] == controller and body["final"] is True, "document-cache-owner-answer")
        return body
    kept = _kept_names(folder)
    need(len(kept) == 1 and KEPT_NAME.fullmatch(kept[0]) is not None and not (folder / RECOVERY_LEAF).exists(),
         "document-cache-corruption-kept-aside:" + kind)
    kept_raw = _read_held(owner, windows, folder / kept[0])
    need(kept_raw == bad, "document-cache-corruption-kept-bytes:" + kind)
    status = call("status")
    need(status["data"].get("runtimeRunning") is False and status.get("warnings") == [KEPT_WARNING],
         "document-cache-corruption-status-warning:" + kind)
    entries = call("logs", "--limit", LOG_LIMIT)["data"].get("entries")
    need(type(entries) is list, "document-cache-corruption-typed-status:" + kind)
    typed = [row.get("message") for row in entries if type(row) is dict and type(row.get("message")) is str
             and row["message"].startswith(UNREADABLE_PREFIX)]
    need(typed == ["%s(%s)" % (DEFAULTS_LOADED, kept[0])], "document-cache-corruption-typed-status:" + kind)
    need(call("subscriptions", "list")["data"].get("subscriptions") == [], "document-cache-corruption-defaults:" + kind)
    # The defaults were saved at once in place of the bad bytes, in this build's format.
    current = _read_held(owner, windows, folder / "workspace.json")
    try:
        saved = json.loads(current.decode("utf-8", "strict"))
    except ValueError:
        saved = None
    need(type(saved) is dict and saved.get("format") == 1 and type(saved.get("persisted_state")) is dict
         and saved["persisted_state"].get("subscriptions") == [], "document-cache-corruption-defaults-saved:" + kind)
    need(child.process.poll() is None and _kept_names(folder) == kept, "document-cache-corruption-owner-alive:" + kind)
    owner.event("document-cache-corrupt-quit-intent", {"kind": kind, "child": child.ordinal, "controllerId": controller,
                                                       "replayAllowed": False})
    call("quit")
    terminal = child.wait()
    need(terminal["exitCode"] == 0 and not (folder / "activation.port").exists(), "document-cache-corruption-owner-closed:" + kind)
    # The kept copy leaves the state folder whole, so no later owner names or warns about it, and the committed bytes
    # go back exactly before anything else opens the workspace.
    evidence = Path(owner.root) / ("document-cache-kept-%s.json" % kind)
    need(not evidence.exists(), "document-cache-corruption-new-leaf")
    os.replace(folder / kept[0], evidence)
    need(_read_held(owner, windows, evidence) == bad, "document-cache-corruption-kept-bytes:" + kind)
    _place_workspace(owner, windows, folder, "document-cache-restore-%s.tmp" % kind, committed)
    need(not _kept_names(folder) and not (folder / RECOVERY_LEAF).exists(), "document-cache-corruption-restored")
    observed = {"kind": kind, "offset": offset, "corruptBytes": len(bad), "corruptSha256": sha256(bad), "keptName": kept[0],
                "keptSha256": sha256(kept_raw), "warnings": status["warnings"], "typedStatus": typed[0],
                "defaultsSha256": sha256(current), "child": child.ordinal, "controllerId": controller,
                "exitCode": terminal["exitCode"], "keptEvidenceLeaf": evidence.name, "restoredSha256": sha256(committed)}
    owner.event("document-cache-corruption-observed", observed)
    return observed, controller


def _run_cache(owner, workspace, identity, harness, windows, case, original):
    cache, lease = case["cache"], owner.document_cache_lease
    expected, name = cache["expectedLocations"], cache["subscriptionName"]
    url = lease.ready["cacheUrl"]
    lease.guard()

    def call(*tail, controller=identity):
        body = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", controller, *tail))
        need(body["controllerId"] == controller and body["final"] is True, "document-cache-owner-answer")
        return body

    def guarded(*tail):
        return call("--if-revision", str(call("status")["configurationRevision"]), *tail)
    before = call("status")
    need(before["data"]["runtimeRunning"] is False, "document-cold-disconnected-owner")
    need(call("subscriptions", "list")["data"]["subscriptions"] == [], "document-cache-fresh-subscriptions")
    # No policy or Find Best runs on this source: the one refresh below is the only fetch the product makes.
    for key, value in (("refresh.policy", "off"), ("refresh.find-best-after-refresh", "false")):
        guarded("settings", "set", key, value)
    subscription = guarded("subscriptions", "add", "--source", url, "--name", name)["data"].get("id")
    need(type(subscription) is str and subscription, "document-cache-subscription-identity")
    guarded("source", "set", "subscription", subscription)
    _show(call, subscription, url, name, 0, "")
    owner.event("document-cache-refresh-intent", {"subscriptionId": subscription, "cacheUrl": url, "controllerId": identity,
                                                  "replayAllowed": False})
    lease.refresh_open = True
    refreshed = owner.invoke(workspace, "--json", "--controller-id", identity, "subscriptions", "refresh", subscription)
    try:
        answer = json.loads(refreshed.stdout)
    except ValueError:
        answer = None
    if type(answer) is dict and answer.get("final") is True and answer.get("controllerId") == identity:
        lease.refresh_open = False  # The product's refresh has ended, whatever it answered.
    refreshed = harness["envelope"](refreshed)
    need(refreshed["controllerId"] == identity and refreshed["final"] is True, "document-cache-refresh-owner")
    _show(call, subscription, url, name, len(expected), "OK")
    warm = committed_cache(owner, windows, workspace, subscription, url, cache, "warm")
    warm_export = locations_export(owner, workspace, identity, harness, windows, "document-cache-export-warm.json", expected)
    # Nothing can be fetched again: whatever a later owner shows is read from the committed cache.
    fetches = stop_cache_source(owner, lease)
    # Cold: the original owner ends through the same public quit a pass sends, and its descriptor goes with it.
    owner.event("document-cold-quit-intent", {"child": original.ordinal, "controllerId": identity, "replayAllowed": False})
    call("quit")
    terminal = original.wait()
    need(terminal["exitCode"] == 0 and not (Path(workspace) / "activation.port").exists(), "document-cold-original-closed")
    closed = committed_cache(owner, windows, workspace, subscription, url, cache, "closed")
    # Still closed: the committed bytes, read whole, are corrupted three ways, each opened by an independent serve and
    # put back exactly, so the reopen below reads the file the original serve left.
    committed = _read_held(owner, windows, Path(workspace) / "workspace.json")
    need(sha256(committed) == closed["workspaceSha256"], "document-cache-workspace-generation")
    corruption, previous = [], identity
    for kind in CORRUPTIONS:
        observed, previous = corrupt_closed(owner, workspace, harness, windows, kind, committed, previous)
        corruption.append(observed)
    child = owner.child("document-cold-serve", [owner.request["cliPath"], "--state-dir", str(workspace), "serve"])
    reopened = _ready(owner, workspace, child, READY_SECONDS["serve"], previous)
    owner.document_reopened_owner = {"child": child, "controllerId": reopened, "gui": False}
    owner.event("document-cold-reopened", {"variant": CACHE, "child": child.ordinal, "controllerId": reopened,
                                           "byInstalledGui": False, "originalControllerId": identity})
    _show(lambda *tail: call(*tail, controller=reopened), subscription, url, name, len(expected), "OK")
    cold = committed_cache(owner, windows, workspace, subscription, url, cache, "reopened")
    cold_export = locations_export(owner, workspace, reopened, harness, windows, "document-cache-export-reopened.json", expected)
    need(cold_export["semanticSha256"] == warm_export["semanticSha256"], "document-cache-reopened-export")
    result = {"variant": CACHE, "subscriptionId": subscription, "cacheCount": cold["cacheCount"], "newlineBytes": cold["newlineBytes"],
              "newlineSha256": cold["newlineSha256"], "warm": warm, "closed": closed, "reopened": cold, "warmExport": warm_export,
              "reopenedExport": cold_export, "productFetches": fetches, "controllerId": reopened, "independentOwner": True,
              "windowsStoreFormat": "workspace-json-array", "productDigestOfCache": False,
              "corruption": corruption, "unreadableKeptAside": [item["kind"] for item in corruption]}
    owner.event("document-cold-observed", {**result, "nativeAcceptanceComplete": False})
    return result


# ---- The routing variants and the shared closing ----------------------------------------------------------------------

def configure_launch(owner, workspace):
    """The serve and any later owner of this workspace spool transfers in the admitted temp parent only.

    The cache variant also starts its own subscription source here, before the serve exists."""
    owner.guard()
    inputs = _inputs(owner)
    workspace, temp = Path(workspace), Path(inputs["spoolTempParent"])
    need(workspace == Path(owner.request["workspace"]) and workspace.parent == Path(owner.root)
         and not workspace.exists() and temp.parent == Path(owner.root) and temp != workspace and temp.is_dir(),
         "document-cold-configure-before-fresh-serve")
    pins = [pin for pin in owner.pins if getattr(pin, "directory", False) and pin.path == temp]
    need(len(pins) == 1, "document-cold-admitted-temp-directory-pin")
    pins[0].current()
    case = literal_input(owner)
    if case["variant"] == CACHE:
        start_cache_source(owner, case["cache"])
    owner.environment["TEMP"] = str(temp)
    owner.environment["TMP"] = str(temp)
    owner.document_launch_marker = {"tempParent": str(temp), "workspace": str(workspace),
                                    "expectedServeOrdinal": len(owner.children), "sourcePath": __file__}
    owner.event("document-temp-configured-before-serve", {**owner.document_launch_marker, "workspaceStillAbsent": True})


def _export(owner, workspace, identity, harness, windows, leaf):
    destination = Path(owner.root) / leaf
    need(not destination.exists(), "document-cold-export-new-leaf")
    result = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity,
                                              "routing", "export", "--output", str(destination)))
    need(result["controllerId"] == identity and result["final"] is True, "document-cold-export-owner")
    held = windows.Held(owner.native, destination)
    try:
        raw = held.bytes(64 * 1024 * 1024)
    finally:
        held.close()
    return semantic_sha256(raw), len(raw)


def _ready(owner, workspace, child, seconds, previous):
    """A status loop that never starts an owner: the new owner answers OK under a new controller."""
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        need(child.process.poll() is None, "document-cold-owner-ended-before-readiness")
        status = owner.invoke(workspace, "--json", "status")
        body = json.loads(status.stdout)
        if status.returncode == 0:
            need(status.stderr == "" and body["code"] == "OK" and body["final"] is True
                 and body["data"]["runtimeRunning"] is False and type(body["controllerId"]) is str
                 and body["controllerId"] != previous, "document-cold-reopened-owner-status")
            return body["controllerId"]
        need(status.returncode == 2 and body["code"] == "UNAVAILABLE", "document-cold-unexpected-readiness")
        time.sleep(0.2)
    owner.park("document-cold-reopened-owner-readiness-unknown")


def _quit_original(owner, workspace, identity, harness, original):
    """Cold: the original owner ends through the same public quit a pass sends, and its descriptor goes with it."""
    owner.event("document-cold-quit-intent", {"child": original.ordinal, "controllerId": identity, "replayAllowed": False})
    quit_body = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity, "quit"))
    need(quit_body["controllerId"] == identity and quit_body["final"] is True, "document-cold-quit-acknowledged")
    terminal = original.wait()
    need(terminal["exitCode"] == 0 and not (Path(workspace) / "activation.port").exists(), "document-cold-original-closed")


# ---- The GUI's own file picker against the CLI (gui-picker) -----------------------------------------------------------

PICKER_FILE_SECONDS = 60  # The GUI's export, written after its Save dialog closed.
PICKER_IMPORT_SECONDS = 60  # The GUI's import, committed after its Open dialog closed.


def _read_whole(owner, windows, path):
    held = windows.Held(owner.native, path)
    try:
        return held.bytes(64 * 1024 * 1024)
    finally:
        held.close()


def _await_written(owner, windows, path):
    """The GUI's export once the product published it whole: a held read that its writer no longer blocks."""
    until = time.monotonic() + PICKER_FILE_SECONDS
    while True:
        if Path(path).exists():
            try:
                return _read_whole(owner, windows, path)
            except Exception as error:
                # Still held by its writer (NativeOpenError), or changed while it was read: read it again.
                if not (type(error).__name__ == "NativeOpenError" or str(error).startswith("document-held-")):
                    raise
        if time.monotonic() >= until:
            owner.event("document-gui-picker-export-absent", {"path": str(path), "exists": Path(path).exists(), "replayAllowed": False})
            raise RuntimeError("document-gui-picker-export-absent")
        time.sleep(0.5)


def _run_picker(owner, workspace, identity, harness, windows, case, original):
    picker = case["picker"]
    suffix = owner.operation.replace("-", "")
    gui_module = owner.module(picker["modulePath"], "document_gui_picker_" + suffix)
    desktop_module = owner.module(picker["desktopPath"], "document_gui_picker_desktop_" + suffix)
    first, second = picker["firstInputPath"], picker["secondInputPath"]
    expected = {"first": (picker["firstSemanticSha256"], picker["suffixCount"]),
                "second": (picker["secondSemanticSha256"], picker["suffixCount"])}
    root = Path(owner.root)

    def call(controller, *tail):
        body = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", controller, *tail))
        need(body["controllerId"] == controller and body["final"] is True, "document-gui-picker-owner-answer")
        return body

    def cli_import(controller, path):
        revision = call(controller, "status")["configurationRevision"]
        call(controller, "--if-revision", str(revision), "routing", "import", "--input", str(path))

    def cli_export(controller, leaf, document, code):
        destination = root / leaf
        need(not destination.exists(), "document-gui-picker-export-new-leaf")
        result = call(controller, "routing", "export", "--output", str(destination))
        raw = _read_whole(owner, windows, destination)
        need(result["data"].get("bytes") in (None, len(raw)) and semantic_sha256(raw) == expected[document], code)
        return destination, raw

    def state(controller, leaf, document, code):
        """The committed routing rules in workspace.json and the product's export of them, after an import."""
        held = windows.Held(owner.native, Path(workspace) / "workspace.json")
        try:
            raw = held.bytes()
            held.current()
        finally:
            held.close()
        status = call(controller, "status")
        _, exported = cli_export(controller, leaf, document, code)
        return {**gui_module.routing_state(raw), "exportSemanticSha256": semantic_sha256(exported)[0],
                "restartRequired": status["restartRequired"], "runtimeRunning": status["data"]["runtimeRunning"]}

    before = call(identity, "status")
    need(before["data"]["runtimeRunning"] is False, "document-cold-disconnected-owner")
    # The CLI's import and export of the first document, by the original serve.
    cli_import(identity, first)
    _, cli_first = cli_export(identity, "document-picker-cli-first.json", "first", "document-gui-picker-cli-readback")
    _quit_original(owner, workspace, identity, harness, original)
    launcher = str(Path(owner.request["cliPath"]).with_name("vpn-control.exe"))
    need(launcher.casefold() in owner.by_path, "document-cold-installed-gui-pin")
    lease, child = gui_module.start(owner, desktop_module, launcher, workspace)
    reopened = _ready(owner, workspace, child, READY_SECONDS["gui"], identity)
    # From here the owner closes this one, on a pass and on a known failure alike: the picker's closing first.
    owner.document_reopened_owner = {"child": child, "controllerId": reopened, "gui": True, "picker": None}
    session = owner.document_reopened_owner["picker"] = gui_module.session(owner, lease, child)
    owner.event("document-cold-reopened", {"variant": PICKER, "child": child.ordinal, "controllerId": reopened,
                                           "byInstalledGui": True, "originalControllerId": identity, "desktop": lease.name})
    session.attach()
    session.show()
    # 1. The GUI's export through its picker is the CLI's export of the same rules, but for its moment.
    gui_first = root / "document-picker-gui-first.json"
    need(not gui_first.exists(), "document-gui-picker-export-new-leaf")
    session.export_file(gui_first)
    gui_raw = _await_written(owner, windows, gui_first)
    same, compared = gui_module.same_export(gui_raw, cli_first)
    owner.event("document-gui-picker-export-compared", {**compared, "same": same})
    need(same, "document-gui-picker-export-bytes")
    # 2. The CLI, through the GUI's own controller: the second document, its export for the GUI, and the GUI's export.
    cli_import(reopened, second)
    cli_second_path, _ = cli_export(reopened, "document-picker-cli-second.json", "second", "document-gui-picker-cli-readback")
    cli_import(reopened, gui_first)
    cli_export(reopened, "document-picker-cli-of-gui-export.json", "first", "document-gui-picker-gui-export-cli-import")
    # 3. The GUI's import of the CLI's export through its picker.
    revision = call(reopened, "status")["configurationRevision"]
    session.import_file(cli_second_path)
    until = time.monotonic() + PICKER_IMPORT_SECONDS
    while call(reopened, "status")["configurationRevision"] == revision:
        if time.monotonic() >= until:
            raise RuntimeError("document-gui-picker-gui-import-not-committed")
        time.sleep(1)
    gui_state = state(reopened, "document-picker-after-gui-import.json", "second", "document-gui-picker-cli-export-gui-import")
    # 4. The CLI's import of the same file from the first document's rules: the same committed state.
    cli_import(reopened, gui_first)
    cli_import(reopened, cli_second_path)
    cli_state = state(reopened, "document-picker-after-cli-import.json", "second", "document-gui-picker-cli-readback")
    owner.event("document-gui-picker-import-compared", {"gui": gui_state, "cli": cli_state, "same": gui_state == cli_state})
    need(gui_state == cli_state, "document-gui-picker-import-state")
    session.restore()
    result = {"variant": PICKER, "controllerId": reopened, "independentOwner": True, "guiExport": compared,
              "guiImportState": gui_state, "cliImportState": cli_state, "steps": list(session.steps),
              "frames": session.frames, "desktop": lease.name}
    owner.event("document-cold-observed", {**result, "nativeAcceptanceComplete": False})
    return result


def run(owner, workspace, identity, harness):
    _inputs(owner)
    case = literal_input(owner)
    variant = case["variant"]
    need(type(harness) is dict and callable(harness.get("envelope")), "document-cold-shared-harness-dict-api")
    marker = owner.document_launch_marker
    cli = owner.request["cliPath"]
    serves = [child for child in owner.children if tuple(child.argv) == (cli, "--state-dir", str(workspace), "serve")]
    need(marker["workspace"] == str(workspace) and marker["sourcePath"] == __file__ and len(serves) == 1
         and serves[0].ordinal == marker["expectedServeOrdinal"] and serves[0].process.poll() is None,
         "document-cold-original-serve")
    original = serves[0]
    windows = owner.module(owner.request["documentAcceptance"]["windowsPath"], "document_cold_windows_" + owner.operation.replace("-", ""))
    if variant == CACHE:
        return _run_cache(owner, workspace, identity, harness, windows, case, original)
    if variant == PICKER:
        return _run_picker(owner, workspace, identity, harness, windows, case, original)
    expected = (case["expectedSemanticSha256"], case["expectedSuffixCount"])
    before = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity, "status"))
    need(before["controllerId"] == identity and before["data"]["runtimeRunning"] is False, "document-cold-disconnected-owner")
    source = case["routingInputPath"]
    imported = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity, "--if-revision",
                                                str(before["configurationRevision"]), "routing", "import", "--input", source))
    need(imported["controllerId"] == identity and imported["final"] is True, "document-cold-import-owner")
    warm, warm_bytes = _export(owner, workspace, identity, harness, windows, "document-cold-export-warm.json")
    need(warm == expected, "document-cold-warm-readback")
    owner.event("document-cold-warm-readback", {"variant": variant, "semanticSha256": warm[0], "suffixes": warm[1],
                                                "exportBytes": warm_bytes, "controllerId": identity})
    _quit_original(owner, workspace, identity, harness, original)
    gui = variant == "gui-owner"
    if gui:
        launcher = str(Path(cli).with_name("vpn-control.exe"))
        need(launcher.casefold() in owner.by_path, "document-cold-installed-gui-pin")
        child = owner.child("document-gui-owner", [launcher, "--state-dir", str(workspace)])
    else:
        child = owner.child("document-cold-serve", [cli, "--state-dir", str(workspace), "serve"])
    reopened = _ready(owner, workspace, child, READY_SECONDS["gui" if gui else "serve"], identity)
    # From here the owner closes this one, on a pass and on a known failure alike.
    owner.document_reopened_owner = {"child": child, "controllerId": reopened, "gui": gui}
    owner.event("document-cold-reopened", {"variant": variant, "child": child.ordinal, "controllerId": reopened,
                                           "byInstalledGui": gui, "originalControllerId": identity})
    cold, cold_bytes = _export(owner, workspace, reopened, harness, windows, "document-cold-export-reopened.json")
    need(cold == expected, "document-cold-reopened-readback")
    result = {"variant": variant, "semanticSha256": cold[0], "suffixes": cold[1], "exportBytes": cold_bytes,
              "controllerId": reopened, "independentOwner": True}
    if gui:
        # The CLI's large upload and download, both through the transfer store of the GUI-started controller.
        current = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", reopened, "status"))
        again = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", reopened, "--if-revision",
                                                 str(current["configurationRevision"]), "routing", "import", "--input", source))
        need(again["controllerId"] == reopened and again["final"] is True, "document-gui-owner-import")
        after, after_bytes = _export(owner, workspace, reopened, harness, windows, "document-gui-export.json")
        need(after == expected and child.process.poll() is None, "document-gui-owner-readback")
        result.update(guiOwnerImport=True, guiExportBytes=after_bytes)
    owner.event("document-cold-observed", {**result, "nativeAcceptanceComplete": False})
    return result


def close_known(owner, error, serve, identity):
    """A finite oracle failure with nothing in flight names the owner still running; anything else returns None.

    Known: the harness's AssertionError, or this module's own document- codes. The cache variant's source is ended
    first, by one termination of its original handle, unless a refresh may still be fetching from it: then every
    original stays for the park. The picker variant's GUI steps close first, whether or not its GUI still runs: a file
    dialog they left open gets one posted cancel and the input desktop is switched back to Default, and what cannot be
    known there parks. A GUI-started owner is closed here by one journaled public quit and its exit, because the owner's
    closing knows only serves; a reopened serve, or the live serve of the cache variant's corruption step, is returned
    for that closing, and before any reopen, or once that serve has exited, the original is.
    """
    try:
        name = type(error).__name__
        if not (name == "AssertionError" or name in ("RuntimeError", "Refused") and str(error).startswith("document-")):
            return None
        lease = getattr(owner, "document_cache_lease", None)
        if lease is not None and not lease.closed:
            if lease.refresh_open:
                return None
            end_cache_source(owner, lease, error, "known-failure")
        reopened = getattr(owner, "document_reopened_owner", None)
        if reopened is not None and reopened.get("picker") is not None:
            # A dialog the GUI steps left open is cancelled and the input desktop is Default again before the quit.
            reopened["picker"].close_known()
        if reopened is None or reopened["child"].terminal is not None:
            return serve, identity
        if not reopened["gui"]:
            return reopened["child"], reopened["controllerId"]
        child, controller, workspace = reopened["child"], reopened["controllerId"], Path(owner.request["workspace"])
        owner.event("document-gui-owner-quit-intent", {"child": child.ordinal, "controllerId": controller, "replayAllowed": False})
        result = owner.invoke(workspace, "--json", "--controller-id", controller, "quit")
        body = json.loads(result.stdout)
        if not (result.returncode == 0 and result.stderr == "" and body.get("controllerId") == controller and body.get("final") is True):
            owner.park("document-gui-owner-quit-not-acknowledged", error)
        until = time.monotonic() + CLOSE_SECONDS
        while child.observe() is None or (workspace / "activation.port").exists():
            if time.monotonic() >= until:
                owner.park("document-gui-owner-exit-unknown", error)
            time.sleep(0.1)
        owner.event("document-gui-owner-closed", {"child": child.ordinal, "terminal": child.terminal, "endpointReleased": True})
        return serve, identity
    except Exception as closing:
        owner.park("document-cold-known-failure-closing-unknown", closing)
