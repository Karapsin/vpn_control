"""Finite installed-Windows stream cases, using the retained ordinary owner.

Private preparation only. A native DIRECT run and matched current-MCP run are
required. Import performs no native, filesystem, network, or product action.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as W
import json
import os
from pathlib import Path, PureWindowsPath
import re
import sys
import time


STREAMS = (("status", "--watch"), ("stats", "--watch"),
           ("logs", "--follow", "--limit", "0"))
READ_LIMIT = 1024 * 1024
READ_SECONDS = 40
INTERRUPT_SECONDS = 15
RESTART_CHILD_FIELDS = frozenset({"pid", "parentPid", "image", "sessionId", "creationFileTime"})


def require(value, reason):
    if not value:
        raise AssertionError(reason)


class ProcessEntry(ctypes.Structure):
    """PROCESSENTRY32W, read as scripts/windows_broker_fixture_observer.py reads it."""
    _fields_ = [("size", W.DWORD), ("usage", W.DWORD), ("pid", W.DWORD), ("heap", ctypes.c_size_t),
                ("module", W.DWORD), ("threads", W.DWORD), ("parentPid", W.DWORD), ("priority", W.LONG),
                ("flags", W.DWORD), ("name", W.WCHAR * 260)]


class ConsoleRefused(AssertionError):
    """A console fence refusal naming every attached process: pid, parent pid, image basename, session."""
    def __init__(self, reason, members):
        super().__init__(reason)
        self.members = members


class SignalUnknown(AssertionError):
    """A failure once this helper's create-only intent exists, never a refusal: the intent forbids a
    second attempt, and signal_attempted says whether the one GenerateConsoleCtrlEvent call was made."""
    def __init__(self, reason, signal_attempted):
        super().__init__(reason)
        self.signal_attempted = signal_attempted


def _json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _read(child, name):
    path = child.owner.root / f"child-{child.ordinal:04d}.{name}.raw"
    with path.open("rb") as source:
        value = source.read(READ_LIMIT + 1)
    require(len(value) <= READ_LIMIT, "stream-observation-byte-bound")
    return value


def _live(child):
    require(child.process is not None and child.pid is not None and child.birth is not None,
            "original-client-native-admission")
    require(child.owner.native.birth(int(child.process._handle)) == child.birth,
            "original-client-handle-birth-changed")
    return child.observe() is None


def _records(child, harness, identity, terminal=False):
    value = _read(child, "stdout")
    if terminal:
        require(value.endswith(b"\n"), "terminal-ndjson-has-unfinished-record")
    records = [json.loads(line.decode("utf-8", "strict"))
               for line in value.split(b"\n")[:-1]]
    snapshots = records
    if terminal and records and records[-1].get("code") == "CANCELLED":
        cancellation = records[-1]
        require(cancellation.get("schemaVersion") == 1 and cancellation.get("ok") is False
                and cancellation.get("final") is True and cancellation.get("controllerId") == identity,
                "terminal-stream-cancellation-metadata")
        snapshots = records[:-1]
    # Reuse the canonical complete-record envelope oracle unchanged.
    harness["verify_stream_records"](snapshots, identity)
    return snapshots


def _status(owner, workspace, identity, harness):
    result = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id",
                                             identity, "status"))
    require(result["controllerId"] == identity and result["final"] is True
            and result["data"]["runtimeRunning"] is False, "same-disconnected-owner")
    return result


def _pulse(owner, workspace, identity, revision, harness, ordinal):
    """A distinct, known-terminal no-op creates one real redacted log entry.

    Human empty-history follow has no initial output. At most eight explicitly
    recorded no-op actions are permitted, each guarded by its own before-read;
    an unknown result is never replayed to produce a missing line.
    """
    before = _status(owner, workspace, identity, harness)
    require(before["configurationRevision"] == revision, "pulse-before-revision-changed")
    result = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity,
        "--if-revision", str(revision), "source", "set", "current-locations"))
    require(result["controllerId"] == identity and result["final"] is True
            and result["configurationRevision"] == revision, "pulse-was-not-known-no-op")
    owner.event("stream-known-log-pulse", {"pulseOrdinal": ordinal,
        "requestId": result["requestId"], "operationId": result.get("operationId"),
        "configurationRevision": revision, "final": True, "replayAllowed": False})


def _wait_ready(child, args, json_mode, identity, revision, workspace, harness):
    deadline = time.monotonic() + READ_SECONDS
    next_pulse, pulses = time.monotonic() + 1, 0
    while time.monotonic() < deadline:
        require(_live(child), "original-stream-ended-before-interrupt")
        if json_mode:
            records = _records(child, harness, identity)
            if args[0] == "logs":
                if records:
                    require(records[0]["data"]["entries"] == [], "follow-zero-replayed-history")
                if len(records) >= 2:
                    ids = [entry["id"] for row in records for entry in row["data"]["entries"]]
                    require(ids and len(ids) == len(set(ids)), "follow-cursor-duplicate-or-empty")
                    return
            elif len(records) >= 2:
                return
        else:
            lines = _read(child, "stderr").split(b"\n")[:-1]
            if len(lines) >= 2:
                for line in lines:
                    if args[0] == "logs":
                        stamp, message = line.decode("utf-8", "strict").split("\t", 1)
                        require(stamp.isdecimal() and type(json.loads(message)) is str,
                                "human-follow-record-shape")
                    else:
                        require(type(json.loads(line.decode("utf-8", "strict"))) is dict,
                                "human-watch-record-shape")
                return
        if args[0] == "logs" and time.monotonic() >= next_pulse:
            # JSON waits for its authoritative tail cursor before its first pulse.
            if not json_mode or records:
                require(pulses < 8, "finite-log-pulse-bound")
                _pulse(child.owner, workspace, identity, revision, harness, pulses)
                pulses += 1
                next_pulse = time.monotonic() + 4
        time.sleep(0.05)
    child.owner.park("stream-readiness-deadline-retained", {"child": child.ordinal,
        "pid": child.pid, "birthFileTimeUtc": child.birth, "replayAllowed": False})


def _wait_terminal(child, seconds, phase):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = child.observe()
        if value is not None:
            return value
        time.sleep(0.05)
    child.owner.park(phase, {"child": child.ordinal, "pid": child.pid,
                            "birthFileTimeUtc": child.birth, "replayAllowed": False})


def _restart_child(owner, child, helper, serve, record):
    """The client launcher's own restart child as the helper admitted it, never another process."""
    return (type(record) is dict and set(record) == RESTART_CHILD_FIELDS
            and type(record["pid"]) is int and record["pid"] > 0
            and record["pid"] not in {child.pid, helper.pid, serve.pid, os.getpid()}
            and record["parentPid"] == child.pid and type(record["image"]) is str
            and record["image"].casefold() == PureWindowsPath(owner.request["cliPath"]).name.casefold()
            and record["sessionId"] == owner.request["context"]["ordinarySessionId"]
            and type(record["creationFileTime"]) is str
            and re.fullmatch(r"[1-9][0-9]{0,18}", record["creationFileTime"]) is not None
            and int(record["creationFileTime"]) > int(child.birth))


def _interrupt(owner, child, serve):
    require(getattr(child, "new_console", False) is True and _live(child),
            "only-original-live-new-console-client")
    owner.guard()
    intent = owner.root / f"child-{child.ordinal:04d}.ctrl-c.intent.json"
    require(not intent.exists(), "client-interrupt-intent-already-exists")
    owner.event("stream-interrupt-intent", {"child": child.ordinal, "pid": child.pid,
        "birthFileTimeUtc": child.birth, "ordinarySessionId": owner.request["context"]["ordinarySessionId"],
        "workerPid": os.getpid(), "servePid": serve.pid, "originalHandleRetained": True,
        "intentPath": str(intent), "signalAttemptsAllowed": 1})
    helper = owner.child("owned-console-interrupter", [owner.request["pythonRuntime"]["interpreterPath"],
        owner.request["casesPath"], "--interrupt-owned-console", str(child.pid), child.birth,
        str(owner.request["context"]["ordinarySessionId"]), str(os.getpid()), str(serve.pid), str(intent)])
    helper_terminal = _wait_terminal(helper, INTERRUPT_SECONDS, "console-helper-deadline-retained")
    require(helper_terminal["exitCode"] == 0 and _read(helper, "stderr") == b"",
            "owned-console-helper-failed")
    receipt = json.loads(_read(helper, "stdout").decode("utf-8", "strict"))
    restart = receipt.get("restartChild")
    admitted = ([] if restart is None else
                [restart["pid"]] if _restart_child(owner, child, helper, serve, restart) else None)
    require("restartChild" in receipt and admitted is not None
            and receipt["state"] == "signal-submitted" and receipt["pid"] == child.pid
            and receipt["birthFileTimeUtc"] == child.birth and receipt["signalAttempts"] == 1
            and receipt["sessionId"] == owner.request["context"]["ordinarySessionId"]
            and receipt["consolePids"] == sorted([child.pid, helper.pid, *admitted]),
            "owned-console-helper-receipt")
    # The client is the launcher the owner started: it waits for its restart child's JVM to handle
    # the one Ctrl+C, then exits with that child's code, and only then do both pipes reach EOF.
    terminal = _wait_terminal(child, INTERRUPT_SECONDS, "original-stream-interrupt-deadline-retained")
    require(terminal["exitCode"] == 130 and all(terminal["eof"].values()),
            "original-stream-interrupt-must-have-exit130-and-dual-eof")
    owner.event("stream-interrupt-closed", {"child": child.ordinal, "helperChild": helper.ordinal,
        "terminal": terminal, "helperTerminal": helper_terminal, "consoleReceipt": receipt,
        "originalHandleRetained": True, "signalAttempts": 1})
    return terminal


def run(owner, workspace, identity, harness):
    """Six cases only; never claim long-operation or document-response loss."""
    require(owner.request["action"] == "streaming-client-interrupt", "finite-stream-action")
    launcher = Path(owner.request["cliPath"])
    installed = [tree for tree in owner.request["treePins"] if tree["role"] == "installed-app"
                 and launcher.is_relative_to(Path(tree["root"]))]
    require(len(installed) == 1 and launcher.relative_to(Path(installed[0]["root"])).as_posix()
            in installed[0]["files"], "complete-installed-artifact-role-binding")
    launcher_pin = owner.by_path[str(launcher).casefold()].record
    owner.guard()
    owner.event("stream-installed-ordinary-admission", {"installedTreeRoot": installed[0]["root"],
        "launcherPin": launcher_pin, "productVersion": owner.request["productVersion"],
        "ordinaryContext": owner.request["context"], "sourceClosing": True,
        "fullWindowsAcceptance": False})
    serves = [child for child in owner.children if child.label == "serve"]
    require(len(serves) == 1 and _live(serves[0]), "one-retained-original-serve")
    serve = serves[0]
    before = _status(owner, workspace, identity, harness)
    source = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity,
                                               "source", "show"))
    require(source["controllerId"] == identity
            and source["configurationRevision"] == before["configurationRevision"],
            "fresh-source-before-streams")
    if source["data"]["mode"] != "current-locations":
        # A new workspace starts in subscription mode. One guarded selection makes
        # every later log pulse a known no-op at a fixed revision.
        selected = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity,
            "--if-revision", str(before["configurationRevision"]), "source", "set", "current-locations"))
        require(selected["controllerId"] == identity and selected["final"] is True
                and selected["configurationRevision"] == before["configurationRevision"] + 1,
                "fresh-current-locations-selection")
        before = _status(owner, workspace, identity, harness)
        require(before["configurationRevision"] == selected["configurationRevision"],
                "fresh-current-locations-before-streams")
    revision = before["configurationRevision"]
    for json_mode in (True, False):
        for args in STREAMS:
            owner.guard()
            argv = [owner.request["cliPath"], "--state-dir", str(workspace),
                    "--controller-id", identity, *( ["--json"] if json_mode else []), *args]
            child = owner.child("stream-" + args[0] + ("-json" if json_mode else "-human"),
                                argv, new_console=True)
            _wait_ready(child, args, json_mode, identity, revision, workspace, harness)
            terminal = _interrupt(owner, child, serve)
            if json_mode:
                require(_read(child, "stderr") == b"", "json-stream-wrote-stderr")
                records = _records(child, harness, identity, terminal=True)
                require(len(records) >= 2, "json-stream-lost-complete-records")
                if args[0] == "logs":
                    ids = [entry["id"] for row in records for entry in row["data"]["entries"]]
                    require(records[0]["data"]["entries"] == [] and ids
                            and len(ids) == len(set(ids)), "terminal-follow-cursor-duplicate-or-empty")
            else:
                require(_read(child, "stdout") == b"", "human-stream-wrote-stdout")
                require(_read(child, "stderr").endswith(b"\n"), "terminal-human-has-unfinished-record")
            after = _status(owner, workspace, identity, harness)
            require(after["configurationRevision"] == revision
                    and after["restartRequired"] == before["restartRequired"] and _live(serve),
                    "client-interrupt-changed-owner-or-configuration")
            owner.event("stream-case-qualified", {"renderer": "json" if json_mode else "human",
                "command": list(args), "controllerId": identity, "configurationRevision": revision,
                "runtimeRunning": False, "terminal": terminal, "ordinaryContext": owner.request["context"],
                "installedCliPath": owner.request["cliPath"], "sourceClosing": True,
                "membershipContributionOnly": ["windows-native-cli/stdout-stderr-exit",
                    "windows-native-cli/operation-progress-cancellation"],
                "longOperationResponseLossProven": False, "fullWindowsAcceptance": False})
    return 0


def interrupt_owned_console(pid, birth, session, worker_pid, serve_pid, intent):
    """Existing harness helper sequence plus exact-process/console fences.

    GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) reaches this attached console only.
    Its members are the admitted client and this helper, and at most one more: the
    client's own restart child. The installed jpackage launcher re-executes itself
    on Windows with the same image, in the same console, with inherited handles and
    a kill-on-close job; that child runs the JVM, while the client waits for it,
    ignores Ctrl+C and exits with its code. The one extra member is admitted only
    as the client's direct child with the client's full image path and session,
    born after the client, and its handle is held until the signal. Any other
    member refuses, naming every member, and a refusal is never permission to
    signal an unqualified process tree.
    """
    require(os.name == "nt" and type(pid) is int and pid > 0
            and re.fullmatch(r"[1-9][0-9]{0,18}", birth)
            and type(session) is int and session > 0
            and len({pid, worker_pid, serve_pid, os.getpid()}) == 4,
            "exact-console-helper-input")
    intent = Path(intent)
    require(intent.parent == Path.cwd() and intent.name.startswith("child-")
            and intent.name.endswith(".ctrl-c.intent.json"), "owned-console-intent-path")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (W.DWORD, W.BOOL, W.DWORD)
    kernel.OpenProcess.restype = W.HANDLE
    kernel.CloseHandle.argtypes = (W.HANDLE,)
    kernel.GetProcessTimes.argtypes = (W.HANDLE, ctypes.POINTER(W.FILETIME), ctypes.POINTER(W.FILETIME),
                                      ctypes.POINTER(W.FILETIME), ctypes.POINTER(W.FILETIME))
    kernel.WaitForSingleObject.argtypes = (W.HANDLE, W.DWORD)
    kernel.WaitForSingleObject.restype = W.DWORD
    kernel.ProcessIdToSessionId.argtypes = (W.DWORD, ctypes.POINTER(W.DWORD))
    kernel.AttachConsole.argtypes = (W.DWORD,)
    kernel.GetConsoleProcessList.argtypes = (ctypes.POINTER(W.DWORD), W.DWORD)
    kernel.GetConsoleProcessList.restype = W.DWORD
    kernel.SetConsoleCtrlHandler.argtypes = (W.LPVOID, W.BOOL)
    kernel.GenerateConsoleCtrlEvent.argtypes = (W.DWORD, W.DWORD)
    kernel.CreateToolhelp32Snapshot.argtypes = (W.DWORD, W.DWORD)
    kernel.CreateToolhelp32Snapshot.restype = W.HANDLE
    kernel.Process32FirstW.argtypes = (W.HANDLE, ctypes.POINTER(ProcessEntry))
    kernel.Process32NextW.argtypes = (W.HANDLE, ctypes.POINTER(ProcessEntry))
    kernel.QueryFullProcessImageNameW.argtypes = (W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD))
    handle = kernel.OpenProcess(0x100000 | 0x1000, False, pid)
    require(handle, "exact-console-process-open")
    attached, held = False, []
    try:
        def created(process):
            values = [W.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(process, *(ctypes.byref(value) for value in values)):
                return None
            return values[0].dwHighDateTime << 32 | values[0].dwLowDateTime

        def session_of(value):
            actual_session = W.DWORD()
            return actual_session.value if kernel.ProcessIdToSessionId(value, ctypes.byref(actual_session)) else None

        def image(process):
            text, length = ctypes.create_unicode_buffer(32768), W.DWORD(32768)
            if not kernel.QueryFullProcessImageNameW(process, 0, text, ctypes.byref(length)) \
                    or not 0 < length.value < 32768:
                return None
            return text.value

        def current():
            actual_birth = created(handle)
            require(actual_birth is not None, "exact-console-process-times")
            require(str(actual_birth) == birth and kernel.WaitForSingleObject(handle, 0) == 0x102,
                    "exact-console-process-live-birth")
            for candidate in (pid, os.getpid(), worker_pid, serve_pid):
                require(session_of(candidate) == session, "ordinary-console-session")

        def snapshot():
            """pid -> (parent pid, image basename) from one process snapshot."""
            shot = kernel.CreateToolhelp32Snapshot(2, 0)
            require(shot not in (None, 0, ctypes.c_void_p(-1).value), "console-member-snapshot")
            try:
                entry, rows = ProcessEntry(), {}
                entry.size = ctypes.sizeof(ProcessEntry)
                more = kernel.Process32FirstW(shot, ctypes.byref(entry))
                while more:
                    require(len(rows) < 16384, "console-member-snapshot-bound")
                    rows[entry.pid] = (entry.parentPid, entry.name)
                    more = kernel.Process32NextW(shot, ctypes.byref(entry))
                return rows
            finally:
                kernel.CloseHandle(shot)

        def members():
            values = (W.DWORD * 64)()
            count = kernel.GetConsoleProcessList(values, len(values))
            require(0 < count <= len(values), "console-membership-count-bound")
            return sorted(values[:count])

        def named(result):
            """Finite identities of console members for a refusal record; a missing fact stays null."""
            try:
                rows = snapshot()
            except AssertionError:
                rows = {}
            return [{"pid": value, "parentPid": rows.get(value, (None, None))[0],
                     "image": rows.get(value, (None, None))[1], "sessionId": session_of(value)}
                    for value in result]

        def restart_child(candidate):
            """The client's own restart child, or None; its handle keeps its pid naming the same process."""
            process = kernel.OpenProcess(0x100000 | 0x1000, False, candidate)
            if not process:
                return None, None
            held.append(process)
            rows = snapshot()  # Taken after the open, so the row for this pid is the process held.
            parent, name = rows.get(candidate, (None, None))
            creation, path, own = created(process), image(process), image(handle)
            if not (parent == pid and type(name) is str and kernel.WaitForSingleObject(process, 0) == 0x102
                    and creation is not None and creation > int(birth) and session_of(candidate) == session
                    and path is not None and own is not None and path.casefold() == own.casefold()):
                return None, None
            return {"pid": candidate, "parentPid": parent, "image": name, "sessionId": session,
                    "creationFileTime": str(creation)}, process

        def fence():
            result = members()
            owned = sorted([pid, os.getpid()])
            extra = [value for value in result if value not in owned]
            if set(owned) <= set(result) and len(extra) <= 1:
                restart, process = restart_child(extra[0]) if extra else (None, None)
                if not extra or restart is not None:
                    return result, restart, process
            raise ConsoleRefused("only-owned-console-members", named(result))

        current()
        # Preserve caller console: only this separate helper detaches/attaches.
        kernel.FreeConsole()
        require(kernel.AttachConsole(pid), "attach-exact-client-new-console")
        attached = True
        opening, restart, restart_process = fence()
        require(kernel.SetConsoleCtrlHandler(None, True), "helper-ignore-own-ctrl-c")
        current()
        closing = members()
        if closing != opening or restart_process is not None \
                and kernel.WaitForSingleObject(restart_process, 0) != 0x102:
            raise ConsoleRefused("console-membership-closing-changed", named(closing))
        receipt = {"schemaVersion": 1, "state": "intent", "pid": pid,
            "birthFileTimeUtc": birth, "sessionId": session, "consolePids": opening,
            "restartChild": restart, "workerPid": worker_pid, "servePid": serve_pid,
            "signalAttempts": 1, "replayAllowed": False}
        attempted = False
        try:
            # Opening an existing intent raises FileExistsError: this helper then created nothing.
            with intent.open("xb", buffering=0) as output:
                body = _json(receipt)
                require(output.write(body) == len(body), "console-intent-full-write")
                os.fsync(output.fileno())
            # The preserved create-only intent forbids any second signal attempt,
            # even if GenerateConsoleCtrlEvent or the output receipt is uncertain.
            attempted = True
            require(kernel.GenerateConsoleCtrlEvent(0, 0), "owned-console-ctrl-c-submit")
        except AssertionError as failure:
            raise SignalUnknown(str(failure), attempted) from failure
        time.sleep(0.1)
        receipt["state"] = "signal-submitted"
        return receipt
    finally:
        if attached:
            kernel.FreeConsole()
        for process in held:
            kernel.CloseHandle(process)
        kernel.CloseHandle(handle)


def main(arguments):
    require(len(arguments) == 7 and arguments[0] == "--interrupt-owned-console",
            "finite-console-helper-entrypoint")
    try:
        receipt = interrupt_owned_console(int(arguments[1]), arguments[2], int(arguments[3]),
            int(arguments[4]), int(arguments[5]), arguments[6])
    except AssertionError as failure:
        # One finite record in place of a traceback; a console fence also names every member.
        # Before the create-only intent exists a failure is a refusal: no intent and no signal.
        # After it the state is unknown, never refused, and no second attempt is allowed.
        created = isinstance(failure, SignalUnknown)
        sys.stderr.buffer.write(_json({"schemaVersion": 1, "state": "unknown" if created else "refused",
            "reason": str(failure)[:120], "intentCreated": created,
            "signalAttempted": created and failure.signal_attempted,
            "consoleMembers": getattr(failure, "members", None), "replayAllowed": False}))
        sys.stderr.buffer.flush()
        return 1
    sys.stdout.buffer.write(_json(receipt))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
