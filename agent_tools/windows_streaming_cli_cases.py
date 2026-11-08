"""Finite installed-Windows stream cases, using the retained ordinary owner.

Private preparation only. A native DIRECT run and matched current-MCP run are
required. Import performs no native, filesystem, network, or product action.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import re
import sys
import time


STREAMS = (("status", "--watch"), ("stats", "--watch"),
           ("logs", "--follow", "--limit", "0"))
READ_LIMIT = 1024 * 1024
READ_SECONDS = 40
INTERRUPT_SECONDS = 15


def require(value, reason):
    if not value:
        raise AssertionError(reason)


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
    require(receipt["state"] == "signal-submitted" and receipt["pid"] == child.pid
            and receipt["birthFileTimeUtc"] == child.birth and receipt["signalAttempts"] == 1
            and receipt["sessionId"] == owner.request["context"]["ordinarySessionId"]
            and receipt["consolePids"] == sorted([child.pid, helper.pid]),
            "owned-console-helper-receipt")
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
    Strictly two members are allowed: the admitted client and this helper. A
    launcher spawning another console member is a native refusal to investigate,
    never permission to signal an unqualified process tree.
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
    handle = kernel.OpenProcess(0x100000 | 0x1000, False, pid)
    require(handle, "exact-console-process-open")
    attached = False
    try:
        def current():
            values = [W.FILETIME() for _ in range(4)]
            require(kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)),
                    "exact-console-process-times")
            actual_birth = str(values[0].dwHighDateTime << 32 | values[0].dwLowDateTime)
            require(actual_birth == birth and kernel.WaitForSingleObject(handle, 0) == 0x102,
                    "exact-console-process-live-birth")
            for candidate in (pid, os.getpid(), worker_pid, serve_pid):
                actual_session = W.DWORD()
                require(kernel.ProcessIdToSessionId(candidate, ctypes.byref(actual_session))
                        and actual_session.value == session, "ordinary-console-session")

        def members():
            values = (W.DWORD * 64)()
            count = kernel.GetConsoleProcessList(values, len(values))
            require(0 < count <= len(values), "console-membership-count-bound")
            result = sorted(values[:count])
            require(result == sorted([pid, os.getpid()]), "only-two-owned-console-members")
            return result

        current()
        # Preserve caller console: only this separate helper detaches/attaches.
        kernel.FreeConsole()
        require(kernel.AttachConsole(pid), "attach-exact-client-new-console")
        attached = True
        opening = members()
        require(kernel.SetConsoleCtrlHandler(None, True), "helper-ignore-own-ctrl-c")
        current()
        require(members() == opening, "console-membership-closing-changed")
        receipt = {"schemaVersion": 1, "state": "intent", "pid": pid,
            "birthFileTimeUtc": birth, "sessionId": session, "consolePids": opening,
            "workerPid": worker_pid, "servePid": serve_pid, "signalAttempts": 1,
            "replayAllowed": False}
        with intent.open("xb", buffering=0) as output:
            body = _json(receipt)
            require(output.write(body) == len(body), "console-intent-full-write")
            os.fsync(output.fileno())
        # The preserved create-only intent forbids any second signal attempt,
        # even if GenerateConsoleCtrlEvent or the output receipt is uncertain.
        require(kernel.GenerateConsoleCtrlEvent(0, 0), "owned-console-ctrl-c-submit")
        time.sleep(0.1)
        receipt["state"] = "signal-submitted"
        return receipt
    finally:
        if attached:
            kernel.FreeConsole()
        kernel.CloseHandle(handle)


def main(arguments):
    require(len(arguments) == 7 and arguments[0] == "--interrupt-owned-console",
            "finite-console-helper-entrypoint")
    receipt = interrupt_owned_console(int(arguments[1]), arguments[2], int(arguments[3]),
        int(arguments[4]), int(arguments[5]), arguments[6])
    sys.stdout.buffer.write(_json(receipt))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
