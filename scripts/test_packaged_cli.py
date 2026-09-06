#!/usr/bin/env python3
"""Disconnected CLI smoke using a native package's public launcher, not MainKt.

Never connects, installs, changes autostart, or reads the user's workspace.
Only processes created here against new temporary workspaces are terminated.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def envelope(result, expected_exit=0, expected_code="OK"):
    require(result.returncode == expected_exit,
            f"CLI exit {result.returncode}, expected {expected_exit}; stderr={result.stderr!r}")
    require(not result.stderr.strip(), f"Unexpected CLI stderr: {result.stderr!r}")
    data = json.loads(result.stdout)
    require(isinstance(data, dict) and data.get("schemaVersion") == 1, "Invalid result envelope")
    require(data.get("code") == expected_code, f"Unexpected result code: {data.get('code')}")
    require(data.get("ok") == (expected_exit == 0), "Result success disagrees with exit code")
    return data


def stream_records(path, maximum_bytes=1024 * 1024):
    """Bound both memory and fixture output; ignore only an unfinished final line."""
    with path.open("rb") as source:
        content = source.read(maximum_bytes + 1)
    require(len(content) <= maximum_bytes, "Native stream exceeded the fixture output bound")
    return [json.loads(line.decode("utf-8", errors="strict"))
            for line in content.split(b"\n")[:-1]]


def verify_stream_records(records, identity):
    for row in records:
        require(row.get("schemaVersion") == 1 and row.get("code") == "OK" and row.get("ok") is True
                and row.get("final") is False and row.get("controllerId") == identity,
                "Stream lost its success, completion, or pinned-owner metadata")


def interrupt_test_console(pid):
    """Private subprocess entry point: attach only to a test-owned NEW console.

    The calling test retains its original console/stdio. This short-lived helper
    has no console of its own and never broadcasts to the owner's console.
    """
    if os.name != "nt" or pid <= 0:
        return 2
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # Some Windows launch contexts still attach a console despite NO_WINDOW.
    # Detach this helper only; never change the caller's console or handles.
    kernel.FreeConsole()
    if not kernel.AttachConsole(pid):
        return 1000 + ctypes.get_last_error()
    try:
        if not kernel.SetConsoleCtrlHandler(None, True):
            return 4
        # Group zero means THIS attached console, created solely for the stream.
        if not kernel.GenerateConsoleCtrlEvent(0, 0):
            return 5
        time.sleep(0.1)
        return 0
    finally:
        kernel.FreeConsole()


def interrupt_stream(process):
    require(process.poll() is None, "Stream exited before Ctrl-C")
    if os.name == "nt":
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--interrupt-test-console", str(process.pid)],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        require(result.returncode == 0, f"Test-console interrupt helper failed: {result.returncode}")
    else:
        process.send_signal(signal.SIGINT)
    require(process.wait(timeout=10) == 130, "Ctrl-C must stop only the stream with exit 130")


def streaming_and_qr_smoke(launcher, workspace, root, identity, invoke, environment):
    def read(*args):
        return envelope(invoke(workspace, "--json", *args))

    def wait_records(path, count, process):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            records = stream_records(path)
            if len(records) >= count:
                verify_stream_records(records, identity)
                return records
            require(process.poll() is None, "Native stream exited before producing snapshots")
            time.sleep(0.05)
        raise AssertionError("Native stream did not produce the expected NDJSON records")

    for index, args in enumerate((("status", "--watch"), ("stats", "--watch"),
                                   ("logs", "--follow", "--limit", "0"))):
        output, error = root / f"stream-{index}.out", root / f"stream-{index}.err"
        with output.open("wb") as stdout, error.open("wb") as stderr:
            process = subprocess.Popen(
                [str(launcher), "--state-dir", str(workspace), "--json", *args],
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=environment,
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0,
            )
            try:
                first = wait_records(output, 1, process)
                if index == 2:
                    require(not first[0]["data"]["entries"], "Follow --limit 0 replayed history")
                    # A genuine disconnected owner action produces a cursor entry.
                    read("source", "set", "current-locations")
                records = wait_records(output, 2, process)
                if index == 2:
                    ids = [entry["id"] for row in records for entry in row["data"]["entries"]]
                    require(ids and len(ids) == len(set(ids)), "Follow lost or duplicated cursor entries")
                interrupt_stream(process)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
        require(not error.read_bytes(), "JSON stream wrote stderr")
        status = read("status")
        require(status["controllerId"] == identity and status["data"]["runtimeRunning"] is False,
                "Stream cancellation stopped/replaced the owner or started a runtime")

    payload, png = root / "東京 QR input.txt", root / "東京 QR output.png"
    payload.write_text("socks://127.0.0.1:1080#PackagedQR", encoding="utf-8")
    read("locations", "add", "--input", str(payload))
    exported = read("locations", "export", "--format", "qr-png", "--output", str(png))
    require(png.read_bytes().startswith(b"\x89PNG\r\n\x1a\n") and "content" not in exported["data"],
            "QR export did not produce a PNG or echoed exported content")
    read("locations", "delete", "PackagedQR")
    read("locations", "import", "--qr-image", str(png))
    require("PackagedQR" in json.dumps(read("locations", "list")["data"]), "QR import lost the location")


def smoke(launcher, expected_version):
    launcher = Path(launcher).resolve(strict=True)
    require(launcher.is_file(), "Launcher must be a file")
    environment = dict(os.environ)
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"):
        environment.pop(name, None)
    with tempfile.TemporaryDirectory(prefix="vpn-control-cli-") as temporary:
        root = Path(temporary)
        first, second = root / "東京 first workspace", root / "second space workspace"
        owners = []
        logs = []

        def invoke(workspace, *args):
            return subprocess.run([str(launcher), "--state-dir", str(workspace), *args],
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  encoding="utf-8", errors="strict", timeout=30, env=environment)

        try:
            help_result = invoke(first, "--help")
            require(help_result.returncode == 0 and "Usage:" in help_result.stdout and
                    not help_result.stderr.strip(), "Help must exit 0 and use stdout")
            version = invoke(first, "--version")
            require(version.returncode == 0 and expected_version in version.stdout and
                    not version.stderr.strip(), "Version must report the packaged product on stdout")
            envelope(invoke(first, "--json", "capabilities"))
            envelope(invoke(first, "--json", "settings", "show", "--typo"), 1, "INVALID_ARGUMENT")
            envelope(invoke(first, "--json", "status"), 2, "UNAVAILABLE")
            require(not first.exists(), "Local/help/invalid/unavailable reads created a workspace")

            identities = []
            for workspace in (first, second):
                log = (root / f"serve-{len(owners)}.log").open("wb")
                logs.append(log)
                owner = subprocess.Popen([str(launcher), "--state-dir", str(workspace), "serve"],
                                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=environment)
                owners.append(owner)
                deadline = time.monotonic() + 30
                while owner.poll() is None and not (workspace / "activation.port").exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                require(owner.poll() is None and (workspace / "activation.port").exists(), "Serve did not become ready")
                status = envelope(invoke(workspace, "--json", "status"))
                require(status["data"]["runtimeRunning"] is False, "Fresh owner unexpectedly connected")
                require(bool(status["controllerId"]), "Owner identity is missing")
                identities.append(status["controllerId"])
            require(identities[0] != identities[1], "Workspaces share an owner")

            baseline = envelope(invoke(second, "--json", "settings", "show", "validation.batch-size"))
            saved = envelope(invoke(first, "--json", "settings", "set", "validation.batch-size", "7"))
            require(saved["configurationRevision"] == 1, "Save did not advance configuration revision")
            read = envelope(invoke(first, "--json", "settings", "show", "validation.batch-size"))
            require(read["data"]["validation.batch-size"] == 7, "Saved setting did not round trip")
            isolated = envelope(invoke(second, "--json", "settings", "show", "validation.batch-size"))
            require(isolated["data"] == baseline["data"] and isolated["configurationRevision"] == 0,
                    "Settings crossed workspace boundaries")
            settings_file = root / "設定 input.json"
            settings_file.write_text('{"validation.batch-size":8}', encoding="utf-8")
            applied = envelope(invoke(first, "--json", "settings", "apply", "--input", str(settings_file)))
            require(applied["configurationRevision"] == 2, "File input did not commit")
            for args in (("stats",), ("logs", "--limit", "0"), ("source", "show"),
                         ("settings", "languages"), ("locations", "list"), ("subscriptions", "list"),
                         ("routing", "show"), ("ssh", "key", "status"), ("updates", "status")):
                read = envelope(invoke(first, "--json", *args))
                require(read["controllerId"] == identities[0] and read["configurationRevision"] == 2
                        and read["final"] is True, "Read lost owner/revision/completion metadata")
            envelope(invoke(first, "--json", "settings", "show", "missing"), 1, "NOT_FOUND")
            # No update manifest has been checked: this fails locally, without a download or installer.
            submitted = invoke(first, "--json", "--async", "updates", "download")
            operation = json.loads(submitted.stdout)
            require(operation.get("code") in ("ACCEPTED", "NOT_FOUND", "RUNTIME_FAILED"),
                    "Unexpected no-manifest update operation result")
            envelope(submitted, 0 if operation["code"] == "ACCEPTED" else 1, operation["code"])
            operation_id = operation.get("operationId")
            require(bool(operation_id), "Async operation identity is missing")
            waited = invoke(first, "--json", "operations", "wait", operation_id)
            terminal = json.loads(waited.stdout)
            require(terminal.get("code") in ("NOT_FOUND", "RUNTIME_FAILED"), "Missing manifest must fail")
            envelope(waited, 1, terminal["code"])
            require(terminal["final"] is True, "Operation wait returned before completion")
            envelope(invoke(first, "--json", "operations", "status", operation_id))
            streaming_and_qr_smoke(launcher, first, root, identities[0], invoke, environment)
            for workspace, owner in zip((first, second), owners):
                status = envelope(invoke(workspace, "--json", "status"))
                require(status["data"]["runtimeRunning"] is False and owner.poll() is None,
                        "Disconnected serve must remain alive without a runtime")
                require((workspace / "workspace.json").is_file(), "Configuration was not persisted")
        finally:
            for owner in owners:
                if owner.poll() is None:
                    owner.terminate()
                    try:
                        owner.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        owner.kill()
                        owner.wait(timeout=10)
            for log in logs:
                log.close()
            if os.name == "nt":
                # Windows may briefly retain process/log handles after wait().
                time.sleep(0.5)
    print("[vpn-control] native public CLI disconnected smoke passed")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--interrupt-test-console":
        # Detaching the helper console invalidates its standard handles. Avoid
        # Python's exit-time flush; the parent checks this bounded exit code.
        os._exit(interrupt_test_console(int(sys.argv[2])))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", required=True)
    parser.add_argument("--expected-version", required=True)
    arguments = parser.parse_args()
    smoke(arguments.launcher, arguments.expected_version)
