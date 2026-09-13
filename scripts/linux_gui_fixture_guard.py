"""Reject GUI fixture observations that cannot prove a fresh live frontend."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def require_fresh_gui_frontend(*, frontend_pid, frontend_alive, window_pids, crash_reports):
    """Return the owned window PID or fail before any lifecycle traffic probe."""
    if not frontend_alive:
        raise RuntimeError("GUI fixture frontend exited before lifecycle probe")
    if crash_reports:
        raise RuntimeError("GUI fixture frontend produced a JVM crash report")
    if frontend_pid not in set(window_pids):
        raise RuntimeError("GUI fixture has no window owned by the fresh frontend")
    return frontend_pid


def proc_starttime(pid, read_text=Path.read_text):
    """Read field 22 safely even when /proc comm includes spaces or parentheses."""
    stat = read_text(Path(f"/proc/{pid}/stat"))
    try:
        _comm, tail = stat.rsplit(") ", 1)
        fields = tail.split()
        if fields[0] == "Z":
            raise RuntimeError("GUI fixture frontend is a zombie")
        return fields[19]  # field 22; tail starts at field 3 (state)
    except (IndexError, ValueError) as error:
        raise RuntimeError("GUI fixture frontend has unreadable /proc stat") from error


def collect_window_pids(run=subprocess.run):
    """Use the root client list, then authoritative _NET_WM_PID ownership."""
    try:
        clients = run(["xprop", "-root", "_NET_CLIENT_LIST"], text=True,
                      capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("GUI fixture cannot execute xprop for X11 client list") from error
    if clients.returncode != 0:
        raise RuntimeError("GUI fixture cannot read X11 client list")
    mapping = {}
    for window in re.findall(r"0x[0-9a-fA-F]+", clients.stdout):
        try:
            owner = run(["xprop", "-id", window, "_NET_WM_PID"], text=True,
                        capture_output=True, check=False, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("GUI fixture cannot inspect X11 window ownership") from error
        match = re.search(r"=\s*(\d+)", owner.stdout)
        if owner.returncode == 0 and match:
            mapping[int(window, 16)] = int(match.group(1))
    return mapping


def graceful_close(window_id, run=subprocess.run):
    """Request a normal WM close; never destroy the X window or kill its client."""
    if not isinstance(window_id, int) or isinstance(window_id, bool) or window_id <= 0:
        raise ValueError("GUI fixture window ID must be a positive integer")
    try:
        result = run(["xdotool", "windowquit", str(window_id)], text=True,
                     capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("GUI fixture cannot request graceful window close") from error
    if result.returncode != 0:
        raise RuntimeError("GUI fixture graceful window close was rejected")


def require_mutable_fixture_source(source_id):
    if source_id != "current-locations":
        raise RuntimeError("GUI fixture requires source current-locations before mutations")


def observe(*, expected_pid, expected_starttime, baseline_windows, proc_starttime, proc_alive,
            window_pid, crash_reports):
    if not proc_alive(expected_pid) or proc_starttime(expected_pid) != expected_starttime:
        raise RuntimeError("GUI fixture frontend exited or PID was reused")
    fresh = [window for window in window_pid if window not in baseline_windows and window_pid[window] == expected_pid]
    require_fresh_gui_frontend(frontend_pid=expected_pid, frontend_alive=True,
                               window_pids=[window_pid[window] for window in fresh], crash_reports=crash_reports)
    return {"frontendPid": expected_pid, "frontendStarttime": expected_starttime, "freshWindows": fresh,
            "crashReports": crash_reports, "ok": True}


def write_failure_receipt(path, error, mapping, reports):
    path.write_text(json.dumps({"ok": False, "error": str(error), "windowPids": mapping,
                                "crashReports": reports}, sort_keys=True) + "\n")


def positive_pid(value):
    pid = int(value)
    if pid <= 0:
        raise argparse.ArgumentTypeError("expected PID must be positive")
    return pid


def main(argv=None, collect=collect_window_pids, start=proc_starttime, alive=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-pid", type=positive_pid, required=True)
    parser.add_argument("--expected-proc-starttime", required=True)
    parser.add_argument("--baseline-window-id", type=int, action="append", default=[])
    parser.add_argument("--crash-report", type=Path, action="append", default=[])
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    mapping = {}
    reports = [str(path) for path in args.crash_report if path.exists()]
    try:
        mapping = collect()
        receipt = observe(expected_pid=args.expected_pid, expected_starttime=args.expected_proc_starttime,
                          baseline_windows=args.baseline_window_id, proc_starttime=start,
                          proc_alive=alive or (lambda pid: Path(f"/proc/{pid}").is_dir()),
                          window_pid=mapping, crash_reports=reports)
    except (RuntimeError, OSError) as error:
        write_failure_receipt(args.receipt, error, mapping, reports)
        print(error, file=sys.stderr)
        return 1
    args.receipt.write_text(json.dumps(receipt, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
