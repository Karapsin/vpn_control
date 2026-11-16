"""Keep the original private agent runner and lease through timeout cleanup.

The caller retains its managed lease until this function returns. A cleanup
deadline changes the recorded outcome, never ownership of a live coordinator.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time


WORK_SECONDS = 3000
CLEANUP_SECONDS = 10
OBSERVATION_SECONDS = 1


def is_private_command(root: Path, command: list[str]) -> bool:
    """Recognize only the POSIX plan/report argv produced by prepare_run."""
    if os.name != "posix" or len(command) != 6:
        return False
    root = Path(root).resolve()
    parent = root / ".rag_index" / "agent-test-runs"
    plan, report = Path(command[3]), Path(command[5])
    return (command[1] == str(root / "agent_tools/agent_test_runner.py")
            and command[2] == "--plan-file" and command[4] == "--report-dir"
            and plan.parent == parent and report.parent == parent
            and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", report.name) is not None
            and plan.name == report.name + ".plan.json")


@dataclass(frozen=True)
class Outcome:
    completed: subprocess.CompletedProcess
    timed_out: bool
    cleanup_budget_exceeded: bool
    termination_requested: bool
    termination_error: str | None

    def metadata(self) -> dict:
        return {"timedOut": self.timed_out,
                "cleanupBudgetExceeded": self.cleanup_budget_exceeded,
                "terminationRequested": self.termination_requested,
                "terminationError": self.termination_error,
                "streamEof": {"stdout": True, "stderr": True},
                "returnCode": self.completed.returncode}


def run(command: list[str], *, cwd: Path, env: dict[str, str],
        timeout: float = WORK_SECONDS, cleanup_seconds: float = CLEANUP_SECONDS) -> Outcome:
    """Request existing runner cancellation once, then observe original closure.

    This is deliberately POSIX-only: Windows terminate does not invoke the
    runner's SIGTERM handler. Work stays bounded at 3,000 seconds. If the
    separate cleanup observation window expires, the same call and managed
    lease stay pending; repeated observations introduce no further effects.
    communicate completing is the positive proof of both pipe EOFs and exit.
    """
    if os.name != "posix":
        raise ValueError("Private runner cancellation requires POSIX")
    for value, limit in ((timeout, WORK_SECONDS), (cleanup_seconds, CLEANUP_SECONDS)):
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= limit:
            raise ValueError("Invalid private runner deadline")
    timed_out = cleanup_exceeded = termination_requested = False
    termination_error = None
    # A check child never inherits the server's stdio transport or terminal.
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + timeout
    phase = "work"
    interruption = None
    while True:
        remaining = (OBSERVATION_SECONDS if phase == "pending"
                     else max(0, deadline - time.monotonic()))
        try:
            stdout, stderr = process.communicate(timeout=remaining)
            break
        except KeyboardInterrupt as error:
            if interruption is None:
                interruption = error
            continue  # Same original child, pipes, lease, and work deadline.
        except subprocess.TimeoutExpired:
            if phase == "work":
                timed_out = True
                phase = "cleanup"
                deadline = time.monotonic() + cleanup_seconds
                termination_requested = True
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                except KeyboardInterrupt as error:
                    if interruption is None:
                        interruption = error
                except OSError as error:
                    termination_error = type(error).__name__
            elif phase == "cleanup":
                cleanup_exceeded = True
                phase = "pending"
    completed = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    # communicate completed: both original streams reached EOF and child reaped.
    process.stdout.close()
    process.stderr.close()
    outcome = Outcome(completed, timed_out, cleanup_exceeded,
                      termination_requested, termination_error)
    if interruption is not None:
        interruption.managed_agent_outcome = outcome
        raise interruption
    return outcome


BACKGROUND_ESCAPE_DISABLE = "VPN_CONTROL_LAUNCHD_ESCAPE"
BACKGROUND_ESCAPE_MARKER = "VPN_CONTROL_LAUNCHD_ESCAPED"


# Opt-in: besides the private agent runner, only these CPU-bound local checks, each
# pure Python with no subprocess, network, Gradle, SSH, guest, VM or release effect.
# Native, guest, SSH, VM and release actions, scripts/visual_review.py (it posts
# GitHub statuses), the SSH keeper child, git/gh and Gradle always run directly.
BACKGROUND_ESCAPE_PYTHON_SCRIPTS = frozenset({
    "scripts/check_ui_theme.py",
    "scripts/test_visual_regression.py",
})
BACKGROUND_ESCAPE_COMMANDS = frozenset({
    ("./scripts/check_localization.py",),
    ("./scripts/status_catalog_tool.py", "check"),
})


def background_escape_eligible(root: Path, command, python=None) -> bool:
    """Only the private agent-runner argv and the named local checks above."""
    command = [str(part) for part in command]
    if is_private_command(root, command):
        return True
    return ((len(command) == 2 and command[0] == (python or sys.executable)
             and command[1] in BACKGROUND_ESCAPE_PYTHON_SCRIPTS)
            or tuple(command) in BACKGROUND_ESCAPE_COMMANDS)


def background_escape(command, *, root=None, bound=None, platform=None, environ=None, which=None, python=None,
                      relay=None):
    """Prefix an opted-in check with the launchd relay on macOS; any other command is unchanged.

    The agent-session tmux tree runs at Darwin background priority and children
    inherit it (agent tests ran 5-7x slower). Only a launchd-parented job escapes
    without sudo. The selection is the argv itself (background_escape_eligible),
    never the caller's timeout. VPN_CONTROL_LAUNCHD_ESCAPE=0 disables it; a missing
    relay file or launchctl keeps the command unchanged. `bound` (seconds) lets a
    later relay sweep a job whose relay vanished.
    """
    import shutil
    environ = os.environ if environ is None else environ
    platform = sys.platform if platform is None else platform
    which = shutil.which if which is None else which
    root = Path(__file__).resolve().parents[1] if root is None else Path(root)
    relay = Path(__file__).resolve().with_name("launchd_escape.py") if relay is None else Path(relay)
    if (platform != "darwin" or environ.get(BACKGROUND_ESCAPE_DISABLE) == "0"
            or environ.get(BACKGROUND_ESCAPE_MARKER) or which("launchctl") is None
            or not background_escape_eligible(root, command, python) or not relay.is_file()):
        return list(command)
    bounded = ["--bound", str(max(1, math.ceil(bound)))] if bound is not None else []
    return [python or sys.executable, str(relay), "relay", *bounded, "--", *command]
