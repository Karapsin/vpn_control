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
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
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
