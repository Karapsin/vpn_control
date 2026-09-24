"""Read-only, durable observation of existing jobs on configured SSH hosts.

This module deliberately has no facility for starting, retrying, signalling, or
otherwise changing a remote job.  A live PID is accepted only when its Linux
``/proc`` start tick matches the identity recorded by the caller; this prevents
PID reuse from becoming a false completion or false liveness result.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path
import re
import select
import subprocess
import time
from typing import Any, Mapping

try:  # Supports both package imports and the standalone MCP CLI loader.
    from . import ssh_transport
except ImportError:  # pragma: no cover - exercised by direct module tests
    import ssh_transport


MAX_OUTPUT_BYTES = 4_096
_JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_REMOTE_PATH = re.compile(r"^/[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")

# This program is passed as one fixed Python argument; no caller-controlled
# expression is ever evaluated remotely.  It returns a narrow JSON envelope,
# never receipt contents, command output, or environment values.
_REMOTE_PROBE = r'''import json,os,stat,sys
pid=int(sys.argv[1]); receipt_path=sys.argv[2]
process={"state":"missing"}
try:
    stat=open("/proc/%d/stat" % pid,"r",encoding="ascii").read()
    tail=stat.rsplit(")",1)[1].split()
    process={"state":"zombie" if tail[0]=="Z" else "running","startTicks":int(tail[19])}
except (OSError,IndexError,ValueError,UnicodeError): pass
receipt={"present":False,"valid":True}
if receipt_path:
    try:
        fd=os.open(receipt_path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0))
        if not stat.S_ISREG(os.fstat(fd).st_mode): raise OSError("receipt is not regular")
        with os.fdopen(fd,"rb") as f: raw=f.read(16385)
        if len(raw)<=16384:
            value=json.loads(raw.decode("utf-8"))
            if isinstance(value,dict):
                receipt={"present":True,"valid":True,"jobId":value.get("jobId"),"exitCode":value.get("exitCode")}
            else: receipt={"present":True,"valid":False}
        else: receipt={"present":True,"valid":False}
    except FileNotFoundError: pass
    except (OSError,ValueError,UnicodeError,json.JSONDecodeError): receipt={"present":True,"valid":False}
print(json.dumps({"process":process,"receipt":receipt},separators=(",",":")))'''
# ``ssh_transport`` rejects control characters in command arguments.  Keeping
# the executable program as a one-line ``exec`` argument also makes the
# command boundary explicit to OpenSSH's remote-command text protocol.
_REMOTE_PROBE_ARGUMENT = "exec(" + repr(_REMOTE_PROBE) + ")"


class SshJobError(ValueError):
    """A caller supplied an unsafe or incomplete job identity."""


class ProbeTimeout(Exception):
    """The remote observer did not complete within its bounded SSH timeout."""


class ProbeFailure(Exception):
    """A bounded observer failure that still yields an unknown observation."""

    def __init__(self, reason: str):
        self.reason = reason


class JobStatus(str, Enum):
    RUNNING = "running"
    TERMINAL = "terminal"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class JobIdentity:
    job_id: str
    pid: int
    start_ticks: int
    receipt_path: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "JobIdentity":
        if not isinstance(value, Mapping) or set(value) - {"jobId", "pid", "startTicks", "receiptPath"} or {"jobId", "pid", "startTicks"} - set(value):
            raise SshJobError("Job identity has unsupported or missing fields.")
        job_id = value["jobId"]
        if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
            raise SshJobError("Job identity jobId is invalid.")
        pid, start_ticks = value["pid"], value["startTicks"]
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1:
            raise SshJobError("Job identity pid is invalid.")
        if isinstance(start_ticks, bool) or not isinstance(start_ticks, int) or start_ticks < 1:
            raise SshJobError("Job identity startTicks is invalid.")
        receipt_path = value.get("receiptPath")
        if receipt_path is not None and (not isinstance(receipt_path, str) or not _REMOTE_PATH.fullmatch(receipt_path)):
            raise SshJobError("Job identity receipt path is invalid.")
        return cls(job_id=job_id, pid=pid, start_ticks=start_ticks, receipt_path=receipt_path)

    def as_dict(self) -> dict[str, int | str]:
        return {"jobId": self.job_id, "pid": self.pid, "startTicks": self.start_ticks}


@dataclass(frozen=True)
class JobObservation:
    host: str
    identity: JobIdentity
    status: JobStatus
    reason: str
    exit_code: int | None = None

    @property
    def pid(self) -> int:
        return self.identity.pid

    @property
    def start_ticks(self) -> int:
        return self.identity.start_ticks

    @property
    def ok(self) -> bool:
        return self.status is not JobStatus.UNKNOWN

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"host": self.host, "identity": self.identity.as_dict(), "status": self.status.value,
                                  "reason": self.reason, "ok": self.ok}
        if self.exit_code is not None:
            result["exitCode"] = self.exit_code
        return result


def _run_probe(argv: list[str], timeout_seconds: int) -> tuple[int, bytes]:
    """Run one SSH observer while retaining at most ``MAX_OUTPUT_BYTES``."""
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL)
    except OSError as exc:
        raise ProbeFailure("ssh_unavailable") from exc
    assert process.stdout is not None
    chunks: list[bytes] = []
    received = 0
    deadline = time.monotonic() + timeout_seconds + 1
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeTimeout()
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if ready:
                chunk = os.read(process.stdout.fileno(), min(1024, MAX_OUTPUT_BYTES + 1 - received))
                if chunk:
                    chunks.append(chunk)
                    received += len(chunk)
                    if received > MAX_OUTPUT_BYTES:
                        raise ProbeFailure("oversized_probe_output")
                    continue
                if process.poll() is not None:
                    return process.returncode, b"".join(chunks)
            if process.poll() is not None and not ready:
                # A descendant may still own stdout.  Keep using select until
                # EOF or the deadline; never perform an unbounded final read.
                continue
    except (OSError, ValueError) as exc:
        process.kill()
        process.wait()
        raise ProbeFailure("observer_io_failed") from exc
    except (ProbeTimeout, ProbeFailure):
        process.kill()
        process.wait()
        raise
    finally:
        process.stdout.close()


def _observation_from_output(host: str, identity: JobIdentity, returncode: int, output: bytes) -> JobObservation:
    if returncode == 130:
        return JobObservation(host, identity, JobStatus.UNKNOWN, "observer_cancelled")
    if returncode != 0:
        return JobObservation(host, identity, JobStatus.UNKNOWN, "remote_probe_failed")
    try:
        value = json.loads(output.decode("utf-8"))
        process = value["process"]
        receipt = value["receipt"]
        if not isinstance(process, dict) or not isinstance(receipt, dict):
            raise ValueError
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return JobObservation(host, identity, JobStatus.UNKNOWN, "malformed_probe_output")
    receipt_job = receipt.get("jobId")
    receipt_exit = receipt.get("exitCode")
    if receipt.get("present") is True and receipt.get("valid") is True and receipt_job == identity.job_id and isinstance(receipt_exit, int) and not isinstance(receipt_exit, bool):
        return JobObservation(host, identity, JobStatus.TERMINAL, "correlated_receipt", receipt_exit)
    state = process.get("state")
    if state == "running":
        observed_ticks = process.get("startTicks")
        if isinstance(observed_ticks, int) and not isinstance(observed_ticks, bool) and observed_ticks == identity.start_ticks:
            return JobObservation(host, identity, JobStatus.RUNNING, "live_pid")
        return JobObservation(host, identity, JobStatus.UNKNOWN, "pid_reused")
    if state == "zombie":
        return JobObservation(host, identity, JobStatus.UNKNOWN, "zombie")
    if state == "missing":
        if receipt.get("present") is True and receipt.get("valid") is not True:
            return JobObservation(host, identity, JobStatus.UNKNOWN, "invalid_receipt")
        if receipt.get("present") is True and receipt_job != identity.job_id:
            return JobObservation(host, identity, JobStatus.UNKNOWN, "receipt_job_mismatch")
        if receipt.get("present") is True:
            return JobObservation(host, identity, JobStatus.UNKNOWN, "invalid_receipt")
        return JobObservation(host, identity, JobStatus.UNKNOWN, "process_missing")
    return JobObservation(host, identity, JobStatus.UNKNOWN, "malformed_probe_output")


def observe(root: Path | str, host: str, identity: Mapping[str, Any], timeout_seconds: int = ssh_transport.DEFAULT_TIMEOUT_SECONDS,
            ssh_binary: str = "ssh") -> JobObservation:
    """Observe an existing job once, preserving unknown outcomes without retrying."""
    job = JobIdentity.from_mapping(identity)
    config = ssh_transport.load_config(root)
    if host not in config.hosts:
        raise SshJobError("Unknown VM host alias.")
    target = config.hosts[host]
    connection_host = config.hosts[target.gateway] if target.transport == "nested" else target
    if connection_host.password is not None:
        raise SshJobError("SSH job observation requires a key or agent profile.")
    argv = ssh_transport.build_ssh_argv(
        config, host, timeout_seconds,
        command=("python3", "-c", _REMOTE_PROBE_ARGUMENT, str(job.pid), job.receipt_path or "-"), ssh_binary=ssh_binary)
    try:
        returncode, output = _run_probe(argv, timeout_seconds)
        observation = _observation_from_output(host, job, returncode, output)
    except ProbeTimeout:
        observation = JobObservation(host, job, JobStatus.UNKNOWN, "timeout")
    except ProbeFailure as error:
        observation = JobObservation(host, job, JobStatus.UNKNOWN, error.reason)
    return observation
