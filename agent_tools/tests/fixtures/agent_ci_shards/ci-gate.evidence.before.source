"""Public, bounded evidence for explicitly sharded CI; never a managed receipt.

Only the caller's newly allocated runner directory is inspected. Private output,
reasons, paths and source contents are never copied into the public projection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


MODULE = re.compile(r"agent_tools\.tests\.test_[A-Za-z0-9_]+\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40,64}\Z")
OUTCOMES = {"incomplete", "success", "failure", "error", "skipped", "expectedFailure", "unexpectedSuccess"}
COUNTS = ("testsRun", "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses")
MAX_JSON = 8 * 1024 * 1024
MAX_LINE = 16384
MAX_EVENTS = 200000
# Hosted Fast Checks agent shard jobs; affected_agent_tests.CI_SHARD_COUNT.
SHARD_COUNT = 6


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def plan_value(*, baseline, head, fingerprint, modules, index, run_id="local", attempt="1"):
    if (type(index) is not int or not 0 <= index < SHARD_COUNT or not COMMIT.fullmatch(baseline)
            or not COMMIT.fullmatch(head) or not HEX.fullmatch(fingerprint)
            or len(modules) > 2000 or modules != sorted(set(modules))
            or any(not isinstance(name, str) or not MODULE.fullmatch(name) for name in modules)
            or not isinstance(run_id, str) or not re.fullmatch(r"local|[1-9][0-9]{0,19}", run_id)
            or not isinstance(attempt, str) or not re.fullmatch(r"[1-9][0-9]{0,5}", attempt)):
        raise ValueError("Invalid public shard plan")
    global_plan = {"baseline": baseline, "head": head, "sourceFingerprint": fingerprint, "modules": modules,
                   "runId": run_id, "runAttempt": attempt}
    return {"schemaVersion": 1, **global_plan, "globalDigest": hashlib.sha256(canonical(global_plan)).hexdigest(),
            "shardIndex": index, "shardCount": SHARD_COUNT, "assignedModules": modules[index::SHARD_COUNT]}


def validate_plan(value):
    if (not isinstance(value, dict) or type(value.get("schemaVersion")) is not int or value.get("schemaVersion") != 1
            or type(value.get("shardCount")) is not int or value.get("shardCount") != SHARD_COUNT):
        raise ValueError("Invalid public shard schema")
    expected = plan_value(baseline=value["baseline"], head=value["head"], fingerprint=value["sourceFingerprint"],
                          modules=value["modules"], index=value["shardIndex"], run_id=value["runId"], attempt=value["runAttempt"])
    if value != expected:
        raise ValueError("Public shard plan mismatch")
    return expected


def read_json(path):
    """Bounded ordinary-file reader; never follow an artifact/journal symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_JSON:
            raise ValueError("Invalid evidence file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_JSON + 1)
        if len(raw) > MAX_JSON:
            raise ValueError("Evidence file exceeds bound")
        return json.loads(raw)
    finally:
        os.close(fd)


def public_event(value, modules):
    """Do not fall back to private testId or project any free-form field."""
    if not isinstance(value, dict) or value.get("event") not in ("started", "finished"):
        return None
    identity = value.get("publicTestId")
    if not isinstance(identity, str) or len(identity) > 512:
        identity = "unclassified-test"
    test = any(re.fullmatch(re.escape(module) + r"(?:\.[A-Za-z_][A-Za-z0-9_]*){1,2}", identity) for module in modules)
    fixture = any(re.fullmatch(r"(?:setUp|tearDown)(?:Class|Module) \(" + re.escape(module) + r"(?:\.[A-Za-z_][A-Za-z0-9_]*)?\)", identity) for module in modules)
    if not (test or fixture):
        identity = "unclassified-test"
    result = {"schemaVersion": 1, "event": value["event"], "publicTestId": identity,
              "outcome": "incomplete" if value["event"] == "started" else value.get("outcome")}
    if not isinstance(result["outcome"], str) or result["outcome"] not in OUTCOMES:
        return None
    if value["event"] == "finished":
        elapsed = value.get("elapsedSeconds")
        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or not 0 <= elapsed <= 7 * 86400:
            return None
        result["elapsedSeconds"] = elapsed
    return result


class Evidence:
    def __init__(self, directory, plan, *, stream=None, heartbeat=30.0):
        self.plan = validate_plan(plan)
        self.directory = Path(directory).absolute()
        for ancestor in [self.directory.parent, *self.directory.parent.parents]:
            if ancestor.exists() and stat.S_ISLNK(ancestor.lstat().st_mode):
                raise ValueError("Evidence ancestors cannot be symlinks")
        self.directory.parent.mkdir(parents=True, exist_ok=True)
        self.directory.mkdir(mode=0o700)  # Exclusive: never reuse a previous attempt.
        self.stream = sys.stdout if stream is None else stream
        self.heartbeat = heartbeat
        self.events = 0
        self.commands = []
        self.journal_generations = {}
        self.write("plan.json", self.plan)
        fd = os.open(self.directory / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.journal = os.fdopen(fd, "w", encoding="utf-8")
        self.emit({"schemaVersion": 1, "event": "selection", "state": "incomplete",
                   "globalDigest": plan["globalDigest"], "shardIndex": plan["shardIndex"]})

    def write(self, name, value):
        fd = os.open(self.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value) + b"\n"); stream.flush(); os.fsync(stream.fileno())

    def emit(self, event):
        if self.events >= MAX_EVENTS:
            raise ValueError("Public event bound exceeded")
        raw = canonical(event).decode()
        self.journal.write(raw + "\n"); self.journal.flush(); os.fsync(self.journal.fileno())
        self.stream.write("AGENT_TEST_PROGRESS " + raw + "\n"); self.stream.flush()
        self.events += 1

    def run(self, command, root, modules, report_directory=None):
        """Wait only for this child; the runner retains its existing owned cleanup."""
        if (not isinstance(modules, list) or not modules or len(modules) != len(set(modules))
                or any(module not in self.plan["assignedModules"] for module in modules)):
            raise ValueError("Command exceeds its assigned shard")
        child = subprocess.Popen(command, cwd=root)
        cancelled = [False]
        handlers = {}
        def cancel(signum, frame):
            cancelled[0] = True
            if child.poll() is None:
                child.send_signal(signum)
        for signum in (signal.SIGTERM, signal.SIGINT):
            handlers[signum] = signal.signal(signum, cancel)
        offsets = {}
        started = last = time.monotonic()
        cancelled_at = None
        try:
            while child.poll() is None:
                if report_directory is not None:
                    self.observe(Path(report_directory), modules, offsets)
                now = time.monotonic()
                if now - last >= self.heartbeat:
                    self.emit({"schemaVersion": 1, "event": "heartbeat", "state": "incomplete",
                               "elapsedSeconds": now - started, "stage": "awaiting-test-event" if not offsets else "worker-active"})
                    last = now
                if cancelled[0]:
                    cancelled_at = now if cancelled_at is None else cancelled_at
                    if now - cancelled_at > 15:
                        child.kill()  # The retained handle belongs to this invocation only.
                time.sleep(0.1)
            code = child.wait()
            if report_directory is not None:
                self.observe(Path(report_directory), modules, offsets, final=True)
            record = {"modules": modules, "returncode": code, "state": "cancelled" if cancelled[0] else "complete" if code == 0 else "failed"}
            if report_directory is not None:
                try:
                    report = read_json(Path(report_directory) / "report.json")
                    workers = report["workers"]
                    valid_workers = isinstance(workers, list) and bool(workers) and all(isinstance(item, dict) for item in workers)
                    closed = valid_workers and all(item.get("reaped") is True and item.get("sessionAbsent") is True
                                 and item.get("descendantLeak") is False and item.get("fixtureRootRemoved") is True for item in workers)
                    counts = report.get("counts", {})
                    counts_valid = (isinstance(counts, dict) and set(counts) == set(COUNTS) and all(type(count) is int and count >= 0 for count in counts.values())
                                    and all(counts[key] == 0 for key in ("failures", "errors", "unexpectedSuccesses")))
                    complete = (report.get("state") == "complete" and report.get("successful") is True
                                and report.get("sourceFingerprint") == self.plan["sourceFingerprint"] and closed and counts_valid
                                and all(item.get("state") == "complete" and type(item.get("returncode")) is int and item.get("returncode") == 0 for item in workers)
                                and sorted(module for item in workers for module in item["modules"]) == sorted(modules)
                                and report.get("replayAllowed") is False and report.get("infrastructureError") is None)
                    record["workerClosure"] = closed
                    record["state"] = "complete" if complete and code == 0 and not cancelled[0] else "incomplete"
                    if not isinstance(counts, dict):
                        raise ValueError("Invalid runner counts")
                    record["observedCounts"] = {key: counts[key] for key in COUNTS
                                                if type(counts.get(key)) is int and counts[key] >= 0}
                except (OSError, ValueError, KeyError, TypeError):
                    record.update(state="incomplete", workerClosure=False)
            self.commands.append(record)
            return code if record["state"] == "complete" else code or 2
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait()
            for signum, handler in handlers.items():
                signal.signal(signum, handler)

    def observe(self, directory, modules, offsets, *, final=False):
        if not directory.exists():
            return
        if stat.S_ISLNK(directory.lstat().st_mode):
            raise ValueError("Owned runner directory cannot be a symlink")
        # This is the single fresh UUID directory returned by prepare_run, never
        # a search for another invocation or for historical jobs.
        leaves = sorted(directory.iterdir())
        if len(leaves) > len(modules) + 4:
            raise ValueError("Owned runner directory exceeds worker bound")
        for leaf in leaves:
            if not re.fullmatch(r"worker-[0-9]{4}", leaf.name):
                continue
            if stat.S_ISLNK(leaf.lstat().st_mode):
                raise ValueError("Worker journal directory cannot be a symlink")
            path = leaf / "timings.jsonl"
            try:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            except FileNotFoundError:
                if final and leaf.name in offsets:
                    raise ValueError("Owned timing journal disappeared")
                continue
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or hasattr(os, "getuid") and info.st_uid != os.getuid()):
                    raise ValueError("Invalid owned timing journal")
                generation = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink)
                key = str(path)
                if self.journal_generations.setdefault(key, generation) != generation:
                    raise ValueError("Owned timing journal identity changed")
                offset = offsets.get(leaf.name, 0)
                if info.st_size < offset:
                    raise ValueError("Owned timing journal was truncated")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    stream.seek(offset)
                    for unused in range(MAX_EVENTS + 1 if final else 1000):
                        raw = stream.readline(MAX_LINE + 1)
                        if len(raw) > MAX_LINE:
                            raise ValueError("Private timing line exceeds bound")
                        if not raw or not raw.endswith(b"\n"):
                            if raw and final:
                                raise ValueError("Terminal timing journal has an incomplete line")
                            break
                        offset = stream.tell()
                        event = public_event(json.loads(raw), modules)
                        if event is not None:
                            self.emit(event)
                    else:
                        if final:
                            raise ValueError("Terminal timing journal exceeds drain bound")
                offsets[leaf.name] = offset
            finally:
                os.close(fd)

    def finish(self, code, source_unchanged):
        assigned = self.plan["assignedModules"]
        actual = [module for command in self.commands for module in command["modules"]]
        successful = (type(code) is int and code == 0 and source_unchanged is True and actual == assigned_or_gate_first(assigned)
                      and all(command["state"] == "complete" for command in self.commands))
        value = {"schemaVersion": 1, "globalDigest": self.plan["globalDigest"], "shardIndex": self.plan["shardIndex"],
                 "state": "complete" if successful and assigned else "empty-shard" if successful else "incomplete",
                 "successful": successful, "sourceUnchanged": source_unchanged is True, "commands": self.commands}
        self.write("summary.json", value)
        self.journal.close()
        return successful


def assigned_or_gate_first(modules):
    gate = "agent_tools.tests.test_ssh_connection_session_close"
    return ([gate] + [name for name in modules if name != gate]) if gate in modules else modules


def verify(directories, parent_results, *, expected=None):
    if parent_results != ["success"] * SHARD_COUNT or len(directories) != SHARD_COUNT:
        raise ValueError("Every actual shard job must succeed")
    plans, summaries = [], []
    for directory in directories:
        plans.append(validate_plan(read_json(Path(directory) / "plan.json")))
        summaries.append(read_json(Path(directory) / "summary.json"))
    if ({value["shardIndex"] for value in plans} != set(range(SHARD_COUNT))
            or {value["globalDigest"] for value in plans} != {plans[0]["globalDigest"]}):
        raise ValueError("Shard identities do not cover one global plan")
    if expected is not None:
        if (set(expected) != {"runId", "runAttempt", "head"}
                or any(plan[key] != value for plan in plans for key, value in expected.items())):
            raise ValueError("Shard receipts belong to another invocation")
    seen = []
    for plan, summary in zip(plans, summaries):
        expected = assigned_or_gate_first(plan["assignedModules"])
        if (set(summary) != {"schemaVersion", "globalDigest", "shardIndex", "state", "successful", "sourceUnchanged", "commands"}
                or type(summary.get("schemaVersion")) is not int or summary.get("schemaVersion") != 1 or summary.get("globalDigest") != plan["globalDigest"]
                or type(summary.get("shardIndex")) is not int or summary.get("shardIndex") != plan["shardIndex"] or summary.get("successful") is not True
                or summary.get("sourceUnchanged") is not True
                or summary.get("state") != ("complete" if plan["assignedModules"] else "empty-shard")):
            raise ValueError("Shard did not complete with source closure")
        commands = summary.get("commands")
        if (not isinstance(commands, list) or not all(isinstance(command, dict) for command in commands)
                or any(command.get("state") != "complete" or type(command.get("returncode")) is not int or command.get("returncode") != 0 for command in commands)):
            raise ValueError("Shard command incomplete")
        gate = "agent_tools.tests.test_ssh_connection_session_close"
        for command in commands:
            if command.get("modules") == [gate]:
                if set(command) != {"modules", "returncode", "state"}:
                    raise ValueError("Unexpected gate evidence")
            elif (set(command) != {"modules", "returncode", "state", "workerClosure", "observedCounts"}
                  or command.get("workerClosure") is not True
                  or not isinstance(command.get("observedCounts"), dict)
                  or set(command.get("observedCounts", {})) != set(COUNTS)
                  or any(type(count) is not int or count < 0 for count in command["observedCounts"].values())
                  or any(command["observedCounts"][key] != 0 for key in ("failures", "errors", "unexpectedSuccesses"))):
                raise ValueError("Worker closure evidence incomplete")
        actual = [module for command in commands for module in command["modules"]]
        if actual != expected:
            raise ValueError("Shard command coverage mismatch")
        seen.extend(actual)
    if len(seen) != len(set(seen)) or sorted(seen) != plans[0]["modules"]:
        raise ValueError("Shard union is incomplete or duplicated")
    return {"schemaVersion": 1, "successful": True, "globalDigest": plans[0]["globalDigest"], "coveredModules": len(seen)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", nargs=SHARD_COUNT, required=True, type=Path)
    parser.add_argument("--parent-results", nargs=SHARD_COUNT, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(verify(args.verify, args.parent_results,
                                expected={"runId": args.run_id, "runAttempt": args.run_attempt, "head": args.head}), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError):
        print("Public agent shard coverage verification failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
