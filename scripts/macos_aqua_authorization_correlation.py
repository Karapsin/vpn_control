#!/usr/bin/env python3
"""Read-only fixture observer for a macOS MACHINE authorization candidate."""
import argparse
import json
import os
import re
import stat
import subprocess
from pathlib import Path

INPUTS_SUFFIX = Path("Library/Application Support/vpn-control-install-inputs")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def parse_ps(text):
    rows = []
    for line in text.splitlines():
        columns = line.strip().split(None, 3)
        if len(columns) != 4 or not all(value.isdecimal() for value in columns[:3]):
            continue
        rows.append({"pid": int(columns[0]), "ppid": int(columns[1]), "uid": int(columns[2]), "command": columns[3]})
    return rows


def coordinator(row, owner_home):
    command = row["command"]
    if not command.startswith("/usr/bin/osascript ") or " -- " not in command:
        return None
    # ps renders argv with spaces but does not shell-quote arguments. Parse
    # the fixed suffix first, then compare the complete captured worker path.
    tail = command.rsplit(" -- ", 1)[1]
    match = re.fullmatch(r"(.+) --coordinate ([0-9a-f-]+) ([0-9]+)", tail)
    if match is None or not UUID.fullmatch(match[2]):
        return None
    job_id, owner_pid = match[2], int(match[3])
    expected = owner_home / INPUTS_SUFFIX / job_id / "vpn-control-install-worker"
    if match[1] not in (str(expected), "'" + str(expected) + "'"):
        return None
    try:
        metadata = expected.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        return None
    return {"osascriptPid": row["pid"], "jobId": job_id, "ownerPid": owner_pid}


def observe(owner_pid, owner_executable):
    rows = parse_ps(subprocess.check_output(["ps", "-axo", "pid=,ppid=,uid=,command="], text=True))
    owner = [row for row in rows if row["pid"] == owner_pid and row["command"].split(None, 1)[0] == owner_executable]
    agents = [row for row in rows if Path(row["command"].split(None, 1)[0]).name == "SecurityAgent"]
    candidates = [item for item in (coordinator(row, Path.home()) for row in rows) if item and item["ownerPid"] == owner_pid]
    return {"ownerMatches": len(owner), "securityAgentCount": len(agents), "coordinators": candidates}


def candidate_prompt_correlation(baseline, observed, job_id):
    if baseline.get("securityAgentCount") != 0:
        return {"candidatePromptCorrelation": False, "reason": "preexisting-security-agent"}
    if observed.get("ownerMatches") != 1:
        return {"candidatePromptCorrelation": False, "reason": "owner-identity-mismatch"}
    coordinators = observed.get("coordinators")
    if not isinstance(coordinators, list):
        return {"candidatePromptCorrelation": False, "reason": "exact-coordinator-missing-or-ambiguous"}
    matching = [item for item in coordinators if isinstance(item, dict) and item.get("jobId") == job_id]
    if len(coordinators) != 1 or len(matching) != 1:
        return {"candidatePromptCorrelation": False, "reason": "exact-coordinator-missing-or-ambiguous"}
    if observed.get("securityAgentCount") != 1:
        return {"candidatePromptCorrelation": False, "reason": "security-agent-missing-or-ambiguous"}
    return {"candidatePromptCorrelation": True, "jobId": job_id, "osascriptPid": matching[0]["osascriptPid"]}


def public_recovery(status, job_id):
    if status.get("ok") is not True or status.get("final") is not True or status.get("code") != "OK":
        return {"terminal": False, "reason": "public-envelope-not-successful-final"}
    installations = status.get("data", {}).get("installations")
    matching = [entry for entry in installations if entry.get("jobId") == job_id] if isinstance(installations, list) else []
    if len(matching) != 1:
        return {"terminal": False, "reason": "public-job-missing-or-ambiguous"}
    entry = matching[0]
    installed = entry.get("installed")
    if installed is not True and installed is not False and installed is not None:
        return {"terminal": False, "reason": "public-installed-malformed"}
    if entry.get("final") is not True or entry.get("phase") not in {"succeeded", "failed", "cancelled"} or not isinstance(entry.get("code"), str):
        return {"terminal": False, "reason": "public-result-not-terminal"}
    return {"terminal": True, "phase": entry["phase"], "code": entry["code"], "installed": installed}


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    observe_parser = sub.add_parser("observe")
    observe_parser.add_argument("--owner-pid", type=int, required=True)
    observe_parser.add_argument("--owner-executable", required=True)
    candidate_parser = sub.add_parser("candidate")
    candidate_parser.add_argument("--baseline", required=True)
    candidate_parser.add_argument("--observed", required=True)
    candidate_parser.add_argument("--job-id", required=True)
    public_parser = sub.add_parser("public")
    public_parser.add_argument("--job-id", required=True)
    public_parser.add_argument("--status", required=True)
    args = parser.parse_args()
    if args.action == "observe":
        result = observe(args.owner_pid, args.owner_executable)
    elif args.action == "candidate":
        result = candidate_prompt_correlation(json.loads(Path(args.baseline).read_text()), json.loads(Path(args.observed).read_text()), args.job_id)
    else:
        result = public_recovery(json.loads(Path(args.status).read_text()), args.job_id)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
