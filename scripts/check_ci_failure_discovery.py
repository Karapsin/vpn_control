#!/usr/bin/env python3
"""TEST-006: required CI jobs report every independent failure in one pass.

After a job's first check, every step keeps running after an earlier failure
(`!cancelled()`, `always()` or `failure()`); a step that consumes another
step's output names that earlier step's success. Multi-task Gradle invocations
use --continue. Jobs that only run on workflow_dispatch are out of scope.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SETUP_PREFIXES = ("Checkout", "Set up ", "Install ", "Read ", "Add ")
CONTINUATIONS = ("!cancelled()", "always()", "failure()")
STEP_REFERENCE = re.compile(r"\bsteps\.([A-Za-z0-9_-]+)\.")
GRADLE = re.compile(r"(?:^|[\s;&|(])(?:\./|\.\\)?gradlew(?:\.bat)?((?:[ \t]+[^\s;&|)]+)+)")


def required_workflows(root: Path = ROOT) -> list[Path]:
    manifest = json.loads((root / ".github/required-workflows.json").read_text(encoding="utf-8"))
    return [root / row["path"] for row in manifest["branches"]["dev"]["workflows"]
            if row["classification"] == "required_push"]


def _scalar(value: str) -> str:
    value = value.strip()
    if value[:1] in ("'", '"'):
        parsed = ast.literal_eval(value) if value[0] == '"' else value[1:-1].replace("''", "'")
        return str(parsed)
    return value


def workflow_jobs(source: str) -> dict[str, dict]:
    """Stdlib extraction of each job's condition and steps' name/if/id/run."""
    lines = source.splitlines()
    try:
        start = lines.index("jobs:") + 1
    except ValueError:
        raise ValueError("workflow has no top-level jobs mapping") from None
    jobs: dict[str, dict] = {}
    job = step = None
    block = None
    for line in lines[start:]:
        indent = len(line) - len(line.lstrip(" "))
        if block is not None:
            if not line.strip() or indent > block[1]:
                block[2].append(line[block[1] + 2:] if line.strip() else "")
                continue
            block = None
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if indent == 0:
            break
        if indent == 2 and re.fullmatch(r"  [A-Za-z0-9_-]+:\s*", line):
            job = jobs.setdefault(line.strip()[:-1], {"steps": []});step = None
            continue
        if job is None:
            continue
        if indent == 4 and line.startswith("    if:"):
            job["if"] = _scalar(line.split(":", 1)[1])
        elif indent == 6 and line.startswith("      - "):
            step = {};job["steps"].append(step);line = " " * 8 + line[8:];indent = 8
        if step is not None and indent == 8:
            match = re.fullmatch(r"        ([A-Za-z_-]+):(.*)", line)
            if match and match.group(1) in ("name", "if", "id"):
                step[match.group(1)] = _scalar(match.group(2))
            elif match and match.group(1) == "run":
                value = match.group(2).strip()
                if value[:1] in ("|", ">"):
                    # Folded blocks join their lines; literal blocks keep them.
                    block = (step, 8, []);step["run"] = (value[:1], block[2])
                else:
                    step["run"] = _scalar(value)
    for job in jobs.values():
        for step in job["steps"]:
            if isinstance(step.get("run"), tuple):
                style, body = step["run"]
                step["run"] = (" ".join(part for part in body if part) if style == ">" else "\n".join(body)) + "\n"
    return jobs


def _dispatch_only(job: dict) -> bool:
    return "github.event_name == 'workflow_dispatch'" in str(job.get("if", ""))


def _gradle_violations(text: str) -> list[str]:
    found = []
    for match in GRADLE.finditer(text):
        arguments = match.group(1).split()
        tasks = [argument for argument in arguments if not argument.startswith("-")]
        if len(tasks) > 1 and "--continue" not in arguments:
            found.append("multi-task Gradle invocation without --continue: gradlew " + " ".join(arguments))
    return found


def violations(source: str, name: str = "workflow") -> list[str]:
    problems = []
    for job_name, job in workflow_jobs(source).items():
        if _dispatch_only(job):
            continue
        steps = job.get("steps") or []
        checks = [index for index, step in enumerate(steps)
                  if "run" in step and not str(step.get("name", "")).startswith(SETUP_PREFIXES)]
        earlier = set()
        for index, step in enumerate(steps):
            label = f"{name}:{job_name}:{step.get('name') or index}"
            condition = str(step.get("if", ""))
            if checks and index > checks[0] and not any(token in condition for token in CONTINUATIONS):
                problems.append(label + ": an earlier failed check would skip this step")
            for reference in STEP_REFERENCE.findall(condition):
                if reference not in earlier:
                    problems.append(label + ": condition references a missing or later step " + reference)
            problems.extend(label + ": " + problem for problem in _gradle_violations(str(step.get("run", ""))))
            if step.get("id"):
                earlier.add(step["id"])
    return problems


def main(argv: list[str]) -> int:
    paths = [Path(argument) for argument in argv] or required_workflows()
    problems = [problem for path in paths for problem in violations(path.read_text(encoding="utf-8"), path.name)]
    for problem in problems:
        print("[vpn-control] TEST-006 " + problem, file=sys.stderr)
    if problems:
        return 1
    print(f"[vpn-control] CI failure discovery passed ({len(paths)} required workflows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
