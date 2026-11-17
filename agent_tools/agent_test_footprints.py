#!/usr/bin/env python3
"""Per-test file footprints for precise local agent-test selection.

CI records, in each managed test worker, which repository files every test
module and every imported module opened, compiled, listed or launched. The
selector joins those recorded edges with its static import graph. Footprints
only narrow local selection; CI still runs the complete agent suite on every
agent-input change, so a stale or missing footprint can never hide a failure
from the completion gate.

Subcommands:
  merge OUTPUT INPUT...   merge worker footprint files into one table
  fetch [--run-id ID]     download the footprints of the newest successful Fast
                          Checks run that recorded them (normally a ci/* gate run)
                          and whose head is an ancestor of HEAD into
                          .rag_index/agent-test-footprints.json (needs gh)
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import uuid

SCHEMA = 1
ENVIRONMENT = "AGENT_TEST_FOOTPRINT_DIR"
CACHE = Path(".rag_index") / "agent-test-footprints.json"
ARTIFACT_PATTERN = "agent-test-footprints-*"
_EVENTS = frozenset({"open", "compile", "os.listdir", "os.scandir", "subprocess.Popen"})
_TEST_MODULE = re.compile(r"(?:agent_tools\.tests|scripts)\.test_[A-Za-z0-9_]+\Z")
_IGNORED = (".git/", ".rag_index/", ".runtime/", ".agent_venv/", "build/", ".gradle/")
_PYC = re.compile(r"(?P<parent>(?:.*/)?)__pycache__/(?P<stem>[^/.]+)\.[^/]+\.pyc\Z")


class Recorder:
    """Attribute repository reads to the innermost test module or importing module.

    A frame of a test module owns the reads made while it runs (fixture reads
    and lazily imported tools). A module body being executed owns the reads made
    while it is imported. Reads from threads without either frame belong to the
    test module that is currently running.
    """

    def __init__(self, root, *, exclude=()):
        self.root = os.path.normpath(str(Path(root).resolve())) + os.sep
        self.exclude = frozenset(exclude)
        self.current = None
        self.edges = {}
        self.directories = {}
        self._local = threading.local()
        self._lock = threading.Lock()

    def install(self):
        sys.addaudithook(self.hook)
        return self

    def relative(self, value):
        if isinstance(value, os.PathLike):
            value = os.fspath(value)
        if isinstance(value, bytes):
            value = os.fsdecode(value)
        if not isinstance(value, str) or not value or value.startswith("<") or "\0" in value:
            return None
        if not os.path.isabs(value):
            value = os.path.join(os.getcwd(), value)
        value = os.path.normpath(value)
        if not value.startswith(self.root):
            return None
        relative = value[len(self.root):].replace(os.sep, "/")
        match = _PYC.fullmatch(relative)
        if match:
            relative = match["parent"] + match["stem"] + ".py"
        if not relative or relative.startswith(_IGNORED) or relative in self.exclude or not os.path.exists(value):
            return None
        return relative

    def lazy_importer(self, frame):
        """The repository function whose import statement is loading a module now.

        Only the standard import system between the read and that function makes
        it an import; a custom loader reading a source is not its importer.
        """
        importing = False
        while frame is not None:
            filename = frame.f_code.co_filename
            importing = importing or filename.startswith("<frozen importlib")
            found = self.relative(filename)
            if found:
                if not importing:
                    return None
                name = frame.f_globals.get("__name__")
                if frame.f_code.co_name == "<module>" or (isinstance(name, str) and _TEST_MODULE.fullmatch(name)):
                    return None
                return found
            frame = frame.f_back
        return None

    def owner(self, frame):
        while frame is not None:
            name = frame.f_globals.get("__name__")
            if isinstance(name, str) and _TEST_MODULE.fullmatch(name):
                found = self.relative(frame.f_globals.get("__file__"))
                if found:
                    return found
            if frame.f_code.co_name == "<module>":
                found = self.relative(frame.f_code.co_filename)
                if found:
                    return found
            frame = frame.f_back
        return self.current

    def hook(self, event, args):
        if event not in _EVENTS or getattr(self._local, "busy", False):
            return
        self._local.busy = True
        try:
            directory = event in ("os.listdir", "os.scandir")
            if event == "open":
                values = [args[0]] if args and not isinstance(args[0], int) else []
            elif event == "compile":
                values = [args[1]] if len(args) > 1 else []
            elif directory:
                values = [args[0] if args and args[0] is not None else "."]
            else:
                command = args[1] if len(args) > 1 else None
                values = [args[0]] + (list(command) if isinstance(command, (list, tuple)) else [command])
            # A named adapter or a file is an edge; a directory only through a listing.
            paths = [path for path in map(self.relative, values) if path and (directory or os.path.isfile(self.root + path))]
            if not paths:
                return
            frame = sys._getframe(1)
            owner = self.owner(frame)
            # An import inside a production function is that module's edge too:
            # a later test reaching it finds the module already cached.
            importer = self.lazy_importer(frame) if event == "open" and paths[0].endswith(".py") else None
            with self._lock:
                target = self.directories if directory else self.edges
                for source in {owner, importer} - {None}:
                    target.setdefault(source, set()).update(path for path in paths if path != source)
        except Exception:
            pass
        finally:
            self._local.busy = False

    def value(self, commit=None):
        with self._lock:
            return {"schemaVersion": SCHEMA, "sourceCommit": commit,
                    "edges": {owner: sorted(paths) for owner, paths in sorted(self.edges.items()) if paths},
                    "directories": {owner: sorted(paths) for owner, paths in sorted(self.directories.items()) if paths}}


def write_worker(directory, recorder, commit=None):
    """Create-only worker output under an explicit footprint directory, created on first use."""
    Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
    path = Path(directory) / ("footprint-" + str(uuid.uuid4()) + ".json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(recorder.value(commit), stream, sort_keys=True, separators=(",", ":"))
    return path


def validate(value):
    if (not isinstance(value, dict) or value.get("schemaVersion") != SCHEMA
            or not isinstance(value.get("edges"), dict) or not isinstance(value.get("directories", {}), dict)):
        raise ValueError("Invalid agent test footprint")
    for table in (value["edges"], value.get("directories", {})):
        for owner, paths in table.items():
            if (not isinstance(owner, str) or not isinstance(paths, list)
                    or any(not isinstance(path, str) or path.startswith("/") or ".." in path.split("/") for path in paths)):
                raise ValueError("Invalid agent test footprint")
    return value


def merge(values, commit=None):
    edges, directories, commits = {}, {}, set()
    for value in values:
        validate(value)
        commits.add(value.get("sourceCommit"))
        for owner, paths in value["edges"].items():
            edges.setdefault(owner, set()).update(paths)
        for owner, paths in value.get("directories", {}).items():
            directories.setdefault(owner, set()).update(paths)
    commits.discard(None)
    if commit is None and len(commits) == 1:
        commit = next(iter(commits))
    return {"schemaVersion": SCHEMA, "sourceCommit": commit,
            "edges": {owner: sorted(paths) for owner, paths in sorted(edges.items())},
            "directories": {owner: sorted(paths) for owner, paths in sorted(directories.items())}}


def _write_cache(root, value):
    target = Path(root) / CACHE
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + "." + str(uuid.uuid4()) + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, target)
    return target


def _gh(*args):
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def _has_footprints(run_id):
    """Whether a run still holds an unexpired agent-test-footprints-* artifact."""
    listed = json.loads(_gh("api", f"repos/{{owner}}/{{repo}}/actions/runs/{run_id}/artifacts?per_page=100"))
    return any(fnmatch.fnmatchcase(artifact.get("name", ""), ARTIFACT_PATTERN) and not artifact.get("expired")
               for artifact in listed.get("artifacts", []))


def fetch(root, run_id=None):
    """Newest successful Fast Checks run with recorded footprints whose head is an ancestor of HEAD.

    A dev push that reuses its ci/* result, and a push that changed no agent
    input, runs no agent shard and uploads no footprints, so the newest dev run
    is usually empty; the ci/* gate run of the same or an earlier SHA has them.
    """
    root = Path(root).resolve()
    if run_id is None:
        runs = json.loads(_gh("run", "list", "--workflow", "fast-checks.yml", "--status", "success",
                              "--limit", "100", "--json", "databaseId,headSha"))
        for run in runs:
            ancestor = subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", run["headSha"], "HEAD"],
                                      capture_output=True)
            if ancestor.returncode == 0 and _has_footprints(run["databaseId"]):
                run_id, commit = str(run["databaseId"]), run["headSha"]
                break
        else:
            raise ValueError("No successful Fast Checks run with agent test footprints is an ancestor of HEAD")
    else:
        commit = json.loads(_gh("run", "view", str(run_id), "--json", "headSha"))["headSha"]
    with tempfile.TemporaryDirectory(prefix="agent-footprints-") as temporary:
        _gh("run", "download", str(run_id), "--pattern", ARTIFACT_PATTERN, "--dir", temporary)
        values = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(Path(temporary).rglob("footprint-*.json"))]
    if not values:
        raise ValueError("The run has no agent test footprints")
    return _write_cache(root, merge(values, commit))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    merged = commands.add_parser("merge")
    merged.add_argument("output", type=Path)
    merged.add_argument("inputs", nargs="+", type=Path)
    merged.add_argument("--commit")
    fetched = commands.add_parser("fetch")
    fetched.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    fetched.add_argument("--run-id")
    args = parser.parse_args(argv)
    try:
        if args.command == "merge":
            value = merge([json.loads(path.read_text(encoding="utf-8")) for path in args.inputs], args.commit)
            args.output.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            print(json.dumps({"ok": True, "owners": len(value["edges"])}))
        else:
            target = fetch(args.root, args.run_id)
            print(json.dumps({"ok": True, "cache": str(target)}))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(json.dumps({"ok": False, "error": type(error).__name__ + ": " + str(error)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
