"""The complete reviewed metadata-disposition positive under its inert World.

Only the qualifier's top-level owned path role moves. Its original oracle,
ActualWorld and model functions execute unchanged. The caller executes whole
with the original two initial globals; real proc/pidfd/signal/RPC are trapped.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import traceback
import types
import uuid

HERE = Path(__file__).resolve().parent
PROVENANCE_SHA = "c0ab9f71b32afdd11bd905238313760427db36b746fd427ecac81e205f98fd12"
REUSED = frozenset({
    "namespace_timestamps/inputs/03-qualify_collector.py.source",
    "namespace_timestamps/inputs/04-harness.py.source",
    "namespace_timestamps/inputs/07-windows_qga_transfer.candidate.py.source",
})
MAX_SOURCE = 256 * 1024


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _generation(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


class Sources:
    def __init__(self, production_root):
        self.production_root = Path(production_root)
        self.held = []
        self.opened = self.closed = 0
        raw = self.capture(HERE / "provenance.json", PROVENANCE_SHA)
        value = json.loads(raw)
        assert value["schemaVersion"] == 1
        self.pins = value["files"]
        self.current = value["currentProducer"]

    def capture(self, path, digest):
        path = Path(path)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        self.opened += 1
        raw = os.read(fd, MAX_SOURCE + 1)
        opening = os.fstat(fd)
        self.held.append((path, fd, raw, _generation(opening)))
        assert stat.S_ISREG(opening.st_mode) and opening.st_nlink == 1
        assert len(raw) <= MAX_SOURCE and _sha(raw) == digest
        self.guard()
        return raw

    def input(self, relative):
        assert relative in self.pins, "finite-metadata-disposition-input"
        pin = self.pins[relative]
        root = (self.production_root / "agent_tools/tests/fixtures/windows_native_packet_recipe"
                if relative in REUSED else HERE.parent)
        raw = self.capture(root / relative, pin["sha256"])
        assert len(raw) == pin["bytes"]
        return raw

    def put(self, path, raw):
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
        self.capture(path, _sha(raw))

    def guard(self):
        for path, fd, raw, identity in self.held:
            os.lseek(fd, 0, os.SEEK_SET)
            assert os.read(fd, MAX_SOURCE + 1) == raw, "metadata-original-source-bytes"
            assert _generation(os.fstat(fd)) == identity == _generation(path.lstat()), "metadata-original-or-named-source-generation"

    def close(self):
        try:
            self.guard()
        finally:
            for _, fd, _, _ in reversed(self.held):
                os.close(fd)
                self.closed += 1


def _bodies(raw):
    tree = raw if isinstance(raw, ast.Module) else ast.parse(raw)
    return [ast.dump(node, include_attributes=False) for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))]


def _entry(phase, destination, production_root, current_path):
    assert phase in {"before", "after"}
    sources = Sources(production_root)
    root = Path(destination) / "owned-repository"
    base = root / "private/lane/windows-fixture"
    work = base / "post/metadata-disposition"
    stage = {
        "metadata_disposition/positive." + ("before" if phase == "before" else "current") + ".qualifier.source": work / "qualify_current.py",
        "metadata_disposition/models.source": base / "host-actor-abandonment-private-preparation-v1/qualification_models_actual.py",
        "namespace_timestamps/inputs/03-qualify_collector.py.source": base / "owned-host-readonly-preparation-v1/qualify_collector.py",
        "namespace_timestamps/inputs/04-harness.py.source": base / "inert-caller-qualification/harness.py",
        "namespace_timestamps/inputs/07-windows_qga_transfer.candidate.py.source": base / "qga-recv-poll-private-preparation-v1/windows_qga_transfer.candidate.py",
        "metadata_disposition/emitter.source": root / "agent_tools/windows_artifact_transfer.py",
        "metadata_disposition/observer.caller.source": work.parent / "host-observer-disposition-preparation-v1/disposition-caller.v2.py",
        "metadata_disposition/observer.qualifier.source": work.parent / "host-observer-disposition-preparation-v1/qualify_current.py",
        "metadata_disposition/rpc18.request.source": work.parent / "msi-metadata7820-host-identity-preparation-v1/qualification-inert-v1/outputs/rpc18.request.reconstructed.json",
        "metadata_disposition/rpc18.raw.bin": work.parent / "msi-metadata7820-host-identity-preparation-v1/qualification-inert-v1/outputs/rpc18.raw.reconstructed",
    }
    module_name = "_native_metadata_positive_" + uuid.uuid4().hex
    prior_path = list(sys.path)
    receipt = None
    error = None
    output = io.StringIO()
    calls = {}
    prior_profile = sys.getprofile()
    try:
        for relative, target in stage.items():
            sources.put(target, sources.input(relative))
        caller = (sources.input("metadata_disposition/caller.before.source") if phase == "before"
                  else sources.capture(current_path, sources.current["sha256"]))
        sources.put(work / "disposition-caller.py", caller)
        sources.put(root / "agent_tools/windows_qga_transfer.py", sources.input(
            "namespace_timestamps/inputs/07-windows_qga_transfer.candidate.py.source"))
        qpath = work / "qualify_current.py"
        original = qpath.read_bytes()
        tree = ast.parse(original)
        moved = 0
        for node in tree.body:
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "W"):
                assert isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "Path"
                node.value = ast.Call(func=ast.Name(id="Path", ctx=ast.Load()),
                                      args=[ast.Constant(str(work))], keywords=[])
                moved += 1
        assert moved == 1
        ast.fix_missing_locations(tree)
        assert _bodies(original) == _bodies(tree), "complete-positive-oracle-body-drift"
        module = types.ModuleType(module_name)
        module.__file__ = str(qpath)
        sys.modules[module_name] = module

        def profile(frame, event, argument):
            if event == "call" and frame.f_globals is module.__dict__:
                assert sys.modules.get(module_name) is module
                name = frame.f_code.co_name
                calls[name] = calls.get(name, 0) + 1

        sys.setprofile(profile)
        with contextlib.redirect_stdout(output):
            sources.guard()
            exec(compile(tree, str(qpath), "exec", dont_inherit=True), module.__dict__)
            sources.guard()
            try:
                module.main()
            except AssertionError as caught:
                error = caught
            sources.guard()
        receipt_path = work / "outputs/complete-before-oracle.receipt.private.json"
        receipt = json.loads(receipt_path.read_bytes())
        assert receipt["completeNamespace"] and not receipt["postExecFunctionReplacement"]
        assert receipt["originalFilesUnchanged"] and not receipt["retainedDescriptors"]
        assert receipt["originalFailure"] is None and receipt["error"] is None
        assert len(receipt["signals"]) == len(receipt["pidfdCalls"]) == 1
        assert calls["<module>"] == calls["main"] == calls["core_reuse"] == 1
    finally:
        sys.setprofile(prior_profile)
        sys.path[:] = prior_path
        sys.modules.pop(module_name, None)
        sources.close()
    result = {"sourceSha256": receipt["sourceSha256"],
              "sameOriginalPositiveOraclePassed": error is None,
              "error": None if error is None else {"class": type(error).__name__, "message": str(error)},
              "registeredWholeQualifierCalls": calls,
              "completeOriginalCaller": receipt,
              "sourcesUnchanged": True,
              "sourceDescriptorsOpened": sources.opened,
              "sourceDescriptorsClosed": sources.closed,
              "noCallerOrOracleFunctionReplacement": True,
              "onlyTopLevelOwnedPathRoleRelocated": True,
              "nativeOrNetworkActions": False}
    print(json.dumps(result, sort_keys=True), flush=True)
    if error is not None:
        traceback.print_exception(error, file=sys.stderr)
    raise SystemExit(1 if error is not None else 0)


def run_disposition_pair(current, production_root, destination):
    """Use identical complete positive function bodies for actual whole sources."""
    source = Sources(production_root)
    try:
        before = source.input("metadata_disposition/positive.before.qualifier.source")
        qualifier = source.input("metadata_disposition/positive.current.qualifier.source")
        assert _bodies(before) == _bodies(qualifier), "positive-oracle-functions-changed"
        assert type(current) is bytes and len(current) == source.current["bytes"] and _sha(current) == source.current["sha256"]
        assert _bodies(source.input("metadata_disposition/caller.before.source")) == _bodies(current), "report-only-caller-functions-changed"
        current_path = Path(destination) / "rendered-current-caller.py"
        source.put(current_path, current)
        results = {}
        command = ("import importlib.util,sys; from pathlib import Path; "
                   "s=importlib.util.spec_from_file_location('_metadata_disposition_entry',sys.argv[1]); "
                   "m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m); "
                   "m._entry(sys.argv[2],Path(sys.argv[3]),Path(sys.argv[4]),Path(sys.argv[5]))")
        for phase in ("before", "after"):
            target = Path(destination) / phase
            target.mkdir(mode=0o700)
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            env.pop("DYLD_INSERT_LIBRARIES", None)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            child = subprocess.Popen([sys.executable, "-B", "-c", command, str(HERE / "boundary.py"),
                phase, str(target), str(production_root), str(current_path)], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=production_root)
            stdout, stderr = child.communicate()
            assert len(stdout) + len(stderr) < 1024 * 1024
            for name, raw in (("stdout", stdout), ("stderr", stderr)):
                with (target / (name + ".raw")).open("xb") as stream:
                    stream.write(raw)
            value = json.loads(stdout)
            value.update(exitCode=child.returncode, naturalExit=True, streamsEof=True,
                         stdoutSha256=_sha(stdout), stderrSha256=_sha(stderr))
            results[phase] = value
        source.guard()
    finally:
        source.close()
    return {"before": results["before"], "after": results["after"],
            "sameOriginalPositiveOracle": True, "completeAuthenticCallers": True,
            "allOriginalFixtureBytesUnchanged": True,
            "nativeOrNetworkActions": False}
