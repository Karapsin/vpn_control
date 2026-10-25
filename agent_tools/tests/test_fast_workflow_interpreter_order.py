"""Fast Checks prepares one compiler before any repository Python imports.

The native 3.12.3 -> 3.12.15 control is recorded in fixture provenance. This
portable routine control models that compiler metadata difference explicitly;
it executes the complete real saved producers and their unchanged code guard.
"""
import argparse
import ast
import hashlib
import importlib
import importlib.util
import json
import marshal
from pathlib import Path
import re
import struct
import sys
import tempfile
import types
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/fast-checks.yml"
FIXTURES = Path(__file__).parent / "fixtures/fast_workflow_interpreter_order"
BEFORE = FIXTURES / "fast-checks.before.yml"
BEFORE_SHA = "32ea92fd1715fd5e261edfe7cd169c3afa31180f57bb582966e91c78df395b87"
PRODUCERS = (
    "ssh_transport.py", "ssh_automatic_program.py",
    "private_inventory_lock.py", "native_review_source_closure.py",
    # The automatic program now imports the shared readiness coordinator.
    "readiness.py",
)
PROFILE_FUNCTIONS = {
    "ssh_transport.py": "_reject_duplicate_keys",
    "ssh_automatic_program.py": "command_bytes",
}


def steps(source, job="fast-checks"):
    sections = list(re.finditer(r"^jobs:\s*$", source, re.MULTILINE))
    if len(sections) != 1:
        raise AssertionError("Expected one workflow jobs mapping")
    source = source[sections[0].end():]
    jobs = list(re.finditer(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\s*$", source, re.MULTILINE))
    selected = [index for index, match in enumerate(jobs) if match.group(1) == job]
    if len(selected) != 1:
        raise AssertionError("Expected one workflow job: " + job)
    index = selected[0]
    source = source[jobs[index].end():jobs[index + 1].start() if index + 1 < len(jobs) else len(source)]
    matches = list(re.finditer(r"^      - name: (.+)$", source, re.MULTILINE))
    labels = [match.group(1) for match in matches]
    if len(labels) != len(set(labels)):
        raise AssertionError("Duplicate workflow step in job: " + job)
    return [(match.group(1), source[match.start():matches[index + 1].start()
                                   if index + 1 < len(matches) else len(source)])
            for index, match in enumerate(matches)]


def position(source, name, job="fast-checks"):
    names = [label for label, _ in steps(source, job)]
    if names.count(name) != 1:
        raise AssertionError("Expected one workflow step: " + name)
    return names.index(name)


def original_agent_step(body):
    suffix = " --shard-index 0 --shard-count 2 --ci-evidence-dir .rag_index/agent-ci-evidence-0"
    original = []
    commands = 0
    for line in body.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        if content.lstrip().startswith("python agent_tools/affected_agent_tests.py "):
            if not content.endswith(suffix):
                raise AssertionError("Unknown first-shard command change")
            commands += 1
            line = content[:-len(suffix)] + line[len(content):]
        original.append(line)
    if commands != 2:
        raise AssertionError("Expected both original affected-test commands")
    return "".join(original)


def admit_public_uploader(body):
    expected = '''      - name: Retain public agent shard evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agent-test-shard-${{ github.run_id }}-${{ github.run_attempt }}-0
          path: |
            .rag_index/agent-ci-evidence-0/plan.json
            .rag_index/agent-ci-evidence-0/events.jsonl
            .rag_index/agent-ci-evidence-0/summary.json
          if-no-files-found: error
          include-hidden-files: true
          retention-days: 7'''
    if body.strip() != expected.strip():
        raise AssertionError("Unknown public evidence retention action")


def before_workflow():
    raw = BEFORE.read_bytes()
    provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
    if (hashlib.sha256(raw).hexdigest() != BEFORE_SHA
            or provenance["sourceSha256"] != BEFORE_SHA
            or provenance["sourceCommit"] != "c68058eb64f8452207bf2091bd2950e5a06231da"):
        raise AssertionError("Original workflow bytes or authority changed")
    return raw.decode()


def prior_compiler_profile(code, raw, filename, name):
    """Change only one real nested code object's valid line-table metadata.

    A blank source line supplies a valid alternate table. The emitted source
    file, opcodes, arguments, flags and constants remain the original ones.
    This is an explicit portable compiler-profile counterfactual, separate from
    the actual two-patch compiler experiment retained in provenance.
    """
    node = next(item for item in ast.parse(raw).body
                if isinstance(item, ast.FunctionDef) and item.name == name)
    lines = raw.splitlines(keepends=True)
    lines.insert(node.body[0].lineno - 1, b"\n")
    shifted = compile(b"".join(lines), filename, "exec", dont_inherit=True)
    original = next(item for item in code.co_consts
                    if isinstance(item, types.CodeType) and item.co_name == name)
    alternate = next(item for item in shifted.co_consts
                     if isinstance(item, types.CodeType) and item.co_name == name)
    if original.co_code != alternate.co_code or original.co_linetable == alternate.co_linetable:
        raise AssertionError("Compiler profile did not isolate a line-table difference")
    variant = original.replace(co_linetable=alternate.co_linetable)
    return code.replace(co_consts=tuple(variant if item is original else item
                                       for item in code.co_consts))


def actual_guard_for_order(workflow):
    """Emit and consume only an owned copied complete import closure."""
    prepared = position(workflow, "Set up Python 3.12") < position(workflow, "Check release hygiene")
    prefix = "_owned_fast_compiler_" + uuid.uuid4().hex
    package = types.ModuleType(prefix)
    record = {"preparedBeforeHygiene": prepared, "headers": [], "sources": {},
              "sshCalls": 0, "nativeActions": 0}
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary).resolve()
        package.__path__ = [str(directory)]
        sys.modules[prefix] = package
        source_bytes = {}
        caches = {}
        try:
            for name in PRODUCERS:
                raw = (ROOT / "agent_tools" / name).read_bytes()
                source_bytes[name] = raw
                path = directory / name
                path.write_bytes(raw)
                compiled = compile(raw, str(path), "exec", dont_inherit=True)
                if not prepared and name in PROFILE_FUNCTIONS:
                    compiled = prior_compiler_profile(compiled, raw, str(path), PROFILE_FUNCTIONS[name])
                cache = Path(importlib.util.cache_from_source(str(path)))
                cache.parent.mkdir(exist_ok=True)
                header = importlib.util.MAGIC_NUMBER + struct.pack(
                    "<III", 0, int(path.stat().st_mtime) & 0xffffffff, len(raw) & 0xffffffff)
                payload = header + marshal.dumps(compiled)
                cache.write_bytes(payload)
                caches[name] = (cache, payload)
                record["headers"].append({
                    "source": name, "magic": header[:4].hex(), "flags": 0,
                    "timestamp": int(path.stat().st_mtime), "size": len(raw),
                    "timestampValid": header[8:12] == struct.pack("<I", int(path.stat().st_mtime) & 0xffffffff),
                    "pycSha256": hashlib.sha256(payload).hexdigest(),
                })
                record["sources"][name] = hashlib.sha256(raw).hexdigest()
            importlib.invalidate_caches()
            transport = importlib.import_module(prefix + ".ssh_transport")
            try:
                module = transport._automatic_module()
                record["guard"] = "accepted"
                record["actualAutomaticSource"] = str(Path(module.__file__).relative_to(directory))
            except transport.SshConfigError as error:
                record["guard"] = "refused"
                record["error"] = str(error)
            record["unchangedSourceBytes"] = all((directory / name).read_bytes() == raw
                                                  for name, raw in source_bytes.items())
            record["unchangedPycBytes"] = all(path.read_bytes() == raw for path, raw in caches.values())
            record["cacheTag"] = sys.implementation.cache_tag
            return record
        finally:
            for name in tuple(sys.modules):
                if name == prefix or name.startswith(prefix + "."):
                    sys.modules.pop(name, None)


class WorkflowInterpreterOrderTests(unittest.TestCase):
    workflow = WORKFLOW

    def test_reordering_retains_every_original_action_and_check(self):
        original = dict(steps(before_workflow()))
        current = dict(steps(self.workflow.read_text()))
        # The TPM and creator census bodies are pinned exactly by test_linux_tpm_native_enrollment
        # and test_linux_creator_census_native_enrollment.
        self.assertEqual(set(original) | {"Install qemu-img for agent fixtures", "Retain public agent shard evidence",
                                          "Test real Linux TPM ownership census",
                                          "Test real Linux creator pre-VM root census"}, set(current))
        admit_public_uploader(current["Retain public agent shard evidence"])
        continuation = "      - name: {}\n        if: ${{{{ !cancelled() }}}}\n"
        for name, body in original.items():
            actual = original_agent_step(current[name]) if name == "Test affected agent tools" else current[name]
            # TEST-006 adds only a continuation after an earlier failed check
            # and lets Gradle finish its other tasks; commands stay exact.
            if actual.startswith(continuation.format(name)):
                actual = "      - name: " + name + "\n" + actual[len(continuation.format(name)):]
            actual = actual.replace("./gradlew --continue ", "./gradlew ", 1)
            self.assertEqual(body.strip(), actual.strip(), name)

    def test_prepared_runtime_and_dependencies_precede_all_python_hygiene(self):
        source = self.workflow.read_text()
        for job in ("fast-checks", "agent-tests-shard-1"):
            prepared = position(source, "Set up Python 3.12", job)
            installed = position(source, "Install agent tool dependencies", job)
            self.assertLess(prepared, installed)
            names = ("Check release hygiene", "Check documentation hygiene", "Check whitespace",
                     "Test affected agent tools") if job == "fast-checks" else ("Test affected agent tools",)
            for name in names:
                self.assertLess(installed, position(source, name, job), name)
            action = dict(steps(source, job))["Set up Python 3.12"]
            self.assertIn("uses: actions/setup-python@v5", action)
            self.assertIn('python-version: "3.12"', action)
        self.assertLess(position(source, "Set up Python 3.12", "agent-test-coverage"),
                        position(source, "Require actual complete disjoint shard coverage", "agent-test-coverage"))
        coverage_action = dict(steps(source, "agent-test-coverage"))["Set up Python 3.12"]
        self.assertIn("uses: actions/setup-python@v5", coverage_action)
        self.assertIn('python-version: "3.12"', coverage_action)

    def test_qemu_img_is_installed_before_actual_agent_fixture_selection(self):
        source = self.workflow.read_text()
        name = "Install qemu-img for agent fixtures"
        for job in ("fast-checks", "agent-tests-shard-1"):
            self.assertLess(position(source, name, job), position(source, "Test affected agent tools", job))
            self.assertIn("sudo apt-get install -y --no-install-recommends qemu-utils", dict(steps(source, job))[name])

    def test_actual_guard_accepts_producer_compiled_by_prepared_runtime(self):
        record = actual_guard_for_order(self.workflow.read_text())
        self.assertTrue(all(row["timestampValid"] for row in record["headers"]), record)
        self.assertTrue(record["unchangedSourceBytes"], record)
        self.assertTrue(record["unchangedPycBytes"], record)
        self.assertEqual("accepted", record["guard"], record)
        self.assertEqual("ssh_automatic_program.py", record["actualAutomaticSource"])

    def test_preserved_order_reaches_actual_code_guard_refusal(self):
        before_workflow()
        case = WorkflowInterpreterOrderTests("test_actual_guard_accepts_producer_compiled_by_prepared_runtime")
        case.workflow = BEFORE
        result = unittest.TestResult()
        case.run(result)
        self.assertEqual(1, result.testsRun)
        self.assertEqual([], result.errors)
        self.assertEqual([], result.skipped)
        self.assertEqual(1, len(result.failures))
        self.assertIn("Automatic transport executing source changed.", result.failures[0][1])
        self.assertIn("'accepted' != 'refused'", result.failures[0][1])

    def test_job_boundaries_duplicates_and_unapproved_action_changes_refuse(self):
        source = self.workflow.read_text()
        self.assertEqual(1, sum(name == "Set up Python 3.12" for name, body in steps(source)))
        with self.assertRaisesRegex(AssertionError, "Expected one workflow job"):
            steps(source, "missing-job")
        with self.assertRaisesRegex(AssertionError, "Expected one workflow job"):
            steps(source.replace("  agent-tests-shard-1:", "  fast-checks:", 1))
        with self.assertRaisesRegex(AssertionError, "Duplicate workflow step"):
            steps(source.replace("      - name: Check release hygiene", "      - name: Set up Python 3.12", 1))
        current = dict(steps(source))
        with self.assertRaisesRegex(AssertionError, "Unknown first-shard command"):
            original_agent_step(current["Test affected agent tools"].replace("--shard-index 0", "--shard-index 1", 1))
        with self.assertRaisesRegex(AssertionError, "Unknown public evidence"):
            admit_public_uploader(current["Retain public agent shard evidence"].replace("/plan.json", "/stdout.txt", 1))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--legacy-red", action="store_true")
    arguments, remaining = parser.parse_known_args()
    if arguments.legacy_red:
        before_workflow()
        case = WorkflowInterpreterOrderTests("test_actual_guard_accepts_producer_compiled_by_prepared_runtime")
        case.workflow = BEFORE
        result = unittest.TextTestRunner(verbosity=2).run(case)
        raise SystemExit(0 if result.wasSuccessful() else 1)
    unittest.main(argv=[sys.argv[0], *remaining])
