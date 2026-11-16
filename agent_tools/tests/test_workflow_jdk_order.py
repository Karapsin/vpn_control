"""Every hosted job sets up its pinned JDK before any step that can start Gradle.

On 450b8764 Fast Checks (run 43474297086), Android Release APK (43474297145) and
Linux Desktop Package (43474296887) failed in "Check release hygiene":
scripts/test_gradle_configuration_cache.py started Gradle 8.10.2 on the runner
image's default JDK, now 25.0.5 ("What went wrong: 25.0.5"), because these jobs set
up their pinned JDK only after that step. The workflows, that probe and the wrapper
had not changed since the green 529cc610; the image's default JDK had. The macOS
package job ran its hygiene the same way and passed only because Gradle 8.10.2
still runs on the default JDK of its image.

A step starts Gradle when it uses an action that runs the wrapper itself, or when
its command (its `run`, or an action input such as the emulator runner's `script`)
calls the wrapper or names a repository program that starts Gradle. A program
does when it calls the wrapper or names such a program outside a syntax check, a
conservative reading. Only a Python program reviewed in GRADLE_TEXT_ONLY is
exempt: every Python program under scripts/ that names the wrapper or a program
that starts Gradle is reviewed there or in GRADLE_PYTHON, so a new one is
classified before this check relies on it. A step runs Gradle on the JDK of the
job's latest setup-java step, which must install the pin whenever the step can
run. Workflows are read from *.yml and *.yaml; a layout the reader does not know,
such as a flow collection, is refused rather than read as no step.
"""
import argparse
import functools
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures/workflow_jdk_order"
SOURCE_COMMIT = "450b8764d25e038fb4815e751c618b83a9121811"
# Every hosted Gradle build pins Temurin 17; Gradle 8.10.2 cannot run on JDK 25.
PINNED_JDK = {"distribution": "temurin", "java-version": "17"}
# Conditions under which the setup still runs whenever a later step does.
CONTINUATIONS = (None, "${{ !cancelled() }}", "!cancelled()", "${{ always() }}", "always()")
# Python programs that start Gradle: each runs the wrapper of this project or of a copy of it.
GRADLE_PYTHON = frozenset((
    "scripts/prepare_desktop_update_fixture.py",
    "scripts/run_android_instrumented_tests.py",
    "scripts/test_android_instrumentation_signatures.py",
    "scripts/test_desktop_sdk_independence.py",
    "scripts/test_gradle_configuration_cache.py",
    "scripts/test_windows_packaging_graph.py",
))
# Python programs that name the wrapper or a program that starts Gradle, and start no Gradle on
# the runner: a checker's pattern and its tests, fake wrappers and drivers in temporary trees,
# asserted commands and read sources, helpers imported without a build, an instruction to the
# user, and commands sent to a guest VM that sets its own JAVA_HOME.
GRADLE_TEXT_ONLY = frozenset((
    "scripts/add_language.py",
    "scripts/capture_visual_macos_tart.py",
    "scripts/check_ci_failure_discovery.py",
    "scripts/test_ci_failure_discovery.py",
    "scripts/test_desktop_update_fixture.py",
    "scripts/test_gradle_configuration_cache_evidence.py",
    "scripts/test_linux_public_install_negative.py",
    "scripts/test_release_hygiene_runner.py",
    "scripts/test_version_metadata.py",
    "scripts/test_visual_platform.py",
    "scripts/test_visual_target.py",
    "scripts/test_windows_fixture_stage_acl.py",
    # The failing-MSI derivation and its tests name the fixture build only in docstrings: msi.dll's database API alone.
    "scripts/test_windows_native_failure_msi.py",
    "scripts/test_windows_update_fixture_workflow.py",
    "scripts/windows_native_failure_msi.py",
))
# Actions that run the project's Gradle wrapper themselves.
GRADLE_ACTIONS = frozenset(("gradle/actions/dependency-submission", "gradle/gradle-build-action",
                            "github/codeql-action/autobuild"))
WRAPPER = re.compile(r"(?<![\w.-])gradlew(?:\.bat)?(?![\w-])")
TOKEN = re.compile(r"[\w./-]+")
# A syntax check reads a program without running it; a command chained after it on its line still runs.
SYNTAX_CHECK = re.compile(r"^[ \t]*(?:run_check[ \t]+)?(?:bash[ \t]+-n|python3?[ \t]+-m[ \t]+py_compile)\b[^\n;&|]*",
                          re.MULTILINE)
# The jobs of the failed workflows whose hygiene ran first, and the macOS job whose image had not moved yet.
FAILED_JOBS = ("android-release.yml:build-release-apk", "fast-checks.yml:fast-checks",
               "linux-desktop.yml:linux-update-fixture", "linux-desktop.yml:package-linux-desktop")
LATENT_JOBS = ("macos-desktop.yml:package-macos-desktop",)
HYGIENE_CHAIN = "scripts/check_release_hygiene.sh -> scripts/test_gradle_configuration_cache.py"


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _skip(line):
    return not line.strip() or line.lstrip().startswith("#")


def _scalar(value):
    value = value.strip()
    if value[:1] in ("{", "["):
        raise ValueError("Unknown workflow flow collection: " + value)
    if len(value) > 1 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _block(lines, index, indent):
    """A block scalar: the following lines indented deeper than its key."""
    body = []
    while index < len(lines) and (not lines[index].strip() or _indent(lines[index]) > indent):
        body.append(lines[index].strip())
        index += 1
    return "\n".join(body).strip("\n") + "\n", index


def _step(lines, index, step):
    """One step's keys at indentation 8, and its `with` or `env` entries at 10."""
    while index < len(lines):
        line = lines[index]
        if _skip(line):
            index += 1
            continue
        if _indent(line) <= 6:
            break
        match = re.fullmatch(r"        ([A-Za-z_-]+):(.*)", line)
        if match is None or match.group(1) in step:
            raise ValueError("Unknown or duplicate workflow step key: " + line.strip())
        key, value = match.group(1), match.group(2).strip()
        index += 1
        if value[:1] in ("|", ">"):
            step[key], index = _block(lines, index, 8)
        elif value:
            step[key] = _scalar(value)
        else:
            entries = step[key] = {}
            while index < len(lines) and (_skip(lines[index]) or _indent(lines[index]) > 8):
                line = lines[index]
                index += 1
                if _skip(line):
                    continue
                match = re.fullmatch(r"          ([A-Za-z0-9_-]+):(.*)", line)
                if match is None or match.group(1) in entries:
                    raise ValueError("Unknown or duplicate workflow step entry: " + line.strip())
                name, value = match.group(1), match.group(2).strip()
                if value[:1] in ("|", ">"):
                    entries[name], index = _block(lines, index, 10)
                else:
                    entries[name] = _scalar(value)
    return index


def workflow_jobs(text):
    """Each job's steps in order (none for a reusable-workflow call) from the workflows' layout."""
    lines = text.replace("\r\n", "\n").split("\n")
    starts = [index for index, line in enumerate(lines) if line.rstrip() == "jobs:"]
    if len(starts) != 1:
        raise ValueError("Expected one workflow jobs mapping")
    jobs, job, in_steps = {}, None, False
    index = starts[0] + 1
    while index < len(lines):
        line = lines[index]
        if _skip(line):
            index += 1
            continue
        indent = _indent(line)
        if indent == 0:
            break
        if indent == 2:
            match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
            if match is None or match.group(1) in jobs:
                raise ValueError("Unknown or duplicate workflow job: " + line.strip())
            job = jobs[match.group(1)] = {"uses": None, "steps": []}
            in_steps = False
        elif job is None:
            raise ValueError("Workflow job content before a job: " + line.strip())
        elif indent == 4:
            if line.startswith("    - "):
                raise ValueError("Unknown workflow step layout: " + line.strip())
            key, _, value = line.strip().partition(":")
            in_steps = key == "steps"
            if in_steps and value.strip() and not value.strip().startswith("#"):
                raise ValueError("Unknown workflow step layout: " + line.strip())
            if key == "uses":
                job["uses"] = _scalar(value)
        elif in_steps:
            if indent != 6 or not line.startswith("      - "):
                raise ValueError("Unknown workflow step layout: " + line.strip())
            step = {}
            job["steps"].append(step)
            lines[index] = "        " + line[8:]
            index = _step(lines, index, step)
            continue
        index += 1
    return jobs


def step_label(step, index):
    return step.get("name") or step.get("uses") or "step %d" % (index + 1)


def gradle_action(step):
    """The action a step uses when that action runs the Gradle wrapper itself, else None."""
    action = str(step.get("uses", "")).partition("@")[0]
    return action if action in GRADLE_ACTIONS else None


def step_command(step):
    """What a step executes: its `run` script and its action inputs (the emulator runner's `script`)."""
    parts = [step.get("run")]
    if isinstance(step.get("with"), dict):
        parts.extend(step["with"].values())
    return "\n".join(part for part in parts if isinstance(part, str))


def jdk_setup(step):
    """None unless the step is setup-java; then whether it installs the pinned JDK whenever it can matter."""
    if not str(step.get("uses", "")).startswith("actions/setup-java@"):
        return None
    entries = step.get("with") if isinstance(step.get("with"), dict) else {}
    return (all(entries.get(key) == value for key, value in PINNED_JDK.items())
            and step.get("if") in CONTINUATIONS and "continue-on-error" not in step)


class Programs:
    """The programs under scripts/, the names a command can call them by, and those that start Gradle."""

    def __init__(self, root=ROOT):
        root = Path(root)
        self.names = {}
        self.texts = {}
        for path in sorted((root / "scripts").rglob("*")):
            name = path.relative_to(root).as_posix()
            if (path.suffix not in (".py", ".sh", ".ps1") or not path.is_file()
                    or name.startswith(("scripts/testdata/", "scripts/tests/"))):
                continue
            self.texts[name] = path.read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n")
            keys = {name, name[len("scripts/"):], path.name}
            if path.suffix == ".py":
                keys.add(name[:-3].replace("/", "."))
            for key in keys:
                self.names.setdefault(key, set()).add(name)
        self.starts = self._starts()
        self.gradle_naming_python = {name for name, text in self.texts.items() if name.endswith(".py") and (
            WRAPPER.search(text) or (self.references(text) - {name}) & set(self.starts))}

    def references(self, text):
        """Programs a command or shell program names, by path, path suffix or module name."""
        found = set()
        for token in TOKEN.findall(SYNTAX_CHECK.sub("", text.replace("\r\n", "\n")).replace("\\", "/")):
            parts = token.rstrip(".").split("/")
            for start in range(len(parts)):
                found.update(self.names.get("/".join(parts[start:]), ()))
        return found

    def _starts(self):
        """Each program that starts Gradle, with its shortest chain to the program that calls the wrapper."""
        starts = {name: (name,) for name in GRADLE_PYTHON if name in self.texts}
        programs = {name: SYNTAX_CHECK.sub("", text) for name, text in self.texts.items()
                    if name not in GRADLE_TEXT_ONLY}
        starts.update((name, (name,)) for name, text in programs.items() if name not in starts and WRAPPER.search(text))
        named = {name: self.references(text) - {name} for name, text in programs.items()}
        changed = True
        while changed:
            changed = False
            for name in sorted(programs):
                found = min(((len(starts[other]), other) for other in named[name] if other in starts), default=None)
                if found is not None and (name not in starts or len(starts[name]) > found[0] + 1):
                    starts[name] = (name,) + starts[found[1]]
                    changed = True
        return starts

    def gradle_start(self, command):
        """How a command starts Gradle: ("gradlew",) when it calls the wrapper, else a program chain, or None."""
        command = SYNTAX_CHECK.sub("", command.replace("\r\n", "\n"))
        if WRAPPER.search(command.replace("\\", "/")):
            return ("gradlew",)
        chains = [self.starts[name] for name in self.references(command) if name in self.starts]
        return min(chains, key=lambda chain: (len(chain), chain), default=None)


@functools.lru_cache(maxsize=None)
def repository_programs():
    return Programs()


def gradle_steps(workflows, programs):
    """Each step that can start Gradle: (workflow:job, step, how it starts Gradle, whether the pin precedes it)."""
    found = []
    for workflow, text in sorted(workflows.items()):
        for job, spec in workflow_jobs(text).items():
            pinned = False
            for index, step in enumerate(spec["steps"]):
                setup = jdk_setup(step)
                if setup is not None:
                    pinned = setup
                    continue
                action = gradle_action(step)
                chain = (action,) if action else programs.gradle_start(step_command(step))
                if chain is not None:
                    found.append((workflow + ":" + job, step_label(step, index), " -> ".join(chain), pinned))
    return found


def violations(workflows, programs):
    """Each step that can start Gradle without the pinned JDK: (workflow:job, step, how it starts Gradle)."""
    return [step[:3] for step in gradle_steps(workflows, programs) if not step[3]]


def current_workflows(root=ROOT):
    directory = Path(root) / ".github/workflows"
    return {path.name: path.read_bytes().decode("utf-8")
            for path in sorted((*directory.glob("*.yml"), *directory.glob("*.yaml")))}


def preserved_workflows():
    """The four 450b8764 workflows, exactly as committed (a Windows checkout may write them with CRLF)."""
    provenance = json.loads(FIXTURES.joinpath("provenance.json").read_bytes())
    if provenance["sourceCommit"] != SOURCE_COMMIT:
        raise ValueError("Preserved workflow authority changed")
    workflows = {}
    for row in provenance["files"]:
        raw = (FIXTURES / row["path"]).read_bytes().replace(b"\r\n", b"\n")
        if len(raw) != row["sourceBytes"] or hashlib.sha256(raw).hexdigest() != row["sourceSha256"]:
            raise ValueError("Preserved workflow changed: " + row["path"])
        workflows[Path(row["workflow"]).name] = raw.decode("utf-8")
    if sorted(workflows) != ["android-release.yml", "fast-checks.yml", "linux-desktop.yml", "macos-desktop.yml"]:
        raise ValueError("Preserved workflow set changed")
    return workflows


def sample(*steps, job="sample"):
    return ("name: Sample\non: push\njobs:\n  %s:\n    runs-on: ubuntu-latest\n    steps:\n" % job) + "".join(steps)


CHECKOUT = "      - uses: actions/checkout@v4\n"
JDK = "      - uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n          java-version: '17'\n"


class WorkflowJdkOrderTests(unittest.TestCase):
    maxDiff = None
    # The current workflows, unless a causal case substitutes the preserved ones.
    workflows = None

    def test_every_job_sets_up_the_pinned_jdk_before_any_step_that_can_start_gradle(self):
        workflows = self.workflows if self.workflows is not None else current_workflows()
        steps = gradle_steps(workflows, repository_programs())
        found = [step[:3] for step in steps if not step[3]]
        self.assertEqual([], found, "Gradle starts before the pinned JDK in "
                         + ", ".join(sorted({job for job, _, _ in found})))
        # Each of these jobs builds with Gradle, so the check cannot pass by reading no step.
        self.assertLessEqual(set(FAILED_JOBS + LATENT_JOBS), {step[0] for step in steps})

    def test_preserved_450b8764_hygiene_started_gradle_before_the_pinned_jdk(self):
        programs = repository_programs()
        self.assertEqual(("scripts/check_release_hygiene.sh", "scripts/test_gradle_configuration_cache.py"),
                         programs.starts["scripts/check_release_hygiene.sh"])
        before = preserved_workflows()
        self.assertEqual(sorted((job, "Check release hygiene", HYGIENE_CHAIN) for job in FAILED_JOBS + LATENT_JOBS),
                         sorted(violations(before, programs)))
        case = type(self)("test_every_job_sets_up_the_pinned_jdk_before_any_step_that_can_start_gradle")
        case.workflows = before
        result = unittest.TestResult()
        case.run(result)
        named = sorted(job for job in FAILED_JOBS + LATENT_JOBS if any(job in text for _, text in result.failures))
        print(json.dumps({"event": "workflow-jdk-order-causal", "sourceCommit": SOURCE_COMMIT,
                          "testsRun": result.testsRun, "failures": len(result.failures),
                          "errors": len(result.errors), "namedJobs": named}, sort_keys=True))
        self.assertEqual((1, 1, 0), (result.testsRun, len(result.failures), len(result.errors)),
                         result.failures + result.errors)
        self.assertEqual(sorted(FAILED_JOBS + LATENT_JOBS), named)

    def test_release_hygiene_runs_this_regression(self):
        # Hygiene runs in every package workflow and in Fast Checks, so a changed script is checked too.
        enrollment = "run_check python3 -m unittest agent_tools.tests.test_workflow_jdk_order"
        hygiene = ROOT.joinpath("scripts/check_release_hygiene.sh").read_bytes().decode("utf-8").splitlines()
        self.assertTrue(enrollment in hygiene, "Release hygiene does not run: " + enrollment)

    def test_every_python_program_naming_the_wrapper_or_a_gradle_program_is_reviewed(self):
        self.assertFalse(GRADLE_PYTHON & GRADLE_TEXT_ONLY)
        self.assertEqual(sorted(GRADLE_PYTHON | GRADLE_TEXT_ONLY), sorted(repository_programs().gradle_naming_python))

    def test_controls_for_jdk_setups_commands_and_programs(self):
        programs = repository_programs()
        gradle = "      - run: ./gradlew build\n"
        cases = (
            ("pinned first", sample(CHECKOUT, JDK, gradle), []),
            ("pinned after", sample(CHECKOUT, gradle, JDK), [("s.yml:sample", "step 2", "gradlew")]),
            ("other version", sample(JDK.replace("'17'", "'21'"), gradle), [("s.yml:sample", "step 2", "gradlew")]),
            ("later other version", sample(JDK, JDK.replace("'17'", "'21'"), gradle),
             [("s.yml:sample", "step 3", "gradlew")]),
            ("conditional", sample(JDK + "        if: github.event_name == 'push'\n", gradle),
             [("s.yml:sample", "step 2", "gradlew")]),
            ("ignored failure", sample(JDK + "        continue-on-error: true\n", gradle),
             [("s.yml:sample", "step 2", "gradlew")]),
            ("continuation", sample(JDK + "        if: ${{ !cancelled() }}\n", gradle), []),
            ("emulator script", sample("      - name: Emulator\n        uses: reactivecircus/android-emulator-runner@v2\n"
                                       "        with:\n          script: >-\n            set -eu; ./gradlew :app:installDebug\n",
                                       JDK), [("s.yml:sample", "Emulator", "gradlew")]),
            ("windows wrapper", sample("      - run: .\\gradlew.bat :desktopApp:test\n"),
             [("s.yml:sample", "step 1", "gradlew")]),
            ("syntax check", sample("      - run: |\n          bash -n scripts/package_linux_desktop.sh\n"
                                    "          python -m py_compile scripts/test_gradle_configuration_cache.py\n"), []),
            ("shell program", sample("      - run: bash scripts/package_linux_desktop.sh\n"),
             [("s.yml:sample", "step 1", "scripts/package_linux_desktop.sh")]),
            ("python module", sample("      - run: python3 -m scripts.test_gradle_configuration_cache\n"),
             [("s.yml:sample", "step 1", "scripts/test_gradle_configuration_cache.py")]),
            ("text-only python", sample("      - run: python3 scripts/test_visual_platform.py\n"), []),
            ("reusable call", "jobs:\n  call:\n    uses: ./.github/workflows/s.yml\n", []),
            ("program after syntax check", sample("      - run: bash -n scripts/package_linux_desktop.sh"
                                                  " && bash scripts/package_linux_desktop.sh\n"),
             [("s.yml:sample", "step 1", "scripts/package_linux_desktop.sh")]),
            ("wrapper after syntax check", sample("      - run: python -m py_compile scripts/version_metadata.py;"
                                                  " ./gradlew :app:assembleRelease\n"),
             [("s.yml:sample", "step 1", "gradlew")]),
            ("dependency submission", sample("      - uses: gradle/actions/dependency-submission@v4\n"),
             [("s.yml:sample", "gradle/actions/dependency-submission@v4", "gradle/actions/dependency-submission")]),
            ("build action", sample("      - uses: gradle/gradle-build-action@v3\n        with:\n"
                                    "          arguments: :app:assembleRelease\n"),
             [("s.yml:sample", "gradle/gradle-build-action@v3", "gradle/gradle-build-action")]),
            ("codeql autobuild", sample("      - uses: github/codeql-action/autobuild@v3\n"),
             [("s.yml:sample", "github/codeql-action/autobuild@v3", "github/codeql-action/autobuild")]),
        )
        for label, text, expected in cases:
            with self.subTest(label):
                self.assertEqual(expected, violations({"s.yml": text}, programs))

    def test_python_programs_that_run_a_gradle_program_start_gradle(self):
        programs = {
            "scripts/package_linux_desktop.sh": "./gradlew :desktopApp:packageDeb\n",
            "scripts/test_gradle_configuration_cache.py": "subprocess.run(['./gradlew', 'help'])\n",
            "scripts/build_fixture_now.py": "subprocess.run(['bash', 'scripts/package_linux_desktop.sh'], check=True)\n",
            "scripts/probe_cache.py": "subprocess.run([sys.executable, '-m', 'scripts.test_gradle_configuration_cache'])\n",
            "scripts/drive_fixture.py": "subprocess.run([sys.executable, 'scripts/build_fixture_now.py'])\n",
            "scripts/test_visual_platform.py": "self.assertIn('scripts/package_linux_desktop.sh', text)\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in programs.items():
                root.joinpath(name).parent.mkdir(parents=True, exist_ok=True)
                root.joinpath(name).write_text(text)
            scanned = Programs(root)
        cases = (
            ("build_fixture_now.py", "scripts/build_fixture_now.py -> scripts/package_linux_desktop.sh"),
            ("probe_cache.py", "scripts/probe_cache.py -> scripts/test_gradle_configuration_cache.py"),
            ("drive_fixture.py",
             "scripts/drive_fixture.py -> scripts/build_fixture_now.py -> scripts/package_linux_desktop.sh"),
        )
        for program, chain in cases:
            with self.subTest(program):
                workflow = sample("      - run: python3 scripts/%s\n" % program, JDK)
                self.assertEqual([("s.yml:sample", "step 1", chain)], violations({"s.yml": workflow}, scanned))
        self.assertEqual([], violations({"s.yml": sample("      - run: python3 scripts/test_visual_platform.py\n")},
                                        scanned))

    def test_yaml_workflows_are_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / ".github/workflows"
            root.mkdir(parents=True)
            root.joinpath("nightly.yaml").write_text(sample("      - run: ./gradlew build\n"))
            root.joinpath("package.yml").write_text(sample(JDK, "      - run: ./gradlew build\n"))
            workflows = current_workflows(directory)
        self.assertEqual(["nightly.yaml", "package.yml"], sorted(workflows))
        self.assertEqual([("nightly.yaml:sample", "step 1", "gradlew")], violations(workflows, repository_programs()))

    def test_reader_refuses_unknown_layouts(self):
        for text in ("name: missing jobs\n",
                     sample("      - run: one\n        run: two\n"),
                     sample("       - run: misplaced\n"),
                     sample("    - run: unindented\n"),
                     sample(JDK) + "  sample:\n    runs-on: ubuntu-latest\n",
                     sample("      - uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n"
                            "          distribution: zulu\n"),
                     sample().replace("    steps:\n", "    steps: [{uses: actions/checkout@v4}, {run: ./gradlew build}]\n"),
                     sample("      - uses: reactivecircus/android-emulator-runner@v2\n"
                            "        with: {script: ./gradlew :app:installDebug}\n"),
                     sample("      - uses: reactivecircus/android-emulator-runner@v2\n        with:\n"
                            "          script: [./gradlew :app:installDebug]\n")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                workflow_jobs(text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--before-red", action="store_true",
                        help="Run the order check on the preserved 450b8764 workflows (expected to fail)")
    arguments, remaining = parser.parse_known_args()
    if arguments.before_red:
        red = WorkflowJdkOrderTests("test_every_job_sets_up_the_pinned_jdk_before_any_step_that_can_start_gradle")
        red.workflows = preserved_workflows()
        outcome = unittest.TextTestRunner(verbosity=2).run(red)
        raise SystemExit(0 if outcome.wasSuccessful() else 1)
    unittest.main(argv=[sys.argv[0], *remaining])
