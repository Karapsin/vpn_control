"""CI and build environment drift is locked down.

GitHub moved `ubuntu-latest` to ubuntu-26.04 (JDK 25, Rust coreutils) and broke
CI without a repository change. Everything the build depends on is therefore
pinned and checked here: runner images, container images, third-party actions,
the Gradle distribution, the JDK toolchain, Gradle dependency checksums and the
hashed Python requirements. Only the advisory weekly canary follows the moving
`-latest` labels.
"""
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"
CANARY = "environment-canary.yml"
SHA_USE = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"^v\d+\.\d+\.\d+$")
DIGEST_IMAGE = re.compile(r"^\S+@sha256:[0-9a-f]{64}$")
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")

# Ubuntu jobs that stay on the host runner. Anything not containerized by digest
# must be listed with its reason; "unverified" means nobody has proven the job
# in a container image yet, so it keeps the pinned host image rather than risk
# red CI. Remove an entry when the job is containerized.
UBUNTU_HOST_EXCEPTIONS = {
    "android-release.yml::reuse": "unverified: queries the Actions API with python3 on the host image",
    "fast-checks.yml::reuse": "unverified: queries the Actions API with python3 on the host image",
    "linux-desktop.yml::reuse": "unverified: queries the Actions API with python3 on the host image",
    "macos-desktop.yml::reuse": "unverified: queries the Actions API with python3 on the host image",
    "windows-desktop.yml::reuse": "unverified: queries the Actions API with python3 on the host image",
    "gradle-cache-warm.yml::resolve": "unverified: needs the gh CLI and the Actions token",
    "android-release.yml::build-release-apk": "unverified: relies on the Android SDK and NDK preinstalled on the host image",
    "fast-checks.yml::fast-checks": "privileged: sudo kernel/TPM ownership census, qemu apt installs, xvfb display",
    "fast-checks.yml::agent-tests-shard-0": "unverified: sudo apt-get qemu-utils for agent fixtures",
    "fast-checks.yml::agent-tests-shard-1": "unverified: sudo apt-get qemu-utils for agent fixtures",
    "fast-checks.yml::agent-tests-shard-2": "unverified: sudo apt-get qemu-utils for agent fixtures",
    "fast-checks.yml::agent-tests-shard-3": "unverified: sudo apt-get qemu-utils for agent fixtures",
    "fast-checks.yml::agent-tests-shard-4": "unverified: sudo apt-get qemu-utils for agent fixtures",
    "fast-checks.yml::agent-tests-shard-5": "unverified: sudo apt-get qemu-utils for agent fixtures",
    "fast-checks.yml::agent-tests-shard-6": "unverified: sudo apt-get qemu-utils for agent fixtures",
    "fast-checks.yml::agent-tests-shard-7": "unverified: sudo apt-get qemu-utils for agent fixtures",
    "fast-checks.yml::agent-test-coverage": "unverified: setup-python and artifact download inside a container",
    "linux-desktop.yml::linux-update-fixture": "unverified: sudo apt-get rpm/fakeroot packaging and jpackage",
    "linux-desktop.yml::package-linux-desktop": "unverified: sudo apt-get rpm/fakeroot packaging and jpackage",
    "release-publish.yml::publish": "unverified: needs the gh CLI and the Actions token",
    "visual-regression.yml::linux": "host-only: Xvfb, openbox and tray GUI session with sudo apt installs",
    "vpn-integration.yml::contracts": "unverified: fast contract suite not proven in a container",
    "vpn-integration.yml::build-linux": "unverified: sudo apt-get rpm/fakeroot packaging and jpackage",
    "vpn-integration.yml::linux-full-vpn": "host-only: TUN device, privileged docker run and networking",
    "vpn-integration.yml::android-full-vpn": "host-only: KVM and the Android emulator",
}


def workflow_files():
    return sorted(WORKFLOWS.glob("*.yml"))


def jobs(text):
    """{job id: its lines} for the top-level jobs mapping."""
    lines = text.splitlines()
    try:
        start = lines.index("jobs:") + 1
    except ValueError:
        return {}
    result, current = {}, None
    for line in lines[start:]:
        if line and not line.startswith(" "):
            break
        match = JOB_KEY.match(line)
        if match:
            current = match.group(1)
            result[current] = []
        elif current is not None:
            result[current].append(line)
    return result


def runner_labels(text):
    """Every runs-on value and matrix os entry, split into labels."""
    labels = []
    for line in text.splitlines():
        match = re.match(r"^\s+(?:runs-on|os):\s*(.+?)\s*(?:#.*)?$", line)
        if match:
            labels += re.findall(r"[A-Za-z][\w.-]*", match.group(1).strip("[]"))
    return labels


def unpinned_uses(text):
    """Problems for each non-local `uses:` that is not a full SHA with a vX.Y.Z comment."""
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        match = re.match(r"^\s*(?:-\s+)?uses:\s*(\S+)(?:\s+#\s*(\S+))?\s*$", line)
        if not match or match.group(1).startswith("./"):
            continue
        reference, comment = match.groups()
        if not SHA_USE.match(reference):
            problems.append(f"{number}: {reference} is not pinned to a full commit SHA")
        elif not (comment and VERSION_COMMENT.match(comment)):
            problems.append(f"{number}: {reference} lacks a '# vX.Y.Z' comment")
    return problems


def ubuntu_job_problems(name, text):
    problems, seen = [], set()
    for job, body in jobs(text).items():
        block = "\n".join(body)
        runs = re.search(r"^    runs-on:\s*(\S+)", block, re.M)
        if not runs or not runs.group(1).startswith("ubuntu"):
            continue
        key = f"{name}::{job}"
        seen.add(key)
        image = re.search(r"^    container:\s*\n      image:\s*(\S+)", block, re.M)
        contained = bool(image and DIGEST_IMAGE.match(image.group(1)))
        if image and not contained:
            problems.append(f"{key}: container image is not pinned by sha256 digest")
        elif not contained and key not in UBUNTU_HOST_EXCEPTIONS:
            problems.append(f"{key}: ubuntu job is neither containerized by digest nor in the exception list")
        elif contained and key in UBUNTU_HOST_EXCEPTIONS:
            problems.append(f"{key}: containerized job is still in the exception list")
    return problems, seen


class RunnerImageTests(unittest.TestCase):
    def test_only_the_canary_follows_a_latest_label(self):
        for path in workflow_files():
            latest = [label for label in runner_labels(path.read_text()) if label.endswith("-latest")]
            if path.name == CANARY:
                self.assertTrue(latest, "the canary exists to follow the -latest labels")
            else:
                self.assertEqual([], latest, f"{path.name} must pin its runner image")

    def test_label_reader_sees_inline_and_matrix_forms(self):
        self.assertEqual(["ubuntu-latest"], runner_labels("    runs-on: ubuntu-latest\n"))
        self.assertEqual(["ubuntu-latest", "macos-latest"], runner_labels("        os: [ubuntu-latest, macos-latest]\n"))

    def test_canary_is_scheduled_advisory_and_not_required(self):
        text = (WORKFLOWS / CANARY).read_text()
        self.assertRegex(text, r"(?m)^  schedule:\n    - cron:")
        self.assertIn("continue-on-error: true", text)
        for label in ("ubuntu-latest", "windows-latest", "macos-latest"):
            self.assertIn(label, text)
        required = (ROOT / ".github/required-workflows.json").read_text()
        self.assertNotIn(CANARY, required)
        self.assertNotIn("Environment Canary", required)


class ActionPinTests(unittest.TestCase):
    def test_every_action_is_a_full_sha_with_a_version_comment(self):
        for path in workflow_files():
            self.assertEqual([], unpinned_uses(path.read_text()), path.name)

    def test_checker_refuses_tags_branches_and_missing_comments(self):
        self.assertEqual(1, len(unpinned_uses("      - uses: actions/checkout@v4\n")))
        self.assertEqual(1, len(unpinned_uses("        uses: actions/checkout@main\n")))
        self.assertEqual(1, len(unpinned_uses("        uses: actions/checkout@" + "a" * 40 + "\n")))
        self.assertEqual(1, len(unpinned_uses("        uses: actions/checkout@" + "a" * 39 + " # v4.1.0\n")))
        self.assertEqual([], unpinned_uses("        uses: actions/checkout@" + "a" * 40 + " # v4.1.0\n"))
        self.assertEqual([], unpinned_uses("        uses: gradle/actions/setup-gradle@" + "b" * 40 + " # v4.4.4\n"))
        self.assertEqual([], unpinned_uses("    uses: ./.github/workflows/windows-update-fixture.yml\n"))


class ContainerTests(unittest.TestCase):
    def test_every_ubuntu_job_is_containerized_by_digest_or_an_excepted_host_job(self):
        seen, problems = set(), []
        for path in workflow_files():
            found, keys = ubuntu_job_problems(path.name, path.read_text())
            problems += found
            seen |= keys
        self.assertEqual([], problems)
        self.assertEqual([], sorted(set(UBUNTU_HOST_EXCEPTIONS) - seen), "stale exception entries")
        for key, reason in UBUNTU_HOST_EXCEPTIONS.items():
            self.assertRegex(reason, r"^(unverified|host-only|privileged): .{8,}", key)

    def test_checker_refuses_tag_only_images_and_unlisted_host_jobs(self):
        host = "jobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps: []\n"
        self.assertEqual(1, len(ubuntu_job_problems("x.yml", host)[0]))
        tag = "jobs:\n  build:\n    runs-on: ubuntu-24.04\n    container:\n      image: python:3.12\n"
        self.assertIn("digest", ubuntu_job_problems("x.yml", tag)[0][0])
        good = tag.replace("python:3.12", "python:3.12@sha256:" + "c" * 64)
        self.assertEqual([], ubuntu_job_problems("x.yml", good)[0])


class GradleTests(unittest.TestCase):
    def modules(self):
        settings = (ROOT / "settings.gradle.kts").read_text()
        return [ROOT / name.strip(":").replace(":", "/") / "build.gradle.kts" for name in re.findall(r'include\("([^"]+)"\)', settings)]

    def test_every_jvm_module_declares_the_jdk17_toolchain(self):
        modules = self.modules()
        self.assertGreaterEqual(len(modules), 6)
        for build in modules:
            self.assertTrue(build.is_file(), str(build))
            self.assertRegex(build.read_text(), r"(?m)^\s*jvmToolchain\(17\)\s*$", f"{build.parent.name} lacks jvmToolchain(17)")

    def test_workflows_install_the_same_jdk(self):
        for path in workflow_files():
            for version in re.findall(r'java-version:\s*"?(\d+)"?', path.read_text()):
                self.assertEqual("17", version, path.name)

    def test_wrapper_distribution_is_checksum_pinned(self):
        text = (ROOT / "gradle/wrapper/gradle-wrapper.properties").read_text()
        self.assertRegex(text, r"(?m)^distributionSha256Sum=[0-9a-f]{64}$")
        self.assertIn("validateDistributionUrl=true", text)

    def test_dependency_verification_metadata_covers_every_native_platform(self):
        text = (ROOT / "gradle/verification-metadata.xml").read_text()
        self.assertIn("<verify-metadata>true</verify-metadata>", text)
        self.assertIn("<verify-signatures>false</verify-signatures>", text)
        self.assertNotRegex(text, r"<(md5|sha1|sha512) ", "only sha256 checksums are recorded")
        self.assertGreater(text.count("<sha256 "), 100)
        for platform in ("linux-x64", "windows-x64", "macos-x64", "macos-arm64"):
            self.assertIn(f'name="skiko-awt-runtime-{platform}"', text, platform)
        # Every recorded artifact has a checksum (no empty component entries).
        self.assertNotRegex(text, r"<component [^>]*>\s*</component>")


class PythonRequirementTests(unittest.TestCase):
    LOCK = ROOT / "agent_tools/requirements-mcp.txt"

    def requirements(self):
        text = self.LOCK.read_text().replace("\\\n", " ")
        return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith(("#", "--"))]

    def test_lock_pins_every_package_exactly_with_hashes(self):
        rows = self.requirements()
        self.assertGreater(len(rows), 10)
        for row in rows:
            self.assertRegex(row, r"^[A-Za-z0-9_.-]+==[\w.!+]+(\s*;[^#]*?)?\s+--hash=sha256:[0-9a-f]{64}", row[:60])
            self.assertNotRegex(row.split("--hash")[0], r"[<>~]=?(?!=)", row[:60])

    def test_human_source_exists_and_names_the_direct_dependencies(self):
        source = (ROOT / "agent_tools/requirements-mcp.in").read_text()
        for name in ("mcp", "vncdotool", "cryptography", "pycdlib"):
            self.assertRegex(source, rf"(?m)^{name}[=<>]")
            self.assertRegex(self.LOCK.read_text(), rf"(?m)^{name}==")

    def test_every_install_requires_hashes(self):
        sources = [*workflow_files(), ROOT / "agent_tools/mcp_server.sh"]
        count = 0
        for path in sources:
            for line in path.read_text().splitlines():
                if "pip install" in line and "requirements" in line:
                    count += 1
                    self.assertIn("--require-hashes", line, f"{path.name}: {line.strip()}")
        self.assertGreaterEqual(count, 7)


class DependabotTests(unittest.TestCase):
    def test_actions_gradle_and_pip_are_updated_weekly_in_groups_on_dev(self):
        text = (ROOT / ".github/dependabot.yml").read_text()
        for ecosystem in ("github-actions", "gradle", "pip"):
            self.assertIn(f"package-ecosystem: {ecosystem}", text)
        self.assertEqual(3, text.count("interval: weekly"))
        self.assertEqual(3, text.count("target-branch: dev"))
        self.assertEqual(3, text.count("groups:"))


if __name__ == "__main__":
    unittest.main()
