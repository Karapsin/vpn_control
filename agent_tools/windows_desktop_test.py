"""Closed actions that run one complete ``./gradlew :desktopApp:test`` in an owned Windows fixture VM.

``start`` takes exactly ``deploymentId``, ``operationId`` and a 40-hex ``sourceCommit`` that exists in
this repository. It makes the source archive itself (``git archive``), takes the pinned Temurin JDK and
Gradle distribution and the prepared offline dependency repository from private coordinator storage,
stages all four into the VM host's artifact cache and submits one durable host job
(windows_desktop_test_host_job over windows_scenario_host_job) under ScenarioExecutor. In the guest the
job runs the pinned runner (windows_desktop_test_guest) as the fixture's ordinary user in its interactive
session, through the existing ordinary-user task (windows_ordinary_task and its owner). Nothing is elevated.

``status`` takes ``deploymentId`` and ``operationId`` and only reads: it observes the original job and,
once it is terminal, copies back the runner summary, the complete XML result set, the Gradle console log
and the job evidence into ``.runtime/windows-desktop-test/operations/<operationId>/`` and summarizes them.
A start is never submitted twice; a lost reply is recovered by ``status`` on the same operation.

``prepare`` (direct only, coordinator network, no VM) downloads and verifies the pinned JDK and Gradle and
exports the dependency repository for the commit's build definition with Windows Compose/Skiko natives.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Callable, Mapping

from . import durable_remote_job, native_scenario_execution as execution, native_scenario_windows as windows
from . import ssh_program_execution_remote as carrier
from . import ssh_transport
from . import windows_desktop_test_guest as guest
from . import windows_desktop_test_host_job as desktop_job
from . import windows_scenario_host_job as host_job

SCENARIO_ID = desktop_job.DESKTOP_SCENARIO  # execution.DESKTOP_TEST_SCENARIO journals it; a test keeps the two equal.
# The CI toolchain of the desktop tests: actions/setup-java temurin "17" resolved 17.0.21+9 on the Windows runner
# (ci/r5-windows.log), and gradle/wrapper/gradle-wrapper.properties names Gradle 8.10.2. Both pins are the
# publishers' own checksums: the Adoptium API and the release's .sha256.txt, and services.gradle.org's .sha256.
JDK = {"version": "17.0.21+9", "javaVersion": "17.0.21", "root": "jdk-17.0.21+9",
       "fileName": "OpenJDK17U-jdk_x64_windows_hotspot_17.0.21_9.zip",
       "url": "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.21%2B9/OpenJDK17U-jdk_x64_windows_hotspot_17.0.21_9.zip",
       "sha256": "98518ecf554465057ee5509462631deeee374bc368c12a411d225cd29381f84b", "bytes": 191117380}
GRADLE = {"version": "8.10.2", "root": "gradle-8.10.2", "fileName": "gradle-8.10.2-bin.zip",
          "url": "https://services.gradle.org/distributions/gradle-8.10.2-bin.zip",
          "sha256": "31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26", "bytes": 136715430,
          # The wrapper's own directory name: base 36 of the MD5 of the distribution URL (PathAssembler).
          "wrapperHash": "a04bxjujx95o3nb99gddekhwo"}
# The ordinary task's owner writes a pending task event every 30 seconds and the run collector refuses a
# 512th, so a task that ran past about 4 h 15 min would end UNKNOWN. Gradle gets 2.5 h; the whole task 3.5 h.
GRADLE_DEADLINE_SECONDS = 150 * 60
TASK_MARGIN_SECONDS = 3600  # Verification, extraction, collection and work-folder cleanup around Gradle.
MINIMUM_FREE_BYTES = 10 * 1024 ** 3
ARCHIVE_ROLES = desktop_job.ARCHIVE_ROLES
ROW = {"evidenceClass": "test", "bootstrapMode": "python-worker", "workerAction": "qualification",
       "guestFiles": (("agent_tools/windows_ordinary_task_owner.ps1", "owner", "powershell"),
                      ("agent_tools/windows_ordinary_process_owner.py", "worker", "data"),
                      ("agent_tools/windows_desktop_test_guest.py", "runner", "data")),
       "package": None, "priorInstall": False, "readPins": (host_job.POWERSHELL_PATH,), "subfolders": (),
       "expectedExit": 0, "expectedStreams": {}, "rawStreamLimitBytes": 4 * 1024 * 1024,
       "deadlineSeconds": GRADLE_DEADLINE_SECONDS + TASK_MARGIN_SECONDS,
       "stages": ("anchor", "context", "publish", "requests", "run", "results", "evidence", "cleanup", "receipt")}
# Every byte the host job reads or pushes; render_program refuses a bundle that differs from this checkout.
BUNDLE_FILES = ("agent_tools/windows_scenario_host_job.py", "agent_tools/windows_desktop_test_host_job.py",
                "agent_tools/windows_ordinary_task.py", "agent_tools/windows_ordinary_process_owner.py",
                "agent_tools/windows_ordinary_task_owner.ps1", "agent_tools/windows_artifact_transfer.py",
                "agent_tools/readiness_windows_guest.py", "agent_tools/windows_scenario_publisher.ps1.template",
                "agent_tools/windows_scenario_system_run.ps1.template", "agent_tools/windows_desktop_test_guest.py")
STORE = (".runtime", "windows-desktop-test")
JOURNALS = (".rag_index", "windows-desktop-test-executions")
DRIVER_STATE = (".rag_index", "windows-desktop-test")
STAGING_STATE = (".rag_index", "windows-desktop-test-staging")
REQUEST_SCHEMA = "vpn-control.windows-desktop-test.request"
SUMMARY_SCHEMA = "vpn-control.windows-desktop-test.summary"
DEPENDENCY_SCHEMA = "vpn-control.windows-desktop-test.dependencies"
# Build-definition files: the dependency repository of one digest serves every commit that shares them.
_DEFINITION = re.compile(r"(?:.*/)?(?:[^/]+\.gradle\.kts|[^/]+\.gradle|gradle\.properties)\Z|gradle/(?!wrapper/gradle-wrapper\.jar\Z).+")
_VERSION_LINE = re.compile(r"(?m)^vpnControlVersion=.*$")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
# Gradle names a cache entry by its SHA-1 as a big integer in hex, so leading zeros may be missing.
_CACHE_SHA1 = re.compile(r"[0-9a-f]{1,40}\Z")
_STAGE_RATE = 512 * 1024  # Bytes a second the staging budget assumes over SSH stdin.
_PULL_CHUNK = 1024 * 1024
_EVIDENCE_LIMIT = 32 * 1024 * 1024
_EXPORT_SECONDS = 5400
WINDOWS_NATIVES = ("org/jetbrains/compose/desktop/desktop-jvm-windows-x64/", "org/jetbrains/skiko/skiko-awt-runtime-windows-x64/")
_FOREIGN_NATIVE = re.compile(r"org/jetbrains/(?:compose/desktop/desktop-jvm|skiko/skiko-awt-runtime)-(?:macos|linux)-")
_GIT = ("git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=",
        "-c", "filter.lfs.required=false", "-c", "core.quotepath=false")
# Coordinator-only: every artifact the Windows :desktopApp:test resolves, with the Windows Compose and
# Skiko natives in place of this host's. Gradle downloads them into a fresh private user home.
EXPORT_INIT_SCRIPT = """// vpn-control windows-desktop-test: the Windows dependency set of :desktopApp:test, resolved on a coordinator.
def windowsNative = { String group, String module ->
    if (group == 'org.jetbrains.compose.desktop' && module.startsWith('desktop-jvm-')) return 'desktop-jvm-windows-x64'
    if (group == 'org.jetbrains.skiko' && module.startsWith('skiko-awt-runtime-')) return 'skiko-awt-runtime-windows-x64'
    return null
}
gradle.allprojects { project ->
    project.configurations.configureEach { configuration ->
        configuration.resolutionStrategy.dependencySubstitution.all { substitution ->
            def requested = substitution.requested
            if (requested instanceof org.gradle.api.artifacts.component.ModuleComponentSelector) {
                def target = windowsNative(requested.group, requested.module)
                if (target != null && target != requested.module) {
                    substitution.useTarget("${requested.group}:${target}:${requested.version}", 'vpn-control windows desktop test')
                }
            }
        }
    }
}
gradle.projectsEvaluated {
    def app = gradle.rootProject.project(':desktopApp')
    app.tasks.register('vcdtExportResolution') {
        dependsOn app.tasks.named('testClasses')
        doLast {
            ['testRuntimeClasspath', 'runtimeClasspath'].each { name -> app.configurations.getByName(name).resolve() }
        }
    }
}
"""
EXPORT_TASK = ":desktopApp:vcdtExportResolution"


class DesktopTestError(ValueError):
    """A finite refusal; ``reason`` is the only text a reply carries."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _need(condition: Any, reason: str) -> None:
    if not condition:
        raise DesktopTestError(reason)


def _uuid(value: Any, reason: str) -> str:
    _need(type(value) is str and _UUID.fullmatch(value) is not None, reason)
    return value


def start_inputs(inputs: Any) -> tuple[str, str, str]:
    _need(isinstance(inputs, Mapping) and set(inputs) == {"deploymentId", "operationId", "sourceCommit"}, "desktop_test_inputs_invalid")
    deployment = _uuid(inputs["deploymentId"], "desktop_test_deployment_invalid")
    operation = _uuid(inputs["operationId"], "desktop_test_operation_invalid")
    _need(type(inputs["sourceCommit"]) is str and _COMMIT.fullmatch(inputs["sourceCommit"]) is not None, "desktop_test_source_commit_invalid")
    return deployment, operation, inputs["sourceCommit"]


def status_inputs(inputs: Any) -> tuple[str, str]:
    _need(isinstance(inputs, Mapping) and set(inputs) == {"deploymentId", "operationId"}, "desktop_test_inputs_invalid")
    return _uuid(inputs["deploymentId"], "desktop_test_deployment_invalid"), _uuid(inputs["operationId"], "desktop_test_operation_invalid")


# Private coordinator storage: owner-only directories and create-only files.
def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(path)
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077,
          "desktop_test_private_state_unsafe")
    return path


def _create_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _read_private(path: Path, limit: int = 16 * 1024 * 1024) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077
              and info.st_size <= limit, "desktop_test_private_state_unsafe")
        return stream.read(limit + 1)


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _store(root: Path, *parts: str) -> Path:
    return _private_directory(root.joinpath(*STORE, *parts))


def _relative(root: Path, path: Path) -> str:
    return str(path.relative_to(root))


def verify_file(path: Path, sha256: str, size: int) -> bool:
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size != size or info.st_uid != os.getuid():
            return False
        digest, total = guest.sha256_file(path)
    except (OSError, guest.StageFailure):
        return False
    return total == size and digest == sha256


# Source: the commit itself, read without any working tree, filter or line-ending conversion.
def _git(root: Path, *arguments: str, stdout=subprocess.PIPE, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run([*_GIT, "-C", str(root), *arguments], stdin=subprocess.DEVNULL, stdout=stdout,
                          stderr=subprocess.PIPE, timeout=timeout, check=False)


def source_facts(root: Path, commit: str) -> dict[str, Any]:
    """The commit exists here, is a desktop source and names the pinned Gradle distribution."""
    _need(type(commit) is str and _COMMIT.fullmatch(commit) is not None, "desktop_test_source_commit_invalid")
    found = _git(root, "rev-parse", "--verify", "--quiet", "--end-of-options", commit + "^{commit}")
    _need(found.returncode == 0 and found.stdout.decode("ascii", "replace").strip() == commit, "desktop_test_source_commit_unknown")
    shown = _git(root, "cat-file", "-p", commit + ":gradle/wrapper/gradle-wrapper.properties")
    _need(shown.returncode == 0 and len(shown.stdout) <= 65536, "desktop_test_source_not_desktop")
    with tempfile.TemporaryDirectory(prefix="vcdt-wrapper-") as directory:
        properties = Path(directory) / "gradle-wrapper.properties"
        properties.write_bytes(shown.stdout)
        values = guest.wrapper_properties(str(properties))
    _need(values.get("distributionUrl") == GRADLE["url"], "desktop_test_gradle_distribution_unpinned")
    _need(not values.get("distributionSha256Sum") or values["distributionSha256Sum"] == GRADLE["sha256"],
          "desktop_test_gradle_distribution_unpinned")
    _need(_git(root, "cat-file", "-e", commit + ":desktopApp/build.gradle.kts").returncode == 0, "desktop_test_source_not_desktop")
    return {"sourceCommit": commit, "dependencyDigest": dependency_digest(root, commit)}


def dependency_digest(root: Path, commit: str) -> str:
    """The build definition that decides every resolved dependency; the product version line does not."""
    listed = _git(root, "ls-tree", "-r", "-z", "--full-tree", commit)
    _need(listed.returncode == 0, "desktop_test_source_commit_unknown")
    rows = []
    for record in listed.stdout.split(b"\0"):
        if not record:
            continue
        meta, _, name = record.partition(b"\t")
        mode, kind, blob = meta.decode("ascii").split()
        path = name.decode("utf-8")
        if kind != "blob" or _DEFINITION.fullmatch(path) is None:
            continue
        if path == "gradle.properties":
            body = _git(root, "cat-file", "blob", blob)
            _need(body.returncode == 0, "desktop_test_source_commit_unknown")
            rows.append([path, hashlib.sha256(_VERSION_LINE.sub("vpnControlVersion=", body.stdout.decode("utf-8"), 1).encode()).hexdigest()])
        else:
            rows.append([path, blob])
    _need(any(path == "settings.gradle.kts" for path, _ in rows), "desktop_test_source_not_desktop")
    return hashlib.sha256(json.dumps(sorted(rows), separators=(",", ":")).encode()).hexdigest()


def source_archive(root: Path, commit: str) -> dict[str, Any]:
    """``git archive`` of exactly the commit, made once and kept privately; its digest binds every run of it."""
    directory = _store(root, "sources")
    target = directory / (commit + ".zip")
    record_path = directory / (commit + ".json")
    if record_path.exists():
        record = json.loads(_read_private(record_path))
        _need(verify_file(target, record["sha256"], record["bytes"]), "desktop_test_source_archive_changed")
        return {"path": target, **record}
    if target.exists():  # An archive whose record was never written is derived data: make it again.
        target.unlink()
    temporary = directory / (commit + "." + uuid.uuid4().hex + ".partial")
    try:
        with open(temporary, "xb") as output:
            os.chmod(temporary, 0o600)
            made = _git(root, "archive", "--format=zip", commit, stdout=output, timeout=1800)
        _need(made.returncode == 0, "desktop_test_source_archive_failed")
        try:  # The runner's own checks: a tree Windows cannot hold, or too large a one, is refused here already.
            facts = guest.inspect_zip(str(temporary), guest.SOURCE_LIMITS)
            digest, size = guest.sha256_file(str(temporary))
        except guest.StageFailure as failure:
            raise DesktopTestError("desktop_test_source_archive_refused:" + failure.code) from None
        _need(size <= guest.ARCHIVE_LIMIT, "desktop_test_source_archive_bound")
        os.link(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    record = {"sourceCommit": commit, "sha256": digest, "bytes": size, "entries": facts["entries"], "files": facts["files"],
              "uncompressedBytes": facts["bytes"], "git": "archive --format=zip"}
    _create_private(record_path, _canonical(record))
    return {"path": target, **record}


def toolchain_path(root: Path, pin: Mapping[str, Any]) -> Path:
    return _store(root, "toolchain") / pin["sha256"]


def download(pin: Mapping[str, Any], target: Path, *, opener: Callable[..., Any] = urllib.request.urlopen, timeout: int = 120) -> None:
    """The publisher's file, verified against its pinned size and digest before it may be used."""
    temporary = target.with_name(target.name + "." + uuid.uuid4().hex + ".partial")
    digest, total = hashlib.sha256(), 0
    try:
        request = urllib.request.Request(pin["url"])  # urllib's generic User-Agent: nothing names this project to the publisher.
        with opener(request, timeout=timeout) as response, open(temporary, "xb") as output:
            os.chmod(temporary, 0o600)
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                _need(total <= pin["bytes"], "desktop_test_toolchain_digest")
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        _need(total == pin["bytes"] and digest.hexdigest() == pin["sha256"], "desktop_test_toolchain_digest")
        os.link(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def ensure_toolchain(root: Path, pin: Mapping[str, Any], *, opener: Callable[..., Any] | None = None) -> Path:
    target = toolchain_path(root, pin)
    if not target.exists():
        _need(opener is not None, "desktop_test_toolchain_unprepared")
        download(pin, target, opener=opener)
    _need(verify_file(target, pin["sha256"], pin["bytes"]), "desktop_test_toolchain_changed")
    return target


# The offline dependency repository: Gradle's own download cache, in Maven layout, verified file by file.
def files_to_repository(files_root: Path, repository: Path) -> list[dict[str, Any]]:
    """files-2.1/<group>/<module>/<version>/<sha1>/<file> becomes <group path>/<module>/<version>/<file>."""
    rows, seen = [], {}
    for group in sorted(files_root.iterdir()):
        _need(group.is_dir() and not group.is_symlink(), "dependency_export_cache_layout")
        for path in sorted(group.rglob("*")):
            if path.is_dir() and not path.is_symlink():
                continue
            parts = path.relative_to(files_root).parts
            _need(len(parts) == 5 and not path.is_symlink() and path.is_file(), "dependency_export_cache_layout")
            group_name, module, version, sha1, leaf = parts
            body = path.read_bytes()
            _need(_CACHE_SHA1.fullmatch(sha1) is not None and hashlib.sha1(body).hexdigest().lstrip("0") == sha1.lstrip("0"),
                  "dependency_export_cache_digest")
            relative = "/".join([*group_name.split("."), module, version, leaf])
            guest.entry_parts(relative)
            digest = hashlib.sha256(body).hexdigest()
            if relative.casefold() in seen:
                _need(seen[relative.casefold()] == digest, "dependency_export_conflict")
                continue
            seen[relative.casefold()] = digest
            destination = repository.joinpath(*relative.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
            rows.append({"path": relative, "sha256": digest, "bytes": len(body)})
    _need(rows, "dependency_export_empty")
    paths = [row["path"] for row in rows]
    _need(all(any(path.startswith(prefix) for path in paths) for prefix in WINDOWS_NATIVES), "dependency_export_windows_natives_missing")
    _need(not any(_FOREIGN_NATIVE.search(path) for path in paths), "dependency_export_foreign_natives")
    return sorted(rows, key=lambda row: row["path"])


def deterministic_zip(repository: Path, rows: list[dict[str, Any]], target: Path) -> None:
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for row in rows:
            info = zipfile.ZipInfo(row["path"], date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type, info.create_system, info.external_attr = zipfile.ZIP_DEFLATED, 3, 0o100644 << 16
            archive.writestr(info, repository.joinpath(*row["path"].split("/")).read_bytes())
    os.chmod(target, 0o600)


def dependency_cache(root: Path, digest: str) -> dict[str, Any]:
    directory = root.joinpath(*STORE, "dependencies", digest)
    manifest = directory / "manifest.json"
    _need(manifest.exists(), "desktop_test_dependencies_unprepared")
    value = json.loads(_read_private(manifest, 64 * 1024 * 1024))
    _need(type(value) is dict and value.get("schema") == DEPENDENCY_SCHEMA and value.get("dependencyDigest") == digest,
          "desktop_test_dependencies_changed")
    archive = directory / "repository.zip"
    _need(verify_file(archive, value["zipSha256"], value["zipBytes"]), "desktop_test_dependencies_changed")
    return {"path": archive, "sha256": value["zipSha256"], "bytes": value["zipBytes"], "entries": value["entries"]}


def _java_home(root: Path) -> str:
    from . import local_build_environment
    environment = local_build_environment.apply(root, dict(os.environ))
    java_home = environment.get("JAVA_HOME")
    _need(type(java_home) is str and os.path.isfile(os.path.join(java_home, "bin", "java")), "dependency_export_java_unavailable")
    return java_home


def export_dependencies(root: Path, commit: str, digest: str, archive: Path, gradle_zip: Path, *,
                        java_home: str, run: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    """Run the commit's own wrapper and pinned Gradle on this coordinator once, with network, into a fresh
    private user home; keep exactly what it downloaded as the Windows offline repository."""
    directory = root.joinpath(*STORE, "dependencies", digest)
    _need(not directory.exists(), "dependency_export_exists")
    work = _private_directory(root.joinpath(*STORE, "work", "export-" + uuid.uuid4().hex))
    log, staging = work / "export-console.log", None
    try:
        source = work / "src"
        guest.extract_zip(str(archive), str(source), guest.SOURCE_LIMITS)
        home = work / "gradle-home"
        dists = home / "wrapper" / "dists" / ("gradle-" + GRADLE["version"] + "-bin")
        dists.mkdir(parents=True)
        guest.extract_zip(str(gradle_zip), str(dists / GRADLE["wrapperHash"]), guest.TOOL_LIMITS, root=GRADLE["root"])
        (dists / GRADLE["wrapperHash"] / ("gradle-" + GRADLE["version"] + "-bin.zip.ok")).touch(exist_ok=False)
        init = work / "export-dependencies.gradle"
        init.write_text(EXPORT_INIT_SCRIPT, encoding="ascii")
        environment = {key: value for key, value in os.environ.items() if key.upper() not in guest.REMOVED_ENVIRONMENT}
        environment.update(JAVA_HOME=java_home, GRADLE_USER_HOME=str(home), ANDROID_HOME=str(work / "no-android-sdk"),
                           ANDROID_SDK_ROOT=str(work / "no-android-sdk"))
        argv = [os.path.join(java_home, "bin", "java"), *guest.WRAPPER_JVM_OPTIONS, "-jar", str(source.joinpath(*guest.WRAPPER_JAR)),
                "--no-daemon", "--console=plain", "--init-script", str(init), *guest.GRADLE_PROPERTIES, EXPORT_TASK]
        with open(log, "xb") as output:
            done = run(argv, cwd=str(source), env=environment, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                       timeout=_EXPORT_SECONDS, check=False)
        _need(done.returncode == 0, "dependency_export_gradle_failed")
        repository = work / "repository"
        rows = files_to_repository(home / "caches" / "modules-2" / "files-2.1", repository)
        _need(len(rows) <= guest.TOOL_LIMITS["entries"], "dependency_export_bound")
        staging = _private_directory(directory.parent) / ("." + digest + "." + uuid.uuid4().hex)
        staging.mkdir(mode=0o700)
        deterministic_zip(repository, rows, staging / "repository.zip")
        zip_digest, zip_bytes = guest.sha256_file(str(staging / "repository.zip"))
        _need(zip_bytes <= guest.ARCHIVE_LIMIT, "dependency_export_bound")
        manifest = {"schema": DEPENDENCY_SCHEMA, "schemaVersion": 1, "dependencyDigest": digest, "exportSourceCommit": commit,
                    "gradle": GRADLE["version"], "exportTask": EXPORT_TASK, "windowsNatives": list(WINDOWS_NATIVES),
                    "entries": len(rows), "bytes": sum(row["bytes"] for row in rows), "zipSha256": zip_digest,
                    "zipBytes": zip_bytes, "files": rows}
        _create_private(staging / "manifest.json", _canonical(manifest))
        shutil.copyfile(log, staging / "export-console.log")
        os.rename(staging, directory)
    except BaseException as error:
        if staging is not None:  # Never renamed into place: no repository of this digest exists.
            shutil.rmtree(staging, ignore_errors=True)
        if log.is_file():  # The work folder goes; the console log of a failed export stays for reading.
            kept = _private_directory(root.joinpath(*STORE, "export-failures")) / (digest + "-" + uuid.uuid4().hex + ".log")
            shutil.copyfile(log, kept)
            os.chmod(kept, 0o600)
        if isinstance(error, guest.StageFailure):  # An archive or cache entry the runner would refuse too.
            raise DesktopTestError("dependency_export_refused:" + error.code) from None
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return dependency_cache(root, digest)


def prepare(root: Path | str, inputs: Any, *, opener: Callable[..., Any] = urllib.request.urlopen,
            run: Callable[..., Any] = subprocess.run, java_home: str | None = None) -> dict[str, Any]:
    """Direct coordinator step before a start: toolchain downloads, source archive and dependency export."""
    _need(isinstance(inputs, Mapping) and set(inputs) == {"sourceCommit"}, "desktop_test_inputs_invalid")
    root = Path(root).resolve(strict=True)
    facts = source_facts(root, inputs["sourceCommit"])
    jdk, gradle = ensure_toolchain(root, JDK, opener=opener), ensure_toolchain(root, GRADLE, opener=opener)
    archive = source_archive(root, facts["sourceCommit"])
    try:
        dependencies = dependency_cache(root, facts["dependencyDigest"])
        exported = False
    except DesktopTestError as error:
        _need(error.reason == "desktop_test_dependencies_unprepared", error.reason)
        dependencies = export_dependencies(root, facts["sourceCommit"], facts["dependencyDigest"], archive["path"], gradle,
                                           java_home=java_home or _java_home(root), run=run)
        exported = True
    return {"state": "prepared", "sourceCommit": facts["sourceCommit"], "dependencyDigest": facts["dependencyDigest"],
            "dependenciesExported": exported, "archives": {
                "source": {"sha256": archive["sha256"], "bytes": archive["bytes"]},
                "jdk": {"sha256": JDK["sha256"], "bytes": JDK["bytes"], "version": JDK["version"]},
                "gradle": {"sha256": GRADLE["sha256"], "bytes": GRADLE["bytes"], "version": GRADLE["version"]},
                "dependencies": {"sha256": dependencies["sha256"], "bytes": dependencies["bytes"], "entries": dependencies["entries"]}},
            "productAction": False, "nativeActionAllowed": False}


def prepared_archives(root: Path, facts: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """The four archives of one run, re-verified now; nothing is downloaded or exported here."""
    source = source_archive(root, facts["sourceCommit"])
    dependencies = dependency_cache(root, facts["dependencyDigest"])
    archives = {"source": {"sha256": source["sha256"], "bytes": source["bytes"], "localPath": str(source["path"])},
                "jdk": {"sha256": JDK["sha256"], "bytes": JDK["bytes"], "localPath": str(ensure_toolchain(root, JDK))},
                "gradle": {"sha256": GRADLE["sha256"], "bytes": GRADLE["bytes"], "localPath": str(ensure_toolchain(root, GRADLE))},
                "dependencies": {"sha256": dependencies["sha256"], "bytes": dependencies["bytes"], "localPath": str(dependencies["path"])}}
    _need(len({row["sha256"] for row in archives.values()}) == len(archives), "desktop_test_archives_alias")
    return archives


def deployment_binding(root: Path, deployment: str) -> dict[str, Any]:
    """The deployment this checkout started: an ordinary fixture, never a visual clone or an image template."""
    from . import readiness_windows_registration as registration
    from . import readiness_windows_remote as packets
    try:
        binding, _, _ = registration.original_binding(root, deployment)
    except (OSError, ValueError, KeyError, TypeError):
        raise DesktopTestError("desktop_test_deployment_unknown") from None
    try:
        provider, spec, setup, _ = packets.validate_binding(binding)
    except (OSError, ValueError, KeyError, TypeError):
        raise DesktopTestError("desktop_test_deployment_foreign") from None
    _need(provider == "raw-qemu-windows" and spec.deployment_id == deployment and "purpose" not in setup
          and binding["context"].get("network") is None, "desktop_test_deployment_foreign")
    return binding


def bundle(root: Path) -> tuple[dict[str, bytes], str]:
    files = {relative: (root / relative).read_bytes() for relative in BUNDLE_FILES}
    manifest = {"schemaVersion": 1, "scenarioId": SCENARIO_ID,
                "files": [{"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)} for path, raw in sorted(files.items())]}
    return files, hashlib.sha256(_canonical(manifest)).hexdigest()


def render_program(plan: execution.ScenarioPlan, binding: Mapping[str, Any], target: Mapping[str, Any], record: Mapping[str, Any],
                   files: Mapping[str, bytes]) -> tuple[str, str]:
    """One fixed host program: the scenario job, this job over it, the canonical guards, the closed plan and files."""
    from . import windows_vm_deploy_remote as deployment
    data = str(PurePosixPath(target["home"]) / windows._DATA_PARENT / plan.environment / plan.correlation_id)
    entries = {path: {"sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)} for path, raw in files.items()}
    job_plan = {"schemaVersion": 1, "operationId": plan.correlation_id, "scenarioId": SCENARIO_ID, "machine": plan.environment,
                "bundleHash": plan.bundle_hash, "user": binding["setup"]["user"], "dataDirectory": data, "row": ROW,
                "files": entries, "stopAfter": None, "artifactDirectory": str(PurePosixPath(target["home"]) / windows._ARTIFACT_PARENT),
                "packages": {role: {"sha256": record["archives"][role]["sha256"], "bytes": record["archives"][role]["bytes"]}
                             for role in ARCHIVE_ROLES},
                "product": None, "prior": {}, "desktopTest": record["desktopTest"]}
    payload = gzip.compress(json.dumps({path: base64.b64encode(raw).decode("ascii") for path, raw in files.items()},
                                       sort_keys=True).encode("ascii"), mtime=0)
    text = files["agent_tools/windows_scenario_host_job.py"].decode("utf-8")
    marker = "    _CANONICAL_INSTANCE_DEFINITIONS()\n"
    _need(text.count(marker) == 1, "desktop_test_host_source")
    text = text.replace(marker, "".join("    " + line + "\n" for line in windows._instance_definitions().splitlines()))
    bindings = {"SPEC": binding["spec"], "SETUP": binding["setup"], "CONTEXT": binding["context"], "PLAN": windows._plain(job_plan),
                "FILES_GZ": base64.b64encode(payload).decode("ascii")}
    source = (text + "\n" + files["agent_tools/windows_desktop_test_host_job.py"].decode("utf-8") + "\n"
              + "\n".join(key + "=" + repr(value) for key, value in bindings.items()) + "\n"
              + deployment.guest_rpc_definitions() + "\nwire=partial_wire=-1\nQGA_PEER_PID=QGA_GUARD=None\n"
              + "raise SystemExit(_host_main())\n")
    compile(source, "windows desktop test job", "exec")
    return source, data


def _operation_directory(root: Path, operation: str) -> Path:
    return root.joinpath(*STORE, "operations", operation)


def _record(root: Path, operation: str) -> dict[str, Any] | None:
    path = _operation_directory(root, operation) / "request.json"
    if not path.exists():
        return None
    value = json.loads(_read_private(path))
    _need(type(value) is dict and value.get("schema") == REQUEST_SCHEMA and value.get("operationId") == operation,
          "desktop_test_operation_record_invalid")
    return value


class DesktopTestDriver(windows.NativeScenarioWindowsDriver):
    """The scenario driver's transport, carrier, identity and observation, with this job's admission and collection."""

    def __init__(self, repository_root: Path | str, *, route: str = "direct", timeout_seconds: int = 30, ssh_binary: str = "ssh",
                 configuration_root: Path | str | None = None):
        super().__init__(repository_root, lambda plan: None, timeout_seconds, ssh_binary, configuration_root, route=route)

    def _local(self, plan: execution.ScenarioPlan) -> Path:
        return self.configuration_root.joinpath(*DRIVER_STATE, plan.correlation_id)

    def _stage(self, config, plan, package, directory, role="package"):
        """The host's content-addressed cache; a present matching copy is kept and never sent again."""
        arguments = (package["sha256"], str(package["bytes"]))
        found = self._send(config, plan.host, windows._py(windows._STAGE, *arguments, "check"), seconds=windows._OBSERVE_SECONDS,
                           keep=directory / ("stage-check-" + role))
        _need(found is not None and found.get("state") in ("present", "absent"), "desktop_test_stage_unavailable")
        if found["state"] == "present":
            return "present"
        staged = self._send(config, plan.host, windows._py(windows._STAGE, *arguments, "write"), seconds=self._stage_seconds(package),
                            keep=directory / ("stage-write-" + role), stdin_path=Path(package["localPath"]))
        _need(staged is not None and staged.get("state") == "staged", "desktop_test_stage_unavailable")
        return "staged"

    @staticmethod
    def _stage_seconds(package: Mapping[str, Any]) -> int:
        return max(windows._STAGE_SECONDS, 120 + package["bytes"] // _STAGE_RATE)

    def stage_archives(self, plan: execution.ScenarioPlan, archives: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
        """Before any journal: staging fills a content-addressed host cache and has no guest effect."""
        directory = _private_directory(self.configuration_root.joinpath(*STAGING_STATE, plan.correlation_id, uuid.uuid4().hex))
        config = ssh_transport.load_config(self.configuration_root)
        seconds = self.timeout_seconds + sum(windows._OBSERVE_SECONDS + self._stage_seconds(row) for row in archives.values())
        states = {}
        with self._admitted(config, plan, seconds):
            for role in ARCHIVE_ROLES:
                states[role] = self._stage(config, plan, archives[role], directory, role)
        return states

    def submit(self, plan: execution.ScenarioPlan) -> execution.JobIdentity:
        record = _record(self.root, plan.correlation_id)
        _need(record is not None and record["plan"] == plan.as_dict(), "desktop_test_plan_differs")
        files, digest = bundle(self.root)
        _need(digest == plan.bundle_hash, "desktop_test_bundle_differs_from_checkout")
        binding = deployment_binding(self.root, plan.environment)
        _need(binding["spec"]["host"] == plan.host, "desktop_test_deployment_host_differs")
        directory = self._local(plan)
        _private_directory(directory.parent)
        try:
            os.mkdir(directory, 0o700)  # Create-only: a second submit of this operation stops here.
        except FileExistsError:
            raise DesktopTestError("desktop_test_job_already_exists") from None
        _create_private(directory / windows.ROUTE_NAME, _canonical({"schemaVersion": 1, "correlationId": plan.correlation_id,
                                                                     "route": self.route}))
        config = ssh_transport.load_config(self.configuration_root)
        seconds = self.timeout_seconds + 2 * windows._SUBMIT_SECONDS + windows._OBSERVE_SECONDS * len(ARCHIVE_ROLES)
        with self._admitted(config, plan, seconds):
            target = self._send(config, plan.host, windows._py(windows._TARGET), seconds=self.timeout_seconds, keep=directory / "target")
            _need(target is not None, "desktop_test_target_unavailable")
            for role in ARCHIVE_ROLES:
                row = record["archives"][role]
                found = self._send(config, plan.host, windows._py(windows._STAGE, row["sha256"], str(row["bytes"]), "check"),
                                   seconds=windows._OBSERVE_SECONDS, keep=directory / ("stage-check-" + role))
                _need(found is not None and found.get("state") == "present", "desktop_test_stage_missing")
            source, data = render_program(plan, binding, target, record, files)
            program = {"language": "python3", "source": source, "args": [], "cwd": target["home"], "targetContext": target}
            _create_private(directory / "program.json", json.dumps({"program": program, "dataDirectory": data}, sort_keys=True).encode())
            packet = self._send(config, plan.host, carrier.prepare_command(plan.correlation_id, program, durable_remote_job.owner_source()),
                                seconds=windows._SUBMIT_SECONDS, keep=directory / "prepare")
            _need(packet is not None, "desktop_test_preparation_unavailable")
            carrier.durable_command(plan.correlation_id, program, packet, mode="observe")  # Validate with an inert render.
            _create_private(directory / "admission.json", json.dumps(packet, sort_keys=True).encode())
            reply = self._send(config, plan.host, carrier.durable_command(plan.correlation_id, program, packet, mode="submit", wait_seconds=2),
                               seconds=windows._SUBMIT_SECONDS, keep=directory / "submit")
        _need(reply is not None, "desktop_test_submit_unavailable")
        status = reply.get("status")
        _need(isinstance(status, Mapping) and status.get("operationId") == plan.correlation_id, "desktop_test_submit_unavailable")
        return self._identity(plan, {"dataDirectory": data}, status.get("owner"))

    def _uac_pending(self, plan: execution.ScenarioPlan, program: Mapping[str, Any]) -> str | None:
        """No prompt belongs to this job; the running reason names the runner's last reported stage instead."""
        try:
            value = self._read_job_file(plan, program["dataDirectory"], "desktop-progress.json")
        except (OSError, ValueError, ssh_transport.SshConfigError):
            return None
        if not isinstance(value, Mapping) or not isinstance(value.get("stage"), str) or not re.fullmatch(r"[a-z][a-z-]{0,31}", value["stage"]):
            return None
        elapsed = value.get("elapsedSeconds")
        return "desktop_test_running:" + value["stage"] + (":" + str(elapsed) + "s" if type(elapsed) is int else "")

    def _summary(self, plan: execution.ScenarioPlan, raw: bytes, job_exit: Any) -> dict[str, Any] | None:
        receipt = json.loads(raw)
        if (not isinstance(receipt, dict) or not isinstance(job_exit, Mapping) or job_exit.get("operationId") != plan.correlation_id
                or type(job_exit.get("exitCode")) is not int or receipt.get("exitCode") != job_exit["exitCode"]
                or receipt.get("scenarioId") != SCENARIO_ID or receipt.get("correlationId") != plan.correlation_id):
            return None
        desktop = receipt.get("desktopTest") if isinstance(receipt.get("desktopTest"), Mapping) else {}
        return {"state": "collected", "scenarioId": plan.scenario_id, "correlationId": plan.correlation_id,
                "result": receipt.get("result"), "exitCode": job_exit["exitCode"],
                "desktopTest": {"runnerOutcome": desktop.get("runnerOutcome"), "gradleExitCode": desktop.get("gradleExitCode")},
                "actualReceiptRaw": raw.decode("utf-8"), "actualReceiptSha256": hashlib.sha256(raw).hexdigest()}

    def read_terminal(self, plan: execution.ScenarioPlan) -> tuple[bytes, dict[str, Any]] | None:
        """The original job's receipt and exit record, read without contacting its VM."""
        retained = self._retained(plan)
        if retained is None:
            return None
        config = ssh_transport.load_config(self.configuration_root)
        with self._admitted(config, plan, windows._OBSERVE_SECONDS):
            reply = self._send(config, plan.host, windows._py(windows._COLLECT, retained["program"]["dataDirectory"]),
                               seconds=windows._OBSERVE_SECONDS)
        if reply is None or reply.get("state") != "collected":
            return None
        return base64.b64decode(reply["receipt"], validate=True), reply.get("jobExit")

    def pull(self, plan: execution.ScenarioPlan, receipt: Mapping[str, Any]) -> dict[str, Any]:
        """Copy the job's kept files to private storage, resuming a partial copy; every file is checked by its receipt digest."""
        retained = self._retained(plan)
        _need(retained is not None, "desktop_test_job_unknown")
        data = retained["program"]["dataDirectory"]
        wanted = []
        evidence = receipt.get("evidence")
        if isinstance(evidence, Mapping):
            _need(isinstance(evidence.get("name"), str) and windows._EVIDENCE_NAME.fullmatch(evidence["name"]) is not None
                  and type(evidence.get("bytes")) is int and 0 <= evidence["bytes"] <= _EVIDENCE_LIMIT, "desktop_test_evidence_invalid")
            wanted.append((evidence["name"], evidence["bytes"], evidence.get("sha256")))
        desktop = receipt.get("desktopTest") if isinstance(receipt.get("desktopTest"), Mapping) else {}
        for name, row, limit in ((guest.SUMMARY_LEAF, desktop.get("summary"), desktop_job.SUMMARY_READ_LIMIT),
                                 (guest.RESULTS_LEAF, desktop.get("results"), guest.RESULTS_ZIP_LIMIT)):
            if isinstance(row, Mapping):
                _need(type(row.get("bytes")) is int and 0 < row["bytes"] <= limit, "desktop_test_results_invalid")
                wanted.append((name, row["bytes"], row.get("sha256")))
        for _, _, digest in wanted:
            _need(isinstance(digest, str) and _SHA256.fullmatch(digest) is not None, "desktop_test_results_invalid")
        directory = _private_directory(_operation_directory(self.root, plan.correlation_id))
        chunks = sum(-(-size // _PULL_CHUNK) for _, size, _ in wanted)
        config = ssh_transport.load_config(self.configuration_root)
        pulled = {}
        with self._admitted(config, plan, min(7200, windows._OBSERVE_SECONDS + 30 * max(1, chunks))):
            for name, size, digest in wanted:
                pulled[name] = self._pull_one(config, plan, data, name, size, digest, directory)
        return pulled

    def _pull_one(self, config, plan, data: str, name: str, size: int, digest: str, directory: Path) -> str:
        final = directory / name
        if final.exists():
            _need(verify_file(final, digest, size), "desktop_test_results_changed")
            return "present"
        partial = directory / (name + ".partial")
        if not partial.exists():
            _create_private(partial, b"")
        have = os.lstat(partial).st_size
        _need(have <= size, "desktop_test_results_changed")
        with open(partial, "ab") as output:
            while have < size:
                reply = self._send(config, plan.host, windows._py(windows._PULL, data, name, str(have), str(_PULL_CHUNK)),
                                   seconds=windows._OBSERVE_SECONDS)
                _need(reply is not None and reply.get("size") == size, "desktop_test_results_unavailable")
                part = base64.b64decode(reply["data"], validate=True)
                _need(0 < len(part) <= min(_PULL_CHUNK, size - have), "desktop_test_results_unavailable")
                output.write(part)
                output.flush()
                os.fsync(output.fileno())
                have += len(part)
        _need(verify_file(partial, digest, size), "desktop_test_results_changed")
        os.link(partial, final)
        partial.unlink()
        return "pulled"

    def collect(self, plan: execution.ScenarioPlan, identity: execution.JobIdentity) -> Mapping[str, Any] | None:
        if self._retained(plan) is None or identity.pid is None:
            return None
        try:
            terminal = self.read_terminal(plan)
            if terminal is None:
                return None
            raw, job_exit = terminal
            summary = self._summary(plan, raw, job_exit)
            if summary is None:
                return None
            directory = _private_directory(_operation_directory(self.root, plan.correlation_id))
            receipt_path = directory / "receipt.json"
            if receipt_path.exists():
                _need(_read_private(receipt_path) == raw, "desktop_test_receipt_changed")
            else:
                _create_private(receipt_path, raw)
            self.pull(plan, json.loads(raw))
        except (OSError, ValueError, KeyError, TypeError, ssh_transport.SshConfigError):
            return None
        return summary


def _executor(root: Path, driver: DesktopTestDriver) -> execution.ScenarioExecutor:
    return execution.ScenarioExecutor(root.joinpath(*JOURNALS), driver)


def start(root: Path | str, inputs: Any, *, route: str = "direct", driver: DesktopTestDriver | None = None) -> dict[str, Any]:
    """Admit, stage and submit once. Every refusal here comes before any journal or guest effect."""
    deployment, operation, commit = start_inputs(inputs)
    root = Path(root).resolve(strict=True)
    binding = deployment_binding(root, deployment)
    _need(_record(root, operation) is None and not root.joinpath(*JOURNALS, operation + ".json").exists(), "desktop_test_operation_exists")
    facts = source_facts(root, commit)
    archives = prepared_archives(root, facts)
    files, bundle_hash = bundle(root)
    plan = execution.ScenarioPlan.from_mapping({
        "scenarioId": SCENARIO_ID, "host": binding["spec"]["host"], "environment": deployment, "bundleHash": bundle_hash,
        "correlationId": operation, "artifactIds": {role + "Archive": "sha256-" + archives[role]["sha256"] for role in ARCHIVE_ROLES}})
    driver = driver or DesktopTestDriver(root, route=route)
    staged = driver.stage_archives(plan, archives)
    desktop = {"sourceCommit": commit, "jdk": {"root": JDK["root"], "javaVersion": JDK["javaVersion"]},
               "gradle": {key: GRADLE[key] for key in ("version", "root", "wrapperHash")} | {"distributionUrl": GRADLE["url"]},
               "gradleDeadlineSeconds": GRADLE_DEADLINE_SECONDS, "minimumFreeBytes": MINIMUM_FREE_BYTES}
    record = {"schema": REQUEST_SCHEMA, "schemaVersion": 1, "operationId": operation, "deploymentId": deployment, "sourceCommit": commit,
              "dependencyDigest": facts["dependencyDigest"], "route": driver.route, "plan": plan.as_dict(), "desktopTest": desktop,
              "archives": {role: {"sha256": row["sha256"], "bytes": row["bytes"]} for role, row in archives.items()},
              "toolchain": {"jdk": JDK["version"], "gradle": GRADLE["version"]}, "staged": staged}
    directory = _private_directory(_operation_directory(root, operation))
    try:
        _create_private(directory / "request.json", _canonical(record))
    except FileExistsError:
        raise DesktopTestError("desktop_test_operation_exists") from None
    result = _executor(root, driver).start(plan.as_dict())
    return {"state": result.get("state"), "reason": result.get("reason"), "operationId": operation, "deploymentId": deployment,
            "sourceCommit": commit, "sourceArchiveSha256": archives["source"]["sha256"], "jobIdentity": result.get("jobIdentity"),
            "toolchain": record["toolchain"], "staged": staged, "nextAction": "windows-desktop-test-status",
            "replayAllowed": False, "productAction": False}


# Results: the XML set as Gradle wrote it, the console log and the runner's summary, read back here.
def parse_results(directory: Path) -> dict[str, Any]:
    classes, skipped, failed = [], [], []
    totals = {"classes": 0, "tests": 0, "failures": 0, "errors": 0, "skipped": 0, "timeSeconds": 0.0}
    for path in sorted(directory.rglob("*.xml")):
        raw = path.read_bytes()
        # No document type or entity in the prolog; a test's own output may quote either inside its CDATA.
        start = raw.find(b"<testsuite")
        prolog = (raw if start < 0 else raw[:start]).upper()
        _need(b"<!DOCTYPE" not in prolog and b"<!ENTITY" not in prolog, "desktop_test_results_xml_declaration")
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            raise DesktopTestError("desktop_test_results_xml_invalid") from None
        suites = [root] if root.tag == "testsuite" else root.findall("testsuite") if root.tag == "testsuites" else []
        for suite in suites:
            try:
                counts = {key: int(suite.get(key, "0")) for key in ("tests", "failures", "errors", "skipped")}
                seconds = float(suite.get("time", "0"))
            except ValueError:
                raise DesktopTestError("desktop_test_results_xml_invalid") from None
            name = suite.get("name") or path.stem
            classes.append({"name": name, **counts, "timeSeconds": seconds, "file": str(path.relative_to(directory))})
            totals["classes"] += 1
            for key in ("tests", "failures", "errors", "skipped"):
                totals[key] += counts[key]
            totals["timeSeconds"] += seconds
            for case in suite.findall("testcase"):
                identity = {"class": case.get("classname") or name, "name": case.get("name")}
                if case.find("skipped") is not None:
                    skipped.append(identity)
                for kind in ("failure", "error"):
                    element = case.find(kind)
                    if element is not None:
                        failed.append({**identity, "kind": kind, "type": element.get("type")})
    totals["timeSeconds"] = round(totals["timeSeconds"], 3)
    return {"totals": totals, "classes": classes, "skippedTests": skipped, "failedTests": failed}


def classify_console(text: str) -> dict[str, Any]:
    failing = re.search(r"Execution failed for task '([^']+)'", text)
    offline = re.search(r"No cached version of .{1,300} available for offline mode|Could not resolve all (?:files|dependencies|artifacts)"
                        r"|Could not resolve (?:plugin|artifact) |Plugin \[id: '[^']+'.{0,200}\] was not found", text)
    return {"build": "successful" if "BUILD SUCCESSFUL" in text else "failed" if "BUILD FAILED" in text else "unknown",
            "failingTask": failing[1] if failing else None, "offlineResolutionFailure": offline is not None,
            "failingTests": "There were failing tests" in text}


def outcome(receipt: Mapping[str, Any], runner: Mapping[str, Any] | None, console: Mapping[str, Any] | None,
            results: Mapping[str, Any] | None) -> dict[str, Any]:
    """Tool outcome and test outcome apart: a failing test is a result, a failed stage is the tool's."""
    code = receipt.get("exitCode")
    stage = receipt.get("stage")
    failure = receipt.get("failure")
    gradle = (runner or {}).get("gradle") or {}
    tool = {0: "completed", 1: "failed", 2: "refused"}.get(code, "unknown")
    failed_stage = None if tool == "completed" else stage
    if isinstance(failure, str) and failure.startswith("desktop_runner:"):
        failed_stage = "runner:" + failure.split(":")[1]
    tests = (results or {}).get("totals")
    if gradle.get("exitCode") is None and not gradle.get("deadline"):
        test_outcome = "not-run"
    elif gradle.get("deadline"):
        test_outcome = "timed-out"
    elif gradle["exitCode"] == 0:
        test_outcome = "passed" if tests is not None and tests["failures"] == 0 and tests["errors"] == 0 else "inconsistent"
    elif (console or {}).get("failingTests") or (console or {}).get("failingTask") == ":desktopApp:test" or (
            tests is not None and tests["failures"] + tests["errors"] > 0):
        test_outcome = "failed"
    elif (console or {}).get("offlineResolutionFailure"):
        # A dependency the prepared repository lacks is this tool's failure, not the source's.
        test_outcome, tool, failed_stage = "not-run", "failed", "gradle-dependencies"
    else:
        test_outcome = "build-failed"
    return {"toolOutcome": tool, "failedStage": failed_stage, "failure": failure if tool != "completed" else None,
            "testOutcome": test_outcome}


def finalize(root: Path, record: Mapping[str, Any], receipt_raw: bytes, *, job_known: bool) -> dict[str, Any]:
    """The summary of one terminal operation, written once from the files already copied back."""
    directory = _operation_directory(root, record["operationId"])
    summary_path = directory / "summary.json"
    if summary_path.exists():
        return json.loads(_read_private(summary_path))
    receipt = json.loads(receipt_raw)
    runner_path, results_path = directory / "desktop-test-summary.json", directory / "desktop-test-results.zip"
    runner = json.loads(_read_private(runner_path)) if runner_path.exists() else None
    results = console = results_error = None
    extracted = directory / "results"
    if results_path.exists():
        try:
            if not extracted.exists():  # Whole or not at all: a later status never reads half an extraction.
                partial = directory / ("results." + uuid.uuid4().hex + ".partial")
                try:
                    guest.extract_zip(str(results_path), str(partial),
                                      {"entries": guest.RESULT_ENTRY_LIMIT + 1,
                                       "bytes": guest.RESULT_TOTAL_LIMIT + guest.CONSOLE_HEAD + guest.CONSOLE_TAIL + 1024,
                                       "file": max(guest.RESULT_FILE_LIMIT, guest.CONSOLE_HEAD + guest.CONSOLE_TAIL + 1024)})
                    os.rename(partial, extracted)
                finally:
                    shutil.rmtree(partial, ignore_errors=True)
            if (extracted / "test-results").exists():
                results = parse_results(extracted / "test-results")
            log = extracted / guest.CONSOLE_LEAF
            if log.exists():
                console = classify_console(log.read_text(encoding="utf-8", errors="replace"))
        except (guest.StageFailure, DesktopTestError) as error:
            results, results_error = None, getattr(error, "reason", None) or getattr(error, "code", "desktop_test_results_unreadable")
    decided = outcome(receipt, runner, console, results)
    if results_error is not None and decided["toolOutcome"] == "completed":
        # The copied results are this tool's to read: a set it cannot read is its own failure, named by its stage.
        decided.update(toolOutcome="failed", failedStage="results-read", failure=results_error)
    if not job_known:
        decided.update(toolOutcome="unknown", failedStage=receipt.get("stage"), failure=receipt.get("failure"))
    gradle = (runner or {}).get("gradle") or {}
    desktop = receipt.get("desktopTest") or {}
    summary = {"schema": SUMMARY_SCHEMA, "schemaVersion": 1, "operationId": record["operationId"], "deploymentId": record["deploymentId"],
               "sourceCommit": record["sourceCommit"], "route": record["route"], "dependencyDigest": record["dependencyDigest"],
               "archives": record["archives"], "toolchain": {"jdk": JDK["version"], "jdkRelease": (runner or {}).get("jdkRelease"),
                                                             "gradle": GRADLE["version"]},
               **decided, "jobExitCode": receipt.get("exitCode"), "jobStage": receipt.get("stage"),
               "gradle": {key: gradle.get(key) for key in ("exitCode", "seconds", "deadline", "leftoverProcesses", "consoleBytes")},
               "console": console, "tests": (results or {}).get("totals"), "classes": (results or {}).get("classes"),
               "skippedTests": (results or {}).get("skippedTests"), "failedTests": (results or {}).get("failedTests"),
               "runner": {key: (runner or {}).get(key) for key in ("outcome", "failedStage", "failure", "stages", "seconds",
                                                                   "freeBytesBefore", "freeBytesAfter", "productProcessesBefore",
                                                                   "productProcessesAfter", "productState", "workRoot")},
               "hygiene": {"workRootDeleted": ((runner or {}).get("workRoot") or {}).get("deleted"),
                           "archivesCleanup": (desktop.get("cleanup") or {}).get("state"), "disk": desktop.get("disk"),
                           "profileEntriesAdded": ((runner or {}).get("profileEntries") or {}).get("added")},
               "files": {"receipt": "receipt.json", "runnerSummary": runner_path.name if runner else None,
                         "resultsZip": results_path.name if results_path.exists() else None,
                         "resultsDirectory": "results/test-results" if results else None,
                         "consoleLog": "results/" + guest.CONSOLE_LEAF if console is not None else None}}
    _create_private(summary_path, _canonical(summary))
    return summary


def status(root: Path | str, inputs: Any, *, driver: DesktopTestDriver | None = None) -> dict[str, Any]:
    """Observe the original operation; once terminal, copy back and summarize it. Never submits."""
    deployment, operation = status_inputs(inputs)
    root = Path(root).resolve(strict=True)
    record = _record(root, operation)
    _need(record is not None, "desktop_test_operation_unknown")
    _need(record["deploymentId"] == deployment, "desktop_test_operation_deployment_mismatch")
    driver = driver or DesktopTestDriver(root, route=record["route"])
    base = {"operationId": operation, "deploymentId": deployment, "sourceCommit": record["sourceCommit"], "replayAllowed": False,
            "productAction": False}
    try:
        result = _executor(root, driver).status(operation)
    except execution.ScenarioExecutionError:
        return {**base, "state": "not-submitted", "reason": "desktop_test_intent_without_journal"}
    view = {**base, "state": result.get("state"), "reason": result.get("reason"), "jobIdentity": result.get("jobIdentity")}
    directory = _operation_directory(root, operation)
    plan = execution.ScenarioPlan.from_mapping(record["plan"])
    complete = result.get("state") == "terminal" and result.get("collectionState") == "complete"
    unknown_exit = result.get("state") == "unknown" and str(result.get("reason", "")).startswith("job_exit_unknown")
    if unknown_exit and not (directory / "summary.json").exists():
        # An open outcome never authorizes a replay; its receipt and kept files are still read.
        try:
            terminal = driver.read_terminal(plan)
            if terminal is not None and not (directory / "receipt.json").exists():
                _create_private(directory / "receipt.json", terminal[0])
            if terminal is not None:
                driver.pull(plan, json.loads(terminal[0]))
        except (OSError, ValueError, KeyError, TypeError, ssh_transport.SshConfigError):
            pass
    if (complete or unknown_exit) and (directory / "receipt.json").exists():
        summary = finalize(root, record, _read_private(directory / "receipt.json"), job_known=complete)
        view.update(toolOutcome=summary["toolOutcome"], failedStage=summary["failedStage"], failure=summary["failure"],
                    testOutcome=summary["testOutcome"], tests=summary["tests"],
                    skippedTests=len(summary["skippedTests"] or []), failedTests=(summary["failedTests"] or [])[:20],
                    jdk=JDK["version"], gradle=GRADLE["version"], sourceArchiveSha256=record["archives"]["source"]["sha256"],
                    hygiene=summary["hygiene"],
                    files={key: (_relative(root, directory / value) if value else None) for key, value in summary["files"].items()},
                    summary=_relative(root, directory / "summary.json"))
    return view


def _print(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, sort_keys=True, indent=2))


def main(argv: list[str] | None = None) -> int:
    """Direct (non-MCP) entry: the same functions the closed vm_workflow actions call, with route "direct"."""
    parser = argparse.ArgumentParser(description="One complete :desktopApp:test in an owned Windows fixture VM.")
    sub = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "start", "status"):
        command = sub.add_parser(name)
        if name != "prepare":
            command.add_argument("--deployment-id", required=True)
            command.add_argument("--operation-id", required=True)
        if name != "status":
            command.add_argument("--source-commit", required=True)
    arguments = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.action == "prepare":
            result = prepare(root, {"sourceCommit": arguments.source_commit})
            ok = True
        elif arguments.action == "start":
            result = start(root, {"deploymentId": arguments.deployment_id, "operationId": arguments.operation_id,
                                  "sourceCommit": arguments.source_commit}, route="direct")
            ok = result["state"] == "submitted"
        else:
            result = status(root, {"deploymentId": arguments.deployment_id, "operationId": arguments.operation_id})
            ok = result["state"] == "submitted" or result.get("toolOutcome") == "completed"
    except DesktopTestError as error:
        _print({"state": "refused", "reason": error.reason, "replayAllowed": False})
        return 2
    _print({**result, "ok": ok})
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
