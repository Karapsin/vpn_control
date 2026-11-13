"""In-guest runner of one complete ``:desktopApp:test`` (windows_desktop_test), as the ordinary user.

The ordinary task worker (windows_ordinary_process_owner, action ``qualification``) starts this file
with the admitted Python 3.13.15 and ``-I -S -B``. It uses the standard library only, accepts no
argument but its pinned request, never elevates and never contacts the network:

1. verifies the request bytes and the four pushed archives (source, JDK, Gradle, dependency repository);
2. extracts them into a short work folder in the ordinary user's profile;
3. runs the source's own Gradle wrapper exactly as ``gradlew.bat`` does, offline, against the extracted
   repository, inside a job object, with a deadline;
4. keeps the complete ``desktopApp/build/test-results/test`` XML set and the console log in one zip
   beside its summary in the operation root;
5. deletes the work folder it created.

A failing test is data in the summary; only a failed stage of this runner makes it exit nonzero.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import ntpath
import os
import posixpath
import re
import shutil
import stat
import subprocess
import time
import zipfile

REQUEST_SCHEMA = "vpn-control.windows-desktop-test.runner-request"
SUMMARY_SCHEMA = "vpn-control.windows-desktop-test.runner-summary"
PROGRESS_SCHEMA = "vpn-control.windows-desktop-test.progress"
REQUEST_LIMIT = 65536
WORK_PREFIX = "vcdt-"
OPERATION_PREFIX = "VpnControlOrdinary-"
WORKSPACE_PREFIX = "C:\\ProgramData\\VpnControlOrdinaryTask-"
ARCHIVE_LEAVES = {"source": "desktop-test-source.zip", "jdk": "desktop-test-jdk.zip",
                  "gradle": "desktop-test-gradle.zip", "dependencies": "desktop-test-dependencies.zip"}
REQUEST_LEAF = "desktop-test-request.json"
SUMMARY_LEAF = "desktop-test-summary.json"
RESULTS_LEAF = "desktop-test-results.zip"
PROGRESS_LEAF = "desktop-test-progress.json"
CONSOLE_LEAF = "gradle-console.log"
INIT_LEAF = "offline-repositories.gradle"
RESULTS_DIRECTORY = ("desktopApp", "build", "test-results", "test")
WRAPPER_PROPERTIES = ("gradle", "wrapper", "gradle-wrapper.properties")
WRAPPER_JAR = ("gradle", "wrapper", "gradle-wrapper.jar")
# gradlew.bat: "%JAVA_EXE%" %DEFAULT_JVM_OPTS% ... "-Dorg.gradle.appname=%APP_BASE_NAME%" -jar gradle-wrapper.jar %*
WRAPPER_JVM_OPTIONS = ("-Xmx64m", "-Xms64m", "-Dorg.gradle.appname=gradlew")
# One process tree that ends with the build (no Kotlin daemon outlives it) and no toolchain download.
GRADLE_PROPERTIES = ("-Pkotlin.compiler.execution.strategy=in-process", "-Porg.gradle.java.installations.auto-download=false")
# The task and its options are constants: no request field reaches the command line except derived paths.
GRADLE_ARGUMENTS = ("--offline", "--no-daemon", "--console=plain", *GRADLE_PROPERTIES, ":desktopApp:test")
REPOSITORY_VARIABLE = "VPN_CONTROL_DESKTOP_TEST_REPOSITORY"
HOME_VARIABLE = "VPN_CONTROL_DESKTOP_TEST_HOME"
# CI installs the pinned .NET SDK before :desktopApp:test; the guest gets none. The desktop tests that build their
# native probes start the program this variable names (else dotnet.exe from PATH), so the runner names one that does
# not exist in its work folder: those tests then fail to start it, the same way on every fixture, and no SDK the
# fixture may have restores NuGet packages from the network. The coordinator reports exactly those failures apart.
DOTNET_VARIABLE = "VPN_CONTROL_TEST_DOTNET"
DOTNET_ABSENT = ("no-dotnet", "dotnet.exe")
# Read by Gradle before any build script: every settings repository becomes the one extracted
# repository (the build forbids project repositories). --offline then refuses any remote one a plugin
# could still add. Test JVMs get user.home in the work folder, so what they write there (Skiko's
# extracted natives, a test's own files) is deleted with it and the fixture user's own state is not theirs.
OFFLINE_INIT_SCRIPT = """// vpn-control windows-desktop-test: offline repository for one in-guest :desktopApp:test.
def repository = new File(System.getenv('VPN_CONTROL_DESKTOP_TEST_REPOSITORY')).toURI()
settingsEvaluated { settings ->
    settings.pluginManagement.repositories.clear()
    settings.pluginManagement.repositories.maven { url = repository; name = 'vpnControlDesktopTestOffline' }
    settings.dependencyResolutionManagement.repositories.clear()
    settings.dependencyResolutionManagement.repositories.maven { url = repository; name = 'vpnControlDesktopTestOffline' }
}
def testHome = System.getenv('VPN_CONTROL_DESKTOP_TEST_HOME')
gradle.allprojects { project ->
    project.tasks.withType(Test).configureEach { task -> task.systemProperty('user.home', testHome) }
}
"""
REMOVED_ENVIRONMENT = frozenset({"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "JAVA_OPTS", "GRADLE_OPTS",
                                 "GRADLE_USER_HOME", "CLASSPATH", "ANDROID_HOME", "ANDROID_SDK_ROOT", "PYTHONPATH",
                                 "PYTHONHOME", REPOSITORY_VARIABLE, HOME_VARIABLE, DOTNET_VARIABLE,
                                 "VPN_CONTROL_TEST_DOTNET_ROOT"})
PRODUCT_IMAGES = frozenset({"vpn-control.exe", "vpn-control-cli.exe", "sing-box.exe"})
STATE_ROOTS = ((".vpn-control-desktop",), ("AppData", "Local", "vpn-control"))
SOURCE_LIMITS = {"entries": 20000, "bytes": 2 * 1024 ** 3, "file": 512 * 1024 ** 2}
TOOL_LIMITS = {"entries": 40000, "bytes": 4 * 1024 ** 3, "file": 1024 ** 3}
ARCHIVE_LIMIT = 1024 ** 3
RESULT_FILE_LIMIT = 128 * 1024 ** 2
RESULT_TOTAL_LIMIT = 512 * 1024 ** 2
RESULT_ENTRY_LIMIT = 20000
RESULTS_ZIP_LIMIT = 192 * 1024 ** 2
CONSOLE_HEAD, CONSOLE_TAIL = 48 * 1024 ** 2, 16 * 1024 ** 2
FINGERPRINT_LIMIT = 20000
HEARTBEAT_SECONDS = 60
TERMINATE_SECONDS = 60
CLEANUP_ATTEMPTS = 6
STAGES = ("preflight", "verify-archives", "extract-source", "source-wrapper", "extract-jdk", "extract-gradle",
          "extract-dependencies", "init-script", "gradle", "collect", "state-check")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}\Z")
_JAVA_VERSION = re.compile(r"[1-9][0-9]?(?:\.[0-9]{1,3}){0,3}\Z")
_CODE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_RESERVED = frozenset({"CON", "PRN", "AUX", "NUL", *{"COM%d" % i for i in range(1, 10)}, *{"LPT%d" % i for i in range(1, 10)}})


class StageFailure(Exception):
    """A finite refusal of one runner stage; ``code`` is the only text that leaves the guest."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class PlatformError(OSError):
    """A native step with a fixed name; its Windows error number is kept, never its message."""

    def __init__(self, code, number=0):
        super().__init__(number, code)
        self.code, self.number = code, number


def need(condition, code):
    if not condition:
        raise StageFailure(code)


def native_code(prefix, error):
    """A finite failure word for an operating system error: its fixed step name and number only."""
    if isinstance(error, PlatformError):
        return prefix + ":" + error.code + (":" + str(error.number) if error.number else "")
    number = getattr(error, "winerror", None) or getattr(error, "errno", None)
    return prefix + ":" + type(error).__name__ + (":" + str(number) if type(number) is int else "")


def sha256_file(path, limit=None):
    digest, total = hashlib.sha256(), 0
    with open(path, "rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            need(limit is None or total <= limit, "file-bound")
            digest.update(block)
    return digest.hexdigest(), total


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_request(value, *, windows=True):
    """Closed fields; every path is derived from the operation and the profile the host observed."""
    paths = ntpath if windows else posixpath
    need(type(value) is dict and set(value) == {"schema", "schemaVersion", "operationId", "sourceCommit", "profileRoot",
                                                "operationRoot", "workspace", "workRoot", "archives", "jdk", "gradle",
                                                "gradleDeadlineSeconds", "minimumFreeBytes"}, "request-fields")
    need(value["schema"] == REQUEST_SCHEMA and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1, "request-schema")
    operation = value["operationId"]
    need(type(operation) is str and _UUID.fullmatch(operation) is not None, "request-operation")
    need(type(value["sourceCommit"]) is str and _COMMIT.fullmatch(value["sourceCommit"]) is not None, "request-commit")
    profile = value["profileRoot"]
    need(type(profile) is str and paths.isabs(profile) and paths.normpath(profile) == profile
         and not any(ord(c) < 32 for c in profile) and len(profile) <= 120, "request-profile")
    need(value["operationRoot"] == paths.join(profile, "AppData", "Local", OPERATION_PREFIX + operation), "request-operation-root")
    need(value["workRoot"] == paths.join(profile, WORK_PREFIX + operation[:8]), "request-work-root")
    workspace = value["workspace"]
    if windows:
        need(workspace == WORKSPACE_PREFIX + operation, "request-workspace")
    else:
        need(type(workspace) is str and paths.isabs(workspace) and paths.normpath(workspace) == workspace, "request-workspace")
    archives = value["archives"]
    need(type(archives) is dict and set(archives) == set(ARCHIVE_LEAVES), "request-archives")
    for role, leaf in ARCHIVE_LEAVES.items():
        row = archives[role]
        need(type(row) is dict and set(row) == {"path", "sha256", "bytes"} and row["path"] == paths.join(workspace, leaf)
             and type(row["sha256"]) is str and _SHA256.fullmatch(row["sha256"]) is not None
             and type(row["bytes"]) is int and 0 < row["bytes"] <= ARCHIVE_LIMIT, "request-archive-" + role)
    jdk = value["jdk"]
    need(type(jdk) is dict and set(jdk) == {"root", "javaVersion"} and type(jdk["root"]) is str
         and _NAME.fullmatch(jdk["root"]) is not None and type(jdk["javaVersion"]) is str
         and _JAVA_VERSION.fullmatch(jdk["javaVersion"]) is not None, "request-jdk")
    gradle = value["gradle"]
    need(type(gradle) is dict and set(gradle) == {"version", "root", "distributionUrl", "wrapperHash"}
         and type(gradle["version"]) is str and re.fullmatch(r"[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,2})?", gradle["version"]) is not None
         and gradle["root"] == "gradle-" + gradle["version"]
         and gradle["distributionUrl"] == "https://services.gradle.org/distributions/gradle-" + gradle["version"] + "-bin.zip"
         and type(gradle["wrapperHash"]) is str and re.fullmatch(r"[0-9a-z]{1,32}", gradle["wrapperHash"]) is not None, "request-gradle")
    need(type(value["gradleDeadlineSeconds"]) is int and 600 <= value["gradleDeadlineSeconds"] <= 6 * 3600, "request-deadline")
    need(type(value["minimumFreeBytes"]) is int and 1024 ** 3 <= value["minimumFreeBytes"] <= 256 * 1024 ** 3, "request-free-space")
    return value


def read_request(path, expected_sha256):
    need(type(expected_sha256) is str and _SHA256.fullmatch(expected_sha256) is not None, "request-digest-argument")
    try:
        with open(path, "rb") as stream:
            raw = stream.read(REQUEST_LIMIT + 1)
    except OSError:
        raise StageFailure("request-unreadable") from None
    need(len(raw) <= REQUEST_LIMIT and hashlib.sha256(raw).hexdigest() == expected_sha256, "request-digest")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise StageFailure("request-json") from None


def entry_parts(name):
    """A member name Windows cannot alias: relative, no drive or stream, no reserved device or trailing dot."""
    need(type(name) is str and name and len(name) <= 400 and not any(ord(c) < 32 for c in name), "zip-entry-name")
    need(not name.startswith("/") and "\\" not in name and ":" not in name, "zip-entry-absolute")
    parts = name.rstrip("/").split("/")
    for part in parts:
        need(part not in ("", ".", "..") and not part.endswith((".", " ")) and not any(c in '<>"|?*' for c in part)
             and part.split(".")[0].upper() not in _RESERVED, "zip-entry-component")
    return parts


def inspect_zip(path, limits, *, root=None):
    """Every member is checked before anything is written; the totals are returned."""
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile):
        raise StageFailure("zip-unreadable") from None
    with archive:
        infos = archive.infolist()
        need(0 < len(infos) <= limits["entries"], "zip-entry-count")
        seen, total, files = set(), 0, 0
        for info in infos:
            parts = entry_parts(info.filename)
            folded = "/".join(parts).casefold()
            need(folded not in seen, "zip-entry-alias")
            seen.add(folded)
            need(not (info.create_system == 3 and stat.S_ISLNK(info.external_attr >> 16)), "zip-entry-link")
            need(not info.flag_bits & 0x1, "zip-entry-encrypted")
            need(root is None or parts[0] == root, "zip-root")
            if not info.is_dir():
                need(info.file_size <= limits["file"], "zip-file-bound")
                total += info.file_size
                files += 1
        need(files > 0 and total <= limits["bytes"], "zip-total-bound")
    return {"entries": len(infos), "files": files, "bytes": total}


def extract_zip(path, target, limits, *, root=None, local=lambda value: value):
    """Create-only extraction into a new directory; each member's CRC is checked as it is read."""
    facts = inspect_zip(path, limits, root=root)
    os.makedirs(local(target), exist_ok=False)
    written = 0
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            parts = entry_parts(info.filename)
            destination = os.path.join(target, *parts)
            if info.is_dir():
                os.makedirs(local(destination), exist_ok=True)
                continue
            os.makedirs(local(os.path.dirname(destination)), exist_ok=True)
            count = 0
            with archive.open(info) as source, open(local(destination), "xb") as output:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    count += len(block)
                    need(count <= info.file_size, "zip-member-size")
                    output.write(block)
            need(count == info.file_size, "zip-member-size")
            written += count
    need(written == facts["bytes"], "zip-total-size")
    return facts


def wrapper_properties(path):
    """The Java properties lines of gradle-wrapper.properties, with the escapes it uses undone."""
    try:
        with open(path, "r", encoding="iso-8859-1") as stream:
            text = stream.read(65536)
    except OSError:
        raise StageFailure("wrapper-properties-unreadable") from None
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "!")) and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().replace("\\:", ":").replace("\\=", "=")
    return values


def java_release(path):
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as stream:
            for line in stream.read(65536).splitlines():
                key, _, value = line.partition("=")
                if key in {"JAVA_VERSION", "JAVA_RUNTIME_VERSION", "IMPLEMENTOR", "IMPLEMENTOR_VERSION", "OS_NAME", "OS_ARCH"}:
                    values[key] = value.strip().strip('"')[:80]
    except OSError:
        raise StageFailure("jdk-release-unreadable") from None
    return values


def fingerprint(root, local=lambda value: value):
    """Names, sizes and write times under one product folder, never following a link or junction."""
    if not os.path.lexists(local(root)):
        return {"present": False}
    rows, pending = [], [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(local(directory)))
        except OSError:
            return {"present": True, "complete": False}
        for entry in entries:
            info = entry.stat(follow_symlinks=False)
            relative = os.path.relpath(os.path.join(directory, entry.name), root).replace(os.sep, "/")
            if getattr(info, "st_file_attributes", 0) & 0x400 or stat.S_ISLNK(info.st_mode):
                rows.append([relative, "link", 0])
            elif stat.S_ISDIR(info.st_mode):
                pending.append(os.path.join(directory, entry.name))
            else:
                rows.append([relative, info.st_size, info.st_mtime_ns])
            if len(rows) > FINGERPRINT_LIMIT:
                return {"present": True, "complete": False}
    rows.sort()
    return {"present": True, "complete": True, "entries": len(rows),
            "sha256": hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest(), "rows": rows}


def compare_state(before, after):
    """Per product folder: unchanged, or the first changed names. Rows themselves stay out of the summary."""
    result = {}
    for name in sorted(before):
        old, new = before[name], after.get(name, {})
        unchanged = (old.get("present") == new.get("present") and old.get("complete", True) is True
                     and new.get("complete", True) is True and old.get("sha256") == new.get("sha256"))
        changed = []
        if not unchanged and old.get("rows") is not None and new.get("rows") is not None:
            left, right = ({row[0]: row[1:] for row in side["rows"]} for side in (old, new))
            changed = sorted(key for key in set(left) | set(right) if left.get(key) != right.get(key))[:20]
        result[name] = {"unchanged": unchanged, "presentBefore": old.get("present"), "presentAfter": new.get("present"),
                        "entriesBefore": old.get("entries"), "entriesAfter": new.get("entries"), "changedNames": changed}
    return result


class PosixGroup:
    """Coordinator and test seam: one session that ends with its leader, or is killed whole."""

    def __init__(self, process):
        self.process = process

    def wait(self, timeout):
        return self.process.wait(timeout=timeout)

    def members(self):
        try:
            os.killpg(self.process.pid, 0)
        except (ProcessLookupError, PermissionError):
            return []
        return [self.process.pid]

    def describe(self, pid):
        return "session-member"

    def terminate(self):
        try:
            os.killpg(self.process.pid, 9)
        except (ProcessLookupError, PermissionError):
            pass
        until = time.monotonic() + TERMINATE_SECONDS
        while time.monotonic() < until:
            self.process.poll()
            if not self.members():
                return True
            time.sleep(0.1)
        return False

    def close(self):
        pass


class PosixPlatform:
    """The same stages on a POSIX host: the offline tests run the whole runner with a fake JVM."""

    windows = False

    @staticmethod
    def long_path(value):
        return value

    @staticmethod
    def free_bytes(path):
        return shutil.disk_usage(path).free

    @staticmethod
    def java(jdk_home):
        return os.path.join(jdk_home, "bin", "java")

    @staticmethod
    def launch(argv, environment, cwd, output):
        process = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                   cwd=cwd, env=environment, close_fds=True, start_new_session=True)
        return PosixGroup(process)

    @staticmethod
    def product_processes():
        return []


def windows_types():
    """The x64 Windows structures in fixed-width fields (DWORD 32-bit, WCHAR 16-bit), apart from any DLL,
    so their layout is the same and testable on every 64-bit host."""
    import ctypes
    DWORD, LONG = ctypes.c_uint32, ctypes.c_int32

    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                          "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class BasicLimit(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", DWORD), ("Affinity", ctypes.c_size_t), ("PriorityClass", DWORD), ("SchedulingClass", DWORD)]

    class ExtendedLimit(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BasicLimit), ("IoInfo", IoCounters), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    class Accounting(ctypes.Structure):
        _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64), ("ThisPeriodTotalUserTime", ctypes.c_int64),
                    ("ThisPeriodTotalKernelTime", ctypes.c_int64), ("TotalPageFaultCount", DWORD), ("TotalProcesses", DWORD),
                    ("ActiveProcesses", DWORD), ("TotalTerminatedProcesses", DWORD)]

    class ThreadEntry(ctypes.Structure):
        _fields_ = [("dwSize", DWORD), ("cntUsage", DWORD), ("th32ThreadID", DWORD), ("th32OwnerProcessID", DWORD),
                    ("tpBasePri", LONG), ("tpDeltaPri", LONG), ("dwFlags", DWORD)]

    class ProcessEntry(ctypes.Structure):
        _fields_ = [("dwSize", DWORD), ("cntUsage", DWORD), ("th32ProcessID", DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", DWORD), ("cntThreads", DWORD), ("th32ParentProcessID", DWORD), ("pcPriClassBase", LONG),
                    ("dwFlags", DWORD), ("szExeFile", ctypes.c_uint16 * 260)]
    return {"IoCounters": IoCounters, "BasicLimit": BasicLimit, "ExtendedLimit": ExtendedLimit, "Accounting": Accounting,
            "ThreadEntry": ThreadEntry, "ProcessEntry": ProcessEntry}


# x64 sizes from the Windows SDK; a different layout here would pass garbage to the job and Toolhelp calls.
WINDOWS_SIZES = {"ExtendedLimit": 144, "Accounting": 48, "ThreadEntry": 28, "ProcessEntry": 568}
# CREATE_SUSPENDED: nothing the JVM starts can run before the JVM is in the job. NORMAL_PRIORITY_CLASS: a scheduled
# task starts below normal and its children inherit that; the build runs at the priority CI gives it, no higher.
# CREATE_NO_WINDOW: no console.
GRADLE_CREATION_FLAGS = 0x00000004 | 0x00000020 | 0x08000000


def wide_name(units):
    """A NUL-terminated UTF-16 array of a Toolhelp entry."""
    values = []
    for unit in units:
        if unit == 0:
            break
        values.append(unit)
    return b"".join(value.to_bytes(2, "little") for value in values).decode("utf-16-le", "replace")


class WindowsGroup:
    """The build's whole process tree in one job object, which kills what is left when its last handle closes."""

    def __init__(self, platform, job, process):
        self.platform, self.job, self.process = platform, job, process

    def wait(self, timeout):
        return self.process.wait(timeout=timeout)

    def members(self):
        ctypes, k = self.platform.ctypes, self.platform.k
        capacity = 4096
        buffer = ctypes.create_string_buffer(8 + 8 * capacity)
        if not k.QueryInformationJobObject(self.job, 3, buffer, len(buffer), None):
            raise PlatformError("job-process-list", ctypes.get_last_error())
        assigned, listed = (int.from_bytes(buffer.raw[offset:offset + 4], "little") for offset in (0, 4))
        if listed < assigned:
            raise PlatformError("job-process-list-bound")
        return [int.from_bytes(buffer.raw[8 + 8 * index:16 + 8 * index], "little") for index in range(listed)]

    def describe(self, pid):
        ctypes, k = self.platform.ctypes, self.platform.k
        handle = k.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return "unreadable"
        try:
            size = self.platform.W.DWORD(1024)
            name = ctypes.create_unicode_buffer(1024)
            if not k.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(size)):
                return "unreadable"
            return ntpath.basename(name.value)[:80]
        finally:
            k.CloseHandle(handle)

    def active(self):
        ctypes = self.platform.ctypes
        value = self.platform.types["Accounting"]()
        if not self.platform.k.QueryInformationJobObject(self.job, 1, ctypes.byref(value), ctypes.sizeof(value), None):
            raise PlatformError("job-accounting", ctypes.get_last_error())
        return value.ActiveProcesses

    def terminate(self):
        self.platform.k.TerminateJobObject(self.job, 1)
        until = time.monotonic() + TERMINATE_SECONDS
        while time.monotonic() < until:
            if self.active() == 0:
                return True
            time.sleep(0.5)
        return False

    def close(self):
        self.platform.k.CloseHandle(self.job)


class WindowsPlatform:
    windows = True

    def __init__(self):
        import ctypes
        from ctypes import wintypes as W
        self.ctypes, self.W, self.types = ctypes, W, windows_types()
        if any(ctypes.sizeof(self.types[name]) != size for name, size in WINDOWS_SIZES.items()):
            raise PlatformError("windows-structure-layout")
        k = self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateJobObjectW.restype = W.HANDLE
        k.CreateJobObjectW.argtypes = (ctypes.c_void_p, W.LPCWSTR)
        k.SetInformationJobObject.argtypes = (W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD)
        k.AssignProcessToJobObject.argtypes = (W.HANDLE, W.HANDLE)
        k.QueryInformationJobObject.argtypes = (W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD, ctypes.c_void_p)
        k.TerminateJobObject.argtypes = (W.HANDLE, W.UINT)
        k.CloseHandle.argtypes = (W.HANDLE,)
        k.CreateToolhelp32Snapshot.restype = W.HANDLE
        k.CreateToolhelp32Snapshot.argtypes = (W.DWORD, W.DWORD)
        k.Thread32First.argtypes = k.Thread32Next.argtypes = (W.HANDLE, ctypes.c_void_p)
        k.Process32FirstW.argtypes = k.Process32NextW.argtypes = (W.HANDLE, ctypes.c_void_p)
        k.OpenThread.restype = W.HANDLE
        k.OpenThread.argtypes = (W.DWORD, W.BOOL, W.DWORD)
        k.ResumeThread.restype = W.DWORD
        k.ResumeThread.argtypes = (W.HANDLE,)
        k.OpenProcess.restype = W.HANDLE
        k.OpenProcess.argtypes = (W.DWORD, W.BOOL, W.DWORD)
        k.QueryFullProcessImageNameW.argtypes = (W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD))

    @staticmethod
    def long_path(value):
        return value if value.startswith("\\\\?\\") else "\\\\?\\" + value

    @staticmethod
    def free_bytes(path):
        return shutil.disk_usage(path).free

    @staticmethod
    def java(jdk_home):
        return ntpath.join(jdk_home, "bin", "java.exe")

    def _snapshot(self, flags):
        handle = self.k.CreateToolhelp32Snapshot(flags, 0)
        if handle is None or handle == self.ctypes.c_void_p(-1).value:
            raise PlatformError("toolhelp-snapshot", self.ctypes.get_last_error())
        return handle

    def _resume(self, pid):
        """Resume the one primary thread of a process created suspended."""
        entry = self.types["ThreadEntry"]()
        entry.dwSize = self.ctypes.sizeof(entry)
        snapshot = self._snapshot(0x4)  # TH32CS_SNAPTHREAD
        resumed = 0
        try:
            more = self.k.Thread32First(snapshot, self.ctypes.byref(entry))
            while more:
                if entry.th32OwnerProcessID == pid:
                    thread = self.k.OpenThread(0x2, False, entry.th32ThreadID)  # THREAD_SUSPEND_RESUME
                    if not thread:
                        raise PlatformError("thread-open", self.ctypes.get_last_error())
                    try:
                        if self.k.ResumeThread(thread) == 0xFFFFFFFF:
                            raise PlatformError("thread-resume", self.ctypes.get_last_error())
                        resumed += 1
                    finally:
                        self.k.CloseHandle(thread)
                more = self.k.Thread32Next(snapshot, self.ctypes.byref(entry))
        finally:
            self.k.CloseHandle(snapshot)
        if resumed != 1:
            raise PlatformError("thread-resume-count")

    def launch(self, argv, environment, cwd, output):
        ctypes, k = self.ctypes, self.k
        job = k.CreateJobObjectW(None, None)
        if not job:
            raise PlatformError("job-create", ctypes.get_last_error())
        try:
            limits = self.types["ExtendedLimit"]()
            limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not k.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise PlatformError("job-limits", ctypes.get_last_error())
            process = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, cwd=cwd,
                                       env=environment, close_fds=True, creationflags=GRADLE_CREATION_FLAGS)
        except BaseException:
            k.CloseHandle(job)
            raise
        try:
            if not k.AssignProcessToJobObject(job, int(process._handle)):
                raise PlatformError("job-assign", ctypes.get_last_error())
            self._resume(process.pid)
        except BaseException:
            process.kill()
            process.wait()
            k.CloseHandle(job)
            raise
        return WindowsGroup(self, job, process)

    def product_processes(self):
        """Image names of running product processes of any user; nothing else is read about them."""
        entry = self.types["ProcessEntry"]()
        entry.dwSize = self.ctypes.sizeof(entry)
        snapshot = self._snapshot(0x2)  # TH32CS_SNAPPROCESS
        found = []
        try:
            more = self.k.Process32FirstW(snapshot, self.ctypes.byref(entry))
            while more:
                name = wide_name(entry.szExeFile).casefold()
                if name in PRODUCT_IMAGES:
                    found.append(name)
                more = self.k.Process32NextW(snapshot, self.ctypes.byref(entry))
        finally:
            self.k.CloseHandle(snapshot)
        return sorted(found)


class Runner:
    """One request, stage by stage. Every stage is timed and journaled; a failure names its stage."""

    def __init__(self, request, platform, *, clock=time.monotonic, sleep=time.sleep):
        self.request, self.platform, self.clock, self.sleep = request, platform, clock, sleep
        self.local = platform.long_path
        self.operation, self.work, self.root = request["operationId"], request["workRoot"], request["operationRoot"]
        self.jdk_home = None
        self.state_before = {}
        self.stages, self.started = [], clock()
        self.summary = {"schema": SUMMARY_SCHEMA, "schemaVersion": 1, "operationId": self.operation,
                        "sourceCommit": request["sourceCommit"], "outcome": "failed", "failedStage": None, "failure": None,
                        "stages": self.stages, "gradle": None, "results": None, "jdkRelease": None, "archives": {},
                        "freeBytesBefore": None, "freeBytesAfter": None, "productProcessesBefore": None,
                        "productProcessesAfter": None, "productState": None, "profileEntries": None, "seconds": None,
                        "workRoot": {"created": False, "deleted": False, "error": None}}
        self.profile_before = None

    def path(self, *parts):
        return os.path.join(self.work, *parts)

    def progress(self, stage, **extra):
        """A rewritten progress file for observers; the summary, written once at the end, is the record."""
        value = {"schema": PROGRESS_SCHEMA, "schemaVersion": 1, "operationId": self.operation, "stage": stage,
                 "elapsedSeconds": int(self.clock() - self.started), "at": utc_now(), **extra}
        target = os.path.join(self.root, PROGRESS_LEAF)
        try:
            with open(self.local(target + ".new"), "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True)
            os.replace(self.local(target + ".new"), self.local(target))
        except OSError:
            pass

    def stage(self, name, action):
        self.progress(name)
        began = self.clock()
        row = {"name": name, "outcome": "running", "seconds": None, "code": None}
        self.stages.append(row)
        try:
            action()
        except StageFailure as failure:
            row.update(outcome="failed", seconds=round(self.clock() - began, 3), code=failure.code)
            raise
        except Exception as error:  # Still this stage's: named by its type and number only.
            code = native_code("unexpected", error)
            row.update(outcome="failed", seconds=round(self.clock() - began, 3), code=code)
            raise StageFailure(code) from error
        row.update(outcome="passed", seconds=round(self.clock() - began, 3))

    def run(self):
        try:
            for name in STAGES:
                self.stage(name, getattr(self, "_" + name.replace("-", "_")))
            self.summary["outcome"] = "completed"
        except StageFailure as failure:
            self.summary.update(outcome="failed", failedStage=self.stages[-1]["name"], failure=failure.code)
        # Cleanup follows whatever happened before it; a failed cleanup fails an otherwise completed run.
        try:
            self.stage("cleanup", self._cleanup)
        except StageFailure as failure:
            if self.summary["outcome"] == "completed":
                self.summary.update(outcome="failed", failedStage="cleanup", failure=failure.code)
        self.summary["seconds"] = round(self.clock() - self.started, 3)
        self.progress("finished", outcome=self.summary["outcome"])
        return self.summary

    def _preflight(self):
        need(os.path.isdir(self.local(self.root)), "operation-root-missing")
        need(not os.path.lexists(self.local(self.work)), "work-root-exists")
        for leaf in (SUMMARY_LEAF, RESULTS_LEAF):
            need(not os.path.lexists(self.local(os.path.join(self.root, leaf))), "result-file-exists")
        free = self.platform.free_bytes(self.request["profileRoot"])
        self.summary["freeBytesBefore"] = free
        need(free >= self.request["minimumFreeBytes"], "free-space-insufficient")
        self.summary["productProcessesBefore"] = self.platform.product_processes()
        self.state_before = {"/".join(parts): fingerprint(os.path.join(self.request["profileRoot"], *parts), self.local)
                             for parts in STATE_ROOTS}
        self.profile_before = self._profile_names()

    def _profile_names(self):
        """The names directly in the user's profile: anything the build left beside its work folder shows here."""
        return set(os.listdir(self.local(self.request["profileRoot"])))

    def _verify_archives(self):
        # The worker holds every archive pin with read sharing only for this whole run:
        # the bytes hashed here are the bytes each extraction reads.
        for role, row in sorted(self.request["archives"].items()):
            digest, size = sha256_file(self.local(row["path"]), ARCHIVE_LIMIT)
            need(size == row["bytes"] and digest == row["sha256"], "archive-digest-" + role)
            self.summary["archives"][role] = {"sha256": digest, "bytes": size}

    def _extract(self, role, target, limits, root=None):
        if not self.summary["workRoot"]["created"]:
            os.makedirs(self.local(self.work), exist_ok=False)
            self.summary["workRoot"]["created"] = True
        facts = extract_zip(self.local(self.request["archives"][role]["path"]), target, limits, root=root, local=self.local)
        self.summary["archives"][role]["extracted"] = facts

    def _extract_source(self):
        self._extract("source", self.path("s"), SOURCE_LIMITS)

    def _source_wrapper(self):
        values = wrapper_properties(self.local(self.path("s", *WRAPPER_PROPERTIES)))
        need(values.get("distributionUrl") == self.request["gradle"]["distributionUrl"], "wrapper-distribution-mismatch")
        # The coordinator's rule: no checksum, or the pinned distribution's own (the gradle archive here).
        need(not values.get("distributionSha256Sum") or values["distributionSha256Sum"] == self.request["archives"]["gradle"]["sha256"],
             "wrapper-distribution-checksum-mismatch")
        need(os.path.isfile(self.local(self.path("s", *WRAPPER_JAR))), "wrapper-jar-missing")
        need(os.path.isfile(self.local(self.path("s", "desktopApp", "build.gradle.kts"))), "desktop-project-missing")

    def _extract_jdk(self):
        jdk = self.request["jdk"]
        self._extract("jdk", self.path("j"), TOOL_LIMITS, root=jdk["root"])
        home = self.path("j", jdk["root"])
        need(os.path.isfile(self.local(self.platform.java(home))), "jdk-layout")
        release = java_release(self.local(os.path.join(home, "release")))
        need(release.get("JAVA_VERSION") == jdk["javaVersion"], "jdk-version")
        self.summary["jdkRelease"] = release
        self.jdk_home = home

    def _extract_gradle(self):
        gradle = self.request["gradle"]
        dists = self.path("g", "wrapper", "dists", "gradle-" + gradle["version"] + "-bin")
        os.makedirs(self.local(dists), exist_ok=False)
        installed = os.path.join(dists, gradle["wrapperHash"])
        self._extract("gradle", installed, TOOL_LIMITS, root=gradle["root"])
        need(os.path.isdir(self.local(os.path.join(installed, gradle["root"], "lib"))), "gradle-layout")
        # The wrapper's own installed marker: this distribution is used as it is and never downloaded.
        with open(self.local(os.path.join(installed, "gradle-" + gradle["version"] + "-bin.zip.ok")), "xb"):
            pass

    def _extract_dependencies(self):
        self._extract("dependencies", self.path("m"), TOOL_LIMITS)

    def _init_script(self):
        with open(self.local(self.path(INIT_LEAF)), "x", encoding="ascii") as stream:
            stream.write(OFFLINE_INIT_SCRIPT)
        for leaf in ("t", "h"):  # Temporary files, and user.home of the test JVMs.
            os.makedirs(self.local(self.path(leaf)), exist_ok=False)

    def environment(self):
        environment = {key: value for key, value in os.environ.items() if key.upper() not in REMOVED_ENVIRONMENT}
        environment.update(JAVA_HOME=self.jdk_home, GRADLE_USER_HOME=self.path("g"), TEMP=self.path("t"), TMP=self.path("t"),
                           # An explicit unavailable SDK, as scripts/test_desktop_sdk_independence.py configures the desktop graph.
                           ANDROID_HOME=self.path("no-android-sdk"), ANDROID_SDK_ROOT=self.path("no-android-sdk"))
        environment[REPOSITORY_VARIABLE] = self.path("m")
        environment[HOME_VARIABLE] = self.path("h")
        environment[DOTNET_VARIABLE] = self.path(*DOTNET_ABSENT)  # Never created: see DOTNET_VARIABLE.
        key = next((name for name in environment if name.upper() == "PATH"), "PATH")
        environment[key] = os.path.dirname(self.platform.java(self.jdk_home)) + os.pathsep + environment.get(key, "")
        return environment

    def argv(self):
        return [self.platform.java(self.jdk_home), *WRAPPER_JVM_OPTIONS, "-jar", self.path("s", *WRAPPER_JAR),
                "--init-script", self.path(INIT_LEAF), *GRADLE_ARGUMENTS]

    def _gradle(self):
        facts = {"argv": [os.path.basename(self.platform.java(self.jdk_home)), *WRAPPER_JVM_OPTIONS, "-jar", "gradle-wrapper.jar",
                          "--init-script", INIT_LEAF, *GRADLE_ARGUMENTS],
                 "exitCode": None, "seconds": None, "deadline": False, "deadlineSeconds": self.request["gradleDeadlineSeconds"],
                 "leftoverProcesses": [], "leftoversTerminated": None, "consoleBytes": None}
        self.summary["gradle"] = facts
        began = self.clock()
        until = began + self.request["gradleDeadlineSeconds"]
        with open(self.local(self.path(CONSOLE_LEAF)), "xb") as output:
            try:
                group = self.platform.launch(self.argv(), self.environment(), self.path("s"), output)
            except OSError as error:
                raise StageFailure(native_code("gradle-start", error)) from None
            try:
                while True:
                    try:
                        facts["exitCode"] = group.wait(max(1, min(HEARTBEAT_SECONDS, until - self.clock())))
                        break
                    except subprocess.TimeoutExpired:
                        if self.clock() >= until:
                            facts["deadline"] = True
                            break
                        self.progress("gradle", consoleBytes=output.tell())
                if facts["deadline"]:
                    facts["leftoversTerminated"] = group.terminate()
                else:
                    # Anything the build left running is recorded by image name, then ended with its job.
                    leftovers = group.members()
                    facts["leftoverProcesses"] = sorted(group.describe(pid) for pid in leftovers)
                    if leftovers:
                        facts["leftoversTerminated"] = group.terminate()
            finally:
                group.close()
            output.flush()
            facts["consoleBytes"] = output.tell()
        facts["seconds"] = round(self.clock() - began, 3)
        need(facts["leftoversTerminated"] is not False, "gradle-processes-survived")

    def _collect(self):
        results = self.path("s", *RESULTS_DIRECTORY)
        rows = []
        if os.path.isdir(self.local(results)):
            for directory, directories, names in os.walk(self.local(results)):
                directories.sort()
                for name in sorted(names):
                    if name.endswith(".xml"):
                        full = os.path.join(directory, name)
                        rows.append((os.path.relpath(full, self.local(results)).replace(os.sep, "/"), full))
        need(len(rows) <= RESULT_ENTRY_LIMIT, "results-entry-bound")
        console = self.local(self.path(CONSOLE_LEAF))
        console_size = os.path.getsize(console) if os.path.isfile(console) else None
        target = self.local(os.path.join(self.root, RESULTS_LEAF))
        total, truncated = 0, False
        with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            def member(name):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type, info.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
                return archive.open(info, "w")
            for relative, full in rows:
                size = os.path.getsize(full)
                total += size
                need(size <= RESULT_FILE_LIMIT and total <= RESULT_TOTAL_LIMIT, "results-bound")
                with open(full, "rb") as source, member("test-results/" + relative) as sink:
                    shutil.copyfileobj(source, sink, 1024 * 1024)
            if console_size is not None:
                with open(console, "rb") as source, member(CONSOLE_LEAF) as sink:
                    if console_size <= CONSOLE_HEAD + CONSOLE_TAIL:
                        shutil.copyfileobj(source, sink, 1024 * 1024)
                    else:
                        truncated = True
                        sink.write(source.read(CONSOLE_HEAD))
                        sink.write(b"\n[vpn-control desktop test: console truncated]\n")
                        source.seek(console_size - CONSOLE_TAIL)
                        sink.write(source.read(CONSOLE_TAIL))
        digest, size = sha256_file(target)
        need(size <= RESULTS_ZIP_LIMIT, "results-zip-bound")
        self.summary["results"] = {"name": RESULTS_LEAF, "bytes": size, "sha256": digest, "xmlFiles": len(rows), "xmlBytes": total,
                                   "consoleBytes": console_size, "consoleTruncated": truncated,
                                   "resultsDirectoryPresent": os.path.isdir(self.local(results))}

    def _state_check(self):
        self.summary["productProcessesAfter"] = self.platform.product_processes()
        after = {"/".join(parts): fingerprint(os.path.join(self.request["profileRoot"], *parts), self.local)
                 for parts in STATE_ROOTS}
        self.summary["productState"] = compare_state(self.state_before, after)
        names = self._profile_names()
        self.summary["profileEntries"] = {"added": sorted(names - self.profile_before - {WORK_PREFIX + self.operation[:8]})[:64],
                                          "removed": sorted(self.profile_before - names)[:64]}

    def _cleanup(self):
        record = self.summary["workRoot"]
        if not record["created"]:
            # A folder this run did not create is never removed, even one that has its name.
            if os.path.lexists(self.local(self.work)):
                record["error"] = "work-root-not-owned"
            return
        info = os.lstat(self.local(self.work))
        need(stat.S_ISDIR(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400 and not stat.S_ISLNK(info.st_mode),
             "work-root-not-a-directory")

        def writable(function, path, error):
            try:
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
                function(path)
            except OSError:
                pass
        for attempt in range(CLEANUP_ATTEMPTS):
            try:
                shutil.rmtree(self.local(self.work), onexc=writable)
            except OSError:
                pass
            if not os.path.lexists(self.local(self.work)):
                break
            self.sleep(min(2 ** attempt, 10))  # A scanner may still hold a file it has just read.
        record["deleted"] = not os.path.lexists(self.local(self.work))
        self.summary["freeBytesAfter"] = self.platform.free_bytes(self.request["profileRoot"])
        if not record["deleted"]:
            record["error"] = "work-root-remains"
        need(record["deleted"], "work-root-remains")


def write_summary(root, summary, local=lambda value: value):
    data = (json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    with open(local(os.path.join(root, SUMMARY_LEAF)), "xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(data).hexdigest()


def main(argv=None, *, platform=None):
    parser = argparse.ArgumentParser(description="One complete :desktopApp:test as the ordinary user.")
    parser.add_argument("--request", required=True)
    parser.add_argument("--request-sha256", required=True)
    arguments = parser.parse_args(argv)
    if platform is None:
        platform = WindowsPlatform() if os.name == "nt" else PosixPlatform()
    try:
        request = validate_request(read_request(arguments.request, arguments.request_sha256), windows=platform.windows)
    except StageFailure as failure:
        print(json.dumps({"schemaVersion": 1, "state": "refused", "failedStage": "request", "failure": failure.code}))
        return 2
    summary = Runner(request, platform).run()
    try:
        digest = write_summary(request["operationRoot"], summary, platform.long_path)
    except OSError as error:
        print(json.dumps({"schemaVersion": 1, "state": "summary-unwritten", "failure": native_code("summary", error)}))
        return 2
    print(json.dumps({"schemaVersion": 1, "state": summary["outcome"], "operationId": request["operationId"],
                      "failedStage": summary["failedStage"], "failure": summary["failure"], "summarySha256": digest},
                     sort_keys=True))
    return 0 if summary["outcome"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
