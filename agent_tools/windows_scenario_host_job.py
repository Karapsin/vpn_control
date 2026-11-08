"""One durable Windows scenario job on the VM host: stages, guest programs and receipts.

native_scenario_windows renders this source with one closed plan and the existing
durable owner runs it detached on the host. It needs only a plain python3 and the
standard library, opens no listener, takes no sudo and never elevates anything.
Importing it performs no I/O. A guest program goes in once: its flat journal is
saved first, an existing journal means never again, and a lost reply ends UNKNOWN.

Exit codes: 0 passed, 1 known failure, 2 refused before any guest effect, 3 UNKNOWN.
The fence terminal closes a known exit and never an UNKNOWN one, because any integer
exit closes the fence and would let readiness-reboot through.
"""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import sys
import time
import types
import uuid
import zlib

try:
    import fcntl
except ImportError:  # CI imports this module on Windows; the job itself runs on Linux.
    fcntl = None

EXIT_PASSED, EXIT_FAILED, EXIT_REFUSED, EXIT_UNKNOWN = 0, 1, 2, 3
KNOWN_EXITS = frozenset({EXIT_PASSED, EXIT_FAILED, EXIT_REFUSED})
RESULTS = {EXIT_PASSED: "passed", EXIT_FAILED: "failed", EXIT_REFUSED: "failed", EXIT_UNKNOWN: "unknown"}
MAX_SOURCE_BYTES = 79183  # Largest stdin program proven natively.
MAX_STDOUT_BYTES = 65536
MAX_DECODED_BYTES = 2 * 1024 * 1024
MAX_TERMINAL_BYTES = 262144
PUBLISHER_OUTPUT_BYTES = 24576
INPUT_BYTES = 262144
RECEIPT_BYTES = 6144
CHUNK_BYTES = 32768
EVIDENCE_CHUNK_BYTES = 65536
FILE_BATCH = 64
READ_PIN_BATCH = 512
VM_ROOT_ENTRY_LIMIT = 3500  # readiness_windows_lifecycle refuses a start above 4,096.
QGA_LOCK_WAIT_SECONDS = 120  # Nothing was sent while waiting; readiness keeps working between exchanges.
PROGRAM_BUDGET_SECONDS = 600
RUN_MARGIN_SECONDS = 1800  # Pins held before launch and at closing: a Python tree is thousands of hashes.
STATUS_POLL_SECONDS = 5
STATUS_FAILURES = 3
POWERSHELL_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
MSIEXEC_PATH = r"C:\Windows\System32\msiexec.exe"
GUEST_ARGUMENTS = ("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                   "$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s))")
WORKSPACE_PREFIX = "C:\\ProgramData\\VpnControlOrdinaryTask-"
ROOT_PREFIX = "VpnControlOrdinary-"
BUNDLE_TOOLS = "bundle/agent_tools"
OWNER_SOURCE = "windows_ordinary_task_owner.ps1"
PUBLISHER_TEMPLATE = "windows_scenario_publisher.ps1.template"
RUN_TEMPLATE = "windows_scenario_system_run.ps1.template"
# Fixed places under the ordinary profile's LocalAppData: the per-user Python the
# python-install row creates, and the per-user MSI install of the product.
PYTHON_RELATIVE = "Programs\\Python\\Python313"
INSTALL_RELATIVE = "vpn-control"
CLI_LEAF = "vpn-control-cli.exe"
PRODUCT_NAME = "vpn-control"
UPGRADE_CODE = "{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}"  # desktopApp/build.gradle.kts upgradeUuid.
PYTHON_REQUIRED = ("python.exe", "python313.dll", "Lib/os.py", "Lib/subprocess.py", "Lib/threading.py",
                   "Lib/json/__init__.py", "Lib/ctypes/__init__.py", "DLLs/_ctypes.pyd")
INSTALLED_REQUIRED = ("vpn-control.exe", CLI_LEAF)
INSTALL_SCENARIOS = frozenset({"windows-msi-base-install", "windows-msi-base-reset"})
TREE_FILE_LIMIT = 3800  # One tree. A product row's Python and installed trees share one request: see _pin_bound.
FILE_PIN_LIMIT, DIRECTORY_PIN_LIMIT = 4096, 1024  # windows_ordinary_task.validate_closure, per request.
DIRECTORY_BATCH = 256
# Top-level evidence only; folders holding activation.port are never entered.
EVIDENCE_NAME = (r"(?:(?:task-)?event-[0-9A-Za-z_.-]+\.json|child-[0-9A-Za-z_.-]+\.raw"
                 r"|task-child\.[0-9A-Za-z_.-]+\.raw|(?:task-)?owner-parked\.json"
                 r"|(?:python-install|msi-install|msi-uninstall)[0-9A-Za-z_.-]*\.log)")
# A collector stage for the update and TUN grant rows runs inside "run", driven by the
# owner's update-native-observation-needed kind in the status file; see Job._on_status.
# "installed" reads what an installer row left behind, before evidence is copied.
STAGE_ORDER = ("anchor", "context", "publish", "requests", "run", "installed", "evidence", "receipt")
STOP_AFTER = frozenset({"context", "publish"})
_TOKEN_CHARACTERS = re.compile(r"[^A-Za-z0-9_.:-]+")
_LABEL = re.compile(r"[a-z][a-z0-9-]{0,79}\Z")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_BUNDLE_PATH = re.compile(r"(?:agent_tools|scripts)/[A-Za-z0-9_.-]+\Z")
_PRODUCT_CODE = re.compile(r"\{[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}\}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(?:[1-9]|1[0-9])\.(?:[0-9]|1[0-9])\.(?:[0-9]|1[0-9])\Z")
_GUEST_CODE = re.compile(r"(?:RUN|TASK|TOKEN|PUB)_[A-Z0-9_]{1,80}\Z")
# The finite name of the receipt check a publisher reply failed; never guest text.
_RECEIPT_CHECK = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_SETUP_WORD = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_OPEN_RUN_STATES = frozenset({"owner-parked", "deadline", "post-launch-unknown"})


class Refused(Exception):
    """Refused before any guest effect: exit 2."""


class KnownFailure(Exception):
    """Nothing is left running and the outcome is known: exit 1."""


class Unknown(Exception):
    """A lost reply, a parked owner, a passed deadline or an open child outcome: exit 3, nothing is stopped."""


def token(value, limit=120):
    """Character-safe text for a receipt. It keeps the words it is given, so callers pass only finite codes."""
    return _TOKEN_CHARACTERS.sub("_", str(value))[:limit] or "unspecified"


def guest_code(value):
    """A guest refusal crosses only as its own closed code; other text stays in the private index."""
    return value if isinstance(value, str) and _GUEST_CODE.fullmatch(value) else "unclassified"


def _setup_reason(error):
    """A guard's own finite word; an OSError's text would carry host paths."""
    word = str(error) if type(error) is ValueError else ""
    return word if _SETUP_WORD.fullmatch(word) else type(error).__name__


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("guest_output_duplicate_key")
        result[key] = value
    return result


def batches(values, size):
    values = list(values)
    return [values[start:start + size] for start in range(0, len(values), size)]


def ancestors(paths):
    """Every existing parent a pinned path needs, outermost first, without duplicates."""
    found = []
    for path in paths:
        for parent in reversed(PureWindowsPath(path).parents):
            if str(parent) not in found:
                found.append(str(parent))
    return found


# Folded renderer: native slices come from the current owner, never a copy.
def fragments(owner_source, emitter):
    text = owner_source.decode("utf-8-sig")
    start = text.index("Add-Type -TypeDefinition @'\n")
    end = text.index("\npublic sealed class RetainedRawPump", start)
    native = text[start:end] + "\n'@ -ReferencedAssemblies @('System','System.Core')\n"
    start = text.index("function Assert-NativeIdentity(")
    assertions = text[start:text.index("function Add-FilePin(", start)]

    def block(source, name):
        found = source.index("public static class " + name)
        start = source.rindex("Add-Type -TypeDefinition @'", 0, found)
        end = source.index("\n'@ -ReferencedAssemblies @('System','System.Core')", found)
        return source[start:end] + "\n'@ -ReferencedAssemblies @('System','System.Core')\n"
    readonly = block(emitter._HELD_BODY, "VpnHeldProgram")
    start = readonly.index(" public static string Identity(")
    readonly = readonly[:start] + readonly[readonly.index(" public static int Refusal(", start):]
    if readonly.count("public static class VpnHeldProgram {") != 1:
        raise ValueError("publisher_fixed_held_type")
    readonly = readonly.replace("public static class VpnHeldProgram {", "public static class VpnPublisherFile {", 1)
    return {"NATIVE": native, "ASSERTIONS": assertions, "READONLY": readonly,
            "CREATE_DIRECTORY": block(emitter._ENDPOINT, "VpnCreateArtifactDirectory")}


def bound_input(value):
    """The closed program input as a gzip literal; the guest decoder refuses any other length."""
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if not 1 <= len(data) <= INPUT_BYTES:
        raise ValueError("guest_program_input_bound")
    encoded = base64.b64encode(gzip.compress(data, mtime=0)).decode("ascii")
    limit = str(INPUT_BYTES)
    return ("$iz=[IO.MemoryStream]::new([Convert]::FromBase64String('" + encoded + "'));"
            "$ig=[IO.Compression.GZipStream]::new($iz,[IO.Compression.CompressionMode]::Decompress)\n"
            "try{$ib=[byte[]]::new(" + limit + "+1);$il=0;while(($ic=$ig.Read($ib,$il," + limit + "+1-$il)) -gt 0){$il+=$ic;"
            "if($il -gt " + limit + "){throw 'IN_INPUT_BOUND'}};if($il -ne " + str(len(data)) + "){throw 'IN_INPUT_LENGTH'};"
            "$m=[Text.UTF8Encoding]::new($false,$true).GetString($ib,0,$il)|ConvertFrom-Json}finally{$ig.Dispose()}")


def fill_template(template, replacements):
    for name, value in replacements.items():
        marker = "@@" + name + "@@"
        if template.count(marker) != 1:
            raise ValueError("guest_template_marker:" + name)
        template = template.replace(marker, value)
    if "@@" in template:
        raise ValueError("guest_template_unbound")
    return template


def wrap_output(text, limit=MAX_STDOUT_BYTES):
    """Inline protocol wrapper: stdout is gzip+base64 JSON, so terminals stay small."""
    return ("$protocolResult= & {\n" + text + "\n}\n"
            "$vcRaw=[Text.UTF8Encoding]::new($false).GetBytes(($protocolResult|ConvertTo-Json -Depth 12 -Compress))\n"
            "$vcMemory=[IO.MemoryStream]::new();$vcZip=[IO.Compression.GZipStream]::new($vcMemory,[IO.Compression.CompressionMode]::Compress,$true)\n"
            "$vcZip.Write($vcRaw,0,$vcRaw.Length);$vcZip.Dispose()\n"
            "$vcOut=[Convert]::ToBase64String($vcMemory.ToArray());if($vcOut.Length -gt " + str(limit) + "){throw 'GUEST_OUTPUT_BOUND'}\n"
            "[Console]::Out.Write($vcOut)\n")


def check_source(source):
    """ASCII, no BOM, within the largest program proven on the stdin route."""
    if type(source) is not str or source.startswith("\ufeff"):
        raise ValueError("guest_source_bom")
    try:
        raw = source.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("guest_source_ascii") from None
    if not 0 < len(raw) <= MAX_SOURCE_BYTES:
        raise ValueError("guest_source_bound")
    return raw


def context_source(guest, user, native):
    """Read-only and not boot-bound: this is what the boot-bound programs are built from."""
    marker = "[Console]::WriteLine(($result|ConvertTo-Json -Depth 6 -Compress))"
    session = guest.powershell_source(user)
    if session.count(marker) != 1:
        raise ValueError("windows_context_source")
    body = session.replace(marker, "$sessionFacts=$result") + native + (
        "$scenarioOs=Get-CimInstance Win32_OperatingSystem\n"
        "$r=[ordered]@{sessionFacts=$sessionFacts;machineGuid=[string](Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid).MachineGuid;"
        "hardwareUuid=[string](Get-CimInstance Win32_ComputerSystemProduct).UUID;bootIdentifier=[OrdinaryNativeFacts]::BootIdentifier();"
        "bootFileTimeUtc=$scenarioOs.LastBootUpTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture);"
        "profileRoot=[string](Get-ItemProperty -LiteralPath ('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\'+$sessionFacts.expectedSid) -Name ProfileImagePath).ProfileImagePath;"
        "systemToken=@([OrdinaryNativeFacts]::Token())}\n"
        "[pscustomobject]$r\n")
    return wrap_output(body)


def decode_stdout(terminal):
    """The gzip+base64 JSON of an ended program; anything else stays a ValueError."""
    if (terminal.get("exited") is not True or type(terminal.get("exitcode")) is not int or terminal["exitcode"] != 0
            or terminal.get("out-truncated", False) or terminal.get("err-truncated", False)):
        raise ValueError("guest_program_failed")
    stdout = base64.b64decode(terminal.get("out-data", ""), validate=True)
    if base64.b64decode(terminal.get("err-data", ""), validate=True) or not 0 < len(stdout) <= MAX_STDOUT_BYTES:
        raise ValueError("guest_output_bound")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(stdout, validate=True))) as stream:
            raw = stream.read(MAX_DECODED_BYTES + 1)
    except (OSError, EOFError, zlib.error):
        raise ValueError("guest_output_gzip") from None
    if len(raw) > MAX_DECODED_BYTES:
        raise ValueError("guest_output_bound")
    value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique)
    if type(value) is not dict:
        raise ValueError("guest_output_shape")
    return value


def refused_before_effects(terminal):
    """The boot-bound prelude's own refusal: it exits 3 before any file effect, in plain JSON."""
    if terminal.get("exitcode") != 3:
        return False
    try:
        value = json.loads(base64.b64decode(terminal.get("out-data", ""), validate=True).decode("utf-8-sig"))
    except ValueError:
        return False
    return type(value) is dict and value.get("state") == "refused-before-file-effects" and value.get("fileEffects") is False


def layout(operation, context, row):
    """Every guest path a row may name, derived from the operation and observed profile only."""
    local = context["localAppData"]
    workspace, root = WORKSPACE_PREFIX + operation, local + "\\" + ROOT_PREFIX + operation
    python, installed = local + "\\" + PYTHON_RELATIVE, local + "\\" + INSTALL_RELATIVE
    paths = {"workspace": workspace, "operationRoot": root, "python": python, "pythonExe": python + "\\python.exe",
             "installed": installed, "cli": installed + "\\" + CLI_LEAF, "productWorkspace": root + "\\workspace",
             "workerRequest": root + "\\worker-request.json", "bootstrapRequest": root + "\\bootstrap-request.json",
             "pythonLog": root + "\\python-install.log", "msiLog": root + "\\msi-install.log",
             "msiUninstallLog": root + "\\msi-uninstall.log"}
    for relative, role, _ in row["guestFiles"]:
        paths["file:" + role] = workspace + "\\" + relative.rsplit("/", 1)[1]
    if row.get("package"):
        paths["file:package"] = workspace + "\\" + row["package"]["leaf"]
    return paths


def bootstrap_inputs(row, paths, *, signer=None, worker_pin=None, encode=None):
    """The one bootstrap a row may run: qualificationArguments and the child are constants of the row."""
    mode = row["bootstrapMode"]
    if mode == "qualification":
        inputs = {"qualificationSourcePath": paths["file:child"], "qualificationArguments": list(row["qualificationArguments"])}
    elif mode == "python-install":
        inputs = {"pythonInstallerPath": paths["file:package"], "pythonTargetDir": paths["python"],
                  "pythonLogPath": paths["pythonLog"], "pythonInstallerSignerCertificateSha256": signer}
    else:
        inputs = {"pythonPath": paths["pythonExe"], "workerPath": paths["file:worker"], "workerRequestPath": paths["workerRequest"],
                  "workerRequestSha256": worker_pin["sha256"], "workerRequestPinBase64": base64.b64encode(encode(worker_pin)).decode("ascii")}
    return {"mode": mode, **inputs}


def worker_inputs(row, paths, product, *, product_code=None):
    """The one worker request a row may run. casesPath and qualificationArgv come only from here."""
    action = row["workerAction"]
    if action in {"msi-install", "msi-reset"}:
        inputs = {"msiPath": paths["file:package"], "installerLogPath": paths["msiLog"]}
        if action == "msi-reset":
            # The worker installs nothing over files the removal left in the install folder.
            inputs.update(uninstallProductCode=product_code, uninstallLogPath=paths["msiUninstallLog"], uninstallRoot=paths["installed"])
        return inputs
    if action == "qualification":
        # The packaged CLI smoke: the unchanged public harness, its sibling diagnostic import kept by -E rather than -I.
        return {"qualificationArgv": [paths["pythonExe"], "-E", "-s", "-B", paths["file:harness"], "--launcher", paths["cli"],
                                      "--expected-version", product["productVersion"]], "expectedExitCode": 0}
    return {"cliPath": paths["cli"], "workspace": paths["productWorkspace"], "productVersion": product["productVersion"],
            "casesPath": paths["file:cases"], "harnessPath": paths["file:harness"]}


def tree_digest(root, files, pins):
    """A complete tree's identity: every relative name with its held bytes, in order."""
    by_path = {pin["path"]: pin for pin in pins}
    rows = []
    for name in sorted(files):
        pin = by_path[root + "\\" + name.replace("/", "\\")]
        rows.append([name, pin["sha256"], pin["nativeIdentity"]["sizeBytes"]])
    return _sha(json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode("ascii"))


def _need_closed(condition, code):
    if not condition:
        raise KnownFailure("requests_not_closed:" + code)


_COMMON_FIELDS = frozenset({"schemaVersion", "context", "operationId", "operationRoot", "filePins", "directoryPins", "treePins",
                            "rawStreamLimitBytes"})


def _same_request(row, request, expected, files, directories, trees, code):
    need = _need_closed
    need(request["schemaVersion"] == 1 and request["operationId"] == expected["operationId"]
         and request["operationRoot"] == expected["operationRoot"] and request["context"] == expected["context"]
         and request["rawStreamLimitBytes"] == row["rawStreamLimitBytes"], code + "identity")
    need(request["treePins"] == trees, code + "tree")
    need({pin["path"]: pin["sha256"] for pin in request["filePins"]} == files and len(request["filePins"]) == len(files), code + "file-pins")
    need(sorted(pin["path"] for pin in request["directoryPins"]) == sorted(directories), code + "directory-pins")
    if row["bootstrapMode"] == "python-worker":
        need(request.get("pythonRuntime") == expected["pythonRuntime"], code + "python-runtime")


def assert_closed_worker(row, worker, expected):
    """The worker request before it is published: action, inputs and every pin are the row's."""
    closed = expected["worker"]
    _need_closed(row["workerAction"] is not None and type(worker) is dict
                 and set(worker) == _COMMON_FIELDS | {"pythonRuntime", "action"} | set(closed["inputs"]), "worker-fields")
    _need_closed(worker["action"] == row["workerAction"] and {key: worker[key] for key in closed["inputs"]} == closed["inputs"],
                 "worker-inputs")
    _same_request(row, worker, expected, closed["files"], closed["directories"], closed["trees"], "worker-")


def assert_closed(row, requests, expected):
    """Refuse any request this closed row does not build, before it reaches a guest."""
    need = _need_closed
    request = requests["bootstrap"]
    worker = requests.get("worker")
    runtime = {"pythonRuntime"} if row["bootstrapMode"] == "python-worker" else set()
    need((worker is None) == (row["workerAction"] is None) == (expected.get("worker") is None), "worker")
    need(type(request) is dict and set(request) == _COMMON_FIELDS | runtime | {"bootstrap"}, "fields")
    _same_request(row, request, expected, expected["files"], expected["directories"], expected["bootstrapTrees"], "")
    need(request["bootstrap"] == expected["bootstrap"], "bootstrap")
    installed = expected.get("installedRoot", "").casefold()
    # Installed application pins live only in the worker request, so an MSI can replace files.
    need(not installed or not any(pin["path"].casefold() == installed or pin["path"].casefold().startswith(installed + "\\")
                                  for pin in request["filePins"] + request["directoryPins"]), "installed-in-bootstrap")
    if worker is not None:
        assert_closed_worker(row, worker, expected)
    task = requests.get("task")
    if task is None:
        return
    policy = task.get("policyExpected", {})
    need(task.get("taskName") == "VpnControlOrdinary-" + expected["operationId"], "task-name")
    need(task.get("nativeActionAllowed") is False and task.get("requestSha256") == expected["requestSha256"]
         and task.get("sourceSha256") == expected["ownerSha256"], "task-sources")
    need(type(task.get("argv")) is list and task["argv"][:6] == [POWERSHELL_PATH, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]
         and task["argv"][6:7] == [expected["owner"]], "task-argv")
    need(policy.get("UserId") == expected["context"]["ordinarySid"] and policy.get("LogonType") == "InteractiveToken"
         and policy.get("WorkingDirectory") == expected["operationRoot"] and policy.get("Command") == POWERSHELL_PATH, "task-policy")


def build_receipt(plan, *, exit_code, stage, failure, context=None, task=None, evidence=None, guest_programs=0,
                  installed=None, python=None, windows=None):
    """Tokens, integers and evidence hashes only; raw evidence stays on the host until pulled.

    ``installed`` is what an installer row left behind and what a product row found; a
    later row compares the tree against it. ``windows`` claims an installed package only
    for a passed product row whose registration, complete tree and package all matched.
    """
    context = context or {}
    task = task or {}
    streams = {row["name"]: row for row in task.get("rawStreams", [])}

    def stream(name):
        row = streams.get(name)
        return None if row is None else {"bytes": row["bytes"], "sha256": row["sha256"]}
    return {
        "schema": "vpn-control." + plan["scenarioId"] + ".receipt", "schemaVersion": 1,
        "scenarioId": plan["scenarioId"], "correlationId": plan["operationId"], "deploymentId": plan["machine"],
        "bundleHash": plan["bundleHash"], "result": RESULTS[exit_code], "exitCode": exit_code, "stage": stage,
        "stoppedAfter": plan.get("stopAfter"), "failure": failure, "guestPrograms": guest_programs,
        "context": {key: context.get(key) for key in ("ordinarySid", "ordinarySessionId", "profileRoot", "bootFileTimeUtc",
                                                      "bootIdentifier", "hardwareUuid", "machineGuid")},
        "task": {"state": task.get("state"), "ownerExitCode": task.get("ownerExitCode"),
                 "terminalExitCode": task.get("terminalExitCode"), "lastTaskResult": task.get("lastTaskResult"),
                 "events": len(task.get("events", [])), "workerEvents": task.get("workerEvents"),
                 "taskDeleted": task.get("taskDeleted"), "parked": bool(task.get("parkedFiles")),
                 "commandLineMatched": task.get("commandLineMatched"), "enginePid": task.get("enginePid"),
                 "ownerPid": task.get("ownerPid"), "polls": task.get("polls"), "statusFailures": task.get("statusFailures"),
                 "stdout": stream("stdout"),
                 "stderr": stream("stderr")},
        "evidence": evidence,
        "installed": installed,
        "python": python,
        "windows": windows or {"installedPackage": False, "packageSha256": None},
    }


class Job:
    """One operation. ``rt`` is the seam: production binds real QGA, tests the shared fake peer."""

    def __init__(self, rt, plan, files):
        self.rt = rt
        self.plan = plan
        self.files = files
        self.row = plan["row"]
        self.op = plan["operationId"]
        self.machine = plan["machine"]
        self.root = Path(rt.root)
        self.data = Path(plan["dataDirectory"])
        self.workspace = WORKSPACE_PREFIX + self.op
        self.stage = "anchor"
        self.anchored = self.owns_data = self.published = self.program_open = False
        self.programs = 0
        self.evidence_number = 0
        self.task = self.evidence = None
        self.modules = {}
        self.context = self.raw_context = self.system_token = self.operation_root = None
        self.directory_pins = []
        self.file_pins = {}
        self.read_pins = []
        self.request_pin = self.rendered_task = None
        self.paths = self.signer = self.msi = self.registered = self.prior_installed = None
        self.python_tree = self.installed_tree = self.installed = self.python_facts = self.worker = None
        self.installed_matched = self.task_checked = False

    # QGA and journal helpers.
    def _keep(self, relative, raw):
        path = self.data / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(descriptor, raw[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def guest_program(self, label, source, *, budget=PROGRAM_BUDGET_SECONDS, poll=1, on_poll=None):
        """Flat direct-guest journals: intent, one guest-exec, ack, original pid, terminal."""
        if _LABEL.fullmatch(label) is None:
            raise ValueError("guest_program_label")
        raw = check_source(source)
        prefix = "direct-guest-" + str(uuid.uuid5(uuid.UUID(self.op), label))
        if os.path.lexists(self.root / (prefix + ".intent.json")):
            raise Unknown("guest_program_intent_exists:" + label)
        self._keep("guest-programs/" + label + ".ps1", raw)
        self.rt.save(prefix + ".intent.json", {"operationId": self.op, "label": label, "sourceSha256": _sha(raw),
                                               "replayAllowed": False})
        self.programs += 1
        self.program_open = True
        try:
            ack = self.rt.rpc("guest-exec", {"path": POWERSHELL_PATH, "arg": list(GUEST_ARGUMENTS),
                                             "input-data": base64.b64encode(raw).decode("ascii"),
                                             "capture-output": True}, budget=20)
        except Exception:
            raise Unknown("guest_exec_reply_lost:" + label) from None
        if type(ack) is not dict or set(ack) != {"pid"} or type(ack["pid"]) is not int or ack["pid"] <= 0:
            raise Unknown("guest_exec_ack_invalid:" + label)
        self.rt.save(prefix + ".ack.json", {"operationId": self.op, "label": label, "ack": ack, "replayAllowed": False})
        deadline = self.rt.monotonic() + budget
        failures = 0
        while True:
            try:
                terminal = self.rt.rpc("guest-exec-status", {"pid": ack["pid"]}, budget=8)
                failures = 0
            except Exception:
                # An exited status may be single-shot: a lost one comes back as a
                # refusal here, so this can only end UNKNOWN, never in a replay.
                terminal = None
                failures += 1
                if failures >= STATUS_FAILURES:
                    raise Unknown("guest_exec_status_lost:" + label) from None
            if type(terminal) is dict and terminal.get("exited") is True:
                break
            if self.rt.monotonic() >= deadline:
                raise Unknown("guest_program_deadline:" + label)
            if on_poll is not None:
                on_poll()
            self.rt.sleep(poll)
        if (len((json.dumps(terminal, sort_keys=True) + "\n").encode()) > MAX_TERMINAL_BYTES
                or (type(terminal.get("exitcode")) is not int and type(terminal.get("signal")) is not int)):
            raise Unknown("guest_terminal_invalid:" + label)
        self.rt.save(prefix + ".terminal.json", terminal)  # Before any decoding.
        self.program_open = False
        return terminal, ack["pid"]

    @staticmethod
    def _rendered(build):
        """A program that cannot be rendered never reached the guest, so this is a known failure."""
        try:
            source = build()
            check_source(source)
            return source
        except ValueError as error:
            raise KnownFailure("guest_source_refused:" + token(error)) from None

    def _artifact(self, package):
        """A staged package in the host's artifact cache, opened without following links."""
        path = Path(self.plan["artifactDirectory"]) / package["sha256"]
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_size != package["bytes"]
                or (hasattr(os, "getuid") and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077))):
            os.close(descriptor)
            raise ValueError("artifact_cache_unsafe")
        return descriptor

    def _chunks(self, source):
        """Bytes in memory, or a staged package read in chunks and hashed on the way."""
        if type(source) is bytes:
            for offset in range(0, len(source), CHUNK_BYTES):
                yield source[offset:offset + CHUNK_BYTES]
            return
        descriptor = self._artifact(source)
        digest, total = hashlib.sha256(), 0
        try:
            while True:
                part = os.read(descriptor, CHUNK_BYTES)
                if not part:
                    break
                digest.update(part)
                total += len(part)
                yield part
        finally:
            os.close(descriptor)
        if total != source["bytes"] or digest.hexdigest() != source["sha256"]:
            raise ValueError("artifact_cache_changed")

    def push_file(self, path, source):
        """QGA writes in 32,768-byte chunks through call(); one line in push.jsonl, no VM-root entry."""
        digest = hashlib.sha256()
        chunks = total = 0
        try:
            handle = self.rt.rpc("guest-file-open", {"path": path, "mode": "wb"}, budget=20)
            if type(handle) is not int or handle <= 0:
                raise ValueError("guest_file_handle")
            try:
                for part in self._chunks(source):
                    reply = self.rt.rpc("guest-file-write", {"handle": handle, "buf-b64": base64.b64encode(part).decode("ascii")}, budget=20)
                    if type(reply) is not dict or reply.get("count") != len(part):
                        raise ValueError("guest_file_short_write")
                    digest.update(part)
                    chunks += 1
                    total += len(part)
            finally:
                self.rt.rpc("guest-file-close", {"handle": handle}, budget=20)
        except Exception:
            # No program runs here. The bytes are checked by "verify" and never written twice.
            raise KnownFailure("guest_file_push_lost") from None
        with (self.data / "push.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"path": path, "bytes": total, "sha256": digest.hexdigest(), "chunks": chunks},
                                    sort_keys=True, separators=(",", ":")) + "\n")

    def read_guest_file(self, path, limit, *, truncate_wires=False):
        """Read-only; the caller decides what a failure means.

        Only the evidence read truncates the wire files: its chunks are what would fill the
        disk, and a status read must not erase the history kept for reading a failure.
        """
        handle = self.rt.rpc("guest-file-open", {"path": path, "mode": "rb"}, budget=8)
        if type(handle) is not int or handle <= 0:
            raise ValueError("guest_file_handle")
        raw = bytearray()
        try:
            while True:
                reply = self.rt.rpc("guest-file-read", {"handle": handle, "count": min(EVIDENCE_CHUNK_BYTES, limit + 1 - len(raw))}, budget=20)
                part = base64.b64decode(reply["buf-b64"], validate=True)
                if reply.get("count") != len(part):
                    raise ValueError("guest_file_read_count")
                raw.extend(part)
                if truncate_wires:
                    self.rt.after_read()
                if len(raw) > limit:
                    raise ValueError("guest_file_read_bound")
                if reply.get("eof") is True or not part:
                    return bytes(raw)
        finally:
            self.rt.rpc("guest-file-close", {"handle": handle}, budget=8)

    def _load(self, name):
        if name not in self.modules:
            path = self.data / BUNDLE_TOOLS / (name + ".py")
            module = types.ModuleType("_windows_scenario_" + name + "_" + self.op.replace("-", ""))
            module.__file__ = str(path)
            sys.modules[module.__name__] = module
            exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
            self.modules[name] = module
        return self.modules[name]

    def _bundle_source(self, name):
        return (self.data / BUNDLE_TOOLS / name).read_bytes()

    # Stage 1.
    def prepare(self):
        self.data.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.mkdir(self.data, 0o700)
        except FileExistsError:
            raise Refused("job_already_exists") from None
        self.owns_data = True
        self.rt.open_wires(self.data)
        for relative, row in sorted(self.plan["files"].items()):
            raw = self.files[relative]
            if _BUNDLE_PATH.fullmatch(relative) is None or len(raw) != row["sizeBytes"] or _sha(raw) != row["sha256"]:
                raise Refused("bundle_bytes_changed")
            self._keep("bundle/" + relative, raw)
        package = self.package()
        if package is not None:
            # Staged before submit; the bytes are hashed here, again while pushed, and in the guest.
            try:
                for _ in self._chunks(package):
                    pass
            except (OSError, ValueError):
                raise Refused("artifact_cache_unavailable") from None

    def package(self):
        spec = self.row.get("package")
        return None if not spec else self.plan["packages"][spec["role"]]

    def _read_record(self, path):
        try:
            value = json.loads(Path(path).read_bytes(), object_pairs_hook=_unique)
        except (OSError, ValueError):
            return None
        return value if type(value) is dict else None

    def _admit(self):
        """A new job refuses unless every prior exit is known and every fence is terminal."""
        for other in sorted(self.data.parent.iterdir()):
            if other.name == self.op or _UUID.fullmatch(other.name) is None:
                continue
            record = self._read_record(other / "job-exit.json")
            if (record is None or record.get("operationId") != other.name or type(record.get("exitCode")) is not int
                    or record["exitCode"] not in KNOWN_EXITS):
                raise Refused("prior_job_exit_unknown")
            fence = "direct-guest-" + other.name
            if record.get("fenceAnchored") is not False and not os.path.lexists(self.root / (fence + ".intent.json")):
                raise Refused("prior_job_fence_missing")
        if self.row.get("priorInstall"):
            self.prior_installed = self._prior_install()
        names = [path.name for path in self.root.iterdir()]
        if len(names) > VM_ROOT_ENTRY_LIMIT:
            raise Refused("vm_root_entry_bound")
        for name in names:
            if name.startswith("direct-guest-") and name.endswith(".intent.json"):
                terminal = self._read_record(self.root / (name[:-len(".intent.json")] + ".terminal.json"))
                if terminal is None or terminal.get("exited") is not True or type(terminal.get("exitcode")) is not int:
                    raise Refused("prior_fence_open")
        try:
            self.rt.rpc("guest-ping", {}, budget=8)
        except Exception:
            raise Refused("guest_agent_unavailable") from None

    def _prior_install(self):
        """The passed installer job on this VM whose package this product row names: what it left is the baseline."""
        prior = (self.plan.get("prior") or {}).get("install")
        if not isinstance(prior, str) or _UUID.fullmatch(prior) is None or prior == self.op:
            raise Refused("prior_install_unavailable")
        other = self.data.parent / prior
        receipt = self._read_record(other / "scenario-receipt.json")
        record = self._read_record(other / "job-exit.json")
        installed = receipt.get("installed") if receipt is not None else None
        target = self.package_target()
        if (receipt is None or record is None or record.get("exitCode") != EXIT_PASSED or receipt.get("exitCode") != EXIT_PASSED
                or receipt.get("result") != "passed" or receipt.get("correlationId") != prior or receipt.get("deploymentId") != self.machine
                or receipt.get("scenarioId") not in INSTALL_SCENARIOS or type(installed) is not dict):
            raise Refused("prior_install_unavailable")
        if (installed.get("packageSha256") != target["sha256"] or installed.get("productVersion") != self.plan["product"]["productVersion"]
                or not isinstance(installed.get("productCode"), str) or _PRODUCT_CODE.fullmatch(installed["productCode"]) is None
                or not isinstance(installed.get("treeSha256"), str) or _SHA256.fullmatch(installed["treeSha256"]) is None
                or type(installed.get("treeFiles")) is not int):
            raise Refused("prior_install_other_package")
        return installed

    def package_target(self):
        return self.plan["packages"]["targetPackage"]

    def stage_anchor(self):
        self.prepare()
        with self.rt.admission():
            self._admit()
            prefix = "direct-guest-" + self.op
            self.rt.save(prefix + ".intent.json", {"operationId": self.op, "label": "scenario-fence",
                                                   "scenarioId": self.plan["scenarioId"], "replayAllowed": False})
            self.anchored = True
            self.rt.save(prefix + ".ack.json", {"operationId": self.op, "ack": {"pid": self.rt.pid}, "replayAllowed": False})

    # Stage 2.
    def stage_context(self):
        guest = self._load("readiness_windows_guest")
        native = fragments(self._bundle_source(OWNER_SOURCE), self._load("windows_artifact_transfer"))["NATIVE"]
        terminal, _ = self.guest_program("context", self._rendered(lambda: context_source(guest, self.plan["user"], native)))
        try:
            value = decode_stdout(terminal)
            if set(value) != {"sessionFacts", "machineGuid", "hardwareUuid", "bootIdentifier", "bootFileTimeUtc", "profileRoot", "systemToken"}:
                raise ValueError("context_fields")
            facts = value["sessionFacts"]
            state = guest.validate_session(facts, facts.get("expectedSid"), self.plan["user"], self.machine)["ordinary_session"]
        except (ValueError, TypeError, KeyError):
            raise KnownFailure("context_unreadable") from None
        if state != "ready":
            raise Refused("session_not_active:" + token(state))
        token_row = value["systemToken"]
        if type(token_row) is not list or token_row[:2] != ["S-1-5-18", "0"]:
            raise KnownFailure("context_system_token")
        self.system_token = token_row
        profile = value["profileRoot"]
        self.operation_root = profile + "\\AppData\\Local\\" + ROOT_PREFIX + self.op
        self.context = {"deploymentId": self.machine, "ordinarySid": facts["expectedSid"], "ordinarySessionId": facts["console"],
                        "profileRoot": profile, "localAppData": profile + "\\AppData\\Local",
                        "machineGuid": value["machineGuid"].lower(), "bootIdentifier": value["bootIdentifier"],
                        "bootFileTimeUtc": value["bootFileTimeUtc"]}
        self.raw_context = {"deploymentId": self.machine, "ordinarySid": facts["expectedSid"], "powerShellPath": POWERSHELL_PATH,
                            "sourceWorkspace": self.workspace,
                            "boot": {"lastBootUpTimeFileTimeUtc": value["bootFileTimeUtc"], "machineGuid": value["machineGuid"],
                                     "hardwareUuid": value["hardwareUuid"]}}
        try:
            self._load("windows_ordinary_task").validate_context(self.context)
            self._load("windows_artifact_transfer")._context(self.raw_context, self.machine)
        except ValueError:
            raise KnownFailure("context_invalid") from None
        self.paths = layout(self.op, self.context, self.row)
        if self.paths["operationRoot"] != self.operation_root:
            raise KnownFailure("context_profile_layout")
        # What the closed UAC action reads through uac_context(plan). The job never calls or waits on that action.
        self._keep("uac-context.json", (json.dumps({"operationRoot": self.operation_root, "ordinarySid": facts["expectedSid"],
                                                    "ordinarySessionId": facts["console"], "bootFileTimeUtc": value["bootFileTimeUtc"]},
                                                   sort_keys=True) + "\n").encode())

    # Stage 3.
    def _publisher(self, label, action, **fields):
        emitter = self._load("windows_artifact_transfer")
        m = {"schemaVersion": 1, "action": action, "operationId": self.op, "ordinarySid": self.context["ordinarySid"],
             "kernelBootIdentifier": self.context["bootIdentifier"], "systemToken": self.system_token,
             "workspace": self.workspace, "operationRoot": self.operation_root, "localAppData": self.context["localAppData"],
             "directoryPins": self.directory_pins, **fields}

        def render():
            parts = fragments(self._bundle_source(OWNER_SOURCE), emitter)
            template = fill_template(self._bundle_source(PUBLISHER_TEMPLATE).decode("ascii"),
                                     {"INPUT": bound_input(m), "EVIDENCE_NAME": EVIDENCE_NAME, **parts})
            # 512 read pins of hashes and file IDs, or a tree listing, do not compress below the publisher bound.
            limit = MAX_STDOUT_BYTES if action in {"read-pins", "read-directories", "list-tree"} else PUBLISHER_OUTPUT_BYTES
            return wrap_output(emitter._boot_bound(template, self.raw_context), limit)
        terminal, pid = self.guest_program(label, self._rendered(render))
        return self._protocol(label, terminal, pid, m)

    def _protocol(self, label, terminal, pid, m):
        emitter = self._load("windows_artifact_transfer")
        try:
            value = emitter.decode_guest_result({"transport": "inline"}, decode_stdout(terminal), self.raw_context, pid)
            required = {"schemaVersion", "state", "operationId", "kernelBootIdentifier", "systemToken", "allHeldAndNamedPinsClosing",
                        "productOperation", "taskOperation", "bootstrapOpening", "bootstrapClosing", "guestBootClosing", "bootstrapActorClosing"}
            if (not required <= set(value) or value["schemaVersion"] != 1 or value["operationId"] != self.op
                    or value["kernelBootIdentifier"] != m["kernelBootIdentifier"] or value["systemToken"] != m["systemToken"]
                    or value["allHeldAndNamedPinsClosing"] is not True or value["productOperation"] is not False or value["taskOperation"] is not False):
                raise ValueError("publisher_result_context")
            return value, required
        except (ValueError, TypeError, KeyError):
            raise KnownFailure("publisher_refused:" + token(label)) from None

    def _file_security(self):
        sid = self.context["ordinarySid"]
        return tuple({"ownerSid": "S-1-5-18", "sddl": "O:SYD:" + form + "(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + sid + ")"}
                     for form in ("P", "PAI"))

    def _directory_security(self, rights):
        sid = self.context["ordinarySid"]
        return tuple({"ownerSid": "S-1-5-18", "sddl": "O:SYD:" + form + "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;" + rights + ";;;" + sid + ")"}
                     for form in ("P", "PAI"))

    def _initialize(self, read_paths):
        planner = self._load("windows_ordinary_task")
        existing = ancestors([self.workspace, self.operation_root, *read_paths])
        subfolders = list(self.row.get("subfolders", ()))
        value, required = self._publisher("publish-initialize", "initialize", existingDirectories=existing, subfolders=subfolders)
        expected = [*existing, self.workspace, *(self.workspace + "\\" + name for name in subfolders), self.operation_root]
        pins = value.get("directoryPins")
        try:
            if (set(value) != required | {"workspace", "operationRoot", "createNew", "directoryPins"}
                    or value["state"] != "ordinary-publication-initialized" or value["createNew"] is not True
                    or value["workspace"] != self.workspace or value["operationRoot"] != self.operation_root
                    or type(pins) is not list or [pin.get("path") for pin in pins] != expected):
                raise ValueError("publisher_initialize_receipt")
            for pin in pins:
                planner.validate_pin(pin, True)
            by_path = {pin["path"]: pin for pin in pins}
            if (by_path[self.workspace]["security"] not in self._directory_security("0x1200a9")
                    or by_path[self.operation_root]["security"] not in self._directory_security("0x1301bf")):
                raise ValueError("publisher_owned_root_security")
        except (ValueError, TypeError, KeyError, AttributeError):
            raise KnownFailure("publisher_initialize_receipt") from None
        self.directory_pins = pins
        self.published = True

    def _publish_files(self, targets, label):
        """Create empty pinned endpoints, write over QGA, then verify; 64 files per batch."""
        planner = self._load("windows_ordinary_task")
        pins = {}
        for number, batch in enumerate(batches(targets, FILE_BATCH), 1):
            rows = [{key: target[key] for key in ("role", "path", "bytes", "sha256", "kind")} for target in batch]
            value, required = self._publisher(label + "-endpoints-" + str(number), "endpoints", targets=rows)
            created = value.get("endpoints")
            try:
                if (set(value) != required | {"endpoints"} or value["state"] != "ordinary-publication-created-set"
                        or type(created) is not list or len(created) != len(rows)):
                    raise ValueError("publisher_endpoint_receipt")
                for receipt, row in zip(created, rows):
                    pin = receipt["filePin"]
                    planner.validate_pin(pin)
                    if (set(receipt) != {"schemaVersion", "state", "operationId", "role", "filePin", "expectedBytes", "expectedSha256",
                                         "createNew", "heldReadOnly", "writeOpenError", "deleteOpenError"}
                            or receipt["state"] != "ordinary-publication-created" or receipt["role"] != row["role"]
                            or receipt["expectedBytes"] != row["bytes"] or receipt["expectedSha256"] != row["sha256"]
                            or receipt["createNew"] is not True or receipt["heldReadOnly"] is not True
                            or receipt["writeOpenError"] != 32 or receipt["deleteOpenError"] != 32
                            or pin["path"] != row["path"] or pin["sha256"] != _sha(b"") or pin["nativeIdentity"]["sizeBytes"] != 0
                            or pin["security"] not in self._file_security()):
                        raise ValueError("publisher_endpoint_receipt")
            except (ValueError, TypeError, KeyError):
                raise KnownFailure("publisher_endpoint_receipt") from None
            for target in batch:
                self.push_file(target["path"], target["raw"])
            rows = [{**row, "endpointPin": receipt["filePin"]} for row, receipt in zip(rows, created)]
            value, required = self._publisher(label + "-verify-" + str(number), "verify", targets=rows)
            verified = value.get("verified")
            try:
                if (set(value) != required | {"verified"} or value["state"] != "ordinary-publication-verified-set"
                        or type(verified) is not list or len(verified) != len(rows)):
                    raise ValueError("publisher_verify_receipt")
                for receipt, row in zip(verified, rows):
                    pin = receipt["filePin"]
                    planner.validate_pin(pin)
                    if (set(receipt) != {"schemaVersion", "state", "operationId", "role", "filePin", "heldPhysicalRead"}
                            or receipt["state"] != "ordinary-publication-verified" or receipt["role"] != row["role"]
                            or receipt["heldPhysicalRead"] is not True or pin["path"] != row["path"] or pin["sha256"] != row["sha256"]
                            or pin["nativeIdentity"]["sizeBytes"] != row["bytes"] or pin["security"] != row["endpointPin"]["security"]
                            or any(pin["nativeIdentity"][key] != row["endpointPin"]["nativeIdentity"][key]
                                   for key in ("attributes", "volumeSerial", "fileIndex", "links", "creationFileTime"))):
                        raise ValueError("publisher_verify_receipt")
                    pins[row["role"]] = pin
            except (ValueError, TypeError, KeyError):
                raise KnownFailure("publisher_verify_receipt") from None
        return pins

    def _read_pins(self, paths, label="publish"):
        planner = self._load("windows_ordinary_task")
        pins = []
        for number, batch in enumerate(batches(paths, READ_PIN_BATCH), 1):
            value, required = self._publisher(label + "-read-pins-" + str(number), "read-pins", readPaths=batch)
            rows = value.get("filePins")
            try:
                if (set(value) != required | {"filePins"} or value["state"] != "ordinary-publication-read-pins"
                        or type(rows) is not list or [pin.get("path") for pin in rows] != batch):
                    raise ValueError("publisher_read_pins_receipt")
                for pin in rows:
                    planner.validate_pin(pin)
            except (ValueError, TypeError, KeyError, AttributeError):
                raise KnownFailure("publisher_read_pins_receipt") from None
            pins.extend(rows)
        return pins

    def _read_directories(self, paths, label):
        planner = self._load("windows_ordinary_task")
        pins = []
        for number, batch in enumerate(batches(paths, DIRECTORY_BATCH), 1):
            value, required = self._publisher(label + "-directories-" + str(number), "read-directories", readDirectories=batch)
            rows = value.get("directoryPins")
            try:
                if (set(value) != required | {"directoryPins"} or value["state"] != "ordinary-publication-read-directories"
                        or type(rows) is not list or [pin.get("path") for pin in rows] != batch):
                    raise ValueError("publisher_read_directories_receipt")
                for pin in rows:
                    planner.validate_pin(pin, True)
            except (ValueError, TypeError, KeyError, AttributeError):
                raise KnownFailure("publisher_read_directories_receipt") from None
            pins.extend(rows)
        return pins

    def _listing(self, label, root):
        value, required = self._publisher(label + "-tree", "list-tree", treeRoot=root)
        listing = value.get("listing")
        try:
            if (set(value) != required | {"treeRoot", "listing"} or value["state"] != "ordinary-tree-listing" or value["treeRoot"] != root
                    or type(listing) is not dict or set(listing) != {"present", "files", "directories"} or type(listing["present"]) is not bool
                    or type(listing["files"]) is not list or type(listing["directories"]) is not list
                    or not all(type(name) is str and name and "\\" not in name and not name.startswith("/") and "//" not in name
                               and ".." not in name.split("/") for name in listing["files"] + listing["directories"])
                    or len(set(name.casefold() for name in listing["files"] + listing["directories"])) != len(listing["files"]) + len(listing["directories"])):
                raise ValueError("publisher_tree_receipt")
        except (ValueError, TypeError, KeyError):
            raise KnownFailure("publisher_tree_receipt") from None
        return listing

    def _listed(self, label, root, required):
        """A tree's listing: present, holding its required files, within one tree's bound."""
        listing = self._listing(label, root)
        if not listing["present"] or not set(required) <= set(listing["files"]):
            raise KnownFailure(label + "_tree_absent")
        if len(listing["files"]) > TREE_FILE_LIMIT:
            raise KnownFailure(label + "_tree_bound")
        return listing

    def _tree_paths(self, root, listing):
        """What pinning a listed tree reads: every file, every unheld ancestor, the root and every directory."""
        held = {pin["path"].casefold() for pin in self.directory_pins}
        directories = [path for path in ancestors([root]) if path.casefold() not in held]
        directories += [root, *(root + "\\" + name.replace("/", "\\") for name in sorted(listing["directories"]))]
        return [root + "\\" + name.replace("/", "\\") for name in sorted(listing["files"])], directories

    def _pin_bound(self, trees):
        """The worker request holds the most pins of a row: its fixed pins and every tree, counted before any tree pin."""
        files = (len(self.read_pins) + sum(1 for _, role, _ in self.row["guestFiles"] if role != "owner")
                 + int("package" in self.file_pins))
        directories = len(self.directory_pins)
        for root, listing in trees:
            tree_files, tree_directories = self._tree_paths(root, listing)
            files += len(tree_files)
            directories += len(tree_directories)
        if files > FILE_PIN_LIMIT or directories > DIRECTORY_PIN_LIMIT:
            raise KnownFailure("worker_pin_bound")

    def _tree(self, label, root, role, listing):
        """A complete tree: a pin for every directory it needs and a read pin for every file."""
        paths, directories = self._tree_paths(root, listing)
        files = sorted(listing["files"])
        directory_pins = self._read_directories(directories, label)
        file_pins = self._read_pins(paths, label)
        return {"tree": {"role": role, "root": root, "files": files}, "directoryPins": directory_pins, "filePins": file_pins,
                "sha256": tree_digest(root, files, file_pins)}

    def _registration(self, label):
        """Registered products named vpn-control in the ordinary user's and the machine's MSI contexts."""
        value, required = self._publisher(label, "msi-registration", productName=PRODUCT_NAME)
        rows, scan = value.get("products"), value.get("scan")
        try:
            if (set(value) != required | {"products", "scan"} or value["state"] != "ordinary-msi-registration" or type(rows) is not list
                    or not all(type(row) is dict and set(row) == {"productCode", "context", "productName", "version", "installLocation"}
                               and isinstance(row["productCode"], str) and _PRODUCT_CODE.fullmatch(row["productCode"])
                               and row["context"] in (1, 2, 4) and row["productName"] == PRODUCT_NAME
                               and isinstance(row["version"], str) and isinstance(row["installLocation"], str) for row in rows)
                    or type(scan) is not dict or set(scan) != {"considered", "unnamed", "unnamedCodes"}
                    or not all(type(scan[key]) is int and scan[key] >= 0 for key in ("considered", "unnamed"))
                    or type(scan["unnamedCodes"]) is not list or len(scan["unnamedCodes"]) > 16
                    or not all(type(code) is int and 0 < code < 65536 for code in scan["unnamedCodes"])):
                raise ValueError("publisher_registration_receipt")
        except (ValueError, TypeError, KeyError):
            raise KnownFailure("publisher_registration_receipt") from None
        self.registration_scan = scan
        return rows

    def _count_check(self, rows):
        """A wrong registration count with what the reader saw: products considered and names it could not read."""
        scan = self.registration_scan
        unread = "unnamed_" + str(min(scan["unnamed"], 999)) + ("_rc_" + str(scan["unnamedCodes"][0]) if scan["unnamedCodes"] else "")
        return "count_" + str(min(len(rows), 9)) + ":considered_" + str(min(scan["considered"], 9999)) + ":" + unread

    def _registration_check(self, rows, code, version):
        """None for exactly one registration: per user, this product code and version, installed where the CLI is run from.

        Otherwise the finite name of the first check that failed; the rows themselves stay on the host.
        """
        if len(rows) != 1:
            return self._count_check(rows)
        row, location = rows[0], self.paths["installed"].casefold()
        for check, held in (("context_" + str(row["context"]), row["context"] == 2), ("code", row["productCode"] == code),
                            ("version", row["version"] == version), ("location_empty", row["installLocation"] != ""),
                            ("location", row["installLocation"].rstrip("\\").casefold() == location)):
            if not held:
                return check
        return None

    def _held_file(self, value, path, package):
        """The publisher's held pin of the published package; a mismatch names its finite check."""
        pin = value.get("filePin")
        try:
            self._load("windows_ordinary_task").validate_pin(pin)
        except ValueError as error:
            raise ValueError("pin_" + str(error)) from None
        for check, held in (("held_path", pin["path"] == path), ("held_sha256", pin["sha256"] == package["sha256"]),
                            ("held_size", pin["nativeIdentity"]["sizeBytes"] == package["bytes"])):
            if not held:
                raise ValueError(check)

    @staticmethod
    def _receipt_check(error):
        """Which receipt check failed, as a finite code: the guest's reply itself stays on the host."""
        text = str(error) if type(error) is ValueError else ""
        return text if _RECEIPT_CHECK.fullmatch(text) else type(error).__name__

    def _msi_properties(self):
        path, package = self.paths["file:package"], self.package()
        value, required = self._publisher("publish-msi-properties", "msi-properties", packagePath=path)
        found = value.get("package")
        try:
            if set(value) != required | {"package"}:
                raise ValueError("keys")
            if value["state"] != "ordinary-msi-properties":
                raise ValueError("state")
            if type(found) is not dict or set(found) != {"filePin", "properties"}:
                raise ValueError("package_shape_" + type(found).__name__)
            properties = found["properties"]
            if type(properties) is not dict:
                raise ValueError("properties_shape_" + type(properties).__name__)
            self._held_file(found, path, package)
        except (ValueError, TypeError, KeyError) as error:
            raise KnownFailure("publisher_msi_receipt:" + self._receipt_check(error)) from None
        code = properties.get("ProductCode")
        if (properties.get("ProductName") != PRODUCT_NAME or properties.get("ProductVersion") != self.plan["product"]["productVersion"]
                or str(properties.get("UpgradeCode")).upper() != UPGRADE_CODE or not isinstance(code, str) or _PRODUCT_CODE.fullmatch(code) is None):
            raise KnownFailure("msi_package_identity")
        return {"productCode": code, "productVersion": properties["ProductVersion"]}

    def _installer_signer(self):
        path, package = self.paths["file:package"], self.package()
        value, required = self._publisher("publish-installer-signer", "installer-signer", installerPath=path)
        signer = value.get("signer")
        try:
            if set(value) != required | {"signer"}:
                raise ValueError("keys")
            if value["state"] != "ordinary-installer-signer":
                raise ValueError("state")
            if type(signer) is not dict or set(signer) != {"filePin", "status", "subject", "certificateSha256"}:
                raise ValueError("signer_shape_" + type(signer).__name__)
            self._held_file(signer, path, package)
        except (ValueError, TypeError, KeyError) as error:
            raise KnownFailure("publisher_signer_receipt:" + self._receipt_check(error)) from None
        if (signer["status"] != "Valid" or not isinstance(signer["subject"], str) or "O=Python Software Foundation" not in signer["subject"]
                or not isinstance(signer["certificateSha256"], str) or _SHA256.fullmatch(signer["certificateSha256"]) is None):
            raise KnownFailure("python_installer_signer")
        return signer["certificateSha256"]

    def stage_publish(self):
        read_paths = list(self.row["readPins"])
        self._initialize(read_paths)
        targets = []
        for relative, role, kind in self.row["guestFiles"]:
            raw = self.files[relative]
            targets.append({"role": role, "path": self.paths["file:" + role], "bytes": len(raw), "sha256": _sha(raw), "kind": kind, "raw": raw})
        package = self.package()
        if package is not None:
            targets.append({"role": "package", "path": self.paths["file:package"], "bytes": package["bytes"], "sha256": package["sha256"],
                            "kind": "data", "raw": package})
        self.file_pins = self._publish_files(targets, "publish")
        self.read_pins = self._read_pins(read_paths)
        if self.row["bootstrapMode"] == "python-install":
            if self._listing("publish-python", self.paths["python"])["present"]:
                raise KnownFailure("python_tree_present")
            self.signer = self._installer_signer()
        if self.row["bootstrapMode"] == "python-worker":
            python = self._listed("python", self.paths["python"], PYTHON_REQUIRED)
            trees, installed = [(self.paths["python"], python)], None
            if self.row.get("priorInstall"):
                rows = self._registration("publish-registration")
                check = self._registration_check(rows, self.prior_installed["productCode"], self.plan["product"]["productVersion"])
                if check is not None:
                    raise KnownFailure("installed_registration_differs:" + check)
                installed = self._listed("installed", self.paths["installed"], INSTALLED_REQUIRED)
                trees.append((self.paths["installed"], installed))
            # Both trees go into one worker request: a joint excess is refused before either tree is pinned.
            self._pin_bound(trees)
            self.python_tree = self._tree("python", self.paths["python"], "python-runtime", python)
            if installed is not None:
                self.installed_tree = self._tree("installed", self.paths["installed"], "installed-app", installed)
                if (self.installed_tree["sha256"] != self.prior_installed["treeSha256"]
                        or len(self.installed_tree["tree"]["files"]) != self.prior_installed["treeFiles"]):
                    raise KnownFailure("installed_tree_differs")
                self.installed = dict(self.prior_installed)
                self.installed_matched = True
        if (self.row.get("package") or {}).get("role") == "basePackage":
            self.msi = self._msi_properties()
            self.registered = self._registration("publish-registration")
            reset = self.row["workerAction"] == "msi-reset"
            # Never a silent upgrade: install needs no product, reset exactly one registered product to remove.
            if len(self.registered) != (1 if reset else 0):
                raise KnownFailure("installed_product_state:" + self._count_check(self.registered))
            if reset and self.registered[0]["context"] != 2:
                raise KnownFailure("installed_product_state:context_" + str(self.registered[0]["context"]))
            if reset and _PRODUCT_CODE.fullmatch(self.registered[0]["productCode"]) is None:
                raise KnownFailure("installed_product_state:code")
            # Files already in the install folder would join the recorded base. Reset's worker checks the same after its removal.
            if not reset and self._listing("publish-installed", self.paths["installed"])["files"]:
                raise KnownFailure("installed_files_present")

    # Stage 4.
    def stage_requests(self):
        try:
            self._build_requests()
        except ValueError as error:  # The planner refused; nothing was started.
            raise KnownFailure("planner_refused:" + token(error)) from None

    def _publish_request(self, role, path, request):
        raw = self._load("windows_ordinary_task").data(request)
        pins = self._publish_files([{"role": role, "path": path, "bytes": len(raw), "sha256": _sha(raw), "kind": "data", "raw": raw}], role)
        return pins[role]

    def _python_runtime(self):
        return {"root": self.paths["python"], "interpreterPath": self.paths["pythonExe"], "version": "3.13.15", "architecture": "amd64"}

    def _build_requests(self):
        planner = self._load("windows_ordinary_task")
        row, paths, owner = self.row, self.paths, self.file_pins["owner"]
        limit = row["rawStreamLimitBytes"]
        expected = {"operationId": self.op, "operationRoot": self.operation_root, "context": self.context, "owner": owner["path"],
                    "ownerSha256": owner["sha256"], "bootstrapTrees": [], "pythonRuntime": None, "worker": None,
                    "installedRoot": paths["installed"]}
        # The task's own executable; msiexec is the worker's child and is held only by the worker request.
        bootstrap_files = [*(pin for pin in self.read_pins if pin["path"] == POWERSHELL_PATH), owner]
        bootstrap_directories, runtime = list(self.directory_pins), None
        requests = {"worker": None}
        if row["bootstrapMode"] == "qualification":
            bootstrap_files.append(self.file_pins["child"])
            inputs = bootstrap_inputs(row, paths)
        elif row["bootstrapMode"] == "python-install":
            bootstrap_files.append(self.file_pins["package"])
            inputs = bootstrap_inputs(row, paths, signer=self.signer)
        else:
            runtime = self._python_runtime()
            python = self.python_tree
            module_pins = [self.file_pins[role] for _, role, _ in row["guestFiles"] if role != "owner"]
            worker_files = [*self.read_pins, *python["filePins"], *module_pins]
            worker_directories = [*self.directory_pins, *python["directoryPins"]]
            worker_trees = [python["tree"]]
            if "package" in self.file_pins:
                worker_files.append(self.file_pins["package"])
            if self.installed_tree is not None:
                worker_files += self.installed_tree["filePins"]
                worker_directories += self.installed_tree["directoryPins"]
                worker_trees.append(self.installed_tree["tree"])
            code = self.registered[0]["productCode"] if row["workerAction"] == "msi-reset" else None
            closed = worker_inputs(row, paths, self.plan.get("product"), product_code=code)
            worker_common = planner.common_request(self.context, self.op, self.operation_root, worker_files, worker_directories,
                                                   worker_trees, limit, runtime)
            requests["worker"] = planner.worker_request(worker_common, row["workerAction"], **closed)
            expected["worker"] = {"inputs": closed, "files": {pin["path"]: pin["sha256"] for pin in worker_files},
                                  "directories": [pin["path"] for pin in worker_directories], "trees": worker_trees}
            expected["pythonRuntime"] = runtime
            assert_closed_worker(row, requests["worker"], expected)
            self.worker = self._publish_request("worker-request", paths["workerRequest"], requests["worker"])
            bootstrap_files += [*python["filePins"], self.file_pins["worker"], self.worker]
            bootstrap_directories += python["directoryPins"]
            expected["bootstrapTrees"] = [python["tree"]]
            inputs = bootstrap_inputs(row, paths, worker_pin=self.worker, encode=planner.data)
        common = planner.common_request(self.context, self.op, self.operation_root, bootstrap_files, bootstrap_directories,
                                        expected["bootstrapTrees"], limit, runtime)
        requests["bootstrap"] = planner.bootstrap_request(common, row["bootstrapMode"], **{k: v for k, v in inputs.items() if k != "mode"})
        expected.update(files={pin["path"]: pin["sha256"] for pin in bootstrap_files},
                        directories=[pin["path"] for pin in bootstrap_directories], bootstrap=inputs)
        assert_closed(row, requests, expected)
        self.request_pin = self._publish_request("bootstrap-request", paths["bootstrapRequest"], requests["bootstrap"])
        self.rendered_task = planner.render_task(requests["bootstrap"], owner, self.request_pin)
        assert_closed(row, {**requests, "task": self.rendered_task}, {**expected, "requestSha256": self.request_pin["sha256"]})

    # Stage 5.
    def _on_status(self):
        """Read the fixed status file; a miss proves nothing and never ends the job."""
        path = self.workspace + "\\scenario-status.json"
        try:
            raw = self.read_guest_file(path, 8192)
            json.loads(raw, object_pairs_hook=_unique)
        except Exception:
            return
        temporary = self.data / "status.json.new"
        temporary.write_bytes(raw)
        os.replace(temporary, self.data / "status.json")

    def _system_run_source(self, m):
        emitter = self._load("windows_artifact_transfer")
        parts = fragments(self._bundle_source(OWNER_SOURCE), emitter)
        template = fill_template(self._bundle_source(RUN_TEMPLATE).decode("ascii"),
                                 {"INPUT": bound_input(m), "NATIVE": parts["NATIVE"], "ASSERTIONS": parts["ASSERTIONS"],
                                  "POLICY_VALIDATOR": self.rendered_task["policyValidatorPowerShell"]})
        return wrap_output(emitter._boot_bound(template, self.raw_context))

    def stage_run(self):
        task = self.rendered_task
        m = {"schemaVersion": 1, "operationId": self.op, "mode": self.row["bootstrapMode"], "scenarioId": self.plan["scenarioId"],
             "context": self.context, "workspace": self.workspace, "taskName": task["taskName"], "taskRequestPin": self.request_pin,
             "taskArguments": task["policyExpected"]["Arguments"], "deadlineSeconds": self.row["deadlineSeconds"],
             # A BSTR is UTF-16: the planner's UTF-8 declaration describes bytes COM never sees.
             "taskXml": re.sub(r"\A<\?xml[^>]*\?>\s*", "", task["xmlUtf8"])}
        terminal, pid = self.guest_program("system-run", self._rendered(lambda: self._system_run_source(m)),
                                           budget=self.row["deadlineSeconds"] + RUN_MARGIN_SECONDS,
                                           poll=STATUS_POLL_SECONDS, on_poll=self._on_status)
        self._on_status()
        if refused_before_effects(terminal):
            raise KnownFailure("system_run_refused_before_file_effects")
        emitter = self._load("windows_artifact_transfer")
        try:
            value = emitter.decode_guest_result({"transport": "inline"}, decode_stdout(terminal), self.raw_context, pid)
        except (ValueError, TypeError, KeyError):
            raise Unknown("system_run_unreadable") from None
        state = value.get("state")
        self.task = value
        self._keep("system-run-index.json", (json.dumps(value, sort_keys=True) + "\n").encode())
        if value.get("operationId") != self.op or value.get("productOperation") is not False:
            raise Unknown("system_run_identity")
        if state == "refused-before-launch":
            raise KnownFailure("refused_before_launch:" + guest_code(value.get("code")))
        if state != "task-finished":
            raise Unknown(state if state in _OPEN_RUN_STATES else "system_run_state_unrecognized")
        self._check_task(value)
        self.task_checked = True

    def _check_task(self, value):
        def need(condition, code):
            if not condition:
                raise KnownFailure("task_" + code)
        expected = self.row["expectedExit"]
        kinds = [row.get("kind") for row in value.get("events", [])]
        streams = {row.get("name"): row for row in value.get("rawStreams", [])}
        # The owner's journal is the only proof of its child. One that opened and shows
        # neither a terminal nor a refusal means an owner that died, and its child may be live.
        if kinds and "terminal" not in kinds and "refused-before-native-start" not in kinds:
            raise Unknown("task_child_outcome_unknown")
        need(value.get("taskDeleted") is True, "not_deleted")
        need(value.get("ownerExitCode") == expected and value.get("terminalExitCode") == expected, "exit_code")
        need(len(kinds) >= 3 and kinds[0] == "submission-intent" and kinds[-1] == "terminal", "events")
        need(value.get("commandLineMatched") is True, "command_line")
        for name, text in self.row["expectedStreams"].items():
            raw = text.encode("ascii")
            need(streams.get(name, {}).get("bytes") == len(raw) and streams[name].get("sha256") == _sha(raw), name)

    # Stage 5b: what an installer row left behind, read after its owner finished.
    def stage_installed(self):
        if self.row["bootstrapMode"] == "python-install":
            listing = self._listing("after-python", self.paths["python"])
            if not listing["present"] or not set(PYTHON_REQUIRED) <= set(listing["files"]):
                raise KnownFailure("python_tree_absent")
            self.python_facts = {"files": len(listing["files"]), "directories": len(listing["directories"])}
            return
        if self.row["workerAction"] not in {"msi-install", "msi-reset"}:
            return
        rows = self._registration("after-registration")
        check = self._registration_check(rows, self.msi["productCode"], self.msi["productVersion"])
        if check is not None:
            raise KnownFailure("installed_registration_differs:" + check)
        tree = self._tree("after-installed", self.paths["installed"], "installed-app",
                          self._listed("after-installed", self.paths["installed"], INSTALLED_REQUIRED))
        self.installed = {"packageSha256": self.package()["sha256"], "productCode": self.msi["productCode"],
                          "productVersion": self.msi["productVersion"], "treeSha256": tree["sha256"], "treeFiles": len(tree["tree"]["files"])}

    # Stage 6.
    def stage_evidence(self):
        self.evidence_number += 1
        number = self.evidence_number
        value, required = self._publisher("evidence-zip-" + str(number), "evidence-zip", evidenceNumber=number)
        path = self.workspace + "\\evidence-" + str(number) + ".zip"
        if (set(value) != required | {"zipPath", "zipBytes", "zipSha256", "entries"} or value["state"] != "ordinary-evidence-zip"
                or value["zipPath"] != path or type(value["zipBytes"]) is not int or type(value["entries"]) is not int):
            raise KnownFailure("evidence_receipt")
        try:
            raw = self.read_guest_file(path, value["zipBytes"], truncate_wires=True)
        except Exception:
            raise KnownFailure("evidence_read_lost") from None
        if len(raw) != value["zipBytes"] or _sha(raw) != value["zipSha256"]:
            raise KnownFailure("evidence_hash")
        name = "evidence-" + str(number) + ".zip"
        self._keep(name, raw)
        self.evidence = {"name": name, "bytes": len(raw), "sha256": value["zipSha256"], "entries": value["entries"]}

    # Stage 7 and the end of the job.
    def _finish(self, code, failure):
        try:
            if self.owns_data:
                # The raw identity as the guest reports it: this is what a first proof reads.
                context = None if self.context is None else {**self.context, **{
                    "hardwareUuid": self.raw_context["boot"]["hardwareUuid"], "machineGuid": self.raw_context["boot"]["machineGuid"]}}
                # Installed-package evidence: a passed product row whose MSI registration, complete
                # installed tree and --version (the worker's own static probe or the harness) all held.
                # A job stopped before its task matched the first two but never ran --version.
                claimed = (code == EXIT_PASSED and self.row["evidenceClass"] == "product" and self.installed_matched
                           and self.task_checked and self.plan.get("stopAfter") is None)
                windows = {"installedPackage": claimed, "packageSha256": self.package_target()["sha256"] if claimed else None}
                receipt = build_receipt(self.plan, exit_code=code, stage=self.stage, failure=failure, context=context,
                                        task=self.task, evidence=self.evidence, guest_programs=self.programs,
                                        installed=self.installed, python=self.python_facts, windows=windows)
                raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
                if len(raw) > RECEIPT_BYTES:
                    raise ValueError("receipt_bound")
                self._keep("scenario-receipt.json", raw)
                self._keep("job-exit.json", (json.dumps({"schemaVersion": 1, "operationId": self.op, "exitCode": code,
                                                         "fenceAnchored": self.anchored}, sort_keys=True) + "\n").encode())
            if self.anchored and code in KNOWN_EXITS:
                self.rt.save("direct-guest-" + self.op + ".terminal.json", {"exited": True, "exitcode": code})
        except Exception:
            code, failure = EXIT_UNKNOWN, "finish_failed"
        self.rt.emit(json.dumps({"schemaVersion": 1, "operationId": self.op, "scenarioExit": code, "failure": failure},
                                sort_keys=True, separators=(",", ":")))
        return code

    def run(self):
        code, failure = EXIT_PASSED, None
        stop = self.plan.get("stopAfter")
        stages = {"anchor": self.stage_anchor, "context": self.stage_context, "publish": self.stage_publish,
                  "requests": self.stage_requests, "run": self.stage_run, "installed": self.stage_installed}
        try:
            for name in self.row["stages"]:
                if name not in stages:
                    break
                self.stage = name
                stages[name]()
                if stop == name:
                    break
        except Refused as error:
            code, failure = EXIT_REFUSED, token(error)
        except KnownFailure as error:
            code, failure = EXIT_FAILED, token(error)
        except Unknown as error:
            code, failure = EXIT_UNKNOWN, token(error)
        except Exception as error:
            if self.anchored:
                code, failure = EXIT_UNKNOWN, "unexpected:" + type(error).__name__
            else:  # Only guest-ping went out. A partly saved intent still blocks through prior_fence_open.
                code, failure = EXIT_REFUSED, "host_prepare:" + type(error).__name__
        if self.published and not self.program_open and stop is None and "evidence" in self.row["stages"]:
            # Only after the last program returned: a lost ack or terminal ends the job here. This copy
            # stops and deletes nothing and leaves a parked owner's live files as they are; its one
            # new file is the zip in the workspace.
            before, stage = code, self.stage
            self.stage = "evidence"
            try:
                self.stage_evidence()
            except KnownFailure as error:
                if code == EXIT_PASSED:
                    code, failure = EXIT_FAILED, token(error)
            except Exception as error:
                code = EXIT_UNKNOWN
                failure = failure or token(error if isinstance(error, Unknown) else "unexpected:" + type(error).__name__)
            if before != EXIT_PASSED:
                self.stage = stage
        if code == EXIT_PASSED and stop is None:
            self.stage = "receipt"
        return self._finish(code, failure)


def run_job(rt, plan, files):
    return Job(rt, plan, files).run()


def locked_exchange(path, perform, *, wait=QGA_LOCK_WAIT_SECONDS, monotonic=time.monotonic, sleep=time.sleep):
    """Flock around one exchange only, released before returning, so readiness still works."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        limit = monotonic() + wait
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if monotonic() >= limit:
                    raise ValueError("scenario_qga_busy") from None
                sleep(.05)
        return perform()
    finally:
        os.close(descriptor)


def _host_boot():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def _staged_files():
    payload = json.loads(gzip.decompress(base64.b64decode(FILES_GZ)))
    return {relative: base64.b64decode(value) for relative, value in payload.items()}


def _host_main():
    """Production binding of the seam; run only inside the rendered program."""
    _CANONICAL_INSTANCE_DEFINITIONS()
    plan = PLAN

    def marker(code, failure):
        print(json.dumps({"schemaVersion": 1, "operationId": plan["operationId"], "scenarioExit": code,
                          "failure": token(failure)}, sort_keys=True, separators=(",", ":")))
        return code
    try:
        chain()
        current_actor = read("qemu-started.json")

        def vm_guard():
            require(_host_boot() == CONTEXT["hostBootId"], "instance_host_epoch")
            instance_intent()
            closing()
            process(current_actor)
            owns(current_actor["pid"], root / "qmp.sock", True)
            mutable = read("mutable-artifacts.json")
            require(set(mutable) == {"disk.qcow2", "uefi-vars.fd"}, "instance_mutable_receipt")
            for name, identity in mutable.items():
                require(identity == list(structure(private(root / name))), "instance_mutable_changed")
                owns(current_actor["pid"], root / name)
            tpm = read("swtpm-started.json")
            process(tpm)
            owns(tpm["pid"], root / "swtpm.sock", True)
        vm_guard()

        def exchange(command, arguments, budget=8):
            def perform():
                global QGA_PEER_PID, QGA_GUARD
                vm_guard()
                QGA_PEER_PID = current_actor["pid"]
                owns(QGA_PEER_PID, root / "qga.sock", True)
                named = os.lstat(root / "qga.sock")

                def guarded():
                    vm_guard()
                    require(os.lstat(root / "qga.sock").st_ino == named.st_ino, "instance_qga_changed")
                QGA_GUARD = guarded
                value = call(str(root / "qga.sock"), command, arguments, _deadline=time.monotonic() + budget)
                vm_guard()
                return value
            return locked_exchange(root / "intent.json", perform)

        def durable_save(name, value):
            save(name, value)
            descriptor = os.open(root, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        def open_wires(data):
            global wire, partial_wire
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW
            wire = os.open(data / "qga.wire", flags, 0o600)
            partial_wire = os.open(data / "qga.partial-wire", flags, 0o600)

        def after_read():
            for descriptor in (wire, partial_wire):
                if descriptor != -1:
                    os.ftruncate(descriptor, 0)

        def admission():
            lock = Path(plan["dataDirectory"]).parent / ".admission.lock"
            descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return os.fdopen(descriptor, "rb")
        rt = types.SimpleNamespace(root=root, pid=os.getpid(), rpc=exchange, save=durable_save, sleep=time.sleep,
                                   monotonic=time.monotonic, emit=print, open_wires=open_wires, after_read=after_read,
                                   admission=admission)
        files = _staged_files()
    except Exception as error:  # Nothing reached the guest and no fence exists.
        return marker(EXIT_REFUSED, "host_setup:" + _setup_reason(error))
    try:
        return run_job(rt, plan, files)
    except BaseException as error:
        return marker(EXIT_UNKNOWN, "unexpected:" + type(error).__name__)
