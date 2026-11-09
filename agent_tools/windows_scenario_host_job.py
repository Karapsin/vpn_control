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
import datetime
import gzip
import hashlib
import hmac
import io
import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import stat
import sys
import time
import types
import uuid
import zipfile
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
                 r"|(?:python-install|msi-install|msi-uninstall)[0-9A-Za-z_.-]*\.log|update-[a-z0-9-]+\.json)")
# The public-update rows. The fixture, its TLS files and the collector roots live in the workspace,
# which the ordinary user may only read; the fixture's server-state folder alone is the user's.
UPDATE_ACTION = "windows-public-update"
UPDATE_FOLDERS = ("windows_public_updater", "windows_system_collector")
UPDATE_TLS = "update-tls"
UPDATE_NEED = "update-native-observation-needed"
PROGRAM_DATA = "C:\\ProgramData"
TRUSTSTORE_ALIAS = "vpn-control-fixture-github"
TRUSTSTORE_PASSWORD = "fixture"  # update_fixture_server.owner_jvm_environment names this store password.
FIXTURE_RELEASE = "disposable-desktop-fixture"
INVENTORY_NAME = "installed-inventory.json"
# The bootstrap's terminal event and its reply each carry the child's stdout as base64, and QGA encodes
# the reply again: 64 KiB of child output stays far below the 256 KiB event cap and MAX_TERMINAL_BYTES.
COLLECTOR_RAW_LIMIT = 65536
COLLECTOR_BUDGET_SECONDS = 1800
COLLECTOR_ROOT_SDDL = "O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;{sid})"  # collector_contract.root_policy
# collector_contract.file_policy: the form a file the publisher protects with SetAccessControl reads back natively.
COLLECTOR_FILE_SDDL = "O:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;{sid})"
# The installer helper of the installed base: the elevated coordinator and its original-user worker run this one image.
INSTALL_HELPER = ("app", "native", "windows-amd64", "vpn-control-install-helper.exe")
INSTALL_HELPER_OPERATIONS = ["validate-only", "install-user", "install-coordinator"]  # DesktopWindowsInstallHelperAdmission
INSTALL_ROLES = (("coordinator", "install-coordinator"), ("worker", "install-user"))
INSTALL_JOBS = PROGRAM_DATA + "\\vpn-control-install-jobs"
INSTALL_INPUTS = "vpn-control-install-inputs"
CENSUS_LIMIT = 16
RETURNED_ACTORS_EVENT = "update-returned-cleanup-expected-actors"
# The nine module roles of one SYSTEM collector request, by the guest file role that carries each.
COLLECTOR_MODULES = {"holdProtocol": "hold_protocol", "taskGuard": "task_guard", "nativeBridge": "native_bridge",
                     "native": "native_primitives", "receipts": "receipts", "observer": "broker_observer",
                     "contract": "collector_contract", "worker": "system_worker", "collector": "collector"}
UPDATE_MODULE_ROLES = ("receipts", "server", "fixture_environment", "macos_packaging_jdk_preflight",
                       "prepare_desktop_update_fixture", "broker_observer", "lifecycle", "collector")
OBSERVED_CHILDREN = ("update-public-serve", "one-public-update-install")
# A collector stage for the update and TUN grant rows runs inside "run", driven by the
# owner's update-native-observation-needed kind in the status file; see Job._on_status.
# "installed" reads what an installer row left behind, before evidence is copied. "declare"
# follows the evidence of a passed reboot preboot row: it publishes the product allowance.
STAGE_ORDER = ("anchor", "context", "publish", "requests", "run", "installed", "evidence", "declare", "receipt")
STOP_AFTER = frozenset({"context", "publish"})
_TOKEN_CHARACTERS = re.compile(r"[^A-Za-z0-9_.:-]+")
_LABEL = re.compile(r"[a-z][a-z0-9-]{0,79}\Z")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_BUNDLE_PATH = re.compile(r"(?:agent_tools(?:/windows_public_updater|/windows_system_collector)?|scripts|scripts/integration)/[A-Za-z0-9_.-]+\Z")
_INSTALLED_JAR = re.compile(r"app/[A-Za-z0-9_.+-]+\.jar\Z")
_FIXTURE_FILE = re.compile(r"[A-Za-z0-9_.+-]{1,120}\.msi\Z")
_ACCOUNT = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,19}\Z")
_ADMIN_SID = re.compile(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+\Z")
_PRODUCT_CODE = re.compile(r"\{[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}\}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(?:[1-9]|1[0-9])\.(?:[0-9]|1[0-9])\.(?:[0-9]|1[0-9])\Z")
_GUEST_CODE = re.compile(r"(?:RUN|TASK|TOKEN|PUB)_[A-Z0-9_]{1,80}\Z")
# A publisher template refusal as its stderr carries it: the code, then an optional detail word and Win32 code.
_PUBLISHER_REFUSAL = re.compile(r"\b(PUB_[A-Z0-9_]{1,80})(?::([A-Za-z]{1,40})(?::([0-9]{1,10}))?)?")
# The finite name of the receipt check a publisher reply failed; never guest text.
_RECEIPT_CHECK = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_SETUP_WORD = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_OPEN_RUN_STATES = frozenset({"owner-parked", "deadline", "post-launch-unknown"})
# Reboot rows: one preboot operation, readiness-reboot, then its postboot operation naming it.
PRODUCT_GUI = "vpn-control.exe"
RUNTIME_LEAF = "sing-box.exe"
# The package has no loose runtime: it ships inside an app jar and is extracted per workspace to
# runtime\tools. Its digest is runtimeAuthority in this installed record (the product's helper admission reads it).
RUNTIME_AUTHORITY = ("app", "native", "windows-amd64", "native-helpers.json")
AUTHORITY_BYTES = 65536  # DesktopWindowsPackagedHelperAdmission.MAX_MANIFEST_BYTES
ALLOWANCE_LEAF = "product-allowance.json"
ALLOWANCE_SCHEMA = "vpn-control.windows-product-allowance"
TRAFFIC_LEAF = "traffic-input.json"
UPSTREAM_TOKEN = "vpn-control-reboot-upstream"  # windows_postboot_source_roles.UPSTREAM_TOKEN
DECLARED_ROLES = ("guiLauncher", "gui", "controllerLauncher", "controller", "runtime")
_EVENT_NAME = re.compile(r"event-[0-9]{6}-([a-z0-9-]{1,80})\.json\Z")
AUTOSTART_INTENTS = frozenset({"autostart-public-toggle-intent", "autostart-highest-fixture-intent", "product-autostart-start-intent"})
# readiness-reboot's own VM-root journal: the only reboot submitter's record of the reboot a postboot follows.
_RECOVERY_INTENT = re.compile(r"readiness-recovery-([0-9a-f]{64})\.intent\.json\Z")
# The document rows: the shared worker's document-acceptance action, a large routing document the publisher makes
# in the guest from a fixed recipe, one spool parent under the operation root, and, for the acceptance row, one
# LOCAL SERVICE probe the job runs while the owner's serve holds its endpoint.
DOCUMENT_INPUT_LEAF = "document-large-routing.json"
DOCUMENT_INPUT_ENTRIES = 320000
DOCUMENT_TEMP = "document-temp"
DOCUMENT_CONTEXTS = 52
DOCUMENT_COLD_INPUT = "document-cold-input.json"
DOCUMENT_LEGACY_INPUT = "document-legacy-newline.json"
# windows-document-responsive: the same action with the responsive case module and its responsiveWork, two transfer
# contexts of its own, and the work fixture's self-signed localhost certificate, key and trust store, made here as the
# proxy rows' are (windows_scenario_proxy.material) and published beside the bundle files.
DOCUMENT_RESPONSIVE = "responsive"
RESPONSIVE_CONTEXTS = 2
RESPONSIVE_TLS = (("certificate", "document-work-localhost.pem"), ("privateKey", "document-work-localhost.key"),
                  ("trustStore", "document-work-trust.jks"))
PRINCIPAL_WINDOW = "document-principal-window"
LOCAL_SERVICE = "S-1-5-19"
_DOMAIN_BOUNDARY = re.compile(r"[,\n\r\t ]")
_ROUND_TRIP_UTC = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,7}))?Z\Z")


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


def held_program_type(emitter):
    """The VpnHeldProgram type a saved-source launcher defines before its program runs. A collector template
    calls it for its native bridge, so on the stdin route the job defines it, from the same pinned emitter."""
    body = emitter._HELD_BODY
    found = body.index("public static class VpnHeldProgram")
    start = body.rindex("Add-Type -TypeDefinition @'", 0, found)
    end = body.index("\n'@ -ReferencedAssemblies @('System','System.Core')", found)
    return body[start:end] + "\n'@ -ReferencedAssemblies @('System','System.Core')\n"


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


def context_source(guest, user, native, administrator=None):
    """Read-only and not boot-bound: this is what the boot-bound programs are built from.

    An update row also reads the SID of the fixture's administrator account, the one a grant would approve with.
    """
    marker = "[Console]::WriteLine(($result|ConvertTo-Json -Depth 6 -Compress))"
    session = guest.powershell_source(user)
    if session.count(marker) != 1:
        raise ValueError("windows_context_source")
    if administrator is not None and (type(administrator) is not str or _ACCOUNT.fullmatch(administrator) is None):
        raise ValueError("windows_context_administrator")
    admin = "" if administrator is None else "administratorSid=[string](Get-LocalUser -Name '" + administrator + "').SID.Value;"
    body = session.replace(marker, "$sessionFacts=$result") + native + (
        "$scenarioOs=Get-CimInstance Win32_OperatingSystem\n"
        "$r=[ordered]@{sessionFacts=$sessionFacts;machineGuid=[string](Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' -Name MachineGuid).MachineGuid;"
        "hardwareUuid=[string](Get-CimInstance Win32_ComputerSystemProduct).UUID;bootIdentifier=[OrdinaryNativeFacts]::BootIdentifier();"
        "bootFileTimeUtc=$scenarioOs.LastBootUpTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture);"
        "profileRoot=[string](Get-ItemProperty -LiteralPath ('HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\'+$sessionFacts.expectedSid) -Name ProfileImagePath).ProfileImagePath;"
        + admin + "systemToken=@([OrdinaryNativeFacts]::Token())}\n"
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
             "msiUninstallLog": root + "\\msi-uninstall.log", "gui": installed + "\\" + PRODUCT_GUI,
             "allowance": workspace + "\\" + ALLOWANCE_LEAF}
    if row.get("reboot"):
        paths["file:trafficInput"] = workspace + "\\" + TRAFFIC_LEAF
    if row.get("document"):
        paths.update(documentInput=workspace + "\\" + DOCUMENT_INPUT_LEAF, documentTemp=root + "\\" + DOCUMENT_TEMP,
                     principalEndpoint=root + "\\workspace\\activation.port")
    for relative, role, _ in row["guestFiles"]:
        # A file of an update bundle subfolder keeps that one folder, where its siblings expect it; any other file,
        # scripts/integration ones included, sits flat in the workspace.
        parts = relative.split("/")
        paths["file:" + role] = workspace + "\\" + (parts[1] + "\\" if len(parts) == 3 and parts[1] in UPDATE_FOLDERS else "") + parts[-1]
    # A row's generated files and the runtime extracted from its installed product sit beside its bundle files.
    for role, leaf in (*row.get("generated", ()), *row.get("extracted", ())):
        paths["file:" + role] = workspace + "\\" + leaf
    if row.get("package"):
        paths["file:package"] = workspace + "\\" + row["package"]["leaf"]
    if row.get("update"):
        fixture, tls = workspace + "\\mcp-update-fixture-" + fixture_id(operation), workspace + "\\" + UPDATE_TLS
        paths.update(fixtureRoot=fixture, fixtureContent=fixture + "\\content", fixtureState=fixture + "\\server-state",
                     fixtureReceipt=fixture + "\\content\\fixture-receipt.json", fixtureTarget=fixture + "\\content\\packages\\target",
                     tls=tls, certificate=tls + "\\server-cert.pem", privateKey=tls + "\\server-key.pem",
                     trustStore=tls + "\\fixture-trust.p12", harness=workspace + "\\update-harness.py",
                     evidenceRoot=PROGRAM_DATA + "\\update-evidence-" + operation)
        for stage in row["update"]["collectorStages"]:
            paths["collector:" + stage] = workspace + "\\system-collector-" + collector_operation(operation, stage)
    return paths


def fixture_id(operation):
    return str(uuid.uuid5(uuid.UUID(operation), "windows-public-update-fixture"))


def collector_operation(operation, stage):
    """One SYSTEM collector per stage of one operation: the close hold names the final one before the task runs."""
    return str(uuid.uuid5(uuid.UUID(operation), "windows-public-update-collector:" + stage))


def decision_id(operation):
    """windows_uac_decision.decision_id: one decision per scenario, its terminal in the VM root's windows-uac folder."""
    return str(uuid.uuid5(uuid.UUID(operation), "windows-uac-decision"))


def update_subfolders(operation, row):
    """Closed folders of one update row, parents first, with the ordinary user's rights on each."""
    if not row.get("update"):
        return []
    fixture = "mcp-update-fixture-" + fixture_id(operation)
    folders = [(name, "0x1200a9") for name in (*UPDATE_FOLDERS, UPDATE_TLS, fixture, fixture + "\\content",
                                               fixture + "\\content\\packages", fixture + "\\content\\packages\\target")]
    folders.append((fixture + "\\server-state", "FA"))  # The user's own: the server writes its probe events and ready file here.
    folders += [("system-collector-" + collector_operation(operation, stage), "0x1200a9") for stage in row["update"]["collectorStages"]]
    return folders


# DER for one Java trust store: the public certificate only, no key, so it is built on the host.
def _der(tag, body):
    size = len(body)
    head = bytes([size]) if size < 0x80 else bytes([0x80 | ((size.bit_length() + 7) // 8)]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + head + body


def _der_oid(text):
    parts = [int(part) for part in text.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        body.extend(reversed(chunk))
    return _der(0x06, bytes(body))


def _der_integer(value):
    return _der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def pkcs12_key(password, salt, iterations, size, name="sha256"):
    """RFC 7292 appendix B.2 with ID 3, the MAC key of a PKCS #12 store."""
    u, v = hashlib.new(name).digest_size, hashlib.new(name).block_size
    secret = password.encode("utf-16-be") + b"\0\0"

    def stretch(raw):
        return (raw * (v * ((len(raw) + v - 1) // v) // len(raw) + 1))[:v * ((len(raw) + v - 1) // v)] if raw else b""
    block = bytearray(stretch(salt) + stretch(secret))
    output = b""
    while len(output) < size:
        digest = hashlib.new(name, bytes([3]) * v + bytes(block)).digest()
        for _ in range(iterations - 1):
            digest = hashlib.new(name, digest).digest()
        output += digest
        addend = int.from_bytes((digest * (v // u + 1))[:v], "big") + 1
        for at in range(0, len(block), v):
            block[at:at + v] = ((int.from_bytes(block[at:at + v], "big") + addend) % (1 << (8 * v))).to_bytes(v, "big")
    return output[:size]


def java_truststore(certificate, salt, iterations=2048):
    """One PKCS #12 trusted certificate entry, as keytool writes it: a certificate bag with Oracle's
    trusted key usage attribute, which is what makes a JVM read it as a trust anchor."""
    attributes = sorted([_der(0x30, _der_oid("2.16.840.1.113894.746875.1.1") + _der(0x31, _der_oid("2.5.29.37.0"))),
                         _der(0x30, _der_oid("1.2.840.113549.1.9.20") + _der(0x31, _der(0x1E, TRUSTSTORE_ALIAS.encode("utf-16-be"))))])
    bag = _der(0x30, _der_oid("1.2.840.113549.1.9.22.1") + _der(0xA0, _der(0x04, certificate)))
    contents = _der(0x30, _der(0x30, _der_oid("1.2.840.113549.1.12.10.1.3") + _der(0xA0, bag) + _der(0x31, b"".join(attributes))))
    data = _der_oid("1.2.840.113549.1.7.1")
    safe = _der(0x30, _der(0x30, data + _der(0xA0, _der(0x04, contents))))
    mac = hmac.new(pkcs12_key(TRUSTSTORE_PASSWORD, salt, iterations, 32), safe, "sha256").digest()
    mac_data = _der(0x30, _der(0x30, _der(0x30, _der_oid("2.16.840.1.101.3.4.2.1") + b"\x05\x00") + _der(0x04, mac))
                    + _der(0x04, salt) + _der_integer(iterations))
    return _der(0x30, _der_integer(3) + _der(0x30, data + _der(0xA0, _der(0x04, safe))) + mac_data)


def update_harness(inputs, hold):
    """The literal harness the dedicated driver admits: a docstring, then exactly two literal constants."""
    text = ('"""Literal public-update inputs of one scenario operation."""\n'
            "UPDATE_INPUTS = " + repr(inputs) + "\nSYSTEM_COLLECTOR_CLOSE_HOLD = " + repr(hold) + "\n")
    compile(text, "update harness", "exec")
    return text.encode("utf-8")


def version_build(version):
    """prepare_desktop_update_fixture.version_build: the update manifest's build number of a version."""
    value = 0
    for component in (*map(int, version.split(".")), 0):
        value = value * 20 + component
    return value


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


def traffic_input():
    """The pinned traffic sampler input: the in-guest upstream's fixed body; the port is the product's, at run time."""
    value = {"schemaVersion": 1, "mixedPort": None, "expectedBodyHex": UPSTREAM_TOKEN.encode("ascii").hex(), "sampleCount": 8,
             "intervalSeconds": 0.1, "ioTimeoutSeconds": 2}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def document_input(entries=DOCUMENT_INPUT_ENTRIES):
    """The document rows' large routing document, byte for byte what the publisher's document-input action writes:
    the product's own export form (RoutingRulesTransfer.writeExport) with a fixed timestamp and unique suffixes."""
    head = ('{\n  "type": "vpn_control_routing_rules",\n  "version": 7,\n  "exported_at": "2026-01-01T00:00:00Z",\n  "rules": {\n'
            '    "ignore_rules": false,\n    "block_quic_udp_443": false,\n    "proxy_packages": [],\n    "direct_domain_suffixes": [')
    body = ",".join('\n      "d%07d.document.invalid"' % number for number in range(entries))
    return (head + body + "\n    ]\n  }\n}").encode("ascii")


def normalized_suffixes(values):
    """RoutingRulesCharacterImport's domain entries: each string split at , LF CR tab and space, trimmed, a leading
    *. and outer dots removed, lower-cased, first occurrence kept. A legacy newline-joined entry is many domains."""
    found = {}
    for value in values:
        for token in _DOMAIN_BOUNDARY.split(value):
            token = token.strip()
            token = token[2:] if token.startswith("*.") else token
            token = token.lstrip(".").rstrip(".").lower()
            if token:
                found.setdefault(token, None)
    return list(found)


LEGACY_ENTRIES = ("alpha.legacy.invalid\nbeta.legacy.invalid\r\ngamma.legacy.invalid",
                  "*.Delta.Legacy.Invalid\tepsilon.legacy.invalid,zeta.legacy.invalid",
                  "alpha.legacy.invalid", " .eta.legacy.invalid. ", "\n\r\n")


def legacy_newline_input():
    """A routing document whose domain entries are legacy joined lists, as an older store kept them in one string."""
    value = {"type": "vpn_control_routing_rules", "version": 7, "rules": {"ignore_rules": False, "block_quic_udp_443": False,
             "proxy_packages": [], "direct_domain_suffixes": list(LEGACY_ENTRIES)}}
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("ascii")


def routing_semantic_sha256(suffixes):
    """What the product's export of these rules is compared by: type, version and rules, never exported_at."""
    value = {"type": "vpn_control_routing_rules", "version": 7, "rules": {"ignore_rules": False, "block_quic_udp_443": False,
             "proxy_packages": [], "direct_domain_suffixes": list(suffixes)}}
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"))


def document_contexts(operation):
    """The 52 reserved transfer contexts the document action names: canonical, distinct and never the operation's own."""
    return [str(uuid.uuid5(uuid.UUID(operation), "windows-document-context-%02d" % number)) for number in range(DOCUMENT_CONTEXTS)]


def responsive_contexts(operation):
    """The responsive cases' own two transfer contexts: canonical, distinct, and never one of the 52 or the operation."""
    return [str(uuid.uuid5(uuid.UUID(operation), "windows-document-responsive-context-%d" % number)) for number in range(RESPONSIVE_CONTEXTS)]


def document_inputs(row, paths, product, operation):
    """The one document-acceptance request a row may run: its fixed case module, the three document modules, the
    public harness, the guest-made large document and the spool parent; nothing else. The responsive row adds its
    responsiveWork: the responsive cases, the runtime stages, the work fixture and its two producers, the TLS files
    this job made, two contexts of its own and the same large document."""
    inputs = {"cliPath": paths["cli"], "workspace": paths["productWorkspace"], "productVersion": product["productVersion"],
              "casesPath": paths["file:cases"], "harnessPath": paths["file:harness"],
              "documentAcceptance": {"schemaVersion": 1, "clientPath": paths["file:client"], "windowsPath": paths["file:windows"],
                                     "racePath": paths["file:race"], "largeRoutingInputPath": paths["documentInput"],
                                     "spoolTempParent": paths["documentTemp"], "contexts": document_contexts(operation),
                                     "endpointPinBeforeObservation": None}}
    if row["document"]["variant"] == DOCUMENT_RESPONSIVE:
        inputs["responsiveWork"] = {
            "schemaVersion": 1, "casesPath": paths["file:responsive"], "runtimeStagesPath": paths["file:runtime"],
            "fixtureWorkerPath": paths["file:workFixture"], "socksSourcePath": paths["file:socks"], "httpsSourcePath": paths["file:https"],
            "certificatePath": paths["file:certificate"], "privateKeyPath": paths["file:privateKey"],
            "trustStorePath": paths["file:trustStore"], "contexts": responsive_contexts(operation),
            "largeRoutingInputPath": paths["documentInput"]}
    return inputs


def cold_input(row, paths, operation):
    """The cold module's literal input: its variant, the document it imports and the digest its export must have."""
    variant = row["document"]["variant"]
    if variant == "legacy-newline":
        source, suffixes = paths["file:legacyInput"], normalized_suffixes(LEGACY_ENTRIES)
    else:
        source, suffixes = paths["documentInput"], ["d%07d.document.invalid" % number for number in range(DOCUMENT_INPUT_ENTRIES)]
    value = {"schemaVersion": 1, "variant": variant, "operationId": operation, "routingInputPath": source,
             "expectedSemanticSha256": routing_semantic_sha256(suffixes), "expectedSuffixCount": len(suffixes)}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def principal_outcome(found):
    """The receipt's principal part from one principal-probe reply, or UNKNOWN while its task may still exist.

    The publisher sets registered before registering and ran before Run, so a reply naming either must show
    the task read absent, and a task that ran must also have been seen to end. One that never ran was refused.
    """
    task, result = found["task"], found["probe"]
    registered, ran = task.get("registered") is True, task.get("ran") is True
    if (registered or ran) and (task.get("deleted") is not True or ran and task.get("ended") is not True):
        raise Unknown("principal_probe_task_open")
    if not ran:
        return {"state": "refused"}
    live = found.get("before") == found.get("after") and (found.get("before") or {}).get("exists") is True
    denied = (type(result) is dict and result.get("state") == "observed" and result.get("actualSid") == LOCAL_SERVICE
              and result.get("accessDenied") is True and result.get("credentialOpened") is False and result.get("win32Error") == 5
              and result.get("credentialBytesRead") == 0 and task.get("principalSid") == LOCAL_SERVICE and task.get("logonType") == 5)
    reason = None if denied and live and task.get("resultRemoved") is True else (
        "window_closed" if not live else "result_missing" if result is None else "not_denied" if not denied else "result_left")
    return {"state": "observed" if reason is None else "failed", "reason": reason,
            "principalSid": task.get("principalSid"), "win32Error": result.get("win32Error") if type(result) is dict else None}


def boot_filetime(text):
    """A guest boot as readiness reports it, LastBootUpTime in UTC round-trip form, as the FILETIME the context program reads."""
    found = _ROUND_TRIP_UTC.fullmatch(text) if isinstance(text, str) else None
    if found is None:
        return None
    try:
        moment = datetime.datetime(*(int(part) for part in found.groups()[:6]), tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    delta = moment - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    return str((delta.days * 86400 + delta.seconds) * 10 ** 7 + int((found[7] or "").ljust(7, "0")))


def runtime_authority(raw, digest):
    """The bundled runtime's digest from the installed native-helpers.json whose exact bytes its tree pin holds."""
    if len(raw) > AUTHORITY_BYTES or _sha(raw) != digest:
        raise ValueError("runtime_authority_bytes")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    authority = value.get("runtimeAuthority") if type(value) is dict else None
    if (type(value) is not dict or set(value) != {"schemaVersion", "policySha256", "artifacts", "runtimeAuthority"}
            or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1 or type(authority) is not dict
            or set(authority) != {"runtimeSha256", "runtimeSizeBytes", "authoritySourceSha256"}
            or not isinstance(authority["runtimeSha256"], str) or _SHA256.fullmatch(authority["runtimeSha256"]) is None
            or type(authority["runtimeSizeBytes"]) is not int or not 64 <= authority["runtimeSizeBytes"] <= 192 * 1024 * 1024):
        raise ValueError("runtime_authority_shape")
    return authority["runtimeSha256"]


def install_helper(raw, digest, pin):
    """The installer helper as the product build declares it in the installed native-helpers.json whose exact bytes its
    tree pin holds: the artifact's digest and size must be the installed helper's own pin, with the operations, machine
    and load policy DesktopWindowsPackagedHelperAdmission admits."""
    if len(raw) > AUTHORITY_BYTES or _sha(raw) != digest:
        raise ValueError("install_helper_manifest_bytes")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    artifacts = value.get("artifacts") if type(value) is dict else None
    found = [item for item in artifacts if type(item) is dict and item.get("name") == INSTALL_HELPER[-1]] if type(artifacts) is list else []
    if (len(found) != 1 or found[0].get("sha256") != pin["sha256"] or found[0].get("sizeBytes") != pin["nativeIdentity"]["sizeBytes"]
            or found[0].get("operations") != INSTALL_HELPER_OPERATIONS or found[0].get("machine") != "AMD64"
            or found[0].get("clrHeader") is not False or found[0].get("dependentLoadFlags") != 0x800):
        raise ValueError("install_helper_manifest")
    return {"path": pin["path"], "sha256": pin["sha256"], "sizeBytes": pin["nativeIdentity"]["sizeBytes"]}


def _same_path(left, right):
    return type(left) is str and type(right) is str and ntpath.normcase(ntpath.normpath(left)) == ntpath.normcase(ntpath.normpath(right))


def census_rows(value):
    """The publisher's SYSTEM process census, in its closed shape: each process of the image it was asked for, described
    through its own handle. A process that could not be opened or is no longer running carries only its ids."""
    fields = {"pid", "parentPid", "openError", "creationFileTime", "alive", "image", "argv", "token", "imageSha256", "imageSizeBytes",
              "parent"}
    if type(value) is not list or len(value) > CENSUS_LIMIT:
        raise ValueError("collector_census_shape")
    rows = []
    for item in value:
        if (type(item) is not dict or set(item) != fields or type(item["pid"]) is not int or not 0 < item["pid"] < 2 ** 32
                or type(item["parentPid"]) is not int or not 0 <= item["parentPid"] < 2 ** 32):
            raise ValueError("collector_census_shape")
        if item["openError"] is not None or item["alive"] is not True:
            if (item["openError"] is not None and type(item["openError"]) is not int) or item["alive"] not in (None, False):
                raise ValueError("collector_census_shape")
            rows.append({"pid": item["pid"], "parentPid": item["parentPid"], "live": False})
            continue
        token, parent = item["token"], item["parent"]
        if (not isinstance(item["creationFileTime"], str) or re.fullmatch(r"[1-9][0-9]{0,19}", item["creationFileTime"]) is None
                or not isinstance(item["image"], str) or type(item["argv"]) is not list or len(item["argv"]) > 16
                or not all(isinstance(value, str) for value in item["argv"])
                or not isinstance(item["imageSha256"], str) or _SHA256.fullmatch(item["imageSha256"]) is None
                or type(item["imageSizeBytes"]) is not int or type(token) is not dict
                or set(token) != {"sid", "sessionId", "elevated", "elevationType"} or not isinstance(token["sid"], str)
                or not all(type(token[key]) is int for key in ("sessionId", "elevated", "elevationType"))
                or type(parent) is not dict or set(parent) != {"pid", "openError", "alive", "creationFileTime", "image"}
                or parent["pid"] != item["parentPid"]):
            raise ValueError("collector_census_shape")
        rows.append({**item, "creationFileTime": int(item["creationFileTime"]), "live": True})
    return rows


def backup_journal(value):
    """One SeBackupPrivilege open of an owner-only product file as the publisher journaled it: the privilege enabled on
    its own thread's impersonation token for that one open, with backup semantics and read access only, then dropped
    and reverted, the process token's own state unchanged."""
    fields = {"privilege", "scope", "processStateBefore", "processStateAfter", "enabledForOpen", "disabledAfterOpen", "reverted",
              "openError", "access", "share", "flags"}
    if (type(value) is not dict or set(value) != fields or value["privilege"] != "SeBackupPrivilege" or value["scope"] != "thread-impersonation"
            or value["processStateBefore"] not in (1, 2) or value["processStateAfter"] != value["processStateBefore"]
            or value["enabledForOpen"] is not True or value["disabledAfterOpen"] is not True or value["reverted"] is not True
            or value["openError"] != 0 or value["access"] != 0x80020000 or value["share"] != 1 or value["flags"] != 0x02200000):
        raise ValueError("collector_backup_read")
    return value


def owner_process(rows, serve, cli, sid, session):
    """The process the product runs its controller in, which the installer helper names as its owner.

    The census of the CLI image must hold the serve the owner started, as it recorded it. The installed jpackage
    launcher relaunches itself once into a child of the same image that runs the JVM; with no such child the serve
    is the controller. Nothing else of that image may be the serve's child.
    """
    def ordinary(row):
        return (row["live"] and _same_path(row["image"], cli) and row["token"]["sid"] == sid and row["token"]["elevated"] == 0
                and row["token"]["sessionId"] == session)
    served = [row for row in rows if row["pid"] == serve["pid"]]
    if len(served) != 1 or not ordinary(served[0]) or served[0]["creationFileTime"] != serve["creationFileTime"]:
        raise ValueError("collector_owner_serve")
    children = [row for row in rows if row["parentPid"] == serve["pid"] and row["pid"] != serve["pid"]]
    if not children:
        return {"pid": serve["pid"], "creationFileTime": serve["creationFileTime"], "relaunched": False}
    if len(children) != 1 or not ordinary(children[0]) or children[0]["creationFileTime"] <= serve["creationFileTime"]:
        raise ValueError("collector_owner_child")
    return {"pid": children[0]["pid"], "creationFileTime": children[0]["creationFileTime"], "relaunched": True}


def install_actors(rows, *, helper, job, owner, administrator_sid, sid, session):
    """The installer job's elevated coordinator and its original-user worker, live, from one SYSTEM census.

    Exactly one live process of the admitted helper image per role runs with this job and this owner as its arguments.
    The coordinator runs elevated as the approving administrator, the worker unelevated as the ordinary user, both in
    the ordinary session, and the worker was born after its coordinator. Their parents are recorded, never assumed:
    AppInfo should give the coordinator the owner that asked for it, and the secondary logon service the worker its
    coordinator. Returns the collector request's actors and the facts a receipt keeps.
    """
    found = {}
    for role, verb in INSTALL_ROLES:
        matches = [row for row in rows if row["live"] and len(row["argv"]) == 5 and row["argv"][1] == verb and row["argv"][2] == job]
        if len(matches) != 1:
            raise ValueError("collector_" + role + "_count_" + str(min(len(matches), 9)))
        row = matches[0]
        if (not _same_path(row["image"], helper["path"]) or row["imageSha256"] != helper["sha256"]
                or row["imageSizeBytes"] != helper["sizeBytes"] or row["argv"][3:] != [str(owner["pid"]), str(owner["creationFileTime"])]):
            raise ValueError("collector_" + role + "_identity")
        principal, elevated = (administrator_sid, 1) if role == "coordinator" else (sid, 0)
        if row["token"]["sid"] != principal or row["token"]["elevated"] != elevated or row["token"]["sessionId"] != session:
            raise ValueError("collector_" + role + "_token")
        found[role] = row
    coordinator, worker = found["coordinator"], found["worker"]
    if worker["creationFileTime"] <= coordinator["creationFileTime"] or worker["pid"] == coordinator["pid"]:
        raise ValueError("collector_worker_generation")
    actors = {role: {"pid": row["pid"], "creationFileTime": row["creationFileTime"], "image": helper["path"], "sha256": helper["sha256"],
                     "sid": row["token"]["sid"], "sessionId": session} for role, row in found.items()}

    def parent(row, expected):
        record = row["parent"]
        known = record["alive"] is True and record["openError"] is None
        return {"pid": row["parentPid"], "alive": known,
                "matches": row["parentPid"] == expected["pid"] and (not known or record["creationFileTime"] == str(expected["creationFileTime"]))}
    facts = {"helperSha256": helper["sha256"], "owner": owner,
             "coordinator": {"pid": coordinator["pid"], "creationFileTime": coordinator["creationFileTime"], "sid": coordinator["token"]["sid"],
                             "elevated": 1, "elevationType": coordinator["token"]["elevationType"], "sessionId": session,
                             "argv0MatchesImage": _same_path(coordinator["argv"][0], helper["path"]), "parent": parent(coordinator, owner)},
             "worker": {"pid": worker["pid"], "creationFileTime": worker["creationFileTime"], "sid": worker["token"]["sid"],
                        "elevated": 0, "elevationType": worker["token"]["elevationType"], "sessionId": session,
                        "argv0MatchesImage": _same_path(worker["argv"][0], helper["path"]),
                        "parent": parent(worker, {"pid": coordinator["pid"], "creationFileTime": coordinator["creationFileTime"]})}}
    return actors, facts


def returned_actors(value, *, need, installed, target_files, sid, session):
    """The returned owner, and GUI where the case kept one, exactly as the case recorded them before returned-cleanup."""
    if (type(value) is not dict or set(value) != {"actors", "jobId", "operationId"} or value["jobId"] != need.get("jobId")
            or value["operationId"] != need.get("productOperationId") or type(value["actors"]) is not dict
            or set(value["actors"]) not in ({"owner"}, {"owner", "gui"})):
        raise ValueError("collector_returned_actors")
    prefix = installed.rstrip("\\") + "\\"
    for actor in value["actors"].values():
        image = actor.get("image") if type(actor) is dict else None
        relative = image[len(prefix):].replace("\\", "/") if isinstance(image, str) and image.casefold().startswith(prefix.casefold()) else None
        record = next((item for name, item in target_files.items() if relative is not None and name.casefold() == relative.casefold()), None)
        if (type(actor) is not dict or set(actor) != {"pid", "creationFileTime", "image", "sha256", "sid", "sessionId"}
                or type(actor["pid"]) is not int or not 0 < actor["pid"] < 2 ** 32 or type(actor["creationFileTime"]) is not int
                or actor["creationFileTime"] <= 0 or relative is None or relative.casefold() not in ("vpn-control.exe", "vpn-control-cli.exe") or record is None
                or actor["sha256"] != record["sha256"] or actor["sid"] != sid or actor["sessionId"] != session):
            raise ValueError("collector_returned_actor")
    return value["actors"]


def reboot_inputs(row, paths, product, *, runtime_authority, preboot=None):
    """A reboot row's closed request: every role a fixed file of this bundle or of the installed product.

    A preboot works in a fresh product workspace under its own root; its postboot reopens that
    same workspace and names the preboot's own checkpoint event.
    """
    reboot = row["reboot"]
    pre = reboot["phase"] != "post"  # The rebootless query row runs the preboot action in its own fresh workspace.
    workspace = paths["productWorkspace"] if pre else preboot["productWorkspace"]
    roles = {role: paths["file:" + role] for _, role, _ in row["guestFiles"] if role not in ("owner", "worker")}
    roles.update(gui=paths["gui"], powerShell=POWERSHELL_PATH, runtimeAuthority=runtime_authority)
    config = {"schemaVersion": 1, "phase": "preboot-reboot" if pre else "postboot-final", "scenario": reboot["scenario"],
              "sourceRoles": roles, "trafficInputPath": paths["file:trafficInput"],
              "autostartInputs": {"schemaVersion": 1, "snapshotScriptPath": roles["snapshotScript"], "powerShellPath": POWERSHELL_PATH,
                                  "migrationScriptPath": roles["migrationScript"], "startScriptPath": roles["startScript"],
                                  "guiPath": paths["gui"], "workspace": workspace}}
    if not pre:
        config["checkpointPath"] = preboot["operationRoot"] + "\\" + preboot["checkpointName"]
    return {"cliPath": paths["cli"], "workspace": workspace, "productVersion": product["productVersion"], "postbootAcceptance": config}


def evidence_events(raw):
    """The owner's own journal from a pulled evidence zip: top-level event files only, each bounded and exact."""
    rows = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for info in archive.infolist():
            if _EVENT_NAME.fullmatch(info.filename) is None:
                continue
            if info.file_size > 256 * 1024:
                raise ValueError("evidence_event_bound")
            value = json.loads(archive.read(info).decode("utf-8"), object_pairs_hook=_unique)
            if type(value) is not dict or value.get("kind") != _EVENT_NAME.fullmatch(info.filename)[1]:
                raise ValueError("evidence_event_name")
            rows.append((info.filename, value))
    return rows


def product_declaration(op, machine, context, paths, hashes, events, scenario):
    """The allowance a passed preboot owner earned, checked here before any SYSTEM file declares it.

    Its checkpoint names the product it started through the autostart task: one tree of the GUI
    launcher, its JVM, the controller launcher the GUI started, that JVM, and for reconnect the
    runtime. Each is this boot's, the installed or runtime image and hash, the ordinary account and
    session, and no process the owner itself started or was.
    """
    def need(condition, code):
        if not condition:
            raise ValueError(code)
    kinds = {}
    for name, value in events:
        kinds.setdefault(value["kind"], []).append((name, value))
    checkpoints, starts = kinds.get("reboot-checkpoint", []), kinds.get("owner-started", [])
    need(len(checkpoints) == 1 and len(starts) == 1, "declaration_events")
    name, event = checkpoints[0]
    checkpoint = event["value"]
    need(event["operationId"] == op and checkpoint["operationId"] == op and checkpoint["scenario"] == scenario
         and checkpoint["deploymentId"] == machine and checkpoint["ordinarySid"] == context["ordinarySid"]
         and checkpoint["oldSessionId"] == context["ordinarySessionId"] and checkpoint["oldBootFileTimeUtc"] == context["bootFileTimeUtc"]
         and checkpoint["workspace"] == paths["productWorkspace"], "declaration_checkpoint")
    owner_pids = {starts[0][1]["value"]["pid"], *(value["value"]["pid"] for _, value in kinds.get("child-started", []))}
    rows = checkpoint["declaredProduct"]
    need(type(rows) is list and [row.get("role") for row in rows] == list(DECLARED_ROLES[:len(rows)])
         and len(rows) == (5 if scenario == "reconnect" else 4), "declaration_tree")
    runtime_image = paths["productWorkspace"] + "\\runtime\\tools\\" + RUNTIME_LEAF
    for row in rows:
        runtime = row["role"] == "runtime"
        need(set(row) == {"role", "pid", "parentPid", "creationFileTime", "image", "sha256", "sid", "sessionId"}
             and type(row["pid"]) is int and type(row["parentPid"]) is int and row["pid"] > 0 and row["parentPid"] > 0
             and row["image"] == (runtime_image if runtime else paths["gui"]) and row["sha256"] == hashes["runtime" if runtime else "gui"]
             and row["sid"] == context["ordinarySid"] and row["sessionId"] == context["ordinarySessionId"]
             and type(row["creationFileTime"]) is str and re.fullmatch(r"[1-9][0-9]{0,18}", row["creationFileTime"]) is not None
             and int(row["creationFileTime"]) > int(context["bootFileTimeUtc"])
             and row["pid"] not in owner_pids and row["parentPid"] not in owner_pids, "declaration_row")
    roles = {row["role"]: row for row in rows}
    need(len({row["pid"] for row in rows}) == len(rows) and roles["guiLauncher"]["parentPid"] not in {row["pid"] for row in rows}
         and all(roles[child]["parentPid"] == roles[parent]["pid"] for child, parent in
                 (("gui", "guiLauncher"), ("controllerLauncher", "gui"), ("controller", "controllerLauncher"), ("runtime", "controller"))
                 if child in roles), "declaration_parentage")
    declaration = {"schema": ALLOWANCE_SCHEMA, "schemaVersion": 1, "operationId": op, "machine": machine,
                   "bootFileTimeUtc": context["bootFileTimeUtc"], "ordinarySid": context["ordinarySid"],
                   "sessionId": context["ordinarySessionId"],
                   "processes": [{key: row[key] for key in ("pid", "parentPid", "creationFileTime", "image", "sha256")} for row in rows]}
    return declaration, name


def worker_inputs(row, paths, product, *, product_code=None, runtime_authority=None, preboot=None, operation=None):
    """The one worker request a row may run. casesPath and qualificationArgv come only from here."""
    if row.get("reboot"):
        return reboot_inputs(row, paths, product, runtime_authority=runtime_authority, preboot=preboot)
    if row.get("document"):
        return document_inputs(row, paths, product, operation)
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


def update_worker_inputs(paths, product):
    """The one public-update request: the installed base's CLI, the fixed sibling case module and the literal harness."""
    return {"cliPath": paths["cli"], "workspace": paths["productWorkspace"], "productVersion": product["baseVersion"],
            "casesPath": paths["file:cases"], "harnessPath": paths["harness"]}


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
                  installed=None, python=None, windows=None, preboot=None, reboot=None):
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
        # A passed reboot preboot: what its postboot reopens and the allowance it declared.
        "preboot": preboot,
        # Any reboot row: what it left for the next one, and for a postboot the readiness-reboot it followed.
        "reboot": reboot,
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
        self.anchored = self.owns_data = self.published = False
        self.program_open = 0  # Programs whose terminal is not saved yet; a collector runs inside the SYSTEM run.
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
        self.prior_preboot = self.preboot = self.runtime_authority = self.runtime_sha256 = self.preboot_pins = self.readiness_reboot = None
        self.generated = {}
        self.update = self.row.get("update")
        self.collected = {}
        self.target_install = self.update_pins = self.harness_pin = self.administrator_sid = None
        # A grant row's installer helper, the product's controller process and the installer job's two live actors, each
        # as a SYSTEM census found it; and every SeBackupPrivilege read of an owner-only product file, as journaled.
        self.install_helper = self.update_owner = self.install_actors = self.install_facts = None
        self.backup_reads = []
        self.fixture_file = self.fixture_fingerprint = self.certificate_sha256 = None
        self.document = self.row.get("document")
        self.principal = None  # The LOCAL SERVICE probe of the acceptance row: None until claimed, then its outcome.

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
        self.program_open += 1
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
        self.program_open -= 1
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
            module = types.ModuleType("_windows_scenario_" + name.replace("/", "_") + "_" + self.op.replace("-", ""))
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
        for package in self.staged():
            # Staged before submit; the bytes are hashed here, again while pushed, and in the guest.
            try:
                for _ in self._chunks(package):
                    pass
            except (OSError, ValueError):
                raise Refused("artifact_cache_unavailable") from None

    def staged(self):
        """The admitted packages whose bytes wait in the host's artifact cache for this row."""
        if self.update:
            return [self.plan["packages"]["targetPackage"], self.plan["packages"]["fixtureReceipt"]]
        package = self.package()
        return [] if package is None else [package]

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
        if (self.row.get("reboot") or {}).get("phase") == "post":
            self.prior_preboot = self._prior_preboot()
        if self.row.get("reboot"):
            self._reboot_chain()
        if self.update:
            self.target_install = self._target_install()
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

    def _installer_record(self, prior):
        """A passed installer job of this VM: its receipt's installed facts, or a refusal."""
        if not isinstance(prior, str) or _UUID.fullmatch(prior) is None or prior == self.op:
            raise Refused("prior_install_unavailable")
        other = self.data.parent / prior
        receipt = self._read_record(other / "scenario-receipt.json")
        record = self._read_record(other / "job-exit.json")
        installed = receipt.get("installed") if receipt is not None else None
        if (receipt is None or record is None or record.get("exitCode") != EXIT_PASSED or receipt.get("exitCode") != EXIT_PASSED
                or receipt.get("result") != "passed" or receipt.get("correlationId") != prior or receipt.get("deploymentId") != self.machine
                or receipt.get("scenarioId") not in INSTALL_SCENARIOS or type(installed) is not dict):
            raise Refused("prior_install_unavailable")
        if (not isinstance(installed.get("productCode"), str) or _PRODUCT_CODE.fullmatch(installed["productCode"]) is None
                or not isinstance(installed.get("treeSha256"), str) or _SHA256.fullmatch(installed["treeSha256"]) is None
                or type(installed.get("treeFiles")) is not int):
            raise Refused("prior_install_other_package")
        return installed

    def _prior_install(self):
        """The passed installer job on this VM whose package this product row names: what it left is the baseline.

        An update row's baseline is the older version it updates from, so it is named by version, not by package.
        """
        prior = (self.plan.get("prior") or {}).get("install")
        installed = self._installer_record(prior)
        if self.update:
            if (installed.get("productVersion") != self.plan["product"]["baseVersion"] or not isinstance(installed.get("packageCode"), str)
                    or _PRODUCT_CODE.fullmatch(installed["packageCode"]) is None):
                raise Refused("prior_install_other_package")
            return installed
        if installed.get("packageSha256") != self.package_target()["sha256"] or installed.get("productVersion") != self.plan["product"]["productVersion"]:
            raise Refused("prior_install_other_package")
        return installed

    def _target_install(self):
        """The earlier install of this very target package on this VM, with the inventory msiexec left: the tree a
        successful update must produce, and the registration it must leave."""
        prior = (self.plan.get("prior") or {}).get("targetInstall")
        installed = self._installer_record(prior)
        target = self.package_target()
        if (installed.get("packageSha256") != target["sha256"] or installed.get("productVersion") != self.plan["product"]["productVersion"]
                or not isinstance(installed.get("packageCode"), str) or _PRODUCT_CODE.fullmatch(installed["packageCode"]) is None):
            raise Refused("target_install_other_package")
        value = self._read_record(self.data.parent / prior / INVENTORY_NAME)
        files = value.get("files") if value is not None else None
        try:
            if (type(files) is not dict or value.get("installed") != installed or value.get("operationId") != prior
                    or len(files) != installed["treeFiles"] or not files):
                raise ValueError("inventory")
            rows = [[name, files[name]["sha256"], files[name]["sizeBytes"]] for name in sorted(files)]
            if (any(type(item) is not dict or set(item) != {"sha256", "sizeBytes"} or _SHA256.fullmatch(str(item["sha256"])) is None
                    or type(item["sizeBytes"]) is not int for item in files.values())
                    or _sha(json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode("ascii")) != installed["treeSha256"]):
                raise ValueError("inventory")
        except (ValueError, TypeError, KeyError):
            raise Refused("target_install_inventory") from None
        return {"installed": installed, "files": files}

    def _prior_preboot(self):
        """The passed preboot this postboot names: its receipt says what to reopen and at which boot it ended."""
        prior = (self.plan.get("prior") or {}).get("preboot")
        reboot = self.row["reboot"]
        if not isinstance(prior, str) or _UUID.fullmatch(prior) is None or prior == self.op:
            raise Refused("prior_preboot_unavailable")
        other = self.data.parent / prior
        receipt = self._read_record(other / "scenario-receipt.json")
        record = self._read_record(other / "job-exit.json")
        preboot = receipt.get("preboot") if receipt is not None else None
        if (receipt is None or record is None or record.get("exitCode") != EXIT_PASSED or receipt.get("exitCode") != EXIT_PASSED
                or receipt.get("result") != "passed" or receipt.get("correlationId") != prior or receipt.get("deploymentId") != self.machine
                or receipt.get("scenarioId") != reboot["preboot"] or type(preboot) is not dict
                or set(preboot) != {"scenario", "productWorkspace", "operationRoot", "checkpointName", "checkpointSha256", "bootFileTimeUtc",
                                    "allowanceSha256", "declaredProcesses"}
                or preboot["scenario"] != reboot["scenario"] or preboot["operationRoot"] != self._prior_root(prior)
                or preboot["productWorkspace"] != preboot["operationRoot"] + "\\workspace"
                or not isinstance(preboot["checkpointName"], str) or _EVENT_NAME.fullmatch(preboot["checkpointName"]) is None
                or not isinstance(preboot["checkpointSha256"], str) or _SHA256.fullmatch(preboot["checkpointSha256"]) is None
                or not isinstance(preboot["bootFileTimeUtc"], str) or re.fullmatch(r"[1-9][0-9]{0,18}", preboot["bootFileTimeUtc"]) is None
                or type(preboot["declaredProcesses"]) is not int):
            raise Refused("prior_preboot_unavailable")
        # The same install, package and version on both sides of the reboot.
        if (receipt.get("installed") != self.prior_installed
                or receipt.get("windows") != {"installedPackage": True, "packageSha256": self.package_target()["sha256"]}):
            raise Refused("prior_preboot_other_install")
        self.readiness_reboot = self._readiness_reboot(preboot)
        return preboot

    def _readiness_reboot(self, preboot):
        """The one readiness-reboot submitted from the boot its preboot ran in, with the declared app let through.

        A later boot alone may be a crash or a restart. Only this journal of the only reboot submitter, in
        the VM root, ties the new boot to a reboot with the app running: its idle census knew every product row.
        """
        found = []
        for path in sorted(self.root.iterdir()):
            name = _RECOVERY_INTENT.fullmatch(path.name)
            intent = self._read_record(path) if name is not None else None
            before = intent.get("before") if intent is not None and intent.get("action") == "reboot" else None
            session = before.get("sessionFacts") if isinstance(before, dict) else None
            if isinstance(session, dict) and boot_filetime(session.get("boot")) == preboot["bootFileTimeUtc"]:
                found.append((name[1], intent, before))
        if len(found) != 1:
            raise Refused("prior_preboot_reboot_unproven")
        recovery, intent, before = found[0]
        result = self._read_record(self.root / ("readiness-recovery-" + recovery + ".result.json"))
        idle = before.get("idleFacts")
        rows = idle.get("processes") if isinstance(idle, dict) else None
        product = [row for row in rows if isinstance(row, dict) and row.get("name") in (PRODUCT_GUI, RUNTIME_LEAF)] if isinstance(rows, list) else []
        if (result is None or result.get("state") != "submitted" or intent.get("recoveryId") != recovery
                or not isinstance(intent.get("operationId"), str) or result.get("operationId") != intent["operationId"]
                or len(product) != preboot["declaredProcesses"] or not all(row.get("knownSystem") is True for row in product)):
            raise Refused("prior_preboot_reboot_unproven")
        return {"recoveryId": recovery, "operationId": intent["operationId"], "shutdownAcknowledged": result.get("shutdownAcknowledged") is True}

    def _reboot_chain(self):
        """One reboot chain at a time on a machine. A preboot whose owner changed the autostart task or started
        the app leaves both behind; it stays open until a passed postboot names it, and only that postboot runs meanwhile."""
        opened, closed = set(), set()
        for other in sorted(self.data.parent.iterdir()):
            if other.name == self.op or _UUID.fullmatch(other.name) is None:
                continue
            receipt = self._read_record(other / "scenario-receipt.json")
            if receipt is None:
                raise Refused("reboot_chain_unknown")
            reboot = receipt.get("reboot")
            if isinstance(reboot, dict) and reboot.get("phase") == "pre" and reboot.get("autostart") != "untouched":
                opened.add(other.name)
            if isinstance(reboot, dict) and reboot.get("phase") == "post" and receipt.get("exitCode") == EXIT_PASSED:
                closed.add(reboot.get("preboot"))
        named = self.plan["prior"]["preboot"] if self.row["reboot"]["phase"] == "post" else None
        if (opened - closed) - {named}:
            raise Refused("reboot_chain_open")
        if named is not None and named not in opened - closed:
            raise Refused("prior_preboot_unavailable")

    def _reboot_receipt(self, code):
        """What a reboot row left for the next: the owner journals an intent before each autostart change or product start."""
        autostart = "unknown"
        if code != EXIT_UNKNOWN and (self.task or {}).get("state") != "task-finished":
            autostart = "untouched"  # The owner never ran.
        elif code != EXIT_UNKNOWN and self.evidence is not None:
            try:
                raw = (self.data / self.evidence["name"]).read_bytes()
                if _sha(raw) == self.evidence["sha256"]:
                    kinds = {value["kind"] for _, value in evidence_events(raw)}
                    autostart = "changed" if kinds & AUTOSTART_INTENTS else "untouched"
            except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
                pass
        phase = self.row["reboot"]["phase"]
        return {"phase": phase, "autostart": autostart, "preboot": (self.plan.get("prior") or {}).get("preboot") if phase == "post" else None,
                "readinessReboot": self.readiness_reboot}

    def _prior_root(self, prior):
        """The preboot's own operation root, under the profile its receipt recorded."""
        receipt = self._read_record(self.data.parent / prior / "scenario-receipt.json") or {}
        profile = (receipt.get("context") or {}).get("profileRoot")
        return None if not isinstance(profile, str) else profile + "\\AppData\\Local\\" + ROOT_PREFIX + prior

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
        # An update or TUN row reads the SID of the account its prompt would be approved with.
        administrator = self.plan["administrator"] if self.update or self.row.get("tun") else None
        terminal, _ = self.guest_program("context", self._rendered(lambda: context_source(guest, self.plan["user"], native, administrator)))
        try:
            value = decode_stdout(terminal)
            if set(value) != {"sessionFacts", "machineGuid", "hardwareUuid", "bootIdentifier", "bootFileTimeUtc", "profileRoot", "systemToken",
                              *(("administratorSid",) if administrator else ())}:
                raise ValueError("context_fields")
            if administrator:
                self.administrator_sid = value["administratorSid"]
                if type(self.administrator_sid) is not str or _ADMIN_SID.fullmatch(self.administrator_sid) is None:
                    raise ValueError("context_administrator")
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
        if self.prior_preboot is not None and (int(self.context["bootFileTimeUtc"]) <= int(self.prior_preboot["bootFileTimeUtc"])
                                               or not self.prior_preboot["operationRoot"].startswith(self.context["localAppData"] + "\\")):
            # The kernel boot identifier is the same on every boot of a clone: only a later boot time is a new boot.
            raise Refused("preboot_boot_not_newer")
        # What the closed UAC action reads through uac_context(plan). The job never calls or waits on that action.
        self._keep("uac-context.json", (json.dumps({"operationRoot": self.operation_root, "ordinarySid": facts["expectedSid"],
                                                    "ordinarySessionId": facts["console"], "bootFileTimeUtc": value["bootFileTimeUtc"]},
                                                   sort_keys=True) + "\n").encode())

    # Stage 3.
    def _publisher(self, label, action, *, unknown=None, **fields):
        """One SYSTEM publisher program. An action whose effect may outlive a failed program names its UNKNOWN code."""
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
            limit = MAX_STDOUT_BYTES if action in {"read-pins", "read-directories", "list-tree", "collector-observe"} else PUBLISHER_OUTPUT_BYTES
            return wrap_output(emitter._boot_bound(template, self.raw_context), limit)
        terminal, pid = self.guest_program(label, self._rendered(render))
        return self._protocol(label, terminal, pid, m, unknown)

    def _protocol(self, label, terminal, pid, m, unknown=None):
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
            # Without its reply, such a program may have left what it made; only the boot prelude's refusal ran nothing.
            if unknown is not None and not refused_before_effects(terminal):
                raise Unknown(unknown) from None
            raise KnownFailure("publisher_refused:" + token(label) + self._publisher_code(terminal)) from None

    def _publisher_code(self, terminal):
        """The template's own refusal code from a failed publisher's stderr, or nothing.

        A PUB_ name crosses only when the template holds it, with its detail word and Win32 code only when that word is
        in the template too: natively (2026-11-09) the receipt said publisher_refused:after-registration, while the
        guest's stderr named PUB_MSI_INFO:PackageCode:1608. No other guest text crosses.
        """
        try:
            text = base64.b64decode(terminal.get("err-data") or "", validate=True).decode("utf-8", "replace")
            source = self._bundle_source(PUBLISHER_TEMPLATE).decode("ascii")
        except (ValueError, TypeError, AttributeError, KeyError, OSError):
            return ""
        for found in _PUBLISHER_REFUSAL.finditer(text[:MAX_TERMINAL_BYTES]):
            name, word, number = found.groups()
            if re.search(r"['\"]" + name + r"['\":]", source) is None:
                continue
            if word is None or re.search(r"\b" + word + r"\b", source) is None:
                return ":" + name
            return ":" + name + ":" + word + ("" if number is None else ":" + number)
        return ""

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
        folders = [(name, "0x1200a9") for name in self.row.get("subfolders", ())] + update_subfolders(self.op, self.row)
        subfolders = [name for name, rights in folders if rights == "0x1200a9"]
        private = [name for name, rights in folders if rights == "FA"]
        fields = {"privateSubfolders": private} if private else {}
        roots = list((self.document or {}).get("rootSubfolders", ()))
        if roots:
            fields["rootSubfolders"] = roots
        value, required = self._publisher("publish-initialize", "initialize", existingDirectories=existing, subfolders=subfolders, **fields)
        expected = [*existing, self.workspace, *(self.workspace + "\\" + name for name in subfolders + private), self.operation_root,
                    *(self.operation_root + "\\" + name for name in roots)]
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
                    or by_path[self.operation_root]["security"] not in self._directory_security("0x1301bf")
                    or any(by_path[self.operation_root + "\\" + name]["security"] not in self._directory_security("0x1301bf") for name in roots)
                    or any(by_path[self.workspace + "\\" + name]["security"] not in self._directory_security(rights) for name, rights in folders)):
                raise ValueError("publisher_owned_root_security")
        except (ValueError, TypeError, KeyError, AttributeError):
            raise KnownFailure("publisher_initialize_receipt") from None
        # The SYSTEM collector refuses any other form of its root; read before any task, not when an owner waits on it.
        sid = self.context["ordinarySid"]
        if self.update and any(by_path[self.paths["collector:" + stage]]["security"] != {"ownerSid": "S-1-5-18", "sddl": COLLECTOR_ROOT_SDDL.format(sid=sid)}
                               for stage in self.update["collectorStages"]):
            raise KnownFailure("collector_root_policy")
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
        # An update row adds its fixture receipt and package, three TLS files and the harness; a document row the
        # document the publisher makes in the guest, which joins self.generated only after this bound.
        files = (len(self.read_pins) + sum(1 for _, role, _ in self.row["guestFiles"] if role != "owner")
                 + int("package" in self.file_pins) + len(self.generated) + int(self.prior_preboot is not None)
                 + len(self.row.get("generated", ())) + len(self.row.get("extracted", ())) + (6 if self.update else 0)
                 + int(bool(self.document) and "documentInput" not in self.generated))
        directories = len(self.directory_pins) + 2 * int(self.prior_preboot is not None)
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
                    or not all(type(row) is dict and set(row) == {"productCode", "context", "productName", "version", "installLocation", "packageCode"}
                               and isinstance(row["productCode"], str) and _PRODUCT_CODE.fullmatch(row["productCode"])
                               and isinstance(row["packageCode"], str) and _PRODUCT_CODE.fullmatch(row["packageCode"])
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
        if self.row.get("reboot"):
            raw = traffic_input()
            self.generated["trafficInput"] = True
            targets.append({"role": "trafficInput", "path": self.paths["file:trafficInput"], "bytes": len(raw), "sha256": _sha(raw),
                            "kind": "data", "raw": raw})
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
                version = self.plan["product"]["baseVersion"] if self.update else self.plan["product"]["productVersion"]
                check = self._registration_check(rows, self.prior_installed["productCode"], version)
                if check is not None:
                    raise KnownFailure("installed_registration_differs:" + check)
                installed = self._listed("installed", self.paths["installed"], INSTALLED_REQUIRED)
                trees.append((self.paths["installed"], installed))
            # Both trees go into one worker request: a joint excess is refused before either tree is pinned.
            self._pin_bound(trees)
            self.python_tree = self._tree("python", self.paths["python"], "python-runtime", python)
            if installed is not None:
                # The updater's lease retires and re-admits exactly one installed-application tree.
                role = "installed-application" if self.update else "installed-app"
                self.installed_tree = self._tree("installed", self.paths["installed"], role, installed)
                if (self.installed_tree["sha256"] != self.prior_installed["treeSha256"]
                        or len(self.installed_tree["tree"]["files"]) != self.prior_installed["treeFiles"]):
                    raise KnownFailure("installed_tree_differs")
                self.installed = dict(self.prior_installed)
                self.installed_matched = True
                if self.row.get("reboot"):
                    self._reboot_pins(installed)
            if self.row.get("proxy"):
                self._proxy_files()
            if self.document:
                self._document_files()
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
        if self.update:
            self._publish_update()

    def _publish_update(self):
        """The fixture the update case serves, its TLS files, and the forms the SYSTEM collector will demand.

        All of it exists before any task runs: an update case waits on its collector with no deadline, so
        a refusal found after launch would leave its owner waiting for good.
        """
        sid = self.context["ordinarySid"]
        # The collector request is published as the owner was, so the owner's own pin shows the form the request will read
        # back with: O:SYD:PAI natively, which the pinned chain now takes. Any other form ends the row here, before a task.
        if self.update["collectorStages"] and self.file_pins["owner"]["security"] != {"ownerSid": "S-1-5-18", "sddl": COLLECTOR_FILE_SDDL.format(sid=sid)}:
            raise KnownFailure("collector_file_policy")
        if "authorization" in self.update["collectorStages"]:
            # A grant's coordinator and worker run the base install's helper: the digest and size its own installed
            # native-helpers.json declares, which must be what the installed tree pin of the helper holds.
            self.install_helper = self._install_helper()
        try:
            receipt_raw = b"".join(self._chunks(self.plan["packages"]["fixtureReceipt"]))
        except (OSError, ValueError):
            raise KnownFailure("artifact_cache_changed") from None
        target = self.package_target()
        try:
            fixture = json.loads(receipt_raw)
            asset = fixture["manifest"]["assets"][0]
            if (len(fixture["manifest"]["assets"]) != 1 or asset["sha256"] != target["sha256"] or asset["sizeBytes"] != target["bytes"]
                    or asset["displayVersion"] != self.plan["product"]["productVersion"] or _FIXTURE_FILE.fullmatch(asset["fileName"]) is None
                    or _SHA256.fullmatch(fixture["sourceFingerprint"]) is None):
                raise ValueError("fixture_receipt")
        except (ValueError, TypeError, KeyError, IndexError):
            raise KnownFailure("fixture_receipt_identity") from None
        self.fixture_file = self.paths["fixtureTarget"] + "\\" + asset["fileName"]
        self.fixture_fingerprint = fixture["sourceFingerprint"]
        pins = self._publish_files([
            {"role": "fixture-receipt", "path": self.paths["fixtureReceipt"], "bytes": len(receipt_raw), "sha256": _sha(receipt_raw),
             "kind": "data", "raw": receipt_raw},
            {"role": "fixture-target", "path": self.fixture_file, "bytes": target["bytes"], "sha256": target["sha256"], "kind": "data", "raw": target}],
            "publish-fixture")
        sealed = self._sealed(pins["fixture-target"])
        certificate, certificate_pin, key_pin = self._fixture_tls()
        store = java_truststore(certificate, os.urandom(16))
        trust = self._publish_files([{"role": "fixture-trust", "path": self.paths["trustStore"], "bytes": len(store), "sha256": _sha(store),
                                      "kind": "data", "raw": store}], "publish-trust")["fixture-trust"]
        self.certificate_sha256 = _sha(certificate)
        self.update_pins = {"receipt": pins["fixture-receipt"], "target": sealed, "certificate": certificate_pin, "privateKey": key_pin,
                            "trustStore": trust}

    def _sealed(self, pin):
        """The served package, now read-only: same bytes, same file, one more attribute."""
        value, required = self._publisher("publish-seal-target", "seal-readonly", sealPath=pin["path"])
        sealed = value.get("filePin")
        try:
            self._load("windows_ordinary_task").validate_pin(sealed)
            if (set(value) != required | {"filePin"} or value["state"] != "ordinary-sealed-readonly" or sealed["path"] != pin["path"]
                    or sealed["sha256"] != pin["sha256"] or not sealed["nativeIdentity"]["attributes"] & 1
                    or any(sealed["nativeIdentity"][key] != pin["nativeIdentity"][key] for key in ("volumeSerial", "fileIndex", "sizeBytes"))):
                raise ValueError("publisher_seal_receipt")
        except (ValueError, TypeError, KeyError):
            raise KnownFailure("publisher_seal_receipt") from None
        return sealed

    def _fixture_tls(self):
        """A github.com leaf and key made in the guest; only the public certificate crosses back."""
        value, required = self._publisher("publish-fixture-tls", "fixture-tls")
        tls = value.get("tls")
        try:
            planner = self._load("windows_ordinary_task")
            if set(value) != required | {"tls"} or value["state"] != "ordinary-fixture-tls" or set(tls) != {"certificateDer", "certificatePin", "privateKeyPin"}:
                raise ValueError("publisher_tls_receipt")
            certificate = base64.b64decode(tls["certificateDer"], validate=True)
            text = base64.b64encode(certificate).decode("ascii")
            pem = ("-----BEGIN CERTIFICATE-----\n" + "\n".join(text[at:at + 64] for at in range(0, len(text), 64))
                   + "\n-----END CERTIFICATE-----\n").encode("ascii")
            for name, pin in (("certificate", tls["certificatePin"]), ("privateKey", tls["privateKeyPin"])):
                planner.validate_pin(pin)
                if pin["path"] != self.paths[name] or pin["security"] not in self._file_security():
                    raise ValueError("publisher_tls_receipt")
            if not 0 < len(certificate) <= 8192 or tls["certificatePin"]["sha256"] != _sha(pem):
                raise ValueError("publisher_tls_receipt")
        except (ValueError, TypeError, KeyError):
            raise KnownFailure("publisher_tls_receipt") from None
        return certificate, tls["certificatePin"], tls["privateKeyPin"]

    def _reboot_pins(self, installed):
        """The installed runtime record a reboot row compares with, and for a postboot what its preboot left.

        Its bytes are read once over the agent and must be the ones the installed tree pin hashed.
        """
        names = [name for name in installed["files"] if name.casefold() == "/".join(RUNTIME_AUTHORITY)]
        if len(names) != 1:
            raise KnownFailure("installed_runtime_authority")
        path = self.paths["installed"] + "\\" + names[0].replace("/", "\\")
        try:
            pin = next(pin for pin in self.installed_tree["filePins"] if pin["path"] == path)
            self.runtime_sha256 = runtime_authority(self.read_guest_file(path, AUTHORITY_BYTES), pin["sha256"])
        except Exception:  # Read-only: a lost reply or other bytes changed nothing in the guest.
            raise KnownFailure("installed_runtime_authority") from None
        self.runtime_authority = path
        if self.prior_preboot is None:
            return
        preboot = self.prior_preboot
        checkpoint = preboot["operationRoot"] + "\\" + preboot["checkpointName"]
        directories = self._read_directories([preboot["operationRoot"], preboot["productWorkspace"]], "preboot")
        pins = self._read_pins([checkpoint], "preboot")
        if pins[0]["sha256"] != preboot["checkpointSha256"]:
            raise KnownFailure("preboot_checkpoint_changed")
        self.preboot_pins = {"directories": directories, "checkpoint": pins[0]}

    def _install_helper(self):
        """The base install's helper image: its tree pin, and the product build's own record of it in the installed
        native-helpers.json, read once over the agent against that file's tree pin. Read-only, before any task."""
        held = {pin["path"].casefold(): pin for pin in self.installed_tree["filePins"]}
        root = self.paths["installed"]
        helper = held.get((root + "\\" + "\\".join(INSTALL_HELPER)).casefold())
        manifest = held.get((root + "\\" + "\\".join(RUNTIME_AUTHORITY)).casefold())
        if helper is None or manifest is None:
            raise KnownFailure("installed_install_helper")
        try:
            return install_helper(self.read_guest_file(manifest["path"], AUTHORITY_BYTES), manifest["sha256"], helper)
        except Exception:  # Read-only: a lost reply or other bytes changed nothing in the guest.
            raise KnownFailure("installed_install_helper") from None

    def _runtime_extract(self, proxy):
        """The installed product's bundled runtime, from the one pinned jar that holds it, into the workspace."""
        planner = self._load("windows_ordinary_task")
        root, tree = self.paths["installed"], self.installed_tree
        jars = [root + "\\" + name.replace("/", "\\") for name in tree["tree"]["files"] if _INSTALLED_JAR.fullmatch(name)]
        if not jars:
            raise KnownFailure("installed_runtime_jar_absent")
        path = self.paths["file:" + proxy.RUNTIME_ROLE]
        value, required = self._publisher("publish-runtime", "runtime-extract", installedRoot=root, jarPaths=jars, runtimePath=path)
        found = value.get("runtime")
        try:
            if (set(value) != required | {"runtime"} or value["state"] != "ordinary-runtime-extracted"
                    or set(found) != {"jarPin", "filePin", "entry"} or found["entry"] != proxy.RUNTIME_ENTRY):
                raise ValueError("publisher_runtime_receipt")
            jar, pin = found["jarPin"], found["filePin"]
            planner.validate_pin(jar)
            planner.validate_pin(pin)
            # The jar it read is the installed tree's pin, so the runtime is the installed package's own bytes.
            held = {item["path"]: item for item in tree["filePins"]}
            if (jar["path"] not in jars or {key: jar[key] for key in ("sha256", "nativeIdentity", "security")}
                    != {key: held[jar["path"]][key] for key in ("sha256", "nativeIdentity", "security")}
                    or pin["path"] != path or pin["security"] not in self._file_security() or pin["nativeIdentity"]["sizeBytes"] < 1):
                raise ValueError("publisher_runtime_receipt")
        except (ValueError, TypeError, KeyError, AttributeError):
            raise KnownFailure("publisher_runtime_receipt") from None
        self.file_pins[proxy.RUNTIME_ROLE] = pin
        return pin

    def _proxy_files(self):
        """The proxy family's generated files: TLS material made here, a literal harness and the sampler input."""
        proxy, planner = self._load("windows_scenario_proxy"), self._load("windows_ordinary_task")
        variant = self.row["proxy"]["variant"]
        runtime = self._runtime_extract(proxy)
        tls = proxy.material(secrets.randbits, time.time())
        admissions = {"installed": "sha256-" + self.package_target()["sha256"], "material": "proxy-material-" + _sha(tls["certificate"]),
                      "context": "windows-context-" + _sha(planner.data(self.context)),
                      "fixture": "proxy-fixture-" + self.plan["files"]["agent_tools/windows_lifecycle_runtime_fixture_worker.py"]["sha256"],
                      "source": "sha256-" + self.plan["bundleHash"]}
        # A TUN row's stage inputs: this context's administrator SID, this operation's one UAC decision and the TUN
        # collector source the pinned contract names. None of them comes from a caller.
        tun = None if not self.row.get("tun") else {
            "administratorSid": self.administrator_sid, "decisionId": decision_id(self.op),
            "collectorSourceSha256": self._load("windows_system_collector/collector_contract").COLLECTORS["tun"]}
        try:
            generated = proxy.files(variant, operation=self.op, paths=self.paths, runtime_sha256=runtime["sha256"],
                                    source_sha=self.plan["product"]["sourceSha"], admissions=admissions, tls=tls, tun=tun)
        except (ValueError, KeyError):
            raise KnownFailure("proxy_files_unbuilt") from None
        if [role for role, _ in self.row["generated"]] != list(generated):
            raise KnownFailure("proxy_files_not_the_row")
        targets = [{"role": role, "path": self.paths["file:" + role], "bytes": len(raw), "sha256": _sha(raw), "kind": "data", "raw": raw}
                   for role, raw in generated.items()]
        self.file_pins.update(self._publish_files(targets, "publish-proxy"))

    def _document_files(self):
        """The guest-made large document, checked against the job's own recipe, a cold row's literal inputs, and the
        responsive row's TLS material, made here as the proxy rows' is: the key lives only in this job's memory and the
        guest workspace."""
        planner = self._load("windows_ordinary_task")
        value, required = self._publisher("publish-document-input", "document-input")
        pin = value.get("filePin")
        try:
            if set(value) != required | {"filePin"} or value["state"] != "ordinary-document-input":
                raise ValueError("publisher_document_receipt")
            planner.validate_pin(pin)
            if pin["path"] != self.paths["documentInput"] or pin["security"] not in self._file_security():
                raise ValueError("publisher_document_receipt")
        except (ValueError, TypeError, KeyError):
            raise KnownFailure("publisher_document_receipt") from None
        expected = document_input()
        if pin["sha256"] != _sha(expected) or pin["nativeIdentity"]["sizeBytes"] != len(expected):
            raise KnownFailure("document_input_recipe")
        self.file_pins["documentInput"], self.generated["documentInput"] = pin, True
        variant = self.document["variant"]
        if variant is None:
            return
        targets = []
        if variant == DOCUMENT_RESPONSIVE:
            tls = self._load("windows_scenario_proxy").material(secrets.randbits, time.time())
            targets += [(role, tls[role]) for role, _ in RESPONSIVE_TLS]
        else:
            if variant == "legacy-newline":
                targets.append(("legacyInput", legacy_newline_input()))
            targets.append(("coldInput", cold_input(self.row, self.paths, self.op)))
        if [role for role, _ in self.row["generated"]] != [role for role, _ in targets]:
            raise KnownFailure("document_files_not_the_row")
        self.file_pins.update(self._publish_files([{"role": role, "path": self.paths["file:" + role], "bytes": len(raw), "sha256": _sha(raw),
                                                    "kind": "data", "raw": raw} for role, raw in targets], "publish-document"))

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
            module_pins += [self.file_pins[role] for role in sorted(self.generated)]
            module_pins += [self.file_pins[role] for role, _ in (*row.get("generated", ()), *row.get("extracted", ()))]
            worker_files = [*self.read_pins, *python["filePins"], *module_pins]
            worker_directories = [*self.directory_pins, *python["directoryPins"]]
            if self.preboot_pins is not None:
                worker_files.append(self.preboot_pins["checkpoint"])
                worker_directories += self.preboot_pins["directories"]
            worker_trees = [python["tree"]]
            if "package" in self.file_pins:
                worker_files.append(self.file_pins["package"])
            if self.installed_tree is not None:
                worker_files += self.installed_tree["filePins"]
                worker_directories += self.installed_tree["directoryPins"]
                worker_trees.append(self.installed_tree["tree"])
            code = self.registered[0]["productCode"] if row["workerAction"] == "msi-reset" else None
            if self.update:
                # The harness names every pin above, so it is published before the request that pins it.
                self.harness_pin = self._publish_harness()
                worker_files += [*self.update_pins.values(), self.harness_pin]
                closed = update_worker_inputs(paths, self.plan["product"])
            else:
                closed = worker_inputs(row, paths, self.plan.get("product"), product_code=code, runtime_authority=self.runtime_authority,
                                       preboot=self.prior_preboot, operation=self.op)
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
    def _on_status(self, serve=True):
        """Read the fixed status file; a miss proves nothing and never ends the job.

        The host copy also says whether this scenario's UAC decision has its input terminal, so a prompt event
        stays pending until then. An update row's collector need is served here, between two polls of the run,
        and only while the run is open and the same status names no parked file: a parked owner is reported,
        never touched, and once the run has returned nothing is started for its owner.
        """
        path = self.workspace + "\\scenario-status.json"
        try:
            raw = self.read_guest_file(path, 8192)
            value = json.loads(raw, object_pairs_hook=_unique)
            if type(value) is not dict:
                return
        except Exception:
            return
        if self.row.get("uac"):
            value["uacDecision"] = self._uac_decision()
        temporary = self.data / "status.json.new"
        temporary.write_bytes((json.dumps(value, sort_keys=True) + "\n").encode())
        os.replace(temporary, self.data / "status.json")
        if self.update and serve and value.get("parkedFiles") == []:
            self._serve_needs(value.get("nativeNeeds"))
        if ((self.document or {}).get("principalProbe") and serve and self.principal is None and value.get("parkedFiles") == []
                and type(value.get("pendingKinds")) is list and PRINCIPAL_WINDOW in value["pendingKinds"]):
            self._principal_probe()

    def _principal_probe(self):
        """One LOCAL SERVICE task opens the live owner-private endpoint; the owner never waits on it.

        A probe the job cannot render never reaches the guest, and the publisher's boot refusal runs
        nothing: both are refused. Otherwise only the publisher's reply tells what may still exist, so a
        program that ends without it, like a reply that leaves a task possibly registered, is UNKNOWN.
        """
        self.principal = {"state": "claimed"}  # Claimed before any program, so a later poll never serves it twice.
        try:
            probe = self._load("windows_document_native").principal_refusal_powershell(
                self.paths["principalEndpoint"], self.context["ordinarySid"], LOCAL_SERVICE, 0)
        except Exception:  # Nothing reached the guest: this row's probe is refused, the run goes on.
            self.principal = {"state": "refused"}
            return
        try:
            value, required = self._publisher("document-principal-probe", "principal-probe", unknown="principal_probe_unreadable",
                                              probeSource=probe)
        except KnownFailure:
            self.principal = {"state": "refused"}
            return
        found = value.get("principal")
        try:
            if (set(value) != required | {"principal"} or value["state"] != "ordinary-principal-probe" or type(found) is not dict
                    or type(found["task"]) is not dict or "probe" not in found):
                raise ValueError("shape")
            self._keep("principal-probe.json", (json.dumps(found, sort_keys=True) + "\n").encode())
        except (ValueError, TypeError, KeyError):
            raise Unknown("principal_probe_unreadable") from None
        self.principal = principal_outcome(found)

    def _uac_decision(self):
        """The decision's own input terminal in the VM root, read only; None until it exists."""
        path = self.root / "windows-uac" / decision_id(self.op) / "input.terminal.json"
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            return None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 65536:
                return None
            terminal = json.loads(os.read(descriptor, 65537))
        except (OSError, ValueError):
            return None
        finally:
            os.close(descriptor)
        if type(terminal) is not dict or terminal.get("operationId") != decision_id(self.op):
            return None
        return {key: terminal.get(key) for key in ("state", "decision", "prompt", "promptClosed")}

    # The public-update harness.
    def _harness_inputs(self):
        """UPDATE_INPUTS and the close hold, every value read from this VM, its prior installs or the admitted fixture."""
        paths, product, update, sid = self.paths, self.plan["product"], self.update, self.context["ordinarySid"]
        root = paths["installed"]
        files = {pin["path"]: pin for pin in self.installed_tree["filePins"]}
        base = {}
        for name in self.installed_tree["tree"]["files"]:
            pin = files[root + "\\" + name.replace("/", "\\")]
            base[name] = {"sizeBytes": pin["nativeIdentity"]["sizeBytes"], "sha256": pin["sha256"]}

        def registration(installed, version):
            return {"productCode": installed["productCode"], "principalSid": sid, "installContext": 2, "displayVersion": version,
                    "installLocation": root, "packageCode": installed["packageCode"]}
        installs = update["variant"] not in ("public-ready", "download-cancelled", "checksum-rejected")
        inputs = {"schemaVersion": 1, "variant": update["variant"], "sourceSha": product["sourceSha"], "sourceFingerprint": self.fixture_fingerprint,
                  "modules": {role: paths["file:" + role] for role in UPDATE_MODULE_ROLES},
                  "fixture": {"fixtureId": fixture_id(self.op), "content": paths["fixtureContent"], "state": paths["fixtureState"],
                              "certificate": paths["certificate"], "privateKey": paths["privateKey"], "trustStore": paths["trustStore"],
                              "certificateSha256": self.certificate_sha256},
                  "baseVersion": product["baseVersion"], "targetVersion": product["productVersion"], "installedRoot": root,
                  "guiPath": root + "\\vpn-control.exe", "baseInventory": base, "targetInventory": self.target_install["files"],
                  "baseRegistration": registration(self.prior_installed, product["baseVersion"]),
                  "targetRegistration": registration(self.target_install["installed"], product["productVersion"]),
                  "programData": PROGRAM_DATA, "evidenceRoot": paths["evidenceRoot"], "collectorSourceSha256": self.file_pins["collector"]["sha256"],
                  "ordinarySid": sid, "ordinarySessionId": self.context["ordinarySessionId"],
                  "approvingAdminSid": self.administrator_sid if installs else None, "initialIntent": "off", "trafficInputs": None,
                  "faultInputs": {}, "returnGuiRequired": False, "connectionFixturePath": None}
        final = update["finalStage"]
        hold = None if final is None else {
            "schemaVersion": 1, "collectorOperationId": collector_operation(self.op, final), "collectorRoot": paths["collector:" + final],
            "scope": "update", "stage": final, "sourceSha": product["sourceSha"],
            "systemContractSourceSha256": self.file_pins["collector_contract"]["sha256"],
            "systemWorkerSourceSha256": self.file_pins["system_worker"]["sha256"],
            "collectorSourceSha256": self.file_pins["collector"]["sha256"], "receiptsPath": paths["file:receipts"]}
        return inputs, hold

    def _publish_harness(self):
        raw = update_harness(*self._harness_inputs())
        return self._publish_files([{"role": "update-harness", "path": self.paths["harness"], "bytes": len(raw), "sha256": _sha(raw),
                                     "kind": "data", "raw": raw}], "update-harness")["update-harness"]

    # Stage 5c: one SYSTEM collector per stage the owner asks for, served between two polls of the run.
    def _serve_needs(self, needs):
        """A pending stage this row has no collector for leaves its owner waiting with no deadline: that is UNKNOWN."""
        if type(needs) is not list:
            return
        for need in needs:
            if type(need) is not dict or type(need.get("stage")) is not str or need["stage"] in self.collected:
                continue
            stage = need["stage"]
            if stage not in self.update["collectorStages"]:
                raise Unknown("collector_stage_unserved:" + token(stage))
            for key in ("jobId", "productOperationId"):
                if need.get(key) is not None and (type(need[key]) is not str or _UUID.fullmatch(need[key]) is None):
                    raise Unknown("collector_need_unreadable:" + token(stage))
            self.collected[stage] = None  # Claimed before any program, so a later poll never serves it twice.
            try:
                self.collected[stage] = self._collector_stage(stage, need)
            except Unknown:
                raise
            except Exception as error:
                # Its owner still waits for this evidence; nothing here can end that wait. A check's own finite code
                # crosses, such as collector_coordinator_token; any other error only by its class name.
                raise Unknown("collector_stage_failed:" + token(stage) + ":" + token(error if isinstance(error, KnownFailure) else self._receipt_check(error))) from None

    def _collector_stage(self, stage, need):
        observed = self._collector_observe(stage, need)
        collector = collector_operation(self.op, stage)
        root = self.paths["collector:" + stage]
        request = self._collector_request(stage, need, collector, root, observed)
        raw = (json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        role = "collector-request-" + stage
        pin = self._publish_files([{"role": role, "path": root + "\\collector-request.json", "bytes": len(raw), "sha256": _sha(raw),
                                    "kind": "data", "raw": raw}], role)[role]
        source = self._collector_source(request, pin)
        terminal, pid = self.guest_program("collector-" + stage, source, budget=COLLECTOR_BUDGET_SECONDS)
        proof = self._collector_proof("collector-" + stage, terminal, pid)
        result = self._validate_collector_child(stage, request, pin, proof)
        record = {"operationId": collector, "requestSha256": pin["sha256"], "publications": len(result["publications"]), "release": None}
        if request["closeHold"] is not None:
            record["release"] = self._collector_release(stage, request, pin, proof, terminal, source, result)
        return record

    def _grant(self):
        """A row whose owner hands a committed install to the helper: its collectors observe that installer job."""
        return "authorization" in self.update["collectorStages"]

    def _install_job(self, need):
        """The installer job a grant's stages observe: named by the authorization need, the same in every later one."""
        job = need.get("jobId")
        if not isinstance(job, str) or _UUID.fullmatch(job) is None:
            raise ValueError("collector_job_unnamed")
        if self.install_actors is not None and job != self.install_facts["jobId"]:
            raise ValueError("collector_job_changed")
        return job

    def _collector_observe(self, stage, need):
        """The task's actors and what this stage reads, read only, as SYSTEM.

        before-install of a grant: a census of the CLI image, which holds the serve and the controller it relaunched into.
        authorization: a census of the base install's helper image and the job's worker-ready record. terminal-actors of a
        denied install: the install child's reply and the product's not-started disposition, which the product grants its
        owner alone, so the publisher opens it through SeBackupPrivilege, enabled on its own thread for that open only;
        after a handoff, the job's protected receipt. returned-cleanup: the case's own record of the actors it expects gone.
        """
        grant, deny = self._grant(), stage == "terminal-actors" and not self._grant()
        fields = {"childStdoutLabels": ["one-public-update-install"] if deny else [], "readDisposition": deny,
                  "productWorkspace": self.paths["productWorkspace"], "census": None, "productPins": [],
                  "returnedActors": stage == "returned-cleanup"}
        if stage == "before-install" and grant:
            fields["census"] = {"image": self.paths["cli"]}
        elif stage == "authorization":
            fields["census"] = {"image": self.install_helper["path"]}
            fields["productPins"] = [self.context["localAppData"] + "\\" + INSTALL_INPUTS + "\\" + self._install_job(need) + "\\worker-ready.json"]
        elif stage == "terminal-actors" and grant:
            fields["productPins"] = [INSTALL_JOBS + "\\" + self._install_job(need) + "\\status.json"]
        value, required = self._publisher("collector-observe-" + stage, "collector-observe", **fields)
        observation = value.get("observation")
        if (set(value) != required | {"observation"} or value["state"] != "ordinary-collector-observation" or type(observation) is not dict
                or set(observation) != {"files", "dispositions", "census", "productPins"}):
            raise ValueError("collector_observation")
        files = {name: base64.b64decode(raw, validate=True) for name, raw in (observation["files"] or {}).items()}

        def event(name, kind):
            item = json.loads(files[name], object_pairs_hook=_unique)
            if type(item) is not dict or item.get("operationId") != self.op or item.get("kind") != kind or type(item.get("value")) is not dict:
                raise ValueError("collector_event")
            return item
        intent = event("task-event-000000-submission-intent.json", "submission-intent")
        submitted = event("task-event-000001-submitted.json", "submitted")
        children = {}
        for name in sorted(files):
            found = re.fullmatch(r"event-[0-9]{6}-child-(intent|started)\.json", name)
            if found:
                item = event(name, "child-" + found[1])["value"]
                children.setdefault(item["child"], {}).update(item)
        labels = {}
        for child in children.values():
            if child.get("label") in OBSERVED_CHILDREN:
                if child["label"] in labels:
                    raise ValueError("collector_child_twice")
                labels[child["label"]] = child
        stdout = {}
        for label, child in labels.items():
            name = "child-%04d.stdout.raw" % child["child"]
            if name in files:
                stdout[label] = files[name]
        returned = [event(name, RETURNED_ACTORS_EVENT)["value"] for name in sorted(files)
                    if re.fullmatch(r"event-[0-9]{6}-" + RETURNED_ACTORS_EVENT + r"\.json", name)]
        planner = self._load("windows_ordinary_task")
        dispositions, reads = [], []
        for record in observation["dispositions"] or []:
            if type(record) is not dict or set(record) != {"filePin", "backupReads"} or type(record["backupReads"]) is not list or len(record["backupReads"]) != 2:
                raise ValueError("collector_disposition")
            planner.validate_pin(record["filePin"])
            reads.extend(backup_journal(item) for item in record["backupReads"])
            dispositions.append(record["filePin"])
        pins = observation["productPins"] or []
        if type(pins) is not list or [pin.get("path") if type(pin) is dict else None for pin in pins] != fields["productPins"]:
            raise ValueError("collector_product_pins")
        for pin in pins:
            planner.validate_pin(pin)
        census = None if fields["census"] is None else census_rows(observation["census"])
        if fields["census"] is None and observation["census"] not in (None, []):
            raise ValueError("collector_census_unasked")
        self.backup_reads.extend(reads)
        if reads:
            # The publisher's own journal of every SeBackupPrivilege open it made for this stage, as validated above.
            self._keep("collectors/" + stage + "/backup-reads.json", (json.dumps(reads, sort_keys=True) + "\n").encode())
        return {"owner": {"pid": intent["ownerPid"], "birth": intent["ownerBirthFileTimeUtc"]},
                "worker": {"pid": submitted["value"]["pid"], "birth": submitted["value"]["birthFileTimeUtc"]},
                "children": labels, "stdout": stdout, "dispositions": dispositions, "census": census, "productPins": pins,
                "returned": returned}

    def _collector_request(self, stage, need, collector, root, observed):
        """One request the frozen contract admits: the task's live actors, its exact pins and this stage's inputs only."""
        contract = self._load("windows_system_collector/collector_contract")
        sid, session = self.context["ordinarySid"], self.context["ordinarySessionId"]
        python = self.python_tree
        powershell = next(pin for pin in self.read_pins if pin["path"] == POWERSHELL_PATH)
        interpreter = next(pin for pin in python["filePins"] if pin["path"] == self.paths["pythonExe"])

        def actor(pid, birth, image, digest):
            if type(pid) is not int or pid <= 0 or not isinstance(birth, str) or re.fullmatch(r"[1-9][0-9]{0,19}", birth) is None:
                raise ValueError("collector_actor")
            return {"pid": pid, "creationFileTime": int(birth), "image": image, "sha256": digest, "sid": sid, "sessionId": session}
        task = {"ownerActor": actor(observed["owner"]["pid"], observed["owner"]["birth"], POWERSHELL_PATH, powershell["sha256"]),
                "workerActor": actor(observed["worker"]["pid"], observed["worker"]["birth"], self.paths["pythonExe"], interpreter["sha256"]),
                "ownerSourcePin": self.file_pins["owner"], "workerSourcePin": self.file_pins["worker"],
                "bootstrapRequestPin": self.request_pin, "workerRequestPin": self.worker}
        argv = contract.task_argv(task)
        task.update(ownerArgv=argv["owner"], workerArgv=argv["worker"])
        final = stage == self.update["finalStage"]
        caller = self.file_pins["caller_hold"] if final else None
        modules = {role: {"path": self.paths["file:" + name], "sha256": self.file_pins[name]["sha256"]} for role, name in COLLECTOR_MODULES.items()}
        context = {"bootIdentifier": self.context["bootIdentifier"], "ordinarySid": sid, "ordinarySessionId": session,
                   "localAppData": self.context["localAppData"], "workspace": self.paths["productWorkspace"],
                   "approvingAdminSid": self.administrator_sid}
        actors, inputs, helper, facts = {}, {}, None, None

        def product_file(pin):
            return {"path": pin["path"], "sha256": pin["sha256"], "sizeBytes": pin["nativeIdentity"]["sizeBytes"]}
        if stage == "before-install":
            serve = observed["children"].get("update-public-serve")
            cli = next(pin for pin in self.installed_tree["filePins"] if pin["path"] == self.paths["cli"])
            if serve is None:
                raise ValueError("collector_owner_unobserved")
            actors["owner"] = actor(serve.get("pid"), serve.get("birthFileTimeUtc"), self.paths["cli"], cli["sha256"])
            if self._grant():
                # The coordinator and worker name the process the product's controller runs in: found here, while it lives.
                owner = owner_process(observed["census"], actors["owner"], self.paths["cli"], sid, session)
        elif stage == "authorization":
            if self.update_owner is None:
                raise ValueError("collector_owner_unknown")
            job = self._install_job(need)
            actors, facts = install_actors(observed["census"], helper=self.install_helper, job=job, owner=self.update_owner,
                                           administrator_sid=self.administrator_sid, sid=sid, session=session)
            facts["jobId"] = job
            inputs["workerReady"] = product_file(observed["productPins"][0])
            helper = self.install_helper["sha256"]
        elif stage == "terminal-actors" and self._grant():
            # After a handoff: the authorization stage's own actors, which must now both be gone, and the protected terminal.
            if self.install_actors is None:
                raise ValueError("collector_actors_unknown")
            self._install_job(need)
            actors = json.loads(json.dumps(self.install_actors))
            inputs["protectedReceipt"] = product_file(observed["productPins"][0])
        elif stage == "terminal-actors":
            # A denied prompt starts no installer: the product's own not-started record joins its public reply.
            reply = json.loads(observed["stdout"]["one-public-update-install"], object_pairs_hook=_unique)
            disposition = observed["dispositions"]
            if (type(reply) is not dict or not isinstance(reply.get("controllerId"), str) or not isinstance(reply.get("requestId"), str)
                    or reply.get("operationId") != need.get("productOperationId") or len(disposition) != 1 or need.get("jobId") is None):
                raise ValueError("collector_terminal_unobserved")
            self._load("windows_ordinary_task").validate_pin(disposition[0])
            context.update(originControllerId=reply["controllerId"], originRequestId=reply["requestId"])
            inputs["notStartedDisposition"] = product_file(disposition[0])
        elif stage == "returned-cleanup":
            if self.install_actors is None or len(observed["returned"]) != 1:
                raise ValueError("collector_returned_unobserved")
            self._install_job(need)
            actors = returned_actors(observed["returned"][0], need=need, installed=self.paths["installed"],
                                     target_files=self.target_install["files"], sid=sid, session=session)
        else:
            raise ValueError("collector_stage")
        hold = None
        if final:
            hold = {"schemaVersion": 1, "callerSourcePin": caller, "scope": "update", "stage": stage, "sourceSha": self.plan["product"]["sourceSha"],
                    "holdReadyPath": self.operation_root + "\\collector-hold-" + collector + ".ready.json",
                    "releasePath": root + "\\close-release.json"}
        request = {"schemaVersion": 1, "operationId": collector, "ordinaryTaskOperationId": self.op, "scope": "update",
                   "operationRoot": root, "requestPath": root + "\\collector-request.json",
                   "context": {"bootIdentifier": self.context["bootIdentifier"], "bootFileTimeUtc": self.context["bootFileTimeUtc"],
                               "machineGuid": self.context["machineGuid"], "hardwareUuid": self.raw_context["boot"]["hardwareUuid"].lower(),
                               "ordinarySid": sid, "ordinarySessionId": session, "systemSessionId": 0},
                   "pythonRuntime": self._python_runtime(),
                   "filePins": [*(self.file_pins[name] for name in COLLECTOR_MODULES.values()), *python["filePins"],
                                self.file_pins["owner"], self.file_pins["worker"], self.request_pin, self.worker, *([caller] if caller else [])],
                   "directoryPins": [*self.directory_pins, *python["directoryPins"]], "treePins": [python["tree"]], "modules": modules,
                   "collectorRequest": {"schemaVersion": 1, "stage": stage, "ordinaryTaskOperationId": self.op,
                                        "sourceSha": self.plan["product"]["sourceSha"], "collectorSourceSha256": self.file_pins["collector"]["sha256"],
                                        "context": context, "jobId": need.get("jobId"), "productOperationId": need.get("productOperationId"),
                                        "actors": actors, "fileInputs": inputs, "faultBinding": {}, "programData": PROGRAM_DATA,
                                        "evidenceRoot": self.paths["evidenceRoot"], "ordinaryWorkerPid": observed["worker"]["pid"],
                                        "ordinaryWorkerBirth": observed["worker"]["birth"], "expectedHelperSha256": helper},
                   "rawStreamLimitBytes": COLLECTOR_RAW_LIMIT, "ordinaryTask": task, "closeHold": hold}
        contract.validate(request, {"contract": self.file_pins["collector_contract"]["sha256"], "worker": self.file_pins["system_worker"]["sha256"]},
                          self._lower_context())
        if stage == "before-install" and self._grant():
            self.update_owner = owner
            self._keep("collectors/before-install/census.json", (json.dumps(observed["census"], sort_keys=True) + "\n").encode())
        if stage == "authorization":
            self.install_actors, self.install_facts = actors, facts
            self._keep("collectors/authorization/census.json", (json.dumps(observed["census"], sort_keys=True) + "\n").encode())
        return request

    def _lower_context(self):
        """The collector contract's guest context: canonical lowercase GUIDs, which the guest itself never reports."""
        boot = self.raw_context["boot"]
        return {"deploymentId": self.machine, "ordinarySid": self.context["ordinarySid"], "powerShellPath": POWERSHELL_PATH,
                "sourceWorkspace": self.workspace, "boot": {"lastBootUpTimeFileTimeUtc": boot["lastBootUpTimeFileTimeUtc"],
                                                           "machineGuid": boot["machineGuid"].lower(), "hardwareUuid": boot["hardwareUuid"].lower()}}

    def _bound(self, source, context):
        """The emitter's prelude, bound to what the guest reports: WMI gives the hardware UUID in upper case and the
        prelude compares it case-sensitively, while the contract demands the lowercase form."""
        if context != self._lower_context():
            raise ValueError("collector_guest_context")
        return self._load("windows_artifact_transfer")._boot_bound(source, self.raw_context)

    def _stdin_collector(self, rendered):
        """A saved-source collector, run on the stdin route: no BOM, the held-program type its launcher used to define,
        and the inline gzip reply."""
        text = rendered.decode("utf-8-sig", "strict")
        first, rest = text.split("\n", 1)
        return wrap_output(first + "\n" + held_program_type(self._load("windows_artifact_transfer")) + rest)

    def _collector_source(self, request, pin):
        wrapper = self._load("windows_system_collector/collector_wrapper")
        rendered = wrapper.render_source(request, pin, self._bundle_source("windows_system_collector/collector_contract.py"),
                                         self._bundle_source("windows_system_collector/system_bootstrap_template.ps1"),
                                         types.SimpleNamespace(_boot_bound=self._bound), self._lower_context())
        return self._rendered(lambda: self._stdin_collector(rendered))

    def _collector_proof(self, label, terminal, pid):
        """A SYSTEM collector that parked never returns; one that returned is read with the raw context."""
        try:
            return self._load("windows_artifact_transfer").decode_guest_result({"transport": "inline"}, decode_stdout(terminal), self.raw_context, pid)
        except (ValueError, TypeError, KeyError):
            raise Unknown("collector_unreadable:" + token(label)) from None

    def _validate_collector_child(self, stage, request, request_pin, proof):
        """collector_wrapper.RetainedSystemCollector.validate_child, on this route's proof."""
        p, r = proof, request

        def need(condition, code):
            if not condition:
                raise ValueError(code)
        expected = {"schemaVersion", "state", "operationId", "ordinaryTaskOperationId", "scope", "collectorSourceSha256", "requestSha256",
                    "requestNativeIdentity", "worker", "captures", "sourceClosing", "productMutation", "bootstrapOpening", "bootstrapClosing",
                    "guestBootClosing", "bootstrapActorClosing"}
        need(type(p) is dict and set(p) == expected and p["schemaVersion"] == 1 and p["state"] == "collector-closed"
             and p["operationId"] == r["operationId"] and p["ordinaryTaskOperationId"] == r["ordinaryTaskOperationId"]
             and p["scope"] == r["scope"] and p["collectorSourceSha256"] == r["modules"]["collector"]["sha256"]
             and p["requestSha256"] == request_pin["sha256"] and p["requestNativeIdentity"] == request_pin["nativeIdentity"]
             and p["sourceClosing"] is True and p["productMutation"] is False, "collector-closed-child-origin")
        w = p["worker"]
        need(type(w) is dict and set(w) == {"pid", "birthFileTimeUtc", "image", "sessionId", "exitCode", "bothEof", "originalHandleRetained"}
             and type(w["pid"]) is int and w["pid"] > 0 and type(w["birthFileTimeUtc"]) is str
             and re.fullmatch("[1-9][0-9]{16,19}", w["birthFileTimeUtc"]) and w["image"] == r["pythonRuntime"]["interpreterPath"]
             and type(w["sessionId"]) is int and w["sessionId"] == 0 and type(w["exitCode"]) is int and w["exitCode"] == 0
             and w["bothEof"] is True and w["originalHandleRetained"] is True, "collector-original-child-native-generation")
        need(type(p["captures"]) is list and len(p["captures"]) == 2, "collector-dual-full-captures")
        captures = {}
        for value in p["captures"]:
            need(type(value) is dict and set(value) == {"name", "sizeBytes", "sha256", "base64", "eof", "nativeIdentity"}
                 and value["name"] in {"stdout", "stderr"} and value["name"] not in captures and value["eof"] is True
                 and type(value["sizeBytes"]) is int and 0 <= value["sizeBytes"] <= r["rawStreamLimitBytes"]
                 and type(value["base64"]) is str and len(value["base64"]) <= 4 * r["rawStreamLimitBytes"] // 3 + 4,
                 "collector-original-child-capture-schema")
            raw = base64.b64decode(value["base64"], validate=True)
            need(len(raw) == value["sizeBytes"] and _sha(raw) == value["sha256"] and value["nativeIdentity"].get("sizeBytes") == len(raw),
                 "collector-original-child-full-capture-digest")
            captures[value["name"]] = raw
            self._keep("collectors/" + stage + "/child." + value["name"] + ".raw", raw)
        need(not captures["stderr"], "collector-child-unexpected-stderr")
        result = json.loads(captures["stdout"].decode("utf-8", "strict"))
        need(type(result) is dict and set(result) == {"schemaVersion", "state", "operationId", "ordinaryTaskOperationId", "scope",
                                                      "collectorSourceSha256", "workerActor", "publications", "closing", "callerHold"}
             and result["schemaVersion"] == 1 and result["state"] == "collector-completed"
             and all(result[key] == p[key] for key in ("operationId", "ordinaryTaskOperationId", "scope", "collectorSourceSha256")),
             "collector-child-result-join")
        actor = result["workerActor"]
        need(actor["pid"] == w["pid"] and actor["birthFileTimeUtc"] == w["birthFileTimeUtc"] and actor["image"] == w["image"]
             and actor["bootIdentifier"] == r["context"]["bootIdentifier"] and actor["token"]["sid"] == "S-1-5-18"
             and actor["token"]["sessionId"] == 0 and actor["token"]["elevation"] == 1, "collector-child-current-system-actor")
        need(result["closing"].get("sourceClosing") is True and type(result["closing"].get("files")) is int
             and result["closing"]["files"] == len(r["filePins"]) + 1
             and re.fullmatch("[a-f0-9]{64}", result["closing"].get("completeFileDigestSha256", "")), "collector-child-complete-source-closing")
        need(type(result["publications"]) is list and len(result["publications"]) == 1, "collector-finite-publication-count")
        h, value = r["closeHold"], result["callerHold"]
        if h is None:
            need(value is None, "collector-unrequested-caller-hold")
        else:
            protocol = self._load("windows_system_collector/hold_protocol")
            need(type(value) is dict and set(value) == {"ready", "sha256", "nativeFile", "originalHandleRetained"}
                 and value["originalHandleRetained"] is True, "collector-held-ready-proof-schema")
            ready = protocol.validate_ready(value["ready"])
            worker = r["ordinaryTask"]["workerActor"]
            need(value["sha256"] == _sha(protocol.encoded(ready)) and value["nativeFile"]["path"] == h["holdReadyPath"]
                 and value["nativeFile"]["security"]["ownerSid"] == r["context"]["ordinarySid"]
                 and value["nativeFile"]["nativeIdentity"]["sizeBytes"] == len(protocol.encoded(ready)), "collector-held-ready-file-byte-join")
            protocol.native_identity(value["nativeFile"]["nativeIdentity"])
            need(ready["collectorOperationId"] == r["operationId"] and ready["ordinaryTaskOperationId"] == r["ordinaryTaskOperationId"]
                 and ready["bootIdentifier"] == r["context"]["bootIdentifier"]
                 and all(ready[key] == h[key] for key in ("scope", "stage", "sourceSha", "callerSourcePin"))
                 and ready["collectorRequestSha256"] == request_pin["sha256"]
                 and ready["ordinaryWorker"] == {"pid": worker["pid"], "birthFileTimeUtc": str(worker["creationFileTime"]),
                                                 **{key: worker[key] for key in ("image", "sha256", "sid", "sessionId")}}
                 and ready["systemActor"] == {"pid": p["bootstrapOpening"]["pid"], "birthFileTimeUtc": p["bootstrapOpening"]["birthFileTimeUtc"]}
                 and ready["collectorChild"] == {key: actor[key] for key in ("pid", "birthFileTimeUtc")}, "collector-held-ready-original-generations")
        return result

    def _collector_release(self, stage, request, pin, proof, terminal, source, result):
        """collector_wrapper's start_release and render_release_source, on the stdin route: the caller's hold ends only here."""
        protocol = self._load("windows_system_collector/hold_protocol")
        contract = self._load("windows_system_collector/collector_contract")
        hold = result["callerHold"]
        captures = {value["name"]: value for value in proof["captures"]}
        closure = {"systemExitCode": terminal["exitcode"], "childExitCode": proof["worker"]["exitCode"], "bothChildEof": proof["worker"]["bothEof"],
                   "sourceClosing": True, "qgaStdoutSha256": _sha(base64.b64decode(terminal.get("out-data", ""), validate=True)),
                   "qgaStderrSha256": _sha(base64.b64decode(terminal.get("err-data", ""), validate=True)),
                   "childStdoutSha256": captures["stdout"]["sha256"], "childStderrSha256": captures["stderr"]["sha256"],
                   "systemSourceSha256": _sha(source.encode("ascii"))}
        record = {**protocol.common_from_ready(hold["ready"]), "kind": "collector-close-release", "holdReadySha256": hold["sha256"],
                  "holdReadyNativeIdentity": hold["nativeFile"]["nativeIdentity"], "closure": closure}
        protocol.validate_release(record, hold["ready"], hold["sha256"], hold["nativeFile"]["nativeIdentity"])
        bridge = next(item for item in request["filePins"] if item["path"] == request["modules"]["nativeBridge"]["path"])
        substitutions = {"BRIDGE_PIN_BASE64": base64.b64encode(contract.encoded(bridge)).decode(),
                         "REQUEST_PIN_BASE64": base64.b64encode(contract.encoded(pin)).decode(),
                         "RELEASE_BASE64": base64.b64encode(protocol.encoded(record)).decode(),
                         "READY_PIN_BASE64": base64.b64encode(contract.encoded({**hold["nativeFile"], "sha256": hold["sha256"]})).decode(),
                         "OPERATION": request["operationId"]}
        template = self._bundle_source("windows_system_collector/release_template.ps1").decode("utf-8", "strict")
        if set(re.findall(r"@@([A-Z0-9_]+)@@", template)) != set(substitutions):
            raise ValueError("collector-release-placeholders")
        for key, value in substitutions.items():
            if template.count("@@" + key + "@@") != 1:
                raise ValueError("collector-release-placeholder-count")
            template = template.replace("@@" + key + "@@", value)
        label = "collector-release-" + stage
        released, pid = self.guest_program(label, self._rendered(lambda: self._stdin_collector(self._bound(template, self._lower_context()).encode("utf-8-sig"))))
        p = self._collector_proof(label, released, pid)
        if (type(p) is not dict or set(p) != {"schemaVersion", "state", "operationId", "requestSha256", "releasePath", "releaseSha256",
                                              "releaseNativeIdentity", "sourceClosing", "originalCollectorKnownClosed", "productMutation",
                                              "bootstrapOpening", "bootstrapClosing", "guestBootClosing", "bootstrapActorClosing"}
                or p["schemaVersion"] != 1 or p["state"] != "collector-release-published" or p["operationId"] != request["operationId"]
                or p["requestSha256"] != pin["sha256"] or p["releasePath"] != request["closeHold"]["releasePath"]
                or p["releaseSha256"] != _sha(protocol.encoded(record)) or p["sourceClosing"] is not True
                or p["originalCollectorKnownClosed"] is not True or p["productMutation"] is not False):
            raise Unknown("collector_release_unproven:" + token(stage))
        protocol.native_identity(p["releaseNativeIdentity"])
        return p["releaseSha256"]

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
             "taskXml": re.sub(r"\A<\?xml[^>]*\?>\s*", "", task["xmlUtf8"]),
             "uacKinds": [self.row["uac"]["event"]] if self.row.get("uac") else [], "nativeNeeds": bool(self.update)}
        terminal, pid = self.guest_program("system-run", self._rendered(lambda: self._system_run_source(m)),
                                           budget=self.row["deadlineSeconds"] + RUN_MARGIN_SECONDS,
                                           poll=STATUS_POLL_SECONDS, on_poll=self._on_status)
        self._on_status(serve=False)  # The final copy for observers; the run has returned, so no need is served.
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
        if (self.document or {}).get("principalProbe"):
            state = (self.principal or {}).get("state")
            if state != "observed":
                raise KnownFailure("document_principal_" + ("unserved" if state is None else state if state != "failed" else self.principal["reason"]))

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
                          "productVersion": self.msi["productVersion"], "packageCode": rows[0]["packageCode"],
                          "treeSha256": tree["sha256"], "treeFiles": len(tree["tree"]["files"])}
        # What msiexec installed, file by file: a later update row compares the tree it finds, or expects, with it.
        files = {pin["path"]: pin for pin in tree["filePins"]}
        inventory = {name: {"sizeBytes": files[self.paths["installed"] + "\\" + name.replace("/", "\\")]["nativeIdentity"]["sizeBytes"],
                            "sha256": files[self.paths["installed"] + "\\" + name.replace("/", "\\")]["sha256"]} for name in tree["tree"]["files"]}
        self._keep(INVENTORY_NAME, (json.dumps({"schemaVersion": 1, "operationId": self.op, "installed": self.installed,
                                                 "installLocation": self.paths["installed"], "files": inventory},
                                                sort_keys=True, separators=(",", ":")) + "\n").encode())

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

    # Stage 6b: a passed reboot preboot declares the product it left running, for the reviewed idle allowance.
    def stage_declare(self):
        raw = (self.data / self.evidence["name"]).read_bytes()
        if len(raw) != self.evidence["bytes"] or _sha(raw) != self.evidence["sha256"]:
            raise KnownFailure("evidence_changed")
        hashes = {pin["path"]: pin["sha256"] for pin in self.installed_tree["filePins"]}
        try:
            declaration, name = product_declaration(self.op, self.machine, self.context, self.paths,
                                                    {"gui": hashes[self.paths["gui"]], "runtime": self.runtime_sha256},
                                                    evidence_events(raw), self.row["reboot"]["scenario"])
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                checkpoint = archive.read(name)
        except (ValueError, KeyError, TypeError, zipfile.BadZipFile):
            raise KnownFailure("product_declaration_refused") from None
        data = (json.dumps(declaration, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        # SYSTEM-owned, user read-only, create-only: the only file the idle census accepts as a declaration.
        self._publish_files([{"role": "allowance", "path": self.paths["allowance"], "bytes": len(data), "sha256": _sha(data),
                              "kind": "data", "raw": data}], "declare")
        self.preboot = {"scenario": self.row["reboot"]["scenario"], "productWorkspace": self.paths["productWorkspace"],
                        "operationRoot": self.operation_root, "checkpointName": name, "checkpointSha256": _sha(checkpoint),
                        "bootFileTimeUtc": self.context["bootFileTimeUtc"], "allowanceSha256": _sha(data),
                        "declaredProcesses": len(declaration["processes"])}

    # Stage 7 and the end of the job.
    def _finish(self, code, failure):
        try:
            if self.owns_data:
                # The raw identity as the guest reports it: this is what a first proof reads.
                context = None if self.context is None else {**self.context, **{
                    "hardwareUuid": self.raw_context["boot"]["hardwareUuid"], "machineGuid": self.raw_context["boot"]["machineGuid"]}}
                # Installed-package evidence: a passed product row whose MSI registration, complete
                # installed tree and --version under the ordinary token (the worker's own static probe,
                # the dedicated driver's before a proxy row's runtime, or the harness) all held.
                # A job stopped before its task matched the first two but never ran --version.
                # An update row claims none: the job matched the base's tree before the run, never the target's after
                # a grant's install; the case's own registration and --version checks stay in its evidence.
                claimed = (code == EXIT_PASSED and self.row["evidenceClass"] == "product" and self.installed_matched
                           and self.task_checked and self.plan.get("stopAfter") is None and not self.update)
                windows = {"installedPackage": claimed, "packageSha256": self.package_target()["sha256"] if claimed else None}
                receipt = build_receipt(self.plan, exit_code=code, stage=self.stage, failure=failure, context=context,
                                        task=self.task, evidence=self.evidence, guest_programs=self.programs,
                                        installed=self.installed, python=self.python_facts, windows=windows, preboot=self.preboot,
                                        reboot=self._reboot_receipt(code) if self.row.get("reboot") else None)
                if self.document:
                    receipt["document"] = {"variant": self.document["variant"], "principal": self.principal}
                if self.update:
                    receipt["update"] = {"variant": self.update["variant"],
                                         "collectors": {stage: (None if record is None else {"requestSha256": record["requestSha256"],
                                                                                              "released": record["release"] is not None})
                                                        for stage, record in sorted(self.collected.items())}}
                    # What the first native runs must show: the installer's live actors as a SYSTEM census found them,
                    # their parents as recorded, and how many owner-only product files were read through SeBackupPrivilege.
                    if self.install_facts is not None:
                        receipt["update"]["installer"] = self.install_facts
                    if self.backup_reads:
                        receipt["update"]["backupReads"] = len(self.backup_reads)
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
        if code == EXIT_PASSED and stop is None and "declare" in self.row["stages"]:
            self.stage = "declare"
            try:
                self.stage_declare()
            except KnownFailure as error:
                code, failure = EXIT_FAILED, token(error)
            except Exception as error:
                code = EXIT_UNKNOWN
                failure = token(error if isinstance(error, Unknown) else "unexpected:" + type(error).__name__)
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
