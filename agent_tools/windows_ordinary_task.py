"""Fresh ordinary Windows task plans and observed privilege-policy validation.

This module never registers a task, publishes a file, or starts a process.

Requires actual native pin records from separately qualified current admission.
This planner is not evidence that the files/VM/token/boot were admitted.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import subprocess
import uuid
import xml.etree.ElementTree as ET

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
MSIEXEC = r"C:\Windows\System32\msiexec.exe"
PYTHON_INSTALLER_SHA256 = "edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403"
PYTHON_INSTALLER_BYTES = 29452944
NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
PYTHON_FLAGS = ("/quiet", "InstallAllUsers=0", "PrependPath=0", "Include_launcher=0",
                "Include_pip=0", "Include_test=0")
PIN_FIELDS = {"path", "nativeIdentity", "security", "sha256"}
TREE_ROLES = frozenset({"python-runtime", "installed-app", "installed-application", "source"})
FILE_ID_FIELDS = {"volumeSerial", "fileIndex", "attributes", "sizeBytes", "links",
                  "creationFileTime", "lastWriteFileTime"}
DIR_ID_FIELDS = {"volumeSerial", "fileIndex", "attributes"}
PYTHON_REQUIRED_FILES = {"python.exe", "python313.dll", "Lib/os.py", "Lib/subprocess.py",
                         "Lib/threading.py", "Lib/json/__init__.py",
                         "Lib/ctypes/__init__.py", "DLLs/_ctypes.pyd"}
SOURCE_PATHS = ("agent_tools/windows_ordinary_task.py",
                "agent_tools/windows_ordinary_process_owner.py",
                "agent_tools/windows_ordinary_task_owner.ps1")
POLICY_FIELDS = ("UserId", "LogonType", "ExecutionTimeLimit", "MultipleInstancesPolicy",
                 "WorkingDirectory", "Command", "Arguments")
COMMON_FIELDS = {"schemaVersion", "context", "operationId", "operationRoot", "filePins",
                 "directoryPins", "treePins", "rawStreamLimitBytes"}
ACTION_FIELDS = {"pythonRuntime", "action", "msiPath", "installerLogPath", "uninstallProductCode",
                 "uninstallLogPath", "uninstallRoot", "qualificationArgv",
                 "expectedExitCode", "cliPath", "workspace", "productVersion", "casesPath",
                 "harnessPath", "documentAcceptance", "postbootAcceptance", "responsiveWork", "bootstrap"}
DEDICATED_DRIVER_SHA = "1c56beaaba4db5674faa5ad01ccdd8c5c51602bc335a7a03104fd99730676677"
DEDICATED_CASES = {
    "windows-public-update": ("windows_public_updater/update_cases.py", "17ecb2f41b42a3988f6905fe6a426935564a48e17e776efe7c3a9dbf4f668f5c"),
    "windows-proxy-lifecycle": ("windows_lifecycle_cases.py", "9a965b3db065ca98bdfa8c63cccaa059e676cf53a49c6705cf648e0989a3f987"),
}

# Reboot actions: one preboot operation, readiness-reboot, then one postboot operation. The
# role table equals windows_postboot_source_roles.ROLES; each fixed source is pinned here.
POSTBOOT_ACTION_PHASES = {"windows-preboot-reboot": "preboot-reboot", "windows-postboot-final": "postboot-final"}
POSTBOOT_SCENARIOS = {"windows-preboot-reboot": frozenset({"reconnect", "explicit-off", "autostart-migration", "query-first"}),
                      "windows-postboot-final": frozenset({"reconnect", "explicit-off", "autostart-migration"})}
POSTBOOT_RUNTIME_AUTHORITY = ("app", "native", "windows-amd64", "native-helpers.json")
POSTBOOT_ROLE_HASHES = {'autostart': '76328cad6b77eb9716545e7c3bdc729b4fa16093c2ddad4002642c20458f6070', 'lifecycle': '9a965b3db065ca98bdfa8c63cccaa059e676cf53a49c6705cf648e0989a3f987', 'listenerScript': '1b62f857e627770be43057749f527128f573b89885590310ad51d95443c0b928', 'migrationScript': 'c984104461806c2f3fa4b74a4260acf48ef9f66524149a01cc4f67b2a305104d', 'observer': '6d08edf9e57b09e98ce80d414b2ac12da4f39eb82e27cd2a3f06d9f900e04dcb', 'postbootAction': 'fc4bb5c44e34fba4239c4798462d650492be224d644491836af9c6e6ebd97b5f', 'prebootAction': '6c6e73890c0502ef983ea9155087a98f3c3a643f116d2ae813c05b7b2f17d18e', 'runtime': 'a3292caa396c3efe4e8c8d44d989615c98bbb9e0418d12487964bf17c9b6601e', 'runtimeStages': '0b6b6c7c4c261a8996c140661b7631fb234115ed215e3d3a4a72fd60e25e676e', 'snapshotScript': 'ece980bb211e52349c4623fd941e217c5c1f1d4e854efd0f7765cbdc5eba2cb2', 'sourceRoles': '20935673ed2dcc58c6a2214136dda371782a76e4084b46fa611088fafd7c601b', 'startScript': '9f7b4b5ad3ffa7743bd9961463cb0d38ef791b0d8191313984e0f74bf0a9d502', 'startupCollector': '3f8f198fde10df843c69a2c1ead1beb05ed59f4d26c097dece6448f5f40d1723', 'trafficWorker': 'c37423c7627e6972eff2b7d717904f9b07fdaeb5b1d880d1606559b58d2e2e2d', 'upstreamFixture': '50239b25bb1c63e7c86baaea8683f188426e87d6a1c6090b505c38d567e70210'}
POSTBOOT_ROLES = frozenset(['autostart', 'gui', 'lifecycle', 'listenerScript', 'migrationScript', 'observer', 'postbootAction', 'powerShell', 'prebootAction', 'runtime', 'runtimeAuthority', 'runtimeStages', 'snapshotScript', 'sourceRoles', 'startScript', 'startupCollector', 'trafficWorker', 'upstreamFixture'])

DOCUMENT_RESPONSIVE_CASE = (
    "windows_document_responsive_cli_cases.py",
    "e68261ac8d8a18a8a5d1e86ad83331a8374315d2ef2ce7e482e3a4f9cfeb8367",
)

DOCUMENT_RESPONSIVE_SOURCES = {
    "casesPath": ("windows_document_responsive_cases.py", "1ae4bea2eac10bfae57846871587e4c4004f3dfbcf2711cdf96f93c998f6eea6"),
    "runtimeStagesPath": ("windows_lifecycle_runtime_stages.py", "0b6b6c7c4c261a8996c140661b7631fb234115ed215e3d3a4a72fd60e25e676e"),
    "fixtureWorkerPath": ("windows_document_gated_https_fixture.py", "c74b153072e4b4ce464eb483b759bc38e02e208195aa6a5bd076feb17b42f971"),
    "socksSourcePath": ("socks_http_fixture.py", "50239b25bb1c63e7c86baaea8683f188426e87d6a1c6090b505c38d567e70210"),
    "httpsSourcePath": ("https_subscription_relay_fixture.py", "e62f262d9703eb63c0eeca9b823eaae9d1a5780aefdedadf8aebe211492651d4"),
}

DOCUMENT_RESPONSIVE_FIELDS = {"schemaVersion", "casesPath", "runtimeStagesPath",
    "fixtureWorkerPath", "socksSourcePath", "httpsSourcePath", "certificatePath",
    "privateKeyPath", "trustStorePath", "contexts", "largeRoutingInputPath"}


_PROTECTED_OS_PATHS = frozenset({
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\msiexec.exe",
})
_PROTECTED_OS_OWNER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
_PROTECTED_OS_WRITERS = frozenset({_PROTECTED_OS_OWNER, "SY", "BA", "S-1-5-18", "S-1-5-32-544"})
_PROTECTED_OS_READ_MASK = 0xA01200A9
_PROTECTED_OS_RIGHTS = {
    "FA": 0x001F01FF, "FR": 0x00120089, "FW": 0x00120116, "FX": 0x001200A0,
    "GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000,
    "RC": 0x00020000, "SD": 0x00010000, "WD": 0x00040000, "WO": 0x00080000,
}
_PROTECTED_OS_SID_ALIASES = frozenset({
    "SY", "BA", "BU", "AC", "WD", "AU", "AN", "IU", "SU", "LS", "NS", "NU",
    "RD", "RC", "OW", "CO", "CG",
})


def _protected_os_security(security):
    """Accept a finite common-ACE protected OS owner/DACL policy, not a fixture ACL."""
    if (type(security) is not dict or set(security) != {"ownerSid", "sddl"}
            or security["ownerSid"] != _PROTECTED_OS_OWNER
            or type(security["sddl"]) is not str or len(security["sddl"]) > 16384):
        return False
    prefix = "O:" + _PROTECTED_OS_OWNER + "D:"
    if not security["sddl"].startswith(prefix):
        return False
    dacl = security["sddl"][len(prefix):]
    start = dacl.find("(")
    if start < 0 or not dacl.endswith(")"):
        return False  # Reject null and empty DACLs, and non-common ACE grammars.
    flags, seen = dacl[:start], set()
    while flags:
        flag = next((v for v in ("AI", "AR", "P") if flags.startswith(v)), None)
        if flag is None or flag in seen:
            return False
        seen.add(flag)
        flags = flags[len(flag):]
    if "P" not in seen:
        return False
    for ace in dacl[start:-1].split(")"):
        if not ace.startswith("("):
            return False
        fields = ace[1:].split(";")
        if len(fields) != 6:
            return False
        kind, flags, rights, object_guid, inherited_guid, trustee = fields
        if (kind not in {"A", "D"} or object_guid or inherited_guid
                or len(flags) % 2 or len(set(flags[i:i + 2] for i in range(0, len(flags), 2)))
                != len(flags) // 2 or any(flags[i:i + 2] not in {"OI", "CI", "NP", "IO", "ID"}
                    for i in range(0, len(flags), 2))):
            return False
        if trustee not in _PROTECTED_OS_SID_ALIASES:
            parts = trustee.split("-")
            if (not 4 <= len(parts) <= 18 or parts[:2] != ["S", "1"]
                    or any(not item.isascii() or not item.isdecimal()
                           or (len(item) > 1 and item[0] == "0") for item in parts[2:])
                    or len(parts[2]) > 15 or any(len(item) > 10 for item in parts[3:])
                    or int(parts[2]) > 0xFFFFFFFFFFFF
                    or any(int(item) > 0xFFFFFFFF for item in parts[3:])):
                return False
        if rights.startswith("0x"):
            if (not 1 <= len(rights[2:]) <= 8
                    or any(c not in "0123456789abcdefABCDEF" for c in rights[2:])):
                return False
            mask = int(rights[2:], 16)
        else:
            if not rights or len(rights) % 2:
                return False
            mask = 0
            for i in range(0, len(rights), 2):
                value = _PROTECTED_OS_RIGHTS.get(rights[i:i + 2])
                if value is None:
                    return False
                mask |= value
        if kind == "A" and trustee not in _PROTECTED_OS_WRITERS and mask & ~_PROTECTED_OS_READ_MASK:
            return False
    return True

def source_inventory():
    """Read only the three original canonical files actually consumed by plans."""
    root = Path(__file__).resolve().parent.parent
    result = {}
    for name in SOURCE_PATHS:
        body = (root / name).read_bytes()
        result[name] = {"path": str(root / name), "sha256": hashlib.sha256(body).hexdigest(),
                        "sizeBytes": len(body)}
    return result


def need(value, code):
    if not value:
        raise ValueError(code)


def data(value):
    result = (json.dumps(value, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":")) + "\n").encode("utf-8", "strict")
    need(len(result) <= 4 * 1024 * 1024, "request-byte-bound")
    return result


def path(value):
    need(type(value) is str and not any(ord(c) < 32 for c in value) and len(value) <= 1000,
         "path-type-or-bound")
    item = PureWindowsPath(value)
    need(len(item.drive) == 2 and item.drive[1] == ":" and item.root == "\\"
         and str(item) == value and not any(part in {".", ".."} or part.endswith((".", " "))
             or any(c in '<>:"|?*' for c in part) for part in item.parts[1:]),
         "normalized-absolute-drive-path")
    need(not any(part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL",
              *{f"COM{i}" for i in range(1, 10)}, *{f"LPT{i}" for i in range(1, 10)}}
                 for part in item.parts[1:]), "windows-device-path")
    return item


def validate_context(context):
    required = {"deploymentId", "ordinarySid", "ordinarySessionId", "profileRoot",
                "localAppData", "machineGuid", "bootIdentifier", "bootFileTimeUtc"}
    need(type(context) is dict and set(context) == required, "context-schema")
    for field in ("deploymentId", "machineGuid", "bootIdentifier"):
        need(type(context[field]) is str and str(uuid.UUID(context[field])) == context[field]
             and uuid.UUID(context[field]).int != 0, "context-canonical-guid")
    need(re.fullmatch(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+", context["ordinarySid"])
         and type(context["ordinarySessionId"]) is int and context["ordinarySessionId"] > 0,
         "ordinary-context")
    need(type(context["bootFileTimeUtc"]) is str
         and re.fullmatch(r"[1-9][0-9]{0,18}", context["bootFileTimeUtc"]),
         "actual-cim-boot-required")
    profile, local = path(context["profileRoot"]), path(context["localAppData"])
    need(local == profile / "AppData" / "Local", "ordinary-profile-local-binding")


def validate_pin(record, directory=False):
    need(type(record) is dict and set(record) == (PIN_FIELDS - {"sha256"} if directory else PIN_FIELDS),
         "native-pin-schema")
    candidate = path(record["path"])
    need(type(record["nativeIdentity"]) is dict and set(record["nativeIdentity"]) ==
         (DIR_ID_FIELDS if directory else FILE_ID_FIELDS), "native-file-id-schema")
    need(all(type(value) is int and value >= 0 for key, value in record["nativeIdentity"].items()
             if key not in {"creationFileTime", "lastWriteFileTime"})
         and all(type(record["nativeIdentity"][key]) is str
                 and re.fullmatch(r"[0-9]{1,19}", record["nativeIdentity"][key])
                 for key in ({"creationFileTime", "lastWriteFileTime"} if not directory else set())),
         "native-file-id-types")
    need(not record["nativeIdentity"]["attributes"] & 0x400
         and bool(record["nativeIdentity"]["attributes"] & 0x10) == directory,
         "native-reparse-or-type")
    need(type(record["security"]) is dict and set(record["security"]) == {"ownerSid", "sddl"}
         and type(record["security"]["ownerSid"]) is str
         and type(record["security"]["sddl"]) is str and len(record["security"]["sddl"]) <= 16384,
         "actual-owner-dacl-sddl-required")
    if not directory:
        protected_os = record["path"] in _PROTECTED_OS_PATHS
        need(not protected_os or _protected_os_security(record["security"]),
             "protected-os-writer-policy")
        need((record["nativeIdentity"]["links"] > 0 if protected_os
              else record["nativeIdentity"]["links"] == 1) and type(record["sha256"]) is str
             and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]), "single-link-file-digest")
    return candidate


def validate_closure(request):
    need(type(request) is dict and COMMON_FIELDS <= set(request)
         and set(request) <= COMMON_FIELDS | ACTION_FIELDS
         and type(request["schemaVersion"]) is int and request["schemaVersion"] == 1,
         "request-schema")
    need(type(request["filePins"]) is list and 1 <= len(request["filePins"]) <= 4096
         and type(request["directoryPins"]) is list and 1 <= len(request["directoryPins"]) <= 1024
         and type(request["treePins"]) is list and len(request["treePins"]) <= 32,
         "pin-list-schema-or-bound")
    validate_context(request["context"])
    root = path(request["operationRoot"])
    need(root.is_relative_to(path(request["context"]["localAppData"]))
         and root != path(request["context"]["localAppData"]), "ordinary-private-operation-root")
    need(str(uuid.UUID(request["operationId"])) == request["operationId"], "operation-id")
    need(len(request["filePins"]) <= 4096 and len(request["directoryPins"]) <= 1024,
         "pin-resource-bound")
    files = {validate_pin(item) for item in request["filePins"]}
    directories = {validate_pin(item, True) for item in request["directoryPins"]}
    need(len(files) == len(request["filePins"]) and len(directories) == len(request["directoryPins"]),
         "duplicate-pin")
    need(root in directories, "operation-root-native-pin")
    for item in files | {root}:
        need(set(item.parents) <= directories, "every-ancestor-native-pin-required")
    for tree in request["treePins"]:
        # installed-application is the one tree the public updater's lease retires and re-admits
        # (update_receipts.InstalledApplicationLease); installed-app stays the read-only CLI rows' role.
        need(type(tree) is dict and set(tree) == {"role", "root", "files"}
             and tree["role"] in TREE_ROLES, "tree-role-schema")
        tree_root = path(tree["root"])
        need(tree_root in directories and type(tree["files"]) is list and len(tree["files"]) <= 8192,
             "complete-tree-schema")
        names = set()
        for name in tree["files"]:
            need(type(name) is str and name and "\\" not in name and not name.startswith("/"),
                 "tree-relative-name")
            candidate = path(str(tree_root / PureWindowsPath(name)))
            need(candidate.is_relative_to(tree_root) and candidate != tree_root
                 and candidate in files and name.casefold() not in names, "tree-file-pin-or-alias")
            names.add(name.casefold())
    need(type(request["rawStreamLimitBytes"]) is int
         and 4096 <= request["rawStreamLimitBytes"] <= 64 * 1024 * 1024,
         "raw-stream-resource-bound")
    data(request)
    return files


def validate_python_runtime(request, interpreter_path=None):
    runtime = request.get("pythonRuntime")
    need(type(runtime) is dict and set(runtime) == {"root", "interpreterPath", "version", "architecture"}
         and runtime["version"] == "3.13.15" and runtime["architecture"] == "amd64",
         "actual-admitted-python-runtime-role-required")
    root = path(runtime["root"])
    need(path(runtime["interpreterPath"]) == root / "python.exe", "python-runtime-interpreter-path")
    if interpreter_path is not None:
        need(path(interpreter_path) == path(runtime["interpreterPath"]), "exact-python-interpreter-binding")
    trees = [tree for tree in request["treePins"]
             if tree.get("role") == "python-runtime" and path(tree["root"]) == root]
    need(len(trees) == 1 and PYTHON_REQUIRED_FILES <= set(trees[0]["files"]),
         "complete-role-bound-python-runtime-tree")


def python_installer_arguments(target_dir, log_path, ordinary_local, operation_root):
    target, log = path(target_dir), path(log_path)
    need(target.is_relative_to(path(ordinary_local)) and target != path(ordinary_local),
         "explicit-new-per-user-python-target")
    need(log.parent == path(operation_root), "explicit-new-private-python-log")
    # CPython v3.13.15 Doc/using/windows.rst lines129-141 documents /log and
    # TargetDir; the first six arguments are already the repository's exact pin.
    return [*PYTHON_FLAGS, "/log", log_path, "TargetDir=" + target_dir]


def common_request(context, operation_id, operation_root, file_pins, directory_pins,
                   tree_pins, raw_stream_limit=16 * 1024 * 1024, python_runtime=None):
    request = {"schemaVersion": 1, "context": context, "operationId": operation_id,
               "operationRoot": operation_root, "filePins": file_pins,
               "directoryPins": directory_pins, "treePins": tree_pins,
               "rawStreamLimitBytes": raw_stream_limit}
    if python_runtime is not None:
        request["pythonRuntime"] = python_runtime
    validate_closure(request)
    return request


def worker_request(common, action, **inputs):
    need(type(common) is dict and set(common) in (COMMON_FIELDS, COMMON_FIELDS | {"pythonRuntime"}),
         "common-request-fields")
    request = dict(common)
    files = validate_closure(request)
    validate_python_runtime(request)
    if action == "qualification":
        need(set(inputs) == {"qualificationArgv", "expectedExitCode"}, "qualification-input-schema")
        need(type(inputs["qualificationArgv"]) is list and 1 <= len(inputs["qualificationArgv"]) <= 128
             and all(type(arg) is str and "\0" not in arg for arg in inputs["qualificationArgv"])
             and path(inputs["qualificationArgv"][0]) in files,
             "qualification-executable-and-argv-pins")
        need(type(inputs["expectedExitCode"]) is int and 0 <= inputs["expectedExitCode"] <= 255,
             "qualification-expected-exit")
    elif action in POSTBOOT_ACTION_PHASES:
        need(set(inputs) == {"cliPath", "workspace", "productVersion", "postbootAcceptance"},
             "postboot-worker-input-schema")
        config = inputs["postbootAcceptance"]
        need(type(config) is dict and config.get("phase") == POSTBOOT_ACTION_PHASES[action],
             "same-fixed-postboot-action-phase")
        extra = set() if action == "windows-preboot-reboot" else {"checkpointPath"}
        need(set(config) == {"schemaVersion", "phase", "scenario", "sourceRoles", "autostartInputs",
             "trafficInputPath"} | extra
             and type(config["schemaVersion"]) is int and config["schemaVersion"] == 1
             and config["scenario"] in POSTBOOT_SCENARIOS[action]
             and all(value is not None for value in config.values()), "closed-postboot-config-schema")
        roles = config["sourceRoles"]
        need(type(roles) is dict and set(roles) == POSTBOOT_ROLES,
             "closed-postboot-source-role-map")
        role_paths = {role: path(value) for role, value in roles.items()}
        need(len(set(role_paths.values())) == len(role_paths)
             and set(role_paths.values()) <= files and path(inputs["cliPath"]) in files,
             "all-distinct-postboot-role-and-cli-native-pins")
        # The package has no loose runtime: its runtime digest is the installed record beside the GUI.
        need(role_paths["runtimeAuthority"] == role_paths["gui"].parent.joinpath(*POSTBOOT_RUNTIME_AUTHORITY),
             "installed-runtime-authority-beside-gui")
        pins = {path(pin["path"]): pin for pin in request["filePins"]}
        for role, expected in POSTBOOT_ROLE_HASHES.items():
            need(pins[role_paths[role]]["sha256"] == expected, "frozen-postboot-role-" + role)
        auto = config["autostartInputs"]
        need(type(auto) is dict and set(auto) == {"schemaVersion", "snapshotScriptPath",
             "powerShellPath", "migrationScriptPath", "startScriptPath", "guiPath", "workspace"}
             and type(auto["schemaVersion"]) is int and auto["schemaVersion"] == 1,
             "frozen-autostart-input-schema")
        for key, role in (("snapshotScriptPath", "snapshotScript"), ("powerShellPath", "powerShell"),
                          ("migrationScriptPath", "migrationScript"), ("startScriptPath", "startScript"),
                          ("guiPath", "gui")):
            need(path(auto[key]) == role_paths[role], "same-autostart-source-role")
        # No reboot command is a role: readiness-reboot is the only reboot submitter.
        need(roles["powerShell"] == PS, "fixed-existing-os-command-roles")
        need(path(config["trafficInputPath"]) in files, "postboot-traffic-initial-data-pin")
        workspace = path(inputs["workspace"])
        need(workspace == path(auto["workspace"]), "same-original-postboot-workspace")
        directories = {path(pin["path"]) for pin in request["directoryPins"]}
        if action == "windows-preboot-reboot":
            need(workspace.parent == path(request["operationRoot"]) and workspace not in directories,
                 "fresh-private-preboot-workspace")
        else:
            need(workspace.is_relative_to(path(request["context"]["localAppData"]))
                 and workspace != path(request["context"]["localAppData"])
                 and not workspace.is_relative_to(path(request["operationRoot"]))
                 and workspace in directories and set(workspace.parents) <= directories,
                 "initial-pinned-persistent-postboot-workspace")
            need(path(config["checkpointPath"]) in files, "original-preboot-checkpoint-native-pin")
        need(type(inputs["productVersion"]) is str
             and re.fullmatch(r"(?:[1-9]|1[0-9])\.(?:[0-9]|1[0-9])\.(?:[0-9]|1[0-9])",
                              inputs["productVersion"]) and inputs["productVersion"] != "2.2.13",
             "postboot-current-product-version")
    elif action in {"msi-install", "msi-reset"}:
        reset = {"uninstallProductCode", "uninstallLogPath", "uninstallRoot"} if action == "msi-reset" else set()
        need(set(inputs) == {"msiPath", "installerLogPath"} | reset, "msi-worker-input-schema")
        need(path(inputs["msiPath"]) in files and path(MSIEXEC) in files, "msi-and-native-installer-pins")
        logs = [path(inputs[name]) for name in ("installerLogPath", "uninstallLogPath") if name in inputs]
        need(all(log.parent == path(request["operationRoot"]) for log in logs) and len(set(logs)) == len(logs),
             "private-msi-log-parent")
        if reset:
            # Setup only: the exact registered product code, never a package path or a pattern.
            need(type(inputs["uninstallProductCode"]) is str and re.fullmatch(
                r"\{[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}\}", inputs["uninstallProductCode"]),
                "msi-reset-product-code")
            # The per-user install folder the removal must leave without files; it is only read.
            folder, local = path(inputs["uninstallRoot"]), path(request["context"]["localAppData"])
            operation_root = path(request["operationRoot"])
            need(folder.is_relative_to(local) and folder != local and not folder.is_relative_to(operation_root)
                 and not operation_root.is_relative_to(folder), "msi-reset-install-root")
    else:
        need(action in {"baseline-source-mode", "fixed-source-mode", "disconnected-cli-config",
                        "streaming-client-interrupt", "document-acceptance", *DEDICATED_CASES}, "worker-action")
        fields = {"cliPath", "workspace", "productVersion", "casesPath", "harnessPath"}
        if action == "document-acceptance":
            fields.add("documentAcceptance")
            if "responsiveWork" in inputs:
                fields.add("responsiveWork")
        need(set(inputs) == fields,
             "cli-worker-input-schema")
        need(all(path(inputs[name]) in files for name in ("cliPath", "casesPath", "harnessPath")),
             "full-cli-and-assertion-source-pins")
        need(path(inputs["workspace"]).parent == path(request["operationRoot"]), "private-workspace")
        need(type(inputs["productVersion"]) is str
             and re.fullmatch(r"(?:[1-9]|1[0-9])\.(?:[0-9]|1[0-9])\.(?:[0-9]|1[0-9])",
                              inputs["productVersion"]), "product-version")
        if action == "baseline-source-mode":
            need(inputs["productVersion"] == "2.2.13", "baseline-artifact-version")
        if action in {"disconnected-cli-config", "streaming-client-interrupt", "document-acceptance", *DEDICATED_CASES}:
            need(inputs["productVersion"] != "2.2.13", "expanded-cases-forbidden-on-baseline")
        if action in DEDICATED_CASES:
            owner_sha = source_inventory()["agent_tools/windows_ordinary_process_owner.py"]["sha256"]
            workers = [pin for pin in request["filePins"]
                       if pin["sha256"] == owner_sha and path(pin["path"]).name == "windows_ordinary_process_owner.py"]
            need(len(workers) == 1, "dedicated-current-ordinary-owner-source")
            source_root = path(workers[0]["path"]).parent
            case_name, case_sha = DEDICATED_CASES[action]
            case = next(pin for pin in request["filePins"] if path(pin["path"]) == path(inputs["casesPath"]))
            driver = [pin for pin in request["filePins"]
                      if path(pin["path"]) == source_root / "windows_ordinary_dedicated_driver.py"]
            need(path(inputs["casesPath"]) == source_root / case_name and case["sha256"] == case_sha
                 and len(driver) == 1 and driver[0]["sha256"] == DEDICATED_DRIVER_SHA,
                 "dedicated-fixed-reviewed-source-roles")
        if action == "document-acceptance":
            document = inputs["documentAcceptance"]
            need(type(document) is dict and set(document) == {"schemaVersion", "clientPath",
                 "windowsPath", "racePath", "largeRoutingInputPath", "spoolTempParent",
                 "contexts", "endpointPinBeforeObservation"}, "document-finite-input-schema")
            need(type(document["schemaVersion"]) is int and document["schemaVersion"] == 1
                 and document["endpointPinBeforeObservation"] is None,
                 "document-endpoint-observation-required")
            contexts = document["contexts"]
            need(type(contexts) is list and len(contexts) == 52
                 and all(type(value) is str for value in contexts) and len(set(contexts)) == 52,
                 "document-reserved-context-schema")
            need(all(str(uuid.UUID(value)) == value for value in contexts)
                 and request["operationId"] not in contexts, "document-reserved-canonical-contexts")
            sources = [path(inputs["casesPath"]), *(path(document[key]) for key in
                       ("clientPath", "windowsPath", "racePath"))]
            need(len(set(sources)) == 4 and set(sources) <= files,
                 "document-distinct-held-module-pins")
            large = path(document["largeRoutingInputPath"])
            need(large in files and large not in sources, "document-large-input-pin")
            size = next(item["nativeIdentity"]["sizeBytes"] for item in request["filePins"]
                        if path(item["path"]) == large)
            need(10 * 1024 * 1024 < size <= 64 * 1024 * 1024, "document-large-input-size")
            temp = path(document["spoolTempParent"])
            need(temp.parent == path(request["operationRoot"])
                 and temp != path(inputs["workspace"])
                 and temp in {path(item["path"]) for item in request["directoryPins"]},
                 "document-dedicated-temp-directory-pin")
            if "responsiveWork" not in inputs:
                case = path(inputs["casesPath"])
                case_pin = next(pin for pin in request["filePins"] if path(pin["path"]) == case)
                need(case.name != DOCUMENT_RESPONSIVE_CASE[0]
                     and case_pin["sha256"] != DOCUMENT_RESPONSIVE_CASE[1],
                     "responsive-cases-require-responsive-work")
            if "responsiveWork" in inputs:
                work = inputs["responsiveWork"]
                need(type(work) is dict and set(work) == DOCUMENT_RESPONSIVE_FIELDS
                     and type(work["schemaVersion"]) is int and work["schemaVersion"] == 1,
                     "responsive-finite-input-schema")
                work_contexts = work["contexts"]
                need(type(work_contexts) is list and len(work_contexts) == 2
                     and all(type(value) is str for value in work_contexts)
                     and len(set(work_contexts)) == 2
                     and all(str(uuid.UUID(value)) == value for value in work_contexts)
                     and not set(work_contexts).intersection(contexts)
                     and request["operationId"] not in work_contexts,
                     "responsive-disjoint-canonical-contexts")
                work_paths = {key: path(work[key]) for key in DOCUMENT_RESPONSIVE_FIELDS
                              - {"schemaVersion", "contexts"}}
                other = {*sources, path(inputs["cliPath"]), path(inputs["harnessPath"])}
                need(len(other) == 6 and len(set(work_paths.values())) == 9
                     and set(work_paths.values()) <= files
                     and not set(work_paths.values()).intersection(other),
                     "responsive-distinct-held-role-paths")
                need(work_paths["largeRoutingInputPath"] == large,
                     "responsive-same-document-large-input")
                pins = {path(pin["path"]): pin for pin in request["filePins"]}
                case = path(inputs["casesPath"])
                need(case.name == DOCUMENT_RESPONSIVE_CASE[0]
                     and pins[case]["sha256"] == DOCUMENT_RESPONSIVE_CASE[1],
                     "responsive-fixed-document-cases-source")
                for key, (name, digest) in DOCUMENT_RESPONSIVE_SOURCES.items():
                    source = work_paths[key]
                    need(source.name == name and pins[source]["sha256"] == digest,
                         "responsive-fixed-producer-source-" + key)
                distinct = {*work_paths.values(), *sources,
                            path(inputs["cliPath"]), path(inputs["harnessPath"])}
                identities = [(pins[value]["nativeIdentity"]["volumeSerial"],
                               pins[value]["nativeIdentity"]["fileIndex"]) for value in distinct]
                need(len(set(identities)) == len(distinct), "responsive-native-role-alias")
    request.update(action=action, **inputs)
    data(request)
    return request


def bootstrap_request(common, mode, **inputs):
    need(type(common) is dict and set(common) in (COMMON_FIELDS, COMMON_FIELDS | {"pythonRuntime"}),
         "common-request-fields")
    request = dict(common)
    files = validate_closure(request)
    if mode == "qualification":
        need(set(inputs) == {"qualificationSourcePath", "qualificationArguments"}
             and path(inputs["qualificationSourcePath"]) in files and path(PS) in files,
             "PS51-qualification-source-and-engine-pins")
        need(type(inputs["qualificationArguments"]) is list
             and len(inputs["qualificationArguments"]) <= 64
             and all(type(arg) is str and "\0" not in arg for arg in inputs["qualificationArguments"]),
             "qualification-argument-schema")
        executable = PS
        argv = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                inputs["qualificationSourcePath"], *inputs["qualificationArguments"]]
    elif mode == "python-install":
        required = {"pythonInstallerPath", "pythonTargetDir", "pythonLogPath",
                    "pythonInstallerSignerCertificateSha256"}
        need(set(inputs) == required and path(inputs["pythonInstallerPath"]) in files,
             "python-installer-input-schema")
        pin = next(item for item in request["filePins"] if item["path"] == inputs["pythonInstallerPath"])
        need(pin["sha256"] == PYTHON_INSTALLER_SHA256
             and pin["nativeIdentity"]["sizeBytes"] == PYTHON_INSTALLER_BYTES, "exact-python-installer")
        need(re.fullmatch(r"[0-9a-f]{64}", inputs["pythonInstallerSignerCertificateSha256"]),
             "actual-PSF-signer-certificate-required")
        argv = python_installer_arguments(inputs["pythonTargetDir"], inputs["pythonLogPath"],
                                         request["context"]["localAppData"], request["operationRoot"])
        executable = inputs["pythonInstallerPath"]
    else:
        required = {"pythonPath", "workerPath", "workerRequestPath", "workerRequestSha256",
                    "workerRequestPinBase64"}
        need(mode == "python-worker" and set(inputs) == required, "python-worker-input-schema")
        validate_python_runtime(request, inputs["pythonPath"])
        need(all(path(inputs[name]) in files for name in ("pythonPath", "workerPath", "workerRequestPath")),
             "python-worker-input-pins")
        nested_pin = json.loads(base64.b64decode(inputs["workerRequestPinBase64"], validate=True))
        validate_pin(nested_pin)
        need(nested_pin["path"] == inputs["workerRequestPath"]
             and nested_pin["sha256"] == inputs["workerRequestSha256"]
             and nested_pin in request["filePins"], "nested-worker-request-native-binding")
        worker_pin = next(item for item in request["filePins"] if item["path"] == inputs["workerPath"])
        canonical_worker = source_inventory()["agent_tools/windows_ordinary_process_owner.py"]
        need(worker_pin["sha256"] == canonical_worker["sha256"]
             and worker_pin["nativeIdentity"]["sizeBytes"] == canonical_worker["sizeBytes"],
             "canonical-original-worker-source-required")
        executable = inputs["pythonPath"]
        argv = ["-I", "-S", "-B", inputs["workerPath"], "--request", inputs["workerRequestPath"],
                "--request-sha256", inputs["workerRequestSha256"],
                "--request-pin-base64", inputs["workerRequestPinBase64"]]
    line = subprocess.list2cmdline([executable, *argv])
    need(len(line.encode("utf-16le")) // 2 + 1 <= 32767
         and len(data({"path": executable, "arg": argv})) <= 60000, "bootstrap-native-command-bounds")
    request["bootstrap"] = {"mode": mode, **inputs}
    data(request)
    return request


def render_task(request, source_pin, request_pin):
    """Render a new task XML and exact argv; never register/start it.

    First publish the canonical request bytes CreateNew and obtain its ACTUAL
    native identity/security. Then supply that external request_pin here. Request
    pins are external to their own bytes, avoiding a self-referential checksum.
    """
    files = validate_closure(request)
    need(set(request) in (COMMON_FIELDS | {"bootstrap"},
                         COMMON_FIELDS | {"pythonRuntime", "bootstrap"})
         and type(request["bootstrap"]) is dict, "task-bootstrap-request-schema")
    validate_pin(source_pin)
    validate_pin(request_pin)
    need(path(source_pin["path"]) in files and source_pin in request["filePins"],
         "whole-powershell-source-pin")
    sources = source_inventory()
    canonical_ps = sources["agent_tools/windows_ordinary_task_owner.ps1"]
    need(source_pin["sha256"] == canonical_ps["sha256"]
         and source_pin["nativeIdentity"]["sizeBytes"] == canonical_ps["sizeBytes"],
         "canonical-original-powershell-source-required")
    request_bytes = data(request)
    need(hashlib.sha256(request_bytes).hexdigest() == request_pin["sha256"]
         and len(request_bytes) == request_pin["nativeIdentity"]["sizeBytes"],
         "published-request-bytes-pin")
    need(path(request_pin["path"]).parent == path(request["operationRoot"]),
         "private-request-root")
    encoded_pin = base64.b64encode(data(request_pin)).decode("ascii")
    argv = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
            source_pin["path"], "-RequestPath", request_pin["path"], "-RequestSha256",
            request_pin["sha256"], "-RequestPinBase64", encoded_pin]
    line = subprocess.list2cmdline([PS, *argv])
    command_units = len(line.encode("utf-16le")) // 2 + 1
    need(command_units <= 32767, "task-command-utf16-bound")
    wire = data({"path": PS, "arg": argv, "capture-output": True})
    need(len(wire) <= 60000, "task-command-json-bound")
    ET.register_namespace("", NS)
    element = lambda tag, **kwargs: ET.Element(f"{{{NS}}}{tag}", kwargs)
    task = element("Task", version="1.4")
    principals = ET.SubElement(task, f"{{{NS}}}Principals")
    principal = ET.SubElement(principals, f"{{{NS}}}Principal", {"id": "OrdinaryUser"})
    for name, value in (("UserId", request["context"]["ordinarySid"]),
                        ("LogonType", "InteractiveToken"), ("RunLevel", "LeastPrivilege")):
        ET.SubElement(principal, f"{{{NS}}}{name}").text = value
    settings = ET.SubElement(task, f"{{{NS}}}Settings")
    for name, value in (("MultipleInstancesPolicy", "IgnoreNew"),
                        ("DisallowStartIfOnBatteries", "false"),
                        ("StopIfGoingOnBatteries", "false"), ("AllowHardTerminate", "false"),
                        ("StartWhenAvailable", "false"), ("RunOnlyIfNetworkAvailable", "false"),
                        ("Enabled", "true"), ("Hidden", "false"),
                        ("ExecutionTimeLimit", "PT0S"), ("WakeToRun", "false")):
        ET.SubElement(settings, f"{{{NS}}}{name}").text = value
    actions = ET.SubElement(task, f"{{{NS}}}Actions", {"Context": "OrdinaryUser"})
    action = ET.SubElement(actions, f"{{{NS}}}Exec")
    for name, value in (("Command", PS), ("Arguments", subprocess.list2cmdline(argv)),
                        ("WorkingDirectory", request["operationRoot"])):
        ET.SubElement(action, f"{{{NS}}}{name}").text = value
    xml_text = ET.tostring(task, encoding="utf-8", xml_declaration=True).decode("utf-8")
    expected_policy = policy_fields(xml_text)
    return {"taskName": "VpnControlOrdinary-" + request["operationId"],
            "xmlUtf8": xml_text, "policyExpected": expected_policy,
            "policyValidatorPowerShell": task_policy_powershell(expected_policy),
            "canonicalSourceFiles": sources,
            "requestSha256": request_pin["sha256"], "sourceSha256": source_pin["sha256"],
            "commandUtf16Units": command_units, "commandJsonBytes": len(wire),
            "argv": [PS, *argv], "nativeActionAllowed": False,
            "remainingAdmission": ["native-PS5.1-parser", "exact-task-XML-COM-policy",
                "current-boot-typed-ABI", "held-source-and-native-file-pins",
                "harmless-direct-complete-owner-scenarios", "matching-current-MCP-scenarios"]}


def _policy_xml(xml_text):
    need(type(xml_text) is str and 0 < len(xml_text.encode("utf-8")) <= 65536
         and "<!DOCTYPE" not in xml_text.upper() and "<!ENTITY" not in xml_text.upper(),
         "task-xml-bound-or-declaration")
    # Windows exported UTF-8 TEXT retains an encoding=UTF-16 declaration. Parse
    # decoded Unicode; never rewrite authentic before bytes or guess their codec.
    tree = ET.fromstring(xml_text)
    need(tree.tag == f"{{{NS}}}Task", "task-xml-root")
    return tree


def policy_fields(xml_text):
    tree = _policy_xml(xml_text)
    result = {}
    for field in POLICY_FIELDS:
        matches = tree.findall(f".//{{{NS}}}{field}")
        need(len(matches) == 1 and matches[0].text is not None, "task-xml-field-" + field)
        result[field] = matches[0].text
    return result


def validate_task_policy(xml_text, native, expected):
    """Validate observed XML plus independently captured typed native facts.

    Pure validation is not a native admission capability. The registered task's
    cmdlet and COM values must be read by the actual sole operator before start;
    request JSON or this return value alone never authorizes registration/start.
    """
    need(type(expected) is dict and set(expected) == set(POLICY_FIELDS), "task-expected-fields")
    need(type(expected["UserId"]) is str
         and re.fullmatch(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+", expected["UserId"])
         and expected["LogonType"] == "InteractiveToken"
         and expected["ExecutionTimeLimit"] == "PT0S"
         and expected["MultipleInstancesPolicy"] == "IgnoreNew"
         and expected["Command"] == PS, "ordinary-task-required-policy")
    need(type(native) is dict and set(native) == {"cmdletSid", "cmdletRunLevel", "cmdletLogonType",
         "comSid", "comRunLevel", "comLogonType"}, "native-principal-schema")
    need(type(native["cmdletSid"]) is str and type(native["comSid"]) is str
         and native["cmdletSid"] == native["comSid"] == expected["UserId"]
         and type(native["cmdletRunLevel"]) is str and native["cmdletRunLevel"] == "Limited"
         and type(native["cmdletLogonType"]) is str and native["cmdletLogonType"] == "Interactive"
         and type(native["comRunLevel"]) is int and native["comRunLevel"] == 0
         and type(native["comLogonType"]) is int and native["comLogonType"] == 3,
         "native-principal-policy")
    tree = _policy_xml(xml_text)
    need(policy_fields(xml_text) == expected, "task-xml-fields-changed")
    levels = tree.findall(f".//{{{NS}}}RunLevel")
    need(len(levels) <= 1 and (not levels or levels[0].text == "LeastPrivilege"),
         "task-xml-runlevel")
    actions = tree.findall(f".//{{{NS}}}Actions")
    need(len(actions) == 1 and len(actions[0]) == 1
         and actions[0][0].tag == f"{{{NS}}}Exec"
         and len(tree.findall(f".//{{{NS}}}Principal")) == 1
         and len(tree.findall(f".//{{{NS}}}Exec")) == 1
         and all(len(element) == 0 for element in tree.findall(f".//{{{NS}}}Triggers")),
         "task-xml-ambiguous-or-triggered")
    return {"xmlRunLevel": "LeastPrivilege" if levels else "omitted-native-limited",
            "typedNativePrincipalMatched": True, "nativeActionAllowed": False}


def _ps_literal(value):
    need(type(value) is str and "\0" not in value, "powershell-data-literal")
    return "'" + value.replace("'", "''") + "'"


def task_policy_powershell(expected):
    """Actual emitted validator consumed by the task plan's pre-start operator.

    This is the native-proven V5 decision generalized to the supplied exact task.
    It reads no task and performs no effect; its parameters are actual native
    cmdlet/COM observations, not caller readiness flags.
    """
    need(type(expected) is dict and set(expected) == set(POLICY_FIELDS), "task-expected-fields")
    fields = ";".join(name + "=" + _ps_literal(expected[name]) for name in POLICY_FIELDS)
    return r'''function Assert-OrdinaryTaskPolicy {
 param([string]$Xml,[string]$CmdletSid,[object]$CmdletRunLevel,[object]$CmdletLogonType,[string]$ComSid,[object]$ComRunLevel,[object]$ComLogonType)
 $fields=[ordered]@{@FIELDS@}
 if($CmdletSid -cne $fields.UserId -or $ComSid -cne $CmdletSid -or $CmdletRunLevel -isnot [string] -or $CmdletRunLevel -cne 'Limited' -or $CmdletLogonType -isnot [string] -or $CmdletLogonType -cne 'Interactive' -or $ComRunLevel -isnot [int] -or $ComRunLevel -ne 0 -or $ComLogonType -isnot [int] -or $ComLogonType -ne 3){throw 'TOKEN_NATIVE_PRINCIPAL_POLICY'}
 if([Text.Encoding]::UTF8.GetByteCount($Xml) -gt 65536 -or $Xml.ToUpperInvariant().Contains('<!DOCTYPE') -or $Xml.ToUpperInvariant().Contains('<!ENTITY')){throw 'TOKEN_XML_DECLARATION_OR_BOUND'}
 $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=65536
 $textReader=[IO.StringReader]::new($Xml);$reader=[Xml.XmlReader]::Create($textReader,$settings)
 try{$policyDoc=[Xml.XmlDocument]::new();$policyDoc.XmlResolver=$null;$policyDoc.Load($reader)}finally{$reader.Dispose();$textReader.Dispose()}
 if($policyDoc.DocumentElement.LocalName -cne 'Task' -or $policyDoc.DocumentElement.NamespaceURI -cne 'http://schemas.microsoft.com/windows/2004/02/mit/task'){throw 'TOKEN_XML_ROOT'}
 $policyNs=[Xml.XmlNamespaceManager]::new($policyDoc.NameTable);$policyNs.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
 foreach($name in $fields.Keys){$nodes=$policyDoc.SelectNodes('//t:'+$name,$policyNs);if($nodes.Count -ne 1 -or $nodes[0].InnerText -cne $fields[$name]){throw ('TOKEN_XML_FIELD_'+$name)}}
 $levels=$policyDoc.SelectNodes('//t:RunLevel',$policyNs);if($levels.Count -gt 1 -or ($levels.Count -eq 1 -and $levels[0].InnerText -cne 'LeastPrivilege')){throw 'TOKEN_XML_RUNLEVEL'}
 $actions=$policyDoc.SelectNodes('//t:Actions',$policyNs)
 if($actions.Count -ne 1 -or $actions[0].ChildNodes.Count -ne 1 -or $actions[0].FirstChild.LocalName -cne 'Exec' -or $actions[0].FirstChild.NamespaceURI -cne 'http://schemas.microsoft.com/windows/2004/02/mit/task' -or $policyDoc.SelectNodes('//t:Principal',$policyNs).Count -ne 1 -or $policyDoc.SelectNodes('//t:Exec',$policyNs).Count -ne 1 -or $policyDoc.SelectNodes('//t:Triggers/*',$policyNs).Count -ne 0){throw 'TOKEN_XML_AMBIGUOUS'}
}
'''.replace("@FIELDS@", fields)


def policy_regression_program(before_source, xml_text, native, mode):
    """Emit finite no-task/no-install causal proof for the original XML failure.

    `before` runs the exact original if-statement on the authentic XML and exits
    nonzero with TOKEN_TASK_XML. `after` runs the actual current emitted validator
    against the same XML/native facts and every native phase's ambiguity control.
    The full preserved before source is data; no historical launcher is replayed.
    """
    need(mode in {"before", "after"}, "policy-regression-mode")
    expected = policy_fields(xml_text)
    needle = "if($doc.SelectSingleNode('//t:UserId'"
    lines = [line for line in before_source.splitlines() if line.startswith(needle)]
    need(len(lines) == 1 and lines[0].endswith("{throw 'TOKEN_TASK_XML'}"), "authentic-before-statement")
    validate_task_policy(xml_text, native, expected)
    prefix = ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';"
              "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
              "$xml=" + _ps_literal(xml_text) + "\n")
    if mode == "before":
        return (prefix + "$output=" + _ps_literal(expected["WorkingDirectory"]) + "\n"
                "[xml]$doc=$xml;$ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);"
                "$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')\n"
                + lines[0] + "\nthrow 'UNEXPECTED_OLD_ACCEPTANCE'\n")
    facts = ("$facts=@{CmdletSid=" + _ps_literal(native["cmdletSid"]) + ";CmdletRunLevel='Limited';"
             "CmdletLogonType='Interactive';ComSid=" + _ps_literal(native["comSid"]) +
             ";ComRunLevel=[int]0;ComLogonType=[int]3}\n")
    controls = r'''$controls=@(
 @{name='original-default-omitted';xml=$xml;accept=$true},
 @{name='explicit-least';xml=$xml.Replace('</LogonType>','</LogonType><RunLevel>LeastPrivilege</RunLevel>');accept=$true},
 @{name='xml-elevated';xml=$xml.Replace('</LogonType>','</LogonType><RunLevel>HighestAvailable</RunLevel>');accept=$false},
 @{name='xml-empty';xml=$xml.Replace('</LogonType>','</LogonType><RunLevel/>');accept=$false},
 @{name='xml-duplicate';xml=$xml.Replace('</LogonType>','</LogonType><RunLevel>LeastPrivilege</RunLevel><RunLevel>LeastPrivilege</RunLevel>');accept=$false},
 @{name='native-com-elevated';changes=@{ComRunLevel=[int]1};accept=$false},
 @{name='native-cmdlet-elevated';changes=@{CmdletRunLevel='Highest'};accept=$false},
 @{name='native-com-null';changes=@{ComRunLevel=$null};accept=$false},
 @{name='native-com-ambiguous-string';changes=@{ComRunLevel='0'};accept=$false},
 @{name='native-logon-wrong';changes=@{ComLogonType=[int]2};accept=$false},
 @{name='xml-user-wrong';xml=$xml.Replace(@SID@,'S-1-5-18');accept=$false},
 @{name='xml-auto-kill';xml=$xml.Replace('PT0S','PT1M');accept=$false},
 @{name='xml-trigger';xml=$xml.Replace('<Triggers />','<Triggers><BootTrigger/></Triggers>');accept=$false},
 @{name='xml-extra-action';xml=$xml.Replace('</Actions>','<ComHandler><ClassId>{11111111-2222-4333-8444-555555555555}</ClassId></ComHandler></Actions>');accept=$false}
)
$observed=@()
foreach($control in $controls){
 $args=$facts.Clone();$args.Xml=$xml;if($control.ContainsKey('xml')){$args.Xml=$control.xml}
 if($control.ContainsKey('changes')){foreach($key in $control.changes.Keys){$args[$key]=$control.changes[$key]}}
 $accepted=$true;$reason=$null;try{Assert-OrdinaryTaskPolicy @args}catch{$accepted=$false;$reason=$_.Exception.Message}
 if($accepted -ne $control.accept){throw ('POLICY_CONTROL_'+$control.name)}
 $observed+=,@{name=$control.name;expected=$control.accept;accepted=$accepted;reason=$reason}
}
[Console]::Out.WriteLine((@{schemaVersion=1;phase='ordinary-task-policy-causal';fixedValidator='GREEN';controls=$observed;productOperation=$false;nativeActionAllowed=$false}|ConvertTo-Json -Depth 8 -Compress))
'''.replace("@SID@", _ps_literal(expected["UserId"]))
    return prefix + task_policy_powershell(expected) + facts + controls
