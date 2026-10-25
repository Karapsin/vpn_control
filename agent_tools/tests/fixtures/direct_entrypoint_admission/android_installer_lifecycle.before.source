#!/usr/bin/env python3
"""Exercise one Android self-update installer interaction on an admitted AVD."""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from scripts import android_no_update_tls_preflight as tls
from scripts.integration import android_update_fixture as fixture
from agent_tools import android_installer_target as target_admission

EXIT = {"OK": 0, "ACCEPTED": 0, "INTERACTION_REQUIRED": 1,
        "PERMISSION_DENIED": 1, "CANCELLED": 130, "TIMEOUT": 2,
        "OUTCOME_UNKNOWN": 2}


class InvocationFailure(RuntimeError):
    def __init__(self, message, record):
        super().__init__(message)
        self.record = record


def invoke(cli, serial, *words, interactive=False, asynchronous=False, environment=None, timeout_seconds=None):
    argv = [str(cli), "--json", "--android", "--serial", serial]
    if asynchronous:
        argv.append("--async")
    if interactive:
        argv.append("--interactive")
    argv.extend(words)
    try:
        done = subprocess.run(argv, text=True, capture_output=True, env=environment, timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        def text(value): return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
        raise InvocationFailure("CLI invocation timed out", {"argv": argv, "exit": None,
            "stdout": text(error.stdout), "stderr": text(error.stderr), "timeoutSeconds": timeout_seconds}) from error
    try:
        body = json.loads(done.stdout)
    except json.JSONDecodeError as error:
        raise InvocationFailure("CLI did not return JSON", {"argv": argv, "exit": done.returncode,
            "stdout": done.stdout, "stderr": done.stderr}) from error
    return {"argv": argv, "exit": done.returncode, "response": body, "stdout": done.stdout, "stderr": done.stderr}


def final(record, expected):
    if (record["exit"] != EXIT[expected] or record["response"].get("code") != expected
            or record["response"].get("final") is not True):
        raise RuntimeError("installer terminal result rejected")


def correlated_terminal(record, operation, expected):
    response = record["response"]
    if response.get("operationId") != operation:
        raise RuntimeError("terminal operation correlation changed")
    if expected == "installed":
        if (record["exit"] != EXIT["OK"] or response.get("ok") is not True or response.get("code") != "OK"
                or response.get("final") is not True
                or (response.get("data") or {}).get("installPhase") != "installed"
                or (response.get("data") or {}).get("installed") is not True):
            raise RuntimeError("expected confirmed installed terminal")
    elif expected == "cancelled":
        if (record["exit"] != EXIT["CANCELLED"] or response.get("ok") is not False or response.get("code") != "CANCELLED"
                or response.get("final") is not True
                or (response.get("data") or {}).get("installPhase") != "cancelled"
                or (response.get("data") or {}).get("installed") is not False):
            raise RuntimeError("expected confirmed cancelled terminal")
    else:
        raise ValueError("terminal expectation must be installed or cancelled")


def handoff_identity(record, operation, target_version, target_sha256, controller_id=None):
    response = record["response"]
    data = response.get("data") or {}
    if (record["exit"] != EXIT["OK"] or response.get("ok") is not True or response.get("code") != "OK"
            or response.get("final") is not True or response.get("operationId") != operation
            or data.get("installerStarted") is not True or data.get("installed") is not None
            or data.get("installPhase") != "handed_off" or data.get("availableVersion") != target_version
            or not isinstance(data.get("installReceiptId"), str) or not data["installReceiptId"]
            or not valid_session_id(data.get("installSessionId"))
            or controller_id is not None and response.get("controllerId") != controller_id):
        raise RuntimeError("expected immutable historical installer handoff")
    return {"operationId": operation, "receiptId": data["installReceiptId"],
            "sessionId": data["installSessionId"], "version": target_version,
            "targetSha256": target_sha256, "controllerId": response.get("controllerId")}


def terminal_identity(record, operation, expected, target_version, target_sha256):
    correlated_terminal(record, operation, expected)
    data = record["response"].get("data") or {}
    if (data.get("availableVersion") != target_version or not isinstance(data.get("installReceiptId"), str)
            or not data["installReceiptId"] or not valid_session_id(data.get("installSessionId"))):
        raise RuntimeError("expected exact terminal installer identity")
    return {"operationId": operation, "receiptId": data["installReceiptId"],
            "sessionId": data["installSessionId"], "version": target_version,
            "targetSha256": target_sha256}


def reconciled_terminal(record, identity, expected):
    response = record["response"]
    data = response.get("data") or {}
    current = data.get("installReceipt")
    if (record["exit"] != EXIT["OK"] or response.get("ok") is not True or response.get("code") != "OK"
            or response.get("final") is not True
            or not isinstance(current, dict) or current.get("installReceiptId") != identity["receiptId"]
            or not valid_session_id(current.get("installSessionId"))
            or current.get("installSessionId") != identity["sessionId"]):
        return False
    if expected == "installed":
        return current.get("installPhase") == "installed" and current.get("installed") is True
    if expected == "cancelled":
        return current.get("installPhase") == "cancelled" and current.get("installed") is False
    raise ValueError("terminal expectation must be installed or cancelled")


def valid_session_id(value):
    return isinstance(value, int) and not isinstance(value, bool)


def await_reconciled_terminal(args, identity, expected):
    timeout = getattr(args, "reconciliation_timeout_seconds", 120.0)
    interval = getattr(args, "reconciliation_poll_seconds", 1.0)
    if timeout <= 0 or interval <= 0:
        raise ValueError("reconciliation timeout and poll interval must be positive")
    deadline = time.monotonic() + timeout
    stages = {"identity": identity, "updatesStatus": [], "rawErrors": []}
    environment = getattr(args, "cli_environment", None)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stages["outcome"] = "OUTCOME_UNKNOWN"
            return stages
        try:
            status = invoke(args.cli, args.serial, "updates", "status", environment=environment,
                            timeout_seconds=remaining)
            stages["updatesStatus"].append(status)
            if reconciled_terminal(status, identity, expected):
                stages["terminal"] = status
                return stages
        except InvocationFailure as error:
            stages["rawErrors"].append(error.record)
        except Exception as error:
            stages["rawErrors"].append(str(error))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stages["outcome"] = "OUTCOME_UNKNOWN"
            return stages
        time.sleep(min(interval, remaining))


def verify_installed_target(args, adb):
    package = adb.shell("dumpsys", "package", "com.kardinal.vpncontrol")
    def field(name, value):
        return re.search(rf"(?:^|\s){re.escape(name)}={re.escape(str(value))}(?=\s|$)", package) is not None
    if not field("versionName", args.target_version) or not field("versionCode", args.target_code):
        raise RuntimeError("installed target version/code does not match frozen artifact")
    return tls.require_installed_base_hash(
        adb, adb.shell("pm", "path", "com.kardinal.vpncontrol"), args.target_sha256
    )


def focused_dialog_state(adb):
    windows = adb.shell("dumpsys", "window", "windows")
    return tuple(line.strip() for line in windows.splitlines()
                 if "AndroidControlInteractionActivity" in line or "packageinstaller" in line.lower())


def checkpoint(args, receipt):
    path = args.probe_output
    persist_private_json(path, {"callbackReceipt": receipt}, "action checkpoint")


def persist_private_json(path, value, label):
    if path.exists():
        raise RuntimeError(f"{label} path already exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError(f"{label} was not private/persisted")


def require_private_callback_parent(parent):
    info = parent.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError("continue callback parent must be private owned mode 0700")


def prepare_continue_file(path, parent):
    require_private_callback_parent(parent)
    if path.parent != parent or path.exists() or path.is_symlink():
        raise RuntimeError("continue callback path must be a new direct private file")


def wait_for_continue_file(path, parent):
    require_private_callback_parent(parent)
    while not path.exists():
        time.sleep(0.1)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as callback:
        info = os.fstat(callback.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise RuntimeError("continue callback must be a private regular file")
        if callback.read() != "continue\n":
            raise RuntimeError("continue callback content must be literal continue")


def await_callback(args):
    callback = getattr(args, "continue_file", None)
    if callback is None:
        print("Handle the requested OS-dialog case, then press Enter. Do not invoke install again.", flush=True)
        input()
        return
    print("Handle the requested OS-dialog case, then create the private continue callback. Do not invoke install again.", flush=True)
    wait_for_continue_file(callback, args.fixture_parent)
    if getattr(args, "governed_callbacks", False):
        verify_governed_callback(args, "continue")


def verify_governed_callback(args, phase, operation=None):
    """A literal callback alone cannot authorize an installer phase."""
    path = args.output / ("callback-" + phase + "-evidence.json")
    value = json.loads(target_admission._private_file(path, 4096))
    if (value.get("correlationId") != args.intent["correlationId"] or
            value.get("phase") != phase or
            value.get("sourceSha") != args.intent["pair"]["sourceSha"] or
            value.get("targetArtifactId") != args.intent["pair"]["targetArtifactId"] or
            not isinstance(value.get("uiSha256"), str) or
            re.fullmatch(r"[0-9a-f]{64}", value["uiSha256"]) is None or
            not isinstance(value.get("operationId"), str) or not value["operationId"] or
            operation is not None and value["operationId"] != operation or
            not isinstance(value.get("receiptId"), str) or not value["receiptId"] or
            not valid_session_id(value.get("sessionId"))):
        raise RuntimeError("governed installer callback evidence changed")
    snapshot = target_admission._private_file(args.output / ("callback-" + phase + "-ui.xml"), 1_048_576)
    if hashlib.sha256(snapshot).hexdigest() != value["uiSha256"]:
        raise RuntimeError("governed installer UI snapshot changed")
    if phase == "handoff-ready":
        if (value.get("owner") != args.intent["expectedOwner"] or
                value.get("revision") != args.intent["expectedRevision"] or
                value.get("focusedInstaller") not in
                ("com.google.android.packageinstaller", "com.android.packageinstaller")):
            raise RuntimeError("governed installer dialog owner changed")
    else:
        identity = json.loads(target_admission._private_file(args.output / "handoff.json", 1_048_576)).get("identity", {})
        if (value.get("focusedInstaller") is not None or
                identity.get("operationId") != value["operationId"] or
                identity.get("receiptId") != value["receiptId"] or
                identity.get("sessionId") != value["sessionId"]):
            raise RuntimeError("governed installer callback session changed")
    return value


def await_handoff_ready(args, operation=None):
    callback = getattr(args, "handoff_ready_file", None)
    if callback is None:
        if (getattr(args, "expected_terminal", "capture") != "installed"
                or getattr(args, "continue_file", None) is not None):
            return False
        print("Grant Unknown Sources if requested. When the Package Installer update dialog is visible, press Enter before choosing Update or Cancel.", flush=True)
        input()
        return True
    print("Grant Unknown Sources if requested. When the Package Installer update dialog is visible, create the private handoff-ready callback before choosing Update or Cancel.", flush=True)
    wait_for_continue_file(callback, args.fixture_parent)
    if getattr(args, "governed_callbacks", False):
        verify_governed_callback(args, "handoff-ready", operation)
    return True


def await_handoff_identity(args, operation, controller_id):
    timeout = getattr(args, "reconciliation_timeout_seconds", 120.0)
    interval = getattr(args, "reconciliation_poll_seconds", 1.0)
    deadline = time.monotonic() + timeout
    stages = {"operationId": operation, "operationStatus": [], "rawErrors": []}
    environment = getattr(args, "cli_environment", None)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stages["outcome"] = "OUTCOME_UNKNOWN"
            return stages
        try:
            status = invoke(args.cli, args.serial, "operations", "status", operation, environment=environment,
                            timeout_seconds=remaining)
            stages["operationStatus"].append(status)
            identity = handoff_identity(status, operation, args.target_version, args.target_sha256, controller_id)
            stages["identity"] = identity
            return stages
        except InvocationFailure as error:
            stages["rawErrors"].append(error.record)
        except Exception as error:
            stages["rawErrors"].append(str(error))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stages["outcome"] = "OUTCOME_UNKNOWN"
            return stages
        time.sleep(min(interval, remaining))


_REPLY_PHASES = {'check', 'download', 'noninteractive', 'interactive'}
_REPLY_CODES = {'OK','ACCEPTED','INVALID_ARGUMENT','NOT_FOUND','AMBIGUOUS_LOCATION',
    'READ_ONLY_SOURCE','BUSY','CONFLICT','UNSUPPORTED','INTERACTION_REQUIRED',
    'PERMISSION_DENIED','PERSISTENCE_FAILED','RUNTIME_FAILED','TIMEOUT',
    'OUTCOME_UNKNOWN','UNAVAILABLE','INCOMPATIBLE_PROTOCOL','CANCELLED'}
_REPLY_LIMIT = 32768


def reply_binding(args):
    intent = args.intent
    if (not isinstance(intent, dict) or not isinstance(intent.get('correlationId'), str) or
            re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', intent['correlationId']) is None or
            not isinstance(intent.get('pair'), dict) or not isinstance(intent['pair'].get('sourceSha'), str) or
            re.fullmatch(r'[0-9a-f]{40}', intent['pair']['sourceSha']) is None or
            not isinstance(intent['pair'].get('targetArtifactId'), str) or
            re.fullmatch(r'sha256-[0-9a-f]{64}', intent['pair']['targetArtifactId']) is None):
        raise ValueError('Installer CLI evidence binding invalid')
    canonical = json.dumps(intent, sort_keys=True, separators=(',', ':')).encode()
    return {'correlationId': intent['correlationId'], 'sourceSha': intent['pair']['sourceSha'],
        'targetArtifactId': intent['pair']['targetArtifactId'],
        'intentCanonicalSha256': hashlib.sha256(canonical).hexdigest()}


def reply_code(record):
    value = record.get('response', {}).get('code') if isinstance(record.get('response'), dict) else None
    return value if isinstance(value, str) and value in _REPLY_CODES else 'UNRECOGNIZED'


def write_cli_evidence(args, name, value):
    if os.name != 'posix':
        raise ValueError('Installer CLI evidence requires POSIX file APIs')
    parent = Path(args.output)
    before = parent.lstat()
    if not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o700:
        raise ValueError('Installer CLI evidence parent unsafe')
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        opened = os.fstat(directory)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('Installer CLI evidence parent changed')
        data = (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
            info = os.fstat(output.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError('Installer CLI evidence file unsafe')
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        fingerprint = lambda x: (x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_mode,x.st_uid,x.st_nlink)
        current = parent.lstat()
        if fingerprint(named) != fingerprint(info) or (current.st_dev,current.st_ino,current.st_mode,current.st_uid) != (before.st_dev,before.st_ino,before.st_mode,before.st_uid):
            raise ValueError('Installer CLI evidence generation changed')
        os.fsync(directory)
    finally:
        os.close(directory)


def retain_cli_reply(args, name, record):
    if getattr(args, 'intent', None) is None:
        return
    if name not in _REPLY_PHASES:
        raise ValueError('Installer CLI reply phase invalid')
    # Parsed response plus exact original stdout/stderr are private evidence.
    # Oversized replies retain a bounded prefix and full digest, explicitly
    # marked truncated. This never changes the record validated by the guards.
    raw = json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
    value = {'schema': 1, 'kind': 'android-installer-cli-reply',
        'binding': reply_binding(args), 'phase': name, 'code': reply_code(record),
        'record': {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'truncated': len(raw) > _REPLY_LIMIT,
            'base64': base64.b64encode(raw[:_REPLY_LIMIT]).decode()}}
    write_cli_evidence(args, 'cli-' + name + '-reply.json', value)


def retain_cli_failure(args, receipt, name, record, guard):
    if getattr(args, 'intent', None) is None:
        return
    if name not in _REPLY_PHASES or guard not in {'terminal-result','owner-revision','invocation','acceptance','dialog-changed'}:
        raise ValueError('Installer CLI failure classification invalid')
    value = {'schema': 1, 'binding': reply_binding(args), 'phase': name,
             'code': reply_code(record), 'guard': guard}
    write_cli_evidence(args, 'cli-failure.json', value)
    receipt['installerActionFailure'] = value


def invoke_retained(args, receipt, name, *words, **kwargs):
    try:
        value = invoke(args.cli, args.serial, *words, **kwargs)
    except InvocationFailure as error:
        retain_cli_reply(args, name, error.record)
        retain_cli_failure(args, receipt, name, error.record, 'invocation')
        raise
    retain_cli_reply(args, name, value)
    return value


def action(args, adb, receipt):
    if adb.shell_id() != "uid=2000":
        raise RuntimeError("product action requires public UID 2000")
    environment = getattr(args, "cli_environment", None)
    def same_owner(name, record):
        if getattr(args, "intent", None) is not None and (
                record.get("response", {}).get("controllerId") != args.intent["expectedOwner"] or
                record.get("response", {}).get("configurationRevision") != args.intent["expectedRevision"]):
            retain_cli_failure(args, receipt, name, record, 'owner-revision')
            raise RuntimeError("installer public owner changed during session")
    if getattr(args, "intent", None) is not None:
        receipt["installerIntent"] = {"correlationId": args.intent["correlationId"],
            "sourceSha": args.intent["pair"]["sourceSha"],
            "targetArtifactId": args.intent["pair"]["targetArtifactId"],
            "backupSha256": args.intent["backupSha256"]}
        phase(args, "check")
    check = invoke_retained(args, receipt, 'check', "updates", "check", environment=environment)
    try: final(check, "OK")
    except RuntimeError:
        retain_cli_failure(args, receipt, 'check', check, 'terminal-result')
        raise
    same_owner('check', check)
    if getattr(args, "intent", None) is not None: phase(args, "download")
    download = invoke_retained(args, receipt, 'download', "updates", "download", environment=environment)
    try: final(download, "OK")
    except RuntimeError:
        retain_cli_failure(args, receipt, 'download', download, 'terminal-result')
        raise
    same_owner('download', download)
    before_windows = focused_dialog_state(adb)
    if getattr(args, "intent", None) is not None: phase(args, "noninteractive")
    rejected = invoke_retained(args, receipt, 'noninteractive', "updates", "install", environment=environment)
    try: final(rejected, "INTERACTION_REQUIRED")
    except RuntimeError:
        retain_cli_failure(args, receipt, 'noninteractive', rejected, 'terminal-result')
        raise
    same_owner('noninteractive', rejected)
    if focused_dialog_state(adb) != before_windows:
        retain_cli_failure(args, receipt, 'noninteractive', rejected, 'dialog-changed')
        raise RuntimeError("noninteractive install opened a focused OS dialog")
    if getattr(args, "intent", None) is not None: phase(args, "interactive")
    accepted = invoke_retained(args, receipt, 'interactive', "updates", "install", interactive=True,
                      asynchronous=True, environment=environment)
    same_owner('interactive', accepted)
    operation = accepted["response"].get("operationId")
    accepted_controller = accepted["response"].get("controllerId")
    if (accepted["exit"] != 0 or accepted["response"].get("code") != "ACCEPTED"
            or accepted["response"].get("final") is not False
            or not isinstance(operation, str) or not operation
            or not isinstance(accepted_controller, str) or not accepted_controller):
        retain_cli_failure(args, receipt, 'interactive', accepted, 'acceptance')
        raise RuntimeError("interactive install was not accepted once")
    receipt["installerLifecycle"] = {"check": check, "download": download,
        "noninteractiveRejected": rejected, "interactiveAccepted": accepted,
        "operationId": operation, "targetSha256": args.target_sha256,
        "terminalExpectation": getattr(args, "expected_terminal", "capture")}
    checkpoint(args, receipt)
    two_phase = await_handoff_ready(args, operation)
    expected_terminal = getattr(args, "expected_terminal", "capture")
    if two_phase:
        handoff = await_handoff_identity(args, operation, accepted_controller)
        if getattr(args, "governed_callbacks", False):
            callback_identity = verify_governed_callback(args, "handoff-ready", operation)
            identity = handoff.get("identity", {})
            if (identity.get("receiptId") != callback_identity["receiptId"] or
                    identity.get("sessionId") != callback_identity["sessionId"]):
                raise RuntimeError("governed installer handoff session changed")
        receipt["installerLifecycle"]["handoffCapture"] = handoff
        if handoff.get("outcome") == "OUTCOME_UNKNOWN":
            raise RuntimeError("installer handoff outcome unknown")
        persist_private_json(args.probe_output.parent / "handoff.json", {
            "originalOperation": accepted, "identity": handoff["identity"], "handoffCapture": handoff,
            "targetSha256": args.target_sha256, "targetVersion": args.target_version,
            "targetCode": args.target_code}, "installer handoff")
    await_callback(args)
    if two_phase:
        if expected_terminal == "capture":
            receipt["installerLifecycle"]["acceptance"] = "capture-only-nonacceptance"
            return receipt["installerLifecycle"]
        reconciliation = await_reconciled_terminal(args, handoff["identity"], expected_terminal)
        receipt["installerLifecycle"]["originalOperation"] = {"stage": "handed_off",
            "identity": handoff["identity"], "status": handoff["operationStatus"][-1]}
        receipt["installerLifecycle"]["reconciliation"] = reconciliation
        if reconciliation.get("outcome") == "OUTCOME_UNKNOWN":
            raise RuntimeError("installer reconciliation outcome unknown")
        if expected_terminal == "installed":
            receipt["installerLifecycle"]["installedBaseSha256"] = verify_installed_target(args, adb)
        receipt["installerLifecycle"]["acceptance"] = "terminal-confirmed"
        return receipt["installerLifecycle"]
    status = invoke(args.cli, args.serial, "operations", "status", operation, environment=environment)
    waited = invoke(args.cli, args.serial, "--timeout-seconds", "0", "operations", "wait", operation,
                    environment=environment)
    receipt["installerLifecycle"].update({"statusAfterUi": status, "waitOriginalOperation": waited,
                                            "targetSha256": args.target_sha256,
                                            "terminalExpectation": expected_terminal})
    if expected_terminal == "capture":
        receipt["installerLifecycle"]["acceptance"] = "capture-only-nonacceptance"
        return receipt["installerLifecycle"]
    try:
        identity = handoff_identity(status, operation, args.target_version, args.target_sha256, accepted_controller)
    except RuntimeError:
        # A cancellation can win before handoff. It is valid only when the exact
        # original operation already carries the requested terminal result.
        identity = terminal_identity(status, operation, expected_terminal, args.target_version, args.target_sha256)
        if terminal_identity(waited, operation, expected_terminal, args.target_version, args.target_sha256) != identity:
            raise RuntimeError("terminal installer identity changed between status and wait")
        receipt["installerLifecycle"]["originalOperation"] = {"stage": expected_terminal, "identity": identity,
                                                                   "status": status, "wait": waited}
    else:
        if handoff_identity(waited, operation, args.target_version, args.target_sha256, accepted_controller) != identity:
            raise RuntimeError("historical installer handoff identity changed between status and wait")
        receipt["installerLifecycle"]["originalOperation"] = {"stage": "handed_off", "identity": identity,
                                                                   "status": status, "wait": waited}
        reconciliation = await_reconciled_terminal(args, identity, expected_terminal)
        receipt["installerLifecycle"]["reconciliation"] = reconciliation
        if reconciliation.get("outcome") == "OUTCOME_UNKNOWN":
            raise RuntimeError("installer reconciliation outcome unknown")
    if expected_terminal == "installed":
        receipt["installerLifecycle"]["installedBaseSha256"] = verify_installed_target(args, adb)
    receipt["installerLifecycle"]["acceptance"] = "terminal-confirmed"
    return receipt["installerLifecycle"]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("adb", "serial", "api", "avd", "device-port"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--ca-certificate", type=Path, required=True)
    parser.add_argument("--leaf-certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--intent-file", type=Path, required=True,
                        help="exact durable target admission created before guest work")
    parser.add_argument("--continue-file", type=Path)
    parser.add_argument("--handoff-ready-file", type=Path)
    parser.add_argument("--governed-callbacks", action="store_true")
    parser.add_argument("--expected-terminal", choices=("capture", "installed", "cancelled"), default="capture",
                        help="capture records an observation only and is not acceptance evidence")
    parser.add_argument("--reconciliation-timeout-seconds", type=float, default=120.0)
    parser.add_argument("--reconciliation-poll-seconds", type=float, default=1.0)
    for prefix in ("base", "target"):
        parser.add_argument(f"--{prefix}-apk", type=Path, required=True)
        parser.add_argument(f"--{prefix}-sha256", required=True)
        parser.add_argument(f"--{prefix}-version", required=True)
        parser.add_argument(f"--{prefix}-code", required=True)
    return parser.parse_args()


def phase(args, name):
    """Record an immutable may-have-started marker before every public step."""
    if name not in {"check", "download", "noninteractive", "interactive"}:
        raise ValueError("installer phase is not fixed")
    target_admission._write_private(args.output / ("phase-" + name + ".json"),
        {"correlationId": args.intent["correlationId"], "phase": name})


def fixture_start_ticks(pid):
    """Bind the detached HTTPS child to its exact Linux process generation."""
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        ticks = int(value.rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError) as error:
        raise RuntimeError("installer fixture process identity unavailable") from error
    if ticks < 1:
        raise RuntimeError("installer fixture process identity invalid")
    return ticks


def validate_intent(args):
    """Reobserve the exact source, package, owner, backup and idle session."""
    if args.intent_file != args.output / "intent.json":
        raise ValueError("installer intent path is not the task-owned file")
    intent = target_admission.load_intent(args.intent_file)
    pair = intent.get("pair")
    if not isinstance(pair, dict) or any(pair.get(field) != value for field, value in (
            ("baseSha256", args.base_sha256),
            ("baseVersion", args.base_version), ("baseCode", int(args.base_code)),
            ("targetSha256", args.target_sha256),
            ("targetVersion", args.target_version), ("targetCode", int(args.target_code)))):
        raise ValueError("installer driver arguments differ from exact intent")
    if (intent.get("expectedAvd") != args.avd or intent.get("expectedApi") != int(args.api) or
            intent.get("expectedTerminal") != args.expected_terminal):
        raise ValueError("installer device or terminal intent changed")
    opening_bytes = target_admission._private_file(Path(intent["backupPath"]), 67_108_864)
    if (hashlib.sha256(opening_bytes).hexdigest() != intent["backupSha256"] or
            len(opening_bytes) != intent["backupSize"]):
        raise ValueError("installer opening backup bytes changed")
    opening = json.loads(opening_bytes)
    if (not isinstance(opening, dict) or opening.get("type") != "vpn_control_routing_rules" or
            opening.get("version") != 7 or not isinstance(opening.get("rules"), dict)):
        raise ValueError("installer opening backup content changed")
    target_admission.verify_staged_pair(pair, args.base_apk, args.target_apk)
    adb = tls.Adb(args.adb, args.serial)
    if adb.shell_id() != "uid=2000":
        raise ValueError("installer public UID changed")
    baseline = tls.verify_public_baseline(adb, args.cli, args.serial, args.avd, args.api,
                                           args.base_version, args.base_code,
                                           args.base_sha256, args.cli_environment)
    if baseline.get("controllerId") != intent["expectedOwner"]:
        raise ValueError("installer owner changed")
    observed = invoke(args.cli, args.serial, "status", environment=args.cli_environment)
    data = observed.get("response", {}).get("data")
    if (observed.get("exit") != 0 or observed["response"].get("ok") is not True or
            observed["response"].get("final") is not True or
            observed["response"].get("controllerId") != intent["expectedOwner"] or
            observed["response"].get("configurationRevision") != intent["expectedRevision"] or
            not isinstance(data, dict) or data.get("runtimeRunning") is not False or
            data.get("runtimeObservation") != "stopped"):
        raise ValueError("installer owner, revision or runtime changed")
    history = invoke(args.cli, args.serial, "operations", "list", environment=args.cli_environment)
    entries = history.get("response", {}).get("data", {}).get("operations")
    if (history.get("exit") != 0 or history["response"].get("ok") is not True or
            history["response"].get("final") is not True or
            history["response"].get("controllerId") != intent["expectedOwner"] or
            history["response"].get("configurationRevision") != intent["expectedRevision"] or
            not isinstance(entries, list) or any(not isinstance(entry, dict) or
                entry.get("final") is not True for entry in entries)):
        raise ValueError("installer has pending or changed operation history")
    session = invoke(args.cli, args.serial, "updates", "status", environment=args.cli_environment)
    session_data = session.get("response", {}).get("data")
    if (session.get("exit") != 0 or session["response"].get("ok") is not True or
            session["response"].get("final") is not True or
            session["response"].get("controllerId") != intent["expectedOwner"] or
            session["response"].get("configurationRevision") != intent["expectedRevision"] or
            not isinstance(session_data, dict) or session_data.get("phase") != "idle" or
            session_data.get("activeOperationId") is not None or
            session_data.get("installPhase") not in (None, "installed", "cancelled")):
        raise ValueError("installer session is not idle")
    retained = session_data.get("installReceipt")
    if retained is not None and (not isinstance(retained, dict) or
            retained.get("installPhase") not in {"installed", "cancelled"} or
            retained.get("installed") is not (retained.get("installPhase") == "installed") or
            not isinstance(retained.get("installReceiptId"), str) or not retained["installReceiptId"] or
            not valid_session_id(retained.get("installSessionId"))):
        raise ValueError("installer retained session is not terminal")
    return intent


def main():
    args = parse_args()
    args.device_port = int(args.device_port)
    if args.api not in ("29", "35"):
        raise SystemExit("API must be 29/35")
    if (not math.isfinite(args.reconciliation_timeout_seconds) or not math.isfinite(args.reconciliation_poll_seconds)
            or args.reconciliation_timeout_seconds <= 0 or args.reconciliation_poll_seconds <= 0):
        raise SystemExit("reconciliation timeout and poll interval must be finite positive values")
    if os.name != "posix":
        raise SystemExit("Android installer lifecycle requires POSIX private file APIs")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.cli_environment = tls.public_cli_environment(args.adb, args.cli)
    args.intent = validate_intent(args)
    target_admission._write_private(args.output / "run-started.json",
        {"correlationId": args.intent["correlationId"], "state": "may_have_started"})
    if (args.continue_file is not None and args.expected_terminal == "installed" and args.handoff_ready_file is None):
        raise SystemExit("installed callback runs require a distinct handoff-ready callback")
    if args.handoff_ready_file is not None:
        if args.handoff_ready_file == args.continue_file:
            raise SystemExit("handoff-ready callback must be distinct from continue callback")
        prepare_continue_file(args.handoff_ready_file, args.output)
    if args.continue_file is None:
        tls.require_interactive_stdin()
    else:
        prepare_continue_file(args.continue_file, args.output)
    tls.require_artifact_hash(args.base_apk, args.base_sha256)
    tls.require_artifact_hash(args.target_apk, args.target_sha256)
    ready, log, served = args.output / "ready.json", args.output / "fixture.log", args.output / "fixture-receipt.json"
    process = fixture.launch_supervised_fixture(args.target_apk, args.target_version, int(args.target_code),
                                                args.leaf_certificate, args.private_key, ready, log, served)
    fixture_identity = None
    try:
        args.host_port = fixture.read_ready_file(
            ready, fixture.make_manifest(args.target_apk, args.target_version, int(args.target_code)))
        fixture_identity = {
            "correlationId": args.intent["correlationId"], "pid": process.pid,
            "startTicks": fixture_start_ticks(process.pid), "port": args.host_port}
        target_admission._write_private(args.output / "fixture-identity.json", fixture_identity)
        lifecycle = argparse.Namespace(
            adb=args.adb, serial=args.serial, cli=args.cli, certificate=args.ca_certificate,
            leaf_certificate=args.leaf_certificate, fixture_parent=args.output, server_log=log,
            probe_output=args.output / "probe.json", device_port=args.device_port, host_port=args.host_port,
            staging=f"/data/local/tmp/vpn-control-installer-api{args.api}", receipt=args.output / "lifecycle-receipt.json",
            expected_avd=args.avd, expected_api=args.api, expected_version=args.base_version,
            expected_code=args.base_code, base_apk=args.base_apk, base_sha256=args.base_sha256,
            target_sha256=args.target_sha256, continue_file=args.continue_file,
            handoff_ready_file=args.handoff_ready_file,
            governed_callbacks=args.governed_callbacks,
            target_version=args.target_version, target_code=args.target_code,
            expected_terminal=args.expected_terminal,
            intent=args.intent, output=args.output,
            reconciliation_timeout_seconds=args.reconciliation_timeout_seconds,
            reconciliation_poll_seconds=args.reconciliation_poll_seconds,
            cli_environment=args.cli_environment)
        target = "/apex/com.android.conscrypt/cacerts" if args.api == "35" else "/system/etc/security/cacerts"
        tls.run_fixture_lifecycle(lifecycle, action, target_install=True, ca_store_target=target,
                                  expected_proxy="null")
    finally:
        fixture._stop_fixture(process)
        if fixture_identity is not None:
            target_admission._write_private(args.output / "worker-finished.json",
                {**fixture_identity, "state": "fixture_stopped"})


if __name__ == "__main__":
    main()
