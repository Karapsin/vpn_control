"""Private registration of one owned raw Windows fixture after direct native proof.

There is no MCP or CLI endpoint and no public input. A descriptor is immutable: a
source change needs a new alias, and old aliases and their pins are never rewritten.
Pins are enforced. A qualification's evidence map is a record the writer does not
check, so running that evidence on those pins is the operator's duty (TEST-002).
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from uuid import UUID

from . import readiness
from . import readiness_fixture_registry as registry
from . import readiness_windows as windows
from . import readiness_windows_login as login
from . import ssh_transport as transport
from .private_credential_file import SecretFile

CAPABILITIES = frozenset({"resume", "transport", "wake_display", "reboot", "login"})
_EVIDENCE_KEY = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}\Z")
_EVIDENCE_VALUE = re.compile(r"[A-Za-z0-9_.:/-]{1,256}\Z")


# Reviewed regions of a fixed-image Windows sign-in screen at 1280x800. The account's
# name and password box identify the screen. The default avatar is the same for every
# account and rerenders one level differently across boots, so it is never a crop.
LOCK_REGIONS = ([30, 250, 250, 500], [1000, 250, 1200, 500])
FIELD_REGIONS = ([565, 384, 636, 412], [660, 384, 716, 412], [504, 446, 786, 478])


def reviewed_profile(lock_frame, field_frame):
    """One public screen pair from two reviewed frames; a secret never enters it."""
    def crops(raw, regions):
        width, height, pixels = login.ppm(raw)
        return {"width": width, "height": height, "crops": [
            {"rect": list(rect), "sha256": hashlib.sha256(b"".join(
                pixels[(y * width + rect[0]) * 3:(y * width + rect[2]) * 3] for y in range(rect[1], rect[3]))).hexdigest()}
            for rect in regions]}
    return login.validate_profile({"lockscreen": crops(lock_frame, LOCK_REGIONS), "password": crops(field_frame, FIELD_REGIONS)})


# Fixed modes that type nothing. Everything else stays with the protected owner.
_LOGIN_ENROLLMENT_MODES = frozenset({"login-probe", "login-lock-fixture", "login-field-capture", "login-original-screens", "login-screen-pin"})


def login_enrollment_packet(root, binding, mode, operation, *, expected_sid, expected=None, original=None, frame=0, timeout=95, limit=6 * 1024 * 1024):
    """One fixed enrollment packet: lock, pin the lock image, capture or read back screens."""
    if mode not in _LOGIN_ENROLLMENT_MODES:
        raise ValueError("windows_registration_login_mode_invalid")
    source = login.program(binding, mode, operation, expected_sid=expected_sid, expected=expected, original_operation=original, original_frame=frame)
    host = binding["spec"]["host"]
    with transport.admitted_transport(Path(root), host, operation, deadline=time.monotonic() + timeout + 60,
                                      requirements=readiness.Requirements(frozenset({"transport"}), frozenset({"reconnect"}))) as admission:
        admission.revalidate()
        argv = transport.build_ssh_argv(transport.load_config(Path(root)), host, command=[
            "python3", "-I", "-B", "-c", "import base64;exec(base64.b64decode(" + repr(base64.b64encode(source).decode()) + "))"])
        result = transport.run_ssh(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode or result.stderr or len(result.stdout) > limit:
        raise ValueError("windows_registration_login_packet_failed")
    return json.loads(result.stdout)


def _need(value, reason):
    if not value:
        raise registry.FixtureRegistryError(reason)


def _machine(value):
    _need(type(value) is str and str(UUID(value)) == value, "windows_registration_machine_invalid")
    return value


def original_binding(root, machine):
    """The binding of the original start intent; nothing here is caller supplied."""
    root = Path(root).resolve(strict=True); _machine(machine)
    path = root / ".rag_index/windows-vm-deploy-intents" / (machine + ".intent.json")
    value, pin = registry._json(path)
    _need(set(value) == {"spec", "setup", "context", "correlationId", "mode", "callerSha256"} and value["mode"] == "start"
          and value["spec"].get("deploymentId") == machine, "windows_registration_intent_invalid")
    binding = {"provider": "raw-qemu-windows", "spec": value["spec"], "setup": value["setup"], "context": value["context"],
               "uri": None, "domain": None, "xmlSha256": None}
    return binding, str(path), pin


def write_qualification(root, machine, capability, *, evidence, profiles=None):
    """Retain one capability's native evidence, bound to the sources it ran under.

    Evidence is a small map of public operation identities and receipt paths. Sign-in
    also carries its reviewed public screen profiles; a secret never enters this file.
    """
    root = Path(root).resolve(strict=True); _machine(machine)
    _need(capability in CAPABILITIES, "windows_registration_capability_invalid")
    _need(type(evidence) is dict and evidence and len(evidence) <= 64
          and all(type(k) is str and _EVIDENCE_KEY.fullmatch(k) and type(v) is str and _EVIDENCE_VALUE.fullmatch(v)
                  for k, v in evidence.items()), "windows_registration_evidence_invalid")
    body = {"schemaVersion": 1, "provider": "raw-qemu-windows", "machine": machine, "capability": capability,
            "qualified": True, "sourcePins": windows._source_pins(), "evidence": evidence}
    if capability == "login":
        _need(type(profiles) is dict and profiles and set(profiles) <= {"locked", "signed_out"}, "windows_registration_profile_invalid")
        for profile in profiles.values():
            login.validate_profile(profile)
        body["profiles"] = profiles
    else:
        _need(profiles is None, "windows_registration_profile_invalid")
    parent = root / ".runtime/readiness-windows-qualifications" / machine
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = parent / (capability + "-" + next(iter(evidence.values())).replace("/", "_").replace(":", "_")[-64:] + ".json")
    windows._save(path, body)
    return {"path": str(path), "pin": registry._json(path)[1]}


def register(root, fixture_id, machine, expected_sid, *, lease_root_generation=None, credential_file=None, qualifications=None):
    """Publish one immutable alias; the actual fixture is observed separately."""
    root = Path(root).resolve(strict=True); registry._id(fixture_id); _machine(machine)
    binding, intent_path, intent_pin = original_binding(root, machine)
    _need(type(expected_sid) is str and re.fullmatch("S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+", expected_sid) is not None, "windows_registration_account_invalid")
    qualifications = {} if qualifications is None else qualifications
    _need(type(qualifications) is dict and set(qualifications) <= CAPABILITIES, "windows_registration_capability_invalid")
    sources = windows._source_pins()
    # Every proof is checked before the immutable alias name is consumed.
    for name, proof in qualifications.items():
        _need(type(proof) is dict and set(proof) == {"path", "pin"}, "windows_registration_proof_invalid")
        body, pin = registry._json(registry._under(proof["path"], root / ".runtime"))
        _need(pin == proof["pin"] and body.get("machine") == machine and body.get("capability") == name and body.get("qualified") is True
              and body.get("sourcePins") == sources, "windows_registration_proof_invalid")
    credential = None
    if credential_file is not None:
        registry._under(credential_file, root / ".runtime")
        with SecretFile(str(credential_file)) as secret:
            credential = {"path": str(secret.path), "generation": list(secret.pin)}
            secret.guard()
    descriptor = {"schemaVersion": 1, "fixtureId": fixture_id, "provider": "raw-qemu-windows", "binding": binding,
                  "expectedSid": expected_sid, "sources": sources, "originalIntent": intent_path,
                  "originalIntentPin": intent_pin, "qualifications": qualifications,
                  "leaseRootGeneration": lease_root_generation, "credential": credential}
    directory = root / ".rag_index/readiness-fixtures"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    windows._save(directory / (fixture_id + ".json"), descriptor)
    return registry.registered_fixture(root, fixture_id)
