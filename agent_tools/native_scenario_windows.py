"""Closed Windows scenario table and the one driver behind ScenarioExecutor.

A scenario is one detached durable job on the VM host (windows_scenario_host_job),
carried by ssh_program_execution_remote over the existing SSH owner. The VM is named
by ``host`` and ``environment``. No request supplies a path, argv, source or bytes:
every byte comes from this checkout and a differing bundle refuses before any journal.
``discover``, ``observe`` and ``collect`` only read; a lost submit reply is resolved
by correlation and the job is never submitted twice.
"""
from __future__ import annotations

import ast
import base64
from contextlib import contextmanager
import gzip
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time
import uuid
from typing import Any, Callable, Mapping

try:
    from . import durable_remote_job, native_artifact_registry, native_artifact_reuse, native_scenario_bundle, native_scenario_execution
    from . import ssh_program_execution_remote as carrier
    from . import ssh_transport
    from . import windows_ordinary_task as planner
    from . import windows_scenario_host_job as host_job
except ImportError:  # pragma: no cover - MCP CLI fallback executes mcp_server.py as a script.
    import durable_remote_job  # type: ignore[no-redef]
    import native_artifact_registry  # type: ignore[no-redef]
    import native_artifact_reuse  # type: ignore[no-redef]
    import native_scenario_bundle  # type: ignore[no-redef]
    import native_scenario_execution  # type: ignore[no-redef]
    import ssh_program_execution_remote as carrier  # type: ignore[no-redef]
    import ssh_transport  # type: ignore[no-redef]
    import windows_ordinary_task as planner  # type: ignore[no-redef]
    import windows_scenario_host_job as host_job  # type: ignore[no-redef]


BUNDLE_SCENARIO_ID = "windows-scenario-driver"
_HOST_JOB_PATH = "agent_tools/windows_scenario_host_job.py"
_DATA_PARENT = ".cache/vpn-control-windows-scenarios"
_ARTIFACT_PARENT = _DATA_PARENT + "/artifacts"
_STAGE_SECONDS = 900  # One package over SSH stdin; a present, matching copy is never sent again.
_LOCAL_STATE = (".rag_index", "native-scenario-windows")
_EVIDENCE_PARENT = (".runtime", "windows-scenarios")
_MAX_REPLY = 2 * 1024 * 1024  # Above native_scenario_ssh's 8,192: terminal replies carry base64 streams.
_EVIDENCE_CHUNK = 1024 * 1024
# One admission covers the whole pull and every chunk is a new SSH connection, so this is what
# 60 s can carry. A row with more evidence needs a deadline scaled to its bytes and a pull that resumes.
_MAX_EVIDENCE = 8 * 1024 * 1024
_SUBMIT_SECONDS = 180
_OBSERVE_SECONDS = 60
_EVIDENCE_NAME = re.compile(r"evidence-[0-9]{1,6}\.zip\Z")
# windows_uac_decision writes exactly these fields in a known input's terminal.
_DECISION_FIELDS = frozenset({"state", "operationId", "attempt", "decision", "prompt", "promptClosed", "approvalSucceeded",
                              "productOutcomeProved", "replayAllowed"})
_BIRTH = re.compile(r"(?:linux:([1-9][0-9]*)|darwin:([0-9]+):([0-9]+))\Z")

_OWNER = ("agent_tools/windows_ordinary_task_owner.ps1", "owner", "powershell")
_WORKER = ("agent_tools/windows_ordinary_process_owner.py", "worker", "data")
_HARNESS = (("scripts/test_packaged_cli.py", "harness", "data"),
            ("scripts/windows_install_admission_diagnostic.py", "diagnostic", "data"))
# "declare" belongs to a reboot preboot alone, "installed" to the installer rows.
_ALL_STAGES = tuple(stage for stage in host_job.STAGE_ORDER if stage != "declare")
_STAGES = tuple(stage for stage in _ALL_STAGES if stage != "installed")


def _worker_row(evidence: str, action: str, keys: tuple[str, ...], files: tuple[tuple[str, str, str], ...], *,
                package: dict[str, str] | None = None, prior: bool = False, msiexec: bool = False, deadline: int) -> dict[str, Any]:
    return {"evidenceClass": evidence, "bootstrapMode": "python-worker", "workerAction": action,
            "artifactKeys": ("bundleManifest", "scenarioInput", *keys), "guestFiles": (_OWNER, _WORKER, *files),
            "package": package, "priorInstall": prior,
            "readPins": (host_job.POWERSHELL_PATH, *((host_job.MSIEXEC_PATH,) if msiexec else ())), "subfolders": (),
            "expectedExit": 0, "expectedStreams": {}, "rawStreamLimitBytes": 16 * 1024 * 1024, "deadlineSeconds": deadline,
            "stages": _ALL_STAGES if package else _STAGES}


_BASE = {"role": "basePackage", "leaf": "package.msi"}
# The reboot actions' fixed sources; their roles are windows_postboot_source_roles.ROLES less the installed ones.
_REBOOT_FILES = (
    ("agent_tools/windows_postboot_source_roles.py", "sourceRoles", "data"),
    ("agent_tools/windows_postboot_action.py", "postbootAction", "data"),
    ("agent_tools/windows_preboot_action.py", "prebootAction", "data"),
    ("agent_tools/windows_autostart_reboot.py", "autostart", "data"),
    ("agent_tools/windows_lifecycle_cases.py", "lifecycle", "data"),
    ("agent_tools/windows_runtime_branch_cases.py", "runtime", "data"),
    ("agent_tools/windows_lifecycle_runtime_stages.py", "runtimeStages", "data"),
    ("scripts/windows_broker_fixture_observer.py", "observer", "data"),
    ("agent_tools/windows_lifecycle_traffic_worker.py", "trafficWorker", "data"),
    ("scripts/integration/socks_http_fixture.py", "upstreamFixture", "data"),
    ("agent_tools/windows_runtime_tcp_listeners.ps1", "listenerScript", "data"),
    ("agent_tools/windows_autostart_snapshot.ps1", "snapshotScript", "data"),
    ("agent_tools/windows_autostart_create_highest_fixture.ps1", "migrationScript", "data"),
    ("agent_tools/windows_autostart_task_start.ps1", "startScript", "data"),
    ("agent_tools/windows_postboot_startup_actors.ps1", "startupCollector", "data"),
)
_REBOOT_STAGES = {"pre": tuple(stage for stage in host_job.STAGE_ORDER if stage != "installed"), "post": _STAGES, "none": _STAGES}


def _reboot_row(name, phase, scenario):
    """One side of a reboot scenario. A preboot leaves the app running from its autostart task and declares it;
    readiness-reboot runs between; the postboot is a new operation naming its preboot through scenarioInput."""
    row = _worker_row("product", "windows-postboot-final" if phase == "post" else "windows-preboot-reboot", ("targetPackage",),
                      _REBOOT_FILES, prior=True, deadline=3600)
    row.update(stages=_REBOOT_STAGES[phase], reboot={"phase": phase, "scenario": scenario,
                                                     "preboot": name + ".pre" if phase == "post" else None})
    return row


# windows-proxy-lifecycle.<variant>: exactly the variants windows_ordinary_dedicated_driver accepts for this action.
PROXY_VARIANTS = ("gui-pending", "find-best-success", "find-best-verification-failure", "find-best-cancel",
                  "generated", "custom", "large", "prepare-failure", "commit-readiness-failure", "sibling-off")
_PROXY_BRANCH_VARIANTS = frozenset({"generated", "custom", "large", "prepare-failure", "commit-readiness-failure", "sibling-off"})
_PROXY_FILES = (("agent_tools/windows_ordinary_dedicated_driver.py", "driver", "data"), ("agent_tools/windows_lifecycle_cases.py", "cases", "data"),
                ("agent_tools/windows_lifecycle_runtime_stages.py", "runtime", "data"), ("scripts/windows_broker_fixture_observer.py", "observer", "data"),
                ("agent_tools/windows_lifecycle_runtime_fixture_worker.py", "fixture", "data"),
                ("scripts/integration/socks_http_fixture.py", "socks", "data"), ("scripts/integration/https_subscription_relay_fixture.py", "https", "data"))
_PROXY_TRAFFIC = (("agent_tools/windows_lifecycle_traffic_worker.py", "traffic", "data"),)
_PROXY_BRANCH = (("agent_tools/windows_runtime_branch_cases.py", "branches", "data"), ("agent_tools/windows_runtime_tcp_listeners.ps1", "listener", "data"))


def _proxy_row(variant: str) -> dict[str, Any]:
    """The driver's roles as published files, and the files the job makes for the literal harness (windows_scenario_proxy)."""
    branch = variant in _PROXY_BRANCH_VARIANTS
    traffic = branch or variant == "gui-pending"
    row = _worker_row("product", "windows-proxy-lifecycle", ("targetPackage",),
                      _PROXY_FILES + (_PROXY_TRAFFIC if traffic else ()) + (_PROXY_BRANCH if branch else ()), prior=True, deadline=3600)
    row.update(proxy={"variant": variant},
               generated=(("harness", "proxy-harness.py"), ("certificate", "proxy-localhost.pem"), ("privateKey", "proxy-localhost.key"),
                          ("trustStore", "proxy-trust.jks"), *((("trafficInput", "proxy-traffic.json"),) if traffic else ())),
               extracted=(("runtimeTool", "sing-box.exe"),))
    return row


# windows-public-update: the dedicated driver, its update module roles and, for a row with a SYSTEM
# collector, the collector's own sources and the caller's close hold. Subfolders keep the siblings
# each module expects: windows_public_updater beside the driver, windows_system_collector beside it too.
_UPDATE_FILES = (("agent_tools/windows_ordinary_dedicated_driver.py", "driver", "data"),
                 ("agent_tools/windows_public_updater/update_cases.py", "cases", "data"),
                 ("agent_tools/windows_public_updater/update_receipts.py", "receipts", "data"),
                 ("agent_tools/windows_public_updater/update_fixture_server.py", "server", "data"),
                 ("agent_tools/windows_public_updater/native_collector.py", "collector", "data"),
                 ("agent_tools/windows_lifecycle_cases.py", "lifecycle", "data"),
                 ("scripts/fixture_environment.py", "fixture_environment", "data"),
                 ("scripts/macos_packaging_jdk_preflight.py", "macos_packaging_jdk_preflight", "data"),
                 ("scripts/prepare_desktop_update_fixture.py", "prepare_desktop_update_fixture", "data"),
                 ("scripts/windows_broker_fixture_observer.py", "broker_observer", "data"))
_COLLECTOR_FILES = (("agent_tools/windows_system_collector/caller_hold.py", "caller_hold", "data"),
                    ("agent_tools/windows_system_collector/hold_protocol.py", "hold_protocol", "data"),
                    ("agent_tools/windows_system_collector/collector_contract.py", "collector_contract", "data"),
                    ("agent_tools/windows_system_collector/system_collector_worker.py", "system_worker", "data"),
                    ("agent_tools/windows_system_collector/native_primitives.py", "native_primitives", "data"),
                    ("agent_tools/windows_system_collector/ordinary_task_guard.ps1", "task_guard", "data"),
                    ("agent_tools/windows_system_collector/system_collector_native.cs", "native_bridge", "data"))
# The variants update_cases.VARIANTS accepts, less transport-loss, which it refuses itself.
UPDATE_VARIANTS = ("public-ready", "download-cancelled", "checksum-rejected", "uac-denied", "install-cancelled",
                   "participating-copy-lock", "protected-storage-rejected", "native-install-failed", "success-off",
                   "success-reconnect", "different-admin", "wait-client-loss", "installer-wait-client-loss")
_NO_SYSTEM = ("public-ready", "download-cancelled", "checksum-rejected")
# Refused before any journal, each with what is missing. A grant's authorization stage observes the elevated helper
# coordinator and its original-user worker as live actors, and terminal-actors after a handoff needs both again; no
# stage of this job discovers them, so no collector proves the helper image and the approving SID.
_UPDATE_REFUSED = {
    "install-cancelled": "windows_scenario_update_grant_unproven",
    "participating-copy-lock": "windows_scenario_update_grant_unproven",
    "success-off": "windows_scenario_update_grant_unproven",
    "success-reconnect": "windows_scenario_update_grant_unproven",
    "different-admin": "windows_scenario_update_grant_unproven",
    "wait-client-loss": "windows_scenario_update_grant_unproven",
    "installer-wait-client-loss": "windows_scenario_update_grant_unproven",
    # No producer: the product's MSIs carry no LaunchCondition table for the failing-MSI derivation, and nothing
    # creates or removes a counterfeit protected-storage root.
    "native-install-failed": "windows_scenario_update_fault_unavailable",
    "protected-storage-rejected": "windows_scenario_update_fault_unavailable",
    # The pinned collector chain takes its request only in the O:SYD:P form, but a file the publisher creates and then
    # protects reads back O:SYD:PAI natively, so publish ends collector_file_policy. And its terminal-actors stage reads
    # the product's not-started disposition as SYSTEM, while the product writes that file for its owner alone and
    # nothing enables SeBackupPrivilege. Both a request writer and a reader have to be proved natively first.
    "uac-denied": "windows_scenario_update_collector_unproven",
}
# The stages each variant's owner asks a SYSTEM collector for, the last one behind the caller's close hold.
_UPDATE_COLLECTORS = {"uac-denied": (("before-install", "terminal-actors"), "terminal-actors")}


def _update_row(variant: str) -> dict[str, Any]:
    stages, final = _UPDATE_COLLECTORS.get(variant, ((), None))
    row = _worker_row("product", "windows-public-update", ("targetPackage", "fixtureReceipt"),
                      (*_UPDATE_FILES, *(_COLLECTOR_FILES if stages else ())), prior=True, deadline=3600)
    row["update"] = {"variant": variant, "collectorStages": stages, "finalStage": final}
    row["refusal"] = _UPDATE_REFUSED.get(variant)
    if variant not in _NO_SYSTEM:
        deny = variant == "uac-denied"
        # windows_uac_decision.ROWS answers each prompt; collect joins a deny row's own input terminal.
        row["uac"] = {"prompt": "install-helper", "decision": "deny" if deny else "approve",
                      "event": {"install-cancelled": "update-install-cancel-requested-before-authorization",
                                "installer-wait-client-loss": "update-installer-wait-client-lost"}.get(variant, "update-uac-action-pending")}
        row["denyJoin"] = deny
    return row


# One row per closed name. A later name is a row here plus its stages in the host job.
# setup rows prepare the one VM and never count as matrix evidence; product rows claim
# installed-package only from the receipt facts public_evidence reads.
RECIPES: dict[str, dict[str, Any]] = {
    "windows-ordinary-qualification": {
        "evidenceClass": "component",
        "bootstrapMode": "qualification",
        "workerAction": None,
        "artifactKeys": ("bundleManifest",),
        "guestFiles": (_OWNER, ("agent_tools/windows_scenario_qualification_child.ps1", "child", "powershell")),
        "package": None,
        "priorInstall": False,
        "readPins": (host_job.POWERSHELL_PATH,),
        "subfolders": (),
        "qualificationArguments": ("-Value", "scenario-ok"),
        "expectedExit": 7,
        "expectedStreams": {"stdout": "stdout|scenario-ok", "stderr": "stderr|scenario-ok"},
        "rawStreamLimitBytes": 1024 * 1024,
        "deadlineSeconds": 300,
        "stages": _STAGES,
    },
    "windows-python-install": {
        "evidenceClass": "setup",
        "bootstrapMode": "python-install",
        "workerAction": None,
        "artifactKeys": ("bundleManifest", "pythonInstaller"),
        "guestFiles": (_OWNER,),
        "package": {"role": "pythonInstaller", "leaf": "python-3.13.15-amd64.exe"},
        "priorInstall": False,
        "readPins": (host_job.POWERSHELL_PATH,),
        "subfolders": (),
        "expectedExit": 0,
        "expectedStreams": {},
        "rawStreamLimitBytes": 1024 * 1024,
        "deadlineSeconds": 3600,
        "stages": _ALL_STAGES,
    },
    "windows-msi-base-install": _worker_row("setup", "msi-install", ("basePackage",), (), package=_BASE, msiexec=True, deadline=7200),
    # The VM's way back to a clean base: remove the one registered product by its code, install the admitted base.
    "windows-msi-base-reset": _worker_row("setup", "msi-reset", ("basePackage",), (), package=_BASE, msiexec=True, deadline=7200),
    "windows-packaged-cli-smoke": _worker_row("product", "qualification", ("targetPackage",), _HARNESS, prior=True, deadline=7200),
    "windows-disconnected-cli-config": _worker_row(
        "product", "disconnected-cli-config", ("targetPackage",),
        (("agent_tools/windows_disconnected_cli_cases.py", "cases", "data"), *_HARNESS), prior=True, deadline=14400),
    "windows-streaming-client-interrupt": _worker_row(
        "product", "streaming-client-interrupt", ("targetPackage",),
        (("agent_tools/windows_streaming_cli_cases.py", "cases", "data"), *_HARNESS), prior=True, deadline=7200),
    "windows-autostart-migration.pre": _reboot_row("windows-autostart-migration", "pre", "autostart-migration"),
    "windows-autostart-migration.post": _reboot_row("windows-autostart-migration", "post", "autostart-migration"),
    "windows-reboot-reconnect.pre": _reboot_row("windows-reboot-reconnect", "pre", "reconnect"),
    "windows-reboot-reconnect.post": _reboot_row("windows-reboot-reconnect", "post", "reconnect"),
    "windows-reboot-explicit-off.pre": _reboot_row("windows-reboot-explicit-off", "pre", "explicit-off"),
    "windows-reboot-explicit-off.post": _reboot_row("windows-reboot-explicit-off", "post", "explicit-off"),
    # Rebootless: a query starts a transient owner that never connects, then a GUI restores intent once.
    "windows-query-owner-gui-reconnect": _reboot_row("windows-query-owner-gui-reconnect", "none", "query-first"),
    **{"windows-proxy-lifecycle." + variant: _proxy_row(variant) for variant in PROXY_VARIANTS},
    **{"windows-public-update." + variant: _update_row(variant) for variant in UPDATE_VARIANTS},
}
SETUP_OR_COMPONENT = frozenset({"setup", "component"})
INPUT_SCHEMA = "vpn-control.windows-scenario.input"
_INPUT_FIELDS = frozenset({"schema", "schemaVersion", "scenarioId", "correlationId", "deploymentId", "sourceSha", "productVersion",
                           "artifactSetId", "priorInstall"})
# Only a postboot row's input names its preboot; no other row's input has the field.
# An update row also names the version it updates from and the earlier install of its target that recorded the tree.
_UPDATE_INPUT_FIELDS = frozenset({"baseVersion", "targetInstall"})
_MAX_INPUT_BYTES = 4096
# Fixed admission per package role: the registry kind, and for desktop packages the frozen-set source.
PACKAGE_KINDS = {"pythonInstaller": "test-toolchain-installer", "basePackage": "desktop-package", "targetPackage": "desktop-package",
                 "fixtureReceipt": "desktop-update-fixture-receipt"}
_MAX_PACKAGE_BYTES = 1024 * 1024 * 1024
_MAX_RECEIPT_BYTES = 1024 * 1024
_FIXTURE_URL = "https://github.com/Karapsin/vpn_control/releases/download/disposable-desktop-fixture/"


class NativeScenarioWindowsError(ValueError):
    """A finite refusal; no private path or stream crosses it."""


def _need(condition: Any, reason: str) -> None:
    if not condition:
        raise NativeScenarioWindowsError(reason)


def _canonical_uuid(value: Any, reason: str) -> str:
    try:
        _need(type(value) is str and str(uuid.UUID(value)) == value, reason)
    except (ValueError, AttributeError, TypeError):
        raise NativeScenarioWindowsError(reason) from None
    return value


def _row(scenario_id: Any) -> dict[str, Any]:
    row = RECIPES.get(scenario_id) if isinstance(scenario_id, str) else None
    _need(row is not None, "windows_scenario_not_allowlisted")
    return row


def _binding(root: Path | str, plan: native_scenario_execution.ScenarioPlan) -> dict[str, Any]:
    """The original start intent names the VM; nothing here is caller supplied."""
    from . import readiness_windows_registration as registration
    from . import readiness_windows_remote as packets
    try:
        binding, _, _ = registration.original_binding(root, plan.environment)
        provider, spec, _, _ = packets.validate_binding(binding)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise NativeScenarioWindowsError("windows_scenario_environment_unavailable") from error
    _need(provider == "raw-qemu-windows" and spec.deployment_id == plan.environment and spec.host == plan.host,
          "windows_scenario_environment_mismatch")
    return binding


def verified_bundle(root: Path | str, plan: native_scenario_execution.ScenarioPlan,
                    bundle_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str]) -> tuple[Path, dict[str, Any]]:
    """The frozen inventory, byte for byte this checkout: no caller supplies case bytes."""
    try:
        bundle = Path(bundle_resolver(plan)).resolve(strict=True)
        verified = native_scenario_bundle.verify_bundle(root, bundle, plan.bundle_hash)
    except (OSError, ValueError) as error:
        raise NativeScenarioWindowsError("windows_scenario_bundle_unavailable") from error
    _need(verified.get("scenarioId") == BUNDLE_SCENARIO_ID, "windows_scenario_bundle_foreign")
    for entry in verified["files"]:
        source = Path(root) / entry["path"]
        try:
            matches = source.is_file() and not source.is_symlink() and native_scenario_bundle._hash(source) == entry["sha256"]
        except OSError:
            matches = False
        _need(matches, "windows_scenario_bundle_differs_from_checkout")
    return bundle, verified


def _verified_artifact(root: Path | str, artifact_id: str, reason: str) -> tuple[dict[str, Any], Path]:
    """Registered local bytes, re-read now; a remote or changed record refuses."""
    try:
        verified = native_artifact_registry.verify_artifact_readonly(root, artifact_id)
    except (OSError, ValueError):
        raise NativeScenarioWindowsError(reason + "_unavailable") from None
    location = verified.get("location") or {}
    _need(verified.get("verification") == "verified" and location.get("evidenceClass") == "local-verified"
          and isinstance(location.get("localPath"), str), reason + "_unavailable")
    return verified["artifact"], Path(location["localPath"])


def scenario_input(root: Path | str, plan: native_scenario_execution.ScenarioPlan, row: Mapping[str, Any]) -> dict[str, Any] | None:
    """The typed input of a package row: names its own operation, VM, source, version and frozen set."""
    if "scenarioInput" not in row["artifactKeys"]:
        return None
    artifact, path = _verified_artifact(root, plan.artifact_ids["scenarioInput"], "windows_scenario_input")
    _need(artifact.get("platform") == "windows" and artifact.get("artifactKind") == "scenario-input"
          and type(artifact.get("size")) is int and artifact["size"] <= _MAX_INPUT_BYTES, "windows_scenario_input_invalid")
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, ValueError):
        raise NativeScenarioWindowsError("windows_scenario_input_invalid") from None
    postboot = (row.get("reboot") or {}).get("phase") == "post"
    fields = (_INPUT_FIELDS | (_UPDATE_INPUT_FIELDS if row.get("update") else frozenset())
              | (frozenset({"priorPreboot"}) if postboot else frozenset()))
    _need(hashlib.sha256(raw).hexdigest() == artifact["sha256"] and isinstance(value, dict) and set(value) == fields,
          "windows_scenario_input_invalid")
    prior = value["priorInstall"]
    _need(value["schema"] == INPUT_SCHEMA and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
          and value["scenarioId"] == plan.scenario_id and value["correlationId"] == plan.correlation_id
          and value["deploymentId"] == plan.environment
          and isinstance(value["sourceSha"], str) and re.fullmatch(r"[0-9a-f]{40}", value["sourceSha"]) is not None
          and isinstance(value["productVersion"], str) and host_job._VERSION.fullmatch(value["productVersion"]) is not None
          and isinstance(value["artifactSetId"], str) and re.fullmatch(r"artifact-set-[0-9a-f]{64}", value["artifactSetId"]) is not None
          and (prior is None if not row["priorInstall"] else isinstance(prior, str) and prior != plan.correlation_id),
          "windows_scenario_input_invalid")
    if row["priorInstall"]:
        _canonical_uuid(prior, "windows_scenario_input_invalid")
    if postboot:
        _canonical_uuid(value["priorPreboot"], "windows_scenario_input_invalid")
        _need(value["priorPreboot"] not in {plan.correlation_id, prior}, "windows_scenario_input_invalid")
    if row.get("update"):
        base, target = value["baseVersion"], value["targetInstall"]
        _need(isinstance(base, str) and host_job._VERSION.fullmatch(base) is not None, "windows_scenario_input_invalid")
        # The planner keeps the expanded cases off the 2.2.13 baseline, and an update needs an older base.
        _need(base != "2.2.13", "windows_scenario_update_base_baseline")
        _need(tuple(map(int, base.split("."))) < tuple(map(int, value["productVersion"].split("."))), "windows_scenario_update_not_newer")
        _need(_canonical_uuid(target, "windows_scenario_input_invalid") not in {plan.correlation_id, prior}, "windows_scenario_input_invalid")
    return value


def fixture_receipt(path: Path, artifact: Mapping[str, Any], value: Mapping[str, Any], target: Mapping[str, Any]) -> dict[str, Any]:
    """The CI fixture pair's receipt, which the guest's update server reads: one source built twice, its target
    the admitted target package, its manifest the one asset served. The base build is never installed from here."""
    try:
        raw = path.read_bytes()
        receipt = json.loads(raw)
        _need(hashlib.sha256(raw).hexdigest() == artifact["sha256"] and type(receipt) is dict, "windows_scenario_fixture_receipt")
        base, built = receipt["builds"]
        manifest = receipt["manifest"]
        asset = manifest["assets"][0]
        version = value["productVersion"]
        _need(receipt["testOnly"] is True and receipt["productionTrustChanged"] is False and receipt["architecture"] == "x86_64"
              and re.fullmatch(r"[0-9a-f]{64}", receipt["sourceFingerprint"]) is not None
              and base["label"] == "base" and built["label"] == "target"
              and base["sourceFingerprint"] == built["sourceFingerprint"] == receipt["sourceFingerprint"]
              and re.fullmatch(r"[0-9a-f]{64}", built["codeFingerprint"]) is not None and base["codeFingerprint"] == built["codeFingerprint"]
              and built["version"] == version and host_job._VERSION.fullmatch(base["version"]) is not None
              and tuple(map(int, base["version"].split("."))) < tuple(map(int, version.split(".")))
              and manifest["assets"] == built["assets"] and len(manifest["assets"]) == 1
              and manifest["buildNumber"] == host_job.version_build(version) and manifest["releaseTag"] == host_job.FIXTURE_RELEASE
              and set(asset) == {"platform", "architecture", "packageType", "displayVersion", "fileName", "downloadUrl", "sha256", "sizeBytes"}
              and asset["platform"] == "windows" and asset["architecture"] == "x86_64" and asset["packageType"] == "msi"
              and asset["displayVersion"] == version and host_job._FIXTURE_FILE.fullmatch(asset["fileName"]) is not None
              and asset["downloadUrl"] == _FIXTURE_URL + asset["fileName"]
              and asset["sha256"] == target["sha256"] and asset["sizeBytes"] == target["bytes"], "windows_scenario_fixture_receipt")
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError):
        raise NativeScenarioWindowsError("windows_scenario_fixture_receipt") from None
    return {"fileName": asset["fileName"], "sourceFingerprint": receipt["sourceFingerprint"]}


def admitted_packages(root: Path | str, plan: native_scenario_execution.ScenarioPlan, row: Mapping[str, Any],
                      value: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Package IDs a caller names: platform windows, the role's fixed kind, the input's source, a frozen set's member.

    The set's own product version must be the one the input names. That catches a mislabelled input, not a
    substituted package: the set records whatever its caller registered.
    """
    packages = {}
    for role in [key for key in row["artifactKeys"] if key in PACKAGE_KINDS]:
        artifact, path = _verified_artifact(root, plan.artifact_ids[role], "windows_scenario_package")
        _need(artifact.get("platform") == "windows" and artifact.get("artifactKind") == PACKAGE_KINDS[role]
              and type(artifact.get("size")) is int and 0 < artifact["size"] <= _MAX_PACKAGE_BYTES, "windows_scenario_package_kind")
        if role == "pythonInstaller":
            # The planner and the owner pin these bytes; no source or set can stand in for them.
            _need(artifact["sha256"] == planner.PYTHON_INSTALLER_SHA256 and artifact["size"] == planner.PYTHON_INSTALLER_BYTES,
                  "windows_scenario_python_installer")
        else:
            _need(value is not None and artifact.get("sourceSha") == value["sourceSha"], "windows_scenario_package_source")
            if role == "fixtureReceipt":
                _need(path.suffix.lower() == ".json" and artifact["size"] <= _MAX_RECEIPT_BYTES, "windows_scenario_package_kind")
                fixture_receipt(path, artifact, value, packages["targetPackage"])
            else:
                _need(path.suffix.lower() == ".msi", "windows_scenario_package_kind")
            try:
                frozen = native_artifact_reuse.artifact_set_verify_readonly(root, value["artifactSetId"])
            except (OSError, ValueError):
                frozen = {"verification": "unavailable"}
            _need(frozen.get("verification") == "verified" and frozen.get("originalSourceSha") == value["sourceSha"]
                  and plan.artifact_ids[role] in {item.get("artifactId") for item in frozen.get("packages", [])},
                  "windows_scenario_package_not_frozen")
            _need(frozen.get("productVersion") == value["productVersion"], "windows_scenario_package_version")
        packages[role] = {"sha256": artifact["sha256"], "bytes": artifact["size"], "localPath": str(path)}
    return packages


def staged_roles(row: Mapping[str, Any]) -> tuple[str, ...]:
    """The admitted packages a row pushes into the guest, staged on the host before its job exists."""
    if row.get("update"):
        return ("targetPackage", "fixtureReceipt")
    return (row["package"]["role"],) if row["package"] else ()


def _admit(root: Path | str, request: Mapping[str, Any],
           bundle_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str]) -> tuple[dict[str, Any], Any, Any, dict[str, Any]]:
    if not isinstance(request, Mapping):
        raise NativeScenarioWindowsError("windows_scenario_request_invalid")
    row = _row(request.get("scenarioId"))
    # A row whose evidence has no producer yet is closed, named and refused here, before any journal.
    _need(row.get("refusal") is None, str(row.get("refusal")))
    # An expired prompt ends as the same public CANCELLED as Esc, so a deny row would pass with no decision at all.
    # It is admitted only where collect joins the decision's own input terminal.
    _need((row.get("uac") or {}).get("decision") != "deny" or row.get("denyJoin") is True, "windows_scenario_deny_needs_decision_join")
    plan = native_scenario_execution.ScenarioPlan.from_mapping(request)
    _canonical_uuid(plan.correlation_id, "windows_scenario_correlation_invalid")
    _canonical_uuid(plan.environment, "windows_scenario_environment_invalid")
    _need(set(plan.artifact_ids) == set(row["artifactKeys"]), "windows_scenario_artifacts_invalid")
    _need(plan.artifact_ids["bundleManifest"] == "sha256-" + plan.bundle_hash, "windows_scenario_bundle_artifact_invalid")
    _binding(root, plan)
    verified_bundle(root, plan, bundle_resolver)
    value = scenario_input(root, plan, row)
    return row, plan, value, admitted_packages(root, plan, row, value)


def admit_start(root: Path | str, request: Mapping[str, Any],
                bundle_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str]) -> dict[str, Any]:
    """Pure gates before any journal: no connection, no guest and no intent exists yet."""
    return _admit(root, request, bundle_resolver)[0]


def public_evidence(result: Mapping[str, Any]) -> dict[str, Any]:
    """A setup or component row never claims installed-package, whatever its receipt says.

    Nor does a job the direct script stopped early: no task ran, so --version never held.
    """
    row = _row(result.get("scenarioId"))
    if row["evidenceClass"] in SETUP_OR_COMPONENT:
        return {"evidenceClass": row["evidenceClass"], "productAction": False}
    windows = (result.get("scenarioEvidence") or {}).get("windows") if isinstance(result.get("scenarioEvidence"), Mapping) else None
    target = (result.get("artifactIds") or {}).get("targetPackage") if isinstance(result.get("artifactIds"), Mapping) else None
    proven = (result.get("state") == "terminal" and result.get("collectionState") == "complete" and isinstance(windows, Mapping)
              and windows.get("stoppedAfter") is None
              and windows.get("installedPackage") is True and isinstance(windows.get("packageSha256"), str)
              and isinstance(target, str) and target == "sha256-" + windows["packageSha256"])
    return {"evidenceClass": "installed-package" if proven else "installed-package-unproven", "productAction": True}


def _instance_definitions() -> str:
    """The same canonical definitions readiness packets embed, so the guards cannot drift."""
    from . import windows_vm_instance as instance
    source = inspect.getsource(instance._vm_main)
    node = next(item for item in ast.parse(source).body if isinstance(item, ast.FunctionDef))
    nodes = [item for item in node.body if isinstance(item, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
             and not (isinstance(item, ast.FunctionDef) and item.name == "launch")]
    return "\n".join(ast.get_source_segment(source, item) for item in nodes)


def render_program(plan: native_scenario_execution.ScenarioPlan, binding: Mapping[str, Any], bundle: Path,
                   verified: Mapping[str, Any], target: Mapping[str, Any], *, stop_after: str | None = None,
                   value: Mapping[str, Any] | None = None, packages: Mapping[str, Mapping[str, Any]] | None = None) -> tuple[str, str]:
    """One fixed job source: host module, canonical guards, closed plan and the frozen files.

    Package rows carry only admitted digests and sizes; the bytes wait in the host's
    artifact cache, staged before submit, and the job reads nothing a caller named.
    """
    from . import windows_vm_deploy_remote as deployment
    row = _row(plan.scenario_id)
    data = str(PurePosixPath(target["home"]) / _DATA_PARENT / plan.environment / plan.correlation_id)
    entries = {entry["path"]: {"sha256": entry["sha256"], "sizeBytes": entry["sizeBytes"]} for entry in verified["files"]}
    raw_files = {path: (bundle / path).read_bytes() for path in entries}
    _need(all(hashlib.sha256(raw_files[path]).hexdigest() == entry["sha256"] for path, entry in entries.items()),
          "windows_scenario_bundle_changed")
    job_plan = {"schemaVersion": 1, "operationId": plan.correlation_id, "scenarioId": plan.scenario_id, "machine": plan.environment,
                "bundleHash": plan.bundle_hash, "user": binding["setup"]["user"], "dataDirectory": data,
                "row": row, "files": entries, "stopAfter": stop_after,
                "artifactDirectory": str(PurePosixPath(target["home"]) / _ARTIFACT_PARENT),
                "packages": {role: {"sha256": item["sha256"], "bytes": item["bytes"]} for role, item in (packages or {}).items()},
                "product": None if value is None else {"sourceSha": value["sourceSha"], "productVersion": value["productVersion"],
                                                       **({"baseVersion": value["baseVersion"]} if row.get("update") else {})},
                "prior": {**({} if value is None or value["priorInstall"] is None else {
                    "install": value["priorInstall"], **({"targetInstall": value["targetInstall"]} if row.get("update") else {})}),
                          **({"preboot": value["priorPreboot"]} if value is not None and "priorPreboot" in value else {})}}
    if row.get("update"):
        job_plan["administrator"] = binding["setup"]["administrator"]  # The account a grant approves with; its SID is read in the guest.
    payload = gzip.compress(json.dumps({path: base64.b64encode(raw).decode("ascii") for path, raw in raw_files.items()},
                                       sort_keys=True).encode("ascii"), mtime=0)
    text = raw_files[_HOST_JOB_PATH].decode("utf-8")
    marker = "    _CANONICAL_INSTANCE_DEFINITIONS()\n"
    _need(text.count(marker) == 1, "windows_scenario_host_source")
    text = text.replace(marker, "".join("    " + line + "\n" for line in _instance_definitions().splitlines()))
    bindings = {"SPEC": binding["spec"], "SETUP": binding["setup"], "CONTEXT": binding["context"], "PLAN": _plain(job_plan),
                "FILES_GZ": base64.b64encode(payload).decode("ascii")}
    source = (text + "\n" + "\n".join(key + "=" + repr(value) for key, value in bindings.items()) + "\n"
              + deployment.guest_rpc_definitions() + "\nwire=partial_wire=-1\nQGA_PEER_PID=QGA_GUARD=None\n"
              + "raise SystemExit(_host_main())\n")
    compile(source, "windows scenario job", "exec")
    return source, data


def _plain(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _py(program: str, *arguments: str) -> tuple[str, ...]:
    return ("python3", "-I", "-B", "-c", "exec(" + repr(program) + ")", *arguments)


# Fixed read-only programs for the host. They take token arguments and no source.
_TARGET = r'''import json,os,pwd,subprocess,sys
e=pwd.getpwuid(os.geteuid())
if sys.platform.startswith('linux'):
 b=open('/proc/sys/kernel/random/boot_id').read(128).strip()
else:b=subprocess.run(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3,check=True).stdout.decode('ascii').strip().lower()
print(json.dumps({'kind':'ssh','uid':os.geteuid(),'principal':e.pw_name,'home':e.pw_dir,'bootId':b},sort_keys=True))'''

_COLLECT = r'''import base64,json,os,stat,sys
job=sys.argv[1]
def read(name,limit):
 fd=os.open(os.path.join(job,name),os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>limit: raise ValueError()
  raw=os.read(fd,limit+1)
  if len(raw)!=info.st_size: raise ValueError()
  return raw
 finally: os.close(fd)
try:
 print(json.dumps({"state":"collected","receipt":base64.b64encode(read("scenario-receipt.json",8192)).decode(),"jobExit":json.loads(read("job-exit.json",1024))},separators=(",",":")))
except Exception: print(json.dumps({"state":"unknown"},separators=(",",":")))'''

# Stage one admitted package into the host's artifact cache: digest and size are the only arguments,
# the bytes arrive on stdin, land in a private temporary file, are hashed, then linked create-only.
# It runs under the SSH login's umask, not the durable owner's: makedirs gives its mode only to the
# leaf, so the umask is what keeps a first-created cache parent private.
_STAGE = r'''import hashlib,json,os,stat,sys
digest,size,mode=sys.argv[1],int(sys.argv[2]),sys.argv[3]
if len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest) or not 0<size<=1073741824 or mode not in ("check","write"):raise SystemExit(2)
os.umask(0o077)
parent=os.path.join(os.path.expanduser("~"),".cache","vpn-control-windows-scenarios");directory=os.path.join(parent,"artifacts")
os.makedirs(directory,mode=0o700,exist_ok=True)
for path in (parent,directory):
 info=os.lstat(path)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o077:raise SystemExit(3)
target=os.path.join(directory,digest)
def present():
 try:fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
 except FileNotFoundError:return None
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=size:return False
  h=hashlib.sha256()
  while True:
   b=os.read(fd,1048576)
   if not b:break
   h.update(b)
  return h.hexdigest()==digest
 finally:os.close(fd)
state=present()
if state is not None or mode=="check":
 print(json.dumps({"state":"present" if state else ("absent" if state is None else "differs")}));raise SystemExit(0)
temporary=os.path.join(directory,"."+digest+"."+str(os.getpid())+".partial")
fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);h=hashlib.sha256();total=0
try:
 while total<size:
  b=sys.stdin.buffer.read(min(1048576,size-total))
  if not b:break
  v=memoryview(b)
  while v:v=v[os.write(fd,v):]
  h.update(b);total+=len(b)
 os.fsync(fd)
finally:os.close(fd)
if total!=size or h.hexdigest()!=digest or sys.stdin.buffer.read(1):
 os.unlink(temporary);print(json.dumps({"state":"differs"}));raise SystemExit(0)
try:os.link(temporary,target)
except FileExistsError:pass
os.unlink(temporary);d=os.open(directory,os.O_RDONLY);os.fsync(d);os.close(d)
print(json.dumps({"state":"staged" if present() else "differs"}))'''

# The decision's own input terminal, read from the VM root it was written under. Two token arguments, no source.
_READ_DECISION = r'''import json,os,re,stat,sys
root,decision=sys.argv[1:]
try:
 if re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',decision) is None:raise ValueError()
 fd=os.open(os.path.join(root,'windows-uac',decision,'input.terminal.json'),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=65536: raise ValueError()
  raw=os.read(fd,65537)
 finally: os.close(fd)
 print(json.dumps({"state":"read","value":json.loads(raw)},separators=(",",":")))
except Exception: print(json.dumps({"state":"unavailable"},separators=(",",":")))'''

_PULL = r'''import base64,json,os,stat,sys
job,name,offset,length=sys.argv[1:]
fd=os.open(os.path.join(job,name),os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
try:
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600: raise ValueError()
 print(json.dumps({"size":info.st_size,"data":base64.b64encode(os.pread(fd,int(length),int(offset))).decode()},separators=(",",":")))
finally: os.close(fd)'''

_READ_JOB_FILE = r'''import json,os,stat,sys
try:
 fd=os.open(os.path.join(sys.argv[1],sys.argv[2]),os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_size>8192: raise ValueError()
  raw=os.read(fd,8193)
 finally: os.close(fd)
 print(json.dumps({"state":"read","value":json.loads(raw)},separators=(",",":")))
except Exception: print(json.dumps({"state":"unavailable"},separators=(",",":")))'''


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(path)
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077,
          "windows_scenario_private_state_unsafe")
    return path


def _create_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _read_private(path: Path) -> Any:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077,
              "windows_scenario_private_state_unsafe")
        return json.loads(stream.read())


def _start_ticks(birth: Any) -> int | None:
    match = _BIRTH.fullmatch(birth) if isinstance(birth, str) else None
    if match is None:
        return None
    return int(match[1]) if match[1] else int(match[2]) * 1_000_000 + int(match[3]) + 1


def _exit_marker(stdout: bytes, operation: str) -> dict[str, Any] | None:
    """Job exit 1 is also what an uncaught Python error exits with; only the job's own line counts."""
    lines = stdout.decode("utf-8", "replace").strip().splitlines()
    try:
        value = json.loads(lines[-1]) if lines else None
    except ValueError:
        return None
    if (isinstance(value, dict) and value.get("operationId") == operation and type(value.get("scenarioExit")) is int
            and (value.get("failure") is None or isinstance(value.get("failure"), str))):
        return value
    return None


class NativeScenarioWindowsDriver:
    """Private adapter. ``stop_after`` is constructor wiring for the direct script, never request data."""

    def __init__(self, repository_root: Path | str, bundle_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str],
                 timeout_seconds: int = 30, ssh_binary: str = "ssh", configuration_root: Path | str | None = None,
                 *, stop_after: str | None = None):
        _need(stop_after is None or stop_after in host_job.STOP_AFTER, "windows_scenario_stop_after_invalid")
        self.root = Path(repository_root).resolve()
        self.configuration_root = Path(configuration_root).resolve() if configuration_root is not None else self.root
        self.bundle_resolver = bundle_resolver
        self.timeout_seconds = timeout_seconds
        self.ssh_binary = ssh_binary
        self.stop_after = stop_after

    def _local(self, plan: native_scenario_execution.ScenarioPlan) -> Path:
        return self.configuration_root.joinpath(*_LOCAL_STATE, plan.correlation_id)

    @contextmanager
    def _admitted(self, config: Any, plan: native_scenario_execution.ScenarioPlan, seconds: int):
        """Send pattern of readiness_windows: an explicit transport admission around the SSH child."""
        if ssh_transport._dispatch_binding(config, plan.host) is not None:
            yield  # The public dispatch boundary already admitted this host.
            return
        with ssh_transport.admitted_transport(self.configuration_root, plan.host, plan.correlation_id, deadline=time.monotonic() + seconds):
            yield

    def _send(self, config: Any, host: str, command: tuple[str, ...], *, seconds: int, keep: Path | None = None,
              stdin_path: Path | None = None) -> dict[str, Any] | None:
        argv = ssh_transport.build_ssh_argv(config, host, self.timeout_seconds, command=command, ssh_binary=self.ssh_binary)
        connection = ssh_transport.connection_host(config, host)

        def run(environment=None):
            if stdin_path is None:
                return ssh_transport.run_ssh(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             timeout=seconds, env=environment, check=False)
            with stdin_path.open("rb") as source:
                return ssh_transport.run_ssh(argv, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             timeout=seconds, env=environment, check=False)
        try:
            if connection.password is not None:
                with tempfile.TemporaryDirectory(prefix="vpn-control-askpass-") as directory:
                    _, environment = ssh_transport._askpass_environment(connection.password, Path(directory))
                    done = run(environment)
            else:
                done = run()
        except (OSError, subprocess.TimeoutExpired):
            return None
        if keep is not None:  # A first contact's only record of what the host said.
            _create_private(keep.with_name(keep.name + ".stdout.private"), done.stdout)
            _create_private(keep.with_name(keep.name + ".stderr.private"), done.stderr)
            _create_private(keep.with_name(keep.name + ".returncode"), str(done.returncode).encode())
        if done.returncode != 0 or len(done.stdout) > _MAX_REPLY:
            return None
        try:
            value = json.loads(done.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def _retained(self, plan: native_scenario_execution.ScenarioPlan) -> dict[str, Any] | None:
        directory = self._local(plan)
        try:
            return {"program": _read_private(directory / "program.json"), "packet": _read_private(directory / "admission.json")}
        except FileNotFoundError:
            return None

    def _identity(self, plan: native_scenario_execution.ScenarioPlan, program: Mapping[str, Any], owner: Any) -> native_scenario_execution.JobIdentity:
        receipt = str(PurePosixPath(program["dataDirectory"]) / "scenario-receipt.json")
        ticks = _start_ticks(owner.get("birth")) if isinstance(owner, Mapping) else None
        pid = owner.get("pid") if isinstance(owner, Mapping) and ticks is not None else None
        return native_scenario_execution.JobIdentity("windows-" + plan.correlation_id, pid if type(pid) is int else None,
                                                     ticks if type(pid) is int else None, receipt)

    def _stage(self, config: Any, plan: native_scenario_execution.ScenarioPlan, package: Mapping[str, Any], directory: Path,
               role: str = "package") -> None:
        """The package reaches the host's artifact cache before the job exists; a matching copy is kept, never resent."""
        arguments = (package["sha256"], str(package["bytes"]))
        # The first role keeps the names a single package always had.
        suffix = "" if role in ("package", "basePackage", "pythonInstaller", "targetPackage") else "-" + role
        found = self._send(config, plan.host, _py(_STAGE, *arguments, "check"), seconds=_OBSERVE_SECONDS, keep=directory / ("stage-check" + suffix))
        _need(found is not None and found.get("state") in ("present", "absent"), "windows_scenario_stage_unavailable")
        if found["state"] == "present":
            return
        staged = self._send(config, plan.host, _py(_STAGE, *arguments, "write"), seconds=_STAGE_SECONDS, keep=directory / ("stage-write" + suffix),
                            stdin_path=Path(package["localPath"]))
        _need(staged is not None and staged.get("state") == "staged", "windows_scenario_stage_unavailable")

    def submit(self, plan: native_scenario_execution.ScenarioPlan) -> native_scenario_execution.JobIdentity:
        row, _, value, packages = _admit(self.root, plan.as_dict(), self.bundle_resolver)
        bundle, verified = verified_bundle(self.root, plan, self.bundle_resolver)
        binding = _binding(self.root, plan)
        directory = self._local(plan)
        _private_directory(directory.parent)
        try:
            os.mkdir(directory, 0o700)  # Create-only: a second submit of this correlation stops here.
        except FileExistsError:
            raise NativeScenarioWindowsError("windows_scenario_job_already_exists") from None
        config = ssh_transport.load_config(self.configuration_root)
        # The admission deadline clips every call under it, so it is the sum of their own budgets:
        # a slow but in-budget staging never shortens the prepare or submit into an unknown outcome.
        roles = staged_roles(row)
        seconds = self.timeout_seconds + 2 * _SUBMIT_SECONDS + (_OBSERVE_SECONDS + _STAGE_SECONDS) * len(roles)
        with self._admitted(config, plan, seconds):
            target = self._send(config, plan.host, _py(_TARGET), seconds=self.timeout_seconds, keep=directory / "target")
            _need(target is not None, "windows_scenario_target_unavailable")
            for role in roles:
                self._stage(config, plan, packages[role], directory, role)
            source, data = render_program(plan, binding, bundle, verified, target, stop_after=self.stop_after,
                                          value=value, packages=packages)
            program = {"language": "python3", "source": source, "args": [], "cwd": target["home"], "targetContext": target}
            _create_private(directory / "program.json", json.dumps({"program": program, "dataDirectory": data}, sort_keys=True).encode())
            packet = self._send(config, plan.host, carrier.prepare_command(plan.correlation_id, program, durable_remote_job.owner_source()),
                                seconds=_SUBMIT_SECONDS, keep=directory / "prepare")
            _need(packet is not None, "windows_scenario_preparation_unavailable")
            carrier.durable_command(plan.correlation_id, program, packet, mode="observe")  # Validate with an inert render.
            _create_private(directory / "admission.json", json.dumps(packet, sort_keys=True).encode())
            reply = self._send(config, plan.host, carrier.durable_command(plan.correlation_id, program, packet, mode="submit", wait_seconds=2),
                               seconds=_SUBMIT_SECONDS, keep=directory / "submit")
        _need(reply is not None, "windows_scenario_submit_unavailable")
        status = reply.get("status")
        _need(isinstance(status, Mapping) and status.get("operationId") == plan.correlation_id, "windows_scenario_submit_unavailable")
        return self._identity(plan, {"dataDirectory": data}, status.get("owner"))

    def _status(self, plan: native_scenario_execution.ScenarioPlan) -> tuple[dict[str, Any], dict[str, Any]] | None:
        retained = self._retained(plan)
        if retained is None:
            return None
        program = retained["program"]["program"]
        try:
            config = ssh_transport.load_config(self.configuration_root)
            with self._admitted(config, plan, _OBSERVE_SECONDS):
                reply = self._send(config, plan.host, carrier.durable_command(plan.correlation_id, program, retained["packet"], mode="observe", wait_seconds=0),
                                   seconds=_OBSERVE_SECONDS)
        except (OSError, ValueError, ssh_transport.SshConfigError):
            return None
        if (reply is None or reply.get("schemaVersion") != 1 or reply.get("operationId") != plan.correlation_id
                or not isinstance(reply.get("status"), Mapping) or reply["status"].get("operationId") != plan.correlation_id):
            return None
        return reply, retained["program"]

    def discover(self, plan: native_scenario_execution.ScenarioPlan) -> native_scenario_execution.JobIdentity | None:
        found = self._status(plan)
        if found is None:
            return None
        reply, program = found
        identity = self._identity(plan, program, reply["status"].get("owner"))
        return identity if identity.pid is not None else None

    def observe(self, plan: native_scenario_execution.ScenarioPlan, identity: native_scenario_execution.JobIdentity) -> native_scenario_execution.DriverObservation:
        unknown = native_scenario_execution.ObservationStatus.UNKNOWN
        found = self._status(plan)
        if found is None:
            return native_scenario_execution.DriverObservation(unknown, "observer_unavailable")
        reply, program = found
        status = reply["status"]
        observed = self._identity(plan, program, status.get("owner"))
        observed = observed if observed.pid is not None else None
        paths = (observed.receipt_path,) if observed is not None else ()
        state = status.get("state")
        if state == "running":
            return native_scenario_execution.DriverObservation(native_scenario_execution.ObservationStatus.RUNNING,
                                                               self._uac_pending(plan, program) or "original_owner_running", observed, evidence_paths=paths)
        if state != "terminal":
            return native_scenario_execution.DriverObservation(unknown, str(status.get("reason", "remote_unknown")), observed, evidence_paths=paths)
        terminal = status.get("terminal")
        code = terminal.get("exitCode") if isinstance(terminal, Mapping) else None
        try:
            marker = _exit_marker(base64.b64decode(reply.get("stdout", ""), validate=True), plan.correlation_id)
        except (ValueError, TypeError):
            marker = None
        if (type(code) is not int or code not in host_job.KNOWN_EXITS or marker is None or marker["scenarioExit"] != code
                or observed is None):
            failure = host_job.token(marker.get("failure")) if marker and marker.get("failure") else "unverified"
            return native_scenario_execution.DriverObservation(unknown, "job_exit_unknown:" + failure, observed, evidence_paths=paths)
        receipt = {**plan.as_dict(), "jobId": observed.job_id, "pid": observed.pid, "startTicks": observed.start_ticks, "exitCode": code}
        # A job refused before it started leaves no receipt: its own line is the only cause there is.
        excerpt = host_job.token(marker["failure"]) if marker.get("failure") else None
        return native_scenario_execution.DriverObservation(native_scenario_execution.ObservationStatus.TERMINAL, "remote_receipt",
                                                           observed, receipt, paths, excerpt)

    def _read_job_file(self, plan: native_scenario_execution.ScenarioPlan, data: str, name: str) -> Any:
        config = ssh_transport.load_config(self.configuration_root)
        with self._admitted(config, plan, _OBSERVE_SECONDS):
            reply = self._send(config, plan.host, _py(_READ_JOB_FILE, data, name), seconds=_OBSERVE_SECONDS)
        return reply["value"] if isinstance(reply, Mapping) and reply.get("state") == "read" else None

    def _uac_pending(self, plan: native_scenario_execution.ScenarioPlan, program: Mapping[str, Any]) -> str | None:
        """uac-pending:<prompt>:<decision> once this row's owner published its prompt event; a fixed client polls for it.

        A row with no prompt reads nothing more. A miss proves nothing, so the job just stays running.
        """
        uac = _row(plan.scenario_id).get("uac")
        if uac is None:
            return None
        try:
            status = self._read_job_file(plan, program["dataDirectory"], "status.json")
        except (OSError, ValueError, ssh_transport.SshConfigError):
            return None
        # The run template reports the row's prompt event from every event, not a recent window, and the host job
        # adds the decision's input terminal once it exists: until then the prompt is pending.
        pending = status.get("uacEvents") if isinstance(status, Mapping) else None
        decided = isinstance(status, Mapping) and status.get("uacDecision") is not None
        return ("uac-pending:" + uac["prompt"] + ":" + uac["decision"]
                if isinstance(pending, list) and uac["event"] in pending and not decided else None)

    def uac_context(self, plan: native_scenario_execution.ScenarioPlan) -> dict[str, Any]:
        """The operation root and SIDs this job's context stage retained. Holds no QMP or QGA socket and takes no lock."""
        retained = self._retained(plan)
        _need(retained is not None, "windows_scenario_job_unknown")
        value = self._read_job_file(plan, retained["program"]["dataDirectory"], "uac-context.json")
        _need(isinstance(value, dict), "windows_scenario_uac_context_unavailable")
        return value

    def collect(self, plan: native_scenario_execution.ScenarioPlan, identity: native_scenario_execution.JobIdentity) -> Mapping[str, Any] | None:
        retained = self._retained(plan)
        if retained is None or identity.pid is None:
            return None
        data = retained["program"]["dataDirectory"]
        try:
            config = ssh_transport.load_config(self.configuration_root)
            with self._admitted(config, plan, _OBSERVE_SECONDS):
                reply = self._send(config, plan.host, _py(_COLLECT, data), seconds=_OBSERVE_SECONDS)
                if reply is None or reply.get("state") != "collected":
                    return None
                raw = base64.b64decode(reply["receipt"], validate=True)
                summary = self._summary(plan, raw, reply.get("jobExit"))
                if summary is not None and not self._decision_joined(config, plan, summary):
                    return None  # A deny row passes only with its decision's own terminal; until then it is unknown.
                if summary is not None:
                    self._pull_evidence(config, plan, data, json.loads(raw).get("evidence"))
        except (OSError, ValueError, KeyError, TypeError, ssh_transport.SshConfigError):
            return None
        return summary

    def _decision_joined(self, config: Any, plan: native_scenario_execution.ScenarioPlan, summary: dict[str, Any]) -> bool:
        """A passed deny row joins its decision's input terminal: input-ack-only, deny, the prompt closed.

        An expired prompt ends as the same public CANCELLED as Esc, so the receipt alone cannot tell a deny from no answer.
        """
        uac = _row(plan.scenario_id).get("uac") or {}
        if uac.get("decision") != "deny" or summary["result"] != "passed":
            return True
        decision = str(uuid.uuid5(uuid.UUID(plan.correlation_id), "windows-uac-decision"))
        root = _binding(self.root, plan)["spec"]["root"]
        reply = self._send(config, plan.host, _py(_READ_DECISION, root, decision), seconds=_OBSERVE_SECONDS)
        value = reply.get("value") if isinstance(reply, Mapping) and reply.get("state") == "read" else None
        joined = (isinstance(value, Mapping) and set(value) == _DECISION_FIELDS and value["state"] == "input-ack-only"
                  and value["operationId"] == decision and value["decision"] == "deny" and value["prompt"] == uac["prompt"]
                  and value["promptClosed"] is True and value["approvalSucceeded"] is False and value["productOutcomeProved"] is False
                  and value["replayAllowed"] is False and type(value["attempt"]) is int)
        if joined:
            summary["windows"]["uacDecision"] = "deny-acknowledged-prompt-closed"
        return joined

    def _summary(self, plan: native_scenario_execution.ScenarioPlan, raw: bytes, job_exit: Any) -> dict[str, Any] | None:
        receipt = json.loads(raw)
        if (not isinstance(receipt, dict) or not isinstance(job_exit, Mapping) or job_exit.get("operationId") != plan.correlation_id
                or type(job_exit.get("exitCode")) is not int or receipt.get("exitCode") != job_exit["exitCode"]):
            return None
        task = receipt.get("task") if isinstance(receipt.get("task"), Mapping) else {}
        windows = receipt.get("windows") if isinstance(receipt.get("windows"), Mapping) else {}
        return {"state": "collected", "scenarioId": plan.scenario_id, "correlationId": plan.correlation_id,
                "result": receipt.get("result"), "exitCode": job_exit["exitCode"],
                "windows": {"evidenceClass": _row(plan.scenario_id)["evidenceClass"], "installedPackage": windows.get("installedPackage") is True,
                            "packageSha256": windows.get("packageSha256"), "taskDeleted": task.get("taskDeleted"),
                            "taskExitCode": task.get("ownerExitCode"), "taskEvents": task.get("events"),
                            "parked": task.get("parked"), "stoppedAfter": receipt.get("stoppedAfter"),
                            "failure": receipt.get("failure")},
                "actualReceiptRaw": raw.decode("utf-8"), "actualReceiptSha256": hashlib.sha256(raw).hexdigest()}

    def _pull_evidence(self, config: Any, plan: native_scenario_execution.ScenarioPlan, data: str, evidence: Any) -> None:
        """Raw evidence stays on the host until here; a collection is complete only with its bytes."""
        if evidence is None:
            return
        _need(isinstance(evidence, Mapping) and isinstance(evidence.get("name"), str) and _EVIDENCE_NAME.fullmatch(evidence["name"])
              and type(evidence.get("bytes")) is int and 0 <= evidence["bytes"] <= _MAX_EVIDENCE and isinstance(evidence.get("sha256"), str),
              "windows_scenario_evidence_invalid")
        directory = _private_directory(self.configuration_root.joinpath(*_EVIDENCE_PARENT, plan.correlation_id))
        target = directory / evidence["name"]
        if target.exists():
            _need(native_scenario_bundle._hash(target) == evidence["sha256"], "windows_scenario_evidence_changed")
            return
        digest = hashlib.sha256()
        parts = []
        offset = 0
        while offset < evidence["bytes"]:
            reply = self._send(config, plan.host, _py(_PULL, data, evidence["name"], str(offset), str(_EVIDENCE_CHUNK)), seconds=_OBSERVE_SECONDS)
            _need(reply is not None and reply.get("size") == evidence["bytes"], "windows_scenario_evidence_unavailable")
            part = base64.b64decode(reply["data"], validate=True)
            _need(0 < len(part) <= _EVIDENCE_CHUNK, "windows_scenario_evidence_unavailable")
            digest.update(part)
            parts.append(part)
            offset += len(part)
        _need(offset == evidence["bytes"] and digest.hexdigest() == evidence["sha256"], "windows_scenario_evidence_changed")
        _create_private(target, b"".join(parts))
