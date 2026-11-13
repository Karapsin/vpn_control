"""Closed Windows scenario table and the one driver behind ScenarioExecutor.

A scenario is one detached durable job on the VM host (windows_scenario_host_job),
carried by ssh_program_execution_remote over the existing SSH owner. The VM is named
by ``host`` and ``environment``. No request supplies a path, argv, source or bytes:
every byte comes from this checkout and a differing bundle refuses before any journal.
``discover``, ``observe`` and ``collect`` only read; a lost submit reply is resolved
by correlation and the job is never submitted twice.
"""
from __future__ import annotations

import argparse
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
import sys
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
# The public route that started a job, recorded in its private local state before any connection.
ROUTES = frozenset({"direct", "mcp"})
ROUTE_NAME = "route.json"
_JOURNALS = (".rag_index", "native-scenario-executions")
_MATRIX_EVIDENCE = (".rag_index", "native-acceptance-evidence")

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
# scheduled-refresh is the owner's own scheduled subscription refresh with no GUI (windows_lifecycle_scheduled_cases).
# no-tray-close attaches the GUI on an owned desktop with no notification area and closes it once (windows_no_tray_desktop).
PROXY_VARIANTS = ("gui-pending", "find-best-success", "find-best-verification-failure", "find-best-cancel",
                  "generated", "custom", "large", "prepare-failure", "commit-readiness-failure", "sibling-off", "scheduled-refresh",
                  "no-tray-close")
_PROXY_BRANCH_VARIANTS = frozenset({"generated", "custom", "large", "prepare-failure", "commit-readiness-failure", "sibling-off"})
_PROXY_SCHEDULED_VARIANTS = frozenset({"scheduled-refresh"})
_PROXY_NO_TRAY_VARIANTS = frozenset({"no-tray-close"})
_PROXY_FILES = (("agent_tools/windows_ordinary_dedicated_driver.py", "driver", "data"), ("agent_tools/windows_lifecycle_cases.py", "cases", "data"),
                ("agent_tools/windows_lifecycle_runtime_stages.py", "runtime", "data"), ("scripts/windows_broker_fixture_observer.py", "observer", "data"),
                ("agent_tools/windows_lifecycle_runtime_fixture_worker.py", "fixture", "data"),
                ("scripts/integration/socks_http_fixture.py", "socks", "data"), ("scripts/integration/https_subscription_relay_fixture.py", "https", "data"))
_PROXY_TRAFFIC = (("agent_tools/windows_lifecycle_traffic_worker.py", "traffic", "data"),)
_PROXY_BRANCH = (("agent_tools/windows_runtime_branch_cases.py", "branches", "data"), ("agent_tools/windows_runtime_tcp_listeners.ps1", "listener", "data"))
_PROXY_SCHEDULED = (("agent_tools/windows_lifecycle_scheduled_cases.py", "scheduled", "data"),)
_PROXY_NO_TRAY = (("agent_tools/windows_no_tray_desktop.py", "noTray", "data"),)


def _proxy_row(variant: str) -> dict[str, Any]:
    """The driver's roles as published files, and the files the job makes for the literal harness (windows_scenario_proxy)."""
    branch, scheduled = variant in _PROXY_BRANCH_VARIANTS, variant in _PROXY_SCHEDULED_VARIANTS
    no_tray = variant in _PROXY_NO_TRAY_VARIANTS
    traffic = branch or scheduled or no_tray or variant == "gui-pending"
    row = _worker_row("product", "windows-proxy-lifecycle", ("targetPackage",),
                      _PROXY_FILES + (_PROXY_TRAFFIC if traffic else ()) + (_PROXY_BRANCH if branch else ())
                      + (_PROXY_SCHEDULED if scheduled else ()) + (_PROXY_NO_TRAY if no_tray else ()), prior=True, deadline=3600)
    row.update(proxy={"variant": variant},
               generated=(("harness", "proxy-harness.py"), ("certificate", "proxy-localhost.pem"), ("privateKey", "proxy-localhost.key"),
                          ("trustStore", "proxy-trust.jks"), *((("trafficInput", "proxy-traffic.json"),) if traffic else ())),
               extracted=(("runtimeTool", "sing-box.exe"),))
    return row


# windows-scoped-tun.<variant>: windows_tun_stages through the same action and runtime as the proxy rows. Active proxy A,
# pending VPN B, then an async restart or find-best raises the vpn-broker prompt, which only windows-uac-decision answers.
TUN_VARIANTS = ("restart-deny", "restart-grant", "find-best-deny", "find-best-grant")
_TUN_FILES = (("agent_tools/windows_tun_stages.py", "tun", "data"),)
_TUN_SAMPLER = (("agent_tools/windows_tun_direct_sampler.py", "sampler", "data"),)
# Refused before any journal, each with what is missing.
_TUN_REFUSED = {
    # The approved broker runs elevated as the approving administrator, so only the TUN SYSTEM collector's ready and off
    # records (windows_tun_native_observer) prove its image, its SID and its exact child. No stage of this job discovers the
    # broker and its runtime for that collector's request, and the dedicated driver has no TUN close hold or record handoff.
    "restart-grant": "windows_scenario_tun_grant_unproven",
    "find-best-grant": "windows_scenario_tun_grant_unproven",
    # Find Best validates every candidate before it prepares the broker, so its prompt follows the pending event by an
    # unmeasured time that the decision's 30 s gate may not cover; the decision table has no find-best row.
    "find-best-deny": "windows_scenario_tun_find_best_unproven",
}


def _tun_row(variant: str) -> dict[str, Any]:
    """A proxy-lifecycle row plus the TUN stages, the decision of its prompt and, for a grant, the direct sampler."""
    grant = variant.endswith("-grant")
    row = _worker_row("product", "windows-proxy-lifecycle", ("targetPackage",),
                      _PROXY_FILES + _TUN_FILES + (_TUN_SAMPLER if grant else ()), prior=True, deadline=3600)
    row.update(proxy={"variant": variant}, tun={"variant": variant},
               generated=(("harness", "proxy-harness.py"), ("certificate", "proxy-localhost.pem"), ("privateKey", "proxy-localhost.key"),
                          ("trustStore", "proxy-trust.jks"), *((("samplerInput", "tun-direct-traffic.json"),) if grant else ())),
               extracted=(("runtimeTool", "sing-box.exe"),), refusal=_TUN_REFUSED.get(variant))
    if not variant.startswith("find-best"):
        # windows_uac_decision.ROWS answers the restart prompt; collect joins a deny row's own input terminal.
        row["uac"] = {"prompt": "vpn-broker", "decision": "approve" if grant else "deny", "event": "scoped-tun-awaiting-current-input"}
        row["denyJoin"] = not grant
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
# Refused before any journal, each with exactly what is still missing.
_UPDATE_REFUSED = {
    # The cancelled job's coordinator and worker live only from the approval to the product's own CANCELLED, which
    # follows the cancel the owner already sent, and the product keeps no record of the coordinator (its
    # input-custody.json is written on success alone). terminal-actors needs both identities and no stage can see them.
    "install-cancelled": "windows_scenario_update_cancel_actors_unobserved",
    # The host job passes no fault inputs, so update_cases refuses its blocking copy, and no stage serves fault-ready
    # with the participating copy's actor.
    "participating-copy-lock": "windows_scenario_update_copy_lock_fixture_unavailable",
    # The host job passes initialIntent off with no loopback connection profile and no traffic inputs.
    "success-reconnect": "windows_scenario_update_reconnect_fixture_unavailable",
    # The fixture has one administrator account (windows_vm_unattend: user and administrator), the decision approves
    # only with final-administrator.secret, and the context reads only that account's SID. A second approving
    # administrator needs a second Administrators account, its credential and a decision row that types it.
    "different-admin": "windows_scenario_update_second_administrator_unavailable",
    # No producer: the product's MSIs carry no LaunchCondition table for the failing-MSI derivation, and nothing
    # creates or removes a counterfeit protected-storage root.
    "native-install-failed": "windows_scenario_update_fault_unavailable",
    "protected-storage-rejected": "windows_scenario_update_fault_unavailable",
}
# The stages each variant's owner asks a SYSTEM collector for, the last one behind the caller's close hold. A grant's
# before-install also finds the controller the helper will name, authorization the live coordinator and worker,
# terminal-actors their exit beside the protected terminal and returned-cleanup the returned owner's exit.
_GRANT_STAGES = ("before-install", "authorization", "terminal-actors", "returned-cleanup")
_UPDATE_COLLECTORS = {"uac-denied": (("before-install", "terminal-actors"), "terminal-actors"),
                      **{variant: (_GRANT_STAGES, "returned-cleanup") for variant in ("success-off", "wait-client-loss", "installer-wait-client-loss")}}


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


# The document family: the shared worker's document-acceptance action with one fixed case module per row, the three
# document modules that action names and the public harness. The publisher makes the large routing document in the
# guest from a fixed recipe the job checks, and one spool parent under the operation root.
_DOCUMENT_FILES = (("agent_tools/windows_document_client.py", "client", "data"),
                   ("agent_tools/windows_document_native.py", "windows", "data"),
                   ("agent_tools/windows_document_export_race.py", "race", "data"), *_HARNESS)
# windows-document-cold.<variant>: the cold module's variants, and cache-bytes, which has no producer yet. gui-owner is
# the CLI's transfer through a GUI-started owner, never gui-cli-transfer: the GUI's own import and export have no tool.
DOCUMENT_COLD_VARIANTS = ("cold-reopen", "legacy-newline", "gui-owner", "cache-bytes")
# The committed subscription cache is filled only by a refresh from a subscription source, and this route has no
# in-guest subscription fixture for a document row: refused before any journal, with what is missing.
_DOCUMENT_REFUSED = {"cache-bytes": "windows_scenario_document_cache_fixture_unavailable"}


def _document_row(cases: str, variant: str | None = None) -> dict[str, Any]:
    row = _worker_row("product", "document-acceptance", ("targetPackage",), ((cases, "cases", "data"), *_DOCUMENT_FILES),
                      prior=True, deadline=7200 if variant is None else 3600)
    # Only the acceptance row probes a second principal: its owner opens the window during the expiry wait.
    row["document"] = {"variant": variant, "principalProbe": variant is None, "rootSubfolders": (host_job.DOCUMENT_TEMP,)}
    if variant is not None:
        row["generated"] = (*((("legacyInput", host_job.DOCUMENT_LEGACY_INPUT),) if variant == "legacy-newline" else ()),
                            ("coldInput", host_job.DOCUMENT_COLD_INPUT))
    row["refusal"] = _DOCUMENT_REFUSED.get(variant)
    return row


# windows-document-responsive: the same action, document modules and harness with the responsive case module, plus the
# responsiveWork sources the planner and owner pin by digest (DOCUMENT_RESPONSIVE_SOURCES): the responsive cases, the
# runtime stages they borrow, the gated HTTPS work fixture and its two producers. The job makes the fixture's localhost
# TLS material as it does the proxy rows'. No principal probe: only the acceptance row runs one.
_RESPONSIVE_CASES = ("agent_tools/windows_document_responsive_cli_cases.py", "cases", "data")
_RESPONSIVE_FILES = (("agent_tools/windows_document_responsive_cases.py", "responsive", "data"),
                     ("agent_tools/windows_lifecycle_runtime_stages.py", "runtime", "data"),
                     ("agent_tools/windows_document_gated_https_fixture.py", "workFixture", "data"),
                     ("scripts/integration/socks_http_fixture.py", "socks", "data"),
                     ("scripts/integration/https_subscription_relay_fixture.py", "https", "data"))


def _responsive_row() -> dict[str, Any]:
    row = _worker_row("product", "document-acceptance", ("targetPackage",), (_RESPONSIVE_CASES, *_DOCUMENT_FILES, *_RESPONSIVE_FILES),
                      prior=True, deadline=3600)
    row["document"] = {"variant": host_job.DOCUMENT_RESPONSIVE, "principalProbe": False, "rootSubfolders": (host_job.DOCUMENT_TEMP,)}
    row["generated"] = host_job.RESPONSIVE_TLS
    row["refusal"] = None
    return row


# windows-disconnected-cli-config.ssh-relay-transfer: the same owner action and harness as the disconnected rows, its own
# case module, the in-guest SSH relay fixture (an SSH server and its home SOCKS relay), the pinned SOCKS fixture as the
# selected location, and the origin's localhost certificate, key and trust store, which the job makes as for the
# responsive row. The case module scopes the serve's JVM to that store and imports its key on stdin.
_SSH_RELAY_FILES = (("agent_tools/windows_ssh_relay_cases.py", "cases", "data"),
                    ("agent_tools/windows_ssh_relay_fixture.py", "relay", "data"),
                    ("scripts/integration/socks_http_fixture.py", "socks", "data"), *_HARNESS)


def _ssh_relay_row() -> dict[str, Any]:
    row = _worker_row("product", "disconnected-cli-config", ("targetPackage",), _SSH_RELAY_FILES, prior=True, deadline=7200)
    row.update(generated=host_job.SSH_RELAY_TLS, sshRelay={"variant": "relay-transfer"}, refusal=None)
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
    # A closed variant of the disconnected row: the same owner action and harness with its own case module,
    # SSH key import, the SSH Routing truth table and route choice, and routing import with their guards.
    "windows-disconnected-cli-config.ssh-import-routing": _worker_row(
        "product", "disconnected-cli-config", ("targetPackage",),
        (("agent_tools/windows_ssh_import_routing_cases.py", "cases", "data"), *_HARNESS), prior=True, deadline=7200),
    # A stdin key import and refreshes through a real in-guest SSH relay: disconnected, connected, after disconnecting,
    # with an unpinned relay host key and with the relay stopped.
    "windows-disconnected-cli-config.ssh-relay-transfer": _ssh_relay_row(),
    "windows-autostart-migration.pre": _reboot_row("windows-autostart-migration", "pre", "autostart-migration"),
    "windows-autostart-migration.post": _reboot_row("windows-autostart-migration", "post", "autostart-migration"),
    "windows-reboot-reconnect.pre": _reboot_row("windows-reboot-reconnect", "pre", "reconnect"),
    "windows-reboot-reconnect.post": _reboot_row("windows-reboot-reconnect", "post", "reconnect"),
    "windows-reboot-explicit-off.pre": _reboot_row("windows-reboot-explicit-off", "pre", "explicit-off"),
    "windows-reboot-explicit-off.post": _reboot_row("windows-reboot-explicit-off", "post", "explicit-off"),
    # Rebootless: a query starts a transient owner that never connects, then a GUI restores intent once.
    "windows-query-owner-gui-reconnect": _reboot_row("windows-query-owner-gui-reconnect", "none", "query-first"),
    **{"windows-proxy-lifecycle." + variant: _proxy_row(variant) for variant in PROXY_VARIANTS},
    **{"windows-scoped-tun." + variant: _tun_row(variant) for variant in TUN_VARIANTS},
    **{"windows-public-update." + variant: _update_row(variant) for variant in UPDATE_VARIANTS},
    "windows-document-acceptance": _document_row("agent_tools/windows_document_cli_cases.py"),
    **{"windows-document-cold." + variant: _document_row("agent_tools/windows_document_cold_cases.py", variant)
       for variant in DOCUMENT_COLD_VARIANTS},
    "windows-document-responsive": _responsive_row(),
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
    # It is admitted only where collect joins the decision's own input terminal. A row is a deny row by its decision
    # or by its name, so a "-deny" variant with no decision row is refused here too.
    uac = row.get("uac") or {}
    deny = uac.get("decision") == "deny" or str(request.get("scenarioId")).endswith("-deny")
    _need(not deny or uac.get("decision") == "deny" and row.get("denyJoin") is True, "windows_scenario_deny_needs_decision_join")
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
    if row.get("update") or row.get("tun"):
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
    """Private adapter. ``stop_after`` is constructor wiring for the direct script, never request data.

    ``route`` is wiring too: ``mcp`` only from native_scenario_ssh, the delegate mcp_server builds, and
    ``direct`` for a script that builds this driver itself. Submit records it before any connection.
    """

    def __init__(self, repository_root: Path | str, bundle_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str],
                 timeout_seconds: int = 30, ssh_binary: str = "ssh", configuration_root: Path | str | None = None,
                 *, stop_after: str | None = None, route: str = "direct"):
        _need(stop_after is None or stop_after in host_job.STOP_AFTER, "windows_scenario_stop_after_invalid")
        _need(route in ROUTES, "windows_scenario_route_invalid")
        self.root = Path(repository_root).resolve()
        self.configuration_root = Path(configuration_root).resolve() if configuration_root is not None else self.root
        self.bundle_resolver = bundle_resolver
        self.timeout_seconds = timeout_seconds
        self.ssh_binary = ssh_binary
        self.stop_after = stop_after
        self.route = route

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
        # Which public route started this job; the matrix needs a direct and an MCP twin of every row.
        _create_private(directory / ROUTE_NAME, json.dumps({"schemaVersion": 1, "correlationId": plan.correlation_id,
                                                            "route": self.route}, sort_keys=True).encode())
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


# The matrix. One reviewed table, built from design.md adapter steps 4-8 with the row names the code accepts:
# each Windows-applicable requirement scenario and the rows whose passed direct and MCP runs together prove it.
# () is a scenario no built row proves yet, which stays missing; its comment names what design.md wants.
# windows-visual stays on visual_platform and visual_review; android-48m-heap is no Windows scenario.
_U, _P = "windows-public-update.", "windows-proxy-lifecycle."
_SMK, _CFG, _STR, _QRY = ("windows-packaged-cli-smoke", "windows-disconnected-cli-config", "windows-streaming-client-interrupt",
                          "windows-query-owner-gui-reconnect")
_DOC, _RSP, _CLD = "windows-document-acceptance", "windows-document-responsive", "windows-document-cold."
_SSH, _RLY = "windows-disconnected-cli-config.ssh-import-routing", "windows-disconnected-cli-config.ssh-relay-transfer"
MATRIX_SCENARIOS: dict[str, dict[str, tuple[str, ...]]] = {
    "windows-native-cli": {
        "msi-installer": (_U + "success-off", _U + "native-install-failed"),
        "public-update": (_U + "public-ready", _U + "download-cancelled", _U + "checksum-rejected", _U + "wait-client-loss",
                          _U + "success-off"),
        "packaged-public-cli": (_SMK, _CFG),
        "stdout-stderr-exit": (_CFG, _STR),
        "unicode-space-path": (_SMK, _CFG),
        "config-parity": (_CFG, _P + "generated", _P + "custom", _P + "large"),
        # RSP brings the owner-held refresh's status, cancel and wait; UPD(install-cancelled) is refused at admission today.
        "operation-progress-cancellation": (_CFG, _STR, _RSP, _P + "find-best-cancel", _U + "download-cancelled", _U + "install-cancelled"),
        "ordinary-user": (_CFG, _P + "find-best-success"),
        # TUN(approve) and UPD(success-off). The TUN grant rows exist but are refused at admission (windows_scenario_tun_grant_unproven).
        "scoped-elevation": (),
        "headless-serve": (_SMK, _P + "find-best-success"),
        # design.md: PRX(gui-pending, no-tray-close). gui-pending proves an attach, a crash and the at-once re-attach under
        # one sampler and one runtime, but a crash is no detach (DESKTOP-001 names them apart). On Windows a GUI detaches
        # only when it closes without a tray (Main.kt onCloseRequest): no-tray-close attaches one on an owned desktop with
        # no notification area and proves its close's detach, the lease released, under its own sampler and runtime.
        "gui-attach-detach": (_P + "gui-pending", _P + "no-tray-close"),
        "runtime-owner": (_P + "sibling-off",),
        "traffic-continuity": (_P + "gui-pending", _U + "success-reconnect"),
        "find-best": (_P + "find-best-success", _P + "find-best-verification-failure", _P + "find-best-cancel"),
        # SSH proves import, the SSH Routing truth table and route choice; RLY a stdin key import and refreshes through a
        # real in-guest relay, connected and disconnected, an unpinned host key and a stopped relay without fallback.
        "ssh-import-routing": (_SSH, _RLY),
    },
    "windows-visual": {"scene-capture": (), "geometry-contrast": (), "agent-verdict": ()},
    "windows-installer-lifecycle": {
        "msi-uac-grant-denial": (_U + "success-off", _U + "uac-denied", _U + "install-cancelled"),
        "ordinary-elevated-owner": (_U + "success-off", _U + "success-reconnect"),
        "different-approving-admin": (_U + "different-admin",),
        "original-user-worker": (_U + "success-off", _U + "different-admin"),
        "participating-copy-locks": (_U + "participating-copy-lock",),
        "protected-storage-adversarial": (_U + "protected-storage-rejected",),
        "next-owner-recovery": (_U + "success-off", _U + "wait-client-loss", _U + "installer-wait-client-loss"),
        "reconnect-off-preserved": (_U + "success-off", _U + "success-reconnect", "windows-reboot-reconnect.pre",
                                    "windows-reboot-reconnect.post"),
    },
    "windows-scoped-vpn": {
        "standard-user-gui-proxy": (_P + "gui-pending",),
        "scoped-uac-tun-traffic": (),  # TUN(approve): the grant rows are refused at admission (windows_scenario_tun_grant_unproven).
        "denial-preserves-active-a": ("windows-scoped-tun.restart-deny",),
        "prepare-commit-recovery": (),  # PRX(prepare-failure, commit-readiness-failure) and TUN(fault), which has no row.
        "exact-child-stop": (),  # PRX(sibling-off) and TUN(approve), whose grant rows are refused at admission.
        "generated-custom-config": (),  # PRX(generated, custom) and TUN(config).
        "large-config": (),  # PRX(large) and TUN(config).
        "dns-ws-ssh-cache-resources": (),  # Reserved: no case module.
        "pipe-storage-races": (),  # Reserved: no case module.
        "ordinary-autostart-migration": ("windows-autostart-migration.pre", "windows-autostart-migration.post"),
    },
    "windows-owner-lifecycle": {
        "attach-traffic": (_P + "gui-pending",),
        "hide-show-traffic": (_P + "gui-pending",),
        # design.md: PRX(gui-pending, no-tray-close). A close detaches only without a usable tray (DESKTOP-002, Main.kt
        # onCloseRequest), and gui-pending's close hides into the shell's tray. no-tray-close runs the GUI on an owned
        # desktop with no Shell_TrayWnd: its WM_CLOSE must end and detach the GUI while the sampler and runtime go on.
        "close-detach-traffic": (_P + "no-tray-close",),
        "gui-crash-traffic": (_P + "gui-pending",),
        "cli-disconnect-long-work": (_RSP,),
        "scheduled-without-gui": (_P + "scheduled-refresh",),
        "missing-owner-status-no-start": (_SMK, _CFG),
        "static-discovery-no-workspace": (_SMK, _CFG),
        "transient-query-owner": (_SMK, _QRY),
        "disconnected-serve": (_P + "gui-pending",),
        "explicit-off-intent": (_P + "gui-pending", "windows-reboot-explicit-off.pre", "windows-reboot-explicit-off.post"),
        "query-owner-gui-reconnect": (_QRY,),
    },
    # Limited: android-48m-heap is no Windows scenario (MATRIX_LIMITED).
    "document-persistence-transfer": {
        "large-import-readback": (_DOC, _CFG),
        "exact-retry-no-op": (_DOC,),
        "retained-result-export": (_DOC, _CFG),
        "cold-independent-reopen": (_CLD + "cold-reopen",),
        "protobuf-newline-compatibility": (_CLD + "legacy-newline",),
        # CLD(cache-bytes) is a closed name refused before any journal: no in-guest subscription fixture fills the cache.
        "cache-digest-bytes": (),
        "failed-persistence": (_DOC,),
        "mutable-input-resource-failure": (_DOC,),
        # The second real principal is DOC's own LOCAL SERVICE probe: a DOC row passes only with it observed denied, and
        # a DOC run whose owner passed but whose probe proved no denial fails this scenario alone (MATRIX_PRINCIPAL).
        "wrong-principal-owner-context-kind": (_DOC,),
        "expiry-forged-id-hash-length": (_DOC,),
        "interruption-response-loss": (_DOC,),
        "responsive-status-cancel": (_RSP,),
        "private-no-overwrite-export": (_DOC, _CFG),
        "racing-parent-destination": (_DOC,),
        "unicode-surrogate": (_DOC, _CFG),
        # The GUI's own file-picker import and export have no tool. CLD(gui-owner) is only the CLI half and never counts.
        "gui-cli-transfer": (),
    },
}
# A shared requirement Windows can only partly prove: recorded as limited, its other platforms' scenarios missing.
MATRIX_LIMITED = {"document-persistence-transfer": ("android-48m-heap",)}
# The one verdict on the product a job reaches after its owner passed: the acceptance row's LOCAL SERVICE probe that proved
# no denial of the owner-private endpoint (document_principal_not_denied). Such a run is failed-principal, a failure of
# this scenario alone; for the row's other scenarios it never counts, and it holds a pass only of this requirement.
MATRIX_PRINCIPAL = {"document-persistence-transfer": "wrong-principal-owner-context-kind"}
_PRINCIPAL_FAILURE = "document_principal_not_denied"
_COLLECTION_FINAL_UNKNOWN = frozenset({"collector_output_limit"})  # Overflow stays unknown; other misses may collect later.
# The durable job's own final UNKNOWNs (durable_remote_job.observe): an owner gone without a terminal, a host boot since
# submit, a terminal whose stream overflowed. A missed read or any other reason may still settle on the next status.
_DURABLE_FINAL_UNKNOWN = frozenset({"original_owner_missing", "boot_changed", "output_overflow"})


def _matrix_module():
    try:
        from . import native_acceptance_matrix
    except ImportError:  # pragma: no cover - script-style fallback
        import native_acceptance_matrix  # type: ignore[no-redef]
    return native_acceptance_matrix


def _matrix_requirement(requirement_id: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    _need(isinstance(requirement_id, str) and requirement_id in MATRIX_SCENARIOS, "windows_matrix_requirement_unknown")
    matrix = _matrix_module()
    try:
        requirements = matrix.load_requirements()
    except matrix.NativeAcceptanceMatrixError:
        raise NativeScenarioWindowsError("windows_matrix_ledger_unavailable") from None
    requirement = requirements[requirement_id]
    applicable = [name for name in requirement["requiredScenarios"] if name not in MATRIX_LIMITED.get(requirement_id, ())]
    _need(set(MATRIX_SCENARIOS[requirement_id]) == set(applicable), "windows_matrix_table_differs")
    return requirement, requirements


def _route(root: Path, correlation: str) -> str | None:
    try:
        value = _read_private(root.joinpath(*_LOCAL_STATE, correlation, ROUTE_NAME))
    except (OSError, ValueError):
        return None
    if (isinstance(value, dict) and set(value) == {"schemaVersion", "correlationId", "route"} and value["schemaVersion"] == 1
            and value["correlationId"] == correlation and value["route"] in ROUTES):
        return value["route"]
    return None


def _matrix_row(root: Path, correlation: str) -> dict[str, Any]:
    """One row as the matrix reads it, from its journal, its input and its route only; nothing is collected."""
    try:
        record = native_scenario_execution.ScenarioExecutor(root.joinpath(*_JOURNALS), None)._read(correlation)
    except (native_scenario_execution.ScenarioExecutionError, OSError, ValueError):
        record = None
    _need(record is not None, "windows_matrix_journal_unavailable:" + correlation)
    plan = native_scenario_execution.ScenarioPlan.from_mapping(record["plan"])
    _need(plan.scenario_id in RECIPES, "windows_matrix_not_windows_row:" + correlation)
    row = RECIPES[plan.scenario_id]
    facts = {"correlationId": correlation, "scenarioId": plan.scenario_id, "deploymentId": plan.environment,
             "route": _route(root, correlation), "classification": "setup", "receiptSha256": None,
             "exitCode": record.get("exitCode"), "stage": None, "failure": None}
    if row["evidenceClass"] in SETUP_OR_COMPONENT:
        return facts
    try:
        value = scenario_input(root, plan, row)
    except NativeScenarioWindowsError:
        raise NativeScenarioWindowsError("windows_matrix_input_unavailable:" + correlation) from None
    facts.update(sourceSha=value["sourceSha"], productVersion=value["productVersion"], artifactSetId=value["artifactSetId"],
                 packages=sorted(plan.artifact_ids[key] for key in ("targetPackage", "fixtureReceipt") if key in plan.artifact_ids),
                 targetPackage=plan.artifact_ids["targetPackage"])
    collection = record.get("collection") or {}
    if record["state"] == native_scenario_execution.ExecutionState.TERMINAL.value and collection.get("state") == "complete":
        summary = json.loads(collection["rawJson"])
        raw = summary["actualReceiptRaw"]
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        _need(digest == summary["actualReceiptSha256"], "windows_matrix_receipt_changed:" + correlation)
        receipt = json.loads(raw)
        task = receipt.get("task") if isinstance(receipt.get("task"), dict) else {}
        facts.update(receiptSha256=digest, stage=host_job.token(receipt.get("stage")) if receipt.get("stage") else None,
                     failure=host_job.token(receipt.get("failure")) if receipt.get("failure") else None)
        public = public_evidence(native_scenario_execution.ScenarioExecutor._public(record))
        if receipt.get("stoppedAfter") is not None:
            kind = "stopped"
        elif receipt.get("result") == "passed":
            kind = "passed" if public["evidenceClass"] == "installed-package" else "installed-package-unproven"
        elif receipt.get("result") == "failed":
            # A verdict on the installed product needs its task to have run, and is the owner's own: its exit 1, which a
            # case oracle failure ends with. An earlier stop is the row's setup; a failure after the task (the task journal,
            # the command line read, the evidence copy, the declaration, another exit) is the harness's.
            if task.get("state") != "task-finished":
                kind = "failed-before-task"
            elif receipt.get("failure") == "task_exit_code" and all(type(task.get(key)) is int and task[key] == 1
                                                                   for key in ("ownerExitCode", "terminalExitCode")):
                kind = "failed"
            elif (receipt.get("failure") == _PRINCIPAL_FAILURE and (row.get("document") or {}).get("principalProbe") is True
                  and all(type(task.get(key)) is int and task[key] == row["expectedExit"] for key in ("ownerExitCode", "terminalExitCode"))):
                # The owner passed, and the row's own LOCAL SERVICE probe proved no denial: the product's verdict on its
                # owner-private endpoint (MATRIX_PRINCIPAL). The probe's other ends are the harness's.
                kind = "failed-principal"
            else:
                kind = "failed-after-task"
        else:
            raise NativeScenarioWindowsError("windows_matrix_receipt_changed:" + correlation)
    elif record["state"] == native_scenario_execution.ExecutionState.TERMINAL.value and record["exitCode"] == host_job.EXIT_REFUSED:
        kind = "refused"  # Refused before any guest effect: no claim of any kind.
    elif (record["state"] == native_scenario_execution.ExecutionState.UNKNOWN.value
          and (record["lastReason"].startswith("job_exit_unknown:") or record["lastReason"] in _DURABLE_FINAL_UNKNOWN)
          or record["state"] == native_scenario_execution.ExecutionState.TERMINAL.value
          and collection.get("reason") in _COLLECTION_FINAL_UNKNOWN):
        kind = "unknown"
    else:
        raise NativeScenarioWindowsError("windows_matrix_row_unsettled:" + correlation)
    facts["classification"] = kind
    return facts


def _matrix_row_state(rows: list[Mapping[str, Any]], name: str, principal: bool = False) -> str:
    """A row proves its part only with a passed direct run and a passed MCP run; a failure or an unknown wins.

    A failed-principal run fails only the scenario its probe proves (principal); for any other it never counts.
    """
    found = [row for row in rows if row["scenarioId"] == name]
    kinds = {row["classification"] for row in found}
    if "failed" in kinds or principal and "failed-principal" in kinds:
        return "failed"
    if "unknown" in kinds:
        return "unknown"
    routes = {row["route"] for row in found if row["classification"] == "passed"}
    return "passed" if ROUTES <= routes else "missing"


def matrix_review(root: Path | str, requirement_id: str, correlation_ids: Any) -> dict[str, Any]:
    """Read only: each named row's class and route, and the state of every scenario of one requirement."""
    requirement, _ = _matrix_requirement(requirement_id)
    root = Path(root).resolve()
    _need(isinstance(correlation_ids, (list, tuple)) and 0 < len(correlation_ids) <= 256
          and len(set(correlation_ids)) == len(correlation_ids), "windows_matrix_correlations_invalid")
    for correlation in correlation_ids:
        _canonical_uuid(correlation, "windows_matrix_correlations_invalid")
    rows = [_matrix_row(root, correlation) for correlation in correlation_ids]
    product = [row for row in rows if row["classification"] != "setup"]
    # One package: every product row names the same source, version, frozen set and target package.
    for key, reason in (("sourceSha", "windows_matrix_mixed_source"), ("productVersion", "windows_matrix_mixed_source"),
                        ("artifactSetId", "windows_matrix_mixed_source"), ("targetPackage", "windows_matrix_mixed_package")):
        _need(len({row[key] for row in product}) <= 1, reason)
    scenarios = {}
    for scenario, names in MATRIX_SCENARIOS[requirement_id].items():
        if not names or any(name not in RECIPES for name in names):
            scenarios[scenario] = "unmapped"
            continue
        principal = MATRIX_PRINCIPAL.get(requirement_id) == scenario
        states = {_matrix_row_state(rows, name, principal) for name in names}
        scenarios[scenario] = next((state for state in ("failed", "unknown", "missing") if state in states), "passed")
    return {"requirementId": requirement_id, "platform": requirement["platform"], "rows": rows, "scenarios": scenarios,
            "package": None if not product else {key: product[0][key] for key in ("sourceSha", "productVersion", "artifactSetId",
                                                                                     "targetPackage")}}


def _settled_runs(root: Path, names: set[str], target: str) -> list[dict[str, Any]]:
    """Every settled run of these rows on this target package, named or not, read from the journals alone.

    A run still unsettled has no outcome to record yet; any other refusal of a matching run refuses the scan.
    """
    journals = root.joinpath(*_JOURNALS)
    executor = native_scenario_execution.ScenarioExecutor(journals, None)
    try:
        paths = sorted(journals.glob("*.json"))
    except OSError:
        raise NativeScenarioWindowsError("windows_matrix_journals_unavailable") from None
    runs = []
    for path in paths:
        correlation = path.name[:-len(".json")]
        try:
            _canonical_uuid(correlation, "windows_matrix_correlations_invalid")
            record = executor._read(correlation)
        except (NativeScenarioWindowsError, native_scenario_execution.ScenarioExecutionError, OSError, ValueError):
            continue  # Not a scenario journal of a readable row.
        if (record is None or record["plan"]["scenarioId"] not in names
                or record["plan"]["artifactIds"].get("targetPackage") != target):
            continue
        try:
            runs.append(_matrix_row(root, correlation))
        except NativeScenarioWindowsError as error:
            if not str(error).startswith("windows_matrix_row_unsettled:"):
                raise
    return runs


def _recorded_rows(root: Path, earlier: list[Mapping[str, Any]], requirement_id: str, source: str) -> set[str]:
    """The rows every recorded observation of this requirement and source named, retracted or not."""
    matrix = _matrix_module()
    named: set[str] = set()
    for item in earlier:
        if (item["requirementId"] != requirement_id or item["originalSourceSHA"] != source
                or not item["evidencePath"].startswith("/".join(_MATRIX_EVIDENCE) + "/")):
            continue
        try:
            matrix._verify_evidence(root, item["evidencePath"], item["evidenceHash"])
            document = json.loads(root.joinpath(*PurePosixPath(item["evidencePath"]).parts).read_bytes())
            named.update(row["correlationId"] for row in document["rows"])
        except (matrix.NativeAcceptanceMatrixError, OSError, ValueError, KeyError, TypeError):
            continue  # Evidence that no longer verifies names no row.
    return named


def _matrix_evidence(root: Path, requirement_id: str, document: Mapping[str, Any]) -> tuple[str, str]:
    matrix = _matrix_module()
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    name = requirement_id + "-" + digest[:12] + ".json"
    path = root.joinpath(*_MATRIX_EVIDENCE, name)
    try:
        _private_directory(path.parent)
        if not os.path.lexists(path):
            # The ledger's own publish: a synced private temporary file linked create-only under the name, so an
            # interrupted write never leaves part of a document there.
            matrix._exclusive_write(path, raw)
    except (matrix.NativeAcceptanceMatrixError, OSError):
        if not os.path.lexists(path):
            raise NativeScenarioWindowsError("windows_matrix_evidence_unavailable") from None
    # Create-only: the same document again is the same evidence; anything else under its name refuses.
    try:
        same = native_scenario_bundle._hash(path) == digest
    except OSError:
        same = False
    _need(same, "windows_matrix_evidence_differs")
    return "/".join((*_MATRIX_EVIDENCE, name)), digest


def matrix_observation(root: Path | str, requirement_id: str, correlation_ids: Any, reviewer_attestation: str) -> dict[str, Any]:
    """The matrix-record input for one requirement, from collected rows; it records nothing itself.

    A passed observation needs every scenario of the requirement passed: each of its rows passed directly and through
    MCP, all on one package, and every settled failed or unknown run of those rows on that package, named or not,
    already in a recorded observation of the requirement. A failed or unknown row yields a failed or unknown
    observation at once. Setup, stopped, refused, installed-package-unproven, failed-before-task and failed-after-task
    rows never count. A failed-principal run is a failed one of its MATRIX_PRINCIPAL scenario alone, and of no other.
    The attestation is the coordinator's, never this code's.
    """
    _need(isinstance(reviewer_attestation, str) and reviewer_attestation.strip() and len(reviewer_attestation) <= 240,
          "windows_matrix_attestation_invalid")
    root = Path(root).resolve()
    review = matrix_review(root, requirement_id, correlation_ids)
    requirement, requirements = _matrix_requirement(requirement_id)
    matrix = _matrix_module()
    states = review["scenarios"]
    results = {name: state for name, state in states.items() if state in ("failed", "unknown")}
    limited = MATRIX_LIMITED.get(requirement_id, ())
    if results:
        result = "failed" if "failed" in results.values() else "unknown"
        missing = sorted(set(requirement["requiredScenarios"]) - set(results))
    else:
        open_scenarios = [name for name, state in states.items() if state != "passed"]
        _need(not open_scenarios, "windows_matrix_incomplete:" + str(len(open_scenarios)))
        result, results, missing = "passed", dict(states), list(limited)
    counted = {name for scenario in results for name in MATRIX_SCENARIOS[requirement_id][scenario]}
    rows = [row for row in review["rows"] if row["scenarioId"] in counted and row["classification"] != "setup"]
    package = review["package"]
    _need(package is not None and rows, "windows_matrix_incomplete:" + str(len(states)))
    source = package["sourceSha"]
    if result == "passed":
        try:
            directory = matrix._existing_directory(root)
            earlier = [] if directory is None else matrix._records_read_only(directory, requirements)
            retracted = set() if directory is None else matrix._read_retractions(directory, requirements)
        except (matrix.NativeAcceptanceMatrixError, OSError):
            raise NativeScenarioWindowsError("windows_matrix_ledger_unavailable") from None
        # Recorded once: a passed record of this requirement and source that was not retracted refuses another.
        _need(not any(item["requirementId"] == requirement_id and item["originalSourceSHA"] == source and item["result"] == "passed"
                      and item["receiptId"] not in retracted for item in earlier), "windows_matrix_already_recorded")
        # Failed or unknown at once, so none is left out: a pass waits until every settled failed or unknown run of a
        # counted row on this package is in a recorded observation of this requirement, where it stands beside the pass.
        recorded = _recorded_rows(root, earlier, requirement_id, source)
        holding = {"failed", "unknown"} | ({"failed-principal"} if requirement_id in MATRIX_PRINCIPAL else set())
        unrecorded = sorted(run["correlationId"] for run in _settled_runs(root, counted, package["targetPackage"])
                            if run["classification"] in holding and run["correlationId"] not in recorded)
        _need(not unrecorded, "windows_matrix_unrecorded_outcome:" + "".join(unrecorded[:1]))
    artifacts = sorted({artifact for row in rows for artifact in row["packages"]})
    scope = "limited" if limited else "full-native"
    deployments = sorted({row["deploymentId"] for row in rows})
    environment = "windows-qemu-" + (deployments[0] if len(deployments) == 1 else
                                     str(len(deployments)) + "-clones-" + hashlib.sha256(",".join(deployments).encode()).hexdigest()[:12])
    document = {"schema": "vpn-control.windows-matrix-evidence", "schemaVersion": 1, "requirementId": requirement_id,
                "platform": requirement["platform"], "result": result, "evidenceScope": scope, "package": package,
                "immutableArtifactIDs": artifacts, "scenarios": states,
                "rowsByScenario": {name: list(MATRIX_SCENARIOS[requirement_id][name]) for name in results},
                "rows": [{key: row.get(key) for key in ("correlationId", "scenarioId", "deploymentId", "route", "classification",
                                                        "receiptSha256", "exitCode", "stage", "failure")} for row in review["rows"]]}
    path, digest = _matrix_evidence(root, requirement_id, document)
    observation = {"requirementId": requirement_id, "platform": requirement["platform"], "originalSourceSHA": source,
                   "immutableArtifactIDs": artifacts, "evidencePath": path, "evidenceHash": digest, "environment": environment,
                   "result": result, "scenarioResults": results, "missingEvidence": missing,
                   "nextFixedCommand": "none" if result == "passed" else "inspect-evidence",
                   "reviewerAttestation": reviewer_attestation, "evidenceScope": scope}
    try:
        matrix._stored_observation(observation, requirements)
        matrix._verify_evidence(root, path, digest)
        matrix._verify_artifacts_readonly(root, artifacts, requirement["platform"], source, scope)
    except (matrix.NativeAcceptanceMatrixError, OSError, ValueError) as error:
        raise NativeScenarioWindowsError("windows_matrix_record_invalid") from error
    return observation


def main(argv: list[str] | None = None) -> int:
    """Print one matrix observation for review: the record input on stdout, the row review on stderr. Records nothing."""
    parser = argparse.ArgumentParser(prog="native_scenario_windows")
    actions = parser.add_subparsers(dest="action", required=True)
    observe = actions.add_parser("matrix-observation")
    observe.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    observe.add_argument("--requirement", required=True)
    observe.add_argument("--reviewer-attestation", required=True)
    observe.add_argument("correlation", nargs="+")
    options = parser.parse_args(argv)
    try:
        print(json.dumps(matrix_review(options.root, options.requirement, options.correlation), indent=2, sort_keys=True), file=sys.stderr)
        observation = matrix_observation(options.root, options.requirement, options.correlation, options.reviewer_attestation)
    except NativeScenarioWindowsError as error:
        print(json.dumps({"refused": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(observation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
