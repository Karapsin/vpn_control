"""Proof and fencing primitives for a dead installer worker's first-check failure.

This module has no public CLI and no product action. A trusted native adapter must
measure the proof under its device lock, pin every input, call validate_proof,
then release_fenced while retaining that lock. Caller-supplied assertions are
not native evidence. The original installer outcome is always unknown.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import inspect
import fcntl
import shlex
import base64
import uuid
import ast
from contextlib import contextmanager
from typing import Any

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


def privileged_command(script: str) -> tuple[str, ...]:
    if not isinstance(script, str) or not script or "\x00" in script: raise ValueError("privileged_script_invalid")
    return (shlex.join(("/system/xbin/su", "0", "/system/bin/sh", "-c", script)),)


def validate_original(dispatch: dict[str, Any], product: dict[str, Any], correlation: str) -> None:
    bundle_ids = [dispatch.get("toolBundleId"), dispatch.get("toolBundle", {}).get("toolBundleId"),
                  dispatch.get("remote", {}).get("toolBundle", {}).get("toolBundleId")]
    bundle_ids = [value for value in bundle_ids if value is not None]
    if (correlation != "0dd55704-1e80-4d62-8d9d-2f0a123e0c3b" or
        dispatch.get("sourceSha") != "d32f719a08db57e5d40ce2bf77e0d7c5b42de557" or
        not bundle_ids or any(value != "sha256-64c3b9f8176515770db963dd5858d3044ebd969b8d460272eb9ef3f4c9deb7ac" for value in bundle_ids) or
        dispatch.get("remote", {}).get("sourceSha", dispatch.get("sourceSha")) != dispatch.get("sourceSha") or
        product.get("correlationId") != correlation or product.get("pair", {}).get("sourceSha") != dispatch.get("sourceSha")):
        raise ValueError("only_reviewed_original_allowed")
REQUIRED_FILES = frozenset({"dispatch.json", "identity.json", "output/intent.json",
    "output/lifecycle-receipt.json", "output/phase-check.json", "output/fixture-identity.json",
    "output/worker-finished.json", "output/fixture-receipt.json", "output/ready.json",
    "tool-bundle-owned.json", "opening-routing.json", "closing-routing.json",
    "closing-readback.json", "local-lease.json", "remote-lease.json",
    "bundle/agent_tools/android_installer_target.py", "bundle/scripts/android_installer_lifecycle.py",
    "bundle/scripts/android_no_update_tls_preflight.py", "bundle/scripts/android_fixture_preflight.py",
    "bundle/scripts/android_fixture_transport.py", "bundle/scripts/android_fixture_trust.py",
    "bundle/scripts/integration/android_update_fixture.py"})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode() + b"\n"


def routing_digest(document: dict[str, Any]) -> str:
    """Compare all version-seven rules, excluding export metadata timestamps."""
    if not isinstance(document, dict) or document.get("type") != "vpn_control_routing_rules" or document.get("version") != 7:
        raise ValueError("routing_format_invalid")
    rules = document.get("rules")
    if (not isinstance(rules, dict) or set(rules) != {"ignore_rules", "block_quic_udp_443", "proxy_packages", "direct_domain_suffixes"} or
        any(type(rules[key]) is not bool for key in ("ignore_rules", "block_quic_udp_443")) or
        any(not isinstance(rules[key], list) or any(not isinstance(item, str) for item in rules[key])
            for key in ("proxy_packages", "direct_domain_suffixes"))):
        raise ValueError("routing_rules_invalid")
    return hashlib.sha256(_canonical(rules)).hexdigest()


def measure_public_snapshot(read_public, export_routing, owner: str, revision: int,
                            installed_base_sha256: str, installer_preflight) -> dict[str, Any]:
    """Measure fixed getters using trusted authenticated native transport callbacks.

    Callbacks are adapter code, never tool arguments. export_routing must validate
    its successful final envelope against the same explicit owner/revision and
    return the complete bounded version-seven export. The adapter independently
    checks UID/device/base APK and holds the device lock throughout both calls.
    """
    if not isinstance(owner, str) or not owner or type(revision) is not int or revision < 0 or not isinstance(installed_base_sha256, str) or not _SHA.fullmatch(installed_base_sha256):
        raise ValueError("snapshot_binding_invalid")
    def read(*words):
        envelope = read_public(*words)
        if (not isinstance(envelope, dict) or envelope.get("ok") is not True or envelope.get("final") is not True or
            envelope.get("code") != "OK" or envelope.get("controllerId") != owner or
            type(envelope.get("configurationRevision")) is not int or envelope["configurationRevision"] != revision or
            not isinstance(envelope.get("data"), dict)):
            raise ValueError("snapshot_owner_or_final_changed")
        return envelope["data"]
    def stopped(status):
        if status.get("runtimeRunning") is not False or status.get("runtimeObservation") != "stopped":
            raise ValueError("snapshot_runtime_not_stopped")
    stopped(read("status"))
    operations = read("operations", "list").get("operations")
    if not isinstance(operations, list) or any(not isinstance(item, dict) or item.get("final") is not True for item in operations):
        raise ValueError("snapshot_operations_pending_or_unknown")
    settings = read("settings", "show"); source = read("source", "show")
    # This getter can reconcile installer receipts. The trusted adapter must
    # independently authenticate their absence and no OS session BEFORE it runs.
    installer_preflight()
    updates = read("updates", "status")
    if updates.get("phase") not in {"idle", "up_to_date", "unsupported", "failed"}:
        raise ValueError("snapshot_update_work_pending_or_unknown")
    if ("installReceipt" not in updates or updates["installReceipt"] is not None or
        updates.get("installRecoveryUnavailable") is not False or
        type(updates.get("legacyInstallerPins")) is not int or updates["legacyInstallerPins"] != 0):
        raise ValueError("snapshot_installer_pending_or_unknown")
    routing = routing_digest(export_routing())
    stopped(read("status"))
    return {"owner": owner, "revision": revision, "allFinal": True, "runtimeRunning": False,
        "runtimeObservation": "stopped", "packageSha256": installed_base_sha256,
        "routingSha256": routing, "settingsSha256": hashlib.sha256(_canonical(settings)).hexdigest(),
        "sourceSha256": hashlib.sha256(_canonical(source)).hexdigest(), "updateWorkIdle": True, "installerIdle": True}


def validate_proof(value: dict[str, Any]) -> dict[str, Any]:
    """Validate a measured proof; this alone does not authenticate its origin."""
    if not isinstance(value, dict): raise ValueError("retirement_proof_invalid")
    for key in ("originalCorrelationId", "retirementCorrelationId", "closingReadbackCorrelationId"):
        if not isinstance(value.get(key), str) or not _UUID.fullmatch(value[key]): raise ValueError("retirement_correlation_invalid")
    if value["originalCorrelationId"] == value["retirementCorrelationId"]: raise ValueError("retirement_requires_new_correlation")
    if value.get("originalOutcome") != "unknown": raise ValueError("original_outcome_must_remain_unknown")
    if value.get("historicalSettingsSource") != "unavailable" or value.get("productDataMutationAllowed") is not False:
        raise ValueError("historical_state_claim_or_product_mutation_forbidden")
    if not isinstance(value.get("sourceSha"), str) or not re.fullmatch(r"[0-9a-f]{40}", value["sourceSha"]): raise ValueError("source_invalid")
    if not isinstance(value.get("toolBundleId"), str) or not re.fullmatch(r"sha256-[0-9a-f]{64}", value["toolBundleId"]): raise ValueError("tool_bundle_invalid")
    for key in ("intentSha256", "lifecycleSha256"):
        if not isinstance(value.get(key), str) or not _SHA.fullmatch(value[key]): raise ValueError("receipt_hash_invalid")
    for key in ("worker", "fixture"):
        item = value.get(key)
        if (not isinstance(item, dict) or any(type(item.get(field)) is not int or item[field] < 1 for field in ("pid", "startTicks")) or item.get("stopped") is not True): raise ValueError("process_not_authenticated_stopped")
    if value["fixture"].get("portRefused") is not True: raise ValueError("fixture_listener_unproven")
    if value.get("phases") != {"check": True, "download": False, "noninteractive": False, "interactive": False}: raise ValueError("not_first_check_only")
    if any(type(value["phases"][key]) is not bool for key in value["phases"]): raise ValueError("phase_types_invalid")
    if value.get("failureType") != "RuntimeError" or value.get("cleanupFailures") != []: raise ValueError("failure_or_cleanup_unproven")
    if any(value.get(key) is not True for key in ("probeAbsent", "freshOwnerAdmission", "nativeRestored")): raise ValueError("fresh_admission_or_restoration_unproven")
    snapshots = value.get("snapshots"); opening = value.get("opening")
    if not isinstance(snapshots, list) or len(snapshots) != 2 or snapshots[0] != snapshots[1] or not isinstance(opening, dict): raise ValueError("two_equal_snapshots_required")
    snapshot = snapshots[0]
    if (not isinstance(snapshot, dict) or not isinstance(snapshot.get("owner"), str) or not snapshot["owner"] or
        type(snapshot.get("revision")) is not int or snapshot["revision"] < 0 or snapshot.get("allFinal") is not True or
        snapshot.get("runtimeRunning") is not False or snapshot.get("runtimeObservation") != "stopped" or
        snapshot.get("updateWorkIdle") is not True or snapshot.get("installerIdle") is not True):
        raise ValueError("fresh_stopped_owner_unproven")
    for key in ("packageSha256", "routingSha256", "settingsSha256", "sourceSha256"):
        if not isinstance(snapshot.get(key), str) or not _SHA.fullmatch(snapshot[key]): raise ValueError("snapshot_hash_invalid")
        if key in ("packageSha256", "routingSha256") and snapshot[key] != opening.get(key): raise ValueError("baseline_changed")
    if set(opening) != {"packageSha256", "routingSha256"}: raise ValueError("historical_settings_source_must_remain_unavailable")
    files = value.get("files")
    if not isinstance(files, dict) or set(files) != REQUIRED_FILES: raise ValueError("file_generations_missing")
    for name, item in files.items():
        if (not isinstance(name, str) or not name or not isinstance(item, dict) or
            not isinstance(item.get("sha256"), str) or not _SHA.fullmatch(item["sha256"]) or
            not isinstance(item.get("generation"), list) or len(item["generation"]) != 8 or
            any(type(part) is not int or part < 0 for part in item["generation"]) or
            item["generation"][5:] != [0o600, value.get("localLeaseUid") if name == "local-lease.json" else value.get("measurementUid"), 1]): raise ValueError("file_generation_invalid")
    if any(type(value.get(key)) is not int or value[key] < 0 for key in ("measurementUid", "localLeaseUid")): raise ValueError("measurement_uid_invalid")
    if (files["output/intent.json"]["sha256"] != value["intentSha256"] or
        files["output/lifecycle-receipt.json"]["sha256"] != value["lifecycleSha256"]): raise ValueError("proof_receipt_binding_changed")
    return json.loads(_canonical(value))


def validate_component_terminal_history(passes: list[dict[str, Any]], app_uid: int) -> dict[str, Any]:
    """Validate raw repeated terminal history; grant no ownership or release.

    The native adapter must authenticate every held/named descriptor and the
    original component/device/source guards. App metadata UID is independent
    of host measurement and public shell principals. AtomicFile backups or
    other additional files are refused in this measured three-receipt scope.
    """
    if type(app_uid) is not int or not 10000 <= app_uid <= 99999 or type(passes) is not list or len(passes) != 2:
        raise ValueError('component_terminal_history_invalid')
    outcomes=[]
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value: raise ValueError('component_receipt_duplicate_field')
            value[key]=item
        return value
    for observation in passes:
        if type(observation) is not dict or not {'rows','metadata','osInventory'} <= observation.keys():
            raise ValueError('component_terminal_history_invalid')
        metadata=observation['metadata'];rows=observation['rows']
        if type(metadata) is not dict or set(metadata)!={'no_backup/control-install-sessions','files/control-installs'}:
            raise ValueError('component_metadata_incomplete')
        if metadata['files/control-installs']!={'kind':'absent','generation':'','entries':[]}:
            raise ValueError('component_legacy_installer_present')
        directory=metadata['no_backup/control-install-sessions']
        if type(directory) is not dict or set(directory)!={'kind','generation','entries'} or directory['kind']!='directory':
            raise ValueError('component_metadata_incomplete')
        def generation(text,mode,kind):
            if type(text) is not str: raise ValueError('component_metadata_principal_changed')
            fields=text.split('|')
            if len(fields)!=10 or fields[5]!=mode or fields[6:8]!=[str(app_uid)]*2 or fields[9]!=kind:
                raise ValueError('component_metadata_principal_changed')
            if any(not fields[i].isdigit() or int(fields[i])<1 for i in (0,1,2,8)) or not fields[3] or not fields[4]:
                raise ValueError('component_metadata_generation_invalid')
            if kind=='regular file' and fields[8]!='1': raise ValueError('component_receipt_link_changed')
            return fields
        generation(directory['generation'],'700','directory')
        if type(rows) is not list or len(rows)!=3 or type(directory['entries']) is not list or len(directory['entries'])!=3:
            raise ValueError('component_receipt_inventory_changed')
        receipts=[];names=[]
        for row,entry in zip(rows,directory['entries']):
            if type(row) is not dict or set(row)!={'name','generation','sha256','bytes','rawBase64','phase','classification','sessionId'}:
                raise ValueError('component_receipt_schema_invalid')
            if type(entry) is not dict or set(entry)!={'name','generation'} or entry!={k:row[k] for k in ('name','generation')}:
                raise ValueError('component_receipt_inventory_changed')
            fields=generation(row['generation'],'600','regular file')
            if type(row['name']) is not str or not re.fullmatch(r'[0-9a-f-]{36}\.json',row['name']) or type(row['rawBase64']) is not str:
                raise ValueError('component_receipt_schema_invalid')
            raw=base64.b64decode(row['rawBase64'],validate=True)
            if type(row['bytes']) is not int or not 0<len(raw)<=4096 or len(raw)!=row['bytes'] or len(raw)!=int(fields[2]) or hashlib.sha256(raw).hexdigest()!=row['sha256']:
                raise ValueError('component_receipt_bytes_changed')
            receipt=json.loads(raw,object_pairs_hook=unique)
            keys={'id','nonce','sessionId','version','build','sha256','byteCount','phase','createdAt','confirmation','signers'}
            if type(receipt) is not dict or set(receipt)!=keys: raise ValueError('component_receipt_schema_invalid')
            for field in ('id','nonce'):
                if type(receipt[field]) is not str or str(uuid.UUID(receipt[field]))!=receipt[field]:
                    raise ValueError('component_receipt_uuid_invalid')
            if row['name']!=receipt['id']+'.json' or row['name'] in names: raise ValueError('component_receipt_inventory_changed')
            names.append(row['name'])
            if receipt['phase'] not in ('INSTALLED','FAILED','CANCELLED') or row['phase']!=receipt['phase'] or row['classification']!='terminal':
                raise ValueError('component_receipt_not_terminal')
            if type(receipt['sessionId']) is not int or receipt['sessionId']<0 or type(row['sessionId']) is not int or row['sessionId']!=receipt['sessionId']:
                raise ValueError('component_receipt_session_invalid')
            version=receipt['version']
            if type(version) is not str or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',version): raise ValueError('component_receipt_version_invalid')
            parts=list(map(int,version.split('.')))
            if not 1<=parts[0]<=19 or not all(0<=v<=19 for v in parts[1:]): raise ValueError('component_receipt_version_invalid')
            for field,minimum in (('build',1),('byteCount',1),('createdAt',0)):
                if type(receipt[field]) is not int or receipt[field]<minimum: raise ValueError('component_receipt_schema_invalid')
            if type(receipt['sha256']) is not str or not _SHA.fullmatch(receipt['sha256']): raise ValueError('component_receipt_digest_invalid')
            signers=receipt['signers']
            if type(signers) is not list or not signers or any(type(v) is not str or not _SHA.fullmatch(v) for v in signers) or len(set(signers))!=len(signers):
                raise ValueError('component_receipt_signers_invalid')
            if receipt['confirmation'] is not None and (type(receipt['confirmation']) is not str or len(receipt['confirmation'])>8192):
                raise ValueError('component_receipt_schema_invalid')
            receipts.append(receipt)
        if names!=sorted(names): raise ValueError('component_receipt_inventory_order_changed')
        inventory=observation['osInventory']
        if type(inventory) is not dict or set(inventory)!={'state','complete','bytes','sha256','rawBase64','activeSectionSha256'} or inventory['state']!='empty' or inventory['complete'] is not True:
            raise ValueError('component_os_sessions_not_empty')
        raw=base64.b64decode(inventory['rawBase64'],validate=True)
        if type(inventory['bytes']) is not int or not 0<len(raw)<=1048576 or inventory['bytes']!=len(raw) or hashlib.sha256(raw).hexdigest()!=inventory['sha256']:
            raise ValueError('component_os_sessions_bytes_changed')
        text=raw.decode('utf-8','strict');headers=list(re.finditer(r'(?m)^(Active|Orphaned|Finalized|Historical|Legacy) install sessions:[ \t]*$',text))
        if [m.group(1) for m in headers]!=['Active','Finalized','Historical','Legacy']:
            raise ValueError('component_os_sessions_incomplete')
        active=text[headers[0].end():headers[1].start()]
        if active.strip() not in ('','(none)','None') or hashlib.sha256((active+'\x00').encode()).hexdigest()!=inventory['activeSectionSha256']:
            raise ValueError('component_os_sessions_not_empty')
        outcomes.append({'metadata':metadata,'rows':rows,'receipts':receipts,'activeSectionSha256':inventory['activeSectionSha256']})
    if outcomes[0]!=outcomes[1]: raise ValueError('component_terminal_history_changed')
    latest=max(outcomes[0]['receipts'],key=lambda v:(v['createdAt'],v['id']))
    return {'terminalCount':3,'historySha256':hashlib.sha256(_canonical(outcomes[0])).hexdigest(),
        'latestPublicReceipt':{'installReceiptId':latest['id'],'installSessionId':latest['sessionId'],
            'installPhase':latest['phase'].lower(),'installed':latest['phase']=='INSTALLED'},
        'appUid':app_uid,'osSessionsEmpty':True,'claimGranted':False,'releaseGranted':False}


def validate_component_certificate(producer: dict[str, Any], expected_pin: dict[str, Any]) -> dict[str, Any]:
    """Consume actual component producer schema, never a fabricated legacy DTO.

    expected_pin is the source-bound native adapter's independently retained
    complete FD certificate pin. Neither this validator nor the historical
    certificate grants fresh ownership, installer admission, or release.
    """
    flags=('installedLauncherAccepted','bundledRuntimeAccepted','acceptanceComplete')
    if (type(producer) is not dict or type(producer.get('schema')) is not int or producer['schema']!=1 or
        producer.get('kind')!='api35-current-owner-admission-proof' or producer.get('failure') is not None or
        producer.get('failureDetail') is not None or any(producer.get(k) is not False for k in flags)):
        raise ValueError('component_certificate_producer_invalid')
    result=producer.get('result');rows=producer.get('rows')
    if type(result) is not dict or result.get('state')!='api35-current-owner-admitted' or result.get('componentRuntime')!='EXTERNAL_JDK' or any(result.get(k) is not False for k in ('installerLeaseGranted','guestMutationPerformed','acceptanceComplete','replayAllowed')):
        raise ValueError('component_certificate_scope_invalid')
    if type(rows) is not list or not 1<=len(rows)<=512: raise ValueError('component_certificate_inventory_invalid')
    names=[];selected=None
    for row in rows:
        if type(row) is not dict or set(row)!={'name','pin','rawBase64','sha256','bytes'} or type(row['name']) is not str or row['name'] in names:
            raise ValueError('component_certificate_inventory_invalid')
        names.append(row['name']);pin=row['pin']
        if type(pin) is not dict or set(pin)!={'generation','parents','sha256'} or type(pin['generation']) is not list or len(pin['generation'])!=9 or any(type(v) is not int or v<0 for v in pin['generation']):
            raise ValueError('component_certificate_pin_invalid')
        generation=pin['generation']
        if generation[0]<=0 or generation[1]<=0 or generation[2:6]!=[0o100600,0,0,1] or generation[7]<=0 or generation[8]<=0 or type(pin['parents']) is not dict or not pin['parents']:
            raise ValueError('component_certificate_principal_invalid')
        for path,parent in pin['parents'].items():
            if type(path) is not str or not path.startswith('/') or '..' in Path(path).parts: raise ValueError('component_certificate_parent_invalid')
            if type(parent) is not list or len(parent)!=5 or any(type(v) is not int or v<0 for v in parent) or parent[0]<=0 or parent[1]<=0 or not stat.S_ISDIR(parent[2]):
                raise ValueError('component_certificate_parent_invalid')
        raw=base64.b64decode(row['rawBase64'],validate=True)
        if type(row['bytes']) is not int or not 0<len(raw)<=1048576 or len(raw)!=row['bytes'] or generation[6]!=len(raw) or hashlib.sha256(raw).hexdigest()!=row['sha256'] or row['sha256']!=pin['sha256']:
            raise ValueError('component_certificate_bytes_changed')
        if row['name']=='admission.json':selected=(raw,pin)
    if selected is None or selected[1]!=expected_pin or result.get('certificatePin')!=expected_pin:
        raise ValueError('component_certificate_binding_changed')
    certificate=json.loads(selected[0])
    if type(certificate) is not dict or type(certificate.get('schema')) is not int or certificate['schema']!=1 or certificate.get('kind')!='api35-current-owner-read-only-admission':
        raise ValueError('component_certificate_schema_invalid')
    if certificate.get('componentRuntime')!='EXTERNAL_JDK' or any(certificate.get(k) is not False for k in (*flags,'installerLeaseGranted','guestMutationPerformed','replayAllowed')):
        raise ValueError('component_certificate_scope_invalid')
    owner=certificate.get('controllerId');revision=certificate.get('configurationRevision')
    if type(owner) is not str or str(uuid.UUID(owner))!=owner or type(revision) is not int or revision<0 or result.get('controllerId')!=owner or type(result.get('configurationRevision')) is not int or result['configurationRevision']!=revision:
        raise ValueError('component_certificate_owner_invalid')
    request=certificate.get('request');facts=certificate.get('facts');app=certificate.get('appProcess');host=certificate.get('host')
    if (type(request) is not dict or producer.get('request')!=request or request.get('host')!='archlinux' or
        request.get('device')!='android-api35' or type(request.get('expectedApi')) is not int or request['expectedApi']!=35 or
        request.get('expectedAvd')!='vpn-control-parity113-api35' or request.get('sourceSha')!='d32f719a08db57e5d40ce2bf77e0d7c5b42de557' or
        request.get('packageSha256')!='352af218242311884a355f789c0d1c45b736c35270b096f41408de55e2c4ed33'):
        raise ValueError('component_certificate_product_invalid')
    if type(facts) is not dict or facts.get('sdk')!='35' or facts.get('abi')!='x86_64' or facts.get('shellUid')!='2000' or facts.get('bootCompleted')!='1' or facts.get('guestBootId')!='d177ded3-526f-486d-bd19-3042d1836d9a' or facts.get('packageSha256')!=request['packageSha256']:
        raise ValueError('component_certificate_guest_invalid')
    if type(app) is not dict or app.get('name')!='com.kardinal.vpncontrol' or app.get('guestBootId')!=facts['guestBootId'] or any(type(app.get(k)) is not int or app[k]<=0 for k in ('pid','startTicks','uid')) or not 10000<=app['uid']<=99999:
        raise ValueError('component_certificate_app_invalid')
    if type(host) is not dict or any(type(host.get(k)) is not int or host[k]!=0 for k in ('uid','euid','gid','egid')) or type(host.get('groups')) is not list or any(type(v) is not int for v in host['groups']) or host['groups']!=[0]:
        raise ValueError('component_certificate_host_principal_invalid')
    if certificate.get('status',{}).get('runtimeRunning') is not False or certificate.get('status',{}).get('runtimeObservation')!='stopped' or type(certificate.get('operations')) is not dict or certificate['operations'].get('scope')!='android-provider-operations' or certificate['operations'].get('operations')!=[]:
        raise ValueError('component_certificate_runtime_invalid')
    for name in ('sourceSha256','commandSourceSha256','environmentSha256'):
        if type(certificate.get(name)) is not str or not _SHA.fullmatch(certificate[name]): raise ValueError('component_certificate_source_invalid')
    for name in ('bundleReceipt','backendBinding','stage','responsePins'):
        if type(certificate.get(name)) is not dict or not certificate[name]: raise ValueError('component_certificate_source_invalid')
    return certificate


def validate_component_public_receipt(value: dict[str, Any]) -> dict[str, Any]:
    """Exact installed-source terminal DTO; bools never compare as integers."""
    if type(value) is not dict or set(value)!={'installReceiptId','installSessionId','installPhase','installed'}:
        raise ValueError('component_terminal_dto_changed')
    identifier=value['installReceiptId'];phase=value['installPhase']
    if type(identifier) is not str or str(uuid.UUID(identifier))!=identifier or type(value['installSessionId']) is not int or value['installSessionId']<0 or type(phase) is not str or phase not in ('installed','failed','cancelled') or type(value['installed']) is not bool or value['installed'] is not (phase=='installed'):
        raise ValueError('component_terminal_dto_changed')
    return value


def measure_component_retained_snapshot(read_public, export_routing, certificate: dict[str, Any], terminal_preflight) -> dict[str, Any]:
    """Fixed native-adapter callbacks, never caller supplied tool arguments.

    The adapter authenticates current physical/app/JDK/source facts around
    every command and repeats terminal_preflight before the reconcile getter.
    Historical certificate admission alone is not a current-state assertion.
    """
    owner=certificate['controllerId'];revision=certificate['configurationRevision']
    def read(*words):
        value=read_public(*words)
        if type(value) is not dict or value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK' or value.get('controllerId')!=owner or type(value.get('configurationRevision')) is not int or value['configurationRevision']!=revision or type(value.get('data')) is not dict:
            raise ValueError('component_snapshot_owner_changed')
        return value['data']
    def stopped():
        value=read('status')
        if value.get('runtimeRunning') is not False or value.get('runtimeObservation')!='stopped': raise ValueError('component_snapshot_runtime_running')
    stopped();operations=read('operations','list').get('operations')
    if type(operations) is not list or any(type(v) is not dict or v.get('final') is not True or v.get('controllerId')!=owner for v in operations):
        raise ValueError('component_snapshot_operations_pending')
    settings=read('settings','show');source=read('source','show')
    history=terminal_preflight()
    if type(history) is not dict or history.get('claimGranted') is not False or history.get('releaseGranted') is not False or history.get('osSessionsEmpty') is not True or history.get('terminalCount')!=3 or history.get('appUid')!=certificate['appProcess']['uid']:
        raise ValueError('component_snapshot_terminal_precondition_invalid')
    updates=read('updates','status')
    if updates.get('phase') not in ('idle','up_to_date','unsupported','failed') or updates.get('installRecoveryUnavailable') is not False or type(updates.get('legacyInstallerPins')) is not int or updates['legacyInstallerPins']!=0 or validate_component_public_receipt(updates.get('installReceipt'))!=validate_component_public_receipt(history['latestPublicReceipt']):
        raise ValueError('component_snapshot_terminal_dto_changed')
    routing=routing_digest(export_routing());closing=terminal_preflight()
    if closing!=history: raise ValueError('component_snapshot_terminal_history_changed')
    stopped()
    return {'owner':owner,'revision':revision,'allFinal':True,'runtimeRunning':False,'runtimeObservation':'stopped',
        'packageSha256':certificate['request']['packageSha256'],'routingSha256':routing,
        'settingsSha256':hashlib.sha256(_canonical(settings)).hexdigest(),'sourceSha256':hashlib.sha256(_canonical(source)).hexdigest(),
        'updateWorkIdle':True,'installerIdle':True,'terminalHistorySha256':history['historySha256'],
        'latestPublicReceipt':history['latestPublicReceipt']}


COMPONENT_REQUIRED_FILES = frozenset((REQUIRED_FILES - {'closing-routing.json','closing-readback.json'}) |
    {'component-admission.json','closing-component-routing.json','terminal-history.json'})


def validate_component_retained_proof(value: dict[str, Any]) -> dict[str, Any]:
    """Explicit component/terminal branch; preserve the historical validator.

    This is a shape/binding validator. The source-bound native adapter measures
    the original files, aliases, restoration, and current component guards
    under the original device lock. A caller-authored proof is not authority.
    """
    if type(value) is not dict or value.get('kind')!='android-installer-component-retained-terminal-first-check':
        raise ValueError('component_retirement_proof_invalid')
    if value.get('originalCorrelationId')!='0dd55704-1e80-4d62-8d9d-2f0a123e0c3b' or value.get('originalOutcome')!='unknown' or value.get('historicalSettingsSource')!='unavailable' or value.get('productDataMutationAllowed') is not False:
        raise ValueError('component_original_outcome_changed')
    new=value.get('retirementCorrelationId')
    if type(new) is not str or str(uuid.UUID(new))!=new or new==value['originalCorrelationId']:
        raise ValueError('component_separate_retirement_required')
    if value.get('sourceSha')!='d32f719a08db57e5d40ce2bf77e0d7c5b42de557' or value.get('toolBundleId')!='sha256-64c3b9f8176515770db963dd5858d3044ebd969b8d460272eb9ef3f4c9deb7ac':
        raise ValueError('component_original_source_changed')
    if value.get('intentSha256')!='1b1eba7b0744ae47adc98b6b7fd7cc1480bc62a5b2ed7d4902fb36de580d7656' or value.get('lifecycleSha256')!='b550f7ae50f60bcf53c0d688efda2165a6c39b505a997235bd9d78c710757e59' or value.get('phaseCheckSha256')!='dadfe1eb79d0ea884dd9f9ad71f7f47f3bce56856fb15a61ec54e7495b2c6b33':
        raise ValueError('component_original_receipt_changed')
    if value.get('phases')!={'check':True,'download':False,'noninteractive':False,'interactive':False} or any(type(v) is not bool for v in value['phases'].values()) or value.get('failureType')!='RuntimeError' or value.get('cleanupFailures')!=[]:
        raise ValueError('component_first_check_unproved')
    if any(value.get(k) is not True for k in ('probeAbsent','handoffAbsent','nativeRestored','freshOwnerAdmission','deviceLockHeld','canonicalLeaseAbsent')):
        raise ValueError('component_original_closure_unproved')
    for name,pid,ticks in (('worker',1169929,72285068),('fixture',1172004,72288190)):
        item=value.get(name)
        if type(item) is not dict or type(item.get('pid')) is not int or item['pid']!=pid or type(item.get('startTicks')) is not int or item['startTicks']!=ticks or item.get('stopped') is not True:
            raise ValueError('component_original_process_unproved')
    if value['fixture'].get('portRefused') is not True: raise ValueError('component_fixture_listener_unproved')
    certificate=validate_component_certificate(value.get('componentProducer'),value.get('componentCertificatePin'))
    app_uid=certificate['appProcess']['uid']
    principals=value.get('principals')
    if type(principals) is not dict or set(principals)!={'historicalWorkerUid','hostMeasurementUid','hostPublicUid','adbShellUid','appMetadataUid','localLeaseUid'} or any(type(v) is not int for v in principals.values()) or principals!={
        'historicalWorkerUid':1000,'hostMeasurementUid':0,'hostPublicUid':1000,'adbShellUid':2000,'appMetadataUid':app_uid,'localLeaseUid':principals['localLeaseUid']} or principals['localLeaseUid']<0:
        raise ValueError('component_principal_substitution')
    history=validate_component_terminal_history(value.get('terminalHistory'),app_uid)
    snapshots=value.get('snapshots');opening=value.get('opening')
    if type(snapshots) is not list or len(snapshots)!=2 or snapshots[0]!=snapshots[1] or type(opening) is not dict or set(opening)!={'packageSha256','routingSha256'}:
        raise ValueError('component_two_snapshots_required')
    snapshot=snapshots[0]
    if type(snapshot) is not dict or set(snapshot)!={'owner','revision','allFinal','runtimeRunning','runtimeObservation','packageSha256','routingSha256','settingsSha256','sourceSha256','updateWorkIdle','installerIdle','terminalHistorySha256','latestPublicReceipt'}:
        raise ValueError('component_snapshot_invalid')
    if snapshot['owner']!=certificate['controllerId'] or type(snapshot['revision']) is not int or snapshot['revision']!=certificate['configurationRevision'] or any(snapshot[k] is not True for k in ('allFinal','updateWorkIdle','installerIdle')) or snapshot['runtimeRunning'] is not False or snapshot['runtimeObservation']!='stopped':
        raise ValueError('component_current_owner_unproved')
    if snapshot['terminalHistorySha256']!=history['historySha256'] or validate_component_public_receipt(snapshot['latestPublicReceipt'])!=validate_component_public_receipt(history['latestPublicReceipt']):
        raise ValueError('component_terminal_dto_changed')
    for key in ('packageSha256','routingSha256','settingsSha256','sourceSha256'):
        if type(snapshot[key]) is not str or not _SHA.fullmatch(snapshot[key]): raise ValueError('component_snapshot_hash_invalid')
    if snapshot['packageSha256']!=certificate['request']['packageSha256'] or any(snapshot[k]!=opening[k] for k in opening):
        raise ValueError('component_opening_baseline_changed')
    files=value.get('files')
    if type(files) is not dict or set(files)!=COMPONENT_REQUIRED_FILES: raise ValueError('component_file_roles_missing')
    for name,item in files.items():
        if type(item) is not dict or set(item)!={'principal','format','generation','sha256'} or type(item['sha256']) is not str or not _SHA.fullmatch(item['sha256']):
            raise ValueError('component_file_role_invalid')
        original=name not in ('component-admission.json','closing-component-routing.json','terminal-history.json','local-lease.json')
        principal='historical-worker' if original else 'local-lease' if name=='local-lease.json' else 'component-worker'
        uid=1000 if original else principals['localLeaseUid'] if name=='local-lease.json' else 0
        generation=item['generation']
        if item['principal']!=principal or type(generation) is not list or any(type(v) is not int or v<0 for v in generation):
            raise ValueError('component_file_principal_invalid')
        if item['format']=='private8':
            if len(generation)!=8 or generation[5:]!=[0o600,uid,1] or min(generation[:5])<1: raise ValueError('component_file_generation_invalid')
        elif item['format']=='descriptor9':
            if len(generation)!=9 or generation[2:6]!=[0o100600,uid,uid,1] or min(generation[0:2]+generation[6:9])<1: raise ValueError('component_file_generation_invalid')
        else: raise ValueError('component_file_format_invalid')
    for name,key in (('output/intent.json','intentSha256'),('output/lifecycle-receipt.json','lifecycleSha256'),('output/phase-check.json','phaseCheckSha256')):
        if files[name]['sha256']!=value[key]: raise ValueError('component_original_file_binding_changed')
    if files['component-admission.json']['format']!='descriptor9' or files['component-admission.json']['generation']!=value['componentCertificatePin']['generation'] or files['component-admission.json']['sha256']!=value['componentCertificatePin']['sha256']:
        raise ValueError('component_certificate_file_binding_changed')
    return json.loads(_canonical(value))


def admit_component_fenced(original_output: Path, admission_directory: Path,
                           proof: dict[str, Any], current_guard, original_parent_uid: int) -> dict[str, Any]:
    """One metadata admission, no lease release or product action.

    Only a source-authenticated native adapter invokes this primitive, holding
    the original device lock. It supplies fixed original paths and repeats
    complete physical/source/record/alias/owner guards. No public tool accepts
    these paths, callback or caller-authored assertions.
    The global original-journal intent remains consumed on every uncertainty.
    """
    verified=validate_component_retained_proof(proof)
    if type(original_parent_uid) is not int or original_parent_uid<0:
        raise ValueError('component_original_parent_principal_invalid')
    original_output=Path(original_output).absolute();admission_directory=Path(admission_directory).absolute()
    # Descriptor-relative complete ancestry, with independent original-worker
    # ownership rather than substituting the current root measurement UID.
    def held_directory(path,uid):
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);ancestors=[]
        try:
            for part in path.parts[1:]:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=child
            info=os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=0o700:
                raise ValueError('component_admission_parent_invalid')
            ancestors=_ancestry(path)
            return fd,_generation(info),ancestors
        except BaseException:os.close(fd);raise
    original_fd,original_pin,original_ancestry=held_directory(original_output,original_parent_uid)
    admission_fd=None
    try:
        admission_fd,admission_pin,admission_ancestry=held_directory(admission_directory,os.getuid())
        parent_gids={original_fd:os.fstat(original_fd).st_gid,admission_fd:os.fstat(admission_fd).st_gid}
        original_names=set(os.listdir(original_fd));admission_names=set(os.listdir(admission_fd))
        if admission_names: raise ValueError('component_admission_directory_not_empty')
        created={}
        def created_pin(fd,name,expected_raw):
            read_fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            try:
                def descriptor(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
                before=os.fstat(read_fd);generation=descriptor(before)
                if generation[2:6]!=[0o100600,os.getuid(),os.getgid(),1] or not 0<before.st_size<=2097152:
                    raise ValueError('component_admission_record_unsafe')
                data=b''
                while len(data)<=2097152:
                    part=os.read(read_fd,min(65536,2097153-len(data)))
                    if not part:break
                    data+=part
                if data!=expected_raw or descriptor(os.fstat(read_fd))!=generation or descriptor(os.stat(name,dir_fd=fd,follow_symlinks=False))!=generation:
                    raise ValueError('component_admission_record_changed')
                return {'generation':generation,'sha256':hashlib.sha256(data).hexdigest()}
            finally:os.close(read_fd)
        def guard_directories():
            for path,fd,pin,parents in ((original_output,original_fd,original_pin,original_ancestry),
                                        (admission_directory,admission_fd,admission_pin,admission_ancestry)):
                held=_generation(os.fstat(fd));named=_generation(path.lstat())
                # Controlled own child creation changes directory timestamps
                # and size only. Identity/mode/owner/nlink and ancestry remain.
                if any(held[i]!=pin[i] or named[i]!=pin[i] for i in (0,1,5,6,7)) or os.fstat(fd).st_gid!=parent_gids[fd] or path.lstat().st_gid!=parent_gids[fd] or _ancestry(path)!=parents:
                    raise ValueError('component_admission_parent_changed')
            if set(os.listdir(original_fd))!=original_names or set(os.listdir(admission_fd))!=admission_names:
                raise ValueError('component_admission_inventory_changed')
            for (fd,name),(raw,pin) in created.items():
                if created_pin(fd,name,raw)!=pin: raise ValueError('component_admission_record_changed')
        def create_record(fd,name,value,names):
            before=os.fstat(fd)
            _create(fd,name,value);names.add(name)
            after=os.fstat(fd)
            if after.st_nlink not in (before.st_nlink,before.st_nlink+1):raise ValueError('component_admission_parent_changed')
            # Linux counts directory links; APFS also counts the created file.
            # Admit only this known child progression, with exact inventory and
            # independent identity/mode/UID/GID checks immediately afterward.
            (original_pin if fd==original_fd else admission_pin)[7]=after.st_nlink
            raw=_canonical(value);created[(fd,name)]=(raw,created_pin(fd,name,raw))
        current_guard();guard_directories()
        digest=hashlib.sha256(_canonical(verified)).hexdigest()
        intent={'schema':1,'kind':'android-installer-component-retained-terminal-admission-intent',
            'originalCorrelationId':verified['originalCorrelationId'],'retirementCorrelationId':verified['retirementCorrelationId'],
            'proofSha256':digest,'originalOutcome':'unknown','releaseGranted':False,'replayAllowed':False}
        # This original global name prevents a fresh UUID bypass of an unknown
        # admission. _create fsyncs the file and its held parent descriptor.
        create_record(original_fd,'component-retained-retirement-admission-intent.json',intent,original_names)
        guard_directories();current_guard();guard_directories()
        create_record(admission_fd,'component-admitted-proof.json',verified,admission_names)
        guard_directories();current_guard();guard_directories()
        create_record(admission_fd,'component-admitted.json',{'schema':1,'kind':'android-installer-component-retained-terminal-admitted',
            'proofSha256':digest,'originalOutcome':'unknown','leaseReleased':False,'replayAllowed':False},admission_names)
        guard_directories()
        return {'state':'component-retained-terminal-admitted','proofSha256':digest,
            'proofPin':created[(admission_fd,'component-admitted-proof.json')][1],
            'admissionPin':created[(admission_fd,'component-admitted.json')][1],
            'globalFencePin':created[(original_fd,'component-retained-retirement-admission-intent.json')][1],
            'originalOutcome':'unknown','leaseReleased':False,'replayAllowed':False}
    finally:
        if admission_fd is not None:os.close(admission_fd)
        os.close(original_fd)


def component_admission_source(source_raw: bytes, expected_source_sha256: str) -> str:
    """Closed definitions for the current source-bound native adapter.

    No dispatch occurs here. The fixed caller owns current transport and the
    original lock/record/provenance measurement. Historical remote_source()
    remains byte-for-byte unchanged and retains its original empty/null gate.
    """
    if type(source_raw) is not bytes or not 0<len(source_raw)<=2097152 or type(expected_source_sha256) is not str or not _SHA.fullmatch(expected_source_sha256) or hashlib.sha256(source_raw).hexdigest()!=expected_source_sha256:
        raise ValueError('component_factory_source_changed')
    # Derive every definition and table from the ONE immutable FD snapshot,
    # authenticated by the fixed caller's reviewed source SHA. No getsource or
    # named-path reread can introduce exchanged bytes during preparation.
    text=source_raw.decode('utf-8','strict');tree=ast.parse(text)
    names=('validate_component_terminal_history','validate_component_certificate','validate_component_public_receipt',
        'measure_component_retained_snapshot','validate_component_retained_proof',
        'admit_component_fenced','_canonical','routing_digest','_generation','_ancestry','_create')
    definitions=[]
    for name in names:
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name]
        if len(nodes)!=1 or nodes[0].decorator_list: raise ValueError('component_factory_definition_changed')
        definitions.append(ast.get_source_segment(text,nodes[0]))
    required=[n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id=='REQUIRED_FILES' for v in n.targets)]
    component=[n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(v,ast.Name) and v.id=='COMPONENT_REQUIRED_FILES' for v in n.targets)]
    if len(required)!=1 or len(component)!=1: raise ValueError('component_factory_table_changed')
    if not (isinstance(required[0],ast.Call) and isinstance(required[0].func,ast.Name) and required[0].func.id=='frozenset' and len(required[0].args)==1 and not required[0].keywords):raise ValueError('component_factory_table_changed')
    expression=component[0]
    if not (isinstance(expression,ast.Call) and isinstance(expression.func,ast.Name) and expression.func.id=='frozenset' and len(expression.args)==1 and not expression.keywords):raise ValueError('component_factory_table_changed')
    expression=expression.args[0]
    if not (isinstance(expression,ast.BinOp) and isinstance(expression.op,ast.BitOr) and isinstance(expression.left,ast.BinOp) and isinstance(expression.left.op,ast.Sub) and isinstance(expression.left.left,ast.Name) and expression.left.left.id=='REQUIRED_FILES'):raise ValueError('component_factory_table_changed')
    files=(set(ast.literal_eval(required[0].args[0]))-set(ast.literal_eval(expression.left.right)))|set(ast.literal_eval(expression.right))
    return ('import json,hashlib,os,re,stat,base64,uuid\nfrom pathlib import Path\nfrom typing import Any\n'
        +"_SHA=re.compile(r'[0-9a-f]{64}\\Z');_UUID=re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\\Z')\n"
        +'COMPONENT_REQUIRED_FILES=frozenset('+repr(sorted(files))+')\n'
        +'\n'.join(definitions))


def release_component_fenced(lease: Path, expected_pin: dict[str, Any],
                             admitted_proof: dict[str, Any], release_correlation_id: str,
                             current_proof, role: str,
                             remote_result: dict[str, Any] | None = None) -> dict[str, Any]:
    """Separate component release, invoked only by the sealed direct adapter.

    The adapter continuously holds the original device lock, authenticates the
    persisted original admission and supplies complete freshly measured proofs
    before every effect. No MCP input supplies paths, callbacks or assertions.
    Root measures the ordinary-user remote lease without adopting its owner.
    Local release follows an independently authenticated successful remote
    response. Original metadata is captured into private retired evidence,
    never deleted. Any exception after the fence consumes this operation.
    """
    old=validate_component_retained_proof(admitted_proof)
    original=old['originalCorrelationId'];digest=hashlib.sha256(_canonical(old)).hexdigest()
    if type(release_correlation_id) is not str or not _UUID.fullmatch(release_correlation_id) or str(uuid.UUID(release_correlation_id))!=release_correlation_id or release_correlation_id in (original,old['retirementCorrelationId']):
        raise ValueError('component_release_correlation_invalid')
    if role not in ('remote-original','local-original'):
        raise ValueError('component_release_role_invalid')
    remote=role=='remote-original';uid=1000 if remote else old['principals']['localLeaseUid']
    actor=0 if remote else uid
    actor_gid=0 if remote else os.getgid();lease_gid=1000 if remote else actor_gid
    if os.getuid()!=actor or os.getgid()!=actor_gid:
        raise ValueError('component_release_actor_invalid')
    lease=Path(lease).absolute()
    if lease.name!=('android-native-device-api35.lease' if remote else 'lease-archlinux-api35.json'):
        raise ValueError('component_release_path_invalid')
    release_name=('android-native-device-api35-'+original+'.release-intent') if remote else 'release-'+original+'.json'
    fence_name=('android-native-device-api35-'+original+'.component-retirement-fence') if remote else 'component-retirement-'+original+'.json'
    quarantine_name=('android-native-device-api35-'+original+'.component-retirement-quarantine') if remote else 'component-retirement-'+original+'.quarantine'
    captured_name='captured-original-lease.json';snapshot_name='held-original-snapshot.json'
    expected={'owner':'android-installer','host':'archlinux','device':'api35','correlationId':original}
    if not remote:
        required={'schema':1,'kind':'android-installer-component-remote-lease-released',
            'originalCorrelationId':original,'admissionCorrelationId':old['retirementCorrelationId'],
            'releaseCorrelationId':release_correlation_id,'admittedProofSha256':digest,
            'originalOutcome':'unknown','leaseReleased':True,'replayAllowed':False}
        if type(remote_result) is not dict or set(remote_result)!=set(required)|{'retiredEvidence'} or _canonical({k:remote_result[k] for k in required})!=_canonical(required):
            raise ValueError('component_remote_release_unproven')
        evidence=remote_result['retiredEvidence'];prior=old['files']['remote-lease.json']
        if type(evidence) is not dict or set(evidence)!={'path','generation','sha256','parents','leaseCapturedNotDeleted'} or evidence['leaseCapturedNotDeleted'] is not True or type(evidence['path']) is not str or Path(evidence['path']).parts[-2:]!=('android-native-device-api35-'+original+'.component-retirement-quarantine',captured_name) or evidence['sha256']!=prior['sha256']:
            raise ValueError('component_remote_release_unproven')
        captured=evidence['generation'];original_pin=prior['generation']
        if prior['format']!='descriptor9' or type(captured) is not list or len(captured)!=9 or any(type(v) is not int or v<0 for v in captured) or captured[:8]!=original_pin[:8] or captured[8]<original_pin[8]:
            raise ValueError('component_remote_release_unproven')
        ancestors=evidence['parents']
        if type(ancestors) is not list or not ancestors or any(type(row) is not list or len(row)!=5 or any(type(v) is not int or v<0 for v in row) for row in ancestors) or ancestors[-1][2:]!=[0o40700,0,0]:
            raise ValueError('component_remote_release_unproven')
    elif remote_result is not None:
        raise ValueError('component_release_role_invalid')
    if type(expected_pin) is not dict or set(expected_pin)!={'generation','sha256','parents'}:
        raise ValueError('component_release_pin_invalid')
    generation=expected_pin['generation'];parents=expected_pin['parents']
    if type(generation) is not list or len(generation)!=9 or any(type(v) is not int or v<0 for v in generation) or generation[2:6]!=[0o100600,uid,lease_gid,1] or generation[6]!=121 or min(generation[:2]+generation[7:])<1 or expected_pin['sha256']!='44f2b1d325cbd0dedda6d6af5b1bf856792edf327accad99475e8cde6e4e865a':
        raise ValueError('component_release_pin_invalid')
    if type(parents) is not list or not parents or any(type(row) is not list or len(row)!=5 or any(type(v) is not int or v<0 for v in row) for row in parents):
        raise ValueError('component_release_parent_invalid')
    old_pin=old['files']['remote-lease.json' if remote else 'local-lease.json']
    projected=generation if old_pin['format']=='descriptor9' else [generation[0],generation[1],generation[6],generation[7],generation[8],stat.S_IMODE(generation[2]),generation[3],generation[5]]
    if old_pin['generation']!=projected or old_pin['sha256']!=expected_pin['sha256']:
        raise ValueError('component_release_original_lease_changed')
    def fp(info):
        return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
    def ancestry():
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);rows=[]
        try:
            for part in lease.parent.parts[1:]:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=child;info=os.fstat(fd)
                rows.append([info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid])
            if rows!=parents or rows[-1][2:]!=[0o40700,uid,lease_gid]:
                raise ValueError('component_release_parent_changed')
            return fd
        except BaseException:os.close(fd);raise
    parent=ancestry()
    try:
        parent_pin=fp(os.fstat(parent));names=sorted(os.listdir(parent));created={};link_step=None
        def guard_parent():
            other=ancestry()
            try:
                if fp(os.fstat(other))!=parent_pin or fp(os.fstat(parent))!=parent_pin or sorted(os.listdir(parent))!=names:
                    raise ValueError('component_release_parent_changed')
            finally:os.close(other)
        def read_lease():
            guard_parent()
            fd=os.open(lease.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            with os.fdopen(fd,'rb') as stream:
                before=fp(os.fstat(stream.fileno()));raw=stream.read(1025);after=fp(os.fstat(stream.fileno()))
            if before!=generation or after!=generation or fp(os.stat(lease.name,dir_fd=parent,follow_symlinks=False))!=generation or len(raw)!=121 or hashlib.sha256(raw).hexdigest()!=expected_pin['sha256'] or _canonical(json.loads(raw))!=_canonical(expected):
                raise ValueError('component_release_lease_changed')
            guard_records();guard_parent()
        def guard_records():
            for name,(payload,pin) in created.items():
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                with os.fdopen(fd,'rb') as stream:
                    first=fp(os.fstat(stream.fileno()));data=stream.read(len(payload)+1);last=fp(os.fstat(stream.fileno()))
                if first!=pin or last!=pin or fp(os.stat(name,dir_fd=parent,follow_symlinks=False))!=pin or data!=payload:
                    raise ValueError('component_release_created_record_changed')
        def fresh():
            read_lease()
            measured=validate_component_retained_proof(current_proof())
            for key in ('originalCorrelationId','retirementCorrelationId','sourceSha','toolBundleId','intentSha256','lifecycleSha256','phaseCheckSha256','opening'):
                if _canonical(measured[key])!=_canonical(old[key]):
                    raise ValueError('component_release_fresh_binding_changed')
            for key in ('packageSha256','routingSha256','settingsSha256','terminalHistorySha256','latestPublicReceipt'):
                if _canonical(measured['snapshots'][0][key])!=_canonical(old['snapshots'][0][key]):
                    raise ValueError('component_release_fresh_baseline_changed')
            if measured['principals']!=old['principals'] or measured['files']['remote-lease.json']!=old['files']['remote-lease.json'] or measured['files']['local-lease.json']!=old['files']['local-lease.json']:
                raise ValueError('component_release_fresh_lease_changed')
            read_lease()
        def create(name,value):
            nonlocal parent_pin,names,link_step
            guard_parent();payload=_canonical(value)
            _create(parent,name,value)
            current_names=sorted(os.listdir(parent));now=fp(os.fstat(parent))
            # Linux directories retain nlink for a file create; APFS counts the
            # new child. Admit only the measured sole controlled entry change,
            # then require that same progression for the second create/unlink.
            delta=now[5]-parent_pin[5]
            if link_step is None:link_step=delta
            if current_names!=sorted(names+[name]) or now[:5]!=parent_pin[:5] or delta not in ((0,) if remote else (0,1)) or delta!=link_step:
                raise ValueError('component_release_parent_changed')
            pin=fp(os.stat(name,dir_fd=parent,follow_symlinks=False))
            if pin[2:6]!=[0o100600,actor,actor_gid,1] or pin[6]!=len(payload):
                raise ValueError('component_release_created_record_changed')
            names=current_names;parent_pin=now;created[name]=(payload,pin)
            read_lease()
        guard_parent()
        if any(name in names for name in (release_name,fence_name,quarantine_name)):
            raise ValueError('component_release_already_fenced')
        fresh()
        create(fence_name,{'schema':1,'kind':'android-installer-component-retained-terminal-release-intent',
            'role':role,'originalCorrelationId':original,'admissionCorrelationId':old['retirementCorrelationId'],
            'releaseCorrelationId':release_correlation_id,'admittedProofSha256':digest,
            'leaseGeneration':generation,'leaseSha256':expected_pin['sha256'],
            'originalOutcome':'unknown','replayAllowed':False})
        fresh();create(release_name,expected);fresh()
        # The ordinary-user source directory cannot make name-based unlink
        # safe. Capture into one exclusively created actor-private directory,
        # retain the original FD across the atomic rename, and never delete any
        # captured object. A name exchange remains preserved UNKNOWN evidence.
        guard_parent();os.mkdir(quarantine_name,0o700,dir_fd=parent);os.fsync(parent)
        now=fp(os.fstat(parent));new_names=sorted(os.listdir(parent))
        if new_names!=sorted(names+[quarantine_name]) or now[:5]!=parent_pin[:5] or now[5]!=parent_pin[5]+1:
            raise ValueError('component_release_parent_changed')
        names=new_names;parent_pin=now
        quarantine=os.open(quarantine_name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        original_fd=None
        try:
            quarantine_pin=fp(os.fstat(quarantine))
            if quarantine_pin[2:5]!=[0o40700,actor,actor_gid] or os.listdir(quarantine)!=[]:
                raise ValueError('component_release_quarantine_invalid')
            def guard_quarantine(pin,entries):
                if fp(os.fstat(quarantine))!=pin or fp(os.stat(quarantine_name,dir_fd=parent,follow_symlinks=False))!=pin or sorted(os.listdir(quarantine))!=entries:
                    raise ValueError('component_release_quarantine_changed')
            fresh();guard_quarantine(quarantine_pin,[])
            original_fd=os.open(lease.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            if fp(os.fstat(original_fd))!=generation:
                raise ValueError('component_release_lease_changed')
            original_raw=os.read(original_fd,1025)
            if len(original_raw)!=121 or hashlib.sha256(original_raw).hexdigest()!=expected_pin['sha256'] or fp(os.fstat(original_fd))!=generation:
                raise ValueError('component_release_lease_changed')
            # A source actor can unlink the original inode through name
            # exchange. Preserve its exact held bytes before capture; do not
            # claim that an externally unlinked inode remains named.
            _create(quarantine,snapshot_name,expected)
            snapshot_pin=fp(os.stat(snapshot_name,dir_fd=quarantine,follow_symlinks=False))
            snapshot_quarantine=fp(os.fstat(quarantine))
            if snapshot_pin[2:6]!=[0o100600,actor,actor_gid,1] or snapshot_pin[6]!=121 or snapshot_quarantine[:5]!=quarantine_pin[:5] or snapshot_quarantine[5]-quarantine_pin[5] not in ((0,) if remote else (0,1)):
                raise ValueError('component_release_quarantine_changed')
            def guard_snapshot():
                fd=os.open(snapshot_name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=quarantine)
                with os.fdopen(fd,'rb') as stream:
                    before=fp(os.fstat(stream.fileno()));data=stream.read(1025);after=fp(os.fstat(stream.fileno()))
                if before!=snapshot_pin or after!=snapshot_pin or fp(os.stat(snapshot_name,dir_fd=quarantine,follow_symlinks=False))!=snapshot_pin or data!=original_raw:
                    raise ValueError('component_release_snapshot_changed')
            guard_snapshot();guard_quarantine(snapshot_quarantine,[snapshot_name])
            os.rename(lease.name,captured_name,src_dir_fd=parent,dst_dir_fd=quarantine)
            os.fsync(parent);os.fsync(quarantine)
            captured_pin=fp(os.stat(captured_name,dir_fd=quarantine,follow_symlinks=False))
            held_pin=fp(os.fstat(original_fd));post_quarantine=fp(os.fstat(quarantine))
            if captured_pin!=held_pin or captured_pin[:8]!=generation[:8] or captured_pin[8]<generation[8]:
                raise ValueError('component_release_captured_foreign_unknown')
            fd=os.open(captured_name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=quarantine)
            with os.fdopen(fd,'rb') as stream:
                before=fp(os.fstat(stream.fileno()));payload=stream.read(1025);after=fp(os.fstat(stream.fileno()))
            if before!=captured_pin or after!=captured_pin or len(payload)!=121 or hashlib.sha256(payload).hexdigest()!=expected_pin['sha256'] or _canonical(json.loads(payload))!=_canonical(expected) or fp(os.fstat(original_fd))!=captured_pin:
                raise ValueError('component_release_captured_changed_unknown')
            if post_quarantine[:5]!=snapshot_quarantine[:5] or post_quarantine[5]-snapshot_quarantine[5] not in ((0,) if remote else (0,1)):
                raise ValueError('component_release_quarantine_changed')
            guard_quarantine(post_quarantine,sorted([captured_name,snapshot_name]));guard_snapshot();guard_records()
            closing_pin=fp(os.fstat(parent));closing_names=sorted(name for name in names if name!=lease.name)
            if sorted(os.listdir(parent))!=closing_names or closing_pin[:5]!=parent_pin[:5] or closing_pin[5]!=parent_pin[5]-link_step:
                raise ValueError('component_release_closing_parent_changed')
            other=ancestry()
            try:
                if fp(os.fstat(other))!=closing_pin or fp(os.fstat(parent))!=closing_pin:
                    raise ValueError('component_release_closing_parent_changed')
            finally:os.close(other)
            guard_quarantine(post_quarantine,sorted([captured_name,snapshot_name]));guard_snapshot()
            evidence_parents=parents+[[post_quarantine[0],post_quarantine[1],post_quarantine[2],post_quarantine[3],post_quarantine[4]]]
            return {'schema':1,'kind':'android-installer-component-'+('remote' if remote else 'local')+'-lease-released',
                'originalCorrelationId':original,'admissionCorrelationId':old['retirementCorrelationId'],
                'releaseCorrelationId':release_correlation_id,'admittedProofSha256':digest,
                'originalOutcome':'unknown','leaseReleased':True,'replayAllowed':False,
                'retiredEvidence':{'path':str(lease.parent/quarantine_name/captured_name),'generation':captured_pin,
                    'sha256':expected_pin['sha256'],'parents':evidence_parents,'leaseCapturedNotDeleted':True}}
        finally:
            if original_fd is not None:os.close(original_fd)
            os.close(quarantine)
    finally:os.close(parent)


def component_release_source(source_raw: bytes, expected_source_sha256: str) -> str:
    """Separate held-source component release definitions; no dispatch."""
    base=component_admission_source(source_raw,expected_source_sha256)
    text=source_raw.decode('utf-8','strict');tree=ast.parse(text)
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='release_component_fenced']
    if len(nodes)!=1 or nodes[0].decorator_list:
        raise ValueError('component_factory_definition_changed')
    return base+'\n'+ast.get_source_segment(text,nodes[0])+'\n'


def _generation(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink]


def _directory(path: Path) -> int:
    # Walk every parent through descriptor-relative O_NOFOLLOW, including root.
    absolute = path.absolute(); fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError("private_parent_invalid")
        return fd
    except BaseException:
        os.close(fd); raise


def _ancestry(path: Path) -> list[list[int]]:
    absolute = path.absolute(); fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    result = []
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child; info = os.fstat(fd)
            result.append([info.st_dev, info.st_ino, info.st_mode, info.st_uid])
        return result
    finally: os.close(fd)


def private_snapshot(path: Path, limit: int = 1_048_576) -> tuple[bytes, list[int], str]:
    ancestry = _ancestry(path.parent); parent = _directory(path.parent)
    try:
        info = os.fstat(parent)
        if ancestry[-1] != [info.st_dev, info.st_ino, info.st_mode, info.st_uid]: raise ValueError("private_parent_changed")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno()); payload = stream.read(limit + 1); after = os.fstat(stream.fileno())
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600 or
            before.st_nlink != 1 or len(payload) > limit or len(payload) != before.st_size or
            _generation(before) != _generation(after) or _generation(before) != _generation(named) or _ancestry(path.parent) != ancestry):
            raise ValueError("private_file_changed")
        return payload, _generation(before), hashlib.sha256(payload).hexdigest()
    finally: os.close(parent)


def _create(parent: int, name: str, value: dict[str, Any]) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    with os.fdopen(fd, "wb") as stream:
        stream.write(_canonical(value)); stream.flush(); os.fsync(stream.fileno())
    os.fsync(parent)


def release_fenced(lease: Path, release_record: Path, retirement_fence: Path,
                   expected: dict[str, str], generation: list[int], digest: str,
                   measured_proof: dict[str, Any]) -> None:
    """Release metadata under the caller's continuously held shared device lock.

    release_record uses the existing shared helper's exact compatible format.
    A separate create-only proof fence durably records why release was allowed.
    This intentionally refuses retries: an interrupted release needs read-only
    investigation of the fenced generation, never a new lease adoption.
    """
    proof = validate_proof(measured_proof)
    if (set(expected) != {"owner", "host", "device", "correlationId"} or expected["owner"] != "android-installer" or
        expected["correlationId"] != proof["originalCorrelationId"]): raise ValueError("lease_binding_invalid")
    if lease.parent != release_record.parent or lease.parent != retirement_fence.parent or len({lease.name, release_record.name, retirement_fence.name}) != 3:
        raise ValueError("release_paths_invalid")
    ancestry = _ancestry(lease.parent); parent = _directory(lease.parent)
    try:
        def current():
            info = os.fstat(parent)
            if ancestry[-1] != [info.st_dev, info.st_ino, info.st_mode, info.st_uid] or _ancestry(lease.parent) != ancestry:
                raise ValueError("lease_parent_changed")
            fd = os.open(lease.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno()); raw = stream.read(1025); after = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or _generation(before) != generation or _generation(after) != generation or
                _generation(os.stat(lease.name, dir_fd=parent, follow_symlinks=False)) != generation or
                generation[5:] != [0o600, os.getuid(), 1] or hashlib.sha256(raw).hexdigest() != digest or json.loads(raw) != expected or _ancestry(lease.parent) != ancestry):
                raise ValueError("lease_generation_changed")
        current()
        for name in (release_record.name, retirement_fence.name):
            try: os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise ValueError("release_already_fenced")
        _create(parent, retirement_fence.name, {"schema": 1, "kind": "android-installer-failed-check-retirement",
            "lease": expected, "leaseGeneration": generation, "leaseSha256": digest, "proof": proof})
        current()
        _create(parent, release_record.name, expected)
        current()
        os.unlink(lease.name, dir_fd=parent); os.fsync(parent)
    finally: os.close(parent)


_DISPATCH_DEFINITIONS_SHA256 = "503e162cf09583f3b806642b8c361793e901326317a1ffdc59b4d0e9a6068718"

_REMOTE_TAIL = r'''
binding=expected.pop('retirementBinding'); retired=root/('android-failed-check-retirement-'+binding['retirementCorrelationId'])
owner=binding['owner']; revision=binding['revision']; output=job/'output'
try:
 validate_original(expected,binding['originalIntent'],correlation)
 if not _UUID.fullmatch(binding['retirementCorrelationId']) or binding['retirementCorrelationId']==correlation or not _UUID.fullmatch(binding['closingReadbackCorrelationId']):raise ValueError('retirement_uuid_invalid')
except (ValueError,TypeError,KeyError):unknown('reviewed_original_restriction')
info=root.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:unknown('remote_root_unsafe')
def snapshot_file(path,limit=67108864):
 raw,pin,digest=private_snapshot(path,limit);return raw,{'generation':pin,'sha256':digest}
def guard_files(pins,paths,parents):
 for name,pin in pins.items():
  if name=='local-lease.json':continue
  if snapshot_file(paths[name])[1]!=pin or _ancestry(paths[name].parent)!=parents[name]:raise ValueError('retirement_input_changed')
def native():
 adb=[expected['adb'],'-s',expected['serial']]
 def shell(*words):return fixed_run([*adb,'shell','-T',*words]).strip()
 if shell('id','-u')!='2000' or shell('getprop','ro.build.version.sdk')!=str(expected['api']) or shell('getprop','ro.product.cpu.abi')!='x86_64':raise ValueError('device_identity_changed')
 if {x for x in (shell('getprop','ro.kernel.qemu.avd_name'),shell('getprop','ro.boot.qemu.avd_name')) if x}!={expected['avd']}:raise ValueError('device_identity_changed')
 apk=[s[8:] for s in shell('pm','path','com.kardinal.vpncontrol').splitlines() if s.startswith('package:') and s.endswith('/base.apk')]
 if len(apk)!=1 or not apk[0].startswith('/data/app/'):raise ValueError('package_path_unknown')
 if shell('sha256sum',apk[0]).split()!=[binding['originalIntent']['pair']['baseSha256'],apk[0]]:raise ValueError('base_apk_changed')
 return adb,shell
su_pin=None
def authenticated_privileged_read(shell,script):
 global su_pin
 def probe(words):
  result=subprocess.run([expected['adb'],'-s',expected['serial'],'shell','-T',shlex.join(words)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
  if len(result.stdout)>4096 or len(result.stderr)>4096:raise ValueError('su_probe_bounds')
  return result.returncode,result.stdout.decode('utf-8','strict').strip(),result.stderr.decode('utf-8','strict').strip()
 def identity():
  code,text,error=probe(('/system/bin/stat','-c','%u:%g:%a:%d:%i:%F','/system/xbin/su'))
  if code or error or not re.fullmatch(r'0:2000:4750:[0-9]+:[1-9][0-9]*:regular file',text):raise ValueError('su_identity_unverified')
  code,digest,error=probe(('/system/bin/sha256sum','/system/xbin/su'))
  if code or error or not re.fullmatch(r'[0-9a-f]{64}  /system/xbin/su',digest):raise ValueError('su_hash_unverified')
  return {'stat':text,'sha256':digest.split()[0]}
 before=identity()
 if su_pin is not None and before!=su_pin:raise ValueError('su_generation_changed')
 code,out,error=probe(('/system/xbin/su','--help'))
 help_text="usage: su [WHO [COMMAND...]]\n\nSwitch to WHO (default 'root') and run the given COMMAND (default sh).\n\nWHO is a comma-separated list of user, group, and supplementary groups\nin that order."
 if code or bool(out) and bool(error) or (out or error)!=help_text or identity()!=before:raise ValueError('su_grammar_unverified')
 su_pin=before
 result=shell(*privileged_command(script))
 if identity()!=before:raise ValueError('su_changed_during_read')
 return result
def restored(lifecycle):
 adb,shell=native()
 for name,value in lifecycle['effectiveProxyBaseline'].items():
  if name not in ('http_proxy','global_http_proxy_host','global_http_proxy_port','global_http_proxy_pac','global_http_proxy_exclusion_list') or shell('settings','get','global',name)!=value:raise ValueError('proxy_baseline_changed')
 if len(lifecycle['effectiveProxyBaseline'])!=5:raise ValueError('proxy_baseline_incomplete')
 old=[x for x in lifecycle['commands'] if x.get('args')==['reverse','--list']]
 if not old or old[0].get('exit')!=0 or old[0].get('stdoutTruncated') is not False or fixed_run([*adb,'reverse','--list']).strip()!=old[0]['stdout'].strip():raise ValueError('reverse_baseline_changed')
 stage='/data/local/tmp/vpn-control-installer-api'+str(expected['api'])
 shell('test','!','-e',stage)
 # A fixed authenticated privileged READ is needed for the original zygote
 # namespace and app-private installer preconditions. Never root/unroot here.
 script='set -eu; test "$(id -u)" = 0; z=$(pidof zygote64); test -n "$z"; test "${z#* }" = "$z"; cat /proc/$z/mountinfo'
 mounts=authenticated_privileged_read(shell,script)
 if any(len(line.split())<6 for line in mounts.splitlines()) or not mounts.strip():raise ValueError('namespace_mounts_unknown')
 if any(line.split()[4]==lifecycle['target'] for line in mounts.splitlines()):raise ValueError('fixture_mount_present')
 return {'uid':'2000','baseSha256':binding['originalIntent']['pair']['baseSha256'],'mountsSha256':hashlib.sha256(mounts.encode()).hexdigest()}
def installer_preflight():
 adb,shell=native()
 script='set -eu; test "$(id -u)" = 0; p=/data/user/0/com.kardinal.vpncontrol; test -d "$p/no_backup/control-install-sessions"; for d in "$p/no_backup/control-install-sessions" "$p/files/control-installs"; do test ! -L "$d"; if test -e "$d"; then test -d "$d"; test -z "$(find "$d" -mindepth 1 -maxdepth 1 -print)"; fi; done; printf installer_metadata_empty'
 if authenticated_privileged_read(shell,script)!='installer_metadata_empty':raise ValueError('installer_metadata_not_empty')
 package=shell('dumpsys','package')
 # Android package dump must expose its active-session section explicitly.
 match=re.search(r'(?m)^Active install sessions:\s*\n(.*?)(?=^Historical install sessions:|^Legacy install sessions:)',package,re.S|re.M)
 if match is None or match.group(1).strip() not in ('','(none)','None'):raise ValueError('os_installer_sessions_not_empty')
 return {'appInstallerMetadata':'empty','osActiveSessions':'empty','getterReconciliation':'normal_with_empty_precondition'}
def measure(index):
 captured={}
 def public(*words):
  result=public_cli(*words);captured[' '.join(words)]=result;return result
 def export():
  path=retired/('routing-'+index+'.json')
  result=public_cli('routing','export','--output',str(path),'--format','json')
  if result.get('controllerId')!=owner or result.get('configurationRevision')!=revision:raise ValueError('routing_owner_changed')
  raw,pin=snapshot_file(path)
  if result.get('data',{}).get('bytes')!=len(raw) or result.get('data',{}).get('format')!='json':raise ValueError('routing_export_invalid')
  return json.loads(raw)
 def preflight():captured['installerPrecondition']=installer_preflight()
 _,shell=native()
 value=measure_public_snapshot(public,export,owner,revision,binding['originalIntent']['pair']['baseSha256'],preflight)
 put(retired/('public-'+index+'.json'),_canonical(captured))
 return value
fd=device_lock()
try:
 lockpin=snapshot_file(lock,1024)[1];lockparents=_ancestry(lock.parent)
 if _generation(os.fstat(fd))!=lockpin['generation']:raise ValueError('device_lock_changed')
 if action not in ('admit','retire'):raise ValueError('retirement_action_invalid')
 if action=='admit':
  retired.mkdir(mode=0o700)
  put(retired/'binding.json',_canonical(binding))
 else:
  if json.loads(private(retired/'binding.json'))!={k:v for k,v in binding.items() if k not in ('admittedProofSha256','admittedProofPin')}:raise ValueError('retirement_binding_changed')
  admitted=json.loads(private(retired/'proof.json',1048576))
  if snapshot_file(retired/'proof.json',1048576)[1]!=binding['admittedProofPin'] or binding['admittedProofPin']['sha256']!=binding['admittedProofSha256']:raise ValueError('retirement_proof_changed')
 verify_manifest()
 if json.loads(private(job/'dispatch.json'))!=expected or json.loads(private(output/'intent.json'))!=binding['originalIntent']:raise ValueError('original_intent_changed')
 original=binding['originalIntent']
 if original.get('correlationId')!=correlation or original.get('pair',{}).get('sourceSha')!=expected['sourceSha'] or original.get('pair',{}).get('targetArtifactId')!=expected['targetArtifactId']:raise ValueError('source_binding_changed')
 paths={name:job/name for name in REQUIRED_FILES if name not in ('local-lease.json','remote-lease.json','opening-routing.json','closing-routing.json','closing-readback.json')}
 paths.update({'remote-lease.json':lease,'opening-routing.json':pathlib.Path(original['backupPath']),
  'closing-routing.json':root/('android-readback-'+binding['closingReadbackCorrelationId'])/'routing.json',
  'closing-readback.json':root/('android-readback-job-'+binding['closingReadbackCorrelationId'])/'result.json'})
 pins={name:snapshot_file(path)[1] for name,path in paths.items()};pins['local-lease.json']=binding['localLeasePin']
 parents={name:_ancestry(path.parent) for name,path in paths.items()}
 lifecycle=json.loads(private(output/'lifecycle-receipt.json',1048576))
 if pins['output/lifecycle-receipt.json']['sha256']!=binding['lifecycleSha256']:raise ValueError('lifecycle_receipt_changed')
 if lifecycle.get('installerIntent')!={'correlationId':correlation,'sourceSha':expected['sourceSha'],'targetArtifactId':expected['targetArtifactId'],'backupSha256':original['backupSha256']} or lifecycle.get('failure',{}).get('type')!='RuntimeError' or lifecycle.get('cleanupFailures')!=[]:raise ValueError('original_failure_binding_changed')
 if json.loads(private(output/'phase-check.json'))!={'correlationId':correlation,'phase':'check'}:raise ValueError('check_phase_missing')
 if any((output/name).exists() or (output/name).is_symlink() for name in ('phase-download.json','phase-noninteractive.json','phase-interactive.json','probe.json','handoff.json')):raise ValueError('later_phase_or_terminal_present')
 worker=json.loads(private(job/'identity.json'))
 if any(type(worker.get(k)) is not int or worker[k]<1 for k in ('pid','startTicks')) or ticks(worker['pid'])==worker['startTicks']:raise ValueError('original_worker_not_stopped')
 fixture_stopped(output); fixture=json.loads(private(output/'fixture-identity.json'))
 closing=json.loads(private(paths['closing-readback.json']))
 if closing.get('state')!='complete' or closing.get('result')!=binding['closingResult'] or closing['result'].get('guard',{}).get('controllerId')!=owner or closing['result']['guard'].get('configurationRevision')!=revision or closing['result'].get('package',{}).get('baseSha256')!=original['pair']['baseSha256']:raise ValueError('closing_owner_not_explicitly_admitted')
 openingraw=private(paths['opening-routing.json'],67108864)
 if hashlib.sha256(openingraw).hexdigest()!=original['backupSha256'] or len(openingraw)!=original['backupSize']:raise ValueError('original_routing_backup_changed')
 routing=routing_digest(json.loads(openingraw))
 if routing_digest(json.loads(private(paths['closing-routing.json'],67108864)))!=routing:raise ValueError('closing_routing_changed')
 exact={'owner':'android-installer','host':host,'device':device,'correlationId':correlation}
 if json.loads(private(lease,1024))!=exact:raise ValueError('lease_owner_changed')
 nativeproof=restored(lifecycle)
 suffix='admit' if action=='admit' else 'retire'
 snapshots=[measure(suffix+'-'+str(i)) for i in range(2)]
 restored(lifecycle);guard_files(pins,paths,parents);verify_manifest();fixture_stopped(output)
 if ticks(worker['pid'])==worker['startTicks']:raise ValueError('worker_returned')
 proof=validate_proof({'originalCorrelationId':correlation,'retirementCorrelationId':binding['retirementCorrelationId'],
  'closingReadbackCorrelationId':binding['closingReadbackCorrelationId'],'originalOutcome':'unknown','measurementUid':os.getuid(),'localLeaseUid':binding['localLeasePin']['generation'][6],
  'historicalSettingsSource':'unavailable','productDataMutationAllowed':False,'sourceSha':expected['sourceSha'],
  'toolBundleId':expected['toolBundle']['toolBundleId'],'intentSha256':pins['output/intent.json']['sha256'],
  'lifecycleSha256':pins['output/lifecycle-receipt.json']['sha256'],'worker':{**worker,'stopped':True},
  'fixture':{'pid':fixture['pid'],'startTicks':fixture['startTicks'],'stopped':True,'portRefused':True},
  'phases':{'check':True,'download':False,'noninteractive':False,'interactive':False},'failureType':'RuntimeError',
  'cleanupFailures':[],'probeAbsent':True,'freshOwnerAdmission':True,'nativeRestored':True,
  'opening':{'packageSha256':original['pair']['baseSha256'],'routingSha256':routing},'snapshots':snapshots,'files':pins,'parentGenerations':parents,'deviceLockPin':lockpin,'deviceLockParents':lockparents,'privilegedHelperPin':su_pin})
 if action=='admit':
  put(retired/'proof.json',_canonical(proof));put(retired/'native.json',_canonical(nativeproof))
  emit('admitted',None,proofSha256=hashlib.sha256(_canonical(proof)).hexdigest(),proofPin=snapshot_file(retired/'proof.json',1048576)[1],proof=proof,retirementCorrelationId=binding['retirementCorrelationId'],originalOutcome='unknown')
 if any(admitted[name]!=proof[name] for name in ('files','snapshots','parentGenerations','deviceLockPin','deviceLockParents','privilegedHelperPin')):raise ValueError('admitted_state_changed')
 if snapshot_file(lock,1024)[1]!=lockpin or _generation(os.fstat(fd))!=lockpin['generation'] or _ancestry(lock.parent)!=lockparents:raise ValueError('device_lock_changed')
 guard_files(pins,paths,parents)
 release_fenced(lease,root/('android-native-device-'+device+'-'+correlation+'.release-intent'),
  root/('android-native-device-'+device+'-'+binding['retirementCorrelationId']+'.retirement-fence'),exact,pins['remote-lease.json']['generation'],pins['remote-lease.json']['sha256'],proof)
 put(retired/'terminal.json',_canonical({'originalOutcome':'unknown','leaseReleased':True,'proofSha256':binding['admittedProofSha256']}))
 emit('retired',None,leaseReleased=True,retirementCorrelationId=binding['retirementCorrelationId'],originalOutcome='unknown')
except (OSError,ValueError,TypeError,KeyError,IndexError):unknown('retirement_proof_or_generation_unknown')
finally:unlock(fd)
'''


def remote_source() -> str:
    """Generate reviewed fixed control flow; never execute staged lifecycle bytes."""
    from agent_tools import android_installer_dispatch as dispatch
    definitions = dispatch._REMOTE.split("\ninfo=root.lstat()", 1)[0]
    if hashlib.sha256(definitions.encode()).hexdigest() != _DISPATCH_DEFINITIONS_SHA256:
        raise ValueError("frozen_dispatch_definitions_changed")
    functions = (privileged_command, validate_original, _canonical, routing_digest, measure_public_snapshot, validate_proof,
                 _generation, _directory, _ancestry, private_snapshot, _create, release_fenced)
    return definitions + "\nfrom pathlib import Path\nfrom typing import Any\nimport shlex\n" + \
        "_SHA=re.compile(r'[0-9a-f]{64}\\Z');_UUID=re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\\Z')\n" + \
        "REQUIRED_FILES=frozenset(" + repr(sorted(REQUIRED_FILES)) + ")\n" + \
        "\n".join(inspect.getsource(function) for function in functions) + _REMOTE_TAIL


def _local_directory(root: Path, correlation: str) -> Path:
    if not isinstance(correlation, str) or not _UUID.fullmatch(correlation): raise ValueError("retirement_uuid_invalid")
    parent = root / ".rag_index" / "android-installer-failed-check-retirement"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = _directory(parent); os.close(fd)
    return parent / correlation


def _save(path: Path, value: dict[str, Any]) -> None:
    parent = _directory(path.parent)
    try: _create(parent, path.name, value)
    finally: os.close(parent)


@contextmanager
def _local_lock(root: Path, host: str, device: str):
    from agent_tools import android_installer_dispatch as dispatch
    if not re.fullmatch(r"[A-Za-z0-9_-]+", host) or not re.fullmatch(r"[A-Za-z0-9_-]+", device): raise ValueError("lease_alias_invalid")
    directory = dispatch._shared_directory(root); parents = _ancestry(directory)
    parent = _directory(directory); name = "lock-" + host + "-" + device + ".json"
    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        pin = _generation(os.fstat(fd))
        if pin[5:] != [0o600, os.getuid(), 1] or not stat.S_ISREG(os.fstat(fd).st_mode): raise ValueError("local_lock_unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        def guard():
            if _generation(os.fstat(fd)) != pin or _generation(os.stat(name, dir_fd=parent, follow_symlinks=False)) != pin or _ancestry(directory) != parents:
                raise ValueError("local_lock_generation_changed")
        guard()
        yield directory / ("lease-" + host + "-" + device + ".json"), guard
        guard()
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd); os.close(parent)


def _call(root: Path, dispatch_intent: dict[str, Any], binding: dict[str, Any], action: str) -> dict[str, Any]:
    from agent_tools import ssh_transport, ssh_transfer, android_observation, android_installer_tool_bundle, android_cli_stage
    config = ssh_transport.load_config(root); host = dispatch_intent["host"]; device = dispatch_intent["device"]
    if (host not in config.hosts or device not in config.hosts[host].android_devices or
        ssh_transport.connection_host(config, host).password is not None or
        str(config.hosts[host].fixture_transfer_root) != dispatch_intent["fixtureRoot"]):
        return {"state": "unknown", "reason": "route_changed"}
    profile = android_observation._profile(config.hosts[host].android_devices[device])
    if any(profile[field] != dispatch_intent["remote"][other] for field, other in
           (("serial", "serial"), ("expectedAvd", "avd"), ("api", "api"), ("adb", "adb"))):
        return {"state": "unknown", "reason": "device_profile_changed"}
    cli = android_cli_stage.collect(root, dispatch_intent["cliStageCorrelationId"])
    if (cli.get("ok") is not True or cli.get("state") != "published" or cli.get("sourceSha") != dispatch_intent["sourceSha"] or
        cli.get("receipt", {}).get("cliPath") != dispatch_intent["remote"]["cli"]):
        return {"state": "unknown", "reason": "original_cli_stage_changed"}
    tools = android_installer_tool_bundle.load(root, dispatch_intent["toolBundleId"])
    if dispatch_intent["remote"].get("toolBundle") != {key: tools[key] for key in ("toolBundleId", "reviewedTreeSha256", "manifest")}:
        return {"state": "unknown", "reason": "tool_bundle_binding_changed"}
    program = remote_source()
    if binding.get("adapterSha256") != hashlib.sha256(program.encode()).hexdigest(): return {"state": "unknown", "reason": "adapter_source_changed"}
    packet = {**dispatch_intent["remote"], "retirementBinding": binding}
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c",
        "exec(" + repr(program) + ")", action, dispatch_intent["fixtureRoot"], host, device,
        dispatch_intent["correlationId"], json.dumps(packet, sort_keys=True, separators=(",", ":"))))
    try:
        code, raw = ssh_transfer._bounded_run(argv, None, 300)
        result = json.loads(raw) if code == 0 and len(raw) <= 1_048_576 else None
        if (isinstance(result, dict) and result.get("correlationId") == dispatch_intent["correlationId"] and
            result.get("state") in {"admitted", "retired", "unknown"}): return result
    except (OSError, ValueError, UnicodeError, ssh_transfer.SshTransferError): pass
    return {"state": "unknown", "reason": "retirement_transport_or_receipt_unknown"}


def admit(root: Path | str, original_correlation_id: str, retirement_correlation_id: str,
          closing_readback_correlation_id: str, expected_current_owner: str,
          expected_current_revision: int) -> dict[str, Any]:
    """Authenticate and persist a new metadata-only retirement admission once."""
    from agent_tools import android_installer_dispatch as dispatch, android_admission_readback as readback
    root = Path(root).resolve()
    if original_correlation_id != "0dd55704-1e80-4d62-8d9d-2f0a123e0c3b": raise ValueError("only_reviewed_failed_check_allowed")
    if not _UUID.fullmatch(closing_readback_correlation_id) or not isinstance(expected_current_owner, str) or not expected_current_owner or type(expected_current_revision) is not int or expected_current_revision < 0:
        raise ValueError("closing_admission_binding_invalid")
    directory = _local_directory(root, retirement_correlation_id)
    if retirement_correlation_id == original_correlation_id: raise ValueError("separate_retirement_required")
    original_dir = root / ".rag_index" / "android-installer-dispatch" / original_correlation_id
    raw, dispatch_generation, dispatch_hash = private_snapshot(original_dir / "dispatch.json", 16384)
    intent = json.loads(raw)
    raw, product_generation, product_hash = private_snapshot(original_dir / "intent.json", 16384)
    product = json.loads(raw)
    validate_original(intent,product,original_correlation_id)
    with _local_lock(root, intent["host"], intent["device"]) as (lease, lock_guard):
        lease_raw, lease_generation, lease_hash = private_snapshot(lease, 1024)
        exact = dispatch._lease_value("android-installer", intent["host"], intent["device"], original_correlation_id)
        if json.loads(lease_raw) != exact: raise ValueError("original_local_lease_changed")
        closing = readback.async_collect(root, closing_readback_correlation_id)
        observed = closing.get("result", {})
        if (closing.get("ok") is not True or closing.get("state") != "complete" or
            observed.get("guard", {}).get("controllerId") != expected_current_owner or
            observed.get("guard", {}).get("configurationRevision") != expected_current_revision or
            observed.get("package", {}).get("baseSha256") != product["pair"]["baseSha256"]):
            return {"ok": False, "state": "unknown", "reason": "closing_owner_not_admitted", "originalOutcome": "unknown"}
        binding = {"retirementCorrelationId": retirement_correlation_id, "closingReadbackCorrelationId": closing_readback_correlation_id,
            "owner": expected_current_owner, "revision": expected_current_revision, "originalIntent": product,
            "closingResult": observed, "localLeasePin": {"generation": lease_generation, "sha256": lease_hash},
            "lifecycleSha256": "b550f7ae50f60bcf53c0d688efda2165a6c39b505a997235bd9d78c710757e59",
            "adapterSha256": hashlib.sha256(remote_source().encode()).hexdigest()}
        local = {"dispatch": intent, "binding": binding, "dispatchPin": {"generation": dispatch_generation, "sha256": dispatch_hash},
                 "intentPin": {"generation": product_generation, "sha256": product_hash}}
        directory.mkdir(mode=0o700); _save(directory / "intent.json", local)
        remote = _call(root, intent, binding, "admit")
        lock_guard()
        if remote.get("state") != "admitted": return {"ok": False, **remote, "originalOutcome": "unknown"}
        proof = remote.get("proof")
        if not isinstance(proof, dict) or hashlib.sha256(_canonical(proof)).hexdigest() != remote.get("proofSha256"):
            return {"ok": False, "state": "unknown", "reason": "remote_proof_invalid", "originalOutcome": "unknown"}
        if private_snapshot(lease, 1024)[1:] != (lease_generation, lease_hash): raise ValueError("local_lease_changed_during_admission")
        _save(directory / "admitted.json", remote)
        return {"ok": True, "state": "admitted", "retirementCorrelationId": retirement_correlation_id,
                "proofSha256": remote["proofSha256"], "originalOutcome": "unknown", "replayAllowed": False}


def retire(root: Path | str, retirement_correlation_id: str) -> dict[str, Any]:
    """Consume admitted retirement once; preserve all product state and evidence."""
    from agent_tools import android_installer_dispatch as dispatch
    root = Path(root).resolve(); directory = _local_directory(root, retirement_correlation_id)
    raw, local_generation, local_hash = private_snapshot(directory / "intent.json", 65536); local = json.loads(raw)
    raw, admitted_generation, admitted_hash = private_snapshot(directory / "admitted.json", 65536); admitted = json.loads(raw)
    intent = local["dispatch"]; binding = local["binding"]; original = intent["correlationId"]
    validate_original(intent,binding['originalIntent'],original)
    if binding.get("retirementCorrelationId") != retirement_correlation_id or admitted.get("retirementCorrelationId") != retirement_correlation_id or admitted.get("state") != "admitted": raise ValueError("retirement_admission_changed")
    if hashlib.sha256(_canonical(admitted.get('proof'))).hexdigest()!=admitted.get('proofSha256') or admitted.get('proofPin',{}).get('sha256')!=admitted.get('proofSha256'):
        raise ValueError('retirement_proof_hash_changed')
    validate_proof(admitted['proof'])
    original_dir = root / ".rag_index" / "android-installer-dispatch" / original
    with _local_lock(root, intent["host"], intent["device"]) as (lease, lock_guard):
        for name, pin in (("dispatch.json", local["dispatchPin"]), ("intent.json", local["intentPin"])):
            _, generation, digest = private_snapshot(original_dir / name, 16384)
            if {"generation": generation, "sha256": digest} != pin: raise ValueError("original_local_generation_changed")
        lease_raw, lease_generation, lease_hash = private_snapshot(lease, 1024)
        if {"generation": lease_generation, "sha256": lease_hash} != binding["localLeasePin"]: raise ValueError("original_local_lease_changed")
        _save(directory / "release-request.json", {"proofSha256": admitted["proofSha256"], "originalOutcome": "unknown"})
        if private_snapshot(directory / "intent.json", 65536)[1:] != (local_generation, local_hash) or private_snapshot(directory / "admitted.json", 65536)[1:] != (admitted_generation, admitted_hash): raise ValueError("local_admission_generation_changed_before_effect")
        lock_guard()
        remote = _call(root, intent, {**binding, "admittedProofSha256": admitted["proofSha256"], "admittedProofPin": admitted["proofPin"]}, "retire")
        lock_guard()
        if remote.get("state") != "retired" or remote.get("leaseReleased") is not True:
            return {"ok": False, **remote, "originalOutcome": "unknown", "replayAllowed": False}
        if private_snapshot(directory / "intent.json", 65536)[1:] != (local_generation, local_hash) or private_snapshot(directory / "admitted.json", 65536)[1:] != (admitted_generation, admitted_hash): raise ValueError("local_admission_generation_changed")
        exact = dispatch._lease_value("android-installer", intent["host"], intent["device"], original)
        release_fenced(lease, lease.parent / ("release-" + original + ".json"), lease.parent / ("retirement-" + retirement_correlation_id + ".json"),
                       exact, lease_generation, lease_hash, admitted["proof"])
        _save(directory / "terminal.json", {"originalOutcome": "unknown", "leaseReleased": True,
                                            "proofSha256": admitted["proofSha256"]})
        return {"ok": True, "state": "retired", "leaseReleased": True, "originalOutcome": "unknown", "replayAllowed": False}


def remote_diagnostic_source() -> str:
    """Separate measured diagnosis; original adapter generation remains unchanged."""
    original = remote_source()
    prefix = original.split("\nfd=device_lock()\n", 1)[0]
    prefix = prefix.replace("def unknown(reason): emit('unknown',reason)", "def unknown(reason): raise DiagnosticFailure(reason)")
    start = original.index("\n verify_manifest()\n if json.loads(private(job/'dispatch.json'))")
    stop = original.index("\n nativeproof=restored(lifecycle)", start)
    checks = "\n".join(line[1:] if line.startswith(" ") else line for line in original[start:stop].splitlines())
    phases = (("verify_manifest()", "original-manifest"),
        ("lifecycle=json.loads", "original-lifecycle"),
        ("if json.loads(private(output/'phase-check.json'))", "phase-census"),
        ("worker=json.loads", "worker-identity"),
        ("fixture_stopped(output);", "fixture-shutdown"),
        ("closing=json.loads", "closing-readback"),
        ("openingraw=private", "routing-baseline"),
        ("exact={'owner'", "original-lease"))
    for marker, phase in phases:
        checks = checks.replace(marker, "phase=" + repr(phase) + "\n" + marker, 1)
    checks += r'''
phase='effective-proxy-census'
_,proxy_shell=native()
proxy_fields=('http_proxy','global_http_proxy_host','global_http_proxy_port','global_http_proxy_pac','global_http_proxy_exclusion_list')
current_proxy={name:proxy_shell('settings','get','global',name) for name in proxy_fields}
effect_commands=[]
for index,entry in enumerate(lifecycle['commands']):
 if entry.get('args') in (['shell','settings','put','global','http_proxy','127.0.0.1:'+str(expected['devicePort'])],['shell','settings','put','global','http_proxy',lifecycle['effectiveProxyBaseline']['http_proxy']]):
  effect_commands.append({'index':index,'sha256':hashlib.sha256(_canonical(entry)).hexdigest(),'exit':entry.get('exit')})
effective_proxy={'baseline':lifecycle['effectiveProxyBaseline'],'current':current_proxy,'originalCombinedProxyCommands':effect_commands,'lifecycleSha256':binding['lifecycleSha256']}
phase='native-restoration';restored(lifecycle)
phase='current-public-snapshot'
def readonly_measure():
 def public(*words):return public_cli(*words)
 def routing_show():
  env=public_cli_environment(expected['adb'],pathlib.Path(expected['cli']))
  value=json.loads(fixed_run([expected['cli'],'--json','--android','--serial',expected['serial'],'--timeout-seconds','30','routing','show'],limit=67108864,environment=env))
  if value.get('ok') is not True or value.get('final') is not True or value.get('code')!='OK' or value.get('controllerId')!=owner or value.get('configurationRevision')!=revision:raise ValueError('routing_owner_changed')
  return value.get('data',{}).get('routing')
 return measure_public_snapshot(public,routing_show,owner,revision,original['pair']['baseSha256'],installer_preflight)
current=[readonly_measure(),readonly_measure()]
if current[0]!=current[1] or current[0]['routingSha256']!=routing:raise ValueError('current_snapshot_changed')
phase='final-input-guard';guard_files(pins,paths,parents);verify_manifest();fixture_stopped(output)
'''
    bootstrap = r'''import base64,fcntl,hashlib,json,os,pathlib,stat,subprocess,sys
class DiagnosticFailure(Exception):pass
action,root_raw,host,device,correlation,packet_raw=sys.argv[1:]
packet=json.loads(packet_raw);diagnostic=packet.pop('diagnosticBinding');binding=packet['retirementBinding']
diagnostic_id=diagnostic['diagnosticCorrelationId'];phase='retained-binding';commands=[];failure=None;lockfd=None;effective_proxy=None
root=pathlib.Path(root_raw);initial_parent=root.lstat();initial_directory=[initial_parent.st_dev,initial_parent.st_ino,initial_parent.st_mode,initial_parent.st_uid]
def bounded(raw):
 if raw is None:raw=b''
 if isinstance(raw,str):raw=raw.encode()
 return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'truncated':len(raw)>16384,'base64':base64.b64encode(raw[:16384]).decode()}
def retain_command(argv,code,stdout,stderr):
 if len(commands)>=128:return
 commands.append({'phase':phase,'argv':bounded(json.dumps(argv).encode()),'exit':code,'stdout':bounded(stdout),'stderr':bounded(stderr)})
original_run=subprocess.run
def traced_run(*args,**kwargs):
 try:result=original_run(*args,**kwargs)
 except subprocess.TimeoutExpired as error:
  retain_command(args[0],None,error.stdout,error.stderr);raise
 retain_command(args[0],result.returncode,result.stdout,result.stderr);return result
try:
 if action!='diagnose' or diagnostic.get('originalAdapterSha256')!=ORIGINAL_SHA or binding.get('retirementCorrelationId')!='45a379b3-417e-4e00-a8e4-e2e8657c1705':raise DiagnosticFailure('diagnostic_source_binding_changed')
 sys.argv[-1]=json.dumps(packet,sort_keys=True,separators=(',',':'))
 exec(PREFIX,globals())
 if not _UUID.fullmatch(diagnostic_id):raise DiagnosticFailure('diagnostic_uuid_invalid')
 if json.loads(private(retired/'binding.json'))!=binding:raise DiagnosticFailure('retained_admission_binding_changed')
 lockfd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW);lockpin=_generation(os.fstat(lockfd));lockparents=_ancestry(lock.parent)
 if lockpin[5:]!=[0o600,os.getuid(),1] or not stat.S_ISREG(os.fstat(lockfd).st_mode) or snapshot_file(lock,1024)[1]['generation']!=lockpin:raise DiagnosticFailure('diagnostic_lock_unsafe')
 fcntl.flock(lockfd,fcntl.LOCK_EX)
 subprocess.run=traced_run
 exec(CHECKS,globals())
 if snapshot_file(lock,1024)[1]['generation']!=lockpin or _generation(os.fstat(lockfd))!=lockpin or _ancestry(lock.parent)!=lockparents:raise DiagnosticFailure('diagnostic_lock_changed')
except Exception as error:
 failure={'type':type(error).__name__,'message':bounded(str(error))}
finally:
 subprocess.run=original_run
 if lockfd is not None:fcntl.flock(lockfd,fcntl.LOCK_UN);os.close(lockfd)
receipt={'schema':1,'kind':'android-failed-check-admission-diagnostic','admissionCorrelationId':binding['retirementCorrelationId'],
 'diagnosticCorrelationId':diagnostic_id,'originalCorrelationId':correlation,'originalOutcome':'unknown',
 'historicalFailureCause':'unavailable','currentFailurePhase':phase,'exception':failure,'commands':commands,
 'originalAdapterSha256':ORIGINAL_SHA,'diagnosticSourceSha256':diagnostic.get('diagnosticSourceSha256'),'measurementState':'current-guards-passed' if failure is None else 'current-guard-failed',
 'effectiveProxy':effective_proxy,'priorDiagnosticReceiptSha256':diagnostic.get('priorDiagnosticReceiptSha256')}
try:
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 meta=os.fstat(fd)
 if [meta.st_dev,meta.st_ino,meta.st_mode,meta.st_uid]!=initial_directory or stat.S_IMODE(meta.st_mode)!=0o700 or meta.st_uid!=os.getuid():raise ValueError('diagnostic_root_changed')
 name='android-failed-check-retirement-diagnostic-'+diagnostic_id
 os.mkdir(name,0o700,dir_fd=fd);directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
 payload=(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode()
 if len(payload)>4194304:raise ValueError('diagnostic_receipt_bounds')
 target=os.open('receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
 with os.fdopen(target,'wb') as output:output.write(payload);output.flush();os.fsync(output.fileno())
 os.fsync(directory);os.close(directory);os.fsync(fd);os.close(fd)
 print(json.dumps({'state':'diagnosed','diagnosticCorrelationId':diagnostic_id,'admissionCorrelationId':binding['retirementCorrelationId'],
  'originalOutcome':'unknown','historicalFailureCause':'unavailable','currentFailurePhase':phase,
  'errorType':failure['type'] if failure and failure['type'] in ('ValueError','DiagnosticFailure','FileNotFoundError','PermissionError','TimeoutExpired','JSONDecodeError','KeyError','TypeError') else 'Other' if failure else None,
  'receiptSha256':hashlib.sha256(payload).hexdigest(),'replayAllowed':False},separators=(',',':')))
except (OSError,ValueError):print(json.dumps({'state':'unknown','reason':'diagnostic_receipt_unavailable','originalOutcome':'unknown','replayAllowed':False},separators=(',',':')))
'''
    return "ORIGINAL_SHA=" + repr(hashlib.sha256(original.encode()).hexdigest()) + "\nPREFIX=" + repr(prefix) + \
        "\nCHECKS=" + repr(checks) + "\n" + bootstrap



def diagnostic_transport(argv: list[str], receipt_path: Path, binding: dict, timeout: int = 300) -> tuple[int | None, bytes]:
    """Retain bounded local transport evidence before any JSON classification."""
    import base64, select, subprocess, time
    if receipt_path.exists() or receipt_path.is_symlink():
        raise ValueError("diagnostic_transport_reservation_already_exists")
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": 16384, "stderr": 65536}
    failure = None; code = None; process = None; oversized = False; reap = "not-started"; reap_failure = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        handles = {process.stdout: "stdout", process.stderr: "stderr"}
        deadline = time.monotonic() + timeout
        while handles:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            ready, _, _ = select.select(list(handles), [], [], remaining)
            for stream in ready:
                name = handles[stream]
                chunk = os.read(stream.fileno(), 4096)
                if not chunk:
                    del handles[stream]; continue
                streams[name].extend(chunk)
                if len(streams[name]) > limits[name]:
                    oversized = True
                    raise ValueError("diagnostic_transport_output_bounds")
        code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        reap = "finished"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        failure = {"type": type(error).__name__, "message": base64.b64encode(str(error).encode()[:16384]).decode()}
        if process is not None and process.poll() is None:
            reap = "not-reaped"
            try:
                process.kill()
                process.wait(timeout=2.0)
                reap = "reaped-after-termination"
            except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                reap_failure = type(cleanup_error).__name__
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    try: stream.close()
                    except OSError: reap_failure = "pipe-close-failed"
    evidence = {"schema": 1, "kind": "android-proxy-service-local-transport", "binding": binding,
        "argvSha256": hashlib.sha256(_canonical(argv)).hexdigest(), "argvByteSizes": [len(word.encode()) for word in argv],
        "exit": code, "exception": failure, "originalOutcome": "unknown", "oversized": oversized, "processReap": reap, "reapFailure": reap_failure}
    for name, raw in streams.items():
        evidence[name] = {"observedBytes": len(raw), "complete": failure is None,
            "sha256": hashlib.sha256(raw).hexdigest(), "base64": base64.b64encode(raw[:limits[name]]).decode(),
            "truncated": len(raw) > limits[name]}
    _save(receipt_path, evidence)
    return code, bytes(streams["stdout"]) if failure is None else b""

def _diagnose_failed_admission(root: Path | str, admission_correlation_id: str,
                              diagnostic_correlation_id: str, *, service: bool = False, metadata: bool = False, metadata_os: bool = False) -> dict[str, Any]:
    """Diagnose only retained 45 admission; never re-admit or release its lease."""
    from agent_tools import ssh_transport, ssh_transfer, android_observation, android_installer_tool_bundle
    root = Path(root).resolve()
    if admission_correlation_id != "45a379b3-417e-4e00-a8e4-e2e8657c1705":raise ValueError('only_retained_failed_admission_allowed')
    directory = _local_directory(root, admission_correlation_id)
    raw,generation,digest=private_snapshot(directory/'intent.json',65536);local=json.loads(raw)
    intent=local['dispatch'];binding=local['binding']
    validate_original(intent,binding['originalIntent'],intent['correlationId'])
    if binding['retirementCorrelationId']!=admission_correlation_id or binding['adapterSha256']!=hashlib.sha256(remote_source().encode()).hexdigest():raise ValueError('original_adapter_generation_changed')
    if not _UUID.fullmatch(diagnostic_correlation_id) or diagnostic_correlation_id in (admission_correlation_id,intent['correlationId']):raise ValueError('separate_diagnostic_uuid_required')
    config=ssh_transport.load_config(root);host=intent['host'];device=intent['device']
    if host not in config.hosts or ssh_transport.connection_host(config,host).password is not None or str(config.hosts[host].fixture_transfer_root)!=intent['fixtureRoot']:raise ValueError('diagnostic_route_changed')
    profile=android_observation._profile(config.hosts[host].android_devices[device])
    if any(profile[field]!=intent['remote'][other] for field,other in (('serial','serial'),('expectedAvd','avd'),('api','api'),('adb','adb'))):raise ValueError('diagnostic_device_profile_changed')
    tools=android_installer_tool_bundle.load(root,intent['toolBundleId'])
    if intent['remote']['toolBundle']!={key:tools[key] for key in ('toolBundleId','reviewedTreeSha256','manifest')}:raise ValueError('diagnostic_tool_bundle_changed')
    program=remote_metadata_bound_proxy_service_source() if metadata_os else remote_installer_metadata_diagnostic_source() if metadata else remote_proxy_service_diagnostic_source() if service else remote_diagnostic_source()
    prior=root/'.runtime'/'parity-evidence'/'android-current'/('api35-retirement-d0fb-native-receipt.json' if service else 'api35-retirement-d7ba-native-receipt.json')
    _,prior_generation,prior_hash=private_snapshot(prior,1048576)
    if prior_hash!=('96489c3073bb358ba9a51e61331c6dc67eefae5de7c13f0dd2cff727c0b04eba' if service else 'e712cf8565efc4bd2fe6733d20d97482f5daa9fea94b9d8ce31d09c380e323f0'):raise ValueError('prior_diagnostic_receipt_changed')
    diagnostic={'diagnosticCorrelationId':diagnostic_correlation_id,'originalAdapterSha256':binding['adapterSha256'],'diagnosticSourceSha256':hashlib.sha256(program.encode()).hexdigest(),'priorDiagnosticReceiptSha256':prior_hash}
    if metadata:
        capsule=root/'.runtime'/'parity-evidence'/'android-current'/'api35-service-10eb-error-capsule.json'
        capsule_raw,capsule_generation,capsule_hash=private_snapshot(capsule,1048576)
        if json.loads(capsule_raw).get('receiptSha256')!='519d6d96c5683e10e08134ad6084ed650a34a4cf3dda5bd075b4d654abe0020a':raise ValueError('metadata_prior_failure_binding_changed')
        diagnostic['priorErrorCapsulePin']={'generation':capsule_generation,'sha256':capsule_hash}
    if metadata_os:
        identity_path=directory/'metadata-identity-1247d3dc-557e-4c99-a1b3-1ac737128cf3-capsule.json'
        identity_raw,identity_gen,identity_sha=private_snapshot(identity_path,8192)
        if identity_sha!=_OS_METADATA_CAPSULE_SHA or json.loads(identity_raw)!=_OS_METADATA_IDENTITY:raise ValueError('metadata_os_local_identity_changed')
        diagnostic['metadataIdentity']=_OS_METADATA_IDENTITY
        diagnostic['metadataIdentityCapsulePin']={'generation':identity_gen,'sha256':identity_sha}
    packet={**intent['remote'],'retirementBinding':binding,'diagnosticBinding':diagnostic}
    with _local_lock(root,host,device) as (lease,guard):
        original_dir=root/'.rag_index'/'android-installer-dispatch'/intent['correlationId']
        def originals_guard():
            for name,key in (('dispatch.json','dispatchPin'),('intent.json','intentPin')):
                _,pin,sha=private_snapshot(original_dir/name,16384)
                if {'generation':pin,'sha256':sha}!=local[key]:raise ValueError('diagnostic_original_source_generation_changed')
        originals_guard()
        _,lease_gen,lease_hash=private_snapshot(lease,1024)
        if {'generation':lease_gen,'sha256':lease_hash}!=binding['localLeasePin']:raise ValueError('diagnostic_local_lease_changed')
        request=directory/('diagnostic-'+diagnostic_correlation_id+'.json')
        _save(request,{'schema':1,'admissionIntentPin':{'generation':generation,'sha256':digest},
            'originalAdapterSha256':binding['adapterSha256'],'diagnosticSourceSha256':hashlib.sha256(program.encode()).hexdigest(),**diagnostic})
        if private_snapshot(directory/'intent.json',65536)[1:]!=(generation,digest):raise ValueError('diagnostic_admission_generation_changed')
        guard()
        originals_guard()
        if metadata_os and private_snapshot(identity_path,8192)[1:]!=(identity_gen,identity_sha):raise ValueError('metadata_os_local_identity_changed')
        argv=ssh_transport.build_ssh_argv(config,host,60,command=('python3','-I','-B','-c','exec('+repr(program)+')','diagnose',intent['fixtureRoot'],host,device,intent['correlationId'],json.dumps(packet,sort_keys=True,separators=(',',':'))))
        try:
            transport_path=directory/('diagnostic-'+diagnostic_correlation_id+'-transport.json')
            code,out=diagnostic_transport(argv,transport_path,diagnostic)
            value=json.loads(out) if code==0 and len(out)<=16384 else None
        except (OSError,ValueError,UnicodeError,ssh_transfer.SshTransferError):value=None
        guard()
        originals_guard()
        if private_snapshot(directory/'intent.json',65536)[1:]!=(generation,digest) or private_snapshot(lease,1024)[1:]!=(lease_gen,lease_hash):raise ValueError('diagnostic_original_changed')
        if private_snapshot(prior,1048576)[1:]!=(prior_generation,prior_hash):raise ValueError('prior_diagnostic_receipt_changed')
        if metadata_os and private_snapshot(identity_path,8192)[1:]!=(identity_gen,identity_sha):raise ValueError('metadata_os_local_identity_changed')
        if metadata and private_snapshot(capsule,1048576)[1:]!=(capsule_generation,capsule_hash):raise ValueError('metadata_prior_error_capsule_changed')
        if not isinstance(value,dict) or value.get('state')!='diagnosed' or value.get('diagnosticCorrelationId')!=diagnostic_correlation_id or value.get('admissionCorrelationId')!=admission_correlation_id:
            return {'ok':False,'state':'unknown','reason':'diagnostic_transport_or_receipt_unknown','originalOutcome':'unknown','replayAllowed':False,'transportReceiptPath':str(transport_path)}
        _save(directory/('diagnostic-'+diagnostic_correlation_id+'-result.json'),value)
        return {'ok':True,**value}


def diagnose_failed_admission(root: Path | str, admission_correlation_id: str,
                              diagnostic_correlation_id: str) -> dict[str, Any]:
    return _diagnose_failed_admission(root, admission_correlation_id, diagnostic_correlation_id)


def diagnose_proxy_service(root: Path | str, diagnostic_correlation_id: str) -> dict[str, Any]:
    """Capture authoritative service output; no proxy restoration or OS inference."""
    return _diagnose_failed_admission(root, "45a379b3-417e-4e00-a8e4-e2e8657c1705", diagnostic_correlation_id, service=True)


def remote_proxy_service_diagnostic_source() -> str:
    """A separate version of the read-only prefix bound to the measured d0fb residue."""
    import ast
    original = remote_diagnostic_source()
    tree = ast.parse(original)
    constants = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body[:3]}
    checks = constants["CHECKS"]
    checks = checks.replace("phase='native-restoration';restored(lifecycle)", r"""
phase='d0fb-residue-binding'
prior_path=root/'android-failed-check-retirement-diagnostic-d0fb92e8-34fd-49b1-8e84-8617e524d8eb'/'receipt.json'
prior_raw,prior_pin=snapshot_file(prior_path,1048576)
if prior_pin['sha256']!='96489c3073bb358ba9a51e61331c6dc67eefae5de7c13f0dd2cff727c0b04eba':raise ValueError('d0fb_receipt_changed')
prior=json.loads(prior_raw)
residue={'http_proxy':'null','global_http_proxy_host':'127.0.0.1','global_http_proxy_port':'45635','global_http_proxy_pac':'null','global_http_proxy_exclusion_list':''}
if prior.get('admissionCorrelationId')!=binding['retirementCorrelationId'] or prior.get('originalCorrelationId')!=correlation or prior.get('originalOutcome')!='unknown' or prior.get('effectiveProxy',{}).get('current')!=residue or prior['effectiveProxy'].get('baseline')!=lifecycle['effectiveProxyBaseline'] or prior['effectiveProxy'].get('lifecycleSha256')!=binding['lifecycleSha256'] or current_proxy!=residue or expected['devicePort']!=45635:raise ValueError('exact_measured_residue_changed')
if {name:proxy_shell('settings','get','global',name) for name in proxy_fields}!=residue:raise ValueError('proxy_changed_between_reads')
# This copy admits ONLY the exact known proxy residue for READ-only service
# inspection. Original lifecycle and native-restoration guard remain immutable.
phase='nonproxy-native-restoration'
nonproxy_lifecycle=dict(lifecycle);nonproxy_lifecycle['effectiveProxyBaseline']=residue
restored(nonproxy_lifecycle)
""")
    checks += r"""
phase='service-capture'
if snapshot_file(prior_path,1048576)[1]!=prior_pin:raise ValueError('d0fb_generation_changed')
if {name:proxy_shell('settings','get','global',name) for name in proxy_fields}!=residue:raise ValueError('proxy_changed_before_service_capture')
service_result=subprocess.run([expected['adb'],'-s',expected['serial'],'shell','-T','/system/bin/dumpsys connectivity'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
if len(service_result.stdout)>1048576 or len(service_result.stderr)>65536:raise ValueError('service_capture_bounds')
service_bytes=service_result.stdout
service_capture={'name':'connectivity.txt','bytes':len(service_bytes),'sha256':hashlib.sha256(service_bytes).hexdigest(),'exit':service_result.returncode,'stderr':{'bytes':len(service_result.stderr),'sha256':hashlib.sha256(service_result.stderr).hexdigest()},'interpretation':'unreviewed','historicalRowPresence':'unavailable','proxyRestorationPerformed':False}
if snapshot_file(prior_path,1048576)[1]!=prior_pin or {name:proxy_shell('settings','get','global',name) for name in proxy_fields}!=residue:raise ValueError('proxy_or_d0fb_changed_after_capture')
guard_files(pins,paths,parents);verify_manifest();fixture_stopped(output)
"""
    start = original.index('import base64,fcntl,hashlib,json,os,pathlib,stat,subprocess,sys')
    bootstrap = original[start:]
    bootstrap = bootstrap.replace('effective_proxy=None', 'effective_proxy=None;service_capture=None;service_bytes=None')
    bootstrap = bootstrap.replace("'effectiveProxy':effective_proxy,", "'effectiveProxy':effective_proxy,'serviceCapture':service_capture,")
    bootstrap = bootstrap.replace("payload=(json.dumps(receipt", r"""if service_capture is not None:
  capture_fd=os.open('connectivity.txt',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
  with os.fdopen(capture_fd,'wb') as capture:
   capture.write(service_bytes);capture.flush();os.fsync(capture.fileno());service_capture['generation']=_generation(os.fstat(capture.fileno()))
  receipt['serviceCapture']=service_capture
 payload=(json.dumps(receipt""")
    bootstrap = bootstrap.replace("'receiptSha256':hashlib.sha256(payload).hexdigest(),", "'receiptSha256':hashlib.sha256(payload).hexdigest(),'serviceCapture':service_capture,")
    return 'ORIGINAL_SHA='+repr(constants['ORIGINAL_SHA'])+'\nPREFIX='+repr(constants['PREFIX'])+'\nCHECKS='+repr(checks)+'\n'+bootstrap


_PROXY_SERVICE_COLLECT = r"""import base64,hashlib,json,os,pathlib,re,stat,sys
root_raw,diag,kind,offset_raw,pin_raw,service_source=sys.argv[1:]
root=pathlib.Path(root_raw);offset=int(offset_raw);requested=json.loads(pin_raw)
def generation(x):return [x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,stat.S_IMODE(x.st_mode),x.st_uid,x.st_nlink]
def read(path,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  first=os.fstat(fd)
  if not stat.S_ISREG(first.st_mode) or generation(first)[5:]!=[0o600,os.getuid(),1] or first.st_size>limit:raise ValueError('private_file_unsafe')
  raw=b''
  while len(raw)<=limit:
   part=os.read(fd,min(65536,limit+1-len(raw)))
   if not part:break
   raw+=part
  if len(raw)>limit or generation(first)!=generation(os.fstat(fd)) or generation(first)!=generation(path.lstat()):raise ValueError('private_file_changed')
  return raw,{'generation':generation(first),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
 finally:os.close(fd)
try:
 if not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',diag) or kind not in ('status','receipt','connectivity') or offset<0:raise ValueError('collector_request_invalid')
 directory=root/('android-failed-check-retirement-diagnostic-'+diag)
 parents=[]
 for path in (root,directory):
  x=path.lstat()
  if not stat.S_ISDIR(x.st_mode) or stat.S_IMODE(x.st_mode)!=0o700 or x.st_uid!=os.getuid():raise ValueError('collector_parent_unsafe')
  parents.append([x.st_dev,x.st_ino])
 raw,receipt_pin=read(directory/'receipt.json',4194304);value=json.loads(raw)
 if value.get('diagnosticCorrelationId')!=diag or value.get('admissionCorrelationId')!='45a379b3-417e-4e00-a8e4-e2e8657c1705' or value.get('originalCorrelationId')!='0dd55704-1e80-4d62-8d9d-2f0a123e0c3b' or value.get('originalOutcome')!='unknown' or value.get('diagnosticSourceSha256')!=service_source:raise ValueError('collector_binding_changed')
 failure=value.get('exception');capture=value.get('serviceCapture')
 if capture is not None:
  if not isinstance(capture,dict) or capture.get('name')!='connectivity.txt' or type(capture.get('bytes')) is not int or not 0<=capture['bytes']<=1048576 or not re.fullmatch('[0-9a-f]{64}',capture.get('sha256','')) or not isinstance(capture.get('generation'),list) or len(capture['generation'])!=8:raise ValueError('capture_metadata_invalid')
  capture={key:capture[key] for key in ('name','bytes','sha256','generation','exit')}
 phase=value.get('currentFailurePhase')
 allowed_phases=('retained-binding','original-manifest','original-lifecycle','phase-census','worker-identity','fixture-shutdown','closing-readback','routing-baseline','original-lease','effective-proxy-census','d0fb-residue-binding','nonproxy-native-restoration','current-public-snapshot','final-input-guard','service-capture')
 if phase not in allowed_phases:raise ValueError('diagnostic_phase_invalid')
 error_type=failure.get('type') if isinstance(failure,dict) else None
 if error_type not in (None,'ValueError','DiagnosticFailure','FileNotFoundError','PermissionError','TimeoutExpired','JSONDecodeError','KeyError','TypeError'):error_type='Other'
 state='diagnosed-with-failure' if failure is not None else 'capture-complete' if capture is not None else 'diagnosed-without-capture'
 result={'state':state,'diagnosticCorrelationId':diag,'originalOutcome':'unknown','receiptPin':receipt_pin,'phase':phase,'errorType':error_type,'serviceCapture':capture,'replayAllowed':False}
 if kind!='status':
  selected=raw;selected_pin=receipt_pin
  if kind=='connectivity':
   if not isinstance(capture,dict) or capture.get('name')!='connectivity.txt':raise ValueError('capture_absent')
   selected,selected_pin=read(directory/'connectivity.txt',1048576)
   if capture.get('bytes')!=len(selected) or capture.get('sha256')!=selected_pin['sha256'] or capture.get('generation')!=selected_pin['generation']:raise ValueError('capture_generation_changed')
  if requested!=selected_pin or offset>len(selected):raise ValueError('collector_pin_or_offset_changed')
  result.update({'kind':kind,'offset':offset,'pin':selected_pin,'chunk':base64.b64encode(selected[offset:offset+1536]).decode(),'eof':offset+1536>=len(selected)})
 for path,pin in zip((root,directory),parents):
  x=path.lstat()
  if [x.st_dev,x.st_ino]!=pin:raise ValueError('collector_parent_changed')
 if read(directory/'receipt.json',4194304)[1]!=receipt_pin:raise ValueError('collector_receipt_changed')
 print(json.dumps(result,separators=(',',':')))
except FileNotFoundError:
 missing=not (directory/'receipt.json').exists() and not (directory/'receipt.json').is_symlink()
 print(json.dumps({'state':'absent' if missing else 'unknown','diagnosticCorrelationId':diag,'originalOutcome':'unknown','replayAllowed':False}))
except (OSError,ValueError,TypeError,KeyError):print(json.dumps({'state':'unknown','reason':'collector_proof_or_generation_unknown','diagnosticCorrelationId':diag,'originalOutcome':'unknown','replayAllowed':False}))
"""


def collect_proxy_service_receipt(root: Path | str, diagnostic_correlation_id: str,
                                  collection_correlation_id: str, *, kind: str = "status",
                                  offset: int = 0, expected_pin: dict | None = None, metadata_bound: bool = False) -> dict[str, Any]:
    """Read an existing service diagnostic; never execute the diagnostic again."""
    from agent_tools import ssh_transport
    root=Path(root).resolve()
    if (not _UUID.fullmatch(diagnostic_correlation_id) or not _UUID.fullmatch(collection_correlation_id)
            or diagnostic_correlation_id==collection_correlation_id or kind not in ('status','receipt','connectivity')
            or type(offset) is not int or offset<0 or kind!='status' and not isinstance(expected_pin,dict)):
        raise ValueError('collector_request_invalid')
    directory=_local_directory(root,'45a379b3-417e-4e00-a8e4-e2e8657c1705')
    raw,local_gen,local_hash=private_snapshot(directory/'intent.json',65536);local=json.loads(raw)
    intent=local['dispatch'];binding=local['binding'];validate_original(intent,binding['originalIntent'],intent['correlationId'])
    request=directory/('diagnostic-'+diagnostic_correlation_id+'.json')
    request_raw,request_gen,request_hash=private_snapshot(request,65536);request_value=json.loads(request_raw)
    service_hash=hashlib.sha256((remote_metadata_bound_proxy_service_source() if metadata_bound else remote_proxy_service_diagnostic_source()).encode()).hexdigest()
    if request_value.get('diagnosticSourceSha256')!=service_hash or request_value.get('admissionIntentPin')!={'generation':local_gen,'sha256':local_hash}:raise ValueError('collector_local_binding_changed')
    record=directory/('collection-'+collection_correlation_id+'.json')
    _save(record,{'diagnosticCorrelationId':diagnostic_correlation_id,'kind':kind,'offset':offset,'expectedPin':expected_pin,'requestPin':{'generation':request_gen,'sha256':request_hash}})
    config=ssh_transport.load_config(root)
    argv=ssh_transport.build_ssh_argv(config,intent['host'],60,command=('python3','-I','-B','-c','exec('+repr(remote_metadata_bound_proxy_collector_source() if metadata_bound else _PROXY_SERVICE_COLLECT)+')',intent['fixtureRoot'],diagnostic_correlation_id,kind,str(offset),json.dumps(expected_pin),service_hash))
    code,out=diagnostic_transport(argv,directory/('collection-'+collection_correlation_id+'-transport.json'),{'diagnosticCorrelationId':diagnostic_correlation_id,'collectionCorrelationId':collection_correlation_id})
    if private_snapshot(directory/'intent.json',65536)[1:]!=(local_gen,local_hash) or private_snapshot(request,65536)[1:]!=(request_gen,request_hash):raise ValueError('collector_local_generation_changed')
    try:value=json.loads(out) if code==0 and len(out)<=4096 else None
    except (ValueError,UnicodeError):value=None
    result_path=directory/('collection-'+collection_correlation_id+'-result.json')
    _save(result_path,value if isinstance(value,dict) else {'state':'unknown','reason':'collector_transport_unknown'})
    if not isinstance(value,dict) or value.get('diagnosticCorrelationId')!=diagnostic_correlation_id:return {'ok':False,'state':'unknown','reason':'collector_transport_unknown','resultPath':str(result_path)}
    return {'ok':value.get('state')!='unknown',**{key:item for key,item in value.items() if key!='chunk'},'resultPath':str(result_path)}


_INSTALLER_METADATA_READ = r"""set -eu; test "$(id -u)" = 0; p=/data/user/0/com.kardinal.vpncontrol; test -d "$p"; count=0; for rel in no_backup/control-install-sessions files/control-installs; do d="$p/$rel"; printf 'D\0%s\0' "$rel"; if test -L "$d"; then kind=symlink; elif ! test -e "$d"; then kind=absent; elif test -d "$d"; then kind=directory; else kind=other; fi; printf '%s\0' "$kind"; if test "$kind" = absent; then printf '\0'; else printf '%s\0' "$(/system/bin/stat -c '%d|%i|%s|%y|%z|%a|%u|%g|%h|%F' "$d")"; fi; if test "$kind" = directory; then for f in "$d"/* "$d"/.[!.]* "$d"/..?*; do if ! test -e "$f" && ! test -L "$f"; then continue; fi; count=$((count+1)); test "$count" -le 32; printf 'E\0%s\0' "${f##*/}"; printf '%s\0' "$(/system/bin/stat -c '%d|%i|%s|%y|%z|%a|%u|%g|%h|%F' "$f")"; done; fi; printf 'Z\0'; done; printf 'DONE\0'"""


def parse_installer_metadata_census(text: str) -> dict[str, Any]:
    if not isinstance(text,str) or len(text.encode())>65536:raise ValueError('metadata_census_bounds')
    fields=text.split('\x00');index=0;result={}
    for name in ('no_backup/control-install-sessions','files/control-installs'):
        if fields[index:index+2]!=['D',name]:raise ValueError('metadata_directory_order_invalid')
        kind,generation=fields[index+2:index+4];index+=4
        if kind not in ('absent','directory','symlink','other') or (kind=='absent')!=(generation==''):raise ValueError('metadata_directory_type_invalid')
        entries=[]
        while fields[index]=='E':
            entry,entry_generation=fields[index+1:index+3];index+=3
            if not entry or '/' in entry or not entry_generation:raise ValueError('metadata_entry_invalid')
            entries.append({'name':entry,'generation':entry_generation})
            if len(entries)>32:raise ValueError('metadata_entry_bounds')
        if fields[index]!='Z' or kind!='directory' and entries:raise ValueError('metadata_directory_end_invalid')
        index+=1;result[name]={'kind':kind,'generation':generation,'entries':entries}
    if fields[index:]!=['DONE','']:raise ValueError('metadata_census_trailing_data')
    return result


def remote_installer_metadata_diagnostic_source() -> str:
    """Census only; no updates getter, installer mutation, or admission relaxation."""
    import ast,inspect
    original=remote_proxy_service_diagnostic_source();tree=ast.parse(original)
    constants={node.targets[0].id:ast.literal_eval(node.value) for node in tree.body[:3]}
    checks=constants['CHECKS'].split("phase='current-public-snapshot'",1)[0]
    checks+='\n'+inspect.getsource(parse_installer_metadata_census)
    checks+=r"""
phase='prior-metadata-failure-binding'
old_path=root/'android-failed-check-retirement-diagnostic-10ebc536-9b47-4d0e-a6a6-0e289868aa2d'/'receipt.json'
old_raw,old_pin=snapshot_file(old_path,1048576)
if old_pin['sha256']!='519d6d96c5683e10e08134ad6084ed650a34a4cf3dda5bd075b4d654abe0020a':raise ValueError('prior_service_failure_changed')
old=json.loads(old_raw)
if old.get('diagnosticCorrelationId')!='10ebc536-9b47-4d0e-a6a6-0e289868aa2d' or old.get('diagnosticSourceSha256')!='ec90948de549cfdbd73f6a11e239aafab4600b9e821cd2ef6084b75500bf1987' or old.get('currentFailurePhase')!='current-public-snapshot' or old.get('originalOutcome')!='unknown':raise ValueError('prior_service_failure_binding_changed')
phase='metadata-owner-admission'
for _ in range(2):
 state=public_cli('status');history=public_cli('operations','list')
 for envelope in (state,history):
  if envelope.get('ok') is not True or envelope.get('final') is not True or envelope.get('code')!='OK' or envelope.get('controllerId')!=owner or envelope.get('configurationRevision')!=revision:raise ValueError('metadata_owner_changed')
 if state.get('data',{}).get('runtimeRunning') is not False or state.get('data',{}).get('runtimeObservation')!='stopped':raise ValueError('metadata_runtime_not_stopped')
 operations=history.get('data',{}).get('operations')
 if not isinstance(operations,list) or any(item.get('final') is not True for item in operations):raise ValueError('metadata_operations_not_final')
phase='installer-metadata-census'
_,shell=native()
raw_metadata=authenticated_privileged_read(shell,METADATA_SCRIPT)
metadata_census=parse_installer_metadata_census(raw_metadata)
metadata_raw={'bytes':len(raw_metadata.encode()),'sha256':hashlib.sha256(raw_metadata.encode()).hexdigest(),'base64':base64.b64encode(raw_metadata.encode()).decode(),'complete':True}
if authenticated_privileged_read(shell,METADATA_SCRIPT)!=raw_metadata:raise ValueError('metadata_census_changed_between_reads')
phase='metadata-final-input-guard'
if snapshot_file(old_path,1048576)[1]!=old_pin or snapshot_file(prior_path,1048576)[1]!=prior_pin:raise ValueError('metadata_prior_receipt_generation_changed')
guard_files(pins,paths,parents);verify_manifest();fixture_stopped(output)
"""
    start=original.index('import base64,fcntl,hashlib,json,os,pathlib,stat,subprocess,sys')
    bootstrap=original[start:]
    bootstrap=bootstrap.replace('service_bytes=None','service_bytes=None;metadata_census=None;metadata_raw=None')
    bootstrap=bootstrap.replace("'serviceCapture':service_capture,","'serviceCapture':service_capture,'installerMetadataCensus':metadata_census,'installerMetadataRaw':metadata_raw,",1)
    bootstrap=bootstrap.replace("'serviceCapture':service_capture,'replayAllowed':False", "'serviceCapture':service_capture,'installerMetadataSummary':{name:{'kind':entry['kind'],'entryCount':len(entry['entries']),'generation':entry['generation']} for name,entry in metadata_census.items()} if metadata_census is not None else None,'replayAllowed':False")
    return 'ORIGINAL_SHA='+repr(constants['ORIGINAL_SHA'])+'\nPREFIX='+repr(constants['PREFIX'])+'\nCHECKS='+repr(checks)+'\nMETADATA_SCRIPT='+repr(_INSTALLER_METADATA_READ)+'\n'+bootstrap


def diagnose_installer_metadata(root: Path | str, diagnostic_correlation_id: str) -> dict[str, Any]:
    return _diagnose_failed_admission(root,'45a379b3-417e-4e00-a8e4-e2e8657c1705',diagnostic_correlation_id,service=True,metadata=True)


_METADATA_IDENTITY_COLLECT = _PROXY_SERVICE_COLLECT.split('try:\n if not re.fullmatch',1)[0] + r"""
root_fd=None;directory_fd=None
try:
 if diag!='d1ad89ea-b504-4421-bc86-408e699f1564' or kind!='status' or offset!=0 or requested is not None or service_source!='f325d70e54c3012a8e24e3efb5fc96e7e31fae273cdf8a1056d3def3c80d381f':raise ValueError('metadata_identity_request_invalid')
 directory=root/('android-failed-check-retirement-diagnostic-'+diag)
 root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 directory_fd=os.open(directory.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root_fd)
 def parent_pin(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid]
 parents=[parent_pin(os.fstat(handle)) for handle in (root_fd,directory_fd)]
 def guard_parents():
  for handle,pin in zip((root_fd,directory_fd),parents):
   info=os.fstat(handle)
   if parent_pin(info)!=pin or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=os.getuid():raise ValueError('metadata_identity_parent_unsafe_or_changed')
  if parent_pin(root.lstat())!=parents[0] or parent_pin(os.stat(directory.name,dir_fd=root_fd,follow_symlinks=False))!=parents[1] or parent_pin(directory.lstat())!=parents[1]:raise ValueError('metadata_identity_named_parent_changed')
 def read(path,limit):
  if path!=directory/'receipt.json':raise ValueError('metadata_identity_read_path_invalid')
  fd=os.open('receipt.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd)
  try:
   first=os.fstat(fd)
   if not stat.S_ISREG(first.st_mode) or generation(first)[5:]!=[0o600,os.getuid(),1] or first.st_size>limit:raise ValueError('metadata_identity_file_unsafe')
   raw=b''
   while len(raw)<=limit:
    chunk=os.read(fd,min(65536,limit+1-len(raw)))
    if not chunk:break
    raw+=chunk
   if len(raw)>limit or generation(first)!=generation(os.fstat(fd)) or generation(first)!=generation(os.stat('receipt.json',dir_fd=directory_fd,follow_symlinks=False)):raise ValueError('metadata_identity_file_changed')
   return raw,{'generation':generation(first),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
  finally:os.close(fd)
 guard_parents()
 raw,pin=read(directory/'receipt.json',4194304)
 if pin['sha256']!='72e6a5c8b34d58e51b95517c070e45cc0cb905911122f35d334f1c8754e35e02':raise ValueError('metadata_identity_receipt_changed')
 value=json.loads(raw)
 if value.get('diagnosticCorrelationId')!=diag or value.get('diagnosticSourceSha256')!=service_source or value.get('admissionCorrelationId')!='45a379b3-417e-4e00-a8e4-e2e8657c1705' or value.get('originalCorrelationId')!='0dd55704-1e80-4d62-8d9d-2f0a123e0c3b' or value.get('originalOutcome')!='unknown' or value.get('exception') is not None or value.get('currentFailurePhase')!='metadata-final-input-guard':raise ValueError('metadata_identity_binding_changed')
 census=value.get('installerMetadataCensus')
 if not isinstance(census,dict) or set(census)!={'no_backup/control-install-sessions','files/control-installs'}:raise ValueError('metadata_identity_census_invalid')
 guard_parents()
 if read(directory/'receipt.json',4194304)[1]!=pin:raise ValueError('metadata_identity_generation_changed')
 guard_parents()
 result={'state':'collected','receiptPin':pin,'diagnosticCorrelationId':diag,'originalOutcome':'unknown','historicalMetadataEquality':'unavailable',
  'census':census,'originalAdapterSha256':value.get('originalAdapterSha256'),'sourceSha256':service_source,'priorDiagnosticReceiptSha256':value.get('priorDiagnosticReceiptSha256')}
 payload=json.dumps(result,separators=(',',':'))
 if len(payload.encode())>8192:raise ValueError('metadata_identity_capsule_bounds')
 print(payload)
except (OSError,ValueError,TypeError,KeyError):print(json.dumps({'state':'unknown','reason':'metadata_identity_proof_or_generation_unknown','originalOutcome':'unknown','diagnosticCorrelationId':diag}))
finally:
 for handle in (directory_fd,root_fd):
  if handle is not None:os.close(handle)
"""


def collect_installer_metadata_identity(root: Path | str, collection_correlation_id: str) -> dict[str, Any]:
    """Collect only the authenticated existing d1ad census; no native remeasurement."""
    from agent_tools import ssh_transport
    root=Path(root).resolve();diag='d1ad89ea-b504-4421-bc86-408e699f1564'
    if not _UUID.fullmatch(collection_correlation_id) or collection_correlation_id==diag:raise ValueError('metadata_identity_collection_uuid_invalid')
    directory=_local_directory(root,'45a379b3-417e-4e00-a8e4-e2e8657c1705')
    raw,gen,digest=private_snapshot(directory/'intent.json',65536);local=json.loads(raw);intent=local['dispatch']
    validate_original(intent,local['binding']['originalIntent'],intent['correlationId'])
    request=directory/('diagnostic-'+diag+'.json');request_raw,request_gen,request_sha=private_snapshot(request,65536);value=json.loads(request_raw)
    metadata_sha='f325d70e54c3012a8e24e3efb5fc96e7e31fae273cdf8a1056d3def3c80d381f'
    if value.get('diagnosticSourceSha256')!=metadata_sha or value.get('admissionIntentPin')!={'generation':gen,'sha256':digest}:raise ValueError('metadata_identity_local_binding_changed')
    _save(directory/('metadata-identity-'+collection_correlation_id+'.json'),{'requestPin':{'generation':request_gen,'sha256':request_sha},'receiptSha256':'72e6a5c8b34d58e51b95517c070e45cc0cb905911122f35d334f1c8754e35e02'})
    argv=ssh_transport.build_ssh_argv(ssh_transport.load_config(root),intent['host'],60,command=('python3','-I','-B','-c','exec('+repr(_METADATA_IDENTITY_COLLECT)+')',intent['fixtureRoot'],diag,'status','0','null',metadata_sha))
    code,out=diagnostic_transport(argv,directory/('metadata-identity-'+collection_correlation_id+'-transport.json'),{'collectionCorrelationId':collection_correlation_id,'diagnosticCorrelationId':diag})
    if private_snapshot(directory/'intent.json',65536)[1:]!=(gen,digest) or private_snapshot(request,65536)[1:]!=(request_gen,request_sha):raise ValueError('metadata_identity_local_generation_changed')
    try:value=json.loads(out) if code==0 and len(out)<=8192 else None
    except (ValueError,UnicodeError):value=None
    destination=directory/('metadata-identity-'+collection_correlation_id+'-capsule.json')
    _save(destination,value if isinstance(value,dict) else {'state':'unknown','reason':'metadata_identity_transport_unknown'})
    return {'ok':isinstance(value,dict) and value.get('state')=='collected','state':value.get('state') if isinstance(value,dict) else 'unknown','capsulePath':str(destination),'originalOutcome':'unknown'}


_OS_METADATA_IDENTITY = {'census': {'files/control-installs': {'entries': [], 'generation': '', 'kind': 'absent'}, 'no_backup/control-install-sessions': {'entries': [{'generation': '65070|353900|547|2026-09-23 15:38:21.230000000 +0300|2026-09-23 15:38:21.230000000 +0300|600|10209|10209|1|regular file', 'name': '2d502ff6-5969-443e-892a-6193c7f6830c.json'}, {'generation': '65070|353824|545|2026-09-23 16:02:17.962000000 +0300|2026-09-23 16:02:17.962000000 +0300|600|10209|10209|1|regular file', 'name': '50f929cc-e47f-498c-8d83-936819c2493d.json'}, {'generation': '65070|353822|546|2026-09-23 15:57:00.354000000 +0300|2026-09-23 15:57:00.358000000 +0300|600|10209|10209|1|regular file', 'name': 'e920ea52-10d8-435a-9e11-786dda586629.json'}], 'generation': '65070|353851|4096|2026-09-23 16:02:17.962000000 +0300|2026-09-23 16:02:17.962000000 +0300|700|10209|10209|2|directory', 'kind': 'directory'}}, 'diagnosticCorrelationId': 'd1ad89ea-b504-4421-bc86-408e699f1564', 'historicalMetadataEquality': 'unavailable', 'originalAdapterSha256': 'eb29932a944d59a786c790ec1531772579e4a382a94660274f29178347b2da12', 'originalOutcome': 'unknown', 'priorDiagnosticReceiptSha256': '96489c3073bb358ba9a51e61331c6dc67eefae5de7c13f0dd2cff727c0b04eba', 'receiptPin': {'bytes': 73538, 'generation': [66307, 103946108, 73538, 1790993166877515210, 1790993166877515210, 384, 1000, 1], 'sha256': '72e6a5c8b34d58e51b95517c070e45cc0cb905911122f35d334f1c8754e35e02'}, 'sourceSha256': 'f325d70e54c3012a8e24e3efb5fc96e7e31fae273cdf8a1056d3def3c80d381f', 'state': 'collected'}
_OS_METADATA_CAPSULE_SHA = 'c65bb0d00806c83e2a80ac9162640aa4ef640c56a2e8afb035135d6045b8e5a7'


def remote_metadata_bound_proxy_service_source() -> str:
    """New OS-only observation; retained metadata is pinned, never reconciled."""
    import ast
    original=remote_installer_metadata_diagnostic_source()
    constants={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(original).body[:3]}
    checks=constants['CHECKS']
    marker="phase='metadata-owner-admission'"
    identity_checks=r"""
phase='metadata-os-identity-binding'
identity=OS_METADATA_IDENTITY
if diagnostic.get('metadataIdentity')!=identity or diagnostic.get('metadataIdentityCapsulePin',{}).get('sha256')!=OS_METADATA_CAPSULE_SHA:raise ValueError('metadata_os_identity_binding_changed')
identity_path=root/'android-failed-check-retirement-diagnostic-d1ad89ea-b504-4421-bc86-408e699f1564'/'receipt.json'
identity_raw,identity_pin=snapshot_file(identity_path,1048576)
if {**identity_pin,'bytes':len(identity_raw)}!=identity['receiptPin']:raise ValueError('metadata_os_receipt_generation_changed')
identity_receipt=json.loads(identity_raw)
if identity_receipt.get('installerMetadataCensus')!=identity['census'] or identity_receipt.get('diagnosticSourceSha256')!=identity['sourceSha256'] or identity_receipt.get('diagnosticCorrelationId')!=identity['diagnosticCorrelationId'] or identity_receipt.get('exception') is not None or identity_receipt.get('currentFailurePhase')!='metadata-final-input-guard' or identity_receipt.get('originalOutcome')!='unknown':raise ValueError('metadata_os_receipt_binding_changed')
"""
    checks=checks.replace(marker,identity_checks+'\n'+marker,1)
    checks+=r"""
phase='metadata-os-census-admission'
if metadata_census!=identity['census']:raise ValueError('metadata_os_census_changed')
phase='metadata-os-service-capture'
service_result=subprocess.run([expected['adb'],'-s',expected['serial'],'shell','-T','/system/bin/dumpsys connectivity'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
if len(service_result.stdout)>1048576 or len(service_result.stderr)>65536:raise ValueError('service_capture_bounds')
service_bytes=service_result.stdout
service_capture={'name':'connectivity.txt','bytes':len(service_bytes),'sha256':hashlib.sha256(service_bytes).hexdigest(),'exit':service_result.returncode,'stderr':{'bytes':len(service_result.stderr),'sha256':hashlib.sha256(service_result.stderr).hexdigest()},'interpretation':'unreviewed','historicalRowPresence':'unavailable','historicalMetadataEquality':'unavailable','proxyRestorationPerformed':False}
phase='metadata-os-closing-guard'
if parse_installer_metadata_census(authenticated_privileged_read(shell,METADATA_SCRIPT))!=identity['census']:raise ValueError('metadata_os_census_changed')
for _ in range(2):
 state=public_cli('status');history=public_cli('operations','list')
 for envelope in (state,history):
  if envelope.get('ok') is not True or envelope.get('final') is not True or envelope.get('code')!='OK' or envelope.get('controllerId')!=owner or envelope.get('configurationRevision')!=revision:raise ValueError('metadata_os_owner_changed')
 if state.get('data',{}).get('runtimeRunning') is not False or state.get('data',{}).get('runtimeObservation')!='stopped':raise ValueError('metadata_os_runtime_not_stopped')
 operations=history.get('data',{}).get('operations')
 if not isinstance(operations,list) or any(item.get('final') is not True for item in operations):raise ValueError('metadata_os_operations_not_final')
if snapshot_file(identity_path,1048576)[1]!=identity_pin or snapshot_file(old_path,1048576)[1]!=old_pin or snapshot_file(prior_path,1048576)[1]!=prior_pin:raise ValueError('metadata_os_prior_generation_changed')
if {name:proxy_shell('settings','get','global',name) for name in proxy_fields}!=residue:raise ValueError('metadata_os_proxy_changed')
guard_files(pins,paths,parents);verify_manifest();fixture_stopped(output)
"""
    start=original.index('import base64,fcntl,hashlib,json,os,pathlib,stat,subprocess,sys')
    return ('ORIGINAL_SHA='+repr(constants['ORIGINAL_SHA'])+'\nPREFIX='+repr(constants['PREFIX'])+'\nCHECKS='+repr(checks)
            +'\nMETADATA_SCRIPT='+repr(_INSTALLER_METADATA_READ)+'\nOS_METADATA_IDENTITY='+repr(_OS_METADATA_IDENTITY)
            +'\nOS_METADATA_CAPSULE_SHA='+repr(_OS_METADATA_CAPSULE_SHA)+'\n'+original[start:])


def diagnose_metadata_bound_proxy_service(root: Path | str, diagnostic_correlation_id: str) -> dict[str, Any]:
    return _diagnose_failed_admission(root,'45a379b3-417e-4e00-a8e4-e2e8657c1705',diagnostic_correlation_id,service=True,metadata=True,metadata_os=True)


def remote_metadata_bound_proxy_collector_source() -> str:
    """Separate classifier for the new observation; old collector stays frozen."""
    source=_PROXY_SERVICE_COLLECT.replace("'service-capture')", "'service-capture','prior-metadata-failure-binding','metadata-os-identity-binding','metadata-owner-admission','installer-metadata-census','metadata-final-input-guard','metadata-os-census-admission','metadata-os-service-capture','metadata-os-closing-guard')",1)
    source=source.replace("fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)", "fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd)",1)
    source=source.replace("path.lstat())", "os.stat(path.name,dir_fd=directory_fd,follow_symlinks=False))",1)
    source=source.replace(" parents=[]", " root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)\n directory_fd=os.open(directory.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root_fd)\n parents=[]",1)
    source=source.replace("parents.append([x.st_dev,x.st_ino])", "parents.append([x.st_dev,x.st_ino,x.st_mode,x.st_uid])",1)
    old_guard=""" for path,pin in zip((root,directory),parents):
  x=path.lstat()
  if [x.st_dev,x.st_ino]!=pin:raise ValueError('collector_parent_changed')
 if read(directory/'receipt.json',4194304)[1]!=receipt_pin:raise ValueError('collector_receipt_changed')"""
    new_guard=""" if read(directory/'receipt.json',4194304)[1]!=receipt_pin:raise ValueError('collector_receipt_changed')
 for fd,path,pin in zip((root_fd,directory_fd),(root,directory),parents):
  x=os.fstat(fd);named=path.lstat()
  if [x.st_dev,x.st_ino,x.st_mode,x.st_uid]!=pin or [named.st_dev,named.st_ino,named.st_mode,named.st_uid]!=pin or not stat.S_ISDIR(x.st_mode) or stat.S_IMODE(x.st_mode)!=0o700 or x.st_uid!=os.getuid():raise ValueError('collector_parent_changed')
 named=os.stat(directory.name,dir_fd=root_fd,follow_symlinks=False)
 if [named.st_dev,named.st_ino,named.st_mode,named.st_uid]!=parents[1]:raise ValueError('collector_named_parent_changed')"""
    if old_guard not in source:raise ValueError('collector_source_shape_changed')
    return source.replace(old_guard,new_guard,1)
