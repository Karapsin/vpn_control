"""Finite read-only joins for the deliberately failing same-source MSI.

This does not derive/install/sign a package or assert native qualification.
Actual source/artifact/derivation admission remains with the original holder.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import PureWindowsPath
import sys
import time

PRODUCER_SHA='3941f950cf19c010130fb128449569402498a46e3c82fdc97a7f94783e6d7e33'
PENDING_SHA='3eab6a7fbca0f40dd7a618ce19190ad1459fa28e74a5d64761764d3c9e5445ce'
FAULT_FIELDS={'kind','originalPairRequest','derivationBinding','derivedFixtureReceiptPath'}


def require(value, code):
    if not value:raise ValueError(code)


def decode(raw, maximum):
    require(type(raw) is bytes and 0<len(raw)<=maximum,'fault-input-json-byte-bound')
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'fault-input-json-duplicate');result[key]=value
        return result
    value=json.loads(raw.decode('utf-8','strict'),object_pairs_hook=unique)
    require(type(value) is dict,'fault-input-json-object')
    return value


def held_json(owner,path,maximum):
    require(type(path) is str and path.casefold() in owner.by_path,'fault-actual-input-pin')
    pin=owner.by_path[path.casefold()];pin.current()
    raw=pin.digest(True,maximum)
    require(hashlib.sha256(raw).hexdigest()==pin.record['sha256'],'fault-actual-input-bytes')
    return decode(raw,maximum)


def source(owner,path,expected,name):
    require(type(path) is str and path.casefold() in owner.by_path,'fault-fixed-source-pin')
    pin=owner.by_path[path.casefold()]
    require(pin.record['sha256']==expected and pin.digest()==expected,'fault-fixed-source-bytes')
    module=owner.module(path,name)
    require(sys.modules.get(module.__name__) is module and str(module.__file__).casefold()==path.casefold(),
        'fault-fixed-registered-source-module')
    return module


def validate_inputs(value):
    require(type(value) is dict and set(value)==FAULT_FIELDS and value['kind']=='native-install-failed',
        'fault-exact-semantic-input-schema')
    binding=value['derivationBinding']
    require(type(binding) is dict and set(binding)=={'kind','derivationReceiptPath','beforeSnapshotPath','afterSnapshotPath','faultMsiPath'}
        and binding['kind']=='windows-native-install-failed-msi','fault-exact-derivation-binding')
    require(type(value['originalPairRequest']) is dict and type(value['derivedFixtureReceiptPath']) is str,
        'fault-original-pair-and-derived-fixture')
    return value


def input_paths(value):
    validate_inputs(value)
    return [value['derivedFixtureReceiptPath'],
        *[value['originalPairRequest'][k] for k in ('fixtureReceiptPath','sourceSnapshotPath','buildPlanPath','targetMsiPath')],
        *[value['derivationBinding'][k] for k in ('derivationReceiptPath','beforeSnapshotPath','afterSnapshotPath','faultMsiPath')]]


def validate_served(owner,value,asset,producer,source_sha,source_fingerprint):
    validate_inputs(value);request=value['originalPairRequest'];binding=value['derivationBinding']
    producer.validate_request(request)
    require(request['sourceSha']==source_sha and request['sourceFingerprint']==source_fingerprint,
        'fault-current-source-pair-join')
    owner.guard()
    served=held_json(owner,value['derivedFixtureReceiptPath'],1024*1024)
    original=held_json(owner,request['fixtureReceiptPath'],1024*1024)
    derivation=held_json(owner,binding['derivationReceiptPath'],producer.MAX_RECEIPT)
    require(served==producer.derived_fixture_receipt(original,derivation)
        and served.get('manifest',{}).get('assets')==[asset],
        'fault-actual-derived-fixture-and-served-asset')
    result=producer.validate_served_fault(owner,request,binding,asset)
    require(result['sourceSha']==source_sha and result['sourceFingerprint']==source_fingerprint
        and result['faultMsiArtifactId']=='sha256-'+asset['sha256']
        and result['nativeAcceptance'] is None,'fault-actual-semantic-source-asset-join')
    owner.guard()
    return result


def verify_download(value,asset,workspace):
    require(type(value) is dict and set(value)=={'nativeFile','sizeBytes','sha256','expectedSha256','matchesManifest','readOnly'}
        and value['readOnly'] is True and value['matchesManifest'] is True
        and value['sha256']==value['expectedSha256']==asset['sha256']
        and value['sizeBytes']==asset['sizeBytes']
        and PureWindowsPath(value['nativeFile']['path'])==PureWindowsPath(str(workspace))/'updates'/asset['fileName']
        and value['nativeFile']['nativeIdentity']['sizeBytes']==asset['sizeBytes'],
        'fault-actual-downloaded-msi-to-served-derivation')
    return value


def capture_before_authorization(owner,pending,before,install_child,serve,workspace,asset,gui=None):
    # Only read-only operations-list children may be repeated. The original
    # install child is never relaunched; ambiguous/final/ended states refuse.
    for _ in range(256):
        owner.guard()
        require(install_child.process.poll() is None,'fault-original-install-ended-before-capture')
        current=pending.observe_list(owner,workspace,before.controller)
        old={row['id'] for row in before.rows}
        candidates=[row for row in current.rows if row['id'] not in old and row.get('operation')=='updates.install']
        require(len(candidates)<=1,'fault-ambiguous-pending-install')
        if candidates:break
        time.sleep(0.1)
    else:raise ValueError('fault-pending-install-observation-bound')
    binding=pending.select_original_pending(owner,before,current,install_child)
    target={'sha256':asset['sha256'],'sizeBytes':asset['sizeBytes'],'launcher':owner.request['cliPath'],
        'frontendPid':None if gui is None else gui.pid,
        'frontendStartedAtEpochMillis':None if gui is None else int(gui.birth)//10000-11644473600000}
    files=pending.observe_installer_files(owner,binding,workspace,serve,target)
    package=files['packageFile']
    require(package['sha256']==asset['sha256'] and package['sizeBytes']==asset['sizeBytes']
        and files['pendingRequest']['jobId']==files['correlationRecord']['record']['jobId'],
        'fault-actual-captured-msi-to-served-derivation')
    owner.event('failing-msi-original-captured-package-verified',{'taskBinding':binding,'files':files,
        'expectedSha256':asset['sha256'],'expectedSizeBytes':asset['sizeBytes'],'authorizationPerformed':False})
    return {'taskBinding':binding,'files':files}
