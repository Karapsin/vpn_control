"""Publish only the canonical intent for the original live d606 master.

Gateway queries are fixed read-only observations. The shared successor admission
owns local publication; adoption independently rechecks current socket readiness.
No original unknown receipt or remote ready record is changed.
"""
from __future__ import annotations
import base64
import os
from pathlib import Path
import re
import subprocess

from . import ssh_gateway_tmux_master as owner, ssh_gateway_tmux_master_ssh as adapter
from . import ssh_gateway_tmux_d606_diagnostic as diagnostic
from . import ssh_connection_recovery as recovery, ssh_recovery_adoption as adoption
from . import ssh_expired_recovery_retirement as retirement

HISTORICAL_CAPSULE = 'query-diagnostic-422b759442b44d159b3b3ae5a6e79a67'
HISTORICAL_PROOF_SHA256 = 'a7634571ed5b0e4d07eb9dc65608f32a28b5b51da6d579b2622d7f7faaf2522d'
HISTORICAL_PROOF_GENERATION = [16777234,112603265,33152,503,20,1,4147,1791111434997696709,1791111434997696709]
DIAGNOSTIC_SOURCE_SHA256 = '205358c9bac9ffb41d7b0926f1f9ae6f39c100dc63a036ed2e9e45a63edc348b'
PENDING = '.reconciliation.pending.json'
TERMINAL = '.reconciliation.published.json'


def _need(condition, reason):
    if not condition: raise ValueError(reason)


def _unknown():
    return {'state': 'unknown', 'replayAllowed': False, 'launchAllowed': False,
            'adoptionAllowed': False, 'nextAction': 'inspect-original-reconciliation'}


def _proof(authority, job, name, raw, anchor, intent, caller, original):
    _need(type(name) is str and re.fullmatch(r'query-diagnostic-[0-9a-f]{32}', name), 'fixed_capsule')
    capsule = job/name; authority.directory(capsule, True)
    proof = authority.capture(capsule/'proof.private.json', maximum=diagnostic.LIMIT)
    value = owner.value(proof.body); diagnostic._validate_response(value, raw, anchor)
    public = value['public']
    _need(public['state'] == 'observed' and public['reason'] == 'late_ready_original_child'
          and public['originalStatus'] == 'unknown' and public['originalStatusReason'] == 'ready_record_missing'
          and public['originalStatusMethod'] == 'capture_record' and not public['readyRecordPresent']
          and not public['terminalRecordPresent'], 'original_late_master')
    receipt = authority.capture(capsule/'receipt.json')
    out = authority.capture(capsule/'stdout.private', maximum=diagnostic.LIMIT)
    err = authority.capture(capsule/'stderr.private', maximum=diagnostic.LIMIT)
    record = owner.value(receipt.body)
    _need(set(record) == {'version','correlationId','outcome','exitCode','stdout','stderr','callerSource',
          'originalSource','intentPin','anchorPin','argvSha256','replayAllowed'}
          and type(record['version']) is int and record['version'] == 1
          and record['correlationId'] == diagnostic.CORRELATION and record['outcome'] == 'completed'
          and type(record['exitCode']) is int and record['exitCode'] == 0
          and record['stdout'] == out.pin and record['stderr'] == err.pin and not err.body
          and record['callerSource'] == caller.pin and record['originalSource'] == original.pin
          and record['intentPin'] == intent.pin and record['anchorPin'] == authority.files[job/'anchor.json'].pin
          and record['replayAllowed'] is False and re.fullmatch('[0-9a-f]{64}',record['argvSha256'])
          and owner.canonical(owner.value(out.body)) == owner.canonical(value), 'durable_query_binding')
    return proof


def _close(authority, admission_guard=None):
    if admission_guard is not None: admission_guard()
    authority.guard()
    if admission_guard is not None: admission_guard()
    # No body read follows these full FD/named/parent generations before create.
    authority.generations()


def _published(authority, job, expected, pending, sources, historical):
    terminal = authority.capture(job/TERMINAL)
    value = owner.value(terminal.body)
    _need(set(value) == {'version','state','pendingPin','intentPin','freshProofPins'}
          and type(value['version']) is int and value['version'] == 1 and value['state'] == 'published'
          and value['pendingPin'] == pending.pin and type(value['freshProofPins']) is list
          and len(value['freshProofPins']) == 2, 'publication_terminal')
    fenced = owner.value(pending.body)
    _need(set(fenced) == {'version','state','correlationId','canonicalIntent','historicalProof','sources'}
          and type(fenced['version']) is int and fenced['version'] == 1 and fenced['state'] == 'pending'
          and fenced['correlationId'] == diagnostic.CORRELATION and fenced['canonicalIntent'] == expected
          and fenced['historicalProof'] == historical.pin and fenced['sources'] == sources, 'publication_fence')
    target = adoption._validate_candidate(base64.b64decode(owner.value(authority.files[job/'intent.json'].body)['configBytes'],validate=True),authority.root).hosts['archlinux']
    history = []
    retirement.require_admission(authority.root,'archlinux',target,stack=authority.stack,snapshots=history)
    path = recovery._intent_path(authority.root,'archlinux',target)
    intent = authority.capture(path)
    _need(intent.pin == value['intentPin'] and owner.value(intent.body) == expected, 'published_intent')
    for item in value['freshProofPins']:
        _need(type(item) is dict and set(item) == {'capsule','pin'}, 'fresh_proof_binding')
        adapter.valid_pin(item['pin'])
        _need(re.fullmatch(r'query-diagnostic-[0-9a-f]{32}', item['capsule']), 'fresh_capsule')
        proof = authority.capture(job/item['capsule']/'proof.private.json', maximum=diagnostic.LIMIT)
        _need(proof.pin == item['pin'] and proof.body == historical.body, 'fresh_proof_changed')
    for snapshot in history: snapshot.guard()
    _close(authority)
    retirement._close_generations(*history)
    authority.generations()
    return {'state':'published','replayAllowed':False,'launchAllowed':False,'adoptionAllowed':False,
            'canonicalIntentPin':intent.pin,'nextAction':'existing-recovery-adoption'}


def publish(root):
    """Fixed original correlation; create-only local publication, never replay."""
    try:
        with adapter.LocalAuthority(root) as authority:
            job = authority.group()/diagnostic.CORRELATION; directory = authority.directory(job,True)
            intent = authority.capture(job/'intent.json'); record = owner.value(intent.body)
            consumed = os.path.lexists(job/PENDING)
            raw = adapter.original_authority(authority,job,diagnostic.CORRELATION,'status' if consumed else 'release',record)
            original = authority.files[Path(owner.__file__).absolute()]
            _need(original.pin['sha256'] == diagnostic.ORIGINAL_SOURCE_SHA256 == raw['workerSha256'], 'original_source')
            anchor = authority.capture(job/'anchor.json'); prepared = owner.value(anchor.body)
            adapter.reply(prepared,'prepare',diagnostic.CORRELATION,raw)
            _need(prepared['state'] == 'prepared', 'original_anchor')
            caller = authority.capture(Path(diagnostic.__file__).absolute(),private=False)
            _need(caller.pin['sha256'] == DIAGNOSTIC_SOURCE_SHA256, 'diagnostic_source')
            authority.capture(Path(__file__).absolute(),private=False)
            authority.capture(Path(retirement.__file__).absolute(),private=False)
            modules = (owner,adapter,diagnostic,retirement,recovery,adoption,adapter.transport,adapter.connection,adapter.inventory)
            sources = {str(Path(module.__file__).absolute()):authority.files[Path(module.__file__).absolute()].pin for module in modules}
            sources[str(Path(__file__).absolute())] = authority.files[Path(__file__).absolute()].pin
            historical = _proof(authority,job,HISTORICAL_CAPSULE,raw,prepared['anchorPin'],intent,caller,original)
            _need(historical.pin == {'sha256':HISTORICAL_PROOF_SHA256,'generation':HISTORICAL_PROOF_GENERATION}, 'original_diagnostic')
            config = adoption._validate_candidate(base64.b64decode(record['configBytes'],validate=True),authority.root)
            target = config.hosts['archlinux']; path = recovery._intent_path(authority.root,'archlinux',target)
            expected = recovery._intent_value('archlinux',target,diagnostic.CORRELATION.replace('-',''),'ready',raw['masterControlPath'])
            _need(str(recovery._recovery_socket_path(target,diagnostic.CORRELATION.replace('-',''))[1]) == raw['masterControlPath'], 'canonical_path')
            if consumed:
                pending = authority.capture(job/PENDING)
                if not os.path.lexists(job/TERMINAL): return _unknown()
                return _published(authority,job,expected,pending,sources,historical)
            _need(not os.path.lexists(job/TERMINAL), 'foreign_terminal')
            with recovery.successor_admission(authority.root,'archlinux',config) as (canonical,current,admitted,guard):
                _need(canonical == authority.root and current.hosts == config.hosts and admitted == target, 'successor_route')
                destination = authority.directory(path.parent,True)
                # Require actual completed retired history, not an empty folder.
                names = os.listdir(destination.fd); _need(len(names) <= 4096,'history_bound')
                relevant = False
                for name in names:
                    if re.fullmatch(r'\.retire-[0-9a-f]{64}\.(?:pending|terminal)\.json|\.retired-[0-9a-f]{64}\.intent\.json',name):
                        item = authority.capture(path.parent/name)
                        if name.endswith('.pending.json') and owner.value(item.body).get('host') == 'archlinux': relevant = True
                _need(relevant and not os.path.lexists(path), 'completed_retirement_required')
                _close(authority,guard)
                owner.create(directory,PENDING,owner.canonical({'version':1,'state':'pending',
                             'correlationId':diagnostic.CORRELATION,'canonicalIntent':expected,
                             'historicalProof':historical.pin,'sources':sources}))
                pending = authority.capture(job/PENDING)
                fresh = []
                for _ in range(2):
                    _close(authority,guard)
                    result = diagnostic.observe(authority.root)
                    _need(result.get('state') == 'observed', 'fresh_master_unknown')
                    proof = _proof(authority,job,result['capsule'],raw,prepared['anchorPin'],intent,caller,original)
                    _need(proof.pin == result['privateProofPin'] and proof.body == historical.body, 'original_proof_changed')
                    fresh.append({'capsule':result['capsule'],'pin':proof.pin})
                _close(authority,guard)
                _need(not os.path.lexists(path), 'canonical_collision')
                # Cooperative config ownership is retained. External actors
                # ignoring it are not covered by an atomic remote/local CAS.
                published = owner.create(destination,path.name,owner.canonical(expected)+b'\n')
                written = authority.capture(path); _need(written.pin == published,'published_generation')
                _close(authority,guard)
                owner.create(directory,TERMINAL,owner.canonical({'version':1,'state':'published',
                             'pendingPin':pending.pin,'intentPin':written.pin,'freshProofPins':fresh}))
                _close(authority,guard)
            # Context-exit retirement/inventory closure must pass before success.
            return _published(authority,job,expected,pending,sources,historical)
    except (OSError,ValueError,TypeError,KeyError,IndexError,AttributeError,subprocess.SubprocessError):
        return _unknown()
