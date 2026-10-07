"""Read only the original d606 publication and separately completed adoption.

No temporary parser files, receipts, remote queries or mutations are made.
This reports historical local publication/adoption, never current master ready.
"""
from __future__ import annotations
import base64
import fcntl
import os
from pathlib import Path

from . import ssh_gateway_tmux_ready_reconciliation as publisher
from . import ssh_gateway_tmux_master as owner, ssh_gateway_tmux_master_ssh as adapter
from . import ssh_gateway_tmux_d606_diagnostic as diagnostic
from . import ssh_connection_recovery as recovery, ssh_recovery_adoption as adoption
from . import ssh_expired_recovery_retirement as retirement

PUBLISHER_SOURCE_SHA256 = '75aa8d28c40febb8d19a898c0ae334805107202b1babb97988b26c954a4d1c1b'


def _need(condition):
    if not condition: raise ValueError('status_binding')


def _result(state):
    return {'state':state,'replayAllowed':False,'launchAllowed':False,'adoptionAllowed':False}


def _parse(body, root):
    """Same top-level schema and actual shared host/graph validators, in memory."""
    raw = owner.value(body); transport = adapter.transport
    _need({'schemaVersion','hosts'} <= set(raw) and not set(raw)-{'schemaVersion','hosts','nativeBaselines'}
          and ('nativeBaselines' not in raw or isinstance(raw['nativeBaselines'],dict))
          and not isinstance(raw['schemaVersion'],bool) and raw['schemaVersion'] == transport.CONFIG_SCHEMA_VERSION
          and isinstance(raw['hosts'],dict))
    hosts = {alias:transport._host_from_entry(alias,entry) for alias,entry in raw['hosts'].items()}
    transport._validate_proxy_graph(hosts)
    return transport.SshConfig(root=root,hosts=hosts)


def _original(authority, job, record):
    """Read-only counterpart of frozen adapter original_authority(status)."""
    _need(set(record) == {'packet','authority','action','configBytes'} and record['action'] == 'prepare')
    original = base64.b64decode(record['configBytes'],validate=True)
    config = _parse(original,authority.root); target = config.hosts['archlinux']
    config_path = adapter.transport._private_config_path(authority.root)
    baseline = record['authority']
    current = {str(path):item.pin for path,item in authority.files.items() if path != job/'intent.json'}
    _need(type(baseline) is dict and set(baseline) == set(current)
          and adapter.digest(original) == baseline[str(config_path)]['sha256']
          and all(owner.canonical(pin) == owner.canonical(current[path]) for path,pin in baseline.items() if path != str(config_path)))
    raw = record['packet']; expected = adapter.packet(authority,diagnostic.CORRELATION,target)
    expected['localAuthoritySha256'] = adapter.digest(owner.canonical(baseline))
    _need(owner.canonical(raw) == owner.canonical(expected))
    changed = owner.canonical(baseline[str(config_path)]) != owner.canonical(current[str(config_path)])
    if not changed: _need(authority.files[config_path].body == original)
    else:
        candidate = owner.value(original);candidate['hosts']['archlinux']['remoteControlPath'] = raw['masterControlPath']
        _need(authority.files[config_path].body == owner.canonical(candidate)+b'\n')
    # This existing lock is read-only and shared. It is never created here.
    receipts = authority.root/adoption._RECEIPTS
    lock = authority.capture(receipts/adapter.inventory.InventoryLock.name)
    _need(lock.body == adapter.inventory.InventoryLock.body)
    fcntl.flock(lock.fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
    if changed:
        canonical = authority.capture(recovery._intent_path(authority.root,'archlinux',target))
        _need(owner.value(canonical.body) == recovery._intent_value('archlinux',target,diagnostic.CORRELATION.replace('-',''),'ready',raw['masterControlPath']))
        route_sha = adoption._route_sha(original,config,'archlinux')
        key = adoption._route_key('archlinux',raw['configuredControlPath'],raw['masterControlPath'],diagnostic.CORRELATION.replace('-',''),route_sha)
        pending = authority.capture(receipts/(key+'.pending.json'))
        terminal = authority.capture(receipts/(key+'.adopted.json'))
        value = {'schemaVersion':1,'host':'archlinux','oldControlPath':raw['configuredControlPath'],
                 'controlPath':raw['masterControlPath'],'correlationId':diagnostic.CORRELATION.replace('-',''),
                 'routeSha256':route_sha,'source':{**baseline[str(config_path)],'size':len(original)},
                 'intent':adapter.snapshot_pin(canonical),'ownershipLock':adapter.snapshot_pin(lock)}
        _need(owner.canonical(owner.value(pending.body)) == owner.canonical({**value,'state':'pending'})
              and owner.canonical(owner.value(terminal.body)) == owner.canonical({**value,'state':'adopted',
                     'adopted':adapter.snapshot_pin(authority.files[config_path])}))
    return raw,target,changed


def observe(root):
    try:
        with adapter.LocalAuthority(root) as authority:
            job = authority.group()/diagnostic.CORRELATION;authority.directory(job,True)
            initial = authority.capture(job/'intent.json');raw,target,adopted = _original(authority,job,owner.value(initial.body))
            original = authority.files[Path(owner.__file__).absolute()]
            _need(original.pin['sha256'] == diagnostic.ORIGINAL_SOURCE_SHA256 == raw['workerSha256'])
            anchor = authority.capture(job/'anchor.json');prepared = owner.value(anchor.body)
            adapter.reply(prepared,'prepare',diagnostic.CORRELATION,raw);_need(prepared['state'] == 'prepared')
            caller = authority.capture(Path(diagnostic.__file__).absolute(),private=False)
            source = authority.capture(Path(publisher.__file__).absolute(),private=False)
            _need(caller.pin['sha256'] == publisher.DIAGNOSTIC_SOURCE_SHA256 and source.pin['sha256'] == PUBLISHER_SOURCE_SHA256)
            authority.capture(Path(retirement.__file__).absolute(),private=False)
            authority.capture(Path(__file__).absolute(),private=False)
            modules = (owner,adapter,diagnostic,retirement,recovery,adoption,adapter.transport,adapter.connection,adapter.inventory,publisher)
            sources = {str(Path(module.__file__).absolute()):authority.files[Path(module.__file__).absolute()].pin for module in modules}
            historical = publisher._proof(authority,job,publisher.HISTORICAL_CAPSULE,raw,prepared['anchorPin'],initial,caller,original)
            _need(historical.pin == {'generation':publisher.HISTORICAL_PROOF_GENERATION,'sha256':publisher.HISTORICAL_PROOF_SHA256})
            expected = recovery._intent_value('archlinux',target,diagnostic.CORRELATION.replace('-',''),'ready',raw['masterControlPath'])
            _need(str(recovery._recovery_socket_path(target,diagnostic.CORRELATION.replace('-',''))[1]) == raw['masterControlPath'])
            pending = authority.capture(job/publisher.PENDING);terminal = authority.capture(job/publisher.TERMINAL)
            fenced = owner.value(pending.body);value = owner.value(terminal.body)
            _need(owner.canonical(fenced) == owner.canonical({'version':1,'state':'pending','correlationId':diagnostic.CORRELATION,
                  'canonicalIntent':expected,'historicalProof':historical.pin,'sources':sources}))
            _need(set(value) == {'version','state','pendingPin','intentPin','freshProofPins'}
                  and type(value['version']) is int and value['version'] == 1 and value['state'] == 'published'
                  and value['pendingPin'] == pending.pin and type(value['freshProofPins']) is list and len(value['freshProofPins']) == 2)
            canonical = authority.capture(recovery._intent_path(authority.root,'archlinux',target))
            _need(canonical.pin == value['intentPin'] and owner.value(canonical.body) == expected)
            seen = {publisher.HISTORICAL_CAPSULE}
            for item in value['freshProofPins']:
                _need(type(item) is dict and set(item) == {'capsule','pin'} and type(item['capsule']) is str and item['capsule'] not in seen)
                adapter.valid_pin(item['pin']);seen.add(item['capsule'])
                proof = publisher._proof(authority,job,item['capsule'],raw,prepared['anchorPin'],initial,caller,original)
                _need(proof.pin == item['pin'] and proof.body == historical.body)
            history = []
            retirement.require_admission(authority.root,'archlinux',target,stack=authority.stack,snapshots=history)
            for snapshot in history:snapshot.guard()
            authority.guard()
            retirement._close_generations(*history)
            authority.generations()
            return _result('adopted' if adopted else 'published')
    except (OSError,ValueError,TypeError,KeyError,IndexError,AttributeError):return _result('unknown')
