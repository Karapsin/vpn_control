"""New UID-owned home key observation after measured ~/ IdentityFile rejection.

Consumed sources stay immutable. Derive their complete guarded flow, adding
only exact ~/ expansion from getpwuid(current UID), metadata-only key/parent
pins and a new fixed prior-failure binding. No key body, signal or archive.
"""
from __future__ import annotations
import hashlib
import inspect
import os
from pathlib import Path
import pwd
import stat
from agent_tools import ssh_nested_socket_noninteractive_observation as previous
from agent_tools import ssh_nested_socket_retirement as frozen
from agent_tools import ssh_recovery_adoption as adoption
from agent_tools.private_inventory_lock import Directory,Snapshot
generation=frozen.generation

PREVIOUS_SHA='3ca002e128e0b887db78f39881955de6581d1d01f5dae2d8e34ba0ddbbde08f9'
PREVIOUS_REMOTE_SHA='e2da146a8e247b41e897f6b475f5573e8e5481e6e4049683bf397c21e4278b2d'
FAILED='50d5c0e0-6db9-4cc8-9fef-d023aaf02109'
FAILED_REMOTE_SHA='a367f213f68ecc96d0e42e0b945180601d28b22e5ffcd92be77e9cc957c2eed5'
FAILED_INTENT_PIN={'generation':[16777234,111542918,33152,503,20,1,12957,1791025564181031834,1791025564181031834],'size':12957,'sha256':'3293d4ffda382a667b06c40c9c152cdc38400cd17ca7bb3e20e4dc84f8aca4c2'}
FAILED_OUTPUT_PINS={
 'stdout':{'generation':[16777234,111542919,33152,503,20,1,0,1791025564461362257,1791025564461362257],'bytes':0,'sha256':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
 'stderr':{'generation':[16777234,111542920,33152,503,20,1,1029,1791025564461558718,1791025564461558718],'bytes':1029,'sha256':'e20b2534297aa89493d5b0ad03e1ea1effa551faf4903f5f3081ee264d205dc4'}}


def owned_home_identity(value):
    if not isinstance(value,str) or '%' in value or '..' in value.split('/') or any(ord(c)<32 for c in value):raise ValueError('effective_key_not_literal')
    if value.startswith('~/'):
        home=Path(pwd.getpwuid(os.getuid()).pw_dir)
        if not home.is_absolute():raise ValueError('effective_home_unknown')
        info=os.lstat(home)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o022:raise ValueError('effective_home_foreign')
        return {'path':str(home/value[2:]),'home':str(home),'homePin':generation(info)}
    if value.startswith('~') or not Path(value).is_absolute():raise ValueError('effective_key_unknown')
    return {'path':value,'home':None,'homePin':None}


def _replace_once(source,old,new):
    if source.count(old)!=1:raise ValueError('reviewed_rewrite_count_changed')
    return source.replace(old,new,1)


def _previous_guard():
    if frozen.file_pin(Path(previous.__file__),body=True)['sha256']!=PREVIOUS_SHA:raise ValueError('consumed_noninteractive_source_changed')


def remote_source():
    _previous_guard();source=previous.remote_source()
    if hashlib.sha256(source.encode()).hexdigest()!=PREVIOUS_REMOTE_SHA:raise ValueError('consumed_noninteractive_remote_changed')
    source=_replace_once(source,"if not keys or any(not Path(p).is_absolute() for p in keys):raise ValueError('effective_key_unknown')",
        "if not keys:raise ValueError('effective_key_unknown')\n    identities=[owned_home_identity(p) for p in keys]\n    keys=[item['path'] for item in identities]\n    homes={item['home']:item['homePin'] for item in identities if item['home'] is not None}")
    source=_replace_once(source,"if not existing:raise ValueError('effective_key_unavailable')",
        "if not existing:raise ValueError('effective_key_unavailable')\n    for home,pin in homes.items():\n        if generation(os.lstat(home))!=pin:raise ValueError('effective_home_changed')")
    source=_replace_once(source,"return {'effectiveSha256':hashlib.sha256(result.stdout).hexdigest(),'keyMetadata':existing}",
        "return {'effectiveSha256':hashlib.sha256(result.stdout).hexdigest(),'keyMetadata':existing,'ownedHomePins':homes}")
    return 'import pwd\n'+inspect.getsource(owned_home_identity)+'\n'+source


def _failed_sources(root,stack,measurement_intent):
    directory=stack.enter_context(Directory(root/'.rag_index/ssh-nested-socket-noninteractive-observation'/FAILED))
    source=stack.enter_context(Snapshot(directory,'intent.json'))
    if source.pin()!=FAILED_INTENT_PIN:raise ValueError('consumed_home_failure_intent_changed')
    value=adoption._json(source.body)
    if value.get('correlationId')!=FAILED or value.get('remoteSourceSha256')!=FAILED_REMOTE_SHA or value.get('measuredDiagnosticId')!=previous.MEASURED or value.get('measurementPins')!=previous.MEASURED_PINS or value.get('archiveAllowed')is not False or any(value.get(k)!=measurement_intent.get(k) for k in ('host','inventory','binding')):
        raise ValueError('consumed_home_failure_binding_changed')
    pins={}
    for suffix,expected in FAILED_OUTPUT_PINS.items():
        p=directory.path/suffix;pin=frozen.file_pin(p,body=True,private=True)
        if {k:pin[k] for k in ('generation','bytes','sha256')}!=expected:raise ValueError('consumed_home_failure_capture_changed')
        pins[str(p)]=pin
    for path,expected in value['inputPins'].items():
        pin=frozen.file_pin(path,body=True,private=path.endswith(('.stdout','.stderr')))
        if any(pin[k]!=expected[k] for k in ('generation','bytes','sha256')):raise ValueError('consumed_home_input_changed')
        pins[path]=pin
    return source,pins


def _build_observe():
    _previous_guard();source=inspect.getsource(previous.observe)
    source=_replace_once(source,"ssh-nested-socket-noninteractive-observation'","ssh-nested-socket-owned-home-observation'")
    source=_replace_once(source,'measured_value(intent,result)','measured_value(intent,result)\n        failed_source,failed_pins=_failed_sources(root,stack,intent)')
    source=_replace_once(source,'pins={}','pins=dict(failed_pins)')
    source=_replace_once(source,"config=adoption._validate_candidate(source.body,root);target,binding,histories=frozen._owned_binding(root,config,host,stack)",
        "config=adoption._validate_candidate(source.body,root);target,binding,histories=frozen._owned_binding(root,config,host,stack)\n        histories.append(failed_source)")
    source=_replace_once(source,"'repair':'exact-fixed-ssh-options-add-T-only'","'repair':'exact-T-and-UID-owned-home-key-metadata','failedNoninteractiveObservationId':FAILED")
    namespace=dict(previous.__dict__)
    namespace.update({'__file__':__file__,'remote_source':remote_source,'_failed_sources':_failed_sources,'FAILED':FAILED})
    exec(compile(source,'reviewed-owned-home-local-observer','exec'),namespace)
    return namespace['observe']


def observe(root,host,correlation):
    if correlation==FAILED:raise ValueError('new_observation_uuid_required')
    return _build_observe()(root,host,correlation)


def retire(*args,**kwargs):
    raise ValueError('separate_archive_proof_review_required')
