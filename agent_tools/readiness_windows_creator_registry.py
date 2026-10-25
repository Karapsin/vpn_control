"""Private local custody for an actual initialized managed creator namespace.

No initialization, transport, guest lookup or recovery occurs in these getters.
The captured observer is read-only. Consumed creator bootstrap stays unresolved
until an independently qualified source-owned closure exists.
"""
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import sys
import weakref

from . import durable_remote_job as jobs
from . import readiness_windows_managed_create as creator
from . import readiness_windows_remote as packets
from . import readiness_windows_host_jobs as custody

_EXECUTING_CODE=inspect.currentframe().f_code
_HANDLES=weakref.WeakKeyDictionary()
_BOOTSTRAP_HISTORY=weakref.WeakKeyDictionary()
_FILES=('creator-original.json','creator-owner.source','creator-observer.source')


def _need(value):
    if not value:raise ValueError('windows_creator_custody_unresolved')


def _scope(binding):
    packets.validate_binding(binding);_need(binding['provider']=='libvirt-windows')
    # Initial request XML and later canonical/seed-ejected XML are different
    # public graphs. They never change the original VM/manager/host selector.
    return {'provider':binding['provider'],'spec':binding['spec'],'setup':binding['setup'],
        'uri':binding['uri'],'domain':binding['domain'],'hostBoot':binding['context']['hostBootId']}


def _directory(root,binding,*,create):
    root=Path(root).resolve(strict=True);info=root.lstat()
    _need(stat.S_ISDIR(info.st_mode)and info.st_uid==os.geteuid()and not info.st_mode&0o022)
    token=hashlib.sha256(json.dumps([binding['spec']['host'],binding['spec']['deploymentId']],separators=(',',':')).encode()).hexdigest()
    path=root/'.rag_index'/'windows-managed-creators'/token
    for directory in (root/'.rag_index',path.parent,path):
        if not directory.exists()and not directory.is_symlink():
            if not create:return None
            directory.mkdir(mode=0o700)
        jobs._private(directory,directory=True);_need(directory.resolve()==directory)
    return path


def _record(value):
    _need(type(value)is dict and set(value)=={'schemaVersion','kind','scope','plan','hostBinding','namespace','ownerSourceSha256','observerSourceSha256'}
        and type(value['schemaVersion'])is int and value['schemaVersion']==1 and value['kind']=='windows-managed-creator-local-original-v1')
    plan=creator._plan(value['plan']);_need(value['scope']==_scope(plan['binding']))
    bound=jobs.MachineBinding.from_dict(value['hostBinding']);creator._namespace_reply(plan,bound,value['namespace'])
    _need(value['ownerSourceSha256']==value['namespace']['marker']['ownerSourceSha256']
        and creator.lifecycle._digest(value['observerSourceSha256']))
    return json.loads(json.dumps(value,allow_nan=False))


class CreatorHandle:
    __slots__=('__weakref__',)
    def __new__(cls,*args,**kwargs):raise TypeError('windows_creator_handle_opaque')
    def __reduce__(self):raise TypeError('windows_creator_handle_opaque')
    def guard(self):return _load(self)[0]
    def definitions(self):return _load(self)[1].decode('utf-8','strict')


def _load(handle):
    _need(type(handle)is CreatorHandle and handle in _HANDLES)
    directory,expected,manifest,manifest_pin=_HANDLES[handle]
    _need(custody._file_pin(directory/'creator-custody.json')==manifest_pin)
    _need(custody._custody(directory,'creator-custody.json',_FILES)==manifest)
    record=_record(jobs._record(directory/'creator-original.json'));_need(record==expected)
    owner=jobs._read(directory/'creator-owner.source',jobs.MAX_PROGRAM_BYTES)
    observer=jobs._read(directory/'creator-observer.source',jobs.MAX_PROGRAM_BYTES)
    _need(hashlib.sha256(owner).hexdigest()==record['ownerSourceSha256']and hashlib.sha256(observer).hexdigest()==record['observerSourceSha256'])
    compile(observer,'original read-only creator observer','exec')
    _need(custody._file_pin(directory/'creator-custody.json')==manifest_pin)
    return record,observer


def retain(root,plan,host_binding,namespace):
    """Internal post-initialization enrollment, not caller ownership flags."""
    plan=creator._plan(plan);namespace=creator._namespace_reply(plan,host_binding,namespace)
    directory=_directory(root,plan['binding'],create=True);observer=creator.observer_inventory_definitions(plan,host_binding,namespace).encode()
    record={'schemaVersion':1,'kind':'windows-managed-creator-local-original-v1','scope':_scope(plan['binding']),
        'plan':plan,'hostBinding':jobs.asdict(host_binding),'namespace':namespace,
        'ownerSourceSha256':hashlib.sha256(jobs.owner_source()).hexdigest(),'observerSourceSha256':hashlib.sha256(observer).hexdigest()}
    record=_record(record)
    if not any(directory.iterdir()):
        jobs._publish(directory/'creator-original.json',record);jobs._create(directory/'creator-owner.source',jobs.owner_source())
        jobs._create(directory/'creator-observer.source',observer);custody._create_custody(directory,'creator-custody.json',_FILES)
    manifest=custody._custody(directory,'creator-custody.json',_FILES);pin=custody._file_pin(directory/'creator-custody.json')
    handle=object.__new__(CreatorHandle);_HANDLES[handle]=(directory,record,manifest,pin);_load(handle);return handle


def load(root,binding):
    """Pure exact-target discovery: absent returns None, damaged data blocks."""
    expected=_scope(binding);directory=_directory(root,binding,create=False)
    if directory is None:return None
    manifest=custody._custody(directory,'creator-custody.json',_FILES);pin=custody._file_pin(directory/'creator-custody.json')
    record=_record(jobs._record(directory/'creator-original.json'));_need(record['scope']==expected)
    handle=object.__new__(CreatorHandle);_HANDLES[handle]=(directory,record,manifest,pin);_load(handle);return handle


def _bootstrap_join(handle,history):
    """Join live original-observer authority; never adopt a saved history DTO."""
    from . import readiness_windows_bootstrap_durable as bootstrap
    bootstrap._guard_sources()
    path=Path(__file__).absolute()
    with bootstrap._bootstrap_source(path)as(raw,check):
        bootstrap._verify_callables(sys.modules[__name__],raw,compile(raw,str(path),'exec',dont_inherit=True));check()
    _need(type(handle)is CreatorHandle and type(history)is bootstrap.HistoricalBootstrapClosure)
    actual=history.as_dict();record=handle.guard()
    finalizer=bootstrap._HISTORY[history][0]
    retained,_,_,plan=bootstrap._load(finalizer);original=plan['seedOriginal'];expected=original['creatorExpected']
    _need(_scope(original['binding'])==record['scope']
        and original['creatorNamespace']==record['namespace']
        and original['creatorOperationId']==record['plan']['operationId']
        and expected['binding']==record['hostBinding']
        and expected['rootGeneration']==record['namespace']['generation']
        and expected['admissionsGeneration']==record['namespace']['admissionsGeneration']
        and actual['creatorOperationId']==original['creatorOperationId']
        and actual['seedOperationId']==original['operationId']
        and actual['operationId']==retained['operationId']
        and actual['programSha256']==retained['programSha256']
        and actual['machine']==record['plan']['binding']['spec']['deploymentId'])
    return {'schemaVersion':1,'kind':'windows-creator-historical-bootstrap-v1',
        'machine':actual['machine'],'creatorOperationId':actual['creatorOperationId'],
        'seedOperationId':actual['seedOperationId'],'finalizerOperationId':actual['operationId'],
        'expectedSid':actual['account'],'originalGuestBoot':actual['originalGuestBoot'],
        'closureGeneration':actual['closureGeneration'],'historicalBootstrapComplete':True,
        'ordinarySigninAuthorized':False,'creatorIdleAuthorized':False,
        'currentDesktopVerified':False,'currentReadersVerified':False,'currentLineageVerified':False,
        'replayAllowed':False}


class HistoricalCreatorBootstrap:
    __slots__=('__weakref__',)
    def __new__(cls,*args,**kwargs):raise TypeError('windows_creator_original_observer_required')
    def __reduce__(self):raise TypeError('windows_creator_original_observer_required')
    def as_dict(self):
        _need(type(self)is HistoricalCreatorBootstrap and self in _BOOTSTRAP_HISTORY)
        handle,history,expected=_BOOTSTRAP_HISTORY[self]
        current=_bootstrap_join(handle,history);_need(current==expected);return current


def historical_bootstrap(handle,history):
    """Historical admission only. Current VM lineage/session is a separate gate.

    The ordinary creator inventory deliberately remains unresolved. This
    object cannot authorize signin, clear idle work, or submit any owner.
    """
    expected=_bootstrap_join(handle,history)
    result=object.__new__(HistoricalCreatorBootstrap)
    _BOOTSTRAP_HISTORY[result]=(handle,history,expected);result.as_dict();return result
