"""Explicit private channel selection; getters never connect or renew.

Selection changes transport admission, never application job identity. An
uncertain selected channel is refused instead of falling back to the canonical
socket. Private inventory bytes/options are never public return fields.
"""
from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from . import private_inventory_lock as private
from . import ssh_fresh_nested_channel as channel
from . import ssh_connection_session as session
from . import ssh_direct_nested_channel as direct_channel
from . import ssh_transport as transport

class SelectionUnknown(ValueError):
    pass

class _Lock(private.InventoryLock):
    name='selection.lock'
    body=b'ssh-channel-selection-v1\n'

_GROUP='.rag_index/ssh-channel-selection'
_KEYS={'correlationId','receiptSha256','outerReceiptSha256','outerOptions','innerOptions'}

def _sources():
    result={}
    for name,source in (('selector',__file__),('channel',channel.__file__),('transport',transport.__file__),('direct',direct_channel.__file__)):
        body,generation=session._bytes(Path(source),private=False)
        result[name]={'generation':list(generation),'sha256':hashlib.sha256(body).hexdigest()}
    return result

def _json(body):return json.loads(body,object_pairs_hook=transport._reject_duplicate_keys)

def _metadata(value,corr,receipt):
    if isinstance(value,dict) and value.get('transportMode')=='direct':
        keys={'transportMode','correlationId','receiptSha256','outerAuthoritySha256','outerOptions','innerOptions'}
        if set(value)!=keys or value['correlationId']!=corr or value['receiptSha256']!=receipt:raise SelectionUnknown()
        if type(value['outerAuthoritySha256'])is not str or re.fullmatch('[0-9a-f]{64}',value['outerAuthoritySha256'])is None:raise SelectionUnknown()
        if tuple(value['outerOptions'])!=direct_channel.OUTER_OPTIONS:raise SelectionUnknown()
        expected=('-S','/tmp/vpn-channel-'+corr+'/m','-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false')
        if tuple(value['innerOptions'])!=expected:raise SelectionUnknown()
        return {key:list(item) if isinstance(item,tuple) else item for key,item in value.items()}
    if not isinstance(value,dict) or set(value)!=_KEYS or value['correlationId']!=corr or value['receiptSha256']!=receipt:raise SelectionUnknown()
    if not isinstance(value['outerReceiptSha256'],str) or re.fullmatch('[0-9a-f]{64}',value['outerReceiptSha256']) is None:raise SelectionUnknown()
    for name in ('outerOptions','innerOptions'):
        options=value[name]
        if not isinstance(options,(tuple,list)) or len(options)!=8 or options[0]!='-S' or not isinstance(options[1],str) or not Path(options[1]).is_absolute() or '..' in Path(options[1]).parts or options[2:] not in (['-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false'],('-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false')):raise SelectionUnknown()
    if value['innerOptions'][1]!='/tmp/vpn-channel-'+corr+'/m':raise SelectionUnknown()
    return {key:list(item) if isinstance(item,tuple) else item for key,item in value.items()}

def _group(root,create):
    path=root/_GROUP
    if create:
        session._directory(root/'.rag_index')
        try:path.mkdir(mode=0o700)
        except FileExistsError:pass
    session._directory(path)
    return path

def _replace(directory,value,old):
    # Only this fixed private pointer is mutable. History stays create-only.
    temporary='pending-'+uuid.uuid4().hex+'.json'
    session._create(directory.path/temporary,value,parent_fd=directory.fd)
    with private.Snapshot(directory,temporary) as saved:
        directory.guard()
        if old:old.guard()
        elif os.path.lexists(directory.path/'current.json'):raise SelectionUnknown()
        os.rename(temporary,'current.json',src_dir_fd=directory.fd,dst_dir_fd=directory.fd)
        os.fsync(directory.fd)
    with private.Snapshot(directory,'current.json') as current:
        if _json(current.body)!=value:raise SelectionUnknown()
        current.guard()

def select_channel(root,host,correlation_id,receipt_sha256,*,direct=False):
    """Publish selection only after genuine current read-only admission."""
    try:
        channel._corr(correlation_id)
        if host!=channel.HOST or not isinstance(receipt_sha256,str) or re.fullmatch('[0-9a-f]{64}',receipt_sha256) is None:raise SelectionUnknown()
        provider=direct_channel if direct else channel
        presented=private.PresentedPath(Path(root).absolute());root=presented.canonical
        with private.Directory(root) as base, private.Snapshot(base,transport.CONFIG_FILENAME) as inventory, ExitStack() as stack:
            source=_sources();metadata=_metadata(provider.route_options(root,host,correlation_id,receipt_sha256),correlation_id,receipt_sha256)
            group=stack.enter_context(private.Directory(_group(root,True)))
            lock=stack.enter_context(_Lock(group))
            current=stack.enter_context(private.Snapshot(group,'current.json')) if os.path.lexists(group.path/'current.json') else None
            value={'version':2 if direct else 1,'host':host,'metadata':metadata,'inventory':inventory.pin(),'sources':source}
            name='selection-'+uuid.uuid4().hex+'.json'
            session._create(group.path/name,value,parent_fd=group.fd)
            history=stack.enter_context(private.Snapshot(group,name))
            published=None
            def guard():
                presented.guard();inventory.guard();lock.guard();history.guard()
                if published is not None:published.guard()
                if _sources()!=source or _json(history.body)!=value:raise SelectionUnknown()
            guard()
            if _metadata(provider.route_options(root,host,correlation_id,receipt_sha256),correlation_id,receipt_sha256)!=metadata:raise SelectionUnknown()
            guard()
            pointer={'version':1,'history':name,'pin':history.pin()}
            _replace(group,pointer,current)
            published=stack.enter_context(private.Snapshot(group,'current.json'))
            if _json(published.body)!=pointer:raise SelectionUnknown()
            guard()
            if _metadata(provider.route_options(root,host,correlation_id,receipt_sha256),correlation_id,receipt_sha256)!=metadata:raise SelectionUnknown()
            guard()
            return {'state':'selected','host':host,'correlationId':correlation_id,'receiptSha256':receipt_sha256}
    except channel.ChannelUnknown as failure:
        try:return channel.validated_unknown(failure.result)
        except (ValueError,TypeError,KeyError,AttributeError):return {'state':'unknown','nativeActionAllowed':False,'replayAllowed':False}
    except (OSError,ValueError,KeyError,TypeError):return {'state':'unknown','nativeActionAllowed':False,'replayAllowed':False}

def selected_route_options(root,host,config=None):
    """Read-only selected admission, or None when nothing was selected.

    Existing but malformed/expired selection always raises SelectionUnknown.
    """
    if host!=channel.HOST:return None
    presented=private.PresentedPath(Path(root).absolute());root=presented.canonical
    path=root/_GROUP/'current.json'
    if not os.path.lexists(root/_GROUP):return None
    if not os.path.lexists(path):raise SelectionUnknown()
    try:
        with private.Directory(root) as base, private.Snapshot(base,transport.CONFIG_FILENAME) as inventory, private.Directory(_group(root,False)) as group, private.Snapshot(group,_Lock.name) as lock, private.Snapshot(group,'current.json') as current:
            if lock.body!=_Lock.body:raise SelectionUnknown()
            private.fcntl.flock(lock.fd,private.fcntl.LOCK_SH|private.fcntl.LOCK_NB)
            pointer=_json(current.body)
            if not isinstance(pointer,dict) or set(pointer)!={'version','history','pin'} or type(pointer['version']) is not int or pointer['version']!=1 or not isinstance(pointer['history'],str) or re.fullmatch('selection-[0-9a-f]{32}\\.json',pointer['history']) is None:raise SelectionUnknown()
            with private.Snapshot(group,pointer['history']) as history:
                if history.pin()!=pointer['pin']:raise SelectionUnknown()
                value=_json(history.body)
                if not isinstance(value,dict) or set(value)!={'version','host','metadata','inventory','sources'} or type(value['version']) is not int or value['version'] not in (1,2) or value['host']!=host or value['inventory']!=inventory.pin() or value['sources']!=_sources():raise SelectionUnknown()
                if config is not None and asdict(config)!=asdict(transport.load_config(root)):raise SelectionUnknown()
                corr=value['metadata']['correlationId'];receipt=value['metadata']['receiptSha256'];channel._corr(corr)
                if not isinstance(receipt,str) or re.fullmatch('[0-9a-f]{64}',receipt) is None:raise SelectionUnknown()
                direct=value['version']==2
                if direct!=(value['metadata'].get('transportMode')=='direct'):raise SelectionUnknown()
                provider=direct_channel if direct else channel
                metadata=_metadata(provider.route_options(root,host,corr,receipt),corr,receipt)
                if metadata!=value['metadata']:raise SelectionUnknown()
                presented.guard();inventory.guard();lock.guard();current.guard();history.guard()
                if value['sources']!=_sources():raise SelectionUnknown()
                return metadata
    except (OSError,ValueError,KeyError,TypeError):raise SelectionUnknown() from None
