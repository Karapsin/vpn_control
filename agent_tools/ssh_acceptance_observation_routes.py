"""Three fixed public routes; unknown history never grants lifecycle authority.

This companion only dispatches reviewed helpers and projects their finite typed
outputs. The archive keeps its original source/proof fences and one-use history.
Android availability is transport visibility, never permission to boot or mutate.
"""
from __future__ import annotations
from contextlib import ExitStack
import hashlib
import importlib
import os
from pathlib import Path
import re
import stat
import sys

ACTIONS=frozenset({'connection-nested-orphan-archive','connection-nested-orphan-archive-status','android-availability'})
ARCHIVE_IDENTITY={'observationId':'0fb841fc-2f24-4eca-ae2b-6cc16f772f28','observationSha256':'522ffc5f5f1a9cb6160ffe5b1989c86837b5662ba6fed3fa869b4d9dd1f27069'}
FROZEN={'ssh_nested_socket_orphan_archive':'e28c6682ff2b37a870d3de9f7c51892933f98569cafe38baf0984c38d8c03d50',
        'android_device_availability':'cf1c73ef15a432ff57eff452fd99cf27f2f9927f7305b56f642ee7c544e838ef'}
_ALIAS=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
_UUID=re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')


def _module(name):
    # CLI loads mcp_server directly, outside its package. Always load these
    # relative-import helpers through agent_tools, even in an isolated process.
    if not __package__:
        parent=str(Path(__file__).resolve().parent.parent)
        if parent not in sys.path:sys.path.insert(0,parent)
    return importlib.import_module('agent_tools.'+name)


def _generation(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _source_pin(name):
    path=Path(__file__).absolute().parent/(name+'.py')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);pin=_generation(before)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or not 0<before.st_size<=262144:raise ValueError('source_invalid')
        body=b''
        while len(body)<=262144:
            chunk=os.read(fd,262145-len(body))
            if not chunk:break
            body+=chunk
        if len(body)!=before.st_size or _generation(os.fstat(fd))!=pin or _generation(os.lstat(path))!=pin or hashlib.sha256(body).hexdigest()!=FROZEN[name]:raise ValueError('source_changed')
        return pin,hashlib.sha256(body).hexdigest()
    finally:os.close(fd)


def _unknown(action):
    common={'tool':'ssh_workflow','ok':False,'replayAllowed':False}
    if action=='android-availability':
        return {**common,'available':False,'outcome':'unknown','reason':'availability_route_unknown','bootContinuity':'unknown','productAdmitted':False,'lifecycleActionAllowed':False}
    return {**common,'state':'consumed-unknown','historicalStatus':True,'remoteRevalidated':False,'archivePerformed':False}


def _archive_projection(value):
    if not isinstance(value,dict):raise ValueError('archive_result_invalid')
    short={'ok':False,'state':'consumed-unknown','replayAllowed':False,'historicalStatus':True}
    full={**short,'remoteRevalidated':False,'archivePerformed':False}
    complete={**full,'ok':True,'state':'archived','archivePerformed':True}
    # Equality alone admits bool/int substitution. Every scalar has exact type.
    if not any(set(value)==set(expected) and all(type(value[k])is type(v) and value[k]==v for k,v in expected.items()) for expected in (short,full,complete)):
        raise ValueError('archive_result_invalid')
    return {**full,**value}


def _availability_projection(value,expected_boot):
    core={'available','outcome','reason','bootContinuity','productAdmitted','lifecycleActionAllowed'}
    if not isinstance(value,dict) or set(value) not in (core,core|{'bootId','adbGeneration'}) or value['productAdmitted']is not False or value['lifecycleActionAllowed']is not False or type(value['available'])is not bool:raise ValueError('availability_result_invalid')
    known={('available','adb_transport_visible',True),('unavailable','configured_device_not_found',False),('unavailable','configured_device_offline',False)}
    unknown={'transport_failed','malformed_availability','availability_changed','adb_read_unclassified','availability_transport_unknown'}
    if (value['outcome'],value['reason'],value['available']) not in known and not (value['outcome']=='unknown' and value['reason'] in unknown and value['available']is False):raise ValueError('availability_result_invalid')
    if set(value)==core:
        if value['outcome']!='unknown' or value['bootContinuity']!='unknown' or value['reason']=='adb_read_unclassified':raise ValueError('availability_identity_missing')
    else:
        if value['outcome']=='unknown' and value['reason']!='adb_read_unclassified':raise ValueError('availability_identity_unexpected')
        boot=value['bootId'];gen=value['adbGeneration']
        if not isinstance(boot,str) or not _UUID.fullmatch(boot) or not isinstance(gen,list) or len(gen)!=8 or any(type(x)is not int or x<0 for x in gen) or not stat.S_ISREG(gen[2]) or gen[2]&0o022 or not gen[2]&0o111 or gen[7]<1:raise ValueError('availability_identity_invalid')
        continuity='unknown' if expected_boot is None else 'same' if boot==expected_boot else 'changed'
        if value['bootContinuity']!=continuity:raise ValueError('availability_continuity_invalid')
    return dict(value)


def dispatch(root,action,host=None,timeout_seconds=15,identity=None,transfer=None,device=None):
    """Return a finite public result for a supported action; None if unhandled.

    Root hooks this before the existing SSH branches. Public archive identity
    confirms only the fixed historical proof; it cannot substitute a new source,
    path or correlation. Archive status never reaches the transport helper.
    """
    if not isinstance(action,str) or action not in ACTIONS:return None
    unknown=_unknown(action)
    if not isinstance(host,str) or not _ALIAS.fullmatch(host) or type(timeout_seconds)is not int or not 1<=timeout_seconds<=60 or transfer is not None:return unknown
    try:
        if action!='android-availability':
            if host!='archlinux' or device is not None or type(identity)is not dict or identity!=ARCHIVE_IDENTITY or any(type(x)is not str for x in identity.values()):return unknown
            name='ssh_nested_socket_orphan_archive';pin=_source_pin(name);helper=_module(name)
            if _source_pin(name)!=pin:return unknown
            operation=helper.archive if action=='connection-nested-orphan-archive' else helper.status
            result=operation(Path(root),host)
            if _source_pin(name)!=pin:return unknown
            return {'tool':'ssh_workflow',**_archive_projection(result)}
        if timeout_seconds>30 or device not in ('api29','api35') or (identity is not None and (type(identity)is not dict or set(identity)!={'expectedBootId'} or not isinstance(identity['expectedBootId'],str) or not _UUID.fullmatch(identity['expectedBootId']))):return unknown
        expected_boot=None if identity is None else identity['expectedBootId']
        transport=_module('ssh_transport');private=_module('private_inventory_lock');profile_module=_module('android_observation')
        with ExitStack() as stack:
            directory=stack.enter_context(private.Directory(Path(root).resolve(strict=True)))
            source=stack.enter_context(private.Snapshot(directory,transport.CONFIG_FILENAME))
            config=transport.load_config(Path(root));source.guard()
            target=config.hosts.get(host)
            if target is None or transport.connection_host(config,host).password is not None or device not in target.android_devices:return unknown
            profile=profile_module._profile(target.android_devices[device])
            if profile['api']!=int(device[3:]):return unknown
            name='android_device_availability';pin=_source_pin(name);helper=_module(name)
            source.guard()
            if _source_pin(name)!=pin:return unknown
            result=helper.observe(Path(root),host,profile,timeout_seconds,expected_boot)
            source.guard()
            if _source_pin(name)!=pin:return unknown
            result=_availability_projection(result,expected_boot)
            return {'tool':'ssh_workflow','ok':result['outcome']!='unknown','replayAllowed':False,**result}
    except Exception:
        # Public callers receive finite classifications, never private exception
        # text, tracebacks, SSH stderr, profile paths, or credentials.
        return unknown
