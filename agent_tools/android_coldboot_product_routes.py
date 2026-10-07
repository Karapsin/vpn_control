"""Fixed API29 read-only MCP route with bounded private transport receipts."""
from __future__ import annotations
from contextlib import ExitStack
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time
import uuid
from . import android_coldboot_product_observation as getter
from . import android_device_availability as availability
from . import private_inventory_lock as private
from . import ssh_transport

ACTION='android-coldboot-product-api29-observe'
FROZEN='ec56e238b0bac95d67ae1942b7218bb844db1e48b29cff1ad7b390b1721d8ae7'
RESERVATION='env-11f1a10b21cfea11b504bd9db53dd9a0'
LIMIT=8388608
_REMOTE=r'''
import sys,subprocess,base64,json,hashlib,os,select,time
secret=sys.stdin.buffer.read(513)
if not 0<len(secret)<=512 or b'\0' in secret:raise SystemExit(2)
if not secret.endswith(b'\n'):secret+=b'\n'
process=None;out=b'';err=b'';timed_out=False;output_limit=False;code=None;deadline=time.monotonic()+165
try:
 process=subprocess.Popen(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-I','-B','-c',__CARRIER__],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 process.stdin.write(secret);process.stdin.close();secret=b'';streams={process.stdout:'out',process.stderr:'err'}
 while streams:
  remaining=deadline-time.monotonic()
  if remaining<=0:timed_out=True;break
  ready,_,_=select.select(list(streams),[],[],min(remaining,1))
  for stream in ready:
   part=os.read(stream.fileno(),min(65536,2097153-len(out)-len(err)))
   if not part:del streams[stream];continue
   if streams[stream]=='out':out+=part
   else:err+=part
   if len(out)+len(err)>2097152:output_limit=True;break
  if output_limit:break
 if not timed_out and not output_limit:code=process.wait(timeout=max(.01,deadline-time.monotonic()))
finally:
 secret=b''
 if process is not None:
  if process.poll() is None:process.kill();process.wait()
  for stream in (process.stdin,process.stdout,process.stderr):stream.close()
record={'returncode':code,'stdoutB64':base64.b64encode(out).decode(),'stderrB64':base64.b64encode(err).decode(),'timedOut':timed_out,'outputLimit':output_limit}
raw=(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()
if len(raw)>4194304:raise SystemExit(3)
print(json.dumps({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},separators=(',',':')))
for offset in range(0,len(raw),1536):print(base64.b64encode(raw[offset:offset+1536]).decode())
'''


def _unknown(reason='observation_unknown'):
    return {'tool':'vm_workflow','ok':False,'state':'diagnostic-only','reason':reason,'productAdmitted':False,'acceptanceComplete':False,'replayAllowed':False}

def _projection(value,receipt):
    result=_unknown();result.update(receiptSha256=receipt['sha256'],receiptBytes=receipt['bytes'])
    if not isinstance(value,dict) or value.get('state')!='current-product-getters-admitted' or value.get('productAdmitted') is not True or value.get('acceptanceComplete') is not False or value.get('historicalUnknownsPreserved') is not True:return result
    owner=value.get('controllerId');revision=value.get('configurationRevision');records=value.get('records')
    if not isinstance(owner,str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',owner) or type(revision)is not int or revision<0 or not isinstance(records,dict) or set(records)!={'statusBefore','operations','routing','statusAfter'}:return result
    for item in records.values():
        envelope=item.get('stdout') if isinstance(item,dict) else None
        if not isinstance(item,dict) or type(item.get('returncode'))is not int or item['returncode']!=0 or not isinstance(envelope,dict) or envelope.get('ok') is not True or envelope.get('final') is not True or envelope.get('code')!='OK' or envelope.get('controllerId')!=owner or envelope.get('configurationRevision')!=revision:return result
    before=records['statusBefore']['stdout'].get('data');after=records['statusAfter']['stdout'].get('data');operations=records['operations']['stdout'].get('data',{}).get('operations');routing=records['routing']['stdout'].get('data',{}).get('routing')
    if not isinstance(before,dict) or before!=after or before.get('runtimeRunning') is not False or before.get('runtimeObservation')!='stopped' or not isinstance(operations,list) or any(not isinstance(x,dict) or x.get('final') is not True for x in operations) or not isinstance(routing,dict):return result
    return {**result,'ok':True,'reason':'observed','state':'current-product-getters-admitted','productAdmitted':True,'controllerId':owner,'configurationRevision':revision,'runtimeOff':True,'recordCount':4,'operationCount':len(operations)}

def _decode(output):
    lines=output.splitlines()
    if not lines or len(lines)>4096:raise ValueError('chunk_protocol_unknown')
    header=json.loads(lines[0])
    if set(header)!={'bytes','sha256'} or type(header['bytes'])is not int or not 0<header['bytes']<=4194304 or not isinstance(header['sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',header['sha256']):raise ValueError('chunk_header_unknown')
    if any(not line or len(line)>2048 for line in lines[1:]):raise ValueError('chunk_size_unknown')
    raw=b''.join(base64.b64decode(line,validate=True) for line in lines[1:])
    if len(raw)!=header['bytes'] or hashlib.sha256(raw).hexdigest()!=header['sha256']:raise ValueError('chunk_binding_changed')
    record=json.loads(raw)
    if not isinstance(record,dict) or set(record)!={'returncode','stdoutB64','stderrB64','timedOut','outputLimit'} or type(record['timedOut'])is not bool or type(record['outputLimit'])is not bool or record['returncode'] is not None and type(record['returncode'])is not int:raise ValueError('transport_record_unknown')
    stdout=base64.b64decode(record['stdoutB64'],validate=True);base64.b64decode(record['stderrB64'],validate=True)
    if record['timedOut'] or record['outputLimit'] or record['returncode']!=0:return record,None
    return record,json.loads(stdout)

def _transport(argv,credential,record):
    process=None;streams={};deadline=time.monotonic()+180
    try:
        process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        process.stdin.write(credential);process.stdin.close();streams={process.stdout:'stdout',process.stderr:'stderr'}
        while streams:
            remaining=deadline-time.monotonic()
            if remaining<=0:record['timedOut']=True;raise TimeoutError('transport_timeout')
            ready,_,_=select.select(list(streams),[],[],min(remaining,1))
            for stream in ready:
                part=os.read(stream.fileno(),65536)
                if not part:del streams[stream];continue
                key=streams[stream];record[key]+=part
                if len(record['stdout'])+len(record['stderr'])>LIMIT:raise ValueError('transport_output_limit')
        record['returncode']=process.wait(timeout=max(0.01,deadline-time.monotonic()))
    finally:
        if process is not None:
            if process.poll() is None:process.kill();process.wait()
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream is not None:stream.close()


def _directory(root,identifier):
    # All creation stays relative to held, named, no-follow ancestry.
    path=Path(root).absolute()
    with ExitStack() as held:
        initial=held.enter_context(private.Directory(path));parents=[initial]
        for name in ('.runtime','parity-evidence','android-coldboot-product-mcp',identifier):
            parent=parents[-1]
            parent.guard()
            try:os.mkdir(name,0o700,dir_fd=parent.fd);os.fsync(parent.fd)
            except FileExistsError:
                if name==identifier:raise
            parent.guard();info=os.stat(name,dir_fd=parent.fd,follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o022:raise ValueError('capture_parent_unsafe')
            path=path/name
            parents.append(held.enter_context(private.Directory(path)));parent.guard()
        initial.guard()
        for parent in parents:parent.guard()
        directory=private.Directory(path)
        if stat.S_IMODE(os.fstat(directory.fd).st_mode)!=0o700:directory.close();raise ValueError('capture_directory_unsafe')
        return directory

def _write_receipt(directory,value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(raw)>LIMIT*2:raise ValueError('capture_limit')
    directory.guard();fd=os.open('receipt.json',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
    try:
        before=os.fstat(fd);offset=0
        while offset<len(raw):
            count=os.write(fd,raw[offset:])
            if count<=0:raise ValueError('capture_partial')
            offset+=count
        os.fsync(fd);after=os.fstat(fd);named=os.stat('receipt.json',dir_fd=directory.fd,follow_symlinks=False)
        if private._generation(after)!=private._generation(named) or any(getattr(before,k)!=getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')) or not stat.S_ISREG(after.st_mode) or stat.S_IMODE(after.st_mode)!=0o600 or after.st_nlink!=1 or after.st_uid!=os.getuid() or os.pread(fd,len(raw)+1,0)!=raw:raise ValueError('capture_changed')
        os.fsync(directory.fd);directory.guard();return {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'generation':list(private._generation(after))}
    finally:os.close(fd)

def dispatch(root,action,inputs):
    if action!=ACTION:return None
    if type(inputs)is not dict or inputs:return _unknown('invalid_inputs')
    root=Path(root).absolute();identifier=str(uuid.uuid4());capture=None;prepared=None;value=None;outcome='unknown';transport_record={'stdout':b'','stderr':b'','returncode':None,'timedOut':False};decoded=None;receipt=None;source_pin=None
    try:
        with ExitStack() as stack:
            registry_dir=stack.enter_context(private.Directory(root/'.rag_index/native-environments'));registry=stack.enter_context(private.Snapshot(registry_dir,'reservations.json'));rows=json.loads(registry.body)['reservations'];matches=[row for row in rows if row.get('id')==RESERVATION]
            if len(matches)!=1:raise ValueError('reservation_unavailable')
            row=matches[0]
            if row.get('hostAlias')!='archlinux' or row.get('environment')!='owned-android-api29-coldboot' or row.get('operator')!='root-android' or row.get('requestedMemoryBytes')!=2147483648 or row.get('allocationState') not in {'pending','running'}:raise ValueError('reservation_unadmitted')
            identity={key:row[{'reservationId':'id'}.get(key,key)] for key in ('reservationId','token','hostAlias','environment','operator')}
            helper_path=Path(getter.__file__).absolute();source_pin=availability._snapshot(helper_path)
            if hashlib.sha256(source_pin[1]).hexdigest()!=FROZEN:raise ValueError('getter_source_changed')
            prepared=getter.prepare(root,identity);registry.guard();getter.guard_prepared(prepared)
            route_path=Path(__file__).absolute();route_pin=availability._snapshot(route_path)
            config_dir=stack.enter_context(private.Directory(root));config_pin=stack.enter_context(private.Snapshot(config_dir,ssh_transport.CONFIG_FILENAME));config=ssh_transport.load_config(root);config_pin.guard()
            if 'archlinux' not in config.hosts or ssh_transport.connection_host(config,'archlinux').password is not None:raise ValueError('route_unavailable')
            command=_REMOTE.replace('__CARRIER__',repr(getter.ssh_carrier(prepared)));argv=ssh_transport.build_ssh_argv(config,'archlinux',60,command=('/usr/bin/python3','-I','-B','-c','exec('+repr(command)+')'),ssh_binary='/usr/bin/ssh',nested_ssh_binary='/usr/bin/ssh')
            capture=stack.enter_context(_directory(root,identifier))
            credential_dir=stack.enter_context(private.Directory(root/'.codex'));credential=stack.enter_context(private.Snapshot(credential_dir,'arch-sudo.local'));secret=credential.body
            if not 0<len(secret)<=512 or b'\0' in secret or b'\n' in secret.rstrip(b'\n'):raise ValueError('credential_shape')
            credential.guard();registry.guard();config_pin.guard();getter.guard_prepared(prepared)
            if availability._snapshot(helper_path)!=source_pin or availability._snapshot(route_path)!=route_pin:raise ValueError('route_source_changed')
            try:
                _transport(argv,secret,transport_record);secret=b''
                credential.guard();registry.guard();config_pin.guard();getter.guard_prepared(prepared)
                if availability._snapshot(helper_path)!=source_pin or availability._snapshot(route_path)!=route_pin:raise ValueError('route_source_changed')
                if transport_record['returncode']!=0:raise ValueError('ssh_unknown')
                decoded,value=_decode(transport_record['stdout']);outcome='observed' if value is not None else 'unknown'
            finally:
                # The finally receipt retains partial output on transport,
                # timeout, source drift, and protocol failure without replay.
                receipt=_write_receipt(capture,{'schema':1,'kind':'readonly-api29-product-mcp-observation','observationId':identifier,'getterSourceSha256':FROZEN,'outcome':outcome,'transport':{'returncode':transport_record['returncode'],'timedOut':transport_record['timedOut'],'stdoutB64':base64.b64encode(transport_record['stdout']).decode(),'stderrB64':base64.b64encode(transport_record['stderr']).decode()},'remoteRecord':decoded,'result':value,'historicalUnknownsPreserved':True})
        return _projection(value,receipt)
    except Exception:
        result=_unknown()
        if receipt:result.update(receiptSha256=receipt['sha256'],receiptBytes=receipt['bytes'])
        return result
