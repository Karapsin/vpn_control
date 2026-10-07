"""Bounded ADB transport availability reads; never device/product admission.

Missing configured emulators are unavailable, not malformed public CLI results.
This does not boot an AVD, change leases, reconcile cleanup, or run public CLI.
"""
from __future__ import annotations
import ast
import json
import os
from pathlib import Path
import re
import stat
from . import android_observation, ssh_transport

_REMOTE=r'''
import json,os,pathlib,re,select,stat,subprocess,sys,time

def boot():
 text=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
 if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',text):raise ValueError('boot_identity_unavailable')
 return text

def generation(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_nlink]

def adb_read(fd,serial,timeout):
 process=subprocess.Popen(['/proc/self/fd/'+str(fd),'-s',serial,'get-state'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(fd,))
 streams={process.stdout:bytearray(),process.stderr:bytearray()};active=set(streams);deadline=time.monotonic()+timeout
 try:
  while active:
   left=deadline-time.monotonic()
   if left<=0:raise TimeoutError('adb_read_timeout')
   ready,_,_=select.select(list(active),[],[],left)
   for stream in ready:
    chunk=os.read(stream.fileno(),4097-len(streams[stream]))
    if chunk:
     streams[stream]+=chunk
     if len(streams[stream])>4096:raise ValueError('adb_output_limit')
    else:active.remove(stream)
  process.wait(timeout=max(.01,deadline-time.monotonic()))
  return {'exit':process.returncode,'stdout':bytes(streams[process.stdout]).decode('utf-8','strict'),'stderr':bytes(streams[process.stderr]).decode('utf-8','strict')}
 finally:
  if process.poll() is None:process.kill()
  process.wait();process.stdout.close();process.stderr.close()

def probe(adb,serial,timeout,expected_boot):
 before=boot();fd=os.open(adb,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd);pin=generation(info)
  if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0,os.getuid()} or info.st_mode&0o022 or not info.st_mode&0o111 or info.st_nlink<1:raise ValueError('adb_executable_untrusted')
  if generation(os.lstat(adb))!=pin:raise ValueError('adb_generation_changed')
  first=adb_read(fd,serial,timeout);second=adb_read(fd,serial,timeout)
  if generation(os.fstat(fd))!=pin or generation(os.lstat(adb))!=pin or boot()!=before:raise ValueError('host_or_adb_generation_changed')
  return {'schema':1,'serial':serial,'bootId':before,'expectedBootId':expected_boot,'adbGeneration':pin,'observations':[first,second]}
 finally:os.close(fd)
if __name__=='__main__':
 try:
  adb,serial,timeout,expected_boot=sys.argv[1:];value=probe(adb,serial,int(timeout),expected_boot or None)
  print(json.dumps(value,sort_keys=True,separators=(',',':')))
 except (OSError,ValueError,TimeoutError,subprocess.TimeoutExpired,UnicodeError):
  print(json.dumps({'schema':1,'reason':'availability_read_unknown'}))
'''

def _unknown(reason):
    return {'available':False,'outcome':'unknown','reason':reason,'productAdmitted':False,'lifecycleActionAllowed':False,'bootContinuity':'unknown'}

def classify(returncode,output,serial,expected_boot=None):
    if returncode:return _unknown('transport_failed')
    try:
        value=json.loads(output)
        if not isinstance(value,dict) or set(value)!={'schema','serial','bootId','expectedBootId','adbGeneration','observations'} or type(value['schema']) is not int or value['schema']!=1 or value['serial']!=serial or value['expectedBootId']!=expected_boot or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value['bootId']):raise ValueError
        gen=value['adbGeneration'];reads=value['observations']
        if not isinstance(gen,list) or len(gen)!=8 or any(type(x) is not int or x<0 for x in gen) or not stat.S_ISREG(gen[2]) or gen[2]&0o022 or not gen[2]&0o111 or gen[7]<1 or not isinstance(reads,list) or len(reads)!=2:raise ValueError
        for read in reads:
            if not isinstance(read,dict) or set(read)!={'exit','stdout','stderr'} or type(read['exit']) is not int or not all(isinstance(read[x],str) and len(read[x].encode())<=4096 for x in ('stdout','stderr')):raise ValueError
    except (ValueError,TypeError,KeyError,UnicodeError):return _unknown('malformed_availability')
    if reads[0]!=reads[1]:return _unknown('availability_changed')
    continuity='unknown' if expected_boot is None else 'same' if expected_boot==value['bootId'] else 'changed'
    common={'bootId':value['bootId'],'bootContinuity':continuity,'adbGeneration':gen,'productAdmitted':False,'lifecycleActionAllowed':False}
    read=reads[0]
    if read=={'exit':1,'stdout':'','stderr':"error: device '"+serial+"' not found\n"}:return {'available':False,'outcome':'unavailable','reason':'configured_device_not_found',**common}
    if read=={'exit':0,'stdout':'device\n','stderr':''}:return {'available':True,'outcome':'available','reason':'adb_transport_visible',**common}
    if read=={'exit':0,'stdout':'offline\n','stderr':''}:return {'available':False,'outcome':'unavailable','reason':'configured_device_offline',**common}
    return {**_unknown('adb_read_unclassified'),**common}

def _snapshot(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_size>262144:raise ValueError('availability_source_untrusted')
        chunks=[];size=0
        while True:
            chunk=os.read(fd,8192)
            if not chunk:break
            chunks.append(chunk);size+=len(chunk)
            if size>262144:raise ValueError('availability_source_limit')
        def pin(i):return (i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_mode,i.st_uid,i.st_gid,i.st_nlink)
        if pin(info)!=pin(os.fstat(fd)) or pin(info)!=pin(os.lstat(path)):raise ValueError('availability_source_changed')
        return pin(info),b''.join(chunks)
    finally:os.close(fd)

def observe(root,host,device_profile,timeout_seconds=10,expected_boot=None):
    profile=android_observation._profile(device_profile)
    if type(timeout_seconds) is not int or not 1<=timeout_seconds<=30:raise ValueError('availability_timeout_invalid')
    if expected_boot is not None and (not isinstance(expected_boot,str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',expected_boot)):raise ValueError('availability_boot_invalid')
    path=Path(__file__).absolute();snapshot=_snapshot(path);tree=ast.parse(snapshot[1]);template=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_REMOTE' for t in n.targets)))
    config=ssh_transport.load_config(root)
    if host not in config.hosts or ssh_transport.connection_host(config,host).password is not None:raise ValueError('availability_route_invalid')
    argv=ssh_transport.build_ssh_argv(config,host,timeout_seconds,command=('python3','-c','exec('+repr(template)+')',profile['adb'],profile['serial'],str(timeout_seconds),expected_boot or ''))
    if _snapshot(path)!=snapshot:raise ValueError('availability_source_changed')
    try:code,output=android_observation._run_probe(argv,timeout_seconds*2+5)
    except (OSError,RuntimeError,TimeoutError):return _unknown('availability_transport_unknown')
    if _snapshot(path)!=snapshot:raise ValueError('availability_source_changed')
    return classify(code,output,profile['serial'],expected_boot)
