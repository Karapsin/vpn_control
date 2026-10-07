"""Fixed read-only recovery preflight for two historical task-owned AVDs.

This first stage captures current provenance. It grants no boot, cleanup,
installer, ownership adoption or replay authority. Historical claims stay intact.
"""
from __future__ import annotations
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
from . import android_device_availability as availability
from . import android_endpoint_admission as endpoint
from . import android_owned_endpoint_bind_recovery as private_io

HISTORY={
 '.runtime/parity-evidence/checkpoint113/android-guest113/ownership.json':'f9b6c35360fc06ca7a591cf2daf853d88dc295882b72896b9b60e78866d7f480',
 '.runtime/parity-evidence/checkpoint117/android-sdk-native-correct-home.stdout':'e97f44d07de3528e09440cb5702c2258b6d849e6dc3d262c60fc9c9615f23e04',
 '.runtime/parity-evidence/checkpoint115/android/uid-provider-bootstrap.stdout':'64a2b2bfa575d1333887f2c5e2be48fc4ca00508a15a3053d3cfdac9f7b400b1',
}
OWNED={
 'api29':{'api':29,'avd':'vpn-control-parity116-api29','serial':'emulator-5684','port':5684,'sdk':'/home/kardinal/.vpn-control-parity116-api29/sdk','avdHome':'/home/kardinal/.vpn-control-parity116-api29','emulator':'/home/kardinal/Android/Sdk/emulator/emulator','systemImage':'system-images;android-29;google_apis;x86_64'},
 'api35':{'api':35,'avd':'vpn-control-parity113-api35','serial':'emulator-5682','port':5682,'sdk':'/home/kardinal/Android/Sdk','avdHome':'/home/kardinal/.vpn-control-parity113/avd','emulator':'/home/kardinal/Android/Sdk/emulator/emulator','systemImage':'system-images;android-35;google_apis;x86_64'},
}
_REMOTE=r'''
import base64,hashlib,json,os,pathlib,re,shutil,stat,sys
CFG=__CFG__;SDK_TEXT=__SDK__;OWNED=__OWNED__
root=pathlib.Path(CFG['remoteRoot']);capsule=root/('android-avd-preflight-'+CFG['correlationId']+'.json')

def fp(i):return [i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_mode,i.st_uid,i.st_gid,i.st_nlink]
def fixed_read(path,limit=1048576,full=True):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  i=os.fstat(fd)
  if not stat.S_ISREG(i.st_mode) or i.st_nlink<1:raise ValueError('preflight_file_type')
  count=min(i.st_size,limit);raw=b''
  while len(raw)<count:
   chunk=os.read(fd,min(65536,count-len(raw)))
   if not chunk:break
   raw+=chunk
  if len(raw)!=count or fp(i)!=fp(os.fstat(fd)) or fp(i)!=fp(os.lstat(path)):raise ValueError('preflight_file_changed')
  return {'generation':fp(i),'bytesRead':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'hashScope':'full' if len(raw)==i.st_size else 'prefix','raw':raw if full else None}
 finally:os.close(fd)
def facts(path,limit=1048576,include_text=False):
 try:
  i=path.lstat()
  if stat.S_ISLNK(i.st_mode):return {'present':True,'kind':'symlink','generation':fp(i),'link':os.readlink(path),'contentRead':False}
  if stat.S_ISDIR(i.st_mode):return {'present':True,'kind':'directory','generation':fp(i)}
  result=fixed_read(path,limit);raw=result.pop('raw')
  if include_text:
   if result['hashScope']!='full':raise ValueError('preflight_metadata_limit')
   result['text']=raw.decode('utf-8','strict')
  return {'present':True,'kind':'regular',**result}
 except FileNotFoundError:return {'present':False}
def boot():
 value=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value):raise ValueError('preflight_boot_unknown')
 return value
def parse_ini(text):
 result={}
 for line in text.splitlines():
  if not line.strip() or line.lstrip().startswith('#'):continue
  if '=' not in line:raise ValueError('preflight_ini_invalid')
  key,value=line.split('=',1);key=key.strip();value=value.strip()
  if not key or key in result:raise ValueError('preflight_ini_invalid')
  result[key]=value
 return result

def avd_facts(alias):
 chosen=OWNED[alias];home=pathlib.Path(chosen['avdHome']);directory=home/(chosen['avd']+'.avd');ini=home/(chosen['avd']+'.ini')
 scope={'__name__':'sdk_preflight'};exec(compile(SDK_TEXT,'<reviewed-sdk-preflight>','exec'),scope)
 admitted=scope['safe_emulator_environment'](chosen['sdk'],chosen['avdHome'],chosen['systemImage'])
 if admitted['sdkRoot'] not in {chosen['sdk'],'/opt/android-sdk'} or admitted['avdHome']!=chosen['avdHome'] or admitted['emulator'] not in {chosen['emulator'],'/opt/android-sdk/emulator/emulator'}:raise ValueError('preflight_sdk_path_changed')
 ini_info=facts(ini,65536,True);config=facts(directory/'config.ini',65536,True)
 if not ini_info.get('present') or not config.get('present') or ini_info.get('kind')!='regular' or config.get('kind')!='regular':raise ValueError('preflight_avd_metadata_missing')
 values=parse_ini(ini_info['text']);cfg=parse_ini(config['text'])
 if values.get('path')!=str(directory) or cfg.get('AvdId') not in (None,chosen['avd']) or cfg.get('abi.type')!='x86_64':raise ValueError('preflight_avd_identity_changed')
 named=directory.lstat()
 if not stat.S_ISDIR(named.st_mode) or named.st_uid!=os.getuid():raise ValueError('preflight_avd_directory_changed')
 names=sorted(os.listdir(directory))
 if len(names)>256 or any(not re.fullmatch(r'[A-Za-z0-9_.-]+',n) for n in names):raise ValueError('preflight_avd_inventory_limit')
 inventory={n:facts(directory/n,65536,n.endswith('.ini') or n.endswith('.txt')) for n in names}
 if fp(named)!=fp(directory.lstat()):raise ValueError('preflight_avd_directory_changed')
 image=pathlib.Path(chosen['sdk']).joinpath(*chosen['systemImage'].split(';'))
 sdk_files={str(path):facts(path,16777216,path.name=='package.xml') for path in [pathlib.Path(admitted['emulator']),pathlib.Path(CFG['profiles'][alias]['adb']),image/'package.xml',image/'system.img',image/'userdata.img',image/'ramdisk.img',image/'kernel-ranchu']}
 return {'historicalSelection':chosen,'sdkPreflight':admitted,'avdDirectory':{'path':str(directory),'generation':fp(named)},'ini':ini_info,'config':config,'inventory':inventory,'sdkFiles':sdk_files,'diskFullHistoricalShaVerified':False}

def sockets():
 result=[]
 for family in ('tcp','tcp6'):
  for line in pathlib.Path('/proc/net/'+family).read_text().splitlines()[1:]:
   parts=line.split()
   if len(parts)<10:raise ValueError('preflight_socket_inventory_unknown')
   port=int(parts[1].rsplit(':',1)[1],16)
   if port in (5682,5683,5684,5685):result.append({'family':family,'port':port,'state':parts[3],'inode':parts[9]})
 return sorted(result,key=lambda x:(x['family'],x['port'],x['inode']))
def start_ticks(path):
 text=(path/'stat').read_text();return int(text.rsplit(')',1)[1].split()[19])
def holders(avds):
 identities={}
 for alias,value in avds.items():
  for name,entry in value.get('inventory',{}).items():
   if entry.get('kind')=='regular':identities[tuple(entry['generation'][:2])]=alias+'/'+name
 denied=0;found=[];qemu=[]
 pids=[p for p in pathlib.Path('/proc').iterdir() if p.name.isdecimal()]
 if len(pids)>32768:raise ValueError('preflight_process_inventory_limit')
 for proc in pids:
  try:
   before=start_ticks(proc);cmd=(proc/'cmdline').read_bytes()
   if len(cmd)>131072:raise ValueError('preflight_process_command_limit')
   args=cmd.split(b'\0');exe=args[0].rsplit(b'/',1)[-1]
   if exe.startswith(b'qemu-system-') or exe==b'emulator':qemu.append({'pid':int(proc.name),'startTicks':before})
   matches=[]
   for fd in (proc/'fd').iterdir():
    try:i=fd.stat()
    except FileNotFoundError:continue
    if (i.st_dev,i.st_ino) in identities:matches.append(identities[(i.st_dev,i.st_ino)])
   if start_ticks(proc)!=before:raise ValueError('preflight_pid_reused')
   if matches:found.append({'pid':int(proc.name),'startTicks':before,'files':sorted(set(matches))})
  except FileNotFoundError:continue
  except PermissionError:denied+=1
 return {'complete':denied==0,'unreadableProcessCount':denied,'holders':found,'emulators':qemu,'requiresPrivilegedConfirmation':os.getuid()!=0}
def resources():
 values={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in pathlib.Path('/proc/meminfo').read_text().splitlines()}
 available=int(values['MemAvailable'].split()[0])*1024;free=shutil.disk_usage(root).free
 return {'availableMemoryBytes':available,'freeDiskBytes':free,'windowsReservedBytes':4294967296,'androidRequestedBytes':4294967296,'minimumHeadroomBytes':10737418240,'budgetSatisfied':available>=19327352832 and free>=10737418240}
def snapshot():
 avds={}
 for alias in ('api29','api35'):
  try:avds[alias]=avd_facts(alias)
  except (OSError,ValueError,UnicodeError) as exc:
   reason=str(exc) if str(exc).startswith('preflight_') and len(str(exc))<80 else 'preflight_layout_unadmitted'
   chosen=OWNED[alias];home=pathlib.Path(chosen['avdHome'])
   avds[alias]={'error':reason,'historicalSelection':chosen,'avdHome':facts(home),'avdDirectory':facts(home/(chosen['avd']+'.avd')),'ini':facts(home/(chosen['avd']+'.ini'),65536,True),'inventory':{}}
 claims={alias:facts(root/('android-native-device-'+alias+'.lease'),8192,True) for alias in ('api29','api35')}
 return {'bootId':boot(),'avds':avds,'claims':claims,'ports':sockets(),'holderCensus':holders(avds),'resources':resources()}
def capture():
 i=root.lstat()
 if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.getuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError('preflight_root_unsafe')
 if os.path.lexists(capsule):raise ValueError('preflight_capture_exists')
 first=snapshot();second=snapshot()
 stable=all(first[k]==second[k] for k in ('bootId','avds','claims','ports','holderCensus'))
 value={'schema':1,'kind':'readonly-owned-avd-preflight','correlationId':CFG['correlationId'],'source':CFG['source'],'history':CFG['history'],'localClaims':CFG['localClaims'],'observations':[first,second],'stable':stable,'lifecycleAllowed':False,'productAdmitted':False,'historicalOutcomesPreserved':True}
 raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
 if len(raw)>524288:raise ValueError('preflight_capture_limit')
 fd=os.open(capsule,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 pin=fixed_read(capsule,524288);pin.pop('raw');summary={'stable':stable,'layoutErrors':sum('error' in value for value in second['avds'].values()),'bootId':second['bootId'],'ownedPortsFree':not second['ports'],'emulatorCount':len(second['holderCensus']['emulators']),'holderCount':len(second['holderCensus']['holders']),'holderCensusComplete':second['holderCensus']['complete'],'budgetSatisfied':first['resources']['budgetSatisfied'] and second['resources']['budgetSatisfied'],'lifecycleAllowed':False}
 print(json.dumps({'state':'captured','correlationId':CFG['correlationId'],'pin':pin,'summary':summary},separators=(',',':')))
capture()
'''
_FETCH=r'''
import base64,hashlib,json,os,pathlib,stat,sys
root,name,pin_json,offset=sys.argv[1:];root=pathlib.Path(root);pin=json.loads(pin_json);offset=int(offset)
if not __import__('re').fullmatch(r'android-avd-preflight-[0-9a-f-]{36}\.json',name) or offset<0 or offset%2048:raise ValueError('fetch_binding')
def fp(i):return [i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_mode,i.st_uid,i.st_gid,i.st_nlink]
path=root/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
try:
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size>524288 or fp(info)!=pin['generation']:raise ValueError('fetch_generation')
 raw=b''
 while len(raw)<=524288:
  piece=os.read(fd,65536)
  if not piece:break
  raw+=piece
 if len(raw)!=info.st_size or hashlib.sha256(raw).hexdigest()!=pin['sha256'] or fp(os.fstat(fd))!=pin['generation'] or fp(path.lstat())!=pin['generation']:raise ValueError('fetch_changed')
 print(json.dumps({'offset':offset,'data':base64.b64encode(raw[offset:offset+2048]).decode()}))
finally:os.close(fd)
'''

def _prepare(root,correlation):
    if not isinstance(correlation,str) or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',correlation):raise ValueError('avd_preflight_correlation')
    paths=[Path(__file__).absolute(),root/'scripts/android_avd_sdk_preflight.py'];source={};snapshots={}
    for path in paths:
        pin,raw=availability._snapshot(path);snapshots[path]=(pin,raw);source[str(path.relative_to(root))]=hashlib.sha256(raw).hexdigest()
    historical={}
    for name,wanted in HISTORY.items():
        path=root/name;pin,raw=availability._snapshot(path)
        if hashlib.sha256(raw).hexdigest()!=wanted:raise ValueError('avd_historical_path_changed')
        snapshots[path]=(pin,raw);historical[name]=wanted
    api35=json.loads(snapshots[root/next(iter(HISTORY))][1]);api29=json.loads(snapshots[root/list(HISTORY)[1]][1])
    if api35['android_avd_home']!=OWNED['api35']['avdHome'] or api35['avd_path']!=OWNED['api35']['avdHome']+'/'+OWNED['api35']['avd']+'.avd' or api29['avdHome']!=OWNED['api29']['avdHome'] or api29['sdkRoot']!=OWNED['api29']['sdk'] or api29['emulator']!=OWNED['api29']['emulator']:raise ValueError('avd_historical_path_changed')
    config=endpoint.ssh_transport.load_config(root);host=config.hosts['archlinux'];profiles={}
    for alias,wanted in OWNED.items():
        profile=endpoint.android_observation._profile(host.android_devices[alias])
        if profile['serial']!=wanted['serial'] or profile['expectedAvd']!=wanted['avd'] or profile['api']!=wanted['api']:raise ValueError('avd_configured_identity_changed')
        profiles[alias]=profile
    if str(host.fixture_transfer_root)!='/home/kardinal/.vpn-control-mcp-fixtures' or endpoint.ssh_transport.connection_host(config,'archlinux').password is not None:raise ValueError('avd_route_changed')
    claims={};claimpins={}
    for alias in OWNED:
        path=root/'.rag_index/android-native-device-leases'/('lease-archlinux-'+alias+'.json')
        if os.path.lexists(path):
            pin=endpoint._recovery_local_snapshot(path);claims[alias]={'present':True,'body':pin[0],'sha256':pin[1],'generation':list(pin[2])};claimpins[path]=pin
        else:claims[alias]={'present':False};claimpins[path]=None
    cfg={'correlationId':correlation,'remoteRoot':str(host.fixture_transfer_root),'profiles':profiles,'source':source,'history':historical,'localClaims':claims}
    return cfg,snapshots,claimpins,config

def _call(root,correlation,collect_only=False):
    root=Path(root).absolute();cfg,snapshots,claims,config=_prepare(root,correlation)
    local=root/'.runtime/parity-evidence/android-current'/('owned-avd-preflight-'+correlation+'.json')
    if os.path.lexists(local):raise ValueError('avd_local_capture_exists')
    def guard():
        for path,pin in snapshots.items():
            if availability._snapshot(path)!=pin:raise ValueError('avd_local_source_changed')
        for path,pin in claims.items():
            if (endpoint._recovery_local_snapshot(path) if os.path.lexists(path) else None)!=pin:raise ValueError('avd_local_claim_changed')
    def invoke(program,args):
        guard();argv=endpoint.ssh_transport.build_ssh_argv(config,'archlinux',30,command=('python3','-c','exec('+repr(program)+')',*args));code,raw=endpoint.android_observation._run_probe(argv,180);guard()
        if code:raise ValueError('avd_preflight_transport_unknown')
        return json.loads(raw)
    own=snapshots[Path(__file__).absolute()][1];template=ast.literal_eval(next(n.value for n in ast.parse(own).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_REMOTE' for t in n.targets)))
    sdk=snapshots[root/'scripts/android_avd_sdk_preflight.py'][1].decode();program=template.replace('__CFG__',repr(cfg)).replace('__SDK__',repr(sdk)).replace('__OWNED__',repr(OWNED))
    receipt_path=local.with_name(local.stem+'.receipt.json')
    if collect_only:
        receipt=private_io._private(receipt_path,65536)
        if receipt[0].get('cfg')!=cfg:raise ValueError('avd_preflight_receipt_changed')
        result=receipt[0]['result']
    else:
        if os.path.lexists(receipt_path):raise ValueError('avd_preflight_submission_recorded_use_collect')
        result=invoke(program,())
        private_io._write(receipt_path,{'cfg':cfg,'result':result})
    receipt_pin=private_io._private(receipt_path,65536)
    if result.get('state')!='captured' or result.get('correlationId')!=correlation:raise ValueError('avd_preflight_capture_unknown')
    pin=result['pin'];gen=pin.get('generation')
    if not isinstance(gen,list) or len(gen)!=9 or any(type(x) is not int or x<0 for x in gen) or gen[2]>524288 or __import__('stat').S_IMODE(gen[5])!=0o600 or gen[8]!=1 or not re.fullmatch(r'[0-9a-f]{64}',str(pin.get('sha256',''))):raise ValueError('avd_preflight_pin_invalid')
    name='android-avd-preflight-'+correlation+'.json';raw=b''
    fetch=ast.literal_eval(next(n.value for n in ast.parse(own).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_FETCH' for t in n.targets)))
    for offset in range(0,pin['generation'][2],2048):
        if private_io._private(receipt_path,65536)!=receipt_pin:raise ValueError('avd_preflight_receipt_changed')
        chunk=invoke(fetch,(cfg['remoteRoot'],name,json.dumps(pin,separators=(',',':')),str(offset)))
        if chunk.get('offset')!=offset:raise ValueError('avd_preflight_collection_changed')
        part=base64.b64decode(chunk['data'],validate=True)
        if len(part)!=min(2048,pin['generation'][2]-offset):raise ValueError('avd_preflight_collection_changed')
        raw+=part
    if len(raw)>524288 or hashlib.sha256(raw).hexdigest()!=pin['sha256']:raise ValueError('avd_preflight_collection_changed')
    value=json.loads(raw)
    if value.get('correlationId')!=correlation or value.get('source')!=cfg['source'] or value.get('localClaims')!=cfg['localClaims'] or value.get('lifecycleAllowed') is not False:raise ValueError('avd_preflight_collection_changed')
    if private_io._private(receipt_path,65536)!=receipt_pin:raise ValueError('avd_preflight_receipt_changed')
    guard();fd=os.open(local,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    guard();return {'state':'captured','summary':result['summary'],'path':str(local),'sha256':pin['sha256'],'bytes':len(raw),'lifecycleAllowed':False,'productAdmitted':False,'historicalOutcomesPreserved':True}


def preflight(root,correlation):return _call(root,correlation)
def collect(root,correlation):return _call(root,correlation,True)
