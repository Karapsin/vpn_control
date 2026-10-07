"""Fixed API35 asset-only bridge; preparation and source emission never submit.

The trusted operator supplies actual mint/artifact custody and an admitted root
route. This module does not issue/adopt a lease or execute the installer. The
operator retains raw transport and both EOFs before projecting custody.
"""
from __future__ import annotations
import hashlib,json,os,stat,uuid
from contextlib import contextmanager
from pathlib import Path
from . import android_installer_dispatch as dispatch, ssh_transfer, ssh_transport

PRODUCT='d32f719a08db57e5d40ce2bf77e0d7c5b42de557'
BASE='352af218242311884a355f789c0d1c45b736c35270b096f41408de55e2c4ed33'
TARGET='2734b5da9b3e8becbe54bc7e980f06402f65994e071ef95123511ddaac78bcf9'
NAMES=('base.apk','target.apk','ca.pem','leaf.pem','key.pem','receipt.json')
MAX_SMALL=65536
APK_SIZE=45026948
MAX_TOTAL=2*APK_SIZE+4*MAX_SMALL
CANONICAL_ROOT='/home/kardinal/.vpn-control-mcp-fixtures'

# This entry consumes the actual source-closed bundle/command namespace. Its
# receipt is read through the original authenticated receiver, not accepted as
# an authored admission flag. It creates only BaselineGuard's private evidence.
PARENT_ENTRY='''import base64,copy,json
asset_guard=COMPONENT_BUNDLE.BaselineGuard(COMPONENT_RECEIPT,COMPONENT_MODULES,globals(),ASSET_PARENT_REQUEST)
asset_guard()
asset_path=asset_guard.args.output/'component-guard-current-admission.json'
asset_raw,asset_pin=COMPONENT_BUNDLE._read(asset_path,True)
command_host_guard()
asset_parent_result={'schema':1,'kind':'android-asset-parent-readonly','correlationId':ASSET_PARENT_CORRELATION,'root':str(ROOT),'hostBootId':boot(),'request':copy.deepcopy(ASSET_PARENT_REQUEST),'owner':asset_guard.owner,'revision':asset_guard.revision,'admission':{'path':str(asset_path),'rawBase64':base64.b64encode(asset_raw).decode(),'pin':asset_pin},'installerLeaseGranted':False,'guestMutationPerformed':False,'acceptanceComplete':False,'replayAllowed':False}
print(json.dumps(asset_parent_result,sort_keys=True,separators=(',',':')))
'''

def parent_admission_source(receipt,prepared,request,correlation):
    """Genuine fresh readonly payload; assembling it never submits it."""
    from . import android_installer_component_bundle as bundle
    corr(correlation)
    require(type(request)is dict and request.get('device')=='android-api35' and request.get('sourceSha')==PRODUCT and request.get('packageSha256')==BASE and request.get('expectedApi')==35 and type(request.get('expectedRevision'))is int and request['expectedRevision']==0,'asset_parent_request_invalid')
    corr(request['expectedOwner']);corr(request['correlationId'])
    source=bundle.carrier_source(receipt,prepared,str(uuid.uuid5(uuid.UUID(correlation),'asset-parent-bundle')))
    source+='\nASSET_PARENT_REQUEST='+repr(request)+'\nASSET_PARENT_CORRELATION='+repr(correlation)+'\n'+PARENT_ENTRY
    compile(source,'<fixed-asset-parent-readonly>','exec',dont_inherit=True)
    return source.encode()

def parent_custody(evidence,correlation,boot_id,expected_source):
    """Explicit original readonly capsule provenance, never a raw grant dict.

    The operator's reviewed source admission seals these expected full pins
    before submission. Preserve them across raw collection and source closing.
    """
    import base64
    require(type(expected_source)is bytes and 0<len(expected_source)<=8388608,'asset_parent_expected_source_required')
    require(type(evidence)is dict and set(evidence)=={'programme','raw','terminal','closing'},'asset_parent_provenance_required')
    blobs={};pins=[]
    for name,limit in [('programme',8388608),('raw',33554432),('terminal',MAX_SMALL),('closing',MAX_SMALL)]:
        expected=evidence[name];require(type(expected)is dict and set(expected)=={'path','generation','parents','sha256'},'asset_parent_provenance_required')
        raw,pin=snapshot(Path(expected['path']),limit,True);require(pin==expected,'asset_parent_provenance_changed');blobs[name]=raw;pins.append((expected,limit))
    require(blobs['programme']==expected_source,'asset_parent_producer_changed')
    document=decode(blobs['raw']);terminal=decode(blobs['terminal']);closing=decode(blobs['closing'])
    require(type(closing)is dict and set(closing)=={'schema','correlationId','sourceClosingVerified','transportTerminalAuthenticated','rawSha256','rawBytes','programmeSha256'} and type(closing['schema'])is int and closing['schema']==1 and closing['correlationId']==correlation and closing['sourceClosingVerified']is True and closing['transportTerminalAuthenticated']is True and closing['rawSha256']==sha(blobs['raw']) and type(closing['rawBytes'])is int and closing['rawBytes']==len(blobs['raw']) and closing['programmeSha256']==sha(blobs['programme']),'asset_parent_source_closing_changed')
    require(type(terminal)is dict and set(terminal)=={'schema','kind','returncode','failure','hostIdentity','sourceBytes','sourceSha256','stdoutBytes','stdoutSha256','stderrBytes','stderrSha256'} and type(terminal['schema'])is int and terminal['schema']==1 and terminal['kind']=='api29-component-baseline-terminal' and type(terminal['returncode'])is int and terminal['returncode']==0 and terminal['failure']is None and type(terminal['sourceBytes'])is int and terminal['sourceBytes']==len(blobs['programme']) and terminal['sourceSha256']==sha(blobs['programme']) and type(terminal['stdoutBytes'])is int and terminal['stdoutBytes']==len(blobs['raw']) and terminal['stdoutSha256']==sha(blobs['raw']) and type(terminal['stderrBytes'])is int and terminal['stderrBytes']==0 and terminal['stderrSha256']==sha(b''),'asset_parent_terminal_changed')
    host=terminal['hostIdentity'];require(type(host)is dict and set(host)=={'uid','euid','gid','egid','groups'} and all(type(host[k])is int and host[k]==1000 for k in ('uid','euid','gid','egid')) and type(host['groups'])is list and len(host['groups'])<=64 and all(type(x)is int and x>=0 for x in host['groups']),'asset_parent_transport_identity_changed')
    require(type(document)is dict and set(document)=={'schema','kind','correlationId','root','hostBootId','request','owner','revision','admission','installerLeaseGranted','guestMutationPerformed','acceptanceComplete','replayAllowed'} and type(document['schema'])is int and document['schema']==1 and document['kind']=='android-asset-parent-readonly' and document['correlationId']==correlation and document['root']==CANONICAL_ROOT and document['hostBootId']==boot_id and all(document[k]is False for k in ('installerLeaseGranted','guestMutationPerformed','acceptanceComplete','replayAllowed')),'asset_parent_reply_changed')
    require(blobs['programme'].endswith(PARENT_ENTRY.encode()),'asset_parent_producer_changed')
    import ast
    tree=ast.parse(blobs['programme']);assignments={}
    for n in tree.body:
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('ASSET_PARENT_REQUEST','ASSET_PARENT_CORRELATION'):
            require(n.targets[0].id not in assignments,'asset_parent_producer_changed');assignments[n.targets[0].id]=ast.literal_eval(n.value)
    request=document['request'];require(type(request)is dict and set(request)=={'host','device','correlationId','sourceSha','expectedOwner','expectedRevision','expectedAvd','expectedApi','packageSha256','reservation'} and type(request['expectedRevision'])is int and type(request['expectedAvd'])is str and type(request['reservation'])is dict and request['reservation'],'asset_parent_request_changed');corr(request['correlationId']);corr(request['expectedOwner']);require(assignments=={'ASSET_PARENT_REQUEST':request,'ASSET_PARENT_CORRELATION':correlation} and type(request)is dict and request.get('host')=='archlinux' and request.get('device')=='android-api35' and request.get('sourceSha')==PRODUCT and request.get('packageSha256')==BASE and type(request.get('expectedApi'))is int and request['expectedApi']==35 and request.get('expectedOwner')==document['owner'] and type(document['revision'])is int and document['revision']==request.get('expectedRevision')==0,'asset_parent_request_changed')
    row=document['admission'];require(type(row)is dict and set(row)=={'path','rawBase64','pin'},'asset_parent_record_changed');raw=base64.b64decode(row['rawBase64'],validate=True);pin=row['pin'];record=decode(raw)
    require(type(pin)is dict and set(pin)=={'generation','parents','sha256'} and pin['sha256']==sha(raw) and type(pin['generation'])is list and len(pin['generation'])==9 and all(type(x)is int for x in pin['generation']) and pin['generation'][3:7]==[0,0,1,len(raw)] and stat.S_ISREG(pin['generation'][2]) and stat.S_IMODE(pin['generation'][2])==0o600,'asset_parent_record_changed')
    expected_path=Path(CANONICAL_ROOT)/('android-installer-component-baseline-'+request['correlationId'])/'component-guard-current-admission.json';require(row['path']==str(expected_path),'asset_parent_path_changed')
    require(type(record)is dict and set(record)=={'schema','kind','phase','binding','record','componentRuntime','installerLeaseGranted','guestMutationPerformed','installedLauncherAccepted','bundledRuntimeAccepted','replayAllowed'} and type(record['schema'])is int and record['schema']==1 and record['kind']=='android-installer-component-baseline-read' and record['phase']=='baseline-read-only' and record['binding']==request and record['componentRuntime']=='EXTERNAL_JDK' and all(record[k]is False for k in ('installerLeaseGranted','guestMutationPerformed','installedLauncherAccepted','bundledRuntimeAccepted','replayAllowed')),'asset_parent_admission_changed')
    require(type(record.get('record'))is dict and set(record['record'])=={'facts','stage','host','owner','revision','installedPackageDump'} and record['record']['owner']==request['expectedOwner'] and type(record['record']['revision'])is int and record['record']['revision']==0,'asset_parent_admission_changed')
    principal=record['record']['host'];require(type(principal)is dict and set(principal)=={'uid','euid','gid','egid','groups'} and all(type(principal[k])is int and principal[k]==0 for k in ('uid','euid','gid','egid')) and type(principal['groups'])is list and principal['groups']==sorted(set(principal['groups'])) and all(type(x)is int and x>=0 for x in principal['groups']),'asset_parent_principal_changed')
    roots={str(p)for p in Path(CANONICAL_ROOT).parents}|{CANONICAL_ROOT};parents=pin['parents'];require(type(parents)is dict and set(parents)=={str(p)for p in expected_path.parents} and all(type(v)is list and len(v)==5 and all(type(x)is int for x in v) and stat.S_ISDIR(v[2])for v in parents.values()),'asset_parent_ancestry_changed');require(parents[CANONICAL_ROOT][3:]==[1000,1000] and stat.S_IMODE(parents[CANONICAL_ROOT][2])==0o700,'asset_parent_principal_changed')
    value={'root':CANONICAL_ROOT,'correlationId':correlation,'bootId':boot_id,'principal':principal,'parents':{p:parents[p]for p in sorted(roots)},'programmeSha256':sha(blobs['programme']),'rawSha256':sha(blobs['raw'])}
    with held_custody(pins)as closing:closing()
    return value

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(value,code):
    if not value:raise ValueError(code)
def json_pairs(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'asset_json_duplicate');result[key]=value
    return result
def decode(raw):return json.loads(raw,object_pairs_hook=json_pairs)
def corr(value):
    require(type(value)is str and str(uuid.UUID(value))==value,'asset_correlation_invalid');return value
def generation(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def parent(s):return generation(s)[:5]

def snapshot(path,limit,body=False):
    """Owned private explicit path, full read and all ancestor structural closure."""
    path=Path(path);require(path.is_absolute() and '..'not in path.parts,'asset_path_invalid')
    chain=[];fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);chain.append(('/',fd,parent(os.fstat(fd))));leaf=None
    try:
        current=Path('/')
        for part in path.parts[1:-1]:
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);current=current/part;chain.append((str(current),fd,parent(os.fstat(fd))))
        leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);s=os.fstat(leaf);g=generation(s)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_gid==os.getgid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=limit,'asset_file_unsafe')
        h=hashlib.sha256();size=0;parts=[]
        while b:=os.read(leaf,524288):
            size+=len(b);require(size<=limit,'asset_file_limit');h.update(b)
            if body:parts.append(b)
        require(size==s.st_size and generation(os.fstat(leaf))==g==generation(os.stat(path.name,dir_fd=fd,follow_symlinks=False)),'asset_file_changed')
        for name,d,p in chain:require(parent(os.fstat(d))==p==parent(os.stat(name,follow_symlinks=False)),'asset_parent_changed')
        pin={'path':str(path),'generation':g,'parents':{n:p for n,_,p in chain},'sha256':h.hexdigest()}
        return (b''.join(parts),pin) if body else pin
    finally:
        if leaf is not None:os.close(leaf)
        for _,d,_ in reversed(chain):os.close(d)

def tls_binding(receipt,pins,correlation):
    require(type(receipt)is dict and type(receipt.get('schema'))is int and receipt['schema']==1 and receipt.get('kind')=='android-disposable-fixture-tls' and receipt.get('testOnly')is True and receipt.get('campaignId')==correlation,'asset_tls_receipt_invalid')
    facts=receipt.get('sourceFacts',{})
    require(type(facts)is dict and facts.get('sourceSha')==PRODUCT and facts.get('baseArtifactId')=='sha256-'+BASE and facts.get('targetArtifactId')=='sha256-'+TARGET and facts.get('targetSha256')==TARGET and facts.get('baseVersion')=='2.2.2' and facts.get('targetVersion')=='2.2.3' and type(facts.get('baseCode'))is int and facts['baseCode']==16840 and type(facts.get('targetCode'))is int and facts['targetCode']==16860 and type(facts.get('targetSize'))is int and facts['targetSize']==APK_SIZE,'asset_tls_plan_changed')
    for name,origin in [('ca.pem','ca.pem'),('leaf.pem','leaf.pem'),('key.pem','leaf-key.pem')]:
        value=receipt.get('files',{}).get(origin,{})
        require(type(value)is dict and type(value.get('bytes'))is int and value['bytes']==pins[name]['generation'][6] and value.get('sha256')==pins[name]['sha256'],'asset_tls_material_changed')

@contextmanager
def held_custody(pins):
    """Full authenticated reads, then one pure population closure before return."""
    held=[]
    try:
        for pin,limit in pins:
            path=Path(pin['path']);chain=[];leaf=None
            try:
                fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);chain.append(('/',fd))
                current=Path('/')
                for part in path.parts[1:-1]:
                    fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);current=current/part;chain.append((str(current),fd))
                leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                require(generation(os.fstat(leaf))==pin['generation'],'asset_custody_changed')
                h=hashlib.sha256();size=0
                while b:=os.read(leaf,524288):
                    size+=len(b);require(size<=limit,'asset_custody_changed');h.update(b)
                require(size==pin['generation'][6] and h.hexdigest()==pin['sha256'],'asset_custody_changed')
                require({p:parent(os.fstat(d))for p,d in chain}==pin['parents'],'asset_custody_changed')
                held.append((pin,leaf,chain));leaf=None;chain=[]
            finally:
                if leaf is not None:os.close(leaf)
                for _,d in reversed(chain):os.close(d)
        def closing():
            # No hashing, file reads, route lookup or publication follows this
            # complete held/named population check in transport_request.
            for pin,leaf,chain in held:
                require(generation(os.fstat(leaf))==pin['generation']==generation(os.stat(Path(pin['path']).name,dir_fd=chain[-1][1],follow_symlinks=False)),'asset_custody_changed')
                for name,d in chain:require(parent(os.fstat(d))==pin['parents'][name]==parent(os.stat(name,follow_symlinks=False)),'asset_custody_changed')
        yield closing
    finally:
        for _,leaf,chain in reversed(held):
            os.close(leaf)
            for _,d in reversed(chain):os.close(d)

# Standalone fixed receiver. Authentication of these exact bytes precedes exec
# in the reviewed operator carrier; the frame carries only fixed material data.
RECEIVER=r'''import hashlib,json,os,stat,sys,uuid
root_raw,correlation,expected_manifest,expected_boot=sys.argv[1:]
def req(v,c):
 if not v:raise ValueError(c)
def pairs(items):
 result={}
 for key,value in items:
  req(key not in result,'asset_json_duplicate');result[key]=value
 return result
def canon(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
def gen(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def p5(s):return gen(s)[:5]
def put(fd,data):
 at=0
 while at<len(data):
  n=os.write(fd,data[at:]);req(n>0,'asset_short_write');at+=n
req(os.getuid()==0 and os.geteuid()==0 and os.getgid()==0 and os.getegid()==0,'asset_root_required')
req(str(uuid.UUID(correlation))==correlation and str(uuid.UUID(expected_boot))==expected_boot,'asset_identity_invalid')
with open('/proc/sys/kernel/random/boot_id','r',encoding='ascii')as b:req(b.read().strip()==expected_boot,'asset_boot_changed')
req(root_raw.startswith('/')and all(p not in ('','.', '..')for p in root_raw.split('/')[1:]),'asset_root_invalid')
chain=[];root_fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);chain.append(('/',root_fd,p5(os.fstat(root_fd))))
name='android-complete-update-inputs-'+correlation;leaf_fd=None;created=False
try:
 current=''
 for part in root_raw.split('/')[1:]:
  root_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root_fd);current+='/'+part;chain.append((current,root_fd,p5(os.fstat(root_fd))))
 r=os.fstat(root_fd);req(stat.S_ISDIR(r.st_mode)and stat.S_IMODE(r.st_mode)==0o700,'asset_root_unsafe')
 header=sys.stdin.buffer.readline(65537);req(0<len(header)<=65536 and hashlib.sha256(header).hexdigest()==expected_manifest,'asset_manifest_changed')
 m=json.loads(header,object_pairs_hook=pairs);names=('base.apk','target.apk','ca.pem','leaf.pem','key.pem','receipt.json')
 req(type(m)is dict and set(m)in ({'schema','correlationId','productSourceSha','files'},{'schema','correlationId','productSourceSha','files','parentAuthority'})and type(m['schema'])is int and m['schema']==1 and m['correlationId']==correlation and m['productSourceSha']=='d32f719a08db57e5d40ce2bf77e0d7c5b42de557'and type(m['files'])is list and len(m['files'])==6,'asset_manifest_invalid')
 authority=m.get('parentAuthority')
 if authority is None:req(r.st_uid==0 and r.st_gid==0,'asset_root_unsafe')
 else:
  req(type(authority)is dict and set(authority)=={'root','correlationId','bootId','principal','parents','programmeSha256','rawSha256'}and root_raw=='/home/kardinal/.vpn-control-mcp-fixtures'and authority['root']==root_raw and authority['correlationId']==correlation and authority['bootId']==expected_boot and r.st_uid==1000 and r.st_gid==1000,'asset_parent_authority_changed')
  principal=authority['principal'];req(type(principal)is dict and set(principal)=={'uid','euid','gid','egid','groups'}and all(type(principal[k])is int and principal[k]==0 for k in ('uid','euid','gid','egid'))and type(principal['groups'])is list and principal['groups']==sorted(set(principal['groups']))and all(type(x)is int and x>=0 for x in principal['groups'])and principal=={'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':sorted(os.getgroups())},'asset_parent_principal_changed')
  req(type(authority['parents'])is dict and authority['parents']=={p:p5(os.fstat(d))for p,d,_ in chain},'asset_parent_ancestry_changed')
  for key in ('programmeSha256','rawSha256'):req(type(authority[key])is str and len(authority[key])==64 and all(c in '0123456789abcdef'for c in authority[key]),'asset_parent_authority_changed')
 for name0,entry in zip(names,m['files']):
  req(type(entry)is dict and set(entry)=={'name','size','sha256'}and entry['name']==name0 and type(entry['size'])is int and 0<entry['size']<=(45026948 if name0.endswith('.apk')else 65536)and type(entry['sha256'])is str and len(entry['sha256'])==64 and all(c in '0123456789abcdef'for c in entry['sha256']),'asset_manifest_invalid')
 req(m['files'][0]['size']==45026948 and m['files'][0]['sha256']=='352af218242311884a355f789c0d1c45b736c35270b096f41408de55e2c4ed33'and m['files'][1]['size']==45026948 and m['files'][1]['sha256']=='2734b5da9b3e8becbe54bc7e980f06402f65994e071ef95123511ddaac78bcf9','asset_apk_changed')
 # Current root and original structural ancestors close before first effect.
 for p,d,g in chain:req(p5(os.fstat(d))==g==p5(os.stat(p,follow_symlinks=False)),'asset_parent_changed')
 os.mkdir(name,0o700,dir_fd=root_fd);created=True;os.fsync(root_fd)
 leaf_fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root_fd);leaf_gen=p5(os.fstat(leaf_fd));leaf_path=root_raw+'/'+name
 req(leaf_gen[3:]==[0,0]and stat.S_IMODE(leaf_gen[2])==0o700,'asset_leaf_unsafe')
 pins={};bodies={}
 for entry in m['files']:
  fd=os.open(entry['name'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=leaf_fd);h=hashlib.sha256();left=entry['size']
  try:
   while left:
    b=sys.stdin.buffer.read(min(65536,left));req(bool(b),'asset_stream_short');put(fd,b);h.update(b);left-=len(b)
   req(h.hexdigest()==entry['sha256'],'asset_stream_hash_changed');os.fsync(fd);g=gen(os.fstat(fd))
  finally:os.close(fd)
  req(gen(os.stat(entry['name'],dir_fd=leaf_fd,follow_symlinks=False))==g,'asset_file_changed')
  pins[entry['name']]={'path':leaf_path+'/'+entry['name'],'generation':g,'parents':{**{p:g0 for p,_,g0 in chain},leaf_path:leaf_gen},'sha256':entry['sha256']}
 req(sys.stdin.buffer.read(1)==b'','asset_stream_extra')
 os.fsync(leaf_fd);os.fsync(root_fd)
 for entry in m['files']:
  fd=os.open(entry['name'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=leaf_fd);h=hashlib.sha256();size=0;chunks=[]
  try:
   before=gen(os.fstat(fd));req(before==pins[entry['name']]['generation']and stat.S_ISREG(before[2])and before[3:6]==[0,0,1]and stat.S_IMODE(before[2])==0o600,'asset_file_changed')
   while b:=os.read(fd,524288):
    size+=len(b);req(size<=entry['size'],'asset_file_changed');h.update(b)
    if entry['name']=='receipt.json':chunks.append(b)
   req(size==entry['size']and h.hexdigest()==entry['sha256']and gen(os.fstat(fd))==before==gen(os.stat(entry['name'],dir_fd=leaf_fd,follow_symlinks=False)),'asset_file_changed')
   if chunks:bodies['receipt.json']=b''.join(chunks)
  finally:os.close(fd)
 receipt=json.loads(bodies['receipt.json'],object_pairs_hook=pairs);req(type(receipt.get('schema'))is int and receipt['schema']==1 and receipt.get('kind')=='android-disposable-fixture-tls'and receipt.get('testOnly')is True and receipt.get('campaignId')==correlation,'asset_tls_receipt_invalid')
 facts=receipt.get('sourceFacts',{});req(facts.get('sourceSha')==m['productSourceSha']and facts.get('baseArtifactId')=='sha256-'+m['files'][0]['sha256']and facts.get('targetArtifactId')=='sha256-'+m['files'][1]['sha256']and facts.get('baseVersion')=='2.2.2'and facts.get('targetVersion')=='2.2.3'and type(facts.get('baseCode'))is int and facts['baseCode']==16840 and type(facts.get('targetCode'))is int and facts['targetCode']==16860 and type(facts.get('targetSize'))is int and facts['targetSize']==45026948,'asset_tls_plan_changed')
 for dest,origin in [('ca.pem','ca.pem'),('leaf.pem','leaf.pem'),('key.pem','leaf-key.pem')]:
  item=receipt.get('files',{}).get(origin,{});req(type(item.get('bytes'))is int and item['bytes']==pins[dest]['generation'][6]and item.get('sha256')==pins[dest]['sha256'],'asset_tls_material_changed')
 with open('/proc/sys/kernel/random/boot_id','r',encoding='ascii')as b:req(b.read().strip()==expected_boot,'asset_boot_changed')
 for p,d,g in chain:req(p5(os.fstat(d))==g==p5(os.stat(p,follow_symlinks=False)),'asset_parent_changed')
 req(p5(os.fstat(leaf_fd))==leaf_gen==p5(os.stat(name,dir_fd=root_fd,follow_symlinks=False)),'asset_leaf_changed')
 for entry in m['files']:req(gen(os.stat(entry['name'],dir_fd=leaf_fd,follow_symlinks=False))==pins[entry['name']]['generation'],'asset_file_changed')
 authority={'schema':1,'correlationId':correlation,'productSourceSha':m['productSourceSha'],'inputDirectory':leaf_path,'files':{n:pins[n]for n in names[:-1]},'tlsReceipt':pins['receipt.json']}
 print(json.dumps({'schema':1,'state':'complete','correlationId':correlation,'manifestSha256':expected_manifest,'authority':authority,'leaseIssued':False,'nativeInstallerStarted':False,'replayAllowed':False},sort_keys=True,separators=(',',':')))
except Exception as e:
 code=str(e)if type(e)is ValueError and str(e) in ('asset_apk_changed', 'asset_boot_changed', 'asset_file_changed', 'asset_identity_invalid', 'asset_json_duplicate', 'asset_leaf_changed', 'asset_leaf_unsafe', 'asset_manifest_changed', 'asset_manifest_invalid', 'asset_parent_changed', 'asset_parent_authority_changed', 'asset_parent_principal_changed', 'asset_parent_ancestry_changed', 'asset_root_invalid', 'asset_root_required', 'asset_root_unsafe', 'asset_short_write', 'asset_stream_extra', 'asset_stream_hash_changed', 'asset_stream_short', 'asset_tls_material_changed', 'asset_tls_plan_changed', 'asset_tls_receipt_invalid')else ('asset_leaf_consumed'if type(e)is FileExistsError else 'asset_receiver_unknown')
 print(json.dumps({'schema':1,'state':'unknown','correlationId':correlation,'code':code,'partialLeafRetained':created,'replayAllowed':False},sort_keys=True,separators=(',',':')))
finally:
 if leaf_fd is not None:os.close(leaf_fd)
 for _,d,_ in reversed(chain):os.close(d)
'''

def prepare_local(repository,correlation,receiver_root,boot_id,files,parent_evidence=None,parent_source=None):
    """Actual custody preparation, called only after source-only/native approval.

    Never executed at import; caller supplies explicit paths to actual custody.
    There is no credential, lease, emulator or registry discovery here.
    """
    corr(correlation);corr(boot_id);receiver_root=Path(receiver_root)
    require(receiver_root.is_absolute()and '..'not in receiver_root.parts,'asset_root_invalid')
    require(type(files)is dict and set(files)==set(NAMES),'asset_inputs_invalid')
    pins={n:snapshot(Path(files[n]),APK_SIZE if n.endswith('.apk')else MAX_SMALL)for n in NAMES}
    require(pins['base.apk']['generation'][6]==APK_SIZE and pins['base.apk']['sha256']==BASE and pins['target.apk']['generation'][6]==APK_SIZE and pins['target.apk']['sha256']==TARGET,'asset_apk_changed')
    receipt_raw,_=snapshot(Path(files['receipt.json']),MAX_SMALL,True);tls_binding(decode(receipt_raw),pins,correlation)
    directory=Path(repository)/'.runtime'/'parity-evidence'/('android-asset-staging-'+correlation);directory.mkdir(mode=0o700)
    require(stat.S_IMODE(directory.stat().st_mode)==0o700 and directory.stat().st_uid==os.getuid(),'asset_capsule_unsafe')
    manifest={'schema':1,'correlationId':correlation,'productSourceSha':PRODUCT,'files':[{'name':n,'size':pins[n]['generation'][6],'sha256':pins[n]['sha256']}for n in NAMES]}
    if parent_evidence is not None:
        require(str(receiver_root)==CANONICAL_ROOT,'asset_parent_path_changed');manifest['parentAuthority']=parent_custody(parent_evidence,correlation,boot_id,parent_source)
    header=canonical(manifest)
    actual=dispatch._snapshot_payload(directory,[(n,Path(files[n]))for n in NAMES])
    require(actual==manifest['files'],'asset_snapshot_changed')
    for n in NAMES:require(snapshot(Path(files[n]),APK_SIZE if n.endswith('.apk')else MAX_SMALL)==pins[n],'asset_source_changed')
    payload=snapshot(directory/'payload.bin',MAX_TOTAL)
    prepared={'schema':1,'correlationId':correlation,'receiverRoot':str(receiver_root),'bootId':boot_id,'manifest':manifest,'manifestSha256':sha(header),'sourceSha256':sha(RECEIVER.encode()),'payloadPin':payload,'inputPins':pins,'replayAllowed':False}
    if parent_evidence is not None:
        prepared['parentEvidence']=parent_evidence;prepared['parentExpectedSource']={'sha256':sha(parent_source),'bytes':len(parent_source)}
    dispatch.android_installer_target._write_private(directory/'intent.json',prepared)
    prepared['intentPin']=snapshot(directory/'intent.json',MAX_SMALL)
    return prepared

def transport_request(repository,prepared,protected_prefix=b''):
    """Compose existing selected-route request only; does not execute it.

    The trusted operator must archive the original process/raw/dualEOF and use
    project only after current source/route/device admission and closing guards.
    """
    require(type(protected_prefix)is bytes and len(protected_prefix)<=4096,'asset_protected_channel_invalid')
    require(prepared['sourceSha256']==sha(RECEIVER.encode()),'asset_receiver_source_changed')
    payload=Path(prepared['payloadPin']['path']);require(snapshot(payload,MAX_TOTAL)==prepared['payloadPin'],'asset_snapshot_changed')
    intent_raw,intent_pin=snapshot(Path(prepared['intentPin']['path']),MAX_SMALL,True)
    require(intent_pin==prepared['intentPin'],'asset_intent_changed')
    require(canonical(decode(intent_raw))==canonical({k:v for k,v in prepared.items()if k!='intentPin'}),'asset_preparation_changed')
    for n in NAMES:require(snapshot(Path(prepared['inputPins'][n]['path']),APK_SIZE if n.endswith('.apk')else MAX_SMALL)==prepared['inputPins'][n],'asset_source_changed')
    if 'parentEvidence'in prepared:
        expected=prepared['parentExpectedSource'];require(type(expected)is dict and set(expected)=={'sha256','bytes'} and type(expected['bytes'])is int and 0<expected['bytes']<=8388608,'asset_parent_expected_source_required')
        source,pin=snapshot(Path(prepared['parentEvidence']['programme']['path']),8388608,True)
        require(sha(source)==expected['sha256'] and len(source)==expected['bytes'],'asset_parent_producer_changed')
        require(parent_custody(prepared['parentEvidence'],prepared['correlationId'],prepared['bootId'],source)==prepared['manifest']['parentAuthority'],'asset_parent_provenance_changed')
    submission=payload.parent/'submission-intent.json'
    try:os.lstat(submission)
    except FileNotFoundError:pass
    else:raise ValueError('asset_submit_consumed')
    pins=[(prepared['payloadPin'],MAX_TOTAL),(prepared['intentPin'],MAX_SMALL)]+[(prepared['inputPins'][n],APK_SIZE if n.endswith('.apk')else MAX_SMALL)for n in NAMES]
    if 'parentEvidence'in prepared:pins += [(prepared['parentEvidence'][name],limit)for name,limit in [('programme',8388608),('raw',33554432),('terminal',MAX_SMALL),('closing',MAX_SMALL)]]
    with held_custody(pins)as closing:
        config=ssh_transport.load_config(repository)
        argv=ssh_transport.build_ssh_argv(config,'archlinux',60,command=('sudo','-S','-p','','--','/usr/bin/python3','-I','-B','-c','exec('+repr(RECEIVER)+')',prepared['receiverRoot'],prepared['correlationId'],prepared['manifestSha256'],prepared['bootId']))
        # Durable before returning any executable request. A failed or uncertain
        # submission consumes this preparation; recovery observes its original raw.
        submission_value={'schema':1,'correlationId':prepared['correlationId'],'manifestSha256':prepared['manifestSha256'],'sourceSha256':prepared['sourceSha256'],'intentPin':prepared['intentPin'],'payloadPin':prepared['payloadPin'],'replayAllowed':False}
        try:dispatch.android_installer_target._write_private(submission,submission_value)
        except FileExistsError:raise ValueError('asset_submit_consumed')from None
        stream=ssh_transfer.StreamPayload(protected_prefix+canonical(prepared['manifest']),payload)
        submission_raw,submission_pin=snapshot(submission,MAX_SMALL,True)
        require(submission_raw==canonical(submission_value),'asset_custody_changed')
        with held_custody([(submission_pin,MAX_SMALL)])as fence_closing:
            fence_closing()
            closing()
            return argv,stream

def project(prepared,stdout,stderr,returncode,eof):
    """Raw must be durable first; partial or absent EOF never produces custody."""
    require(type(stdout)is bytes and type(stderr)is bytes,'asset_raw_type_invalid')
    unknown={'state':'unknown','correlationId':prepared['correlationId'],'replayAllowed':False}
    if type(returncode)is not int or returncode!=0 or stderr or len(stdout)>65536 or type(eof)is not dict or set(eof)!={'stdout','stderr'}or eof['stdout']is not True or eof['stderr']is not True:return unknown
    try:
        value=decode(stdout)
        if type(value)is not dict or set(value)!={'schema','state','correlationId','manifestSha256','authority','leaseIssued','nativeInstallerStarted','replayAllowed'}or type(value['schema'])is not int or value['schema']!=1 or value['state']!='complete' or value['correlationId']!=prepared['correlationId']or value['manifestSha256']!=prepared['manifestSha256']or value['leaseIssued']is not False or value['nativeInstallerStarted']is not False or value['replayAllowed']is not False:return unknown
        authority=value['authority'];root=Path(prepared['receiverRoot']);leaf=root/('android-complete-update-inputs-'+prepared['correlationId'])
        if type(authority)is not dict or set(authority)!={'schema','correlationId','productSourceSha','inputDirectory','files','tlsReceipt'}or type(authority['schema'])is not int or authority['schema']!=1 or authority['correlationId']!=prepared['correlationId']or authority['productSourceSha']!=PRODUCT or authority['inputDirectory']!=str(leaf)or type(authority['files'])is not dict or set(authority['files'])!=set(NAMES[:-1]):return unknown
        expected_parents={str(p) for p in leaf.parents}|{str(leaf)}
        parent_binding=None
        for entry in prepared['manifest']['files']:
            pin=authority['tlsReceipt']if entry['name']=='receipt.json'else authority['files'][entry['name']]
            if type(pin)is not dict or set(pin)!={'path','generation','parents','sha256'}or pin['path']!=str(leaf/entry['name'])or pin['sha256']!=entry['sha256']or type(pin['generation'])is not list or len(pin['generation'])!=9 or any(type(x)is not int for x in pin['generation'])or pin['generation'][3:7]!=[0,0,1,entry['size']]or not stat.S_ISREG(pin['generation'][2])or stat.S_IMODE(pin['generation'][2])!=0o600:return unknown
            if type(pin['parents'])is not dict or not pin['parents']or any(type(k)is not str or type(v)is not list or len(v)!=5 or any(type(x)is not int for x in v)for k,v in pin['parents'].items())or str(leaf)not in pin['parents']or pin['parents'][str(leaf)][3:]!=[0,0]or stat.S_IMODE(pin['parents'][str(leaf)][2])!=0o700:return unknown
            if set(pin['parents'])!=expected_parents or any(not stat.S_ISDIR(v[2]) for v in pin['parents'].values()):return unknown
            if parent_binding is None:parent_binding=pin['parents']
            elif pin['parents']!=parent_binding:return unknown
        parent_authority=prepared['manifest'].get('parentAuthority')
        if parent_authority is None:
            if parent_binding[str(root)][3:]!=[0,0] or stat.S_IMODE(parent_binding[str(root)][2])!=0o700:return unknown
        else:
            if type(parent_authority)is not dict or parent_authority.get('root')!=str(root) or any(parent_binding.get(path)!=pin for path,pin in parent_authority.get('parents',{}).items()) or set(parent_authority.get('parents',{}))!={str(p)for p in root.parents}|{str(root)}:return unknown
        return {'state':'complete','correlationId':prepared['correlationId'],'authority':authority,'leaseIssued':False,'nativeInstallerStarted':False,'replayAllowed':False}
    except (ValueError,TypeError,KeyError):return unknown
