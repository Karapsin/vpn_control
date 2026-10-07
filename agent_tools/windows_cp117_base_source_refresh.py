"""CP117 source-refresh setup admission: fixed read-only MSI metadata phase.

This module does not dispatch installers. Equal displayed versions are admitted
only as explicit fixture setup after old/new byte provenance is established.
The public updater's newer-version gate remains unchanged.
"""
import ast,base64,gzip,hashlib,json,os,re
from pathlib import Path
from . import windows_cp117_installed_base_observe as installed
from .windows_diagnostic_authority_capture import AuthorityCapture
CORRELATION='4b58346f-2c18-4bcd-bf20-48d2dd701c2a'
NONCE='4675e87e-099c-44a1-a2b5-b84638bf14c0'
INSTALLED_CORR=installed.CORRELATION
INSTALLED_SHA='fa5f054ecb6166ab09a29faaccbe3ce960cb864af764762b71e518a2716b531d'
PAIR_EXPECTED=installed.PAIR_EXPECTED
OLD_HASHES={'cliSha256':'ca95b4e671c3effe05eb8f888a4260dedb6ff22363fe347383290240801dd2b1','jarSha256':'586ecc7479375ed131577fd1a1bd4e5c4adf98a0ad2e6ab8080c766e94d24e5d','helperSha256':'72b12b3f02eda96caa54807730c2097117c66d8674bf7a6c86d769625bffd6ad','runtimeSha256':'ca74563c93440a2e9cb73eae6a04c109d3f5efce36a385f8261a654e362d2ea3'}
BASE_HASH=PAIR_EXPECTED['baseArtifactId'][7:]
BASE_SIZE=131101044
CANDIDATE=r'C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-67eeeedb-a618-42d5-8e31-821650d16302\base.msi'
GUID=r'\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}'
METADATA_PS=r'''$script:cp117OwnerDiagStage='package'
if($products.Count -ne 1 -or $products[0].DisplayVersion -cne '2.1.19' -or $products[0].PSChildName -notmatch '^\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$'){throw 'PACKAGE_DRIFT'}
$oldCode=$products[0].PSChildName.ToUpperInvariant();$candidate='@CANDIDATE@';$staged=$null
if(Test-Path -LiteralPath $candidate){
 $item=Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
 if($item.PSIsContainer -or $item.Length -ne @BASE_SIZE@){throw 'PACKAGE_DRIFT'}
 $first=[Cp117InstalledFile]::Read($candidate)
 if($first[0] -cne '@BASE_HASH@'){throw 'PACKAGE_DRIFT'}
 $owner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $candidate -ErrorAction Stop).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
 if($owner -cne '@SID@'){throw 'PACKAGE_DRIFT'}
 $engine=New-Object -ComObject WindowsInstaller.Installer
 $database=$engine.OpenDatabase($candidate,0)
 function ReadFixedProperty([string]$name){
  if($name -cnotin @('ProductCode','ProductVersion','UpgradeCode','ALLUSERS','MSIINSTALLPERUSER')){throw 'PACKAGE_DRIFT'}
  $query='SELECT `Value` FROM `Property` WHERE `Property` = '+[char]39+$name+[char]39;$view=$database.OpenView($query);$view.Execute();$row=$view.Fetch()
  try{if($null -eq $row){return $null};$value=$row.StringData(1);if($null -ne $view.Fetch()){throw 'PACKAGE_DRIFT'};return $value}finally{$view.Close()}
 }
 try{
  $code=ReadFixedProperty 'ProductCode';$upgrade=ReadFixedProperty 'UpgradeCode';$version=ReadFixedProperty 'ProductVersion';$allUsers=ReadFixedProperty 'ALLUSERS';$perUser=ReadFixedProperty 'MSIINSTALLPERUSER'
 }finally{[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database);[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine)}
 $last=[Cp117InstalledFile]::Read($candidate)
 if($last[0] -cne $first[0] -or $last[1] -cne $first[1]){throw 'PACKAGE_DRIFT'}
 $staged=@{sha256=$first[0];size=$item.Length;identity=$first[1];ownerMatches=$true;productCode=$code;upgradeCode=$upgrade;productVersion=$version;allUsers=$allUsers;perUser=$perUser}
}
$cp117Refresh=@{version=1;oldProductCode=$oldCode;staged=$staged;installerAction=$false;setupAdmission=$false}
'''

def _functions(raw,names):
    text=raw.decode();tree=ast.parse(text)
    return '\n\n'.join(ast.get_source_segment(text,next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name))for name in names)+'\n'

def body(admitted):
    bound=installed.precise.owner.guest.recovery.authority._read_bound_file
    pin,_=bound(Path(installed.__file__),retain_bytes=True)
    if pin['sha256']!=INSTALLED_SHA or admitted!=PAIR_EXPECTED:raise ValueError('refresh-fixed-source')
    source=installed.body(admitted)
    if hashlib.sha256(source.encode('utf-16le')).hexdigest()!='2bbfac5a7a37d28a36a2853c1d7f5e1a1d3f14f988f680c58379b476df44b9b2' or hashlib.sha256(METADATA_PS.encode()).hexdigest()!='1e71d6a3fe3fbdaac5481706093125ab543150cbddd73fa1f2761e6adb126534':raise ValueError('refresh-fixed-factory')
    marker="[Console]::Out.WriteLine((@{version=1;correlationId='"+INSTALLED_CORR
    at=source.index(marker)
    metadata=METADATA_PS.replace('@CANDIDATE@',CANDIDATE).replace('@BASE_SIZE@',str(BASE_SIZE)).replace('@BASE_HASH@',BASE_HASH).replace('@SID@',installed.precise.owner.SID)
    source=source[:at]+metadata+source[at:]
    source=source.replace('package=$cp117Package};details','package=$cp117Package;metadata=$cp117Refresh};details')
    if bound(Path(installed.__file__))!=pin:raise ValueError('refresh-source-drift')
    return source.replace(INSTALLED_CORR,CORRELATION)

def validate(value):
    if not isinstance(value,dict)or value.get('correlationId')!=CORRELATION:raise ValueError('refresh-correlation')
    base=dict(value,correlationId=INSTALLED_CORR)
    if value.get('outcome')=='complete':
        facts=value.get('facts')
        if not isinstance(facts,dict)or set(facts)!={'owner','readiness','package','metadata'}:raise ValueError('refresh-facts')
        base['facts']={k:facts[k]for k in ('owner','readiness','package')}
    installed.validate(base)
    if value['outcome']!='complete':return value
    metadata=value['facts']['metadata']
    if not isinstance(metadata,dict)or set(metadata)!={'version','oldProductCode','staged','installerAction','setupAdmission'}or type(metadata['version'])is not int or metadata['version']!=1 or metadata['installerAction']is not False or metadata['setupAdmission']is not False:raise ValueError('refresh-metadata')
    if not isinstance(metadata['oldProductCode'],str)or re.fullmatch(GUID,metadata['oldProductCode'])is None:raise ValueError('refresh-old-product')
    staged=metadata['staged']
    if staged is None:return value
    if not isinstance(staged,dict)or set(staged)!={'sha256','size','identity','ownerMatches','productCode','upgradeCode','productVersion','allUsers','perUser'}:raise ValueError('refresh-staged-schema')
    if staged['sha256']!=BASE_HASH or type(staged['size'])is not int or staged['size']!=BASE_SIZE or staged['ownerMatches']is not True:raise ValueError('refresh-staged-bytes')
    if not isinstance(staged['identity'],str)or not 0<len(staged['identity'])<=256 or re.fullmatch(r'[0-9]+(?::[0-9]+){10}',staged['identity'])is None:raise ValueError('refresh-staged-identity')
    for name in ('productCode','upgradeCode'):
        if not isinstance(staged[name],str)or re.fullmatch(GUID,staged[name])is None:raise ValueError('refresh-msi-product')
    if staged['productVersion']!='2.1.19' or staged['allUsers']not in (None,'','1','2')or staged['perUser']not in(None,'','0','1'):raise ValueError('refresh-msi-scope')
    return value

def parse_terminal(value,nonce,sha,pid):
    if value.get('exited')is not True:return None
    if value.get('out-truncated')or value.get('err-truncated'):raise ValueError('refresh-truncated')
    raw=base64.b64decode(value.get('out-data',''),validate=True)
    if len(raw)>32768:raise ValueError('refresh-output-cap')
    header,sep,payload=raw.partition(b'\n')
    if not sep or header.rstrip(b'\r')!=('CP117-READ %s %s %d'%(nonce,sha,pid)).encode():return None
    if type(value.get('exitcode'))is not int or value['exitcode']!=0:raise ValueError('refresh-guest-exit')
    return validate(json.loads(payload))

def setup_plan(value):
    validate(value)
    if value['outcome']!='complete':return {'state':'blocked','reason':'observation','installerAction':False}
    facts=value['facts'];metadata=facts['metadata']
    if any(facts['package'][k]!=v for k,v in OLD_HASHES.items())or not facts['package']['registeredPathMatches'] or facts['readiness']['code']!='READY':raise ValueError('refresh-old-lineage')
    if metadata['staged']is None:return {'state':'needs-stage','installerAction':False,'publicUpdateAcceptance':False}
    stage=metadata['staged']
    if stage['allUsers']not in(None,'','2')or stage['perUser']not in(None,'','1'):raise ValueError('refresh-scope-refused')
    return {'state':'planned','branch':'repair'if metadata['oldProductCode'].upper()==stage['productCode'].upper()else'uninstall-install','installerAction':False,'publicUpdateAcceptance':False}

def program(record,admitted):
    r=installed.precise.owner.guest.recovery;ownpin,ownraw=r.authority._read_bound_file(Path(__file__),retain_bytes=True)
    source,oldsha=installed.program(record,admitted);plain=body(admitted);sha=hashlib.sha256(plain.encode('utf-16le')).hexdigest()
    full="[Console]::Out.WriteLine(('CP117-READ "+NONCE+" "+sha+" '+$PID))\n"+plain
    data=full.encode('utf-8');packed=base64.b64encode(gzip.compress(data,mtime=0)).decode()
    bootstrap="$ErrorActionPreference='Stop';$i=[IO.MemoryStream]::new([Convert]::FromBase64String('"+packed+"'));$z=[IO.Compression.GZipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();try{$b=New-Object byte[] 4096;while(($n=$z.Read($b,0,$b.Length)) -gt 0){$o.Write($b,0,$n);if($o.Length -gt 65536){throw 'PACKAGE_SOURCE_BOUND'}};$v=$o.ToArray();if($v.Length -ne "+str(len(data))+" -or [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($v)).Replace('-','').ToLowerInvariant() -cne '"+hashlib.sha256(data).hexdigest()+"'){throw 'PACKAGE_SOURCE_HASH'};& ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false,$true).GetString($v)))}finally{$z.Dispose();$i.Dispose();$o.Dispose()}"
    encoded=base64.b64encode(bootstrap.encode('utf-16le')).decode()
    if len(data)>65536 or len(encoded)>=30000:raise ValueError('refresh-command-cap')
    tree=ast.parse(source);oldencoded=next(n.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets))
    for old,new in((repr(oldencoded.value),repr(encoded)),('D='+repr(INSTALLED_CORR),'D='+repr(CORRELATION)),('NONCE='+repr(installed.NONCE),'NONCE='+repr(NONCE)),('BODY_SHA='+repr(oldsha),'BODY_SHA='+repr(sha))):
        if source.count(old)!=1:raise ValueError('refresh-carrier-factory')
        source=source.replace(old,new)
    tree=ast.parse(source);definition=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate');old=ast.get_source_segment(source,definition)
    wrapper='import types\nINSTALLED_CORR='+repr(INSTALLED_CORR)+'\nGUID='+repr(GUID)+'\nBASE_HASH='+repr(BASE_HASH)+'\nBASE_SIZE='+repr(BASE_SIZE)+'\n_installed_ns=dict(globals(),CORRELATION=INSTALLED_CORR)\nexec('+repr(old)+',_installed_ns)\ninstalled=types.SimpleNamespace(validate=_installed_ns["validate"])\nCORRELATION='+repr(CORRELATION)+'\n'+_functions(ownraw,('validate',))
    source=source.replace(old,wrapper)
    if r.authority._read_bound_file(Path(__file__))!=ownpin:raise ValueError('refresh-parser-source-drift')
    compile(source,'fixed-refresh-metadata','exec');return source,sha

flow=installed.flow

def observe_metadata(root):
    root=Path(root).resolve(strict=True);r=installed.precise.owner.guest.recovery;leaf='windows-cp117-base-refresh-metadata-'+CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','stage':'consumed','installerAction':False,'replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION);events=[]
    try:
        raw=r._local_read(original,installed.precise.owner.guest.ORIGINAL['name'],installed.precise.owner.guest.ORIGINAL['pin']);record=json.loads(raw);admitted=installed.pair(root)
        paths=(Path(__file__),Path(installed.__file__),Path(installed.precise.__file__),Path(installed.public.__file__),Path(flow.__file__),Path(installed.precise.owner.guest.__file__),Path(r.authority.closure.base.__file__))
        pins={str(p):r.authority._read_bound_file(p)for p in paths};execution=flow._execution_source_proof(root,record);outer=r.authority._outer_authority(root)
        def verify():
            if r._local_read(original,installed.precise.owner.guest.ORIGINAL['name'],installed.precise.owner.guest.ORIGINAL['pin'])!=raw:raise ValueError('refresh-original-drift')
            for i,item in enumerate(record['authority']):
                r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('refresh-original-frame')
            if flow._execution_source_proof(root,record)!=execution or any(r.authority._read_bound_file(Path(p))!=v for p,v in pins.items()):raise ValueError('refresh-source-drift')
            r.authority._verify_outer(root,{'outerAuthority':outer})
            if installed.pair(root)!=admitted:raise ValueError('refresh-artifact-drift')
        verify();source,sha=program(record,admitted)
        capture.create('request.json',json.dumps({'correlationId':CORRELATION,'nonce':NONCE,'sourceSha256':sha,'sources':pins,'pair':admitted,'executionSourceProof':execution,'outerAuthority':outer,'installerAction':False},sort_keys=True).encode());capture.create('remote.py',source.encode());os.fsync(capture.fd)
        config,_,_=r.authority.closure.base._descriptor(root);argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        capture.create('attempt.json',json.dumps({'state':'consumed','correlationId':CORRELATION,'nonce':NONCE}).encode());os.fsync(capture.fd);verify()
        value,events=flow._stream(argv,capture,CORRELATION,NONCE,sha,record['result']['qemu'],None);verify();pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        plan=setup_plan(value['facts'])if value.get('state')=='observed'else {'state':'unknown','installerAction':False}
        return dict(plan,evidenceLeaf=leaf,receipt=pin,replayAllowed=False)
    except Exception as error:
        events.extend(getattr(error,'events',[]));pin=capture.create('unknown.json',json.dumps({'state':'unknown','failureType':type(error).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','installerAction':False,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:original.close();capture.close()

# A separate current-generation upload: no CP135 descriptor substitution and no
# installer launch. Consumed metadata sources remain in their original capsule.
from contextlib import contextmanager
import selectors,stat,subprocess,time
from . import windows_msi_http_transfer as transfer
HOST_STAGE_CORRELATION='a995ae62-2b86-47c1-96d7-9c7723960a62'
HTTP_SHA='eeb8884ac9466e3c55e869da79ab9cd97cc1a19dfed636bb57de24ae2fb51d04'
HTTP_STAGE_SHA='4e407658fe2a1a11f6187668db5ba35ec9801afa5a3127991c6d33049ac397b4'
FIXTURE_ROOT='/home/kardinal/.vpn-control-mcp-fixtures'
METADATA_PIN={'generation':[16777234,112861660,33152,503,20,1,11307,1791156568533599187,1791156568533599187],'sha256':'af37a5a6c4ba19c84b0c6ab67fe15a312a4ec6c1ab2d8b1c1f64a43e26a09163'}

def stage_program(record,observation='upload'):
    if observation not in ('upload','limits'):raise ValueError('fixed-host-stage-catalog')
    r=installed.precise.owner.guest.recovery;bound=r.authority._read_bound_file
    helperpin,_=bound(Path(__file__),retain_bytes=True);http=bound(Path(transfer.__file__))
    if http['sha256']!=HTTP_SHA or hashlib.sha256(transfer._REMOTE_STAGE.encode()).hexdigest()!=HTTP_STAGE_SHA:raise ValueError('refresh-transfer-source')
    source,_=installed.program(record,PAIR_EXPECTED)
    marker=" guards();child=call(LEAF+'/qga.sock','guest-exec'"
    if source.count(marker)!=1:raise ValueError('refresh-transfer-guard-factory')
    prefix=source[:source.index(marker)]
    qemu=record['result']['qemu'];args=(FIXTURE_ROOT,'windows-cp117',HOST_STAGE_CORRELATION,PAIR_EXPECTED['sourceSha'],PAIR_EXPECTED['baseArtifactId'],r.recipe()['leaf']+'/qga.sock',str(qemu['pid']),str(qemu['startTicks']),installed.precise.owner.SID,BASE_HASH,str(BASE_SIZE))
    # Keep the complete original boot/held-child/disk/socket/anchor admission.
    # The transfer body executes in its own namespace, so its os/root/stage
    # locals cannot replace the original guard's authority observations.
    operation=" guards()\n import resource\n _soft,_hard=resource.getrlimit(resource.RLIMIT_FSIZE)\n print('CP117-FILE-LIMIT '+json.dumps({'soft':_soft,'hard':_hard,'requiredBytes':"+str(BASE_SIZE)+"},sort_keys=True),file=sys.stderr,flush=True)\n need(_soft==resource.RLIM_INFINITY or _soft>="+str(BASE_SIZE)+",'host-file-size-limit')\n _transfer_scope={'__builtins__':__builtins__}\n _old_argv=sys.argv\n try:\n  sys.argv=['fixed-base-host-stage']+"+repr(list(args))+"\n  exec("+repr(transfer._REMOTE_STAGE)+",_transfer_scope)\n finally:sys.argv=_old_argv\n guards()\nexcept Exception as error:\n result({'state':'unknown','failureType':type(error).__name__,'installerAction':False,'replayAllowed':False})\n"
    if observation=='limits':
        operation=" guards()\n import resource\n _soft,_hard=resource.getrlimit(resource.RLIMIT_FSIZE)\n guards()\n result({'state':'limits','soft':_soft,'hard':_hard})\nexcept Exception as error:\n result({'state':'unknown','failureType':type(error).__name__,'installerAction':False,'replayAllowed':False})\n"
    source=prefix+operation
    if bound(Path(__file__))!=helperpin or bound(Path(transfer.__file__))!=http:raise ValueError('refresh-transfer-source-drift')
    compile(source,'fixed-current-base-upload','exec');return source,args

@contextmanager
def _held_msi(path):
    path=Path(path).absolute();parents=[]
    for parent in path.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode):raise ValueError('msi-ancestry')
        parents.append((parent,(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    stream=os.fdopen(fd,'rb')
    try:
        generation=lambda v:[v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns]
        first=os.fstat(fd);pin=generation(first)
        if not stat.S_ISREG(first.st_mode)or first.st_uid!=os.getuid()or first.st_nlink!=1 or first.st_size!=BASE_SIZE:raise ValueError('msi-record')
        digest=hashlib.sha256()
        for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
        if digest.hexdigest()!=BASE_HASH:raise ValueError('msi-hash')
        def verify():
            if generation(os.fstat(fd))!=pin or generation(path.lstat())!=pin:raise ValueError('msi-generation')
            for parent,identity in parents:
                now=parent.lstat()
                if(now.st_dev,now.st_ino,now.st_mode,now.st_uid,now.st_gid)!=identity:raise ValueError('msi-ancestry')
            if generation(os.fstat(fd))!=pin or generation(path.lstat())!=pin:raise ValueError('msi-generation')
        verify();stream.seek(0);yield stream,{'sha256':BASE_HASH,'generation':pin},verify;verify()
    finally:stream.close()

def _upload(argv,stream,capture,guard):
    """One fixed upload transport; retain bounded raw even on lost observation."""
    guard();process=subprocess.Popen(argv,stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector();chunks={'stdout':bytearray(),'stderr':bytearray()};deadline=time.monotonic()+60
    selector.register(process.stdout,selectors.EVENT_READ,'stdout');selector.register(process.stderr,selectors.EVENT_READ,'stderr')
    retention_attempted=False
    def retain():
        nonlocal retention_attempted
        if retention_attempted:return
        retention_attempted=True
        for name,raw in chunks.items():capture.create(name+'.bin',bytes(raw[:262144]))
        capture.create('exit.json',json.dumps({'returncode':process.poll(),'pipesClosed':not bool(selector.get_map())},sort_keys=True).encode())
        os.fsync(capture.fd)
    try:
        while selector.get_map():
            if time.monotonic()>=deadline:raise ValueError('host-stage-deadline')
            for key,_ in selector.select(.25):
                block=os.read(key.fileobj.fileno(),4096)
                if not block:selector.unregister(key.fileobj);continue
                chunks[key.data].extend(block)
                if len(chunks[key.data])>262144:raise ValueError('host-stage-output-cap')
        code=process.wait(timeout=max(.001,deadline-time.monotonic()))
        retain() # Complete bounded stdout/stderr/exit is durable BEFORE any decode.
        if code!=0:raise ValueError('host-stage-transport-exit')
        guard();return json.loads(chunks['stdout'])
    except BaseException:
        if process.poll()is None:process.kill() # This held local SSH caller only.
        process.wait(timeout=3);raise
    finally:
        retain();selector.close();process.stdout.close();process.stderr.close()

def stage_host(root):
    root=Path(root).resolve(strict=True);r=installed.precise.owner.guest.recovery;leaf='windows-cp117-base-refresh-host-stage-'+HOST_STAGE_CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','stage':'consumed','installerAction':False,'replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION);metadata=AuthorityCapture(root,'windows-cp117-base-refresh-metadata-'+CORRELATION)
    (root/'.runtime/parity-evidence'/(leaf+'-limits')).mkdir(mode=0o700);limits_capture=AuthorityCapture(root,leaf+'-limits')
    try:
        originalraw=r._local_read(original,installed.precise.owner.guest.ORIGINAL['name'],installed.precise.owner.guest.ORIGINAL['pin']);record=json.loads(originalraw)
        metaraw=r._local_read(metadata,'result.json',METADATA_PIN);previous=json.loads(metaraw)
        if previous['result']['state']!='observed'or setup_plan(previous['result']['facts'])['state']!='needs-stage':raise ValueError('refresh-prior-metadata')
        admitted=installed.pair(root);artifact=installed.public._verified_location(root,PAIR_EXPECTED['baseArtifactId'],'desktop-package',PAIR_EXPECTED['sourceSha'])
        paths=(Path(__file__),Path(transfer.__file__),Path(installed.__file__),Path(installed.precise.__file__),Path(installed.public.__file__),Path(flow.__file__),Path(installed.precise.owner.guest.__file__),Path(r.authority.closure.base.__file__))
        pins={str(p):r.authority._read_bound_file(p)for p in paths};execution=flow._execution_source_proof(root,record);outer=r.authority._outer_authority(root)
        def verify():
            if r._local_read(original,installed.precise.owner.guest.ORIGINAL['name'],installed.precise.owner.guest.ORIGINAL['pin'])!=originalraw or r._local_read(metadata,'result.json',METADATA_PIN)!=metaraw:raise ValueError('refresh-stage-history-drift')
            for i,item in enumerate(record['authority']):
                r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('refresh-stage-original-frame')
            if flow._execution_source_proof(root,record)!=execution or any(r.authority._read_bound_file(Path(p))!=v for p,v in pins.items()):raise ValueError('refresh-stage-source-drift')
            r.authority._verify_outer(root,{'outerAuthority':outer})
            if installed.pair(root)!=admitted or installed.public._verified_location(root,PAIR_EXPECTED['baseArtifactId'],'desktop-package',PAIR_EXPECTED['sourceSha'])!=artifact:raise ValueError('refresh-stage-artifact-drift')
        verify();source,args=stage_program(record)
        with _held_msi(artifact)as(stream,artifactpin,fileguard):
            def guard():verify();fileguard()
            capture.create('request.json',json.dumps({'correlationId':HOST_STAGE_CORRELATION,'metadata':METADATA_PIN,'artifact':artifactpin,'sources':pins,'executionSourceProof':execution,'outerAuthority':outer,'args':args,'installerAction':False},sort_keys=True).encode());capture.create('remote.py',source.encode());os.fsync(capture.fd)
            config,_,_=r.authority.closure.base._descriptor(root);argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
            limits_source,_=stage_program(record,'limits');limits_capture.create('remote.py',limits_source.encode());os.fsync(limits_capture.fd)
            limits_argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(limits_source))
            limits=_upload(limits_argv,subprocess.DEVNULL,limits_capture,guard);admit_file_limit(limits)
            capture.create('file-limit.json',json.dumps(limits,sort_keys=True).encode());os.fsync(capture.fd)
            capture.create('attempt.json',json.dumps({'state':'consumed','correlationId':HOST_STAGE_CORRELATION}).encode());os.fsync(capture.fd);guard()
            value=_upload(argv,stream,capture,guard)
            if value!={'state':'staged','sha256':BASE_HASH,'length':BASE_SIZE}or type(value.get('length'))is not int:raise ValueError('refresh-stage-result')
            pin=capture.create('result.json',json.dumps({'result':value,'artifact':artifactpin},sort_keys=True).encode());os.fsync(capture.fd)
            return {'state':'host-staged','correlationId':HOST_STAGE_CORRELATION,'evidenceLeaf':leaf,'receipt':pin,'installerAction':False,'replayAllowed':False}
    except Exception as error:
        pin=capture.create('unknown.json',json.dumps({'state':'unknown','failureType':type(error).__name__},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','evidenceLeaf':leaf,'receipt':pin,'installerAction':False,'replayAllowed':False}
    finally:limits_capture.close();metadata.close();original.close();capture.close()


def admit_file_limit(value):
    if not isinstance(value,dict)or set(value)!={'state','soft','hard'}or value['state']!='limits'or any(type(value[k])is not int or not -1<=value[k]<=2**63-1 for k in('soft','hard')):raise ValueError('host-file-limit-schema')
    if value['soft']!=-1 and value['soft']<BASE_SIZE:raise ValueError('host-file-size-limit')
    if value['hard']!=-1 and(value['soft']==-1 or value['soft']>value['hard']):raise ValueError('host-file-limit-order')
    return value

# Current-generation listener and one ordinary-user task submission. This is
# fixture staging only; downloaded bytes require a separate held-file census.
DOWNLOAD_CORRELATION='f35d9a16-2bc7-45e4-9b31-37218f0b2d47'
DOWNLOAD_NONCE='30bdb27a-597f-455e-953a-9b7d753644ba'
ROUTE_PATH='/a995ae622b8647c196d79c7723960a62539504d6'
HOST_STAGE_PIN={'generation':[16777234,112876226,33152,503,20,1,331,1791160521054227458,1791160521054227458],'sha256':'a6a5019c582f17fa0da989cc392a41fbbc97bb19bb9e840374254ef7437c52f9'}
LISTENER_SHA='04a1e060e92c1cd5816e0ee0a8d6e38b3f437334561742026d6a161870d4b269'
DOWNLOAD_PS_SHA='42919e53992b7bdad54b6f3a874abae559bb5065b13903d1d175206d9de3ebf1'
DOWNLOAD_REMOTE_SHA='8da39cfa35dc300fcf9e2ae837abb543445214371f7ed8132776585136791316'

def listener_program(record):
    r=installed.precise.owner.guest.recovery;bound=r.authority._read_bound_file
    pin=bound(Path(transfer.__file__))
    if pin['sha256']!=HTTP_SHA or hashlib.sha256(transfer._REMOTE_LISTEN_START.encode()).hexdigest()!=LISTENER_SHA:raise ValueError('refresh-listener-source')
    source,args=stage_program(record,'limits');marker=' guards()\n import resource\n'
    if source.count(marker)!=1:raise ValueError('refresh-listener-factory')
    prefix=source[:source.index(marker)]
    # The original listener retains its own worker PID/start and path fence.
    tail=" guards()\n _scope={'__builtins__':__builtins__}\n _old_argv=sys.argv\n try:\n  sys.argv=['fixed-current-listener']+"+repr(list(args))+"\n  exec("+repr(transfer._REMOTE_LISTEN_START)+",_scope)\n finally:sys.argv=_old_argv\n guards()\nexcept Exception as error:\n result({'state':'unknown','failureType':type(error).__name__})\n"
    if bound(Path(transfer.__file__))!=pin:raise ValueError('refresh-listener-drift')
    source=prefix+tail;compile(source,'fixed-current-listener','exec');return source

def admit_listener(value):
    if not isinstance(value,dict)or set(value)!={'state','port','path'}or value['state']!='listening'or value['path']!=ROUTE_PATH or type(value['port'])is not int or not 1<=value['port']<=65535:raise ValueError('refresh-listener-result')
    return value

def download_body(port):
    if type(port)is not int or not 1<=port<=65535:raise ValueError('refresh-download-port')
    bound=installed.precise.owner.guest.recovery.authority._read_bound_file
    pin=bound(Path(transfer.__file__))
    if pin['sha256']!=HTTP_SHA or hashlib.sha256(transfer._GUEST_DOWNLOAD_PS.encode()).hexdigest()!=DOWNLOAD_PS_SHA or hashlib.sha256(transfer._REMOTE_GUEST_DOWNLOAD.encode()).hexdigest()!=DOWNLOAD_REMOTE_SHA:raise ValueError('refresh-download-source')
    script=transfer._GUEST_DOWNLOAD_PS
    for key,value in(('SID',installed.precise.owner.SID),('CORR',HOST_STAGE_CORRELATION),('DIGEST',BASE_HASH),('SIZE',str(BASE_SIZE)),('PORT',str(port)),('PATH',ROUTE_PATH[1:])):script=script.replace('@'+key+'@',value)
    encoded=base64.b64encode(script.encode('utf-16le')).decode()
    if len(encoded)>30000:raise ValueError('refresh-download-action-cap')
    tree=ast.parse(transfer._REMOTE_GUEST_DOWNLOAD)
    expression=next(n.value for n in ast.walk(tree)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='bootstrap'for t in n.targets))
    # Evaluate only the pinned original fixed bootstrap expression. No live,
    # old-generation admission or unbound QGA dispatch is imported from it.
    bootstrap=eval(compile(ast.Expression(expression),'fixed-download-bootstrap','eval'),{'__builtins__':{}},{'task':'VpnControlMcpTransfer-'+HOST_STAGE_CORRELATION,'sid':installed.precise.owner.SID,'encoded':encoded})
    output=";[Console]::Out.WriteLine('{\"state\":\"submitted\"}')"
    if not bootstrap.endswith(output):raise ValueError('refresh-download-bootstrap-output')
    bootstrap=bootstrap[:-len(output)]
    argument="-Argument ('-NoProfile -NonInteractive -EncodedCommand "+encoded+"')"
    if bootstrap.count(argument)!=1:raise ValueError('refresh-download-action-factory')
    # Reconstruct the exact unchanged action's UTF16 encoding at runtime. The
    # outer complete-source hash protects these UTF8 bytes and avoids bloating
    # the command with a second UTF16/base64 representation.
    if not script.endswith('\n') or "\n'@" in script:raise ValueError('refresh-download-action-literal')
    action="$cp117ActionSource=@'\n"+script[:-1]+"\n'@\n$cp117ActionSource += [char]10;$cp117ActionBytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($cp117ActionSource);if([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($cp117ActionBytes)).Replace('-','').ToLowerInvariant() -cne '"+hashlib.sha256(script.encode()).hexdigest()+"'){throw 'DOWNLOAD_ACTION_SOURCE'};$cp117ActionEncoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cp117ActionSource));\n"
    bootstrap=action+bootstrap.replace(argument,"-Argument ('-NoProfile -NonInteractive -EncodedCommand '+$cp117ActionEncoded)")
    plain=installed.body(PAIR_EXPECTED)
    marker="[Console]::Out.WriteLine((@{version=1;correlationId='"+INSTALLED_CORR+"';outcome='complete'"
    if plain.count(marker)!=1:raise ValueError('refresh-download-owner-factory')
    at=plain.index(marker)
    checks="if($cp117ReadinessProof.code -cne 'READY'){throw 'PACKAGE_DRIFT'}\n"
    for name,value in OLD_HASHES.items():checks+="if($cp117Package."+name+" -cne '"+value+"'){throw 'PACKAGE_DRIFT'}\n"
    plain=plain[:at]+checks+bootstrap+"\n$cp117Download=@{state='submitted';taskArgumentsSha256='"+hashlib.sha256(('-NoProfile -NonInteractive -EncodedCommand '+encoded).encode()).hexdigest()+"'}\n"+plain[at:]
    plain=plain.replace('package=$cp117Package};details','package=$cp117Package;download=$cp117Download};details').replace(INSTALLED_CORR,DOWNLOAD_CORRELATION)
    if bound(Path(transfer.__file__))!=pin:raise ValueError('refresh-download-source-drift')
    return plain,hashlib.sha256(('-NoProfile -NonInteractive -EncodedCommand '+encoded).encode()).hexdigest()

def validate_download(value):
    if not isinstance(value,dict)or value.get('correlationId')!=DOWNLOAD_CORRELATION:raise ValueError('refresh-download-correlation')
    base=dict(value,correlationId=INSTALLED_CORR)
    if value.get('outcome')=='complete':
        facts=value.get('facts')
        if not isinstance(facts,dict)or set(facts)!={'owner','readiness','package','download'}:raise ValueError('refresh-download-facts')
        mark=facts['download']
        if not isinstance(mark,dict)or set(mark)!={'state','taskArgumentsSha256'}or mark['state']!='submitted'or mark['taskArgumentsSha256']!=TASK_ARGUMENTS_SHA:raise ValueError('refresh-download-task')
        base['facts']={k:facts[k]for k in('owner','readiness','package')}
        if facts['readiness']['code']!='READY'or any(facts['package'][k]!=v for k,v in OLD_HASHES.items()):raise ValueError('refresh-download-old-lineage')
    installed.validate(base);return value

def download_program(record,port):
    r=installed.precise.owner.guest.recovery;pin,raw=r.authority._read_bound_file(Path(__file__),retain_bytes=True)
    source,oldsha=installed.program(record,PAIR_EXPECTED);plain,tasksha=download_body(port);sha=hashlib.sha256(plain.encode('utf-16le')).hexdigest()
    full="[Console]::Out.WriteLine(('CP117-READ "+DOWNLOAD_NONCE+" "+sha+" '+$PID))\n"+plain;data=full.encode();packed=base64.b64encode(gzip.compress(data,mtime=0)).decode()
    bootstrap="$ErrorActionPreference='Stop';$i=[IO.MemoryStream]::new([Convert]::FromBase64String('"+packed+"'));$z=[IO.Compression.GZipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();try{$b=New-Object byte[] 4096;while(($n=$z.Read($b,0,$b.Length)) -gt 0){$o.Write($b,0,$n);if($o.Length -gt 65536){throw 'PACKAGE_SOURCE_BOUND'}};$v=$o.ToArray();if($v.Length -ne "+str(len(data))+" -or [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($v)).Replace('-','').ToLowerInvariant() -cne '"+hashlib.sha256(data).hexdigest()+"'){throw 'PACKAGE_SOURCE_HASH'};& ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false,$true).GetString($v)))}finally{$z.Dispose();$i.Dispose();$o.Dispose()}"
    encoded=base64.b64encode(bootstrap.encode('utf-16le')).decode()
    if len(data)>65536 or len(encoded)>=30000:raise ValueError('refresh-download-command-cap')
    tree=ast.parse(source);oldencoded=next(n.value.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets))
    for before,after in((repr(oldencoded),repr(encoded)),('D='+repr(INSTALLED_CORR),'D='+repr(DOWNLOAD_CORRELATION)),('NONCE='+repr(installed.NONCE),'NONCE='+repr(DOWNLOAD_NONCE)),('BODY_SHA='+repr(oldsha),'BODY_SHA='+repr(sha))):
        if source.count(before)!=1:raise ValueError('refresh-download-carrier-factory')
        source=source.replace(before,after)
    tree=ast.parse(source);definition=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate');old=ast.get_source_segment(source,definition)
    wrapper='INSTALLED_CORR='+repr(INSTALLED_CORR)+'\nOLD_HASHES='+repr(OLD_HASHES)+'\nTASK_ARGUMENTS_SHA='+repr(tasksha)+'\n_download_installed_ns=dict(globals(),CORRELATION=INSTALLED_CORR)\nexec('+repr(old)+',_download_installed_ns)\ninstalled=types.SimpleNamespace(validate=_download_installed_ns["validate"])\nDOWNLOAD_CORRELATION='+repr(DOWNLOAD_CORRELATION)+'\n'+_functions(raw,('validate_download',))+'\nvalidate=validate_download\n'
    source=source.replace(old,wrapper)
    if r.authority._read_bound_file(Path(__file__))!=pin:raise ValueError('refresh-download-parser-drift')
    compile(source,'fixed-current-download','exec');return source,sha,tasksha

def submit_guest_download(root):
    """One listener and one Interactive/Limited task; never installers."""
    import tempfile
    root=Path(root).resolve(strict=True);r=installed.precise.owner.guest.recovery;leaf='windows-cp117-base-refresh-download-'+DOWNLOAD_CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','stage':'consumed','installerAction':False,'replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf)
    original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION);host=AuthorityCapture(root,'windows-cp117-base-refresh-host-stage-'+HOST_STAGE_CORRELATION)
    listener_leaf=leaf+'-listener';(root/'.runtime/parity-evidence'/listener_leaf).mkdir(mode=0o700);listener=AuthorityCapture(root,listener_leaf);events=[]
    try:
        originalraw=r._local_read(original,installed.precise.owner.guest.ORIGINAL['name'],installed.precise.owner.guest.ORIGINAL['pin']);record=json.loads(originalraw)
        hostraw=r._local_read(host,'result.json',HOST_STAGE_PIN);prior=json.loads(hostraw)
        if not isinstance(prior,dict)or set(prior)!={'artifact','result'}or prior['result']!={'state':'staged','sha256':BASE_HASH,'length':BASE_SIZE}or type(prior['result']['length'])is not int:raise ValueError('refresh-download-host-proof')
        admitted=installed.pair(root)
        files=(Path(__file__),Path(transfer.__file__),Path(installed.__file__),Path(installed.precise.__file__),Path(installed.public.__file__),Path(flow.__file__),Path(installed.precise.owner.guest.__file__),Path(r.authority.closure.base.__file__))
        pins={str(p):r.authority._read_bound_file(p)for p in files};execution=flow._execution_source_proof(root,record);outer=r.authority._outer_authority(root)
        def verify():
            if r._local_read(original,installed.precise.owner.guest.ORIGINAL['name'],installed.precise.owner.guest.ORIGINAL['pin'])!=originalraw or r._local_read(host,'result.json',HOST_STAGE_PIN)!=hostraw:raise ValueError('refresh-download-history-drift')
            for i,item in enumerate(record['authority']):
                r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('refresh-download-original-frame')
            if flow._execution_source_proof(root,record)!=execution or any(r.authority._read_bound_file(Path(p))!=v for p,v in pins.items()):raise ValueError('refresh-download-source-drift')
            r.authority._verify_outer(root,{'outerAuthority':outer})
            if installed.pair(root)!=admitted:raise ValueError('refresh-download-artifact-drift')
        verify();listener_source=listener_program(record)
        # Establish all generated composition/caps before the listener effect.
        download_program(record,65535)
        capture.create('request.json',json.dumps({'correlationId':DOWNLOAD_CORRELATION,'nonce':DOWNLOAD_NONCE,'hostStage':HOST_STAGE_PIN,'sources':pins,'executionSourceProof':execution,'outerAuthority':outer,'pair':admitted,'installerAction':False},sort_keys=True).encode())
        listener.create('remote.py',listener_source.encode());listener.create('route.json',json.dumps({'path':ROUTE_PATH},sort_keys=True).encode());os.fsync(listener.fd);os.fsync(capture.fd)
        config,_,_=r.authority.closure.base._descriptor(root)
        def argv(source):return r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        listener.create('attempt.json',json.dumps({'state':'consumed','correlationId':DOWNLOAD_CORRELATION,'hostCorrelationId':HOST_STAGE_CORRELATION},sort_keys=True).encode());os.fsync(listener.fd);verify()
        with tempfile.TemporaryFile(mode='w+b')as route:
            route.write(json.dumps({'path':ROUTE_PATH},sort_keys=True).encode());route.flush();os.fsync(route.fileno());route.seek(0)
            ready=admit_listener(_upload(argv(listener_source),route,listener,verify))
        listener.create('result.json',json.dumps(ready,sort_keys=True).encode());os.fsync(listener.fd)
        source,sha,tasksha=download_program(record,ready['port'])
        capture.create('remote.py',source.encode());capture.create('submission.json',json.dumps({'sourceSha256':sha,'taskArgumentsSha256':tasksha,'port':ready['port'],'pathSha256':hashlib.sha256(ROUTE_PATH.encode()).hexdigest(),'guestPath':r'C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-'+HOST_STAGE_CORRELATION+r'\base.msi'},sort_keys=True).encode());os.fsync(capture.fd)
        capture.create('attempt.json',json.dumps({'state':'consumed','correlationId':DOWNLOAD_CORRELATION,'nonce':DOWNLOAD_NONCE},sort_keys=True).encode());os.fsync(capture.fd);verify()
        value,events=flow._stream(argv(source),capture,DOWNLOAD_CORRELATION,DOWNLOAD_NONCE,sha,record['result']['qemu'],None);verify()
        pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        if value.get('state')!='observed'or value['facts']['outcome']!='complete':return {'state':'unknown','stage':'guest-submission','evidenceLeaf':leaf,'receipt':pin,'installerAction':False,'replayAllowed':False}
        return {'state':'guest-download-submitted','evidenceLeaf':leaf,'receipt':pin,'installerAction':False,'downloadedBytesProven':False,'replayAllowed':False}
    except Exception as error:
        events.extend(getattr(error,'events',[]));pin=capture.create('unknown.json',json.dumps({'state':'unknown','failureType':type(error).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','evidenceLeaf':leaf,'receipt':pin,'installerAction':False,'replayAllowed':False}
    finally:listener.close();host.close();original.close();capture.close()

CENSUS_CORRELATION='e84df90c-e115-4dfc-9932-688f569edbfd'
CENSUS_NONCE='a9d956a3-3a62-4d11-b27e-4581eff7d9b1'
DOWNLOAD_RESULT_PIN={'generation':[16777234,112885392,33152,503,20,1,19077,1791163848032030807,1791163848032030807],'sha256':'fc1c91ccb70f240efc03d413dc83f4b395aa8e2708fb449592871aaa88faf687'}
SUBMISSION_PIN={'generation':[16777234,112885372,33152,503,20,1,393,1791163842925852142,1791163842925852142],'sha256':'66341618fcb96435deb36e5a26d942ed25f9fd6dbda90090f2a725e4c10efb9f'}
SUBMITTED_PORT=59871
SUBMITTED_ACTION_SHA='c4cb3f6905c2950b954e52ec5cea333e58b3358a0fca259969b34dbe01207e56'
LISTENER_STATUS_SHA='769a04587138accaec244607d8a1411a2ce54e576935faf5dc62b5427ac25ed3'
DOWNLOADED_CANDIDATE=r'C:\Users\vpncp117\AppData\Local\VpnControl\mcp-base-'+HOST_STAGE_CORRELATION+r'\base.msi'
TASK_CENSUS_PS=r'''function ReadCp117Task {
 $task=Get-ScheduledTask -TaskPath '\' -TaskName '@TASK@' -ErrorAction Stop
 $user=([string]$task.Principal.UserId);if($user -notmatch '^S-1-'){$user=([Security.Principal.NTAccount]::new($user)).Translate([Security.Principal.SecurityIdentifier]).Value}
 $actions=@($task.Actions)
 if($task.TaskName -cne '@TASK@' -or $task.TaskPath -cne '\' -or $user -cne '@SID@' -or $task.Principal.LogonType -cne 'Interactive' -or $task.Principal.RunLevel -cne 'Limited' -or $actions.Count -ne 1 -or $actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'){throw 'PACKAGE_DRIFT'}
 $hash=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($actions[0].Arguments)))).Replace('-','').ToLowerInvariant()
 if($hash -cne '@ARGS@'){throw 'PACKAGE_DRIFT'}
 $state=$task.State.ToString();if($state -cnotin @('Ready','Running','Disabled','Queued','Unknown')){throw 'PACKAGE_DRIFT'}
 $info=Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop
 return @{state=$state;ownerMatches=$true;logonType='Interactive';runLevel='Limited';actionSha256=$hash;lastRunTicks=$info.LastRunTime.Ticks.ToString();lastTaskResult=[uint32]$info.LastTaskResult}
}
$cp117Task=ReadCp117Task
'''

def listener_status_program(record):
    bound=installed.precise.owner.guest.recovery.authority._read_bound_file;pin=bound(Path(transfer.__file__))
    if pin['sha256']!=HTTP_SHA or hashlib.sha256(transfer._REMOTE_LISTEN_STATUS.encode()).hexdigest()!=LISTENER_STATUS_SHA:raise ValueError('refresh-listener-status-source')
    source,args=stage_program(record,'limits');marker=' guards()\n import resource\n';prefix=source[:source.index(marker)]
    tail=" guards()\n _scope={'__builtins__':__builtins__}\n _old_argv=sys.argv\n try:\n  sys.argv=['fixed-current-listener-status']+"+repr(list(args))+"\n  try:exec("+repr(transfer._REMOTE_LISTEN_STATUS)+",_scope)\n  except SystemExit as _status_exit:\n   if type(_status_exit.code)is not int or _status_exit.code!=0:raise\n finally:sys.argv=_old_argv\n guards()\nexcept Exception as error:\n result({'state':'unknown','failureType':type(error).__name__})\n"
    if bound(Path(transfer.__file__))!=pin:raise ValueError('refresh-listener-status-drift')
    source=prefix+tail;compile(source,'fixed-listener-status','exec');return source

def admit_listener_status(value):
    if not isinstance(value,dict)or value.get('state')not in('stopped','starting','failed','served','listening'):raise ValueError('refresh-listener-status')
    if set(value)=={'state'}and value['state']in('stopped','starting','failed'):return value
    if set(value)!={'state','port','pathSha256'}or value['state']not in('served','stopped','listening')or type(value['port'])is not int or value['port']!=SUBMITTED_PORT or value['pathSha256']!=hashlib.sha256(ROUTE_PATH.encode()).hexdigest():raise ValueError('refresh-listener-status-binding')
    return value

def census_body():
    if download_body(SUBMITTED_PORT)[1]!=SUBMITTED_ACTION_SHA:raise ValueError('refresh-census-action-source')
    plain=body(PAIR_EXPECTED)
    marker='$oldCode=$products[0].PSChildName.ToUpperInvariant();'
    if plain.count(marker)!=1:raise ValueError('refresh-census-factory')
    task=TASK_CENSUS_PS.replace('@TASK@','VpnControlMcpTransfer-'+HOST_STAGE_CORRELATION).replace('@SID@',installed.precise.owner.SID).replace('@ARGS@',SUBMITTED_ACTION_SHA)
    plain=plain.replace(marker,task+marker).replace(CANDIDATE,DOWNLOADED_CANDIDATE)
    for before,after in(('$view.Execute();','[void]$view.Execute();'),('$view.Close()','[void]$view.Close()')):
        if plain.count(before)!=1:raise ValueError('refresh-census-com-factory')
        plain=plain.replace(before,after)
    output="[Console]::Out.WriteLine((@{version=1;correlationId='"+CORRELATION+"';outcome='complete'"
    if plain.count(output)!=1:raise ValueError('refresh-census-output-factory')
    stable="$cp117TaskAfter=ReadCp117Task;foreach($cp117TaskKey in @('state','ownerMatches','logonType','runLevel','actionSha256','lastRunTicks','lastTaskResult')){if($cp117Task[$cp117TaskKey] -cne $cp117TaskAfter[$cp117TaskKey]){throw 'PACKAGE_DRIFT'}}\n"
    plain=plain.replace(output,stable+output).replace('metadata=$cp117Refresh};details','metadata=$cp117Refresh;task=$cp117Task};details').replace(CORRELATION,CENSUS_CORRELATION)
    return plain

def validate_census(value):
    if not isinstance(value,dict)or value.get('correlationId')!=CENSUS_CORRELATION:raise ValueError('refresh-census-correlation')
    base=dict(value,correlationId=CORRELATION)
    if value.get('outcome')=='complete':
        facts=value.get('facts')
        if not isinstance(facts,dict)or set(facts)!={'owner','readiness','package','metadata','task'}:raise ValueError('refresh-census-facts')
        task=facts['task']
        if not isinstance(task,dict)or set(task)!={'state','ownerMatches','logonType','runLevel','actionSha256','lastRunTicks','lastTaskResult'}or task['state']not in('Ready','Running','Disabled','Queued','Unknown')or task['ownerMatches']is not True or task['logonType']!='Interactive'or task['runLevel']!='Limited'or task['actionSha256']!=SUBMITTED_ACTION_SHA or not isinstance(task['lastRunTicks'],str)or re.fullmatch(r'[0-9]{1,19}',task['lastRunTicks'])is None or int(task['lastRunTicks'])>2**63-1 or type(task['lastTaskResult'])is not int or not 0<=task['lastTaskResult']<=2**32-1:raise ValueError('refresh-census-task')
        base['facts']={k:facts[k]for k in('owner','readiness','package','metadata')}
    validate(base);return value

def census_program(record):
    r=installed.precise.owner.guest.recovery;pin,raw=r.authority._read_bound_file(Path(__file__),retain_bytes=True)
    source,oldsha=program(record,PAIR_EXPECTED);plain=census_body();sha=hashlib.sha256(plain.encode('utf-16le')).hexdigest()
    full="[Console]::Out.WriteLine(('CP117-READ "+CENSUS_NONCE+" "+sha+" '+$PID))\n"+plain;data=full.encode();packed=base64.b64encode(gzip.compress(data,mtime=0)).decode()
    bootstrap="$ErrorActionPreference='Stop';$i=[IO.MemoryStream]::new([Convert]::FromBase64String('"+packed+"'));$z=[IO.Compression.GZipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();try{$b=New-Object byte[] 4096;while(($n=$z.Read($b,0,$b.Length)) -gt 0){$o.Write($b,0,$n);if($o.Length -gt 65536){throw 'PACKAGE_SOURCE_BOUND'}};$v=$o.ToArray();if($v.Length -ne "+str(len(data))+" -or [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($v)).Replace('-','').ToLowerInvariant() -cne '"+hashlib.sha256(data).hexdigest()+"'){throw 'PACKAGE_SOURCE_HASH'};& ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false,$true).GetString($v)))}finally{$z.Dispose();$i.Dispose();$o.Dispose()}"
    encoded=base64.b64encode(bootstrap.encode('utf-16le')).decode()
    if len(data)>65536 or len(encoded)>=30000:raise ValueError('refresh-census-command-cap')
    tree=ast.parse(source);oldencoded=next(n.value.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets))
    for before,after in((repr(oldencoded),repr(encoded)),('D='+repr(CORRELATION),'D='+repr(CENSUS_CORRELATION)),('NONCE='+repr(NONCE),'NONCE='+repr(CENSUS_NONCE)),('BODY_SHA='+repr(oldsha),'BODY_SHA='+repr(sha))):
        if source.count(before)!=1:raise ValueError('refresh-census-carrier-factory')
        source=source.replace(before,after)
    tree=ast.parse(source);definition=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate');old=ast.get_source_segment(source,definition)
    wrapper='_metadata_ns=dict(globals(),CORRELATION='+repr(CORRELATION)+')\nexec('+repr(old)+',_metadata_ns)\n_metadata_validate=_metadata_ns["validate"]\nSUBMITTED_ACTION_SHA='+repr(SUBMITTED_ACTION_SHA)+'\nCENSUS_CORRELATION='+repr(CENSUS_CORRELATION)+'\n'+_functions(raw,('validate_census',))+'\nvalidate=validate_census\n'
    wrapper=wrapper.replace('    validate(base);return value','    _metadata_validate(base);return value')
    source=source.replace(old,wrapper)
    if r.authority._read_bound_file(Path(__file__))!=pin:raise ValueError('refresh-census-parser-drift')
    compile(source,'fixed-current-staging-census','exec');return source,sha

def census_summary(value,listener):
    validate_census(value);admit_listener_status(listener)
    if value['outcome']!='complete':return {'state':'blocked','installerAction':False}
    task=value['facts']['task'];base=dict(value,correlationId=CORRELATION,facts={k:value['facts'][k]for k in('owner','readiness','package','metadata')})
    plan=setup_plan(base)
    return {'state':'observed','downloadedBytesProven':value['facts']['metadata']['staged']is not None,'taskStopped':task['state']=='Ready','taskExitZero':task['lastTaskResult']==0,'listenerState':listener['state'],'setupBranch':plan.get('branch'),'installerAction':False,'publicUpdateAcceptance':False}

def observe_downloaded(root):
    root=Path(root).resolve(strict=True);r=installed.precise.owner.guest.recovery;leaf='windows-cp117-base-refresh-staging-census-'+CENSUS_CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','stage':'consumed','installerAction':False,'replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf)
    original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION);prior=AuthorityCapture(root,'windows-cp117-base-refresh-download-'+DOWNLOAD_CORRELATION)
    listener_leaf=leaf+'-listener';(root/'.runtime/parity-evidence'/listener_leaf).mkdir(mode=0o700);listener=AuthorityCapture(root,listener_leaf);events=[]
    try:
        originalraw=r._local_read(original,installed.precise.owner.guest.ORIGINAL['name'],installed.precise.owner.guest.ORIGINAL['pin']);record=json.loads(originalraw)
        priorraw=r._local_read(prior,'result.json',DOWNLOAD_RESULT_PIN);submittedraw=r._local_read(prior,'submission.json',SUBMISSION_PIN)
        previous=json.loads(priorraw);submitted=json.loads(submittedraw)
        if previous['result']['state']!='observed'or previous['result']['facts']['outcome']!='complete'or previous['result']['facts']['facts']['download']!={'state':'submitted','taskArgumentsSha256':SUBMITTED_ACTION_SHA}:raise ValueError('refresh-census-prior-proof')
        if submitted['port']!=SUBMITTED_PORT or type(submitted['port'])is not int or submitted['taskArgumentsSha256']!=SUBMITTED_ACTION_SHA or submitted['guestPath']!=DOWNLOADED_CANDIDATE or submitted['pathSha256']!=hashlib.sha256(ROUTE_PATH.encode()).hexdigest():raise ValueError('refresh-census-submission-binding')
        admitted=installed.pair(root);files=(Path(__file__),Path(transfer.__file__),Path(installed.__file__),Path(installed.precise.__file__),Path(installed.public.__file__),Path(flow.__file__),Path(installed.precise.owner.guest.__file__),Path(r.authority.closure.base.__file__))
        pins={str(p):r.authority._read_bound_file(p)for p in files};execution=flow._execution_source_proof(root,record);outer=r.authority._outer_authority(root)
        def verify():
            if r._local_read(original,installed.precise.owner.guest.ORIGINAL['name'],installed.precise.owner.guest.ORIGINAL['pin'])!=originalraw or r._local_read(prior,'result.json',DOWNLOAD_RESULT_PIN)!=priorraw or r._local_read(prior,'submission.json',SUBMISSION_PIN)!=submittedraw:raise ValueError('refresh-census-history-drift')
            for i,item in enumerate(record['authority']):
                r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('refresh-census-original-frame')
            if flow._execution_source_proof(root,record)!=execution or any(r.authority._read_bound_file(Path(p))!=v for p,v in pins.items()):raise ValueError('refresh-census-source-drift')
            r.authority._verify_outer(root,{'outerAuthority':outer})
            if installed.pair(root)!=admitted:raise ValueError('refresh-census-artifact-drift')
        verify();source,sha=census_program(record);listener_source=listener_status_program(record)
        capture.create('request.json',json.dumps({'correlationId':CENSUS_CORRELATION,'nonce':CENSUS_NONCE,'priorResult':DOWNLOAD_RESULT_PIN,'submission':SUBMISSION_PIN,'sources':pins,'executionSourceProof':execution,'outerAuthority':outer,'pair':admitted,'installerAction':False},sort_keys=True).encode());capture.create('remote.py',source.encode());listener.create('remote.py',listener_source.encode());os.fsync(capture.fd);os.fsync(listener.fd)
        config,_,_=r.authority.closure.base._descriptor(root)
        def argv(script):return r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(script))
        listener.create('attempt.json',json.dumps({'state':'consumed','correlationId':CENSUS_CORRELATION}).encode());os.fsync(listener.fd);verify()
        status=admit_listener_status(_upload(argv(listener_source),subprocess.DEVNULL,listener,verify));listenerpin=listener.create('result.json',json.dumps(status,sort_keys=True).encode());os.fsync(listener.fd)
        capture.create('attempt.json',json.dumps({'state':'consumed','correlationId':CENSUS_CORRELATION,'nonce':CENSUS_NONCE}).encode());os.fsync(capture.fd);verify()
        value,events=flow._stream(argv(source),capture,CENSUS_CORRELATION,CENSUS_NONCE,sha,record['result']['qemu'],None);verify()
        pin=capture.create('result.json',json.dumps({'result':value,'events':events,'listener':status,'listenerReceipt':listenerpin},sort_keys=True).encode());os.fsync(capture.fd)
        summary=census_summary(value['facts'],status)if value.get('state')=='observed'else{'state':'unknown','installerAction':False}
        return dict(summary,evidenceLeaf=leaf,receipt=pin,replayAllowed=False)
    except Exception as error:
        events.extend(getattr(error,'events',[]));pin=capture.create('unknown.json',json.dumps({'state':'unknown','failureType':type(error).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','evidenceLeaf':leaf,'receipt':pin,'installerAction':False,'replayAllowed':False}
    finally:listener.close();prior.close();original.close();capture.close()

# Explicit same-version source refresh is fixture setup, never update admission.
# These actions are fixed to the positively observed original ProductCode and
# current owned staging file. The general base version gate is untouched.
REPAIR_CORRELATION='caf8dbc4-3764-4b9f-8a15-dc77fe6d9f9b'
REPAIR_NONCE='48a77814-e777-4a79-a53a-bbcfdde21cde'
REPAIR_PRODUCT='{CFCB6A78-7F8F-31FD-8B20-C1977A677578}'
REPAIR_UPGRADE='{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}'
REPAIR_MSI_IDENTITY='3996455293:1441792:98853:664289174:31282281:0:131101044:32:655066335:31282281:1'
REPAIR_ACTION_SHA='36dc5483b09db95d627dcf5f7f5ffedbdfaf562c9b160d13def750c5ffacd8c0'
CENSUS_RESULT_PIN={'sha256':'6142d15ba0371daf43a84177668366c05f2c8b6f8e813242caa59f52c5c842ee','generation':[16777234,112909969,33152,503,20,1,20021,1791166047715422305,1791166047715422305]}
REPAIR_ROOT=r'C:\Users\vpncp117\AppData\Local\VpnControl\mcp-refresh-'+REPAIR_CORRELATION
WORKSPACE_ROOT=r'C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state'

WORKSPACE_CS=r'''using System;using System.IO;using System.Text;using System.Collections.Generic;using System.Security.AccessControl;using System.Runtime.InteropServices;
public static class Cp117RefreshWorkspace {
 [StructLayout(LayoutKind.Sequential)]public struct Info{public uint Attr,CH,CL,AH,AL,WH,WL,Volume,SizeHigh,SizeLow,Links,IdHigh,IdLow;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr sa,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(IntPtr h,out Info i);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateDirectory(string p,IntPtr sa);
 public static void CreateExclusive(string p){if(!CreateDirectory(p,IntPtr.Zero))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());}
 public static Microsoft.Win32.SafeHandles.SafeFileHandle HoldDirectory(string p){if((File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("DIRECTORY_REPARSE");var h=CreateFile(p,0x80,3,IntPtr.Zero,3,0x02000000,IntPtr.Zero);if(h.IsInvalid){h.Dispose();throw new IOException("DIRECTORY_HOLD");}return h;}
 static string DirPin(string p){using(var h=CreateFile(p,0x80,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero)){Info i;if(h.IsInvalid||!GetFileInformationByHandle(h.DangerousGetHandle(),out i))throw new IOException("WORKSPACE_IDENTITY");return i.Volume+":"+i.IdHigh+":"+i.IdLow+":"+i.Attr+":"+i.CH+":"+i.CL+":"+i.WH+":"+i.WL;}}
 static string FilePin(FileStream f){Info i;if(!GetFileInformationByHandle(f.SafeFileHandle.DangerousGetHandle(),out i)||i.Links!=1)throw new IOException("WORKSPACE_FILE_IDENTITY");return i.Volume+":"+i.IdHigh+":"+i.IdLow+":"+i.Attr+":"+i.CH+":"+i.CL+":"+i.WH+":"+i.WL+":"+i.SizeHigh+":"+i.SizeLow+":"+i.Links;}
 static string FileRow(string p,long expected){using(var f=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.Read)){if(f.Length!=expected)throw new IOException("WORKSPACE_SIZE_DRIFT");string pin=FilePin(f);string hash;using(var h=System.Security.Cryptography.SHA256.Create())hash=BitConverter.ToString(h.ComputeHash(f)).Replace("-","");if(pin!=FilePin(f))throw new IOException("WORKSPACE_FILE_DRIFT");using(var named=new FileStream(p,FileMode.Open,FileAccess.Read,FileShare.Read)){if(pin!=FilePin(named))throw new IOException("WORKSPACE_FILE_EXCHANGED");}return pin+"|"+hash+"|"+File.GetAccessControl(p).GetSecurityDescriptorSddlForm(AccessControlSections.All);}}
 static void Budget(string relative,long n,ref long normal,ref long retained,HashSet<string> seen){
  if(n<0)throw new IOException("WORKSPACE_BYTES");
  long expected=relative==@"\updates\vpn-control-2.1.16.msi"?131055988:relative==@"\updates\vpn-control-2.1.18.msi"?131060084:0;
  if(expected!=0){if(n!=expected||!seen.Add(relative))throw new IOException("WORKSPACE_RETAINED");retained+=n;if(retained>262116072)throw new IOException("WORKSPACE_RETAINED");}
  else{normal+=n;if(n>67108864||normal>134217728)throw new IOException("WORKSPACE_BYTES");}
 }
 public static string Snapshot(string root){var items=new List<string>();var pending=new Queue<string>();pending.Enqueue(root);long normal=0,retained=0;var seen=new HashSet<string>(StringComparer.Ordinal);var result=new StringBuilder();int count=0;
  while(pending.Count!=0){string dir=pending.Dequeue();if((File.GetAttributes(dir)&FileAttributes.ReparsePoint)!=0)throw new IOException("WORKSPACE_REPARSE");string before=DirPin(dir);string acl=Directory.GetAccessControl(dir).GetSecurityDescriptorSddlForm(AccessControlSections.All);items.Add("D|"+dir.Substring(root.Length)+"|"+before+"|"+acl);
   string[] children=Directory.GetFileSystemEntries(dir);Array.Sort(children,StringComparer.Ordinal);foreach(string p in children){if(++count>4096)throw new IOException("WORKSPACE_COUNT");FileAttributes attr=File.GetAttributes(p);if((attr&FileAttributes.ReparsePoint)!=0)throw new IOException("WORKSPACE_REPARSE");if((attr&FileAttributes.Directory)!=0){pending.Enqueue(p);continue;}long n=new FileInfo(p).Length;Budget(p.Substring(root.Length),n,ref normal,ref retained,seen);items.Add("F|"+p.Substring(root.Length)+"|"+FileRow(p,n));}
   if(before!=DirPin(dir)||acl!=Directory.GetAccessControl(dir).GetSecurityDescriptorSddlForm(AccessControlSections.All))throw new IOException("WORKSPACE_DRIFT");
  }if((retained!=0||String.Equals(root,@"C:\Users\vpncp117\AppData\Local\VpnControl\cp166\state",StringComparison.Ordinal))&&(retained!=262116072||seen.Count!=2))throw new IOException("WORKSPACE_RETAINED_INVENTORY");items.Sort(StringComparer.Ordinal);foreach(string row in items)result.Append(row.Length).Append(':').Append(row).Append('\n');return result.ToString();}
}'''

REFRESH_SECURITY_PS="function RequireRefreshSecurity([string]$path,[string]$actorSid){\n $acl=[IO.Directory]::GetAccessControl($path);$actors=@($actorSid,'S-1-5-18')|Select-Object -Unique\n if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $actorSid -or $acl.GetGroup([Security.Principal.SecurityIdentifier]).Value -cne $actorSid -or -not $acl.AreAccessRulesProtected){throw 'DIRECTORY_SECURITY'}\n $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));if($rules.Count -ne @($actors).Count){throw 'DIRECTORY_SECURITY'}\n foreach($who in $actors){$matches=@($rules|Where-Object {$_.IdentityReference.Value -ceq $who});if($matches.Count -ne 1){throw 'DIRECTORY_SECURITY'};$rule=$matches[0];if($rule.IsInherited -or [int64]$rule.FileSystemRights -ne 2032127 -or [int]$rule.InheritanceFlags -ne 3 -or [int]$rule.PropagationFlags -ne 0 -or [int]$rule.AccessControlType -ne 0){throw 'DIRECTORY_SECURITY'}}\n}\nfunction SetRefreshSecurity([string]$path,[string]$actorSid){\n $current=[Security.Principal.WindowsIdentity]::GetCurrent();if($current.User.Value -cne $actorSid){throw 'SECURITY_ACTOR'}\n $security=[Security.AccessControl.DirectorySecurity]::new();$userSid=[Security.Principal.SecurityIdentifier]::new($actorSid);$security.SetOwner($userSid);$security.SetGroup($userSid);$security.SetAccessRuleProtection($true,$false)\n foreach($who in (@($actorSid,'S-1-5-18')|Select-Object -Unique)){$rule=[Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($who),[Security.AccessControl.FileSystemRights]::FullControl,([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow);[void]$security.AddAccessRule($rule)}\n [IO.Directory]::SetAccessControl($path,$security);RequireRefreshSecurity $path $actorSid\n}\n"

REPAIR_TASK_PS=r'''$ErrorActionPreference='Stop';$phase='identity';$heldMsi=$null;$heldRoot=$null;$installer=$null;$installerExitCode=$null;$rootCreated=$false;$errorType=$null;$errorHResult=$null
$root='@ROOT@';$msi='@MSI@';$sid='@SID@';$corr='@CORR@';$nonce='@NONCE@'
@SECURITY_PS@
function WriteNew([string]$name,[string]$text){$bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($text);if($bytes.Length -gt 2097152){throw 'RECORD_BOUND'};$stream=[IO.FileStream]::new((Join-Path $root $name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}}
function Finish([string]$state,[int]$code){WriteNew 'result.json' ((@{version=1;correlationId=$corr;nonce=$nonce;state=$state;phase=$phase;errorType=$errorType;errorHResult=$errorHResult;exitCode=$code;installerExitCode=$installerExitCode;originalSid=$identity.User.Value;sessionId=$self.SessionId;limited=$limited;installerPid=if($null -ne $installer){$installer.Id}else{$null};installerBirth=if($null -ne $installer){$installer.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()}else{$null};workspacePreserved=$preserved;installedBytesMatched=$matched;publicUpdateAcceptance=$false}|ConvertTo-Json -Depth 5 -Compress))}
try{
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$self=Get-Process -Id $PID;$limited=-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if($identity.User.Value -cne $sid -or $self.SessionId -ne 1 -or -not $limited){throw 'IDENTITY'}
 Add-Type -AssemblyName System.IO.Compression
 Add-Type -TypeDefinition @'
@FILE_CS@
'@ -ReferencedAssemblies @('System','System.Core','System.IO.Compression')
 Add-Type -TypeDefinition @'
@WORKSPACE_CS@
'@ -ReferencedAssemblies @('System','System.Core')
 foreach($component in @('C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local','C:\Users\vpncp117\AppData\Local\VpnControl')){$entry=Get-Item -LiteralPath $component -Force;$who=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $component).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value;if(-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or ($who -cne $sid -and ($component -cne 'C:\Users\vpncp117' -or $who -cne 'S-1-5-18'))){throw 'DIRECTORY'}}
 $heldParent=[Cp117RefreshWorkspace]::HoldDirectory('C:\Users\vpncp117\AppData\Local\VpnControl')
 try{[Cp117RefreshWorkspace]::CreateExclusive($root);$rootCreated=$true;$heldRoot=[Cp117RefreshWorkspace]::HoldDirectory($root);SetRefreshSecurity $root $sid;RequireRefreshSecurity $root $sid}finally{$heldParent.Dispose()}
 Add-Type -TypeDefinition @'
@TOKEN_CS@
'@ -ReferencedAssemblies @('System','System.Core')
 $actorBirth=$self.StartTime.ToUniversalTime().ToFileTimeUtc();$actorToken=[Cp117OwnerToken]::Read($PID,$actorBirth)
 if($actorToken[0] -cne $sid -or $actorToken[1] -cne '0' -or $actorToken[2] -notin @('1','3') -or $actorToken[3] -cne 'False' -or $actorToken[4] -cne 'False' -or $actorToken[5] -cne '1'){throw 'IDENTITY'}
 $phase='admission';$preserved=$false;$matched=$false
 $install='C:\Users\vpncp117\AppData\Local\vpn-control';$jar=@(Get-ChildItem -LiteralPath (Join-Path $install 'app') -Filter 'desktopApp-*.jar' -File)
 if($jar.Count -ne 1){throw 'OLD_BYTES'}
 foreach($entry in @(@((Join-Path $install 'vpn-control-cli.exe'),'@OLD_CLI@'),@($jar[0].FullName,'@OLD_JAR@'),@((Join-Path $install 'app\native\windows-amd64\vpn-control-install-helper.exe'),'@OLD_HELPER@'))){if([Cp117InstalledFile]::Read($entry[0])[0] -cne $entry[1]){throw 'OLD_BYTES'}}
 if([Cp117InstalledFile]::Runtime($jar[0].FullName) -cne '@RUNTIME@'){throw 'OLD_BYTES'}
 $phase='product';$products=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 if($products.Count -ne 1 -or $products[0].PSChildName.ToUpperInvariant() -cne '@PRODUCT@' -or $products[0].DisplayVersion -cne '2.1.19' -or $products[0].InstallLocation.TrimEnd('\') -cne $install){throw 'OLD_PRODUCT'}
 $active=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\.exe$'});if($active.Count -ne 0){throw 'ACTIVE_PROCESS'}
 $phase='msi';$heldMsi=[IO.FileStream]::new($msi,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 $heldHash=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($heldMsi)).Replace('-','').ToLowerInvariant();$msiBefore=[Cp117InstalledFile]::Read($msi)
 if($heldMsi.Length -ne @SIZE@ -or $heldHash -cne '@HASH@' -or $msiBefore[0] -cne '@HASH@' -or $msiBefore[1] -cne '@MSI_ID@'){throw 'MSI_FILE'}
 $msiOwner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $msi).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value;if($msiOwner -cne $sid){throw 'MSI_OWNER'}
 $phase='workspace';$before=[Cp117RefreshWorkspace]::Snapshot('@WORKSPACE@');WriteNew 'workspace-before.private' $before
 WriteNew 'attempt.json' ((@{version=1;correlationId=$corr;nonce=$nonce;state='consumed';actorPid=$PID;actorBirth=$self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();sid=$sid;sessionId=1;msiIdentity=$msiBefore[1];msiSha256=$heldHash;action='same-version-source-refresh'}|ConvertTo-Json -Compress))
 $phase='pre-effect';if([Cp117RefreshWorkspace]::Snapshot('@WORKSPACE@') -cne $before -or [Cp117InstalledFile]::Read($msi)[1] -cne $msiBefore[1]){throw 'PRE_EFFECT_DRIFT'}
 if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\.exe$'}).Count -ne 0){throw 'ACTIVE_PROCESS'}
 $phase='installer';$arguments='/i "'+$msi+'" REINSTALL=ALL REINSTALLMODE=vamus /qn /norestart REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable ALLUSERS=2 MSIINSTALLPERUSER=1 /L*v "'+(Join-Path $root 'baseline-msi.log')+'"'
 $installer=Start-Process -FilePath 'C:\Windows\System32\msiexec.exe' -ArgumentList $arguments -PassThru
 WriteNew 'installer.json' ((@{version=1;correlationId=$corr;nonce=$nonce;pid=$installer.Id;startFileTime=$installer.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();commandSha256=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($arguments))).Replace('-','').ToLowerInvariant()}|ConvertTo-Json -Compress))
 if(-not $installer.WaitForExit(600000)){Finish 'unknown' -1;exit 1}
 $installerExitCode=[int]$installer.ExitCode
 $phase='readback';$after=[Cp117RefreshWorkspace]::Snapshot('@WORKSPACE@');WriteNew 'workspace-after.private' $after;$preserved=$after -ceq $before
 $msiAfter=[Cp117InstalledFile]::Read($msi);if($msiAfter[0] -cne $msiBefore[0] -or $msiAfter[1] -cne $msiBefore[1]){throw 'MSI_DRIFT'}
 $afterProducts=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue|Where-Object {$_.DisplayName -eq 'vpn-control'})
 if($afterProducts.Count -ne 1 -or $afterProducts[0].PSChildName.ToUpperInvariant() -cne '@PRODUCT@' -or $afterProducts[0].DisplayVersion -cne '2.1.19' -or $afterProducts[0].InstallLocation.TrimEnd('\') -cne $install){throw 'NEW_PRODUCT'}
 $newJar=Join-Path (Join-Path $install 'app') '@NEW_JAR_NAME@';$newJars=@(Get-ChildItem -LiteralPath (Join-Path $install 'app') -Filter 'desktopApp-*.jar' -File)
 if($newJars.Count -ne 1 -or $newJars[0].FullName -cne $newJar){throw 'NEW_BYTES'}
 $matched=[Cp117InstalledFile]::Read((Join-Path $install 'vpn-control-cli.exe'))[0] -ceq '@NEW_CLI@' -and [Cp117InstalledFile]::Read($newJar)[0] -ceq '@NEW_JAR@' -and [Cp117InstalledFile]::Read((Join-Path $install 'app\native\windows-amd64\vpn-control-install-helper.exe'))[0] -ceq '@NEW_HELPER@' -and [Cp117InstalledFile]::Runtime($newJar) -ceq '@RUNTIME@'
 if($installer.ExitCode -eq 0 -and $matched -and $preserved){$phase='complete';Finish 'passed' 0}else{Finish 'failed' $installer.ExitCode;exit 1}
}catch{$errorType=$_.Exception.GetType().FullName;$errorHResult=$_.Exception.HResult;if($rootCreated -and [IO.Directory]::Exists($root) -and -not [IO.File]::Exists((Join-Path $root 'result.json'))){$details=$_.Exception.ToString();if([Text.Encoding]::UTF8.GetByteCount($details) -le 65536 -and -not [IO.File]::Exists((Join-Path $root 'failure.private'))){WriteNew 'failure.private' $details};Finish 'unknown' -1};exit 1}finally{if($null -ne $heldMsi){$heldMsi.Dispose()};if($null -ne $heldRoot){$heldRoot.Dispose()};if($null -ne $installer){$installer.Dispose()};if($null -ne $self){$self.Dispose()}}
'''

def repair_admission(value):
    validate_census(value)
    summary=census_summary(value,{'state':'served','port':SUBMITTED_PORT,'pathSha256':hashlib.sha256(ROUTE_PATH.encode()).hexdigest()})
    if not all(summary[k]is True for k in('downloadedBytesProven','taskStopped','taskExitZero'))or summary.get('setupBranch')!='repair':raise ValueError('refresh-repair-admission')
    staged=value['facts']['metadata']['staged']
    if staged['productCode']!=REPAIR_PRODUCT or staged['upgradeCode']!=REPAIR_UPGRADE or staged['identity']!=REPAIR_MSI_IDENTITY or staged['allUsers']is not None or staged['perUser']is not None or value['facts']['metadata']['oldProductCode']!=REPAIR_PRODUCT:raise ValueError('refresh-repair-exact-product')
    return {'state':'ready','action':'same-version-source-refresh','publicUpdateAcceptance':False}

def repair_task():
    # Source bytes come from the already authenticated fixed installed factory.
    installed.body(PAIR_EXPECTED)
    if hashlib.sha256(WORKSPACE_CS.encode()).hexdigest()!='459462516407f3e2b2a1a930206a3ef99981f7b1ce1f1c0298605d7b2ffc1a39' or hashlib.sha256(REPAIR_TASK_PS.encode()).hexdigest()!='42f270b592587e46f3510b4439c9515cc69403400bccb963a8bcd6975f58cd88':raise ValueError('refresh-repair-fixed-template')
    values={'SECURITY_PS':REFRESH_SECURITY_PS,'ROOT':REPAIR_ROOT,'MSI':DOWNLOADED_CANDIDATE,'SID':installed.precise.owner.SID,'CORR':REPAIR_CORRELATION,'NONCE':REPAIR_NONCE,'FILE_CS':installed.FILE_CS,'WORKSPACE_CS':WORKSPACE_CS,'TOKEN_CS':installed.precise.owner._TOKEN_CS,'PRODUCT':REPAIR_PRODUCT,'MSI_ID':REPAIR_MSI_IDENTITY,'WORKSPACE':WORKSPACE_ROOT,'HASH':BASE_HASH,'SIZE':str(BASE_SIZE),'OLD_CLI':OLD_HASHES['cliSha256'],'OLD_JAR':OLD_HASHES['jarSha256'],'OLD_HELPER':OLD_HASHES['helperSha256'],'RUNTIME':PAIR_EXPECTED['baseRuntimeSha256'],'NEW_CLI':PAIR_EXPECTED['baseCliSha256'],'NEW_JAR':PAIR_EXPECTED['baseAppJarSha256'],'NEW_HELPER':PAIR_EXPECTED['baseHelperSha256'],'NEW_JAR_NAME':PAIR_EXPECTED['baseAppJarName']}
    source=REPAIR_TASK_PS
    for key,value in values.items():source=source.replace('@'+key+'@',value)
    if re.search(r'@[A-Z_]+@',source):raise ValueError('refresh-repair-task-template')
    if hashlib.sha256(source.encode()).hexdigest()!=REPAIR_ACTION_SHA:raise ValueError('refresh-repair-task-catalog')
    return source

def _repair_encoded(source):
    data=source.encode();packed=base64.b64encode(gzip.compress(data,mtime=0)).decode()
    bootstrap="$ErrorActionPreference='Stop';$i=[IO.MemoryStream]::new([Convert]::FromBase64String('"+packed+"'));$z=[IO.Compression.GZipStream]::new($i,[IO.Compression.CompressionMode]::Decompress);$o=[IO.MemoryStream]::new();try{$b=New-Object byte[] 4096;while(($n=$z.Read($b,0,$b.Length)) -gt 0){$o.Write($b,0,$n);if($o.Length -gt 65536){throw 'REFRESH_SOURCE_BOUND'}};$v=$o.ToArray();if($v.Length -ne "+str(len(data))+" -or [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($v)).Replace('-','').ToLowerInvariant() -cne '"+hashlib.sha256(data).hexdigest()+"'){throw 'REFRESH_SOURCE_HASH'};& ([ScriptBlock]::Create([Text.UTF8Encoding]::new($false,$true).GetString($v)))}finally{$z.Dispose();$i.Dispose();$o.Dispose()}"
    encoded=base64.b64encode(bootstrap.encode('utf-16le')).decode()
    if len(data)>65536 or len(encoded)>=30000:raise ValueError('refresh-repair-command-cap')
    return encoded

def repair_body():
    task_source=repair_task();encoded=_repair_encoded(task_source)
    action_bootstrap=base64.b64decode(encoded).decode('utf-16le')
    packed=base64.b64encode(gzip.compress(task_source.encode(),mtime=0)).decode()
    if action_bootstrap.count(packed)!=1:raise ValueError('refresh-repair-action-literal')
    left,right=action_bootstrap.split(packed)
    ps=installed.public._ps_literal
    # Task source is retained as authenticated plain text; .NET creates its
    # bounded gzip command in memory. Exact decoded bytes/length/hash remain
    # checked by the child before the first identity or installer operation.
    action_literal="$cp117TaskInput=[Console]::OpenStandardInput();$cp117TaskBuffer=[IO.MemoryStream]::new();try{$block=New-Object byte[] 4096;while(($amount=$cp117TaskInput.Read($block,0,$block.Length)) -gt 0){$cp117TaskBuffer.Write($block,0,$amount);if($cp117TaskBuffer.Length -gt 65536){throw 'PACKAGE_DRIFT'}};$cp117TaskBytes=$cp117TaskBuffer.ToArray()}finally{$cp117TaskBuffer.Dispose()};if($cp117TaskBytes.Length -ne "+str(len(task_source.encode()))+" -or [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($cp117TaskBytes)).Replace('-','').ToLowerInvariant() -cne '"+hashlib.sha256(task_source.encode()).hexdigest()+"'){throw 'PACKAGE_DRIFT'};$cp117TaskText=[Text.UTF8Encoding]::new($false,$true).GetString($cp117TaskBytes);$cp117Tokens=$null;$cp117Errors=$null;[void][Management.Automation.Language.Parser]::ParseInput($cp117TaskText,[ref]$cp117Tokens,[ref]$cp117Errors);if($cp117Errors.Count -ne 0){throw 'REFRESH_TASK_PARSE'};$cp117Memory=[IO.MemoryStream]::new();$cp117Compressor=[IO.Compression.GZipStream]::new($cp117Memory,[IO.Compression.CompressionMode]::Compress,$true);try{$cp117Compressor.Write($cp117TaskBytes,0,$cp117TaskBytes.Length)}finally{$cp117Compressor.Dispose()};try{$cp117Packed=[Convert]::ToBase64String($cp117Memory.ToArray())}finally{$cp117Memory.Dispose()};$cp117ActionBootstrap="+ps(left)+"+$cp117Packed+"+ps(right)+";$cp117ActionEncoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cp117ActionBootstrap));if($cp117ActionEncoded.Length -ge 30000){throw 'PACKAGE_DRIFT'};$cp117ActionArgument='-NoProfile -NonInteractive -EncodedCommand '+$cp117ActionEncoded;$cp117ActionSha=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($cp117ActionArgument))).Replace('-','').ToLowerInvariant()\n"
    action_sha=hashlib.sha256(task_source.encode()).hexdigest()
    plain=census_body();marker="[Console]::Out.WriteLine((@{version=1;correlationId='"+CENSUS_CORRELATION+"';outcome='complete'"
    if plain.count(marker)!=1:raise ValueError('refresh-repair-owner-factory')
    # All immutable MSI COM values and all current owner/old bytes are freshly
    # established in this SAME current guest query before task registration.
    before=r'''if($cp117ReadinessProof.code -cne 'READY' -or $cp117Task.state -cne 'Ready' -or $cp117Task.lastTaskResult -ne 0){throw 'PACKAGE_DRIFT'}
if($cp117Refresh.oldProductCode -cne '@PRODUCT@' -or $null -eq $cp117Refresh.staged -or $cp117Refresh.staged.productCode -cne '@PRODUCT@' -or $cp117Refresh.staged.upgradeCode -cne '@UPGRADE@' -or $cp117Refresh.staged.identity -cne '@MSI_ID@' -or $null -ne $cp117Refresh.staged.allUsers -or $null -ne $cp117Refresh.staged.perUser){throw 'PACKAGE_DRIFT'}
@OLD_CHECKS@
$refreshRoot='@ROOT@';$refreshTask='VpnControlMcpRefresh-@CORR@'
foreach($component in @('C:\Users\vpncp117','C:\Users\vpncp117\AppData','C:\Users\vpncp117\AppData\Local','C:\Users\vpncp117\AppData\Local\VpnControl')){$item=Get-Item -LiteralPath $component -Force;$componentOwner=([Security.Principal.NTAccount]::new((Get-Acl -LiteralPath $component).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value;if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or ($componentOwner -cne $sid -and ($component -cne 'C:\Users\vpncp117' -or $componentOwner -cne 'S-1-5-18'))){throw 'PACKAGE_DRIFT'}}
if([IO.Directory]::Exists($refreshRoot) -or [IO.File]::Exists($refreshRoot) -or @(Get-ScheduledTask -TaskPath '\'|Where-Object {$_.TaskName -ceq $refreshTask}).Count -ne 0){throw 'PACKAGE_DRIFT'}
@DIRECTORY_CS@
$heldRefreshParent=[Cp117RefreshWorkspace]::HoldDirectory('C:\Users\vpncp117\AppData\Local\VpnControl');$heldRefreshRoot=$null;$heldIntentRoot=$null;$heldIntentParent=$null
try{
$intentRoot='C:\Windows\Temp\vpn-control-refresh-submit-@CORR@';$heldIntentParent=[Cp117RefreshWorkspace]::HoldDirectory('C:\Windows\Temp');[Cp117RefreshWorkspace]::CreateExclusive($intentRoot);$heldIntentRoot=[Cp117RefreshWorkspace]::HoldDirectory($intentRoot)
@SECURITY_PS@
SetRefreshSecurity $intentRoot 'S-1-5-18'
@ACTION_LITERAL@
$intent=[Text.UTF8Encoding]::new($false,$true).GetBytes((@{version=1;correlationId='@CORR@';nonce='@NONCE@';state='consumed';action='same-version-source-refresh';taskArgumentsSha256=$cp117ActionSha;sourceSha256='@SOURCE_SHA@';publicUpdateAcceptance=$false}|ConvertTo-Json -Compress));$intentFile=[IO.FileStream]::new((Join-Path $intentRoot 'intent.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$intentFile.Write($intent,0,$intent.Length);$intentFile.Flush($true)}finally{$intentFile.Dispose()}
$action=New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$cp117ActionEncoded)
$principal=New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskPath '\' -TaskName $refreshTask -Action $action -Principal $principal -Settings $settings|Out-Null
$registered=Get-ScheduledTask -TaskPath '\' -TaskName $refreshTask
$registeredSid=if($registered.Principal.UserId -like 'S-1-*'){$registered.Principal.UserId}else{([Security.Principal.NTAccount]::new($registered.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
if($registeredSid -cne $sid -or $registered.Principal.LogonType.ToString() -cne 'Interactive' -or $registered.Principal.RunLevel.ToString() -cne 'Limited' -or @($registered.Actions).Count -ne 1 -or $registered.Actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($registered.Actions[0].Arguments))).Replace('-','').ToLowerInvariant() -cne $cp117ActionSha){throw 'PACKAGE_DRIFT'}
Start-ScheduledTask -TaskPath '\' -TaskName $refreshTask
$cp117RepairSubmission=@{state='submitted';action='same-version-source-refresh';taskArgumentsSha256=$cp117ActionSha;taskSourceSha256='@SOURCE_SHA@';publicUpdateAcceptance=$false}
}finally{if($null -ne $heldIntentParent){$heldIntentParent.Dispose()};if($null -ne $heldIntentRoot){$heldIntentRoot.Dispose()};if($null -ne $heldRefreshRoot){$heldRefreshRoot.Dispose()};$heldRefreshParent.Dispose()}
'''
    old_checks='\n'.join("if($cp117Package.%s -cne '%s'){throw 'PACKAGE_DRIFT'}"%(key,value)for key,value in OLD_HASHES.items())
    directory_cs='Add-Type -TypeDefinition '+ps(WORKSPACE_CS)+" -ReferencedAssemblies @('System','System.Core')\n"
    for key,value in {'PRODUCT':REPAIR_PRODUCT,'UPGRADE':REPAIR_UPGRADE,'MSI_ID':REPAIR_MSI_IDENTITY,'OLD_CHECKS':old_checks,'ROOT':REPAIR_ROOT,'CORR':REPAIR_CORRELATION,'NONCE':REPAIR_NONCE,'ACTION_SHA':action_sha,'SOURCE_SHA':hashlib.sha256(task_source.encode()).hexdigest(),'ACTION_LITERAL':action_literal,'DIRECTORY_CS':directory_cs,'SECURITY_PS':REFRESH_SECURITY_PS}.items():before=before.replace('@'+key+'@',value)
    at=plain.index(marker);plain=plain[:at]+before+plain[at:]
    plain=plain.replace('task=$cp117Task};details','task=$cp117Task;repair=$cp117RepairSubmission};details').replace(CENSUS_CORRELATION,REPAIR_CORRELATION)
    return plain,action_sha

def validate_repair_submission(value):
    if not isinstance(value,dict)or value.get('correlationId')!=REPAIR_CORRELATION:raise ValueError('refresh-repair-correlation')
    base=dict(value,correlationId=CENSUS_CORRELATION)
    if value.get('outcome')=='complete':
        facts=value.get('facts')
        if not isinstance(facts,dict)or set(facts)!={'owner','readiness','package','metadata','task','repair'}:raise ValueError('refresh-repair-facts')
        mark=facts['repair']
        if not isinstance(mark,dict)or set(mark)!={'state','action','taskArgumentsSha256','taskSourceSha256','publicUpdateAcceptance'}or mark['state']!='submitted'or mark['action']!='same-version-source-refresh'or not isinstance(mark['taskArgumentsSha256'],str)or re.fullmatch('[0-9a-f]{64}',mark['taskArgumentsSha256'])is None or mark['taskSourceSha256']!=REPAIR_ACTION_SHA or mark['publicUpdateAcceptance']is not False:raise ValueError('refresh-repair-marker')
        base['facts']={key:facts[key]for key in('owner','readiness','package','metadata','task')}
        repair_admission(base)
    validate_census(base);return value

def repair_program(record):
    r=installed.precise.owner.guest.recovery;pin,raw=r.authority._read_bound_file(Path(__file__),retain_bytes=True)
    source,oldsha=census_program(record);plain,action_sha=repair_body();sha=hashlib.sha256(plain.encode('utf-16le')).hexdigest()
    full="[Console]::Out.WriteLine(('CP117-READ "+REPAIR_NONCE+" "+sha+" '+$PID))\n"+plain
    public=full.encode();task_bytes=repair_task().encode()
    if len(public)>65536 or len(task_bytes)>65536:raise ValueError('refresh-repair-input-bound')
    # The fixed public program and task source share QGA's existing input-data
    # channel. A bounded length/hash authenticated loader consumes exactly the
    # first frame; the fixed parent then consumes the task bytes through EOF.
    # This avoids two nested encoded command representations; no cap changes.
    loader="$ErrorActionPreference='Stop';$stream=[Console]::OpenStandardInput();$head=New-Object byte[] 4;$offset=0;while($offset -lt 4){$amount=$stream.Read($head,$offset,4-$offset);if($amount -le 0){throw 'REFRESH_SOURCE_EOF'};$offset+=$amount};$length=[BitConverter]::ToUInt32($head,0);if($length -ne "+str(len(public))+" -or $length -gt 65536){throw 'REFRESH_SOURCE_BOUND'};$data=New-Object byte[] $length;$offset=0;while($offset -lt $length){$amount=$stream.Read($data,$offset,$length-$offset);if($amount -le 0){throw 'REFRESH_SOURCE_EOF'};$offset+=$amount};if([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($data)).Replace('-','').ToLowerInvariant() -cne '"+hashlib.sha256(public).hexdigest()+"'){throw 'REFRESH_SOURCE_HASH'};$cp117Body=[Text.UTF8Encoding]::new($false,$true).GetString($data);$cp117Tokens=$null;$cp117Errors=$null;[void][Management.Automation.Language.Parser]::ParseInput($cp117Body,[ref]$cp117Tokens,[ref]$cp117Errors);if($cp117Errors.Count -ne 0){throw 'REFRESH_BODY_PARSE'};& ([ScriptBlock]::Create($cp117Body))"
    encoded=base64.b64encode(loader.encode('utf-16le')).decode()
    if len(encoded)>=30000:raise ValueError('refresh-repair-command-cap')
    packet=len(public).to_bytes(4,'little')+public+task_bytes
    tree=ast.parse(source);oldencoded=next(n.value.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets))
    for before,after in((repr(oldencoded),repr(encoded)),('D='+repr(CENSUS_CORRELATION),'D='+repr(REPAIR_CORRELATION)),('NONCE='+repr(CENSUS_NONCE),'NONCE='+repr(REPAIR_NONCE)),('BODY_SHA='+repr(oldsha),'BODY_SHA='+repr(sha))):
        if source.count(before)!=1:raise ValueError('refresh-repair-carrier-factory')
        source=source.replace(before,after)
    wrapper='REPAIR_CORRELATION='+repr(REPAIR_CORRELATION)+'\nREPAIR_PRODUCT='+repr(REPAIR_PRODUCT)+'\nREPAIR_UPGRADE='+repr(REPAIR_UPGRADE)+'\nREPAIR_MSI_IDENTITY='+repr(REPAIR_MSI_IDENTITY)+'\nREPAIR_ACTION_SHA='+repr(action_sha)+'\nSUBMITTED_PORT='+repr(SUBMITTED_PORT)+'\nROUTE_PATH='+repr(ROUTE_PATH)+'\n_refresh_validate=validate\n'+_functions(raw,('setup_plan','repair_admission','validate_repair_submission'))+'\nvalidate=validate_repair_submission\n'
    # Existing validator references stay bound to their original namespace.
    source+='\n' # wrapper is inserted before child dispatch, never at the end.
    marker="try:\n children=[item['frame']['value']"
    if source.count(marker)!=1:raise ValueError('refresh-repair-parser-slot')
    wrapper=wrapper.replace('    validate(value)','    _metadata_validate(value)').replace('    validate_census(value)','    _census_validate(value)').replace('    validate_census(base);return value','    _census_validate(base);return value')
    wrapper=wrapper.replace("    summary=census_summary(value,{'state':'served','port':SUBMITTED_PORT,'pathSha256':hashlib.sha256(ROUTE_PATH.encode()).hexdigest()})","    task=value['facts']['task'];base=dict(value,correlationId=CORRELATION,facts={k:value['facts'][k]for k in('owner','readiness','package','metadata')});plan=setup_plan(base);summary={'downloadedBytesProven':value['facts']['metadata']['staged'] is not None,'taskStopped':task['state']=='Ready','taskExitZero':task['lastTaskResult']==0,'setupBranch':plan.get('branch')}")
    wrapper='_census_validate=validate\nOLD_HASHES='+repr(OLD_HASHES)+'\n'+wrapper
    source=source.replace(marker,wrapper+'\n'+marker)
    request="'capture-output':True})"
    if source.count(request)!=1:raise ValueError('refresh-repair-public-input-slot')
    source=source.replace(request,"'capture-output':True,'input-data':"+repr(base64.b64encode(packet).decode())+"})")
    if r.authority._read_bound_file(Path(__file__))!=pin:raise ValueError('refresh-repair-parser-drift')
    compile(source,'fixed-current-base-repair','exec');return source,sha,action_sha

def submit_repair(root):
    root=Path(root).resolve(strict=True);r=installed.precise.owner.guest.recovery;leaf='windows-cp117-base-refresh-repair-'+REPAIR_CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','stage':'consumed','installerAction':False,'replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf)
    original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION);census=AuthorityCapture(root,'windows-cp117-base-refresh-staging-census-'+CENSUS_CORRELATION);events=[]
    try:
        originalraw=r._local_read(original,installed.precise.owner.guest.ORIGINAL['name'],installed.precise.owner.guest.ORIGINAL['pin']);record=json.loads(originalraw)
        priorraw=r._local_read(census,'result.json',CENSUS_RESULT_PIN);prior=json.loads(priorraw)
        if prior['result']['state']!='observed':raise ValueError('refresh-repair-prior-state')
        repair_admission(prior['result']['facts']);admitted=installed.pair(root)
        files=(Path(__file__),Path(transfer.__file__),Path(installed.__file__),Path(installed.precise.__file__),Path(installed.public.__file__),Path(flow.__file__),Path(installed.precise.owner.__file__),Path(installed.precise.owner.guest.__file__),Path(r.authority.closure.base.__file__))
        pins={str(p):r.authority._read_bound_file(p)for p in files};execution=flow._execution_source_proof(root,record);outer=r.authority._outer_authority(root)
        def verify():
            if r._local_read(original,installed.precise.owner.guest.ORIGINAL['name'],installed.precise.owner.guest.ORIGINAL['pin'])!=originalraw or r._local_read(census,'result.json',CENSUS_RESULT_PIN)!=priorraw:raise ValueError('refresh-repair-history-drift')
            for i,item in enumerate(record['authority']):
                r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('refresh-repair-original-frame')
            if flow._execution_source_proof(root,record)!=execution or any(r.authority._read_bound_file(Path(p))!=v for p,v in pins.items()):raise ValueError('refresh-repair-source-drift')
            r.authority._verify_outer(root,{'outerAuthority':outer})
            if installed.pair(root)!=admitted:raise ValueError('refresh-repair-artifact-drift')
        verify();source,sha,task_sha=repair_program(record);action=repair_task()
        capture.create('request.json',json.dumps({'correlationId':REPAIR_CORRELATION,'nonce':REPAIR_NONCE,'priorResult':CENSUS_RESULT_PIN,'sources':pins,'executionSourceProof':execution,'outerAuthority':outer,'pair':admitted,'taskSourceSha256':task_sha,'action':'same-version-source-refresh','publicUpdateAcceptance':False},sort_keys=True).encode());capture.create('remote.py',source.encode());capture.create('task.ps1',action.encode());os.fsync(capture.fd)
        config,_,_=r.authority.closure.base._descriptor(root);argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        capture.create('attempt.json',json.dumps({'state':'consumed','correlationId':REPAIR_CORRELATION,'nonce':REPAIR_NONCE,'action':'same-version-source-refresh'},sort_keys=True).encode());os.fsync(capture.fd);verify()
        value,events=flow._stream(argv,capture,REPAIR_CORRELATION,REPAIR_NONCE,sha,record['result']['qemu'],None);verify()
        pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        if value.get('state')!='observed':return {'state':'unknown','evidenceLeaf':leaf,'receipt':pin,'installerAction':True,'publicUpdateAcceptance':False,'replayAllowed':False}
        validate_repair_submission(value['facts'])
        return {'state':'repair-submitted','evidenceLeaf':leaf,'receipt':pin,'installerAction':True,'installerCompleted':False,'publicUpdateAcceptance':False,'replayAllowed':False}
    except Exception as error:
        events.extend(getattr(error,'events',[]));pin=capture.create('unknown.json',json.dumps({'state':'unknown','failureType':type(error).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','evidenceLeaf':leaf,'receipt':pin,'installerAction':True,'publicUpdateAcceptance':False,'replayAllowed':False}
    finally:census.close();original.close();capture.close()


# Explicit disposable fixture replacement. The general setup_plan/repair path
# above remains unchanged; these are two separately fenced ordinary-user tasks.
REPLACEMENT_CONTEXT_CS=r"""using System;using System.Text;using System.IO;using System.Runtime.InteropServices;
public static class Cp117ReplacementContext{
 const string Product="{CFCB6A78-7F8F-31FD-8B20-C1977A677578}";
 [DllImport("msi.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]static extern uint MsiEnumProductsExW(string product,string user,uint contexts,uint index,StringBuilder code,out uint context,StringBuilder sid,ref uint size);
 [DllImport("msi.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]static extern uint MsiGetProductInfoExW(string product,string user,uint context,string property,StringBuilder value,ref uint size);
 public static string[] Read(int index){if(index<0||index>2)throw new IOException("CONTEXT_CATALOGUE");uint requested=new uint[]{1,2,4}[index],actual=0,size=184;var product=new StringBuilder(39);var sid=new StringBuilder(185);uint code=MsiEnumProductsExW(Product,null,requested,0,product,out actual,sid,ref size);uint next=259;
 if(code==0){if(product.ToString()!=Product||actual!=requested||size>184||sid.Length!=size)throw new IOException("CONTEXT_SHAPE");var p=new StringBuilder(39);var s=new StringBuilder(185);uint n=184,c;next=MsiEnumProductsExW(Product,null,requested,1,p,out c,s,ref n);}
 else if(code!=259)throw new IOException("CONTEXT_UNAVAILABLE");return new string[]{requested.ToString(),code.ToString(),code==0?actual.ToString():"0",code==0?sid.ToString():null,next.ToString()};}
 public static string[] Info(string property){if(property!="PackageCode"&&property!="VersionString")throw new IOException("PROPERTY_CATALOGUE");var b=new StringBuilder(513);uint n=512;uint code=MsiGetProductInfoExW(Product,null,2,property,b,ref n);if(code==0&&(n>512||b.Length!=n))throw new IOException("PROPERTY_SHAPE");return new string[]{code.ToString(),code==0?b.ToString():null};}
}"""
REPLACEMENT_CONTEXT_PS=r"""
function RequireReplacementContext([bool]$absent){
 $before=@();for($index=0;$index -lt 3;$index++){[string[]]$entry=[Cp117ReplacementContext]::Read($index);$before+=,($entry -join '|');
  if($absent -or $index -ne 1){if($entry[1] -cne '259' -or $entry[2] -cne '0' -or $null -ne $entry[3] -or $entry[4] -cne '259'){throw 'REPLACEMENT_CONTEXT_ABSENCE'}}
  elseif($entry[1] -cne '0' -or $entry[2] -cne '2' -or $entry[3] -cne $sid -or $entry[4] -cne '259'){throw 'REPLACEMENT_ORDINARY_CONTEXT'}
 }
 if(-not $absent){[string[]]$package=[Cp117ReplacementContext]::Info('PackageCode');[string[]]$version=[Cp117ReplacementContext]::Info('VersionString');if($package[0] -cne '0' -or $package[1] -cne '{398537AF-50FB-4D8D-B9E9-B34FCB2547F4}' -or $version[0] -cne '0' -or $version[1] -cne '2.1.19'){throw 'REPLACEMENT_REGISTERED_SOURCE'}}
 for($index=0;$index -lt 3;$index++){[string[]]$entry=[Cp117ReplacementContext]::Read($index);if(($entry -join '|') -cne $before[$index]){throw 'REPLACEMENT_CONTEXT_DRIFT'}}
}
function RequireReplacementIdle(){
 $cp117Busy=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\.exe$'})
 if($cp117Busy.Count -ne 0){
  $cp117BusyRows=@()
  foreach($cp117BusyEntry in @($cp117Busy|Select-Object -First 32)){
   $cp117BusyProcess=$null;$cp117BusyBirth=$null;$cp117BusySid=$null;$cp117BusyExecutable=$null;$cp117BusySuccess=$false;$cp117BusyError=$null;$cp117BusyHResult=$null
   try{
    $cp117BusyProcess=[Diagnostics.Process]::GetProcessById([int]$cp117BusyEntry.ProcessId)
    $cp117BusyBirth=$cp117BusyProcess.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
    if($cp117BusyProcess.HasExited -or $cp117BusyProcess.SessionId -ne [int]$cp117BusyEntry.SessionId -or [Math]::Floor([decimal]::Parse($cp117BusyBirth)/10) -ne [Math]::Floor([decimal]::Parse($cp117BusyEntry.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString())/10)){throw 'BUSY_PROCESS_GENERATION'}
    $cp117BusyOwner=Invoke-CimMethod -InputObject $cp117BusyEntry -MethodName GetOwnerSid -ErrorAction Stop
    if($cp117BusyOwner.ReturnValue -ne 0 -or $cp117BusyOwner.Sid -notmatch '^S-1-[0-9]+(-[0-9]+)+$'){throw 'BUSY_PROCESS_OWNER'}
    $cp117BusySid=[string]$cp117BusyOwner.Sid;$cp117BusyExecutable=[string]$cp117BusyEntry.ExecutablePath
    if($cp117BusyExecutable.Length -eq 0 -or $cp117BusyExecutable.Length -gt 4096){throw 'BUSY_PROCESS_EXECUTABLE'}
    $cp117BusyAgain=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$cp117BusyEntry.ProcessId) -ErrorAction Stop
    if($null -eq $cp117BusyAgain -or $cp117BusyAgain.Name -cne $cp117BusyEntry.Name -or $cp117BusyAgain.CreationDate -ne $cp117BusyEntry.CreationDate -or $cp117BusyAgain.SessionId -ne $cp117BusyEntry.SessionId -or $cp117BusyAgain.ExecutablePath -cne $cp117BusyExecutable -or $cp117BusyProcess.HasExited -or $cp117BusyProcess.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -cne $cp117BusyBirth){throw 'BUSY_PROCESS_DRIFT'}
    $cp117BusySuccess=$true
   }catch{$cp117BusyError=$_.Exception.GetBaseException().GetType().Name;$cp117BusyHResult=$_.Exception.GetBaseException().HResult}
   finally{if($null -ne $cp117BusyProcess){$cp117BusyProcess.Dispose()}}
   $cp117BusyRows+=@{pid=[int]$cp117BusyEntry.ProcessId;name=[string]$cp117BusyEntry.Name;sessionId=[int]$cp117BusyEntry.SessionId;birth=$cp117BusyBirth;sid=$cp117BusySid;executable=$cp117BusyExecutable;querySuccess=$cp117BusySuccess;errorType=$cp117BusyError;errorHResult=$cp117BusyHResult}
  }
  $script:cp117BusyObservation=@{version=1;totalCount=$cp117Busy.Count;overflow=($cp117Busy.Count -gt 32);rows=$cp117BusyRows}
  $cp117BusyJson=$script:cp117BusyObservation|ConvertTo-Json -Depth 6 -Compress
  if($rootCreated -eq $true -and [Text.Encoding]::UTF8.GetByteCount($cp117BusyJson) -le 65536){WriteNew 'active-process.private' $cp117BusyJson}
  throw 'ACTIVE_PROCESS'
 }
 foreach($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')){if(Test-Path -LiteralPath $key){throw 'PENDING_REBOOT'}}
 $key=Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop;$pending=$key.GetValue('PendingFileRenameOperations',$null);if($null -ne $pending -and @($pending).Count -ne 0){throw 'PENDING_REBOOT'}
}
"""

def replacement_task(phase,correlation,nonce,workspace_sha256=None):
    if phase not in ('retire','provision')or not isinstance(correlation,str)or re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',correlation)is None or not isinstance(nonce,str)or re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',nonce)is None or correlation==nonce or correlation==REPAIR_CORRELATION:
        raise ValueError('replacement-attempt-identity')
    if phase=='provision':
        if type(workspace_sha256)is not str or re.fullmatch('[0-9a-f]{64}',workspace_sha256)is None:raise ValueError('replacement-workspace-proof')
    elif workspace_sha256 is not None:raise ValueError('replacement-retirement-workspace')
    source=repair_task()
    source=source.replace("$errorHResult=$null\n","$errorHResult=$null;$retired=$false;$provisioned=$false;$workspaceSha=$null;$preserved=$false;$matched=$false;$actorBirth=$null\n",1)
    def change(before,after):
        nonlocal source
        if source.count(before)!=1:raise ValueError('replacement-template-boundary')
        source=source.replace(before,after)
    root=REPAIR_ROOT.replace(REPAIR_CORRELATION,correlation)
    source=source.replace(REPAIR_CORRELATION,correlation).replace(REPAIR_NONCE,nonce)
    change("$phase='admission';$preserved=$false;$matched=$false","Add-Type -TypeDefinition @'\n"+REPLACEMENT_CONTEXT_CS+"\n'@ -ReferencedAssemblies @('System','System.Core')\n"+REPLACEMENT_CONTEXT_PS+"\n$phase='admission';$preserved=$false;$matched=$false;$retired=$false;$provisioned=$false;$workspaceSha=$null;RequireReplacementIdle")
    change('publicUpdateAcceptance=$false}|ConvertTo-Json -Depth 5 -Compress','phaseKind=\''+phase+'\';actorPid=$PID;actorBirth=if($null -ne $actorBirth){$actorBirth.ToString()}else{$null};retirementProven=$retired;provisioningProven=$provisioned;workspaceSha256=$workspaceSha;publicUpdateAcceptance=$false}|ConvertTo-Json -Depth 5 -Compress')
    if phase=='provision':
        start=source.index(" $install='C:\\Users\\vpncp117\\AppData\\Local\\vpn-control';$jar=")
        end=source.index(" $active=@(Get-CimInstance",start)
        source=source[:start]+" $install='C:\\Users\\vpncp117\\AppData\\Local\\vpn-control';RequireReplacementContext $true\n foreach($path in @((Join-Path $install 'vpn-control.exe'),(Join-Path $install 'vpn-control-cli.exe'),(Join-Path $install 'app'))){if(Test-Path -LiteralPath $path){throw 'REPLACEMENT_INSTALLED_RESIDUE'}}\n"+source[end:]
    else:
        change(" $phase='product';$products="," RequireReplacementContext $false\n $phase='product';$products=")
    change("action='same-version-source-refresh'","action='explicit-baseline-"+phase+"'")
    if phase=='provision':
        change("$before=[Cp117RefreshWorkspace]::Snapshot('"+WORKSPACE_ROOT+"');WriteNew 'workspace-before.private' $before","$before=[Cp117RefreshWorkspace]::Snapshot('"+WORKSPACE_ROOT+"');$beforeSha=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($before))).Replace('-','').ToLowerInvariant();if($beforeSha -cne '"+workspace_sha256+"'){throw 'REPLACEMENT_WORKSPACE_DRIFT'};WriteNew 'workspace-before.private' $before")
    change(" $phase='installer';$arguments=", " RequireReplacementContext $"+('true'if phase=='provision'else'false')+";RequireReplacementIdle\n $phase='installer';$arguments=")
    old=source[source.index("$phase='installer';$arguments="):source.index("\n $installer=Start-Process",source.index("$phase='installer';$arguments="))]
    if phase=='retire':
        args="$phase='installer';$arguments='/x "+REPAIR_PRODUCT+" /qn /norestart REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable /L*v \"'+(Join-Path $root 'retirement-msi.log')+'\"'"
    else:
        args=old.replace(' REINSTALL=ALL REINSTALLMODE=vamus','').replace('baseline-msi.log','provision-msi.log')
    change(old,args)
    change("$after=[Cp117RefreshWorkspace]::Snapshot('"+WORKSPACE_ROOT+"');WriteNew 'workspace-after.private' $after;$preserved=$after -ceq $before","$after=[Cp117RefreshWorkspace]::Snapshot('"+WORKSPACE_ROOT+"');WriteNew 'workspace-after.private' $after;$preserved=$after -ceq $before;$workspaceSha=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($after))).Replace('-','').ToLowerInvariant();RequireReplacementIdle")
    if phase=='retire':
        start=source.index(' $afterProducts=');end=source.index('}catch{',start)
        source=source[:start]+" RequireReplacementContext $true;$retired=$installerExitCode -eq 0 -and $preserved\n if($retired){$phase='complete';Finish 'passed' 0}else{Finish 'failed' $installerExitCode;exit 1}\n"+source[end:]
    else:
        change(" if($installer.ExitCode -eq 0 -and $matched -and $preserved)"," RequireReplacementContext $false;$provisioned=$installerExitCode -eq 0 -and $matched -and $preserved\n if($provisioned)")
        # The freshly provisioned package code belongs to d32, not old c32.
        source=source.replace(" -or $package[1] -cne '{398537AF-50FB-4D8D-B9E9-B34FCB2547F4}'"," -or $package[1] -cne $expectedPackageCode")
        marker=" $phase='workspace';"
        package=" $expectedPackageCode=$null;$wi=New-Object -ComObject WindowsInstaller.Installer;$db=$null;$summary=$null;try{$db=$wi.OpenDatabase($msi,0);$summary=$db.SummaryInformation(0);$expectedPackageCode=[string]$summary.Property(9);if($expectedPackageCode -cnotmatch '^\\{[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}\\}$'){throw 'REPLACEMENT_PACKAGE_CODE'}}finally{if($null -ne $summary){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary)};if($null -ne $db){[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)};[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($wi)}\n"
        change(marker,package+marker)
    change("}catch{$errorType=","}catch{$retired=$false;$provisioned=$false;$errorType=")
    if len(source.encode())>65536 or root not in source:raise ValueError('replacement-task-source-bound')
    return source


REPLACEMENT_PARENT_TEMPLATE_SHA='8a03623995d07f5d5b8a2e126a0dffe45ad251546343e434b9afc2f401dc271f'
REPLACEMENT_PARENT_CORRELATION='6fecef7a-9094-44e6-a46b-8f01e64bc45c'
REPLACEMENT_PARENT_NONCE='95f34636-4b33-489b-a1e6-77c3f6ce1772'
REPLACEMENT_PARENT_TASK_SHA='9f7be3665c9c7563466d0249220a0c86756ae1f3ae0068655536b01a57f1c21c'

def replacement_body(template,phase,correlation,nonce,workspace_sha256=None):
    if type(template)is not str or hashlib.sha256(template.encode()).hexdigest()!=REPLACEMENT_PARENT_TEMPLATE_SHA:raise ValueError('replacement-parent-source')
    task=replacement_task(phase,correlation,nonce,workspace_sha256);task_sha=hashlib.sha256(task.encode()).hexdigest()
    source=template.replace(REPLACEMENT_PARENT_CORRELATION,correlation).replace(REPLACEMENT_PARENT_NONCE,nonce)
    if source.count(REPLACEMENT_PARENT_TASK_SHA)!=4 or source.count(str(21105))!=2:raise ValueError('replacement-task-bindings')
    source=source.replace(REPLACEMENT_PARENT_TASK_SHA,task_sha).replace(str(21105),str(len(task.encode())))
    source=source.replace("action='ordinary-admission-diagnostic'","action='explicit-baseline-"+phase+"'")
    if phase=='provision':
        # Keep the exact owner/process prelude and native reader definitions.
        # Installed-byte reads are inapplicable only after proved retirement.
        start=source.index('$jars=@(Get-ChildItem');end=source.index("$script:cp117OwnerDiagStage='package'",start)
        source=source[:start]+source[end:]
        start=source.index("if($products.Count -ne 1 -or $products[0].DisplayVersion")
        end=source.index('\n',start);source=source[:start]+source[end+1:]
        source=source.replace("$oldCode=$products[0].PSChildName.ToUpperInvariant()","$oldCode=''",1)
        source=source.replace("if($cp117ReadinessProof.code -cne 'READY' -or $cp117Task.state", "if($cp117ReadinessProof.productCount -ne 0 -or $cp117ReadinessProof.activeCount -ne 0 -or $cp117ReadinessProof.ownedExplorerCount -ne 1 -or $cp117Task.state",1)
        source=source.replace("$cp117Refresh.oldProductCode -cne '"+REPAIR_PRODUCT+"'","$cp117Refresh.oldProductCode -cne ''",1)
        start=source.index('if($cp117Package.cliSha256');end=source.index("$refreshRoot=",start);source=source[:start]+source[end:]
    start=source.index("$deadline=[Diagnostics.Stopwatch]::StartNew();$scratchPath=")
    end=source.index("}finally{if($null -ne $heldIntentParent)",start)
    # A submission receipt never waits for or classifies MSI completion. The
    # separate fixed collector observes this same task/files/client afterwards.
    source=source[:start]+"$cp117ReplacementSubmitted=@{version=1;correlationId='"+correlation+"';nonce='"+nonce+"';phaseKind='"+phase+"';state='submitted';taskName=$refreshTask;taskSourceSha256='"+task_sha+"';taskArgumentsSha256=$cp117ActionSha;taskAction=$true;installerAction=$true;installerCompleted=$false;credentialInput=$false;publicUpdateAcceptance=$false}\n"+source[end:]
    start=source.index('$cp117AccessProjection=');end=source.index("}catch{$cp117OwnerDiagError=",start)
    source=source[:start]+"[Console]::Out.WriteLine(($cp117ReplacementSubmitted|ConvertTo-Json -Depth 4 -Compress))\n"+source[end:]
    if source.count(task_sha)!=4 or len(source.encode())>65536:raise ValueError('replacement-parent-bound')
    return source,task


def validate_replacement_submission(value,phase,correlation,nonce,task_sha):
    fields={'version','correlationId','nonce','phaseKind','state','taskName','taskSourceSha256','taskArgumentsSha256','taskAction','installerAction','installerCompleted','credentialInput','publicUpdateAcceptance'}
    if type(value)is not dict or set(value)!=fields or type(value['version'])is not int or value['version']!=1 or value['phaseKind']!=phase or value['correlationId']!=correlation or value['nonce']!=nonce or value['state']!='submitted' or value['taskName']!='VpnControlMcpRefresh-'+correlation or value['taskSourceSha256']!=task_sha or type(value['taskArgumentsSha256'])is not str or re.fullmatch('[0-9a-f]{64}',value['taskArgumentsSha256'])is None:raise ValueError('replacement-submission')
    for key,want in {'taskAction':True,'installerAction':True,'installerCompleted':False,'credentialInput':False,'publicUpdateAcceptance':False}.items():
        if value[key]is not want:raise ValueError('replacement-submission-effect')
    return value


def replacement_completion(value,phase,correlation,nonce,before_sha256,after_sha256):
    fields={'version','correlationId','nonce','state','phase','phaseKind','errorType','errorHResult','exitCode','installerExitCode','originalSid','sessionId','limited','installerPid','installerBirth','actorPid','actorBirth','workspacePreserved','installedBytesMatched','retirementProven','provisioningProven','workspaceSha256','publicUpdateAcceptance'}
    if type(value)is not dict or set(value)!=fields or type(value['version'])is not int or value['version']!=1 or value['correlationId']!=correlation or value['nonce']!=nonce or value['phaseKind']!=phase or phase not in ('retire','provision') or value['state']not in ('passed','failed','unknown') or type(value['phase'])is not str or value['originalSid']!=installed.precise.owner.SID or type(value['sessionId'])is not int or value['sessionId']!=1 or value['limited']is not True or value['publicUpdateAcceptance']is not False:raise ValueError('replacement-completion-schema')
    for key in ('workspacePreserved','installedBytesMatched','retirementProven','provisioningProven'):
        if type(value[key])is not bool:raise ValueError('replacement-completion-boolean')
    for key in ('exitCode','installerExitCode'):
        if value[key]is not None and (type(value[key])is not int or not -2147483648<=value[key]<=2147483647):raise ValueError('replacement-completion-exit')
    if type(value['exitCode'])is not int:raise ValueError('replacement-completion-primary-exit')
    for pid,birth in (('actorPid','actorBirth'),('installerPid','installerBirth')):
        if value[pid]is None and value[birth]is None and value['state']!='passed':continue
        if type(value[pid])is not int or not 0<value[pid]<=2147483647 or type(value[birth])is not str or re.fullmatch('[1-9][0-9]{0,18}',value[birth])is None:raise ValueError('replacement-completion-generation')
    if value['errorType']is not None and (type(value['errorType'])is not str or len(value['errorType'])>256):raise ValueError('replacement-completion-error')
    if value['errorHResult']is not None and (type(value['errorHResult'])is not int or not -2147483648<=value['errorHResult']<=2147483647):raise ValueError('replacement-completion-error')
    if value['state']!='passed':
        if value['retirementProven']or value['provisioningProven']:raise ValueError('replacement-failed-promotion')
        return {'state':value['state'],'provisionAllowed':False,'installerExitCode':value['installerExitCode'],'publicUpdateAcceptance':False}
    if value['exitCode']!=0 or value['installerExitCode']!=0 or value['phase']!='complete' or value['errorType']is not None or value['errorHResult']is not None or value['workspacePreserved']is not True:raise ValueError('replacement-completion-predicate')
    if type(before_sha256)is not str or re.fullmatch('[0-9a-f]{64}',before_sha256)is None or before_sha256!=after_sha256:raise ValueError('replacement-workspace-conservation')
    sha=after_sha256
    if value['workspaceSha256']!=sha:raise ValueError('replacement-workspace-digest')
    if phase=='retire':
        if value['retirementProven']is not True or value['provisioningProven']is not False or value['installedBytesMatched']is not False:raise ValueError('replacement-retirement-predicate')
    elif value['provisioningProven']is not True or value['retirementProven']is not False or value['installedBytesMatched']is not True:raise ValueError('replacement-provision-predicate')
    return {'state':'passed','provisionAllowed':phase=='retire','workspaceSha256':sha,'installerExitCode':0,'publicUpdateAcceptance':False}


def replacement_collection_body(phase,correlation,nonce,task_arguments_sha256,workspace_sha256=None):
    """Fixed same-operation reader. Parameters are pinned by its reviewed caller."""
    task=replacement_task(phase,correlation,nonce,workspace_sha256)
    if type(task_arguments_sha256)is not str or re.fullmatch('[0-9a-f]{64}',task_arguments_sha256)is None:raise ValueError('replacement-action-binding')
    owner=installed.precise.body()
    marker=next(line for line in owner.splitlines()if "stage='complete'"in line and '[Console]::Out.WriteLine'in line)
    if owner.count(marker)!=1:raise ValueError('replacement-owner-slot')
    owner=owner.replace(marker,' $cp117ReplacementOwner=$facts')
    cs=installed.FILE_CS.replace('Cp117InstalledFile','Cp117ReplacementRecord').replace('f.Length<=0','f.Length<0')
    if installed.FILE_CS.count('f.Length<=0')!=1:raise ValueError('replacement-record-reader')
    root=REPAIR_ROOT.replace(REPAIR_CORRELATION,correlation)
    system='C:\\Windows\\Temp\\vpn-control-refresh-submit-'+correlation
    security=REFRESH_SECURITY_PS.split('function SetRefreshSecurity')[0]
    body=r'''$ErrorActionPreference='Stop';$me=[Security.Principal.WindowsIdentity]::GetCurrent();if($me.User.Value -cne 'S-1-5-18' -or (Get-Process -Id $PID).SessionId -ne 0){throw 'COLLECTOR_ACTOR'}
if($null -eq $cp117ReplacementOwner -or $cp117ReplacementOwner.explorers.Count -ne 1 -or $cp117ReplacementOwner.explorers[0].pid -ne 3804 -or $cp117ReplacementOwner.explorers[0].startFileTime -cne '134356192583360055' -or -not $cp117ReplacementOwner.explorers[0].expectedSid -or $cp117ReplacementOwner.explorers[0].sessionId -ne 1 -or $cp117ReplacementOwner.explorers[0].elevated -or $cp117ReplacementOwner.explorers[0].adminEnabled -or $cp117ReplacementOwner.explorers[0].adminMember -or $cp117ReplacementOwner.apps.Count -ne 0 -or $cp117ReplacementOwner.runtimeCount -ne 0){throw 'CURRENT_OWNER'}
Add-Type -AssemblyName System.IO.Compression
Add-Type -TypeDefinition @'
@RECORD_CS@
'@ -ReferencedAssemblies @('System','System.Core','System.IO.Compression')
Add-Type -TypeDefinition @'
@WORKSPACE_CS@
'@ -ReferencedAssemblies @('System','System.Core')
@SECURITY@
$root='@ROOT@';$system='@SYSTEM@';RequireRefreshSecurity $root '@SID@';RequireRefreshSecurity $system 'S-1-5-18'
$heldRoot=[Cp117RefreshWorkspace]::HoldDirectory($root);$heldSystem=[Cp117RefreshWorkspace]::HoldDirectory($system)
try{
function ReplacementTaskFacts{
 $rows=@(Get-ScheduledTask -TaskPath '\'|Where-Object {$_.TaskName -ceq 'VpnControlMcpRefresh-@CORR@'});if($rows.Count -ne 1){throw 'TASK_COUNT'};$item=$rows[0];$info=Get-ScheduledTaskInfo -TaskPath '\' -TaskName $item.TaskName;$actions=@($item.Actions);if($actions.Count -ne 1){throw 'TASK_ACTION_COUNT'}
 $who=if($item.Principal.UserId -like 'S-1-*'){$item.Principal.UserId}else{([Security.Principal.NTAccount]::new($item.Principal.UserId)).Translate([Security.Principal.SecurityIdentifier]).Value}
 $argumentSha=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($actions[0].Arguments))).Replace('-','').ToLowerInvariant()
 if($who -cne '@SID@' -or $item.Principal.LogonType.ToString() -cne 'Interactive' -or $item.Principal.RunLevel.ToString() -cne 'Limited' -or $actions[0].Execute -cne 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -or $argumentSha -cne '@ARG_SHA@'){throw 'TASK_BINDING'}
 return @{state=$item.State.ToString();sid=$who;logon='Interactive';level='Limited';argumentsSha256=$argumentSha;lastResult=$info.LastTaskResult;lastRun=$info.LastRunTime.ToUniversalTime().ToFileTimeUtc().ToString()}
}
$task=ReplacementTaskFacts;$taskPin=$task|ConvertTo-Json -Compress
$paths=@((Join-Path $system 'intent.json'),(Join-Path $root 'attempt.json'),(Join-Path $root 'installer.json'),(Join-Path $root 'result.json'),(Join-Path $root 'workspace-before.private'),(Join-Path $root 'workspace-after.private'),(Join-Path $root 'failure.private'));$files=@()
for($index=0;$index -lt 7;$index++){
 $path=$paths[$index];if(-not [IO.File]::Exists($path)){$files+=@{index=$index;state='absent'};continue}
 $first=[Cp117ReplacementRecord]::Read($path);$stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{$length=$stream.Length;if($length -gt 2097152 -or ($index -lt 4 -and $length -gt 4096) -or ($index -eq 6 -and $length -gt 4096)){throw 'REPLACEMENT_RECORD_BOUND'};$encoded=$null
  if($index -lt 4 -or $index -eq 6){$bytes=[byte[]]::new($length);$at=0;while($at -lt $bytes.Length){$n=$stream.Read($bytes,$at,$bytes.Length-$at);if($n -le 0){throw 'RECORD_SHORT'};$at+=$n};$encoded=[Convert]::ToBase64String($bytes)}
  $last=[Cp117ReplacementRecord]::Read($path);if($first[0] -cne $last[0] -or $first[1] -cne $last[1]){throw 'RECORD_DRIFT'}
  $files+=@{index=$index;state='file';sha256=$first[0];identity=$first[1];size=$length;bytesBase64=$encoded}
 }finally{$stream.Dispose()}
}
if((ReplacementTaskFacts|ConvertTo-Json -Compress) -cne $taskPin){throw 'TASK_DRIFT'}
RequireRefreshSecurity $root '@SID@';RequireRefreshSecurity $system 'S-1-5-18'
[Console]::Out.WriteLine((@{version=1;phaseKind='@PHASE@';correlationId='@CORR@';nonce='@NONCE@';taskSourceSha256='@TASK_SHA@';task=$task;files=$files;owner=$cp117ReplacementOwner;installerAction=$false;taskAction=$false;completionAuthority=$false;publicUpdateAcceptance=$false}|ConvertTo-Json -Depth 12 -Compress))
}finally{$heldRoot.Dispose();$heldSystem.Dispose()}
'''
    for before,after in {'@RECORD_CS@':cs,'@WORKSPACE_CS@':WORKSPACE_CS,'@SECURITY@':security,'@ROOT@':root,'@SYSTEM@':system,'@SID@':installed.precise.owner.SID,'@CORR@':correlation,'@NONCE@':nonce,'@ARG_SHA@':task_arguments_sha256,'@PHASE@':phase,'@TASK_SHA@':hashlib.sha256(task.encode()).hexdigest()}.items():body=body.replace(before,after)
    result=owner+'\n'+body
    if len(result.encode())>65536:raise ValueError('replacement-collection-source-bound')
    return result


def replacement_record_admission(value,phase,correlation,nonce,task_sha256,task_arguments_sha256):
    """Interpret only facts from the fixed authenticated same-task reader.

    Its caller additionally holds source/receipt/record generations before and
    after interpretation. This function cannot itself grant native permission.
    """
    fields={'version','phaseKind','correlationId','nonce','taskSourceSha256','task','files','owner','installerAction','taskAction','completionAuthority','publicUpdateAcceptance'}
    if type(value)is not dict or set(value)!=fields or type(value['version'])is not int or value['version']!=1 or value['phaseKind']!=phase or value['correlationId']!=correlation or value['nonce']!=nonce or value['taskSourceSha256']!=task_sha256:raise ValueError('replacement-collection-schema')
    for key in ('installerAction','taskAction','completionAuthority','publicUpdateAcceptance'):
        if value[key]is not False:raise ValueError('replacement-collection-effects')
    task=value['task']
    if type(task)is not dict or set(task)!={'state','sid','logon','level','argumentsSha256','lastResult','lastRun'}or task['sid']!=installed.precise.owner.SID or task['logon']!='Interactive' or task['level']!='Limited' or task['argumentsSha256']!=task_arguments_sha256 or task['state']not in ('Unknown','Disabled','Queued','Ready','Running')or type(task['lastResult'])is not int or not 0<=task['lastResult']<=4294967295 or type(task['lastRun'])is not str or re.fullmatch('[1-9][0-9]{0,18}',task['lastRun'])is None:raise ValueError('replacement-collected-task')
    owner=value['owner'];installed.precise.owner.validate_facts(owner)
    if len(owner['explorers'])!=1 or owner['explorers'][0]['pid']!=3804 or owner['explorers'][0]['startFileTime']!='134356192583360055'or owner['apps'] or owner['runtimeCount']!=0:raise ValueError('replacement-current-owner')
    files=value['files']
    if type(files)is not list or len(files)!=7:raise ValueError('replacement-record-catalogue')
    decoded={}
    for index,row in enumerate(files):
        if type(row)is not dict or type(row.get('index'))is not int or row['index']!=index or row.get('state')not in ('absent','file'):raise ValueError('replacement-record-index')
        if row['state']=='absent':
            if set(row)!={'index','state'}:raise ValueError('replacement-record-absence')
            continue
        if set(row)!={'index','state','sha256','identity','size','bytesBase64'}or type(row['size'])is not int or not 0<=row['size']<=2097152 or type(row['sha256'])is not str or re.fullmatch('[0-9a-f]{64}',row['sha256'])is None or type(row['identity'])is not str or re.fullmatch('[0-9]+(:[0-9]+){10}',row['identity'])is None:raise ValueError('replacement-record-pin')
        if index<4 or index==6:
            if row['size']>4096 or type(row['bytesBase64'])is not str:raise ValueError('replacement-small-record')
            raw=base64.b64decode(row['bytesBase64'],validate=True)
            if len(raw)!=row['size']or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('replacement-record-bytes')
            if index<4:decoded[index]=json.loads(raw)
        elif row['bytesBase64']is not None:raise ValueError('replacement-workspace-content')
    if task['state']!='Ready':return {'state':'pending','provisionAllowed':False,'publicUpdateAcceptance':False}
    if not all(index in decoded for index in range(4)):return {'state':'unknown','provisionAllowed':False,'publicUpdateAcceptance':False}
    intent,attempt,installer,result=(decoded[index]for index in range(4))
    for row in (intent,attempt,installer,result):
        if type(row)is not dict or type(row.get('version'))is not int or row['version']!=1 or row.get('correlationId')!=correlation or row.get('nonce')!=nonce:raise ValueError('replacement-journal-binding')
    if intent.get('sourceSha256')!=task_sha256 or intent.get('action')!='explicit-baseline-'+phase or intent.get('taskArgumentsSha256')!=task_arguments_sha256 or intent.get('state')!='consumed' or intent.get('publicUpdateAcceptance')is not False or attempt.get('state')!='consumed' or attempt.get('action')!='explicit-baseline-'+phase or attempt.get('sid')!=installed.precise.owner.SID or type(attempt.get('sessionId'))is not int or attempt['sessionId']!=1 or attempt.get('msiSha256')!=BASE_HASH or attempt.get('msiIdentity')!=REPAIR_MSI_IDENTITY:raise ValueError('replacement-intent-binding')
    if attempt.get('actorPid')!=result.get('actorPid')or type(attempt.get('actorPid'))is not int or attempt.get('actorBirth')!=result.get('actorBirth')or installer.get('pid')!=result.get('installerPid')or type(installer.get('pid'))is not int or installer.get('startFileTime')!=result.get('installerBirth')or installer.get('commandSha256')!=replacement_client_command_sha256(phase,correlation):raise ValueError('replacement-client-generation')
    if result.get('state')!='passed':
        return replacement_completion(result,phase,correlation,nonce,None,None)
    if task['lastResult']!=0:raise ValueError('replacement-terminal-task-result')
    if files[4]['state']!='file'or files[5]['state']!='file'or files[4]['size']<=0 or files[4]['size']!=files[5]['size']or files[4]['sha256']!=files[5]['sha256']:raise ValueError('replacement-bound-workspace')
    return replacement_completion(result,phase,correlation,nonce,files[4]['sha256'],files[5]['sha256'])


def replacement_client_command_sha256(phase,correlation):
    # This closed literal is compared in routine checks with the actual emitted
    # argument expression. It is not a general command selector.
    root=REPAIR_ROOT.replace(REPAIR_CORRELATION,correlation)
    if phase=='retire':command='/x '+REPAIR_PRODUCT+' /qn /norestart REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable /L*v "'+root+'\\retirement-msi.log"'
    elif phase=='provision':command='/i "'+DOWNLOADED_CANDIDATE+'" /qn /norestart REBOOT=ReallySuppress MSIRESTARTMANAGERCONTROL=Disable ALLUSERS=2 MSIINSTALLPERUSER=1 /L*v "'+root+'\\provision-msi.log"'
    else:raise ValueError('replacement-command-phase')
    return hashlib.sha256(command.encode()).hexdigest()


def replacement_retirement_admission(submission_record,collection_record,correlation,nonce,task_sha256):
    """Called only after a concrete caller authenticates both held receipts.

    This is a preparation decision, not current VM or native effect authority.
    Provision repeats fresh context/idle/source/owner/workspace gates itself.
    """
    for row in (submission_record,collection_record):
        if type(row)is not dict or set(row)!={'result','events'}or type(row['events'])is not list or not row['events']or type(row['result'])is not dict or row['result'].get('state')!='observed'or type(row['result'].get('facts'))is not dict:raise ValueError('replacement-retirement-receipt')
    submitted=validate_replacement_submission(submission_record['result']['facts'],'retire',correlation,nonce,task_sha256)
    answer=replacement_record_admission(collection_record['result']['facts'],'retire',correlation,nonce,task_sha256,submitted['taskArgumentsSha256'])
    if answer.get('state')!='passed'or answer.get('provisionAllowed')is not True:raise ValueError('replacement-retirement-not-complete')
    return {'state':'prepared','workspaceSha256':answer['workspaceSha256'],'retirementCompleted':True,'currentVmAdmission':False,'installerAction':False,'publicUpdateAcceptance':False}

# Read-only reconciliation is distinct from the immutable retirement result.
RETIREMENT_RECOVERY_TOKEN_CS=r'''using System;using System.Runtime.InteropServices;using System.Security.Principal;using System.ComponentModel;
public static class Cp117RecoverySnapshot{
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,int p);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr p,out long c,out long e,out long k,out long u);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool DuplicateToken(IntPtr t,int level,out IntPtr d);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool GetTokenInformation(IntPtr t,int kind,out int data,int size,out int n);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool ImpersonateLoggedOnUser(IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)]static extern bool RevertToSelf();
 static void Birth(IntPtr p){long c,e,k,u;if(!GetProcessTimes(p,out c,out e,out k,out u)||c!=134356192583360055L||e!=0)throw new InvalidOperationException("RECOVERY_TOKEN_BIRTH");}
 static int Info(IntPtr t,int kind){int v,n;if(!GetTokenInformation(t,kind,out v,4,out n)||n!=4)throw new Win32Exception(Marshal.GetLastWin32Error());return v;}
 public static string Read(){IntPtr p=IntPtr.Zero,t=IntPtr.Zero,d=IntPtr.Zero;bool impersonated=false;
  try{using(var system=WindowsIdentity.GetCurrent()){if(system.User.Value!="S-1-5-18")throw new InvalidOperationException("RECOVERY_SYSTEM");}
   p=OpenProcess(0x1000,false,3804);if(p==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());Birth(p);
   if(!OpenProcessToken(p,10,out t))throw new Win32Exception(Marshal.GetLastWin32Error());
   using(var id=new WindowsIdentity(t)){if(id.User.Value!="S-1-5-21-2404255130-2183793310-3766671872-1002"||Info(t,12)!=1||Info(t,20)!=0||Info(t,18)!=1||new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator))throw new InvalidOperationException("RECOVERY_TOKEN_IDENTITY");}
   if(!DuplicateToken(t,2,out d))throw new Win32Exception(Marshal.GetLastWin32Error());Birth(p);
   if(!ImpersonateLoggedOnUser(d))throw new Win32Exception(Marshal.GetLastWin32Error());impersonated=true;string snapshot;
   try{using(var id=WindowsIdentity.GetCurrent()){if(id.User.Value!="S-1-5-21-2404255130-2183793310-3766671872-1002")throw new InvalidOperationException("RECOVERY_IMPERSONATION");}snapshot=Cp117RefreshWorkspace.Snapshot("C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\cp166\\state");}
   finally{if(!RevertToSelf())throw new Win32Exception(Marshal.GetLastWin32Error());impersonated=false;}
   Birth(p);using(var id=WindowsIdentity.GetCurrent()){if(id.User.Value!="S-1-5-18")throw new InvalidOperationException("RECOVERY_REVERT");}return snapshot;
  }finally{bool failed=impersonated&&!RevertToSelf();if(d!=IntPtr.Zero)CloseHandle(d);if(t!=IntPtr.Zero)CloseHandle(t);if(p!=IntPtr.Zero)CloseHandle(p);if(failed)throw new Win32Exception(Marshal.GetLastWin32Error());}
 }
}'''


def retirement_recovery_body(correlation,nonce,arguments_sha256):
    source=replacement_collection_body('retire',correlation,nonce,arguments_sha256)
    line=next(x for x in source.splitlines()if x.startswith('[Console]::Out.WriteLine((@{version=1;phaseKind='))
    expression=line[len('[Console]::Out.WriteLine(('):-2].removesuffix('|ConvertTo-Json -Depth 12 -Compress')
    # Explicit expected SID for user contexts under SYSTEM; machine requires null.
    cs=REPLACEMENT_CONTEXT_CS.replace('Cp117ReplacementContext','Cp117RecoveryContext')
    cs=cs.replace('MsiEnumProductsExW(Product,null,requested,','MsiEnumProductsExW(Product,requested==4?null:"'+installed.precise.owner.SID+'",requested,')
    if cs.count('requested==4?null:')!=2:raise ValueError('recovery-context-source')
    extra=r'''$cp117RecoveryOriginal=(@EXPRESSION@)
Add-Type -TypeDefinition @'
@CONTEXT_CS@
'@ -ReferencedAssemblies @('System','System.Core')
Add-Type -TypeDefinition @'
@TOKEN_CS@
'@ -ReferencedAssemblies @('System','System.Core')
@IDLE@
$cp117Contexts=@();for($index=0;$index -lt 3;$index++){[string[]]$row=[Cp117RecoveryContext]::Read($index);$cp117Contexts+=@{requested=[int]$row[0];code=[int]$row[1];actual=[int]$row[2];sid=$row[3];nextCode=[int]$row[4]}}
$cp117ContextsPin=$cp117Contexts|ConvertTo-Json -Compress
RequireReplacementIdle
$cp117MsiBefore=[Cp117ReplacementRecord]::Read('@MSI@');if($cp117MsiBefore[0] -cne '@MSI_SHA@' -or $cp117MsiBefore[1] -cne '@MSI_ID@'){throw 'RECOVERY_MSI'}
$cp117Workspace=[Cp117RecoverySnapshot]::Read();$cp117WorkspaceSize=[Text.Encoding]::UTF8.GetByteCount($cp117Workspace);if($cp117WorkspaceSize -le 0 -or $cp117WorkspaceSize -gt 2097152){throw 'RECOVERY_WORKSPACE_BOUND'}
$cp117WorkspaceSha=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($cp117Workspace))).Replace('-','').ToLowerInvariant()
$cp117MsiAfter=[Cp117ReplacementRecord]::Read('@MSI@');if(($cp117MsiAfter -join '|') -cne ($cp117MsiBefore -join '|')){throw 'RECOVERY_MSI_DRIFT'}
$cp117ContextsAgain=@();for($index=0;$index -lt 3;$index++){[string[]]$row=[Cp117RecoveryContext]::Read($index);$cp117ContextsAgain+=@{requested=[int]$row[0];code=[int]$row[1];actual=[int]$row[2];sid=$row[3];nextCode=[int]$row[4]}}
if(($cp117ContextsAgain|ConvertTo-Json -Compress) -cne $cp117ContextsPin){throw 'RECOVERY_CONTEXT_DRIFT'};RequireReplacementIdle
for($index=0;$index -lt 7;$index++){if($files[$index].state -ceq 'file'){$closing=[Cp117ReplacementRecord]::Read($paths[$index]);if($closing[0] -cne $files[$index].sha256 -or $closing[1] -cne $files[$index].identity){throw 'RECOVERY_RECORD_DRIFT'}}elseif([IO.File]::Exists($paths[$index])){throw 'RECOVERY_RECORD_DRIFT'}}
if((ReplacementTaskFacts|ConvertTo-Json -Compress) -cne $taskPin){throw 'TASK_DRIFT'};RequireRefreshSecurity $root '@SID@';RequireRefreshSecurity $system 'S-1-5-18'
$cp117RecoveryJson=(@{version=1;original=$cp117RecoveryOriginal;contexts=$cp117Contexts;idle=$true;rebootAbsent=$true;workspaceSha256=$cp117WorkspaceSha;workspaceBytes=$cp117WorkspaceSize;baseSha256=$cp117MsiBefore[0];baseIdentity=$cp117MsiBefore[1];tokenPid=3804;tokenBirth='134356192583360055';tokenSid='@SID@';tokenSession=1;tokenLimited=$true;systemReverted=$true;installerAction=$false;taskAction=$false;completionAuthority=$false;publicUpdateAcceptance=$false}|ConvertTo-Json -Depth 14 -Compress)
if([Text.Encoding]::UTF8.GetByteCount($cp117RecoveryJson) -gt 20000){throw 'RECOVERY_PROJECTION_BOUND'};[Console]::Out.WriteLine($cp117RecoveryJson)
'''
    idle=REPLACEMENT_CONTEXT_PS[REPLACEMENT_CONTEXT_PS.index('function RequireReplacementIdle'):]
    for before,after in {'@EXPRESSION@':expression,'@CONTEXT_CS@':cs,'@TOKEN_CS@':retirement_recovery_token_assembly(),'@IDLE@':idle,'@MSI@':DOWNLOADED_CANDIDATE,'@MSI_SHA@':BASE_HASH,'@MSI_ID@':REPAIR_MSI_IDENTITY,'@SID@':installed.precise.owner.SID}.items():extra=extra.replace(before,after)
    source=source.replace(line,extra)
    if len(source.encode())>65536:raise ValueError('recovery-source-bound')
    return source


def retirement_recovery_observation(value,correlation,nonce,task_sha,arguments_sha):
    fields={'version','original','contexts','idle','rebootAbsent','workspaceSha256','workspaceBytes','baseSha256','baseIdentity','tokenPid','tokenBirth','tokenSid','tokenSession','tokenLimited','systemReverted','installerAction','taskAction','completionAuthority','publicUpdateAcceptance'}
    if type(value)is not dict or set(value)!=fields or type(value['version'])is not int or value['version']!=1:raise ValueError('recovery-schema')
    for key in ('installerAction','taskAction','completionAuthority','publicUpdateAcceptance'):
        if value[key]is not False:raise ValueError('recovery-effects')
    for key in ('idle','rebootAbsent','tokenLimited','systemReverted'):
        if value[key]is not True:raise ValueError('recovery-unsafe')
    if type(value['tokenPid'])is not int or value['tokenPid']!=3804 or value['tokenBirth']!='134356192583360055' or value['tokenSid']!=installed.precise.owner.SID or type(value['tokenSession'])is not int or value['tokenSession']!=1 or value['baseSha256']!=BASE_HASH or value['baseIdentity']!=REPAIR_MSI_IDENTITY:raise ValueError('recovery-identity')
    if type(value['workspaceBytes'])is not int or not 0<value['workspaceBytes']<=2097152 or type(value['workspaceSha256'])is not str or re.fullmatch('[0-9a-f]{64}',value['workspaceSha256'])is None:raise ValueError('recovery-workspace')
    replacement_record_admission(value['original'],'retire',correlation,nonce,task_sha,arguments_sha)
    contexts=value['contexts']
    if type(contexts)is not list or len(contexts)!=3:raise ValueError('recovery-contexts')
    for row,requested in zip(contexts,(1,2,4)):
        if type(row)is not dict or set(row)!={'requested','code','actual','sid','nextCode'}or any(type(row[k])is not int for k in ('requested','code','actual','nextCode'))or row['requested']!=requested or row['code']not in (0,259)or row['nextCode']!=259:raise ValueError('recovery-context-row')
        if row['code']==259:
            if row['actual']!=0 or row['sid']is not None:raise ValueError('recovery-context-absence')
        elif row['actual']!=requested or row['sid']!=('' if requested==4 else installed.precise.owner.SID):raise ValueError('recovery-context-owner')
    return value


def retirement_recovery_admission(submission,old_collection,fresh_collection,correlation,nonce,task_sha):
    # Call only after concrete held receipt/source/frame/nonce/birth authentication.
    for receipt in (submission,old_collection,fresh_collection):
        if type(receipt)is not dict or set(receipt)!={'result','events'}or type(receipt['events'])is not list or not receipt['events']or type(receipt['result'])is not dict or receipt['result'].get('state')!='observed':raise ValueError('recovery-receipt')
    submitted=validate_replacement_submission(submission['result']['facts'],'retire',correlation,nonce,task_sha)
    old=old_collection['result']['facts'];answer=replacement_record_admission(old,'retire',correlation,nonce,task_sha,submitted['taskArgumentsSha256'])
    fresh=retirement_recovery_observation(fresh_collection['result']['facts'],correlation,nonce,task_sha,submitted['taskArgumentsSha256'])
    if fresh['original']!=old or answer['state']!='unknown' or answer.get('installerExitCode')!=0:raise ValueError('recovery-original-binding')
    rows=old['files'];result=json.loads(base64.b64decode(rows[3]['bytesBase64'],validate=True));failure=base64.b64decode(rows[6]['bytesBase64'],validate=True)
    if result['phase']!='readback' or result['exitCode']!=-1 or result['workspacePreserved']is not True or result['retirementProven']is not False or failure!=b'System.Management.Automation.RuntimeException: ACTIVE_PROCESS':raise ValueError('recovery-causal-boundary')
    if rows[4]['state']!='file' or rows[5]['state']!='file' or rows[4]['sha256']!=rows[5]['sha256'] or rows[4]['size']!=rows[5]['size'] or fresh['workspaceBytes']!=rows[5]['size'] or fresh['workspaceSha256']!=rows[5]['sha256'] or result['workspaceSha256']!=rows[5]['sha256']:raise ValueError('recovery-conservation')
    if any(row['code']!=259 for row in fresh['contexts']):raise ValueError('recovery-product-still-present')
    return {'state':'reconciled','originalState':'unknown','clientExitCode':0,'workspaceSha256':fresh['workspaceSha256'],'currentUserAndMachineAbsent':True,'currentVmAdmission':False,'installerAction':False,'provisionAllowed':True,'publicUpdateAcceptance':False}


def retirement_recovery_token_assembly():
    # Two fixed complete source units, not a generic C# rewriting facility.
    sources=(WORKSPACE_CS.replace('Cp117RefreshWorkspace','Cp117RecoveryWorkspace'),RETIREMENT_RECOVERY_TOKEN_CS.replace('Cp117RefreshWorkspace.Snapshot','Cp117RecoveryWorkspace.Snapshot'))
    directives=[];bodies=[]
    for source in sources:
        matches=list(re.finditer(r'using [A-Za-z.]+;',source));first=source.index('public ')
        if not matches or any(match.start()>=first for match in matches):raise ValueError('recovery-using-catalogue')
        directives.extend(match.group(0)for match in matches)
        bodies.append(re.sub(r'using [A-Za-z.]+;','',source))
    return ''.join(dict.fromkeys(directives))+bodies[0]+'\n'+bodies[1]


def retirement_recovery_compiler_body(correlation,nonce,arguments_sha256):
    old=WORKSPACE_CS.replace('Cp117RefreshWorkspace','Cp117RecoveryWorkspace')+'\n'+RETIREMENT_RECOVERY_TOKEN_CS.replace('Cp117RefreshWorkspace.Snapshot','Cp117RecoveryWorkspace.Snapshot')
    current=retirement_recovery_token_assembly();reader=retirement_recovery_body(correlation,nonce,arguments_sha256);ps=installed.public._ps_literal
    script="$ErrorActionPreference='Stop';$oldRejected=$false;$oldType=$null;try{Add-Type -TypeDefinition "+ps(old)+" -ReferencedAssemblies @('System','System.Core')}catch{$oldRejected=$true;$oldType=$_.Exception.GetBaseException().GetType().Name;[Console]::Error.WriteLine(($_|Out-String))};if(-not $oldRejected){throw 'OLD_COMPILER_REFUSAL_MISSING'};Add-Type -TypeDefinition "+ps(current)+" -ReferencedAssemblies @('System','System.Core');$reader="+ps(reader)+";$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseInput($reader,[ref]$tokens,[ref]$errors);if($errors.Count -ne 0){[Console]::Error.WriteLine(($errors|Out-String));throw 'RECOVERY_PARSE_UNKNOWN'};[Console]::Out.WriteLine((@{version=1;oldCompilerRejected=$oldRejected;currentCompilerPassed=$true;readerParserPassed=$true;tokenInvoked=$false;installerAction=$false;taskAction=$false;completionAuthority=$false}|ConvertTo-Json -Compress))"
    if len(script.encode())>65536:raise ValueError('recovery-compiler-body-bound')
    return script


def validate_replacement_busy_observation(value):
    if type(value)is not dict or set(value)!={'version','totalCount','overflow','rows'}or type(value['version'])is not int or value['version']!=1 or type(value['totalCount'])is not int or not 1<=value['totalCount']<=4096 or type(value['overflow'])is not bool or value['overflow']!=(value['totalCount']>32)or type(value['rows'])is not list or len(value['rows'])!=min(32,value['totalCount']):raise ValueError('replacement-busy-schema')
    seen=set()
    for row in value['rows']:
        if type(row)is not dict or set(row)!={'pid','name','sessionId','birth','sid','executable','querySuccess','errorType','errorHResult'}or type(row['pid'])is not int or not 1<=row['pid']<=2147483647 or row['pid']in seen or row['name']not in ('vpn-control.exe','vpn-control-cli.exe','msiexec.exe','consent.exe','sing-box.exe')or type(row['sessionId'])is not int or not 0<=row['sessionId']<=65535 or type(row['querySuccess'])is not bool:raise ValueError('replacement-busy-row')
        seen.add(row['pid'])
        if row['birth']is not None and(type(row['birth'])is not str or re.fullmatch('[1-9][0-9]{0,18}',row['birth'])is None):raise ValueError('replacement-busy-birth')
        if row['sid']is not None and(type(row['sid'])is not str or len(row['sid'])>184 or re.fullmatch('S-1-[0-9]+(-[0-9]+)+',row['sid'])is None):raise ValueError('replacement-busy-sid')
        if row['executable']is not None and(type(row['executable'])is not str or not 1<=len(row['executable'])<=4096 or any(ord(c)<32 for c in row['executable'])):raise ValueError('replacement-busy-executable')
        if row['querySuccess']:
            if any(row[key]is None for key in ('birth','sid','executable'))or row['errorType']is not None or row['errorHResult']is not None:raise ValueError('replacement-busy-success')
        elif type(row['errorType'])is not str or re.fullmatch('[A-Za-z][A-Za-z0-9]{0,127}',row['errorType'])is None or type(row['errorHResult'])is not int or not -2147483648<=row['errorHResult']<=2147483647:raise ValueError('replacement-busy-failure')
    return value


def provision_recovery_body(correlation,nonce,arguments_sha256,workspace_sha256,*,recorded_task_sha256):
    # Reuse the natively proved snapshot/token/closing reader. Replace only its
    # original record prefix with the exact same provision-operation catalogue.
    old=replacement_collection_body('retire',correlation,nonce,arguments_sha256)
    current=replacement_collection_body('provision',correlation,nonce,arguments_sha256,workspace_sha256)
    line=next(x for x in old.splitlines()if x.startswith('[Console]::Out.WriteLine((@{version=1;phaseKind='))
    current_line=next(x for x in current.splitlines()if x.startswith('[Console]::Out.WriteLine((@{version=1;phaseKind='))
    if type(recorded_task_sha256)is not str or re.fullmatch('[0-9a-f]{64}',recorded_task_sha256)is None:raise ValueError('provision-recorded-task-source')
    generated_task_sha=hashlib.sha256(replacement_task('provision',correlation,nonce,workspace_sha256).encode()).hexdigest()
    task_marker="taskSourceSha256='"+generated_task_sha+"'"
    if current_line.count(task_marker)!=1:raise ValueError('provision-recorded-task-slot')
    original_current_line=current_line
    current_line=current_line.replace(task_marker,"taskSourceSha256='"+recorded_task_sha256+"'",1)
    current=current.replace(original_current_line,current_line,1)
    source=retirement_recovery_body(correlation,nonce,arguments_sha256)
    prefix=old[:old.index(line)];current_prefix=current[:current.index(current_line)]
    if not source.startswith(prefix):raise ValueError('provision-recovery-prefix')
    source=current_prefix+source[len(prefix):]
    before=line[len('[Console]::Out.WriteLine(('):-2].removesuffix('|ConvertTo-Json -Depth 12 -Compress')
    after=current_line[len('[Console]::Out.WriteLine(('):-2].removesuffix('|ConvertTo-Json -Depth 12 -Compress')
    if source.count('$cp117RecoveryOriginal=('+before+')')!=1:raise ValueError('provision-recovery-record-expression')
    source=source.replace('$cp117RecoveryOriginal=('+before+')','$cp117RecoveryOriginal=('+after+')',1)
    # SYSTEM is not the installed per-user principal. These two fixed MSI info
    # properties use the same explicit expected SID as the context enumeration.
    needle='MsiGetProductInfoExW(Product,null,2,property,'
    if source.count(needle)!=1:raise ValueError('provision-recovery-info-source')
    source=source.replace(needle,'MsiGetProductInfoExW(Product,"'+installed.precise.owner.SID+'",2,property,',1)
    readiness=installed.precise.owner.guest.recovery.authority.closure.base._readiness_script('2.1.19',installed.precise.owner.SID)
    marker=next(x for x in readiness.splitlines()if '[Console]::Out.WriteLine(([pscustomobject]'in x)
    expression=marker.strip()[len('[Console]::Out.WriteLine(('):-2].removesuffix('|ConvertTo-Json -Depth 5 -Compress')
    readiness=readiness.replace(marker,' $cp117CurrentReadiness='+expression)
    package=installed.PACKAGE_PS.replace('@FILE_CS@',installed.FILE_CS).replace('@JAR_NAME@',installed.PAIR_EXPECTED['baseAppJarName'])
    marker=next(x for x in package.splitlines()if x.startswith('[Console]::Out.WriteLine'))
    package=package.replace(marker,'')
    projection='$cp117RecoveryJson=(@{version=1;original='
    if source.count(projection)!=1:raise ValueError('provision-recovery-projection')
    extra=readiness+'\n'+package+"\n[string[]]$cp117CurrentPackage=[Cp117RecoveryContext]::Info('PackageCode');[string[]]$cp117CurrentVersion=[Cp117RecoveryContext]::Info('VersionString')\n"
    extra+="[string[]]$cp117CurrentPackageAgain=[Cp117RecoveryContext]::Info('PackageCode');[string[]]$cp117CurrentVersionAgain=[Cp117RecoveryContext]::Info('VersionString');if(($cp117CurrentPackageAgain -join '|') -cne ($cp117CurrentPackage -join '|') -or ($cp117CurrentVersionAgain -join '|') -cne ($cp117CurrentVersion -join '|')){throw 'PROVISION_REGISTERED_DRIFT'};for($index=0;$index -lt 3;$index++){[string[]]$row=[Cp117RecoveryContext]::Read($index);if(($row -join '|') -cne (@($cp117Contexts[$index].requested,$cp117Contexts[$index].code,$cp117Contexts[$index].actual,$cp117Contexts[$index].sid,$cp117Contexts[$index].nextCode) -join '|')){throw 'PROVISION_CONTEXT_DRIFT'}};if([Cp117RecoverySnapshot]::Read() -cne $cp117Workspace){throw 'PROVISION_WORKSPACE_DRIFT'};RequireReplacementIdle\n"
    source=source.replace(projection,extra+projection,1)
    source=source.replace('version=1;original=$cp117RecoveryOriginal;contexts=','version=1;original=$cp117RecoveryOriginal;currentReadiness=$cp117CurrentReadiness;currentPackage=$cp117Package;registeredPackageCode=$cp117CurrentPackage;registeredVersion=$cp117CurrentVersion;contexts=',1)
    source='$rootCreated=$false\n'+source
    if source.count("throw 'ACTIVE_PROCESS'")!=1:raise ValueError('provision-busy-projection-source')
    source=source.replace("throw 'ACTIVE_PROCESS'","[Console]::Error.WriteLine(('CP117-BUSY '+$cp117BusyJson));throw 'ACTIVE_PROCESS'",1)
    if len(source.encode())>65536:raise ValueError('provision-recovery-source-bound')
    return source


def provision_recovery_observation(value,correlation,nonce,task_sha,arguments_sha):
    extras={'currentReadiness','currentPackage','registeredPackageCode','registeredVersion'}
    if type(value)is not dict or not extras.issubset(value):raise ValueError('provision-recovery-fields')
    basic={key:item for key,item in value.items()if key not in extras}
    # Fixed schema/identity checks are unchanged; only the original operation
    # record validator is the provision validator instead of retirement.
    original=basic['original'];replacement_record_admission(original,'provision',correlation,nonce,task_sha,arguments_sha)
    # Reuse the structural/token/context checks without reinterpreting journals.
    fields={'version','original','contexts','idle','rebootAbsent','workspaceSha256','workspaceBytes','baseSha256','baseIdentity','tokenPid','tokenBirth','tokenSid','tokenSession','tokenLimited','systemReverted','installerAction','taskAction','completionAuthority','publicUpdateAcceptance'}
    if set(basic)!=fields or type(basic['version'])is not int or basic['version']!=1:raise ValueError('provision-recovery-schema')
    if any(basic[k]is not False for k in ('installerAction','taskAction','completionAuthority','publicUpdateAcceptance'))or any(basic[k]is not True for k in ('idle','rebootAbsent','tokenLimited','systemReverted')):raise ValueError('provision-recovery-effects')
    if type(basic['tokenPid'])is not int or basic['tokenPid']!=3804 or basic['tokenBirth']!='134356192583360055' or basic['tokenSid']!=installed.precise.owner.SID or type(basic['tokenSession'])is not int or basic['tokenSession']!=1 or basic['baseSha256']!=BASE_HASH or basic['baseIdentity']!=REPAIR_MSI_IDENTITY:raise ValueError('provision-recovery-token')
    if type(basic['workspaceBytes'])is not int or not 0<basic['workspaceBytes']<=2097152 or type(basic['workspaceSha256'])is not str or re.fullmatch('[0-9a-f]{64}',basic['workspaceSha256'])is None:raise ValueError('provision-recovery-workspace')
    rows=basic['contexts']
    if type(rows)is not list or len(rows)!=3:raise ValueError('provision-recovery-contexts')
    for row,requested in zip(rows,(1,2,4)):
        if type(row)is not dict or set(row)!={'requested','code','actual','sid','nextCode'}or any(type(row[k])is not int for k in ('requested','code','actual','nextCode'))or row['requested']!=requested or row['code']not in (0,259)or row['nextCode']!=259 or (row['code']==259 and(row['actual']!=0 or row['sid']is not None))or(row['code']==0 and(row['actual']!=requested or row['sid']!=(None if requested==4 else installed.precise.owner.SID))):raise ValueError('provision-recovery-context-row')
    for key in ('registeredPackageCode','registeredVersion'):
        row=value[key]
        if type(row)is not list or len(row)!=2 or row[0]not in ('0','1605','1608')or(row[0]!='0'and row[1]is not None)or(row[0]=='0'and(type(row[1])is not str or len(row[1])>512)):raise ValueError('provision-recovery-property')
    # The actual installed reader's strict schema/hash/signer validator is
    # reused. Mismatches remain observations rather than admission grants.
    validate_provision_package_projection(value['currentReadiness'],value['currentPackage'])
    return value


def validate_provision_package_projection(readiness,package):
    keys={'version','code','installedVersion','productCount','activeCount','activeKinds','activeProcesses','workspaceLockPid','ownedExplorerCount'}
    if type(readiness)is not dict or set(readiness)!=keys or type(readiness['version'])is not int or readiness['version']!=1 or readiness['code']not in {'READY','PRODUCT_COUNT','PRODUCT_VERSION','ACTIVE_PROCESS','SESSION_OWNER'}:raise ValueError('provision-readiness-schema')
    for key in ('productCount','activeCount','ownedExplorerCount'):
        if type(readiness[key])is not int or not 0<=readiness[key]<=64:raise ValueError('provision-readiness-count')
    if readiness['installedVersion']is not None and(type(readiness['installedVersion'])is not str or re.fullmatch(r'(?:[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])',readiness['installedVersion'])is None):raise ValueError('provision-readiness-version')
    if readiness['activeCount']!=0 or readiness['activeKinds']!=[]or readiness['activeProcesses']!=[]:raise ValueError('provision-readiness-active')
    if readiness['workspaceLockPid']is not None and(type(readiness['workspaceLockPid'])is not int or readiness['workspaceLockPid']<=0):raise ValueError('provision-workspace-lock')
    if type(package)is not dict or set(package)!={'jarCount','registeredPathMatches','jarNameMatches','cliSha256','jarSha256','helperSha256','runtimeSha256','cliSignerStatus','helperSignerStatus','identitiesStable'}or type(package['jarCount'])is not int or package['jarCount']!=1 or type(package['registeredPathMatches'])is not bool or type(package['jarNameMatches'])is not bool or package['identitiesStable']is not True:raise ValueError('provision-package-schema')
    for key in ('cliSha256','jarSha256','helperSha256','runtimeSha256'):
        if type(package[key])is not str or re.fullmatch('[0-9a-f]{64}',package[key])is None:raise ValueError('provision-package-hash')
    signers={'Valid','UnknownError','NotSigned','HashMismatch','NotTrusted','NotSupportedFileFormat','Incompatible'}
    if package['cliSignerStatus']not in signers or package['helperSignerStatus']not in signers:raise ValueError('provision-package-signer')
    return {'readiness':readiness,'package':package}
