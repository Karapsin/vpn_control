"""One fixed, read-only diagnosis of the recovered CP117 owner census."""
import ast,base64,hashlib,json,os
from pathlib import Path
from . import windows_cp117_recovered_owner_observe as owner
from . import windows_cp117_windowless_provider_login as flow
from .windows_diagnostic_authority_capture import AuthorityCapture

CORRELATION='8ca43fbe-7d90-4267-96fa-bc0113f30c43'
NONCE='0580ab4b-677a-4b12-b88e-9c6ffbfad2cd'
OWNER_SHA='9ff8275a77e71e8b1a7ae90ee4e7dd5a1910ad130720e4621ff85a6fe9b38342'
FLOW_SHA='f54029cf3259011d71df93c51f15b3c2b7a886470008427cf85c8e127c567a72'
ORIGINAL_LOGIN_LEAF='windows-cp117-provider-login-9dbd4008-7f34-4e1d-85a6-f3f30ea7fdc0'
ORIGINAL_UNKNOWN={'sha256':'69dbdba92e02ca98b054849ebf04fe65ed61a59d85d893ed1ffd7c45b03fbed8','generation':[16777234,112830854,33152,503,20,1,101431,1791145663307559327,1791145663307559327]}
STAGES=('compiler','account-profile','process-census','process-generation','token','process-again','serialize','complete')

def body():
    """Preserve every original predicate, adding finite boundary observations."""
    if hashlib.sha256(Path(owner.__file__).read_bytes()).hexdigest()!=OWNER_SHA:raise ValueError('diagnostic-owner-source')
    value=owner.body()
    if hashlib.sha256(value.encode('utf-16le')).hexdigest()!=owner.BODY_SHA:raise ValueError('diagnostic-owner-body')
    changes=[
        ("try {\n $sid=", "$script:cp117OwnerDiagStage='compiler';$script:cp117OwnerDiagObservations=@()\ntry {\n $sid="),
        (" $accounts=@("," $script:cp117OwnerDiagStage='account-profile'\n $accounts=@("),
        (" $all=@("," $script:cp117OwnerDiagStage='process-census'\n $all=@("),
        ("   $p=[Diagnostics.Process]::GetProcessById", "   $script:cp117OwnerDiagStage='process-generation'\n   $p=[Diagnostics.Process]::GetProcessById"),
        ("    if($p.HasExited", "    $script:cp117OwnerDiagObservations+=@{pid=[int]$item.ProcessId;sessionId=[int]$item.SessionId;osStart=$stamp.ToString();cimStart=$item.CreationDate.ToUniversalTime().ToFileTimeUtc().ToString();hasExited=[bool]$p.HasExited}\n    if($script:cp117OwnerDiagObservations.Count -gt 32){throw 'OWNER_DIAGNOSTIC_BOUND'}\n    if($p.HasExited"),
        ("$stamp -ne $item.CreationDate.ToUniversalTime().ToFileTimeUtc()", "$stamp -le 0 -or $item.CreationDate.ToUniversalTime().ToFileTimeUtc() -le 0 -or ($item.CreationDate.ToUniversalTime().ToFileTimeUtc() % 10) -ne 0 -or ($stamp - ($stamp % 10)) -ne $item.CreationDate.ToUniversalTime().ToFileTimeUtc()"),
        ("    $t=[Cp117OwnerToken]", "    $script:cp117OwnerDiagStage='token'\n    $t=[Cp117OwnerToken]"),
        ("    $again=Get-CimInstance", "    $script:cp117OwnerDiagStage='process-again'\n    $again=Get-CimInstance"),
        (" [Console]::Out.WriteLine(($facts|ConvertTo-Json -Depth 8 -Compress))", " $script:cp117OwnerDiagStage='serialize'\n [Console]::Out.WriteLine((@{version=1;correlationId='"+CORRELATION+"';outcome='complete';stage='complete';category='none';errorType='none';hresult=0;observations=@($script:cp117OwnerDiagObservations);facts=$facts;details=''}|ConvertTo-Json -Depth 10 -Compress))"),
        ("}catch{[Console]::Out.WriteLine('{\"version\":1,\"code\":\"OWNER_UNKNOWN\"}');exit 1}", "}catch{$cp117OwnerDiagError=$_.Exception.GetBaseException();$cp117OwnerDiagDetails=($_|Out-String);if($cp117OwnerDiagDetails.Length -gt 4096){$cp117OwnerDiagDetails=$cp117OwnerDiagDetails.Substring(0,4096)};$cp117OwnerDiagCategory='stage-failure';if($_.Exception.Message -cmatch '^OWNER_[A-Z_]+$'){$cp117OwnerDiagCategory=$_.Exception.Message};[Console]::Out.WriteLine((@{version=1;correlationId='"+CORRELATION+"';outcome='blocked';stage=$script:cp117OwnerDiagStage;category=$cp117OwnerDiagCategory;errorType=$cp117OwnerDiagError.GetType().Name;hresult=[int]$cp117OwnerDiagError.HResult;observations=@($script:cp117OwnerDiagObservations);facts=$null;details=$cp117OwnerDiagDetails}|ConvertTo-Json -Depth 10 -Compress))}\n"),
    ]
    for old,new in changes:
        if value.count(old)!=1:raise ValueError('diagnostic-fixed-boundary')
        value=value.replace(old,new)
    return value

def validate(value):
    fields={'version','correlationId','outcome','stage','category','errorType','hresult','observations','facts','details'}
    if not isinstance(value,dict)or set(value)!=fields or type(value['version'])is not int or value['version']!=1 or value['correlationId']!=CORRELATION:raise ValueError('diagnostic-schema')
    if value['outcome']not in('complete','blocked')or value['stage']not in STAGES or type(value['hresult'])is not int or not isinstance(value['details'],str)or len(value['details'])>4096:raise ValueError('diagnostic-classification')
    categories={'none','stage-failure','OWNER_ACCOUNT_PROFILE','OWNER_PROCESS_BOUND','OWNER_PROCESS_GENERATION','OWNER_TOKEN_SESSION','OWNER_PROCESS_CHANGED','OWNER_DIAGNOSTIC_BOUND'}
    if value['category']not in categories or not isinstance(value['errorType'],str)or not value['errorType'].isascii()or not value['errorType'].isalnum()or len(value['errorType'])>80:raise ValueError('diagnostic-category')
    if not isinstance(value['observations'],list)or len(value['observations'])>32:raise ValueError('diagnostic-process-bound')
    for item in value['observations']:
        if not isinstance(item,dict)or set(item)!={'pid','sessionId','osStart','cimStart','hasExited'}or type(item['pid'])is not int or item['pid']<=0 or type(item['sessionId'])is not int or not 0<=item['sessionId']<=65535 or type(item['hasExited'])is not bool:raise ValueError('diagnostic-process-shape')
        if any(not isinstance(item[k],str)or not item[k].isascii()or not item[k].isdigit()or not 1<=len(item[k])<=20 for k in('osStart','cimStart')):raise ValueError('diagnostic-process-time')
    if value['outcome']=='blocked':
        if value['facts']is not None or value['stage']=='complete' or value['category']=='none':raise ValueError('diagnostic-blocked')
    else:
        if value['stage']!='complete'or value['category']!='none'or value['errorType']!='none'or value['hresult']!=0 or value['details']!=''or not isinstance(value['facts'],dict):raise ValueError('diagnostic-complete')
    return value

def parse_terminal(value,nonce,sha,pid):
    if value.get('exited')is not True:return None
    if value.get('out-truncated')or value.get('err-truncated'):raise ValueError('diagnostic-truncated')
    raw=base64.b64decode(value.get('out-data',''),validate=True)
    if len(raw)>32768:raise ValueError('diagnostic-output-cap')
    header,sep,payload=raw.partition(b'\n')
    if not sep or header.rstrip(b'\r')!=('CP117-READ %s %s %d'%(nonce,sha,pid)).encode():return None
    if type(value.get('exitcode'))is not int or value['exitcode']!=0:raise ValueError('diagnostic-guest-exit')
    return validate(json.loads(payload))

def _program(record, expected_flow_sha):
    r=owner.guest.recovery
    files=(Path(__file__),Path(owner.__file__),Path(flow.__file__))
    pins={str(p):r.authority._read_bound_file(p,retain_bytes=True)for p in files}
    if pins[str(files[1])][0]['sha256']!=OWNER_SHA or pins[str(files[2])][0]['sha256']!=expected_flow_sha:raise ValueError('diagnostic-factory-source')
    source,_=owner.program(record);plain=body();sha=hashlib.sha256(plain.encode('utf-16le')).hexdigest()
    old=base64.b64encode(("[Console]::Out.WriteLine(('CP117-READ "+owner.NONCE+" "+owner.BODY_SHA+" '+$PID))\n"+owner.body()).encode('utf-16le')).decode()
    new=base64.b64encode(("[Console]::Out.WriteLine(('CP117-READ "+NONCE+" "+sha+" '+$PID))\n"+plain).encode('utf-16le')).decode()
    if len(new)>=30000:raise ValueError('diagnostic-command-cap')
    def functions(raw,names):
        tree=ast.parse(raw.decode());return '\n\n'.join(ast.get_source_segment(raw.decode(),next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name))for name in names)+'\n'
    previous=functions(pins[str(files[1])][1],('validate_facts','parse_terminal'))
    replacement='CORRELATION='+repr(CORRELATION)+'\nSTAGES='+repr(STAGES)+'\n'+functions(pins[str(files[0])][1],('validate','parse_terminal'))
    for before,after in((repr(old),repr(new)),('D='+repr(owner.CORRELATION),'D='+repr(CORRELATION)),('NONCE='+repr(owner.NONCE),'NONCE='+repr(NONCE)),('BODY_SHA='+repr(owner.BODY_SHA),'BODY_SHA='+repr(sha)),(previous,replacement)):
        if source.count(before)!=1:raise ValueError('diagnostic-carrier-factory')
        source=source.replace(before,after)
    for path,(pin,_)in pins.items():
        if r.authority._read_bound_file(Path(path))!=pin:raise ValueError('diagnostic-factory-drift')
    compile(source,'fixed-owner-diagnostic','exec');return source,sha

CURRENT_FLOW_SHA='3447001b51cb4df248e4566135bba568c5e3e090a9a9744d4ba3eafc4e9a8c12'

def program(record):
    """Historical fixed producer; current provider bytes are not historical authority."""
    return _program(record,FLOW_SHA)

def program_current(record):
    """Explicit source successor for the one declared formatting-only provider delta."""
    r=owner.guest.recovery
    pin,raw=r.authority._read_bound_file(Path(flow.__file__),retain_bytes=True)
    lines=raw.splitlines(keepends=True)
    if pin['sha256']!=CURRENT_FLOW_SHA or len(lines)<146 or not lines[145].endswith(b'\n'):
        raise ValueError('diagnostic-current-factory-source')
    lines[145]=lines[145][:-1]+b' \n'
    if hashlib.sha256(b''.join(lines)).hexdigest()!=FLOW_SHA:
        raise ValueError('diagnostic-current-recipe')
    value=_program(record,CURRENT_FLOW_SHA)
    if r.authority._read_bound_file(Path(flow.__file__))!=pin:
        raise ValueError('diagnostic-current-factory-drift')
    return value

def summary(value):
    facts=value.get('facts');verified=False
    if facts is not None:
        try:owner.validate_facts(facts);verified=True
        except ValueError:pass
    return {'state':'diagnosed','correlationId':CORRELATION,'outcome':value['outcome'],'stage':value['stage'],'category':value['category'],'originalFactsVerified':verified,'observationsCount':len(value['observations']),'ordinaryRequesterAdmission':False,'installerAction':False,'replayAllowed':False}

def observe(root):
    root=Path(root).resolve(strict=True);r=owner.guest.recovery;leaf='windows-cp117-owner-diagnostic-'+CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','correlationId':CORRELATION,'stage':'consumed','ordinaryRequesterAdmission':False,'installerAction':False,'replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION);login=AuthorityCapture(root,ORIGINAL_LOGIN_LEAF);events=[]
    try:
        original_raw=r._local_read(original,owner.guest.ORIGINAL['name'],owner.guest.ORIGINAL['pin']);record=json.loads(original_raw)
        unknown_raw=r._local_read(login,'unknown.json',ORIGINAL_UNKNOWN);unknown=json.loads(unknown_raw)
        if unknown['state']!='unknown'or unknown['phase']!='login-owner':raise ValueError('diagnostic-original-unknown')
        files=(Path(__file__),Path(owner.__file__),Path(flow.__file__),Path(owner.guest.__file__))
        pins={str(p):r.authority._read_bound_file(p)for p in files};execution=flow._execution_source_proof(root,record);outer=r.authority._outer_authority(root)
        def verify():
            if r._local_read(original,owner.guest.ORIGINAL['name'],owner.guest.ORIGINAL['pin'])!=original_raw or r._local_read(login,'unknown.json',ORIGINAL_UNKNOWN)!=unknown_raw:raise ValueError('diagnostic-historical-drift')
            for i,item in enumerate(record['authority']):
                r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('diagnostic-original-frame')
            if flow._execution_source_proof(root,record)!=execution or any(r.authority._read_bound_file(Path(path))!=pin for path,pin in pins.items()):raise ValueError('diagnostic-source-drift')
            r.authority._verify_outer(root,{'outerAuthority':outer})
        verify();source,sha=program(record)
        capture.create('request.json',json.dumps({'correlationId':CORRELATION,'nonce':NONCE,'sourceSha256':sha,'programSha256':hashlib.sha256(source.encode()).hexdigest(),'sources':pins,'originalLoginUnknown':ORIGINAL_UNKNOWN,'executionSourceProof':execution,'outerAuthority':outer,'ordinaryRequesterAdmission':False,'installerAction':False},sort_keys=True).encode());capture.create('remote.py',source.encode());os.fsync(capture.fd)
        config,_,_=r.authority.closure.base._descriptor(root);argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
        capture.create('attempt.json',json.dumps({'state':'consumed','correlationId':CORRELATION,'nonce':NONCE},sort_keys=True).encode());os.fsync(capture.fd);verify()
        value,events=flow._stream(argv,capture,CORRELATION,NONCE,sha,record['result']['qemu'],None);verify()
        pin=capture.create('result.json',json.dumps({'result':value,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        if value.get('state')!='observed':return {'state':'unknown','correlationId':CORRELATION,'stage':'observation','evidenceLeaf':leaf,'receipt':pin,'ordinaryRequesterAdmission':False,'installerAction':False,'replayAllowed':False}
        return dict(summary(value['facts']),evidenceLeaf=leaf,receipt=pin)
    except Exception as error:
        events.extend(getattr(error,'events',[]));pin=capture.create('unknown.json',json.dumps({'state':'unknown','failureType':type(error).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','correlationId':CORRELATION,'stage':'observation','evidenceLeaf':leaf,'receipt':pin,'ordinaryRequesterAdmission':False,'installerAction':False,'replayAllowed':False}
    finally:login.close();original.close();capture.close()
