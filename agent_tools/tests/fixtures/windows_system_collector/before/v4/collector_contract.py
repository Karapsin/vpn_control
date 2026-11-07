"""Closed data contract for the two frozen read-only SYSTEM collectors.

No import action or native capability. Real native admissions remain external.
"""
from __future__ import annotations
import hashlib
import json
import base64
from pathlib import PureWindowsPath
import re
import uuid

FIXED = {
    'holdProtocol': '70440195ac8f3116f4a40b788616419ea88591eb430119ce386f6b31684fc1c1',
    'taskGuard': '8105ad57f5140e6caef6fd21848f34d1684a00ca7c9e54ce64908211260844c1',
    'nativeBridge': '88ad6bbbf8b309bb641017d035bdf6688d37ac5d6e506bcffd4122203850a955',
    'native': 'ee28050bd0e33166956cc4f4ac68ca10cc89c30c01ae93468379895fee268a18',
    'receipts': '5e2e406b82d4a446ab971f27918b3b0f110e67e3eb8cae971b0bfe4256aa71ec',
    'observer': '6d08edf9e57b09e98ce80d414b2ac12da4f39eb82e27cd2a3f06d9f900e04dcb',
}
COLLECTORS = {
    'update': '246bb5e7110fe5fdad986e3cf082683934070195098730bf79ab86e0fd0296b2',
    'tun': 'ec5256d42208585695e1566df5697c8c4c010631258876e08a1ea61874172de1',
}
CALLER_HOLD_SHA='6a6fbbe73e8d70db247656af330a8a4de9b2119a181ae4e3af5d0757dc8f0ef5'
PYTHON_REQUIRED = {'python.exe','python313.dll','Lib/os.py','Lib/subprocess.py',
                   'Lib/threading.py','Lib/json/__init__.py','Lib/ctypes/__init__.py','DLLs/_ctypes.pyd'}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)+'\n').encode('utf-8')


def guid(value):
    require(type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0,
            'collector-canonical-guid')
    return value


def path(value):
    require(type(value) is str and 0 < len(value) <= 1000 and not any(ord(c)<32 for c in value),
            'collector-path-type')
    p=PureWindowsPath(value)
    require(len(p.drive)==2 and p.drive[1]==':' and p.root=='\\' and str(p)==value
            and all(x not in {'.','..'} and ':' not in x and not x.endswith(('.', ' ')) for x in p.parts[1:]),
            'collector-canonical-drive-path')
    return p


def sha(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value), 'collector-source-sha256')
    return value


def pin(value, directory=False):
    fields={'path','nativeIdentity','security'}| (set() if directory else {'sha256'})
    require(type(value) is dict and set(value)==fields, 'collector-pin-schema')
    p=path(value['path']); i=value['nativeIdentity']
    names={'volumeSerial','fileIndex','attributes'} | (set() if directory else
        {'sizeBytes','links','creationFileTime','lastWriteFileTime'})
    require(type(i) is dict and set(i)==names, 'collector-pin-native-schema')
    for k,v in i.items():
        require((type(v) is str and re.fullmatch('[0-9]{1,19}',v)) if k in
            {'creationFileTime','lastWriteFileTime'} else type(v) is int and v>=0, 'collector-pin-native-type')
    require(not i['attributes']&0x400 and bool(i['attributes']&0x10)==directory,
            'collector-reparse-or-type')
    if not directory:
        require(i['links']==1, 'collector-file-hardlink');sha(value['sha256'])
    s=value['security']
    require(type(s) is dict and set(s)=={'ownerSid','sddl'} and type(s['ownerSid']) is str
            and type(s['sddl']) is str and 0<len(s['sddl'])<=16384, 'collector-exact-security')
    return p


def validate(request, private_hashes, guest_context=None):
    fields={'schemaVersion','operationId','ordinaryTaskOperationId','scope','operationRoot','requestPath',
        'context','pythonRuntime','filePins','directoryPins','treePins','modules','collectorRequest','rawStreamLimitBytes','ordinaryTask','closeHold'}
    require(type(request) is dict and set(request)==fields and type(request['schemaVersion']) is int
            and request['schemaVersion']==1 and request['scope'] in COLLECTORS, 'collector-closed-request-schema')
    guid(request['operationId']);guid(request['ordinaryTaskOperationId'])
    root=path(request['operationRoot'])
    require(root.name=='system-collector-'+request['operationId'] and
            path(request['requestPath'])==root/'collector-request.json', 'collector-operation-path')
    c=request['context'];cf={'bootIdentifier','bootFileTimeUtc','machineGuid','hardwareUuid',
                            'ordinarySid','ordinarySessionId','systemSessionId'}
    require(type(c) is dict and set(c)==cf and c['systemSessionId']==0 and type(c['systemSessionId']) is int,
            'collector-system-zero-context')
    for key in ('bootIdentifier','machineGuid','hardwareUuid'):guid(c[key])
    require(type(c['ordinarySid']) is str and re.fullmatch(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+',c['ordinarySid'])
            and type(c['ordinarySessionId']) is int and c['ordinarySessionId']>0
            and type(c['bootFileTimeUtc']) is str and re.fullmatch('[1-9][0-9]{16,19}',c['bootFileTimeUtc']),
            'collector-actual-ordinary-boot-context')
    if guest_context is not None:
        require(guest_context['ordinarySid']==c['ordinarySid'] and path(guest_context['sourceWorkspace'])==root.parent
                and guest_context['boot']=={'lastBootUpTimeFileTimeUtc':c['bootFileTimeUtc'],
                    'machineGuid':c['machineGuid'],'hardwareUuid':c['hardwareUuid']}, 'collector-guest-context-join')
    require(type(private_hashes) is dict and set(private_hashes)=={'contract','worker'},'collector-private-source-roles')
    expected={**FIXED,**{k:sha(v) for k,v in private_hashes.items()},'collector':COLLECTORS[request['scope']]}
    modules=request['modules']
    require(type(modules) is dict and set(modules)==set(expected), 'collector-fixed-source-roles')
    module_paths=set()
    for role,record in modules.items():
        require(type(record) is dict and set(record)=={'path','sha256'} and record['sha256']==expected[role],
                'collector-exact-source-'+role)
        p=path(record['path']);require(str(p).casefold() not in module_paths,'collector-source-alias')
        module_paths.add(str(p).casefold())
    require(type(request['filePins']) is list and 1<=len(request['filePins'])<=4096
            and type(request['directoryPins']) is list and 1<=len(request['directoryPins'])<=1024,
            'collector-pin-capacity')
    files={str(pin(p)).casefold():p for p in request['filePins']}
    dirs={str(pin(p,True)).casefold():p for p in request['directoryPins']}
    require(len(files)==len(request['filePins']) and len(dirs)==len(request['directoryPins']), 'collector-pin-alias')
    require(str(root).casefold() in dirs, 'collector-operation-directory-pin')
    root_policy(dirs[str(root).casefold()]['security'],c['ordinarySid'])
    task=ordinary_task(request['ordinaryTask'],c)
    task_paths=set()
    for role in ('ownerSourcePin','workerSourcePin','bootstrapRequestPin','workerRequestPin'):
        rec=task[role];key=rec['path'].casefold();task_paths.add(key)
        require(files.get(key)==rec,'collector-original-task-held-input-'+role)
    hold=request['closeHold']
    if hold is not None:
        require(type(hold) is dict and set(hold)=={'schemaVersion','callerSourcePin','holdReadyPath','releasePath','scope','stage','sourceSha'}
            and type(hold['schemaVersion']) is int and hold['schemaVersion']==1,'collector-close-hold-schema')
        caller=hold['callerSourcePin'];pin(caller);key=caller['path'].casefold();task_paths.add(key)
        require(files.get(key)==caller and caller['sha256']==CALLER_HOLD_SHA
            and path(modules['holdProtocol']['path'])==path(caller['path']).with_name('hold_protocol.py'),
            'collector-caller-source-held')
        require(hold['scope']==request['scope'] and hold['sourceSha']==request['collectorRequest']['sourceSha']
            and path(hold['releasePath'])==root/'close-release.json'
            and path(hold['holdReadyPath'])==path(task['workerRequestPin']['path']).parent/('collector-hold-'+request['operationId']+'.ready.json')
            and ((request['scope']=='update' and hold['stage']==request['collectorRequest']['stage']
                and hold['stage'] in {'terminal-actors','returned-cleanup'}) or (request['scope']=='tun' and hold['stage']=='off')),
            'collector-fixed-final-hold-role')
    require(not (request['scope']=='tun' or request['collectorRequest'].get('stage')=='returned-cleanup')
        or hold is not None,'collector-final-stage-caller-hold-required')
    for p in [root,path(request['requestPath']),*[path(v['path']) for v in files.values()]]:
        require(all(str(a).casefold() in dirs for a in p.parents),'collector-complete-ancestry')
    for role,record in modules.items():
        require(record['path'].casefold() in files and files[record['path'].casefold()]['sha256']==expected[role],
                'collector-held-module-'+role)
    runtime=request['pythonRuntime']
    require(type(runtime) is dict and set(runtime)=={'root','interpreterPath','version','architecture'}
            and runtime['version']=='3.13.15' and runtime['architecture']=='amd64'
            and path(runtime['interpreterPath'])==path(runtime['root'])/'python.exe', 'collector-python-runtime')
    trees=request['treePins']
    require(type(trees) is list and len(trees)==1 and type(trees[0]) is dict
            and set(trees[0])=={'role','root','files'} and trees[0]['role']=='python-runtime'
            and path(trees[0]['root'])==path(runtime['root']) and type(trees[0]['files']) is list
            and 1<=len(trees[0]['files'])<=4096, 'collector-only-complete-python-tree')
    names=trees[0]['files'];seen=set();runtime_paths=set()
    for name in names:
        require(type(name) is str and name and '\\' not in name and not name.startswith('/')
                and all(x not in {'','.','..'} and ':' not in x and not x.endswith(('.', ' ')) for x in name.split('/'))
                and name.casefold() not in seen, 'collector-python-relative-file')
        seen.add(name.casefold());p=path(str(path(runtime['root'])/PureWindowsPath(name)))
        require(str(p).casefold() in files,'collector-python-file-pin');runtime_paths.add(str(p).casefold())
    require(PYTHON_REQUIRED<=set(names) and set(files)==module_paths|runtime_paths|task_paths,
            'collector-no-extra-file-or-missing-python-inputs')
    require(not module_paths&runtime_paths,'collector-sources-disjoint-from-python')
    require(type(request['rawStreamLimitBytes']) is int and 4096<=request['rawStreamLimitBytes']<=2*1024*1024,
            'collector-complete-raw-bound')
    r=request['collectorRequest']
    require(type(r) is dict and r.get('schemaVersion')==1
            and r.get('ordinaryTaskOperationId')==request['ordinaryTaskOperationId']
            and r.get('collectorSourceSha256')==expected['collector']
            and r.get('context',{}).get('bootIdentifier')==c['bootIdentifier']
            and r['context'].get('ordinarySid')==c['ordinarySid']
            and r['context'].get('ordinarySessionId')==c['ordinarySessionId'], 'collector-request-origin-join')
    if request['scope']=='update':
        require(set(r)=={'schemaVersion','stage','ordinaryTaskOperationId','sourceSha','collectorSourceSha256',
            'context','jobId','productOperationId','actors','fileInputs','faultBinding','programData','evidenceRoot',
            'ordinaryWorkerPid','ordinaryWorkerBirth','expectedHelperSha256'}
            and r.get('stage') in {'before-install','authorization','terminal-actors','returned-cleanup','fault-ready'},
                'collector-finite-updater-stage')
    else:
        require(set(r)=={'schemaVersion','ordinaryTaskOperationId','productOperationId','originRequestId','controllerId',
            'collectorSourceSha256','sourceSha','context','ownerActor','guiActor','helperActor','runtimeActor',
            'helperImagePath','helperImageSha256','runtimeImagePath','runtimeImageSha256','configuration'},
            'collector-finite-tun-request')
    require(len(encoded(request))<=4*1024*1024,'collector-request-byte-bound')
    return request


def request_digest(request):
    return hashlib.sha256(encoded(request)).hexdigest()


def root_policy(security, ordinary_sid):
    expected='O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;'+ordinary_sid+')'
    require(security=={'ownerSid':'S-1-5-18','sddl':expected},'collector-machine-writer-operation-root-policy')


def file_policy(security, ordinary_sid):
    expected='O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;'+ordinary_sid+')'
    require(security=={'ownerSid':'S-1-5-18','sddl':expected},'collector-machine-writer-file-policy')


def task_argv(task):
    owner=task['ownerActor']['image'];worker=task['workerActor']['image']
    b=task['bootstrapRequestPin'];w=task['workerRequestPin']
    return {'owner':[owner,'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',
        task['ownerSourcePin']['path'],'-RequestPath',b['path'],'-RequestSha256',b['sha256'],
        '-RequestPinBase64',base64.b64encode(encoded(b)).decode()],
      'worker':[worker,'-I','-S','-B',task['workerSourcePin']['path'],'--request',w['path'],
        '--request-sha256',w['sha256'],'--request-pin-base64',base64.b64encode(encoded(w)).decode()]}


def ordinary_task(task, context):
    require(type(task) is dict and set(task)=={'ownerActor','workerActor','ownerSourcePin','workerSourcePin',
        'bootstrapRequestPin','workerRequestPin','ownerArgv','workerArgv'},'collector-original-task-schema')
    for role in ('ownerActor','workerActor'):
        a=task[role]
        require(type(a) is dict and set(a)=={'pid','creationFileTime','image','sha256','sid','sessionId'}
            and type(a['pid']) is int and a['pid']>0 and type(a['creationFileTime']) is int and a['creationFileTime']>0
            and a['sid']==context['ordinarySid'] and a['sessionId']==context['ordinarySessionId'],
            'collector-original-ordinary-'+role)
        path(a['image']);sha(a['sha256'])
    require(task['ownerActor']['pid']!=task['workerActor']['pid']
        and task['ownerActor']['image']==r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        'collector-original-task-ps-engine')
    for role in ('ownerSourcePin','workerSourcePin','bootstrapRequestPin','workerRequestPin'):pin(task[role])
    require(task['ownerSourcePin']['sha256']=='d6317f066f4a679e37f0a6aa5c30c229a2c6115ae2968aed568bec91d07362b2',
            'collector-canonical-original-task-owner-source')
    expected=task_argv(task)
    require(task['ownerArgv']==expected['owner'] and task['workerArgv']==expected['worker'],
            'collector-exact-original-task-argv')
    return task


def task_documents(request, bootstrap_raw, worker_raw):
    task=ordinary_task(request['ordinaryTask'],request['context'])
    values=[]
    for raw,role in ((bootstrap_raw,'bootstrapRequestPin'),(worker_raw,'workerRequestPin')):
        require(type(raw) is bytes and 0<len(raw)<=4*1024*1024
            and len(raw)==task[role]['nativeIdentity']['sizeBytes']
            and hashlib.sha256(raw).hexdigest()==task[role]['sha256'],'collector-original-task-request-bytes')
        v=json.loads(raw);c=v.get('context',{})
        require(v.get('schemaVersion')==1 and v.get('operationId')==request['ordinaryTaskOperationId']
            and c.get('ordinarySid')==request['context']['ordinarySid']
            and c.get('ordinarySessionId')==request['context']['ordinarySessionId']
            and c.get('bootIdentifier')==request['context']['bootIdentifier']
            and c.get('machineGuid')==request['context']['machineGuid'], 'collector-original-task-request-context')
        values.append(v)
    b,w=values;boot=b.get('bootstrap',{})
    require(b['operationRoot']==w['operationRoot'] and path(task['bootstrapRequestPin']['path']).parent==path(b['operationRoot'])
        and path(task['workerRequestPin']['path']).parent==path(w['operationRoot'])
        and w.get('workspace')==request['collectorRequest']['context'].get('workspace'),
        'collector-original-task-workspace-request-join')
    require(boot.get('mode')=='python-worker' and boot.get('pythonPath')==task['workerActor']['image']
        and boot.get('workerPath')==task['workerSourcePin']['path']
        and boot.get('workerRequestPath')==task['workerRequestPin']['path']
        and boot.get('workerRequestSha256')==task['workerRequestPin']['sha256']
        and base64.b64decode(boot.get('workerRequestPinBase64',''),validate=True)==encoded(task['workerRequestPin']),
        'collector-original-task-bootstrap-worker-join')
    require(all(task[k] in b.get('filePins',[]) for k in ('ownerSourcePin','workerSourcePin','workerRequestPin'))
        and task['workerSourcePin'] in w.get('filePins',[])
        and w.get('pythonRuntime',{}).get('interpreterPath')==task['workerActor']['image'],
        'collector-original-task-source-pins')
    if request['closeHold'] is not None:
        require(request['closeHold']['callerSourcePin'] in w.get('filePins',[])
            and any(x.get('sha256')==FIXED['holdProtocol'] for x in w.get('filePins',[])),
            'collector-caller-hold-original-worker-inputs')
    return values
