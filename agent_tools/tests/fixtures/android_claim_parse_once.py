"""Nonsecret exact consumed postcollector/parser code for inert TEST-001.

Sources a8e19456 original claim ingress, ff42ced9 terminal/projection, and
9bc49735 consume_once. No credentials, historical captures, guest authority or
private host paths are included. Only fixed test root/correlation constants differ.
"""
import ast,base64,hashlib,json,math,re,stat
from pathlib import Path
CHUNK=524288
STREAM_LIMIT=201326592
ORIGINAL='11111111-1111-4111-8111-111111111111'
REMOTE_ROOT='/inert-fixture'
PROVENANCE={'run-api35-original-claim-census-once.py': 'a8e19456991cd8a9dce841d7645968e1432ef831a5f2b76ceb4e1649f8f87024', 'run-api35-original-claim-derived-observation.py': '9bc497356cacbf30013f73710af1246ccf090035951df207abe133a59f2532da', 'run-api35-routing-backup-current-certificate-once.py': 'ff42ced941d6d2dd6996f9c7a486188a8736bd91b78d0f029326dbadaff7e394'}
ORIGINAL_TAIL="raw = ns['collect'](state, credential)\ncredential = b''\nproof = json.loads(ns['parse_terminal'](raw, state))\nns['guard'](state)\nif proof.get('kind') != 'api35-original-claim-census-proof' or proof.get('failure') is not None or proof.get('failureDetail') is not None or (proof.get('request') != state['request']):\n    raise ValueError('claim_observation_unknown')\nguard_projection(ns, ns['parse_terminal'](raw, state), state)\nresult = proof['backup']\nvalidate_result(result)\nsummary = {'state': 'original-claim-observed', 'leaf': state['leaf'], 'recordCount': len(result['passes'][0]['records']), 'workerStates': [r['state'] for r in result['passes'][0]['workers']], 'rawSha256': hashlib.sha256(raw).hexdigest(), 'claimGranted': False, 'releaseGranted': False, 'acceptanceComplete': False}\ncap.create('claim-summary.json', encoded(summary))\nprint(json.dumps(summary), flush=True)"
SUMMARY_TAIL="summary = {'state': 'original-claim-observed', 'leaf': state['leaf'], 'recordCount': len(result['passes'][0]['records']), 'workerStates': [r['state'] for r in result['passes'][0]['workers']], 'rawSha256': hashlib.sha256(raw).hexdigest(), 'claimGranted': False, 'releaseGranted': False, 'acceptanceComplete': False}\ncap.create('claim-summary.json', encoded(summary))\nprint(json.dumps(summary), flush=True)"
PARENT_VALIDATE_SOURCE="def validate_proof(raw,state):\n    value=json.loads(raw)\n    if (type(value)is not dict or type(value.get('schema'))is not int or value['schema']!=1 or value.get('kind')!='api35-installer-routing-backup-proof' or\n        value.get('request')!=state['request'] or value.get('failure')is not None or value.get('failureDetail')is not None or\n        value.get('installedLauncherAccepted')is not False or value.get('bundledRuntimeAccepted')is not False or\n        value.get('acceptanceComplete')is not False or type(value.get('records'))is not list):\n        raise ValueError('baseline_component_proof_unknown')\n    stdin_pin=value.get('carrierSourceStdinPin');initial_pin=value.get('carrierInitialStdinPin');original_limit=value.get('originalFileLimit')\n    if (type(initial_pin)is not list or len(initial_pin)!=9 or type(stdin_pin)is not list or len(stdin_pin)!=9 or\n        any(type(x)is not int for x in initial_pin+stdin_pin) or initial_pin[:6]!=stdin_pin[:6] or stdin_pin[3:6]!=[1000,1000,1] or\n        not stat.S_ISFIFO(stdin_pin[2]) or value.get('admittedFileLimit')!=[8388608,8388608] or\n        type(original_limit)is not list or len(original_limit)!=2 or any(type(x)is not int or x< -1 for x in original_limit)):\n        raise ValueError('baseline_carrier_limits_or_stdin_unknown')\n    observations=value.get('certificateObservations')\n    if type(observations)is not list or value.get('certificatePin')!=state['certificatePin'] or value.get('certificateSha256')!=state['certificateSha256']:raise ValueError('backup_certificate_observations_unknown')\n    archive(state['capture'],'certificate-observations',encoded(observations))\n    certificate_frames=[row for row in observations if 'certificatePath'in row]\n    if len(certificate_frames)!=2 or any(row.get('certificatePath')!=state['certificatePath'] or row.get('certificatePin')!=state['certificatePin'] or row.get('certificateSha256')!=state['certificateSha256'] or digest(base64.b64decode(row['rawBase64'],validate=True))!=state['certificateSha256'] for row in certificate_frames):raise ValueError('backup_certificate_observations_unknown')\n    generation_frames=[row['originalGeneration'] for row in observations if 'originalGeneration'in row]\n    if len(generation_frames)!=2 or any(frame.get('state')!='guest-generation-admitted' or frame.get('guestAdmitted')is not True or any(frame.get(key)!=state['getterGeneration'][key] for key in ('child','guest','device')) for frame in generation_frames):raise ValueError('backup_certificate_generation_unknown')\n    from agent_tools import android_installer_component_bundle as observed_bundle\n    expected_words=[['shell','-T','getprop',prop] for _,prop in observed_bundle._PROPERTIES]+[['shell','-T','id','-u'],['shell','-T','cat','/proc/sys/kernel/random/boot_id'],['shell','-T','sh -c '+__import__('shlex').quote(observed_bundle._PROCESS_READ)],['shell','-T','pm','path','com.kardinal.vpncontrol'],['shell','-T','sha256sum',state['certificate']['facts']['packagePath']],['shell','-T','pidof','com.kardinal.vpncontrol'],['shell','-T','ps','-A','-o','PID,UID,NAME'],['shell','-T','cat','/proc/'+str(state['certificate']['appProcess']['pid'])+'/stat']]\n    commands=[row for row in observations if 'words'in row]\n    if [row['words'] for row in commands]!=expected_words*2:raise ValueError('backup_certificate_read_set_unknown')\n    for row in commands:\n        result=row.get('result');captures=row.get('captures')\n        if type(result)is not dict or type(result.get('returncode'))is not int or result['returncode']!=0 or type(result.get('stdoutRaw'))is not str or result.get('stderrRaw')!='' or type(captures)is not list or len(captures)!=1 or captures[0].get('failure')is not None or type(captures[0].get('returncode'))is not int or captures[0]['returncode']!=0 or captures[0].get('stdoutBase64')!=base64.b64encode(result['stdoutRaw'].encode()).decode() or captures[0].get('stderrBase64')!='':raise ValueError('backup_certificate_command_unknown')\n    result=value.get('backup')\n    if (type(result)is not dict or type(result.get('schema'))is not int or result['schema']!=1 or\n        result.get('kind')!='android-installer-routing-backup' or result.get('request')!=state['request'] or\n        type(result.get('readCount'))is not int or result['readCount']!=2 or\n        type(result.get('formatVersion'))is not int or result['formatVersion']!=7 or\n        result.get('installerLeaseGranted')is not False or result.get('guestMutationPerformed')is not False or\n        result.get('replayAllowed')is not False or result.get('limitsRestored')is not True or\n        result.get('originalFileLimit')!=[8388608,8388608] or result.get('admittedFileLimit')!=[33554432,33554432]):\n        raise ValueError('routing_backup_component_result_unknown')\n    replies=[];seen=set()\n    for index,row in enumerate(value['records']):\n        if type(row)is not dict or set(row)!={'name','bytes','sha256','pin','rawBase64'} or row['name'] in seen or not re.fullmatch(r'component-guard-(?:read-[0-9]{5}|current-admission)\\.json',row['name']):raise ValueError('baseline_evidence_inventory_unknown')\n        seen.add(row['name']);content=base64.b64decode(row['rawBase64'],validate=True)\n        if type(row['bytes'])is not int or len(content)!=row['bytes'] or digest(content)!=row['sha256'] or row['pin'].get('sha256')!=row['sha256']:\n            raise ValueError('baseline_evidence_bytes_changed')\n        archive(state['capture'],'guard-record-'+str(index),content)\n        evidence=json.loads(content)\n        if evidence.get('binding')!=state['request'] or evidence.get('phase')!='baseline-read-only' or evidence.get('installerLeaseGranted')is not False:\n            raise ValueError('baseline_evidence_binding_unknown')\n        record=evidence.get('record',{})\n        if row['name']=='component-guard-current-admission.json' and any(record.get(key)!=state['certificate'][key] for key in ('facts','stage','host')):raise ValueError('backup_certificate_current_facts_changed')\n        if record.get('phase')=='baseline' and record.get('words') in (['status'],['operations','list']):\n            reply=json.loads(record['stdoutRaw'])\n            if (type(record.get('returncode'))is not int or record['returncode']!=0 or record.get('stderrRaw')!='' or\n                reply.get('ok')is not True or reply.get('final')is not True or reply.get('code')!='OK' or\n                reply.get('controllerId')!=state['request']['expectedOwner'] or type(reply.get('configurationRevision'))is not int or reply['configurationRevision']!=0):\n                raise ValueError('baseline_public_owner_unknown')\n            data=reply.get('data')\n            if type(data)is not dict:raise ValueError('baseline_public_data_unknown')\n            if record['words']==['status']:\n                if data.get('runtimeRunning')is not False or data.get('runtimeObservation')!='stopped':raise ValueError('baseline_runtime_not_off')\n            elif data.get('operations')!=state['ledger'] or any(row.get('final')is not True or row.get('controllerId')!=state['request']['expectedOwner'] for row in data['operations']):\n                raise ValueError('baseline_owned_terminal_ledger_changed')\n            replies.append(record['words'])\n    if 'component-guard-current-admission.json' not in seen or replies.count(['status'])<2 or replies.count(['operations','list'])<1:\n        raise ValueError('baseline_public_read_set_incomplete')\n    from agent_tools import android_installer_routing_backup as backup\n    source=backup.bundle._read(state['root']/backup.READER)[0]\n    if digest(source)!=backup.SOURCES[backup.READER]:raise ValueError('routing_backup_reader_source_changed')\n    template=ast.literal_eval(next(n.value for n in ast.parse(source).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_OBSERVER' for t in n.targets)))\n    semantic_node=next(n for n in ast.parse(template).body if isinstance(n,ast.FunctionDef) and n.name=='large_semantic')\n    semantic_namespace={'json':json};exec(compile(ast.unparse(semantic_node),'<fixed-backup-semantic>','exec'),semantic_namespace)\n    rows=value.get('backupRows')\n    if type(rows)is not list or not 1<=len(rows)<=260:raise ValueError('routing_backup_raw_inventory_unknown')\n    files={}\n    for index,row in enumerate(rows):\n        if (type(row)is not dict or set(row)!={'name','bytes','sha256','pin','rawBase64'} or\n            type(row['name'])is not str or row['name'] in files or\n            re.fullmatch(r'(?:routing(?:Before|After)-(?:stdout|stderr)-[0-9]{1,2}\\.private|routing(?:Before|After)-raw\\.json|backup-receipt\\.json)',row['name'])is None):\n            raise ValueError('routing_backup_raw_inventory_unknown')\n        content=base64.b64decode(row['rawBase64'],validate=True)\n        archive(state['capture'],'routing-file-'+str(index),content)\n        if (type(row['bytes'])is not int or not 0<len(content)<=CHUNK or len(content)!=row['bytes'] or\n            digest(content)!=row['sha256'] or row['pin'].get('sha256')!=row['sha256']):raise ValueError('routing_backup_raw_bytes_changed')\n        files[row['name']]=(content,row['pin'])\n    if backup._strict(files['backup-receipt.json'][0])!=result:raise ValueError('routing_backup_result_receipt_changed')\n    consumed={'backup-receipt.json'};semantics=[];opening=None\n    for phase in ('routingBefore','routingAfter'):\n        manifest=result.get('rawReads',{}).get(phase)\n        if type(manifest)is not dict:raise ValueError('routing_backup_manifest_unknown')\n        manifest_name=phase+'-raw.json';content,pin=files[manifest_name];consumed.add(manifest_name)\n        if pin!=manifest.get('manifestPin') or backup._strict(content)!={k:v for k,v in manifest.items() if k!='manifestPin'}:\n            raise ValueError('routing_backup_manifest_changed')\n        if (type(manifest.get('returncode'))is not int or manifest['returncode']!=0 or manifest.get('stdoutEof')is not True or manifest.get('stderrEof')is not True):raise ValueError('routing_backup_transport_unknown')\n        streams={}\n        for stream in ('stdout','stderr'):\n            descriptor=manifest[stream];parts=[]\n            if type(descriptor.get('chunks'))is not list or len(descriptor['chunks'])>65:raise ValueError('routing_backup_chunks_unknown')\n            for index,chunk in enumerate(descriptor['chunks']):\n                name=phase+'-'+stream+'-'+str(index)+'.private'\n                if chunk.get('name')!=name or name in consumed:raise ValueError('routing_backup_chunks_unknown')\n                part,current=files[name];consumed.add(name)\n                if current!=chunk['pin'] or len(part)!=chunk['bytes'] or digest(part)!=chunk['sha256']:raise ValueError('routing_backup_chunk_changed')\n                parts.append(part)\n            raw_stream=b''.join(parts)\n            if (type(descriptor.get('bytes'))is not int or not 0<=len(raw_stream)<=33554432 or\n                len(raw_stream)!=descriptor['bytes'] or digest(raw_stream)!=descriptor['sha256']):raise ValueError('routing_backup_stream_changed')\n            streams[stream]=raw_stream\n        if streams['stderr']!=b'':raise ValueError('routing_backup_stderr_unknown')\n        response=backup._strict(streams['stdout'])\n        if (type(response)is not dict or response.get('ok')is not True or response.get('final')is not True or\n            response.get('code')!='OK' or response.get('controllerId')!=state['request']['expectedOwner'] or\n            type(response.get('configurationRevision'))is not int or response['configurationRevision']!=0):raise ValueError('routing_backup_owner_changed')\n        semantics.append(semantic_namespace['large_semantic'](response))\n        if opening is None:opening=backup.bundle._raw(response['data']['routing'])\n    if consumed!=set(files) or semantics[0]!=semantics[1] or digest(semantics[0])!=result.get('semanticSha256'):\n        raise ValueError('routing_backup_semantic_changed')\n    if type(result.get('size'))is not int or len(opening)!=result['size'] or digest(opening)!=result.get('sha256'):\n        raise ValueError('routing_backup_opening_changed')\n    archive(state['capture'],'opening-routing',opening)\n    return {'state':'read-only-routing-backup-verified','leaf':state['leaf'],'owner':state['request']['expectedOwner'],'revision':state['request']['expectedRevision'],\n            'operationCount':0,'resultSha256':digest(raw),'recordCount':len(seen),'backupBytes':len(opening),\n            'backupSha256':digest(opening),'semanticSha256':digest(semantics[0]),'readCount':2,\n            'installerLeaseGranted':False,'guestMutationPerformed':False,'acceptanceComplete':False,'replayAllowed':False}"

def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()

def digest(raw):return hashlib.sha256(raw).hexdigest()

def archive(capture,name,raw):
    """Every local evidence file is <=512KiB; the manifest binds full bytes."""
    chunks=[]
    for index,offset in enumerate(range(0,len(raw),CHUNK)):
        child=name+'-'+str(index)+'.private';pin=capture.create(child,raw[offset:offset+CHUNK])
        chunks.append({'name':child,'pin':pin})
    manifest={'bytes':len(raw),'sha256':digest(raw),'chunks':chunks}
    capture.create(name+'-manifest.json',encoded(manifest))
    return manifest

def parse_terminal(raw, state):
    lines = raw.splitlines()
    if not lines:
        raise ValueError('baseline_remote_terminal_missing')
    header = json.loads(lines[0])
    required = {'schema', 'kind', 'returncode', 'failure', 'hostIdentity', 'sourceBytes', 'sourceSha256', 'stdoutBytes', 'stdoutSha256', 'stderrBytes', 'stderrSha256'}
    if type(header) is not dict or set(header) != required or type(header['schema']) is not int or (header['schema'] != 1) or (header['kind'] != 'api29-component-baseline-terminal') or (header['sourceBytes'] != len(state['source'])) or (header['sourceSha256'] != digest(state['source'])):
        raise ValueError('baseline_remote_terminal_unknown_raw_retained')
    identity = header['hostIdentity']
    if type(identity) is not dict or set(identity) != {'uid', 'euid', 'gid', 'egid', 'groups'} or any((type(identity[key]) is not int or identity[key] != 1000 for key in ('uid', 'euid', 'gid', 'egid'))) or (type(identity['groups']) is not list) or (len(identity['groups']) > 64) or any((type(x) is not int or x < 0 for x in identity['groups'])):
        raise ValueError('baseline_remote_host_unknown')
    decoded = {}
    offset = 1
    for name, label in [('out', 'stdout'), ('err', 'stderr')]:
        count = header[label + 'Bytes']
        if type(count) is not int or not 0 <= count <= STREAM_LIMIT:
            raise ValueError('baseline_remote_stream_size_unknown')
        rows = []
        for _ in range(math.ceil(count / CHUNK)):
            if offset >= len(lines) or not lines[offset].startswith((name + ':').encode()):
                raise ValueError('baseline_remote_stream_frame_unknown')
            part = base64.b64decode(lines[offset][len(name) + 1:], validate=True)
            offset += 1
            if len(part) > CHUNK:
                raise ValueError('baseline_remote_stream_chunk_unknown')
            rows.append(part)
        value = b''.join(rows)
        if len(value) != count or digest(value) != header[label + 'Sha256']:
            raise ValueError('baseline_remote_stream_changed')
        archive(state['capture'], 'remote-' + label, value)
        decoded[name] = value
    if offset != len(lines):
        raise ValueError('baseline_remote_extra_frame_unknown')
    state['capture'].create('remote-terminal.json', encoded(header))
    if type(header['returncode']) is not int or header['returncode'] != 0 or header['failure'] is not None or decoded['err']:
        raise ValueError('baseline_component_terminal_unknown_raw_retained')
    return decoded['out']

def guard_projection(ns,raw,state):
 tree=ast.parse(ns['__authenticated_raw'])
 fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate_proof')
 stop=next(i for i,n in enumerate(fn.body)if isinstance(n,ast.ImportFrom)and n.module=='agent_tools'and any(a.name=='android_installer_routing_backup'for a in n.names))
 fn.body=fn.body[:stop]
 result_at=next(i for i,n in enumerate(fn.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='result'for t in n.targets))
 # Exactly the old backup-result projection is absent for this new diagnostic producer.
 del fn.body[result_at:result_at+2]
 fn.body.append(ast.Return(ast.Constant(True)));fn.name='claim_guard_projection'
 compiled=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]));scope=dict(ns)
 exec(compile(compiled,'<unchanged-guard-projection>','exec'),scope)
 value=json.loads(raw);value['kind']='api35-installer-routing-backup-proof'
 return scope['claim_guard_projection'](encoded(value),state)

def fixed_record_paths():
 job=REMOTE_ROOT+'/android-installer-'+ORIGINAL
 paths=[REMOTE_ROOT+'/android-native-device-api35.lease',REMOTE_ROOT+'/android-native-device-android-api35.lease',REMOTE_ROOT+'/android-native-device-api35-'+ORIGINAL+'.release-intent',REMOTE_ROOT+'/android-native-device-android-api35-'+ORIGINAL+'.release-intent']
 paths += [job+'/'+name for name in ('dispatch.json','identity.json','launch-intent.json','release','release-intent.json')]
 paths += [job+'/output/'+name for name in ('intent.json','run-started.json','probe.json','lifecycle-receipt.json','handoff.json','fixture-identity.json','worker-finished.json','fixture-receipt.json','ready.json')]
 return paths

def parents_valid(parents,path):
 expected=[];current=Path(path)
 while True:
  expected.append(str(current))
  if current==current.parent:break
  current=current.parent
 if type(parents)is not dict or set(parents)!=set(expected):raise ValueError('claim_result_parent_unknown')
 for pin in parents.values():
  if type(pin)is not list or len(pin)!=5 or any(type(x)is not int for x in pin) or pin[0]<0 or pin[1]<=0 or not stat.S_ISDIR(pin[2]) or pin[3]not in(0,1000) or pin[4]not in(0,1000):raise ValueError('claim_result_parent_unknown')

def validate_result(result):
 if type(result)is not dict or set(result)!={'state','originalCorrelationId','passes','claimGranted','releaseGranted','originalOutcomeChanged','acceptanceComplete'} or result['state']!='original-claim-observed' or result['originalCorrelationId']!=ORIGINAL or any(result[k]is not False for k in ('claimGranted','releaseGranted','originalOutcomeChanged','acceptanceComplete')):raise ValueError('claim_result_unknown')
 passes=result['passes'];expected_paths=fixed_record_paths();job=REMOTE_ROOT+'/android-installer-'+ORIGINAL
 if type(passes)is not list or len(passes)!=2 or passes[0]!=passes[1]:raise ValueError('claim_result_unstable')
 for row in passes:
  if type(row)is not dict or set(row)!={'records','inventories','workers'} or type(row['records'])is not list or [r.get('path')for r in row['records']if type(r)is dict]!=expected_paths or type(row['inventories'])is not list or len(row['inventories'])!=2 or type(row['workers'])is not list or len(row['workers'])>1:raise ValueError('claim_result_inventory_unknown')
  files={}
  for record in row['records']:
   if type(record)is not dict or record.get('state')not in ('present','absent'):raise ValueError('claim_result_record_unknown')
   parents_valid(record.get('parents'),str(Path(record['path']).parent))
   if record['state']=='present':
    if set(record)!={'path','state','generation','parents','bytes','sha256','rawBase64'}:raise ValueError('claim_result_record_unknown')
    data=__import__('base64').b64decode(record['rawBase64'],validate=True);gen=record['generation']
    if type(gen)is not list or len(gen)!=9 or any(type(x)is not int for x in gen) or gen[0]<0 or gen[1]<=0 or gen[2]!=33152 or gen[3]not in(0,1000) or gen[4]not in(0,1000) or gen[5]!=1 or gen[6]!=len(data) or gen[7]<=0 or gen[8]<=0 or type(record['bytes'])is not int or record['bytes']!=len(data) or not 0<len(data)<=4194304 or hashlib.sha256(data).hexdigest()!=record['sha256']:raise ValueError('claim_result_generation_unknown')
    files[record['path']]=data
   elif set(record)!={'path','state','parents'}:raise ValueError('claim_result_record_unknown')
  for expected,inv in zip((job,job+'/output'),row['inventories']):
   if type(inv)is not dict or set(inv)!={'path','generation','parents','names'} or inv['path']!=expected:raise ValueError('claim_result_inventory_unknown')
   parents_valid(inv['parents'],expected);gen=inv['generation'];names=inv['names']
   if type(gen)is not list or len(gen)!=9 or any(type(x)is not int for x in gen) or gen[0]<0 or gen[1]<=0 or gen[2]!=16832 or gen[3]not in(0,1000) or gen[4]not in(0,1000) or gen[5]<2 or gen[6]<0 or gen[7]<=0 or gen[8]<=0 or gen[:5]!=inv['parents'][expected] or type(names)is not list or len(names)>256 or any(type(n)is not str or not n or len(n)>128 or n in('.','..') or '/'in n or '\x00'in n or any(ord(c)<32 or ord(c)>126 for c in n) for n in names) or names!=sorted(set(names)):raise ValueError('claim_result_inventory_unknown')
   for path in expected_paths:
    if str(Path(path).parent)==expected and ((path in files)is not (Path(path).name in names)):raise ValueError('claim_result_inventory_disagrees')
  identity_path=job+'/identity.json';identity=None
  if identity_path in files:
   identity=json.loads(files[identity_path])
   if type(identity)is not dict or set(identity)!={'pid','startTicks'} or any(type(identity[k])is not int or identity[k]<1 for k in identity):raise ValueError('claim_result_worker_unknown')
  if len(row['workers'])!=(1 if identity is not None else 0):raise ValueError('claim_result_worker_unknown')
  for worker in row['workers']:
   if type(worker)is not dict or worker.get('state')not in('absent','pid-reused','same-birth-present') or worker.get('original')!=identity:raise ValueError('claim_result_worker_unknown')
   if worker['state']=='absent':
    if set(worker)!={'original','state'}:raise ValueError('claim_result_worker_unknown')
   else:
    if set(worker)!={'original','state','currentStartTicks','rawBase64'} or type(worker['currentStartTicks'])is not int or worker['currentStartTicks']<=0:raise ValueError('claim_result_worker_unknown')
    raw=__import__('base64').b64decode(worker['rawBase64'],validate=True)
    if not 0<len(raw)<=4096:raise ValueError('claim_result_worker_unknown')
    try:pid=int(raw.split(b'(',1)[0]);ticks=int(raw.rsplit(b')',1)[1].split()[19])
    except (ValueError,IndexError):raise ValueError('claim_result_worker_unknown')
    if pid!=identity['pid'] or ticks!=worker['currentStartTicks'] or (worker['state']=='same-birth-present')is not(ticks==identity['startTicks']):raise ValueError('claim_result_worker_unknown')
 return True

def consume_once(ns,old_ns,wrapped,state):
 # Complete original post-collector ingress: decode/archive once, then keep
 # the held result through source guards, full projection and final summary.
 proof_raw=ns['parse_terminal'](wrapped,state);ns['guard'](state)
 proof=json.loads(proof_raw)
 if proof.get('kind')!='api35-original-claim-census-proof' or proof.get('failure')is not None or proof.get('failureDetail')is not None or proof.get('request')!=state['request']:raise ValueError('claim_observation_unknown')
 old_ns['guard_projection'](ns,proof_raw,state)
 result=proof['backup'];old_ns['validate_result'](result)
 return proof_raw,proof
