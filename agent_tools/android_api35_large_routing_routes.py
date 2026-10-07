"""Fixed API35 read-only MCP action with durable bounded PIPE collection."""
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
from . import android_api35_large_routing_observation as getter
from . import android_device_availability as availability
from . import private_inventory_lock as private
from . import ssh_transport
from . import windows_diagnostic_authority_capture as authority

ACTION='android-api35-large-routing-observe'
FROZEN='246db8b813b6be8a40a0ba3605e3854192adbc2f4b205a2d06ca62f397959ab7'
CAPTURE_SOURCE='8101d9665a3beb8ed8771f36baa058d2f137ca68db3750ea9c9ecfdb52e9503a'
RESERVATION='env-d2731056fb591098d64a377ce2dd3698'
DECODED_LIMIT=104857600
WIRE_LIMIT=157286400
CHUNK=524288
_REMOTE=r'''
import sys,subprocess,select,time,os,hashlib,base64,json
secret=sys.stdin.buffer.read(513)
if not 0<len(secret)<=512 or b'\0' in secret or b'\n' in secret.rstrip(b'\n'):raise SystemExit(2)
if not secret.endswith(b'\n'):secret+=b'\n'
p=None;streams={};code=None;timed=False;limited=False;reaped=True
try:
 p=subprocess.Popen(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-I','-B','-c',__CARRIER__],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 p.stdin.write(secret);p.stdin.close();secret=b'';streams={p.stdout:bytearray(),p.stderr:bytearray()};opened=list(streams);deadline=time.monotonic()+1200
 while opened:
  left=deadline-time.monotonic()
  if left<=0:timed=True;break
  ready,_,_=select.select(opened,[],[],min(left,1))
  for s in ready:
   block=os.read(s.fileno(),min(65536,104857601-sum(map(len,streams.values()))))
   if not block:opened.remove(s);continue
   streams[s].extend(block)
   if sum(map(len,streams.values()))>104857600:limited=True;break
  if limited:break
 if not timed and not limited:code=p.wait(timeout=max(.01,deadline-time.monotonic()))
except subprocess.TimeoutExpired:timed=True
finally:
 secret=b''
 if p is not None:
  if p.poll() is None:
   p.kill()
   try:p.wait(timeout=2)
   except subprocess.TimeoutExpired:reaped=False
  for s in (p.stdin,p.stdout,p.stderr):s.close()
out=streams.get(p.stdout,b'') if p is not None else b'';err=streams.get(p.stderr,b'') if p is not None else b''
print(json.dumps({'returncode':code,'timedOut':timed,'outputLimit':limited,'reaped':reaped,'stdoutBytes':len(out),'stdoutSha256':hashlib.sha256(out).hexdigest(),'stderrBytes':len(err),'stderrSha256':hashlib.sha256(err).hexdigest()},separators=(',',':')),flush=True)
for name,raw in [('out',out),('err',err)]:
 for offset in range(0,len(raw),1536):print(name+':'+base64.b64encode(raw[offset:offset+1536]).decode('ascii'),flush=True)
'''


def _unknown(reason='observation_unknown'):
    return dict(tool='vm_workflow',ok=False,state='diagnostic-only',reason=reason,currentRoutingVerified=False,productAdmitted=False,acceptanceComplete=False,historicalUnknownsPreserved=True,replayAllowed=False,observationOnly=True)


def _strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            if key in value:raise ValueError('duplicate_json_key')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite_json')))


class Collector:
    """Decoded output is fsynced as it arrives; wire data is not copied again."""
    def __init__(self,capture):
        self.finished=None;self.capture=capture;self.pending=bytearray();self.header=None;self.phase='out';self.counts={k:0 for k in ('out','err')};self.hashes={k:hashlib.sha256()for k in self.counts};self.buffers={k:bytearray()for k in self.counts};self.pins={k:[]for k in self.counts}
    def _save(self,key):
        if not self.buffers[key]:return
        raw=bytes(self.buffers[key]);name=key+'-'+str(len(self.pins[key]))+'.private';pin=self.capture.create(name,raw);os.fsync(self.capture.fd)
        self.pins[key].append(dict(name=name,bytes=len(raw),**pin));self.buffers[key].clear()
    def _line(self,line):
        if self.header is None:
            h=_strict(line);keys={'returncode','timedOut','outputLimit','reaped','stdoutBytes','stdoutSha256','stderrBytes','stderrSha256'}
            if type(h)is not dict or set(h)!=keys or any(type(h[k])is not bool for k in ('timedOut','outputLimit','reaped'))or h['returncode']is not None and type(h['returncode'])is not int:raise ValueError('remote_header_unknown')
            if any(type(h[k])is not int or not 0<=h[k]<=DECODED_LIMIT+1 for k in ('stdoutBytes','stderrBytes'))or h['stdoutBytes']+h['stderrBytes']>DECODED_LIMIT+1 or any(type(h[k])is not str or not re.fullmatch('[0-9a-f]{64}',h[k])for k in ('stdoutSha256','stderrSha256')):raise ValueError('remote_size_unknown')
            self.header=h;return
        if len(line)>2052 or not line.startswith((b'out:',b'err:')):raise ValueError('remote_frame_unknown')
        key=line[:3].decode('ascii');encoded=line[4:];raw=base64.b64decode(encoded,validate=True)
        if not raw or len(raw)>1536 or base64.b64encode(raw)!=encoded or self.phase=='err'and key=='out':raise ValueError('remote_frame_unknown')
        if key=='err':self.phase='err'
        if key=='out'and self.counts['out']+len(raw)>self.header['stdoutBytes']or key=='err'and self.counts['err']+len(raw)>self.header['stderrBytes']:raise ValueError('remote_frame_overflow')
        self.counts[key]+=len(raw);self.hashes[key].update(raw);self.buffers[key].extend(raw)
        if len(self.buffers[key])>=CHUNK:self._save(key)
    def feed(self,raw):
        self.pending.extend(raw)
        while b'\n' in self.pending:
            offset=self.pending.index(10);line=bytes(self.pending[:offset]);del self.pending[:offset+1]
            if not line or len(line)>2052:raise ValueError('remote_line_unknown')
            self._line(line)
        if len(self.pending)>2052:raise ValueError('remote_line_limit')
    def finish(self):
        if self.finished is not None:return self.finished
        for key in self.buffers:self._save(key)
        if self.pending:self.capture.create('incomplete-frame.private',bytes(self.pending[:65536]))
        result={key:{'bytes':self.counts[key],'sha256':self.hashes[key].hexdigest(),'chunks':self.pins[key]}for key in self.counts}
        valid=self.header is not None and not self.pending and all(self.counts[key]==self.header[label+'Bytes']and self.hashes[key].hexdigest()==self.header[label+'Sha256']for key,label in (('out','stdout'),('err','stderr')))
        self.finished=dict(header=self.header,streams=result,framesVerified=valid);return self.finished
    def read_output(self):
        result=bytearray()
        for pin in self.pins['out']:
            result.extend(self.capture.verify(pin['name'],pin))
            if len(result)>DECODED_LIMIT:raise ValueError('decoded_limit')
        return result


def _transport(argv,secret,collector,record):
    process=None;wire=0;deadline=time.monotonic()+1250;stderr=bytearray()
    try:
        process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        process.stdin.write(secret);process.stdin.close();secret=b'';streams={process.stdout:'out',process.stderr:'err'}
        while streams:
            left=deadline-time.monotonic()
            if left<=0:record['timedOut']=True;raise TimeoutError('local_timeout')
            ready,_,_=select.select(list(streams),[],[],min(left,1))
            for stream in ready:
                part=os.read(stream.fileno(),min(65536,WIRE_LIMIT+1-wire))
                if not part:del streams[stream];continue
                wire+=len(part);record['wireBytes']=wire
                if streams[stream]=='err':
                    stderr.extend(part)
                    if len(stderr)>1048576:raise ValueError('ssh_stderr_limit')
                else:
                    try:collector.feed(part)
                    except Exception:
                        collector.capture.create('failed-wire-block.private',part);raise
                if wire>WIRE_LIMIT:raise ValueError('wire_limit')
        record['returncode']=process.wait(timeout=max(.01,deadline-time.monotonic()))
    finally:
        secret=b''
        if process is not None:
            if process.poll()is None:
                process.kill()
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:record['reaped']=False
            for stream in (process.stdin,process.stdout,process.stderr):stream.close()
        record['stderrBytes']=len(stderr);record['stderrSha256']=hashlib.sha256(stderr).hexdigest()
        if stderr:collector.capture.create('ssh-stderr.private',bytes(stderr[:1048576]));os.fsync(collector.capture.fd)


def _raw_chunks(record,limit=33554433):
    if type(record)is not dict or set(record)!={'bytes','sha256','encoding','chunkBytes','chunks'}or type(record['bytes'])is not int or not 0<=record['bytes']<=limit or record['encoding']!='base64'or type(record['chunkBytes'])is not int or record['chunkBytes']!=65536 or type(record['chunks'])is not list or len(record['chunks'])!=(record['bytes']+65535)//65536:raise ValueError('reply_chunks_unknown')
    raw=bytearray()
    for index,encoded in enumerate(record['chunks']):
        if type(encoded)is not str or len(encoded)>87384:raise ValueError('reply_chunk_unknown')
        chunk=base64.b64decode(encoded,validate=True)
        expected=min(65536,record['bytes']-index*65536)
        if len(chunk)!=expected or base64.b64encode(chunk).decode()!=encoded:raise ValueError('reply_chunk_changed')
        raw.extend(chunk)
    if type(record['sha256'])is not str or hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('reply_hash_changed')
    return raw


def _envelope(item):
    if type(item)is not dict or type(item.get('returncode'))is not int or item['returncode']!=0:raise ValueError('reply_exit_unknown')
    value=_strict(_raw_chunks(item['stdout']));_raw_chunks(item['stderr'])
    if type(value)is not dict or value.get('schemaVersion')!=1 or type(value.get('schemaVersion'))is not int or value.get('ok')is not True or value.get('final')is not True or value.get('code')!='OK'or value.get('controllerId')!=getter.OWNER or type(value.get('configurationRevision'))is not int or value['configurationRevision']!=0 or type(value.get('requestId'))is not str or str(uuid.UUID(value['requestId']))!=value['requestId']:raise ValueError('reply_owner_unknown')
    return value


def _stage_valid(stage):
    if type(stage)is not dict or not {'intent.json','receipt.json'}<=set(stage):return False
    for item in stage.values():
        if type(item)is not dict or set(item)!={'generation','bytesRead','sha256','hashScope'}or item['hashScope']!='full'or type(item['bytesRead'])is not int or item['bytesRead']<0 or type(item['sha256'])is not str or not re.fullmatch('[0-9a-f]{64}',item['sha256']):return False
        g=item['generation']
        if type(g)is not list or len(g)!=9 or any(type(n)is not int for n in g)or not stat.S_ISREG(g[5])or g[6:]!=[1000,1000,1]or g[2]!=item['bytesRead']:return False
    return True


def _projection(value):
    unknown=_unknown()
    if type(value)is not dict or value.get('state')!='current-large-routing-observed'or value.get('reason')is not None or value.get('currentRoutingVerified')is not True or value.get('productAdmitted')is not False or value.get('acceptanceComplete')is not False or value.get('historicalUnknownsPreserved')is not True or value.get('semanticComparison')!='full-type-version-rules-excluding-generated-exported_at-only':return unknown
    stages=value.get('cliStagePins');records=value.get('records')
    if type(stages)is not list or len(stages)!=2 or not _stage_valid(stages[0])or stages[0]!=stages[1]or type(records)is not dict or records.get('observedPackageBefore')!=getter.original.APK or records.get('observedPackageAfter')!=getter.original.APK:return unknown
    try:
        statuses=[_envelope(records[k])['data']for k in ('statusBefore','statusAfter')]
        if statuses[0]!=statuses[1]or statuses[0].get('runtimeRunning')is not False or statuses[0].get('runtimeObservation')!='stopped':raise ValueError('off_unknown')
        for key in ('operationsBefore','operationsAfter'):
            if _envelope(records[key])['data'].get('operations')!=[]:raise ValueError('operations_unknown')
        semantic=[];counts=[]
        for key in ('routingBefore','routingAfter'):
            item=records[key];envelope=_envelope(item);routing=envelope['data']['routing']
            if set(envelope['data'])!={'routing'}or type(routing)is not dict or set(routing)!={'type','version','exported_at','rules'}or routing['type']!='vpn_control_routing_rules'or type(routing['version'])is not int or routing['version']!=7 or type(routing['exported_at'])is not str or not routing['exported_at']or type(routing['rules'])is not dict:raise ValueError('rules_unknown')
            rules=routing['rules']
            if set(rules)!={'ignore_rules','block_quic_udp_443','proxy_packages','direct_domain_suffixes'}or any(type(rules[k])is not bool for k in ('ignore_rules','block_quic_udp_443'))or any(type(rules[k])is not list or any(type(x)is not str for x in rules[k])for k in ('proxy_packages','direct_domain_suffixes')):raise ValueError('rule_types_unknown')
            raw=json.dumps({k:routing[k]for k in ('type','version','rules')},sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
            if type(item.get('semanticBytes'))is not int or item['semanticBytes']!=len(raw)or item.get('semanticSha256')!=hashlib.sha256(raw).hexdigest()or item.get('envelope')!={k:envelope.get(k)for k in ('schemaVersion','controllerId','requestId','ok','code','final','configurationRevision','operationId','restartRequired','warnings')}:raise ValueError('semantic_binding_unknown')
            semantic.append(raw);counts.append(len(routing['rules'].get('direct_domain_suffixes',[])))
        if semantic[0]!=semantic[1]:raise ValueError('semantic_changed')
    except (ValueError,KeyError,TypeError,AttributeError):return unknown
    return {**unknown,'ok':True,'state':'current-large-routing-observed','reason':'observed','currentRoutingVerified':True,'controllerId':getter.OWNER,'configurationRevision':0,'runtimeOff':True,'operationCount':0,'routingDomainCount':counts[0],'semanticSha256':hashlib.sha256(semantic[0]).hexdigest()}


def _capture(root,identifier):
    with ExitStack()as stack:
        directory=stack.enter_context(private.Directory(root));path=root
        for name in ('.runtime','parity-evidence','android-api35-large-routing-mcp-'+identifier):
            directory.guard()
            try:os.mkdir(name,0o700,dir_fd=directory.fd);os.fsync(directory.fd)
            except FileExistsError:
                if name.endswith(identifier):raise
            directory.guard();path=path/name;directory=stack.enter_context(private.Directory(path))
        return authority.AuthorityCapture(root,path.name)


def dispatch(root,action,inputs):
    if action!=ACTION:return None
    if type(inputs)is not dict or inputs:return _unknown('invalid_inputs')
    root=Path(root).absolute();identifier=str(uuid.uuid4());capture=None;receipt=None;result=_unknown();transport={'returncode':None,'timedOut':False,'reaped':True};collector=None
    try:
        with ExitStack()as stack:
            rd=stack.enter_context(private.Directory(root/'.rag_index/native-environments'));registry=stack.enter_context(private.Snapshot(rd,'reservations.json'));rows=_strict(registry.body)['reservations'];matches=[r for r in rows if r.get('id')==RESERVATION]
            if len(matches)!=1:raise ValueError('reservation_unknown')
            row=matches[0]
            if row.get('hostAlias')!='archlinux'or row.get('environment')!='owned-android-api35-coldboot'or row.get('operator')!='root-android'or type(row.get('requestedMemoryBytes'))is not int or row['requestedMemoryBytes']!=2147483648 or row.get('allocationState')not in {'pending','running'}:raise ValueError('reservation_unknown')
            identity={k:row[{'reservationId':'id'}.get(k,k)]for k in ('reservationId','token','hostAlias','environment','operator')}
            pins={}
            for module,expected in ((getter,FROZEN),(authority,CAPTURE_SOURCE),(ssh_transport,None),(private,None),(availability,None)):
                p=Path(module.__file__).absolute();pins[p]=availability._snapshot(p)
                if expected and hashlib.sha256(pins[p][1]).hexdigest()!=expected:raise ValueError('source_unknown')
            route=Path(__file__).absolute();pins[route]=availability._snapshot(route);prepared=getter.prepare(root,identity)
            cd=stack.enter_context(private.Directory(root));config_pin=stack.enter_context(private.Snapshot(cd,ssh_transport.CONFIG_FILENAME));config=ssh_transport.load_config(root)
            if 'archlinux'not in config.hosts or ssh_transport.connection_host(config,'archlinux').password is not None:raise ValueError('route_unknown')
            command=_REMOTE.replace('__CARRIER__',repr(getter.ssh_carrier(prepared)));argv=ssh_transport.build_ssh_argv(config,'archlinux',60,command=('/usr/bin/python3','-I','-B','-c','exec('+repr(command)+')'),ssh_binary='/usr/bin/ssh',nested_ssh_binary='/usr/bin/ssh')
            credential_dir=stack.enter_context(private.Directory(root/'.codex'));credential=stack.enter_context(private.Snapshot(credential_dir,'arch-sudo.local'));secret=credential.body
            if not 0<len(secret)<=512 or b'\0'in secret or b'\n'in secret.rstrip(b'\n'):raise ValueError('credential_unknown')
            def guard():
                registry.guard();config_pin.guard();credential.guard();getter.guard_prepared(prepared)
                if any(availability._snapshot(p)!=pin for p,pin in pins.items()):raise ValueError('source_changed')
            guard();capture=_capture(root,identifier);collector=Collector(capture)
            capture.create('binding.json',(json.dumps({'schema':1,'observationId':identifier,'getterSha256':FROZEN,'programSha256':hashlib.sha256(prepared['program'].encode()).hexdigest(),'observationOnly':True,'replayAllowed':False},sort_keys=True)+'\n').encode());os.fsync(capture.fd);guard()
            try:
                _transport(argv,secret,collector,transport);secret=b'';guard()
                manifest=collector.finish()
                if transport['returncode']!=0 or transport['timedOut']or not transport['reaped']or not manifest['framesVerified']:raise ValueError('transport_unknown')
                header=manifest['header']
                if header['returncode']!=0 or header['timedOut']or header['outputLimit']or not header['reaped']:raise ValueError('remote_unknown')
                result=_projection(_strict(collector.read_output()));guard()
            finally:
                secret=b''
                manifest=collector.finish();raw=(json.dumps({'schema':1,'observationId':identifier,'getterSha256':FROZEN,'transport':transport,'remote':manifest,'observationOnly':True,'historicalUnknownsPreserved':True,'replayAllowed':False},sort_keys=True,separators=(',',':'))+'\n').encode()
                receipt=capture.create('receipt.json',raw);os.fsync(capture.fd);receipt['bytes']=len(raw)
            guard()
        if receipt:result.update(observationId=identifier,receiptSha256=receipt['sha256'],receiptBytes=receipt['bytes'])
        return result
    except Exception:
        result=_unknown()
        if receipt:result.update(observationId=identifier,receiptSha256=receipt['sha256'],receiptBytes=receipt['bytes'])
        return result
    finally:
        if capture is not None:capture.close()
