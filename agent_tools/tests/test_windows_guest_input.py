"""Focused current producer controls; native boundaries are explicitly inert."""
import base64
from dataclasses import asdict, replace
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from agent_tools import windows_guest_input as input_owner
from agent_tools import ssh_transport
from agent_tools.native_review_source_closure import _Held
from agent_tools import native_review_source_closure as source_closure

CORRELATION='12345678-1234-4567-8123-123456789abc'
CONTROLLER='12345678-1234-4567-8123-123456789abd'
ACK={'requestId':'12345678-1234-4567-8123-123456789abe',
     'operationId':'12345678-1234-4567-8123-123456789abf',
     'controllerId':CONTROLLER,'code':'ACCEPTED','final':False}
SID='S-1-5-21-1-2-3-1000'

def context():
    return input_owner.CurrentGuestContext('synthetic',SID,1,'2026-10-05T23:28:49.1890040Z',
        40,134357313540855812,input_owner.GuardProcessFacts(10,5,134361888290469085),
        input_owner.GuardProcessFacts(11,10,134361888294367328),
        input_owner.GuardProcessFacts(12,11,134362251846706448),
        r'C:\Users\ordinary\AppData\Local\vpn-control',r'C:\Users\ordinary\AppData\Local\vpn-control-install-inputs',
        r'C:\Users\ordinary\AppData\Local\VpnControl\persistent\state',
        r'C:\Users\ordinary\AppData\Local\VpnControl\persistent',CONTROLLER,
        '1'*64,123,'2'*64,'3'*40,'4'*64,'5'*40)

def binding():
    return {'controllerId':CONTROLLER,'helperSha256':'2'*64,'inputBound':True,
        'internalRequestSha256':'6'*64,'jobId':'12345678-1234-4567-8123-123456789ac0',
        'limited':True,'operationId':ACK['operationId'],'originalSid':SID,'ownerPid':11,
        'requestId':ACK['requestId'],'sessionId':1}

def profile(path, digest):
    return ssh_transport.WindowsInputProfile('synthetic',PurePosixPath('/owned/qga.sock'),
        PurePosixPath('/owned/qmp.sock'),100,200,99,1000,'7'*64,
        '12345678-1234-4567-8123-123456789ac1','ordinary',SID,1,
        PureWindowsPath(r'C:\Users\ordinary'),PureWindowsPath(context().install_directory),
        PureWindowsPath(context().task_parent_directory),path,digest,
        ssh_transport.WindowsInputTokenPolicy('ordinaryFilteredAdmin',0,3,True,False))


class WindowsGuestInputProducerTest(unittest.TestCase):
    def test_context_is_selected_by_config_not_positive_caller_flags(self):
        c=context();raw=input_owner._json(asdict(c));p=profile(Path('/not-opened'),hashlib.sha256(raw).hexdigest())
        self.assertEqual(input_owner._context(raw,'synthetic',p),c)
        for value in (dict(asdict(c),nativeAdmitted=True),dict(asdict(c),profile_name='foreign'),
                      dict(asdict(c),ordinary_sid='S-1-5-21-1-2-3-1001')):
            with self.assertRaises(ValueError):input_owner._context(input_owner._json(value),'synthetic',p)
        with self.assertRaises(ValueError):input_owner._input_schema('windows-input-start',
            {'host':'archlinux','profile':'synthetic','correlationId':CORRELATION,'jobId':binding()['jobId']})

    def test_join_requires_actual_accepted_ack_and_current_binding(self):
        c=context();b=binding()
        self.assertEqual(input_owner.validate_current_binding(b,ACK,ACK,c),b)
        for name,value in [('ownerPid',True),('ownerPid',99),('sessionId',True),('limited',1),
                           ('inputBound',1),('helperSha256','f'*64),('controllerId',ACK['requestId'])]:
            with self.subTest(name=name,value=value),self.assertRaises(ValueError):
                input_owner.validate_current_binding(dict(b,**{name:value}),ACK,ACK,c)
        for value in (dict(ACK,final=True),dict(ACK,code='OK'),dict(ACK,operationId=ACK['requestId'])):
            with self.assertRaises(ValueError):input_owner.validate_current_binding(b,value,ACK,c)

    def test_dotted_profile_name_matches_the_existing_configured_selector(self):
        c=replace(context(),profile_name='synthetic.ordinary')
        self.assertIn('__CURRENT_BINDING__',input_owner.render_unbound_current_guest_guard(c))
        self.assertEqual(input_owner._input_schema('windows-input-start',{'host':'archlinux','profile':'synthetic.ordinary',
                         'correlationId':CORRELATION})['profile'],'synthetic.ordinary')

    def test_atomic_sequence_requires_fresh_visual_and_binding(self):
        events=input_owner.decision_events({'action':'approve','frameSha256':'a'*64,'bindingSha256':'b'*64,
            'promptVerified':True,'expandedDetailsVerified':True,'detailsFocusVerified':True},'approve','b'*64,'a'*64)
        self.assertEqual([(r['data']['key']['data'],r['data']['down']) for r in events],
                         [('alt',True),('y',True),('y',False),('alt',False)])
        command={'action':'focus','frameSha256':'a'*64,'bindingSha256':'b'*64,
                 'promptVerified':True,'expandedDetailsVerified':False,'detailsFocusVerified':False}
        for value in (dict(command,promptVerified=False),dict(command,frameSha256='c'*64),
                      dict(command,bindingSha256='c'*64),dict(command,extra=True)):
            with self.assertRaises(ValueError):input_owner.decision_events(value,'focus','b'*64,'a'*64)

    def test_actual_guard_template_binding_source_and_argument_cap(self):
        raw,encoded=input_owner.guard_command(context(),binding())
        self.assertNotIn('__CURRENT_BINDING__',raw)
        self.assertLessEqual(len('powershell.exe -NoProfile -NonInteractive -EncodedCommand ')+len(encoded),30000)
        self.assertLessEqual(len(raw.encode()),65536)
        wrapper=base64.b64decode(encoded).decode('utf-16le')
        self.assertIn(hashlib.sha256(raw.encode()).hexdigest(),wrapper)
        with patch.object(input_owner,'CURRENT_GUEST_GUARD_TEMPLATE',input_owner.CURRENT_GUEST_GUARD_TEMPLATE+'\n'):
            with self.assertRaisesRegex(ValueError,'GUARD_TEMPLATE_SOURCE'):input_owner.guard_command(context(),binding())
        with patch.object(input_owner,'compressed_powershell_command',return_value='x'*20000):
            with self.assertRaisesRegex(ValueError,'INPUT_GUARD_COMMAND_BOUND'):input_owner.guard_command(context(),binding())

    def test_stdlib_frame_conversion_and_decompression_bounds(self):
        raw=b'P6\n2 1\n255\n\x00\x01\x02\x03\x04\x05'
        row={'state':'FRESH_CHAIN_FRAME','sha256':hashlib.sha256(raw).hexdigest(),
             'frameGzip':base64.b64encode(gzip.compress(raw,mtime=0)).decode()}
        self.assertEqual(input_owner._bounded_frame(row),raw)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);dims=input_owner._render_frame(raw,p/'a.ppm',p/'a.png')
            self.assertEqual((dims['width'],dims['height']),(2,1))
            self.assertTrue((p/'a.png').read_bytes().startswith(b'\x89PNG\r\n\x1a\n'))
        for candidate in (dict(row,sha256='0'*64),dict(row,frameGzip=row['frameGzip']+'!')):
            with self.assertRaises(ValueError):input_owner._bounded_frame(candidate)
        large=gzip.compress(b'x'*16777216,mtime=0)
        with self.assertRaisesRegex(ValueError,'BODY_BOUND'):
            input_owner._bounded_frame(dict(row,frameGzip=base64.b64encode(large).decode()))

    def test_renderer_refusal_precedes_guard_intent_and_transport(self):
        with tempfile.TemporaryDirectory() as d:
            guard_calls=[]
            with patch.object(input_owner,'_renderer_preflight',side_effect=ImportError('controlled renderer refusal')),\
                 patch.object(input_owner.channel,'Guard',side_effect=lambda *a:guard_calls.append(a)),\
                 patch.object(input_owner.subprocess,'Popen',side_effect=AssertionError('transport reached')):
                reply=input_owner.dispatch(d,'windows-input-start',{'host':'archlinux','profile':'synthetic','correlationId':CORRELATION})
            self.assertEqual(reply['state'],'UNKNOWN');self.assertEqual(guard_calls,[])
            self.assertFalse((Path(d)/'.rag_index').exists())


# A harmless real local child emits controlled transport rows. It cannot call
# QMP/QGA, read credentials, execute the native guard or qualify guest admission.
_CHILD=r"""
import base64,gzip,hashlib,json,sys
context,template,corr,scenario,binding=json.loads(sys.argv[1])
def emit(row):
 row.update(contextSha256=context,guardTemplateSha256=template,correlationId=corr)
 print(json.dumps(row),flush=True)
raw=b'P6\n2 1\n255\n\x00\x01\x02\x03\x04\x05'
def frame(b=None):
 emit({'state':'FRESH_CHAIN_FRAME','stage':'focus','sha256':hashlib.sha256(raw).hexdigest(),
 'frameGzip':base64.b64encode(gzip.compress(raw,mtime=0)).decode(),'binding':b,
 'bindingSha256':hashlib.sha256(json.dumps(b,sort_keys=True,separators=(',',':')).encode()).hexdigest() if b else None,
 'inputAckIsUiProof':False})
sys.stdin.readline();frame();stage='focus'
for line in sys.stdin:
 value=json.loads(line)
 if value['action']=='finish':break
 if value['action']=='join':
  emit({'state':'INPUT_JOB_JOINED','binding':binding,'bindingSha256':hashlib.sha256(json.dumps(binding,sort_keys=True,separators=(',',':')).encode()).hexdigest()});frame(binding);continue
 if value['action']=='observe':frame(binding);continue
 if scenario=='ack-lost':break
 if scenario=='collector-interrupted':
  print('{malformed',flush=True);continue
 emit({'state':'ORIGINAL_KEY_CHAIN_ACK','stage':stage,'commandId':1,'reply':{},'jobId':binding['jobId'],
       'replayAllowed':False,'uiSuccess':False})
 stage='expand' if stage=='focus' else 'approve';frame(binding)
emit({'state':'ORIGINAL_KEY_CHAIN_CLOSED','allOwnedQmpHoldersClosed':True,'replayAllowed':False})
"""



# Full emitted main + real local QMP wire. Only the Win32/proc/QGA boundaries
# are controlled; this model emits no native guest admission or platform effects.
_PRODUCTION_CHILD=r"""
import json,sys,os,socket,threading,base64
values=json.loads(sys.argv[1]);program,binding,ack,typed,green=values[:5];options=values[5] if len(values)>5 else {};sys.stdin.readline()
ns={'__name__':'inert_current_owner'};exec(compile(program,'<actual producer>','exec'),ns)
qmp=ns['QMP_SOCKET'];server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(qmp);server.listen(1)
frames=b'P6\n2 1\n255\n\x00\x01\x02\x03\x04\x05'
if options.get('large'):
 import hashlib,gzip
 pixels=hashlib.shake_256(b'owned deterministic P6 frame budget').digest(600000)+b'\0'*(1280*800*3-600000)
 frames=b'P6\n1280 800\n255\n'+pixels
 assert 590000<len(gzip.compress(frames,mtime=0))<=700000
keys=[]
def broker():
 c,_=server.accept();r=c.makefile('rb');c.sendall(b'{"QMP":{}}\n')
 try:
  for raw in r:
   value=json.loads(raw);name=value['execute'];args=value.get('arguments',{})
   if name=='screendump':
    fd=os.open(args['filename'],os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:os.write(fd,frames)
    finally:os.close(fd)
   elif name=='input-send-event':keys.append(args['events'])
   elif name!='qmp_capabilities':raise AssertionError(name)
   c.sendall(json.dumps({'id':value['id'],'return':{}}).encode()+b'\n')
 finally:r.close();c.close()
t=threading.Thread(target=broker);t.start();handles={};guard_calls=[]
def qga(sock,name,args,**kw):
 if name=='guest-file-open':
  body=binding if args['path'].endswith('uac-binding.json')else ack
  handle=len(handles)+1;handles[handle]=json.dumps(body).encode();return handle
 if name=='guest-file-read':
  body=handles[args['handle']];handles[args['handle']]=b''
  return {'count':len(body),'buf-b64':base64.b64encode(body).decode(),'eof':True}
 if name=='guest-file-close':return {}
 if name=='guest-exec':
  wrapper=base64.b64decode(args['arg'][-1]).decode('utf-16le')
  assert len(args['arg'][-1])+len('powershell.exe -NoProfile -NonInteractive -EncodedCommand ')<=30000
  guard_calls.append(wrapper);return {'pid':700}
 if name=='guest-exec-status':
  # Model source-bound native guard projection. Actual C#/Windows is not invoked.
  return {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(typed).encode()+b'\n'+json.dumps(green).encode()).decode()}
 raise AssertionError(name)
ns['call']=qga;ns['identity']=lambda:['inert native boundary'];ns['main']();t.join(2);assert not t.is_alive();server.close()
if not options.get('large') and not options.get('sourceBoundary'):
 assert len(keys)==3 and len(guard_calls)==4
 assert [(r['data']['key']['data'],r['data']['down'])for r in keys[-1]]==[('alt',True),('y',True),('y',False),('alt',False)]
if options.get('large'):
 if len(keys)==3:assert [(r['data']['key']['data'],r['data']['down'])for r in keys[-1]]==[('alt',True),('y',True),('y',False),('alt',False)]
 print('LARGE_FRAME_WIRE '+json.dumps({'gzipBytes':len(gzip.compress(frames,mtime=0)),'keyPackets':len(keys),'lastPacket':keys[-1]if keys else None,'nativeCalls':0}),file=sys.stderr)
if options.get('sourceBoundary'):
 print('SOURCE_GUARD_WIRE '+json.dumps({'keyPackets':len(keys),'lastPacket':keys[-1]if keys else None,'nativeCalls':0}),file=sys.stderr)
"""

@unittest.skipUnless(input_owner.channel.coordinator_capable(),'POSIX retained observer required; pure producer/profile tests remain portable')
class WindowsGuestInputOriginalObserverTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        self.observers=[];self.fake_guard_calls=[]
        self.c=context();self.raw=input_owner._json(asdict(self.c));self.path=self.root/'context.json';self.path.write_bytes(self.raw)
        self.digest=hashlib.sha256(self.raw).hexdigest();self.p=profile(self.path,self.digest)
        owner=self
        class ControlledGuard:
            def __init__(self,root):
                owner.fake_guard_calls.append(root);self.held=_Held();self.closed=False
                self.config=ssh_transport.SshConfig(root,{'archlinux':ssh_transport.SshHost('archlinux','unused',22,'unused',
                    Path('/unused'),Path('/unused'),windows_input_profiles={'synthetic':owner.p})})
            def guard(self):self.held.finish()
            def close(self):
                if not self.closed:self.held.close();self.closed=True
        self.guard_patch=patch.object(input_owner.channel,'Guard',ControlledGuard);self.guard_patch.start()
        self.epoch_patch=patch.object(input_owner,'_source_epoch',return_value=(self.c.caller_source_sha,self.c.caller_content_fingerprint));self.epoch_patch.start()
        self.runtime_patch=patch.object(input_owner,'build_remote_program',return_value='controlled transport fixture');self.runtime_patch.start()

    def tearDown(self):
        for observer in self.observers:
            if observer.process.poll() is None:
                # Close only this controlled local child; the production API is
                # required to retain unknown live custody instead of killing.
                try:observer.process.stdin.write(b'{"action":"finish"}\n');observer.process.stdin.flush()
                except (OSError,ValueError):pass
            observer.process.wait(timeout=5)
            observer.thread.join(timeout=5)
            self.assertFalse(observer.thread.is_alive())
            self.assertTrue(observer.closed)
            self.assertTrue(observer.guard.closed)
            self.assertTrue(all(stream.closed for stream in (observer.process.stdin,observer.process.stdout,observer.process.stderr)))
            for fd in [*observer.raw_fds,observer.lock_fd]:
                with self.assertRaises(OSError):os.fstat(fd)
            print('OWNED_CHILD_CLOSED '+json.dumps({'pid':observer.process.pid,'returncode':observer.process.returncode,
                  'threadClosed':True,'streamsClosed':True,'heldSourcesClosed':True,'nativeCalls':0}),file=sys.stderr)
        with input_owner._SESSIONS_LOCK:
            for key in list(input_owner._SESSIONS):
                if key[0]==str(self.root):del input_owner._SESSIONS[key]
        self.runtime_patch.stop();self.epoch_patch.stop();self.guard_patch.stop();self.temp.cleanup()

    def start(self,scenario='normal'):
        argv=[sys.executable,'-u','-c',_CHILD,json.dumps([self.digest,input_owner.CURRENT_GUEST_GUARD_TEMPLATE_SHA256,CORRELATION,scenario,binding()])]
        with patch.object(input_owner,'_launch',return_value=(argv,b'{}\n')):
            reply=input_owner.dispatch(self.root,'windows-input-start',{'host':'archlinux','profile':'synthetic','correlationId':CORRELATION})
        self.assertTrue(reply['ok'],reply)
        self.assertFalse(reply['nativeInputAdmitted'])
        observer=input_owner._SESSIONS[(str(self.root),reply['inputId'])];self.observers.append(observer)
        self.selectors={'host':'archlinux','profile':'synthetic','correlationId':CORRELATION,'inputId':reply['inputId']}
        return reply,observer

    def call(self,action,**more):
        return input_owner.dispatch(self.root,'windows-input-'+action,dict(self.selectors,**more))

    def join(self):
        self.assertEqual(self.call('join',acceptedAck=ACK)['state'],'INPUT_JOB_JOINED')
        reply=self.call('observe');self.assertEqual(reply['state'],'INPUT_FRAME_READY');return reply

    def focus(self,row):
        return {'action':'focus','frameSha256':row['sha256'],'bindingSha256':row['bindingSha256'],
                'promptVerified':True,'expandedDetailsVerified':False,'detailsFocusVerified':False}

    def test_first_actual_frame_precedes_job_join_and_no_replay(self):
        reply,observer=self.start()
        self.assertIsNone(reply['binding']);self.assertIsNone(reply['bindingSha256'])
        with patch.object(input_owner.subprocess,'Popen',side_effect=AssertionError('replay')):
            self.assertEqual(input_owner.dispatch(self.root,'windows-input-start',{'host':'archlinux','profile':'synthetic','correlationId':CORRELATION})['inputId'],reply['inputId'])
        row=self.join();ack=self.call('decision',decision=self.focus(row))
        self.assertEqual(ack['state'],'INPUT_KEY_ACK_ONLY');self.assertFalse(ack['uiSuccess'])
        self.assertFalse(ack['nativeInputAdmitted']);self.assertFalse(ack['installerResultProved'])
        closed=self.call('finish');self.assertEqual(closed['state'],'INPUT_CLOSED');self.assertTrue(closed['holdersClosed'])

    def test_dispatch_emitted_main_and_original_collector_share_real_qmp_wire(self):
        self.runtime_patch.stop()
        self.p=replace(self.p,qga_socket_path=PurePosixPath(str(self.root/'qga.sock')),
                       qmp_socket_path=PurePosixPath(str(self.root/'qmp.sock')),qemu_uid=os.getuid())
        typed={'state':'CURRENT_TYPED_GETPROCESS_BIRTHS','effects':False,'source':'GetProcess.StartTime.ToFileTimeUtc',
               'explorer40':self.c.console_birth,'owner11':self.c.owner.birth,'launcher10':self.c.owner_wrapper.birth}
        green={'state':'CURRENT_BOUND_GUEST_GREEN','jobId':binding()['jobId'],'sid':SID,'sessionId':1,
               'consolePid':40,'ownerPid':11,'ownerBirth':self.c.owner.birth,'boot':self.c.boot_utc,
               'elevated':0,'elevationType':3,'effects':False,'helperActors':[],
               'consentActor':{'pid':50,'birth':'134362251846706448'}}
        def launch(guard,program):
            return [sys.executable,'-u','-c',_PRODUCTION_CHILD,json.dumps([program,binding(),ACK,typed,green])],b'{}\n'
        try:
            with patch.object(input_owner,'_launch',side_effect=launch):
                reply=input_owner.dispatch(self.root,'windows-input-start',{'host':'archlinux','profile':'synthetic','correlationId':CORRELATION})
            self.assertEqual(reply['state'],'INPUT_FRAME_READY',reply);self.assertIsNone(reply['binding'])
            observer=input_owner._SESSIONS[(str(self.root),reply['inputId'])];self.observers.append(observer)
            self.selectors={'host':'archlinux','profile':'synthetic','correlationId':CORRELATION,'inputId':reply['inputId']}
            row=self.join()
            for stage,expanded,focused in [('focus',False,False),('expand',False,True),('approve',True,True)]:
                decision={'action':stage,'frameSha256':row['sha256'],'bindingSha256':row['bindingSha256'],
                          'promptVerified':True,'expandedDetailsVerified':expanded,'detailsFocusVerified':focused}
                ack=self.call('decision',decision=decision)
                self.assertEqual(ack['state'],'INPUT_KEY_ACK_ONLY',ack);self.assertFalse(ack['uiSuccess'])
                if stage!='approve':row=self.call('observe')
            observer.thread.join(5)
            self.assertEqual(observer.process.returncode,0,(observer.directory/'stderr.private').read_bytes())
            self.assertEqual(self.call('finish')['state'],'INPUT_CLOSED')
            rows=[json.loads(line)for line in (observer.directory/'stdout.private').read_bytes().splitlines()]
            self.assertEqual(len([r for r in rows if r['state']=='SAME_GUEST_GUARD_ACCEPTED']),3)
            self.assertEqual([r['stage']for r in rows if r['state']=='ORIGINAL_KEY_CHAIN_ACK'],['focus','expand','approve'])
            for r in rows:
                self.assertEqual(r['contextSha256'],self.digest)
                self.assertEqual(r['guardTemplateSha256'],input_owner.CURRENT_GUEST_GUARD_TEMPLATE_SHA256)
        finally:self.runtime_patch.start()

    def test_required_five_valid_large_frames_complete_three_key_flow(self):
        self.runtime_patch.stop()
        self.p=replace(self.p,qga_socket_path=PurePosixPath(str(self.root/'qga.sock')),
                       qmp_socket_path=PurePosixPath(str(self.root/'qmp.sock')),qemu_uid=os.getuid())
        typed={'state':'CURRENT_TYPED_GETPROCESS_BIRTHS','effects':False,'source':'GetProcess.StartTime.ToFileTimeUtc',
               'explorer40':self.c.console_birth,'owner11':self.c.owner.birth,'launcher10':self.c.owner_wrapper.birth}
        green={'state':'CURRENT_BOUND_GUEST_GREEN','jobId':binding()['jobId'],'sid':SID,'sessionId':1,
               'consolePid':40,'ownerPid':11,'ownerBirth':self.c.owner.birth,'boot':self.c.boot_utc,
               'elevated':0,'elevationType':3,'effects':False,'helperActors':[],
               'consentActor':{'pid':50,'birth':'134362251846706448'}}
        def launch(guard,program):
            return [sys.executable,'-u','-c',_PRODUCTION_CHILD,json.dumps([program,binding(),ACK,typed,green,{'large':True}])],b'{}\n'
        try:
            with patch.object(input_owner,'_launch',side_effect=launch):
                reply=input_owner.dispatch(self.root,'windows-input-start',{'host':'archlinux','profile':'synthetic','correlationId':CORRELATION})
            self.assertEqual(reply['state'],'INPUT_FRAME_READY',reply)
            observer=input_owner._SESSIONS[(str(self.root),reply['inputId'])];self.observers.append(observer)
            self.selectors={'host':'archlinux','profile':'synthetic','correlationId':CORRELATION,'inputId':reply['inputId']}
            baseline=observer.version
            self.assertEqual(self.call('join',acceptedAck=ACK)['state'],'INPUT_JOB_JOINED')
            row=observer.wait('INPUT_FRAME_READY',baseline)
            self.assertEqual(row['state'],'INPUT_FRAME_READY',row)
            for stage,expanded,focused in [('focus',False,False),('expand',False,True),('approve',True,True)]:
                baseline=observer.version
                decision={'action':stage,'frameSha256':row['sha256'],'bindingSha256':row['bindingSha256'],
                          'promptVerified':True,'expandedDetailsVerified':expanded,'detailsFocusVerified':focused}
                ack=self.call('decision',decision=decision)
                self.assertEqual(ack['state'],'INPUT_KEY_ACK_ONLY',ack)
                row=observer.wait('INPUT_FRAME_READY',baseline)
                self.assertEqual(row['state'],'INPUT_FRAME_READY',row)
            observer.thread.join(5)
            self.assertEqual(observer.process.returncode,0)
            rows=[json.loads(line)for line in (observer.directory/'stdout.private').read_bytes().splitlines()]
            frames=[r for r in rows if r['state']=='FRESH_CHAIN_FRAME']
            self.assertEqual(len(frames),5)
            for r in frames:
                self.assertGreater(len(base64.b64decode(r['frameGzip'])),590000)
                self.assertLessEqual(len(base64.b64decode(r['frameGzip'])),700000)
                self.assertEqual(len(input_owner._bounded_frame(r)),1280*800*3+len(b'P6\n1280 800\n255\n'))
            self.assertEqual([r['stage']for r in rows if r['state']=='ORIGINAL_KEY_CHAIN_ACK'],['focus','expand','approve'])
            broker_rows=[line.removeprefix('LARGE_FRAME_WIRE ')for line in (observer.directory/'stderr.private').read_text().splitlines()if line.startswith('LARGE_FRAME_WIRE ')]
            self.assertEqual(len(broker_rows),1)
            broker=json.loads(broker_rows[0]);self.assertEqual(broker['keyPackets'],3)
            self.assertEqual([(r['data']['key']['data'],r['data']['down'])for r in broker['lastPacket']],
                             [('alt',True),('y',True),('y',False),('alt',False)])
            self.assertEqual(broker['nativeCalls'],0)
            print('BROKER_KEY_PACKETS '+json.dumps(broker),file=sys.stderr)
            print('FIVE_FRAME_BUDGET '+json.dumps({'stdoutBytes':(observer.directory/'stdout.private').stat().st_size,
                  'frames':5,'nativeCalls':0,'allThreeKeysAckOnly':True}),file=sys.stderr)
        finally:self.runtime_patch.start()

    def _start_actual_source_control(self):
        self.runtime_patch.stop()
        self.p=replace(self.p,qga_socket_path=PurePosixPath(str(self.root/'qga.sock')),
                       qmp_socket_path=PurePosixPath(str(self.root/'qmp.sock')),qemu_uid=os.getuid())
        typed={'state':'CURRENT_TYPED_GETPROCESS_BIRTHS','effects':False,'source':'GetProcess.StartTime.ToFileTimeUtc',
               'explorer40':self.c.console_birth,'owner11':self.c.owner.birth,'launcher10':self.c.owner_wrapper.birth}
        green={'state':'CURRENT_BOUND_GUEST_GREEN','jobId':binding()['jobId'],'sid':SID,'sessionId':1,
               'consolePid':40,'ownerPid':11,'ownerBirth':self.c.owner.birth,'boot':self.c.boot_utc,
               'elevated':0,'elevationType':3,'effects':False,'helperActors':[],
               'consentActor':{'pid':50,'birth':'134362251846706448'}}
        def launch(guard,program):
            return [sys.executable,'-u','-c',_PRODUCTION_CHILD,json.dumps([program,binding(),ACK,typed,green,{'sourceBoundary':True}])],b'{}\n'
        try:
            with patch.object(input_owner,'_launch',side_effect=launch):
                reply=input_owner.dispatch(self.root,'windows-input-start',{'host':'archlinux','profile':'synthetic','correlationId':CORRELATION})
            self.assertEqual(reply['state'],'INPUT_FRAME_READY',reply)
            observer=input_owner._SESSIONS[(str(self.root),reply['inputId'])];self.observers.append(observer)
            self.selectors={'host':'archlinux','profile':'synthetic','correlationId':CORRELATION,'inputId':reply['inputId']}
            return observer,self.join()
        finally:self.runtime_patch.start()

    def test_collector_and_foreground_source_rehash_share_owned_lifetime(self):
        observer,_=self._start_actual_source_control()
        name=str(self.path);fd,pinned_gen,pinned_sha,pinned_raw=observer.guard.held.files[name]
        named_before=source_closure.generation(self.path.stat())
        paused=threading.Event();resume=threading.Event();main=threading.current_thread()
        original_read=source_closure.os.read;original_guard=observer.source_guard
        original_condition=observer.condition;armed=True;evidence={};errors=[]
        class BoundaryCondition:
            def __enter__(boundary):
                if threading.current_thread() is main and paused.is_set():
                    acquired=original_condition.acquire(blocking=False)
                    evidence.setdefault('collectorOwnedCondition',not acquired)
                    if acquired:original_condition.release()
                    else:resume.set()
                return original_condition.__enter__()
            def __exit__(boundary,*args):return original_condition.__exit__(*args)
            def __getattr__(boundary,key):return getattr(original_condition,key)
        def guarded():
            try:return original_guard()
            except BaseException as error:
                errors.append({'thread':threading.current_thread().name,'type':type(error).__name__,'message':str(error)})
                raise
            finally:
                if threading.current_thread() is main and paused.is_set():resume.set()
        def retained_read(current_fd,count):
            nonlocal armed
            if current_fd==fd and threading.current_thread() is observer.thread and armed:
                armed=False
                evidence.update(path=name,fd=fd,pinnedSha256=pinned_sha,pinnedGeneration=list(pinned_gen),
                                collectorOffsetAfterSeek=os.lseek(fd,0,os.SEEK_CUR),
                                originalPid=observer.process.pid,originalInitiallyTerminal=observer.process.poll() is not None)
                paused.set()
                if not resume.wait(5):raise AssertionError('source boundary release unavailable')
                evidence['collectorOffsetBeforeRead']=os.lseek(fd,0,os.SEEK_CUR)
            return original_read(current_fd,count)
        observer.condition=BoundaryCondition();observer.source_guard=guarded
        try:
            with patch.object(source_closure.os,'read',side_effect=retained_read):
                # Harmless fixture observation supplies a real emitted frame to
                # the real collector; no key or native admission is bypassed.
                observer.process.stdin.write(b'{"action":"observe"}\n');observer.process.stdin.flush()
                self.assertTrue(paused.wait(5),'collector never reached actual held-FD read')
                row=self.call('observe')
                evidence.update(namedSha256=hashlib.sha256(self.path.read_bytes()).hexdigest(),
                                heldSha256=hashlib.sha256(os.pread(fd,len(pinned_raw)+1,0)).hexdigest(),
                                namedGeneration=list(source_closure.generation(self.path.stat())),
                                heldGeneration=list(source_closure.generation(os.fstat(fd))),errors=errors,result=row['state'])
                print('SOURCE_FD_BOUNDARY '+json.dumps(evidence,sort_keys=True),file=sys.stderr)
                self.assertEqual(evidence['namedSha256'],pinned_sha)
                self.assertEqual(evidence['heldSha256'],pinned_sha)
                self.assertEqual(tuple(evidence['namedGeneration']),named_before)
                self.assertEqual(tuple(evidence['heldGeneration']),pinned_gen)
                self.assertFalse(evidence['originalInitiallyTerminal'])
                self.assertEqual(row['state'],'INPUT_FRAME_READY',row)
                self.assertEqual(errors,[])
                self.assertEqual(evidence['collectorOffsetBeforeRead'],0)
            for stage,expanded,focused in [('focus',False,False),('expand',False,True),('approve',True,True)]:
                decision={'action':stage,'frameSha256':row['sha256'],'bindingSha256':row['bindingSha256'],
                          'promptVerified':True,'expandedDetailsVerified':expanded,'detailsFocusVerified':focused}
                self.assertEqual(self.call('decision',decision=decision)['state'],'INPUT_KEY_ACK_ONLY')
                if stage!='approve':row=self.call('observe')
            observer.thread.join(5);self.assertEqual(observer.process.returncode,0)
            wire=[json.loads(line.removeprefix('SOURCE_GUARD_WIRE '))for line in (observer.directory/'stderr.private').read_text().splitlines()if line.startswith('SOURCE_GUARD_WIRE ')]
            self.assertEqual(len(wire),1);self.assertEqual(wire[0]['keyPackets'],3)
            self.assertEqual([(r['data']['key']['data'],r['data']['down'])for r in wire[0]['lastPacket']],
                             [('alt',True),('y',True),('y',False),('alt',False)])
            print('SOURCE_GUARD_KEYS '+json.dumps(wire[0]),file=sys.stderr)
        finally:
            resume.set();observer.source_guard=original_guard;observer.condition=original_condition

    def _genuine_source_drift_refuses(self,replace_name):
        observer,row=self._start_actual_source_control()
        source_name=str(self.path);fd,pinned_gen,pinned_sha,_=observer.guard.held.files[source_name]
        source_errors=[];original_guard=observer.source_guard
        def guarded():
            try:return original_guard()
            except BaseException as error:
                source_errors.append({'type':type(error).__name__,'message':str(error)})
                raise
        observer.source_guard=guarded
        try:
            with observer.condition,patch.object(input_owner.subprocess,'Popen',side_effect=AssertionError('original replay')):
                if replace_name:
                    replacement=self.root/'replacement.json';replacement.write_bytes(self.raw)
                    os.replace(replacement,self.path)
                else:self.path.write_bytes(self.raw+b' ')
                refused=self.call('decision',decision=self.focus(row))
                self.assertEqual(refused['state'],'UNKNOWN');self.assertFalse(refused['replayAllowed'])
                repeat=input_owner.dispatch(self.root,'windows-input-start',{'host':'archlinux','profile':'synthetic','correlationId':CORRELATION})
                self.assertEqual(repeat['inputId'],observer.input_id);self.assertEqual(repeat['state'],'UNKNOWN')
            self.assertTrue(source_errors)
            expected='Final file FD/name generation drift'if replace_name else'Final source SHA drift'
            self.assertEqual(source_errors[0]['message'],expected)
            print('GENUINE_SOURCE_DRIFT '+json.dumps({'replaceName':replace_name,'pinnedSha256':pinned_sha,
                  'namedSha256':hashlib.sha256(self.path.read_bytes()).hexdigest(),
                  'pinnedGeneration':list(pinned_gen),'namedGeneration':list(source_closure.generation(self.path.stat())),
                  'heldGeneration':list(source_closure.generation(os.fstat(fd))),'sourceErrors':source_errors,
                  'result':refused['state'],'sameOriginal':repeat['inputId']==observer.input_id,'replayAllowed':False}),file=sys.stderr)
        finally:observer.source_guard=original_guard
        rows=[json.loads(line)for line in (observer.directory/'stdout.private').read_bytes().splitlines()]
        self.assertFalse(any(r['state']=='ORIGINAL_KEY_CHAIN_ACK'for r in rows))

    def test_genuine_source_bytes_drift_refuses_new_keys_and_replay(self):
        self._genuine_source_drift_refuses(False)

    def test_genuine_source_name_replacement_refuses_new_keys_and_replay(self):
        self._genuine_source_drift_refuses(True)

    def test_binding_mismatch_and_ambiguous_visual_refuse_before_command(self):
        _,observer=self.start();row=self.join()
        before=observer.version
        decision=dict(self.focus(row),promptVerified=False)
        self.assertEqual(self.call('decision',decision=decision)['state'],'UNKNOWN')
        self.assertEqual(observer.version,before)
        self.assertNotIn(b'"action":"focus"',(observer.directory/'stdout.private').read_bytes())

    def test_intent_loss_refuses_before_atomic_input(self):
        _,observer=self.start();row=self.join()
        (observer.directory/'intent.json').unlink()
        self.assertEqual(self.call('decision',decision=self.focus(row))['state'],'UNKNOWN')
        self.assertIsNone(observer.process.poll())
        self.assertFalse(observer.closed)

    def test_lost_ack_never_replays_and_preserves_original(self):
        _,observer=self.start('ack-lost');row=self.join()
        self.assertEqual(self.call('decision',decision=self.focus(row))['state'],'UNKNOWN')
        with patch.object(input_owner.subprocess,'Popen',side_effect=AssertionError('replay')):
            self.assertEqual(self.call('decision',decision=self.focus(row))['state'],'UNKNOWN')
        observer.thread.join(timeout=5);self.assertTrue(observer.closed)

    def test_decision_cannot_alias_observe_or_finish(self):
        _,observer=self.start()
        with self.assertRaises(ValueError):self.call('decision',decision={'action':'finish'})
        self.assertIsNone(observer.process.poll())
        with self.assertRaises(ValueError):self.call('decision',decision={'action':'observe'})

    def test_pre_popen_refusal_leaves_no_process_none_registry(self):
        with patch.object(input_owner,'_launch',return_value=(['unused'],b'{}\n')),\
             patch.object(input_owner.subprocess,'Popen',side_effect=OSError('controlled pre-Popen refusal')):
            first=input_owner.dispatch(self.root,'windows-input-start',{'host':'archlinux','profile':'synthetic','correlationId':CORRELATION})
            second=input_owner.dispatch(self.root,'windows-input-start',{'host':'archlinux','profile':'synthetic','correlationId':CORRELATION})
        self.assertEqual(first['state'],'UNKNOWN');self.assertEqual(second['state'],'UNKNOWN')
        self.assertFalse(second['replayAllowed'])

    def test_fresh_cli_owner_cannot_recover_or_replay_disk_markers(self):
        _,observer=self.start();self.join()
        code="""import json,sys
from agent_tools import windows_guest_input as owner
owner.channel.Guard=lambda *a: (_ for _ in ()).throw(AssertionError('Guard reached'))
print(json.dumps(owner.dispatch(sys.argv[1],'windows-input-observe',json.loads(sys.argv[2]))))
"""
        result=subprocess.run([sys.executable,'-B','-c',code,str(self.root),json.dumps(self.selectors)],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        reply=json.loads(result.stdout);self.assertEqual(reply['state'],'UNKNOWN');self.assertFalse(reply['replayAllowed'])
        # Even a disk marker cannot recreate a live in-memory original.
        (observer.directory/'untrusted-marker.json').write_text('{"nativeInputAdmitted":true}')
        with input_owner._SESSIONS_LOCK: del input_owner._SESSIONS[(str(self.root),observer.input_id)]
        self.assertEqual(self.call('observe')['state'],'UNKNOWN')
        with patch.object(input_owner.subprocess,'Popen',side_effect=AssertionError('SSH replay')):
            reply=input_owner.dispatch(self.root,'windows-input-start',{'host':'archlinux','profile':'synthetic','correlationId':CORRELATION})
        self.assertEqual(reply['state'],'UNKNOWN');self.assertFalse(reply['replayAllowed'])

    def test_collector_interruption_keeps_live_original_custody(self):
        _,observer=self.start('collector-interrupted');row=self.join()
        self.assertEqual(self.call('decision',decision=self.focus(row))['state'],'UNKNOWN')
        self.assertIsNone(observer.process.poll());self.assertFalse(observer.closed)
        with patch.object(input_owner.subprocess,'Popen',side_effect=AssertionError('replay')):
            self.assertEqual(self.call('decision',decision=self.focus(row))['state'],'UNKNOWN')


_POWERSHELL=os.environ.get('VPN_CONTROL_TEST_PWSH') or shutil.which('pwsh') or shutil.which('powershell')
@unittest.skipUnless(_POWERSHELL,'local PowerShell required for exact native guard syntax control')
class WindowsGuestInputPowerShellSourceTest(unittest.TestCase):
    def test_exact_emitted_native_guard_parser_only(self):
        body,_=input_owner.guard_command(context(),binding())
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'guard.ps1';path.write_text(body,encoding='utf-8',newline='\n')
            command="$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile('"+str(path).replace("'","''")+"',[ref]$t,[ref]$e);if($e.Count){$e|%{$_.ToString()};exit 1};'PARSE_ONLY_NO_NATIVE'"
            result=subprocess.run([_POWERSHELL,'-NoLogo','-NoProfile','-NonInteractive','-Command',command],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'PARSE_ONLY_NO_NATIVE',result.stdout)


class WindowsGuestInputEmittedRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.c=context();self.p=profile(Path('/not-opened'), '8'*64)
        self.source=input_owner.build_remote_program(self.p,self.c,CORRELATION,'8'*64)
        self.runtime={'__name__':'controlled_no_native'}
        exec(compile(self.source,'<actual emitted input program>','exec'),self.runtime)
        self.runtime['validate_globals']();self.runtime['validate_parameters'](self.runtime['PARAMETERS'])
        self.events=[];self.runtime['emit']=self.events.append
        self.calls=[]
        self.result={'exited':True,'exitcode':0,'out-data':base64.b64encode(input_owner._json({
            'state':'CURRENT_TYPED_GETPROCESS_BIRTHS','effects':False,'source':'GetProcess.StartTime.ToFileTimeUtc',
            'explorer40':self.c.console_birth,'owner11':self.c.owner.birth,'launcher10':self.c.owner_wrapper.birth})+b'\n'+input_owner._json({
            'state':'CURRENT_BOUND_GUEST_GREEN','jobId':binding()['jobId'],'sid':SID,'sessionId':1,
            'consolePid':40,'ownerPid':11,'ownerBirth':self.c.owner.birth,'boot':self.c.boot_utc,
            'elevated':0,'elevationType':3,'effects':False,'helperActors':[],
            'consentActor':{'pid':50,'birth':'134362251846706448'}})).decode()}
        def controlled_qga(sock,command,args,**kwargs):
            self.calls.append((sock,command,args))
            if command=='guest-exec':return {'pid':7}
            if command=='guest-exec-status':return self.result
            raise AssertionError('unexpected controlled QGA command')
        self.runtime['call']=controlled_qga

    def test_actual_emission_couples_profile_context_template_and_command(self):
        self.assertLessEqual(len(self.source.encode()),65536)
        # This execution reaches emitted functions only; __main__ is suppressed.
        self.assertNotIn('jobId',self.runtime['PARAMETERS'])
        self.assertEqual(self.runtime['CONTEXT_SHA256'],'8'*64)
        self.assertEqual(self.runtime['GUARD_TEMPLATE_SHA256'],input_owner.CURRENT_GUEST_GUARD_TEMPLATE_SHA256)
        row,digest=self.runtime['current_guest_guard'](binding())
        self.assertEqual(row['state'],'CURRENT_BOUND_GUEST_GREEN')
        body,encoded=input_owner.guard_command(self.c,binding())
        self.assertEqual(self.calls[0][2]['arg'][-1],encoded)
        self.assertEqual(digest,hashlib.sha256(body.encode()).hexdigest())
        self.assertEqual([c[1] for c in self.calls],['guest-exec','guest-exec-status'])
        with patch.dict(self.runtime,GUARD_SOURCE=self.runtime['GUARD_SOURCE']+'\n'):
            with self.assertRaisesRegex(ValueError,'INTERNAL_GUARD_SOURCE'):self.runtime['current_guest_guard'](binding())
        self.assertEqual(len(self.calls),2)

    def test_command_bound_and_failed_guard_refuse_before_any_key(self):
        with patch.dict(self.runtime,compressed_powershell_command=lambda _: 'x'*20000):
            with self.assertRaisesRegex(ValueError,'GUARD_FULL_COMMAND_BOUND'):self.runtime['current_guest_guard'](binding())
        self.assertEqual(self.calls,[])
        self.result={'exited':True,'exitcode':1,'out-data':''}
        sends=[]
        with tempfile.TemporaryDirectory() as directory,patch.dict(self.runtime,load_binding=lambda _:binding(),identity=lambda:['controlled']):
            with self.assertRaisesRegex(ValueError,'CURRENT_GUEST_GUARD_REFUSED'):
                self.runtime['perform_current_stage']({},'focus',binding(),ACK,None,['controlled'],lambda:b'',
                    lambda *a:sends.append(a),directory)
        self.assertEqual(sends,[])

    def test_full_guard_binding_and_consent_are_rechecked_before_atomic_wire(self):
        raw=b'P6\n1 1\n255\n\x01\x02\x03'
        sha=hashlib.sha256(raw).hexdigest();bsha=hashlib.sha256(input_owner._json(binding())).hexdigest()
        decision={'action':'focus','frameSha256':sha,'bindingSha256':bsha,'promptVerified':True,
                  'expandedDetailsVerified':False,'detailsFocusVerified':False}
        left,right=socket.socketpair();captured=[]
        def send(name,args):
            left.sendall(input_owner._json({'execute':name,'arguments':args})+b'\n')
            captured.append(json.loads(right.recv(8192)));return 1,{}
        try:
            with tempfile.TemporaryDirectory() as directory,patch.dict(self.runtime,load_binding=lambda _:binding(),identity=lambda:['controlled']):
                self.runtime['perform_current_stage'](decision,'focus',binding(),ACK,None,['controlled'],lambda:raw,send,directory)
            self.assertEqual(captured[0]['execute'],'input-send-event')
            self.assertEqual(captured[0]['arguments']['events'],input_owner.decision_events(decision,'focus',bsha,sha))
            self.assertEqual([c[1]for c in self.calls],['guest-exec','guest-exec-status'])
            ack=self.events[-1];self.assertFalse(ack['uiSuccess']);self.assertFalse(ack['replayAllowed'])
            captured.clear();self.calls.clear()
            sequence=iter([binding(),dict(binding(),operationId=ACK['requestId'])])
            with tempfile.TemporaryDirectory() as directory,patch.dict(self.runtime,load_binding=lambda _:next(sequence),identity=lambda:['controlled']):
                with self.assertRaisesRegex(ValueError,'CURRENT_BINDING_CHANGED'):
                    self.runtime['perform_current_stage'](decision,'focus',binding(),ACK,None,['controlled'],lambda:raw,send,directory)
            self.assertEqual(captured,[])
            with tempfile.TemporaryDirectory() as directory,patch.dict(self.runtime,load_binding=lambda _:binding(),identity=lambda:['controlled']):
                with self.assertRaisesRegex(ValueError,'ORIGINAL_CONSENT_CHANGED'):
                    self.runtime['perform_current_stage'](decision,'focus',binding(),ACK,{'pid':99},['controlled'],lambda:raw,send,directory)
            self.assertEqual(captured,[])
        finally:left.close();right.close()

    def test_guest_open_protocol_error_is_unknown_not_missing_metadata(self):
        def refuse(*args,**kwargs):raise ValueError('controlled QGA protocol refusal')
        with patch.dict(self.runtime,call=refuse):
            with self.assertRaisesRegex(ValueError,'controlled QGA protocol refusal'):
                self.runtime['read']('/unused','C:\\missing.json')

    def test_current_binding_refusal_matches_authentic_original_policy(self):
        original_controller='10d0e79e-900a-4d0a-a888-83ca40304ffb'
        c=replace(self.c,owner_controller_id=original_controller,ordinary_sid='S-1-5-21-606332539-4179368406-55829832-1000',
            owner_wrapper=input_owner.GuardProcessFacts(7580,6656,134361888290469085),
            owner=input_owner.GuardProcessFacts(9856,7580,134361888294367328),
            frontend=input_owner.GuardProcessFacts(2064,9856,134362251846706448),
            helper_sha256='84f580792428f05b810000ea52729b10f43668d93b2ee4a5119022736126a98d')
        # Exact five-field projection from genuine public J2 request ACKde8a7538.
        ack={'requestId':'0ae408e8-a60f-4f15-8f6f-36788fce7437','operationId':'fda2d042-e605-4c98-b6c9-ea1788f5b229',
             'controllerId':original_controller,'code':'ACCEPTED','final':False}
        b=dict(binding(),controllerId=original_controller,requestId=ack['requestId'],operationId=ack['operationId'],
               jobId='18c8ee55-df82-4ac1-8696-63def65a4198',ownerPid=9856,originalSid=c.ordinary_sid,helperSha256=c.helper_sha256)
        # Internal digest here is an inert synthetic input, not an exported private record.
        self.assertEqual(input_owner.validate_current_binding(b,dict(ack,data={'handoffReady':False}),ack,c),b)
        for change in ({'operationId':ACK['operationId']},{'ownerPid':11},{'limited':False},{'inputBound':False}):
            with self.assertRaises(ValueError):input_owner.validate_current_binding(dict(b,**change),ack,ack,c)


# These seven discovered tests retain the actual121 harmless load_config decisions.
import copy
from dataclasses import FrozenInstanceError
_PROFILE_RECORDS = []
_PROFILE_ROOT = 'C:\\Users\\source_fixture'
_PROFILE_TASK = _PROFILE_ROOT + '\\AppData\\Local\\VpnControl\\persistent-recovery-owner-11111111-2222-4333-8444-555555555555'

def _configured_profile():
    return {'environment': 'owned-source-fixture', 'qgaSocketPath': '/owned-source-fixture/guest.qga', 'qmpSocketPath': '/owned-source-fixture/guest.qmp', 'qemuPid': 123, 'qemuStartTicks': 456, 'qemuParentPid': 122, 'qemuUid': 1000, 'qemuArgvSha256': 'a' * 64, 'hostBootId': '11111111-2222-4333-8444-555555555555', 'accountName': 'source_fixture', 'expectedSid': 'S-1-5-21-100-200-300-1001', 'sessionId': 1, 'profileRoot': _PROFILE_ROOT, 'installedRoot': _PROFILE_ROOT + '\\AppData\\Local\\vpn-control', 'taskRootParent': _PROFILE_TASK, 'nativeContextPath': '/owned-source-fixture/never-opened-native-context.json', 'nativeContextSha256': 'c' * 64, 'tokenPolicy': {'kind': 'ordinaryFilteredAdmin', 'elevation': 0, 'elevationType': 3, 'adminMember': True, 'adminEnabled': False}}

def _configured_inventory(profiles=None):
    host = {'host': '127.0.0.1', 'port': 2222, 'user': 'source_fixture', 'identityFile': '/owned-source-fixture/never-opened-identity', 'knownHostsFile': '/owned-source-fixture/never-opened-known-hosts'}
    if profiles is not None:
        host['windowsInputProfiles'] = profiles
    return {'schemaVersion': 1, 'hosts': {'owned': host}}

class WindowsInputProfileConfigTest(unittest.TestCase):

    def parse(self, case, raw, *, accepts):
        contents = raw if isinstance(raw, str) else json.dumps(raw, sort_keys=True)
        with tempfile.TemporaryDirectory(prefix='fixture-', dir=None) as temp:
            fixture = Path(temp) / ssh_transport.CONFIG_FILENAME
            with fixture.open('x', encoding='utf-8') as handle:
                handle.write(contents)
            fixture.chmod(384)
            try:
                result = ssh_transport.load_config(temp)
            except ssh_transport.SshConfigError as exc:
                result = None
                observed = 'reject'
                reason = str(exc)
            else:
                observed = 'accept'
                reason = None
            _PROFILE_RECORDS.append({'case': case, 'expected': 'accept' if accepts else 'reject', 'observed': observed, 'reason': reason, 'fixtureJson': contents, 'fixtureRemovedAfterContext': True})
        self.assertFalse(Path(temp).exists(), 'owned fixture directory must close')
        self.assertEqual('accept' if accepts else 'reject', observed, case)
        return result

    def test_configured_profile_exact_typed_and_asdict(self):
        conf = self.parse('configured-profile', _configured_inventory({'ordinary': _configured_profile()}), accepts=True)
        selected = conf.hosts['owned'].windows_input_profiles['ordinary']
        self.assertIsInstance(selected, ssh_transport.WindowsInputProfile)
        self.assertIsInstance(selected.token_policy, ssh_transport.WindowsInputTokenPolicy)
        expected = _configured_profile()
        self.assertEqual(selected.environment, expected['environment'])
        for field, value in (('qga_socket_path', expected['qgaSocketPath']), ('qmp_socket_path', expected['qmpSocketPath'])):
            self.assertIs(type(getattr(selected, field)), PurePosixPath)
            self.assertEqual(str(getattr(selected, field)), value)
        for field, value in (('profile_root', _PROFILE_ROOT), ('installed_root', expected['installedRoot']), ('task_root_parent', _PROFILE_TASK)):
            self.assertIs(type(getattr(selected, field)), PureWindowsPath)
            self.assertEqual(str(getattr(selected, field)), value)
        self.assertEqual((selected.qemu_pid, selected.qemu_start_ticks, selected.qemu_parent_pid, selected.qemu_uid), (123, 456, 122, 1000))
        self.assertEqual((selected.qemu_argv_sha256, selected.host_boot_id, selected.account_name, selected.expected_sid, selected.session_id), ('a' * 64, expected['hostBootId'], 'source_fixture', expected['expectedSid'], 1))
        self.assertEqual(asdict(selected.token_policy), {'kind': 'ordinaryFilteredAdmin', 'elevation': 0, 'elevation_type': 3, 'admin_member': True, 'admin_enabled': False})
        self.assertIs(type(selected.native_context_path), type(Path('/')))
        self.assertEqual(str(selected.native_context_path), str(Path(expected['nativeContextPath'])))
        self.assertEqual(selected.native_context_sha256, 'c' * 64)
        snapshot = asdict(conf)
        with self.assertRaises(FrozenInstanceError):
            selected.session_id = 2
        with self.assertRaises(FrozenInstanceError):
            selected.token_policy.elevation = 1
        conf.hosts['owned'].windows_input_profiles.clear()
        self.assertNotEqual(snapshot, asdict(conf), 'existing asdict remeasurement detects map mutation')

    def test_original_task_parent_uid_zero_and_two_named_profiles(self):
        first = _configured_profile()
        first['qemuUid'] = 0
        second = copy.deepcopy(first)
        second['environment'] = 'second-owned-fixture'
        conf = self.parse('two-explicit-named-profiles-uid-zero', _configured_inventory({'ordinary': first, 'second': second}), accepts=True)
        self.assertEqual(set(conf.hosts['owned'].windows_input_profiles), {'ordinary', 'second'})
        self.assertEqual(str(conf.hosts['owned'].windows_input_profiles['ordinary'].task_root_parent), _PROFILE_TASK)
        self.assertEqual(conf.hosts['owned'].windows_input_profiles['ordinary'].qemu_uid, 0)

    def test_absent_profiles_and_cp117_behavior(self):
        raw = _configured_inventory()
        raw['hosts']['owned']['windowsCredentialProbe'] = {'environment': 'legacy-probe', 'qgaSocketPath': '/owned-source-fixture/legacy.qga', 'qemuPid': 123, 'qemuStartTicks': 456, 'accountName': 'source_fixture', 'expectedSid': 'S-1-5-21-100-200-300-1001', 'credentialPath': '/owned-source-fixture/never-opened-secret', 'recoveryAdmission': {'taskName': 'owned-task', 'taskPath': '\\VpnControl\\', 'expectedLastResult': 0, 'expectedTaskExecute': 'powershell.exe', 'expectedTaskPrincipal': 'source_fixture', 'expectedTaskArgumentsSha256': 'b' * 64, 'expectedTaskState': 'Ready'}}
        conf = self.parse('legacy-cp117-no-new-records', raw, accepts=True)
        host = conf.hosts['owned']
        self.assertEqual(getattr(host, 'windows_input_profiles', {}), {})
        self.assertEqual(host.windows_credential_probe.account_name, 'source_fixture')
        self.assertEqual(host.windows_credential_probe.recovery_admission.expected_task_arguments_sha256, 'b' * 64)
        self.assertEqual(host.windows_credential_probe.recovery_admission.expected_task_state, 'Ready')

    def reject(self, case, candidate):
        self.parse(case, _configured_inventory({'ordinary': candidate}), accepts=False)

    def test_rejects_missing_unknown_and_duplicate_fields(self):
        for field in _configured_profile():
            with self.subTest(missing=field):
                candidate = _configured_profile()
                del candidate[field]
                self.reject('missing-' + field, candidate)
        candidate = _configured_profile()
        candidate['unexpected'] = 'unused'
        self.reject('unknown-profile-field', candidate)
        for field in ('kind', 'elevation', 'elevationType', 'adminMember', 'adminEnabled'):
            candidate = _configured_profile()
            del candidate['tokenPolicy'][field]
            self.reject('missing-policy-' + field, candidate)
        candidate = _configured_profile()
        candidate['tokenPolicy']['unexpected'] = 0
        self.reject('unknown-policy-field', candidate)
        raw = json.dumps(_configured_inventory({'ordinary': _configured_profile()}))
        self.parse('duplicate-profile-name', raw.replace('"ordinary": {', '"ordinary": {}, "ordinary": {', 1), accepts=False)
        self.parse('duplicate-profile-field', raw.replace('"qemuPid": 123', '"qemuPid": 999, "qemuPid": 123', 1), accepts=False)
        self.parse('duplicate-policy-field', raw.replace('"elevation": 0', '"elevation": 1, "elevation": 0', 1), accepts=False)

    def test_rejects_generation_and_identity_types(self):
        mutations = []
        for field in ('qemuPid', 'qemuStartTicks', 'qemuParentPid'):
            mutations += [(field, True), (field, 0), (field, '123')]
        mutations += [('qemuUid', True), ('qemuUid', -1), ('qemuUid', '0'), ('qemuArgvSha256', 'A' * 64), ('qemuArgvSha256', 'a' * 63), ('qemuArgvSha256', 123), ('hostBootId', '11111111222243338444555555555555'), ('hostBootId', 'not-a-uuid'), ('hostBootId', 123), ('nativeContextSha256', 'C' * 64), ('nativeContextSha256', 'c' * 63), ('nativeContextSha256', True), ('environment', 'bad environment'), ('environment', True)]
        for index, (field, value) in enumerate(mutations):
            with self.subTest(field=field, value=value):
                candidate = _configured_profile()
                candidate[field] = value
                self.reject(f'identity-{index}-{field}', candidate)
        for invalid in ([], None, {'bad name': _configured_profile()}, {'ordinary': []}):
            self.parse('profile-map-' + str(type(invalid).__name__) + '-' + str(len(_PROFILE_RECORDS)), _configured_inventory(invalid) if invalid is not None else _configured_inventory(None) | {'hosts': {'owned': _configured_inventory()['hosts']['owned'] | {'windowsInputProfiles': None}}}, accepts=False)

    def test_rejects_account_session_and_token_policy(self):
        mutations = [('accountName', 'DOMAIN\\source_fixture'), ('accountName', 'source fixture'), ('accountName', True), ('expectedSid', 'S-1-5-18'), ('expectedSid', 123), ('sessionId', 0), ('sessionId', True), ('sessionId', '1')]
        for index, (field, value) in enumerate(mutations):
            candidate = _configured_profile()
            candidate[field] = value
            self.reject(f'account-{index}-{field}', candidate)
        mutations = [('kind', 'administrator'), ('kind', True), ('elevation', True), ('elevation', 1), ('elevationType', True), ('elevationType', 2), ('adminMember', 1), ('adminMember', False), ('adminEnabled', 0), ('adminEnabled', True)]
        for index, (field, value) in enumerate(mutations):
            candidate = _configured_profile()
            candidate['tokenPolicy'][field] = value
            self.reject(f'policy-{index}-{field}', candidate)

    def test_rejects_socket_and_windows_path_escape(self):
        for index, value in enumerate(('relative.qga', '/', '/owned/../guest.qga', '/owned/./guest.qga', '/owned//guest.qga', '//owned/guest.qga', '/owned/guest.qga ', '/owned\\guest.qga', '/owned/guest\n.qga', 123)):
            for field in ('qgaSocketPath', 'qmpSocketPath'):
                candidate = _configured_profile()
                candidate[field] = value
                self.reject(f'socket-{index}-{field}', candidate)
        candidate = _configured_profile()
        candidate['qmpSocketPath'] = candidate['qgaSocketPath']
        self.reject('same-qga-qmp', candidate)
        for index, value in enumerate(('relative.json', '/', '/owned/../context.json', '/owned/./context.json', '/owned//context.json', '//owned/context.json', '/owned/context.json ', '/owned\\context.json', True)):
            candidate = _configured_profile()
            candidate['nativeContextPath'] = value
            self.reject(f'context-path-{index}', candidate)
        mutations = [('profileRoot', 'C:\\Users\\another'), ('profileRoot', 'C:\\Users\\source_fixture\\..\\source_fixture'), ('installedRoot', _PROFILE_ROOT + '\\AppData\\Local\\another'), ('taskRootParent', _PROFILE_ROOT + '\\AppData\\Local\\VpnControl'), ('taskRootParent', _PROFILE_ROOT + '\\AppData\\Local\\VpnControl-other\\leaf'), ('taskRootParent', _PROFILE_ROOT + '\\AppData\\Local\\VpnControl\\..\\foreign'), ('taskRootParent', _PROFILE_ROOT + '\\AppData\\Local\\VpnControl\\leaf:ads'), ('taskRootParent', _PROFILE_ROOT + '\\AppData\\Local\\VpnControl\\leaf.'), ('taskRootParent', _PROFILE_ROOT + '\\AppData\\Local\\VpnControl\\leaf '), ('taskRootParent', _PROFILE_ROOT + '\\AppData\\Local\\VpnControl\\NUL'), ('taskRootParent', _PROFILE_ROOT + '\\AppData\\Local\\VpnControl\\leaf\\\\child'), ('taskRootParent', 'C:/Users/source_fixture/AppData/Local/VpnControl/leaf'), ('taskRootParent', '\\\\?\\C:\\Users\\source_fixture\\AppData\\Local\\VpnControl\\leaf'), ('taskRootParent', '\\relative\\leaf'), ('taskRootParent', 123)]
        for index, (field, value) in enumerate(mutations):
            candidate = _configured_profile()
            candidate[field] = value
            self.reject(f'path-{index}-{field}', candidate)
