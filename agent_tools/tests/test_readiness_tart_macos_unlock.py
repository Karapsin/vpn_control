"""Controlled real pipes/RFB; no VM, profile inventory or native credentials."""
from contextlib import contextmanager
import contextlib
from copy import deepcopy
import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace, ModuleType
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import private_inventory_lock as private
from agent_tools import readiness_tart_macos as mac
from agent_tools import readiness_tart_macos_registry as registry
from agent_tools import readiness_tart_macos_unlock as unlock
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint


def binding():
    return mac.MacBinding('local-tart-macos-'+'a'*24, '11111111-1111-4111-8111-111111111111',
        'vpn-tool-recovery-tart-macos-selected', '/public/tart', '/public/vpn-tool-recovery-tart-macos-selected',
        'fixtureuser', 507, '/Users/fixtureuser', '/usr/local/libexec/vpn-tool-recovery-selected/python/bin/python3.12',
        4096, 'selected-storage')


def identity():
    selected = binding()
    return {'target': selected.target, 'machine': selected.machine,
        'boot': '22222222-2222-4222-8222-222222222222', 'rawBoot': '22222222-2222-4222-8222-222222222222',
        'uid': 507, 'principal': 'fixtureuser', 'home': '/Users/fixtureuser',
        'agent': {'pid': 17, 'birth': 'darwin:123:4', 'uid': 507},
        'console': {'uid': 507, 'name': 'fixtureuser', 'session': '42', 'onConsole': True, 'loginDone': True, 'locked': True},
        'display': 'ready'}


class IdentityTests(unittest.TestCase):
    def test_selected_account_parameterization_whole_original_caller_red_current_green(self):
        # Original qualified specimen is DATA: execute definitions only, never
        # its unlock_once entrypoint or a private run/profile/credential path.
        path = Path(__file__).parent/'fixtures/tart_macos_protected_unlock_caller.source'
        raw = path.read_bytes()
        self.assertEqual('032d5c6966d1ed15f486a828b990cf7ef0bbacff419b46ec012d222f249b6267', hashlib.sha256(raw).hexdigest())
        scope = {'__file__': str(path)}
        # The old entrypoint is never invoked. Keep its unrelated POSIX-only
        # resource import inert so this pure identity regression runs on Windows.
        def imported(name,*args,**kwargs):
            return SimpleNamespace() if name=='resource' else builtins.__import__(name,*args,**kwargs)
        scope['__builtins__']={**vars(builtins),'__import__':imported}
        exec(compile(raw, str(path), 'exec'), scope)
        old = object.__new__(scope['SessionObserver']); old.expected = identity()
        with self.assertRaisesRegex(RuntimeError, 'ordinary_console_or_display_changed'):
            old.validate(identity())
        self.assertEqual(identity(), unlock._identity(identity(), binding(), identity()))
        # This is a parameterization RED, not a new native failure claim.

    def test_machine_rawboot_agent_session_account_strict_types_and_signedout(self):
        for key, value in [('machine',str(uuid4())),('rawBoot',str(uuid4())),('uid',True),('principal','wrong')]:
            packet = identity(); packet[key] = value
            with self.subTest(key=key), self.assertRaises(unlock.UnlockBlocked):
                unlock._identity(packet, binding(), identity())
        for key,value in [('session','43'),('locked',1),('loginDone',False),('uid',True)]:
            packet = identity(); packet['console'][key] = value
            with self.subTest(console=key), self.assertRaises(unlock.UnlockBlocked):
                unlock._identity(packet,binding(),identity())
        for key,value in [('pid',18),('birth','darwin:125:4')]:
            packet=identity();packet['agent'][key]=value
            with self.assertRaisesRegex(unlock.UnlockBlocked,'identity_changed'):
                unlock._identity(packet,binding(),identity())
        packet=identity();packet['console'].update(uid=None,name='loginwindow')
        with self.assertRaisesRegex(unlock.UnlockBlocked,'signed_out_unsupported'):
            unlock._identity(packet,binding())

    def test_profile_rejects_overlap_outside_full_mask_and_boolean_geometry(self):
        profile={'dimensions':(1024,768),'accountBox':(425,410,605,451),
                 'fieldBox':(432,458,592,489),'caretBox':(14,7,15,23)}
        self.assertEqual(profile,unlock._profile(profile))
        for key,value in [('dimensions',(True,768)),('accountBox',(432,458,592,489)),
                          ('fieldBox',(-1,0,20,20)),('caretBox',(0,0,160,31)),('caretBox',(0,0,2,2))]:
            with self.subTest(key=key),self.assertRaises(unlock.UnlockBlocked):
                unlock._profile({**profile,key:value})


@unittest.skipUnless(os.name=='posix','controlled private FD/pipes require POSIX')
class PipeTests(unittest.TestCase):
    def read(self,raw,expired=False):
        reader,writer=os.pipe()
        try:
            os.write(writer,raw);os.close(writer);writer=None
            with os.fdopen(reader,'rb',buffering=0) as channel:
                reader=None
                observer=object.__new__(unlock.SessionObserver)
                observer.process=SimpleNamespace(stdout=channel);observer.buffer=bytearray()
                observer.deadline=time.monotonic()+1 if not expired else time.monotonic()-1
                observer.binding=binding();observer.expected=identity()
                reply=observer.read();return observer.validate(reply['observation'])
        finally:
            if reader is not None:os.close(reader)
            if writer is not None:os.close(writer)

    def test_actual_pipe_malformed_echo_duplicate_nan_overflow_timeout(self):
        for raw in [b'{"state":"observed","state":"PRIVATE","observation":{}}\n',
                    b'{"state":"observed","observation":{"uid":1,"uid":"PRIVATE"}}\n',
                    b'{"state":"observed","observation":NaN}\n', b'PRIVATE'+b'x'*17000,
                    b'{"state":"observed","observation":{},"PRIVATE":0}\n']:
            with self.subTest(length=len(raw)),self.assertRaises(unlock.UnlockBlocked) as caught:
                self.read(raw)
            self.assertNotIn('PRIVATE',str(caught.exception))
        with self.assertRaisesRegex(unlock.UnlockBlocked,'deadline'):
            self.read(b'PRIVATE',expired=True)
        self.assertEqual(identity(),self.read(json.dumps({'protocol':unlock.stream.PROTOCOL,
            'state':'observer_ready','observation':identity()}).encode()+b'\n'))

    def test_whole846_delayed_duplicate_after_queue_probe_red_nonce_parser_refuses(self):
        path=Path(__file__).parent/'fixtures/tart_macos_unlock_nonce.before.source';raw=path.read_bytes()
        self.assertEqual('846939bd8087ec35b6408e2cb812f3917cbed2b4f55dcacc66b80279153200ad',hashlib.sha256(raw).hexdigest())
        before=ModuleType('agent_tools._delayed_unlock_before');before.__file__=str(path);before.__package__='agent_tools'
        exec(compile(raw,str(path),'exec'),before.__dict__)
        for subject in (before,unlock):
            reader,writer=os.pipe();requests=[];protected=[]
            class Delayed:
                def write(self,request):
                    # Actual pipe injection happens inside write, AFTER the
                    # complete check's zero-select observed no queued reply.
                    requests.append(request)
                    value={'state':'observed','observation':identity()}
                    if subject is unlock:
                        value.update(protocol=unlock.stream.PROTOCOL,counter=1,nonce='0'*32)
                    os.write(writer,json.dumps(value).encode()+b'\n');return len(request)
                def flush(self):pass
            try:
                with os.fdopen(reader,'rb',buffering=0) as reply:
                    reader=None;o=object.__new__(subject.SessionObserver)
                    o.process=SimpleNamespace(stdout=reply,stdin=Delayed(),poll=lambda:None)
                    o.buffer=bytearray();o.deadline=time.monotonic()+2;o.binding=binding();o.expected=identity()
                    o.counter=0;o.used_nonces=set()
                    if subject is before:
                        protected.append(o.check())
                        self.assertEqual([identity()],protected)
                    else:
                        with mock.patch.object(subject.secrets,'token_hex',return_value='1'*32):
                            with self.assertRaisesRegex(subject.UnlockBlocked,'uncorrelated'):
                                protected.append(o.check())
                        self.assertEqual([],protected)
                    self.assertEqual(1,len(requests))
            finally:
                if reader is not None:os.close(reader)
                os.close(writer)

    def test_wrong_missing_old_and_duplicate_request_correlations_never_authorize_input(self):
        for variant in ('nonce','counter','boolean','missing','old','ready','extra','protocol'):
            reader,writer=os.pipe();protected=[]
            class Reply:
                def write(self,request):
                    _,counter,nonce=request.decode().strip().split()
                    value={'protocol':unlock.stream.PROTOCOL,'state':'observed','counter':int(counter),
                           'nonce':nonce,'observation':identity()}
                    if variant=='nonce':value['nonce']='0'*32
                    if variant=='counter':value['counter']=2
                    if variant=='boolean':value['counter']=True
                    if variant=='missing':del value['nonce']
                    if variant=='old':value={'state':'observed','observation':identity()}
                    if variant=='ready':value={'protocol':unlock.stream.PROTOCOL,'state':'observer_ready','observation':identity()}
                    if variant=='extra':value['PRIVATE']='forbidden'
                    if variant=='protocol':value['protocol']='unqualified'
                    os.write(writer,json.dumps(value).encode()+b'\n');return len(request)
                def flush(self):pass
            try:
                with os.fdopen(reader,'rb',buffering=0) as channel:
                    reader=None;o=object.__new__(unlock.SessionObserver)
                    o.process=SimpleNamespace(stdout=channel,stdin=Reply(),poll=lambda:None)
                    o.buffer=bytearray();o.deadline=time.monotonic()+2;o.binding=binding();o.expected=identity()
                    o.counter=0;o.used_nonces=set()
                    with mock.patch.object(unlock.secrets,'token_hex',return_value='1'*32):
                        with self.subTest(variant=variant),self.assertRaises(unlock.UnlockBlocked) as caught:
                            protected.append(o.check())
                    self.assertEqual([],protected);self.assertNotIn('PRIVATE',str(caught.exception))
            finally:
                if reader is not None:os.close(reader)
                os.close(writer)

    def test_whole_before_unsolicited_reply_real_pipe_red_current_rejects(self):
        path=Path(__file__).parent/'fixtures/tart_macos_unlock_unsolicited.before.source'
        raw=path.read_bytes()
        self.assertEqual('bd0174f4d383a03bb3872d3685e15b7806a346973a27203b50a57b3d88fd9b57',hashlib.sha256(raw).hexdigest())
        before=ModuleType('agent_tools._unsolicited_unlock_before');before.__file__=str(path);before.__package__='agent_tools'
        exec(compile(raw,str(path),'exec'),before.__dict__)
        line=json.dumps({'state':'observed','observation':identity()}).encode()+b'\n'
        for subject in (before,unlock):
            a,b=os.pipe()
            try:
                os.write(b,line+line)
                with os.fdopen(a,'rb',buffering=0) as channel:
                    a=None;o=object.__new__(subject.SessionObserver);o.process=SimpleNamespace(stdout=channel,poll=lambda:None)
                    o.buffer=bytearray();o.deadline=time.monotonic()+2;o.binding=binding();o.expected=identity()
                    if subject is before:
                        self.assertEqual(identity(),o.validate(o.read()['observation']))
                        self.assertEqual(identity(),o.validate(o.read()['observation']))
                    else:
                        with self.assertRaisesRegex(subject.UnlockBlocked,'unsolicited'):o.read()
                        # Independently queued response with an empty local
                        # buffer must be refused before sending a new request.
                        o.buffer.clear()
                        os.write(b,line)
                        with self.assertRaisesRegex(subject.UnlockBlocked,'unsolicited'):o.check()
            finally:
                if a is not None:os.close(a)
                os.close(b)

    def test_whole_native_empty_field_before_caret_blink_red_current_exact_mask_green(self):
        from PIL import Image,ImageDraw
        path=Path(__file__).parent/'fixtures/tart_macos_unlock_empty_caret.before.source'
        raw=path.read_bytes()
        self.assertEqual('1de0cfabdeac014369d5e26e60327302e3dda23ffed322f26fe955c228a49ab9',
                         hashlib.sha256(raw).hexdigest())
        scope={'__file__':str(path)}
        exec(compile(raw,str(path),'exec'),scope)
        # Execute the complete original pre-input caller using only generated
        # public pixels and a finite local FD surface. No native frame/profile,
        # private helper, ordinary credential or original operation is opened.
        baseline=Image.new('RGB',(1024,768),(20,30,40));blink=baseline.copy()
        ImageDraw.Draw(blink).rectangle((446,465,446,480),fill=(255,255,255))
        output=io.BytesIO();blink.save(output,format='PNG')
        class View:
            def __init__(self,**kwargs):pass
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def capture_png(self):return output.getvalue()
            def type_secret_from_fd(self,*args,**kwargs):raise AssertionError('no secret admission')
        opened=[]
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            def finite_open(path,flags,mode=0o600):
                path=Path(path);opened.append(path.name)
                if path.name not in {'phase.lock','vnc-auth.bin'}:raise AssertionError('unexpected original file access')
                return os.open(root/path.name,os.O_RDWR|os.O_CREAT,0o600)
            scope.update(ROOT=root,DIRECTORY=root,BASELINE=root/'public-baseline.png',
                         ProtectedVncSession=View,guard=lambda:{'record':lambda *args:None},
                         Image=SimpleNamespace(open=lambda _:baseline.copy() if isinstance(_,Path) else Image.open(_)),
                         os=SimpleNamespace(open=finite_open,close=os.close,O_CREAT=os.O_CREAT,O_RDWR=os.O_RDWR,
                                            O_NOFOLLOW=os.O_NOFOLLOW,O_RDONLY=os.O_RDONLY,O_NONBLOCK=os.O_NONBLOCK))
            with self.assertRaisesRegex(RuntimeError,'ordinary_login_field_not_known_empty'):
                scope['login_once']()
        self.assertEqual(['phase.lock','vnc-auth.bin'],opened)
        profile={'dimensions':(1024,768),'accountBox':(425,410,605,451),
                 'fieldBox':(432,458,592,489),'caretBox':(14,7,15,23)}
        self.assertTrue(unlock._empty(blink,baseline,profile))
        # Only the proven one-pixel caret blinks; a neighboring typed pixel
        # remains a refusal. The full current socket caller tests admission.
        changed=blink.copy();changed.putpixel((447,465),(0,0,0))
        self.assertFalse(unlock._empty(changed,baseline,profile))


@unittest.skipUnless(os.name=='posix','controlled RFB/private metadata require POSIX')
class CallerTests(unittest.TestCase):
    def setUp(self):
        from PIL import Image
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.endpoint=RfbEndpoint(size=(3,1));self.operation=str(uuid4())
        self.profile={'dimensions':(3,1),'accountBox':(0,0,1,1),'fieldBox':(1,0,3,1),'caretBox':(0,0,1,1)}
        image=Image.new('RGB',(3,1));image.putdata([(255,0,0),(0,255,0),(0,0,255)])
        out=io.BytesIO();image.save(out,format='PNG')
        self.baseline=self.root/'empty.png';self.baseline.write_bytes(out.getvalue());self.baseline.chmod(0o600)
        self.paths={};self.opens={'vnc':0,'ordinary':0}
        self.credentials={}
        for name,raw in [('vnc',b'public-fixture'),('ordinary',b'Z!')]:
            path=self.root/(name+'.secret');path.write_bytes(raw);path.chmod(0o600);self.paths[name]=path
            self.credentials[name]=registry.HeldArtifact(path)
        self.backend=object.__new__(mac.MacTartBackend);self.backend.binding=binding()
        custody=object.__new__(registry.MacCustody);custody.binding=self.backend.binding
        custody.lifecycle_root=self.root;custody._credentials=self.credentials;custody.endpoint={'port':self.endpoint.port}
        self.backend.custody=custody
        self.backend.operation_scope=lambda **kwargs:contextlib.nullcontext()
        self.guards=0;self.fail=None;self.change_identity=None;self.snapshot_count=0
        self.subject=unlock
        def guard():
            self.guards+=1
            for holder in self.credentials.values():holder.guard()
            if self.fail:self.fail()
        @contextmanager
        def material(backend,operation,*,deadline):
            with private.Directory(self.root) as directory,private.Snapshot(directory,self.baseline.name) as baseline:
                with self.subject._held_material(backend,operation,baseline_snapshot=baseline,profile=self.profile,
                                                expected=identity(),guard=guard) as held:
                    yield held
        custody.unlock_material=material
        def probe(selected,deadline):
            self.snapshot_count+=1;value=identity()
            if self.snapshot_count>1:
                self.endpoint.wait_events(10)
                value['console']['locked']=False
            if self.change_identity:self.change_identity(value)
            return {'facts':{'machine':value['machine'],'boot':value['boot'],'uid':value['uid'],
                'account':value['principal'],'home':value['home'],'console':value['console'],'display':value['display']},
                'agent':{'rawBoot':value['rawBoot'],'actor':{k:value['agent'][k] for k in ('pid','birth')},
                         'uid':value['uid'],'principal':value['principal'],'home':value['home'],'python':self.backend.binding.guest_python}}
        custody.guest_probe=probe
        self.popen=subprocess.Popen
        self.children=[]
        def spawn(*args,**kwargs):
            # Real process, exact framed stdin + newline checks; launch seam only.
            packet=identity()
            code=('import json,sys\nexpected='+repr(packet)+'\n'
                  'assert sys.stdin.buffer.read(7)==b"PUBLIC!"\n'
                  'print(json.dumps({"protocol":"macos-unlock-stream-v1","state":"observer_ready","observation":expected}),flush=True)\n'
                  'counter=0\n'
                  'for line in sys.stdin.buffer:\n'
                  ' counter+=1\n'
                  ' action,n,nonce=line.decode().strip().split()\n'
                  ' assert action=="check" and int(n)==counter\n'
                  ' print(json.dumps({"protocol":"macos-unlock-stream-v1","state":"observed",'
                  '"counter":counter,"nonce":nonce,"observation":expected}),flush=True)\n')
            child=self.popen([sys.executable,'-I','-B','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,bufsize=0)
            self.children.append(child);return child
        self.patches=[mock.patch.object(unlock.stream,'session_stream_command',return_value=(('fixed',),b'PUBLIC!')),
                      mock.patch.object(unlock.subprocess,'Popen',side_effect=spawn)]
        for patch in self.patches:patch.start()
        for name,holder in self.credentials.items():
            actual=holder.credential_fd
            def opened(name=name,actual=actual):
                self.opens[name]+=1;return actual()
            holder.credential_fd=opened

    def tearDown(self):
        for patch in reversed(self.patches):patch.stop()
        for child in self.children:
            if child.poll() is None:child.kill();child.wait()
        for holder in self.credentials.values():holder.close()
        self.endpoint.close();self.temp.cleanup()

    def run_unlock(self):
        return self.subject.unlock_once(self.backend,self.operation,deadline=time.monotonic()+15)

    def test_complete_actual_pipe_socket_caller_once_then_status_without_credential_open(self):
        self.endpoint.receipt_probe=lambda:(self.root/('macos-unlock-'+self.operation+'.json')).exists()
        result=self.run_unlock();self.assertEqual('observed_ready',result['state'])
        self.assertEqual([('key',1,0xffe1),('key',1,ord('Z')),('key',0,ord('Z')),('key',0,0xffe1),
                          ('key',1,0xffe1),('key',1,ord('!')),('key',0,ord('!')),('key',0,0xffe1),
                          ('key',1,0xff0d),('key',0,0xff0d)],self.endpoint.wait_events(10))
        self.assertFalse(self.endpoint.missing_receipt);self.assertEqual(1,self.opens['ordinary'])
        before=dict(self.opens)
        self.assertEqual('observed_ready',unlock.status(self.backend,self.operation,deadline=time.monotonic()+3)['state'])
        self.assertEqual(before,self.opens)
        self.change_identity=lambda value:value.update(display='sleeping')
        sleeping=unlock.status(self.backend,self.operation,deadline=time.monotonic()+3)
        self.assertEqual(('observed_ready','sleeping'),(sleeping['state'],sleeping['display']))
        self.assertEqual(before,self.opens)
        self.change_identity=None
        with self.assertRaisesRegex(unlock.UnlockBlocked,'original_pending'):self.run_unlock()
        self.assertEqual(before,self.opens)
        for path in self.root.glob('*.json'):
            self.assertNotIn(b'Z!',path.read_bytes())
            self.assertEqual(0o600,path.stat().st_mode&0o777)

    def test_unrecognized_field_blocks_before_ordinary_credential_or_uncertainty(self):
        from PIL import Image
        image=Image.new('RGB',(3,1),(255,0,0));out=io.BytesIO();image.save(out,format='PNG')
        self.baseline.write_bytes(out.getvalue())
        with self.assertRaisesRegex(unlock.UnlockBlocked,'field_not_known_empty'):self.run_unlock()
        self.assertEqual(0,self.opens['ordinary']);self.assertEqual([],self.endpoint.events)
        self.assertFalse(any(self.root.glob('macos-unlock-*.json')))

    def test_wrong_account_signed_out_and_forged_material_never_authenticate(self):
        self.change_identity=lambda value:value['console'].update(name='loginwindow',uid=None)
        with self.assertRaisesRegex(unlock.UnlockBlocked,'signed_out_unsupported'):self.run_unlock()
        self.assertEqual({'vnc':0,'ordinary':0},self.opens)
        self.change_identity=None
        self.backend.custody.unlock_material=lambda *a,**kw:contextlib.nullcontext(SimpleNamespace(live=True))
        with self.assertRaisesRegex(unlock.UnlockBlocked,'material_unqualified'):self.run_unlock()
        self.assertEqual([],self.endpoint.responses)

    def test_credential_generation_change_after_authentication_blocks_before_secret(self):
        def change():
            if self.endpoint.responses and self.opens['vnc']:
                self.paths['ordinary'].write_bytes(b'PRIVATE changed credential')
        self.fail=change
        with self.assertRaises((unlock.UnlockBlocked,unlock.rfb.VncBlocked)) as caught:self.run_unlock()
        self.assertNotIn('PRIVATE',str(caught.exception));self.assertEqual(0,self.opens['ordinary'])
        self.assertEqual([],self.endpoint.events)

    def test_guard_loss_after_first_event_preserves_unknown_without_release_or_replay(self):
        def fail():
            if self.endpoint.events:raise RuntimeError('PRIVATE cancellation')
        self.fail=fail
        with self.assertRaises((unlock.UnlockBlocked,unlock.rfb.VncBlocked)) as caught:self.run_unlock()
        self.assertNotIn('PRIVATE',str(caught.exception))
        self.assertTrue((self.root/('macos-unlock-'+self.operation+'.json')).exists())
        # No compensating key-up can target a possibly replaced session.
        self.assertLess(len(self.endpoint.events),10)
        self.fail=None
        with self.assertRaisesRegex(unlock.UnlockBlocked,'original_pending'):self.run_unlock()

    def test_material_from_other_backend_or_expired_context_rejected(self):
        with self.backend.custody.unlock_material(self.backend,self.operation,deadline=time.monotonic()+2) as material:
            other=object.__new__(mac.MacTartBackend);other.binding=self.backend.binding;other.custody=self.backend.custody
            factory=lambda *a,**kw:contextlib.nullcontext(material)
            with mock.patch.object(self.backend.custody,'unlock_material',factory):
                material.backend=other
                with self.assertRaisesRegex(unlock.UnlockBlocked,'material_unqualified'):self.run_unlock()
                material.backend=self.backend
        with self.assertRaisesRegex(unlock.UnlockBlocked,'material_changed'):material.guard()

    def test_original_admitted_snapshot_mismatch_stops_before_authentication(self):
        self.change_identity=lambda value:value['console'].update(session='43')
        with self.assertRaisesRegex(unlock.UnlockBlocked,'admitted_snapshot_changed'):self.run_unlock()
        self.assertEqual({'vnc':0,'ordinary':0},self.opens)
        self.assertEqual([],self.endpoint.responses)

    def test_complete_loaded_source_change_during_input_stops_without_compensating_events(self):
        raw=Path(unlock.__file__).read_bytes();path=self.root/'selected-unlock.py'
        path.write_bytes(raw);path.chmod(0o600)
        subject=ModuleType('agent_tools._selected_unlock_test');subject.__file__=str(path)
        subject.__package__='agent_tools'
        exec(compile(raw,str(path),'exec'),subject.__dict__)
        self.subject=subject
        def change():
            if self.endpoint.events:
                with path.open('ab') as output:output.write(b'\n# actual owned source mutation\n')
        self.fail=change
        with self.assertRaises((subject.UnlockBlocked,unlock.rfb.VncBlocked)):self.run_unlock()
        self.assertTrue((self.root/('macos-unlock-'+self.operation+'.json')).exists())
        self.assertLess(len(self.endpoint.events),10)
        self.assertEqual(1,self.opens['ordinary'])

    def test_secret_utf8_failure_is_fixed_unknown_and_never_retries(self):
        self.credentials['ordinary'].close()
        self.paths['ordinary'].write_bytes(b'PRIVATE\xffinvalid')
        holder=registry.HeldArtifact(self.paths['ordinary']);self.credentials['ordinary']=holder
        with self.assertRaises(unlock.rfb.VncBlocked) as caught:self.run_unlock()
        self.assertNotIn('PRIVATE',str(caught.exception));self.assertEqual([],self.endpoint.events)
        self.assertTrue((self.root/('macos-unlock-'+self.operation+'.json')).exists())
        with self.assertRaisesRegex(unlock.UnlockBlocked,'original_pending'):self.run_unlock()

    def test_unqualified_unicode_and_overlength_layout_refuse_before_input(self):
        for raw in ('é'.encode(),b'x'*33):
            with self.subTest(length=len(raw)):
                self.operation=str(uuid4())
                self.credentials['ordinary'].close();self.paths['ordinary'].write_bytes(raw)
                self.credentials['ordinary']=registry.HeldArtifact(self.paths['ordinary'])
                with self.assertRaisesRegex(unlock.rfb.VncBlocked,'layout_unsupported'):self.run_unlock()
                self.assertEqual([],self.endpoint.events)
                self.assertTrue((self.root/('macos-unlock-'+self.operation+'.json')).exists())
                # Each independent fixture case gets a fresh owned endpoint;
                # this never retries the refused original operation.
                self.endpoint.close();self.endpoint=RfbEndpoint(size=(3,1))
                self.backend.custody.endpoint={'port':self.endpoint.port}
                self.snapshot_count=0


if __name__=='__main__':unittest.main()
