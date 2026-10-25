"""Complete packets over real owned Unix QMP/QGA sockets, with guest SSH IO seams."""
import contextlib
import hashlib
import io
import json
import os
import shlex
import types
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from agent_tools import readiness_qemu_remote as subject
from agent_tools import readiness_qemu_jobs as protocol,durable_remote_job as owner_protocol

SERVER=r'''
import json,os,pathlib,socket,sys,threading,time
root=pathlib.Path(sys.argv[1]);machine=sys.argv[2]
def handle(client,agent):
 with client:
  stream=client.makefile('rwb',buffering=0)
  if not agent:stream.write(b'{"QMP":{}}\n')
  while True:
   line=stream.readline(65537)
   if not line:return
   request=json.loads(line.lstrip(b'\xff'));name=request['execute']
   state=json.loads((root/'endpoint-state.json').read_text())
   if name=='guest-sync-delimited':stream.write(b'\xff'+(json.dumps({'return':request['arguments']['id']})+'\n').encode());continue
   if name=='query-status':value={'status':state['status'],'running':state['status']=='running'}
   elif name=='query-uuid':value={'UUID':machine}
   elif name=='query-current-machine':value={'wakeup-suspend-support':state.get('wakeSupport',True)}
   elif name in ['stop','cont','system_wakeup']:
    original=state['status']
    if name=='stop':state['status']='paused'
    elif name=='cont' and original!='suspended':state['status']='running'
    elif name=='system_wakeup' and original=='suspended' and state.get('wakeSupport',True) is True:state['status']='running'
    state['changes']+=int(state['status']!=original)
    if name!='stop':state.setdefault('resumeCommands',[]).append(name)
    (root/'endpoint-state.json').write_text(json.dumps(state));value={}
   else:value={}
   stream.write((json.dumps({'return':value,'id':request.get('id')})+'\n').encode())
def serve(name,agent):
 server=socket.socket(socket.AF_UNIX);server.bind(str(root/name));server.listen()
 while True:
  client,_=server.accept();threading.Thread(target=handle,args=(client,agent),daemon=True).start()
threading.Thread(target=serve,args=('qmp.sock',False),daemon=True).start()
threading.Thread(target=serve,args=('qga.sock',True),daemon=True).start()
while True:time.sleep(1)
'''


@unittest.skipUnless(os.name=='posix' and hasattr(__import__('socket'),'SO_PEERCRED'),'Linux SO_PEERCRED boundary')
class QemuRemotePacketTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.root.chmod(0o700)
        self.machine='0f559886-4ff5-4075-ad25-beb805173364';self.boot='25515f23-b966-4c3a-ae63-d38452375578'
        self.binding={'root':str(self.root),'machine':self.machine,'host':'fixture','target':'qemu-linux:'+self.machine}
        self.proc=self.root/'proc';self.proc.mkdir();boot=self.proc/'sys/kernel/random';boot.mkdir(parents=True);(boot/'boot_id').write_text(self.boot)
        (self.root/'endpoint-state.json').write_text(json.dumps({'status':'running','changes':0}))
        self.child=subprocess.Popen([sys.executable,'-c',SERVER,str(self.root),self.machine],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_child)
        for _ in range(100):
            if (self.root/'qmp.sock').exists() and (self.root/'qga.sock').exists():break
            time.sleep(.01)
        self.assertTrue((self.root/'qmp.sock').exists())
        actor=self.proc/str(self.child.pid);actor.mkdir();fields=['S']+['1']*19;fields[19]='777'
        (actor/'stat').write_text(str(self.child.pid)+' (controlled endpoint) '+' '.join(fields))
        (actor/'cmdline').write_bytes(b'PUBLIC_CONTROLLED_ENDPOINT\0')
        controller=self.proc/str(os.getpid());controller.mkdir()
        (controller/'stat').write_text(str(os.getpid())+' (controlled controller) '+' '.join(['S']+['1']*18+['888']))
        self.owner={'operationId':'a7117920-2ee8-4194-b035-a5adb1e1467d','preparationId':self.machine,'hostBootId':self.boot,
                    'pid':self.child.pid,'startTicks':777,'argvSha256':hashlib.sha256(b'PUBLIC_CONTROLLED_ENDPOINT\0').hexdigest(),
                    'qmpSocketInode':(self.root/'qmp.sock').stat().st_ino,'state':'running','guestSubmitted':True}
        for name,value in {'prepared.json':{'operationId':self.machine,'guestAccount':'recovery','interactiveDesktop':False,'sshPort':23861,'qemuArgv':[]},
                           'qemu-owner.json':self.owner,'reservation.json':{'operationId':self.machine,'operator':'tool-recovery-qemu'}}.items():
            self.write(name,json.dumps(value).encode())
        for name,value in {'seed.iso':b'INERT_PRIVATE_SEED','client-key':b'INERT_PRIVATE_TEST_KEY','known-hosts':b'PUBLIC_KNOWN_HOST','disk.qcow2':b'OWNED_DISK','operator.lock':b'LOCK'}.items():self.write(name,value)
        self.write('ubuntu.img',b'PUBLIC_BASE_IMAGE');(self.root/'ubuntu.img').chmod(0o400)
        self.write('image.json',json.dumps({'url':'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img',
            'sha256':hashlib.sha256(b'PUBLIC_BASE_IMAGE').hexdigest(),'bytes':len(b'PUBLIC_BASE_IMAGE')}).encode())
        self.guest_boot='766684cb-a628-4c05-98f7-6fd364d351cc';self.guest_blockers=[];self.ssh=[]
    def stop_child(self):
        self.child.terminate();self.child.wait(timeout=5)
    def write(self,name,raw):
        path=self.root/name;path.write_bytes(raw);path.chmod(0o600)
    def run_packet(self,action='observe',pins=None,rid=None,expected=None,producer=subject,guest_job_source=None,guest_job_mode=None,dispatch_identity=None):
        concrete=type(self.root)
        def path(*parts):
            result=concrete(*parts)
            if str(result)=='/proc' or str(result).startswith('/proc/'):
                return self.proc/str(result).removeprefix('/proc').lstrip('/')
            return result
        def run(argv,**kwargs):
            self.ssh.append(argv)
            self.assertEqual('/usr/bin/ssh',argv[0])
            self.assertIn('StrictHostKeyChecking=yes',argv)
            self.assertIn('BatchMode=yes',argv)
            self.assertNotIn('INERT_PRIVATE_TEST_KEY',' '.join(argv))
            if shlex.split(argv[-1])[:3]==['sudo','-n','systemctl']:return subprocess.CompletedProcess(argv,0,b'',b'')
            if guest_job_mode=='enroll' and kwargs.get('input',b'').startswith(b'PARAMETERS='):
                namespace={'schemaVersion':1,'root':'/var/tmp/vc-recovery-jobs','generation':[1,2],'admissionGeneration':[1,3],'target':self.binding['target'],'machine':self.machine,'actualMachineId':'a'*32,'account':'1000','ownerSourceSha256':hashlib.sha256(owner_protocol.owner_source()).hexdigest()}
                return subprocess.CompletedProcess(argv,0,json.dumps({'namespace':namespace}).encode(),b'')
            value={'bootId':self.guest_boot,'account':'recovery','originalUid':'1000','protectedOrInstallerProcesses':self.guest_blockers,
                   'machineId':'a'*32,'jobVisibilityComplete':True,'systemdJobs':[],'cloudInit':'status: done','foreignSessions':[],'unknownOrRunningJobs':[]}
            return subprocess.CompletedProcess(argv,0,json.dumps(value).encode(),b'')
        stream=io.StringIO()
        with mock.patch('pathlib.Path',side_effect=path),mock.patch.object(subprocess,'run',side_effect=run),contextlib.redirect_stdout(stream):
            options={} if guest_job_source is None else {'guest_job_source':guest_job_source,'guest_job_mode':guest_job_mode}
            if dispatch_identity is not None:options['dispatch_identity']=dispatch_identity
            exec(compile(producer.program(self.binding,pins,action,rid,expected,**options),'complete QEMU readiness packet','exec'),{'__name__':'__main__'})
        return json.loads(stream.getvalue())
    def test_preserved_packet_lock_is_released_by_current_whole_program(self):
        folder=Path(__file__).parent/'fixtures/qemu_packet_boundaries';raw=(folder/'remote.before.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_text());self.assertEqual(metadata['remoteSourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools.qemu_packet_before');before.__package__='agent_tools';before.__file__=str(folder/'remote.before.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        opened=[];real_open=os.open
        def capture(path,*args,**kwargs):
            descriptor=real_open(path,*args,**kwargs)
            if os.fspath(path)==str(self.root/'operator.lock'):opened.append(descriptor)
            return descriptor
        try:
            with mock.patch.object(os,'open',side_effect=capture):
                self.assertEqual('observed',self.run_packet(producer=before)['state'])
            self.assertEqual('competing_operator',self.run_packet()['reason'])
        finally:
            for descriptor in opened:os.close(descriptor)
        self.assertEqual('observed',self.run_packet()['state'])
    def test_preserved_guest_ssh_seam_confused_source_literals_with_commands(self):
        folder=Path(__file__).parent/'fixtures/qemu_packet_boundaries';raw=(folder/'test.before.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_text());self.assertEqual(metadata['testSourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('qemu_ssh_seam_before');before.__file__=str(folder/'test.before.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        controller=types.ModuleType('agent_tools.qemu_old_seam_controller');controller.__package__='agent_tools';controller.__file__=str(folder/'remote.before.source')
        exec(compile((folder/'remote.before.source').read_bytes(),controller.__file__,'exec'),controller.__dict__)
        before.subject=controller
        fixture=before.QemuRemotePacketTests('runTest');fixture.setUp()
        opened=[];real_open=os.open
        def capture(path,*args,**kwargs):
            descriptor=real_open(path,*args,**kwargs)
            if os.fspath(path)==str(fixture.root/'operator.lock'):opened.append(descriptor)
            return descriptor
        try:
            with mock.patch.object(os,'open',side_effect=capture):
                self.assertEqual('blocked',fixture.run_packet()['state'])
        finally:
            for descriptor in opened:os.close(descriptor)
            fixture.doCleanups()
        self.assertEqual('observed',self.run_packet()['state'])
    def test_healthy_packet_uses_bound_real_qmp_qga_and_never_hashes_key(self):
        value=self.run_packet('enroll')
        self.assertEqual('observed',value['state']);self.assertEqual('running',value['facts']['guest'])
        self.assertTrue(value['facts']['guestAgent']);self.assertEqual(self.guest_boot,value['facts']['boot'])
        self.assertEqual({'generation'},set(value['pins']['key']))
        self.assertEqual(0,json.loads((self.root/'endpoint-state.json').read_text())['changes'])
    def test_paused_packet_requires_no_guest_ssh_then_resumes_once(self):
        value=self.run_packet('enroll');pins=value['pins']
        (self.root/'endpoint-state.json').write_text(json.dumps({'status':'paused','changes':0}));self.ssh.clear()
        paused=self.run_packet(pins=pins);self.assertEqual('paused',paused['facts']['guest']);self.assertEqual([],self.ssh)
        expected={k:paused['facts'][k] for k in ['owner','boot','guest']};rid='ab'*32
        self.assertEqual('submitted',self.run_packet('resume',pins,rid,expected)['state'])
        self.assertEqual('running',self.run_packet(pins=pins)['facts']['guest'])
        self.assertEqual('blocked',self.run_packet('resume',pins,rid,expected)['state'])
        self.assertEqual(1,json.loads((self.root/'endpoint-state.json').read_text())['changes'])
    def test_s3_requires_system_wakeup_causal_whole_controller_red_green(self):
        folder=Path(__file__).parent/'fixtures/qemu_s3_wakeup_before'
        raw=(folder/'readiness_qemu_remote.py.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_bytes())['sourceSha256']
        self.assertEqual(metadata['readiness_qemu_remote.py'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(metadata['windows_vm_resources.py'],hashlib.sha256((folder/'windows_vm_resources.py').read_bytes()).hexdigest())
        self.assertEqual((folder/'windows_vm_resources.py.source').read_bytes(),(folder/'windows_vm_resources.py').read_bytes())
        before=types.ModuleType('agent_tools.qemu_s3_before');before.__package__='agent_tools';before.__file__=str(folder/'readiness_qemu_remote.py.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        value=self.run_packet('enroll');pins=value['pins']
        self.write('endpoint-state.json',json.dumps({'status':'suspended','changes':0,'wakeSupport':True}).encode())
        asleep=self.run_packet(pins=pins);self.assertEqual('suspended',asleep['facts']['guest'])
        expected={key:asleep['facts'][key] for key in ('owner','boot','guest')}
        old=self.run_packet('resume',pins,'91'*32,expected,producer=before)
        self.assertEqual('submitted',old['state'])
        with self.assertRaises(AssertionError):self.assertEqual('running',self.run_packet(pins=pins)['facts']['guest'])
        self.assertEqual(['cont'],json.loads((self.root/'endpoint-state.json').read_bytes())['resumeCommands'])
        self.assertEqual('submitted',self.run_packet('resume',pins,'92'*32,expected)['state'])
        self.assertEqual('running',self.run_packet(pins=pins)['facts']['guest'])
        final=json.loads((self.root/'endpoint-state.json').read_bytes())
        self.assertEqual(['cont','system_wakeup'],final['resumeCommands']);self.assertEqual(1,final['changes'])
        self.assertEqual('blocked',self.run_packet('resume',pins,'92'*32,expected)['state'])
        self.assertEqual(final,json.loads((self.root/'endpoint-state.json').read_bytes()))

    def test_s3_unsupported_or_malformed_machine_capability_blocks_before_intent(self):
        value=self.run_packet('enroll');pins=value['pins']
        for support in (False,1,None,{},'true'):
            self.write('endpoint-state.json',json.dumps({'status':'suspended','changes':0,'wakeSupport':support}).encode())
            observed=self.run_packet(pins=pins)
            expected={key:observed['facts'][key] for key in ('owner','boot','guest')}
            reply=self.run_packet('resume',pins,'93'*32,expected)
            self.assertEqual('suspend_wakeup_unsupported',reply['reason']);self.assertFalse(reply['vmSubmitted'])
            self.assertFalse((self.root/'readiness-qemu'/('93'*32+'.intent.json')).exists())
            self.assertEqual(0,json.loads((self.root/'endpoint-state.json').read_bytes())['changes'])

    def test_reboot_admission_waits_for_renewed_boot_and_never_repeats(self):
        value=self.run_packet('enroll');expected={k:value['facts'][k] for k in ['owner','boot','guest']};rid='cd'*32
        self.assertEqual('submitted',self.run_packet('reboot',value['pins'],rid,expected)['state'])
        self.assertEqual('booting',self.run_packet(pins=value['pins'])['facts']['guest'])
        self.guest_boot='a830e08f-986b-48c1-897b-7ea7229e171e'
        self.assertEqual('running',self.run_packet(pins=value['pins'])['facts']['guest'])
        self.assertEqual('blocked',self.run_packet('reboot',value['pins'],rid,expected)['state'])
    def test_terminal_stale_refusal_is_proven_before_vm_admission_causal_red_green(self):
        folder=Path(__file__).parent/'fixtures/qemu_remote_refusal_before'
        raw=(folder/'readiness_qemu_remote.py.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256']['readiness_qemu_remote.py'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools.qemu_remote_refusal_before');before.__package__='agent_tools';before.__file__=str(folder/'readiness_qemu_remote.py.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        value=self.run_packet('enroll');pins=value['pins'];rid='56'*32;digest='78'*32
        (self.root/'endpoint-state.json').write_text(json.dumps({'status':'paused','changes':0}))
        stale={'owner':self.owner,'boot':self.guest_boot,'guest':'paused'}
        old=self.run_packet('resume',pins,rid,stale,producer=before)
        self.assertEqual('prepared_context_stale',old['reason']);self.assertFalse(old['vmSubmitted'])
        with self.assertRaises(AssertionError):self.assertIn('completedRefusal',old)
        current=self.run_packet('resume',pins,rid,stale,dispatch_identity={'recoveryId':rid,'attempt':1,'dispatchDigest':digest})
        proof=current['completedRefusal'];self.assertEqual('prepared_context_stale',current['reason'])
        self.assertEqual((rid,1,digest),(proof['recoveryId'],proof['attempt'],proof['dispatchDigest']))
        self.assertEqual({'owner':self.owner,'boot':None,'guest':'paused'},proof['actual'])
        self.assertEqual({'pid':os.getpid(),'startTicks':888,'uid':os.geteuid(),'hostBootId':self.boot},proof['controller'])
        self.assertTrue(proof['powerIntentAbsent']);self.assertTrue(proof['noVmEffectAdmitted'])
        self.assertEqual('alive',proof['originalActor']);self.assertIsNone(proof['cleanStop'])
        self.assertFalse((self.root/'readiness-qemu'/(rid+'.intent.json')).exists())
        self.assertEqual(0,json.loads((self.root/'endpoint-state.json').read_text())['changes'])
    def test_active_or_unknown_work_blocks_power_before_intent(self):
        value=self.run_packet('enroll');self.guest_blockers=['protected_runtime']
        current=self.run_packet(pins=value['pins']);expected={k:current['facts'][k] for k in ['owner','boot','guest']}
        blocked=self.run_packet('reboot',value['pins'],'ef'*32,expected)
        self.assertEqual('positive_idle_proof',blocked['reason']);self.assertFalse((self.root/'readiness-qemu').exists())
    def test_stopped_start_requires_original_clean_shutdown_and_full_capacity(self):
        value=self.run_packet('enroll');pins=value['pins']
        expected={key:value['facts'][key] for key in ('owner','boot','guest')}
        self.assertEqual('submitted',self.run_packet('poweroff',pins,'12'*32,expected)['state'])
        (self.proc/str(self.child.pid)/'stat').unlink()
        stopped=self.run_packet(pins=pins)
        self.assertEqual('stopped',stopped['facts']['guest'])
        self.assertEqual({'pid':self.child.pid,'startTicks':777},stopped['cleanStop']['actor'])
        expected={key:stopped['facts'][key] for key in ('owner','boot','guest')}
        denied=self.run_packet('start',pins,'34'*32,expected)
        self.assertEqual('start_requires_full_admission',denied['reason'])
        self.assertFalse(denied['vmSubmitted'])
        self.assertFalse((self.root/'readiness-qemu'/('34'*32+'.intent.json')).exists())

    def test_acknowledged_poweroff_blocks_new_guest_admission_causal_red_green(self):
        folder=Path(__file__).parent/'fixtures/qemu_poweroff_pending_before'
        raw=(folder/'readiness_qemu_remote.py.before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools.qemu_poweroff_before');before.__package__='agent_tools';before.__file__=str(folder/'readiness_qemu_remote.py.before.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        for producer in (before,subject):
            fixture=type(self)('runTest');fixture.setUp()
            try:
                value=fixture.run_packet('enroll',producer=producer);pins=value['pins']
                expected={key:value['facts'][key] for key in ('owner','boot','guest')}
                self.assertEqual('submitted',fixture.run_packet('poweroff',pins,'12'*32,expected,producer=producer)['state'])
                # SSH acknowledged shutdown, but this real QMP actor is still
                # live. Admission must remain closed until actual absence.
                pending=fixture.run_packet(pins=pins,producer=producer)
                expected={key:pending['facts'][key] for key in ('owner','boot','guest')}
                command=protocol.enroll_program(fixture.binding['target'],fixture.machine,1000,actual_machine_id='a'*32)
                reply=fixture.run_packet('guest_jobs',pins,expected=expected,producer=producer,guest_job_source=command,guest_job_mode='enroll')
                if producer is before:
                    self.assertEqual('running',pending['facts']['guest'])
                    with self.assertRaises(AssertionError):self.assertEqual('blocked',reply['state'])
                    self.assertEqual('guest-completed',reply['state']);self.assertTrue((fixture.root/'guest-jobs.json').exists())
                else:
                    self.assertEqual('unknown',pending['facts']['guest']);self.assertEqual(['original_shutdown_pending'],pending['facts']['idleBlockers']);self.assertEqual('prepared_context_stale',reply['reason'])
                    self.assertFalse((fixture.root/'guest-jobs.json').exists())
            finally:fixture.doCleanups()

    def test_recovery_observer_retains_directory_generation_without_admitting_power(self):
        value=self.run_packet('enroll');pins=value['pins']
        expected={key:value['facts'][key] for key in ('owner','boot','guest')}
        self.assertEqual('submitted',self.run_packet('poweroff',pins,'12'*32,expected)['state'])
        (self.proc/str(self.child.pid)/'stat').unlink()
        manager=self.root/'readiness-qemu';before=manager.stat()
        result=self.run_packet('recovery-observe',pins,'34'*32)
        self.assertEqual('observed',result['state']);self.assertTrue(result['recoveryObservation']['intentAbsent'])
        self.assertEqual('34'*32,result['recoveryObservation']['recoveryId'])
        generation=result['recoveryObservation']['managerGeneration']
        self.assertEqual((before.st_dev,before.st_ino,before.st_ctime_ns),(generation[0],generation[1],generation[8]))
        self.assertEqual(before.st_ctime_ns,manager.stat().st_ctime_ns)
        self.assertFalse((manager/('34'*32+'.intent.json')).exists())
        self.assertEqual('stopped',result['facts']['guest'])

    def test_changed_private_key_generation_or_public_authority_refuses(self):
        value=self.run_packet('enroll');self.write('client-key',b'ANOTHER_INERT_KEY')
        self.assertEqual('fixture_changed',self.run_packet(pins=value['pins'])['reason'])


if __name__=='__main__':unittest.main()
