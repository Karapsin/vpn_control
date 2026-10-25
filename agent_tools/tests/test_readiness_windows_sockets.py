"""Complete generated callers against physical QMP/QGA sockets and kernel IDs."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import types
from uuid import uuid4

from agent_tools import readiness_windows_remote as packets
from agent_tools import readiness_windows_guest as guest
from agent_tools.tests.test_native_vm_spec import request
from agent_tools.tests.test_readiness_windows_guest import facts,SID

ENDPOINT=Path(__file__).parent/'fixtures/windows_readiness_sockets/endpoint.py'
BEFORE=Path(__file__).parent/'fixtures/windows_libvirt_socket_binding'


def before_module(directory=BEFORE):
    raw=(directory/'remote.before.source').read_bytes()
    provenance=json.loads((directory/'provenance.json').read_text())
    expected=provenance['sourceSha256']
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('windows_remote_beforeimage_changed')
    module=types.ModuleType('agent_tools._windows_remote_before')
    module.__package__='agent_tools';module.__file__=str(directory/'remote.before.source')
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


def identity(pid):
    process=Path('/proc',str(pid));words=(process/'stat').read_text().rsplit(')',1)[1].split()
    raw=(process/'cmdline').read_bytes();s=os.stat(process/'exe')
    return {'pid':pid,'startTicks':int(words[19]),'argv':[os.fsdecode(w)for w in raw.split(b'\0')if w],
            'commandSha256':hashlib.sha256(raw).hexdigest(),
            'executableGeneration':[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]}


@unittest.skipUnless(sys.platform=='linux','actual Linux kernel actor and Unix socket descriptor census')
class CompleteWindowsSocketTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='vc-windows-sockets-',dir='/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        spec=request();spec['root']=str(self.root);self.machine=spec['deploymentId'];session=facts();session['machine']=self.machine
        setup={'imageName':'Windows 11 Pro','locale':'en-US','user':'recovery','administrator':'recoveryadmin'}
        hostboot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.binding={'provider':'raw-qemu-windows','spec':spec,'setup':setup,'context':{'hostBootId':hostboot,'pending':[]},'uri':None,'domain':None,'xmlSha256':None}
        def save(name,value):
            p=self.root/name;p.write_text(json.dumps(value));p.chmod(0o600)
        save('fixture.json',{'machine':self.machine,'sessionFacts':session})
        for name in ('disk.qcow2','uefi-vars.fd'):
            p=self.root/name;p.write_bytes(b'OWNED BLANK TEST DATA');p.chmod(0o600)
        mutable={}
        for name in ('disk.qcow2','uefi-vars.fd'):
            s=(self.root/name).stat();mutable[name]=[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid]
        save('mutable-artifacts.json',mutable)
        s=self.root.stat()
        save('intent.json',{'schemaVersion':1,'spec':spec,'setup':setup,'hostBootId':hostboot,
                           'rootIdentity':[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid],
                           'assetIdentities':{k:{}for k in ('firmwareCode','installer','drivers')}})
        for mode,name in [('qemu','qemu-started.json'),('tpm','swtpm-started.json')]:
            child=subprocess.Popen([sys.executable,'-I','-B',str(ENDPOINT),str(self.root),mode],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            def close(child=child):
                child.terminate();child.communicate(timeout=5)
            self.addCleanup(close)
            expected='qga.sock.ready'if mode=='qemu'else'swtpm.sock.ready'
            deadline=time.monotonic()+5
            while not(self.root/expected).exists():
                self.assertIsNone(child.poll());self.assertLess(time.monotonic(),deadline);time.sleep(.01)
            save(name,identity(child.pid))

    def run_packet(self,mode='observe',*,operation=None,producer=packets,**options):
        operation=operation or str(uuid4());source=producer.program(self.binding,mode,operation,**options)
        path=self.root/(operation+'.py');path.write_bytes(source);path.chmod(0o600)
        result=subprocess.run([sys.executable,'-I','-B',str(path)],stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
        self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'))
        return json.loads(result.stdout)

    def test_healthy_background_and_interactive_observation_no_unnecessary_recovery(self):
        first=self.run_packet();self.assertEqual('observed',first['state']);self.assertTrue(first['guestAgent'])
        self.assertIsNone(first['displayFacts'])
        self.assertEqual('ready',guest.validate_session(first['sessionFacts'],SID,'recovery',self.machine)['ordinary_session'])
        second=self.run_packet(interactive=True)
        self.assertEqual(0,second['displayFacts']['displayState']);self.assertEqual(0,json.loads((self.root/'counters.json').read_text())['inputCount'])

    def test_paused_resume_and_actual_display_wake_keep_original_actor(self):
        (self.root/'intentional-paused').write_text('intentional fixture phase')
        before=self.run_packet();self.assertEqual('paused',before['guest']);self.assertFalse(before['guestAgent'])
        resumed=self.run_packet('resume',expected=before,recovery_id='a'*64)
        self.assertEqual('submitted',resumed['state']);self.assertEqual(before['actor'],resumed['actor'])
        observed=self.run_packet(interactive=True)
        woken=self.run_packet('wake_display',expected=observed,recovery_id='b'*64)
        self.assertEqual('submitted',woken['state']);self.assertEqual(before['actor'],woken['actor'])
        final=self.run_packet(interactive=True)
        self.assertEqual(1,final['displayFacts']['displayState']);self.assertEqual(1,json.loads((self.root/'counters.json').read_text())['inputCount'])

    def test_stale_session_and_repeated_power_identity_never_duplicate_input(self):
        before=self.run_packet(interactive=True);before['sessionFacts']['boot']='2000-01-01T00:00:00.0000000Z'
        refused=self.run_packet('wake_display',expected=before,recovery_id='c'*64)
        self.assertEqual('instance_recovery_session_changed',refused['reason'])
        self.assertEqual(0,json.loads((self.root/'counters.json').read_text())['inputCount'])
        before=self.run_packet(interactive=True)
        self.assertEqual('submitted',self.run_packet('wake_display',expected=before,recovery_id='d'*64)['state'])
        self.assertEqual('blocked',self.run_packet('wake_display',expected=before,recovery_id='d'*64)['state'])
        self.assertEqual(1,json.loads((self.root/'counters.json').read_text())['inputCount'])

    def test_original_enrollment_absence_is_observed_without_guest_exec(self):
        before=self.run_packet();count=json.loads((self.root/'counters.json').read_text())['execCount']
        value=self.run_packet('lease-enrollment-status',expected={k:before[k]for k in ('actor','hostBoot','controlConnection')},
                              original_script={'operationId':str(uuid4()),'sourceSha256':'e'*64})
        self.assertEqual({'state':'unsubmitted','reason':'original_admission_absent','replayAllowed':False},value['lease'])
        self.assertEqual(count,json.loads((self.root/'counters.json').read_text())['execCount'])

    def test_indented_early_output_before_RED_fixed_refusal_before_guest_exec_GREEN(self):
        before=before_module(Path(__file__).parent/'fixtures/windows_controller_output_program')
        # The exact native failure was a successful PowerShell early Console
        # plus exit. Its output bypassed the source/nonce/PID envelope. Exercise
        # the complete caller's admission before the controlled Windows ABI.
        fixture=Path(__file__).parent/'fixtures/windows_jobs_observer_framing'
        provenance=json.loads((fixture/'provenance.json').read_text())
        captured=(fixture/'status.before.source').read_bytes()
        self.assertEqual(provenance['sourceSha256']['status.before.source'],hashlib.sha256(captured).hexdigest())
        program=captured.decode()
        for producer,fixed in [(before,False),(packets,True)]:
            operation=str(uuid4());source=producer.program(self.binding,'observe',operation).decode()
            original='SESSION_SCRIPT='+repr(guest.powershell_source('recovery'))+'\n'
            self.assertEqual(1,source.count(original))
            source=source.replace(original,'SESSION_SCRIPT='+repr(program)+'\n')
            path=self.root/(operation+'.py');path.write_text(source);path.chmod(0o600)
            counter_path=self.root/'counters.json'
            prior=json.loads(counter_path.read_text())['execCount'] if counter_path.exists() else 0
            result=subprocess.run([sys.executable,'-I','-B',str(path)],stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
            self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'));value=json.loads(result.stdout)
            self.assertEqual('blocked' if fixed else 'observed',value['state'])
            self.assertEqual(prior+(0 if fixed else 1),json.loads(counter_path.read_text())['execCount'])
            if fixed:
                self.assertEqual('instance_guest_output_program',value['reason'])
                self.assertFalse((self.root/('readiness-'+operation+'-session.intent.json')).exists())

    def test_indented_final_output_before_RED_fixed_refusal_before_guest_exec_GREEN(self):
        before=before_module(Path(__file__).parent/'fixtures/windows_controller_output_indent')
        for producer,fixed in [(before,False),(packets,True)]:
            operation=str(uuid4());source=producer.program(self.binding,'observe',operation).decode()
            original='SESSION_SCRIPT='+repr(guest.powershell_source('recovery'))+'\n'
            self.assertEqual(1,source.count(original));source=source.replace(original,'SESSION_SCRIPT='+repr(" [Console]::WriteLine('{}')")+'\n')
            path=self.root/(operation+'.py');path.write_text(source);path.chmod(0o600)
            counter_path=self.root/'counters.json';prior=json.loads(counter_path.read_text())['execCount'] if counter_path.exists() else 0
            result=subprocess.run([sys.executable,'-I','-B',str(path)],stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
            self.assertEqual(0,result.returncode,result.stderr.decode(errors='replace'));value=json.loads(result.stdout)
            self.assertEqual('blocked' if fixed else 'observed',value['state'])
            self.assertEqual(prior+(0 if fixed else 1),json.loads(counter_path.read_text())['execCount'])
            if fixed:
                self.assertEqual('instance_guest_output_program',value['reason'])
                self.assertFalse((self.root/('readiness-'+operation+'-session.intent.json')).exists())

    def test_original_controller_correlation_RED_and_GREEN(self):
        before=before_module(Path(__file__).parent/'fixtures/windows_controller_identity')
        (self.root/'wrong-controller').write_text('return unrelated QGA cached identity')
        self.assertEqual('observed',self.run_packet(producer=before)['state'])
        refused=self.run_packet()
        self.assertEqual('blocked',refused['state'])
        self.assertEqual('instance_guest_controller_identity',refused['reason'])
        # Rejected output is never promoted to a terminal receipt.
        intents=[p for p in self.root.glob('readiness-*.intent.json')if 'controllerIdentity'in json.loads(p.read_text())]
        self.assertEqual(1,len(intents))
        self.assertFalse(intents[0].with_name(intents[0].name.replace('.intent.','.terminal.')).exists())

    def test_legacy_retained_terminal_collects_but_pending_ack_never_queries_reused_pid(self):
        before=before_module(Path(__file__).parent/'fixtures/windows_controller_identity')
        operation=str(uuid4())
        self.assertEqual('observed',self.run_packet(operation=operation,producer=before)['state'])
        counters=json.loads((self.root/'counters.json').read_text())
        self.assertEqual('observed',self.run_packet(operation=operation)['state'])
        self.assertEqual(counters,json.loads((self.root/'counters.json').read_text()))
        (self.root/('readiness-'+operation+'-session.terminal.json')).unlink()
        refused=self.run_packet(operation=operation)
        self.assertEqual('instance_legacy_guest_job_unresolved',refused['reason'])
        self.assertEqual(counters,json.loads((self.root/'counters.json').read_text()))

    def test_overflow_terminal_evidence_RED_and_GREEN_preserves_bound_and_original(self):
        before=before_module(Path(__file__).parent/'fixtures/windows_terminal_evidence')
        (self.root/'oversized-controller').write_text('bounded untrusted output')
        for producer,fixed in [(before,False),(packets,True)]:
            operation=str(uuid4())
            with self.subTest(fixed=fixed):
                refused=self.run_packet(operation=operation,producer=producer)
                self.assertEqual('instance_guest_output_bound',refused['reason'])
                prefix='readiness-'+operation+'-session'
                observed=self.root/(prefix+'.observed-terminal.json')
                self.assertEqual(fixed,observed.exists())
                self.assertFalse((self.root/(prefix+'.terminal.json')).exists())
                if fixed:
                    original=observed.read_bytes();counters=json.loads((self.root/'counters.json').read_text())
                    self.assertTrue(json.loads(original)['exited'])
                    self.assertEqual('instance_guest_output_bound',self.run_packet(operation=operation)['reason'])
                    self.assertEqual(original,observed.read_bytes())
                    self.assertEqual(counters,json.loads((self.root/'counters.json').read_text()))

    def test_boolean_frame_schema_is_malformed_even_when_equal_to_integer_one(self):
        before=before_module(Path(__file__).parent/'fixtures/windows_terminal_evidence')
        (self.root/'malformed-controller').write_text('JSON booleans are not schema integers')
        self.assertEqual('observed',self.run_packet(producer=before)['state'])
        refused=self.run_packet()
        self.assertEqual('instance_guest_controller_identity',refused['reason'])

    def test_complete_cache_before_RED_and_fixed_repeated_original_GREEN(self):
        before=before_module(Path(__file__).parent/'fixtures/windows_terminal_cache')
        legacy=before_module(Path(__file__).parent/'fixtures/windows_controller_identity')
        for producer,fixed in [(before,False),(packets,True)]:
            operation=str(uuid4());prefix='readiness-'+operation+'-session'
            self.assertEqual('observed',self.run_packet(operation=operation,producer=legacy)['state'])
            self.assertEqual('observed',self.run_packet(operation=operation,producer=producer)['state'])
            self.assertEqual(not fixed,(self.root/(prefix+'.observed-terminal.json')).exists())
            (self.root/(prefix+'.terminal.json')).unlink()
            result=self.run_packet(operation=operation,producer=producer)
            self.assertEqual('blocked'if fixed else'observed',result['state'])
            if fixed:self.assertEqual('instance_legacy_guest_job_unresolved',result['reason'])
        (self.root/'oversized-controller').write_text('bounded untrusted output')
        for producer,fixed in [(before,False),(packets,True)]:
            operation=str(uuid4())
            self.assertEqual('instance_guest_output_bound',self.run_packet(operation=operation,producer=producer)['reason'])
            counters=json.loads((self.root/'counters.json').read_text())
            result=self.run_packet(operation=operation,producer=producer)
            self.assertEqual('instance_guest_output_bound'if fixed else'instance_receipt_bound',result['reason'])
            self.assertEqual(counters,json.loads((self.root/'counters.json').read_text()))

    def test_complete_before_accepts_replaced_disk_RED_and_fixed_rejects_GREEN(self):
        before=before_module()
        self.assertEqual('observed',self.run_packet(producer=before)['state'])
        original=self.root/'disk.qcow2';retained=self.root/'disk.before.qcow2';original.rename(retained)
        original.write_bytes(b'FOREIGN REPLACEMENT DISK');original.chmod(0o600)
        # The real original actor still holds the retained inode. A matching VM
        # UUID/QMP listener alone must not admit a different persisted disk.
        self.assertEqual('observed',self.run_packet(producer=before)['state'])
        refused=self.run_packet()
        self.assertEqual('blocked',refused['state']);self.assertEqual('instance_mutable_changed',refused['reason'])
        self.assertEqual(b'OWNED BLANK TEST DATA',retained.read_bytes())


if __name__=='__main__':unittest.main()
