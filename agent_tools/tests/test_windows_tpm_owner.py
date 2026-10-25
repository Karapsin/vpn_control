"""Fixed HOST metadata carrier checks, plus Linux actual nondumpable-kernel RED/GREEN.

The Linux test needs genuine root CAP_SYS_PTRACE and never uses a VM. Ordinary
macOS runs explicitly skip that native kernel check; controlled carriers still
exercise full generated source, private input containment and result admission.
"""
import contextlib
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import readiness_windows_tpm_owner as subject
from agent_tools import readiness_windows_lifecycle as lifecycle
from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding

FIXTURE=Path(__file__).parent/'fixtures/windows_tpm_owner'


def request():
    return {'schemaVersion':1,'kind':'windows-tpm-listener-request-v1','machine':str(uuid4()),'hostBoot':str(uuid4()),
        'root':'/home/operator/fixture','rootIdentity':[1,2,0o40700,1000,1000],
        'mutable':{'disk.qcow2':[1,3,0o100600,1000,1000],'uefi-vars.fd':[1,4,0o100600,1000,1000]},
        'qemu':{'pid':100,'birth':1000,'uid':1000,'executableGeneration':[1,4,0o100755,0,0,1,30,0,0]},
        'socket':{'path':'/home/operator/.cache/libvirt/qemu/run/swtpm/selected.sock','inode':123,'identity':[1,5,0o140600,1000,1000]}}


@contextlib.contextmanager
def issued_witness(r,result=None):
    """Explicit controlled carrier; production minting remains observe-only."""
    if result is None:result={'complete':True,'holders':[{'pid':201,'uid':r['qemu']['uid'],'birth':2001}],
                             'observedNs':1_000_000_000,'deadlineNs':31_000_000_000}
    admission=mock.MagicMock();authority=mock.MagicMock()
    with tempfile.TemporaryDirectory()as tmp:
        credential=Path(tmp)/'credential';credential.write_text('controlled-private-value');credential.chmod(0o600)
        with mock.patch.object(subject.transport,'admitted_transport',return_value=admission), \
             mock.patch.object(subject.deploy.direct,'Guard',return_value=authority), \
             mock.patch.object(subject.transport,'build_ssh_argv',return_value=['controlled']), \
             mock.patch.object(subject.transport,'run_ssh',return_value=subprocess.CompletedProcess([],0,json.dumps(result).encode(),b'')):
            with subject.observe(Path(tmp),'controlled-target',r,credential,guard=lambda:None)as witness:
                yield witness


class TpmOwnerTests(unittest.TestCase):
    def test_finite_request_witness_and_source_binding(self):
        r=request();value={'complete':True,'holders':[{'pid':20,'uid':1000,'birth':90}],
                           'observedNs':1_000_000_000,'deadlineNs':31_000_000_000}
        with self.assertRaises(TypeError):subject.OwnerWitness(r,value,'0'*64)
        forged=object.__new__(subject.OwnerWitness)
        with self.assertRaises(ValueError):forged.validate(r)
        with issued_witness(r,value)as witness:
            self.assertEqual(witness.validate(r),value['holders'][0])
            mutated=witness.result;mutated['holders'][0]['pid']=999
            self.assertEqual(witness.validate(r),value['holders'][0])
            for key in ('hostBoot','machine'):
                bad=copy.deepcopy(r);bad[key]=str(uuid4())
                with self.assertRaisesRegex(ValueError,'observation_unknown'):witness.validate(bad)
            witness.consume(str(uuid4()))
            with self.assertRaises(ValueError):witness.consume(str(uuid4()))
            with mock.patch.object(subject.time,'monotonic',return_value=time.monotonic()+31):
                with self.assertRaises(ValueError):witness.validate(r)
        with self.assertRaises(ValueError):witness.validate(r)
        for result in ({'complete':False,'holders':[]},{'complete':True,'holders':[],'observedNs':1,'deadlineNs':2},
                       {'complete':True,'holders':[{'pid':20,'uid':0,'birth':90}],'observedNs':1,'deadlineNs':2}):
            with self.assertRaises(ValueError):
                with issued_witness(r,result):pass

    def test_target_socket_root_and_private_fields_refused(self):
        r=request()
        for change in ({'root':'/home/operator/../other'},{'secret':'private'}, {'socket':{**r['socket'],'path':'/tmp/foreign.sock'}},
                       {'qemu':{**r['qemu'],'uid':False}}, {'mutable':{'disk.qcow2':r['mutable']['disk.qcow2']}}):
            with self.assertRaises(ValueError):subject.program({**r,**change})
        for extra in ('argv','fdNames','contents','passwordSha256'):
            with self.assertRaises(ValueError):subject.validate_result({'complete':True,'holders':[],extra:[]})

    def test_generated_root_boundary_no_effect_and_constant_failure(self):
        # Full generated observer on this actual interpreter must not accept
        # an invented selected actor, whether the test host is root or ordinary.
        result=subprocess.run([sys.executable,'-I','-B','-c',subject.program(request()).decode()],capture_output=True)
        self.assertEqual(result.returncode,1);self.assertEqual(json.loads(result.stdout),{'complete':False,'holders':[],'observedNs':0,'deadlineNs':0})
        self.assertEqual(result.stderr,b'')
        source=subject.program(request()).decode()
        for forbidden in ('socket.connect','os.kill','pidfd_send_signal','guest-shutdown','subprocess','cmdline','read_bytes','hashlib'):
            self.assertNotIn(forbidden,source)

    def test_lineage_requires_exact_privileged_witness_before_generation(self):
        binding,_=managed_binding()
        with mock.patch.object(lifecycle.packets,'program',side_effect=AssertionError('generated')):
            with self.assertRaisesRegex(ValueError,'managed_tpm_owner_unqualified'):
                lifecycle.libvirt_lineage_program(binding,str(uuid4()))
        source=lifecycle.libvirt_lineage_program(binding,str(uuid4()),request_only=True).decode()
        compile(source,'request-only','exec')
        self.assertIn('LIFECYCLE_TPM_REQUEST_ONLY=True',source)
        self.assertNotIn("for candidate in pathlib.Path('/proc').iterdir()",source)

    def test_protected_controller_private_echo_timeout_overflow_and_strict_result(self):
        r=request();guard=mock.Mock();admission=mock.MagicMock();authority=mock.MagicMock()
        with tempfile.TemporaryDirectory()as folder:
            credential=Path(folder)/'credential';credential.write_text('never-output-private-value\n');credential.chmod(0o600)
            valid={'complete':True,'holders':[{'pid':20,'uid':1000,'birth':90}],'observedNs':1,'deadlineNs':2}
            replies=[subprocess.CompletedProcess([],0,json.dumps(valid).encode(),b''),
                     subprocess.CompletedProcess([],0,b'never-output-private-value',b''),
                     subprocess.CompletedProcess([],0,b'x'*65537,b''),
                     subprocess.CompletedProcess([],0,b'{"complete":true,"complete":true,"holders":[]}',b''),
                     subprocess.CompletedProcess([],1,b'',b'secret diagnostic'),subprocess.TimeoutExpired([],1)]
            for index,reply in enumerate(replies):
                with mock.patch.object(subject.transport,'admitted_transport',return_value=admission), \
                     mock.patch.object(subject.deploy.direct,'Guard',return_value=authority), \
                     mock.patch.object(subject.transport,'build_ssh_argv',return_value=['controlled']), \
                     mock.patch.object(subject.transport,'run_ssh',side_effect=reply if isinstance(reply,BaseException)else None,
                                       return_value=reply):
                    if index==0:
                        with subject.observe(Path(folder),'fixture-host',r,credential,guard=guard)as witness:
                            self.assertEqual(witness.validate(r),valid['holders'][0])
                    else:
                        with self.assertRaisesRegex(ValueError,'^windows_tpm_owner_observation_unknown$')as caught:
                            with subject.observe(Path(folder),'fixture-host',r,credential,guard=guard):pass
                        self.assertNotIn('private',str(caught.exception))


class LinuxKernelCausalTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform=='linux'and os.geteuid()==0,'actual Linux root metadata capability required')
    def test_whole_before_unrelated_nondumpable_red_privileged_full_generated_observer_green(self):
        # A real nondumpable same-UID process reproduces the original kernel
        # EACCES. Root without CAP_SYS_PTRACE is explicitly insufficient.
        capabilities=int(next(v.split()[1]for v in Path('/proc/self/status').read_text().splitlines()if v.startswith('CapEff:')),16)
        if not capabilities&(1<<19):self.skipTest('actual CAP_SYS_PTRACE required; cannot substitute mocked procfs')
        raw=(FIXTURE/'before.source').read_bytes();provenance=json.loads((FIXTURE/'provenance.json').read_text())
        self.assertEqual(hashlib.sha256(raw).hexdigest(),provenance['sourceSha256'])
        uid=65534;children=[]
        with tempfile.TemporaryDirectory()as tmp:
            home=Path(tmp);home.chmod(0o700);os.chown(home,uid,uid)
            root=home/'fixture';root.mkdir(mode=0o700);os.chown(root,uid,uid)
            for name in ('disk.qcow2','uefi-vars.fd'):
                p=root/name;p.write_bytes(b'harmless fixture');p.chmod(0o600);os.chown(p,uid,uid)
            wire=home/'.cache/libvirt/qemu/run/swtpm/selected.sock';wire.parent.mkdir(parents=True)
            for p in list(wire.parents):
                if p==home:break
                p.chmod(0o700);os.chown(p,uid,uid)
            child_source='''import os,socket,sys,time,ctypes
os.setgroups([]);os.setgid(65534);os.setuid(65534)
ctypes.CDLL(None).prctl(4,1)
files=[open(sys.argv[1]+'/'+n,'rb')for n in ('disk.qcow2','uefi-vars.fd')]
s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[2]);os.chmod(sys.argv[2],0o600);s.listen(1)
print('ready',flush=True)
time.sleep(60)
'''
            listener=subprocess.Popen([sys.executable,'-I','-c',child_source,str(root),str(wire)],stdout=subprocess.PIPE);children.append(listener)
            self.assertEqual(listener.stdout.readline(),b'ready\n')
            hidden=subprocess.Popen([sys.executable,'-I','-c',"import os,ctypes,time;os.setgroups([]);os.setgid(65534);os.setuid(65534);ctypes.CDLL(None).prctl(4,0);print('ready',flush=True);time.sleep(60)"],stdout=subprocess.PIPE);children.append(hidden)
            self.assertEqual(hidden.stdout.readline(),b'ready\n')
            def identity(p):
                i=os.stat(p);return [i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid]
            i=os.stat('/proc/'+str(listener.pid)+'/exe')
            birth=int(Path('/proc',str(listener.pid),'stat').read_text().rsplit(')',1)[1].split()[19])
            rows=[v.split()for v in Path('/proc/net/unix').read_text().splitlines()[1:]]
            inode=int(next(v[6]for v in rows if len(v)>7 and v[-1]==str(wire)and v[3]=='00010000'))
            r={'schemaVersion':1,'kind':'windows-tpm-listener-request-v1','machine':str(uuid4()),
               'hostBoot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'root':str(root),'rootIdentity':identity(root),
               'mutable':{n:identity(root/n)for n in ('disk.qcow2','uefi-vars.fd')},
               'qemu':{'pid':listener.pid,'birth':birth,'uid':uid,'executableGeneration':identity('/proc/'+str(listener.pid)+'/exe')+[i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]},
               'socket':{'path':str(wire),'inode':inode,'identity':identity(wire)}}
            try:
                # Execute the actual unfixed census block from the authenticated
                # whole source, under the ordinary same UID, on real procfs.
                text=raw.decode();start=text.index('    for candidate in pathlib.Path(\'/proc\').iterdir():',text.index('def _capture_libvirt_lineage'))
                end=text.index("    need(len(candidates)==1",start)
                block=text[start:end];block=block[:block.index('            pid=int(candidate.name)')]+"        except FileNotFoundError:continue\n"
                before='import os,pathlib\nos.setgroups([]);os.setgid(65534);os.setuid(65534)\ndef need(v):\n if not v:raise ValueError()\ntarget='+repr('socket:['+str(inode)+']')+'\nif True:\n'+block
                red=subprocess.run([sys.executable,'-I','-c',before],capture_output=True)
                self.assertNotEqual(red.returncode,0);self.assertIn(b'PermissionError',red.stderr)
                env={**os.environ,'SUDO_UID':str(uid)}
                green=subprocess.run([sys.executable,'-I','-B','-c',subject.program(r).decode()],capture_output=True,env=env)
                self.assertEqual(green.returncode,0,green.stdout.decode());value=json.loads(green.stdout)
                self.assertEqual(subject.validate_result(value)['holders'],[{'pid':listener.pid,'uid':uid,'birth':birth}])
                # No client connected: the actual listener remains ready to
                # accept no queued connection and was neither killed nor woken.
                self.assertIsNone(listener.poll());self.assertIsNone(hidden.poll())
            finally:
                for child in children:child.terminate();child.wait(timeout=5)


if __name__=='__main__':unittest.main()
