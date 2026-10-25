"""Actual gateway/socket and mmap-only kernel readers, without a real VM."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import ModuleType
import unittest
from unittest import mock

from agent_tools import readiness_windows_seed_detach as current
from agent_tools import readiness_windows_host_jobs as host
from agent_tools import durable_remote_job as jobs
from agent_tools import ssh_transport
from agent_tools.tests import test_windows_seed_detach as fixtures

FIXTURE=Path(__file__).parent/'fixtures/windows_seed_reader_scope'


def subject():
    if os.environ.get('VPN_CONTROL_SEED_REQUEST_BEFORE')!='1':return current
    raw=(FIXTURE/'before.source').read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._seed_reader_scope_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


def controlled_request(module,original,packet):
    """Source-only structural fixture, never an assertion of live ROOT facts."""
    body=original.as_dict();record,_,_=host._load(packet);ns=body['creatorNamespace'];uid=int(body['creatorExpected']['binding']['account'])
    pin=[1,2,stat.S_IFREG|0o600,uid,os.getegid(),1,100,1,1]
    actor={'pid':20,'birth':420,'uid':uid,'executableGeneration':[1,20,stat.S_IFREG|0o755,0,0,1,100,1,1]}
    root=Path(body['binding']['spec']['root']);info=root.lstat();h={k:record[k]for k in ('namespace','operationId','recoveryId','programSha256')}
    h.update(ownerSourceSha256=record['namespace']['ownerSourceSha256'],artifacts={k:list(pin)for k in ('intent.json','program.py','owner.py','terminal.json')})
    return {'schemaVersion':1,'kind':'windows-private-seed-readers-v1','machine':body['binding']['spec']['deploymentId'],'hostBoot':body['binding']['context']['hostBootId'],
        'uid':uid,'vmRoot':str(root),'rootIdentity':[info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid],'seedGeneration':pin,
        'creator':{'root':ns['root'],'rootGeneration':list(ns['generation']),'operationId':body['creatorOperationId'],'binding':body['creatorExpected']['binding'],
            'programSha256':body['creatorExpected']['programSha256'],'ownerSourceSha256':ns['marker']['ownerSourceSha256'],'artifacts':{k:list(pin)for k in ('intent.json','program.py','owner.py','terminal.json')}},
        'manager':actor,'actor':actor,'mutable':{'disk.qcow2':pin[:5],'uefi-vars.fd':pin[:5]},
        'managerSocket':{'path':str(root.parent/'.cache/libvirt/virtqemud-sock'),'inode':3,'identity':[1,3,stat.S_IFSOCK|0o600,uid,os.getegid()]},
        'detachment':{'operationId':body['operationId'],'intentGeneration':pin,'boot':'2026-10-20T03:04:05.0000000Z','account':'S-1-5-21-1-2-3-1001','hostOriginal':h}}


@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary actual private HOST artifacts required')
class SeedReaderScopeTests(unittest.TestCase):
    def _blocked_before_channel(self,attack):
        module=subject();done=[False];original_attach=module.attach_ejection
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as directory:
            root=Path(directory);root.chmod(0o700);wire=root/'observer.sock';ready=root/'ready';contacted=root/'contacted'
            child=subprocess.Popen([sys.executable,'-I','-B','-c',
                'import socket,sys;from pathlib import Path;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(1);s.settimeout(3);Path(sys.argv[2]).touch();\ntry:\n c,_=s.accept();assert c.recv(64)==b"privileged-observer";Path(sys.argv[3]).touch();c.close()\nexcept TimeoutError:pass\ns.close()',str(wire),str(ready),str(contacted)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                end=time.monotonic()+5
                while not ready.exists():self.assertIsNone(child.poll());self.assertLess(time.monotonic(),end);time.sleep(.01)
                def channel(*args,**kwargs):
                    with socket.socket(socket.AF_UNIX)as client:client.connect(str(wire));client.sendall(b'privileged-observer')
                    raise ValueError('controlled_gateway_stop_no_root')
                def capture(original,packet):
                    returned=original_attach(original,packet)
                    if done[0]:return returned
                    done[0]=True;request=controlled_request(module,original,packet)
                    if attack=='namespace':
                        namespace=Path(request['creator']['root']);saved=namespace.with_name(namespace.name+'.preserved-original')
                        os.rename(namespace,saved);shutil.copytree(saved,namespace)
                        try:
                            request['creator']['rootGeneration']=list(jobs.root_generation(namespace))
                            with mock.patch.object(ssh_transport,'admitted_transport',side_effect=channel):
                                with self.assertRaises(ValueError):
                                    with module.observe_readers(root,original.as_dict()['binding']['spec']['host'],original,request,'/unopened-secret',guard=lambda:None):self.fail('no ROOT observer allowed')
                        finally:shutil.rmtree(namespace);os.rename(saved,namespace)
                    elif attack=='owner':
                        class CanonicalChanged:
                            def __getattr__(self,name):return getattr(jobs,name)
                            def owner_source(self):return jobs.owner_source()+b'\n# newly canonical code differs from retained ordinary source\n'
                        with mock.patch.object(module,'jobs',CanonicalChanged()),mock.patch.object(ssh_transport,'admitted_transport',side_effect=channel):
                            with self.assertRaises(ValueError):
                                with module.observe_readers(root,original.as_dict()['binding']['spec']['host'],original,request,'/unopened-secret',guard=lambda:None):self.fail('historical bytes cannot execute as ROOT')
                    else:
                        with mock.patch.object(module.jobs,'_boot',None),mock.patch.object(ssh_transport,'admitted_transport',side_effect=channel):
                            with self.assertRaises(ValueError):
                                with module.observe_readers(root,original.as_dict()['binding']['spec']['host'],original,request,'/unopened-secret',guard=lambda:None):self.fail('non-function cannot authenticate current executing code')
                    return returned
                with mock.patch.object(fixtures,'subject',module),mock.patch.object(module,'attach_ejection',side_effect=capture):
                    result=unittest.TestResult();fixtures.SeedOwnerSourceTests('test_fixed_ejection_builder_uses_actual_opaque_host_namespace_and_original_packet').run(result)
                self.assertTrue(result.wasSuccessful(),str(result.errors)+str(result.failures));self.assertTrue(done[0])
                child.communicate(timeout=5);self.assertFalse(contacted.exists(),'unqualified request reached actual privileged transport boundary')
            finally:
                if child.poll()is None:child.terminate();child.communicate(timeout=3)

    def test_samebytes_replaced_creator_namespace_rejected_before_actual_channel(self):self._blocked_before_channel('namespace')
    def test_old_authenticated_owner_bytes_cannot_become_current_root_code(self):self._blocked_before_channel('owner')


@unittest.skipUnless(sys.platform.startswith('linux'),'actual Linux mapping metadata required')
class SeedMappedReaderTests(unittest.TestCase):
    def test_mapping_only_holder_with_no_matching_fd_is_observed(self):
        module=subject()
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'private.iso';path.write_bytes(b'x'*4096);path.chmod(0o600);info=path.stat()
            code='import ctypes,os,sys,time;fd=os.open(sys.argv[1],os.O_RDONLY);libc=ctypes.CDLL(None);libc.mmap.restype=ctypes.c_void_p;libc.mmap.argtypes=(ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long);value=libc.mmap(None,4096,1,2,fd,0);assert value not in (None,ctypes.c_void_p(-1).value);os.close(fd);os.write(1,b"ready");time.sleep(10)'
            child=subprocess.Popen([sys.executable,'-I','-B','-c',code,str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                self.assertEqual(child.stdout.read(5),b'ready')
                original=Path.iterdir
                def selected_projection(parent):
                    if parent==Path('/proc'):return iter([Path('/proc')/str(child.pid)])
                    return original(parent)
                with mock.patch.object(Path,'iterdir',selected_projection):rows,_=module._regular_file_census([info.st_dev,info.st_ino],time.monotonic()+5)
                self.assertEqual([row['pid']for row in rows],[child.pid],'a closed image FD does not close a live mmap reader')
            finally:child.terminate();child.communicate(timeout=3)


if __name__=='__main__':unittest.main()
