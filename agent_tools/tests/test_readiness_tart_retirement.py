import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from uuid import uuid4
from unittest import mock

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_fixture_registry as registry
from agent_tools import readiness_tart_registry as custody_module
from agent_tools import readiness_tart_retirement as retirement
from agent_tools import ssh_program_execution_remote as protocol


class CollectedRetirementTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.lifecycle = self.root / 'lifecycle'; self.lifecycle.mkdir(mode=0o700)
        self.native = self.root / '.runtime/native'; self.native.mkdir(parents=True,mode=0o700)
        self.c = object.__new__(custody_module.TartCustody)
        self.c.root=self.root; self.c.lifecycle_root=self.lifecycle; self.c._operator_held=False
        self.c.descriptor={'provider':'tart-linux'}
        self.c.binding=SimpleNamespace(machine='1'*32,expected_uid=1000,expected_account='admin')
        self.c._pins=lambda:None; self.c.guard=lambda **kwargs:{'state':'running','actor':{'pid':123,'birth':'same'}}
        self.op=str(uuid4()); self.boot=str(uuid4()); self.newboot=str(uuid4())
        self.program={'language':'python3','source':"print('sentinel')",'args':[],'cwd':'/tmp',
          'targetContext':{'kind':'ssh','uid':1000,'principal':'admin','home':'/home/admin','bootId':self.boot}}
        self.packet={'operationId':self.op,'remoteRoot':'/tmp/vpn-control-program-1000-'+self.op,'generation':[1,2],
          'binding':{'target':'job','machine':'1'*32,'boot':self.boot,'account':'1000'},
          'requestSha256':hashlib.sha256(protocol._canonical(self.program)).hexdigest(),
          'ownerSourceSha256':hashlib.sha256(jobs.owner_source()).hexdigest()}
        self.admission={'operationId':self.op,'provider':'tart-linux','packet':self.packet,'program':self.program,'counterPath':'/tmp/counter'}
        self.path=self.native/'original-admission.json'; jobs._publish(self.path,self.admission)
        directory=self.lifecycle/'guest-programs'; directory.mkdir(mode=0o700)
        self.recordpath=directory/(self.op+'.json')
        self.record={'packet':self.packet,'admissionPath':str(self.path),'admissionPin':registry._json(self.path)[1]}
        jobs._publish(self.recordpath,self.record)
        payload='import sys\nsys.argv='+repr(['-c'])+'\n'+protocol.command(self.program)[4]
        self.terminal={'binding':self.packet['binding'],'operationId':self.op,'owner':{'pid':345,'birth':'linux:123'},
          'generation':str(uuid4()),'programSha256':jobs.Program('generated-python-program',payload.encode(),jobs.MAX_STREAM_BYTES).digest,
          'exitCode':0,'streamsClosed':True}
        for name,raw in [('stdout',b'sentinel\n'),('stderr',b'')]:
            self.terminal[name]={'overflow':False,'retainedBytes':len(raw),'totalBytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        self.status={'binding':self.packet['binding'],'operationId':self.op,'owner':self.terminal['owner'],
          'reason':'correlated_terminal','replayAllowed':False,'schemaVersion':1,'state':'terminal','terminal':self.terminal}
        self.reply={'schemaVersion':1,'operationId':self.op,'status':self.status,
          'stdout':base64.b64encode(b'sentinel\n').decode(),'stderr':''}
        self.collection={'exitCode':0,'stdout':json.dumps(self.reply),'stderr':''}
        self.result={'operationId':self.op,'provider':'tart-linux','terminal':self.status,'sentinelOutput':'sentinel\n',
          'completeOutput':True,'singleExecution':True}
        jobs._publish(self.native/'original-reconciliation.json',self.collection)
        jobs._publish(self.native/'result.json',self.result)
        self.absence={'machine':'1'*32,'boot':self.newboot,'account':'1000','rootAbsent':True}
        self.original={str(p):p.read_bytes() for p in [self.path,self.recordpath,self.native/'original-reconciliation.json',self.native/'result.json']}

    def retire(self,absence=None):
        from agent_tools import readiness_tart
        reply=SimpleNamespace(returncode=0,stdout=json.dumps(self.absence if absence is None else absence))
        with mock.patch.object(readiness_tart.TartBackend,'_guest',return_value=(reply,{'same':'actor'})):
            return retirement._retire_custody(self.c,self.op,deadline=time.monotonic()+2)

    def test_collected_absent_previous_boot_owner_leaves_active_projection_without_rewriting_history(self):
        self.assertEqual(self.c.guest_jobs,[self.packet])
        self.assertEqual(self.c.guest_collected_jobs,[self.packet])
        self.retire()
        before=os.environ.get('VPN_CONTROL_TART_RETIREMENT_BEFORE')
        if before:
            self.assertEqual(before,'1')
            path=Path(__file__).parent/'fixtures'/'tart_collected_retirement_before.py'
            namespace=dict(vars(custody_module));exec(compile(path.read_text(),str(path),'exec'),namespace)
            projected=namespace['guest_jobs'](self.c)
        else:
            projected=self.c.guest_jobs
        self.assertEqual(projected,[])
        self.assertEqual(self.c.guest_collected_jobs,[self.packet])
        proof=self.lifecycle/'guest-program-retirements'/(self.op+'.json');raw=proof.read_bytes()
        self.retire();self.assertEqual(proof.read_bytes(),raw)
        for path,body in self.original.items():self.assertEqual(Path(path).read_bytes(),body)

    def test_unknown_incomplete_or_wrong_original_terminal_never_retires(self):
        import copy
        cases=[]
        changed=copy.deepcopy(self.collection);reply=copy.deepcopy(self.reply);reply['status']['state']='unknown';changed['stdout']=json.dumps(reply);cases.append(changed)
        changed=copy.deepcopy(self.collection);reply=copy.deepcopy(self.reply);reply['status']['terminal']['streamsClosed']=False;changed['stdout']=json.dumps(reply);cases.append(changed)
        changed=copy.deepcopy(self.collection);reply=copy.deepcopy(self.reply);reply['status']['terminal']['stdout']['overflow']=True;changed['stdout']=json.dumps(reply);cases.append(changed)
        changed=copy.deepcopy(self.collection);reply=copy.deepcopy(self.reply);reply['stdout']=base64.b64encode(b'foreign').decode();changed['stdout']=json.dumps(reply);cases.append(changed)
        changed=copy.deepcopy(self.collection);reply=copy.deepcopy(self.reply);reply['status']['terminal']['programSha256']='f'*64;changed['stdout']=json.dumps(reply);cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed):
                with self.assertRaises(registry.FixtureRegistryError):retirement._collected(self.admission,changed,self.result)
        self.assertFalse((self.lifecycle/'guest-program-retirements').exists())

    def test_original_root_present_same_boot_or_foreign_identity_blocks_retirement(self):
        for key,value in [('rootAbsent',False),('boot',self.boot),('machine','2'*32),('account','0')]:
            absent=dict(self.absence);absent[key]=value
            with self.subTest(key=key),self.assertRaises(registry.FixtureRegistryError):self.retire(absent)
        self.assertEqual(self.c.guest_jobs,[self.packet])

    def test_pure_projection_has_no_guest_execution_and_revalidates_original_evidence(self):
        from agent_tools import readiness_tart
        self.retire()
        with mock.patch.object(readiness_tart.TartBackend,'_guest',side_effect=AssertionError('pure')):
            self.assertEqual(self.c.guest_jobs,[])
        path=self.native/'result.json';value=json.loads(path.read_text());value['sentinelOutput']='changed';path.write_text(json.dumps(value));path.chmod(0o600)
        with self.assertRaises(registry.FixtureRegistryError):_ = self.c.guest_jobs

    def test_missing_collection_stays_active_and_normal_hook_never_retires_same_boot(self):
        from agent_tools import readiness_tart
        self.c._operator_held=True
        same=dict(self.absence);same['boot']=self.boot
        with mock.patch.object(readiness_tart.TartBackend,'_guest',return_value=(SimpleNamespace(returncode=0,stdout=json.dumps(same)),{})):
            self.c.reconcile_collected_guest_programs(deadline=time.monotonic()+2)
        self.assertEqual(self.c.guest_jobs,[self.packet])

    def test_stopped_normal_hook_preserves_collection_and_does_not_probe_guest(self):
        from agent_tools import readiness_tart
        self.c._operator_held=True
        self.c.guard=lambda **kwargs:{'state':'stopped'}
        with mock.patch.object(readiness_tart.TartBackend,'_guest',side_effect=AssertionError('stopped')):
            self.c.reconcile_collected_guest_programs(deadline=time.monotonic()+2)
        self.assertEqual(self.c.guest_jobs,[self.packet])
        (self.native/'original-reconciliation.json').unlink()
        self.assertEqual(self.c.guest_collected_jobs,[])
        self.assertEqual(self.c.guest_jobs,[self.packet])

    def test_absence_observer_uses_lstat_so_dangling_root_is_present(self):
        import subprocess
        packet=dict(self.packet);packet['remoteRoot']=str(self.root/'dangling')
        (self.root/'dangling').symlink_to(self.root/'missing')
        harness=("from pathlib import Path\nfrom unittest.mock import patch\n"
                 "with patch.object(Path,'read_text',return_value='controlled-identity'):\n "
                 "exec(compile("+repr(retirement._observer(packet))+",'<actual-absence-observer>','exec'))")
        result=subprocess.run(['python3','-I','-B','-c',harness],stdout=subprocess.PIPE,check=True)
        self.assertFalse(json.loads(result.stdout)['rootAbsent'])


if __name__=='__main__':unittest.main()
