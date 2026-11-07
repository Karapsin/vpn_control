"""Pure local ownership proof with actual private files and full census DTOs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest import mock
from uuid import uuid4

if os.name == 'posix':
    from agent_tools import readiness_reservation_observation as observer
    from agent_tools.tests.test_native_vm_spec import request

GIB = 1024**3
INSTANCE_FIELDS = ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs')
CENSUS_FIELDS = ('dev', 'ino', 'mode', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs', 'nlink')
BEFORE_SHA = '21623665ca18a477a4311334d3e048c496e09dbb55e783b36d9bde405f4d5fb2'
NATIVE_SCHEMA_SHA = 'c597b19b58fecda0816f549e4672fcf695b5beeb43d678d0cc622fc8d3225ebc'


@unittest.skipUnless(os.name == 'posix', 'Actual private directory/FD ownership requires POSIX')
class ReservationObservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)
        self.fixture = Path(__file__).parent/'fixtures/windows_reservation_executable_schema'
        native_body = (self.fixture/'native-schema.json').read_bytes()
        self.assertEqual(NATIVE_SCHEMA_SHA,hashlib.sha256(native_body).hexdigest())
        self.native = json.loads(native_body)
        self.machine = str(uuid4()); self.boot = str(uuid4()); self.now = 2_000_000_000_000
        self.spec = request(); self.spec['deploymentId'] = self.machine
        self.actor = {key:self.native['getterActor'][key] for key in ('pid', 'startTicks')}
        self.row = next(copy.deepcopy(row) for row in self.native['hostResources']['vms']
                        if (row['pid'],row['startTicks']) == (self.actor['pid'],self.actor['startTicks']))
        self.spec['memoryMiB'] = self.row['configuredMemoryBytes']//1024**2
        self.binding = {'provider':'raw-qemu-windows', 'spec':self.spec,
                        'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'ordinary','administrator':'admin'},
                        'context':{'hostBootId':self.boot,'pending':[]},'uri':None,'domain':None,'xmlSha256':None}
        self.facts = {'provider':'raw-qemu-windows','machine':self.machine,'hostBoot':self.boot,
                      'actor':copy.deepcopy(self.native['getterActor']),
                      'guest':'running','controlConnection':'owned-qmp-connection'}
        self.identity = {'reservationId':'env-'+'b'*32,'token':'PRIVATE-OPAQUE-RESERVATION-TOKEN',
                         'hostAlias':self.spec['host'],'environment':'windows-'+self.machine,'operator':'windows-vm-deploy'}
        self.record = {'id':self.identity['reservationId'],'token':self.identity['token'],'hostAlias':self.spec['host'],
                       'environment':self.identity['environment'],'operator':'windows-vm-deploy','requestedMemoryBytes':self.row['configuredMemoryBytes'],
                       'allocationState':'running','activeJob':'active',
                       'activeJobEvidence':{'kind':'active-job','source':'windows-vm-deploy','outcome':'active',
                           'reservationId':self.identity['reservationId'],'reservationToken':self.identity['token']}}
        self.census = self.measurement()
        self.correlation = 'c'*32
        source = ('SPEC='+repr(self.spec)+'\nSETUP='+repr(self.binding['setup'])+'\nCONTEXT='+repr(self.binding['context'])+"\nMODE='start'\nraise RuntimeError('SOURCE_MUST_NEVER_EXECUTE')\n").encode()
        sha = hashlib.sha256(source).hexdigest()
        self.intent = {'spec':self.spec,'setup':self.binding['setup'],'context':self.binding['context'],
                       'mode':'start','correlationId':self.correlation,'callerSha256':sha}
        self.write('.rag_index/windows-vm-deploy-intents/'+self.machine+'.intent.json',self.intent)
        self.write('.runtime/windows-vm-deploy/'+self.correlation+'/caller.py',source)
        self.write('.runtime/windows-vm-deploy/'+self.correlation+'/request.json',{'spec':self.spec,'mode':'start','correlationId':self.correlation,'callerSha256':sha})
        self.write('.runtime/windows-vm-deploy/'+self.correlation+'/closing.json',{'sourceClosing':True,'correlationId':self.correlation})
        base='.runtime/windows-vm-credentials/'+self.machine+'/'
        self.write(base+'reservation.private.json',{'hostBootId':self.boot,'reservation':{'identity':self.identity}})
        self.write(base+'running-reservation.private.json',{'state':'reserved','identity':self.identity,'reservation':{'memoryBytes':self.row['configuredMemoryBytes'],'allocationState':'running'}})
        self.write(base+'boot-result.private.json',{'deploymentId':self.machine,'mode':'start','state':'booted-observed','qemu':self.actor})
        self.inventory_path='.rag_index/native-environments/reservations.json'
        self.write(self.inventory_path,{'version':1,'reservations':[self.record]})

    def write(self,name,value):
        path=self.root/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        path.write_bytes(value if type(value)is bytes else json.dumps(value).encode());path.chmod(0o600)
        return path

    def measurement(self):
        sample=lambda when:{'observedAtUnixMs':when,'availableMemoryBytes':40*GIB,'psi':'normal','psiSomeAvg10':0.,'psiFullAvg10':0.,'vmstat':{'pswpin':0,'pswpout':0,'oomKill':0}}
        return {'schemaVersion':1,'deploymentId':self.machine,'mode':'host-resources','state':'resources-observed','reason':None,
                'hostBootId':self.boot,'vms':[copy.deepcopy(self.row)],'physicalMemoryBytes':64*GIB,'swapUsedBytes':0,
                'samples':[sample(self.now-100),sample(self.now)],'freeDiskBytes':300*GIB,'inventoryComplete':True,'nativeActionAllowed':False,'replayAllowed':False}

    def observe(self,census=True):
        return observer.observe(self.root,self.binding,self.facts,census=self.census if census else None,clock=lambda:self.now)

    def assert_visible(self):
        with self.observe() as proof:
            self.assertTrue(proof.visibility_complete)
            self.assertEqual([],proof.as_dict()['blockers'])
            proof.guard()

    def assert_refused(self):
        with self.observe() as proof:
            self.assertFalse(proof.visibility_complete)
            self.assertEqual(['reservations'],proof.as_dict()['blockers'])
            with self.assertRaises(ValueError):proof.guard()

    def owned_observer(self, body):
        path = self.write('owned-observer.py',body)
        module = ModuleType('agent_tools._owned_reservation_schema')
        module.__file__ = str(path)
        module.__package__ = 'agent_tools'
        exec(compile(body,str(path),'exec',dont_inherit=True),module.__dict__)
        return module,path

    def traced_observe(self, module):
        failures = []
        def trace(frame,event,arg):
            if (event == 'exception' and frame.f_code.co_filename == module.__file__
                    and frame.f_code.co_name == '_need' and type(arg[1]) is ValueError):
                failures.append({'reason':str(arg[1]),'callerLine':frame.f_back.f_lineno,
                                 'callerFunction':frame.f_back.f_code.co_name})
            return trace
        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            proof = module.observe(self.root,self.binding,self.facts,census=self.census,clock=lambda:self.now)
        finally:
            sys.settrace(previous)
        return proof,failures

    def test_retained_native_schema_pair_joins_through_full_observe(self):
        self.assertNotEqual(self.row['executableGeneration'],self.facts['actor']['executableGeneration'])
        self.assertEqual(dict(zip(CENSUS_FIELDS,self.row['executableGeneration'])),
                         dict(zip(INSTANCE_FIELDS,self.facts['actor']['executableGeneration'])))
        before={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assert_visible()
        self.assertEqual(before,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_authentic_whole_before_refuses_same_pair_at_original_comparison(self):
        body = (self.fixture/'observer.before.source').read_bytes()
        self.assertEqual(BEFORE_SHA,hashlib.sha256(body).hexdigest())
        module,_ = self.owned_observer(body)
        proof,failures = self.traced_observe(module)
        with proof:
            self.assertFalse(proof.visibility_complete)
            with self.assertRaises(ValueError):proof.guard()
        self.assertEqual([{'reason':'reservation_visibility_unavailable','callerLine':178,
                          'callerFunction':'observe'}],failures)

    def test_each_named_executable_field_drift_refuses_in_both_schemas(self):
        for producer,fields in (('getter',INSTANCE_FIELDS),('census',CENSUS_FIELDS)):
            target = self.facts['actor'] if producer == 'getter' else self.census['vms'][0]
            for index,name in enumerate(fields):
                with self.subTest(producer=producer,field=name):
                    self.assert_visible()
                    original = target['executableGeneration'][index]
                    target['executableGeneration'][index] = original+1
                    try:self.assert_refused()
                    finally:target['executableGeneration'][index] = original

    def test_equal_raw_lists_do_not_guess_a_producer_schema(self):
        self.assert_visible()
        self.census['vms'][0]['executableGeneration'] = list(self.facts['actor']['executableGeneration'])
        self.assert_refused()

    def test_each_producer_requires_exact_width_list_and_actual_nonnegative_ints(self):
        class IntegerSubclass(int):pass
        for producer in ('getter','census'):
            target = self.facts['actor'] if producer == 'getter' else self.census['vms'][0]
            original = list(target['executableGeneration'])
            malformed = [None,tuple(original),dict(zip(INSTANCE_FIELDS,original)),
                         original[:-1],original+[1],'1'*9]
            for value in malformed:
                with self.subTest(producer=producer,valueType=type(value).__name__,width=getattr(value,'__len__',lambda:None)()):
                    self.assert_visible()
                    target['executableGeneration'] = value
                    try:self.assert_refused()
                    finally:target['executableGeneration'] = list(original)
            for index,number in enumerate(original):
                for value in (False,True,float(number),str(number),-1,None,IntegerSubclass(number)):
                    with self.subTest(producer=producer,index=index,valueType=type(value).__name__):
                        self.assert_visible()
                        target['executableGeneration'][index] = value
                        try:self.assert_refused()
                        finally:target['executableGeneration'][index] = number

    def test_pid_birth_and_exact_command_digest_mismatches_stay_refused(self):
        for producer in ('getter','census'):
            target = self.facts['actor'] if producer == 'getter' else self.census['vms'][0]
            for field in ('pid','startTicks','commandSha256'):
                with self.subTest(producer=producer,field=field):
                    self.assert_visible()
                    original = target[field]
                    target[field] = 'f'*64 if field == 'commandSha256' else original+1
                    try:self.assert_refused()
                    finally:target[field] = original
        for value in ('f'*63,'F'*64,True,None):
            with self.subTest(invalidDigest=value):
                self.assert_visible()
                original = self.census['vms'][0]['commandSha256'],self.facts['actor']['commandSha256']
                self.census['vms'][0]['commandSha256'] = self.facts['actor']['commandSha256'] = value
                try:self.assert_refused()
                finally:self.census['vms'][0]['commandSha256'],self.facts['actor']['commandSha256'] = original

    def test_census_uid_validation_and_private_owner_guards_remain_active(self):
        for value in (-1,2**32,True,1000.0,'1000'):
            with self.subTest(censusUid=value):
                self.assert_visible()
                original = self.census['vms'][0]['uid']
                self.census['vms'][0]['uid'] = value
                try:self.assert_refused()
                finally:self.census['vms'][0]['uid'] = original
        # The getter authenticates its process owner upstream; its actor DTO has
        # no process UID. FD9 uid/gid drift is covered independently above.
        expected = os.geteuid()+1
        with mock.patch('agent_tools.private_inventory_lock.os.geteuid',return_value=expected):
            self.assert_refused()
        expected = os.getuid()+1
        with mock.patch('agent_tools.native_review_source_closure.os.getuid',return_value=expected):
            self.assert_refused()
        self.assert_visible()

    def test_each_memory_join_stays_exact(self):
        self.assert_visible()
        self.census['vms'][0]['configuredMemoryBytes'] += GIB
        self.assert_refused()
        self.census['vms'][0]['configuredMemoryBytes'] -= GIB
        self.record['requestedMemoryBytes'] += GIB
        self.write(self.inventory_path,{'version':1,'reservations':[self.record]})
        self.assert_refused()
        self.record['requestedMemoryBytes'] -= GIB
        self.write(self.inventory_path,{'version':1,'reservations':[self.record]})
        base='.runtime/windows-vm-credentials/'+self.machine+'/'
        self.write(base+'running-reservation.private.json',{'state':'reserved','identity':self.identity,
                   'reservation':{'memoryBytes':self.row['configuredMemoryBytes']+GIB,'allocationState':'running'}})
        self.assert_refused()

    def test_loaded_source_and_final_source_guards_refuse_real_owned_file_drift(self):
        body = Path(observer.__file__).read_bytes()
        module,path = self.owned_observer(body)
        path.write_bytes(body+b'\nSOURCE_DRIFT=True\n')
        with module.observe(self.root,self.binding,self.facts,census=self.census,clock=lambda:self.now) as proof:
            self.assertFalse(proof.visibility_complete)
        module,path = self.owned_observer(body)
        with module.observe(self.root,self.binding,self.facts,census=self.census,clock=lambda:self.now) as proof:
            self.assertTrue(proof.visibility_complete);proof.guard()
            path.write_bytes(body+b'\n# actual source bytes changed after observation\n')
            with self.assertRaises(ValueError):proof.guard()

    def test_original_caller_digest_and_request_and_closing_are_still_authenticated(self):
        directory='.runtime/windows-vm-deploy/'+self.correlation+'/'
        for name in ('caller.py','request.json','closing.json'):
            with self.subTest(file=name):
                self.assert_visible()
                path=self.root/directory/name;original=path.read_bytes()
                if name == 'caller.py':value=original+b'\nCALLER_DRIFT=True\n'
                else:
                    value=json.loads(original)
                    if name == 'request.json':value['callerSha256']='e'*64
                    else:value['sourceClosing']=False
                self.write(directory+name,value)
                try:self.assert_refused()
                finally:self.write(directory+name,original)

    def test_every_held_private_snapshot_is_rechecked_at_final_guard(self):
        paths = sorted(path for path in self.root.rglob('*') if path.is_file())
        for path in paths:
            with self.subTest(file=str(path.relative_to(self.root))):
                original=path.read_bytes()
                with self.observe() as proof:
                    self.assertTrue(proof.visibility_complete);proof.guard()
                    path.write_bytes(original+b'\n')
                    try:
                        with self.assertRaises(ValueError):proof.guard()
                    finally:path.write_bytes(original)

    def test_later_running_claim_total_policy_still_refuses_24_gib_against_native_16_gib(self):
        self.assert_visible()
        other={**self.record,'id':'env-'+'d'*32,'token':'OTHER','environment':'held-other-fixture',
               'requestedMemoryBytes':20*GIB}
        self.write(self.inventory_path,{'version':1,'reservations':[self.record,other]})
        self.census={**copy.deepcopy(self.native['hostResources']),'deploymentId':self.machine,
                     'hostBootId':self.boot,'samples':self.measurement()['samples']}
        before=(self.root/self.inventory_path).read_bytes()
        self.assertEqual(16*GIB,sum(row['configuredMemoryBytes'] for row in self.census['vms']))
        self.assertEqual(24*GIB,sum(row['requestedMemoryBytes'] for row in (self.record,other)))
        self.assert_refused()
        self.assertEqual(before,(self.root/self.inventory_path).read_bytes())

    def test_original_metadata_is_not_executed_and_proof_publishes_no_token(self):
        before={str(p.relative_to(self.root)):p.read_bytes()for p in self.root.rglob('*')if p.is_file()}
        with self.observe()as proof:
            self.assertTrue(proof.as_dict()['visibilityComplete']);self.assertEqual([],proof.as_dict()['blockers']);proof.guard()
            self.assertEqual({'machine','hostBoot','actor','visibilityComplete','blockers'},set(proof.as_dict()))
            self.assertNotIn(self.identity['token'],json.dumps(proof.as_dict()))
        self.assertEqual(before,{str(p.relative_to(self.root)):p.read_bytes()for p in self.root.rglob('*')if p.is_file()})

    def test_missing_census_or_incomplete_inventory_never_proves_idle(self):
        with self.observe(census=False)as proof:
            self.assertFalse(proof.visibility_complete)
            with self.assertRaises(ValueError):proof.guard()
        self.census['inventoryComplete']=False
        with self.observe()as proof:self.assertFalse(proof.visibility_complete)

    def test_pending_and_unknown_competing_claims_block_dispatch(self):
        for allocation,active in [('pending','absent'),('running','unknown')]:
            row={**self.record,'id':'env-'+'d'*32,'token':'OTHER','environment':'other-fixture',
                 'allocationState':allocation,'activeJob':active,'requestedMemoryBytes':GIB}
            self.census['vms']=[{**self.row,'configuredMemoryBytes':8*GIB}]
            # Keep own exact memory while adding an independently seen actor.
            self.census['vms']=[self.row,{**self.row,'pid':19,'startTicks':779,'configuredMemoryBytes':GIB}]
            self.write(self.inventory_path,{'version':1,'reservations':[self.record,row]})
            with self.observe()as proof:
                self.assertTrue(proof.visibility_complete);self.assertEqual(['reservations'],proof.as_dict()['blockers'])
                with self.assertRaises(ValueError):proof.guard()

    def test_wrong_epoch_actor_or_memory_blocks_visibility(self):
        original=copy.deepcopy(self.census)
        for field,value in [('hostBootId',str(uuid4())),('vms',[]),('vms',[{**self.row,'configuredMemoryBytes':7*GIB}])]:
            self.census={**original,field:value}
            with self.observe()as proof:self.assertFalse(proof.visibility_complete)

    def test_migrated_libvirt_binds_current_actor_without_adopting_old_raw_pid(self):
        self.binding.update(provider='libvirt-windows',uri='qemu+unix:///session?socket=/owned/socket',domain='owned-domain',xmlSha256='f'*64)
        self.facts['provider']='libvirt-windows';self.facts['actor'].update(pid=20,startTicks=780)
        self.census['vms'][0].update(pid=20,startTicks=780)
        with self.observe()as proof:
            self.assertTrue(proof.visibility_complete);self.assertEqual({'pid':20,'startTicks':780},proof.as_dict()['actor']);proof.guard()

    def test_guard_rejects_changed_inventory_and_expired_samples(self):
        with self.observe()as proof:
            path=self.root/self.inventory_path;raw=path.read_bytes();path.write_bytes(raw)
            with self.assertRaises(ValueError):proof.guard()
        with self.observe()as proof:
            self.now+=60_001
            with self.assertRaises(ValueError):proof.guard()

    def test_alias_unknown_or_missing_original_closure_blocks(self):
        row={**self.record,'id':'env-'+'e'*32,'hostAlias':'unverified-alias','environment':'other-fixture'}
        self.write(self.inventory_path,{'version':1,'reservations':[self.record,row]})
        with self.observe()as proof:self.assertFalse(proof.visibility_complete)
        self.write(self.inventory_path,{'version':1,'reservations':[self.record]})
        (self.root/'.runtime/windows-vm-deploy'/self.correlation/'closing.json').unlink()
        with self.observe()as proof:self.assertFalse(proof.visibility_complete)


if __name__=='__main__':unittest.main()
