"""Pure local ownership proof with actual private files and full census DTOs."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from agent_tools import readiness_reservation_observation as observer
from agent_tools.tests.test_native_vm_spec import request

GIB = 1024**3


class ReservationObservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.root.chmod(0o700)
        self.machine = str(uuid4()); self.boot = str(uuid4()); self.now = 2_000_000_000_000
        self.spec = request(); self.spec['deploymentId'] = self.machine
        self.binding = {'provider':'raw-qemu-windows', 'spec':self.spec,
                        'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'ordinary','administrator':'admin'},
                        'context':{'hostBootId':self.boot,'pending':[]},'uri':None,'domain':None,'xmlSha256':None}
        self.actor = {'pid':17,'startTicks':777}
        self.row = {**self.actor,'sessionId':17,'uid':1000,'commandSha256':'a'*64,
                    'executableGeneration':[1]*9,'configuredMemoryBytes':6*GIB}
        self.facts = {'provider':'raw-qemu-windows','machine':self.machine,'hostBoot':self.boot,
                      'actor':{**self.actor,'argv':['qemu-system-x86_64'],'commandSha256':'a'*64,'executableGeneration':[1]*9},
                      'guest':'running','controlConnection':'owned-qmp-connection'}
        self.identity = {'reservationId':'env-'+'b'*32,'token':'PRIVATE-OPAQUE-RESERVATION-TOKEN',
                         'hostAlias':self.spec['host'],'environment':'windows-'+self.machine,'operator':'windows-vm-deploy'}
        self.record = {'id':self.identity['reservationId'],'token':self.identity['token'],'hostAlias':self.spec['host'],
                       'environment':self.identity['environment'],'operator':'windows-vm-deploy','requestedMemoryBytes':6*GIB,
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
        self.write(base+'running-reservation.private.json',{'state':'reserved','identity':self.identity,'reservation':{'memoryBytes':6*GIB,'allocationState':'running'}})
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
