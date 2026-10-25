"""Real retained source files and durable terminal jobs; tiny trusted ZIP boundary."""
from contextlib import ExitStack
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import threading
import types
import unittest
from unittest import mock
from uuid import uuid4
import zipfile

from agent_tools import durable_remote_job as jobs
try:
    from . import native_fixture_storage as storage
    from . import native_restore_image as restore
except ImportError:
    import native_fixture_storage as storage
    import native_restore_image as restore


@unittest.skipUnless(os.name=='posix','real durable owner and private descriptor custody')
class VerifiedRestoreTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        temp=self.stack.enter_context(tempfile.TemporaryDirectory());self.root=Path(temp).resolve();self.root.chmod(0o700)
        self.op=str(uuid4());self.base=self.root/'.runtime/tool-recovery/tart'/('apple-asset-'+self.op);self.base.mkdir(mode=0o700,parents=True)
        memory=io.BytesIO()
        with zipfile.ZipFile(memory,'w') as archive:archive.writestr('approved','inert-public-restore-input')
        self.body=memory.getvalue();self.image=self.base/'Restore.ipsw';self.image.write_bytes(self.body);self.image.chmod(0o600)
        self.stack.enter_context(mock.patch.multiple(restore,SOURCE_BYTES=len(self.body),SOURCE_SHA256=hashlib.sha256(self.body).hexdigest(),ZIP_ENTRIES=1,ZIP_STAGING_BYTES=len(b'inert-public-restore-input')))
        self.jobs=self.base/'jobs';self.jobs.mkdir(mode=0o700);self.generation=jobs.root_generation(self.jobs)
        self.binding=jobs.MachineBinding('restore-profile','fixture-host',jobs._boot(),str(os.geteuid()))
        source=('import json,os,sys\nfrom pathlib import Path\n'+inspect.getsource(jobs._birth)+
                '\nPath('+repr(str(self.base/'actor.json'))+').write_text(json.dumps({"operationId":'+repr(self.op)+',"pid":os.getpid(),"birth":_birth(os.getpid())}))\nprint("original-complete")\n')
        self.program=jobs.Program('restore-test',source.encode())
        jobs.submit(self.jobs,self.op,self.binding,self.program,generation=self.generation)
        end=time.monotonic()+10
        while time.monotonic()<end:
            status=jobs.observe(self.jobs,self.op,self.binding,generation=self.generation)
            if status['state']=='terminal' and jobs._birth(status['terminal']['owner']['pid'])!=status['terminal']['owner']['birth']:break
            time.sleep(.02)
        self.assertEqual(status['state'],'terminal');self.actor=json.loads((self.base/'actor.json').read_bytes())
        self.plan_id='apple-ventura-source-'+self.op[:8];self.plans=storage.StoragePlans(self.root/'ledger')
        self.stack.enter_context(mock.patch.object(storage.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(1024**4,0,100*storage.GIB)))
        self.plans.reserve(self.plan_id,'macos','prepare-image',self.base,[{'path':str(self.image),'capacityBytes':len(self.body)}],writer_pid=self.actor['pid'])
        self.plans.settle(self.plan_id)
        self.intent={'operationId':self.op,'storageFixtureId':self.plan_id,'source':{'url':restore.SOURCE_URL,'bytes':len(self.body),'sha256':hashlib.sha256(self.body).hexdigest()},'programSha256':self.program.digest,'hostBinding':self.binding.__dict__,'jobRootGeneration':list(self.generation),'noVmAdmission':True}
        jobs._publish(self.base/'intent.json',self.intent)
        jobs._publish(self.base/'verified-source.json',{'operationId':self.op,'sourceUrl':restore.SOURCE_URL,'bytes':len(self.body),'sha256':hashlib.sha256(self.body).hexdigest(),'path':str(self.image),'actor':self.actor})

    def verify(self):
        proof=restore.verify_restore_image(self.root,self.plans,self.op);self.addCleanup(proof.close);return proof

    def guard(self,proof):
        with self.plans._locked():proof.guard(self.plans,self.plans._read())

    def test_complete_original_source_qualifies_only_exact_finite_install_capacity(self):
        before=self.plans._read();proof=self.verify();self.guard(proof)
        self.assertEqual(proof.bootstrap_growth([{'path':'/owned/vm/disk.img','capacityBytes':restore.RAW_CAPACITY_BYTES}]),(restore.RAW_CAPACITY_BYTES+restore.ZIP_STAGING_BYTES,restore.ZIP_STAGING_BYTES))
        self.assertEqual(before,self.plans._read());self.assertEqual(self.image.read_bytes(),self.body)
        for disks in ([{'path':'/owned/vm/disk.img','capacityBytes':1}], [{'path':'/owned/other.img','capacityBytes':restore.RAW_CAPACITY_BYTES}], []):
            with self.subTest(disks=disks),self.assertRaises(restore.RestoreImageError):proof.bootstrap_growth(disks)

    def test_initial_25_decimal_gb_profile_before_any_writer_preserves_all_other_growth(self):
        folder=Path(__file__).resolve().parents[1]/'agent_tools/tests/fixtures/restore_initial_disk_capacity_before'
        raw=(folder/'native_restore_image.py.source').read_bytes()
        expected=json.loads((folder/'provenance.json').read_text())['sourceSha256']['native_restore_image.py']
        self.assertEqual(expected,hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('scripts._restore_initial_capacity_before');before.__package__='scripts'
        exec(compile(raw,str(folder/'native_restore_image.py.source'),'exec'),before.__dict__)
        self.assertEqual(25_000_000_000,restore.RAW_CAPACITY_BYTES)
        self.assertEqual(29_000_000_000,before.RAW_CAPACITY_BYTES)
        other=6*storage.GIB
        self.plans.reserve('old-unknown','android','start',self.root,[{'path':str(self.root/'old.img'),'capacityBytes':other}])
        initial=self.plans._read();target=self.root/'mac'
        free=25_000_000_000+restore.ZIP_STAGING_BYTES+other+storage.HEADROOM_BYTES
        with mock.patch.multiple(before,SOURCE_BYTES=len(self.body),SOURCE_SHA256=hashlib.sha256(self.body).hexdigest(),ZIP_ENTRIES=1,ZIP_STAGING_BYTES=restore.ZIP_STAGING_BYTES),mock.patch.object(storage.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(1024**4,0,free)):
            with before.verify_restore_image(self.root,self.plans,self.op)as original:
                with self.assertRaisesRegex(storage.FixtureStorageError,'fixture_disk_capacity_insufficient'):
                    before.reserve_verified_bootstrap(original,self.plans,'mac',target)
            self.assertEqual(initial,self.plans._read())
            with self.verify()as proof:
                result=restore.reserve_verified_bootstrap(proof,self.plans,'mac',target)
        claim=self.plans._read()['plans']['mac']
        self.assertEqual([{'path':str(target/'disk.img'),'capacityBytes':25_000_000_000}],claim['disks'])
        self.assertEqual(25_000_000_000+restore.ZIP_STAGING_BYTES,claim['workingBytes'])
        self.assertEqual(restore.ZIP_STAGING_BYTES,claim['stagingBytes'])
        self.assertEqual(other,result['otherOwnedGrowthBytes']);self.assertEqual(free,result['requiredBytes'])
        self.assertEqual(initial['plans']['old-unknown'],self.plans._read()['plans']['old-unknown'])
        self.assertEqual(initial['plans'][self.plan_id],self.plans._read()['plans'][self.plan_id])
        self.assertFalse(target.exists())
        with self.verify()as proof:
            for capacity in [24_000_000_000,26_000_000_000,29_000_000_000,True]:
                with self.subTest(capacity=capacity),self.assertRaises(restore.RestoreImageError):
                    proof.bootstrap_growth([{'path':str(target/'disk.img'),'capacityBytes':capacity}])

    def test_pending_or_unbound_original_source_never_qualifies(self):
        state=self.plans._read();state['plans'][self.plan_id]['state']='pending';self.plans._save(state)
        with self.assertRaises(restore.RestoreImageError):self.verify()

    def test_wrong_approved_bytes_or_zip_staging_refuses(self):
        self.image.write_bytes(b'X'*len(self.body))
        with self.assertRaises(restore.RestoreImageError):self.verify()
        self.image.write_bytes(self.body)
        with mock.patch.object(restore,'ZIP_STAGING_BYTES',restore.ZIP_STAGING_BYTES+1),self.assertRaises(restore.RestoreImageError):self.verify()

    def test_metadata_or_path_claim_cannot_choose_another_source(self):
        v=json.loads((self.base/'verified-source.json').read_bytes());v['sourceUrl']='https://untrusted.invalid/image';(self.base/'verified-source.json').write_text(json.dumps(v))
        with self.assertRaises(restore.RestoreImageError):self.verify()

    def test_closed_proof_and_changed_named_file_original_receipt_or_claim_fail(self):
        proof=self.verify();replacement=self.base/'replacement';replacement.write_bytes(self.body);replacement.chmod(0o600);os.replace(replacement,self.image)
        with self.assertRaises((restore.RestoreImageError,ValueError)):self.guard(proof)
        proof.close()
        with self.assertRaises(restore.RestoreImageError):proof.bootstrap_growth([{'path':'/owned/disk.img','capacityBytes':restore.RAW_CAPACITY_BYTES}])

    def test_terminal_receipt_and_original_program_custody_are_revalidated(self):
        proof=self.verify();path=self.jobs/self.op/'program.py';path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises((restore.RestoreImageError,ValueError)):self.guard(proof)

    def test_ledger_change_or_running_original_actor_blocks_existing_capability(self):
        proof=self.verify();state=self.plans._read();state['plans'][self.plan_id]['writerPid']=os.getpid();self.plans._save(state)
        with self.assertRaises(restore.RestoreImageError):self.guard(proof)

    def test_verified_profile_removes_only_unknown_source_floor_and_preserves_other_claims(self):
        proof=self.verify();target=self.root/'new-mac';target.mkdir(mode=0o700)
        self.plans.reserve('android-unknown','android','start',self.root,[{'path':str(self.root/'android.img'),'capacityBytes':6*storage.GIB}])
        expected=restore.RAW_CAPACITY_BYTES+restore.ZIP_STAGING_BYTES+8*storage.GIB
        source_before=self.plans._read()['plans'][self.plan_id]
        with mock.patch.object(storage.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(1024**4,0,expected)):
            with self.assertRaisesRegex(storage.FixtureStorageError,'fixture_disk_capacity_insufficient'):
                self.plans.reserve('default-mac','macos','bootstrap',target,[{'path':str(target/'disk.img'),'capacityBytes':restore.RAW_CAPACITY_BYTES}],staging_growth_bytes=restore.ZIP_STAGING_BYTES)
            result=restore.reserve_verified_bootstrap(proof,self.plans,'verified-mac',target)
            self.assertEqual(result['requiredBytes'],expected)
            self.assertEqual(result['candidateGrowthBytes'],restore.RAW_CAPACITY_BYTES+restore.ZIP_STAGING_BYTES)
            self.assertEqual(result['otherOwnedGrowthBytes'],6*storage.GIB)
        self.assertEqual(self.plans._read()['plans'][self.plan_id],source_before)
        self.assertEqual(self.plans._read()['plans']['android-unknown']['state'],'pending')

    def test_insufficient_aggregate_claim_blocks_without_publishing_any_candidate(self):
        proof=self.verify();before=self.plans._read();target=self.root/'mac'
        with mock.patch.object(storage.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(1024**4,0,restore.RAW_CAPACITY_BYTES+restore.ZIP_STAGING_BYTES+storage.HEADROOM_BYTES-1)):
            with self.assertRaisesRegex(storage.FixtureStorageError,'fixture_disk_capacity_insufficient'):
                restore.reserve_verified_bootstrap(proof,self.plans,'mac',target)
        self.assertEqual(self.plans._read(),before);self.assertFalse(target.exists())

    def test_concurrent_finite_profiles_share_the_existing_capacity_lock(self):
        proof=self.verify();barrier=threading.Barrier(2);results=[]
        def reserve(name):
            barrier.wait()
            try:restore.reserve_verified_bootstrap(proof,self.plans,name,self.root/name);results.append('admitted')
            except storage.FixtureStorageError:results.append('blocked')
        free=restore.RAW_CAPACITY_BYTES+restore.ZIP_STAGING_BYTES+storage.HEADROOM_BYTES
        with mock.patch.object(storage.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(1024**4,0,free)):
            threads=[threading.Thread(target=reserve,args=(name,))for name in ('mac-a','mac-b')]
            for thread in threads:thread.start()
            for thread in threads:thread.join(timeout=5)
        self.assertEqual(sorted(results),['admitted','blocked'])
        self.assertEqual(len(self.plans._read()['plans']),2)

    def test_repeated_original_claim_retains_writer_and_changed_claim_is_rejected(self):
        proof=self.verify();target=self.root/'mac'
        one=restore.reserve_verified_bootstrap(proof,self.plans,'original-mac',target,writer_pid=os.getpid())
        two=restore.reserve_verified_bootstrap(proof,self.plans,'original-mac',target)
        self.assertEqual(one,two)
        with self.assertRaises(restore.RestoreImageError):restore.reserve_verified_bootstrap(proof,self.plans,'original-mac',target,writer_pid=os.getpid()+1)

    def test_known_immutable_source_is_not_future_growth_even_if_allocation_is_conservative(self):
        proof=self.verify();original=self.plans._growth;source=self.plans._read()['plans'][self.plan_id]
        def growth(plan,device,seen):
            result=original(plan,device,seen)
            return restore.SOURCE_BYTES if plan==source else result
        with mock.patch.object(self.plans,'_growth',side_effect=growth):
            result=restore.reserve_verified_bootstrap(proof,self.plans,'qualified-mac',self.root/'mac')
        self.assertEqual(result['requiredBytes'],restore.RAW_CAPACITY_BYTES+restore.ZIP_STAGING_BYTES+storage.HEADROOM_BYTES)
        self.assertEqual(self.plans._read()['plans'][self.plan_id],source)

    def test_missing_birth_visibility_is_not_original_actor_absence(self):
        proof=self.verify()
        with mock.patch.object(jobs,'_birth',return_value=None),mock.patch.object(self.plans,'_absent',side_effect=storage.FixtureStorageError('fixture_storage_writer_not_absent')):
            with self.assertRaisesRegex(storage.FixtureStorageError,'fixture_storage_writer_not_absent'):self.guard(proof)

    def test_source_verification_never_recreates_a_missing_capacity_ledger(self):
        self.plans.directory.rename(self.root/'retained-ledger')
        with self.assertRaises(restore.RestoreImageError):self.verify()
        self.assertFalse(self.plans.directory.exists())

if __name__=='__main__':unittest.main()
