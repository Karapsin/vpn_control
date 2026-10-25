"""Canonical acceptance keeps original byte and inode custody across fresh lookups."""
import hashlib,json,os,sys,types,unittest,uuid
from pathlib import Path
from agent_tools import readiness_windows_host_work as current
from agent_tools.tests import test_readiness_windows_host_work as fixtures

FIXTURE=Path(__file__).parent/'fixtures/windows_host_work_acceptance'

def old_module():
    records=json.loads((FIXTURE/'provenance.json').read_bytes())['sourceSha256']
    if set(records)!={'before.source','actual-failure.txt'}:raise ValueError('acceptance_fixture_scope')
    for name,digest in records.items():
        if hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest()!=digest:raise ValueError('acceptance_fixture_changed')
    name='agent_tools._host_work_before_'+uuid.uuid4().hex
    module=types.ModuleType(name);module.__file__=str(FIXTURE/'before.source');module.__package__='agent_tools'
    sys.modules[name]=module
    try:exec(compile((FIXTURE/'before.source').read_bytes(),module.__file__,'exec'),vars(module))
    finally:sys.modules.pop(name,None)
    return module

class AcceptanceOriginalPinsTests(unittest.TestCase):
    def fixture(self):
        value=fixtures.HostWorkTests('runTest');value.setUp();self.addCleanup(value.doCleanups)
        args=value.arguments();identity={k:args[k]for k in ('spec','setup','host_boot')}
        return value,args,identity
    def mutate(self,fixture,args,mode):
        path=fixture.root/args['define_capture'];body=path.read_bytes()
        if mode=='whitespace':path.write_bytes(body+b'\n')
        else:
            other=path.with_name('same-content-replacement');other.write_bytes(body);other.chmod(0o600)
            original=path.stat();os.replace(other,path)
            self.assertNotEqual(original.st_ino,path.stat().st_ino)
    def test_full_before_rebuilds_changed_pins_current_refuses_bytes_and_same_content_inode(self):
        old=old_module()
        for mode in ('whitespace','same-content-inode'):
            with self.subTest(mode=mode):
                f,args,identity=self.fixture();old.register_libvirt_lifecycle_proofs(f.root,'fixture',**args)
                self.mutate(f,args,mode)
                self.assertEqual(2,len(old.accepted_libvirt_lifecycle_proofs(f.root,'fixture',**identity)),
                                 'authentic before no longer reproduces silently rebuilt custody')
                f,args,identity=self.fixture();current.register_libvirt_lifecycle_proofs(f.root,'fixture',**args)
                self.mutate(f,args,mode)
                with self.assertRaisesRegex(ValueError,'original_evidence_changed'):
                    current.accepted_libvirt_lifecycle_proofs(f.root,'fixture',**identity)
    def test_legacy_unpinned_record_stays_unchanged_and_requires_separate_explicit_admission(self):
        old=old_module();f,args,identity=self.fixture()
        old.register_libvirt_lifecycle_proofs(f.root,'fixture',**args)
        path=old._phase_record(f.root,'fixture',args['spec']['deploymentId']);before=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'acceptance_unpinned'):
            current.accepted_libvirt_lifecycle_proofs(f.root,'fixture',**identity)
        self.assertEqual(before,path.read_bytes())
        current.register_libvirt_lifecycle_proofs(f.root,'fixture',**args)
        self.assertEqual(before,path.read_bytes())
        self.assertEqual(2,len(current.accepted_libvirt_lifecycle_proofs(f.root,'fixture',**identity)))
        self.assertNotEqual(path,current._phase_record(f.root,'fixture',args['spec']['deploymentId']))

if __name__=='__main__':unittest.main()
