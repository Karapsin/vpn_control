"""Coordinator metadata portability; separate live host checks remain mandatory."""
import hashlib,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest import mock
from agent_tools import linux_deb_arch_acceptance as subject
from agent_tools import linux_deb_arch_guest_prepare_remote as worker
from agent_tools.tests import test_linux_deb_arch_acceptance as fixtures

class RolePathTests(unittest.TestCase):
    def manifest(self,module,home):
        intent=subject.Intent.parse(fixtures.DebArchAcceptanceTest('runTest').request())
        value={'schemaVersion':1,'host':'archlinux','profile':intent.profile,'distribution':intent.distribution,
               'guestRole':intent.guest_role,'sourceSha':intent.source_sha,'tree':home+'/vpn-control-install-vm-parity-'+intent.guest_role,
               'sshPort':intent.guest_port,'qemuPid':123,'qemuStartTicks':456,'diskDevice':7,'diskInode':8,'pristine':True}
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'manifest.json';path.write_text(json.dumps(value))
            return module._guest_manifest(intent,{'guestManifest':{'path':path}})
    def before(self,filename):
        path=Path(__file__).parent/'fixtures/linux_role_paths'/filename;raw=path.read_bytes()
        expected={'acceptance.before.source':'42836732e173a3185cd5cfba8fedf91067f1155d9929ba12d7a39e3139e19d6f','worker.before.source':'3ca0db900635ae8c65ff9a98746d6fdc7873df30c71e58720b36de3d11cb9e1f'}
        self.assertEqual(expected[filename],hashlib.sha256(raw).hexdigest())
        value=types.ModuleType('agent_tools._role_fixture_before');value.__package__='agent_tools';value.__file__=str(path)
        with mock.patch.dict(sys.modules,{value.__name__:value}):exec(compile(raw,str(path),'exec'),value.__dict__)
        return value
    def test_metadata_accepts_different_home_only_as_lexical_candidate(self):
        for home in ('/srv/lab-user','/different owned home'):
            self.assertEqual(home,self.manifest(subject,home)['tree'].rsplit('/',1)[0])
    def test_actual_before_manifest_rejects_same_new_home_candidate(self):
        old=self.before('acceptance.before.source')
        with self.assertRaises(ValueError):self.manifest(old,'/srv/lab-user')
        self.assertEqual('/srv/lab-user',self.manifest(subject,'/srv/lab-user')['tree'].rsplit('/',1)[0])
    def test_role_path_cannot_escape_or_change_role(self):
        for value in ('relative/vpn-control-install-vm-parity-ubuntu-update','/srv/../vpn-control-install-vm-parity-ubuntu-update','/srv//vpn-control-install-vm-parity-ubuntu-update','/srv/vpn-control-install-vm-parity-arch-update','/srv/\n/vpn-control-install-vm-parity-ubuntu-update'):
            self.assertFalse(subject.role_tree_path(value,'ubuntu-update'))
    @unittest.skipUnless(os.name=='posix','POSIX account database')
    def test_worker_root_comes_from_account_database_despite_old_home_environment(self):
        import pwd
        expected=Path(pwd.getpwuid(os.getuid()).pw_dir)/'.vpn-control-parity-prepare'
        path=Path(worker.__file__);raw=path.read_bytes()
        with mock.patch.dict(os.environ,{'HOME':'/PUBLIC_OLD_ATTEMPT_HOME'}):
            fresh=types.ModuleType('agent_tools._fresh_worker');fresh.__package__='agent_tools';fresh.__file__=str(path)
            exec(compile(raw,str(path),'exec'),fresh.__dict__)
        self.assertEqual(expected,fresh._HOST_ROOT)
        old=self.before('worker.before.source')
        # Original literal belongs to one historical user; it is not derived
        # from this native account database. This fixture never launches a VM.
        if expected!=Path('/home/kardinal/.vpn-control-parity-prepare'):self.assertNotEqual(expected,old._HOST_ROOT)

if __name__=='__main__':unittest.main()
