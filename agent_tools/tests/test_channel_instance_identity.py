"""Complete channel entry points, real custody/children, transport-only fixture seam."""
import json,os,unittest
from agent_tools import ssh_fresh_nested_channel as subject
from agent_tools.tests import test_ssh_fresh_nested_channel as fixtures

@unittest.skipUnless(os.name=='posix','POSIX custody required')
class ChannelInstanceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.FreshChannelTests('runTest');self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
    def test_authenticated_peer_can_have_a_new_uid_and_boot(self):
        f=self.fixture;remote=f.ready_fixture()
        remote['arch']={'uid':2048,'boot':'a91dce69-8d35-4ce8-b917-87e890adca21'}
        f.stdout=json.dumps(remote).encode();f.rc=0
        self.assertEqual('ready',f.invoke()['state'])
        self.assertEqual('ready',f.invoke(False)['state'])
        f.stdout=json.dumps({**remote,'arch':{**remote['arch'],'boot':'bfcb12fa-d056-4f8c-bcef-929380a44d1d'}}).encode()
        self.assertEqual('unknown',f.invoke(False)['state'])
        self.assertEqual(['prepare','status','status'],[call[6] for call in f.calls])
    def test_new_source_revision_uses_archived_terminal_without_hash_bridges(self):
        from unittest import mock
        from pathlib import Path
        import tempfile
        f=self.fixture;remote=f.ready_fixture();f.stdout=json.dumps(remote).encode();f.rc=0
        with tempfile.TemporaryDirectory(dir=f.root) as temporary:
            copy=Path(temporary)/'ssh_fresh_nested_channel.py';copy.write_bytes(Path(subject.__file__).read_bytes())
            with mock.patch.object(subject,'__file__',str(copy)):
                self.assertEqual('ready',f.invoke()['state'])
                f.stdout=json.dumps({'state':'ended','correlationId':f.corr,'prior':remote,'gatewayBoot':remote['master']['gatewayBoot']}).encode()
                self.assertEqual('ended',f.invoke(False)['state'])
                group=f.root/'.rag_index/ssh-fresh-nested-channel/hosts/archlinux'
                before={p.name:p.read_bytes() for p in group.iterdir()}
                copy.write_bytes(copy.read_bytes()+b'\n# independently changed tool revision\n')
                self.assertEqual('ended',f.invoke(False)['state'])
                self.assertEqual(before,{p.name:p.read_bytes() for p in group.iterdir()})
                f.stdout=b'{}';f.rc=3;f.invoke(corr='c'*32)
                self.assertEqual('prepare',f.calls[-1][6])
                self.assertEqual(2,sum(call[6]=='prepare' for call in f.calls))
    def test_unknown_or_tampered_archive_never_allows_a_second_launch(self):
        f=self.fixture;remote=f.ready_fixture();f.stdout=json.dumps(remote).encode();f.rc=0
        self.assertEqual('ready',f.invoke()['state'])
        count=len(f.calls)
        self.assertEqual('unknown',f.invoke(corr='c'*32)['state']);self.assertEqual(count,len(f.calls))
        f.stdout=json.dumps({'state':'ended','correlationId':f.corr,'prior':remote,'gatewayBoot':remote['master']['gatewayBoot']}).encode()
        self.assertEqual('ended',f.invoke(False)['state'])
        group=f.root/'.rag_index/ssh-fresh-nested-channel/hosts/archlinux';capsule=group/(f.corr+'.remote.source')
        capsule.write_bytes(capsule.read_bytes()+b'PUBLIC_TAMPER')
        count=len(f.calls)
        self.assertEqual('unknown',f.invoke(corr='c'*32)['state']);self.assertEqual(count,len(f.calls))
    def test_invalid_native_identity_is_not_ready(self):
        f=self.fixture;remote=f.ready_fixture();remote['arch']['uid']=True
        f.stdout=json.dumps(remote).encode();f.rc=0
        self.assertEqual('unknown',f.invoke()['state'])

if __name__=='__main__':unittest.main()
