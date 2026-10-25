"""Complete direct callers and emitted remote children never hash credentials."""
import ast,base64,hashlib,importlib,importlib.util,json,os,py_compile,shutil,sys,tempfile,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import ssh_direct_nested_channel as direct,ssh_fresh_nested_channel as channel

FIXTURE=Path(__file__).parent/'fixtures/direct_private_inventory'

@unittest.skipUnless(os.name=='posix','POSIX private inventory and original channel endpoints')
class DirectPrivateInventoryTests(unittest.TestCase):
    def before_sources(self):
        rows=json.loads((FIXTURE/'provenance.json').read_bytes())['beforeSha256']
        out={}
        for name,digest in rows.items():
            raw=(FIXTURE/(name+'.before.source')).read_bytes();self.assertEqual(digest,hashlib.sha256(raw).hexdigest());out[name]=raw
        return out
    def fixture(self):
        from agent_tools.tests.test_ssh_direct_nested_channel import DirectChannelTests
        f=DirectChannelTests('runTest');f.setUp();self.addCleanup(f.doCleanups);return f
    def old_provider(self,root):
        folder=root/'old-source';folder.mkdir(mode=0o700)
        for name in direct._SOURCE_NAMES+('readiness.py',):shutil.copyfile(Path(direct.__file__).with_name(name),folder/name)
        for name,raw in self.before_sources().items():(folder/name).write_bytes(raw)
        package='_private_direct_before_'+uuid.uuid4().hex;module=types.ModuleType(package);module.__path__=[str(folder)];sys.modules[package]=module
        self.addCleanup(lambda p=package:[sys.modules.pop(n,None)for n in list(sys.modules)if n==p or n.startswith(p+'.')])
        provider=importlib.import_module(package+'.ssh_direct_nested_channel')
        return provider,importlib.import_module(package+'.ssh_fresh_nested_channel')._REMOTE
    def test_full_direct_before_private_content_hash_red_new_generation_custody_green(self):
        old_sources=self.before_sources();real_sha=hashlib.sha256
        for original in (True,False):
            f=self.fixture();provider=direct;remote=channel._REMOTE
            if original:provider,remote=self.old_provider(f.root)
            f.expected_remote=remote;raw=f.config_path.read_bytes();secret=f.f.f.config['hosts']['archlinux']['password'].encode();seen=[]
            def hashing(body=b'',*args,**kwargs):
                if body==raw or body==secret:seen.append(True)
                return real_sha(body,*args,**kwargs)
            with mock.patch.object(hashlib,'sha256',side_effect=hashing),mock.patch.object(channel.subprocess,'Popen',side_effect=f.consumer):
                result=provider.prepare(f.root,'archlinux',f.corr)
            self.assertEqual('ready',result['state'],{k:v for k,v in result.items()if k not in ('stdout','stderr')})
            path=f.root/'.rag_index/ssh-direct-nested-channel/hosts/archlinux'/(f.corr+'.intent.json')
            intent=json.loads(path.read_bytes())
            if original:
                self.assertTrue(seen);self.assertIn('sha256',intent['inventory']);self.assertEqual(2,intent['version'])
            else:
                self.assertEqual([],seen);self.assertEqual(3,intent['version']);self.assertNotIn('sha256',intent['inventory'])
                self.assertEqual('private-generation-v1',intent['inventory']['custody'])
                rendered=path.read_bytes();self.assertNotIn(secret,rendered);self.assertNotIn(real_sha(raw).hexdigest().encode(),rendered)
                old=path.read_bytes();f.f.f.config['hosts']['archlinux']['password']='changed inert credential';f.f.f.write_config()
                before=len(f.calls)
                with mock.patch.object(channel.subprocess,'Popen',side_effect=f.consumer):blocked=provider.status(f.root,'archlinux',f.corr)
                self.assertEqual('unknown',blocked['state']);self.assertEqual(before,len(f.calls));self.assertEqual(old,path.read_bytes())
            f.assert_legacy_unchanged()
    def test_whole_generated_remote_actual_child_echo_before_red_current_no_bytes_or_hash_green(self):
        from agent_tools.tests.test_ssh_fresh_nested_channel import FreshChannelTests
        secret=b'inert fixture';encoded=base64.b64encode(secret).decode();digest=hashlib.sha256(secret).hexdigest()
        for original in (True,False):
            f=FreshChannelTests('runTest');f.setUp();self.addCleanup(f.doCleanups)
            if original:_,remote=self.old_provider(f.root)
            with mock.patch.object(channel,'_REMOTE',remote if original else channel._REMOTE):
                value=f.whole_remote_status(prepare_launch=True,launch_echo=True)
            rendered=json.dumps(value)
            self.assertNotIn(secret.decode(),rendered)
            if original:self.assertIn(encoded,rendered);self.assertIn(digest,rendered)
            else:self.assertNotIn(encoded,rendered);self.assertNotIn(digest,rendered);self.assertNotIn('streams',value['launchCapture'])
    def test_new_prepare_malformed_outer_echo_never_enters_callback_or_result(self):
        f=self.fixture();capture={};secret=f.f.f.config['hosts']['archlinux']['password'].encode()
        original=f.consumer
        def echo(argv,**kwargs):
            f.result={'arbitrary':secret.decode()};return original(argv,**kwargs)
        with mock.patch.object(channel.subprocess,'Popen',side_effect=echo):
            result=direct.prepare(f.root,'archlinux',f.corr,_private_capture=capture.update)
        self.assertEqual('unknown',result['state']);self.assertEqual(b'',capture['stdout']);self.assertEqual(b'',capture['stderr'])
        self.assertTrue(capture['credentialStreamsSuppressed']);self.assertNotIn(secret.decode(),repr(result))
    def test_timestamp_valid_private_helper_pyc_never_executes_in_verified_loader(self):
        f=self.fixture();folder=f.root/'private-helper-source';folder.mkdir(mode=0o700)
        for name in ('ssh_direct_nested_channel.py','ssh_direct_inventory.py','private_config_custody.py'):
            shutil.copyfile(Path(direct.__file__).with_name(name),folder/name)
        target=folder/'private_config_custody.py';raw=target.read_bytes();marker=f.root/'poison-executed'
        payload=('from pathlib import Path\nPath('+repr(str(marker))+').write_text("poison")\n').encode()
        payload+=b' '*(len(raw)-len(payload));self.assertEqual(len(raw),len(payload))
        target.write_bytes(payload);py_compile.compile(str(target),doraise=True);info=target.stat()
        target.write_bytes(raw);os.utime(target,ns=(info.st_atime_ns,info.st_mtime_ns))
        # Negative control proves a normal timestamp-cache import really
        # executes the poisoned compiled module on this interpreter.
        spec=importlib.util.spec_from_file_location('_private_helper_cache_control',target)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertTrue(marker.exists());marker.unlink()
        with mock.patch.object(direct,'__file__',str(folder/'ssh_direct_nested_channel.py')):
            with direct.private_inventory(f.root)as held:self.assertEqual('private-generation-v1',held.pin()['custody'])
        self.assertFalse(marker.exists())

    def test_held_inventory_exact_bytes_and_close_lifetime(self):
        f=self.fixture()
        with direct.private_inventory(f.root)as held:
            self.assertNotIn('sha256',held.pin());raw=f.config_path.read_bytes()
            info=f.config_path.stat();f.config_path.write_bytes(raw.replace(b'inert private sentinel',b'other private sentinel'))
            os.utime(f.config_path,ns=(info.st_atime_ns,info.st_mtime_ns))
            with self.assertRaises(ValueError):held.guard()
        with self.assertRaises(ValueError):held.guard()

if __name__=='__main__':unittest.main()
