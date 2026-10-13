"""Routine causal readonly checkpoint controls; owned synthetic Git and callbacks only."""
import hashlib,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
FIXTURES=Path(__file__).with_name('fixtures')/'windows_readonly_checkpoint'
PINS={'readonly_checkpoint.py':'8c791334f5036336c43eb287a3bf3a3d7aa96351102aafe1226b4bdbc93936e8','checkpoint.before.public.py':'982abc064f167b8a3083b93042e92f58ea790e4c524577d8c5f7d95be64aa09c','original-refusal.public.json':'620b6466bdd18d0c864151027bfe39b9f64230c768b3862134d146a7dcb2a915'}
SIZES={'readonly_checkpoint.py':8841,'checkpoint.before.public.py':673,'original-refusal.public.json':292}
def read_fixture(name):
    with (FIXTURES/name).open('rb')as source:value=source.read(SIZES[name]+1)
    if len(value)!=SIZES[name]:raise ValueError('readonly_fixture_size')
    if hashlib.sha256(value).hexdigest()!=PINS[name]:raise ValueError('readonly_fixture_pin')
    return value
def fixture_env():
    env={key:value for key,value in os.environ.items()if not key.startswith('GIT_')and key!='DYLD_INSERT_LIBRARIES'}
    env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0',GIT_OPTIONAL_LOCKS='0')
    return env
namespace={'__name__':'owned_checkpoint_fixture','__file__':str(FIXTURES/'readonly_checkpoint.py')}
exec(compile(read_fixture('readonly_checkpoint.py'),str(FIXTURES/'readonly_checkpoint.py'),'exec'),namespace)

@unittest.skipUnless(os.name=='posix' and hasattr(os,'getuid') and hasattr(os,'O_NOFOLLOW') and Path('/dev/fd').is_dir() and shutil.which('git'),'requires owned POSIX Git fixture')
class WindowsDirectReadonlyCheckpointTests(unittest.TestCase):
    _docs_consumer="new"
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='owned-readonly-checkpoint-');self.root=Path(self.temp.name)/'repo';self.root.mkdir()
        self.fd_before=len(os.listdir('/dev/fd'));self.addCleanup(self.assert_fd_count);self.addCleanup(self.temp.cleanup)
        self.git('init','-b','dev');self.git('config','user.email','fixture@example.invalid');self.git('config','user.name','Owned Fixture');self.git('config','commit.gpgsign','false')
        for name in ('app/main.kt','desktopApp/main.kt','shared/main.kt','buildSrc/build.gradle.kts','gradle/gradle-wrapper.properties','scripts/package.ps1','.github/workflows/windows.yml','gradle.properties','build.gradle.kts','settings.gradle.kts','gradlew','.gitignore','.gitattributes','docs/readme.md','agent_tools/tool.py'):
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('owned-fixture\n')
        self.git('add','.');self.git('commit','-m','owned fixture');self.head=self.git('rev-parse','HEAD').decode().strip();self.git('update-ref','refs/remotes/origin/dev',self.head)
        self.local=dict(namespace);self.local['EXPECTED_HEAD']=self.head
        # Fresh function globals use this explicitly modelled fixture HEAD, never alter real module globals.
        exec(compile(read_fixture('readonly_checkpoint.py'),str(FIXTURES/'readonly_checkpoint.py'),'exec'),self.local);self.local['EXPECTED_HEAD']=self.head
        self.calls=[]
    def assert_fd_count(self):
        self.assertEqual(self.fd_before,len(os.listdir('/dev/fd')))
    def git(self,*args):
        result=subprocess.run(['git','-c','core.hooksPath=/dev/null',*args],cwd=self.root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=fixture_env(),timeout=10)
        self.assertEqual(0,result.returncode,result.stderr.decode());return result.stdout
    def old_checkpoint(self):
        stub=Path(self.temp.name)/'stub/agent_tools';stub.mkdir(parents=True)
        (stub/'__init__.py').write_text('');(stub/'mcp_server.py').write_text("def _snapshot_fingerprint():return 'owned-fixture-FP'\n")
        source=read_fixture('checkpoint.before.public.py')
        code="import pathlib,subprocess,sys;sys.path.insert(0,"+repr(str(stub.parent))+ ");ROOT=pathlib.Path("+repr(str(self.root))+");HEAD="+repr(self.head)+";FP='owned-fixture-FP';exec(compile("+repr(source)+",'actual-old-public-checkpoint','exec'));checkpoint()"
        return subprocess.run([sys.executable,'-I','-B','-c',code],stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=fixture_env(),timeout=10)
    def source(self):self.calls.append('source')
    def config(self):self.calls.append('config')
    def check(self,scope='connection_uid_boot',source=None,config=None):
        return self.local['validate_readonly_checkpoint'](self.root,scope,source_guard=source or self.source,config_key_guard=config or self.config)
    def test_docs_and_unrelated_tool_dirty_allowed(self):
        (self.root/'docs/readme.md').write_text('changed-docs\n');(self.root/'agent_tools/tool.py').write_text('changed-unrelated-tool\n')
        old=self.old_checkpoint()
        if self._docs_consumer=='old':
            self.assertEqual(0,old.returncode,old.stderr.decode())
        else:
            self.assertNotEqual(0,old.returncode);self.assertIn(b'checkpoint_tuple',old.stderr)
            original=json.loads(read_fixture('original-refusal.public.json'))
            self.assertEqual('checkpoint_tuple',original['failure']['reason'])
            value=self.check();self.assertEqual(self.head,value['head']);self.assertFalse(value['nativeActionAllowed']);self.assertEqual(['source','config','source','config'],self.calls)
            value=self.check('windows_admission_census');self.assertEqual('windows_admission_census',value['scope'])
    def test_changed_product_refuses(self):
        (self.root/'app/main.kt').write_text('changed-product\n')
        with self.assertRaises(ValueError):self.check()
        self.assertEqual(['source','config','source','config'],self.calls)
    def test_staged_product_refuses(self):
        (self.root/'shared/main.kt').write_text('changed-staged\n');self.git('add','shared/main.kt')
        with self.assertRaises(ValueError):self.check()
    def test_added_product_refuses(self):
        (self.root/'scripts/new.ps1').write_text('added-product\n')
        with self.assertRaises(ValueError):self.check()
    def test_source_callback_refuses_without_adoption_and_both_after_guards_run(self):
        def refuse():self.calls.append('source');raise ValueError('owned-source-refusal')
        with self.assertRaisesRegex(ValueError,'owned-source-refusal'):self.check(source=refuse)
        self.assertEqual(['source','config','source','config'],self.calls)
    def test_config_callback_refuses(self):
        def refuse():self.calls.append('config');return False
        with self.assertRaises(ValueError):self.check(config=refuse)
        self.assertEqual(['source','config','source','config'],self.calls)
    def test_changed_HEAD_refuses(self):
        (self.root/'docs/readme.md').write_text('second-commit\n');self.git('add','.');self.git('commit','-m','wrong HEAD')
        with self.assertRaises(ValueError):self.check()
    def test_wrong_scope_or_missing_callbacks_refuse(self):
        for scope in ('install','run','arbitrary_command',True):
            with self.assertRaises(ValueError):self.check(scope)
        with self.assertRaises(ValueError):self.local['validate_readonly_checkpoint'](self.root,'connection_uid_boot',source_guard=None,config_key_guard=self.config)
    def test_callback_time_product_change_refuses(self):
        count=0
        def source():
            nonlocal count;count+=1;self.calls.append('source')
            if count==2:(self.root/'desktopApp/main.kt').write_text('callback-time-mutation\n')
        with self.assertRaises(ValueError):self.check(source=source)
        self.assertEqual(['source','config','source','config'],self.calls)


if __name__=='__main__':unittest.main()
