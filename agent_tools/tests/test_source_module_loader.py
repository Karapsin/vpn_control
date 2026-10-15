"""Actual public adapter loader, real imports/files/cache and source mutation."""
import importlib,os,shutil,sys,tempfile,types,unittest
from pathlib import Path
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools.source_module_loader import Adapter
from agent_tools import source_module_loader as current

@unittest.skipUnless(os.name=='posix','POSIX physical custody')
class AdapterSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.sources=self.root/'agent_tools';self.sources.mkdir(mode=0o700)
        self.entry=self.sources/'windows_vm_deploy.py';self.entry.write_text('from . import native_vm_spec\ndef observe():return native_vm_spec.VALUE\n')
        self.helper=self.sources/'native_vm_spec.py';self.helper.write_text("VALUE='OLDER'\n")
        shutil.copyfile(Path(server.__file__).with_name('native_review_source_closure.py'),self.sources/'native_review_source_closure.py')
        for path in self.sources.iterdir():path.chmod(0o600);os.utime(path,ns=(1_000_000_000,1_000_000_000))
        self.name='_audit_original_loader';package=types.ModuleType(self.name);package.__path__=[str(self.sources)];sys.modules[self.name]=package
        self.addCleanup(self.remove_modules)
    def remove_modules(self):
        for name in list(sys.modules):
            if name==self.name or name.startswith(self.name+'.'):sys.modules.pop(name,None)
            elif hasattr(self,'public_server') and name.startswith('_vpn_core_'+str(self.public_server._MCP_BOOT_TIME_NS)+'_'):
                sys.modules.pop(name,None)
    def public_entry(self):
        # Run the authentic server from an owned source checkout. REPO_ROOT is
        # operational data; changing it must not select different executable code.
        if not hasattr(self,'public_server'):
            source=Path(server.__file__).parent
            for name in ('mcp_server.py','docs_assistant.py','local_build_environment.py',
                         'managed_check_lease.py','check_output_retention.py','windows_vm_setup_policy.py',
                         'native_workflow_policy.py',
                         'affected_agent_tests.py','affected_agent_test_dependencies.json','agent_test_runner.py'):
                shutil.copyfile(source/name,self.sources/name)
            name=self.name+'.mcp_server'
            spec=importlib.util.spec_from_file_location(name,self.sources/'mcp_server.py')
            self.public_server=importlib.util.module_from_spec(spec);sys.modules[name]=self.public_server
            spec.loader.exec_module(self.public_server)
        return self.public_server
    def changed_helper(self):
        metadata=self.helper.stat();self.helper.write_text("VALUE='NEWER'\n");os.utime(self.helper,ns=(metadata.st_atime_ns,metadata.st_mtime_ns))
    def test_public_entry_never_reuses_cached_dependency_or_timestamp_valid_pyc(self):
        public=self.public_entry()
        with mock.patch.object(public,'REPO_ROOT',self.root):
            first=public._agent_module('windows_vm_deploy')
            try:self.assertEqual('OLDER',first.observe())
            finally:
                if hasattr(first,'close'):first.close()
            self.changed_helper()
            second=public._agent_module('windows_vm_deploy')
            try:self.assertEqual('NEWER',second.observe())
            finally:
                if hasattr(second,'close'):second.close()
    def test_public_entry_captures_local_script_dependencies_too(self):
        scripts=self.root/'scripts';scripts.mkdir(mode=0o700)
        helper=scripts/'fixture_environment.py';helper.write_text("VALUE='OLDER'\n");helper.chmod(0o600)
        self.entry.write_text('import fixture_environment\ndef observe():return fixture_environment.VALUE\n')
        name='fixture_environment';previous=sys.modules.get(name)
        spec=importlib.util.spec_from_file_location(name,helper);cached=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cached);sys.modules[name]=cached
        try:
            public=self.public_entry()
            with mock.patch.object(public,'REPO_ROOT',self.root):
                first=public._agent_module('windows_vm_deploy')
                try:self.assertEqual('OLDER',first.observe())
                finally:first.close()
                metadata=helper.stat();helper.write_text("VALUE='NEWER'\n");os.utime(helper,ns=(metadata.st_atime_ns,metadata.st_mtime_ns))
                second=public._agent_module('windows_vm_deploy')
                try:self.assertEqual('NEWER',second.observe())
                finally:second.close()
        finally:
            if previous is None:sys.modules.pop(name,None)
            else:sys.modules[name]=previous

    def test_adapter_import_paths_do_not_modify_the_next_requests_environment(self):
        self.entry.write_text("import sys\nsys.path.insert(0,'PUBLIC_PREVIOUS_ATTEMPT_PATH')\ndef observe():return sys.path[0]\n")
        original=list(sys.path);proxy=Adapter(self.sources,'windows_vm_deploy')
        try:
            self.assertEqual('PUBLIC_PREVIOUS_ATTEMPT_PATH',proxy.observe())
            self.assertEqual(original,sys.path)
        finally:proxy.close()
        self.assertEqual(original,sys.path)

    def test_async_entry_holds_and_checks_source_until_await_finishes(self):
        import asyncio
        self.entry.write_text('import asyncio\nfrom . import native_vm_spec\nasync def observe():\n await asyncio.sleep(0)\n return native_vm_spec.VALUE\n')
        proxy=Adapter(self.sources,'windows_vm_deploy')
        try:
            self.assertEqual('OLDER',asyncio.run(proxy.observe()))
            pending=proxy.observe();self.changed_helper()
            with self.assertRaises(ValueError):asyncio.run(pending)
        finally:proxy.close()

    def test_original_open_source_rejects_dependency_change_before_effect(self):
        public=self.public_entry()
        with mock.patch.object(public,'REPO_ROOT',self.root):
            entry=public._agent_module('windows_vm_deploy')
            try:
                self.assertEqual('OLDER',entry.observe());self.changed_helper()
                with self.assertRaises(ValueError):entry.observe()
            finally:
                if hasattr(entry,'close'):entry.close()
    def test_temporary_adapter_keeps_custody_until_its_call_finishes(self):
        self.assertEqual('OLDER',Adapter(self.sources,'windows_vm_deploy').observe())

    def test_closing_source_guard_and_namespace_cleanup(self):
        before=set(name for name in sys.modules if name.startswith('_vpn_source_'))
        proxy=Adapter(self.sources,'windows_vm_deploy')
        try:
            prefix=proxy._session.prefix
            self.assertEqual('OLDER',proxy.observe());self.assertIn(prefix,sys.modules)
            self.changed_helper()
            with self.assertRaises(ValueError):proxy.observe()
        finally:proxy.close()
        self.assertEqual(before,set(name for name in sys.modules if name.startswith('_vpn_source_')))

    def worker_source(self):
        self.entry.write_text('from pathlib import Path\nfrom . import native_vm_spec\nclass Worker:\n def effect(self,path):Path(path).write_text(native_vm_spec.VALUE)\ndef worker():return Worker()\n')

    def test_preserved_class_lifetime_counterfactual_blocks_before_effect(self):
        self.worker_source();path=Path(__file__).parent/'fixtures/source_loader_lifetime/before.source'
        previous=types.ModuleType('source_loader_lifetime_before');previous.__file__=str(path)
        exec(compile(path.read_bytes(),str(path),'exec'),previous.__dict__)
        marker=self.root/'effect'
        old=previous.Adapter(self.sources,'windows_vm_deploy').Worker()
        self.changed_helper();old.effect(str(marker))
        self.assertEqual('OLDER',marker.read_text());marker.unlink()
        with self.assertRaises(ValueError):
            with current.request_scope(self.sources):
                worker=current.adapter(self.sources,'windows_vm_deploy').Worker()
                self.helper.write_text("VALUE='THIRD'\n")
                worker.effect(str(marker))
        self.assertFalse(marker.exists())

    def test_shared_request_keeps_class_and_factory_result_until_closing(self):
        self.worker_source();marker=self.root/'effect'
        before={n for n in sys.modules if n.startswith('_vpn_source_')}
        with current.request_scope(self.sources):
            worker=current.adapter(self.sources,'windows_vm_deploy').worker()
            klass=current.adapter(self.sources,'windows_vm_deploy').Worker
            self.assertIsInstance(worker,klass)
            worker.effect(str(marker));self.assertEqual('OLDER',marker.read_text())
            with current.request_scope(self.sources):
                self.assertIs(klass,current.adapter(self.sources,'windows_vm_deploy').Worker)
        self.assertEqual(before,{n for n in sys.modules if n.startswith('_vpn_source_')})
        marker.unlink()
        with self.assertRaises(ValueError):worker.effect(str(marker))
        self.assertFalse(marker.exists())

    def test_factory_result_checks_physical_same_byte_exchange(self):
        self.worker_source();marker=self.root/'effect'
        with self.assertRaises(ValueError):
            with current.request_scope(self.sources):
                worker=current.adapter(self.sources,'windows_vm_deploy').worker()
                replacement=self.helper.with_name('replacement.py');replacement.write_bytes(self.helper.read_bytes())
                replacement.replace(self.helper)
                worker.effect(str(marker))
        self.assertFalse(marker.exists())

    def test_callback_and_borrowed_module_cannot_escape_the_source_guard(self):
        path=Path(__file__).parent/'fixtures/source_loader_lifetime/before.source'
        previous=types.ModuleType('source_loader_callbacks_before');previous.__file__=str(path)
        exec(compile(path.read_bytes(),str(path),'exec'),previous.__dict__)
        helper="from pathlib import Path\nVALUE='OLDER'\ndef effect(path):Path(path).write_text(VALUE)\n"
        self.entry.write_text('from pathlib import Path\nfrom . import native_vm_spec\ndef callback():\n return lambda path:Path(path).write_text(native_vm_spec.VALUE)\ndef module():return native_vm_spec\n')
        marker=self.root/'effect'
        for kind in ('callback','module'):
            self.helper.write_text(helper)
            before=previous.Adapter(self.sources,'windows_vm_deploy')
            try:
                target=getattr(before,kind)();self.changed_helper()
                (target if kind=='callback' else target.effect)(str(marker))
                self.assertTrue(marker.exists());marker.unlink()
            finally:before.close()
            self.helper.write_text(helper)
            with self.assertRaises(ValueError):
                with current.request_scope(self.sources):
                    target=getattr(current.adapter(self.sources,'windows_vm_deploy'),kind)()
                    self.changed_helper()
                    (target if kind=='callback' else target.effect)(str(marker))
            self.assertFalse(marker.exists())

    def test_nested_callbacks_require_an_explicit_guarded_owner(self):
        self.entry.write_text('def boxed():return {"callback":lambda:None}\n')
        proxy=Adapter(self.sources,'windows_vm_deploy')
        try:
            with self.assertRaisesRegex(ValueError,'nested_adapter_capability'):proxy.boxed()
        finally:proxy.close()

    def test_preserved_cleanup_guard_leaks_descriptor_but_fix_always_unwinds(self):
        path=Path(__file__).parent/'fixtures/source_loader_lifetime/cleanup.before.source'
        previous=types.ModuleType('source_cleanup_before');previous.__file__=str(path)
        exec(compile(path.read_bytes(),str(path),'exec'),previous.__dict__)
        self.entry.write_text('from . import native_vm_spec\nclass Worker:\n def __init__(self,path):self.handle=open(path,"wb")\n def close(self):self.handle.close()\n')
        for module,leaked in ((previous,True),(current,False)):
            self.helper.write_text("VALUE='OLDER'\n")
            with self.assertRaises(ValueError):
                with module.request_scope(self.sources):
                    worker=module.adapter(self.sources,'windows_vm_deploy').Worker(str(self.root/'descriptor'))
                    self.changed_helper();worker.close()
            self.assertEqual(leaked,not worker.handle.closed)
            worker.handle.close()

if __name__=='__main__':unittest.main()
