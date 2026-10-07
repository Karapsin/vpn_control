"""Real generated component invocation, authority and retained failure tests."""
import ast, base64, json, os, pathlib, subprocess, sys, types, unittest
from unittest import mock
from agent_tools.tests.fixtures.android_component_hermetic import backend, OWNER
from agent_tools import android_component_command_transport as command

from agent_tools.tests.fixtures.android_component_hermetic import ComponentContext,scope
from agent_tools.tests.test_android_external_java_component_transport import FixtureCase

class CommandTests(FixtureCase):
    def setUp(self):
        super().setUp()
        from agent_tools.tests import test_android_external_java_component_transport as external_tests
        for name,value in (('command',external_tests._CONTEXT.command),('ROOT',external_tests.ROOT),('prepared',external_tests.prepared)):
            patch=mock.patch(__name__+'.'+name,value,create=True);patch.start();self.addCleanup(patch.stop)
    def test_actual_installer_async_and_noninteractive_reply_are_not_transport_failures(self):
        env,calls,saved,guards,guard,capture=scope()
        original=env['getter_binary']
        def child(*args,**kwargs):
            kwargs.pop('timeout',None)
            original(*args,**kwargs)
            interactive='--interactive' in args[2]
            is_status=args[2][-1:] == ['status']
            raw=json.dumps({'ok':True,'code':'OK' if is_status else 'ACCEPTED' if interactive else 'INTERACTION_REQUIRED','final':not interactive,'controllerId':OWNER,'configurationRevision':0,'data':{'runtimeRunning':False}})
            code=0 if interactive or is_status else 1
            env['GETTER_RECORDS']['captures'][-1].update(returncode=code,stdoutBase64=base64.b64encode(raw.encode()).decode(),stdoutBytes=len(raw.encode()))
            return dict(returncode=code,stdoutRaw=raw,stderrRaw='')
        env['command_binary']=child
        record=env['component_command'](['updates','install'],OWNER,0,'install-noninteractive',guard,capture)
        self.assertEqual(1,record['returncode']);self.assertEqual('INTERACTION_REQUIRED',record['stdout']['code'])
        record=env['component_command'](['updates','install'],OWNER,0,'install-interactive',guard,capture)
        self.assertFalse(record['stdout']['final']);self.assertEqual('ACCEPTED',record['stdout']['code'])
        self.assertIn('--async',calls[-1]);self.assertIn('--interactive',calls[-1])
        self.assertEqual(4,len(saved));self.assertFalse(record['installedLauncherAccepted'])

    def test_invalid_catalogue_phase_owner_revision_environment_prevent_child(self):
        env,calls,saved,guards,guard,capture=scope()
        for words,owner,revision,phase in [(['quit'],OWNER,0,'check'),(['updates','download'],OWNER,0,'check'),(['updates','install'],OWNER,True,'install-interactive'),(['updates','check'],'bad',0,'check'),(['diagnostics','export','--output','/secret'],OWNER,0,'baseline')]:
            with self.assertRaises(ValueError):env['component_command'](words,owner,revision,phase,guard,capture)
        self.assertEqual([],calls)

    def test_actual_owner_drift_rejects_before_update_dispatch(self):
        env,calls,saved,guards,guard,capture=scope()
        original=env['command_binary']
        def changed(*args,**kwargs):
            record=original(*args,**kwargs);value=json.loads(record['stdoutRaw']);value['controllerId']='d486ea37-70ec-4bcc-9f22-a4e382ce18b0';raw=json.dumps(value);record['stdoutRaw']=raw;env['GETTER_RECORDS']['captures'][-1].update(stdoutBase64=base64.b64encode(raw.encode()).decode(),stdoutBytes=len(raw.encode()));return record
        env['command_binary']=changed
        with self.assertRaisesRegex(ValueError,'command_owner_changed'):
            env['component_command'](['updates','check'],OWNER,0,'check',guard,capture)
        self.assertEqual(1,len(calls));self.assertEqual(['status'],calls[0][-1:])

    def test_raw_capture_precedes_json_guard_and_closing_failure(self):
        env,calls,saved,guards,guard,capture=scope()
        def child(*args,**kwargs):
            raw='private-invalid-json'
            env['GETTER_RECORDS'].setdefault('captures',[]).append({'returncode':0,'failure':None,'stdoutBase64':base64.b64encode(raw.encode()).decode(),'stderrBase64':'','stdoutBytes':len(raw),'stderrBytes':0})
            return dict(returncode=0,stdoutRaw=raw,stderrRaw='')
        env['command_binary']=child
        with self.assertRaisesRegex(ValueError,'command_json_invalid'):
            env['component_command'](['updates','status'],OWNER,0,'reconcile',guard,capture)
        self.assertEqual('private-invalid-json',saved[0]['stdoutRaw'])
        self.assertGreaterEqual(len(guards),2)

    def test_read_backend_remains_read_only(self):
        env,calls,saved,guards,guard,capture=scope()
        with self.assertRaisesRegex(ValueError,'component_fixed_command_required'):env['component_cli'](['updates','check'],OWNER)

    def test_actual_source_closed_prepare_compiles_composed_program_and_keeps_c466(self):
        import hashlib
        read=pathlib.Path(command.readonly.__file__).read_bytes()
        for device in ('android-api29','android-api35'):
            actual,binding=command.prepare(ROOT,prepared(device),device)
            tree=ast.parse(actual['program'])
            self.assertEqual(1,len([n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='component_command']))
            compile(actual['program'],'<complete-generated-command-flow>','exec')
            prefix=command.namespace_source(actual)
            self.assertNotEqual('coldboot_dispatch()',ast.unparse(ast.parse(prefix).body[-1]))
            original=actual['program'];actual['program']+='\nprivate_effect()\n'
            with self.assertRaisesRegex(ValueError,'command_program_changed'):command.namespace_source(actual)
            actual['program']=original
            self.assertEqual(command.readonly.DEVICES[device],binding['serial'])
        self.assertEqual(command.READ_SOURCE,hashlib.sha256(read).hexdigest());self.assertEqual(read,pathlib.Path(command.readonly.__file__).read_bytes())

    def test_actual_fd_binary_parent_guards_and_bounded_partial_loss_capture(self):
        import select,time,tempfile
        # Execute the actual generated descriptor wrapper and actual frozen
        # bounded reader. Only privilege drop and child JVM payload are replaced.
        with tempfile.TemporaryDirectory()as directory:
            path=pathlib.Path(directory)/'java';path.write_bytes(b'fixed');path.chmod(0o600)
            env,calls,saved,guards,guard,capture=scope()
            def fp(info):return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode,info.st_uid,info.st_gid,info.st_nlink]
            fd=os.open(directory,os.O_RDONLY);checks=[]
            env.update(fp=fp,parent_fds=lambda p:([{'fd':fd}],p.name),guard_parents=lambda _:checks.append('parent'),close_parents=lambda _:None)
            exec(ast.unparse(next(n for n in ast.parse(command.REMOTE).body if isinstance(n,ast.FunctionDef) and n.name=='command_binary')),env)
            real=subprocess.Popen
            def launch(argv,**kwargs):
                self.assertEqual('/proc/self/fd/'+str(kwargs['pass_fds'][0]),kwargs['executable'])
                kwargs.pop('executable');kwargs.pop('preexec_fn')
                return real([sys.executable,'-c',"import os,time;os.write(1,b'actual-private-partial');time.sleep(2)"],**kwargs)
            try:
                with mock.patch.object(subprocess,'Popen',side_effect=launch):
                    with self.assertRaisesRegex(ValueError,'permission_command_timeout'):
                        env['command_binary'](path,fp(path.stat()),[],{},limit=1024,timeout=.08)
                entry=env['GETTER_RECORDS']['captures'][-1]
                self.assertEqual(b'actual-private-partial',base64.b64decode(entry['stdoutBase64']));self.assertEqual('permission_command_timeout',entry['failure']);self.assertGreaterEqual(len(checks),1)
            finally:os.close(fd)

    def test_product_cancel_timeout_unknown_and_raw_export_preserved_for_caller(self):
        for code,envelope in ((130,{'code':'CANCELLED','final':True}),(2,{'code':'OUTCOME_UNKNOWN','final':True}),(2,{'code':'TIMEOUT','final':True})):
            env,calls,saved,guards,guard,capture=scope()
            def child(*a,**k):
                raw=json.dumps(envelope);env['GETTER_RECORDS'].setdefault('captures',[]).append({'returncode':code,'failure':None,'stdoutBase64':base64.b64encode(raw.encode()).decode(),'stderrBase64':'','stdoutBytes':len(raw),'stderrBytes':0});return dict(returncode=code,stdoutRaw=raw,stderrRaw='')
            env['command_binary']=child
            result=env['component_command'](['operations','wait',OWNER],OWNER,0,'operation-wait',guard,capture)
            self.assertEqual(envelope,result['stdout']);self.assertEqual(code,result['returncode']);self.assertEqual(1,len(saved))

    def test_capture_failure_still_runs_closing_authority_guards(self):
        env,calls,saved,guards,guard,capture=scope();child=env['getter_binary']
        env['command_binary']=lambda *a,**k:child(*a,**{n:v for n,v in k.items() if n!='timeout'})
        def failed(_):raise ValueError('durable_capture_failed')
        with self.assertRaisesRegex(ValueError,'durable_capture_failed'):env['component_command'](['updates','status'],OWNER,0,'reconcile',guard,failed)
        self.assertEqual(2,len(guards));self.assertEqual(1,len(calls))

    def test_actual_direct_nonroot_child_avoids_legacy_setgroups_and_preserves_raw(self):
        env,calls,saved,guards,guard,capture=scope();real=subprocess.Popen
        def forbidden(*a):raise PermissionError('nonroot_setgroups_refused')
        env['os'].setgroups=forbidden
        script="import os;os.write(1,b'actual-direct-child')"
        def launch(argv,**kwargs):
            # Parent identity facts are inert at this unit boundary. Real fork,
            # preexec, pipes and child execution prove the credential hook cause;
            # this does not claim real host UID1000 admission on this Mac.
            kwargs.pop('executable');return real([sys.executable,'-c',script],**kwargs)
        fd=os.open(sys.executable,os.O_RDONLY)
        try:
            with mock.patch.object(subprocess,'Popen',side_effect=launch):
                with self.assertRaises(subprocess.SubprocessError):env['getter_bounded'](['fixed'],fd,{},timeout=3)
                result=env['command_bounded'](['fixed'],fd,{},timeout=3)
            self.assertEqual('actual-direct-child',result['stdoutRaw']);self.assertEqual(0,result['returncode'])
            entry=env['GETTER_RECORDS']['captures'][-1];self.assertIsNone(entry['failure']);self.assertEqual(b'actual-direct-child',base64.b64decode(entry['stdoutBase64']))
        finally:os.close(fd)

    def test_host_group_drift_and_unknown_identity_reject_before_child(self):
        env,calls,saved,guards,guard,capture=scope()
        env['os'].getgroups=lambda:[1000,999]
        with self.assertRaisesRegex(ValueError,'command_host_identity_changed'):env['component_command'](['updates','check'],OWNER,0,'check',guard,capture)
        self.assertEqual([],calls)
        env['os'].getuid=env['os'].geteuid=lambda:501
        with self.assertRaisesRegex(ValueError,'command_host_identity_unadmitted'):env['command_host_identity']()

    @unittest.skipUnless(os.name=='posix' and os.geteuid()==1000 and os.getegid()==1000,'actual Linux UID/GID1000 carrier unavailable on this host')
    def test_real_exact_uid1000_carrier(self):
        env,calls,saved,guards,guard,capture=scope();env['os']=os;env['COMMAND_HOST']=env['command_host_identity']();real=subprocess.Popen
        def launch(argv,**kwargs):kwargs.pop('executable');return real([sys.executable,'-c','import os,json;print(json.dumps([os.getuid(),os.getgid(),sorted(os.getgroups())]))'],**kwargs)
        fd=os.open(sys.executable,os.O_RDONLY)
        try:
            with mock.patch.object(subprocess,'Popen',side_effect=launch):result=env['command_bounded'](['fixed'],fd,{},timeout=3)
            self.assertEqual([1000,1000,env['COMMAND_HOST']['groups']],json.loads(result['stdoutRaw']))
        finally:os.close(fd)

if __name__=='__main__': unittest.main()
