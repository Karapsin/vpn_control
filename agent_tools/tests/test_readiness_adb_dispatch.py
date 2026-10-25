"""Protected Android child adapter with real process execution and provider sockets."""
import json
import importlib.util
from importlib.machinery import SourceFileLoader
import os
from pathlib import Path
import subprocess
import sys
import unittest
from dataclasses import replace
from uuid import uuid4

from agent_tools import readiness_entrypoints as entry
from agent_tools import readiness_adb_dispatch as subject
from agent_tools.tests import test_readiness_entrypoints as fixture


CALLER = r'''
import json,sys
from pathlib import Path
from types import SimpleNamespace
from agent_tools import readiness,readiness_entrypoints as entry
from agent_tools.tests.test_readiness import SocketAdapter
from agent_tools.tests.test_readiness_entrypoints import controlled_lease_workflow
root,wrapper,rawbinding,*arguments=sys.argv[1:]
root=Path(root)
context=readiness.Context('fixture','machine-a',SocketAdapter(root/'provider.sock'),readiness.RecoveryJournal(root))
entry.fixtures.registered_fixture=lambda *_:SimpleNamespace(context=lambda:context)
entry.fixtures.dispatch_binding=lambda *_:json.loads(rawbinding)
entry._registration_pin=lambda *_:{'generation':[1],'sha256':'fixture-pin'}
entry.gui_leases.workflow.workflow=controlled_lease_workflow(root)
sys.argv=[wrapper,*arguments]
exec(compile(Path(wrapper).read_bytes(),wrapper,'exec'),{'__name__':'__main__','__file__':wrapper})
'''


@unittest.skipUnless(os.name == 'posix', 'private executable adapter and provider sockets')
class AdbDispatchTests(unittest.TestCase):
    close = fixture.EntrypointTests.close

    def setUp(self):
        fixture.EntrypointTests.setUp(self)
        self.log = self.root/'adb-executions.jsonl'
        (self.root/'trusted-bin').mkdir(mode=0o700)
        self.adb = self.root/'trusted-bin/adb'
        self.adb.write_text('#!'+sys.executable+'\nimport json,os,sys\n'
                            'fd=os.open('+repr(str(self.log))+',os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)\n'
                            'os.write(fd,(json.dumps(sys.argv[1:])+"\\n").encode());os.close(fd)\n')
        self.adb.chmod(0o700)
        self.binding = {'adb':str(self.adb),'serial':'emulator-5660','avd':'owned-avd','serverPort':5038}
        self.dispatch.stop()
        from unittest import mock
        self.dispatch = mock.patch.object(entry.fixtures, 'dispatch_binding', return_value=self.binding)
        self.dispatch.start(); self.addCleanup(self.dispatch.stop)
        self.admission = entry.admit(self.root,'capture_visual_android','run',fixture_id='fixture', lease_ttl_seconds=5)
        self.addCleanup(self.admission.close)
        self.environment = subject.environment(self.admission)
        self.wrapper = Path(self.environment['PATH'].split(os.pathsep)[0])/'adb'

    def invoke(self, *arguments):
        return subprocess.run([sys.executable,'-I','-B','-c','import sys;sys.path.insert(0,'+repr(str(fixture.ROOT))+');'+CALLER,
                               str(self.root),str(self.wrapper),json.dumps(self.binding),*arguments],
                              cwd=fixture.ROOT,capture_output=True,text=True,timeout=5)

    def test_complete_generated_child_targets_original_daemon_explicitly(self):
        done = self.invoke('-s','emulator-5660','shell','echo','sentinel')
        self.assertEqual(0,done.returncode,done.stderr)
        self.assertEqual([['-H127.0.0.1','-P5038','-s','emulator-5660','shell','echo','sentinel']],
                         [json.loads(line) for line in self.log.read_text().splitlines()])
        self.assertTrue(self.wrapper.read_bytes().splitlines()[0].endswith(b' -I'))
        self.assertEqual([],self.provider.effects)

    def test_stale_child_is_stopped_before_actual_exec_no_recovery(self):
        self.provider.observation = replace(self.provider.observation,boot='new-boot')
        done=self.invoke('-s','emulator-5660','shell','input','keyevent','3')
        self.assertEqual(2,done.returncode)
        self.assertFalse(self.log.exists())
        self.assertEqual([],self.provider.effects)
        self.assertNotIn('keyevent',done.stderr)

    def test_daemon_lifecycle_and_endpoint_override_never_launch(self):
        for arguments in [('start-server',),('kill-server',),('-Hother','shell','id'),('-s','foreign','shell','id'),('-P','5037','shell','id')]:
            with self.subTest(arguments=arguments):
                done=self.invoke(*arguments)
                self.assertEqual(2,done.returncode)
        self.assertFalse(self.log.exists())
        self.assertEqual([],self.provider.effects)

    def test_original_unprotected_client_red_and_guarded_child_green(self):
        # Original PATH-only CLI selection still executes its configured ADB
        # after a guest generation changes. The fixed protected wrapper checks
        # the exact retained parent before that same harmless process executes.
        self.provider.observation = replace(self.provider.observation,boot='new-boot')
        source = fixture.before_source('android_installer_lifecycle.before.source')
        spec = importlib.util.spec_from_loader('before_installer_adb', SourceFileLoader('before_installer_adb',str(source)))
        previous = importlib.util.module_from_spec(spec)
        sys.path.insert(0,str(fixture.ROOT/'scripts'))
        try:
            spec.loader.exec_module(previous)
        finally:
            sys.path.pop(0)
        old_environment = previous.tls.public_cli_environment(str(self.adb),self.root/'packaged-cli')
        before = subprocess.run(['adb','-s','emulator-5660','shell','input','keyevent','3'],env=old_environment,capture_output=True)
        self.assertEqual(0,before.returncode)
        self.assertEqual(1,len(self.log.read_text().splitlines()))
        current=self.invoke('-s','emulator-5660','shell','input','keyevent','3')
        self.assertEqual(2,current.returncode)
        self.assertEqual(1,len(self.log.read_text().splitlines()))

    def test_existing_wrapper_is_create_only_and_content_change_is_blocker(self):
        self.assertEqual(self.environment['PATH'],subject.environment(self.admission)['PATH'])
        self.wrapper.write_text('#!'+sys.executable+'\nraise SystemExit(0)\n')
        with self.assertRaises(ValueError) as caught:
            subject.environment(self.admission)
        self.assertEqual('adb_dispatch_wrapper_changed',str(caught.exception))


if __name__=='__main__':
    unittest.main()
