"""Complete fixed observer refuses a different account before native getters."""
from dataclasses import replace
import os
import subprocess
import sys
import unittest
import ast
import hashlib
import importlib.util
from pathlib import Path
import py_compile
import tempfile

from agent_tools.tests.test_readiness_tart_macos import binding
from agent_tools import readiness_tart_macos_session as session
from agent_tools import readiness_tart_macos_registry as registry


class SessionObserverTests(unittest.TestCase):
    def test_factory_generated_validator_executes_hash_verified_source_despite_valid_stale_cache(self):
        tree=ast.parse((Path(__file__).parent/'fixtures/macos_registry_pyc.before.source').read_bytes())
        before=next(node.value.value for node in tree.body if isinstance(node,ast.Assign)
                    and any(isinstance(name,ast.Name)and name.id=='_GUEST_PROBE'for name in node.targets))
        old=before[before.index('spec=importlib.util.spec_from_file_location'):before.index('native=m.Native()')]
        new=registry._GUEST_PROBE[registry._GUEST_PROBE.index('source=probe.read_bytes()'):registry._GUEST_PROBE.index('native=m.Native()')]
        import types
        with tempfile.TemporaryDirectory()as temporary:
            probe=Path(temporary)/'public_probe.py';probe.write_bytes(b"identity='OLD'\n");timestamp=probe.stat().st_mtime_ns
            py_compile.compile(str(probe),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            probe.write_bytes(b"identity='NEW'\n");os.utime(probe,ns=(timestamp,timestamp))
            scope={'probe':probe,'importlib':__import__('importlib')}
            exec(compile(old,'actual-before-validator-loader','exec'),scope)
            self.assertEqual(scope['m'].identity,'OLD')
            def need(value):self.assertTrue(value)
            scope={'probe':probe,'hashlib':hashlib,'types':types,'sys':sys,'need':need,
                   'p':{'files':{'guest-probe.py':hashlib.sha256(probe.read_bytes()).hexdigest()}}}
            exec(compile(new,'actual-current-validator-loader','exec'),scope)
            self.assertEqual(scope['m'].identity,'NEW')

    def test_actual_timestamp_valid_stale_bytecode_old_loader_red_exact_source_green(self):
        before=(Path(__file__).parent/'fixtures/macos_session_pyc.before.source').read_bytes()
        tree=ast.parse(before)
        observer=next(node.value.value for node in tree.body if isinstance(node,ast.Assign)
                      and any(isinstance(name,ast.Name)and name.id=='_OBSERVER'for name in node.targets))
        loader=observer[observer.index('spec=importlib.util.spec_from_file_location'):observer.index('native=module.Native()')]
        with tempfile.TemporaryDirectory()as temporary:
            probe=Path(temporary)/'public_probe.py';probe.write_bytes(b"identity='OLD'\n")
            timestamp=probe.stat().st_mtime_ns
            py_compile.compile(str(probe),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            probe.write_bytes(b"identity='NEW'\n");os.utime(probe,ns=(timestamp,timestamp))
            raw=probe.read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),hashlib.sha256(b"identity='NEW'\n").hexdigest())
            scope={'probe':probe,'importlib':__import__('importlib')}
            exec(compile(loader,'retained-before-loader','exec'),scope)
            self.assertEqual(scope['module'].identity,'OLD')
            self.assertEqual(session._load_verified_probe(raw,str(probe)).identity,'NEW')

    def binding(self):
        return replace(binding(),guest_python='/usr/local/libexec/vpn-tool-recovery-cont-control/python/bin/python3.12')

    def test_pure_builder_has_explicit_target_and_qualified_installed_probe(self):
        actual=self.binding();body=session.guest_session_source(actual)
        compile(body,'fixed-ordinary-session-observer','exec')
        self.assertIn(actual.target.encode(),body)
        self.assertIn(session._PROBE.encode(),body)
        for invalid in (None,{},'caller-machine'):
            with self.assertRaisesRegex(session.backend.MacBlocked,'^macos_session_binding_invalid$'):
                session.guest_session_source(invalid)

    @unittest.skipUnless(os.name=='posix','ordinary account fixed-caller refusal')
    def test_complete_subprocess_wrong_account_refuses_without_native_calls_or_output(self):
        actual=replace(self.binding(),ordinary_uid=max(501,os.geteuid()+1))
        body=session.guest_session_source(actual)
        result=subprocess.run([sys.executable,'-I','-'],input=body,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertEqual(result.returncode,73)
        self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')


if __name__=='__main__':unittest.main()
