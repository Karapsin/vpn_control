import hashlib
import subprocess
import unittest
from unittest import mock
from agent_tools import ssh_nested_socket_route_diagnostic as diagnostic
from agent_tools import ssh_nested_socket_retirement as frozen

WARNING=b'Pseudo-terminal will not be allocated because stdin is not a terminal.\r\n'


class RouteDiagnosticTests(unittest.TestCase):
    def test_exact_consumed_argv_retains_warning_cause_instead_of_losing_output(self):
        spec={'configFile':'/private/config','controlPath':'/private/r-123456789abcdef/m','remoteHostAlias':'target'}
        stdout=b'hostname target.example\nidentityfile /private/key\n'
        response=subprocess.CompletedProcess([],0,stdout,WARNING)
        with mock.patch.object(frozen.subprocess,'run',return_value=response):
            with self.assertRaisesRegex(ValueError,'effective_route_unknown'):frozen.effective_route(spec)
        with mock.patch.object(diagnostic,'file_pin',return_value={'unsupportedConfigDirectives':False},create=True),mock.patch.object(diagnostic,'ssh_options',side_effect=frozen.ssh_options,create=True),mock.patch.object(subprocess,'run',return_value=response) as run:
            result=diagnostic.diagnose_remote(spec)
        self.assertIsNotNone(run.call_args)
        self.assertEqual([*frozen.ssh_options(spec),'-G','target'],run.call_args.args[0])
        self.assertEqual('exact-nonterminal-warning',result['category'])
        self.assertEqual(hashlib.sha256(WARNING).hexdigest(),result['stderr']['sha256'])
        self.assertEqual(hashlib.sha256(stdout).hexdigest(),result['stdout']['sha256'])

    def test_unknown_stderr_failure_and_clean_routes_are_retained_without_retry(self):
        spec={'configFile':'/private/config','controlPath':'/private/r-123456789abcdef/m','remoteHostAlias':'target'}
        for code,out,err,category in ((0,b'options',b'other warning','stderr-present'),(255,b'partial',b'failed','command-failed'),(0,b'options',b'','clean-effective-options'),(0,b'',WARNING,'stdout-unavailable')):
            with self.subTest(category=category),mock.patch.object(diagnostic,'file_pin',return_value={'unsupportedConfigDirectives':False}),mock.patch.object(diagnostic.subprocess,'run',return_value=subprocess.CompletedProcess([],code,out,err)) as run:
                value=diagnostic.diagnose_remote(spec)
            run.assert_called_once();self.assertEqual(category,value['category'])
            self.assertEqual(code,value['returnCode']);self.assertEqual(diagnostic.captured(err),value['stderr'])
            self.assertFalse(value['mutationPerformed']);self.assertFalse(value['observerRetried'])

    def test_config_drift_and_unsupported_directives_block(self):
        spec={'configFile':'/private/config','controlPath':'/private/r-123456789abcdef/m','remoteHostAlias':'target'}
        with mock.patch.object(diagnostic,'file_pin',return_value={'unsupportedConfigDirectives':True}),mock.patch.object(diagnostic.subprocess,'run') as run,self.assertRaisesRegex(ValueError,'config_dependency_unsupported'):
            diagnostic.diagnose_remote(spec)
        run.assert_not_called()
        with mock.patch.object(diagnostic,'file_pin',side_effect=({'unsupportedConfigDirectives':False,'pin':1},{'unsupportedConfigDirectives':False,'pin':2})),mock.patch.object(diagnostic.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'options',WARNING)),self.assertRaisesRegex(ValueError,'route_config_changed'):
            diagnostic.diagnose_remote(spec)

    def test_full_capture_bounds_and_warning_exactness(self):
        spec={'configFile':'/private/config','controlPath':'/private/r-123456789abcdef/m','remoteHostAlias':'target'}
        for out,err in ((b'x'*65537,b''),(b'options',b'x'*8193)):
            with mock.patch.object(diagnostic,'file_pin',return_value={'unsupportedConfigDirectives':False}),mock.patch.object(diagnostic.subprocess,'run',return_value=subprocess.CompletedProcess([],0,out,err)),self.assertRaisesRegex(ValueError,'capture_unbounded'):
                diagnostic.diagnose_remote(spec)
        with mock.patch.object(diagnostic,'file_pin',return_value={'unsupportedConfigDirectives':False}),mock.patch.object(diagnostic.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'options',WARNING+b'other warning')):
            self.assertEqual('stderr-present',diagnostic.diagnose_remote(spec)['category'])

    def test_source_closed_carrier_preserves_frozen_observer_and_has_no_tty_fix(self):
        from pathlib import Path
        self.assertEqual(diagnostic.FROZEN_SHA,hashlib.sha256(Path(frozen.__file__).read_bytes()).hexdigest())
        source=diagnostic.remote_source();compile(source,'diagnostic','exec')
        self.assertIn('def diagnose_remote',source);self.assertIn("'-G'",source)
        for forbidden in ("'-T'",'os.kill','os.unlink','os.rename','recover(', 'observe_remote(', 'effective_route('):self.assertNotIn(forbidden,source)
