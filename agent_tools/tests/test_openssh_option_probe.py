"""Real owned children cover local-parser timeout recovery; no SSH connections.

The argv-to-Python launcher and 0.3-second clock ceiling are explicit local
seams. subprocess.run's actual timeout, kill, wait and partial pipes are intact.
The frozen original method comes from full source ceaf51213e2847246ba5fbd718fd
eff448494c01398413a236744e96aee4aca6; its fragment hash is recorded below.
"""
import base64
from contextlib import contextmanager, redirect_stderr
import hashlib
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

from agent_tools import openssh_option_probe as probe


ORIGINAL_SESSION_METHOD = """def test_actual_openssh_launch_is_noninteractive_master_not_ask(self):
        config,outer,_=s._snapshot(self.root,'archlinux')
        launch=s._launch_argv(config,outer,Path('/tmp/inert-no-connect/m'))
        # -G prints effective options and exits before any network operation.
        observed=subprocess.run([*launch[:-1],'-G',launch[-1]],stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
        self.assertEqual(observed.returncode,0)
        options=dict(line.split(' ',1) for line in observed.stdout.decode().splitlines() if ' ' in line)
        self.assertEqual(options.get('controlmaster'),'true')"""
ORIGINAL_METHOD_SHA256 = 'f3f3ac7bffd933d8d017e4f1f60b522cdd02a4ed3282198d41681843b6930444'
ORIGINAL_TWO_HOP_METHOD = '''def test_actual_openssh_parser_and_two_hop_option_precedence(self):
        import subprocess,shlex
        ssh=__import__('shutil').which('ssh')
        if ssh is None:self.skipTest('local OpenSSH option parser unavailable')
        inner=['ssh','-F','/dev/null','-S','/tmp/owned-inner','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/tmp/public-known-hosts','archlinux','python3 -c "print(7)"']
        argv=['ssh','-F','/dev/null','-S','/tmp/owned-outer','-o','ControlMaster=no','-o','ProxyCommand=false','gateway',shlex.join(inner)]
        bypass=stage.direct_nested_ssh_argv(argv,'/tmp/owned-outer','/tmp/owned-inner','gateway','archlinux')
        actual_inner=shlex.split(bypass[-1]);self.assertEqual(actual_inner[-1],inner[-1]);self.assertEqual(bypass[-2],argv[-2])
        for command in [bypass[:-1],actual_inner[:-1]]:
            result=subprocess.run([ssh,'-G',*command[1:]],capture_output=True,check=True,timeout=5)
            values=dict(line.split(' ',1)for line in result.stdout.decode().splitlines()if ' 'in line)
            self.assertIn(values.get('controlpath'),(None,'none'));self.assertEqual(values['controlmaster'],'false')
        self.assertIn('StrictHostKeyChecking=yes',actual_inner);self.assertIn('UserKnownHostsFile=/tmp/public-known-hosts',actual_inner)
        self.assertEqual(argv[argv.index('-S')+1],'/tmp/owned-outer')
        with self.assertRaises(ValueError):stage.direct_nested_ssh_argv(argv,'/foreign','/tmp/owned-inner','gateway','archlinux')'''
# Full two-hop beforeimage: b85a2a73301683bbe124722e340127686d158f987beb3af84abfd3a00c82f136.
ORIGINAL_TWO_HOP_SHA256 = '2909e23223866659c9ecaeae19fe05cd91dc7cb96b71a39497a0e5a6f02a8ac2'
QUERY = [str(Path('/usr/bin/ssh').absolute()), '-G', '-F', '/dev/null', '-S', 'none',
         '-o', 'ControlMaster=no', '-o', 'ProxyCommand=false', 'gateway']
# Binary writes keep fixture bytes invariant under Windows text translation.
SLOW = "import os,time;os.write(1,b'partial-out\\n');os.write(2,b'partial-err\\n');time.sleep(30)"
GOOD = "import os;os.write(1,b'controlmaster true\\n')"
NONZERO = "import os,sys;os.write(2,b'syntax-error\\n');sys.exit(7)"

# Authentic methods at the Directory Services failure checkpoint.
# Full beforeimage hashes: Session4921ffd2...; two-hopaeb12b7f....
SERVICE_ORIGINAL_SESSION_METHOD = "def test_actual_openssh_launch_is_noninteractive_master_not_ask(self):\n        from agent_tools.openssh_option_probe import run_option_probe\n        config,outer,_=s._snapshot(self.root,'archlinux')\n        launch=s._launch_argv(config,outer,Path('/tmp/inert-no-connect/m'))\n        # -G prints effective options and exits before any network operation.\n        observed=run_option_probe([*launch[:-1],'-G',launch[-1]])\n        self.assertEqual(observed.returncode,0)\n        options=dict(line.split(' ',1) for line in observed.stdout.decode().splitlines() if ' ' in line)\n        self.assertEqual(options.get('controlmaster'),'true')"
SERVICE_ORIGINAL_SESSION_SHA256 = 'e9f5b4578e7cb27cc566e30baa5e92fc334a5e1fa6e5694179c92992c7117f7b'
SERVICE_ORIGINAL_TWO_HOP_METHOD = 'def test_actual_openssh_parser_and_two_hop_option_precedence(self):\n        import shlex\n        from agent_tools.openssh_option_probe import run_option_probe\n        ssh=__import__(\'shutil\').which(\'ssh\')\n        if ssh is None:self.skipTest(\'local OpenSSH option parser unavailable\')\n        inner=[\'ssh\',\'-F\',\'/dev/null\',\'-S\',\'/tmp/owned-inner\',\'-o\',\'BatchMode=yes\',\'-o\',\'StrictHostKeyChecking=yes\',\'-o\',\'UserKnownHostsFile=/tmp/public-known-hosts\',\'archlinux\',\'python3 -c "print(7)"\']\n        argv=[\'ssh\',\'-F\',\'/dev/null\',\'-S\',\'/tmp/owned-outer\',\'-o\',\'ControlMaster=no\',\'-o\',\'ProxyCommand=false\',\'gateway\',shlex.join(inner)]\n        bypass=stage.direct_nested_ssh_argv(argv,\'/tmp/owned-outer\',\'/tmp/owned-inner\',\'gateway\',\'archlinux\')\n        actual_inner=shlex.split(bypass[-1]);self.assertEqual(actual_inner[-1],inner[-1]);self.assertEqual(bypass[-2],argv[-2])\n        for command in [bypass[:-1],actual_inner[:-1]]:\n            result=run_option_probe([ssh,\'-G\',*command[1:]])\n            values=dict(line.split(\' \',1)for line in result.stdout.decode().splitlines()if \' \'in line)\n            self.assertIn(values.get(\'controlpath\'),(None,\'none\'));self.assertEqual(values[\'controlmaster\'],\'false\')\n        self.assertIn(\'StrictHostKeyChecking=yes\',actual_inner);self.assertIn(\'UserKnownHostsFile=/tmp/public-known-hosts\',actual_inner)\n        self.assertEqual(argv[argv.index(\'-S\')+1],\'/tmp/owned-outer\')\n        with self.assertRaises(ValueError):stage.direct_nested_ssh_argv(argv,\'/foreign\',\'/tmp/owned-inner\',\'gateway\',\'archlinux\')'
SERVICE_ORIGINAL_TWO_HOP_SHA256 = '7a526f9261d14a8105301f79bc151f91ac46e4c687fb89fe22cf9cfc8a7a5e6c'
SERVICE_LOOKUP_BOUNDARY_CHILD = "import ipaddress,os,time\ntry:ipaddress.ip_address(command[-1]);numeric=True\nexcept ValueError:numeric=False\nport=int(command[command.index('-p')+1]) if '-p' in command else 0\nif not numeric or port<=0:time.sleep(30)\nvalues={command[i+1].split('=',1)[0]:command[i+1].split('=',1)[1] for i,x in enumerate(command[:-1]) if x=='-o'}\nmode='true' if values.get('ControlMaster')=='yes' else 'false'\nos.write(1,('controlmaster '+mode+'\\ncontrolpath none\\nport '+str(port)+'\\n').encode())\n"


class OptionProbeTests(unittest.TestCase):
    @contextmanager
    def children(self, bodies, *, short_deadline=True, same_query=True, windows_text_newlines=False, service_lookup_fault=False):
        real_run = subprocess.run
        real_popen = subprocess.Popen
        self.spawned = []
        self.commands = []
        self.requested_timeouts = []
        self.observed_timeouts = []
        self.timeout_log = io.StringIO()

        def spawn(argv, **kwargs):
            # The old child must be terminal before submitting any successor.
            self.assertTrue(all(child.returncode is not None for child in self.spawned))
            self.commands.append(tuple(argv))
            if same_query:
                self.assertEqual(self.commands[-1], self.commands[0])
            self.assertLess(len(self.spawned), len(bodies))
            body = bodies[len(self.spawned)]
            if service_lookup_fault:
                body = "command=" + repr(tuple(argv)) + "\n" + SERVICE_LOOKUP_BOUNDARY_CHILD
            if windows_text_newlines:
                body = ("import io,sys;"
                        "sys.stdout=io.TextIOWrapper(sys.stdout.buffer,newline='\\r\\n',write_through=True);"
                        "sys.stderr=io.TextIOWrapper(sys.stderr.buffer,newline='\\r\\n',write_through=True);" + body)
            child = real_popen([sys.executable, '-I', '-c', body], **kwargs)
            self.spawned.append(child)
            return child

        def run(argv, **kwargs):
            self.requested_timeouts.append(kwargs['timeout'])
            if short_deadline:
                kwargs['timeout'] = 0.3
            try:
                return real_run(argv, **kwargs)
            except subprocess.TimeoutExpired as error:
                self.observed_timeouts.append(error)
                raise

        try:
            with mock.patch.object(subprocess, 'Popen', side_effect=spawn), \
                    mock.patch.object(subprocess, 'run', side_effect=run), \
                    redirect_stderr(self.timeout_log):
                yield
        finally:
            for child in self.spawned:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=5)
            self.assertTrue(all(child.returncode is not None for child in self.spawned))

    def session_case(self):
        from agent_tools.tests.test_ssh_connection_session import SessionTests, s
        case = SessionTests('test_actual_openssh_launch_is_noninteractive_master_not_ask')
        case.setUp()
        self.addCleanup(case.doCleanups)
        return case, s

    @unittest.skipUnless(os.name == 'posix', 'original session fixture requires POSIX authority')
    def test_preserved_actual_original_method_fails_on_first_slow_parser(self):
        self.assertEqual(hashlib.sha256(ORIGINAL_SESSION_METHOD.encode()).hexdigest(), ORIGINAL_METHOD_SHA256)
        case, session = self.session_case()
        namespace = {'s': session, 'Path': Path, 'subprocess': subprocess}
        exec(compile(ORIGINAL_SESSION_METHOD, 'preserved original OpenSSH parser method', 'exec'), namespace)
        with self.children([SLOW, GOOD]), self.assertRaises(subprocess.TimeoutExpired) as caught:
            namespace['test_actual_openssh_launch_is_noninteractive_master_not_ask'](case)
        self.assertEqual(len(self.spawned), 1)
        self.assertEqual(self.requested_timeouts, [5])
        self.assertEqual(caught.exception.stdout, b'partial-out\n')
        self.assertEqual(caught.exception.stderr, b'partial-err\n')

    def test_preserved_actual_two_hop_method_fails_on_first_slow_parser(self):
        from agent_tools.tests.test_windows_tertiary_guest_stage import DirectSshCarrierTests, stage
        self.assertEqual(hashlib.sha256(ORIGINAL_TWO_HOP_METHOD.encode()).hexdigest(), ORIGINAL_TWO_HOP_SHA256)
        namespace = {'stage': stage}
        exec(compile(ORIGINAL_TWO_HOP_METHOD, 'preserved original two-hop OpenSSH parser method', 'exec'), namespace)
        case = DirectSshCarrierTests('test_actual_openssh_parser_and_two_hop_option_precedence')
        with self.children([SLOW, GOOD]), mock.patch.object(shutil, 'which', return_value=QUERY[0]), \
                self.assertRaises(subprocess.TimeoutExpired) as caught:
            namespace['test_actual_openssh_parser_and_two_hop_option_precedence'](case)
        self.assertEqual(self.commands, [tuple(QUERY)])
        self.assertEqual(self.requested_timeouts, [5])
        self.assertIs(caught.exception, self.observed_timeouts[0])
        self.assertEqual(caught.exception.stdout, b'partial-out\n')
        self.assertEqual(caught.exception.stderr, b'partial-err\n')

    def test_same_query_recovers_after_original_child_reaped_and_keeps_timeout_bytes(self):
        with self.children([SLOW, GOOD]):
            result = probe.run_option_probe(QUERY)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'controlmaster true\n')
        self.assertEqual(self.commands, [tuple(QUERY), tuple(QUERY)])
        self.assertEqual(self.requested_timeouts, [5, 5])
        self.assertEqual(len(result.timeout_attempts), 1)
        original = result.timeout_attempts[0]
        self.assertIs(original, self.observed_timeouts[0])
        self.assertEqual(original.cmd, self.spawned[0].args)
        self.assertEqual(original.stdout, b'partial-out\n')
        self.assertEqual(original.stderr, b'partial-err\n')
        record = json.loads(self.timeout_log.getvalue())
        self.assertEqual(record['querySha256'], hashlib.sha256(json.dumps(tuple(QUERY)).encode()).hexdigest())
        self.assertTrue(record['originalChildReaped'])
        self.assertEqual(record['cause'], 'unknown')
        self.assertEqual(base64.b64decode(record['stdoutBase64']), original.stdout)
        self.assertEqual(base64.b64decode(record['stderrBase64']), original.stderr)

    @unittest.skipUnless(os.name == 'posix', 'original session fixture requires POSIX authority')
    def test_integrated_session_method_recovers_without_losing_semantic_assertion(self):
        case, _ = self.session_case()
        with self.children([SLOW, GOOD + ";os.write(1,b'port 2228\\n')"]):
            case.test_actual_openssh_launch_is_noninteractive_master_not_ask()
        self.assertEqual(len(self.spawned), 2)

    def test_integrated_two_hop_parser_recovers_only_the_timed_out_query(self):
        from agent_tools.tests.test_windows_tertiary_guest_stage import DirectSshCarrierTests
        case = DirectSshCarrierTests('test_actual_openssh_parser_and_two_hop_option_precedence')
        body = "import os;os.write(1,b'controlmaster false\\ncontrolpath none\\nport 22\\n')"
        with self.children([SLOW, body, body], same_query=False), \
                mock.patch.object(shutil, 'which', return_value=QUERY[0]):
            case.test_actual_openssh_parser_and_two_hop_option_precedence()
        self.assertEqual(len(self.spawned), 3)
        self.assertEqual(self.commands[0], self.commands[1])
        self.assertEqual(self.commands[1][-1], '192.0.2.2')
        self.assertEqual(self.commands[2][-1], '192.0.2.1')

    def test_two_persistent_timeouts_fail_closed_with_both_original_observations(self):
        with self.children([SLOW, SLOW]), self.assertRaises(subprocess.TimeoutExpired) as caught:
            probe.run_option_probe(QUERY)
        self.assertEqual(len(self.spawned), 2)
        self.assertEqual(self.requested_timeouts, [5, 5])
        self.assertEqual(len(caught.exception.timeout_attempts), 2)
        self.assertTrue(all(error.stdout == b'partial-out\n' and error.stderr == b'partial-err\n'
                            for error in caught.exception.timeout_attempts))
        self.assertEqual(len(self.timeout_log.getvalue().splitlines()), 2)

    def test_nonzero_syntax_failure_is_not_retried(self):
        with self.children([NONZERO]), self.assertRaises(subprocess.CalledProcessError) as caught:
            probe.run_option_probe(QUERY)
        self.assertEqual(len(self.spawned), 1)
        self.assertEqual(caught.exception.returncode, 7)
        self.assertEqual(caught.exception.stderr, b'syntax-error\n')
        self.assertEqual(caught.exception.timeout_attempts, ())

    def test_nonzero_after_timeout_does_not_retry_or_lose_first_observation(self):
        with self.children([SLOW, NONZERO]), self.assertRaises(subprocess.CalledProcessError) as caught:
            probe.run_option_probe(QUERY)
        self.assertEqual(len(self.spawned), 2)
        self.assertEqual(caught.exception.returncode, 7)
        self.assertEqual(len(caught.exception.timeout_attempts), 1)

    @unittest.skipUnless(os.name == 'posix', 'original session fixture requires POSIX authority')
    def test_integrated_semantic_failure_is_not_retried(self):
        case, _ = self.session_case()
        with self.children(["print('controlmaster ask')"]), self.assertRaises(AssertionError):
            case.test_actual_openssh_launch_is_noninteractive_master_not_ask()
        self.assertEqual(len(self.spawned), 1)

    def test_production_deadline_remains_five_seconds_and_success_is_not_retried(self):
        with self.children([GOOD], short_deadline=False):
            result = probe.run_option_probe(QUERY)
        self.assertEqual(self.requested_timeouts, [5])
        self.assertEqual(result.timeout_attempts, ())

    def test_binary_fixtures_keep_exact_bytes_under_windows_text_newlines(self):
        with self.subTest(flow='timeout-then-success'):
            with self.children([SLOW, GOOD], windows_text_newlines=True):
                result = probe.run_option_probe(QUERY)
            original = result.timeout_attempts[0]
            self.assertIs(original, self.observed_timeouts[0])
            for stream, actual, expected in [
                    ('partial-stdout', original.stdout, b'partial-out\n'),
                    ('partial-stderr', original.stderr, b'partial-err\n'),
                    ('success-stdout', result.stdout, b'controlmaster true\n')]:
                with self.subTest(stream=stream):
                    self.assertEqual(actual, expected)
            record = json.loads(self.timeout_log.getvalue())
            self.assertEqual(base64.b64decode(record['stdoutBase64']), original.stdout)
            self.assertEqual(base64.b64decode(record['stderrBase64']), original.stderr)
        with self.subTest(flow='nonzero'):
            with self.children([NONZERO], windows_text_newlines=True), \
                    self.assertRaises(subprocess.CalledProcessError) as caught:
                probe.run_option_probe(QUERY)
            self.assertEqual(caught.exception.stderr, b'syntax-error\n')
            self.assertEqual(len(self.spawned), 1)

    @unittest.skipUnless(os.name == 'posix', 'real original session fixture requires POSIX')
    def test_actual_methods_bypass_measured_default_service_lookup_boundary(self):
        # The host OS RPC latency trigger is not reproduced. This explicit
        # launcher seam models the measured service dependency in a real child;
        # timeout/kill/wait/reap, original methods and constructors are actual.
        from agent_tools.tests.test_windows_tertiary_guest_stage import DirectSshCarrierTests, stage
        for name, old, digest in [
                ('session', SERVICE_ORIGINAL_SESSION_METHOD, SERVICE_ORIGINAL_SESSION_SHA256),
                ('two-hop', SERVICE_ORIGINAL_TWO_HOP_METHOD, SERVICE_ORIGINAL_TWO_HOP_SHA256)]:
            with self.subTest(flow=name):
                self.assertEqual(hashlib.sha256(old.encode()).hexdigest(), digest)
                case, session = self.session_case() if name == 'session' else (DirectSshCarrierTests(), None)
                namespace = {'s': session, 'Path': Path, 'stage': stage}
                exec(compile(old, 'authentic method before service-lookup fix', 'exec'), namespace)
                method_name = 'test_actual_openssh_launch_is_noninteractive_master_not_ask' if name == 'session' else 'test_actual_openssh_parser_and_two_hop_option_precedence'
                with self.children([GOOD, GOOD], same_query=False, service_lookup_fault=True), \
                        mock.patch.object(shutil, 'which', return_value=QUERY[0]), \
                        self.assertRaises(subprocess.TimeoutExpired) as caught:
                    namespace[method_name](case)
                self.assertEqual(len(self.spawned), 2)
                self.assertEqual(self.requested_timeouts, [5, 5])
                self.assertTrue(all(error.stdout in (None, b'') and error.stderr in (None, b'')
                                    for error in caught.exception.timeout_attempts))
                self.assertEqual(self.commands[0], self.commands[1])
                if name == 'session':self.assertEqual(self.commands[0][self.commands[0].index('-p') + 1], '2228')
                with self.children([GOOD, GOOD], same_query=False, service_lookup_fault=True), \
                        mock.patch.object(shutil, 'which', return_value=QUERY[0]):
                    getattr(case, method_name)()
                self.assertEqual(len(self.spawned), 1 if name == 'session' else 2)
                self.assertEqual(self.requested_timeouts, [5] if name == 'session' else [5, 5])
                expected_port = '2228' if name == 'session' else '22'
                self.assertTrue(all(command[command.index('-p') + 1] == expected_port for command in self.commands))

    def test_unsafe_queries_are_refused_before_any_child(self):
        unsafe = [
            ['ssh', *QUERY[1:]],
            [QUERY[0], '-F', '/dev/null', 'gateway'],
            [QUERY[0], '-F', '/dev/null', 'gateway', '-G'],
            [*QUERY, 'remote-payload'],
            [QUERY[0], '-G', '-F', '/tmp/config-with-match-exec', 'gateway'],
            [QUERY[0], '-G', '-F', '/dev/null', '-F', '/dev/null', 'gateway'],
            [QUERY[0], '-G', '-G', '-F', '/dev/null', 'gateway'],
            [QUERY[0], '-G', '-F', '/dev/null', '-O', 'check', 'gateway'],
            [QUERY[0], '-G', '-F', '/dev/null', '-J', 'jump', 'gateway'],
        ]
        for option in ['Include=/tmp/config', 'Match=exec false', 'KnownHostsCommand=false',
                       'LocalCommand=false', 'ProxyCommand=ssh foreign', 'CanonicalizeHostname=yes']:
            unsafe.append([QUERY[0], '-G', '-F', '/dev/null', '-o', option, 'gateway'])
        with mock.patch.object(subprocess, 'run', side_effect=AssertionError('unsafe child')) as run:
            for argv in unsafe:
                with self.subTest(argv=argv), self.assertRaises(ValueError):
                    probe.run_option_probe(argv)
            run.assert_not_called()
