from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


transport = load("ssh_transport")
recovery = load("ssh_connection_recovery")


class SshConnectionRecoveryTest(unittest.TestCase):
    def config(self):
        gateway = transport.SshHost("gateway", "gateway.example", 2228, "tester", Path("/tmp/gateway-key"), Path("/tmp/gateway-known"))
        nested = transport.SshHost("archlinux", "unused", 22, "unused", Path("/tmp/unused"), transport.PurePosixPath("/remote/known"),
                                  transport="nested", gateway="gateway", remote_host_alias="archlinux",
                                  remote_control_path=transport.PurePosixPath("/remote/configured.sock"), password="nested-passphrase-value")
        return transport.SshConfig(Path.cwd(), {"gateway": gateway, "archlinux": nested})

    def materialize_inventory(self, directory, config):
        # Recovery successor admission now keeps the real private file open.
        # These mocked transport fixtures must include the corresponding file.
        hosts = {}
        for alias, host in config.hosts.items():
            value = {"host":host.host,"port":host.port,"user":host.user,
                     "identityFile":str(host.identity_file),"knownHostsFile":str(host.known_hosts_file)}
            for field, attribute in (("transport","transport"),("gateway","gateway"),
                    ("remoteHostAlias","remote_host_alias"),("remoteControlPath","remote_control_path"),
                    ("remoteConfigFile","remote_config_file"),("password","password")):
                item = getattr(host, attribute)
                if item is not None: value[field] = str(item)
            hosts[alias] = value
        path = Path(directory) / transport.CONFIG_FILENAME
        path.write_text(json.dumps({"schemaVersion":1,"hosts":hosts})); path.chmod(0o600)

    @unittest.skipUnless(os.name == 'posix', 'real harmless child parser proof')
    def test_readonly_configured_master_diagnostic_real_child_states(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.materialize_inventory(root,self.config())
            for expected,text,code in (('ready','Master running (pid=123)',0),
                  ('unknown','Control socket connect(/remote/configured.sock): Connection refused',255),
                  ('absent','Control socket connect(/remote/configured.sock): No such file or directory',255)):
                child=root/('check-'+expected)
                child.write_text('#!/bin/sh\nprintf "%s\\n" '+repr(text)+' >&2\nexit '+str(code)+'\n');child.chmod(0o700)
                calls=[]
                def run(config,target,command,timeout,**kw):
                    self.assertEqual(('ssh','-S','/remote/configured.sock','-O','check','archlinux'),command)
                    self.assertFalse(kw);calls.append(command)
                    return subprocess.run([str(child)],capture_output=True,text=True,timeout=timeout,check=False)
                with mock.patch.object(recovery,'_gateway_run',side_effect=run),mock.patch.object(recovery,'recover',side_effect=AssertionError('mutation')):
                    result=recovery.configured_master_status(root,'archlinux',3)
                self.assertEqual(result,{'nestedState':expected,'replayAllowed':False,'launchAllowed':False,'nativeActionAllowed':False})
                self.assertEqual(1,len(calls))

    def test_adopted_ready_master_can_recover_after_expiry_without_replacing_history(self):
        config = self.config()
        old = config.hosts["archlinux"]
        adopted = replace(old, remote_control_path=transport.PurePosixPath("/remote/recovered/m"))
        config = replace(config, hosts={**config.hosts, "archlinux": adopted})
        with tempfile.TemporaryDirectory() as directory:
            legacy = Path(directory) / ".rag_index/ssh-recovery/archlinux.json"
            legacy.parent.mkdir(parents=True)
            history = recovery._intent_value("archlinux", old, "previous", "ready", str(adopted.remote_control_path))
            legacy.write_text(json.dumps(history))
            def response(*args, **kwargs):
                return mock.Mock(stdout=json.dumps({"state": "ready", "control_path": args[2][-1]}))
            with mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(recovery, "_socket_state", return_value="absent"), \
                    mock.patch.object(recovery, "_gateway_run", side_effect=response) as run:
                self.materialize_inventory(directory, recovery.ssh_transport.load_config(directory))
                result = recovery.recover(directory, "archlinux")
            self.assertEqual({"ok": True, "state": "recovery_master_ready"}, result)
            self.assertEqual(history, json.loads(legacy.read_text()))
            self.assertEqual(1, run.call_count)
            with mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(recovery, "_socket_state", side_effect=("absent", "unknown")), \
                    mock.patch.object(recovery, "_gateway_run") as replay:
                self.assertEqual("recovery_intent_pending", recovery.recover(directory, "archlinux")["state"])
                replay.assert_not_called()

    def test_unknown_or_foreign_legacy_recovery_cannot_be_bypassed(self):
        old = self.config().hosts["archlinux"]
        adopted = replace(old, remote_control_path=transport.PurePosixPath("/remote/adopted/m"))
        for state, gateway in (("pending", old.gateway), ("ready", "other-gateway")):
            with self.subTest(state=state, gateway=gateway), tempfile.TemporaryDirectory() as directory:
                legacy = Path(directory) / ".rag_index/ssh-recovery/archlinux.json"
                legacy.parent.mkdir(parents=True)
                history = recovery._intent_value("archlinux", old, "previous", state, str(adopted.remote_control_path))
                history["gateway"] = gateway
                legacy.write_text(json.dumps(history))
                with self.assertRaises(recovery.RecoveryError):
                    recovery._read_intent(Path(directory), "archlinux", adopted)

    def test_changed_socket_or_config_cannot_bypass_unknown_hashed_recovery(self):
        initial = self.config()
        old = initial.hosts["archlinux"]
        recovered_path = recovery._recovery_socket_path(old, "0" * 32)[1]
        targets = (
            replace(old, remote_control_path=recovered_path),
            replace(old, remote_config_file=transport.PurePosixPath("/fixture/new-config")),
        )
        for target in targets:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                recovery._create_intent(Path(directory), "archlinux", old, "previous", str(recovered_path))
                history_path = recovery._intent_path(Path(directory), "archlinux", old)
                history = history_path.read_bytes()
                config = replace(initial, hosts={**initial.hosts, "archlinux": target})
                with mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                        mock.patch.object(recovery, "_socket_state", return_value="absent"), \
                        mock.patch.object(recovery, "_gateway_run") as run:
                    self.materialize_inventory(directory, recovery.ssh_transport.load_config(directory))
                    result = recovery.recover(directory, "archlinux")
                self.assertEqual({"ok": False, "state": "recovery_unavailable"}, result)
                run.assert_not_called()
                self.assertEqual(history, history_path.read_bytes())
                self.assertFalse(recovery._intent_path(Path(directory), "archlinux", target).exists())

    def test_ready_configured_master_does_not_create_or_write_intent(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", return_value="ready") as check, \
                mock.patch.object(recovery, "_gateway_run") as run:
            self.materialize_inventory(directory, recovery.ssh_transport.load_config(directory))
            result = recovery.recover(directory, "archlinux")
        self.assertEqual({"ok": True, "state": "configured_master_ready"}, result)
        check.assert_called_once()
        run.assert_not_called()

    def test_unknown_configured_socket_never_launches_recovery(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", return_value="unknown"), \
                mock.patch.object(recovery, "_gateway_run") as run:
            self.materialize_inventory(directory, recovery.ssh_transport.load_config(directory))
            result = recovery.recover(directory, "archlinux")
        self.assertEqual({"ok": False, "state": "configured_master_unknown"}, result)
        run.assert_not_called()

    def test_socket_observation_uses_the_configured_remote_config(self):
        config = self.config()
        target = replace(config.hosts["archlinux"], remote_config_file=transport.PurePosixPath("/fixture/private-config"))
        with mock.patch.object(recovery, "_gateway_run", return_value=mock.Mock(returncode=0)) as run:
            self.assertEqual("ready", recovery._socket_state(config, target, target.remote_control_path, 5))
        self.assertEqual(("ssh", "-F", "/fixture/private-config", "-S", "/remote/configured.sock", "-O", "check", "archlinux"),
                         run.call_args.args[2])

    def test_recovery_intent_binds_the_remote_config_file(self):
        target = self.config().hosts["archlinux"]
        other = replace(target, remote_config_file=transport.PurePosixPath("/fixture/private-config"))
        self.assertNotEqual(recovery._intent_path(Path("/repo"), "archlinux", target),
                            recovery._intent_path(Path("/repo"), "archlinux", other))

    def test_pending_intent_prevents_second_master_launch(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", side_effect=("absent", "unknown")), \
                mock.patch.object(recovery, "_gateway_run") as run:
            recovery._create_intent(Path(directory), "archlinux", self.config().hosts["archlinux"], "correlation", "/remote/new.sock")
            self.materialize_inventory(directory, recovery.ssh_transport.load_config(directory))
            result = recovery.recover(directory, "archlinux")
        self.assertEqual({"ok": False, "state": "recovery_intent_pending"}, result)
        run.assert_not_called()

    def test_observed_master_readiness_resolves_intent_without_resubmitting(self):
        target = self.config().hosts["archlinux"]
        with tempfile.TemporaryDirectory() as directory:
            recovery._create_intent(Path(directory), "archlinux", target, "correlation", "/remote/new.sock")
            with mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                    mock.patch.object(recovery, "_socket_state", side_effect=("absent", "ready")), \
                    mock.patch.object(recovery, "_gateway_run") as run:
                self.materialize_inventory(directory, recovery.ssh_transport.load_config(directory))
                result = recovery.recover(directory, "archlinux")
            intent = recovery._read_intent(Path(directory), "archlinux", target)
        self.assertEqual({"ok": True, "state": "recovery_master_ready"}, result)
        self.assertEqual("ready", intent["state"])
        self.assertEqual("correlation", intent["correlationId"])
        run.assert_not_called()

    def test_absent_socket_records_intent_before_secret_stdin_request(self):
        completed = mock.Mock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", return_value="absent"), \
                mock.patch.object(recovery, "_gateway_run", return_value=completed) as run:
            expected_parent = "/remote/r-"
            def response(*args, **kwargs):
                command = args[2]
                control_path = command[-1]
                return mock.Mock(returncode=0, stdout=json.dumps({"state": "ready", "control_path": control_path}), stderr="")
            run.side_effect = response
            self.materialize_inventory(directory, recovery.ssh_transport.load_config(directory))
            result = recovery.recover(directory, "archlinux")
            intent = recovery._read_intent(Path(directory), "archlinux", self.config().hosts["archlinux"])
        self.assertEqual({"ok": True, "state": "recovery_master_ready"}, result)
        self.assertEqual("ready", intent["state"])
        self.assertTrue(intent["controlPath"].startswith(expected_parent))
        secret = json.loads(run.call_args.kwargs["input_text"])["passphrase"]
        self.assertEqual("nested-passphrase-value", secret)
        self.assertNotIn(secret, " ".join(run.call_args.args[2]))
        self.assertIn("StrictHostKeyChecking=yes", recovery._REMOTE_RECOVERY_SCRIPT)

    def test_response_loss_keeps_deterministic_path_for_readonly_retry(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(recovery.ssh_transport, "load_config", return_value=self.config()), \
                mock.patch.object(recovery, "_socket_state", return_value="absent"), \
                mock.patch.object(recovery, "_gateway_run", return_value=None):
            self.materialize_inventory(directory, recovery.ssh_transport.load_config(directory))
            result = recovery.recover(directory, "archlinux")
            intent = recovery._read_intent(Path(directory), "archlinux", self.config().hosts["archlinux"])
        self.assertEqual({"ok": False, "state": "recovery_intent_pending"}, result)
        self.assertTrue(intent["controlPath"].startswith("/remote/r-"))
        self.assertTrue(intent["controlPath"].endswith("/m"))

    def test_configured_like_long_socket_parent_is_rejected_before_intent(self):
        base = self.config().hosts["archlinux"]
        target = transport.SshHost(base.alias, base.host, base.port, base.user, base.identity_file,
                                   base.known_hosts_file, transport=base.transport, gateway=base.gateway,
                                   remote_host_alias=base.remote_host_alias,
                                   remote_control_path=transport.PurePosixPath("/" + "a" * 80 + "/configured.sock"),
                                   password=base.password)
        self.assertIsNone(recovery._recovery_socket_path(target, "1234567890abcdef1234567890abcdef"))

    def test_67_byte_configured_socket_allows_bounded_recovery_master(self):
        config = self.config()
        base = config.hosts["archlinux"]
        target = replace(base, remote_control_path=transport.PurePosixPath("/" + "a" * 64 + "/m"))
        config = replace(config, hosts={**config.hosts, "archlinux": target})
        self.assertEqual(67, len(str(target.remote_control_path).encode("utf-8")))
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                mock.patch.object(recovery, "_socket_state", return_value="absent"), \
                mock.patch.object(recovery, "_gateway_run") as run:
            run.side_effect = lambda *args, **kwargs: mock.Mock(
                stdout=json.dumps({"state": "ready", "control_path": args[2][-1]}))
            self.materialize_inventory(directory, recovery.ssh_transport.load_config(directory))
            result = recovery.recover(directory, "archlinux")
            intent = recovery._read_intent(Path(directory), "archlinux", target)
        self.assertEqual({"ok": True, "state": "recovery_master_ready"}, result)
        self.assertEqual("ready", intent["state"])
        self.assertLessEqual(len(intent["controlPath"].encode("utf-8")), recovery._MAX_REMOTE_SOCKET_BYTES)
        run.assert_called_once()

    def test_adopted_bounded_recovery_uses_a_sibling_without_replaying_a_mutation(self):
        initial = self.config()
        original = replace(initial.hosts["archlinux"], remote_control_path=transport.PurePosixPath("/" + "a" * 64 + "/m"))
        first_path = recovery._recovery_socket_path(original, "0" * 32)[1]
        adopted = replace(original, remote_control_path=first_path)
        config = replace(initial, hosts={**initial.hosts, "archlinux": adopted})
        old_history = recovery._intent_value("archlinux", original, "old-correlation", "ready", str(first_path))
        expected_path = original.remote_control_path.parent / f"r-{'1' * recovery._RECOVERY_CORRELATION_CHARS}" / "m"
        with tempfile.TemporaryDirectory() as directory:
            old_path = recovery._intent_path(Path(directory), "archlinux", original)
            old_path.parent.mkdir(parents=True)
            old_path.write_text(json.dumps(old_history))
            with mock.patch.object(recovery.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(recovery, "uuid4", return_value=mock.Mock(hex="1" * 32)), \
                    mock.patch.object(recovery, "_socket_state", side_effect=("absent", "absent", "unknown")), \
                    mock.patch.object(recovery, "_gateway_run") as run:
                run.side_effect = lambda *args, **kwargs: mock.Mock(
                    stdout=json.dumps({"state": "ready", "control_path": args[2][-1]}))
                self.materialize_inventory(directory, recovery.ssh_transport.load_config(directory))
                first = recovery.recover(directory, "archlinux")
                second = recovery.recover(directory, "archlinux")
            current_intent = recovery._read_intent(Path(directory), "archlinux", adopted)
            stored_history = json.loads(old_path.read_text())
        self.assertEqual({"ok": True, "state": "recovery_master_ready"}, first)
        self.assertEqual({"ok": False, "state": "recovery_intent_pending"}, second)
        self.assertEqual(old_history, stored_history)
        self.assertEqual(str(expected_path), current_intent["controlPath"])
        self.assertLessEqual(len(current_intent["controlPath"].encode("utf-8")), recovery._MAX_REMOTE_SOCKET_BYTES)
        run.assert_called_once()

    def test_real_transport_accepts_encoded_remote_recovery_command(self):
        target = self.config().hosts["archlinux"]
        command = recovery._remote_command(target, 30, transport.PurePosixPath("/remote/r-1234567890abcdef"),
                                           "/remote/r-1234567890abcdef/m")
        argv = transport.build_ssh_argv(self.config(), "gateway", 30, command=command)
        self.assertNotIn("\n", command[2])
        self.assertIn("exec(", command[2])
        self.assertEqual("gateway.example", argv[-2])

    def test_exclusive_intent_rejects_a_duplicate_creator(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.config().hosts["archlinux"]
            recovery._create_intent(Path(directory), "archlinux", target, "first", "/remote/first.sock")
            with self.assertRaises(FileExistsError):
                recovery._create_intent(Path(directory), "archlinux", target, "second", "/remote/second.sock")

    def test_gateway_capture_retains_a_fixed_maximum(self):
        with tempfile.TemporaryDirectory() as directory:
            writer = Path(directory) / "writer"
            writer.write_text("#!/bin/sh\nhead -c 20000 /dev/zero | tr '\\000' x >&2\n", encoding="utf-8")
            writer.chmod(0o700)
            completed = recovery._bounded_run([str(writer)], 2)
        self.assertEqual(0, completed.returncode)
        self.assertEqual(recovery._MAX_CAPTURE_CHARS, len(completed.stderr))

    def test_remote_helper_uses_askpass_stdin_and_resolved_known_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh = root / "ssh"
            evidence = root / "evidence"
            ssh.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"-G\" ]; then printf '%s\\n' 'userknownhostsfile /fixture/known'; exit 0; fi\n"
                "if [ \"$1\" = \"-M\" ]; then \"$SSH_ASKPASS\" > \"$SSH_TEST_EVIDENCE\"; printf '%s\\n' \"$*\" >> \"$SSH_TEST_EVIDENCE\"; exit 0; fi\n"
                "if [ \"$3\" = \"-O\" ]; then exit 0; fi\n"
                "exit 1\n", encoding="utf-8")
            ssh.chmod(0o700)
            control_directory = root / "remote-control"
            control_path = control_directory / "master.sock"
            environment = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "SSH_TEST_EVIDENCE": str(evidence)}
            completed = subprocess.run(
                ["python3", "-c", recovery._REMOTE_RECOVERY_SCRIPT, "", "archlinux", "5",
                 str(control_directory), str(control_path)],
                input=json.dumps({"passphrase": "test-only-secret"}), text=True, capture_output=True, check=False, env=environment)
            self.assertEqual(0, completed.returncode)
            self.assertEqual({"state": "ready", "control_path": str(control_path)}, json.loads(completed.stdout))
            captured = evidence.read_text(encoding="utf-8")
            self.assertIn("test-only-secret", captured)
            self.assertEqual(1, captured.count("test-only-secret"))
            self.assertIn("UserKnownHostsFile=/fixture/known", captured)
            self.assertIn("BatchMode=no", captured)
            self.assertIn("ConnectTimeout=5", captured)

    def test_remote_helper_resolves_and_creates_only_the_private_config_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh = root / "ssh"
            evidence = root / "evidence"
            ssh.write_text(
                "#!/bin/sh\n"
                "test \"$1\" = '-F' && test \"$2\" = '/fixture/private config' || exit 19\n"
                "shift 2\n"
                "printf '%s\\n' \"$*\" >> \"$SSH_TEST_EVIDENCE\"\n"
                "if [ \"$1\" = '-G' ]; then printf '%s\\n' 'userknownhostsfile /fixture/known'; exit 0; fi\n"
                "if [ \"$1\" = '-M' ]; then exit 0; fi\n"
                "if [ \"$3\" = '-O' ]; then exit 0; fi\n"
                "exit 1\n", encoding="utf-8")
            ssh.chmod(0o700)
            target = replace(self.config().hosts["archlinux"],
                             remote_config_file=transport.PurePosixPath("/fixture/private config"))
            control_directory = root / "remote-control"
            control_path = str(control_directory / "master.sock")
            command = recovery._remote_command(target, 5, control_directory, control_path)
            environment = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "SSH_TEST_EVIDENCE": str(evidence)}
            completed = subprocess.run(command, input=json.dumps({"passphrase": "test-only-secret"}),
                                       text=True, capture_output=True, check=False, env=environment)
            self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            self.assertEqual({"state": "ready", "control_path": control_path}, json.loads(completed.stdout))
            self.assertEqual(3, len(evidence.read_text(encoding="utf-8").splitlines()))




@unittest.skipUnless(os.name=='posix','real binary pipes and managed private session fixtures')
class FencedConfiguredSocketTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests import test_ssh_connection_session as fixture
        self.fixture=fixture.SessionTests(methodName='runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.ready=self.fixture.ready();self.raw={};self.calls=[]
        self.stdout=b'';self.stderr=b'Master running (pid=123)\n';self.code=0
        self.real_popen=subprocess.Popen
        self.child=self.root/'read-child.py';self.child.write_text('import sys,json;v=json.loads(sys.argv[1]);sys.stdout.buffer.write(bytes.fromhex(v[0]));sys.stderr.buffer.write(bytes.fromhex(v[1]));sys.exit(v[2])')
    def child_consumer(self,argv,**kw):
        self.assertEqual(['-F','/dev/null'],argv[1:3]);self.assertIn('ProxyCommand=false',argv)
        self.assertIn('ControlMaster=no',argv);self.assertIn('ControlPersist=no',argv)
        self.calls.append(argv)
        return self.real_popen([sys.executable,'-I','-B',str(self.child),json.dumps([self.stdout.hex(),self.stderr.hex(),self.code])],**kw)
    def invoke(self,timeout=10):
        self.raw.clear()
        with mock.patch.object(recovery.subprocess,'Popen',side_effect=self.child_consumer):
            return recovery.configured_master_fenced_status(self.root,'archlinux',timeout,_private_capture=self.raw.update)
    def test_dynamic_current_receipt_real_guard_and_binary_child(self):
        self.assertEqual('ready',self.invoke()['nestedState']);self.assertTrue(self.raw['complete'])
        self.assertEqual(self.ready['receiptSha256'],self.raw['outerReceiptSha256'])
        self.assertEqual(1,len(self.fixture.spawns),'observer never prepares newmaster')
        self.assertEqual(1,len(self.calls))
    def test_foreign_ready_receipt_refused_by_actual_managed_guard(self):
        from agent_tools import ssh_connection_session as session
        with self.assertRaises(session.SessionUnknown):
            session.reuse_only_options(self.root,'archlinux','0'*64)
        self.assertEqual('ready',self.invoke()['nestedState'])

    def test_ready_or_master_drift_never_submits_or_claims_ready(self):
        from agent_tools import ssh_connection_session as session
        self.fixture.master_patch.stop()
        with mock.patch.object(session,'_master',side_effect=session.SessionUnknown('master')),mock.patch.object(recovery.subprocess,'Popen',side_effect=AssertionError('query')):
            self.assertEqual('unknown',recovery.configured_master_fenced_status(self.root,'archlinux')['nestedState'])
        self.fixture.master_patch.start()
        real_verify=session.verify_reuse;count=0
        def changed(*args):
            nonlocal count
            count+=1
            if count==2:
                path=self.fixture.journal()/'ready.json';data=path.read_bytes();path.write_bytes(data);path.chmod(0o600)
            return real_verify(*args)
        with mock.patch.object(session,'verify_reuse',side_effect=changed):
            self.assertEqual('unknown',self.invoke()['nestedState'])


    def test_exact_refusal_is_finite_cause_without_absence_authority(self):
        from agent_tools import ssh_transport
        path=str(ssh_transport.load_config(self.root).hosts['archlinux'].remote_control_path)
        self.stdout=b'';self.stderr=('Control socket connect('+path+'): Connection refused\n').encode();self.code=255
        result=self.invoke()
        self.assertEqual('refused',result['socketState']);self.assertEqual('unknown',result['nestedState'])
        self.assertFalse(result['nativeActionAllowed']);self.assertNotIn(path,json.dumps(result))
        for raw,code,stdout in ((self.stderr+b'extra',255,b''),(self.stderr,0,b''),(self.stderr,255,b'x'),
                                (self.stderr.replace(path.encode(),b'/foreign'),255,b'')):
            self.stderr=raw;self.code=code;self.stdout=stdout
            self.assertEqual('unknown',self.invoke()['socketState'])

    def test_invalid_stdout_offsets_and_stderr_bytes_are_preserved_and_refused(self):
        for raw in (b'\xff',b'x\xff',b'\xffx',b'x'*1023+b'\xff',b'x'*1024+b'\xff',b'x'*4095+b'\xff',b'x'*4096+b'\xff'):
            self.stdout=raw
            with self.subTest(offset=len(raw)-1):
                self.assertEqual('unknown',self.invoke()['nestedState'])
                self.assertEqual(raw[:recovery._SOCKET_CAPTURE_BYTES+1],self.raw['stdout'])
        self.stdout=b'';good=b'Master running (pid=123)\n'
        for raw in (b'\xff'+good,good[:7]+b'\xff'+good[7:],good+b'\xff',good[:-1]):
            self.stderr=raw
            self.assertEqual('unknown',self.invoke()['nestedState']);self.assertEqual(raw,self.raw['stderr'])

    def test_absence_is_exact_and_wrong_returncode_or_stdout_unknown(self):
        self.stderr=b'Control socket connect(/private/inert-master): No such file or directory\n';self.code=255
        self.assertEqual('absent',self.invoke()['nestedState'])
        self.stderr=b'Control socket connect(/foreign): No such file or directory\n'
        self.assertEqual('unknown',self.invoke()['nestedState'])
        self.stderr=b'Master running (pid=123)\n';self.code=255
        self.assertEqual('unknown',self.invoke()['nestedState'])
        self.code=0;self.stdout=b'foreign'
        self.assertEqual('unknown',self.invoke()['nestedState'])

    def test_byte_overflow_counts_and_hash_scope_remain_unknown(self):
        self.stdout=b'x'*(recovery._SOCKET_CAPTURE_BYTES+5)
        self.assertEqual('unknown',self.invoke()['nestedState'])
        self.assertTrue(self.raw['overflow']);self.assertEqual('retained-prefix',self.raw['hashScope']['stdout'])
        self.assertEqual(recovery._SOCKET_CAPTURE_BYTES+1,self.raw['capturedBytes']['stdout'])
        self.assertEqual(recovery._SOCKET_CAPTURE_BYTES+5,self.raw['counts']['stdout'])

    def test_real_no_eof_or_nonterminal_child_times_out(self):
        self.child.write_text('import sys,subprocess;sys.stderr.buffer.write(b"Master running (pid=123)\\n");sys.stderr.flush();subprocess.Popen([sys.executable,"-c","import time;time.sleep(1.3)"]);sys.exit(0)')
        self.assertEqual('unknown',self.invoke(timeout=1)['nestedState']);self.assertTrue(self.raw['timeout']);self.assertFalse(all(self.raw['eof'].values()))
        self.child.write_text('import sys,time;sys.stderr.buffer.write(b"Master running (pid=123)\\n");sys.stderr.flush();time.sleep(1.3)')
        self.assertEqual('unknown',self.invoke(timeout=1)['nestedState']);self.assertTrue(self.raw['timeout']);self.assertFalse(self.raw['complete'])

    def test_actual_collect_pipe_read_fault_is_unknown(self):
        original=os.read
        def fault(fd,size):
            if sys._getframe(1).f_code is recovery._bounded_socket_query.__code__:raise OSError('inert read fault')
            return original(fd,size)
        with mock.patch.object(recovery.os,'read',new=fault):
            self.assertEqual('unknown',self.invoke()['nestedState'])
        self.assertTrue(self.raw['readError']);self.assertFalse(self.raw['complete'])

    def test_capture_retention_failure_refuses_ready(self):
        def fail_capture(capture):raise OSError('private-sensitive-sentinel')
        with mock.patch.object(recovery.subprocess,'Popen',side_effect=self.child_consumer):
            value=recovery.configured_master_fenced_status(self.root,'archlinux',_private_capture=fail_capture)
        self.assertEqual('unknown',value['nestedState']);self.assertEqual('capture_retention',value['failurePhase']);self.assertNotIn('sentinel',json.dumps(value))

    def test_bad_parameters_and_missing_ready_fence_never_query(self):
        with mock.patch.object(recovery,'_bounded_socket_query',side_effect=AssertionError('query')):
            for host,timeout in (('foreign',10),('archlinux',True),('archlinux',0),('archlinux',61)):
                self.assertEqual('unknown',recovery.configured_master_fenced_status(self.root,host,timeout)['nestedState'])
            (self.fixture.journal()/'ready.json').unlink()
            self.assertEqual('unknown',recovery.configured_master_fenced_status(self.root,'archlinux')['nestedState'])


if __name__ == "__main__":
    unittest.main()
