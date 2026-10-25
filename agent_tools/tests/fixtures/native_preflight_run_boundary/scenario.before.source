"""End-to-end local SSH stand-in checks for the fixed preflight adapter."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "agent_tools"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SOURCE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


transport = load("ssh_transport")
bundle = load("native_scenario_bundle")
execution = load("native_scenario_execution")
ssh_driver = load("native_scenario_ssh")


class NativeScenarioSshTest(unittest.TestCase):
    def request(self):
        return {"scenarioId": "linux-public-update-preflight", "host": "fixture", "environment": "ownedguest",
                "bundleHash": self.bundle_info["manifestSha256"], "artifactIds": {"fixture": "sha256-" + "a" * 64}, "correlationId": "preflight-17"}

    def setUp(self):
        if os.name != "posix":
            self.skipTest("SSH stand-in and private journal tests require POSIX")
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.remote = self.work / "remote"; self.remote.mkdir(mode=0o700)
        self.bundle_info = bundle.prepare_bundle(ROOT, "linux-public-update-driver", self.work / "bundle")
        self.key = self.work / "key"; self.key.write_text("key", encoding="utf-8"); self.key.chmod(0o600)
        self.known = self.work / "known"; self.known.write_text("known", encoding="utf-8"); self.known.chmod(0o600)
        self.fake_ssh = self.work / "fake-ssh"
        self.log = self.work / "fake-ssh.log"
        self.fake_ssh.write_text("#!/bin/sh\nfor last; do :; done\n: \"${FAKE_SSH_LOG:?}\"\nif [ \"${DROP_RESPONSE:-}\" = 1 ]; then /bin/sh -c \"$last\" > \"$FAKE_SSH_LOG\" 2>&1; exit 255; fi\nexec /bin/sh -c \"$last\"\n", encoding="utf-8")
        self.fake_ssh.chmod(0o700)
        config = {"schemaVersion": 1, "hosts": {"fixture": {"host": "fixture", "port": 22, "user": "tester",
                  "identityFile": str(self.key), "knownHostsFile": str(self.known), "fixtureTransferRoot": str(self.remote)}}}
        path = self.work / ".vm-hosts.local.json"; path.write_text(json.dumps(config), encoding="utf-8"); path.chmod(0o600)

    def make(self):
        os.environ.setdefault("FAKE_SSH_LOG", str(self.log))
        return ssh_driver.NativeScenarioSshDriver(ROOT, lambda plan: self.bundle_info["directory"], ssh_binary=str(self.fake_ssh), configuration_root=self.work)

    def test_driver_uses_local_gateway_askpass_for_nested_guest(self):
        direct = transport.SshHost("gateway", "gateway.example", 2228, "owner", self.key, self.known,
                                   password="gateway-secret")
        arch = transport.SshHost("arch", "unused", 22, "unused", self.key,
                                 transport.PurePosixPath("/owned/known_hosts"), transport="nested",
                                 gateway="gateway", remote_host_alias="archlinux",
                                 remote_control_path=transport.PurePosixPath("/owned/master.sock"),
                                 password="wrong-intermediate-secret")
        guest = transport.SshHost("guest", "unused", 2328, "unused", self.key,
                                  transport.PurePosixPath("/owned/guest_known_hosts"), transport="nested",
                                  gateway="arch", remote_host_alias="fedora",
                                  remote_config_file=transport.PurePosixPath("/owned/scp-config"))
        config = transport.SshConfig(self.work, {"gateway": direct, "arch": arch, "guest": guest})
        with mock.patch.object(transport, "_askpass_environment", return_value=(self.work / "askpass", {})) as askpass, \
             mock.patch.object(ssh_driver.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=b'{"ok":true}')) as run:
            self.assertEqual({"ok": True}, self.make()._run(config, "guest", ("true",), None))
        self.assertEqual("gateway-secret", askpass.call_args.args[0])
        self.assertIn("archlinux", run.call_args.args[0][-1])
        self.assertIn("scp-config", run.call_args.args[0][-1])
        self.assertNotIn("gateway-secret", " ".join(run.call_args.args[0]))

    def _embedded_worker_evidence(self, exit_code):
        """Run the generated remote launcher with only process execution mocked."""
        request = self.request()
        request["correlationId"] = "embedded-evidence-" + str(exit_code)
        plan = execution.ScenarioPlan.from_mapping(request)
        payload = self.make()._payload(Path(self.bundle_info["directory"]))
        previous_argv, previous_stdin = sys.argv, sys.stdin
        real_open = open

        class FakeProcess:
            pid = 417

            def kill(self):
                pass

        def process_stat(path, *args, **kwargs):
            if path == "/proc/417/stat":
                return io.StringIO("417 (launcher) S " + "0 " * 18 + "9917\n")
            return real_open(path, *args, **kwargs)

        try:
            sys.argv = ["remote-submit", str(self.remote), plan.host, plan.environment, plan.scenario_id,
                        plan.correlation_id, plan.bundle_hash,
                        json.dumps(dict(plan.artifact_ids), sort_keys=True, separators=(",", ":"))]
            sys.stdin = type("Input", (), {"buffer": io.BytesIO(payload)})()
            with mock.patch("subprocess.Popen", return_value=FakeProcess()), mock.patch("builtins.open", side_effect=process_stat):
                exec(ssh_driver._SUBMIT, {})
        finally:
            sys.argv, sys.stdin = previous_argv, previous_stdin
        job = self.remote / "native-scenario-jobs" / plan.environment / plan.scenario_id / plan.correlation_id
        launch = (job / "launch.py").read_text(encoding="utf-8")
        previous_argv = sys.argv
        try:
            sys.argv = [str(job / "launch.py"), str(job), str(job / "bundle")]
            with mock.patch("subprocess.call", return_value=exit_code):
                exec(compile(launch, str(job / "launch.py"), "exec"), {"__name__": "__main__"})
        finally:
            sys.argv = previous_argv
        return json.loads((job / "evidence.json").read_text(encoding="utf-8")), str(job / "failure.stderr")

    def test_embedded_worker_evidence_marks_failure_only_for_nonzero_exit(self):
        success, _ = self._embedded_worker_evidence(0)
        self.assertEqual({"evidenceClass": "component", "action": "no_product_action", "exitCode": 0}, success)
        failed, failure_path = self._embedded_worker_evidence(23)
        self.assertEqual({"evidenceClass": "component", "action": "no_product_action", "exitCode": 23,
                          "failurePath": failure_path}, failed)

    @unittest.skipUnless(Path("/proc/self/stat").exists(), "remote PID generation test requires Linux /proc")
    def test_local_subprocess_standin_retains_receipt_after_submit_response_disconnect(self):
        request = self.request(); plan = execution.ScenarioPlan.from_mapping(request)
        old = os.environ.get("DROP_RESPONSE"); old_log = os.environ.get("FAKE_SSH_LOG"); os.environ["DROP_RESPONSE"] = "1"; os.environ["FAKE_SSH_LOG"] = str(self.log)
        try:
            first = execution.ScenarioExecutor(self.work / "journal", self.make()).start(request)
            self.assertEqual(("submitting", "submit_response_unavailable"), (first["state"], first["reason"]))
        finally:
            if old is None: os.environ.pop("DROP_RESPONSE", None)
            else: os.environ["DROP_RESPONSE"] = old
            if old_log is None: os.environ.pop("FAKE_SSH_LOG", None)
            else: os.environ["FAKE_SSH_LOG"] = old_log
        driver = self.make(); resumed = execution.ScenarioExecutor(self.work / "journal", driver)
        for _ in range(150):
            result = resumed.resume("preflight-17")
            if result["state"] == "terminal":
                    self.assertEqual(0, result["exitCode"])
                    evidence = json.loads((self.remote / "native-scenario-jobs" / "ownedguest" / "linux-public-update-preflight" / "preflight-17" / "evidence.json").read_text())
                    self.assertEqual({"evidenceClass": "component", "action": "no_product_action", "exitCode": 0}, evidence)
                    break
            time.sleep(.02)
        else:
            self.fail("retained remote receipt was not observed: " + self.log.read_text(encoding="utf-8"))
        job = self.remote / "native-scenario-jobs" / "ownedguest" / "linux-public-update-preflight" / "preflight-17"
        self.assertTrue((job / "receipt.json").exists())
        with self.assertRaisesRegex(ssh_driver.NativeScenarioSshError, "unavailable"):
            self.make().submit(plan)

    def test_adapter_rejects_bundle_scenario_mismatch_before_transport(self):
        plan = execution.ScenarioPlan.from_mapping(self.request())
        info = bundle.prepare_bundle(ROOT, "desktop-update-entrypoint", self.work / "wrong")
        plan_value = self.request(); plan_value["bundleHash"] = info["manifestSha256"]
        plan = execution.ScenarioPlan.from_mapping(plan_value)
        driver = ssh_driver.NativeScenarioSshDriver(ROOT, lambda _: info["directory"], ssh_binary=str(self.fake_ssh), configuration_root=self.work)
        with self.assertRaisesRegex(ssh_driver.NativeScenarioSshError, "fixed preflight"):
            driver.submit(plan)

    def test_payload_uses_frozen_runner_after_checkout_runner_changes(self):
        checkout = self.work / "checkout"
        (checkout / "scripts").mkdir(parents=True)
        required = ("test_linux_public_install.py", "linux_fixture_auth.py", "arch_public_update.py", "rpm_public_update.py",
                    "prepare_desktop_update_fixture.py", "fixture_environment.py",
                    "macos_packaging_jdk_preflight.py", "native_fixture_run.sh")
        for name in required:
            shutil.copyfile(ROOT / "scripts" / name, checkout / "scripts" / name)
        frozen = bundle.prepare_bundle(checkout, "linux-public-update-driver", self.work / "frozen-checkout")
        (checkout / "scripts/native_fixture_run.sh").write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        request = self.request(); request["bundleHash"] = frozen["manifestSha256"]
        plan = execution.ScenarioPlan.from_mapping(request)
        driver = ssh_driver.NativeScenarioSshDriver(checkout, lambda _: frozen["directory"], ssh_binary=str(self.fake_ssh), configuration_root=self.work)
        payload = driver._payload(Path(frozen["directory"]))
        header, data = payload.split(b"\n", 1)
        offset = 0
        streamed = {}
        for entry in json.loads(header)["files"]:
            size = entry["sizeBytes"]
            streamed[entry["path"]] = data[offset:offset + size]
            offset += size
        self.assertEqual(offset, len(data))
        self.assertEqual((Path(frozen["directory"]) / "scripts/native_fixture_run.sh").read_bytes(),
                         streamed["scripts/native_fixture_run.sh"])
        self.assertNotEqual((checkout / "scripts/native_fixture_run.sh").read_bytes(),
                            streamed["scripts/native_fixture_run.sh"])
        self.assertEqual(plan.bundle_hash, frozen["manifestSha256"])


if __name__ == "__main__":
    unittest.main()
