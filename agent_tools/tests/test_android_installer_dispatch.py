"""Causal no-replay and shared-lease checks for Android installer dispatch."""
from __future__ import annotations

import json
import hashlib
import socket
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from agent_tools import android_installer_dispatch as dispatch

CORR = "3a328d13-28a6-442b-bcc0-266ca20368f5"


class AndroidInstallerDispatchTest(unittest.TestCase):
    def test_ui_callback_requires_owned_dialog_session_and_is_one_shot(self):
        """Execute fixed callback code with fake public CLI and OS UI readers."""
        def scenario(mode="valid", accepted_owner="owner", source="a" * 40):
            temporary = tempfile.TemporaryDirectory()
            root = Path(temporary.name); root.chmod(0o700)
            job = root / ("android-installer-" + CORR); job.mkdir(mode=0o700)
            output = job / "output"; output.mkdir(mode=0o700)
            mode_file = root / "mode.txt"; mode_file.write_text(mode)
            adb = root / "adb"
            adb.write_text("#!/usr/bin/env python3\nimport pathlib,sys\n"
                "args=sys.argv[1:]; mode=pathlib.Path(" + repr(str(mode_file)) + ").read_text()\n"
                "if 'dumpsys' in args: print('mCurrentFocus=Window{abc u0 '+('com.android.settings/.Home' if mode=='after' else 'com.android.packageinstaller.evil/.Overlay' if mode=='foreign-focus' else 'com.android.packageinstaller/.InstallAppProgress')+'}')\n"
                "elif 'cat' in args:\n"
                " title='VPN Control' if mode in ('valid','foreign-focus') else 'Foreign App'\n"
                " print('<hierarchy/>' if mode=='after' else '<hierarchy><node package=\"com.android.packageinstaller\" text=\"'+title+'\"/><node package=\"com.android.packageinstaller\" text=\"Update\" enabled=\"true\"/><node package=\"com.android.packageinstaller\" text=\"Cancel\" enabled=\"true\"/></hierarchy>')\n")
            adb.chmod(0o700)
            cli = root / "cli.py"
            cli.write_text("#!/usr/bin/env python3\nimport json,sys,pathlib\n"
                "mode=pathlib.Path(" + repr(str(mode_file)) + ").read_text()\n"
                "base={'ok':True,'final':True,'code':'OK'}\n"
                "if sys.argv[-2:]==['updates','status']: value={**base,'controllerId':'new-owner','configurationRevision':5,'data':{'installReceipt':{'installReceiptId':'receipt-1','installSessionId':17,'installPhase':'installed','installed':True}}}\n"
                "elif sys.argv[-1:] == ['status']: value={**base,'controllerId':'new-owner' if mode=='after' else 'owner','configurationRevision':5 if mode=='after' else 4,'data':{'runtimeRunning':False,'runtimeObservation':'stopped'}}\n"
                "else: value={**base,'operationId':'op-1','controllerId':'owner','configurationRevision':4,'data':{'installerStarted':True,'installPhase':'handed_off','installReceiptId':'receipt-1','installSessionId':17}}\n"
                "print(json.dumps(value))\n")
            cli.chmod(0o700)
            pair = {"sourceSha": source, "targetArtifactId": "sha256-" + "c" * 64}
            product = {"correlationId": CORR, "host": "archlinux", "device": "api35",
                "pair": pair, "expectedOwner": "owner", "expectedRevision": 4,
                "expectedAvd": "owned-api35", "expectedApi": 35}
            values = {"intent.json": product,
                "phase-interactive.json": {"correlationId": CORR, "phase": "interactive"},
                "probe.json": {"callbackReceipt": {"installerLifecycle": {
                    "interactiveAccepted": {"response": {"ok": True, "code": "ACCEPTED",
                        "final": False, "controllerId": accepted_owner,
                        "configurationRevision": 4, "operationId": "op-1"}}}}}}
            for name, value in values.items():
                path = output / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            expected = {"sourceSha": "a" * 40, "targetArtifactId": "sha256-" + "c" * 64,
                "owner": "owner", "revision": 4, "avd": "owned-api35", "api": 35,
                "adb": str(adb), "cli": str(cli), "serial": "emulator-5554",
                "terminal": "installed", "files": []}
            before, after = dispatch._REMOTE.split("def observe():", 1)
            _old, after = after.split("info=root.lstat()", 1)
            worker = before + "def observe(): return {'state':'running'}\ninfo=root.lstat()" + after
            def call(action="callback-handoff-ready"):
                result = subprocess.run([sys.executable, "-I", "-B", "-c", "exec(" + repr(worker) + ")",
                    action, str(root), "archlinux", "api35", CORR,
                    json.dumps(expected, sort_keys=True)], capture_output=True, timeout=5)
                self.assertEqual(0, result.returncode, result.stderr[-2000:])
                return json.loads(result.stdout)
            return temporary, root, job, output, call

        temporary, _root, _job, output, call = scenario()
        try:
            first = call()
            self.assertEqual("complete", first["state"], first)
            self.assertEqual("handoff-ready", first["callback"]["phase"])
            self.assertEqual("callback_already_submitted", call()["reason"])
            self.assertEqual(first["callback"], call("callback-status-handoff-ready")["callback"])
            ui_file = output / "callback-handoff-ready-ui.xml"
            snapshot = ui_file.read_bytes(); ui_file.write_bytes(b"tampered")
            self.assertEqual("callback_evidence_changed", call("callback-status-handoff-ready")["reason"])
            ui_file.write_bytes(snapshot)
            self.assertEqual(b"continue\n", (output / "handoff-ready").read_bytes())
            handoff = output / "handoff.json"
            handoff.write_text(json.dumps({"identity": {"operationId": "op-1",
                "receiptId": "foreign-receipt", "sessionId": 17}})); handoff.chmod(0o600)
            self.assertEqual("callback_handoff_changed", call("callback-continue")["reason"])
            self.assertFalse((output / "continue").exists())
            handoff.write_text(json.dumps({"identity": {"operationId": "op-1",
                "receiptId": "receipt-1", "sessionId": 17}})); handoff.chmod(0o600)
            (_root / "mode.txt").write_text("after")
            continued = call("callback-continue")
            self.assertEqual("complete", continued["state"], continued)
            self.assertEqual("new-owner", continued["callback"]["owner"])
            self.assertEqual("callback_already_submitted", call("callback-continue")["reason"])
            self.assertEqual(continued["callback"], call("callback-status-continue")["callback"])
        finally: temporary.cleanup()
        for variant in ("foreign-ui", "foreign-focus", "stale-owner", "source"):
            temporary, _root, job, output, call = scenario(
                mode="foreign" if variant == "foreign-ui" else "foreign-focus" if variant == "foreign-focus" else "valid",
                accepted_owner="foreign" if variant == "stale-owner" else "owner",
                source="b" * 40 if variant == "source" else "a" * 40)
            try:
                observed = call()
                self.assertEqual("unknown", observed["state"])
                self.assertEqual({"foreign-ui": "callback_dialog_not_owned",
                    "foreign-focus": "callback_dialog_not_owned",
                    "stale-owner": "callback_operation_changed",
                    "source": "callback_intent_changed"}[variant], observed["reason"])
                self.assertFalse((output / "handoff-ready").exists())
                self.assertFalse((output / "callback-handoff-ready-evidence.json").exists())
            finally: temporary.cleanup()

    def test_injected_proc_harness_requires_worker_exit_before_terminal_release(self):
        """Execute launch/observe/finalize on macOS using a deterministic PID shim."""
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0)); fixture_port = probe.getsockname()[1]
            intent = {"correlationId": CORR, "host": "archlinux", "device": "api35",
                      "pair": {"sourceSha": "a" * 40, "baseSha256": "b" * 64,
                               "targetSha256": "c" * 64, "baseVersion": "2.2.0",
                               "targetVersion": "2.2.1", "baseCode": 16800, "targetCode": 16820}}
            files = {
                "output/intent.json": json.dumps(intent).encode(),
                "bundle/agent_tools/android_installer_target.py":
                    b"from pathlib import Path\ndef status(output, correlation):\n"
                    b" return {'state':'complete','correlationId':correlation,'replayAllowed':False} if (Path(output)/'done').exists() else {'state':'submitted','correlationId':correlation,'replayAllowed':False}\n",
                "bundle/scripts/android_installer_lifecycle.py":
                    ("from pathlib import Path\nimport sys,time,json\n"
                     "out=Path(sys.argv[sys.argv.index('--output')+1])\n"
                     f"identity={{'correlationId':'{CORR}','pid':999999,'startTicks':1,'port':{fixture_port}}}\n"
                     "records={'fixture-identity.json':identity,'worker-finished.json':{**identity,'state':'fixture_stopped'},"
                     f"'fixture-receipt.json':{{'state':'ready','pid':999999,'port':{fixture_port}}},"
                     f"'ready.json':{{'port':{fixture_port},'manifest':{{}}}}}}\n"
                     "for name,value in records.items():\n path=out/name; path.write_text(json.dumps(value)); path.chmod(0o600)\n"
                     "out.joinpath('done').write_text('done')\ntime.sleep(1)\n").encode(),
                "bundle/scripts/android_no_update_tls_preflight.py": b"",
                "bundle/scripts/android_fixture_preflight.py": b"",
                "bundle/scripts/android_fixture_transport.py": b"",
                "bundle/scripts/android_fixture_trust.py": b"",
                "bundle/scripts/integration/android_update_fixture.py": b"",
                "base.apk": b"base", "target.apk": b"target",
                "ca.pem": b"ca", "leaf.pem": b"leaf", "key.pem": b"key",
            }
            expected = {"sourceSha": "a" * 40, "adb": "/adb", "cli": "/cli",
                        "serial": "emulator-5554", "avd": "owned-api35", "api": 35,
                        "devicePort": 45635, "terminal": "installed",
                        "files": [{"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                  for name, data in files.items()]}
            generated = dispatch._REMOTE
            before, after = generated.split("def ticks(pid):", 1)
            _old_ticks, after = after.split("def fixture_stopped(output):", 1)
            fake_ticks = "def ticks(pid):\n try:\n  value=subprocess.run(['ps','-p',str(pid),'-o','stat='],capture_output=True,text=True,timeout=2)\n  return pid if value.returncode==0 and value.stdout.strip() and not value.stdout.strip().startswith('Z') else None\n except OSError: return None\n"
            generated = before + fake_ticks + "def fixture_stopped(output):" + after
            generated = generated.replace("if not pathlib.Path('/proc').is_dir(): unknown('proc_unavailable')",
                                          "if False: unknown('proc_unavailable')")
            prefix = [sys.executable, "-I", "-B", "-c", "exec(" + repr(generated) + ")"]
            def call(action, payload=b""):
                result = subprocess.run([*prefix, action, str(root), "archlinux", "api35", CORR,
                    json.dumps(expected, sort_keys=True)], input=payload, capture_output=True, timeout=5)
                self.assertEqual(0, result.returncode, result.stderr)
                return json.loads(result.stdout)
            self.assertEqual("submitted", call("start", b"".join(files.values()))["state"])
            import time
            deadline = time.monotonic() + 2
            while not (root / ("android-installer-" + CORR) / "output" / "done").exists() and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue((root / ("android-installer-" + CORR) / "output" / "done").exists())
            self.assertEqual("running", call("status")["state"])
            self.assertEqual("terminal_not_complete", call("finalize")["reason"])
            time.sleep(1.1)
            output = root / ("android-installer-" + CORR) / "output"
            finished = output / "worker-finished.json"
            finished_bytes = finished.read_bytes(); finished.unlink()
            self.assertEqual("fixture_teardown_unproven", call("status")["reason"])
            finished.write_bytes(finished_bytes); finished.chmod(0o600)
            def fixture_records(pid, ticks):
                identity = {"correlationId": CORR, "pid": pid,
                    "startTicks": ticks, "port": fixture_port}
                values = {"fixture-identity.json": identity,
                    "worker-finished.json": {**identity, "state": "fixture_stopped"},
                    "fixture-receipt.json": {"state": "ready", "pid": pid, "port": fixture_port},
                    "ready.json": {"port": fixture_port, "manifest": {}}}
                for name, value in values.items():
                    (output / name).write_text(json.dumps(value))
            fixture_records(os.getpid(), os.getpid())
            self.assertEqual("fixture_server_live", call("status")["reason"])
            self.assertEqual("fixture_server_live", call("finalize")["reason"])
            fixture_records(999999, 1)
            with socket.socket() as orphan:
                orphan.bind(("127.0.0.1", fixture_port)); orphan.listen(1)
                self.assertEqual("fixture_listener_present", call("status")["reason"])
                accepted, _ = orphan.accept(); accepted.close()
                self.assertEqual("fixture_listener_present", call("finalize")["reason"])
            self.assertEqual("complete", call("status")["state"])
            release_intent = root / ("android-installer-" + CORR) / "release-intent.json"
            release_intent.write_text(json.dumps({"correlationId": CORR,
                "resultState": "complete"}) + "\n")
            release_intent.chmod(0o600)
            self.assertEqual("complete", call("finalize")["state"])
            self.assertEqual("complete", call("finalize")["state"])
            self.assertFalse((root / "android-native-device-api35.lease").exists())

    def test_remote_shared_release_receipt_survives_lost_response(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            prefix = [sys.executable, "-I", "-B", "-c",
                "exec(" + repr(dispatch._REMOTE_SHARED) + ")"]
            def call(action):
                done = subprocess.run([*prefix, action, str(root), "archlinux", "api35",
                    CORR, "android-package-install"], capture_output=True, timeout=5)
                self.assertEqual(0, done.returncode, done.stderr)
                return json.loads(done.stdout)
            self.assertEqual("claimed", call("claim")["state"])
            self.assertEqual("claimed", call("status")["state"])
            # Simulate a process death after durable release intent but before unlink.
            release_intent = root / ("android-native-device-api35-" + CORR + ".release-intent")
            release_intent.write_text(json.dumps(dispatch._lease_value(
                "android-package-install", "archlinux", "api35", CORR)) + "\n")
            release_intent.chmod(0o600)
            self.assertEqual("release_incomplete", call("status")["reason"])
            self.assertEqual("released", call("release")["state"])
            self.assertEqual("released", call("status")["state"])
            self.assertEqual("released", call("release")["state"])
            self.assertFalse((root / "android-native-device-api35.lease").exists())

    def test_payload_snapshot_rejects_symlinked_apk_before_remote_submission(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            output = root / "output"; output.mkdir(mode=0o700)
            actual = root / "actual.apk"; actual.write_bytes(b"bytes")
            link = root / "base.apk"; link.symlink_to(actual)
            with self.assertRaises(OSError):
                dispatch._snapshot_payload(output, [("base.apk", link)])
            self.assertFalse((root / "android-native-device-api35.lease").exists())

    def test_partial_remote_upload_has_guarded_prelaunch_abort(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            expected = {"sourceSha": "a" * 40, "files": [{"name": "output/intent.json",
                "size": 10, "sha256": hashlib.sha256(b"0123456789").hexdigest()}]}
            prefix = [sys.executable, "-I", "-B", "-c", "exec(" + repr(dispatch._REMOTE) + ")"]
            def call(action, payload=b""):
                done = subprocess.run([*prefix, action, str(root), "archlinux", "api35", CORR,
                    json.dumps(expected, sort_keys=True)], input=payload, capture_output=True, timeout=5)
                self.assertEqual(0, done.returncode, done.stderr)
                return json.loads(done.stdout)
            self.assertEqual("stream_truncated", call("start", b"0")["reason"])
            lease = root / "android-native-device-api35.lease"
            self.assertTrue(lease.is_file())
            job = root / ("android-installer-" + CORR)
            self.assertFalse((job / "launch-intent.json").exists())
            aborted = call("abort-prelaunch")
            self.assertEqual("complete", aborted["state"], aborted)
            self.assertFalse(lease.exists())
            self.assertEqual("complete", call("abort-prelaunch")["state"])

    def test_remote_status_refuses_symlinked_bundle_parent(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            foreign = root / "foreign"; foreign.mkdir(mode=0o700)
            marker = foreign / "marker"; marker.write_bytes(b"unchanged")
            expected = {"sourceSha": "a" * 40, "files": []}
            job = root / ("android-installer-" + CORR); job.mkdir(mode=0o700)
            (job / "output").mkdir(mode=0o700)
            (job / "bundle").symlink_to(foreign)
            dispatch_file = job / "dispatch.json"
            dispatch_file.write_text(json.dumps(expected) + "\n"); dispatch_file.chmod(0o600)
            done = subprocess.run([sys.executable, "-I", "-B", "-c",
                "exec(" + repr(dispatch._REMOTE) + ")", "status", str(root), "archlinux",
                "api35", CORR, json.dumps(expected, sort_keys=True)], capture_output=True, timeout=5)
            self.assertEqual(0, done.returncode, done.stderr)
            self.assertEqual("structure_unsafe", json.loads(done.stdout)["reason"])
            self.assertEqual(b"unchanged", marker.read_bytes())

    def test_uploaded_driver_tamper_is_caught_before_launch_intent(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            intent = {"correlationId": CORR, "host": "archlinux", "device": "api35",
                "pair": {"sourceSha": "a" * 40}}
            files = {"output/intent.json": json.dumps(intent).encode(),
                "bundle/agent_tools/android_installer_target.py": b"pass\n",
                "bundle/scripts/android_installer_lifecycle.py": b"print('safe')\n",
                "bundle/scripts/android_no_update_tls_preflight.py": b"",
                "bundle/scripts/android_fixture_preflight.py": b"",
                "bundle/scripts/android_fixture_transport.py": b"",
                "bundle/scripts/android_fixture_trust.py": b"",
                "bundle/scripts/integration/android_update_fixture.py": b"",
                "ca.pem": b"ca", "leaf.pem": b"leaf", "key.pem": b"key",
                "base.apk": b"base", "target.apk": b"target"}
            expected = {"sourceSha": "a" * 40, "files": [
                {"name": name, "size": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                for name, value in files.items()]}
            original = "if sys.stdin.buffer.read(1): unknown('stream_extra_bytes')\n verify_manifest()"
            self.assertIn(original, dispatch._REMOTE)
            injected = dispatch._REMOTE.replace(original,
                "if sys.stdin.buffer.read(1): unknown('stream_extra_bytes')\n"
                " victim=job/'bundle'/'scripts'/'android_installer_lifecycle.py'\n"
                " victim.write_bytes(b'X'*len(private(victim,1024)))\n verify_manifest()")
            done = subprocess.run([sys.executable, "-I", "-B", "-c", "exec(" + repr(injected) + ")",
                "start", str(root), "archlinux", "api35", CORR, json.dumps(expected, sort_keys=True)],
                input=b"".join(files.values()), capture_output=True, timeout=5)
            self.assertEqual(0, done.returncode, done.stderr)
            self.assertEqual("staged_bytes_changed", json.loads(done.stdout)["reason"])
            job = root / ("android-installer-" + CORR)
            self.assertFalse((job / "launch-intent.json").exists())

    def test_fixed_remote_staging_detached_status_and_terminal_release(self):
        """Exercise the generated worker through its launch and release branches."""
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0)); fixture_port = probe.getsockname()[1]
            correlation = CORR
            intent = {"correlationId": correlation, "host": "archlinux", "device": "api35",
                      "pair": {"sourceSha": "a" * 40, "baseSha256": "b" * 64,
                               "targetSha256": "c" * 64, "baseVersion": "2.2.0",
                               "targetVersion": "2.2.1", "baseCode": 16800, "targetCode": 16820}}
            files = {
                "output/intent.json": json.dumps(intent).encode(),
                "bundle/agent_tools/android_installer_target.py":
                    b"from pathlib import Path\ndef status(output, correlation):\n"
                    b" return {'state':'complete','correlationId':correlation,'replayAllowed':False} if (Path(output)/'done').exists() else {'state':'submitted','correlationId':correlation,'replayAllowed':False}\n",
                "bundle/scripts/android_installer_lifecycle.py":
                    ("from pathlib import Path\nimport sys,json\n"
                     "out=Path(sys.argv[sys.argv.index('--output')+1])\n"
                     f"identity={{'correlationId':'{CORR}','pid':999999,'startTicks':1,'port':{fixture_port}}}\n"
                     "records={'fixture-identity.json':identity,'worker-finished.json':{**identity,'state':'fixture_stopped'},"
                     f"'fixture-receipt.json':{{'state':'ready','pid':999999,'port':{fixture_port}}},"
                     f"'ready.json':{{'port':{fixture_port},'manifest':{{}}}}}}\n"
                     "for name,value in records.items():\n path=out/name; path.write_text(json.dumps(value)); path.chmod(0o600)\n"
                     "out.joinpath('done').write_text('done')\n").encode(),
                "bundle/scripts/android_no_update_tls_preflight.py": b"",
                "bundle/scripts/android_fixture_preflight.py": b"",
                "bundle/scripts/android_fixture_transport.py": b"",
                "bundle/scripts/android_fixture_trust.py": b"",
                "bundle/scripts/integration/android_update_fixture.py": b"",
                "base.apk": b"base", "target.apk": b"target",
                "ca.pem": b"ca", "leaf.pem": b"leaf", "key.pem": b"key",
            }
            expected = {"sourceSha": "a" * 40, "adb": "/adb", "cli": "/cli",
                        "serial": "emulator-5554", "avd": "owned-api35", "api": 35,
                        "devicePort": 45635, "terminal": "installed",
                        "files": [{"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                  for name, data in files.items()]}
            args = [sys.executable, "-I", "-B", "-c", "exec(" + repr(dispatch._REMOTE) + ")",
                    "start", str(root), "archlinux", "api35", correlation,
                    json.dumps(expected, sort_keys=True)]
            started = subprocess.run(args, input=b"".join(files.values()), capture_output=True, timeout=5)
            self.assertEqual(0, started.returncode, started.stderr)
            if not Path("/proc").is_dir():
                self.assertEqual({"state": "unknown", "reason": "proc_unavailable"},
                    {key: json.loads(started.stdout)[key] for key in ("state", "reason")})
                job = root / ("android-installer-" + correlation)
                self.assertTrue((job / "launch-intent.json").is_file())
                self.assertFalse((job / "identity.json").exists())
                self.assertFalse((job / "release").exists())
                return
            self.assertEqual("submitted", json.loads(started.stdout)["state"], started.stdout)
            for action in ("status", "finalize", "finalize"):
                argv = args.copy(); argv[5] = action
                observed = subprocess.run(argv, capture_output=True, timeout=5)
                self.assertEqual(0, observed.returncode, observed.stderr)
                value = json.loads(observed.stdout)
                if action == "status" and value["state"] == "running":
                    import time
                    time.sleep(.1)
                    observed = subprocess.run(argv, capture_output=True, timeout=5)
                    value = json.loads(observed.stdout)
                self.assertEqual("complete", value["state"], value)
                if action == "finalize":
                    self.assertTrue(value["leaseReleased"])
            self.assertFalse((root / "android-native-device-api35.lease").exists())

    def test_foreign_shared_local_lease_is_not_overwritten_or_released(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            directory = dispatch._shared_directory(root)
            lease = directory / "lease-archlinux-api35.json"
            foreign = dispatch._lease_value("android-endpoint", "archlinux", "api35", CORR)
            dispatch.android_installer_target._write_private(lease, foreign)
            with self.assertRaises(FileExistsError):
                dispatch._claim_local(root, "archlinux", "api35", "4a328d13-28a6-442b-bcc0-266ca20368f5")
            self.assertFalse(dispatch._release_local(root, "archlinux", "api35", "4a328d13-28a6-442b-bcc0-266ca20368f5"))
            self.assertEqual(foreign, json.loads(lease.read_text()))

    def test_remote_foreign_lease_rejects_before_stream_or_guest_action(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            lease = root / "android-native-device-api35.lease"
            foreign = dispatch._lease_value("android-endpoint", "archlinux", "api35", CORR)
            lease.write_text(json.dumps(foreign) + "\n"); lease.chmod(0o600)
            args = [sys.executable, "-I", "-B", "-c", "exec(" + repr(dispatch._REMOTE) + ")",
                "start", str(root), "archlinux", "api35",
                "4a328d13-28a6-442b-bcc0-266ca20368f5",
                json.dumps({"sourceSha": "a" * 40, "files": []})]
            completed = subprocess.run(args, input=b"", capture_output=True, timeout=5)
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("unknown", json.loads(completed.stdout)["state"])
            self.assertEqual(foreign, json.loads(lease.read_text()))
            job = root / "android-installer-4a328d13-28a6-442b-bcc0-266ca20368f5"
            self.assertTrue((job / "dispatch.json").is_file())
            self.assertFalse((job / "launch-intent.json").exists())

    def test_response_loss_retains_local_intent_and_lease_without_retry(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            base = root / "base.apk"; target = root / "target.apk"
            base.write_bytes(b"base"); target.write_bytes(b"target")
            pair = {"basePath": str(base), "targetPath": str(target), "baseSha256": "b" * 64,
                "targetSha256": "c" * 64, "sourceSha": "a" * 40}
            profile = {"adb": "/adb", "cli": "/cli", "serial": "emulator-5554",
                "expectedAvd": "owned-api35", "api": 35}
            host = SimpleNamespace(android_devices={"api35": profile},
                                   fixture_transfer_root=Path("/private/fixture"))
            config = SimpleNamespace(hosts={"archlinux": host})
            def create(_root, output, correlation, pair, **_):
                output.mkdir(mode=0o700)
                dispatch.android_installer_target._write_private(output / "intent.json",
                    {"schema": 1, "correlationId": correlation, "pair": pair, "replayAllowed": False})
            with mock.patch.object(dispatch.ssh_transport, "load_config", return_value=config), \
                 mock.patch.object(dispatch.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                 mock.patch.object(dispatch.android_observation, "_profile", return_value=profile), \
                 mock.patch.object(dispatch.android_cli_stage, "collect", return_value={"ok": True,
                     "state": "published", "sourceSha": "a" * 40,
                     "receipt": {"cliPath": "/private/fixture/cli"}}), \
                 mock.patch.object(dispatch.android_cli_stage, "_read_intent", return_value={"host": "archlinux"}), \
                 mock.patch.object(dispatch.android_installer_target, "admit_pair", return_value=pair), \
                 mock.patch.object(dispatch.android_admission_readback, "async_collect", return_value={
                     "result": {"backup": {"path": "/private/fixture/opening.json"}}}), \
                 mock.patch.object(dispatch.android_installer_target, "create_intent", side_effect=create), \
                 mock.patch.object(dispatch, "_fixture_bytes", return_value=b"fixture"), \
                 mock.patch.object(dispatch, "_source_bytes", return_value=b"source"), \
                 mock.patch.object(dispatch, "_remote", return_value={"state": "unknown", "reason": "response_loss"}) as submitted:
                result = dispatch.start(root, "archlinux", "api35", CORR, "a" * 40,
                    "sha256-" + "b" * 64, "sha256-" + "c" * 64,
                    "5a328d13-28a6-442b-bcc0-266ca20368f5",
                    "6a328d13-28a6-442b-bcc0-266ca20368f5",
                    "owner", 4, "d" * 64, "installed",
                    "7a328d13-28a6-442b-bcc0-266ca20368f5",
                    "sha256-" + "e" * 64, "sha256-" + "f" * 64,
                    "sha256-" + "0" * 64)
                self.assertEqual("unknown", result["state"])
                self.assertFalse(result["replayAllowed"])
                self.assertTrue((dispatch._directory(root) / CORR / "dispatch.json").is_file())
                self.assertTrue((dispatch._shared_directory(root) / "lease-archlinux-api35.json").is_file())
                self.assertEqual(1, submitted.call_count)
                with self.assertRaises(FileExistsError):
                    dispatch.start(root, "archlinux", "api35", CORR, "a" * 40,
                        "sha256-" + "b" * 64, "sha256-" + "c" * 64,
                        "5a328d13-28a6-442b-bcc0-266ca20368f5",
                        "6a328d13-28a6-442b-bcc0-266ca20368f5",
                        "owner", 4, "d" * 64, "installed",
                        "7a328d13-28a6-442b-bcc0-266ca20368f5",
                        "sha256-" + "e" * 64, "sha256-" + "f" * 64,
                        "sha256-" + "0" * 64)
                self.assertEqual(1, submitted.call_count)

    def test_stale_owner_blocks_before_lease_or_remote_submission(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            profile = {"expectedAvd": "owned-api35", "api": 35}
            host = SimpleNamespace(android_devices={"api35": profile}, fixture_transfer_root=Path("/private/fixture"))
            with mock.patch.object(dispatch.ssh_transport, "load_config", return_value=SimpleNamespace(hosts={"archlinux": host})), \
                 mock.patch.object(dispatch.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                 mock.patch.object(dispatch.android_observation, "_profile", return_value=profile), \
                 mock.patch.object(dispatch.android_cli_stage, "collect", return_value={"ok": True, "state": "published",
                     "sourceSha": "a" * 40, "receipt": {"cliPath": "/cli"}}), \
                 mock.patch.object(dispatch.android_cli_stage, "_read_intent", return_value={"host": "archlinux"}), \
                 mock.patch.object(dispatch.android_installer_target, "admit_pair", return_value={}), \
                 mock.patch.object(dispatch.android_admission_readback, "async_collect", return_value={
                     "result": {"backup": {"path": "/private/fixture/opening.json"}}}), \
                 mock.patch.object(dispatch.android_installer_target, "create_intent", side_effect=ValueError("owner changed")), \
                 mock.patch.object(dispatch, "_fixture_bytes", return_value=b"tls"), \
                 mock.patch.object(dispatch, "_source_bytes", return_value=b"tool"), \
                 mock.patch.object(dispatch, "_remote") as submitted:
                with self.assertRaisesRegex(ValueError, "owner changed"):
                    dispatch.start(root, "archlinux", "api35", CORR, "a" * 40,
                        "sha256-" + "b" * 64, "sha256-" + "c" * 64,
                        "5a328d13-28a6-442b-bcc0-266ca20368f5",
                        "6a328d13-28a6-442b-bcc0-266ca20368f5",
                        "owner", 4, "d" * 64, "installed",
                        "7a328d13-28a6-442b-bcc0-266ca20368f5",
                        "sha256-" + "e" * 64, "sha256-" + "f" * 64,
                        "sha256-" + "0" * 64)
                submitted.assert_not_called()
                self.assertFalse((dispatch._shared_directory(root) / "lease-archlinux-api35.json").exists())

    def test_prelaunch_abort_rejects_stale_owner_before_remote_lease_release(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            intent = {"host": "archlinux", "device": "api35", "correlationId": CORR,
                "remote": {"serial": "emulator-5554", "avd": "owned-api35", "api": 35, "adb": "/adb"}}
            original = {"expectedOwner": "opening-owner", "expectedRevision": 4,
                "backupSha256": "d" * 64, "backupSize": 239,
                "expectedAvd": "owned-api35", "expectedApi": 35,
                "pair": {"baseSha256": "b" * 64}}
            profile = {"serial": "emulator-5554", "expectedAvd": "owned-api35", "api": 35,
                "adb": "/adb"}
            host = SimpleNamespace(android_devices={"api35": profile})
            with mock.patch.object(dispatch, "_local_intent", return_value=intent), \
                 mock.patch.object(dispatch.android_installer_target, "load_intent", return_value=original), \
                 mock.patch.object(dispatch.ssh_transport, "load_config", return_value=SimpleNamespace(hosts={"archlinux": host})), \
                 mock.patch.object(dispatch.android_observation, "_profile", return_value=profile), \
                 mock.patch.object(dispatch.android_admission_readback, "readback_status", return_value={
                     "ok": True, "result": {"stage": "backup_present", "controllerId": "foreign-owner"}}), \
                 mock.patch.object(dispatch.android_admission_readback, "async_collect", return_value={}), \
                 mock.patch.object(dispatch, "_remote") as remote:
                closed = dispatch.abort_prelaunch(root, CORR, "6a328d13-28a6-442b-bcc0-266ca20368f5")
                self.assertEqual("unknown", closed["state"])
                self.assertEqual("closing_readback_changed", closed["reason"])
                remote.assert_not_called()

    def test_terminal_reconcile_rejects_changed_backup_or_foreign_avd(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            intent = {"host": "archlinux", "device": "api35", "correlationId": CORR,
                "remote": {"serial": "emulator-5554", "avd": "owned-api35", "api": 35, "adb": "/adb"}}
            original = {"expectedOwner": "owner", "expectedRevision": 4,
                "backupSha256": "d" * 64, "backupSize": 239, "expectedTerminal": "installed",
                "expectedAvd": "owned-api35", "expectedApi": 35,
                "pair": {"baseSha256": "b" * 64, "targetSha256": "c" * 64}}
            profile = {"serial": "emulator-5554", "expectedAvd": "owned-api35", "api": 35,
                "adb": "/adb"}
            host = SimpleNamespace(android_devices={"api35": profile})
            for changed in ("backup", "avd"):
                with self.subTest(changed=changed):
                    backup_hash = "e" * 64 if changed == "backup" else "d" * 64
                    avd = "foreign-api35" if changed == "avd" else "owned-api35"
                    observed = {"ok": True, "result": {"stage": "backup_present", "deviceIdentity": True,
                        "controllerId": "owner", "configurationRevision": 4,
                        "backup": {"sha256": backup_hash, "size": 239, "formatValid": True}}}
                    collected = {"ok": True, "state": "complete", "result": {
                        "package": {"baseSha256": "c" * 64},
                        "device": {"uid": "2000", "avd": avd, "api": 35},
                        "guard": {"controllerId": "owner", "configurationRevision": 4},
                        "backup": {"sha256": backup_hash}}}
                    with mock.patch.object(dispatch, "_local_intent", return_value=intent), \
                         mock.patch.object(dispatch, "collect", return_value={"ok": True, "state": "complete",
                             "result": {"terminal": "installed", "terminalOwner": "owner", "terminalRevision": 4}}), \
                         mock.patch.object(dispatch.android_installer_target, "load_intent", return_value=original), \
                         mock.patch.object(dispatch.ssh_transport, "load_config", return_value=SimpleNamespace(hosts={"archlinux": host})), \
                         mock.patch.object(dispatch.android_observation, "_profile", return_value=profile), \
                         mock.patch.object(dispatch.android_admission_readback, "readback_status", return_value=observed), \
                         mock.patch.object(dispatch.android_admission_readback, "async_collect", return_value=collected), \
                         mock.patch.object(dispatch.android_public_inspect, "inspect") as public, \
                         mock.patch.object(dispatch, "_remote") as remote:
                        closed = dispatch.reconcile(root, CORR,
                            "6a328d13-28a6-442b-bcc0-266ca20368f5", "owner", 4)
                        self.assertEqual("closing_readback_changed", closed["reason"])
                        public.assert_not_called(); remote.assert_not_called()

    def test_installed_owner_replacement_bound_to_terminal_and_fresh_readback(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            intent = {"host": "archlinux", "device": "api35", "correlationId": CORR,
                "remote": {"serial": "emulator-5554", "avd": "owned-api35", "api": 35, "adb": "/adb"}}
            original = {"expectedOwner": "opening-owner", "expectedRevision": 4,
                "backupSha256": "d" * 64, "backupSize": 239, "expectedTerminal": "installed",
                "expectedAvd": "owned-api35", "expectedApi": 35,
                "pair": {"baseSha256": "b" * 64, "targetSha256": "c" * 64}}
            profile = {"serial": "emulator-5554", "expectedAvd": "owned-api35", "api": 35,
                "adb": "/adb"}
            host = SimpleNamespace(android_devices={"api35": profile})
            observed = {"ok": True, "result": {"stage": "backup_present", "deviceIdentity": True,
                "controllerId": "new-owner", "configurationRevision": 5,
                "backup": {"sha256": "d" * 64, "size": 239, "formatValid": True}}}
            collected = {"ok": True, "state": "complete", "result": {
                "package": {"baseSha256": "c" * 64},
                "device": {"uid": "2000", "avd": "owned-api35", "api": 35},
                "guard": {"controllerId": "new-owner", "configurationRevision": 5},
                "backup": {"sha256": "d" * 64}}}
            public = {"ok": True, "outcome": "admitted", "result": {
                "packageSha256": "c" * 64, "controllerId": "new-owner", "configurationRevision": 5,
                "device": {"uid": "2000", "avd": "owned-api35", "api": 35},
                "runtime": {"running": False, "observation": "stopped"}}}
            with mock.patch.object(dispatch, "_local_intent", return_value=intent), \
                 mock.patch.object(dispatch, "collect", return_value={"ok": True, "state": "complete",
                     "result": {"terminal": "installed", "terminalOwner": "new-owner", "terminalRevision": 5}}), \
                 mock.patch.object(dispatch.android_installer_target, "load_intent", return_value=original), \
                 mock.patch.object(dispatch.ssh_transport, "load_config", return_value=SimpleNamespace(hosts={"archlinux": host})), \
                 mock.patch.object(dispatch.android_observation, "_profile", return_value=profile), \
                 mock.patch.object(dispatch.android_admission_readback, "readback_status", return_value=observed), \
                 mock.patch.object(dispatch.android_admission_readback, "async_collect", return_value=collected), \
                 mock.patch.object(dispatch.android_public_inspect, "inspect", return_value=public), \
                 mock.patch.object(dispatch, "_remote", return_value={"state": "complete", "leaseReleased": True}) as remote, \
                 mock.patch.object(dispatch, "_release_local", return_value=True):
                closed = dispatch.reconcile(root, CORR,
                    "6a328d13-28a6-442b-bcc0-266ca20368f5", "new-owner", 5)
                self.assertEqual("complete", closed["state"])
                remote.assert_called_once()
                remote.reset_mock()
                foreign = dispatch.reconcile(root, CORR,
                    "6a328d13-28a6-442b-bcc0-266ca20368f5", "foreign-owner", 5)
                self.assertEqual("closing_owner_changed", foreign["reason"])
                remote.assert_not_called()



    def test_tool_or_tls_preflight_rejection_never_creates_product_intent_or_claim(self):
        from contextlib import ExitStack
        for failure in ('source','tls'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as raw,ExitStack() as stack:
                root=Path(raw);root.chmod(0o700)
                profile={'adb':'/adb','cli':'/cli','serial':'emulator-5554','expectedAvd':'owned-api35','api':35}
                config=SimpleNamespace(hosts={'archlinux':SimpleNamespace(android_devices={'api35':profile},fixture_transfer_root=Path('/private/fixture'))})
                patches=[(dispatch.ssh_transport,'load_config',{'return_value':config}),
                    (dispatch.ssh_transport,'connection_host',{'return_value':SimpleNamespace(password=None)}),
                    (dispatch.android_observation,'_profile',{'return_value':profile}),
                    (dispatch.android_cli_stage,'collect',{'return_value':{'ok':True,'state':'published','sourceSha':'a'*40,'receipt':{'cliPath':'/cli'}}}),
                    (dispatch.android_cli_stage,'_read_intent',{'return_value':{'host':'archlinux'}}),
                    (dispatch.android_installer_target,'admit_pair',{'return_value':{'sourceSha':'a'*40}}),
                    (dispatch.android_admission_readback,'async_collect',{'return_value':{'result':{'backup':{'path':'/backup'}}}}),
                    (dispatch,'_source_bytes',{'side_effect':ValueError('unreviewed source')} if failure=='source' else {'return_value':b'tool'}),
                    (dispatch,'_fixture_bytes',{'side_effect':ValueError('unverified TLS')} if failure=='tls' else {'return_value':b'tls'})]
                for obj,name,kw in patches:stack.enter_context(mock.patch.object(obj,name,**kw))
                create=stack.enter_context(mock.patch.object(dispatch.android_installer_target,'create_intent'))
                claim=stack.enter_context(mock.patch.object(dispatch,'_claim_local'))
                remote=stack.enter_context(mock.patch.object(dispatch,'_remote'))
                with self.assertRaises(ValueError):dispatch.start(root,'archlinux','api35',CORR,'a'*40,'sha256-'+'b'*64,'sha256-'+'c'*64,'5a328d13-28a6-442b-bcc0-266ca20368f5','6a328d13-28a6-442b-bcc0-266ca20368f5','owner',4,'d'*64,'installed','7a328d13-28a6-442b-bcc0-266ca20368f5','sha256-'+'e'*64,'sha256-'+'f'*64,'sha256-'+'0'*64)
                create.assert_not_called();claim.assert_not_called();remote.assert_not_called()

    def test_reviewed_tool_bundle_dispatch_keeps_original_product_source_and_no_retry(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            base = root / "base.apk"; target = root / "target.apk"
            base.write_bytes(b"base"); target.write_bytes(b"target")
            pair = {"basePath": str(base), "targetPath": str(target), "baseSha256": "b" * 64,
                "targetSha256": "c" * 64, "sourceSha": "a" * 40}
            profile = {"adb": "/adb", "cli": "/cli", "serial": "emulator-5554",
                "expectedAvd": "owned-api35", "api": 35}
            host = SimpleNamespace(android_devices={"api35": profile},
                                   fixture_transfer_root=Path("/private/fixture"))
            config = SimpleNamespace(hosts={"archlinux": host})
            tools={'toolBundleId':'sha256-'+'1'*64,'reviewedTreeSha256':'2'*64,'manifest':{'schema':1,'kind':'android-installer-reviewed-tools','files':[]},'files':{name:b'reviewed tooling' for name in dispatch._BUNDLE}}
            def create(_root, output, correlation, pair, **_):
                output.mkdir(mode=0o700)
                dispatch.android_installer_target._write_private(output / "intent.json",
                    {"schema": 1, "correlationId": correlation, "pair": pair, "replayAllowed": False})
            with mock.patch.object(dispatch.ssh_transport, "load_config", return_value=config), \
                 mock.patch.object(dispatch.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                 mock.patch.object(dispatch.android_observation, "_profile", return_value=profile), \
                 mock.patch.object(dispatch.android_cli_stage, "collect", return_value={"ok": True,
                     "state": "published", "sourceSha": "a" * 40,
                     "receipt": {"cliPath": "/private/fixture/cli"}}), \
                 mock.patch.object(dispatch.android_cli_stage, "_read_intent", return_value={"host": "archlinux"}), \
                 mock.patch.object(dispatch.android_installer_target, "admit_pair", return_value=pair), \
                 mock.patch.object(dispatch.android_admission_readback, "async_collect", return_value={
                     "result": {"backup": {"path": "/private/fixture/opening.json"}}}), \
                 mock.patch.object(dispatch.android_installer_target, "create_intent", side_effect=create), \
                 mock.patch.object(dispatch, "_fixture_bytes", return_value=b"fixture"), \
                 mock.patch.object(dispatch, "_source_bytes", side_effect=AssertionError("product SHA must not identify reviewed tools")), \
                 mock.patch.object(dispatch.android_installer_tool_bundle, "load", return_value=tools), \
                 mock.patch.object(dispatch, "_remote", return_value={"state": "unknown", "reason": "response_loss"}) as submitted:
                result = dispatch.start(root, "archlinux", "api35", CORR, "a" * 40,
                    "sha256-" + "b" * 64, "sha256-" + "c" * 64,
                    "5a328d13-28a6-442b-bcc0-266ca20368f5",
                    "6a328d13-28a6-442b-bcc0-266ca20368f5",
                    "owner", 4, "d" * 64, "installed",
                    "7a328d13-28a6-442b-bcc0-266ca20368f5",
                    "sha256-" + "e" * 64, "sha256-" + "f" * 64,
                    "sha256-" + "0" * 64, tool_bundle_id=tools["toolBundleId"])
                self.assertEqual("unknown", result["state"])
                self.assertFalse(result["replayAllowed"])
                self.assertTrue((dispatch._directory(root) / CORR / "dispatch.json").is_file())
                self.assertTrue((dispatch._shared_directory(root) / "lease-archlinux-api35.json").is_file())
                self.assertEqual(1, submitted.call_count)
                recorded=dispatch._local_intent(root,CORR)
                self.assertEqual('a'*40,recorded['sourceSha']);self.assertEqual('a'*40,recorded['remote']['sourceSha'])
                self.assertEqual(tools['toolBundleId'],recorded['toolBundleId'])
                self.assertEqual({key:tools[key] for key in ('toolBundleId','reviewedTreeSha256','manifest')},recorded['remote']['toolBundle'])
                with self.assertRaises(FileExistsError):
                    dispatch.start(root, "archlinux", "api35", CORR, "a" * 40,
                        "sha256-" + "b" * 64, "sha256-" + "c" * 64,
                        "5a328d13-28a6-442b-bcc0-266ca20368f5",
                        "6a328d13-28a6-442b-bcc0-266ca20368f5",
                        "owner", 4, "d" * 64, "installed",
                        "7a328d13-28a6-442b-bcc0-266ca20368f5",
                        "sha256-" + "e" * 64, "sha256-" + "f" * 64,
                        "sha256-" + "0" * 64, tool_bundle_id=tools["toolBundleId"])
                self.assertEqual(1, submitted.call_count)


    def test_actual_remote_tool_manifest_rejection_occurs_before_worker_launch(self):
        from agent_tools import android_installer_tool_bundle as bundle
        for attack in ('manifest-hash','file-binding','bad-id'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as raw:
                root=Path(raw);root.chmod(0o700)
                files=[{'name':'bundle/'+name,'size':5,'sha256':hashlib.sha256(b'pass\n').hexdigest()} for name in bundle.FILES]
                product=json.dumps({'correlationId':CORR,'host':'archlinux','device':'api35','pair':{'sourceSha':'a'*40}}).encode()
                files.append({'name':'output/intent.json','size':len(product),'sha256':hashlib.sha256(product).hexdigest()})
                manifest={'schema':1,'kind':'android-installer-reviewed-tools','files':[{'path':name,'size':5,'sha256':hashlib.sha256(b'pass\n').hexdigest()} for name in bundle.FILES]}
                tools={'toolBundleId':'sha256-'+'1'*64,'reviewedTreeSha256':hashlib.sha256(bundle._bytes(manifest)).hexdigest(),'manifest':manifest}
                if attack=='manifest-hash':tools['reviewedTreeSha256']='0'*64
                elif attack=='file-binding':manifest['files'][0]['sha256']='0'*64;tools['reviewedTreeSha256']=hashlib.sha256(bundle._bytes(manifest)).hexdigest()
                else:tools['toolBundleId']='invalid'
                expected={'sourceSha':'a'*40,'files':files,'toolBundle':tools}
                result=subprocess.run([sys.executable,'-I','-B','-c','exec('+repr(dispatch._REMOTE)+')','start',str(root),'archlinux','api35',CORR,json.dumps(expected)],input=b'pass\n'*7+product,capture_output=True,timeout=5)
                self.assertEqual(0,result.returncode,result.stderr);value=json.loads(result.stdout)
                self.assertEqual('unknown',value['state']);self.assertIn(value['reason'],{'tool_bundle_invalid','tool_bundle_manifest_changed'})
                self.assertFalse((root/('android-installer-'+CORR)/'launch-intent.json').exists())
                self.assertFalse((root/('android-installer-'+CORR)/'identity.json').exists())

    def test_generated_remote_tool_generation_marker_rejects_same_byte_rewrite(self):
        import ast,re,stat
        from agent_tools import android_installer_tool_bundle as bundle
        with tempfile.TemporaryDirectory() as raw:
            job=Path(raw);files=[]
            for name in bundle.FILES:
                path=job/'bundle'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'reviewed');path.chmod(0o600)
                files.append({'name':'bundle/'+name,'size':8,'sha256':hashlib.sha256(b'reviewed').hexdigest()})
            manifest={'schema':1,'kind':'android-installer-reviewed-tools','files':[{'path':name,'size':8,'sha256':hashlib.sha256(b'reviewed').hexdigest()} for name in bundle.FILES]}
            expected={'files':files,'toolBundle':{'toolBundleId':'sha256-'+'1'*64,'reviewedTreeSha256':hashlib.sha256(bundle._bytes(manifest)).hexdigest(),'manifest':manifest}}
            def unknown(reason):raise ValueError(reason)
            def put(path,data):
                path.write_bytes(data);path.chmod(0o600)
            environment={'job':job,'expected':expected,'action':'start','tool_stream_pins':{},'os':os,'stat':stat,'re':re,'hashlib':hashlib,'json':json,'unknown':unknown,'put':put,'private':lambda path,limit:path.read_bytes()}
            tree=ast.parse(dispatch._REMOTE)
            functions=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in {'tool_file_pin','verify_tool_bundle'}]
            exec(compile(ast.Module(body=functions,type_ignores=[]),'<actual-tool-guards>','exec'),environment)
            environment['verify_tool_bundle']()
            self.assertTrue((job/'tool-bundle-owned.json').exists())
            environment['action']='status';environment['verify_tool_bundle']()
            path=job/'bundle'/bundle.FILES[0];path.write_bytes(path.read_bytes())
            with self.assertRaisesRegex(ValueError,'tool_bundle_generation_changed'):environment['verify_tool_bundle']()

if __name__ == "__main__":
    unittest.main()
