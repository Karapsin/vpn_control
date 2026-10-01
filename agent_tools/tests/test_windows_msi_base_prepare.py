from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import tempfile
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_tools import windows_msi_base_prepare as base


CORR = "05fd80ad-b93f-4450-a3e5-a67d14f24478"
SOURCE = "a" * 40
ARTIFACT = "sha256-" + "b" * 64
REQUEST = {"host": "archlinux", "correlationId": CORR, "sourceSha": SOURCE,
           "fixtureReceiptArtifactId": ARTIFACT, "baseMsiArtifactId": ARTIFACT,
           "targetMsiArtifactId": ARTIFACT, "expectedCurrentVersion": "2.1.17"}
PAIR = {"sourceSha": SOURCE, "sourceFingerprint": "c" * 64,
        "receiptArtifactId": ARTIFACT, "baseArtifactId": ARTIFACT,
        "targetArtifactId": ARTIFACT, "baseVersion": "2.1.19", "targetVersion": "2.2.0",
        "baseCliSha256": "d" * 64, "baseAppJarSha256": "e" * 64,
        "baseHelperSha256": "f" * 64, "baseRuntimeSha256": "1" * 64,
        "baseAppJarName": "desktopApp-2.1.19.jar", "targetMsiSha256": "b" * 64,
        "targetMsiSize": 211}
STAGE_SIZE = 131


def _run_preverified_base_stage(proof: dict) -> tuple[dict, list[str]] | None:
    """Execute the actual base stage with a fake QGA, without any MSI stdin."""
    if not Path("/proc/self/stat").is_file():
        return None
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); root.chmod(0o700)
        socket_path = str(root / "qga.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(socket_path); server.listen(3); server.settimeout(3)
        ticks = Path("/proc/self/stat").read_text().split()[21]
        command = b"fixed bootstrap"
        encoded = base64.b64encode(command).decode()
        digest = __import__("hashlib").sha256(command).hexdigest()
        commands: list[str] = []

        def receive(connection):
            raw = bytearray()
            while not raw.endswith(b"\n"):
                chunk = connection.recv(4096)
                if not chunk:
                    raise AssertionError("unexpected QGA EOF")
                raw.extend(chunk)
            return json.loads(raw.lstrip(b"\xff"))

        def qga_replies():
            try:
                for index in range(3 if proof.get("sha256") == "b" * 64 else 2):
                    connection, _ = server.accept()
                    with connection:
                        sync = receive(connection)
                        connection.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                        request = receive(connection)
                        commands.append(request["execute"])
                        if index == 0:
                            value = {"pid": 41}
                        elif index == 1:
                            value = {"exited": True, "exitcode": 0,
                                     "out-data": base64.b64encode(json.dumps(proof).encode()).decode()}
                        else:
                            value = {"pid": 42}
                        connection.sendall(json.dumps({"return": value}).encode() + b"\n")
            except socket.timeout:
                pass

        worker = threading.Thread(target=qga_replies); worker.start()
        try:
            guard = base.campaign_lease.remote_role_guard()
            program = base._STAGE.replace(guard, "def require_campaign_role(*args): pass\n")
            args = [str(root), "windows-cp117", CORR, CORR, socket_path,
                    str(os.getpid()), ticks, "S-1-5-21-1-2-3-1002", "1", encoded,
                    digest, SOURCE, PAIR["sourceFingerprint"], ARTIFACT, ARTIFACT,
                    ARTIFACT, "preverified"]
            completed = subprocess.run([__import__("sys").executable, "-c", program, *args],
                                       input=b"", capture_output=True, timeout=8, check=False)
        finally:
            worker.join(timeout=4); server.close()
        if worker.is_alive():
            raise AssertionError("fake QGA did not stop")
        if completed.returncode != 0:
            raise AssertionError(completed.stderr.decode())
        return json.loads(completed.stdout), commands


def _run_qga_status_program(status_value, *, program=base._STATUS):
    """Run the actual remote observer against one bounded fake QGA reply."""
    if not Path("/proc/self/stat").is_file():
        return None
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        socket_path = str(root / "qga.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(socket_path)
        server.listen(1)
        ticks = Path("/proc/self/stat").read_text().split()[21]
        stage = root / "windows-cp117" / "windows-msi-base" / CORR
        stage.mkdir(mode=0o700, parents=True)
        for parent in (root / "windows-cp117", root / "windows-cp117" / "windows-msi-base"):
            parent.chmod(0o700)
        binding = {"socketPath": socket_path, "pid": os.getpid(), "startTicks": int(ticks),
                   "sourceSha": SOURCE, "sourceFingerprint": PAIR["sourceFingerprint"],
                   "receiptArtifactId": ARTIFACT, "baseArtifactId": ARTIFACT,
                   "targetArtifactId": ARTIFACT, "commandSha256": "0" * 64,
                   "expectedSid": "S-1-5-21-1-2-3-1002"}
        (stage / "binding.json").write_text(json.dumps(binding))
        (stage / "dispatch.json").write_text(json.dumps({"pid": 1}))

        def receive(connection):
            data = bytearray()
            while not data.endswith(b"\n"):
                data.extend(connection.recv(4096))
            return bytes(data)

        def qga_once():
            connection, _ = server.accept()
            with connection:
                sync = json.loads(receive(connection)[1:])
                connection.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                request = json.loads(receive(connection))
                if request.get("execute") != "guest-exec-status":
                    raise AssertionError("unexpected QGA request")
                connection.sendall(json.dumps({"return": status_value}).encode() + b"\n")

        worker = threading.Thread(target=qga_once)
        worker.start()
        try:
            command = [__import__("sys").executable, "-c", program, str(root), "windows-cp117", CORR,
                       socket_path, str(os.getpid()), ticks, SOURCE, PAIR["sourceFingerprint"], ARTIFACT,
                       ARTIFACT, ARTIFACT, "0" * 64, "S-1-5-21-1-2-3-1002"]
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        finally:
            worker.join(timeout=5)
            server.close()
        if worker.is_alive():
            raise AssertionError("QGA observer did not finish")
        if completed.returncode != 0:
            raise AssertionError(completed.stderr.decode())
        return json.loads(completed.stdout)


def _run_dispatch_absent_program(replies, *, program=base._DIAGNOSTIC):
    """Execute the embedded absent-dispatch observer against bounded QGA replies."""
    if not Path("/proc/self/stat").is_file():
        return None
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        socket_path = str(root / "qga.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(socket_path)
        server.listen(1)
        ticks = Path("/proc/self/stat").read_text().split()[21]
        stage = root / "windows-cp117" / "windows-msi-base" / CORR
        stage.mkdir(mode=0o700, parents=True)
        for parent in (root / "windows-cp117", root / "windows-cp117" / "windows-msi-base"):
            parent.chmod(0o700)
        binding = {"socketPath": socket_path, "pid": os.getpid(), "startTicks": int(ticks),
                   "sourceSha": SOURCE, "sourceFingerprint": PAIR["sourceFingerprint"],
                   "receiptArtifactId": ARTIFACT, "baseArtifactId": ARTIFACT,
                   "targetArtifactId": ARTIFACT, "commandSha256": "0" * 64,
                   "expectedSid": "S-1-5-21-1-2-3-1002"}
        (stage / "binding.json").write_text(json.dumps(binding))

        def receive(connection):
            data = bytearray()
            while not data.endswith(b"\n"):
                data.extend(connection.recv(4096))
            return bytes(data)

        def qga_replies():
            for expected, reply in replies:
                connection, _ = server.accept()
                with connection:
                    sync = json.loads(receive(connection)[1:])
                    connection.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                    request = json.loads(receive(connection))
                    if request["execute"] != expected:
                        raise AssertionError((request["execute"], expected))
                    connection.sendall(json.dumps({"return": reply}).encode() + b"\n")

        worker = threading.Thread(target=qga_replies)
        worker.start()
        try:
            command = [__import__("sys").executable, "-c", program, str(root), "windows-cp117", CORR,
                       socket_path, str(os.getpid()), ticks, SOURCE, PAIR["sourceFingerprint"], ARTIFACT,
                       ARTIFACT, ARTIFACT, "0" * 64, "S-1-5-21-1-2-3-1002"]
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        finally:
            worker.join(timeout=5)
            server.close()
        if worker.is_alive():
            raise AssertionError("QGA observer did not finish")
        if completed.returncode != 0:
            raise AssertionError(completed.stderr.decode())
        return json.loads(completed.stdout)


def _run_stage_diagnostic_program(replies):
    """Exercise the guest-side MSI hash observer through its real QGA protocol."""
    if not Path("/proc/self/stat").is_file():
        return None
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); root.chmod(0o700)
        socket_path = str(root / "qga.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(socket_path); server.listen(1)
        ticks = Path("/proc/self/stat").read_text().split()[21]
        stage = root / "windows-cp117" / "windows-msi-base" / CORR
        stage.mkdir(mode=0o700, parents=True)
        for parent in (root / "windows-cp117", root / "windows-cp117" / "windows-msi-base"):
            parent.chmod(0o700)
        binding = {"socketPath": socket_path, "pid": os.getpid(), "startTicks": int(ticks),
                   "sourceSha": SOURCE, "sourceFingerprint": PAIR["sourceFingerprint"],
                   "receiptArtifactId": ARTIFACT, "baseArtifactId": ARTIFACT,
                   "targetArtifactId": ARTIFACT, "commandSha256": "0" * 64,
                   "expectedSid": "S-1-5-21-1-2-3-1002"}
        binding_path = stage / "binding.json"; binding_path.write_text(json.dumps(binding))
        before = (tuple(sorted(item.name for item in stage.iterdir())), binding_path.read_bytes())

        def receive(connection):
            data = bytearray()
            while not data.endswith(b"\n"):
                chunk = connection.recv(4096)
                if not chunk:
                    raise AssertionError("unexpected QGA EOF")
                data.extend(chunk)
            return bytes(data)

        def qga_replies():
            for expected, reply in replies:
                connection, _ = server.accept()
                with connection:
                    sync = json.loads(receive(connection)[1:])
                    connection.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                    request = json.loads(receive(connection))
                    if request.get("execute") != expected:
                        raise AssertionError((request.get("execute"), expected))
                    connection.sendall(json.dumps({"return": reply}).encode() + b"\n")

        worker = threading.Thread(target=qga_replies); worker.start()
        try:
            command = [__import__("sys").executable, "-c", base._STAGE_DIAGNOSTIC, str(root), "windows-cp117", CORR,
                       socket_path, str(os.getpid()), ticks, SOURCE, PAIR["sourceFingerprint"], ARTIFACT,
                       ARTIFACT, ARTIFACT, "0" * 64, "S-1-5-21-1-2-3-1002", str(STAGE_SIZE)]
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        finally:
            worker.join(timeout=5); server.close()
        if worker.is_alive():
            raise AssertionError("stage observer did not finish")
        if completed.returncode != 0:
            raise AssertionError(completed.stderr.decode())
        after = (tuple(sorted(item.name for item in stage.iterdir())), binding_path.read_bytes())
        return json.loads(completed.stdout), before == after


def _run_unknown_cleanup_program(replies, *, mode: str, stage: str, polls: int = 40) -> tuple[dict, bool]:
    """Execute the real uncertain-cleanup program through a fake QGA socket.

    The production program proves QEMU ownership through Linux procfs.  This
    host-only harness substitutes that single predicate while retaining the
    socket protocol, encoded PowerShell launch, status envelopes, and remote
    stage filesystem behavior.
    """
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); root.chmod(0o700)
        socket_path = str(root / "qga.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(socket_path); server.listen(1)
        group = root / "windows-cp117" / "windows-msi-base"
        group.mkdir(mode=0o700, parents=True); (root / "windows-cp117").chmod(0o700)
        stage_path = group / base._UNKNOWN_CLOSURE_CORRELATION
        stage_path.mkdir(mode=0o700)
        if stage == "bound":
            binding = {"socketPath": socket_path, "pid": 4321, "startTicks": 98765,
                       "sourceSha": base._UNKNOWN_CLOSURE_REQUEST["sourceSha"],
                       "sourceFingerprint": "a" * 64,
                       "receiptArtifactId": base._UNKNOWN_CLOSURE_REQUEST["fixtureReceiptArtifactId"],
                       "baseArtifactId": base._UNKNOWN_CLOSURE_REQUEST["baseMsiArtifactId"],
                       "targetArtifactId": base._UNKNOWN_CLOSURE_REQUEST["targetMsiArtifactId"],
                       "commandSha256": base._UNKNOWN_CLOSURE_COMMAND_SHA256,
                       "expectedSid": "S-1-5-21-1-2-3-1002"}
            (stage_path / "binding.json").write_text(json.dumps(binding))
        elif stage != "empty":
            raise AssertionError(stage)

        def receive(connection):
            data = bytearray()
            while not data.endswith(b"\n"):
                chunk = connection.recv(4096)
                if not chunk: raise AssertionError("unexpected QGA EOF")
                data.extend(chunk)
            return bytes(data)

        counter = 0
        def qga_worker():
            nonlocal counter
            try:
                while replies:
                    try: connection, _ = server.accept()
                    except OSError: return
                    with connection:
                        sync = json.loads(receive(connection)[1:])
                        connection.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                        request = json.loads(receive(connection))
                        if request["execute"] == "guest-exec":
                            counter += 1
                            if replies and isinstance(replies[0], tuple) and replies[0][0] == "exec":
                                response = replies.pop(0)[1]
                            else:
                                response = {"pid": counter}
                            connection.sendall(json.dumps({"return": response}).encode() + b"\n")
                        elif request["execute"] == "guest-exec-status":
                            connection.sendall(json.dumps({"return": replies.pop(0)}).encode() + b"\n")
                        else:
                            raise AssertionError(request["execute"])
            finally:
                server.close()

        worker = threading.Thread(target=qga_worker)
        worker.start()
        # Do not relax parsing or cleanup semantics: only replace the host's
        # procfs ownership proof with the exact fixture socket identity.
        program = base._UNKNOWN_CLEANUP.replace(
            "if env!='windows-cp117' or mode not in ('status','cleanup') or not live(sock,pid,ticks):raise ValueError()",
            "if env!='windows-cp117' or mode not in ('status','cleanup') or (sock!='" + socket_path + "' or pid!='4321' or ticks!='98765'):raise ValueError()")
        program = program.replace("for _ in range(40):", "for _ in range(" + str(polls) + "):" )
        command = [__import__("sys").executable, "-c", program, str(root), "windows-cp117",
                   base._UNKNOWN_CLOSURE_CORRELATION, socket_path, "4321", "98765",
                   base._UNKNOWN_CLOSURE_REQUEST["sourceSha"], "a" * 64,
                   base._UNKNOWN_CLOSURE_REQUEST["fixtureReceiptArtifactId"],
                   base._UNKNOWN_CLOSURE_REQUEST["baseMsiArtifactId"],
                   base._UNKNOWN_CLOSURE_REQUEST["targetMsiArtifactId"],
                   base._UNKNOWN_CLOSURE_COMMAND_SHA256, "S-1-5-21-1-2-3-1002", mode]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        server.close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise AssertionError("cleanup QGA worker did not finish")
        if completed.returncode != 0:
            raise AssertionError(completed.stderr.decode())
        result = json.loads(completed.stdout)
        return result, stage_path.exists()


class BasePrepareTests(unittest.TestCase):
    def test_terminal_reconcile_survives_consumed_bootstrap_status_only_with_durable_proof(self):
        """A terminal QGA status can be read once; later reads must use bound facts."""
        intent = {"environment": "windows-cp117", "socketPath": "/private/qga.sock",
                  "pid": 100, "startTicks": 200, "expectedSid": "S-1-5-21-1-2-3-1002",
                  "request": dict(REQUEST), "pair": dict(PAIR), "commandSha256": "0" * 64}
        descriptor = ("windows-cp117", "/private/qga.sock", 100, 200, "S-1-5-21-1-2-3-1002")
        payload = {"version": 1, "correlationId": CORR, "stage": "READBACK", "result": "PASSED",
                   "exitCode": 0, "originalSid": descriptor[-1], "sessionId": 1, "limited": True,
                   "msiSha256": "b" * 64, "installedVersion": "2.1.19",
                   "cliSha256": "d" * 64, "jarSha256": "e" * 64, "helperSha256": "f" * 64,
                   "priorProducts": [{"version": "2.1.17", "productCode": "{11111111-1111-1111-1111-111111111111}",
                                      "installLocation": "C:\\Users\\vpncp117\\AppData\\Local\\vpn-control", "hive": "HKCU"}],
                   "installedProducts": [{"version": "2.1.19", "productCode": "{22222222-2222-2222-2222-222222222222}",
                                          "installLocation": "C:\\Users\\vpncp117\\AppData\\Local\\vpn-control", "hive": "HKCU"}]}
        with (patch.object(base, "_private_intent", return_value=intent),
              patch.object(base, "_stage_artifact_readonly", return_value=(dict(PAIR), STAGE_SIZE)),
              patch.object(base, "_descriptor", return_value=(object(), type("T", (), {"fixture_transfer_root": Path("/private")})(), descriptor)),
              patch.object(base, "status", return_value={"state": "unknown", "correlationId": CORR, "replayAllowed": False}),
              patch.object(base, "_remote", return_value=json.dumps({"state": "observed", "correlationId": CORR,
                                                                      "result": payload}).encode())):
            recovered = base.terminal_reconcile(Path.cwd(), {"correlationId": CORR})
        self.assertEqual(recovered["state"], "terminal")
        self.assertFalse(recovered["replayAllowed"])
        self.assertEqual(recovered["baseArtifactId"], ARTIFACT)
        intent["startTicks"] = 201
        with (patch.object(base, "_private_intent", return_value=intent),
              patch.object(base, "_stage_artifact_readonly", return_value=(dict(PAIR), STAGE_SIZE)),
              patch.object(base, "_descriptor", return_value=(object(), type("T", (), {"fixture_transfer_root": Path("/private")})(), descriptor)),
              patch.object(base, "_remote") as remote):
            self.assertEqual(base.terminal_reconcile(Path.cwd(), {"correlationId": CORR})["state"], "unknown")
            remote.assert_not_called()
        intent["startTicks"] = 200
        for corrupted in (dict(payload, result="IN_PROGRESS"), dict(payload, cliSha256="0" * 64),
                          dict(payload, extra=True)):
            with (patch.object(base, "_private_intent", return_value=intent),
                  patch.object(base, "_stage_artifact_readonly", return_value=(dict(PAIR), STAGE_SIZE)),
                  patch.object(base, "_descriptor", return_value=(object(), type("T", (), {"fixture_transfer_root": Path("/private")})(), descriptor)),
                  patch.object(base, "_remote", return_value=json.dumps({"state": "observed", "correlationId": CORR,
                                                                          "result": corrupted}).encode())):
                self.assertEqual(base.terminal_reconcile(Path.cwd(), {"correlationId": CORR})["state"], "unknown")
        self.assertIn("Get-ScheduledTaskInfo", base._TERMINAL_PS)
        self.assertIn("$principalSid -cne $sid", base._TERMINAL_PS)
        self.assertIn("$actualAction -cne $expectedAction", base._TERMINAL_PS)
        self.assertIn("Parser]::ParseInput", base._terminal_reconcile_powershell_preflight_script())
        self.assertLess(len(base64.b64encode(base._terminal_reconcile_powershell_preflight_script().encode("utf-16le"))), 30000)

    def test_terminal_remote_uses_fresh_read_only_guest_probe_after_bootstrap_pid_is_gone(self):
        payload = {"version": 1, "correlationId": CORR, "stage": "READBACK", "result": "PASSED",
                   "exitCode": 0, "originalSid": "S-1-5-21-1-2-3-1002", "sessionId": 1,
                   "limited": True, "msiSha256": "b" * 64, "installedVersion": "2.1.19",
                   "cliSha256": "d" * 64, "jarSha256": "e" * 64, "helperSha256": "f" * 64,
                   "priorProducts": [], "installedProducts": []}
        proof = json.dumps({"version": 1, "correlationId": CORR, "result": payload}).encode()
        stub = '''import base64,json,os,stat,sys
def live(*args):return True
def decode(value):return value.decode()
def call(sock,command,args):
 if command=='guest-exec':
  script=base64.b64decode(args['arg'][-1]).decode('utf-16le')
  if 'Get-ScheduledTaskInfo' not in script or 'Get-FileHash' not in script:raise ValueError('missing proof')
  return {'pid':42}
 if command=='guest-exec-status':
  if args!={'pid':42}:raise ValueError('retired bootstrap pid was queried')
  return {'exited':True,'exitcode':0,'out-data':base64.b64encode(PROOF).decode()}
 raise ValueError('unexpected QGA action')
'''.replace("PROOF", repr(proof))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / "windows-cp117" / "windows-msi-base" / CORR
            stage.mkdir(parents=True, mode=0o700)
            binding = {"socketPath": "/private/qga.sock", "pid": 100, "startTicks": 200,
                       "sourceSha": SOURCE, "sourceFingerprint": PAIR["sourceFingerprint"],
                       "receiptArtifactId": ARTIFACT, "baseArtifactId": ARTIFACT,
                       "targetArtifactId": ARTIFACT, "commandSha256": "0" * 64,
                       "expectedSid": "S-1-5-21-1-2-3-1002"}
            (stage / "binding.json").write_text(json.dumps(binding))
            (stage / "dispatch.json").write_text(json.dumps({"pid": 1}))
            program = stub + base._TERMINAL_RECONCILE[len(base._QGA):]
            args = [str(root), "windows-cp117", CORR, "/private/qga.sock", "100", "200",
                    SOURCE, PAIR["sourceFingerprint"], ARTIFACT, ARTIFACT, ARTIFACT,
                    "0" * 64, "S-1-5-21-1-2-3-1002", "1" * 64, "d" * 64, "e" * 64,
                    "f" * 64, "desktopApp-2.1.19.jar"]
            run = subprocess.run([__import__("sys").executable, "-c", program, *args],
                                 capture_output=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
        self.assertEqual(json.loads(run.stdout), {"state": "observed", "correlationId": CORR,
                                                   "result": payload})
    def test_exact_request_and_canonical_correlation(self):
        self.assertEqual(base._request(REQUEST), REQUEST)
        for change in ({"host": "other"}, {"extra": 1}, {"correlationId": CORR.upper()},
                       {"baseMsiArtifactId": "b" * 64}):
            value = dict(REQUEST, **change)
            with self.assertRaises(base.WindowsMsiBasePrepareError):
                base._request(value)

    def test_original_user_task_binds_msi_and_installed_bytes(self):
        body = base._task(CORR, PAIR, "2.1.17", "S-1-5-21-1-2-3-1002")
        for token in ("SessionId", "RunLevel Limited", "msiexec.exe", "MSIINSTALLPERUSER=1",
                      "S-1-5-21-1-2-3-1002", PAIR["baseCliSha256"], PAIR["baseHelperSha256"],
                      "Get-FileHash", "DisplayVersion"):
            if token == "RunLevel Limited":
                self.assertIn("RunLevel Limited", base._bootstrap(CORR, PAIR, "2.1.17", "S-1-5-21-1-2-3-1002"))
            else:
                self.assertIn(token, body)
        self.assertIn("HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", body)

    def test_product_inventory_accepts_only_one_exact_hklm_or_hkcu_registration(self):
        product = {"version": "2.1.19", "productCode": "{6C1D6870-76CD-3552-9176-F6AE1A3E268E}",
                   "installLocation": "C:\\Users\\vpncp117\\AppData\\Local\\vpn-control\\", "hive": "HKCU"}
        self.assertTrue(base._unique_product([product], "2.1.19"))
        self.assertFalse(base._unique_product([product, dict(product, hive="HKLM")], "2.1.19"))
        self.assertFalse(base._unique_product([dict(product, version="2.1.17")], "2.1.19"))
        self.assertFalse(base._unique_product([dict(product, installLocation="C:\\Other")], "2.1.19"))

    def test_downgrade_is_rejected_before_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            newer = dict(REQUEST, expectedCurrentVersion="2.2.0")
            with patch.object(base.windows_msi_public_scenario, "_admit_pair", return_value=PAIR):
                with self.assertRaisesRegex(base.WindowsMsiBasePrepareError, "newer"):
                    base._admit(Path(directory), newer)

    def test_transfer_timeout_is_bounded_and_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "base.msi"
            package.write_bytes(b"source")
            with patch.object(base.windows_credential_probe_ssh, "_remote_command", return_value=("python3", "-c", "pass")), \
                 patch.object(base.ssh_transport, "build_ssh_argv", return_value=["ssh", "archlinux"]) as argv, \
                 patch.object(base.subprocess, "run", side_effect=subprocess.TimeoutExpired("ssh", 1800)) as run:
                self.assertIsNone(base._remote(object(), "", (), package, 1800))
                self.assertEqual(run.call_args.kwargs["timeout"], 1800)
                self.assertEqual(argv.call_args.args[2], 60)
                self.assertTrue(run.call_args.kwargs["stdin"].closed)

    def test_stage_reports_only_bounded_phase_and_total_written_offset_on_uncertainty(self):
        self.assertIn("'phase':phase", base._STAGE)
        self.assertIn("'offset':min(max(transferred,0),max(size,0))", base._STAGE)
        self.assertNotIn("stderr", base._STAGE)
        self.assertNotIn("repr(", base._STAGE)

    def test_start_projects_bounded_stage_failure_without_replaying(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "base.msi"; source.write_bytes(b"fixture")
            class Target: fixture_transfer_root = Path("/private/cp117")
            descriptor = (object(), Target(), ("windows-cp117", "/qga.sock", 4321, 98765,
                                                "S-1-5-21-1-2-3-1002"))
            envelope = {"state": "unknown", "reason": "submission-uncertain", "correlationId": CORR,
                        "phase": "guest-file-open", "offset": 14 * 49152}
            with patch.object(base, "_private_intent", return_value=None), \
                 patch.object(base, "_admit", return_value=(PAIR, source, 131101044)), \
                 patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_require_reconciled_legacy"), \
                 patch.object(base, "_require_base_route_free"), \
                 patch.object(base.ssh_transport, "build_ssh_argv"), \
                 patch.object(base, "_reserve") as reserve, \
                 patch.object(base, "_open_base_campaign"), \
                 patch.object(base, "_remote", return_value=json.dumps(envelope)) as remote:
                result = base.start(root, REQUEST)
            self.assertEqual(result, {"state": "unknown", "correlationId": CORR,
                                      "stagePhase": "guest-file-open", "stageOffset": 14 * 49152,
                                      "replayAllowed": False})
            reserve.assert_called_once()
            remote.assert_called_once()

    def test_transfer_preflight_is_source_bound_read_only_and_fails_closed(self):
        correlation = base._TRANSFER_RECOVERY_CORRELATION
        request = base._TRANSFER_RECOVERY_REQUEST
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / base._LOCAL
            journal.mkdir(mode=0o700, parents=True)
            intent = {"request": request, "pair": {"sourceFingerprint": "a" * 64},
                      "environment": "windows-cp117", "socketPath": "/qga.sock", "pid": 4321,
                      "startTicks": 98765, "expectedSid": "S-1-5-21-1-2-3-1002",
                      "commandSha256": base._TRANSFER_RECOVERY_COMMAND_SHA256, "leaseId": correlation}
            path = journal / (correlation + ".json")
            path.write_text(json.dumps(intent)); path.chmod(0o600)
            class Target: fixture_transfer_root = Path("/private/cp117")
            descriptor = (object(), Target(), ("windows-cp117", "/qga.sock", 4321, 98765,
                                                "S-1-5-21-1-2-3-1002"))
            with patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_stage_artifact_readonly", return_value=({}, 131101044)), \
                 patch.object(base, "_remote", return_value=json.dumps(
                     {"state": "observed", "qga": "healthy", "disk": "enough"})) as remote:
                self.assertEqual(base.transfer_preflight(root, {"correlationId": correlation})["state"], "ready")
                self.assertIs(remote.call_args.args[1], base._TRANSFER_PREFLIGHT)
                self.assertIsNone(remote.call_args.args[3])
                remote.return_value = json.dumps({"state": "observed", "qga": "healthy", "disk": "insufficient"})
                self.assertEqual(base.transfer_preflight(root, {"correlationId": correlation})["state"], "blocked")
                remote.return_value = json.dumps({"state": "observed", "qga": "healthy", "disk": "enough", "extra": True})
                self.assertEqual(base.transfer_preflight(root, {"correlationId": correlation})["state"], "unknown")

    def test_transfer_network_admission_is_bound_and_rejects_nonexact_qga_projection(self):
        correlation = base._TRANSFER_RECOVERY_CORRELATION
        request = base._TRANSFER_RECOVERY_REQUEST
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / base._LOCAL
            journal.mkdir(mode=0o700, parents=True)
            intent = {"request": request, "pair": {"sourceFingerprint": "a" * 64},
                      "environment": "windows-cp117", "socketPath": "/qga.sock", "pid": 4321,
                      "startTicks": 98765, "expectedSid": "S-1-5-21-1-2-3-1002",
                      "commandSha256": base._TRANSFER_RECOVERY_COMMAND_SHA256, "leaseId": correlation}
            path = journal / (correlation + ".json")
            path.write_text(json.dumps(intent)); path.chmod(0o600)
            class Target: fixture_transfer_root = Path("/private/cp117")
            descriptor = (object(), Target(), ("windows-cp117", "/qga.sock", 4321, 98765,
                                                "S-1-5-21-1-2-3-1002"))
            observed = {"state": "observed", "qga": "healthy", "qemuNetwork": "user-mode",
                        "guestGateway": "slirp-gateway"}
            with patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_remote", return_value=json.dumps(observed)) as remote:
                result = base.transfer_network_admission(root, {"correlationId": correlation})
                self.assertEqual(result["state"], "ready")
                self.assertEqual(result["hostBindAddress"], "127.0.0.1")
                self.assertEqual(result["guestHostAddress"], "10.0.2.2")
                self.assertIs(remote.call_args.args[1], base._TRANSFER_NETWORK_ADMISSION)
                self.assertIsNone(remote.call_args.args[3])
                remote.return_value = json.dumps({**observed, "extra": True})
                self.assertEqual(base.transfer_network_admission(root, {"correlationId": correlation})["state"], "unknown")
            self.assertRaises(base.WindowsMsiBasePrepareError, base.transfer_network_admission,
                              root, {"correlationId": base._UNKNOWN_CLOSURE_CORRELATION})

    def test_transfer_network_admission_program_has_no_listener_or_guest_connect(self):
        program = base._TRANSFER_NETWORK_ADMISSION
        observer = program[len(base._QGA):]
        self.assertIn("Get-NetIPConfiguration", program)
        self.assertIn("10.0.2.2", program)
        self.assertIn("os.path.basename(argv[0])!=b'qemu-system-x86_64'", program)
        self.assertNotIn("guest-file-open", observer)
        self.assertNotIn("socket.bind", observer)
        self.assertNotIn("Start-Process", observer)

    def test_transfer_network_qemu_topology_rejects_extra_or_ambiguous_nics(self):
        scope = {"os": os, "re": __import__("re")}
        exec(base._TRANSFER_NETWORK_QEMU_TOPOLOGY, scope)
        valid = [b"qemu-system-x86_64", b"-netdev", b"user,id=net0", b"-device",
                 b"virtio-net-pci,netdev=net0"]
        network_models = {b"e1000", b"igb", b"i82550", b"usb-net", b"virtio-net-pci"}
        self.assertTrue(scope["single_user_network"](valid, network_models.__contains__))
        for invalid in (
                valid + [b"-device", b"e1000"],
                valid + [b"-device", b"igb"],
                valid + [b"-device", b"i82550"],
                valid + [b"-device", b"usb-net"],
                valid + [b"-netdev", b"tap,id=extra"],
                [b"qemu-system-x86_64", b"-nic", b"user", b"-device", b"virtio-net-pci"],
                [b"qemu-system-x86_64", b"-netdev", b"user,id=net0", b"-device",
                 b"virtio-net-pci,netdev=other"],
        ):
            with self.assertRaises(ValueError):
                scope["single_user_network"](invalid, network_models.__contains__)
        self.assertTrue(scope["single_user_network"](
            valid + [b"-device", b"virtio-blk-pci,drive=data"], network_models.__contains__))
        self.assertIn("$adapters.Count -ne 1", base._TRANSFER_NETWORK_ADMISSION)

    def test_second_reviewed_unknown_close_profile_keeps_its_exact_correlation(self):
        correlation = base._TRANSFER_RECOVERY_CORRELATION
        intent = {"request": base._TRANSFER_RECOVERY_REQUEST,
                  "pair": {"sourceFingerprint": "a" * 64},
                  "commandSha256": base._TRANSFER_RECOVERY_COMMAND_SHA256}
        census = {"state": "observed", "correlationId": correlation, "remoteStage": "present",
                  "mutation": "none", "task": "absent", "leaf": "present", "result": "absent",
                  "correlationPowerShell": "absent", "product": "single", "installedVersion": "2.1.17",
                  "installer": "absent"}
        class Target: fixture_transfer_root = Path("/private/cp117")
        descriptor = ("windows-cp117", "/qga.sock", 4321, 98765, "S-1-5-21-1-2-3-1002")
        with patch.object(base, "_remote", return_value=json.dumps(census)) as remote:
            actual = base._unknown_cleanup_census(object(), Target(), intent, descriptor, "status", correlation)
        self.assertEqual(actual, census)
        self.assertEqual(remote.call_args.args[2][2], correlation)

    def test_preflight_is_inert_and_bounded(self):
        script = base._powershell_preflight_script()
        self.assertIn("Parser]::ParseInput", script)
        self.assertNotIn("Start-ScheduledTask", script)
        self.assertNotIn("msiexec.exe", script)
        self.assertLess(len(__import__("base64").b64encode(script.encode("utf-16le"))), 30000)

    def test_preverified_powershell_parser_is_fixed_and_bounded(self):
        script = base._preverified_powershell_preflight_script()
        self.assertIn("Parser]::ParseInput", script)
        self.assertNotIn("Start-ScheduledTask", script)
        self.assertNotIn("msiexec.exe", script)
        self.assertLess(len(base64.b64encode(script.encode("utf-16le"))), 30000)
        with self.assertRaises(base.WindowsMsiBasePrepareError):
            base.powershell_preflight(Path("."), {"host": "archlinux", "profile": "arbitrary"})

    def test_preverified_profile_allows_system_owner_only_at_fixed_profile(self):
        # CP117 census: the profile is SYSTEM-owned; every app/stage leaf is user-owned.
        script = base._PREVERIFIED_PS
        self.assertIn("if($path -ceq $profile)", script)
        self.assertIn("$owner -cne $sid -and $owner -cne 'S-1-5-18'", script)
        self.assertIn("} elseif($owner -cne $sid) { throw 'OWNER' }", script)
        self.assertIn("if($owner -cne $sid) { throw 'OWNER' }", script.split("$item=Get-Item -LiteralPath $msi", 1)[1])
        self.assertEqual(script.count("S-1-5-18"), 1)

    def test_readiness_binds_product_version_idle_owner_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            descriptor = (object(), Target(), ("windows-cp117", "/qga.sock", 589342, 520739,
                       "S-1-5-21-1-2-3-1002"))
            inventory = {"version": 1, "code": "READY", "installedVersion": "2.1.17",
                         "productCount": 1, "activeCount": 0, "activeKinds": [], "activeProcesses": [],
                         "workspaceLockPid": None, "ownedExplorerCount": 1}
            with patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_remote") as remote:
                remote.return_value = json.dumps({"state": "observed", "inventory": inventory}).encode()
                self.assertEqual(base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})["state"], "ready")
                remote.return_value = json.dumps({"state": "observed", "inventory": dict(inventory, activeCount=1)}).encode()
                self.assertEqual(base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})["state"], "unknown")
                remote.return_value = json.dumps({"state": "observed", "inventory": dict(inventory, code="ACTIVE_PROCESS", activeCount=1, activeKinds=["msiexec"])}).encode()
                self.assertEqual(base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})["state"], "unknown")
                observed = dict(inventory, code="ACTIVE_PROCESS", activeCount=1,
                                activeKinds=["vpn-control-cli"], activeProcesses=[{"kind": "vpn-control-cli", "pid": 1234,
                                  "parentPid": 4, "startedAtUtc": "2026-09-28T10:00:00Z", "sessionId": 1,
                                  "originalUser": True, "role": "owner", "currentWorkspaceOwner": True}],
                                workspaceLockPid=1234)
                remote.return_value = json.dumps({"state": "observed", "inventory": observed}).encode()
                actual = base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})
                self.assertEqual(actual["activeKinds"], ["vpn-control-cli"])
                self.assertEqual(actual["activeProcesses"][0]["role"], "owner")
                remote.return_value = json.dumps({"state": "observed", "inventory": dict(observed, activeKinds=["private-process-name"])}).encode()
                self.assertEqual(base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})["state"], "unknown")
                remote.return_value = None
                self.assertEqual(base.readiness(directory, {"host": "archlinux", "expectedCurrentVersion": "2.1.17"})["state"], "unknown")

    def test_readiness_script_only_observes_cp117_state(self):
        script = base._readiness_script("2.1.17", "S-1-5-21-1-2-3-1002")
        self.assertIn("HKEY_USERS", script)
        self.assertIn("GetOwnerSid", script)
        self.assertIn("ACTIVE_PROCESS", script)
        self.assertNotIn("Start-Process", script)
        self.assertNotIn("Start-ScheduledTask", script)

    def test_unknown_submission_reserves_once_and_never_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "base.msi"
            package.write_bytes(b"x")
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            with patch.object(base, "_admit", return_value=(PAIR, package, 1)), \
                 patch.object(base, "_descriptor", return_value=(object(), Target(),
                     ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_require_reconciled_legacy"), \
                 patch.object(base.ssh_transport, "build_ssh_argv", return_value=["ssh", "archlinux"]), \
                 patch.object(base, "_open_base_campaign", return_value=CORR), \
                 patch.object(base, "_remote", return_value=None) as remote:
                result = base.start(root, REQUEST)
                self.assertEqual(result["state"], "unknown")
                self.assertFalse(result["replayAllowed"])
                self.assertEqual(base.start(root, REQUEST)["state"], "unknown")
                self.assertEqual(remote.call_count, 1)
                self.assertEqual(base._private_intent(root, CORR)["request"], REQUEST)

    def test_preverified_transfer_dispatch_never_streams_msi_through_qga(self):
        """The prior 49 KiB QGA transfer stopped before installer dispatch."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); package = root / "base.msi"; package.write_bytes(b"x")
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            ready = {"state": "ready-for-base", "correlationId": CORR,
                     "sourceSha": SOURCE, "baseMsiArtifactId": ARTIFACT,
                     "sha256": "b" * 64, "length": 1,
                     "guestPath": "C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-" + CORR + "\\base.msi",
                     "replayAllowed": False, "nativeActionAllowed": False,
                     "productAction": False}
            with patch.object(base, "_admit", return_value=(PAIR, package, 1)), \
                 patch.object(base, "_descriptor", return_value=(object(), target,
                     ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_transfer_ready_for_base", return_value=ready), \
                 patch.object(base, "_require_reconciled_legacy"), \
                 patch.object(base, "_require_base_route_free"), \
                 patch.object(base.ssh_transport, "build_ssh_argv", return_value=["ssh", "archlinux"]), \
                 patch.object(base, "_open_base_campaign", return_value=CORR), \
                 patch.object(base, "_remote", return_value=None) as remote:
                result = base.start_from_transfer(root, REQUEST)
                self.assertEqual(result["state"], "unknown")
                self.assertIsNone(remote.call_args.args[3])
                self.assertEqual(remote.call_args.args[2][-1], "preverified")
                self.assertEqual(base.start_from_transfer(root, REQUEST)["state"], "unknown")
                self.assertEqual(remote.call_count, 1)

    def test_preverified_transfer_binding_mismatch_blocks_before_base_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); package = root / "base.msi"; package.write_bytes(b"x")
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            forged = {"state": "ready-for-base", "correlationId": CORR,
                      "sourceSha": SOURCE, "baseMsiArtifactId": ARTIFACT,
                      "sha256": "0" * 64, "length": 1,
                      "guestPath": "C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-base-" + CORR + "\\base.msi",
                      "replayAllowed": False, "nativeActionAllowed": False,
                      "productAction": False}
            with patch.object(base, "_admit", return_value=(PAIR, package, 1)), \
                 patch.object(base, "_descriptor", return_value=(object(), target,
                     ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_transfer_ready_for_base", return_value=forged), \
                 patch.object(base, "_reserve") as reserve, \
                 patch.object(base, "_open_base_campaign") as campaign, \
                 patch.object(base, "_remote") as remote:
                with self.assertRaisesRegex(base.WindowsMsiBasePrepareError, "handoff"):
                    base.start_from_transfer(root, REQUEST)
                reserve.assert_not_called(); campaign.assert_not_called(); remote.assert_not_called()

    def test_preverified_stage_dispatches_only_after_guest_hash_and_owner_proof(self):
        proof = {"version": 1, "sha256": "b" * 64, "length": 1,
                 "ownerSid": "S-1-5-21-1-2-3-1002"}
        observed = _run_preverified_base_stage(proof)
        if observed is None:
            self.skipTest("Linux QGA fake needs procfs")
        result, commands = observed
        self.assertEqual(result["state"], "submitted")
        self.assertEqual(commands, ["guest-exec", "guest-exec-status", "guest-exec"])
        self.assertNotIn("guest-file-write", commands)

    def test_preverified_stage_rejects_wrong_guest_hash_before_bootstrap(self):
        proof = {"version": 1, "sha256": "0" * 64, "length": 1,
                 "ownerSid": "S-1-5-21-1-2-3-1002"}
        observed = _run_preverified_base_stage(proof)
        if observed is None:
            self.skipTest("Linux QGA fake needs procfs")
        result, commands = observed
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["phase"], "guest-file-verify")
        self.assertEqual(commands, ["guest-exec", "guest-exec-status"])

    def test_base_intent_write_failure_cannot_begin_or_claim_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); package = root / "base.msi"; package.write_bytes(b"x")
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            with patch.object(base, "_admit", return_value=(PAIR, package, 1)), \
                 patch.object(base, "_descriptor", return_value=(object(), Target(),
                    ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_require_reconciled_legacy"), \
                 patch.object(base.ssh_transport, "build_ssh_argv", return_value=["ssh", "archlinux"]), \
                 patch.object(base, "_reserve", side_effect=OSError("fsync failed")), \
                 patch.object(base.campaign_lease, "begin") as begin, \
                 patch.object(base.campaign_lease, "claim_role") as claim, \
                 patch.object(base, "_remote") as remote:
                with self.assertRaisesRegex(OSError, "fsync failed"):
                    base.start(root, REQUEST)
                begin.assert_not_called(); claim.assert_not_called(); remote.assert_not_called()

    def test_invalid_ssh_transport_fails_before_base_intent_or_campaign(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); package = root / "base.msi"; package.write_bytes(b"x")
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            with patch.object(base, "_admit", return_value=(PAIR, package, 1)), \
                 patch.object(base, "_descriptor", return_value=(object(), target,
                     ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_require_reconciled_legacy"), \
                 patch.object(base, "_require_base_route_free"), \
                 patch.object(base.ssh_transport, "build_ssh_argv", side_effect=ValueError("transport invalid")) as argv, \
                 patch.object(base, "_reserve") as reserve, \
                 patch.object(base, "_open_base_campaign") as campaign, \
                 patch.object(base, "_remote") as remote:
                with self.assertRaisesRegex(ValueError, "transport invalid"):
                    base.start(root, REQUEST)
                self.assertEqual(argv.call_args.args[2], 60)
                reserve.assert_not_called(); campaign.assert_not_called(); remote.assert_not_called()
                self.assertIsNone(base._private_intent(root, CORR))

    def test_pre_effect_status_requires_exact_failed_intent_and_guest_absence(self):
        corr = base._PRE_EFFECT_REJECTED_CORRELATION
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = {"request": dict(REQUEST, correlationId=corr), "leaseId": corr,
                      "commandSha256": base._PRE_EFFECT_REJECTED_COMMAND_SHA256,
                      "environment": "windows-cp117", "socketPath": "/qga.sock",
                      "pid": 589342, "startTicks": 520739,
                      "expectedSid": "S-1-5-21-1-2-3-1002"}
            base._reserve(root, intent)
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            descriptor = (object(), target, ("windows-cp117", "/qga.sock", 589342,
                      520739, "S-1-5-21-1-2-3-1002"))
            absent = {"state": "absent", "correlationId": corr, "qemuPid": 589342,
                      "startTicks": 520739}
            with patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_remote", return_value=json.dumps(absent).encode()) as remote:
                self.assertEqual(base.pre_effect_status(root, {"host": "archlinux"}), absent)
                self.assertIs(remote.call_args.args[1], base._PRE_EFFECT_STATUS)
            with patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_remote", return_value=json.dumps(dict(absent, state="present")).encode()):
                self.assertEqual(base.pre_effect_status(root, {"host": "archlinux"})["state"], "unknown")
            with self.assertRaises(base.WindowsMsiBasePrepareError):
                base.pre_effect_status(root, {"host": "wrong"})

    def test_failed_pre_dispatch_base_closure_preserves_intent_and_frees_only_exact_route(self):
        corr = base._PRE_EFFECT_REJECTED_CORRELATION
        sid = "S-1-5-21-1-2-3-1002"
        descriptor = ("windows-cp117", "/qga.sock", 589342, 520739, sid)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = {"request": base._PRE_EFFECT_REJECTED_REQUEST, "leaseId": corr,
                      "commandSha256": base._PRE_EFFECT_REJECTED_COMMAND_SHA256,
                      "environment": descriptor[0], "socketPath": descriptor[1],
                      "pid": descriptor[2], "startTicks": descriptor[3], "expectedSid": sid}
            base._reserve(root, intent)
            original = base._private_intent(root, corr)
            identity = base._campaign_identity(base._PRE_EFFECT_REJECTED_REQUEST, descriptor)
            def remote(action, request):
                desired = request["desired"]
                return json.dumps({"version": 1, "action": action, "leaseId": corr,
                                   "recordSha256": base.campaign_lease._digest(desired),
                                   "state": "confirmed"}).encode()
            self.assertEqual(base.campaign_lease.begin(root, identity, remote)["state"], "active")
            self.assertEqual(base.campaign_lease.claim_role(root, corr, "base", corr, remote)["state"], "role-active")
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            observed = {"state": "absent", "correlationId": corr, "qemuPid": 589342,
                        "startTicks": 520739}
            idle = {"state": "ready", "ready": True, "code": "READY", "installedVersion": "2.1.17",
                    "productCount": 1, "activeCount": 0, "activeProcesses": []}
            with patch.object(base, "_descriptor", return_value=(object(), target, descriptor)), \
                 patch.object(base, "pre_effect_status", return_value=observed) as probe, \
                 patch.object(base, "readiness", return_value=idle), \
                 patch.object(base, "_campaign_remote", return_value=remote):
                closed = base.close_pre_effect(root, {"host": "archlinux"})
            self.assertEqual(closed["state"], "pre-effect-closed")
            self.assertEqual(probe.call_count, 2)
            self.assertEqual(base._private_intent(root, corr), original)
            self.assertTrue(base._pre_effect_closed(root))
            base._require_base_route_free(root)
            next_corr = "05fd80ad-b93f-4450-a3e5-a67d14f24478"
            base._reserve(root, {"request": dict(REQUEST, correlationId=next_corr),
                                 "commandSha256": "a" * 64})
            self.assertIsNotNone(base._private_intent(root, next_corr))

    def test_pre_effect_closure_refuses_present_guest_or_active_installer(self):
        corr = base._PRE_EFFECT_REJECTED_CORRELATION
        sid = "S-1-5-21-1-2-3-1002"
        descriptor = ("windows-cp117", "/qga.sock", 589342, 520739, sid)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base._reserve(root, {"request": base._PRE_EFFECT_REJECTED_REQUEST, "leaseId": corr,
                "commandSha256": base._PRE_EFFECT_REJECTED_COMMAND_SHA256,
                "environment": descriptor[0], "socketPath": descriptor[1], "pid": descriptor[2],
                "startTicks": descriptor[3], "expectedSid": sid})
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            exact = {"state": "absent", "correlationId": corr, "qemuPid": 589342, "startTicks": 520739}
            idle = {"state": "ready", "ready": True, "code": "READY", "installedVersion": "2.1.17",
                    "productCount": 1, "activeCount": 0, "activeProcesses": []}
            with patch.object(base, "_descriptor", return_value=(object(), target, descriptor)), \
                 patch.object(base, "_campaign_remote") as remote, \
                 patch.object(base, "readiness", return_value=idle):
                with patch.object(base, "pre_effect_status", side_effect=[exact, dict(exact, state="unknown")]):
                    self.assertEqual(base.close_pre_effect(root, {"host": "archlinux"})["state"], "unknown")
                with patch.object(base, "pre_effect_status", return_value=exact), \
                     patch.object(base, "readiness", return_value=dict(idle, activeCount=1)):
                    self.assertEqual(base.close_pre_effect(root, {"host": "archlinux"})["state"], "unknown")
                remote.assert_not_called()
            self.assertFalse(base._pre_effect_marker(root).exists())

    def test_forged_pre_effect_marker_cannot_free_base_route(self):
        corr = base._PRE_EFFECT_REJECTED_CORRELATION
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base._reserve(root, {"request": base._PRE_EFFECT_REJECTED_REQUEST,
                "commandSha256": base._PRE_EFFECT_REJECTED_COMMAND_SHA256})
            marker = base._pre_effect_marker(root)
            marker.write_text(json.dumps({"correlationId": corr,
                "commandSha256": base._PRE_EFFECT_REJECTED_COMMAND_SHA256,
                "state": "pre-effect-closed", "cleanupReceiptSha256": "a" * 64}))
            marker.chmod(0o600)
            self.assertFalse(base._pre_effect_closed(root))
            with self.assertRaises(base.WindowsMsiBasePrepareError):
                base._require_base_route_free(root)

    def test_legacy_reconciliation_blocks_before_base_intent_or_guest_submission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); package = root / "base.msi"; package.write_bytes(b"x")
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            with patch.object(base, "_admit", return_value=(PAIR, package, 1)), \
                 patch.object(base, "_descriptor", return_value=(object(), Target(),
                    ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base.windows_msi_public_scenario, "preinstall_status", return_value={
                    "state": "observed", "jobId": base._LEGACY_JOB, "phase": "Failed",
                    "code": "RUNTIME_FAILED", "sequence": 3}), \
                 patch.object(base, "readiness", return_value={"state": "ready", "activeCount": 0}), \
                 patch.object(base, "_legacy_task_observation", return_value={"state": "blocked"}), \
                 patch.object(base, "_remote") as remote:
                with self.assertRaisesRegex(base.WindowsMsiBasePrepareError,
                                            "CP117_LEGACY_CLEANUP_UNVERIFIED"):
                    base.start(root, REQUEST)
                remote.assert_not_called()
                self.assertIsNone(base._private_intent(root, CORR))

    def test_legacy_cleanup_requires_exact_terminal_idle_task_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = ("windows-cp117", "/qga.sock", 589342, 520739,
                          "S-1-5-21-1-2-3-1002")
            protected = {"state": "observed", "jobId": base._LEGACY_JOB,
                         "phase": "Failed", "code": "RUNTIME_FAILED", "sequence": 3}
            clean = {"state": "cleaned", "version": 1, "code": "CLEANED",
                     "legacyTaskCount": 0, "otherTaskCount": 0, "activeInstallerCount": 0}
            history = {"state": "clean", "groups": {"windows-msi-base": [],
                "windows-msi-target": [], "windows-msi-public": [base._LEGACY_CORRELATION]}}
            with patch.object(base.windows_msi_public_scenario, "preinstall_status", return_value=protected), \
                 patch.object(base, "readiness", return_value={"state": "ready", "activeCount": 0}), \
                 patch.object(base, "_legacy_task_observation", return_value=clean), \
                 patch.object(base, "_legacy_history_observation", return_value=history), \
                 patch.object(base.campaign_lease, "attest_legacy_closed") as attest:
                base._require_reconciled_legacy(root, descriptor, "2.1.17")
                proof = attest.call_args.args[1]
                self.assertEqual(proof["terminalJobId"], base._LEGACY_JOB)
                self.assertEqual(proof["correlationId"], base._LEGACY_CORRELATION)
                self.assertTrue(proof["activeInstallerProcessesAbsent"])
            body = base._legacy_task_script()
            self.assertIn("Get-ScheduledTask", body)
            self.assertIn(base._LEGACY_CORRELATION, body)
            self.assertNotIn("Unregister-ScheduledTask", body)
            self.assertNotIn("Start-ScheduledTask", body)
            self.assertNotIn("Stop-Process", body)
            self.assertNotIn("os.mkdir", base._LEGACY_HISTORY)

    def test_shared_campaign_rejects_second_route_and_mismatched_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = ("windows-cp117", "/qga.sock", 589342, 520739,
                          "S-1-5-21-1-2-3-1002")
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            def journal(action, payload):
                desired = payload["desired"]
                return json.dumps({"version": 1, "action": action, "leaseId": CORR,
                    "recordSha256": base.campaign_lease._digest(desired),
                    "state": "confirmed"}).encode()
            base._reserve(root, {"request": REQUEST, "pair": PAIR,
                "environment": descriptor[0], "socketPath": descriptor[1],
                "pid": descriptor[2], "startTicks": descriptor[3],
                "expectedSid": descriptor[4], "leaseId": CORR})
            with patch.object(base, "_require_reconciled_legacy"), \
                 patch.object(base, "_campaign_remote", return_value=journal):
                self.assertEqual(base._open_base_campaign(root, REQUEST, object(), Target(), descriptor), CORR)
                with self.assertRaises(base.WindowsMsiBasePrepareError):
                    base._open_base_campaign(root, dict(REQUEST, correlationId=
                        "70fa550a-a622-4123-b89c-f68a087ce808"), object(), Target(), descriptor)
                with self.assertRaises(base.WindowsMsiBasePrepareError):
                    base._verified_active_campaign(root, dict(REQUEST, targetMsiArtifactId=
                        "sha256-" + "f" * 64), descriptor, object(), Target(), require_server=False)

    def test_live_receipt_recheck_binds_pair_and_generation_after_claim(self):
        expected = base._campaign_identity(REQUEST, ("windows-cp117", "/qga.sock", 589342,
            520739, "S-1-5-21-1-2-3-1002"))
        receipt = {key: expected[key] for key in ("leaseId", "sourceSha",
            "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId",
            "socketPath", "qemuPid", "startTicks")}
        receipt.update(serverReady=True, liveReceiptSha256="a" * 64)
        self.assertTrue(base._live_receipt_matches(receipt, expected))
        self.assertFalse(base._live_receipt_matches(dict(receipt, startTicks=520740), expected))
        self.assertFalse(base._live_receipt_matches(dict(receipt, serverReady=False), expected))

    def test_second_correlation_is_blocked_after_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base._reserve(root, {"request": REQUEST, "pair": PAIR})
            another = dict(REQUEST, correlationId="70fa550a-a622-4123-b89c-f68a087ce808")
            with self.assertRaises(base.WindowsMsiBasePrepareError):
                base._reserve(root, {"request": another, "pair": PAIR})

    def test_status_rejects_forged_passed_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                      "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                      "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64}
            base._reserve(root, intent)
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            forged = {"state": "observed", "correlationId": CORR,
                      "result": {"version": 1, "correlationId": CORR, "stage": "READBACK",
                                 "result": "PASSED", "exitCode": 0}}
            with patch.object(base, "_descriptor", return_value=(object(), Target(),
                 ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_remote", return_value=json.dumps(forged).encode()):
                self.assertEqual(base.status(root, {"correlationId": CORR})["state"], "unknown")

    def test_reconcile_retains_post_registration_bootstrap_throw_as_unknown(self):
        """Generic false can follow Register-ScheduledTask or Start-ScheduledTask."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                      "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                      "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64}
            base._reserve(root, intent)
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            observed = {"state": "observed", "correlationId": CORR,
                        "failure": {"phase": "bootstrap", "code": "task_trigger_outcome_ambiguous"}}
            with patch.object(base, "_descriptor", return_value=(object(), target,
                 ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_remote", return_value=json.dumps(observed).encode()) as remote:
                result = base.reconcile(root, {"correlationId": CORR})
            self.assertEqual(result, {"state": "unknown", "correlationId": CORR,
                                      "failurePhase": "bootstrap",
                                      "failureType": "task_trigger_outcome_ambiguous",
                                      "code": "task_trigger_outcome_ambiguous", "replayAllowed": False})
            self.assertIs(remote.call_args.args[1], base._STATUS)
            self.assertEqual(remote.call_args.args[4], 120)

    def test_reconcile_rejects_untyped_failure_and_keeps_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base._reserve(root, {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                                 "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                                 "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64})
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            with patch.object(base, "_descriptor", return_value=(object(), target,
                 ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_remote", return_value=json.dumps({"state": "observed", "correlationId": CORR,
                     "failure": {"phase": "bootstrap", "code": "untrusted"}}).encode()):
                self.assertEqual(base.reconcile(root, {"correlationId": CORR}),
                                 {"state": "unknown", "correlationId": CORR, "replayAllowed": False})

    def test_reconcile_rejects_extra_bootstrap_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base._reserve(root, {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                                 "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                                 "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64})
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            malformed = {"state": "observed", "correlationId": CORR,
                         "failure": {"phase": "bootstrap", "code": "task_trigger_outcome_ambiguous"},
                         "extra": "untrusted"}
            with patch.object(base, "_descriptor", return_value=(object(), target,
                 ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_remote", return_value=json.dumps(malformed).encode()):
                self.assertEqual(base.reconcile(root, {"correlationId": CORR}),
                                 {"state": "unknown", "correlationId": CORR, "replayAllowed": False})

    def test_status_rejects_extra_running_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base._reserve(root, {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                                 "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                                 "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64})
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            with patch.object(base, "_descriptor", return_value=(object(), target,
                 ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_remote", return_value=json.dumps({"state": "running", "correlationId": CORR,
                     "extra": "untrusted"}).encode()):
                self.assertEqual(base.status(root, {"correlationId": CORR}),
                                 {"state": "unknown", "correlationId": CORR, "replayAllowed": False})

    def test_status_program_rejects_truncated_qga_output_before_bootstrap_projection(self):
        if not Path("/proc/self/stat").is_file():
            self.skipTest("The fixed remote QGA observer requires Linux procfs.")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            socket_path = str(root / "qga.sock")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(socket_path)
            server.listen(1)
            ticks = Path("/proc/self/stat").read_text().split()[21]
            stage = root / "windows-cp117" / "windows-msi-base" / CORR
            stage.mkdir(mode=0o700, parents=True)
            for parent in (root / "windows-cp117", root / "windows-cp117" / "windows-msi-base"):
                parent.chmod(0o700)
            binding = {"socketPath": socket_path, "pid": os.getpid(), "startTicks": int(ticks),
                       "sourceSha": SOURCE, "sourceFingerprint": PAIR["sourceFingerprint"],
                       "receiptArtifactId": ARTIFACT, "baseArtifactId": ARTIFACT,
                       "targetArtifactId": ARTIFACT, "commandSha256": "0" * 64,
                       "expectedSid": "S-1-5-21-1-2-3-1002"}
            (stage / "binding.json").write_text(json.dumps(binding))
            (stage / "dispatch.json").write_text(json.dumps({"pid": 1}))
            false_output = json.dumps({"version": 1, "correlationId": CORR, "triggered": False}).encode()

            def receive(connection):
                data = bytearray()
                while not data.endswith(b"\n"):
                    data.extend(connection.recv(4096))
                return bytes(data)

            def qga_once():
                connection, _ = server.accept()
                with connection:
                    sync = json.loads(receive(connection)[1:])
                    connection.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                    request = json.loads(receive(connection))
                    self.assertEqual(request["execute"], "guest-exec-status")
                    connection.sendall(json.dumps({"return": {"exited": True, "exitcode": 1,
                        "out-truncated": True, "err-truncated": False,
                        "out-data": base64.b64encode(false_output).decode()}}).encode() + b"\n")

            worker = threading.Thread(target=qga_once)
            worker.start()
            try:
                command = [__import__("sys").executable, "-c", base._STATUS, str(root), "windows-cp117", CORR,
                           socket_path, str(os.getpid()), ticks, SOURCE, PAIR["sourceFingerprint"], ARTIFACT,
                           ARTIFACT, ARTIFACT, "0" * 64, "S-1-5-21-1-2-3-1002"]
                completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            finally:
                worker.join(timeout=5)
                server.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(json.loads(completed.stdout), {"state": "unknown", "correlationId": CORR})

    def test_status_program_accepts_absent_optional_truncation_flags_and_rejects_true_or_malformed(self):
        if not Path("/proc/self/stat").is_file():
            self.skipTest("The fixed remote QGA observer requires Linux procfs.")
        false_output = base64.b64encode(json.dumps({"version": 1, "correlationId": CORR,
                                                     "triggered": False}).encode()).decode()
        malformed = (
            {"exitcode": 1, "out-truncated": False, "err-truncated": False, "out-data": false_output},
            {"exited": "false", "exitcode": 1, "out-truncated": False, "err-truncated": False,
             "out-data": false_output},
            {"exited": True, "exitcode": 1, "out-truncated": True, "out-data": false_output},
            {"exited": True, "exitcode": 1, "err-truncated": "false", "out-data": false_output},
        )
        for status_value in malformed:
            with self.subTest(status_value=status_value):
                self.assertEqual(_run_qga_status_program(status_value),
                                 {"state": "unknown", "correlationId": CORR})
        optional_absent = {"exited": True, "exitcode": 1, "out-data": false_output}
        bootstrap = {"state": "observed", "correlationId": CORR,
                     "failure": {"phase": "bootstrap", "code": "task_trigger_outcome_ambiguous"}}
        self.assertEqual(_run_qga_status_program(optional_absent), bootstrap)
        self.assertEqual(_run_qga_status_program(optional_absent, program=base._DIAGNOSTIC), {
            "state": "diagnosed", "correlationId": CORR, "binding": "exact",
            "checkpoint": "bootstrap-result-proof"})
        self.assertEqual(_run_qga_status_program({"exited": False}),
                         {"state": "running", "correlationId": CORR})

    def test_stage_diagnostic_program_classifies_absent_partial_and_full_without_mutation(self):
        if not Path("/proc/self/stat").is_file():
            self.skipTest("The fixed remote QGA observer requires Linux procfs.")
        cases = (
            ("absent", {"version": 1, "guestStage": "absent", "observedSize": None,
                        "sizeMatches": False, "sha256Matches": False}),
            ("partial", {"version": 1, "guestStage": "partial", "observedSize": 17,
                         "sizeMatches": False, "sha256Matches": False}),
            ("full", {"version": 1, "guestStage": "full", "observedSize": STAGE_SIZE,
                      "sizeMatches": True, "sha256Matches": True}),
        )
        for expected, envelope in cases:
            with self.subTest(expected=expected):
                status = {"exited": True, "exitcode": 0, "out-truncated": False, "err-truncated": False,
                          "out-data": base64.b64encode(json.dumps(envelope).encode()).decode()}
                result, unchanged = _run_stage_diagnostic_program((("guest-exec", {"pid": 7}),
                                                                      ("guest-exec-status", status)))
                self.assertTrue(unchanged)
                self.assertEqual(result, {"state": "stage-diagnosed", "correlationId": CORR,
                                          "binding": "exact", "checkpoint": "guest-stage",
                                          "guestStage": expected, "observedSize": envelope["observedSize"],
                                          "sizeMatches": envelope["sizeMatches"],
                                          "sha256Matches": envelope["sha256Matches"]})

    def test_stage_diagnostic_program_rejects_malformed_and_truncated_qga_evidence_without_mutation(self):
        if not Path("/proc/self/stat").is_file():
            self.skipTest("The fixed remote QGA observer requires Linux procfs.")
        malformed = {"version": 1, "guestStage": "full", "observedSize": STAGE_SIZE,
                     "sizeMatches": True, "sha256Matches": True, "extra": "untrusted"}
        cases = (
            {"exited": True, "exitcode": 0, "out-truncated": False, "err-truncated": False,
             "out-data": base64.b64encode(json.dumps(malformed).encode()).decode()},
            {"exited": True, "exitcode": 0, "out-truncated": True, "err-truncated": False,
             "out-data": base64.b64encode(json.dumps({"version": 1, "guestStage": "absent", "observedSize": None,
                                                         "sizeMatches": False, "sha256Matches": False}).encode()).decode()},
        )
        for status in cases:
            with self.subTest(status=status):
                result, unchanged = _run_stage_diagnostic_program((("guest-exec", {"pid": 7}),
                                                                      ("guest-exec-status", status)))
                self.assertTrue(unchanged)
                self.assertEqual(result, {"state": "stage-diagnosed", "correlationId": CORR,
                                          "binding": "exact", "checkpoint": "qga-protocol"})

    def test_stage_diagnostic_projects_only_exact_source_bound_stage_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                      "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                      "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64}
            base._reserve(root, intent)
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            descriptor = (object(), target, ("windows-cp117", "/qga.sock", 589342, 520739,
                                             "S-1-5-21-1-2-3-1002"))
            full = {"state": "stage-diagnosed", "correlationId": CORR, "binding": "exact",
                    "checkpoint": "guest-stage", "guestStage": "full", "observedSize": STAGE_SIZE,
                    "sizeMatches": True, "sha256Matches": True}
            with patch.object(base, "_stage_artifact_readonly", return_value=(PAIR, STAGE_SIZE)), \
                 patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_remote", return_value=json.dumps(full).encode()) as remote:
                result = base.stage_diagnose(root, {"correlationId": CORR})
            self.assertEqual(result, {**full, "state": "unknown", "replayAllowed": False,
                                      "nativeActionAllowed": False})
            self.assertIs(remote.call_args.args[1], base._STAGE_DIAGNOSTIC)
            self.assertEqual(remote.call_args.args[4], 120)
            malformed = dict(full, extra="untrusted")
            with patch.object(base, "_stage_artifact_readonly", return_value=(PAIR, STAGE_SIZE)), \
                 patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_remote", return_value=json.dumps(malformed).encode()):
                self.assertEqual(base.stage_diagnose(root, {"correlationId": CORR})["checkpoint"], "qga-protocol")
            with patch.object(base, "_stage_artifact_readonly", side_effect=base.WindowsMsiBasePrepareError("unavailable")), \
                 patch.object(base, "_remote") as remote:
                unavailable = base.stage_diagnose(root, {"correlationId": CORR})
            self.assertEqual((unavailable["binding"], unavailable["checkpoint"]), ("unverified", "local-artifact"))
            remote.assert_not_called()

    def test_stage_artifact_admission_uses_only_readonly_registry_verification(self):
        intent = {"request": REQUEST, "pair": PAIR}
        verified = {"verification": "verified", "artifact": {"platform": "windows",
                    "artifactKind": "desktop-package", "sourceSha": SOURCE,
                    "sourceFingerprint": PAIR["sourceFingerprint"],
                    "sha256": ARTIFACT.removeprefix("sha256-"), "size": STAGE_SIZE},
                    "location": {"evidenceClass": "local-verified"},
                    "observedSize": STAGE_SIZE, "observedSha256": ARTIFACT.removeprefix("sha256-")}
        registry = base.windows_msi_public_scenario.native_artifact_registry
        with patch.object(registry, "verify_artifact_readonly", return_value=verified) as readonly, \
             patch.object(registry, "verify_artifact", side_effect=AssertionError("mutable verifier used")):
            pair, size = base._stage_artifact_readonly(Path("/tmp"), intent)
        self.assertEqual((pair, size), (PAIR, STAGE_SIZE))
        readonly.assert_called_once_with(Path("/tmp"), ARTIFACT)

    def test_stage_artifact_admission_accepts_current_pair_shape_without_mutable_registry(self):
        """Current base intents include the target MSI identity recorded by _admit."""
        intent = {"request": REQUEST, "pair": PAIR}
        verified = {"verification": "verified", "artifact": {"platform": "windows",
                    "artifactKind": "desktop-package", "sourceSha": SOURCE,
                    "sourceFingerprint": PAIR["sourceFingerprint"],
                    "sha256": ARTIFACT.removeprefix("sha256-"), "size": STAGE_SIZE},
                    "location": {"evidenceClass": "local-verified"},
                    "observedSize": STAGE_SIZE, "observedSha256": ARTIFACT.removeprefix("sha256-")}
        registry = base.windows_msi_public_scenario.native_artifact_registry
        with patch.object(registry, "verify_artifact_readonly", return_value=verified) as readonly, \
             patch.object(registry, "verify_artifact", side_effect=AssertionError("mutable verifier used")):
            self.assertEqual(base._stage_artifact_readonly(Path("/tmp"), intent), (PAIR, STAGE_SIZE))
        readonly.assert_called_once_with(Path("/tmp"), ARTIFACT)

    def test_diagnostic_classifies_each_public_checkpoint_without_authorizing_action(self):
        """Each diagnosed missing proof remains the original non-replayable run."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                      "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                      "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64}
            base._reserve(root, intent)
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            descriptor = (object(), target, ("windows-cp117", "/qga.sock", 589342, 520739,
                                             "S-1-5-21-1-2-3-1002"))
            checkpoints = (("remote-stage", "exact"), ("remote-binding", "mismatch"),
                           ("remote-dispatch-malformed", "exact"), ("qga-protocol", "exact"),
                           ("bootstrap-result-proof", "exact"))
            for checkpoint, binding in checkpoints:
                with self.subTest(checkpoint=checkpoint), \
                     patch.object(base, "_descriptor", return_value=descriptor), \
                     patch.object(base, "_remote", return_value=json.dumps({
                         "state": "diagnosed", "correlationId": CORR,
                         "binding": binding, "checkpoint": checkpoint}).encode()) as remote:
                    result = base.diagnose(root, {"correlationId": CORR})
                self.assertEqual(result, {"state": "unknown", "correlationId": CORR,
                                          "binding": binding, "checkpoint": checkpoint,
                                          "replayAllowed": False, "nativeActionAllowed": False})
                self.assertIs(remote.call_args.args[1], base._DIAGNOSTIC)
                self.assertEqual(remote.call_args.args[4], 120)

    def test_diagnostic_projects_dispatch_absent_guest_proof_but_keeps_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                      "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                      "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64}
            base._reserve(root, intent)
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            descriptor = (object(), target, ("windows-cp117", "/qga.sock", 589342, 520739,
                                             "S-1-5-21-1-2-3-1002"))
            proof = {"task": "absent", "leaf": "absent", "result": "absent",
                     "correlationPowerShell": "absent", "product": "single",
                     "installedVersion": "2.1.17", "installer": "absent"}
            observed = {"state": "diagnosed", "correlationId": CORR, "binding": "exact",
                        "checkpoint": "remote-dispatch-absent", "guestProof": proof,
                        "guestProofFailure": "none", "guestProofFailurePhase": "none",
                        "guestProofProjectionReason": "none"}
            with patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_remote", return_value=json.dumps(observed).encode()):
                result = base.diagnose(root, {"correlationId": CORR})
            self.assertEqual(result["guestProof"], proof)
            self.assertEqual(result["checkpoint"], "remote-dispatch-absent")
            self.assertEqual(result["guestProofFailure"], "none")
            self.assertEqual(result["guestProofFailurePhase"], "none")
            self.assertEqual(result["guestProofProjectionReason"], "none")
            self.assertFalse(result["replayAllowed"])
            self.assertFalse(result["nativeActionAllowed"])

    def test_diagnostic_projects_each_guest_proof_failure_without_promoting_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                      "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                      "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64}
            base._reserve(root, intent)
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            descriptor = (object(), target, ("windows-cp117", "/qga.sock", 589342, 520739,
                                             "S-1-5-21-1-2-3-1002"))
            unknown_proof = {"task": "unknown", "leaf": "unknown", "result": "unknown",
                             "correlationPowerShell": "unknown", "product": "unknown",
                             "installedVersion": None, "installer": "unknown"}
            failures = (("qga-exec-rpc-or-protocol", "unavailable"),
                        ("qga-status-rpc-or-protocol", "unavailable"),
                        ("qga-status-exited-malformed", "unavailable"),
                        ("qga-status-terminal-fields-malformed", "unavailable"),
                        ("qga-status-running-timeout", "unavailable"), ("qga-truncated", "unavailable"),
                        ("powershell-nonzero", "unavailable"),
                        ("powershell-empty-or-malformed-output", "unavailable"),
                        *( ("projection", reason) for reason in (
                            "missing-or-extra-fields", "version-or-phase-invalid",
                            "nonzero-failure-envelope-invalid", "success-enum-invalid",
                            "product-version-invalid", "internal-error")))
            for failure, projection_reason in failures:
                phase = "task" if failure == "powershell-nonzero" else "unavailable"
                observed = {"state": "diagnosed", "correlationId": CORR, "binding": "exact",
                            "checkpoint": "remote-dispatch-absent", "guestProof": unknown_proof,
                            "guestProofFailure": failure, "guestProofFailurePhase": phase,
                            "guestProofProjectionReason": projection_reason,
                            **({"guestProofProjectionSchema": {"presenceMask": "100000000", "extraFieldCount": 0}}
                               if projection_reason == "missing-or-extra-fields" else {})}
                with self.subTest(failure=failure), patch.object(base, "_descriptor", return_value=descriptor), \
                     patch.object(base, "_remote", return_value=json.dumps(observed).encode()):
                    result = base.diagnose(root, {"correlationId": CORR})
                self.assertEqual(result["guestProofFailure"], failure)
                self.assertEqual(result["guestProofFailurePhase"], phase)
                self.assertEqual(result["guestProofProjectionReason"], projection_reason)
                if projection_reason == "missing-or-extra-fields":
                    self.assertEqual(result["guestProofProjectionSchema"],
                                     {"presenceMask": "100000000", "extraFieldCount": 0})
                else:
                    self.assertNotIn("guestProofProjectionSchema", result)
                self.assertEqual(result["guestProof"], unknown_proof)
                self.assertFalse(result["replayAllowed"])
            malformed = dict(observed, guestProofFailure="private-detail")
            with patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_remote", return_value=json.dumps(malformed).encode()):
                self.assertEqual(base.diagnose(root, {"correlationId": CORR})["checkpoint"], "qga-protocol")
            for field, malformed_value in (("guestProofFailure", []), ("guestProofFailurePhase", []),
                                           ("guestProofProjectionReason", []), ("guestProof", [])):
                malformed = dict(observed, **{field: malformed_value})
                with self.subTest(field=field), patch.object(base, "_descriptor", return_value=descriptor), \
                     patch.object(base, "_remote", return_value=json.dumps(malformed).encode()):
                    self.assertEqual(base.diagnose(root, {"correlationId": CORR})["checkpoint"], "qga-protocol")
            schema_observed = dict(observed, guestProofFailure="projection",
                                   guestProofFailurePhase="unavailable",
                                   guestProofProjectionReason="missing-or-extra-fields",
                                   guestProofProjectionSchema={"presenceMask": "100000000", "extraFieldCount": 0})
            for schema in ({"presenceMask": "100000000"},
                           {"presenceMask": "10000000x", "extraFieldCount": 0},
                           {"presenceMask": "100000000", "extraFieldCount": 10},
                           {"presenceMask": "100000000", "extraFieldCount": True}):
                with self.subTest(schema=schema), patch.object(base, "_descriptor", return_value=descriptor), \
                     patch.object(base, "_remote", return_value=json.dumps(dict(schema_observed,
                         guestProofProjectionSchema=schema)).encode()):
                    self.assertEqual(base.diagnose(root, {"correlationId": CORR})["checkpoint"], "qga-protocol")

    def test_diagnostic_classifies_local_intent_and_descriptor_without_remote_call(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(base.diagnose(root, {"correlationId": CORR}), {
                "state": "unknown", "correlationId": CORR, "binding": "unverified",
                "checkpoint": "local-intent", "replayAllowed": False,
                "nativeActionAllowed": False})
            intent = {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                      "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                      "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64}
            base._reserve(root, intent)
            with patch.object(base, "_descriptor", side_effect=base.WindowsMsiBasePrepareError("private")), \
                 patch.object(base, "_remote") as remote:
                result = base.diagnose(root, {"correlationId": CORR})
            self.assertEqual(result["checkpoint"], "descriptor")
            self.assertEqual(result["binding"], "unverified")
            remote.assert_not_called()

    def test_diagnostic_rejects_malformed_or_truncated_remote_evidence_as_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = {"request": REQUEST, "pair": PAIR, "environment": "windows-cp117",
                      "socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                      "expectedSid": "S-1-5-21-1-2-3-1002", "commandSha256": "0" * 64}
            base._reserve(root, intent)
            target = type("Target", (), {"fixture_transfer_root": Path("/private/cp117")})()
            descriptor = (object(), target, ("windows-cp117", "/qga.sock", 589342, 520739,
                                             "S-1-5-21-1-2-3-1002"))
            malformed = ({"state": "diagnosed", "correlationId": CORR, "binding": "exact",
                          "checkpoint": "remote-stage", "extra": "untrusted"},
                         {"state": "diagnosed", "correlationId": CORR, "binding": "exact",
                          "checkpoint": "remote-binding"})
            for payload in malformed:
                with self.subTest(payload=payload), patch.object(base, "_descriptor", return_value=descriptor), \
                     patch.object(base, "_remote", return_value=json.dumps(payload).encode()):
                    result = base.diagnose(root, {"correlationId": CORR})
                self.assertEqual(result["checkpoint"], "qga-protocol")
                self.assertEqual(result["binding"], "unverified")
                self.assertFalse(result["replayAllowed"])
            with patch.object(base, "_descriptor", return_value=descriptor), \
                 patch.object(base, "_remote", return_value=None):
                truncated = base.diagnose(root, {"correlationId": CORR})
            self.assertEqual(truncated["checkpoint"], "qga-protocol")
            self.assertEqual(truncated["binding"], "unverified")

    def test_diagnostic_program_maps_truncated_qga_and_generic_bootstrap_to_safe_checkpoints(self):
        if not Path("/proc/self/stat").is_file():
            self.skipTest("The fixed remote QGA observer requires Linux procfs.")
        generic_false = base64.b64encode(json.dumps({"version": 1, "correlationId": CORR,
                                                       "triggered": False}).encode()).decode()
        truncated = {"exited": True, "exitcode": 1, "out-truncated": True,
                     "err-truncated": False, "out-data": generic_false}
        self.assertEqual(_run_qga_status_program(truncated, program=base._DIAGNOSTIC), {
            "state": "diagnosed", "correlationId": CORR, "binding": "exact",
            "checkpoint": "qga-protocol"})
        complete_false = dict(truncated, **{"out-truncated": False})
        self.assertEqual(_run_qga_status_program(complete_false, program=base._DIAGNOSTIC), {
            "state": "diagnosed", "correlationId": CORR, "binding": "exact",
            "checkpoint": "bootstrap-result-proof"})
        self.assertIn("guest-exec-status", base._DIAGNOSTIC)
        self.assertIn("'guest-exec'", base._DIAGNOSTIC)
        self.assertIn("Get-ScheduledTask", base._DIAGNOSTIC)
        self.assertIn("HKEY_USERS", base._DIAGNOSTIC)
        self.assertIn("Get-ScheduledTask -TaskPath '\\\\' -ErrorAction Stop", base._DIAGNOSTIC)
        self.assertIn("Test-Path -LiteralPath $path", base._DIAGNOSTIC)
        self.assertIn("Get-ItemProperty -Path ($path+'\\\\*') -ErrorAction Stop", base._DIAGNOSTIC)
        self.assertNotIn("-ErrorAction SilentlyContinue", base._DIAGNOSTIC)
        self.assertNotIn("Start-ScheduledTask", base._DIAGNOSTIC)
        self.assertNotIn("guest-file-write", base._DIAGNOSTIC)

    def test_dispatch_absent_census_uses_fail_closed_task_and_registry_queries(self):
        self.assertIn("Get-ScheduledTask -TaskPath '\\\\' -ErrorAction Stop", base._DIAGNOSTIC)
        self.assertIn("Test-Path -LiteralPath $path", base._DIAGNOSTIC)
        self.assertIn("Get-ItemProperty -Path ($path+'\\\\*') -ErrorAction Stop", base._DIAGNOSTIC)
        self.assertNotIn("-ErrorAction SilentlyContinue", base._DIAGNOSTIC)
        self.assertNotIn("Start-ScheduledTask", base._DIAGNOSTIC)
        self.assertNotIn("guest-file-write", base._DIAGNOSTIC)

    def test_in_scope_capture_observers_require_integer_exitcodes(self):
        self.assertIn("type(state.get('exitcode')) is not int", base._READINESS)
        self.assertIn("type(observed.get('exitcode')) is not int", base._PRE_EFFECT_STATUS)
        self.assertIn("type(state.get('exitcode')) is not int", base._STAGE)

    def test_diagnostic_program_causally_separates_stage_binding_and_dispatch(self):
        if not Path("/proc/self/stat").is_file():
            self.skipTest("The fixed remote QGA observer requires Linux procfs.")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ticks = Path("/proc/self/stat").read_text().split()[21]
            socket_path = str(root / "qga.sock")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(socket_path)
            server.listen(1)
            common = [__import__("sys").executable, "-c", base._DIAGNOSTIC, str(root),
                      "windows-cp117", CORR, socket_path, str(os.getpid()), ticks, SOURCE,
                      PAIR["sourceFingerprint"], ARTIFACT, ARTIFACT, ARTIFACT, "0" * 64,
                      "S-1-5-21-1-2-3-1002"]
            worker = None
            try:
                def run():
                    completed = subprocess.run(common, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, check=False)
                    self.assertEqual(completed.returncode, 0, completed.stderr.decode())
                    return json.loads(completed.stdout)

                self.assertEqual(run()["checkpoint"], "remote-stage")
                stage = root / "windows-cp117" / "windows-msi-base" / CORR
                stage.mkdir(mode=0o700, parents=True)
                for parent in (root / "windows-cp117", root / "windows-cp117" / "windows-msi-base"):
                    parent.chmod(0o700)
                (stage / "binding.json").write_text("{}")
                self.assertEqual(run(), {"state": "diagnosed", "correlationId": CORR,
                                         "binding": "mismatch", "checkpoint": "remote-binding"})
                binding = {"socketPath": socket_path, "pid": os.getpid(), "startTicks": int(ticks),
                           "sourceSha": SOURCE, "sourceFingerprint": PAIR["sourceFingerprint"],
                           "receiptArtifactId": ARTIFACT, "baseArtifactId": ARTIFACT,
                           "targetArtifactId": ARTIFACT, "commandSha256": "0" * 64,
                           "expectedSid": "S-1-5-21-1-2-3-1002"}
                (stage / "binding.json").write_text(json.dumps(binding))
                (stage / "dispatch.json").write_text("{}")
                self.assertEqual(run(), {"state": "diagnosed", "correlationId": CORR,
                                         "binding": "exact", "checkpoint": "remote-dispatch-malformed"})
                (stage / "dispatch.json").unlink()
                positive = {"version": 1, "phase": "output", "task": "present", "leaf": "present",
                            "result": "present", "correlationPowerShell": "present",
                            "product": "single", "installedVersion": "2.1.19",
                            "installer": "present"}

                def receive(connection):
                    data = bytearray()
                    while not data.endswith(b"\n"):
                        data.extend(connection.recv(4096))
                    return bytes(data)

                def qga_proof():
                    for expected, reply in (
                            ("guest-exec", {"pid": 7}),
                            ("guest-exec-status", {"exited": True, "exitcode": 0,
                             "out-truncated": False, "err-truncated": False,
                             "out-data": base64.b64encode(json.dumps(positive).encode()).decode()})):
                        connection, _ = server.accept()
                        with connection:
                            sync = json.loads(receive(connection)[1:])
                            connection.sendall(b"\xff" + json.dumps({"return": sync["arguments"]["id"]}).encode() + b"\n")
                            request = json.loads(receive(connection))
                            self.assertEqual(request["execute"], expected)
                            connection.sendall(json.dumps({"return": reply}).encode() + b"\n")

                worker = threading.Thread(target=qga_proof)
                worker.start()
                observed = run()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertEqual(observed, {"state": "diagnosed", "correlationId": CORR,
                                            "binding": "exact", "checkpoint": "remote-dispatch-absent",
                                            "guestProof": {key: value for key, value in positive.items()
                                                           if key not in {"version", "phase"}},
                                            "guestProofFailure": "none", "guestProofFailurePhase": "none",
                        "guestProofProjectionReason": "none"})
            finally:
                if worker is not None:
                    worker.join(timeout=1)
                server.close()

    def test_dispatch_absent_program_classifies_each_guest_proof_failure(self):
        if not Path("/proc/self/stat").is_file():
            self.skipTest("The fixed remote QGA observer requires Linux procfs.")
        good = {"version": 1, "phase": "output", "task": "absent", "leaf": "absent", "result": "absent",
                "correlationPowerShell": "absent", "product": "single",
                "installedVersion": "2.1.17", "installer": "absent"}
        terminal = lambda exitcode, output, **extra: {"exited": True, "exitcode": exitcode,
            "out-truncated": False, "err-truncated": False,
            "out-data": base64.b64encode(output).decode(), **extra}
        failed = lambda phase: {"version": 1, "phase": phase, "task": "unknown",
            "leaf": "unknown", "result": "unknown", "correlationPowerShell": "unknown",
            "product": "unknown", "installedVersion": None, "installer": "unknown"}
        cases = (
            ("qga-exec-rpc-or-protocol", "unavailable", (("guest-exec", {}),)),
            ("qga-status-rpc-or-protocol", "unavailable", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", None))),
            ("qga-status-exited-malformed", "unavailable", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", {"exited": "bad"}))),
            ("qga-status-terminal-fields-malformed", "unavailable", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", {"exited": True}))),
            ("qga-status-running-timeout", "unavailable", (("guest-exec", {"pid": 7}),) +
                tuple(("guest-exec-status", {"exited": False}) for _ in range(40))),
            ("qga-truncated", "unavailable", (("guest-exec", {"pid": 7}), ("guest-exec-status",
                dict(terminal(0, b"{}"), **{"out-truncated": True})))),
            ("qga-truncated", "unavailable", (("guest-exec", {"pid": 7}), ("guest-exec-status",
                dict(terminal(0, b"{}"), **{"err-truncated": True})))),
            ("qga-status-terminal-fields-malformed", "unavailable", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", dict(terminal(0, b"{}"), **{"out-truncated": "false"})))),
            ("qga-status-terminal-fields-malformed", "unavailable", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", dict(terminal(0, b"{}"), **{"err-truncated": "false"})))),
            ("powershell-empty-or-malformed-output", "unavailable", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, b"not-json")))),
            ("projection", "unavailable", "missing-or-extra-fields", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, b'{"version":1}')))),
            ("projection", "unavailable", "missing-or-extra-fields", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, json.dumps(dict(good, extra=True)).encode())))),
            ("projection", "unavailable", "version-or-phase-invalid", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, json.dumps(dict(good, version=True)).encode())))),
            ("projection", "unavailable", "version-or-phase-invalid", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, json.dumps(dict(good, version=1.0)).encode())))),
            ("projection", "unavailable", "version-or-phase-invalid", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, json.dumps(dict(good, phase=[])).encode())))),
            ("projection", "unavailable", "version-or-phase-invalid", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, json.dumps(dict(good, phase="bad")).encode())))),
            ("projection", "unavailable", "nonzero-failure-envelope-invalid", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(1, json.dumps(good).encode())))),
            ("projection", "unavailable", "success-enum-invalid", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, json.dumps(dict(good, task="unknown")).encode())))),
            ("projection", "unavailable", "success-enum-invalid", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, json.dumps(dict(good, product=[])).encode())))),
            ("projection", "unavailable", "product-version-invalid", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, json.dumps(dict(good, installedVersion="bad")).encode())))),
            ("none", "none", "none", (("guest-exec", {"pid": 7}),
                ("guest-exec-status", terminal(0, json.dumps(good).encode())))),
            ("none", "none", (("guest-exec", {"pid": 7}), ("guest-exec-status", {
                "exited": True, "exitcode": 0,
                "out-data": base64.b64encode(json.dumps(good).encode()).decode()}))),
        ) + tuple(("powershell-nonzero", phase, (("guest-exec", {"pid": 7}),
            ("guest-exec-status", terminal(1, json.dumps(failed(phase)).encode()))))
            for phase in ("task", "leaf", "process", "product", "installer", "output"))
        for case in cases:
            expected, phase, *rest = case
            projection_reason, replies = (rest if len(rest) == 2 else
                                          ("missing-or-extra-fields" if expected == "projection" else
                                           ("none" if expected == "none" else "unavailable"), rest[0]))
            with self.subTest(expected=expected, phase=phase, projection_reason=projection_reason):
                result = _run_dispatch_absent_program(replies)
            self.assertEqual(result["state"], "diagnosed")
            self.assertEqual(result["checkpoint"], "remote-dispatch-absent")
            self.assertEqual(result["guestProofFailure"], expected)
            if expected == "none":
                self.assertEqual(result["guestProof"], {key: value for key, value in good.items()
                                                       if key not in {"version", "phase"}})
                self.assertEqual(result["guestProofFailurePhase"], phase)
                self.assertEqual(result["guestProofProjectionReason"], "none")
            else:
                self.assertEqual(result["guestProof"], {"task": "unknown", "leaf": "unknown",
                    "result": "unknown", "correlationPowerShell": "unknown", "product": "unknown",
                    "installedVersion": None, "installer": "unknown"})
                self.assertEqual(result["guestProofFailurePhase"], phase)
                self.assertEqual(result["guestProofProjectionReason"], projection_reason)
                if projection_reason == "missing-or-extra-fields":
                    self.assertIn("guestProofProjectionSchema", result)
                else:
                    self.assertNotIn("guestProofProjectionSchema", result)

    def test_dispatch_absent_program_imports_regex_for_valid_single_product_projection(self):
        if not Path("/proc/self/stat").is_file():
            self.skipTest("The fixed remote QGA observer requires Linux procfs.")
        product = {"version": 1, "phase": "output", "task": "absent", "leaf": "absent",
                   "result": "absent", "correlationPowerShell": "absent", "product": "single",
                   "installedVersion": "2.1.17", "installer": "absent"}
        terminal = {"exited": True, "exitcode": 0, "out-truncated": False, "err-truncated": False,
                    "out-data": base64.b64encode(json.dumps(product).encode()).decode()}
        replies = (("guest-exec", {"pid": 7}), ("guest-exec-status", terminal))
        result = _run_dispatch_absent_program(replies)
        self.assertEqual(result["guestProofFailure"], "none")
        self.assertEqual(result["guestProof"]["product"], "single")
        self.assertEqual(result["guestProof"]["installedVersion"], "2.1.17")
        self.assertNotIn("guestProofProjectionSchema", result)
        without_re = base._DIAGNOSTIC.replace("json,os,re,secrets", "json,os,secrets", 1)
        result = _run_dispatch_absent_program(replies, program=without_re)
        self.assertEqual(result["guestProofFailure"], "projection")
        self.assertEqual(result["guestProofProjectionReason"], "internal-error")
        self.assertNotIn("guestProofProjectionSchema", result)
        self.assertNotIn("replayAllowed", result)
        self.assertNotIn("nativeActionAllowed", result)

    def test_dispatch_absent_program_reports_only_bounded_missing_extra_schema(self):
        if not Path("/proc/self/stat").is_file():
            self.skipTest("The fixed remote QGA observer requires Linux procfs.")
        terminal = lambda value: {"exited": True, "exitcode": 0, "out-truncated": False,
                                  "err-truncated": False,
                                  "out-data": base64.b64encode(json.dumps(value).encode()).decode()}
        complete = {"version": 1, "phase": "output", "task": "absent", "leaf": "absent",
                    "result": "absent", "correlationPowerShell": "absent", "product": "absent",
                    "installedVersion": None, "installer": "absent"}
        cases = (({"version": 1}, {"presenceMask": "100000000", "extraFieldCount": 0}),
                 (dict(complete, extra=True), {"presenceMask": "111111111", "extraFieldCount": 1}),
                 (dict(complete, **{f"x{index}": True for index in range(10)}),
                  {"presenceMask": "111111111", "extraFieldCount": 9}))
        for value, expected_schema in cases:
            with self.subTest(expected_schema=expected_schema):
                result = _run_dispatch_absent_program((("guest-exec", {"pid": 7}),
                                                        ("guest-exec-status", terminal(value))))
            self.assertEqual(result["guestProofFailure"], "projection")
            self.assertEqual(result["guestProofProjectionReason"], "missing-or-extra-fields")
            self.assertEqual(result["guestProofProjectionSchema"], expected_schema)
            self.assertFalse(result.get("replayAllowed", False))
            self.assertNotIn("nativeActionAllowed", result)

    def test_base_role_finish_requires_native_terminal_and_idle_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base._reserve(root, {"request": REQUEST, "pair": PAIR, "leaseId": CORR})
            terminal = {"state": "terminal", "correlationId": CORR, "result": "PASSED",
                        "stage": "READBACK", "exitCode": 0, "sourceSha": SOURCE,
                        "baseArtifactId": ARTIFACT}
            idle = {"state": "ready", "activeCount": 0, "installedVersion": PAIR["baseVersion"]}
            with patch.object(base, "status", return_value=dict(terminal, result="FAILED")), \
                 patch.object(base, "readiness", return_value=idle), \
                 patch.object(base.campaign_lease, "finish_role") as finish:
                with self.assertRaisesRegex(base.WindowsMsiBasePrepareError, "terminal"):
                    base.finish_observed(root, CORR)
                finish.assert_not_called()
            with patch.object(base, "status", return_value=terminal), \
                 patch.object(base, "readiness", return_value=dict(idle, activeCount=1)), \
                 patch.object(base.campaign_lease, "finish_role") as finish:
                with self.assertRaisesRegex(base.WindowsMsiBasePrepareError, "cleanup"):
                    base.finish_observed(root, CORR)
                finish.assert_not_called()
            with patch.object(base, "status", return_value=terminal), \
                 patch.object(base, "readiness", return_value=idle), \
                 patch.object(base, "_descriptor", return_value=(object(), object(),
                    ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_verified_claimed_campaign"), \
                 patch.object(base.campaign_lease, "finish_role", return_value={"state": "active"}) as finish:
                self.assertEqual(base.finish_observed(root, CORR)["state"], "active")
                self.assertEqual(finish.call_args.args[1:4], (CORR, "base", CORR))
            with patch.object(base, "status", return_value={"state": "unknown", "correlationId": CORR}), \
                 patch.object(base, "terminal_reconcile", return_value=terminal) as durable, \
                 patch.object(base, "readiness", return_value=idle), \
                 patch.object(base, "_descriptor", return_value=(object(), object(),
                    ("windows-cp117", "/qga.sock", 589342, 520739, "S-1-5-21-1-2-3-1002"))), \
                 patch.object(base, "_verified_claimed_campaign"), \
                 patch.object(base.campaign_lease, "finish_role", return_value={"state": "active"}) as finish:
                self.assertEqual(base.finish_observed(root, CORR)["state"], "active")
                durable.assert_called_once_with(root.resolve(), {"correlationId": CORR})
                finish.assert_called_once()

    def _unknown_close_root(self, root: Path) -> tuple[object, object, tuple]:
        directory = root / base._LOCAL
        directory.mkdir(mode=0o700, parents=True)
        record = {"request": base._UNKNOWN_CLOSURE_REQUEST, "pair": {"sourceSha": base._UNKNOWN_CLOSURE_REQUEST["sourceSha"], "sourceFingerprint": "a" * 64},
                  "environment": "windows-cp117", "socketPath": "/owned/cp117.qga", "pid": 4321,
                  "startTicks": 98765, "expectedSid": "S-1-5-21-1-2-3-1002",
                  "commandSha256": base._UNKNOWN_CLOSURE_COMMAND_SHA256,
                  "leaseId": base._UNKNOWN_CLOSURE_CORRELATION}
        (directory / (base._UNKNOWN_CLOSURE_CORRELATION + ".json")).write_text(json.dumps(record))
        os.chmod(directory / (base._UNKNOWN_CLOSURE_CORRELATION + ".json"), 0o600)
        class Target: fixture_transfer_root = root / "remote"
        return object(), Target(), ("windows-cp117", "/owned/cp117.qga", 4321, 98765,
                                    "S-1-5-21-1-2-3-1002")

    @staticmethod
    def _unknown_diagnostic() -> dict:
        proof = {"task": "absent", "leaf": "present", "result": "absent",
                 "correlationPowerShell": "absent", "product": "single",
                 "installedVersion": "2.1.17", "installer": "absent"}
        return {"state": "unknown", "correlationId": base._UNKNOWN_CLOSURE_CORRELATION,
                "binding": "exact", "checkpoint": "remote-dispatch-absent",
                "guestProof": proof, "guestProofFailure": "none", "guestProofFailurePhase": "none",
                "guestProofProjectionReason": "none", "replayAllowed": False,
                "nativeActionAllowed": False}

    @staticmethod
    def _unknown_census(remote: str, leaf: str, mutation: str = "none") -> dict:
        return {"state": "observed", "correlationId": base._UNKNOWN_CLOSURE_CORRELATION,
                "remoteStage": remote, "mutation": mutation, "task": "absent", "leaf": leaf,
                "result": "absent", "correlationPowerShell": "absent", "product": "single",
                "installedVersion": "2.1.17", "installer": "absent"}

    def test_unknown_close_rejects_malformed_diagnostic_before_marker_or_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, target, descriptor = self._unknown_close_root(root)
            malformed = dict(self._unknown_diagnostic(), guestProofFailure="none", extra=True)
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "diagnose", return_value=malformed), \
                 patch.object(base, "_unknown_cleanup_census") as census:
                result = base.close_unknown(root, {"correlationId": base._UNKNOWN_CLOSURE_CORRELATION})
            self.assertEqual(result["state"], "unknown")
            self.assertFalse((root / base._LOCAL / (base._UNKNOWN_CLOSURE_CORRELATION + ".unknown-close.json")).exists())
            census.assert_not_called()

    def test_unknown_close_lost_cleanup_response_keeps_campaign_open_after_durable_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, target, descriptor = self._unknown_close_root(root)
            present = self._unknown_census("present", "present")
            absent = self._unknown_census("absent", "absent")
            replies = [present, present, present, None, absent, absent]
            calls = []
            def census(*args):
                calls.append(args[-1])
                if args[-1] == "cleanup":
                    self.assertTrue((root / base._LOCAL / (base._UNKNOWN_CLOSURE_CORRELATION + ".unknown-close.json")).exists())
                return replies.pop(0)
            ready = {"state": "ready", "ready": True, "installedVersion": "2.1.17",
                     "productCount": 1, "activeCount": 0, "activeProcesses": []}
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "diagnose", return_value=self._unknown_diagnostic()), \
                 patch.object(base, "readiness", return_value=ready), \
                 patch.object(base, "_unknown_cleanup_census", side_effect=census), \
                 patch.object(base.campaign_lease, "finish_role") as finish:
                result = base.close_unknown(root, {"correlationId": base._UNKNOWN_CLOSURE_CORRELATION})
            self.assertEqual(result["state"], "unknown")
            self.assertEqual(calls, ["status", "status", "status", "cleanup", "status", "status"])
            finish.assert_not_called()

    def test_unknown_close_resumes_a_leaf_only_partial_state_after_lost_response(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, target, descriptor = self._unknown_close_root(root)
            intent = base._private_intent(root, base._UNKNOWN_CLOSURE_CORRELATION)
            original = self._unknown_census("present", "present")
            marker = base._unknown_close_marker_value(intent, descriptor, original, original)
            self.assertTrue(base._write_private_once(base._unknown_closure_marker(root), marker))
            partial = self._unknown_census("absent", "present")
            absent = self._unknown_census("absent", "absent")
            replies = [partial, partial, partial, None, absent, absent]
            ready = {"state": "ready", "ready": True, "installedVersion": "2.1.17",
                     "productCount": 1, "activeCount": 0, "activeProcesses": []}
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "diagnose") as diagnose, \
                 patch.object(base, "readiness", return_value=ready), \
                 patch.object(base, "_unknown_cleanup_census", side_effect=replies), \
                 patch.object(base.campaign_lease, "finish_role") as finish:
                result = base.close_unknown(root, {"correlationId": base._UNKNOWN_CLOSURE_CORRELATION})
            self.assertEqual(result["state"], "unknown")
            diagnose.assert_not_called()
            finish.assert_not_called()

    def test_unknown_close_resumes_empty_remote_stage_and_post_finish_close(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, target, descriptor = self._unknown_close_root(root)
            intent = base._private_intent(root, base._UNKNOWN_CLOSURE_CORRELATION)
            original = self._unknown_census("present", "present")
            self.assertTrue(base._write_private_once(base._unknown_closure_marker(root),
                base._unknown_close_marker_value(intent, descriptor, original, original)))
            partial = self._unknown_census("empty", "absent")
            absent = self._unknown_census("absent", "absent")
            replies = [partial, partial, partial, absent, absent, absent]
            ready = {"state": "ready", "ready": True, "installedVersion": "2.1.17",
                     "productCount": 1, "activeCount": 0, "activeProcesses": []}
            evidence = {"afterFirst": absent, "afterSecond": absent,
                        "closeIntent": base._UNKNOWN_CLOSURE_CORRELATION}
            evidence_sha = __import__("hashlib").sha256(json.dumps(evidence, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            record = {"identity": base._campaign_identity(base._UNKNOWN_CLOSURE_REQUEST, descriptor),
                      "state": "active", "role": None, "correlationId": None, "server": "stopped",
                      "credentials": "absent", "lastOutcome": "unknown-cleaned",
                      "lastEvidenceSha256": evidence_sha}
            lock_path = root / "campaign.lock"; lock_path.touch(); lock_fd = os.open(lock_path, os.O_RDWR)
            try:
                with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                     patch.object(base, "diagnose") as diagnose, \
                     patch.object(base, "readiness", return_value=ready), \
                     patch.object(base, "_unknown_cleanup_census", side_effect=replies), \
                     patch.object(base.campaign_lease, "inspect", return_value={"state": "active"}), \
                     patch.object(base.campaign_lease, "_locked", return_value=(root, lock_fd)), \
                     patch.object(base.campaign_lease, "_active", return_value=record), \
                     patch.object(base.campaign_lease, "_remote_confirm", return_value=True), \
                     patch.object(base.campaign_lease, "finish_role") as finish, \
                     patch.object(base.campaign_lease, "close", return_value={"state": "closed"}) as close:
                    result = base.close_unknown(root, {"correlationId": base._UNKNOWN_CLOSURE_CORRELATION})
                self.assertEqual(result["state"], "closed")
                diagnose.assert_not_called()
                finish.assert_not_called()
                close.assert_called_once()
            finally:
                try: os.close(lock_fd)
                except OSError: pass

    def test_second_unknown_close_marker_cleans_partial_stage_only_under_45e_and_keeps_both_archives(self):
        """TEST-001: a partial MSI after a lost 45e transport stays non-replayable.

        The durable marker suppresses a second diagnostic/installer attempt.  The
        exact correlation must travel through all status and cleanup censuses
        before the role can close, and archive admission must retain both
        historical intent journals.
        """
        correlation = base._TRANSFER_RECOVERY_CORRELATION
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, target, descriptor = self._unknown_close_root(root)
            journal = root / base._LOCAL
            previous = base._private_intent(root, base._UNKNOWN_CLOSURE_CORRELATION)
            intent = {"request": base._TRANSFER_RECOVERY_REQUEST,
                      "pair": {"sourceSha": base._TRANSFER_RECOVERY_REQUEST["sourceSha"],
                               "sourceFingerprint": "a" * 64},
                      "environment": descriptor[0], "socketPath": descriptor[1], "pid": descriptor[2],
                      "startTicks": descriptor[3], "expectedSid": descriptor[4],
                      "commandSha256": base._TRANSFER_RECOVERY_COMMAND_SHA256, "leaseId": correlation}
            intent_path = journal / (correlation + ".json")
            intent_path.write_text(json.dumps(intent)); intent_path.chmod(0o600)
            present = {"state": "observed", "correlationId": correlation, "remoteStage": "present",
                       "mutation": "none", "task": "absent", "leaf": "present", "result": "absent",
                       "correlationPowerShell": "absent", "product": "single", "installedVersion": "2.1.17",
                       "installer": "absent"}
            absent = dict(present, remoteStage="absent", leaf="absent")
            marker = base._unknown_close_marker_value(intent, descriptor, present, present, correlation)
            self.assertTrue(base._write_private_once(base._unknown_closure_marker(root, correlation), marker))
            evidence = {"afterFirst": absent, "afterSecond": absent, "closeIntent": correlation}
            evidence_sha = __import__("hashlib").sha256(json.dumps(evidence, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            record = {"identity": base._campaign_identity(base._TRANSFER_RECOVERY_REQUEST, descriptor),
                      "state": "role-active", "role": "base", "correlationId": correlation,
                      "server": "stopped", "credentials": "absent", "lastOutcome": None,
                      "lastEvidenceSha256": None}
            ready = {"state": "ready", "ready": True, "installedVersion": "2.1.17",
                     "productCount": 1, "activeCount": 0, "activeProcesses": []}
            lock_path = root / "campaign-45e.lock"; lock_path.touch(); lock_fd = os.open(lock_path, os.O_RDWR)
            calls: list[tuple[str, str]] = []
            def census(*args):
                calls.append((args[-2], args[-1]))
                return [present, present, present, absent, absent, absent][len(calls) - 1]
            try:
                with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                     patch.object(base, "diagnose") as diagnose, \
                     patch.object(base, "readiness", return_value=ready), \
                     patch.object(base, "_unknown_cleanup_census", side_effect=census), \
                     patch.object(base.campaign_lease, "inspect", return_value={"state": "active"}), \
                     patch.object(base.campaign_lease, "_locked", return_value=(root, lock_fd)), \
                     patch.object(base.campaign_lease, "_active", return_value=record), \
                     patch.object(base.campaign_lease, "_remote_confirm", return_value=True), \
                     patch.object(base.campaign_lease, "finish_role", return_value={"state": "active"}) as finish, \
                     patch.object(base.campaign_lease, "close", return_value={"state": "closed"}) as close:
                    result = base.close_unknown(root, {"correlationId": correlation})
                self.assertEqual(result, {"state": "closed", "correlationId": correlation,
                                          "outcome": "unknown-cleaned", "replayAllowed": False})
                diagnose.assert_not_called()
                self.assertEqual(calls, [("status", correlation), ("status", correlation),
                                         ("status", correlation), ("cleanup", correlation),
                                         ("status", correlation), ("status", correlation)])
                finish.assert_called_once_with(root.resolve(), correlation, "base", correlation, evidence_sha,
                                               "unknown-cleaned", unittest.mock.ANY)
                close.assert_called_once_with(root.resolve(), correlation, unittest.mock.ANY, unittest.mock.ANY)
            finally:
                pass
            # Re-observe both archives through their exact marker, closed
            # record, and two fresh censuses; the admission path never trusts
            # a caller-authored archive flag.
            previous_present = self._unknown_census("present", "present")
            self.assertTrue(base._write_private_once(base._unknown_closure_marker(root),
                base._unknown_close_marker_value(previous, descriptor, previous_present, previous_present)))
            previous_absent = self._unknown_census("absent", "absent")
            previous_evidence = {"afterFirst": previous_absent, "afterSecond": previous_absent,
                                 "closeIntent": base._UNKNOWN_CLOSURE_CORRELATION}
            previous_sha = __import__("hashlib").sha256(json.dumps(previous_evidence, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            closed_records = {
                base._UNKNOWN_CLOSURE_CORRELATION: {
                    "identity": base._campaign_identity(base._UNKNOWN_CLOSURE_REQUEST, descriptor),
                    "lastOutcome": "unknown-cleaned", "lastEvidenceSha256": previous_sha},
                correlation: {"identity": base._campaign_identity(base._TRANSFER_RECOVERY_REQUEST, descriptor),
                              "lastOutcome": "unknown-cleaned", "lastEvidenceSha256": evidence_sha},
            }
            archive_lock = root / "archive-45e.lock"; archive_lock.touch()
            archive_calls: list[str] = []
            def locked(_root): return root, os.open(archive_lock, os.O_RDWR)
            def archive_census(*args):
                observed = args[-1] if args[-1] in base._UNKNOWN_RECOVERY_PROFILES else base._UNKNOWN_CLOSURE_CORRELATION
                archive_calls.append(observed)
                return absent if observed == correlation else previous_absent
            with patch.object(base.campaign_lease, "_locked", side_effect=locked), \
                 patch.object(base.campaign_lease, "_active", return_value=None), \
                 patch.object(base.campaign_lease, "_closed", side_effect=lambda _directory, corr: closed_records.get(corr)), \
                 patch.object(base, "_unknown_cleanup_census", side_effect=archive_census):
                names = base._archived_base_record_names(root, config, target, descriptor)
                self.assertEqual(archive_calls, [base._UNKNOWN_CLOSURE_CORRELATION, base._UNKNOWN_CLOSURE_CORRELATION,
                                                 correlation, correlation])
                self.assertIn(base._UNKNOWN_CLOSURE_CORRELATION + ".json", names)
                self.assertIn(correlation + ".json", names)
                base._reserve(root, {"request": dict(REQUEST, correlationId=CORR), "commandSha256": "b" * 64},
                              config=config, target=target, descriptor=descriptor)
            self.assertEqual(base._private_intent(root, base._UNKNOWN_CLOSURE_CORRELATION), previous)
            self.assertEqual(base._private_intent(root, correlation), intent)

    def test_unknown_cleanup_program_has_no_task_or_installer_start_and_uses_phase_specific_delete(self):
        self.assertNotIn("Start-ScheduledTask", base._UNKNOWN_CLEANUP)
        self.assertNotIn("msiexec.exe' -ArgumentList", base._UNKNOWN_CLEANUP)
        self.assertIn("Remove-Item -LiteralPath $leaf -Force -Recurse", base._UNKNOWN_CLEANUP)
        self.assertIn("if remote=='present':os.unlink(os.path.join(stage,'binding.json'))", base._UNKNOWN_CLEANUP)
        self.assertIn("os.rmdir(stage)", base._UNKNOWN_CLEANUP)
        self.assertIn("mode not in ('status','cleanup')", base._UNKNOWN_CLEANUP)
        self.assertIn("Get-ItemProperty -Path ($path+'\\\\*') -ErrorAction Stop", base._UNKNOWN_CLEANUP)
        self.assertIn("Get-ScheduledTask -TaskPath '\\\\' -ErrorAction Stop|Where-Object", base._UNKNOWN_CLEANUP)
        self.assertIn("name='powershell.exe' OR name='pwsh.exe'", base._UNKNOWN_CLEANUP)
        self.assertIn("$_.ProcessId -ne $PID", base._UNKNOWN_CLEANUP)
        self.assertNotIn("Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue", base._UNKNOWN_CLEANUP)
        self.assertIn("elif names==set():remote='empty'", base._UNKNOWN_CLEANUP)
        self.assertIn("proof=guest();safe=(proof['task']=='absent'", base._UNKNOWN_CLEANUP)

    @staticmethod
    def _cleanup_terminal(value: dict, *, exitcode: int = 0) -> dict:
        return {"exited": True, "exitcode": exitcode, "out-truncated": False,
                "err-truncated": False, "out-data": base64.b64encode(json.dumps(value).encode()).decode()}

    @staticmethod
    def _cleanup_guest(*, leaf: str = "present", task: str = "absent") -> dict:
        return {"version": 1, "phase": "output", "task": task, "leaf": leaf, "result": "absent",
                "correlationPowerShell": "absent", "product": "single",
                "installedVersion": "2.1.17", "installer": "absent"}

    def test_unknown_cleanup_second_census_unsafe_preserves_exact_remote_stage(self):
        safe = self._cleanup_guest(leaf="present")
        unsafe = self._cleanup_guest(leaf="absent", task="present")
        result, stage_exists = _run_unknown_cleanup_program([
            self._cleanup_terminal(safe),
            self._cleanup_terminal({"version": 1, "state": "absent"}),
            self._cleanup_terminal(unsafe)], mode="cleanup", stage="bound")
        self.assertEqual(result, {"state": "unknown", "correlationId": base._UNKNOWN_CLOSURE_CORRELATION,
                                  "phase": "guest-recheck"})
        self.assertTrue(stage_exists)

    def test_unknown_cleanup_malformed_guest_failure_envelope_is_projection_without_stage_mutation(self):
        result, stage_exists = _run_unknown_cleanup_program([
            self._cleanup_terminal({}, exitcode=1)], mode="cleanup", stage="bound")
        self.assertEqual(result, {"state": "unknown", "correlationId": base._UNKNOWN_CLOSURE_CORRELATION,
                                  "phase": "guest-projection"})
        self.assertTrue(stage_exists)

    def test_unknown_cleanup_transport_and_output_failures_have_bounded_subcodes(self):
        cases = [
            ([('exec', {"pid": "bad"})], "guest-qga-exec"),
            ([None], "guest-qga-status-rpc"),
            ([17], "guest-qga-status-rpc"),
            ([{"exited": "bad"}], "guest-qga-status-exited-malformed"),
            ([{"exited": True, "exitcode": "bad"}], "guest-qga-status-terminal-fields"),
            ([dict(self._cleanup_terminal(self._cleanup_guest(leaf="absent")), **{"out-truncated": True})],
             "guest-qga-status-truncated"),
            ([{"exited": True, "exitcode": 0, "out-truncated": False, "err-truncated": False,
               "out-data": base64.b64encode(b"not-json").decode()}], "guest-empty-or-malformed-output"),
            ([self._cleanup_terminal({"version": 1})], "guest-projection"),
        ]
        for replies, phase in cases:
            with self.subTest(phase=phase):
                result, stage_exists = _run_unknown_cleanup_program(replies, mode="cleanup", stage="bound")
                self.assertEqual(result, {"state": "unknown", "correlationId": base._UNKNOWN_CLOSURE_CORRELATION,
                                          "phase": phase})
                self.assertTrue(stage_exists)

    def test_unknown_cleanup_running_guest_status_times_out_without_stage_mutation(self):
        result, stage_exists = _run_unknown_cleanup_program([
            {"exited": False}], mode="cleanup", stage="bound", polls=1)
        self.assertEqual(result, {"state": "unknown", "correlationId": base._UNKNOWN_CLOSURE_CORRELATION,
                                  "phase": "guest-qga-status-running-timeout"})
        self.assertTrue(stage_exists)

    def test_unknown_cleanup_power_shell_task_failure_is_bounded_and_preserves_stage(self):
        failure = {"version": 1, "phase": "task", "task": "unknown", "leaf": "unknown",
                   "result": "unknown", "correlationPowerShell": "unknown", "product": "unknown",
                   "installedVersion": None, "installer": "unknown"}
        result, stage_exists = _run_unknown_cleanup_program([
            self._cleanup_terminal(failure, exitcode=1)], mode="cleanup", stage="bound")
        self.assertEqual(result, {"state": "unknown", "correlationId": base._UNKNOWN_CLOSURE_CORRELATION,
                                  "phase": "guest-task"})
        self.assertTrue(stage_exists)

    def test_unknown_cleanup_accepts_exact_positive_product_census(self):
        result, stage_exists = _run_unknown_cleanup_program([
            self._cleanup_terminal(self._cleanup_guest(leaf="absent"))], mode="status", stage="bound")
        self.assertEqual(result["state"], "observed")
        self.assertEqual(result["product"], "single")
        self.assertEqual(result["installedVersion"], "2.1.17")
        self.assertTrue(stage_exists)

    def test_unknown_cleanup_status_observes_safe_precleanup_leaf_without_mutation(self):
        result, stage_exists = _run_unknown_cleanup_program([
            self._cleanup_terminal(self._cleanup_guest(leaf="present"))], mode="status", stage="bound")
        self.assertEqual(result["state"], "observed")
        self.assertEqual((result["remoteStage"], result["mutation"], result["leaf"]),
                         ("present", "none", "present"))
        self.assertTrue(stage_exists)

    def test_unknown_cleanup_status_projects_valid_unsafe_proof_without_mutation(self):
        unsafe = self._cleanup_guest(leaf="present", task="present")
        result, stage_exists = _run_unknown_cleanup_program([
            self._cleanup_terminal(unsafe)], mode="status", stage="bound")
        self.assertEqual(result, {"state": "guest-unsafe", "correlationId": base._UNKNOWN_CLOSURE_CORRELATION,
                                  **{key: unsafe[key] for key in unsafe if key not in {"version", "phase"}}})
        self.assertTrue(stage_exists)
        result, stage_exists = _run_unknown_cleanup_program([
            self._cleanup_terminal(unsafe)], mode="cleanup", stage="bound")
        self.assertEqual(result, {"state": "unknown", "correlationId": base._UNKNOWN_CLOSURE_CORRELATION,
                                  "phase": "guest-census"})
        self.assertTrue(stage_exists)

    def test_unknown_cleanup_empty_stage_retry_deletes_exact_empty_stage_after_safe_census(self):
        result, stage_exists = _run_unknown_cleanup_program([
            self._cleanup_terminal(self._cleanup_guest(leaf="absent"))], mode="cleanup", stage="empty")
        self.assertEqual(result["state"], "observed")
        self.assertEqual(result["remoteStage"], "absent")
        self.assertEqual(result["mutation"], "remote-stage")
        self.assertFalse(stage_exists)

    def test_unknown_close_status_projects_each_bounded_phase_without_cleanup(self):
        correlation = {"correlationId": base._UNKNOWN_CLOSURE_CORRELATION}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(base, "_private_intent", return_value=None):
                self.assertEqual(base.close_unknown_status(root, correlation)["phase"], "local-intent")
            config, target, descriptor = self._unknown_close_root(root)
            intent = base._private_intent(root, base._UNKNOWN_CLOSURE_CORRELATION)
            with patch.object(base, "_descriptor", side_effect=ValueError("offline")):
                self.assertEqual(base.close_unknown_status(root, correlation)["phase"], "descriptor")
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "diagnose", return_value={"state": "unknown", "checkpoint": "qga-protocol"}), \
                 patch.object(base, "_unknown_cleanup_observe") as observe:
                result = base.close_unknown_status(root, correlation)
            self.assertEqual((result["phase"], result["reason"]), ("diagnostic", "qga-protocol"))
            observe.assert_not_called()
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "diagnose", return_value=self._unknown_diagnostic()), \
                 patch.object(base, "_unknown_cleanup_observe", return_value={"state": "unknown", "phase": "remote-stage"}), \
                 patch.object(base, "readiness") as readiness:
                result = base.close_unknown_status(root, correlation)
            self.assertEqual((result["phase"], result["reason"]), ("cleanup-status", "remote-stage"))
            readiness.assert_not_called()
            unsafe = {"state": "guest-unsafe", "correlationId": base._UNKNOWN_CLOSURE_CORRELATION,
                      **self._cleanup_guest(leaf="present", task="present")}
            unsafe.pop("version"); unsafe.pop("phase")
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "diagnose", return_value=self._unknown_diagnostic()), \
                 patch.object(base, "_unknown_cleanup_observe", return_value=unsafe), \
                 patch.object(base, "readiness") as readiness:
                result = base.close_unknown_status(root, correlation)
            self.assertEqual((result["phase"], result["reason"]), ("cleanup-status", "guest-unsafe"))
            self.assertEqual(result["guestProof"], {key: unsafe[key] for key in unsafe if key not in {"state", "correlationId"}})
            readiness.assert_not_called()
            malformed_unsafe = dict(unsafe, installedVersion=None)
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "diagnose", return_value=self._unknown_diagnostic()), \
                 patch.object(base, "_unknown_cleanup_observe", return_value=malformed_unsafe), \
                 patch.object(base, "readiness") as readiness:
                result = base.close_unknown_status(root, correlation)
            self.assertEqual((result["phase"], result["reason"]), ("cleanup-status", "projection"))
            readiness.assert_not_called()
            census = self._unknown_census("present", "present")
            calls = []
            def observe(*args):
                calls.append(args[-1]); return census
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "diagnose", return_value=self._unknown_diagnostic()), \
                 patch.object(base, "_unknown_cleanup_observe", side_effect=observe), \
                 patch.object(base, "readiness", return_value={"state": "blocked", "code": "PRODUCT_VERSION"}), \
                 patch.object(base, "_unknown_lease_status") as lease:
                result = base.close_unknown_status(root, correlation)
            self.assertEqual((result["phase"], result["reason"]), ("readiness", "PRODUCT_VERSION"))
            self.assertEqual(calls, ["status"])
            lease.assert_called_once_with(root.resolve())
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "diagnose", return_value=self._unknown_diagnostic()), \
                 patch.object(base, "_unknown_cleanup_observe", side_effect=observe), \
                 patch.object(base, "readiness", return_value={"state": "ready", "ready": True}), \
                 patch.object(base, "_unknown_lease_status", return_value={"state": "active", "role": "base", "server": "stopped", "lastOutcome": None}) as lease:
                result = base.close_unknown_status(root, correlation)
            self.assertEqual((result["state"], result["phase"], result["reason"]), ("observed", "lease", "active"))
            self.assertEqual(result["census"], census)
            self.assertEqual(lease.call_count, 2)
            lease.assert_called_with(root.resolve())

    def test_unknown_close_status_rejects_first_mutating_envelope_without_retry_or_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, target, descriptor = self._unknown_close_root(root)
            mutating = self._unknown_census("absent", "absent", mutation="remote-stage")
            valid = self._unknown_census("present", "present")
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "diagnose", return_value=self._unknown_diagnostic()), \
                 patch.object(base, "_unknown_cleanup_observe", side_effect=[mutating, valid]) as observe, \
                 patch.object(base, "readiness") as readiness, \
                 patch.object(base, "_unknown_lease_status") as lease:
                result = base.close_unknown_status(root, {"correlationId": base._UNKNOWN_CLOSURE_CORRELATION})
            self.assertEqual((result["phase"], result["reason"]), ("cleanup-status", "projection"))
            observe.assert_called_once()
            readiness.assert_not_called()
            lease.assert_called_once_with(root.resolve())

    def test_unknown_close_status_verifies_durable_postclosed_evidence_before_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, target, descriptor = self._unknown_close_root(root)
            intent = base._private_intent(root, base._UNKNOWN_CLOSURE_CORRELATION)
            present = self._unknown_census("present", "present")
            self.assertTrue(base._write_private_once(base._unknown_closure_marker(root),
                base._unknown_close_marker_value(intent, descriptor, present, present)))
            absent = self._unknown_census("absent", "absent")
            closed = {"state": "closed", "role": None, "server": "stopped",
                      "lastOutcome": "unknown-cleaned"}
            ready = {"state": "ready", "ready": True, "installedVersion": "2.1.17",
                     "productCount": 1, "activeCount": 0, "activeProcesses": []}
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "_unknown_lease_status", return_value=closed), \
                 patch.object(base, "_unknown_cleanup_observe", return_value=absent), \
                 patch.object(base, "readiness", return_value=ready), \
                 patch.object(base, "diagnose") as diagnose:
                result = base.close_unknown_status(root, {"correlationId": base._UNKNOWN_CLOSURE_CORRELATION})
            self.assertEqual((result["state"], result["phase"], result["outcome"]),
                             ("closed", "closed", "unknown-cleaned"))
            self.assertEqual(result["census"], absent)
            diagnose.assert_not_called()

    def test_unknown_close_status_rejects_postclosed_missing_or_ambiguous_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, target, descriptor = self._unknown_close_root(root)
            closed = {"state": "closed", "role": None, "server": "stopped",
                      "lastOutcome": "unknown-cleaned"}
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "_unknown_lease_status", return_value=closed), \
                 patch.object(base, "diagnose") as diagnose:
                missing = base.close_unknown_status(root, {"correlationId": base._UNKNOWN_CLOSURE_CORRELATION})
            self.assertEqual((missing["phase"], missing["reason"]), ("post-close-evidence", "marker-missing"))
            diagnose.assert_not_called()
            intent = base._private_intent(root, base._UNKNOWN_CLOSURE_CORRELATION)
            present = self._unknown_census("present", "present")
            self.assertTrue(base._write_private_once(base._unknown_closure_marker(root),
                base._unknown_close_marker_value(intent, descriptor, present, present)))
            with patch.object(base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(base, "_unknown_lease_status", return_value=closed), \
                 patch.object(base, "_unknown_cleanup_observe", return_value=self._unknown_census("present", "absent")), \
                 patch.object(base, "readiness") as readiness, \
                 patch.object(base, "diagnose") as diagnose:
                ambiguous = base.close_unknown_status(root, {"correlationId": base._UNKNOWN_CLOSURE_CORRELATION})
            self.assertEqual((ambiguous["phase"], ambiguous["reason"]), ("post-close-evidence", "both-absent"))
            readiness.assert_not_called()
            diagnose.assert_not_called()

    def test_unknown_closed_archive_requires_exact_marker_lease_and_fresh_both_absent_census(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, target, descriptor = self._unknown_close_root(root)
            intent = base._private_intent(root, base._UNKNOWN_CLOSURE_CORRELATION)
            present = self._unknown_census("present", "present")
            self.assertTrue(base._write_private_once(base._unknown_closure_marker(root),
                base._unknown_close_marker_value(intent, descriptor, present, present)))
            absent = self._unknown_census("absent", "absent")
            evidence = {"afterFirst": absent, "afterSecond": absent,
                        "closeIntent": base._UNKNOWN_CLOSURE_CORRELATION}
            evidence_sha = __import__("hashlib").sha256(json.dumps(evidence, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            closed = {"identity": base._campaign_identity(base._UNKNOWN_CLOSURE_REQUEST, descriptor),
                      "lastOutcome": "unknown-cleaned", "lastEvidenceSha256": evidence_sha}
            lock_path = root / "archive.lock"; lock_path.touch()
            def locked(_root): return root, os.open(lock_path, os.O_RDWR)
            with patch.object(base.campaign_lease, "_locked", side_effect=locked), \
                 patch.object(base.campaign_lease, "_active", return_value=None), \
                 patch.object(base.campaign_lease, "_closed", return_value=closed), \
                 patch.object(base, "_unknown_cleanup_census", side_effect=[absent, absent]):
                self.assertTrue(base._unknown_closure_archived(root, config, target, descriptor))
            with patch.object(base.campaign_lease, "_locked", side_effect=locked), \
                 patch.object(base.campaign_lease, "_active", return_value=None), \
                 patch.object(base.campaign_lease, "_closed", return_value=dict(closed, lastEvidenceSha256="0" * 64)), \
                 patch.object(base, "_unknown_cleanup_census", side_effect=[absent, absent]):
                self.assertFalse(base._unknown_closure_archived(root, config, target, descriptor))
            residual = self._unknown_census("present", "absent")
            with patch.object(base.campaign_lease, "_locked", side_effect=locked), \
                 patch.object(base.campaign_lease, "_active", return_value=None), \
                 patch.object(base.campaign_lease, "_closed", return_value=closed), \
                 patch.object(base, "_unknown_cleanup_census", side_effect=[absent, residual]):
                self.assertFalse(base._unknown_closure_archived(root, config, target, descriptor))
            forged = dict(intent, pair=dict(intent["pair"], sourceSha="0" * 40))
            path = root / base._LOCAL / (base._UNKNOWN_CLOSURE_CORRELATION + ".json")
            path.write_text(json.dumps(forged)); path.chmod(0o600)
            self.assertFalse(base._unknown_closure_archived(root, config, target, descriptor))
            base._unknown_closure_marker(root).unlink()
            self.assertFalse(base._unknown_closure_archived(root, config, target, descriptor))

    def test_unknown_closed_archive_allows_new_intent_without_deleting_old_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); config, target, descriptor = self._unknown_close_root(root)
            old_intent = base._private_intent(root, base._UNKNOWN_CLOSURE_CORRELATION)
            marker = base._unknown_closure_marker(root)
            marker.write_text("{}")
            marker.chmod(0o600)
            next_corr = "05fd80ad-b93f-4450-a3e5-a67d14f24478"
            with patch.object(base, "_unknown_closure_archived", return_value=True):
                base._require_base_route_free(root, config, target, descriptor)
                base._reserve(root, {"request": dict(REQUEST, correlationId=next_corr),
                                     "commandSha256": "a" * 64}, config=config, target=target,
                              descriptor=descriptor)
            self.assertEqual(base._private_intent(root, base._UNKNOWN_CLOSURE_CORRELATION), old_intent)
            self.assertTrue(marker.exists())
            self.assertIsNotNone(base._private_intent(root, next_corr))


if __name__ == "__main__":
    unittest.main()
