"""Read-only fixed Mac fixture server generation observation tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from agent_tools import macos_machine_kernel_observer as subject


SOURCE = "a" * 40
CORRELATION = "11111111-1111-4111-8111-111111111111"
INSTANCE = "22222222-2222-4222-8222-222222222222"
READY = "b" * 64
START = "darwin:100:200"


class Runner:
    def __init__(self):
        self.calls = []
        self.value = {"schemaVersion": 1, "sourceSha": SOURCE, "correlationId": CORRELATION,
                      "readySha256": READY, "serverInstanceId": INSTANCE, "serverPid": 123,
                      "serverProcessStartIdentity": START, "port": 49152,
                      "pidGenerationAlive": False, "listenerOpen": False}

    def __call__(self, argv, **_):
        self.calls.append(argv)
        rows = [{"Name": "vpn-control-boot-control53", "Source": "local",
                 "Running": True, "State": "running"}]
        output = rows if argv[:2] == ["tart", "list"] else self.value
        return SimpleNamespace(returncode=0, stdout=json.dumps(output))


class MacMachineKernelObserverTest(unittest.TestCase):
    def test_guest_kernel_branches_fail_closed_without_tart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parent = root / "state" / "acceptance-evidence" / CORRELATION
            parent.mkdir(parents=True, mode=0o700)
            ready = parent / "server-ready.json"
            ready.write_text(json.dumps({"serverPid": 123,
                                         "serverProcessStartIdentity": START, "port": 49152,
                                         "serverInstanceId": INSTANCE}))
            ready.chmod(0o600)
            original = subject._GUEST_PROBE.replace(
                "root=pathlib.Path('/Users/admin/macos-parity'+source[:7])",
                f"root=pathlib.Path({str(root)!r})").replace("501", str(os.getuid()))
            original = original.replace("index>=3", "index>=999")
            proc_line = "lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True);fn=lib.proc_pidinfo"
            socket_line = "results=[]"
            def run(mode, kill="esrch", ports=("refused", "refused"), source_code=None):
                proc = f'''class FakeProc:
 def __call__(self,pid,flavor,arg,pointer,size):
  if {mode!r}=='zero':return 0
  if {mode!r}=='partial':return 1
  info=ctypes.cast(pointer,ctypes.POINTER(Info)).contents
  info.pid=pid;info.startsec=100 if {mode!r}=='exact' else 200;info.startusec=200
  return ctypes.sizeof(Info)
fn=FakeProc()
def fake_kill(pid,signal):
 raise ProcessLookupError() if {kill!r}=='esrch' else PermissionError()
os.kill=fake_kill'''
                sockets = f'''_port_results=list({ports!r})
class FakeSocket:
 def settimeout(self,value):pass
 def connect_ex(self,address):
  value=_port_results.pop(0)
  return errno.ECONNREFUSED if value=='refused' else (0 if value=='open' else errno.ETIMEDOUT)
 def close(self):pass
socket.socket=lambda *args:FakeSocket()
results=[]'''
                code = (source_code or original).replace(proc_line, proc).replace(socket_line, sockets)
                return subprocess.run(["python3", "-c", code, SOURCE, CORRELATION],
                                      capture_output=True, text=True)
            absent = run("zero")
            self.assertEqual(absent.returncode, 0, absent.stderr)
            self.assertFalse(json.loads(absent.stdout)["pidGenerationAlive"])
            self.assertFalse(json.loads(absent.stdout)["listenerOpen"])
            link = parent / "duplicate-ready.json"
            os.link(ready, link)
            self.assertNotEqual(run("zero").returncode, 0)
            link.unlink()
            actual = parent / "actual-ready.json"
            ready.rename(actual)
            ready.symlink_to(actual)
            self.assertNotEqual(run("zero").returncode, 0)
            ready.unlink(); actual.rename(ready)
            altered = original.replace("raw=os.read(fd,16385);after=os.fstat(fd)",
                                       "raw=os.read(fd,16385);os.chmod(path,0o644);after=os.fstat(fd)")
            self.assertNotEqual(run("zero", source_code=altered).returncode, 0)
            ready.chmod(0o600)
            for mode, kill, ports in (("zero", "eperm", ("refused", "refused")),
                                      ("partial", "esrch", ("refused", "refused")),
                                      ("zero", "esrch", ("timeout", "refused"))):
                with self.subTest(mode=mode, kill=kill, ports=ports):
                    self.assertNotEqual(run(mode, kill, ports).returncode, 0)
            reused = run("mismatch")
            self.assertEqual(reused.returncode, 0, reused.stderr)
            self.assertFalse(json.loads(reused.stdout)["pidGenerationAlive"])
            live = run("exact", ports=("refused", "open"))
            self.assertEqual(live.returncode, 0, live.stderr)
            self.assertTrue(json.loads(live.stdout)["pidGenerationAlive"])
            self.assertTrue(json.loads(live.stdout)["listenerOpen"])

    def observe(self, runner):
        return subject.observe_server_generation(
            SOURCE, CORRELATION, expected_ready_sha256=READY,
            expected_instance_id=INSTANCE, expected_pid=123, expected_start=START,
            runner=runner)

    def test_exact_fixed_ready_and_fresh_kernel_absence(self):
        runner = Runner()
        self.assertEqual(self.observe(runner)["serverPid"], 123)
        self.assertEqual(runner.calls[1][:5], ["tart", "exec", "vpn-control-boot-control53",
                                               "/usr/bin/python3", "-c"])
        self.assertEqual(runner.calls[1][-2:], [SOURCE, CORRELATION])
        code = runner.calls[1][5]
        for token in ("O_NOFOLLOW", "dir_fd=parent", "before.st_nlink!=1", "proc_pidinfo",
                      "os.kill(pid,0)", "socket.AF_INET", "socket.AF_INET6",
                      "('127.0.0.1',port)", "('::1',port,0,0)"):
            self.assertIn(token, code)

    def test_changed_start_ready_instance_or_live_process_rejects(self):
        for field, value in (("readySha256", "f" * 64), ("serverInstanceId", CORRELATION),
                             ("serverProcessStartIdentity", "darwin:200:300"),
                             ("serverPid", 456), ("pidGenerationAlive", True),
                             ("pidGenerationAlive", 0), ("listenerOpen", True),
                             ("listenerOpen", 0), ("schemaVersion", True)):
            runner = Runner(); runner.value[field] = value
            with self.subTest(field=field), self.assertRaises(subject.MacReceiptError):
                self.observe(runner)

    def test_invalid_source_or_correlation_never_reaches_tart(self):
        runner = Runner()
        with self.assertRaises(subject.MacReceiptError):
            subject.observe_server_generation("../bad", CORRELATION, expected_ready_sha256=READY,
                expected_instance_id=INSTANCE, expected_pid=123, expected_start=START, runner=runner)
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
