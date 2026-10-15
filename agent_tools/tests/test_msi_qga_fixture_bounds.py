"""Physical portable bounds for the inert local QGA test fixture only."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from agent_tools.tests import test_windows_msi_base_prepare as fixtures


FIXTURE = Path(__file__).parent / "fixtures/msi_qga_fixture_bounds"
EOF_MESSAGE = "physical EOF reader must finish and refuse EOF before watchdog"
DRIVER = r'''import hashlib,json,os,socket,sys,time
from pathlib import Path
raw=Path(sys.argv[1]).read_bytes()
if hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError('reader_source_changed')
namespace={'socket':socket,'time':time}
exec(compile(raw,str(Path(sys.argv[1])),'exec'),namespace)
reader=namespace['receive']if sys.argv[3]=='before'else namespace['_receive_dispatch_qga_line']
left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
class SocketWitness:
 written=False
 def settimeout(self,seconds):return left.settimeout(seconds)
 def recv(self,size):
  raw=left.recv(size)
  if raw==b''and not self.written:
   value={'sourceSha256':sys.argv[2],'mode':sys.argv[3],'family':int(left.family),
          'readerEntered':True,'physicalEof':True}
   fd=os.open(sys.argv[4],os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
   with os.fdopen(fd,'w')as output:
    json.dump(value,output,sort_keys=True);output.flush();os.fsync(output.fileno())
   self.written=True
  return raw
witness=SocketWitness()
state='unexpected-return'
try:
 right.sendall(b'\xff{');right.shutdown(socket.SHUT_WR)
 try:
  if sys.argv[3]=='before':reader(witness)
  else:reader(witness,time.monotonic()+.5)
 except EOFError:state='eof-refused'
finally:left.close();right.close()
print(json.dumps({'state':state,'socketsClosed':left.fileno()==right.fileno()==-1}),flush=True)
'''


def exact_sources():
    provenance = json.loads((FIXTURE / "provenance.json").read_bytes())
    reader = (FIXTURE / "receive.before.fragment").read_bytes()
    helper = (FIXTURE / "helper.before.source").read_bytes()
    for raw, size, digest in ((reader, provenance["readerBytes"], provenance["readerSha256"]),
                              (helper, provenance["helperBytes"], provenance["helperSha256"])):
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("QGA before source changed")
    old_tree = ast.parse(helper.decode())
    old_reader = next(node for node in ast.walk(old_tree)
                      if isinstance(node, ast.FunctionDef) and node.name == "receive")
    if (ast.get_source_segment(helper.decode(), old_reader) + "\n").encode() != reader:
        raise ValueError("QGA reader is not the exact preserved helper component")
    current = Path(fixtures.__file__).read_text()
    current_node = next(node for node in ast.parse(current).body
                        if isinstance(node, ast.FunctionDef) and node.name == "_receive_dispatch_qga_line")
    return reader, (ast.get_source_segment(current, current_node) + "\n").encode()


def saved_file(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def reader_case(before):
    class PhysicalReaderCase(unittest.TestCase):
        def runTest(self):
            old, current = exact_sources()
            raw = old if before else current
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                driver = root / "reader-driver.py"
                source = root / "reader.source"
                witness_path = root / "physical-eof.json"
                saved_file(driver, DRIVER.encode())
                saved_file(source, raw)
                command = [sys.executable, "-B", str(driver), str(source), hashlib.sha256(raw).hexdigest(),
                           "before" if before else "current", str(witness_path)]
                self.assertLessEqual(sum(len(os.fsencode(word)) + 1 for word in command), 60000)
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           start_new_session=True)
                completed = False
                observed = None
                failure = None
                captured = False
                stdout = stderr = b""
                try:
                    startup_deadline = time.monotonic() + 5
                    while time.monotonic() < startup_deadline:
                        try:
                            descriptor = os.open(witness_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                            with os.fdopen(descriptor, "rb") as stream:
                                info = os.fstat(stream.fileno())
                                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                                    raise RuntimeError("physical EOF witness custody refused")
                                witness_raw = stream.read(4097)
                            if len(witness_raw) > 4096:
                                raise RuntimeError("physical EOF witness too large")
                            observed = json.loads(witness_raw)
                            break
                        except (FileNotFoundError, json.JSONDecodeError):
                            # The child may close immediately after publishing;
                            # retry partial publication even if it is terminal.
                            time.sleep(0.01)
                    expected = {"sourceSha256": hashlib.sha256(raw).hexdigest(),
                                "mode": "before" if before else "current", "family": int(socket.AF_UNIX),
                                "readerEntered": True, "physicalEof": True}
                    if observed != expected:
                        raise RuntimeError("reader did not establish physical EOF witness")
                    try:
                        stdout, stderr = process.communicate(timeout=3)
                        captured = True
                        completed = True
                    except subprocess.TimeoutExpired:
                        process.kill()  # The exact newly owned, single-process reader.
                        stdout, stderr = process.communicate(timeout=2)
                        captured = True
                except BaseException as error:
                    failure = error
                finally:
                    try:
                        if process.poll() is None:
                            try:
                                process.kill()
                            except BaseException as error:
                                if failure is None:
                                    failure = error
                        if not captured:
                            try:
                                stdout, stderr = process.communicate(timeout=2)
                            except BaseException as error:
                                if failure is None:
                                    failure = error
                        try:
                            process.wait(timeout=2)
                        except BaseException as error:
                            if failure is None:
                                failure = error
                    finally:
                        for stream in (process.stdout, process.stderr):
                            try:
                                stream.close()
                            except BaseException as error:
                                if failure is None:
                                    failure = error
                self.trace = {"before": before, "sourceSha256": hashlib.sha256(raw).hexdigest(),
                              "completed": completed, "childReaped": process.poll() is not None,
                              "physicalEofWitness": observed, "childReturncode": process.returncode,
                              "stderr": stderr.decode(errors="replace")}
                self.assertLessEqual(len(stdout) + len(stderr), 8192)
                print("QGA_READER_OBSERVATION " + json.dumps(self.trace, sort_keys=True), flush=True)
                if failure is not None:
                    raise failure
                self.assertTrue(self.trace["childReaped"])
                self.assertTrue(completed, EOF_MESSAGE)
                self.assertEqual(0, process.returncode, stderr.decode(errors="replace"))
                self.assertEqual({"state": "eof-refused", "socketsClosed": True}, json.loads(stdout))
    return PhysicalReaderCase()


@unittest.skipUnless(hasattr(socket, "AF_UNIX") and os.name == "posix", "Physical POSIX AF_UNIX fixture required")
class QgaFixtureBoundsTests(unittest.TestCase):
    def test_preserved_physical_eof_reader_is_actual_completion_red(self):
        result = unittest.TestResult()
        case = reader_case(True)
        case.run(result)
        trace = result.failures[0][1] if result.failures else ""
        self.assertLessEqual(len(trace.encode()), 8192)
        print("QGA_READER_COUNTERFACTUAL " + json.dumps({"testsRun": result.testsRun,
              "errors": len(result.errors), "skips": len(result.skipped), "failures": len(result.failures),
              "assertionTrace": trace, "observation": getattr(case, "trace", None)}, sort_keys=True), flush=True)
        self.assertEqual(1, result.testsRun)
        self.assertEqual([], result.errors)
        self.assertEqual([], result.skipped)
        self.assertEqual(1, len(result.failures), result.failures)
        self.assertIn(EOF_MESSAGE, trace)
        self.assertTrue(case.trace["childReaped"])
        self.assertFalse(case.trace["completed"])

    def test_fixed_physical_eof_reader_completes_and_closes(self):
        result = unittest.TestResult()
        reader_case(False).run(result)
        self.assertEqual(1, result.testsRun)
        self.assertEqual([], result.errors)
        self.assertEqual([], result.failures)
        self.assertEqual([], result.skipped)

    def test_real_line_reader_preserves_line_and_refuses_excess(self):
        for raw, expected in ((b'{"return":1}\n', b'{"return":1}\n'), (b"x" * 32769, None)):
            with self.subTest(size=len(raw)):
                left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                writer_errors = []
                right.settimeout(1)

                def send():
                    try:
                        right.sendall(raw)
                        right.shutdown(socket.SHUT_WR)
                    except Exception as error:
                        writer_errors.append(error)

                writer = threading.Thread(target=send)
                writer.start()
                try:
                    if expected is None:
                        with self.assertRaisesRegex(ValueError, "32768"):
                            fixtures._receive_dispatch_qga_line(left, time.monotonic() + 1)
                    else:
                        self.assertEqual(expected, fixtures._receive_dispatch_qga_line(left, time.monotonic() + 1))
                finally:
                    writer.join(timeout=1)
                    right.close()
                    left.close()
                    writer.join(timeout=1)
                self.assertFalse(writer.is_alive())
                self.assertEqual([], writer_errors)

    def test_silent_real_peer_obeys_absolute_read_deadline(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(TimeoutError, "line deadline"):
                fixtures._receive_dispatch_qga_line(left, started + 0.2)
        finally:
            left.close()
            right.close()
        self.assertLess(time.monotonic() - started, 2)

    def test_dribbling_real_peer_cannot_extend_absolute_read_deadline(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        stopped = threading.Event()
        writer_errors = []
        right.settimeout(0.5)

        def send():
            try:
                while not stopped.is_set():
                    right.sendall(b"x")
                    stopped.wait(0.04)
            except Exception as error:
                writer_errors.append(error)

        writer = threading.Thread(target=send)
        writer.start()
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(TimeoutError, "line deadline"):
                fixtures._receive_dispatch_qga_line(left, started + 0.2)
        finally:
            stopped.set()
            writer.join(timeout=1)
            left.close()
            right.close()
        self.assertFalse(writer.is_alive())
        self.assertEqual([], writer_errors)
        self.assertLess(time.monotonic() - started, 2)

    def run_fixture(self, program, replies, *, budget=0.75):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(root / "qga.sock"))
            server.listen(1)
            driver = root / "peer.py"
            saved_file(driver, program.encode())
            command = [sys.executable, "-B", str(driver), str(root / "qga.sock")]
            started = time.monotonic()
            try:
                result = fixtures._run_dispatch_absent_fixture(server, replies, command, budget_seconds=budget)
            except Exception as error:
                self.assertEqual({"childReaped": True, "threadTerminal": True, "serverClosed": True,
                                  "childPipesClosed": True}, getattr(error, "fixture_cleanup", None))
                self.assertLess(time.monotonic() - started, budget + 2.5)
                return error
            finally:
                server.close()
            self.assertEqual({"childReaped": True, "threadTerminal": True, "serverClosed": True,
                              "childPipesClosed": True}, result.fixture_cleanup)
            return result

    def test_no_connect_child_deadline_closes_accept_thread_and_reaps_child(self):
        error = self.run_fixture("import time\ntime.sleep(20)\n", (("guest-exec", {}),))
        self.assertIsInstance(error, subprocess.TimeoutExpired)

    def test_silent_connected_child_deadline_closes_read_thread_and_reaps_child(self):
        error = self.run_fixture("import socket,sys,time\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
                                 "s.connect(sys.argv[1]);s.sendall(b'\\xff{');time.sleep(20)\n",
                                 (("guest-exec", {}),))
        self.assertIsInstance(error, subprocess.TimeoutExpired)

    def test_protocol_error_is_retained_and_owned_resources_close(self):
        error = self.run_fixture("import socket,sys\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
                                 "s.connect(sys.argv[1]);s.sendall(b'\\xff{');s.shutdown(socket.SHUT_WR);"
                                 "assert s.recv(1)==b'';s.close()\n",
                                 (("guest-exec", {}),))
        self.assertIsInstance(error, EOFError)
        self.assertTrue(any(isinstance(item, EOFError) for item in error.fixture_thread_errors))

    def test_real_complete_exchange_preserves_response_and_closes(self):
        program = r'''import json,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(sys.argv[1])
f=s.makefile('rb');s.sendall(b'\xff{"execute":"guest-sync-delimited","arguments":{"id":41}}\n')
assert json.loads(f.readline()[1:])=={'return':41}
s.sendall(b'{"execute":"guest-exec","arguments":{}}\n')
assert json.loads(f.readline())=={'return':{'pid':7}}
f.close();s.close();print('{"state":"complete"}')
'''
        result = self.run_fixture(program, (("guest-exec", {"pid": 7}),), budget=2)
        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual({"state": "complete"}, json.loads(result.stdout))

    def test_command_over_60000_bytes_refuses_before_child_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "must-not-exist"
            driver = root / "peer.py"
            saved_file(driver, ("from pathlib import Path\nPath(" + repr(str(marker)) + ").touch()\n").encode())
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(root / "qga.sock"))
                server.listen(1)
                command = [sys.executable, "-B", str(driver), "x" * 60000]
                with self.assertRaisesRegex(ValueError, "60000 bytes"):
                    fixtures._run_dispatch_absent_fixture(server, (), command)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    if "--legacy-red" in sys.argv:
        result = unittest.TextTestRunner(verbosity=2).run(reader_case(True))
        raise SystemExit(not result.wasSuccessful())
    unittest.main()
