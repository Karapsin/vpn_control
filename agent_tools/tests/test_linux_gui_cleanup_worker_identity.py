"""Actual used wrapper fragments: sudo monitor is not its unprivileged child."""
import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/linux_gui_cleanup_worker_identity'


class WorkerIdentityTests(unittest.TestCase):
    def run_fragment(self, child_uid=1000, present=False):
        worker = {'pid': 10559, 'startTicks': 424650, 'uid': child_uid}
        payload = {'recovery': {'recoveryWorker': worker}}
        monitor = SimpleNamespace(pid=10558, returncode=0, stdout=json.dumps(payload).encode(), poll=lambda: None)
        class FakePath:
            def __init__(self, path): self.path = path
            def stat(self): return SimpleNamespace(st_uid=0)
            def exists(self): return present
            def read_text(self): return '10558 (sudo) S ' + '0 ' * 18 + '424649'
        clock = iter([0, 11])
        ns = {'subprocess': SimpleNamespace(Popen=lambda *a, **k: monitor, PIPE=-1), 'Path': FakePath,
              'time': SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda n: None), 'json': json, 'p': monitor}
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile((FIXTURE / 'fixed.suffix.py').read_bytes(), 'actual-used-wrapper-fragment', 'exec'), ns)
        return ns['v']['recoveryWorkerTerminal']

    def test_kernel_child_identity_survives_root_monitor(self):
        result = self.run_fragment()
        self.assertEqual(result, {'pid':10559, 'startTicks':424650, 'uid':1000, 'terminalExitCode':0, 'physicallyAbsent':True})

    def test_wrong_child_uid_refused(self):
        with self.assertRaises(AssertionError): self.run_fragment(child_uid=0)

    def test_retained_child_refused(self):
        with self.assertRaises(AssertionError): self.run_fragment(present=True)


if __name__ == '__main__': unittest.main()
