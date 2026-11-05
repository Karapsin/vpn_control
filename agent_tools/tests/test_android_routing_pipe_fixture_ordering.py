"""Real process ordering for the terminal-child/inherited-pipe fixture."""
import io
import subprocess
import sys
import unittest
from unittest import mock


class RoutingPipeFixtureOrderingTests(unittest.TestCase):
    def test_actual_fixture_waits_for_parent_before_capture_deadline(self):
        from agent_tools.tests import test_android_api35_routing_step_diagnostic as subject
        actual_popen = subprocess.Popen
        owned = []

        class StartupGatePopen(actual_popen):
            def __init__(self, argv, *args, **kwargs):
                argv = list(argv)
                if len(argv) < 4 or argv[:3] != [sys.executable, '-I', '-c']:
                    raise AssertionError('unexpected fixture child')
                self.startup_gated = '# routing_pipe_holder' not in argv[3]
                self.startup_released = False
                self.kill_requested = False
                if self.startup_gated:
                    # Only fixture startup is gated. Every poll, wait, clock,
                    # pipe, byte and classification remains the actual one.
                    argv[3] = 'import sys\nsys.stdin.buffer.read(1)\n' + argv[3]
                    kwargs['stdin'] = subprocess.PIPE
                super().__init__(argv, *args, **kwargs)
                owned.append(self)

            def kill(self):
                self.kill_requested = True
                return super().kill()

            def wait(self, *args, **kwargs):
                if self.startup_gated and not self.startup_released:
                    self.startup_released = True
                    try:
                        self.stdin.write(b'G')
                        self.stdin.flush()
                    except BrokenPipeError:
                        pass
                    finally:
                        self.stdin.close()
                return super().wait(*args, **kwargs)

        methods = [name for name in (
            'test_exited_parent_with_descendant_held_pipe_is_distinct',
            'test_exited_parent_with_inherited_pipe_holder_is_distinct')
            if hasattr(subject.RoutingTests, name)]
        self.assertEqual(1, len(methods))
        output = io.StringIO()
        try:
            with mock.patch.object(subprocess, 'Popen', StartupGatePopen):
                result = unittest.TextTestRunner(stream=output, verbosity=2).run(
                    unittest.TestSuite([subject.RoutingTests(methods[0])]))
        finally:
            for process in owned:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
        self.assertTrue(result.wasSuccessful(), output.getvalue())
        self.assertEqual(1, result.testsRun)
        self.assertEqual([], result.skipped)
        self.assertEqual(2, len(owned))
        self.assertEqual(1, sum(p.startup_gated for p in owned))
        for process in owned:
            self.assertEqual(0, process.returncode)
            self.assertFalse(process.kill_requested)
            self.assertTrue(all(stream is None or stream.closed
                                for stream in (process.stdin, process.stdout, process.stderr)))


if __name__ == '__main__':
    unittest.main()
