"""Complete locked submission validates data without pre-admission generation."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import readiness_windows_jobs as jobs
from agent_tools.tests.test_readiness_windows import snapshot


class WindowsInnerGenerationTests(unittest.TestCase):
    def test_whole_inner_dispatch_generated_before_readiness_red_then_pure_validation_green(self):
        folder = Path(__file__).parent / 'fixtures/windows_jobs_inner_generation'
        raw = (folder / 'before.source').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), json.loads((folder / 'provenance.json').read_bytes())['sourceSha256'])
        before = types.ModuleType('agent_tools._windows_inner_generation_before')
        before.__package__, before.__file__ = 'agent_tools', str(folder / 'before.source')
        sys.modules[before.__name__] = before
        self.addCleanup(sys.modules.pop, before.__name__, None)
        exec(compile(raw, before.__file__, 'exec'), before.__dict__)
        class DispatchBoundary(Exception):
            pass
        for module in (before, jobs):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as directory:
                binding = module.WindowsJobBinding('abcdef78-1234-4234-9234-123456789012',
                    '2026-10-20T09:04:39.5000000Z', '12345678:0003000000000847:01dd6077063bd7e7',
                    '12345678:0003000000000848:01dd6077063bd7e8')
                saved = snapshot()
                saved['binding']['spec']['deploymentId'] = binding.machine
                backend = types.SimpleNamespace(root=Path(directory).resolve(), target='windows:trusted:'+binding.machine,
                    machine=binding.machine, provider=saved['provider'], binding=saved['binding'], expected_sid=saved['expectedSid'])
                state = {**saved, 'guest':module.asdict(binding), 'sources':{'public':'fixed'}}
                with mock.patch.object(module, '_source_pins', return_value={'public':'fixed'}):
                    executor = module.WindowsJobExecutor(backend, state)
                    with mock.patch.object(module, 'program', side_effect=AssertionError('generated before _run readiness')) as generate, mock.patch.object(module, '_run', side_effect=DispatchBoundary) as dispatch:
                        if module is before:
                            with self.assertRaisesRegex(AssertionError, 'generated before _run readiness'):
                                executor.submit(str(uuid4()), count=3, interval_seconds=.01, deadline=time.monotonic()+10)
                            self.assertEqual(0, dispatch.call_count)
                            self.assertEqual(1, generate.call_count)
                        else:
                            with self.assertRaises(DispatchBoundary):
                                executor.submit(str(uuid4()), count=3, interval_seconds=.01, deadline=time.monotonic()+10)
                            self.assertEqual(0, generate.call_count)
                            self.assertEqual(1, dispatch.call_count)
                            self.assertEqual('job-start', dispatch.call_args.args[1])


if __name__ == '__main__':
    unittest.main()
