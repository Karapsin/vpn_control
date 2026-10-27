"""Causal complete-file publication through the actual inert manager/test body."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import types
import unittest
from unittest import mock
import uuid

BEFORE = Path(__file__).parent / 'fixtures/ssh_gateway_fixture_release_gate/test_ssh_gateway_fixture_release_gate.py.before.source'
BEFORE_SHA = 'fcc34697548b0d9901ceb9f6252154e2b9c9aca3f29b97b64f512391aa15e5ff'
METHOD = 'test_authentic_whole_before_short_gate_red_current_same_delayed_release_green'
DUMP = "with os.fdopen(_fd,'w')as _out:json.dump({'exitCode':child.returncode,'pid':child.pid},_out)"


@unittest.skipUnless(os.name == 'posix', 'real owned inert processes/Unix sockets')
class TerminalPublicationTests(unittest.TestCase):
    def test_whole_before_exposes_empty_json_atomic_current_publishes_complete_json(self):
        from agent_tools.tests import test_ssh_gateway_fixture_release_gate as fixture
        current = Path(fixture.__file__)
        self.records = []
        for label, path in (('before', BEFORE), ('current', current)):
            with self.subTest(label=label):
                self.check_publication(label, path, fixture)

    def check_publication(self, label, path, fixture):
        raw = path.read_bytes()
        if label == 'before':
            self.assertEqual(BEFORE_SHA, hashlib.sha256(raw).hexdigest())
        module = types.ModuleType('_terminal_publication_' + uuid.uuid4().hex)
        module.__file__ = fixture.__file__
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        original_write, original_exists, original_read = Path.write_text, Path.exists, Path.read_bytes
        observed, homes = [], set()
        terminal = entered = resume = manager = None
        injected = released = False

        def release():
            nonlocal released
            if not released:
                fd = os.open(resume, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
                released = True

        def exists(path):
            nonlocal manager
            if path != terminal:
                return original_exists(path)
            present = original_exists(path)
            if released:
                return present
            if present or original_exists(entered):
                deadline = time.monotonic() + 5
                while not original_exists(entered):
                    if time.monotonic() >= deadline:
                        raise RuntimeError('terminal_writer_gate_unavailable')
                    time.sleep(.005)
                writer = json.loads(original_read(entered))
                manager = fixture.fixture.fixture_observer._identity(writer['managerPid'])
                self.assertIsNotNone(manager)
                self.assertIsNone(fixture.fixture.fixture_observer._identity(writer['panePid']))
                present = original_exists(path)
                observed.append({'event': 'writer_blocked_before_json', 'publicExists': present})
                if not present:
                    release()
            return present

        def read(path):
            data = original_read(path)
            if path == terminal:
                observed.append({'event': 'actual_terminal_read', 'length': len(data)})
                if not released:
                    release()
            return data

        def write(path, data, *args, **kwargs):
            nonlocal injected, terminal, entered, resume
            if path.name == 'tmux':
                homes.add(path.parent)
            # Only the first (short-gate) writer is coordinated. The unchanged
            # second subtest and fixture cleanup retain their original behavior.
            if not injected and path.name == 'tmux' and DUMP in data:
                self.assertEqual(1, data.count(DUMP))
                injected = True
                terminal = path.parent / 'test-pane-terminal.json'
                entered = path.parent / 'publication-writer-entered'
                resume = path.parent / 'publication-reader-finished'
                line = next(line for line in data.splitlines() if DUMP in line)
                indent = line[:len(line) - len(line.lstrip())]
                gate = [
                    '_gate_stage=' + repr(str(entered) + '.stage'),
                    '_gate_fd=os.open(_gate_stage,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)',
                    "with os.fdopen(_gate_fd,'w')as _gate_out:json.dump({'managerPid':os.getpid(),'panePid':child.pid},_gate_out)",
                    'os.link(_gate_stage,' + repr(str(entered)) + ',follow_symlinks=False)',
                    'os.unlink(_gate_stage)',
                    '_gate_deadline=time.monotonic()+5',
                    'while not os.path.exists(' + repr(str(resume)) + '):',
                    " if time.monotonic()>=_gate_deadline:raise RuntimeError('terminal_reader_gate_unavailable')",
                    ' time.sleep(.005)',
                ]
                data = data.replace(line, '\n'.join(indent + text for text in gate) + '\n' + line)
            return original_write(path, data, *args, **kwargs)

        result = unittest.TestResult()
        with mock.patch.object(Path, 'write_text', write), mock.patch.object(Path, 'exists', exists), mock.patch.object(Path, 'read_bytes', read):
            module.FixtureReleaseGateTests(METHOD).run(result)
        record = {
            'variant': label, 'sourceSha256': hashlib.sha256(raw).hexdigest(),
            'testsRun': result.testsRun, 'errors': [trace for _, trace in result.errors],
            'failures': [trace for _, trace in result.failures], 'observations': observed,
            'fixtureHomesRemoved': all(not original_exists(home) for home in homes),
            'managerIdentity': manager,
        }
        self.records.append(record)
        self.assertTrue(injected and released, record)
        self.assertTrue(record['fixtureHomesRemoved'], record)
        self.assertIsNotNone(manager, record)
        current = fixture.fixture.fixture_observer._identity(manager['pid'])
        self.assertTrue(current is None or current['birth'] != manager['birth'], record)
        self.assertEqual(1, result.testsRun, record)
        self.assertFalse(result.failures, record)
        if label == 'before':
            self.assertEqual(1, len(result.errors), record)
            self.assertIn('json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)', result.errors[0][1])
            self.assertIn({'event': 'writer_blocked_before_json', 'publicExists': True}, observed)
            self.assertIn({'event': 'actual_terminal_read', 'length': 0}, observed)
        else:
            self.assertFalse(result.errors, record)
            self.assertIn({'event': 'writer_blocked_before_json', 'publicExists': False}, observed)
            self.assertTrue(any(item['event'] == 'actual_terminal_read' and item['length'] > 0 for item in observed), record)


if __name__ == '__main__':
    unittest.main()
