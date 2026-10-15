"""Real private journal/file closing controls; remote channel replies are inert."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import ssh_fresh_nested_channel as channel
from agent_tools import ssh_source_file_stage as stage
from agent_tools.tests import test_ssh_fresh_nested_channel as channel_fixtures

FIXTURE = Path(__file__).parent / 'fixtures/source_terminal_closing'


def implementation(name, current, before):
    if not before:
        return current
    provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
    entry = next(row for row in provenance['sources'] if row['path'] == 'agent_tools/' + name)
    path = FIXTURE / entry['fixture']
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != entry['sourceSha256']:
        raise ValueError('causal_source_changed')
    selected = types.ModuleType('agent_tools._terminal_closing_before_' + name[:-3])
    selected.__package__ = 'agent_tools'
    selected.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), selected.__dict__)
    return selected


@unittest.skipUnless(os.name == 'posix', 'POSIX descriptor and private journal custody')
class SourceTerminalClosingTests(unittest.TestCase):
    source_before = False

    def channel_subject(self):
        return implementation('ssh_fresh_nested_channel.py', channel, self.source_before)

    def crossed_journal(self):
        fixture = channel_fixtures.FreshChannelTests('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        subject = self.channel_subject()
        patch = mock.patch.object(channel_fixtures, 'channel', subject)
        patch.start()
        self.addCleanup(patch.stop)
        self.assertEqual('unknown', fixture.invoke()['state'])
        fixture.stdout = json.dumps({'state': 'ended', 'correlationId': fixture.corr,
                                     'prior': None, 'gatewayBoot': subject.EXPECTED_BOOT}).encode()
        fixture.rc = 0
        self.assertEqual('ended', fixture.invoke(False)['state'])
        journal = (subject._context_journal(fixture.root, 'archlinux', fixture.corr, False)
                   if hasattr(subject, '_context_journal') else subject._journal(fixture.root, False))
        crossed = 'd' * 32
        # Preserve the original byte bodies; only their outer intent filename is
        # crossed. Its original terminal has no READY receipt or pin to rewrite.
        (journal / (fixture.corr + '.intent.json')).rename(journal / (crossed + '.intent.json'))
        original = json.loads((journal / (fixture.corr + '.terminal.json')).read_bytes())
        original['correlationId'] = crossed
        alias_terminal = journal / (crossed + '.terminal.json')
        alias_terminal.write_text(json.dumps(original))
        alias_terminal.chmod(0o600)
        return fixture, journal, crossed

    def test_crossed_intent_filename_cannot_publish_another_original_as_ended(self):
        fixture, journal, crossed = self.crossed_journal()
        before = {path.name: path.read_bytes() for path in journal.iterdir()}
        count = len(fixture.calls)
        value = fixture.invoke(False, corr=crossed)
        self.assertEqual('unknown', value['state'])
        self.assertEqual(count, len(fixture.calls))
        self.assertEqual(before, {path.name: path.read_bytes() for path in journal.iterdir()})

    def test_crossed_prior_cannot_admit_a_second_channel(self):
        fixture, journal, crossed = self.crossed_journal()
        before = {path.name: path.read_bytes() for path in journal.iterdir()}
        count = len(fixture.calls)
        fixture.stdout = b'{}'
        fixture.rc = 3
        value = fixture.invoke(corr='c' * 32)
        self.assertEqual('unknown', value['state'])
        self.assertEqual(count, len(fixture.calls), 'crossed prior admitted a second transport')
        self.assertEqual(before, {path.name: path.read_bytes() for path in journal.iterdir()})

    def test_named_source_exchange_during_receipt_publication_refuses_staged(self):
        subject = implementation('ssh_source_file_stage.py', stage, self.source_before)
        for same_bytes in (False, True):
            with self.subTest(same_bytes=same_bytes), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                root.chmod(0o700)
                correlation = 'ab' * 16
                directory = root / ('vpn-control-windows-caller-' + correlation)
                raw = b"print('PUBLIC_SOURCE')\n"
                real_open = os.open
                changed = []

                def exchange(name, flags, *args, **kwargs):
                    if name == 'receipt.json' and not changed:
                        replacement = directory / 'replacement.py'
                        replacement.write_bytes(raw if same_bytes else b"print('PUBLIC_OTHER')\n")
                        replacement.chmod(0o600)
                        replacement.replace(directory / 'caller.py')
                        changed.append(True)
                    return real_open(name, flags, *args, **kwargs)

                with mock.patch.object(os, 'open', side_effect=exchange):
                    with self.assertRaisesRegex(ValueError, 'source_stage_file_changed'):
                        subject.receive_source(correlation, io.BytesIO(subject.source_payload(raw)), str(root))
                self.assertEqual([True], changed)
                # The original correlation stays consumed after a failed close.
                with self.assertRaises(FileExistsError):
                    subject.receive_source(correlation, io.BytesIO(subject.source_payload(raw)), str(root))

    def test_staging_directory_mode_drift_during_receipt_publication_refuses(self):
        subject = implementation('ssh_source_file_stage.py', stage, self.source_before)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            correlation = 'ac' * 16
            directory = root / ('vpn-control-windows-caller-' + correlation)
            real_open = os.open

            def drift(name, flags, *args, **kwargs):
                if name == 'receipt.json':directory.chmod(0o777)
                return real_open(name, flags, *args, **kwargs)

            with mock.patch.object(os, 'open', side_effect=drift):
                with self.assertRaisesRegex(ValueError, 'source_stage_directory_changed'):
                    subject.receive_source(correlation, io.BytesIO(subject.source_payload(b"print('PUBLIC')\n")), str(root))

    def test_named_temporary_root_exchange_during_receipt_publication_refuses(self):
        subject = implementation('ssh_source_file_stage.py', stage, self.source_before)
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            root = parent / 'current-root'
            root.mkdir(mode=0o700)
            correlation = 'ad' * 16
            real_open = os.open

            def drift(name, flags, *args, **kwargs):
                if name == 'receipt.json':
                    root.rename(parent / 'original-root')
                    root.mkdir(mode=0o700)
                return real_open(name, flags, *args, **kwargs)

            with mock.patch.object(os, 'open', side_effect=drift):
                with self.assertRaisesRegex(ValueError, 'source_stage_directory_changed'):
                    subject.receive_source(correlation, io.BytesIO(subject.source_payload(b"print('PUBLIC')\n")), str(root))
            self.assertEqual([], list(root.iterdir()))


if __name__ == '__main__':
    unittest.main()
