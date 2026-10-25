"""Exercise the complete retained provider boundary through real readiness admission."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from uuid import uuid4

from agent_tools import readiness as r
from agent_tools import readiness_providers as current

FIXTURE = Path(__file__).parent / 'fixtures/provider_typed_blocker'
SECRET = 'private-input-must-never-be-projected'


def before_module():
    raw = (FIXTURE / 'providers.before.source').read_bytes()
    pin = json.loads((FIXTURE / 'provenance.json').read_bytes())['sourceSha256']['providers.before.source']
    if hashlib.sha256(raw).hexdigest() != pin:
        raise AssertionError('retained provider bytes changed')
    name = 'agent_tools._typed_provider_before'
    module = ModuleType(name)
    module.__file__ = str(FIXTURE / 'providers.before.source')
    module.__package__ = 'agent_tools'
    sys.modules[name] = module
    try:
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    finally:
        del sys.modules[name]
    return module


class ProviderTypedBlockerTests(unittest.TestCase):
    def result(self, module, error):
        class Backend:
            capabilities = frozenset()
            calls = 0
            def observe(self, requirements, deadline):
                self.calls += 1
                raise error
            def recover(self, *args):
                raise AssertionError('blocked observation cannot recover or submit')
        backend = Backend()
        adapter = module.ProviderAdapter('raw-qemu-linux', 'selected-target', 'selected-machine', backend)
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp).chmod(0o700)
            context = r.Context('selected-target', 'selected-machine', adapter, r.RecoveryJournal(Path(tmp)))
            with self.assertRaises(r.ReadinessBlocked) as raised:
                r.ensure_ready(context, r.Requirements(frozenset({'guest_agent'})), str(uuid4()))
            self.assertEqual(backend.calls, 1)
            self.assertFalse(tuple(Path(tmp).glob('*.json')))
            value = raised.exception.as_dict()
            self.assertNotIn(SECRET, json.dumps(value))
            self.assertFalse(value['replayAllowed'])
            return value

    def test_complete_before_RED_specific_blocker_lost_current_GREEN(self):
        before = before_module()
        for reason in sorted(r.AdapterBlocked.REASONS - {'provider_unavailable'}):
            with self.subTest(reason=reason):
                error = r.AdapterBlocked(reason)
                error.args = (SECRET,)
                self.assertEqual(self.result(before, error)['reason'], 'provider_unavailable')
                self.assertEqual(self.result(current, error)['reason'], reason)

    def test_unreviewed_or_corrupt_backend_errors_are_finite_and_private(self):
        class Subclass(r.AdapterBlocked):
            pass
        errors = [RuntimeError(SECRET), Subclass('credential_unavailable')]
        for invalid in (SECRET, ['credential_unavailable'], None):
            error = r.AdapterBlocked('credential_unavailable')
            error.reason = invalid
            error.args = (SECRET,)
            errors.append(error)
        for error in errors:
            with self.subTest(error_type=type(error).__name__):
                self.assertEqual(self.result(current, error)['reason'], 'provider_unavailable')


if __name__ == '__main__':
    unittest.main()
