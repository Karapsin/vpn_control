"""Whole current-owner review beforeimage through the actual observer gateway."""
import hashlib,json,os
from pathlib import Path
import sys,unittest
from types import ModuleType
from unittest import mock
from agent_tools import readiness_windows_seed_detach as current
from agent_tools.tests import test_windows_seed_reader_scope as scope
FIXTURE=Path(__file__).parent/'fixtures/windows_seed_executing_code'

def subject():
    if os.environ.get('VPN_CONTROL_SEED_CODE_BEFORE')!='1':return current
    raw=(FIXTURE/'before.source').read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    value=ModuleType('agent_tools._seed_executing_before');value.__package__='agent_tools';value.__file__=str(FIXTURE/'before.source')
    sys.modules[value.__name__]=value;exec(compile(raw,value.__file__,'exec'),value.__dict__);return value

@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'actual ordinary private original HOST custody required')
class ExecutingCodeTests(unittest.TestCase):
    def test_nonfunction_replacement_is_rejected_before_actual_privileged_channel(self):
        with mock.patch.object(scope,'subject',return_value=subject()):
            scope.SeedReaderScopeTests._blocked_before_channel(self,'executingcode')

if __name__=='__main__':unittest.main()
