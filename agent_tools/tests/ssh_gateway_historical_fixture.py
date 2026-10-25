"""Exact v1 source contexts for historical gateway proof regressions only."""
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
import hashlib
import json
from pathlib import Path
import sys
import types
from unittest import mock

ROOT=Path(__file__).parent/'fixtures/ssh_gateway_bound_carrier'
_ACTIVE=ContextVar('gateway_historical_test_sources',default=None)


def load(name):
    if name not in ('master.private-config.before.source','diagnostic.carrier-only.before.source'):
        raise ValueError('historical_source_not_catalogued')
    path=ROOT/name;raw=path.read_bytes()
    expected=json.loads((ROOT/'provenance.json').read_bytes())['sources'][str(path.relative_to(Path(__file__).parents[2]))]['sha256']
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('historical_source_changed')
    module=types.ModuleType('agent_tools._historical_'+name.replace('.','_'))
    module.__package__='agent_tools';module.__file__=str(path)
    with mock.patch.dict(sys.modules,{module.__name__:module}):exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


@contextmanager
def archived():
    existing=_ACTIVE.get()
    if existing is not None:
        yield existing;return
    import agent_tools
    adapter=load('master.private-config.before.source')
    diagnostic=load('diagnostic.carrier-only.before.source')
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(agent_tools,'ssh_gateway_tmux_master_ssh',adapter))
        for name in ('agent_tools.tests.test_ssh_gateway_tmux_master_ssh',
                     'agent_tools.tests.test_ssh_gateway_tmux_d606_diagnostic',
                     'agent_tools.tests.test_ssh_gateway_tmux_ready_reconciliation',
                     'agent_tools.tests.test_ssh_gateway_tmux_reconciliation_status',
                     'agent_tools.ssh_gateway_tmux_ready_reconciliation',
                     'agent_tools.ssh_gateway_tmux_reconciliation_status'):
            module=sys.modules.get(name)
            if module is not None:
                if hasattr(module,'adapter'):stack.enter_context(mock.patch.object(module,'adapter',adapter))
                if hasattr(module,'diagnostic'):stack.enter_context(mock.patch.object(module,'diagnostic',diagnostic))
        token=_ACTIVE.set((adapter,diagnostic))
        try:yield adapter,diagnostic
        finally:_ACTIVE.reset(token)
