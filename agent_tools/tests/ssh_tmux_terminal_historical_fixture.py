"""Authenticated complete historical pin family, for local inert tests only.

Every module body is compiled unchanged. Finite original dependency imports use
this same family; no production pins, readers, namespaces or helper histories are
rewritten, and current production source drift remains an explicit blocker.
"""
from contextlib import contextmanager
import builtins
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types

BASE=Path(__file__).parent/'fixtures/tmux_terminal_historical_family'
NAMES=('private_inventory_lock','linux_package_fixture_build','ssh_tmux_session',
       'ssh_tmux_session_ssh','ssh_tmux_source_staging_recovery','ssh_tmux_bounded_pipe_collection',
       'ssh_tmux_mcp_adapter','ssh_tmux_terminal_closure','ssh_tmux_resource_admission',
       'ssh_tmux_closure_census_diagnostic','ssh_tmux_privileged_terminal_closure',
       'ssh_tmux_privileged_terminal_claim_bridge')
PROVENANCE_SHA='c8d4f9be37006754d5c097dbebe7cd513dd9845711cef997392f9015b8c72353'


@contextmanager
def archived_family():
    raw=(BASE/'provenance.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PROVENANCE_SHA:raise ValueError('historical_provenance_changed')
    records=json.loads(raw)['modules']
    if set(records)!=set(NAMES):raise ValueError('historical_catalog_changed')
    modules={};registered=[]
    def imports(name,globals=None,locals=None,fromlist=(),level=0):
        if (level==1 and name=='')or(level==0 and name=='agent_tools'):
            if fromlist and all(item in modules for item in fromlist):
                return types.SimpleNamespace(**{item:modules[item]for item in fromlist})
        if level==1 and name in modules:return modules[name]
        if level==0 and name.startswith('agent_tools.')and name[12:]in modules:return modules[name[12:]]
        return builtins.__import__(name,globals,locals,fromlist,level)
    with tempfile.TemporaryDirectory(prefix='tmux-historical-chain-',dir=Path('/tmp').resolve())as tmp:
        root=Path(tmp);tools=root/'agent_tools';tools.mkdir()
        try:
            for name in NAMES:
                body=(BASE/(name+'.py.source')).read_bytes()
                if hashlib.sha256(body).hexdigest()!=records[name]['sha256']:raise ValueError('historical_source_changed')
                (tools/(name+'.py')).write_bytes(body)
            for name in NAMES:
                path=tools/(name+'.py');body=path.read_bytes()
                module=types.ModuleType('agent_tools._terminal_archive_'+name)
                module.__package__='agent_tools';module.__file__=str(path)
                module.__dict__['__builtins__']=dict(vars(builtins),__import__=imports)
                sys.modules[module.__name__]=module;registered.append(module.__name__)
                exec(compile(body,str(path),'exec',dont_inherit=True),module.__dict__)
                modules[name]=module
            yield root,modules
        finally:
            for name in reversed(registered):sys.modules.pop(name,None)
