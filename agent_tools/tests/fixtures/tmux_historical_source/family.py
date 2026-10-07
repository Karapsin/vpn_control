"""Exact historical source modules for inert tests, never production authority.

Module bodies are compiled unchanged. Only declared dependency imports and the
existing test factory's source-copy ROOT are bound to this authenticated family.
"""
import builtins
import hashlib
from pathlib import Path
import tempfile
import types

PINS = {
    'linux_package_fixture_build': '2aeaef328f9ccb9b7a1d929603929c9ee1fbb827c027ca09d3953dc0cb00a8c8',
    'ssh_tmux_session': '468adbbb45d7b68de50c6df601cf9c25421ef0e09ca3b1c13dddb1dffc580fb3',
    'ssh_tmux_session_ssh': 'bec936bd1a34679939a817777443255fbb7c6d5fc2adafc3193e25ce9ed07c44',
    'ssh_tmux_source_staging_recovery': '841cd9f40b045df5471184fca0997ce0d51151741db0f12d0b66d10f6fc36749',
}
FACTORY_SHA = '12aae299a9d7b479cf07d1c9b80fbab7df52a3f277d14ff1d5483e4738cfad7f'
BASE = Path(__file__).resolve().parent


def source(name):
    path=BASE/(name+'.py.source');raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PINS[name]:
        raise AssertionError('historical_source_changed')
    return path,raw


def load_family():
    modules={}
    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if (level==1 and name=='') or (level==0 and name=='agent_tools'):
            if fromlist and all(item in modules for item in fromlist):
                return types.SimpleNamespace(**{item:modules[item] for item in fromlist})
        return builtins.__import__(name,globals,locals,fromlist,level)
    def compile_module(name,path,raw):
        module=types.ModuleType('agent_tools._historical_'+name)
        module.__package__='agent_tools';module.__file__=str(path)
        module.__dict__['__builtins__']=dict(vars(builtins),__import__=imports)
        exec(compile(raw,str(path),'exec'),module.__dict__)
        return module
    for name in PINS:
        path,raw=source(name);modules[name]=compile_module(name,path,raw)
    factory_path=BASE.parents[1]/'test_ssh_tmux_session_ssh.py'
    raw=factory_path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=FACTORY_SHA:
        raise AssertionError('historical_factory_source_changed')
    factory=compile_module('factory',factory_path,raw)
    temporary=tempfile.TemporaryDirectory(prefix='tmux-historical-tools-',dir='/tmp')
    root=Path(temporary.name);tools=root/'agent_tools';tools.mkdir()
    for name in PINS:
        (tools/(name+'.py')).write_bytes(source(name)[1])
    # The complete unchanged DriverTests/Remote factory now copies old bytes,
    # imports old modules, and retains all actual coordinator/driver guards.
    factory.ROOT=root
    return modules,factory,temporary
