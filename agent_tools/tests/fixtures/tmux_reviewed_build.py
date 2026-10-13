"""Current tool fixtures and an unchanged historical tmux build model.

Historical874 bytes come unchanged from Git60e925b21274d5502517562c8d9375b24881464f
at agent_tools/linux_package_fixture_build.py. Their loader preserves the original
foreground tar/disconnect model. Current tool consumers capture the actual
current helper/session bytes through the unchanged production allowlist.
"""
import hashlib
from pathlib import Path
import tempfile
import types

BUILD_SHA256 = '874b7be8d70e917553d466ed2b8ad71419dec5f21bfd3092060f16180c284cf5'
BASE = Path(__file__).resolve().parent / 'tmux_reviewed_build'


def reviewed_build_bytes():
    raw = (BASE / 'linux_package_fixture_build.py.source').read_bytes()
    if hashlib.sha256(raw).hexdigest() != BUILD_SHA256:
        raise AssertionError('reviewed_test_build_source_changed')
    return raw


def load_reviewed_build():
    module = types.ModuleType('agent_tools._tmux_reviewed_build_fixture')
    module.__package__ = 'agent_tools'
    module.__file__ = str(BASE / 'linux_package_fixture_build.py.source')
    exec(compile(reviewed_build_bytes(), module.__file__, 'exec'), module.__dict__)
    return module


def current_build_bytes():
    from agent_tools import linux_package_fixture_build as build
    return Path(build.__file__).read_bytes()


def reviewed_tool_sources():
    from agent_tools import ssh_tmux_session as session
    from agent_tools import ssh_tmux_session_ssh as adapter
    with tempfile.TemporaryDirectory(prefix='tmux-current-tools-', dir='/tmp') as tmp:
        root = Path(tmp); root.chmod(0o700)
        tools = root / 'agent_tools'; tools.mkdir()
        (tools / 'linux_package_fixture_build.py').write_bytes(current_build_bytes())
        (tools / 'ssh_tmux_session.py').write_bytes(Path(session.__file__).read_bytes())
        # Exercise the real production allowlist; no hash or _tools bypass.
        return adapter.TmuxArchDriver(root)._tools()
