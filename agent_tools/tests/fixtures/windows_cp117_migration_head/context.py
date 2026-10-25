"""Exact d24c1904 CP117 dependency bytes for frozen historical replays.

Frozen sources keep every original pin. Each copy is authenticated by its
recorded d24c1904 digest (provenance.json) and by the frozen pin that names it;
only testcase-scoped references change. Copies without a frozen d24c1904 image
live here; the others are the existing immutable ssh_stream_e2big beforeimages.
Current modules keep the ssh_transport migration and their reviewed current
re-pins. No native entry point executes.
"""
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch
from agent_tools.tests.fixtures import historical_source
from agent_tools.tests.fixtures.windows_cp117_historical_factory import context as history

FOLDER = Path(__file__).resolve().parent
BEFORE = FOLDER.parent / 'ssh_stream_e2big'
SOURCES = {
    'owner': (FOLDER / 'windows_cp117_recovered_owner_observe.py.source', '9ff8275a77e71e8b1a7ae90ee4e7dd5a1910ad130720e4621ff85a6fe9b38342'),
    'secure': (FOLDER / 'windows_cp117_secure_layout_observe.py.source', 'bbcb1de84c89b44d7e541a35a2634ba0cf644e89f5cef7d9061e3a33e6499782'),
    'semantic': (FOLDER / 'windows_cp117_secure_input_observe.py.source', '836d2d13dea8604d8d9f3c409db7d15fde349ceb0ecade06ce704a3a2693f590'),
    'guest': (BEFORE / 'windows_cp117_recovered_guest_observe.py.before.source', '254d7495f1a4c02e68b34c6168c6dad93a693445b9569849f61fdf4ca2379b58'),
    'login': (BEFORE / 'windows_cp117_recovered_login.py.before.source', '8cf4087a82f542f9c30ce8453cd3802b7daf0ef63ee06320edeeb97bb005b779'),
    'role': (BEFORE / 'windows_cp117_windowless_gui_login.py.before.source', 'afaa1184bc10f9358d57238e2d6d736de2435c0f7b2553a7aaf7343efe9ae7a8'),
    'refresh': (BEFORE / 'windows_cp117_base_source_refresh.py.before.source', '8708e75d47885830702fe5553661f5dd3a1f4f758000f1e8f9368d75aa79bcfa'),
}
# Public inputs relative to the inert reader's agent_tools root.
NAMES = tuple(path.relative_to(FOLDER.parents[2]).as_posix() for path, _ in SOURCES.values())


def load(name, pin, family=None):
    """One exact copy named by a frozen pin; never the migrated current module."""
    family = history if family is None else family
    path, sha256 = SOURCES[name]
    if pin != sha256:
        raise ValueError('migration_head_pin_changed')
    module = historical_source.load(path, sha256)
    # Non-POSIX held-source custody serves only declared public inputs.
    registry = getattr(family, '_PUBLIC_SOURCE_REGISTRY', None)
    if registry is not None and registry.get() is not None:
        family.register_inert_public_source(path, path.read_bytes())
    return module


def owner(pin, family=None):
    """The exact owner reader named by OWNER_SHA, bound to the guest reader its GUEST_SHA names."""
    value = load('owner', pin, family)
    value.guest = load('guest', value.GUEST_SHA, family)
    return value


@contextmanager
def declared_reads(family=None):
    """Declare the held copies to inert readers entered later in this scope."""
    family = history if family is None else family
    with ExitStack() as stack:
        if hasattr(family, '_PUBLIC_SOURCE_NAMES'):
            stack.enter_context(patch.object(family, '_PUBLIC_SOURCE_NAMES', family._PUBLIC_SOURCE_NAMES + NAMES))
        yield


@contextmanager
def sealed_diagnostic(family=None):
    """Scope frozen diagnostic 615e1b09's owner reference to the bytes its OWNER_SHA binds."""
    family = history if family is None else family
    diagnostic = family.diagnostic()
    with declared_reads(family), patch.object(diagnostic, 'owner', owner(diagnostic.OWNER_SHA, family)):
        yield diagnostic


class HistoricalFactoryTestCase(history.HistoricalFactoryTestCase):
    def setUp(self):
        super().setUp()
        self.enterContext(sealed_diagnostic())


def role(provider):
    """The exact role reader named by the frozen provider's ROLE_SHA."""
    return load('role', provider.ROLE_SHA)


@contextmanager
def sealed_role(provider):
    """Scope a frozen provider's role graph to the bytes its ROLE_SHA and SECURE_SHA bind."""
    value = role(provider)
    secure = load('secure', provider.SECURE_SHA)
    login = load('login', secure.LOGIN_SHA)
    login.guest = load('guest', login.GUEST_SHA)
    secure.login = value.login = login
    value.secure, value.original_semantic = secure, load('semantic', value.ORIGINAL_SEMANTIC_SHA)
    with declared_reads(), patch.object(provider, 'role', value), patch.object(provider, 'windowless', value):
        yield value


@contextmanager
def sealed_context_worker():
    """Scope the sealed public context's helper reference to the bytes its HELPER_SHA binds."""
    from agent_tools.tests.fixtures.windows_cp117_public_context import whole_entry
    with patch.object(whole_entry, 'worker', load('refresh', SOURCES['refresh'][1])):
        yield
