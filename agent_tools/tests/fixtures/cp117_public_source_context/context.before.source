"""Exact sealed provider source for inert historical factory regressions.

Only testcase lifetime references change. Production source and digest guards
remain unchanged. This fixture makes no current/native admission claim.
"""
from contextlib import ExitStack, contextmanager
from functools import wraps
import hashlib
import os
import posixpath
from pathlib import Path
import unittest
from unittest.mock import patch
from agent_tools.tests.fixtures import historical_source
from agent_tools.tests.fixtures.cp117_gzip_runtime import historical_gzip_context

SOURCE = Path(__file__).with_name('provider_f54029cf.source')
SHA256 = 'f54029cf3259011d71df93c51f15b3c2b7a886470008427cf85c8e127c567a72'

DIAGNOSTIC_SOURCE = SOURCE.with_name('diagnostic_615e1b09.source')
DIAGNOSTIC_SHA256 = '615e1b0975ea8a2875af91717aa9291110decb6f530c372d51b3c8f5cc793aa8'
_DIAGNOSTIC = historical_source.load(DIAGNOSTIC_SOURCE, DIAGNOSTIC_SHA256)

INSTALLED_SOURCE = SOURCE.with_name('installed_fa5f054e.source')
INSTALLED_SHA256 = 'fa5f054ecb6166ab09a29faaccbe3ce960cb864af764762b71e518a2716b531d'
_INSTALLED = historical_source.load(INSTALLED_SOURCE, INSTALLED_SHA256)

PUBLIC_SOURCE = SOURCE.with_name('public_msi_5e60d94f.source')
PUBLIC_SHA256 = '5e60d94fe2b020957694b21611b9bb5b4789c20830597589b42d32e8dafeeb78'
_PUBLIC = historical_source.load(PUBLIC_SOURCE, PUBLIC_SHA256)

BASE_SOURCE = SOURCE.with_name('base_5d06ef74.source')
BASE_SHA256 = '5d06ef745bbaba0208f08907a9b1c8ed7a3c8c549a940ecf5a4f127744d47cb7'
BASE_BYTES = 200141


@contextmanager
def historical_base(source=BASE_SOURCE):
    """Hold the exact complete base source under its actual fixture filename."""
    from agent_tools import source_module_loader
    path = Path(source).absolute()
    with source_module_loader._bootstrap_source(path) as (raw, guard):
        try:
            if len(raw) != BASE_BYTES or hashlib.sha256(raw).hexdigest() != BASE_SHA256:
                raise ValueError('historical_base_source_changed')
            guard()
            module = historical_source.load(path, BASE_SHA256)
            guard()
            yield module
        finally:
            guard()


def historical_update_fixture_source():
 """Exact 57e server bytes carried by the sealed CP117 factory; never executed."""
 import hashlib
 path=Path(__file__).with_name('update_fixture_a6445062.source')
 raw=path.read_bytes()
 if len(raw)!=100648 or hashlib.sha256(raw).hexdigest()!='a6445062d5885ca013eae3017b39791b844373fb472d87d8d8c22f67576a3980':
  raise ValueError('historical_update_fixture_binding_changed')
 return raw

def installed():
    return historical_source.verify(_INSTALLED, INSTALLED_SOURCE, INSTALLED_SHA256)

def public():
    return historical_source.verify(_PUBLIC, PUBLIC_SOURCE, PUBLIC_SHA256)

def diagnostic():
    return historical_source.verify(_DIAGNOSTIC, DIAGNOSTIC_SOURCE, DIAGNOSTIC_SHA256)

def provider():
    return historical_source.load(SOURCE, SHA256)


@contextmanager
def historical_current_package():
    """Keep the explicit current producer with its historical public input."""
    from agent_tools import windows_cp117_installed_base_observe as current_installed
    historical_public = public()
    if current_installed.PUBLIC_SHA != PUBLIC_SHA256 or current_installed.BASE_SHA != BASE_SHA256:
        raise ValueError('historical_package_public_pin')
    with ExitStack() as stack:
        archived_base = stack.enter_context(historical_base())
        closure = current_installed.precise.owner.guest.recovery.authority.closure
        stack.enter_context(patch.object(closure, 'base', archived_base))
        stack.enter_context(patch.object(archived_base, 'windows_msi_public_scenario', historical_public))
        stack.enter_context(patch.object(current_installed, 'public', historical_public))
        yield current_installed


@contextmanager
def historical_factories():
    from agent_tools import windows_cp117_recovered_owner_diagnostic as current_diagnostic
    from agent_tools import windows_cp117_installed_base_observe as current_installed
    from agent_tools import windows_cp117_base_source_refresh as refresh
    old = provider()
    precise = diagnostic()
    historical_installed = installed()
    historical_public = public()
    with ExitStack() as stack:
        archived_base = stack.enter_context(historical_base())
        # The exact historical diagnostic owns this scoped dependency view.
        # The current base module and its source are never modified.
        closure = precise.owner.guest.recovery.authority.closure
        stack.enter_context(patch.object(closure, 'base', archived_base))
        stack.enter_context(patch.object(archived_base, 'windows_msi_public_scenario', historical_public))
        for module in (current_diagnostic, precise, current_installed, historical_installed, refresh):
            stack.enter_context(patch.object(module, 'flow', old))
        stack.enter_context(patch.object(historical_installed, 'precise', precise))
        stack.enter_context(patch.object(historical_installed, 'public', historical_public))
        stack.enter_context(patch.object(refresh, 'installed', historical_installed))
        # Install the dependency view on this actual sealed provider graph,
        # after its source-verified module objects and references exist.
        stack.enter_context(historical_gzip_context(old))
        yield old


class HistoricalFactoryTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.historical_provider = stack.enter_context(historical_factories())


@contextmanager
def inert_repository_source_reads():
    """Resolve two sealed-factory source labels on this checkout, only in tests.

    Historical programmes contain an author's absolute workspace labels. Those
    are inert fixture data, not current paths or native admission. All other
    source/private-record reads retain the production nofollow/generation guard.
    """
    from agent_tools import windows_cp117_bound_absence_completion as binding
    historical=Path('/Users/karapsin_de/Nextcloud/projects/vpn_control/agent_tools')
    names=('windows_fixture_credentials.py','windows_update_fixture_server.py')
    actual={historical/name:Path(__file__).resolve().parents[3]/name for name in names}
    original=binding._read_bound_file
    def read(path,private=False,retain_bytes=False):
        supplied=Path(path)
        # This is an explicit fixed-source IO seam for inert emission tests.
        # Private inputs, intents, arbitrary source names and native code never map.
        if not private and supplied in actual:
            supplied=actual[supplied]
            if os.name=='nt':
                # These two public source labels are data for sealed emission,
                # not imports of their POSIX coordinator implementations.
                from agent_tools import source_module_loader
                with source_module_loader._bootstrap_source(supplied) as (raw,guard):
                    if not 0<len(raw)<=1048576:raise ValueError('source-record')
                    before=supplied.stat()
                    generation=lambda value:[value.st_dev,value.st_ino,value.st_mode,value.st_uid,
                        value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns]
                    pin={'sha256':hashlib.sha256(raw).hexdigest(),'generation':generation(before)}
                    guard()
                    if generation(supplied.stat())!=pin['generation']:raise ValueError('source-generation')
                    return (pin,raw) if retain_bytes else pin
        return original(supplied,private=private,retain_bytes=retain_bytes)
    with patch.object(binding,'_read_bound_file',side_effect=read):
        yield


@contextmanager
def remote_posix_recipe_context(recovery):
    """Interpret only an inert remote recipe's paths using its POSIX grammar.

    The actual recovery functions, socket length checks and source bytes stay
    intact. Local IO, flags and platform capabilities delegate to the real OS;
    no stdlib/global platform value changes and this grants no native custody.
    """
    original=recovery.os
    class RemotePathView:
        path=posixpath
        def __getattr__(self,name):return getattr(original,name)
    with patch.object(recovery,'os',RemotePathView()):
        yield


def remote_posix_recipe_tests(recovery):
    """Scope the explicit recipe-data context to actual inert test methods."""
    def decorate(cls):
        for name,method in tuple(vars(cls).items()):
            if name.startswith('test_') and callable(method):
                @wraps(method)
                def run(self,*args,__method=method,**kwargs):
                    with remote_posix_recipe_context(recovery):
                        return __method(self,*args,**kwargs)
                setattr(cls,name,run)
        return cls
    return decorate
