"""Exact sealed provider source for inert historical factory regressions.

Only testcase lifetime references change. Production source and digest guards
remain unchanged. This fixture makes no current/native admission claim.
"""
from contextlib import ExitStack, contextmanager
from pathlib import Path
import unittest
from unittest.mock import patch
from agent_tools.tests.fixtures import historical_source

SOURCE = Path(__file__).with_name('provider_f54029cf.source')
SHA256 = 'f54029cf3259011d71df93c51f15b3c2b7a886470008427cf85c8e127c567a72'

DIAGNOSTIC_SOURCE = SOURCE.with_name('diagnostic_615e1b09.source')
DIAGNOSTIC_SHA256 = '615e1b0975ea8a2875af91717aa9291110decb6f530c372d51b3c8f5cc793aa8'
_DIAGNOSTIC = historical_source.load(DIAGNOSTIC_SOURCE, DIAGNOSTIC_SHA256)

INSTALLED_SOURCE = SOURCE.with_name('installed_fa5f054e.source')
INSTALLED_SHA256 = 'fa5f054ecb6166ab09a29faaccbe3ce960cb864af764762b71e518a2716b531d'
_INSTALLED = historical_source.load(INSTALLED_SOURCE, INSTALLED_SHA256)

def installed():
    return historical_source.verify(_INSTALLED, INSTALLED_SOURCE, INSTALLED_SHA256)

def diagnostic():
    return historical_source.verify(_DIAGNOSTIC, DIAGNOSTIC_SOURCE, DIAGNOSTIC_SHA256)

def provider():
    return historical_source.load(SOURCE, SHA256)


@contextmanager
def historical_factories():
    from agent_tools import windows_cp117_recovered_owner_diagnostic as current_diagnostic
    from agent_tools import windows_cp117_installed_base_observe as current_installed
    from agent_tools import windows_cp117_base_source_refresh as refresh
    old = provider()
    precise = diagnostic()
    historical_installed = installed()
    with ExitStack() as stack:
        for module in (current_diagnostic, precise, current_installed, historical_installed, refresh):
            stack.enter_context(patch.object(module, 'flow', old))
        stack.enter_context(patch.object(historical_installed, 'precise', precise))
        stack.enter_context(patch.object(refresh, 'installed', historical_installed))
        yield old


class HistoricalFactoryTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.historical_provider = stack.enter_context(historical_factories())
