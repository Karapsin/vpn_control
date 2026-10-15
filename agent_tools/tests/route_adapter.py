"""Explicit routing-unit seam; production imports stay source-backed and fresh."""
from unittest import mock
import sys
from agent_tools import vm_workflow


def bind_routes(test, server, *modules):
    """Route only named fake dependencies through the public adapter boundary.

    Patching a process-global imported module intentionally cannot change a fresh
    production request. Routing tests opt in here; physical source-custody and
    SDK tests exercise the real loader separately.
    """
    original = server._agent_module
    named = {'vm_workflow': vm_workflow,
             **{module.__name__.rsplit('.', 1)[-1]: module for module in modules}}
    patch = mock.patch.object(server, '_agent_module',
                              side_effect=lambda name: named[name] if name in named else original(name))
    patch.start()
    test.addCleanup(patch.stop)


def bind_cached_routes(test, server, *module_names):
    """Explicit finite route dependencies, including imports inside test methods.

    This is a unit-test dependency seam. Unnamed adapters still use the genuine
    production loader; this helper never changes production import behavior.
    """
    original=server._agent_module
    allowed=frozenset(module_names)
    def route(name):
        if name in allowed:
            module=sys.modules.get('agent_tools.'+name)
            if module is not None:return module
        return original(name)
    patch=mock.patch.object(server,'_agent_module',side_effect=route)
    patch.start();test.addCleanup(patch.stop)
    return original
