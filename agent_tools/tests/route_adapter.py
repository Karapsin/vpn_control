"""Explicit routing-unit seam; production imports stay source-backed and fresh."""
from unittest import mock
from contextlib import nullcontext
import sys
from types import SimpleNamespace
from agent_tools import vm_workflow


def _routing_readiness():
    # Routing units replace native effects with fakes. Their preliminary
    # admission must be equally inert: real readiness/transport is covered by
    # the complete controlled-socket callers, never by reaching a user's host
    # while the eventual native adapter is mocked.
    return SimpleNamespace(admitted_dispatch=lambda *args, **kwargs: nullcontext())


def bind_routes(test, server, *modules):
    """Route only named fake dependencies through the public adapter boundary.

    Patching a process-global imported module intentionally cannot change a fresh
    production request. Routing tests opt in here; physical source-custody and
    SDK tests exercise the real loader separately.
    """
    original = server._agent_module
    named = {'vm_workflow': vm_workflow, 'readiness_vm_dispatch': _routing_readiness(),
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
    readiness = _routing_readiness()
    def route(name):
        if name == 'readiness_vm_dispatch' and name not in allowed:
            return readiness
        if name in allowed:
            module=sys.modules.get('agent_tools.'+name)
            if module is not None:return module
        return original(name)
    patch=mock.patch.object(server,'_agent_module',side_effect=route)
    patch.start();test.addCleanup(patch.stop)
    return original


# Admission infrastructure every effectful VM route loads before its adapter.
ADMISSION_MODULES = frozenset({'tool_action_policy', 'readiness_vm_dispatch', 'readiness'})


def admitted_adapter(adapter):
    """`_agent_module` side effect: inert admission, then the route's fake adapter."""
    import importlib
    readiness = _routing_readiness()
    def module(name):
        if name == 'readiness_vm_dispatch':
            return readiness
        if name in ADMISSION_MODULES:
            return importlib.import_module('agent_tools.' + name)
        return adapter
    return module


def adapter_calls(module):
    """Calls for route adapters, excluding the shared admission infrastructure."""
    return [call for call in module.call_args_list if call.args[0] not in ADMISSION_MODULES]


def admitted_failure(error):
    """`_agent_module` side effect: inert admission, then the route adapter fails to load."""
    admitted = admitted_adapter(None)
    def module(name):
        if name in ADMISSION_MODULES:
            return admitted(name)
        raise error
    return module
