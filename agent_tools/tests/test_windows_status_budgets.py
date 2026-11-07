"""Budgets of one registered Windows observation, from what the real fixture took.

On clone 246a3304 (2026-11-06) one registered observation with idle facts took
47.8 s, because it adds a reservation census to the guest packet, so the 30 s public
status could never finish: that part is a real route-level failure. No packet ever hit
its transport bound, so PacketBoundTests is a constant guard, not a reproduced failure:
the slowest retained packet took 72.8 s on the loaded Mac, and the bound must outlast
that plus the packet's own guest wait so a host refusal stays typed.
"""
import ast,hashlib,json,re,sys,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import readiness,readiness_windows as windows,readiness_windows_remote as remote,readiness_workflow as workflow

FIXTURE=Path(__file__).parent/'fixtures/windows_native_tools_20261106'
NATIVE_IDLE_OBSERVATION=47.8
NATIVE_SLOWEST_PACKET=72.8


def before_bytes(filename):
    raw=(FIXTURE/filename).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sha256'][filename]:raise AssertionError(filename+' beforeimage changed')
    return raw


def before_module(name,filename):
    module=types.ModuleType('agent_tools._status_budget_before_'+name+uuid.uuid4().hex);module.__package__='agent_tools';module.__file__=str(FIXTURE/filename)
    sys.modules[module.__name__]=module;exec(compile(before_bytes(filename),module.__file__,'exec'),module.__dict__);return module


def status_budget(module):
    """The real route's own deadline, measured at the adapter it reaches."""
    seen=[]
    class Stop(Exception):pass
    def observe(requirements,deadline):
        seen.append(deadline-time.monotonic());raise Stop()
    fixture=types.SimpleNamespace(adapter=types.SimpleNamespace(observe=observe,capabilities=frozenset()),required_readiness=frozenset({'interactive_desktop'}))
    policy=types.SimpleNamespace(permitted_recoveries=frozenset())
    with mock.patch.object(module.fixtures,'registered_fixture',return_value=fixture),mock.patch.object(module.policies,'action_policy',return_value=policy):
        try:module.vm_workflow(Path('.'),'readiness-status',{'fixtureId':'windows-raw246a3304-v1','operationId':'00000000-0000-4000-8000-000000000001'})
        except Stop:pass
    return seen[0]


def transport_bound(source):
    """The literal bound of the one guest-packet SSH call in the backend's `_run`."""
    calls=[node for node in ast.walk(ast.parse(source)) if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='run_ssh'
           and any(keyword.arg=='stdout' for keyword in node.keywords)]
    bounds=[keyword.value.args[0].value for call in calls for keyword in call.keywords
            if keyword.arg=='timeout' and isinstance(keyword.value,ast.Call) and getattr(keyword.value.func,'id',None)=='min']
    if len(bounds)!=1:raise AssertionError('expected one guest packet transport bound')
    return bounds[0]


def guest_wait(source):
    """How long the packet waits for its guest program, from the one retained loop."""
    found=re.findall(r"deadline=time\.monotonic\(\)\+(\d+)\s+while True:\s+terminal=rpc\('guest-exec-status',ack\['ack'\]\)",source)
    if len(found)!=1:raise AssertionError('expected one guest program wait')
    return int(found[0])


class StatusBudgetTests(unittest.TestCase):
    def test_before_status_cannot_finish_a_native_idle_observation(self):
        self.assertLess(status_budget(before_module('workflow','workflow.before.source')),NATIVE_IDLE_OBSERVATION)
    def test_current_status_outlasts_it_within_the_normal_budget(self):
        budget=status_budget(workflow)
        self.assertGreater(budget,NATIVE_IDLE_OBSERVATION);self.assertLessEqual(budget,readiness.NORMAL_BUDGET)


class PacketBoundTests(unittest.TestCase):
    def test_before_transport_bound_does_not_cover_a_slow_guest_program(self):
        source=before_bytes('windows.before.source').decode()
        self.assertLess(transport_bound(source),guest_wait(before_bytes('remote.before.source').decode())+NATIVE_SLOWEST_PACKET)
    def test_current_transport_bound_covers_it_and_the_status_budget_holds_one_packet(self):
        bound=transport_bound(Path(windows.__file__).read_text(encoding='utf-8'));wait=guest_wait(Path(remote.__file__).read_text(encoding='utf-8'))
        self.assertGreaterEqual(bound,wait+NATIVE_SLOWEST_PACKET);self.assertLess(bound,status_budget(workflow))


if __name__=='__main__':unittest.main()
