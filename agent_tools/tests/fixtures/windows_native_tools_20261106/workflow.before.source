"""Normal tool facade for readiness of explicitly configured/registered targets.

No public request supplies an ownership assertion, arbitrary observer, recovery
program, credential, VM path or journal path. Registration follows direct proof.
"""
from dataclasses import asdict
import hashlib
import time
from uuid import UUID

from . import readiness
from . import readiness_recovery_status as recovery_status
from . import readiness_fixture_registry as fixtures
from . import readiness_providers as providers
from . import readiness_transport as ssh
from . import tool_action_policy as policies


def _operation(identity):
    if type(identity) is not dict or set(identity) != {"operationId"}:
        raise ValueError("readiness_identity_invalid")
    operation = identity["operationId"]
    if type(operation) is not str or str(UUID(operation)) != operation:
        raise ValueError("readiness_identity_invalid")
    return operation


def _observation(value):
    result = asdict(value)
    for key in ("idle_visibility", "idle_blockers"):
        result[key] = sorted(result[key])
    return result


def ensure_ssh(root, host, operation, *, deadline=None):
    """New operation admission; all commands use the admitted master getter."""
    context = ssh.context(root, host, deadline=deadline)
    requirements = readiness.Requirements(frozenset({"transport"}), frozenset({"reconnect"}))
    ready = readiness.ensure_ready(context, requirements, operation)
    readiness.revalidate(context, ready)
    return context, ready


def ssh_workflow(root, action, host, identity):
    operation = _operation(identity)
    policy = policies.action_policy("ssh_workflow", action)
    adapter = ssh.TransportAdapter(root, host)
    if action == "readiness-status":
        observed = adapter.observe(readiness.Requirements(frozenset({"transport"})), time.monotonic() + 30)
        return {"host": host, "ok": observed.transport == "ready", "state": observed.transport,
                "operationId": operation, "observation": _observation(observed),
                "recoveryStatus": recovery_status.inspect(adapter.root / ".rag_index" / "readiness" / hashlib.sha256(host.encode()).hexdigest(),
                                                          target=host, machine=adapter.machine),
                "replayAllowed": False, "nextAction": "ensure_ready" if observed.transport != "ready" else "complete"}
    if action != "readiness-ensure":
        raise ValueError("readiness_action_invalid")
    requirements = readiness.Requirements(policy.requirements, policy.permitted_recoveries)
    context = ssh.context(root, host)
    ready = readiness.ensure_ready(context, requirements, operation)
    policies._guard_loaded_catalog()
    readiness.revalidate(context, ready)
    return {"host": host, "ok": True, "state": "ready", "operationId": operation,
            "identities": list(ready.identities()), "replayAllowed": False, "nextAction": "complete"}


def vm_workflow(root, action, inputs):
    policy = policies.action_policy("vm_workflow", action)
    if action == "readiness-providers":
        if type(inputs) is not dict or inputs:
            raise ValueError("readiness_inputs_invalid")
        lanes = [providers.ProviderAdapter(lane, "unconfigured", "unconfigured").inspect()
                 for lane in sorted(providers.PROVIDERS)]
        return {"ok": True, "state": "observed", "providers": lanes,
                "replayAllowed": False, "nextAction": "complete"}
    if type(inputs) is not dict or set(inputs) != {"fixtureId", "operationId"}:
        raise ValueError("readiness_inputs_invalid")
    operation = _operation({"operationId": inputs["operationId"]})
    fixture = fixtures.registered_fixture(root, inputs["fixtureId"])
    # The private factory binds the actual fixture's capabilities. Headless
    # guests require an agent, while desktop fixtures require a user session.
    required = (frozenset({"guest_agent"}) if action == "readiness-reboot" else
                getattr(fixture, "required_readiness", frozenset({"interactive_desktop"})))
    requirements = readiness.Requirements(required, policy.permitted_recoveries)
    if action == "readiness-status":
        observed = fixture.adapter.observe(requirements, time.monotonic() + 30)
        try:
            ready = readiness._next(observed, requirements, operation) is None
            blocker = {}
        except readiness.ReadinessBlocked as error:
            ready = False
            blocker = {"readinessBlocker": error.reason}
        return {"fixtureId": inputs["fixtureId"], "ok": True, "state": "ready" if ready else "not_ready", "operationId": operation, **blocker,
                "recoveryStatus": recovery_status.inspect(getattr(fixture,"journal_directory",None),target=observed.target,machine=observed.machine),
                "observation": _observation(observed), "replayAllowed": False, "nextAction": "complete" if ready else "ensure_ready"}
    if action not in {"readiness-ensure", "readiness-reboot"}:
        raise ValueError("readiness_action_invalid")
    context = fixture.context()
    ready = (readiness.idle_reboot(context, operation) if action == "readiness-reboot" else
             readiness.ensure_ready(context, requirements, operation))
    policies._guard_loaded_catalog()
    readiness.revalidate(context, ready)
    return {"fixtureId": inputs["fixtureId"], "ok": True, "state": "ready", "operationId": operation, "identities": list(ready.identities()),
            "capabilities": sorted(fixture.adapter.capabilities), "replayAllowed": False, "nextAction": "complete"}
