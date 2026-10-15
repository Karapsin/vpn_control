"""Fence new work that still names a historical fixture implicitly.

Original status, collection and exact-owner closure routes remain available.
Resuming a product acceptance campaign requires an explicit environment context;
a new correlation alone cannot qualify a previous attempt's guest or account.
"""


def refusal(action):
    if action != "macos-fixture-guest-stage-start":
        return None
    return {
        "tool": "vm_workflow", "ok": False, "state": "blocked",
        "reason": "historical_macos_fixture_stage_retired", "action": action,
        "nativeActionAllowed": False, "replayAllowed": False,
        "productAction": False,
        "nextAction": "macos-fixture-stage-start",
    }
