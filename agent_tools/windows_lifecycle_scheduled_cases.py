"""windows-proxy-lifecycle.scheduled-refresh: one scheduled subscription refresh in the owner, no GUI attached.

A finite case inside the retained ordinary Owner, after windows_lifecycle_runtime_stages.start_runtime started the
loopback fixture, a persistent serve and proxy A. Every product effect is a public CLI call; no GUI is ever started,
and the case proves none is attached or running. No import-time effects.

What the product defines and the oracles read:
- DesktopAutoRefreshScheduler schedules only the subscription source with a policy interval and a remote target, and
  its first run follows the subscription's last refresh by one interval. DesktopHeadlessSession runs each one through
  the owner's own operation ledger as ``subscriptions.refresh`` with a ``scheduled-refresh:`` request ID, so
  ``operations list`` shows it, and ``operations status`` its retained result, like any operation of that controller.
- MIN_SUBSCRIPTION_REFRESH_MINUTES (Models.kt) is five minutes; ``refresh.custom-hours`` takes a JSON number
  (ControlSettingsLogic) normalized to at least that.
- SUBSCRIPTIONS_REFRESH takes no revision guard (DesktopControlSupport.revisionGuardOperations), so it never gets one.
- DesktopSubscriptionDownloadClient fetches with User-Agent ``VPNControlDesktop/1.0``: the fixture's ledger row of that
  GET is the refresh's own network effect.
- DesktopGuiVisibilityControl answers ``gui hide`` NOT_FOUND, exit 1 and final, when the owner holds no frontend.
- DESKTOP-005: the refresh leaves the runtime running. The fixture's subscription never changes, so no generated
  configuration does either and not even a short restart is allowed: the runtime process is the same one throughout.
"""
from __future__ import annotations

import json
import ntpath
from pathlib import Path
import re
import time

SUBSCRIPTION_NAME = "Owned scheduled"
CUSTOM_HOURS = "0.08333333333333333"  # Five minutes, the product's shortest custom interval, as a JSON number.
INTERVAL_SECONDS = 300
# The scheduler's one-second sync loop and the refresh itself, past one interval from the manual refresh.
OBSERVE_SLACK_SECONDS = 120
POLL_SECONDS = 1.0
SCHEDULED_PREFIX = "scheduled-refresh:"
OPERATION = "subscriptions.refresh"
PRODUCT_AGENT = "VPNControlDesktop/1.0"
GUI_LEAF = "vpn-control.exe"
INPUT_FIELDS = frozenset({"schemaVersion", "guiPath", "trafficWorkerPath", "trafficInputPath", "installedAdmissionArtifactId",
                          "fixtureAdmissionArtifactId"})
RUNTIME_KEYS = ("runtimeRunning", "runtimeId", "runtimeStartedAt", "activeLocationId", "activeMode", "selectedLocationId")
MAX_LEDGER = 1024 * 1024


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def runtime_view(status):
    return {key: status["data"].get(key) for key in RUNTIME_KEYS}


def guarded(owner, runtime, workspace, identity, *tail):
    """A revision-guarded write at the revision status reports just before it."""
    status = runtime.result(owner, workspace, identity, "status")
    return runtime.result(owner, workspace, identity, "--if-revision", str(status["configurationRevision"]), *tail)


def envelope(value, identity, code, exit_code):
    """One final envelope of this controller on stdout, nothing on stderr, with exactly this code and exit."""
    require(value.stderr == "", "scheduled-public-cli-stderr")
    body = json.loads(value.stdout)
    return (type(body) is dict and value.returncode == exit_code and body.get("schemaVersion") == 1
            and body.get("controllerId") == identity and body.get("code") == code and body.get("final") is True
            and body.get("ok") is (exit_code == 0)), body


def no_frontend(owner, workspace, identity, label):
    """The owner itself says it holds no frontend: gui hide is NOT_FOUND without a registration."""
    matched, body = envelope(owner.invoke(workspace, "--json", "--controller-id", identity, "gui", "hide"), identity, "NOT_FOUND", 1)
    require(matched, "scheduled-owner-frontend-attached")
    owner.event("scheduled-owner-without-frontend", {"label": label, "code": body["code"], "configurationRevision": body.get("configurationRevision")})


def gui_absent(owner, native, observer, gui_path, label):
    """No live process runs the installed GUI image; a process of that name that already ended is none."""
    seen = []
    for entry in native.processes():
        if entry["name"].casefold() != GUI_LEAF:
            continue
        try:
            with native.open_process(entry["pid"], 0x101000) as process:
                record, state = process.describe(), process.wait()
        except observer.ProcessAbsent:
            seen.append({"pid": entry["pid"], "originalAbsent": True})
            continue
        require(state in (0, 258), "scheduled-gui-census-wait-unknown")
        seen.append({"pid": entry["pid"], "image": record["image"], "creationFileTime": record["creationFileTime"], "waitState": state})
        require(state == 0 or ntpath.normcase(record["image"]) != ntpath.normcase(gui_path), "scheduled-installed-gui-running")
    owner.event("scheduled-gui-census", {"label": label, "candidates": seen, "installedGuiRunning": False})


def product_fetches(path, since):
    """The fixture ledger's complete rows of the product's own subscription GETs from a time on."""
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_LEDGER + 1)
    require(len(raw) <= MAX_LEDGER, "scheduled-fixture-ledger-bound")
    rows = [json.loads(line) for line in raw.split(b"\n")[:-1]]  # A row still being written is no observation.
    return [row for row in rows if row.get("path") == "/subscription" and row.get("userAgent") == PRODUCT_AGENT
            and type(row.get("timestamp")) in (int, float) and row["timestamp"] >= since]


def subscription_row(owner, runtime, workspace, identity, subscription, refreshed):
    rows = runtime.result(owner, workspace, identity, "subscriptions", "list")["data"]["subscriptions"]
    require(len(rows) == 1 and rows[0].get("id") == subscription and rows[0].get("name") == SUBSCRIPTION_NAME,
            "scheduled-one-owned-subscription")
    expected = ("OK", None, 1) if refreshed else ("", None, 0)
    require((rows[0].get("refreshStatus"), rows[0].get("failureReason"), rows[0].get("cachedLocations")) == expected,
            "scheduled-subscription-refresh-state")
    return rows[0]


def opening_samples(owner, traffic):
    """The sampler's first two samples succeeded before anything is armed; it is never started again."""
    raw = owner.root / f"child-{traffic.ordinal:04d}.stdout.raw"
    until = time.monotonic() + 30
    while True:
        require(traffic.process.poll() is None, "scheduled-traffic-ended-before-observation")
        lines = raw.read_bytes().split(b"\n")[:-1]
        if len(lines) >= 2:
            first = [json.loads(line) for line in lines[:2]]
            require(all(row.get("kind") == "sample" and row.get("succeeded") is True for row in first),
                    "scheduled-traffic-opening-samples-failed")
            return first
        if time.monotonic() >= until:
            owner.park("scheduled-traffic-opening-not-observed-no-replay")
        time.sleep(0.05)


def observe(owner, runtime, workspace, identity, baseline, opened, deadline, traffic):
    """Read the owner's ledger until its one new scheduled refresh is final; nothing here writes.

    The bracket runs from the start of the last listing without that operation to the return of the first listing that
    shows it final, so the refresh ran inside it. A run still open at the deadline is an unknown outcome.
    """
    absent_since, first, polls = opened, None, 0
    while True:
        require(traffic.process.poll() is None, "scheduled-traffic-ended-before-refresh")
        started = time.time()
        rows = runtime.result(owner, workspace, identity, "operations", "list")["data"]["operations"]
        returned = time.time()
        polls += 1
        new = [row for row in rows if row.get("id") not in baseline and str(row.get("requestId", "")).startswith(SCHEDULED_PREFIX)]
        require(len(new) <= 1 and all(row.get("operation") == OPERATION and row.get("controllerId") == identity for row in new),
                "scheduled-refresh-not-one-owner-operation")
        if new:
            first = first or {"row": new[0], "observedAt": returned, "poll": polls}
            require(new[0].get("id") == first["row"].get("id"), "scheduled-refresh-identity-changed")
            if new[0].get("final") is True:
                return {"row": new[0], "first": first, "polls": polls, "bracket": {"startedAt": absent_since, "finishedAt": returned}}
        else:
            absent_since = started
        if time.time() >= deadline:
            if first is not None:
                owner.park("scheduled-refresh-pending-no-replay")
            raise AssertionError("scheduled-refresh-not-observed")
        time.sleep(POLL_SECONDS)


def disarm_after_failure(owner, runtime, workspace, identity, error):
    """A known failure after arming turns the policy off first, so no scheduled run meets the closing's own off.

    The original failure stays the row's reason; a refused write is only recorded, never sent again.
    """
    try:
        guarded(owner, runtime, workspace, identity, "settings", "set", "refresh.policy", "off")
        disarmed = True
    except AssertionError as refused:
        disarmed = False
        owner.event("scheduled-disarm-after-failure-refused", {"reason": str(refused)[:120], "replayAllowed": False})
    owner.event("scheduled-disarmed-after-failure", {"reason": str(error)[:120], "disarmed": disarmed, "replayAllowed": False})


def run(owner, state, inputs, runtime, cases, observer):
    """Configure one owned subscription, observe its scheduled refresh with traffic sampled, disarm it.

    Returns the actors of the runtime it leaves running for the row's own explicit off.
    """
    require(type(inputs) is dict and set(inputs) == INPUT_FIELDS and type(inputs["schemaVersion"]) is int
            and inputs["schemaVersion"] == 1, "scheduled-native-inputs")
    workspace, identity, ready = state["workspace"], state["identity"], state["ready"]
    native = observer.WindowsNative()
    source = ready.get("source")
    found = re.fullmatch(r"https://localhost:([0-9]{1,5})/subscription", source) if type(source) is str else None
    require(found is not None and int(found[1]) == ready["httpsPort"], "scheduled-fixture-subscription-source")
    ledger = Path(state["inputs"]["fixtureRoot"]) / "ledger.jsonl"
    require(not any(child.label == "lifecycle-gui" for child in owner.children), "scheduled-row-started-a-gui")
    # Proxy A goes off first: the source then changes with no live runtime to strand or to leave pending.
    opening = runtime.result(owner, workspace, identity, "status")
    require(opening["data"]["runtimeRunning"] is True, "scheduled-opening-proxy-a")
    runtime.result(owner, workspace, identity, "off")
    stopped = runtime.result(owner, workspace, identity, "status")
    require(stopped["data"]["runtimeRunning"] is False and stopped["data"]["runtimeId"] is None, "scheduled-proxy-a-off")
    exits = observer.observe_exit([state["actors"]["runtime"]], native)
    require(len(exits) == 1 and exits[0].get("originalAbsent") is True, "scheduled-proxy-a-runtime-exit-unproven")
    # No policy runs while the source is made; the default is off, and this says so before any subscription exists.
    guarded(owner, runtime, workspace, identity, "settings", "set", "refresh.policy", "off")
    require(runtime.result(owner, workspace, identity, "subscriptions", "list")["data"]["subscriptions"] == [],
            "scheduled-empty-subscription-population")
    added = guarded(owner, runtime, workspace, identity, "subscriptions", "add", "--source", source, "--name", SUBSCRIPTION_NAME)
    subscription = added["data"].get("id")
    require(type(subscription) is str and subscription, "scheduled-subscription-identity")
    subscription_row(owner, runtime, workspace, identity, subscription, False)
    guarded(owner, runtime, workspace, identity, "source", "set", "subscription", subscription)
    manual = time.time()
    runtime.result(owner, workspace, identity, "subscriptions", "refresh", subscription)
    subscription_row(owner, runtime, workspace, identity, subscription, True)
    require(product_fetches(ledger, manual), "scheduled-manual-refresh-fetch-not-observed")
    locations = runtime.result(owner, workspace, identity, "locations", "list")["data"]["locations"]
    require(len(locations) == 1 and locations[0].get("index") == 1, "scheduled-one-subscription-location")
    guarded(owner, runtime, workspace, identity, "locations", "select", "1")
    for key, value in (("refresh.find-best-after-refresh", "false"), ("refresh.custom-hours", CUSTOM_HOURS)):
        guarded(owner, runtime, workspace, identity, "settings", "set", key, value)
    runtime.result(owner, workspace, identity, "on")
    on = runtime.result(owner, workspace, identity, "status")
    view = runtime_view(on)
    require(view["runtimeRunning"] is True and view["activeMode"] == "proxy-only" and view["runtimeId"]
            and view["activeLocationId"] and view["activeLocationId"] == view["selectedLocationId"]
            and on["restartRequired"] is False, "scheduled-subscription-runtime-on")
    actors = runtime.capture_proxy_actors(owner, state["serve"], native, state["inputs"]["runtimeImagePath"],
                                          state["inputs"]["runtimeSha256"])
    owner.event("scheduled-subscription-runtime-on", {"subscriptionId": subscription, "status": on, "actors": actors,
                                                       "manualRefreshAt": manual, "replayAllowed": False})
    mixed = cases.product_traffic_port(str(workspace / "runtime-config.json"), ready["advertisedSocksPort"])
    traffic = owner.child("lifecycle-traffic", [owner.request["pythonRuntime"]["interpreterPath"], "-I", "-B",
                                                inputs["trafficWorkerPath"], "--input", inputs["trafficInputPath"],
                                                "--mixed-port", str(mixed)])
    opening_samples(owner, traffic)
    armed = False
    try:
        no_frontend(owner, workspace, identity, "opening")
        gui_absent(owner, native, observer, inputs["guiPath"], "opening")
        opened = time.time()
        baseline = {row.get("id") for row in runtime.result(owner, workspace, identity, "operations", "list")["data"]["operations"]}
        armed = True  # Before the write: a reply that does not prove its outcome still gets the policy turned off again.
        guarded(owner, runtime, workspace, identity, "settings", "set", "refresh.policy", "custom")
        status = runtime.result(owner, workspace, identity, "status")
        require(runtime_view(status) == view and status["restartRequired"] is False, "scheduled-arming-changed-runtime")
        owner.event("scheduled-refresh-armed", {"policy": "custom", "customHours": CUSTOM_HOURS, "status": status,
                                                "baselineOperations": len(baseline), "replayAllowed": False})
        seen = observe(owner, runtime, workspace, identity, baseline, opened, manual + INTERVAL_SECONDS + OBSERVE_SLACK_SECONDS, traffic)
        operation = seen["row"]["id"]
        matched, terminal = envelope(owner.invoke(workspace, "--json", "--controller-id", identity, "operations", "status", operation),
                                     identity, "OK", 0)
        require(matched and terminal.get("operationId") == operation, "scheduled-refresh-terminal-not-ok")
        closing = runtime.result(owner, workspace, identity, "status")
        require(runtime_view(closing) == view, "scheduled-refresh-changed-runtime")
        require(closing["restartRequired"] is False, "scheduled-refresh-left-pending-change")
        for role in ("owner", "runtime"):
            cases.exact_actor(native, actors[role], elevated=False)
        no_frontend(owner, workspace, identity, "closing")
        gui_absent(owner, native, observer, inputs["guiPath"], "closing")
        refreshed = subscription_row(owner, runtime, workspace, identity, subscription, True)
        bracket = seen["bracket"]
        fetches = product_fetches(ledger, opened)
        require(fetches and all(bracket["startedAt"] <= row["timestamp"] <= bracket["finishedAt"] and row.get("status") == 200
                                for row in fetches), "scheduled-refresh-fetch-not-observed")
    except AssertionError as error:
        if armed:
            disarm_after_failure(owner, runtime, workspace, identity, error)
        raise
    guarded(owner, runtime, workspace, identity, "settings", "set", "refresh.policy", "off")
    terminal_traffic = traffic.wait()
    require(terminal_traffic["exitCode"] == 0 and all(terminal_traffic["eof"].values()), "scheduled-traffic-original-child-terminal")
    stdout = (owner.root / f"child-{traffic.ordinal:04d}.stdout.raw").read_text(encoding="utf-8")
    require(not (owner.root / f"child-{traffic.ordinal:04d}.stderr.raw").read_bytes(), "scheduled-traffic-observer-stderr")
    measured = cases.traffic_window(stdout, [{"action": "scheduled-refresh", **bracket}])
    require(all(row.get("mixedPort") == mixed for row in map(json.loads, stdout.splitlines()) if row.get("kind") == "sample"),
            "scheduled-sampler-product-port-binding")
    owner.event("scheduled-refresh-observed", {"subscriptionId": subscription, "operation": seen["row"], "firstSeen": seen["first"],
                                               "polls": seen["polls"], "bracket": bracket, "terminal": terminal, "fetches": fetches,
                                               "subscription": refreshed, "closingStatus": closing, "runtimeActor": actors["runtime"],
                                               "measuredTraffic": measured, "trafficTerminal": terminal_traffic, "policyDisarmed": True,
                                               "noFrontendAttached": True, "installedAdmissionArtifactId": inputs["installedAdmissionArtifactId"],
                                               "fixtureAdmissionArtifactId": inputs["fixtureAdmissionArtifactId"],
                                               "nativeAcceptanceComplete": False})
    return {"actors": actors, "subscriptionId": subscription, "operation": seen["row"], "measuredTraffic": measured}
