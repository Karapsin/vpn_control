"""windows-proxy-lifecycle.scheduled-refresh, offline: the full row in test_windows_proxy_lifecycle's world.

The world's product gains what this row reads from the Kotlin source: the subscription source, the owner's operation
ledger, DesktopAutoRefreshScheduler's first run one interval after the last refresh and every interval after a run,
the revision-guard rule of DesktopControlSupport (read from its source), and the fixture ledger row of each fetch with
DesktopSubscriptionDownloadClient's User-Agent. Every row runs through the real dedicated driver, runtime stages,
lifecycle cases and scheduled cases; each control makes the product answer wrong once and the row must end 1 with
everything it started closed, or park where the outcome is open. Nothing here proves a Windows behaviour.
"""
import hashlib
import json
from pathlib import Path
import re
import types
import unittest
from unittest import mock
import uuid

from agent_tools import native_scenario_windows as windows
from agent_tools import windows_lifecycle_cases as lifecycle_cases
from agent_tools import windows_lifecycle_runtime_stages as runtime_stages
from agent_tools import windows_lifecycle_scheduled_cases as scheduled_cases
from agent_tools import windows_ordinary_dedicated_driver as dedicated_driver
from agent_tools import windows_scenario_proxy as proxy
from agent_tools.tests import test_windows_proxy_lifecycle as world

ROOT = world.ROOT
VARIANT = "scheduled-refresh"
SCENARIO = "windows-proxy-lifecycle." + VARIANT
SOURCE = "https://localhost:24443/subscription"
RELAY = 23456  # The world fixture's advertised SOCKS port: the subscription's one location points at it.
TRAFFIC_INPUT = "C:\\W\\proxy-traffic.json"


def kotlin(path):
    return (ROOT / path).read_text(encoding="utf-8")


def revision_guarded():
    """The wire names DesktopControlSupport.revisionGuardOperations takes a revision guard for, read from the source."""
    support = kotlin("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopControlSupport.kt")
    names = re.findall(r"\bval revisionGuardOperations = setOf\(([A-Z_,\s]+)\)", support)
    wires = dict(re.findall(r"\b([A-Z_]+)\(\"([a-z.-]+)\"\)", kotlin("shared/model/src/commonMain/kotlin/com/kardinal/vpncontrol/model/ControlOperationId.kt")))
    if len(names) != 1 or not wires:
        raise AssertionError("the revision guard rule is not where the fake product reads it")
    return frozenset(wires[name.strip()] for name in names[0].split(",") if name.strip()), frozenset(wires.values())


GUARDED, WIRES = revision_guarded()


class ScheduledProduct(world.Product):
    """The world's product with the subscription source, the owner's operation ledger and its scheduler."""

    def __init__(self, world_, owner):
        super().__init__(world_, owner)
        self.subscription_rows, self.active_subscription = [], None
        self.policy, self.hours, self.find_best_after = "off", 3.0, True
        self.ledger_rows, self.signature, self.next_fire = [], None, None
        self.ledger = None  # The fixture's ledger.jsonl, once the fixture started.
        self.run_seconds = 2.5  # A scheduled run takes this long, so a poll first sees it running.
        self.scheduler = True  # False: a product whose scheduler never runs anything.
        self.fault = None  # What a wrong product does in its scheduled run, or in the manual refresh.
        self.pending_change = False

    def envelope(self, code="OK", **data):
        body = super().envelope(code, **data)
        body["restartRequired"] = body["restartRequired"] or self.pending_change
        return body

    def status(self):
        body = super().status()
        if self.running:  # Each runtime its own identity, as DesktopRuntimeTransition gives a started runtime.
            body["data"].update(runtimeId="runtime-%d" % self.runtime.pid, runtimeStartedAt=self.runtime.created)
        return body

    def target(self):
        found = [row for row in self.subscription_rows if row["id"] == self.active_subscription]
        return found[0] if self.source == "subscription" and found and found[0]["url"] else None

    def interval(self):
        """SubscriptionRefreshPolicy.effectiveIntervalMinutes, in seconds: at least the product's five minutes."""
        return {"custom": max(round(self.hours * 60), 5) * 60.0, "every-hour": 3600.0}.get(self.policy)

    def tick(self):
        """DesktopAutoRefreshScheduler: a changed schedule restarts its job; the first run one interval after the last
        refresh, or at once without one; each later run one interval after the previous one ended."""
        now, target, interval = self.owner.clock.now, self.target(), self.interval()
        signature = (self.policy, self.hours, target and target["id"], target and target["url"])
        if signature != self.signature:
            self.signature = signature
            self.next_fire = None if target is None or interval is None or not self.scheduler else (
                target["lastRefreshed"] + interval if target["lastRefreshed"] else now)
        while self.next_fire is not None and now >= self.next_fire:
            fire = self.next_fire
            self.scheduled_run(fire)
            self.next_fire = fire + self.run_seconds + interval

    def fetch(self, at):
        """The fixture worker's ledger row of the product's own GET of the subscription."""
        row = {"timestamp": at, "path": "/subscription", "userAgent": "VPNControlDesktop/1.0", "status": 200, "mode": "ok", "modeOrdinal": 0}
        with self.ledger.open("ab") as output:
            output.write((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode())

    def record(self, operation, started, *, request=None, code="OK", seconds=0.0, controller=None):
        row = {"id": str(uuid.uuid4()), "requestId": request or str(uuid.uuid4()), "operation": operation,
               "controllerId": controller or self.identity, "startedAt": started, "finishedAt": started + seconds, "code": code}
        self.ledger_rows.append(row)
        return row

    def scheduled_run(self, fire):
        fault, target = self.fault, self.target()
        row = self.record("subscriptions.refresh", fire, request="scheduled-refresh:" + str(uuid.uuid4()), seconds=self.run_seconds,
                          code="RUNTIME_FAILED" if fault == "failed" else "OK",
                          controller="controller-other" if fault == "other-controller" else None)
        if fault == "pending":
            row["finishedAt"] = float("inf")
        if fault not in ("no-fetch", "failed"):
            self.fetch(fire + 0.1)
        if fault in ("restart", "stop") and self.running:
            self.runtime.end(0)
            if fault == "restart":
                image = str(Path(self.owner.request["workspace"]) / "runtime" / "tools" / "sing-box.exe")
                self.runtime, _ = self.world.spawn(self.jvm.pid, image, world.RUNTIME_SHA)
            else:
                self.running, self.active = False, None
        if fault == "pending-change":
            self.pending_change = True
        if fault == "drop-traffic":
            self.owner.sampler_failing = (fire, fire + self.run_seconds)
        if row["code"] == "OK":
            target["lastRefreshed"] = fire + self.run_seconds

    def summary(self, row):
        final = self.owner.clock.now >= row["finishedAt"]
        return {"controllerId": row["controllerId"], "id": row["id"], "requestId": row["requestId"], "operation": row["operation"],
                "phase": ("succeeded" if row["code"] == "OK" else "failed") if final else "running", "final": final,
                "cancellable": row["operation"] == "subscriptions.refresh", "completedUnits": None, "totalUnits": None,
                "code": row["code"] if final else None}

    def handled(self, words):
        """The commands this product answers itself; any other goes to the world's product."""
        if words[:2] == ["settings", "set"] and words[2].startswith("refresh."):
            return self.settings
        if words in (["subscriptions", "list"], ["operations", "list"]) or words[:2] in (["subscriptions", "add"], ["subscriptions", "refresh"],
                                                                                       ["operations", "status"]):
            return getattr(self, words[0] + "_command")
        if words[:3] == ["source", "set", "subscription"]:
            return self.source_set
        if self.source == "subscription" and words[:2] in (["locations", "list"], ["locations", "select"]):
            return self.locations_command
        return None

    def run(self, words):
        self.tick()
        words, rest = list(words), list(words)[1:]
        if rest[:1] == ["--controller-id"]:
            if rest[1] != self.identity:
                return super().run(words)
            rest = rest[2:]
        guard = None
        if rest[:1] == ["--if-revision"]:
            guard, rest = int(rest[1]), rest[2:]
            # DesktopCli refuses a revision guard on any operation outside revisionGuardOperations, before the owner.
            wire = next((".".join(rest[:size]) for size in (3, 2, 1) if ".".join(rest[:size]) in WIRES), None)
            if wire not in GUARDED:
                self.calls.append(tuple(words))
                return 1, self.envelope("UNSUPPORTED")
        handler = self.handled(rest)
        if handler is None:
            code, body = super().run(words)
            if code == 0 and (rest[:1] in (["on"], ["off"]) or rest[:2] in (["locations", "select"], ["settings", "set"])):
                self.record(".".join(rest[:2] if rest[0] in ("locations", "settings") else rest[:1]), self.owner.clock.now)
            return code, body
        self.calls.append(tuple(words))
        if guard is not None and guard != self.revision:
            return 1, self.envelope("CONFLICT")
        return handler(rest)

    def changed(self):
        self.revision += 1

    def settings(self, words):
        key, value = words[2], words[3]
        before = (self.policy, self.hours, self.find_best_after)
        if key == "refresh.policy" and value in ("off", "every-hour", "custom"):
            self.policy = value
        elif key == "refresh.custom-hours":
            self.hours = max(float(json.loads(value)), 5 / 60.0)  # normalizeSubscriptionRefreshCustomHours
        elif key == "refresh.find-best-after-refresh" and value in ("true", "false"):
            self.find_best_after = value == "true"
        else:
            return 1, self.envelope("INVALID_ARGUMENT")
        if (self.policy, self.hours, self.find_best_after) != before:
            self.changed()  # ControlConfigurationIdentity: only a changed configuration is an edit.
        self.record("settings.set", self.owner.clock.now)
        return 0, self.envelope()

    def subscriptions_command(self, words):
        if words[1] == "list":
            return 0, self.envelope(subscriptions=[{"id": row["id"], "name": row["name"], "cachedLocations": len(row["cached"]),
                                                     "refreshStatus": row["status"], "failureReason": None} for row in self.subscription_rows])
        if words[1] == "add":
            options = dict(zip(words[2::2], words[3::2]))
            if set(options) != {"--source", "--name"} or not options["--source"].startswith("https://"):
                return 1, self.envelope("INVALID_ARGUMENT")
            row = {"id": "subscription-" + uuid.uuid4().hex[:8], "name": options["--name"], "url": options["--source"], "cached": [],
                   "status": "", "lastRefreshed": 0}
            self.subscription_rows.insert(0, row)
            # SubscriptionSourceLogic.saveSubscriptionDraft: the new subscription becomes the active subscription source.
            self.source, self.active_subscription = "subscription", row["id"]
            self.changed()
            self.record("subscriptions.add", self.owner.clock.now)
            return 0, self.envelope(id=row["id"])
        # refresh <id>: one fetch, its one location cached, and its time the last refresh.
        found = [row for row in self.subscription_rows if row["id"] == words[2]]
        if not found:
            return 1, self.envelope("NOT_FOUND")
        if self.fault != "manual-no-fetch":
            self.fetch(self.owner.clock.now)
        found[0].update(cached=["socks://127.0.0.1:%d" % RELAY], status="OK", lastRefreshed=self.owner.clock.now)
        self.record("subscriptions.refresh", self.owner.clock.now)
        return 0, self.envelope()

    def source_set(self, words):
        if words[3] not in {row["id"] for row in self.subscription_rows}:
            return 1, self.envelope("NOT_FOUND")
        if (self.source, self.active_subscription) != ("subscription", words[3]):
            self.source, self.active_subscription = "subscription", words[3]
            self.changed()
        self.record("source.set", self.owner.clock.now)
        return 0, self.envelope(id=words[3])

    def locations_command(self, words):
        target = self.target()
        names = [link.split("://", 1)[1] for link in (target["cached"] if target else [])]
        if words[1] == "list":
            return 0, self.envelope(locations=[{"index": index + 1, "name": name} for index, name in enumerate(names)])
        selector = words[2]
        chosen = names[int(selector) - 1] if selector.isdigit() and 0 < int(selector) <= len(names) else selector if selector in names else None
        if chosen is None:
            return 1, self.envelope("NOT_FOUND")
        if chosen != self.selected:
            self.selected = chosen
            self.changed()
        self.record("locations.select", self.owner.clock.now)
        return 0, self.envelope()

    def operations_command(self, words):
        if words[1] == "list":
            return 0, self.envelope(operations=[self.summary(row) for row in self.ledger_rows])
        found = [row for row in self.ledger_rows if row["id"] == words[2]]
        if not found:
            return 1, self.envelope("NOT_FOUND")
        summary = self.summary(found[0])
        code = summary["code"] if summary["final"] else "ACCEPTED"
        body = self.envelope(code)  # The retained result: the action's own data, which the case never reads.
        body.update(final=summary["final"], ok=code in ("OK", "ACCEPTED"), operationId=found[0]["id"])
        return (0 if code in ("OK", "ACCEPTED") else 1), body


class Sampler(world.Traffic):
    """The world's sampler; a product that dropped traffic through its scheduled run fails the samples of that run."""

    def failed(self):
        failing = getattr(self.owner, "sampler_failing", None)
        path = self.owner.root / f"child-{self.ordinal:04d}.stdout.raw"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        for row in rows:
            if failing and row["kind"] == "sample" and row["startedAt"] <= failing[1] and row["finishedAt"] >= failing[0]:
                row.update(succeeded=False, errorClass="ConnectionResetError", reason="peer reset")
            if row["kind"] == "terminal":
                row["allSamplesSucceeded"] = all(item["succeeded"] for item in rows if item["kind"] == "sample")
        path.write_bytes("".join(json.dumps(row) + "\n" for row in rows).encode())
        return any(row["kind"] == "sample" and not row["succeeded"] for row in rows)

    def wait(self):
        if self.terminal is None:
            self.write(self.owner.clock.now + 1, terminal=True)
            self.os_process.end(1 if self.failed() else 0)
        return world.Child.wait(self)


class ScheduledOwner(world.StartOwner):
    """The dedicated driver's owner over the world: the real stage, cases and scheduled cases, the extended product."""

    def __init__(self, root, world_):
        super().__init__(root, world_)
        self.product = ScheduledProduct(world_, self)
        self.ready_changes["source"] = SOURCE  # https_subscription_relay_fixture.readiness publishes it.

    def source(self, relative):
        raw = (ROOT / relative).read_bytes()
        path = self.SOURCE + relative.rsplit("/", 1)[1]
        record = {"sha256": hashlib.sha256(raw).hexdigest(), "nativeIdentity": {"sizeBytes": len(raw)}}
        self.by_path[path.casefold()] = types.SimpleNamespace(record=record, directory=False, digest=lambda as_bytes=False, maximum=0: raw)
        return path

    def module(self, path, name):
        if name == "_owned_dedicated_scheduled_cases":
            self.loaded.append(name)
            return scheduled_cases
        return super().module(path, name)

    def child(self, label, argv, **options):
        if label == "lifecycle-traffic":
            return Sampler(self, label, argv)
        child = super().child(label, argv, **options)
        if label == "owned-runtime-fixture":
            # The fixture worker creates its ledger before it serves.
            config = json.loads(Path(argv[-1]).read_bytes())
            self.product.ledger = Path(config["ledgerFile"])
            self.product.ledger.touch()
        return child


class ScheduledBase(world.WorldBase):
    def setUp(self):
        super().setUp()
        self.owner = ScheduledOwner(self.root, self.world)
        for patcher in (mock.patch.object(runtime_stages, "os", world.NtOs()), mock.patch.object(runtime_stages, "time", world.Clock()),
                        mock.patch.object(lifecycle_cases, "time", self.owner.clock), mock.patch.object(scheduled_cases, "time", self.owner.clock)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def harness(self):
        harness = world.StartFailureTests.harness(self, VARIANT)
        owner = self.owner
        owner.pin(world.GUI, world.GUI_SHA)
        owner.pin(world.CLI, world.LAUNCHER_SHA)
        owner.pin(TRAFFIC_INPUT, "6" * 64)
        inputs = harness.LIFECYCLE_INPUTS
        inputs["modules"]["scheduled"] = owner.source("agent_tools/windows_lifecycle_scheduled_cases.py")
        inputs["scheduled"] = {"schemaVersion": 1, "guiPath": world.GUI,
                               "trafficWorkerPath": owner.source("agent_tools/windows_lifecycle_traffic_worker.py"),
                               "trafficInputPath": TRAFFIC_INPUT, "installedAdmissionArtifactId": "installed", "fixtureAdmissionArtifactId": "fixture"}
        return harness

    def run_row(self, harness=None):
        return dedicated_driver.run_lifecycle(self.owner, lifecycle_cases, harness or self.harness())

    def commands(self):
        return world.StartFailureTests.commands(self)

    def events(self, kind):
        return [value for name, value in self.owner.events if name == kind]

    def scheduled_runs(self):
        return [row for row in self.owner.product.ledger_rows if row["requestId"].startswith("scheduled-refresh:")]

    def assert_known_failure(self, reason):
        self.assertEqual(1, self.run_row())
        self.assertEqual([reason], [value["reason"] for value in self.events("dedicated-proxy-lifecycle-known-failure")])
        self.assert_closed()

    def assert_closed(self):
        self.assertTrue(all(child.terminal is not None for child in self.owner.children), "every child the row started has ended")
        self.assertEqual(0, self.owner.product.jvm.exit_code, "the serve's owner quit")
        self.assertTrue((self.root / "fixture" / "stop.json").exists(), "the fixture ended on its own stop record")
        self.assertEqual(1, self.commands().count(("quit",)), "one quit, never sent again")
        self.assertEqual("off", self.owner.product.policy, "no scheduled run is left armed for the closing to meet")


class ScheduledRowTests(ScheduledBase):
    def test_the_row_observes_one_scheduled_refresh_with_no_gui_and_closes_known(self):
        self.assertEqual(0, self.run_row())
        product = self.owner.product
        self.assertEqual(["_owned_dedicated_runtime_stages", "_owned_dedicated_proxy_observer", "_owned_dedicated_scheduled_cases"],
                         self.owner.loaded)
        self.assertEqual([], self.events("dedicated-proxy-lifecycle-known-failure"))
        self.assertEqual([VARIANT], [value["variant"] for value in self.events("dedicated-proxy-lifecycle-known-closed")])
        runs = self.scheduled_runs()
        self.assertEqual(1, len(runs), "one scheduled run, then the policy is off again")
        observed = self.events("scheduled-refresh-observed")[0]
        self.assertEqual(runs[0]["id"], observed["operation"]["id"])
        self.assertEqual((runs[0]["id"], "OK", True), (observed["terminal"]["operationId"], observed["terminal"]["code"], observed["terminal"]["final"]))
        self.assertGreater(observed["firstSeen"]["poll"], 1, "the scheduled run came one interval after the manual refresh, not at arming")
        self.assertFalse(observed["firstSeen"]["row"]["final"], "this run was seen running before it was final")
        bracket = observed["bracket"]
        self.assertTrue(bracket["startedAt"] <= runs[0]["startedAt"] and runs[0]["startedAt"] + product.run_seconds <= bracket["finishedAt"])
        self.assertEqual([runs[0]["startedAt"] + 0.1], [row["timestamp"] for row in observed["fetches"]], "the run's own fetch, and no other")
        coverage = observed["measuredTraffic"]["coverage"]
        self.assertEqual(["scheduled-refresh"], [row["action"] for row in coverage])
        self.assertTrue(all(row["beforeSamples"] and row["duringSamples"] and row["afterSamples"] for row in coverage))
        # No GUI: the owner held no frontend at both edges, and none ran.
        self.assertEqual(["opening", "closing"], [value["label"] for value in self.events("scheduled-owner-without-frontend")])
        self.assertEqual(["opening", "closing"], [value["label"] for value in self.events("scheduled-gui-census")])
        self.assertNotIn("lifecycle-gui", [child.label for child in self.owner.children])
        self.assertIsNone(product.frontend)
        # The runtime the subscription location started is the one the row's own off stopped; proxy A was off before it.
        on = self.events("scheduled-subscription-runtime-on")[0]
        self.assertEqual(on["actors"]["runtime"]["pid"], observed["runtimeActor"]["pid"])
        self.assertEqual(0, product.runtime.exit_code)
        commands = self.commands()
        self.assertLess(commands.index(("off",)), commands.index(("subscriptions", "add", "--source", SOURCE, "--name", "Owned scheduled")))
        self.assertEqual(2, commands.count(("off",)), "proxy A's off, then the row's own explicit off")
        self.assertIn(("subscriptions", "refresh", product.subscription_rows[0]["id"]), commands)
        self.assertEqual("off", product.policy)
        self.assertEqual(1, commands.count(("quit",)))
        self.assertTrue(all(child.terminal is not None for child in self.owner.children))

    def test_a_run_first_seen_final_is_bracketed_by_the_listing_before_it(self):
        self.owner.product.run_seconds = 0.1  # Ends between two listings: never seen running.
        self.assertEqual(0, self.run_row())
        observed = self.events("scheduled-refresh-observed")[0]
        run = self.scheduled_runs()[0]
        self.assertTrue(observed["firstSeen"]["row"]["final"])
        self.assertEqual(observed["firstSeen"]["poll"], observed["polls"], "final at first sight")
        self.assertTrue(observed["bracket"]["startedAt"] <= run["startedAt"] < run["startedAt"] + 0.1 <= observed["bracket"]["finishedAt"])
        self.assertTrue(all(row["duringSamples"] for row in observed["measuredTraffic"]["coverage"]))

    def test_no_write_this_row_makes_carries_a_guard_the_product_refuses(self):
        self.assertEqual(0, self.run_row())
        guarded = [call for call in self.owner.product.calls if "--if-revision" in call]
        self.assertTrue(guarded)
        for call in guarded:
            words = list(call[call.index("--if-revision") + 2:])
            self.assertIn(next(".".join(words[:size]) for size in (3, 2, 1) if ".".join(words[:size]) in WIRES), GUARDED, call)
        self.assertNotIn("subscriptions.refresh", GUARDED, "DesktopControlSupport takes no guard for a refresh")
        self.assertEqual([], [call for call in self.owner.product.calls if "UNSUPPORTED" in json.dumps(call)])

    def test_the_constants_are_the_products_own(self):
        models = kotlin("shared/model/src/commonMain/kotlin/com/kardinal/vpncontrol/model/Models.kt")
        minutes = int(re.findall(r"\bconst val MIN_SUBSCRIPTION_REFRESH_MINUTES = ([0-9]+)\b", models)[0])
        self.assertEqual((minutes * 60, float(minutes)), (scheduled_cases.INTERVAL_SECONDS, float(scheduled_cases.CUSTOM_HOURS) * 60.0))
        session = kotlin("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopHeadlessSession.kt")
        self.assertEqual(["SUBSCRIPTIONS_REFRESH"], re.findall(r"operations\.execute\(\s*com\.kardinal\.vpncontrol\.model\.ControlOperationId\.([A-Z_]+),\s*"
                                                                r"DesktopCliCommand\.SubscriptionRefresh\(\"scheduled\"\),\s*requestId = \"scheduled-refresh:", session))
        self.assertEqual(scheduled_cases.SCHEDULED_PREFIX, "scheduled-refresh:")
        self.assertIn(scheduled_cases.OPERATION, WIRES)
        client = kotlin("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopSubscriptionDownloadClient.kt")
        self.assertEqual([scheduled_cases.PRODUCT_AGENT], re.findall(r"\buserAgent = \"([^\"]+)\"", client))
        visibility = kotlin("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/DesktopGuiVisibilityControl.kt")
        self.assertRegex(visibility, r"if \(frontend == null\) \{\n\s+if \(input\.command\.operation == ControlOperationId\.GUI_HIDE\) \{\n\s+code = ControlCode\.NOT_FOUND\n")
        self.assertEqual(scheduled_cases.GUI_LEAF, windows.host_job.PRODUCT_GUI)
        self.assertEqual(set(scheduled_cases.INPUT_FIELDS), set(dedicated_driver.SCHEDULED_FIELDS))
        self.assertEqual(hashlib.sha256((ROOT / "agent_tools/windows_lifecycle_scheduled_cases.py").read_bytes()).hexdigest(), dedicated_driver.SCHEDULED_SHA)


class ScheduledControlTests(ScheduledBase):
    """A wrong product answer ends the row 1 with what it started closed; the failed oracle never runs again."""

    def test_a_product_whose_scheduler_never_runs_is_a_known_failure_at_the_deadline(self):
        self.owner.product.scheduler = False
        self.assert_known_failure("scheduled-refresh-not-observed")
        disarmed = self.events("scheduled-disarmed-after-failure")
        self.assertEqual([("scheduled-refresh-not-observed", True)], [(value["reason"], value["disarmed"]) for value in disarmed])

    def test_a_failed_scheduled_refresh_is_a_known_failure(self):
        self.owner.product.fault = "failed"
        self.assert_known_failure("scheduled-refresh-terminal-not-ok")

    def test_a_refresh_that_replaced_the_runtime_is_a_known_failure(self):
        self.owner.product.fault = "restart"
        self.assert_known_failure("scheduled-refresh-changed-runtime")

    def test_a_refresh_that_left_the_proxy_stopped_is_a_known_failure(self):
        self.owner.product.fault = "stop"
        self.assert_known_failure("scheduled-refresh-changed-runtime")
        self.assertEqual(1, self.commands().count(("off",)), "the closing turns off nothing that is not running")

    def test_a_refresh_that_left_a_pending_change_is_a_known_failure(self):
        self.owner.product.fault = "pending-change"
        self.assert_known_failure("scheduled-refresh-left-pending-change")

    def test_a_refresh_with_no_fetch_of_its_own_is_a_known_failure(self):
        self.owner.product.fault = "no-fetch"
        self.assert_known_failure("scheduled-refresh-fetch-not-observed")

    def test_a_manual_refresh_with_no_fetch_is_a_known_failure_before_anything_is_armed(self):
        self.owner.product.fault = "manual-no-fetch"
        self.assert_known_failure("scheduled-manual-refresh-fetch-not-observed")
        self.assertEqual([], self.events("scheduled-refresh-armed"))
        self.assertNotIn("lifecycle-traffic", [child.label for child in self.owner.children])

    def test_a_run_of_another_controller_is_a_known_failure(self):
        self.owner.product.fault = "other-controller"
        self.assert_known_failure("scheduled-refresh-not-one-owner-operation")

    def test_traffic_that_failed_through_the_run_is_a_known_failure(self):
        self.owner.product.fault = "drop-traffic"
        self.assert_known_failure("scheduled-traffic-original-child-terminal")
        sampler = [child for child in self.owner.children if child.label == "lifecycle-traffic"]
        self.assertEqual([1], [child.terminal["exitCode"] for child in sampler], "the sampler's failed samples stay its evidence")

    def test_an_owner_that_holds_a_frontend_is_a_known_failure(self):
        launcher, jvm = self.world.spawn(None, world.GUI, world.GUI_SHA, launcher=True)
        self.owner.product.frontend = (jvm, self.owner.clock.now, True)
        self.assert_known_failure("scheduled-owner-frontend-attached")
        self.assertEqual([], self.events("scheduled-refresh-armed"), "nothing is armed while a GUI is attached")

    def test_a_running_installed_gui_is_a_known_failure_even_unattached(self):
        self.world.spawn(None, world.GUI, world.GUI_SHA, launcher=True)
        self.assert_known_failure("scheduled-installed-gui-running")

    def test_a_run_still_open_at_the_deadline_parks_with_everything_kept(self):
        self.owner.product.fault = "pending"
        with self.assertRaisesRegex(world.Parked, "^scheduled-refresh-pending-no-replay$"):
            self.run_row()
        self.assertNotIn(("quit",), self.commands())
        self.assertEqual("custom", self.owner.product.policy, "an open outcome is left as it is, never written over")
        self.assertEqual([], self.events("dedicated-proxy-lifecycle-known-failure"))


class AdmissionTests(unittest.TestCase):
    """The row exists end to end: the driver's variant, the job's files and harness, the matrix scenario it proves."""

    def test_the_variant_is_a_row_the_driver_and_the_job_both_know(self):
        # The admission's first gate (native_scenario_windows._admit): a closed name, never a refusal.
        row = windows._row(SCENARIO)
        self.assertIn(VARIANT, dedicated_driver.SCHEDULED_VARIANTS)
        self.assertEqual({"variant": VARIANT}, row["proxy"])
        self.assertIn(("agent_tools/windows_lifecycle_scheduled_cases.py", "scheduled", "data"), row["guestFiles"])
        self.assertIn(("agent_tools/windows_lifecycle_traffic_worker.py", "traffic", "data"), row["guestFiles"])
        self.assertEqual(proxy.generated_roles(VARIANT), tuple(role for role, _ in row["generated"]))
        self.assertIsNone(row.get("refusal"))
        sampler = json.loads(proxy.traffic_input(VARIANT, str(uuid.uuid4())))
        self.assertEqual((1800, 0.25), (sampler["sampleCount"], sampler["intervalSeconds"]))
        # The sampler starts after the case's own on, so it must outlast one interval and the slack from there.
        self.assertGreater(sampler["sampleCount"] * sampler["intervalSeconds"], scheduled_cases.INTERVAL_SECONDS + scheduled_cases.OBSERVE_SLACK_SECONDS)

    def test_the_matrix_counts_it_for_scheduled_work_without_a_gui_alone(self):
        named = sorted(name + ":" + scenario for name, table in windows.MATRIX_SCENARIOS.items() for scenario, rows in table.items() if SCENARIO in rows)
        self.assertEqual(["windows-owner-lifecycle:scheduled-without-gui"], named)
        self.assertEqual((SCENARIO,), windows.MATRIX_SCENARIOS["windows-owner-lifecycle"]["scheduled-without-gui"])


if __name__ == "__main__":
    unittest.main()
