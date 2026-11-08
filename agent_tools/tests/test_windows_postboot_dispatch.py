"""Reboot action planning, owner dispatch and main: declared peers only, no native effect.

A preboot ends with a known result the owner finishes, and nothing here reboots. Only
an effect whose outcome is unknown parks; a known failure finishes with exit 1.
"""
from pathlib import Path, PureWindowsPath
import base64
import contextlib
import copy
import hashlib
import io
import json
import sys
import types
import unittest
from unittest import mock

from agent_tools import windows_ordinary_process_owner as process_owner
from agent_tools import windows_ordinary_task as task
from agent_tools import windows_postboot_source_roles as roles
from agent_tools.tests import test_windows_ordinary_task as existing

ROOT = Path(__file__).resolve().parents[2]
ENTRY = {"sourceRoles": "windows_postboot_source_roles.py", "postbootAction": "windows_postboot_action.py",
         "prebootAction": "windows_preboot_action.py", "startupCollector": "windows_postboot_startup_actors.ps1"}


def planner_inputs(phase="postboot-final", scenario="reconnect"):
    common, _, _ = existing.synthetic_request()
    root = PureWindowsPath(common["operationRoot"])
    source = PureWindowsPath(next(p["path"] for p in common["filePins"] if p["path"].endswith("windows_ordinary_process_owner.py"))).parent
    local = PureWindowsPath(common["context"]["localAppData"])
    workspace = local / "VpnControlOrdinary-prior" / "workspace" if phase == "postboot-final" else root / "workspace"
    paths = {role: str(source / (role + ".data")) for role in task.POSTBOOT_ROLES}
    paths.update(powerShell=task.PS, gui=str(local / "vpn-control" / "vpn-control.exe"),
                 runtimeAuthority=str(local / "vpn-control" / "app" / "native" / "windows-amd64" / "native-helpers.json"))
    pins = {p["path"] for p in common["filePins"]}
    for role, value in paths.items():
        if value not in pins:
            common["filePins"].append(existing.pin(value, digest=task.POSTBOOT_ROLE_HASHES.get(role, "3" * 64)))
    cli = str(local / "vpn-control" / "vpn-control-cli.exe")
    traffic, checkpoint = str(root / "traffic-input.json"), str(local / "VpnControlOrdinary-prior" / "event-000040-reboot-checkpoint.json")
    common["filePins"] += [existing.pin(cli), existing.pin(traffic)] + ([existing.pin(checkpoint)] if phase == "postboot-final" else [])
    auto = {"schemaVersion": 1, "workspace": str(workspace)}
    for key, role in (("snapshotScriptPath", "snapshotScript"), ("powerShellPath", "powerShell"), ("migrationScriptPath", "migrationScript"),
                      ("startScriptPath", "startScript"), ("guiPath", "gui")):
        auto[key] = paths[role]
    config = {"schemaVersion": 1, "phase": phase, "scenario": scenario, "sourceRoles": paths, "autostartInputs": auto, "trafficInputPath": traffic}
    if phase == "postboot-final":
        config["checkpointPath"] = checkpoint
    directories = {PureWindowsPath(p["path"]) for p in common["directoryPins"]}
    for record in common["filePins"]:
        directories.update(PureWindowsPath(record["path"]).parents)
    if phase == "postboot-final":
        directories.update({workspace, *workspace.parents})
    common["directoryPins"] = [existing.pin(path, directory=True) for path in sorted(directories, key=str)]
    return common, {"cliPath": cli, "workspace": str(workspace), "productVersion": "2.2.16", "postbootAcceptance": config}


def plan(phase="postboot-final", scenario="reconnect", change=None):
    common, fields = planner_inputs(phase, scenario)
    if change is not None:
        change(common, fields)
    action = "windows-postboot-final" if phase == "postboot-final" else "windows-preboot-reboot"
    return task.worker_request(common, action, **fields)


class PlannerTests(unittest.TestCase):
    def test_both_phases_plan_one_closed_request(self):
        for phase, scenarios in (("preboot-reboot", ("reconnect", "explicit-off", "autostart-migration", "query-first")),
                                 ("postboot-final", ("reconnect", "explicit-off", "autostart-migration"))):
            for scenario in scenarios:
                with self.subTest(phase=phase, scenario=scenario):
                    request = plan(phase, scenario)
                    self.assertEqual((phase, scenario), (request["postbootAcceptance"]["phase"], request["postbootAcceptance"]["scenario"]))

    def test_every_open_door_is_refused(self):
        def config(change):
            return lambda common, fields: change(fields["postbootAcceptance"])
        cases = (
            ("missing-role", "postboot-final", config(lambda c: c["sourceRoles"].pop("startupCollector")), "closed-postboot-source-role-map"),
            ("reboot-command-role", "postboot-final", config(lambda c: c["sourceRoles"].update(shutdown=r"C:\Windows\System32\shutdown.exe")),
             "closed-postboot-source-role-map"),
            ("source-drift", "postboot-final", lambda common, fields: next(p for p in common["filePins"]
             if p["path"] == fields["postbootAcceptance"]["sourceRoles"]["startScript"]).update(sha256="4" * 64), "frozen-postboot-role-startScript"),
            ("host-packet-field", "preboot-reboot", config(lambda c: c.update(fixturePacketPath=c["trafficInputPath"])), "closed-postboot-config-schema"),
            ("reboot-intent-field", "preboot-reboot", config(lambda c: c.update(rebootIntentPath=c["trafficInputPath"])), "closed-postboot-config-schema"),
            ("query-first-after-reboot", "postboot-final", config(lambda c: c.update(scenario="query-first")), "closed-postboot-config-schema"),
            ("open-scenario", "preboot-reboot", config(lambda c: c.update(scenario="anything")), "closed-postboot-config-schema"),
            ("new-workspace-after-reboot", "postboot-final", lambda common, fields: fields.update(workspace=str(
             PureWindowsPath(common["operationRoot"]) / "workspace")), "same-original-postboot-workspace"),
            ("reused-workspace-before-reboot", "preboot-reboot", lambda common, fields: (
             fields.update(workspace=str(PureWindowsPath(common["context"]["localAppData"]) / "other" / "workspace")),
             fields["postbootAcceptance"]["autostartInputs"].update(workspace=fields["workspace"])), "fresh-private-preboot-workspace"),
            ("unpinned-checkpoint", "postboot-final", lambda common, fields: common["filePins"].remove(next(
             p for p in common["filePins"] if p["path"] == fields["postbootAcceptance"]["checkpointPath"])), "original-preboot-checkpoint-native-pin"),
            ("baseline-version", "postboot-final", lambda common, fields: fields.update(productVersion="2.2.13"), "postboot-current-product-version"),
            ("other-start-script", "preboot-reboot", config(lambda c: c["autostartInputs"].update(startScriptPath=c["sourceRoles"]["snapshotScript"])),
             "same-autostart-source-role"),
            # The runtime digest is read from the installed record beside the GUI, never from a file a caller names.
            ("runtime-authority-elsewhere", "postboot-final", config(lambda c: c["sourceRoles"].update(runtimeAuthority=c["trafficInputPath"])),
             "installed-runtime-authority-beside-gui"),
        )
        for name, phase, change, reason in cases:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, reason):
                plan(phase, change=change)


class Parked(BaseException):
    pass


def peer(action, behavior="positive"):
    """A declared owner: real Owner.run and main, peer pins, modules and effects."""
    phase = task.POSTBOOT_ACTION_PHASES[action]
    trace = []
    owner = types.SimpleNamespace(trace=trace, children=[types.SimpleNamespace(terminal={"exitCode": 0})], pins=[], by_path={}, reboot_effect=None)
    owner.request = {"action": action, "postbootAcceptance": {"phase": phase, "sourceRoles": {}}}
    modules = {}
    for role, name in ENTRY.items():
        path = ROOT / "agent_tools" / name
        raw = path.read_bytes()
        owner.request["postbootAcceptance"]["sourceRoles"][role] = str(path)
        owner.by_path[str(path).casefold()] = types.SimpleNamespace(
            record={"sha256": hashlib.sha256(raw).hexdigest(), "nativeIdentity": {"sizeBytes": len(raw)}},
            current=lambda role=role: trace.append(("pin-current", role)), digest=lambda retain=False, raw=raw: raw)
        if role != "startupCollector":
            modules[role] = types.SimpleNamespace(role=role)

    def action_body(*arguments):
        trace.append(("action", phase))
        if behavior == "known-failure":
            raise ValueError("declared-known-refusal")
        if behavior == "effect-unknown":
            owner.reboot_effect = "declared-effect"
            owner.park("declared-effect-unknown")
        return 0
    modules["prebootAction"].run_preboot = lambda who, config, sources, postboot: action_body(who, sources, postboot)
    modules["postbootAction"].run_postboot = lambda who, config, sources: action_body(who, sources)

    def module(path, name):
        role = next(key for key, value in owner.request["postbootAcceptance"]["sourceRoles"].items() if value == path)
        trace.append(("module", role))
        return modules[role]
    owner.module = module

    def park(reason, error=None):
        trace.append(("park", reason))
        raise Parked(reason)
    owner.park = park
    owner.finish = lambda code, error=None: trace.append(("finish", code))
    return owner


def run_main(owner):
    raw = json.dumps(owner.request).encode()
    record = {"path": "declared-request", "sha256": hashlib.sha256(raw).hexdigest()}

    class RequestPin:
        def __init__(self, native, pin):
            assert pin == record

        def digest(self, retain=False, maximum=None):
            return raw
    real_run = process_owner.Owner.run
    owner.run = lambda: real_run(owner)
    argv = ["program", "--request", record["path"], "--request-sha256", record["sha256"],
            "--request-pin-base64", base64.b64encode(json.dumps(record).encode()).decode()]
    output = io.StringIO()
    with mock.patch.object(process_owner, "absolute", Path), mock.patch.object(process_owner, "Native", lambda: object()), \
            mock.patch.object(process_owner, "Pin", RequestPin), mock.patch.object(process_owner, "Owner", lambda request, pin: owner), \
            mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
        try:
            result = process_owner.main()
        except Parked as error:
            result = error
    return result, output.getvalue()


class DispatchTests(unittest.TestCase):
    real_run = staticmethod(process_owner.Owner.run)

    def dispatch(self, action, behavior="positive"):
        owner = peer(action, behavior)
        with mock.patch.object(process_owner, "absolute", Path):
            return owner, self.real_run(owner)

    def test_each_action_loads_its_held_entry_sources_once(self):
        for action in task.POSTBOOT_ACTION_PHASES:
            with self.subTest(action=action):
                owner, result = self.dispatch(action)
                self.assertEqual(0, result)
                self.assertEqual(1, sum(row[0] == "action" for row in owner.trace))
                self.assertEqual(["sourceRoles", "postbootAction", "prebootAction"], [row[1] for row in owner.trace if row[0] == "module"])
                with mock.patch.object(process_owner, "absolute", Path), self.assertRaisesRegex(process_owner.Refused, "one-original-fixed-postboot-dispatch"):
                    self.real_run(owner)

    def test_a_drifted_entry_source_is_refused_before_any_module(self):
        owner = peer("windows-postboot-final")
        path = owner.request["postbootAcceptance"]["sourceRoles"]["prebootAction"]
        owner.by_path[str(path).casefold()].record["sha256"] = "0" * 64
        with mock.patch.object(process_owner, "absolute", Path), self.assertRaisesRegex(process_owner.Refused, "held-fixed-postboot-entry-source-prebootAction"):
            self.real_run(owner)
        self.assertEqual(["sourceRoles", "postbootAction"], [row[1] for row in owner.trace if row[0] == "module"])

    def test_the_table_names_the_four_current_entry_sources(self):
        for role, name in ENTRY.items():
            raw = (ROOT / "agent_tools" / name).read_bytes()
            self.assertEqual({"sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)}, process_owner._POSTBOOT_ENTRY_SOURCES[role])


class MainTests(unittest.TestCase):
    def test_a_returned_preboot_finishes_its_owner_and_prints_nothing(self):
        # The candidate parked here and could never finish: the app it leaves running is no child of the owner.
        for action in task.POSTBOOT_ACTION_PHASES:
            with self.subTest(action=action):
                owner = peer(action)
                result, output = run_main(owner)
                self.assertEqual((0, ""), (result, output))
                self.assertEqual([("finish", 0)], [row for row in owner.trace if row[0] in ("finish", "park")])

    def test_a_known_failure_finishes_with_exit_1_and_is_never_run_again(self):
        for action in task.POSTBOOT_ACTION_PHASES:
            with self.subTest(action=action):
                owner = peer(action, "known-failure")
                result, output = run_main(owner)
                self.assertEqual((1, ""), (result, output))
                self.assertEqual([("finish", 1)], [row for row in owner.trace if row[0] in ("finish", "park")])
                self.assertEqual(1, sum(row[0] == "action" for row in owner.trace))

    def test_an_unknown_effect_parks_before_anything_could_finish(self):
        # A real park never returns; this peer's raises, so what follows it here never runs on Windows.
        owner = peer("windows-preboot-reboot", "effect-unknown")
        run_main(owner)
        self.assertEqual(("park", "declared-effect-unknown"), [row for row in owner.trace if row[0] in ("finish", "park")][0])

    def test_a_live_child_still_parks_through_the_generic_rule(self):
        owner = peer("windows-postboot-final", "known-failure")
        owner.children.append(types.SimpleNamespace(terminal=None))
        result, _ = run_main(owner)
        self.assertIsInstance(result, Parked)
        self.assertEqual("scenario-failure-with-retained-child", str(result))


class SourceRoleTests(unittest.TestCase):
    def test_roles_scenarios_and_phases_are_closed(self):
        self.assertEqual(roles.ROLES, task.POSTBOOT_ROLES)
        self.assertEqual({phase: frozenset(values) for phase, values in roles.SCENARIOS.items()},
                         {task.POSTBOOT_ACTION_PHASES[action]: values for action, values in task.POSTBOOT_SCENARIOS.items()})
        config = plan("postboot-final")["postbootAcceptance"]
        roles.validate_config(copy.deepcopy(config))
        for change in (lambda c: c.update(scenario="query-first"), lambda c: c["sourceRoles"].update(powerShell=r"C:\Temp\powershell.exe"),
                       lambda c: c.update(rebootIntentPath=c["trafficInputPath"]),
                       lambda c: c["sourceRoles"].update(runtimeAuthority=c["trafficInputPath"])):
            value = copy.deepcopy(config)
            change(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                roles.validate_config(value)


if __name__ == "__main__":
    unittest.main()
