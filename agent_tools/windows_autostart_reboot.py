"""Finite Windows autostart stages; no import-time/native effects.

Uses an already admitted ordinary Owner. Nothing here reboots: readiness-reboot is
the only reboot submitter, between a preboot and a postboot operation. No
fabricated observation closes a case.
"""
from __future__ import annotations

import hashlib
import json
import ntpath
from pathlib import Path
import uuid
import xml.etree.ElementTree as ET

NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
TASK = "\\VPN Control"
SCENARIOS = {"reconnect", "explicit-off", "autostart-migration"}


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def wire(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def uuid_value(value):
    require(type(value) is str and str(uuid.UUID(value)) == value, "canonical-uuid")
    return value


def path_value(value):
    require(type(value) is str and ntpath.isabs(value) and not value.startswith("\\\\")
            and not any(c in value for c in '\x00\r\n"'), "local-exact-windows-path")
    return value


def command(gui, workspace):
    return f'"{path_value(gui)}" --autostart --state-dir "{path_value(workspace)}"'


def task_fields(xml):
    require(type(xml) is str and 0 < len(xml.encode()) <= 131072
            and "<!DOCTYPE" not in xml.upper() and "<!ENTITY" not in xml.upper(), "bounded-task-xml")
    root = ET.fromstring(xml)
    require(root.tag == "{" + NS + "}Task", "task-namespace")
    def children(name):
        return root.findall("t:" + name + "/*", {"t": NS})
    principals, actions, triggers = (children(name) for name in ("Principals", "Actions", "Triggers"))
    require(len(principals) == len(actions) == len(triggers) == 1
            and principals[0].tag == "{" + NS + "}Principal"
            and actions[0].tag == "{" + NS + "}Exec"
            and triggers[0].tag == "{" + NS + "}LogonTrigger", "one-exact-task-action-trigger")
    def text(node, field):
        elements = node.findall("t:" + field, {"t": NS})
        require(len(elements) <= 1, "duplicate-task-field")
        return "" if not elements else (elements[0].text or "")
    principal, action, trigger = principals[0], actions[0], triggers[0]
    return {"sid": text(principal, "UserId"), "logonType": text(principal, "LogonType"),
        "runLevel": text(principal, "RunLevel"), "command": text(action, "Command"),
        "arguments": text(action, "Arguments"), "workingDirectory": text(action, "WorkingDirectory"),
        "triggerSid": text(trigger, "UserId"), "triggerEnabled": text(trigger, "Enabled"),
        "actionsContext": root.find("t:Actions", {"t": NS}).get("Context", ""),
        "principalId": principal.get("id", "")}


def ownership(snapshot, gui, workspace, sid):
    require(snapshot["schemaVersion"] == 2 and snapshot["collector"] == "exact-autostart-read-only-v2"
            and snapshot["sid"] == sid and snapshot["elevated"] == 0, "ordinary-native-snapshot")
    task, run = snapshot["task"], snapshot["run"]
    require(run["state"] in {"present", "absent"}, "legacy-run-known-state")
    if run["state"] == "present":
        require(run["kind"] == "String" and run["value"].casefold() == command(gui, workspace).casefold(),
                "foreign-run-value-refused")
    require(task["state"] in {"present", "absent"}, "task-known-state")
    if task["state"] == "absent":
        return "absent"
    require(task["path"] == TASK and task["enabled"] is True and type(task["sddl"]) is str
            and 0 < len(task["sddl"]) <= 32768, "enabled-exact-task-security")
    fields = task_fields(task["xml"])
    require(fields["sid"] == sid and fields["logonType"] == "InteractiveToken"
            and ntpath.normcase(fields["command"]) == ntpath.normcase(path_value(gui))
            and fields["arguments"] == f'--autostart --state-dir "{path_value(workspace)}"'
            and fields["workingDirectory"] == "" and fields["triggerSid"] in {"", sid}
            and fields["triggerEnabled"] in {"", "true"}
            and fields["actionsContext"] == fields["principalId"] != "", "exact-owned-startup-task")
    # Exported XML omits RunLevel for the limited default; only HighestAvailable elevates.
    require(fields["runLevel"] in {"", "LeastPrivilege", "HighestAvailable"}, "task-run-level")
    return "highest" if fields["runLevel"] == "HighestAvailable" else "limited"


def public(owner, state, *arguments):
    owner.guard()
    output = owner.invoke(state["workspace"], "--json", "--controller-id", state["identity"], *arguments)
    require(output.returncode == 0 and output.stderr == "" and len(output.stdout.encode()) <= 1024 * 1024,
            "public-original-terminal-envelope-bound")
    value = json.loads(output.stdout)
    require(type(value) is dict and value["schemaVersion"] == 1 and value["code"] == "OK"
            and value["final"] is True and value["controllerId"] == state["identity"], "public-final-same-controller")
    owner.guard()
    return value


def held_path(owner, path):
    require(type(path) is str and str(Path(path)).casefold() in owner.by_path, "required-held-source-path")
    owner.by_path[str(Path(path)).casefold()].current()
    return path


def collect(owner, inputs):
    require(type(inputs) is dict and set(inputs) == {"schemaVersion", "snapshotScriptPath", "powerShellPath",
        "migrationScriptPath", "startScriptPath", "guiPath", "workspace"} and inputs["schemaVersion"] == 1
        and all(value is not None for value in inputs.values()), "autostart-inputs-unbound")
    require(inputs["workspace"] == owner.request["workspace"], "same-admitted-workspace")
    for key in ("snapshotScriptPath", "powerShellPath", "migrationScriptPath", "startScriptPath", "guiPath"):
        held_path(owner, inputs[key])
    owner.guard()
    child = owner.child("autostart-read-only", [inputs["powerShellPath"], "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-File", inputs["snapshotScriptPath"]])
    output = child.completed()
    require(output.returncode == 0 and output.stderr == "" and len(output.stdout.encode()) <= 262144,
            "snapshot-original-terminal-full-eof")
    value = json.loads(output.stdout)
    context = owner.request["context"]
    require(value["machineGuid"].casefold() == context["machineGuid"].casefold()
            and value["bootIdentifier"] == owner.native.boot_identifier() == context["bootIdentifier"]
            and value["sessionId"] == context["ordinarySessionId"]
            and value["pid"] == child.pid and str(value["creationFileTime"]) == str(child.birth),
            "snapshot-current-native-child-boot-token")
    value["qualifiedOwnership"] = ownership(value, inputs["guiPath"], inputs["workspace"], context["ordinarySid"])
    owner.guard()
    owner.event("autostart-native-snapshot", {"child": child.ordinal, "stdoutSha256": sha(output.stdout.encode()),
        "snapshot": value, "readOnly": True})
    return value


def toggle(owner, state, inputs, enabled):
    require(type(enabled) is bool, "finite-autostart-toggle")
    before = collect(owner, inputs)
    initial = public(owner, state, "status")
    owner.event("autostart-public-toggle-intent", {"enabled": enabled, "before": before, "replayAllowed": False})
    public(owner, state, "--if-revision", str(initial["configurationRevision"]), "settings", "set", "autostart",
           str(enabled).lower())
    after = collect(owner, inputs)
    require(after["qualifiedOwnership"] == ("limited" if enabled else "absent") and after["run"]["state"] == "absent"
            and before["machineGuid"] == after["machineGuid"] and before["bootIdentifier"] == after["bootIdentifier"],
            "actual-public-toggle-registration")
    if enabled and before["qualifiedOwnership"] == "highest":
        require(after["task"]["sddl"] == before["task"]["sddl"], "migration-preserves-entire-task-dacl")
        before_fields, after_fields = task_fields(before["task"]["xml"]), task_fields(after["task"]["xml"])
        before_fields["runLevel"] = after_fields["runLevel"]
        require(before_fields == after_fields, "migration-preserves-action-trigger-principal")
    owner.event("autostart-public-toggle-observed", {"before": before, "after": after})
    return after


def prepare_highest_fixture(owner, state, inputs):
    """Create an exact owned legacy task once, only after public OFF removes ours.

    The helper uses COM TASK_CREATE, never TASK_CREATE_OR_UPDATE. Existing or
    raced names refuse. A native error is preserved; no elevated workaround.
    """
    before = collect(owner, inputs)
    require(before["qualifiedOwnership"] == "absent" and before["run"]["state"] == "absent",
            "legacy-fixture-exact-absence-required")
    owner.event("autostart-highest-fixture-intent", {"before": before, "replayAllowed": False})
    child = owner.child("autostart-highest-fixture", [inputs["powerShellPath"], "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-File", inputs["migrationScriptPath"], "-GuiPath", inputs["guiPath"],
        "-Workspace", inputs["workspace"], "-ExpectedSid", owner.request["context"]["ordinarySid"]])
    output = child.completed()
    require(output.returncode == 0 and output.stderr == "" and len(output.stdout.encode()) <= 4096,
            "highest-fixture-original-child-terminal")
    created = json.loads(output.stdout)
    require(created == {"schemaVersion": 1, "taskPath": TASK, "runLevel": "HighestAvailable"},
            "highest-fixture-helper-result")
    after = collect(owner, inputs)
    require(after["qualifiedOwnership"] == "highest", "actual-legacy-highest-fixture-required")
    owner.event("autostart-highest-fixture-observed", {"before": before, "after": after, "child": child.ordinal})
    return after


def migration(owner, state, inputs):
    toggle(owner, state, inputs, False)
    before = prepare_highest_fixture(owner, state, inputs)
    # A read must leave the actual high task unchanged before explicit mutation.
    public(owner, state, "settings", "show")
    unchanged = collect(owner, inputs)
    require(unchanged["task"] == before["task"] and unchanged["run"] == before["run"],
            "ordinary-query-must-not-migrate-startup-task")
    after = toggle(owner, state, inputs, True)
    return {"before": before, "after": after, "acceptanceComplete": False}


def enable_from_absent(owner, state, inputs):
    """The plain public enable: no task before, an exact LeastPrivilege task after."""
    before = collect(owner, inputs)
    require(before["qualifiedOwnership"] == "absent" and before["run"]["state"] == "absent",
            "plain-enable-requires-exact-absence")
    return toggle(owner, state, inputs, True)


def closing_off(owner, state, inputs):
    """Public disable as the last autostart step: the task names this workspace and
    must not outlive it, or the next reboot scenario on this clone meets it first."""
    after = toggle(owner, state, inputs, False)
    owner.event("autostart-closing-off-observed", {"after": after})
    return after


def location_name(owner, state, status):
    """Location IDs are salted per owner, so a reboot compares the active name."""
    active = status["data"].get("activeLocationId")
    if active is None:
        return None
    listed = public(owner, state, "locations", "list")
    names = [row.get("name") for row in listed["data"]["locations"] if row.get("id") == active]
    require(len(names) == 1 and type(names[0]) is str and names[0], "one-named-active-location")
    return names[0]


def product_rows(actors):
    """The declared product generations a reboot may find running: exact facts only.

    A GUI or controller launcher that did not relaunch is its own JVM, so only a relaunched one adds its
    guiLauncher or controllerLauncher row. Always gui and controller, runtime only for reconnect: 2 to 5 rows,
    reconnect 3 to 5, explicit-off and autostart-migration 2 to 4.
    """
    rows = []
    for role in ("guiLauncher", "gui", "controllerLauncher", "controller", "runtime"):
        actor = actors.get(role)
        if actor is None:
            continue
        rows.append({"role": role, "pid": actor["pid"], "parentPid": actor["parentPid"],
                     "creationFileTime": str(actor["creationFileTime"]), "image": actor["image"],
                     "sha256": actor["sha256"], "sid": actor["sid"], "sessionId": actor["sessionId"]})
    require(len({row["pid"] for row in rows}) == len(rows) and {"gui", "controller"} <= {row["role"] for row in rows}
            and 2 <= len(rows) <= 5, "declared-product-tree-shape")
    return rows


def prepare_reboot_checkpoint(owner, inputs, scenario, status, actors, location):
    """After the product's own autostart start: what the new boot is compared with.

    The running app is no child of this owner; its exact generations are declared so
    the reviewed idle allowance can let readiness-reboot through with it running.
    """
    require(scenario in SCENARIOS, "finite-reboot-scenario")
    require(not hasattr(owner, "autostart_reboot_checkpoint"), "one-original-reboot-checkpoint")
    owner.autostart_reboot_checkpoint = None
    snapshot = collect(owner, inputs)
    require(snapshot["qualifiedOwnership"] == "limited" and snapshot["run"]["state"] == "absent",
            "limited-ordinary-autostart-before-reboot")
    running = scenario == "reconnect"
    require(status["code"] == "OK" and status["final"] is True and status["data"]["runtimeRunning"] is running,
            "actual-preboot-runtime-state")
    require((location is not None) is running, "named-active-location-only-when-connected")
    context = owner.request["context"]
    checkpoint = {"schemaVersion": 3, "kind": "owned-reboot-checkpoint", "operationId": owner.operation,
        "scenario": scenario, "machineGuid": snapshot["machineGuid"], "oldBootIdentifier": context["bootIdentifier"],
        "oldBootFileTimeUtc": context["bootFileTimeUtc"], "ordinarySid": context["ordinarySid"],
        "oldSessionId": context["ordinarySessionId"], "deploymentId": context["deploymentId"],
        "workspace": inputs["workspace"], "guiPath": inputs["guiPath"], "oldControllerId": status["controllerId"],
        "activeLocationName": location, "activeMode": status["data"].get("activeMode"), "task": snapshot["task"],
        "status": status, "declaredProduct": product_rows(actors), "replayAllowed": False}
    owner.autostart_reboot_checkpoint = checkpoint
    owner.event("reboot-checkpoint", checkpoint)
    return checkpoint


def qualify_new_boot(checkpoint, new_snapshot, new_owner, new_status, gui_actor, new_location):
    """Pure finite join; actual native owners/actors are collected outside this join.

    This returns an observation join, never complete native acceptance. It cannot
    certify input receipts or substitute for the retained post-boot owner guard.
    The kernel boot identifier names the boot entry and is the same on every boot of
    a clone, so only a later boot time proves a new boot.
    """
    context = new_owner["context"]
    require(checkpoint["kind"] == "owned-reboot-checkpoint" and new_snapshot["machineGuid"].casefold()
            == checkpoint["machineGuid"].casefold() == context["machineGuid"].casefold()
            and context["deploymentId"] == checkpoint["deploymentId"]
            and new_snapshot["bootIdentifier"] == context["bootIdentifier"]
            and int(context["bootFileTimeUtc"]) > int(checkpoint["oldBootFileTimeUtc"])
            and new_snapshot["sid"] == context["ordinarySid"] == checkpoint["ordinarySid"]
            and new_snapshot["sessionId"] == context["ordinarySessionId"]
            and new_owner["workspace"] == checkpoint["workspace"], "new-native-boot-context-changed-or-pending")
    require(new_snapshot["qualifiedOwnership"] == "limited" and new_snapshot["run"]["state"] == "absent"
            and new_snapshot["task"]["sddl"] == checkpoint["task"]["sddl"]
            and task_fields(new_snapshot["task"]["xml"]) == task_fields(checkpoint["task"]["xml"]),
            "same-ordinary-autostart-registration-after-reboot")
    require(new_status["code"] == "OK" and new_status["final"] is True
            and new_status["controllerId"] != checkpoint["oldControllerId"], "fresh-controller-after-real-boot")
    running = checkpoint["scenario"] == "reconnect"
    require(checkpoint["scenario"] in SCENARIOS and new_status["data"]["runtimeRunning"] is running,
            "reconnect-or-explicit-off-preserved")
    if running:
        require(new_location == checkpoint["activeLocationName"] and type(new_location) is str
                and new_status["data"]["activeMode"] == checkpoint["activeMode"],
                "remembered-actual-active-selection-after-reboot")
    require(gui_actor["sid"] == checkpoint["ordinarySid"] and gui_actor["sessionId"] == new_snapshot["sessionId"]
            and gui_actor["elevated"] == 0 and gui_actor["creationFileTime"] > int(context["bootFileTimeUtc"])
            and ntpath.normcase(gui_actor["image"]) == ntpath.normcase(checkpoint["guiPath"]),
            "ordinary-new-boot-gui-actor")
    return {"schemaVersion": 3, "kind": "new-boot-autostart-observation-join", "scenario": checkpoint["scenario"],
        "checkpointOperationId": checkpoint["operationId"], "newBootFileTimeUtc": context["bootFileTimeUtc"],
        "newControllerId": new_status["controllerId"], "acceptanceComplete": False,
        "requiredNativeRemainder": ["actual-tray-before-hidden-or-visible-fallback", "direct-then-matching-mcp"]}
