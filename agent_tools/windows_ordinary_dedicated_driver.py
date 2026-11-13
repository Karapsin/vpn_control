"""Closed DIRECT updater and six proxy-lifecycle dispatchers.

Reviewed bodies keep their own original serve and cleanup. No callable, source
selector, physical input or SYSTEM launcher is accepted from a caller.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path, PureWindowsPath
import re


CASE_SHA = {
    "windows-public-update": "17ecb2f41b42a3988f6905fe6a426935564a48e17e776efe7c3a9dbf4f668f5c",
    "windows-proxy-lifecycle": "9a965b3db065ca98bdfa8c63cccaa059e676cf53a49c6705cf648e0989a3f987",
}
CASE_NAME = {"windows-public-update": "windows_public_updater/update_cases.py",
             "windows-proxy-lifecycle": "windows_lifecycle_cases.py"}
UPDATE_MODULES = {
    "receipts": "5e2e406b82d4a446ab971f27918b3b0f110e67e3eb8cae971b0bfe4256aa71ec",
    "server": "507b8fe1e0c3ca8d8e327f0e49312f6040cfc6577154341dbcc3a21badc86c0e",
    "fixture_environment": "0a36302028c3dc2605887a73abcd2850afcbaec302e28f2087a303926681b323",
    "macos_packaging_jdk_preflight": "3e4aa0524cb916c343ce377cb6ca5ab00674d0f6e6981f82ae514f80136cbca5",
    "prepare_desktop_update_fixture": "8612730c46fff65aad2ee101edf86f7f4afc93550e9eb1340c88fffb5acc175b",
    "broker_observer": "6d08edf9e57b09e98ce80d414b2ac12da4f39eb82e27cd2a3f06d9f900e04dcb",
    "lifecycle": CASE_SHA["windows-proxy-lifecycle"],
    "collector": "5a38ac02dd120d755a1d7bff25d8d0cd5fbf438c5fb52e57db15c45e335807a2",
}
RUNTIME_SHA = "0b6b6c7c4c261a8996c140661b7631fb234115ed215e3d3a4a72fd60e25e676e"
FIXTURE_WORKER_SHA = "cc30090de39143e260ad1b5e33aea4c5da0de8557118ec1c3b323ccf14b52c7a"
SOCKS_SHA = "50239b25bb1c63e7c86baaea8683f188426e87d6a1c6090b505c38d567e70210"
HTTPS_SHA = "e62f262d9703eb63c0eeca9b823eaae9d1a5780aefdedadf8aebe211492651d4"
TRAFFIC_SHA = "c37423c7627e6972eff2b7d717904f9b07fdaeb5b1d880d1606559b58d2e2e2d"
CALLER_SHA = "51a165023d867b7097cb75675f7a938ad683a0c188c88388a7ac0f5b16d851d1"
PROTOCOL_SHA = "b0e197fc68b077d5ea3a0f55338249b7b9a02e53d6f1da689367cbd1bf4f9335"
CONTRACT_SHA = "a00dd01e2515f23b11d4eb21cafc67e2c45a20a4043e261d66a52845802620eb"
SYSTEM_WORKER_SHA = "323e2550b7efa53f93382efa366cfcf4cbf9e870b34a6578447b68128b2327fc"
NO_SYSTEM = frozenset({"public-ready", "download-cancelled", "checksum-rejected"})
FINAL_TERMINAL = frozenset({"uac-denied", "install-cancelled"})
FINAL_RETURNED = frozenset({"participating-copy-lock", "native-install-failed", "success-off",
    "success-reconnect", "different-admin", "wait-client-loss", "installer-wait-client-loss"})
PROXY_VARIANTS = frozenset({"gui-pending", "find-best-success",
    "find-best-verification-failure", "find-best-cancel"})
CONFIG_VARIANTS = frozenset({"generated", "custom", "large"})
FAILURE_VARIANTS = frozenset({"prepare-failure", "commit-readiness-failure"})
BRANCH_VARIANTS = CONFIG_VARIANTS | FAILURE_VARIANTS | {"sibling-off"}
# restart-grant waits for the collector stage: an approved grant ends only with its native ready record.
TUN_VARIANTS = frozenset({"restart-deny"})
TUN_SHA = "8eabdd41e8b98e55166d43541b09a3ec3a4c85d8e421b9e7195875b68f50b65d"
SAMPLER_SHA = "c1caaac8cbb29c415c1a1bf6ba098716062ccb1978c01ae4a17934bc55597433"  # A grant's direct TUN sampler
BRANCH_SHA = "a3292caa396c3efe4e8c8d44d989615c98bbb9e0418d12487964bf17c9b6601e"
LISTENER_SHA = "1b62f857e627770be43057749f527128f573b89885590310ad51d95443c0b928"
# The owner's own scheduled refresh with no GUI (windows_lifecycle_scheduled_cases), sampled by the same traffic worker.
SCHEDULED_VARIANTS = frozenset({"scheduled-refresh"})
SCHEDULED_SHA = "25aa7f14fdf5928006bf95a3f3fc8cd07e6c6d460ebbe2b44ac7b84fbb3877c2"
SCHEDULED_FIELDS = frozenset({"schemaVersion", "guiPath", "trafficWorkerPath", "trafficInputPath", "installedAdmissionArtifactId",
                              "fixtureAdmissionArtifactId"})
# The GUI attached on an owned desktop with no notification area and closed once (windows_no_tray_desktop, DESKTOP-002),
# sampled by the same traffic worker; its inputs are the scheduled row's fields.
NO_TRAY_VARIANTS = frozenset({"no-tray-close"})
NO_TRAY_SHA = "89b560bd8be11c4098a627fce00bf9a9f2ecb7a8298c80b2ddcc90bf1970b030"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def held_source(owner, path, expected=None, maximum=1024 * 1024):
    require(type(path) is str, "dedicated-source-path-type")
    pin = owner.by_path[str(PureWindowsPath(path)).casefold()]
    require(not pin.directory and type(pin.record["nativeIdentity"]["sizeBytes"]) is int
            and 0 < pin.record["nativeIdentity"]["sizeBytes"] <= maximum,
            "dedicated-source-opening-bound")
    if expected is not None:
        require(pin.record["sha256"] == expected, "dedicated-reviewed-source-pin")
    raw = pin.digest(True, maximum)
    require(type(raw) is bytes and len(raw) == pin.record["nativeIdentity"]["sizeBytes"]
            and hashlib.sha256(raw).hexdigest() == pin.record["sha256"],
            "dedicated-held-source-bytes")
    return raw


def module_roles(owner, paths, expected):
    require(type(paths) is dict and set(paths) == set(expected), "dedicated-module-role-schema")
    normalized = [str(PureWindowsPath(value)).casefold() for value in paths.values()
                  if type(value) is str]
    require(len(normalized) == len(paths) and len(set(normalized)) == len(paths),
            "dedicated-distinct-source-roles")
    for role, source_sha in expected.items():
        held_source(owner, paths[role], source_sha)


def literal_harness(owner, action):
    """Keep the existing held module API, after rejecting executable harnesses."""
    names = {"SYSTEM_COLLECTOR_CLOSE_HOLD", "UPDATE_INPUTS" if action == "windows-public-update"
             else "LIFECYCLE_INPUTS"}
    raw = held_source(owner, owner.request["harnessPath"], maximum=8 * 1024 * 1024)
    tree = ast.parse(raw.decode("utf-8", "strict"))
    constants = {}
    for number, node in enumerate(tree.body):
        if number == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) \
                and type(node.value.value) is str:
            continue
        require(isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name), "dedicated-literal-harness-only")
        name = node.targets[0].id
        require(name in names and name not in constants, "dedicated-closed-harness-constants")
        constants[name] = ast.literal_eval(node.value)
    require(set(constants) == names, "dedicated-complete-harness-constants")
    harness = owner.module(owner.request["harnessPath"], "_owned_dedicated_literal_harness")
    require(all(getattr(harness, name) == value for name, value in constants.items()),
            "dedicated-same-held-literal-harness")
    return harness


def update_hold(owner, inputs, hold_inputs):
    variant = inputs["variant"]
    if variant in NO_SYSTEM or variant == "protected-storage-rejected":
        require(hold_inputs is None, "dedicated-no-final-system-collector")
        return None
    require(variant in FINAL_TERMINAL | FINAL_RETURNED, "dedicated-update-variant-not-enabled")
    stage = "terminal-actors" if variant in FINAL_TERMINAL else "returned-cleanup"
    root = PureWindowsPath(__file__).parent / "windows_system_collector"
    protocol_path, caller_path = str(root / "hold_protocol.py"), str(root / "caller_hold.py")
    held_source(owner, protocol_path, PROTOCOL_SHA)
    held_source(owner, caller_path, CALLER_SHA)
    protocol = owner.module(protocol_path, "_owned_dedicated_hold_protocol")
    protocol.validate_inputs(hold_inputs, ordinary_task_operation_id=owner.operation)
    require(hold_inputs["scope"] == "update" and hold_inputs["stage"] == stage
            and hold_inputs["sourceSha"] == inputs["sourceSha"]
            and hold_inputs["systemContractSourceSha256"] == CONTRACT_SHA
            and hold_inputs["systemWorkerSourceSha256"] == SYSTEM_WORKER_SHA
            and hold_inputs["collectorSourceSha256"] == UPDATE_MODULES["collector"]
            and hold_inputs["receiptsPath"] == inputs["modules"]["receipts"],
            "dedicated-exact-final-update-collector-binding")
    caller = owner.module(caller_path, "_owned_dedicated_caller_hold")
    return caller.CallerCollectionHold(owner, hold_inputs)


def run_update(owner, cases, harness):
    inputs = harness.UPDATE_INPUTS
    require(type(inputs) is dict and type(inputs.get("schemaVersion")) is int
            and inputs["schemaVersion"] == 1, "dedicated-update-schema-version")
    # The reviewed validator refuses transport-loss before any scenario effect.
    cases.validate_inputs(owner, inputs)
    module_roles(owner, inputs["modules"], UPDATE_MODULES)
    app = PureWindowsPath(inputs["installedRoot"])
    internal = [PureWindowsPath(__file__)]
    if inputs["variant"] in FINAL_TERMINAL | FINAL_RETURNED:
        internal += [PureWindowsPath(__file__).parent / "windows_system_collector" / name
                     for name in ("caller_hold.py", "hold_protocol.py")]
    require(all(value != app and app not in value.parents and value not in app.parents
                for value in internal), "dedicated-driver-and-hold-outside-retiring-app-role")
    hold = update_hold(owner, inputs, harness.SYSTEM_COLLECTOR_CLOSE_HOLD)
    try:
        result = cases.run_update(owner, harness.__dict__)
    except BaseException as error:
        if hold is not None:
            owner.park("dedicated-case-failure-with-original-collector-hold", error)
        raise
    # The counterfeit storage root stays on the clone, so this variant parks however its prompt ended.
    if inputs["variant"] == "protected-storage-rejected":
        owner.park("protected-storage-scenario-cannot-return-known-success")
    cancelled = getattr(owner, "update_cancelled_grant", None)
    if type(result) is int and result == 1 and cancelled is not None and cancelled.get("variant") == inputs["variant"]:
        # The case closed everything it started and proved no handoff. No collector was asked to hold this
        # owner, so its armed hold retires here; waiting for a release would park the clone over a known failure.
        if hold is not None:
            if getattr(owner, "caller_collection_hold", None) is not hold or hold.state != "armed":
                owner.park("dedicated-original-caller-hold-replaced")
            owner.retired_collection_hold = hold
            owner.caller_collection_hold = None
        owner.event("dedicated-update-grant-cancelled-known", {**cancelled, "holdRetired": hold is not None, "replayAllowed": False})
        return 1
    if hold is not None:
        if getattr(owner, "caller_collection_hold", None) is not hold:
            owner.park("dedicated-original-caller-hold-replaced")
        hold.driver_completed(result)
        hold.wait_for_release()
        if hold.state != "released":
            owner.park("dedicated-original-collector-release-required")
    require(type(result) is int and result == 0, "dedicated-known-driver-result-zero")
    return result


def gui_sibling_inputs(owner, inputs, runtime_inputs, tag):
    """A scheduled or no-tray row's own inputs: the installed GUI beside the CLI, the held traffic worker and its input."""
    require(type(inputs) is dict and set(inputs) == SCHEDULED_FIELDS and type(inputs["schemaVersion"]) is int
            and inputs["schemaVersion"] == 1 and all(type(inputs[name]) is str and inputs[name] for name in SCHEDULED_FIELDS - {"schemaVersion"}),
            "dedicated-" + tag + "-input-fields")
    require(inputs["installedAdmissionArtifactId"] == runtime_inputs["installedAdmissionArtifactId"],
            "dedicated-" + tag + "-same-admission-references")
    held_source(owner, inputs["trafficWorkerPath"], TRAFFIC_SHA)
    # The GUI is the installed launcher's own sibling, held like the rest of the tree.
    gui_path = PureWindowsPath(inputs["guiPath"])
    require(gui_path.name.casefold() == "vpn-control.exe" and gui_path.parent == PureWindowsPath(owner.request["cliPath"]).parent,
            "dedicated-" + tag + "-installed-gui-role")
    for name in ("guiPath", "trafficInputPath"):
        key = str(PureWindowsPath(inputs[name])).casefold()
        require(key in owner.by_path and not owner.by_path[key].directory, "dedicated-" + tag + "-pinned-input")


def lifecycle_inputs(owner, value):
    fields = {"schemaVersion", "variant", "sourceSha", "modules", "runtime", "gui"}
    require(type(value) is dict and type(value.get("variant")) is str
            and (value["variant"] in PROXY_VARIANTS | BRANCH_VARIANTS | SCHEDULED_VARIANTS | NO_TRAY_VARIANTS
                 or value["variant"] in TUN_VARIANTS and "tun" in value),
            "dedicated-finite-proxy-variants-only")
    branch = value["variant"] in BRANCH_VARIANTS
    tun = value["variant"] in TUN_VARIANTS
    scheduled = value["variant"] in SCHEDULED_VARIANTS
    no_tray = value["variant"] in NO_TRAY_VARIANTS
    extra = {"branch"} if branch else {"tun"} if tun else {"scheduled"} if scheduled else {"noTray"} if no_tray else set()
    require(set(value) == fields | extra and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1,
            "dedicated-proxy-input-schema")
    # The stages pick restart or find-best, deny or grant, from their own inputs: they must name this variant.
    require(not tun or type(value["tun"]) is dict and value["tun"].get("variant") == value["variant"],
            "dedicated-tun-variant-binding")
    require(type(value["sourceSha"]) is str and re.fullmatch("[a-f0-9]{40}", value["sourceSha"]),
            "dedicated-lifecycle-source-sha")
    roles = {"runtime": RUNTIME_SHA, "observer": UPDATE_MODULES["broker_observer"]}
    if branch:
        roles["branches"] = BRANCH_SHA
    if tun:
        roles["tun"] = TUN_SHA
    if scheduled:
        roles["scheduled"] = SCHEDULED_SHA
    if no_tray:
        roles["noTray"] = NO_TRAY_SHA
    module_roles(owner, value["modules"], roles)
    runtime_inputs = value["runtime"]
    require(type(runtime_inputs) is dict and type(runtime_inputs.get("schemaVersion")) is int
            and runtime_inputs["schemaVersion"] == 1
            and runtime_inputs.get("operationId") == owner.operation,
            "dedicated-original-runtime-operation")
    if tun:
        # The stages check the rest; these name the same install, context and product config as the runtime's.
        require(value["tun"].get("installedAdmissionArtifactId") == runtime_inputs.get("installedAdmissionArtifactId")
                and value["tun"].get("ordinaryContextArtifactId") == runtime_inputs.get("ordinaryContextArtifactId")
                and type(runtime_inputs.get("workspace")) is str
                and value["tun"].get("runtimeConfigPath") == str(PureWindowsPath(runtime_inputs["workspace"]) / "runtime-config.json"),
                "dedicated-tun-same-admission-references")
        if value["variant"].endswith("grant"):
            # A grant's sampler runs under the pinned interpreter: the reviewed bytes, the bundle's own beside this driver.
            sampler = value["tun"].get("samplerPath")
            require(type(sampler) is str and PureWindowsPath(sampler) == PureWindowsPath(__file__).parent / "windows_tun_direct_sampler.py",
                    "dedicated-tun-sampler-role")
            held_source(owner, sampler, SAMPLER_SHA)
    for key, sha in (("fixtureWorkerPath", FIXTURE_WORKER_SHA), ("socksSourcePath", SOCKS_SHA),
                     ("httpsSourcePath", HTTPS_SHA)):
        held_source(owner, runtime_inputs[key], sha)
    gui = value["gui"]
    if value["variant"] == "gui-pending":
        fields = {"schemaVersion", "guiPath", "trafficWorkerPath", "trafficInputPath",
            "installedAdmissionArtifactId", "fixtureAdmissionArtifactId", "sourceArtifactId",
            "frontendCrashScenario", "trayAdmissionArtifactId"}
        require(type(gui) is dict and set(gui) == fields and type(gui["schemaVersion"]) is int
                and gui["schemaVersion"] == 1 and all(gui[name] is not None for name in fields)
                and gui["installedAdmissionArtifactId"] == runtime_inputs["installedAdmissionArtifactId"]
                and gui["frontendCrashScenario"] == "exact-owned-original-gui-handle",
                "dedicated-gui-admission-inputs")
        held_source(owner, gui["trafficWorkerPath"], TRAFFIC_SHA)
        for name in ("guiPath", "trafficInputPath"):
            require(str(PureWindowsPath(gui[name])).casefold() in owner.by_path,
                    "dedicated-pinned-gui-input")
    else:
        require(gui is None, "dedicated-find-best-has-no-gui-input")
    if scheduled:
        gui_sibling_inputs(owner, value["scheduled"], runtime_inputs, "scheduled")
    if no_tray:
        gui_sibling_inputs(owner, value["noTray"], runtime_inputs, "no-tray")
    if branch:
        inputs = value["branch"]
        names = {"schemaVersion", "fixtureRuntimeToolPath", "runtimeSha256", "listenerScriptPath",
            "powerShellPath", "trafficWorkerPath", "trafficInputPath",
            "installedAdmissionArtifactId", "ordinaryContextArtifactId"}
        require(type(inputs) is dict and set(inputs) == names
                and type(inputs["schemaVersion"]) is int and inputs["schemaVersion"] == 1
                and all(type(inputs[name]) is str and inputs[name] for name in names - {"schemaVersion"}),
                "dedicated-runtime-nine-field-inputs")
        require(inputs["installedAdmissionArtifactId"] == runtime_inputs["installedAdmissionArtifactId"]
                and inputs["ordinaryContextArtifactId"] == runtime_inputs["ordinaryContextArtifactId"],
                "dedicated-runtime-same-admission-references")
        require(inputs["powerShellPath"] == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                and owner.raw_limit >= 8 * 1024 * 1024, "dedicated-runtime-program-and-capture-policy")
        held_source(owner, inputs["listenerScriptPath"], LISTENER_SHA)
        held_source(owner, inputs["trafficWorkerPath"], TRAFFIC_SHA)
        for name in ("fixtureRuntimeToolPath", "powerShellPath", "trafficInputPath"):
            key = str(PureWindowsPath(inputs[name])).casefold()
            require(key in owner.by_path and not owner.by_path[key].directory,
                    "dedicated-runtime-held-program-or-data")
        tool = owner.by_path[str(PureWindowsPath(inputs["fixtureRuntimeToolPath"])).casefold()]
        require(re.fullmatch("[a-f0-9]{64}", inputs["runtimeSha256"])
                and inputs["runtimeSha256"] == runtime_inputs["runtimeSha256"] == tool.record["sha256"]
                and PureWindowsPath(inputs["fixtureRuntimeToolPath"]).name.casefold() == "sing-box.exe",
                "dedicated-runtime-bundled-tool-hash")
    return value


def installed_version(owner):
    """The installed launcher's --help and --version under this ordinary token, before any product state.

    The owner's own static probe, which its dedicated route does not reach. The host job
    claims installed-package only for a passed row, so a launcher that reports another
    version ends the row 1 before its runtime starts.
    """
    workspace = Path(owner.request["workspace"])
    for label, argv, text in (("help", ["--help"], "Usage:"),
                              ("version", ["--version"], owner.request["productVersion"])):
        value = owner.child(label, [owner.request["cliPath"], "--state-dir", str(workspace), *argv]).completed()
        require(value.returncode == 0 and value.stderr == "" and text in value.stdout,
                "dedicated-static-public-launcher-probe")
    require(not workspace.exists(), "dedicated-static-launch-created-owner-state")


def tun_census(owner, tun, lease, observer):
    """A TUN row's closing census after its own off. Anything scoped left behind parks with everything else kept."""
    try:
        tun.closing(owner, lease, observer)
    except AssertionError as error:
        owner.park("dedicated-tun-scoped-state-left-behind", error)


def known_failure(owner, cases, runtime, branches, observer, state, inputs, error, census=None):
    """A reviewed oracle failed after its own public call returned, so the outcome is known.

    The row closes what it started by the same public steps as a pass and ends 1. The
    failed oracle never runs again and no step is replayed over an unknown outcome, but
    the closing issues its own off while status shows the runtime running and its own
    quit: an off that left the runtime running, or a quit that was refused, is issued
    once more. A fixture that already ended keeps its own terminal. A child whose
    outcome is still open, or any closing step that does not end as it must, parks.
    A TUN row's census reads right after the off, as in a pass, before anything else closes.
    """
    workspace, identity = state["workspace"], state["identity"]
    reason = str(error)[:120]
    sibling = getattr(owner, "runtime_case_sibling", None)
    retained = [state["serve"], state["fixture"], *(() if sibling is None else (sibling["child"],))]
    for child in owner.children:
        if child.terminal is not None or child.label == "lifecycle-gui" or any(child is held for held in retained):
            continue
        if child.label != "lifecycle-traffic":
            owner.park("dedicated-known-failure-child-outcome-open", error)
        child.wait()  # A finite sampler: every sample has its own I/O bound, and its terminal is evidence.
    if sibling is not None and sibling["child"] is not None and sibling["child"].terminal is None and sibling["stopAttempted"]:
        owner.park("dedicated-known-failure-sibling-stop-open", error)
    owner.event("dedicated-proxy-lifecycle-known-failure-closing", {"variant": inputs["variant"], "reason": reason,
        "controllerId": identity, "replayAllowed": False})
    if cases.read(owner, workspace, identity, "status")["data"]["runtimeRunning"] is True:
        cases.read(owner, workspace, identity, "off")
        require(cases.read(owner, workspace, identity, "status")["data"]["runtimeRunning"] is False,
                "dedicated-known-failure-product-off")
    if census is not None:
        census()
    if sibling is not None and sibling["child"] is not None and sibling["child"].terminal is None:
        branches.close_sibling(owner, state, inputs["branch"], runtime, observer, sibling)
    # A sibling that never started leaves only file handles, which close with this process.
    if branches is not None and (sibling is None or sibling["child"] is not None):
        branches.close_fixture_files_after_off(owner, state, runtime)
    fixture = state["fixture"]
    if fixture.terminal is None and fixture.process.poll() is None:
        try:
            runtime.stop_fixture(owner, state)
        except AssertionError:
            # Only the fixture's own nonzero terminal excuses this: its lease ended as the stop went out.
            if fixture.terminal is None or fixture.terminal["exitCode"] == 0:
                raise
    # A fixture that ended by itself (its 1,800 s lease, or the fault the oracle saw) is no open outcome.
    fixture_terminal = fixture.wait()
    require(all(fixture_terminal["eof"].values()), "dedicated-known-failure-fixture-terminal")
    for lease in reversed(getattr(owner, "fixture_data_leases", [])):
        if lease.handle is not None:
            lease.close()
    cases.read(owner, workspace, identity, "quit")
    for child in [state["serve"], *(child for child in owner.children if child.label == "lifecycle-gui")]:
        terminal = child.wait()
        expected = cases.CRASH_EXIT if getattr(child, "_lifecycle_crash_attempted", False) is True else 0
        require(terminal["exitCode"] == expected and terminal["eof"] == {"stdout": True, "stderr": True},
                "dedicated-known-failure-terminal-and-eof")
    require(all(type(child.terminal) is dict for child in owner.children), "dedicated-known-failure-all-children-terminal")
    # An owned desktop closes once its GUI is terminal; the row never switches the input desktop to it.
    for lease in reversed(getattr(owner, "no_tray_desktop_leases", [])):
        if lease.handle is not None:
            lease.close()
    require(not (workspace / "activation.port").exists(), "dedicated-known-failure-endpoint-released")
    owner.event("dedicated-proxy-lifecycle-known-failure", {"variant": inputs["variant"], "reason": reason,
        "controllerId": identity, "sourceSha": inputs["sourceSha"], "fixtureExitCode": fixture_terminal["exitCode"],
        "closed": True, "replayAllowed": False, "nativeAcceptanceComplete": False})
    return 1


def run_lifecycle(owner, cases, harness):
    require(harness.SYSTEM_COLLECTOR_CLOSE_HOLD is None, "proxy-has-no-system-collector")
    inputs = lifecycle_inputs(owner, harness.LIFECYCLE_INPUTS)
    runtime = owner.module(inputs["modules"]["runtime"], "_owned_dedicated_runtime_stages")
    observer = owner.module(inputs["modules"]["observer"], "_owned_dedicated_proxy_observer")
    branches = None
    if inputs["variant"] in BRANCH_VARIANTS:
        branches = owner.module(inputs["modules"]["branches"], "_owned_dedicated_runtime_branches")
    runtime.validate_inputs(owner, inputs["runtime"])
    installed_version(owner)
    try:
        state = runtime.start_runtime(owner, inputs["runtime"], observer)
    except AssertionError as error:
        # Once its serve answered as a controller, the start kept what the closing needs: a reviewed
        # oracle that failed there is closed like a later one. No TUN stage has begun, so a TUN row
        # has no prompt or broker yet and closes the same way. Before that it still parks.
        started = getattr(owner, "runtime_start_state", None)
        if started is None:
            raise
        return known_failure(owner, cases, runtime, branches, observer, started, inputs, error)
    workspace, identity = state["workspace"], state["identity"]
    tun = lease = None
    outcome = {}
    try:
        if inputs["variant"] in TUN_VARIANTS:
            # The deny row has no collector: active A must survive the prompt unchanged.
            tun = owner.module(inputs["modules"]["tun"], "_owned_dedicated_tun_stages")
            lease = tun.begin(owner, state, inputs["tun"], runtime, cases, observer)
            outcome = tun.finish(owner, lease, runtime, cases, observer)
            actors = state["actors"]
        elif inputs["variant"] == "gui-pending":
            gui = dict(inputs["gui"], stateDir=str(workspace), controllerId=identity,
                observerPath=inputs["modules"]["observer"], runtimeConfigPath=str(workspace / "runtime-config.json"),
                ownerActor=state["actors"]["owner"], runtimeActor=state["actors"]["runtime"],
                fixtureSocksPort=state["ready"]["advertisedSocksPort"], runtimeArtifact=state["runtimeArtifact"])
            cases.gui_continuity(owner, workspace, identity, gui)
            cases.pending_selection(owner, workspace, identity, {"active": "Owned A", "pending": "Owned B"},
                str(workspace / "runtime-config.json"), observer.WindowsNative(),
                state["actors"]["owner"], state["actors"]["runtime"])
            actors = state["actors"]
        elif inputs["variant"] in SCHEDULED_VARIANTS:
            # Proxy A goes off, an owned subscription's location runs instead, and its scheduled refresh is observed
            # with no GUI; the runtime it leaves is the one this row's own explicit off below stops.
            scheduled = owner.module(inputs["modules"]["scheduled"], "_owned_dedicated_scheduled_cases")
            actors = scheduled.run(owner, state, inputs["scheduled"], runtime, cases, observer)["actors"]
        elif inputs["variant"] in NO_TRAY_VARIANTS:
            # The GUI attaches on an owned desktop with no notification area and one WM_CLOSE must detach it (DESKTOP-002);
            # the runtime that keeps serving is the one this row's own explicit off below stops.
            desktop = owner.module(inputs["modules"]["noTray"], "_owned_dedicated_no_tray_desktop")
            actors = desktop.no_tray_close_case(owner, state, inputs["noTray"], runtime, cases, observer)["actors"]
        elif inputs["variant"] in BRANCH_VARIANTS:
            if inputs["variant"] in CONFIG_VARIANTS:
                branches.config_case(owner, state, inputs["branch"], runtime, cases, observer, inputs["variant"])
            elif inputs["variant"] in FAILURE_VARIANTS:
                branches.failure_case(owner, state, inputs["branch"], runtime, cases, observer, inputs["variant"])
            else:
                sibling = branches.start_sibling(owner, state, inputs["branch"], runtime, observer)
                branches.off_with_sibling_survivor(owner, state, inputs["branch"], runtime, cases, observer, sibling)
                branches.close_sibling(owner, state, inputs["branch"], runtime, observer, sibling)
            if inputs["variant"] != "sibling-off":
                actors = runtime.capture_proxy_actors(owner, state["serve"], observer.WindowsNative(),
                    inputs["runtime"]["runtimeImagePath"], inputs["runtime"]["runtimeSha256"])
                cases.off_proxy_and_disconnected_serve(owner, workspace, identity, observer,
                    actors["owner"], actors["runtime"])
            branches.close_fixture_files_after_off(owner, state, runtime)
        else:
            runtime.find_best(owner, state, inputs["variant"].removeprefix("find-best-"))
            actors = runtime.capture_proxy_actors(owner, state["serve"], observer.WindowsNative(),
                inputs["runtime"]["runtimeImagePath"], inputs["runtime"]["runtimeSha256"])
        if inputs["variant"] not in BRANCH_VARIANTS:
            cases.off_proxy_and_disconnected_serve(owner, workspace, identity, observer,
                actors["owner"], actors["runtime"])
        if tun is not None:
            tun_census(owner, tun, lease, observer)  # No broker, scoped runtime, private stage or TUN route is left.
        runtime.stop_fixture(owner, state)
        cases.read(owner, workspace, identity, "quit")
    except AssertionError as error:
        # From a TUN row's request until its stages show the operation settled, its operation, prompt and broker are
        # theirs to close: it parks. A refusal before the request, a final refusal of the request itself, or a failure
        # once settled left only the row's proxy, which closes like any other; once settled, its census follows the off.
        if inputs["variant"] in TUN_VARIANTS and getattr(owner, "tun_operation_requested", False) \
                and (lease is None or not tun.settled(lease)):
            raise
        census = None if lease is None or lease.get("closed") else lambda: tun_census(owner, tun, lease, observer)
        return known_failure(owner, cases, runtime, branches, observer, state, inputs, error, census)
    originals = [state["serve"], *(child for child in owner.children if child.label == "lifecycle-gui")]
    for child in originals:
        terminal = child.wait()
        expected = cases.CRASH_EXIT if getattr(child, "_lifecycle_crash_attempted", False) is True else 0
        require(terminal["exitCode"] == expected and terminal["eof"] == {"stdout": True, "stderr": True},
                "dedicated-original-lifecycle-terminal-and-eof")
    if inputs["variant"] in BRANCH_VARIANTS:
        require(all(type(child.terminal) is dict and child.terminal.get("eof") == {"stdout": True, "stderr": True}
                    for child in owner.children), "dedicated-runtime-all-original-child-eof")
    require(not (workspace / "activation.port").exists(), "dedicated-original-endpoint-released")
    # A TUN outcome the stages proved known but not the variant's own (a cancelled grant, a refused preparation)
    # closed by the same steps as a pass and ends 1.
    known = outcome.get("knownFailure") or ("cancelled" if outcome.get("cancelled") else None)
    owner.event("dedicated-proxy-lifecycle-known-closed", {"variant": inputs["variant"],
        "controllerId": identity, "sourceSha": inputs["sourceSha"], "nativeAcceptanceComplete": False,
        **({"knownFailure": known} if known else {})})
    return 1 if known else 0


def run(owner, action):
    require(action in CASE_SHA, "dedicated-fixed-action")
    root = PureWindowsPath(__file__).parent
    require(PureWindowsPath(owner.request["casesPath"]) == root / CASE_NAME[action],
            "dedicated-fixed-case-source-role")
    held_source(owner, owner.request["casesPath"], CASE_SHA[action])
    harness = literal_harness(owner, action)
    cases = owner.module(owner.request["casesPath"], "_owned_dedicated_reviewed_cases")
    owner.guard()
    return run_update(owner, cases, harness) if action == "windows-public-update" else run_lifecycle(owner, cases, harness)
