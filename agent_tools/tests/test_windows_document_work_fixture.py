"""The responsive row's work fixture: a start that says where it is, and an owner that ends it and knows.

Native run b9aa4616 (2026-11-13, windows-document-responsive) parked 30 s after the fixture child
started: no ready file, nothing on its stdout or stderr, the child alive. The unfixed fixture kept
any failure of its start to itself and slept, and the unfixed cases could only park.

Local only. The fixture's main runs in this process over a declared peer of its two producer
sources: no socket, listener or TLS. The cases run over the real Child and real pipes with a
declared process peer, as test_windows_document_responsive does, and over the real read_ready of
the runtime stages, whose 30 s run on a scaled clock. Each behavior is run on the exact unfixed
bytes (the before-images beside this module) and on the fix.
"""
from __future__ import annotations
import contextlib, hashlib, io, json, os, tempfile, threading, time as real_time, types, unittest, uuid
from pathlib import Path
from unittest import mock

from agent_tools import windows_document_gated_https_fixture as gated
from agent_tools import windows_document_native as native_module
from agent_tools import windows_document_responsive_cases as cases
from agent_tools import windows_document_responsive_cli_cases as cli
from agent_tools import windows_lifecycle_runtime_stages as stages
from agent_tools import windows_ordinary_process_owner as ordinary
from agent_tools.tests import test_windows_document_responsive as responsive

FIXTURES = Path(__file__).with_name("fixtures") / "windows_document_work_fixture"
GATED_SHA256 = "205a1bdd79fa3c2d0df3d3f3cf4746132ed78d09500d4947a4ab6bb177f63e9c"
CASES_SHA256 = "750bf3925e867c7560fd869ce523b9fd95ca7d7d51de451bb208b771ae8995a5"
CLI_SHA256 = "f02bd180210568a7219f33bd22e7c72d8fde5dbab560ce2b6a5803de21338705"
STEPS = ("input", "sources", "tls-context", "https-listen", "relay-listen", "listening", "certificate-digest",
         "ready-create", "ready-rename")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def module_of(name, raw, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def before_gated():
    raw = (FIXTURES / "gated-fixture-silent-start.before.source").read_bytes()
    assert sha(raw) == GATED_SHA256
    return module_of("gated_before", raw, FIXTURES / "gated-fixture-silent-start.before.source")


def before_cases():
    raw = (FIXTURES / "responsive-cases-readiness-park.before.source").read_bytes()
    assert sha(raw) == CASES_SHA256
    return module_of("responsive_cases_before", raw, FIXTURES / "responsive-cases-readiness-park.before.source")


def before_cli():
    raw = (FIXTURES / "responsive-cli-no-closing.before.source").read_bytes()
    assert sha(raw) == CLI_SHA256
    return module_of("responsive_cli_before", raw, FIXTURES / "responsive-cli-no-closing.before.source")


def fixed(module, name):
    """A private copy of the fix, so a test's clock and bounds never reach another test."""
    return module_of(name, Path(module.__file__).read_bytes(), module.__file__)


class Stayed(BaseException):
    """The fixture reached a sleep it never leaves: its retention, or its serving loop."""


class Forever(BaseException):
    """owner.park never returns: nothing after it runs, and no closing's own handler takes it."""


# ---- The fixture's main over a declared peer of its producer sources ---------------------------------

PRODUCER = '''
"""Declared peer of https_subscription_relay_fixture: the same start(), with listeners that only record."""
TLS_HANDSHAKE_TIMEOUT_SECONDS = 0.25


class _SubscriptionHandler:
    pass


class Listener:
    def __init__(self, role):
        self.role, self.serving, self.shut, self.closed = role, False, False, False
        WORLD.listeners.append(self)

    def shutdown(self):
        self.shut = True
        self.serving = False

    def server_close(self):
        # Windows: closing a listening socket under its serving thread ends that thread with WinError 10038.
        if self.serving:
            WORLD.closed_under_serving.append(self.role)
        self.closed = True


def _localhost_tls_server(context):
    WORLD.enter("https-listen")
    return Listener("https")


def FixtureServer(host, port, token, forward_host=None, forward_port=None):
    WORLD.enter("relay-listen")
    return Listener("relay")


class HttpsSubscriptionRelayFixture:
    def __init__(self, certificate, private_key, readiness_file, token):
        self.certificate, self.private_key, self.readiness_file, self.token = certificate, private_key, readiness_file, token
        self.https_server = self.relay_server = None

    def start(self):
        WORLD.enter("tls-context")
        https = _localhost_tls_server(object())
        try:
            relay = FixtureServer("127.0.0.1", 0, self.token, forward_host="localhost", forward_port=1)
            self.https_server, self.relay_server = https, relay
            https.serving = relay.serving = True
            readiness = {"source": "https://localhost:1/subscription", "httpsHost": "localhost", "httpsPort": 1,
                         "advertisedSocksHost": "127.0.0.1", "advertisedSocksPort": 2, "relayPort": 2,
                         "forwardHost": "localhost", "forwardPort": 1, "subscriptionRequests": 0}
            WORLD.enter("publish")
            self._publish_readiness(readiness)
            return readiness
        except BaseException:
            https.server_close()
            self.stop()
            raise

    def stop(self, timeout=3):
        for server in (self.relay_server, self.https_server):
            if server is not None:
                server.shutdown()
                server.server_close()
        self.https_server = self.relay_server = None
'''


class FixtureWorld:
    """One fixture process's files and its producer peer; fail names the peer step that raises."""

    def __init__(self, root, fail=None):
        self.root, self.fail, self.listeners, self.closed_under_serving, self.entered = root, fail, [], [], []
        self.fixture = root / "fixture"
        self.fixture.mkdir()
        self.certificate, self.key, self.input = root / "cert.pem", root / "key.pem", root / "document-work-input.json"
        self.certificate.write_bytes(b"certificate\n")
        self.key.write_bytes(b"key\n")
        self.operation = str(uuid.uuid4())
        self.config = {"schemaVersion": 1, "operationId": self.operation, "socksSourcePath": str(root / "socks.py"),
                       "httpsSourcePath": str(root / "https.py"), "certificatePath": str(self.certificate),
                       "privateKeyPath": str(self.key), "readyFile": str(self.fixture / "ready.json"),
                       "controlFile": str(self.fixture / "stop.json"), "token": "owned-document-work-" + self.operation}
        self.input.write_bytes((json.dumps(self.config, sort_keys=True, separators=(",", ":")) + "\n").encode())
        self.producer = types.ModuleType("_owned_work_https_peer")
        self.producer.WORLD = self
        exec(compile(PRODUCER, "producer-peer", "exec"), self.producer.__dict__)

    def enter(self, name):
        self.entered.append(name)
        if name == self.fail:
            error = PermissionError(13, "declared refusal of " + str(self.root))
            error.winerror = 10013
            raise error
        if name == "publish" and self.fail == "ready-rename":
            # Another name takes the ready file between the fresh check and the publication.
            (self.fixture / "ready.json").write_bytes(b"{}\n")

    def exact_stop(self):
        """Both requests ended and the owner's exact stop record is there: the fixture's own way out."""
        if not (self.fixture / "stop.json").exists():
            self.listeners[0].work_states = {phase: {"status": "response-written"} for phase in ("responsive", "client-loss")}
            (self.fixture / "stop.json").write_bytes((json.dumps({"schemaVersion": 1, "operationId": self.operation,
                                                                  "action": "stop-owned-fixture"}) + "\n").encode())
        return True

    def run(self, module, argv=None, serving=None):
        """main over the peer: a serving wait calls serving, and a sleep the fixture never leaves ends the run with Stayed.

        Returns (main's result or "stayed", the stdout rows, stderr)."""
        serving = serving or self.exact_stop

        def sleep(seconds):
            if seconds < 1 and serving():
                return
            raise Stayed()
        module.load = lambda path, role: self.producer
        module.time = types.SimpleNamespace(sleep=sleep, monotonic=real_time.monotonic)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                result = module.main(["--input", str(self.input)] if argv is None else argv)
            except Stayed:
                result = "stayed"
            except ValueError as error:
                result = "raised:" + str(error)
        return result, [json.loads(line) for line in out.getvalue().splitlines()], err.getvalue()


class FixtureStartTests(unittest.TestCase):
    def world(self, fail=None):
        temporary = tempfile.TemporaryDirectory(prefix="owned-work-fixture-")
        self.addCleanup(temporary.cleanup)
        return FixtureWorld(Path(temporary.name).resolve(), fail)

    def test_a_start_names_every_step_in_order_before_its_ready_line(self):
        world = self.world()
        result, rows, err = world.run(fixed(gated, "gated_fixed"))
        self.assertEqual(0, result, "served, then stopped by the owner's exact record")
        self.assertEqual([{"kind": "owned-work-fixture-step", "step": step} for step in STEPS], rows[:-2])
        self.assertEqual(["owned-work-fixture-ready", "owned-work-fixture-terminal"], [row["kind"] for row in rows[-2:]])
        self.assertEqual(STEPS, gated.STEPS)
        self.assertEqual(STEPS, cases.FIXTURE_STEPS, "the owner reads the steps the fixture says")
        ready = json.loads((world.fixture / "ready.json").read_bytes())
        self.assertEqual((world.operation, sha(b"certificate\n")), (ready["operationId"], ready["certificateSha256"]))
        self.assertEqual(("", [], ["ready.json", "stop.json"]), (err, world.closed_under_serving, sorted(p.name for p in world.fixture.iterdir())))
        # RED: the unfixed start says nothing before its ready line.
        world = self.world()
        result, rows, err = world.run(before_gated())
        self.assertEqual((0, ["owned-work-fixture-ready", "owned-work-fixture-terminal"]), (result, [row["kind"] for row in rows]))

    def failed(self, fail, module=None, prepare=None):
        world = self.world(fail)
        if prepare is not None:
            prepare(world)
        return (world, *world.run(module or fixed(gated, "gated_fixed")))

    def test_a_failure_while_the_listeners_are_made_is_said_and_ends_the_fixture(self):
        for step in ("tls-context", "https-listen", "relay-listen"):
            with self.subTest(step=step):
                world, result, rows, err = self.failed(step)
                self.assertEqual(gated.START_FAILED, result)
                self.assertEqual({"kind": "owned-work-fixture-failed", "step": step, "errorClass": "PermissionError",
                                  "winerror": 10013, "errno": 13, "reason": None, "listenersStopped": True}, rows[-1])
                self.assertEqual([row["step"] for row in rows[:-1]], list(STEPS[:STEPS.index(step) + 1]))
                self.assertIn("PermissionError", err, "the traceback goes to stderr")
                self.assertNotIn(str(world.root), json.dumps(rows), "no message or path reaches the record")
                self.assertEqual(([], False), (world.closed_under_serving, (world.fixture / "ready.json").exists()))
                # RED: the unfixed fixture keeps the failure to itself and sleeps: no line, no exit.
                _, result, rows, err = self.failed(step, before_gated())
                self.assertEqual(("stayed", [], ""), (result, rows, err))

    def test_a_failure_of_the_publication_stops_the_listeners_in_order_and_says_its_step(self):
        def linked(world):
            os.link(world.certificate, world.root / "second-name.pem")

        def taken(world):
            (world.fixture / "ready.json.publishing").write_bytes(b"")
        expected = {"certificate-digest": (linked, "Refusal", None, None, "work-input-bound-type"),
                    "ready-create": (taken, "FileExistsError", None, 17, None),
                    "ready-rename": (None, "FileExistsError", None, 17, None)}
        for step, (prepare, error, winerror, number, reason) in expected.items():
            with self.subTest(step=step):
                world, result, rows, err = self.failed(step, prepare=prepare)
                self.assertEqual(gated.START_FAILED, result)
                self.assertEqual({"kind": "owned-work-fixture-failed", "step": step, "errorClass": error, "winerror": winerror,
                                  "errno": number, "reason": reason, "listenersStopped": True}, rows[-1])
                self.assertEqual(STEPS[:STEPS.index(step) + 1], tuple(row["step"] for row in rows[:-1]))
                # Both listeners were serving: each is shut down before its socket is closed.
                self.assertEqual(([], [True, True], [True, True]), (world.closed_under_serving,
                                 [listener.shut for listener in world.listeners], [listener.closed for listener in world.listeners]))
                self.assertIn(error if error != "Refusal" else "work-input-bound-type", err)
                self.assertNotIn(str(world.root), json.dumps(rows))
                # RED: silent, alive, and the unchanged start() closed the HTTPS socket under its serving thread.
                world, result, rows, err = self.failed(step, before_gated(), prepare)
                self.assertEqual(("stayed", [], "", ["https"]), (result, rows, err, world.closed_under_serving))

    def test_a_refused_input_is_said_too(self):
        world = self.world()
        result, rows, err = world.run(fixed(gated, "gated_fixed"), argv=["--input"])
        self.assertEqual((gated.START_FAILED, [{"kind": "owned-work-fixture-step", "step": "input"},
                          {"kind": "owned-work-fixture-failed", "step": "input", "errorClass": "Refusal", "winerror": None,
                           "errno": None, "reason": "finite-work-entry", "listenersStopped": True}]), (result, rows))
        self.assertIn("finite-work-entry", err)
        # RED: the unfixed main raised it, which the interpreter reports only as a traceback and exit 1.
        self.assertEqual(("raised:finite-work-entry", []), world.run(before_gated(), argv=["--input"])[:2])

    def test_a_failure_after_readiness_stays_and_says_why_once(self):
        def wrong_stop(world):
            def serving():
                (world.fixture / "stop.json").write_bytes(b'{"action":"stop-owned-fixture","operationId":"other","schemaVersion":1}\n')
                return True
            return serving
        world = self.world()
        result, rows, err = world.run(fixed(gated, "gated_fixed"), serving=wrong_stop(world))
        self.assertEqual("stayed", result, "a request may be in flight after readiness: the fixture and its listeners stay")
        self.assertEqual({"kind": "owned-work-fixture-retained", "step": "serving", "errorClass": "Refusal", "winerror": None,
                          "errno": None, "reason": "exact-work-stop"}, rows[-1])
        self.assertEqual(1, [row["kind"] for row in rows].count("owned-work-fixture-retained"))
        self.assertEqual([False, False], [listener.shut for listener in world.listeners])
        # RED: it stayed without a word.
        world = self.world()
        result, rows, err = world.run(before_gated(), serving=wrong_stop(world))
        self.assertEqual(("stayed", ["owned-work-fixture-ready"]), (result, [row["kind"] for row in rows]))

    def test_only_this_sources_own_codes_are_copied_as_a_reason(self):
        self.assertTrue(issubclass(gated.Refusal, ValueError))
        self.assertEqual(3, gated.START_FAILED, "not 0 or 1: a start that failed is told from a stop and from a crash")
        self.assertEqual("work-event-bound", gated.failure(gated.Refusal("work-event-bound"))["reason"])
        for error in (ValueError("C:\\Users\\someone\\private"), OSError(5, "C:\\Users\\someone\\private"), KeyError("token")):
            self.assertIsNone(gated.failure(error)["reason"])
        with self.assertRaises(gated.Refusal):
            gated.step("not-a-step")


# ---- The owner's side: the real cases over the real Child, real pipes and the stages' real read_ready ----

READY_BOUND = 0.5  # The fix's READY_SECONDS in these runs; the stated 30 is checked by itself.


class Scaled:
    """The unfixed wait's clock: the stages' literal 30 s pass in READY_BOUND real seconds."""

    def monotonic(self):
        return real_time.monotonic() * 30 / READY_BOUND

    def sleep(self, seconds):
        real_time.sleep(seconds * READY_BOUND / 30)


class Process(responsive.ProcessPeer):
    """Every child's process peer; the work fixture's one termination ends it with TerminateProcess's 1."""

    def terminate(self):
        if "-I" not in self.argv:
            return super().terminate()
        self.world.terminations.append(self)
        if self.world.terminate_ends:
            self.finish(1)


PEER_SUBPROCESS = types.SimpleNamespace(**{**vars(responsive.PEER_SUBPROCESS), "Popen": Process})


class WindowsPeer:
    """The document native module's census, as its record: the kernel names the fixture on what it has open."""

    def __init__(self, world):
        self.world, self.calls = world, []

    def holder_census(self, owner, fixture, step, moment, winerror, targets):
        self.calls.append((fixture, step, moment, winerror, [(role, Path(path).name) for role, path in targets]))
        held = self.world.fixture_holds if self.world.fixture_process.poll() is None else ()
        return {"censusError": None, "targets": [
            {"role": role, "leaf": Path(path).name, "status": "ok" if Path(path).exists() else "open-refused:2",
             "holderCount": int(role in held), "holders": [{"pid": self.world.fixture_process.pid, "image": "python.exe",
             "role": "work-fixture", "child": 0, "parentPid": None, "openError": None}] if role in held else []}
            for role, path in targets]}


class Owner(responsive.OwnerPeer):
    def __init__(self, world):
        super().__init__(world)
        self.parked, self.modules, self.pins = None, {}, []

    def park(self, reason, error=None):
        self.parked = (reason, error)
        raise Forever(reason)

    def child(self, label, argv):
        child = ordinary.Child(self, label, argv)
        # What the peer process wrote as it started has reached the owner's raw file before the owner goes on.
        until = real_time.monotonic() + 10
        while child.counts["stdout"] < self.world.spoken.get(child.process, 0) and real_time.monotonic() < until:
            real_time.sleep(0.001)
        return child

    def module(self, path, name):
        return self.modules[Path(path).name]

    def kinds(self):
        return [event["kind"] for event in self.events]

    def last(self, kind):
        return [event["value"] for event in self.events if event["kind"] == kind][-1]


class World(responsive.World):
    """behavior is what the fixture process does once started; the other children are the full protocol peer's."""

    def __init__(self, root, behavior="ready", full=False):
        super().__init__(root, full)
        self.owner = Owner(self)
        self.behavior, self.terminations, self.terminate_ends = behavior, [], True
        self.fixture_holds, self.refreshes, self.fault, self.spoken = ("fixture-folder", "certificate"), [], None, {}
        self.windows = WindowsPeer(self)

    def say(self, process, *steps):
        data = self.said(process, *steps)
        os.write(process._stdout, data)
        self.spoken[process] = len(data)

    def said(self, process, *steps, failed=None):
        rows = [{"kind": "owned-work-fixture-step", "step": step} for step in steps]
        if failed is not None:
            rows.append({"kind": "owned-work-fixture-failed", **failed})
        return b"".join((json.dumps(row) + "\n").encode() for row in rows)

    def spawn(self, process):
        argv = process.argv
        if "-I" not in argv:
            if "refresh" in argv:
                self.refreshes.append(self.owner.document_work_lease.open_phase)
            if self.fault is not None and self.fault(argv):
                # A completed public call whose envelope no oracle takes.
                process.finish(0, cases.encoded(dict(self.envelope(), schemaVersion=2)))
                return
            return super().spawn(process)
        if self.behavior in ("ready", "refused-ready", "foreign-ready"):
            super().spawn(process)
            self.say(process, *STEPS)
            if self.behavior == "refused-ready":
                Path(self.config["readyFile"]).write_bytes(cases.encoded(dict(self.ready, certificateSha256="0" * 64)))
            if self.behavior == "foreign-ready":  # A ready record that names another process.
                Path(self.config["readyFile"]).write_bytes(cases.encoded(dict(self.ready, pid=process.pid + 1)))
            return
        self.config, self.fixture_process = json.loads(Path(argv[-1]).read_bytes()), process
        if self.behavior == "silent":
            return
        if self.behavior == "stuck":
            self.say(process, *STEPS[:4])
            return
        assert self.behavior == "ended"
        Path(self.config["readyFile"] + ".publishing").write_bytes(b"{}\n")
        process.finish(3, self.said(process, *STEPS, failed={"step": "ready-rename", "errorClass": "PermissionError", "winerror": 32,
            "errno": 13, "reason": "refused at " + str(self.root), "listenersStopped": True, "path": str(self.root)}),
            b"Traceback: " + str(self.root).encode() + b"\n")


class Tree:
    """One set of the three sources: the fix, or the exact unfixed bytes."""

    def __init__(self, unfixed):
        self.cases = before_cases() if unfixed else fixed(cases, "responsive_cases_fixed")
        self.cli = before_cli() if unfixed else fixed(cli, "responsive_cli_fixed")
        self.stages = fixed(stages, "runtime_stages_private")


class OwnerSide(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(ordinary, "subprocess", PEER_SUBPROCESS)
        patcher.start()
        self.addCleanup(patcher.stop)

    def world(self, behavior="ready", unfixed=False, full=False):
        temporary = tempfile.TemporaryDirectory(prefix="owned-work-owner-")
        self.addCleanup(temporary.cleanup)
        world = World(Path(temporary.name).resolve(), behavior, full)
        self.addCleanup(world.__exit__)
        tree, owner = Tree(unfixed), world.owner
        tree.stages.time = Scaled()
        if not unfixed:
            tree.cases.READY_SECONDS = READY_BOUND
        # The stages' real read_ready over declared custody: no native handle exists here.
        tree.stages.OwnedData, tree.stages.data_guard = responsive.DataPeer, lambda owner: owner.guard()
        runtime = types.SimpleNamespace(OwnedData=responsive.DataPeer, data_guard=tree.stages.data_guard,
                                        publish=world.runtime.publish, read_ready=tree.stages.read_ready,
                                        scoped_trust_options=tree.stages.scoped_trust_options)
        files = {}
        for role in ("fixtureWorkerPath", "socksSourcePath", "httpsSourcePath", "certificatePath", "privateKeyPath", "trustStorePath",
                     "largeRoutingInputPath", "casesPath", "runtimeStagesPath", "windowsPath"):
            path = world.root / (role + ".input")
            path.write_bytes(b"\n" * (10 * 1024 * 1024 + 1) if role == "largeRoutingInputPath" else (role + "-declared").encode())
            owner.by_path[str(path).casefold()] = responsive.FilePin(path)
            files[role] = str(path)
        temp = world.root / "document-temp"
        temp.mkdir()
        owner.pins = [types.SimpleNamespace(directory=True, path=temp, current=lambda: None, record={"nativeIdentity": {}})]
        owner.modules = {"casesPath.input": tree.cases, "runtimeStagesPath.input": runtime, "windowsPath.input": world.windows}
        contexts = [str(uuid.uuid4()) for _ in range(52)]
        owner.request.update(
            documentAcceptance={"schemaVersion": 1, "clientPath": "client", "windowsPath": files["windowsPath"], "racePath": "race",
                                "largeRoutingInputPath": files["largeRoutingInputPath"], "spoolTempParent": str(temp),
                                "contexts": contexts, "endpointPinBeforeObservation": None},
            responsiveWork={"schemaVersion": 1, **{key: files[key] for key in (
                "casesPath", "runtimeStagesPath", "fixtureWorkerPath", "socksSourcePath", "httpsSourcePath", "certificatePath",
                "privateKeyPath", "trustStorePath", "largeRoutingInputPath")}, "contexts": [str(uuid.uuid4()), str(uuid.uuid4())]})
        return world, tree, owner, Path(owner.request["workspace"])

    def served(self, behavior="ready", unfixed=False, full=False):
        """Through the real configure_launch to a started serve, as Owner.run does."""
        world, tree, owner, workspace = self.world(behavior, unfixed, full)
        tree.cli.configure_launch(owner, workspace)
        _, _, lease = owner.document_responsive_modules
        serve = owner.child("serve", [owner.request["cliPath"], "--state-dir", str(workspace), "serve"])
        workspace.mkdir()
        owner.environment.pop("JAVA_TOOL_OPTIONS")
        tree.cases.after_original_serve_started(owner, lease, serve)
        return world, tree, owner, workspace, lease, serve


class ReadinessTests(OwnerSide):
    def test_a_fixture_that_never_becomes_ready_is_journaled_ended_and_known(self):
        world, tree, owner, workspace = self.world("stuck")
        with self.assertRaisesRegex(AssertionError, r"\Adocument-work-fixture-not-ready:timeout:https-listen\Z"):
            tree.cli.configure_launch(owner, workspace)
        child = owner.children[0]
        self.assertEqual((None, [world.fixture_process], 1), (owner.parked, world.terminations, child.terminal["exitCode"]))
        self.assertEqual(["child-intent", "child-started", "document-work-fixture-not-ready",
                          "document-work-fixture-terminate-intent", "child-terminal", "document-work-fixture-closed"], owner.kinds())
        found = owner.last("document-work-fixture-not-ready")
        self.assertEqual({"reason": "timeout", "child": 0, "pid": child.pid, "birthFileTimeUtc": child.birth, "alive": True,
                          "exitCode": None, "boundSeconds": READY_BOUND, "errorClass": "AssertionError", "steps": list(STEPS[:4]),
                          "lastStep": "https-listen", "failure": None, "readySaid": False, "stderrBytes": 0, "unreadable": None,
                          "readyExists": False, "publishingExists": False, "folderCount": 0, "folder": [],
                          "heldByFixture": ["fixture-folder", "certificate"], "censusError": None, "replayAllowed": False},
                         {key: value for key, value in found.items() if key not in ("waitedSeconds", "stdoutBytes")})
        self.assertGreaterEqual(found["waitedSeconds"], READY_BOUND)
        self.assertGreater(found["stdoutBytes"], 0)
        # The census ran while the child was as found, over the fixture's own files by role and leaf.
        self.assertEqual([("work", "readiness", "timeout", None, [
            ("fixture-folder", "fixture"), ("ready", "ready.json"), ("ready-publishing", "ready.json.publishing"),
            ("input", "document-work-input.json"), ("fixture-source", "fixtureWorkerPath.input"),
            ("socks-source", "socksSourcePath.input"), ("https-source", "httpsSourcePath.input"),
            ("certificate", "certificatePath.input"), ("private-key", "privateKeyPath.input")])], world.windows.calls)
        self.assertEqual({"child": 0, "pid": child.pid, "birthFileTimeUtc": child.birth, "effect": "one-original-Popen.terminate",
                          "groupOrJobSignal": False, "replayAllowed": False}, owner.last("document-work-fixture-terminate-intent"))
        closed = owner.last("document-work-fixture-closed")
        self.assertEqual(("timeout", True, 1, list(STEPS[:4])),
                         (closed["reason"], closed["terminated"], closed["terminal"]["exitCode"], closed["steps"]))
        # No serve was started and no JVM option was left: every child is terminal, so the owner finishes 1.
        self.assertEqual(([FIXTURE], True, False), ([c.label for c in owner.children],
                         all(c.terminal is not None for c in owner.children), "JAVA_TOOL_OPTIONS" in owner.environment))
        self.assertNotIn(str(world.root), json.dumps([e for e in owner.events if e["kind"].startswith("document-work-")]))

    def test_the_unfixed_cases_park_over_a_fixture_that_never_becomes_ready(self):
        world, tree, owner, workspace = self.world("stuck", unfixed=True)
        with self.assertRaises(Forever):
            tree.cli.configure_launch(owner, workspace)
        self.assertEqual(("runtime-fixture-readiness-unknown-no-replay", None), owner.parked)
        self.assertEqual(([], None, None), (world.terminations, world.fixture_process.poll(), owner.children[0].terminal))
        self.assertEqual([], [kind for kind in owner.kinds() if kind.startswith("document-work-")])
        self.assertEqual([], world.windows.calls)

    def test_a_silent_fixture_is_known_by_no_step(self):
        world, tree, owner, workspace = self.world("silent")
        world.fixture_holds = ()
        with self.assertRaisesRegex(AssertionError, r"\Adocument-work-fixture-not-ready:timeout:none\Z"):
            tree.cli.configure_launch(owner, workspace)
        found = owner.last("document-work-fixture-not-ready")
        self.assertEqual(([], None, 0, 0, []), (found["steps"], found["lastStep"], found["stdoutBytes"], found["stderrBytes"],
                                                 found["heldByFixture"]))

    def test_a_fixture_that_ended_before_ready_is_read_to_its_end_and_known(self):
        world, tree, owner, workspace = self.world("ended")
        with self.assertRaisesRegex(AssertionError, r"\Adocument-work-fixture-not-ready:ended:3:ready-rename\Z"):
            tree.cli.configure_launch(owner, workspace)
        found, child = owner.last("document-work-fixture-not-ready"), owner.children[0]
        self.assertEqual(("ended", False, 3, list(STEPS), "ready-rename", False, True, ["ready.json.publishing"], []),
                         (found["reason"], found["alive"], found["exitCode"], found["steps"], found["lastStep"], found["readyExists"],
                          found["publishingExists"], found["folder"], found["heldByFixture"]))
        # Only the finite fields of what the fixture said are kept.
        self.assertEqual({"step": "ready-rename", "errorClass": "PermissionError", "winerror": 32, "errno": 13, "reason": None,
                          "listenersStopped": True}, found["failure"])
        self.assertEqual((None, [], 3), (owner.parked, world.terminations, child.terminal["exitCode"]))
        self.assertNotIn("document-work-fixture-terminate-intent", owner.kinds())
        self.assertEqual((False, found["failure"]), (owner.last("document-work-fixture-closed")["terminated"],
                                                     owner.last("document-work-fixture-closed")["failure"]))
        self.assertNotIn(str(world.root), json.dumps([e for e in owner.events if e["kind"].startswith("document-work-")]))
        # RED: the oracle's error escaped with the child unobserved, which the owner's main parks.
        world, tree, owner, workspace = self.world("ended", unfixed=True)
        with self.assertRaisesRegex(AssertionError, "original-runtime-fixture-ended-before-ready"):
            tree.cli.configure_launch(owner, workspace)
        self.assertEqual((None, []), (owner.children[0].terminal, [k for k in owner.kinds() if k.startswith("document-work-")]))

    def test_a_ready_record_an_oracle_refuses_ends_the_fixture(self):
        for behavior, code in (("refused-ready", "actual-work-tls-endpoints"), ("foreign-ready", "actual-original-fixture-child-ready")):
            with self.subTest(behavior=behavior):
                world, tree, owner, workspace = self.world(behavior)
                with self.assertRaisesRegex(AssertionError, r"\Adocument-work-fixture-not-ready:refused:" + code + r"\Z"):
                    tree.cli.configure_launch(owner, workspace)
                found = owner.last("document-work-fixture-not-ready")
                self.assertEqual(("refused", True, True, list(STEPS), ["ready.json"]),
                                 (found["reason"], found["alive"], found["readyExists"], found["steps"], found["folder"]))
                # No refusal leaves the serve's trust options behind in the owner's environment.
                self.assertEqual((None, 1, 1, False), (owner.parked, len(world.terminations), owner.children[0].terminal["exitCode"],
                                                       "JAVA_TOOL_OPTIONS" in owner.environment))
        # RED: the refusal escaped with the fixture alive and listening, the second one with the options set.
        for behavior, code, options in (("refused-ready", "actual-work-tls-endpoints", False),
                                        ("foreign-ready", "actual-original-fixture-child-ready", True)):
            with self.subTest(unfixed=behavior):
                world, tree, owner, workspace = self.world(behavior, unfixed=True)
                with self.assertRaisesRegex(AssertionError, r"\A" + code + r"\Z"):
                    tree.cli.configure_launch(owner, workspace)
                self.assertEqual(([], None, None, options), (world.terminations, world.fixture_process.poll(),
                                 owner.children[0].terminal, "JAVA_TOOL_OPTIONS" in owner.environment))

    def test_only_the_finite_fields_of_what_the_fixture_said_are_kept(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned-work-said-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        secret = json.dumps(str(root / "secret"))
        lines = ['{"kind":"owned-work-fixture-step","step":"input"}',
                 '{"kind":"owned-work-fixture-step","step":%s}' % secret, "not json", "[1,2]",
                 '{"kind":"owned-work-fixture-step","step":"sources"}',
                 '{"kind":"owned-work-fixture-failed","step":%s,"errorClass":"Some Error","winerror":"32","errno":13,'
                 '"reason":%s,"listenersStopped":"yes","path":%s}' % (secret, secret, secret),
                 '{"kind":"owned-work-fixture-step","step":"tls-context"']  # The last line is not complete.
        (root / "child-0003.stdout.raw").write_bytes("\n".join(lines).encode())
        owner, child = types.SimpleNamespace(root=root), types.SimpleNamespace(ordinal=3, counts={"stdout": 7, "stderr": 0})
        self.assertEqual({"steps": ["input", "sources"], "lastStep": "sources", "readySaid": False, "stdoutBytes": 7, "stderrBytes": 0,
                          "unreadable": None, "failure": {"step": None, "errorClass": None, "winerror": None, "errno": 13,
                                                          "reason": None, "listenersStopped": False}}, cases.fixture_said(owner, child))
        # A fixture that repeats itself is not copied without end, and a raw file that cannot be read is named, not raised.
        (root / "child-0003.stdout.raw").write_bytes(b'{"kind":"owned-work-fixture-step","step":"input"}\n' * 50)
        self.assertEqual(2 * len(STEPS), len(cases.fixture_said(owner, child)["steps"]))
        child.ordinal = 4
        self.assertEqual(([], None, "FileNotFoundError"), tuple(cases.fixture_said(owner, child)[key] for key in ("steps", "lastStep", "unreadable")))
        self.assertEqual(("ready-rename", None, None, "PermissionError", None),
                         (cases.finite("ready-rename"), cases.finite("Ready Rename"), cases.finite("x" * 81),
                          cases.finite("PermissionError", cases.NAME_CHARACTERS, 64), cases.finite(13)))

    def test_a_fixture_that_outlives_its_one_termination_parks(self):
        world, tree, owner, workspace = self.world("stuck")
        world.terminate_ends, tree.cases.TERMINATE_SECONDS = False, 0.3
        with self.assertRaises(Forever):
            tree.cli.configure_launch(owner, workspace)
        self.assertEqual("document-work-fixture-end-unknown", owner.parked[0])
        self.assertEqual({"child": 0, "pid": world.fixture_process.pid, "birthFileTimeUtc": owner.children[0].birth,
                          "terminated": True, "replayAllowed": False}, owner.parked[1])
        self.assertEqual((1, None), (len(world.terminations), owner.children[0].terminal), "one termination, never a second")
        self.assertNotIn("document-work-fixture-closed", owner.kinds())

    def test_another_generation_of_the_child_is_never_terminated(self):
        world, tree, owner, workspace = self.world("stuck")
        owner.native = types.SimpleNamespace(birth=lambda handle: (
            "another-generation" if "document-work-fixture-not-ready" in owner.kinds() else str(handle * 100)))
        with self.assertRaises(Forever):
            tree.cli.configure_launch(owner, workspace)
        self.assertEqual(("document-work-fixture-closing-unknown", "original-work-fixture-live-birth", []),
                         (owner.parked[0], str(owner.parked[1]), world.terminations))

    def test_a_ready_fixture_is_journaled_with_its_measured_wait_and_no_census(self):
        world, tree, owner, workspace = self.world()
        marker = tree.cli.configure_launch(owner, workspace)
        _, _, lease = owner.document_responsive_modules
        ready = owner.last("document-work-fixture-ready")
        self.assertEqual({"child": 0, "pid": lease.child.pid, "boundSeconds": READY_BOUND},
                         {key: value for key, value in ready.items() if key != "readySeconds"})
        self.assertLess(ready["readySeconds"], READY_BOUND)
        self.assertEqual(([], [], None, world.windows, 1), (world.windows.calls, world.terminations, lease.open_phase, lease.windows,
                                                           marker["expectedServeOrdinal"]))
        self.assertIs(owner.document_windows_module, world.windows, "the native module is loaded once, before the fixture")
        source = Path(cli.__file__).read_text()
        self.assertEqual((1, 1), (source.count('owner.module(inputs["windowsPath"]'), source.count("windows = owner.document_windows_module")))
        # The admitted client is kept for the closing, which reads its sockets.
        self.assertIn("    client = windows.admit_endpoint(owner, workspace, identity, native_endpoint_pin, module)\n"
                      "    owner.document_client = client", source)
        self.assertIn("JAVA_TOOL_OPTIONS", owner.environment)
        # RED: no measurement was journaled.
        world, tree, owner, workspace = self.world(unfixed=True)
        tree.cli.configure_launch(owner, workspace)
        self.assertNotIn("document-work-fixture-ready", owner.kinds())


FIXTURE = "owned-document-work-fixture"
HELP, WORK, SERVE = 4000011, 4000012, 4000013  # No real process of this machine.


class ClosingTests(OwnerSide):
    def quiet_client(self, owner):
        owner.document_client = types.SimpleNamespace(original_sockets=[], last_exchange=None)
        owner.document_endpoint_handle = types.SimpleNamespace(closed=False, close=lambda: setattr(owner.document_endpoint_handle, "closed", True))
        owner.document_workspace_handle = types.SimpleNamespace(closed=False, close=lambda: setattr(owner.document_workspace_handle, "closed", True))

    def test_a_finite_failure_with_no_refresh_open_ends_the_fixture_and_names_the_owner(self):
        world, tree, owner, workspace, lease, serve = self.served()
        self.quiet_client(owner)
        for error in (AssertionError("same-owner-public-envelope"), RuntimeError("document-same-disconnected-installed-owner")):
            with self.subTest(error=type(error).__name__):
                known = tree.cli.close_known(owner, error, serve, "controller")
                self.assertEqual((serve, "controller"), known)
        self.assertEqual((1, 1, True, None), (len(world.terminations), lease.child.terminal["exitCode"], lease.closed, owner.parked))
        ending = owner.last("document-work-fixture-ending")
        self.assertEqual(("known-failure", True, True, list(STEPS), ["fixture-folder", "certificate"]),
                         (ending["reason"], ending["alive"], ending["readyExists"], ending["steps"], ending["heldByFixture"]))
        self.assertEqual({"reason": "same-owner-public-envelope", "socketsOpen": 0, "workFixtureEnded": True, "replayAllowed": False},
                         [e["value"] for e in owner.events if e["kind"] == "document-known-failure-observers-released"][0])
        self.assertEqual((True, True), (owner.document_endpoint_handle.closed, owner.document_workspace_handle.closed))
        # Only the serve is left for the owner's closing, which quits it; the fixture is terminal.
        self.assertEqual(["serve"], [child.label for child in owner.children if child.terminal is None])
        # RED: the unfixed module had no closing, so the owner parked over every failure of this row.
        self.assertFalse(hasattr(before_cli(), "close_known"))
        self.assertFalse(hasattr(before_cases(), "close_known_work"))

    def test_an_open_refresh_open_sockets_or_an_unknown_error_keep_every_original(self):
        world, tree, owner, workspace, lease, serve = self.served()
        self.quiet_client(owner)
        error = AssertionError("one-fresh-actual-owned-subscription-work")
        lease.open_phase = "responsive"
        self.assertIsNone(tree.cli.close_known(owner, error, serve, "controller"))
        lease.open_phase = None
        owner.responsive_client_effects = {7: {"stage": "effect-entered", "stream": None}}
        self.assertIsNone(tree.cli.close_known(owner, error, serve, "controller"))
        owner.responsive_client_effects = {7: {"stage": "known-client-terminal", "stream": None}}
        owner.document_client.original_sockets = [object()]
        self.assertIsNone(tree.cli.close_known(owner, error, serve, "controller"))
        owner.document_client.original_sockets = []
        owner.document_client.last_exchange = {"secondary": True}
        self.assertIsNone(tree.cli.close_known(owner, error, serve, "controller"))
        owner.document_client.last_exchange = None
        for unknown in (ValueError("unreadable"), RuntimeError("anything-else"), KeyError("data")):
            self.assertIsNone(tree.cli.close_known(owner, unknown, serve, "controller"))
        self.assertEqual(([], None, False, False), (world.terminations, lease.child.terminal, lease.closed, owner.document_endpoint_handle.closed))
        self.assertNotIn("document-known-failure-observers-released", owner.kinds())
        # The same failure with nothing open is closed.
        self.assertEqual((serve, "controller"), tree.cli.close_known(owner, error, serve, "controller"))

    def test_a_fixture_that_already_ended_is_not_terminated_again(self):
        world, tree, owner, workspace, lease, serve = self.served()
        self.quiet_client(owner)
        world.fixture_process.finish(0, cases.encoded({"kind": "owned-work-fixture-terminal", "operationId": owner.operation,
                                                       "onlyOriginalObjectsStopped": True}))
        self.assertEqual((serve, "controller"), tree.cli.close_known(owner, AssertionError("original-fixture-known-terminal"), serve, "controller"))
        self.assertEqual(([], 0, False), (world.terminations, lease.child.terminal["exitCode"], owner.last("document-work-fixture-ending")["alive"]))
        self.assertEqual((serve, "controller"), tree.cli.close_known(owner, AssertionError("again"), serve, "controller"))
        self.assertEqual(1, owner.kinds().count("document-work-fixture-ending"), "a terminal fixture is not journaled twice")

    def test_a_closing_that_cannot_be_known_parks(self):
        world, tree, owner, workspace, lease, serve = self.served()
        self.quiet_client(owner)
        world.terminate_ends, tree.cases.TERMINATE_SECONDS = False, 0.3
        with self.assertRaises(Forever):
            tree.cli.close_known(owner, AssertionError("same-owner-public-envelope"), serve, "controller")
        self.assertEqual("document-work-fixture-end-unknown", owner.parked[0])
        world2, tree2, owner2, _, _, serve2 = self.served()
        owner2.document_client = types.SimpleNamespace()
        with self.assertRaises(Forever):
            tree2.cli.close_known(owner2, AssertionError("same-owner-public-envelope"), serve2, "controller")
        self.assertEqual(("document-known-failure-release-unknown", []), (owner2.parked[0], world2.terminations))


class LongWorkTests(OwnerSide):
    def run_cases(self, unfixed=False, fault=None):
        world, tree, owner, workspace, lease, serve = self.served(unfixed=unfixed, full=True)
        world.fault = fault
        client = responsive.DocumentPeer(owner)
        return world, tree, owner, lease, lambda: tree.cases.run(owner, workspace, world.controller, client, responsive.documents, lease)

    def test_each_phase_is_open_from_its_refresh_until_it_is_known_final(self):
        world, tree, owner, lease, run = self.run_cases()
        opened = []
        mark = lease.mark_known
        lease.mark_known = lambda phase, terminal: (opened.append(lease.open_phase), mark(phase, terminal), opened.append(lease.open_phase))
        self.assertEqual(2, len(run()["observations"]))
        self.assertEqual((["responsive", "client-loss"], ["responsive", None, "client-loss", None], None),
                         (world.refreshes, opened, lease.open_phase))

    def test_an_oracle_failure_before_any_refresh_is_left_to_the_closing(self):
        first_list = lambda argv: argv[-2:] == ("subscriptions", "list")
        world, tree, owner, lease, run = self.run_cases(fault=first_list)
        with self.assertRaisesRegex(AssertionError, "same-owner-public-envelope"):
            run()
        self.assertEqual((None, None, []), (owner.parked, lease.open_phase, world.refreshes))
        self.assertTrue(tree.cases.close_known_work(owner, lease, AssertionError("same-owner-public-envelope")))
        self.assertEqual((1, True), (len(world.terminations), lease.closed))
        # RED: the unfixed cases parked over it, product state known or not.
        world, tree, owner, lease, run = self.run_cases(unfixed=True, fault=first_list)
        with self.assertRaises(Forever):
            run()
        self.assertEqual("document-responsive-longwork-unqualified-originals-retained", owner.parked[0])

    def test_an_oracle_failure_between_the_phases_is_left_to_the_closing(self):
        second_baseline = {"seen": 0}

        def fault(argv):
            if argv[-2:] == ("operations", "list") and not any("refresh" in process.argv and process.code is None
                                                                for process in world.processes):
                second_baseline["seen"] += 1
                return second_baseline["seen"] == 3  # The first phase lists twice; the third list opens the second phase.
            return False
        world, tree, owner, lease, run = self.run_cases(fault=fault)
        with self.assertRaisesRegex(AssertionError, "same-owner-public-envelope"):
            run()
        self.assertEqual((None, None, ["responsive"], {"responsive"}), (owner.parked, lease.open_phase, world.refreshes, lease.completed))

    def test_a_failure_while_a_refresh_is_open_still_parks(self):
        def during(argv):
            return argv[-2:] == ("operations", "list") and bool(world.refreshes)
        world, tree, owner, lease, run = self.run_cases(fault=during)
        with self.assertRaises(Forever):
            run()
        self.assertEqual(("document-responsive-longwork-unqualified-originals-retained", "responsive", []),
                         (owner.parked[0], lease.open_phase, world.terminations))
        self.assertFalse(tree.cases.close_known_work(owner, lease, owner.parked[1]))
        self.assertEqual(([], False), (world.terminations, lease.closed))

    def test_an_error_no_oracle_raised_still_parks(self):
        world, tree, owner, lease, run = self.run_cases()
        lease.inputs = dict(lease.inputs, contexts=None)  # A TypeError, not an oracle's AssertionError.
        with self.assertRaises(Forever):
            run()
        self.assertEqual(("document-responsive-longwork-unqualified-originals-retained", "TypeError"),
                         (owner.parked[0], type(owner.parked[1]).__name__))


# ---- The census names the work fixture and the owner's leases on its files -------------------------------

class CensusRoleTests(unittest.TestCase):
    def owner(self):
        child = lambda ordinal, pid, label, argv, terminal=None: types.SimpleNamespace(
            ordinal=ordinal, pid=pid, label=label, argv=argv, birth=str(pid), terminal=terminal)
        return types.SimpleNamespace(
            children=[child(0, HELP, "help", ("cli", "--help"), {"exitCode": 0}),
                      child(1, WORK, FIXTURE, ("python.exe", "-I", "-B", "fixture.py", "--input", "input.json")),
                      child(2, SERVE, "serve", ("cli", "--state-dir", "workspace", "serve"))],
            native=types.SimpleNamespace(document_retained_handles=[]), pins=[],
            fixture_data_leases=[types.SimpleNamespace(path=Path("C:/root/fixture"), directory=True, handle=7),
                                 types.SimpleNamespace(path=Path("C:/root/document-work-input.json"), directory=False, handle=8),
                                 types.SimpleNamespace(path=Path("C:/root/fixture/closed.json"), directory=False, handle=None)])

    def test_the_census_names_the_work_fixture_child_by_its_role(self):
        known = native_module.known_processes(self.owner())
        self.assertEqual(({"role": "work-fixture", "child": 1, "birth": str(WORK), "live": True}, "cli-child", "serve"),
                         (known[WORK], known[HELP]["role"], known[SERVE]["role"]))
        self.assertEqual(FIXTURE, native_module.WORK_FIXTURE_LABEL)
        self.assertEqual(FIXTURE, cases.FIXTURE_LABEL)
        self.assertEqual(("work-fixture", 1), native_module.holder_role(WORK, {"birth": str(WORK), "parentPid": 1}, known))

    def test_the_harness_handles_list_an_owned_fixtures_open_leases_with_their_modes(self):
        found = native_module.harness_handles(self.owner())
        self.assertEqual((2, [{"path": str(Path("C:/root/fixture")), "directory": True, "access": 0x20080, "share": 3},
                              {"path": str(Path("C:/root/document-work-input.json")), "directory": False, "access": 0x80020000, "share": 1}]),
                         (found["dataLeaseCount"], found["dataLeases"]))
        # The modes are the stages' own: a folder for attributes with read and write sharing, a file for reading with read sharing.
        self.assertIn("owner.native.k.CreateFileW(str(path), 0x20080 if directory else 0x80020000,\n            3 if directory else 1,",
                      Path(stages.__file__).read_text())
        self.assertEqual({True: (0x20080, 3), False: (0x80020000, 1)}, native_module.DATA_LEASE_MODES)

    def test_the_readiness_bound_is_stated_and_the_stages_wait_is_not_reached(self):
        self.assertEqual((30, 15), (cases.READY_SECONDS, cases.TERMINATE_SECONDS))
        source = Path(cases.__file__).read_text()
        # The cases wait themselves and call read_ready only once the file exists, so its park is never reached here.
        self.assertLess(source.index("reason,waited=await_ready(owner,child,Path(config['readyFile']))"),
                        source.index("ready=runtime.read_ready(owner,child,Path(config['readyFile']),owner.operation)"))
        self.assertIn('owner.park("runtime-fixture-readiness-unknown-no-replay")', Path(stages.__file__).read_text())


class ProvenanceTests(unittest.TestCase):
    def test_the_before_images_are_the_bytes_that_ran_natively(self):
        record = json.loads((FIXTURES / "provenance.json").read_bytes())
        found = {"gated-fixture-silent-start.before.source": (FIXTURES / "gated-fixture-silent-start.before.source").read_bytes(),
                 "responsive-cases-readiness-park.before.source": (FIXTURES / "responsive-cases-readiness-park.before.source").read_bytes(),
                 "responsive-cli-no-closing.before.source": (FIXTURES / "responsive-cli-no-closing.before.source").read_bytes()}
        self.assertEqual({name: {"sha256": sha(raw), "sizeBytes": len(raw)} for name, raw in found.items()},
                         {name: {"sha256": row["sha256"], "sizeBytes": row["sizeBytes"]} for name, row in record["fixtures"].items()})
        self.assertEqual([GATED_SHA256, CASES_SHA256, CLI_SHA256], [sha(raw) for raw in found.values()])
        # The owner and the planner pinned exactly these three digests for the native run.
        owner_before = (Path(__file__).with_name("fixtures") / "windows_document_fixture_holders" / "owner-pin-modes.before.source").read_text()
        for digest in (GATED_SHA256, CASES_SHA256, CLI_SHA256):
            self.assertIn(digest, owner_before)


if __name__ == "__main__":
    unittest.main()
