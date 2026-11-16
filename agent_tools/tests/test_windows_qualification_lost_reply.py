"""A lost reply of the read-only setup qualification closes in the idle census; nothing else does.

Native contact, raw QEMU Windows clone be766f0c on 2026-11-08: the MCP qualification
dea00558 ended UNKNOWN (failure class OSError, native failure 80a38b34), nine status reads
of it ended UNKNOWN too (ValueError with no check name: the guest agent no longer knew its
pid, native failure 1d5509db), and a new qualification 383aff75 then observed the setup. The
original's qualification-dea00558-....intent.json stayed in the VM root, so the full idle
census of 2026-11-09 (b01d37c6) reported it as original_guest_work_unresolved and the clone
could never be positively idle.

Each case runs the actual nested host_work of this tree's readiness packet source over real
private files. The qualification's program text comes from its real producer,
windows_vm_guest.powershell_source; the mutating control is the real secure_source.

Only an acknowledged qualification closes. qualify_instance saves its intent and .ps1
before its guest-exec and takes no lock the census holds, and the census reads its process
rows before it lists the receipts, so one without an acknowledgement may still be about to
start (review of 3f3ebd75). The native evidence of dea00558 is the acknowledged case: its
status reads failed with a ValueError and no check name, which is what guest-exec-status
answers for a forgotten pid, while a missing acknowledgement fails that read with an OSError.
"""
import ast, base64, hashlib, json, os, re, stat, tempfile, unittest, uuid
from pathlib import Path
from unittest import mock

from agent_tools import readiness_windows_remote as remote
from agent_tools import windows_vm_guest as setup_guest

SETUP = {"user": "fixtureuser", "administrator": "fixtureadmin", "locale": "en-US", "imageName": "Windows 11 Pro"}
NATIVE = "dea00558-3414-4944-953f-ac01fd07c8af"
ACTOR = {"pid": 4242, "startTicks": 99}
FORGOTTEN = {"state": "guest-agent-no-longer-tracks-absent-read-only-program", "replayAllowed": False}


def host_work_source():
    raw = Path(remote.__file__).read_bytes()
    nodes = [node for node in ast.walk(ast.parse(raw)) if isinstance(node, ast.FunctionDef) and node.name == "host_work"]
    if len(nodes) != 1:
        raise AssertionError("host_work is not unique")
    return ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), ast.get_source_segment(raw.decode(), nodes[0])


class VmRoot:
    """The instance helpers of the packet, over one private directory."""

    def __init__(self, root):
        self.root = root
        self.rpc = mock.Mock(side_effect=AssertionError("no guest call expected"))
        self.processes = [{"pid": 1, "name": "System", "self": False}, {"pid": 900, "name": "powershell.exe", "self": True}]

    def write(self, name, value, mode=0o600):
        path = self.root / name
        path.write_bytes(value if type(value) is bytes else (json.dumps(value, sort_keys=True) + "\n").encode())
        path.chmod(mode)
        return path

    def census(self):
        root = self.root

        def require(value, reason):
            if not value:
                raise ValueError(reason)

        def generation(s):
            return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

        def private(path):
            info = os.lstat(path)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_nlink == 1, "instance_private")
            return info

        def read(name):
            path = root / name
            private(path)
            raw = path.read_bytes()
            require(len(raw) <= 262144, "instance_receipt_bound")
            return json.loads(raw)

        def save(name, value):
            fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(value if type(value) is bytes else (json.dumps(value, sort_keys=True) + "\n").encode())

        namespace = {"root": root, "os": os, "re": re, "hashlib": hashlib, "read": read, "read_guest_terminal": read,
                     "save": save, "require": require, "private": private, "generation": generation, "rpc": self.rpc,
                     "result": {"idleFacts": {"processes": self.processes}}, "current_actor": ACTOR, "SETUP": dict(SETUP),
                     "SPEC": {"deploymentId": "be766f0c-bdb2-4c63-bd76-e3576f2af10c"}, "ORIGINAL_HOST_PHASES": [],
                     "CREATOR_ENROLLED": False}
        exec(compile(host_work_source()[0], "<host-work>", "exec"), namespace)
        return namespace["host_work"]()

    def qualification(self, operation=NATIVE, *, script=None, pid=7777, intent=None, source=True):
        """The receipts windows_vm_guest.qualify_instance leaves before its terminal."""
        prefix = "qualification-" + operation
        script = setup_guest.powershell_source(SETUP, operation) if script is None else script
        record = {"operationId": operation, "powerShellSha256": hashlib.sha256(script.encode()).hexdigest(), "readOnly": True,
                  "before": {"guestAgentReady": True, "ordinarySessionObserved": True}}
        record.update(intent or {})
        self.write(prefix + ".intent.json", record)
        if source:
            self.write(prefix + ".ps1", script.encode())
        for suffix in ("0123456789abcdef01234567.wire", "0123456789abcdef01234567.partial-wire"):
            self.write(prefix + "." + suffix, b"")
        if pid is not None:
            self.write(prefix + ".ack.json", {"operationId": operation, "ack": {"pid": pid}, "replayAllowed": False})
        return prefix


class Case(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "vc-rw-be766f0c"
        self.root.mkdir(mode=0o700)
        self.vm = VmRoot(self.root)

    def outcome(self):
        result = self.vm.census()
        return result["terminalCount"], [(row["receipt"], row["reason"]) for row in result["unresolved"]]

    def names(self):
        return sorted(path.name for path in self.root.iterdir())

    def open_row(self, prefix):
        return [(prefix + ".intent.json", "original_guest_work_unresolved")]


@unittest.skipUnless(os.name == "posix", "POSIX private-file custody")
class LostQualificationTests(Case):
    def test_dea00558_agent_forgot_the_acknowledged_qualification_RED_unresolved_GREEN_closed(self):
        prefix = self.vm.qualification()
        self.vm.rpc = mock.Mock(side_effect=ValueError())  # the agent's own error reply: it no longer tracks this pid
        count, unresolved = self.outcome()
        self.assertEqual([], unresolved, "the lost read-only setup qualification still blocks the idle census")
        self.assertEqual(1, count)
        self.vm.rpc.assert_called_once_with("guest-exec-status", {"pid": 7777})
        self.assertEqual({"pid": 7777, **FORGOTTEN}, json.loads((self.root / (prefix + ".orphan-closed.json")).read_bytes()))
        self.assertFalse((self.root / (prefix + ".terminal.json")).exists())
        self.vm.rpc.reset_mock()
        self.assertEqual((1, []), self.outcome())
        self.vm.rpc.assert_not_called()

    def test_census_during_an_in_flight_qualification_RED_closed_before_its_ack_GREEN_open_until_its_own_end(self):
        # qualify_instance has saved its intent and .ps1; its guest-exec waits for the agent
        # socket this census holds, so no shell of it is in the census's process rows yet.
        prefix = self.vm.qualification(pid=None)
        self.assertEqual((0, self.open_row(prefix)), self.outcome(),
                         "the census closed a qualification whose guest-exec had not started")
        self.assertFalse((self.root / (prefix + ".orphan-closed.json")).exists())
        self.vm.rpc.assert_not_called()
        # Its guest-exec is acknowledged and the program runs: still open.
        self.vm.write(prefix + ".ack.json", {"operationId": NATIVE, "ack": {"pid": 7777}, "replayAllowed": False})
        self.vm.rpc = mock.Mock(return_value={"exited": False})
        self.assertEqual((0, self.open_row(prefix)), self.outcome())
        # The guest rebooted before any status kept its terminal: the agent no longer knows the
        # pid and no shell has it, so it closes by its own pid, as a lost reply of it would.
        self.vm.rpc = mock.Mock(side_effect=ValueError())
        self.assertEqual((1, []), self.outcome(), "the acknowledged qualification never closes after an early census")
        self.assertEqual({"pid": 7777, **FORGOTTEN}, json.loads((self.root / (prefix + ".orphan-closed.json")).read_bytes()))

    def test_ended_qualification_the_agent_still_holds_RED_unresolved_GREEN_retained_as_its_owners_terminal(self):
        prefix = self.vm.qualification()
        terminal = {"exited": True, "exitcode": 0, "out-data": base64.b64encode(json.dumps({"nonce": NATIVE}).encode()).decode()}
        self.vm.rpc = mock.Mock(return_value=terminal)
        count, unresolved = self.outcome()
        self.assertEqual([], unresolved, "the ended read-only setup qualification still blocks the idle census")
        self.assertEqual(1, count)
        # qualify_instance reads only <prefix>.terminal.json: its status still answers from this receipt.
        self.assertEqual(terminal, json.loads((self.root / (prefix + ".terminal.json")).read_bytes()))
        self.assertFalse((self.root / (prefix + ".observed-terminal.json")).exists())
        self.assertFalse((self.root / (prefix + ".orphan-closed.json")).exists())
        self.vm.rpc.reset_mock()
        self.assertEqual((1, []), self.outcome())
        self.vm.rpc.assert_not_called()

    def test_fixed_the_derived_check_of_a_secure_phase_closes_the_same_way(self):
        check = str(uuid.uuid5(uuid.UUID(NATIVE), "secure-setup-admission"))
        self.vm.qualification(check)
        self.vm.rpc = mock.Mock(side_effect=ValueError())
        self.assertEqual((1, []), self.outcome())


@unittest.skipUnless(os.name == "posix", "POSIX private-file custody")
class NeverClosedTests(Case):
    """Controls: they hold before and after the fix."""

    def assert_open_and_untouched(self, prefix):
        before = self.names()
        self.assertEqual((0, self.open_row(prefix)), self.outcome())
        self.assertEqual(before, self.names())

    def test_an_unacknowledged_qualification_stays_open_whether_or_not_another_shell_runs(self):
        # A lost guest-exec reply and a guest-exec that has not started yet look the same here.
        prefix = self.vm.qualification(pid=None)
        for processes in ([{"pid": 5, "name": "powershell.exe", "self": False}, {"pid": 900, "name": "powershell.exe", "self": True}],
                          [{"pid": 1, "name": "System", "self": False}, {"pid": 900, "name": "powershell.exe", "self": True}]):
            with self.subTest(processes=processes):
                self.vm.processes = processes
                self.assert_open_and_untouched(prefix)
                self.vm.rpc.assert_not_called()

    def test_a_mutating_program_under_the_qualification_name_stays_open_and_is_never_asked_about(self):
        mutating = setup_guest.secure_source(SETUP, NATIVE)
        self.assertNotEqual(setup_guest.powershell_source(SETUP, NATIVE), mutating)
        for pid in (7777, None):
            with self.subTest(pid=pid):
                for path in self.root.iterdir():
                    path.unlink()
                prefix = self.vm.qualification(script=mutating, pid=pid)  # its intent says readOnly, as every one does
                self.assert_open_and_untouched(prefix)
                self.vm.rpc.assert_not_called()

    def test_any_deviation_from_the_exact_reviewed_source_stays_open(self):
        exact = setup_guest.powershell_source(SETUP, NATIVE)
        other_accounts = setup_guest.powershell_source({**SETUP, "user": "someoneelse"}, NATIVE)
        other_operation = setup_guest.powershell_source(SETUP, "383aff75-9524-4de8-898f-536cc78a1180")
        from agent_tools import windows_visual_fixture
        visual = windows_visual_fixture.powershell_source({**SETUP, "purpose": "windowsUacVisual"}, NATIVE)
        self.assertTrue(visual.startswith(exact[:exact.index(setup_guest.READ_SETUP)]) and visual != exact)
        cases = {"appended statement": {"script": exact + "Remove-Item -LiteralPath C:\\ProgramData\\VpnControlFixture -Recurse\n"},
                 "the visual fixture's own qualification program": {"script": visual},
                 "prepended statement": {"script": "Stop-Service qemu-ga\n" + exact},
                 "another deployment's accounts": {"script": other_accounts},
                 "another operation's program": {"script": other_operation},
                 "intent not read-only": {"intent": {"readOnly": False}},
                 "intent of another operation": {"intent": {"operationId": "383aff75-9524-4de8-898f-536cc78a1180"}},
                 "intent bound to another source": {"intent": {"powerShellSha256": "0" * 64}},
                 "source not retained": {"source": False}}
        for name, change in cases.items():
            for pid in (7777, None):
                with self.subTest(case=name, pid=pid):
                    for path in self.root.iterdir():
                        path.unlink()
                    prefix = self.vm.qualification(pid=pid, **change)
                    self.assert_open_and_untouched(prefix)
                    self.vm.rpc.assert_not_called()

    def test_a_source_file_that_is_not_one_private_regular_file_stays_open(self):
        def group_readable(path):
            path.chmod(0o640)

        def linked_twice(path):
            os.link(path, path.with_name("another-name.ps1"))

        def symbolic(path):
            target = path.with_name("target.ps1")
            path.rename(target)
            path.symlink_to(target)

        for change in (group_readable, linked_twice, symbolic):
            with self.subTest(change=change.__name__):
                for path in self.root.iterdir():
                    path.unlink()
                prefix = self.vm.qualification()
                change(self.root / (prefix + ".ps1"))
                self.assert_open_and_untouched(prefix)
                self.vm.rpc.assert_not_called()

    def test_a_running_unreachable_or_refused_qualification_stays_open(self):
        prefix = self.vm.qualification()
        for answer in ({"exited": False}, OSError("reset"), TimeoutError("deadline"), ValueError("instance_qga_changed"), {"exited": True}):
            with self.subTest(answer=answer):
                self.vm.rpc = mock.Mock(return_value=answer) if type(answer) is dict else mock.Mock(side_effect=answer)
                self.assert_open_and_untouched(prefix)
        self.vm.rpc = mock.Mock(side_effect=ValueError())
        self.vm.processes = [{"pid": 7777, "name": "powershell.exe", "self": False}]
        self.assert_open_and_untouched(prefix)  # forgotten by the agent, but a shell with its pid is alive
        self.vm.processes = None
        self.assert_open_and_untouched(prefix)  # no complete process census

    def test_other_lost_guest_programs_keep_their_own_rules(self):
        operation = str(uuid.uuid4())
        for prefix in ("direct-guest-" + operation, "readiness-" + operation + "-lease-cancel"):
            with self.subTest(prefix=prefix):
                for path in self.root.iterdir():
                    path.unlink()
                self.vm.write(prefix + ".intent.json", {"operationId": operation})
                self.vm.write(prefix + ".ps1", setup_guest.powershell_source(SETUP, operation).encode())
                self.assert_open_and_untouched(prefix)
                self.vm.write(prefix + ".ack.json", {"operationId": operation, "ack": {"pid": 7777}, "replayAllowed": False})
                self.assert_open_and_untouched(prefix)
                self.vm.rpc.assert_not_called()


class ReviewedSourceTests(unittest.TestCase):
    def test_fixed_the_packet_names_exactly_the_current_setup_program(self):
        source = host_work_source()[1]
        reviewed = re.findall(r"hexdigest\(\)=='([0-9a-f]{64})'", source)
        self.assertEqual([hashlib.sha256(setup_guest.READ_SETUP.encode()).hexdigest()], reviewed,
                         "the census must name the reviewed text of windows_vm_guest.READ_SETUP")
        operation = str(uuid.uuid4())
        head = ("$ProgressPreference='SilentlyContinue'\n$ExpectedUser=" + repr(SETUP["user"]) + "\n$ExpectedAdministrator="
                + repr(SETUP["administrator"]) + "\n$OperationId=" + repr(operation) + "\n")
        self.assertEqual(head + setup_guest.READ_SETUP, setup_guest.powershell_source(SETUP, operation))

    def test_the_setup_program_only_reads(self):
        # Every cmdlet of the reviewed text. Another one needs a new review of the census rule.
        cmdlets = set(re.findall(r"\b[A-Za-z]+-[A-Z][A-Za-z]+\b", setup_guest.READ_SETUP))
        self.assertEqual({"ConvertFrom-Json", "ConvertTo-Json", "ForEach-Object", "Get-CimInstance", "Get-Content",
                          "Get-ItemProperty", "Get-LocalGroupMember", "Get-LocalUser", "Get-ScheduledTask",
                          "Get-ScheduledTaskInfo", "Get-WinSystemLocale", "Join-Path", "Test-Path"}, cmdlets)
        for word in ("Invoke-", "Start-Process", ".exe", "::Create", "::Write(", "::Delete", "::Set", ">"):
            self.assertNotIn(word, setup_guest.READ_SETUP.replace("[Console]::WriteLine(", "").replace("VpnControlFixture", ""))
        mutating = {name.split("-")[0] for name in re.findall(r"\b[A-Za-z]+-[A-Z][A-Za-z]+\b", setup_guest.SECURE_SETUP)}
        self.assertTrue({"Set", "Remove", "Disable"} <= mutating)  # the control program of this module really writes

    def test_fixed_the_generated_packet_carries_the_rule(self):
        from agent_tools.tests.test_readiness_windows import snapshot
        packet = remote.program(snapshot()["binding"], "idle-inventory", str(uuid.uuid4()), idle=True, expected_sid="S-1-5-21-1-2-3-1000",
                                lease_root_generation="12345678:0000000000000042:0000000000000001")
        self.assertIn(b"def setup_qualification(prefix):", packet)
        self.assertEqual(1, packet.count(hashlib.sha256(setup_guest.READ_SETUP.encode()).hexdigest().encode()))


if __name__ == "__main__":
    unittest.main()
