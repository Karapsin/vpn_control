"""Guest file reads through one handle: a path stat that lags the handle is no change.

Native 1ee00956 (windows-disconnected-cli-config) stopped at the first product-written
output it read: `routing export --output` exited 0 and Cases.output refused it with
output-changed-during-read, which compared the path's lstat with the handle's fstat. On
Windows, CPython can answer a path stat from the directory entry (GetFileInformationByName),
whose size and times may lag the file's own while another handle, a scanner's for one, is
open: a hypothesis no native run has proven. These tests model that split over real files:
the path stat of the one file under test reports a stale size or write time while its
handle reports the file as it is. A file that changes through its handle, or a name that
comes to denote another file, is still refused, and each refusal names its check and field.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
import uuid

from agent_tools import windows_disconnected_cli_cases as disconnected
from agent_tools import windows_document_gated_https_fixture as gated
from agent_tools import windows_document_responsive_cases as responsive

CONTENT = b'{"schemaVersion":1,"rules":["example.test"]}\n'


class PathStats:
    """os.stat and os.lstat of one file answer as a lagging directory entry would; every other call is real.

    `stale` replaces fields of that file's path stat. With `other`, from the `other_from`th path stat
    of that file on, the answer is another file's stat: the name now denotes another file.
    """

    def __init__(self, path, stale=None, other=None, other_from=1):
        self.path, self.stale, self.other, self.other_from = os.fspath(path), dict(stale or {}), other, other_from
        self.real_stat, self.real_lstat, self.calls = os.stat, os.lstat, 0

    def answer(self, value, target):
        if not isinstance(target, (str, bytes, os.PathLike)) or os.fspath(target) != self.path:
            return value
        self.calls += 1
        if self.other is not None and self.calls >= self.other_from:
            value = self.real_stat(self.other, follow_symlinks=False)
        fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
        fields.update(self.stale)
        return types.SimpleNamespace(**fields)

    def stat(self, target, *args, **kwargs):
        return self.answer(self.real_stat(target, *args, **kwargs), target)

    def lstat(self, target, *args, **kwargs):
        return self.answer(self.real_lstat(target, *args, **kwargs), target)

    def patches(self):
        return mock.patch.multiple(os, stat=self.stat, lstat=self.lstat)


class HandleChange:
    """Right after the handle's first stat, the file changes through another handle, which the handle then shows."""

    def __init__(self, path, change):
        self.path, self.change, self.real, self.calls = path, change, os.fstat, 0

    def fstat(self, fd):
        value = self.real(fd)
        self.calls += 1
        if self.calls == 1:
            self.change(self.path)
        return value

    def patches(self):
        return mock.patch.object(os, "fstat", self.fstat)


class Short:
    """A stream whose read comes back one byte shorter than the file."""

    def __init__(self, stream):
        self.stream = stream

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        return self.stream.__exit__(*args)

    def fileno(self):
        return self.stream.fileno()

    def read(self, bound=-1):
        return self.stream.read(bound)[:-1]


def grow(path):
    with open(path, "ab") as stream:
        stream.write(b"later bytes\n")


def touch(path):
    """Only the write time moves, five seconds on, as a rewrite of the same length would move it."""
    value = os.stat(path)
    os.utime(path, ns=(value.st_atime_ns, value.st_mtime_ns + 5_000_000_000))


def splits(path):
    """The split each reader may meet: a path stat with a stale size, or with a stale write time."""
    value = os.stat(path)
    return (("size", {"st_size": 0}), ("mtime_ns", {"st_mtime_ns": value.st_mtime_ns - 2_000_000_000}))


class Base(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def write(self, name, content=CONTENT):
        path = self.root / name
        path.write_bytes(content)
        return path

    def refusal(self, call, error, prefix):
        """The refusal's message; whatever the version, a refusal of this reader's own kind."""
        with self.assertRaises(error) as raised:
            call()
        message = str(raised.exception)
        self.assertTrue(message == prefix or message.startswith(prefix + ":"), message)
        return message

    def each_refusal(self, scenarios, call, error, prefix, path, named):
        """Every scenario is refused; with `named`, by the token of the check and field that saw it."""
        for check, patches in scenarios:
            with self.subTest(check=check), patches():
                message = self.refusal(call, error, prefix)
                if named:
                    self.assertEqual(prefix + ":" + check, message)
            path.write_bytes(CONTENT)


class DisconnectedOutputTests(Base):
    """Cases.output, as `routing export --output` met it natively."""

    def setUp(self):
        super().setUp()
        self.events = []
        owner = types.SimpleNamespace(event=lambda kind, value: self.events.append((kind, value)))
        self.cases = disconnected.Cases(owner, self.root / "workspace", "owner", {}, self.root)
        self.path = self.write("routing 東京 human export.json")
        self.other = self.write("another export.json", b'{"another":"file"}\n')

    def test_a_path_stat_that_lags_the_handle_is_read(self):
        for field, stale in splits(self.path):
            with self.subTest(field=field), PathStats(self.path, stale).patches():
                result = self.cases.output(self.path)
                self.assertEqual((CONTENT, hashlib.sha256(CONTENT).hexdigest()), (result["content"], result["sha256"]))
                self.assertEqual("disconnected-output", self.events[-1][0])
                self.assertIn(field, self.events[-1][1]["pathStatLag"], "the lagging field is recorded for the next native run")

    def scenarios(self):
        """Each change or other file, by the check that sees it: path stats 1 and 2 open the read, 3 closes it."""
        return (("handle-size", lambda: HandleChange(self.path, grow).patches()),
                ("handle-mtime_ns", lambda: HandleChange(self.path, touch).patches()),
                ("identity-open-ino", lambda: PathStats(self.path, other=self.other).patches()),
                ("identity-close-ino", lambda: PathStats(self.path, other=self.other, other_from=3).patches()),
                ("count-size", lambda: mock.patch.object(Path, "open", lambda path, *args, **kwargs: Short(open(path, *args, **kwargs)))))

    def test_a_file_that_changes_or_is_replaced_during_the_read_is_still_refused(self):
        self.each_refusal(self.scenarios(), lambda: self.cases.output(self.path), AssertionError, "output-changed-during-read",
                          self.path, named=False)

    def test_each_refusal_names_its_check_and_field(self):
        self.each_refusal(self.scenarios(), lambda: self.cases.output(self.path), AssertionError, "output-changed-during-read",
                          self.path, named=True)


class GatedInputTests(Base):
    """The document fixture worker's read_exact of a work input the owner published."""

    def setUp(self):
        super().setUp()
        self.path = self.write("responsive-release.json")
        self.other = self.write("another-release.json", b'{"another":"file"}\n')

    def test_a_path_stat_that_lags_the_handle_is_read(self):
        for field, stale in splits(self.path):
            with self.subTest(field=field), PathStats(self.path, stale).patches():
                self.assertEqual(CONTENT, gated.read_exact(str(self.path), 1024))

    def scenarios(self):
        return (("handle-size", lambda: HandleChange(str(self.path), grow).patches()),
                ("handle-mtime_ns", lambda: HandleChange(str(self.path), touch).patches()),
                ("identity-ino", lambda: PathStats(self.path, other=self.other).patches()))

    def test_a_change_or_another_file_is_still_refused(self):
        self.each_refusal(self.scenarios(), lambda: gated.read_exact(str(self.path), 1024), ValueError, "work-input-closing",
                          self.path, named=False)

    def test_each_refusal_names_its_check_and_field(self):
        self.each_refusal(self.scenarios(), lambda: gated.read_exact(str(self.path), 1024), ValueError, "work-input-closing",
                          self.path, named=True)


class ResponsiveReadTests(Base):
    """The responsive cases' reads of the owner's raw child streams and of the fixture's work events."""

    def setUp(self):
        super().setUp()
        self.owner = types.SimpleNamespace(root=self.root, operation=str(uuid.uuid4()), guard=lambda: None)
        self.child = types.SimpleNamespace(owner=self.owner, ordinal=0, pid=4242, birth="7")
        self.owner.children = [self.child]
        streams = {"stdout": CONTENT, "stderr": b""}
        for name, raw in streams.items():
            self.write("child-0000." + name + ".raw", raw)
        self.child.terminal = {"pid": 4242, "birthFileTimeUtc": "7", "eof": {"stdout": True, "stderr": True},
                               "sourceClosing": True, "originalHandleRetained": True,
                               "counts": {name: len(raw) for name, raw in streams.items()},
                               "sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in streams.items()}}
        self.path = self.root / "child-0000.stdout.raw"
        self.other = self.write("another.raw", b"another\n")

    def test_a_raw_stream_whose_path_stat_lags_the_handle_is_read(self):
        for field, stale in splits(self.path):
            with self.subTest(field=field), PathStats(self.path, stale).patches():
                self.assertEqual({"stdout": CONTENT, "stderr": b""}, responsive.raw_child(self.owner, self.child))

    def scenarios(self):
        return (("handle-size", lambda: HandleChange(self.path, grow).patches()),
                ("handle-mtime_ns", lambda: HandleChange(self.path, touch).patches()),
                ("identity-ino", lambda: PathStats(self.path, other=self.other).patches()))

    def test_a_raw_stream_that_changes_or_is_another_file_is_still_refused(self):
        self.each_refusal(self.scenarios(), lambda: responsive.raw_child(self.owner, self.child), AssertionError,
                          "original-public-raw-join", self.path, named=False)

    def test_each_raw_stream_refusal_names_its_check_and_field(self):
        self.each_refusal(self.scenarios(), lambda: responsive.raw_child(self.owner, self.child), AssertionError,
                          "original-public-raw-join", self.path, named=True)

    def test_a_work_event_whose_path_stat_lags_the_handle_is_read(self):
        owner = types.SimpleNamespace(operation=str(uuid.uuid4()), native=types.SimpleNamespace(birth=lambda handle: "7"))
        child = types.SimpleNamespace(pid=4242, birth="7", process=types.SimpleNamespace(poll=lambda: None, _handle=99))
        runtime = types.SimpleNamespace(data_guard=lambda who: None,
                                        OwnedData=lambda who, path, digest: types.SimpleNamespace(current=lambda: None))
        value = {"schemaVersion": 1, "operationId": owner.operation, "phase": "responsive", "pid": 4242, "requestOrdinal": 1,
                 "path": "/subscription/responsive/" + owner.operation, "status": 200}
        path = self.write("responsive-entered.json", (json.dumps(value) + "\n").encode())
        for field, stale in splits(path):
            with self.subTest(field=field), PathStats(path, stale).patches():
                lease = responsive.WorkLease(owner, child, {"pid": 4242, "operationId": owner.operation},
                                             {"readyFile": str(self.root / "ready.json")}, runtime)
                self.assertEqual(value, lease.event("responsive", "entered"))


if __name__ == "__main__":
    unittest.main()
