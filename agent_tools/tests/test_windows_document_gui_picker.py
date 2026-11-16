"""The GUI half of gui-cli-transfer: windows-document-cold.gui-picker, offline.

Nothing here reaches a VM, a desktop or Win32. The picker's session runs over Native, a model of the GUI's own
windows on its owned desktop: a home and a routing screen, the two menus and the common file dialog, drawn as
deterministic frames. The cold flow runs in the real Owner with the inert guest of test_windows_document_acceptance,
whose owners keep the committed routing rules and revision per workspace as the product persists them. What only the
guest can show (the switch of the input desktop, BitBlt of its screen, SendInput, WM_SETTEXT and WM_COMMAND IDOK in a
real common dialog, the GUI's own export and import, and the reviewed anchors themselves) is first native contact.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import native_scenario_execution as execution
from agent_tools import native_scenario_ssh as scenario_ssh
from agent_tools import native_scenario_windows as windows
from agent_tools import windows_document_cold_cases as cold_cases
from agent_tools import windows_document_gui_picker as picker
from agent_tools import windows_ordinary_process_owner as process_owner
from agent_tools import windows_scenario_host_job as host_job
from agent_tools.tests.test_windows_cli_native_failures import Clock, Parked, held_harness, run_owner
from agent_tools.tests.test_windows_document_acceptance import DOCUMENT_CASES, LAUNCHER_PATH, ColdGuest

ROW = "windows-document-cold.gui-picker"
OPERATION = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
LAUNCHER, JVM, OTHER = 7001, 7002, 9100
MAIN, DIALOG, FOREIGN = 0x100, 0x200, 0x300
EDIT, OK_BUTTON, CANCEL_BUTTON = 0x201, 0x202, 0x203
# The control each step clicks, and the screen it must be on, in screen pixels of the canonical placement.
POINTS = {"routing-nav": (180, 300), "export-menu": (420, 140), "export-file": (430, 190),
          "import-menu": (300, 140), "import-file": (310, 190)}
BEFORE = {"routing-nav": "home", "export-menu": "routing", "export-file": "export-menu", "import-menu": "routing",
          "import-file": "import-menu"}
AFTER = {"routing-nav": "routing", "export-menu": "export-menu", "export-file": "save", "import-menu": "import-menu",
         "import-file": "open"}
SCREENS = ("home", "routing", "export-menu", "import-menu", "dialog")
DIALOG_RECT = (300, 160, 940, 620)


def anchor(step):
    x, y = POINTS[step]
    return [x - 20, y - 12, x + 20, y + 12]


def render(screen, rect):
    """A frame of the model: each row of the screen's own colour shade, never one flat colour."""
    code = 40 * (SCREENS.index(screen) + 1)
    left, top, right, bottom = rect
    return b"".join(bytes((code, row % 251, (row * 7) % 253)) * (right - left) for row in range(top, bottom))


def reviewed_profile():
    """A reviewer's profile of the model: each step's anchor digest from the frame of the screen it starts on."""
    placement = picker._placement_rect()
    steps = {}
    for step in picker.STEPS:
        frame = picker.Frame(placement, render(BEFORE[step], placement))
        steps[step] = picker.review_step(picker.png(frame), placement[:2], POINTS[step], anchor(step))
    return {**picker.PROFILE, "steps": steps}


class FakeLease:
    def __init__(self):
        self.name, self.switched, self.trace = "VcParityNoTray-0123", False, []

    def show(self):
        self.switched = True
        self.trace.append("show")

    def restore(self):
        self.switched = False
        self.trace.append("restore")


class Native:
    """The GUI's windows on its owned desktop, as the picker's Win32 primitives would read and drive them."""

    def __init__(self, *, on_ok=None):
        self.screen, self.dialog, self.text = "home", None, ""
        self.window_rect = [320, 180, 1120, 780]
        self.cursor = (640, 400)
        self.clicks, self.commands, self.texts, self.trace = [], [], [], []
        self.on_ok = on_ok or (lambda kind, path: None)
        self.extra_windows, self.inserted, self.capture_change = [], 2, None
        self.display_size, self.window_dpi, self.ok_closes, self.cancel_closes = (1280, 800), 96, True, True
        self.edits = None  # None: the dialog's own one file name Edit
        self.readback = None
        self.under = None
        self.captures = 0
        self.closed = 0

    def close(self):
        self.closed += 1

    def display(self):
        return self.display_size

    def parents(self):
        return {JVM: LAUNCHER, LAUNCHER: 4, OTHER: 4}

    def windows(self):
        rows = [{"hwnd": MAIN, "pid": JVM, "threadId": 11, "class": "SunAwtFrame", "visible": True, "rect": list(self.window_rect)},
                {"hwnd": 0x101, "pid": JVM, "threadId": 12, "class": "SunAwtToolkit", "visible": False, "rect": [0, 0, 0, 0]}]
        if self.dialog is not None:
            rows.append({"hwnd": DIALOG, "pid": JVM, "threadId": 11, "class": "#32770", "visible": True, "rect": list(DIALOG_RECT)})
        return rows + list(self.extra_windows)

    def dpi(self, hwnd):
        return self.window_dpi

    def place(self, hwnd, rect):
        self.trace.append(("place", hwnd, tuple(rect)))
        self.window_rect = list(rect)
        return True, tuple(self.window_rect)

    def rect(self, hwnd):
        return tuple(DIALOG_RECT) if hwnd == DIALOG else tuple(self.window_rect)

    def capture(self, rect):
        self.captures += 1
        screen = "dialog" if self.dialog is not None and tuple(rect) == DIALOG_RECT else self.screen
        raw = render(screen, rect)
        if self.capture_change is not None:
            raw = self.capture_change(raw, self.captures)
        return raw

    def point_cursor(self, x, y):
        self.cursor = (x, y)
        self.trace.append(("cursor", x, y))
        return True, self.cursor

    def window_at(self, x, y):
        if self.under is not None:
            return self.under
        left, top, right, bottom = self.window_rect
        if left <= x < right and top <= y < bottom:
            return {"hwnd": MAIN + 1, "root": MAIN, "rootClass": "SunAwtFrame", "pid": JVM}
        return {"hwnd": 0x10010, "root": 0x10010, "rootClass": "#32769", "pid": None}

    def click(self):
        self.clicks.append(self.cursor)
        self.trace.append(("click",) + self.cursor)
        for step, point in POINTS.items():
            if point == self.cursor and BEFORE[step] == self.screen and self.dialog is None:
                after = AFTER[step]
                if after in ("save", "open"):
                    self.dialog, self.text, self.screen = after, "routing-rules.json" if after == "save" else "", "routing"
                else:
                    self.screen = after
                break
        return self.inserted, (5 if self.inserted == 0 else 0)

    def controls(self, dialog):
        identifier = picker.FILENAME_EDIT[self.dialog]
        edits = self.edits if self.edits is not None else [{"hwnd": EDIT, "class": "Edit", "id": identifier, "visible": True,
                                                            "enabled": True}]
        return [{"hwnd": 0x210, "class": "ComboBox", "id": identifier, "visible": True, "enabled": True}, *edits,
                {"hwnd": OK_BUTTON, "class": "Button", "id": 1, "visible": True, "enabled": True},
                {"hwnd": CANCEL_BUTTON, "class": "Button", "id": 2, "visible": True, "enabled": True}]

    def set_text(self, hwnd, text):
        self.texts.append((hwnd, text))
        self.text = text
        return True

    def get_text(self, hwnd):
        return self.text if self.readback is None else self.readback

    def command(self, dialog, identifier, button):
        self.commands.append((dialog, identifier, button))
        self.trace.append(("command", identifier))
        kind = self.dialog
        if identifier == picker.IDOK and self.ok_closes:
            self.dialog = None
            self.on_ok(kind, self.text)
        if identifier == picker.IDCANCEL and self.cancel_closes:
            self.dialog = None
        return True


class FakeOwner:
    def __init__(self, root):
        self.root, self.events, self.parks, self.children = root, [], [], []

    def event(self, kind, value):
        json.dumps(value)  # Every event the owner journals is JSON.
        self.events.append((kind, value))

    def park(self, reason, error=None):
        self.parks.append(reason)
        raise Parked(reason)

    def kinds(self):
        return [kind for kind, _ in self.events]


class SessionBase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = self.root = Path(temporary.name)
        self.clock = Clock()
        patcher = mock.patch.object(picker, "time", self.clock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def session(self, profile="reviewed", **options):
        self.root = Path(tempfile.mkdtemp(dir=self.base))  # One operation root per session, as one per row.
        self.owner, self.lease, self.native = FakeOwner(self.root), FakeLease(), Native(**options)
        self.child = types.SimpleNamespace(pid=LAUNCHER, process=types.SimpleNamespace(poll=lambda: None))
        return picker.Session(self.owner, self.lease, self.child, self.native, reviewed_profile() if profile == "reviewed" else profile)

    def attached(self, **options):
        session = self.session(**options)
        session.attach()
        session.show()
        return session

    def frames(self):
        return sorted(path.name for path in self.root.glob("document-gui-picker-frame-*.png"))


class ProfileAndFrameTests(SessionBase):
    def test_the_tracked_profile_is_well_formed_and_reviews_no_step_yet(self):
        picker.validate_profile(picker.PROFILE)
        self.assertEqual(picker.STEPS, tuple(picker.PROFILE["steps"]))
        self.assertEqual({None}, set(picker.PROFILE["steps"].values()), "a step is reviewed only from a native frame")

    def test_a_kept_frame_reads_back_and_its_reviewed_anchor_is_the_digest_of_those_pixels(self):
        placement = picker._placement_rect()
        frame = picker.Frame(placement, render("routing", placement))
        back = picker.read_png(picker.png(frame), placement[:2])
        self.assertEqual((frame.rect, frame.pixels), (back.rect, back.pixels))
        entry = picker.review_step(picker.png(frame), placement[:2], POINTS["export-menu"], anchor("export-menu"))
        self.assertEqual(hashlib.sha256(frame.crop(tuple(anchor("export-menu")))).hexdigest(), entry["sha256"])
        self.assertNotEqual(entry["sha256"], picker.review_step(picker.png(picker.Frame(placement, render("home", placement))),
                                                                placement[:2], POINTS["export-menu"], anchor("export-menu"))["sha256"])

    def test_a_profile_entry_whose_point_or_anchor_could_click_anything_else_is_refused(self):
        good = reviewed_profile()
        changes = {
            "point-outside-anchor": lambda entry: entry.update(point=[entry["anchor"][2], entry["point"][1]]),
            "anchor-outside-placement": lambda entry: entry.update(anchor=[100, 10, 160, 40], point=[120, 20]),
            "anchor-too-small": lambda entry: entry.update(anchor=[entry["point"][0], entry["point"][1], entry["point"][0] + 4,
                                                                   entry["point"][1] + 4]),
            "anchor-too-large": lambda entry: entry.update(anchor=[140, 16, 1140, 736]),
            "digest": lambda entry: entry.update(sha256="0" * 63),
            "extra": lambda entry: entry.update(button="right"),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                profile = json.loads(json.dumps(good))
                change(profile["steps"]["export-menu"])
                with self.assertRaisesRegex(RuntimeError, "document-gui-picker-profile"):
                    picker.validate_profile(profile)
        for name, change in {"order": lambda p: p.update(steps=dict(reversed(list(p["steps"].items())))),
                             "placement": lambda p: p.update(placement=[0, 0, 1000, 720]),
                             "display": lambda p: p.update(display=[1920, 1080])}.items():
            with self.subTest(change=name):
                profile = json.loads(json.dumps(good))
                change(profile)
                with self.assertRaisesRegex(RuntimeError, "document-gui-picker-profile-schema"):
                    picker.validate_profile(profile)

    def test_only_this_modules_own_frames_read_back(self):
        frame = picker.Frame((0, 0, 4, 2), bytes(range(24)))
        raw = picker.png(frame)
        for changed in (raw[:8] + b"X" + raw[9:], raw[:-1], raw.replace(b"IEND", b"IENX")):
            with self.assertRaisesRegex(RuntimeError, "document-gui-picker-png"):
                picker.read_png(changed, (0, 0))


class ExportComparisonTests(unittest.TestCase):
    def export(self, suffixes, at, tail=""):
        body = ",".join('\n      "' + value + '"' for value in suffixes)
        return ('{\n  "type": "vpn_control_routing_rules",\n  "version": 7,\n  "exported_at": "' + at + '",\n  "rules": {\n'
                '    "ignore_rules": false,\n    "block_quic_udp_443": false,\n    "proxy_packages": [],\n    "direct_domain_suffixes": ['
                + body + "\n    ]\n  }\n}" + tail).encode("ascii")

    def test_the_gui_export_is_the_cli_export_but_for_the_moment_each_was_written(self):
        names = host_job.picker_suffixes("first", 3)
        same, compared = picker.same_export(self.export(names, "2026-11-17T10:00:00.123Z"), self.export(names, "2026-11-17T10:00:07Z"))
        self.assertTrue(same)
        self.assertEqual(("2026-11-17T10:00:00.123Z", "2026-11-17T10:00:07Z"), (compared["guiExportedAt"], compared["cliExportedAt"]))
        self.assertEqual(1, len(set(compared["withoutExportedAtSha256"])))

    def test_any_other_byte_is_a_difference(self):
        names = host_job.picker_suffixes("first", 3)
        cli = self.export(names, "2026-11-17T10:00:07Z")
        for gui in (self.export(names, "2026-11-17T10:00:00Z", tail="\n"), self.export(names[:2], "2026-11-17T10:00:00Z"),
                    self.export(names, "2026-11-17T10:00:00Z").replace(b"\n", b"\r\n"),
                    self.export(list(reversed(names)), "2026-11-17T10:00:00Z")):
            self.assertFalse(picker.same_export(gui, cli)[0])

    def test_an_export_without_exactly_one_exported_at_in_its_place_differs_and_a_cli_one_is_refused(self):
        names = host_job.picker_suffixes("first", 1)
        good = self.export(names, "2026-11-17T10:00:07Z")
        for bad in (good.replace(b'  "exported_at": "2026-11-17T10:00:07Z",\n', b""),
                    good.replace(b'"rules": {', b'"exported_at": "2026-11-17T10:00:07Z",\n  "rules": {'),
                    good.replace(b"2026-11-17T10:00:07Z", b"yesterday")):
            same, compared = picker.same_export(bad, good)
            self.assertEqual((False, None), (same, compared["guiExportedAt"]))
            with self.assertRaisesRegex(RuntimeError, "document-gui-picker-exported-at"):
                picker.same_export(good, bad)

    def test_the_routing_state_is_the_committed_rules_only(self):
        workspace = {"format": 1, "persisted_state": {"routing_rules": {"ignore_rules": False, "direct_domain_suffixes": ["a.invalid"]},
                                                       "app_language": "SYSTEM"}}
        state = picker.routing_state(json.dumps(workspace).encode())
        workspace["persisted_state"]["app_language"] = "DE"
        self.assertEqual(state, picker.routing_state(json.dumps(workspace).encode()))
        workspace["persisted_state"]["routing_rules"]["ignore_rules"] = True
        self.assertNotEqual(state, picker.routing_state(json.dumps(workspace).encode()))
        with self.assertRaisesRegex(RuntimeError, "document-gui-picker-workspace-shape"):
            picker.routing_state(b'{"persisted_state": {}}')


class ReviewedStepTests(SessionBase):
    def test_both_transfers_click_only_reviewed_points_each_after_its_own_kept_frame(self):
        session = self.attached()
        session.export_file(str(self.root / "gui.json"))
        session.import_file(str(self.root / "cli.json"))
        self.assertEqual([POINTS[step] for step in picker.STEPS], self.native.clicks)
        self.assertEqual(list(picker.STEPS), session.steps)
        self.assertEqual([(EDIT, str(self.root / "gui.json")), (EDIT, str(self.root / "cli.json"))], self.native.texts)
        self.assertEqual([(DIALOG, picker.IDOK, OK_BUTTON)] * 2, self.native.commands)
        kinds = self.owner.kinds()
        for step in picker.STEPS:
            frame = [index for index, (kind, value) in enumerate(self.owner.events) if kind == "document-gui-picker-frame"
                     and value["step"] == step]
            intent = [index for index, (kind, value) in enumerate(self.owner.events) if kind == "document-gui-picker-click-intent"
                      and value["step"] == step]
            self.assertEqual(1, len(frame) * len(intent))
            self.assertLess(frame[0], intent[0], "the frame is kept before its click")
        # Before every click the pointer rests on the bare desktop, then moves to the reviewed point alone.
        cursor = [item for item in self.native.trace if item[0] in ("cursor", "click")]
        for index, item in enumerate(cursor):
            if item[0] == "click":
                self.assertEqual(("cursor",) + item[1:], cursor[index - 1])
                self.assertEqual(("cursor",) + picker.PARK, cursor[index - 2])
        self.assertEqual(9, len(self.frames()), "five steps and two frames of each dialog")
        self.assertEqual(["show"], self.lease.trace)
        self.assertEqual(("place", MAIN, picker._placement_rect()), self.native.trace[0])
        self.assertNotIn("document-gui-picker-unreviewed", kinds)

    def test_a_step_with_no_review_keeps_its_frame_and_clicks_nothing(self):
        session = self.attached(profile=picker.PROFILE)
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-frame-unreviewed:routing-nav\Z"):
            session.export_file(str(self.root / "gui.json"))
        self.assertEqual(([], []), (self.native.clicks, self.native.texts))
        self.assertEqual(["document-gui-picker-frame-00-routing-nav.png"], self.frames())
        frame = dict(self.owner.events)["document-gui-picker-frame"]
        placement = picker._placement_rect()
        raw = (self.root / frame["name"]).read_bytes()
        self.assertEqual(list(placement), frame["rect"])
        self.assertEqual(hashlib.sha256(render("home", placement)).hexdigest(), frame["pixelsSha256"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), frame["pngSha256"])
        self.assertTrue(dict(self.owner.events)["document-gui-picker-unreviewed"]["clicked"] is False)

    def test_a_frame_other_than_the_reviewed_one_clicks_nothing(self):
        # The GUI is not on the screen the review saw: a menu left open, another screen or a redrawn control.
        session = self.attached()
        self.native.screen = "routing"
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-anchor-mismatch:routing-nav\Z"):
            session.export_file(str(self.root / "gui.json"))
        self.assertEqual([], self.native.clicks)
        self.assertNotIn(("cursor",) + POINTS["routing-nav"], self.native.trace, "the pointer never went to the point")

    def test_a_window_of_any_other_process_on_the_desktop_stops_the_row_before_any_click(self):
        session = self.attached()
        self.native.extra_windows = [{"hwnd": FOREIGN, "pid": OTHER, "threadId": 99, "class": "ConsoleWindowClass", "visible": True,
                                      "rect": [0, 0, 200, 100]}]
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-foreign-window:routing-nav\Z"):
            session.export_file(str(self.root / "gui.json"))
        self.assertEqual(([], []), (self.native.clicks, self.frames()))

    def test_a_point_over_a_window_of_another_process_is_never_clicked(self):
        session = self.attached()
        original = self.native.window_at

        def at(x, y):
            value = original(x, y)
            return {**value, "pid": OTHER} if (x, y) == POINTS["routing-nav"] else value
        self.native.window_at = at
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-point-not-owned:routing-nav\Z"):
            session.export_file(str(self.root / "gui.json"))
        self.assertEqual([], self.native.clicks)

    def test_a_pointer_that_cannot_rest_on_the_bare_desktop_stops_before_any_frame(self):
        session = self.attached()
        self.native.under = {"hwnd": FOREIGN, "root": FOREIGN, "rootClass": "SunAwtFrame", "pid": JVM}
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-park\Z"):
            session.export_file(str(self.root / "gui.json"))
        self.assertEqual(([], []), (self.native.clicks, self.frames()))

    def test_a_pointer_that_did_not_reach_the_point_is_never_clicked(self):
        session = self.attached()
        original = self.native.point_cursor
        self.native.point_cursor = lambda x, y: (True, (x + 1, y)) if (x, y) == POINTS["routing-nav"] else original(x, y)
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-point-not-owned:routing-nav\Z"):
            session.export_file(str(self.root / "gui.json"))
        self.assertEqual([], self.native.clicks)

    def test_a_click_sendinput_inserted_only_in_part_parks_and_is_never_sent_again(self):
        session = self.attached()
        self.native.inserted = 1
        with self.assertRaises(Parked):
            session.export_file(str(self.root / "gui.json"))
        self.assertEqual((["document-gui-picker-click-outcome-unknown"], 1), (self.owner.parks, len(self.native.clicks)))

    def test_a_click_sendinput_inserted_nothing_of_is_a_known_refusal_naming_its_error(self):
        session = self.attached()
        self.native.inserted = 0
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-click-refused:routing-nav\Z"):
            session.export_file(str(self.root / "gui.json"))
        self.assertEqual(([], 5), (self.owner.parks, dict(self.owner.events)["document-gui-picker-click-refused"]["winerror"]))
        self.assertNotIn("document-gui-picker-clicked", self.owner.kinds())

    def test_a_frame_that_never_settles_or_shows_one_colour_clicks_nothing(self):
        for name, change, code in (("unstable", lambda raw, count: raw[:-1] + bytes((count % 256,)), "unstable"),
                                   ("blank", lambda raw, count: b"\x00" * len(raw), "blank")):
            with self.subTest(case=name):
                session = self.attached()
                self.native.capture_change = change
                with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-frame-%s:routing-nav\Z" % code):
                    session.export_file(str(self.root / ("gui-%s.json" % name)))
                self.assertEqual([], self.native.clicks)
                self.assertTrue(any(value["step"] == "routing-nav" for kind, value in self.owner.events
                                    if kind == "document-gui-picker-frame"), "the last frame is kept as evidence")

    def test_a_main_window_moved_or_a_dialog_already_open_stops_before_the_step(self):
        session = self.attached()
        self.native.window_rect = [141, 16, 1141, 736]
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-main-window-changed:routing-nav\Z"):
            session.export_file(str(self.root / "gui.json"))
        session = self.attached()
        self.native.dialog = "save"
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-dialog-before:routing-nav\Z"):
            session.export_file(str(self.root / "gui.json"))
        self.assertEqual([], self.native.clicks)


class AttachTests(SessionBase):
    def test_a_display_other_than_the_canonical_one_refuses_before_the_switch(self):
        for name, change in (("size", lambda native: setattr(native, "display_size", (1920, 1080))),
                             ("dpi", lambda native: setattr(native, "window_dpi", 120))):
            with self.subTest(change=name):
                session = self.session()
                change(self.native)
                with self.assertRaisesRegex(RuntimeError, "document-gui-picker-display-not-canonical"):
                    session.attach()
                self.assertEqual([], self.lease.trace)

    def test_a_placement_that_did_not_hold_is_a_known_failure(self):
        session = self.session()
        session.attach()
        self.native.place = lambda hwnd, rect: (True, (rect[0], rect[1], rect[2], rect[3] - 1))
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-placement\Z"):
            session.show()

    def test_no_main_window_within_the_bound_is_a_known_failure_naming_the_windows(self):
        session = self.session()
        self.native.windows = lambda: [{"hwnd": 0x101, "pid": JVM, "threadId": 12, "class": "SunAwtToolkit", "visible": False,
                                        "rect": [0, 0, 0, 0]}]
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-window-unresolved\Z"):
            session.attach()
        self.assertIn("document-gui-picker-window-unresolved", self.owner.kinds())
        self.assertEqual([], self.lease.trace)


class DialogTests(SessionBase):
    def to_dialog(self, **options):
        session = self.attached(**options)
        for step in picker.EXPORT_STEPS:
            session.step(step)
        return session

    def test_a_dialog_without_exactly_one_file_name_edit_is_a_known_failure_with_its_controls(self):
        for name, edits in (("none", []), ("two", [{"hwnd": EDIT, "class": "Edit", "id": 1001, "visible": True, "enabled": True},
                                                    {"hwnd": EDIT + 9, "class": "Edit", "id": 1001, "visible": True, "enabled": True}]),
                            ("open-id", [{"hwnd": EDIT, "class": "Edit", "id": 1148, "visible": True, "enabled": True}])):
            with self.subTest(edits=name):
                session = self.to_dialog()
                self.native.edits = edits
                with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-dialog-controls:save\Z"):
                    session.choose("save", str(self.root / "gui.json"))
                self.assertEqual(([], []), (self.native.texts, self.native.commands))
                self.assertIn("document-gui-picker-dialog-controls", self.owner.kinds())

    def test_a_file_name_that_does_not_read_back_is_never_confirmed(self):
        session = self.to_dialog()
        self.native.readback = "C:\\other.json"
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-filename-readback:save\Z"):
            session.choose("save", str(self.root / "gui.json"))
        self.assertEqual([], self.native.commands)

    def test_a_dialog_that_stays_after_its_ok_is_cancelled_once_by_the_closing_and_the_desktop_restored(self):
        session = self.to_dialog()
        self.native.ok_closes = False
        with self.assertRaisesRegex(RuntimeError, r"\Adocument-gui-picker-dialog-stayed:save\Z"):
            session.choose("save", str(self.root / "gui.json"))
        done = session.close_known()
        self.assertEqual({"dialogCancelled": True, "restored": True}, done)
        self.assertEqual([(DIALOG, picker.IDOK, OK_BUTTON), (DIALOG, picker.IDCANCEL, 0)], self.native.commands)
        self.assertEqual(["show", "restore"], self.lease.trace)
        self.assertEqual({"dialogCancelled": False, "restored": False}, session.close_known(), "the closing runs once")

    def test_a_cancel_that_does_not_close_the_dialog_parks(self):
        session = self.to_dialog()
        self.native.ok_closes = self.native.cancel_closes = False
        with self.assertRaises(RuntimeError):
            session.choose("save", str(self.root / "gui.json"))
        with self.assertRaises(Parked):
            session.close_known()
        self.assertEqual(["document-gui-picker-dialog-cancel-unknown"], self.owner.parks)
        self.assertEqual(["show"], self.lease.trace, "the desktop stays as it is for reading the original")

    def test_the_closing_cancels_only_the_guis_own_dialog_beside_another_processs_window(self):
        session = self.to_dialog()
        self.native.extra_windows = [{"hwnd": FOREIGN, "pid": OTHER, "threadId": 99, "class": "#32770", "visible": True,
                                      "rect": [0, 0, 300, 200]}]
        self.assertEqual({"dialogCancelled": True, "restored": True}, session.close_known())
        self.assertEqual([(DIALOG, picker.IDCANCEL, 0)], self.native.commands)
        self.assertEqual(["show", "restore"], self.lease.trace)

    def test_the_closing_of_a_failure_with_no_dialog_only_restores_the_desktop(self):
        session = self.attached()
        self.assertEqual({"dialogCancelled": False, "restored": True}, session.close_known())
        self.assertEqual(([], 1), (self.native.commands, self.native.closed))


# ---- The cold flow in the real owner ---------------------------------------------------------------------------------

def export_bytes(suffixes, at):
    body = ",".join('\n      "' + value + '"' for value in suffixes)
    return ('{\n  "type": "vpn_control_routing_rules",\n  "version": 7,\n  "exported_at": "' + at + '",\n  "rules": {\n'
            '    "ignore_rules": false,\n    "block_quic_udp_443": false,\n    "proxy_packages": [],\n    "direct_domain_suffixes": ['
            + body + ("\n    " if suffixes else "") + ']\n  }\n}').encode("ascii")


class PickerGuest(ColdGuest):
    """The inert guest whose owners keep the committed rules and revision per workspace, and write workspace.json."""

    def __init__(self, root, **options):
        super().__init__(root, **options)
        self.revision, self.moment = {}, 0
        self.extra_rules = {}

    def commit(self, workspace, suffixes, extra=None):
        self.routing[workspace] = list(suffixes)
        self.revision[workspace] = self.revision.get(workspace, 43) + 1
        rules = {"ignore_rules": False, "block_quic_udp_443": False, "proxy_packages": [], "direct_domain_suffixes": list(suffixes),
                 **(extra or {})}
        Path(workspace).mkdir(exist_ok=True)
        (Path(workspace) / "workspace.json").write_text(json.dumps({"format": 1, "persisted_state": {"routing_rules": rules}}))

    def export_now(self, workspace):
        self.moment += 1
        return export_bytes(self.routing.get(workspace, []), "2026-11-17T10:%02d:%02d.%03dZ" % (self.moment // 60, self.moment % 60,
                                                                                             self.moment))

    def public(self, argv):
        workspace, rest = argv[2], list(argv[3:])
        serve = self.serve_of(workspace)
        controller = None if serve is None or serve.ordinal in self.quit_generations else self.generations[serve.ordinal]
        revision = self.revision.get(workspace, 43)
        if rest in (["--json", "status"], ["--json", "--controller-id", controller, "status"]) and controller is not None:
            return 0, self.envelope("OK", controller, {"runtimeRunning": False}, configurationRevision=revision), ""
        if rest[:3] == ["--json", "--controller-id", controller] and rest[3:5] == ["--if-revision", str(revision)] \
                and rest[5:8] == ["routing", "import", "--input"]:
            value = json.loads(Path(rest[8]).read_bytes())
            self.commit(workspace, host_job.normalized_suffixes(value["rules"]["direct_domain_suffixes"]))
            self.imports.append((controller, rest[8]))
            return 0, self.envelope("OK", controller, configurationRevision=self.revision[workspace]), ""
        if rest[:3] == ["--json", "--controller-id", controller] and rest[3:6] == ["routing", "export", "--output"]:
            raw = self.export_now(workspace)
            Path(rest[6]).write_bytes(raw)
            self.exports.append((controller, rest[6]))
            return 0, self.envelope("OK", controller, {"bytes": len(raw)}, configurationRevision=revision), ""
        return super().public(argv)


class Held:
    def __init__(self, native, path, directory=False, write=False, share=1):
        self.path = Path(path)

    def bytes(self, maximum=64 * 1024 * 1024, stable_content=True):
        return self.path.read_bytes()

    def current(self, stable_content=True):
        return {}

    def close(self):
        pass


class PickerFlowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_picker(self, *, on_ok=None, profile="reviewed", desktop=None, literal_change=None, session_error=None):
        guest = PickerGuest(Path(tempfile.mkdtemp(dir=self.root)))
        workspace = str(guest.root / "workspace")
        temp = guest.root / "document-temp"
        temp.mkdir()
        large = guest.root / "document-large-routing.json"
        large.write_bytes(host_job.document_input(entries=4))
        paths = {"file:picker": str(guest.root / "windows_document_gui_picker.py"),
                 "file:pickerDesktop": str(guest.root / "windows_no_tray_desktop.py"),
                 "file:pickerFirst": str(guest.root / "document-picker-first.json"),
                 "file:pickerSecond": str(guest.root / "document-picker-second.json")}
        for role, _, label in host_job.PICKER_INPUTS:
            Path(paths["file:" + role]).write_bytes(host_job.picker_input(label))
        literal = json.loads(host_job.cold_input({"document": {"variant": "gui-picker"}}, paths, OPERATION))
        if literal_change is not None:
            literal_change(literal)
        raw = (json.dumps(literal, sort_keys=True) + "\n").encode()
        native = Native(on_ok=lambda kind, path: (on_ok or self.product_ok)(guest, workspace, kind, path))
        if desktop is not None:
            desktop(native)
        self.native, self.lease = native, FakeLease()

        def pin(data, path):
            return types.SimpleNamespace(path=path, record={"sha256": hashlib.sha256(data).hexdigest()}, current=lambda: None,
                                         digest=lambda return_bytes=False, maximum=0: data)

        def start(owner, desktop_module, gui_path, workspace_path):
            child = owner.child(picker.LABEL, [str(gui_path), "--state-dir", str(workspace_path)], owned_desktop=self.lease)
            return self.lease, child

        def session(owner, lease, child, profile_value=None):
            if session_error is not None:
                raise RuntimeError(session_error)
            native.child_pid = child.pid
            return picker.Session(owner, lease, types.SimpleNamespace(pid=LAUNCHER, process=child.process), native,
                                  reviewed_profile() if profile == "reviewed" else profile)
        gui_module = types.SimpleNamespace(start=start, session=session, same_export=picker.same_export,
                                           routing_state=picker.routing_state)
        windows_module = types.SimpleNamespace(Held=Held)
        harness = types.SimpleNamespace(**held_harness())
        original_owner = guest.owner

        def owner_with_inputs(module, action, situation):
            owner = original_owner(module, action, situation)
            owner.request["cliPath"] = guest.cli = LAUNCHER_PATH
            guest.gui = str(Path(LAUNCHER_PATH).with_name("vpn-control.exe"))
            owner.request["documentAcceptance"] = {"schemaVersion": 1, "clientPath": "client.py", "windowsPath": "windows.py",
                                                   "racePath": "race.py", "largeRoutingInputPath": str(large), "spoolTempParent": str(temp),
                                                   "contexts": host_job.document_contexts(OPERATION), "endpointPinBeforeObservation": None}
            owner.operation = OPERATION
            owner.pins = [types.SimpleNamespace(directory=True, path=temp, current=lambda: None)]
            owner.by_path.update({str(Path(cold_cases.__file__).with_name(cold_cases.INPUT_LEAF)).casefold(): pin(raw, None),
                                  guest.gui.casefold(): pin(b"MZ", guest.gui),
                                  **{value.casefold(): pin(b"held", value) for value in paths.values()}})

            def module_peer(path, name):
                if path == DOCUMENT_CASES:
                    return types.SimpleNamespace(configure_launch=cold_cases.configure_launch, run=cold_cases.run,
                                                 close_known=cold_cases.close_known)
                if path == "windows.py":
                    return windows_module
                if path == paths["file:picker"]:
                    return gui_module
                if path == paths["file:pickerDesktop"]:
                    return types.SimpleNamespace()
                return harness
            owner.module = module_peer
            return owner
        guest.owner = owner_with_inputs
        with mock.patch.object(cold_cases, "time", guest.clock), mock.patch.object(process_owner, "time", guest.clock), \
                mock.patch.object(picker, "time", guest.clock):
            try:
                code = run_owner(process_owner, guest, "document-acceptance", None)
            except Parked:
                code = None
        self.guest, self.workspace, self.paths = guest, workspace, paths
        return guest, code

    @staticmethod
    def product_ok(guest, workspace, kind, path):
        """The product after its dialog's OK: a save writes its export of the committed rules, an open imports the file."""
        if kind == "save":
            Path(path).write_bytes(guest.export_now(workspace))
        else:
            value = json.loads(Path(path).read_bytes())
            guest.commit(workspace, host_job.normalized_suffixes(value["rules"]["direct_domain_suffixes"]))

    def events(self, kind):
        return [value for name, value in self.guest.events if name == kind]

    def test_the_gui_and_the_cli_transfer_the_same_document_and_each_reads_the_others_file(self):
        guest, code = self.run_picker()
        self.assertEqual((0, [], [(0, "NoneType", "None")]), (code, guest.parks, guest.finished))
        root = guest.root
        exported = self.events("document-gui-picker-export-compared")[0]
        self.assertTrue(exported["same"])
        self.assertNotEqual(exported["guiExportedAt"], exported["cliExportedAt"])
        self.assertNotEqual(exported["guiSha256"], exported["cliSha256"], "the moments differ, nothing else")
        imported = self.events("document-gui-picker-import-compared")[0]
        self.assertTrue(imported["same"])
        self.assertEqual(host_job.PICKER_ENTRIES, imported["gui"]["suffixes"])
        first, second = guest.generations[guest.owners(self.workspace)[0].ordinal], guest.generations[guest.owners(self.workspace)[1].ordinal]
        # The CLI read the GUI's export, and the GUI read the CLI's.
        self.assertIn((second, str(root / "document-picker-gui-first.json")), guest.imports)
        self.assertEqual([str(root / "document-picker-gui-first.json"), str(root / "document-picker-cli-second.json")],
                         [text for _, text in self.native.texts])
        self.assertEqual([(first, self.paths["file:pickerFirst"]), (second, self.paths["file:pickerSecond"]),
                          (second, str(root / "document-picker-gui-first.json")), (second, str(root / "document-picker-gui-first.json")),
                          (second, str(root / "document-picker-cli-second.json"))], guest.imports)
        self.assertEqual([POINTS[step] for step in picker.STEPS], self.native.clicks)
        self.assertEqual(["show", "restore"], self.lease.trace, "the input desktop is Default again before the owner's quit")
        observed = self.events("document-cold-observed")[0]
        self.assertEqual(("gui-picker", second, list(picker.STEPS), False),
                         (observed["variant"], observed["controllerId"], observed["steps"], observed["nativeAcceptanceComplete"]))
        self.assertEqual(["quit", "quit"], [row[0] for row in guest.trace if row[0] == "quit"], "the original's and the GUI's")
        gui = next(child for child in guest.owner_object.children if child.label == picker.LABEL)
        self.assertEqual((guest.gui, "--state-dir", self.workspace), gui.argv)
        self.assertTrue(all(child.terminal is not None for child in guest.owner_object.children))

    def test_a_gui_export_that_differs_by_any_other_byte_is_a_known_failure_that_closes_the_gui(self):
        def ok(guest, workspace, kind, path):
            if kind == "save":
                Path(path).write_bytes(guest.export_now(workspace) + b"\n")
            else:
                self.product_ok(guest, workspace, kind, path)
        guest, code = self.run_picker(on_ok=ok)
        self.assertEqual((1, [], "document-gui-picker-export-bytes"), (code, guest.parks, guest.finished[0][2]))
        self.assertFalse(self.events("document-gui-picker-export-compared")[0]["same"])
        closing = [kind for kind, _ in guest.events if kind.startswith(("known-failure", "document-gui-owner", "document-gui-picker-closed"))]
        self.assertEqual(["document-gui-picker-closed", "document-gui-owner-quit-intent", "document-gui-owner-closed",
                          "known-failure-closing", "known-failure-closed"], closing)
        self.assertEqual(["show", "restore"], self.lease.trace)
        self.assertEqual(3, len(self.native.clicks), "the import steps never ran")

    def test_a_gui_import_that_never_commits_is_a_known_failure(self):
        def ok(guest, workspace, kind, path):
            if kind == "save":
                self.product_ok(guest, workspace, kind, path)
        guest, code = self.run_picker(on_ok=ok)
        self.assertEqual((1, [], "document-gui-picker-gui-import-not-committed"), (code, guest.parks, guest.finished[0][2]))
        self.assertEqual(["show", "restore"], self.lease.trace)

    def test_a_gui_import_that_commits_other_rules_than_the_files_is_a_known_failure(self):
        def ok(guest, workspace, kind, path):
            if kind == "open":
                value = json.loads(Path(path).read_bytes())
                guest.commit(workspace, value["rules"]["direct_domain_suffixes"][1:])
            else:
                self.product_ok(guest, workspace, kind, path)
        guest, code = self.run_picker(on_ok=ok)
        self.assertEqual((1, [], "document-gui-picker-cli-export-gui-import"), (code, guest.parks, guest.finished[0][2]))

    def test_a_gui_import_whose_committed_state_differs_from_the_clis_import_of_the_same_file_is_a_known_failure(self):
        def ok(guest, workspace, kind, path):
            if kind == "open":
                value = json.loads(Path(path).read_bytes())
                guest.commit(workspace, host_job.normalized_suffixes(value["rules"]["direct_domain_suffixes"]),
                             extra={"block_quic_udp_443": True})
            else:
                self.product_ok(guest, workspace, kind, path)
        guest, code = self.run_picker(on_ok=ok)
        self.assertEqual((1, [], "document-gui-picker-import-state"), (code, guest.parks, guest.finished[0][2]))
        compared = self.events("document-gui-picker-import-compared")[0]
        self.assertNotEqual(compared["gui"]["routingRulesSha256"], compared["cli"]["routingRulesSha256"])
        self.assertEqual(compared["gui"]["exportSemanticSha256"], compared["cli"]["exportSemanticSha256"])

    def test_an_unreviewed_profile_ends_known_at_the_first_step_with_its_frame_and_no_click(self):
        guest, code = self.run_picker(profile=picker.PROFILE)
        self.assertEqual((1, [], "document-gui-picker-frame-unreviewed:routing-nav"), (code, guest.parks, guest.finished[0][2]))
        self.assertEqual(([], []), (self.native.clicks, self.native.texts))
        self.assertEqual(["document-gui-picker-frame-00-routing-nav.png"],
                         sorted(path.name for path in guest.root.glob("document-gui-picker-frame-*")))
        self.assertTrue(re.fullmatch(host_job.EVIDENCE_NAME, "document-gui-picker-frame-00-routing-nav.png"),
                        "the evidence zip collects the frame a reviewer opens")
        self.assertEqual(["show", "restore"], self.lease.trace)
        self.assertTrue(all(child.terminal is not None for child in guest.owner_object.children), "the GUI was quit")

    def test_a_dialog_left_open_by_a_failure_is_cancelled_before_the_gui_is_quit(self):
        guest, code = self.run_picker(desktop=lambda native: setattr(native, "ok_closes", False))
        self.assertEqual((1, [], "document-gui-picker-dialog-stayed:save"), (code, guest.parks, guest.finished[0][2]))
        kinds = [kind for kind, _ in guest.events]
        self.assertLess(kinds.index("document-gui-picker-dialog-cancel-intent"), kinds.index("document-gui-owner-quit-intent"))
        self.assertEqual([picker.IDOK, picker.IDCANCEL], [identifier for _, identifier, _ in self.native.commands])

    def test_a_picker_that_cannot_open_its_desktop_handle_still_closes_the_gui_it_started(self):
        guest, code = self.run_picker(session_error="document-gui-picker-input-desktop-open")
        self.assertEqual((1, [], "document-gui-picker-input-desktop-open"), (code, guest.parks, guest.finished[0][2]))
        self.assertEqual(([], []), (self.lease.trace, self.native.clicks))
        self.assertIn("document-gui-owner-closed", [kind for kind, _ in guest.events])
        self.assertTrue(all(child.terminal is not None for child in guest.owner_object.children))

    def test_a_literal_naming_other_modules_or_one_document_twice_refuses_before_any_effect(self):
        for name, change in (
                ("module-leaf", lambda literal: literal["picker"].update(modulePath=literal["picker"]["firstInputPath"])),
                ("same-document", lambda literal: literal["picker"].update(secondInputPath=literal["picker"]["firstInputPath"])),
                ("same-digest", lambda literal: literal["picker"].update(secondSemanticSha256=literal["picker"]["firstSemanticSha256"])),
                ("unheld", lambda literal: literal["picker"].update(secondInputPath="C:\\Windows\\win.ini")),
                ("extra", lambda literal: literal.update(routingInputPath="x"))):
            with self.subTest(change=name):
                guest, code = self.run_picker(literal_change=change)
                self.assertEqual((1, [], "document-cold-input-schema"), (code, guest.parks, guest.finished[0][2]))
                self.assertEqual(([], []), (guest.imports, self.native.clicks))


class RowTests(unittest.TestCase):
    def test_gui_cli_transfer_is_the_cli_half_and_the_gui_half(self):
        self.assertEqual(("windows-document-cold.gui-owner", ROW),
                         windows.MATRIX_SCENARIOS["document-persistence-transfer"]["gui-cli-transfer"])

    def test_the_row_is_an_admitted_cold_variant_with_the_picker_modules_and_its_two_documents(self):
        self.assertIn("gui-picker", cold_cases.VARIANTS)
        self.assertIn("gui-picker", windows.DOCUMENT_COLD_VARIANTS)
        self.assertIn(ROW, execution.WINDOWS_SCENARIOS)
        row = windows.RECIPES[ROW]
        self.assertEqual((None, "document-acceptance", "product"), (row["refusal"], row["workerAction"], row["evidenceClass"]))
        self.assertEqual({"variant": "gui-picker", "principalProbe": False, "rootSubfolders": ("document-temp",)}, row["document"])
        files = {role: relative for relative, role, _ in row["guestFiles"]}
        self.assertEqual(("agent_tools/windows_document_cold_cases.py", "agent_tools/windows_document_gui_picker.py",
                          "agent_tools/windows_no_tray_desktop.py"), (files["cases"], files["picker"], files["pickerDesktop"]))
        self.assertEqual((("pickerFirst", "document-picker-first.json"), ("pickerSecond", "document-picker-second.json"),
                          ("coldInput", "document-cold-input.json")), tuple(row["generated"]))
        self.assertEqual(frozenset({"bundleManifest", "scenarioInput", "targetPackage"}), scenario_ssh.SCENARIO_ARTIFACT_KEYS[ROW])
        self.assertEqual(("bundleManifest", "scenarioInput", "targetPackage"), row["artifactKeys"])

    def test_the_two_documents_are_distinct_exports_whose_digests_the_literal_names(self):
        first, second = (host_job.picker_input(label) for label in ("first", "second"))
        self.assertNotEqual(first, second)
        for label, raw in (("first", first), ("second", second)):
            value = json.loads(raw)
            self.assertEqual(("vpn_control_routing_rules", 7, host_job.PICKER_ENTRIES),
                             (value["type"], value["version"], len(value["rules"]["direct_domain_suffixes"])))
            self.assertEqual((host_job.routing_semantic_sha256(host_job.picker_suffixes(label)), host_job.PICKER_ENTRIES),
                             cold_cases.semantic_sha256(raw))
        paths = {"file:picker": "C:\\w\\windows_document_gui_picker.py", "file:pickerDesktop": "C:\\w\\windows_no_tray_desktop.py",
                 "file:pickerFirst": "C:\\w\\document-picker-first.json", "file:pickerSecond": "C:\\w\\document-picker-second.json"}
        literal = json.loads(host_job.cold_input({"document": {"variant": "gui-picker"}}, paths, OPERATION))
        self.assertEqual({"schemaVersion", "variant", "operationId", "picker"}, set(literal))
        self.assertEqual(cold_cases.PICKER_FIELDS, set(literal["picker"]))
        self.assertEqual(cold_cases.semantic_sha256(first)[0], literal["picker"]["firstSemanticSha256"])

    def test_only_the_pickers_own_frames_join_the_evidence(self):
        pattern = re.compile(host_job.EVIDENCE_NAME + r"\Z")
        self.assertTrue(pattern.match("document-gui-picker-frame-15-dialog-open-named.png"))
        for name in ("document-gui-picker-frame-1-routing-nav.png", "document-picker-gui-first.json", "frame.png",
                     "document-gui-picker-frame-00-Routing.png", "document-gui-picker-frame-00-x.png.json"):
            self.assertIsNone(pattern.match(name), name)


if __name__ == "__main__":
    unittest.main()
