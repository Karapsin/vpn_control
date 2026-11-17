"""The GUI's own file-picker export and import on an owned private desktop: the GUI half of gui-cli-transfer.

The cold document module loads this module, and windows_no_tray_desktop beside it, by their held paths for the
windows-document-cold.gui-picker row. Nothing here runs on import, and nothing here is a generic executor: every
input is one of the closed steps below, at a reviewed point, into a window of the GUI's own process tree.

- The GUI is the installed vpn-control.exe with --state-dir, started through the Owner's CreateProcessW path on a
  new desktop of the interactive window station that only SYSTEM and the ordinary user may open
  (windows_no_tray_desktop.OwnedNoTrayDesktop). No Explorer, shell or other program has a window there: every
  top-level window of that desktop must belong to the launcher or to its direct child, the relaunched JVM.
- The row switches the input desktop to that desktop for the GUI steps only and back to Default after them, so the
  pointer, the screen and SendInput reach the GUI's own windows and nothing else. A switch whose outcome is unknown
  parks (OwnedNoTrayDesktop.show and restore).
- The main window is moved to the canonical placement of the visual suite's window frame (140, 16, 1000 x 720 on the
  1280 x 800, 96 DPI display), so a reviewed point means the same control on every run.
- Before every click the pointer is parked on the bare desktop (Session.park: it reads back there, WindowFromPoint
  names the desktop window or none, and no visible window of the desktop's census holds the point; a refused park
  names each failed check with what it saw and keeps one unreviewable frame of the whole display), the main window's
  region is captured from the screen
  of that desktop until two consecutive captures are identical (the region capture's stable-frame rule, VISUAL-002),
  and the frame is kept in the operation root as document-gui-picker-frame-<nn>-<step>.png, which the evidence zip
  collects. The click happens only when the frame's pixels inside the step's reviewed anchor rectangle have the
  reviewed sha256, the pointer then reads back at the reviewed point, and the window under it is the GUI's own. A step
  that has no reviewed anchor yet stops the row there, with its frame kept and no click: that frame is what a
  reviewer opens to add the step to PROFILE (review_step). Clicks are one SendInput of a left press and release at
  the pointer's own position; a partial insertion parks.
- The common file dialog is driven by handle only, never by a click: its one visible file name Edit (control ID
  1001 in a Save dialog, 1148 in an Open dialog) gets the path by WM_SETTEXT and is read back, and the dialog gets
  one posted WM_COMMAND IDOK, which is what Enter sends. Its region is captured before and after the text.

What the cold module compares (CLI-002, PRODUCT-004): the GUI's export through its picker against the CLI export of
the same rules, byte for byte except for the one exported_at value; the GUI's import through its picker against the
CLI import of the same file, by the committed routing rules in workspace.json and the product's export; and both
crossings, a GUI export read by the CLI and a CLI export read by the GUI.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import threading
import time
import uuid
import zlib

LABEL = "document-gui-picker"
GUI_LEAF = "vpn-control.exe"
STEPS = ("routing-nav", "export-menu", "export-file", "import-menu", "import-file")
EXPORT_STEPS, IMPORT_STEPS = STEPS[:3], STEPS[3:]
DISPLAY = (1280, 800)
DPI = 96
# WindowsRegionScenes.windowFrame: left, top, width, height.
PLACEMENT = (140, 16, 1000, 720)
# Where the pointer rests before every frame, so no control shows hover: in the 140-pixel gutter left of the placement,
# halfway down, at least 64 pixels from the placement and from every display edge. A shell's taskbar, where a desktop
# has one, is a band along an edge (48 pixels at the bottom on Windows 11), and nothing on the owned desktop is at an
# edge or a corner. Session.park proves the point bare on every run.
PARK = (70, 400)
DESKTOP_WINDOW_CLASS = "#32769"
DIALOG_CLASS = "#32770"
MAIN_CLASS = "SunAwtFrame"
MAIN_WIDTH, MAIN_HEIGHT = 500, 300
FILENAME_EDIT = {"save": 1001, "open": 1148}
IDOK, IDCANCEL = 1, 2
WINDOW_SECONDS = 90
STABLE_ATTEMPTS, STABLE_INTERVAL = 20, 0.25  # REGION_STABLE_MAX_ATTEMPTS and REGION_STABLE_INTERVAL_MILLIS.
SETTLE_SECONDS = 1.0  # After a click, before the next frame: a menu or screen change is drawn.
DIALOG_SECONDS = 30
CANCEL_SECONDS = 15
FRAME_LIMIT = 16
FRAME_BYTES = 4 * 1024 * 1024
ANCHOR_MIN, ANCHOR_MAX = 8, 480
THREAD_SECONDS = 60  # One primitive on its desktop thread; a thread still running after this parks.
CENSUS_LIMIT = 64
CONTROL_LIMIT = 512
_FRAME_NAME = re.compile(r"document-gui-picker-frame-[0-9]{2}-[a-z0-9-]+\.png\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")

# The reviewed click profile of the GUI picker steps. Each step is None until a reviewer opened its frame from a run and
# recorded it with review_step: the screen point to click, an anchor rectangle that holds the point, both in screen
# pixels of the canonical placement, and the sha256 of the frame's RGB pixels inside the anchor. A run stops before the
# first step that is None, keeping its frame; a frame whose anchor pixels differ stops the run the same way. A product
# change that moves or redraws a control is therefore never clicked blind: it needs a new review.
PROFILE = {"schemaVersion": 1, "display": list(DISPLAY), "placement": list(PLACEMENT),
           "steps": {step: None for step in STEPS}}


def need(value, code):
    if not value:
        raise RuntimeError(code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


# ---- The reviewed profile -------------------------------------------------------------------------------------------

def _placement_rect(profile=None):
    left, top, width, height = (profile or PROFILE)["placement"]
    return (left, top, left + width, top + height)


def validate_profile(profile):
    """The profile's shape: every step None or a point inside an anchor inside the placement, with a digest."""
    need(type(profile) is dict and set(profile) == {"schemaVersion", "display", "placement", "steps"}
         and profile["schemaVersion"] == 1 and profile["display"] == list(DISPLAY) and profile["placement"] == list(PLACEMENT)
         and type(profile["steps"]) is dict and tuple(profile["steps"]) == STEPS, "document-gui-picker-profile-schema")
    bounds = _placement_rect(profile)
    for step, value in profile["steps"].items():
        if value is None:
            continue
        need(type(value) is dict and set(value) == {"point", "anchor", "sha256"}, "document-gui-picker-profile-schema:" + step)
        point, anchor = value["point"], value["anchor"]
        need(type(point) is list and len(point) == 2 and all(type(item) is int for item in point)
             and type(anchor) is list and len(anchor) == 4 and all(type(item) is int for item in anchor)
             and type(value["sha256"]) is str and _SHA.fullmatch(value["sha256"]) is not None,
             "document-gui-picker-profile-schema:" + step)
        left, top, right, bottom = anchor
        need(bounds[0] <= left < right <= bounds[2] and bounds[1] <= top < bottom <= bounds[3]
             and ANCHOR_MIN <= right - left <= ANCHOR_MAX and ANCHOR_MIN <= bottom - top <= ANCHOR_MAX,
             "document-gui-picker-profile-anchor:" + step)
        need(left <= point[0] < right and top <= point[1] < bottom, "document-gui-picker-profile-point:" + step)
    return profile


def reviewed(profile, step):
    validate_profile(profile)
    need(step in STEPS, "document-gui-picker-step")
    return profile["steps"][step]


# ---- Frames: RGB pixels of a screen region and their PNG ------------------------------------------------------------

class Frame:
    """One captured region: its screen rectangle and its RGB pixels, top-down, three bytes per pixel."""

    def __init__(self, rect, pixels):
        left, top, right, bottom = rect
        need(right > left and bottom > top and type(pixels) is bytes and len(pixels) == (right - left) * (bottom - top) * 3,
             "document-gui-picker-frame-shape")
        self.rect, self.pixels = tuple(rect), pixels

    @property
    def width(self):
        return self.rect[2] - self.rect[0]

    @property
    def height(self):
        return self.rect[3] - self.rect[1]

    def crop(self, rect):
        """The RGB pixels of a screen rectangle inside this frame."""
        left, top, right, bottom = rect
        need(self.rect[0] <= left < right <= self.rect[2] and self.rect[1] <= top < bottom <= self.rect[3],
             "document-gui-picker-anchor-outside-frame")
        stride, x = self.width * 3, (left - self.rect[0]) * 3
        return b"".join(self.pixels[(row - self.rect[1]) * stride + x:(row - self.rect[1]) * stride + x + (right - left) * 3]
                        for row in range(top, bottom))

    def blank(self):
        return self.pixels == self.pixels[:3] * (len(self.pixels) // 3)


def _chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def png(frame):
    """An 8-bit RGB PNG of the frame, every row with filter 0; review_step reads it back."""
    stride = frame.width * 3
    raw = b"".join(b"\x00" + frame.pixels[row * stride:(row + 1) * stride] for row in range(frame.height))
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", frame.width, frame.height, 8, 2, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(raw, 6)) + _chunk(b"IEND", b""))


def read_png(raw, origin):
    """A frame this module wrote, placed back at its screen origin (left, top); any other PNG is refused."""
    try:
        return _read_png(raw, origin)
    except (struct.error, zlib.error, ValueError, IndexError):
        raise RuntimeError("document-gui-picker-png") from None


def _read_png(raw, origin):
    need(raw[:8] == b"\x89PNG\r\n\x1a\n", "document-gui-picker-png")
    offset, chunks = 8, []
    while offset < len(raw):
        size, kind = struct.unpack(">I4s", raw[offset:offset + 8])
        data = raw[offset + 8:offset + 8 + size]
        need(len(data) == size and struct.unpack(">I", raw[offset + 8 + size:offset + 12 + size])[0]
             == zlib.crc32(kind + data) & 0xFFFFFFFF, "document-gui-picker-png")
        chunks.append((kind, data))
        offset += 12 + size
    need([kind for kind, _ in chunks] == [b"IHDR", b"IDAT", b"IEND"], "document-gui-picker-png")
    width, height, depth, colour, compression, filtering, interlace = struct.unpack(">IIBBBBB", chunks[0][1])
    need((depth, colour, compression, filtering, interlace) == (8, 2, 0, 0, 0), "document-gui-picker-png")
    raw_rows, stride = zlib.decompress(chunks[1][1]), width * 3
    need(len(raw_rows) == height * (stride + 1) and all(raw_rows[row * (stride + 1)] == 0 for row in range(height)),
         "document-gui-picker-png")
    pixels = b"".join(raw_rows[row * (stride + 1) + 1:(row + 1) * (stride + 1)] for row in range(height))
    left, top = origin
    return Frame((left, top, left + width, top + height), pixels)


def review_step(raw_png, origin, point, anchor):
    """A reviewer's PROFILE entry for one step, from the frame of that step the reviewer opened.

    origin is the frame's screen origin, the left and top of its document-gui-picker-frame event's rect."""
    frame = read_png(raw_png, origin)
    entry = {"point": list(point), "anchor": list(anchor), "sha256": sha256(frame.crop(tuple(anchor)))}
    profile = {**PROFILE, "steps": {**{step: None for step in STEPS}, STEPS[0]: entry}}
    validate_profile(profile)  # The point inside its anchor, the anchor inside the placement and its size bounds.
    return entry


# ---- The owned desktop of the one GUI child -------------------------------------------------------------------------

def picker_desktop(desktop_module, owner, gui_path, workspace):
    """An OwnedNoTrayDesktop whose one child is this row's GUI, under this row's own label."""
    base = desktop_module.OwnedNoTrayDesktop

    class PickerDesktop(base):
        def desktop_for_child(self, owner, label, argv):
            self.current()
            need(owner is self.owner and any(held is self for held in owner.no_tray_desktop_leases) and not self.used
                 and label == LABEL and list(argv) == [self.gui_path, "--state-dir", self.workspace], "document-gui-picker-child-role")
            self.used = True  # Consumed before the first possible CreateProcessW.
            desktop = "WinSta0\\" + self.name
            self.owner.event("document-gui-picker-child-intent", {"desktop": self.name, "lpDesktop": desktop, "argv": list(argv),
                "desktopSecuritySha256": sha256(self.security), "replayAllowed": False})
            return desktop

        def child_started(self, child):
            need(self.used and self.child is None and child in self.owner.children and child.owner is self.owner
                 and child.label == LABEL and child.process is not None and child.process.poll() is None
                 and child.pid == child.process.pid and child.birth is not None
                 and self.owner.native.birth(int(child.process._handle)) == child.birth, "document-gui-picker-original-child")
            self.child = child
            self.current()

    need(Path(str(gui_path)).name.casefold() == GUI_LEAF, "document-gui-picker-gui-leaf")
    return PickerDesktop(owner, gui_path, workspace)


# ---- Win32 on the owned desktop -------------------------------------------------------------------------------------

class _Input(ctypes.Structure):
    class _Union(ctypes.Union):
        class _Mouse(ctypes.Structure):
            _fields_ = [("dx", W.LONG), ("dy", W.LONG), ("mouseData", W.DWORD), ("dwFlags", W.DWORD), ("time", W.DWORD),
                        ("dwExtraInfo", ctypes.c_size_t)]

        class _Keyboard(ctypes.Structure):
            _fields_ = [("wVk", W.WORD), ("wScan", W.WORD), ("dwFlags", W.DWORD), ("time", W.DWORD),
                        ("dwExtraInfo", ctypes.c_size_t)]
        _fields_ = [("mi", _Mouse), ("ki", _Keyboard)]
    _fields_ = [("type", W.DWORD), ("u", _Union)]


class _BitmapInfo(ctypes.Structure):
    _fields_ = [("biSize", W.DWORD), ("biWidth", W.LONG), ("biHeight", W.LONG), ("biPlanes", W.WORD), ("biBitCount", W.WORD),
                ("biCompression", W.DWORD), ("biSizeImage", W.DWORD), ("biXPelsPerMeter", W.LONG), ("biYPelsPerMeter", W.LONG),
                ("biClrUsed", W.DWORD), ("biClrImportant", W.DWORD), ("colours", W.DWORD * 4)]


class _ProcessEntry(ctypes.Structure):
    _fields_ = [("dwSize", W.DWORD), ("cntUsage", W.DWORD), ("th32ProcessID", W.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", W.DWORD), ("cntThreads", W.DWORD), ("th32ParentProcessID", W.DWORD), ("pcPriClassBase", W.LONG),
                ("dwFlags", W.DWORD), ("szExeFile", W.WCHAR * 260)]


_MOUSE, _LEFTDOWN, _LEFTUP = 0, 0x0002, 0x0004
_WM_SETTEXT, _WM_GETTEXT, _WM_GETTEXTLENGTH, _WM_COMMAND = 0x000C, 0x000D, 0x000E, 0x0111
_SMTO_ABORTIFHUNG, _MESSAGE_MILLIS = 0x0002, 5000
_SWP_NOZORDER, _SWP_NOACTIVATE = 0x0004, 0x0010
_SRCCOPY, _CAPTUREBLT = 0x00CC0020, 0x40000000
_GA_ROOT = 2
# SendInput refuses a thread whose desktop handle lacks journal playback access, which the lease's own handle does not
# grant; the primitives' threads take a second handle of the same desktop that adds it.
_DESKTOP_JOURNALPLAYBACK = 0x0020


class Win32:
    """The closed primitives, each run on a fresh thread that SetThreadDesktop put on the owned desktop."""

    def __init__(self, lease):
        self.lease = lease
        self.handle = None
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.gdi = ctypes.WinDLL("gdi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        api = self.api
        u, g, k = self.user, self.gdi, self.kernel
        self.callback = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
        self.enum_desktop = api(u, "EnumDesktopWindows", W.BOOL, [W.HANDLE, self.callback, W.LPARAM])
        self.enum_children = api(u, "EnumChildWindows", W.BOOL, [W.HWND, self.callback, W.LPARAM])
        self.class_name = api(u, "GetClassNameW", ctypes.c_int, [W.HWND, W.LPWSTR, ctypes.c_int])
        self.window_pid = api(u, "GetWindowThreadProcessId", W.DWORD, [W.HWND, ctypes.POINTER(W.DWORD)])
        self.visible = api(u, "IsWindowVisible", W.BOOL, [W.HWND])
        self.enabled = api(u, "IsWindowEnabled", W.BOOL, [W.HWND])
        self.window_rect = api(u, "GetWindowRect", W.BOOL, [W.HWND, ctypes.POINTER(W.RECT)])
        self.control_id = api(u, "GetDlgCtrlID", ctypes.c_int, [W.HWND])
        self.metric = api(u, "GetSystemMetrics", ctypes.c_int, [ctypes.c_int])
        self.window_dpi = api(u, "GetDpiForWindow", W.UINT, [W.HWND])
        self.set_position = api(u, "SetWindowPos", W.BOOL, [W.HWND, W.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, W.UINT])
        self.from_point = api(u, "WindowFromPoint", W.HWND, [W.POINT])
        self.ancestor = api(u, "GetAncestor", W.HWND, [W.HWND, W.UINT])
        self.set_cursor = api(u, "SetCursorPos", W.BOOL, [ctypes.c_int, ctypes.c_int])
        self.get_cursor = api(u, "GetCursorPos", W.BOOL, [ctypes.POINTER(W.POINT)])
        self.send_input = api(u, "SendInput", W.UINT, [W.UINT, ctypes.POINTER(_Input), ctypes.c_int])
        self.send_timeout = api(u, "SendMessageTimeoutW", W.LPARAM, [W.HWND, W.UINT, W.WPARAM, W.LPARAM, W.UINT, W.UINT,
                                                                      ctypes.POINTER(ctypes.c_size_t)])
        self.post = api(u, "PostMessageW", W.BOOL, [W.HWND, W.UINT, W.WPARAM, W.LPARAM])
        self.get_dc = api(u, "GetDC", W.HDC, [W.HWND])
        self.release_dc = api(u, "ReleaseDC", ctypes.c_int, [W.HWND, W.HDC])
        self.compatible_dc = api(g, "CreateCompatibleDC", W.HDC, [W.HDC])
        self.dib = api(g, "CreateDIBSection", W.HBITMAP, [W.HDC, ctypes.POINTER(_BitmapInfo), W.UINT,
                                                           ctypes.POINTER(ctypes.c_void_p), W.HANDLE, W.DWORD])
        self.select = api(g, "SelectObject", W.HGDIOBJ, [W.HDC, W.HGDIOBJ])
        self.blit = api(g, "BitBlt", W.BOOL, [W.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, W.HDC,
                                               ctypes.c_int, ctypes.c_int, W.DWORD])
        self.flush = api(g, "GdiFlush", W.BOOL, [])
        self.delete_object = api(g, "DeleteObject", W.BOOL, [W.HGDIOBJ])
        self.delete_dc = api(g, "DeleteDC", W.BOOL, [W.HDC])
        self.snapshot = api(k, "CreateToolhelp32Snapshot", W.HANDLE, [W.DWORD, W.DWORD])
        self.first = api(k, "Process32FirstW", W.BOOL, [W.HANDLE, ctypes.POINTER(_ProcessEntry)])
        self.next = api(k, "Process32NextW", W.BOOL, [W.HANDLE, ctypes.POINTER(_ProcessEntry)])
        self.close_handle = api(k, "CloseHandle", W.BOOL, [W.HANDLE])
        self.set_thread = api(u, "SetThreadDesktop", W.BOOL, [W.HANDLE])
        self.get_thread = api(u, "GetThreadDesktop", W.HANDLE, [W.DWORD])
        self.close_desktop = api(u, "CloseDesktop", W.BOOL, [W.HANDLE])
        self.thread_id = api(k, "GetCurrentThreadId", W.DWORD, [])
        open_desktop = api(u, "OpenDesktopW", W.HANDLE, [W.LPCWSTR, W.DWORD, W.BOOL, W.DWORD])
        lease.current()
        self.handle = open_desktop(lease.name, 0, False, lease.ACCESS | _DESKTOP_JOURNALPLAYBACK)
        need(self.handle, "document-gui-picker-input-desktop-open")
        need(lease.object_name(self.handle) == lease.name and lease.security_bytes(self.handle) == lease.security,
             "document-gui-picker-input-desktop-identity")

    def close(self):
        """The second handle, once no primitive thread runs; the lease keeps its own."""
        if self.handle is not None:
            need(self.close_desktop(self.handle), "document-gui-picker-input-desktop-close")
            self.handle = None

    @staticmethod
    def api(library, name, result, arguments):
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
        return function

    def on_desktop(self, function):
        """function() on a fresh thread on the owned desktop through the second handle: its value or its error."""
        self.lease.current()
        need(self.handle is not None, "document-gui-picker-input-desktop-closed")
        outcome = {}

        def body():
            try:
                need(self.set_thread(self.handle), "document-gui-picker-thread-desktop")
                need(self.lease.object_name(self.get_thread(self.thread_id())) == self.lease.name, "document-gui-picker-thread-desktop")
                outcome["value"] = function()
            except BaseException as error:
                outcome["error"] = error
        worker = threading.Thread(target=body, name="document-gui-picker-" + uuid.uuid4().hex[:8], daemon=False)
        worker.start()
        worker.join(THREAD_SECONDS)
        if worker.is_alive():
            self.lease.owner.park("document-gui-picker-thread-outcome-unknown")
        if "error" in outcome:
            raise outcome["error"]
        return outcome["value"]

    def _name(self, hwnd):
        text = ctypes.create_unicode_buffer(256)
        return text.value if self.class_name(hwnd, text, len(text)) else None

    def _rect(self, hwnd):
        rect = W.RECT()
        return (rect.left, rect.top, rect.right, rect.bottom) if self.window_rect(hwnd, ctypes.byref(rect)) else None

    def _pid(self, hwnd):
        pid = W.DWORD()
        thread = self.window_pid(hwnd, ctypes.byref(pid))
        return (pid.value, thread) if thread else (None, None)

    def display(self):
        return self.on_desktop(lambda: (self.metric(0), self.metric(1)))

    def windows(self):
        """Every top-level window of the owned desktop: a census whose callback raised is refused, never shorter."""
        def census():
            rows, errors = [], []

            def visit(hwnd, _):
                try:
                    if len(rows) >= CENSUS_LIMIT:
                        errors.append("census-bound")
                        return False
                    pid, thread = self._pid(hwnd)
                    name, rect = self._name(hwnd), self._rect(hwnd)
                    if pid is None or name is None or rect is None:
                        return True  # Destroyed while listed.
                    rows.append({"hwnd": int(hwnd), "pid": pid, "threadId": thread, "class": name,
                                 "visible": bool(self.visible(hwnd)), "rect": list(rect)})
                    return True
                except BaseException as error:
                    errors.append("callback-" + type(error).__name__)
                    return False
            ctypes.set_last_error(0)
            listed = bool(self.enum_desktop(self.lease.handle, self.callback(visit), 0))
            need(not errors and (listed or not rows), "document-gui-picker-window-census")
            return rows
        return self.on_desktop(census)

    def parents(self):
        """pid -> parent pid of every process, from one toolhelp snapshot."""
        handle = self.snapshot(0x00000002, 0)
        need(handle and handle != ctypes.c_void_p(-1).value, "document-gui-picker-process-snapshot")
        try:
            entry, found = _ProcessEntry(), {}
            entry.dwSize = ctypes.sizeof(_ProcessEntry)
            more = self.first(handle, ctypes.byref(entry))
            while more:
                found[entry.th32ProcessID] = entry.th32ParentProcessID
                more = self.next(handle, ctypes.byref(entry))
            return found
        finally:
            self.close_handle(handle)

    def dpi(self, hwnd):
        return self.on_desktop(lambda: int(self.window_dpi(hwnd)))

    def place(self, hwnd, rect):
        left, top, right, bottom = rect

        def move():
            ctypes.set_last_error(0)
            moved = bool(self.set_position(hwnd, None, left, top, right - left, bottom - top, _SWP_NOZORDER | _SWP_NOACTIVATE))
            return moved, self._rect(hwnd)
        return self.on_desktop(move)

    def rect(self, hwnd):
        return self.on_desktop(lambda: self._rect(hwnd))

    def capture(self, rect):
        """The screen of the owned desktop, which is the input desktop now, inside rect: RGB, top-down."""
        left, top, right, bottom = rect
        width, height = right - left, bottom - top

        def grab():
            screen = self.get_dc(None)
            need(screen, "document-gui-picker-screen-dc")
            memory = bitmap = old = None
            try:
                memory = self.compatible_dc(screen)
                need(memory, "document-gui-picker-memory-dc")
                info, bits = _BitmapInfo(), ctypes.c_void_p()
                info.biSize, info.biWidth, info.biHeight, info.biPlanes, info.biBitCount = 40, width, -height, 1, 32
                bitmap = self.dib(screen, ctypes.byref(info), 0, ctypes.byref(bits), None, 0)
                need(bitmap and bits.value, "document-gui-picker-dib")
                old = self.select(memory, bitmap)
                need(self.blit(memory, 0, 0, width, height, screen, left, top, _SRCCOPY | _CAPTUREBLT), "document-gui-picker-bitblt")
                self.flush()
                bgra = ctypes.string_at(bits.value, width * height * 4)
            finally:
                if old:
                    self.select(memory, old)
                if bitmap:
                    self.delete_object(bitmap)
                if memory:
                    self.delete_dc(memory)
                self.release_dc(None, screen)
            rgb = bytearray(width * height * 3)
            rgb[0::3], rgb[1::3], rgb[2::3] = bgra[2::4], bgra[1::4], bgra[0::4]
            return bytes(rgb)
        return self.on_desktop(grab)

    def point_cursor(self, x, y):
        """SetCursorPos, then the pointer's own position read back, and the error of each call that failed. A move is
        not a click."""
        def move():
            ctypes.set_last_error(0)
            moved = bool(self.set_cursor(x, y))
            errors = {"setCursorPos": 0 if moved else ctypes.get_last_error(), "getCursorPos": 0}
            where = W.POINT()
            ctypes.set_last_error(0)
            read = bool(self.get_cursor(ctypes.byref(where)))
            if not read:
                errors["getCursorPos"] = ctypes.get_last_error()
            return moved, ((where.x, where.y) if read else None), errors
        return self.on_desktop(move)

    def window_at(self, x, y):
        """WindowFromPoint: the window it names and its root (the desktop window is its own root), or None."""
        def read():
            hwnd = self.from_point(W.POINT(x, y))
            if not hwnd:
                return None
            root = self.ancestor(hwnd, _GA_ROOT) or hwnd
            pid, _ = self._pid(root)
            return {"hwnd": int(hwnd), "class": self._name(hwnd), "root": int(root), "rootClass": self._name(root), "pid": pid}
        return self.on_desktop(read)

    def click(self):
        """One SendInput of a left press and release at the pointer's position: the count it inserted, and the error
        of a call that inserted nothing."""
        def press():
            events = (_Input * 2)()
            for index, flag in enumerate((_LEFTDOWN, _LEFTUP)):
                events[index].type = _MOUSE
                events[index].u.mi.dwFlags = flag
            ctypes.set_last_error(0)
            inserted = int(self.send_input(2, events, ctypes.sizeof(_Input)))
            return inserted, (ctypes.get_last_error() if inserted == 0 else 0)
        return self.on_desktop(press)

    def controls(self, dialog):
        def census():
            rows, errors = [], []

            def visit(hwnd, _):
                try:
                    if len(rows) >= CONTROL_LIMIT:
                        errors.append("control-bound")
                        return False
                    name = self._name(hwnd)
                    if name is not None:
                        rows.append({"hwnd": int(hwnd), "class": name, "id": int(self.control_id(hwnd)),
                                     "visible": bool(self.visible(hwnd)), "enabled": bool(self.enabled(hwnd))})
                    return True
                except BaseException as error:
                    errors.append("callback-" + type(error).__name__)
                    return False
            self.enum_children(dialog, self.callback(visit), 0)
            need(not errors, "document-gui-picker-control-census")
            return rows
        return self.on_desktop(census)

    def set_text(self, hwnd, text):
        def write():
            buffer, result = ctypes.create_unicode_buffer(text), ctypes.c_size_t()
            sent = self.send_timeout(hwnd, _WM_SETTEXT, 0, ctypes.cast(buffer, ctypes.c_void_p).value, _SMTO_ABORTIFHUNG,
                                     _MESSAGE_MILLIS, ctypes.byref(result))
            return bool(sent) and result.value == 1
        return self.on_desktop(write)

    def get_text(self, hwnd):
        def read():
            length = ctypes.c_size_t()
            if not self.send_timeout(hwnd, _WM_GETTEXTLENGTH, 0, 0, _SMTO_ABORTIFHUNG, _MESSAGE_MILLIS, ctypes.byref(length)):
                return None
            buffer, copied = ctypes.create_unicode_buffer(length.value + 1), ctypes.c_size_t()
            if not self.send_timeout(hwnd, _WM_GETTEXT, length.value + 1, ctypes.cast(buffer, ctypes.c_void_p).value,
                                     _SMTO_ABORTIFHUNG, _MESSAGE_MILLIS, ctypes.byref(copied)):
                return None
            return buffer.value
        return self.on_desktop(read)

    def command(self, dialog, identifier, button):
        """One posted WM_COMMAND of a button of the dialog, as Enter (IDOK) or Esc (IDCANCEL) sends it."""
        return self.on_desktop(lambda: bool(self.post(dialog, _WM_COMMAND, identifier, button)))


# ---- The session: the GUI's own windows, the reviewed steps and the dialogs -----------------------------------------

class Session:
    """The GUI child on its owned desktop, the steps it took and whether the input desktop is switched to it."""

    def __init__(self, owner, lease, child, native, profile=None):
        self.owner, self.lease, self.child, self.native = owner, lease, child, native
        self.profile = validate_profile(PROFILE if profile is None else profile)
        self.main, self.frames, self.steps = None, 0, []
        self.dialog_open = None  # The dialog a step opened and that has not been seen to close.
        self.closed = False

    # -- census and identity --

    def owned_pids(self):
        parents = self.native.parents()
        return {self.child.pid} | {pid for pid, parent in parents.items() if parent == self.child.pid}

    def census(self, reason):
        """Every window of the owned desktop, each one the GUI launcher's or its direct child's."""
        rows, pids = self.native.windows(), self.owned_pids()
        if not all(row["pid"] in pids for row in rows):
            self.owner.event("document-gui-picker-foreign-window", {"reason": reason, "windows": rows, "ownedPids": sorted(pids),
                                                                    "replayAllowed": False})
            raise RuntimeError("document-gui-picker-foreign-window:" + reason)
        return rows, pids

    def attach(self):
        """The GUI's one visible main window on its own desktop, within the bound; the display canonical."""
        need(self.child.process.poll() is None, "document-gui-picker-gui-ended")
        need(tuple(self.native.display()) == DISPLAY, "document-gui-picker-display-not-canonical")
        until = time.monotonic() + WINDOW_SECONDS
        while True:
            need(self.child.process.poll() is None, "document-gui-picker-gui-ended")
            rows, pids = self.census("attach")
            main = [row for row in rows if row["visible"] and row["class"] == MAIN_CLASS
                    and row["rect"][2] - row["rect"][0] >= MAIN_WIDTH and row["rect"][3] - row["rect"][1] >= MAIN_HEIGHT]
            if len(main) == 1 and not any(row["visible"] and row["class"] == DIALOG_CLASS for row in rows):
                self.main = main[0]
                need(self.native.dpi(self.main["hwnd"]) == DPI, "document-gui-picker-display-not-canonical")
                self.owner.event("document-gui-picker-attached", {"window": self.main, "windows": rows, "ownedPids": sorted(pids),
                                                                  "desktop": self.lease.name, "launcherPid": self.child.pid})
                return self.main
            if time.monotonic() >= until:
                self.owner.event("document-gui-picker-window-unresolved", {"windows": rows, "ownedPids": sorted(pids),
                                                                           "replayAllowed": False})
                raise RuntimeError("document-gui-picker-window-unresolved")
            time.sleep(0.25)

    def show(self):
        """The input desktop switched to the GUI's own, and its main window at the canonical placement."""
        need(self.main is not None, "document-gui-picker-not-attached")
        self.lease.show()  # Parks when the switch's outcome is unknown.
        target = _placement_rect(self.profile)
        moved, rect = self.native.place(self.main["hwnd"], target)
        self.owner.event("document-gui-picker-placed", {"window": self.main["hwnd"], "requested": list(target),
                                                        "moved": moved, "rect": rect})
        need(moved and rect is not None and tuple(rect) == target, "document-gui-picker-placement")

    def restore(self):
        """Default is the input desktop again, and the primitives' own desktop handle is closed."""
        if self.lease.switched:
            self.lease.restore()  # Parks when the switch back's outcome is unknown.
        self.native.close()

    # -- frames --

    def keep(self, step, frame, kind):
        """The frame as evidence: a create-only PNG in the operation root and an event naming its digests."""
        need(self.frames < FRAME_LIMIT, "document-gui-picker-frame-limit")
        name = "document-gui-picker-frame-%02d-%s.png" % (self.frames, step)
        need(_FRAME_NAME.fullmatch(name) is not None, "document-gui-picker-frame-name")
        data = png(frame)
        need(len(data) <= FRAME_BYTES, "document-gui-picker-frame-bytes")
        self.frames += 1
        with (Path(self.owner.root) / name).open("xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        value = {"step": step, "kind": kind, "name": name, "rect": list(frame.rect), "pixelsSha256": sha256(frame.pixels),
                 "pngSha256": sha256(data), "pngBytes": len(data)}
        self.owner.event("document-gui-picker-frame", value)
        return value

    def stable(self, step, rect, kind):
        """The region captured until two consecutive captures are identical; the first of them is kept."""
        previous = None
        for attempt in range(STABLE_ATTEMPTS):
            frame = Frame(rect, self.native.capture(rect))
            if previous is not None and frame.pixels == previous.pixels:
                if frame.blank():
                    self.keep(step, frame, kind + "-blank")
                    raise RuntimeError("document-gui-picker-frame-blank:" + step)
                kept = self.keep(step, previous, kind)
                return previous, {**kept, "attempts": attempt + 1}
            previous = frame
            time.sleep(STABLE_INTERVAL)
        self.keep(step, previous, kind + "-unstable")
        raise RuntimeError("document-gui-picker-frame-unstable:" + step)

    # -- the reviewed steps --

    def park(self, step):
        """The pointer at PARK, over the bare owned desktop and outside the crop, before the step's frame.

        Every check is made, and each one that fails is named in one document-gui-picker-park-refused event with what it
        observed: SetCursorPos's answer and error, the position read back, the window WindowFromPoint names there, and
        the visible windows of the desktop whose rectangle holds the point. WindowFromPoint must name the desktop window
        (#32769, its own root) or no window at all. It passes over hidden and disabled windows, so the census of every
        top-level window of the desktop must also show none over the point. A refused park keeps one frame of the whole
        display, a diagnostic that is never a step's reviewed frame, and the row ends there with no click."""
        x, y = PARK
        moved, where, errors = self.native.point_cursor(x, y)
        under = self.native.window_at(x, y)
        rows, pids = self.census("park-" + step)
        crop = _placement_rect(self.profile)
        covering = [row for row in rows if row["visible"] and row["rect"][0] <= x < row["rect"][2]
                    and row["rect"][1] <= y < row["rect"][3]]
        passed = {"cursor-move": moved is True, "cursor-readback": where == PARK,
                  "window-at-point": under is None or (under["hwnd"] == under["root"] and under["rootClass"] == DESKTOP_WINDOW_CLASS
                                                       and under["pid"] not in pids),
                  "window-over-point": not covering,
                  "point-in-crop": not (crop[0] <= x < crop[2] and crop[1] <= y < crop[3])}
        failed = [check for check, held in passed.items() if not held]
        if not failed:
            return
        frame = frame_error = None
        display = (0, 0) + DISPLAY
        try:
            frame = self.keep("park-" + step, Frame(display, self.native.capture(display)), "park-diagnostic")
        except Exception as error:  # The park's own refusal stays the reason; a park of the owner is never caught.
            frame_error = (type(error).__name__ + ":" + str(error))[:160]
        self.owner.event("document-gui-picker-park-refused", {"step": step, "park": list(PARK), "failed": failed,
            "moved": moved, "winerror": errors, "cursor": None if where is None else list(where), "under": under,
            "covering": covering, "crop": list(crop), "frame": frame, "frameError": frame_error, "frameReviewable": False,
            "clicked": False, "replayAllowed": False})
        raise RuntimeError("document-gui-picker-park-" + failed[0] + ":" + step)

    def main_unchanged(self, step):
        rows, pids = self.census(step)
        same = [row for row in rows if row["hwnd"] == self.main["hwnd"]]
        need(len(same) == 1 and same[0]["pid"] == self.main["pid"] and same[0]["visible"]
             and tuple(same[0]["rect"]) == _placement_rect(self.profile), "document-gui-picker-main-window-changed:" + step)
        need(not any(row["visible"] and row["class"] == DIALOG_CLASS for row in rows), "document-gui-picker-dialog-before:" + step)
        return pids

    def step(self, step):
        """One reviewed click: parked pointer, stable frame, reviewed anchor, the pointer at the point over the GUI."""
        need(self.child.process.poll() is None and self.lease.switched, "document-gui-picker-step-context:" + step)
        pids = self.main_unchanged(step)
        self.park(step)
        frame, kept = self.stable(step, _placement_rect(self.profile), "before-click")
        entry = reviewed(self.profile, step)
        if entry is None:
            self.owner.event("document-gui-picker-unreviewed", {"step": step, "frame": kept, "clicked": False,
                                                                "replayAllowed": False})
            raise RuntimeError("document-gui-picker-frame-unreviewed:" + step)
        digest = sha256(frame.crop(tuple(entry["anchor"])))
        if digest != entry["sha256"]:
            self.owner.event("document-gui-picker-anchor-mismatch", {"step": step, "frame": kept, "anchor": entry["anchor"],
                "observed": digest, "reviewed": entry["sha256"], "clicked": False, "replayAllowed": False})
            raise RuntimeError("document-gui-picker-anchor-mismatch:" + step)
        x, y = entry["point"]
        moved, where, errors = self.native.point_cursor(x, y)
        under = self.native.window_at(x, y)
        if not (moved and where == (x, y) and under is not None and under["pid"] in pids):
            self.owner.event("document-gui-picker-point-refused", {"step": step, "point": [x, y], "moved": moved, "cursor": where,
                                                                   "winerror": errors, "under": under, "clicked": False,
                                                                   "replayAllowed": False})
            raise RuntimeError("document-gui-picker-point-not-owned:" + step)
        self.owner.event("document-gui-picker-click-intent", {"step": step, "point": [x, y], "under": under, "frame": kept["name"],
                                                              "anchorSha256": digest, "oneEffect": True, "replayAllowed": False})
        inserted, error = self.native.click()
        if inserted == 0:
            # SendInput inserted nothing, so nothing reached the GUI (blocked input, or an access refusal it names).
            self.owner.event("document-gui-picker-click-refused", {"step": step, "winerror": error, "replayAllowed": False})
            raise RuntimeError("document-gui-picker-click-refused:" + step)
        if inserted != 2:
            # The press alone reached the input stream: the GUI's state is unknown and the click is never sent again.
            self.owner.park("document-gui-picker-click-outcome-unknown")
        self.steps.append(step)
        self.owner.event("document-gui-picker-clicked", {"step": step, "inserted": inserted})
        time.sleep(SETTLE_SECONDS)

    # -- the common file dialog, by handle --

    def await_dialog(self, kind):
        until = time.monotonic() + DIALOG_SECONDS
        while True:
            need(self.child.process.poll() is None, "document-gui-picker-gui-ended")
            rows, pids = self.census("dialog-" + kind)
            dialogs = [row for row in rows if row["visible"] and row["class"] == DIALOG_CLASS]
            if len(dialogs) == 1:
                self.dialog_open = dialogs[0]
                return dialogs[0]
            need(len(dialogs) < 2, "document-gui-picker-dialog-ambiguous:" + kind)
            if time.monotonic() >= until:
                self.owner.event("document-gui-picker-dialog-absent", {"kind": kind, "windows": rows, "replayAllowed": False})
                raise RuntimeError("document-gui-picker-dialog-absent:" + kind)
            time.sleep(0.25)

    def dialog_controls(self, dialog, kind):
        controls = self.native.controls(dialog["hwnd"])
        edits = [row for row in controls if row["class"] == "Edit" and row["id"] == FILENAME_EDIT[kind] and row["visible"]
                 and row["enabled"]]
        oks = [row for row in controls if row["class"] == "Button" and row["id"] == IDOK and row["visible"] and row["enabled"]]
        if len(edits) != 1 or len(oks) != 1:
            self.owner.event("document-gui-picker-dialog-controls", {"kind": kind, "dialog": dialog, "replayAllowed": False,
                "controls": [{key: row[key] for key in ("class", "id", "visible", "enabled")} for row in controls][:CONTROL_LIMIT]})
            raise RuntimeError("document-gui-picker-dialog-controls:" + kind)
        return edits[0], oks[0]

    def dialog_rect(self, dialog):
        rect = self.native.rect(dialog["hwnd"])
        need(rect is not None, "document-gui-picker-dialog-rect")
        left, top, right, bottom = rect
        clipped = (max(left, 0), max(top, 0), min(right, DISPLAY[0]), min(bottom, DISPLAY[1]))
        need(clipped[2] > clipped[0] and clipped[3] > clipped[1], "document-gui-picker-dialog-rect")
        return clipped

    def choose(self, kind, path):
        """The open dialog's file name set to path by handle, read back, and one IDOK; the dialog must then close."""
        need(kind in FILENAME_EDIT and type(path) is str and Path(path).is_absolute(), "document-gui-picker-choose")
        dialog = self.await_dialog(kind)
        edit, ok = self.dialog_controls(dialog, kind)
        rect = self.dialog_rect(dialog)
        self.stable("dialog-" + kind, rect, "dialog")
        self.owner.event("document-gui-picker-filename-intent", {"kind": kind, "dialog": dialog["hwnd"], "edit": edit["hwnd"],
                                                                 "path": path, "replayAllowed": False})
        need(self.native.set_text(edit["hwnd"], path), "document-gui-picker-filename-not-set:" + kind)
        need(self.native.get_text(edit["hwnd"]) == path, "document-gui-picker-filename-readback:" + kind)
        self.stable("dialog-" + kind + "-named", rect, "dialog")
        self.owner.event("document-gui-picker-dialog-ok-intent", {"kind": kind, "dialog": dialog["hwnd"], "button": ok["hwnd"],
                                                                  "oneEffect": True, "replayAllowed": False})
        need(self.native.command(dialog["hwnd"], IDOK, ok["hwnd"]), "document-gui-picker-dialog-ok-refused:" + kind)
        until = time.monotonic() + DIALOG_SECONDS
        while True:
            rows, _ = self.census("dialog-close-" + kind)
            if not any(row["hwnd"] == dialog["hwnd"] and row["visible"] for row in rows):
                break
            if time.monotonic() >= until:
                raise RuntimeError("document-gui-picker-dialog-stayed:" + kind)
            time.sleep(0.25)
        self.dialog_open = None
        self.owner.event("document-gui-picker-dialog-closed", {"kind": kind, "dialog": dialog["hwnd"], "path": path})

    # -- the two transfers --

    def export_file(self, path):
        """Routing, Export, File, then the Save dialog: the GUI writes its export to path."""
        for step in EXPORT_STEPS:
            self.step(step)
        self.choose("save", str(path))

    def import_file(self, path):
        """Import, File on the routing screen, then the Open dialog: the GUI imports path."""
        for step in IMPORT_STEPS:
            self.step(step)
        self.choose("open", str(path))

    # -- the closing of a known failure --

    def close_known(self):
        """A dialog this session saw open gets one posted IDCANCEL and must close; then the input desktop is Default again.

        Returns what it did. Anything it cannot know parks: a cancel that was posted but whose dialog stays, or a switch
        whose outcome is unknown (OwnedNoTrayDesktop.restore)."""
        done = {"dialogCancelled": False, "restored": False}
        if self.closed:
            return done
        self.closed = True
        dialog = self.dialog_open
        if dialog is None and self.lease.switched and self.child.process.poll() is None:
            # Only the GUI's own dialogs: a census that also lists another process's window still closes what is the GUI's.
            pids = self.owned_pids()
            dialogs = [row for row in self.native.windows() if row["visible"] and row["class"] == DIALOG_CLASS and row["pid"] in pids]
            dialog = dialogs[0] if len(dialogs) == 1 else None
            need(len(dialogs) < 2, "document-gui-picker-dialog-ambiguous:closing")
        if dialog is not None and self.child.process.poll() is None:
            self.owner.event("document-gui-picker-dialog-cancel-intent", {"dialog": dialog["hwnd"], "oneEffect": True,
                                                                          "replayAllowed": False})
            if not self.native.command(dialog["hwnd"], IDCANCEL, 0):
                self.owner.park("document-gui-picker-dialog-cancel-refused")
            until = time.monotonic() + CANCEL_SECONDS
            while any(row["hwnd"] == dialog["hwnd"] and row["visible"] for row in self.native.windows()):
                if time.monotonic() >= until:
                    self.owner.park("document-gui-picker-dialog-cancel-unknown")
                time.sleep(0.25)
            self.dialog_open, done["dialogCancelled"] = None, True
        if self.lease.switched:
            self.restore()
            done["restored"] = True
        self.owner.event("document-gui-picker-closed", done)
        return done


def start(owner, desktop_module, gui_path, workspace):
    """The owned desktop and the one GUI child on it: (lease, child)."""
    lease = picker_desktop(desktop_module, owner, gui_path, workspace)
    child = owner.child(LABEL, [str(gui_path), "--state-dir", str(workspace)], owned_desktop=lease)
    need(lease.child is child, "document-gui-picker-original-child")
    return lease, child


def session(owner, lease, child, profile=None):
    return Session(owner, lease, child, Win32(lease), profile)


# ---- What the cold module compares ----------------------------------------------------------------------------------

_EXPORTED_AT = re.compile(rb'\n  "exported_at": "([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z)",\n')


def without_exported_at(raw):
    """The export's bytes with its one exported_at value cut out, and that value; the product writes it once
    (RoutingRulesTransfer.writeExport), as the third member of the top-level object."""
    found = list(_EXPORTED_AT.finditer(raw))
    need(len(found) == 1 and raw.count(b'"exported_at"') == 1, "document-gui-picker-exported-at")
    match = found[0]
    return raw[:match.start(1)] + raw[match.end(1):], match.group(1).decode("ascii")


def same_export(gui, cli):
    """Whether the GUI's export bytes are the CLI's, but for the moment each was written.

    The CLI's export is the reference and must have its one exported_at in its place. A GUI export that has not is a
    difference, as any other byte is."""
    cli_rest, cli_at = without_exported_at(cli)
    try:
        gui_rest, gui_at = without_exported_at(gui)
    except RuntimeError:
        gui_rest, gui_at = gui, None
    return gui_at is not None and gui_rest == cli_rest, {"guiBytes": len(gui), "cliBytes": len(cli), "guiSha256": sha256(gui), "cliSha256": sha256(cli),
                                  "guiExportedAt": gui_at, "cliExportedAt": cli_at,
                                  "withoutExportedAtSha256": [sha256(gui_rest), sha256(cli_rest)]}


def routing_state(raw_workspace):
    """The committed routing rules in a workspace.json, canonical: what an import changes and a cold owner reads."""
    value = json.loads(raw_workspace.decode("utf-8", "strict"))
    need(type(value) is dict and type(value.get("persisted_state")) is dict
         and type(value["persisted_state"].get("routing_rules")) is dict, "document-gui-picker-workspace-shape")
    rules = value["persisted_state"]["routing_rules"]
    canonical = json.dumps(rules, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    suffixes = rules.get("direct_domain_suffixes")
    return {"routingRulesSha256": sha256(canonical), "suffixes": len(suffixes) if type(suffixes) is list else None}
