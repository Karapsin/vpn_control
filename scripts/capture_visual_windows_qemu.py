#!/usr/bin/env python3
"""Capture the real Windows secure-desktop UAC surface from the managed QEMU VM."""

from __future__ import annotations

import argparse
import binascii
import json
import socket
import struct
import time
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = ROOT / ".runtime/visual-vms/windows"
QMP_SOCKET = RUNTIME_DIR / "qmp.sock"
READY_MARKER = RUNTIME_DIR / "READY"
CANONICAL_SIZE = (1280, 800)


class CaptureError(RuntimeError):
    pass


class QmpClient:
    def __init__(self, path: Path) -> None:
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(15)
        self._socket.connect(str(path))
        self._stream = self._socket.makefile("rwb", buffering=0)
        greeting = self._receive()
        if "QMP" not in greeting:
            raise CaptureError("QEMU did not return a QMP greeting")
        self.execute("qmp_capabilities")

    def close(self) -> None:
        self._stream.close()
        self._socket.close()

    def _receive(self) -> dict[str, object]:
        while True:
            line = self._stream.readline()
            if not line:
                raise CaptureError("QMP connection closed unexpectedly")
            message = json.loads(line)
            if "event" not in message:
                return message

    def execute(self, name: str, arguments: dict[str, object] | None = None) -> object:
        request: dict[str, object] = {"execute": name}
        if arguments:
            request["arguments"] = arguments
        self._stream.write(json.dumps(request).encode("utf-8") + b"\n")
        response = self._receive()
        if "error" in response:
            raise CaptureError(f"QMP {name} failed: {response['error']}")
        return response.get("return")

    def send_key(self, key: str) -> None:
        self.execute(
            "human-monitor-command",
            {"command-line": f"sendkey {key}"},
        )


def _type_command(qmp: QmpClient, command: str) -> None:
    keys = {
        " ": "spc",
        "-": "minus",
        ":": "shift-semicolon",
        "\\": "backslash",
        ".": "dot",
    }
    for character in command:
        key = keys.get(character, character)
        if not (key.isalnum() or key in {"spc", "minus", "shift-semicolon", "backslash", "dot"}):
            raise CaptureError(f"unsupported QMP input character: {character!r}")
        qmp.send_key(key)
        time.sleep(0.035)


def _ppm_token(data: bytes, start: int) -> tuple[bytes, int]:
    position = start
    while position < len(data):
        if data[position] == ord("#"):
            newline = data.find(b"\n", position)
            if newline < 0:
                raise CaptureError("truncated PPM comment")
            position = newline + 1
        elif chr(data[position]).isspace():
            position += 1
        else:
            break
    end = position
    while end < len(data) and not chr(data[end]).isspace():
        end += 1
    if end == position:
        raise CaptureError("truncated PPM header")
    return data[position:end], end


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    checksum = binascii.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", checksum)


def convert_ppm_to_png(ppm: Path, png: Path) -> tuple[int, int]:
    data = ppm.read_bytes()
    magic, position = _ppm_token(data, 0)
    width_raw, position = _ppm_token(data, position)
    height_raw, position = _ppm_token(data, position)
    maximum_raw, position = _ppm_token(data, position)
    if magic != b"P6" or maximum_raw != b"255":
        raise CaptureError("QEMU screendump must be an 8-bit RGB PPM")
    width, height = int(width_raw), int(height_raw)
    if position >= len(data) or not chr(data[position]).isspace():
        raise CaptureError("PPM header has no pixel separator")
    pixels = data[position + 1 :]
    if len(pixels) != width * height * 3:
        raise CaptureError("PPM framebuffer data has an unexpected length")
    scanlines = b"".join(
        b"\x00" + pixels[row * width * 3 : (row + 1) * width * 3]
        for row in range(height)
    )
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    encoded = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(scanlines, level=9))
        + _png_chunk(b"IEND", b"")
    )
    png.write_bytes(encoded)
    return width, height


def capture_uac(output: Path) -> None:
    if not READY_MARKER.is_file():
        raise CaptureError("managed Windows VM has not passed agent provisioning checks")
    if not QMP_SOCKET.exists():
        raise CaptureError("managed Windows VM is not running or its QMP socket is missing")
    output.mkdir(parents=True, exist_ok=True)
    ppm = output / "windows-uac.ppm"
    png = output / "windows-uac.png"
    qmp = QmpClient(QMP_SOCKET)
    try:
        qmp.send_key("meta_l-r")
        time.sleep(1)
        _type_command(qmp, "powershell start powershell -verb runas")
        qmp.send_key("ret")
        time.sleep(3)
        qmp.execute("screendump", {"filename": str(ppm)})
        actual_size = convert_ppm_to_png(ppm, png)
        if actual_size != CANONICAL_SIZE:
            raise CaptureError(
                f"Windows framebuffer is {actual_size[0]}x{actual_size[1]}; expected 1280x800"
            )
    finally:
        qmp.send_key("esc")
        qmp.close()
        ppm.unlink(missing_ok=True)


def probe_vm(output: Path | None = None, *, require_canonical: bool = True) -> tuple[int, int]:
    if not QMP_SOCKET.exists():
        raise CaptureError("managed Windows VM is not running or its QMP socket is missing")
    ppm = RUNTIME_DIR / "probe-frame.ppm"
    png = output or RUNTIME_DIR / "probe-frame.png"
    qmp = QmpClient(QMP_SOCKET)
    try:
        status = qmp.execute("query-status")
        if not isinstance(status, dict) or status.get("status") != "running":
            raise CaptureError(f"managed Windows VM is not running: {status}")
        qmp.execute("screendump", {"filename": str(ppm)})
        size = convert_ppm_to_png(ppm, png)
        if require_canonical and size != CANONICAL_SIZE:
            raise CaptureError(f"Windows framebuffer is {size[0]}x{size[1]}; expected 1280x800")
        return size
    finally:
        qmp.close()
        ppm.unlink(missing_ok=True)
        if output is None:
            png.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--probe-output", type=Path)
    parser.add_argument("--allow-noncanonical", action="store_true")
    parser.add_argument("--send-key", action="append", default=[])
    parser.add_argument("--key-delay", type=float, default=0.05)
    parser.add_argument("--type-text")
    parser.add_argument("--platform", choices=("windows",))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--scenes", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.send_key or args.type_text is not None:
        qmp = QmpClient(QMP_SOCKET)
        try:
            if args.type_text is not None:
                _type_command(qmp, args.type_text)
            for index, key in enumerate(args.send_key):
                if index:
                    time.sleep(args.key_delay)
                qmp.send_key(key)
        finally:
            qmp.close()
        print(json.dumps({"keys_sent": args.send_key, "text_length": len(args.type_text or "")}))
        return 0
    if args.probe:
        if args.probe_output is not None:
            args.probe_output.parent.mkdir(parents=True, exist_ok=True)
        width, height = probe_vm(
            args.probe_output,
            require_canonical=not args.allow_noncanonical,
        )
        print(json.dumps({"status": "running", "framebuffer": f"{width}x{height}"}))
        return 0
    if not all((args.platform, args.manifest, args.scenes, args.output)):
        raise CaptureError("capture requires --platform, --manifest, --scenes, and --output")
    requested = json.loads(args.scenes.read_text(encoding="utf-8"))
    if requested != ["windows-uac"]:
        raise CaptureError("the QEMU secure-desktop driver captures only windows-uac")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    known = {scene.get("id") for scene in manifest.get("scenes", [])}
    if "windows-uac" not in known:
        raise CaptureError("visual manifest does not contain windows-uac")
    capture_uac(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
