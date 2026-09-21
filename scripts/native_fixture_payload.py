#!/usr/bin/env python3
"""Freeze the explicit inputs for a small native-fixture transfer.

This module deliberately has no guest, SSH, or QGA code.  Its caller must obtain
the complete payload before it opens a remote transport.
"""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


_DIGEST = re.compile(r"[0-9a-f]{64}")
_MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  (?:\./)?([^\r\n]+)")
_VARIANTS = ("red", "green")
_SOURCE_NAMES = (
    "CoordinatorNativeAdmissionProbe.csproj",
    "NuGet.Config",
    "global.json",
    "windows-install-helper-coordinator-native-admission-fixture.cs",
    "windows-install-helper-inventory.cs",
    "windows-install-helper-msi.cs",
    "windows-install-helper-protocol.cs",
    "windows-install-helper-roles.cs",
    "windows-install-helper-sessions.cs",
    "windows-install-native.cs",
    "windows-install-original-user-launch.cs",
)
_WRAPPER_NAMES = ("build-fixtures.ps1", "run-private-user-fixture.ps1")
_MAX_FILE_BYTES = 256 * 1024
_MAX_TOTAL_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class PayloadFile:
    relative_path: str
    contents: bytes
    sha256: str


@dataclass(frozen=True)
class FixturePayload:
    files: tuple[PayloadFile, ...]
    source_hashes: dict[str, str]


def _sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def _safe_relative_path(name: str) -> str:
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"Unsafe fixture relative path: {name!r}")
    return path.as_posix()


def _read_regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Fixture input is not a regular file: {path}")
    size = path.stat().st_size
    if size > _MAX_FILE_BYTES:
        raise ValueError(f"Fixture input exceeds {_MAX_FILE_BYTES} byte limit: {path}")
    return path.read_bytes()


def _manifest_entries(manifest: Path) -> dict[str, str]:
    text = _read_regular(manifest).decode("utf-8")
    if not text.endswith("\n"):
        raise ValueError(f"Fixture manifest lacks a final newline: {manifest}")
    entries: dict[str, str] = {}
    for line in text.splitlines():
        match = _MANIFEST_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"Malformed fixture manifest entry: {line!r}")
        digest, name = match.groups()
        name = _safe_relative_path(name)
        if name in entries:
            raise ValueError(f"Duplicate fixture manifest entry: {name}")
        entries[name] = digest
    return entries


def load_windows_admission_payload(root: Path) -> FixturePayload:
    """Read only the frozen admission sources named by the two manifests.

    The result includes generated manifests after their source bytes have been
    checked, so the remote build wrapper can recheck the same exact 11 inputs.
    """
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Fixture root is not a directory: {root}")
    files: list[PayloadFile] = []
    source_hashes: dict[str, str] = {}
    for variant in _VARIANTS:
        variant_root = root / variant
        entries = _manifest_entries(variant_root / "SHA256SUMS.txt")
        if tuple(entries) != _SOURCE_NAMES:
            raise ValueError(f"{variant} manifest must name exactly the 11 frozen source files")
        for name in _SOURCE_NAMES:
            contents = _read_regular(variant_root / name)
            digest = _sha256(contents)
            if digest != entries[name]:
                raise ValueError(f"{variant} fixture hash mismatch: {name}")
            relative_path = _safe_relative_path(f"{variant}/{name}")
            files.append(PayloadFile(relative_path, contents, digest))
            source_hashes[relative_path] = digest
        manifest_contents = ("\n".join(f"{entries[name]}  ./{name}" for name in _SOURCE_NAMES) + "\n").encode("utf-8")
        files.append(PayloadFile(f"{variant}/SHA256SUMS.txt", manifest_contents, _sha256(manifest_contents)))

    wrapper_entries = _manifest_entries(root / "WRAPPER-SHA256SUMS.txt")
    if tuple(wrapper_entries) != _WRAPPER_NAMES:
        raise ValueError("Wrapper manifest must name exactly the two fixture PowerShell scripts")
    for name in _WRAPPER_NAMES:
        contents = _read_regular(root / name)
        digest = _sha256(contents)
        if digest != wrapper_entries[name]:
            raise ValueError(f"Fixture wrapper hash mismatch: {name}")
        files.append(PayloadFile(name, contents, digest))
        source_hashes[name] = digest

    if len(source_hashes) != 24 or len(files) != 26:
        raise AssertionError("Unexpected Windows admission payload size")
    if sum(len(item.contents) for item in files) > _MAX_TOTAL_BYTES:
        raise ValueError(f"Fixture payload exceeds {_MAX_TOTAL_BYTES} byte limit")
    return FixturePayload(tuple(files), source_hashes)


def render_windows_admission_receiver(payload: FixturePayload, qga_socket: str, destination: str) -> str:
    """Return a stdlib-only receiver that can safely run through ``python -``.

    The receiver contains every validated byte and hash.  It never resolves a
    local source path, so its working directory is irrelevant on the Arch host.
    """
    if not qga_socket.startswith("/") or not destination.startswith("C:\\"):
        raise ValueError("Receiver needs an absolute QGA socket and Windows destination")
    records = [
        {"path": item.relative_path, "data": base64.b64encode(item.contents).decode("ascii"), "sha256": item.sha256}
        for item in payload.files
    ]
    source = _RECEIVER_TEMPLATE.replace("__PAYLOAD__", json.dumps(records, separators=(",", ":")))
    source = source.replace("__QGA_SOCKET__", json.dumps(qga_socket)).replace("__DESTINATION__", json.dumps(destination))
    return source


_RECEIVER_TEMPLATE = r'''#!/usr/bin/env python3
# Generated by scripts/native_fixture_payload.py.  Stdlib only; safe for python -.
import argparse
import base64
import hashlib
import json
import socket
import time

PAYLOAD = __PAYLOAD__
DEFAULT_QGA_SOCKET = __QGA_SOCKET__
DEFAULT_DESTINATION = __DESTINATION__
MAX_STATUS_POLLS = 20

def encoded_powershell(script):
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")

def powershell_literal(value):
    if "\x00" in value:
        raise RuntimeError("NUL cannot appear in a PowerShell literal")
    return "'" + value.replace("'", "''") + "'"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qga-socket", default=DEFAULT_QGA_SOCKET)
    parser.add_argument("--destination", default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    if not args.qga_socket.startswith("/") or not args.destination.startswith("C:\\"):
        raise RuntimeError("Receiver paths must remain absolute and fixed-scope")
    expected = {}
    decoded = []
    for item in PAYLOAD:
        name, encoded, digest = item["path"], item["data"], item["sha256"]
        if not name or "\\" in name or name.startswith("/") or any(part in {"", ".", ".."} for part in name.split("/")):
            raise RuntimeError("Unsafe embedded payload path")
        if name in expected or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise RuntimeError("Duplicate or malformed embedded payload record")
        contents = base64.b64decode(encoded, validate=True)
        if hashlib.sha256(contents).hexdigest() != digest:
            raise RuntimeError("Embedded payload hash mismatch: " + name)
        expected[name.replace("/", "\\")] = digest
        decoded.append((name, contents))
    if len(expected) != 26 or sum(len(contents) for _, contents in decoded) > 2 * 1024 * 1024:
        raise RuntimeError("Embedded payload bounds changed")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect(args.qga_socket)
    response = sock.makefile("rb")
    def call(command, arguments):
        sock.sendall((json.dumps({"execute": command, "arguments": arguments}) + "\n").encode("utf-8"))
        result = json.loads(response.readline())
        if "error" in result:
            raise RuntimeError("QGA " + command + " failed: " + str(result["error"]))
        return result["return"]
    def run_powershell(script):
        process = call("guest-exec", {"path": "powershell.exe", "arg": ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_powershell(script)], "capture-output": True})
        pid = process["pid"]
        for _ in range(MAX_STATUS_POLLS):
            state = call("guest-exec-status", {"pid": pid})
            if state.get("exited"):
                out = base64.b64decode(state.get("out-data", "")).decode("utf-8", errors="replace")
                err = base64.b64decode(state.get("err-data", "")).decode("utf-8", errors="replace")
                if state.get("exitcode") != 0:
                    raise RuntimeError("Guest PowerShell failed (pid %s): %s" % (pid, err))
                return out
            time.sleep(1)
        raise RuntimeError("Guest PowerShell remained pending after %s polls (pid %s)" % (MAX_STATUS_POLLS, pid))
    parents = {args.destination}
    for name, _ in decoded:
        parent = name.replace("/", "\\").rpartition("\\")[0]
        if parent:
            parents.add(args.destination + "\\" + parent)
    parents = sorted(parents)
    directories = ",".join(powershell_literal(parent) for parent in parents)
    run_powershell("$ErrorActionPreference='Stop';$r=" + powershell_literal(args.destination) + ";if([IO.Directory]::Exists($r)){throw 'Fixture destination already exists'};$parents=@(" + directories + ");foreach($parent in $parents){[IO.Directory]::CreateDirectory($parent)|Out-Null}")
    for name, contents in decoded:
        remote = args.destination + "\\" + name.replace("/", "\\")
        handle = call("guest-file-open", {"path": remote, "mode": "wb"})
        try:
            written = call("guest-file-write", {"handle": handle, "buf-b64": base64.b64encode(contents).decode("ascii")})
            if written.get("count") != len(contents):
                raise RuntimeError("Guest short write for " + name)
            call("guest-file-flush", {"handle": handle})
        finally:
            call("guest-file-close", {"handle": handle})
    assignments = ";".join("$expected[" + powershell_literal(name) + "]=" + powershell_literal(digest) for name, digest in expected.items())
    receiver = "$ErrorActionPreference='Stop';$r=" + powershell_literal(args.destination) + ";$expected=@{};" + assignments + ";$actual=@{};foreach($entry in $expected.GetEnumerator()){$path=Join-Path $r $entry.Key;if(-not [IO.File]::Exists($path)){throw ('Missing staged file: '+$entry.Key)};$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();if($hash -ne $entry.Value){throw ('Hash mismatch: '+$entry.Key)};$actual[$entry.Key]=$hash};$parse=@();foreach($path in @((Join-Path $r " + powershell_literal("build-fixtures.ps1") + "),(Join-Path $r " + powershell_literal("run-private-user-fixture.ps1") + "))){$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)|Out-Null;$parse += [ordered]@{file=[IO.Path]::GetFileName($path);errors=@($errors|ForEach-Object {$_.Message})}};if($parse|Where-Object {$_.errors.Count -ne 0}){throw 'PowerShell parse errors'};[ordered]@{count=$actual.Count;hashes=$actual;parse=$parse}|ConvertTo-Json -Compress -Depth 4"
    verified = json.loads(run_powershell(receiver))
    if verified["count"] != len(expected) or verified["hashes"] != expected:
        raise RuntimeError("Guest staged-hash receipt did not match embedded payload")
    print(json.dumps({"destination": args.destination, "files": len(expected), "sourceFiles": 24}, sort_keys=True))

if __name__ == "__main__":
    main()
'''


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a standalone Windows fixture QGA receiver")
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qga-socket", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()
    receiver = render_windows_admission_receiver(
        load_windows_admission_payload(args.fixture_root), args.qga_socket, args.destination,
    )
    args.output.write_text(receiver, encoding="utf-8")


if __name__ == "__main__":
    main()
