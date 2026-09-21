#!/usr/bin/env python3
"""Causal regression for stdin-delivered fixture staging payloads."""

import hashlib
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading

from native_fixture_payload import (
    _SOURCE_NAMES,
    _WRAPPER_NAMES,
    FixturePayload,
    PayloadFile,
    load_windows_admission_payload,
    render_windows_admission_receiver,
)


def write_fixture(root: Path) -> None:
    root.mkdir()
    for variant in ("red", "green"):
        variant_root = root / variant
        variant_root.mkdir()
        lines = []
        for name in _SOURCE_NAMES:
            contents = f"{variant}/{name}".encode("utf-8")
            (variant_root / name).write_bytes(contents)
            lines.append(f"{hashlib.sha256(contents).hexdigest()}  ./{name}")
        (variant_root / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    wrapper_lines = []
    for name in _WRAPPER_NAMES:
        contents = f"wrapper/{name}".encode("utf-8")
        (root / name).write_bytes(contents)
        wrapper_lines.append(f"{hashlib.sha256(contents).hexdigest()}  {name}")
    (root / "WRAPPER-SHA256SUMS.txt").write_text("\n".join(wrapper_lines) + "\n", encoding="utf-8")


def run_fake_qga(socket_path: Path, destination: str, captured: dict[str, bytes], powershell_scripts: list[str]) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    connection, _ = listener.accept()
    response = connection.makefile("wb")
    request = connection.makefile("rb")
    handles: dict[str, str] = {}
    next_handle = 0
    next_pid = 0
    try:
        for line in request:
            command = json.loads(line)
            name, arguments = command["execute"], command["arguments"]
            if name == "guest-exec":
                next_pid += 1
                powershell_scripts.append(base64.b64decode(arguments["arg"][-1]).decode("utf-16le"))
                value = {"pid": next_pid}
            elif name == "guest-exec-status":
                if next_pid == 2:
                    hashes = {
                        path[len(destination) + 1:]: hashlib.sha256(contents).hexdigest()
                        for path, contents in captured.items()
                    }
                    value = {"exited": True, "exitcode": 0, "out-data": base64.b64encode(json.dumps({"count": len(hashes), "hashes": hashes, "parse": []}).encode()).decode()}
                else:
                    value = {"exited": True, "exitcode": 0}
            elif name == "guest-file-open":
                next_handle += 1
                handle = str(next_handle)
                handles[handle] = arguments["path"]
                value = handle
            elif name == "guest-file-write":
                contents = base64.b64decode(arguments["buf-b64"])
                captured[handles[arguments["handle"]]] = contents
                value = {"count": len(contents)}
            elif name in {"guest-file-flush", "guest-file-close"}:
                value = {}
            else:
                raise AssertionError(f"Unexpected fake QGA call: {name}")
            response.write((json.dumps({"return": value}) + "\n").encode())
            response.flush()
    finally:
        connection.close()
        listener.close()


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        foreign_cwd = Path(temporary)
        (foreign_cwd / "unrelated-home-sized-sentinel.txt").write_bytes(b"never stage this")
        old_stdin_script = (
            "from pathlib import Path\n"
            "print(Path(__file__).resolve().parent)\n"
            "print('unrelated-home-sized-sentinel.txt' in {p.name for p in Path(__file__).resolve().parent.rglob('*')})\n"
        )
        old = subprocess.run(
            [sys.executable, "-"], input=old_stdin_script, text=True, cwd=foreign_cwd,
            capture_output=True, check=True,
        ).stdout.splitlines()
        assert Path(old[0]) == foreign_cwd.resolve()
        assert old[1] == "True", "RED: stdin __file__ discovery must reproduce the foreign-cwd capture"

        fixture = foreign_cwd / "frozen-fixture"
        write_fixture(fixture)
        payload = load_windows_admission_payload(fixture)
        assert len(payload.source_hashes) == 24
        assert len(payload.files) == 26
        assert "unrelated-home-sized-sentinel.txt" not in payload.source_hashes
        assert tuple(item.relative_path for item in payload.files[:11]) == tuple(f"red/{name}" for name in (
            "CoordinatorNativeAdmissionProbe.csproj", "NuGet.Config", "global.json",
            "windows-install-helper-coordinator-native-admission-fixture.cs",
            "windows-install-helper-inventory.cs", "windows-install-helper-msi.cs",
            "windows-install-helper-protocol.cs", "windows-install-helper-roles.cs",
            "windows-install-helper-sessions.cs", "windows-install-native.cs",
            "windows-install-original-user-launch.cs",
        ))
        assert all(len(item.contents) <= 256 * 1024 for item in payload.files)
        (fixture / "green" / "global.json").write_text("changed", encoding="utf-8")
        try:
            load_windows_admission_payload(fixture)
        except ValueError as error:
            assert "hash mismatch" in str(error)
        else:
            raise AssertionError("hash-modified frozen input must be rejected")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        fixture = root / "fixture"
        write_fixture(fixture)
        payload = load_windows_admission_payload(fixture)
        special = PayloadFile("red/o'hara$`name.cs", payload.files[0].contents, payload.files[0].sha256)
        payload = FixturePayload((special,) + payload.files[1:], payload.source_hashes)
        destination = r"C:\O'Hara\$stage\`fixture"
        try:
            render_windows_admission_receiver(payload, r"C:\temporary\fake-qga.sock", destination)
        except ValueError as error:
            assert "absolute QGA socket" in str(error), "RED: a Windows temporary path is not a QGA Unix socket"
        else:
            raise AssertionError("Windows temporary path must be rejected as a QGA Unix socket")

        # Generation and literal safety apply on every host.  The production
        # receiver deliberately requires a POSIX QGA socket because it runs on
        # the remote Arch transport host, not on the Windows fixture guest.
        receiver = render_windows_admission_receiver(payload, "/synthetic/qga.sock", destination)
        assert "__file__" not in receiver and "rglob" not in receiver and "Get-ChildItem" not in receiver
        compile(receiver, "generated-windows-admission-receiver.py", "exec")
        generated: dict[str, object] = {"__name__": "generated_receiver"}
        exec(receiver, generated)
        assert [base64.b64decode(item["data"], validate=True) for item in generated["PAYLOAD"]] == [item.contents for item in payload.files]
        powershell_literal = generated["powershell_literal"]
        assert powershell_literal(destination) == "'C:\\O''Hara\\$stage\\`fixture'"
        assert powershell_literal("red\\o'hara$`name.cs") == "'red\\o''hara$`name.cs'"

        if os.name == "nt":
            print("[vpn-control] skipped real QGA AF_UNIX transport on Windows; receiver generation and literals verified")
            print("[vpn-control] native fixture payload RED/GREEN regression passed")
            return

        socket_path = root / "fake-qga.sock"
        captured: dict[str, bytes] = {}
        powershell_scripts: list[str] = []
        server = threading.Thread(target=run_fake_qga, args=(socket_path, destination, captured, powershell_scripts), daemon=True)
        server.start()
        foreign_cwd = root / "foreign-cwd"
        foreign_cwd.mkdir()
        result = subprocess.run(
            [sys.executable, "-", "--qga-socket", str(socket_path), "--destination", destination],
            input=receiver, text=True, cwd=foreign_cwd, capture_output=True, check=True,
        )
        server.join(timeout=5)
        assert not server.is_alive()
        assert json.loads(result.stdout)["files"] == 26
        assert captured == {
            destination + "\\" + item.relative_path.replace("/", "\\"): item.contents
            for item in payload.files
        }
        assert len(powershell_scripts) == 2, "Directory setup must be one pre-write guest process"
        assert "New-Item" not in powershell_scripts[0]
        assert "$r='C:\\O''Hara\\$stage\\`fixture'" in powershell_scripts[0]
        assert "[IO.Directory]::CreateDirectory" in powershell_scripts[0]
        assert "$expected['red\\o''hara$`name.cs']=" in powershell_scripts[1]
        assert '$r="' not in powershell_scripts[0] and '$expected["' not in powershell_scripts[1]
    print("[vpn-control] native fixture payload RED/GREEN regression passed")


if __name__ == "__main__":
    main()
