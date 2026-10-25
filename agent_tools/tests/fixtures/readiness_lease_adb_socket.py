"""Controlled TCP ADB-shaped endpoint for complete fixed lease callers.

No real ADB, VM, credentials or privileged state is used. This file is executable
as a client or an owned daemon; all commands are fixed to harmless fixture data.
"""
import json
import os
from pathlib import Path
import socket
import sys


if len(sys.argv) == 5 and sys.argv[1] == "daemon":
    state, port, ready = Path(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4])
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(8)
    ready.write_text(str(os.getpid()))
    while True:
        channel, _ = server.accept()
        with channel:
            data = b""
            while not data.endswith(b"\n") and len(data) < 4096:
                part = channel.recv(4096)
                if not part:
                    break
                data += part
            try:
                argv = json.loads(data)
                record = json.loads(state.read_text())
                if argv == ["emu", "avd", "name"]:
                    result = record["avd"] + "\nOK\n"
                elif argv == ["shell", "cat", "/proc/sys/kernel/random/boot_id"]:
                    result = record["boot"] + "\n"
                elif argv == ["shell", "am", "get-current-user"]:
                    result = record["account"] + "\n"
                elif argv == ["shell", "getprop", "sys.boot_completed"]:
                    result = "1\n"
                elif argv == ["shell", "settings", "get", "global", "stay_on_while_plugged_in"]:
                    result = record["value"] + "\n"
                elif argv[:5] == ["shell", "settings", "put", "global", "stay_on_while_plugged_in"] and len(argv) == 6 and argv[5] in tuple(str(n) for n in range(8)):
                    record["value"] = argv[5]
                    record["writes"].append(argv[5])
                    state.write_text(json.dumps(record))
                    result = ""
                elif argv == ["shell", "settings", "delete", "global", "stay_on_while_plugged_in"]:
                    record["value"] = "null"
                    record["writes"].append("null")
                    state.write_text(json.dumps(record))
                    result = "Deleted 1 rows\n"
                else:
                    raise ValueError("unrecognized fixed command")
                channel.sendall(json.dumps({"code": 0, "stdout": result}).encode())
            except (ValueError, OSError, KeyError):
                channel.sendall(b'{"code":1,"stdout":""}')
else:
    args = sys.argv[1:]
    if args[:2] != ["-H", "127.0.0.1"] or args[2:3] != ["-P"] or args[4:5] != ["-s"]:
        raise SystemExit(2)
    try:
        with socket.create_connection(("127.0.0.1", int(args[3])), timeout=2) as channel:
            channel.sendall(json.dumps(args[6:]).encode() + b"\n")
            channel.shutdown(socket.SHUT_WR)
            data = b""
            while len(data) < 4096:
                part = channel.recv(4096)
                if not part:
                    break
                data += part
        result = json.loads(data)
        sys.stdout.write(result["stdout"])
        raise SystemExit(result["code"])
    except (ValueError, OSError, KeyError):
        raise SystemExit(1)
