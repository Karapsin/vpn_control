"""Owned loopback endpoint: one fixed sentinel, never arbitrary execution."""
import base64
import importlib.util
import json
from pathlib import Path
import socket
import sys
import time

module_path, root_path, ready_path = sys.argv[1:]
spec = importlib.util.spec_from_file_location("durable_remote_job", module_path)
jobs = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = jobs
spec.loader.exec_module(jobs)
root = Path(root_path)
binding = jobs.current_binding("fixture", "owned-fixture")
generation = jobs.root_generation(root)
source = ("import pathlib,time,sys\n"
          "p=pathlib.Path(" + repr(str(root / "counter")) + ")\n"
          "with p.open('a') as out:\n"
          " out.write('execution\\n');out.flush()\n"
          " for n in range(15):\n"
          "  out.write(str(n)+'\\n');out.flush();print(n,flush=True);time.sleep(.04)\n"
          "sys.stderr.write('sentinel stderr\\n')\n").encode()
program = jobs.Program("counter-sentinel", source)
with socket.socket() as server:
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    Path(ready_path).write_text(json.dumps({"port": server.getsockname()[1]}))
    while True:
        channel, _ = server.accept()
        with channel:
            raw = b""
            while not raw.endswith(b"\n") and len(raw) < 4096:
                chunk = channel.recv(4096 - len(raw))
                if not chunk:
                    break
                raw += chunk
            if not raw:
                continue
            try:
                request = json.loads(raw)
                operation = request["operationId"]
                if request["action"] == "submit":
                    result = jobs.submit(root, operation, binding, program, generation=generation)
                elif request["action"] == "observe":
                    result = jobs.observe(root, operation, binding, generation=generation)
                elif request["action"] == "collect":
                    result, stdout, stderr = jobs.collect(root, operation, binding, generation=generation)
                    result = {**result, "privateStdout": base64.b64encode(stdout).decode(),
                              "privateStderr": base64.b64encode(stderr).decode()}
                else:
                    raise ValueError()
                # Allows client death/ACK loss without changing original work.
                if request.get("dropReply"):
                    continue
                channel.sendall(json.dumps(result).encode() + b"\n")
            except (ValueError, KeyError, BrokenPipeError, ConnectionResetError):
                pass
