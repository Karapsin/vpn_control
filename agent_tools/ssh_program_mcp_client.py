"""Fresh retained MCP client; follows original job observations, never replays start."""
from __future__ import annotations

import argparse
import asyncio
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import uuid

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
ACTIONS = ("program-start", "program-status", "program-collect", "program-reconcile",
           "guest-program-start", "guest-program-status", "guest-program-collect", "guest-program-reconcile",
           "android-program-start", "android-program-status", "android-program-collect", "android-program-reconcile")


def save(directory, name, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, raw[offset:])
            if count <= 0:
                raise OSError("client_record_short_write")
            offset += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def request(action, host, body, fixture=None):
    if action in ACTIONS and action.startswith(("guest-", "android-")):
        if host is not None or type(fixture) is not str or re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", fixture) is None:
            raise ValueError("program_mcp_action_fixture")
        fields = {"operationId", "count", "intervalSeconds"} if action == "guest-program-start" else {"operationId"}
        if type(body) is not dict or set(body) != fields or str(uuid.UUID(body["operationId"])) != body["operationId"]:
            raise ValueError("program_mcp_request")
        if action == "guest-program-start":
            import math
            if (type(body["count"]) is not int or not 1 <= body["count"] <= 120
                    or type(body["intervalSeconds"]) not in (int, float) or not math.isfinite(body["intervalSeconds"])
                    or not .01 <= body["intervalSeconds"] <= 1):
                raise ValueError("program_mcp_guest_spec")
        return {"action": action, "inputs": {"fixtureId": fixture, **body}}
    if fixture is not None:
        raise ValueError("program_mcp_unexpected_fixture")
    if action not in ACTIONS or type(host) is not str or re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", host) is None:
        raise ValueError("program_mcp_action_host")
    fields = {"operationId", "program"} if action == "program-start" else {"operationId"}
    if type(body) is not dict or set(body) != fields or str(uuid.UUID(body["operationId"])) != body["operationId"]:
        raise ValueError("program_mcp_request")
    return {"action": action, "host": host, "timeout_seconds": 15,
            "transfer" if action == "program-start" else "identity": body}


def follow_request(action, host, operation, value, fixture=None):
    """Only this original operation can drive follow-up RPCs. Ignore supplied argv."""
    if type(value) is not dict or value.get("operationId") != operation:
        return None
    if value.get("host", host) != host:
        raise ValueError("program_mcp_follow_binding")
    if fixture is not None and value.get("fixtureId") != fixture:
        raise ValueError("program_mcp_follow_binding")
    guidance = value.get("nextAction")
    kind = guidance.get("kind", guidance.get("action")) if type(guidance) is dict else guidance
    prefix = "android-program-" if action.startswith("android-") else "guest-program-" if fixture is not None else "program-"
    next_action = {"observe_original": prefix + "status", "reconcile_original": prefix + "reconcile",
                   "collect_original": prefix + "collect"}.get(kind)
    if next_action is None or action == prefix + "collect" and next_action == prefix + "collect":
        return None
    return request(next_action, host, {"operationId": operation}, fixture)


# Bounded overrun past the follow deadline for one in-flight call and the
# relay close; the MCP SDK kills the relay 2 s after stdin closes otherwise.
CLOSE_GRACE_SECONDS = 30


def protocol_loss(error):
    """Finite typed transport errors; source, trust and cancellation never retry."""
    import anyio
    from mcp.shared.exceptions import McpError
    from mcp.types import CONNECTION_CLOSED
    if isinstance(error, BaseExceptionGroup):
        return bool(error.exceptions) and all(protocol_loss(child) for child in error.exceptions)
    if isinstance(error, McpError):
        return error.error.code in (CONNECTION_CLOSED, 408)
    return isinstance(error, (EOFError, ConnectionError, TimeoutError,
                              anyio.EndOfStream, anyio.BrokenResourceError, anyio.ClosedResourceError))


def relay_terminal(directory, attempted, *, successful):
    terminal = json.loads((directory / "server-terminal.json").read_bytes())
    code = terminal.get("returnCode")
    if (terminal.get("complete") is not True or type(code) is not int
            or (code != 0 if successful else code > 0)
            or terminal.get("eof") != {"stdout": True, "stderr": True}
            or terminal.get("overflow") is not False or terminal.get("readError") is not False):
        raise ValueError("program_mcp_original_server_unclosed")
    for name in ("stdin", "stdout", "stderr"):
        pin = terminal["raw"][name]
        descriptor = os.open(directory / ("server." + name), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            generation = lambda value: [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                                         value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]
            raw = os.read(descriptor, 16 * 1024 * 1024 + 1)
            if (len(raw) != pin["bytes"] or hashlib.sha256(raw).hexdigest() != pin["sha256"]
                    or generation(info) != pin["generation"] or generation(os.fstat(descriptor)) != pin["generation"]
                    or generation(os.lstat(directory / ("server." + name))) != pin["generation"]):
                raise ValueError("program_mcp_raw_closing")
        finally:
            os.close(descriptor)
    delivery = terminal["delivery"]
    frames, forwarded = delivery["toolCallFrameCount"], delivery["fullyForwardedToolCallFrameCount"]
    if (type(frames) is not int or type(forwarded) is not int or not 0 <= forwarded <= frames <= attempted
            or successful and (frames != attempted or forwarded != attempted or delivery["pendingFrameBytes"] != 0)
            or delivery["stdinBytesWritten"] != terminal["raw"]["stdin"]["bytes"]):
        raise ValueError("program_mcp_delivery_unproved")
    unchanged = terminal.get("sourceUnchanged")
    if "sourceUnchanged" in terminal and type(unchanged) is not bool:
        raise ValueError("program_mcp_terminal_source_invalid")
    return forwarded, unchanged


async def main(arguments):
    expected = arguments.server_sha256
    server = ROOT / "agent_tools/mcp_server.py"
    if re.fullmatch("[0-9a-f]{64}", expected) is None or hashlib.sha256(server.read_bytes()).hexdigest() != expected:
        raise ValueError("program_mcp_server_source")
    body = json.loads(Path(arguments.request_file).read_bytes()) if arguments.request_file else None
    fixture = getattr(arguments, "fixture", None)
    payload = request(arguments.action, arguments.host, body, fixture) if arguments.action else None
    tool = "vm_workflow" if fixture is not None else "ssh_workflow"
    binding_field = {"fixtureId": fixture} if fixture is not None else {"host": arguments.host}
    if payload is None and (arguments.host or fixture or arguments.request_file):
        raise ValueError("program_mcp_unexpected_request")
    parent = Path(arguments.output_root)
    if not parent.is_absolute() or parent.resolve(strict=True) != parent or re.fullmatch("[A-Za-z0-9-]{1,80}", arguments.session) is None:
        raise ValueError("program_mcp_output")
    directory = parent / arguments.session
    directory.mkdir(mode=0o700)
    save(directory, "client-intent.json", {"request": payload, "serverSha256": expected,
                                           "automaticReplay": False, "clientPid": os.getpid()})
    environment = {key: value for key, value in os.environ.items() if not key.startswith("DYLD_")}
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(ROOT)
    follow = getattr(arguments, "follow", None)
    follow = arguments.action in ("program-start", "guest-program-start", "android-program-start") if follow is None else follow
    follow_seconds = getattr(arguments, "follow_seconds", 180)
    if type(follow_seconds) is not int or not 1 <= follow_seconds <= 600:
        raise ValueError("program_mcp_follow_deadline")
    deadline = asyncio.get_running_loop().time() + follow_seconds
    operation = body["operationId"] if payload is not None else None
    attempted_calls = returned_calls = forwarded_calls = 0
    attempts = []
    result = {"state": "unknown", "automaticReplay": False, "serverExecutionProven": False}
    active_payload = payload
    for attempt in range(3):
        relay = directory if attempt == 0 else directory / ("relay-recovery-%08d" % attempt)
        if attempt:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                result["followDeadlineReached"] = True
                break
            await asyncio.sleep(min(2 ** (attempt - 1), remaining))
            if asyncio.get_running_loop().time() >= deadline:
                result["followDeadlineReached"] = True
                break
            relay.mkdir(mode=0o700)
            # A lost request/reply never authorizes repeating program-start.
            active_payload = request("android-program-reconcile" if arguments.action.startswith("android-") else
                                     "guest-program-reconcile" if fixture is not None else "program-reconcile",
                                     arguments.host, {"operationId": operation}, fixture)
        parameters = StdioServerParameters(command=str(ROOT / ".agent_venv/bin/python"),
            args=["-B", str(ROOT / "agent_tools/ssh_keeper_mcp_relay.py"), str(relay), expected],
            cwd=ROOT, env=environment)
        save(directory, "relay-attempt-%08d.json" % attempt, {"directory": str(relay),
             "initialRequest": active_payload, "serverSha256": expected, "automaticReplay": False})
        before_calls = attempted_calls
        recoverable = False
        closed = False
        try:
            if hashlib.sha256(server.read_bytes()).hexdigest() != expected:
                raise ValueError("program_mcp_server_source_changed")
            with (relay / "sdk.stderr").open("x", encoding="utf-8") as errors:
                os.chmod(relay / "sdk.stderr", 0o600)
                # The follow deadline only stops new calls: an in-flight call
                # keeps a bounded grace so the relay closes and records its
                # terminal instead of being killed mid-call.
                async with asyncio.timeout_at(deadline + CLOSE_GRACE_SECONDS), stdio_client(parameters, errlog=errors) as streams:
                    async with ClientSession(*streams, read_timeout_seconds=timedelta(seconds=max(.01, min(30, deadline-asyncio.get_running_loop().time())))) as session:
                        initialized = await session.initialize()
                        save(relay, "initialize.json", initialized.model_dump(mode="json"))
                        inventory = await session.list_tools()
                        save(relay, "tools.json", inventory.model_dump(mode="json"))
                        if tool not in {entry.name for entry in inventory.tools}:
                            raise ValueError("program_mcp_tool_absent")
                        result = {"state": "protocol_ready", "automaticReplay": False, "serverExecutionProven": False}
                        while active_payload is not None:
                            remaining = deadline - asyncio.get_running_loop().time()
                            if remaining <= 0:
                                result["followDeadlineReached"] = True
                                break
                            ordinal = attempted_calls
                            save(directory, "call-intent-%08d.json" % ordinal, {"request": active_payload,
                                 "operationId": operation, "relayAttempt": attempt, "automaticReplay": False})
                            attempted_calls += 1
                            response = await session.call_tool(tool, active_payload,
                                read_timeout_seconds=timedelta(seconds=min(90, remaining + CLOSE_GRACE_SECONDS)))
                            returned_calls += 1
                            wire = response.model_dump(mode="json")
                            save(directory, "call-result-%08d.json" % ordinal, wire)
                            if ordinal == 0:
                                save(directory, "call-result.json", wire)
                            value = wire.get("structuredContent")
                            result.update(state="rpc_returned", toolError=response.isError,
                                          operationId=operation, **binding_field)
                            if type(value) is dict:
                                result.update(programState=value.get("state"), nextAction=value.get("nextAction"))
                            if response.isError or not follow:
                                break
                            active_payload = follow_request(active_payload["action"], arguments.host, operation, value, fixture)
                            if active_payload is not None:
                                await asyncio.sleep(min(.5, max(0, deadline-asyncio.get_running_loop().time())))
            forwarded, source_unchanged = relay_terminal(relay, attempted_calls-before_calls, successful=True)
            forwarded_calls += forwarded
            closed = True
            if source_unchanged is False or hashlib.sha256(server.read_bytes()).hexdigest() != expected:
                raise ValueError("program_mcp_server_source_changed")
        except Exception as error:
            recoverable = protocol_loss(error)
            result = {"state": "unknown", "exceptionClass": type(error).__name__, "automaticReplay": False,
                      "serverExecutionProven": False}
            if isinstance(error, ValueError) and str(error) in {"program_mcp_server_source_changed", "program_mcp_server_source"}:
                result["reason"] = str(error)
            if recoverable and (relay / "server-terminal.json").exists():
                try:
                    forwarded, source_unchanged = relay_terminal(relay, attempted_calls-before_calls, successful=False)
                    forwarded_calls += forwarded
                    closed = True
                    if source_unchanged is False:
                        recoverable = False
                        result["reason"] = "program_mcp_server_source_changed"
                except (OSError, ValueError, KeyError, TypeError):
                    recoverable = False
            if hashlib.sha256(server.read_bytes()).hexdigest() != expected:
                recoverable = False
                result["reason"] = "program_mcp_server_source_changed"
            if operation is not None:
                result.update(operationId=operation, **binding_field,
                              nextAction={"kind": "reconcile_original" if recoverable else "resolve_blocker"})
        receipt = {"attempt": attempt, "directory": str(relay), "result": result,
                   "protocolLoss": recoverable, "terminalClosed": closed,
                   "attemptedToolCalls": attempted_calls-before_calls, "automaticReplay": False}
        save(directory, "relay-result-%08d.json" % attempt, receipt)
        attempts.append(receipt)
        if not (recoverable and follow and operation is not None):
            break
    result.update(sdkCallAttempted=attempted_calls > 0, attemptedToolCalls=attempted_calls,
                  returnedToolCalls=returned_calls, forwardedToolCalls=forwarded_calls,
                  relayAttempts=len(attempts), originalServerTerminalClosed=bool(attempts and attempts[0]["terminalClosed"]),
                  allRelayAttemptsClosed=all(item["terminalClosed"] for item in attempts))
    save(directory, "client-result.json", result)
    print(json.dumps(result, sort_keys=True))
    return int(result["state"] == "unknown")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", required=True)
    parser.add_argument("--server-sha256", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--action", choices=ACTIONS)
    parser.add_argument("--host")
    parser.add_argument("--fixture")
    parser.add_argument("--request-file")
    follow_group = parser.add_mutually_exclusive_group()
    follow_group.add_argument("--follow", dest="follow", action="store_true")
    follow_group.add_argument("--no-follow", dest="follow", action="store_false")
    parser.set_defaults(follow=None)
    parser.add_argument("--follow-seconds", type=int, default=180)
    raise SystemExit(asyncio.run(main(parser.parse_args())))
