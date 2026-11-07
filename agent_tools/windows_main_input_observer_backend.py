"""PRIVATE finite binding to actual canonical2938 producer + bf05 QGA owner.

No network, native process or input starts on import or construction. The sole
operator supplies its already admitted live RetainedQgaOwner and held complete
canonical module; this adapter supplies no replacement route or admission flag.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def generation(info):
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def held_bytes(fd, size):
    need(type(size) is int and 0 <= size <= 2 * 1024 * 1024, "observer-rpc-capture-bound")
    chunks = []
    offset = 0
    while offset < size:
        value = os.pread(fd, min(262144, size-offset), offset)
        need(bool(value), "observer-rpc-short")
        chunks.append(value)
        offset += len(value)
    need(not os.pread(fd, 1, size), "observer-rpc-trailing")
    return b"".join(chunks)


@dataclass
class OriginalObserver:
    phase_id: str
    packet: dict
    plan: dict
    guest_pid: int | None = None
    result: dict | None = None
    protocol_result: dict | None = None
    stdout: bytes | None = None
    stderr: bytes | None = None
    rpc_rows: list = field(default_factory=list)


class CanonicalObserverBackend:
    def __init__(self, canonical_module, admitted_qga_owner, guest_context, source_lease,
                 fixed_renderer, expected_observer, native_record_sha256):
        self.canonical, self.qga = canonical_module, admitted_qga_owner
        self.context, self.lease = guest_context, source_lease
        self.renderer, self.expected_observer = fixed_renderer, expected_observer
        self.native_record_sha256 = native_record_sha256
        self.runs = []
        self.failed = False
        need(self.qga.peer_pid == expected_observer["qemuIdentity"]["pid"]
             and Path(self.qga.root) == Path("/home/kardinal/vc-win-d493a3731d2c")
             and self.context["deploymentId"] == expected_observer["qemuIdentity"]["deployment_id"]
             and self.context["ordinarySid"] == expected_observer["ordinarySid"]
             and self.context["boot"]["machineGuid"].casefold() == expected_observer["machineGuid"].casefold(),
             "same-current-qga-native-context")

    def guard(self):
        self.lease.verify_current_original_sources()
        self.qga.guard()

    def _call(self, original, command, arguments):
        need(command in {"guest-exec", "guest-exec-status"}, "fixed-read-only-observer-rpc")
        self.guard()
        value = self.qga.call(command, arguments, time.monotonic()+20)
        rpc = self.qga.current
        need(rpc is not None and not rpc.unknown and rpc.response is not None, "same-retained-rpc")
        rows = []
        for fd, path, size, digest in ((rpc.request_fd, Path(self.qga.root)/rpc.request_name, len(rpc.request), sha(rpc.request)),
                                      (rpc.raw_fd, Path(self.qga.root)/rpc.raw_name, len(rpc.raw), sha(rpc.raw))):
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and generation(info) == generation(path.lstat())
                 and sha(held_bytes(fd, size)) == digest, "actual-rpc-held-custody")
            rows.append({"fd": fd, "path": path, "generation": generation(info), "bytes": size, "sha256": digest})
        original.rpc_rows.append({"object": rpc, "captures": rows})
        self.guard()
        return value

    def run_current_main_read_only_observer_once(self, packet):
        need(not self.failed and type(packet) is dict and packet.get("inputPerformed") is False,
             "original-observer-backend-state")
        self.guard()
        prefix = "C:\\ProgramData\\VpnControlMainInputRead-"
        need(type(packet.get("directory")) is str and packet["directory"].startswith(prefix), "fixed-observer-directory")
        nonce = packet["directory"][len(prefix):]
        need(str(uuid.UUID(nonce)) == nonce and packet == self.renderer(self.expected_observer, nonce, self.native_record_sha256),
             "exact-fixed-rendered-observer-only")
        phase = str(uuid.uuid4())
        source = self.canonical._boot_bound(packet["program"], self.context).encode("utf-8-sig")
        plan = self.canonical.build_guest_exec(source, guest_context=self.context, phase_id=phase)
        original = OriginalObserver(phase, packet, plan)
        self.runs.append(original)  # Retain original BEFORE intent or first call.
        receipt = {"schemaVersion": 1, "phaseId": phase, "state": "input-observer-intent",
                   "programSha256": packet["programUtf8Sha256"], "parentSha256": packet["parentUtf8Sha256"],
                   "childSha256": packet["childUtf8Sha256"], "replayAllowed": False}
        try:
            need(self.qga.safe_journal(self.qga.prefix+".input-observer-"+phase+".intent.json", receipt), "observer-intent-custody")
            ack = self._call(original, "guest-exec", plan["arguments"])
            need(type(ack) is dict and type(ack.get("pid")) is int and ack["pid"] > 0, "observer-original-pid")
            original.guest_pid = ack["pid"]
            deadline = time.monotonic()+180
            while True:
                value = self._call(original, "guest-exec-status", {"pid": original.guest_pid})
                if value.get("exited") is True:
                    original.result = value
                    break
                need(time.monotonic() < deadline, "observer-original-terminal-unknown")
                time.sleep(.1)
            need(not value.get("out-truncated") and not value.get("err-truncated"), "observer-original-stream-truncated")
            original.stdout = base64.b64decode(value.get("out-data", ""), validate=True)
            original.stderr = base64.b64decode(value.get("err-data", ""), validate=True)
            need(len(original.stdout) <= 2*1024*1024 and len(original.stderr) <= 65536, "observer-original-stream-bound")
            # Preserve a known refusal before raising; a native failure is not
            # converted into permission to run a replacement observer or input.
            need(self.qga.safe_journal(self.qga.prefix+".input-observer-"+phase+".terminal.json", {
                **receipt, "state": "known-terminal", "guestPid": original.guest_pid, "result": value}), "observer-terminal-custody")
            need(type(value.get("exitcode")) is int and value["exitcode"] == 0 and not original.stderr,
                 "observer-known-native-refusal")
            decoded = json.loads(original.stdout.decode("utf-8-sig"))
            original.protocol_result = self.canonical.decode_guest_result(plan, decoded, self.context, original.guest_pid)
            self.validate_original_read_only_observer(original, packet)
            return original
        except BaseException as error:
            self.failed = True
            # Actual canonical owner preserves same socket/pid/frames and only
            # observes its original. It never retransmits or starts a successor.
            if original.result is None or self.qga.failed or self.qga.parked:
                self.qga.park_original(receipt, error)
            raise

    def validate_original_read_only_observer(self, original, packet):
        need(any(item is original for item in self.runs) and original.packet is packet
             and original.protocol_result is not None, "same-original-observer")
        self.guard()
        need(original.result["exited"] is True and original.result["exitcode"] == 0
             and original.stderr == b"", "same-original-terminal")
        protocol = original.protocol_result
        need(protocol.get("state") == "current-main-input-read-only-observed"
             and protocol.get("fixedParentSha256") == packet["parentUtf8Sha256"]
             and protocol.get("inputPerformed") is False and protocol.get("productOperation") is False
             and protocol.get("taskOperation") is False, "fixed-read-only-protocol")
        child = protocol["child"]
        need(type(child["pid"]) is int and child["pid"] > 0 and type(child["creationFileTime"]) is int
             and child["creationFileTime"] > 0 and child["sessionId"] == 2 and child["exitCode"] == 0
             and child["sourceSha256"] == packet["childUtf8Sha256"] and child["knownTerminal"] is True,
             "held-session-reader-terminal")
        need(set(protocol["captures"]) == {"stdout", "stderr"}, "reader-stream-roles")
        for capture in protocol["captures"].values():
            raw = base64.b64decode(capture["base64"], validate=True)
            need(type(capture["bytes"]) is int and 0 <= capture["bytes"] <= 65536
                 and capture["bytes"] == len(raw) and capture["sha256"] == sha(raw)
                 and capture["writersClosedByOwnedJobAndHandles"] is True, "source-produced-reader-stream-custody")
        need(protocol["captures"]["stderr"]["bytes"] == 0, "reader-stderr-refusal")
        for row in original.rpc_rows:
            rpc = row["object"]
            need(not rpc.unknown and rpc.response is not None and rpc.raw_saved_bytes == len(rpc.raw), "original-rpc-known-captured")
            for capture in row["captures"]:
                path = capture["path"]
                need(generation(path.lstat()) == capture["generation"], "original-rpc-named-generation")
                if rpc.closed:
                    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW)
                    try:
                        need(generation(os.fstat(fd)) == capture["generation"]
                             and sha(held_bytes(fd, capture["bytes"])) == capture["sha256"], "closed-original-rpc-custody")
                    finally:
                        os.close(fd)
                else:
                    need(generation(os.fstat(capture["fd"])) == capture["generation"]
                         and sha(held_bytes(capture["fd"], capture["bytes"])) == capture["sha256"], "held-original-rpc-custody")
        self.guard()
