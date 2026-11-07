"""Retain one original QGA request and its custody through an unknown outcome.

Importing this module performs no I/O. The caller supplies already admitted
paths, peer identity, guards, journals and descriptors. Unknown operations keep
their original socket, bytes and descriptors; observation never sends a frame.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import sys
import time


def _require(value, reason):
    if not value:
        raise ValueError(reason)


def _generation(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _held_hash(fd, length):
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        data = os.read(fd, 262144)
        if not data:
            break
        total += len(data)
        _require(total <= length, "retained_rpc_held_size")
        digest.update(data)
    _require(total == length, "retained_rpc_held_size")
    return digest.hexdigest()


def _write_exact_fd(fd, data):
    offset = 0
    while offset < len(data):
        count = os.write(fd, data[offset:])
        _require(type(count) is int and 0 < count <= len(data) - offset,
                 "retained_rpc_capture_write")
        offset += count
    return offset


def write_journal(root, name, value, *, guard):
    """Create one guarded journal with finite positive-count writes."""
    _require(callable(guard) and isinstance(root, (str, Path)), "retained_qga_journal_dependencies")
    root = Path(root)
    _require(root.is_absolute() and ".." not in root.parts and type(name) is str
             and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", name) is not None
             and name not in (".", ".."), "retained_qga_journal_name")
    guard()
    data = value if type(value) is bytes else (json.dumps(value, sort_keys=True) + "\n").encode()
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        _write_exact_fd(fd, data)
        os.fsync(fd)
        guard()
    finally:
        os.close(fd)


class RetainedQgaOwner:
    """Own requests, reporting and parking in the same original Python process.

    Construction only validates and binds explicit dependencies. A descriptor
    pair of (-1, -1) allows an owner to exist before host admission. Bind actual
    captures and the final RPC guard once, before the first call. The initial
    guard may admit only host journals; it must refuse unadmitted paths.
    """

    def __init__(self, root, prefix, peer_pid, guard, save, held_fds,
                 wire_fd, partial_wire_fd):
        _require(isinstance(root, (str, Path)), "retained_qga_root")
        self.root = Path(root)
        _require(self.root.is_absolute() and ".." not in self.root.parts,
                 "retained_qga_root")
        _require(type(prefix) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}", prefix)
                 is not None and prefix not in (".", ".."), "retained_qga_prefix")
        _require(type(peer_pid) is int and peer_pid > 0, "retained_qga_peer_pid")
        _require(callable(guard) and callable(save) and type(held_fds) is list,
                 "retained_qga_dependencies")
        _require(type(wire_fd) is int and type(partial_wire_fd) is int and
                 ((wire_fd == partial_wire_fd == -1) or
                  (wire_fd >= 0 and partial_wire_fd >= 0 and wire_fd != partial_wire_fd)),
                 "retained_qga_capture_fds")
        self.prefix = prefix
        self.peer_pid = peer_pid
        self.guard = guard
        self.journal_guard = guard
        self.save = save
        self.held_fds = held_fds
        self.wire_fd = wire_fd
        self.partial_wire_fd = partial_wire_fd
        self.captures_bound = wire_fd >= 0
        self.current = None
        self.sequence = 0
        self.reporting_failures = []
        self.failed = False
        self.parked = False
        self.finalized = False
        self.unknown_journal_path = None

    def bind_captures(self, wire_fd, partial_wire_fd, *, guard):
        """Bind capture descriptors and the final guard once, without I/O."""
        _require(not self.captures_bound and self.current is None and self.sequence == 0
                 and not self.failed and not self.parked and not self.finalized,
                 "retained_qga_capture_rebind")
        _require(type(wire_fd) is int and type(partial_wire_fd) is int and
                 wire_fd >= 0 and partial_wire_fd >= 0 and wire_fd != partial_wire_fd
                 and callable(guard), "retained_qga_capture_fds")
        self.wire_fd = wire_fd
        self.partial_wire_fd = partial_wire_fd
        self.guard = guard
        self.captures_bound = True

    def remember_reporting_failure(self, stage, error):
        self.failed = True
        try:
            if len(self.reporting_failures) >= 64:
                self.reporting_failures.pop(0)
            self.reporting_failures.append({"stage": stage, "errorClass": type(error).__name__,
                                            "error": str(error)[:512]})
        except BaseException:
            pass

    def safe_report(self, value):
        try:
            print(json.dumps(value, sort_keys=True))
            sys.stdout.flush()
            return True
        except BaseException as error:
            self.remember_reporting_failure("stdout", error)
            return False

    def safe_journal(self, name, value):
        try:
            _require(type(name) is str and name.startswith(self.prefix + ".") and
                     "/" not in name and "\\" not in name and "\x00" not in name,
                     "retained_qga_journal_name")
            self.journal_guard()
            self.save(name, value)
            if name == self.prefix + ".unknown.json":
                self.unknown_journal_path = str(self.root / name)
            return True
        except BaseException as error:
            self.remember_reporting_failure("journal:" + str(name), error)
            return False

    def call(self, command, args, deadline):
        _require(self.captures_bound and not self.failed and not self.parked
                 and not self.finalized, "retained_qga_call_state")
        try:
            self.guard()
            if self.current is not None:
                self.current.close_known()
            self.sequence += 1
            # Keep the original object before its first journal, open or send.
            self.current = RetainedRpc(self, command, args, deadline, self.sequence)
            return self.current.run()
        except BaseException:
            self.failed = True
            raise

    def finalize_known(self):
        _require(not self.failed and not self.parked and not self.finalized,
                 "retained_qga_finalize_state")
        try:
            self.guard()
            if self.current is not None:
                self.current.close_known()
            self.finalized = True
        except BaseException:
            self.failed = True
            raise

    def snapshot(self):
        return None if self.current is None else self.current.snapshot()

    def park_original(self, receipt, error):
        """Park without replay, reconnect, mutation resume, or custody cleanup."""
        self.failed = True
        self.parked = True
        late_index = 0
        last = None
        while True:
            try:
                try:
                    observation = (self.current.observe_same_wire(time.monotonic() + 1)
                                   if self.current is not None and self.current.unknown
                                   else self.snapshot())
                except BaseException as observation_error:
                    observation = {"errorClass": type(observation_error).__name__,
                                   "error": str(observation_error), "custodyRetained": True}
                fingerprint = hashlib.sha256(json.dumps(observation, sort_keys=True).encode()).hexdigest()
                if fingerprint != last:
                    late_index += 1
                    self.safe_journal(self.prefix + ".late-" + str(late_index).zfill(6) + ".json", {
                        "state": "pending", "immutableUnknownPath": self.unknown_journal_path,
                        "sameWireReadOnly": True, "automaticMutationResume": False,
                        "observation": observation})
                    last = fingerprint
                    self.safe_report({"state": "pending", "operationPrefix": self.prefix,
                                      "sameWireReadOnly": True, "automaticMutationResume": False,
                                      "observation": observation})
            except BaseException as preparation_error:
                # Fingerprinting and preparing reports are part of custody too.
                self.remember_reporting_failure("pending-preparation", preparation_error)
            try:
                time.sleep(1)
            except BaseException as sleep_error:
                self.remember_reporting_failure("pending-wait", sleep_error)


class RetainedRpc:
    """One original request. Only its owner may advance or finalize it."""

    def __init__(self, owner, command, args, deadline, sequence):
        _require(isinstance(owner, RetainedQgaOwner), "retained_rpc_owner")
        _require(type(command) is str and command and type(args) is dict,
                 "retained_rpc_command")
        _require(type(deadline) in (int, float), "retained_rpc_deadline")
        self.owner = owner
        self.command = command
        self.args = args
        self.started_monotonic = time.monotonic()
        self.deadline = min(self.started_monotonic + 20, deadline)
        self.read_timeout_polls = 0
        self.read_timeout_trace = []
        self.timing = None
        self.sequence = sequence
        self.request = (json.dumps({"execute": command, "arguments": args}, separators=(",", ":")) + "\n").encode()
        _require(len(self.request) <= 60000, "retained_rpc_request_bound")
        self.nonce = secrets.randbits(63)
        self.sync = b"\xff" + (json.dumps({"execute": "guest-sync-delimited", "arguments": {"id": self.nonce}}, separators=(",", ":")) + "\n").encode()
        self.client = self.request_fd = self.raw_fd = None
        self.raw = bytearray()
        self.buffer = bytearray()
        self.response = None
        self.phase = "constructed"
        self.frame = None
        self.sent = 0
        self.sync_sent = self.sync_known = self.command_sent = False
        self.unknown = self.eof = self.closed = self.read_refused = False
        self.capture_failure = None
        self.pending_reply = None
        self.reply_failure = None
        self.raw_saved_bytes = 0
        self.name = owner.prefix + ".rpc-" + str(sequence).zfill(6)
        self.request_name = self.name + ".request.json"
        self.raw_name = self.name + ".raw"

    def budget(self, deadline):
        remaining = deadline - time.monotonic()
        _require(remaining > 0, "retained_rpc_deadline")
        self.client.settimeout(min(1, remaining))

    def open(self):
        owner = self.owner
        owner.guard()
        owner.save(self.request_name, self.request)
        self.request_fd = os.open(owner.root / self.request_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        owner.held_fds.append(self.request_fd)
        self.request_generation = _generation(os.fstat(self.request_fd))
        self.raw_fd = os.open(owner.root / self.raw_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        owner.held_fds.append(self.raw_fd)
        self.raw_identity = _generation(os.fstat(self.raw_fd))[:6]
        _require(_generation(os.fstat(self.raw_fd)) == _generation(os.lstat(owner.root / self.raw_name)),
                 "retained_rpc_raw_named_opening")
        owner.save(self.name + ".intent.json", {"command": self.command, "requestPath": str(owner.root / self.request_name),
                   "requestBytes": len(self.request), "requestSha256": hashlib.sha256(self.request).hexdigest(),
                   "rawPath": str(owner.root / self.raw_name), "nonce": self.nonce, "sequence": self.sequence})
        self.client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.budget(self.deadline)
        self.client.connect(str(owner.root / "qga.sock"))
        peer = struct.unpack("3i", self.client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        _require(peer[:2] == (owner.peer_pid, os.geteuid()), "retained_rpc_peer")
        owner.guard()

    def send(self, frame, kind):
        _require(not self.unknown and not self.owner.failed and not self.owner.parked,
                 "retained_rpc_no_send_after_unknown")
        self.phase = kind + "-sending"
        self.frame = frame
        self.sent = 0
        while self.sent < len(frame):
            self.budget(self.deadline)
            count = self.client.send(frame[self.sent:])
            _require(type(count) is int and 0 < count <= len(frame) - self.sent, "retained_rpc_send")
            self.sent += count
        if kind == "sync":
            self.sync_sent = True
        else:
            self.command_sent = True
        self.phase = kind + "-waiting"

    def receive_line(self, deadline):
        while b"\n" not in self.buffer:
            _require(not self.eof and not self.read_refused, "retained_rpc_original_read_refused")
            self.budget(deadline)
            try:
                data = self.client.recv(min(4096, 524288 - len(self.raw) + 1, 262144 - len(self.buffer) + 1))
            except TimeoutError:
                # This is only a no-data poll on the original socket. The next
                # budget check still enforces this exact admitted deadline.
                if not self.unknown:
                    try:
                        self.read_timeout_polls += 1
                        if len(self.read_timeout_trace) < 16:
                            now = time.monotonic()
                            self.read_timeout_trace.append({"phase": self.phase,
                                "elapsedSeconds": now - self.started_monotonic,
                                "remainingSeconds": max(0, deadline - now)})
                    except BaseException:
                        pass
                continue
            if not data:
                self.eof = True
                raise ConnectionError("retained_rpc_original_wire_eof")
            self.raw.extend(data)
            self.buffer.extend(data)
            try:
                self.raw_saved_bytes += _write_exact_fd(self.raw_fd, data)
                os.fsync(self.raw_fd)
                _write_exact_fd(self.owner.partial_wire_fd, data)
                os.fsync(self.owner.partial_wire_fd)
            except BaseException as error:
                self.read_refused = True
                self.capture_failure = {"errorClass": type(error).__name__, "error": str(error),
                                        "rawMemoryBytes": len(self.raw), "rawFileBytesConfirmed": self.raw_saved_bytes}
                raise
            if len(self.raw) > 524288 or len(self.buffer) > 262144:
                self.read_refused = True
                raise ValueError("retained_rpc_response_bound_latched")
        end = self.buffer.index(b"\n") + 1
        line = bytes(self.buffer[:end])
        del self.buffer[:end]
        return line

    def receive_sync(self, deadline):
        for _ in range(32):
            line = self.receive_line(deadline)
            marker = line.rfind(b"\xff")
            if marker < 0:
                continue
            try:
                value = json.loads(line[marker + 1:])
            except (ValueError, UnicodeError):
                continue
            if type(value) is dict and type(value.get("return")) is int and value["return"] == self.nonce:
                self.sync_known = True
                return
        raise ValueError("retained_rpc_sync")

    def receive_reply(self, deadline):
        _require(self.pending_reply is None, "retained_rpc_original_reply_pending")
        self.pending_reply = self.receive_line(deadline)
        try:
            _write_exact_fd(self.owner.wire_fd, self.pending_reply)
            os.fsync(self.owner.wire_fd)
            value = json.loads(self.pending_reply)
            _require(type(value) is dict and set(value) in ({"return"}, {"error"}), "retained_rpc_reply_fields")
            self.response = value
            self.pending_reply = None
            self.phase = "reply-observed"
            return value
        except BaseException as error:
            # The original line has left the input buffer. Retain it and stop
            # reading; a later line must never be promoted to its response.
            self.read_refused = True
            self.reply_failure = {"errorClass": type(error).__name__, "error": str(error)}
            raise

    def run(self):
        try:
            self.open()
            self.send(self.sync, "sync")
            self.receive_sync(self.deadline)
            self.owner.guard()
            self.send(self.request, "command")
            value = self.receive_reply(self.deadline)
            _require("return" in value, "retained_rpc_remote_error")
            return value["return"]
        except BaseException as error:
            self.unknown = True
            self.failure = {"errorClass": type(error).__name__, "error": str(error)}
            raise
        finally:
            # Freeze original-run diagnostics. Read-only late observation must
            # not change the parked owner's fingerprint every second.
            try:
                self.timing = {"startedMonotonic": self.started_monotonic,
                    "deadlineMonotonic": self.deadline,
                    "elapsedSeconds": time.monotonic() - self.started_monotonic,
                    "readTimeoutPolls": self.read_timeout_polls,
                    "readTimeoutTrace": list(self.read_timeout_trace),
                    "readTimeoutTraceOverflow": self.read_timeout_polls > len(self.read_timeout_trace)}
            except BaseException:
                pass

    def snapshot(self):
        return {"sequence": self.sequence, "command": self.command, "phase": self.phase,
                "unknown": self.unknown, "nonce": self.nonce, "timing": self.timing,
                "frameBytes": None if self.frame is None else len(self.frame),
                "frameConfirmedSentBytes": self.sent, "syncSent": self.sync_sent,
                "syncKnown": self.sync_known, "commandSent": self.command_sent,
                "originalSocketRetained": self.client is not None and not self.closed,
                "wireEof": self.eof, "readRefused": self.read_refused,
                "captureFailure": self.capture_failure,
                "replyFailure": self.reply_failure,
                "pendingReplyBytes": 0 if self.pending_reply is None else len(self.pending_reply),
                "pendingReplySha256": None if self.pending_reply is None else hashlib.sha256(self.pending_reply).hexdigest(),
                "requestPath": str(self.owner.root / self.request_name),
                "requestBytes": len(self.request), "requestSha256": hashlib.sha256(self.request).hexdigest(),
                "rawPath": str(self.owner.root / self.raw_name), "rawBytes": len(self.raw),
                "rawSha256": hashlib.sha256(self.raw).hexdigest(),
                "rawFileBytesConfirmed": self.raw_saved_bytes,
                "rawCaptureComplete": self.raw_saved_bytes == len(self.raw),
                "bufferBytes": len(self.buffer), "bufferSha256": hashlib.sha256(self.buffer).hexdigest(),
                "response": self.response, "closed": self.closed}

    def observe_same_wire(self, deadline):
        _require(self.unknown and not self.closed, "retained_rpc_late_state")
        self.owner.guard()
        if self.response is not None or self.eof or self.read_refused or self.client is None:
            return self.snapshot()
        try:
            if self.command_sent:
                self.receive_reply(deadline)
            elif self.sync_sent and not self.sync_known:
                self.receive_sync(deadline)
                self.phase = "late-sync-only-command-not-sent"
        except (TimeoutError, OSError, ValueError) as error:
            self.lastObservationError = {"errorClass": type(error).__name__, "error": str(error)}
        self.owner.guard()
        return self.snapshot()

    def close_known(self):
        _require(not self.unknown and self.response is not None and not self.closed
                 and not self.owner.failed and not self.owner.parked,
                 "retained_rpc_close_requires_known_reply")
        self.owner.guard()
        _require(_generation(os.fstat(self.request_fd)) == self.request_generation
                 and _generation(os.lstat(self.owner.root / self.request_name)) == self.request_generation
                 and _held_hash(self.request_fd, len(self.request)) == hashlib.sha256(self.request).hexdigest(),
                 "retained_rpc_request_changed")
        raw_generation = _generation(os.fstat(self.raw_fd))
        _require(raw_generation[:6] == self.raw_identity
                 and _generation(os.lstat(self.owner.root / self.raw_name)) == raw_generation,
                 "retained_rpc_raw_changed")
        _require(self.raw_saved_bytes == len(self.raw)
                 and _held_hash(self.raw_fd, len(self.raw)) == hashlib.sha256(self.raw).hexdigest()
                 and _generation(os.fstat(self.raw_fd)) == raw_generation
                 and _generation(os.lstat(self.owner.root / self.raw_name)) == raw_generation,
                 "retained_rpc_raw_changed")
        self.owner.save(self.name + ".known.json", self.snapshot())
        self.owner.guard()
        _require(_generation(os.fstat(self.raw_fd)) == raw_generation
                 and _generation(os.lstat(self.owner.root / self.raw_name)) == raw_generation
                 and _generation(os.fstat(self.request_fd)) == self.request_generation
                 and _generation(os.lstat(self.owner.root / self.request_name)) == self.request_generation,
                 "retained_rpc_closing_changed")
        self.client.close()
        self.closed = True
        for fd in (self.request_fd, self.raw_fd):
            os.close(fd)
            self.owner.held_fds.remove(fd)


_CONSUMER_BRIDGE = "# Emitted by the canonical QGA owner factory; only delegates to that module.\nimport sys\nimport types\nHOST_ADMITTED=False\nQGA_MODULE=None\nQGA_OWNER=None\nQGA_MODULE_RECORD=None\nCURRENT_RPC=None\nREPORTING_FAILURES=[]\n\ndef qga_host_journal_guard():\n require(HOST_ADMITTED is True and len(parents)>0,'host_root_not_admitted')\n for fd,parent,name,identity in parents:\n  require(structure(os.fstat(fd))==identity and structure(os.lstat('/')if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False))==identity,'instance_parent_changed')\n instance_intent()\n\ndef save(name,value):return QGA_MODULE.write_journal(root,name,value,guard=qga_host_journal_guard)\n\ndef initialize_qga_owner(peer_pid):\n global QGA_MODULE,QGA_OWNER,QGA_MODULE_RECORD,REPORTING_FAILURES\n require(type(QGA_MODULE_SOURCE)is bytes and hashlib.sha256(QGA_MODULE_SOURCE).hexdigest()==QGA_MODULE_SHA,'qga_module_source_sha256')\n module=types.ModuleType('_vpn_control_windows_qga_'+QGA_MODULE_SHA);module.__name__+='_'+str(id(module));module.__file__=QGA_MODULE_ORIGIN\n require(module.__name__ not in sys.modules,'qga_module_preexisting');sys.modules[module.__name__]=module\n exec(compile(QGA_MODULE_SOURCE,QGA_MODULE_ORIGIN,'exec'),module.__dict__,module.__dict__)\n require(sys.modules[module.__name__]is module and module.RetainedQgaOwner.__module__==module.__name__ and module.RetainedRpc.__module__==module.__name__ and module.write_journal.__globals__ is module.__dict__,'qga_module_owner')\n QGA_MODULE=module;QGA_OWNER=module.RetainedQgaOwner(root,prefix,peer_pid,qga_host_journal_guard,save,held,-1,-1);REPORTING_FAILURES=QGA_OWNER.reporting_failures\n QGA_MODULE_RECORD={'sha256':QGA_MODULE_SHA,'bytes':len(QGA_MODULE_SOURCE),'origin':QGA_MODULE_ORIGIN,'moduleName':module.__name__,'registered':True,'completeNamespaceExecuted':True,'peerPid':peer_pid}\n return QGA_MODULE_RECORD\n\ndef pin_qga_source():\n require(hold_generated_bytes(prefix+'.canonical-qga.py',QGA_MODULE_SOURCE)==QGA_MODULE_SHA,'qga_module_held_sha256');save(prefix+'.canonical-qga.json',QGA_MODULE_RECORD)\n\ndef setup_qga_owner(extra_guard=None):\n global wire,partial_wire,QGA_GUARD\n qga_host_journal_guard();require(QGA_OWNER is not None and QGA_OWNER.current is None and not QGA_OWNER.captures_bound,'qga_owner_setup')\n row=read('qemu-started.json');require(row['pid']==QGA_OWNER.peer_pid,'qga_owner_peer_scope');process(row);owns(row['pid'],root/'qga.sock',True);named=os.lstat(root/'qga.sock')\n def guard():\n  process(row);require(os.lstat(root/'qga.sock').st_ino==named.st_ino,'qga_owner_socket_changed');instance_intent();closing()\n  if extra_guard is not None:extra_guard()\n QGA_GUARD=guard\n wire=os.open(root/(prefix+'.wire'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n partial_wire=os.open(root/(prefix+'.partial-wire'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n QGA_OWNER.bind_captures(wire,partial_wire,guard=guard)\n\ndef retained_call(command,args,_deadline):\n global CURRENT_RPC\n try:return QGA_OWNER.call(command,args,_deadline)\n finally:CURRENT_RPC=QGA_OWNER.current\n\ndef call(sock,command,args,_deadline=None):\n require(str(sock)==str(root/'qga.sock'),'qga_owner_socket_scope')\n return retained_call(command,args,overall_deadline if _deadline is None else _deadline)\n\ndef finalize_rpc_success():return QGA_OWNER.finalize_known()\ndef safe_journal(name,value):return QGA_OWNER.safe_journal(name,value)\ndef safe_report(value):return QGA_OWNER.safe_report(value)\ndef park_original(receipt,error):return QGA_OWNER.park_original(receipt,error)\n\ndef guest_state(pid):\n require(type(pid)is int and pid==QGA_OWNER.peer_pid,'qga_owner_observation_peer')\n require(retained_call('guest-ping',{},overall_deadline)=={},'qga_owner_ping')\n osinfo=retained_call('guest-get-osinfo',{},overall_deadline);require(type(osinfo)is dict,'qga_owner_osinfo')\n name=osinfo.get('pretty-name')or osinfo.get('name');name=name if type(name)is str and 0<len(name)<=256 and not any(ord(c)<32 for c in name)else None\n users=retained_call('guest-get-users',{},overall_deadline);require(type(users)is list and len(users)<=128,'qga_owner_users')\n ordinary=any(type(user)is dict and type(user.get('user'))is str and user['user'].rsplit('\\\\',1)[-1].casefold()==SETUP['user'].casefold()for user in users)\n return {'guestAgentReady':True,'ordinarySessionObserved':ordinary,'osName':name}\n"


def render_consumer_bridge(module_source):
    """Emit the actual registered-module caller bridge without performing I/O.

    The caller supplies exact canonical module bytes, then the normal host
    namespace defines its root, guards, declarations and operation body.
    """
    _require(type(module_source) is bytes and bool(module_source), "retained_qga_module_source")
    digest = hashlib.sha256(module_source).hexdigest()
    return "QGA_MODULE_SOURCE=" + repr(module_source) + "\nQGA_MODULE_SHA=" + repr(digest) + "\nQGA_MODULE_ORIGIN=" + repr("agent_tools/windows_qga_transfer.py@" + digest) + "\n" + _CONSUMER_BRIDGE


def render_consumer_caller(module_source, namespace_prelude, operation_body):
    """Emit and compile the complete caller that consumes this owner bridge."""
    _require(type(namespace_prelude) is str and type(operation_body) is str, "retained_qga_caller_source")
    source = namespace_prelude + "\n" + render_consumer_bridge(module_source) + "\n" + operation_body
    compile(source, "<windows-qga-consumer>", "exec")
    return source
