"""Fixed privileged READ-ONLY source closure for additional Windows guests.

Only the historical flat native fixture disk is inspected. No source selector,
copy, VM launch, guest command, reservation or installer action is exposed.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import stat
import subprocess
import math
import re
import selectors
import uuid
import time
from typing import Any

HOST = "archlinux"
SOURCE = "/home/kardinal/vpn-control-windows-native-20260907/task.qcow2"
SOURCE_ROOT = "/home/kardinal"
DESTINATIONS = (
    "/home/kardinal/vpn-control-windows-parallel-vm-secondary-20261005",
    "/home/kardinal/vpn-control-windows-parallel-vm-tertiary-20261005",
)
PORTS = (2339, 5939, 2338, 5938)
MACS = ("52:54:00:57:50:21", "52:54:00:57:50:22")
EXCLUDED = (
    "/home/kardinal/vpn-control-windows-msi-acceptance-cp117/task.qcow2",
    "/home/kardinal/vpn-control-windows-msi-native-20260907/clean-base.qcow2",
)
FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
MAX_OUTPUT = 131072
MIN_FREE_DISK = 32 * 1024 ** 3


def need(value, code):
    if not value:
        raise ValueError(code)


def generation(info):
    return [getattr(info, name) for name in FIELDS]


def parent_identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid]


def parent_pins(source, allowed_root):
    need(source.is_absolute() and allowed_root.is_absolute() and source.is_relative_to(allowed_root), "source-scope")
    need(os.path.realpath(source) == str(source), "source-ancestry")
    paths = []
    parent = source.parent
    while True:
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022, "source-parent")
        paths.append((parent, parent_identity(info)))
        if parent == allowed_root:
            return paths
        parent = parent.parent


def verify_source(source, fd, expected, parents):
    need(generation(os.fstat(fd)) == expected == generation(source.lstat()), "source-generation")
    for path, identity in parents:
        need(parent_identity(path.lstat()) == identity, "source-parent-generation")


def process_birth(proc, pid):
    try:
        raw = (proc / str(pid) / "stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    tail = raw.rsplit(")", 1)[1].split()
    need(len(tail) >= 20 and tail[19].isdigit(), "process-birth")
    return int(tail[19])


def holder_census(proc, identity, ignored, deadline, source_name):
    """Any invisible PID/fd or generation change refuses stopped-state proof.

    Ignore only this observer's exact source reader fd, never its whole PID.
    Unrelated readers also refuse: there must be no other source holder.
    """
    entries = list(proc.iterdir())
    need(len(entries) <= 8192, "process-bound")
    holders, qemu, macs, argv_users = [], [], set(), []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        need(time.monotonic() < deadline, "census-deadline")
        pid = int(entry.name)
        before = process_birth(proc, pid)
        if before is None:
            need(not entry.exists(), "process-generation")
            continue
        try:
            names = list((entry / "fd").iterdir())
        except FileNotFoundError:
            need(not entry.exists(), "process-generation")
            continue
        need(len(names) <= 8192, "fd-bound")
        for descriptor in names:
            if (pid, descriptor.name) == ignored:
                continue
            try:
                info = descriptor.stat()
            except FileNotFoundError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                holders.append({"pid": pid, "startTicks": before, "fd": descriptor.name})
                need(len(holders) <= 64, "holder-bound")
        try:
            comm = (entry / "comm").read_text(encoding="ascii").strip()
            if comm.startswith("qemu-system-"):
                raw = (entry / "cmdline").read_bytes()
                need(0 < len(raw) <= 65536, "qemu-argv-bound")
                argv = [os.fsdecode(v) for v in raw.rstrip(b"\0").split(b"\0")]
                qemu.append({"pid": pid, "startTicks": before, "executable": comm})
                need(len(qemu) <= 128, "qemu-bound")
                if any(source_name in token for token in argv):
                    argv_users.append({"pid": pid, "startTicks": before})
                for token in argv:
                    for part in token.split(","):
                        if part.startswith(("mac=", "macaddr=")):
                            macs.add(part.split("=", 1)[1].lower())
                            need(len(macs) <= 128, "mac-bound")
        except FileNotFoundError:
            # A disappearing process contributes no stable census admission.
            need(not entry.exists(), "process-generation")
            continue
        need(process_birth(proc, pid) == before, "process-generation")
    return {"complete": True, "holders": holders, "qemu": sorted(qemu, key=lambda x: x["pid"]), "macs": sorted(macs), "argvUsers": argv_users}


def tcp_conflicts(proc, ports):
    conflicts = set()
    for name in ("tcp", "tcp6"):
        raw = (proc / "net" / name).read_bytes()
        need(len(raw) <= 1048576, "tcp-bound")
        for line in raw.decode("ascii").splitlines()[1:]:
            fields = line.split()
            need(len(fields) >= 4 and ":" in fields[1], "tcp-schema")
            port = int(fields[1].split(":")[1], 16)
            if port in ports:
                # Any socket using the prospective port is a conflict, not
                # just a listener or a particular address family.
                conflicts.add(port)
    return sorted(conflicts)


def namespace_facts(proc, destinations, ports, macs, census):
    need(all(not os.path.lexists(path) for path in destinations), "destination-exists")
    need(not tcp_conflicts(proc, ports), "port-conflict")
    need(not set(macs) & set(census["macs"]), "mac-conflict")
    raw = (proc / "net" / "unix").read_bytes()
    need(len(raw) <= 1048576, "unix-bound")
    used = [line.split()[-1] for line in raw.decode("utf-8", "strict").splitlines()[1:] if len(line.split()) >= 8]
    need(not any(path == root or path.startswith(root + "/") for path in used for root in destinations), "socket-conflict")
    return {"destinationsAbsent": True, "portsAbsent": list(ports), "macsAbsent": list(macs),
            "qgaQmpTpmNamespacesAbsent": True}


def image_metadata(source):
    result = subprocess.run(("/usr/bin/qemu-img", "info", "--output=json", str(source)),
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=15, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    need(result.returncode == 0 and len(result.stdout) <= 16384, "image-observation")
    value = json.loads(result.stdout)
    need(type(value) is dict, "image-dependency-descriptor")
    need(not {"data-file", "data-file-raw"}.intersection(value), "image-external-data")
    if "format-specific" in value:
        descriptor = value["format-specific"]
        need(type(descriptor) is dict and descriptor.get("type") == "qcow2"
             and type(descriptor.get("data")) is dict, "image-dependency-descriptor")
        # ImageInfoSpecificQCow2 carries external data-file dependencies here,
        # independently of backing-filename. Presence alone refuses; an empty
        # or malformed dependency must never be treated as a standalone disk.
        need(not {"data-file", "data-file-raw"}.intersection(descriptor)
             and not {"data-file", "data-file-raw"}.intersection(descriptor["data"]),
             "image-external-data")
    need(value.get("format") == "qcow2" and value.get("backing-filename") is None
         and type(value.get("virtual-size")) is int and value["virtual-size"] == 96 * 1024 ** 3,
         "image-not-flat-96g")
    need(value.get("dirty-flag") is None or value.get("dirty-flag") is False, "image-dirty")
    return {"format": "qcow2", "backingFile": None, "virtualSizeBytes": value["virtual-size"]}


def hash_source(fd, size, deadline):
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    remaining = size
    while remaining:
        need(time.monotonic() < deadline, "hash-deadline")
        block = os.read(fd, min(1048576, remaining))
        need(bool(block), "source-short-read")
        digest.update(block)
        remaining -= len(block)
    need(not os.read(fd, 1), "source-growing")
    return digest.hexdigest()


def observe_source(source, allowed_root, proc, destinations, ports, macs, excluded, timeout_seconds,
                   minimum_free_disk=MIN_FREE_DISK):
    """Same code executes on the remote host and in causal TempFS tests.

    The public adapter supplies only the fixed constants. Tests project the
    paths/process table and native qemu-img boundary, never a native PASS.
    """
    start = time.monotonic()
    deadline = start + timeout_seconds
    parents = parent_pins(source, allowed_root)
    named = source.lstat()
    owner = allowed_root.lstat().st_uid
    need(stat.S_ISREG(named.st_mode) and named.st_uid == owner and named.st_nlink == 1
         and 0 < named.st_size <= 120 * 1024 ** 3, "source-file")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        expected = generation(os.fstat(fd))
        verify_source(source, fd, expected, parents)
        identity = (expected[0], expected[1])
        for path in excluded:
            if os.path.lexists(path):
                value = os.lstat(path)
                need(identity != (value.st_dev, value.st_ino), "cp117-source-excluded")
        census = holder_census(proc, identity, (os.getpid(), str(fd)), deadline, str(source))
        need(not census["holders"] and not census["argvUsers"], "source-held")
        space = os.statvfs(allowed_root)
        free = space.f_bavail * space.f_frsize
        need(free >= minimum_free_disk, "disk-free")
        namespace = namespace_facts(proc, destinations, ports, macs, census)
        metadata = image_metadata(source)
        verify_source(source, fd, expected, parents)
        # Stream the large disk only after cheap complete holder/shape/space/
        # namespace refusal gates. Disk bytes never enter a receipt or stdout.
        digest = hash_source(fd, expected[6], deadline)
        verify_source(source, fd, expected, parents)
        final = holder_census(proc, identity, (os.getpid(), str(fd)), deadline, str(source))
        need(not final["holders"] and not final["argvUsers"], "closing-source-held")
        need(final["qemu"] == census["qemu"] and final["macs"] == census["macs"], "closing-qemu-generation")
        namespace_facts(proc, destinations, ports, macs, final)
        verify_source(source, fd, expected, parents)
        return {"schemaVersion": 1, "host": HOST, "state": "observed", "sourceState": "stopped-observed",
                "nativeActionAllowed": False, "cloneAdmitted": False, "source": str(source),
                "sourceGeneration": expected, "sourceSha256": digest, "sourceSizeBytes": expected[6],
                "sourceParents": [{"path": str(p), "generation": v} for p, v in parents],
                "image": metadata, "holderCensusComplete": True, "sourceHolders": [],
                "qemuGenerations": final["qemu"], "namespace": namespace,
                "diskFreeBytes": free, "minimumDiskFreeBytes": minimum_free_disk,
                "observedAtUnixMs": time.time_ns() // 1000000,
                "durationSeconds": round(time.monotonic() - start, 3),
                "guestAccessVerified": False, "installedProductVerified": False}
    finally:
        os.close(fd)


def remote_program(timeout_seconds):
    functions = (need, generation, parent_identity, parent_pins, verify_source, process_birth,
                 holder_census, tcp_conflicts, namespace_facts, image_metadata, hash_source, observe_source)
    constants = {key: globals()[key] for key in ("HOST", "SOURCE", "SOURCE_ROOT", "DESTINATIONS", "PORTS", "MACS", "EXCLUDED", "FIELDS", "MIN_FREE_DISK")}
    header = "from __future__ import annotations\nimport os,stat,subprocess,time,json,hashlib\nfrom pathlib import Path\n"
    header += "\n".join(key + "=" + repr(value) for key, value in constants.items()) + "\n"
    body = "\n".join(inspect.getsource(function) for function in functions)
    entry = "\ntry:\n need(os.geteuid()==0,'privilege-required')\n value=observe_source(Path(SOURCE),Path(SOURCE_ROOT),Path('/proc'),DESTINATIONS,PORTS,MACS,EXCLUDED," + str(timeout_seconds) + ")\nexcept Exception as error:\n value={'schemaVersion':1,'host':HOST,'state':'unknown','sourceState':'unknown','nativeActionAllowed':False,'cloneAdmitted':False,'reason':str(error) if isinstance(error,ValueError) and str(error).replace('-','').isalnum() else type(error).__name__}\nprint(json.dumps(value,sort_keys=True,separators=(',',':')))\n"
    return header + body + entry


def credential_metadata(root):
    """Metadata guard only: never hash, print or persist credential bytes."""
    path = root / ".codex" / "arch-sudo.local"
    parent = path.parent.lstat()
    item = path.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
         and not parent.st_mode & 0o022, "credential-parent")
    need(stat.S_ISREG(item.st_mode) and item.st_uid == os.getuid()
         and stat.S_IMODE(item.st_mode) == 0o600 and item.st_nlink == 1
         and 0 < item.st_size <= 512, "credential-file")
    return parent_identity(parent), generation(item)


def config_metadata(root):
    """Guard private configuration generation without hashing credentials."""
    path = root / ".vm-hosts.local.json"
    parent = path.parent.lstat()
    item = path.lstat()
    need(stat.S_ISDIR(parent.st_mode) and stat.S_ISREG(item.st_mode)
         and item.st_uid == os.getuid() and item.st_nlink == 1
         and stat.S_IMODE(item.st_mode) == 0o600 and 0 < item.st_size <= 1048576,
         "configuration-file")
    return {"parent": parent_identity(parent), "generation": generation(item)}


def validate_report(value):
    """Typed fixed-scope observation; this never grants clone authority."""
    need(isinstance(value, dict) and type(value.get("schemaVersion")) is int
         and value["schemaVersion"] == 1 and value.get("host") == HOST
         and value.get("nativeActionAllowed") is False and value.get("cloneAdmitted") is False,
         "readonly-envelope")
    base = {"schemaVersion", "host", "state", "sourceState", "nativeActionAllowed", "cloneAdmitted"}
    if value.get("state") == "unknown":
        need(set(value) == base | {"reason"} and value.get("sourceState") == "unknown"
             and isinstance(value["reason"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value["reason"]),
             "unknown-envelope")
        return value
    fields = base | {"source", "sourceGeneration", "sourceSha256", "sourceSizeBytes", "sourceParents",
        "image", "holderCensusComplete", "sourceHolders", "qemuGenerations", "namespace", "diskFreeBytes",
        "minimumDiskFreeBytes", "observedAtUnixMs", "durationSeconds", "guestAccessVerified", "installedProductVerified"}
    need(set(value) == fields and value.get("state") == "observed" and value.get("sourceState") == "stopped-observed"
         and value.get("source") == SOURCE and value.get("holderCensusComplete") is True
         and value.get("sourceHolders") == [] and value.get("guestAccessVerified") is False
         and value.get("installedProductVerified") is False, "observed-envelope")
    gen = value["sourceGeneration"]
    need(isinstance(gen, list) and len(gen) == 9 and all(type(x) is int and x >= 0 for x in gen)
         and stat.S_ISREG(gen[2]) and gen[5] == 1 and 0 < gen[6] <= 120 * 1024 ** 3
         and type(value["sourceSizeBytes"]) is int and value["sourceSizeBytes"] == gen[6]
         and isinstance(value["sourceSha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["sourceSha256"]),
         "source-envelope")
    parents = value["sourceParents"]
    need(isinstance(parents, list) and len(parents) == 2, "parents-envelope")
    for row, path in zip(parents, (str(Path(SOURCE).parent), SOURCE_ROOT)):
        need(isinstance(row, dict) and set(row) == {"path", "generation"} and row["path"] == path
             and isinstance(row["generation"], list) and len(row["generation"]) == 5
             and all(type(x) is int and x >= 0 for x in row["generation"])
             and stat.S_ISDIR(row["generation"][2]) and not row["generation"][2] & 0o022, "parent-envelope")
    need(gen[3] == parents[-1]["generation"][3], "source-owner-envelope")
    need(value["image"] == {"format": "qcow2", "backingFile": None, "virtualSizeBytes": 96 * 1024 ** 3}
         and type(value["image"]["virtualSizeBytes"]) is int, "image-envelope")
    namespace = value["namespace"]
    need(isinstance(namespace, dict) and set(namespace) == {"destinationsAbsent", "portsAbsent", "macsAbsent", "qgaQmpTpmNamespacesAbsent"}
         and namespace["destinationsAbsent"] is True and namespace["qgaQmpTpmNamespacesAbsent"] is True
         and namespace["portsAbsent"] == list(PORTS) and all(type(p) is int for p in namespace["portsAbsent"])
         and namespace["macsAbsent"] == list(MACS), "namespace-envelope")
    for name in ("diskFreeBytes", "minimumDiskFreeBytes", "observedAtUnixMs"):
        need(type(value[name]) is int and value[name] > 0, "resource-envelope")
    need(abs(time.time_ns() // 1000000 - value["observedAtUnixMs"]) <= 30000, "observation-stale")
    need(value["minimumDiskFreeBytes"] == MIN_FREE_DISK and value["diskFreeBytes"] >= MIN_FREE_DISK
         and type(value["durationSeconds"]) in (int, float) and math.isfinite(value["durationSeconds"])
         and 0 <= value["durationSeconds"] <= 300, "resource-envelope")
    qemu = value["qemuGenerations"]
    need(isinstance(qemu, list) and len(qemu) <= 128, "qemu-envelope")
    seen = set()
    for row in qemu:
        need(isinstance(row, dict) and set(row) == {"pid", "startTicks", "executable"}
             and type(row["pid"]) is int and row["pid"] > 0 and row["pid"] not in seen
             and type(row["startTicks"]) is int and row["startTicks"] > 0
             and isinstance(row["executable"], str) and re.fullmatch(r"qemu-system-[a-zA-Z0-9_-]{1,40}", row["executable"]),
             "qemu-envelope")
        seen.add(row["pid"])
    return value


def bounded_collect(argv, secret, timeout_seconds):
    """Bound actual client allocation; retain the original prefix on refusal.

    On deadline/overflow only this owned read-only SSH client is terminated.
    Its remote read remains unknown; no VM/native operation is cancelled.
    """
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    raw, eof, reason = bytearray(), False, None
    deadline = time.monotonic() + timeout_seconds
    stopped_for_bound = False
    try:
        try:
            process.stdin.write(secret)
            process.stdin.close()
        except OSError:
            reason = "stdin-unavailable"
        selector.register(process.stdout, selectors.EVENT_READ)
        while not eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "transport-deadline"
                break
            for key, _ in selector.select(min(remaining, .1)):
                block = os.read(key.fileobj.fileno(), min(4096, MAX_OUTPUT + 1 - len(raw)))
                if not block:
                    eof = True
                    break
                raw.extend(block)
                if len(raw) > MAX_OUTPUT:
                    reason = "transport-output-limit"
                    break
            if len(raw) > MAX_OUTPUT:
                break
        code = process.poll()
        if eof and code is None:
            try:
                code = process.wait(timeout=max(.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                reason = "transport-deadline"
        if reason is None and code != 0:
            reason = "transport-nonzero"
        return bytes(raw), {"pid": process.pid, "stdoutEof": eof, "exitCode": code,
                            "reason": reason, "clientTerminatedForBound": reason is not None and process.poll() is None}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()
        selector.close()


def observe(root: Path | str, *, host: str, timeout_seconds: int = 240) -> dict[str, Any]:
    """Fixed configured Arch privileged read; no caller commands or paths."""
    need(host == HOST and type(timeout_seconds) is int and 30 <= timeout_seconds <= 300, "inputs")
    # These existing reviewed helpers validate the prepared SSH socket/master,
    # quote the fixed Python command and guard the private ignored sudo file.
    from . import ssh_transport, windows_credential_probe_ssh as launcher
    from . import windows_cp117_bound_absence_completion as authority
    from . import windows_vm_virt_firmware_install as credential
    root = Path(root).resolve(strict=True)
    outer = authority._outer_authority(root)
    modules = [Path(__file__), Path(ssh_transport.__file__), Path(launcher.__file__),
               Path(authority.__file__), Path(credential.__file__)]
    pins = {str(path): authority._read_bound_file(path) for path in modules}
    config_pin = config_metadata(root)
    source = remote_program(timeout_seconds - 10)
    wrapper = "import sys,subprocess,base64\nsecret=sys.stdin.buffer.read(513)\nif not 1<=len(secret)<=512 or b'\\0' in secret:raise SystemExit(2)\nif not secret.endswith(b'\\n'):secret+=b'\\n'\nr=subprocess.run(['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-c',base64.b64decode(" + repr(base64.b64encode(source.encode()).decode()) + ").decode()],input=secret,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=" + str(timeout_seconds - 5) + ",check=False)\nsecret=None\nif len(r.stdout)<=" + str(MAX_OUTPUT) + ":sys.stdout.buffer.write(r.stdout)\nelse:raise SystemExit(3)\nsys.exit(r.returncode)\n"
    config = ssh_transport.load_config(root)
    # Connection admission and the bounded disk observation have independent
    # deadlines; the shared SSH builder accepts at most 60 seconds to connect.
    argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout_seconds, 60),
                                        command=launcher._remote_command(wrapper))
    authority._verify_outer(root, {"outerAuthority": outer})
    credential_pin = credential_metadata(root)
    secret = credential._read_credential(root)
    need(credential_pin == credential_metadata(root), "credential-generation")
    from .windows_diagnostic_authority_capture import AuthorityCapture
    leaf = "windows-parallel-vm-source-read-" + uuid.uuid4().hex
    evidence = root / ".runtime" / "parity-evidence" / leaf
    evidence.mkdir(mode=0o700)
    capture = AuthorityCapture(root, leaf)
    try:
        capture.create("request.json", json.dumps({"toolSources": pins, "configPin": config_pin,
            "configuredTransportAuthority": outer["receiptSha256"], "remoteProgramSha256": hashlib.sha256(source.encode()).hexdigest(),
            "nativeActionAllowed": False}, sort_keys=True).encode())
        capture.create("remote.py", source.encode())
        raw, trace = bounded_collect(argv, secret, timeout_seconds)
        secret = None
        # Durable original raw precedes any parsing and remains available when
        # schema, source or configured transport rechecks refuse admission.
        raw_pin = capture.create("transport.stdout.private", raw)
        capture.create("transport.json", json.dumps(trace, sort_keys=True).encode())
        try:
            authority._verify_outer(root, {"outerAuthority": outer})
            need(config_pin == config_metadata(root), "config-generation")
            need(pins == {str(path): authority._read_bound_file(path) for path in modules}, "tool-source-generation")
            need(trace["reason"] is None and trace["stdoutEof"] is True and trace["exitCode"] == 0, "readonly-transport")
            value = validate_report(json.loads(raw))
        except (ValueError, OSError, TypeError, KeyError):
            value = {"schemaVersion": 1, "host": HOST, "state": "unknown", "sourceState": "unknown",
                     "nativeActionAllowed": False, "cloneAdmitted": False, "reason": trace["reason"] or "readonly-output-or-authority"}
        capture.create("result.json", json.dumps(value, sort_keys=True).encode())
        return {**value, "toolSources": pins, "remoteProgramSha256": hashlib.sha256(source.encode()).hexdigest(),
                "configuredTransportAuthority": outer["receiptSha256"], "evidenceLeaf": leaf,
                "rawReceipt": raw_pin, "transport": trace}
    finally:
        secret = None
        capture.close()
