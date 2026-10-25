"""Bounded read-only guest probe; transferred as verified public source."""
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import hashlib
import stat
import time
import sys
import types
import uuid

_UNITS = frozenset({"systemd-journald.service", "multipathd.service", "systemd-udevd.service",
                   "systemd-resolved.service", "systemd-timesyncd.service", "systemd-networkd.service",
                   "cron.service", "dbus.service", "polkit.service", "systemd-logind.service",
                   "tart-guest-agent.service", "udisks2.service", "unattended-upgrades.service",
                   "rsyslog.service", "getty@tty1.service", "ModemManager.service", "packagekit.service",
                   "fwupd.service"})


def _generation(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _unit(unit):
    if unit not in _UNITS:
        raise ValueError("guest_service_unrecognized")
    value = _call(["systemctl", "show", unit, "-p", "MainPID", "-p", "FragmentPath",
                   "-p", "ActiveState", "-p", "SubState"]).decode("utf-8")
    fields = dict(line.split("=", 1) for line in value.splitlines() if "=" in line)
    if set(fields) != {"MainPID", "FragmentPath", "ActiveState", "SubState"}:
        raise ValueError("guest_service_unavailable")
    path = Path(fields["FragmentPath"]).resolve(strict=True)
    if path.parent not in {Path("/usr/lib/systemd/system"), Path("/etc/systemd/system")}:
        raise ValueError("guest_service_unrecognized")
    for parent in path.parents:
        info = parent.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("guest_service_unsafe")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise ValueError("guest_service_unsafe")
    return fields, path, _generation(info)


def baseline_units():
    """Capture only reviewed public static unit artifacts before private input."""
    result = {}
    for unit in sorted(_UNITS):
        fields, path, generation = _unit(unit)
        source = path.read_bytes()
        if _generation(path.stat()) != generation:
            raise ValueError("guest_service_changed")
        result[unit] = {"fragment": str(path), "sha256": hashlib.sha256(source).hexdigest(),
                        "generation": generation}
    return result


def cgroup_unit(raw):
    names = {part for line in raw.splitlines() for part in line.split("/") if part.endswith(".service")}
    return next(iter(names)) if len(names) == 1 else None


def _guest_owner_facts():
    """Inspect admitted original owners; no process is not absence proof."""
    rows = []
    try:
        roots = {str(path) for path in Path("/tmp").glob("vpn-control-program-*")}
        packets = globals().get("__guest_jobs__", [])
        if type(packets) is not list or len(packets) > 64 or len(roots) > 4096:
            raise ValueError("guest_owner_visibility_incomplete")
        known = {}
        for packet in packets:
            if type(packet) is not dict or set(packet) != {"remoteRoot", "generation", "binding", "operationId", "requestSha256", "ownerSourceSha256"}:
                raise ValueError("guest_owner_packet_invalid")
            operation = str(uuid.UUID(packet["operationId"]))
            if operation != packet["operationId"] or packet["remoteRoot"] != "/tmp/vpn-control-program-" + str(os.getuid()) + "-" + operation or packet["remoteRoot"] in known:
                raise ValueError("guest_owner_packet_invalid")
            binding = packet["binding"]
            if type(binding) is not dict or set(binding) != {"target", "machine", "boot", "account"} or binding["account"] != str(os.getuid()) or binding["machine"] != Path("/etc/machine-id").read_text().strip():
                raise ValueError("guest_owner_binding_changed")
            if type(packet["generation"]) is not list or len(packet["generation"]) != 2 or not all(type(n) is int and n >= 0 for n in packet["generation"]):
                raise ValueError("guest_owner_packet_invalid")
            known[packet["remoteRoot"]] = packet
        if roots != set(known):
            return {"complete": False, "running": [], "unknown": [{"role": "unadmitted_durable_namespace"}]}
        if not known:
            return {"complete": True, "running": [], "unknown": []}
        source = globals().get("__owner_source__")
        if type(source) is not bytes:
            raise ValueError("guest_owner_observer_unavailable")
        digest = hashlib.sha256(source).hexdigest()
        module = types.ModuleType("tart_fixed_owner_observer")
        module.__file__ = "<fixed-tart-owner-observer>"
        sys.modules[module.__name__] = module
        exec(compile(source, module.__file__, "exec"), module.__dict__)
        running, unknown = [], []
        for root, packet in known.items():
            if packet["ownerSourceSha256"] != digest:
                raise ValueError("guest_owner_observer_changed")
            binding = module.MachineBinding.from_dict(packet["binding"])
            state = module.observe(root, packet["operationId"], binding, generation=tuple(packet["generation"]))
            row = {"operationId": packet["operationId"], "role": "durable_" + state["state"]}
            if state["state"] == "running":
                running.append(row)
            elif state["state"] == "terminal":
                # Closed receipt alone is insufficient; retained streams must
                # still match their original terminal digests.
                module.collect(root, packet["operationId"], binding, generation=tuple(packet["generation"]))
            else:
                unknown.append(row)
        return {"complete": True, "running": running, "unknown": unknown}
    except (OSError, ValueError, TypeError, KeyError):
        return {"complete": False, "running": [], "unknown": [{"role": "durable_owner_visibility_incomplete"}]}


def _job_facts(baseline):
    rows, units, complete = [], {}, bool(baseline) and set(baseline) == _UNITS
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = dict(line.split(":", 1) for line in (entry / "status").read_text().splitlines())
            tail = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if "Kthread" not in status:
                complete = False
            if status.get("Kthread", "").strip() == "1" or tail[0] == "Z":
                continue
            pid, birth = int(entry.name), "linux:" + tail[19]
            unit = cgroup_unit((entry / "cgroup").read_text())
            role = "unmanaged"
            if pid == os.getpid():
                role = "verified_probe"
            elif pid == 1 and int(status["Uid"].split()[1]) == 0 and status["Name"].strip() == "systemd" and tail[1] == "0":
                role = "guest_init"
            elif unit in baseline and unit in _UNITS:
                if unit not in units:
                    fields, path, generation = _unit(unit)
                    expected = baseline[unit]
                    # Do not read/hash changed unit bytes: they could now carry
                    # private input. The original public artifact generation is pinned.
                    if set(expected) != {"fragment", "sha256", "generation"} or expected["fragment"] != str(path) or expected["generation"] != generation:
                        raise ValueError("guest_service_integrity_changed")
                    units[unit] = fields
                fields = units[unit]
                if fields["MainPID"] == str(pid) and fields["ActiveState"] == "active" and fields["SubState"] == "running":
                    role = "baseline_service"
            if (entry / "stat").read_text().rsplit(")", 1)[1].split()[19] != tail[19]:
                complete = False
            rows.append({"pid": pid, "birth": birth, "role": role})
        except FileNotFoundError:
            continue
        except (OSError, ValueError, IndexError, KeyError):
            complete = False
    unknown = [row for row in rows if row["role"] == "unmanaged"]
    owners = _guest_owner_facts()
    try:
        Path("/var/tmp/vc-recovery-jobs").lstat()
        canonical_present = True
    except FileNotFoundError:
        canonical_present = False
    except OSError:
        canonical_present = True
    legacy_complete = complete and owners["complete"]
    return {"jobVisibilityComplete": legacy_complete and not canonical_present,
            "legacyJobVisibilityComplete": legacy_complete, "canonicalOwnerPresent": canonical_present,
            "runningJobs": unknown + owners["running"],
            "unknownJobs": unknown + owners["unknown"], "processVisibilityComplete": complete}


def _call(argv):
    value = subprocess.run(argv, capture_output=True, timeout=10, check=False)
    if value.returncode or len(value.stdout) > 65536 or len(value.stderr) > 65536:
        raise ValueError("guest_observation_unavailable")
    return value.stdout


def installer_role(pid, command, service, transactions=None):
    """Only exact, systemd-correlated idle daemons are exempted."""
    fields = dict(line.split("=", 1) for line in service.splitlines() if "=" in line)
    if fields != {"MainPID": str(pid), "ActiveState": "active", "SubState": "running"}:
        return "blocked"
    if command == b"/usr/bin/python3\0/usr/share/unattended-upgrades/unattended-upgrade-shutdown\0--wait-for-signal\0":
        return "shutdown_waiter"
    if command == b"/usr/libexec/packagekitd\0" and transactions == b"ao 0\n":
        return "packagekit_idle"
    # fwupd's public Status enum defines IDLE=1. A virtual fixture with no
    # detected devices and no update history has no queued firmware work.
    # https://fwupd.github.io/libfwupd/enum.Status.html
    if command == b"/usr/libexec/fwupd/fwupd\0" and transactions == (
            (0, b"u 1\n", b""),
            (1, b"", b"Call failed: No detected devices\n"),
            (1, b"", b"Call failed: No history\n")):
        return "fwupd_idle_no_devices"
    return "blocked"


def main():
    result = {"uid": os.getuid(), "account": pwd.getpwuid(os.getuid()).pw_name,
              "machine": Path("/etc/machine-id").read_text().strip(),
              "boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
              "observedEpoch": time.time()}
    parent = Path("/proc", str(os.getppid()))
    agent, _, _ = _unit("tart-guest-agent.service")
    if agent["MainPID"] != str(os.getppid()) or cgroup_unit((parent / "cgroup").read_text()) != "tart-guest-agent.service":
        raise ValueError("guest_agent_identity_unavailable")
    result["agentIdentity"] = "linux:" + str(os.getppid()) + ":" + (parent / "stat").read_text().rsplit(")", 1)[1].split()[19]
    protected = re.compile(r"(sing.?box|vpn.?control|openvpn|wireguard|tailscaled|zerotier|charon|strongswan|pppd)", re.I)
    installers = re.compile(r"(apt|dpkg|unattended|snapd|packagekit|fwupd|rpm|dnf|yum|installer)", re.I)
    processes = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                processes.append((int(entry.name), (entry / "comm").read_text().strip()))
            except FileNotFoundError:
                pass
    if len(processes) > 4096:
        raise ValueError("guest_process_overflow")
    result["protectedProcesses"] = [pid for pid, name in processes if protected.search(name)]
    result["installerRoles"] = []
    for pid, name in processes:
        if not installers.search(name):
            continue
        command = Path("/proc", str(pid), "cmdline").read_bytes()
        unit = ("unattended-upgrades" if command == b"/usr/bin/python3\0/usr/share/unattended-upgrades/unattended-upgrade-shutdown\0--wait-for-signal\0"
                else "packagekit" if command == b"/usr/libexec/packagekitd\0"
                else "fwupd" if command == b"/usr/libexec/fwupd/fwupd\0" else None)
        if unit is None:
            role = "blocked"
        else:
            service = _call(["systemctl", "show", unit, "-p", "MainPID", "-p", "ActiveState", "-p", "SubState"]).decode("utf-8")
            transactions = (_call(["busctl", "--auto-start=no", "call", "org.freedesktop.PackageKit",
                                   "/org/freedesktop/PackageKit", "org.freedesktop.PackageKit", "GetTransactionList"])
                            if unit == "packagekit" else None)
            if unit == "fwupd":
                replies = []
                for suffix in (["get-property", "org.freedesktop.fwupd", "/", "org.freedesktop.fwupd", "Status"],
                               ["call", "org.freedesktop.fwupd", "/", "org.freedesktop.fwupd", "GetDevices"],
                               ["call", "org.freedesktop.fwupd", "/", "org.freedesktop.fwupd", "GetHistory"]):
                    reply = subprocess.run(["busctl", "--auto-start=no", *suffix], capture_output=True, timeout=10)
                    if len(reply.stdout) > 65536 or len(reply.stderr) > 65536:
                        raise ValueError("guest_observation_overflow")
                    replies.append((reply.returncode, reply.stdout, reply.stderr))
                transactions = tuple(replies)
            role = installer_role(pid, command, service, transactions)
        result["installerRoles"].append({"pid": pid, "role": role})
    locks = Path("/proc/locks").read_text()
    if len(locks) > 262144:
        raise ValueError("guest_lock_overflow")
    result["installerLocks"] = []
    for filename in ("/var/lib/dpkg/lock", "/var/lib/dpkg/lock-frontend", "/var/cache/apt/archives/lock"):
        path = Path(filename)
        if path.exists():
            info = path.stat()
            if f"{os.major(info.st_dev):02x}:{os.minor(info.st_dev):02x}:{info.st_ino}" in locks:
                result["installerLocks"].append(filename)
    updates = Path("/var/lib/dpkg/updates")
    result["installerUpdates"] = [p.name for p in updates.iterdir() if p.name.isdigit()] if updates.is_dir() else []
    result["systemdJobs"] = _call(["systemctl", "list-jobs", "--no-legend", "--no-pager"]).decode("utf-8").strip()
    result["interactiveSessions"] = _call(["who"]).decode("utf-8").strip()
    result["displayManager"] = _call(["systemctl", "show", "display-manager", "-p", "LoadState", "-p", "ActiveState"]).decode("utf-8").strip()
    result["processCount"] = len(processes)
    result.update(_job_facts(globals().get("__baseline__", {})))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
