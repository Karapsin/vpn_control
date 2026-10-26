"""Enroll a VM host's fixture storage ledger and claim its running fixtures.

Writers on a Linux VM host (the managed Windows creator, the libvirt Windows
lifecycle and the creator pre-VM proof) refuse unless
``~/.cache/vpn-control-fixture-storage`` exists with its lock, and unless every
writable disk of every running VM is claimed there. No writer creates that
state, so a host whose ledger was never set up blocks every one of them with a
generic typed result. This helper is the explicit operator step:

- ``enroll`` creates the ledger directory (0700) and lock (0600) through
  ``StoragePlans._locked``, or validates an existing one;
- ``coverage`` reports, read-only, the running VM disks without a claim;
- ``register`` claims named running fixtures through ``StoragePlans.reserve``,
  bound to their exact QEMU process. It never stops, starts or changes a VM.

Host-side functions use only the standard library and the storage module, so
the same source runs on the host through the admitted SSH transport.
"""
import json
import os
import stat
import subprocess

LEDGER = "~/.cache/vpn-control-fixture-storage"
# Same writable-disk predicate as readiness_windows_lifecycle._storage_vm_coverage.
DISK_SUFFIXES = (".qcow2", ".img", ".raw", ".vhd", ".vhdx", ".fd")
FIRMWARE_VARS_BYTES = 8 * 1024**2


class HostStorageError(ValueError):
    pass


def _need(condition, reason):
    if not condition:
        raise HostStorageError(reason)


def birth(pid, proc="/proc"):
    with open("%s/%d/stat" % (proc, pid)) as stream:
        return int(stream.read().rsplit(")", 1)[1].split()[19])


def enroll(storage, ledger):
    """Create the ledger once, or validate the existing one; never rewrites claims."""
    ledger = os.path.abspath(os.path.expanduser(ledger))
    existed = os.path.lexists(ledger)
    with storage.StoragePlans(ledger)._locked():
        pass
    info = os.lstat(ledger)
    lock = os.lstat(os.path.join(ledger, "storage-plans.lock"))
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022
          and stat.S_ISREG(lock.st_mode) and lock.st_uid == os.geteuid() and lock.st_nlink == 1
          and stat.S_IMODE(lock.st_mode) == 0o600, "fixture_storage_host_enrollment_unsafe")
    plans = storage.StoragePlans(ledger)._read()["plans"]
    return {"state": "already-enrolled" if existed else "enrolled", "ledger": ledger, "plans": len(plans)}


def writable_disks(pid, proc="/proc"):
    """Writable VM disk paths a running actor holds, exactly as coverage sees them."""
    base = "%s/%d" % (proc, pid)
    names = os.listdir(base + "/fd")
    _need(len(names) <= 8192, "fixture_storage_host_descriptor_limit")
    disks = []
    for name in names:
        try:
            info = os.stat(base + "/fd/" + name)
            if not stat.S_ISREG(info.st_mode):
                continue
            with open(base + "/fdinfo/" + name) as stream:
                flags = [row.split()[1] for row in stream.read(8193).splitlines() if row.startswith("flags:")]
            _need(len(flags) == 1, "fixture_storage_host_descriptor_unknown")
            if int(flags[0], 8) & os.O_ACCMODE == os.O_RDONLY:
                continue
            path = os.readlink(base + "/fd/" + name)
        except FileNotFoundError:
            continue
        if (path.endswith(DISK_SUFFIXES) or info.st_size >= 1024**3) and path not in disks:
            disks.append(path)
    return sorted(disks)


def qemu_actors(proc="/proc"):
    """Same-account QEMU processes: {pid: (startTicks, command line)}."""
    actors = {}
    for entry in os.listdir(proc):
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            if os.stat("%s/%d" % (proc, pid)).st_uid != os.geteuid():
                continue
            if not os.path.basename(os.readlink("%s/%d/exe" % (proc, pid))).startswith("qemu-system"):
                continue
            with open("%s/%d/cmdline" % (proc, pid), "rb") as stream:
                command = stream.read().replace(b"\0", b" ").decode(errors="replace")
            actors[pid] = (birth(pid, proc), command)
        except (OSError, IndexError, ValueError):
            continue
    return actors


def _claimed(state):
    claimed = set()
    for plan in state["plans"].values():
        if plan["state"] == "retired":
            continue
        for disk in plan["disks"]:
            try:
                info = os.stat(disk["path"], follow_symlinks=False)
            except FileNotFoundError:
                continue
            claimed.add((info.st_dev, info.st_ino))
    return claimed


def coverage(storage, ledger, actors, proc="/proc"):
    """Read-only: running actor disks that no unretired claim covers."""
    ledger = os.path.abspath(os.path.expanduser(ledger))
    _need(os.path.isdir(ledger) and not os.path.islink(ledger), "fixture_storage_host_unenrolled")
    claimed = _claimed(storage.StoragePlans(ledger)._read())
    uncovered = []
    for pid, (start, command) in sorted(actors.items()):
        for path in writable_disks(pid, proc):
            info = os.stat(path)
            if (info.st_dev, info.st_ino) not in claimed:
                uncovered.append({"pid": pid, "startTicks": start, "path": path})
    return {"state": "covered" if not uncovered else "uncovered", "uncovered": uncovered}


def _capacity(path, virtual_size):
    if path.endswith(".qcow2"):
        return virtual_size(path)
    return max(os.stat(path).st_size, FIRMWARE_VARS_BYTES if path.endswith(".fd") else 1)


def qcow2_virtual_size(path):
    raw = subprocess.run(["qemu-img", "info", "-U", "--output=json", path], capture_output=True, check=True).stdout
    value = json.loads(raw)["virtual-size"]
    _need(type(value) is int and value > 0, "fixture_storage_host_capacity_unknown")
    return value


def register(storage, ledger, fixtures, actors, proc="/proc", virtual_size=qcow2_virtual_size):
    """Claim each named running fixture: {fixtureId: {platform, pid, startTicks}}.

    One directory per fixture, every disk at full capacity, writer = the actor.
    An actor that changed identity refuses before and after the claim.
    """
    ledger = os.path.abspath(os.path.expanduser(ledger))
    _need(os.path.isdir(ledger) and not os.path.islink(ledger), "fixture_storage_host_unenrolled")
    result = {}
    for fixture_id, row in sorted(fixtures.items()):
        pid, start = row["pid"], row["startTicks"]
        _need(actors.get(pid, (None,))[0] == start and birth(pid, proc) == start, "fixture_storage_host_actor_changed")
        paths = writable_disks(pid, proc)
        directories = {os.path.dirname(path) for path in paths}
        _need(paths and len(directories) == 1, "fixture_storage_host_disks_unresolved")
        disks = [{"path": path, "capacityBytes": _capacity(path, virtual_size)} for path in paths]
        check = storage.StoragePlans(ledger).reserve(fixture_id, row["platform"], "start", directories.pop(), disks,
                                                     writer_pid=pid)
        _need(birth(pid, proc) == start, "fixture_storage_host_actor_changed")
        result[fixture_id] = {"pid": pid, "startTicks": start, "disks": disks, "requiredBytes": check["requiredBytes"],
                              "freeBytes": check["freeBytes"]}
    return result


def resolve(actors, deployments):
    """{fixtureId: platform} -> exactly one running actor per deployment id."""
    fixtures = {}
    for fixture_id, platform in deployments.items():
        _need(fixture_id.startswith(platform + "-"), "fixture_storage_host_fixture_invalid")
        deployment = fixture_id[len(platform) + 1:]
        matches = [pid for pid, (_, command) in actors.items() if deployment[:8] in command]
        _need(len(matches) == 1, "fixture_storage_host_actor_unresolved")
        fixtures[fixture_id] = {"platform": platform, "pid": matches[0], "startTicks": actors[matches[0]][0]}
    return fixtures


def host_main(storage, action, deployments):
    """Entry point executed on the VM host."""
    if action == "enroll":
        return enroll(storage, LEDGER)
    actors = qemu_actors()
    if action == "coverage":
        return coverage(storage, LEDGER, actors)
    _need(action == "register", "fixture_storage_host_action_unknown")
    return register(storage, LEDGER, resolve(actors, deployments), actors)


def _program(action, deployments):
    from pathlib import Path
    here = Path(__file__).resolve().parent
    return "\n".join([
        "import json, sys, types",
        "storage = types.ModuleType('native_fixture_storage'); sys.modules[storage.__name__] = storage",
        "exec(compile(%r, 'native_fixture_storage', 'exec'), storage.__dict__)"
        % (here / "native_fixture_storage.py").read_text(),
        "host = types.ModuleType('fixture_storage_host'); sys.modules[host.__name__] = host",
        "exec(compile(%r, 'fixture_storage_host', 'exec'), host.__dict__)" % (here / "fixture_storage_host.py").read_text(),
        "print(json.dumps(host.host_main(storage, %r, %r), sort_keys=True))" % (action, deployments),
    ]) + "\n"


def main(argv=None):
    import argparse
    import base64
    import sys
    import time
    import uuid
    import zlib
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", required=True)
    parser.add_argument("action", choices=("enroll", "coverage", "register"))
    parser.add_argument("--fixture", action="append", default=[], help="platform:deploymentId, for register")
    args = parser.parse_args(argv)
    deployments = {}
    for value in args.fixture:
        platform, _, deployment = value.partition(":")
        _need(platform in {"linux", "windows"} and deployment, "fixture_storage_host_fixture_invalid")
        deployments[platform + "-" + deployment] = platform
    _need((args.action == "register") == bool(deployments), "fixture_storage_host_fixture_invalid")
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    from agent_tools import ssh_transport as transport, windows_vm_deploy as deploy
    encoded = base64.b64encode(zlib.compress(_program(args.action, deployments).encode())).decode()
    command = ("python3", "-I", "-B", "-c", "import base64,zlib;exec(zlib.decompress(base64.b64decode(%r)))" % encoded)
    with transport.admitted_transport(root, args.host, str(uuid.uuid4()), deadline=time.monotonic() + 60):
        with deploy.direct.Guard(root, host=args.host) as authority:
            argv = transport.build_ssh_argv(authority.config, args.host, 30, command=command)
            result = transport.run_ssh(argv, input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, cwd=root)
    sys.stdout.write(result.stdout.decode(errors="replace"))
    sys.stderr.write(result.stderr.decode(errors="replace")[-4000:])
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
