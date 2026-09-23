#!/usr/bin/env python3
"""Read-only admission guard for Linux VPN fixture runtime binaries.

A file capability reported by getcap is ineffective when its filesystem is
mounted nosuid. This guard records the actual binary's mount and capabilities
before a disposable native VPN fixture asks the runtime to create a TUN device.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

REQUIRED_CAPABILITIES = ("cap_net_admin", "cap_net_raw")
BLOCKED_MOUNT_OPTIONS = frozenset(("nosuid", "noexec"))


class FixtureGuardError(RuntimeError):
    """The fixture runtime cannot safely be admitted for a VPN attempt."""

    def __init__(self, message, evidence=None):
        super().__init__(message)
        self.evidence = evidence


def parse_findmnt_json(text):
    """Return the one complete findmnt JSON record or reject untrustworthy data."""
    try:
        payload = json.loads(text)
    except (TypeError, json.JSONDecodeError) as error:
        raise FixtureGuardError("findmnt did not return valid JSON mount evidence") from error
    filesystems = payload.get("filesystems") if isinstance(payload, dict) else None
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise FixtureGuardError("findmnt mount evidence must contain exactly one filesystem")
    filesystem = filesystems[0]
    if not isinstance(filesystem, dict):
        raise FixtureGuardError("findmnt filesystem evidence is malformed")
    required = ("target", "source", "fstype", "options")
    if any(not isinstance(filesystem.get(key), str) or not filesystem[key].strip() for key in required):
        raise FixtureGuardError("findmnt mount evidence is missing target, source, fstype, or options")
    options = {option.strip() for option in filesystem["options"].split(",") if option.strip()}
    if not options:
        raise FixtureGuardError("findmnt mount evidence has no options")
    blocked = sorted(BLOCKED_MOUNT_OPTIONS.intersection(options))
    if blocked:
        raise FixtureGuardError(
            "runtime binary is on a mount with " + ", ".join(blocked) +
            "; file capabilities cannot safely admit this VPN fixture"
        )
    return {key: filesystem[key] for key in required} | {"optionSet": sorted(options)}


def require_runtime_capabilities(getcap_output, binary):
    """Require both effective, permitted capabilities for this exact binary."""
    lines = [line.strip() for line in getcap_output.splitlines() if line.strip()]
    if len(lines) != 1 or "=" not in lines[0] or not any(character.isspace() for character in lines[0]):
        raise FixtureGuardError(f"getcap returned malformed capability evidence for {binary}")
    observed_path, capability_spec = lines[0].rsplit(None, 1)
    if observed_path != str(binary):
        raise FixtureGuardError(f"getcap evidence names a different binary: {observed_path}")
    if capability_spec.count("=") != 1:
        raise FixtureGuardError(f"getcap returned malformed capability flags for {binary}")
    capabilities, flags = capability_spec.split("=", 1)
    if not capabilities or not flags or any(flag not in "eip" for flag in flags):
        raise FixtureGuardError(f"getcap returned malformed capability flags for {binary}")
    capability_set = set(capabilities.split(","))
    missing = [capability for capability in REQUIRED_CAPABILITIES if capability not in capability_set]
    if missing:
        raise FixtureGuardError(
            f"runtime binary is missing required capability {'/'.join(missing)}: {binary}"
        )
    if "e" not in flags or "p" not in flags:
        raise FixtureGuardError(
            f"runtime binary capabilities must be effective and permitted for {binary}"
        )
    return list(REQUIRED_CAPABILITIES)


def _capture(command, *, run):
    try:
        result = run(command, text=True, capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"args": command, "exception": repr(error)}
    return {
        "args": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _require_success(record, command_name):
    if "exception" in record:
        raise FixtureGuardError(f"cannot execute {command_name} for fixture admission")
    if record["returncode"] != 0:
        stderr = (record["stderr"] or "").strip()
        raise FixtureGuardError(
            f"{command_name} could not inspect the runtime binary" + (f": {stderr}" if stderr else "")
        )


def evaluate_runtime_binary(binary, *, run=subprocess.run):
    """Collect and validate the actual runtime binary's mount and capabilities."""
    binary = Path(binary)
    mount_record = _capture(
        ["findmnt", "--json", "--target", str(binary), "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"], run=run,
    )
    getcap_record = _capture(["getcap", "-n", "--", str(binary)], run=run)
    evidence = {"findmnt": mount_record, "getcap": getcap_record}
    try:
        _require_success(mount_record, "findmnt")
        _require_success(getcap_record, "getcap")
        mount = parse_findmnt_json(mount_record["stdout"])
        capabilities = require_runtime_capabilities(getcap_record["stdout"], binary)
    except FixtureGuardError as error:
        error.evidence = evidence
        raise
    return {"binary": str(binary), "mount": mount, "capabilities": capabilities, "evidence": evidence}


def fixture_http_probe_arguments(*, port, resolved_address, interface=None, host="fixture.invalid"):
    """Build a DNS-free synthetic HTTP probe for a TEST-NET or loopback target."""
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("fixture port must be in 1..65535")
    if not host or any(character.isspace() for character in host):
        raise ValueError("fixture host must be a non-empty hostname")
    if not resolved_address:
        raise ValueError("fixture resolved address is required")
    arguments = ["curl", "--noproxy", "*", "--connect-timeout", "5", "--max-time", "8"]
    if interface:
        arguments.extend(("--interface", interface))
    arguments.extend(("--resolve", f"{host}:{port}:{resolved_address}", f"http://{host}:{port}/"))
    return arguments


def _write_receipt(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")


def main(argv=None, *, run=subprocess.run, resolve=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="exact resolved sing-box binary")
    parser.add_argument("--receipt", type=Path, required=True, help="JSON result path")
    args = parser.parse_args(argv)
    resolver = resolve or (lambda path: path.resolve(strict=True))
    try:
        binary = resolver(args.binary)
        if not binary.is_file():
            raise FixtureGuardError(f"runtime binary is not a regular file: {binary}")
        result = evaluate_runtime_binary(binary, run=run)
    except (FixtureGuardError, OSError, ValueError) as error:
        _write_receipt(args.receipt, {
            "ok": False, "binary": str(args.binary), "error": str(error),
            "evidence": getattr(error, "evidence", None),
        })
        print(error, file=sys.stderr)
        return 1
    _write_receipt(args.receipt, {"ok": True, **result})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
