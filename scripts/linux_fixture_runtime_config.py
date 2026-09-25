"""Read-only selection of a fixture owner's live sing-box config and user port.

The Linux desktop creates runtime/candidate-*/config.json and may expose a
second mixed inbound for management. Fixture traffic must follow the live
child's -c argument and the user-facing mixed-in tag.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class RuntimeConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeProcess:
    pid: int
    ppid: int
    argv: tuple[str, ...]


def resolve_owned_runtime_config(state_dir: Path, owner_pid: int,
                                 processes: Sequence[RuntimeProcess]) -> Path:
    """Return the sole live, state-contained config named by an owned runtime."""
    state = Path(state_dir).resolve(strict=True)
    runtime_dir = state / "runtime"
    by_pid = {process.pid: process for process in processes}
    if owner_pid not in by_pid or len(by_pid) != len(processes):
        raise RuntimeConfigError("fixture owner or unique process identities missing")

    matches = []
    for process in processes:
        argv = process.argv
        if (len(argv) < 4 or Path(argv[0]).name != "sing-box" or
                argv[1:3] != ("run", "-c")):
            continue
        parent = process.ppid
        seen = {process.pid}
        while parent != owner_pid and parent in by_pid and parent not in seen:
            seen.add(parent)
            parent = by_pid[parent].ppid
        if parent != owner_pid or parent in seen:
            continue
        candidate = Path(argv[3])
        if (not candidate.is_absolute() or candidate.name != "config.json" or
                not candidate.parent.name.startswith("candidate-") or
                candidate.is_symlink() or not candidate.is_file()):
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.parent.parent == runtime_dir and not resolved.is_symlink():
            matches.append(resolved)
    if len(matches) != 1:
        raise RuntimeConfigError("expected exactly one live owned sing-box config")
    return matches[0]


def select_user_proxy_port(config: dict) -> int:
    """Choose the loopback user proxy, excluding the management mixed inbound."""
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list):
        raise RuntimeConfigError("runtime inbounds missing")
    ports = [item.get("listen_port") for item in inbounds if isinstance(item, dict)
             and item.get("type") == "mixed" and item.get("tag") == "mixed-in"
             and item.get("listen") == "127.0.0.1"]
    if len(ports) != 1 or type(ports[0]) is not int or not 1 <= ports[0] <= 65535:
        raise RuntimeConfigError("expected exactly one valid loopback user proxy port")
    return ports[0]
