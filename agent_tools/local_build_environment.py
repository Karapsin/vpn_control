"""Apply checkout-local toolchain paths to managed child commands.

Absolute machine paths belong in ignored .codex/build-env.local.json, never in
the tracked MCP configuration. The file is data, not shell code.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path


class LocalBuildEnvironmentError(ValueError):
    pass


def apply(root: Path, environment: dict[str, str]) -> dict[str, str]:
    config = root / ".codex" / "build-env.local.json"
    try:
        config.lstat()
    except FileNotFoundError:
        return environment
    except OSError as exc:
        raise LocalBuildEnvironmentError("Local build environment cannot be inspected.") from exc
    # POSIX ownership and mode are required; Windows needs an ACL-aware reader.
    if not hasattr(os, "getuid"):
        raise LocalBuildEnvironmentError("Local build environment requires POSIX ownership checks.")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(config, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise LocalBuildEnvironmentError("Local build environment must be an owner-only regular file.")
            values = json.load(handle)
    except LocalBuildEnvironmentError:
        raise
    except (OSError, ValueError) as exc:
        raise LocalBuildEnvironmentError("Local build environment JSON is invalid.") from exc
    if not isinstance(values, dict) or set(values) - {"JAVA_HOME", "ANDROID_HOME"}:
        raise LocalBuildEnvironmentError("Local build environment contains unsupported keys.")
    updated = dict(environment)
    for key, value in values.items():
        if not isinstance(value, str) or not value or "\x00" in value:
            raise LocalBuildEnvironmentError(f"{key} must be an absolute directory path.")
        path = Path(value)
        if not path.is_absolute() or not path.is_dir():
            raise LocalBuildEnvironmentError(f"{key} must be an absolute existing directory.")
        if key == "JAVA_HOME" and not os.access(path / "bin" / "java", os.X_OK):
            raise LocalBuildEnvironmentError("JAVA_HOME must contain an executable bin/java.")
        updated[key] = value
    return updated
