"""Shared validation for task-owned Windows native fixture launchers."""
from pathlib import PureWindowsPath
import re
import uuid

_TASK_NAME = re.compile(
    r"^VpnInstaller(?:Entry|Close|Preflight)32-"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)


def private_task_root(task_name: str, local_app_data: str) -> str:
    """Return the exact private LocalAppData root for an allowed task name."""
    if not isinstance(task_name, str) or not isinstance(local_app_data, str):
        raise ValueError("task name and LocalAppData must be strings")
    match = _TASK_NAME.fullmatch(task_name)
    if match is None:
        raise ValueError("unsupported Windows native fixture task name")
    try:
        uuid.UUID(match.group(1))
    except ValueError as error:
        raise ValueError("invalid Windows native fixture task UUID") from error
    parent = PureWindowsPath(local_app_data)
    if not parent.is_absolute() or parent.name.lower() != "local":
        raise ValueError("LocalAppData must be an absolute Local directory")
    return str(parent / task_name)
