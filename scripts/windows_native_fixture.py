"""Shared validation for task-owned Windows native fixture launchers."""
from pathlib import PureWindowsPath
import re
import uuid

_TASK_NAME = re.compile(
    r"^VpnInstaller(?:Entry|Close|Preflight)32-"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)
_INTERACTIVE_USER_SID = re.compile(
    r"^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$",
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


def _validate_expected_recipient(expected_sid: str, expected_session_id: int) -> None:
    if not isinstance(expected_sid, str) or _INTERACTIVE_USER_SID.fullmatch(expected_sid) is None:
        raise ValueError("expected SID must be a canonical interactive user SID")
    if type(expected_session_id) is not int or expected_session_id <= 0:
        raise ValueError("expected session must be a positive integer")


def original_recipient_actor_classifier(expected_sid: str, expected_session_id: int) -> str:
    """Generate the sole PowerShell classifier used before a per-user install."""
    _validate_expected_recipient(expected_sid, expected_session_id)
    return (
        "function Assert-VpnFixtureOriginalRecipientActor {\n"
        "  param([string]$ActualSid,[object]$ActualSession)\n"
        f"  $expectedSid='{expected_sid}'\n"
        "  if($ActualSid -eq 'S-1-5-18'){throw 'SYSTEM must not install a per-user fixture'}\n"
        "  if($ActualSid -notmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$')"
        "{throw 'service or non-user SID must not install a per-user fixture'}\n"
        "  if($ActualSession -isnot [int] -or $ActualSession -le 0)"
        "{throw 'interactive recipient session must be a positive integer'}\n"
        f"  if($ActualSid -ne $expectedSid -or $ActualSession -ne {expected_session_id})"
        "{throw 'interactive recipient actor did not match'}\n"
        "}\n"
    )


def original_recipient_actor_guard(expected_sid: str, expected_session_id: int) -> str:
    """Generate the pre-msiexec PowerShell guard for an InteractiveToken fixture."""
    return (
        original_recipient_actor_classifier(expected_sid, expected_session_id)
        +
        "$actualSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
        "$actualSession=(Get-Process -Id $PID).SessionId\n"
        "Assert-VpnFixtureOriginalRecipientActor -ActualSid $actualSid -ActualSession $actualSession\n"
    )
