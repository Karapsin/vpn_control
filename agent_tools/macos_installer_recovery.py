"""Read-only diagnostic for a lost macOS installer preauthorization process.

The caller supplies already-redacted product observations.  This module never
contacts a VM, reads credentials, starts an owner, retries an installer, or
turns caller claims into a terminal installation result.
"""

from __future__ import annotations

import re
from typing import Any, Mapping


_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_INPUT_FIELDS = {"jobId", "publicStatus", "protectedReceiptObservation", "bootSessionToken",
                 "currentBootSessionUuid"}
_PUBLIC_FIELDS = {"receiptId", "phase", "code", "final", "installed"}
_TOKEN_FIELDS = {"jobId", "launchBootSessionUuid"}


class MacInstallerRecoveryError(ValueError):
    """The diagnostic evidence envelope is malformed or overbroad."""


def _uuid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _UUID.fullmatch(value):
        raise MacInstallerRecoveryError(f"{label} must be a canonical lowercase UUID")
    return value


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise MacInstallerRecoveryError(f"{label} must contain exactly {', '.join(sorted(fields))}")
    return value


def diagnose(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Classify whether future product maintenance has a boot-session proof.

    Even the strongest result remains diagnostic-only: the product must reopen
    its private token and protected receipt itself before publishing cancellation.
    """
    values = _exact(inputs, _INPUT_FIELDS, "macOS installer recovery input")
    job = _uuid(values["jobId"], "jobId")
    public = _exact(values["publicStatus"], _PUBLIC_FIELDS, "publicStatus")
    if public["receiptId"] != job or public["phase"] != "installing" or \
            public["code"] != "OUTCOME_UNKNOWN" or public["final"] is not False or \
            public["installed"] is not None:
        raise MacInstallerRecoveryError("publicStatus must be the exact nonfinal unknown installing job")
    receipt = values["protectedReceiptObservation"]
    if not isinstance(receipt, str) or receipt not in {"absent", "present", "unknown"}:
        raise MacInstallerRecoveryError("protectedReceiptObservation must be absent, present, or unknown")
    current = _uuid(values["currentBootSessionUuid"], "currentBootSessionUuid")
    token = values["bootSessionToken"]

    reason: str
    eligible = False
    if token is None:
        reason = "launch_boot_session_token_missing"
    else:
        token = _exact(token, _TOKEN_FIELDS, "bootSessionToken")
        if token["jobId"] != job:
            raise MacInstallerRecoveryError("bootSessionToken jobId does not match the unknown job")
        launch = _uuid(token["launchBootSessionUuid"], "launchBootSessionUuid")
        if receipt != "absent":
            reason = "protected_receipt_not_authoritatively_absent"
        elif launch == current:
            reason = "same_boot_process_outcome_unknown"
        else:
            reason = "prior_boot_token_requires_product_revalidation"
            eligible = True

    return {
        "state": "unknown",
        "classification": "macos-preauthorization-process-loss",
        "reason": reason,
        "jobId": job,
        "productReconciliationEligible": eligible,
        "productNextAction": "run-product-owner-maintenance-and-reobserve" if eligible else "preserve-and-observe",
        "evidenceScope": "caller-supplied-diagnostic-only",
        "nativeActionAllowed": False,
        "replayAllowed": False,
        "cancellationAllowed": False,
    }
