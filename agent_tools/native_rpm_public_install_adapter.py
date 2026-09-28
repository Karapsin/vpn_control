"""Fixed admission boundary for the Fedora RPM public-install recovery harness.

The durable batch owns retries.  This adapter owns the narrower boundary between
that batch and the one approved guest harness: no caller can replace its
launcher, source fixture, package, owner, credential handle, or correlation.
The actual SSH transport is injected by MCP wiring so this module stays usable
for deterministic host tests and never opens a VM on import.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import uuid
from typing import Any, Callable, Mapping, Protocol


SCENARIO_ID = "linux-rpm-public-install-recovery"
HARNESS_RELATIVE_PATH = "scripts/test_linux_public_install.py"
PUBLIC_LAUNCHER = "/opt/vpn-control/bin/vpn-control"
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ARTIFACT = re.compile(r"^sha256-[0-9a-f]{64}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_NEVRA = re.compile(r"^vpn-control-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.x86_64$")
INPUT_SCHEMA = "vpn-control.linux-rpm-public-install.input"


class RpmPublicInstallAdapterError(ValueError):
    pass


def parse_scenario_input(raw: bytes, intent: "RpmPublicInstallIntent") -> dict[str, Any]:
    """Admit the canonical immutable RPM fixture contract before guest staging."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 65536:
        raise RpmPublicInstallAdapterError("RPM scenario input is missing or exceeds its bound.")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as error:
        raise RpmPublicInstallAdapterError("RPM scenario input is invalid JSON.") from error
    required = {"schema", "schemaVersion", "scenarioId", "host", "environment", "correlationId",
                "sourceFixtureSha256", "targetPackageSha256", "sourceFingerprint", "expectedBaseNevra",
                "expectedTargetNevra", "expectedDesktopJarSha256", "expectedBaseVersion", "expectedTargetVersion",
                "fixtureHttpsOrigin", "productionTrustChanged", "preservePasswordBaseline"}
    if (not isinstance(value, dict) or set(value) != required or value.get("schema") != INPUT_SCHEMA
            or type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1
            or value.get("scenarioId") != SCENARIO_ID
            or any(value.get(key) != getattr(intent, {"host": "host", "environment": "environment", "correlationId": "correlation_id"}[key])
                   for key in ("host", "environment", "correlationId"))):
        raise RpmPublicInstallAdapterError("RPM scenario input does not bind its immutable request.")
    digests = {"sourceFixtureSha256": "sourceFixture", "targetPackageSha256": "targetPackage"}
    for field, artifact in digests.items():
        if not isinstance(value.get(field), str) or value[field] != intent.artifact_ids[artifact].removeprefix("sha256-"):
            raise RpmPublicInstallAdapterError("RPM scenario input artifact digest differs from its registered bytes.")
    if (not all(isinstance(value.get(key), str) and _HEX.fullmatch(value[key]) for key in
                ("sourceFingerprint", "expectedDesktopJarSha256"))
            or not all(isinstance(value.get(key), str) and _NEVRA.fullmatch(value[key]) for key in
                       ("expectedBaseNevra", "expectedTargetNevra"))
            or value["expectedBaseNevra"] == value["expectedTargetNevra"]
            or value.get("expectedBaseVersion") != value["expectedBaseNevra"].removeprefix("vpn-control-").split("-")[0]
            or value.get("expectedTargetVersion") != value["expectedTargetNevra"].removeprefix("vpn-control-").split("-")[0]
            or tuple(map(int, value["expectedTargetVersion"].split('.'))) <= tuple(map(int, value["expectedBaseVersion"].split('.')))
            or not isinstance(value.get("fixtureHttpsOrigin"), str)
            or not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?", value["fixtureHttpsOrigin"])
            or value.get("productionTrustChanged") is not False
            or value.get("preservePasswordBaseline") is not True):
        raise RpmPublicInstallAdapterError("RPM scenario input source, package, owner, or credential preservation is invalid.")
    canonical = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    if raw != canonical:
        raise RpmPublicInstallAdapterError("RPM scenario input must use canonical JSON bytes.")
    return value


@dataclass(frozen=True)
class RpmPublicInstallIntent:
    host: str
    environment: str
    bundle_hash: str
    artifact_ids: Mapping[str, str]
    credential_handle: str
    correlation_id: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RpmPublicInstallIntent":
        required = {"scenarioId", "host", "environment", "bundleHash", "artifactIds", "credentialHandle", "correlationId"}
        if not isinstance(value, Mapping) or set(value) != required or value.get("scenarioId") != SCENARIO_ID:
            raise RpmPublicInstallAdapterError("RPM public install requires its exact fixed request fields.")
        strings = ("host", "environment", "bundleHash", "credentialHandle", "correlationId")
        if any(not isinstance(value[key], str) or not _TOKEN.fullmatch(value[key]) for key in strings):
            raise RpmPublicInstallAdapterError("RPM public install identity is invalid.")
        try:
            if str(uuid.UUID(value["correlationId"])) != value["correlationId"]:
                raise ValueError()
        except ValueError as error:
            raise RpmPublicInstallAdapterError("RPM public install correlationId must be a canonical UUID.") from error
        artifacts = value["artifactIds"]
        expected = {"bundleManifest", "scenarioInput", "sourceFixture", "targetPackage"}
        if not isinstance(artifacts, Mapping) or set(artifacts) != expected or any(
                not isinstance(item, str) or not _ARTIFACT.fullmatch(item) for item in artifacts.values()):
            raise RpmPublicInstallAdapterError("RPM public install requires exactly its frozen source/package artifacts.")
        if value["bundleHash"] != artifacts["bundleManifest"].removeprefix("sha256-"):
            raise RpmPublicInstallAdapterError("RPM public install bundle hash differs from its frozen manifest artifact.")
        return cls(value["host"], value["environment"], value["bundleHash"], dict(sorted(artifacts.items())),
                   value["credentialHandle"], value["correlationId"])

    def public_mapping(self) -> dict[str, Any]:
        return {"scenarioId": SCENARIO_ID, "host": self.host, "environment": self.environment,
                "bundleHash": self.bundle_hash, "artifactIds": dict(self.artifact_ids),
                "correlationId": self.correlation_id}


class RpmPublicInstallDriver(Protocol):
    def submit(self, intent: RpmPublicInstallIntent) -> Mapping[str, Any]: ...
    def status(self, correlation_id: str) -> Mapping[str, Any]: ...
    def collect(self, correlation_id: str) -> Mapping[str, Any]: ...


def _correlated(value: Mapping[str, Any], correlation: str, *, collecting: bool = False) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("correlationId") != correlation:
        raise RpmPublicInstallAdapterError("RPM public install observation is not correlated to its immutable request.")
    state = value.get("state")
    if state not in {"submitted", "running", "terminal", "unknown"}:
        raise RpmPublicInstallAdapterError("RPM public install observation state is invalid.")
    result: dict[str, Any] = {"state": state, "correlationId": correlation}
    if type(value.get("exitCode")) is int:
        result["exitCode"] = value["exitCode"]
    if collecting:
        summary = value.get("scenarioEvidence")
        cleanup = summary.get("cleanup") if isinstance(summary, Mapping) else None
        if state == "terminal" and type(value.get("exitCode")) is int and value["exitCode"] != 0 and summary is None:
            phase = value.get("failurePhase")
            result["scenarioEvidence"] = {"correlationId": correlation, "result": "failed",
                "failurePhase": phase if isinstance(phase, str) and phase in {"harness-unverified", "guest-admission"} else "harness-unverified",
                "reason": "no_typed_recovery_receipt"}
            return result
        if (state != "terminal" or not isinstance(summary, Mapping) or summary.get("correlationId") != correlation
                or summary.get("result") not in {"passed", "failed"} or not isinstance(cleanup, Mapping)
                or not isinstance(summary.get("operationId"), str) or not _TOKEN.fullmatch(summary["operationId"])
                or not isinstance(summary.get("protectedJobId"), str) or not _TOKEN.fullmatch(summary["protectedJobId"])):
            raise RpmPublicInstallAdapterError("RPM public install collector has no exact terminal recovery receipt.")
        if summary["result"] == "passed" and (type(value.get("exitCode")) is not int or value["exitCode"] != 0
                or summary.get("rpmVerifyClean") is not True
                or summary.get("credentialRestored") is not True or cleanup.get("state") != "complete"
                or any(cleanup.get(key) is not True for key in ("ownerStopped", "protectedPreserved", "workspaceRemoved"))):
            raise RpmPublicInstallAdapterError("RPM public install passed without verified cleanup and credential restoration.")
        result["scenarioEvidence"] = {"correlationId": correlation, "result": summary["result"],
            "operationId": summary["operationId"], "protectedJobId": summary["protectedJobId"],
            "rpmVerifyClean": summary.get("rpmVerifyClean") if type(summary.get("rpmVerifyClean")) is bool else None,
            "credentialRestored": summary.get("credentialRestored") if type(summary.get("credentialRestored")) is bool else None,
            "cleanup": {"state": cleanup.get("state") if cleanup.get("state") in
                        ("complete", "incomplete", "preserved-for-recovery", "not-started") else "unknown",
                        **{key: cleanup.get(key) if type(cleanup.get(key)) is bool else None
                           for key in ("ownerStopped", "protectedPreserved", "workspaceRemoved")}}}
    return result


class RpmPublicInstallAdapter:
    """Expose only start/status/collect; secret material never crosses this API."""
    def __init__(self, driver: RpmPublicInstallDriver):
        self.driver = driver

    def start(self, request: Mapping[str, Any]) -> dict[str, Any]:
        intent = RpmPublicInstallIntent.from_mapping(request)
        return _correlated(self.driver.submit(intent), intent.correlation_id)

    def status(self, correlation_id: str) -> dict[str, Any]:
        self._correlation(correlation_id)
        return _correlated(self.driver.status(correlation_id), correlation_id)

    def collect(self, correlation_id: str) -> dict[str, Any]:
        self._correlation(correlation_id)
        return _correlated(self.driver.collect(correlation_id), correlation_id, collecting=True)

    @staticmethod
    def _correlation(value: object) -> None:
        try:
            if not isinstance(value, str) or str(uuid.UUID(value)) != value:
                raise ValueError()
        except ValueError as error:
            raise RpmPublicInstallAdapterError("RPM public install correlationId must be a canonical UUID.") from error
