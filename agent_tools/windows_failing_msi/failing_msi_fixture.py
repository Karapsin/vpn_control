"""PRIVATE finite derivation; no action on import, no installation API exposed.

Run derive(owner, request) only inside the qualified ordinary Owner. All source,
snapshot, plan, receipt and MSI inputs must already be held Owner pins. The host
coordinator must have admitted their actual registered artifacts. This module
does not replace that upstream authority, run an installer, sign a package,
dispatch a task or authorize product acceptance. Native qualification is pending.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import ctypes
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import re
import uuid


KIND = "windows-native-install-failed-msi"
CONDITION = ["0", "VPN_CONTROL_NATIVE_ACCEPTANCE_DELIBERATE_FAILURE"]
UPGRADE = "{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}"
NAMESPACE = uuid.UUID("d5d591da-1558-4a24-8586-e516fa7af817")
MAX_PACKAGE = 1024 ** 3
MAX_SNAPSHOT = 16 * 1024 ** 2
MAX_RECEIPT = 64 * 1024
HASH = re.compile(r"[0-9a-f]{64}\Z")
SOURCE = re.compile(r"[0-9a-f]{40}\Z")
ARTIFACT = re.compile(r"sha256-[0-9a-f]{64}\Z")
GUID = re.compile(r"\{[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\}\Z")
VERSION = re.compile(r"(?:[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\.(?:0|[1-9]|1[0-9])\Z")
# Every modifying standard action that this finite recipe recognizes must follow
# LaunchConditions. Unknown/custom actions count as potentially modifying and
# must also follow it. Unordered negative sequence actions refuse.
READ_ONLY_ACTIONS = frozenset(("FindRelatedProducts", "AppSearch", "LaunchConditions",
    "ValidateProductID", "CostInitialize", "FileCost", "CostFinalize", "MigrateFeatureStates",
    "InstallValidate", "ResolveSource"))
MODIFYING_ACTIONS = frozenset(("InstallInitialize", "RemoveExistingProducts", "ProcessComponents",
    "UnpublishFeatures", "RemoveShortcuts", "RemoveFiles", "RemoveFolders", "CreateFolders",
    "MoveFiles", "InstallFiles", "PatchFiles", "DuplicateFiles", "CreateShortcuts",
    "WriteRegistryValues", "WriteIniValues", "WriteEnvironmentStrings", "RegisterClassInfo",
    "RegisterExtensionInfo", "RegisterProgIdInfo", "RegisterMIMEInfo", "RegisterTypeLibraries",
    "RegisterFonts", "InstallODBC", "InstallServices", "StartServices", "StopServices",
    "DeleteServices", "RemoveRegistryValues", "RemoveIniValues", "RemoveEnvironmentStrings",
    "UnregisterClassInfo", "UnregisterExtensionInfo", "UnregisterProgIdInfo", "UnregisterMIMEInfo",
    "UnregisterTypeLibraries", "UnregisterFonts", "RemoveODBC", "RegisterUser", "RegisterProduct",
    "PublishComponents", "PublishFeatures", "PublishProduct", "InstallExecute", "InstallExecuteAgain",
    "InstallFinalize", "SelfRegModules", "SelfUnregModules", "BindImage", "IsolateComponents"))
REQUEST_FIELDS = {"sourceSha", "sourceFingerprint", "fixtureReceiptArtifactId", "baseMsiArtifactId",
    "targetMsiArtifactId", "fixtureReceiptPath", "sourceSnapshotPath", "buildPlanPath",
    "targetMsiPath", "expectedParentSignatureStatus"}


class Refused(ValueError):
    pass


def require(value, code):
    if not value:
        raise Refused(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def _exact(value, keys, code):
    require(type(value) is dict and set(value) == set(keys), code)


def validate_request(value):
    _exact(value, REQUEST_FIELDS, "derivation-request-schema")
    require(type(value["sourceSha"]) is str and SOURCE.fullmatch(value["sourceSha"])
            and type(value["sourceFingerprint"]) is str and HASH.fullmatch(value["sourceFingerprint"]),
            "exact-source-context")
    for key in ("fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"):
        require(type(value[key]) is str and ARTIFACT.fullmatch(value[key]), "exact-artifact-id")
    require(value["expectedParentSignatureStatus"] == "NotSigned", "signed-parent-not-supported")
    for key in ("fixtureReceiptPath", "sourceSnapshotPath", "buildPlanPath", "targetMsiPath"):
        require(type(value[key]) is str and "\0" not in value[key], "held-input-path")
    return value


def _pin(owner, path):
    require(type(path) is str and path.casefold() in owner.by_path, "actual-held-input-pin")
    pin = owner.by_path[path.casefold()]
    pin.current()
    return pin


def _json_pin(owner, path, maximum):
    raw = _pin(owner, path).digest(return_bytes=True, maximum=maximum)
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate-json-field")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def admitted_inputs(owner, request):
    """Revalidate the transferred, upstream-admitted actual pair under held pins."""
    validate_request(request)
    owner.guard()
    recipe = _pin(owner, str(Path(__file__)))
    recipe_sha = recipe.digest()
    receipt_pin = _pin(owner, request["fixtureReceiptPath"])
    target_pin = _pin(owner, request["targetMsiPath"])
    require(receipt_pin.record["sha256"] == request["fixtureReceiptArtifactId"][7:]
            and target_pin.record["sha256"] == request["targetMsiArtifactId"][7:], "artifact-pin-join")
    receipt = _json_pin(owner, request["fixtureReceiptPath"], 1024 * 1024)
    snapshot = _json_pin(owner, request["sourceSnapshotPath"], 32 * 1024 * 1024)
    plan = _json_pin(owner, request["buildPlanPath"], 1024 * 1024)
    require(receipt.get("schemaVersion") == 1 and receipt.get("testOnly") is True
            and receipt.get("productionTrustChanged") is False and receipt.get("architecture") == "x86_64"
            and type(receipt.get("nativeOs")) is str and receipt["nativeOs"].startswith("Windows-")
            and type(receipt.get("builds")) is list and len(receipt["builds"]) == 2,
            "actual-normal-pair-receipt")
    require(snapshot.get("schemaVersion") == 1 and snapshot.get("sourceHead") == request["sourceSha"]
            and type(snapshot.get("files")) is list, "actual-source-snapshot")
    # Match the existing producer's no-newline fingerprint encoding.
    fingerprint = hashlib.sha256(json.dumps(snapshot["files"], sort_keys=True,
        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    require(fingerprint == snapshot.get("sourceFingerprint") == receipt.get("sourceFingerprint")
            == plan.get("sourceFingerprint") == request["sourceFingerprint"], "same-source-fingerprint")
    base, target = receipt["builds"]
    require(base.get("label") == "base" and target.get("label") == "target"
            and base.get("sourceFingerprint") == target.get("sourceFingerprint") == fingerprint
            and type(base.get("codeFingerprint")) is str and HASH.fullmatch(base["codeFingerprint"])
            and base["codeFingerprint"] == target.get("codeFingerprint"), "normal-pair-code-identity")
    require(all(type(x.get("version")) is str and VERSION.fullmatch(x["version"]) for x in (base, target))
            and tuple(map(int, base["version"].split("."))) < tuple(map(int, target["version"].split(".")))
            and snapshot.get("canonicalVersion") == target["version"], "normal-pair-versions")
    require(plan.get("schemaVersion") == 1 and plan.get("testOnly") is True
            and plan.get("productionTrustChanged") is False and plan.get("platform") == "windows"
            and plan.get("architecture") == "x86_64" and plan.get("packageFamily") == "default"
            and [(x.get("label"), x.get("version")) for x in plan.get("stages", [])]
                == [("base", base["version"]), ("target", target["version"])], "normal-pair-build-plan")
    assets = []
    for build, artifact in ((base, request["baseMsiArtifactId"]), (target, request["targetMsiArtifactId"])):
        require(type(build.get("assets")) is list and len(build["assets"]) == 1, "one-msi-per-build")
        asset = build["assets"][0]
        require(asset.get("packageType") == "msi" and asset.get("platform") == "windows"
                and asset.get("architecture") == "x86_64" and asset.get("displayVersion") == build["version"]
                and asset.get("sha256") == artifact[7:] and type(asset.get("sizeBytes")) is int
                and 0 < asset["sizeBytes"] <= MAX_PACKAGE, "normal-pair-msi-asset")
        assets.append(asset)
    require(target_pin.record["nativeIdentity"]["sizeBytes"] == assets[1]["sizeBytes"]
            and Path(request["targetMsiPath"]).name == assets[1]["fileName"]
            and receipt.get("manifest", {}).get("assets") == target["assets"], "target-msi-manifest-pin")
    target_pin.digest()
    owner.guard()
    return {"recipeSha256": recipe_sha, "pair": receipt, "parentPin": target_pin, "asset": assets[1]}


def product(snapshot):
    _exact(snapshot, {"schemaVersion", "tables", "summary"}, "msi-snapshot-schema")
    require(snapshot["schemaVersion"] == 1 and type(snapshot["tables"]) is dict
            and type(snapshot["summary"]) is dict and len(encoded(snapshot)) <= MAX_SNAPSHOT,
            "bounded-msi-snapshot")
    table = snapshot["tables"].get("Property")
    require(type(table) is dict and _string_columns(table.get("columns"), ["Property", "Value"]),
            "fixed-property-table-schema")
    rows = table.get("rows")
    require(type(rows) is list and all(type(x) is list and len(x) == 2 and type(x[0]) is str for x in rows)
            and len({x[0] for x in rows}) == len(rows), "property-table-rows")
    props = dict(rows)
    values = {"productName": props.get("ProductName"), "productCode": props.get("ProductCode"),
              "upgradeCode": props.get("UpgradeCode"), "version": props.get("ProductVersion"),
              "packageCode": snapshot["summary"].get("9", {}).get("value")}
    require(values["productName"] == "vpn-control" and type(values["version"]) is str
            and VERSION.fullmatch(values["version"]), "real-product-version")
    for key in ("productCode", "upgradeCode", "packageCode"):
        require(type(values[key]) is str and GUID.fullmatch(values[key].upper()), "real-msi-guid")
        values[key] = values[key].upper()
    require(values["upgradeCode"] == UPGRADE, "product-upgrade-identity")
    template = snapshot["summary"].get("7", {}).get("value")
    require(type(template) is str and template.split(";", 1)[0] == "x64", "actual-x64-package-template")
    return values


def _string_columns(columns, names):
    return type(columns) is list and len(columns) == len(names) and all(type(x) is list
        and len(x) == 2 and x[0] == name and type(x[1]) is str and re.fullmatch(r"[sSlL][0-9]{1,5}", x[1])
        for x, name in zip(columns, names))


def validate_schedule(snapshot):
    product(snapshot)
    tables = snapshot["tables"]
    condition = tables.get("LaunchCondition")
    require(type(condition) is dict and _string_columns(condition.get("columns"), ["Condition", "Description"])
            and type(condition.get("rows")) is list and all(type(x) is list and len(x) == 2 for x in condition["rows"])
            and all(x[0] != "0" for x in condition["rows"]), "existing-unfaulted-launchcondition-table")
    sequence = tables.get("InstallExecuteSequence")
    require(type(sequence) is dict and type(sequence.get("columns")) is list and len(sequence["columns"]) == 3
            and _string_columns(sequence["columns"][:2], ["Action", "Condition"])
            and sequence["columns"][2] in [["Sequence", "I2"], ["Sequence", "i2"]]
            and type(sequence.get("rows")) is list, "existing-execute-sequence-schema")
    rows = sequence["rows"]
    require(all(type(x) is list and len(x) == 3 and type(x[0]) is str
                and (x[1] is None or type(x[1]) is str) and type(x[2]) is str
                and re.fullmatch(r"[0-9]{1,5}", x[2]) for x in rows)
            and len({x[0] for x in rows}) == len(rows), "finite-sequence-rows")
    launch = [x for x in rows if x[0] == "LaunchConditions"]
    require(len(launch) == 1 and launch[0][1] in {None, "1"} and 0 < int(launch[0][2]) <= 32767,
            "unconditional-positive-launchconditions")
    actions = {x[0] for x in rows}
    require({"InstallInitialize", "InstallFiles", "InstallFinalize"} <= actions, "real-install-sequence-required")
    require(all(int(x[2]) > int(launch[0][2]) for x in rows if x[0] not in READ_ONLY_ACTIONS),
            "launchconditions-before-every-modifying-action")


def expected_package_code(source_sha, parent_sha, recipe_sha):
    return "{" + str(uuid.uuid5(NAMESPACE, source_sha + ":" + parent_sha + ":" + recipe_sha)).upper() + "}"


def expected_after(before, package_code):
    validate_schedule(before)
    require(GUID.fullmatch(package_code) and package_code != product(before)["packageCode"],
            "distinct-derived-package-code")
    after = copy.deepcopy(before)
    after["tables"]["LaunchCondition"]["rows"].append(list(CONDITION))
    after["tables"]["LaunchCondition"]["rows"].sort(key=encoded)
    require(after["summary"]["9"].get("type") == 30, "package-code-summary-type")
    after["summary"]["9"]["value"] = package_code
    return after


def validate_derivation(receipt, before, after, expected, asset):
    """Pure strict validator. Native callers must ALSO reread actual MSI snapshots."""
    _exact(receipt, {"schemaVersion", "kind", "testOnly", "productionTrustChanged", "sourceSha",
        "sourceFingerprint", "derivationSourceSha256", "operationId", "parent", "output",
        "beforeSnapshotSha256", "afterSnapshotSha256", "signatures", "semanticDelta",
        "nativeInstallationExecuted", "nativeAcceptance"}, "derivation-receipt-schema")
    _exact(expected, {"sourceSha", "sourceFingerprint", "recipeSha256", "fixtureReceiptArtifactId",
        "baseMsiArtifactId", "targetMsiArtifactId", "parentSizeBytes", "targetVersion"}, "expected-derivation-schema")
    require(all(type(expected[k]) is str and ARTIFACT.fullmatch(expected[k])
                for k in ("fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"))
            and type(expected["parentSizeBytes"]) is int and 0 < expected["parentSizeBytes"] <= MAX_PACKAGE
            and type(expected["targetVersion"]) is str and VERSION.fullmatch(expected["targetVersion"]),
            "typed-expected-artifact-identities")
    require(receipt["schemaVersion"] == 1 and receipt["kind"] == KIND and receipt["testOnly"] is True
            and receipt["productionTrustChanged"] is False and receipt["nativeInstallationExecuted"] is False
            and receipt["nativeAcceptance"] is None, "derivation-is-not-install-acceptance")
    require(str(uuid.UUID(receipt["operationId"])) == receipt["operationId"], "derivation-operation-id")
    require(receipt["sourceSha"] == expected["sourceSha"] and SOURCE.fullmatch(receipt["sourceSha"])
            and receipt["sourceFingerprint"] == expected["sourceFingerprint"] and HASH.fullmatch(receipt["sourceFingerprint"])
            and receipt["derivationSourceSha256"] == expected["recipeSha256"] and HASH.fullmatch(expected["recipeSha256"]),
            "derivation-exact-source-join")
    code = expected_package_code(expected["sourceSha"], expected["targetMsiArtifactId"][7:], expected["recipeSha256"])
    require(after == expected_after(before, code), "only-declared-msi-semantic-delta")
    require(receipt["beforeSnapshotSha256"] == digest(before) and receipt["afterSnapshotSha256"] == digest(after),
            "complete-snapshot-digest-join")
    parent = {"fixtureReceiptArtifactId": expected["fixtureReceiptArtifactId"],
        "baseMsiArtifactId": expected["baseMsiArtifactId"], "targetMsiArtifactId": expected["targetMsiArtifactId"],
        "sizeBytes": expected["parentSizeBytes"], "product": product(before)}
    require(receipt["parent"] == parent and product(before)["version"] == expected["targetVersion"],
            "normal-parent-product-artifact-join")
    output = receipt["output"]
    _exact(output, {"fileName", "sizeBytes", "sha256", "artifactId", "product"}, "output-artifact-schema")
    require(type(output["sizeBytes"]) is int and 0 < output["sizeBytes"] <= MAX_PACKAGE
            and type(output["sha256"]) is str and HASH.fullmatch(output["sha256"])
            and output["artifactId"] == "sha256-" + output["sha256"]
            and output["fileName"] == "native-failure-" + receipt["operationId"] + ".msi"
            and output["product"] == product(after), "derived-asset-identity")
    signature = {"status": "NotSigned", "winVerifyTrustStatus": 0x800B0100, "cacheOnly": True}
    require(receipt["signatures"] == {"parent": signature, "output": signature, "preservationClaim": False},
            "actual-unsigned-observations-no-signature-preservation")
    require(receipt["semanticDelta"] == {"launchCondition": CONDITION,
        "packageCode": {"before": product(before)["packageCode"], "after": code}}, "finite-semantic-delta")
    require(type(asset) is dict and asset == fault_asset(receipt), "actual-served-downloaded-fault-asset-join")
    require(len(encoded(receipt)) <= MAX_RECEIPT, "derivation-receipt-bound")
    return {"kind": KIND, "sourceSha": receipt["sourceSha"], "sourceFingerprint": receipt["sourceFingerprint"],
        "derivationReceiptSha256": digest(receipt), "faultMsiArtifactId": output["artifactId"],
        "parentMsiArtifactId": expected["targetMsiArtifactId"], "nativeAcceptance": None}


def expected_context(request, admitted):
    return {**{key: request[key] for key in ("sourceSha", "sourceFingerprint", "fixtureReceiptArtifactId",
            "baseMsiArtifactId", "targetMsiArtifactId")}, "recipeSha256": admitted["recipeSha256"],
            "parentSizeBytes": admitted["asset"]["sizeBytes"], "targetVersion": admitted["asset"]["displayVersion"]}


def fault_asset(receipt):
    output = receipt["output"]
    return {"platform": "windows", "architecture": "x86_64", "packageType": "msi",
        "displayVersion": output["product"]["version"], "fileName": output["fileName"],
        "sizeBytes": output["sizeBytes"], "sha256": output["sha256"],
        "downloadUrl": "https://github.com/Karapsin/vpn_control/releases/download/disposable-desktop-fixture/" + output["fileName"]}


def derived_fixture_receipt(original, receipt):
    """A separately named derivative receipt; never overwrites the normal pair."""
    value = copy.deepcopy(original)
    require(type(value.get("builds")) is list and len(value["builds"]) == 2
            and value["builds"][1]["assets"][0]["sha256"] == receipt["parent"]["targetMsiArtifactId"][7:],
            "derived-fixture-original-target-join")
    asset = fault_asset(receipt)
    value["builds"][1]["assets"] = [asset]
    value["manifest"]["assets"] = [asset]
    value["nativeFailureDerivation"] = {"kind": KIND, "derivationReceiptSha256": digest(receipt),
        "originalPairReceiptArtifactId": receipt["parent"]["fixtureReceiptArtifactId"],
        "originalTargetMsiArtifactId": receipt["parent"]["targetMsiArtifactId"],
        "derivedMsiArtifactId": receipt["output"]["artifactId"]}
    return value


def _write_once(path, raw):
    with path.open("xb", buffering=0) as stream:
        offset = 0
        while offset < len(raw):
            count = stream.write(raw[offset:])
            require(type(count) is int and count > 0, "durable-write-progress")
            offset += count
        os.fsync(stream.fileno())


def derive(owner, request):
    require(os.name == "nt", "actual-windows-native-derivation-required")
    native = SystemMsi()
    owner.failing_msi_native = native  # Retain exact handles before the first API.
    return _derive(owner, request, native)


def _derive(owner, request, native):
    admitted = admitted_inputs(owner, request)
    operation = owner.operation
    require(str(uuid.UUID(operation)) == operation, "original-owner-operation")
    root = Path(owner.root)
    parent = Path(request["targetMsiPath"])
    source_pin = admitted["parentPin"]
    signature = native.signature(parent)
    require(signature == {"status": "NotSigned", "winVerifyTrustStatus": 0x800B0100, "cacheOnly": True},
            "actual-parent-signature-policy")
    before = native.inspect(parent)
    validate_schedule(before)
    require(product(before)["version"] == admitted["asset"]["displayVersion"], "native-parent-product-version")
    owner.guard(); source_pin.digest()
    code = expected_package_code(request["sourceSha"], request["targetMsiArtifactId"][7:], admitted["recipeSha256"])
    expected = expected_after(before, code)
    prefix = root / ("native-failure-" + operation)
    output = prefix.with_suffix(".msi")
    intent_path = Path(str(prefix) + ".intent.json")
    _write_once(intent_path, encoded({"kind": KIND, "operationId": operation,
        "request": request, "derivationSourceSha256": admitted["recipeSha256"],
        "outputPath": str(output), "installationAllowed": False, "replayAllowed": False}))
    owner.event("failing-msi-derivation-intent", {"path": str(intent_path), "output": str(output)})
    # Existing held no-write/no-delete source is the copy authority, not a second
    # unqualified named-path read. Failures retain files and never silently retry.
    with output.open("xb", buffering=0) as stream:
        copied = 0
        for block in owner.native.read_blocks(source_pin.handle):
            copied += len(block)
            require(copied <= admitted["asset"]["sizeBytes"], "parent-copy-overflow")
            offset = 0
            while offset < len(block):
                count = stream.write(block[offset:])
                require(type(count) is int and count > 0, "parent-copy-write")
                offset += count
        require(copied == admitted["asset"]["sizeBytes"], "parent-copy-size")
        os.fsync(stream.fileno())
    source_pin.digest(); owner.guard()
    native.add_fixed_condition(output, code)
    # Seal under an actual retained no-write/no-delete Owner pin before inspecting
    # or publishing. The engine's initial editable interval is not called atomic.
    output_pin = native.seal(owner, output, source_pin)
    after = native.inspect(output)
    output_signature = native.signature(output)
    require(after == expected, "unexpected-native-msi-delta")
    out_hash = output_pin.digest()
    receipt = {"schemaVersion": 1, "kind": KIND, "testOnly": True, "productionTrustChanged": False,
        "sourceSha": request["sourceSha"], "sourceFingerprint": request["sourceFingerprint"],
        "derivationSourceSha256": admitted["recipeSha256"], "operationId": operation,
        "parent": {"fixtureReceiptArtifactId": request["fixtureReceiptArtifactId"],
            "baseMsiArtifactId": request["baseMsiArtifactId"], "targetMsiArtifactId": request["targetMsiArtifactId"],
            "sizeBytes": admitted["asset"]["sizeBytes"], "product": product(before)},
        "output": {"fileName": output.name, "sizeBytes": output_pin.record["nativeIdentity"]["sizeBytes"],
            "sha256": out_hash, "artifactId": "sha256-" + out_hash, "product": product(after)},
        "beforeSnapshotSha256": digest(before), "afterSnapshotSha256": digest(after),
        "signatures": {"parent": signature, "output": output_signature, "preservationClaim": False},
        "semanticDelta": {"launchCondition": CONDITION,
            "packageCode": {"before": product(before)["packageCode"], "after": code}},
        "nativeInstallationExecuted": False, "nativeAcceptance": None}
    validated = validate_derivation(receipt, before, after, expected_context(request, admitted), fault_asset(receipt))
    outputs = {"beforeSnapshot": (Path(str(prefix) + ".before.json"), before),
        "afterSnapshot": (Path(str(prefix) + ".after.json"), after),
        "derivationReceipt": (Path(str(prefix) + ".derivation.json"), receipt),
        "derivedFixtureReceipt": (Path(str(prefix) + ".fixture.json"), derived_fixture_receipt(admitted["pair"], receipt))}
    for _, (path, value) in outputs.items():
        _write_once(path, encoded(value))
    owner.guard(); source_pin.digest(); output_pin.digest()
    owner.event("failing-msi-derivation-complete", validated)
    return {**validated, "outputPin": output_pin.record,
        "paths": {key: str(value[0]) for key, value in outputs.items()}, "actualNativeAcceptance": None}


def validate_served_fault(owner, request, binding, manifest_asset):
    """Read-only consumer: reobserve actual source and fault MSI, not a metadata flag.

    The downloaded/captured package must independently match manifest_asset at
    the public updater boundary; this function joins that exact asset to its
    actual held MSI and source-derived recipe before native authorization.
    """
    _exact(binding, {"kind", "derivationReceiptPath", "beforeSnapshotPath", "afterSnapshotPath", "faultMsiPath"},
           "actual-fault-binding-schema")
    require(binding["kind"] == KIND and os.name == "nt", "actual-native-fault-validation-required")
    native = SystemMsi()
    owner.failing_msi_validation_native = native
    return _validate_served_fault(owner, request, binding, manifest_asset, native)


def _validate_served_fault(owner, request, binding, manifest_asset, native):
    admitted = admitted_inputs(owner, request)
    receipt = _json_pin(owner, binding["derivationReceiptPath"], MAX_RECEIPT)
    before = _json_pin(owner, binding["beforeSnapshotPath"], MAX_SNAPSHOT)
    after = _json_pin(owner, binding["afterSnapshotPath"], MAX_SNAPSHOT)
    fault = _pin(owner, binding["faultMsiPath"])
    require(fault.record["sha256"] == receipt["output"]["sha256"]
            and fault.record["nativeIdentity"]["sizeBytes"] == receipt["output"]["sizeBytes"]
            and Path(binding["faultMsiPath"]).name == receipt["output"]["fileName"], "actual-fault-msi-held-pin-join")
    require(native.inspect(Path(request["targetMsiPath"])) == before
            and native.inspect(Path(binding["faultMsiPath"])) == after, "actual-native-msi-snapshot-join")
    require(native.signature(Path(request["targetMsiPath"])) == receipt["signatures"]["parent"]
            and native.signature(Path(binding["faultMsiPath"])) == receipt["signatures"]["output"], "actual-native-msi-signature-join")
    result = validate_derivation(receipt, before, after, expected_context(request, admitted), manifest_asset)
    fault.digest(); admitted["parentPin"].digest(); owner.guard()
    return result


class SystemMsi:
    """Fixed MSI database operations; deliberately no installation entrypoint."""
    def __init__(self):
        require(os.name == "nt" and ctypes.sizeof(ctypes.c_void_p) == 8, "native-windows-amd64")
        self.m = ctypes.WinDLL("msi.dll", use_last_error=True, winmode=0x800)
        self.handles = []
        signatures = {
            "MsiOpenDatabaseW": ([W.LPCWSTR, W.LPCWSTR, ctypes.POINTER(W.UINT)], W.UINT),
            "MsiDatabaseOpenViewW": ([W.UINT, W.LPCWSTR, ctypes.POINTER(W.UINT)], W.UINT),
            "MsiViewExecute": ([W.UINT, W.UINT], W.UINT),
            "MsiViewFetch": ([W.UINT, ctypes.POINTER(W.UINT)], W.UINT),
            "MsiViewGetColumnInfo": ([W.UINT, ctypes.c_int, ctypes.POINTER(W.UINT)], W.UINT),
            "MsiRecordGetFieldCount": ([W.UINT], W.UINT),
            "MsiRecordIsNull": ([W.UINT, W.UINT], W.BOOL),
            "MsiRecordGetStringW": ([W.UINT, W.UINT, W.LPWSTR, ctypes.POINTER(W.DWORD)], W.UINT),
            "MsiRecordReadStream": ([W.UINT, W.UINT, W.LPVOID, ctypes.POINTER(W.DWORD)], W.UINT),
            "MsiGetSummaryInformationW": ([W.UINT, W.LPCWSTR, W.UINT, ctypes.POINTER(W.UINT)], W.UINT),
            "MsiSummaryInfoGetPropertyW": ([W.UINT, W.UINT, ctypes.POINTER(W.UINT), ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(W.FILETIME), W.LPWSTR, ctypes.POINTER(W.DWORD)], W.UINT),
            "MsiSummaryInfoSetPropertyW": ([W.UINT, W.UINT, W.UINT, ctypes.c_int,
                ctypes.POINTER(W.FILETIME), W.LPCWSTR], W.UINT),
            "MsiSummaryInfoPersist": ([W.UINT], W.UINT), "MsiDatabaseCommit": ([W.UINT], W.UINT),
            "MsiCloseHandle": ([W.UINT], W.UINT),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.m, name); fn.argtypes, fn.restype = args, result

    def check(self, code):
        require(code == 0, "native-msi-api-" + str(code))

    @contextmanager
    def handle(self, name, *args):
        handle = W.UINT()
        code = getattr(self.m, name)(*args, ctypes.byref(handle))
        if handle.value:
            self.handles.append(handle.value)
        self.check(code)
        require(handle.value != 0, "native-msi-null-handle")
        try:
            yield handle.value
        finally:
            self.check(self.m.MsiCloseHandle(handle.value))
            self.handles.remove(handle.value)

    def string(self, record, field):
        count = W.DWORD(0)
        code = self.m.MsiRecordGetStringW(record, field, None, ctypes.byref(count))
        require(code in {0, 234} and count.value <= 1024 * 1024, "bounded-msi-string")
        buffer = ctypes.create_unicode_buffer(count.value + 1); capacity = W.DWORD(len(buffer))
        self.check(self.m.MsiRecordGetStringW(record, field, buffer, ctypes.byref(capacity)))
        require(capacity.value < len(buffer), "msi-string-overflow")
        return buffer.value

    def query(self, database, sql):
        with self.handle("MsiDatabaseOpenViewW", database, sql) as view:
            self.check(self.m.MsiViewExecute(view, 0))
            with self.handle("MsiViewGetColumnInfo", view, 0) as names:
                count = self.m.MsiRecordGetFieldCount(names)
                require(0 < count <= 128, "msi-column-bound")
                columns = [self.string(names, i) for i in range(1, count + 1)]
            with self.handle("MsiViewGetColumnInfo", view, 1) as types:
                kinds = [self.string(types, i) for i in range(1, count + 1)]
            rows, table_bytes = [], 0
            while True:
                record = W.UINT(); code = self.m.MsiViewFetch(view, ctypes.byref(record))
                if record.value:
                    self.handles.append(record.value)
                if code == 259:
                    require(record.value == 0, "msi-eof-returned-record")
                    break
                self.check(code); require(record.value != 0, "msi-fetch-null")
                try:
                    require(len(rows) < 131072, "msi-row-bound")
                    row = []
                    for index, kind in enumerate(kinds, 1):
                        require(re.fullmatch(r"[sSlLiIvV][0-9]{1,5}", kind), "msi-column-type")
                        if self.m.MsiRecordIsNull(record.value, index):
                            row.append(None)
                        elif kind[0].lower() == "v":
                            h = hashlib.sha256(); size = 0
                            while True:
                                buffer = ctypes.create_string_buffer(65536); used = W.DWORD(len(buffer))
                                self.check(self.m.MsiRecordReadStream(record.value, index, buffer, ctypes.byref(used)))
                                require(used.value <= len(buffer), "msi-stream-read-bound")
                                if not used.value: break
                                size += used.value; require(size <= MAX_PACKAGE, "msi-stream-size-bound")
                                self.stream_budget -= used.value
                                require(self.stream_budget >= 0, "aggregate-msi-stream-read-bound")
                                h.update(buffer.raw[:used.value])
                            row.append({"sizeBytes": size, "sha256": h.hexdigest()})
                        else:
                            row.append(self.string(record.value, index))
                    table_bytes += len(encoded(row))
                    require(table_bytes <= MAX_SNAPSHOT, "msi-table-size-bound")
                    rows.append(row)
                finally:
                    self.check(self.m.MsiCloseHandle(record.value)); self.handles.remove(record.value)
            rows.sort(key=encoded)
            result = {"columns": [list(x) for x in zip(columns, kinds)], "rows": rows}
            require(len(encoded(result)) <= MAX_SNAPSHOT, "msi-table-size-bound")
            return result

    def inspect(self, path):
        self.stream_budget = 2 * MAX_PACKAGE
        with self.handle("MsiOpenDatabaseW", str(path), None) as database:
            names = self.query(database, "SELECT `Name` FROM `_Tables`")
            tables = {x[0] for x in names["rows"]} | {"_Streams", "_Storages"}
            require(len(tables) <= 256 and all(type(x) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,71}", x)
                                               for x in tables), "msi-table-name-bound")
            values = {}
            for name in sorted(tables):
                values[name] = self.query(database, "SELECT * FROM `" + name + "`")
                require(len(encoded(values)) <= MAX_SNAPSHOT, "complete-msi-snapshot-bound")
            summary = {}
            with self.handle("MsiGetSummaryInformationW", database, None, 0) as info:
                for number in range(1, 20):
                    kind, integer, ft = W.UINT(), ctypes.c_int(), W.FILETIME()
                    text, length = ctypes.create_unicode_buffer(4097), W.DWORD(4096)
                    self.check(self.m.MsiSummaryInfoGetPropertyW(info, number, ctypes.byref(kind),
                        ctypes.byref(integer), ctypes.byref(ft), text, ctypes.byref(length)))
                    require(length.value <= 4096 and kind.value in {0, 2, 3, 30, 64}, "msi-summary-type-bound")
                    value = None if kind.value == 0 else integer.value if kind.value in {2, 3} else \
                        str(ft.dwHighDateTime << 32 | ft.dwLowDateTime) if kind.value == 64 else text.value
                    summary[str(number)] = {"type": kind.value, "value": value}
            return {"schemaVersion": 1, "tables": values, "summary": summary}

    def add_fixed_condition(self, path, package_code):
        require(GUID.fullmatch(package_code), "derived-package-code")
        # MSIDBOPEN_TRANSACT (1), not CREATE or a shell command.
        with self.handle("MsiOpenDatabaseW", str(path), ctypes.cast(ctypes.c_void_p(1), W.LPCWSTR)) as database:
            sql = "INSERT INTO `LaunchCondition` (`Condition`,`Description`) VALUES ('0','" + CONDITION[1] + "')"
            with self.handle("MsiDatabaseOpenViewW", database, sql) as view:
                self.check(self.m.MsiViewExecute(view, 0))
            with self.handle("MsiGetSummaryInformationW", database, None, 1) as info:
                self.check(self.m.MsiSummaryInfoSetPropertyW(info, 9, 30, 0, None, package_code))
                self.check(self.m.MsiSummaryInfoPersist(info))
            self.check(self.m.MsiDatabaseCommit(database))

    def seal(self, owner, path, parent_pin):
        native = owner.native
        handle = native.k.CreateFileW(str(path), 0x80020000, 1, None, 3, 0x02200000, None)
        require(handle != ctypes.c_void_p(-1).value, "derived-output-no-write-no-delete-open")
        owner.failing_msi_unclosed_handle = handle
        record = {"path": str(path), "nativeIdentity": native.identity(handle, False), "security": native.security(handle)}
        h = hashlib.sha256()
        for block in native.read_blocks(handle): h.update(block)
        record["sha256"] = h.hexdigest()
        # Reuse the actual admitted Owner Pin class and its named/held checks.
        pin_type = type(parent_pin)
        pin = pin_type.__new__(pin_type)
        owner.failing_msi_pending_pin = pin  # BEFORE __init__ can open a handle.
        pin_type.__init__(pin, native, record)
        owner.pins.append(pin); owner.by_path[str(path).casefold()] = pin
        owner.failing_msi_pending_pin = None
        require(native.k.CloseHandle(handle), "derived-output-initial-close")
        owner.failing_msi_unclosed_handle = None
        return pin

    def signature(self, path):
        class FileInfo(ctypes.Structure):
            _fields_ = [("size", W.DWORD), ("path", W.LPCWSTR), ("file", W.HANDLE), ("subject", W.LPVOID)]
        class TrustData(ctypes.Structure):
            _fields_ = [("size", W.DWORD), ("policy", W.LPVOID), ("sip", W.LPVOID), ("ui", W.DWORD),
                ("revocation", W.DWORD), ("choice", W.DWORD), ("file", ctypes.POINTER(FileInfo)),
                ("stateAction", W.DWORD), ("state", W.HANDLE), ("url", W.LPCWSTR),
                ("flags", W.DWORD), ("uiContext", W.DWORD)]
        trust = ctypes.WinDLL("wintrust.dll", use_last_error=True, winmode=0x800)
        trust.WinVerifyTrust.argtypes = (W.HANDLE, W.LPVOID, ctypes.POINTER(TrustData))
        trust.WinVerifyTrust.restype = ctypes.c_long
        action = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID("00aac56b-cd44-11d0-8cc2-00c04fc295ee").bytes_le)
        info = FileInfo(ctypes.sizeof(FileInfo), str(path), None, None)
        data = TrustData(ctypes.sizeof(TrustData), None, None, 2, 0, 1, ctypes.pointer(info),
                         0, None, None, 0x1000 | 0x10, 0)
        code = trust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data)) & 0xffffffff
        return {"status": "NotSigned" if code == 0x800B0100 else "Valid" if code == 0 else "Refused",
                "winVerifyTrustStatus": code, "cacheOnly": True}
