#!/usr/bin/env python3
"""Derive, on the Windows fixture builder, the deliberately failing MSI of one update fixture pair.

Test only. The fixture workflow runs ``derive`` after ``prepare_desktop_update_fixture.py build`` has built and
verified the same-source pair. The derived package is the pair's own target MSI with exactly one declared change set
(DELTA below), applied through msi.dll's database API and never through an installer API:

1. a new LaunchCondition table holding one row whose condition is "0". Windows Installer evaluates it in the
   LaunchConditions action, finds it false and ends the install with ERROR_INSTALL_FAILURE (1603);
2. that LaunchConditions action in InstallExecuteSequence at SEQUENCE. It comes after the read-only
   FindRelatedProducts and AppSearch and before every other action, so before RemoveExistingProducts (798 in the
   product's jpackage schedule, a removal outside the install transaction) and InstallInitialize. Nothing on the
   machine has changed when it fails, so the installed base stays installed;
3. a new package code (summary property 9), derived from the pair's source fingerprint, the target MSI's digest and
   this recipe's digest, so Windows Installer never takes it for the target package.

Nothing else may change. ``derive`` reads every table, every user stream and the summary properties before and after,
and refuses unless the after snapshot is exactly the expected one; a property-set stream (name starting with \\x05)
is compared through the summary properties alone. The product's install helper admits a package by its ProductName
and UpgradeCode (windows-install-helper-msi.cs), and the updater by the manifest's digest and size, both unchanged,
so the failing package reaches MsiInstallProductW under UI level NONE and fails there, in InstallExecuteSequence.

Outputs, each created once: packages/fault/<target stem>-native-install-failed.msi (read-only), the derivation
receipt native-install-failure.json, and the two snapshots native-install-failure-before.json and -after.json for
diagnosis. A failure leaves whatever it made for diagnosis and never retries. Nothing is installed, signed or
published: the asset's download URL names the disposable fixture release only the in-guest fixture server serves.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import uuid


KIND = "windows-native-install-failed-msi"
RECEIPT_NAME = "native-install-failure.json"
BEFORE_NAME = "native-install-failure-before.json"
AFTER_NAME = "native-install-failure-after.json"
FAULT_DIRECTORY = "packages/fault"
FAULT_SUFFIX = "-native-install-failed.msi"
CONDITION = ("0", "VPN_CONTROL_NATIVE_ACCEPTANCE_DELIBERATE_FAILURE")
SEQUENCE = 100
EXPECTED_INSTALLER_RESULT = 1603  # ERROR_INSTALL_FAILURE: a false launch condition under UI level NONE.
DELTA = {"launchCondition": list(CONDITION), "executeSequence": ["LaunchConditions", None, SEQUENCE],
         "table": {"name": "LaunchCondition", "columns": [["Condition", "s255"], ["Description", "l255"]]}}
CREATE_TABLE = ("CREATE TABLE `LaunchCondition` (`Condition` CHAR(255) NOT NULL, "
                "`Description` CHAR(255) NOT NULL LOCALIZABLE PRIMARY KEY `Condition`)")
INSERT_CONDITION = ("INSERT INTO `LaunchCondition` (`Condition`, `Description`) VALUES ('"
                    + CONDITION[0] + "', '" + CONDITION[1] + "')")
INSERT_ACTION = "INSERT INTO `InstallExecuteSequence` (`Action`, `Sequence`) VALUES ('LaunchConditions', " + str(SEQUENCE) + ")"
PRODUCT_NAME = "vpn-control"
UPGRADE_CODE = "{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}"  # desktopApp/build.gradle.kts upgradeUuid.
NAMESPACE = uuid.UUID("5d0f6c56-8c1b-5a3e-9b0e-4f0b6a1c2d71")
RELEASE_URL = "https://github.com/Karapsin/vpn_control/releases/download/disposable-desktop-fixture/"
MAX_PACKAGE = 1024 ** 3
MAX_SNAPSHOT = 32 * 1024 ** 2
MAX_RECEIPT = 64 * 1024
# Actions that only read the machine or the package. Every other action, a custom one included, counts as one that
# may change the machine and must come after the deliberate failure.
READ_ONLY_ACTIONS = frozenset({"FindRelatedProducts", "AppSearch", "CCPSearch", "RMCCPSearch", "ValidateProductID",
                               "CostInitialize", "FileCost", "CostFinalize", "MigrateFeatureStates", "InstallValidate",
                               "ResolveSource", "LaunchConditions"})
REQUIRED_ACTIONS = ("FindRelatedProducts", "RemoveExistingProducts", "InstallInitialize", "InstallFiles", "InstallFinalize")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_GUID = re.compile(r"\{[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}\}\Z")
_VERSION = re.compile(r"(?:[1-9]|1[0-9])\.(?:[0-9]|1[0-9])\.(?:[0-9]|1[0-9])\Z")
_FILE = re.compile(r"[A-Za-z0-9_.+-]{1,120}\.msi\Z")


class Refused(ValueError):
    """A finite refusal; the code names the check, never a private path."""


def require(condition, code):
    if not condition:
        raise Refused(code)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def file_sha256(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def recipe_sha256():
    return file_sha256(Path(__file__))


def package_code(source_fingerprint, parent_sha256, recipe):
    require(all(type(value) is str and _HASH.fullmatch(value) for value in (source_fingerprint, parent_sha256, recipe)),
            "package-code-inputs")
    return "{" + str(uuid.uuid5(NAMESPACE, source_fingerprint + ":" + parent_sha256 + ":" + recipe)).upper() + "}"


def _columns(table, names):
    columns = table.get("columns") if type(table) is dict else None
    return (type(columns) is list and [column[0] if type(column) is list and len(column) == 2 else None
                                       for column in columns] == list(names))


def product(snapshot):
    """The identity a snapshot's Property table and summary declare, or a refusal."""
    require(type(snapshot) is dict and set(snapshot) == {"schemaVersion", "tables", "summary", "streams"}
            and snapshot["schemaVersion"] == 1 and type(snapshot["tables"]) is dict and type(snapshot["summary"]) is dict
            and type(snapshot["streams"]) is dict, "msi-snapshot-schema")
    table = snapshot["tables"].get("Property")
    require(_columns(table, ("Property", "Value")) and type(table.get("rows")) is list
            and all(type(row) is list and len(row) == 2 and type(row[0]) is str for row in table["rows"])
            and len({row[0] for row in table["rows"]}) == len(table["rows"]), "msi-property-table")
    values = dict(table["rows"])
    summary = snapshot["summary"].get("9")
    facts = {"productName": values.get("ProductName"), "productCode": values.get("ProductCode"),
             "upgradeCode": values.get("UpgradeCode"), "productVersion": values.get("ProductVersion"),
             "packageCode": summary.get("value") if type(summary) is dict else None}
    require(facts["productName"] == PRODUCT_NAME and type(facts["productVersion"]) is str
            and _VERSION.fullmatch(facts["productVersion"]), "msi-product-identity")
    for key in ("productCode", "upgradeCode", "packageCode"):
        require(type(facts[key]) is str and _GUID.fullmatch(facts[key].upper()), "msi-product-guid")
        facts[key] = facts[key].upper()
    require(facts["upgradeCode"] == UPGRADE_CODE, "msi-product-upgrade-code")
    require(type(summary) is dict and summary.get("type") == 30, "msi-package-code-summary-type")
    return facts


def validate_schedule(snapshot):
    """The product MSI as its pair builds it: no launch condition of its own, and room for the declared one first."""
    facts = product(snapshot)
    tables = snapshot["tables"]
    require("LaunchCondition" not in tables, "msi-launch-condition-table-present")
    sequence = tables.get("InstallExecuteSequence")
    require(_columns(sequence, ("Action", "Condition", "Sequence")) and type(sequence.get("rows")) is list,
            "msi-execute-sequence-schema")
    rows = sequence["rows"]
    require(all(type(row) is list and len(row) == 3 and type(row[0]) is str and (row[1] is None or type(row[1]) is str)
                and type(row[2]) is str and re.fullmatch(r"-?[0-9]{1,5}", row[2]) for row in rows)
            and len({row[0] for row in rows}) == len(rows), "msi-execute-sequence-rows")
    actions = {row[0]: int(row[2]) for row in rows}
    require("LaunchConditions" not in actions, "msi-launch-conditions-action-present")
    require(all(name in actions for name in REQUIRED_ACTIONS), "msi-execute-sequence-actions")
    require(SEQUENCE not in actions.values(), "msi-execute-sequence-slot-taken")
    require(all(actions[name] < SEQUENCE for name in ("FindRelatedProducts", "AppSearch") if name in actions),
            "msi-execute-sequence-search-order")
    # Negative and zero sequence numbers are not scheduled; every scheduled action that may change the machine,
    # RemoveExistingProducts and every custom action among them, comes after the deliberate failure.
    require(all(number > SEQUENCE for name, number in actions.items() if number > 0 and name not in READ_ONLY_ACTIONS),
            "msi-execute-sequence-modifying-before-failure")
    return facts


def expected_after(before, code):
    """The one declared change set, applied to a snapshot."""
    validate_schedule(before)
    require(type(code) is str and _GUID.fullmatch(code) and code != product(before)["packageCode"], "msi-derived-package-code")
    after = copy.deepcopy(before)
    after["tables"]["LaunchCondition"] = {"columns": copy.deepcopy(DELTA["table"]["columns"]), "rows": [list(CONDITION)]}
    rows = after["tables"]["InstallExecuteSequence"]["rows"]
    rows.append(["LaunchConditions", None, str(SEQUENCE)])
    rows.sort(key=encoded)
    after["summary"]["9"]["value"] = code
    return after


def property_set(name):
    return name.startswith("\x05")


def same_except_declared(before, after, code):
    """True when after is exactly before with the declared change set, property-set streams aside."""
    expected = expected_after(before, code)
    keep = {name: value for name, value in after["streams"].items() if not property_set(name)}
    wanted = {name: value for name, value in expected["streams"].items() if not property_set(name)}
    return ({key: value for key, value in after.items() if key != "streams"}
            == {key: value for key, value in expected.items() if key != "streams"} and keep == wanted
            and {name for name in after["streams"] if property_set(name)} == {name for name in expected["streams"] if property_set(name)})


def fault_asset(target, name, sha256, size):
    require(_FILE.fullmatch(name) is not None and _HASH.fullmatch(sha256) and type(size) is int and 0 < size <= MAX_PACKAGE,
            "fault-asset-identity")
    return {"platform": "windows", "architecture": "x86_64", "packageType": "msi", "displayVersion": target["displayVersion"],
            "fileName": name, "downloadUrl": RELEASE_URL + name, "sha256": sha256, "sizeBytes": size}


def fault_name(target_name):
    require(_FILE.fullmatch(target_name) is not None and target_name.lower().endswith(".msi"), "target-asset-name")
    name = target_name[:-4] + FAULT_SUFFIX
    require(_FILE.fullmatch(name) is not None, "fault-asset-name")
    return name


def pair_target(receipt):
    """The pair's target asset: the one MSI its manifest serves, built from the receipt's source."""
    require(type(receipt) is dict and receipt.get("schemaVersion") == 1 and receipt.get("testOnly") is True
            and receipt.get("productionTrustChanged") is False and receipt.get("architecture") == "x86_64"
            and type(receipt.get("sourceFingerprint")) is str and _HASH.fullmatch(receipt["sourceFingerprint"])
            and type(receipt.get("builds")) is list and len(receipt["builds"]) == 2, "fixture-receipt-schema")
    base, target = receipt["builds"]
    manifest = receipt.get("manifest")
    require(type(base) is dict and type(target) is dict and base.get("label") == "base" and target.get("label") == "target"
            and type(manifest) is dict and type(target.get("assets")) is list and len(target["assets"]) == 1
            and manifest.get("assets") == target["assets"], "fixture-receipt-pair")
    asset = target["assets"][0]
    require(type(asset) is dict and asset.get("platform") == "windows" and asset.get("architecture") == "x86_64"
            and asset.get("packageType") == "msi" and asset.get("displayVersion") == target.get("version")
            and type(asset.get("fileName")) is str and _FILE.fullmatch(asset["fileName"])
            and type(asset.get("sha256")) is str and _HASH.fullmatch(asset["sha256"])
            and type(asset.get("sizeBytes")) is int and 0 < asset["sizeBytes"] <= MAX_PACKAGE, "fixture-receipt-target-asset")
    return asset


def build_receipt(fixture, target, before, after, code, recipe, output):
    parent = product(before)
    return {"schemaVersion": 1, "kind": KIND, "testOnly": True, "productionTrustChanged": False,
            "sourceFingerprint": fixture["sourceFingerprint"], "recipeSha256": recipe,
            "parent": {"asset": target, **{key: parent[key] for key in ("productCode", "upgradeCode", "productVersion", "packageCode")}},
            "output": {"asset": output, "packageCode": code},
            "delta": {**copy.deepcopy(DELTA), "packageCode": {"before": parent["packageCode"], "after": code}},
            "expectedInstallerResult": EXPECTED_INSTALLER_RESULT,
            "beforeSnapshotSha256": digest(before), "afterSnapshotSha256": digest(after),
            "nativeInstallationExecuted": False, "nativeAcceptance": None}


def _write_once(path, raw):
    with Path(path).open("xb", buffering=0) as stream:
        offset = 0
        while offset < len(raw):
            count = stream.write(raw[offset:])
            require(type(count) is int and count > 0, "durable-write-progress")
            offset += count
        os.fsync(stream.fileno())


def derive(directory, native=None):
    """Derive once into a pair's fixture directory; returns the receipt it wrote."""
    directory = Path(directory).resolve(strict=True)
    native = native if native is not None else SystemMsi()
    fixture = json.loads((directory / "fixture-receipt.json").read_bytes())
    target = pair_target(fixture)
    source = directory / "packages" / "target" / target["fileName"]
    require(source.is_file() and not source.is_symlink() and source.stat().st_size == target["sizeBytes"]
            and file_sha256(source) == target["sha256"], "target-msi-bytes")
    outputs = [directory / name for name in (RECEIPT_NAME, BEFORE_NAME, AFTER_NAME)] + [directory / FAULT_DIRECTORY]
    require(not any(os.path.lexists(path) for path in outputs), "derivation-outputs-exist")
    before = native.inspect(source)
    facts = validate_schedule(before)
    require(facts["productVersion"] == target["displayVersion"], "target-msi-version")
    recipe = recipe_sha256()
    code = package_code(fixture["sourceFingerprint"], target["sha256"], recipe)
    expected_after(before, code)  # Refuses before any output exists.
    _write_once(directory / BEFORE_NAME, encoded(before))
    folder = directory / FAULT_DIRECTORY
    folder.mkdir(mode=0o700)
    output = folder / fault_name(target["fileName"])
    with source.open("rb") as reader, output.open("xb", buffering=0) as writer:
        shutil.copyfileobj(reader, writer, 1024 * 1024)
        os.fsync(writer.fileno())
    require(file_sha256(output) == target["sha256"], "fault-copy-bytes")
    native.apply(output, code)
    after = native.inspect(output)
    _write_once(directory / AFTER_NAME, encoded(after))
    require(same_except_declared(before, after, code), "unexpected-native-msi-delta")
    require(file_sha256(source) == target["sha256"], "target-msi-changed")
    output.chmod(0o400)
    asset = fault_asset(target, output.name, file_sha256(output), output.stat().st_size)
    receipt = build_receipt(fixture, target, before, after, code, recipe, asset)
    raw = encoded(receipt)
    require(len(raw) <= MAX_RECEIPT, "derivation-receipt-bound")
    _write_once(directory / RECEIPT_NAME, raw)
    return receipt


class SystemMsi:
    """Fixed msi.dll database operations on one local file. Deliberately no installation entry point."""
    _SIGNATURES = None

    def __init__(self):
        require(os.name == "nt" and ctypes.sizeof(ctypes.c_void_p) == 8, "native-windows-amd64")
        from ctypes import wintypes as W
        self.W = W
        self.m = ctypes.WinDLL("msi.dll", use_last_error=True)
        for name, arguments, result in (
                ("MsiOpenDatabaseW", (W.LPCWSTR, W.LPCWSTR, ctypes.POINTER(W.DWORD)), W.UINT),
                ("MsiDatabaseOpenViewW", (W.DWORD, W.LPCWSTR, ctypes.POINTER(W.DWORD)), W.UINT),
                ("MsiViewExecute", (W.DWORD, W.DWORD), W.UINT),
                ("MsiViewFetch", (W.DWORD, ctypes.POINTER(W.DWORD)), W.UINT),
                ("MsiViewClose", (W.DWORD,), W.UINT),
                ("MsiViewGetColumnInfo", (W.DWORD, ctypes.c_int, ctypes.POINTER(W.DWORD)), W.UINT),
                ("MsiRecordGetFieldCount", (W.DWORD,), W.UINT),
                ("MsiRecordIsNull", (W.DWORD, W.UINT), W.BOOL),
                ("MsiRecordGetStringW", (W.DWORD, W.UINT, W.LPWSTR, ctypes.POINTER(W.DWORD)), W.UINT),
                ("MsiRecordReadStream", (W.DWORD, W.UINT, ctypes.c_char_p, ctypes.POINTER(W.DWORD)), W.UINT),
                ("MsiGetSummaryInformationW", (W.DWORD, W.LPCWSTR, W.UINT, ctypes.POINTER(W.DWORD)), W.UINT),
                ("MsiSummaryInfoGetPropertyW", (W.DWORD, W.UINT, ctypes.POINTER(W.UINT), ctypes.POINTER(ctypes.c_int),
                                                ctypes.POINTER(W.FILETIME), W.LPWSTR, ctypes.POINTER(W.DWORD)), W.UINT),
                ("MsiSummaryInfoSetPropertyW", (W.DWORD, W.UINT, W.UINT, ctypes.c_int, ctypes.POINTER(W.FILETIME), W.LPCWSTR), W.UINT),
                ("MsiSummaryInfoPersist", (W.DWORD,), W.UINT),
                ("MsiDatabaseCommit", (W.DWORD,), W.UINT),
                ("MsiCloseHandle", (W.DWORD,), W.UINT)):
            function = getattr(self.m, name)
            function.argtypes, function.restype = arguments, result

    @staticmethod
    def check(code, what):
        require(code == 0, "native-msi-" + what + "-" + str(code))

    def _open(self, path, mode):
        handle = self.W.DWORD(0)
        persist = ctypes.cast(ctypes.c_void_p(mode), self.W.LPCWSTR)  # MSIDBOPEN_READONLY 0, MSIDBOPEN_TRANSACT 1.
        self.check(self.m.MsiOpenDatabaseW(str(path), persist, ctypes.byref(handle)), "open")
        require(handle.value != 0, "native-msi-null-database")
        return handle.value

    def _close(self, handle):
        self.check(self.m.MsiCloseHandle(handle), "close")

    def _string(self, record, field):
        size = self.W.DWORD(0)
        empty = ctypes.create_unicode_buffer(1)
        code = self.m.MsiRecordGetStringW(record, field, empty, ctypes.byref(size))
        require(code in (0, 234) and size.value <= 1024 * 1024, "native-msi-string-bound")
        if code == 0:
            return empty.value
        buffer = ctypes.create_unicode_buffer(size.value + 1)
        capacity = self.W.DWORD(len(buffer))
        self.check(self.m.MsiRecordGetStringW(record, field, buffer, ctypes.byref(capacity)), "string")
        return buffer.value

    def _stream(self, record, field):
        value, size = hashlib.sha256(), 0
        buffer = ctypes.create_string_buffer(65536)
        while True:
            count = self.W.DWORD(len(buffer))
            self.check(self.m.MsiRecordReadStream(record, field, buffer, ctypes.byref(count)), "stream")
            require(count.value <= len(buffer), "native-msi-stream-count")
            if count.value == 0:
                return {"sizeBytes": size, "sha256": value.hexdigest()}
            size += count.value
            require(size <= MAX_PACKAGE, "native-msi-stream-bound")
            value.update(buffer.raw[:count.value])

    def _query(self, database, sql):
        view = self.W.DWORD(0)
        self.check(self.m.MsiDatabaseOpenViewW(database, sql, ctypes.byref(view)), "view")
        try:
            self.check(self.m.MsiViewExecute(view.value, 0), "execute")
            info = []
            for kind in (0, 1):  # MSICOLINFO_NAMES, MSICOLINFO_TYPES
                record = self.W.DWORD(0)
                self.check(self.m.MsiViewGetColumnInfo(view.value, kind, ctypes.byref(record)), "columns")
                try:
                    count = self.m.MsiRecordGetFieldCount(record.value)
                    require(0 < count <= 128, "native-msi-column-bound")
                    info.append([self._string(record.value, index) for index in range(1, count + 1)])
                finally:
                    self._close(record.value)
            names, kinds = info
            require(len(names) == len(kinds) and all(re.fullmatch(r"[sSlLiIvVgGjJ][0-9]{1,5}", kind) for kind in kinds),
                    "native-msi-column-types")
            rows, size = [], 0
            while True:
                record = self.W.DWORD(0)
                code = self.m.MsiViewFetch(view.value, ctypes.byref(record))
                if code == 259:  # ERROR_NO_MORE_ITEMS
                    break
                self.check(code, "fetch")
                try:
                    row = []
                    for index, kind in enumerate(kinds, 1):
                        if self.m.MsiRecordIsNull(record.value, index):
                            row.append(None)
                        elif kind[0] in "vV":
                            row.append(self._stream(record.value, index))
                        else:
                            row.append(self._string(record.value, index))
                    size += len(encoded(row))
                    require(len(rows) < 131072 and size <= MAX_SNAPSHOT, "native-msi-table-bound")
                    rows.append(row)
                finally:
                    self._close(record.value)
            rows.sort(key=encoded)
            return {"columns": [[name, kind] for name, kind in zip(names, kinds)], "rows": rows}
        finally:
            self.m.MsiViewClose(view.value)
            self._close(view.value)

    def _summary(self, database):
        handle = self.W.DWORD(0)
        self.check(self.m.MsiGetSummaryInformationW(database, None, 0, ctypes.byref(handle)), "summary")
        try:
            values = {}
            for number in range(1, 20):
                kind, integer, filetime = self.W.UINT(0), ctypes.c_int(0), self.W.FILETIME()
                text, length = ctypes.create_unicode_buffer(4097), self.W.DWORD(4096)
                self.check(self.m.MsiSummaryInfoGetPropertyW(handle.value, number, ctypes.byref(kind), ctypes.byref(integer),
                                                             ctypes.byref(filetime), text, ctypes.byref(length)), "summary-property")
                require(kind.value in (0, 2, 3, 30, 64) and length.value <= 4096, "native-msi-summary-type")
                value = (None if kind.value == 0 else integer.value if kind.value in (2, 3)
                         else str(filetime.dwHighDateTime << 32 | filetime.dwLowDateTime) if kind.value == 64 else text.value)
                values[str(number)] = {"type": kind.value, "value": value}
            return values
        finally:
            self._close(handle.value)

    def inspect(self, path):
        database = self._open(path, 0)
        try:
            names = self._query(database, "SELECT `Name` FROM `_Tables`")
            tables = {}
            for row in names["rows"]:
                name = row[0]
                require(type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,71}", name) and len(names["rows"]) <= 256,
                        "native-msi-table-name")
                tables[name] = self._query(database, "SELECT * FROM `" + name + "`")
            streams = {row[0]: row[1] for row in self._query(database, "SELECT `Name`, `Data` FROM `_Streams`")["rows"]}
            snapshot = {"schemaVersion": 1, "tables": tables, "summary": self._summary(database), "streams": streams}
            require(len(encoded(snapshot)) <= MAX_SNAPSHOT, "native-msi-snapshot-bound")
            return snapshot
        finally:
            self._close(database)

    def _execute(self, database, sql):
        view = self.W.DWORD(0)
        self.check(self.m.MsiDatabaseOpenViewW(database, sql, ctypes.byref(view)), "view")
        try:
            self.check(self.m.MsiViewExecute(view.value, 0), "execute")
        finally:
            self.m.MsiViewClose(view.value)
            self._close(view.value)

    def apply(self, path, code):
        """The declared change set, in one transacted database: two rows, one table and the package code."""
        require(_GUID.fullmatch(code) is not None, "native-msi-package-code")
        database = self._open(path, 1)
        try:
            for sql in (CREATE_TABLE, INSERT_CONDITION, INSERT_ACTION):
                self._execute(database, sql)
            summary = self.W.DWORD(0)
            self.check(self.m.MsiGetSummaryInformationW(database, None, 1, ctypes.byref(summary)), "summary-open")
            try:
                self.check(self.m.MsiSummaryInfoSetPropertyW(summary.value, 9, 30, 0, None, code), "summary-set")
                self.check(self.m.MsiSummaryInfoPersist(summary.value), "summary-persist")
            finally:
                self._close(summary.value)
            self.check(self.m.MsiDatabaseCommit(database), "commit")
        finally:
            self._close(database)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="action", required=True)
    derive_parser = commands.add_parser("derive")
    derive_parser.add_argument("--directory", required=True, type=Path)
    derive_parser.add_argument("--confirm-owned-native-host-build", action="store_true")
    arguments = parser.parse_args(argv)
    require(arguments.confirm_owned_native_host_build, "explicit-owned-build-confirmation")
    receipt = derive(arguments.directory)
    print(json.dumps({"kind": receipt["kind"], "fault": receipt["output"]["asset"]["fileName"],
                      "sha256": receipt["output"]["asset"]["sha256"], "packageCode": receipt["output"]["packageCode"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refused as error:
        print("windows-native-failure-msi refused: " + str(error), file=sys.stderr)
        sys.exit(1)
