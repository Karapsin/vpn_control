"""Read-only identity admission for an RPM-installed Linux update base."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from prepare_desktop_update_fixture import image_identity


_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_SOURCE_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HEADER_SHA = re.compile(r"[a-f0-9]{40}\Z")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command(runner, arguments):
    return runner(arguments, capture_output=True, text=True, timeout=30, check=False)


def rpm_identity(runner, package_or_name):
    result = command(runner, ["rpm", "-q" if package_or_name == "vpn-control" else "-qp",
                              "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SHA1HEADER}\\n",
                              package_or_name])
    require(result.returncode == 0 and len(lines := result.stdout.splitlines()) == 1 and
            len(fields := lines[0].split("\t")) == 6 and all(fields[:5]) and _HEADER_SHA.fullmatch(fields[5]),
            "RPM identity query failed")
    return tuple(fields)


def _source_identity(receipt, base, target):
    fingerprint = receipt.get("sourceFingerprint")
    require(isinstance(fingerprint, str) and _SHA256.fullmatch(fingerprint) and
            base.get("sourceFingerprint") == target.get("sourceFingerprint") == fingerprint,
            "RPM source fingerprint differs across fixture receipt")
    source_sha_values = [item.get("sourceSha") for item in (receipt, base, target) if item.get("sourceSha") is not None]
    if source_sha_values:
        require(len(source_sha_values) == 3 and all(isinstance(value, str) and _SOURCE_SHA.fullmatch(value)
                                                     for value in source_sha_values) and len(set(source_sha_values)) == 1,
                "RPM source SHA differs across fixture receipt")
    # A source SHA identifies the Git source revision. The source fingerprint is
    # a hash of frozen build inputs, so they intentionally have different forms.
    return fingerprint, source_sha_values[0] if source_sha_values else None


def verify_rpm_bundle_base(launcher, fixture, *, runner=subprocess.run, identity=image_identity, platform_name=sys.platform):
    """Verify a package-managed installed RPM against a frozen source-pair base.

    This performs no installation, service control, or package-manager mutation.
    It intentionally does not accept Arch bundles or image markers.
    """
    require(platform_name.startswith("linux"), "RPM fixture verification requires Linux")
    launcher, fixture = Path(launcher), Path(fixture)
    require(launcher == Path("/opt/vpn-control/bin/vpn-control"), "RPM fixture requires the supported installed launcher")
    require(fixture.is_absolute() and fixture.is_dir() and not fixture.is_symlink(), "RPM fixture directory is invalid")
    receipt_path = fixture / "fixture-receipt.json"
    require(receipt_path.is_file() and not receipt_path.is_symlink(), "RPM fixture receipt is missing or unsafe")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    require(receipt.get("schemaVersion") == 1 and receipt.get("testOnly") is True and
            receipt.get("productionTrustChanged") is False, "Not a source-pair fixture")
    builds = receipt.get("builds")
    require(isinstance(builds, list) and len(builds) == 2, "RPM fixture requires base and target builds")
    base, target = builds
    require(isinstance(base, dict) and isinstance(target, dict) and base.get("label") == "base" and
            target.get("label") == "target", "RPM fixture build labels are invalid")
    fingerprint, source_sha = _source_identity(receipt, base, target)
    require(base.get("codeFingerprint") == target.get("codeFingerprint"), "RPM source pair code differs")
    assets = [asset for asset in base.get("assets", []) if isinstance(asset, dict) and asset.get("packageType") == "rpm"]
    require(len(assets) == 1, "RPM fixture requires exactly one base RPM asset")
    asset = assets[0]
    name = asset.get("fileName")
    require(isinstance(name, str) and "/" not in name and ".." not in name and asset.get("platform") == "linux" and
            asset.get("displayVersion") == base.get("version") and isinstance(asset.get("sizeBytes"), int) and
            isinstance(asset.get("sha256"), str) and _SHA256.fullmatch(asset["sha256"]), "RPM base asset is invalid")
    package = fixture / "packages" / "base" / name
    require(package.is_file() and not package.is_symlink() and package.stat().st_size == asset["sizeBytes"] and
            file_hash(package) == asset["sha256"], "RPM base asset hash or size differs")
    owner = command(runner, ["rpm", "--query", "--file", "--queryformat", "%{NAME}\\n", str(launcher)])
    require(owner.returncode == 0 and owner.stdout == "vpn-control\n", "RPM does not own the installed launcher")
    expected_rpm = rpm_identity(runner, str(package))
    installed_rpm = rpm_identity(runner, "vpn-control")
    require(installed_rpm[:5] == expected_rpm[:5], "Installed RPM NEVRA differs from frozen base")
    require(installed_rpm[5] == expected_rpm[5], "Installed RPM header differs from frozen base")
    verified = command(runner, ["rpm", "-V", "vpn-control"])
    require(verified.returncode == 0 and not verified.stdout.strip() and not verified.stderr.strip(),
            "Installed RPM verification is not clean")
    actual = identity(launcher.parent.parent, base["version"])
    expected = {key: base.get(key) for key in ("codeFingerprint", "mainJar", "mainJarSha256")}
    require(actual == expected, "Installed RPM image differs from frozen base")
    return {"testOnly": True, "productionTrustChanged": False, "sameSourceBuild": True,
            "packageType": "rpm", "version": base["version"], "sourceFingerprint": fingerprint,
            "sourceSha": source_sha, **actual}
