"""Read-only verification of an installed Arch fixture against its source bundle."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

from prepare_desktop_update_fixture import image_identity


def require(value, message):
    if not value:
        raise RuntimeError(message)


def stream_hash(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def verify_arch_bundle_base(launcher, fixture, *, lstat=Path.lstat):
    # Arch has neither package-manager ownership nor an embedded test marker.
    # Compare actual installed files to the hash-verified immutable base bundle.
    launcher, fixture = Path(launcher), Path(fixture)
    require(launcher.is_absolute() and launcher.name == "vpn-control" and
            launcher.parent.name == "bin" and ".." not in launcher.parts,
            "Requires an absolute installed Arch launcher")
    image = launcher.parent.parent

    def safe(path, kind):
        info = lstat(path)
        require(stat.S_IFMT(info.st_mode) == kind and info.st_uid == 0 and
                not info.st_mode & 0o022, "Untrusted installed file or ancestry")
        return info

    for parent in launcher.parents:
        safe(parent, stat.S_IFDIR)
    safe(launcher, stat.S_IFREG)
    receipt = json.loads((fixture / "fixture-receipt.json").read_text())
    require(receipt.get("schemaVersion") == 1 and receipt.get("testOnly") is True and
            receipt.get("productionTrustChanged") is False, "Not a source-pair fixture")
    base, target = receipt["builds"]
    fingerprint = receipt["sourceFingerprint"]
    require(re.fullmatch(r"[a-f0-9]{64}", fingerprint) and base["label"] == "base" and
            target["label"] == "target" and base["sourceFingerprint"] ==
            target["sourceFingerprint"] == fingerprint and
            base["codeFingerprint"] == target["codeFingerprint"], "Mismatched source pair")
    assets = [asset for asset in base["assets"] if asset.get("packageType") == "arch-bundle"]
    require(len(assets) == 1, "Requires exactly one Arch base bundle")
    asset = assets[0]
    require(asset.get("platform") == "linux" and asset.get("displayVersion") == base["version"] and
            re.fullmatch(r"[A-Za-z0-9_.+-]+", asset["fileName"]), "Wrong Arch base asset")
    package = fixture / "packages/base" / asset["fileName"]
    require(stat.S_ISREG(package.lstat().st_mode) and package.stat().st_size == asset["sizeBytes"],
            "Base bundle size or file type mismatch")
    with package.open("rb") as stream:
        require(stream_hash(stream) == asset["sha256"], "Base bundle hash mismatch")
    expected, members = set(), set()
    runtime_seen = False
    prefix = "vpn-control-arch-update"
    with tarfile.open(package, "r:gz") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts and member.name not in members,
                    "Unsafe or duplicate bundle entry")
            members.add(member.name)
            if name.parts[:2] == (prefix, "app"):
                relative = Path(*name.parts[2:])
            elif name.parts == (prefix, "sing-box"):
                require(member.isfile(), "Invalid bundled runtime")
                runtime_seen = True
                relative = Path("bin/sing-box")
            else:
                continue
            require(relative not in expected, "Duplicate installed bundle path")
            expected.add(relative)
            installed = image / relative
            for parent in installed.parents:
                if parent == image:
                    break
                if parent.is_relative_to(image):
                    safe(parent, stat.S_IFDIR)
            if member.isdir():
                safe(installed, stat.S_IFDIR)
            elif member.isfile():
                info = safe(installed, stat.S_IFREG)
                require(info.st_size == member.size, "Installed file size differs from base bundle")
                with archive.extractfile(member) as source, installed.open("rb") as current:
                    require(stream_hash(source) == stream_hash(current), "Installed bytes differ from base bundle")
            elif member.issym():
                info = lstat(installed)
                require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and
                        os.readlink(installed) == member.linkname, "Installed symlink differs from base bundle")
                require(installed.resolve(strict=True).is_relative_to(image), "Escaped installed symlink")
            else:
                raise RuntimeError("Unsupported installed bundle entry")
    require(runtime_seen and Path("bin/vpn-control") in expected, "Incomplete Arch bundle")
    actual = {Path(".")}
    for directory, directories, files in os.walk(image, followlinks=False):
        actual.update((Path(directory) / name).relative_to(image) for name in directories + files)
    require(actual == expected, "Unexpected or missing installed image entries")
    identity = image_identity(image, base["version"])
    require(identity == {key: base[key] for key in ("codeFingerprint", "mainJar", "mainJarSha256")},
            "Installed code differs from source pair")
    return {"testOnly": True, "productionTrustChanged": False, "sameSourceBuild": True,
            "version": base["version"], "sourceFingerprint": fingerprint, **identity}
