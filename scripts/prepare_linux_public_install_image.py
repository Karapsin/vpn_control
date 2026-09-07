#!/usr/bin/env python3
"""Clone a Linux app image with TEST-ONLY older build metadata; never alter trust/code.

The output is for an explicitly owned disposable VM only. This does not install it.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import zipfile


def prepare(source, output):
    source = source.resolve(strict=True)
    output = output.absolute()
    assert source.is_dir() and not output.exists()
    assert source != output and source not in output.parents
    launcher = source / "bin/vpn-control"
    assert launcher.read_bytes()[:4] == b"\x7fELF", "Requires a native Linux app image"
    assert (source / "lib/runtime").is_dir()
    for path in source.rglob("*"):
        if path.is_symlink():
            assert path.resolve(strict=True).is_relative_to(source), "Image contains an external symlink"
    owners = []
    for path in (source / "lib/app").glob("*.jar"):
        with zipfile.ZipFile(path) as jar:
            if "com/kardinal/vpncontrol/desktop/MainKt.class" in jar.namelist():
                owners.append(path)
    assert len(owners) == 1, "Resolve exactly one packaged main jar"
    main = owners[0]
    metadata = "vpn-control-version.properties"
    with zipfile.ZipFile(main) as jar:
        for name in (metadata, "linux-install-worker.sh", "linux-install-arch.sh",
                     "com/kardinal/vpncontrol/desktop/DesktopLinuxInstallClient.class",
                     "com/kardinal/vpncontrol/desktop/DesktopInstallCorrelationJournal.class"):
            assert name in jar.namelist(), "Stale app image: " + name
        assert not any(n.startswith("META-INF/") and n.endswith((".SF", ".RSA", ".DSA")) for n in jar.namelist())
        original_metadata = jar.read(metadata).decode("utf-8")
    output.mkdir()
    image = output / "TEST-ONLY-vpn-control"
    shutil.copytree(source, image, symlinks=True)
    target = image / main.relative_to(source)
    temporary = output / "metadata-replacement.jar"
    with zipfile.ZipFile(main) as original, zipfile.ZipFile(temporary, "w") as replaced:
        for info in original.infolist():
            data = b"buildNumber=1\ndisplayVersion=1.0.0\n" if info.filename == metadata else original.read(info.filename)
            replaced.writestr(info, data)
    temporary.replace(target)
    receipt = {"testOnly": True, "productionTrustChanged": False, "sourceImage": str(source),
               "mainJar": str(main.relative_to(source)), "originalMetadata": original_metadata,
               "originalMainSha256": hashlib.sha256(main.read_bytes()).hexdigest(),
               "fixtureMainSha256": hashlib.sha256(target.read_bytes()).hexdigest()}
    (image / "TEST-ONLY-INSTALL-FIXTURE.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    (output / "fixture-receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return {"image": str(image), "receipt": receipt}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.image, args.output), indent=2))
