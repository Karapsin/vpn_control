#!/usr/bin/env python3

import json
from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    repository = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        incoming = root / "incoming"
        files = {
            "vpn-control-android-release-apk/app.apk": b"apk",
            "vpn-control-windows-installers/app.msi": b"msi",
            "vpn-control-windows-installers/app.exe": b"exe",
            "vpn-control-linux-packages/app.deb": b"deb",
            "vpn-control-linux-packages/app.rpm": b"rpm",
            "vpn-control-linux-packages/app.tar.gz": b"arch",
            "vpn-control-macos-package/app.dmg": b"dmg",
        }
        for relative, content in files.items():
            path = incoming / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        output = root / "release"
        subprocess.run(
            [
                "python3",
                str(repository / "scripts/assemble_update_release.py"),
                "--incoming", str(incoming),
                "--output", str(output),
                "--build-number", "16000",
                "--version", "2.0.0",
                "--tag", "v2.0.0",
                "--mac-architecture", "aarch64",
            ],
            check=True,
        )
        manifest = json.loads((output / "update-manifest.json").read_text(encoding="utf-8"))
        assert manifest["buildNumber"] == 16000
        assert len(manifest["assets"]) == 6
        assert {asset["packageType"] for asset in manifest["assets"]} == {
            "apk", "msi", "deb", "rpm", "arch-bundle", "dmg"
        }
        mac = next(asset for asset in manifest["assets"] if asset["platform"] == "macos")
        assert mac["architecture"] == "arm64"
        assert mac["displayVersion"] == "2.0.0"
        assert len((output / "SHA256SUMS.txt").read_text().splitlines()) == 8
    print("[vpn-control] update release assembly test passed")


if __name__ == "__main__":
    main()
