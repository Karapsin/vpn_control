#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile


SCRIPT = Path(__file__).with_name("version_metadata.py")
SPEC = importlib.util.spec_from_file_location("version_metadata", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
version_metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(version_metadata)


def main() -> None:
    assert version_metadata.parse_version("2.0.0") == (2, 0, 0)
    assert version_metadata.product_version((2, 0, 0)) == "2.0.0"
    assert version_metadata.build_number((2, 0, 0)) == 16_000
    for invalid in ("1.1", "1.1.x", "1.1.20", "1.1.2.3", "0.2.0"):
        try:
            version_metadata.parse_version(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid version: {invalid}")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "gradle.properties").write_text("vpnControlVersion=2.0.0\n", encoding="utf-8")
        assert version_metadata.metadata(root) == {
            "version": "2.0.0",
            "build-number": "16000",
            "desktop-package-version": "2.0.0",
            "macos-package-version": "2.0.0",
            "tag": "v2.0.0",
        }

    repository = SCRIPT.parents[1]
    android_gradle = (repository / "app/build.gradle.kts").read_text(encoding="utf-8")
    desktop_gradle = (repository / "desktopApp/build.gradle.kts").read_text(encoding="utf-8")
    arch_packager = (repository / "scripts/package_arch_desktop_update.sh").read_text(encoding="utf-8")
    assert "val generatedVersionCode = canonicalVersionCode" in android_gradle
    assert "val generatedVersionName = canonicalVersion" in android_gradle
    assert "val runtimeDisplayVersion = canonicalVersion" in desktop_gradle
    assert 'packageVersion = canonicalVersion.get()' in desktop_gradle
    assert 'display_version="$(python3 scripts/version_metadata.py --field version)"' in arch_packager
    print("[vpn-control] version metadata test passed")


if __name__ == "__main__":
    main()
