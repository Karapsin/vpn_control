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
    assert version_metadata.parse_version("0.1.7.3") == (0, 1, 7, 3)
    assert version_metadata.build_number((0, 1, 7, 3)) == 543
    assert version_metadata.desktop_package_version((0, 1, 7, 3)) == "0.1.143"
    assert version_metadata.macos_package_version((0, 1, 7, 3)) == "1.1.143"
    for invalid in ("0.1.2", "0.1.2.x", "0.1.2.20"):
        try:
            version_metadata.parse_version(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid version: {invalid}")

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "gradle.properties").write_text("vpnControlVersion=0.1.7.3\n", encoding="utf-8")
        assert version_metadata.metadata(root) == {
            "version": "0.1.7.3",
            "build-number": "543",
            "desktop-package-version": "0.1.143",
            "macos-package-version": "1.1.143",
            "tag": "v0.1.7.3",
        }
    print("[vpn-control] version metadata test passed")


if __name__ == "__main__":
    main()
