#!/usr/bin/env python3
"""Regression coverage for native-fixture SHA-256 manifest generation."""

import hashlib
from pathlib import Path
import tempfile

from native_fixture_manifest import _relative_name, verify_manifest, write_manifest


def manifest_entries(path: Path) -> dict[str, str]:
    return {
        name: digest
        for digest, name in (line.split("  ", 1) for line in path.read_text(encoding="utf-8").splitlines())
    }


def main() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        first = root / "alpha.bin"
        second = root / "nested" / "beta.bin"
        second.parent.mkdir()
        first.write_bytes(b"first contents")
        second.write_bytes(b"second contents")
        manifest = root / "SHA256SUMS.txt"
        manifest.write_text("0" * 64 + "  SHA256SUMS.txt\n", encoding="utf-8")

        write_manifest(root)
        first_generation = manifest.read_bytes()
        entries = manifest_entries(manifest)
        assert list(entries) == ["alpha.bin", "nested/beta.bin"]
        assert "SHA256SUMS.txt" not in entries
        assert entries["alpha.bin"] == hashlib.sha256(first.read_bytes()).hexdigest()
        assert entries["nested/beta.bin"] == hashlib.sha256(second.read_bytes()).hexdigest()
        verify_manifest(root, manifest)

        write_manifest(root)
        assert manifest.read_bytes() == first_generation

        second.write_bytes(b"changed contents")
        write_manifest(root)
        changed_entries = manifest_entries(manifest)
        assert changed_entries["alpha.bin"] == entries["alpha.bin"]
        assert changed_entries["nested/beta.bin"] != entries["nested/beta.bin"]
        assert changed_entries["nested/beta.bin"] == hashlib.sha256(second.read_bytes()).hexdigest()
        verify_manifest(root, manifest)

        try:
            _relative_name(root, root / "not\na-file")
        except ValueError as error:
            assert "newline" in str(error)
        else:
            raise AssertionError("newline filenames must be rejected")

        invalid_manifest = root / "invalid-SHA256SUMS.txt"
        for invalid_name in ("C:payload", r"nested\payload"):
            invalid_manifest.write_text("0" * 64 + f"  {invalid_name}\n", encoding="utf-8")
            try:
                verify_manifest(root, invalid_manifest)
            except ValueError as error:
                assert "Windows path syntax" in str(error)
            else:
                raise AssertionError("Windows manifest path syntax must be rejected")

        protected = root / "protected.bin"
        protected.write_bytes(b"must not be overwritten")
        linked_output = root / "linked-SHA256SUMS.txt"
        try:
            linked_output.symlink_to(protected)
        except OSError:
            pass
        else:
            try:
                write_manifest(root, linked_output)
            except ValueError as error:
                assert "symbolic links" in str(error)
            else:
                raise AssertionError("symbolic-link output must be rejected")
            assert protected.read_bytes() == b"must not be overwritten"

        protected_parent = root / "protected-parent"
        protected_parent.mkdir()
        protected_child = protected_parent / "SHA256SUMS.txt"
        protected_child.write_bytes(b"must not be overwritten through a parent link")
        linked_parent = root / "linked-parent"
        try:
            linked_parent.symlink_to(protected_parent, target_is_directory=True)
        except OSError:
            pass
        else:
            try:
                write_manifest(root, linked_parent / "SHA256SUMS.txt")
            except ValueError as error:
                assert "symbolic links" in str(error)
            else:
                raise AssertionError("symbolic-link output parent must be rejected")
            assert protected_child.read_bytes() == b"must not be overwritten through a parent link"
    print("[vpn-control] native fixture manifest test passed")


if __name__ == "__main__":
    main()
