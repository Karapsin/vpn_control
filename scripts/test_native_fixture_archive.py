#!/usr/bin/env python3
"""Regression coverage for archive metadata and restoration verification."""

import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile

from native_fixture_archive import archive_header_entries, compare_archive_headers, compare_manifests, load_manifest, manifest_tree


def entry(rel, kind, mode, size=0, **more):
    return {"rel": rel, "type": kind, "mode": mode, "size": size, **more}


def write_manifest(path: Path, entries):
    path.write_text(json.dumps({"schema": 1, "entries": entries}), encoding="utf-8")


def main() -> None:
    digest = hashlib.sha256(b"contents").hexdigest()
    source = [entry("fixture", "directory", "755", 512), entry("fixture/run", "file", "755", 8, sha256=digest)]
    restored = [entry("fixture", "directory", "755", 4096), entry("fixture/run", "file", "755", 8, sha256=digest)]
    assert not compare_manifests({item["rel"]: item for item in source}, {item["rel"]: item for item in restored})

    mode_lost = [entry("fixture", "directory", "700", 4096), entry("fixture/run", "file", "600", 8, sha256=digest)]
    failure = compare_manifests({item["rel"]: item for item in source}, {item["rel"]: item for item in mode_lost})
    assert failure == ["metadata mismatch: fixture", "metadata mismatch: fixture/run"]

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        manifest = root / "source.json"
        write_manifest(manifest, source)
        assert load_manifest(str(manifest))["fixture/run"]["sha256"] == digest
        tree = root / "fixture"
        tree.mkdir()
        executable = tree / "run"
        executable.write_bytes(b"contents")
        executable.chmod(0o755)
        generated = manifest_tree(tree)
        generated_entries = {item["rel"]: item for item in generated["entries"]}
        # Build the expected values from this filesystem rather than assuming POSIX defaults.
        filesystem_source = [
            entry(tree.name, "directory", f"{stat.S_IMODE(tree.lstat().st_mode):03o}", tree.lstat().st_size),
            entry(f"{tree.name}/run", "file", f"{stat.S_IMODE(executable.lstat().st_mode):03o}", executable.lstat().st_size, sha256=digest),
        ]
        assert not compare_manifests({item["rel"]: item for item in filesystem_source}, generated_entries)
        generated_size_changed = {name: dict(item) for name, item in generated_entries.items()}
        generated_size_changed[tree.name]["size"] += 1
        assert not compare_manifests(generated_entries, generated_size_changed)

        linked_root = root / "linked-fixture"
        try:
            linked_root.symlink_to(tree, target_is_directory=True)
        except OSError:
            pass
        else:
            try:
                manifest_tree(linked_root)
            except ValueError as error:
                assert "real directory" in str(error)
            else:
                raise AssertionError("symbolic-link manifest roots must be rejected")

        malformed = root / "malformed.json"
        for unsafe_path in ("fixture/./run", "fixture//run"):
            write_manifest(malformed, [entry(unsafe_path, "file", "755", 8, sha256=digest)])
            try:
                load_manifest(str(malformed))
            except ValueError as error:
                assert "unsafe" in str(error)
            else:
                raise AssertionError("lexically normalized manifest paths must be rejected")
        archive_path = root / "fixture.tar"
        with tarfile.open(archive_path, "w") as archive:
            directory = tarfile.TarInfo("fixture/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
            file_entry = tarfile.TarInfo("fixture/run")
            file_entry.mode = 0o755
            file_entry.size = 8
            archive.addfile(file_entry, io.BytesIO(b"contents"))
        assert not compare_archive_headers(load_manifest(str(manifest)), archive_header_entries(str(archive_path)))

        hardlink_source = [*source, entry("fixture/copy", "file", "755", 8, sha256=digest)]
        write_manifest(manifest, hardlink_source)
        with tarfile.open(archive_path, "w") as archive:
            directory = tarfile.TarInfo("fixture/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
            file_entry = tarfile.TarInfo("fixture/run")
            file_entry.mode = 0o755
            file_entry.size = 8
            archive.addfile(file_entry, io.BytesIO(b"contents"))
            copy = tarfile.TarInfo("fixture/copy")
            copy.type = tarfile.LNKTYPE
            copy.linkname = "fixture/run"
            copy.mode = 0o755
            archive.addfile(copy)
        assert not compare_archive_headers(load_manifest(str(manifest)), archive_header_entries(str(archive_path)))

        with tarfile.open(archive_path, "w") as archive:
            special = tarfile.TarInfo("fixture/run")
            special.mode = 0o4755
            special.size = 8
            archive.addfile(special, io.BytesIO(b"contents"))
        try:
            archive_header_entries(str(archive_path))
        except ValueError as error:
            assert "special mode bits" in str(error)
        else:
            raise AssertionError("special tar mode bits must be rejected")

        with tarfile.open(archive_path, "w") as archive:
            directory = tarfile.TarInfo("fixture/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
            file_entry = tarfile.TarInfo("fixture/run")
            file_entry.mode = 0o600
            file_entry.size = 8
            archive.addfile(file_entry, io.BytesIO(b"contents"))
        write_manifest(manifest, source)
        assert compare_archive_headers(load_manifest(str(manifest)), archive_header_entries(str(archive_path))) == ["archive header mismatch: fixture/run"]

    link = entry("fixture/link", "symlink", "777", 4, target="run")
    changed_link = dict(link, size=5)
    assert compare_manifests({link["rel"]: link}, {changed_link["rel"]: changed_link}) == ["metadata mismatch: fixture/link"]

    print("[vpn-control] native fixture archive test passed")


if __name__ == "__main__":
    main()
