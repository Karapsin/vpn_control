import errno
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from fixture_environment import extract_readonly_archive, require_jdk17, validate_qemu_argv


def symlink_probe_available(directory):
    target = directory / "symlink-probe-target"
    link = directory / "symlink-probe-link"
    target.mkdir()
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        unsupported = (os.name == "nt" and getattr(error, "winerror", None) == 1314) or error.errno in {
            errno.EACCES, errno.EPERM, errno.ENOSYS, errno.EOPNOTSUPP,
        }
        if unsupported:
            return False
        raise
    else:
        link.unlink()
        return True

class FixtureEnvironmentTest(unittest.TestCase):
    def test_symlink_probe_classifies_only_known_unavailable_cases(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as second:
            root = Path(temporary)
            with mock.patch.object(Path, "symlink_to", side_effect=OSError(errno.EPERM, "denied")):
                self.assertFalse(symlink_probe_available(root))
            with mock.patch.object(Path, "symlink_to", side_effect=OSError(errno.EIO, "I/O failure")):
                with self.assertRaises(OSError):
                    symlink_probe_available(Path(second))

    def test_java26_is_rejected_and_jdk17_is_accepted(self):
        runner = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr='openjdk version "26.0.2.1"\n'))
        with self.assertRaisesRegex(ValueError, "JDK 17"):
            require_jdk17(runner=runner)
        runner = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr='openjdk version "17.0.20"\n'))
        self.assertIn("17.0.20", require_jdk17(runner=runner))
    def test_java_home_controls_effective_gradle_jvm(self):
        runner = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr='openjdk version "26.0.2"\n'))
        with self.assertRaisesRegex(ValueError, "JDK 17"):
            require_jdk17(runner=runner, environment={"JAVA_HOME": "/jdk26"})
        executable = "java.exe" if os.name == "nt" else "java"
        self.assertEqual([str(Path("/jdk26") / "bin" / executable), "-version"], runner.call_args.args[0])

    def test_qemu_serial_requires_file_colon(self):
        with self.assertRaisesRegex(ValueError, "file:"):
            validate_qemu_argv(["qemu", "-serial", "file=x"])
        validate_qemu_argv(["qemu", "-serial", "file:x"])

    def test_old_extractall_signature_is_red_but_safe_extraction_remains_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"; source.mkdir(); (source / "child").write_text("ok")
            archive = root / "fixture.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(source, arcname="source")
            original = tarfile.TarFile.extractall

            def old_extractall(self, path=".", members=None, *, numeric_owner=False):
                return original(self, path, members, numeric_owner=numeric_owner)

            with mock.patch.object(tarfile.TarFile, "extractall", old_extractall):
                with tarfile.open(archive, "r:gz") as bundle, self.assertRaises(TypeError):
                    bundle.extractall(root / "old", filter=lambda member, path: member)
                extract_readonly_archive(archive, root / "new")
            self.assertEqual("ok", (root / "new/source/child").read_text())

    def test_archive_rejects_path_escape_and_unsafe_links(self):
        def archive_with(member):
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            archive = Path(temporary.name) / "fixture.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                if member.isfile():
                    import io
                    bundle.addfile(member, io.BytesIO(b"unsafe"))
                else:
                    bundle.addfile(member)
            return archive, Path(temporary.name)

        escaped = tarfile.TarInfo("../outside")
        escaped.size = len(b"unsafe")
        archive, root = archive_with(escaped)
        with self.assertRaisesRegex(ValueError, "path"):
            extract_readonly_archive(archive, root / "out")

    def test_archive_rejects_symlink_chain_escape_cycles_aliases_and_descendants(self):
        def archive_with(members):
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            archive = Path(temporary.name) / "fixture.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                for member in members:
                    if member.isfile():
                        import io
                        bundle.addfile(member, io.BytesIO(b"unsafe"))
                    else:
                        bundle.addfile(member)
            return archive, Path(temporary.name)

        a = tarfile.TarInfo("source/a"); a.type = tarfile.SYMTYPE; a.linkname = ".."
        b = tarfile.TarInfo("source/b"); b.type = tarfile.SYMTYPE; b.linkname = "A/../outside"
        archive, root = archive_with((a, b))
        # RED for lexical-only checking: this spelling appears below root before
        # source/a is expanded, but resolves outside after the link chain.
        self.assertEqual(str(root / "out/source/outside"),
                         os.path.normpath(str(root / "out/source/a/../outside")))
        with self.assertRaisesRegex(ValueError, "escapes"):
            extract_readonly_archive(archive, root / "out")
        cycle_a = tarfile.TarInfo("source/a"); cycle_a.type = tarfile.SYMTYPE; cycle_a.linkname = "b"
        cycle_b = tarfile.TarInfo("source/b"); cycle_b.type = tarfile.SYMTYPE; cycle_b.linkname = "a"
        alias = tarfile.TarInfo("source/./alias"); alias.size = len(b"unsafe")
        drive = tarfile.TarInfo("C:drive"); drive.size = len(b"unsafe")
        dot_alias = tarfile.TarInfo("source/name."); dot_alias.size = len(b"unsafe")
        space_alias = tarfile.TarInfo("source/name "); space_alias.size = len(b"unsafe")
        descendant = tarfile.TarInfo("source/a/child"); descendant.size = len(b"unsafe")
        for members, message in (((cycle_a, cycle_b), "cycle"), ((alias,), "path"), ((drive,), "path"),
                                 ((dot_alias,), "path"), ((space_alias,), "path"), ((a, descendant), "below")):
            archive, root = archive_with(members)
            with self.assertRaisesRegex(ValueError, message):
                extract_readonly_archive(archive, root / "out")

    def test_archive_preserves_safe_relative_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if not symlink_probe_available(root):
                self.skipTest("ordinary user cannot create fixture symlinks")
            archive = root / "fixture.tar.gz"
            child = tarfile.TarInfo("source/child")
            child.size = len(b"ok")
            link = tarfile.TarInfo("source/link")
            link.type = tarfile.SYMTYPE
            link.linkname = "child"
            broken = tarfile.TarInfo("source/broken")
            broken.type = tarfile.SYMTYPE
            broken.linkname = "missing-internal-target"
            import io
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.addfile(child, io.BytesIO(b"ok"))
                bundle.addfile(link)
                bundle.addfile(broken)
            extract_readonly_archive(archive, root / "out")
            self.assertTrue((root / "out/source/link").is_symlink())
            self.assertEqual("child", os.readlink(root / "out/source/link"))
            self.assertTrue((root / "out/source/broken").is_symlink())
            self.assertEqual("missing-internal-target", os.readlink(root / "out/source/broken"))
if __name__ == "__main__": unittest.main()
