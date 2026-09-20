#!/usr/bin/env python3
"""Opt-in syscall-fault checks of production macOS installer persistence.

The generated probe is compiled during ordinary macOS checks without executing it.
Fault scenarios run only in an explicitly assigned guest directory. Inputs are
inert files; one control mounts an 8 MiB task-owned sparse image. No application
replacement or authorization is performed.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import tempfile
import unittest


@unittest.skipUnless(platform.system() == "Darwin" and os.environ.get("VPN_CONTROL_MAC_INSTALL_ENOSPC_TEST_ROOT"),
                     "Requires an explicitly assigned macOS VM temporary directory")
class MacInstallEnospcTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent = Path(os.environ["VPN_CONTROL_MAC_INSTALL_ENOSPC_TEST_ROOT"]).resolve(strict=True)
        if parent.parent != Path("/private/tmp") or not parent.name.startswith("vpn-parity-"):
            raise ValueError("Requires a task-owned /private/tmp/vpn-parity-* directory")
        cls.fixture = tempfile.TemporaryDirectory(prefix="enospc-", dir=parent)
        cls.root = Path(cls.fixture.name)
        worker = Path(__file__).resolve().parent / "native/macos_install_worker.c"
        source = cls.root / "probe.c"
        source.write_text("#include <unistd.h>\n#include <copyfile.h>\n#include <limits.h>\n#include <pwd.h>\n"
                          "static ssize_t fault_write(int, const void *, size_t);\n"
                          "static int fault_copyfile(const char *, const char *, copyfile_state_t, copyfile_flags_t);\n"
                          "static int fixture_getpwuid_r(uid_t, struct passwd *, char *, size_t, struct passwd **);\n"
                          "#define write fault_write\n#define copyfile fault_copyfile\n#define getpwuid_r fixture_getpwuid_r\n"
                          "#define main packaged_worker_main\n#include " +
                          json.dumps(str(worker)) + "\n#undef main\n#undef getpwuid_r\n#undef copyfile\n#undef write\n" + r'''
static ssize_t remaining = -1;
static char fixture_home[PATH_MAX], copyfile_evidence[PATH_MAX];
static ssize_t fault_write(int fd, const void *bytes, size_t size) {
    if (remaining == 0) { errno = ENOSPC; return -1; }
    if (remaining > 0 && size > (size_t)remaining) size = (size_t)remaining;
    ssize_t result = write(fd, bytes, size);
    if (remaining > 0 && result > 0) remaining -= result;
    return result;
}
static int fixture_getpwuid_r(uid_t uid, struct passwd *password, char *buffer, size_t size, struct passwd **result) {
    (void)buffer; (void)size;
    if (uid != getuid()) return EINVAL;
    memset(password, 0, sizeof(*password)); password->pw_uid = uid; password->pw_dir = fixture_home;
    *result = password; return 0;
}
static void directory(const char *path) {
    if (mkdir(path, 0700) != 0) require(errno == EEXIST, "PERSISTENCE_FAILED");
    require(chmod(path, 0700) == 0, "PERSISTENCE_FAILED");
}
static void write_record(const char *path, const char *bytes, mode_t mode) {
    int fd = open(path, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, mode);
    require(fd >= 0 && fchmod(fd, mode) == 0, "PERSISTENCE_FAILED");
    write_all(fd, bytes, strlen(bytes)); require(fsync(fd) == 0 && close(fd) == 0, "PERSISTENCE_FAILED");
}
static int fault_copyfile(const char *source, const char *destination, copyfile_state_t state, copyfile_flags_t flags) {
    static unsigned calls;
    (void)source; (void)state; (void)flags;
    ++calls;
    int evidence = open(copyfile_evidence, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
    require(evidence >= 0 && calls == 1, "CONFLICT");
    write_all(evidence, "1", 1); require(fsync(evidence) == 0 && close(evidence) == 0, "PERSISTENCE_FAILED");
    directory(destination);
    char partial[PATH_MAX]; join(partial, sizeof(partial), destination, "partial"); write_record(partial, "partial", 0600);
    errno = EIO; return -1;
}
static void setup_fixture_home(const char *root) {
    snprintf(fixture_home, sizeof(fixture_home), "%s/home", root);
    char library[PATH_MAX], support[PATH_MAX];
    directory(fixture_home);
    join(library, sizeof(library), fixture_home, "Library"); directory(library);
    join(support, sizeof(support), library, "Application Support"); directory(support);
}
static void copyfile_eio_fixture(const char *root) {
    setup_fixture_home(root);
    struct request request = {0};
    request.owner.uid = getuid();
    text_copy(request.job, sizeof(request.job), "7e17453b-bc14-4c90-9e3c-05baf2c73841");
    text_copy(request.bundle, sizeof(request.bundle), "/Applications/inert-copyfile-eio-fixture.app");
    struct pins pins = {0}; int receipts = root_create(&request, &pins);
    struct receipt_writer writer = job_create(receipts, &request, &pins);
    int gate = gate_open(receipts, &request, &pins); gate_pending(gate, true);
    char library[PATH_MAX], support[PATH_MAX], inputs[PATH_MAX], input[PATH_MAX], path[PATH_MAX];
    join(library, sizeof(library), fixture_home, "Library");
    join(support, sizeof(support), library, "Application Support");
    join(inputs, sizeof(inputs), support, "vpn-control-install-inputs"); directory(inputs);
    join(input, sizeof(input), inputs, request.job); directory(input);
    snprintf(path, sizeof(path), "%s/request", input);
    char request_bytes[16384];
    int count = snprintf(request_bytes, sizeof(request_bytes),
        "1\n%s\nUSER_LOCAL\n1\n%u\n1\n0\n0\n0\n0\n1\n%s\n%s/package.dmg\n%s/inert.app/Contents/MacOS/vpn-control\n%s\n",
        request.job, (unsigned)getuid(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", input, fixture_home, root);
    require(count > 0 && (size_t)count < sizeof(request_bytes), "PERSISTENCE_FAILED");
    write_record(path, request_bytes, 0600);
    snprintf(path, sizeof(path), "%s/vpn-control-install-worker", input); write_record(path, "fixture", 0700);
    char applications[PATH_MAX], base[PATH_MAX], source[PATH_MAX], stage[PATH_MAX];
    join(applications, sizeof(applications), root, "applications"); directory(applications);
    join(base, sizeof(base), applications, "base.app"); directory(base);
    join(path, sizeof(path), base, "marker"); write_record(path, "base", 0600);
    int parent = open(applications, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); require(parent >= 0, "UNAVAILABLE"); retain(&pins, parent);
    int old_bundle = openat(parent, "base.app", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); require(old_bundle >= 0, "UNAVAILABLE"); retain(&pins, old_bundle);
    struct stat before; require(fstat(old_bundle, &before) == 0, "UNAVAILABLE");
    char identity[256]; int identity_size = snprintf(identity, sizeof(identity), "%llu %llu %u %u %u\n",
        (unsigned long long)before.st_dev, (unsigned long long)before.st_ino, (unsigned)before.st_uid,
        (unsigned)before.st_gid, (unsigned)(before.st_mode & 07777));
    require(identity_size > 0 && (size_t)identity_size < sizeof(identity), "PERSISTENCE_FAILED");
    snprintf(path, sizeof(path), "%s/base-before", root); write_record(path, identity, 0600);
    active = (struct transaction){.writer=&writer, .parent=parent, .old_bundle=old_bundle, .candidate=-1, .gate=gate, .executable=-1};
    text_copy(active.target, sizeof(active.target), "base.app");
    snprintf(active.stage, sizeof(active.stage), ".vpn-control-stage-%s.app", request.job);
    snprintf(active.backup, sizeof(active.backup), ".vpn-control-backup-%s.app", request.job);
    snprintf(stage, sizeof(stage), "%s/%s", applications, active.stage);
    snprintf(copyfile_evidence, sizeof(copyfile_evidence), "%s/copyfile-calls", root);
    failure_handler = transaction_failed;
    join(source, sizeof(source), root, "source.app");
    stage_bundle(source, stage, &active, getuid(), &pins);
    fail("CONFLICT");
}
int main(int argc, char **argv) {
    require(argc == 4, "INVALID_ARGUMENT");
    int root = open(argv[1], O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    require(root >= 0, "UNAVAILABLE");
    struct request request = {0};
    request.owner.uid = getuid();
    text_copy(request.bundle, sizeof(request.bundle), "/Applications/inert-enospc-fixture.app");
    text_copy(request.job, sizeof(request.job), "ecf69f90-9f10-4daf-a6bb-ecc9c1e7b881");
    struct pins pins = {0};
    if (!strcmp(argv[2], "copyfile-eio")) { copyfile_eio_fixture(argv[1]); return 9; }
    if (!strcmp(argv[2], "copyfile-cleanup")) {
        setup_fixture_home(argv[1]); cleanup_input("7e17453b-bc14-4c90-9e3c-05baf2c73841", true); return 0;
    }
    int gate = gate_open(root, &request, &pins);
    if (!strcmp(argv[2], "retry")) return 9;
    gate_pending(gate, true);
    struct receipt_writer writer = job_create(root, &request, &pins);
    if (!strcmp(argv[2], "staging")) {
        /* Model the real coordinator after staging fails with ENOSPC: its
           transaction failure path must still replace PREPARING with a
           terminal receipt.  The exhausted status write is intentionally
           performed by the production publish() implementation. */
        active = (struct transaction){.writer=&writer, .parent=-1, .old_bundle=-1,
            .candidate=-1, .gate=-1, .executable=-1};
        failure_handler = transaction_failed;
        remaining = 0;
        fail("PERSISTENCE_FAILED");
    }
    if (!strcmp(argv[2], "staging-volume")) {
        /* This uses the actual filesystem rather than the syscall interposer.
           The caller supplies a tiny task-owned image, so filling it cannot
           consume guest capacity outside the fixture. */
        int filler = openat(root, "fixture-fill", O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
        require(filler >= 0, "UNAVAILABLE");
        unsigned char bytes[65536] = {0};
        while (write(filler, bytes, sizeof(bytes)) > 0) {}
        require(errno == ENOSPC && close(filler) == 0, "UNAVAILABLE");
        active = (struct transaction){.writer=&writer, .parent=-1, .old_bundle=-1,
            .candidate=-1, .gate=-1, .executable=-1};
        failure_handler = transaction_failed;
        fail("PERSISTENCE_FAILED");
    }
    remaining = !strcmp(argv[2], "clean") ? -1 : 8;
    if (!strcmp(argv[2], "package")) {
        request.package_size = 32;
        text_copy(request.sha256, sizeof(request.sha256), argv[3]);
        package_capture(root, &request, &writer, gate);
    }
    publish(&writer, "SUCCEEDED", "OK");
    release(&pins); close(root);
    return 0;
}
''', encoding="utf-8")
        cls.probe = cls.root / "probe"
        compile_probe = subprocess.run(
            ["xcrun", "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-Wno-deprecated-declarations", "-framework", "CoreFoundation", str(source),
             "-o", str(cls.probe)],
            capture_output=True, text=True,
        )
        if compile_probe.returncode:
            raise RuntimeError(
                "macOS installer ENOSPC probe compilation failed:\n"
                f"stdout:\n{compile_probe.stdout}\n"
                f"stderr:\n{compile_probe.stderr}"
            )

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def run_probe(self, root, mode):
        return subprocess.run([str(self.probe), str(root), mode, hashlib.sha256(b"x" * 32).hexdigest()],
                              capture_output=True, text=True, timeout=10)

    def check_fault(self, mode):
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            (root / "package.dmg").write_bytes(b"x" * 32)
            (root / "package.dmg").chmod(0o600)
            result = self.run_probe(root, mode)
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertEqual("PERSISTENCE_FAILED\n", result.stderr)
            receipt = json.loads(next(root.glob("*/status.json")).read_text())
            self.assertEqual("PREPARING", receipt["phase"])
            self.assertEqual(0, receipt["sequence"])
            self.assertEqual("OK", receipt["code"])
            if mode == "package":
                self.assertEqual(b"x" * 8, next(root.glob("*/package.dmg")).read_bytes())
            else:
                self.assertEqual(8, next(root.glob("*/status-*.tmp")).stat().st_size)
            retry = self.run_probe(root, "retry")
            self.assertEqual(2, retry.returncode, retry.stderr)
            self.assertEqual("BUSY\n", retry.stderr)
            self.assertEqual(receipt, json.loads(next(root.glob("*/status.json")).read_text()))

    def test_partial_receipt_write_preserves_preparing_and_blocks_replay(self):
        self.check_fault("receipt")

    def test_partial_package_capture_preserves_preparing_and_blocks_replay(self):
        self.check_fault("package")

    def test_staging_enospc_preserves_preparing_when_terminal_publication_cannot_persist(self):
        """Total persistence loss leaves the authoritative PREPARING receipt intact."""
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            result = self.run_probe(root, "staging")
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertEqual("PERSISTENCE_FAILED\n", result.stderr)
            receipt = json.loads(next(root.glob("*/status.json")).read_text())
            self.assertEqual("PREPARING", receipt["phase"])
            self.assertEqual(0, receipt["sequence"])
            self.assertEqual("OK", receipt["code"])
            temporary = next(root.glob("*/status-*.tmp"))
            self.assertEqual(0, temporary.stat().st_size)

    def test_actual_small_volume_staging_enospc_must_publish_terminal_failure(self):
        """Exercise bounded Darwin ENOSPC with space for terminal receipt metadata."""
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            fixture = Path(temporary)
            image = fixture / "staging.sparseimage"
            mount = fixture / "mount"
            mount.mkdir(mode=0o700)
            subprocess.run(["hdiutil", "create", "-size", "8m", "-fs", "HFS+", "-volname", "vpn-parity-enospc",
                            "-type", "SPARSE", str(image)], check=True, capture_output=True, text=True)
            subprocess.run(["hdiutil", "attach", "-nobrowse", "-mountpoint", str(mount), str(image)],
                           check=True, capture_output=True, text=True)
            try:
                result = self.run_probe(mount, "staging-volume")
                self.assertEqual(2, result.returncode, result.stderr)
                self.assertEqual("PERSISTENCE_FAILED\n", result.stderr)
                receipt = json.loads(next(mount.glob("*/status.json")).read_text())
                self.assertEqual("FAILED", receipt["phase"])
                self.assertEqual(1, receipt["sequence"])
                self.assertEqual("PERSISTENCE_FAILED", receipt["code"])
            finally:
                subprocess.run(["hdiutil", "detach", str(mount)], check=True, capture_output=True, text=True)

    def test_copyfile_eio_at_production_staging_helper_preserves_terminal_failure_evidence(self):
        """The production staging helper must publish failed, never rename, and retain evidence."""
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            production = (Path(__file__).resolve().parent / "native/macos_install_worker.c").read_text()
            self.assertIn("stage_bundle(source, stage, &active, authority, &pins);", production,
                          "coordinator must use the faulted production staging helper")
            self.assertIn("require(copyfile(source, stage, NULL, COPYFILE_ALL|COPYFILE_RECURSIVE|COPYFILE_NOFOLLOW|COPYFILE_EXCL) == 0, \"PERSISTENCE_FAILED\");",
                          production, "the EIO boundary must remain a terminal persistence failure")
            result = self.run_probe(root, "copyfile-eio")
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertEqual("PERSISTENCE_FAILED\n", result.stderr)
            self.assertEqual(b"1", (root / "copyfile-calls").read_bytes(), "one injected EIO at the helper boundary")
            job = "7e17453b-bc14-4c90-9e3c-05baf2c73841"
            receipt = root / "home/Library/Application Support/vpn-control-install-jobs" / job / "status.json"
            self.assertEqual({"version": 1, "jobId": job, "sequence": 1,
                              "phase": "FAILED", "code": "PERSISTENCE_FAILED"}, json.loads(receipt.read_text()))
            applications = root / "applications"
            base = applications / "base.app"
            self.assertEqual(b"base", (base / "marker").read_bytes())
            before_identity = tuple(map(int, (root / "base-before").read_text().split()))
            base_stat = base.stat()
            self.assertEqual(before_identity, (base_stat.st_dev, base_stat.st_ino, base_stat.st_uid,
                                               base_stat.st_gid, stat.S_IMODE(base_stat.st_mode)))
            self.assertFalse((applications / f".vpn-control-backup-{job}.app").exists())
            stage = applications / f".vpn-control-stage-{job}.app"
            self.assertEqual(b"partial", (stage / "partial").read_bytes())
            gate = next((root / "home/Library/Application Support/vpn-control-install-jobs").glob("gate-*"))
            self.assertEqual(0, gate.read_bytes()[8], "failure releases the pending admission gate")
            input_directory = root / "home/Library/Application Support/vpn-control-install-inputs" / job
            self.assertTrue(input_directory.is_dir())
            receipt_bytes = receipt.read_bytes()
            receipt_stat = receipt.stat()
            receipt_identity = (receipt_stat.st_dev, receipt_stat.st_ino, receipt_stat.st_uid,
                                receipt_stat.st_gid, stat.S_IMODE(receipt_stat.st_mode))
            cleanup = self.run_probe(root, "copyfile-cleanup")
            self.assertEqual(0, cleanup.returncode, cleanup.stderr)
            self.assertFalse(input_directory.exists())
            self.assertEqual(receipt_bytes, receipt.read_bytes())
            after_receipt = receipt.stat()
            self.assertEqual(receipt_identity, (after_receipt.st_dev, after_receipt.st_ino, after_receipt.st_uid,
                                                after_receipt.st_gid, stat.S_IMODE(after_receipt.st_mode)))
            self.assertEqual("FAILED", json.loads(receipt.read_text())["phase"])
            self.assertEqual(b"base", (base / "marker").read_bytes())
            self.assertEqual(b"partial", (stage / "partial").read_bytes())

    def test_same_publication_path_succeeds_without_fault(self):
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            result = self.run_probe(root, "clean")
            self.assertEqual(0, result.returncode, result.stderr)
            receipt = json.loads(next(root.glob("*/status.json")).read_text())
            self.assertEqual("SUCCEEDED", receipt["phase"])
            self.assertEqual(1, receipt["sequence"])


@unittest.skipUnless(platform.system() == "Darwin", "Requires the macOS compiler")
class MacInstallEnospcProbeCompileTest(unittest.TestCase):
    def test_fault_injection_probe_compiles_without_an_installer_fixture(self):
        """Keep the generated probe in ordinary macOS pre-push checks without mounting a volume."""
        previous_root = os.environ.get("VPN_CONTROL_MAC_INSTALL_ENOSPC_TEST_ROOT")
        with tempfile.TemporaryDirectory(prefix="vpn-parity-compile-", dir="/private/tmp") as parent:
            os.environ["VPN_CONTROL_MAC_INSTALL_ENOSPC_TEST_ROOT"] = parent
            try:
                MacInstallEnospcTest.setUpClass()
                self.assertTrue(MacInstallEnospcTest.probe.is_file())
            finally:
                fixture = getattr(MacInstallEnospcTest, "fixture", None)
                if fixture is not None:
                    MacInstallEnospcTest.tearDownClass()
                    delattr(MacInstallEnospcTest, "fixture")
                if previous_root is None:
                    del os.environ["VPN_CONTROL_MAC_INSTALL_ENOSPC_TEST_ROOT"]
                else:
                    os.environ["VPN_CONTROL_MAC_INSTALL_ENOSPC_TEST_ROOT"] = previous_root


if __name__ == "__main__":
    unittest.main()
