#!/usr/bin/env python3
"""Opt-in syscall-fault checks of production macOS installer persistence.

Runs only in an explicitly assigned guest directory. No application, installer,
mount, authorization, or host storage is used; all inputs are tiny inert files.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
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
        source.write_text("#include <unistd.h>\nstatic ssize_t fault_write(int, const void *, size_t);\n"
                          "#define write fault_write\n#define main packaged_worker_main\n#include " +
                          json.dumps(str(worker)) + "\n#undef main\n#undef write\n" + r'''
static ssize_t remaining = -1;
static ssize_t fault_write(int fd, const void *bytes, size_t size) {
    if (remaining == 0) { errno = ENOSPC; return -1; }
    if (remaining > 0 && size > (size_t)remaining) size = (size_t)remaining;
    ssize_t result = write(fd, bytes, size);
    if (remaining > 0 && result > 0) remaining -= result;
    return result;
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
    int gate = gate_open(root, &request, &pins);
    if (!strcmp(argv[2], "retry")) return 9;
    gate_pending(gate, true);
    struct receipt_writer writer = job_create(root, &request, &pins);
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
        subprocess.run(["xcrun", "clang", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-Wno-deprecated-declarations", "-framework", "CoreFoundation", str(source),
                        "-o", str(cls.probe)], check=True, capture_output=True, text=True)

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

    def test_same_publication_path_succeeds_without_fault(self):
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            result = self.run_probe(root, "clean")
            self.assertEqual(0, result.returncode, result.stderr)
            receipt = json.loads(next(root.glob("*/status.json")).read_text())
            self.assertEqual("SUCCEEDED", receipt["phase"])
            self.assertEqual(1, receipt["sequence"])


if __name__ == "__main__":
    unittest.main()
