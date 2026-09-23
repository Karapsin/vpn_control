import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import subprocess
import threading
import unittest

from linux_vpn_fixture_guard import (
    FixtureGuardError,
    evaluate_runtime_binary,
    main,
    parse_findmnt_json,
    require_runtime_capabilities,
    fixture_http_probe_arguments,
)


class Completed:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class LinuxVpnFixtureGuardTest(unittest.TestCase):
    def test_retained_nosuid_getcap_case_is_rejected_before_native_vpn_start(self):
        # Captured CP120 failure shape: getcap reports both capabilities, but the
        # per-state runtime was extracted beneath /tmp, a nosuid tmpfs.
        binary = Path("/tmp/vpn-cp120-vpn126-aa9b1139/state/runtime/tools/sing-box")
        findmnt = json.dumps({"filesystems": [{
            "target": "/tmp", "source": "tmpfs", "fstype": "tmpfs",
            "options": "rw,nosuid,nodev,seclabel",
        }]})
        calls = []

        def run(args, **_kwargs):
            calls.append(args)
            if args[0] == "findmnt":
                return Completed(stdout=findmnt)
            return Completed(stdout=f"{binary} cap_net_admin,cap_net_raw=ep\n")

        with self.assertRaisesRegex(FixtureGuardError, "nosuid"):
            evaluate_runtime_binary(binary, run=run)
        self.assertEqual("findmnt", calls[0][0])
        self.assertEqual("getcap", calls[1][0])

    def test_well_formed_getcap_for_another_file_is_rejected(self):
        binary = Path("/home/vpnfixture/runtime/tools/sing-box")
        with self.assertRaisesRegex(FixtureGuardError, "different binary"):
            require_runtime_capabilities(
                "/home/vpnfixture/other/sing-box cap_net_admin,cap_net_raw=ep\n", binary,
            )

    def test_home_backed_mount_and_effective_capabilities_pass(self):
        binary = Path("/home/vpnfixture/.vpn-control-desktop/runtime/tools/sing-box")
        findmnt = json.dumps({"filesystems": [{
            "target": "/home", "source": "/dev/vda3[/home]", "fstype": "btrfs",
            "options": "rw,relatime,seclabel,compress=zstd:1",
        }]})

        def run(args, **_kwargs):
            if args[0] == "findmnt":
                return Completed(stdout=findmnt)
            return Completed(stdout=f"{binary} cap_net_admin,cap_net_raw=ep\n")

        result = evaluate_runtime_binary(binary, run=run)
        self.assertEqual("/home", result["mount"]["target"])
        self.assertEqual(["cap_net_admin", "cap_net_raw"], result["capabilities"])

    def test_malformed_or_unavailable_mount_evidence_is_rejected(self):
        with self.assertRaisesRegex(FixtureGuardError, "valid JSON"):
            parse_findmnt_json("not-json")
        with self.assertRaisesRegex(FixtureGuardError, "exactly one"):
            parse_findmnt_json(json.dumps({"filesystems": []}))
        with self.assertRaisesRegex(FixtureGuardError, "options"):
            parse_findmnt_json(json.dumps({"filesystems": [{
                "target": "/home", "source": "/dev/vda3", "fstype": "btrfs", "options": "",
            }]}))

    def test_noexec_mount_and_ineffective_or_missing_capabilities_are_rejected(self):
        with self.assertRaisesRegex(FixtureGuardError, "noexec"):
            parse_findmnt_json(json.dumps({"filesystems": [{
                "target": "/workspace", "source": "tmpfs", "fstype": "tmpfs", "options": "rw,noexec",
            }]}))
        binary = Path("/home/vpnfixture/runtime/tools/sing-box")
        with self.assertRaisesRegex(FixtureGuardError, "effective"):
            require_runtime_capabilities(f"{binary} cap_net_admin,cap_net_raw=p\n", binary)
        with self.assertRaisesRegex(FixtureGuardError, "cap_net_raw"):
            require_runtime_capabilities(f"{binary} cap_net_admin=ep\n", binary)

    def test_dns_free_probe_builder_and_local_http_fixture_preserve_fixture_host(self):
        observed = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                observed.append(self.headers.get("Host"))
                self.send_response(204)
                self.end_headers()
            def log_message(self, _format, *_args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            port = server.server_address[1]
            arguments = fixture_http_probe_arguments(port=port, resolved_address="127.0.0.1")
            result = subprocess.run(arguments, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual([f"fixture.invalid:{port}"], observed)
        finally:
            server.shutdown()
            worker.join(5)
            server.server_close()

    def test_dns_free_probe_builder_keeps_tun_and_test_net_inputs_explicit(self):
        arguments = fixture_http_probe_arguments(
            port=80, resolved_address="198.51.100.1", interface="vpn-control",
        )
        self.assertEqual(["--interface", "vpn-control"], arguments[7:9])
        self.assertIn("fixture.invalid:80:198.51.100.1", arguments)
        self.assertEqual("http://fixture.invalid:80/", arguments[-1])

    def test_cli_writes_machine_readable_failure_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "sing-box"
            binary.write_bytes(b"fixture")
            receipt = Path(directory) / "guard.json"
            def run(args, **_kwargs):
                if args[0] == "findmnt":
                    return Completed(stdout=json.dumps({"filesystems": [{
                        "target": "/tmp", "source": "tmpfs", "fstype": "tmpfs", "options": "rw,nosuid",
                    }]}))
                return Completed(stdout=f"{binary} cap_net_admin,cap_net_raw=ep\n")
            code = main(["--binary", str(binary), "--receipt", str(receipt)], run=run)
            self.assertEqual(1, code)
            data = json.loads(receipt.read_text())
            self.assertFalse(data["ok"])
            self.assertIn("nosuid", data["error"])



if __name__ == "__main__":
    unittest.main()
