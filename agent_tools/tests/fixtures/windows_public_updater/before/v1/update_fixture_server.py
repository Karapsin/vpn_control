"""Private finite Windows HTTPS update fixture, using the current staged helpers.

This adapter adds only three named asset responses: exact, paced, and one corrupt
byte. It never changes the signed/immutable target manifest, production trust,
global proxy, certificate stores or source. The server is an owned thread in the
original ordinary Owner, not a detached replayable process.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socketserver
import ssl
import threading
import time
import uuid


def require(condition, code):
    if not condition:
        raise ValueError(code)


def write_asset(stream, path, asset, mode):
    require(mode in {"exact", "paced", "checksum-corrupt"}, "finite-update-response")
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        length = os.fstat(source.fileno()).st_size
        require(length == asset["sizeBytes"] and length > 0, "frozen-update-asset-length")
        for block in iter(lambda: source.read(131072), b""):
            digest.update(block)
        require(digest.hexdigest() == asset["sha256"], "frozen-update-asset-hash")
        source.seek(0)
        stream.sendall((f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").encode())
        first = True
        for block in iter(lambda: source.read(65536), b""):
            if first and mode == "checksum-corrupt":
                block = bytes((block[0] ^ 1,)) + block[1:]
            first = False
            stream.sendall(block)
            if mode == "paced":
                time.sleep(0.025)
    return length


class UpdateFixture:
    def __init__(self, owner, prepared, inputs, mode):
        self.owner, self.prepared, self.inputs, self.mode = owner, prepared, inputs, mode
        self.closed, self.errors, self.records = False, [], []
        require(mode in {"exact", "paced", "checksum-corrupt"}, "finite-update-response")
        content, state = Path(inputs["content"]), Path(inputs["state"])
        root_name = "mcp-update-fixture-" + str(uuid.UUID(inputs["fixtureId"]))
        require(content.name == "content" and content.parent.name == root_name
                and state == content.parent / "server-state" and state.is_dir()
                and not state.is_symlink() and not any(state.iterdir()), "fresh-owned-update-fixture-layout")
        recipient = prepared.require_windows_private_acl(content, private=False, directory=True)
        require(prepared.require_windows_private_acl(state, private=True, directory=True, establish=False)
                == recipient == owner.request["context"]["ordinarySid"], "same-ordinary-fixture-recipient")
        for name in ("certificate", "privateKey", "trustStore"):
            require(inputs[name].casefold() in owner.by_path, "held-update-tls-input")
        owner.guard()
        receipt_path = content / "fixture-receipt.json"
        require(str(receipt_path).casefold() in owner.by_path, "held-source-package-fixture-receipt")
        receipt_bytes = owner.by_path[str(receipt_path).casefold()].digest(True)
        self.manifest, self.resources = prepared.load_resources(content, receipt_bytes=receipt_bytes)
        require(len(self.manifest["assets"]) == 1 and self.manifest["assets"][0]["platform"] == "windows"
                and self.manifest["assets"][0]["packageType"] == "msi"
                and self.manifest["assets"][0]["architecture"] == "x86_64", "one-current-windows-msi-resource")
        for path in self.resources.values():
            require(str(path).casefold() in owner.by_path, "held-frozen-target-package")
        body = json.dumps(self.manifest, separators=(",", ":")).encode()
        prepared.require_fixture_certificate_current(Path(inputs["certificate"]))
        certificate_sha = prepared.probe_certificate_sha256(Path(inputs["certificate"]))
        require(certificate_sha == inputs["certificateSha256"], "exact-current-update-certificate")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(inputs["certificate"], inputs["privateKey"])
        require(prepared.probe_certificate_sha256(Path(inputs["certificate"])) == certificate_sha,
                "update-certificate-chain-closing")
        prepared.probe_events_path(state)
        instance = str(uuid.uuid4())
        fixture = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                tls = None
                stage = "connect-admission"
                try:
                    self.request.settimeout(30)
                    method, target, host = prepared.read_request_header(self.request)
                    require(method == "CONNECT" and target.lower() == "github.com:443"
                            and host.lower() in {"github.com", "github.com:443"}, "exact-fixture-connect")
                    self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    stage = "tls-handshake"
                    tls = context.wrap_socket(self.request, server_side=True)
                    stage = "tunneled-get"
                    method, target, host, probes = prepared.read_request_header(tls, include_probe=True)
                    resource = prepared.select_resource(method, target, host, fixture.manifest)
                    require(resource is not None, "exact-fixture-resource")
                    if probes:
                        require(len(probes) == 1 and resource == "manifest" and target == prepared.MANIFEST_PATH,
                                "exact-fixture-probe")
                        event = prepared.claim_probe_event(state, probes[0])
                    if resource == "manifest":
                        count = prepared.write_resource_response(tls, resource, fixture.manifest,
                                                                 fixture.resources, body)
                    else:
                        asset = next(x for x in fixture.manifest["assets"] if x["fileName"] == resource)
                        count = write_asset(tls, fixture.resources[resource], asset, fixture.mode)
                    if probes:
                        prepared.write_probe_event(event, probes[0], body, certificate_sha, instance)
                    fixture.records.append({"resource": resource, "sizeBytes": count, "mode": fixture.mode})
                except (OSError, EOFError, ValueError) as error:
                    # A cancelled download normally closes its socket. Preserve
                    # the actual type and stage; never reinterpret it as success.
                    fixture.errors.append(prepared.fixture_failure_diagnostic(stage, error))
                finally:
                    if tls is not None:
                        tls.close()

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = False
            block_on_close = True
            allow_reuse_address = False

        self.server = Server(("127.0.0.1", 0), Handler)
        identity = prepared.server_process_identity()
        self.ready = {"port": self.server.server_address[1], "serverInstanceId": instance,
            **identity, "sourceFingerprint": json.loads(receipt_bytes)["sourceFingerprint"],
            "fixtureReceiptSha256": hashlib.sha256(receipt_bytes).hexdigest(),
            "manifestSha256": hashlib.sha256(body).hexdigest(), "peerCertificateSha256": certificate_sha,
            "manifest": self.manifest}
        self.ready_path = state / "ready.json"
        prepared.write_private_ready_json(self.ready_path, self.ready)
        self.thread = threading.Thread(target=self.server.serve_forever, name="owned-windows-update-fixture", daemon=False)
        self.thread.start()
        owner.event("update-fixture-ready", {k: self.ready[k] for k in
            ("port", "serverInstanceId", "serverPid", "serverProcessStartIdentity", "sourceFingerprint",
             "fixtureReceiptSha256", "manifestSha256", "peerCertificateSha256")})

    def owner_jvm_environment(self):
        args = self.prepared.fixture_proxy_arguments(self.ready_path)
        trust = self.inputs["trustStore"]
        # JVM's environment-option parser accepts quoted whole options. Reject
        # quotes/control characters rather than interpolate a second option.
        require(type(trust) is str and not any(c in trust for c in '\r\n\0"'), "fixture-trust-store-option")
        return {"JAVA_TOOL_OPTIONS": " ".join([*args,
            '"-Djavax.net.ssl.trustStore=' + trust + '"',
            "-Djavax.net.ssl.trustStorePassword=fixture", "-Djavax.net.ssl.trustStoreType=PKCS12"])}

    def close_known(self, *, all_update_operations_terminal):
        require(not self.closed and all_update_operations_terminal is True, "no-fixture-close-on-unknown")
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()  # Joins every existing request worker.
        self.closed = True
        self.owner.event("update-fixture-closed", {"serverInstanceId": self.ready["serverInstanceId"],
            "allRequestThreadsClosed": True, "records": self.records, "diagnostics": self.errors})
