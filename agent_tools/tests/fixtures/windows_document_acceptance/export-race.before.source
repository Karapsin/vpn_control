"""Finite authenticated export relay for a deterministic publication barrier.

Used only in the isolated admitted VM. All product response bytes come from the
actual installed owner. The relay forwards the original authentication and frame
bytes unchanged. It pauses the first export Read after the installed public
client has created its private output partial, before product publication. This
does not invoke a fake action handler or supply a product result.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
import time


def need(value, code):
    if not value:
        raise RuntimeError(code)


def read_packet(sock, module):
    data = bytearray()
    def exact(size):
        out = bytearray()
        while len(out) < size:
            try:
                piece = sock.recv(size - len(out))
            except BaseException as error:
                error.document_frame_fragment = bytes(data) + bytes(out)
                raise
            if not piece:
                raise module.ClosedFrame(bytes(data) + bytes(out))
            out.extend(piece)
        data.extend(out)
        return bytes(out)
    count = int.from_bytes(exact(4), "big")
    need(0 < count <= module.FRAME, "document-relay-frame-bound")
    value = module.load(exact(count).decode("utf-8", "strict"))
    need(type(value) is str, "document-relay-string-frame")
    return bytes(data), value


def is_export_read(value, module, owner):
    if not value.startswith(module.TRANSFER):
        return False
    envelope = module.load(value[len(module.TRANSFER):])
    need(set(envelope) == {"owner", "context", "kind", "command"}
         and envelope["owner"] == owner, "document-relay-transfer-binding")
    command = module.load(envelope["command"])
    return envelope["kind"] == "export" and command.get("action") == "read" and command.get("offset") == 0


class ExportRelay:
    def __init__(self, owner, client, module):
        self.owner, self.client, self.module = owner, client, module
        # Keep the exact constructor object before any socket API can run.
        if not hasattr(owner, "document_export_relays"):
            owner.document_export_relays = []
        owner.document_export_relays.append(self)
        self.barrier, self.release, self.stop = threading.Event(), threading.Event(), threading.Event()
        self.errors, self.connections, self.threads = [], [], []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        self.listener.bind(("127.0.0.1", 0)); self.listener.listen(8); self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        try:
            while not self.stop.is_set():
                try: local, address = self.listener.accept()
                except socket.timeout: continue
                need(address[0] == "127.0.0.1", "document-relay-loopback-peer")
                self.connections.append(local)
                thread = threading.Thread(target=self.exchange, args=(local,), daemon=True)
                self.threads.append(thread); thread.start()
        except BaseException as error:
            self.errors.append(error)

    def exchange(self, local):
        remote = None
        try:
            self.client.guard()
            remote = socket.create_connection(("127.0.0.1", self.client._endpoint["port"]), .5)
            self.connections.append(remote)
            local.settimeout(30); remote.settimeout(30)
            token_packet, token = read_packet(local, self.module)
            need(token == self.client._endpoint["token"], "document-relay-client-token")
            remote.sendall(token_packet)
            auth_packet, auth = read_packet(remote, self.module)
            local.sendall(auth_packet)
            need(auth == "AUTHENTICATED", "document-relay-real-owner-authentication")
            packet, first = read_packet(local, self.module)
            if first.startswith(self.module.CONTEXT):
                remote.sendall(packet)
                packet, first = read_packet(local, self.module)
            if is_export_read(first, self.module, self.client.owner) and not self.barrier.is_set():
                self.owner.event("document-export-read-barrier", {"owner": self.client.owner,
                    "payloadSha256": hashlib.sha256(packet).hexdigest(),
                    "actualOwnerAuthenticated": True, "productReadNotForwardedYet": True})
                self.barrier.set()
                while not self.release.wait(.2):
                    need(not self.stop.is_set(), "document-relay-stopped-before-release")
            remote.sendall(packet)
            response, value = read_packet(remote, self.module)
            local.sendall(response)  # No generated result, envelope or payload.
            self.client.guard()
        except BaseException as error:
            self.errors.append(error)
        finally:
            for sock in (local, remote):
                if sock is not None:
                    sock.close()
                    self.connections.remove(sock)

    def close_known(self):
        need(not self.connections and all(not t.is_alive() for t in self.threads),
             "document-relay-live-original-connections")
        self.stop.set(); self.thread.join(2)
        need(not self.thread.is_alive() and not self.errors, "document-relay-closing")
        self.listener.close()


def run_public_export_race(owner, workspace, identity, client, module, windows, harness, mode):
    need(os.name == "nt" and mode in ("parent", "destination"), "document-race-finite-mode")
    owner.guard(); client.guard()
    base = Path(owner.root)
    parent = base / ("document-race-" + mode)
    renamed = base / ("document-race-" + mode + "-moved")
    proxy = base / ("document-export-client-" + mode)
    need(not parent.exists() and not renamed.exists() and not proxy.exists(), "document-race-before-absences")
    parent.mkdir(); proxy.mkdir()
    # Prove this actual ordinary context can rename this fixture before the
    # product opens it. The temporary witness handle must be closed first.
    probe = windows.Held(owner.native, parent, directory=True)
    initial = probe.current(); probe.close()
    parent.rename(renamed); renamed.rename(parent)
    probe = windows.Held(owner.native, parent, directory=True)
    need(probe.current() == initial, "document-race-rename-positive-identity"); probe.close()
    destination = parent / "routing 東京 export.json"
    relay = ExportRelay(owner, client, module)
    descriptor = dict(client._endpoint, schemaVersion=1, port=relay.port)
    descriptor_path = proxy / "activation.port"
    raw = module.dump(descriptor).encode()
    windows.create_sid_private_new(owner.native, descriptor_path, raw,
                                   owner.request["context"]["ordinarySid"])
    held_descriptor = windows.Held(owner.native, descriptor_path)
    descriptor_pin = held_descriptor.pin()
    windows.endpoint_private_acl(owner.native, held_descriptor.handle,
                                 owner.request["context"]["ordinarySid"])
    owner.document_export_relay = relay
    owner.document_export_descriptor = held_descriptor
    child = owner.child("document-public-export-race-" + mode, [owner.request["cliPath"],
        "--state-dir", str(proxy), "--json", "--controller-id", identity,
        "routing", "export", "--output", str(destination)])
    try:
        while not relay.barrier.wait(.1):
            need(not relay.errors, "document-relay-before-barrier-error")
            observation = child.observe()
            need(observation is None, "document-export-exited-before-barrier")
        # Public writer has opened the actual destination parent before requesting
        # its first chunk. No harness parent handle remains to mask a product bug.
        partials = [p for p in parent.iterdir() if p.name.startswith(".vpn-export-") and p.name.endswith(".partial")]
        need(len(partials) == 1 and partials[0].is_file(), "document-race-real-product-partial")
        if mode == "destination":
            sentinel = b"owned racing destination sentinel\n"
            with destination.open("xb") as output:
                output.write(sentinel); output.flush(); os.fsync(output.fileno())
            sentinel_pin = windows.Held(owner.native, destination)
            sentinel_before = sentinel_pin.pin(); sentinel_pin.close()
            owner.event("document-racing-destination-created", {"pin": sentinel_before})
        else:
            try:
                parent.rename(renamed)
            except OSError as error:
                need(error.winerror in (5, 32), "document-parent-race-unexpected-win32-error")
                owner.event("document-parent-race-refused", {"win32Error": error.winerror,
                    "positiveRenameBeforeProduct": True, "harnessParentHandleHeld": False})
            else:
                # Preserve a product pinning failure. Do not restore paths or
                # release the product to publish through a changed namespace.
                owner.event("document-parent-race-unexpectedly-renamed", {"from": str(parent), "to": str(renamed)})
                owner.park("document-parent-race-product-pinning-failure")
        relay.release.set()
        completed = child.completed()
        result = harness["envelope"](completed, 1 if mode == "destination" else 0,
                                  "PERSISTENCE_FAILED" if mode == "destination" else "OK")
        if mode == "destination":
            check = windows.Held(owner.native, destination)
            need(check.pin() == sentinel_before and check.bytes() == sentinel, "document-raced-target-overwritten")
            check.close()
        need(not [p for p in parent.iterdir() if p.name.startswith(".vpn-export-") and p.name.endswith(".partial")],
             "document-race-known-partial-cleanup")
        # All product connections have completed before relay/descriptor closure.
        for thread in relay.threads: thread.join(2)
        relay.close_known()
        need(held_descriptor.pin() == descriptor_pin and {p.name for p in proxy.iterdir()} == {"activation.port"},
             "document-exact-owned-proxy-descriptor-closing")
        held_descriptor.close()
        owner.event("document-public-export-race-complete", {"mode": mode, "controllerId": identity,
                    "code": result["code"], "realProductResponsesOnly": True,
                    "originalChildTerminalAndFullEof": True, "privateCredentialDescriptorRetained": True,
                    "pathDeletionPerformed": False})
        return result
    except BaseException as error:
        owner.park("document-public-export-race-unknown", error)
