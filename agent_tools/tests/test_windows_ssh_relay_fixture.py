"""The in-guest SSH relay fixture, offline: its primitives against their RFC vectors, and its SSH server, SOCKS
relay and HTTPS origin against peers over socket pairs. Nothing listens and no process starts.

The client here is written from RFC 4253, 4252, 4254, 8731 and OpenSSH's PROTOCOL.chacha20poly1305 with the
module's own primitives, which the vectors pin first. Interop with the product's actual client stack is
recorded separately: sing-box 1.13.4 (the bundled revision d0918261) with HomeSshRouteConfigBuilder's bootstrap
config and a reduced proxy-only runtime, and a JDK 17 HttpURLConnection as DesktopSubscriptionDownloadClient
makes it, all on one Mac's loopback (agent_docs/parity-failure-regressions.md).
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from agent_tools import windows_scenario_proxy as proxy
from agent_tools import windows_ssh_relay_fixture as fixture

R = fixture.Reader


class Peer:
    """A loopback connector of the relay that never listens: each connect is one socket pair served by ``serve``."""

    def __init__(self, serve=None):
        self.calls, self.threads, self.serve = [], [], serve or self.echo

    @staticmethod
    def echo(connection):
        with connection:
            try:
                while True:
                    data = connection.recv(65536)
                    if not data:
                        break
                    connection.sendall(data)
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass  # The relay closed its end first.

    def __call__(self, host, port):
        self.calls.append((host, port))
        near, far = socket.socketpair()
        thread = threading.Thread(target=self.serve, args=(far,), daemon=True)
        thread.start()
        self.threads.append(thread)
        return near


class Client:
    """An SSH client of the relay over one socket: just enough of the protocol for these tests."""

    def __init__(self, connection, *, kex="curve25519-sha256", ciphers=(fixture.CIPHER,), strict=True):
        self.connection, self.buffer = connection, b""
        self.kex, self.ciphers, self.strict = kex, ciphers, strict
        self.send_sequence = self.receive_sequence = 0
        self.send_cipher = self.receive_cipher = None
        connection.settimeout(30)

    def read(self, size):
        while len(self.buffer) < size:
            chunk = self.connection.recv(65536)
            if not chunk:
                raise EOFError("relay closed")
            self.buffer += chunk
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def send(self, payload):
        aligned = 0 if self.send_cipher is None else 4
        padding = 8 - (len(payload) + 5 - aligned) % 8
        padding += 8 if padding < 4 else 0
        packet = fixture.uint32(len(payload) + padding + 1) + bytes([padding]) + payload + os.urandom(padding)
        sequence, self.send_sequence = self.send_sequence, self.send_sequence + 1
        self.connection.sendall(packet if self.send_cipher is None else self.send_cipher.seal(sequence, packet))

    def receive(self):
        sequence, self.receive_sequence = self.receive_sequence, self.receive_sequence + 1
        head = self.read(4)
        if self.receive_cipher is None:
            body = self.read(struct.unpack(">I", head)[0])
        else:
            length = self.receive_cipher.length(sequence, head)
            body = self.receive_cipher.open(sequence, head, self.read(length), self.read(16))
        return body[1:len(body) - body[0]]

    def handshake(self, host_public):
        self.connection.sendall(b"SSH-2.0-RelayFixtureTestClient\r\n")
        line = b""
        while not line.endswith(b"\r\n"):
            line += self.read(1)
        self.server_version = line[:-2]
        kex = [self.kex] + (["kex-strict-c-v00@openssh.com"] if self.strict else [])
        init = (bytes([fixture.KEXINIT]) + os.urandom(16) + fixture.string(",".join(kex)) + fixture.string("ssh-ed25519")
                + fixture.string(",".join(self.ciphers)) * 2 + fixture.string("hmac-sha2-256") * 2 + fixture.string("none") * 2
                + fixture.string("") * 2 + b"\0" + fixture.uint32(0))
        self.send(init)
        server_init = self.receive()
        assert server_init[0] == fixture.KEXINIT
        private = os.urandom(32)
        public = fixture.x25519(private, (9).to_bytes(32, "little"))
        try:
            self.send(bytes([fixture.KEX_ECDH_INIT]) + fixture.string(public))
            reply = self.receive()
        except (OSError, EOFError):
            return "closed"  # A relay that refused the offer may close before this message arrives.
        if reply[0] == fixture.DISCONNECT:
            return reply
        assert reply[0] == fixture.KEX_ECDH_REPLY
        body = R(reply[1:])
        host_blob, server_public, signature = body.string(), body.string(), R(body.string())
        assert host_blob == fixture.ed25519_blob(host_public), "host key differs from the pinned one"
        shared = fixture.mpint(int.from_bytes(fixture.x25519(private, server_public), "big"))
        exchange = hashlib.sha256(fixture.string(b"SSH-2.0-RelayFixtureTestClient") + fixture.string(self.server_version)
                                  + fixture.string(init) + fixture.string(server_init) + fixture.string(host_blob)
                                  + fixture.string(public) + fixture.string(server_public) + shared).digest()
        assert signature.text() == "ssh-ed25519" and fixture.ed25519_verify(host_public, exchange, signature.string())
        self.session_id = exchange
        assert self.receive() == bytes([fixture.NEWKEYS])
        self.send(bytes([fixture.NEWKEYS]))

        def derive(letter):
            key = hashlib.sha256(shared + exchange + letter + exchange).digest()
            return key + hashlib.sha256(shared + exchange + key).digest()
        self.send_cipher, self.receive_cipher = fixture.PacketCipher(derive(b"C")), fixture.PacketCipher(derive(b"D"))
        if self.strict:
            self.send_sequence = self.receive_sequence = 0
        return None

    def authenticate(self, user, seed, *, sign_with=None, query=True):
        self.send(bytes([fixture.SERVICE_REQUEST]) + fixture.string("ssh-userauth"))
        assert self.receive() == bytes([fixture.SERVICE_ACCEPT]) + fixture.string("ssh-userauth")
        self.send(bytes([fixture.USERAUTH_REQUEST]) + fixture.string(user) + fixture.string("ssh-connection") + fixture.string("none"))
        failure = self.receive()
        assert failure[0] == fixture.USERAUTH_FAILURE and R(failure[1:]).text() == "publickey"
        blob = fixture.ed25519_blob(fixture.ed25519_public(seed))
        head = (fixture.string(user) + fixture.string("ssh-connection") + fixture.string("publickey"))
        if query:
            self.send(bytes([fixture.USERAUTH_REQUEST]) + head + b"\0" + fixture.string("ssh-ed25519") + fixture.string(blob))
            answer = self.receive()
            if answer[0] != fixture.USERAUTH_PK_OK:
                return answer[0]
        data = (fixture.string(self.session_id) + bytes([fixture.USERAUTH_REQUEST]) + head + b"\x01" + fixture.string("ssh-ed25519")
                + fixture.string(blob))
        proof = fixture.string("ssh-ed25519") + fixture.string(fixture.ed25519_sign(sign_with or seed, data))
        self.send(bytes([fixture.USERAUTH_REQUEST]) + head + b"\x01" + fixture.string("ssh-ed25519") + fixture.string(blob)
                  + fixture.string(proof))
        return self.receive()[0]

    def open(self, host, port, kind="direct-tcpip"):
        extra = fixture.string(host) + fixture.uint32(port) + fixture.string("127.0.0.1") + fixture.uint32(40000) if kind == "direct-tcpip" else b""
        self.send(bytes([fixture.CHANNEL_OPEN]) + fixture.string(kind) + fixture.uint32(7) + fixture.uint32(1 << 20)
                  + fixture.uint32(32768) + extra)
        return self.receive()


def connected(relay, client_kwargs=None):
    near, far = socket.socketpair()
    thread = threading.Thread(target=relay.serve_ssh, args=(far,), daemon=True)
    thread.start()
    return Client(near, **(client_kwargs or {})), thread


def new_relay(user_seed, connector=None):
    relay = fixture.Relay(user="fixture", authorized_public=fixture.ed25519_public(user_seed), host_seed=os.urandom(32),
                          connector=connector or Peer())
    relay.socks_port = 41001  # The port start() would have bound; no listener exists here.
    return relay


class VectorTests(unittest.TestCase):
    def test_x25519_rfc7748(self):
        h = bytes.fromhex
        self.assertEqual("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", fixture.x25519(
            h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")).hex())
        alice, bob = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"), h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        nine = (9).to_bytes(32, "little")
        self.assertEqual("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", fixture.x25519(alice, nine).hex())
        self.assertEqual("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", fixture.x25519(bob, nine).hex())
        shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        self.assertEqual(shared, fixture.x25519(alice, fixture.x25519(bob, nine)).hex())
        self.assertEqual(shared, fixture.x25519(bob, fixture.x25519(alice, nine)).hex())
        self.assertEqual(bytes(32), fixture.x25519(alice, bytes(32)), "the zero point the server refuses")

    def test_ed25519_rfc8032(self):
        for seed, public, message, signature in (
                ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                 "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                 "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
                ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                 "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
                 "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
                ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                 "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
                 "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")):
            with self.subTest(public=public[:8]):
                seed, public, message, signature = (bytes.fromhex(value) for value in (seed, public, message, signature))
                self.assertEqual(public, fixture.ed25519_public(seed))
                self.assertEqual(signature, fixture.ed25519_sign(seed, message))
                self.assertTrue(fixture.ed25519_verify(public, message, signature))
                self.assertFalse(fixture.ed25519_verify(public, message + b"x", signature))
                self.assertFalse(fixture.ed25519_verify(public, message, signature[:63] + bytes([signature[63] ^ 1])))
                self.assertFalse(fixture.ed25519_verify(fixture.ed25519_public(os.urandom(32)), message, signature))

    def test_chacha20_and_poly1305_rfc8439_in_openssh_layout(self):
        # RFC 8439 2.3.2: counter 1, nonce 000000090000004a00000000. OpenSSH's layout puts a 64-bit counter in
        # words 12-13 and a 64-bit nonce in 14-15, so the same block is counter 1 + (0x09000000 << 32), nonce 4a.
        block = fixture.chacha20_block(bytes(range(32)), (1,) + struct.unpack("<3I", bytes.fromhex("000000090000004a00000000")))
        self.assertEqual("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e", block.hex())
        stream = fixture.chacha20_stream(bytes(range(32)), bytes.fromhex("0000004a00000000"), 1 + (0x09000000 << 32), 64)
        self.assertEqual(block, stream)
        tag = fixture.poly1305(bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
                               b"Cryptographic Forum Research Group")
        self.assertEqual("a8061dc1305136c6c22b8baf0c0127a9", tag.hex())

    def test_a_sealed_packet_opens_only_whole_and_in_sequence(self):
        cipher = fixture.PacketCipher(os.urandom(64))
        packet = fixture.uint32(12) + bytes([6]) + b"hello" + bytes(6)
        wire = cipher.seal(7, packet)
        self.assertEqual(12, cipher.length(7, wire[:4]))
        self.assertEqual(packet[4:], cipher.open(7, wire[:4], wire[4:-16], wire[-16:]))
        for sequence, body in ((8, wire[4:-16]), (7, bytes([wire[4] ^ 1]) + wire[5:-16])):
            with self.subTest(sequence=sequence), self.assertRaisesRegex(fixture.ProtocolError, "packet-tag"):
                cipher.open(sequence, wire[:4], body, wire[-16:])

    def test_the_private_key_container_holds_the_seed_and_its_derived_public_key(self):
        seed = os.urandom(32)
        text = fixture.openssh_private_key(seed, check=b"\1\2\3\4")
        lines = text.strip().splitlines()
        self.assertEqual(("-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"), (lines[0], lines[-1]))
        self.assertTrue(all(len(line) <= 70 for line in lines))
        body = R(base64.b64decode("".join(lines[1:-1]))[len(b"openssh-key-v1\0"):])
        self.assertEqual((b"none", b"none", b"", 1), (body.string(), body.string(), body.string(), body.uint32()))
        public = fixture.ed25519_public(seed)
        self.assertEqual(fixture.ed25519_blob(public), body.string())
        private = R(body.string())
        self.assertEqual((b"\1\2\3\4", b"\1\2\3\4", "ssh-ed25519", public, seed + public, b""),
                         (private.take(4), private.take(4), private.text(), private.string(), private.string(), private.string()))
        padding = private.data[private.offset:]
        self.assertEqual(bytes(range(1, len(padding) + 1)), padding)
        self.assertEqual(0, len(private.data) % 8)
        line = fixture.public_key_line(public, "relay")
        self.assertEqual(["ssh-ed25519", base64.b64encode(fixture.ed25519_blob(public)).decode(), "relay"], line.split(" "))
        self.assertEqual("SHA256:" + base64.b64encode(hashlib.sha256(fixture.ed25519_blob(public)).digest()).decode().rstrip("="),
                         fixture.fingerprint(fixture.ed25519_blob(public)))


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.seed = os.urandom(32)
        self.peer = Peer()
        self.relay = new_relay(self.seed, self.peer)
        self.addCleanup(self.relay.close, 2)

    def session(self, **client):
        client, thread = connected(self.relay, client)
        self.addCleanup(client.connection.close)
        return client, thread

    def test_a_pinned_key_publickey_login_and_a_direct_tcpip_channel_to_the_relay_port(self):
        client, thread = self.session()
        self.assertIsNone(client.handshake(self.relay.host_public))
        self.assertTrue(client.server_version.startswith(b"SSH-2.0-"))
        self.assertEqual(fixture.USERAUTH_SUCCESS, client.authenticate("fixture", self.seed))
        reply = client.open("127.0.0.1", self.relay.socks_port)
        self.assertEqual(fixture.CHANNEL_OPEN_CONFIRMATION, reply[0])
        body = R(reply[1:])
        self.assertEqual(7, body.uint32())
        local = body.uint32()
        client.send(bytes([fixture.CHANNEL_DATA]) + fixture.uint32(local) + fixture.string(b"through the relay"))
        echoed = client.receive()
        self.assertEqual(bytes([fixture.CHANNEL_DATA]) + fixture.uint32(7) + fixture.string(b"through the relay"), echoed)
        client.send(bytes([fixture.CHANNEL_EOF]) + fixture.uint32(local))
        self.assertEqual([bytes([fixture.CHANNEL_EOF]) + fixture.uint32(7), bytes([fixture.CHANNEL_CLOSE]) + fixture.uint32(7)],
                         [client.receive(), client.receive()])
        client.send(bytes([fixture.CHANNEL_CLOSE]) + fixture.uint32(local))
        client.send(bytes([fixture.DISCONNECT]) + fixture.uint32(11) + fixture.string("done") + fixture.string(""))
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual([("127.0.0.1", self.relay.socks_port)], self.peer.calls)
        facts = self.relay.facts()["sessions"]
        fingerprint = fixture.fingerprint(fixture.ed25519_blob(fixture.ed25519_public(self.seed)))
        self.assertEqual(1, len(facts))
        session = facts[0]
        self.assertEqual(("SSH-2.0-RelayFixtureTestClient", "curve25519-sha256", fixture.CIPHER, True, True, True, fingerprint, "client-disconnect"),
                         tuple(session[key] for key in ("clientVersion", "kex", "cipher", "strict", "keysExchanged", "authenticated",
                                                        "authenticatedKey", "end")))
        self.assertEqual([("none", False, "failure"), ("publickey", False, "pk-ok"), ("publickey", True, "success")],
                         [(entry["method"], entry["signed"], entry["result"]) for entry in session["auth"]])
        self.assertEqual([{"type": "direct-tcpip", "host": "127.0.0.1", "port": self.relay.socks_port, "result": "opened",
                           "toTarget": 17, "fromTarget": 17}], session["channels"])
        self.assertNotIn(self.seed.hex(), json.dumps(self.relay.facts()), "records carry no key material")

    def test_a_non_strict_client_keeps_its_sequence_numbers(self):
        client, _ = self.session(strict=False)
        self.assertIsNone(client.handshake(self.relay.host_public))
        self.assertEqual(fixture.USERAUTH_SUCCESS, client.authenticate("fixture", self.seed))
        self.assertFalse(self.relay.facts()["sessions"][0]["strict"])

    def test_another_key_user_or_signature_never_authenticates(self):
        for name, user, seed, sign_with, query in (("other key", "fixture", os.urandom(32), None, True),
                                                   ("other user", "root", self.seed, None, True),
                                                   ("forged signature", "fixture", self.seed, os.urandom(32), False)):
            with self.subTest(name=name):
                client, _ = self.session()
                client.handshake(self.relay.host_public)
                self.assertEqual(fixture.USERAUTH_FAILURE, client.authenticate(user, seed, sign_with=sign_with, query=query))
                reply = client.open("127.0.0.1", self.relay.socks_port)
                self.assertEqual(fixture.DISCONNECT, reply[0], "nothing is served before authentication")
        sessions = self.relay.facts()["sessions"]
        self.assertEqual([False] * 3, [session["authenticated"] for session in sessions])
        self.assertEqual(["not-authenticated"] * 3, [session["end"] for session in sessions])
        self.assertEqual([], self.peer.calls)

    def test_a_channel_opens_to_the_relay_port_alone(self):
        client, _ = self.session()
        client.handshake(self.relay.host_public)
        client.authenticate("fixture", self.seed)
        for host, port, kind, reason in (("127.0.0.1", self.relay.socks_port + 1, "direct-tcpip", fixture.PROHIBITED),
                                         ("192.0.2.10", self.relay.socks_port, "direct-tcpip", fixture.PROHIBITED),
                                         ("", 0, "session", fixture.UNKNOWN_CHANNEL_TYPE)):
            with self.subTest(host=host, kind=kind):
                reply = client.open(host, port, kind)
                self.assertEqual(fixture.CHANNEL_OPEN_FAILURE, reply[0])
                body = R(reply[1:])
                self.assertEqual((7, reason), (body.uint32(), body.uint32()))
        self.assertEqual([], self.peer.calls)
        self.assertEqual(["prohibited", "prohibited", "unknown-type"],
                         [channel["result"] for channel in self.relay.facts()["sessions"][0]["channels"]])

    def test_a_target_that_refuses_is_a_connect_failure(self):
        def refused(host, port):
            raise ConnectionRefusedError("refused")
        self.relay.connector = refused
        client, _ = self.session()
        client.handshake(self.relay.host_public)
        client.authenticate("fixture", self.seed)
        reply = client.open("127.0.0.1", self.relay.socks_port)
        self.assertEqual((fixture.CHANNEL_OPEN_FAILURE, fixture.CONNECT_FAILED), (reply[0], struct.unpack(">I", reply[5:9])[0]))
        self.assertEqual("connect-failed", self.relay.facts()["sessions"][0]["channels"][0]["result"])

    def test_no_common_algorithm_ends_the_session_before_any_key(self):
        for kex, ciphers in (("diffie-hellman-group14-sha256", (fixture.CIPHER,)), ("curve25519-sha256", ("aes128-ctr",))):
            with self.subTest(kex=kex, ciphers=ciphers):
                client, thread = self.session(kex=kex, ciphers=ciphers)
                reply = client.handshake(self.relay.host_public)
                self.assertTrue(reply == "closed" or reply[0] == fixture.DISCONNECT, reply)
                thread.join(10)
        self.assertEqual(["no-common-algorithm"] * 2, [session["end"] for session in self.relay.facts()["sessions"]])

    def test_a_tampered_packet_ends_the_session(self):
        client, thread = self.session()
        client.handshake(self.relay.host_public)
        original = client.send_cipher.seal
        client.send_cipher.seal = lambda sequence, packet: (lambda wire: wire[:-1] + bytes([wire[-1] ^ 1]))(original(sequence, packet))
        client.send(bytes([fixture.SERVICE_REQUEST]) + fixture.string("ssh-userauth"))
        thread.join(10)
        self.assertEqual("packet-tag", self.relay.facts()["sessions"][0]["end"])

    def test_a_strict_session_refuses_anything_before_the_key_exchange(self):
        near, far = socket.socketpair()
        self.addCleanup(near.close)
        thread = threading.Thread(target=self.relay.serve_ssh, args=(far,), daemon=True)
        thread.start()
        client = Client(near)
        client.connection.sendall(b"SSH-2.0-RelayFixtureTestClient\r\n")
        client.send(bytes([fixture.IGNORE]) + fixture.string(""))
        thread.join(10)
        self.assertEqual("first-message-not-kexinit", self.relay.facts()["sessions"][0]["end"])

    def test_stopping_the_relay_ends_its_sessions_and_channels(self):
        client, thread = self.session()
        client.handshake(self.relay.host_public)
        client.authenticate("fixture", self.seed)
        self.assertEqual(fixture.CHANNEL_OPEN_CONFIRMATION, client.open("127.0.0.1", self.relay.socks_port)[0])
        self.relay.stop_ssh()
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual("stopped", self.relay.facts()["sessions"][0]["end"])
        with self.assertRaises((EOFError, OSError)):
            client.receive()


class Listener:
    """A listener stand-in: accept hands out queued socket pair ends and fails once closed. Its fileno is a socket
    pair end that is readable while a connection waits, so the relay's select sees it as a listener."""

    def __init__(self, port):
        self.port, self.queue, self.lock, self.closed = port, [], threading.Lock(), False
        self.signal, self.wake = socket.socketpair()

    def fileno(self):
        return self.signal.fileno()

    def getsockname(self):
        return ("127.0.0.1", self.port)

    def accept(self):
        with self.lock:
            if self.closed or not self.queue:
                raise OSError("closed")
            self.signal.recv(1)
            return self.queue.pop(0), ("127.0.0.1", 1)

    def connect(self):
        near, far = socket.socketpair()
        with self.lock:
            if self.closed:
                near.close()
                far.close()
                raise ConnectionRefusedError("refused")
            self.queue.append(far)
            self.wake.sendall(b"x")
        return near

    def shutdown(self, how):
        pass

    def close(self):
        with self.lock:
            if not self.closed:
                self.closed = True
                for item in (*self.queue, self.wake, self.signal):
                    item.close()
                self.queue.clear()


class LifetimeTests(unittest.TestCase):
    def test_start_binds_two_listeners_and_stop_ssh_refuses_new_sessions_while_socks_stays(self):
        ports = iter((41010, 41011))
        listeners = []

        def listener():
            listeners.append(Listener(next(ports)))
            return listeners[-1]
        seed = os.urandom(32)
        relay = fixture.Relay(user="fixture", authorized_public=fixture.ed25519_public(seed), host_seed=os.urandom(32),
                              listener=listener, connector=Peer())
        relay.start()
        self.assertEqual((41010, 41011), (relay.socks_port, relay.ssh_port))
        client = Client(listeners[1].connect())
        client.handshake(relay.host_public)
        self.assertEqual(fixture.USERAUTH_SUCCESS, client.authenticate("fixture", seed))
        relay.stop_ssh()
        with self.assertRaises(ConnectionRefusedError):
            listeners[1].connect()
        socks = listeners[0].connect()
        socks.settimeout(10)
        socks.sendall(b"\x05\x01\x00")
        self.assertEqual(b"\x05\x00", socks.recv(2))
        socks.close()
        self.assertTrue(relay.close(10), "every thread ended")
        self.assertTrue(listeners[0].closed and listeners[1].closed)
        with self.assertRaisesRegex(ValueError, "relay-started-once"):
            relay.start()
        client.connection.close()

    def test_the_module_is_plain_ascii_and_starts_nothing_on_import(self):
        raw = Path(fixture.__file__).read_bytes()
        self.assertTrue(all(byte < 128 for byte in raw))
        before = threading.active_count()
        relay = fixture.Relay(user="fixture", authorized_public=bytes(32), host_seed=bytes(32))
        self.assertEqual((None, None, before), (relay.ssh_server, relay.socks_server, threading.active_count()))
        for bad in ({"user": "", "authorized_public": bytes(32), "host_seed": bytes(32)},
                    {"user": "fixture", "authorized_public": bytes(31), "host_seed": bytes(32)}):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "relay-identity"):
                fixture.Relay(**bad)


class SocksTests(unittest.TestCase):
    def setUp(self):
        self.peer = Peer()
        self.relay = new_relay(os.urandom(32), self.peer)
        self.addCleanup(self.relay.close, 2)

    def request(self, greeting, request):
        near, far = socket.socketpair()
        self.addCleanup(near.close)
        thread = threading.Thread(target=self.relay.serve_socks, args=(far,), daemon=True)
        thread.start()
        near.settimeout(10)
        near.sendall(greeting)
        method = near.recv(2)
        if method != b"\x05\x00":
            thread.join(10)
            return method, None, near, thread
        near.sendall(request)
        return method, near.recv(10), near, thread

    def test_a_connect_to_the_loopback_is_relayed_and_counted(self):
        for host, kind, address in (("localhost", 3, bytes([9]) + b"localhost"), ("127.0.0.1", 1, socket.inet_aton("127.0.0.1"))):
            with self.subTest(host=host):
                method, reply, near, thread = self.request(b"\x05\x02\x02\x00", bytes([5, 1, 0, kind]) + address + struct.pack(">H", 8443))
                self.assertEqual((b"\x05\x00", b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack(">H", 8443)), (method, reply))
                near.sendall(b"ClientHello")
                self.assertEqual(b"ClientHello", near.recv(64))
                near.shutdown(socket.SHUT_WR)
                self.assertEqual(b"", near.recv(64))
                thread.join(10)
        self.assertEqual([("localhost", 8443), ("127.0.0.1", 8443)], self.peer.calls)
        self.assertEqual([("localhost", 8443, "connected", 11, 11), ("127.0.0.1", 8443, "connected", 11, 11)],
                         [(row["host"], row["port"], row["result"], row["up"], row["down"]) for row in self.relay.facts()["socks"]])

    def test_nothing_leaves_the_loopback_and_only_connect_is_served(self):
        cases = ((b"\x05\x01\x02", b"", None, "bad-request"),
                 (b"\x05\x01\x00", bytes([5, 1, 0, 1]) + socket.inet_aton("192.0.2.1") + struct.pack(">H", 443), b"\x05\x02", "refused-not-loopback"),
                 (b"\x05\x01\x00", bytes([5, 1, 0, 3, 11]) + b"example.org" + struct.pack(">H", 443), b"\x05\x02", "refused-not-loopback"),
                 (b"\x05\x01\x00", bytes([5, 3, 0, 1]) + socket.inet_aton("127.0.0.1") + struct.pack(">H", 53), b"\x05\x07", "unsupported-command"))
        for greeting, request, prefix, result in cases:
            with self.subTest(result=result):
                method, reply, _, thread = self.request(greeting, request)
                if prefix is None:
                    self.assertEqual(b"\x05\xff", method)
                else:
                    self.assertEqual(prefix, reply[:2])
                thread.join(10)
        self.assertEqual([], self.peer.calls)
        self.assertEqual([row[3] for row in cases], [row["result"] for row in self.relay.facts()["socks"]])


class OriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tls = proxy.material(secrets.randbits, time.time())
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        (root / "cert.pem").write_bytes(cls.tls["certificate"])
        (root / "key.pem").write_bytes(cls.tls["privateKey"])
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(root / "cert.pem", root / "key.pem")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def fetch(self, origin, path):
        near, far = socket.socketpair()
        thread = threading.Thread(target=origin.serve, args=(far,), daemon=True)
        thread.start()
        client = ssl.create_default_context(cadata=self.tls["certificate"].decode("ascii"))
        with client.wrap_socket(near, server_hostname="localhost") as stream:
            stream.settimeout(30)
            stream.sendall(("GET " + path + " HTTP/1.1\r\nHost: localhost\r\n\r\n").encode("ascii"))
            # The origin closes after its Content-Length body without a close_notify, so read exactly that much,
            # as the JDK's HttpURLConnection does.
            response = b""
            while b"\r\n\r\n" not in response:
                response += stream.recv(4096)
            head, body = response.split(b"\r\n\r\n", 1)
            length = int(next(line.split(b":")[1] for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")))
            while len(body) < length:
                body += stream.recv(4096)
            response = head + b"\r\n\r\n" + body
        thread.join(10)
        return response

    def test_one_path_answers_the_body_and_every_request_is_recorded(self):
        origin = fixture.HttpsOrigin(self.context, "/subscription/op", b"socks://127.0.0.1:1080#Relay\n")
        self.assertTrue(self.fetch(origin, "/subscription/op").startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertTrue(self.fetch(origin, "/subscription/op").endswith(b"\r\n\r\nsocks://127.0.0.1:1080#Relay\n"))
        self.assertTrue(self.fetch(origin, "/other").startswith(b"HTTP/1.1 404 Not Found\r\n"))
        self.assertEqual([("GET", "/subscription/op", 200, 29)] * 2 + [("GET", "/other", 404, 10)],
                         [(row["method"], row["path"], row["status"], row["bytes"]) for row in origin.served()])
        self.assertTrue(origin.close())

    def test_the_pinned_fixtures_handshake_ends_after_a_quarter_second_without_a_client_hello(self):
        # The causal control of the next test: the first relay interop used https_subscription_relay_fixture as the
        # origin, and a JVM's first ClientHello through the relay came after its 0.25 s. Its own accept path, given
        # one socket pair end whose peer stays silent, ends in that timeout. Nothing listens.
        integration = Path(__file__).resolve().parents[2] / "scripts" / "integration"
        socks = types.ModuleType("socks_http_fixture")
        exec(compile((integration / "socks_http_fixture.py").read_bytes(), str(integration / "socks_http_fixture.py"), "exec"),
             socks.__dict__)
        pinned = types.ModuleType("_pinned_https_subscription_relay_fixture")
        with mock.patch.dict(sys.modules, {"socks_http_fixture": socks}):
            exec(compile((integration / "https_subscription_relay_fixture.py").read_bytes(),
                         str(integration / "https_subscription_relay_fixture.py"), "exec"), pinned.__dict__)
        self.assertEqual(0.25, pinned.TLS_HANDSHAKE_TIMEOUT_SECONDS)
        near, far = socket.socketpair()
        self.addCleanup(near.close)
        server = types.SimpleNamespace(socket=types.SimpleNamespace(accept=lambda: (far, ("127.0.0.1", 1))), _context=self.context)
        started = time.monotonic()
        with self.assertRaises((TimeoutError, socket.timeout)):
            pinned._TlsThreadingHTTPServer.get_request(server)
        self.assertLess(time.monotonic() - started, fixture.HANDSHAKE_SECONDS)

    def test_a_handshake_has_more_than_the_pinned_fixtures_quarter_second(self):
        origin = fixture.HttpsOrigin(self.context, "/subscription/op", b"late\n")
        near, far = socket.socketpair()
        thread = threading.Thread(target=origin.serve, args=(far,), daemon=True)
        thread.start()
        time.sleep(0.6)  # A cold JVM's first ClientHello through the relay came this late on loopback.
        client = ssl.create_default_context(cadata=self.tls["certificate"].decode("ascii"))
        with client.wrap_socket(near, server_hostname="localhost") as stream:
            stream.sendall(b"GET /subscription/op HTTP/1.1\r\n\r\n")
            self.assertTrue(stream.recv(4096).startswith(b"HTTP/1.1 200 OK"))
        thread.join(10)
        self.assertEqual(fixture.HANDSHAKE_SECONDS, 60)
        self.assertEqual(1, len(origin.served()))


if __name__ == "__main__":
    unittest.main()
