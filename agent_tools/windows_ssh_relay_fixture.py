"""The in-guest SSH relay of the Windows SSH Routing rows: a stdlib-only SSH server and its loopback SOCKS relay.

What the product needs from the far end (HomeSshRouteConfigBuilder, DesktopSubscriptionDownloadClient, sing-box's
ssh outbound on golang.org/x/crypto/ssh): an SSH-2 server whose host key equals one pinned ``ssh.host-keys`` line,
publickey authentication of ``ssh.user`` with the imported private key, and "direct-tcpip" channels to
``127.0.0.1:<ssh.relay-port>``, where a SOCKS5 relay listens on the loopback and connects onward (the home relay of
scripts/install_home_relay.sh). Nothing else: no session, shell, exec, subsystem or remote forwarding is used.

sing-box has no SSH inbound (1.13.4: "unknown inbound type: ssh"), the guest image has no SSH server and fixtures
install no Windows feature, so this module is that server, written for these rows: curve25519-sha256 key exchange
(RFC 8731), an ssh-ed25519 host key and user key (RFC 8032), chacha20-poly1305@openssh.com packets, strict key
exchange, publickey authentication and direct-tcpip only. Every listener binds 127.0.0.1, a channel opens only to
the relay's own SOCKS port and the SOCKS relay connects loopback destinations only, so no byte leaves the guest.

The case module owns the lifetime: no main, no listener, thread or clock runs on import. Records hold tokens,
counts and public-key fingerprints only, never key material or relayed bytes.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import select
import socket
import struct
import threading
import time

SERVER_VERSION = b"SSH-2.0-VpnControlRelayFixture_1"
KEX = ("curve25519-sha256", "curve25519-sha256@libssh.org")
STRICT_CLIENT, STRICT_SERVER = "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com"
HOST_KEY_ALGORITHM = "ssh-ed25519"
CIPHER = "chacha20-poly1305@openssh.com"
MAC = "hmac-sha2-256"  # Negotiated by nobody: an AEAD cipher carries its own tag, but the list may not be empty.
MAX_PACKET = 256 * 1024
WINDOW = 1 << 20
MAX_DATA = 32768
HANDSHAKE_SECONDS = 60
CONNECT_SECONDS = 10
POLL_SECONDS = 0.25
MAX_RECORDS = 256
MAX_AUTH_ATTEMPTS = 16

# Message numbers (RFC 4250 section 4.1.2).
DISCONNECT, IGNORE, UNIMPLEMENTED, DEBUG, SERVICE_REQUEST, SERVICE_ACCEPT = 1, 2, 3, 4, 5, 6
KEXINIT, NEWKEYS, KEX_ECDH_INIT, KEX_ECDH_REPLY = 20, 21, 30, 31
USERAUTH_REQUEST, USERAUTH_FAILURE, USERAUTH_SUCCESS, USERAUTH_PK_OK = 50, 51, 52, 60
GLOBAL_REQUEST, REQUEST_FAILURE = 80, 82
CHANNEL_OPEN, CHANNEL_OPEN_CONFIRMATION, CHANNEL_OPEN_FAILURE, CHANNEL_WINDOW_ADJUST = 90, 91, 92, 93
CHANNEL_DATA, CHANNEL_EXTENDED_DATA, CHANNEL_EOF, CHANNEL_CLOSE, CHANNEL_REQUEST, CHANNEL_FAILURE = 94, 95, 96, 97, 98, 100
PROHIBITED, CONNECT_FAILED, UNKNOWN_CHANNEL_TYPE = 1, 2, 3


class ProtocolError(Exception):
    """A finite end of one SSH session; its text is a fixed token."""


# ---- Curve25519 and Ed25519 (RFC 7748, RFC 8032), on Python integers ------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def x25519(scalar, point):
    """RFC 7748 section 5: the u-coordinate of scalar * point, both 32 little-endian bytes."""
    if len(scalar) != 32 or len(point) != 32:
        raise ValueError("x25519-length")
    k = int.from_bytes(scalar, "little")
    k = (k & ~7 & ((1 << 255) - 1)) | (1 << 254)
    x1 = int.from_bytes(point, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for bit_index in range(254, -1, -1):
        bit = (k >> bit_index) & 1
        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3, z3 = (da + cb) ** 2 % _P, x1 * (da - cb) ** 2 % _P
        x2, z2 = aa * bb % _P, e * (aa + 121665 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    return _P - x if x & 1 != sign else x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_BASE = (_GX, _GY, 1, _GX * _GY % _P)
_IDENTITY = (0, 1, 1, 0)


def _add(left, right):
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a, b = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    c, d = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _multiply(scalar, point):
    result = _IDENTITY
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode_point(point):
    x, y, z, _ = point
    inverse = pow(z, _P - 2, _P)
    x, y = x * inverse % _P, y * inverse % _P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def _decode_point(raw):
    y = int.from_bytes(raw, "little")
    x = _recover_x(y & ((1 << 255) - 1), y >> 255)
    if x is None:
        return None
    y &= (1 << 255) - 1
    return x, y, 1, x * y % _P


def _same_point(left, right):
    return (left[0] * right[2] - right[0] * left[2]) % _P == 0 and (left[1] * right[2] - right[1] * left[2]) % _P == 0


def _expand(seed):
    if len(seed) != 32:
        raise ValueError("ed25519-seed-length")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    return (scalar & ((1 << 254) - 8)) | (1 << 254), digest[32:]


def _scalar_hash(*parts):
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little") % _L


def ed25519_public(seed):
    return _encode_point(_multiply(_expand(seed)[0], _BASE))


def ed25519_sign(seed, message):
    scalar, prefix = _expand(seed)
    public = _encode_point(_multiply(scalar, _BASE))
    nonce = _scalar_hash(prefix, message)
    commitment = _encode_point(_multiply(nonce, _BASE))
    return commitment + ((nonce + _scalar_hash(commitment, public, message) * scalar) % _L).to_bytes(32, "little")


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    point, commitment = _decode_point(public), _decode_point(signature[:32])
    proof = int.from_bytes(signature[32:], "little")
    if point is None or commitment is None or proof >= _L:
        return False
    challenge = _scalar_hash(signature[:32], public, message)
    return _same_point(_multiply(proof, _BASE), _add(commitment, _multiply(challenge, point)))


# ---- ChaCha20 and Poly1305 (RFC 8439), as chacha20-poly1305@openssh.com uses them --------------------------------

_MASK = 0xFFFFFFFF
_SIGMA = struct.unpack("<4I", b"expand 32-byte k")


def _quarter(a, b, c, d):
    a = (a + b) & _MASK
    d ^= a
    d = (d << 16 | d >> 16) & _MASK
    c = (c + d) & _MASK
    b ^= c
    b = (b << 12 | b >> 20) & _MASK
    a = (a + b) & _MASK
    d ^= a
    d = (d << 8 | d >> 24) & _MASK
    c = (c + d) & _MASK
    b ^= c
    b = (b << 7 | b >> 25) & _MASK
    return a, b, c, d


def chacha20_block(key, tail):
    """One 64-byte block of the state: the constants, eight key words and the four words ``tail``."""
    state = (*_SIGMA, *struct.unpack("<8I", key), *tail)
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = state
    for _ in range(10):
        x0, x4, x8, x12 = _quarter(x0, x4, x8, x12)
        x1, x5, x9, x13 = _quarter(x1, x5, x9, x13)
        x2, x6, x10, x14 = _quarter(x2, x6, x10, x14)
        x3, x7, x11, x15 = _quarter(x3, x7, x11, x15)
        x0, x5, x10, x15 = _quarter(x0, x5, x10, x15)
        x1, x6, x11, x12 = _quarter(x1, x6, x11, x12)
        x2, x7, x8, x13 = _quarter(x2, x7, x8, x13)
        x3, x4, x9, x14 = _quarter(x3, x4, x9, x14)
    mixed = (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15)
    return struct.pack("<16I", *((left + right) & _MASK for left, right in zip(mixed, state)))


def chacha20_stream(key, nonce, counter, length):
    """The original 64-bit-nonce ChaCha20 OpenSSH runs: the counter and the nonce each fill two words."""
    words, blocks = struct.unpack("<2I", nonce), []
    for index in range((length + 63) // 64):
        value = counter + index
        blocks.append(chacha20_block(key, (value & _MASK, value >> 32 & _MASK, *words)))
    return b"".join(blocks)[:length]


def _xor(data, stream):
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(data), "little")


def poly1305(key, message):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s, prime, accumulator = int.from_bytes(key[16:], "little"), (1 << 130) - 5, 0
    for start in range(0, len(message), 16):
        accumulator = (accumulator + int.from_bytes(message[start:start + 16] + b"\x01", "little")) * r % prime
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


class PacketCipher:
    """chacha20-poly1305@openssh.com: K_1, the second 32 key bytes, hides the length; K_2, the first, the rest."""

    def __init__(self, key):
        if len(key) != 64:
            raise ValueError("chacha-key-length")
        self.main, self.header = key[:32], key[32:]

    def seal(self, sequence, packet):
        nonce = struct.pack(">Q", sequence)
        head = _xor(packet[:4], chacha20_stream(self.header, nonce, 0, 4))
        body = _xor(packet[4:], chacha20_stream(self.main, nonce, 1, len(packet) - 4))
        return head + body + poly1305(chacha20_stream(self.main, nonce, 0, 32), head + body)

    def length(self, sequence, head):
        return struct.unpack(">I", _xor(head, chacha20_stream(self.header, struct.pack(">Q", sequence), 0, 4)))[0]

    def open(self, sequence, head, body, tag):
        nonce = struct.pack(">Q", sequence)
        expected = poly1305(chacha20_stream(self.main, nonce, 0, 32), head + body)
        if not _constant_equal(expected, tag):
            raise ProtocolError("packet-tag")
        return _xor(body, chacha20_stream(self.main, nonce, 1, len(body)))


def _constant_equal(left, right):
    return len(left) == len(right) and not int.from_bytes(bytes(a ^ b for a, b in zip(left, right)) or b"\0", "big")


# ---- SSH wire encoding (RFC 4251 section 5) ------------------------------------------------------------------

def string(value):
    value = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return struct.pack(">I", len(value)) + value


def uint32(value):
    return struct.pack(">I", value)


def mpint(value):
    if value == 0:
        return uint32(0)
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return string(raw)


class Reader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, size):
        if size < 0 or self.offset + size > len(self.data):
            raise ProtocolError("message-truncated")
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def byte(self):
        return self.take(1)[0]

    def boolean(self):
        return self.take(1) != b"\0"

    def uint32(self):
        return struct.unpack(">I", self.take(4))[0]

    def string(self, limit=MAX_PACKET):
        size = self.uint32()
        if size > limit:
            raise ProtocolError("string-bound")
        return self.take(size)

    def text(self, limit=1024):
        try:
            return self.string(limit).decode("utf-8")
        except UnicodeDecodeError:
            raise ProtocolError("text-encoding") from None

    def names(self):
        return [name for name in self.text(8192).split(",") if name]


def ed25519_blob(public):
    return string(HOST_KEY_ALGORITHM) + string(public)


def fingerprint(blob):
    """OpenSSH's SHA256 fingerprint of a public key blob: public, never key material."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def public_key_line(public, comment=None):
    line = HOST_KEY_ALGORITHM + " " + base64.b64encode(ed25519_blob(public)).decode("ascii")
    return line + " " + comment if comment else line


def openssh_private_key(seed, comment="", check=None):
    """An unencrypted OpenSSH container of one ed25519 key pair whose public half is derived from ``seed``."""
    public = ed25519_public(seed)
    check = os.urandom(4) if check is None else check
    private = (check + check + string(HOST_KEY_ALGORITHM) + string(public) + string(seed + public) + string(comment))
    private += bytes(range(1, 1 + (-len(private)) % 8))
    body = (b"openssh-key-v1\0" + string(b"none") + string(b"none") + string(b"") + uint32(1)
            + string(ed25519_blob(public)) + string(private))
    encoded = base64.b64encode(body).decode("ascii")
    lines = [encoded[start:start + 70] for start in range(0, len(encoded), 70)]
    return "\n".join(["-----BEGIN OPENSSH PRIVATE KEY-----", *lines, "-----END OPENSSH PRIVATE KEY-----"]) + "\n"


# ---- Loopback sockets -------------------------------------------------------------------------------------------
# Only the thread that owns a socket closes it. Another thread ends a wait by a stop flag and a shutdown: a wait
# polls its flag every POLL_SECONDS, since no platform wakes every blocked call on a peer's shutdown or close.

def loopback_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(16)
    except BaseException:
        server.close()
        raise
    return server


def loopback_connect(host, port):
    """The relay's only egress: a loopback address, or localhost, which is 127.0.0.1 here without any lookup."""
    if host == "localhost":
        host = "127.0.0.1"
    if not ipaddress.ip_address(host).is_loopback:
        raise PermissionError("relay-destination-not-loopback")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    connection = socket.socket(family, socket.SOCK_STREAM)
    try:
        connection.settimeout(CONNECT_SECONDS)
        connection.connect((host, port))
        connection.settimeout(None)
    except BaseException:
        connection.close()
        raise
    return connection


def _loopback_destination(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _shutdown(connection):
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except (OSError, ValueError):
        pass


def _close(connection):
    _shutdown(connection)
    try:
        connection.close()
    except OSError:
        pass


def _wait(connection, stopped, deadline=None):
    """Until ``connection`` is readable; a stop or the deadline ends the wait with a finite ProtocolError."""
    while True:
        if stopped():
            raise ProtocolError("stopped")
        if deadline is not None and time.monotonic() >= deadline:
            raise ProtocolError("handshake-timeout")
        try:
            readable, _, _ = select.select([connection], [], [], POLL_SECONDS)
        except (OSError, ValueError):
            raise ProtocolError("stopped") from None
        if readable:
            return


def _receive(connection, size, stopped, deadline=None):
    _wait(connection, stopped, deadline)
    return connection.recv(size)


def _exact(connection, size, stopped, deadline=None):
    data = b""
    while len(data) < size:
        chunk = _receive(connection, size - len(data), stopped, deadline)
        if not chunk:
            raise ProtocolError("peer-closed")
        data += chunk
    return data


def _token(value, limit=64):
    text = value.decode("ascii", "replace") if isinstance(value, bytes) else str(value)
    return "".join(character if 32 < ord(character) < 127 else "?" for character in text)[:limit]


# ---- The relay -------------------------------------------------------------------------------------------------

class Relay:
    """One SSH server and one SOCKS5 relay on the loopback, sharing a record of what each peer did.

    ``user`` and ``authorized_public`` name the one account and ed25519 key it accepts; ``host_seed`` is its
    host key. ``listener`` and ``connector`` are the socket seams; offline tests pass socket pairs instead.
    """

    def __init__(self, *, user, authorized_public, host_seed, listener=loopback_listener, connector=loopback_connect):
        if not user or len(authorized_public) != 32 or len(host_seed) != 32:
            raise ValueError("relay-identity")
        self.user, self.authorized_blob = user, ed25519_blob(authorized_public)
        self.host_seed, self.host_public = host_seed, ed25519_public(host_seed)
        self.host_blob = ed25519_blob(self.host_public)
        self.listener, self.connector = listener, connector
        self.lock = threading.Lock()
        self.sessions, self.socks = [], []
        self.live = set()
        self.threads = []
        self.ssh_server = self.socks_server = self.ssh_accept = None
        self.ssh_port = self.socks_port = None
        self.ssh_stopped = threading.Event()
        self.closed = threading.Event()

    # Lifetime.
    def start(self):
        if self.ssh_server is not None or self.closed.is_set():
            raise ValueError("relay-started-once")
        self.socks_server = self.listener()
        try:
            self.ssh_server = self.listener()
        except BaseException:
            _close(self.socks_server)
            raise
        self.socks_port = self.socks_server.getsockname()[1]
        self.ssh_port = self.ssh_server.getsockname()[1]
        self._thread(self._accept, self.socks_server, self.serve_socks, self.closed.is_set)
        self.ssh_accept = self._thread(self._accept, self.ssh_server, self.serve_ssh, self.ssh_stopped.is_set)
        return self

    def _thread(self, target, *args):
        thread = threading.Thread(target=target, args=args, daemon=True, name="ssh-relay-fixture")
        with self.lock:
            self.threads.append(thread)
        thread.start()
        return thread

    def _accept(self, server, handler, stopped):
        """The listener's own thread: it accepts until stopped, then closes the listener itself."""
        try:
            while True:
                try:
                    _wait(server, stopped)
                    connection, _ = server.accept()
                except (OSError, ProtocolError):
                    return
                if stopped():
                    _close(connection)
                    return
                self._thread(handler, connection)
        finally:
            _close(server)

    def host_key_line(self, comment=None):
        return public_key_line(self.host_public, comment)

    def stop_ssh(self, seconds=5.0):
        """The relay is stopped: once this returns its SSH port refuses, and every SSH session and channel ends.
        The SOCKS relay stays. True when the SSH listener is closed within ``seconds``."""
        self.ssh_stopped.set()
        with self.lock:
            live = [connection for kind, connection in self.live if kind == "ssh"]
        for connection in live:
            _shutdown(connection)
        if self.ssh_accept is not None:
            self.ssh_accept.join(seconds)
            return not self.ssh_accept.is_alive()
        return True

    def close(self, seconds=5.0):
        """Everything ends: both listeners, every session, channel and relayed socket. True when every thread
        ended within ``seconds`` in all; a thread still alive is a daemon of this process."""
        self.ssh_stopped.set()
        self.closed.set()
        with self.lock:
            live = [connection for _, connection in self.live]
        for connection in live:
            _shutdown(connection)
        deadline = time.monotonic() + seconds
        while True:
            with self.lock:
                threads = [thread for thread in self.threads if thread is not threading.current_thread()]
            for thread in threads:
                thread.join(max(0.0, deadline - time.monotonic()))
            with self.lock:
                grown = len([thread for thread in self.threads if thread is not threading.current_thread()]) != len(threads)
            if not grown or time.monotonic() >= deadline:
                return not any(thread.is_alive() for thread in threads)

    def facts(self):
        """A copy of every record: sessions in accept order with their auth and channels, then SOCKS requests."""
        with self.lock:
            return {"sessions": [dict(row, auth=[dict(item) for item in row["auth"]], channels=[dict(item) for item in row["channels"]])
                                 for row in self.sessions],
                    "socks": [dict(row) for row in self.socks]}

    def _hold(self, kind, connection):
        with self.lock:
            self.live.add((kind, connection))
        if (self.ssh_stopped if kind == "ssh" else self.closed).is_set():
            _shutdown(connection)

    def _release(self, kind, connection):
        """The owner's close of one socket it held."""
        with self.lock:
            self.live.discard((kind, connection))
        _close(connection)

    # SOCKS5 (RFC 1928): no authentication, CONNECT to a loopback destination only.
    def serve_socks(self, connection):
        self._hold("socks", connection)
        record = {"ordinal": None, "host": None, "port": None, "result": "bad-request", "up": 0, "down": 0}
        target, down, stopped = None, None, self.closed.is_set
        deadline = time.monotonic() + HANDSHAKE_SECONDS
        try:
            with self.lock:
                if len(self.socks) >= MAX_RECORDS:
                    raise ProtocolError("socks-record-bound")
                record["ordinal"] = len(self.socks)
                self.socks.append(record)
            version, count = _exact(connection, 2, stopped, deadline)
            methods = _exact(connection, count, stopped, deadline)
            if version != 5 or 0 not in methods:
                connection.sendall(b"\x05\xff")
                return
            connection.sendall(b"\x05\x00")
            version, command, _, kind = _exact(connection, 4, stopped, deadline)
            if kind == 1:
                host = socket.inet_ntoa(_exact(connection, 4, stopped, deadline))
            elif kind == 3:
                host = _exact(connection, _exact(connection, 1, stopped, deadline)[0], stopped, deadline).decode("ascii", "replace")
            elif kind == 4:
                host = socket.inet_ntop(socket.AF_INET6, _exact(connection, 16, stopped, deadline))
            else:
                connection.sendall(b"\x05\x08\x00\x01" + bytes(6))
                return
            port = struct.unpack(">H", _exact(connection, 2, stopped, deadline))[0]
            with self.lock:
                record.update(host=_token(host, 255), port=port)
            if version != 5 or command != 1:
                with self.lock:
                    record["result"] = "unsupported-command"
                connection.sendall(b"\x05\x07\x00\x01" + bytes(6))
                return
            if not _loopback_destination(host):
                with self.lock:
                    record["result"] = "refused-not-loopback"
                connection.sendall(b"\x05\x02\x00\x01" + bytes(6))
                return
            try:
                target = self.connector(host, port)
            except (OSError, ValueError):
                with self.lock:
                    record["result"] = "connect-failed"
                connection.sendall(b"\x05\x05\x00\x01" + bytes(6))
                return
            self._hold("socks", target)
            with self.lock:
                record["result"] = "connected"
            connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack(">H", port))
            down = self._thread(_pump, target, connection, record, "down", self.lock, stopped)
            _pump(connection, target, record, "up", self.lock, stopped)
            down.join(HANDSHAKE_SECONDS)
        except (OSError, ProtocolError, ValueError):
            pass
        finally:
            if down is not None and down.is_alive():
                _shutdown(target)
                down.join(HANDSHAKE_SECONDS)
            if target is not None:
                self._release("socks", target)
            self._release("socks", connection)

    # SSH.
    def serve_ssh(self, connection):
        self._hold("ssh", connection)
        session = None
        try:
            with self.lock:
                if len(self.sessions) >= MAX_RECORDS:
                    raise ProtocolError("session-record-bound")
            session = _Session(self, connection)
            session.run()
        except ProtocolError as error:
            if session is not None:
                session.note(end=session.record["end"] or ("stopped" if self.ssh_stopped.is_set() else str(error)))
        except (OSError, ValueError):
            pass
        finally:
            if session is not None:
                session.finish()
            self._release("ssh", connection)


class HttpsOrigin:
    """The subscription origin: one HTTPS path on 127.0.0.1 that answers ``body``, every other path 404.

    The pinned https_subscription_relay_fixture gives a TLS handshake 0.25 s, which a JVM's first handshake through
    this relay's Python ciphers exceeds (sing-box 1.13.4 and JDK 17 on loopback: "Remote host terminated the
    handshake"). Here each handshake and request read has HANDSHAKE_SECONDS. ``context`` is the server's
    ssl.SSLContext; ``listener`` the socket seam. Records hold the method, path, status and body length only.
    """

    def __init__(self, context, path, body, *, listener=loopback_listener):
        if not path.startswith("/") or not isinstance(body, bytes):
            raise ValueError("origin-path-or-body")
        self.context, self.path, self.body, self.listener = context, path, body, listener
        self.lock, self.requests, self.threads, self.live = threading.Lock(), [], [], set()
        self.server, self.port, self.closed = None, None, threading.Event()

    def start(self):
        if self.server is not None or self.closed.is_set():
            raise ValueError("origin-started-once")
        self.server = self.listener()
        self.port = self.server.getsockname()[1]
        thread = threading.Thread(target=self._accept, daemon=True, name="ssh-relay-origin")
        self.threads.append(thread)
        thread.start()
        return self

    def url(self):
        return "https://localhost:" + str(self.port) + self.path

    def _accept(self):
        try:
            while True:
                try:
                    _wait(self.server, self.closed.is_set)
                    connection, _ = self.server.accept()
                except (OSError, ProtocolError):
                    return
                thread = threading.Thread(target=self.serve, args=(connection,), daemon=True, name="ssh-relay-origin")
                with self.lock:
                    self.threads.append(thread)
                thread.start()
        finally:
            _close(self.server)

    def serve(self, connection):
        """One request on one connection, owned and closed by this thread."""
        record = {"method": None, "path": None, "status": None, "bytes": 0}
        with self.lock:
            self.live.add(connection)
        stream = None
        try:
            _wait(connection, self.closed.is_set, time.monotonic() + HANDSHAKE_SECONDS)
            connection.settimeout(HANDSHAKE_SECONDS)
            stream = self.context.wrap_socket(connection, server_side=True)
            with self.lock:
                self.live.discard(connection)
                self.live.add(stream)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = stream.recv(4096)
                if not chunk or len(head) > 16384:
                    return
                head += chunk
            line = head.split(b"\r\n", 1)[0].decode("ascii", "replace").split(" ")
            method, path = (line + ["", ""])[:2]
            found = method == "GET" and path == self.path
            body = self.body if found else b"not found\n"
            record.update(method=_token(method, 16), path=_token(path, 255), status=200 if found else 404, bytes=len(body))
            with self.lock:
                if len(self.requests) < MAX_RECORDS:
                    self.requests.append(record)
            stream.sendall(("HTTP/1.1 " + ("200 OK" if found else "404 Not Found") + "\r\nContent-Type: text/plain; charset=utf-8"
                            "\r\nContent-Length: " + str(len(body)) + "\r\nConnection: close\r\n\r\n").encode("ascii") + body)
        except (OSError, ValueError, ProtocolError):
            pass
        finally:
            with self.lock:
                self.live.discard(connection)
                self.live.discard(stream)
            _close(stream if stream is not None else connection)

    def served(self):
        """Every request read so far, in order."""
        with self.lock:
            return [dict(row) for row in self.requests]

    def close(self, seconds=5.0):
        self.closed.set()
        with self.lock:
            live = list(self.live)
        for connection in live:
            _shutdown(connection)
        deadline = time.monotonic() + seconds
        with self.lock:
            threads = list(self.threads)
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        return not any(thread.is_alive() for thread in threads)


def _pump(source, destination, record, field, lock, stopped):
    """Copy one direction until EOF or a stop, then half-close the other side; counts only, never bytes."""
    try:
        while True:
            data = _receive(source, 65536, stopped)
            if not data:
                break
            destination.sendall(data)
            with lock:
                record[field] += len(data)
    except (OSError, ProtocolError):
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except (OSError, ValueError):
            pass


class _Channel:
    """One direct-tcpip channel. Every message of it is sent under its condition, so none follows its CLOSE:
    golang.org/x/crypto/ssh drops a channel on that CLOSE and ends the whole connection on a later message.
    The pump thread owns the target socket and closes it."""

    def __init__(self, session, local, remote, window, maximum, target, record):
        self.session, self.local, self.remote, self.target, self.record = session, local, remote, target, record
        self.remote_window, self.remote_maximum, self.local_window = window, max(1, min(maximum, MAX_DATA)), WINDOW
        self.condition = threading.Condition()
        self.close_sent = self.close_received = False
        self.ended = threading.Event()

    def stopped(self):
        return self.ended.is_set() or self.session.relay.ssh_stopped.is_set()

    def pump(self):
        """Target bytes to the client within its window; at target EOF an EOF and a CLOSE."""
        try:
            while True:
                data = _receive(self.target, MAX_DATA, self.stopped)
                if not data:
                    break
                while data:
                    with self.condition:
                        while self.remote_window == 0 and not (self.close_received or self.close_sent or self.stopped()):
                            self.condition.wait(POLL_SECONDS)
                        if self.close_received or self.close_sent or self.stopped():
                            return
                        size = min(len(data), self.remote_window, self.remote_maximum)
                        self.remote_window -= size
                        self.session.send(bytes([CHANNEL_DATA]) + uint32(self.remote) + string(data[:size]))
                    with self.session.relay.lock:
                        self.record["fromTarget"] += size
                    data = data[size:]
            with self.condition:
                if self.close_received or self.close_sent or self.stopped():
                    return
                self.session.send(bytes([CHANNEL_EOF]) + uint32(self.remote))
            self.close()
        except ProtocolError:
            pass
        except OSError:
            self.session.abort()
        finally:
            self.session.relay._release("ssh", self.target)

    def close(self):
        with self.condition:
            if not self.close_sent:
                self.close_sent = True
                self.session.send(bytes([CHANNEL_CLOSE]) + uint32(self.remote))

    def end(self):
        """The session's end, or the client's CLOSE: the pump stops and closes the target."""
        with self.condition:
            self.close_received = True
            self.ended.set()
            self.condition.notify_all()
        _shutdown(self.target)


class _Session:
    """One SSH connection: the reader is this thread, writers share ``send``; channels pump their own targets."""

    def __init__(self, relay, connection):
        self.relay, self.connection = relay, connection
        self.buffer = b""
        self.send_lock = threading.Lock()
        self.send_sequence = self.receive_sequence = 0
        self.send_cipher = self.receive_cipher = None
        self.session_id = None
        self.deadline = time.monotonic() + HANDSHAKE_SECONDS
        self.channels, self.next_channel, self.pumps = {}, 0, []
        self.record = {"ordinal": None, "clientVersion": None, "kex": None, "cipher": None, "strict": False,
                       "keysExchanged": False, "auth": [], "authenticated": False, "authenticatedKey": None,
                       "channels": [], "end": None}
        with relay.lock:
            self.record["ordinal"] = len(relay.sessions)
            relay.sessions.append(self.record)

    def note(self, **values):
        with self.relay.lock:
            self.record.update(values)

    # Transport.
    def fill(self):
        chunk = _receive(self.connection, 65536, self.relay.ssh_stopped.is_set, self.deadline)
        if not chunk:
            raise ProtocolError("peer-closed")
        self.buffer += chunk

    def read_line(self):
        while b"\n" not in self.buffer:
            if len(self.buffer) > 8192:
                raise ProtocolError("version-bound")
            self.fill()
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line.rstrip(b"\r")

    def read(self, size):
        while len(self.buffer) < size:
            self.fill()
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def receive(self):
        sequence = self.receive_sequence
        self.receive_sequence = (sequence + 1) & _MASK
        # Block alignment is the sender's duty; like golang.org/x/crypto/ssh, the reader checks bounds and padding only.
        head = self.read(4)
        if self.receive_cipher is None:
            length = struct.unpack(">I", head)[0]
            if not 5 <= length <= MAX_PACKET:
                raise ProtocolError("packet-length")
            body = self.read(length)
        else:
            length = self.receive_cipher.length(sequence, head)
            if not 5 <= length <= MAX_PACKET:
                raise ProtocolError("packet-length")
            body = self.receive_cipher.open(sequence, head, self.read(length), self.read(16))
        padding = body[0]
        if padding < 4 or padding + 1 >= len(body):
            raise ProtocolError("packet-padding")
        payload = body[1:len(body) - padding]
        if not payload:
            raise ProtocolError("packet-empty")
        return payload

    def send(self, payload):
        with self.send_lock:
            aligned = 0 if self.send_cipher is None else 4  # An encrypted length is not part of the alignment.
            padding = 8 - (len(payload) + 5 - aligned) % 8
            padding += 8 if padding < 4 else 0
            packet = uint32(len(payload) + padding + 1) + bytes([padding]) + payload + os.urandom(padding)
            sequence = self.send_sequence
            self.send_sequence = (sequence + 1) & _MASK
            wire = packet if self.send_cipher is None else self.send_cipher.seal(sequence, packet)
            self.connection.sendall(wire)

    def disconnect(self, reason, code=2):
        try:
            self.send(bytes([DISCONNECT]) + uint32(code) + string(reason) + string(""))
        except OSError:
            pass
        raise ProtocolError(reason)

    def abort(self):
        _shutdown(self.connection)

    # Key exchange.
    def run(self):
        self.connection.sendall(SERVER_VERSION + b"\r\n")
        for _ in range(32):
            line = self.read_line()
            if line.startswith(b"SSH-"):
                break
        else:
            raise ProtocolError("no-version")
        if not line.startswith(b"SSH-2.0-") or len(line) > 253:
            raise ProtocolError("version")
        self.note(clientVersion=_token(line))
        client_version = line
        server_init = (bytes([KEXINIT]) + os.urandom(16) + string(",".join((*KEX, STRICT_SERVER))) + string(HOST_KEY_ALGORITHM)
                       + string(CIPHER) * 2 + string(MAC) * 2 + string("none") * 2 + string("") * 2 + b"\0" + uint32(0))
        self.send(server_init)
        client_init = self.receive()
        if client_init[0] != KEXINIT:
            raise ProtocolError("first-message-not-kexinit")
        offer = Reader(client_init[1:])
        offer.take(16)
        kex_names, host_names, ciphers_out, ciphers_in = offer.names(), offer.names(), offer.names(), offer.names()
        for _ in range(6):
            offer.names()
        guessed = offer.boolean()
        strict = STRICT_CLIENT in kex_names
        kex = next((name for name in kex_names if name in KEX), None)
        if kex is None or HOST_KEY_ALGORITHM not in host_names or CIPHER not in ciphers_out or CIPHER not in ciphers_in:
            self.disconnect("no-common-algorithm", 3)
        self.note(kex=kex, cipher=CIPHER, strict=strict)
        message = self.receive()
        if guessed and (kex_names[:1] != [kex] or host_names[:1] != [HOST_KEY_ALGORITHM]):
            message = self.receive()  # A wrong first guess is discarded (RFC 4253 section 7).
        if message[0] != KEX_ECDH_INIT:
            raise ProtocolError("expected-kex-init")
        client_public = Reader(message[1:]).string(64)
        if len(client_public) != 32:
            self.disconnect("kex-public-length", 3)
        private = os.urandom(32)
        server_public = x25519(private, (9).to_bytes(32, "little"))
        shared = x25519(private, client_public)
        if shared == bytes(32):
            self.disconnect("kex-shared-zero", 3)
        secret = mpint(int.from_bytes(shared, "big"))
        exchange = hashlib.sha256(string(client_version) + string(SERVER_VERSION) + string(client_init) + string(server_init)
                                  + string(self.relay.host_blob) + string(client_public) + string(server_public) + secret).digest()
        self.session_id = exchange
        signature = string(HOST_KEY_ALGORITHM) + string(ed25519_sign(self.relay.host_seed, exchange))
        self.send(bytes([KEX_ECDH_REPLY]) + string(self.relay.host_blob) + string(server_public) + string(signature))
        self.send(bytes([NEWKEYS]))

        def derive(letter):
            key = hashlib.sha256(secret + exchange + letter + exchange).digest()
            return key + hashlib.sha256(secret + exchange + key).digest()
        self.send_cipher = PacketCipher(derive(b"D"))
        if strict:
            self.send_sequence = 0
        while True:
            message = self.receive()
            if message[0] == NEWKEYS:
                break
            if strict or message[0] not in (IGNORE, DEBUG):
                raise ProtocolError("expected-newkeys")
        self.receive_cipher = PacketCipher(derive(b"C"))
        if strict:
            self.receive_sequence = 0
        self.note(keysExchanged=True)
        self.deadline = None
        self.serve()

    # Authentication and connection.
    def serve(self):
        attempts = 0
        while True:
            message = self.receive()
            kind, body = message[0], Reader(message[1:])
            if kind in (IGNORE, DEBUG, UNIMPLEMENTED):
                continue
            if kind == DISCONNECT:
                self.note(end="client-disconnect")
                return
            if kind == KEXINIT:
                self.disconnect("rekey-unsupported")
            if kind == SERVICE_REQUEST:
                if body.text() != "ssh-userauth" or self.session_id is None:
                    self.disconnect("service-not-available", 7)
                self.send(bytes([SERVICE_ACCEPT]) + string("ssh-userauth"))
            elif kind == USERAUTH_REQUEST:
                attempts += 1
                if attempts > MAX_AUTH_ATTEMPTS:
                    self.disconnect("too-many-authentication-attempts", 14)
                self.authenticate(body)
            elif not self.record["authenticated"]:
                self.disconnect("not-authenticated")
            elif kind == GLOBAL_REQUEST:
                body.text()
                if body.boolean():
                    self.send(bytes([REQUEST_FAILURE]))
            elif kind == CHANNEL_OPEN:
                self.open_channel(body)
            elif kind in (CHANNEL_DATA, CHANNEL_EXTENDED_DATA, CHANNEL_WINDOW_ADJUST, CHANNEL_EOF, CHANNEL_CLOSE, CHANNEL_REQUEST):
                self.channel_message(kind, body)
            else:
                self.send(bytes([UNIMPLEMENTED]) + uint32((self.receive_sequence - 1) & _MASK))

    def authenticate(self, body):
        user, service, method = body.text(), body.text(), body.text()
        entry = {"user": _token(user), "method": _token(method), "algorithm": None, "key": None, "signed": False, "result": "failure"}
        with self.relay.lock:
            if len(self.record["auth"]) < MAX_RECORDS:
                self.record["auth"].append(entry)
        if self.record["authenticated"]:
            self.disconnect("authenticated-twice")
        accepted = False
        if method == "publickey" and service == "ssh-connection":
            signed, algorithm, blob = body.boolean(), body.text(), body.string(4096)
            update = {"algorithm": _token(algorithm), "key": fingerprint(blob), "signed": signed}
            known = user == self.relay.user and algorithm == HOST_KEY_ALGORITHM and blob == self.relay.authorized_blob
            if known and not signed:
                update["result"] = "pk-ok"
                self.send(bytes([USERAUTH_PK_OK]) + string(algorithm) + string(blob))
            elif known:
                proof = Reader(body.string(4096))
                kind, raw = proof.text(), proof.string(128)
                data = (string(self.session_id) + bytes([USERAUTH_REQUEST]) + string(user) + string(service)
                        + string("publickey") + b"\x01" + string(algorithm) + string(blob))
                accepted = kind == HOST_KEY_ALGORITHM and ed25519_verify(blob[-32:], data, raw)
                update["result"] = "success" if accepted else "failure"
            with self.relay.lock:
                entry.update(update)
            if known and not signed:
                return
        if accepted:
            with self.relay.lock:
                self.record.update(authenticated=True, authenticatedKey=entry["key"])
            self.send(bytes([USERAUTH_SUCCESS]))
        else:
            self.send(bytes([USERAUTH_FAILURE]) + string("publickey") + b"\0")

    def open_channel(self, body):
        kind, remote, window, maximum = body.text(), body.uint32(), body.uint32(), body.uint32()
        record = {"type": _token(kind), "host": None, "port": None, "result": "unknown-type", "toTarget": 0, "fromTarget": 0}
        with self.relay.lock:
            if len(self.record["channels"]) >= MAX_RECORDS:
                self.disconnect("channel-record-bound")
            self.record["channels"].append(record)
        reason, target = UNKNOWN_CHANNEL_TYPE, None
        if kind == "direct-tcpip":
            host, port = body.text(255), body.uint32()
            body.text(255)
            body.uint32()
            with self.relay.lock:
                record.update(host=_token(host, 255), port=port, result="prohibited")
            reason = PROHIBITED
            if host in ("127.0.0.1", "localhost") and port == self.relay.socks_port and len(self.channels) < 64:
                try:
                    target = self.relay.connector(host, port)
                except (OSError, ValueError):
                    reason = CONNECT_FAILED
                    with self.relay.lock:
                        record["result"] = "connect-failed"
        if target is None:
            self.send(bytes([CHANNEL_OPEN_FAILURE]) + uint32(remote) + uint32(reason) + string(record["result"]) + string(""))
            return
        self.relay._hold("ssh", target)
        local, self.next_channel = self.next_channel, self.next_channel + 1
        channel = _Channel(self, local, remote, window, maximum, target, record)
        self.channels[local] = channel
        with self.relay.lock:
            record["result"] = "opened"
        self.send(bytes([CHANNEL_OPEN_CONFIRMATION]) + uint32(remote) + uint32(local) + uint32(WINDOW) + uint32(MAX_DATA))
        self.pumps.append(self.relay._thread(channel.pump))

    def channel_message(self, kind, body):
        channel = self.channels.get(body.uint32())
        if channel is None:
            self.disconnect("unknown-channel")
        if kind == CHANNEL_WINDOW_ADJUST:
            with channel.condition:
                channel.remote_window = min(channel.remote_window + body.uint32(), _MASK)
                channel.condition.notify_all()
        elif kind == CHANNEL_DATA:
            data = body.string(MAX_PACKET)
            channel.local_window -= len(data)
            if channel.local_window < 0:
                self.disconnect("channel-window-exceeded")
            if not channel.close_sent:
                try:
                    channel.target.sendall(data)
                    with self.relay.lock:
                        channel.record["toTarget"] += len(data)
                except OSError:
                    channel.close()
            with channel.condition:
                if channel.local_window < WINDOW // 2 and not channel.close_sent:
                    self.send(bytes([CHANNEL_WINDOW_ADJUST]) + uint32(channel.remote) + uint32(WINDOW - channel.local_window))
                    channel.local_window = WINDOW
        elif kind == CHANNEL_EXTENDED_DATA:
            self.disconnect("extended-data-unexpected")
        elif kind == CHANNEL_EOF:
            try:
                channel.target.shutdown(socket.SHUT_WR)
            except (OSError, ValueError):
                pass
        elif kind == CHANNEL_REQUEST:
            body.text()
            if body.boolean():
                self.send(bytes([CHANNEL_FAILURE]) + uint32(channel.remote))
        else:
            channel.end()
            channel.close()
            del self.channels[channel.local]

    def finish(self):
        for channel in list(self.channels.values()):
            channel.end()
        self.channels.clear()
        for pump in self.pumps:
            pump.join(HANDSHAKE_SECONDS)
        with self.relay.lock:
            if self.record["end"] is None:
                self.record["end"] = "stopped" if self.relay.ssh_stopped.is_set() else "closed"
