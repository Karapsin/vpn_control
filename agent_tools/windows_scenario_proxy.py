"""Generated guest files of the windows-proxy-lifecycle family and its windows-scoped-tun rows.

Pure functions of the row's variant, the operation's guest paths and the installed
runtime's digest: the literal harness the dedicated driver reads, the TLS material of
the in-guest loopback fixture and the traffic sampler's input. A TUN row's stage inputs
come only from this job: its context stage's administrator SID, the one UAC decision
of its operation and the pinned TUN collector source. The host job publishes
what they return and pins it like any other file. Standard library only: no listener,
no process and no clock but the one passed in. The private key exists only in the job's
memory and the guest workspace (ProgramData, read-only for the ordinary user): QGA wire
files keep replies, never the write requests that carry it, so it never reaches host disk.
"""
import base64
import hashlib
import json
import math
import struct
import time

PROXY_VARIANTS = ("gui-pending", "find-best-success", "find-best-verification-failure", "find-best-cancel")
BRANCH_VARIANTS = ("generated", "custom", "large", "prepare-failure", "commit-readiness-failure", "sibling-off")
# The owner's own scheduled refresh with no GUI attached: windows_lifecycle_scheduled_cases and the sampler.
SCHEDULED_VARIANTS = ("scheduled-refresh",)
VARIANTS = PROXY_VARIANTS + BRANCH_VARIANTS + SCHEDULED_VARIANTS
TRAFFIC_VARIANTS = frozenset({"gui-pending", *BRANCH_VARIANTS, *SCHEDULED_VARIANTS})
# windows-scoped-tun.<variant>: the same action and runtime, plus windows_tun_stages; a grant adds the direct sampler.
TUN_VARIANTS = ("restart-deny", "restart-grant", "find-best-deny", "find-best-grant")
TUN_GRANT_VARIANTS = frozenset({"restart-grant", "find-best-grant"})
PROGRAM_DATA = "C:\\ProgramData"
# Role -> workspace leaf of every file this module writes; the trafficInput role only where a sampler runs.
GENERATED = {"harness": "proxy-harness.py", "certificate": "proxy-localhost.pem", "privateKey": "proxy-localhost.key",
             "trustStore": "proxy-trust.jks", "trafficInput": "proxy-traffic.json", "samplerInput": "tun-direct-traffic.json"}
RUNTIME_ROLE, RUNTIME_LEAF = "runtimeTool", "sing-box.exe"
RUNTIME_ENTRY = "bin/windows-amd64/sing-box.exe"  # DesktopSingBoxResolver's bundled resource.
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
TRUST_PASSWORD = "changeit"  # The public keytool default the runtime stages hand the JVM.
MAX_FIXTURE_SECONDS = 1800  # The fixture lease outlasts every stage of the row; a stop ends it first.
FRONTEND_CRASH = "exact-owned-original-gui-handle"
TRAY_UNPROVEN = "tray-unproven"  # No tray proof exists on this route; the field only names that.
_RSA_BITS = 2048
_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_SMALL_PRIMES = tuple(p for p in range(3, 2000, 2) if all(p % q for q in range(3, math.isqrt(p) + 1, 2)))


def generated_roles(variant):
    if variant in TUN_VARIANTS:
        return ("harness", "certificate", "privateKey", "trustStore", *(("samplerInput",) if variant in TUN_GRANT_VARIANTS else ()))
    if variant not in VARIANTS:
        raise ValueError("proxy_variant")
    return tuple(role for role in GENERATED if role not in ("trafficInput", "samplerInput") or role == "trafficInput" and variant in TRAFFIC_VARIANTS)


def _der(tag, body):
    if len(body) < 0x80:
        return bytes((tag, len(body))) + body
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes((tag, 0x80 | len(size))) + size + body


def _integer(value):
    return _der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def _sequence(*items):
    return _der(0x30, b"".join(items))


def _oid(dotted):
    first, second, *rest = (int(part) for part in dotted.split("."))
    body = bytearray((40 * first + second,))
    for value in rest:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        body.extend(reversed(chunk))
    return _der(0x06, bytes(body))


def _utc(seconds):
    return _der(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(seconds)).encode("ascii"))


def _pem(label, der):
    text = base64.b64encode(der).decode("ascii")
    lines = "\n".join(text[start:start + 64] for start in range(0, len(text), 64))
    return ("-----BEGIN " + label + "-----\n" + lines + "\n-----END " + label + "-----\n").encode("ascii")


def _probable_prime(candidate, randbits, rounds=40):
    odd, shifts = candidate - 1, 0
    while not odd & 1:
        odd >>= 1
        shifts += 1
    for _ in range(rounds):
        witness = 2 + randbits(candidate.bit_length()) % (candidate - 3)
        value = pow(witness, odd, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(shifts - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _prime(bits, randbits):
    while True:
        # The two top bits make the product exactly twice as long.
        candidate = randbits(bits) | (3 << (bits - 2)) | 1
        if all(candidate % small for small in _SMALL_PRIMES) and _probable_prime(candidate, randbits):
            return candidate


def _rsa(randbits):
    exponent = 65537
    while True:
        p, q = _prime(_RSA_BITS // 2, randbits), _prime(_RSA_BITS // 2, randbits)
        phi = (p - 1) * (q - 1)
        if p != q and math.gcd(exponent, phi) == 1:
            return p * q, exponent, pow(exponent, -1, phi), p, q


def _sign(message, modulus, private):
    size = (modulus.bit_length() + 7) // 8
    digest = _DIGEST_INFO + hashlib.sha256(message).digest()
    encoded = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
    return pow(int.from_bytes(encoded, "big"), private, modulus).to_bytes(size, "big")


def _utf(text):
    raw = text.encode("ascii")
    return struct.pack(">H", len(raw)) + raw


def trust_store(certificate, created_ms, password=TRUST_PASSWORD):
    """A JKS trust store holding one trusted certificate; JDK 17 reads it under its PKCS12 default type."""
    body = struct.pack(">III", 0xFEEDFEED, 2, 1) + struct.pack(">I", 2) + _utf("owned-fixture") + struct.pack(">Q", created_ms)
    body += _utf("X.509") + struct.pack(">I", len(certificate)) + certificate
    key = b"".join(struct.pack(">H", ord(character)) for character in password) + b"Mighty Aphrodite"
    return body + hashlib.sha1(key + body, usedforsecurity=False).digest()


def material(randbits, now):
    """A self-signed localhost certificate, its RSA key and a trust store holding it.

    ``randbits`` is secrets.randbits on the host; ``now`` is seconds since the epoch. The
    certificate is valid from two days before ``now`` to seven days after, which covers a
    guest clock a little off the host's.
    """
    modulus, exponent, private, p, q = _rsa(randbits)
    algorithm = _sequence(_oid(_SHA256_WITH_RSA), b"\x05\x00")
    name = _sequence(_der(0x31, _sequence(_oid("2.5.4.3"), _der(0x0C, b"localhost"))))
    public = _sequence(_sequence(_oid("1.2.840.113549.1.1.1"), b"\x05\x00"),
                       _der(0x03, b"\x00" + _sequence(_integer(modulus), _integer(exponent))))
    extensions = _der(0xA3, _sequence(
        _sequence(_oid("2.5.29.19"), _der(0x01, b"\xff"), _der(0x04, _sequence(_der(0x01, b"\xff")))),
        _sequence(_oid("2.5.29.17"), _der(0x04, _sequence(_der(0x82, b"localhost"))))))
    serial = randbits(63) | 1 << 62
    tbs = _sequence(_der(0xA0, _integer(2)), _integer(serial), algorithm, name,
                    _sequence(_utc(int(now) - 2 * 86400), _utc(int(now) + 7 * 86400)), name, public, extensions)
    certificate = _sequence(tbs, algorithm, _der(0x03, b"\x00" + _sign(tbs, modulus, private)))
    key = _sequence(*(_integer(value) for value in (0, modulus, exponent, private, p, q, private % (p - 1),
                                                    private % (q - 1), pow(q, -1, p))))
    return {"certificate": _pem("CERTIFICATE", certificate), "privateKey": _pem("RSA PRIVATE KEY", key),
            "trustStore": trust_store(certificate, int(now) * 1000)}


def fixture_body(operation):
    return "vpn-control-proxy-" + operation


def traffic_input(variant, operation):
    """The sampler's own input; the cases replace the port with the product's live mixed listener.

    A scheduled refresh runs one five-minute interval after the case's manual refresh, and the case waits two minutes
    past that: 1,800 samples a quarter second apart (the worker's most), started after the case's own on, run past it.
    """
    count, interval = {"gui-pending": (1800, 0.2), "scheduled-refresh": (1800, 0.25)}.get(variant, (8, 0.05))
    value = {"schemaVersion": 1, "mixedPort": 1, "expectedBodyHex": fixture_body(operation).encode("ascii").hex(),
             "sampleCount": count, "intervalSeconds": interval, "ioTimeoutSeconds": 5}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def sampler_input(operation):
    """windows_tun_direct_sampler's input: the owned upstream's body, read back over plain HTTP through the TUN."""
    value = {"schemaVersion": 1, "expectedBodyHex": fixture_body(operation).encode("ascii").hex(), "sampleCount": 8,
             "intervalSeconds": 0.25, "ioTimeoutSeconds": 5}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def tun_inputs(variant, *, paths, admissions, tun):
    """windows_tun_stages' closed inputs: the context stage's administrator SID, the one UAC decision of this
    operation and the pinned TUN collector source, beside the paths and admissions of this same row."""
    if type(tun) is not dict or set(tun) != {"administratorSid", "decisionId", "collectorSourceSha256"}:
        raise ValueError("tun_inputs")
    value = {"schemaVersion": 1, "variant": variant, "pendingLocation": "Owned B",
             "runtimeConfigPath": paths["productWorkspace"] + "\\runtime-config.json", "guiPath": paths["installed"] + "\\vpn-control.exe",
             "installedAdmissionArtifactId": admissions["installed"], "ordinaryContextArtifactId": admissions["context"],
             "expectedApprovingAdminSid": tun["administratorSid"], "uacDecisionId": tun["decisionId"], "programData": PROGRAM_DATA,
             "collectorSourceSha256": tun["collectorSourceSha256"]}
    if variant in TUN_GRANT_VARIANTS:
        value.update(samplerPath=paths["file:sampler"], samplerInputPath=paths["file:samplerInput"])
    return value


def harness(variant, *, operation, paths, runtime_sha256, source_sha, admissions, tun=None):
    """The literal harness: one docstring and the two constants the dedicated driver allows."""
    if variant not in VARIANTS + TUN_VARIANTS or (tun is not None) != (variant in TUN_VARIANTS):
        raise ValueError("proxy_variant")
    workspace = paths["productWorkspace"]
    runtime = {"schemaVersion": 1, "workspace": workspace, "fixtureRoot": paths["operationRoot"] + "\\fixture",
               "operationId": operation, "fixtureWorkerPath": paths["file:fixture"], "socksSourcePath": paths["file:socks"],
               "httpsSourcePath": paths["file:https"], "certificatePath": paths["file:certificate"],
               "privateKeyPath": paths["file:privateKey"], "trustStorePath": paths["file:trustStore"],
               "runtimeImagePath": workspace + "\\runtime\\tools\\" + RUNTIME_LEAF, "runtimeSha256": runtime_sha256,
               "installedAdmissionArtifactId": admissions["installed"], "materialAdmissionArtifactId": admissions["material"],
               "ordinaryContextArtifactId": admissions["context"], "fixtureBody": fixture_body(operation),
               "maxFixtureSeconds": MAX_FIXTURE_SECONDS}
    value = {"schemaVersion": 1, "variant": variant, "sourceSha": source_sha,
             "modules": {"runtime": paths["file:runtime"], "observer": paths["file:observer"]}, "runtime": runtime, "gui": None}
    if variant == "gui-pending":
        value["gui"] = {"schemaVersion": 1, "guiPath": paths["installed"] + "\\vpn-control.exe",
                        "trafficWorkerPath": paths["file:traffic"], "trafficInputPath": paths["file:trafficInput"],
                        "installedAdmissionArtifactId": admissions["installed"], "fixtureAdmissionArtifactId": admissions["fixture"],
                        "sourceArtifactId": admissions["source"], "frontendCrashScenario": FRONTEND_CRASH,
                        "trayAdmissionArtifactId": TRAY_UNPROVEN}
    if variant in SCHEDULED_VARIANTS:
        value["modules"]["scheduled"] = paths["file:scheduled"]
        value["scheduled"] = {"schemaVersion": 1, "guiPath": paths["installed"] + "\\vpn-control.exe",
                              "trafficWorkerPath": paths["file:traffic"], "trafficInputPath": paths["file:trafficInput"],
                              "installedAdmissionArtifactId": admissions["installed"], "fixtureAdmissionArtifactId": admissions["fixture"]}
    if variant in BRANCH_VARIANTS:
        value["modules"]["branches"] = paths["file:branches"]
        value["branch"] = {"schemaVersion": 1, "fixtureRuntimeToolPath": paths["file:" + RUNTIME_ROLE],
                           "runtimeSha256": runtime_sha256, "listenerScriptPath": paths["file:listener"],
                           "powerShellPath": POWERSHELL, "trafficWorkerPath": paths["file:traffic"],
                           "trafficInputPath": paths["file:trafficInput"], "installedAdmissionArtifactId": admissions["installed"],
                           "ordinaryContextArtifactId": admissions["context"]}
    if variant in TUN_VARIANTS:
        value["modules"]["tun"] = paths["file:tun"]
        value["tun"] = tun_inputs(variant, paths=paths, admissions=admissions, tun=tun)
    family = "windows-scoped-tun." if variant in TUN_VARIANTS else "windows-proxy-lifecycle."
    text = ('"""Literal inputs of ' + family + variant + ' for one operation; no other statement runs."""\n'
            "LIFECYCLE_INPUTS = " + ascii(value) + "\nSYSTEM_COLLECTOR_CLOSE_HOLD = None\n")
    return text.encode("ascii")


def files(variant, *, operation, paths, runtime_sha256, source_sha, admissions, tls, tun=None):
    """Every generated file of one row, by role, from material made once by ``material``."""
    found = {"harness": harness(variant, operation=operation, paths=paths, runtime_sha256=runtime_sha256,
                                source_sha=source_sha, admissions=admissions, tun=tun),
             "certificate": tls["certificate"], "privateKey": tls["privateKey"], "trustStore": tls["trustStore"]}
    if variant in TRAFFIC_VARIANTS:
        found["trafficInput"] = traffic_input(variant, operation)
    if variant in TUN_GRANT_VARIANTS:
        found["samplerInput"] = sampler_input(operation)
    if tuple(found) != generated_roles(variant):
        raise ValueError("proxy_generated_roles")
    return found
