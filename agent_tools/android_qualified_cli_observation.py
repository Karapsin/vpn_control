"""One source-owned, qualified engineering CLI image for Android observation.

The selector is not a path, command, receipt, source hash, or authority flag.
Its reviewed source maps to the already-qualified D32/fae image. This observer
never installs, changes a global profile, acquires a lease, or retires an actor.
"""
from __future__ import annotations
from . import ssh_transport
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import time
import uuid
import zlib

SELECTOR = "qualified-d32-fae-2.2.2"
DIRECT_RESULT_SHA256 = "b4d2d86dc3d50ba92a3b7f6332ce10c49e2859cd8c19f4aaa8db34b8afa9bd25"
PACKAGE_SHA256 = "fae8a09a543ea6266614d6ddba3adf26a4edd24aec5f32d8b68e6d63e2a36e9b"
IMAGE_MANIFEST_SHA256 = "0b408f7a513c38a0a58687725625c5df64219dbf6d34bd6fff70df2b8dbb6e35"
REMOTE_SOURCE_SHA256 = '9b6585ad543225751608ef29e9090edaec719626f580c78f1883cf80b6b56c84'
OUTER_CAP = 65536

class QualifiedCliError(ValueError):
    """An unsupported or unqualified CLI context was requested."""

def validate_selection(host, device, selector, timeout_seconds):
    if (type(selector) is not str or selector != SELECTOR
            or host != "archlinux" or device != "api35"
            or type(timeout_seconds) is not int or timeout_seconds != 15):
        raise QualifiedCliError("Unsupported qualified Android CLI selector or scope.")

def _programme(source, profile, correlation):
    """Bind only the genuine configured profile and a fresh owned record name."""
    if (type(correlation) is not str or len(correlation) != 32
            or any(c not in "0123456789abcdef" for c in correlation)):
        raise QualifiedCliError("Invalid qualified observation correlation.")
    if (type(profile) is not dict or set(profile) != {"adb", "cli", "serial", "expectedAvd", "api"}
            or type(profile["api"]) is not int or profile["api"] != 35
            or profile["serial"] != "emulator-5682"
            or profile["expectedAvd"] != "vpn-control-parity113-api35"):
        raise QualifiedCliError("Configured Android profile differs from qualified image scope.")
    if type(source) is not str or hashlib.sha256(source.encode()).hexdigest() != REMOTE_SOURCE_SHA256:
        raise QualifiedCliError("Qualified observer source binding changed.")
    nodes = [n for n in ast.parse(source).body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "PROBE" for t in n.targets)]
    if len(nodes) != 1:
        raise QualifiedCliError("Qualified observer source binding changed.")
    node = nodes[0]
    probe = ast.literal_eval(node.value)
    from agent_tools import android_observation
    embedded = [n for n in ast.parse(probe).body if isinstance(n, ast.FunctionDef) and n.name == "public_cli_environment"]
    current = [n for n in ast.parse(android_observation._canonical_cli_environment_source()).body
               if isinstance(n, ast.FunctionDef) and n.name == "public_cli_environment"]
    if (len(embedded) != 1 or len(current) != 1
            or ast.dump(embedded[0], include_attributes=False) != ast.dump(current[0], include_attributes=False)):
        raise QualifiedCliError("Canonical Android CLI environment source changed.")
    original_name = "OBS_NAME = 'full-observe-b995aafeebbb41caaca1998a17add08f'"
    if (type(probe) is not str or probe.count("PROFILE = None") != 1
            or probe.count(original_name) != 1):
        raise QualifiedCliError("Qualified observer source binding changed.")
    probe = probe.replace("PROFILE = None", "PROFILE = " + repr(profile), 1)
    probe = probe.replace(original_name, "OBS_NAME = " + repr("mcp-observe-" + correlation), 1)
    lines = source.splitlines(True)
    result = "".join(lines[:node.lineno-1]) + "PROBE=" + repr(probe) + "\n" + "".join(lines[node.end_lineno:])
    compile(result, "qualified_android_readonly", "exec")
    return result

class OuterCustody:
    def __init__(self,argv,envelope=None):
        self.child=ssh_transport.popen_ssh(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.selector=selectors.DefaultSelector();self.raw={'stdout':bytearray(),'stderr':bytearray()};self.counts={k:0 for k in self.raw};self.eof={k:False for k in self.raw};self.overflow=False;self.timeout=False;self.closed=False;self.sendError=None
        for name in self.raw:
            fd=getattr(self.child,name).fileno();os.set_blocking(fd,False);self.selector.register(fd,selectors.EVENT_READ,name)
        if envelope is not None:self.send(envelope)
    def send(self,envelope):
        try:
            if not isinstance(envelope,bytes) or not 0<len(envelope)<=4096:raise ValueError('envelope_cap')
            self.child.stdin.write(envelope);self.child.stdin.flush()
        except (OSError,ValueError) as exc:self.sendError=type(exc).__name__
        finally:self.child.stdin.close()
    def step(self,seconds):
        for key,_ in self.selector.select(seconds):
            try:b=os.read(key.fd,4096)
            except BlockingIOError:continue
            if not b:self.eof[key.data]=True;self.selector.unregister(key.fd);continue
            name=key.data;self.counts[name]+=len(b);left=OUTER_CAP-len(self.raw[name]);self.raw[name].extend(b[:max(left,0)])
            if self.counts[name]>OUTER_CAP:self.overflow=True
    def observe(self,seconds=60):
        end=time.monotonic()+seconds
        while not (self.child.poll()is not None and all(self.eof.values())):
            left=end-time.monotonic()
            if left<=0:self.timeout=True;break
            self.step(min(left,.05))
        return self.snapshot()
    def snapshot(self):
        # Freeze metadata for this same child; never re-observe, reset the
        # original timeout, or start another process.
        return {'pid':self.child.pid,'returnCode':self.child.poll(),'complete':self.child.poll()is not None and all(self.eof.values()),'timeout':self.timeout,'overflow':self.overflow,'counts':dict(self.counts),'eof':dict(self.eof),'sendError':self.sendError}
    def finish_naturally(self):
        if not self.child.stdin.closed:self.child.stdin.close()
        while not (self.child.poll()is not None and all(self.eof.values())):self.step(.05)
        self.selector.close();self.child.stdout.close();self.child.stderr.close();self.closed=True
        ssh_transport.finish_ssh(self.child,failed=self.timeout or self.overflow or self.sendError is not None)

def _project_observation(value):
    """Use the unchanged canonical parser for full owner-consistency semantics."""
    from agent_tools import android_observation
    try:
        native = value["arch"]["androidObservation"]
        if (type(native) is not dict or native.get("state") != "CORRECTED_D32_FULL_OBSERVATION"
                or native.get("packageSha256") != PACKAGE_SHA256
                or native.get("engineeringOnly") is not True or native.get("imageFiles") != 155
                or native.get("freshPhysicalAndAppBrackets") != 2
                or native.get("sourceAndImageClosing") is not True
                or any(native.get(k) is not False for k in ("finalProductAcceptance", "globalInstall",
                    "configuredProfileChanged", "guestMutationPerformed", "newOwnerAdmission",
                    "leaseOrRetirementAuthority", "replayAllowed", "configuredCliInvoked"))):
            raise ValueError
        device = native["device"]
        trials = native["trials"]
        if type(trials) is not list or len(trials) != 2:
            raise ValueError
        rows = {}
        for family, trial in zip(("status", "operations"), trials):
            if (type(trial) is not dict or trial.get("family") != family
                    or type(trial.get("returnCode")) is not int or trial["returnCode"] != 0
                    or trial.get("complete") is not True or trial.get("quietContractPassed") is not True
                    or type(trial.get("stderrBytes")) is not int or trial["stderrBytes"] != 0):
                raise ValueError
            rows[family] = {key: trial.get(key) for key in ("ok", "code", "final", "controllerId", "operationId")}
        rows["operations"]["operationCount"] = trials[1].get("operationCount")
        baseline = {"uid": device["shellUid"], "sdk": device["sdk"], "kernelAvd": device["kernelAvd"],
                    "bootAvd": device["bootAvd"], "proxy": device["proxy"]}
        return android_observation._result(0, json.dumps({"baseline": baseline, "admitted": True,
                                          "status": rows["status"], "operations": rows["operations"]}).encode())
    except (KeyError, TypeError, ValueError):
        raise QualifiedCliError("Qualified full observation framing is incomplete.") from None

def _retain(directory, name, value):
    raw = value if type(value) is bytes else (json.dumps(value, sort_keys=True) + "\n").encode()
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("Short retained observation write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)

def _retain_final(execution, custody):
    """Append terminal evidence without changing any initial observation file."""
    final = custody.snapshot()
    if not custody.closed or not final["complete"]:
        raise QualifiedCliError("Final capture requires natural terminal and dual EOF.")
    streams = {}
    _retain(execution, "final-capture.private.json", final)
    for name, raw in custody.raw.items():
        data = bytes(raw)
        _retain(execution, "outer-final-" + name + ".private", data)
        streams[name] = {"receivedBytes": custody.counts[name], "retainedBytes": len(data),
                         "sha256": hashlib.sha256(data).hexdigest(),
                         "fullBytesRetained": custody.counts[name] == len(data)}
    evidence = {"capture": final, "streams": streams,
                "sameOriginalChild": True, "initialOutcomeUnchanged": True,
                "replayAllowed": False}
    _retain(execution, "final-terminal.private.json", evidence)
    return evidence

def _checkpoint(root, guard, head):
    guard.guard()
    if subprocess.check_output(["git", "rev-parse", "HEAD", "origin/dev"], cwd=root, text=True).splitlines() != [head, head]:
        raise QualifiedCliError("Qualified observation source checkpoint changed.")

def observe(root, host, device, selector, timeout_seconds=15):
    """Run the fixed DIRECT status/operations observation once, with full custody."""
    validate_selection(host, device, selector, timeout_seconds)
    # Import POSIX custody only after validating the public selector; unsupported
    # coordinators refuse rather than falling back to another route or context.
    if __package__:
        from . import ssh_direct_nested_channel as direct, ssh_transport as transport, android_observation
    else:
        from agent_tools import ssh_direct_nested_channel as direct, ssh_transport as transport, android_observation
    if not direct.coordinator_capable():
        raise QualifiedCliError("Unsupported qualified observer coordinator.")
    root = Path(root).resolve(strict=True)
    corr = uuid.uuid4().hex
    output_root = root / ".runtime" / "android-qualified-cli-observations"
    output_root.mkdir(mode=0o700, exist_ok=True)
    execution = output_root / corr
    execution.mkdir(mode=0o700)
    guard = custody = None
    head = profile_digest = source_digest = profile = None
    closing = False
    final_evidence = None
    phase = "source_admission"
    result = {"state": "unknown", "correlationId": corr}
    try:
        guard = direct.Guard(root)
        own = Path(__file__).resolve()
        remote = own.with_name("android_qualified_cli_remote.source")
        # All input code remains held through raw retention and final closing.
        source = None
        for path in (own, remote, Path(android_observation.__file__).resolve(),
                     root / "scripts" / "android_no_update_tls_preflight.py"):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            raw = guard.held.read(str(path), digest)
            if path == remote:
                source = raw.decode("utf-8", "strict")
        head_rows = subprocess.check_output(["git", "rev-parse", "HEAD", "origin/dev"], cwd=root, text=True).splitlines()
        if (len(head_rows) != 2 or head_rows[0] != head_rows[1] or len(head_rows[0]) != 40
                or any(c not in "0123456789abcdef" for c in head_rows[0])):
            raise QualifiedCliError("Qualified observation requires the delivered source checkpoint.")
        head = head_rows[0]
        config = guard.config
        target = config.hosts.get(host)
        if (target is None or target.transport != "nested" or not target.gateway
                or len(transport._route_hosts(config.hosts, host)) != 2
                or device not in target.android_devices):
            raise QualifiedCliError("Qualified Android configured route is unavailable.")
        profile = android_observation._profile(target.android_devices[device])
        program = _programme(source, profile, corr)
        gateway = transport.connection_host(config, target.gateway)
        prefix, endpoint = direct.outer_prefix(config, gateway)
        secret = target.password
        if type(secret) is not str or not 0 < len(secret.encode()) <= 512 or any(c in secret for c in ("\r", "\n", "\0")):
            raise QualifiedCliError("Qualified route credential is unavailable.")
        digest = hashlib.sha256(program.encode()).hexdigest()
        packed = base64.b64encode(zlib.compress(program.encode())).decode()
        wrapper = ("import hashlib,base64,zlib\n_PACKED=" + repr(packed)
                   + "\n_PROGRAM=zlib.decompress(base64.b64decode(_PACKED,validate=True)).decode('utf-8','strict')"
                   + "\nassert len(_PROGRAM.encode())==" + str(len(program.encode()))
                   + " and hashlib.sha256(_PROGRAM.encode()).hexdigest()==" + repr(digest)
                   + "\n_DECODED_SOURCE_SHA=hashlib.sha256(_PROGRAM.encode()).hexdigest()"
                   + "\nexec(compile(_PROGRAM,'fixed_android_readonly','exec'))")
        command = shlex.join(("python3", "-I", "-B", "-c", wrapper, corr,
                              str(target.remote_config_file or ""), target.remote_host_alias, digest))
        if len(os.fsencode(command)) > 60000:
            raise QualifiedCliError("Qualified observation command exceeds its fixed bound.")
        argv = [*prefix, *direct.OUTER_OPTIONS, "-T", "-o", "ClearAllForwardings=yes",
                "-o", "PermitLocalCommand=no", "-o", "UpdateHostKeys=no", endpoint, command]
        envelope = json.dumps({"passphrase": secret}, separators=(",", ":")).encode()
        secret = None
        _checkpoint(root, guard, head)
        profile_digest = hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()
        source_digest = hashlib.sha256(json.dumps({**guard.source_pins, "qualifiedRemote": REMOTE_SOURCE_SHA256,
                           "qualifiedOwner": hashlib.sha256(own.read_bytes()).hexdigest()}, sort_keys=True).encode()).hexdigest()
        _retain(execution, "intent.private.json", {"correlationId": corr, "sourceHead": head,
                "sourcePins": guard.source_pins, "inventorySha256": guard.authority["configSha256"],
                "profileSha256": hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest(),
                "programmeSha256": digest, "selector": SELECTOR, "replayAllowed": False})
        phase = "transport"
        custody = OuterCustody(argv)
        _retain(execution, "accepted.private.json", {"pid": custody.child.pid, "parentPid": os.getpid(), "correlationId": corr})
        custody.send(envelope)
        envelope = None
        capture = custody.observe(45)
        _retain(execution, "capture.private.json", capture)
        for name, raw in custody.raw.items():
            _retain(execution, "outer-" + name + ".private", bytes(raw))
        if not capture["complete"] or capture["overflow"] or capture["sendError"] or custody.raw["stderr"]:
            result.update(reason="qualified_transport_unknown", capture=capture)
        else:
            value = json.loads(bytes(custody.raw["stdout"]))
            if type(value) is not dict:
                raise QualifiedCliError("Qualified observer framing changed.")
            private = value.pop("_operatorPrivateCapture", None)
            if private is not None:
                _retain(execution, "inner-capture.private.json", private)
            if (type(value) is not dict or value.get("correlationId") != corr
                    or value.get("state") not in ("observed", "unknown")
                    or value.get("nativeActionAllowed") is not False or value.get("replayAllowed") is not False
                    or value["state"] == "observed" and capture["returnCode"] != 0):
                raise QualifiedCliError("Qualified observer framing changed.")
            result = {**value, **_project_observation(value)} if value["state"] == "observed" else value
        custody.finish_naturally()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        result = {"state": "unknown", "correlationId": corr, "failurePhase": phase, "errorClass": type(exc).__name__}
    finally:
        try:
            if custody is not None:
                if not custody.closed:
                    custody.finish_naturally()
                phase = "final_retention"
                final_evidence = _retain_final(execution, custody)
                # Retention callbacks can touch source inputs. Authenticate the
                # final source/config/profile/HEAD population only afterwards.
                phase = "closing"
                _checkpoint(root, guard, head)
                current_profile = android_observation._profile(guard.config.hosts[host].android_devices[device])
                if current_profile != profile:
                    raise QualifiedCliError("Qualified configured profile changed during final retention.")
                closing = True
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            closing = False
            failure = {"failurePhase": phase, "errorClass": type(exc).__name__}
            if result.get("state") == "observed":
                result = {"state": "unknown", "correlationId": corr, **failure}
            result["closingFailure"] = failure
        finally:
            if guard is not None:
                guard.close()
        if result.get("state") != "observed":
            from agent_tools import android_observation
            result = {**result, **android_observation._unknown("qualified_observation_unknown")}
        result.update(sourceClosing=closing, holdersClosed=True, cliArtifact=SELECTOR,
                      finalCapture=final_evidence["capture"] if final_evidence else None,
                      finalStreamEvidence=final_evidence["streams"] if final_evidence else None,
                      sourceHead=head, sourceDigest=source_digest, configuredProfileSha256=profile_digest,
                      packageSha256=PACKAGE_SHA256, imageManifestSha256=IMAGE_MANIFEST_SHA256,
                      engineeringOnly=True, productAcceptance=False, nativeActionAllowed=False,
                      newOwnerAdmission=False, leaseOrRetirementAuthority=False, replayAllowed=False,
                      scope="qualified engineering CLI full Android observation",
                      configuredCliInvoked=False, configuredProfileChanged=False,
                      recordDirectory=str(execution))
        _retain(execution, "finite-result.public.json", result)
    return result
