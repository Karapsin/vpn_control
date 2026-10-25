"""Controlled real sockets/children; these do not qualify any Mac native API."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import json
import os
from pathlib import Path
import signal
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import uuid

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_tart_macos_leases as leases


class _Assertions(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.lock = threading.Lock()
        self.assertions = {}
        self.creations = []
        self.calls = []
        self.next_id = 1
        self.admitted = True
        self.release_available = True
        self.inventory_available = True
        super().__init__(("127.0.0.1", 0), _Request)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown(); self.server_close(); self.thread.join(timeout=3)

    def request(self, packet):
        with self.lock:
            self.calls.append(packet)
            now = time.monotonic()
            # Model the two independent OS safeguards: finite native expiry and
            # automatic release on the actual creating process generation's exit.
            self.assertions = {key: row for key, row in self.assertions.items()
                               if row["deadline"] > now and jobs._birth(row["owner"]["pid"]) == row["owner"]["birth"]}
            owner = packet["owner"]
            if (type(owner) is not dict or set(owner) != {"pid", "birth"}
                    or jobs._birth(owner["pid"]) != owner["birth"]):
                return {"ok": False, "value": None}
            action = packet["action"]
            value = None
            ok = True
            if action == "admit":
                ok = self.admitted
            elif action == "create":
                ok = self.admitted and packet["kind"] in leases._KINDS and 0 < packet["ttl"] <= 18000
                if ok:
                    value = self.next_id; self.next_id += 1
                    row = {"owner": owner, "kind": packet["kind"], "deadline": now + packet["ttl"]}
                    self.assertions[value] = row; self.creations.append((value, row))
            elif action == "verified":
                row = self.assertions.get(packet["identity"])
                value = bool(row and row["owner"] == owner and row["kind"] == packet["kind"])
            elif action == "release":
                row = self.assertions.get(packet["identity"])
                ok = self.release_available and (row is None or row["owner"] == owner)
                if ok:
                    self.assertions.pop(packet["identity"], None); value = True
            elif action == "absent":
                ok = self.inventory_available
                value = not any(row["owner"]["pid"] == packet["originalOwner"]["pid"]
                                for row in self.assertions.values())
            else:
                ok = False
            return {"ok": ok, "value": value}


class _Request(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(3)
        raw = self.rfile.readline(4097)
        if len(raw) > 4096 or not raw.endswith(b"\n"):
            return
        try:
            response = self.server.request(json.loads(raw))
        except (ValueError, TypeError, KeyError, OSError):
            response = {"ok": False, "value": None}
        self.wfile.write(json.dumps(response).encode() + b"\n")


class MacLeaseProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vc-mac-lease-")
        self.root = Path(self.tmp.name).resolve(); self.root.chmod(0o700)
        self.generation = jobs.root_generation(self.root)
        self.binding = leases.MacLeaseBinding("controlled-tart-macos", str(uuid.uuid4()), jobs._boot(),
                                              str(max(501, os.geteuid())), "leasefixture", "/Users/leasefixture", "1024")
        if os.geteuid() < 501:
            # Root-only test containers can run the private socket model; the
            # public native renderer independently revalidates and rejects this
            # forged ordinary binding. No native Mac assertion is involved.
            object.__setattr__(self.binding, "account", str(os.geteuid()))
        self.server = _Assertions()
        self.port = self.server.server_address[1]
        self.operations = []

    def tearDown(self):
        self.server.release_available = True
        for operation in self.operations:
            try:
                leases.cancel(self.root, operation, self.binding, generation=self.generation)
                self.until(lambda: jobs.observe(self.root, operation, self.binding.job_binding(),
                                                 generation=self.generation)["state"] == "terminal")
            except (ValueError, OSError):
                pass
        self.server.close(); self.tmp.cleanup()

    def until(self, check, timeout=10):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            result = check()
            if result:
                return result
            time.sleep(.02)
        self.fail("controlled original owner did not reach expected state")

    def submit(self, ttl=.8):
        operation = str(uuid.uuid4()); self.operations.append(operation)
        program = leases._controlled_program(self.root, operation, self.binding, ttl, self.port)
        jobs.submit(self.root, operation, self.binding.job_binding(), program, generation=self.generation)
        return operation, program

    def state(self, operation):
        return leases.inspect(self.root, operation, self.binding, generation=self.generation)

    def active(self, operation):
        return self.until(lambda: (row if row["state"] == "active" else None)
                          if (row := self.state(operation)) else None)

    def terminal(self, operation):
        return self.until(lambda: (row if row["jobState"] == "terminal" else None)
                          if (row := self.state(operation)) else None)

    def test_expiry_retains_one_owner_two_assertions_and_closed_output(self):
        operation, program = self.submit()
        self.active(operation)
        original = jobs._record(self.root / operation / "owner.json")
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: jobs.submit(self.root, operation, self.binding.job_binding(), program,
                                                generation=self.generation), range(4)))
        row = self.terminal(operation)
        self.assertEqual(("expired", True, "none"), (row["state"], row["restored"], row["nextAction"]))
        self.assertEqual(original, jobs._record(self.root / operation / "owner.json"))
        self.assertEqual(2, len(self.server.creations))
        self.assertEqual(set(leases._KINDS), {value["kind"] for _, value in self.server.creations})
        status, output, error = jobs.collect(self.root, operation, self.binding.job_binding(), generation=self.generation)
        self.assertEqual(0, status["terminal"]["exitCode"])
        self.assertEqual("expired", json.loads(output)["state"])
        self.assertEqual(b"", error)
        self.assertFalse(self.server.assertions)

    def test_fresh_agent_cancel_addresses_same_original_uuid(self):
        operation, _ = self.submit(4)
        self.active(operation)
        original = jobs._record(self.root / operation / "owner.json")
        code = ("import json;from agent_tools import readiness_tart_macos_leases as L;"
                "b=object.__new__(L.MacLeaseBinding);"
                "[object.__setattr__(b,k,v)for k,v in " + repr(asdict(self.binding)) + ".items()];"
                "print(json.dumps(L.cancel(" + repr(str(self.root)) + "," + repr(operation) +
                ",b,generation=" + repr(self.generation) + ")))")
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr.decode())
        row = self.terminal(operation)
        self.assertEqual(("cancelled", True), (row["state"], row["restored"]))
        self.assertEqual(original, jobs._record(self.root / operation / "owner.json"))
        self.assertEqual(operation, jobs._record(self.root / operation / "lease-cancel.json")["operationId"])
        self.assertEqual(2, len(self.server.creations))

    def test_submitter_death_does_not_own_lease_lifetime(self):
        operation = str(uuid.uuid4()); self.operations.append(operation)
        code = ("import os;from agent_tools import durable_remote_job as J,readiness_tart_macos_leases as L;"
                "b=object.__new__(L.MacLeaseBinding);[object.__setattr__(b,k,v)for k,v in " +
                repr(asdict(self.binding)) + ".items()];r=" + repr(str(self.root)) + ";"
                "J.submit(r," + repr(operation) + ",b.job_binding(),L._controlled_program(r," + repr(operation) +
                ",b,1.3," + repr(self.port) + "),generation=" + repr(self.generation) + ");os._exit(0)")
        submitter = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.assertEqual(0, submitter.wait(timeout=5)); submitter.stderr.close()
        self.active(operation)
        self.assertEqual("expired", self.terminal(operation)["state"])
        self.assertEqual(2, len(self.server.creations))

    def test_owner_death_reconciles_absence_without_new_assertion_or_receipt_rewrite(self):
        operation, _ = self.submit(4)
        self.active(operation)
        path = self.root / operation / "lease-acquired.json"
        before = path.read_bytes(); owner = json.loads(before)["leaseOwner"]
        self.assertEqual(owner["birth"], jobs._birth(owner["pid"]))
        os.kill(owner["pid"], signal.SIGKILL)
        self.terminal(operation)
        self.assertFalse((self.root / operation / "lease-terminal.json").exists())
        row = leases._reconcile(self.root, operation, self.binding, generation=self.generation, controlled=self.port)
        self.assertEqual(("restored", True), (row["state"], row["restored"]))
        self.assertEqual(before, path.read_bytes())
        self.assertEqual(2, len(self.server.creations))
        self.assertFalse(self.server.assertions)
        resolution = (self.root / operation / "lease-resolution.json").read_bytes()
        leases._reconcile(self.root, operation, self.binding, generation=self.generation, controlled=self.port)
        self.assertEqual(resolution, (self.root / operation / "lease-resolution.json").read_bytes())
        next_operation, _ = self.submit(.4)
        self.assertEqual("expired", self.terminal(next_operation)["state"])

    def test_unavailable_inventory_cannot_resolve_unknown_owner(self):
        operation, _ = self.submit(4); self.active(operation)
        owner = jobs._record(self.root / operation / "lease-acquired.json")["leaseOwner"]
        os.kill(owner["pid"], signal.SIGKILL); self.terminal(operation)
        self.server.inventory_available = False
        with self.assertRaises(ValueError):
            leases._reconcile(self.root, operation, self.binding, generation=self.generation, controlled=self.port)
        self.assertFalse((self.root / operation / "lease-resolution.json").exists())
        blocked, _ = self.submit(.3)
        self.assertEqual("failed", self.terminal(blocked)["state"])
        self.assertEqual(2, len(self.server.creations))

    def test_release_failure_preserves_original_and_resolution_is_append_only(self):
        operation, _ = self.submit(.5); self.active(operation)
        self.server.release_available = False
        row = self.terminal(operation)
        self.assertEqual(("restore_blocked", False), (row["state"], row["restored"]))
        receipt = (self.root / operation / "lease-terminal.json").read_bytes()
        row = leases._reconcile(self.root, operation, self.binding, generation=self.generation, controlled=self.port)
        self.assertEqual("restored", row["state"])
        self.assertEqual(receipt, (self.root / operation / "lease-terminal.json").read_bytes())
        self.assertEqual(2, len(self.server.creations))

    def test_simultaneous_distinct_operations_cannot_assert_twice(self):
        first, _ = self.submit(2); self.active(first)
        second, _ = self.submit(.3)
        self.assertEqual("failed", self.terminal(second)["state"])
        self.assertEqual(2, len(self.server.creations))
        leases.cancel(self.root, first, self.binding, generation=self.generation)
        self.assertEqual("cancelled", self.terminal(first)["state"])

    def test_corrupt_cancel_cannot_signal_unrelated_process_or_hide_blocker(self):
        operation, _ = self.submit(.7); self.active(operation)
        jobs._publish(self.root / operation / "lease-cancel.json", {"operationId": str(uuid.uuid4())})
        row = self.terminal(operation)
        self.assertEqual(("failed", True), (row["state"], row["restored"]))
        self.assertIsNotNone(jobs._birth(os.getpid()))

    def test_status_is_inert_even_when_native_probe_would_be_unavailable(self):
        operation, _ = self.submit(.4); self.terminal(operation)
        count = len(self.server.calls)
        self.assertEqual("expired", self.state(operation)["state"])
        self.assertEqual(count, len(self.server.calls))
        self.assertFalse(leases.NATIVE_QUALIFIED)


class MacAdmissionTests(unittest.TestCase):
    def test_actual_ctypes_call_uses_finite_release_action_without_native_iokit(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("controlled C ABI fixture requires cc; native IOKit remains unqualified")
        # This is an isolated shared library, never IOKit. It validates the
        # actual C argument boundary used by the fixed ctypes implementation.
        c_source = r'''
        #include <stdint.h>
        #include <stdlib.h>
        #include <string.h>
        static int strings=0,active=0,created=0,released=0;
        static double timeout_value;
        static const char *kind_value;
        void *CFStringCreateWithCString(void*a,const char*s,uint32_t encoding){
            if(a || encoding!=0x08000100)return 0;
            strings++;return strdup(s);
        }
        void CFRelease(void *p){if(p){strings--;free(p);}}
        int IOPMAssertionCreateWithDescription(void*kind,void*name,void*details,void*reason,
                void*bundle,double timeout,void*action,uint32_t*identity){
            if(!kind || strcmp(kind,"PreventUserIdleDisplaySleep") || !name ||
                strcmp(name,"VPNControlTemporaryGUILease") || !details ||
                strcmp(details,"Owned temporary GUI test lease") || reason || bundle ||
                timeout<=0 || timeout>18000 || !action || strcmp(action,"TimeoutActionRelease"))return 7;
            kind_value="PreventUserIdleDisplaySleep";timeout_value=timeout;
            active=1;created++;*identity=123;return 0;
        }
        int IOPMAssertionRelease(uint32_t identity){
            if(identity!=123)return 7;
            if(!active)return (int)0xe00002f0;
            active=0;released++;return 0;
        }
        void *IOPMAssertionCopyProperties(uint32_t identity){return active && identity==123 ? (void*)123 : 0;}
        int IOPMCopyAssertionsByProcess(void **p){*p=0;return 7;}
        long CFDictionaryGetCount(void*p){return 0;}
        void CFDictionaryGetKeysAndValues(void*p,void*k,void*v){}
        unsigned long CFGetTypeID(void*p){return 1;}
        unsigned long CFNumberGetTypeID(void){return 1;}
        unsigned long CFArrayGetTypeID(void){return 2;}
        int CFNumberGetValue(void*p,int t,void*v){return 0;}
        long CFArrayGetCount(void*p){return 0;}
        double FixtureTimeout(void){return timeout_value;}
        int FixtureStrings(void){return strings;}
        int FixtureCreated(void){return created;}
        int FixtureReleased(void){return released;}
        '''
        with tempfile.TemporaryDirectory(prefix="vc-mac-abi-") as directory:
            library = Path(directory) / ("fixture.dylib" if sys.platform == "darwin" else "fixture.so")
            build = subprocess.run([compiler, "-dynamiclib" if sys.platform == "darwin" else "-shared", "-fPIC",
                                    "-x", "c", "-", "-o", str(library)], input=c_source.encode(),
                                   capture_output=True, timeout=20)
            self.assertEqual(0, build.returncode, build.stderr.decode())
            import ctypes
            native_lib = ctypes.CDLL(str(library))
            native_lib.FixtureTimeout.restype = ctypes.c_double
            scope = {"D": vars(jobs), "P": {}}
            exec(leases._ASSERTIONS, scope)
            class NativeFixture:
                cf = io = native_lib
                @staticmethod
                def _fn(lib, name, result, args):
                    fn = getattr(lib, name); fn.restype = result; fn.argtypes = args
                @staticmethod
                def console():
                    return {"uid": 501, "name": "ordinary", "session": "42", "onConsole": True,
                            "loginDone": True, "locked": False}
                @staticmethod
                def displays(): return "ready"
                @staticmethod
                def value(pointer):
                    return None if not pointer else {"AssertType": "PreventUserIdleDisplaySleep", "AssertLevel": 255,
                        "AssertName": "VPNControlTemporaryGUILease", "TimeoutAction": "TimeoutActionRelease",
                        "TimeoutSeconds": native_lib.FixtureTimeout()}
            scope["P"]["Native"] = NativeFixture
            class Api(scope["MacAssertions"]):
                # This test covers only the ABI, never actual host/guest identity.
                def validate_identity(self): pass
            api = Api({"account": "501", "principal": "ordinary", "session": "42"})
            identity = api.create("PreventUserIdleDisplaySleep", 1.25)
            self.assertEqual(123, identity)
            self.assertTrue(api.verified(identity, "PreventUserIdleDisplaySleep"))
            self.assertEqual(1.25, native_lib.FixtureTimeout())
            self.assertEqual(0, native_lib.FixtureStrings())
            api.release(identity, False)
            self.assertEqual((1, 1), (native_lib.FixtureCreated(), native_lib.FixtureReleased()))
            self.assertFalse(api.verified(identity, "PreventUserIdleDisplaySleep"))
            with self.assertRaises(jobs.DurableJobError): api.release(identity, False)
            api.release(identity, True)

    def test_native_console_requires_positive_login_done_and_same_session(self):
        scope = {"D": vars(jobs), "P": {}}
        exec(leases._ASSERTIONS, scope)
        api = scope["MacAssertions"].__new__(scope["MacAssertions"])
        api.binding = {"account": "501", "principal": "ordinary", "session": "42"}
        api.validate_identity = lambda: None
        facts = {"uid": 501, "name": "ordinary", "session": "42", "onConsole": True, "locked": False}
        api.native = SimpleNamespace(console=lambda: dict(facts), displays=lambda: "ready")
        with self.assertRaisesRegex(jobs.DurableJobError, "macos_usable_console_unverified"):
            api.admit()
        facts["loginDone"] = True; api.admit()
        for key, value in (("uid", True), ("uid", 501.0), ("session", "43"), ("onConsole", False),
                           ("locked", True), ("loginDone", False)):
            original = facts[key]; facts[key] = value
            with self.assertRaises(jobs.DurableJobError): api.admit()
            facts[key] = original

    def test_finite_native_renderer_contains_no_coordinator_executor(self):
        with tempfile.TemporaryDirectory(prefix="vc-mac-render-") as directory:
            root = Path(directory).resolve(); root.chmod(0o700)
            binding = leases.MacLeaseBinding("owned-tart", str(uuid.uuid4()), str(uuid.uuid4()),
                                             "501", "ordinary", "/Users/ordinary", "42")
            value = leases.program(root, str(uuid.uuid4()), binding, 18000)
            compile(value.source, "mac-guest-lease", "exec")
            self.assertEqual("tart-macos-assertion-lease-v1", value.purpose)
            for invalid in (True, float("nan"), 18001, 0, "1"):
                with self.assertRaises(leases.MacLeaseError):
                    leases.program(root, str(uuid.uuid4()), binding, invalid)
            with self.assertRaises(leases.MacLeaseError):
                leases.MacLeaseBinding("owned-tart", binding.machine, binding.boot, "0", "root", "/root", "42")


if __name__ == "__main__":
    unittest.main()
