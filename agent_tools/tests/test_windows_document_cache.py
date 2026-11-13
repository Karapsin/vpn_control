"""windows-document-cold.cache-bytes: the owned in-guest subscription source and the committed cache read back cold.

Until this change the row was refused before any journal (windows_scenario_document_cache_fixture_unavailable): no
in-guest source filled the product's committed subscription cache. These tests are RED on that unfixed source and
GREEN on the fix. Nothing here reaches a VM, a guest, a product or the Internet:

- the source (windows_document_cache_fixture) runs as a real child process over loopback TLS with key material
  made locally, and is stopped by its own stop record;
- the recipe's model of the product's stored-location encoding is compared with the strings the product's own
  compiled encoder wrote for the same lines (recorded below, with how they were obtained);
- the cold module's cache flow runs under the real owner's main and run with the inert guest of the document tests,
  whose product keeps the committed cache in a workspace.json shaped as DesktopStateStore writes it.

What only a native run shows: the installed product's own refresh over the guest's loopback TLS with the scoped trust
store, its persistence of the cache on Windows, and the independent serve's cold read of it.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import random
import ssl
import socket
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
import uuid

from agent_tools import native_scenario_bundle as bundles
from agent_tools import native_scenario_windows as windows
from agent_tools import windows_document_cache_fixture as fixture
from agent_tools import windows_document_cold_cases as cold
from agent_tools import windows_document_native as native_module
from agent_tools import windows_ordinary_process_owner as process_owner
from agent_tools import windows_scenario_host_job as host_job
from agent_tools.tests.test_windows_cli_native_failures import Parked, held_harness, run_owner
from agent_tools.tests.test_windows_document_acceptance import ColdGuest, DOCUMENT_CASES, LAUNCHER_PATH

ROOT = Path(__file__).resolve().parents[2]
OPERATION = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
ROW = "windows-document-cold.cache-bytes"
# DesktopSubscriptionDownloadClient's own User-Agent: the product's fetch, as the source journals it.
PRODUCT_AGENT = "VPNControlDesktop/1.0"
# What LocationConfigs.encodeStoredLocation wrote for the recipe's first eight lines, one of each shape, after
# ProxyParser.parseSubscription read the whole recipe body: the product's own compiled shared/core encoder
# (core-desktop.jar of the recovery tree, Kotlin 2.0.21, kotlinx-serialization-json 1.8.0), run offline over
# host_job.cache_body() on 2026-11-13. All 256 strings it wrote equal host_job.cache_stored_locations(); their
# newline join is PRODUCT_NEWLINE below. Each stored location is also a fixpoint of decodeStoredLocation then
# encodeStoredLocation, which the cold owner's export repeats.
PRODUCT_STORED = (
    '{"type":"socks","protocol":"socks","remarks":"Cache 000","uuid":"","username":"","server":"192.0.2.1","server_port":1080,'
    '"password":"","method":"","network":"tcp","flow":"","security":"","sni":"","fingerprint":"chrome","public_key":"","short_id":"",'
    '"path":"","host_header":"","service_name":"","header_type":"none","alter_id":0,"vmess_security":"auto","plugin":"",'
    '"plugin_options":"","raw_link":"socks://192.0.2.1:1080#Cache%20000"}',
    '{"type":"socks","protocol":"socks","remarks":"\u041a\u044d\u0448 1","uuid":"","username":"","server":"cache-001.document.invalid",'
    '"server_port":2001,"password":"","method":"","network":"tcp","flow":"","security":"","sni":"","fingerprint":"chrome",'
    '"public_key":"","short_id":"","path":"","host_header":"","service_name":"","header_type":"none","alter_id":0,'
    '"vmess_security":"auto","plugin":"","plugin_options":"","raw_link":"socks://cache-001.document.invalid:2001#%D0%9A%D1%8D%D1%88%201"}',
    '{"type":"socks","protocol":"socks","remarks":"cred-2","uuid":"","username":"user2","server":"198.51.100.15","server_port":3002,'
    '"password":"p@ss2","method":"","network":"tcp","flow":"","security":"","sni":"","fingerprint":"chrome","public_key":"",'
    '"short_id":"","path":"","host_header":"","service_name":"","header_type":"none","alter_id":0,"vmess_security":"auto",'
    '"plugin":"","plugin_options":"","raw_link":"socks://user2:p%40ss2@198.51.100.15:3002#cred-2"}',
    '{"type":"socks","protocol":"socks","remarks":"v6-3","uuid":"","username":"","server":"2001:db8::4","server_port":4003,'
    '"password":"","method":"","network":"tcp","flow":"","security":"","sni":"","fingerprint":"chrome","public_key":"","short_id":"",'
    '"path":"","host_header":"","service_name":"","header_type":"none","alter_id":0,"vmess_security":"auto","plugin":"",'
    '"plugin_options":"","raw_link":"socks://[2001:db8::4]:4003#v6-3"}',
    '{"type":"socks","protocol":"socks","remarks":"203.0.113.5","uuid":"","username":"","server":"203.0.113.5","server_port":5004,'
    '"password":"","method":"","network":"tcp","flow":"","security":"","sni":"","fingerprint":"chrome","public_key":"","short_id":"",'
    '"path":"","host_header":"","service_name":"","header_type":"none","alter_id":0,"vmess_security":"auto","plugin":"",'
    '"plugin_options":"","raw_link":"socks://203.0.113.5:5004"}',
    '{"type":"socks","protocol":"socks","remarks":"\u7f13\u5b58-5","uuid":"","username":"","server":"cache-5.document.invalid",'
    '"server_port":6005,"password":"","method":"","network":"tcp","flow":"","security":"","sni":"","fingerprint":"chrome",'
    '"public_key":"","short_id":"","path":"","host_header":"","service_name":"","header_type":"none","alter_id":0,'
    '"vmess_security":"auto","plugin":"","plugin_options":"","raw_link":"socks://cache-5.document.invalid:6005?note=x#%E7%BC%93%E5%AD%98-5"}',
    '{"type":"socks","protocol":"socks","remarks":"\U0001f4e6 box 6","uuid":"","username":"","server":"192.0.2.43","server_port":7006,'
    '"password":"","method":"","network":"tcp","flow":"","security":"","sni":"","fingerprint":"chrome","public_key":"","short_id":"",'
    '"path":"","host_header":"","service_name":"","header_type":"none","alter_id":0,"vmess_security":"auto","plugin":"",'
    '"plugin_options":"","raw_link":"socks://192.0.2.43:7006#%F0%9F%93%A6%20box%206"}',
    '{"type":"socks","protocol":"socks","remarks":"quote\\"back\\\\slash/7","uuid":"","username":"","server":"198.51.100.8",'
    '"server_port":8007,"password":"","method":"","network":"tcp","flow":"","security":"","sni":"","fingerprint":"chrome",'
    '"public_key":"","short_id":"","path":"","host_header":"","service_name":"","header_type":"none","alter_id":0,'
    '"vmess_security":"auto","plugin":"","plugin_options":"","raw_link":"socks://198.51.100.8:8007#quote%22back%5Cslash%2F7"}',
)
PRODUCT_NEWLINE = (116862, "b063e3c4100584a8b1be0a0735bff9b4a408229a01785630ec7c46d999c09211")
RECIPE_BODY = (12406, "daec39acacd19ddb1f24d77cf7b86edaed3a63d8a2af47db0a9a33666c0d67c4")
_TLS = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def tls():
    """One localhost key for this module, made as the job makes it; making it is the slow part."""
    if not _TLS:
        from agent_tools import windows_scenario_proxy as proxy
        _TLS.append(proxy.material(random.Random(11).getrandbits, time.time()))
    return _TLS[0]


# ---- The recipe and the product's encoding -------------------------------------------------------------------------

class RecipeTests(unittest.TestCase):
    def test_the_recipe_model_writes_what_the_products_encoder_wrote(self):
        stored = host_job.cache_stored_locations()
        self.assertEqual(list(PRODUCT_STORED), stored[:8])
        newline = "\n".join(stored).encode("utf-8")
        self.assertEqual(PRODUCT_NEWLINE, (len(newline), sha(newline)))
        body = host_job.cache_body()
        self.assertEqual(RECIPE_BODY, (len(body), sha(body)))

    def test_the_recipe_is_256_distinct_links_of_eight_shapes_that_no_inspector_refuses(self):
        lines = host_job.cache_lines()
        self.assertEqual((256, 256), (len(lines), len(set(lines))))
        self.assertEqual(256, len(set(host_job.cache_stored_locations())), "one distinct stored location per line")
        body = host_job.cache_body()
        self.assertTrue(body.isascii() and body.endswith(b"\n") and b"\r" not in body, "percent-encoded lines, LF only")
        self.assertEqual(lines, body.decode("ascii").split("\n")[:-1])
        lowered = body.decode("ascii").lower()
        # SubscriptionPayloadInspector.detectPayloadError's challenge markers, and its JSON and HTML guesses.
        for marker in ("ddos-guard", "captcha", "enable javascript", "just a moment", "attention required", "access denied",
                       "liberty vpn", "<html", "<!doctype"):
            self.assertNotIn(marker, lowered)
        self.assertFalse(body.startswith((b"{", b"[")))
        servers = {json.loads(item)["server"] for item in host_job.cache_stored_locations()}
        self.assertNotIn("0.0.0.0", servers, "no device-binding placeholder")
        self.assertTrue(all(server.endswith(".invalid") or server.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8:"))
                            for server in servers), "documentation addresses and names only: nothing is ever contacted")
        remarks = [json.loads(item)["remarks"] for item in host_job.cache_stored_locations()]
        self.assertTrue(any(ord(char) > 0xFFFF for remark in remarks for char in remark), "a supplementary-plane remark")
        self.assertTrue(any('"' in remark and "\\" in remark for remark in remarks), "a remark JSON must escape")

    def test_the_model_refuses_a_shape_it_does_not_know(self):
        for line in ("vless://u@h:1#x", "socks://h:x#y", "socks://a:b:c#y", " socks://"):
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, "cache_recipe_shape"):
                host_job.stored_socks_location(line)

    def test_the_cold_input_names_the_rows_roles_and_the_recipes_own_digests(self):
        row = windows.RECIPES[ROW]
        paths = host_job.layout(OPERATION, {"localAppData": "C:\\Users\\fixture\\AppData\\Local"}, row)
        value = json.loads(host_job.cold_input(row, paths, OPERATION))
        cache = value.pop("cache")
        self.assertEqual({"schemaVersion": 1, "variant": "cache-bytes", "operationId": OPERATION}, value)
        self.assertEqual(cold.CACHE_FIELDS, set(cache))
        workspace = host_job.WORKSPACE_PREFIX + OPERATION + "\\"
        self.assertEqual({"fixtureWorkerPath": workspace + "windows_document_cache_fixture.py",
                          "runtimeStagesPath": workspace + "windows_lifecycle_runtime_stages.py",
                          "socksSourcePath": workspace + "socks_http_fixture.py",
                          "httpsSourcePath": workspace + "https_subscription_relay_fixture.py",
                          "certificatePath": workspace + "document-cache-localhost.pem",
                          "privateKeyPath": workspace + "document-cache-localhost.key",
                          "trustStorePath": workspace + "document-cache-trust.jks",
                          "bodyPath": workspace + "document-cache-subscription.txt"},
                         {key: cache[key] for key in cache if key.endswith("Path")})
        self.assertEqual((host_job.cache_stored_locations(), 256, *PRODUCT_NEWLINE, *RECIPE_BODY, "Owned cache"),
                         (cache["expectedLocations"], cache["expectedCount"], cache["expectedNewlineBytes"],
                          cache["expectedNewlineSha256"], cache["bodyBytes"], cache["bodySha256"], cache["subscriptionName"]))
        self.assertTrue(host_job.cold_input(row, paths, OPERATION).isascii(), "the literal is ASCII JSON; json.loads restores each string")
        self.assertLessEqual(len(host_job.cold_input(row, paths, OPERATION)), cold.INPUT_LIMIT)

    def test_the_cold_modules_fixed_sources_are_the_bundle_files_bytes(self):
        rows, seen = {relative for relative, _, _ in windows.RECIPES[ROW]["guestFiles"]}, set()
        for key, relative in (("fixtureWorkerPath", "agent_tools/windows_document_cache_fixture.py"),
                              ("runtimeStagesPath", "agent_tools/windows_lifecycle_runtime_stages.py"),
                              ("socksSourcePath", "scripts/integration/socks_http_fixture.py"),
                              ("httpsSourcePath", "scripts/integration/https_subscription_relay_fixture.py")):
            self.assertIn(relative, rows, "a file the row publishes")
            self.assertEqual((relative.rsplit("/", 1)[1], sha((ROOT / relative).read_bytes())), cold.CACHE_SOURCES[key], key)
            seen.add(key)
        self.assertEqual(set(cold.CACHE_SOURCES), seen)
        self.assertEqual(fixture.SOURCES, {"https": cold.CACHE_SOURCES["httpsSourcePath"][1], "socks": cold.CACHE_SOURCES["socksSourcePath"][1]})
        self.assertEqual(cold.CACHE_STEPS, fixture.STEPS, "the owner reads the source's own step names")
        self.assertEqual(PRODUCT_AGENT, cold.PRODUCT_AGENT, "the case accepts only the product's own fetch")


# ---- The source over loopback TLS -------------------------------------------------------------------------------------

class SourceTests(unittest.TestCase):
    """The real source as a child process: its steps, its ready record, the one owned path, its journal, its stop."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.children = []
        self.addCleanup(self.reap)

    def reap(self):
        # Test teardown only: a child a test left running is ended here, never by the source's own code.
        for child in self.children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=30)

    def start(self, change=None, body=None):
        material = tls()
        (self.root / "fixture").mkdir()
        certificate, key, body_path = self.root / "c.pem", self.root / "k.key", self.root / "body.txt"
        certificate.write_bytes(material["certificate"])
        key.write_bytes(material["privateKey"])
        body_path.write_bytes(host_job.cache_body() if body is None else body)
        self.operation = str(uuid.uuid4())
        value = {"schemaVersion": 1, "operationId": self.operation,
                 "socksSourcePath": str(ROOT / "scripts/integration/socks_http_fixture.py"),
                 "httpsSourcePath": str(ROOT / "scripts/integration/https_subscription_relay_fixture.py"),
                 "certificatePath": str(certificate), "privateKeyPath": str(key), "bodyPath": str(body_path),
                 "bodySha256": sha(host_job.cache_body()), "readyFile": str(self.root / "fixture/ready.json"),
                 "controlFile": str(self.root / "fixture/stop.json"), "journalFile": str(self.root / "fixture/journal.jsonl"),
                 "token": "owned-document-cache-" + self.operation}
        if change is not None:
            change(value)
        (self.root / "input.json").write_text(json.dumps(value))
        self.value = value
        child = subprocess.Popen([sys.executable, "-I", "-B", str(ROOT / "agent_tools/windows_document_cache_fixture.py"),
                                  "--input", str(self.root / "input.json")], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 stdin=subprocess.DEVNULL, cwd=self.root)
        self.children.append(child)
        return child

    def ready(self, child):
        until = time.monotonic() + 60
        while not (self.root / "fixture/ready.json").exists():
            self.assertIsNone(child.poll(), "the source ended before its ready file")
            self.assertLess(time.monotonic(), until)
            time.sleep(0.05)
        return json.loads((self.root / "fixture/ready.json").read_bytes())

    def exchange(self, ready, raw):
        """Bytes over the source's TLS, as any local client could send them, and everything it answered."""
        context = ssl.create_default_context(cafile=str(self.root / "c.pem"))
        with socket.create_connection(("127.0.0.1", ready["httpsPort"]), timeout=10) as connection:
            with context.wrap_socket(connection, server_hostname="localhost") as stream:
                stream.sendall(raw)
                data = b""
                while True:
                    part = stream.recv(65536)
                    if not part:
                        break
                    data += part
        return data

    def fetch(self, ready, path, agent=PRODUCT_AGENT):
        data = self.exchange(ready, ("GET %s HTTP/1.1\r\nHost: localhost:%d\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n"
                                     % (path, ready["httpsPort"], agent)).encode("ascii"))
        head, _, payload = data.partition(b"\r\n\r\n")
        return head.split(b"\r\n")[0], payload

    def stop(self, child, record=None):
        stop = {"schemaVersion": 1, "operationId": self.operation, "action": "stop-owned-fixture"} if record is None else record
        (self.root / "fixture/stop.json").write_text(json.dumps(stop))
        out, err = child.communicate(timeout=60)
        return [json.loads(line) for line in out.decode().splitlines()], err

    def test_it_serves_the_recipe_body_on_its_one_path_journals_each_answer_and_stops_on_its_record(self):
        child = self.start()
        ready = self.ready(child)
        path = "/subscription/cache/" + self.operation
        self.assertEqual({"cacheUrl": "https://localhost:%d%s" % (ready["httpsPort"], path), "operationId": self.operation,
                          "pid": child.pid, "certificateSha256": sha(tls()["certificate"]), "bodySha256": RECIPE_BODY[1],
                          "bodyBytes": RECIPE_BODY[0], "scope": "one-owned-subscription-source", "nativeAcceptance": False,
                          "httpsHost": "localhost", "advertisedSocksHost": "127.0.0.1"},
                         {key: ready[key] for key in ("cacheUrl", "operationId", "pid", "certificateSha256", "bodySha256", "bodyBytes",
                                                      "scope", "nativeAcceptance", "httpsHost", "advertisedSocksHost")})
        self.assertEqual((b"HTTP/1.0 200 OK", host_job.cache_body()), self.fetch(ready, path))
        self.assertEqual(b"HTTP/1.0 404 Not Found", self.fetch(ready, "/subscription", agent="other")[0])
        rows, err = self.stop(child)
        self.assertEqual((0, b""), (child.returncode, err))
        self.assertEqual([{"kind": "owned-cache-fixture-step", "step": step} for step in fixture.STEPS], rows[:len(fixture.STEPS)])
        self.assertEqual("owned-cache-fixture-ready", rows[len(fixture.STEPS)]["kind"])
        self.assertEqual({"kind": "owned-cache-fixture-terminal", "operationId": self.operation, "journalEntries": 4,
                          "onlyOriginalObjectsStopped": True}, rows[-1])
        journal = [json.loads(line) for line in (self.root / "fixture/journal.jsonl").read_bytes().splitlines()]
        self.assertEqual([{"ordinal": 0, "event": "request", "method": "GET", "path": path, "status": 200, "userAgent": PRODUCT_AGENT,
                           "agentTruncated": False},
                          {"ordinal": 1, "event": "answer", "status": 200, "sent": True, "bodyBytes": RECIPE_BODY[0],
                           "bodySha256": RECIPE_BODY[1]},
                          {"ordinal": 2, "event": "request", "method": "GET", "path": "/subscription", "status": 404,
                           "userAgent": "other", "agentTruncated": False},
                          {"ordinal": 3, "event": "answer", "status": 404, "sent": True, "bodyBytes": 0, "bodySha256": None}], journal)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", ready["httpsPort"]), timeout=2).close()

    def test_a_request_the_stdlib_answers_itself_is_journaled_too_and_gets_no_body(self):
        # RED on 7e6ee369: only what reached do_GET was journaled. The stdlib answered another method (501) and a request
        # line or headers it could not parse (400, 431) itself, with no journal line, while the owner's stop oracle reads
        # the journal as the complete record of who reached the source. A request line too long (414) takes the same path.
        child = self.start()
        ready = self.ready(child)
        path = "/subscription/cache/" + self.operation
        sent = (("HEAD", "HEAD %s HTTP/1.0\r\nUser-Agent: probe\r\n\r\n" % path, 501, path, "probe"),
                ("POST", "POST %s HTTP/1.0\r\nUser-Agent: probe\r\nContent-Length: 0\r\n\r\n" % path, 501, path, "probe"),
                ("", "BAD\r\n\r\n", 400, "", ""),
                ("GET", "GET %s HTTP/1.0\r\n%s\r\n" % (path, "X-Many: 1\r\n" * 101), 431, path, ""))
        answered = [self.exchange(ready, raw.encode("ascii")) for _, raw, _, _, _ in sent]
        rows, err = self.stop(child)
        self.assertEqual((0, b""), (child.returncode, err), "no request ended in a traceback")
        expected = []
        for method, _, status, journaled, agent in sent:
            expected.append({"ordinal": len(expected), "event": "request", "method": method, "path": journaled, "status": status,
                             "userAgent": agent, "agentTruncated": False})
            expected.append({"ordinal": len(expected), "event": "answer", "status": status, "sent": True, "bodyBytes": 0,
                             "bodySha256": None})
        journal = [json.loads(line) for line in (self.root / "fixture/journal.jsonl").read_bytes().splitlines()]
        self.assertEqual(expected, journal)
        self.assertEqual({"kind": "owned-cache-fixture-terminal", "operationId": self.operation, "journalEntries": len(expected),
                          "onlyOriginalObjectsStopped": True}, rows[-1])
        for answer, status in ((answered[0], 501), (answered[1], 501), (answered[3], 431)):
            head, _, body = answer.partition(b"\r\n\r\n")
            self.assertEqual((("HTTP/1.0 %d" % status).encode(), b""), (head.split(b"\r\n")[0][:12], body), "a status and no body")
            self.assertIn(b"\r\nContent-Length: 0", head)
        self.assertEqual(b"", answered[2], "a request line with no version gets no status line, and no body either")

    def test_a_body_other_than_the_recipe_ends_the_start_before_any_listener(self):
        child = self.start(body=host_job.cache_body() + b"socks://192.0.2.9:9#extra\n")
        out, err = child.communicate(timeout=60)
        rows = [json.loads(line) for line in out.decode().splitlines()]
        self.assertEqual(fixture.START_FAILED, child.returncode)
        self.assertEqual(["input", "sources", "body"], [row["step"] for row in rows[:-1]])
        self.assertEqual({"kind": "owned-cache-fixture-failed", "step": "body", "errorClass": "Refusal", "winerror": None, "errno": None,
                          "reason": "cache-body-recipe", "listenersStopped": True}, rows[-1])
        self.assertIn(b"cache-body-recipe", err, "the traceback goes to stderr")
        self.assertFalse((self.root / "fixture/ready.json").exists())
        self.assertFalse((self.root / "fixture/journal.jsonl").exists())

    def test_a_producer_other_than_the_pinned_bytes_is_never_loaded(self):
        other = self.root / "other_https.py"
        other.write_bytes((ROOT / "scripts/integration/https_subscription_relay_fixture.py").read_bytes() + b"\n")
        child = self.start(change=lambda value: value.update(httpsSourcePath=str(other)))
        out, _ = child.communicate(timeout=60)
        rows = [json.loads(line) for line in out.decode().splitlines()]
        self.assertEqual((fixture.START_FAILED, "sources", "cache-fixture-exact-source"),
                         (child.returncode, rows[-1]["step"], rows[-1]["reason"]))

    def test_an_input_with_another_field_or_a_used_root_refuses_at_its_first_step(self):
        for name, change in (("extra-field", lambda value: value.update(argv=["cmd.exe"])),
                             ("same-outputs", lambda value: value.update(journalFile=value["readyFile"]))):
            with self.subTest(case=name):
                for leaf in ("fixture", "input.json", "c.pem", "k.key", "body.txt"):
                    target = self.root / leaf
                    if target.is_dir():
                        target.rmdir()
                    elif target.exists():
                        target.unlink()
                child = self.start(change=change)
                out, _ = child.communicate(timeout=60)
                rows = [json.loads(line) for line in out.decode().splitlines()]
                self.assertEqual((fixture.START_FAILED, "input"), (child.returncode, rows[-1]["step"]))
                self.assertIn(rows[-1]["reason"], {"finite-cache-input-schema", "fresh-owned-cache-root"})

    def test_a_stop_record_that_is_not_its_own_keeps_it_serving_and_says_why_once(self):
        child = self.start()
        ready = self.ready(child)
        (self.root / "fixture/stop.json").write_text(json.dumps({"schemaVersion": 1, "operationId": str(uuid.uuid4()),
                                                                  "action": "stop-owned-fixture"}))
        time.sleep(1)  # The source reads its control file every 0.1 s.
        self.assertIsNone(child.poll(), "a foreign stop record never ends it")
        self.assertEqual((b"HTTP/1.0 200 OK", host_job.cache_body()), self.fetch(ready, "/subscription/cache/" + self.operation),
                         "its listeners still serve: nothing was stopped on uncertainty")
        self.assertIsNone(child.poll())
        child.kill()  # Test teardown only.
        out, _ = child.communicate(timeout=30)
        rows = [json.loads(line) for line in out.decode().splitlines()]
        self.assertEqual([("owned-cache-fixture-retained", "exact-cache-stop")],
                         [(row["kind"], row["reason"]) for row in rows if row["kind"] == "owned-cache-fixture-retained"])
        self.assertNotIn("owned-cache-fixture-terminal", [row["kind"] for row in rows])


# ---- The cold module's cache flow under the real owner ----------------------------------------------------------------

class CacheGuest(ColdGuest):
    """The inert guest's product with subscriptions, a committed cache in workspace.json as DesktopStateStore writes it,
    and the cache source as a declared child that serves the recipe body to the product's one refresh."""

    def __init__(self, root, **options):
        super().__init__(root, **options)
        self.subscriptions = {}  # workspace -> [subscription dict]
        self.settings = {"refresh.policy": "every-day", "refresh.find-best-after-refresh": "true"}
        self.source = None  # workspace -> id
        self.environments = []  # (label, JAVA_TOOL_OPTIONS at the child's start)
        self.fixture_child = self.fixture_input = None
        self.fixture_ready = True
        self.fixture_exit = None  # an exit the source ends with before its ready file
        self.terminations = []
        self.refresh_answer = None  # (exit, code, final) the product answers its refresh with
        self.commit_change = None  # cached list -> committed list
        self.reopen_change = None  # workspace document -> document, as the reopened owner rewrites it
        self.export_change = None
        self.extra_fetch = None  # another request the source answers: (path, agent, status[, method])
        self.ready_change = None  # ready record -> the record the source publishes
        self.answer_change = None  # the answer row the source journals for the product's fetch -> row
        # How the source ends on its stop record: its exit code, its stderr, its terminal line, the journal it leaves,
        # and how many entries its terminal line claims beyond the journal's lines.
        self.stop_exit, self.stop_stderr, self.terminal_change, self.journal_change, self.entries_delta = 0, "", None, None, 0

    def outcome(self, child):
        if child.label == cold.CACHE_FIXTURE_LABEL:
            return self.fixture_outcome(child)
        return super().outcome(child)

    def fixture_outcome(self, child):
        # A source that never became ready stalled in its TLS context; the others said every step.
        said = fixture.STEPS if self.fixture_ready else fixture.STEPS[:fixture.STEPS.index("tls-context") + 1]
        steps = "".join(json.dumps({"kind": "owned-cache-fixture-step", "step": step}) + "\n" for step in said)
        if self.fixture_exit is not None:
            failed = {"kind": "owned-cache-fixture-failed", "step": "body", "errorClass": "Refusal", "winerror": None, "errno": None,
                      "reason": "cache-body-recipe", "listenersStopped": True}
            return self.fixture_exit, "".join(json.dumps({"kind": "owned-cache-fixture-step", "step": step}) + "\n"
                                              for step in ("input", "sources", "body")) + json.dumps(failed) + "\n", "Traceback\n"
        if self.terminations:
            return 1, steps, ""
        control = Path(self.fixture_input["controlFile"])
        if not control.exists():
            return None
        record = json.loads(control.read_bytes())
        if record != {"schemaVersion": 1, "operationId": self.fixture_input["operationId"], "action": "stop-owned-fixture"}:
            return None
        journal = Path(self.fixture_input["journalFile"])
        if self.journal_change is not None:
            journal.write_bytes(self.journal_change(journal.read_bytes()))
            self.journal_change = None  # The outcome is read once; the journal is left changed once.
        entries = len(journal.read_bytes().splitlines()) + self.entries_delta
        terminal = {"kind": "owned-cache-fixture-terminal", "operationId": self.fixture_input["operationId"], "journalEntries": entries,
                    "onlyOriginalObjectsStopped": True}
        if self.terminal_change is not None:
            terminal = self.terminal_change(terminal)
        return (self.stop_exit, steps + json.dumps({"kind": "owned-cache-fixture-ready"}) + "\n" + json.dumps(terminal) + "\n",
                self.stop_stderr)

    def start_fixture(self, child):
        """What the source does on its start, as the real one does it: its journal, then its ready record."""
        self.fixture_child = child
        self.fixture_input = json.loads(Path(child.argv[-1]).read_bytes())
        if self.fixture_exit is not None or not self.fixture_ready:
            return
        Path(self.fixture_input["journalFile"]).write_bytes(b"")
        ready = {"source": "https://localhost:50443/subscription", "httpsHost": "localhost", "httpsPort": 50443,
                 "advertisedSocksHost": "127.0.0.1", "advertisedSocksPort": 50444, "relayPort": 50444, "forwardHost": "localhost",
                 "forwardPort": 50443, "subscriptionRequests": 0, "operationId": self.fixture_input["operationId"], "pid": child.pid,
                 "cacheUrl": "https://localhost:50443/subscription/cache/" + self.fixture_input["operationId"],
                 "certificateSha256": sha(b"certificate"), "bodySha256": self.fixture_input["bodySha256"],
                 "bodyBytes": len(Path(self.fixture_input["bodyPath"]).read_bytes()), "scope": "one-owned-subscription-source",
                 "nativeAcceptance": False}
        if self.ready_change is not None:
            ready = self.ready_change(ready)
        Path(self.fixture_input["readyFile"]).write_bytes((json.dumps(ready) + "\n").encode())

    def journal(self, path, agent=PRODUCT_AGENT, status=200, method="GET"):
        rows = Path(self.fixture_input["journalFile"]).read_bytes().splitlines()
        body = Path(self.fixture_input["bodyPath"]).read_bytes()
        # As the source answers: the recipe body for a 200 only, and no body for anything else.
        answer = {"ordinal": len(rows) + 1, "event": "answer", "status": status, "sent": True,
                  "bodyBytes": len(body) if status == 200 else 0, "bodySha256": sha(body) if status == 200 else None}
        if self.answer_change is not None and (path, agent, method) == ("/subscription/cache/" + self.fixture_input["operationId"],
                                                                        PRODUCT_AGENT, "GET"):
            answer = self.answer_change(answer)
        with Path(self.fixture_input["journalFile"]).open("ab") as stream:
            for row in ({"ordinal": len(rows), "event": "request", "method": method, "path": path, "status": status, "userAgent": agent,
                         "agentTruncated": False}, answer):
                stream.write((json.dumps(row) + "\n").encode())
        return body

    def workspace_file(self, workspace):
        return Path(workspace) / "workspace.json"

    def commit(self, workspace):
        """DesktopStateStore.encodeWorkspace's shape: the subscription's cached_locations and the location records of its source."""
        rows = self.subscriptions[workspace]
        document = {"persisted_state": {"subscriptions": [{"id": row["id"], "url": row["source"], "custom_name": row["name"],
                                                           "cached_locations": row["cached"], "last_refreshed_at_epoch_millis": 1,
                                                           "last_refresh_status": row["status"]} for row in rows],
                                        "current_locations": next((row["cached"] for row in rows if row["id"] == self.source), [])},
                    "resume_connection_on_launch": False,
                    "locations": [{"index": index, "source_url": row["source"], "raw_link": link, "name": "n", "server": "s",
                                   "details": "SOCKS", "benchmark_detail": "Refreshed", "auto_selectable": True, "is_valid": True,
                                   "is_selected": False}
                                  for row in rows for index, link in enumerate(row["cached"])]}
        self.workspace_file(workspace).parent.mkdir(parents=True, exist_ok=True)
        self.workspace_file(workspace).write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")

    def reload(self, workspace):
        """A new owner reads the workspace: each subscription's cache is rebuilt from the location records of its source."""
        path = self.workspace_file(workspace)
        document = json.loads(path.read_text(encoding="utf-8"))
        if self.reopen_change is not None:
            document = self.reopen_change(document)
            path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
        for row in self.subscriptions[workspace]:
            row["cached"] = [record["raw_link"] for record in document["locations"] if record["source_url"] == row["source"]]

    def public(self, argv):
        workspace, rest = argv[2], list(argv[3:])
        serve = self.serve_of(workspace)
        controller = None if serve is None or serve.ordinal in self.quit_generations else self.generations[serve.ordinal]
        bound = ["--json", "--controller-id", controller]
        if rest[:3] != bound or controller is None:
            return super().public(argv)
        tail = rest[3:]
        if tail[:2] == ["--if-revision", "43"]:
            tail = tail[2:]
        rows = self.subscriptions.setdefault(workspace, [])
        if getattr(serve, "reloaded", False) is False and serve.label == "document-cold-serve":
            serve.reloaded = True
            self.reload(workspace)
        if tail == ["subscriptions", "list"]:
            return 0, self.envelope("OK", controller, {"subscriptions": [{"id": row["id"], "name": row["name"], "cachedLocations": len(row["cached"]),
                                                                          "refreshStatus": row["status"], "failureReason": None} for row in rows]}), ""
        if tail[:2] == ["settings", "set"] and len(tail) == 4:
            self.settings[tail[2]] = tail[3]
            return 0, self.envelope("OK", controller, {tail[2]: tail[3]}), ""
        if tail[:3] == ["subscriptions", "add", "--source"] and tail[4:5] == ["--name"] and len(tail) == 6:
            row = {"id": str(uuid.uuid4()), "source": tail[3], "name": tail[5], "cached": [], "status": ""}
            rows.append(row)
            return 0, self.envelope("OK", controller, {"id": row["id"]}), ""
        if tail[:3] == ["source", "set", "subscription"]:
            self.source = tail[3]
            return 0, self.envelope("OK", controller, {}), ""
        if tail[:2] == ["subscriptions", "show"]:
            row = next(row for row in rows if row["id"] == tail[2])
            return 0, self.envelope("OK", controller, {"id": row["id"], "name": row["name"], "source": row["source"],
                                                       "cachedLocations": len(row["cached"]), "refreshStatus": row["status"],
                                                       "failureReason": None}), ""
        if tail[:2] == ["subscriptions", "refresh"]:
            if self.refresh_answer is not None:
                code, name, final = self.refresh_answer
                return code, self.envelope(name, controller, {}, final=final), ""
            row = next(row for row in rows if row["id"] == tail[2])
            prefix = "https://localhost:50443"
            self.journal(row["source"][len(prefix):])
            if self.extra_fetch is not None:
                self.journal(*self.extra_fetch)
            body = Path(self.fixture_input["bodyPath"]).read_text(encoding="utf-8")
            cached = [host_job.stored_socks_location(line) for line in body.split("\n") if line]
            row["cached"] = cached if self.commit_change is None else self.commit_change(cached)
            row["status"] = "OK"
            self.commit(workspace)
            return 0, self.envelope("OK", controller, {}), ""
        if tail[:3] == ["locations", "export", "--output"]:
            current = next(row["cached"] for row in rows if row["id"] == self.source)
            content = json.dumps({"type": "vpn_control_locations", "version": 1, "exported_at": "2026-11-13T00:00:00Z",
                                  "locations": [json.loads(item) for item in current]}, indent=2, ensure_ascii=False).encode("utf-8")
            if self.export_change is not None:
                content = self.export_change(content)
            Path(tail[3]).write_bytes(content)
            return 0, self.envelope("OK", controller, {"format": "json", "bytes": len(content)}), ""
        return super().public(argv)

    def owner(self, module, action, situation):
        owner = super().owner(module, action, situation)
        submit = owner.child

        def child(label, argv, *, new_console=False, owned_desktop=None):
            self.environments.append((label, owner.environment.get("JAVA_TOOL_OPTIONS")))
            value = submit(label, argv, new_console=new_console, owned_desktop=owned_desktop)
            value.counts = {"stdout": 0, "stderr": 0}  # The real Child's live byte counts; this one writes at its end.
            if label == cold.CACHE_FIXTURE_LABEL:
                def terminate(value=value):
                    self.terminations.append(value.ordinal)
                value.process.terminate = terminate
                self.start_fixture(value)
            return value
        owner.child = child
        return owner


class FakeHeld:
    """windows_document_native.Held as the cases use it, over a local file: its bytes, its generation, its close."""

    def __init__(self, native, path, directory=False, write=False, share=1):
        self.path, self.closed, self.security = Path(path), False, {"ownerSid": "S-1-5-21-1"}

    def current(self, stable_content=True):
        return {"sizeBytes": self.path.stat().st_size}

    def bytes(self, maximum=64 * 1024 * 1024, stable_content=True):
        raw = self.path.read_bytes()
        if len(raw) > maximum:
            raise RuntimeError("document-held-read-resource-bound")
        return raw

    def pin(self):
        raw = self.bytes()
        return {"path": str(self.path), "nativeIdentity": self.current(), "security": self.security, "sha256": sha(raw)}

    def close(self):
        if self.closed:
            raise RuntimeError("document-handle-already-closed")
        self.closed = True


class RuntimePeer:
    """windows_lifecycle_runtime_stages as the cache source uses it, over local files: publish, ready, trust, guard."""

    class OwnedData:
        def __init__(self, owner, path, expected=None, directory=False):
            self.path = Path(path)

    @staticmethod
    def data_guard(owner):
        owner.guard()

    @staticmethod
    def scoped_trust_options(path):
        return '"-Djavax.net.ssl.trustStore=' + path + '" -Djavax.net.ssl.trustStorePassword=changeit'

    @staticmethod
    def publish(owner, path, value):
        assert path.parent in {Path(owner.root), Path(owner.root) / "fixture"} and not path.exists()
        path.write_bytes((json.dumps(value, sort_keys=True) + "\n").encode())
        return path

    @staticmethod
    def read_ready(owner, child, path, operation):
        ready = json.loads(path.read_bytes())
        assert ready["operationId"] == operation and child.process.poll() is None
        return ready


class CacheFlowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_cache(self, *, change=None, guest_change=None, entries=None, held_digests=None):
        guest = CacheGuest(Path(tempfile.mkdtemp(dir=self.root)))
        digests = {key: digest for key, (_, digest) in cold.CACHE_SOURCES.items()}
        digests.update(held_digests or {})
        temp = guest.root / "document-temp"
        temp.mkdir()
        bundle = guest.root / "bundle"
        bundle.mkdir()
        paths = {"file:" + role: str(bundle / leaf) for role, leaf in (
            ("cacheFixture", "windows_document_cache_fixture.py"), ("runtime", "windows_lifecycle_runtime_stages.py"),
            ("socks", "socks_http_fixture.py"), ("https", "https_subscription_relay_fixture.py"),
            ("certificate", "document-cache-localhost.pem"), ("privateKey", "document-cache-localhost.key"),
            ("trustStore", "document-cache-trust.jks"), ("cacheBody", "document-cache-subscription.txt"))}
        body = host_job.cache_body() if entries is None else host_job.cache_body(entries)
        Path(paths["file:cacheBody"]).write_bytes(body)
        cache = host_job.cache_input(paths)
        if entries is not None:
            stored = host_job.cache_stored_locations(entries)
            newline = "\n".join(stored).encode()
            cache.update(expectedLocations=stored, expectedCount=entries, expectedNewlineBytes=len(newline),
                         expectedNewlineSha256=sha(newline), bodySha256=sha(body), bodyBytes=len(body))
        literal = {"schemaVersion": 1, "variant": "cache-bytes", "operationId": OPERATION, "cache": cache}
        if change is not None:
            change(literal)
        raw = self.literal_raw = (json.dumps(literal, sort_keys=True) + "\n").encode()
        if guest_change is not None:
            guest_change(guest)

        def pin(data, path, digest=None):
            def read(return_bytes=False, maximum=8 * 1024 * 1024):
                # As the owner's Pin.digest: a held file read for its bytes refuses beyond the caller's own maximum.
                if return_bytes and len(data) > maximum:
                    raise process_owner.Refused("held-source-bound")
                return data if return_bytes else digest or sha(data)
            return types.SimpleNamespace(path=path, record={"sha256": digest or sha(data)}, current=lambda: None, digest=read)
        windows_peer = types.SimpleNamespace(Held=FakeHeld, cache_bytes=native_module.cache_bytes)
        harness = types.SimpleNamespace(**held_harness())
        original_owner = guest.owner
        held = {"fixtureWorkerPath": "cacheFixture", "runtimeStagesPath": "runtime", "socksSourcePath": "socks", "httpsSourcePath": "https"}

        def owner_with_inputs(module, action, situation):
            owner = original_owner(module, action, situation)
            owner.request["cliPath"] = guest.cli = LAUNCHER_PATH
            owner.request["documentAcceptance"] = {"schemaVersion": 1, "clientPath": "client.py", "windowsPath": "windows.py",
                                                   "racePath": "race.py", "largeRoutingInputPath": "large.json", "spoolTempParent": str(temp),
                                                   "contexts": host_job.document_contexts(OPERATION), "endpointPinBeforeObservation": None}
            owner.operation = OPERATION
            owner.pins = [types.SimpleNamespace(directory=True, path=temp, current=lambda: None)]
            owner.by_path.update({str(Path(cold.__file__).with_name(cold.INPUT_LEAF)).casefold(): pin(raw, None)})
            for key, role in held.items():
                owner.by_path[str(Path(paths["file:" + role])).casefold()] = pin(b"", Path(paths["file:" + role]), digests[key])
            for role, data in (("certificate", b"certificate"), ("privateKey", b"key"), ("trustStore", b"store"), ("cacheBody", body)):
                owner.by_path[str(Path(paths["file:" + role])).casefold()] = pin(data, Path(paths["file:" + role]))

            def module_peer(path, name):
                if path == DOCUMENT_CASES:
                    return types.SimpleNamespace(configure_launch=cold.configure_launch, run=cold.run, close_known=cold.close_known)
                if path == "windows.py":
                    return windows_peer
                if path == paths["file:runtime"]:
                    return RuntimePeer
                return harness
            owner.module = module_peer
            return owner
        guest.owner = owner_with_inputs
        with mock.patch.object(cold, "time", guest.clock), mock.patch.object(process_owner, "time", guest.clock), \
                mock.patch.object(native_module, "Held", FakeHeld), mock.patch.object(native_module, "lexical", Path):
            try:
                code = run_owner(process_owner, guest, "document-acceptance", None)
            except Parked:
                code = None
        return guest, code

    def kinds(self, guest):
        return [kind for kind, _ in guest.events]

    def test_the_committed_cache_is_the_recipes_bytes_and_an_independent_owner_reads_it_back_unchanged(self):
        guest, code = self.run_cache()
        self.assertEqual((0, [], [(0, "NoneType", "None")]), (code, guest.parks, guest.finished))
        events = dict(guest.events)
        committed = [value for kind, value in guest.events if kind == "document-cache-committed"]
        self.assertEqual(["warm", "closed", "reopened"], [value["moment"] for value in committed])
        for value in committed:
            self.assertEqual((256, *PRODUCT_NEWLINE), (value["cacheCount"], value["newlineBytes"], value["newlineSha256"]))
            self.assertEqual(PRODUCT_NEWLINE[1], value["recordsNewlineSha256"], "the records a cold owner rebuilds the cache from")
        self.assertEqual(3, self.kinds(guest).count("document-cache-bytes"), "the document rows' own reader at each moment")
        observed = events["document-cold-observed"]
        self.assertEqual(("cache-bytes", 256, *PRODUCT_NEWLINE, 1, True, False, False),
                         (observed["variant"], observed["cacheCount"], observed["newlineBytes"], observed["newlineSha256"],
                          observed["productFetches"], observed["independentOwner"], observed["productDigestOfCache"],
                          observed["nativeAcceptanceComplete"]))
        self.assertEqual(observed["warmExport"], observed["reopenedExport"])
        stopped = events["document-cache-fixture-stopped"]
        self.assertEqual((1, 2), (stopped["productFetches"], stopped["journalEntries"]))
        order = self.kinds(guest)
        self.assertLess(order.index("document-cache-fixture-stopped"), order.index("document-cold-quit-intent"),
                        "nothing can be fetched again before the cold owner reads the cache")
        self.assertLess(order.index("document-cold-quit-intent"), order.index("document-cold-reopened"))
        owners = guest.owners(str(guest.root / "workspace"))
        self.assertEqual(2, len(owners), "the original serve and one independent serve")
        self.assertEqual(guest.generations[owners[1].ordinal], observed["controllerId"])
        self.assertTrue(all(child.terminal is not None and child.terminal["exitCode"] == 0 for child in guest.owner_object.children))
        self.assertEqual([], guest.terminations, "a pass stops the source by its own record, never by a termination")
        self.assertEqual(2, len([row for row in guest.trace if row[0] == "quit"]), "the case's quit of the original and the owner's own")

    def test_only_the_original_serve_trusts_the_source(self):
        # RED on the unfixed owner: it removed the scoped trust options after its serve only for the responsive work,
        # so every later child (the readiness status, each public call, the cold serve) started with them.
        guest, code = self.run_cache()
        self.assertEqual(0, code)
        trusted = [label for label, options in guest.environments if options is not None]
        self.assertEqual(["serve"], trusted)
        options = dict(guest.environments)["serve"]
        self.assertEqual('"-Djavax.net.ssl.trustStore=' + str(guest.root / "bundle" / "document-cache-trust.jks")
                         + '" -Djavax.net.ssl.trustStorePassword=changeit', options)
        labels = [label for label, _ in guest.environments]
        self.assertLess(labels.index(cold.CACHE_FIXTURE_LABEL), labels.index("serve"), "the source is ready before the serve exists")
        self.assertNotIn("JAVA_TOOL_OPTIONS", guest.owner_object.environment)

    def test_the_closed_read_is_of_the_file_the_original_serve_left_after_its_exit(self):
        # RED on the mutant closed-early (the closed read moved before the quit): the moments kept their order, but the
        # "closed" cache was read while the original serve still ran. The review found nothing placed that read.
        guest, code = self.run_cache()
        self.assertEqual(0, code)
        trace = guest.trace
        committed = [index for index, entry in enumerate(trace) if entry == ("event", "document-cache-committed")]
        self.assertEqual(["warm", "closed", "reopened"], [value["moment"] for kind, value in guest.events if kind == "document-cache-committed"])
        quit_intent, exited = trace.index(("event", "document-cold-quit-intent")), trace.index(("terminal", "serve", 0))
        cold_serve = next(index for index, entry in enumerate(trace) if entry[:2] == ("submit", "document-cold-serve"))
        reopened = trace.index(("event", "document-cold-reopened"))
        self.assertLess(committed[0], quit_intent, "warm: read while the original serve runs")
        self.assertLess(quit_intent, exited)
        self.assertLess(exited, committed[1], "closed: read only after the original serve's own exit")
        self.assertLess(committed[1], cold_serve, "and before any later owner of the workspace exists")
        self.assertLess(cold_serve, reopened)
        self.assertLess(reopened, committed[2], "reopened: read once the independent serve answered")

    def test_the_cache_literal_is_read_within_the_cases_own_bound(self):
        # RED on the mutant bound-64k: the case read its literal input at the base's 64 KiB, which the owner's Pin.digest
        # refuses (held-source-bound) for the 256-entry literal. The flow tests' pin used to ignore the bound, so no test saw it.
        guest, code = self.run_cache()
        self.assertEqual((0, []), (code, guest.parks))
        self.assertLess(65536, len(self.literal_raw), "the cache literal is larger than the routing variants' bound")
        self.assertLessEqual(len(self.literal_raw), cold.INPUT_LIMIT)
        with mock.patch.object(cold, "INPUT_LIMIT", len(self.literal_raw) - 1):
            guest, code = self.run_cache()
        self.assertEqual((1, [], "Refused", "held-source-bound"), (code, guest.parks, *guest.finished[0][1:]))
        self.assertIsNone(guest.fixture_child, "refused before any source or serve")

    def test_a_cache_committed_with_any_byte_or_entry_changed_is_a_known_failure(self):
        changes = {"truncated": lambda cached: cached[:-1], "one-byte": lambda cached: [cached[0].replace("Cache 000", "Cache 001")] + cached[1:],
                   "reordered": lambda cached: cached[1:] + cached[:1], "empty": lambda cached: []}
        for name, change in changes.items():
            with self.subTest(change=name):
                guest, code = self.run_cache(guest_change=lambda guest, change=change: setattr(guest, "commit_change", change))
                self.assertEqual((1, [], "document-cache-subscription-row" if name in ("truncated", "empty") else "document-committed-cache-bytes"),
                                 (code, guest.parks, guest.finished[0][2]))
                self.assertEqual(1, len(guest.owners(str(guest.root / "workspace"))), "no owner was reopened")
                self.assertEqual([guest.fixture_child.ordinal], guest.terminations, "the source is ended by one termination")
                self.assertIn("document-cache-fixture-closed", self.kinds(guest))
                self.assertTrue(all(child.terminal is not None for child in guest.owner_object.children))

    def test_a_cold_owner_that_reads_a_different_cache_is_a_known_failure_that_closes_it(self):
        def drop_last(document):
            document["locations"] = document["locations"][:-1]
            return document

        def rewrite(document):
            document["persisted_state"]["subscriptions"][0]["cached_locations"][3] = document["persisted_state"]["subscriptions"][0][
                "cached_locations"][3].replace("v6-3", "v6-x")
            return document
        for name, change, failure in (("records", drop_last, "document-cache-subscription-row"),
                                      ("cached", rewrite, "document-committed-cache-bytes")):
            with self.subTest(change=name):
                guest, code = self.run_cache(guest_change=lambda guest, change=change: setattr(guest, "reopen_change", change))
                self.assertEqual((1, [], failure), (code, guest.parks, guest.finished[0][2]))
                self.assertEqual(2, len(guest.owners(str(guest.root / "workspace"))))
                self.assertEqual(["known-failure-closing", "known-failure-quit-intent", "known-failure-serve-closed", "known-failure-closed"],
                                 [kind for kind in self.kinds(guest) if kind.startswith("known-failure")], "the reopened serve is quit")
                self.assertEqual([], guest.terminations, "the source had already stopped by its own record")

    def test_records_that_differ_from_the_committed_cache_are_seen_before_any_reopen(self):
        def change(guest):
            original = guest.commit

            def commit(workspace):
                original(workspace)
                path = guest.workspace_file(workspace)
                document = json.loads(path.read_text(encoding="utf-8"))
                document["locations"][0]["raw_link"] = "socks://192.0.2.200:1#other"
                path.write_text(json.dumps(document), encoding="utf-8")
            guest.commit = commit
        guest, code = self.run_cache(guest_change=change)
        self.assertEqual((1, [], "document-cache-location-records"), (code, guest.parks, guest.finished[0][2]))
        self.assertEqual(1, len(guest.owners(str(guest.root / "workspace"))))

    def test_an_export_that_differs_from_the_cache_is_a_known_failure(self):
        guest, code = self.run_cache(guest_change=lambda guest: setattr(guest, "export_change",
                                                                        lambda raw: raw.replace(b'"server_port": 1080', b'"server_port": 1081')))
        self.assertEqual((1, [], "document-cache-export-readback"), (code, guest.parks, guest.finished[0][2]))
        self.assertEqual([guest.fixture_child.ordinal], guest.terminations)

    def test_a_refresh_the_product_answered_final_failed_ends_the_source_and_closes(self):
        guest, code = self.run_cache(guest_change=lambda guest: setattr(guest, "refresh_answer", (1, "PARTIAL_FAILURE", True)))
        self.assertEqual((1, [], "AssertionError"), (code, guest.parks, guest.finished[0][1]))
        self.assertEqual([guest.fixture_child.ordinal], guest.terminations)
        self.assertEqual(["known-failure-closing", "known-failure-quit-intent", "known-failure-serve-closed", "known-failure-closed"],
                         [kind for kind in self.kinds(guest) if kind.startswith("known-failure")])

    def test_a_refresh_whose_outcome_is_not_final_keeps_every_original_for_the_park(self):
        guest, code = self.run_cache(guest_change=lambda guest: setattr(guest, "refresh_answer", (2, "TIMEOUT", False)))
        self.assertEqual((None, "scenario-failure-with-retained-child"), (code, guest.parks[0][0]))
        self.assertEqual([], guest.terminations, "the product may still be fetching from it")
        self.assertIsNone(guest.fixture_child.terminal)

    def test_a_fetch_other_than_the_products_own_of_the_one_path_is_a_known_failure(self):
        # stdlib-answer: a HEAD the stdlib refused (501), which the source now journals. not-a-get: a row no source writes
        # (a 200 for a POST); RED on 7e6ee369, whose oracle read no method.
        for name, extra in (("other-path", ("/subscription", PRODUCT_AGENT, 404)), ("other-agent", (None, "curl/8", 200)),
                            ("stdlib-answer", (None, PRODUCT_AGENT, 501, "HEAD")), ("not-a-get", (None, PRODUCT_AGENT, 200, "POST"))):
            with self.subTest(case=name):
                def change(guest, extra=extra):
                    guest.extra_fetch = extra
                    if extra[0] is None:
                        guest.extra_fetch = ("/subscription/cache/" + OPERATION, *extra[1:])
                guest, code = self.run_cache(guest_change=change)
                self.assertEqual((1, [], "document-cache-fixture-fetches"), (code, guest.parks, guest.finished[0][2]))
                self.assertEqual([], guest.terminations, "it had stopped by its own record")

    def test_a_ready_record_an_oracle_refuses_ends_the_source_before_any_serve(self):
        # RED on the mutant ready-unchecked: a record that misnamed the source's process, certificate, URL, body or scope
        # was taken, and the serve started with trust in it. The review found no test reached the refused branch.
        for field, value in (("pid", 1), ("certificateSha256", "0" * 64), ("cacheUrl", "https://localhost:50443/subscription"),
                             ("bodySha256", "0" * 64), ("bodyBytes", 1), ("scope", "any-source")):
            with self.subTest(field=field):
                guest, code = self.run_cache(guest_change=lambda guest, field=field, value=value: setattr(
                    guest, "ready_change", lambda ready: {**ready, field: value}))
                self.assertEqual((1, [], "document-cache-fixture-not-ready:refused:document-cache-fixture-ready-record"),
                                 (code, guest.parks, guest.finished[0][2]))
                self.assertFalse([child for child in guest.owner_object.children if child.label == "serve"], "no serve was started")
                self.assertEqual([guest.fixture_child.ordinal], guest.terminations, "one termination of the live source")
                ending = dict(guest.events)["document-cache-fixture-ending"]
                self.assertEqual(("not-ready", True, True), (ending["reason"], ending["alive"], ending["readyExists"]))
                self.assertNotIn("document-cache-fixture-ready", self.kinds(guest))
                self.assertNotIn("JAVA_TOOL_OPTIONS", guest.owner_object.environment)

    def test_a_stop_receipt_other_than_the_sources_clean_end_is_a_known_failure(self):
        # RED on the mutant stop-unchecked for exit-1 and stderr: the source's exit code and stderr were not part of its
        # receipt. terminal is the receipt's other clause, which that mutant keeps.
        for name, change in (("exit-1", {"stop_exit": 1}), ("stderr", {"stop_stderr": "Traceback (most recent call last):\n"}),
                             ("terminal", {"terminal_change": lambda terminal: {**terminal, "onlyOriginalObjectsStopped": False}})):
            with self.subTest(case=name):
                guest, code = self.run_cache(guest_change=lambda guest, change=change: guest.__dict__.update(change))
                self.assertEqual((1, [], "document-cache-fixture-stop-receipt"), (code, guest.parks, guest.finished[0][2]))
                self.assertEqual([], guest.terminations, "it had ended on its own stop record")
                self.assertNotIn("document-cache-fixture-stopped", self.kinds(guest))
                self.assertEqual(1, len(guest.owners(str(guest.root / "workspace"))), "no owner was reopened")
                self.assertEqual(["known-failure-closing", "known-failure-quit-intent", "known-failure-serve-closed", "known-failure-closed"],
                                 [kind for kind in self.kinds(guest) if kind.startswith("known-failure")], "the original serve is quit")

    def test_a_journal_other_than_the_sources_own_count_and_order_is_a_known_failure(self):
        # RED on the mutant count-unchecked for count and ordinal: a journal with a line missing or out of order passed.
        # torn and unreadable are the journal's other clauses, which that mutant keeps.
        def skip_an_ordinal(raw):
            lines = raw.splitlines(keepends=True)
            row = json.loads(lines[1])
            lines[1] = (json.dumps({**row, "ordinal": 2}) + "\n").encode()
            return b"".join(lines)
        for name, change, failure in (("count", {"entries_delta": 1}, "document-cache-journal-complete"),
                                      ("ordinal", {"journal_change": skip_an_ordinal}, "document-cache-journal-complete"),
                                      ("torn", {"journal_change": lambda raw: raw + b'{"ordinal": 2'}, "document-cache-journal-bound"),
                                      ("unreadable", {"journal_change": lambda raw: raw + b"{\n"}, "document-cache-journal-complete")):
            with self.subTest(case=name):
                guest, code = self.run_cache(guest_change=lambda guest, change=change: guest.__dict__.update(change))
                self.assertEqual((1, [], failure), (code, guest.parks, guest.finished[0][2]))
                self.assertEqual([], guest.terminations)
                self.assertNotIn("document-cache-fixture-stopped", self.kinds(guest))

    def test_an_answer_the_source_did_not_send_whole_is_a_known_failure(self):
        # RED on the mutant sent-unchecked for unsent-recipe: an answer row whose send failed passed when it still named
        # the recipe body. failed-send is the row the source writes when its send raises: no body fields at all.
        for name, change in (("unsent-recipe", lambda row: {**row, "sent": False}),
                             ("failed-send", lambda row: {"ordinal": row["ordinal"], "event": "answer", "status": 200, "sent": False,
                                                          "errorClass": "ConnectionResetError"})):
            with self.subTest(case=name):
                guest, code = self.run_cache(guest_change=lambda guest, change=change: setattr(guest, "answer_change", change))
                self.assertEqual((1, [], "document-cache-fixture-fetches"), (code, guest.parks, guest.finished[0][2]))
                self.assertEqual([], guest.terminations)

    def test_a_source_that_is_not_ready_is_ended_before_any_serve_exists(self):
        for name, change, failure in (("timeout", lambda guest: setattr(guest, "fixture_ready", False),
                                       "document-cache-fixture-not-ready:timeout:tls-context"),
                                      ("ended", lambda guest: setattr(guest, "fixture_exit", 3),
                                       "document-cache-fixture-not-ready:ended:3:body")):
            with self.subTest(case=name):
                guest, code = self.run_cache(guest_change=change)
                self.assertEqual((1, [], failure), (code, guest.parks, guest.finished[0][2]))
                self.assertFalse([child for child in guest.owner_object.children if child.label == "serve"], "no serve was started")
                self.assertEqual([guest.fixture_child.ordinal] if name == "timeout" else [], guest.terminations)
                ending = dict(guest.events)["document-cache-fixture-ending"]
                self.assertEqual(("not-ready", name == "timeout"), (ending["reason"], ending["alive"]))
                if name == "ended":
                    self.assertEqual("body", ending["failure"]["step"])
                self.assertNotIn("JAVA_TOOL_OPTIONS", guest.owner_object.environment)

    def test_a_literal_input_with_another_source_role_or_digest_refuses_before_any_effect(self):
        def wrong_role(literal):
            literal["cache"]["fixtureWorkerPath"] = literal["cache"]["socksSourcePath"]

        def wrong_digest(literal):
            literal["cache"]["expectedNewlineSha256"] = "0" * 64

        def extra(literal):
            literal["cache"]["argv"] = ["cmd.exe"]

        def routing(literal):
            literal["routingInputPath"] = "large.json"
        for name, change, failure in (("role", wrong_role, "document-cold-input-schema"), ("digest", wrong_digest, "document-cold-input-schema"),
                                      ("extra", extra, "document-cold-input-schema"), ("routing", routing, "document-cold-input-schema")):
            with self.subTest(case=name):
                guest, code = self.run_cache(change=change)
                self.assertEqual((1, [], failure), (code, guest.parks, guest.finished[0][2]))
                self.assertIsNone(guest.fixture_child, "no source was started")

    def test_a_source_role_holding_other_bytes_refuses_before_any_effect(self):
        for key in cold.CACHE_SOURCES:
            with self.subTest(role=key):
                guest, code = self.run_cache(held_digests={key: "0" * 64})
                self.assertEqual((1, [], "document-cache-fixed-source-" + key), (code, guest.parks, guest.finished[0][2]))
                self.assertIsNone(guest.fixture_child, "no source was started")
        guest, code = self.run_cache(change=lambda literal: literal["cache"].update(runtimeStagesPath=literal["cache"]["bodyPath"]))
        self.assertEqual((1, "document-cold-input-schema"), (code, guest.finished[0][2]), "one held file in two roles")
        self.assertIsNone(guest.fixture_child)


class TrustGuest(ColdGuest):
    """The inert guest whose case module, like the cache variant, gives the serve it is about to start scoped trust."""

    def __init__(self, root, **options):
        super().__init__(root, **options)
        self.environments = []

    def owner(self, module, action, situation):
        owner = super().owner(module, action, situation)
        submit = owner.child

        def child(label, argv, *, new_console=False, owned_desktop=None):
            self.environments.append((label, owner.environment.get("JAVA_TOOL_OPTIONS")))
            return submit(label, argv, new_console=new_console, owned_desktop=owned_desktop)
        owner.child = child

        def configure_launch(owner, workspace):
            owner.environment["JAVA_TOOL_OPTIONS"] = '"-Djavax.net.ssl.trustStore=C:\\trust.jks"'

        def run(owner, workspace, identity, harness):
            harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity, "status"))
        owner.module = lambda path, name: (types.SimpleNamespace(configure_launch=configure_launch, run=run, close_known=lambda *a: None)
                                           if path == DOCUMENT_CASES else types.SimpleNamespace(**held_harness()))
        return owner


class OwnerTrustTests(unittest.TestCase):
    def test_scoped_trust_a_document_case_gives_its_serve_reaches_no_later_child(self):
        # RED on the unfixed owner, which removed the options after its serve only for the responsive work: the readiness
        # status, every public call and the quit then started under them, and a JVM says "Picked up JAVA_TOOL_OPTIONS"
        # on stderr, which fails each public call's empty-stderr oracle.
        with tempfile.TemporaryDirectory() as temporary:
            guest = TrustGuest(Path(temporary))
            with mock.patch.object(process_owner, "time", guest.clock):
                code = run_owner(process_owner, guest, "document-acceptance", None)
        self.assertEqual((0, []), (code, guest.parks))
        self.assertEqual(["serve"], [label for label, options in guest.environments if options is not None])
        labels = [label for label, _ in guest.environments]
        self.assertEqual(["help", "version", "serve"], labels[:3])
        self.assertLess(3, len(labels), "the readiness status and the case's public calls came after the serve")


class RowTests(unittest.TestCase):
    def test_the_row_is_admitted_with_its_sources_and_generated_files_and_proves_no_scenario_alone(self):
        row = windows.RECIPES[ROW]
        self.assertIsNone(row["refusal"])
        self.assertEqual({"variant": "cache-bytes", "principalProbe": False, "rootSubfolders": ("document-temp",)}, row["document"])
        self.assertEqual(["owner", "worker", "cases", "client", "windows", "race", "harness", "diagnostic", "cacheFixture", "runtime",
                          "socks", "https"], [role for _, role, _ in row["guestFiles"]])
        self.assertEqual((*host_job.CACHE_TLS, ("cacheBody", "document-cache-subscription.txt"), ("coldInput", "document-cold-input.json")),
                         row["generated"])
        # RED on 7e6ee369, which named this row for cache-digest-bytes: it proves the committed cache's readback only, while
        # the scenario's Android anchor also fails a read of truncated bytes, and the desktop store writes its default
        # workspace over a workspace.json that does not decode. No row corrupts one yet, so the scenario maps to no row.
        self.assertEqual((), windows.MATRIX_SCENARIOS["document-persistence-transfer"]["cache-digest-bytes"])
        self.assertEqual([], [scenario for table in windows.MATRIX_SCENARIOS.values() for scenario, rows in table.items() if ROW in rows])
        self.assertIn("agent_tools/windows_document_cache_fixture.py", bundles._SCENARIOS["windows-scenario-driver"])


if __name__ == "__main__":
    unittest.main()
