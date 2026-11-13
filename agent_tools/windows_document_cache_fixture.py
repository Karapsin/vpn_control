"""One owned in-guest subscription source for the document cache row (windows-document-cold.cache-bytes).

No import-time listener or action. No upstream Internet, proxy, runtime or VM control: loopback only,
the producer's own localhost TLS listener and its relay inside the guest. The original ordinary Owner
holds every script, TLS and input file before its Child starts this source.

It serves exactly one path, /subscription/cache/<operationId>, to a GET, with the exact body the host job
made from its recipe (bodyPath, checked against bodySha256 before any listener). From its listening step
on, before the ready file names its port, it journals every request its HTTPS listener answers before the
answer goes, and how the answer ended: the stdlib's own answers to another method, or to a request line
or headers it cannot parse, too, and those never carry a body. The producer's relay beside it answers no
request itself: with forwarding set, it refuses every destination but that listener. The installed
product's own refresh is its only expected client. A start says each step on stdout before entering it,
as the gated work fixture does; one that
fails before the ready file is published has served nobody: it says the step and the error in a finite
record, stops its own listeners and ends with START_FAILED. After readiness it serves until the owner's
exact stop record, then stops only its own listeners and says so. Anything else after readiness keeps
the same fixture, threads and sockets, says why once, and is never restarted.
"""
from __future__ import annotations
import hashlib, json, os, stat, sys, threading, time, traceback, types, uuid
from pathlib import Path

# The two producer sources, the same pinned bytes the gated work fixture and the proxy rows load.
SOURCES = {'https': 'e62f262d9703eb63c0eeca9b823eaae9d1a5780aefdedadf8aebe211492651d4',
           'socks': '50239b25bb1c63e7c86baaea8683f188426e87d6a1c6090b505c38d567e70210'}
STEPS = ('input', 'sources', 'body', 'tls-context', 'https-listen', 'relay-listen', 'listening', 'certificate-digest',
         'ready-create', 'ready-rename')
INPUT_FIELDS = frozenset({'schemaVersion', 'operationId', 'socksSourcePath', 'httpsSourcePath', 'certificatePath',
                          'privateKeyPath', 'bodyPath', 'bodySha256', 'readyFile', 'controlFile', 'journalFile', 'token'})
BODY_LIMIT = 1024 * 1024
JOURNAL_LIMIT = 1024 * 1024
AGENT_LIMIT = 128
METHOD_LIMIT = 16
# The gated work fixture's handshake wait: a JVM's first handshake is not cut at the producer's 0.25 s.
TLS_HANDSHAKE_SECONDS = 5
START_FAILED = 3
CURRENT = ['none']


class Refusal(ValueError):
    """One of this source's own finite codes."""


def need(ok, reason):
    if not ok:
        raise Refusal(reason)


def step(name):
    """Said before the step is entered, so a start that stops or stays there has named it."""
    need(name in STEPS, 'finite-cache-step')
    CURRENT[0] = name
    print(json.dumps({'kind': 'owned-cache-fixture-step', 'step': name}), flush=True)


def failure(error):
    """What stopped the fixture, finite and private-safe: its step, the error class, an OS error's codes, one of this source's codes."""
    codes = [getattr(error, name, None) for name in ('winerror', 'errno')]
    return {'step': CURRENT[0], 'errorClass': type(error).__name__, 'winerror': codes[0] if type(codes[0]) is int else None,
            'errno': codes[1] if type(codes[1]) is int else None, 'reason': str(error) if type(error) is Refusal else None}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_exact(path, limit):
    """One regular single-link file read through one descriptor, unchanged by handle and by name while it is read."""
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    try:
        held = os.fstat(fd)
        need(stat.S_ISREG(held.st_mode) and held.st_nlink == 1 and held.st_size <= limit, 'cache-input-bound-type')
        blocks, remaining = [], held.st_size + 1
        while remaining:
            block = os.read(fd, remaining)
            if not block:
                break
            blocks.append(block)
            remaining -= len(block)
        raw = b''.join(blocks)
        after, named = os.fstat(fd), os.stat(path, follow_symlinks=False)
        need(stat.S_ISREG(named.st_mode) and not getattr(named, 'st_file_attributes', 0) & 0x400, 'cache-input-closing:name-type')
        need((named.st_dev, named.st_ino) == (held.st_dev, held.st_ino), 'cache-input-closing:identity')
        need(all(getattr(after, 'st_' + field) == getattr(held, 'st_' + field)
                 for field in ('dev', 'ino', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns')), 'cache-input-closing:handle')
        need(len(raw) == held.st_size, 'cache-input-closing:count-size')
        return raw
    finally:
        os.close(fd)


def publish(path, value, entering=None):
    """The ready file: written whole under a new name, then renamed, so a reader never sees part of it."""
    raw = encoded(value)
    need(len(raw) <= 16384, 'cache-ready-bound')
    temporary = path.with_name(path.name + '.publishing')
    if entering:
        entering('ready-create')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            need(count > 0, 'cache-ready-short-write')
            at += count
        os.fsync(fd)
    finally:
        os.close(fd)
    if entering:
        entering('ready-rename')
    if os.name == 'nt':
        os.rename(temporary, path)  # Windows refuses replacement.
    else:
        os.link(temporary, path)
        temporary.unlink()


def load(path, role):
    raw = read_exact(path, 1024 * 1024)
    need(sha(raw) == SOURCES[role], 'cache-fixture-exact-source')
    name = 'socks_http_fixture' if role == 'socks' else '_owned_cache_https'
    need(name not in sys.modules, 'cache-fixture-module-name')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class Journal:
    """Create-only request journal: one complete line per entry, flushed to disk before the answer goes on."""

    def __init__(self, path):
        self.lock, self.count, self.size = threading.Lock(), 0, 0
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600)

    def write(self, row):
        with self.lock:
            raw = encoded({'ordinal': self.count, **row})
            need(self.size + len(raw) <= JOURNAL_LIMIT, 'cache-journal-bound')
            at = 0
            while at < len(raw):
                count = os.write(self.fd, raw[at:])
                need(count > 0, 'cache-journal-short-write')
                at += count
            os.fsync(self.fd)
            self.count += 1
            self.size += len(raw)

    def close(self):
        with self.lock:
            os.close(self.fd)


def answer(server, method, path, agent, send, status=None):
    """One request: journaled before its answer, then how the answer ended. Only a GET of the one owned path is served.

    A status is given only for the stdlib's own answer to a request no do_ method reached; it never carries the body."""
    if status is None:
        status = 200 if method == 'GET' and path == server.cache_path else 404
    request = {'event': 'request', 'method': method[:METHOD_LIMIT], 'path': path if len(path) <= 256 else path[:256],
               'status': status, 'userAgent': agent[:AGENT_LIMIT], 'agentTruncated': len(agent) > AGENT_LIMIT}
    server.cache_journal.write(request)
    try:
        send(status, server.cache_body if status == 200 else b'')
    except BaseException as error:
        server.cache_journal.write({'event': 'answer', 'status': status, 'sent': False, 'errorClass': type(error).__name__})
        raise
    server.cache_journal.write({'event': 'answer', 'status': status, 'sent': True,
                                'bodyBytes': len(server.cache_body) if status == 200 else 0,
                                'bodySha256': server.cache_body_sha256 if status == 200 else None})


def fixture_class(source):
    class Handler(source._SubscriptionHandler):
        def cache_request(self):
            """The method, path and User-Agent as far as the stdlib parsed them: a request it refused may have none yet."""
            headers = getattr(self, 'headers', None)
            agent = headers.get('User-Agent', '') if headers is not None else ''
            return str(getattr(self, 'command', None) or ''), str(getattr(self, 'path', None) or ''), str(agent)

        def cache_send(self, status, body):
            self.send_response(status)
            if status == 200:
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
            else:
                self.send_header('Connection', 'close')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)
            self.wfile.flush()

        def do_GET(self):
            answer(self.server, *self.cache_request(), self.cache_send)

        def send_error(self, code, message=None, explain=None):
            # Only the stdlib calls this, for a request no do_ method reached: another method (501), a request line
            # or headers it cannot parse (400, 431, 505) or a line too long (414). This handler's own answers never do.
            answer(self.server, *self.cache_request(), self.cache_send, status=code)

    def entered(name, call):
        def enter(*args, **kwargs):
            step(name)
            return call(*args, **kwargs)
        return enter
    if not getattr(source, 'cache_steps_named', False):
        # Private loaded module only, before start: the unchanged start() names its two listeners as it makes them.
        source._localhost_tls_server = entered('https-listen', source._localhost_tls_server)
        source.FixtureServer = entered('relay-listen', source.FixtureServer)
        source.cache_steps_named = True

    class Fixture(source.HttpsSubscriptionRelayFixture):
        def __init__(self, value, body):
            self.cache_value, self.cache_raw, self.cache_failure = value, body, None
            super().__init__(Path(value['certificatePath']), Path(value['privateKeyPath']), Path(value['readyFile']), value['token'])

        def start(self):
            step('tls-context')
            ready = super().start()
            # A failed publication is raised here, after the unchanged start() returned with both listeners serving:
            # that start() closes a listening socket under its serving thread when its own body fails.
            if self.cache_failure is not None:
                raise self.cache_failure
            return ready

        def _publish_readiness(self, ready):
            try:
                step('listening')
                server, value = self.https_server, self.cache_value
                server.cache_path = '/subscription/cache/' + value['operationId']
                server.cache_body, server.cache_body_sha256 = self.cache_raw, value['bodySha256']
                server.cache_journal = Journal(Path(value['journalFile']))
                server.RequestHandlerClass = Handler
                step('certificate-digest')
                digest = sha(read_exact(value['certificatePath'], 1024 * 1024))
                publish(Path(value['readyFile']), {**ready, 'operationId': value['operationId'], 'pid': os.getpid(),
                    'cacheUrl': 'https://localhost:%d%s' % (ready['httpsPort'], server.cache_path),
                    'certificateSha256': digest, 'bodySha256': value['bodySha256'], 'bodyBytes': len(self.cache_raw),
                    'scope': 'one-owned-subscription-source', 'nativeAcceptance': False}, step)
            except BaseException as error:
                self.cache_failure = error
    return Fixture


def start_failed(fixture, error):
    """A start that failed before its ready file was published: no request can have reached it.

    Its own listeners are shut down in order if they serve, the step and the error go to stdout as one
    finite record and the traceback to stderr, and the process ends with START_FAILED."""
    stopped = True
    try:
        if fixture is not None and (fixture.https_server is not None or fixture.relay_server is not None):
            fixture.stop()
    except BaseException:
        stopped = False
    try:
        print(json.dumps({'kind': 'owned-cache-fixture-failed', **failure(error), 'listenersStopped': stopped}), flush=True)
        traceback.print_exception(type(error), error, error.__traceback__)
    except BaseException:
        pass
    return START_FAILED


def validate(value):
    need(type(value) is dict and set(value) == INPUT_FIELDS and type(value['schemaVersion']) is int and value['schemaVersion'] == 1,
         'finite-cache-input-schema')
    need(str(uuid.UUID(value['operationId'])) == value['operationId'] and type(value['token']) is str
         and 0 < len(value['token'].encode()) <= 4096 and type(value['bodySha256']) is str and len(value['bodySha256']) == 64,
         'finite-cache-input-identity')
    outputs = [Path(value[key]) for key in ('readyFile', 'controlFile', 'journalFile')]
    need(len(set(outputs)) == 3 and len({path.parent for path in outputs}) == 1 and not any(path.exists() for path in outputs),
         'fresh-owned-cache-root')
    return value


def main(argv):
    fixture = None
    try:
        step('input')
        need(len(argv) == 2 and argv[0] == '--input', 'finite-cache-entry')
        value = validate(json.loads(read_exact(argv[1], 16384)))
        step('sources')
        load(value['socksSourcePath'], 'socks')
        source = load(value['httpsSourcePath'], 'https')
        source.TLS_HANDSHAKE_TIMEOUT_SECONDS = TLS_HANDSHAKE_SECONDS
        step('body')
        body = read_exact(value['bodyPath'], BODY_LIMIT)
        need(0 < len(body) and sha(body) == value['bodySha256'], 'cache-body-recipe')
        fixture = fixture_class(source)(value, body)
        ready = fixture.start()
    except BaseException as error:
        return start_failed(fixture, error)
    try:
        print(json.dumps({'kind': 'owned-cache-fixture-ready', 'operationId': value['operationId'], 'ready': ready}), flush=True)
        while True:
            if Path(value['controlFile']).exists():
                stop = json.loads(read_exact(value['controlFile'], 1024))
                need(stop == {'schemaVersion': 1, 'operationId': value['operationId'], 'action': 'stop-owned-fixture'},
                     'exact-cache-stop')
                break
            time.sleep(.1)
        journal = fixture.https_server.cache_journal
        fixture.stop()
        journal.close()
        print(json.dumps({'kind': 'owned-cache-fixture-terminal', 'operationId': value['operationId'],
                          'journalEntries': journal.count, 'onlyOriginalObjectsStopped': True}), flush=True)
    except BaseException as error:
        # Preserve the original fixture, threads, sockets and primary traceback in the same lifecycle frame.
        # No restart or second stop follows uncertainty. After readiness a request may be in flight, so this stays.
        fixture.cache_lifetime_primary = error
        CURRENT[0] = 'serving'
        try:
            print(json.dumps({'kind': 'owned-cache-fixture-retained', **failure(error)}), flush=True)
        except BaseException:
            pass
        while True:
            time.sleep(1)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
