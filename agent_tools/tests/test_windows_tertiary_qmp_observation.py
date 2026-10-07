"""Actual Unix socket regressions for the fixed read-only protocol slice."""
import json
import os
import socket
import tempfile
import threading
import unittest
import time
from unittest import mock
import subprocess
import ast
import hashlib
import types
from pathlib import Path
from agent_tools import windows_parallel_vm_source_inventory as inventory

from agent_tools import windows_tertiary_qmp_observation as observation


# Exact protocol AST from historical a223d50b65de40aa62d61d4728c942366a2750ba9b0c2b2a3c1bb87e3e8a9afb.
# Nonsecret source excerpt only; no runtime dependency or native guard projection.
LEGACY_PROTOCOL = "def qmp_read():\n    data = bytearray()\n    stop = time.monotonic() + 10\n    for count in range(16384):\n        need(time.monotonic() < stop, 'terminal-observe-qmp-deadline')\n        b = q.recv(1)\n        need(bool(b), 'terminal-observe-qmp-eof')\n        data.extend(b)\n        if b == b'\\n':\n            return json.loads(data)\n    raise ValueError('terminal-observe-qmp-bound')\ngreeting = qmp_read()\nneed(type(greeting) is dict and 'QMP' in greeting, 'terminal-observe-qmp-greeting')\nresults = []\nfor command in ['qmp_capabilities', 'query-status']:\n    q.sendall((json.dumps({'execute': command}) + '\\n').encode())\n    response = None\n    for attempt in range(8):\n        candidate = qmp_read()\n        if 'event' in candidate:\n            continue\n        response = candidate\n        break\n    need(type(response) is dict and 'return' in response and ('error' not in response), 'terminal-observe-qmp-reply')\n    results.append(response['return'])\nneed(type(results[1]) is dict and type(results[1].get('status')) is str and (len(results[1]['status']) <= 128) and (type(results[1].get('running')) is bool) and (type(results[1].get('singlestep')) is bool), 'terminal-observe-status-types')"


def legacy_query(sock, correlation):
    def need(condition, reason):
        if not condition:
            raise ValueError(reason)
    namespace = {"q": sock, "json": json, "time": time, "need": need}
    exec(compile(LEGACY_PROTOCOL, "historical-qmp-protocol", "exec"), namespace)
    return namespace["results"][1]


class QmpObservationTests(unittest.TestCase):
    def test_channel_admission_nochild_positive_and_malformed(self):
        with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('NoChild')), mock.patch.object(subprocess, 'run', side_effect=AssertionError('NoChild')):
            positive = observation.parse_channel_admission(['a' * 32, 'b' * 64])
            self.assertEqual(positive, observation.verify_channel_admission(positive, positive))
            for malformed in ([], ['a' * 32], ['a' * 32, 'b' * 64, 'extra'], [True, 'b' * 64], ['A' * 32, 'b' * 64], ['a' * 32, 'b' * 63], ['../foreign', 'b' * 64], ['a' * 32, 'b' * 64 + '\n']):
                with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                    observation.parse_channel_admission(malformed)
            for mismatch in ({**positive, 'correlationId': 'c' * 32}, {**positive, 'receiptSha256': 'd' * 64}, {}, None):
                with self.subTest(metadata=mismatch), self.assertRaises(ValueError):
                    observation.verify_channel_admission(mismatch, positive)

    def exchange(self, case, query=observation.query_status):
        client, server = socket.socketpair()
        client.settimeout(2)
        server.settimeout(2)
        failures = []

        def serve():
            try:
                with server:
                    server.sendall(b'{"QMP":{}}\n')
                    stream = server.makefile('rb')
                    for index in range(2):
                        request = json.loads(stream.readline())
                        rid = request.get('id')
                        if case == 'eof':
                            return
                        if case == 'events':
                            server.sendall(b'{"event":"PUBLIC"}\n' * 8)
                            return
                        if index == 1 and case == 'duplicate':
                            frame = ('{"return":{"status":"running","running":true,'
                                     '"running":false,"singlestep":false},"id":' +
                                     json.dumps(rid) + '}\n').encode()
                        else:
                            value = {} if index == 0 else {
                                'status': 'running', 'running': True, 'singlestep': False}
                            frame = (json.dumps({'return': value,
                                      'id': 'FOREIGN' if case == 'foreign' else rid}) + '\n').encode()
                        server.sendall(frame)
                        if case == 'foreign' and query is observation.query_status:
                            return
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        with tempfile.TemporaryFile() as journal:
            owned_fd = os.dup(journal.fileno())
            try:
                value = query(client, 'PUBLIC')
                return value
            finally:
                observation.close_observation(client, owned_fd)
                self.assertEqual(client.fileno(), -1)
                with self.assertRaises(OSError):
                    os.fstat(owned_fd)
                thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(failures, [])

    def test_actual_socket_positive(self):
        self.assertIs(self.exchange('valid')['running'], True)

    def test_actual_duplicate_reply_refused_and_descriptors_closed(self):
        with self.assertRaisesRegex(ValueError, 'duplicate-key'):
            self.exchange('duplicate')

    def test_actual_foreign_reply_refused_and_descriptors_closed(self):
        with self.assertRaisesRegex(ValueError, 'qmp-reply$'):
            self.exchange('foreign')

    def test_actual_eof_refused_and_descriptors_closed(self):
        with self.assertRaisesRegex(ValueError, 'qmp-eof'):
            self.exchange('eof')

    def test_actual_event_bound_refused(self):
        with self.assertRaisesRegex(ValueError, 'qmp-reply$'):
            self.exchange('events')

    def test_journal_closes_when_socket_close_raises(self):
        class BrokenClose:
            def close(self):
                raise ValueError('PUBLIC-close-failure')
        with tempfile.TemporaryFile() as journal:
            fd = os.dup(journal.fileno())
            with self.assertRaisesRegex(ValueError, 'PUBLIC-close-failure'):
                observation.close_observation(BrokenClose(), fd)
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_actual_historical_duplicate_red_fixed_green(self):
        self.assertIs(self.exchange("duplicate", legacy_query)["running"], False)
        with self.assertRaisesRegex(ValueError, "duplicate-key"):
            self.exchange("duplicate")

    def test_actual_historical_foreign_red_fixed_green(self):
        self.assertIs(self.exchange("foreign", legacy_query)["running"], True)
        with self.assertRaisesRegex(ValueError, "qmp-reply$"):
            self.exchange("foreign")

# Exact typed4d8 complete verify AST; process/path/route facts projected explicitly.
OLD_SOURCE_VERIFY = "def verify():\n    originalPs = __import__('subprocess').run(['/bin/ps', '-p', '54599,54592', '-o', 'pid=,ppid=,uid=,lstart=,comm='], capture_output=True)\n    transport.need(originalPs.returncode == 1 and originalPs.stdout == b'' and (originalPs.stderr == b''), 'tertiary-original-local-terminal')\n    originalTerminal = json.loads(Path('/Users/karapsin_de/Nextcloud/projects/vpn_control/.runtime/parity-evidence/windows-tertiary-reboot-eec0f760b60843429bbd64a3e25ce46d/result.json').read_bytes())\n    transport.need(originalTerminal.get('originalTransportPid') == 54599 and originalTerminal.get('exitCode') == 255 and (originalTerminal.get('stdoutEof') is True) and (originalTerminal.get('state') == 'unknown'), 'tertiary-original-terminal-receipt')\n    for p, fd, pin, parents in held:\n        os.lseek(fd, 0, 0)\n        digest = hashlib.sha256()\n        size = 0\n        while True:\n            b = os.read(fd, 65536)\n            if not b:\n                break\n            digest.update(b)\n            size += len(b)\n        transport.need(inventory.generation(os.fstat(fd)) == pin['generation'] == inventory.generation(p.lstat()) and digest.hexdigest() == pin['sha256'] and (size == pin['generation'][6]) and (inventory.parent_pins(p, root) == parents), 'tertiary-source-closure')\n    transport.need(hashlib.sha256(program).hexdigest() == proof['programSha256'] and hashlib.sha256(wrapper).hexdigest() == proof['wrapperSha256'], 'tertiary-program-binding')\n    currentConfig = ssh_transport.load_config(root)\n    from agent_tools import ssh_channel_selection as selection\n    selected = selection.selected_route_options(root, 'archlinux', currentConfig)\n    qmpAdmission.verify_channel_admission(selected, channelAdmission)"
FIXED_SOURCE_VERIFY = "def verify():\n    originalPs = __import__('subprocess').run(['/bin/ps', '-p', '54599,54592', '-o', 'pid=,ppid=,uid=,lstart=,comm='], capture_output=True)\n    transport.need(originalPs.returncode == 1 and originalPs.stdout == b'' and (originalPs.stderr == b''), 'tertiary-original-local-terminal')\n    originalTerminal = json.loads(Path('/Users/karapsin_de/Nextcloud/projects/vpn_control/.runtime/parity-evidence/windows-tertiary-reboot-eec0f760b60843429bbd64a3e25ce46d/result.json').read_bytes())\n    transport.need(originalTerminal.get('originalTransportPid') == 54599 and originalTerminal.get('exitCode') == 255 and (originalTerminal.get('stdoutEof') is True) and (originalTerminal.get('state') == 'unknown'), 'tertiary-original-terminal-receipt')\n    for p, fd, pin, parents in held:\n        os.lseek(fd, 0, 0)\n        digest = hashlib.sha256()\n        size = 0\n        while True:\n            b = os.read(fd, 65536)\n            if not b:\n                break\n            digest.update(b)\n            size += len(b)\n        transport.need(inventory.generation(os.fstat(fd)) == pin['generation'] == inventory.generation(p.lstat()) and digest.hexdigest() == pin['sha256'] and (size == pin['generation'][6]) and (inventory.parent_pins(p, root) == parents), 'tertiary-source-closure')\n    transport.need(hashlib.sha256(program).hexdigest() == proof['programSha256'] and hashlib.sha256(wrapper).hexdigest() == proof['wrapperSha256'], 'tertiary-program-binding')\n    currentConfig = ssh_transport.load_config(root)\n    from agent_tools import ssh_channel_selection as selection\n    selected = selection.selected_route_options(root, 'archlinux', currentConfig)\n    qmpAdmission.verify_channel_admission(selected, channelAdmission)\n    for p, fd, pin, parents in held:\n        transport.need(inventory.generation(os.fstat(fd)) == pin['generation'] == inventory.generation(p.lstat()) and inventory.parent_pins(p, root) == parents, 'tertiary-source-final-population')"


class SourcePopulationTests(unittest.TestCase):
    def exercise(self, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            earlier, later = root / 'earlier.py', root / 'later.py'
            earlier.write_bytes(b'original'); later.write_bytes(b'later')
            terminal = root / 'terminal.json'
            terminal.write_text(json.dumps({'originalTransportPid':54599,'exitCode':255,'stdoutEof':True,'state':'unknown'}))
            held = []
            for path in (earlier,later):
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
                held.append((path,fd,{'generation':inventory.generation(os.fstat(fd)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()},inventory.parent_pins(path,root)))
            read=os.read; changed=[]
            def read_then_mutate(fd,count):
                data=read(fd,count)
                if fd==held[1][1] and not data and not changed:
                    earlier.write_bytes(b'originalforeign');changed.append(True)
                return data
            def need(condition,reason):
                if not condition:raise ValueError(reason)
            def projected_path(value):
                return terminal
            program=b'PUBLICPROGRAM';wrapper=b'PUBLICWRAPPER'
            admission={'correlationId':'a'*32,'receiptSha256':'b'*64}
            namespace={'Path':projected_path,'json':json,'os':os,'hashlib':hashlib,'inventory':inventory,'transport':types.SimpleNamespace(need=need),'root':root,'held':held,'program':program,'wrapper':wrapper,'proof':{'programSha256':hashlib.sha256(program).hexdigest(),'wrapperSha256':hashlib.sha256(wrapper).hexdigest()},'ssh_transport':types.SimpleNamespace(load_config=lambda root:None),'request':{},'channelAdmission':admission,'qmpAdmission':observation}
            from agent_tools import ssh_channel_selection as selection
            exec(compile(source,'actual-verify-fixture','exec'),namespace)
            try:
                with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('NoChild')),mock.patch.object(subprocess,'run',return_value=types.SimpleNamespace(returncode=1,stdout=b'',stderr=b'')),mock.patch.object(selection,'selected_route_options',return_value=admission),mock.patch.object(os,'read',side_effect=read_then_mutate):
                    namespace['verify']()
                self.assertEqual([True],changed)
            finally:
                for _,fd,_,_ in held:os.close(fd)
    def test_actual_complete_verify_old_accepts_mutation_fixed_refuses(self):
        self.exercise(OLD_SOURCE_VERIFY)
        with self.assertRaisesRegex(ValueError,'tertiary-source-final-population'):
            self.exercise(FIXED_SOURCE_VERIFY)
