"""Causal guard coverage for a measured Windows recovery transition.

These full nonsecret PNGs came from the retained tertiary ordinary navigation:
0.5 seconds after Enter, QMP captured only a dark blue transition. The actual
step correctly returned UNKNOWN rather than sending a following key. This
local test presents the same transition after the first key to verify the
same guard stops the remaining sequence; it is not native timing acceptance.
Process phase and guest paths are fixture projections; QMP response framing,
root UID, socket peer and screenshot ownership are simulated. The actual UI
decision, journal writer and full screenshot byte hashes execute.
"""
import unittest,uuid
from agent_tools import windows_parallel_vm_launch as launch,windows_tertiary_vm_recovery as recovery
class ActualTransientUiDecisionTest(unittest.TestCase):
    def test_actual_blue_transition_stops_before_next_key_and_never_replays(self):
        import hashlib, json, os, socket, struct, tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        for wrong_peer in (False,):
            with self.subTest(wrong_peer=wrong_peer), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); guest_root = root / 'tertiary'; state = guest_root / 'vm-state'
                state.mkdir(parents=True); template = root / 'template.qcow2'; template.write_bytes(b'TEMPLATE')
                sockpath = state / 'qmp.sock'; original_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                original_socket.bind(str(sockpath)); original_socket.close()
                guest = launch.Guest('tertiary', guest_root, 2338, 5938, '52:54:00:57:50:22')
                prepared = {'template': str(template), 'templateGeneration': launch.inventory.generation(template.lstat()),
                    'overlays': [{'path': str(guest_root / 'disk.qcow2'), 'guestGeneration': launch.inventory.parent_identity(guest_root.lstat())}]}
                raw = json.dumps({'identities': [{}, {'pid': 3474306, 'startTicks': 21163512}]}).encode()
                proof = {'original': {'unknownBase64': __import__('base64').b64encode(raw).decode()}}
                commands = []
                evidence=Path(__file__).parent/'fixtures/windows_tertiary_recovery'
                before_png=(evidence/'automatic-repair-before.png').read_bytes()
                transition_png=(evidence/'advanced-transition.png').read_bytes()
                self.assertEqual(hashlib.sha256(before_png).hexdigest(),recovery.UI_STEPS['advanced'][0])
                self.assertEqual(hashlib.sha256(transition_png).hexdigest(),'6465d38f4d5ce9a31db57a46244d6d8e611914ad140fe30f62ba34c22078ee32')
                class Connection:
                    def __enter__(self): return self
                    def __exit__(self, *args): pass
                    def settimeout(self, timeout): pass
                    def connect(self, path): self.path = path
                    def getsockopt(self, *args): return struct.pack('3i', 777 if wrong_peer else 3474306, 1000, 1000)
                    def sendall(self, raw):
                        self.request = json.loads(raw); commands.append(self.request['execute'])
                        if self.request['execute'] == 'screendump':
                            Path(self.request['arguments']['filename']).write_bytes(before_png if commands.count('screendump')==1 else transition_png)
                connection = Connection()
                class Framer:
                    frames = 0
                    def bind(self, *args): return self
                    def _read_qmp_response(self, conn, deadline):
                        self.frames += 1
                        if self.frames == 1: return b'{"QMP":{}}'
                        request = conn.request
                        return json.dumps({'id': request['id'], 'return': {'status': 'running'} if request['execute'] == 'query-status' else {}}).encode()
                real_lstat = Path.lstat; real_hash = launch.file_hash
                def projected_lstat(path):
                    result = real_lstat(path)
                    if path == sockpath or path.suffix == '.png':
                        values = {name: getattr(result, name) for name in ['st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns']}
                        values.update(st_uid=1000, st_gid=1000)
                        return SimpleNamespace(**values)
                    return result
                def projected_hash(fd, maximum):
                    result = real_hash(fd, maximum)
                    result['generation'][3:5] = [1000, 1000]
                    return result
                # Project process phase/guest paths, emulate QMP responses and OS UID/peer;
                # actual UI source, receipt writer, file bytes/hash/namespace and
                # decisions execute. No socket to a guest is opened.
                with patch.object(os, 'geteuid', return_value=0), \
                     patch.object(recovery, 'tertiary_phase', return_value={}), \
                     patch.object(launch, 'fixed_guest', return_value=guest), \
                     patch.object(launch, 'AccessClient', side_effect=lambda *a, **kw: Framer()), \
                     patch.object(socket, 'socket', return_value=connection), \
                     patch.object(socket, 'SO_PEERCRED', 17, create=True), \
                     patch.object(Path, 'lstat', projected_lstat), \
                     patch.object(launch, 'file_hash', side_effect=projected_hash):
                    value = recovery.tertiary_ui_step(prepared, proof, str(uuid.uuid4()), 'advanced')
                self.assertEqual(value['state'], 'unknown')
                self.assertEqual(value['reason'], 'tertiary-ui-after-screen')
                self.assertEqual(commands.count('send-key'),1)
                self.assertEqual(commands.count('screendump'),2)
                self.assertNotIn('system_powerdown',commands)
                self.assertNotIn('quit',commands)
                journals = list(root.glob('tertiary-ui-*/unknown.json'))
                self.assertEqual(len(journals), 1)
                self.assertFalse(json.loads(journals[0].read_bytes())['replayAllowed'])

if __name__=='__main__':unittest.main()
