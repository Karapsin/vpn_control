"""Physical Unix-socket counterfactual for the complete public input RPC."""
import hashlib,json,sys,unittest
from pathlib import Path
from agent_tools import windows_guest_input as subject
from agent_tools.tests.connected_input_peer_causal import prove


@unittest.skipUnless(sys.platform=='linux','actual Linux SO_PEERCRED PID/UID')
class ConnectedPeerTests(unittest.TestCase):
    def test_foreign_connected_peer_is_rejected_before_sync_or_guest_command(self):
        folder=Path(__file__).parent/'fixtures/windows_input_connected_peer';raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['fragmentSha256'],hashlib.sha256(raw).hexdigest())
        value=prove(raw.decode(),subject._REMOTE_RUNTIME)
        self.assertEqual('RED',value['before']);self.assertEqual('GREEN',value['after'])
        self.assertTrue(value['wrongPidRejectedBeforeSend']);self.assertTrue(value['wrongUidRejectedBeforeSend'])


if __name__=='__main__':unittest.main()
