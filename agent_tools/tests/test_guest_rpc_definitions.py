"""Actual complete RPC namespace; protocol/process IO is a finite unit seam."""
import base64
import hashlib
import json
import os
import struct
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock
from agent_tools import windows_vm_deploy_remote as producer


class GuestRpcDefinitionTests(unittest.TestCase):
    def test_preserved_missing_import_fails_before_socket_current_complete_namespace_reaches_exact_reply(self):
        folder=Path(__file__).parent/'fixtures/guest_rpc_namespace';raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['fragmentSha256'],hashlib.sha256(raw).hexdigest())
        before={};exec(compile(raw,str(folder/'before.source'),'exec'),before)
        with self.assertRaisesRegex(NameError,'time'):before['call']('/INERT','guest-ping',{})
        self.assertEqual({},self.run_current())
    def run_current(self,wrong_peer=False):
        source=producer.guest_rpc_definitions();namespace={};exec(compile(source,'complete current guest RPC','exec'),namespace)
        peers=[];sends=[]
        class Client:
            response=b''
            def settimeout(self,_):pass
            def connect(self,path):peers.append(path)
            def getsockopt(self,*_):return struct.pack('3i',os.getpid()+int(wrong_peer),os.geteuid(),os.getegid())
            def sendall(self,raw):
                sends.append(raw);request=json.loads(raw.lstrip(b'\xff'))
                self.response=(b'flush-error\n\xff'+(json.dumps({'return':request['arguments']['id']})+'\n').encode()
                               if request['execute']=='guest-sync-delimited' else b'{"return":{}}\n')
            def recv(self,count):value=self.response[:count];self.response=self.response[count:];return value
            def close(self):pass
        protocol=types.SimpleNamespace(socket=lambda *_:Client(),AF_UNIX=1,SOCK_STREAM=1,SOL_SOCKET=1,SO_PEERCRED=1)
        guard=mock.Mock();namespace.update(socket=protocol,QGA_PEER_PID=os.getpid(),QGA_GUARD=guard)
        with tempfile.TemporaryDirectory() as temporary:
            wire=os.open(Path(temporary)/'wire',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            partial=os.open(Path(temporary)/'partial',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            namespace.update(wire=wire,partial_wire=partial)
            try:
                if wrong_peer:
                    with self.assertRaisesRegex(ValueError,'instance_qga_peer'):namespace['call']('/INERT','guest-ping',{})
                    guard.assert_not_called();self.assertEqual([],sends);return None
                value=namespace['call']('/INERT','guest-ping',{})
                guard.assert_called_once_with();self.assertEqual(2,len(sends));self.assertEqual(['/INERT'],peers)
                self.assertGreater((Path(temporary)/'wire').stat().st_size,0)
                return value
            finally:os.close(wire);os.close(partial)
    def test_wrong_kernel_peer_refuses_before_any_guest_command(self):self.run_current(wrong_peer=True)

    def test_missing_peer_binding_in_consumed_runtime_refuses_before_producing_code(self):
        from agent_tools import windows_guest_input
        source=windows_guest_input._REMOTE_RUNTIME.replace(';verify_peer(c,sock);',';')
        self.assertNotEqual(source,windows_guest_input._REMOTE_RUNTIME)
        with mock.patch.object(windows_guest_input,'_REMOTE_RUNTIME',source),self.assertRaisesRegex(ValueError,'guest_rpc_peer_binding'):
            producer.guest_rpc_definitions()


if __name__=='__main__':unittest.main()
