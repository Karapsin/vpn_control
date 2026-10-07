"""Fixed read-only d606 proof through real inert owners, children and sockets."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
import unittest
from unittest import mock

from agent_tools import ssh_gateway_tmux_d606_diagnostic as diagnostic
from agent_tools import ssh_gateway_tmux_master as owner
from agent_tools import ssh_gateway_tmux_master_ssh as adapter
from agent_tools.tests import test_ssh_gateway_tmux_master as fixtures
from agent_tools.tests import test_ssh_gateway_tmux_master_ssh as adapter_fixtures

PARENT = '''def _parent(pid):
    result = subprocess.run(['/bin/ps','-p',str(pid),'-o','ppid='],capture_output=True,check=True)
    return int(result.stdout.strip())


'''


class DiagnosticRemoteTests(fixtures.GatewayOwnerTests):
    def setUp(self):
        super().setUp()
        self.request['correlationId'] = diagnostic.CORRELATION
        self.request['masterControlPath'] = str(self.home/'.vc'/('r-'+diagnostic.CORRELATION.replace('-','')[:15])/'m')
        namespace = {'subprocess': subprocess}; exec(PARENT, namespace)
        for patch in (mock.patch.object(diagnostic, 'ORIGINAL_SOURCE_SHA256', owner.sha(self.raw)),
                      mock.patch.object(diagnostic, '_ORIGIN_SOURCE', self.raw, create=True),
                      mock.patch.object(diagnostic, '_parent', namespace['_parent'])):
            patch.start(); self.addCleanup(patch.stop)

    def observe(self):
        result = diagnostic._remote(self.request, self.anchor)
        diagnostic._validate_response(result, self.request, self.anchor)
        return result

    def test_original_ready_readonly_and_credentials_never_opened(self):
        self.ready(); job = owner.paths(self.request)[2]
        credential = job/'credential.private'; credential.chmod(0)
        self.addCleanup(credential.chmod, 0o600)
        before = {name: owner.generation((job/name).lstat()) for name in diagnostic.RECORDS if (job/name).exists()}
        result = self.observe()
        self.assertEqual('observed', result['public']['state'], result)
        self.assertEqual('original_child_ready', result['public']['reason'])
        self.assertEqual('ready', result['public']['originalStatus'])
        self.assertNotIn('inert-secret', json.dumps(result))
        self.assertNotIn('credential.private', result['proof']['records'])
        self.assertEqual(before, {name: owner.generation((job/name).lstat()) for name in before})

    def test_real_six_second_child_is_late_ready_without_ready_publication(self):
        self.ssh.write_text(self.ssh.read_text().replace("assert '-M' in args", "time.sleep(6.1)\nassert '-M' in args"))
        self.prepare()
        self.assertEqual('released', owner.operate('release', self.request, self.anchor, 'inert-secret')['state'])
        deadline = time.monotonic()+8
        while not owner.master_path(self.request).exists() and time.monotonic()<deadline: time.sleep(.02)
        self.assertTrue(owner.master_path(self.request).is_socket())
        job = owner.paths(self.request)[2]
        self.assertFalse((job/'ready.json').exists())
        self.assertEqual('unknown', owner.operate('status', self.request, self.anchor)['state'])
        result = self.observe()
        self.assertEqual('observed', result['public']['state'], result)
        self.assertEqual('late_ready_original_child', result['public']['reason'])
        self.assertEqual('ready_record_missing', result['public']['originalStatusReason'])
        self.assertEqual('capture_record', result['public']['originalStatusMethod'])
        self.assertFalse(result['public']['readyPublicationAllowed'])
        self.assertFalse((job/'ready.json').exists())
        self.assertFalse((job/'terminal.json').exists())

    def test_changed_original_source_rejects_before_history_reads(self):
        self.ready()
        with mock.patch.object(diagnostic, '_ORIGIN_SOURCE', self.raw+b'\n'):
            result = self.observe()
        self.assertEqual('original_source', result['public']['phase'])
        self.assertEqual('original_source_changed', result['public']['reason'])
        self.assertEqual({}, result['proof'])

    def test_forged_child_birth_rejects_positive_socket(self):
        self.ready(); path = owner.paths(self.request)[2]/'child.json'
        value = json.loads(path.read_bytes()); value['process']['startTicks'] += 1
        path.write_bytes(owner.canonical(value))
        result = self.observe()
        self.assertEqual('unknown', result['public']['state'])
        self.assertEqual({}, result['proof'])

    def test_ready_binding_drift_never_becomes_independent_ready(self):
        self.ready(); path = owner.paths(self.request)[2]/'ready.json'
        value = json.loads(path.read_bytes()); value['childPin']['sha256'] = 'f'*64
        path.write_bytes(owner.canonical(value))
        result = self.observe()
        self.assertEqual('unknown', result['public']['state'])
        self.assertEqual('ready_binding', result['public']['reason'])

    def test_public_reply_rejects_unbounded_or_unbound_proof_fields(self):
        self.ready(); result = self.observe()
        result['proof']['controlArgvSha256'] = 'private config value'
        with self.assertRaises(ValueError): diagnostic._validate_response(result, self.request, self.anchor)

    def test_record_rewrite_during_original_status_closes_original_generation(self):
        job = owner.paths(self.request)[2]
        insertion = "\n_original_bounded=bounded\ndef bounded(argv,*args,**kwargs):\n    result=_original_bounded(argv,*args,**kwargs)\n    target=Path("+repr(str(job/'ready.json'))+")\n    marker=Path("+repr(str(self.home/'diagnostic-race'))+")\n    if '-O' in argv and marker.exists() and target.exists():\n        target.write_bytes(target.read_bytes());marker.unlink()\n    return result\n\n"
        raw = self.raw.replace(b"if __name__ == '__main__':", insertion.encode()+b"if __name__ == '__main__':")
        self.request['workerSha256'] = owner.sha(raw)
        with mock.patch.object(owner,'source_bytes',return_value=raw), \
             mock.patch.object(diagnostic,'_ORIGIN_SOURCE',raw), \
             mock.patch.object(diagnostic,'ORIGINAL_SOURCE_SHA256',owner.sha(raw)):
            self.ready(); (self.home/'diagnostic-race').touch()
            result = self.observe()
        self.assertEqual('unknown',result['public']['state'],result)
        self.assertIn(result['public']['phase'], ('original_tmux_owners','closing_original_proofs'))
        self.assertEqual({},result['proof'])


class DiagnosticCallerTests(adapter_fixtures.GatewayAdapterTests):
    def setUp(self):
        super().setUp()
        self.request_inputs['correlationId'] = diagnostic.CORRELATION
        self.request['correlationId'] = diagnostic.CORRELATION
        self.request['masterControlPath'] = str(self.home/'.vc'/('r-'+diagnostic.CORRELATION.replace('-','')[:15])/'m')
        text = Path(diagnostic.__file__).read_text().replace(diagnostic.ORIGINAL_SOURCE_SHA256, owner.sha(self.raw))
        start = text.index('def _parent(pid):'); end = text.index('def _stderr_kind', start)
        text = text[:start]+PARENT+text[end:]
        self.caller = self.controller/'fixed-diagnostic.py'; self.caller.write_text(text); self.caller.chmod(0o600)
        for patch in (mock.patch.object(diagnostic, 'ORIGINAL_SOURCE_SHA256', owner.sha(self.raw)),
                      mock.patch.object(diagnostic, '__file__', str(self.caller))):
            patch.start(); self.addCleanup(patch.stop)

    def test_fixed_caller_captures_private_proof_before_public_result(self):
        self.ready_adapter()
        self.launcher.stop()
        def launch(argv, **kwargs):
            ssh = json.loads(argv[-1]); command = shlex.split(ssh[-1])
            self.assertEqual(['/usr/bin/python3','-I','-B','-c'], command[:4])
            self.assertEqual('gateway.invalid', ssh[-2])
            self.assertNotIn('inert-secret', ' '.join(ssh))
            return self.original_popen([os.sys.executable,'-I','-B','-c',command[4]], **kwargs)
        with mock.patch.object(diagnostic.subprocess, 'Popen', side_effect=launch):
            result = diagnostic.observe(self.controller)
        self.assertEqual('observed', result['state'], result)
        self.assertNotIn('inert-secret', json.dumps(result))
        job = self.controller/'.rag_index/ssh-gateway-tmux-master'/diagnostic.CORRELATION
        capsule = job/result['capsule']
        self.assertTrue((capsule/'receipt.json').exists())
        proof = json.loads((capsule/'proof.private.json').read_bytes())
        self.assertEqual('ready', proof['public']['originalStatus'])
        self.assertEqual(result['privateProofPin']['sha256'], owner.sha((capsule/'proof.private.json').read_bytes()))
        self.assertFalse(result['adoptionAllowed']); self.assertFalse(result['readyPublicationAllowed'])

    def test_original_config_drift_blocks_before_readonly_transport(self):
        self.ready_adapter(); self.config.write_bytes(self.config.read_bytes()); before = len(self.calls)
        result = diagnostic.observe(self.controller)
        self.assertEqual('unknown', result['state'])
        self.assertEqual(before, len(self.calls))


# Reuse fixture setup only; inherited owner/adapter regressions have their own
# routine modules and are not silently multiplied by this focused diagnostic.
for _class in (DiagnosticRemoteTests, DiagnosticCallerTests):
    for _name in dir(_class):
        if _name.startswith('test_') and _name not in _class.__dict__: setattr(_class, _name, None)

del _class, _name

if __name__ == '__main__': unittest.main()
