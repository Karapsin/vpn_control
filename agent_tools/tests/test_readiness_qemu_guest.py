"""Complete emitted guest query with physical proc files and native command seams."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import readiness_qemu_guest as subject


class QemuGuestFactsTests(unittest.TestCase):
    def observe(self, source=None, *, session='ordinary', process='systemd', job_state=None,command=None):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);(base/'machine-id').write_text('a'*32);proc=base/'proc';proc.mkdir();item=proc/'17';item.mkdir()
            (item/'comm').write_text(process+'\n');(item/'cmdline').write_bytes(command if command is not None else process.encode()+b'\0')
            boot=proc/'sys/kernel/random';boot.mkdir(parents=True);(boot/'boot_id').write_text('a830e08f-986b-48c1-897b-7ea7229e171e\n')
            jobs=base/'jobs'
            if job_state is not None:
                record=jobs/'test';record.mkdir(parents=True);(record/'state.json').write_text(json.dumps({'state':job_state}))
            concrete=type(base)
            def path(*parts):
                presented=concrete(*parts)
                if str(presented)=='/etc/machine-id':return base/'machine-id'
                if str(presented)=='/proc':return proc
                if str(presented)=='/proc/sys/kernel/random/boot_id':return boot/'boot_id'
                if str(presented)=='/var/tmp/vc-recovery-jobs':return jobs
                return presented
            calls=[]
            def run(argv,**kwargs):
                calls.append(argv)
                if argv==['loginctl','list-sessions','--json=short']:
                    return subprocess.CompletedProcess(argv,1,'',"loginctl: unrecognized option '--json=short'\n")
                if argv==['systemctl','list-jobs','--no-legend','--plain']:output=''
                elif argv==['cloud-init','status']:output='status: done\n'
                elif argv==['loginctl','list-sessions','--no-legend','--no-pager']:
                    output='MALFORMED\n' if session=='malformed' else '3 1000 recovery - - no -\n'
                    if session=='competing':output+='4 1000 recovery - - no -\n'
                elif argv[:2]==['loginctl','show-session']:
                    output='User=1000\nName=recovery\nRemote=yes\nService=sshd\n'
                    if session=='foreign':output='User=1000\nName=recovery\nRemote=no\nService=login\n'
                else:raise AssertionError('Unclassified native query')
                return subprocess.CompletedProcess(argv,0,output,'')
            stream=io.StringIO()
            with mock.patch('pathlib.Path',side_effect=path),mock.patch.object(subprocess,'run',side_effect=run),mock.patch.object(os,'geteuid',return_value=0),mock.patch.dict(os.environ,{'SUDO_USER':'recovery','SUDO_UID':'1000'}),contextlib.redirect_stdout(stream):
                exec(compile(source or subject.program(),'complete emitted guest facts','exec'),{'__name__':'__main__'})
            return json.loads(stream.getvalue()),calls

    def test_diagnostic_source_literal_is_not_a_running_vpn_program(self):
        command=b'python3\0-c\0'+subject.program().encode()+b'\0'
        self.assertEqual([],self.observe(process='python3',command=command)[0]['protectedOrInstallerProcesses'])
        self.assertEqual(['protected_runtime'],self.observe(process='java',command=b'java\0com.kardinal.vpncontrol.desktop.MainKt\0')[0]['protectedOrInstallerProcesses'])
    def test_preserved_self_classification_failure_is_causal(self):
        folder=Path(__file__).parent/'fixtures/qemu_guest_self_classification';raw=(folder/'before.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_text());self.assertEqual(metadata['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('qemu_guest_self_before');before.__file__=str(folder/'before.source');exec(compile(raw,before.__file__,'exec'),before.__dict__)
        command=b'python3\0-c\0'+before.program().encode()+b'\0'
        self.assertEqual(['protected_runtime'],self.observe(before.program(),process='python3',command=command)[0]['protectedOrInstallerProcesses'])
        self.assertEqual([],self.observe(process='python3',command=command)[0]['protectedOrInstallerProcesses'])
    def test_default_ubuntu_loginctl_does_not_require_newer_json_option(self):
        value,calls=self.observe()
        self.assertEqual('status: done',value['cloudInit'])
        self.assertEqual([],value['foreignSessions'])
        self.assertFalse(value['jobVisibilityComplete'])
        self.assertEqual('process_baseline_unavailable',value['unknownOrRunningJobs'][0]['reason'])
        self.assertIn(['loginctl','show-session','3','--property=User','--property=Name','--property=Remote','--property=Service'],calls)

    def test_preserved_native_query_fails_before_reboot_admission(self):
        folder=Path(__file__).parent/'fixtures/qemu_guest_loginctl';source=(folder/'guest.before.source').read_text()
        metadata=json.loads((folder/'provenance.json').read_text());self.assertEqual(metadata['sourceSha256'],hashlib.sha256(source.encode()).hexdigest())
        with self.assertRaisesRegex(ValueError,'idle_visibility'):self.observe(source)
        self.assertEqual([],self.observe()[0]['foreignSessions'])

    def test_obsolete_state_file_cannot_prove_canonical_namespace_idle(self):
        folder=Path(__file__).parent/'fixtures/qemu_canonical_jobs_before'
        raw=(folder/'readiness_qemu_guest.py.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_text())
        self.assertEqual(metadata['sourceSha256']['readiness_qemu_guest.py'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('qemu_guest_registry_before');before.__file__=str(folder/'readiness_qemu_guest.py.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        self.assertEqual([],self.observe(before.program(),job_state='complete')[0]['unknownOrRunningJobs'])
        current=self.observe(job_state='complete')[0]
        self.assertFalse(current['jobVisibilityComplete']);self.assertTrue(current['unknownOrRunningJobs'])

    def test_foreign_and_competing_sessions_and_active_jobs_remain_blockers(self):
        for session in ['foreign','competing']:
            self.assertTrue(self.observe(session=session)[0]['foreignSessions'])
        with self.assertRaisesRegex(ValueError,'session_visibility'):self.observe(session='malformed')
        self.assertTrue(self.observe(job_state='running')[0]['unknownOrRunningJobs'])
        self.assertTrue(self.observe(job_state='unknown')[0]['unknownOrRunningJobs'])
        self.assertTrue(self.observe(job_state='complete')[0]['unknownOrRunningJobs'])
        self.assertEqual(['protected_runtime'],self.observe(process='sing-box')[0]['protectedOrInstallerProcesses'])
        self.assertEqual(['installer'],self.observe(process='dpkg')[0]['protectedOrInstallerProcesses'])


if __name__=='__main__':unittest.main()
