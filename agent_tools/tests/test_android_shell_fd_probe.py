"""Inert external-exec FD tests; no Android/native operation or native ABI claim."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from agent_tools import android_shell_fd_probe as probe
from agent_tools import android_proxy_os_fresh_owner as fresh


# Independent mksh external-exec contract: shell-opened extra FDs CLOEXEC;
# IODUPSELF explicitly clears CLOEXEC immediately before an external command.
# Actual OS exec/fstat/read is used below, not a canned 'argv contains su' result.
CHILD=r'''
import hashlib,os,sys
fd=int(sys.argv[1])
try:
 s=os.fstat(fd);os.lseek(fd,0,0);b=os.read(fd,65536)
 print('|'.join(map(str,(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,oct(s.st_mode&511)[2:],s.st_uid,s.st_gid,s.st_nlink,'regular file'))))
 print(hashlib.sha256(b).hexdigest()+'  /proc/self/fd/'+str(fd))
except OSError:
 print('stat: descriptor absent',file=sys.stderr);sys.exit(1)
'''


class ShellFDProbeTests(unittest.TestCase):
    def external(self,case,path):
        # Consume the actual generated Android script's FD and selfdup syntax.
        command=case['command'];fd=int(re.search(r'exec ([34])</system/build.prop',command).group(1))
        saved=None
        try:saved=os.dup(fd)
        except OSError:pass
        opened=os.open(path,os.O_RDONLY)
        try:
            os.dup2(opened,fd,inheritable=False)
            consumers=[part.strip() for part in command.split(';') if '/system/bin/stat -Lc' in part or '/system/bin/sha256sum' in part]
            self.assertEqual(2,len(consumers))
            selfdup=all(part.endswith(str(fd)+'>&'+str(fd)) for part in consumers)
            parent=all('"/proc/$$/fd/'+str(fd)+'"' in part for part in consumers)
            # Parent /proc/PID/fd lookup is modeled by transferring that held
            # description. External self lookups rely on actual exec inheritance.
            os.set_inheritable(fd,selfdup or parent)
            value=subprocess.run([sys.executable,'-I','-B','-c',CHILD,str(fd)],close_fds=False,capture_output=True,timeout=3)
            return probe.parse_reply(value.returncode,value.stdout,value.stderr)
        finally:
            if saved is not None:os.dup2(saved,fd);os.close(saved)
            else:
                try:os.close(fd)
                except OSError:pass
            if opened!=fd:os.close(opened)

    def test_actual_generated_scripts_cloexec_red_selfdup_green(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'fixed-system-build-prop';path.write_bytes(b'fixed harmless ABI fixture\n')
            reads=[]
            for case in probe.probe_commands():reads.append({**case,'result':self.external(case,path)})
            for fd in (3,4):
                group=[r for r in reads if r['fd']==fd]
                self.assertEqual('command-failed',group[1]['result']['state'])
                self.assertEqual(group[0]['result'],group[2]['result'])
            result=probe.classify(reads)
            self.assertTrue(result['explicitSelfdupObserved']);self.assertEqual('not-tested',result['appProcessInheritance'])

    def test_missing_hash_consumer_selfdup_remains_failure(self):
        case=next(c for c in probe.probe_commands() if c['fd']==4 and c['mode']=='with-selfdup')
        case={**case,'command':case['command'].rsplit(' 4>&4',1)[0]}
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'build-prop';path.write_bytes(b'fixed')
            self.assertEqual('command-failed',self.external(case,path)['state'])

    def test_fixed_source_has_no_guest_effect_and_preserves_admission_guards(self):
        commands=probe.probe_commands();self.assertEqual(6,len(commands))
        for case in commands:
            self.assertIn('exec '+str(case['fd'])+'</system/build.prop',case['command'])
            self.assertNotIn('>./',case['command']);self.assertNotIn('mkdir',case['command'])
        source=probe.remote_source();compile(source,'fd-probe-remote','exec')
        values={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(source).body if isinstance(n,ast.Assign) and isinstance(n.value,ast.Constant) and n.targets[0].id in ('CHECKS','ADMIT_CHECKS')}
        self.assertEqual(values['CHECKS'],values['ADMIT_CHECKS'])
        for forbidden in ('proxy-os-fixed-stage','app_process','exec 4>./','/system/bin/mkdir'):
            self.assertNotIn(forbidden,values['CHECKS'])
        for required in ('fresh_owner_admission_generation_changed','fresh_owner_closing_drift','guard_files(pins,paths,parents);verify_manifest();fixture_stopped(output)','fresh_owner_admission_drift'):
            self.assertIn(required,values['CHECKS'])
        self.assertEqual(probe.FRESH_SHA,hashlib.sha256(Path(fresh.__file__).read_bytes()).hexdigest())

    def test_unsafe_partial_success_drift_and_false_exit_reject(self):
        for args in ((False,b'',b''),(0,b'x'*4097,b''),(0,b'bad',b''),(0,b'',b'warning')):
            with self.assertRaises(ValueError):probe.parse_reply(*args)
        with self.assertRaisesRegex(ValueError,'incomplete'):probe.classify([])
        baseline={'state':'descriptor-read','exit':0,'generation':'identity','sha256':'a'*64}
        reads=[{'fd':c['fd'],'mode':c['mode'],'result':dict(baseline)} for c in probe.probe_commands()]
        reads[-1]['result']['sha256']='b'*64
        with self.assertRaisesRegex(ValueError,'handoff_unproven'):probe.classify(reads)

    def test_prepare_requires_current_admission_and_exact_failure_before_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(fresh,'_retained',return_value=({}, {}, [])),mock.patch.object(probe.frozen,'_private_pin',return_value={'bytes':1,'sha256':'bad'}),mock.patch.object(subprocess,'run') as run:
            with self.assertRaisesRegex(ValueError,'ca03_history_changed'):probe.prepare(tmp,'03e40a15-34ad-43d7-965a-58ebbb222e77','2fd40a15-34ad-43d7-965a-58ebbb222e77')
            run.assert_not_called()
            self.assertFalse((Path(tmp)/'.rag_index/android-shell-fd-probe').exists())
