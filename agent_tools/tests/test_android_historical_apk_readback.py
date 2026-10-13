"""TEST-001: real FIFO child + complete historical readback carrier/parser.

Only TempFS data and fixed synthetic host authority are used. These tests grant
no native artifact, campaign, device, historical-outcome or acceptance authority.
"""
import ast
import contextlib
import copy
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from agent_tools.tests.fixtures import android_historical_apk_readback as fixture


def portable(source):
    # Mechanically replace exactly the unavailable host identity and UID/GID
    # projection; no filesystem/read/guard/parser statement is changed.
    tree=ast.parse(source)
    host=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='host']
    pins=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='fp']
    if len(host)!=1 or len(pins)!=1:raise ValueError('fixed_carrier_unknown')
    host[0].body=ast.parse("return {'uid':1000,'euid':1000,'gid':1000,'egid':1000,'groups':[1000],'boot':EXPECTED['boot'],'uname':['Linux','fixture','1','fixture','x86_64']}").body
    pins[0].body=ast.parse('value=[i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]\nif value[3:5]==[os.getuid(),os.getgid()]:value[3:5]=[1000,1000]\nreturn value').body
    return ast.unparse(ast.fix_missing_locations(tree))


class HistoricalApkReadbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.parent=Path(self.tmp.name).resolve();self.job=self.parent/'historical-job'
        self.job.mkdir(mode=0o700);(self.job/'output').mkdir(mode=0o700)
        files={}
        for name,value in [('base.apk',b'b'*8192),('target.apk',b't'*8192),('output/intent.json',b'{"fixture":"inert"}\n')]:
            path=self.job/name;path.write_bytes(value);path.chmod(0o600)
            files[name]={'size':len(value),'sha256':hashlib.sha256(value).hexdigest()}
        self.carrier_refusals=[]
        self.expected={'boot':fixture.BOOT,'job':str(self.job),'files':files,
            'observationId':'33333333-3333-4333-8333-333333333333','originalCorrelationId':fixture.ORIGINAL}

    def source(self,legacy=False):
        remote=fixture.REMOTE
        if legacy:
            self.assertEqual(1,remote.count('|os.O_NONBLOCK'))
            remote=remote.replace('|os.O_NONBLOCK','')
        return portable(remote.replace('__EXPECTED__',repr(self.expected)))

    def _run_carrier_once(self,read_hook=None,expected=None):
        source=portable(fixture.REMOTE.replace('__EXPECTED__',repr(expected or self.expected)))
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            if read_hook is None:exec(compile(source,'<complete-fixed-readback>','exec'),{'__name__':'__inert_carrier__'})
            else:
                with patch.object(os,'read',side_effect=read_hook):
                    exec(compile(source,'<complete-fixed-readback>','exec'),{'__name__':'__inert_carrier__'})
        self.assertEqual(1,len(output.getvalue().splitlines()))
        return json.loads(output.getvalue())

    @staticmethod
    def generation(path):
        value=path.lstat()
        return [value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
                value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns]

    def owned_generations(self):
        return {str(p):self.generation(p) for p in [self.parent,*self.parent.rglob('*')]}

    def outside_generations(self):
        # The carrier still guards every ancestor. Shared host temp metadata
        # may change independently; only an entirely new guarded proof can pass.
        return {str(p):self.generation(p) for p in self.parent.parents}

    def run_carrier(self,read_hook=None,expected=None):
        for attempt in range(3):
            owned=self.owned_generations();outside=self.outside_generations()
            proof=self._run_carrier_once(read_hook,expected)
            if proof['state']=='observed':return proof
            self.carrier_refusals.append(copy.deepcopy(proof))
            owned_after=self.owned_generations();outside_after=self.outside_generations()
            external_metadata_only=(outside!=outside_after and set(outside)==set(outside_after)
                and all(outside[name][:6]==outside_after[name][:6] for name in outside))
            if (proof['failure']!='parent_changed' or owned!=owned_after
                    or not external_metadata_only or attempt==2):return proof
        raise AssertionError('bounded carrier attempts exhausted')

    def test_exact_nonsecret_extraction_hashes(self):
        self.assertEqual(fixture.REMOTE_SHA256,hashlib.sha256(fixture.REMOTE.encode()).hexdigest())
        parser=inspect.getsource(fixture.validate).rstrip('\n')
        self.assertEqual(fixture.PARSER_SHA256,hashlib.sha256(parser.encode()).hexdigest())
        self.assertEqual(1,fixture.REMOTE.count('|os.O_NONBLOCK'))

    def test_complete_regular_two_read_proof_and_parser_no_effects(self):
        before={str(p.relative_to(self.job)):p.read_bytes()for p in self.job.rglob('*')if p.is_file()}
        proof=self.run_carrier();self.assertEqual('observed',proof['state'],
            f"carrier failure={proof['failure']} phase={proof['phase']}")
        self.assertEqual(proof,fixture.validate(proof,{'expected':self.expected}))
        self.assertEqual(proof['observations'][0],proof['observations'][1])
        self.assertTrue(all(proof[k]is False for k in ('effectsPerformed','historicalOutcomeChanged','acceptanceComplete')))
        after={str(p.relative_to(self.job)):p.read_bytes()for p in self.job.rglob('*')if p.is_file()}
        self.assertEqual(before,after)
        for row in proof['observations']:
            for f in row['files']:
                self.assertEqual(9,len(f['generation']));self.assertEqual(f['bytes'],f['generation'][6])
                self.assertIn('/',f['parents']);self.assertIn(str(Path(f['path']).parent),f['parents'])

    def test_causal_real_child_fifo_legacy_blocks_fixed_refuses_promptly(self):
        path=self.job/'base.apk';path.unlink();os.mkfifo(path,0o600)
        pin=path.lstat();before=(pin.st_ino,pin.st_mode,pin.st_size,pin.st_ctime_ns)
        # Actual predecessor differs only by missing O_NONBLOCK. subprocess.run
        # kills/reaps its own timed-out inert child; no external process touched.
        with self.assertRaises(subprocess.TimeoutExpired):
            subprocess.run([sys.executable,'-I','-B','-c',self.source(True)],capture_output=True,timeout=0.5)
        completed=subprocess.run([sys.executable,'-I','-B','-c',self.source()],capture_output=True,timeout=2)
        self.assertEqual(0,completed.returncode);self.assertEqual(b'',completed.stderr)
        proof=json.loads(completed.stdout)
        self.assertEqual(('unknown','file_unsafe','base.apk'),(proof['state'],proof['failure'],proof['phase']))
        self.assertFalse(proof['effectsPerformed']);self.assertFalse(proof['historicalOutcomeChanged'])
        pin=path.lstat();self.assertEqual(before,(pin.st_ino,pin.st_mode,pin.st_size,pin.st_ctime_ns))
        with self.assertRaisesRegex(ValueError,'observation_unknown'):fixture.validate(proof,{'expected':self.expected})

    def test_actual_parser_refuses_impossible_full_generation(self):
        proof=self.run_carrier()
        for row in proof['observations']:row['files'][0]['generation'][6]+=1
        with self.assertRaisesRegex(ValueError,'file_pin_invalid',
                msg=f"carrier failure={proof['failure']} phase={proof['phase']}"):
            fixture.validate(proof,{'expected':self.expected})

    def shared_ancestor_noise(self,repeat=False):
        actual=os.read;changes=[]
        def noise(fd,size):
            part=actual(fd,size)
            if part and os.fstat(fd).st_ino==(self.job/'output/intent.json').lstat().st_ino and (repeat or not changes):
                with tempfile.TemporaryDirectory(dir=self.parent.parent):pass
                changes.append(True)
            return part
        return noise,changes

    def test_shared_ancestor_metadata_noise_needs_new_complete_proof(self):
        noise,changes=self.shared_ancestor_noise()
        proof=self.run_carrier(noise)
        self.assertEqual('observed',proof['state'])
        self.assertEqual(proof,fixture.validate(proof,{'expected':self.expected}))
        self.assertEqual(1,len(changes));self.assertEqual(1,len(self.carrier_refusals))
        old=self.carrier_refusals[0]
        self.assertEqual(('unknown','parent_changed'),(old['state'],old['failure']))
        self.assertTrue(all(old[k]is False for k in ('effectsPerformed','historicalOutcomeChanged','acceptanceComplete')))
        with self.assertRaisesRegex(ValueError,'observation_unknown'):fixture.validate(old,{'expected':self.expected})

    def test_original_regular_and_parser_cases_survive_once_only_shared_noise(self):
        original=self.run_carrier
        for name in ('test_complete_regular_two_read_proof_and_parser_no_effects',
                     'test_actual_parser_refuses_impossible_full_generation'):
            with self.subTest(case=name):
                noise,changes=self.shared_ancestor_noise()
                with patch.object(self,'run_carrier',side_effect=lambda:original(noise)):
                    getattr(self,name)()
                self.assertEqual(1,len(changes))

    def test_shared_ancestor_noise_exhausts_without_promoting_unknown(self):
        noise,changes=self.shared_ancestor_noise(repeat=True)
        proof=self.run_carrier(noise)
        self.assertEqual(('unknown','parent_changed'),(proof['state'],proof['failure']))
        self.assertEqual(3,len(getattr(self,'carrier_refusals',[])));self.assertEqual(3,len(changes))
        with self.assertRaisesRegex(ValueError,'observation_unknown'):fixture.validate(proof,{'expected':self.expected})

    def test_owned_parent_drift_refuses_without_retry(self):
        actual=os.read;reads=[]
        def drift(fd,size):
            part=actual(fd,size)
            if part and stat.S_ISREG(os.fstat(fd).st_mode):
                reads.append(True);self.job.chmod(0o755)
            return part
        proof=self.run_carrier(drift)
        self.assertEqual(('unknown','parent_changed'),(proof['state'],proof['failure']))
        self.assertEqual(1,len(reads));self.assertEqual(1,len(getattr(self,'carrier_refusals',[proof])))

    def test_symlink_and_hardlink_refused_without_foreign_read(self):
        path=self.job/'target.apk';foreign=self.parent/'foreign';foreign.write_bytes(path.read_bytes());foreign.chmod(0o600)
        path.unlink();path.symlink_to(foreign)
        self.assertEqual('unknown',self.run_carrier()['state'])
        path.unlink();os.link(foreign,path)
        self.assertEqual('file_unsafe',self.run_carrier()['failure'])
        self.assertEqual(b't'*8192,foreign.read_bytes())

    def test_hash_metadata_mismatch_fails(self):
        expected=copy.deepcopy(self.expected);expected['files']['target.apk']['sha256']='0'*64
        self.assertEqual('file_changed',self.run_carrier(expected=expected)['failure'])

    def test_parent_path_exchange_after_fd_read_fails(self):
        actual=os.read;exchanged=False
        def exchange(fd,size):
            nonlocal exchanged
            part=actual(fd,size)
            if part and not exchanged and stat.S_ISREG(os.fstat(fd).st_mode):
                exchanged=True;self.job.rename(self.parent/'moved');self.job.symlink_to(self.parent/'moved',target_is_directory=True)
            return part
        self.assertEqual('parent_changed',self.run_carrier(exchange)['failure']);self.assertTrue(exchanged)

    def test_same_bytes_named_leaf_exchange_after_fd_read_fails(self):
        actual=os.read;exchanged=False;path=self.job/'base.apk'
        replacement=self.job/'replacement';replacement.write_bytes(path.read_bytes());replacement.chmod(0o600)
        def exchange(fd,size):
            nonlocal exchanged
            part=actual(fd,size)
            if part and not exchanged and os.fstat(fd).st_ino==path.stat().st_ino:
                exchanged=True;os.replace(replacement,path)
            return part
        # The complete carrier's finally guard reports the changed parent
        # generation after the replaced named file has already been rejected.
        self.assertEqual('parent_changed',self.run_carrier(exchange)['failure']);self.assertTrue(exchanged)

    def test_parent_mode_drift_after_read_fails(self):
        actual=os.read;changed=False
        def drift(fd,size):
            nonlocal changed
            part=actual(fd,size)
            if part and not changed and stat.S_ISREG(os.fstat(fd).st_mode):
                changed=True;self.job.chmod(0o755)
            return part
        self.assertEqual('parent_changed',self.run_carrier(drift)['failure']);self.assertTrue(changed)


if __name__=='__main__':unittest.main()
