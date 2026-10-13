"""Fixed unused libsource gitlink: actual mode160000 and checkout bytes only."""
import os
from pathlib import Path
import subprocess
import unittest
from agent_tools import native_execution_context as context
from agent_tools.tests import test_native_execution_context as fixture

@unittest.skipUnless(os.name=='posix','Local fixed Git entry control')
class NativeGitlinkTest(unittest.TestCase):
    setUp=fixture.NativeExecutionContextTest.setUp
    git=fixture.NativeExecutionContextTest.git
    def linked_source(self):
        sub=self.base/'local-lib-source';sub.mkdir()
        self.git('init',root=sub);self.git('config','user.name','Local Source',root=sub)
        self.git('config','user.email','local@example.invalid',root=sub)
        (sub/'library.c').write_bytes(b'original library bytes')
        self.git('add','library.c',root=sub);self.git('commit','-m','original libsource',root=sub)
        commit=self.git('rev-parse','HEAD',root=sub)
        self.git('update-index','--add','--cacheinfo','160000,'+commit+',sing-box-libsrc')
        self.git('commit','-m','original fixed unused gitlink')
        source=self.base/'gitlink-source';sha=self.git('rev-parse','HEAD')
        self.git('worktree','add','--detach',str(source),sha)
        self.assertIn('160000 commit '+commit,self.git('ls-tree','HEAD','sing-box-libsrc',root=source))
        return sub,commit,source,sha
    def test_actual_gitlink_uninitialized_empty_or_absent_binds_original_oid(self):
        sub,commit,source,sha=self.linked_source()
        first=context._catalogue(source,sha)['sing-box-libsrc']
        self.assertEqual(commit,first['gitCommitOID']);self.assertIn(first['state'],('absent','uninitialized'))
        path=source/'sing-box-libsrc';path.mkdir(mode=0o700,exist_ok=True)
        self.assertEqual('uninitialized',context._catalogue(source,sha)['sing-box-libsrc']['state'])
        (path/'unexpected.txt').write_text('not a qualified empty checkout')
        with self.assertRaisesRegex(context.ExecutionContextError,'native_gitlink_uninitialized_nonempty'):context._catalogue(source,sha)
    def test_actual_initialized_gitlink_exact_commit_and_bytes_ignore_config_cannot_hide_tamper(self):
        sub,commit,source,sha=self.linked_source();path=source/'sing-box-libsrc'
        if path.exists():path.rmdir()
        subprocess.run(['git','clone',str(sub),str(path)],capture_output=True,check=True,timeout=10)
        first=context._catalogue(source,sha)['sing-box-libsrc'];self.assertEqual('initialized',first['state'])
        self.git('config','submodule.sing-box-libsrc.ignore','all',root=source)
        self.git('config','diff.ignoreSubmodules','all',root=source)
        file=path/'library.c';before=file.stat();self.git('update-index','--assume-unchanged','library.c',root=path)
        file.write_bytes(b'Original library bytes');os.utime(file,ns=(before.st_atime_ns,before.st_mtime_ns))
        self.assertEqual('',self.git('status','--porcelain',root=path))
        with self.assertRaisesRegex(context.ExecutionContextError,'native_product_bytes_changed'):context._catalogue(source,sha)
        self.git('update-index','--no-assume-unchanged','library.c',root=path)
        with self.assertRaisesRegex(context.ExecutionContextError,'native_gitlink_checkout_dirty'):context._catalogue(source,sha)
        file.write_bytes(b'original library bytes');(path/'untracked.c').write_text('unknown')
        with self.assertRaisesRegex(context.ExecutionContextError,'native_gitlink_checkout_dirty'):context._catalogue(source,sha)
    def test_gitlink_changed_checkout_or_git_oid_or_unknown_link_refuses(self):
        sub,commit,source,sha=self.linked_source();path=source/'sing-box-libsrc'
        if path.exists():path.rmdir()
        subprocess.run(['git','clone',str(sub),str(path)],capture_output=True,check=True,timeout=10)
        self.git('config','user.name','Local',root=path);self.git('config','user.email','local@example.invalid',root=path)
        (path/'library.c').write_text('changed');self.git('add','library.c',root=path);self.git('commit','-m','changed',root=path)
        with self.assertRaisesRegex(context.ExecutionContextError,'native_gitlink_commit_changed'):context._catalogue(source,sha)
        self.git('update-index','--cacheinfo','160000,'+self.git('rev-parse','HEAD',root=path)+',sing-box-libsrc')
        self.git('commit','-m','changed gitlink')
        with self.assertRaises((context.ExecutionContextError,ValueError)):context._diff(self.coordinator,sha,self.git('rev-parse','HEAD'))
        self.git('update-index','--add','--cacheinfo','160000,'+commit+',arbitrary-lib')
        self.git('commit','-m','unknown gitlink')
        with self.assertRaisesRegex(context.ExecutionContextError,'native_gitlink_unknown'):context._catalogue(self.coordinator,self.git('rev-parse','HEAD'))
    def test_unexpected_gitmodules_refuses_without_initialization_or_network(self):
        sub,commit,source,sha=self.linked_source()
        (self.coordinator/'.gitmodules').write_text('[submodule "sing-box-libsrc"]\npath = sing-box-libsrc\nurl = https://unused.invalid/library\n')
        self.git('add','.gitmodules');self.git('commit','-m','unknown module configuration')
        with self.assertRaisesRegex(context.ExecutionContextError,'native_gitmodules_unknown'):
            context._catalogue(self.coordinator,self.git('rev-parse','HEAD'))
