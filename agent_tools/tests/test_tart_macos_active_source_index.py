"""Controlled real-FD custody tests; no native SSV or idle qualification."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

from agent_tools import tart_macos_active_source_index as index
from agent_tools import tart_macos_service_census as service


@unittest.skipUnless(os.name=='posix','fixed protected reader requires POSIX nofollow FDs')
class ActiveIndexTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.daemons=self.root/'LaunchDaemons';self.daemons.mkdir()
        self.agents=self.root/'LaunchAgents';self.agents.mkdir()
        self.bin=self.root/'bin';self.bin.mkdir();self.program=self.bin/'service';self.program.write_bytes(b'PUBLIC')
        self.device=self.root.stat().st_dev;self.bad_inodes={};self.native=service.NativeServices.__new__(service.NativeServices)
        self.volume=service.Volume((1,2),True,True,self.device,True)
        self.stack.enter_context(patch.object(service.NativeServices,'volume',return_value=self.volume))
        self.stack.enter_context(patch.object(index,'_SOURCE_ROOT',str(self.root)))
        self.stack.enter_context(patch.object(index,'_SOURCE_DIRECTORIES',((str(self.daemons),'system_daemon'),(str(self.agents),'system_agent'))))
        self.stack.enter_context(patch.object(index,'_EXECUTABLE_ROOTS',(str(self.bin),)))
        real_stat=os.stat;real_fstat=os.fstat;real_lstat=os.lstat
        # Root ownership/SSV topology is a controlled getter seam. All reads,
        # directory entries, links, FD operations and races use actual files.
        def metadata(value):
            # st_mtime is no census field: linecache reads it while unittest formats
            # a real refusal under these patches, which must not crash the whole run.
            fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns','st_mtime')
            data={key:getattr(value,key)for key in fields}
            data.update(st_uid=0,st_dev=self.device)
            if stat.S_ISDIR(value.st_mode):data['st_mode']&=~0o022
            data.update(self.bad_inodes.get(value.st_ino,{}));return types.SimpleNamespace(**data)
        self.stack.enter_context(patch.object(os,'stat',side_effect=lambda *a,**k:metadata(real_stat(*a,**k))))
        self.stack.enter_context(patch.object(os,'lstat',side_effect=lambda *a,**k:metadata(real_lstat(*a,**k))))
        self.stack.enter_context(patch.object(os,'fstat',side_effect=lambda *a,**k:metadata(real_fstat(*a,**k))))
        self.reader=index.NativeSSVReader(self.native)
    def write(self,name,value,origin='system_daemon'):
        path=(self.daemons if origin=='system_daemon'else self.agents)/name
        path.write_bytes(plistlib.dumps(value));return path
    def value(self,label='PRIVATE-LABEL',**changes):
        return {'Label':label,'ProgramArguments':[str(self.program),'PRIVATE-ARG'],**changes}
    def process(self,value,uid=0,domain=None):
        actor=(123,uid,1,1000,1);row={'Label':value['Label'],'PID':123}
        native=types.SimpleNamespace(argv=lambda _: (os.fsencode(self.program),tuple(os.fsencode(v)for v in value['ProgramArguments'])))
        return row,actor,native,domain or service.Domain('system',0,[row])
    def test_full_e103_inactive_account_aborts_red_active_index_match_green(self):
        raw=(Path(__file__).parent/'fixtures/macos_active_index_before.source').read_bytes()
        self.assertEqual('e103665a0d940e5a01f50b709256b957b4dd5480745e26d1b05170fca9687d29',hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('_active_index_before');__import__('sys').modules[old.__name__]=old
        self.addCleanup(__import__('sys').modules.pop,old.__name__,None)
        exec(compile(raw,'<whole-e103>','exec'),old.__dict__)
        good=self.value('ACTIVE');self.write('active.plist',good)
        self.write('inactive.plist',self.value('INACTIVE',UserName='PRIVATE-NONEXISTENT-ACCOUNT'))
        with patch.object(old.Catalog,'_DIRECTORIES',index._SOURCE_DIRECTORIES),\
                patch.object(old.pwd,'getpwnam',side_effect=KeyError):
            with self.assertRaisesRegex(old.ServiceUnavailable,'macos_service_source_account_unavailable'):
                old.Catalog(old.Volume((1,2),True,True,self.device,True),502)
            current=index.ActiveSourceIndex(self.reader)
            row,actor,native,domain=self.process(good)
            self.assertEqual('ACTIVE',current.match(row,actor,native,domain=domain).value['Label'])
            row['Label']='INACTIVE'
            with self.assertRaisesRegex(index.SourceUnavailable,'active_source_account_unavailable'):
                current.match(row,actor,native,domain=domain)
        self.assertNotIn('PRIVATE',json.dumps(current.public()))
        self.assertFalse(current.public()['idleAuthority'])
    def test_actual_hardlinks_and_guarded_internal_symlink_under_qualified_volume(self):
        path=self.write('a.plist',self.value());os.link(path,self.daemons/'b.plist')
        link=self.agents/'c.plist';link.symlink_to('../LaunchDaemons/a.plist')
        self.assertEqual(path.read_bytes(),self.reader.read(str(path)).raw)
        self.assertEqual(path.read_bytes(),self.reader.read(str(link)).raw)
        # Two equal labels in the same actual origin remain ambiguous.
        source=index.ActiveSourceIndex(self.reader);row,actor,native,domain=self.process(self.value())
        with self.assertRaisesRegex(index.SourceUnavailable,'active_source_missing_or_ambiguous'):
            source.match(row,actor,native,domain=domain)
    def test_whole_e103_link_rejection_red_guarded_qualified_reader_green(self):
        raw=(Path(__file__).parent/'fixtures/macos_active_index_before.source').read_bytes()
        self.assertEqual('e103665a0d940e5a01f50b709256b957b4dd5480745e26d1b05170fca9687d29',hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('_link_reader_before');__import__('sys').modules[old.__name__]=old
        self.addCleanup(__import__('sys').modules.pop,old.__name__,None)
        exec(compile(raw,'<whole-e103>','exec'),old.__dict__)
        before=old.Catalog.__new__(old.Catalog);before.volume=old.Volume((1,2),True,True,self.device,True)
        path=self.write('original.plist',self.value());os.link(path,self.daemons/'hardlink.plist')
        link=self.agents/'alias.plist';link.symlink_to('../LaunchDaemons/original.plist')
        for selected in (path,link):
            with self.subTest(selected=selected.name):
                with self.assertRaises((old.ServiceUnavailable,OSError)):before._read(selected)
                self.assertEqual(path.read_bytes(),self.reader.read(str(selected)).raw)
    def test_all_nine_named_vs_fd_generation_changes_refuse_before_content_read(self):
        path=self.write('active.plist',self.value());inode=path.stat().st_ino
        original=os.fstat
        for field in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'):
            def changed(fd):
                value=original(fd)
                if value.st_ino==inode:
                    data=vars(value).copy();data[field]+=1;return types.SimpleNamespace(**data)
                return value
            with self.subTest(field=field),patch.object(os,'fstat',side_effect=changed),\
                    patch.object(os,'read',side_effect=AssertionError('changed FD must not read')):
                with self.assertRaisesRegex(index.SourceUnavailable,'source_changed'):self.reader.read(str(path))
    def test_symlink_target_and_source_changes_during_read_refuse(self):
        path=self.write('active.plist',self.value());link=self.agents/'alias.plist';link.symlink_to('../LaunchDaemons/active.plist')
        alternate=self.write('alternate.plist',self.value('OTHER'));original=os.read
        def switched(fd,size):
            raw=original(fd,size);link.unlink();link.symlink_to('../LaunchDaemons/alternate.plist');return raw
        with patch.object(os,'read',side_effect=switched):
            with self.assertRaisesRegex(index.SourceUnavailable,'source_changed'):self.reader.read(str(link))
        # Repeated aliases cannot widen the fixed namespace or loop forever.
        link.unlink();link.symlink_to('../LaunchAgents/alias.plist')
        with self.assertRaisesRegex(index.SourceUnavailable,'source_symlink_overflow'):self.reader.read(str(link))
    def test_symlink_escape_user_writeable_wrong_owner_or_device_refused(self):
        path=self.write('a.plist',self.value());link=self.agents/'alias.plist'
        link.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(index.SourceUnavailable,'source_namespace_unqualified'):self.reader.read(str(link))
        link.unlink();link.symlink_to('../LaunchDaemons/a.plist')
        for changes in ({'st_uid':501},{'st_dev':self.device+1},{'st_mode':stat.S_IFREG|0o666}):
            self.bad_inodes[path.stat().st_ino]=changes
            with self.subTest(changes=changes),self.assertRaisesRegex(index.SourceUnavailable,'source_component_unqualified'):
                self.reader.read(str(link))
            self.bad_inodes.clear()
    def test_unknown_labels_or_unreadable_source_coverage_cannot_be_assumed_inactive(self):
        good=self.value();self.write('active.plist',good);bad=self.write('unknown.plist',{'Program':'/PRIVATE'})
        source=index.ActiveSourceIndex(self.reader)
        self.assertFalse(source.public()['coverageComplete'])
        row,actor,native,domain=self.process(good)
        with self.assertRaisesRegex(index.SourceUnavailable,'source_index_coverage_incomplete'):source.match(row,actor,native,domain=domain)
        bad.write_bytes(b'not plist PRIVATE')
        self.assertFalse(index.ActiveSourceIndex(self.reader).public()['coverageComplete'])
    def test_same_label_across_origins_only_matches_actual_domain_account(self):
        value=self.value();self.write('system.plist',value);self.write('user.plist',value,'system_agent')
        source=index.ActiveSourceIndex(self.reader)
        for domain,uid in ((service.Domain('system',0,[]),0),(service.Domain('caller_user',501,[]),501),(service.Domain('caller_user',502,[]),502)):
            row,actor,native,_=self.process(value,uid)
            domain=service.Domain(domain.kind,domain.uid,[row])
            self.assertEqual('system_daemon'if uid==0 else'system_agent',source.match(row,actor,native,domain=domain).origin)
        row,actor,native,_=self.process(value,501)
        with self.assertRaisesRegex(index.SourceUnavailable,'active_source_account_or_parent_unqualified'):
            source.match(row,actor,native,domain=service.Domain('caller_user',502,[row]))
    def test_actual_domain_membership_duplicate_pid_and_missing_user_domains_block(self):
        value=self.value();self.write('active.plist',value);source=index.ActiveSourceIndex(self.reader)
        row,actor,native,domain=self.process(value)
        self.assertEqual({123},set(source.match_active({123:actor},[domain],native)))
        with self.assertRaisesRegex(index.SourceUnavailable,'loaded_source_domain_unmatched'):
            source.match(dict(row),actor,native,domain=domain)
        with self.assertRaisesRegex(index.SourceUnavailable,'loaded_source_pid_ambiguous'):
            source.match_active({123:actor},[domain,service.Domain('caller_user',502,[row])],native)
        with self.assertRaisesRegex(index.SourceUnavailable,'user_source_domain_unobserved'):
            source.match_active({123:actor,124:(124,501,1,1000,1)},[domain],native)
        with self.assertRaisesRegex(index.SourceUnavailable,'loaded_source_process_changed'):
            source.match_active({},[domain],native)
    def test_source_generation_or_arguments_change_never_uses_old_index(self):
        value=self.value();path=self.write('active.plist',value);source=index.ActiveSourceIndex(self.reader)
        row,actor,native,domain=self.process(value)
        native.argv=lambda _: (os.fsencode(self.program),(b'PRIVATE-WRONG',))
        with self.assertRaisesRegex(index.SourceUnavailable,'active_source_arguments_unqualified'):source.match(row,actor,native,domain=domain)
        path.write_bytes(plistlib.dumps(self.value(ProgramArguments=[str(self.program),'CHANGED'])))
        with self.assertRaisesRegex(index.SourceUnavailable,'source_changed'):source.match(row,actor,native,domain=domain)
    def test_volume_revalidation_and_nonregular_file_refuse_without_content_reads(self):
        path=self.write('active.plist',self.value())
        with patch.object(service.NativeServices,'volume',return_value=service.Volume((1,2),False,True,self.device,True)):
            with self.assertRaisesRegex(index.SourceUnavailable,'source_volume_unqualified'):self.reader.read(str(path))
        fifo=self.daemons/'fifo.plist';os.mkfifo(fifo)
        with patch.object(os,'read',side_effect=AssertionError('must not read fifo')):
            with self.assertRaisesRegex(index.SourceUnavailable,'source_file_unqualified'):self.reader.read(str(fifo))
    def test_nonprotected_parent_and_fd_cleanup_on_read_failure(self):
        path=self.write('active.plist',self.value())
        self.bad_inodes[self.daemons.stat().st_ino]={'st_mode':stat.S_IFDIR|0o777}
        with self.assertRaisesRegex(index.SourceUnavailable,'source_component_unqualified'):self.reader.read(str(path))
        self.bad_inodes.clear();opened=[];original=os.open
        def tracked(*args,**kwargs):
            fd=original(*args,**kwargs);opened.append(fd);return fd
        with patch.object(os,'open',side_effect=tracked),patch.object(os,'read',side_effect=OSError('PRIVATE-READ')):
            with self.assertRaisesRegex(index.SourceUnavailable,'source_read_unavailable'):self.reader.read(str(path))
        self.assertGreater(len(opened),1)
        for fd in opened:
            with self.assertRaises(OSError):os.fstat(fd)
    def test_unknown_native_exception_and_arbitrary_namespace_do_not_expose_details(self):
        for path in ('/Users/PRIVATE/a.plist','/System/Volumes/Data/PRIVATE/a.plist',None):
            with self.assertRaisesRegex(index.SourceUnavailable,'source_namespace_unqualified'):self.reader.read(path)
        path=self.write('active.plist',self.value())
        with patch.object(os,'open',side_effect=OSError('PRIVATE-PATH-ARGV')):
            with self.assertRaises(index.SourceUnavailable)as error:self.reader.read(str(path))
        self.assertEqual(('source_read_unavailable',),error.exception.args)
    def test_refusal_under_getter_seam_formats_like_unittest_without_aborting_run(self):
        # unittest formats a failure before cleanups unpatch os.stat; linecache then
        # reads st_mtime through this seam. A crash there aborts the whole worker.
        import traceback
        text=''  # assertRaises would drop the traceback that linecache must read.
        try:index.need(False,'source_changed')
        except index.SourceUnavailable as refused:text=''.join(traceback.format_exception(refused))
        self.assertIn('SourceUnavailable: source_changed',text)


if __name__=='__main__':unittest.main()
