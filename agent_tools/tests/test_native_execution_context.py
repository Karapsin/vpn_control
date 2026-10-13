"""Real local Git/registry controls for existing clean native worktree isolation.

No network, VM, SSH, tmux, Android, build, or native action runs here. These tests
prove the existing admission boundary rather than introducing a second context.
"""
import hashlib
import ast
import sys
import inspect
from types import SimpleNamespace
from unittest.mock import patch
from agent_tools import ssh_transport
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid
from agent_tools import linux_package_fixture_build as build
from agent_tools import native_artifact_registry as registry
from agent_tools import ssh_tmux_session_ssh as tmux
from agent_tools import native_execution_context as context

ROOT = Path(__file__).resolve().parents[2]

@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'Local Git/private registry support')
class NativeExecutionContextTest(unittest.TestCase):
    def git(self, *words, root=None):
        result = subprocess.run(['git', '-C', str(root or self.coordinator), *words],
                                capture_output=True, text=True, timeout=15, check=True)
        return result.stdout.strip()
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.coordinator = self.base/'coordinator'
        self.coordinator.mkdir(mode=0o700)
        self.native = self.base/'native'
        self.origin = self.base/'origin.git'
        subprocess.run(['git','init','--bare',str(self.origin)],capture_output=True,check=True,timeout=15)
        self.git('init','-b','dev')
        self.git('config','user.email','local-control@example.invalid')
        self.git('config','user.name','Local Control')
        self.git('config','core.hooksPath','/dev/null')
        (self.coordinator/'gradle.properties').write_text('vpnControlVersion=2.2.9\n')
        (self.coordinator/'.gitignore').write_text('.rag_index/\npackage.bin\n')
        tools=self.coordinator/'agent_tools';tools.mkdir()
        pending=list(context._CORE|context._REQUIRED_SCRIPTS);seen=set();stdlib=set(sys.stdlib_module_names)|{'__future__'}
        while pending:
            relative=pending.pop()
            if relative in seen:continue
            seen.add(relative);source=ROOT/relative;destination=self.coordinator/relative
            destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,destination)
            if source.suffix!='.py':continue
            for node in ast.walk(ast.parse(source.read_bytes())):
                dependencies=[]
                if isinstance(node,ast.Import):dependencies=[a.name for a in node.names]
                elif isinstance(node,ast.ImportFrom):
                    if node.level:dependencies=[relative.split('/')[0]+'.'+(node.module or a.name) for a in node.names]
                    elif node.module in ("agent_tools","scripts"):dependencies=[node.module+"."+a.name for a in node.names]
                    elif node.module:dependencies=[node.module]
                for name in dependencies:
                    if name.split('.')[0] in stdlib:continue
                    candidates=[name.replace('.','/')+'.py',name.replace('.','/')+'/__init__.py',relative.rsplit('/',1)[0]+'/'+name.replace('.','/')+'.py']
                    found=next((name for name in candidates if (ROOT/name).is_file()),None)
                    if found:pending.append(found)
        (tools/'check_output_retention.py').write_text('check_only = 1\n')
        (tools/'unrelated_selector.py').write_text('value = 1\n')
        self.git('add','gradle.properties','.gitignore','agent_tools','scripts')
        self.git('commit','-m','exact clean native checkpoint')
        self.sha=self.git('rev-parse','HEAD')
        self.git('remote','add','origin',str(self.origin))
        self.git('push','origin','dev')
        self.git('worktree','add','--detach',str(self.native),self.sha)
        self.request={'sourceSha':self.sha,'baseVersion':'2.2.8','targetVersion':'2.2.9','correlationId':str(uuid.uuid4())}
    def qualify(self):
        source=build._source_root(self.coordinator,self.native)
        build._source_preflight(source,self.request)
        return source
    def test_dirty_unrelated_coordinator_does_not_invalidate_actual_clean_native_source(self):
        (self.coordinator/'agent_tools/unrelated_selector.py').write_text('value = 2\n')
        self.assertEqual(self.native,self.qualify())
        self.assertTrue(self.git('status','--porcelain'))
        self.assertEqual('',self.git('status','--porcelain',root=self.native))
        self.assertEqual(self.sha,self.git('rev-parse','HEAD',root=self.native))
        driver=tmux.TmuxArchDriver(self.coordinator,source_root=self.native)
        digest=hashlib.sha256((self.coordinator/'agent_tools/linux_package_fixture_build.py').read_bytes()).hexdigest()
        if digest==tmux.BUILD_SHA:
            tools=driver._tools()  # Authentic pinned tooling check, no transport.
            self.assertEqual(tmux.BUILD_SHA,tools['linux_package_fixture_build.py']['pin']['sha256'])
            self.assertEqual(tmux.TOOL_SHA,tools['ssh_tmux_session.py']['pin']['sha256'])
        else:
            # A candidate producer is not silently added to the native allowlist.
            with self.assertRaisesRegex(tmux.AdapterError,'unreviewed_tool_source'):driver._tools()
    def test_native_used_tool_change_still_requires_requalification(self):
        self.qualify()
        driver=tmux.TmuxArchDriver(self.coordinator,source_root=self.native)
        path=self.coordinator/'agent_tools/linux_package_fixture_build.py'
        path.write_bytes(path.read_bytes()+b'\n# actual changed producer\n')
        with self.assertRaisesRegex(tmux.AdapterError,'unreviewed_tool_source'):
            driver._tools()
        self.assertEqual(self.native,self.qualify())
    def test_dirty_native_checkout_never_receives_dirty_waiver(self):
        (self.native/'gradle.properties').write_text('vpnControlVersion=2.2.10\n')
        with self.assertRaisesRegex(build.LinuxPackageFixtureBuildError,'clean exact'):
            self.qualify()
    def test_foreign_repository_and_symlink_are_not_source_contexts(self):
        foreign=self.base/'foreign';foreign.mkdir();self.git('init',root=foreign)
        for source in (foreign,self.base/'native-link'):
            if source.name=='native-link':source.symlink_to(self.native)
            with self.subTest(source=source.name),self.assertRaises(build.LinuxPackageFixtureBuildError):
                build._source_root(self.coordinator,source)
    def test_advancing_origin_blocks_fresh_build_but_registry_keeps_original_native_source(self):
        package=self.coordinator/'package.bin';package.write_bytes(b'actual bounded component package')
        package.chmod(0o600)
        record=registry.register_artifact(self.coordinator,{'platform':'linux','artifactKind':'package',
            'localPath':str(package),'sha256':hashlib.sha256(package.read_bytes()).hexdigest(),
            'size':package.stat().st_size,'evidenceClass':'local-verified','sourceSha':self.sha})
        (self.coordinator/'agent_tools/unrelated_selector.py').write_text('value = 2\n')
        self.git('add','agent_tools/unrelated_selector.py');self.git('commit','-m','unrelated tooling checkpoint')
        self.git('push','origin','dev')
        with self.assertRaisesRegex(build.LinuxPackageFixtureBuildError,'clean exact'):
            self.qualify()
        verified=registry.verify_artifact_readonly(self.coordinator,record['artifactId'])
        self.assertEqual('verified',verified['verification'])
        self.assertEqual(self.sha,verified['artifact']['sourceSha'])
        self.assertNotEqual(self.sha,self.git('rev-parse','HEAD'))
        package.write_bytes(b'tampered')
        self.assertEqual('mismatch',registry.verify_artifact_readonly(self.coordinator,record['artifactId'])['verification'])

    def engineering(self, *, change='unrelated'):
        package=self.coordinator/'package.bin';package.write_bytes(b'actual original package');package.chmod(0o600)
        artifact=registry.register_artifact(self.coordinator,{'platform':'linux','artifactKind':'package',
            'localPath':str(package),'sha256':hashlib.sha256(package.read_bytes()).hexdigest(),
            'size':package.stat().st_size,'evidenceClass':'local-verified','sourceSha':self.sha})
        if change=='unrelated':
            (self.coordinator/'agent_tools/check_output_retention.py').write_text('check_only = 2\n')
        elif change=='native':
            path=self.coordinator/'scripts/native_fixture_run.sh';path.write_bytes(path.read_bytes()+b'\n#changed native consumed script\n')
        elif change=='unknown':
            (self.coordinator/'agent_tools/unknown_new_helper.py').write_text('value = 2\n')
        elif change=='version':
            (self.coordinator/'gradle.properties').write_text('vpnControlVersion=2.2.10\n')
        self.git('add','agent_tools','scripts','gradle.properties');self.git('commit','-m','separate tooling checkpoint')
        self.git('push','origin','dev')
        return artifact,package

    def test_explicit_engineering_context_admits_old_clean_checkpoint_after_unrelated_pushed_tool_change(self):
        artifact,package=self.engineering()
        with self.assertRaisesRegex(build.LinuxPackageFixtureBuildError,'clean exact'):self.qualify()
        qualified=context.EngineeringExecutionContext.qualify(self.coordinator,self.native,self.request,(artifact['artifactId'],))
        # This same regression executes the authentic strict preflight on the
        # preserved beforeimage. Its old origin rejection is causal RED.
        if 'engineering_context' in inspect.signature(build._source_preflight).parameters:
            build._source_preflight(self.native,self.request,engineering_context=qualified)
        else:
            build._source_preflight(self.native,self.request)
        proof=qualified.revalidate(self.native,self.request)
        self.assertFalse(proof['finalAcceptance'])
        self.assertFalse(proof['nativeActionAllowed'])
        self.assertEqual(self.sha,proof['sourceSha'])
        self.assertEqual('2.2.9',proof['originalPackageVersion'])
        self.assertEqual(self.sha,registry.verify_artifact_readonly(self.coordinator,artifact['artifactId'])['artifact']['sourceSha'])

    def test_engineering_context_rejects_native_dependency_and_unknown_tool_changes(self):
        for change in ('native','unknown'):
            # Each test subcase uses a fresh exact original baseline.
            if change=='unknown':
                self.git('reset','--hard',self.sha);self.git('push','--force','origin','dev')
            artifact,package=self.engineering(change=change)
            with self.subTest(change=change),self.assertRaisesRegex(context.ExecutionContextError,'native_consumed_source_changed'):
                context.EngineeringExecutionContext.qualify(self.coordinator,self.native,self.request,(artifact['artifactId'],))

    def test_engineering_version_metadata_keeps_original_package_version(self):
        artifact,package=self.engineering(change='version')
        qualified=context.EngineeringExecutionContext.qualify(self.coordinator,self.native,self.request,(artifact['artifactId'],))
        self.assertEqual('2.2.9',qualified.revalidate(self.native,self.request)['originalPackageVersion'])
        self.assertEqual('vpnControlVersion=2.2.10',self.git('show','HEAD:gradle.properties'))

    def test_engineering_context_rejects_ref_change_package_drift_and_consumers_outside_context(self):
        artifact,package=self.engineering()
        qualified=context.EngineeringExecutionContext.qualify(self.coordinator,self.native,self.request,(artifact['artifactId'],))
        with self.assertRaisesRegex(context.ExecutionContextError,'native_consumer_outside_frozen_context'):
            qualified.require_native_consumers((ROOT/'agent_tools/linux_package_fixture_build.py',))
        package.write_bytes(b'actual changed package')
        with self.assertRaisesRegex(context.ExecutionContextError,'native_artifact_source_or_bytes_changed'):
            qualified.revalidate(self.native,self.request)
        package.write_bytes(b'actual original package')
        (self.coordinator/'agent_tools/check_output_retention.py').write_text('check_only = 3\n')
        self.git('add','agent_tools/check_output_retention.py');self.git('commit','-m','moved ref');self.git('push','origin','dev')
        with self.assertRaisesRegex(context.ExecutionContextError,'native_target_ref_changed'):
            qualified.revalidate(self.native,self.request)

    def test_missing_catalogue_or_dynamic_unknown_dependency_refuses_qualification(self):
        artifact,package=self.engineering()
        (self.native/'agent_tools/ssh_connection_session.py').unlink()
        with self.assertRaises((context.ExecutionContextError,FileNotFoundError)):
            context.EngineeringExecutionContext.qualify(self.coordinator,self.native,self.request,(artifact['artifactId'],))

    def test_actual_tmux_caller_preflight_propagates_context_and_rejects_changed_artifact_before_effect(self):
        artifact,package=self.engineering()
        qualified=context.EngineeringExecutionContext.qualify(self.coordinator,self.native,self.request,(artifact['artifactId'],))
        driver=tmux.TmuxArchDriver(self.coordinator,source_root=self.native,engineering_context=qualified)
        with patch.object(ssh_transport,'load_config',return_value=SimpleNamespace(hosts={'archlinux':object()})), \
                patch.object(driver,'availability',return_value={'available':True,'reason':'available'}):
            preflight=driver.preflight(self.request)
        self.assertEqual('ready',preflight['state'])
        self.assertFalse(preflight['finalAcceptance'])
        self.assertEqual(self.sha,preflight['sourceSha'])
        # The actual frozen-source driver repeats qualification at submission.
        frozen=tmux.TmuxArchDriver(self.coordinator,source_root=self.native,engineering_context=qualified)
        package.write_bytes(b'changed after preflight')
        with patch.object(frozen,'_query',side_effect=AssertionError('No effect permitted')) as effect:
            with self.assertRaisesRegex(context.ExecutionContextError,'native_artifact_source_or_bytes_changed'):
                frozen.submit(self.request)
        effect.assert_not_called()

    def test_actual_tmux_caller_ref_or_dependency_change_before_submit_has_zero_effects(self):
        artifact,package=self.engineering()
        qualified=context.EngineeringExecutionContext.qualify(self.coordinator,self.native,self.request,(artifact['artifactId'],))
        driver=tmux.TmuxArchDriver(self.coordinator,source_root=self.native,engineering_context=qualified)
        path=self.native/'scripts/native_fixture_run.sh';before=path.read_bytes();path.write_bytes(before+b'\n')
        with patch.object(driver,'_query',side_effect=AssertionError('No effect permitted')) as effect:
            with self.assertRaisesRegex(context.ExecutionContextError,'native_source_requires_clean_exact_checkpoint'):
                driver.submit(self.request)
            path.write_bytes(before)
            (self.coordinator/'agent_tools/check_output_retention.py').write_text('check_only = 3\n')
            self.git('add','agent_tools/check_output_retention.py');self.git('commit','-m','ref changed after preflight');self.git('push','origin','dev')
            with self.assertRaisesRegex(context.ExecutionContextError,'native_target_ref_changed'):
                driver.submit(self.request)
        effect.assert_not_called()

    def test_actual_tmux_caller_rejects_nonqualified_context_before_any_effect(self):
        artifact,package=self.engineering()
        driver=tmux.TmuxArchDriver(self.coordinator,source_root=self.native,engineering_context=object())
        with patch.object(driver,'_query',side_effect=AssertionError('No effect permitted')) as effect:
            with self.assertRaisesRegex(build.LinuxPackageFixtureBuildError,'qualified context'):
                driver.submit(self.request)
        effect.assert_not_called()

    def test_unknown_dynamic_dependency_refuses_actual_committed_source_catalogue(self):
        path=self.native/'agent_tools/ssh_transport.py'
        path.write_bytes(path.read_bytes()+b'\ndef unresolved_dependency(): return __import__(caller_selected_module)\n')
        self.git('add','agent_tools/ssh_transport.py',root=self.native)
        self.git('commit','-m','local unknown dependency fixture',root=self.native)
        sha=self.git('rev-parse','HEAD',root=self.native)
        with self.assertRaisesRegex(context.ExecutionContextError,'native_dependency_dynamic_unknown'):
            context._catalogue(self.native,sha)

    def test_missing_dependency_refuses_actual_committed_source_catalogue(self):
        self.git('rm','agent_tools/ssh_connection_session.py',root=self.native)
        self.git('commit','-m','local missing dependency fixture',root=self.native)
        sha=self.git('rev-parse','HEAD',root=self.native)
        with self.assertRaisesRegex(context.ExecutionContextError,'native_catalogue_missing_dependency'):
            context._catalogue(self.native,sha)

    def test_readonly_original_context_survives_later_unrelated_branch_advance_only(self):
        artifact,package=self.engineering()
        qualified=context.EngineeringExecutionContext.qualify(self.coordinator,self.native,self.request,(artifact['artifactId'],))
        before=qualified.authority
        (self.coordinator/'agent_tools/check_output_retention.py').write_text('check_only = 3\n')
        self.git('add','agent_tools/check_output_retention.py');self.git('commit','-m','unrelated tooling during old observation');self.git('push','origin','dev')
        proof=qualified.revalidate(self.native,self.request,admission=False)
        self.assertEqual(self.sha,proof['sourceSha'])
        self.assertFalse(proof['finalAcceptance'])
        self.assertEqual(before,qualified.authority)
        with self.assertRaisesRegex(context.ExecutionContextError,'native_target_ref_changed'):
            build._source_preflight(self.native,self.request,engineering_context=qualified)

    def test_index_flags_same_mode_size_mtime_never_hide_actual_product_byte_changes(self):
        product=self.coordinator/'product.kt';product.write_bytes(b'original product bytes')
        self.git('add','product.kt');self.git('commit','-m','actual product input')
        sha=self.git('rev-parse','HEAD')
        source=self.base/'product-source';self.git('worktree','add','--detach',str(source),sha)
        path=source/'product.kt';before=path.stat()
        for flag in ('--assume-unchanged','--skip-worktree'):
            with self.subTest(flag=flag):
                path.write_bytes(b'Original product bytes')
                os.chmod(path,before.st_mode);os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
                self.git('update-index',flag,'product.kt',root=source)
                self.assertEqual('',self.git('status','--porcelain',root=source))
                self.assertEqual(before.st_size,path.stat().st_size)
                self.assertEqual(before.st_mode,path.stat().st_mode)
                self.assertEqual(before.st_mtime_ns,path.stat().st_mtime_ns)
                with self.assertRaisesRegex(context.ExecutionContextError,'native_product_bytes_changed'):
                    context._catalogue(source,sha)
                self.git('update-index','--no-assume-unchanged','--no-skip-worktree','product.kt',root=source)
                path.write_bytes(b'original product bytes')
