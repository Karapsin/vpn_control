"""Causal selection controls; inert sources and temporary real Git only."""
import ast
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
import shlex
import unittest
from unittest import mock
from agent_tools import affected_agent_tests as selector

class DependencySelectionTests(unittest.TestCase):
    def sources(self):
        return {'agent_tools/leaf.py':'value=1', 'agent_tools/adapter.py':'from . import leaf',
                'agent_tools/other.py':'value=2', 'agent_tools/tests/test_adapter.py':'from agent_tools import adapter',
                'agent_tools/tests/test_other.py':'from agent_tools import other', 'Feature.kt':None}
    def plan(self, changed, additions=None):
        return selector.select_from_sources(self.sources() | (additions or {}), changed)
    def test_reviewed_frozen_transport_package_context_is_finite_and_hash_bound(self):
        root=Path(__file__).resolve().parents[2]
        for name in ('ssh_transport.before-reviewed74.py.gz','ssh_transport.checkpoint74.py.gz'):
            with self.subTest(name=name):
                path='agent_tools/tests/fixtures/ssh_direct_ended_v1/'+name
                source=gzip.decompress((root/path).read_bytes()).decode()
                inventory={path,'agent_tools/ssh_connection_session.py','agent_tools/ssh_channel_selection.py','agent_tools/unrelated.py'}
                edges=selector.dependencies(path,source,inventory)
                self.assertIn('agent_tools/ssh_connection_session.py',edges)
                self.assertNotIn('agent_tools/unrelated.py',edges)
                with self.assertRaises(selector.SelectionError):selector.dependencies(path,source+'\n# changed loader bytes\n',inventory)
    def test_literal_self_import_is_bounded(self):
        sources=self.sources()|{'agent_tools/tests/test_self.py':"__import__('agent_tools.tests.test_self',fromlist=['VALUE'])"}
        self.assertEqual(('agent_tools.tests.test_adapter',),selector.select_from_sources(sources,{'agent_tools/leaf.py'}).modules)
    def test_product_only(self):
        self.assertEqual((), self.plan(['Feature.kt']).modules)
    def test_docs_and_metadata_only(self):
        self.assertEqual((), self.plan(['agent_docs/development.md','AGENTS.md','docs/CHANGELOG.md','gradle.properties']).modules)
    def test_transitive_consumer_only(self):
        self.assertEqual(('agent_tools.tests.test_adapter',), self.plan(['agent_tools/leaf.py']).modules)
    def test_fixture_pin_dependency(self):
        self.assertEqual(('agent_tools.tests.test_pin',), self.plan(['agent_tools/tests/fixtures/frozen.py.gz'],
          {'agent_tools/tests/fixtures/frozen.py.gz':None, 'agent_tools/tests/test_pin.py':"from pathlib import Path\np=Path('fixtures')/'frozen.py.gz'\nPIN='ab'*32"}).modules)
    def test_computed_fixture_resource_read_includes_shared_consumers(self):
        text="from pathlib import Path\nROOT=Path(__file__).parent/'fixtures'\ndef read(name):\n return (ROOT/(name+'.json')).read_text()"
        declaration={'sourceSha256':[hashlib.sha256(text.encode()).hexdigest()],'scopes':['agent_tools/tests/fixtures/shared.json']}
        with mock.patch.dict(selector.REVIEWED_DYNAMIC_DEPENDENCIES,{'agent_tools/tests/test_computed.py':declaration}):
            self.assertEqual(('agent_tools.tests.test_computed','agent_tools.tests.test_literal'),self.plan(['agent_tools/tests/fixtures/shared.json'],
              {'agent_tools/tests/fixtures/shared.json':None,'agent_tools/tests/test_computed.py':text,'agent_tools/tests/test_literal.py':"filename='fixtures/shared.json'"}).modules)
    def test_fixture_transitive_dependency(self):
        self.assertEqual(('agent_tools.tests.test_adapter','agent_tools.tests.test_fixture'), self.plan(['agent_tools/leaf.py'],
          {'agent_tools/tests/fixtures/family.py':'from agent_tools import leaf', 'agent_tools/tests/test_fixture.py':'from agent_tools.tests.fixtures import family'}).modules)
    def test_literal_dynamic_loader(self):
        self.assertIn('agent_tools.tests.test_loader', self.plan(['agent_tools/leaf.py'],
          {'agent_tools/tests/test_loader.py':"import importlib.util\nfrom pathlib import Path\np=Path('agent_tools/leaf.py')\nmodule=importlib.util.spec_from_file_location('loaded',p)"}).modules)
    def test_local_dispatcher_consumes_package(self):
        self.assertEqual(('agent_tools.tests.test_adapter','agent_tools.tests.test_dispatch'), self.plan(['agent_tools/leaf.py'],
          {'agent_tools/dispatcher.py':"import importlib\ndef load(name):\n return importlib.import_module('agent_tools.'+name)", 'agent_tools/tests/test_dispatch.py':'from agent_tools import dispatcher'}).modules)
    def test_unknown_loader_refuses_even_with_known_unrelated_import(self):
        with self.assertRaisesRegex(selector.SelectionError,'Unresolved source loader'):
            self.plan(['agent_tools/leaf.py'], {'agent_tools/tests/test_adapter.py':"from agent_tools import adapter\nimport importlib.util\ndef load(path):\n return importlib.util.spec_from_file_location('x',path)"})
    def test_unknown_new_source_refuses(self):
        with self.assertRaisesRegex(selector.SelectionError,'no known consumers'):
            self.plan(['agent_tools/new.py'], {'agent_tools/new.py':'x=1'})
    def test_requirements_select_only_real_sdk_consumers(self):
        self.assertEqual(('agent_tools.tests.test_sdk',),self.plan(['agent_tools/requirements-mcp.txt'],
          {'agent_tools/requirements-mcp.txt':None,'agent_tools/sdk.py':'import mcp','agent_tools/tests/test_sdk.py':'from agent_tools import sdk'}).modules)
    def test_applicable_close_gate_first(self):
        selection=self.plan(['agent_tools/leaf.py'], {'agent_tools/tests/test_ssh_connection_session_close.py':'from agent_tools import leaf'})
        self.assertEqual(['python','-m','unittest','agent_tools.tests.test_ssh_connection_session_close'],selection.commands('python')[0])
        self.assertEqual([],self.plan(['Feature.kt']).commands('python'))
    def test_unrelated_unknown_loader_cannot_silently_lose_consumer(self):
        with self.assertRaisesRegex(selector.SelectionError,'Unresolved source loader'):
            self.plan(['agent_tools/leaf.py'], {'agent_tools/tests/test_unknown.py':"import importlib.util\ndef load(path):\n return importlib.util.spec_from_file_location('x',path)"})
    def test_reviewed_loader_hash_cannot_auto_accept_edits(self):
        text="import importlib.util\ndef load(path):\n return importlib.util.spec_from_file_location('x',path)"
        declaration={'sourceSha256':[hashlib.sha256(text.encode()).hexdigest()],'scopes':['agent_tools/leaf.py']}
        with mock.patch.dict(selector.REVIEWED_DYNAMIC_DEPENDENCIES,{'agent_tools/tests/test_loader.py':declaration}):
            self.assertIn('agent_tools.tests.test_loader',self.plan(['agent_tools/leaf.py'],{'agent_tools/tests/test_loader.py':text}).modules)
            with self.assertRaisesRegex(selector.SelectionError,'Unresolved source loader'):
                self.plan(['agent_tools/leaf.py'],{'agent_tools/tests/test_loader.py':text+'\n# changed opaque loader'})
    def test_reviewed_literal_registry_selects_its_finite_consumers(self):
        text="import importlib\nREGISTRY=('leaf',)\ndef load(name):\n if name not in REGISTRY: raise ValueError()\n return importlib.import_module('agent_tools.'+name)"
        declaration={'sourceSha256':[hashlib.sha256(text.encode()).hexdigest()],'scopes':['@modules:REGISTRY']}
        with mock.patch.dict(selector.REVIEWED_DYNAMIC_DEPENDENCIES,{'agent_tools/dispatcher.py':declaration}):
            additions={'agent_tools/dispatcher.py':text,'agent_tools/tests/test_dispatch.py':'from agent_tools import dispatcher'}
            self.assertEqual(('agent_tools.tests.test_adapter','agent_tools.tests.test_dispatch'),self.plan(['agent_tools/leaf.py'],additions).modules)
            self.assertEqual(('agent_tools.tests.test_other',),self.plan(['agent_tools/other.py'],additions).modules)
    def test_ordinary_variable_name_is_not_a_module_dependency(self):
        self.assertEqual(('agent_tools.tests.test_adapter',),self.plan(['agent_tools/leaf.py'],{'agent_tools/tests/test_other.py':'leaf=3'}).modules)
    def test_declared_missing_resource_refuses(self):
        text="import importlib.util\ndef load(path):\n return importlib.util.spec_from_file_location('x',path)"
        declaration={'sourceSha256':[hashlib.sha256(text.encode()).hexdigest()],'scopes':['agent_tools/missing.py']}
        with mock.patch.dict(selector.REVIEWED_DYNAMIC_DEPENDENCIES,{'agent_tools/tests/test_loader.py':declaration}):
            with self.assertRaisesRegex(selector.SelectionError,'Declared dependency is unavailable'):
                self.plan(['agent_tools/leaf.py'],{'agent_tools/tests/test_loader.py':text})
    def test_compressed_frozen_source_dependencies(self):
        raw=gzip.compress(b'from agent_tools import leaf')
        text=selector.read_source('agent_tools/tests/fixtures/frozen.py.gz',raw)
        self.assertEqual(('agent_tools.tests.test_adapter','agent_tools.tests.test_frozen'),self.plan(['agent_tools/leaf.py'],
          {'agent_tools/tests/fixtures/frozen.py.gz':text,'agent_tools/tests/test_frozen.py':"path='fixtures/frozen.py.gz'"}).modules)

class GitSelectionTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.git('init','-q');self.git('config','user.email','fixture@example.invalid');self.git('config','user.name','Fixture')
        self.write('agent_tools/leaf.py','value=1');self.write('agent_tools/tests/test_leaf.py','from agent_tools import leaf');self.write('Feature.kt','old')
        self.git('add','.');self.git('commit','-qm','baseline');self.base=self.git('rev-parse','HEAD').strip()
        env=mock.patch.dict(os.environ,{},clear=True);env.start();self.addCleanup(env.stop)
    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.root),*args],text=True)
    def write(self,path,text):
        p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    def test_missing_baseline_refuses(self):
        with self.assertRaises(selector.SelectionError):selector.select(self.root)
    def test_committed_staged_dirty_and_new(self):
        self.write('Feature.kt','commit');self.git('add','.');self.git('commit','-qm','product')
        self.write('staged.kt','staged');self.git('add','.');self.write('agent_tools/leaf.py','value=3')
        self.write('agent_tools/new.py','x=1');self.write('agent_tools/tests/test_new.py','from agent_tools import new')
        plan=selector.select(self.root,self.base)
        self.assertEqual({'Feature.kt','staged.kt','agent_tools/leaf.py','agent_tools/new.py','agent_tools/tests/test_new.py'},set(plan.changed))
        self.assertEqual(('agent_tools.tests.test_leaf','agent_tools.tests.test_new'),plan.modules)
    def test_deleted_dependency(self):
        (self.root/'agent_tools/leaf.py').unlink()
        self.assertEqual(('agent_tools.tests.test_leaf',),selector.select(self.root,self.base).modules)
    def test_rename_retains_both_paths(self):
        self.git('mv','agent_tools/leaf.py','agent_tools/renamed.py');self.write('agent_tools/tests/test_leaf.py','from agent_tools import renamed')
        plan=selector.select(self.root,self.base);self.assertEqual(('agent_tools.tests.test_leaf',),plan.modules)
        self.assertIn('agent_tools/leaf.py',plan.changed);self.assertIn('agent_tools/renamed.py',plan.changed)
    def test_deleted_test_not_executed(self):
        (self.root/'agent_tools/tests/test_leaf.py').unlink()
        self.assertEqual((),selector.select(self.root,self.base).modules)
    def test_push_event_before(self):
        self.write('Feature.kt','new');self.git('add','.');self.git('commit','-qm','one')
        self.write('agent_tools/leaf.py','value=4');self.git('add','.');self.git('commit','-qm','two')
        event=self.root/'.event.json';event.write_text(json.dumps({'before':self.base}))
        with mock.patch.dict(os.environ,{'GITHUB_EVENT_NAME':'push','GITHUB_EVENT_PATH':str(event)}):
            self.assertEqual(self.base,selector.select(self.root).baseline)
    def test_dispatch_missing_baseline_refuses(self):
        with mock.patch.dict(os.environ,{'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_EVENT_PATH':str(self.root/'missing')}):
            with self.assertRaises(selector.SelectionError):selector.select(self.root)
    def test_intentional_audit_needs_no_remote_comparison_baseline(self):
        self.assertEqual(('agent_tools.tests.test_leaf',),selector.select(self.root,audit=True).modules)
    def test_intentional_audit(self):
        self.assertEqual(('agent_tools.tests.test_leaf',),selector.select(self.root,self.base,audit=True).modules)
    def test_pr_uses_merge_base_with_advanced_base_branch(self):
        self.git('checkout','-qb','feature');self.write('agent_tools/leaf.py','value=4');self.git('add','.');self.git('commit','-qm','feature')
        self.git('checkout','-qb','base',self.base);self.write('base-only.kt','base');self.git('add','.');self.git('commit','-qm','base')
        base_head=self.git('rev-parse','HEAD').strip();self.git('checkout','-q','feature')
        event=self.root/'.event.json';event.write_text(json.dumps({'pull_request':{'base':{'sha':base_head}}}))
        with mock.patch.dict(os.environ,{'GITHUB_EVENT_NAME':'pull_request','GITHUB_EVENT_PATH':str(event)}):
            plan=selector.select(self.root)
            self.assertEqual(self.base,plan.baseline);self.assertNotIn('base-only.kt',plan.changed)
            self.assertEqual(('agent_tools.tests.test_leaf',),plan.modules)
    def test_new_branch_zero_baseline_refuses(self):
        with self.assertRaisesRegex(selector.SelectionError,'baseline is missing'):
            selector.select(self.root,'0'*40)

class WorkflowExecutionTests(unittest.TestCase):
    git = GitSelectionTests.git
    write = GitSelectionTests.write
    # Override unittest fixture inheritance: the parent's tests retain their own
    # fixture while these controls execute real workflow commands on tiny suites.
    def setUp(self):
        self.workflow_source=os.environ.get("AGENT_SELECTION_WORKFLOW_SOURCE")
        GitSelectionTests.setUp(self)
        tools=Path(__file__).resolve().parents[1]
        for name in ('affected_agent_tests.py','affected_agent_test_dependencies.json','agent_test_runner.py'):
            shutil.copy2(tools/name,self.root/'agent_tools'/name)
        self.write('.gitignore','.rag_index/\n__pycache__/\n')
        self.write('agent_tools/tests/test_leaf.py','import unittest\nfrom agent_tools import leaf\nclass Case(unittest.TestCase):\n def test_value(self): self.assertGreater(leaf.value,0)\n')
        self.write('agent_tools/tests/test_unrelated.py',"raise RuntimeError('unrelated suite imported')\n")
        self.git('add','.');self.git('commit','-qm','tiny CI fixture');self.base=self.git('rev-parse','HEAD').strip()
    def workflow_command(self):
        workflow=Path(self.workflow_source or Path(__file__).resolve().parents[2]/'.github/workflows/fast-checks.yml')
        lines=workflow.read_text().splitlines();start=next(i for i,line in enumerate(lines) if '- name: Test ' in line and 'agent tools' in line)
        run=next(i for i in range(start+1,len(lines)) if lines[i].lstrip().startswith('run:'))
        value=lines[run].split('run:',1)[1].strip()
        if value=='|':
            body=[]
            for line in lines[run+1:]:
                if line and not line.startswith('          '):break
                body.append(line[10:] if line else '')
            value='\n'.join(body)
        return value.replace('python ',shlex.quote(sys.executable)+' ')
    def execute_workflow(self):
        event=self.root/'.event.json';event.write_text(json.dumps({'before':self.base}))
        env={**os.environ,'GITHUB_EVENT_NAME':'push','GITHUB_EVENT_PATH':str(event),'GITHUB_SHA':self.git('rev-parse','HEAD').strip(),'PATH':str(Path(sys.executable).parent)+':'+os.defpath,'AUDIT_AGENT_TESTS':''}
        return subprocess.run(['bash','-c',self.workflow_command()],cwd=self.root,env=env,capture_output=True,text=True)
    def test_actual_ci_product_only_never_imports_agent_suites(self):
        self.write('Feature.kt','changed product');result=self.execute_workflow()
        self.assertEqual(0,result.returncode,result.stderr);self.assertIn('"selectedModuleCount": 0',result.stdout)
    def test_actual_ci_runs_only_tool_consumer_with_retained_report(self):
        self.write('agent_tools/leaf.py','value=3');result=self.execute_workflow()
        self.assertEqual(0,result.returncode,result.stderr);self.assertIn('"selectedModuleCount": 1',result.stdout)
        reports=list((self.root/'.rag_index/agent-test-runs').glob('*/report.json'))
        self.assertEqual(1,len(reports));report=json.loads(reports[0].read_text())
        self.assertEqual(1,report['counts']['testsRun']);self.assertTrue(report['successful'])

class CliIncludeTests(unittest.TestCase):
    git = GitSelectionTests.git
    write = GitSelectionTests.write
    setUp = WorkflowExecutionTests.setUp
    def run_include(self):
        self.write('scripts/test_windows_fixture_stage_acl.py','import unittest\nclass Case(unittest.TestCase):\n def test_product_permission_check(self): self.assertTrue(True)\n')
        self.git('add','.');self.git('commit','-qm','existing script native check');self.base=self.git('rev-parse','HEAD').strip()
        self.write('Feature.kt','product edit')
        args=[sys.executable,str(self.root/'agent_tools/affected_agent_tests.py'),'--baseline',self.base,'--run','--include',
              'agent_tools.tests.test_leaf.Case.test_value','scripts.test_windows_fixture_stage_acl.Case']
        return args
    def test_product_only_preserves_existing_script_check_and_skips_agent_ids(self):
        result=subprocess.run(self.run_include(),cwd=self.root,text=True,capture_output=True)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertIn('Ran 1 test',result.stderr)
        self.assertIn('scripts.test_windows_fixture_stage_acl.Case.test_product_permission_check',result.stdout)
        self.assertNotIn('AGENT_TEST_TIMING {"schemaVersion": 1, "testId": "agent_tools.tests.test_leaf',result.stdout)
    def test_tool_dependency_runs_original_selected_class_method_ids(self):
        args=self.run_include();self.write('agent_tools/leaf.py','value=4')
        result=subprocess.run(args,cwd=self.root,text=True,capture_output=True)
        self.assertEqual(0,result.returncode,result.stderr);self.assertIn('Ran 2 tests',result.stderr)
        self.assertIn('agent_tools.tests.test_leaf.Case.test_value',result.stdout)
    def test_serial_cli_source_drift_cannot_claim_completed_success(self):
        args=self.run_include()
        self.write('scripts/test_windows_fixture_stage_acl.py',"import unittest\nfrom pathlib import Path\nclass Case(unittest.TestCase):\n def test_product_permission_check(self): Path('Feature.kt').write_text('changed during tests')\n")
        self.git('add','.');self.git('commit','-qm','drift fixture');args[args.index('--baseline')+1]=self.git('rev-parse','HEAD').strip()
        result=subprocess.run(args,cwd=self.root,text=True,capture_output=True)
        self.assertEqual(2,result.returncode,result.stderr);self.assertIn('Repository changed during selected tests',result.stderr)

class DocumentationResourceSelectionTests(unittest.TestCase):
    def sources(self, path):
        return {'agent_tools/tests/test_fixture.py': 'from pathlib import Path\ndef test_body():\n return Path('+repr(path)+').read_text()\n',path:None}
    def test_actual_root_markdown_fixture_is_a_dependency(self):
        path='agent_tools/tests/fixtures/recipe.md'
        self.assertEqual(('agent_tools.tests.test_fixture',),selector.select_from_sources(self.sources(path),{path}).modules)
    def test_rst_and_readme_fixture_files_are_data(self):
        for path in ('agent_tools/tests/fixtures/recipe.rst','agent_tools/tests/fixtures/README.md'):
            with self.subTest(path=path):
                self.assertEqual(('agent_tools.tests.test_fixture',),selector.select_from_sources(self.sources(path),{path}).modules)
    def test_executable_tool_resource_with_doc_extension_is_data(self):
        path='agent_tools/templates/operation.md'
        self.assertEqual(('agent_tools.tests.test_fixture',),selector.select_from_sources(self.sources(path),{path}).modules)
    def test_public_maintainer_prose_and_version_only_metadata_are_exempt(self):
        for path in ('docs/setup.md','agent_docs/development.md','AGENTS.md','README.md','agent_tools/README.md','gradle.properties'):
            with self.subTest(path=path):
                self.assertEqual((),selector.select_from_sources(self.sources(path),{path}).modules)

class GitDocumentationResourceSelectionTests(unittest.TestCase):
    git = GitSelectionTests.git
    write = GitSelectionTests.write
    setUp = GitSelectionTests.setUp
    def test_real_git_md_and_rst_fixture_change_survives_early_doc_shortcircuit(self):
        for suffix in ('md','rst'):
            path='agent_tools/tests/fixtures/recipe.'+suffix
            self.write(path,'old data')
            self.write('agent_tools/tests/test_fixture.py','from pathlib import Path\ndef test_body():\n return Path('+repr(path)+').read_text()\n')
            self.git('add','.');self.git('commit','-qm','fixture baseline');baseline=self.git('rev-parse','HEAD').strip()
            self.write(path,'changed data')
            self.assertEqual(('agent_tools.tests.test_fixture',),selector.select(self.root,baseline).modules)

class IndependentReviewPolicyControls(unittest.TestCase):
    def test_product_reader_still_omits_agent_tests(self):
        sources={'Feature.kt':None,'agent_tools/tests/test_feature_reader.py':"from pathlib import Path\nVALUE=Path('Feature.kt').read_text()"}
        self.assertEqual((),selector.select_from_sources(sources,{'Feature.kt'}).modules)
    def test_shared_mcp_selects_only_actual_consumers(self):
        sources={'agent_tools/mcp_server.py':'value=1','agent_tools/other.py':'value=2','agent_tools/tests/test_mcp.py':'from agent_tools import mcp_server','agent_tools/tests/test_other.py':'from agent_tools import other'}
        self.assertEqual(('agent_tools.tests.test_mcp',),selector.select_from_sources(sources,{'agent_tools/mcp_server.py'}).modules)
    def test_shared_retention_selects_only_actual_consumers(self):
        sources={'agent_tools/check_output_retention.py':'value=1','agent_tools/other.py':'value=2','agent_tools/tests/test_retention.py':'from agent_tools import check_output_retention','agent_tools/tests/test_other.py':'from agent_tools import other'}
        self.assertEqual(('agent_tools.tests.test_retention',),selector.select_from_sources(sources,{'agent_tools/check_output_retention.py'}).modules)
    def test_stdlib_literal_does_not_qualify_unknown_alternative(self):
        sources={'agent_tools/leaf.py':'value=1','agent_tools/tests/test_leaf.py':'from agent_tools import leaf','agent_tools/tests/test_hidden_loader.py':"import importlib\ndef load(name):\n return importlib.import_module('json' if name=='public' else name)"}
        with self.assertRaises(selector.SelectionError):selector.select_from_sources(sources,{'agent_tools/leaf.py'})
    def test_known_local_literal_does_not_qualify_unknown_alternative(self):
        sources={'agent_tools/leaf.py':'value=1','agent_tools/other.py':'value=1','agent_tools/tests/test_leaf.py':'from agent_tools import leaf','agent_tools/tests/test_hidden_loader.py':"import importlib\ndef load(name):\n return importlib.import_module('agent_tools.other' if name=='public' else name)"}
        with self.assertRaises(selector.SelectionError):selector.select_from_sources(sources,{'agent_tools/leaf.py'})
    def test_known_source_path_does_not_qualify_unknown_alternative(self):
        sources={'agent_tools/leaf.py':'value=1','agent_tools/tests/test_leaf.py':'from agent_tools import leaf','agent_tools/tests/test_hidden_loader.py':"import importlib.util\ndef load(name):\n return importlib.util.spec_from_file_location('loaded','agent_tools/leaf.py' if name=='public' else name)"}
        with self.assertRaises(selector.SelectionError):selector.select_from_sources(sources,{'agent_tools/leaf.py'})
    def test_windows_pr_filter_admits_dependency_registry_change(self):
        workflow=Path(os.environ.get('WINDOWS_AGENT_FILTER_SOURCE',Path(__file__).resolve().parents[2]/'.github/workflows/windows-desktop.yml'))
        body=workflow.read_text().split('  pull_request:',1)[1].split('jobs:',1)[0]
        import fnmatch
        filters=[line.strip()[3:-1] for line in body.splitlines() if line.strip().startswith('- "')]
        self.assertTrue(any(fnmatch.fnmatchcase('agent_tools/affected_agent_test_dependencies.json',pattern) for pattern in filters))

class DirectoryInputPolicyTests(unittest.TestCase):
    def plan(self,body):
        return selector.select_from_sources({'agent_tools/tests/fixtures/value.json':None,'agent_tools/tests/test_reader.py':body,'agent_tools/tests/test_other.py':'pass','agent_tools/tests/test_actual.py':"from pathlib import Path\nPath('agent_tools/tests/fixtures/value.json').read_text()"},{'agent_tools/tests/fixtures/value.json'})
    def test_directory_writer_does_not_consume_unrelated_children(self):
        self.assertEqual(('agent_tools.tests.test_actual',),self.plan("from pathlib import Path\nPath('agent_tools/tests/fixtures').mkdir()\nPath('agent_tools/tests/fixtures').write_text('inert')").modules)
    def test_command_directory_data_is_not_a_module_dependency(self):
        self.assertEqual(('agent_tools.tests.test_actual',),self.plan("COMMAND=['python','-m','unittest','discover','-s','agent_tools/tests/fixtures']").modules)
    def test_literal_filename_loop_reads_only_finite_named_inputs(self):
        sources={'agent_tools/tests/fixtures/value.json':None,'agent_tools/tests/fixtures/other.json':None,'agent_tools/tests/test_named.py':"from pathlib import Path\nfor name in ('value.json',):\n (Path('agent_tools/tests/fixtures')/name).read_text()",'agent_tools/tests/test_other.py':"from pathlib import Path\nPath('agent_tools/tests/fixtures/other.json').read_text()"}
        self.assertEqual(('agent_tools.tests.test_other',),selector.select_from_sources(sources,{'agent_tools/tests/fixtures/other.json'}).modules)
        self.assertEqual(('agent_tools.tests.test_named',),selector.select_from_sources(sources,{'agent_tools/tests/fixtures/value.json'}).modules)
    def test_readonly_directory_glob_and_iterator_consume_children(self):
        for expression in ("Path('agent_tools/tests/fixtures').glob('*.json')","Path('agent_tools/tests/fixtures').rglob('*.json')","Path('agent_tools/tests/fixtures').iterdir()","os.listdir('agent_tools/tests/fixtures')","os.walk('agent_tools/tests/fixtures')"):
            with self.subTest(expression=expression):self.assertEqual(('agent_tools.tests.test_actual','agent_tools.tests.test_reader'),self.plan('from pathlib import Path\nimport os\n'+expression).modules)
    def test_copytree_source_is_consumed_and_destination_is_not(self):
        self.assertEqual(('agent_tools.tests.test_actual','agent_tools.tests.test_reader'),self.plan("import shutil\nshutil.copytree('agent_tools/tests/fixtures','inert-temporary-destination')").modules)
        self.assertEqual(('agent_tools.tests.test_actual',),self.plan("import shutil\nshutil.copytree('inert-temporary-source','agent_tools/tests/fixtures')").modules)
    def test_bounded_directory_source_loader_preserves_children(self):
        self.assertEqual(('agent_tools.tests.test_actual','agent_tools.tests.test_reader'),self.plan("import importlib.util\nimportlib.util.spec_from_file_location('fixture','agent_tools/tests/fixtures')").modules)
    def test_unknown_read_alternative_cannot_hide_behind_known_directory(self):
        with self.assertRaises(selector.SelectionError):self.plan("from pathlib import Path\ndef read(name):\n return Path('agent_tools/tests/fixtures' if name=='public' else name).glob('*.json')")
    def test_ast_walk_command_text_is_not_filesystem_source_read(self):
        sources={'agent_tools/leaf.py':'value=1','agent_tools/tests/test_leaf.py':'from agent_tools import leaf','agent_tools/tests/test_ast.py':"import ast\nTEMPLATE=\"from pathlib import Path;ROOT=Path('agent_tools')\"\nfor node in ast.walk(ast.parse(TEMPLATE)):pass"}
        self.assertEqual(('agent_tools.tests.test_leaf',),selector.select_from_sources(sources,{'agent_tools/leaf.py'}).modules)
    def test_artifact_app_directory_is_not_repository_source(self):
        sources={'agent_tools/tests/fixtures/app/output.jar':None,'agent_tools/tests/test_fixture.py':"from pathlib import Path\nPath('agent_tools/tests/fixtures/app/output.jar').read_bytes()",'agent_tools/tests/test_runtime.py':"def jars(image):\n return (image/'app').glob('*.jar')"}
        self.assertEqual(('agent_tools.tests.test_fixture',),selector.select_from_sources(sources,{'agent_tools/tests/fixtures/app/output.jar'}).modules)
    def test_imported_source_filename_read_does_not_consume_other_modules(self):
        sources={'agent_tools/value.py':'value=1','agent_tools/other.py':'value=2','agent_tools/tests/test_named.py':"from agent_tools import value as production\nfrom pathlib import Path\n(ROOT/'agent_tools'/Path(production.__file__).name).read_bytes()\nROOT=Path(__file__).parents[2]",'agent_tools/tests/test_other.py':'from agent_tools import other'}
        self.assertEqual(('agent_tools.tests.test_other',),selector.select_from_sources(sources,{'agent_tools/other.py'}).modules)
        self.assertEqual(('agent_tools.tests.test_named',),selector.select_from_sources(sources,{'agent_tools/value.py'}).modules)
    def test_pathlib_qualified_source_loader_is_statically_bounded(self):
        source="import pathlib,importlib.util\nROOT=pathlib.Path(__file__).parent\nimportlib.util.spec_from_file_location('fixture',ROOT/'fixtures/value.json')"
        self.assertEqual(('agent_tools.tests.test_actual','agent_tools.tests.test_reader'),self.plan(source).modules)
    def test_known_directory_cannot_authenticate_arbitrary_source_suffix(self):
        sources={'agent_tools/tests/fixtures/value.json':None,'agent_tools/tests/test_reader.py':"import importlib.util\nfrom pathlib import Path\ndef load(name):\n return importlib.util.spec_from_file_location('loaded',Path('agent_tools/tests/fixtures')/name)"}
        with self.assertRaises(selector.SelectionError):selector.select_from_sources(sources,{'agent_tools/tests/fixtures/value.json'})
    def test_computed_call_suffix_requires_reviewed_source_scope(self):
        source="from pathlib import Path\ndef read(name):\n return (Path('agent_tools/tests/fixtures')/str(name)).read_bytes()"
        with self.assertRaises(selector.SelectionError):self.plan(source)
        declaration={'sourceSha256':[hashlib.sha256(source.encode()).hexdigest()],'scopes':['agent_tools/tests/fixtures/value.json']}
        with mock.patch.dict(selector.REVIEWED_DYNAMIC_DEPENDENCIES,{'agent_tools/tests/test_reader.py':declaration}):
            self.assertEqual(('agent_tools.tests.test_actual','agent_tools.tests.test_reader'),self.plan(source).modules)
    def test_unbounded_read_suffix_cannot_escape_declared_parent_silently(self):
        sources={'agent_tools/leaf.py':'value=1','agent_tools/tests/fixtures/known/data.txt':None,'agent_tools/tests/test_leaf.py':'from agent_tools import leaf','agent_tools/tests/test_hidden.py':"from pathlib import Path\nROOT=Path('agent_tools/tests/fixtures/known')\ndef read(name):\n return (ROOT/name).read_text()"}
        namespace={};exec(sources['agent_tools/tests/test_hidden.py'],namespace)
        with tempfile.TemporaryDirectory() as temporary:
            owned=Path(temporary).resolve()/'owned-leaf.txt';owned.write_text('owned outside-prefix reader proof')
            self.assertEqual('owned outside-prefix reader proof',namespace['read'](str(owned)))
        with self.assertRaises(selector.SelectionError):selector.select_from_sources(sources,{'agent_tools/leaf.py'})
        for prefix in ('/tmp','app'):
            with self.subTest(prefix=prefix):
                sources['agent_tools/tests/test_hidden.py']=sources['agent_tools/tests/test_hidden.py'].replace('agent_tools/tests/fixtures/known',prefix)
                with self.assertRaises(selector.SelectionError):selector.select_from_sources(sources,{'agent_tools/leaf.py'})
    def test_open_write_mode_does_not_consume_directory_children(self):
        self.assertEqual(('agent_tools.tests.test_actual',),self.plan("from pathlib import Path\nPath('agent_tools/tests/fixtures').open('w')").modules)

class StartupSourceIntegrityTests(unittest.TestCase):
    def isolated_root(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name).resolve()
        source=Path(os.environ.get('AGENT_SELECTOR_BOOT_SOURCE',Path(__file__).resolve().parents[1]))
        shutil.copytree(source,root/'agent_tools',ignore=shutil.ignore_patterns('tests','__pycache__'))
        return root
    def run_control(self,kind):
        root=self.isolated_root()
        code=r"""
import builtins, hashlib, importlib.machinery, json
from pathlib import Path
from unittest import mock
root=Path.cwd(); target=root/'agent_tools/affected_agent_test_dependencies.json'; changed=[]; reads=[]
text_reader=Path.read_text; byte_reader=Path.read_bytes; code_loader=importlib.machinery.SourceFileLoader.get_code; compiler=builtins.compile

def mutate(raw):
    value=json.loads(raw);value['loaders']['agent_tools/agent_test_runner.py']['reason']='OWNED_METADATA_CHANGED_AFTER_READ'
    target.write_text(json.dumps(value))

def text_read(path,*args,**kwargs):
    raw=text_reader(path,*args,**kwargs)
    if path.resolve()==target.resolve() and not changed:
        changed.append(True);mutate(raw)
    return raw

def byte_read(path,*args,**kwargs):
    raw=byte_reader(path,*args,**kwargs)
    if path.resolve()==target.resolve():
        reads.append(True)
        # New pipeline captures original bytes before import. Replace after the
        # actual parser read; the old pipeline uses its actual text-read seam.
        if len(reads)==2 and not changed:
            changed.append(True);mutate(raw)
    return raw

def load(loader,name):
    result=code_loader(loader,name)
    if name=='agent_tools.affected_agent_tests' and not changed:
        changed.append(True);path=root/'agent_tools/affected_agent_tests.py'
        path.write_text(text_reader(path)+'\nBOOT_RACE_PROBE=True\n')
    return result

def compile_source(raw,filename,*args,**kwargs):
    result=compiler(raw,filename,*args,**kwargs)
    if str(filename)==str(root/'agent_tools/affected_agent_tests.py') and KIND=='selector' and not changed:
        changed.append(True);path=root/'agent_tools/affected_agent_tests.py'
        path.write_text(text_reader(path)+'\nBOOT_RACE_PROBE=True\n')
    return result

KIND=__KIND__
with mock.patch.object(builtins,'compile',compile_source), mock.patch.object(Path,'read_text' ,text_read if KIND=='metadata' else text_reader), mock.patch.object(Path,'read_bytes',byte_read if KIND=='metadata' else byte_reader), mock.patch.object(importlib.machinery.SourceFileLoader,'get_code',load if KIND=='selector' else code_loader):
    from agent_tools import mcp_server as server
assert changed, 'actual startup seam did not trigger'
if KIND=='metadata':
    assert server.affected_agent_tests.REVIEWED_DYNAMIC_DEPENDENCIES['agent_tools/agent_test_runner.py']['reason'] != json.loads(text_reader(target))['loaders']['agent_tools/agent_test_runner.py']['reason']
else:
    assert not hasattr(server.affected_agent_tests,'BOOT_RACE_PROBE'), 'loaded code was not the preserved original'
error=server._check_runner_source_error()
assert error is not None, 'stale loaded bytes were admitted under new disk bytes'
with mock.patch.object(server.managed_check_lease,'acquire',side_effect=AssertionError('lease must not be acquired')):
    result=server.run_checks(area='agent_tools',level='prepush')
assert not result['ok']
assert not (root/'.rag_index/prepush_receipt.json').exists()
""".replace('__KIND__',repr(kind))
        result=subprocess.run([sys.executable,'-c',code],cwd=root,capture_output=True,text=True)
        self.assertEqual(0,result.returncode,result.stderr)
    def test_actual_timestamp_valid_old_bytecode_cannot_qualify_new_source(self):
        root=self.isolated_root()
        code=r"""
from pathlib import Path
import hashlib,os,py_compile
path=Path('agent_tools/affected_agent_tests.py');raw=path.read_bytes();info=path.stat()
py_compile.compile(str(path),doraise=True)
changed=raw.replace(b'PROSE_FILES = {"README.md"',b'PROSE_FILES = {"README.zz"',1)
assert changed!=raw and len(changed)==len(raw)
path.write_bytes(changed);os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns))
from agent_tools import mcp_server as server
assert 'README.zz' in server.affected_agent_tests.PROSE_FILES, 'timestamp-valid old bytecode executed'
assert 'README.md' not in server.affected_agent_tests.PROSE_FILES
assert server._check_runner_source_error() is None
assert hashlib.sha256(changed).hexdigest()==server.affected_agent_tests.LOADED_SELECTOR_SOURCE_SHA256
"""
        result=subprocess.run([sys.executable,'-c',code],cwd=root,capture_output=True,text=True)
        self.assertEqual(0,result.returncode,result.stderr)
    def test_cli_loaded_sources_changed_are_refused_before_snapshot(self):
        for name in ('affected_agent_tests.py','affected_agent_test_dependencies.json'):
            with self.subTest(name=name):
                root=self.isolated_root()
                code=r"""
from pathlib import Path
from unittest import mock
from agent_tools import affected_agent_tests as selector
path=Path('agent_tools')/__NAME__
path.write_bytes(path.read_bytes()+b'\n')
with mock.patch.object(selector,'snapshot',side_effect=AssertionError('snapshot must not run')):
    assert selector.main(['--run'])==2
""".replace('__NAME__',repr(name))
                result=subprocess.run([sys.executable,'-c',code],cwd=root,capture_output=True,text=True)
                self.assertEqual(0,result.returncode,result.stderr)
    def test_metadata_changed_after_actual_parse_read_is_refused_before_lease(self):
        self.run_control('metadata')
    def test_selector_changed_after_actual_compile_is_refused_before_lease(self):
        self.run_control('selector')

class ActualPlannerPolicyTests(unittest.TestCase):
    def actual(self,selection):
        source=Path(__file__).resolve().parents[1]/'mcp_server.py';tree=ast.parse(source.read_bytes());chosen=[]
        for n in tree.body:
            if isinstance(n,ast.FunctionDef) and n.name=='_commands_for':chosen.append(n)
            elif isinstance(n,(ast.Assign,ast.AnnAssign)) and any(isinstance(t,ast.Name) and t.id in {'FOCUSED_COMMANDS','PREPUSH_COMMANDS'} for t in (n.targets if isinstance(n,ast.Assign) else [n.target])):chosen.append(n)
        ns={'sys':sys,'AGENT_TEST_PYTHON':sys.executable,'REPO_ROOT':source.parents[1],'_agent_test_selection':lambda:selection}
        exec(compile(ast.Module(chosen,[]),str(source),'exec'),ns);return ns
    def test_actual_product_prepush_omits_agent_commands(self):
        ns=self.actual(selector.Selection('a',('Feature.kt',),(),2))
        self.assertFalse(any('unittest' in c for c in ns['_commands_for']('desktop','prepush')))
    def test_actual_focused_runs_selected_modules(self):
        selection=selector.Selection('a',('agent_tools/leaf.py',),('agent_tools.tests.test_leaf',),2);ns=self.actual(selection)
        self.assertEqual(selection.commands(sys.executable)+[['./scripts/check_docs_hygiene.sh']],ns['_commands_for']('agent_tools','focused'))

if __name__=='__main__':unittest.main()
