"""Real portable caller qualifications; native Windows cases remain mandatory.

Current and authentic B implementations run from real physical package copies.
Only subprocess.run is made inert, after normal imports. A sentinel stops before
PowerShell and before native PASS assertions; no native result is fabricated.
"""
import ast
import base64
from contextlib import ExitStack
import hashlib
import importlib
import inspect
import io
import json
import os
from pathlib import Path, PureWindowsPath
import stat
import subprocess
import sys
import tempfile
import traceback
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SELF = 'agent_tools/tests/test_windows_native_fixture_callers.py'
FIXTURE = 'agent_tools/tests/fixtures/windows_native_fixture_callers'
# Reviewed finite AST/import/resource closure; no whole-package fallback.
# The current bytes are snapshotted per case; these paths grant no native action.
CONTEXT_PATHS = (
 '.gitattributes',
 'agent_tools/mcp_tool.sh',
 'agent_tools/native_artifact_registry.py',
 'agent_tools/native_review_source_closure.py',
 'agent_tools/private_inventory_lock.py',
 'agent_tools/source_module_loader.py',
 'agent_tools/ssh_automatic_program.py',
 'agent_tools/ssh_channel_inventory_diagnostics.py',
 'agent_tools/ssh_channel_selection.py',
 'agent_tools/ssh_connection_recovery.py',
 'agent_tools/ssh_connection_session.py',
 'agent_tools/ssh_direct_nested_channel.py',
 'agent_tools/ssh_expired_recovery_retirement.py',
 'agent_tools/ssh_fresh_nested_channel.py',
 'agent_tools/ssh_nested_socket_noninteractive_observation.py',
 'agent_tools/ssh_nested_socket_owned_home_observation.py',
 'agent_tools/ssh_nested_socket_retirement.py',
 'agent_tools/ssh_nested_socket_route_diagnostic.py',
 'agent_tools/ssh_recovery_adoption.py',
 'agent_tools/ssh_transport.py',
 'agent_tools/tests/__init__.py',
 'agent_tools/tests/fixtures/cp117_gzip_runtime.py',
 'agent_tools/tests/fixtures/historical_source.py',
 'agent_tools/tests/fixtures/setup_process_capture/after.ps1',
 'agent_tools/tests/fixtures/windows_cp117_historical_factory/base_5d06ef74.source',
 'agent_tools/tests/fixtures/windows_cp117_historical_factory/base_provenance.json',
 'agent_tools/tests/fixtures/windows_cp117_historical_factory/context.py',
 'agent_tools/tests/fixtures/windows_cp117_historical_factory/diagnostic_615e1b09.source',
 'agent_tools/tests/fixtures/windows_cp117_historical_factory/installed_fa5f054e.source',
 'agent_tools/tests/fixtures/windows_cp117_historical_factory/preflight.py',
 'agent_tools/tests/fixtures/windows_cp117_historical_factory/provider_f54029cf.source',
 'agent_tools/tests/fixtures/windows_cp117_historical_factory/public_msi_5e60d94f.source',
 'agent_tools/tests/fixtures/windows_cp117_historical_factory/update_fixture_a6445062.source',
 'agent_tools/tests/fixtures/windows_cp117_public_cli_alias.json',
 'agent_tools/tests/fixtures/windows_cp117_public_cli_alias.ps1',
 'agent_tools/tests/fixtures/windows_cp117_public_context/current-context.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/current-host-main.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/fixture-script.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/old-context.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/old-host-main.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/original-base-test.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/original-context-caller.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/original-server-test.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/original-stage-caller.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/original-stage-exit.json',
 'agent_tools/tests/fixtures/windows_cp117_public_context/original-stage-remote.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/original-stage-result.json',
 'agent_tools/tests/fixtures/windows_cp117_public_context/provenance.json',
 'agent_tools/tests/fixtures/windows_cp117_public_context/reviewed-base-test.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/reviewed-server-test.source',
 'agent_tools/tests/fixtures/windows_cp117_public_context/whole_entry.py',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/base.overflow-before-slim.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/base.server-read-before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/base.parser-catch-before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/read-binding.text-writer-before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/routine.metadata-before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/provenance.json',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/test_windows_cp117_base_source_refresh.py.before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/test_windows_cp117_public_update_flow.py.before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/test_windows_cp117_server_preflight.py.before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/test_windows_cp117_server_read_binding.py.before.source',
 'agent_tools/tests/fixtures/windows_powershell_environment.py',
 'agent_tools/tests/fixtures/windows_shortcut_access_wire.py',
 'agent_tools/tests/fixtures/windows_replacement_fixture_sections.py',
 'agent_tools/tests/test_windows_cp117_base_source_refresh.py',
 'agent_tools/tests/test_windows_cp117_installed_base_observe.py',
 'agent_tools/tests/test_windows_cp117_public_update_flow.py',
 'agent_tools/tests/test_windows_cp117_recovered_login.py',
 'agent_tools/tests/test_windows_cp117_recovered_owner_diagnostic.py',
 'agent_tools/tests/test_windows_cp117_recovered_owner_observe.py',
 'agent_tools/tests/test_windows_cp117_server_preflight.py',
 'agent_tools/tests/test_windows_cp117_server_read_binding.py',
 'agent_tools/tests/test_windows_native_fixture_callers.py',
 'agent_tools/windows_cp117_base_source_refresh.py',
 'agent_tools/windows_cp117_bound_absence_completion.py',
 'agent_tools/windows_cp117_c32_absence.py',
 'agent_tools/windows_cp117_c32_archive_admission.py',
 'agent_tools/windows_cp117_c32_host_archive.py',
 'agent_tools/windows_cp117_c32_retained_task_retire.py',
 'agent_tools/windows_cp117_campaign_rebase.py',
 'agent_tools/windows_cp117_campaign_status.py',
 'agent_tools/windows_cp117_download_abort_current_successor.py',
 'agent_tools/windows_cp117_download_abort_successor.py',
 'agent_tools/windows_cp117_e66_successor.py',
 'agent_tools/windows_cp117_e848_http_task.py',
 'agent_tools/windows_cp117_e848_http_task_retire.py',
 'agent_tools/windows_cp117_fixture_recovery_short_socket.py',
 'agent_tools/windows_cp117_guest_abort_successor.py',
 'agent_tools/windows_cp117_guest_agent_recovery.py',
 'agent_tools/windows_cp117_guest_agent_recovery_successor.py',
 'agent_tools/windows_cp117_historical_base_archives.py',
 'agent_tools/windows_cp117_installed_base_observe.py',
 'agent_tools/windows_cp117_lease.py',
 'agent_tools/windows_cp117_protected_journal.py',
 'agent_tools/windows_cp117_public_cli_binding.py',
 'agent_tools/windows_cp117_recovered_guest_observe.py',
 'agent_tools/windows_cp117_recovered_gui_login.py',
 'agent_tools/windows_cp117_recovered_login.py',
 'agent_tools/windows_cp117_recovered_owner_diagnostic.py',
 'agent_tools/windows_cp117_recovered_owner_observe.py',
 'agent_tools/windows_cp117_recovered_session_observe.py',
 'agent_tools/windows_cp117_retirement_guards.py',
 'agent_tools/windows_cp117_secure_input_geometry_observe.py',
 'agent_tools/windows_cp117_secure_input_observe.py',
 'agent_tools/windows_cp117_secure_layout_observe.py',
 'agent_tools/windows_cp117_source_campaign.py',
 'agent_tools/windows_cp117_source_pre_effect_close.py',
 'agent_tools/windows_cp117_staged_fixture_retire.py',
 'agent_tools/windows_cp117_static_tasks_absence_close.py',
 'agent_tools/windows_cp117_static_tasks_retire.py',
 'agent_tools/windows_cp117_windowless_gui_login.py',
 'agent_tools/windows_cp117_windowless_provider_login.py',
 'agent_tools/windows_credential_probe_ssh.py',
 'agent_tools/windows_diagnostic_authority_capture.py',
 'agent_tools/windows_fixture_credentials.py',
 'agent_tools/windows_fixture_network_probe.py',
 'agent_tools/windows_fixture_owner_network.py',
 'agent_tools/windows_fixture_phase_status.py',
 'agent_tools/windows_fixture_server_abort_successor.py',
 'agent_tools/windows_fixture_server_second_abort_successor.py',
 'agent_tools/windows_guest_receipt_read.py',
 'agent_tools/windows_large_artifact_transfer.py',
 'agent_tools/windows_msi_base_prepare.py',
 'agent_tools/windows_msi_http_transfer.py',
 'agent_tools/windows_msi_owner_liveness.py',
 'agent_tools/windows_msi_owner_public_status.py',
 'agent_tools/windows_msi_owner_quit_phase_diagnostic.py',
 'agent_tools/windows_msi_owner_relaunch.py',
 'agent_tools/windows_msi_owner_relaunch_quit.py',
 'agent_tools/windows_msi_owner_relaunch_quit_v3.py',
 'agent_tools/windows_msi_owner_relaunch_quit_v4.py',
 'agent_tools/windows_msi_public_scenario.py',
 'agent_tools/windows_msi_stale_lock_reconcile.py',
 'agent_tools/windows_msi_stale_lock_recovery.py',
 'agent_tools/windows_msi_target_prepare.py',
 'agent_tools/windows_ps_bootstrap.py',
 'agent_tools/windows_source_custody.py',
 'agent_tools/windows_update_fixture_download_abort.py',
 'agent_tools/windows_update_fixture_download_abort_current.py',
 'agent_tools/windows_update_fixture_guest_create_abort.py',
 'agent_tools/windows_update_fixture_http_stage.py',
 'agent_tools/windows_update_fixture_server.py',
 'agent_tools/windows_update_fixture_stage.py',
 'agent_tools/windows_update_fixture_stage_recovery.py',
 'agent_tools/windows_vm_virt_firmware_install.py',
 'scripts/install_arch_desktop_update.sh',
 'scripts/prepare_macos_install_worker.sh',
 'scripts/setup_macos_signing.sh',
 'scripts/windows_fixture_stage_acl.py',
 'scripts/windows_qga_powershell_size.py',
 'scripts/windows_task_admission.ps1',
)
BEFORE = {
 'test_windows_cp117_base_source_refresh.py': ('fd685eeb83f7e7d5f622ad25492caab83627d4946e628c78104f956fca298205', 1046856),
 'test_windows_cp117_server_preflight.py': ('24dd7aa7c54bd14da74485f2050bd068be3e6e287a8b78f30c7126f89d257d27', 91794),
 'test_windows_cp117_server_read_binding.py': ('da891225fc3b912eb8eea0235943f9879426abf7a01dfedf5415cf4e7faf50c7', 1050462),
 'test_windows_cp117_public_update_flow.py': ('565a02dfe24430be615ea96294a5582265f0b041266fc3a009b74cde8ea4ce64', 932937),
}
REPLACEMENT_BEFORE = ('eb38d09322428d4c5eed77ab87832af30b2c0f2624ceaedbe60870da050acaa9', 1039682)
WINDOWS_WRITER_BEFORE = ('75cb5961f31a2e1bac90e7f27cfd6d34923bed08bad3dac58402c21cd79d1f4a', 1055464)
READ_BEFORE = ('d143a7c39e4b9684f76769eda11cc858958fa2cf8223fcdcd454b5ccbd9d0740',1039581)
METADATA_BEFORE = ('b06d6dc5a5ad8955ba760dad00a59adb0473229175a384ea18f9ecff741bccc3',25267)
CAP_BEFORE = ('33f7d0fed1b77a2af6f96b1c50ebb7045bd70e02f6f3ab8d3e8591c511bca11f',1048941)
BASE_MODULE = 'agent_tools.tests.test_windows_cp117_base_source_refresh'
BYTE_CALLERS = (
 ('agent_tools.tests.test_windows_cp117_server_preflight','ServerPreflightFlowTests','test_actual_full_body_powershell_parser'),
 ('agent_tools.tests.test_windows_cp117_server_preflight','ServerInheritedFailureDiagnosticTests','test_actual_source_guard_inherited_failure_old_red_diagnostic_green'),
 ('agent_tools.tests.test_windows_cp117_server_preflight','ServerFailureWireProjectionTests','test_actual_generated_projection_multibyte_red_bounded_fallback_green'),
 ('agent_tools.tests.test_windows_cp117_server_preflight','ServerInitialTruncationTests','test_actual_initial_ascii_truncation_old_red_current_green'),
 ('agent_tools.tests.test_windows_cp117_server_read_binding','PublisherTypedReadTests','test_actual_source_extracted_native_file_row_old_red_typed_green'),
 ('agent_tools.tests.test_windows_cp117_server_read_binding','PublisherAccessOnlyReadTests','test_actual_installed_read_arity_old_refusal_one_argument_producer'),
)
BASE_CALLERS = (
 (BASE_MODULE,'DirectFixtureReadbackTests','test_actual_whole_readback_body_parser'),
 (BASE_MODULE,'DirectFixtureTlsChannelTests','test_actual_whole_tls_body_and_owner_script_parse_without_effects'),
 (BASE_MODULE,'DirectTlsReadbackTests','test_complete_readonly_task_body_parser'),
 (BASE_MODULE,'DirectTlsFirstStartTests','test_actual_registered_guard_old_null_refusal_and_closed_sid_resolution'),
 (BASE_MODULE,'DirectTlsFirstStartContinuityTests','test_actual_old_final_boundary_starts_changed_task_current_refuses'),
 (BASE_MODULE,'DirectFixtureServerTests','test_actual_complete_server_body_parser'),
 (BASE_MODULE,'DirectFixtureServerReadTests','test_actual_complete_server_read_body_parser'),
 ('agent_tools.tests.test_windows_cp117_server_read_binding','ServerCensusFactoryTests','test_actual_complete_census_body_parser'),
 ('agent_tools.tests.test_windows_cp117_server_read_binding','PublisherReadbackTests','test_actual_native_full_body_parser'),
)
WINDOWS_WRITER_CALLERS = (
 ('agent_tools.tests.test_windows_cp117_server_read_binding','PublisherBoundaryTests','test_actual_source_extracted_catch_preserves_inner_exception'),
 ('agent_tools.tests.test_windows_cp117_server_read_binding','PublisherTypedReadTests','test_actual_source_extracted_native_file_row_old_red_typed_green'),
)
REPLACEMENT_CALLERS = (
 (BASE_MODULE,'BaselineReplacementCompletionTests','test_actual_windows_finish_wait_readback_failed_nonzero_and_timeout'),
 (BASE_MODULE,'RetirementRecoveryTests','test_actual_generated_active_process_readback_preserves_exit_and_unknown'),
)
PUBLIC_CALLER = ('agent_tools.tests.test_windows_cp117_public_update_flow',
 'PublicPostConsentCoordinatorTests','test_actual_native_five_argument_consumer_and_complete_script_parser')
PROGRAM = '''import json,sys\nfrom pathlib import Path\nroot=Path(sys.argv[1]).resolve(strict=True)\nsys.path.insert(0,str(root))\nfrom agent_tools.tests import test_windows_native_fixture_callers as helper\nraise SystemExit(helper.qualify(root,sys.argv[2],sys.argv[3]))\n'''

class BoundaryReached(BaseException):
 """Not a native PASS, transport result or OS exception."""


def _source(path):
 before = path.lstat()
 if path.is_symlink() or not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= 8*1024*1024:
  raise ValueError('qualification-source-metadata')
 raw = path.read_bytes()
 generation=lambda value:tuple(getattr(value,name)for name in
  ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
 if generation(path.lstat()) != generation(before) or len(raw) != before.st_size:
  raise ValueError('qualification-source-changed')
 return raw, (hashlib.sha256(raw).hexdigest(), stat.S_IMODE(before.st_mode))


def _snapshot(root, names):
 return {name: _source(root/name)[1] for name in names}


def _module(name, root, variant, original=None):
 module = importlib.import_module(name)
 expected = root/Path(*name.split('.')).with_suffix('.py')
 if Path(module.__file__).resolve() != expected.resolve():
  raise ValueError('qualification-import-origin')
 if variant == 'before' and expected.name in BEFORE:
  digest, size = original if original is not None else BEFORE[expected.name]
  raw, pin = _source(expected)
  if len(raw) != size or pin[0] != digest:
   raise ValueError('qualification-original-B-origin')
 return module


def _method(selector, root, variant, boundary, original=None):
 name, cls, function = selector
 module = _module(name, root, variant,original)
 case = getattr(module, cls)(function)
 actual = inspect.unwrap(getattr(type(case), function))
 if not Path(actual.__code__.co_filename).resolve().is_relative_to(root):
  raise ValueError('qualification-method-origin')
 # Normal imports and genuine module globals already exist. Re-enter only the
 # repository's established exact public-source test context after unwrapping.
 from agent_tools.tests.fixtures.windows_cp117_historical_factory.context import inert_repository_source_reads
 with inert_repository_source_reads(), mock.patch.object(subprocess, 'run', boundary):
  try:
   case.setUp()
   actual(case)
  finally:
   case.doCleanups()


def _boundary(observations, require_packet, require_env=False, expected_public=None, public_sink=None):
 def run(argv, **options):
  units = len(subprocess.list2cmdline(argv).encode('utf-16-le'))//2+1
  packet = options.get('input')
  row = {'commandUtf16Units': units, 'argvBytes': len(subprocess.list2cmdline(argv).encode()),
         'packetBytes': len(packet) if type(packet) is bytes else None}
  observations.append(row)
  # Projection of the real generated argv, not a fabricated Win32 exception.
  if units >= 32767:
   raise AssertionError('portable-win32-command-budget: '+str(units))
  if require_packet or packet is not None:
   if type(packet) is not bytes or len(packet) <= 4:
    raise AssertionError('authenticated-frame-required')
   public = packet[4:]
   if int.from_bytes(packet[:4], 'little') != len(public) or len(public) > 262144:
    raise AssertionError('authenticated-frame-length')
   public.decode('utf-8', errors='strict')
   loader = base64.b64decode(argv[-1],validate=True).decode('utf-16-le',errors='strict')
   sha = hashlib.sha256(public).hexdigest()
   row.update(sourceBytes=len(public),sourceSha256=sha)
   if public_sink is not None:public_sink.append(public)
   if sha not in loader or len(argv[-1]) >= 30000:
    raise AssertionError('authenticated-loader-bound')
   if not loader.endswith('& ([ScriptBlock]::Create($cp117Body))'):
    raise AssertionError('authenticated-loader-completion')
   if expected_public is not None and public != expected_public:
    raise AssertionError('whole-source-drift')
  if require_env:
   from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment
   if options.get('env') != windows_powershell_environment(argv[0], os.environ):
    raise AssertionError('actual-peer-environment-missing')
  raise BoundaryReached()
 return run



def _replacement_section(module,selector,root,variant):
 from agent_tools.tests.fixtures.windows_cp117_historical_factory import context
 from agent_tools.tests.fixtures.windows_replacement_fixture_sections import OUTER_REPLACEMENT_CATCH
 source=Path(module.__file__);raw,pin=_source(source);tree=ast.parse(raw)
 cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name==selector[1])
 method=next(n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name==selector[2])
 slots={}
 for name in ('task','final','finish'):
  assignments=[n for n in ast.walk(method)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==name for t in n.targets)]
  if len(assignments)!=int(name!='finish' or selector[1]=='BaselineReplacementCompletionTests'):raise ValueError('replacement-fixture-caller-'+name+'-slot')
  if assignments:slots[name]=assignments[0].value
 call=slots['task']
 if not isinstance(call,ast.Call)or not isinstance(call.func,ast.Attribute)or call.func.attr!='replacement_task':raise ValueError('replacement-fixture-task-call')
 argument=call.args[0]
 if isinstance(argument,ast.Constant)and type(argument.value)is str:phases=(argument.value,)
 elif isinstance(argument,ast.Name):
  loops=[n for n in ast.walk(method)if isinstance(n,ast.For)and isinstance(n.target,ast.Name)and n.target.id==argument.id]
  if len(loops)!=1:raise ValueError('replacement-fixture-phase-loop')
  phases=ast.literal_eval(loops[0].iter)
 else:raise ValueError('replacement-fixture-phase-source')
 if type(phases)is not tuple or not phases or len(set(phases))!=len(phases)or any(type(p)is not str for p in phases):raise ValueError('replacement-fixture-phase-values')
 case=getattr(module,selector[1])(selector[2]);tasks=[]
 with context.inert_repository_source_reads():
  try:
   case.setUp()
   for phase in phases:
    local={'phase':phase,'corr':'10101010-1010-4010-8010-101010101010','nonce':'20202020-2020-4020-8020-202020202020'}
    task=eval(compile(ast.Expression(call),str(source),'eval'),module.__dict__,local)
    tasks.append((phase,task,local))
  finally:case.doCleanups()
 issues=[];evidence=[];check=unittest.TestCase()
 for phase,task,local in tasks:
  if task.count(OUTER_REPLACEMENT_CATCH)!=1 or task.count('\ntry{')!=1 or '}catch{$cp117BusyError='not in task:raise ValueError('replacement-fixture-authentic-catches')
  begin=task.index('\ntry{');end=task.index(OUTER_REPLACEMENT_CATCH)
  if not begin<task.index('}catch{$cp117BusyError=')<end:raise ValueError('replacement-fixture-authentic-catch-order')
  local['task']=task;row={'phase':phase,'taskSha256':hashlib.sha256(task.encode()).hexdigest(),'taskBytes':len(task.encode()),'outerTryOffset':begin,'firstCatchOffset':task.index('}catch{'),'outerCatchOffset':end,'sections':{}}
  for name in ('final','finish'):
   if name not in slots:continue
   # Execute both actual caller expressions independently, so a bad final tail
   # cannot hide a separate empty or preempted finish branch.
   actual=eval(compile(ast.Expression(slots[name]),str(source),'eval'),module.__dict__,local)
   if name=='final':start=end;expected=task[end:]
   else:
    marker=' if($retired)'if phase=='retire'else' if($provisioned)'
    if task.count(marker,begin+len('\ntry{'),end)!=1:raise ValueError('replacement-fixture-authentic-finish-marker')
    start=task.index(marker,begin+len('\ntry{'),end);expected=task[start:end]
   passed=type(actual)is str and bool(actual)and actual==expected
   row['sections'][name]={'startOffset':start,'endOffset':len(task)if name=='final'else end,'expectedBytes':len(expected.encode()),'actualBytes':len(actual.encode())if type(actual)is str else None,'exactCompleteSlice':passed}
   if not passed:issues.append(phase+':'+name+':replacement-complete-outer-section')
  if variant=='current':
   guard=module.replacement_fixture_outer_catch
   for bad in (b'PUBLIC',task.replace(OUTER_REPLACEMENT_CATCH,'FOREIGN'),task+OUTER_REPLACEMENT_CATCH,OUTER_REPLACEMENT_CATCH+'\ntry{',task+'#'*65536):
    with check.assertRaisesRegex(ValueError,'replacement-fixture-'):guard(bad)
   if 'finish'in slots:
    finish_guard=module.replacement_fixture_finish;marker=' if($retired)'if phase=='retire'else' if($provisioned)'
    for bad in (task[:start]+task[start:].replace(marker,' FOREIGN',1),task[:end]+marker+task[end:]):
     with check.assertRaisesRegex(ValueError,'replacement-fixture-'):finish_guard(bad,phase)
    for bad_phase in (None,True,'foreign'):
     with check.assertRaisesRegex(ValueError,'replacement-fixture-phase'):finish_guard(task,bad_phase)
  evidence.append(row)
 print('CP117_REPLACEMENT_SECTION_EVIDENCE '+json.dumps({'variant':variant,'caller':list(selector),'rows':evidence},sort_keys=True),flush=True)
 check.assertFalse(issues,';'.join(issues))
 if _source(source)[1]!=pin:raise ValueError('replacement-fixture-caller-changed')


def _replacement_parse_evidence(module,public):
 from agent_tools.tests.fixtures.windows_replacement_fixture_sections import replacement_parse_only_observer
 done=module._run_complete_windows_fixture(replacement_parse_only_observer(public),timeout=25)
 evidence={'returncode':done.returncode,'sourceSha256':hashlib.sha256(public).hexdigest(),'sourceBytes':len(public),'sourceBase64':base64.b64encode(public).decode(),'stdoutBase64':base64.b64encode(done.stdout[:65536]).decode(),'stderrBase64':base64.b64encode(done.stderr[:65536]).decode(),'stdoutBytes':len(done.stdout),'stderrBytes':len(done.stderr)}
 print('CP117_REPLACEMENT_PARSE_EVIDENCE '+json.dumps(evidence,sort_keys=True),flush=True)
 check=unittest.TestCase();check.assertEqual(done.returncode,0,repr(evidence));check.assertLessEqual(len(done.stdout),65536,repr(evidence));check.assertLessEqual(len(done.stderr),65536,repr(evidence))
 value=json.loads(done.stdout.decode('utf-8',errors='strict'))
 check.assertEqual(set(value),{'sourceSha256','sourceBytes','sourceExecuted','parsed','errorCount','errors','truncated'})
 check.assertEqual((value['sourceSha256'],value['sourceBytes']),(evidence['sourceSha256'],len(public)))
 check.assertIs(value['sourceExecuted'],False);check.assertIs(value['truncated'],False);check.assertIs(type(value['parsed']),bool);check.assertIs(type(value['errorCount']),int);check.assertIs(type(value['errors']),list);check.assertEqual(value['errorCount'],len(value['errors']))
 keys={'errorId','message','incompleteInput','startLine','startColumn','endLine','endColumn','startOffset','endOffset','extentText'}
 for row in value['errors']:
  check.assertEqual(set(row),keys);check.assertIs(type(row['errorId']),str);check.assertTrue(row['errorId']);check.assertIs(type(row['message']),str);check.assertIs(type(row['extentText']),str);check.assertIs(type(row['incompleteInput']),bool)
  for name in ('startLine','startColumn','endLine','endColumn','startOffset','endOffset'):check.assertIs(type(row[name]),int);check.assertGreaterEqual(row[name],0)
 return value

def qualify(root, variant, group):
 """Plain internal helper, deliberately not a discovered TestCase class."""
 test = unittest.TestCase()
 rows = []
 if group=='windows-writers':
  if os.name!='nt':raise ValueError('native-windows-writer-required')
  selectors=WINDOWS_WRITER_CALLERS
 elif group in ('replacement-parser','replacement-sections'):
  if group=='replacement-parser' and os.name!='nt':raise ValueError('native-windows-parser-required')
  selectors=REPLACEMENT_CALLERS
 elif group == 'callers':
  selectors = BYTE_CALLERS+BASE_CALLERS
 elif group == 'public':
  selectors = (PUBLIC_CALLER,)
 elif group == 'helper':
  selectors = ((BASE_MODULE, '', '_run_complete_windows_fixture'),)
 elif group == 'server-read-source':
  selectors=((BASE_MODULE,'DirectFixtureServerReadTests','test_actual_complete_server_read_body_parser'),)
 elif group == 'custody':
  selectors = ((BASE_MODULE,'','actual-public-source-custody'),)
 elif group == 'separator':
  selectors = ((BASE_MODULE,'ProvisionRecoveryIngressTests',
                'test_actual_old_ingress_refuses_provision_and_current_binds_whole_receipts'),)
 else:
  raise ValueError('qualification-group')
 for selector in selectors:
  observations = []
  entry = {'selector': selector, 'observations': observations}
  try:
   if group=='windows-writers':
    writes=[];entry['physicalSourceWrites']=writes
    text_writer=Path.write_text;byte_writer=Path.write_bytes
    def report(path,expected,kind):
     if path.name=='old.py':
      actual=path.read_bytes();writes.append({'writer':kind,'expectedSha256':hashlib.sha256(expected).hexdigest(),'observedSha256':hashlib.sha256(actual).hexdigest(),'bytes':len(actual),'exactBytes':actual==expected,'exactWindowsNewlineProjection':actual==expected.replace(b'\n',b'\r\n')})
    def write_text(path,data,*args,**kwargs):
     value=text_writer(path,data,*args,**kwargs);report(path,data.encode('utf-8',errors='strict'),'text');return value
    def write_bytes(path,data,*args,**kwargs):
     value=byte_writer(path,data,*args,**kwargs);report(path,data,'bytes');return value
    with mock.patch.object(Path,'write_text',write_text),mock.patch.object(Path,'write_bytes',write_bytes),test.assertRaises(BoundaryReached):
     _method(selector,root,variant,_boundary(observations,True),WINDOWS_WRITER_BEFORE if variant=='before'else None)
   elif group=='replacement-sections':
    module=_module(BASE_MODULE,root,variant,REPLACEMENT_BEFORE if variant=='before'else None)
    _replacement_section(module,selector,root,variant)
   elif group=='replacement-parser':
    public=[]
    with test.assertRaises(BoundaryReached):_method(selector,root,variant,_boundary(observations,True,public_sink=public),REPLACEMENT_BEFORE if variant=='before'else None)
    test.assertEqual(len(public),1)
    module=_module(BASE_MODULE,root,variant,REPLACEMENT_BEFORE if variant=='before'else None)
    entry['parser']=_replacement_parse_evidence(module,public[0])
    test.assertTrue(entry['parser']['parsed'] and not entry['parser']['errors'],'replacement-fixture-body-parse')
   elif group == 'helper':
    module = _module(BASE_MODULE,root,variant)
    public = b'#'+b'PUBLIC'*20000+b"\n'PUBLIC lambda: \xce\xbb'\n"
    boundary = _boundary(observations,True,True,public)
    with mock.patch.object(subprocess,'run',boundary), test.assertRaises(BoundaryReached):
     module._run_complete_windows_fixture(public,timeout=20)
    for invalid in (b'',b'P'*262145,'PUBLIC'):
     with mock.patch.object(subprocess,'run',side_effect=AssertionError('bound-before-IO')):
      with test.assertRaisesRegex(ValueError,'test-source-bound'):
       module._run_complete_windows_fixture(invalid,timeout=20)
   elif group == 'custody':
    from agent_tools.tests.fixtures.windows_cp117_historical_factory import context
    actual = root/'agent_tools/tests/fixtures/windows_cp117_historical_factory/context.py'
    test.assertEqual(Path(context.__file__).resolve(),actual.resolve())
    source = root/'agent_tools/tests/test_windows_cp117_base_source_refresh.py'
    pin,public = context._public_source(source)
    test.assertLessEqual(len(public),1048576)
    test.assertEqual(pin['sha256'],hashlib.sha256(public).hexdigest())
    test.assertEqual(public,_source(source)[0])
    entry['sourceBytes']=len(public)
   elif group == 'separator':
    module = _module(BASE_MODULE,root,variant)
    # The actual stdlib Windows path flavour projects the observed key failure.
    # No filesystem identity or source origin is relabelled. Existing whole
    # receipt positive and hash/generation refusal assertions all execute.
    with mock.patch.object(module,'Path',PureWindowsPath):
     _method(selector,root,variant,lambda *a,**k: (_ for _ in ()).throw(AssertionError('unexpected-process')))
   else:
    boundary = _boundary(observations,group == 'public' or selector in BYTE_CALLERS)
    with test.assertRaises(BoundaryReached):
     _method(selector,root,variant,boundary,READ_BEFORE if group=='server-read-source' and variant=='before' else None)
   test.assertEqual(len(observations),0 if group in ('separator','custody','replacement-sections') else 1)
   entry['passed'] = True
  except BaseException as error:
   entry.update(passed=False,exceptionType=type(error).__name__,reason=str(error),
                traceback=''.join(traceback.format_exception(error)))
  rows.append(entry)
 print(json.dumps({'variant':variant,'group':group,'rows':rows},sort_keys=True),flush=True)
 return 0 if all(row['passed'] for row in rows) else 1


def _retained_qualification_captures(text,group,variants):
 """Reconstruct public evidence only; never execute captured programme bytes."""
 def require(ok,label):
  if not ok:raise ValueError('qualification-capture-'+label)
 def unique(pairs):
  value={}
  for key,item in pairs:
   require(key not in value,'duplicate-key');value[key]=item
  return value
 def integer(value,minimum,maximum):return type(value)is int and minimum<=value<=maximum
 require(type(text)is str and group in ('replacement-parser','windows-writers','replacement-sections'),'input')
 require(type(variants)is tuple and variants in (('before',),('current',),('before','current')),'expected-variants')
 lines=text.splitlines();require(len(lines)<=(768+1)*len(variants),'line-count')
 captures=[];seen=set();parts=[];pending=None;count=None
 chunk_prefix='CP117_NATIVE_CALLER_CAPTURE_CHUNK ';manifest_prefix='CP117_NATIVE_CALLER_CAPTURE_MANIFEST '
 for line in lines:
  require(0<len(line.encode('ascii'))<=16384,'line-bound')
  chunk=line.startswith(chunk_prefix);manifest=line.startswith(manifest_prefix)
  require(chunk or manifest,'label')
  frame=json.loads(line[len(chunk_prefix if chunk else manifest_prefix):],object_pairs_hook=unique)
  require(type(frame)is dict,'frame-type')
  require(type(frame.get('schemaVersion'))is int and frame['schemaVersion']==1,'schema')
  identity=frame.get('captureId');require(type(identity)is str and len(identity)==32 and all(c in '0123456789abcdef'for c in identity),'identity')
  if chunk:
   require(set(frame)=={'schemaVersion','captureId','index','chunks','payloadBytes','payloadSha256','dataBase64'},'chunk-keys')
   require(integer(frame['index'],0,767)and integer(frame['chunks'],1,768),'chunk-numbers')
   if pending is None:
    require(identity not in seen and frame['index']==0,'new-capture');pending=identity;count=frame['chunks']
   require(identity==pending and frame['chunks']==count and frame['index']==len(parts)and len(parts)<count,'chunk-order')
   require(integer(frame['payloadBytes'],1,8192)and type(frame['dataBase64'])is str and len(frame['dataBase64'])<=10924,'chunk-bound')
   part=base64.b64decode(frame['dataBase64'],validate=True)
   require(len(part)==frame['payloadBytes']and hashlib.sha256(part).hexdigest()==frame['payloadSha256'],'chunk-hash')
   require(len(part)==8192 or len(parts)==count-1,'chunk-size-order')
   parts.append(part);require(sum(map(len,parts))<=6*1024*1024,'payload-bound')
   continue
  require(set(frame)=={'schemaVersion','captureId','group','variant','returncode','chunks','payloadBytes','payloadSha256','rawStreams'},'manifest-keys')
  require(pending is not None and identity==pending and integer(frame['chunks'],1,768)and frame['chunks']==count and len(parts)==count,'complete-chunks')
  require(len(captures)<len(variants)and frame['group']==group and frame['variant']==variants[len(captures)],'capture-order')
  require(type(frame['returncode'])is int and frame['returncode']==(1 if frame['variant']=='before'else 0),'returncode')
  payload=b''.join(parts)
  require(integer(frame['payloadBytes'],1,6*1024*1024)and len(payload)==frame['payloadBytes']and (len(payload)+8191)//8192==count and hashlib.sha256(payload).hexdigest()==frame['payloadSha256'],'whole-hash')
  record=json.loads(payload.decode('ascii',errors='strict'),object_pairs_hook=unique)
  truths={'stdoutEOF','stderrEOF','directChildReaped','programmeSourceChecked','copiedSourceChecked','repositorySourceChecked','ownedCopyRemoved'}
  require(type(record)is dict and set(record)=={'schemaVersion','captureId','group','variant','returncode','streams','nativeFixtureBodyExecuted'}|truths,'payload-keys')
  require(type(record['schemaVersion'])is int and record['schemaVersion']==1 and record['captureId']==identity and record['group']==group and record['variant']==frame['variant']and type(record['returncode'])is int and record['returncode']==frame['returncode'],'payload-identity')
  require(all(type(record[k])is bool and record[k]is True for k in truths)and type(record['nativeFixtureBodyExecuted'])is bool and record['nativeFixtureBodyExecuted']is False,'closure')
  require(type(record['streams'])is dict and set(record['streams'])=={'stdout','stderr'}and type(frame['rawStreams'])is dict and set(frame['rawStreams'])=={'stdout','stderr'},'stream-keys')
  for label,stream in record['streams'].items():
   require(type(stream)is dict and set(stream)=={'bytes','sha256','base64'}and integer(stream['bytes'],0,2*1024*1024)and type(stream['base64'])is str,'stream-schema')
   raw=base64.b64decode(stream['base64'],validate=True)
   require(len(raw)==stream['bytes']and hashlib.sha256(raw).hexdigest()==stream['sha256'],'stream-hash')
   summary=frame['rawStreams'][label]
   require(type(summary)is dict and set(summary)=={'bytes','sha256'}and type(summary['bytes'])is int and summary=={k:stream[k]for k in ('bytes','sha256')},'manifest-stream')
  seen.add(identity);captures.append(record);pending=None;parts=[];count=None
 require(pending is None and len(captures)==len(variants),'complete-captures')
 return captures


class WindowsNativeFixtureCallerTests(unittest.TestCase):
 def _variant(self, group, variant):
  required = {SELF, FIXTURE+'/provenance.json', *(FIXTURE+'/'+name+'.before.source' for name in BEFORE),
              'agent_tools/tests/fixtures/windows_powershell_environment.py',
              'agent_tools/tests/fixtures/windows_shortcut_access_wire.py',
              FIXTURE+'/base.overflow-before-slim.source',
              FIXTURE+'/base.server-read-before.source',
              FIXTURE+'/routine.metadata-before.source',FIXTURE+'/base.parser-catch-before.source',FIXTURE+'/read-binding.text-writer-before.source',
              '.gitattributes','agent_tools/tests/fixtures/windows_replacement_fixture_sections.py'}
  names = tuple(CONTEXT_PATHS)
  self.assertTrue(names,'parent must fill the finite CONTEXT_PATHS tuple before execution')
  self.assertEqual(len(names),len(set(names)))
  self.assertLessEqual(len(names),512)
  self.assertTrue(required <= set(names),'complete own module/beforefiles/actual helper graph required')
  for name in names:
   relative = Path(name)
   self.assertFalse(relative.is_absolute() or '..' in relative.parts)
  provenance=json.loads((ROOT/FIXTURE/'provenance.json').read_bytes())
  self.assertEqual(provenance['originalHeadSha'],'a5cd9b73d49ff0b52f4a04a29a9122d4fe48b173')
  self.assertEqual({Path(row['path']).name:(row['sha256'],row['bytes'])for row in provenance['files']},BEFORE)
  self.assertEqual((provenance['sourceCapBefore']['sha256'],provenance['sourceCapBefore']['bytes']),CAP_BEFORE)
  self.assertEqual((provenance['serverReadBefore']['sha256'],provenance['serverReadBefore']['bytes']),READ_BEFORE)
  self.assertEqual((provenance['metadataBefore']['sha256'],provenance['metadataBefore']['bytes']),METADATA_BEFORE)
  for field,expected in (('replacementParserBefore',REPLACEMENT_BEFORE),('windowsTextWriterBefore',WINDOWS_WRITER_BEFORE)):
   self.assertEqual((provenance[field]['sha256'],provenance[field]['bytes']),expected)
  opening = _snapshot(ROOT,names)
  with tempfile.TemporaryDirectory(prefix='vc-native-callers-') as temporary:
   context = Path(temporary).resolve()
   total = 0
   for name in names:
    raw,pin = _source(ROOT/name)
    total += len(raw)
    self.assertLessEqual(total,64*1024*1024)
    target = context/name
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(raw)
    target.chmod(pin[1])
   if variant == 'before' and group not in ('server-read-source','windows-writers','replacement-parser','replacement-sections'):
    for name,(sha,size) in BEFORE.items():
     source = context/FIXTURE/(name+'.before.source')
     raw,pin = _source(source)
     self.assertEqual((len(raw),pin[0]),(size,sha))
     (context/'agent_tools/tests'/name).write_bytes(raw)
   if variant=='before' and group in ('replacement-parser','replacement-sections','windows-writers'):
    name,preserved,expected=('test_windows_cp117_server_read_binding.py','read-binding.text-writer-before.source',WINDOWS_WRITER_BEFORE)if group=='windows-writers'else('test_windows_cp117_base_source_refresh.py','base.parser-catch-before.source',REPLACEMENT_BEFORE)
    raw,pin=_source(context/FIXTURE/preserved);self.assertEqual((pin[0],len(raw)),expected)
    (context/'agent_tools/tests'/name).write_bytes(raw)
   if variant=='before' and group=='server-read-source':
    raw,pin=_source(context/FIXTURE/'base.server-read-before.source')
    self.assertEqual((pin[0],len(raw)),READ_BEFORE)
    (context/'agent_tools/tests/test_windows_cp117_base_source_refresh.py').write_bytes(raw)
   if variant == 'before' and group == 'custody':
    raw,pin=_source(context/FIXTURE/'base.overflow-before-slim.source')
    self.assertEqual((pin[0],len(raw)),CAP_BEFORE)
    (context/'agent_tools/tests/test_windows_cp117_base_source_refresh.py').write_bytes(raw)
   copied = _snapshot(context,names)
   programme = context/'_native_fixture_qualification.py'
   programme_raw=PROGRAM.encode('utf-8')
   with programme.open('xb')as saved:saved.write(programme_raw)
   programme.chmod(0o600)
   programme_opening=_source(programme)[1]
   environment = dict(os.environ)
   environment.pop('DYLD_INSERT_LIBRARIES',None)
   environment.pop('DYLD_LIBRARY_PATH',None)
   environment.pop('WINDOWS_NATIVE_CALLER_VARIANT',None)
   environment['PYTHONDONTWRITEBYTECODE'] = '1'
   owned = context/'owned-tmp';owned.mkdir()
   environment.update(TMPDIR=str(owned),TEMP=str(owned),TMP=str(owned))
   argv = [sys.executable,'-I','-B',str(programme),str(context),variant,group]
   self.assertLessEqual(len(subprocess.list2cmdline(argv).encode()),60000)
   completed = subprocess.run(argv,capture_output=True,env=environment,cwd=context,timeout=180)
   evidence = (f'variant={variant}; group={group}; exit={completed.returncode}\n'
               f'stdout={completed.stdout!r}\nstderr={completed.stderr!r}')
   self.assertEqual(_source(programme)[1],programme_opening,evidence)
   self.assertEqual(_snapshot(context,names),copied,evidence)
   self.assertEqual(_snapshot(ROOT,names),opening,evidence)
  if group in ('replacement-parser','windows-writers','replacement-sections'):
   self.assertFalse(context.exists(),'qualification-owned-copy-cleanup')
   streams={}
   for label,value in (('stdout',completed.stdout),('stderr',completed.stderr)):
    self.assertLessEqual(len(value),2*1024*1024,'qualification-evidence-stream-bound:'+label)
    streams[label]={'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest(),'base64':base64.b64encode(value).decode('ascii')}
   capture_id=os.urandom(16).hex()
   capture={'schemaVersion':1,'captureId':capture_id,'group':group,'variant':variant,'returncode':completed.returncode,
            'streams':streams,'stdoutEOF':True,'stderrEOF':True,'directChildReaped':True,
            'programmeSourceChecked':True,'copiedSourceChecked':True,'repositorySourceChecked':True,
            'ownedCopyRemoved':True,'nativeFixtureBodyExecuted':False}
   payload=json.dumps(capture,sort_keys=True).encode('ascii')
   self.assertLessEqual(len(payload),6*1024*1024,'qualification-evidence-payload-bound')
   count=(len(payload)+8191)//8192
   for index,offset in enumerate(range(0,len(payload),8192)):
    part=payload[offset:offset+8192]
    frame={'schemaVersion':1,'captureId':capture_id,'index':index,'chunks':count,'payloadBytes':len(part),
           'payloadSha256':hashlib.sha256(part).hexdigest(),'dataBase64':base64.b64encode(part).decode('ascii')}
    line='CP117_NATIVE_CALLER_CAPTURE_CHUNK '+json.dumps(frame,sort_keys=True)
    self.assertLessEqual(len(line.encode('ascii')),16384,'qualification-evidence-line-bound')
    print(line,flush=True)
   manifest={'schemaVersion':1,'captureId':capture_id,'group':group,'variant':variant,'returncode':completed.returncode,
             'chunks':count,'payloadBytes':len(payload),'payloadSha256':hashlib.sha256(payload).hexdigest(),
             'rawStreams':{label:{key:value[key]for key in ('bytes','sha256')}for label,value in streams.items()}}
   line='CP117_NATIVE_CALLER_CAPTURE_MANIFEST '+json.dumps(manifest,sort_keys=True)
   self.assertLessEqual(len(line.encode('ascii')),16384,'qualification-evidence-manifest-bound')
   print(line,flush=True)
  lines = completed.stdout.decode('utf-8',errors='strict').splitlines()
  result = json.loads(lines[-1]) if lines else None
  return completed,result,evidence

 def _compare(self, group):
  requested = os.environ.get('WINDOWS_NATIVE_CALLER_VARIANT','compare')
  self.assertIn(requested,('compare','before','current'))
  if requested in ('compare','before'):
   old,record,evidence = self._variant(group,'before')
   if requested == 'before':
    # Explicit actual RED command runs the same positive assertion on B bytes.
    self.assertEqual(old.returncode,0,evidence)
    return
   self.assertNotEqual(old.returncode,0,evidence)
   self.assertIsNotNone(record,evidence)
   self.assertTrue(record['rows'],evidence)
   for row in record['rows']:
    self.assertFalse(row['passed'],evidence)
    cause = row['reason']
    if group == 'helper':
     self.assertIn('actual-peer-environment-missing',cause,evidence)
    elif group == 'public':
     self.assertIn('portable-win32-command-budget',cause,evidence)
    elif group=='windows-writers':
     self.assertEqual((row['exceptionType'],cause),('ValueError','inert-public-source-bytes'),evidence)
     self.assertEqual(len(row['physicalSourceWrites']),1,evidence);write=row['physicalSourceWrites'][0];self.assertEqual(write['writer'],'text',evidence);self.assertFalse(write['exactBytes'],evidence);self.assertTrue(write['exactWindowsNewlineProjection'],evidence)
    elif group=='replacement-sections':
     self.assertEqual(row['exceptionType'],'AssertionError',evidence)
     expected=['retire:final:replacement-complete-outer-section']
     if row['selector'][1]=='BaselineReplacementCompletionTests':expected+=['retire:finish:replacement-complete-outer-section','provision:final:replacement-complete-outer-section','provision:finish:replacement-complete-outer-section']
     for detail in expected:self.assertIn(detail,cause,evidence)
    elif group=='replacement-parser':
     self.assertEqual(row['exceptionType'],'AssertionError',evidence);self.assertIn('replacement-fixture-body-parse',cause,evidence);self.assertFalse(row['parser']['parsed'],evidence);self.assertTrue(row['parser']['errors'],evidence)
    elif group == 'server-read-source':
     self.assertEqual((row['exceptionType'],cause),('ValueError','inert-public-source-bytes'),evidence)
    elif group == 'custody':
     self.assertEqual((row['exceptionType'],cause),('ValueError','source-record'),evidence)
    elif group == 'separator':
     self.assertEqual(row['exceptionType'],'KeyError',evidence)
     self.assertIn('\\',cause,evidence)
    elif tuple(row['selector']) in BYTE_CALLERS:
     self.assertEqual((row['exceptionType'],cause),('ValueError','test-source-bound'),evidence)
    else:
     self.assertEqual(row['exceptionType'],'NameError',evidence)
     self.assertIn("name 'subprocess' is not defined",cause,evidence)
  if requested in ('compare','current'):
   fixed,record,evidence = self._variant(group,'current')
   self.assertEqual(fixed.returncode,0,evidence)
   self.assertTrue(record['rows'],evidence)
   self.assertTrue(all(row['passed'] for row in record['rows']),evidence)
   if group=='windows-writers':
    for row in record['rows']:
     self.assertEqual(len(row['physicalSourceWrites']),1,evidence);write=row['physicalSourceWrites'][0];self.assertEqual(write['writer'],'bytes',evidence);self.assertTrue(write['exactBytes'],evidence)


 def test_actual_native_caller_methods_reach_the_authenticated_boundary(self):
  self._compare('callers')

 def test_actual_public_consumer_method_has_a_bounded_win32_projection(self):
  self._compare('public')

 def test_actual_complete_fixture_helper_preserves_bytes_caps_and_peer_environment(self):
  self._compare('helper')

 def test_actual_receipt_ingress_uses_windows_posix_relative_keys(self):
  self._compare('separator')

 def test_actual_public_source_custody_keeps_its_one_mib_guard(self):
  self._compare('custody')

 def test_actual_inherited_server_read_parser_uses_its_owned_source(self):
  self._compare('server-read-source')

 def test_actual_source_reader_allows_access_time_only_and_refuses_stable_generation_drift(self):
  from types import SimpleNamespace
  # The retained physical3.12 observation changed only access time when read.
  # This portable metadata-only projection keeps real file IO and models that
  # read-side field change explicitly; no physical/native result is invented.
  names=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  requested=os.environ.get('WINDOWS_NATIVE_CALLER_VARIANT','compare')
  self.assertIn(requested,('compare','before','current'))
  sources=[('before',ROOT/FIXTURE/'routine.metadata-before.source',METADATA_BEFORE),
           ('current',ROOT/SELF,None)]
  for variant,source,expected in sources:
   if requested!='compare' and requested!=variant:continue
   raw,pin=_source(source)
   if expected is not None:self.assertEqual((pin[0],len(raw)),expected)
   tree=ast.parse(raw);function=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_source')
   # Run the actual function and its actual ordinary stdlib imports. It consumes
   # no module ROOT/__file__ or project globals; source filenames remain real.
   imports=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom))]
   scope={};exec(compile(ast.Module(body=imports+[function],type_ignores=[]),str(source),'exec'),scope)
   read=scope['_source']
   with tempfile.TemporaryDirectory(prefix='vc-source-metadata-')as directory:
    physical=Path(directory)/'public.source';data=b'PUBLIC metadata read probe\n';physical.write_bytes(data)
    class ReadView:
     def __init__(self,drift=None):self.after=False;self.drift=drift
     def lstat(self):
      actual=physical.lstat();values={name:getattr(actual,name)for name in names+('st_atime','st_atime_ns')}
      if self.after:
       values['st_atime']+=1;values['st_atime_ns']+=1000000000
       if self.drift is not None:values[self.drift]+=1
      return SimpleNamespace(**values)
     def is_symlink(self):return physical.is_symlink()
     def read_bytes(self):self.after=True;return physical.read_bytes()
    if variant=='before' and requested=='compare':
     with self.assertRaisesRegex(ValueError,'qualification-source-changed'):read(ReadView())
    else:self.assertEqual(read(ReadView())[0],data)
    for name in names:
     with self.subTest(variant=variant,drift=name),self.assertRaisesRegex(ValueError,'qualification-source-changed'):
      read(ReadView(name))
   self.assertEqual(_source(source)[1],pin)

 def test_actual_caller_tail_expression_selects_the_unique_outer_catch(self):
  captured=io.StringIO()
  try:
   with mock.patch.object(sys,'stdout',captured):self._compare('replacement-sections')
  finally:
   retained=captured.getvalue();sys.stdout.write(retained);sys.stdout.flush()
  requested=os.environ.get('WINDOWS_NATIVE_CALLER_VARIANT','compare')
  variants=('before','current')if requested=='compare'else(requested,)
  records=_retained_qualification_captures(retained,'replacement-sections',variants)
  self.assertEqual([row['variant']for row in records],list(variants))
  lines=retained.splitlines();prefix='CP117_NATIVE_CALLER_CAPTURE_CHUNK '
  first=json.loads(lines[0][len(prefix):]);tampered=dict(first,dataBase64=('A'if first['dataBase64'][0]!='A'else'B')+first['dataBase64'][1:])
  foreign=dict(first,captureId='0'*32 if first['captureId']!='0'*32 else'1'*32);unknown=dict(first,unknown=True);wrongtype=dict(first,index=False)
  bad_cases=[retained+retained,'\n'.join(lines[1:]),'\n'.join(lines[:-1]),'\n'.join([lines[1],lines[0],*lines[2:]]),'X'*16385]
  for badframe in (tampered,foreign,unknown,wrongtype):bad_cases.append('\n'.join([prefix+json.dumps(badframe,sort_keys=True),*lines[1:]]))
  for number,bad in enumerate(bad_cases):
   with self.subTest(retentionRefusal=number),self.assertRaisesRegex(ValueError,'qualification-capture-'):
    _retained_qualification_captures(bad,'replacement-sections',variants)

 @unittest.skipUnless(os.name=='nt','native Windows physical newline conversion and real custody required')
 def test_actual_windows_old_text_writer_red_exact_byte_writer_green(self):
  self._compare('windows-writers')

 @unittest.skipUnless(os.name=='nt','native Windows PowerShell Parser IDs and extents required')
 def test_actual_windows_old_caller_body_parse_red_complete_current_body_green(self):
  self._compare('replacement-parser')
