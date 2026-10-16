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
 'agent_tools/tests/fixtures/windows_native_fixture_callers/routine.metadata-before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/provenance.json',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/test_windows_cp117_base_source_refresh.py.before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/test_windows_cp117_public_update_flow.py.before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/test_windows_cp117_server_preflight.py.before.source',
 'agent_tools/tests/fixtures/windows_native_fixture_callers/test_windows_cp117_server_read_binding.py.before.source',
 'agent_tools/tests/fixtures/windows_powershell_environment.py',
 'agent_tools/tests/fixtures/windows_shortcut_access_wire.py',
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


def _boundary(observations, require_packet, require_env=False, expected_public=None):
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


def qualify(root, variant, group):
 """Plain internal helper, deliberately not a discovered TestCase class."""
 test = unittest.TestCase()
 rows = []
 if group == 'callers':
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
   if group == 'helper':
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
   test.assertEqual(len(observations),0 if group in ('separator','custody') else 1)
   entry['passed'] = True
  except BaseException as error:
   entry.update(passed=False,exceptionType=type(error).__name__,reason=str(error),
                traceback=''.join(traceback.format_exception(error)))
  rows.append(entry)
 print(json.dumps({'variant':variant,'group':group,'rows':rows},sort_keys=True),flush=True)
 return 0 if all(row['passed'] for row in rows) else 1


class WindowsNativeFixtureCallerTests(unittest.TestCase):
 def _variant(self, group, variant):
  required = {SELF, FIXTURE+'/provenance.json', *(FIXTURE+'/'+name+'.before.source' for name in BEFORE),
              'agent_tools/tests/fixtures/windows_powershell_environment.py',
              'agent_tools/tests/fixtures/windows_shortcut_access_wire.py',
              FIXTURE+'/base.overflow-before-slim.source',
              FIXTURE+'/base.server-read-before.source',
              FIXTURE+'/routine.metadata-before.source'}
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
   if variant == 'before' and group!='server-read-source':
    for name,(sha,size) in BEFORE.items():
     source = context/FIXTURE/(name+'.before.source')
     raw,pin = _source(source)
     self.assertEqual((len(raw),pin[0]),(size,sha))
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
