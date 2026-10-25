"""Actual fixed MCP callback body; fake local/native transport effects only."""
import ast
from contextlib import contextmanager
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import sys
import types
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid
from agent_tools import native_execution_context as context,mcp_server as current_server,readiness,tool_action_policy
from agent_tools.tests import test_native_engineering_entrypoint as fixture

class NativeEngineeringMcpRouteTest(unittest.TestCase):
    def callback(self):
        path=Path(os.environ.get('VPN_ENGINEERING_MCP_SOURCE',str(fixture.fixture.ROOT/'agent_tools/mcp_server.py')))
        tree=ast.parse(path.read_bytes())
        names={'_vm_workflow_impl','_vm_workflow_dispatch','_vm_invalid_before_recovery'}
        # Actual module-level request-shape helpers the pre-recovery gate reads.
        names|={'_WINDOWS_FIXTURE_LIFECYCLE','_windows_fixture_lifecycle_refusal','_valid_uuid','_secureboot_clone_invalid',
                '_secureboot_inventory_invalid','_virt_firmware_admission_invalid','_secureboot_fresh_invalid','_readiness_input_refusal',
                '_deploy_frame_invalid','_deploy_lifecycle_invalid','_deploy_read_invalid','_source_review_close_invalid',
                '_baseline_source_inventory_invalid','_matrix_equivalence_record_invalid','_android_admission_readback_invalid',
                '_android_unknown_install_invalid','_obsolete_consent_denial_invalid','_consent_grant_prompt_invalid',
                '_android_runtime_acceptance_invalid','_api35_remaining_proxy_status_invalid','_endpoint_mount_collect_invalid',
                '_recovered_endpoint_stage_invalid','_endpoint_cleanup_readmission_invalid','_consent_acceptance_preflight_invalid',
                '_msi_preinstall_status_invalid','_msi_powershell_preflight_invalid','_msiexec_service_diagnostic_invalid',
                '_artifact_cache_check_invalid','_android_proxy_refusal','_credential_workflow_refusal','_credential_probe_refusal',
                '_parallel_vm_copy_invalid','_parallel_vm_source_inventory_invalid','_swtpm_owner_observe_invalid',
                '_optical_frame_collect_invalid','_c32_archive_lease_invalid','_consent_grant_acceptance_refusal',
                '_vpn_permission_reset_refusal','_fixture_tls_mint_invalid','_msi_base_finish_invalid'}
        defined=lambda n:n.name if isinstance(n,ast.FunctionDef) else isinstance(n,ast.Assign) and len(n.targets)==1 and getattr(n.targets[0],'id',None)
        nodes=[n for n in tree.body if defined(n) in names]
        if {defined(n) for n in nodes}!=names or len(nodes)!=len(names):raise AssertionError('Incomplete actual MCP callback closure')
        self.admissions=[]
        @contextmanager
        def admit(root,action,inputs):
            # This routing test fakes only the provider admission boundary.
            self.admissions.append((root,action,inputs))
            yield
        def module(name):
            if name=='native_execution_context':return context
            if name=='tmux_workflow_routes':return SimpleNamespace(dispatch=lambda root,action,inputs:{'legacy':True})
            if name=='tool_action_policy':return tool_action_policy
            if name=='readiness':return readiness
            if name=='readiness_vm_dispatch':return SimpleNamespace(admitted_dispatch=admit)
            raise AssertionError('Unsupported native module')
        ns={'__package__':'agent_tools','importlib':importlib,'re':re,'uuid':uuid,'REPO_ROOT':Path('/unused'),
            '_native_source_request':current_server._native_source_request,
            '_agent_module':module,'_error':lambda tool,message:{'tool':tool,'ok':False,'error':message}}
        future=[item for item in tree.body if isinstance(item,ast.ImportFrom) and item.module=='__future__']
        exec(compile(ast.Module(body=future+nodes,type_ignores=[]),str(path),'exec',dont_inherit=True),ns)
        return ns['_vm_workflow_impl']
    def test_complete_before_fixture_omits_actual_dispatch_dependencies(self):
        folder=Path(__file__).with_name('fixtures')/'native_engineering_route_closure'
        raw=(folder/'route.before.source').read_bytes();proof=json.loads((folder/'provenance.json').read_text())
        self.assertEqual(len(raw),proof['sourceSize'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(),proof['sourceSha256'])
        before=types.ModuleType('agent_tools.tests._engineering_route_before')
        before.__file__=str(folder/'route.before.source')
        with patch.dict(sys.modules,{before.__name__:before}):
            exec(compile(raw,before.__file__,'exec'),before.__dict__)
            with self.assertRaisesRegex(NameError,'_vm_invalid_before_recovery'):
                before.NativeEngineeringMcpRouteTest().callback()('linux-package-tmux-start',{'engineeringContext':{}})
    def test_actual_callback_preserves_typed_context_and_all_four_original_request_fields(self):
        callback=self.callback();raw={'sourceSha':'a'*40,'baseVersion':'2.2.8','targetVersion':'2.2.9','correlationId':'original',
            'engineeringContext':{'sourceRoot':'/fixed/same-git/source','artifactIds':['sha256-'+'b'*64]}}
        for operation in ('preflight','start','status','collect'):
            with self.subTest(operation=operation),patch.object(context,'dispatch_linux_engineering',return_value={'state':'unknown','replayAllowed':False}) as dispatch:
                admitted=len(self.admissions)
                result=callback('linux-package-tmux-'+operation,raw)
                dispatch.assert_called_once_with(Path('/unused'),operation,raw)
                self.assertFalse(result['replayAllowed'])
                required=bool(tool_action_policy.action_policy('vm_workflow','linux-package-tmux-'+operation).requirements)
                self.assertEqual(admitted+int(required),len(self.admissions))
                if required:
                    self.assertEqual((Path('/unused'),'linux-package-tmux-'+operation),self.admissions[-1][:2])
                    self.assertIs(raw,self.admissions[-1][2])
    def test_context_cannot_escape_fixed_operations_and_failed_qualification_has_safe_unknown(self):
        callback=self.callback();raw={'engineeringContext':{'admission':False,'command':'caller'}}
        for action in ('linux-package-tmux-availability','linux-package-tmux-resource-prepare','arch-tmux-install-start'):
            with self.subTest(action=action),patch.object(context,'dispatch_linux_engineering',side_effect=AssertionError('No producer dispatch')) as dispatch:
                self.assertFalse(callback(action,raw)['ok']);dispatch.assert_not_called()
        with patch.object(context,'dispatch_linux_engineering',side_effect=ValueError('private paths and raw authority')):
            result=callback('linux-package-tmux-start',raw)
        self.assertEqual('unknown',result['state']);self.assertFalse(result['replayAllowed'])
        self.assertFalse(result['nativeActionAllowed']);self.assertNotIn('private',str(result))
        self.assertEqual({'legacy':True},callback('linux-package-tmux-status',{'correlationId':'original'}))
