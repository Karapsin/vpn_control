"""Actual fixed dispatcher regressions: private helper DTOs are never public DTOs."""
import copy
import ast
import json
import types
import unittest
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import android_consent_grant_acceptance as grant
from agent_tools import android_runtime_acceptance as runtime
from agent_tools import android_vpn_permission_reset as permission
from agent_tools import windows_cp117_staged_fixture_retire as retire

CORRELATION='27f3c11d-2ef6-447b-8f56-7b2bb13eac10'
OTHER='63d2a7bf-686e-480e-9789-a63f83a29089'
STAGE='c01493dd-f2f9-4d64-b8b9-faf6f858e713'
OWNER='2b2f9c45-6c2e-4b40-9d7a-313e2ef71cce'
SECRET='PRIVATE_PROJECTION_SENTINEL'
BASE={'correlationId':CORRELATION,'artifactId':'sha256-'+'a'*64,'cliStageCorrelationId':STAGE,'openingReadbackCorrelationId':OTHER,'expectedBackupSha256':'b'*64,'expectedOwner':OWNER,'expectedRevision':0}
FAMILIES={'android-consent-grant-acceptance':'android_consent_grant_acceptance','android-vpn-permission-reset':'android_vpn_permission_reset','android-runtime-acceptance':'android_runtime_acceptance'}


def inputs(family,method):
    if method!='start':return {'correlationId':CORRELATION}
    if family=='android-runtime-acceptance':return {'correlationId':CORRELATION,'endpointCorrelationId':OTHER,'cliStageCorrelationId':STAGE}
    value=copy.deepcopy(BASE)
    if family=='android-consent-grant-acceptance':value.update(host='archlinux',device='api35')
    return value


def reply(family,state='unknown',**extra):
    if family=='android-consent-grant-acceptance':return grant._reply(CORRELATION,state,**extra)
    if family=='android-runtime-acceptance':return runtime._reply(state,CORRELATION,**extra)
    return {'ok':state in {'submitted','running','complete'},'state':state,'correlationId':CORRELATION,'replayAllowed':False,**extra}


def producer_terminal(family):
    """Evaluate only an actual producer's fixed DTO expression with inert IDs.

    This validates response structure, never a native receipt or its authority.
    """
    source={'android-consent-grant-acceptance':grant._REMOTE,'android-runtime-acceptance':runtime._REMOTE,'android-vpn-permission-reset':permission._STATUS}[family]
    marker={'android-consent-grant-acceptance':'operationCode','android-runtime-acceptance':'sourcePackageSha256','android-vpn-permission-reset':'appOp'}[family]
    target={'android-consent-grant-acceptance':'required','android-runtime-acceptance':'result','android-vpn-permission-reset':'needed'}[family]
    values=[node.value for node in ast.walk(ast.parse(source)) if isinstance(node,ast.Assign) and any(isinstance(name,ast.Name) and name.id==target for name in node.targets) and isinstance(node.value,ast.Dict) and any(isinstance(key,ast.Constant) and key.value==marker for key in node.value.keys)]
    # Runtime also publishes an activity marker; only its result has statsObserved.
    if family=='android-runtime-acceptance':values=[node for node in values if any(isinstance(key,ast.Constant) and key.value=='statsObserved' for key in node.keys)]
    if len(values)!=1:raise AssertionError('producer terminal DTO changed')
    symbols={'correlation':CORRELATION,'op':{'operationId':STAGE},'owner':OWNER,'revision':0,'intent_sha':'c'*64,'package_hash':'a'*64,'parent_correlation':OTHER,'campaign':STAGE,'opening_revision':'0','last_revision':3,'admission_mode':'vpn-authorized','json':json,'expected':json.dumps({'expectedOwner':OWNER,'expectedRevision':0})}
    return eval(compile(ast.Expression(values[0]),'<actual-producer-terminal-dto>','eval'),{'__builtins__':{'int':int}},symbols)


def valid_response(family,method):
    if method=='start':return reply(family,'submitted',identity={'pid':17,'startTicks':123})
    if method=='status':
        terminal=producer_terminal(family)
        extra={'result':terminal} if family=='android-consent-grant-acceptance' else {'identity':{'pid':17,'startTicks':123},'receipt':{'state':'complete','result':terminal,'reason':None}}
    elif family=='android-consent-grant-acceptance':extra={'result':producer_terminal(family),'leaseReleased':True}
    elif family=='android-vpn-permission-reset':extra={'leaseReleased':True}
    else:extra={'result':{'selectedProxy':True,'outboundEvidence':True,'statsObserved':True,'fixtureSocksAndTrafficObserved':True,'admittedMode':'vpn-authorized','restoredEmptyBaseline':True}}
    return reply(family,'complete',**extra)


class ParityResponseProjectionTests(unittest.TestCase):
    def dispatch(self,family,method,value=None,error=None):
        helper=types.SimpleNamespace()
        names=('preflight','start','status','diagnose','diagnose_parser','diagnose_guard','diagnose_retirement_boundary','diagnose_tree','diagnose_locks') if family=='windows-cp117-staged-fixture-retire' else ('start','status','collect')
        for name in names:setattr(helper,name,mock.Mock(return_value=copy.deepcopy(value),side_effect=error))
        helper._STAGE=retire._STAGE;helper._LEASE=retire._LEASE;helper._SERVER=retire._SERVER
        helper._SERVER_CLEANUP_SHA256=retire._SERVER_CLEANUP_SHA256;helper._CREDENTIAL_CLEANUP_SHA256=retire._CREDENTIAL_CLEANUP_SHA256
        module_name='windows_cp117_staged_fixture_retire' if family=='windows-cp117-staged-fixture-retire' else FAMILIES[family]
        original=server._agent_module
        def module(name):return helper if name==module_name else original(name)
        request={} if family=='windows-cp117-staged-fixture-retire' else inputs(family,method)
        with mock.patch.object(server,'_agent_module',side_effect=module):
            result=server._vm_workflow_impl(family+'-'+method,request)
        getattr(helper,method).assert_called_once()
        if family in FAMILIES:self.assertEqual(CORRELATION,result.get('correlationId'))
        return result
    def assert_refused(self,result):
        self.assertIs(result.get('ok'),False)
        self.assertEqual('unknown',result.get('state'))
        self.assertIs(result.get('replayAllowed'),False)
        self.assertIs(result.get('productAction'),False)
        self.assertNotIn(SECRET,json.dumps(result,sort_keys=True))
        self.assertNotIn('privateField',result)
        self.assertNotIn('rawPrivate',result)
    def test_cp117_raw_extra_fields_and_replay_flags_refused_all_three_methods(self):
        for method in ('preflight','start','status'):
            valid={**retire._UNKNOWN,'state':'retired','stageCorrelationId':retire._STAGE,'leaseId':retire._LEASE}
            if method=='preflight':valid.update(state='ready',serverCorrelationId=retire._SERVER,serverCleanupReceiptSha256=retire._SERVER_CLEANUP_SHA256,credentialCleanupReceiptSha256=retire._CREDENTIAL_CLEANUP_SHA256)
            for patch in ({'privateField':SECRET},{'replayAllowed':True},{'correlationId':OTHER},{'leaseId':OTHER},{'stageCorrelationId':OTHER},{'nativeActionAllowed':True},{'productAction':True},{'state':'arbitrary'}):
                with self.subTest(method=method,patch=patch):self.assert_refused(self.dispatch('windows-cp117-staged-fixture-retire',method,{**valid,**patch}))
    def test_android_raw_extra_fields_foreign_correlation_and_state_ok_refused(self):
        for family in FAMILIES:
            for method in ('start','status','collect'):
                valid=valid_response(family,method)
                for patch in ({'privateField':SECRET},{'correlationId':OTHER},{'replayAllowed':True},{'ok':False},{'ok':1},{'state':'unknown','ok':True},{'state':'arbitrary'},{'nativeMutationAllowed':True},{'nativeActionAllowed':True},{'productAction':True}):
                    with self.subTest(family=family,method=method,patch=patch):self.assert_refused(self.dispatch(family,method,{**valid,**patch}))
    def test_android_nested_private_identity_and_result_do_not_cross_boundary(self):
        for family in FAMILIES:
            for method in ('start','status','collect'):
                for extra in ({'identity':{'pid':17,'startTicks':123,'rawPrivate':SECRET}},{'result':{'rawPrivate':SECRET}},{'receipt':{'rawPrivate':SECRET}},{'checkpoint':{'rawPrivate':SECRET}},{'reason':SECRET}):
                    with self.subTest(family=family,method=method,extra=extra):self.assert_refused(self.dispatch(family,method,reply(family,'submitted',**extra)))
    def test_actual_android_helper_base_dto_is_preserved_without_private_evidence(self):
        for family in FAMILIES:
            value=reply(family,'submitted',identity={'pid':17,'startTicks':123})
            result=self.dispatch(family,'start',value)
            self.assertIs(result['ok'],True);self.assertEqual('submitted',result['state']);self.assertEqual(CORRELATION,result['correlationId']);self.assertIs(result['replayAllowed'],False)
            self.assertEqual({'pid':17,'startTicks':123},result['identity'])
    def test_actual_windows_retired_dto_preserved_with_fixed_binding(self):
        value={**retire._UNKNOWN,'state':'retired','stageCorrelationId':retire._STAGE,'leaseId':retire._LEASE}
        for method in ('start','status'):
            result=self.dispatch('windows-cp117-staged-fixture-retire',method,value)
            self.assertIs(result['ok'],True);self.assertEqual('retired',result['state']);self.assertEqual(retire._STAGE,result['stageCorrelationId']);self.assertEqual(retire._LEASE,result['leaseId']);self.assertIs(result['replayAllowed'],False)
    def test_actual_windows_ready_preflight_dto_preserved_with_fixed_bindings(self):
        value={**retire._UNKNOWN,'state':'ready','stageCorrelationId':retire._STAGE,'leaseId':retire._LEASE,'serverCorrelationId':retire._SERVER,'serverCleanupReceiptSha256':retire._SERVER_CLEANUP_SHA256,'credentialCleanupReceiptSha256':retire._CREDENTIAL_CLEANUP_SHA256}
        result=self.dispatch('windows-cp117-staged-fixture-retire','preflight',value)
        self.assertIs(result['ok'],True);self.assertEqual('ready',result['state']);self.assertEqual(retire._SERVER,result['serverCorrelationId']);self.assertEqual(retire._SERVER_CLEANUP_SHA256,result['serverCleanupReceiptSha256'])
    def test_android_helper_exception_text_is_not_public(self):
        for family in FAMILIES:
            for method in ('start','status','collect'):
                with self.subTest(family=family,method=method):self.assert_refused(self.dispatch(family,method,error=ValueError(SECRET)))
    def test_actual_running_and_unknown_producer_observations_are_preserved(self):
        for family in FAMILIES:
            extra={} if family=='android-consent-grant-acceptance' else {'identity':{'pid':17,'startTicks':123}}
            if family=='android-runtime-acceptance':extra['receipt']=None
            # Permission-reset status emits complete/unknown, never running.
            if family!='android-vpn-permission-reset':
                value=reply(family,'running',**extra)
                result=self.dispatch(family,'status',value);self.assertIs(result['ok'],True);self.assertEqual('running',result['state']);self.assertEqual(CORRELATION,result['correlationId'])
                for key,item in extra.items():self.assertEqual(item,result[key])
            value=reply(family,'unknown',reason='missing_worker_receipt',**extra)
            result=self.dispatch(family,'status',value);self.assertIs(result['ok'],False);self.assertEqual('unknown',result['state']);self.assertEqual('missing_worker_receipt',result['reason']);self.assertIs(result['replayAllowed'],False)
    def test_actual_complete_status_terminal_dtos_are_preserved(self):
        for family in FAMILIES:
            terminal=producer_terminal(family)
            extra={'result':terminal} if family=='android-consent-grant-acceptance' else {'identity':{'pid':17,'startTicks':123},'receipt':{'state':'complete','result':terminal,'reason':None}}
            value=reply(family,'complete',**extra)
            result=self.dispatch(family,'status',value);self.assertIs(result['ok'],True);self.assertEqual('complete',result['state']);self.assertEqual(CORRELATION,result['correlationId'])
            for key,item in extra.items():self.assertEqual(item,result[key])
    def test_actual_complete_collect_public_dtos_are_preserved(self):
        extras={'android-consent-grant-acceptance':{'result':producer_terminal('android-consent-grant-acceptance'),'leaseReleased':True},'android-runtime-acceptance':{'result':{'selectedProxy':True,'outboundEvidence':True,'statsObserved':True,'fixtureSocksAndTrafficObserved':True,'admittedMode':'vpn-authorized','restoredEmptyBaseline':True}},'android-vpn-permission-reset':{'leaseReleased':True}}
        for family,extra in extras.items():
            value=reply(family,'complete',**extra);result=self.dispatch(family,'collect',value)
            self.assertIs(result['ok'],True);self.assertEqual('complete',result['state']);self.assertIs(result['replayAllowed'],False)
            for key,item in extra.items():self.assertEqual(item,result[key])
    def test_terminal_private_fields_foreign_ids_and_boolean_type_drift_are_refused(self):
        for family in FAMILIES:
            original=producer_terminal(family)
            key='permissionGranted' if family=='android-consent-grant-acceptance' else 'selectedProxy' if family=='android-runtime-acceptance' else 'permissionAbsent'
            patches=[{'privateField':SECRET},{key:1},{'state':'unknown'}]
            if family=='android-consent-grant-acceptance':patches += [{'correlationId':OTHER},{'operationCode':'OK'},{'runtimeStarted':True}]
            elif family=='android-runtime-acceptance':patches += [{'closingOwner':OTHER},{'closingRevision':0},{'admittedMode':'arbitrary'}]
            else:patches += [{'api':35},{'appOp':'arbitrary'},{'runtimeOff':False}]
            for patch in patches:
                terminal={**original,**patch};extra={'result':terminal} if family=='android-consent-grant-acceptance' else {'identity':{'pid':17,'startTicks':123},'receipt':{'state':'complete','result':terminal,'reason':None}}
                with self.subTest(family=family,patch=patch):self.assert_refused(self.dispatch(family,'status',reply(family,'complete',**extra)))
    def test_grant_unknown_worker_checkpoint_and_cp117_finite_blocked_guard_are_preserved(self):
        value=grant._reply(CORRELATION,'unknown','worker_failed',checkpoint='worker-returned-unknown')
        result=self.dispatch('android-consent-grant-acceptance','status',value)
        self.assertIs(result['ok'],False);self.assertEqual('worker_failed',result['reason']);self.assertEqual('worker-returned-unknown',result['checkpoint'])
        value={**retire._UNKNOWN,'state':'blocked','reason':'native-guard','guard':'unknown'}
        result=self.dispatch('windows-cp117-staged-fixture-retire','preflight',value)
        self.assertIs(result['ok'],False);self.assertEqual('blocked',result['state']);self.assertEqual('native-guard',result['reason']);self.assertEqual('unknown',result['guard'])
    def test_actual_blocked_start_does_not_claim_a_product_effect(self):
        for family in ('android-consent-grant-acceptance','android-vpn-permission-reset'):
            reason='device_lease_active' if family=='android-consent-grant-acceptance' else 'endpoint_lease_active'
            value=reply(family,'blocked',reason=reason)
            result=self.dispatch(family,'start',value)
            self.assertIs(result['ok'],False);self.assertEqual('blocked',result['state']);self.assertEqual(reason,result['reason']);self.assertIs(result['productAction'],False);self.assertIs(result['replayAllowed'],False)
    def test_typed_identity_and_collect_completion_flags_refuse_forgery(self):
        for family in FAMILIES:
            for identity in ({'pid':True,'startTicks':123},{'pid':0,'startTicks':123},{'pid':17,'startTicks':False},{'pid':17,'startTicks':-1}):
                with self.subTest(family=family,identity=identity):self.assert_refused(self.dispatch(family,'start',reply(family,'submitted',identity=identity)))
        for family in ('android-consent-grant-acceptance','android-vpn-permission-reset'):
            extra={'leaseReleased':1}
            if family=='android-consent-grant-acceptance':extra['result']=producer_terminal(family)
            self.assert_refused(self.dispatch(family,'collect',reply(family,'complete',**extra)))


def cp_diagnostics():
    """Exact finite DTO shapes from the six frozen CP117 diagnostic producers."""
    flags={**retire._UNKNOWN,'state':'observed'}
    return {
        'diagnose':{**flags,**{key:'absent' for key in ('stage','owner','reparse','serverTask','serverProcess','listener','credentials','runtime')}},
        'parser':{**flags,'scripts':{key:{'syntax':'valid','runtime':'available'} for key in ('diagnostic','preflight','retire')}},
        'guard-diagnostic':{**flags,'guard':'ACL','category':'PermissionDenied'},
        'boundary':{**flags,'guard':'DELETION_READY','category':'NotSpecified'},
        'tree':{**flags,**{key:'present' for key in ('root','bundle','content','result','serverState','probeEvents')},**{key:0 for key in ('unexpectedRootCount','contentFileCount','probeEntryCount','otherPowerShellCount')},'resultAccess':'exclusive-read','resultReadOnly':'absent'},
        'locks':{**flags,'cause':'low-hresult-32','lockingProcess':'qemu-ga','count':1,'qemuGaExactLocalSystem':True},
    }

class PureProducerProjectionTests(unittest.TestCase):
    def test_actual_producer_terminal_and_collect_schemas_keep_all_public_fields(self):
        from agent_tools.native_parity_response_projection import project
        for family in FAMILIES:
            for method in ('start','status','collect'):
                original=valid_response(family,method);result=project(family+'-'+method,CORRELATION,original)
                for key,item in original.items():self.assertEqual(item,result[key])
                self.assertIs(result['ok'],True);self.assertIs(result['replayAllowed'],False)
    def test_private_extra_foreign_correlation_and_typed_flags_refuse_purely(self):
        from agent_tools.native_parity_response_projection import project
        for family in FAMILIES:
            for method in ('start','status','collect'):
                original=valid_response(family,method)
                for extra in ({'privateField':SECRET},{'correlationId':OTHER},{'replayAllowed':True},{'ok':1}):
                    with self.subTest(family=family,method=method,extra=extra):
                        result=project(family+'-'+method,CORRELATION,{**original,**extra})
                        self.assertIs(result['ok'],False);self.assertEqual('unknown',result['state']);self.assertEqual(CORRELATION,result['correlationId']);self.assertIs(result['replayAllowed'],False);self.assertIs(result['productAction'],False);self.assertNotIn(SECRET,json.dumps(result))

    def test_cp117_all_six_diagnostic_shapes_preserve_public_fields(self):
        from agent_tools.native_parity_response_projection import project
        for method, original in cp_diagnostics().items():
            with self.subTest(method=method):
                result=project('windows-cp117-staged-fixture-retire-'+method,None,original)
                for key,item in original.items():self.assertEqual(item,result[key])
                self.assertIs(result['ok'],True);self.assertIs(result['productAction'],False)
                diagnosed={**retire._UNKNOWN,'state':'diagnosed','phase':{'diagnose':'json-shape','parser':'parser-qga','guard-diagnostic':'guard-source','boundary':'guard-admission','tree':'tree-transport','locks':'lock-shape'}[method]}
                result=project('windows-cp117-staged-fixture-retire-'+method,None,diagnosed)
                for key,item in diagnosed.items():self.assertEqual(item,result[key])
                self.assertIs(result['ok'],True)
    def test_cp117_nested_diagnostic_forgery_and_type_drift_refused(self):
        from agent_tools.native_parity_response_projection import project
        cases=[]
        for method,original in cp_diagnostics().items():
            cases.extend(((method,{**original,'privateField':SECRET}),(method,{**original,'replayAllowed':True})))
        for scripts in ({'diagnostic':{'syntax':'valid','runtime':'available','rawPrivate':SECRET},'preflight':{'syntax':'valid','runtime':'available'},'retire':{'syntax':'valid','runtime':'available'}},{'diagnostic':{'syntax':True,'runtime':'available'},'preflight':{'syntax':'valid','runtime':'available'},'retire':{'syntax':'valid','runtime':'available'}}):
            cases.append(('parser',{**cp_diagnostics()['parser'],'scripts':scripts}))
        for method in ('guard-diagnostic','boundary'):
            for patch in ({'category':SECRET},{'category':1},{'guard':SECRET},{'guard':'unknown'}):cases.append((method,{**cp_diagnostics()[method],**patch}))
        for key in ('unexpectedRootCount','contentFileCount','probeEntryCount','otherPowerShellCount'):
            for value in (True,-1,1001):cases.append(('tree',{**cp_diagnostics()['tree'],key:value}))
        for patch in ({'count':True},{'count':101},{'qemuGaExactLocalSystem':1},{'lockingProcess':'other'},{'count':2},{'cause':SECRET}):cases.append(('locks',{**cp_diagnostics()['locks'],**patch}))
        cases.append(('diagnose',{**cp_diagnostics()['diagnose'],'owner':SECRET}))
        for method,value in cases:
            with self.subTest(method=method,value=value):
                result=project('windows-cp117-staged-fixture-retire-'+method,None,value)
                self.assertIs(result['ok'],False);self.assertEqual('unknown',result['state'])
                self.assertIs(result['replayAllowed'],False);self.assertIs(result['productAction'],False)
                self.assertNotIn(SECRET,json.dumps(result))

if __name__=='__main__':unittest.main()
