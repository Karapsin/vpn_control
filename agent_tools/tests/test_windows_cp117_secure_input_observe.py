import ast,base64,copy,hashlib,inspect,json,tempfile,textwrap,unittest
from pathlib import Path
from unittest.mock import patch
from agent_tools import windows_cp117_secure_input_observe as m
from agent_tools.tests import test_windows_cp117_secure_layout_observe as layout

class SemanticTests(unittest.TestCase):
    def answer(self):
        a=layout.SecureLayoutTests().answer();a['reader']['nonce']=m.NONCE;a['birth']['nonce']=m.NONCE;a['reader']['sourceSha256']=m.CHILD_SHA;a['birth']['sourceSha256']=m.CHILD_SHA
        a['facts']['secureInput']={'ownerPid':1096,'threadId':111,'hkl':'0000000004090409','windowStation':'WinSta0','desktop':'Winlogon','controlType':'Edit','controlName':'Password','className':'Edit','isPassword':True,'keyboardFocus':True,'enabled':True,'offscreen':False,'expectedAccount':True,'capsLock':False,'lengthAvailable':True,'nativeHandleMatches':True,'accountCount':1,'editCount':1,'passwordLength':0,'window':45678,'runtimeId':[42,99]}
        return a
    def terminal(self,answer=None,nonce=None):
        raw=('CP117-READ '+(nonce or m.NONCE)+' '+m.PARENT_SHA+' 456\n'+json.dumps(answer or self.answer())).encode()
        return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
    def test_actual_namespace_accepts_exact_bound_empty_control(self):
        a=self.answer();self.assertEqual(m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456),a)
    def test_filled_control_is_observation_not_empty_authority(self):
        a=self.answer();a['facts']['secureInput']['passwordLength']=3
        s=m.validate_semantic(a);self.assertEqual(s['passwordLength'],3)
        # Future keyboard admission must require exactly0 for typing. This
        # readonly reader never maps observation to an input permission.
        self.assertNotEqual(s['passwordLength'],0)
    def test_unsafe_or_ambiguous_semantics_refused(self):
        for k,v in [('ownerPid',88),('threadId',222),('hkl','0000000004190419'),('desktop','Default'),('windowStation','Foreign'),('controlType','Text'),('controlName','Other'),('className','DirectUIHWND'),('isPassword',False),('keyboardFocus',False),('enabled',False),('offscreen',True),('expectedAccount',False),('capsLock',True),('lengthAvailable',False),('nativeHandleMatches',False),('accountCount',2),('editCount',2),('passwordLength',None),('passwordLength',65),('passwordLength',True),('window',0),('runtimeId',[])]:
            a=self.answer();a['facts']['secureInput'][k]=v
            with self.subTest(k=k,v=v),self.assertRaises(ValueError):m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456)
    def test_actual_uniform_render_shift_does_not_supply_input_authority(self):
        from agent_tools import windows_cp117_recovered_gui_login as old
        # Actual bound4140 wake frame: root viewed the same selected account and
        # empty field. Every crop pixel differed, with median channel delta1.
        actual=('fadd22ddcea97fd97ca6ae82acb087ea9f0134378abf339837c386d73d29dd12','f89252f2826dfdea23e6c5f2d63a3a109a8f4533c4808459ad416b4b75321201','759ea64935a24c67f5750a903348b3e32704db3f939c93e41ef2a4bf32d644db','6962979bc75ba03730ac1e3c9e900a5be389735f1cc7f327e664d63dcd3072db')
        with patch.object(old,'_crop_sha',side_effect=actual),self.assertRaisesRegex(ValueError,'gui-selected-account-field-or-caps'):old._screen_gate(b'retained-source-bound-frame',0,True)
        # This passes only with independent exact OS-control semantics. A
        # screenshot or normalized glyph alone does not substitute for them.
        self.assertEqual(m.validate_semantic(self.answer())['passwordLength'],0)
        a=self.answer();a['facts']['secureInput']['lengthAvailable']=False
        with self.assertRaises(ValueError):m.validate_semantic(a)
    def test_mutated_imported_validator_refused_before_program(self):
        def altered(answer):return None
        with patch.object(m.secure,'validate_focus',altered),self.assertRaisesRegex(ValueError,'semantic-imported-factory'):m.program(layout.fixtures.ScreenTests().record())
    def test_source_nonce_child_and_terminal_timeout_refused(self):
        self.assertIsNone(m.parse_terminal(self.terminal(nonce='old'),m.NONCE,m.PARENT_SHA,456));self.assertIsNone(m.parse_terminal({'exited':False},m.NONCE,m.PARENT_SHA,456))
        a=self.answer();a['reader']['sourceSha256']='0'*64;a['birth']['sourceSha256']='0'*64
        with self.assertRaises(ValueError):m.parse_terminal(self.terminal(a),m.NONCE,m.PARENT_SHA,456)
    def test_generated_child_failure_has_durable_original_binding_before_exit(self):
        _,child,_=m.bodies()
        # Actual492c child errors were printed to an unobserved stdout. The
        # new diagnostic must publish a bound private failure before exit.
        failure=child[child.rfind('}catch{'):]
        self.assertIn("WritePrivate 'failure.json'",failure)
        self.assertIn('reader=$birth',failure)
        for field in ('phase',):
            self.assertIn(field,failure)
        self.assertLess(failure.index("WritePrivate 'failure.json'"),failure.index('exit 1'))
    def test_fixed_source_tails_rejected_before_dispatch(self):
        for name in('_SEMANTIC_CS',):
            with patch.object(m,name,getattr(m,name)+'\nforeign\n'),self.assertRaises(ValueError):m.program(layout.fixtures.ScreenTests().record())
        with patch.object(m.secure,'_PARENT',m.secure._PARENT+'\nStop-Service Foreign\n'),self.assertRaises(ValueError):m.program(layout.fixtures.ScreenTests().record())
    def test_no_text_read_or_input_and_original_watchdog_fences(self):
        parent,child,_=m.bodies();source,_=m.program(layout.fixtures.ScreenTests().record())
        self.assertLess(len(base64.b64encode(child.encode('utf-16le'))),30000);self.assertLess(len(parent.encode()),65536)
        self.assertLess(parent.index("WritePrivate 'attempt.json'"),parent.index('::Suspended('));self.assertLess(parent.index("WritePrivate 'child.json'"),parent.index('::Resume('))
        for forbidden in ('ValuePattern','TextPattern','WM_GETTEXT,','send-key','LogonUser','SetFocus','SetValue'):
            self.assertNotIn(forbidden,m._SEMANTIC_CS+source)
        self.assertIn('0x000E',m._SEMANTIC_CS);self.assertIn('3,500,out count',m._SEMANTIC_CS);self.assertIn('SEMANTIC_STANDARD_PASSWORD_EDIT',m._SEMANTIC_CS)
        self.assertIn('SEMANTIC_INPUT_DRIFT',m._SEMANTIC_CS);self.assertIn('SEMANTIC_CODE_HASH',child);self.assertIn('expired=true',parent)
    def test_consumed_observation_has_no_dispatch(self):
        with tempfile.TemporaryDirectory()as d:
            root=Path(d);(root/'.runtime/parity-evidence'/('windows-cp117-secure-input-'+m.CORRELATION)).mkdir(parents=True)
            with patch.object(m.login.guest,'_stream')as stream:result=m.observe(root)
            self.assertEqual(result['phase'],'semantic-consumed');stream.assert_not_called()

class CompleteGeneratedTests(SemanticTests):
    def execute_flow(self,stale=False,foreign=False):
        # Reuse the reviewed whole transport fixture; execute every generated
        # statement and parser with OS/transport mocks only, no parser patch.
        src=textwrap.dedent(inspect.getsource(layout.CompleteGeneratedFlowTests.execute_flow)).replace('secure.program(record,secure.NONCE)','m.program(record)').replace('secure.CORRELATION','m.CORRELATION').replace('secure.NONCE','m.NONCE')
        ns={'ast':ast,'base64':base64,'json':json,'patch':patch,'secure':m.secure,'m':m};exec(src,ns);return ns['execute_flow'](self,stale,foreign)
    def test_complete_one_submit_same_child_and_positive_semantics(self):
        result,calls,_=self.execute_flow();self.assertEqual(result['state'],'observed');self.assertEqual(result['facts'],self.answer());self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status']);self.assertEqual(calls[1][1],{'pid':456})
        payload=base64.b64decode(calls[0][1]['input-data']);self.assertEqual(payload[4:],m.bodies()[0].encode())
    def test_old_terminal_uses_original80polls_without_resubmit(self):
        result,calls,_=self.execute_flow(stale=True);self.assertEqual(result['state'],'unknown');self.assertEqual(result['phase'],'guest-observation-exhausted');self.assertEqual(len(calls),81);self.assertEqual(sum(op=='guest-exec'for op,_ in calls),1)
    def test_foreign_socket_zero_dispatch(self):
        result,calls,_=self.execute_flow(foreign=True);self.assertEqual(result['state'],'unknown');self.assertEqual(calls,[])
