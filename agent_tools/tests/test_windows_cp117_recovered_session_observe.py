import base64,hashlib,json,unittest
from unittest.mock import patch
from agent_tools import windows_cp117_recovered_guest_observe as guest
from agent_tools import windows_cp117_recovered_session_observe as session

class SessionTests(unittest.TestCase):
    nonce='45efb990-1d58-467f-8e45-4b21bf15c9c6'
    sha='5a5f1b7632c6dfb0a130b7b8cac6d96263c2407c2f5bebfd3785490428fb22b2'
    def facts(self,explorer=False):
        return dict(version=1,accountCount=1,accounts=[dict(expectedSid=True,expectedName=True,disabled=False,lockedOut=False,localAccount=True)],processCount=1,processes=[dict(kind='explorer'if explorer else'logonui',pid=34,parentPid=12,sessionId=2,startedAtUtc='2026-10-03T16:00:00Z',ownerKnown=True,expectedUser=explorer)])
    def terminal(self,facts):
        raw=('CP117-READ %s %s 456\n'%(self.nonce,self.sha)+json.dumps(facts)).encode()
        return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
    def test_fixed_catalog_routes_session_body(self):
        encoded,sha=guest.encoded_read(self.nonce,observation='session')
        self.assertEqual(sha,self.sha);self.assertTrue(base64.b64decode(encoded).decode('utf-16le').endswith(session.BODY))
    def test_body_exact_digest(self):self.assertEqual(hashlib.sha256(session.BODY.encode('utf-16le')).hexdigest(),self.sha)
    def test_login_screen_distinguished(self):
        facts=session.parse_terminal(self.terminal(self.facts()),self.nonce,self.sha,456)
        self.assertEqual(facts['processes'][0]['kind'],'logonui');self.assertFalse(facts['processes'][0]['expectedUser'])
    def test_expected_user_other_session_observed(self):
        facts=session.parse_terminal(self.terminal(self.facts(True)),self.nonce,self.sha,456)
        self.assertTrue(facts['processes'][0]['expectedUser']);self.assertEqual(facts['processes'][0]['sessionId'],2)
    def test_stale_terminal_rejected(self):self.assertIsNone(session.parse_terminal(self.terminal(self.facts()),'old',self.sha,456))
    def test_account_and_process_shapes_fail_closed(self):
        for mutate in (lambda f:f.update(accountCount=2),lambda f:f['accounts'][0].update(expectedSid='yes'),lambda f:f['processes'][0].update(expectedUser=True,ownerKnown=False),lambda f:f['processes'][0].update(kind='foreign')):
            facts=self.facts();mutate(facts)
            with self.assertRaises(ValueError):session.parse_terminal(self.terminal(facts),self.nonce,self.sha,456)
    def test_session_factory_tail_refused(self):
        with patch.object(session,'BODY',session.BODY+'\nStop-Service ForeignService'):
            with self.assertRaisesRegex(ValueError,'fixed-readonly-body'):guest.encoded_read(self.nonce,observation='session')
    def test_arbitrary_selector_refused(self):
        with self.assertRaises(ValueError):guest.encoded_read(self.nonce,observation='arbitrary')

    def test_actual_generated_session_parser_accepts_schema_readiness_rejects(self):
        import ast
        record={'request':{'recipeSha256':guest.recovery._digest(guest.recovery.recipe())},'result':{'state':'running','sockets':{}},'authority':[]}
        source,sha=guest.program(record,'diag',self.nonce,observation='session')
        with self.assertRaisesRegex(ValueError,'guest-schema'):guest.parse_terminal(self.terminal(self.facts(True)),self.nonce,self.sha,456)
        tree=ast.parse(source);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='parse_terminal')
        ns={'json':json,'base64':base64};exec(compile(ast.Module(body=[node],type_ignores=[]),'actual-session-parser','exec'),ns)
        self.assertEqual(ns['parse_terminal'](self.terminal(self.facts(True)),self.nonce,sha,456),self.facts(True))
        self.assertEqual(source.count("'guest-exec',"),1)
        self.assertIn('range(80)',source)
    def test_mutated_session_parser_factory_refused(self):
        record={'request':{'recipeSha256':guest.recovery._digest(guest.recovery.recipe())},'result':{'state':'running','sockets':{}},'authority':[]}
        def foreign(value,nonce,sha,pid):return {'admitted':True}
        with patch.object(session,'parse_terminal',foreign):
            with self.assertRaisesRegex(ValueError,'session-parser-source'):guest.program(record,'diag',self.nonce,observation='session')
