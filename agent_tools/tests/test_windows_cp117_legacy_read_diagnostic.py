import ast
import base64
import hashlib
import json
import types
import unittest
from agent_tools import windows_cp117_legacy_read_diagnostic as d


def actual_query_namespace(delegate):
    # Actual unchanged parser/query functions, mocking transport only.
    tree=ast.parse(d.history._REMOTE)
    wanted={'unique','load','stderr_phase','query','decode'}
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in wanted]
    import xml.etree.ElementTree as ET
    ns={'call':delegate,'sock':'fixed.sock','base64':base64,'json':json,'ET':ET,'time':types.SimpleNamespace(sleep=lambda value:None),'phase':'guard','hashlib':hashlib}
    exec(compile(ast.Module(body=functions,type_ignores=[]),'actual-historical-query','exec'),ns)
    return ns


class LegacyReadDiagnosticTests(unittest.TestCase):
    def request(self):return {'diagnosticId':'11111111-1111-4111-8111-111111111111','generation':list(d.history._GENERATION),'catalog':d.catalog()}
    def test_actual_malformed_query_keeps_raw_before_same_json_failure(self):
        calls=[];events=[];raw=b'not-json-but-original-evidence'
        def delegate(sock,operation,args):
            calls.append((operation,args))
            return {'pid':456}if operation=='guest-exec'else {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
        old=actual_query_namespace(delegate)
        with self.assertRaises(json.JSONDecodeError):old['query'](d.catalog()[0])
        self.assertEqual(old['phase'],'output-json')
        self.assertNotIn('_legacy_events',old)  # Original discarded exact output.
        ns=actual_query_namespace(delegate);ns['_legacy_save']=events.append
        exec(d.trace_support(self.request()),ns)
        with self.assertRaises(json.JSONDecodeError):ns['query'](d.catalog()[0])
        self.assertEqual(ns['phase'],'output-json')
        terminal=[e for e in events if e['kind']=='terminal']
        self.assertEqual(len(terminal),1,'exact failing bytes must survive before parser throws')
        self.assertEqual(base64.b64decode(terminal[0]['output']['out-data']['prefix']),raw)
        self.assertEqual(terminal[0]['childPid'],456)
        self.assertEqual(calls[-1],('guest-exec-status',{'pid':456}))

    def test_two_actual_queries_keep_exact_sources_and_return_values(self):
        events=[];calls=[];responses=[{'version':1,'code':'OK'},{'task':'absent'}]
        def delegate(sock,operation,args):
            calls.append((operation,args))
            if operation=='guest-exec':return {'pid':456+len([x for x in calls if x[0]=='guest-exec'])}
            return {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(responses.pop(0)).encode()).decode()}
        ns=actual_query_namespace(delegate);ns['_legacy_save']=events.append;exec(d.trace_support(self.request()),ns)
        self.assertEqual(ns['query'](d.catalog()[0]),(0,{'version':1,'code':'OK'}))
        self.assertEqual(ns['query'](d.catalog()[1]),(0,{'task':'absent'}))
        self.assertEqual([x[0]for x in calls],['guest-exec','guest-exec-status']*2)
        with self.assertRaisesRegex(ValueError,'fixed-legacy-source'):ns['query'](d.catalog()[1])
        self.assertEqual(len(calls),4)
        self.assertEqual([e['kind']for e in events],['submitted','poll','terminal']*2)

    def test_actual_40_live_polls_exhaust_without_new_submission(self):
        import time
        events=[];calls=[]
        def delegate(sock,operation,args):
            calls.append((operation,args));return {'pid':456}if operation=='guest-exec'else {'exited':False}
        ns=actual_query_namespace(delegate);ns['_legacy_save']=events.append;exec(d.trace_support(self.request()),ns)
        ns['time']=types.SimpleNamespace(sleep=lambda seconds:None,monotonic=time.monotonic)
        with self.assertRaises(ValueError):ns['query'](d.catalog()[0])
        self.assertEqual(len(calls),41)
        self.assertEqual(sum(x[0]=='guest-exec'for x in calls),1)
        self.assertEqual([e['poll']for e in events if e['kind']=='poll'],list(range(1,41)))
        with self.assertRaisesRegex(ValueError,'fixed-legacy-status'):ns['call']('fixed.sock','guest-exec-status',{'pid':456})
        self.assertEqual(len(calls),41)

    def test_wrong_source_and_wrong_child_do_not_query(self):
        calls=[];events=[]
        def delegate(sock,operation,args):calls.append((operation,args));return {'pid':456}
        ns=actual_query_namespace(delegate);ns['_legacy_save']=events.append;exec(d.trace_support(self.request()),ns)
        with self.assertRaisesRegex(ValueError,'fixed-legacy-source'):ns['query'](d.catalog()[1])
        self.assertEqual(calls,[])
        ns['call']('fixed.sock','guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',d.catalog()[0]],'capture-output':True})
        with self.assertRaisesRegex(ValueError,'fixed-legacy-status'):ns['call']('fixed.sock','guest-exec-status',{'pid':999})
        self.assertEqual(len(calls),1)

    def test_program_recognizes_only_frozen_reader_and_fixed_inputs(self):
        generation=d.history._GENERATION
        args=('/fixed/private/root',generation[0],d._CORRELATION,*map(str,generation[1:4]),generation[4],'{}',d.catalog()[1])
        source,request=d.program(args,self.request()['diagnosticId'])
        self.assertTrue(source.endswith(d.history._REMOTE[len(d.history.base._QGA):]))
        self.assertEqual(request['inputsSha256'],hashlib.sha256(json.dumps(list(args),separators=(',',':')).encode()).hexdigest())
        changed=list(args);changed[-1]=base64.b64encode('Write-Output anything'.encode('utf-16le')).decode()
        with self.assertRaisesRegex(ValueError,'fixed-inputs'):d.program(changed,self.request()['diagnosticId'])

    def test_changed_historical_proof_tail_is_not_an_executable_whitelist(self):
        from unittest import mock
        with mock.patch.object(d.history,'_PS',d.history._PS+'\nStop-Service ForeignService\n'):
            with self.assertRaisesRegex(ValueError,'proof-source'):d.catalog()

    def test_changed_historical_parser_is_rejected_before_catalog(self):
        from unittest import mock
        with mock.patch.object(d.history,'_PARSER',d.history._PARSER+'\nStop-Service ForeignService\n'):
            with self.assertRaisesRegex(ValueError,'parser-source'):d.catalog()

    def test_remote_gzip_header_keeps_original_pinned_parser_factory(self):
        from unittest import mock
        import gzip
        calls=[];events=[];original=gzip.compress
        def alternate(raw,mtime=0):
            packed=bytearray(original(raw,mtime=mtime));packed[9]=3 if packed[9]!=3 else 255;return bytes(packed)
        proof=base64.b64decode(d.catalog()[1])
        parser=d.history._PARSER.replace('@PACKED@',base64.b64encode(alternate(proof,mtime=0)).decode())
        encoded=base64.b64encode(parser.encode('utf-16le')).decode()
        self.assertNotEqual(encoded,d.catalog()[0])
        request=self.request();support=d.trace_support(request)
        def delegate(sock,operation,args):
            calls.append(operation)
            return {'pid':456}if operation=='guest-exec'else {'exited':True,'exitcode':0,'out-data':base64.b64encode(b'{"version":1,"code":"OK"}').decode()}
        ns=actual_query_namespace(delegate);ns['_legacy_save']=events.append
        with mock.patch.object(gzip,'compress',side_effect=alternate):exec(support,ns)
        self.assertEqual(ns['query'](encoded),(0,{'version':1,'code':'OK'}))
        self.assertEqual(calls,['guest-exec','guest-exec-status'])
