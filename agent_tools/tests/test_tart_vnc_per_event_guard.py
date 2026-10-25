"""Per-secret-event guard regression: complete before/current source, TCP only.

All credentials are synthetic local fixture bytes. No provider/VM/profile or
user credential is opened; no input capability/native acceptance is granted.
"""
from pathlib import Path
import contextlib,hashlib,importlib.util,json,os,sys,tempfile,time,traceback,unittest
from uuid import uuid4
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint
HERE=Path(__file__).absolute().parent/"fixtures"/"tart_vnc_per_event_guard"
SOURCES={'before': ('before.source', '2938db527eae5879ff7a7fcfde1801e447727edd57d41868f95ac8ea45cbf4c0'), 'current': ('current.source', 'e217651bf4a277133771c6a75c5d7ded2c3d60760092bc757058d20aa294ca68')}
PROVENANCE=json.loads((HERE/'provenance.json').read_bytes())

def load(name):
    filename,expected=SOURCES[name]
    path=HERE/filename
    raw=path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==expected
    assert PROVENANCE['roles'][name]['sha256']==expected
    assert PROVENANCE['roles'][name]['path']==filename
    assert PROVENANCE['roles'][name]['bytes']==len(raw)
    spec=importlib.util.spec_from_loader('agent_tools._review_vnc_'+name,loader=None)
    m=importlib.util.module_from_spec(spec);m.__file__=str(path);sys.modules[spec.name]=m
    exec(compile(raw,str(path),'exec',dont_inherit=True),m.__dict__)
    return m

OLD=load('before');NEW=load('current')

@contextlib.contextmanager
def fd(body):
    reader,writer=os.pipe()
    try:
        os.write(writer,body);os.close(writer);writer=None
        yield reader
    finally:
        if writer is not None:os.close(writer)
        os.close(reader)


@unittest.skipUnless(os.name=='posix','protected FD/journal source protocol requires POSIX')
class PerEvent(unittest.TestCase):
    def run_session(self,module,*,text=b'Aa',stop_after=None,raise_initial=False,native_fail=False,public=False,budget=.5,slow_guard=False):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as td:
            root=Path(td);root.chmod(0o700);endpoint=RfbEndpoint();op=str(uuid4());journal=module.SecretInputJournal(root,str(uuid4()))
            counts={'extra':0,'native':0};changed=False;result=None;reason=None;trace='';session=None
            def probe():
                nonlocal changed
                if stop_after is not None and len(endpoint.events)+1>=stop_after:changed=True
                return any(root.iterdir())
            endpoint.receipt_probe=probe
            def native():
                counts['native']+=1
                if native_fail and changed:raise RuntimeError('synthetic-private-canary')
            def extra():
                counts['extra']+=1
                # Await delivery of the PREVIOUS event only, to reproduce an
                # actual account/ROI change at the server before the next event.
                if counts['extra']>2:endpoint.wait_events(counts['extra']-2)
                if raise_initial or changed:raise RuntimeError('synthetic-private-canary')
                if slow_guard and counts['extra']==2:time.sleep(budget+.05)
            try:
                with fd(b'rfb-only-fixture') as auth:
                    with module.ProtectedVncSession(port=endpoint.port,credential_fd=auth,guard=native,timeout=budget) as session:
                        if public:
                            session.type_public(text.decode('ascii'));result='public'
                        else:
                            with fd(text) as secret:result=session.type_secret_from_fd(secret,operation_id=op,journal=journal,guard=extra)
            except module.VncBlocked as error:
                reason=str(error);trace=''.join(traceback.format_exception(error))
            finally:
                # Wait the finite expected send count or EOF, then positively
                # close only this retained local server/thread/socket context.
                if result is not None:endpoint.wait_events(sum(4 if 65<=v<=90 or chr(v) in module._SHIFTED_US else 2 for v in text))
                endpoint.close()
                self.assertFalse(endpoint.thread.is_alive())
                self.assertTrue(endpoint.listener.fileno()==-1)
                if endpoint.connection is not None:self.assertEqual(endpoint.connection.fileno(),-1)
                if session is not None:self.assertIsNone(session._socket)
            receipts=[json.loads(p.read_bytes()) for p in root.iterdir()]
            return {'events':endpoint.events,'result':result,'reason':reason,'trace':trace,'counts':counts,'receipts':receipts,
                    'rfbAuthResponseBytes':len(endpoint.responses[0]) if endpoint.responses else 0}

    def test_complete_before_red_current_green_after_account_roi_changes_on_first_event(self):
        old=self.run_session(OLD,stop_after=1);new=self.run_session(NEW,stop_after=1)
        # Same account guard and actual server change; authentic2938 continues.
        self.assertGreater(len(old['events']),1)
        self.assertIsNotNone(old['result'])
        with self.assertRaises(AssertionError):self.assertEqual(len(old['events']),1)
        self.assertEqual(new['events'],[('key',1,0xFFE1)])
        self.assertEqual(new['reason'],'vnc_binding_changed')
        self.assertEqual(len(new['receipts']),1)
        self.assertNotIn('synthetic-private-canary',new['trace'])

    def test_every_shifted_or_unshifted_event_checks_extra_guard(self):
        for text,total in ((b'ab',4),(b'A!',8)):
            result=self.run_session(NEW,text=text)
            self.assertEqual(len(result['events']),total)
            self.assertEqual(result['counts']['extra'],1+total)
            self.assertGreaterEqual(result['counts']['native'],total)
            self.assertIsNotNone(result['result'])
            self.assertEqual(result['rfbAuthResponseBytes'],16)

    def test_each_shift_down_keydown_keyup_shiftup_boundary_can_stop_without_auto_release(self):
        for count in range(1,8):
            result=self.run_session(NEW,text=b'A!',stop_after=count)
            self.assertEqual(len(result['events']),count)
            self.assertEqual(result['reason'],'vnc_binding_changed')
            self.assertEqual(len(result['receipts']),1)

    def test_pre_group_extra_guard_refusal_has_no_journal_or_input(self):
        result=self.run_session(NEW,raise_initial=True)
        self.assertEqual(result['events'],[]);self.assertEqual(result['receipts'],[])
        self.assertNotIn('synthetic-private-canary',result['trace'])

    def test_native_guard_still_stops_without_auto_keyup(self):
        result=self.run_session(NEW,stop_after=1,native_fail=True)
        self.assertEqual(result['events'],[('key',1,0xFFE1)])
        self.assertEqual(result['reason'],'vnc_binding_changed')
        self.assertNotIn('synthetic-private-canary',result['trace'])

    def test_complete_fd_invalid_suffix_refuses_before_admission_or_input(self):
        for payload in (b'ok\x00suffix',b'\xff',b'x'*1025):
            result=self.run_session(NEW,text=payload)
            self.assertEqual(result['events'],[]);self.assertEqual(result['receipts'],[])
            self.assertEqual(result['counts']['extra'],0)

    def test_public_text_keeps_existing_behavior_without_extra_recipient_guard(self):
        old=self.run_session(OLD,public=True);new=self.run_session(NEW,public=True)
        self.assertEqual(new['events'],old['events'])
        self.assertEqual(new['counts']['extra'],0);self.assertEqual(new['receipts'],[])
        self.assertEqual(new['rfbAuthResponseBytes'],16)

    def test_guard_cost_consumes_original_group_deadline_not_a_fresh_per_event_budget(self):
        start=time.monotonic();result=self.run_session(NEW,text=b'a',budget=.25,slow_guard=True)
        self.assertLess(time.monotonic()-start,2)
        self.assertEqual(result['events'],[]);self.assertEqual(result['reason'],'vnc_deadline')
        self.assertEqual(len(result['receipts']),1)

    def test_once_journal_rejects_second_group_without_reopening_guard_or_input(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as td:
            root=Path(td);root.chmod(0o700);journal=NEW.SecretInputJournal(root,str(uuid4()));operation=str(uuid4());journal.begin(operation)
            endpoint=RfbEndpoint()
            try:
                with fd(b'rfb-only-fixture') as auth,fd(b'fixture') as secret:
                    with NEW.ProtectedVncSession(port=endpoint.port,credential_fd=auth,guard=lambda:None,timeout=.5) as session:
                        with self.assertRaisesRegex(NEW.VncBlocked,'vnc_secret_original_unknown'):
                            session.type_secret_from_fd(secret,operation_id=operation,journal=journal,guard=lambda:None)
                self.assertEqual(endpoint.events,[])
                self.assertEqual(len(list(root.iterdir())),1)
            finally:endpoint.close();self.assertFalse(endpoint.thread.is_alive())

    def test_minimal_complete_source_edit_and_public_return_path_unchanged(self):
        old=(HERE/'before.source').read_text();new=(HERE/'current.source').read_text()
        # Whole public key()/mouse()/type_public() and low-level _key() bytes
        # remain exact. Return stays the separately guarded U/native phase.
        for start,end in (('    def _key(', '    @staticmethod\n    def _text('),('    def type_public(', '    def type_secret_from_fd(')):
            self.assertEqual(old[old.index(start):old.index(end,old.index(start))],new[new.index(start):new.index(end,new.index(start))])
        self.assertIn('self._character(char, deadline, guard)',new)
        character=new[new.index('    def _character('):new.index('    def type_public(')]
        self.assertEqual(character.count('input_guard=guard, mutation=True)'),2)

if __name__=='__main__':unittest.main()
