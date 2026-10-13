"""Actual local provider and protected journals; no native SSH or live admission.

The original source fixture is public Git 71431848. Remote replies during
fixture seeding are the existing inert declared seam. Retained status is wholly
local positive ENDED evidence; it never proves current native connectivity.
"""
import hashlib,json,os,unittest
from unittest import mock
from agent_tools.tests import test_ssh_direct_ended_source_transition as history
from agent_tools.tests import test_ssh_direct_nested_channel as owner

WRAPPER_BEFORE=history.historical('ssh_fresh_nested_channel.wrapper-before.py.gz','dcb5714fc706482826e5d5238cee19b22c64f06084a5a4e8610c5a53e4fbba68')
MCP_WRAPPER=history.historical('mcp_server.android-wrapper-reviewed.py.gz','9df8d8600b67c6d6161673cc5bfefa77af205b5dfa8adfcd3a52bc1107d52f58')

@unittest.skipUnless(owner.COORDINATOR_CAPABLE,'POSIX protected journal provider required')
class RetainedWrapperTransitionTests(unittest.TestCase):
    def setUp(self):
        self.f=history.ProviderEndedHistoryTests('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        f=self.f
        f.provider_path.write_bytes(WRAPPER_BEFORE);(f.source/'mcp_server.py').write_bytes(history.MCP_CHECKPOINT74)
        f.module=f.load();f.seed()
        f.transition(mcp_body=MCP_WRAPPER)
    def unchanged(self):
        f=self.f;self.assertEqual(f.before,{name:(f.journal/(f.corr+'.'+name+'.json')).read_bytes() for name in f.before})
        f.assert_legacy_unchanged()
    def observe(self):return self.f.invoke('status')
    def refuse(self,*,new_prepare=True):
        f=self.f;before=len(f.calls);fds=len(os.listdir('/dev/fd'));self.assertEqual('unknown',self.observe()['state'])
        self.assertEqual(before,len(f.calls));self.assertEqual(fds,len(os.listdir('/dev/fd')))
        if new_prepare:
            self.assertEqual('unknown',f.invoke(corr=f.new)['state']);self.assertEqual(before,len(f.calls))
        self.assertFalse((f.journal/(f.new+'.intent.json')).exists());f.assert_legacy_unchanged()
    def test_retained_status_reports_only_original_positive_end_without_child_or_writes(self):
        f=self.f;before=len(f.calls);fds=len(os.listdir('/dev/fd'))
        self.assertEqual({'state':'ended','nativeActionAllowed':False,'replayAllowed':False,'correlationId':f.corr},self.observe())
        self.assertEqual(before,len(f.calls));self.assertEqual(fds,len(os.listdir('/dev/fd')));self.unchanged()
    def test_new_prepare_creates_only_new_connection_after_qualified_history(self):
        f=self.f;self.assertEqual('ready',f.invoke(corr=f.new)['state']);self.unchanged()
        self.assertEqual(['prepare','status','prepare'],[c[6]for c in f.calls])
        self.assertEqual(f.new,f.row_for(f.new,'intent')['correlationId'])
    def test_existing_prepare_cannot_renew_original_after_source_transition(self):
        f=self.f;before=len(f.calls);self.assertEqual('unknown',f.invoke()['state']);self.assertEqual(before,len(f.calls));self.unchanged()
    def test_no_selection_or_route_authority_from_retained_ended_evidence(self):
        from agent_tools import ssh_direct_nested_channel as direct
        f=self.f;before=len(f.calls)
        with self.assertRaises(ValueError):direct.route_options(f.root,'archlinux',f.corr,hashlib.sha256(f.before['ready']).hexdigest())
        self.assertEqual(before,len(f.calls));self.unchanged()
    def test_current_credentials_inventory_drift_refuses(self):
        f=self.f;f.owner.f.f.config['hosts']['archlinux']['password']='inert changed credential';f.owner.f.f.write_config();self.refuse(new_prepare=False)
    def test_future_mcp_source_bytes_refuse(self):
        f=self.f;(f.source/'mcp_server.py').write_bytes(MCP_WRAPPER+b'\n# unreviewed future wrapper\n');self.refuse()
    def test_current_other_source_bytes_refuse(self):
        f=self.f;p=f.source/'ssh_transport.py';p.write_bytes(p.read_bytes()+b'\n# future transport\n');self.refuse()
    def test_closing_terminal_mutation_refuses_without_child(self):
        from agent_tools import private_inventory_lock as private
        f=self.f;real=private.Snapshot.guard;seen=[]
        def drift(snapshot):
            real(snapshot)
            if snapshot.name==f.corr+'.ready.json' and not seen:
                seen.append(True);p=f.journal/(f.corr+'.terminal.json');p.write_bytes(p.read_bytes()+b'\n')
        with mock.patch.object(private.Snapshot,'guard',drift):self.refuse(new_prepare=False)
    def test_unobserved_predecessor_mcp_combination_refuses(self):
        f=self.f;f.mutate_intent(lambda v:v['directSourcePins'].__setitem__('mcp_server.py',hashlib.sha256(MCP_WRAPPER).hexdigest()));self.refuse()
    def test_missing_original_ready_refuses(self):
        f=self.f;(f.journal/(f.corr+'.ready.json')).unlink();self.refuse()
    def test_malformed_terminal_refuses(self):
        f=self.f;(f.journal/(f.corr+'.terminal.json')).write_bytes(b'{');self.refuse()
    def test_duplicate_terminal_fields_refuse(self):
        f=self.f;p=f.journal/(f.corr+'.terminal.json');body=p.read_bytes();p.write_bytes(b'{"state":"ended",'+body[1:]);self.refuse()
    def negative(self,kind):
        f=self.f
        # Reuse the existing complete-provider causal mutations; they target
        # the journal/typed intent, never simulate an admission return value.
        f.seed=lambda:None;f.transition=lambda **kw:None
        f.refuse=self.refuse
        f.negative(kind)

for name in history.NEGATIVE:
    def test(self,name=name):self.negative(name)
    setattr(RetainedWrapperTransitionTests,'test_refuses_'+name,test)

@unittest.skipUnless(owner.COORDINATOR_CAPABLE,'POSIX protected journal provider required')
class ReviewedWrapperHistoryPopulationTests(unittest.TestCase):
    def admit(self,kind):
        f=history.Checkpoint74EndedPopulationTests('runTest');f.setUp();self.addCleanup(f.doCleanups)
        f.seed_original(kind);f.transition(mcp=MCP_WRAPPER)
        self.assertEqual('ready',f.f.invoke(corr=f.f.new)['state'])
        self.assertEqual(f.f.before,{name:(f.f.journal/(f.f.corr+'.'+name+'.json')).read_bytes()for name in f.f.before})
        self.assertEqual(['prepare','status','prepare'],[c[6]for c in f.f.calls]);f.f.assert_legacy_unchanged()
    def test_b957_reviewed_population_to_wrapper(self):self.admit('b957')
    def test_f569_reviewed_population_to_wrapper(self):self.admit('f569')
    def test_b1a_reviewed_population_to_wrapper(self):self.admit('b1a')
    def test_a78_reviewed_population_to_wrapper(self):self.admit('a78')
