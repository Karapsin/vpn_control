"""Real private reservation files retain claims across configured host aliases."""
import json
import hashlib
import tempfile
import types
import unittest
from pathlib import Path
from agent_tools import native_environment as current


class ResourceAliasTests(unittest.TestCase):
    def idempotent_before(self):
        directory=Path(__file__).parent/'fixtures/resource_aliases'
        path=directory/'idempotent.before.source';raw=path.read_bytes()
        provenance=json.loads((directory/'idempotent.provenance.json').read_bytes())
        self.assertEqual(provenance['beforeSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._resource_idempotent_alias_before')
        before.__package__='agent_tools';before.__file__=str(path)
        exec(compile(raw,str(path),'exec'),before.__dict__)
        return before

    def request(self,host,environment,**fields):
        return {'hostAlias':host,'environment':environment,'operator':'owned-test',
                'requestedMemoryBytes':8*1024**3,'headroomBytes':4*1024**3,
                'measurement':{'physicalMemoryBytes':16*1024**3,'runningConfiguredMemoryBytes':0,
                               'pressure':'normal','swapUsedBytes':0},**fields}
    def test_original_alias_bypass_red_and_fixed_preserves_old_claim_bytes(self):
        fixture=Path(__file__).parent/'fixtures/resource_aliases/before.source'
        before=types.ModuleType('agent_tools._resource_alias_before');before.__package__='agent_tools';before.__file__=str(fixture)
        exec(compile(fixture.read_bytes(),str(fixture),'exec'),before.__dict__)
        for module,blocked in ((before,False),(current,True)):
            with self.subTest(module=module.__name__),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                module.reserve_environment(root,self.request('old-alias','original'))
                state=root/'.rag_index/native-environments/reservations.json';original=state.read_bytes()
                request=self.request('renamed-alias','new',resourceAliases=['old-alias','renamed-alias'])
                if blocked:
                    with self.assertRaises(module.NativeEnvironmentError):module.reserve_environment(root,request)
                    self.assertEqual(original,state.read_bytes())
                else:
                    self.assertTrue(module.reserve_environment(root,request)['ok'])
                    self.assertEqual(2,len(json.loads(state.read_bytes())['reservations']))
    def test_previous_binding_is_counted_even_by_a_single_alias_legacy_caller(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            current.reserve_environment(root,self.request('renamed-alias','first',resourceAliases=['old-alias','renamed-alias']))
            with self.assertRaises(current.NativeEnvironmentError):current.reserve_environment(root,self.request('old-alias','next'))
    def test_alias_input_cannot_drop_its_host_or_add_duplicate_names(self):
        for aliases in ([],['different'],['same','same'],True,'same'):
            with self.subTest(aliases=aliases),tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(current.NativeEnvironmentError):current.reserve_environment(temporary,self.request('same','test',resourceAliases=aliases))
                self.assertFalse((Path(temporary)/'.rag_index').exists())
    def test_stale_inventory_observation_cannot_overwrite_an_intervening_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            current.reserve_environment(root,self.request('host','first',requestedMemoryBytes=1024**3))
            state=root/'.rag_index/native-environments/reservations.json'
            observed=hashlib.sha256(state.read_bytes()).hexdigest()
            current.reserve_environment(root,self.request('host','second',requestedMemoryBytes=1024**3))
            original=state.read_bytes()
            with self.assertRaises(current.NativeEnvironmentError):
                current.reserve_environment(root,self.request('host','third',requestedMemoryBytes=1024**3,expectedInventorySha256=observed))
            self.assertEqual(original,state.read_bytes())

    def assert_idempotent_alias_claim(self,module):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            original=module.reserve_environment(root,self.request('alias-A','original',
                resourceAliases=['alias-A'],nowUnixMs=1_000,observations=[{
                    'kind':'active-job','source':'original-job','observedAtUnixMs':1_000,
                    'outcome':'unknown'}]))
            module.reserve_environment(root,self.request('unrelated-host','unrelated',
                requestedMemoryBytes=1024**3,nowUnixMs=1_000))
            state=root/'.rag_index/native-environments/reservations.json'
            before=json.loads(state.read_bytes())['reservations']
            again=module.reserve_environment(root,self.request('alias-A','original',
                resourceAliases=['alias-A','alias-B'],nowUnixMs=1_001))
            self.assertTrue(again['idempotent']);self.assertEqual(original['identity'],again['identity'])
            observed=state.read_bytes()
            # A subsequent B-only caller no longer has A in its configuration.
            # The saved equivalence must keep counting A's original 8 GiB claim.
            with self.assertRaises(module.NativeEnvironmentError):
                module.reserve_environment(root,self.request('alias-B','new',nowUnixMs=1_002))
            self.assertEqual(observed,state.read_bytes())
            after=json.loads(observed)['reservations']
            self.assertEqual(['alias-A','alias-B'],after[0]['resourceAliases'])
            self.assertEqual(before[1],after[1])
            for key,value in before[0].items():
                if key!='lastObservation':self.assertEqual(value,after[0][key],key)
            self.assertEqual('unknown',after[0]['activeJob'])
            with self.assertRaises(module.NativeEnvironmentError):
                module.release_environment(root,original['identity'])
            self.assertEqual(observed,state.read_bytes())
            module.reserve_environment(root,self.request('alias-A','original',nowUnixMs=1_003))
            final=json.loads(state.read_bytes())['reservations']
            self.assertEqual(['alias-A','alias-B'],final[0]['resourceAliases'])
            self.assertEqual(before[1],final[1])

    def test_idempotent_alias_observation_retains_claim_after_original_alias_disappears(self):
        self.assert_idempotent_alias_claim(current)

    def test_preserved_idempotent_alias_beforeimage_red_current_green(self):
        with self.assertRaisesRegex(AssertionError,'NativeEnvironmentError not raised'):
            self.assert_idempotent_alias_claim(self.idempotent_before())
        self.assert_idempotent_alias_claim(current)

    def test_idempotent_aliases_are_not_persisted_before_ownership_receipt_and_cas_checks(self):
        changes=({'operator':'foreign'}, {'expectedInventorySha256':'f'*64},
                 {'allocationState':'running','reservationIdentity':{},'runningAllocationMapping':[]},
                 {'observations':[{'kind':'active-job','source':'receipt','observedAtUnixMs':1_000,
                                   'outcome':'invalid'}]})
        for change in changes:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                current.reserve_environment(root,self.request('alias-A','original',nowUnixMs=1_000))
                state=root/'.rag_index/native-environments/reservations.json';before=state.read_bytes()
                with self.assertRaises(current.NativeEnvironmentError):
                    current.reserve_environment(root,self.request('alias-A','original',
                        resourceAliases=['alias-A','alias-B'],nowUnixMs=1_001,**change))
                self.assertEqual(before,state.read_bytes())

    def test_idempotent_alias_union_cannot_exceed_persisted_schema_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            current.reserve_environment(root,self.request('alias-A','original',
                resourceAliases=['alias-A',*['old-'+str(index) for index in range(63)]],nowUnixMs=1_000))
            state=root/'.rag_index/native-environments/reservations.json';before=state.read_bytes()
            with self.assertRaises(current.NativeEnvironmentError):
                current.reserve_environment(root,self.request('alias-A','original',
                    resourceAliases=['alias-A',*['new-'+str(index) for index in range(63)]],nowUnixMs=1_001))
            self.assertEqual(before,state.read_bytes())


if __name__=='__main__':unittest.main()
