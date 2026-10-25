"""Nohash admission and the original pin must refer to the same public bytes."""
import ast
import hashlib
import json
import os
from pathlib import Path
import secrets
import types
import unittest
from unittest import mock

from agent_tools import ssh_tmux_mcp_adapter as adapter
from agent_tools.tests import test_ssh_tmux_mcp_adapter as fixtures

BASE=Path(__file__).with_name('fixtures')/'tmux_private_transport_v2'
BEFORE_SHA='2bfb31a2f9fe871a006c18e8a45c73fc81048a63560e90a689ead595b4027fbd'
OLD_SHA='b61177cf4e9c2fcfaec0fca4aa5974bbc98eec1ca1f96fd4889898dffc19428a'


@unittest.skipUnless(os.name=='posix','held POSIX intent descriptors')
class IntentRaceTests(unittest.TestCase):
    def before(self):
        path=BASE/'ssh_tmux_mcp_adapter.py.before-reread.source';raw=path.read_bytes()
        self.assertEqual(BEFORE_SHA,hashlib.sha256(raw).hexdigest())
        module=types.ModuleType('agent_tools._tmux_before_nofhash_reread')
        module.__file__=str(path);module.__package__='agent_tools'
        exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__)
        return module

    def fixture(self,before=False):
        case=fixtures.AdapterTests();case.setUp();self.addCleanup(case.doCleanups)
        module=self.before()if before else adapter
        if before:
            case.driver.close();case.driver=module.McpTmuxDriver(case.root);self.addCleanup(case.driver.close)
        return case,module

    def mutate(self,path,kind,marker):
        value=json.loads(path.read_bytes());value['privateEcho']=marker.decode()
        if kind=='replace':
            new=path.with_name('replacement');new.write_text(json.dumps(value));new.chmod(0o600);new.replace(path)
        elif kind=='hardlink':os.link(path,path.with_name('extra-link'))
        else:path.write_text(json.dumps(value))

    def test_authentic_whole_saved_reader_gap_mutation_and_replacement_red_current_nohash_green(self):
        for before in (True,False):
            for kind in ('mutate','replace','hardlink'):
                with self.subTest(before=before,kind=kind):
                    case,module=self.fixture(before);self.assertEqual('submitted',case.start()['state'])
                    request=case.fixture.req;path=case.fixture.job()/'tmux-adapter-intent.json'
                    marker=secrets.token_hex(24).encode();seen=[];changed=[];digest=hashlib.sha256
                    name='_public_intent'if before else'_public_intent_data';original=getattr(case.driver,name)
                    def gate(*args,**kwargs):
                        value=original(*args,**kwargs)
                        if not changed:self.mutate(path,kind,marker);changed.append(True)
                        return value
                    def spy(raw=b'',*args,**kwargs):
                        if marker in raw:seen.append(True)
                        return digest(raw,*args,**kwargs)
                    count=len(case.calls)
                    with mock.patch.object(case.driver,name,side_effect=gate),mock.patch.object(hashlib,'sha256',side_effect=spy):
                        with self.assertRaises(ValueError):case.driver._saved(request)
                    self.assertEqual([True],changed)
                    self.assertEqual(before and kind!='hardlink',bool(seen))
                    self.assertEqual(count,len(case.calls))

    def test_authentic_complete_submit_publication_gap_red_current_nohash_before_any_child_green(self):
        for before in (True,False):
            with self.subTest(before=before):
                case,module=self.fixture(before);path=case.fixture.job()/'tmux-adapter-intent.json'
                marker=secrets.token_hex(24).encode();seen=[];changed=[];digest=hashlib.sha256;fsync=os.fsync
                def sync(fd):
                    result=fsync(fd)
                    if path.exists()and not changed:
                        actual=os.fstat(fd);named=path.stat(follow_symlinks=False)
                        if (actual.st_dev,actual.st_ino)==(named.st_dev,named.st_ino):
                            self.mutate(path,'mutate',marker);changed.append(True)
                    return result
                def spy(raw=b'',*args,**kwargs):
                    if marker in raw:seen.append(True)
                    return digest(raw,*args,**kwargs)
                with mock.patch.object(os,'fsync',side_effect=sync),mock.patch.object(hashlib,'sha256',side_effect=spy):
                    self.assertEqual('unknown',case.start()['state'])
                self.assertEqual([True],changed);self.assertEqual(before,bool(seen));self.assertEqual([],case.calls)
                self.assertTrue(path.exists())
                before_calls=len(case.calls);self.assertEqual('unknown',case.start()['state']);self.assertEqual(before_calls,len(case.calls))

    def test_phase_postvalidation_mutation_never_hashes_changed_payload_or_launches(self):
        for kind in ('mutate','replace','hardlink'):
            with self.subTest(kind=kind):
                case,module=self.fixture();self.assertEqual('submitted',case.start()['state'])
                request=case.fixture.req;path=case.fixture.job()/'tmux-adapter-intent.json'
                marker=secrets.token_hex(24).encode();seen=[];changed=[];digest=hashlib.sha256;original=case.driver._public_intent_data
                def gate(*args,**kwargs):
                    value=original(*args,**kwargs)
                    if not changed:self.mutate(path,kind,marker);changed.append(True)
                    return value
                def spy(raw=b'',*args,**kwargs):
                    if marker in raw:seen.append(True)
                    return digest(raw,*args,**kwargs)
                count=len(case.calls)
                with mock.patch.object(case.driver,'_public_intent_data',side_effect=gate),mock.patch.object(hashlib,'sha256',side_effect=spy):
                    with self.assertRaises(ValueError):case.driver._phase(module.old._ACTION,{'request':module.old.purpose(request)},case.fixture.job())
                self.assertEqual([],seen);self.assertEqual(count,len(case.calls))

    def test_submit_action_only_four_intent_boundaries_and_namespace_bindings_differ(self):
        before=(BASE/'ssh_tmux_session_ssh.py.before.source').read_bytes()
        self.assertEqual(OLD_SHA,hashlib.sha256(before).hexdigest())
        old=next(n for n in ast.parse(before).body if isinstance(n,ast.ClassDef)and n.name=='TmuxArchDriver')
        new=next(n for n in ast.parse(Path(adapter.__file__).read_bytes()).body if isinstance(n,ast.ClassDef)and n.name=='McpTmuxDriver')
        counts=[]
        class Normalize(ast.NodeTransformer):
            def visit_Attribute(self,node):
                node=self.generic_visit(node)
                if isinstance(node.value,ast.Name)and node.value.id=='old'and node.attr in ('purpose','_STAGE','_ACTION','__file__'):
                    return ast.Name(id=node.attr,ctx=ast.Load())
                return node
            def visit_Call(self,node):
                node=self.generic_visit(node)
                if isinstance(node.func,ast.Attribute)and isinstance(node.func.value,ast.Name)and node.func.value.id=='self':
                    if node.func.attr=='_publish_public_intent':
                        counts.append('publish');return ast.parse('session.write_once(job / "tmux-adapter-intent.json", session.canonical(original))',mode='eval').body
                    if node.func.attr=='_public_intent_pin':
                        counts.append('read');return ast.parse('session.read(job / "tmux-adapter-intent.json")[1]',mode='eval').body
                return node
        for name in ('submit','_action'):
            original=next(n for n in old.body if isinstance(n,ast.FunctionDef)and n.name==name)
            current=next(n for n in new.body if isinstance(n,ast.FunctionDef)and n.name==name)
            self.assertEqual(ast.dump(original,include_attributes=False),ast.dump(Normalize().visit(current),include_attributes=False))
        self.assertEqual(['publish','read','read','read'],counts)


if __name__=='__main__':unittest.main()
