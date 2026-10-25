"""Actual collected terminal schema versus complete preserved close-audit sources."""
from pathlib import Path
import ast,hashlib,json,tempfile,unittest
HERE=Path(__file__).resolve().parent/'fixtures/ssh_acceptance_close_audit'
PINS={'actual-collected-terminal.json': 'f419f646979b571525f7ad9f272b7bdaab8504602e995b3df85765bd8042b06d', 'audit.before.source': '2cfaa34050718cae07a7c781ac703a57c14e3ad7d8d1b95c73efb74404c8d8b1', 'audit.fixed.source': 'dd71589ff5e81ec957de820e4a014001466f09957c081c3598d6d72c61b7c458'}

def raw(name):
    value=(HERE/name).read_bytes()
    if hashlib.sha256(value).hexdigest()!=PINS[name]:raise ValueError('close_audit_fixture_changed')
    return value

def selected(fixed):
    tree=ast.parse(raw('audit.fixed.source'if fixed else'audit.before.source'))
    read=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='read')
    key='collected_status'if fixed else'terminal'
    index=next(i for i,n in enumerate(tree.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==key for t in n.targets)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='read')
    nodes=tree.body[index:index+(4 if fixed else 2)]
    if not isinstance(nodes[-1],ast.Assert):raise ValueError('close_audit_selected_scope')
    return [read,*nodes]

class ActualCollectionBoundary(unittest.TestCase):
    def test_actual_collected_wrapper_before_red_fixed_green(self):
        body=raw('actual-collected-terminal.json');actual=json.loads(body)
        self.assertEqual(json.loads((HERE/'provenance.json').read_bytes())['pins'],PINS)
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);path=root/'local-owner-direct/collections/counter-612554/terminal.json';path.parent.mkdir(parents=True);path.write_bytes(body)
            env={'HERE':root,'LOCAL':actual['operationId'],'json':json}
            with self.assertRaisesRegex(KeyError,'exitCode'):exec(compile(ast.Module(body=selected(False),type_ignores=[]),'exact-before-audit','exec'),dict(env))
            exec(compile(ast.Module(body=selected(True),type_ignores=[]),'exact-fixed-audit','exec'),env)
            self.assertEqual(env['terminal'],actual['terminal'])
            self.assertEqual(env['terminal']['exitCode'],0)
            self.assertTrue(env['terminal']['streamsClosed'])

if __name__=='__main__':unittest.main()
