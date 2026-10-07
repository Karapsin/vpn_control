"""Routine causal coverage for the measured diagnostic command-record collision."""
import ast
import json
import unittest
from agent_tools import android_endpoint_admission as endpoint
from agent_tools.android_diagnostic_composition import compose_readonly_diagnostic

class PostDiagnosticCompositionTest(unittest.TestCase):
    def inherited(self):
        return endpoint._REMOTE.split("\nif action=='start':",1)[0]
    def test_measured_try_scope_command_record_collision_rejected_before_execution(self):
        diagnostic="try:\n command=json.loads(private(commandpath,16384))\nfinally:\n pass\n"
        # Reproduce the causal runtime failure with the actual inherited adb_call.
        node=next(n for n in ast.parse(self.inherited()).body if isinstance(n,ast.FunctionDef) and n.name=='adb_call')
        scope={'command':lambda *_:'0','adb':'adb','serial':'inert','json':json,'private':lambda *_:b'{}','commandpath':'inert'}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-inherited-adb-call>','exec'),scope)
        exec(diagnostic,scope)
        with self.assertRaises(TypeError):scope['adb_call']('shell','-T','id','-u')
        with self.assertRaisesRegex(ValueError,'diagnostic_callable_shadowed'):
            compose_readonly_diagnostic(self.inherited(),diagnostic)
    def test_renamed_record_preserves_actual_inherited_callable(self):
        program=compose_readonly_diagnostic(self.inherited(),"try:\n command_record=json.loads(private(commandpath,16384))\nfinally:\n pass\n")
        tree=ast.parse(program);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='adb_call');record=tree.body[-1]
        calls=[];scope={'command':lambda *args:calls.append(args) or '0','adb':'adb','serial':'inert','json':json,'private':lambda *_:b'{}','commandpath':'inert'}
        exec(compile(ast.Module(body=[node,record],type_ignores=[]),'<actual-composed-record>','exec'),scope)
        self.assertEqual('0',scope['adb_call']('shell','-T','id','-u'));self.assertEqual({},scope['command_record']);self.assertEqual(1,len(calls))
    def test_nested_module_scopes_import_and_definition_collisions_reject(self):
        for diagnostic in ('if True:\n command={}\n','for command in []:\n pass\n','from json import loads as command\n','def command():\n pass\n'):
            with self.subTest(diagnostic=diagnostic),self.assertRaises(ValueError):compose_readonly_diagnostic(self.inherited(),diagnostic)
    def test_local_function_record_name_does_not_shadow_inherited_global(self):
        compose_readonly_diagnostic(self.inherited(),'def diagnostic():\n command={}\n return command\n')
    def test_exception_and_match_string_bindings_cannot_replace_inherited_callable(self):
        cases=('try:\n raise ValueError()\nexcept ValueError as command:\n pass\n',
               'match {}:\n case command:\n  pass\n',
               'match {}:\n case {**command}:\n  pass\n',
               'match []:\n case [*command]:\n  pass\n')
        for diagnostic in cases:
            with self.subTest(diagnostic=diagnostic),self.assertRaisesRegex(ValueError,'diagnostic_callable_shadowed'):
                compose_readonly_diagnostic(self.inherited(),diagnostic)
    def test_two_reader_pid_raw_paths_have_equal_actual_frozen_parser_facts(self):
        from agent_tools.tests.test_android_owned_endpoint_bind_recovery import trees,PLAN
        from agent_tools import android_owned_endpoint_bind_recovery as recovery
        first,stock=trees(False);second=first.replace('/proc/123/fd/3/','/proc/456/fd/3/')
        self.assertNotEqual(first,second)
        self.assertEqual(recovery._parse_tree(first,PLAN,stock,False,True),recovery._parse_tree(second,PLAN,stock,False,True))
