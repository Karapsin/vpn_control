"""Reject diagnostic module bindings that overwrite inherited callables."""
from __future__ import annotations
import ast

def compose_readonly_diagnostic(inherited: str, diagnostic: str) -> str:
    """Compose source only after checking the diagnostic's module namespace.

    Try/loop bodies execute in that namespace. Function and class bodies have
    separate scopes and are not treated as module assignment targets.
    """
    prefix=ast.parse(inherited);body=ast.parse(diagnostic)
    callables={node.name for node in prefix.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
    class ModuleBindings(ast.NodeVisitor):
        def __init__(self):self.names=set()
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Store):self.names.add(node.id)
        def visit_FunctionDef(self,node):self.names.add(node.name)
        visit_AsyncFunctionDef=visit_FunctionDef
        def visit_ClassDef(self,node):self.names.add(node.name)
        def visit_Lambda(self,node):pass
        def visit_ExceptHandler(self,node):
            if node.name:self.names.add(node.name)
            self.generic_visit(node)
        def visit_MatchAs(self,node):
            if node.name:self.names.add(node.name)
            self.generic_visit(node)
        def visit_MatchStar(self,node):
            if node.name:self.names.add(node.name)
        def visit_MatchMapping(self,node):
            if node.rest:self.names.add(node.rest)
            self.generic_visit(node)
        def visit_Import(self,node):
            self.names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)
        def visit_ImportFrom(self,node):
            self.names.update(alias.asname or alias.name for alias in node.names)
    bindings=ModuleBindings();bindings.visit(body)
    if bindings.names & callables:
        raise ValueError('diagnostic_callable_shadowed')
    result=inherited+'\n'+diagnostic;ast.parse(result);return result
