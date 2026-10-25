"""Every pure dispatcher refusal before the first effect is fenced before readiness by its exact predicate."""
import ast
import builtins
import collections
import contextlib
import copy
import json
import os
from pathlib import Path
import re
from re import _constants as RE_OPS, _parser as RE_PARSER
import sys
import threading
import unittest
from unittest import mock
from agent_tools import mcp_server as server, tool_action_policy as policy
from agent_tools import (windows_credential_probe_ssh, windows_credential_recovery_ssh, windows_msi_owner_relaunch,
                         windows_msi_stale_lock_reconcile, windows_msi_stale_lock_recovery, windows_update_fixture_stage_recovery)

SAFE = ('isinstance', 'set', 'frozenset', 'type', 'len', 'any', 'all', 'str', 'int', 'dict', 'bool', 'tuple', 'list', 'sorted')
TYPES = {'str', 'int', 'dict', 'bool', 'list', 'set', 'tuple', 'float', 'frozenset', 'bytes', 'object', 'type'}
METHODS = {'get', 'keys', 'values', 'items', 'strip', 'startswith', 'endswith', 'removeprefix', 'rsplit', 'split', 'issubset',
           'fullmatch', 'match', 'search', 'is_absolute'}
LEXICAL = {'Path'} if server.Path is Path else set()  # Building a path object reads no filesystem state.
MUTATE = {'add', 'update', 'discard'}
BUILTINS = {name: getattr(builtins, name) for name in SAFE}
DICT_CHECK = ast.dump(ast.parse('not isinstance(inputs, dict)', mode='eval').body)
OPAQUE = ast.Name('__opaque__', ast.Load())
SSH_INPUTS = {'host', 'timeout_seconds', 'identity', 'transfer', 'device'}
VM_IDENTITY = ("type(inputs.get('vmIdentity')) is not str",)
# Reviewed gates: the branch's pure refusals, extra pure checks that the adapter's own validator makes before
# its first I/O, then that validator (an opaque tail), which the branch also reaches before any effect.
# Row: extra checks, the validator's module, the validator, the error it refuses with, other modules the branch loads.
RESIDUAL = {
    'windows-fixture-stage-recover-7f27': (VM_IDENTITY, 'windows_update_fixture_stage_recovery', '_validate_target',
                                           'WindowsUpdateFixtureStageRecoveryError', ()),
    'windows-msi-stale-lock-recover': (VM_IDENTITY, 'windows_msi_stale_lock_recovery', '_validate_target',
                                       'WindowsMsiStaleLockRecoveryError', ()),
    'windows-msi-stale-lock-reconcile': (VM_IDENTITY, 'windows_msi_stale_lock_reconcile', '_validate_target',
                                         'WindowsMsiStaleLockReconcileError', ()),
    'windows-msi-owner-relaunch-launch': (VM_IDENTITY, 'windows_msi_owner_relaunch', '_validate_target',
                                          'WindowsMsiOwnerRelaunchError', ()),
    'windows-credential-probe-start': ((), 'windows_credential_probe_ssh', '_admit_environment',
                                       'WindowsCredentialProbeSshError', ()),
    'windows-credential-recover-start': ((), 'windows_credential_probe_ssh', '_admit_environment',
                                         'WindowsCredentialProbeSshError', ('windows_credential_recovery_ssh',)),
}
# The real residual adapters; the differential replaces only their validators.
ADAPTERS = {module.__name__.rsplit('.', 1)[1]: module for module in (
    windows_credential_probe_ssh, windows_credential_recovery_ssh, windows_msi_owner_relaunch,
    windows_msi_stale_lock_reconcile, windows_msi_stale_lock_recovery, windows_update_fixture_stage_recovery)}
# Fences on actions whose branch has an effect before any pure refusal; each is reviewed, none may be added silently.
EFFECT_FIRST_FENCES = {'macos-machine-server-stop-start': 'pre-existing; dispatcher loads macos_machine_server_stop before its own refusal'}
A, B = '67eeeedb-a618-42d5-8e31-821650d16302', 'c2c0e5c9-77aa-4bd2-91a1-fb7540aa9f58'
# One valid-shape request per literal (helper-free) gate predicate; the group's other actions share it.
VALID = {'windows-cp117-staged-fixture-retire-start': {}, 'windows-msi-owner-census': {'host': 'archlinux'},
         'windows-msi-owner-relaunch-status': {'host': 'archlinux'},
         'windows-vm-swtpm-repair-status': {'host': 'archlinux', 'correlationId': A, 'timeoutSeconds': 60},
         'android-consent-grant-acceptance-diagnose': {'correlationId': A},
         'android-endpoint-cleanup-mount-diagnostic': {'correlationId': A, 'readmissionCorrelationId': B},
         'android-admission-status': {'host': 'h', 'device': 'd', 'correlationId': A, 'timeoutSeconds': 9},
         'windows-msi-base-pre-effect-status': {'host': 'archlinux'}, 'arch-ai-loop-observe': {'host': 'archlinux', 'timeoutSeconds': 9},
         'windows-vm-setup-language-next-start': {'host': 'archlinux', 'nextCorrelationId': A, 'timeoutSeconds': 60},
         'windows-vm-setup-install-disk-proof': {'host': 'archlinux', 'timeoutSeconds': 60},
         'windows-vm-deploy-secure': {'deploymentId': 'd', 'operationId': 'o', 'credentialFile': 'c'},
         'linux-package-fixture-build-pre-effect-status': {'correlationId': A},
         'linux-package-fixture-build-pre-effect-close': {'correlationId': A, 'closureDigest': 'a' * 64}}
STAGE = {'sourceFile': '/fixed/file', 'sourceSha256': '0' * 64, 'correlationId': '0' * 32}
SSH_MALFORMED = {'windows-caller-file-stage': [dict(timeout_seconds=60, transfer=STAGE, identity={'operationId': A}),
    dict(timeout_seconds=60, transfer=STAGE, device='api35'), dict(timeout_seconds=15, transfer=STAGE),
    dict(timeout_seconds=60, transfer={**STAGE, 'extra': 'x'}), dict(timeout_seconds=60, transfer=[STAGE])]}
# Field values the effect-blocked differential tries, beside each branch's own literals.
POOL = (None, True, False, 0, 1, -1, 9, 10, 30, 60, 300, 301, 65536, '', ' ', 'x', 'archlinux', 'api35', A, B, A.upper(),
        'a' * 40, 'a' * 64, 'sha256-' + 'a' * 64, '123:456', '/fixed/root', [], {}, ['x'], {'k': 'v'})


def literal(value):
    if value is None or type(value) in (bool, int, float, str, bytes):
        return ast.Constant(value)
    if type(value) in (tuple, list):
        return (ast.Tuple if type(value) is tuple else ast.List)([literal(item) for item in value], ast.Load())
    if type(value) in (set, frozenset):
        items = [literal(item) for item in sorted(value, key=repr)]
        node = ast.Set(items) if items else ast.Call(ast.Name('set', ast.Load()), [], [])
        return node if type(value) is set else ast.Call(ast.Name('frozenset', ast.Load()), [node] if items else [], [])
    if type(value) is dict:
        keys = sorted(value, key=repr)
        return ast.Dict([literal(key) for key in keys], [literal(value[key]) for key in keys])
    raise TypeError(type(value).__name__)


def bound(node):
    return {n.id for c in ast.walk(node) if isinstance(c, ast.comprehension) for n in ast.walk(c.target) if isinstance(n, ast.Name)}


def names(node):
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def disjunction(tests):
    """`or` of the tests: constant False ones drop out and a constant True one absorbs the rest."""
    tests = [test for test in tests if not (isinstance(test, ast.Constant) and not test.value)]
    if any(isinstance(test, ast.Constant) for test in tests):
        return ast.Constant(True)
    return ast.Constant(False) if not tests else tests[0] if len(tests) == 1 else ast.BoolOp(ast.Or(), tests)


def canon(node):
    """Truthiness-equal normal form: no outer bool(), flat boolean chains, sorted literal sets and dicts."""
    node = copy.deepcopy(node)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'bool' and len(node.args) == 1 and not node.keywords:
        node = node.args[0]
    class Flat(ast.NodeTransformer):
        def visit_BoolOp(self, n):  # Bottom-up, so arbitrarily nested chains of one operator flatten fully.
            self.generic_visit(n)
            n.values = [v for value in n.values for v in (value.values if isinstance(value, ast.BoolOp) and type(value.op) is type(n.op) else [value])]
            return n
    node = Flat().visit(node)
    for part in ast.walk(node):
        if isinstance(part, ast.Set) and all(isinstance(item, ast.Constant) for item in part.elts):
            part.elts.sort(key=lambda item: repr(item.value))
        if isinstance(part, ast.Dict) and all(isinstance(key, ast.Constant) for key in part.keys):
            pairs = sorted(zip(part.keys, part.values), key=lambda pair: repr(pair[0].value))
            part.keys, part.values = [key for key, _ in pairs], [value for _, value in pairs]
    return ast.dump(node, include_attributes=False)


class Source:
    """mcp_server.py as parsed text: literal module constants and verified-pure module helpers."""
    def __init__(self, text):
        self.tree, self.cache = ast.parse(text), {}
        self.funcs = {n.name: n for n in self.tree.body if isinstance(n, ast.FunctionDef)}
        counts = collections.Counter(t.id for n in self.tree.body if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
                                     for t in (n.targets if isinstance(n, ast.Assign) else [n.target]) if isinstance(t, ast.Name))
        mutated = {n.func.value.id for n in ast.walk(self.tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and isinstance(n.func.value, ast.Name) and n.func.attr not in METHODS}
        mutated |= {t.value.id for n in ast.walk(self.tree) if isinstance(n, (ast.Assign, ast.AugAssign, ast.Delete))
                    for t in (n.targets if isinstance(n, (ast.Assign, ast.Delete)) else [n.target])
                    if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)}
        mutated |= {name for n in ast.walk(self.tree) if isinstance(n, (ast.Global, ast.Nonlocal)) for name in n.names}
        self.consts = {}
        for n in self.tree.body:
            if (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                    and counts[n.targets[0].id] == 1 and n.targets[0].id not in mutated):
                try:
                    self.consts[n.targets[0].id] = ast.literal_eval(n.value)
                except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                    pass
        self.pure = {'_valid_uuid', '_error'}  # Reviewed: uuid parsing inside try/except; refusal DTO construction.
        while more := {name for name, f in self.funcs.items() if name not in self.pure and not f.decorator_list
                       and self.block(f.body, {a.arg for a in f.args.posonlyargs + f.args.args + f.args.kwonlyargs}, set())}:
            self.pure |= more

    def expr(self, node, allowed):
        """Effect-free expression over allowed names: fixed builtins, lexical paths, read-only methods and pure helpers."""
        allowed = allowed | bound(node) | TYPES | set(SAFE) | LEXICAL | set(self.consts) | self.pure | {'re'}
        funcs = {id(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)}
        for n in ast.walk(node):
            if (isinstance(n, (ast.Lambda, ast.NamedExpr, ast.Await, ast.Yield, ast.YieldFrom))
                    or isinstance(n, ast.Call) and not (isinstance(n.func, ast.Name) and n.func.id in set(SAFE) | LEXICAL | self.pure
                                                        or isinstance(n.func, ast.Attribute) and n.func.attr in METHODS)
                    or isinstance(n, ast.Attribute) and id(n) not in funcs
                    or isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in allowed):
                return False
        return True

    def block(self, body, params, local):
        """Effect-free helper body: assignments, fresh-local mutation, pure ifs/loops and returns."""
        for st in body:
            allowed = params | local
            if isinstance(st, ast.Pass) or isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant):
                continue
            if isinstance(st, ast.Assign) and all(isinstance(t, (ast.Name, ast.Tuple)) for t in st.targets) and self.expr(st.value, allowed):
                local |= set().union(*map(names, st.targets))
            elif not (isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Subscript)
                      and isinstance(st.targets[0].value, ast.Name) and st.targets[0].value.id in local
                      and self.expr(st.value, allowed) and self.expr(st.targets[0].slice, allowed)
                      or isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and isinstance(st.value.func, ast.Attribute)
                      and st.value.func.attr in MUTATE and isinstance(st.value.func.value, ast.Name)
                      and st.value.func.value.id in local and not st.value.keywords and all(self.expr(a, allowed) for a in st.value.args)
                      or isinstance(st, ast.If) and self.expr(st.test, allowed)
                      and self.block(st.body, params, local) and self.block(st.orelse, params, local)
                      or isinstance(st, ast.For) and not st.orelse and isinstance(st.target, (ast.Name, ast.Tuple)) and self.expr(st.iter, allowed)
                      and self.block(st.body, params, local | names(st.target))
                      or isinstance(st, ast.Return) and (st.value is None or self.expr(st.value, allowed))):
                return False
        return True

    def info(self, node):
        cached = self.cache.get(id(node))
        if cached is None:
            free = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)} - bound(node)
            code = compile(ast.fix_missing_locations(ast.Expression(copy.deepcopy(node))), '<fold>', 'eval') if self.expr(node, free) else None
            cached = self.cache[id(node)] = node, free, code
        return cached[1:]


class Walk:
    """One concrete action through a function body: folded action tests, pure bindings, pure refusals."""
    def __init__(self, src, action, inputs):
        self.src, self.inputs, self.env, self.sym, self.fresh, self.shadow = src, inputs, {'action': action}, {}, set(), set()
        self.refusals = []

    def known(self):
        return set(self.env) | set(self.sym) | self.inputs

    def value(self, node):
        free, code = self.src.info(node)
        free = free - set(self.src.consts) - set(SAFE) - TYPES
        if code is None or free & self.shadow or not free <= set(self.env):
            raise LookupError
        scope = {'__builtins__': BUILTINS, **self.src.consts, **{name: self.env[name] for name in free}}
        return eval(code, scope)  # noqa: S307 - verified effect-free expression over literal values only

    def fold(self, node):
        if isinstance(node, ast.expr) and not isinstance(node, ast.Constant):
            try:
                return literal(self.value(node))
            except Exception:
                pass
        if isinstance(node, ast.BoolOp):
            absorbing, kept = isinstance(node.op, ast.Or), []
            for value in map(self.fold, node.values):
                if isinstance(value, ast.Constant):
                    if bool(value.value) == absorbing:
                        return ast.BoolOp(node.op, kept + [value]) if kept else value
                    continue
                kept.append(value)
            return ast.Constant(not absorbing) if not kept else kept[0] if len(kept) == 1 else ast.BoolOp(node.op, kept)
        if not isinstance(node, (ast.expr, ast.comprehension, ast.keyword)):
            return node
        node = copy.copy(node)
        for field_name, old in ast.iter_fields(node):
            if isinstance(old, ast.AST):
                setattr(node, field_name, self.fold(old))
            elif isinstance(old, list):
                setattr(node, field_name, [self.fold(item) if isinstance(item, ast.AST) else item for item in old])
        return node

    def residual(self, node):
        """Locals substituted, action folded, the redundant dict precheck dropped (inputs is a dict here)."""
        walk = self
        class Subst(ast.NodeTransformer):
            def visit_Name(self, n):
                if isinstance(n.ctx, ast.Load) and n.id not in walk.shadow and walk.sym.get(n.id) is not None:
                    return copy.deepcopy(walk.sym[n.id])
                return n
        class Drop(ast.NodeTransformer):
            def visit_BoolOp(self, n):
                self.generic_visit(n)
                n.values = [v for v in n.values if ast.dump(v if isinstance(n.op, ast.Or) else ast.UnaryOp(ast.Not(), v)) != DICT_CHECK]
                return ast.Constant(isinstance(n.op, ast.And)) if not n.values else n.values[0] if len(n.values) == 1 else n
        for _ in range(8):
            self.shadow = bound(node)
            new = Subst().visit(copy.deepcopy(node))
            if ast.dump(new) == ast.dump(node):
                break
            node = new
        node = Drop().visit(copy.deepcopy(node))
        node = ast.Constant(False) if ast.dump(node) == DICT_CHECK else node
        self.shadow = bound(node)
        try:
            return self.fold(node)
        finally:
            self.shadow = set()

    def bind(self, st):
        """Record a pure local binding or a fresh-local mutation; False for anything else."""
        known = self.known()
        if isinstance(st, ast.Assign) and all(isinstance(t, (ast.Name, ast.Tuple)) for t in st.targets) and self.src.expr(st.value, known):
            single = len(st.targets) == 1 and isinstance(st.targets[0], ast.Name)
            for name in set().union(*map(names, st.targets)):
                self.env.pop(name, None); self.sym[name] = st.value if single else None; self.fresh.discard(name)
            if single:
                name = st.targets[0].id
                try:
                    self.env[name] = self.value(st.value); del self.sym[name]
                except Exception:
                    pass
                if isinstance(st.value, (ast.Set, ast.Dict, ast.List, ast.SetComp, ast.DictComp, ast.ListComp)) or (
                        isinstance(st.value, ast.Call) and isinstance(st.value.func, ast.Name) and st.value.func.id in {'set', 'dict', 'list'}):
                    self.fresh.add(name)
            return True
        item = isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Subscript)
        call = isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and isinstance(st.value.func, ast.Attribute) and st.value.func.attr in MUTATE
        receiver = st.targets[0].value if item else st.value.func.value if call else None
        parts = [st.value, st.targets[0].slice] if item else st.value.args if call else []
        if (not isinstance(receiver, ast.Name) or receiver.id not in self.fresh or call and st.value.keywords
                or not all(self.src.expr(part, known) for part in parts)):
            return False
        try:
            value, args = copy.deepcopy(self.env[receiver.id]), [self.value(part) for part in parts]
            if item:
                value[args[1]] = args[0]
            else:
                getattr(value, st.value.func.attr)(*args)
            self.env[receiver.id] = value
        except Exception:
            self.env.pop(receiver.id, None); self.sym[receiver.id] = None
        return True

    def terminal(self, body):
        """Pure assignments followed by a pure return: the refusal itself."""
        *init, last = body
        known = self.known() | set().union(set(), *(names(t) for st in init if isinstance(st, ast.Assign) for t in st.targets))
        return (all(isinstance(st, ast.Assign) and all(isinstance(t, ast.Name) for t in st.targets) and self.src.expr(st.value, known) for st in init)
                and isinstance(last, ast.Return) and (last.value is None or self.src.expr(last.value, known)))

    def run(self, body):
        """Walk to the first effect, collecting every pure refusal on the way in self.refusals.

        Returns ('return', node) for a pure unconditional return, ('effect', node), or None to fall through."""
        for st in body:
            if isinstance(st, ast.Pass) or isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant):
                continue
            if isinstance(st, ast.If):
                test = ast.Constant(False) if ast.dump(st.test) == DICT_CHECK else self.fold(st.test)
                if isinstance(test, ast.Constant):
                    outcome = self.run(st.body if test.value else st.orelse)
                    if outcome:
                        return outcome
                    continue
                if st.orelse or not self.src.expr(st.test, self.known()) or not self.terminal(st.body):
                    return 'effect', st
                self.refusals.append((st.lineno, self.residual(st.test)))
                continue
            if isinstance(st, (ast.Assign, ast.Expr)) and self.bind(st):
                continue
            if isinstance(st, ast.Return) and (st.value is None or self.src.expr(st.value, self.known())):
                return 'return', st
            return 'effect', st
        return None

    def predicate(self, body):
        """The gate's predicate for this action: each pure `if test: return True` step or-ed with the returned
        expression, and an opaque marker for any other data-dependent step."""
        parts = []
        for index, st in enumerate(body):
            if isinstance(st, ast.Pass) or isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant):
                continue
            if isinstance(st, ast.If):
                test = self.fold(st.test)
                if isinstance(test, ast.Constant):
                    return disjunction(parts + [self.predicate((st.body if test.value else st.orelse) + body[index + 1:])])
                if (not st.orelse and len(st.body) == 1 and isinstance(st.body[0], ast.Return)
                        and isinstance(st.body[0].value, ast.Constant) and st.body[0].value.value is True
                        and self.src.expr(st.test, self.known())):
                    parts.append(self.residual(st.test))
                    continue
                return disjunction(parts + [OPAQUE])
            if isinstance(st, (ast.Assign, ast.Expr)) and self.bind(st):
                continue
            if isinstance(st, ast.Return) and st.value is not None and self.src.expr(st.value, self.known()):
                return disjunction(parts + [self.residual(st.value)])
            if (isinstance(st, ast.Try) and len(st.body) == 1 and isinstance(st.body[0], ast.Return) and st.handlers
                    and not st.orelse and not st.finalbody and all(len(h.body) == 1 and isinstance(h.body[0], ast.Return)
                    and isinstance(h.body[0].value, ast.Constant) and h.body[0].value.value is True for h in st.handlers)):
                return disjunction(parts + [self.predicate(st.body)])  # A raising predicate refuses, as the dispatcher's own handler does.
            return disjunction(parts + [OPAQUE])
        return disjunction(parts + [ast.Constant(False)])


def pure_prefix(src, action, inputs, body):
    """(refusal lines, their disjunction) before this action's first effect in body, or None without any."""
    walk = Walk(src, action, inputs)
    outcome = walk.run(body)
    refusals = walk.refusals + ([(outcome[1].lineno, ast.Constant(True))] if outcome and outcome[0] == 'return' else [])
    return (tuple(line for line, _ in refusals), disjunction([test for _, test in refusals])) if refusals else None


def gate(src, action):
    return Walk(src, action, {'inputs'}).predicate(src.funcs['_vm_invalid_before_recovery'].body)


SOURCE = Source(Path(server.__file__).read_text(encoding='utf-8'))
DISPATCH = next(s for s in SOURCE.funcs['_vm_workflow_dispatch'].body if isinstance(s, ast.Try)).body
VM_ACTIONS = sorted(action for surface, action in policy.CATALOG if surface == 'vm_workflow')
# {action: (refusal lines, disjunction)} for every action whose dispatcher path refuses purely before an effect.
GROUPS = {action: found for action in VM_ACTIONS if (found := pure_prefix(SOURCE, action, {'inputs'}, DISPATCH))}


class Effect(BaseException):
    """An attempted side effect during an armed call; no `except Exception` handler can absorb it."""


class Blocker:
    """Arms the calling thread: audited I/O, unaudited stat-family calls and adapter loads raise Effect."""
    EXACT = {'open', 'import', 'time.sleep', 'builtins.input', 'io.open', 'io.open_code', 'pathlib.Path.glob', 'pathlib.Path.rglob'}
    PREFIXES = ('os.', 'subprocess.', 'socket.', 'shutil.', 'glob.', 'tempfile.', 'sqlite3.', 'urllib.', 'http.', 'ctypes.',
                'fcntl.', 'mmap.', 'pty.', 'signal.', 'syslog.', 'webbrowser.', 'ftplib.', 'smtplib.', '_thread.', 'winreg.',
                'msvcrt.', '_winapi.')
    UNAUDITED = ('stat', 'lstat', 'access', 'readlink')

    def __init__(self):
        self.thread, self.events, self.loads = None, [], []

    def hit(self, name):
        if self.thread == threading.get_ident():
            self.events.append(name)
            raise Effect(name)

    def audit(self, event, args):
        if self.thread == threading.get_ident() and (event in self.EXACT or event.startswith(self.PREFIXES)):
            self.events.append(event)
            raise Effect(event)

    def unaudited(self, name, original):
        def call(*args, **kwargs):
            self.hit('os.' + name)
            return original(*args, **kwargs)
        return call

    def loader(self, adapters):
        def load(name, *args, **kwargs):
            if name in adapters:
                self.loads.append(name)
                return adapters[name]
            self.events.append('_agent_module:' + name)
            raise Effect(name)  # Never a real adapter, armed or not.
        return load

    def call(self, function, *args):
        """(kind, value, allowed loads): kind 'value' only when no effect was attempted, else 'effect' or 'raised'."""
        self.events, self.loads, self.thread = [], [], threading.get_ident()
        try:
            value, kind = function(*args), 'value'
        except Effect as error:
            value, kind = error, 'effect'
        except Exception as error:
            value, kind = error, 'raised'
        finally:
            self.thread = None
        return ('effect' if self.events else kind), value, tuple(self.loads)


BLOCKER = Blocker()
HOOKED = []


class Stand:
    """An adapter whose load is allowed but whose every use is an effect."""
    def __getattr__(self, name):
        BLOCKER.events.append('adapter.' + name)
        raise Effect(name)


def admitting(real):
    """The adapter's own validator, whose first I/O counts as admission, so only its pure checks refuse."""
    def check(*args, **kwargs):
        mark = len(BLOCKER.events)
        try:
            real(*args, **kwargs)
        except Effect:
            del BLOCKER.events[mark:]
    return check


def refusing(error):
    def check(*args, **kwargs):
        raise error('controlled validator refusal')
    return check


def modes(action):
    """(name, validator patch, loadable adapters) for each run of one action."""
    if action in RESIDUAL:  # The validator refusing everything, then admitting whenever its pure checks pass.
        _, module, validator, error, loads = RESIDUAL[action]
        adapters = {name: ADAPTERS[name] for name in (module, *loads)}
        return [('refusing', mock.patch.object(ADAPTERS[module], validator, refusing(getattr(ADAPTERS[module], error))), adapters),
                ('admitting', mock.patch.object(ADAPTERS[module], validator, admitting(getattr(ADAPTERS[module], validator))), adapters)]
    return [('plain', contextlib.nullcontext(), {'macos_machine_server_stop': Stand()} if action in EFFECT_FIRST_FENCES else {})]


def statements(walk, body):
    """The dispatcher statements this action can reach: folded action tests select their branch."""
    for st in body:
        test = walk.fold(st.test) if isinstance(st, ast.If) else None
        if isinstance(test, ast.Constant):
            yield from statements(walk, st.body if test.value else st.orelse)
        else:
            yield st


def key_sets(value):
    """String key sets inside a folded local value."""
    if type(value) in (set, frozenset, dict) and value and all(type(item) is str for item in value):
        yield frozenset(value)
    for item in value.values() if type(value) is dict else value if type(value) in (tuple, list) else ():
        yield from key_sets(item)


def sample(pattern):
    """The shortest text that a pattern of literals, classes and repeats fully matches, else None."""
    def build(items):
        text = ''
        for op, arg in items:
            if op is RE_OPS.LITERAL:
                text += chr(arg)
            elif op is RE_OPS.IN and arg[0][0] in (RE_OPS.LITERAL, RE_OPS.RANGE):
                text += chr(arg[0][1] if arg[0][0] is RE_OPS.LITERAL else arg[0][1][0])
            elif op is RE_OPS.MAX_REPEAT:
                text += build(arg[2]) * arg[0]
        return text  # Any other construct adds nothing, so the full match below rejects the sample.
    text = build(RE_PARSER.parse(pattern))
    return text if re.fullmatch(pattern, text) else None


def field(node):
    """The literal request field an expression reads: inputs['k'] or inputs.get('k', ...)."""
    key = (node.slice if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == 'inputs' else
           node.args[0] if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'get'
           and isinstance(node.func.value, ast.Name) and node.func.value.id == 'inputs' and node.args else None)
    return key.value if isinstance(key, ast.Constant) and type(key.value) is str else None


def compared(node, envs):
    """A value a field is compared with: a literal, the first member of a literal collection, or a folded local."""
    if isinstance(node, ast.Name):
        value = next((env[node.id] for env in envs if node.id in env), None)
    else:
        try:
            value = ast.literal_eval(node)
        except (ValueError, TypeError, SyntaxError):
            return None
    return sorted(value, key=repr)[0] if type(value) in (set, frozenset, tuple, list) and value else value


def literals(action, nodes):
    """Key sets, field hints and short constants of these nodes and the pure module helpers they call, with the
    key sets and compared values that their locals fold to for this action."""
    shapes, hints, constants, seen, pending = set(), {}, set(), set(), list(nodes)
    walk = Walk(SOURCE, action, {'inputs'})
    walk.run(DISPATCH)
    envs = [walk.env]
    while pending:
        for n in ast.walk(pending.pop()):
            elements = n.elts if isinstance(n, ast.Set) else n.keys if isinstance(n, ast.Dict) else []
            if elements and all(isinstance(e, ast.Constant) and type(e.value) is str for e in elements):
                shapes.add(frozenset(e.value for e in elements))
            if field(n):
                hints.setdefault(field(n), None)
            if isinstance(n, ast.Compare) and isinstance(n.ops[0], (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) and field(n.left):
                hints[field(n.left)] = hints.get(field(n.left)) or compared(n.comparators[0], envs)
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in {'fullmatch', 'match'} and len(n.args) == 2
                    and isinstance(n.args[0], ast.Constant) and field(n.args[1])):
                hints[field(n.args[1])] = hints.get(field(n.args[1])) or sample(n.args[0].value)
            typed = (n.args if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'isinstance' and len(n.args) == 2
                     else [n.left.args[0], n.comparators[0]] if isinstance(n, ast.Compare) and isinstance(n.ops[0], (ast.Is, ast.IsNot))
                     and isinstance(n.left, ast.Call) and isinstance(n.left.func, ast.Name) and n.left.func.id == 'type' and n.left.args else [])
            if typed and field(typed[0]) and isinstance(typed[1], ast.Name) and typed[1].id == 'dict':
                hints[field(typed[0])] = {}
            if isinstance(n, ast.Constant) and type(n.value) is str and len(n.value) <= 64 and ' ' not in n.value:
                constants.add(n.value)
            if isinstance(n, ast.Constant) and type(n.value) is int:
                constants |= {n.value - 1, n.value, n.value + 1}
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in SOURCE.pure - seen:
                seen.add(n.func.id)
                helper = SOURCE.funcs[n.func.id]
                pending.append(helper)
                walk = Walk(SOURCE, action, {a.arg for a in helper.args.args} - {'action'})
                walk.run(helper.body)
                envs.append(walk.env)
    shapes |= {shape for env in envs for value in env.values() for shape in key_sets(value)} | {frozenset(hints)}
    shapes = sorted((shape for shape in shapes if len(shape) <= 16), key=lambda shape: (-len(shape), sorted(shape)))
    return shapes, {key: value for key, value in hints.items() if type(value) in (str, int, dict)}, sorted(constants, key=repr)


def default(key, index, hints):
    """A plausible well-formed value for a request field: the value its branch compares it with, else by its name."""
    low = key.lower()
    if key in hints:
        return hints[key]
    if key in {'host', 'device', 'vmIdentity'}:
        return {'host': 'archlinux', 'device': 'api35', 'vmIdentity': '123:456'}[key]
    if 'timeout' in low:
        return 30  # Inside every route's bound.
    if low.endswith('utc'):
        return '2026-01-01T00:00:00Z'
    if 'sha256' in low or 'digest' in low:
        return 'a' * 64
    if low.endswith('sha'):
        return 'a' * 40
    if 'artifactid' in low:
        return 'sha256-' + 'a' * 64
    if low.endswith(('revision', 'pid', 'port', 'ticks', 'version')):
        return 1
    if 'correlation' in low or low.endswith(('id', 'owner')):
        return '%08x-0000-4000-8000-%012x' % (index + 1, index + 1)  # Canonical and distinct per field.
    return 'x'


def explore(action, check):
    """Malformed probes, one base request per key set, and single-field changes of each base that the gate admits."""
    nodes = [*statements(Walk(SOURCE, action, {'inputs'}), DISPATCH), gate(SOURCE, action)]
    nodes += [GROUPS[action][1]] if action in GROUPS else []
    shapes, hints, constants = literals(action, nodes)
    values = [*POOL, *(value for value in constants if value not in POOL)]
    check({})
    check({'zzUnexpectedField': True})
    for shape in shapes:
        base = {key: default(key, index, hints) for index, key in enumerate(sorted(shape))}
        if check(base) and action in GROUPS:
            for key in sorted(base):
                for value in values:
                    check({**base, key: value})
                check({k: v for k, v in base.items() if k != key})
            check({**base, 'zzUnexpectedField': True})


class PureGateContractTests(unittest.TestCase):
    def test_every_pure_dispatcher_refusal_before_the_first_effect_is_fenced_by_the_identical_predicate(self):
        for action, (lines, refused) in sorted(GROUPS.items()):
            tail = [ast.parse(check, mode='eval').body for check in RESIDUAL[action][0]] + [OPAQUE] if action in RESIDUAL else []
            with self.subTest(action=action, lines=lines):
                self.assertEqual(canon(disjunction([refused, *tail])), canon(gate(SOURCE, action)))
        self.assertLessEqual({'readiness-status', 'readiness-providers', 'windows-cp117-c32-archive-diagnose', 'android-observe',
                              'windows-cp117-guest-agent-recovery-successor-start', 'windows-msi-owner-census',
                              'windows-msi-base-finish-observed', 'android-fixture-tls-mint'} | set(RESIDUAL), set(GROUPS))

    def test_actions_without_a_pure_refusal_before_their_first_effect_have_no_fence(self):
        outside = set(VM_ACTIONS) - set(GROUPS)
        fenced = {action for action in outside if canon(gate(SOURCE, action)) != canon(ast.Constant(False))}
        self.assertEqual(sorted(EFFECT_FIRST_FENCES), sorted(fenced))

    def test_malformed_requests_get_the_dispatcher_refusal_before_any_adapter_load(self):
        bad, seen = {'zzUnexpectedField': True}, set()
        for action, (lines, refused) in sorted(GROUPS.items()):
            if canon(refused) in seen:
                continue
            seen.add(canon(refused))
            with self.subTest(action=action, lines=lines), mock.patch.object(server, '_agent_module') as loader:
                self.assertTrue(server._vm_invalid_before_recovery(action, bad))
                refusal = server._vm_workflow_dispatch(action, bad)
                self.assertEqual(refusal, server._vm_workflow_impl(action, bad))
                self.assertIs(False, refusal['ok'])
                loader.assert_not_called()

    def test_effect_blocked_differential_agrees_with_the_gate_for_every_action(self):
        """The gate refuses only what the dispatcher refuses without an effect, and fences every such refusal."""
        if not HOOKED:
            sys.addaudithook(BLOCKER.audit)
            HOOKED.append(True)
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for name in Blocker.UNAUDITED:
            stack.enter_context(mock.patch.object(os, name, BLOCKER.unaudited(name, getattr(os, name))))
        self.assertEqual(['effect', 'effect'], [BLOCKER.call(open, os.devnull)[0], BLOCKER.call(os.stat, os.devnull)[0]])
        first, total, counts, admitted = {}, collections.Counter(), collections.Counter(), set()
        for action in VM_ACTIONS:
            for mode, validating, adapters in modes(action):
                seen = set()
                def check(inputs):
                    key = json.dumps(inputs, sort_keys=True)
                    if key in seen:
                        return False
                    seen.add(key)
                    kind, fenced, _ = BLOCKER.call(server._vm_invalid_before_recovery, action, inputs)
                    outcome, result, loads = BLOCKER.call(server._vm_workflow_dispatch, action, inputs)
                    refused = outcome == 'value' and type(result) is dict and result.get('ok') is False
                    counts[kind, kind == 'value' and bool(fenced), refused, bool(loads)] += 1
                    problem = ('gate ' + kind if kind != 'value' else 'fenced, but the dispatcher ' + outcome if fenced and not refused
                               else 'effect-free refusal not fenced' if not fenced and refused and not loads else None)
                    if problem:
                        total[action, mode, problem] += 1
                        first.setdefault((action, mode, problem), key[:160] + ' -> ' + repr(fenced if kind != 'value' else result)[:160])
                    if kind == 'value' and not fenced:
                        admitted.add(action)
                    return kind == 'value' and not fenced
                with mock.patch.object(server, '_agent_module', BLOCKER.loader(adapters)), validating:
                    explore(action, check)
        report = [f'{action} [{mode}] {problem} x{total[action, mode, problem]}: {example}' for (action, mode, problem), example in sorted(first.items())]
        self.assertEqual([], report[:24], f'{sum(total.values())} disagreements of {len(report)} kinds')
        self.assertEqual([], sorted(action for action, (_, refused) in GROUPS.items()
                                    if action not in admitted and canon(refused) != canon(ast.Constant(True))))
        self.assertGreater(counts['value', True, True, False], 1000)  # Effect-free refusals that the gate fences.
        self.assertGreater(counts['value', False, False, False], 1000)  # Admitted requests that reached an effect.

    def test_literal_gate_predicates_admit_their_valid_request_shape(self):
        literal_groups = collections.defaultdict(set)
        for action, (_, refused) in GROUPS.items():
            helpers = {n.func.id for n in ast.walk(refused) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)} & SOURCE.pure
            if action not in RESIDUAL and not isinstance(refused, ast.Constant) and helpers <= {'_valid_uuid'}:
                literal_groups[canon(refused)].add(action)
        self.assertEqual(set(literal_groups), {canon(GROUPS[action][1]) for action in VALID})
        for actions in literal_groups.values():
            sample_request = VALID[min(actions & set(VALID))]
            for action in sorted(actions):
                with self.subTest(action=action):
                    self.assertFalse(server._vm_invalid_before_recovery(action, dict(sample_request)))
                    self.assertTrue(server._vm_invalid_before_recovery(action, {**sample_request, 'zzUnexpectedField': True}))

    def test_ssh_pure_first_refusals_skip_transport_admission(self):
        skipped = next({c.value for c in n.comparators[0].elts} for n in ast.walk(SOURCE.funcs['_native_source_request'])
                       if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name) and n.left.id == 'action' and isinstance(n.ops[0], ast.NotIn))
        admitted = {action for (surface, action), row in policy.CATALOG.items() if surface == 'ssh_workflow'
                    and row.requirements == {'transport'} and 'reconnect' in row.permitted_recoveries} - skipped
        body = SOURCE.funcs['_ssh_workflow_impl'].body
        self.assertEqual(set(SSH_MALFORMED), {a for a in admitted if pure_prefix(SOURCE, a, SSH_INPUTS, body)})
        for action, cases in SSH_MALFORMED.items():
            for case in cases:
                arguments = {'action': action, 'host': 'archlinux', 'identity': None, 'transfer': None, 'device': None, **case}
                with self.subTest(action=action, case=case), mock.patch.object(server, '_agent_module') as loader:
                    self.assertTrue(server._ssh_invalid_before_recovery(action, arguments))
                    refused = server._ssh_workflow_impl.__wrapped__(action, 'archlinux', **case)
                    self.assertEqual(refused, server._ssh_workflow_impl(action, 'archlinux', **case))
                    self.assertIs(False, refused['ok'])
                    loader.assert_not_called()


if __name__ == '__main__':
    unittest.main()
