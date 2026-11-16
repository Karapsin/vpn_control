"""Native dispatch runs only clean source that origin/dev, the gate ledger or a confirmed origin ci/* tip holds."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import committed_source as subject
from agent_tools import readiness_vm_dispatch as dispatch
from agent_tools.tests import red_gate

FIXTURE = Path(__file__).parent / 'fixtures' / 'committed_source'
PUBLISHED = Path(__file__).parent / 'fixtures' / 'committed_source_published'
FILES = ('agent_tools/alpha.py', 'agent_tools/beta.py')


def before(name):
    """A preserved bf8d2da2 source, checked against its provenance."""
    path = PUBLISHED / name
    provenance = json.loads((PUBLISHED / 'provenance.json').read_bytes())
    assert provenance['files'][name]['sha256'] == hashlib.sha256(path.read_bytes()).hexdigest(), name
    return path


def before_committed_source():
    module = types.ModuleType('committed_source_before')
    module.__file__ = str(Path(subject.__file__))
    exec(compile(before('committed_source.before.source').read_bytes(), 'committed_source.before.source', 'exec'),
         module.__dict__)
    return module


class Repository:
    """A throwaway checkout with a bare origin; origin/dev is a remote-tracking ref, ci/* branches live on origin."""

    def __init__(self, test):
        temporary = tempfile.TemporaryDirectory()
        test.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        self.origin = base / 'origin.git'
        self.root = base / 'checkout'
        (self.root / 'agent_tools' / 'tests').mkdir(parents=True)
        (self.root / 'scripts').mkdir()
        self.run(base, 'init', '-q', '--bare', str(self.origin))
        self.git('init', '-q')
        self.git('remote', 'add', 'origin', str(self.origin))
        for name in FILES:
            self.write(name, '# ' + name + '\n')
        self.write('agent_tools/catalog.json', '{}\n')
        self.write('agent_tools/tests/test_alpha.py', '# a test\n')
        self.write('scripts/payload.py', '# shipped to the guest\n')
        self.write('.gitignore', '__pycache__/\n*.log\n.rag_index/\n')
        self.commit('published')

    def run(self, cwd, *args):
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='fixture',
                   GIT_AUTHOR_EMAIL='fixture@invalid', GIT_COMMITTER_NAME='fixture', GIT_COMMITTER_EMAIL='fixture@invalid')
        return subprocess.run(['git', '-C', str(cwd), *args], check=True, capture_output=True,
                              env=env, text=True).stdout.strip()

    def git(self, *args):
        return self.run(self.root, *args)

    def write(self, name, text):
        (self.root / name).parent.mkdir(parents=True, exist_ok=True)
        (self.root / name).write_text(text)

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-q', '--no-gpg-sign', '-m', message)
        return self.git('rev-parse', 'HEAD')

    def publish(self, ref='refs/remotes/origin/dev', commit='HEAD'):
        self.git('update-ref', ref, self.git('rev-parse', commit))

    def push_ci(self, name, commit='HEAD'):
        self.git('push', '-q', 'origin', self.git('rev-parse', commit) + ':refs/heads/ci/' + name)

    def delete_ci(self, name):
        self.git('push', '-q', 'origin', '--delete', 'ci/' + name)

    def ledger(self, sha, outcome='failed', changes=None):
        directory = self.root / '.rag_index' / 'ci-gate'
        directory.mkdir(parents=True, exist_ok=True)
        record = {'sha': sha, 'branch': 'ci/' + sha[:12], 'outcome': outcome, **(changes or {})}
        (directory / (sha + '.json')).write_text(json.dumps(record))

    def check(self, paths=FILES):
        return subject.require_committed(self.root, paths)

    def tree(self, paths=()):
        return subject.require_published_tree(self.root, paths)


class CommittedSourceTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repository(self)

    def refused(self, reason, paths=FILES, check=None):
        with self.assertRaises(subject.SourceNotCommitted) as caught:
            (check or self.repo.check)(paths)
        self.assertEqual(reason, caught.exception.reason)
        return caught.exception.paths

    def test_clean_source_at_or_behind_dev_is_accepted(self):
        self.repo.publish()
        head = self.repo.git('rev-parse', 'HEAD')
        self.assertEqual(head, self.repo.check())
        self.assertEqual({'reference': head, 'basis': subject.BASIS_DEV, 'head': head}, self.repo.tree())
        # HEAD behind dev: the merge-base is HEAD itself.
        self.repo.write('agent_tools/beta.py', '# later dev edit\n')
        self.repo.commit('dev moves on')
        self.repo.publish()
        self.repo.git('checkout', '-q', '--detach', head)
        self.assertEqual(head, self.repo.check())
        self.assertEqual(head, self.repo.tree()['reference'])

    def test_every_local_state_status_would_show_is_refused(self):
        self.repo.publish()
        self.repo.write('agent_tools/gamma.py', '# never added\n')
        self.assertEqual(('agent_tools/gamma.py',), self.refused(subject.UNTRACKED, FILES + ('agent_tools/gamma.py',)))
        self.repo.write('agent_tools/alpha.py', '# edited\n')
        self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.DIRTY))
        self.repo.git('add', 'agent_tools/alpha.py')  # staged is still not committed
        self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.DIRTY))
        self.repo.git('reset', '-q', '--hard')
        (self.repo.root / 'agent_tools/beta.py').unlink()
        os.symlink('alpha.py', self.repo.root / 'agent_tools/beta.py')
        self.assertEqual(('agent_tools/beta.py',), self.refused(subject.DIRTY))
        self.repo.git('checkout', '-q', '--', 'agent_tools/beta.py')
        self.assertIsNotNone(self.repo.check())
        self.assertEqual(('../outside.py',), self.refused(subject.UNTRACKED, ('../outside.py',)))

    def test_edits_hidden_from_status_are_refused(self):
        self.repo.publish()
        for flag in ('--assume-unchanged', '--skip-worktree'):
            self.repo.git('update-index', flag, 'agent_tools/alpha.py')
            self.repo.write('agent_tools/alpha.py', '# hidden edit\n')
            # git itself reports nothing, which is why the flags are refused.
            self.assertEqual('', self.repo.git('status', '--porcelain'))
            self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.HIDDEN))
            self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.HIDDEN, (), self.repo.tree))
            self.repo.git('update-index', flag.replace('--', '--no-'), 'agent_tools/alpha.py')
            self.repo.git('checkout', '-q', '--', 'agent_tools/alpha.py')
        self.assertIsNotNone(self.repo.check())

    def test_unpushed_commit_runs_only_from_a_confirmed_origin_ci_tip_RED_local_ref_GREEN(self):
        """Review finding 11: a remote-tracking ci/* ref set locally (update-ref) is not a published commit."""
        self.repo.publish()
        self.repo.write('agent_tools/alpha.py', '# local commit\n')
        local = self.repo.commit('local only')
        self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.UNPUBLISHED))
        # A local branch named ci/* or a locally set remote-tracking ref does not count.
        self.repo.git('branch', 'ci/local')
        self.repo.publish('refs/remotes/origin/ci/local', local)
        if red_gate.red_required(self, before('committed_source.before.source')):
            # RED: the bf8d2da2 rule read every refs/remotes/origin/ci/* as published, so the local ref admitted it.
            self.assertEqual(local, before_committed_source().require_committed(self.repo.root, FILES))
        self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.UNPUBLISHED))
        self.assertEqual(('agent_tools/',), self.refused(subject.UNPUBLISHED, (), self.repo.tree))
        # Another candidate's content on origin does not count either.
        self.repo.git('checkout', '-q', '-b', 'other', 'HEAD~1')
        self.repo.write('agent_tools/alpha.py', '# another candidate\n')
        self.repo.push_ci('other', self.repo.commit('other candidate'))
        self.repo.git('checkout', '-q', local)
        self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.UNPUBLISHED))
        # GREEN: the candidate that origin holds now, confirmed by ls-remote, admits exactly these bytes.
        self.repo.push_ci('local', local)
        self.assertEqual(local, self.repo.check())
        self.assertEqual({'reference': local, 'basis': subject.BASIS_REMOTE, 'head': local}, self.repo.tree())
        # Once origin deleted it, the remote-tracking ref left behind admits nothing.
        self.repo.delete_ci('local')
        self.repo.publish('refs/remotes/origin/ci/local', local)
        self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.UNPUBLISHED))

    def test_ls_remote_failure_admits_only_dev_reachable_source(self):
        self.repo.publish()
        published = self.repo.git('rev-parse', 'HEAD')
        self.repo.write('agent_tools/alpha.py', '# candidate\n')
        candidate = self.repo.commit('candidate')
        self.repo.push_ci('candidate', candidate)
        self.assertEqual(subject.BASIS_REMOTE, self.repo.tree()['basis'])
        # Offline: ls-remote fails, so the candidate tip is unconfirmed and refused; dev-reachable source still runs.
        self.repo.git('remote', 'set-url', 'origin', str(self.repo.origin) + '-unreachable')
        self.assertEqual(('agent_tools/',), self.refused(subject.UNPUBLISHED, (), self.repo.tree))
        self.repo.git('checkout', '-q', published)
        self.assertEqual(subject.BASIS_DEV, self.repo.tree()['basis'])
        # The call is bounded: a hung ls-remote ends as a failure, never as a pass.
        self.repo.git('checkout', '-q', candidate)
        with mock.patch.object(subject, '_LS_REMOTE_SECONDS', 0.001):
            self.repo.git('remote', 'set-url', 'origin', str(self.repo.origin))
            self.assertIsNone(subject._remote_candidates(self.repo.root))

    def test_a_gate_ledger_entry_publishes_its_pushed_sha(self):
        self.repo.publish()
        self.repo.write('agent_tools/alpha.py', '# gated candidate\n')
        candidate = self.repo.commit('gated candidate')
        self.repo.git('remote', 'set-url', 'origin', str(self.repo.origin) + '-unreachable')
        for value in ({'outcome': 'not-pushed'}, {'outcome': 'failed', 'sha': 'f' * 40}):
            self.repo.ledger(candidate, changes=value)
            self.assertEqual(('agent_tools/',), self.refused(subject.UNPUBLISHED, (), self.repo.tree))
        target = self.repo.root / '.rag_index' / 'ci-gate' / (candidate + '.json')
        target.unlink()
        (self.repo.root / 'elsewhere.json').write_text(json.dumps({'sha': candidate, 'outcome': 'failed'}))
        os.symlink(self.repo.root / 'elsewhere.json', target)
        self.assertEqual(('agent_tools/',), self.refused(subject.UNPUBLISHED, (), self.repo.tree))
        target.unlink()
        # The gate records a red candidate before deleting its ci/* branch: that record publishes the SHA.
        self.repo.ledger(candidate, 'failed')
        self.assertEqual({'reference': candidate, 'basis': subject.BASIS_LEDGER, 'head': candidate}, self.repo.tree())

    def test_no_dev_ref_and_no_candidate_is_unpublished(self):
        self.assertEqual(FILES, self.refused(subject.UNPUBLISHED))

    def test_inherited_git_environment_cannot_redirect_the_check(self):
        self.repo.publish()
        clean = Repository(self)
        clean.publish()
        self.repo.write('agent_tools/alpha.py', '# edited\n')
        with mock.patch.dict(os.environ, {'GIT_DIR': str(clean.root / '.git'), 'GIT_WORK_TREE': str(clean.root),
                                          'GIT_INDEX_FILE': str(clean.root / '.git' / 'index')}):
            self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.DIRTY))
            self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.DIRTY, (), self.repo.tree))

    def test_the_whole_tool_tree_must_be_clean_and_published_RED_closure_only_GREEN(self):
        """Review finding 3: an agent_tools file outside a closure, such as the dispatch catalog, also runs or steers."""
        self.repo.publish()
        old = before_committed_source() if red_gate.red_required(self, before('committed_source.before.source')) else None
        cases = (
            ('untracked module', lambda: self.repo.write('agent_tools/gamma.py', '# never added\n'), subject.UNTRACKED,
             ('agent_tools/gamma.py',)),
            ('ignored file', lambda: self.repo.write('agent_tools/notes.log', 'ignored but loadable\n'), subject.UNTRACKED,
             ('agent_tools/notes.log',)),
            ('edited catalog', lambda: self.repo.write('agent_tools/catalog.json', '{"edited": true}\n'), subject.DIRTY,
             ('agent_tools/catalog.json',)),
            ('deleted file', lambda: (self.repo.root / 'agent_tools/catalog.json').unlink(), subject.DIRTY,
             ('agent_tools/catalog.json',)),
            ('mode change', lambda: (self.repo.root / 'agent_tools/catalog.json').chmod(0o755), subject.DIRTY,
             ('agent_tools/catalog.json',)),
            ('staged new file', lambda: (self.repo.write('agent_tools/delta.py', '# staged\n'),
                                         self.repo.git('add', 'agent_tools/delta.py')), subject.DIRTY,
             ('agent_tools/delta.py',)),
            ('hidden edit', lambda: (self.repo.git('update-index', '--skip-worktree', 'agent_tools/catalog.json'),
                                     self.repo.write('agent_tools/catalog.json', '{"hidden": true}\n')), subject.HIDDEN,
             ('agent_tools/catalog.json',)),
        )
        for name, damage, reason, paths in cases:
            with self.subTest(name=name):
                damage()
                if old is not None:
                    # RED: the bf8d2da2 rule checked only the closure's files, so these passed.
                    self.assertEqual(self.repo.git('rev-parse', 'HEAD'), old.require_committed(self.repo.root, FILES))
                self.assertEqual(paths, self.refused(reason, FILES, self.repo.tree))
                self.repo.git('update-index', '--no-skip-worktree', 'agent_tools/catalog.json')
                self.repo.git('reset', '-q', '--hard')
                self.repo.git('clean', '-qfdx', '--', 'agent_tools')
                (self.repo.root / 'agent_tools/catalog.json').chmod(0o644)
        # Byte-code caches and tests are not part of the rule; a committed test-only change keeps the published tree.
        self.repo.write('agent_tools/__pycache__/alpha.cpython-314.pyc', 'cache')
        self.repo.write('agent_tools/tests/test_new.py', '# untracked test\n')
        self.repo.write('agent_tools/tests/test_alpha.py', '# edited test\n')
        published = self.repo.git('rev-parse', 'HEAD')
        self.repo.commit('test-only change')
        self.assertEqual(published, self.repo.tree(FILES)['reference'])
        # A committed tool change that origin does not hold is unpublished, whichever tool file it touched.
        self.repo.write('agent_tools/catalog.json', '{"local": true}\n')
        self.repo.commit('local catalog edit')
        self.assertEqual(('agent_tools/',), self.refused(subject.UNPUBLISHED, (), self.repo.tree))

    def test_closure_files_outside_the_tool_tree_are_checked_and_published(self):
        self.repo.publish()
        self.assertEqual(self.repo.git('rev-parse', 'HEAD'), self.repo.tree(('scripts/payload.py',))['reference'])
        self.repo.write('scripts/payload.py', '# edited payload\n')
        self.assertEqual(('scripts/payload.py',), self.refused(subject.DIRTY, ('scripts/payload.py',), self.repo.tree))
        self.repo.commit('local payload')
        self.assertEqual(('scripts/payload.py',), self.refused(subject.UNPUBLISHED, ('scripts/payload.py',), self.repo.tree))
        self.repo.push_ci('payload')
        self.assertEqual(subject.BASIS_REMOTE, self.repo.tree(('scripts/payload.py',))['basis'])

    def test_preserved_pin_rule_admits_repinned_local_edit_RED_committed_rule_refuses_GREEN(self):
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        path = FIXTURE / 'readiness_vm_dispatch.before.source'
        raw = path.read_bytes()
        self.assertEqual(provenance['sha256'], hashlib.sha256(raw).hexdigest())
        self.repo.publish()
        self.repo.write('agent_tools/alpha.py', '# local, unpushed edit\n')
        self.repo.commit('local only')
        edited = hashlib.sha256((self.repo.root / 'agent_tools/alpha.py').read_bytes()).hexdigest()
        source = self.repo.root / 'agent_tools' / 'readiness_vm_dispatch.py'
        # RED: the preserved rule compares bytes with the pin, and repin.py
        # re-derives the pin from those same bytes, so the edit is admitted.
        tree = ast.parse(raw)
        audit = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'audit_sources')
        routes = {action: row for action, row in dispatch.ROUTES.items() if row['kind'] != 'phase'}
        namespace = {**dispatch.__dict__, '_guard': lambda: None, '_SOURCE': source, '_SOURCE_PINS': {'alpha': edited},
                     'ROUTES': routes}
        exec(compile(ast.Module(body=[audit], type_ignores=[]), str(path), 'exec'), namespace)
        self.assertTrue(namespace['audit_sources']()['ok'])
        # GREEN: the dispatch boundary refuses the same unpublished bytes.
        operation = str(uuid4())
        with mock.patch.object(dispatch, '_SOURCE', source), self.assertRaises(dispatch.DispatchBlocked) as caught:
            dispatch._committed({'closure': FILES}, operation)
        self.assertEqual(('vm_readiness_target_source_unpublished', operation),
                         (caught.exception.reason, caught.exception.operation_identity))
        self.repo.git('checkout', '-q', 'HEAD~1')
        with mock.patch.object(dispatch, '_SOURCE', source):
            dispatch._committed({'closure': FILES}, operation)
        self.repo.write('agent_tools/beta.py', '# dirty\n')
        with mock.patch.object(dispatch, '_SOURCE', source), self.assertRaises(dispatch.DispatchBlocked) as caught:
            dispatch._committed({'closure': FILES}, operation)
        self.assertEqual('vm_readiness_target_source_uncommitted', caught.exception.reason)


class SubmittedJobObservationTests(unittest.TestCase):
    """Review finding 13: observing a job whose submit ran published source is not refused after that source's
    ci/* branch is deleted or a local commit follows; the job's recorded submit SHA is checked instead."""

    def setUp(self):
        self.repo = Repository(self)
        self.repo.publish()
        self.source = self.repo.root / 'agent_tools' / 'readiness_vm_dispatch.py'
        patcher = mock.patch.object(dispatch, '_SOURCE', self.source)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.row = {'closure': FILES}
        self.inputs = {'correlationId': str(uuid4())}
        self.submit = dispatch.policies.action_policy('vm_workflow', 'scenario-start')
        self.observe = dispatch.policies.action_policy('vm_workflow', 'scenario-status')

    def committed(self, policy, inputs=None):
        return dispatch._committed(self.row, 'operation', root=self.repo.root, policy=policy,
                                   inputs=self.inputs if inputs is None else inputs)

    def blocked(self, policy, inputs=None):
        with self.assertRaises(dispatch.DispatchBlocked) as caught:
            self.committed(policy, inputs)
        return caught.exception.reason

    def submitted_from_a_deleted_candidate(self):
        self.repo.write('agent_tools/alpha.py', '# candidate\n')
        candidate = self.repo.commit('candidate')
        self.repo.push_ci('candidate', candidate)
        source = self.committed(self.submit)
        self.assertEqual({'reference': candidate, 'basis': subject.BASIS_REMOTE, 'head': candidate}, source)
        record = dispatch.record_submit(self.repo.root, 'scenario-start', self.inputs, source)
        self.assertEqual(candidate, record['reference'])
        self.repo.delete_ci('candidate')
        return candidate

    def test_observation_checks_the_recorded_submit_sha_RED_refused_GREEN(self):
        candidate = self.submitted_from_a_deleted_candidate()
        old = None
        if red_gate.red_required(self, before('readiness_vm_dispatch.before.source'), before('committed_source.before.source')):
            tree = ast.parse(before('readiness_vm_dispatch.before.source').read_bytes())
            function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_committed')
            previous = before_committed_source()
            old = {**dispatch.__dict__, '_require_committed': previous.require_committed, 'committed_source': previous,
                   '_SOURCE': self.source}
            exec(compile(ast.Module(body=[function], type_ignores=[]), 'readiness_vm_dispatch.before.source', 'exec'), old)
            with self.assertRaises(dispatch.DispatchBlocked) as caught:
                old['_committed']({'closure': ('alpha', 'beta')}, 'operation')
            # RED: once the gate deleted the candidate's branch, its own job's status was refused.
            self.assertEqual('vm_readiness_target_source_unpublished', caught.exception.reason)
        observed = self.committed(self.observe)
        self.assertEqual((candidate, 'submit-record'), (observed['reference'], observed['basis']))
        # A later local commit: the observation still checks the job's submit SHA.
        self.repo.write('agent_tools/beta.py', '# later local commit\n')
        self.repo.commit('later local commit')
        if old is not None:
            with self.assertRaises(dispatch.DispatchBlocked):
                old['_committed']({'closure': ('alpha', 'beta')}, 'operation')
        self.assertEqual(candidate, self.committed(self.observe)['reference'])

    def test_only_a_clean_read_only_observation_of_a_recorded_job_is_exempt(self):
        self.submitted_from_a_deleted_candidate()
        self.repo.write('agent_tools/beta.py', '# later local commit\n')
        self.repo.commit('later local commit')
        # A new submission from the same unpublished source, or an observation of another job, is refused.
        self.assertEqual('vm_readiness_target_source_unpublished', self.blocked(self.submit))
        self.assertEqual('vm_readiness_target_source_unpublished', self.blocked(self.observe, {'correlationId': str(uuid4())}))
        self.assertEqual('vm_readiness_target_source_unpublished', self.blocked(self.observe, {}))
        # Uncommitted source is never exempt.
        self.repo.write('agent_tools/beta.py', '# dirty\n')
        self.assertEqual('vm_readiness_target_source_uncommitted', self.blocked(self.observe))
        self.repo.git('checkout', '-q', '--', 'agent_tools/beta.py')
        # A record is create-only (the first submit of a job is the one that ran) and private.
        record = self.repo.root / '.rag_index' / 'dispatch-source' / (self.inputs['correlationId'] + '.json')
        self.assertEqual(0o600, record.stat().st_mode & 0o777)
        self.assertEqual(0o700, record.parent.stat().st_mode & 0o777)
        first = record.read_bytes()
        later = {'reference': 'e' * 40, 'basis': subject.BASIS_DEV, 'head': 'e' * 40}
        self.assertEqual(json.loads(first)['reference'], dispatch.record_submit(self.repo.root, 'x', self.inputs, later)['reference'])
        self.assertEqual(first, record.read_bytes())
        # A record naming no local commit, or a widened file, exempts nothing.
        record.chmod(0o644)
        self.assertEqual('vm_readiness_target_source_unpublished', self.blocked(self.observe))
        record.chmod(0o600)
        record.write_text(json.dumps({**json.loads(first), 'reference': 'e' * 40}))
        self.assertEqual('vm_readiness_target_source_unpublished', self.blocked(self.observe))
        # A source that came from the exemption is never recorded as a new submit.
        self.assertIsNone(dispatch.record_submit(self.repo.root, 'x', {'correlationId': str(uuid4())},
                                                 {'reference': 'e' * 40, 'basis': 'submit-record', 'head': None}))


if __name__ == '__main__':
    unittest.main()
