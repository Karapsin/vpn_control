"""Native dispatch runs only clean source that origin/dev or an origin ci/* candidate holds."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import committed_source as subject
from agent_tools import readiness_vm_dispatch as dispatch

FIXTURE = Path(__file__).parent / 'fixtures' / 'committed_source'
FILES = ('agent_tools/alpha.py', 'agent_tools/beta.py')


class Repository:
    """A throwaway repository with explicit remote-tracking refs; nothing is fetched."""

    def __init__(self, test):
        temporary = tempfile.TemporaryDirectory()
        test.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'checkout'
        (self.root / 'agent_tools').mkdir(parents=True)
        self.git('init', '-q')
        for name in FILES:
            self.write(name, '# ' + name + '\n')
        self.commit('published')

    def git(self, *args):
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='fixture',
                   GIT_AUTHOR_EMAIL='fixture@invalid', GIT_COMMITTER_NAME='fixture', GIT_COMMITTER_EMAIL='fixture@invalid')
        return subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True,
                              env=env, text=True).stdout.strip()

    def write(self, name, text):
        (self.root / name).write_text(text)

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-q', '--no-gpg-sign', '-m', message)
        return self.git('rev-parse', 'HEAD')

    def publish(self, ref='refs/remotes/origin/dev', commit='HEAD'):
        self.git('update-ref', ref, self.git('rev-parse', commit))

    def check(self, paths=FILES):
        return subject.require_committed(self.root, paths)


class CommittedSourceTests(unittest.TestCase):
    def setUp(self):
        self.repo = Repository(self)

    def refused(self, reason, paths=FILES):
        with self.assertRaises(subject.SourceNotCommitted) as caught:
            self.repo.check(paths)
        self.assertEqual(reason, caught.exception.reason)
        return caught.exception.paths

    def test_clean_source_at_or_behind_dev_is_accepted(self):
        self.repo.publish()
        head = self.repo.git('rev-parse', 'HEAD')
        self.assertEqual(head, self.repo.check())
        # HEAD behind dev: the merge-base is HEAD itself.
        self.repo.write('agent_tools/beta.py', '# later dev edit\n')
        self.repo.commit('dev moves on')
        self.repo.publish()
        self.repo.git('checkout', '-q', '--detach', head)
        self.assertEqual(head, self.repo.check())

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
            self.repo.git('update-index', flag.replace('--', '--no-'), 'agent_tools/alpha.py')
            self.repo.git('checkout', '-q', '--', 'agent_tools/alpha.py')
        self.assertIsNotNone(self.repo.check())

    def test_unpushed_commit_runs_only_from_an_origin_ci_candidate_tip(self):
        self.repo.publish()
        self.repo.write('agent_tools/alpha.py', '# local commit\n')
        local = self.repo.commit('local only')
        self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.UNPUBLISHED))
        # A local branch named ci/* or another candidate's content does not count.
        self.repo.git('branch', 'ci/local')
        self.repo.git('checkout', '-q', '-b', 'other', 'HEAD~1')
        self.repo.write('agent_tools/alpha.py', '# another candidate\n')
        self.repo.publish('refs/remotes/origin/ci/other', self.repo.commit('other candidate'))
        self.repo.git('checkout', '-q', local)
        self.assertEqual(('agent_tools/alpha.py',), self.refused(subject.UNPUBLISHED))
        # The pushed candidate holding exactly these bytes admits them.
        self.repo.publish('refs/remotes/origin/ci/local', local)
        self.assertEqual(local, self.repo.check())

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
        before = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'audit_sources')
        namespace = {**dispatch.__dict__, '_guard': lambda: None, '_SOURCE': source, '_SOURCE_PINS': {'alpha': edited}}
        exec(compile(ast.Module(body=[before], type_ignores=[]), str(path), 'exec'), namespace)
        self.assertTrue(namespace['audit_sources']()['ok'])
        # GREEN: the dispatch boundary refuses the same unpublished bytes.
        operation = str(uuid4())
        with mock.patch.object(dispatch, '_SOURCE', source), \
             mock.patch.object(dispatch, '_require_committed', subject.require_committed), \
             self.assertRaises(dispatch.DispatchBlocked) as caught:
            dispatch._committed({'closure': ('alpha', 'beta')}, operation)
        self.assertEqual(('vm_readiness_target_source_unpublished', operation),
                         (caught.exception.reason, caught.exception.operation_identity))
        self.repo.git('checkout', '-q', 'HEAD~1')
        with mock.patch.object(dispatch, '_SOURCE', source), \
             mock.patch.object(dispatch, '_require_committed', subject.require_committed):
            dispatch._committed({'closure': ('alpha', 'beta')}, operation)
        self.repo.write('agent_tools/beta.py', '# dirty\n')
        with mock.patch.object(dispatch, '_SOURCE', source), \
             mock.patch.object(dispatch, '_require_committed', subject.require_committed), \
             self.assertRaises(dispatch.DispatchBlocked) as caught:
            dispatch._committed({'closure': ('alpha', 'beta')}, operation)
        self.assertEqual('vm_readiness_target_source_uncommitted', caught.exception.reason)


if __name__ == '__main__':
    unittest.main()
