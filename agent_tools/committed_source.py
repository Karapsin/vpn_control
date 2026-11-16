"""Committed-source rule for native dispatch.

A native action may run only source that is published for review. Every file
of its computed closure (dispatch_source_closure) must be:
  * tracked by git and a regular file;
  * not hidden by assume-unchanged or skip-worktree, so `git status` would
    show any edit;
  * byte-identical in the working tree and in HEAD (raw bytes, no filters);
  * in HEAD, byte-identical to one published commit: the merge-base of HEAD
    with origin/dev (reachable from dev), or the tip of an origin `ci/*`
    candidate branch (native testing before dev moves).

Purely local, unpushed source is refused. The rule reads the remote-tracking
refs as last fetched; it never fetches, so it opens no connection. The check
compares content, not index or fsmonitor state, so a stale index cannot hide an
edit.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

DEV = "refs/remotes/origin/dev"
CANDIDATES = "refs/remotes/origin/ci/"
_TIMEOUT_SECONDS = 60


class SourceNotCommitted(ValueError):
    """`reason` is one of the finite codes below; `paths` names the files."""

    def __init__(self, reason, paths=()):
        self.reason = reason
        self.paths = tuple(paths)
        super().__init__(reason + (":" + ",".join(self.paths) if self.paths else ""))


# Finite reasons.
GIT_UNAVAILABLE = "source_git_unavailable"
UNTRACKED = "source_untracked"
HIDDEN = "source_hidden_from_status"
DIRTY = "source_uncommitted"
UNPUBLISHED = "source_unpublished"


def _git(repository, *args, stdin=None):
    # Inherited GIT_DIR, GIT_INDEX_FILE or GIT_WORK_TREE could point the check
    # at another repository or index; only the explicit repository counts.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_LITERAL_PATHSPECS="1", GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    try:
        result = subprocess.run(["git", "-C", str(repository), *args], input=stdin, capture_output=True,
                                timeout=_TIMEOUT_SECONDS, env=env, check=False)
    except (OSError, subprocess.SubprocessError):
        raise SourceNotCommitted(GIT_UNAVAILABLE) from None
    if result.returncode:
        raise SourceNotCommitted(GIT_UNAVAILABLE)
    return result.stdout


def _tree(repository, commit, paths):
    """{path: blob} for the regular files of `paths` in `commit`."""
    found = {}
    for record in _git(repository, "ls-tree", "-z", commit, "--", *paths).split(b"\0"):
        if not record:
            continue
        meta, _, name = record.partition(b"\t")
        mode, kind, blob = meta.split(b" ")
        if kind == b"blob" and mode in (b"100644", b"100755"):
            found[os.fsdecode(name)] = blob.decode()
    return found


def require_committed(repository, paths):
    """Refuse unless every path is clean and published; return the reference commit."""
    repository = Path(repository).resolve(strict=True)
    paths = sorted(set(paths))
    if not paths:
        return None
    outside = [path for path in paths if "\n" in path or Path(path).is_absolute() or ".." in Path(path).parts]
    if outside:
        raise SourceNotCommitted(UNTRACKED, outside)
    top = Path(os.fsdecode(_git(repository, "rev-parse", "--show-toplevel").strip())).resolve()
    if top != repository:
        raise SourceNotCommitted(GIT_UNAVAILABLE)

    flags = {}
    for record in _git(repository, "ls-files", "-v", "-z", "--", *paths).split(b"\0"):
        if record:
            flags.setdefault(os.fsdecode(record[2:]), set()).add(record[:1])
    untracked = [path for path in paths if path not in flags]
    if untracked:
        raise SourceNotCommitted(UNTRACKED, untracked)
    # ls-files -v: lowercase marks assume-unchanged, "S" skip-worktree.
    hidden = [path for path in paths if any(tag.islower() or tag == b"S" for tag in flags[path])]
    if hidden:
        raise SourceNotCommitted(HIDDEN, hidden)

    head = _tree(repository, "HEAD", paths)
    missing = [path for path in paths if path not in head]
    if missing:
        raise SourceNotCommitted(DIRTY, missing)
    irregular = [path for path in paths if not (repository / path).is_file() or (repository / path).is_symlink()]
    if irregular:
        raise SourceNotCommitted(DIRTY, irregular)
    stdin = "".join(path + "\n" for path in paths).encode()
    working = _git(repository, "hash-object", "--no-filters", "--stdin-paths", stdin=stdin).decode().split()
    dirty = [path for path, blob in zip(paths, working) if blob != head[path]]
    if len(working) != len(paths) or dirty:
        raise SourceNotCommitted(DIRTY, dirty or paths)

    references = []
    try:
        references.append(_git(repository, "merge-base", "HEAD", DEV).decode().strip())
    except SourceNotCommitted:
        pass  # no dev ref or no common history; a ci/* tip may still match
    listed = _git(repository, "for-each-ref", "--format=%(objectname)", CANDIDATES).decode().split()
    references.extend(sorted(set(listed)))
    for reference in references:
        if _tree(repository, reference, paths) == head:
            return reference
    base = _tree(repository, references[0], paths) if references else {}
    raise SourceNotCommitted(UNPUBLISHED, [path for path in paths if base.get(path) != head[path]])
