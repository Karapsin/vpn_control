"""Committed-source rule for native dispatch (TEST-005).

A native action may run only source that is published for review. At dispatch:
  * the agent_tools/ tree, excluding agent_tools/tests/, is clean: every tracked
    file is a regular file byte-identical in the working tree and in HEAD (raw
    bytes, no filters), with HEAD's executable bit, none hidden by assume-unchanged
    or skip-worktree, none deleted, and no untracked or ignored file exists there
    except Python byte-code caches (__pycache__/*.pyc). readiness_vm_dispatch.json
    and tool_action_policy.json are part of that tree;
  * every other closure file (dispatch_source_closure: the scripts/ payloads the
    scenario bundle ships) is tracked, unhidden and byte-identical to HEAD;
  * HEAD's agent_tools/ tree without tests/, and those other files, equal those of
    one published commit.

Published means one of, in this order:
  1. reachable from origin/dev: the merge-base of HEAD with the last fetched
     refs/remotes/origin/dev;
  2. a gate-ledger entry (.rag_index/ci-gate/<sha>.json) that records the SHA as
     pushed to its ci/* branch or merged into dev;
  3. the current tip of an origin `ci/*` branch, as `git ls-remote` reports it at
     dispatch (bounded by _LS_REMOTE_SECONDS). When ls-remote fails, only 1 and 2
     count. A local branch or a remote-tracking ref set locally never counts.
Purely local, unpushed source is refused. The comparison reads content, not index
or fsmonitor state, so a stale index cannot hide an edit.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess

DEV = "refs/remotes/origin/dev"
CANDIDATES = "refs/heads/ci/*"
TREE = "agent_tools"
_EXCLUDED = "tests"
LEDGER = (".rag_index", "ci-gate")
# Gate outcomes that the gate records only after it pushed the SHA to ci/* or moved dev to it.
PUSHED_OUTCOMES = frozenset({"merged", "pending", "failed", "abandoned", "cleaned", "rebase-needed"})
_LEDGER_LIMIT = 256
_TIMEOUT_SECONDS = 60
_LS_REMOTE_SECONDS = 20
_SHA = re.compile(r"[0-9a-f]{40}\Z")

# Bases of a published reference.
BASIS_DEV, BASIS_LEDGER, BASIS_REMOTE = "origin-dev", "gate-ledger", "origin-ci"


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


def _environment():
    # Inherited GIT_DIR, GIT_INDEX_FILE or GIT_WORK_TREE could point the check
    # at another repository or index; only the explicit repository counts.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_LITERAL_PATHSPECS="1", GIT_OPTIONAL_LOCKS="0", LC_ALL="C", GIT_TERMINAL_PROMPT="0")
    return env


def _git(repository, *args, stdin=None, timeout=_TIMEOUT_SECONDS):
    try:
        result = subprocess.run(["git", "-C", str(repository), *args], input=stdin, capture_output=True,
                                timeout=timeout, env=_environment(), check=False,
                                **({} if stdin is not None else {"stdin": subprocess.DEVNULL}))
    except (OSError, subprocess.SubprocessError):
        raise SourceNotCommitted(GIT_UNAVAILABLE) from None
    if result.returncode:
        raise SourceNotCommitted(GIT_UNAVAILABLE)
    return result.stdout


def _tree(repository, commit, paths):
    """{path: blob} for the regular files of `paths` in `commit`."""
    found = {}
    if not paths:
        return found
    for record in _git(repository, "ls-tree", "-z", commit, "--", *paths).split(b"\0"):
        if not record:
            continue
        meta, _, name = record.partition(b"\t")
        mode, kind, blob = meta.split(b" ")
        if kind == b"blob" and mode in (b"100644", b"100755"):
            found[os.fsdecode(name)] = blob.decode()
    return found


def _root(repository):
    repository = Path(repository).resolve(strict=True)
    top = Path(os.fsdecode(_git(repository, "rev-parse", "--show-toplevel").strip())).resolve()
    if top != repository:
        raise SourceNotCommitted(GIT_UNAVAILABLE)
    return repository


def _flags(repository, pathspecs):
    flags = {}
    for record in _git(repository, "ls-files", "-v", "-z", "--", *pathspecs).split(b"\0"):
        if record:
            flags.setdefault(os.fsdecode(record[2:]), set()).add(record[:1])
    return flags


def _hidden(flags, paths):
    # ls-files -v: lowercase marks assume-unchanged, "S" skip-worktree.
    return [path for path in paths if any(tag.islower() or tag == b"S" for tag in flags[path])]


def _working_blobs(repository, paths):
    stdin = "".join(path + "\n" for path in paths).encode()
    working = _git(repository, "hash-object", "--no-filters", "--stdin-paths", stdin=stdin).decode().split()
    if len(working) != len(paths):
        raise SourceNotCommitted(DIRTY, paths)
    return dict(zip(paths, working))


def _check_paths(repository, paths):
    """Every path is tracked, unhidden, a regular file and byte-identical in HEAD; returns HEAD's blobs."""
    outside = [path for path in paths if "\n" in path or Path(path).is_absolute() or ".." in Path(path).parts]
    if outside:
        raise SourceNotCommitted(UNTRACKED, outside)
    flags = _flags(repository, paths)
    untracked = [path for path in paths if path not in flags]
    if untracked:
        raise SourceNotCommitted(UNTRACKED, untracked)
    hidden = _hidden(flags, paths)
    if hidden:
        raise SourceNotCommitted(HIDDEN, hidden)
    head = _tree(repository, "HEAD", paths)
    missing = [path for path in paths if path not in head]
    if missing:
        raise SourceNotCommitted(DIRTY, missing)
    irregular = [path for path in paths if not (repository / path).is_file() or (repository / path).is_symlink()]
    if irregular:
        raise SourceNotCommitted(DIRTY, irregular)
    working = _working_blobs(repository, paths)
    dirty = [path for path in paths if working[path] != head[path]]
    if dirty:
        raise SourceNotCommitted(DIRTY, dirty)
    return head


def _cache_file(relative):
    parts = relative.split("/")
    return len(parts) > 1 and parts[-2] == "__pycache__" and parts[-1].endswith(".pyc")


def _check_tree(repository):
    """agent_tools/ without tests/ is clean: tracked, unhidden, unmodified, undeleted, nothing untracked or ignored."""
    excluded = TREE + "/" + _EXCLUDED + "/"
    others = [os.fsdecode(path) for path in _git(repository, "ls-files", "--others", "-z", "--", TREE + "/").split(b"\0") if path]
    untracked = sorted(path for path in others if not path.startswith(excluded) and not _cache_file(path))
    if untracked:
        raise SourceNotCommitted(UNTRACKED, untracked)
    head = {}
    for record in _git(repository, "ls-tree", "-r", "-z", "HEAD", "--", TREE + "/").split(b"\0"):
        if not record:
            continue
        meta, _, name = record.partition(b"\t")
        path = os.fsdecode(name)
        if not path.startswith(excluded):
            mode, _, blob = meta.decode().split(" ")
            head[path] = (mode, blob)
    irregular = sorted(path for path, (mode, _) in head.items() if mode not in ("100644", "100755"))
    if irregular:
        raise SourceNotCommitted(DIRTY, irregular)
    flags = _flags(repository, [TREE + "/"])
    tracked = {path for path in flags if not path.startswith(excluded)}
    added = sorted(tracked - set(head))  # staged new files are not committed
    if added:
        raise SourceNotCommitted(DIRTY, added)
    hidden = _hidden(flags, sorted(tracked))
    if hidden:
        raise SourceNotCommitted(HIDDEN, hidden)
    paths = sorted(head)
    absent = []
    for path in paths:
        try:
            info = os.lstat(repository / path)
        except FileNotFoundError:
            absent.append(path)
            continue
        if not stat.S_ISREG(info.st_mode) or bool(info.st_mode & 0o111) != (head[path][0] == "100755"):
            absent.append(path)
    if absent:
        raise SourceNotCommitted(DIRTY, absent)
    working = _working_blobs(repository, paths) if paths else {}
    dirty = [path for path in paths if working[path] != head[path][1]]
    if dirty:
        raise SourceNotCommitted(DIRTY, dirty)


def _tree_keys(repository, commits):
    """{commit: entries of <commit>:agent_tools without tests} for the commits that exist; one git call."""
    commits = list(dict.fromkeys(commits))
    if not commits:
        return {}
    raw = _git(repository, "cat-file", "--batch", stdin="".join(commit + ":" + TREE + "\n" for commit in commits).encode())
    keys, offset = {}, 0
    for commit in commits:
        end = raw.index(b"\n", offset)
        header = raw[offset:end].split(b" ")
        offset = end + 1
        if len(header) != 3 or header[1] not in (b"tree", b"blob", b"commit", b"tag"):
            continue  # "<name> missing" or an ambiguous name: no key
        size = int(header[2])
        body, offset = raw[offset:offset + size], offset + size + 1
        if header[1] != b"tree":
            keys[commit] = None
            continue
        entries, position = [], 0
        while position < len(body):
            space = body.index(b" ", position)
            nul = body.index(b"\0", space)
            mode, name, oid = body[position:space], body[space + 1:nul], body[nul + 1:nul + 21]
            position = nul + 21
            if name != _EXCLUDED.encode():
                entries.append((mode, name, oid))
        keys[commit] = tuple(entries)
    return keys


def _ledger(repository):
    """SHAs the gate ledger records as pushed or merged, newest first."""
    directory = repository.joinpath(*LEDGER)
    try:
        names = [entry for entry in os.scandir(directory) if entry.name.endswith(".json") and _SHA.fullmatch(entry.name[:-5])]
    except OSError:
        return []
    names.sort(key=lambda entry: entry.stat(follow_symlinks=False).st_mtime_ns, reverse=True)
    found = []
    for entry in names[:_LEDGER_LIMIT]:
        try:
            if not entry.is_file(follow_symlinks=False):
                continue
            value = json.loads(Path(entry.path).read_bytes())
        except (OSError, ValueError):
            continue
        if type(value) is dict and value.get("sha") == entry.name[:-5] and value.get("outcome") in PUSHED_OUTCOMES:
            found.append(entry.name[:-5])
    return found


def _remote_candidates(repository):
    """Current origin ci/* tips from ls-remote, or None when ls-remote fails (offline, refused, slow)."""
    try:
        raw = _git(repository, "ls-remote", "--refs", "origin", CANDIDATES, timeout=_LS_REMOTE_SECONDS)
    except SourceNotCommitted:
        return None
    tips = []
    for line in raw.decode("ascii", "replace").splitlines():
        sha, _, ref = line.partition("\t")
        if _SHA.fullmatch(sha) and ref.startswith("refs/heads/ci/"):
            tips.append(sha)
    return sorted(set(tips))


def _dev_reference(repository):
    try:
        return _git(repository, "merge-base", "HEAD", DEV).decode().strip()
    except SourceNotCommitted:
        return None  # no dev ref or no common history


def published_reference(repository, paths=(), *, tree=True):
    """(reference, basis) of the first published commit equal to HEAD on `paths` and, with tree, on agent_tools/."""
    repository = Path(repository)
    paths = sorted(set(paths))
    head_paths = _tree(repository, "HEAD", paths)
    head_key = _tree_keys(repository, ["HEAD"]).get("HEAD") if tree else None

    def matches(candidates):
        keys = _tree_keys(repository, [sha for sha, _ in candidates]) if tree else {}
        for sha, basis in candidates:
            if tree and (sha not in keys or keys[sha] != head_key):
                continue
            if paths and _tree(repository, sha, paths) != head_paths:
                continue
            return sha, basis
        return None

    first = None
    local = []
    dev = _dev_reference(repository)
    if dev is not None:
        local.append((dev, BASIS_DEV))
        first = dev
    local.extend((sha, BASIS_LEDGER) for sha in _ledger(repository))
    found = matches(local)
    if found is not None:
        return found
    remote = _remote_candidates(repository)
    if remote:
        present = []
        for sha in remote:
            try:
                _git(repository, "cat-file", "-e", sha + "^{commit}")
            except SourceNotCommitted:
                continue  # not fetched: its content cannot be compared
            present.append((sha, BASIS_REMOTE))
        found = matches(present)
        if found is not None:
            return found
    base = _tree(repository, first, paths) if first and paths else {}
    raise SourceNotCommitted(UNPUBLISHED, [path for path in paths if base.get(path) != head_paths.get(path)]
                             or ([TREE + "/"] if tree else paths))


def require_committed(repository, paths):
    """Refuse unless every path is clean and published; return the reference commit."""
    repository = Path(repository).resolve(strict=True)
    paths = sorted(set(paths))
    if not paths:
        return None
    outside = [path for path in paths if "\n" in path or Path(path).is_absolute() or ".." in Path(path).parts]
    if outside:
        raise SourceNotCommitted(UNTRACKED, outside)
    repository = _root(repository)
    _check_paths(repository, paths)
    return published_reference(repository, paths, tree=False)[0]


def require_published_tree(repository, paths=()):
    """The dispatch rule: agent_tools/ (without tests/) clean, `paths` clean, both equal to one published commit.

    Returns {"reference": sha, "basis": ..., "head": HEAD sha}.
    """
    repository = Path(repository).resolve(strict=True)
    paths = sorted(set(paths))
    outside = [path for path in paths if "\n" in path or Path(path).is_absolute() or ".." in Path(path).parts]
    if outside:
        raise SourceNotCommitted(UNTRACKED, outside)
    repository = _root(repository)
    _check_tree(repository)
    extra = [path for path in paths if not path.startswith(TREE + "/")]
    _check_paths(repository, extra)
    head = _git(repository, "rev-parse", "HEAD").decode().strip()
    reference, basis = published_reference(repository, extra, tree=True)
    return {"reference": reference, "basis": basis, "head": head}



def commit_exists(repository, sha):
    """Whether `sha` names a commit of this repository (a recorded submit SHA, no network)."""
    if type(sha) is not str or not _SHA.fullmatch(sha):
        return False
    try:
        _git(Path(repository), "cat-file", "-e", sha + "^{commit}")
    except SourceNotCommitted:
        return False
    return True
