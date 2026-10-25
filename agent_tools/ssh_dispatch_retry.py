"""Bounded packet regeneration for reviewed, wholly unsubmitted owners only.

This internal API never repeats a workflow. Its caller supplies a pure builder,
a single target submission, and a held original-intent observer. Unknown work,
ordinary transport failures and post-execution guards never authorize retry.
"""
from __future__ import annotations

import math
from pathlib import Path
import re
import stat
import time
import uuid

from . import readiness, ssh_dispatch_admission as admissions, ssh_transport as transport

_SHA = re.compile(r'[0-9a-f]{64}\Z')
_REFRESHABLE = frozenset({'prepared_context_stale','connection_generation_changed'})


def _journal(root, operation):
    path=root
    for name in ('.rag_index','ssh-dispatch-retry',operation):
        path=path/name
        try:path.mkdir(mode=0o700)
        except FileExistsError:pass
        info=path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=__import__('os').getuid()
                or info.st_mode & 0o077):
            raise ValueError('dispatch_retry_journal_owner')
    return readiness.RecoveryJournal(path)


def run_original(root, host, operation_identity, *, build, submit,
                 prove_operation_unsubmitted, deadline, admission_factory=None):
    """Return ``submit(argv)``; at most three original-target preparation attempts.

    ``build(admission, attempt)`` is pure and returns a bound transport packet.
    ``submit(argv)`` performs exactly one target submission and must not swallow
    the central typed refusal. ``prove_operation_unsubmitted(proof, attempt)``
    checks the caller's retained original intent/source/generation and absence
    of ALL earlier target effects; it returns that public intent's SHA256, or
    None. It is an internal reviewed callback, never a public ownership flag.

    ``admission_factory(root, host, operation_identity, deadline=...)`` is a
    context manager yielding a fresh transport Admission. GUI owners must also
    refresh and attach their guest/session observers there. The caller must
    unwind any old admission before entering this API. Private input stays in
    the owner's submit closure and never enters journals, hashes or messages.
    """
    readiness._identity(operation_identity)
    root=Path(root).resolve(strict=True)
    if (type(host)is not str or not callable(build) or not callable(submit)
            or not callable(prove_operation_unsubmitted)
            or not isinstance(deadline,(float,int)) or not math.isfinite(deadline)
            or deadline<=time.monotonic()):
        raise ValueError('invalid_dispatch_retry_scope')
    if admissions.current(root,host) is not None:
        raise ValueError('dispatch_retry_requires_unwound_admission')
    factory=admissions.admitted_transport if admission_factory is None else admission_factory
    if not callable(factory):raise ValueError('invalid_dispatch_retry_factory')
    invocation=uuid.uuid4().hex
    with _journal(root,operation_identity).locked(deadline=deadline) as journal:
        if journal.lookup('invocation') is not None:
            raise readiness.ReadinessBlocked('original_dispatch_outcome_unknown',operation_identity)
        journal.record('invocation',{'operationId':operation_identity,'host':host,
                                    'invocation':invocation,'replayAllowed':False})
        for attempt in range(1,4):
            if time.monotonic()>=deadline:
                raise readiness.ReadinessBlocked('readiness_deadline',operation_identity)
            with factory(root,host,operation_identity,deadline=deadline) as admission:
                if (not isinstance(admission,admissions.Admission) or admission.closed
                        or admission.root!=root or admission.host!=host
                        or admission.operation_identity!=operation_identity
                        or admissions.current(root,host) is not admission):
                    raise ValueError('dispatch_retry_admission_identity')
                argv=build(admission,attempt)
                carried=(argv.dispatch_admission if isinstance(argv,transport.BoundInlineArgv)
                         else getattr(argv,'dispatch_admission',None))
                if carried is not admission:
                    raise ValueError('dispatch_retry_packet_unbound')
                digest=transport.argv_sha256(argv)
                journal.record('attempt-'+str(attempt),{'operationId':operation_identity,
                    'attempt':attempt,'originalArgvSha256':digest,'replayAllowed':False})
                try:
                    result=submit(argv)
                except (transport.PrelaunchReadinessRefusal,transport.StagedExecutionUnsubmitted) as proof:
                    if (proof.operation_identity!=operation_identity or proof.argv_sha256!=digest
                            or proof.reason not in _REFRESHABLE):raise
                    staged=type(proof)is transport.StagedExecutionUnsubmitted
                    if staged:
                        if (proof.transfer_submitted is not True
                                or proof.target_executable_started is not False
                                or proof.target_child_handle_returned is not False):raise
                    elif (type(proof)is not transport.PrelaunchReadinessRefusal
                            or proof.executable_started is not False
                            or proof.child_handle_returned is not False):raise
                    owner_sha=prove_operation_unsubmitted(proof,attempt)
                    if type(owner_sha)is not str or _SHA.fullmatch(owner_sha)is None:raise
                    journal.record('unsubmitted-'+str(attempt),{'operationId':operation_identity,
                        'attempt':attempt,'originalArgvSha256':digest,'ownerIntentSha256':owner_sha,
                        'transferSubmitted':staged,'targetExecutableStarted':False,
                        'reason':proof.reason,'replayAllowed':False})
                    if attempt==3:raise
                else:
                    journal.record('returned-'+str(attempt),{'operationId':operation_identity,
                        'attempt':attempt,'replayAllowed':False})
                    return result
            # The complete old admission (including guest guards) is closed
            # before the next readiness factory and pure packet builder run.
