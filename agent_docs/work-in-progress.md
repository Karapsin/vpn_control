# Current MCP repair work; Windows parity deferred

The user deferred the Windows parity plan on 2026-10-15 and requested the
MCP/tooling repair described below. The later instructions in the active chat
permit subagents and authorize stopping all prior unknown or historical test VM
sessions and SSH connections before fresh validation. Preserve disks, fixtures,
source edits, original evidence and durable job/lease records; no purge or replay
is authorized. Do not resume Windows product acceptance, H14, visuals or the original
Windows plan without the user resuming it. Linux, Android and macOS product-native
and visual work also remains deferred. No release.

The first repair delivery, `843c4740474a7b1c4038c51f7a941500dae0ce01`,
passed the managed prepush (6,695 pooled agent tests, 186 platform skips) and was
pushed to `origin/dev`. Windows CI then failed importing the core source capture;
that SHA is not a completed delivery. Original logs and ten exact beforeimages
are preserved in `.runtime/mcp-windows-core-capture-failure-843c4740474a/`.
CPython 3.12.10 gives pathname and descriptor `ctime` different Windows meanings;
the old loader compares them directly. The original exception did not retain its
failed field. The repair preserves full generation checks separately for each
API and cross-binds comparable object metadata. A preserved-function regression
and the native Windows counterfactual distinguish this mechanism; final new-SHA
prepush and all five development workflows remain required.
The unchanged-file assertion reproduced RED on the exact preserved function and
GREEN on the fix using physical file IO and the documented Windows metadata
projection. The expanded 28-check slice passed, with two native Windows bootstrap
skips; 102 selector and seven workflow/checkout controls passed. A macOS temporary
path alias in the new wrapper initially failed after successful capture; its
beforeimage and failure remain preserved, and resolving the owned fixture root
passed the same assertion. Evidence is the packet's `causal-local-v1/`,
`causal-local-v2/` and `dependency-review/`; these local results do not claim
native Windows acceptance.

Fast Checks on the same first SHA was subsequently cancelled after 45m14s;
GitHub's annotation explicitly says the 45-minute job limit was exceeded. Its
agent-test phase consumed 40m43s after setup, and 13 later steps never ran.
There is no per-module timing artifact, so no particular slow or hung test is
inferred. Original logs, selection and beforeimages remain in
`.runtime/mcp-fast-checks-timeout-843c4740474a/`. The workflow repair gives the job
90 minutes and the agent-test phase 50 minutes while retaining every command,
selection and the existing managed-command bound. Causal coverage runs an inert
saved producer under scaled real deadlines read from the original/current
configuration; the actual new-SHA GitHub run remains required proof.
The identical completion assertion was actual RED on the preserved 45-minute
configuration and GREEN on the fix. All four deadline controls passed, including
refusal beyond the 50-minute phase cap; 102 selector and nine workflow/checkout
controls passed. The parser found no errors across 1,344 source versions, and
all five saved-producer children closed. Exact raw streams, markers and identical
producer bytes remain in `.runtime/mcp-fast-workflow-budget-843c4740474a/`.

The healthy local prepush v8 was deliberately cancelled before that workflow
edit. Its 3,280 partial timing observations are not a passing receipt. Exactly
one guarded signal went to its owned runner; the worker/session/fixture closed,
the lease is free and source closing matched. Evidence is
`.runtime/mcp-repair-execution-2026-10-15/prepush-final-v8/cancellation/`.
Fresh final prepush and exact-SHA delivery follow the final workflow/content edit.

The second delivery, `c68058eb64f8452207bf2091bd2950e5a06231da`, passed a
fresh managed prepush (6,660 pooled tests, 184 platform skips) and was pushed.
Windows then passed core import, all seven fingerprint checks and all nine
collector controls. Its new native counterfactual stopped at the fixture's strict
metadata assertion: `os.utime()` did not establish distinct creation/change
clocks. The actual fixed capture had already succeeded. The original failure,
numeric metadata and exact beforeimages remain in
`.runtime/mcp-ci-c68058eb-failure/`. The fixture correction must physically set
and verify the owned file's change clock, retain the strict assertion and prove
the preserved original capture RED and fixed capture GREEN on Windows.

macOS on that same SHA failed the resource-monitor test's assumption that a
50-millisecond timeout always lets a fake child journal its startup. The monitor
retained the uncertain receipt and live child. The original log and exact
beforeimages remain in `.runtime/mcp-ci-c68058eb-macos-failure/`. Deterministic
dispatch/timeout coverage must preserve one attempt, no replay and child survival;
the original physical subprocess scenario and fresh native CI remain required.
Neither failure authorizes relaxing production guards or claiming that SHA green.

Both fixture corrections reproduced their retained assertions RED and passed
GREEN. Windows' portable clock model retains physical file/descriptor IO; its
12 controls passed without skips. macOS used actual owned subprocess dispatch
with a gated child journal; all 15 routine controls passed without skips, with
one dispatch, an uncertain receipt and an advancing surviving child. Every owned
test process closed. These are tooling fixtures, not deferred product acceptance.
Evidence is `.runtime/mcp-core-native-setup-c68058eb/summary.json` and the macOS
packet's `focused-v1/causal-summary.json`; actual new-SHA Windows CI remains required.

The new dependency declaration initially omitted the exact original macOS test
hash. Selection correctly refused it. Its preserved manifest reproduced RED;
adding the reviewed original hash passed the same selection and all 102 selector
and checkout controls, retaining every scope and historical pin. Evidence is
`.runtime/mcp-repair-execution-2026-10-15/fixture-dependency-check-v10/`.
A physical Git `autocrlf` roundtrip also reproduced RED with the old attributes
and GREEN with exact byte preservation for both new macOS inputs; the Windows
beforeimage stayed exact under both. All eight Git children and temporary roots
closed. Evidence is the Windows failure packet's `checkout-roundtrip/summary.json`.
Fresh versioning, managed prepush and all five exact-SHA workflows follow these
final content edits; none of the retained failed runs is relabeled successful.

The user's subsequently identified current SSH client is explicitly excluded
from cleanup. It received no signal. Previously closed sessions remain closed;
no global-zero-SSH claim applies while that user client is open.

Fast Checks on `c68058eb64f8452207bf2091bd2950e5a06231da` subsequently
completed its affected suite inside the revised time budget but failed: 6,660
tests, 18 failures, 135 errors and 175 skips. Its 153 failure blocks represent
150 distinct test IDs across 36 modules. The complete original log, 58 exact
beforeimages and disjoint 77/40/36 ownership matrix remain in
`.runtime/mcp-ci-c68058eb-fast-failure/`. Android and Linux passed that SHA;
Windows, macOS and Fast Checks failed. It is not a completed delivery.

The healthy local prepush v10 was cancelled before these further edits. Exactly
one identity-guarded signal went to its owned runner. Its SDK, worker, descendants
and fixture closed, the lease is free, and source closing remained
`4f344a9366e4229e83e2e1d3ff4774f21b1bdc61f884d0db05bc01800f59476b`.
Its 1,627 partial observations supply no final unittest count or passing receipt.
Evidence is the execution packet's `prepush-final-v10/cancellation/`.

Runtime diagnostics distinguish local Python 3.14.3 from hosted Python 3.12.15.
Isolated owned Python 3.12.14, 3.12.3 and 3.12.15 runtimes leave the prepared
environment and user configuration intact. Actual copied-source 3.12.3 cache
creation followed by 3.12.15 consumption reproduces both strict code-identity
refusals: unchanged timestamp-valid bytecode has different line tables. Preparing
3.12.15 first passes the same guards. The original hosted bytecode was not
retained, so that exact artifact remains an inference. Evidence is the Fast
packet's `mixed-patch-cache-v1/`; no source guard is relaxed.

All seven historical gzip builders likewise reproduce their fixed-output
refusal on Python 3.12; changing only the gzip OS-header byte restores all 14
original output hashes. Their execution is confined to inert historical test
graphs, outside the current public adapter/import closure. The scoped fixture
compatibility repair preserves every production source and authority pin.
Missing annotation context also reproduces on Python 3.12 in extracted/inert
test helpers. Those findings led to the finite corrections and causal checks
recorded below; the original failed workflow remains failed.

MCP startup now captures the loader and native custody backend from held raw
source in a private package before native requests. The complete original entry
really refuses unchanged timestamp-valid Python 3.12.3 bytecode under 3.12.15;
the fixed entry passes with private fresh source, unchanged cache generations
and no native effects. The actual entry proof and eight bootstrap controls
are in the Fast packet's `entry-source-bootstrap-v1/`. Fast Checks prepares its
Python runtime and dependencies before hygiene and installs only the qemu-img
prerequisite for owned file tests; it starts no VM. All strict code/source guards
remain intact.

The subsequent source-frozen slices reconcile all 153 original blocks: 151
blocks representing 148 test IDs pass locally; two original Linux-native cases
still require the next hosted run. Both Python 3.12.15 and 3.14.3 pass the 40-case
slice and the complete 245-case historical base/server slice, with 62 existing
Windows-only skips. The historical gzip slice and catalogue pass all 59 checks
per runtime without skips. Preserved actual RED/GREEN also covers the newly
exposed fixture mistakes: missing local import, already-byte program output,
complete original base source, function-local gzip imports, synthetic action
hash binding and nested unittest module setup. The final routine lifecycle
counterfactual uses the exact full unfixed file under its actual owned filename;
its fixed routine checks pass both runtimes. No native capture or historical
source/authority pin was refreshed. Evidence and exact ID/receipt links are in
`common-focus-v3/`, `common-focus-v4/` and the corresponding failure packets.

The remaining Linux cases are the diagnostic output classifier and one-use HTTP
listener. The latter's new routine control preserves the exact old positive
method and uses a real server-first close, TIME_WAIT row and EADDRINUSE before
its strict served assertion. The fixed client sends FIN before the real parser
dispatches and must reach strict served without replay. Darwin probes preserve
both actual served receipts but cannot prove Linux binding policy; they are not
claimed as causal Linux RED. The unchanged worker and ownership/free-port guards
remain strict. Windows CI additionally enrolls the raw bootstrap and held
historical archive controls. Final versioning, fresh SDK/native staging,
managed prepush and all five exact-SHA workflows remain completion gates; prior
VMs stay closed and the user's current SSH client remains untouched.

The next managed prepush, v11, found one additional isolated runner fixture
failure: its copied MCP omitted the newly required loader and custody backend.
Its original partial failure and 117-input archive remain preserved; its runner,
worker, SDK, fixture and lease closed before edits, and source closing matched.
The exact unchanged positive then reproduced RED with the full missing-loader
trace. Adding only the two explicit copied inputs and finite dependency scopes
passed that same assertion and all nine self-input checks on Python 3.12.15 and
3.14.3, with no skips or leaked children/descriptors. Historical pins, accepted
beforeimages and unknown-dependency refusals remain unchanged. Evidence is
`.runtime/mcp-runner-self-input-failure-d2290d35/`; v11 remains cancelled and
supplies no passing receipt.

Fresh twelve-tool SDK checks and inert saved-file SSH staging passed under their
recorded source bracket. The receiver verified exact saved bytes without executing
the inert source; commands remained below 60,000 bytes, all owned sessions closed,
and original records stayed unchanged. A separate invalid-input UNKNOWN remains
preserved and is not replayed. Final metadata, a new source freeze, fresh tool and
staging qualification, managed prepush and all five exact-SHA workflows follow
the runner fixture correction. No prior VM or connection is restored.

The next delivery, `308172ff07e7246a02129ec436193ed9bc81f44e`, passed
all 17 managed prepush checks (6,702 agent tests, 187 skips, zero failures/errors)
and was pushed with a clean worktree. Windows then passed the native core,
collector, loader bootstrap and fingerprint groups, including the actual
Python 3.12.10 creation/change clock RED/GREEN discriminator. The historical
archive group passed eight cases but errored in two retained-context controls:
their POSIX-only dependency import legitimately leaves `closure.base=None` on
Windows, before the intended source-mismatch predicate can run. The complete
original Windows log and 64 exact commit beforeimages remain in
`.runtime/mcp-ci-308172ff-evidence-2026-10-15/windows-failure/`.

The same two original methods reproduced those exact errors under only that
missing-dependency state on Python 3.12.15 and 3.14.3. Supplying the actual current
producer for each negative case preserves its real filename, mismatched full
source hash and strict `package-fixed-source` assertion; its original reference
and bytes are restored on success or exception. A new routine control runs both
cases from the unavailable dependency state and checks restoration. The same two
assertions and all eleven module controls then passed on both runtimes without
skips or leaks. Production code, all historical source/authority pins and finite
dependency scopes remain unchanged. Local causal evidence is in that failure
packet's `local-causal-v1/`; its private harness syntax error is retained separately
and is not project RED. The original remote runs remain untouched. Fresh final
metadata, managed validation and all five workflows for the next exact pushed SHA
remain required; the failed Windows run is never relabeled successful.

Android, Linux and macOS subsequently passed that same SHA. macOS reran the
original resource-monitor scenario twice, with all fifteen checks passing each
time. Fast Checks exceeded its explicit fifty-minute agent-test phase after the
27-test serial close gate. Its complete log has no terminal worker report or
per-test progress identifying the slow or stalled test, so the cause remains
unknown. All five original terminal results, annotations, exact beforeimages and
the source-derived serial topology remain in
`.runtime/mcp-ci-308172ff-evidence-2026-10-15/`; this SHA is a failed delivery.

The follow-up gives only explicit hosted CI calls two deterministic complementary
shards in separate checkouts. Complete global selection and unknown-dependency
refusals precede partitioning; default managed checks, include selection, runner
isolation pins and the existing time bounds remain unchanged. A final job requires
both current-attempt parents to succeed and verifies source-bound complete,
disjoint coverage. Bounded public progress omits private identities, reasons and
raw output; missing closure, source drift, cancellation and incomplete evidence
cannot produce a successful receipt. The retained serial selector and original
workflow support a physical scaled workload counterfactual. This demonstrates
partition throughput, not the unobserved cause of the hosted timeout.

Static inspection also found an unbounded EOF receive loop and teardown in the
inert local QGA test fixture. The repair adds absolute work and cleanup deadlines,
EOF and line bounds, and cleanup through exact owned handles. The original
28-case native method and production dispatcher remain unchanged. Its preserved
reader regression requires an actual physical EOF witness before the completion
watchdog, distinguishing causal failure from startup delay. Original helper
beforeimages and independent reviews remain in the same packet's
`native148-bounds/`. On both Python 3.12.15 and 3.14.3 the preserved reader produced
the sole expected failure after verified kernel EOF, all ten fixed controls
passed without skips, and the original 105-test module passed with eleven
platform skips. Every owned child and log handle closed; source closing matched.

The first CI-focused run exposed two test issues: an undeclared optional YAML
import and an old tail oracle counting the new public artifact step as build
work. Exact failed source and logs remain in `fast-timeout/shard-repair/focused-v1/`.
The corrected strict standard-library reader runs with site packages disabled;
the tail reader admits only the entire exact public uploader block. Actual
preserved-source RED/current-source GREEN pairs cover both failures without
changing the original validation assertions. Both runtimes passed 53 focused
checks, including the serial deadline RED/two-checkout GREEN, cancellation,
privacy, unknown dependencies and current-attempt coverage. The selector and
runner input slice also passed 98 checks per runtime, and workflow syntax passed.
All source brackets and owned resources closed. Evidence is in `focused-v2/` and
the execution packet's `final-integration-v14/`.

Native Linux acceptance, final metadata, fresh managed prepush and all five
workflows for the next exact pushed SHA remain required. No old VM or connection
is restored; the user's identified client remains untouched.

Managed prepush v14 stopped at its first whitespace check because the workflow
had one extra blank line at EOF. No test worker started; the SDK closed with
unchanged source. The complete failed check and exact workflow remain in
`prepush-final-v14/`. The same check reproduced RED before removing that single
blank line and passed GREEN afterward. Fresh final receipts follow this edit.

Managed prepush v15 found four failures in the old workflow reader's single-job
assumption. Its 3,414 partial observations comprise 3,399 successes, eleven skips
and those four failures; no final unittest aggregate or passing receipt exists.
The owned runner was cancelled once and fully closed before edits, with unchanged
source. Its final report, partial timings, original sources and closing evidence
remain in `prepush-final-v15/`. A static review also identified the discovery
fixture's missing copy of the new evidence helper.

The original two test files then reproduced the exact five failures on Python
3.12.15 and 3.14.3; the original compiler-order counterfactual still passed.
The clean causal evidence and full beforeimages remain in
`.runtime/mcp-fast-interpreter-order-failure-2026-10-15/red-v2/`.
An earlier harness cache-prefix failure is retained separately and is not project
RED. The fixes scope the reader to explicit jobs, reject duplicate local labels,
admit only the exact two first-shard suffixes and complete public uploader, and
copy the one missing helper. Original action equality and source guards remain
intact; checks now also cover preparation in both shard jobs. Fresh focused GREEN,
final managed validation and all five exact-SHA workflows follow this checkpoint.

The next delivery, `9a6d4b3cf4850750253af8339a12b9d7b425e5f1`, passed
all seventeen managed prepush checks, including 6,761 pooled tests with 187
platform skips. Android, Linux and macOS packaging passed on that SHA. Windows
then failed its tooling fixture step with twelve failures and 41 errors; Fast
Checks' first shard failed five whole-observer cases at `boot-binary-trust`;
the second shard failed five preparation cases at `source-lock-birth-changed`.
Neither the local receipt nor the three successful workflows qualifies this SHA
as a completed delivery. Complete logs, exact pushed beforeimages and the
53-block Windows diagnosis remain in
`.runtime/mcp-ci-9a6d4b3c-windows-full-v1/`; the Linux five-block log is in
`.runtime/mcp-ci-9a6d4b3cf4850750253af8339a12b9d7b425e5f1-fast-main-failure-v1/`.

The second Fast Checks shard's completed log records 3,562 tests with one
failure, four errors and 115 platform skips. All five cases hit the same earlier
source-lock birth guard. The fixture invokes the actual read-lock constructor,
which observes a positive Linux process birth, then writes the synthetic value
123 into its private process table. The unchanged production closing guard
correctly refuses that inconsistent identity; Darwin's unavailable process birth
had masked the fixture mismatch. The fix retains the observed positive value and
uses the existing synthetic value only when the original constructor has no birth.
Its preserved-source regression must exercise actual closing checks over owned
physical source/process-table files, with an explicit Linux metadata model on
Darwin and the original five genuine Linux cases still required in CI. Evidence
and exact pushed beforeimages are in
`.runtime/mcp-ci-9a6d4b3cf4850750253af8339a12b9d7b425e5f1-fast-shard2-once-v1/`.

Managed prepush v17 was deliberately stopped before this further edit. Exactly
one guarded signal went to its owned runner; the SDK, runner, worker, descendants
and fixture closed, the same pinned lease inode is free, and source closing stayed
`a85806323c5a781f7c6bfe404c163e7b163ccbe10f1a83699f861c1071c0d12e`.
Its 1,222 partial observations comprise 1,219 successes and three skips; there is
no completed unittest aggregate or passing receipt. Evidence remains in
`prepush-final-v17/cancellation/`. Fresh final checks are required after the fix.

The next test-only repair preserves production sources and historical authority
pins. Exact Git attributes protect authenticated C#, PowerShell and provenance
bytes. Historical public source labels use held source without importing POSIX
coordinators merely to obtain filenames; remote Linux recipe fixtures use a
scoped POSIX path view, with physical POSIX custody cases explicitly marked by
capability. Portable helpers retain their actual source. Other corrections use
binary fixture reads, disjoint case directories, strict UTF-8 bytes and the
existing authenticated complete-program carrier with unchanged bounds. The Linux
whole-observer fixture supplies a fresh owned executable copy under the existing
current-UID trust policy, with source generation and copy closing checks.

Finite preserved-source regressions cover checkout conversion, source context,
Python fixture IO, complete PowerShell transfer and owned executable preparation.
All five groups reproduced authentic-source RED and passed the same positives
GREEN on both Python 3.12.15 and 3.14.3, with unchanged source and closed owned
children/streams. The checkout routine passed eight controls; source context ten;
owned binary six; Python IO five; PowerShell seven with one honest native skip.
Original consumer batches also passed. Evidence remains in each failure packet's
focused or wave1 directory and `focused-final-v17-freeze-v2/final-closing.json`.
Selection first refused a missing original campaign-test digest; preserving that
failure and adding only the exact pushed baseline digest passed the same gate.
Original applicable native cases and fresh final managed prepush remain required.
The native decoder parameter collision remains a candidate until the old/current
Windows pair runs.
The native target-owner failure has no retained stderr and its cause remains
unknown; the exact original factory and assertions remain, with both streams
included in the status assertion. No synthetic result qualifies that native case.
All four new Windows regression modules are explicitly enrolled in package CI.

A private read-only CI collector separately confused dynamic run titles with
workflow names. Its original incomplete result is preserved. A corrected private
collector binds workflow identity to the exact pushed manifest, definition IDs,
paths, attempt and SHA, and treats skipped optional jobs as metadata rather than
missing logs. The old collector was identity-checked, stopped once and reaped;
all 49 owned CLI readers closed before edits. This diagnostic repair changes no
production MCP authority or CI outcome. Original failed runs remain failed.
Previously closed VMs and connections remain closed, and the user's identified
SSH client remains excluded from cleanup. No product-native or visual work resumes.

The current repair plan and copyable prompt are:

- `.runtime/mcp-repair-handoff-2026-10-15/plan.md`
- `.runtime/mcp-repair-handoff-2026-10-15/next-agent-prompt.md`

The original Windows plan remains preserved at
`.runtime/windows-only-handoff-2026-10-14/plan.md`.
The previous detailed WIP and capsule are retained in the new handoff's
`before-handoff/` directory. Full evidence remains in
`.runtime/agent-tool-reproducibility-audit-2026-10-15/`.

## Repair snapshot before final validation and delivery

Dirty dev work is based on `e167a73ee8acd7fbb9844380dc12f310f537d0e6`.
The original full audit is terminal FAILED: 7,074 tests, 177 failures, 62 errors,
189 skips; all owned audit workers closed. Its failures and the four later focused
failures remain preserved. Current focused CP117 (324 tests, 75 Windows-only
skips), SSH/tmux/keeper (269), residual/native routes (52), source loader (13)
and dependency selector checks pass after reviewed repairs. The selector also
applies every matching finite declaration to statically resolved source readers;
an explicit declaration cannot silently disappear when a loader becomes static.
These focused results
do not replace the final affected selection, intentional full audit or prepush.
The old MCP process's unresolved Linux loader reflects stale loaded declarations;
fresh selection also exposed missing archival mappings. Finite reviewed mappings
and source-mutation refusal tests repair the latter without widening authority.

Both original hosted fixture builds succeeded. DIRECT collection verified;
MCP build run 38698053628 is complete but its original artifact is not collected.
Neither validates current dirty source. At this snapshot, no final version bump, final managed
prepush, task commit/push or current-SHA CI has occurred.

The owned secured Windows deployment 71872a25-5f16-496f-957f-8b1133eccf7a
has no app installed and productReady=false. All six prior QEMU guests and their
TPM are stopped; the historical SSH tunnel and its autostart job are stopped.
The expanded closure includes SSHFS mounts and the old ADB server. The old tunnel
LaunchAgent and both SSHFS keepers have persistent autostart disabled; their
definitions remain preserved. Closed things must not be restored. Fixture files,
original outcomes and reservation bytes stay
preserved. Historical disk cleanup is already complete; do not repeat it. The
host VPN and service infrastructure remain intact. Closure evidence is under
`.runtime/session-reset-2026-10-15/` and
`.runtime/session-keeper-no-restore-2026-10-15/final-state.json`.

## Current ownership and evidence

This intentionally spans source loading/selection, saved-file SSH transfer,
argument-driven VM infrastructure, observer/ownership guards, route fixtures,
causal tests, Windows CI enrollment and agent procedure documentation. Product
code, native runtime binaries and deferred product acceptance stay outside scope.
The coordinator owns this ledger, final scope review, versioning and delivery.
Separate workers own dependency declarations, CP117 route fixtures, SSH/tmux
fixtures and pin chains, residual audit tests, and environment session closure.
An independent reader reviews the full public tool surface. Source edits began
only after the original audit's three workers were reaped, their sessions absent,
fixture roots removed, and a fresh local census found no active test bracket.

Current execution evidence is `.runtime/mcp-repair-execution-2026-10-15/`.
The original handoff/audit evidence remains unchanged. Focused checks precede a
final source freeze, affected selection and intentional full audit; the final
managed prepush receipt must follow the final content and version edit.

Focused repair evidence:

- `.runtime/mcp-repair-cp117-routes-2026-10-15/repair-evidence.json`: route mocks,
  oversized self-source harness, exact historical labels and sealed context;
  original harness RED and current GREEN, with production guards retained.
- `.runtime/mcp-repair-ssh-2026-10-15/summary.json`: frozen/current authority,
  current tmux pin chain, explicit account/home fixtures, keeper closure source
  graph and invalid-host configuration reads; causal RED/GREEN and no native effects.
- `.runtime/mcp-repair-residual-tests-2026-10-15/summary.json`: sticky temporary
  ancestor seam, explicit timestamp pyc, AST route namespace, finite route mocks
  and complete captured policy copies; actual before/fix outcomes retained.
- `.runtime/mcp-repair-handoff-2026-10-15/dependency-repair/summary.json`: finite
  dependency declarations and unknown/mutated-source refusal, with actual RED/GREEN.
- `.runtime/agent-tool-reproducibility-audit-2026-10-15/cached-recovery-custody/causal-receipt.json`:
  three cached recovery/probe imports replaced by request-scoped source loading;
  identical RED/GREEN assertions cover seven routes and closing drift.

The macOS historical staging start is fenced because it implicitly selected a
previous Tart guest/account. Its separate explicit-context staging path has 43
passing controls, including physical current-Mac filesystem and boot observations,
bounded transfer/capture and artifact closing. It neither starts/restores a guest
nor establishes deferred product acceptance. Evidence is
`.runtime/mcp-repair-execution-2026-10-15/macos-generic-stage/test-evidence.json`.

Fresh SSH channels take an explicit configured host and isolate new journals by
that host. Historical global journals retain original read/closure authority only;
UNKNOWN correlations cannot be replayed or adopted. Channel selection follows
the actual configured aliases and refuses unavailable explicit selections.

Automatic oversized SSH programme handling passed 38 canonical focused checks
with no skips and six actual causal RED/GREEN pairs.
The existing operation owner selects saved-file transfer before submitting a
generated Python carrier that would exceed 60,000 bytes. A private immutable plan
binds source, route and configuration; bounded chunks carry the complete file,
then a short filename/hash loader executes it once with the original stdin.
Ambiguous failures remain UNKNOWN. Unsupported oversized forms refuse before
effects. This is internal transport for existing admitted operations, not new
arbitrary remote execution authority. Native transfer validation and the full
audit follow this snapshot; old sessions are never restored for these checks.
Evidence is
`.runtime/mcp-repair-execution-2026-10-15/ssh-automatic-program/evidence-owned-final.json`
and `canonical-final-after-loader.log` in the same directory.

The final generic SSH slice passed 157 checks with no skips; the original keeper
slice passed 40. Evidence is `.runtime/mcp-generic-channel-context-2026-10-15/summary.json`
and `.runtime/mcp-keeper-legacy-fence-2026-10-15/summary.json`.
The standalone source loader now authenticates its custody primitive before
executing it. An actual preserved-source RED proves the previous symlink ordering
failure; 26 focused checks and three compatibility checks pass. Four native
Windows checks skip locally and are enrolled in Windows package CI. Evidence is
`.runtime/mcp-source-loader-bootstrap-2026-10-15/summary.json`.

Fresh MCP checks exercised all 12 tools and the inert native transfer passed
DIRECT and MCP with unchanged original records and no restored sessions. The
first full audit then stopped at its serial close gate because reviewed current
dependency pins still named the transport before automatic submission. That
failure and all beforeimages remain in
`.runtime/mcp-repair-execution-2026-10-15/full-audit-v4/`. Reviewing 14 current SHA
bindings across 11 files restored the current chain; 206 checks completed, with one
expected skip for absent historical state. Historical source and authority pins
remain unchanged. Evidence is
`.runtime/mcp-current-pin-refresh-2026-10-15/summary.json`.

The native execution catalogue also needed the one new fixed automatic helper
declared. Actual preserved-source RED and GREEN cover the original future driver,
held-helper capture and unknown/missing dependency refusals. Its 22 checks and a
59-check entrypoint/close/resource slice pass. Final selector controls pass 102
checks; 1,505 current/baseline source versions have no unresolved mappings. The
affected plan selects 499 of 556 modules; the intentional audit covers all 556.
Evidence is `.runtime/mcp-native-catalogue-automatic-2026-10-15/summary.json`
and `.runtime/mcp-repair-handoff-2026-10-15/dependency-repair/final-summary-v3.json`.

The next intentional audit passed its 27-test serial close gate. Its 555-module
pool completed 7,228 tests with 22 failures, seven errors and 191 skips; all three
workers closed, and source was unchanged. All 24 modules that failed in the
original handoff audit passed in that run. The 29 additional failures came from
stale fixtures: an empty selected route, incomplete private SSH inventories,
iteration of guarded oversized plans, an inline PNG producer hitting the command
bound, a process-wide Windows platform mock, a missing authentic original host
producer, a formerly restricted valid host alias, and an oversized inert diagnostic
bootstrap shared by the gateway reconciliation tests. The unfixed sources and
complete failure logs remain in
`.runtime/mcp-repair-execution-2026-10-15/full-audit-v5/`.

Eleven exact original cases reproduced RED before the test-only repairs and
passed GREEN afterward. The expanded 11-module slice then passed 352 tests with
21 justified platform skips; all 29 audit failure identities and the new
oversized-diagnostic non-dispatch control passed. This retained the historical
compression/source assertions, source and ownership guards, and 60,000-byte
command limit. Two existing finite dependency declarations gained reviewed current
test hashes without changing their scopes or dropping historical versions.
The final parser reviewed 1,513 source versions with no errors, and 102 selector
checks passed. Evidence is `.runtime/mcp-audit-v5-fixture-focused/` and
`.runtime/mcp-repair-execution-2026-10-15/original-failure-reconciliation-v2.json`.
At this checkpoint, the final native qualification, version note, managed prepush
and exact-SHA delivery verification still follow; none of these earlier results
is a final prepush or CI receipt. Prior VMs and connections remain closed.

The subsequent automatic SSH qualification executed its saved program with the
expected exit 23, complete stdin and both output EOFs; its remote journal verifier
exited 0. The private collector then counted its authority file as a fourth wire
event. That original UNKNOWN and all beforeimages remain unchanged. A separate
read-only inspection validated the three exact events and source closing without
any replay or new connection. The exact preserved collector fragment reproduced
RED, and the same positive assertion passed with explicit event admission. Its
nine routine controls and 38 automatic-program peer checks passed without skips.
An earlier wrapper import failure is retained separately and is not causal RED.
The final dependency parser reviewed 1,515 source versions with no errors; all
102 selector checks passed and the plan selects 500 of 557 modules. Evidence is
`.runtime/mcp-native-automatic-closure-2026-10-15/`. Final stage qualification,
managed prepush and exact-SHA delivery remain separate gates.

Review then found a POSIX permission assumption in the synthetic collector test
wrapper. Its preserved code reproduced RED with an isolated writable Windows
mode projection; the pure input fixture passed the same assertion, and all 47
collector and automatic-program checks passed without skips. The exact original
fragment and production custody guards remain unchanged. This routine collector
module is also enrolled in native Windows package CI. Evidence is
`.runtime/mcp-wire-evidence-windows-portability-2026-10-15/`. The first final
prepush was intentionally cancelled before this edit: all owned workers closed,
its 1,212 partial test observations had no failure, and no successful receipt is
claimed. A new final prepush is required.

Final native staging and refusal checks completed under their recorded source
bracket. A separate strict census found two interactive SSH connections; the
user's explicit instruction to close all connections authorized their exact
identity closure. The subsequent census found no VM/SSH actors or SSHFS mounts,
with keepers disabled and prior records unchanged. Original failed census
observations remain failed; their original cause was not recorded, and no later
observation rewrites them. Nothing was restored. Evidence is
`.runtime/mcp-native-final-2026-10-15/final-native-v6-closure.json`.

Never change captured source/policy/dependencies while a tool/native/test source
bracket is active. Inspect original terminal/closing receipts before any replay.
For every failure, preserve original evidence and unfixed source, obtain actual
causal RED/GREEN and enroll required coverage without weakening production guards.
Finish the MCP repair with reviewed scope, version_bump, fresh managed prepush,
explicit reviewed paths and origin/dev push, then all five required workflows
green for that exact SHA. No release or main merge.
