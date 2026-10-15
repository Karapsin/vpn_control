# Current MCP repair work; Windows parity deferred

The user deferred the Windows parity plan on 2026-10-15 and requested the
MCP/tooling repair described below. The later instructions in the active chat
permit subagents and authorize stopping all prior unknown or historical test VM
sessions and SSH connections before fresh validation. Preserve disks, fixtures,
source edits, original evidence and durable job/lease records; no purge or replay
is authorized. Do not resume Windows product acceptance, H14, visuals or the original
Windows plan without the user resuming it. Linux, Android and macOS product-native
and visual work also remains deferred. No release.

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
