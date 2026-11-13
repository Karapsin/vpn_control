# Active parity failure-to-test index

Use [current WIP](work-in-progress.md), [execution brief](parity-solo-plan.md) and
[path-based test selection](test-matrix.md) before action. Historical passing counts
are source-bounded. The [complete archived ledger](archive/parity/2026-10-14/failure-regressions-through-3944739.md)
retains every causal description, RED/GREEN, command, count/skip, UUID, evidence
locator, cleanup uncertainty and unintegrated proposal. The
[migration manifest](archive/parity/2026-10-14/migration-manifest.md) maps every original heading/anchor/blob.

## Unresolved canonical enrollment and native limits

### Combined test execution: inner causal cleanup was skipped (2026-10-20)

The original nine-module, one-interpreter run completed 263 tests with two failures
and 23 errors. An expected before-source assertion escaped an inner
`TestCase.debug()` call before its registered cleanups ran. Later tests inherited
a fake Python executable, PID function, sleep function and ProgramData value;
their real subprocess launches then failed. The original run and 166 source/data
beforeimages remain in `combined-test-interpreter-contamination-v1/`.

The correction gives each of the three inner cases an owned `TestResult` and
calls `TestCase.run()`. It rethrows original exceptions with their tracebacks,
groups multiple body/cleanup failures and refuses skipped or unexpected outcomes.
Original causal assertions and before/current expectations remain unchanged.
`OracleInterpreterCleanupTests.test_whole_original_barrier_pair_restores_interpreter_and_real_child_launch`
executes the complete preserved `a7d3e8f0` source and the same barrier-pair oracle:
the original pair passes but leaves all four real globals changed and cannot
launch its actual Python child; the fixed whole source restores all four and
the original child exits zero with complete streams. This is a local test defect,
not a Windows product failure or native acceptance.

The seven-path proposal `ac3a8e33` is adopted with finite dependency rows in the
ordinary affected/prepush suites. Root reran the original nine modules together:
264 successes, no skips, receipt
`5bae4b37ca398c2aa8e4b02ea669aa5222dbd1e7b15c9cc78e42864d698667db`.
The 59 historical source fixtures and production planner/owner/task bytes remain
unchanged. Final broad prepush and exact-SHA CI remain required.

### Metadata observer disposition: stale report-only guest PID (2026-10-20)

The original exact-observer disposition guarded and retired the correct owned
host process, but its top-level report still named the older guest PID 152 instead
of the observed failed metadata PID 7820. The complete `03ad7964` before caller
and original positive qualifier are preserved. The registered
`render_metadata_disposition_caller` derives only that report field, producing the
authentic complete `1132d687` correction. The same whole positive oracle reaches
the original report assertion and fails, then passes on the correction under
inert original process/pidfd/signal/RPC peers. No test sends a real signal.

Proposal `b4ba5ece` is adopted in the existing owned-actor recipe case; its
ten-method inventory is unchanged. A controlled peer's single extra EOF newline
was removed with its complete AST unchanged; authentic original bytes remain
separate preserved evidence. All ten recipe cases and four capability checks pass
on the composed canonical source without skips. Source/proof mappings are in
`windows-product-runner/metadata-disposition-routine-preparation-v2/`. This
report-only regression does not change the original UNKNOWN metadata outcome or
authorize replay; the separate once-only host disposition retains its actual
positive exit/absence and EOF evidence.

### MSI metadata: method results entered the row stream (2026-10-20)

The complete metadata reader failed on Windows at the first `_Tables` consumer
with `Cannot index into a null array`. Guest PID 7820 exited 1 and its original
status was consumed. No metadata evidence file or installer action had started.
The host observer timed out, so its original operation remains UNKNOWN and
abandoned. Its exact owned process was subsequently retired once; the separate
disposition finished with full EOF, positive process absence and unchanged source
closings. This does not qualify the original metadata operation.

The preserved complete body is
`4eab4f008f2d23a87196f9893e8b35df96646201d852c6638448ba7523732de8`.
The registered `render_msi_metadata_body` getter adds only `[void]` to `Execute`
and `Close`, preventing their success values from entering the returned rows.
Real PowerShell with declared view/record peers reproduces 24 positive-oracle
failures and four true-void successes on the original, then 28 successes on the
fix, with exact record/view releases. The actual Windows COM return kind remains
unknown. The complete recipe suite now has eight POSIX and two PowerShell cases;
the four capability probes require that exact inventory. Source, raw native
failure, beforeimages, causal matrix and nine-path routine adoption are under
`windows-product-runner/posttransfer-msi-metadata-rows-cause-preparation-v1/`.
The corrected complete reader subsequently passed on Windows PowerShell 5.1 in
original tool session `8394`: natural exit zero, complete 102,640-byte stdout,
empty stderr, both EOFs and all 51 held input generations/hashes unchanged.
The 74,621-byte metadata file was read through its original guest file handle,
physically verified and closed. Qualified receipt
`c3bcb48a850e8bb7eb4c95bb6b3a6e154fbbccca8fa0754c8063db530d9daa4f`
and completion `cdb84e1045ee126abbed4c985f75e480e84b29b92d67b2a1f0f4e1ea161a5efa`
are under `windows-product-runner/posttransfer-msi-metadata-fixed-current-preparation-v1/`.
This qualifies the read-only metadata flow, not installation or product acceptance.

### Initial SYSTEM intake: protected OS hard links and caller typo (2026-10-19)

The first complete intake stopped at `file-type-reparse-link` while examining the
fixed System32 executables. Preserve original guest exit 1 separately from its
UNKNOWN host observation. After exact observer retirement, a new read-only native
query observed two links on both PowerShell and Windows Installer, with regular
non-reparse types, TrustedInstaller ownership and protected ACLs. The proposed
role-specific fix retains the universal single-link guard for transferred files;
only the two exact protected OS paths may admit their observed link count. The
fixed Windows full intake passed in original tool session `80482`, exit zero,
with full raw EOF and all 49 held source generations and hashes unchanged.
Qualified receipt `12c58a279189481e25139f87ae6d1d8d8ec46110695dd0cf521bf27d6d3b146d`
retains the full native pin/ACL/token/kernel/bootstrap closing observations.
The canonical Python planner, Python owner and PowerShell owner now share this
narrow role rule. Their registered ordinary-task suite passed all 28 tests without
skips, including 38 actual C#/PowerShell decision controls against declared API
peers and authentic whole-before Python guard failures. These peer results do not
qualify the native Python owner, task launch or installation. Original
observations, beforeimages and portable controls are under
`.runtime/windows-parity-20261019/windows-product-runner/windows-protected-os-pin-policy-preparation-v1/`.

The separate earlier caller failed before guest-exec because `__name__not` was
parsed as an attribute. The registered whole-caller getter authenticates the
153,074-byte original and derives only the missing space. The same whole-entry
oracle produces the original AttributeError with zero guest-exec calls, then
success with the complete registered decoder exercised. A lost-ACK control still
retains the original request and descriptors without another frame or replay.
`test_windows_native_packet_recipe` now contains eight POSIX cases plus its
separate PowerShell diagnostic. Canonical execution with the verified PowerShell
runtime passed all nine cases and all four capability checks without skips.
Exact 13-path adoption and causal evidence are in
`windows-product-runner/system-intake-caller-lexical-recipe-preparation-v1/`.
These are tooling controls; installed Windows acceptance remains open.

### Windows resume: public subscription-mode entrypoint (2026-10-19)

The desktop public argv adapter rejected schema-valid `source set subscription`
because it used nullable legacy-command translation as typed validation. The
owner already supports mode-only subscription selection. `DesktopControlMutations.accepts`
now validates the shared grammar independently of legacy translation; owner
validation, persistence and epoch/revision guards are unchanged.

`DesktopCliSourceModeParityTest` exercises the actual argv parser and authenticated
owner transport in human/JSON modes: empty/remembered selections, explicit IDs,
durable no-ops, invalid arguments, stale owner/revision and missing pinned owner.
The preserved implementation produced three failures in five tests; the fix
passed all five and the 31-test adjacent slice. Beforeimages, raw logs, JUnit and
the exact mapping are in `.runtime/windows-parity-20261019/cli-entrypoint/`.
Ordinary `:desktopApp:test`, managed prepush and platform CI discover the class.
`scripts/test_packaged_cli.py` now performs matching real-launcher selections and
readbacks; installed Windows baseline RED/fixed GREEN remain native gates.

The first full desktop run had 1,284 tests, 111 skips and one existing Linux
update-watcher test failure at its ten-second wait. An unchanged independent
focused execution passed in 5.906 seconds. Original blocked phase/PID were not
retained by that fixture and remain unknown; logs and source beforeimages are
preserved under the same packet. A separate owned phase discriminator proved that
external fake-sleep actors can consume that observer; its same original child
finished naturally after release. The test now prefixes the actual watcher with
`sleep() { :; }` and makes the otherwise reachable fake executable exit 97.
The authentic before-source test with that declared tripwire input fails at
expected exit 1 versus actual 97; the fixed five-method suite passes without skips.
The production helper, 300 attempts, ten-second observer and absence assertions
remain unchanged. The joined receipt is
`cli-entrypoint/unrelated-desktop-failure/tripwire-causal-v1/summary.json`
(SHA-256 `419c24313614816e97ca0c05d99fb9b03fa301aa6aa274625e0d92d6e3344b10`).
That controlled cause does not establish the unretained historical phase. Fresh
complete prepush remains required; do not relabel the original run green.

### Fresh Windows fixture: sync-database advisory (2026-10-19)

The Arch preflight rejected the policy-correct single swtpm UID difference when
pacman also emitted a missing sync-database advisory. All six installed-package
queries emitted that advisory; five returned zero alterations, while swtpm's
physical tss/root/0750 metadata matched its pinned tmpfiles policy. The exact
original native result and helper beforeimage are retained under
`.runtime/windows-parity-20261019/windows-fixture/direct-package-integrity-v2/`
and `package-integrity/`.

`swtpm_runtime_owner_accepted` accepts at most one exact, bounded advisory prefix
before the mandatory UID warning. Return code, alteration count, policy, physical
type/owner/mode and all source/held-byte guards remain unchanged. Unknown warnings,
checksum differences, duplicate/reordered/malformed lines and changed metadata
still refuse. No host package/configuration or CA-directory change is required.

`test_windows_vm_deploy` now covers the actual retained helper and complete emitted
preflight. Same-positive preserved-source RED has four designated assertions
across two tests, zero errors/skips; fixed-source GREEN passes both and the full
18-test module. Authentic beforeimage/provenance are in the routine fixture
directory. Actual causal proof is `package-integrity/actual-causal-v2/summary.json`
(SHA-256 `13c61efb5596b7f8eb56650921abdb0aaee338bcc9c0130c6fcd64254b0ea476`).
Affected selection finds 513 transitive consumer modules for these four paths;
no dependency-declaration change was needed for that parser delta. The original
direct preflight and current MCP preflight both passed the exact repaired helper.
Fresh complete prepush and final exact-SHA delivery remain required.

### Fresh Windows command and task tooling (2026-10-19)

The missing RPC argument and absent `INITIALIZE` global are whole-caller failures
before guest command submission. Authentic complete callers reproduce their
`TypeError` and `NameError`; the actual `windows_qga_transfer` caller factory
passes in a fresh Python `-c` namespace with no `__file__`, the registered current
artifact producer and the same bounded peer. The routine QGA suite also covers
original-reply retention after parsing/journal failures, write-zero refusal,
source/guard checks, raw-file generation through publication and no-unwind parking.
These controlled peer results are not native Windows acceptance.

Native setup preserved three distinct launch/task failures: an omitted XML
RunLevel despite genuine Limited native facts; a 35,599-unit encoded command
that could not start, with the task independently never run; and a saved source
whose SYSTEM-created file defaulted to Administrators ownership. Original raw
streams, XML, caller sources and native token observations remain under
`windows-fixture/`; the V5 context and causal-map receipts retain the repaired
ordinary-user task result without rewriting earlier failures.

`test_windows_artifact_transfer` now executes the authentic oversized producer
through its launch boundary, proving old oversize submission versus current
prelaunch refusal and a bounded saved-source plan. Its native PowerShell helpers
exercise exact before/current progress headers, atomic directory creation and
explicit source-owner assignment. Those three actual PowerShell cases remain
skipped on this coordinator and must run in the qualified Windows VM. The
original progress query emitted CLIXML despite exit zero; the old directory
method `::New` resolved as a constructor. Their original failure and corrected
native observations are preserved separately from the pending canonical reruns.

`windows_ordinary_task` and its actual retained owners now provide the canonical
task policy. Omitted RunLevel requires exact independent SID, Limited/Interactive
and typed COM facts; ambiguous values refuse. Final review also found that an
extra ComHandler could accompany the expected Exec. The preserved 5d planner
accepts that same forged action set in the actual validator RED; the fixed policy
requires exactly one Actions container and its sole Exec. The focused module has
13 tests: 12 pass and one real-PowerShell case is skipped. Its native packet keeps
the original omitted-field RED and adds a 14-control current GREEN procedure;
execution remains pending. Original 13-control native evidence stays unchanged.

The final transfer/QGA routine slice has 35 tests: 32 pass and three native
PowerShell cases are skipped here. Native-test runner review also reproduced
post-launch attachment interruption and constructor uncertainty on preserved
before-source. The fixed runner reserves its original object before construction
and retains the original exception/streams through closure, without inferring
no-start from fields that Windows may not yet have assigned. Physical native
identity/path/retained-assets checks also have actual before/current regressions.
The final focused receipt is
`qga-transfer-preparation/routine-regression-qualification/final-focused-summary.json`
(SHA-256 `f4ff7582c6a500bf5ea60e90ab55b139ac9a9f5733d1f317736d8a62708e4309`).

The current source/fixture manifests and exact before/current routine boundaries
are in `qga-transfer-preparation/routine-regression-qualification/owned-handoff.json`
and `windows-product-runner/preparation-v1/canonical-owner-handoff.json` beneath
the active evidence root. Native causal proofs, complete original direct and
matching MCP scenarios, final selection and managed checks remain required.

The new canonical PowerShell owner and original XML also need exact-byte Git
attributes. Existing authenticated old attributes reproduce conversion of the
owner on a real Windows-style Git checkout. Two exact `-text` entries preserve
both inputs; the expanded checkout module passes all 15 tests, including its
causal before/current pair. Latest beforeimages and result are retained under
`checkout-byte-preflight/`. No native Windows outcome is inferred from Git tests.

### Current managed checks: readiness and aggregate deadline (2026-10-19)

The original serial worker completed 6,963 tests across 513 modules in 3,537.226
seconds: two failures, one error and 200 skips. Its managed coordinator had already
been killed by the 3,000-second outer wait. Both original processes are now absent;
the worker result is preserved separately from the failed managed call. Full raw
artifacts, plans and 52 source beforeimages are in
`.runtime/windows-parity-20261019/prepush-failure-investigation/natural-worker-terminal-v1/`.
No passing prepush receipt is inferred from that terminal worker.

The two routing-diagnostic assertions observed an empty expected stderr prefix
and a live parent where an exited parent with an inherited pipe was expected.
The original child startup stage was not retained. The fixture used an unqualified
50 ms measurement; controlled delayed-entry executions reproduce the precise two
assertions on authentic before-source and pass with explicit readiness. Production
deadlines and classifications are unchanged. The 14-test routine module passes,
including held-pipe refusal, raw partial capture, cleanup failures and positive EOF.
Authentic fragments/provenance are under `fixtures/android_routing_readiness/`;
the exact retained receipt is `readiness-actual-focused-v1/summary.json`. Independent
review found no remaining actionable ownership or exception-custody issue.

The aggregate managed limit could not fit the measured suite. Optional managed
batches preserve all modules in their original consecutive order, with 16 per
command and the separate SSH gate once. (The 2026-11-07 merge keeps `dev`'s gate
plus two halves in `_commands_for`, so the batches parameter of
`managed_agent_check` is covered by `ManagedBatchTests` but no pre-push path
passes it.) The largest original measured batch is
1,563.478 seconds, below the unchanged 3,000-second command budget. A scoped owner
requests the existing runner's SIGTERM cleanup, keeps its original handle and
lease through worker/session closure, and captures both raw streams to actual EOF.
Crossing the work deadline remains a failure even if exit zero races with cleanup.
Authentic old `_run` and unbounded selector each give a designated causal assertion
RED; eight new controls and the 126-test adjacent slice are GREEN. Evidence and
beforeimages are under `managed-budget-causal-v1/` and `managed-budget-before-v1/`.
Final source-loader enrollment, complete prepush and exact-SHA CI remain open.

The generated Android batch-shell fixture also exceeded its 30-second limit in
the original first normal case. Its raw child channels were not retained by that
exception. A separate owned observation passed the normal case in 25.99 seconds,
then timed out during the file-drift case with nine complete frames. The original
cause remains unknown; finite phase/utility diagnostics are in progress. No
production step deadline changes. Controlled ten-command entry delays stay inside
each native 20-second watchdog but reproduce the old aggregate 30-second fixture
timeout. The finite fixture observer is now 252 seconds: ten 20-second steps plus
52 seconds of measured housekeeping. This is an observation allowance, not a
completion guarantee. Separate same-size/mode/inode file mutations proved both
old shell `test out && test err` guards could continue after a false left side.
Explicit `test ... || exit 1` at both sites now refuses with exit 1, retains the
spool and emits no CLEANED/EOF acceptance.

The current complete 59-method module finished naturally with zero assertion
failures, one error and one expected platform skip; original pipes and cohort
closed and all 50 input generations matched. Both generation-guard methods pass.
Its error is a new before-fixture assembly defect: `textwrap.dedent` cannot remove
method indentation when authentic multiline actor text contains column-zero
lines, so parsing raises `IndentationError` before a historical child starts.
The original error and current beforeimages are preserved. An unchanged-byte
class wrapper passes the actual old-loader RED/current GREEN and the same failed
real before-30/current-252 scenario: two tests pass in 99.551 seconds, with EOF,
positive cohort closure and all 50 input generations unchanged. The routine
module now has 60 methods. Exact owned paths, hashes and receipts are in
`evidence-audit/installer-completion-v1.json`
(SHA-256 `5f4a5739dd52b6afe765c1b824f1724a6dd15d8322b8c42caa0facdb282c4b1b`).
No full-module GREEN is claimed from the original failed run or this focused pair.

### Generated-program transport and source ownership (2026-10-19)

The reusable SSH program owner retains each immutable operation and its original
child through both raw EOFs and source closing. Ordinary coverage now includes
small and saved-file programs, exact arguments/cwd/streams/exit, pending and
duplicate observations, conflicting requests, concurrent publication, source and
credential drift, attachment/write failures and SSH exit 255 without replay.

Authentic beforeimages expose separate defects: source inspection without module
registration, the saved SDK client's missing import path, reordered request keys,
changed loader/import code executing before validation, and a copied worker losing
the selected channel's original source namespace. Current routines execute the
real complete producers or workers against the preserved variants. The source
loader checks the complete expected manifest before module execution; the worker
holds the original source namespace through program closure. Swapped bytes and
same-byte inode replacement refuse, while after-start drift drains the original
child and remains unknown.

A real kernel `E2BIG` witness fails before any inline child starts. Its preserved
owner reports unknown; the fixed owner records definite no-start proof, binds one
saved-file plan to the same program/arguments and executes it once. Other errors,
saved-plan failures and uncertain outcomes cannot acquire that proof. A separate
actual fast-child witness exits before auxiliary process inspection; the fix uses
the retained original handle's known exit without inventing birth metadata and
still requires both EOFs. Windows discovery controls also check these POSIX suites
with `pwd` unavailable before their platform skips.

Routine ownership is in `test_saved_program_introspection`,
`test_ssh_program_mcp_client`, `test_source_expected_manifest`,
`test_ssh_program_selected_source`, `test_ssh_saved_program_force` and
`test_ssh_program_execution`; their authenticated fixtures live beside them.
The final combined source-bound slice passes all 53 tests. Direct configured-host
small and oversized programs and matching actual MCP requests all pass, including
pending/same-child reconciliation, conflict refusal, exact Unicode output/argv/
cwd/exit 7, both EOFs and source closing. All 38 SDK calls each forward one request
and close their original server streams. Receipt
`program-tool-native/native-direct-mcp-qualification.json` has SHA-256
`d286099b9a9899e27bde4236b04a7367b3ebf13ff6173737b50c9225ac2f29b1`.
The original 23 code inputs are unchanged through closing. Final content/version,
dependency enrollment, managed prepush and CI remain open. These tool witnesses
do not qualify Windows package, installer or product acceptance.

The final 748-server/676-policy refresh opened a new five-hour channel and passed
its small program. Oversized operation `bc6ed15f-36ba-492a-88ac-13eaca58fa10`
ended UNKNOWN with `SshConfigError`. The actual worker preserved only the class,
losing the original message, traceback, phase and inner refusal. Its captured
child field is null; that alone is not no-start evidence. The original keeper is
independently absent and no matching automatic-stage intent was found. The exact
read-only argv rebuild and nine native channel statuses now pass, which does not
identify the original cause or permit replay.

All 26 source beforeimages/generations, immutable request, original worker/owner
and SDK frames are retained under `program-tool-native/final-748-676/`.
The joined boundary receipt has SHA-256
`27f37cecb4b0366f7872e9343ac1094788482c045163a4cbfb879cfbf32624ac`.
A narrow diagnostic regression/fix now covers the real worker and selected
admission boundary: private bounded exception/typed-refusal/raw evidence from the
same observation, retaining primary failure and custody. The authentic 780 worker
loses this evidence in the same controlled pre-automatic exception RED; current
source preserves it GREEN. The final two-module slice passes 33 tests, including
12 new controls for primary-error identity, same-observation/default-ABI capture,
UNKNOWN retention, success disposal, write/callback/overflow handling and context
isolation. Earlier bootstrap/import/intent-read failures stay outside this scope.
The focused summary is
`program-tool-native/worker-diagnostics-preparation/final-focused-summary.json`
(SHA-256 `ef63a1728be2b2d63849d2cb4351f84c74f5d67edd9a3941a31a1e4654c72acf`).
Original UNKNOWN remains unchanged. The exact owned 315 channel was retired with native
absence and matching current-MCP ENDED evidence before source edits. At that
checkpoint, new native proof and the seven unsubmitted Windows requests remained
blocked on qualification of the diagnostic source and fresh policy/channel.

The final coordinator guard's source change required retiring the exact owned
verification channel. Its first read-only probe stringified a missing optional
config as `None`, while the original provider uses an empty argument to select
the owned default config. The original native refusal and complete helper
beforeimage are preserved under `fixtures/retirement_default_config/`.
`test_ssh_owned_channel_retirement` exercises the actual complete before/current
probe against real owned no-follow config files: causal RED/current GREEN and
16 focused passing tests. The corrected native probe, sole owned exit request,
independent process/control/listener absence, authentic ENDED publication and
current-MCP terminal observation pass. Joined receipt
`program-tool-native/retirement/retirement-qualification.json` has SHA-256
`4f10f09e419f1e0f97424459b55f40fe8e66e76a0945a0828c384a30c9a6232b`.
No historical connection is restored and unknown outcomes permit no repeated exit.

### Current recovery failure boundaries (2026-10-19)

The following finite ledger supplements the historical failures above. New
observations do not replace original UNKNOWN outcomes or constitute package/product
acceptance. Evidence paths below are relative to `.runtime/windows-parity-20261019/`.

| Failure or boundary | Known cause and current evidence | Coverage and remaining gate |
| --- | --- | --- |
| Historical companion99/102 mismatch | The original failed N report compared a stale99-case expectation with its sealed102-entry Linux plan. Later retained O qualification preserves those obligations and adds the original receipt test plus new regression: Linux104 (93 Fast,4 direct cleanup,7 enrollment); Windows102 retained identities plus Function source-body routine=103. | Exact retained O validation and independent resource closure qualify this tooling reconciliation without collector replay. Original N stays failed; this supplies no current product-native acceptance. |
| Original oversized `bc6ed15f` UNKNOWN | The worker lost the original diagnostic details; its underlying admission cause remains unresolved. The later four-program channel546 proof is a different set of operations. | Diagnostic routine RED/GREEN is recorded above; never replay or relabel the original operation. |
| Channel546 trust drift | `known_hosts` changed from retained `c907aa5b` to `20bb94d7`, with a changed generation and equal length. Actor, cause and key equivalence are unknown. Original READY authority became stale. | Stage A and exact546 retirement are complete under the root receipts below. Trust equivalence is not claimed. Stage B adoption/freeze must precede NEW prepare/select and current-source qualification. |
| Original `ba9620b4` full probe and lost outer custody | Local owner57875/SSH58163 are absent; original completion handle, terminal receipt, dual EOF and source closing are unavailable. The later one-shot query establishes only original PID4120 create `created-terminal-observed`. | Preserve the full probe as `unknown-unverified` and custody as lost. The successful recovery carrier cannot supply the original missing closing evidence. No replay. |
| QGA receive polling | The preserved old complete source treats an individual receive poll timeout as terminal; bf05 preserves the same socket/command until the existing absolute deadline. This routine mechanism does not identify the original native elapsed phase. | Nineteen pre-adoption routine cases pass, with actual before-source RED/current GREEN and one native status component. Stage B is applied and its 203-case canonical slice passes; all seven complete native reruns remain open. |

The count reconciliation is already recorded in the current WIP. Its retained O
receipt is
`.runtime/mcp-ci-d24c19047ec15689948404ede40f50c5ec284e77-readonly-O-2026-10-17/final.json`
(SHA-256 `9f116cd5808ce3e3ddf7fd61e4c20cb71e9f878394dc9516a9a12e49082a3278`),
with independent resource closure at
`.runtime/mcp-next-O-collector-owner-preparation-v1/closer-template-v1/actual-O-resource-closing-v1/closing.json`
(SHA-256 `784a57775afca707ed39827c07695fc2ae90cfc481f521c4014a762edb24088b`).
The old failed/unknown records remain unchanged; no new broad audit is needed
solely for the historical count mismatch.

The later generic-program joined receipt is
`program-tool-native/final-748-638/native-direct-mcp-qualification.private.json`
(SHA-256 `55b5b9302d8e5bc6f6e1f0f3c1e712fc26e1c5e9b5155b38bea4e91153edf612`):
four programs, 65 fresh SDK RPC servers, 26 unchanged source pins, exact streams/
exit 7, both EOFs, source closing, original keeper absence and duplicate/conflict
checks. It is distinct from `d286099b` and is historical proof under546's original
trust authority, not authority to use that now-stale channel.

The drift receipt is
`windows-fixture/known-hosts-drift-before-diagnosis/drift-preservation.private.json`
(SHA-256 `5111993c9951a817612ce13064eba933d01f99d675f5fdf39514debddde9b7cd`).
The lost-custody adjudication is
`windows-fixture/original-ba962-local-closure-after-abandonment-v1/root-custody-adjudication.private.json`
(SHA-256 `0d245d55a80e987098268d7769275ccb830c0488f001d2a7ed9978993d475778`);
it predates the successful status query. Use the later
`artifacts/original-pid4120-status-direct-preparation-v1/packet-final/operator-joined-status-observation.private.json`
(SHA-256 `9d4b748bd9977220031dbb487e48e0d8dea59d640dc972e41ced50625ea58846`)
for the create result, without changing its `fullOriginalProbeQualified=false` or
`originalOuterCustodyRecovered=false` limits. Its 1,853,826-byte automatic stdin
transfer and the separate 470,783-byte cleanup transfer succeeded; neither is a
full original probe or matching public MCP acceptance.

The following capture rows are separate failure types. Beforeimage basenames are
under `capture-custody-private-preparation-v1/candidate/agent_tools/tests/fixtures/capture_custody/`.
`C` means that private preparation's `causal-failure-map.private.json` (SHA-256
`fa125530fd4131fa490ecb47b90007d1f9ac6b5237df65f22feee8979356d2f1`),
which retains the full owner/control set for each row. The 121-test GREEN is bound
by `handoff-final.private.json` (SHA-256
`3fe1c4ce0c1899e1dddc73215d8b01920272d6997d06d27677da96f7eb0469a3`).
These are actual pre-adoption local whole-source/emitted-code RED/GREEN controls
with finite children, pipes and PTYs. Their exact reviewed Stage B source/policy
is now applied; its 203-case canonical slice passes after the one MCP dependency
skip was executed successfully in the project environment. The private121
receipt retains its earlier scope and is not a native Windows failure or acceptance.
No command/output cap or absolute deadline is widened.

| Distinct capture failure | Authentic complete before and causal test | Proof and limit |
| --- | --- | --- |
| Post-Popen constructor/attachment loses child/source custody | `android_qualified_cli_observation.py.before.source` (`6a2cdec7`); `CaptureCustodyRegressionTests.test_whole_android_constructor_failure_keeps_original_until_eof_and_source_close` | C maps the six affected owner paths; GREEN retains the original child through terminal/dual EOF before source close. |
| Read/select/partial attachment error escapes or invents EOF | `ssh_source_file_gateway.source.before.source` (`17ea428f`); `GatewayCustodyFailureTests.test_gateway_read_error_is_unknown_and_not_a_fabricated_eof` and `test_gateway_partial_selector_registration_keeps_both_original_streams` | C and `gateway-owned/causal-summary.private.json`; actual zero-read/terminal PTY EIO proves EOF, not an arbitrary read exception. |
| Reader closes stdin before active writer finishes | `ssh_source_file_stage_direct.py.before.source` (`d793ead7`); `SourceStageCustodyRegressionTests.test_active_original_writer_keeps_stdin_through_natural_drain` | C; RED truncates 1 MiB or leaves writer active; GREEN drains/joins that same writer and child. |
| Late completion promotes latched timeout to success | `android_qualified_cli_observation.py.before.source` (`6a2cdec7`); `CaptureCustodyRegressionTests.test_android_complete_after_timeout_cannot_become_observed` | C maps the corresponding direct/status/gateway controls; late terminal/EOF cannot clear the first timeout. |
| Early UNKNOWN frame omits late original output | `ssh_source_file_gateway.source.before.source` (`17ea428f`); `GatewayCustodyFailureTests.test_gateway_late_output_after_exception_is_in_one_final_unknown_frame` | C plus gateway summaries; one final UNKNOWN frame retains late same-child bytes. |
| First private selector rewrite breaks valid high FDs | `android_qualified_cli_observation.select.before.source` (`a41b56ac`); `CaptureCustodyRegressionTests.test_authentic_first_candidate_high_fd_failure_is_red_before_scalable_fix` | `review-outer-direct/high-fd-actual-reproduction.private.json` and `gateway-owned/high-fd-causal-summary.private.json`; FDs1100/1101 fail only the private candidate; authentic scalable `6a2cdec7` succeeds. |
| Private metadata breaks an established subclass API | Same `a41b56ac` before with unchanged whole program consumer `0b0d21e6`; `CaptureCustodyRegressionTests.test_unchanged_generated_program_subclass_keeps_base_snapshot_api` | `review-outer-direct/subclass-actual-reproduction.private.json`; before raises `AttributeError: captureErrors`, authentic base and fixed candidate accept the same consumer. |
| Private prelaunch key setup leaks reserved selector | `ssh_source_file_gateway.reserved-selector.before.source` (`69cc4be8`) with stage producer `8cb40ada`; `GatewayCustodyFailureTests.test_gateway_reserved_no_child_setup_error_closes_only_owned_selector` | C; injected `UnicodeError` occurs before Popen, zero children; only the owned selector closes. |
| Private UNKNOWN framing duplicates initial/final raw output over cap | `windows_vm_deploy.duplicate-output.before.source` (`f38835e5`); `WindowsDeploymentGatewayCustodyTests.test_windows_gateway_preserved_duplicate_output_before_exceeds_outer_bound` | `windows-gateway-owned/large-output-causal-summary.private.json`; actual 25,172,594 bytes exceeds unchanged 16,777,216-byte cap. GREEN on the same stimulus (`test_windows_gateway_large_file_output_unknown_stays_within_outer_bound`) emits one metadata-only UNKNOWN frame of about 620 bytes: closed `reason` and `capture` from the failure, and `finalCapture` counts and EOF after the drain. No stream copy enters the reply. |
| Pre-existing observed-success combined framing exceeds cap | `windows_vm_deploy.py.before.source` (`00c22a5c`) and `windows_vm_deploy.observed-output.before.source` (`f4a5c340`); `WindowsDeploymentGatewayCustodyTests.test_windows_gateway_preserved_observed_output_befores_exceed_unchanged_outer_bound` | `windows-gateway-owned/observed-output-red-summary.private.json` and `observed-output-green-summary.private.json` (the latter records the pre-merge `a9aed701` reply shape); before emits 19,224,514 bytes. Fixed exact UTF-8 admission (`test_windows_gateway_observed_large_reply_is_bounded_unknown_with_original_complete_streams`) emits one metadata-only UNKNOWN with `reason` `program_reply_bound`, about 610 bytes. Streams no longer enter this reply, so only an oversized result reaches the bound: about 5 MiB of stdout JSON re-encoding to about 20 MiB, without `input_payload`, because `_gateway_payload_result` bounds credential-bearing results. The same stimulus on the befores emits 27,962,636 bytes (`test_windows_gateway_preserved_befores_emit_the_same_list_reply_over_outer_bound`). The harness coalesces PTY reads for these two stimuli because a macOS PTY yields 1 KiB per read and custody rescans all retained tty per read; bytes and frames are unchanged. Local read-review finding, not an observed native failure. |
| Reply precedes drain and denies a credential sent during it | `windows_gateway_unknown_reason/windows_vm_deploy.py.before.source` (`a3c91379`); `WindowsDeploymentGatewayCustodyTests.test_windows_gateway_prompt_after_timed_out_observation_is_a_final_credential_fact` | Before reply says `credentialSent` false while the same custody then sends it. GREEN: `capture` holds the pre-drain facts, `finalCapture.credentialSent` is true, and peer exit 0 proves delivery through the PTY. Local review finding, not an observed native failure. |

Retirement rows below are now canonical in `test_ssh_owned_channel_retirement`;
method names belong to `Fixed546RetirementTests`. Beforeimages are in
`agent_tools/tests/fixtures/owned_channel_retirement/`. Exact associations are
bound by `channel546-retirement-private-candidate-v1/handoff-actual-final.private.json`
(SHA-256 `934d64a43448f300118aab35f4c7ab08737de48d41ea73ddfc1c474c8a088b0f`).
The current canonical 37-method GREEN is in
`stage-a-canonical-adoption-v1/root-canonical-adoption.private.json` (SHA-256
`19a6067480b6baf486631de3364eed1e427587c0b07c1be96158bc1a787371d1`).
Local routine evidence and the separately joined native retirement remain separate.

| Distinct retirement/preparation failure | Complete before and causal method | Proof and limit |
| --- | --- | --- |
| Old helper refuses the explicitly admitted third fixed channel | `546-helper.before.source` (`2cfde229`); `test_authentic_before_profile_red_and_fixed_exact_profile_green_with_declared_inert_release` | Whole before refuses `retirement_identity`; fixed profile binds exact original intent/READY, eleven programs and real status/lost-custody admission. Foreign identities still refuse. |
| Borrowed historical inner timeout branch attempts kill and loses late EOF/bytes | Whole `ssh_connection_recovery.py` (`9c1d6389`), exact `_bounded_socket_query` (`0a636177`); `test_integrated_automatic_gateway_and_inner_carrier_causal_controls` | `carrier-preparation/qualification-e6009ff37d5a44619f9e94136302fa27/summary.json`: actual before branch is trapped without a signal; fixed546 inner retains the same natural child, late bytes and dual EOF while timeout stays UNKNOWN. Historical shared function is not claimed fixed. |
| Private empty-stderr publication rejects its own binary evidence | `546-empty-stderr.before.source` (`e608b2f2`); `test_private_empty_stderr_before_is_actual_red_and_current_publication_green` | `546-private-preparation-provenance.json` and original `tests-v3.stderr.bin`; before raises `unsafe private file`, current real create-only publication succeeds. |
| Reviewed private raw stream accepts mode0644 | `546-capture-custody.before.source` (`c73ac3b8`); `test_actual_reviewed_before_accepts_public_raw_mode_red_and_current_refuses` | `546-capture-custody-provenance.json`; current requires mode0600 for empty and nonempty raw streams. |
| Reviewed private publication adopts post-probe replacement as fresh evidence | Same `c73ac3b8`; `test_probe_writer_generation_and_bytes_remain_held_until_publication` | Same provenance; authentic before accepts same-byte/metadata replacement, current holds original writer bytes/full generation and refuses before terminal publication. |
| Private reader and writer readiness reject valid high FDs | `546-high-fd.before.source` (`1433bc16`); `test_whole_high_fd_reader_writer_red_and_scalable_outer_inner_green` | `546-high-fd-provenance.json` and `high-fd-causal-v1/actual-before-witness.private.json`; real3306 held descriptors/max3308 give reader+writer `ValueError` RED; scalable outer/complete emitted inner GREEN. Before-only rescue drains the same harmless child after the failure latch; no signal/replay. |
| Inert route fixture binds volatile shared ancestors | Whole test before `546-route-fixture.before.source` (`60e8ff7d`); `test_actual_whole_native_fixture_shared_parent_churn_red_and_current_green` | `546-route-fixture-provenance.json`: controlled owned sibling churn reproduces `ValueError: route`; only external-ancestor fixture volatile fields freeze, actual leaf mutation still refuses. Original v12 changed field remains unknown; no production guard is relaxed. After the 2026-11-07 merge the RED arm runs the preserved `original-ee4-remote.before.source` guards (`6a67cbde`), because the current emitted guard deliberately ignores ancestor churn, and a middle arm (current fixture, preserved guards) shows the fixture's ancestor seam is the fix. |
| Retirement source view lacks a module the merged direct catalog loads | Preserved 267 helper; `Fixed267RetirementTests.test_authentic_before_source_view_lacks_readiness_red_and_current_loads` and `test_merged_sources_fail_closed_after_exact_v2_admission_and_authentic_before_refuses_earlier` | Merge review, 2026-11-07. RED: the preserved view gives `FileNotFoundError` on `source-view/readiness.py`, and its helper refuses v2 records with `retirement_authority` or `retirement_source_members`. GREEN: the current view loads, v2 pins are admitted, and real retirements still refuse on merged source with `retirement_executable_source_changed` or `retirement_mcp_source`. |

Private qualification/artifact failures remain separate from owner defects and
native results. Capture's `inert-preparation-fixture-corrections.private.json`
(SHA-256 `3a0e3aab6d823493c1c2ead4354ef839a221df51c8889657afa2e18e1760d544`)
retains three corrections: the broken-before attachment cleanup could not observe
EOF (only its owned local supervisor received SIGINT); read/select/timeout seams
hit Popen/writer setup rather than their intended phase; and status-fixture teardown
closed already-closed handles. Corrected same-child cleanup/seams ran normally;
these do not establish the original Windows cause. Retirement preparation has
these separate non-native records under `channel546-retirement-private-candidate-v1/`:

| Private harness/artifact failure | Preserved before/evidence and correction | Limit |
| --- | --- | --- |
| Overbroad builder full-stat equality guard | `before/prepare_actual_admission-before-atime-guard.py` (`abd83ea0`) asserted `p.stat()==s`; the actual tool transcript retains `AssertionError`. The correction compares the required nine generation fields. | The changed field was not logged; excluding atime does not prove atime caused the original failure. No standalone stderr receipt exists. |
| Private inline preservation path points into `candidate/before/` | Actual tool transcript retains `FileNotFoundError` before any test-source edit; corrected preservation is `before/actual-admission-test-before-counterfactual-owner-binding.py`. | No standalone script/stderr was saved; do not invent one. The shell continued with unchanged source into v15. |
| Current inert facts do not match preserved older-owner schema | Test before `cce38ab9`; `tests-v14.stderr.bin` and `tests-v15.stderr.bin` each record 37 methods, one failure/two errors at `retirement_546_evidence_unavailable`, before intended empty-stream/generation oracles. Fixed `ba8be2c2` binds release data to each actual owner; `tests-v16.stderr.bin` has 37 PASS. | This fixture binding correction preserves the intended old-source REDs; v15 repeats v14, not a second product failure. |
| Generated unified patch is nonapplyable | `candidate-v6.patch` (`20de3425`) fails at fragment1841. Stage A used exact guarded-copy command `50fd8d66`, qualified by `apply-method-qualification-v1/qualification.private.json` (`85da6d87`). | Invalid patch remains failure evidence; no production patch-serializer fix is claimed. |

The builder also correctly refused a mode0644 old root proof (tool transcript
only). Its direct data-only use was omitted; original `0d245d55` stayed unchanged
and remains authentically pinned in the newer private mode0600 root record. This
was no guard relaxation or native failure.

Actual retirement is separately joined by
`stage-a-native-retirement-546-v1/root-retirement-adjudication.private.json`
(SHA-256 `a405c991fac3d7f6f872d1ec12d1c2820454968a7da91569cf29b6c7562c9fad`):
known-zero retained outer/exit-client, both dual EOFs, independent absence and
original546 ENDED publication/readback. Original full ba962 UNKNOWN and missing
original EOF/source-closing remain unchanged. Stage B exact thirty-source adoption
and policy `b2041052` are applied under joined packet `050ef135`; all 203 distinct
methods in the seven-module focused slice pass, with no unresolved skip. Root's
post-check source/policy closure is
`stage-b-canonical-adoption-v1/root-canonical-adoption.private.json`
(SHA-256 `df8f3de570f416e399af17b1b41a778e7c0a3b9471f33412ed689c51a5fb4470`).
At that post-check checkpoint, documentation/version freeze and NEW prepare/select
were pending; later channel267 observations are recorded below. No current
passing prepush or continuation push exists;
all 64 Windows/shared memberships and 58 visual scenes remain open, with no app installed.

### Channel267 prelaunch and private diagnostic failures

Evidence paths here are relative to
`.runtime/windows-parity-20261019/program-tool-native/stage-b-b204-native-v1/`.
The original failed operation is preserved separately from diagnostic-tool defects:

| Failure | Actual before/proof and current limit | TEST-001 disposition |
| --- | --- | --- |
| Oversized c79 prelaunch `SelectionUnknown` | `oversized-original-failure-before-diagnosis/preservation-manifest.private.json` (`c583cc70`) and additional preservation `e2bc2fd2` retain the exact traceback and absent job/intent/owner/child/terminal. Source generations are unchanged; original route cause is UNRESOLVED. | No cause/fix or causal regression is claimed. Preserve without replay; later distinct four-program tool proofs qualify current behavior and do not establish the original cause. |
| Actual diagnostic1 cannot serialize captured raw stderr bytes | Complete entry before `56b9ac4f`; `oversized-original-failure-before-diagnosis/same-boundary-diagnostic-v1/retention-failure.private.json` (`8ba6cb11`) records exec95137 exit1 and unretained diagnostic result/raw bytes. | Local complete-entry `before-rawbytes-red` reproduces `TypeError`; v4 retains typed result/trace before raw publication. Routine wiring adopted and source-current canonical46 passes in final88; this routine gate is CLOSED; this does not repair or explain c79. |
| Private v2 rejects empty binary capture via JSON Snapshot | Entry `39b839d7`; `diagnostic-retention-qualification-v1/v2-empty-readback-red/receipt.private.json` (`102fb206`) records `unsafe private file`, with typed result/trace retained. | Local preparation RED; v4 empty/nonempty refusal and build-success controls pass using the actual canonical binary reader. Routine wiring adopted and source-current canonical46 passes in final88; this routine gate is CLOSED; no native v2 failure is claimed. |
| Private v3 adopts same-byte replacement before readback | Entry `6f749ecd`; `diagnostic-retention-qualification-v1/v3-samebyte-adoption-red/receipt.private.json` (`99791f0a`) confirms acceptance of the replacement, not successful refusal. | Local preparation RED; v4 `7853c190` refuses `diagnostic_capture_generation_changed` and preserves typed result/trace. Routine wiring adopted and source-current canonical46 passes in final88; this routine gate is CLOSED; no native v3 failure is claimed. |

The last three rows use `diagnostic-retention-qualification-v1/handoff.private.json`
(SHA-256 `4ba329a1ace321624a528eb1a008dfcf64531aeb736d6e453725efbe998eb2c1`):
nine actual complete-entry inert controls, zero network/program starts, no canonical
edits. Two earlier import-layout failures occurred before entry execution and remain
private harness failures. Existing canonical 37-method retirement coverage already
exercises empty binary evidence and original writer-generation custody; these new
private entry results do not establish causal routine coverage of the diagnostic
wrappers or the original c79 cause. The focused owner has now implemented a private
37+9=46-method candidate with exact entry RED/GREEN; its handoff is
`channel546-diagnostic-retention-routine-v1/handoff-final.private.json` (SHA-256
`61bfb1d43c4fcca93a878568536df751a5c146e78df53241456bb2eecddafb63`).
That exact wiring is adopted and source-current canonical46 passes in the final
88-method check. The three wrapper routine-enrollment gates are CLOSED; original
native outcomes and the separate Windows acceptance gates are unchanged.
Canonical37 alone was never a RED witness on wrapper56b9. Do not invent a regression
for an assumed original cause.

Actual diagnostic2 separately completed one read-only build: `PlannedArgv`, four
complete same-call admissions, exact raw/source closing, no program/argv execution
and no canonical fix. `oversized-original-failure-before-diagnosis/same-boundary-diagnostic-v4/result.private.json` has SHA-256
`4952a0ce543518e2bbd377a508bd0791b2b0694ce9763c282724f18097846b6b`;
its sibling `same-call-native-capture-index.private.json` has SHA-256
`658314f005baf7c9cadae6bd7cb577e0366ea5c63d97d6208a5bf6e06c43e314`.
All twelve traced events were caught `FileExistsError` in existing-directory/lock
handling. This explains neither original c79 nor LOST diagnostic1.

The distinct four-program DIRECT/fresh-SDK MCP proof qualified the preceding
b204/0b0d source window:
`program-tool-native/stage-b-b204-remaining-proof-v1/native-direct-mcp-qualification.private.json`
(SHA-256 `f88104b12b0fdfe995ef362d312915d7c6044205f04028430c87b25a761858ba`),
root adjudication SHA-256
`fba549716ff1d11e5accd09f22a24af79bf7c59be26da58840b6df7249ab8671`.
It retains the original DIRECT small without rerun, adds distinct large/MCP scopes,
and closes exact streams/exit7/owner/source/keeper proofs for four programs, not 41
program starts. No Windows guest action occurred.

Additional local preparation boundaries remain separate:

| Finding | Existing evidence | Remaining gate |
| --- | --- | --- |
| Repeated private135 manifest-path defect before API/native entry | Preserved full before DIRECT `35d4eba5`/MCP `36edacaa` fail before API. Recipe S's preserved helper450365 derives those operators; current helper0a51 retains the same getter ASTs; `test_direct_manifest_path_causal_whole_entry` and `test_mcp_manifest_path_causal_whole_entry` pass their complete before/current oracles. | Final S recorded31 targets/32 readers; adopted source-current five-method coverage passes after the fixture-isolation correction below. Original N/seven identities remain frozen; no rebinding or launch authority. |
| Missing external-loader post-exec MCP named-source check | Complete old loader312b now has actual source-replacement RED; fixed d03 refuses after exec. S method `test_mcp_named_source_replacement_requires_loader_closing_guard` retains that actual before/current proof. | Locally confirmed, superseding the earlier pending read-review question. Adopted source-current routine coverage passes in final88; this local gate is CLOSED. No native failure is inferred. |
| Pending-prefix regular file replaced by FIFO blocks original open | Complete before5ad9 uses blocking O_RDONLY; actual FIFO RED is released and joined. Current b109 uses O_NONBLOCK plus existing regular-file/identity refusal. S method `test_pending_prefix_fifo_replacement_is_nonblocking_and_refused`. | Actual local RED/GREEN; adopted source-current routine coverage passes. Native observer acceptance remains OPEN. |
| Valid terminal/per-stream EOF receipt sent to pending-only reader | Preserved before5611/5a19 versus current7434; actual RED/GREEN for normal terminal, stdout-EOF and dual-EOF variants. S method `test_uac_receipt_routing_preserves_original_terminal_wait` retains original terminal/owner/source closing. | One routing failure family, three variants. Adopted source-current routine coverage and the separate fixture-isolation correction below pass. Negative newline diagnosis and provisional wording are not additional unsafe-acceptance failures. |
| b7 original operator cannot accept a source-closing publication gap | Original operator observation98/exec73992 exit1 stays UNKNOWN. Root89b4 joins original component terminal0/dualEOF/owner-close/qualified inner/source closing via one pure LOCAL status, zero starts/remote queries. Whole before0b0d fails expected-PENDING/actual-UNKNOWN; current e286 passes `ProgramSourceClosingPublicationTests.test_actual_whole_publisher_gap_before_red_current_pending_then_terminal` with same original harmless publisher/natural closure. | Final private program37 (25+12) PASS15.857s; adopted source-current program37 passes in final88. Routine gate CLOSED; fixed-source native remains OPEN. Native timestamp order alone is not the causal witness. Recovery is component-only; remaining six held. |
| First private publication fix accepts a foreign operation as requested publisher | Complete private before9f1 gives false PENDING on self-consistent foreign records; final e286 gives UNKNOWN without actor lookup. `ProgramSourceClosingPublicationTests.test_self_consistent_foreign_records_cannot_prove_requested_owner` retains actual whole-before/current counterfactual. | Private regression only, never canonical/native. Same final37-method coverage is adopted and source-current PASS. Routine gate CLOSED; fixed-source native remains OPEN. |

The final program-worker candidate is separately pinned by
`program-source-closing-gap-private-v1/handoff-final.private.json` (SHA-256
`577992cb58251d263b41fb36293c963f68e69e56040152b4766e206c14f8d807`),
freeze `a493ceda`, program e286 and 37-method qualification `4a668d9e`. It reports
PENDING only while the exact requested-operation original publisher is positively
live; dead/unproved/mismatched remains UNKNOWN. Any arrived closing receipt still
requires unchanged strict terminal/source/capture/EOF validation. Its initial
private package-root/import mix-up is preserved and corrected as a harness failure,
not a production cause or weakened oracle. Stage C has since adopted e286/policy9e558; the private proof retains its original b204/0b0d before scope.

Stage C's actual42-target adoption is pinned by
`stage-c-canonical-adoption-v1/adoption.private.json` (SHA-256
`ed41525cdd58151ddd4775d5fc1d7dae88ac0be33a13b4ba7eb2b1b3313fa81d`).
Its first canonical88 run has two errors, original raw
`stage-c-canonical-adoption-v1/focused-88.stderr` SHA-256
`bbdf8964b239509f3e0f3343fb1a298ea752e3fb60e2bde7b49d4e443e80b9d4`:
stdout-EOF and dual-EOF routing setup cannot inspect `guest.qualify_instance` source.
That original aggregate stays FAILED. The demonstrated cause was a staged guest
module retained through the canonical test's global alias/package binding after
its temporary source was deleted. It is one fixture-isolation failure family, not
a product/native defect. Handoff
`recipe-routing-canonical-failure-private-preparation-v1/handoff-final.private.json`
(SHA-256 `c095504a2dea32bfbf22bc9efcdbf5bda82b91485df9cd35ba2088aad6e1dd5f`)
preserves authentic before-boundary ea3ba3 and the original failed run. The same
strengthened routing oracle gives actual old-boundary RED3 failures/0 errors in a
preloaded worker; boundary41806/helper0a51 give five-method GREEN, covering cold
three variants, warm normal, and exact aliases/path restoration. An earlier
preloaded-old PASS demonstrated masking only. Two private pretest import/setup
mistakes were preserved separately and corrected without changing product code.

Stage D adoption `stage-d-canonical-isolation-adoption-v1/adoption.private.json`
(SHA-256 `421242a931c19fa6a335ea22f2097308bc2bdb3d0a6e432ea93872a8005ede4e`)
changes only those two fixture/test files plus policy3a4eaf; productione286 is
unchanged. Fresh joined validation
`stage-d-canonical-isolation-adoption-v1/joined-validation.private.json` (SHA-256
`e0d15f8f9224e060b5b3381c19a9089e96c121bbb671e72d3b8543f973b72e37`) records
88 PASS16.885s (program37+retirement/diagnostic46+recipe5), platform2import/7capability
PASS and all43 held full-generation/hash closings unchanged. These source-current
routine-enrollment gates are CLOSED. At that checkpoint, fixed-source native first
fresh T had not started; the later refused caller is recorded below. Remaining six
callers and push remain OPEN; prepush has no final receipt.

The later first post-adoption caller is a separate native admission failure:

| Failure / observation | Preserved evidence and known limit | TEST-001 disposition |
| --- | --- | --- |
| Original4835 first-caller selected-channel refusal | `windows-fixture/post-program-adoption-prerequisite-preparation-v1/native-run-v1/first4835-unknown-preservation-v1/preservation-index.private.json` (`86702dc6`) preserves original UNKNOWN and all84 reviewed pins. Automatic b9 staged a130341-byte wrapper carrying114293 source bytes; journal complement `b6c8df1f` records execution-intent/submission-returned absent. Original diagnostic `08afc0f6` records typed `master_closing` / `fd_changed` before the program loader; program launch capture is null. | Exact changed FD/master type and original cause UNRESOLVED; no speculative cause/fix or causal regression claimed. Preserve original without replay. A separately qualified local FD-enumeration case below does not establish the original cause; adoption and original native acceptance remain OPEN. |
| Controlled listed-FD disappearance falsely refuses an otherwise positively observed listener | Whole before providerfb8dfa sees real listener3 before real removed listed99, then returns `fd_changed`; candidate179c97 skips only that entry's `FileNotFoundError` and positively joins the required listener. `master-fd-enumeration-private-v1/handoff-final-v2.private.json` (`009c4f96`) binds the unchanged same case's natural whole-before-as-CURRENT `fd_changed` ERROR/exit1, current GREEN and private55+4=59 PASS16.824s. | Missing required listener, changed birth/lost stat and `PermissionError` remain refusals. Actual267 ENDED precedes four-source Stage B adoption6ed71d3b; fresh provider59+retirement50=109 PASS14.526s (original7246 natural0) closes this source-current routine-enrollment gate. Original4835 cause and native acceptance remain OPEN. The skipped entry remains unclassified and proves no original4835 FD identity/type/cause. Private test-placement, witness-order and report-writer preparation failures are retained separately, not native causes. |
| Gateway writer-alive test oracle expires before late observation | Original frozen8e55 prepush90637 naturally FAILED1 at `writerAliveAtReturn`; managed workers closed/root exit1. The old injected writer slept .16s; the actual original scheduling cause remains unrecorded. Handoff `gateway-stage-prepush-failure-private-v1/handoff-routine-final.private.json` (`f0d24c0a`) preserves authentic full before plus the identical three-line routine delayed-base-join fixture condition, naturally RED1F/0E, then owned Event-release current GREEN and14-case private GREEN. | Same existing regression retains the causal condition; no producer/production timer changes. Stage A adopted testa854 and canonical source-stage52 passes. Routine mechanism CLOSED at that source; original4835 FD/native cause is separate. The controlled late-observation source is not claimed byte-identical to the unmodified original test. |
| Normal `SystemExit(0)` skips the held loader's post-exec source guard | Found in source review before native submission. Whole authentic getter0a51 emits d03; same positive oracle naturally exits1 before, while candidatec016 emits f9d5 and naturally exits0. `windows-fixture/held-sdk-systemexit-routine-preparation-v1/handoff.private.json` (`85c7f8e0`) and natural-process summaryb7025b55 bind actual causal RED/GREEN; the same five-case family passes privately. | Engineering21's finally loader guarded the later four actual SSH tool programs. Stage F actually adopts six paths/policy688 last (receipt9e20ef17); the existing five-case family canonically PASS5.678s/original25904 natural0 (output3cfcd30e). This live-source unit regression gate is CLOSED. Selected source16/core/e286 are unchanged; four tool proofs remain valid in consumed-runtime-source scope. This is a pre-submit loader-review failure, with no production/native failure claim. Windows-seven rebinding/runs remain OPEN. |

Twelve-source retirement/gateway Stage A is adopted under policy21df, receipt
`stage-e-profile-gateway-adoption-v1/adoption.private.json` (`468884d6`). Canonical
retirement50+source-stage52=102 PASS36.782s; `canonical-64.stderr.bin` is the retained
historical filename, not64 tests. Local real-original17/50 preflight and both absent
execution markers pass (`local-original-preflight.private.json`, `4ec358ff`), with
zero native calls/exit claims/source16 changes. Later once-only actual267 retirement
3f7beb36 returns ENDED, originalexec11155 natural0, complete native exit/status,
independent absence and98 full-generation/hash records closing unchanged, including
all50 historical proofs and16 sources. Root receipt
`windows-fixture/267-retirement-preparation-v1/retire-call-preparation-v1/root-qualification.private.json`
(`f49f564a`) closes original267 only; original4835/c79/b7 outcomes are unchanged.
FD179c Stage B then actually adopted four reviewed sources (provider179c/teste5b5/
fixturea3ab), no policy write/21df unchanged, receipt
`stage-b-fd-adopter-private-preparation-v1/adoption.private.json` (`6ed71d3b`).
Fresh109 (59+50) PASS14.526s on originalsession7246 natural0, retained
`canonical-focused.stderr.bin` SHA-256
`eeebbd4eb137ec7ce422c37fdc320e714346cdd5c239dfb96d7aeaf40b16af68`.
At that checkpoint, four-tool proof/native-seven successor plans were private and
no new channel had been created; the subsequent current-tool qualification follows. No passing current
prepush or push exists. All other native callers are unstarted; all64 memberships/
58 scenes remain OPEN.

Fresh channel11dda7ac's current four tool programs subsequently qualify, receipt3af388db,
joined proof `program-tool-native/post267-stage-b179c-native-v1/native-direct-mcp-qualification.private.json`
(`e85c9f44`), root closinge1840795. Four starts/66 SDK RPC servers,33 source closings,
exact streams/deliberate exit7/full EOF/duplicate/conflict qualify tool behavior only;
zero Windows guest actions and no installed app; all64 memberships/58 scenes remain OPEN.

Current DIRECT canonical call `0694` (`bc3b2867`) and read-only kernel call `8b47`
(`b1bf4497`, boot GUID `71b057dc-cbc9-11f1-8859-a65f36bf1d50`) passed component
qualification. Evidence below is under
`windows-fixture/post267-closure-current-native-preparation-v1/` unless noted.

| Failure / limit | Original evidence | TEST-001 disposition |
| --- | --- | --- |
| DIRECT `8ced` owner-before helper execution error | RPC 83 records `QGAGenericError: Failed to execute helper program (Invalid argument)`, source `e007`, phase `967a`. Read-only `9b3732fd` completed once (original exec `39218`, natural 0/full EOF/source closure); qualification `host-rpc83-readonly-preparation-v1/native-run-v1/actual-readonly-two-file-qualification.private.json` (`5c8eb8f0`) binds the exact 32,805-byte request (`8db1`) and full 214-byte capture (`639e`). Normal delimiter resynchronization and matching nonce ACK precede the helper error; they are not a second failure or a 214-byte final reply. Preservation `d995bdd2` retains 856 files/85 source closings; capsule/journal `b72b` and completion `7fc2` remain separate. | Canonical builder `2938` reserves supported 1,024-unit helper headroom and automatically selects existing saved-source STDIN transfer. The actual 12,122-byte failed script (`e007`) produces natural whole-before `297b` RED/current GREEN, causal result `windows-fixture/windows-spawn-budget-cause-private-v1/causal-results.private.json` (`b7f487a2`). Adoption `windows-spawn-budget-adoption-v1/adoption.private.json` (`2ae5892b`); four canonical consumers: 94 total, 91 pass/three native skips, including artifact suite 20 total/17 pass/three skips. Current DIRECT and matching MCP canonical/six-case/XML prerequisites and exact old-three cleanup below pass; installed-package acceptance remains OPEN. Later metadata supports the bounded overflow explanation below, with no exact historical helper trace or universal helper-bound claim. Guest UNKNOWN/no replay/no-child inference unchanged. |
| Identity collector refuses closing observation before retaining it | First read-only `7d6385a0`, whole source `81f3`, refuses `collector_actor_closing_changed`; its closing fields were not emitted, so the exact original difference is UNOBSERVED. Preservation `host-rpc83-actor-identity-preparation-v1/native-run-v1/first-readonly-closing-refusal-preservation-v1/preservation-index.private.json` (`9881f0d0`) retains the beforeimage and failure. | Diagnostic `65f4ce7a` retains both observations while still refusing identity; original exec `94242` naturally 0/full EOF/source and owner closure. Qualification `host-rpc83-actor-identity-preparation-v1/closing-diagnostic-preparation-v1/native-run-v1/actual-diagnostic-delivery-qualification.private.json` (`c1027a5b`) qualifies delivery only, not actor identity or signal authority. It cannot reconstruct 7d's discarded closing fields. |
| Namespace mtime/ctime changes falsely fail actor identity | Actual `65f4` opening/closing observations differ at exactly 18 fields: namespace target mtime/ctime across nine namespaces. Namespace device/inode and all other compared fields, including full process-root generation, match. | Private collector `c836` and wrapper preserve raw observations and exclude only namespace timestamp indexes 7/8 from identity equality. `host-rpc83-actor-identity-preparation-v1/namespace-stability-preparation-v1/qualification-inert-v1/summary.json` (`ea16799d`): 11 focused cases pass, with natural whole-before `81f3`/diagnostic `200b` RED, fixed GREEN using actual timestamp pairs, and eight strict refusal controls. Native identity call `29650277` qualifies (`6a2ac133`): original exec `7711` natural 0, dual EOF/full closure, 18 raw timestamp differences and empty identity difference. Seventeen-path routine adoption `namespace-projection-adoption-v1/adoption.private.json` (`f2efec5e`), followed by six canonical checks passing in 5.852 seconds, closes this routine gate. One exact host-only pidfd disposition `c9721074` (`67147aee`, natural completion `257b55cf`) closes the parked observer while original `8ced` guest UNKNOWN/no replay remain unchanged. No generic actor-identity relaxation or guest-outcome promotion. |
| Diagnostic result `PSCustomObject` rejects generated properties | V3 `92260053` guest PID `6244` exits 1 with `bootstrapOpening` missing-property error; the original host operator remains UNKNOWN. `v3-diagnostic7479-preservation-v1/preservation-index.private.json` (`7e25917a`) retains 1,017 files/32 actual source pins; the earlier 33-input handoff claim is separate. Exact host-only disposition `b5d626cc` (`e69e4b10`) observes its parked observer exit/absence and new source closure without promoting the original operation. | Whole before body `b076` naturally REDs/exit 1 and current getter body `ba72` GREENs/exit 0 in real PowerShell 7 with declared own-child CIM peers; qualification `windows-fixture/diagnostic-bootstrap-shape-cause-private-v1/real-powershell-pair-final-v1/qualification.private.json` (`2454d2b9`). Full corrected boot-bound Windows PowerShell 5 call `fa759687` naturally returns 0 (original exec `78237`, 4,061 stdout/zero stderr, dual EOF/full closure): `diagnostic-result-container-preparation-v1/diagnostic-packets-v1/packet/direct-canonical-original-operator/qualified.json` (`8332ffce`), completion `bd44754c`, all 35 current runtime inputs close unchanged. Nine-path routine adoption `diagnostic-result-routine-adoption-v1/adoption.private.json` (`e7bac21a`), policy last, and seven canonical tests with real PowerShell/no skips (`canonical-focused.qualified.private.json`, `db34bfd4`) close the routine gate. Original failure evidence and operator UNKNOWN remain unchanged. |

Corrected current DIRECT `a8a4278c` passes all six causal cases with expected
three RED/three GREEN: progress CLIXML 1,297 bytes becomes zero, atomic before fails
while current creates/refuses repeat with 183, and BA owner ACL refusal becomes SY
acceptance. Both owner cases use automatic saved-source transport (30,746 UTF-16
units). All six PS5 actor/boot closings, 32,211 stdout/zero stderr, full EOF and
owner/source closure qualify; exactly three probe scopes remain retained without
cleanup. `native-causal-direct-root-review-v1/review.private.json` (`fe41c7f1`)
joins qualification `eddd8948` and natural completion `70425414`. Current DIRECT
XML `7df75025` also qualifies actual before `TOKEN_TASK_XML` followed by 14 GREEN
controls, including extra-action refusal: root review
`native-xml-direct-root-review-v1/review.private.json` (`7d21da7e`), qualification
`57254f24`/completion `a69e4ae7`, natural 0, 9,298 stdout/zero stderr and full
PS5 actor/boot/stream/source/owner closure, with no task/install/product effects.

Exact old-probe cleanup `48c2d2b4` (`ce48724d`, completion `3c3e1461`) deletes only
three prequalified old `VpnControlTransferProbe` child/root pairs by held handles;
all six known closes and absence-2 checks qualify. Original exec `36347` naturally
returns 0, 3,593 stdout/zero stderr/full closure, all 76 pins unchanged. Original
UNKNOWNs remain unchanged; fresh causal scopes and the later MCP probe remain
retained. Matching fresh-SDK MCP canonical `c3f67b0f` (`78f7e9c9`/`311cb77d`) and
six-case `bdbaa9d3` (`6e31e535`/`af7f8438`) naturally return 0/full EOF/source and
owner closure: respectively 130 source/33 SDK-server closings and 83 source/44
SDK-server closings. Matching MCP XML also qualifies (`5279c8cd`, completion
`e936e9cd`): original exec `4735` natural 0, authentic before `TOKEN_TASK_XML`, all
14 current GREEN controls, 9,298 stdout/zero stderr/full EOF/source and owner
closure, both PS5 SYSTEM actor/boot closings, 136 source pins and 34 SDK-server
closures. These complete the current DIRECT/matching-MCP infrastructure and
old-three cleanup gates; they close no installed-package acceptance or scene.

The native metadata diagnostic observes QGA `110.0.2`, loaded GLib `2.82.2.0`, and
both adjacent helpers, each 26,496 bytes with SHA-256 `4bfe48e0`. Under that layout
and matching upstream implementation, RPC 83's exact 32,710-unit target requires
at least 32,781 units (console: 32,789), above 32,767. This source-supported overflow
explanation is not a retrospective trace of actual helper selection, internal
arguments, original environment or Win32 error; version/hash does not attest an
exact upstream implementation. Join
`windows-fixture/windows-spawn-budget-cause-private-v1/actual-glib2822-native-join-v1/primary-source-minimum-overhead-join.private.json`
(`5340b22c`) preserves those limits, no native file-ID admission and original
UNKNOWN/no replay/no child-absence claim.

The existing 180-second local deadline is an expected UNKNOWN observation stop,
not another product failure. Original `8ced` guest outcome and original `9226`
operator remain UNKNOWN; PID `6244` exit 1 is retained separately. Neither host
observer disposition establishes child absence or replay authority. The current
native source window is closed. Prepush `47576` was intentionally
cancelled and fully closed (`checkpoint-prepush-stage-f-v1/controlled-stop-preparation-v2/after-signal-v1/summary.json`,
`4f43d318`): six complete batches recorded 1,665 tests (zero failures/errors,
seven skips), plus 172 finished observations in an incomplete batch. There is no
final receipt; the cancellation is not a product failure. At this evidence
checkpoint, fresh final prepush was pending and no commit or push had occurred.
The app remains uninstalled; all 64 installed-package memberships and all 58
visual scenes remain OPEN.

### Next checkpoint prepush and host-observer repairs

Managed prepush `93618`/PID `81475` naturally returns 1 at the first
release-hygiene command and fully closes; original stdout/stderr and completion
remain in `checkpoint-prepush-current-prerequisites-v1/`. No later full-suite or
passing prepush receipt is inferred. The following finite repairs preserve the
original failure evidence and beforeimages before changes.

| Failure / cause | Actual causal coverage | Routine and native limits |
| --- | --- | --- |
| Isolated diagnostic recipe imports unavailable `agent_tools`; checker expects five cases although authentic E3 discovers seven; early `unittest.main` omits the diagnostic class in direct execution | Authentic `e3df` whole capability run is RED: seven cases, six POSIX skips plus missing-package ERROR, then stale expected-five assertion; old direct entry actually runs six and omits diagnostic. Current `b86a` reads producer file bytes without the unused package import, declares seven POSIX/one independent diagnostic cases, honors explicit PowerShell and moves main to EOF. Preserved before/current direct-entry and named-runtime controls qualify; four new capability regressions pass. POSIX without PowerShell: seven pass/one honest skip; explicit runtime: eight pass/no skips; Windows-like absent runtime: eight skips; Windows-like explicit runtime: seven POSIX skips/diagnostic pass. | Combined handoff `windows-product-runner/host-asset-shadow-recipe-preparation-v1/handoff.private.json` (`128a4428`), portability handoff `ecb1f0b9`, causal receipts `3084d5de`/`2de25849` and four-control result `fa737258`. Wrong expected total nine still refuses. Core nine-path adoption `host-shadow-and-portability-routine-adoption-v1/adoption.private.json` (`a714b1e0`) uses helper `b86a`/policy `226c`; canonical recipe eight/platform sixteen pass with explicit PowerShell/no skips before the later alias successor below. Loader `f9d5` and prefix `b109` are unchanged. Local own-child PowerShell is not native WinPS5/installed acceptance; fresh final-source prepush remains required. |
| Source-whitespace checker rejects authentic failed-script beforeimage `e007` | The exact 12,122-byte `qga-helper-length.failed.ps1.source` is preserved unchanged. Existing `SourceWhitespaceTest.test_only_exact_authenticated_historical_bytes_are_exempt` actually REDs/exit 1 against whole before checker `812569`, then current checker `0894ef` and test `760bdb` GREEN across all six suite cases/no skips. Qualification `source-whitespace-archive-correction-v1/qualification.private.json` (`e9bb6599`) retains original prepush logs and full beforeimages. | Only the existing `HISTORICAL_BYTE_ARCHIVES` exact path/SHA exception is extended; no byte rewrite, rename or broad exemption. Exact archive, tamper and unlisted controls remain in release hygiene/Fast Checks; checker and diff check pass. This repair supplies no passing replacement prepush receipt. |
| Host observer overwrites callable `generation(s)` with a module-level opening-generation list | Subsequent `terminal.json` hold calls the list and raises TypeError before that FD enters the cleanup list. Authentic whole before `115836` actually REDs (`0947ce50`); rename-only `97e28` GREENs. New routine whole-pair `af77ef7a` preserves the actual traceback and one leaked virtual FD before, all FDs closed after, plus three custody refusal controls; its focused method passes. | Actual host read separately qualifies (`windows-product-runner/baseline-two-host-revalidation-preparation-v1/packet/direct-baseline-two-host-revalidation-original-operator/qualified.json`, `3b46c5e7`; natural completion `5a2ae30f`). Virtual peer leakage is not asserted as an observed native FD leak. Combined handoff `128a4428` is enrolled by core nine-path adoption `a714b1e0`; the existing packet recipe retains complete before/current callers and custody controls. The later two-path alias successor below is separate. Preparation requests remained unsubmitted at this evidence checkpoint; source-current full prepush/product acceptance is still required. |
| Test-fixture Path alias mapping is reset by Python 3.14 initialization | The inherited `PurePath.__init__` receives the original arguments after subclass `__new__`, resetting its mapped path. Authentic preserved boundary `117de` constructor actually returns the Mac root RED for the declared alternate root; current `42933` constructor function returns the alternate root GREEN against real `PurePosixPath`, receipt `a203a42b`. The root's Mac checkout previously matched the literal, so the original local positive had not exercised relocation. | Two-path successor `host-shadow-path-alias-adoption-v1/adoption.private.json` (`e39a449b`) changes only boundary and policy hash (`939e`), leaving helper/platform scripts unchanged. Current routine always executes the alternate-root constructor assertion plus whole host before-TypeError/current-GREEN and three custody controls; standard-module focused test passes one/no skips (`canonical-module-focused.qualified.private.json`, `df9b69b5`). Constructor proof uses a declared peer; no complete alternate-checkout or native/product defect claim. Original whole native host PASS remains separate; fresh prepush is required. |

These fixes and host-read observations close no installed-package membership or
scene. At this evidence checkpoint, the source hold was released to renew bindings
for four unchanged, unsubmitted DIRECT preparations (MSI endpoint/transfer and
Python endpoint/transfer), two physical copies only. Product-scenario MCP remains
required. The app remains uninstalled; all 64 memberships and 58 scenes remain OPEN.
Original UNKNOWNs, retained scope boundaries and the failed prepush remain unchanged.

The seven-callers preparation receipt is
`windows-fixture/current-bf05-seven-preparation-v1/preparation-handoff.private.json`
(SHA-256 `8c62731500d554cd1f6327d82f673c7f261ecdb2e9af34e0a562eab12182ed51`):
local guest17, actual-request7 and whole-outer18 controls, before native submission.
The later b7 component recovery is joined by root89b4 without promoting the original
UNKNOWN operator or launching the other six. Final recipe S is
`windows-fixture/native-packet-recipe-successor-v1/final-successor-handoff.private.json`
(SHA-256 `e85de32ad4f637f8e04ca9a0e75efca393750d6c5728341c929891a316d2db3f`):
five methods, 31 adoption targets/32 current readers, local actual RED/GREEN;
missing-POSIX old3 ERROR/current5 SKIP demonstrates capability guarding only.

Existing canonical UAC foundations remain unchanged. Private31 foundation plus13
whole-outer cases pass under
`windows-visual-context/minimum-uac-foundation-v2/outer-preparation-v1/handoff-outer.final.private.json`
(SHA-256 `2794222695e5dbf6e526fe19fc323fb5670aba325570d01d91f58e7931f2f6dc`),
with local peers, no actual backend/control socket, visual VM or screenshot. No new
canonical feature or native acceptance is claimed. Task/all64 memberships/all58
scenes remain unfinished; no app installed, push or current prepush started.

The remaining native gaps still require final-source inspection and acceptance.
The source-current routine gates described above are closed; private preparation
alone does not establish native acceptance.

| Failure / known or unresolved cause | Coverage / retained evidence | Remaining gate |
| --- | --- | --- |
| Android a96b native1: ancestry changed; exact ancestor/field unretained. Secondary missing `traceback` demonstrated. | Exact emitted-module packet `continuous-entry-traceback-causal-ff7397e5-1c43-4bf9-8d5d-98e717e5b892` beneath WIP Android successor path: RED2 errors → GREEN3 passes. | Map genuine emitter/consumer to canonical routine checks; retain all ancestry fields and add finite diagnostics. Native rerun belongs to subsequent parity. Installer0dd UNKNOWN/held. |
| Linux pending raw-first/anchored capture/inline DTO/observer binding/wrapper path. Compact/cache beforeimages differ from canonical; proposed files absent. | `.runtime/linux-compact-final-review-203e3bf4-ab1a-4711-91cd-99f742342ab1/`; cache `.runtime/linux-negative-cache-review-6ab7354d-a806-4fe6-bf18-a81efb710622/final-naming-addendum.public.json`; [retained enrollment limits](archive/parity/2026-10-14/failure-regressions-through-3944739.md#android-complete-retained-observations-2026-10-140107). | Reconstruct whole delta; map actual consumer and causal routine RED/GREEN for each failure. Later whole settlement does not rewrite original incomplete capture UNKNOWN. |
| Windows bounds/layout/trust/intent/window/cleanup and retained-record components locally corrected; complete caller exceeded 60,000 characters before check. | WIP Windows private batch; [input records](archive/parity/2026-10-14/failure-regressions-through-3944739.md#windows-direct-input-and-readback-faults-2026-10-12) and [retained observations](archive/parity/2026-10-14/failure-regressions-through-3944739.md#android-complete-retained-observations-2026-10-140107). | Confirm existing-versus-missing canonical enrollment; finish caller/server locally before timer. Preserve bounds/quit/f52 history. No check/download/install acceptance. |
| Android dictionaries reached tuple actor helper, falsely checking `/proc/pid`; Windows SYSTEM2020 closing predicate lacks exact opening generation. | [Observations](archive/parity/2026-10-14/failure-regressions-through-3944739.md#android-complete-retained-observations-2026-10-140107) and [collection/resource record](archive/parity/2026-10-14/failure-regressions-through-3944739.md#rich-resource-proof-and-retained-result-collection-2026-10-132359). | Invalid qualification remains excluded; causal routine/native qualification separate. Preserve source/raw; no invented auth/network cause or cleanup replay. |
| Earlier API35 harness/attribution faults coexist with unexplained native failures. | [Source-closure/read-only route](archive/parity/2026-10-14/failure-regressions-through-3944739.md#reviewed-source-closure-schemas-and-read-only-route); exact private raw/source packets. | Distinguish demonstrated harness causes from unproved native/product causes. Collector GREEN does not grant retirement/full routing parity. |

## Delivered routine prevention layers

Use current source and test-matrix mapping rather than replaying archived commands
with historical identities. Complete linked records preserve causal beforeimages/results/skips.

| Cause / routine owner | Complete historical record | Native limitation |
| --- | --- | --- |
| Runner self-input/generation closing, SSH managed fixture roots, Android current-owner bundle identity, downstream physical-batch source pin | [Follow-up integration](archive/parity/2026-10-14/failure-regressions-through-3944739.md#reviewed-follow-up-integration-2026-10-140506) | Complete native scenarios/matching MCP still required. |
| Linked actor/import and 16,384-byte durable JSON/LF bounds | [Actor/import record](archive/parity/2026-10-14/failure-regressions-through-3944739.md#linked-actor-and-isolated-import-coverage-2026-10-140212) | Collector portability does not qualify remote actor or retire installer. |
| Retained binary framing/strict bool-int pins, package Active/Finalized projection | [Complete observations](archive/parity/2026-10-14/failure-regressions-through-3944739.md#android-complete-retained-observations-2026-10-140107) | Partial/error output remains non-admitting; package data remains private. |
| `test_android_current_cli_process_epoch.py` | [Observation fixes](archive/parity/2026-10-14/failure-regressions-through-3944739.md#completed-observation-fixes-and-remaining-native-gates-2026-10-132339) | Recorded21-record facts are engineering observations, not installer/routing acceptance. |
| Rich executable/EACCES census and protected consumer: `test_ssh_tmux_resource_admission`, `test_tmux_resource_routes`, `test_native_engineering_tmux_future`, `test_native_engineering_entrypoint` | [Resource proof](archive/parity/2026-10-14/failure-regressions-through-3944739.md#rich-resource-proof-and-retained-result-collection-2026-10-132359) | No budget admission, reservation release or build follows from census GREEN. |
| Windows receipt/task/parser/bounds and portable fixture guards | [Historical CP117](archive/parity/2026-10-14/failure-regressions-through-3944739.md#cp117-protected-service-recovery-and-retirement-2026-10-01), [full ledger](archive/parity/2026-10-14/failure-regressions-through-3944739.md) | Historical certificates resolve only exact originals; unrelated UNKNOWN remains. |

## Cleanup delivery failures and causal coverage

Original logs/fixture beforeimages: `.runtime/parity-evidence/solo-handoff-2026-10-14/evidence/manifest.json`.
New causal receipts: `.runtime/parity-evidence/docs-cleanup-ci-prerequisites-2026-10-14/`.
Fast Checks' blanket whitespace boundary rejected four byte-authenticated historical
`.source` beforeimages. The actual old workflow produces RED; the repaired workflow
uses the existing exact path/hash checker, including drift/unlisted/untracked refusal.
Four routine whitespace controls pass; original fixture bytes remain unchanged.
Windows baseline selection's locale decoding is reproduced with UTF-8 push/PR
events under cp1252: old selector gives two RED errors, fixed selector's72 controls
pass with malformed/missing/zero/unavailable baselines still refused. Original
Windows log exposes only generic baseline error, so its exact exception is unobserved;
the decoding attribution to that job is an inference. Final exact-SHA CI remains required.
No native scenario or old job was replayed for these fixes.

The first cleanup delivery's Windows run failed in the new whitespace test because
bare `bash` selected the Windows WSL launcher with no installed distribution.
Original full CI log and test/workflow beforeimages are retained at
`.runtime/docs-cleanup-2026-10-14/windows-bash-boundary/`. The portable repair executes
the exact reviewed Python checker command with the test interpreter, refuses
unexpected commands and retains the poisoned-PATH causal RED/GREEN control.
The original four fixture bytes/hashes and whole-whitespace failure evidence remain intact.
Final delivery still requires new content-bound prepush and all five new exact-SHA CI successes.

The next Windows run passed those prerequisites, then its PowerShell5.1 manifest
oracle failed at `Get-FileHash`. The `pwsh` → Python → `powershell.exe` chain inherits
PS7 module paths; the exact original competing path was unobserved. The test-only
repair removes case-insensitive `PSModulePath` from that child environment while
preserving the parent and PS7 route. Real inert-child environment controls give
four RED cases on the preserved helper and six GREEN cases on the fix; they stop
before any PowerShell/hash result and fabricate no success receipt. The unchanged
209-file hash/count/size/tree oracle remains required in Windows exact-SHA CI.
Evidence: `.runtime/docs-cleanup-2026-10-14/windows-hash-oracle/`.

A further Windows package run reached the ordinary desktop test tier and failed
`SuccessfulReceiptWaitsForCoordinatorGateRelease`: its inert fixture still expected
three admission checks. The unchanged adapter now checks during completed-input
cleanup (three checks, two scheduled pauses), then revalidates before relaunch
(fourth check). The fixture-only correction retains two pauses, cleared stage2,
one install/result/relaunch and one disposal; production sources are unchanged.
Original full CI log, beforeimages and causal receipts:
`.runtime/docs-cleanup-2026-10-14/windows-package-build/`. The eight existing
original-user fixture cases remain in routine Windows `:desktopApp:test`; this
inert regression does not run or accept an actual installer/owner-return scenario.

Current custody retrieval still promoted historical instructions after prose moves.
One narrow RAG classification repair demotes archived/retained history for ordinary
queries and keeps explicit history queries discoverable. The same5-test suite gives
three RED failures on preserved code and5 GREEN on the fix, including cache-version
refresh. Evidence: `.runtime/docs-cleanup-2026-10-14/rag/`; native gates remain unchanged.

## Optimization checkout failure and causal coverage

Windows package run `38571387487` at `41da3612c012f98f1e2358e68d81a2e40ce18676`
refused the runner's reviewed dynamic import at line405. Original logs and source
beforeimages are in
`.runtime/agent-tools-optimization-2026-10-14/windows-selection-failure/`.
Actual Git autocrlf checkout reproduces the same RED refusal; the exact-blob
attributes repair gives GREEN for all 55 reviewed loaders without changing the
68 accepted pins. `test_reviewed_source_checkout_bytes` also requires an
unprotected CRLF control, unchanged historical bytes and continued tamper refusal.
The actual attribute-only selector control gives RED0 → GREEN449 consumers;
`.gitattributes` is now recognized as an agent input. Routine affected checks,
managed prepush, Fast Checks and the native Windows managed-check stage enroll
the new test. Full native installer acceptance remains separate; new exact-SHA
Windows package CI must rerun the original failed stage before delivery.

The source checkout controls then passed in Windows run `38578867402` at
`a7a13d395357f6feeb256e419dd1d84f4d07d3d4`. A distinct test fixture failure
expected successful prepush on a host whose private-retention capability is
intentionally unsupported. The native assertion exposed only `ok=false`.
The real-child retainer-only capability seam reproduces the original test RED
and corrected test GREEN with `unsupported_private_retention`, child exit0,
complete captured streams and no validation receipt. The ordinary
`test_mcp_server.FingerprintTest` suite now exercises both actual supported
private output/fingerprint preservation and Windows/missing-API refusal. No
production gate is weakened or replaced with a mocked success. Evidence and
beforeimages remain in the packet's `second-attempt/`; original native Windows
stage rerun remains required before exact-SHA delivery.

## Merge of the paused parity work into `dev` (2026-11-07)

Failures found while merging `a9aed701` and porting the paused worktree. All are
local defects and none is native acceptance. Evidence is under
`.runtime/windows-parity-20261107/merge/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| Private test runner inherits the caller's stdin | `fixtures/runner_stdin_isolation/managed_agent_check.before.source`; `test_runner_stdin_isolation.test_whole_before_managed_runner_launcher_consumed_stdio_current_child_gets_eof` | A runner launched by MCP read the protocol stream. RED on the preserved `managed_agent_check`; GREEN with `stdin=subprocess.DEVNULL`. |
| Timed-out half with parsed failures reruns only those modules | `test_mcp_failed_first_reruns.test_timed_out_private_runner_with_parsed_failures_reruns_its_whole_half` | A timeout means the unlisted modules never finished, so a failed-first rerun must cover the whole half. |
| Windows-only proof of a shared requirement cannot be recorded | `test_native_acceptance_matrix.test_limited_single_platform_receipt_records_on_a_shared_row_without_closing_it` | `matrix-record` refused every receipt on a cross-platform row unless its artifacts covered all four platforms, so the 16 Windows document scenarios had no recordable form. RED on the preserved source; GREEN lets a `limited` receipt carry a platform subset. It stays open and reports `limitedPassedScenarios`; `full-native` and `component` still refuse. |
| Gateway failure path after the merge: drain behaviour and frame loss | `WindowsDeploymentGatewayCustodyTests.test_windows_gateway_failed_drain_still_names_the_closed_reason`, `test_windows_gateway_spawn_failure_is_one_closed_unknown_with_no_child`, `test_windows_gateway_large_echoing_output_is_refused_without_any_stream_in_the_frame` | Review finding, no native failure. The preserved `f38835e5` handler prints only after its drain, so a raising drain loses the whole frame (RED). `a9aed701` refused the prompt during the drain; `dev` never did, and refusing would leave that prompt waiting forever, so the merge keeps answering it and reports `finalCapture.credentialSent` truthfully. The spawn test is a guard, shown by mutation to lose the frame if the no-child branch goes. |
| Visual clone qualifies without the no-update policy | `VisualQualificationTests.test_visual_clone_without_the_update_policy_is_not_ready` | The merge joined `dev`'s update policy with `a9aed701`'s separate visual validator, which never checked it. RED: `setupReady` true with the policy off. GREEN: not ready, and no session binding is written. |
| Hosted Windows capture never names its target | `test_visual_platform.test_hosted_capture_wrappers_name_the_target_the_parser_requires` | `capture-local` requires `--target`. The Linux and macOS wrapper passes `native:<platform>`; the Windows wrapper did not, so every hosted Windows capture would end "Windows visual capture is incomplete" after taking its frames. Found by reading, before any hosted run. |
| Windows remote visual driver rejects the shared `--target` and relative `--output` | `fixtures/windows_remote_visual_capture/`; `test_windows_remote_visual_capture.test_preserved_*` and `test_documented_capture_local_command_with_relative_output_collects_the_frame` | RED: exit 2 `unrecognized arguments: --target`, and `[Errno 2]` for the relative scene path. GREEN adds the capture-only `deployment:<id>` target, allowlisted by the deployment's own retained `windowsUacVisual` intent. Local lifecycle paths still refuse it. No VM was contacted. |

### Windows scenario route, offline build (2026-11-07)

Before any VM contact. Evidence and before-images are under `.runtime/windows-parity-20261107/step2/`; 28 constructed mutations of the driver and host job all go RED (`mutation_red.py`). These are review findings, not native failures.

| Failure type | Regression | Notes |
| --- | --- | --- |
| Frozen bundle keeps only `scripts/` | `test_native_scenario_bundle` | `prepare_bundle` moved only the `scripts` tree, so a bundle holding `agent_tools` paths lost them. RED: 4 errors of 15. |
| Fence could close on an unknown task outcome | `test_windows_scenario_host_job` | An owner whose journal opened with neither a terminal nor a refusal now ends UNKNOWN, and the next job refuses. |
| A SYSTEM program could follow a lost reply | `test_windows_scenario_host_job` | After a lost ack or terminal, or a passed deadline, no further guest program is sent. |
| Free guest text could reach a public reply | `test_windows_scenario_host_job`, `test_native_scenario_windows` | Only closed `RUN_`, `TASK_`, `TOKEN_` and `PUB_` codes cross; the raw message stays in the private index on the host. |
| Status file stops updating after one poll | `test_the_status_file_is_really_replaced_on_every_poll` | `$null` reached `File.Replace` as an empty string; it now passes `[NullString]::Value`. Skips without PowerShell, so CI is its first run. |

### Windows scenario family, offline build (2026-11-08)

Before any VM contact. The first five rows stopped the unchanged case modules
against the real 2.2.15 macOS packaged CLI with a private temporary
`--state-dir`; none is a native Windows failure. Their before-images are
`fixtures/windows_cli_case_rules/*.before.source`, and each oracle of
`test_windows_cli_case_rules` is RED on the preserved module and GREEN on the
current one. The other rows are review findings. `StageProgramTests`,
`PublicEvidenceTests`, `PackageAdmissionTests` and `PackageSubmitTests` are in
`test_native_scenario_windows`; `ProductAdmissionTests`, `PinBoundTests` and
`FamilyJobTests` in `test_windows_scenario_host_job`; `PlannerTests` in
`test_windows_ordinary_task`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A human parser refusal was read as a bare code | `CaseRuleTests.test_disconnected_cases_follow_the_product_rules` (static oracle), `CaseRuleTests.test_the_human_refusal_shapes_are_the_recorded_ones` | The real refusal is one stderr line, `INVALID_ARGUMENT: invalid state directory or command.`. `static_cases` required the bare code and stopped at `human-static-streams`; `human_error_is` accepts `CODE` or `CODE: reason`. |
| Location edits ran in subscription mode | `CaseRuleTests.test_disconnected_cases_follow_the_product_rules` (location oracle) | A subscription add selects subscription mode again, and the owner answers `READ_ONLY_SOURCE` to location edits. `location_cases` first selects current locations with a guarded, revision-checked `source set current-locations`. |
| A transfer imported into a fresh subscription workspace | `CaseRuleTests.test_disconnected_cases_follow_the_product_rules` (transfer oracle) | The destination workspace starts in subscription mode, so `locations import` answered `READ_ONLY_SOURCE`. The second owner selects current locations first. |
| Reads and exports passed `--if-revision` | `CaseRuleTests.test_disconnected_cases_follow_the_product_rules` (diagnostics oracle) | The predicted defect. `diagnostics export`, `operations wait` and `operations status` answered `INVALID_ARGUMENT`: the owner takes the guard only on the writes `capabilities` lists in `revisionGuardOperations`. Every reply still checks its revision metadata. |
| The streaming module expected current locations on a fresh workspace | `CaseRuleTests.test_streaming_cases_select_current_locations_once_on_a_fresh_workspace` | A new workspace starts in subscription mode, so `run` stopped at `fresh-current-locations-before-streams`. One guarded write selects current locations, and every later log pulse stays a known no-op. |
| The staging program refused the cache folder it had just created | `StageProgramTests.test_a_first_staging_under_a_login_umask_creates_private_directories_and_stages_once`, `StageProgramTests.test_a_cache_open_to_other_users_still_refuses` | `os.makedirs` gives its mode only to the last folder, so under a umask-022 login the new cache parent was 0755 and the same program exited 3. It now sets umask 077 first; an existing folder open to other users is still refused, never repaired. |
| A product row stopped after publish claimed installed-package | `ProductAdmissionTests.test_a_product_row_stopped_before_its_task_claims_nothing`, `PublicEvidenceTests.test_a_job_stopped_before_its_task_never_proves_an_installed_package`, `PackageSubmitTests.test_a_job_stopped_after_publish_is_collected_without_an_installed_package_claim` | The receipt claims `installedPackage` only when the task ran and passed its check and nothing stopped the job, and `public_evidence` also refuses a job with `stoppedAfter`. |
| A joint pin excess was refused only by the planner, after every tree read | `PinBoundTests.test_one_file_over_the_bound_refuses_before_any_tree_pin`, `PinBoundTests.test_one_directory_over_the_bound_refuses_before_any_tree_pin`, `PinBoundTests.test_a_product_row_at_both_planner_bounds_runs` | The tree limit was per tree. Both trees are now listed first and counted with the worker request's fixed pins; above 4,096 file or 1,024 directory pins the row ends `worker_pin_bound` before any tree pin and before any task. |
| Leftover files in the install folder joined the recorded base | `FamilyJobTests.test_a_base_install_never_takes_files_it_did_not_install_into_its_baseline`, `PlannerTests.test_owner_reset_installs_nothing_over_files_the_removal_left`, `PlannerTests.test_reset_names_one_exact_product_code_two_private_logs_and_the_folder_it_empties` | A base install refuses with `installed_files_present` when the install folder holds any file. A reset names that folder as `uninstallRoot`, and its worker installs nothing if the removal left files there (event `uninstall-left-files`, exit 1). |
| The submit admission was shorter than the calls under it | `PackageSubmitTests.test_every_call_keeps_its_whole_budget_inside_the_one_submit_admission` | One 180 s admission carried calls budgeted at 390 s, or 1,350 s with a package. It is now their sum, so a slow but in-budget staging cannot clip the submit into an unknown outcome. |
| A scenario input could name another version than its frozen set | `PackageAdmissionTests.test_an_input_naming_another_version_than_its_frozen_set_is_refused_before_any_journal` | Review finding, implemented when the family and UAC tracks were joined. Admission checked source, kind and set membership but never the version, so a mislabelled input was admitted. It now refuses with `windows_scenario_package_version` before any journal. This catches mislabelling, not a substituted package. |

### Windows UAC decision, offline build (2026-11-08)

Before any VM contact; these are review findings, not native failures. Before-images
and the RED/GREEN log are under `.runtime/uac-before/` of the build clone, and for
the review fixes under `.runtime/uac-review/`. All regressions are in
`test_windows_uac_decision`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| TUN finish parks while a prompt is still up | `TunFinishTests.test_the_wait_outlasts_a_prompt_that_the_default_would_park_on` | `finish_operation` parked at its 120 s default, about a prompt's lifetime; TUN finish now waits 300 s. |
| An expired prompt on a TUN grant ends unknown | `TunFinishTests.test_a_cancelled_grant_is_known_and_keeps_the_same_active_runtime` | A grant accepted only `OK`. A CANCELLED that kept active A is now a known failure in the stages; the dispatcher admits a grant only with the collector stage. |
| An expired prompt on an update grant parks the clone | `CancelledGrantUpdateTests.test_a_cancelled_grant_is_closed_and_known_where_it_used_to_park_the_clone`, `CancelledGrantDriverTests.test_a_proven_cancelled_grant_retires_its_unused_hold_and_exits_one` | The handoff check failed with the fixture open. The case now closes what it started and returns 1; the dispatcher retires the unused collector hold. |
| An UNKNOWN input closed its fence | `LostOwnerTests.test_status_never_keys_and_an_unknown_input_keeps_its_fence_open` | Status wrote exit 3 for a dead owner, and any integer exit lets reboots and new jobs through. It now records only the gone prompt. |
| A known input's lost fence close blocked the clone | `LostOwnerTests.test_a_known_input_whose_fence_close_was_lost_is_closed_by_status` | Status returned the input terminal before any closer. It now closes the fence under the lock, with the owner's pid. |
| A receipt was readable half written | `OwnerAdmissionTests.test_the_parent_never_reads_a_terminal_still_being_written` | The final name was created before its bytes, so the parent reported a completed input as unknown. Receipts are now linked from a complete file. |
| The caret refused a good prompt | `ProofBeforeKeyTests.test_a_caret_in_the_field_is_read_again_and_the_prompt_is_answered` | One dark frame of the field refused the attempt; it is now read again within the gate. |
| A prompt could be past 90 s at the first key | `ProofBeforeKeyTests.test_the_age_rule_holds_at_the_burn_and_counts_the_frames_read_after_the_census` | Frames after the second census could add up to the gate's 30 s. The rule is checked again at the burn. |
| A polling client spent every attempt | `ExecuteInputTests.test_a_refusal_that_saw_the_prompt_due_ends_the_submits` | Any refusal allowed a new decide packet, up to 16. Only a "not yet" refusal does now. |
| Protected storage ended known | `CancelledGrantUpdateTests.test_a_cancelled_protected_storage_install_still_parks`, `CancelledGrantDriverTests.test_a_cancelled_protected_storage_grant_still_parks` | An expired prompt returned 1 with the counterfeit root still on the clone. It parks again. |
| An async installer CANCELLED ended known | `CancelledGrantUpdateTests.test_a_cancelled_installer_wait_stays_on_the_parking_path` | No native terminal rules out a running helper there, so it parks until the collector stage. |
| A TUN grant started with no way to finish | `CancelledGrantDriverTests.test_a_tun_grant_waits_for_its_collector_and_starts_nothing` | An approved grant needs its native ready record and would park over VPN B; only `restart-deny` is admitted. |
| TUN inputs could name another variant | `CancelledGrantDriverTests.test_the_tun_inputs_must_name_the_same_variant` | The stages chose restart or find-best, deny or grant, from their own inputs. Both must now name the same variant. |
| A deny row could pass with no decision | `DenyRowAdmissionTests.test_a_deny_row_is_refused_before_any_journal_until_collect_joins_the_decision` | An expired prompt is the same `CANCELLED` as Esc. Deny rows are refused at admission until collect joins the decision terminal. |

### Windows reboot tools and the idle allowance, offline build (2026-11-08)

Before any VM contact; these are review findings and port corrections, not native
failures. The unfixed bytes and the RED/GREEN logs are under `.runtime/reboot/` of the
build clone; the idle census before-image is tracked as
`fixtures/windows_product_allowance/idle.before.source`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The idle census refused every running product | `test_readiness_windows_idle.CensusDecisionTests` and `NativeAllowanceTests`, Windows only; `ProductAllowanceTests.test_before_the_census_blocked_every_running_product_and_now_only_an_undeclared_one` is a source guard | `protected_processes` followed the name alone, so a reboot with the app running was impossible even for an app a passed preboot started and declared. The allowance accepts only a current-boot SYSTEM-owned declaration and checks pid, birth, image, image hash, owner SID, session and a tree rooted at the Task Scheduler service. `CensusDecisionTests` runs the census's own `_OBSERVE` row decision over declared stub facts, on the fix (GREEN) and on the tracked before-image (RED, asserted in the same run); its first run is Windows CI, none ran on the Mac. `NativeAllowanceTests` covers an undeclared process, a wrong hash, SID or session, an owner child, `consent.exe`, a stale boot and a foreign owner. Native only: real WMI rows, `GetOwnerSid`, the SYSTEM owner of the declaration file and the Schedule service parent. |
| The planner refused the updater's tree role | `test_windows_ordinary_task.RebootAndRoleTableTests.test_the_updater_installed_application_tree_role_is_accepted` | `update_receipts.py` leases `installed-application`; the planner knew only `installed-app`. RED `tree-role-schema` on the before-image. Both roles are accepted. |
| A preboot could never finish | `test_windows_postboot_dispatch.MainTests.test_a_returned_preboot_finishes_its_owner_and_prints_nothing` | The candidate owner parked on every preboot return and printed a guest bundle. The app now runs from its own autostart task, so the owner has no live child and finishes; the SYSTEM program collects evidence. |
| Any reboot-action failure parked the clone | `test_windows_postboot_dispatch.MainTests.test_a_known_failure_finishes_with_exit_1_and_is_never_run_again`, `test_an_unknown_effect_parks_before_anything_could_finish` | Only an effect whose outcome is unobserved parks. These peers have no live child; a refusal with one was still parked, see the review rows below. |
| A new boot was proved by the boot identifier | `test_windows_reboot_actions.DeclarationTests.test_a_new_boot_is_a_later_boot_time_never_another_boot_identifier` | Native fact of 2026-11-08: the kernel boot identifier is the same on every boot of a clone. The join and the `.post` admission compare the boot FILETIME. |
| Reboot actions named the wrong owner and compared salted IDs | `test_windows_reboot_actions.PostbootActionTests` | The candidate looked for `vpn-control-cli.exe serve` as the at-logon owner and compared location IDs, which are salted per owner. It now selects the launcher and its JVM child for GUI and `--headless-controller`, and compares location names. |
| An omitted RunLevel was refused | `test_windows_reboot_actions.DeclarationTests.test_an_omitted_run_level_is_the_limited_default` | Exported task XML omits RunLevel for the limited default. `DesktopAutostartManager.kt` may still answer CONFLICT there: a product risk for the first native run. |
| The owned profile was added before its source | `test_windows_reboot_actions.PrebootActionTests` | A fresh workspace reports subscription, so `source set current-locations` now precedes `locations add`. |
| The JVM trust options reached every later child | `test_windows_document_responsive.Qualification.test_a_child_after_serve_that_inherited_the_trust_options_is_refused` | Only serve may inherit them; the owner removes them right after starting serve. |
| A responsive wait timeout was refused | `test_windows_document_responsive.Qualification.test_complete_two_public_protocol_flows_original_child_and_document` | The CLI's local TIMEOUT has a null `controllerId` and `OWNER_METADATA_UNAVAILABLE` (`DesktopCliJson.kt`). Accepted for that call only, with the same operation ID. |

### Windows reboot rows, review of the offline build (2026-11-08)

Review findings before any VM contact. The unfixed bytes, one before-image per fix
step, and the RED/GREEN logs are under `.runtime/review/` of the build clone.

| Failure type | Regression | Notes |
| --- | --- | --- |
| Every reboot row needed a loose installed `sing-box.exe` | `test_windows_scenario_host_job.RebootFamilyTests.test_the_runtime_digest_comes_only_from_the_installed_record`, `test_each_pair_declares_its_app_and_its_postboot_needs_a_new_boot` | The package ships its runtime only as `bin/windows-amd64/sing-box.exe` inside an app jar. RED `installed_runtime_artifact` at publish on the real jar layout. The role is now `runtimeAuthority`, the installed `native-helpers.json` beside the GUI; host and guest take `runtimeAuthority.runtimeSha256` from its pinned bytes. |
| The query row waited for `status` to start an owner | `test_windows_reboot_actions.PrebootActionTests.test_the_query_row_starts_a_transient_owner_by_a_config_query_and_never_reboots_or_declares` | `status` is a no-startup operation (`DesktopCli.kt`), so the body parked: RED `postboot-public-discovery-unknown-no-replay`. Now `status` must answer UNAVAILABLE and `locations list` starts the transient owner. The next RED in the same body was `one-query-started-controller`: the controller launcher and its JVM child share the argv, so the launcher is the one whose parent is neither. The real body now runs offline. |
| A known refusal with a live child parked the clone | `test_windows_reboot_actions.PrebootActionTests.test_a_refused_legacy_fixture_finishes_the_owner_with_exit_1`, `test_a_known_refusal_after_the_query_gui_started_finishes_with_exit_1`, `test_a_known_refusal_retires_the_upstream_and_its_own_serve_and_raises`; `PostbootActionTests.test_a_known_refusal_in_the_traffic_window_stops_the_upstream_and_finishes_with_exit_1` | Run through the real owner `main` and `Owner.run` dispatch. RED `scenario-failure-with-retained-child`: the preboot's own serve (the legacy-fixture gate) or query GUI, or the postboot's upstream, was still live. Now the action stops its upstream and ends its serve or GUI with the journaled public quit to that controller, and the owner finishes with exit 1. |
| A `.post` was admitted after any later boot | `test_windows_scenario_host_job.RebootFamilyTests.test_only_the_readiness_reboot_from_the_preboot_boot_admits_its_postboot` | RED exit 0 after a boot readiness-reboot never submitted. Now exactly one `readiness-recovery-<id>` reboot journal from the `.pre`'s boot, whose idle census knew every declared product process, must exist; the `.post` receipt names it. The boot FILETIME equality rests on `LastBootUpTime` staying the same within one boot, which only a native run shows. |
| A `.post` could follow a `.pre` of another install | `test_windows_scenario_host_job.RebootFamilyTests.test_a_postboot_refuses_a_preboot_that_ran_on_another_install` | RED exit 0. The `.pre` receipt's install record and package must equal the `.post`'s: `prior_preboot_other_install`. |
| A failed or open `.pre` let the next reboot row run | `test_windows_scenario_host_job.RebootFamilyTests.test_a_preboot_that_changed_autostart_holds_reboot_rows_until_its_postboot_passes` | RED: the next `.pre` was admitted while the first one's task named its workspace, and would have parked in its own first snapshot. Now a `.pre` whose journal shows an autostart or product-start intent holds the machine until a passed `.post` names it (`reboot_chain_open`). |

### Windows proxy-lifecycle family, offline build (2026-11-08)

Before any VM contact; these are review predictions proved RED on the preserved
`0f5f3680` modules (a scratch commit whose files landed unchanged as `ce2bc407`),
not native failures. Before-images, `red_green.py` and its logs
for Python 3.14 and 3.12 are under `.runtime/proxy-before/` of the build clone. All
regressions are in `test_windows_proxy_lifecycle`, over a fake process table that
models the launcher pair the old fixture's owner census recorded
(`windows_msi_owner_census.py`: the lock-file PID's parent is a second
`vpn-control-cli.exe`) and `DesktopAppChildProcess.kt` describes. That shape is
not yet proved on this route.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The runtime was sought under the serve launcher, not the JVM it relaunched | `LauncherPairTests.test_the_runtime_is_found_under_the_jvm_the_serve_launcher_relaunched`, `test_a_second_relaunch_or_a_stale_parent_pointer_is_never_taken` | RED `one-exact-owned-proxy-runtime`: sing-box is the JVM's child. `capture_proxy_actors` now returns `owner`, `jvm` and `runtime`; a launcher that did not relaunch is its own JVM, and a child born before its parent is never taken. Every variant met this in `start_runtime`. |
| The sibling census refused the owner's own JVM | `LauncherPairTests.test_the_census_names_the_owner_jvm_beside_the_launcher_and_the_two_runtimes` | RED `machine-census-unexpected-or-duplicate-actor`: the JVM is a second `vpn-control-cli.exe`. The census now names it as `ownerJvm`. |
| GUI windows were sought on the launcher, and a crash ended only the launcher | `LauncherPairTests.test_gui_continuity_follows_the_jvm_each_relaunched_gui_runs_in`, `test_a_frontend_crash_ends_the_jvm_that_runs_the_gui` | RED: `gui_continuity` parks `gui-visibility-unresolved-no-replay` at attach, before its crash. The crash has its own RED: the before-image's `crash_frontend`, called as its `gui_continuity` called it (the runner drops the new keyword), terminates the launcher and leaves the GUI's JVM running. `gui_continuity` now opts in to the relaunched JVM for windows, WM_CLOSE and the crash, which ends the JVM through the handle that identified it; the launcher reports its JVM's code. Whether a terminated launcher takes its JVM with it is unknown, so the old crash could leave the frontend running. The authentic `local` controls keep the launcher-is-its-JVM default. |
| A fresh workspace refused its first location | `SourceOrderTests.test_a_fresh_workspace_takes_locations_only_after_its_source_is_current_locations` | RED `runtime-public-cli-exit-stderr`: `locations add` returns `READ_ONLY_SOURCE` while the source is the default subscription (`DesktopAppService.saveControlLocation`). `start_runtime` now sets `current-locations` first. |
| A finished wrong outcome parked the clone | `KnownFailureTests.test_a_finished_wrong_find_best_outcome_closes_what_the_row_started_and_ends_one`, `test_every_variant_but_tun_closes_a_known_failure`, `test_a_running_sampler_is_waited_for_and_kept_as_evidence` | RED: the failed oracle left serve and the fixture running, so the owner parked and the job ended UNKNOWN. A reviewed oracle failure now runs the row's own closing (off, sibling, fixture files, fixture, quit) and ends 1. The failed oracle never runs again and no unknown outcome is replayed; the closing's own off and quit go out once more when an off left the runtime running or a quit was refused (`test_an_off_or_a_quit_that_had_no_effect_is_issued_once_more_by_the_closing`). Unknown errors, a child with an open outcome, a failing closing step and TUN rows still park. |

Not fixed here, for the update track: `update_cases.py` and `failing_msi_cases.py`
call the same `start_gui` with its launcher-only default, so with a relaunching GUI
launcher an update row would park at attach as `gui_continuity` did. The dedicated
driver loads this lifecycle module for update rows too. Passing `relaunching=True`
there needs its own RED and the update `CASE_SHA` cascade; no update row exists yet.

### Windows proxy-lifecycle family, review of the offline build (2026-11-08)

Review findings on the build commit `2ff432f6`, proved RED on its preserved
dedicated driver (`8714d3bb`), not native failures. The before-image,
`red_green.py` and its logs for Python 3.14 and 3.12 are under
`.runtime/proxy-review/` of the build clone. All regressions are in
`test_windows_proxy_lifecycle`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A proxy row claimed installed-package without `--version` under the ordinary token | `InstalledVersionTests.test_a_row_asks_the_installed_launcher_for_its_version_before_its_runtime_starts`, `test_a_launcher_that_reports_another_version_ends_the_row_before_its_runtime`, `test_a_probe_that_left_owner_state_ends_the_row_before_its_runtime` | The owner's dedicated route returns before its static `--help`/`--version` probe, and no lifecycle module ran one, yet the host job claimed `installedPackage` for every passed proxy row. RED: no probe, a wrong version and created owner state all passed. The driver now runs that same probe, as the ordinary user, before `start_runtime`; a wrong version or created state ends the row 1. |
| The known-failure closing parked when the fixture had ended by itself | `KnownFailureTests.test_a_fixture_that_ended_by_itself_still_closes_a_known_failure`, `test_a_fixture_lease_that_ends_as_the_closing_stops_it_is_still_known` | A fixture past its 1,800 s lease, or one that crashed, exits 1, and the closing's `stop_fixture` required exit 0, so the AssertionError left serve running and the owner parked: every oracle that saw a dead fixture ended UNKNOWN. RED `original-owned-fixture-terminal`. The closing now stops only a live fixture, excuses only the fixture's own nonzero terminal (its lease ending as the stop went out), records that exit and closes the fixture's data leases. `test_a_stop_that_fails_before_the_fixture_ends_is_not_excused` keeps any other stop failure on the parking path. |

### Windows public-update family, offline build (2026-11-08)

Before any VM contact; these are review findings, not native failures. Before-images
and the RED/GREEN log are under `.runtime/updater/` of the build clone, and the
tracked before-images under `agent_tools/tests/fixtures/windows_public_update_defects/`.
The pairs are in `test_windows_public_update_defects`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The planner refused the updater's installed tree | `DefectPairs.test_the_updater_tree_role_is_one_the_planner_admits` | `update_receipts.InstalledApplicationLease` reads one `installed-application` tree, but `validate_closure` admitted only `installed-app`, so every update request ended `tree-role-schema`. Both roles are admitted; the CLI rows keep `installed-app`. |
| `locations add` refused on a fresh workspace | `DefectPairs.test_a_fresh_workspace_takes_current_locations_before_its_first_location` | The reconnect branch added its location while the workspace read subscriptions, which the product answers `READ_ONLY_SOURCE`. It now sets `source set current-locations` first. |
| `on` refused with a revision guard | `DefectPairs.test_on_carries_no_revision_guard` | The branch passed `--if-revision` to `on`, which the CLI answers `UNSUPPORTED` outside its guarded operations. `on` now goes without one. |
| A prompt token vanished after 16 events | `StatusWindowPair.test_a_prompt_event_outlives_the_sixteen_event_window`; `test_windows_uac_decision` `StatusTokenTests.test_the_token_lasts_until_the_decision_has_its_input_terminal` | The run status named only the last 16 event kinds, and the owner's child events push the prompt out within seconds, so a client polling every 5 s could miss `uac-pending`. The status now names the row's prompt kinds from every event, and the token lasts until the decision terminal exists. RED/GREEN under PowerShell 7.4; skips without PowerShell. |
| The failing-MSI fault has no producer | `FailingMsiProof.test_the_real_execute_sequence_is_refused_before_any_derivation` | Proof, not a fix: the product's MSIs carry no LaunchCondition table or action, so the derivation refuses them. `native-install-failed` is refused at admission until a producer exists. |

Review of that build, still before any VM contact. Before-images are the build's
own files, kept under `.runtime/review/before/` of the build clone with their
RED/GREEN log. The driver test is in `test_native_scenario_windows`, the others in
`test_windows_scenario_host_job`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A deny row was admitted though its collector request could never be read natively | `UpdateAdmissionTests.test_the_deny_row_is_refused_until_its_collector_can_take_a_request_and_read_the_disposition`, `UpdateFamilyTests.test_a_published_file_reads_back_auto_inherited_so_a_collector_row_stops_before_its_task` | The pinned collector chain (`collector_contract.file_policy`, the bootstrap and release templates) takes its request file only as `O:SYD:P(...)`. A file the publisher creates and then protects with `SetAccessControl` reads back `O:SYD:PAI(...)`: every native `worker-request.json` pin so far. The fake returned `P`, so `uac-denied` passed offline and would have ended at publish natively. The fake now returns `PAI`, and the driver refuses the row with `windows_scenario_update_collector_unproven`. RED on the build's driver: admitted. |
| SYSTEM cannot read the product's own not-started disposition | `UpdateFamilyTests.test_system_cannot_open_the_owner_only_disposition_so_terminal_actors_ends_unknown` | `terminal-actors` opens `.install-not-started-*.json` as SYSTEM, in the publisher and in the pinned `native_collector`. The product creates it `O:<owner>G:<owner>D:P(A;;FA;;;<owner>)` and nothing enables `SeBackupPrivilege`, so the open is refused while the owner waits on that stage: UNKNOWN, clone blocked. The fake now refuses that open. With the request form supposed, the row ends `collector_stage_failed:terminal-actors`. Only a native run can show the refusal itself. Same refusal token as above. |
| A collector need was served beside a parked owner and after the run returned | `UpdateFamilyTests.test_a_need_beside_a_parked_file_starts_nothing`, `UpdateFamilyTests.test_a_need_read_after_the_run_returned_starts_nothing` | The status handler served every need it read, even when the same status named `owner-parked.json`, and once more after the SYSTEM run returned. A terminal-actors collector started that way waits on a hold the parked caller never writes. It now serves only while the run is open and the status names no parked file. RED on the build's host job: a collector ran in both cases. |
| The update rows were built on the MSI readers the first native contact proved broken | `PublisherFunctionOutputTests.test_the_msi_reader_has_no_bare_method_call_statement`, `RegistrationReaderTests`, `FamilyJobTests.test_a_registration_row_without_a_package_code_is_refused` | Merged from the recovery checkout's natively proven reader fix (its own rows describe those failures): no bare COM calls, one enumeration of every user and context, `InstalledProductName`, a scan count. This build adds `PackageCode` to each row of that reader and requires it in the receipt check, and update rows still check the registration against `baseVersion`. RED for the package code on the live fix's template, RED for the readers on the build's. |

### First full CI run of the merge (run 42392787639 and siblings, 2026-11-07)

These commits had never run in CI, so tests skipped on the Mac met Linux and Windows for the first time. Logs are under `.runtime/windows-parity-20261107/ci/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| Windows helper build refuses a vulnerable toolchain | The Windows Desktop Package workflow itself | `Microsoft.DotNet.ILCompiler 10.0.11` gained high-severity advisory GHSA-p3jp-9v83-76w9 on 2026-11-03 and audit warnings are errors. Pins move to runtime 10.0.14 and SDK 10.0.403. Never suppress the audit. |
| Packaged smoke assumes the wrong start state | `test_packaged_cli_harness.SourceModeSmokeTest` and the packaged smoke on each platform | A new workspace starts in subscription mode. The script expected current-locations, and an exact error line, and had never run on a real package. RED on Linux and macOS CI; GREEN on a real macOS package. The product is unchanged. |
| Linux-only stand-ins lag dev's sign-in changes | `test_windows_login_credential_continuation_execution`, `test_readiness_windows_login` | The stand-in lacked `LOGIN_OWNER_REMAINING`, and a fake owner typed without the credential intent the real flow writes first. Both skip on the Mac. |
| Retirement fixture root collides with the modeled Linux `/tmp` | `test_ssh_owned_channel_retirement` | On Linux a real root under `/tmp` is remapped into itself. It moves to `/var/tmp`; the preserved fixture is redirected without changing its bytes. |
| Stale pin of a changed client | `test_ssh_acceptance_owner_readiness` | dev's client change touched read and follow timeouts, not the request this case proves, so the pin is renewed. |
| Tests assume an order or a moving clock | `test_native_host_observation`, `test_android_persisted_start` | `/proc` listing order is arbitrary, and a Windows clock can return the same value twice. |
| Probe budget too short for real PowerShell | `scripts/check_python_platform_contracts.py` | 30 s cannot fit the complete helper on a hosted Windows runner. |
| Byte pin breaks on a Windows CRLF checkout | `windows-main-input-bridge-test-suite` in `scripts/check_python_platform_contracts.py` | `scripts/capture_visual_windows_qemu.py` is pinned by hash but had no `-text` rule, so a Windows runner saw different bytes. |
| Oracle budget too short for real PowerShell | `test_complete_msi_metadata_recipe_suppresses_com_method_success_values` on Windows | 20 s cannot fit the 28-case oracle on a hosted runner. |
| Windows text mode changes a rendered here-string's hash | `test_actual_powershell_literal_bytes_match_child_and_native_hashes` in `windows_main_input_bridge/v3/controls.source` | Exit 3 on real PowerShell: `write_text` added CRLF, so the parsed literal no longer matched the child and native hashes. The control now writes exact bytes; one line differs from the preserved original. |
| Legacy intent now keeps closed exit facts | `test_readiness_windows_sockets` | dev retains metadata for a legacy intent, so the test asserts that it holds no output rather than that no file exists. |

### Nested reconnect after an ended candidate (Windows deploy status, 2026-11-07/08)

A native failure. The replies are `.runtime/windows-parity-20261107/direct/status-1.json` to `status-3.json`. The retained terminal is `.rag_index/ssh-direct-nested-channel/hosts/archlinux/d5cf3d8a77c08a866afdfa89cd1142a1.terminal.json`. The unfixed adapter that ran is kept byte for byte as `fixtures/nested_ended_candidate/readiness_transport.before.source` (`536fc249`, the campaign's own source pin).

| Failure type | Regression | Notes |
| --- | --- | --- |
| A nested reconnect whose candidate channel ended never became a terminal failure | `test_readiness_transport.NestedEndedCandidateTests.test_whole_before_keeps_the_ended_candidate_pending_current_ends_it_and_reconnects` | The Arch VM was off, so candidate `d5cf3d8a` of recovery `5c310c42` (operation `34e354eb`, the deployment UUID) ended with no receipt. The nested branch of `reconcile_recovery` returned None for every status but ready, so the dispatch stayed pending and each later status call of that operation waited out its budget with `recovery_outcome_unknown`. RED on the preserved whole adapter. GREEN records `ended-<recovery>` with the SHA-256 of the exact retained terminal bytes, then reconnects once under a new recovery. The controls `test_unknown_candidate_status_is_never_ended_and_grants_no_dispatch` and `test_ready_candidate_whose_launch_reply_was_lost_is_selected_not_ended` keep an unknown status and a live candidate unended. Only the remote endpoint is fake, so the status route still needs a native rerun. |

### First native contact of the first family (2026-11-08)

`windows-python-install` passed on all four clones. The first `windows-msi-base-install` of the 2.2.16 target ended exit 1 in its publish stage, before any task or `msiexec`: operation `3a4c2735` with failure `publisher_msi_receipt` and nothing more. The receipts and journals are under `.rag_index/native-scenario-executions/` and `.runtime/windows-parity-20261107/family/`; the unfixed template is kept as `.runtime/windows-parity-20261107/family/diag/before/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A publisher receipt failure lost its cause | `test_windows_scenario_host_job.PublisherReceiptCheckTests` | The failed receipt carried only `publisher_msi_receipt`, and the reply stayed in a guest terminal on the host. The MSI and signer checks now name the check that failed as a finite code (`keys`, `state`, `package_shape_<type>`, `properties_shape_<type>`, `pin_<planner code>`, `held_path`, `held_sha256`, `held_size`), never guest text. A rerun (operation `f9f257f6`) named `package_shape_list`. |
| The MSI reader returned a list, because PowerShell returns everything a function does not capture | `test_windows_scenario_host_job.PublisherFunctionOutputTests.test_the_msi_reader_has_no_bare_method_call_statement` | `Get-MsiProperties` called the COM `$view.Execute()` and `$view.Close()` as bare statements, so their output joined its result and `package` became a list. RED on the template at `ce2bc407` (both bare calls); GREEN discards both. The next native install (operation `67902930`) passed the publish stage and ran `msiexec`. |
| The SYSTEM registration reader missed a per-user install | `test_windows_scenario_host_job.RegistrationReaderTests`, `FamilyJobTests.test_a_registration_read_that_could_not_name_products_says_so` | `msiexec` installed 2.2.16 per user, unmanaged, for the ordinary SID (its log: status 0, `ARPINSTALLLOCATION` set), yet the after-install read found no row: `installed_registration_differs`, then `installed_product_state:count_0` on a reset (operation `d811bdc4`), which refused before any task. The reader enumerated each context by the user's SID, named products by `ProductName` and silently dropped any product whose name it could not read. It now enumerates every user and context at once (`S-1-1-0`, 7) and reads `InstalledProductName`, as the natively proven reader in `windows_tertiary_guest_stage.py` does, and it reports how many products it considered and which name reads failed. A wrong count names both. RED on the template at `ce2bc407`. |

### Windows CLI arguments after the launcher restart (2026-11-08)

A native product failure. On the Windows 11 guest the installed 2.2.16 CLI (runtime
17.0.21) answered `INVALID_ARGUMENT` to the family's `routing set direct-domains`
with `["Example.test"]`, which Python passed correctly (operation `98c8c95a`:
`.runtime/windows-parity-20261107/family/diag/evidence-98c8c95a/`, events 1521
to 1525 and `child-0299.stderr.raw`). Since JDK 17.0.10 (JDK-8301247) the
jpackage launcher restarts itself whenever PATH lacks `<image>\app`, and its
Executor quotes only values holding a space or tab, so `main` received
`[Example.test]`. An empty value disappears the same way, and a quoted value
ending in a backslash swallows the values after it. macOS and Linux are
unaffected. Before-images and the RED/GREEN Gradle output are under
`.runtime/fix-cli-args/` of the fix clone, and those of the review fixes under
`.runtime/fix-cli-args-2/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The restarted Windows launcher handed `main` re-quoted arguments | `DesktopWindowsLauncherArgumentsTest.windowsMainHandsTheCliTheJsonArrayTheUserTypedAfterTheLauncherRestart` and `windowsMainHandsTheCliTheEmptyNameTheUserTypedAfterTheLauncherRestart`, with the escape, restart-model, refusal and detection cases of the same class; `launcher_argument_smoke` in `scripts/test_packaged_cli.py` with `LauncherArgumentSmokeTest` | `main` first takes the waiting parent's command line: only from a parent with the same image that was not created after it, and only when jpackage's re-quoting of it reproduces exactly what `main` received. Anything else keeps the received arguments. RED with the unfixed handoff (arguments passed on unchanged): the native `[Example.test]`, and `--name` left without its empty value. GREEN: `["Example.test"]`, which the CLI parser and the routing logic accept as `example.test`, and `--name ""`. Removing any guard (image, birth, reproduction, platform) turns its case RED. A quoted value ending in one backslash now keeps its `CommandLineToArgvW` meaning, a deliberate trade-off (`aQuotedValueEndingInOneBackslashKeepsWhatCommandLineToArgvMakesOfIt`, `cli.md`). The JNA reads (NtQueryInformationProcess, QueryFullProcessImageNameW, GetProcessTimes, CommandLineToArgvW) run only on Windows: there the packaged CLI smoke, which Windows Desktop Package runs against the real restarting launcher, sets a JSON array and clears a name with an empty value, and fails whenever recovery falls back. `LauncherArgumentSmokeTest` shows each of the two writes failing under a modeled restart without recovery. The family's routing case still needs a native rerun. |
| A parent with exactly its child's creation time was refused, unlike OpenJDK | `DesktopWindowsLauncherArgumentsTest.onlyAParentOfTheSameImageNotBornLaterIsTheRestart` | Found by review of `86a6d163`; theoretical, not observed natively. `86a6d163` refused `parentBorn >= born`, while OpenJDK's `ProcessHandleImpl` (`children`, `descendants`) and `readiness_windows_processes.py` keep an equal time. Only a parent created strictly later is refused now; the image and exact re-quote checks still apply. A genuine restart does not produce an equal time: native creation times are finer than 1 ms (in the recorded guest census `agent_tools/tests/fixtures/windows_desktop_background_roles/native-before.json`, sibling processes 6216 and 4148 were created 90.3 microseconds apart), and the launcher runs before it creates its child. The one recorded restart pair (`scripts/testdata/windows-persistent-*`) was 370 ms apart. So the change removes a theoretical refusal, not an observed or timing-dependent one. RED on the `86a6d163` source: an equal creation time kept the mangled arguments. GREEN on the fix; dropping the birth check turns the strictly later case RED. |

### Native CLI rows of the first family (2026-11-08)

`windows-disconnected-cli-config` (operation `98c8c95a`) and `windows-streaming-client-interrupt` (operation `866c885f`) both ended `job_exit_unknown:owner-parked`, and each consumed its clone. Their events, `child-*.raw` streams and `owner-parked.json` are under `.runtime/windows-parity-20261107/family/diag/evidence-98c8c95a/` and `evidence-866c885f/`. The unfixed owner and streaming module are tracked as `fixtures/windows_cli_native_failures/*.before.source`; the preserved owner's `main()` and the run path of these two actions equal those of `ce2bc407`, the owner that ran. The regressions are in `test_windows_cli_native_failures`, RED on those bytes and GREEN on the fix, with inert peers only. The disconnected row stopped because `["Example.test"]` reached the JVM without its quotes. That is a product defect, fixed separately in the app; the case keeps its product expectation.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The console helper refused the client launcher's own restart child | `ConsoleFenceTests.test_the_launchers_restart_child_is_admitted_as_the_one_third_member`, `test_a_refusal_names_every_member_in_one_finite_stderr_record`, `test_every_other_member_still_refuses_before_any_intent_or_signal`, `test_an_uncertain_signal_still_forbids_a_second_attempt_with_three_members`, `test_a_failure_once_the_intent_exists_is_recorded_unknown_never_refused`; `ReceiptTests` | The helper refused with `only-two-owned-console-members`, so the stream client was still running when the case failed. The installed jpackage launcher (OpenJDK 17.0.21) restarts itself on almost every launch. The launcher the owner started creates a child launcher of the same image in the same console, with inherited handles and a kill-on-close job. It waits for that child, ignores Ctrl+C and exits with the child's code; the child runs the JVM. The helper now admits exactly one more member: the client's direct child, with the client's full image path and session, born after the client. It holds that child's handle until the one signal. The receipt names the child, and the case checks it before it waits for the client to exit with the JVM's 130. Every other member still refuses: a foreign process, another parent, another image or folder, another session, a child born at or before the client, an ended child, a second child, and any change before the signal. A refusal is one finite stderr record naming each member's pid, parent pid, image basename and session, so the next native run shows them; it no longer prints a traceback. Once the create-only intent exists, a failure is recorded as `unknown`, never `refused`, with `intentCreated` and `signalAttempted`; a failed signal call may still have been delivered. The single signal and the create-only intent are unchanged. RED: the preserved helper refuses the native three-member console. Native only: the real launcher pair's parentage, image path and console membership. |
| A known case failure parked the owner while its own children ran | `KnownFailureTests.test_a_known_disconnected_failure_quits_the_owners_serve_and_ends_one`, `test_a_known_streaming_failure_quits_the_serve_and_the_client_ends_by_its_own_close`, `test_a_second_serve_a_case_started_is_quit_first_by_the_controller_its_status_names`, `test_a_serve_the_case_already_quit_is_awaited_and_never_quit_again`, and the parking controls in the same class | Both rows parked with `scenario-failure-with-retained-child`. In `98c8c95a` the serve was still running after `human-exit-code`; in `866c885f` the serve and the stream client were still running after `owned-console-helper-failed`. Nothing was uncertain. The tests run the real owner `main()` and `Owner.run`. A case oracle failure (`AssertionError`) in these two CLI actions now closes what the owner started, as the reboot actions already do, and the owner exits 1. Their case modules start every child through the owner. No child process then has an open outcome, and the product answers a quit `BUSY` while any mutation is in flight. A read-only operation still pending, such as an admitted `--async diagnostics export` whose report stays in memory, ends with its owner. Each serve ends by the journaled public quit to its own controller, after a status admits it. A serve the case already sent a quit, whatever that quit answered, is never sent another: the closing waits up to 120 s for its exit and otherwise parks. A stream client ends by its own close once that owner is gone, because `DesktopCliStream` polls one owner and never starts or rebinds one. A child that already exited is collected. Nothing is killed, signalled or replayed. The owner still parks for a public call or console helper that is still running, for a quit that is refused (`BUSY`) or not admitted, and for a serve or client that has not exited after 120 s. Unknown errors keep the old park, and so do the source-mode and `document-acceptance` actions, whose case modules were not reviewed for a closing. RED: both preserved owners park; GREEN: exit 1 with every child terminal and one quit. Review of the fix found two more defects, RED on its first bytes (owner `3dfa1dfc`, streaming module `50568199`), which never landed: the helper recorded a failed signal call as `refused`, and the closing sent a second quit to a serve whose own quit had answered `OUTCOME_UNKNOWN`. |

### First native and Windows CI contact of round 2a (2026-11-09)

`windows-msi-base-install` of the 2.2.16 MSI built from `04ca7553` ran on two fresh
clones (operations `729de3fc` and `ef5567de`) with the integrated tools of `ea670fe4`.
On both, `msiexec` installed the package (task exit 0), and then the job ended exit 1
with only `publisher_refused:after-registration`. The guest program's own terminal,
read afterwards from the clone's folder and kept privately under
`.runtime/windows-scenarios/<operation>/terminal-after-registration.json`, said
`PUB_MSI_INFO:PackageCode:1608`. The unfixed template, host job and test module are
kept under `.runtime/windows-parity-20261107/family/diag/before-packagecode/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The SYSTEM registration reader could not read a per-user install's package code | `test_windows_scenario_host_job.RegistrationReaderTests.test_each_row_carries_the_package_code_of_its_own_registration` | As SYSTEM, `MsiGetProductInfoExW` answered 1608 (`ERROR_UNKNOWN_PROPERTY`) for `PackageCode` of the per-user unmanaged product, while the installed properties `InstalledProductName`, `VersionString` and `InstallLocation` of the same product read. The reader now takes the installed property `LocalPackage`, requires a flat `.msi` in `%windir%\Installer`, and reads the revision number (PID 9) of that cached package through `MsiGetSummaryInformationW`, which is the installed package code. RED on the template of `ea670fe4`; GREEN on the fix. The native read of the new path is still owed: the next install or reset of a clone that already holds the package reads it in its publish stage, before any task. |
| Windows-only causal harnesses ran the idle census without its allowance prelude | `NativeWindowsProcessTests` (`test_readiness_windows_processes`), `NativeWindowsDesktopBackgroundTests`, `NativeWindowsDefenderServiceTests` | Found by the first Windows Desktop Package run of `ea670fe4` (run 42530357879, 11 failures, log kept privately under `.runtime/windows-parity-20261107/ci/`): `Read-ProductAllowance` was not recognized. Production composes `ALLOWANCE + _OBSERVE` in `readiness_windows_idle.powershell_source`, so the shipped census was complete, but round 2a's census calls the allowance reader and these three harnesses ran `_OBSERVE` alone. They now prepend `ALLOWANCE` as production does. With no declaration on the runner the reader returns an empty allowance, so their census verdicts are unchanged. These tests run only on Windows: the RED is that run, and the GREEN is the next Windows run. |
| A failed publisher program lost its own refusal code | `FamilyJobTests.test_a_failed_publisher_names_the_templates_own_refusal_code`, `test_only_the_templates_own_codes_and_words_cross_from_publisher_stderr` | The template throws finite codes (`PUB_MSI_INFO:<property>:<code>`), but any publisher program that did not exit 0 became `publisher_refused:<label>`, so the cause stayed in a guest terminal on the host. The failure now names the template's own `PUB_` code from the program's stderr, with its detail word and Win32 code only when that word occurs in the template; nothing else of the guest text crosses. RED on the host job of `ea670fe4` (all five cases); GREEN on the fix. |

### First native proxy row and the first output read (2026-11-09)

Two rows on the 2.2.16 install with the tools of `74f80d15`. `windows-proxy-lifecycle.find-best-success`
(operation `6a0a73b8`) ended `job_exit_unknown:owner-parked`; its owner parked with
`scenario-failure-with-retained-child` (`AssertionError`), children 2 (the owned fixture) and 3 (the
serve) without EOF. Evidence: `.runtime/windows-parity-20261107/family/diag/evidence-6a0a73b8/`;
`child-0010.stdout.raw` is the owner's reply. `windows-disconnected-cli-config` (operation `1ee00956`)
got through 298 public commands and ended exit 1 through its known-failure closing; evidence:
`.runtime/windows-parity-20261107/family/diag/evidence-1ee00956/`, events 1585 to 1590. The unfixed
modules, the RED tree and the RED/GREEN logs are under `.runtime/` of the fix clone
(`fix-proxy-start`). RED is the three changed test modules run against the `74f80d15` production
bytes: 59 tests, 24 failures and 11 errors on Python 3.14 and on 3.12, every control passing. GREEN
is the same 59 tests on the fix, OK on both. The proxy row then ran on that fix (`a51ae1b1`, operation
`b3d71dca`, clone `9059be98`) and met the fourth row below; evidence:
`.runtime/windows-parity-20261107/family/diag/evidence-b3d71dca/`, events 131 to 134 and
`child-0040.*.raw`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The proxy rows' owned locations were links the product's parser refuses | `test_windows_proxy_lifecycle`: `SourceOrderTests.test_a_fresh_workspace_takes_locations_only_after_its_source_is_current_locations`, `SourceOrderTests.test_each_owned_location_is_a_socks_link_the_product_parser_takes`, `LinkRuleTests.test_the_fake_product_refuses_a_scheme_its_parser_does_not_dispatch`; `test_windows_reboot_actions`: every test that runs the real preboot body (RED `postboot-public-known-terminal` at its `locations add`), and the control `PrebootActionTests.test_a_profile_the_product_parser_refuses_is_a_known_refusal_that_retires_the_serve` | `start_runtime` published `socks5://127.0.0.1:<port>#Owned%20A`, and the preboot action `socks5://...#Owned%20Reboot`. `ProxyLinkParser.parseProxyLink` dispatches only `vless://`, `trojan://`, `ss://`, `vmess://` and `socks://`, so `--if-revision 1 locations add --input <root>\Owned-A.txt` answered exit 1 `INVALID_ARGUMENT` (child 10). The test worlds' products took any link, so the proxy track passed offline. Both now read the dispatched prefixes from `ProxyLinkParser.kt` (`agent_tools/tests/product_link_schemes.py`) and answer any other scheme exit 1 `INVALID_ARGUMENT` with the revision unchanged; both tools publish `socks://`, which the product renders as a SOCKS5 outbound for the SOCKS5 upstreams. The update cases still require a `socks5://` connection profile, but the host job always passes `initialIntent` `off` with no profile, so no update row reaches it yet. Native only: traffic through the product's `socks://` outbound to the guest fixture. |
| A failure inside `start_runtime` parked the owner over a known outcome | `test_windows_proxy_lifecycle`: `StartFailureTests` | The `AssertionError` of the refused add was raised inside `start_runtime`, before `run_lifecycle`'s known-failure route, so the fixture and the serve kept running and the clone was consumed. Once its serve answers as its controller, `start_runtime` keeps the partial state the closing needs on the owner (`runtime_start_state`: workspace, controller, inputs, fixture, ready record, serve), and `run_lifecycle` sends an `AssertionError` from the start to `known_failure`, unchanged: status, off only while status shows the runtime running, the fixture's own stop record, quit, exit 1. The refused step is never sent again. TUN rows take the same route at start: no TUN stage has begun there, so no pending location, restart, prompt or broker exists, and the fixture and serve are all there is to close; a TUN row's failure after its stages begin still keeps its own ends. A failure before the serve's controller answered (the fixture's ready record, the serve's readiness) and any error that is not an `AssertionError` (an unreadable reply) still escape and park. The real driver, stage and closing run over the world, so the stage's record and the driver's route are covered together. RED on `74f80d15`: the refused add escapes `run_lifecycle` (three tests). Each half is needed on its own: the unfixed driver with the fixed stage, and the fixed driver with the stage's record removed, each fail the same three tests, the runtime-on case at its own `one-exact-owned-proxy-runtime`. |
| The first read of a product-written output compared the path's stat with the handle's | `test_windows_output_reads` | `routing export --output` (human) exited 0 with 184 stdout bytes, and `Cases.output` refused the file with `output-changed-during-read`. That oracle required the path's `lstat` before the open and after the read to equal the handle's `fstat` in dev, inode, mode, size, write and creation time. On Windows, CPython can answer a path stat from the directory entry (`GetFileInformationByName`), whose size and times may lag the file's own while another handle, a scanner's for one, is open: the cause is a hypothesis, unproven natively, and which field differed is unknown. Change is now judged on the handle's stats before and after the read and on the byte count; the path stat gives only the type and the name's identity (volume and file id), which a directory entry holds as the file's own reference. Each refusal names its check and field (`output-changed-during-read:identity-open-ino`, `:handle-size`, `:count-size`, ...), and a passing read records the path-stat fields that differed as `pathStatLag`. The same comparison was in the document fixture worker's `read_exact` (`work-input-closing:<check>`) and the responsive cases' `raw_child` (`original-public-raw-join:<check>`), and the work-event read compared a path size with the bytes read; all now use the handle. The tests model the split over real files: one file's path stat reports a stale size or write time while its handle is current. A file that grows, or whose write time moves, through another handle during the read, and a name that denotes another file at opening or at closing, are still refused. RED on `74f80d15`: each split is refused, except the write-time split of the work-event read, which compared only a size, and no refusal names its check; the refusal controls pass there too. Native only: whether the guest's path stat lags, and in which field; the next run's `pathStatLag` shows it. |
| The explicit-off second serve's line was expected on stdout | `test_windows_proxy_lifecycle`: `DisconnectedServeTests.test_the_existing_owners_line_on_stderr_is_the_known_result`, `DisconnectedServeTests.test_stdout_output_a_second_line_or_a_nonzero_exit_still_refuses` | On `b3d71dca` the runtime started with the `socks://` locations and find-best was accepted and observed. `off_proxy_and_disconnected_serve` then refused the second `serve` on the same workspace, which exited 0 with nothing on stdout and exactly `VPN Control is already running.\n` on stderr (child 40; event 134 `second-serve-existing-owner-result`), and the start's known-failure closing closed everything: exit 1, not parked. The oracle wanted that line on stdout with stderr empty, but the product prints every headless-controller line on stderr: `DesktopHeadlessController.handleArgs` defaults `printLine` to `writeDesktopCliLine(System.err, ...)`, one line ending in LF, and `DesktopExistingService.adopt` prints this one and returns 0 once the running owner accepts `ControlServe`. The oracle now requires exit 0, empty stdout and exactly that one stderr line. The proxy world's product now adopts a running owner on a second `serve` with that reply, and an explicit `off` remembers `resume_connection_on_launch` false, so the real oracle runs over it. RED on `a51ae1b1`'s case bytes: the native refusal, and the control's stdout reply, which that oracle took; GREEN on the fix, Python 3.14 and 3.12. A reply on stdout, a second stderr line, a refused adoption (`OUTCOME_UNKNOWN`, exit 2) and a nonzero exit still refuse. No other headless-controller or human-mode product line is expected in `windows_lifecycle_cases.py`, `windows_runtime_branch_cases.py`, `windows_lifecycle_runtime_stages.py`, `windows_preboot_action.py`, `windows_postboot_action.py` or the responsive document modules: their other stream checks read `--json` replies on stdout, where the product writes them, or the streams of our own helpers. No reboot or postboot world starts a second serve. Native only: the rest of the row after this step. |

### Idle census roles of image 637199a5 (native, 2026-11-09)

The enrollment of NV3 (clone `a218e890`) stopped at its full idle census `6d2447bc`: three
refusals in three minutes with `unknown_jobs`, for `OneDrive.exe` and `WidgetService.exe`
in console session 2. A read-only role probe of NV4 (clone `9059be98`, never signed in by
the tools; operation `8c7ef46c`) found `AppActions.exe`, `OneDrive.Sync.Service.exe` and
`WidgetService.exe` unknown there. Evidence is under
`.runtime/windows-parity-20261107/enroll-a218e890/` and `roles-9059be98/`. The unfixed
roles and census of `74f80d15` and a synthetic projection of the facts are tracked in
`fixtures/windows_console_session_roles/`. `test_windows_console_session_roles` composes the
whole census as production does (the module's native reader with only its six OS calls
answered, the roles, `ALLOWANCE` and `_OBSERVE`): the unfixed program reproduces NV4's
unknown set exactly (RED), the fixed one knows all four roles (GREEN), and 36 controls that
differ from the native facts by one fact stay unknown while the two forms of the 2026-11-06
probe stay known. That program runs in Windows PowerShell only on the Windows runner. It
also ran under PowerShell 7.4.20 on the Mac with two non-Windows seams, where removing any
one of eight checks of the new rules turned exactly that check's controls known.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The widget board's service of the Web Experience package had no rule | `test_windows_console_session_roles` (`NativeConsoleSessionCensusTests`, Windows only; `ConsoleSessionRoleSourceTests` everywhere) | On this image `WidgetService.exe` runs from `MicrosoftWindows.Client.WebExperience_424.1301.270.9_x64__cw5n1h2txyewy\Dashboard\`, not from `Microsoft.WidgetsPlatformRuntime`, as a COM server (`-RegisterProcessAsComServer -Embedding`) started by a session-0 `svchost.exe`. `Test-RecoveryComServer` requires the Windows-signed package family from the process token, the exact image under its install folder, the exact COM arguments, a Microsoft Authenticode signature, the ordinary owner SID, the console session, and a live session-0 System32 `svchost.exe` parent that is Microsoft-signed and born no later. The Widgets Platform Runtime rule is unchanged. |
| `AppActions.exe` had no rule | as above | The `MicrosoftWindows.Client.CBS` COM server in `SystemApps` (`-Embedding`), with the same parent as the widget service; the same checks with its own family, image and arguments. |
| The unconfigured OneDrive's sync helper started without its image on the command line | as above | NV4 read `/silentConfig` alone; the 2026-11-06 probe read `"<image>" /silentConfig`. The rule accepts exactly these two forms; its folder, account, owner, session and signature checks are unchanged. Its parent had exited in both probes, so it has no parent check. |
| `OneDrive.exe` unknown on NV3 only | none: unresolved; the `ONEDRIVE_*` controls pin the unchanged rule | Already unknown in census `5f5acb26`, six hours after logon and before the first sign-in, so the sign-in is not the cause. NV4's `OneDrive.exe` (`" /updateInstalled /background"`, parent exited) passes the rule, which reads neither command line nor parent. What it does read, and so what can differ: the `Accounts` slot names, the slot and value-name counts, the seven configured-account field names, the owner and profile lookups, the exact image path and the signature. NV3 kept no role facts, so the cause is unproven, nothing is relaxed, and NV3 stays blocked by `OneDrive.exe` until a read-only probe of those names shows it. |

Finding, no change: NV4's `OneDrive.exe` started 155 s after logon with `/updateInstalled`,
the argument OneDrive's update installer passes when it restarts it, from a parent that had
already exited. The fixture user's OneDrive is `26.198.1011.0006`, a 2026 build, while the
image's Administrator profile keeps the 2025 build `25.087.0506.0001`, and the fixture
user's `OneDrive Standalone Update Task` is `Ready` while the Administrator's is `Disabled`.
`UPDATE_POLICY` disables only the update tasks that exist when it runs; nothing stops
OneDrive from registering the fixture user's task later, when it installs or updates itself
for that user. Whether NV4's run changed the installed build is unproven: its startup task
still names `26.198.1011.0006`, as on 2026-11-06.

### Windows Defender Firewall prompt in the idle census (native, 2026-11-09)

After a proxy row on NV4 (clone `9059be98`) whose `on` made the product bind a wildcard
listening socket (a product defect, fixed separately by binding loopback), its plain census
`d82d82a4` had one unknown process, `PickerHost.exe` in console session 2. The read-only
role probe `3a0442dc` (operation `7e74021a`) found the COM server of the Windows Defender
Firewall's allow-access prompt, which stays open until answered, so the full idle census
refuses `unknown_jobs` and the clone can be neither enrolled nor rebooted. That census ran
the roles of `f80b3378` (alias pin `6adbd689`) and knew `AppActions.exe`,
`OneDrive.Sync.Service.exe` and `WidgetService.exe`: the first native run of the rows above.
Evidence is under `.runtime/windows-parity-20261107/enroll-9059be98/`. Those roles are
tracked as `fixtures/windows_console_session_roles/processes-firewall.before.source`, and
the facts joined the same synthetic projection. Under PowerShell 7.4.20 on the Mac, with the
same two seams, both unfixed programs reproduced their native sets, and removing any one of
the prompt rule's five checks, or the shared owner or parent check, turned exactly that
check's controls known.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The firewall's allow-access prompt had no rule | `test_windows_console_session_roles` (`NativeConsoleSessionCensusTests.test_first_fix_census_leaves_the_firewall_prompt_unknown_RED_and_the_fixed_census_knows_it_GREEN` and the `PICKER_*` controls, Windows only; `ConsoleSessionRoleSourceTests` everywhere) | `Test-RecoveryFirewallPrompt` requires the image `%SystemRoot%\System32\PickerHost.exe` exactly, the command line `<that image> FirewallNotificationDialogServer -Embedding` and nothing else (case-insensitive; the native line spells `PickerHost.Exe`), no package (`packageError` 15700), a Microsoft Authenticode signature, the ordinary owner SID and the console session. It then takes the owner and parent tail of `Test-RecoveryComServer`, now `Test-RecoveryServiceStarted`: a live session-0 System32 `svchost.exe` parent with a valid identity, Microsoft-signed and born no later. A quoted image, another server, and a missing or extra argument stay unknown. The unfixed census over the later session, the four roles and the prompt, reproduces `d82d82a4`'s unknown set exactly (RED); the fixed one knows it (GREEN); 14 `PICKER_*` controls stay unknown. The probe recorded only that the signer is one of the three accepted Microsoft publishers, so the rule uses the shared signature check, not one subject. |

### Windows document family, offline (2026-11-09)

The review predicted these defects, and they were proved offline when the document
rows landed. No native run has reached them. Before-images are tracked under
`agent_tools/tests/fixtures/windows_document_acceptance/` with their provenance. The
RED runs on them are in the build clone's `.runtime/evidence/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The export relay parsed the product's plain-text acknowledgement as JSON | `test_windows_document_acceptance.ExportRaceAckTests.test_the_products_plain_text_acknowledgement_is_relayed`, `test_only_the_first_export_read_is_the_barrier` | `DesktopControlDocuments.downloadExport` acknowledges with `ack:<id>:<sha256>` as the command text. `is_export_read` raised `JSONDecodeError`, the relay dropped the acknowledgement and `close_known()` refused, so the parent race parked its owner on every run. RED on the before-image: the client read EOF instead of `ACKNOWLEDGED`. The relay now forwards an acknowledgement unchanged, as the product orders it. The relay runs over socket pairs, so no listener opens. |
| A document case's own oracle failure parked the owner with only its serve running | `test_windows_document_acceptance.DocumentKnownFailureTests.test_a_document_oracle_failure_closes_the_serve_and_ends_one` and its controls (`test_anything_in_flight_keeps_every_original_for_the_park`, `test_only_the_modules_own_finite_codes_are_known`, `test_a_harness_oracle_on_a_completed_public_call_is_known_too`, `test_a_failed_release_is_unknown`) | `document-acceptance` caught only `AssertionError`, while the document modules raise `RuntimeError` codes. A case module now opts in with `close_known`. It counts the harness's oracle and its own `document-` codes only after every client socket closed, every export relay stopped and both fixtures were released, then releases its endpoint and workspace observers before the reviewed `close_known_failure`. The responsive cases define no `close_known` and still park. |
| The closing counted a quit sent before a serve started as that serve's own | `test_windows_document_acceptance.ReopenedOwnerTests.test_a_serve_started_after_the_cases_quit_is_quit_not_awaited`, `test_the_owner_closes_the_workspace_a_cold_case_reopened` | A cold case quits the original serve and reopens the workspace. `close_known_failure` keyed case quits by workspace, so it only awaited the reopened serve, which never exits unasked, and parked after 120 s. Only quits with a later ordinal than the serve count now. The owner closes a reopened owner on a pass as well. |

Review of these rows found five more defects in their first bytes (`d84f391c`),
which never landed. Each is RED on those bytes (kept, with the RED output, in the
build clone's `.runtime/`) and GREEN now. The probe rows share one harness: it
runs the publisher template's own probe function under PowerShell against a fake
Task Scheduler, with stand-ins for the Windows-only SID types, so nothing reaches
a real scheduler. The same review renamed the cold variant `gui-transfer` to
`gui-owner`: it runs only the CLI half of gui-cli-transfer, which stays open.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A probe that failed after its task existed ended without a reply, and the job closed the fence | `test_windows_scenario_host_job.PrincipalProbeProgramTests.test_the_reply_names_every_task_that_may_still_exist_and_only_an_absent_one_is_known`; `DocumentFamilyTests.test_a_probe_program_that_ends_without_its_reply_is_unknown_and_keeps_the_fence_open`, `test_a_probe_task_left_registered_is_unknown_and_keeps_the_fence_open`, `test_the_publishers_own_boot_refusal_runs_nothing_and_is_a_known_refusal` | A refused `DeleteTask` threw out of the program with no stdout, and the job read every failed program as `document_principal_refused`, exit 1, closing the fence over a task that may still exist. A `Run` that threw counted as never run, so its task was deleted; a registration that threw was not counted. The action now always replies: as in the run template, the task counts as registered before `RegisterTaskDefinition` and as run before `Run`. The job reads a program without its reply as UNKNOWN unless the boot check refused before any effect. RED: no reply for a refused delete or a leftover task, a deleted task after a throwing `Run`, and a known exit 1 with the fence closed. |
| Any failed lookup counted as the probe task's deletion | The same harness test (`lookup-denied`) | `GetTask` failing for any reason set `deleted`, so a task still registered could close the fence. Only `0x80070002`, the run template's `Is-TaskAbsent`, proves absence now. RED: `deleted` true with the task still registered. |
| An ended probe task that wrote no result was left registered | The same harness test (`ended-without-result`); the `result-missing` case of `DocumentFamilyTests.test_a_probe_that_proves_no_denial_by_another_principal_fails_the_row` | The wait needed the result file, so it ran the full 120 s, left the task and ended the job UNKNOWN, blocking the clone. A task seen to end (no instance and a final `LastTaskResult`) is deleted now, and its row fails with `document_principal_result_missing`. RED took the full 120 s; GREEN takes seconds. |
| On a pass the owner awaited a GUI-started owner's exit without a bound | `test_windows_document_acceptance.ColdCaseTests.test_a_gui_owner_that_stays_after_its_acknowledged_quit_parks_within_the_bound` | After the acknowledged quit, the owner called the unbounded `wait()`, so a GUI that stayed would hold it until the row deadline. It now gets the closing's 120 s, then the owner parks with `document-gui-owner-exit-unknown`. RED: the inert peer refuses an unbounded wait on a live child, so the first bytes parked with `scenario-failure-with-retained-child`. |
| The joint pin bound missed a document row's guest-made document | `test_windows_scenario_host_job.DocumentPinBoundTests.test_the_document_input_counts_toward_the_joint_bound_before_any_tree_pin` | The document joins the worker's pins after the bound is checked. RED: one pin over the bound passed, both trees were pinned, and the planner refused (`planner_refused:pin-list-schema-or-bound`). GREEN: `worker_pin_bound` before any tree pin, and exactly 4,096 pins still run. |

### The document probe harness on the first CI run of `529cc610` (run 42656925414, 2026-11-09)

Fast Checks, job `Agent Tools Shard 5` (Linux, Python 3.12, PowerShell):
`PrincipalProbeProgramTests.test_the_reply_names_every_task_that_may_still_exist_and_only_an_absent_one_is_known`
failed with `ParserError` at `probe.ps1:212`, the line
`'@ -ReferencedAssemblies @('System','System.Core')`: `Unexpected token '-ReferencedAssemblies' in
expression or statement`. The log is kept privately as
`.runtime/windows-parity-20261107/ci/failed-42656925414.log`. The Mac has no PowerShell, so the test
skipped there and CI was the first to run it against the changed template.

The defect is in the test's helper, not in a guest program. `principal_probe_program` compiles its
body from a single-quoted here-string, and it took that body from the publisher template as
everything between `function Get-EndpointFacts(` and `function Get-CollectorObservation`. `957cab0e`
added four functions between those two, and one of them, `Add-ObserverType`, holds an
`Add-Type -TypeDefinition @'` here-string of its own. A here-string cannot hold another of its kind:
the inner terminator on line 212 ended the helper's here-string, opened on line 41, and the helper's
own terminator on line 275 was left over.

Production is not affected. No production code slices the publisher template: the job fills the
whole template. Its three slicers (`fragments`, its `block` and `held_program_type`) read the owner
script and the emitter's bodies. The native slice is the owner's one here-string cut before
`RetainedRawPump`; `CREATE_DIRECTORY` and the held type are, byte for byte, the whole here-strings of
the emitter that hold the class each needs; `READONLY` is the held type without `Identity`, renamed.
Checked offline with the reader named below, on the production sources of `529cc610`: the 6,035
distinct guest programs the module's tests render from the templates (every publisher action, among
them `principal-probe` and `collector-observe` of all four stages, the SYSTEM run, the context
program, the collectors and their releases) close every here-string, hold no terminator outside one,
and compile only their intended types. On the same CI run
`SourceTests.test_every_rendered_source_parses` and
`UpdateFamilyTests.test_the_collector_and_release_programs_parse` passed under PowerShell. The sweep
and comparison scripts, the RED worktree and the logs are under `.runtime/probe-parse/` of the fix
clone (`fix-ci-probe`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| The probe test's helper wrapped a template function that holds a here-string in a here-string of the same kind | `test_windows_scenario_host_job`: `PrincipalProbeProgramTests.test_the_program_is_two_whole_here_strings_and_compiles_only_what_the_probe_needs`, `test_every_function_of_the_template_is_selected_whole_by_its_own_name`; `HereStringTests` (4); controls on the rendered guest programs: `SourceTests.test_every_rendered_source_keeps_its_here_strings_whole`, `UpdateFamilyTests.test_the_collector_program_is_the_rendered_template_on_the_stdin_route` | The helper now takes the four functions the probe needs (`Read-Bounded`, `Get-EndpointFacts`, `Is-TaskAbsent`, `Invoke-PrincipalProbe`), each by its own name: `template_function` ends a function where the next top-level statement begins and never takes a line of a here-string for a statement. The program it renders is byte for byte the one the unfixed helper rendered before `957cab0e`. The probe code and those four functions are unchanged since `70ed16cc`, and CI run 42598475217 passed that program under PowerShell. `here_strings` is a pure-Python model of how PowerShell delimits quoted strings, comments and here-strings, so this defect shows where no PowerShell is installed. It reads only that layer and is not a parser. On the 71 PowerShell files of the repository it agrees with a plain line scan everywhere except three lines where a quoted string ends in `@'`, which the line scan misreads as a header. RED is the fixed module with only the helper of `529cc610` put back (235 lines added to the `529cc610` module, none removed), in a worktree of `529cc610`: 17 tests, 1 failure, 3 skipped, on Python 3.14 and 3.12 alike, `here_string_terminator_outside:line 275:the one opened at line 41 ended at line 212`, the line PowerShell named. GREEN on the fix: the same 17 OK, 3 skipped, and the whole module, 172 tests OK, 4 skipped, on both. Six mutants of the host job's slicers and of the template (a terminator taken from the wrong place, a lost header, a lost terminator) each turn one of the two controls RED. Only CI proves the PowerShell run itself: the module's four PowerShell tests still skip on the Mac. |

### Windows scoped-TUN family, offline build (2026-11-09)

`windows-scoped-tun.<variant>` rows adapt `windows_tun_stages` to the scenario route; only `restart-deny` is admitted (see `agent_docs/tools/visual-and-platform-evidence.md`). Nothing here has run natively. Two existing behaviors would have parked a clone over a known outcome, the class the spec predicted as "parking on known failures". The unfixed bytes are `.runtime/tun-before/windows_ordinary_dedicated_driver.py.before` and `.runtime/tun-before/windows_tun_stages.py.before` in the build clone; RED ran in an isolated worktree at `ea670fe4` (`.runtime/red-base`), and the RED and GREEN output is under `.runtime/tun-logs/`. Review of the build found six more defects, RED on its first bytes (`ffad8f0e`, which never landed): the unfixed bytes are in `.runtime/review-before/` of the build clone, RED ran in an isolated worktree at `ffad8f0e` (`.runtime/red-review`, removed after use), and the RED and GREEN output is under `.runtime/review-logs/`. The review also found that the fixture provenance of `stages/controls.source` still named its historical original without recording that the bytes differ; the entry now records `originalSourceBytes`, `originalSourceSha256` and `currentRoleAdjustment` (metadata only, no regression).

| Failure type | Regression | Notes |
| --- | --- | --- |
| A TUN row parked on a refusal before it asked for anything | `test_windows_proxy_lifecycle.KnownFailureTests.test_a_tun_refusal_before_its_request_closes_the_proxy_like_any_known_failure`, with `test_a_tun_row_keeps_its_own_known_ends` and `test_windows_tun_stages.BeginTests` | The driver re-raised every `AssertionError` of a TUN row, so a refusal in `begin` before the request (a broker or TUN route already present, a changed active A) parked the owner, although only the row's own proxy ran. `begin` now marks `tun_operation_requested` just before it asks for the restart or Find Best; until then a refusal closes like any proxy known failure (off, fixture stop, quit, exit 1). After it, any failure parks until the operation settles, including a lost, transport or foreign reply to the request; a final refusal from the row's own controller is a known end (below). RED on the `ea670fe4` driver: the refusal propagates. GREEN: exit 1 with one off and one quit. |
| A TUN row parked on a final product code its variant did not expect | `test_windows_uac_decision.TunFinishTests.test_a_refused_preparation_on_a_denial_is_a_known_end_not_a_parked_owner`, `test_windows_tun_stages.FinishTests` and `CancelledGrantDriverTests.test_a_known_tun_end_that_is_not_the_variants_own_closes_by_its_census_and_exits_one` | `finish` passed only the variant's own codes to `finish_operation`, which refuses any other final code, so a denial whose preparation failed before any prompt (`RUNTIME_FAILED`) parked. `finish` now reads every final code the stages know. One the variant does not expect is a known failure only when active A is unchanged, owner and runtime are unelevated and the census finds no broker, no new runtime, no new stage and no TUN route; the driver then closes the row by the same steps as a pass and exits 1. A denial that connected (an `OK` that changed A), or anything scoped left behind, still parks. RED on the `ea670fe4` stages: `original-operation-unexpected-terminal`. GREEN: `knownFailure` `RUNTIME_FAILED` with no park. Native only: which codes the product returns for each refused preparation. |
| A TUN row parked on an oracle failure after its denial had settled | `test_windows_proxy_lifecycle.KnownFailureTests.test_a_failure_once_the_denial_settled_closes_with_its_census_after_the_off`, `test_a_failure_after_the_census_closes_without_reading_it_again` and `test_anything_scoped_left_behind_parks_with_the_rest_kept`; `test_windows_tun_stages.ClosingTests.test_an_operation_settles_on_a_denial_a_known_end_or_a_grants_exact_off` | `tun_operation_requested` was never cleared, so once `finish` had read the denial's final code with A intact, a later oracle (`off_proxy_and_disconnected_serve`, the fixture stop, the quit) still re-raised and parked, where a proxy row ends 1. The driver now re-raises only until `windows_tun_stages.settled(lease)`: the denial's own code, a known end, or a grant's exact off. A later failure closes through `known_failure`, whose census reads right after its off; a census that finds a broker, runtime, stage or route left behind parks at once with serve and fixture kept, in a pass too. RED on the `ffad8f0e` driver: the oracle failure propagates. GREEN: exit 1, with one census between the off and the fixture stop. |
| The closing census refused a grant that brought no TUN up | `test_windows_tun_stages.FinishTests.test_a_grant_that_ended_without_its_tun_closes_by_its_census_alone`; `test_windows_uac_decision.CancelledGrantDriverTests.test_a_known_tun_end_that_is_not_the_variants_own_closes_by_its_census_and_exits_one` | `closing` took a grant lease only after its exact off, but a cancelled grant (its prompt expired) or an unexpected final code has no TUN and no off, so the known end the driver promised raised `scoped-tun-closing-once` and parked. The earlier driver regression passed only because its fake `closing` accepted anything, and it gave a denial the `cancelled` outcome the real `finish` never returns. `finish` now records `knownEnd`, and `closing` takes any settled lease. The driver regression runs the real `closing` with a grant lease; the driver admits that grant only inside the test. Latent: grants are refused at admission. RED on `ffad8f0e`: `scoped-tun-closing-once`. |
| A denial passed with pending B no longer selected | `test_windows_tun_stages.FinishTests.test_a_denial_must_keep_pending_b_selected`, with `BeginTests.test_a_refusal_that_moved_a_or_left_anything_scoped_still_parks` | The denial check compared A's runtime, location, mode and config bytes, `restartRequired` and the configured VPN mode, but not the selection, so a product that reselected A on the denial with VPN mode still pending passed. Every known end now also requires B's selection from the lease's pending status. RED on the `ffad8f0e` stages: no failure. |
| A final synchronous refusal of the TUN request parked | `test_windows_tun_stages.BeginTests.test_a_final_refusal_of_the_request_from_this_controller_is_a_known_end`, `test_any_other_reply_to_the_request_leaves_its_outcome_open` and `test_a_refusal_that_moved_a_or_left_anything_scoped_still_parks` | `begin` marks the request before `runtime.result`, which fails the same way for a lost reply and for a final refusal. So `BUSY` at admission, or a job that ended before its reply was built (the product's `acceptedResponse` then returns its terminal), parked. On a failed check `begin` now reads the request's own public child: a final envelope from the row's own controller with an exit 1 or 130 code and that exit is a known end once status shows A intact and B selected and the census is clean; the flag is cleared and the driver closes the proxy. A transport code, a reply from no or another controller, another exit, any stderr or a reply that is not JSON keeps the outcome open and parks. RED on the `ffad8f0e` stages: `runtime-public-cli-exit-stderr` propagates. Native only: which codes the product returns synchronously. |
| A grant's sampler ran without a reviewed digest | `test_windows_uac_decision.CancelledGrantDriverTests.test_a_grant_runs_only_the_reviewed_sampler_beside_the_driver` | `traffic` runs `samplerPath` under the pinned interpreter, and only its presence among the held files was checked, while every other helper role carries a digest. The driver now requires a grant's sampler to be the bundle's `windows_tun_direct_sampler.py` beside itself, held at `SAMPLER_SHA`, before the runtime starts. Latent: no admitted row is a grant. RED on the `ffad8f0e` driver: no refusal, and the runtime starts. |
| A deny row without a decision row could pass on an expired prompt | `test_native_scenario_windows.ScopedTunAdmissionTests.test_a_deny_variant_without_a_decision_join_is_refused_whatever_its_refusal` | The deny-join gate keyed only on the row's `uac` decision, and `find-best-deny` has none, so only its refusal entry kept an expired prompt's `CANCELLED` from passing as its denial. A `-deny` name now counts as a deny row and is refused without a deny decision and its join. Latent while the refusal stays. RED on `ffad8f0e`: admitted. |

### Windows matrix observation and SSH row review (2026-11-09)

Found by review of the local commit `4bea309b` (the SSH import and routing row and the matrix observation helper), which never landed; nothing here was observed natively. The `4bea309b` bytes, the RED output on them and the GREEN output are under `.runtime/climatrix-review/` of the build clone. The docs had also said every Windows requirement has an unmapped scenario; `windows-installer-lifecycle` maps all eight, and `TableTests.test_no_update_row_can_prove_a_scenario_today` now checks that every update variant it names is refused at admission.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A harness failure after the task was classed a product failure | `NeverCountsTests.test_a_harness_failure_after_the_task_never_counts_or_fails_the_requirement` | Any failed receipt whose task finished was `failed`, so an evidence copy that failed after a passed task, a malformed task journal, a missed command-line read or a crashed worker became a failed record, which blocks every equivalence link of its requirement and source. `failed` is now only `task_exit_code` with owner and terminal exit code 1, which a case oracle failure ends with; the rest is `failed-after-task`, never counted and never recorded. RED on the `4bea309b` bytes: all four classed `failed`. |
| The SSH row alone proved `ssh-import-routing` | `TableTests.test_the_table_names_every_windows_scenario_and_only_built_rows`, `FailedAndUnknownTests.test_with_the_real_table_the_ssh_row_proves_no_scenario_alone` | The row's last event lists a relayed transfer and a stdin key import as `remainingProcedures`, and smoke step 11 also needs refreshes through a real relay. The scenario now maps to no row. RED: the table named the row, and a lone failed SSH row made a failed observation instead of a refusal. Trade-off: a failure of this row is not recordable through the matrix until the scenario's other rows exist; its own collection still reports it. |
| A missing owner, a host boot or an overflowed stream refused every observation | `FailedAndUnknownTests.test_a_missing_owner_a_host_boot_or_an_overflowed_stream_is_unknown_at_once` | The spec makes these UNKNOWN and records them at once, but the matrix refused `original_owner_missing`, `boot_changed` and `output_overflow` as `windows_matrix_row_unsettled`, so they could only be left out. They are `unknown` now; a missed read (`observer_unavailable`) stays unsettled (`test_an_unsettled_row_refuses_the_whole_observation`). The durable observe reads `terminal.json` before the owner, so an owner that exits between the two reads `original_owner_missing` once: the matrix reads journals only, and the docs say to call `scenario-status` for every row first. RED: `windows_matrix_row_unsettled:<id>` for all three. |
| A pass could leave out a failed or unknown run | `FailedAndUnknownTests.test_a_pass_needs_every_failed_or_unknown_run_of_its_package_recorded_first` | The observation read only the rows its caller named. A passed one now reads every journal of its counted rows on the same target package and refuses `windows_matrix_unrecorded_outcome:<id>` while a settled failed or unknown run is in no recorded observation of that requirement and source. Runs on another package, rows the requirement does not count, harness failures and unsettled runs do not hold it. Once those are recorded, the pass stands beside them as `conflicting` until a reviewer retracts one. Refusing every pass of the package instead would make one host reboot permanent. RED: the pass was observed with a failed and an unknown run left out. |
| An interrupted evidence write left part of a document under its digest name | `InputTests.test_an_interrupted_evidence_write_leaves_nothing_under_its_name` | The evidence file was created under its final name and written there, so a full disk (modelled as half the bytes, then `ENOSPC`) left a partial file, and every later observation of the same rows refused `windows_matrix_evidence_differs`. It is now published by the ledger's own `_exclusive_write`: a synced temporary file linked create-only. RED: `windows-native-cli-<sha12>.json` remained. |
| A ledger or evidence error ended the entry point with a traceback | `InputTests.test_the_entry_point_refuses_a_ledger_or_evidence_failure_finitely` | `main` caught only the module's own refusals, and the ledger reads and the evidence write ran outside them. A foreign file in the ledger or a failed write now exits 1 with `windows_matrix_ledger_unavailable` or `windows_matrix_evidence_unavailable`. RED: `OSError` (`ENOSPC`) escaped `main`. |
| The SSH case test's product wrote platform text that Windows turns into CRLF | `CaseTests.test_the_fake_product_writes_bytes_as_the_product_does_on_every_platform` | `stored_key` compares exact bytes, as the product writes them (`Files.writeString` of the trimmed key and one LF). The in-memory product used `write_text`, so on Windows the faithful product would fail `stored-key-differs`; Windows CI runs only included test IDs and would not have shown it. Every file of the in-memory product is now written as bytes. RED under modelled Windows text mode: `stored-key-differs`. |

### Round 2b integration, offline (2026-11-09)

Applying the document, scoped-TUN and CLI-matrix commits onto `a51ae1b1` (the
result was then rebased onto `3e19d794`) joined main's start-failure closing with
the TUN track's stricter driver inputs, and the CLI matrix's classifier with the
document row's principal probe. Nothing here ran natively. The failing logs and before-images are kept under
`.runtime/integ/evidence/tun-start-join/` and `.runtime/integ/evidence/principal-verdict/`
of the integration clone (`integrate-2b`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| A TUN start-failure test gave the joined driver TUN inputs it refuses | `test_windows_proxy_lifecycle.StartFailureTests.test_a_tun_row_whose_start_fails_closes_the_same_way_before_any_tun_stage` | Main's test gave the `restart-deny` driver only `schemaVersion` and `variant` as its TUN inputs. The TUN track's driver requires them to name the runtime's own install, context and product config, so `lifecycle_inputs` refused (`dedicated-tun-same-admission-references`) before `start_runtime`, and the test ended in that `ValueError` instead of the closing it checks. The job's real harness (`windows_scenario_proxy.tun_inputs`) always names the three. The test now builds them as the TUN track's own tests do; no production code changed. RED on the unadapted test with the joined driver: `Ran 6 tests`, `FAILED (errors=1)`. GREEN: `Ran 6 tests`, `OK`. |
| The matrix filed the document row's principal verdict as the harness's | `test_native_scenario_windows_matrix.PrincipalVerdictTests` (`test_a_probe_that_proved_no_denial_fails_its_own_scenario_at_once`, `test_the_row_s_other_scenarios_never_count_that_run`, `test_it_holds_a_later_pass_of_the_package_until_it_is_recorded`) | Only in the merged tree: `wrong-principal-owner-context-kind` maps to `windows-document-acceptance` alone, and the CLI matrix's classifier files every failure after a finished task other than the owner's exit 1 as `failed-after-task`, which never counts. A DOC run whose owner passed but whose LOCAL SERVICE probe proved no denial (`document_principal_not_denied`) therefore yielded no failed observation and held no later pass of its package. Such a run is now `failed-principal`: a failure of that scenario alone (`MATRIX_PRINCIPAL`), recorded at once, and a hold on a pass of `document-persistence-transfer` until it is recorded. The probe's other ends stay the harness's. RED on the integration commit `b6ca22e8`: `Ran 8 tests`, `FAILED (failures=3, errors=1)` (the error is the new table guard's missing `MATRIX_PRINCIPAL`). GREEN: `Ran 8 tests`, `OK`, and the module `Ran 33 tests`, `OK`. Offline only: no native DOC run has met the probe yet. |

### Windows Defender Firewall prompt at a proxy `on` (native, 2026-11-09)

On clone `9059be98` with the installed 2.2.16 MSI, the proxy row's public
`vpn-control-cli ... on` (operation `b3d71dca`, child 28, pid 6560, born 02:38:37.41Z;
events 87 and 88 of `.runtime/windows-parity-20261107/family/diag/evidence-b3d71dca/`) was
followed at 02:38:38.67Z by `C:\Windows\System32\PickerHost.Exe FirewallNotificationDialogServer -Embedding`
(pid 6752, console session 2, parent session-0 `svchost.exe` pid 320; `roles-summary.json` of
`.runtime/windows-parity-20261107/enroll-9059be98/roles-probe-3a0442dc-dca7-468c-b2d6-be20cebc57f2/`),
the Windows Defender Firewall prompt to allow network access, 9.3 s before the runtime
`sing-box.exe` started (02:38:47.97Z, event 93). The prompt stayed open and blocks that clone's
idle census. The unfixed sources of `3e19d794`, the RED and GREEN logs and their JUnit reports
are under `.runtime/` of the fix clone (`fix-loopback-ports`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| The app's free-port probes listened on every interface | `DesktopLoopbackListenerTest.everyListenerAndPortProbeOfTheAppBindsTheLoopbackOnly` (`:desktopApp:test`); control `DesktopLoopbackTest` | Ports were found with `ServerSocket(0)`, which binds the wildcard and listens: `DesktopProxyRuntimeManager.allocateListenPort` (twice on a proxy-only `on`, once on a VPN `on` without a verification port), `DesktopDirectProbeProxy.useProxy`, `DesktopProxyValidationRuntime.allocateListenPort` and the SSH bootstrap proxy of `DesktopSubscriptionDownloadClient`. Windows raises the prompt when a program without a rule listens beyond the loopback; sing-box itself listens on `127.0.0.1`, and the control endpoint already bound the loopback. All four now take `DesktopLoopback.freePort()`: `127.0.0.1`, with the same backlog (50), retry loop and exceptions; the `127.0.0.1` port check moved there unchanged (`CONFIG-012`). The test runs the real proxy-only `on`, direct probe, validation, SSH bootstrap and control endpoint in a child JVM whose `ServerSocket` factory records each bind's address and opens no OS socket. No sing-box resolves there, so no runtime starts, and the runtime's two inbound ports and the endpoint's port must come from recorded binds. RED on `3e19d794`: 1 test, 1 failure, five `0.0.0.0` binds (`DesktopProxyRuntimeManager.kt:365` twice, `DesktopDirectProbeProxy.kt:27`, `DesktopProxyValidationRuntime.kt:409`, `DesktopSubscriptionDownloadClient.kt:140`). GREEN on the fix: 1 test, no failure, every bind `127.0.0.1`. Native only: that a proxy `on` of a package built from the fix raises no firewall prompt, shown by the next proxy row on a fixed MSI and a clone without an open prompt. Not changed: Android's SSH bootstrap probe (`AndroidHomeSshBootstrapProxy`, `ServerSocket(0)`); Android has no such prompt. |

### OneDrive self-update on Windows fixtures (native, 2026-11-09)

The finding recorded under the idle census roles above, by user decision "disable updates".
Read-only probe `3a0442dc` on clone `9059be98` (`roles-summary.json` of
`.runtime/windows-parity-20261107/enroll-9059be98/roles-probe-3a0442dc-dca7-468c-b2d6-be20cebc57f2/`):
the fixture user's `OneDrive Standalone Update Task-<SID>` is `Ready` and its OneDrive is
`26.198.1011.0006`, restarted with `/updateInstalled /background`, while the Administrator's task,
present when secure reapplied the policy, is `Disabled` with OneDrive `25.087.0506.0001`. OneDrive
has no supported switch that stops its updates: the running sync app updates itself and registers
its update task again for that user after the policy last ran. The unfixed policy is the
beforeimage `agent_tools/tests/fixtures/windows_onedrive_update_policy/windows_vm_unattend.before.source`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The fixture user's unconfigured OneDrive updated itself and re-enabled its update task | `test_windows_update_policy.OneDriveSelfUpdateTests` | `UPDATE_POLICY` now sets `HKLM\SOFTWARE\Policies\Microsoft\OneDrive` `PreventNetworkTrafficPreUserSignIn=1` (Microsoft's policy: no network traffic, update checks included, and no automatic start until a user signs in to OneDrive; the fixture user never does) and disables `OneDrive*Standalone Update Task*` (per user, per machine, v2) instead of the per-user name only. Clones run the policy from `SetupComplete.cmd`, before the first logon, and secure reapplies it. RED on the beforeimage: 3 failures (two task names not disabled, no policy for the running app); GREEN 18 tests on Python 3.14 and 3.12. Native proof belongs to the next clone created from these sources: policy value set, the fixture user's update task `Disabled`, no `OneDrive.exe` running at idle, the image's build unchanged. Clones created before this change keep the old state. |

### First native gui-pending row: a GUI reopened after a crash got no window (2026-11-09)

`windows-proxy-lifecycle.gui-pending` (operation `90dd6d45`, clone `9059be98`, installed 2.2.16,
tools of `3e19d794`) ended exit 1 through its known-failure closing, not parked, with
`original-gui-child-handle-required`. Evidence:
`.runtime/windows-parity-20261107/family/diag/evidence-90dd6d45/`. The GUI sequence
passed natively up to its reopen: child 34 (launcher 9932, whose restart child JVM 5704 owned
the windows) attached (event 116), hid, showed twice, closed to the tray on WM_CLOSE and showed
again; the crash ended JVM 5704 and the launcher ended with `0xE0421001` (events 161 to 163).
The reopen's `start_gui` then read status (events 168 to 170) and started child 48, launcher
1528 (events 171 and 172), 4.7 to 8.2 s after the crash: the case's own reopen, not a restart
child or a GUI the product started. Event 173, its first window poll, shows 1528 with its
restart child JVM 9976 and no window yet. Before the next poll launcher 1528 had exited 0 with
exactly `UNAVAILABLE: could not attach graphical frontend.` on stdout and nothing on stderr
(`child-0048.*.raw`, terminal at event 206), so that poll's `gui_record` refused. The closing
then quit the serve, which exited 0. This is a product defect: a user who reopens the app
seconds after a GUI crash gets no window for up to 15 s. The before-images, RED trees and logs
are under `.runtime/` of the fix clone (`fix-gui-pending`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| An ATTACH after a GUI crash answered BUSY while the dead GUI's lease ran on | `DesktopFrontendReattachTest.a_new_frontend_attaches_once_the_crashed_frontends_captured_process_is_gone` (`:desktopApp:test`); controls `a_live_captured_frontend_keeps_its_lease`, `an_uncaptured_frontend_keeps_its_lease`, `the_same_registration_attaches_again` and `DesktopFrontendReattachObservationTest` (an UNKNOWN observation, an uncaptured lease until expiry, a GONE observation) | The owner captures an attached GUI's authenticated process identity (`captureProcessIdentity` after `controlInstallFrontend`), and `DesktopOwnerFrontendLifecycle.revokeIfCapturedProcessDead` releases a lease only when that exact generation is proven gone, but only `quitForControl` used it. An ATTACH from another registration answered `BUSY` (`DesktopControllerOwner.execute`, `ControlFrontendLease`) until the dead GUI's lease ran out, `LEASE_MILLIS` (15 s) after its last heartbeat, and `Main.kt` then printed that line and exited 0 with no window. Now the ATTACH reads the held registration under the owner monitor and, outside it, as `quitForControl` does, lets `revokeIfCapturedProcessDead` release that lease when the default observation proves the captured generation GONE; the ATTACH is then granted once. A live, UNKNOWN or uncaptured identity keeps its lease until expiry, the in-progress `UPDATES_INSTALL` BUSY still comes first, and an invalid ATTACH or one for another owner observes nothing. DESKTOP-001 now says so. RED on the owner of `b081beae`: 4 tests, 1 failure, `expected:<OK> but was:<BUSY>`; the three controls of that class pass there, and the observation class, which needs the fix's two seams, was set aside. GREEN: 7 tests, 0 failures. Product mutants that release any captured lease, or any held lease, each turn controls RED. Whole suites on the final tree: `:desktopApp:test` 1306 tests, 0 failures (111 skipped), and `:shared:core:desktopTest` 238 tests, 0 failures. Native only: a package built from the fix reopening after a real GUI crash on the guest. |
| An ended GUI launcher was refused without naming the owner's refusal | `test_windows_proxy_lifecycle`: `FrontendReattachTests.test_an_owner_that_still_refuses_is_named_and_never_started_again`, `GuiPendingRowTests.test_a_reopen_the_owner_refused_ends_the_row_one_with_everything_closed`; controls: the rest of `FrontendReattachTests` (the fake owner's release, a dead GUI it cannot prove gone, the reopen right after the crash, any other launcher end, a GUI the owner started), `GuiPendingRowTests.test_the_row_reopens_at_once_runs_its_pending_selection_and_closes_known`, `LauncherPairTests.test_gui_continuity_follows_the_jvm_each_relaunched_gui_runs_in` | `gui_continuity` keeps reopening right after it sees the crash terminal, as a user would. A GUI launcher that ends before its window is now collected where it ended (`lifecycle-gui-ended`): exit 0 with exactly the product's line and an empty stderr refuses as `gui-attach-refused-by-owner` and is never started again, and any other end keeps `original-gui-child-handle-required`. The world models the fixed owner and, behind a switch, the owner of 2.2.16; the lease, the heartbeat and the line are read from the Kotlin source, and the world also models the frontend lock, `gui show` and `hide`, the owner's own frontend start, a pending restart, `runtime-config.json` and a quit that closes the attached GUI, so the real driver runs the whole gui-pending row offline. RED on the `3e19d794` tool bytes, Python 3.14 and 3.12: 50 tests, 2 failures, each `original-gui-child-handle-required` where `gui-attach-refused-by-owner` is due. GREEN: 50 OK on both. Three loosenings of the name each turn a named test or a control RED. With the fixed owner the old tool's immediate reopen attaches too, and its row closes 0. The driver, `pending_selection` and `gui_record` are unchanged. Native only: a gui-pending row on a package built from the fix; until then the installed 2.2.16 ends the row `gui-attach-refused-by-owner`, and the rest of the row after the reopen stays unproven. |

### Windows deployment reservations never released (native, 2026-11-09)

`windows-vm-deploy-start` of clone `f69643fe` was refused before any effect:
`reservation_admission_refused`, "configured guest memory plus build headroom exceeds
physical host memory (65536MiB > 61674MiB)". The same refusal hit `a5dcd318` on
2026-11-08. The inventory `.rag_index/native-environments/reservations.json` held 11
rows, all `running` with 4096 MiB each, while only `be766f0c` and `9059be98` were alive.
`a218e890`, `66ad4aad`, `db6df990` and `4b28776f` had been stopped by
`windows-vm-deploy-stop` with `stopped-observed` and `positiveAbsence`. `34e354eb`,
`7bb1f0c0`, `7039b09d`, `60dc6c97` and `ffef40d7` died when the Arch host rebooted;
their later stops ended UNKNOWN with `instance_host_epoch` and are never replayed.
Admission adds every running claim to the live census: 11 × 4096 + 2 × 4096 + 4096 +
8192 = 65536 MiB. The two refusals, the reservation listing, the `a218e890` stop output
and the unfixed `windows_vm_deploy.py` are under
`.runtime/windows-parity-20261107/evidence/reservation-leak/` of the recovery checkout.
The fix leaves `windows_vm_deploy.py`, `native_environment.py`, `windows_vm_resources.py`
and `windows_vm_deploy_remote.py` byte for byte unchanged: `readiness_windows._source_pins()`
binds them, and the first sign-in of `9059be98` froze its packets at `70ed16cc`. The
unfixed tool is therefore `70ed16cc` itself. The RED and GREEN logs are under `.runtime/`
of the fix clone (`fix-reservation-release`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| No deploy operation released a stopped or rebooted-away clone's reservation | `test_windows_vm_deploy_release.ReservationReleaseTests` (`test_clean_stop_same_boot_RED_no_release_route_keeps_start_refused_GREEN_proof_a_admits`, `test_reboot_ended_epoch_RED_no_release_route_keeps_start_refused_GREEN_proof_b_admits`) and the controls of the same module | `_prepare_reservation` reserved pending and `_mark_running` marked running, but stop and status never released, and `release_environment` refuses a running row without fresh terminal evidence. The only reviewed release-after-stop path, `ResourceAdmission.release_stopped`, serves readiness admissions alone. The new closed action `windows-vm-deploy-release` (CLI and MCP, module `windows_vm_reservation_release`) releases the deployment's own row only on (a) a read-only status `stopped-observed` with `positiveAbsence` for the bound original actors on the reservation's own boot, with no original QEMU in a fresh census of that boot, or (b) a fresh census on another boot with no original QEMU, which never needs the UNKNOWN stop. Under the inventory lock with an unchanged digest it records its authorization, marks the job absent with a correlated receipt and releases through `release_environment`. The regression replays the native history on physical coordinator state with the real start, admission, status, stop and ledger; only the host is simulated (boot epoch, census, instance replies). The new clone is refused with the exact native text, the generic ledger release refuses the running row, and then one public CLI release, of `a218e890` by (a) or of `7bb1f0c0` by (b), lets the same start be admitted at 61440 MiB of 61674 MiB. RED on an isolated copy of `70ed16cc` holding only the new test module, on Python 3.14 and 3.12: `Ran 16 tests`, `FAILED (failures=2, errors=17)`. Both causal tests keep the start refused with the native text, and the 17 errors are `ModuleNotFoundError` for the absent release module. GREEN on the fix: `Ran 16 tests`, `OK` on both. Controls in the module: unknown, unreachable or running status, a live clone (`be766f0c` and `9059be98` keep their rows), the same boot without positive absence, a status about other actors, a foreign token on the row, another deployment's private file, a pending row, an inventory change during status or census, a held lock and an absent row all block and release nothing; a repeat returns the retained terminal; a lost reply reconciles by reading with `release_environment` called once; an interrupted release keeps the row and re-proves. Native only: the real census and status replies of the Arch host, the transport, and the coordinator's release of the nine clones followed by the `f69643fe` start. A VM of a deployment restarted outside the tool on a new boot is not identified, since no route restarts one. |

### First native document row: a refused harness fixture parked its clone (native, 2026-11-09)

`windows-document-acceptance` (operation `2df348bd`, direct, clone `be766f0c`, installed 2.2.17 of
`70ed16cc`) ended `job_exit_unknown:owner-parked` after 304 s and blocked its clone. Its owner parked
with `scenario-failure-with-retained-child` and `errorClass` `PermissionError`, nothing more, while the
serve (child 2) ran. Evidence: `.runtime/windows-parity-20261107/family/diag/evidence-2df348bd/`
(2,631 events, the last `event-002630-document-large-import-readback`, and `owner-parked.json`) and
the bundle that ran, `.runtime/windows-parity-20261107/family/bundle-2df348bd-6878-41c8-8061-60c87f7e301e/`.
A read-only listing of the row's folder afterwards showed `document-race-parent` and
`document-export-client-parent`, no `document-race-parent-moved` and no `activation.port` in the proxy
folder; Defender real-time protection was on. So the parent race's own fixture failed after both
folders were made and before its descriptor was written, before the product's export child started.
In that window of the preserved race two calls can raise `PermissionError`: the probe's first rename,
`parent.rename(renamed)` on line 145 (a sharing violation, 32, or access denied, 5), and the relay's
loopback listener, lines 69 to 71 through line 149 (`WSAEACCES`, 10013, maps to errno 13). The folders
cannot tell them apart, because a probe that renamed away and back leaves the same names; the second
rename would have left `-moved`. The probe is the likelier; what held the folder, if anything, is
unproven. The race, CLI cases, Windows module, client and harness that ran are the `f76e02fc` bytes;
the owner that ran is `70ed16cc`'s, which differs from `f76e02fc`'s only in the dedicated-driver
literal. Before-images and provenance are in `fixtures/windows_document_native_failures/`, the
regressions in `test_windows_document_native_failures`. RED is that module on the `f76e02fc`
production bytes (`.runtime/red-f76e02fc` of the fix clone, `build-docs-harness`): 12 tests,
12 failures and 4 errors with subtests, on Python 3.14 and 3.12. GREEN is the same module on the fix:
12 tests, OK on both. Logs and 14 mutants of the fix, each failing its named tests, are under
`.runtime/logs/` of the fix clone.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The owner's records named only the error class | `FailureDetailTests` (`test_a_park_names_the_failing_line_and_its_win32_code`, `test_a_known_failure_records_its_frames_and_the_refused_call`, `test_a_raw_capture_park_names_the_streams_own_error`, `test_the_record_is_finite_private_and_never_raises`) | `owner-parked.json` and the `known-failure-closing`, `owner-terminal` and `child-no-process` events now carry `failure`: the class, an OS error's `winerror` and `errno`, and at most 12 innermost frames outside the standard library as `<file basename>:<line>` (on the guest, the agent_tools modules the owner runs and the held harness), with its cause, explicit or the error it was raised while handling, recorded the same way one level deep. No message, argument, path or local value. A raw-capture park names the failed stream's own error instead of a dict. Building the record never raises; one it cannot build names only the class. RED on the `f76e02fc` owner: over the preserved race the park has no `failure`, nor has a known failure's closing over the fixed race. GREEN: `PermissionError`, `winerror` 32, `errno` 13, innermost frame `export-race-fixture.before.source:145`, the native line, and no standard-library frame or message text. |
| A harness fixture step the OS refused parked the clone as an unknown product state | `HarnessFixtureFailureTests` (`test_a_refused_rename_probe_closes_as_the_named_harness_failure`, `test_a_refused_relay_listener_is_closed_and_known`, `test_a_refused_descriptor_closes_the_listening_relay_first`, `test_a_refused_persistence_fixture_releases_its_holds_and_closes_known`, `test_a_refused_export_parent_hold_is_known`, `test_fixture_refused_names_only_os_refusals`) and the controls in `test_what_is_not_a_harness_os_refusal_keeps_its_old_end` | An `OSError`, or a refused native open, of the race's own fixture before its export child starts is the known failure `document-race-fixture-refused:<step>:<code>`, the code being the Win32 error, else `errno-<n>`. The steps: `absences`, `mkdir-parent`, `mkdir-proxy`, `probe-open`, `rename-away`, `rename-back`, `probe-reopen`, `relay-listen`, `descriptor-create`, `descriptor-hold`. The CLI cases' `close_known` counts it, so the owner quits its serve once and ends 1. A listening relay has accepted nothing of the product yet, so it and an open descriptor handle are closed before any failure of those steps propagates, a `document-` code such as `document-private-create-new` included, which then closes known as well; a relay that cannot be closed parks (`document-race-fixture-closing-unknown`). A listener that fails to open closes itself and reads stopped. The scan of the other document modules found the same window twice in `windows_document_native.py`: `persistence_fault` held `workspace.json` and created and held the empty recovery leaf before its request, and `private_export_no_overwrite` opened its observer of the operation root before the first export. They are now `document-persistence-fixture-refused:<step>:<code>` (`primary-hold`, `recovery-create`, `recovery-hold`), after releasing the holds so the product can persist at the quit, and `document-export-fixture-refused:parent-hold:<code>`. The CLI and cold cases open no fixture of their own; the responsive cases have no known-failure closing and still park by design. A failure once the product's child started, a refusal that is not the OS's (the owner's native identity check) and any error not named by the module's own codes still park. RED on the `f76e02fc` bytes: each parks, the race with the native signature (`scenario-failure-with-retained-child`, `PermissionError`), the relay still listening, the primary still held. GREEN: exit 1 with the named code, one quit and every fixture handle closed. |
| The positive rename probe had one attempt | `test_a_folder_held_only_briefly_is_renamed_on_a_later_attempt_and_every_attempt_is_recorded`, `test_a_refused_rename_probe_closes_as_the_named_harness_failure`, `test_what_is_not_a_harness_os_refusal_keeps_its_old_end` | Decision: the probe exists to prove that the ordinary context can rename its own fixture before the product opens it. A short-lived handle of another process on the just-created folder, a real-time scan for one, refuses an attempt without disproving that. The probe now retries access denied (5) and sharing violations (32) only, at most six attempts in under 4 s (0.1, 0.25, 0.5, 1 and 2 s apart), and journals every attempt in `document-race-rename-probe` (step, attempt, elapsed ms, class, `winerror`, `errno`), on success too. Any other code is not retried. The product's race step, the rename while the product holds the folder, is unchanged and stays one attempt. RED on the `f76e02fc` race: the first refusal parks. GREEN: after a 32 and a 5 the third attempt renames, the folder is restored, and the race starts the product's export child, whose early exit still parks (`document-public-export-race-unknown`) with the relay and descriptor kept. Native only: whether the folder was held, by what, and for how long; the next run's probe event shows it. |

### Windows owner-lifecycle rows, offline build (2026-11-09)

Before any VM contact, on `f76e02fc`. `MATRIX_SCENARIOS` mapped `close-detach-traffic`,
`scheduled-without-gui` (`windows-owner-lifecycle`) and `gui-attach-detach`
(`windows-native-cli`) to no row: design.md wants `PRX(no-tray-close)` and
`PRX(scheduled-refresh)`, which the dedicated driver refused. These are review gaps,
not native failures. The RED tree is `git archive f76e02fc` with only the new and
updated test modules and the new case module (which has no unfixed version) copied
in; `red_green.py` and its logs for Python 3.14 and 3.12 are under
`.runtime/owner-rows/` of the build clone (`build-owner-rows`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| No row could prove scheduled work in the owner with no GUI | `test_windows_scheduled_refresh`: `ScheduledRowTests.test_the_row_observes_one_scheduled_refresh_with_no_gui_and_closes_known` and `test_a_run_first_seen_final_is_bracketed_by_the_listing_before_it`, `AdmissionTests`; `test_windows_proxy_lifecycle.HarnessTests.test_every_variant_the_driver_accepts_has_an_admitted_harness`; `test_native_scenario_windows` `TableTests` and `PackageAdmissionTests.test_every_new_row_admits_before_any_journal`; `test_native_scenario_windows_matrix.TableTests.test_the_table_names_every_windows_scenario_and_only_built_rows`; `test_native_scenario_execution.NativeScenarioExecutionTest.test_windows_names_are_closed`; controls: `ScheduledControlTests` (12) | New row `windows-proxy-lifecycle.scheduled-refresh`, mapped to `scheduled-without-gui` alone. Its case module `windows_lifecycle_scheduled_cases.py` is a new pinned driver role (`SCHEDULED_SHA`), so `windows_lifecycle_cases.py`, the runtime stages and every other row's pins are unchanged. After `start_runtime` it turns proxy A off, adds the fixture's own subscription, refreshes it once, runs its one location, starts the same traffic worker (1,800 samples, 0.25 s), proves no frontend (`gui hide` NOT_FOUND, `DesktopGuiVisibilityControl`) and no installed GUI process, arms a five-minute custom policy and reads `operations list` until the owner's own `subscriptions.refresh` with a `scheduled-refresh:` request ID (`DesktopHeadlessSession`) is final; then the oracles of the tool doc: terminal OK, the same runtime, location and actors (DESKTOP-005), still no GUI, the subscription refreshed, every product fetch (`VPNControlDesktop/1.0`) inside the run's bracket, and samples before, during and after it. The world's product models the scheduler, the ledger, the fetches and the revision-guard rule read from `DesktopControlSupport.kt`. Each control makes the product answer wrong once (no run, a failed run, a restart, a stop, a pending change, no fetch, no manual fetch, another controller's run, dropped traffic, an attached frontend, a running GUI) and the row ends 1 with everything closed and the policy off; a run still open at its deadline parks. RED on `f76e02fc`, Python 3.14 and 3.12 alike: 36 tests, 6 failures and 20 errors: 15 are the driver's `dedicated-finite-proxy-variants-only` (the row in both of its timings, its 12 controls and the guard check), one the admission's `windows_scenario_not_allowlisted`, and the rest the closed name lists, the missing `SCHEDULED_*` driver roles and `scheduled-without-gui` still unmapped; the two `NoTrayCloseDecisionTests` pass on both trees. GREEN: 36 OK on both. |

Decision, not a fix: `close-detach-traffic` and `gui-attach-detach` stay mapped to no
row. A GUI window's close detaches only without a tray (`Main.kt` `onCloseRequest`
calls `detachFrontend` when `canHideToTray` is false), and on Windows the tray is
available as soon as AWT takes the icon: `DesktopTray.kt` `AwtTrayHandle.installTrayIcon`
calls `markAvailable()` on every platform but Linux without observing a notification
area. No setting (`ControlSettingsLogic.writableKeys`), GUI flag (`--autostart`,
`--tray`, `--minimized` only start hidden) or command (`gui show`, `gui hide`) turns
the tray off, and every other GUI exit quits or hands off its owner. So no public path
produces `no-tray-close`, and `gui-pending`'s crash is the only detach a Windows row
can make; DESKTOP-001 names a detach apart from a crash. `NoTrayCloseDecisionTests` (2)
read those facts from the product source and turn RED if any changes. The older
`windows_no_tray_desktop.py` cannot place a GUI on its private desktop either: the
Owner's `owned_desktop` seam passes only a `handle_list` startup attribute, and
Python's `subprocess` has no `lpDesktop`, so the child starts on the parent's desktop.
Whether AWT on a desktop without `Shell_TrayWnd` still adds its icon, which would hide
a closed window into no tray (DESKTOP-002), is unproven: only a native run with such a
child could show it.

Not changed here: `windows_lifecycle_runtime_stages.scheduled_setup_and_observe`, never
run and called by no row, sends `--if-revision` with `subscriptions refresh`, which
`DesktopCli` answers UNSUPPORTED (`SUBSCRIPTIONS_REFRESH` is not in
`revisionGuardOperations`), and observes through `windows_lifecycle_cases.scheduled_refresh`
and a curl collector. The new row replaces both; removing them would move the
runtime-stage and lifecycle-case pins of the proxy, document, reboot and update rows.
`ScheduledRowTests.test_no_write_this_row_makes_carries_a_guard_the_product_refuses`
keeps the new row from repeating it.

### Windows public-update deny and grant collectors, offline (2026-11-09)

Built offline in the scratch clone `build-update-grant` on `70ed16cc`; nothing here has run
natively. The unfixed sources are the clone's `.runtime/update-grant/before/`. RED ran in a
worktree of `70ed16cc` (`.runtime/red-base`) with only the new and changed tests copied in, one
unittest process per failure type, on Python 3.14 and 3.12 with identical counts (subtests
included). The logs are `.runtime/update-grant/logs/{red,green}{314,312}-<type>.log`. This
resolves the refusal and the unreadable disposition that the review of the first update build
recorded above. It also replaces `windows_scenario_update_grant_unproven` with what each
still-refused grant lacks. The regressions those rows name were rewritten as the ones below.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The collector chain refused the request form every native publish produces | `test_windows_update_grant_collectors.RequestFormTests`; `test_windows_scenario_host_job.UpdateFamilyTests.test_the_collector_takes_its_request_in_the_form_the_publisher_writes`, `test_a_request_in_any_other_form_stops_the_row_before_its_task` | `collector_contract.file_policy`, the SYSTEM bootstrap and the release program demanded `O:SYD:P(...)`, while a file the publisher creates and protects with `SetAccessControl` reads back `O:SYD:PAI(...)`. The readers now take exactly that form: SYSTEM owner, protected DACL, the three explicit ACEs, nothing inherited. `O:SYD:P` is refused. The release program checks the release it publishes against the same form, and the job checks the owner's pin before any task. The writer is unchanged. `test_windows_system_collector`'s current controls body builds its request pins in that form too. Its whole-source oracle rebinds only the drifted pins of current sources before it runs the authenticated before source, as `DedicatedCleanupCausalControls` does; before-images keep their exact pins. RED (5 tests): failures=4, errors=1, among them `collector-machine-writer-file-policy` on the native form and a deny row ending at publish. GREEN: OK. |
| SYSTEM could not read the product's owner-only not-started disposition | `test_windows_update_grant_collectors.BackupReaderTests`, `PublisherJournalTests`; `UpdateFamilyTests.test_the_owner_only_disposition_is_read_through_the_backup_privilege_alone`, `test_a_publisher_without_the_backup_reader_leaves_terminal_actors_unknown`, `test_a_backup_read_that_kept_the_privilege_or_changed_the_process_token_is_never_used`, `test_a_deny_row_serves_both_collector_stages_inside_the_run_and_releases_the_hold` | The product writes `.install-not-started-*.json` as `O:<owner>G:<owner>D:P(A;;FA;;;<owner>)` by design, and that ACL is left alone. The publisher's `Read-BackupPin` (`VpnScenarioObserver.BackupOpen`) and `native_collector.backup_open` enable `SeBackupPrivilege` on their own thread's impersonation token for one read-only backup-semantics open, disable it and revert before reading. Each open is journaled; a journal with the privilege left on, a failed revert or a changed process token is never used. The Win32 here is a declared model. `WindowsReaderTests` runs both readers against Windows itself, only on Windows, and has not run yet. RED (11 tests): failures=13, errors=8. The `70ed16cc` collector's plain open is refused (`[Errno 5]`), and the job-level tests stop earlier, at the request form. GREEN: OK. |
| No stage discovered a grant's installer actors | `test_windows_update_grant_collectors.CensusTests`, `OwnerProcessTests`, `InstallActorTests`, `ReturnedActorTests`, `InstallHelperTests`; `UpdateFamilyTests.test_a_grant_row_discovers_its_installer_actors_and_serves_every_stage`, `test_authorization_takes_only_the_jobs_own_live_coordinator_and_worker`, `test_before_install_finds_the_controller_the_helper_will_name`, `test_later_stages_take_only_the_authorized_job_and_the_cases_own_returned_owner`, `test_the_real_collector_takes_every_request_a_grant_builds` | `collector-observe` now takes a SYSTEM census of one installed image and reads the job's own product records. `before-install` finds the controller the helper names: the serve, or its one relaunched child. `authorization` takes exactly one live elevated coordinator under the approving administrator's SID and one live unelevated worker under the ordinary SID, both running the helper the installed `native-helpers.json` declares, plus `worker-ready.json`. `terminal-actors` asks for the same two beside `status.json`, and `returned-cleanup` for the owner the case recorded. Parents are recorded in `update.installer`, never required. RED (15 tests): failures=33, errors=37. The discovery functions are absent, and every grant need ends `collector_stage_unserved:before-install`. GREEN: OK. |
| Rows whose every stage is tooled stayed refused, and the refused ones did not say what they lack | `test_native_scenario_windows.UpdateAdmissionTests.test_the_deny_row_and_the_tooled_grant_rows_are_admitted_before_any_journal`, `UpdateTableTests.test_only_rows_with_a_producer_for_their_evidence_are_admitted`, `UpdateTableTests.test_the_rows_agree_with_the_dedicated_driver_and_the_decision_table`, `UpdateObservationTests`, `UpdateCollectionTests`; `test_native_scenario_windows_matrix.TableTests.test_no_update_row_can_prove_a_scenario_today` | `uac-denied`, `success-off`, `wait-client-loss` and `installer-wait-client-loss` are admitted. The others keep exact refusals: `install-cancelled` `windows_scenario_update_cancel_actors_unobserved`, `participating-copy-lock` `windows_scenario_update_copy_lock_fixture_unavailable`, `success-reconnect` `windows_scenario_update_reconnect_fixture_unavailable` and `different-admin` `windows_scenario_update_second_administrator_unavailable`. The fault rows are unchanged. An admitted update row still claims no installed-package evidence, so the matrix stays unproven. RED (7 tests): failures=10, errors=6, refused with `windows_scenario_update_collector_unproven` and `windows_scenario_update_grant_unproven`. GREEN: OK. |

### Hosted Fast Checks races of `529cc610` (run 42656925414, offline, 2026-11-13)

Agent Tools Shard 5 (Linux, CPython 3.12, one serial worker) failed two cases that pass alone.
Neither is a product defect, and neither case nor its source changed in the three commits
before `529cc610`; those add test modules, which moves the shard partition. Fixed offline in
the scratch clone `fix-ci-flakes`; nothing ran on a VM. The unfixed test modules are
`agent_tools/tests/fixtures/hosted_environment_races/*.before.source`, and the provenance
beside them holds the hosted traces, the local reproductions and what stays inferred. RED ran
in the clone's `.runtime/red-base` (`529cc610` `agent_tools` plus only the new regression and
its fixtures), GREEN in the clone, on Python 3.14 and 3.12 with identical counts. The logs are
the clone's `.runtime/flaky-logs/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A collection or a stall inside the high-descriptor case hides the unfixed readiness failure | `test_hosted_environment_races.HighDescriptorCaseTests` | `Fixed546RetirementTests.test_whole_high_fd_reader_writer_red_and_scalable_outer_inner_green` failed `False is not true` at its inner capture, here and on `251184fe`. The unfixed owner records `ValueError` only if its first step runs inside the .08 s budget and `select()` gets a descriptor above its limit. Earlier serial cases leave custody owners in mock call records, 30 or 40 descriptors per `test_ssh_gateway_tmux_reconciliation_status` case. On CPython 3.12 `inspect.getsource` parses the whole beforeimage between the two captures, so the case's first collection runs exactly there: 10 of 10 runs, against 0 of 10 on 3.14. Four returned numbers put the inner child's pipes below the limit. A stall of .08 s before the first step fails the same line. The case now opens `descriptor_window` before it fills the table, asserts that the table stays full, and counts the unfixed owner's clock reads instead of wall time. Which trigger the hosted runner met is inferred, not recorded; the window line names pending descriptors on the next run. RED (4 tests): failures=3. GREEN: OK. |
| The low-disk case compares two samples of a live filesystem | `test_hosted_environment_races.LowDiskCaseTests` | `SourceInventoryTest.test_actual_destination_and_low_disk_refuse_without_hash` failed `ValueError not raised` after 2 ms. It sampled the available bytes and asked the observer to refuse one byte more, so any gain between the two samples admits the request. Here 400 runs of the unfixed case fail 3 to 17 times, with or without a thread deleting files beside it; the fixed case fails 0 of 1600. The observer's own sample now refuses a minimum above the filesystem's capacity, and one actual sample handed to the observer refuses a missing byte and admits its own bytes. The observer is unchanged. Which actor freed space on the hosted runner is not known. |
| The preparation core's disk-budget case compares two samples in the same way | `test_hosted_environment_races.LowDiskCaseTests.test_unfixed_budget_peer_misses_its_refusal_when_the_filesystem_gains_space_and_the_current_case_passes` | Not a hosted failure: found by looping the peer of the row above. `QemuPreparationTest.test_source_drift_and_disk_budget_refuse_before_any_namespace` reserved every available byte it had sampled, so a gain of the 198144-byte source between the samples passes the budget gate and the core stops later with `source-lock-birth`. Here 150 runs of the unfixed case fail 2 to 5 times beside a thread deleting files and 0 or 1 time without it; the fixed case fails 0 of 600. It takes the same two refusals as the row above, and the core is unchanged. RED with this row (5 tests): failures=4. GREEN: OK. |
| The free-space regression compares two samples of the live filesystem itself | `test_hosted_environment_race_neighbours.NeighbourCaseTests` | Not a hosted failure: found by reviewing `68d59e2a`. `test_hosted_environment_races.LowDiskCaseTests` proved its real gain with two `statvfs` samples around each deleted megabyte. A neighbour that took the space back in between failed the current-case arm, let the unfixed case pass and failed that arm, or skipped the unfixed arm. Here 400 runs of the low-disk regression at `68d59e2a` fail 2 times with nothing injected (`False is not true : [1101824, 1040384, -4349952]` and `(1, 1, 0, 2) != (1, 0, 0, 2)`), and 300 runs beside a thread writing 512 KiB files fail 1 time and skip 1 time. An attempt whose own samples show no gain, or whose gain the unfixed case did not meet, is now repeated, at most four times, and named on stderr; the current case must still pass in every attempt. The fixed regression fails 0 of 600 runs beside that thread, with 8 attempts repeated, and 0 of 400 without it. The new cases write one real 4 MiB neighbour file at one chosen moment and compare no samples themselves; a fourth puts the unfixed case in place of the current one and requires the regression to fail still. RED ran in a worktree of `68d59e2a` plus only the new module, GREEN in the clone, on Python 3.12 and 3.14; the logs are the clone's `.runtime/review/`. RED (4 tests): failures=3. GREEN: OK. |

### Second native document row: the rename probe was refused on every attempt (native, 2026-11-09)

`windows-document-acceptance` (direct run `83484649`, clone `ea86866f`, package 2.2.17 discovery
build) ran the fix of the section above and no longer parked. Its job ended `task_exit_code` with
owner exit 1 after 393 s. `document-race-rename-probe` recorded six attempts over 3.9 s at
`rename-away`, each `PermissionError`, errno 13, `winerror` 32. The row closed as
`document-race-fixture-refused:rename-away:32` with frames `windows_document_export_race.py:192` and
`:154`, and the serve was quit. Evidence:
`.runtime/windows-parity-20261107/family/diag/evidence-83484649/`, events 2631 to 2644; the bundle
that ran, `family/bundle-83484649-990b-44ef-a66f-cf77392eef10/`, holds the `529cc610` race, Windows
module and owner. The first run (`2df348bd`, another clone) stopped at the same rename, so the refusal
is deterministic, and it was the rename, not the relay listener the section above left open.

The cause is read from the product source and not yet shown on a guest.
`DesktopControlTransferSpool.create` spools every transfer under `java.io.tmpdir`, which the document
rows set to `<operation root>\document-temp`, and keeps a `DesktopWindowsTransferPins` until the
transfer is erased: one handle on every ancestor of that folder, the operation root among them, opened
as `CreateFile(0x00120081, share 1, OPEN_EXISTING, 0x02200000)`. `FILE_LIST_DIRECTORY` makes the handle
take part in share checks, and it shares read only. The row begins one transfer for its 301 s idle
expiry before its exports and races and retains it. A rename by path (`os.rename`, `MoveFileExW`) has
the I/O manager open the folder of the new name for write access, sharing read and write; the pin does
not share write, so that open ends in a sharing violation. The probe renamed `document-race-parent`,
a direct child of the operation root. The product renames by leaf for this reason
(`JnaWindowsInstallNative.publishExportNoReplace`: "without reopening a directory for write access,
which would conflict with our strict ancestry pins"). No harness handle takes part: its directory
pins and its closed probe hold attributes and `READ_CONTROL` only (`0x20080`). So, by this reading,
the holder is the product's own serve, neither a scanner nor the harness, and no retry could have
helped.

Before-images (the bytes that ran) and provenance: `fixtures/windows_document_fixture_holders/`. The
regressions are in `test_windows_document_fixture_holders`, whose world is that reading as a model:
directory opens judged as `IoCheckShareAccess` judges them. RED is that module and the updated
`test_windows_document_native_failures` on the `529cc610` production bytes
(`.runtime/red-529cc610` of the fix clone, `builders/build-docs-holders`): 18 tests with 12 failures
and 7 errors (subtests counted), and 12 tests with 2 failures, on Python 3.14 and 3.12. GREEN is the
same two modules on the fix: 18 and 12 tests, OK on both. 30 mutants of the fix each fail their named
tests. The logs are under `.runtime/logs/` of the fix clone.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The race's fixture lay where the serve's transfer pins refuse every rename by path | `NestedStageTests.test_the_probe_passes_in_its_stage_while_the_serve_pins_the_operation_root`, `test_the_stage_keeps_the_fixture_out_of_every_folder_the_serve_pins` | The destination parent and its renamed name were direct children of the operation root, so the positive probe could never pass while a transfer lived, and a refusal in the race itself would not have been the public writer's own. Each race now has a stage folder, `<operation root>\document-race-<mode>`, holding `parent` and `moved`; the serve pins neither the stage nor what is in it. The race step is unchanged and stays one attempt: there only the public writer's own pins can refuse it. RED on the bytes that ran, with the retained transfer modelled: six refusals at 0, 100, 350, 850, 1850 and 3850 ms and `document-race-fixture-refused:rename-away:32`, the native record; the same bytes pass when no transfer lives. GREEN: both probes pass at their first attempt, the parent race is refused by the writer's pin (32), the destination race ends `PERSISTENCE_FAILED`, and the owner exits 0. Native only: that the installed product accepts a destination under a stage of the harness's own, and that its writer pins it. |
| A fixture step refused as held named its code but not its holders | `RefusalEvidenceTests.test_a_refused_rename_names_its_holders_at_the_first_refusal_and_at_the_last`, `test_a_holder_that_was_only_passing_is_named_and_the_probe_goes_on`, `test_every_fixture_refused_as_held_gets_its_census_and_no_other_refusal_does`; `HolderNativeTests`, `CensusRecordTests`, `HeldModeTests`, `PinModeTests` | Every `document-<fixture>-fixture-refused` step that has a path and was refused with 5 or 32 journals `document-fixture-holder-census` before the fixture releases anything; the rename probe journals one at its first refusal too, before it waits, so a holder that is only passing by is still there. For the refused path and its folder it records the PIDs that have it open (`NtQueryInformationFile` class 47 on a handle that shares everything), each with its image leaf name, parent PID and role: `worker`, `task-owner`, `serve`, `work-fixture`, `cli-child`, `<role>-child` for a live known child's own child (the launcher's JVM), else `other`. A known PID counts only with its recorded birth. The image comes from `QueryFullProcessImageNameW` where the ordinary token may open the process, and from `NtQuerySystemInformation` class 88 where it may not, which is the case that matters for a scanner. It also lists the harness's own open handles (`document_retained_handles` and the owner's directory pins) with path, access and share mode; `Held` and the owner's `Pin` now keep the modes they were opened with. No command line is read and no process list is walked. The record is bounded (64 holders and 32 handles per list, with counts) and never raises: what fails inside is named in `censusError`. A refusal with any other code, or without a path (the relay listener), gets none. RED on `529cc610`: no census anywhere. Native only: every native read (class 47 on a folder, class 88, what an ordinary token may open). |
| A refused rename did not show where a rename by path works | `RefusalEvidenceTests.test_the_differential_tells_the_folder_of_the_new_name_from_the_probes_handle_and_the_place`, `test_a_differential_never_removes_a_folder_it_did_not_make`, `test_the_differential_never_uses_a_temp_folder_inside_the_operation_root`; `NestedStageTests.test_the_root_control_records_the_refusal_and_who_holds_the_operation_root` | A refused rename probe journals `document-fixture-rename-differential`: beside the refused folder, in the operation root and in a folder of its own in the worker's temp folder, one fresh folder that no handle opened and one opened, inspected and closed as the probe does are each renamed away and back, every step recorded and every folder removed by its exact name; a name that exists is left alone, and a temp folder inside the operation root is not used. It tells the probe's own handle, the folder of the new name and the place apart. A passed probe is followed by `document-fixture-rename-control`, never a gate: one fresh direct child of the operation root renamed by path, with the census of the root if that is refused as held. It is how the next native run shows the cause: the control refused with 32 while the probe passed one folder down, and the serve's JVM (`serve-child`) among the root's holders. RED on `529cc610`: neither is journaled. |

Finding for the product, not changed here: with the default `java.io.tmpdir`, the same pins hold
`%TEMP%` and each of its ancestors up to the volume root with read sharing only for as long as any
transfer lives. By the source that is until its discard, or until its 300 s idle expiry is pruned,
for up to 32 transfers. Meanwhile a rename or hard link by path into any of those folders, by any
program, would end in a sharing violation. This is read from the source, not observed; the control
above would be its first native witness. Whether that is acceptable is the product's decision.

No retry policy changes. The probe's bounded retry stays, although neither native run showed a
holder that left. Evidence that would justify changing it: a first-refusal census that names a
process that is neither the harness's nor the product's, a later attempt of the same probe that
succeeds with nothing changed, and a differential whose fresh folders rename in the same place.

### Third native document row: the work fixture never became ready (native, 2026-11-13)

`windows-document-responsive` (direct run `b9aa4616`, fresh clone `07831787`, package 2.2.17
discovery build of `f31ab987`) was the row's first native run and ended UNKNOWN,
`job_exit_unknown:owner-parked`. The worker ran `--help` and `--version`, published
`document-work-input.json` (908 bytes) and started child 2, the gated HTTPS work fixture (pid 6416),
13.3 s after its own start. `read_ready` parked 30 s later with
`runtime-fixture-readiness-unknown-no-replay`. `owner-parked.json` has `errorClass` and `failure`
null and child 2 without EOF. The evidence zip was made about 37 s after the fixture's start, and
`child-0002.stdout.raw` and `child-0002.stderr.raw` are empty in it. Evidence:
`.runtime/windows-parity-20261107/family/diag/evidence-b9aa4616/` (10 events); the bundle that ran,
`family/bundle-b9aa4616-fc57-4aaa-bbf7-f8864a32f44a/`, holds the `529cc610` fixture and cases.

The cause is not identified. The unfixed fixture wrapped its whole start in
`except BaseException` and slept forever without a word, so a start that failed and one that stalled
leave the same record; the evidence zip lists the operation root only, so whether
`fixture\ready.json.publishing` existed is not recorded. What reading rules out:

- The ready file is written and read at one path, `<operation root>\fixture\ready.json`, through
  `ready.json.publishing` and a rename inside that folder.
- The fixture blocks on nothing: its stdin is NUL and never read, and its input is a regular file
  read once.
- Share modes. The owner holds the input and every source and TLS file for reading with read
  sharing (`0x80020000`, share 1). The fixture opens them through the CRT, for reading while
  sharing read and write, which that admits; the input and both producer sources were read that way
  before the swallowed part, where a refusal would have ended the child with a traceback. The owner
  holds the fixture folder for attributes only (`0x20080`), which takes no part in share checks, and
  no serve exists yet, so no product pin does either. This is not the rename probe's class.
- Slow first-run work. The key and certificate are made by the job on the host. The proxy rows'
  fixture runs the same unchanged `start()` (TLS context, two loopback listeners) and was ready 1.2
  to 2.0 s after its start on three native runs, one of them the first run of a cold clone
  (`6a0a73b8`, `90dd6d45`, `b3d71dca`). The 30 s was a literal, never measured.

What is this fixture's own between the listeners and readiness is the certificate's re-read
(`read_exact`, with its link-count and before-and-after checks) and the ready file's creation and
rename. If one of them had raised, the unchanged `start()` would have closed its HTTPS socket under
the serving thread, which on Windows ends that thread with a `WinError 10038` traceback on stderr,
and stderr was empty. That is a reading of CPython and Winsock, not an observation. It speaks for a
stall, or for a failure before the listeners in code the proxy rows share, and shows neither. The
next native run names the step: the fixture now says each one before entering it.

Before-images (the bytes that ran) and provenance: `fixtures/windows_document_work_fixture/`. The
regressions are in `test_windows_document_work_fixture`: the fixture's `main` over a declared peer
of its producer sources, and the cases over the real `Child`, real pipes and the runtime stages' real
`read_ready`. RED is that module and the updated `test_windows_document_responsive` on the
`529cc610` production bytes (`.runtime/red-529cc610` of the fix clone, `builders/build-docs-holders`):
28 tests with 7 failures and 25 errors (subtests counted), and 12 tests with 1 error, on Python
3.14 and 3.12. GREEN is the same two modules on the fix: 28 and 12 tests, OK on both. 40 mutants of
the fix each fail their named tests. The logs are under `.runtime/logs/` of the fix clone.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The work fixture kept a failed start to itself and slept | `FixtureStartTests.test_a_failure_while_the_listeners_are_made_is_said_and_ends_the_fixture`, `test_a_failure_of_the_publication_stops_the_listeners_in_order_and_says_its_step`, `test_a_refused_input_is_said_too`, `test_a_start_names_every_step_in_order_before_its_ready_line`, `test_a_failure_after_readiness_stays_and_says_why_once`, `test_only_this_sources_own_codes_are_copied_as_a_reason` | The fixture prints `owned-work-fixture-step` before each of `input`, `sources`, `tls-context`, `https-listen`, `relay-listen`, `listening`, `certificate-digest`, `ready-create` and `ready-rename`; the two listener steps are named by wrapping the producer's two constructors in the privately loaded module, as the proxy rows' worker substitutes its relay there, so the producer source and its pins are unchanged. A start that fails before the ready file is published has served nobody: it prints `owned-work-fixture-failed` (step, error class, `winerror`, `errno`, and a reason only for this source's own `Refusal` codes), puts the traceback on stderr, shuts its listeners down in order and exits 3. A failed publication is raised only after the unchanged `start()` returned, so no socket is closed under its serving thread. A failure after readiness stays, as before, since a request may be in flight, and now prints `owned-work-fixture-retained` once. RED on the bytes that ran: every start failure sleeps with empty stdout and stderr, the native record; a failed publication also closes the HTTPS socket under its serving thread; a start prints no step; a refused input is raised; a failure after readiness is silent. |
| A fixture that was not ready parked the owner although no serve existed | `ReadinessTests.test_a_fixture_that_never_becomes_ready_is_journaled_ended_and_known`, `test_the_unfixed_cases_park_over_a_fixture_that_never_becomes_ready`, `test_a_silent_fixture_is_known_by_no_step`, `test_a_fixture_that_ended_before_ready_is_read_to_its_end_and_known`, `test_a_ready_record_an_oracle_refuses_ends_the_fixture`, `test_a_fixture_that_outlives_its_one_termination_parks`, `test_another_generation_of_the_child_is_never_terminated`, `test_only_the_finite_fields_of_what_the_fixture_said_are_kept`, `test_a_ready_fixture_is_journaled_with_its_measured_wait_and_no_census`; `CensusRoleTests` | `prepare_before_serve` runs before the serve, so the product has no part in it. The cases now wait for the ready file themselves for `READY_SECONDS` (30, stated as a bound) and call the stages' `read_ready` only once the file exists, so its park is not reached; the stages module is unchanged, and the proxy rows' start still parks there. A fixture that is not ready in time, ended first, or published a ready record an oracle refuses is journaled, ended and awaited, and the owner finishes with exit 1 and `document-work-fixture-not-ready:timeout:<last step>`, `:ended:<exit>:<failed step>` or `:refused:<code>`. Journaled first: `document-fixture-holder-census` (fixture `work`, step `readiness`) over the fixture folder, the ready file, its `.publishing` name, the input, the fixture script, both producer sources, the certificate and the key, with the fixture named by role `work-fixture` and the owner's data leases listed with their modes; then `document-work-fixture-not-ready` with the child's pid, `alive`, exit code, `readyExists`, `publishingExists`, the folder's names, the steps and failure the fixture said (finite fields only), the waited seconds and `heldByFixture`. A live child gets one termination of its original Popen handle after its birth is checked again (`document-work-fixture-terminate-intent`), and 15 s to reach its terminal and EOF (`document-work-fixture-closed`); one that outlives it parks (`document-work-fixture-end-unknown`), and any other doubt parks as `document-work-fixture-closing-unknown`. A ready fixture journals its measured wait (`document-work-fixture-ready`). RED on the bytes that ran, over the stages' real `read_ready`: the park `runtime-fixture-readiness-unknown-no-replay` with the fixture alive and nothing journaled, the native record; a fixture that ended, and a refused ready record, escape as the oracle's error with the child unobserved, which the owner's `main` parks. Native only: the census calls and `TerminateProcess` on the fixture, and what the step lines show. |
| The responsive row had no closing after its serve started | `ClosingTests`; `LongWorkTests.test_each_phase_is_open_from_its_refresh_until_it_is_known_final`, `test_an_oracle_failure_before_any_refresh_is_left_to_the_closing`, `test_an_oracle_failure_between_the_phases_is_left_to_the_closing`, `test_a_failure_while_a_refresh_is_open_still_parks`, `test_an_error_no_oracle_raised_still_parks`; `test_windows_document_responsive.Qualification.test_a_child_after_serve_that_inherited_the_trust_options_is_refused` | `windows_document_responsive_cli_cases.close_known` now closes an `AssertionError` of the harness or the cases on a completed public call, and the module's own `document-` and `responsive-` codes, when every exchange closed its socket and no refresh is open: the work fixture is ended as above (`document-work-fixture-ending`), the endpoint and workspace observers are released, and the owner's closing quits the serve and exits 1. The lease marks a phase open before its refresh client starts and clears it when the work is known final and the handler's end was read; `run` parks only for a failure in that window or an error that is no oracle's. An open phase, open sockets, a client termination whose end was not observed and any other error type still keep every original. RED on the bytes that ran: no `close_known` exists, and `run` parks over a failed status call before any refresh. Native only: the quit after a terminated fixture, and every step of the long-work cases. |

Not changed: the proxy rows' fixture start. `start_runtime` uses the same `read_ready`, which still
parks a fixture that is not ready after 30 s, also before any serve. Their worker does not swallow
a start failure, and no native run failed there. The same closing would need the runtime stages and
the dedicated driver, which the proxy, reboot and TUN rows pin.

### A sleeping display at a UAC prompt, and the visual scene's prompt (native, 2026-11-09)

Setup run `73974d99` of `windows-scoped-tun.restart-deny` on clone `f452f353` (unenrolled,
discovery package) reached `uac-pending:vpn-broker:deny`. The clone's display was asleep and
the live prompt did not wake it: the frames of the reviewed frame route before and during
the prompt (operations `13cf0672`, `2083a262`, `f8e3622e`, `67befe7f`) are byte-identical,
1280x800 and all zero. The clone had no reviewed profile, so `windows-uac-decision` refused
`uac_profile_unreviewed` three times before any contact, each CLI call taking 33.6 to 35.3 s
on the loaded coordinator, and the prompt expired. The only reviewed wake at a prompt was
the decision's own pointer move, which needs a profile. On the `windowsUacVisual` clone
`39242640` the frame route returned the same black frame (operation `337d5cde`), and the
`windows-uac` scene had no reviewed route: `windows-uac-qualification.*` is a direct table
rung with no recipe, the public action refuses that prompt name, and the decision's context
needs an ordinary-user root. Evidence: `.runtime/windows-uac-nv7-20261109/`,
`.runtime/windows-parity-20261107/family/uac/73974d99-1fd8-469f-9990-42943b3a6509.jsonl` and
`.runtime/windows-uac-vis-39242640-20261109/` of the recovery checkout.

Built offline in `builders/build-uac-review` on `529cc610`; nothing below has run natively.
The unfixed tools are `529cc610` itself, where `windows_uac_decision.py` and `mcp_server.py`
are byte-identical to `bdfa98dd`. RED ran in an archive of it holding only the new and
changed test modules, on Python 3.14 and 3.12 with identical counts (subtests included).
The before-images and the logs are `.runtime/uac-review-before/` and
`.runtime/uac-review-logs/` of the build clone.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A sleeping display at a live prompt left an unenrolled clone no reviewed wake and no frame to review | `test_windows_uac_decision`: `ReviewFlowTests.test_a_sleeping_display_with_no_profile_gets_one_post_wake_frame_and_no_key_or_burn`, `ReviewExecuteTests.test_a_clone_with_no_profile_gets_a_reviewed_frame_without_key_burn_or_credential`; controls: the rest of `ReviewFlowTests`, `ReviewPacketTests` and `ReviewExecuteTests`, `RouteTests.test_the_review_is_a_sibling_closed_route_with_the_decisions_admission`, `test_a_review_route_reply_is_never_an_answer` | The sibling closed action `windows-uac-review` runs the decision's admission without a profile, makes the decision's single journaled pointer move for a black frame, keeps the post-wake frame privately and stops. The pointer journal is the decision's own file, so a repeat, or the decision after a review, refuses `instance_uac_display_black` instead of moving again. For a review that refusal permits another call, which only reads (`ReviewExecuteTests.test_a_display_still_black_permits_a_later_review_and_still_ends_the_decision`), so a slow wake costs a call and not the run; it still ends the decision's submits. It writes no burn, input journal, fence or decision terminal and opens no credential; the decision then answers the same consent process. A lost reply is only read by a status packet, and `retained_review_frame` hands the kept frame to `reviewed_uac_profile`. Every census and local refusal of the decision is asserted for the review beside the decision's own. RED (22 tests): failures=1, errors=70; the module has no `review`, `review_id` or `retained_review_frame`, `program()` takes no review mode and the route does not exist, and `test_lease_provider_policy.LeaseProviderPolicyTests.test_manifest_delta_is_only_the_reviewed_provider_group` errors on the missing action. GREEN: OK. Native only: that a pointer move wakes a display the prompt did not, how long that takes (the reply's `wakeMilliseconds`; the unchanged decision gives its own move one second, so a slower clone needs its prompt reviewed first in the run that answers it), the frame's size through the transport, and what the frame shows, including whether a prompt raised by the scenario's task-owned process is on the secure desktop at all. |
| Each call of the action spent its time before the first packet | `test_windows_uac_decision`: `RouteAdmissionTests.test_a_local_refusal_never_waits_on_the_transport_admission`, `ReviewExecuteTests.test_the_binding_is_the_drivers_binding_without_the_sign_in_stack`, `RouteTests.test_the_server_source_is_compiled_once_and_still_checked_on_every_adapter_load`, `RouteTests.test_a_one_shot_cli_command_never_imports_the_mcp_package`; `test_mcp_tool_launcher.McpToolLauncherTest.test_only_serve_pays_for_importing_the_mcp_package`; controls: `RouteAdmissionTests.test_a_call_that_must_reach_the_host_is_admitted_first`, the changed-source refusals in the compile test and the launcher's other tests | The route admitted the host's transport before the action looked at its own journal, so `uac_profile_unreviewed` waited on SSH. Reading the binding imported `readiness_windows_registration` and with it 43 modules of the sign-in stack, each compiled fresh and re-hashed by every later custody guard. `_agent_module` compiled the server's 10 000 lines on every adapter load. Every one-shot CLI command imported the MCP package twice, in the launcher's probe and in the server. Now both UAC actions answer what local files decide before the admission and run every gate again once admitted. The binding comes from the same file through the same reader without that import, held to the driver's binding and refusals by the test, and the scenario driver loads at the first contact. The loaded server bytes are compiled once per process, with the digest and the executing-code comparison still made on every load. Only `serve` and importers import the MCP package; a one-shot command's probe still imports `cryptography` and still requires the MCP package to be installed. Offline and interleaved on the loaded coordinator (load average 23 to 34), the call that refused `uac_profile_unreviewed` took 52.6 to 66.5 s (median 58.3 s, 5.5 s CPU) on `529cc610` and 17.0 to 19.8 s (median 18.6 s, 1.5 s CPU) with the change, over five rounds; the launcher's probe before it took 9.9 to 16.0 s and takes 0.05 to 0.44 s; a decision that passes the local gates reached its first host read in 36.3 to 54.3 s and does in 17.2 to 20.4 s, over three rounds. What remains is the interpreter compiling the server and the custody loader compiling 20 adapter modules from their held bytes, which is the custody itself. The SSH of a native call is unchanged and unmeasured. RED (5 tests): failures=5; the refusal had passed the transport admission (`(['windows-uac-decision'], [], [])`) and loaded `native_scenario_windows`, `readiness_windows` and `windows_scenario_host_job`, three adapter loads compiled the server three times, a one-shot command imported `mcp.server.fastmcp`, and the probe was `import cryptography, mcp`. GREEN: OK. |
| An owned `windowsUacVisual` clone had no reviewed route to raise, show and cancel the scene's prompt | `test_windows_uac_visual`: `RouteAdmissionTests.test_an_owned_visual_clone_has_a_reviewed_route_that_raises_and_cancels_its_prompt`, `RaiseTests.test_a_sleeping_visual_clone_gets_the_prompt_raised_shown_and_left_open`, `CancelTests.test_cancel_sends_one_esc_to_that_prompt_proves_it_closed_and_closes_the_fence`; controls: the rest of the module | The closed setup action `windows-uac-visual` (`windows_uac_visual.py`) takes `deploymentId`, `operationId` and `step`. `raise` proves the deployment's own qualified filtered-administrator session, parks the pointer once, which wakes the display, proves the Run dialog before it types the visual driver's command, and proves the prompt by a census and a dimmed frame; `cancel` sends one burned `Esc` to that prompt while it is younger than 90 s, or lets it expire, and proves it closed with no shell left. A repeat is a settle packet with no pointer, key or frame code. The controls refuse an unqualified or changed session, a prompt or shell already there, a display that stays black, a screen that is not the Run dialog, a prompt waiting in the taskbar, a foreign prompt and a shell left behind, each with no key beyond what the step allows. RED (40 tests, the census parse skipped for want of a PowerShell parser on this Mac): failures=8, errors=93, the module being absent; `RouteAdmissionTests.test_the_dispatch_names_the_deployments_own_host` is a control that holds on `529cc610` too. GREEN: OK. Native only: all of it, first of all the Run dialog's place, the foreground prompt, the dimming, the relative pointer's park and whether the frame shows the arrow. |

## Historical coverage rule

All older unresolved keeper/source/installer/resource/SSH/visual/protocol proposals
remain in the full archive and heading manifest. Locate the complete record before
judging supersession; omission from this compact index does not mean completed coverage.
TEST-001 requires preserved evidence/beforeimage, actual causal RED/GREEN, routine
consumers and fixed-artifact native rerun. Unknown comparison mappings refuse.
TEST-002 requires DIRECT and matching MCP. macOS deferral changes human scope
without deleting matrix or historical evidence.
