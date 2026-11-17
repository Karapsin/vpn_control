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
| The SSH row alone proved `ssh-import-routing` | `TableTests.test_the_table_names_every_windows_scenario_and_only_built_rows`, `FailedAndUnknownTests.test_with_the_real_table_ssh_import_routing_needs_both_ssh_rows` (formerly `test_with_the_real_table_the_ssh_row_proves_no_scenario_alone`) | The row's last event lists a relayed transfer and a stdin key import as `remainingProcedures`, and smoke step 11 also needs refreshes through a real relay. The scenario mapped to no row. RED: the table named the row, and a lone failed SSH row made a failed observation instead of a refusal. Trade-off: a failure of this row was not recordable through the matrix until the scenario's other rows existed. Since the SSH relay row (below) the scenario maps to both rows, passes only with each passed through both routes, and a failure of either is recorded at once. |
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

Superseded by the no-tray close row below: this build first left
`close-detach-traffic` and `gui-attach-detach` mapped to no row, because no public
setting, flag or command turns the Windows tray off and the older
`windows_no_tray_desktop.py` could not place a GUI on its private desktop (the Owner's
`owned_desktop` seam passed only a `handle_list` startup attribute, and Python's
`subprocess` has no `lpDesktop`). An owned desktop with no `Shell_TrayWnd` is that
missing state, and DESKTOP-002 says what a close must do there.

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
above would be its first native witness. Whether that is acceptable is the product's decision. It is
changed in "Folder pins refused other programs' renames into the user's folders" below, which also
turned that control into a gate.

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

### Windows no-tray close row, offline build (2026-11-13)

Before any VM contact, on `529cc610`. These are review gaps and
tool defects found offline, not native failures. The RED tree is `git archive 529cc610`
with only the new and updated test modules and their new fixtures copied in;
`red_green.py` and its logs for Python 3.14 and 3.12 are under
`.runtime/windows-parity-20261107/evidence/no-tray-close/` of the recovery checkout.

| Failure type | Regression | Notes |
| --- | --- | --- |
| No row could prove a detach by window close on Windows (DESKTOP-002) | `test_windows_no_tray_close`: `NoTrayRowTests` (`test_a_gui_without_a_usable_tray_closes_detaches_and_ends_while_the_runtime_serves`, `test_the_proof_of_the_desktop_needs_no_handle_like_the_guis_own`, `test_a_window_destroyed_while_it_was_listed_is_no_window_of_the_desktop`), `AdmissionTests` (2), `NoTrayDecisionTests` (4); `test_windows_proxy_lifecycle.HarnessTests`; `test_native_scenario_windows` `TableTests` and `PackageAdmissionTests.test_every_new_row_admits_before_any_journal`; `test_native_scenario_windows_matrix.TableTests`; `test_native_scenario_execution.NativeScenarioExecutionTest.test_windows_names_are_closed`; `test_native_scenario_bundle.NativeScenarioBundleTest.test_inventory_outside_scripts_moves_every_top_level_name`; `test_windows_scenario_host_job.ProxyFamilyTests.test_every_proxy_row_runs_on_one_installed_base_and_refuses_each_mutated_request`; controls: `NoTrayControlTests` (20) | New row `windows-proxy-lifecycle.no-tray-close`, mapped to `close-detach-traffic` alone and, with `gui-pending`, to `gui-attach-detach`. Its module, the rewritten `windows_no_tray_desktop.py`, is a new pinned driver role (`NO_TRAY_SHA`) with the scheduled row's six input fields. With proxy A on and the sampler running it creates an owned private desktop, starts only the installed GUI with `--state-dir` there, proves the GUI's window is there (its thread too, where `GetThreadDesktop` can name it for another process) and nothing of it is on Default, watches the window stay visible past the product's last tray-install attempt (75 s against 60 x 1 s read from `DesktopTray.kt`), reads the decision as `gui hide` UNSUPPORTED (`Main.kt`), posts one `WM_CLOSE` from a thread of that desktop, and requires the owner's `gui hide` NOT_FOUND less than 9 s after that post (a lease nobody released is held until 15 s after its last 5 s heartbeat), exit 0, the JVM gone, no window left, status, actors and one owned runtime unchanged, and samples around the attach, the probe and the close. A live GUI with its main window hidden fails `gui-hidden-without-usable-tray`. The world models Default with Explorer's tray host, the private desktop, the message rule between desktops and the product's tray decision read from the source, with the JDK's answer to an icon without a tray host as a switch: AWT refusing it passes the row, AWT taking it (what `installTrayIcon` then marks available at once) fails it named, as does a tray taken at a later retry. The world's native peers convert every argument by its declared type, as ctypes does for the real call, and its journal takes the module's events only as the strict JSON the real Owner writes. Eighteen controls each make the product or the guest answer wrong once (icon taken, taken late, a close that hides, an ignored close, an exit that keeps the lease, a late exit that never detached, a stopped runtime, a second runtime, dropped traffic, windows on Default, a close posted from Default, a refused window census, a new desktop that already lists a window, another process's window beside the GUI's, a window left after the GUI ended, a launcher that ended before its JVM, a census callback that raised on the private desktop and on Default) and the row ends 1 with every child it started terminal and the desktop closed, after one `no-tray-close-failed` event that names the stage it stopped in and, for a refused Win32 call, the error code; a callback that raised makes its census a refusal with the exception named, where ctypes alone would drop it and list less. A refusal over a census or over the JVM's exit records what it saw first (`no-tray-runtime-census`, `no-tray-desktop-not-empty`, `no-tray-foreign-window-on-private-desktop`, `no-tray-jvm-exit-unproven`). A GUI that exits nonzero after its close keeps that terminal, so the closing ends on `dedicated-known-failure-terminal-and-eof` with every child terminal. The twentieth shows that a settle shorter than the product's retries would pass a GUI that later hides. RED on `529cc610`, Python 3.14 and 3.12 alike, over the 65 tests of the three rows: 18 failures and 37 errors, in 54 tests (one fails in two subtests). Twenty end on the driver's `dedicated-finite-proxy-variants-only` (the three row tests and seventeen of the controls), and the nonzero-exit control fails on that same refusal where it expects its closing's; the rest are the admission's `windows_scenario_not_allowlisted`, the generator's `proxy_variant`, the missing recipe and driver names, the module's missing desktop API and constants, the closed name lists, the bundle count, the two scenarios still unmapped, the host job's family test, which finds no such row, the owner's missing `CreateProcessW` structures, flags, signatures and environment block, and its Popen seam in seven of the ten child-seam tests and in the capture test, among them the causal REDs of the two rows below. The other eleven hold on both trees: the reading of `Main.kt`'s close decision, two lease refusals, the census that refuses on an error, the mutated-harness refusal and six table tests of other rows. GREEN: 65 OK on both. |
| The owned desktop's GUI child started through Popen, which names no desktop | `test_windows_owned_desktop`: `ChildSeamTests.test_the_popen_seam_named_no_desktop_actual_red_and_createprocess_green` and `test_exact_lease_desktop_child_and_popen_custody`; controls: the rest of `ChildSeamTests` (default and console children unchanged, a foreign or equal lease, console conflict and closed argv, one launch per lease, a failure after `CreateProcessW` keeps the process handle and pipes, a refused `CreateProcessW` closes only what it made, the environment block), `CaptureTests.test_a_desktop_child_has_the_same_raw_capture_and_terminal_accounting` and `NativeLayoutTests` (5) | The Owner and lease of `529cc610` passed the desktop handle in a Popen `handle_list` and no `lpDesktop`, so the GUI would have started on the Owner's own desktop. `Child` now starts a lease's one GUI child through `DesktopProcess`: `CreateProcessW` with `STARTUPINFO.lpDesktop` `WinSta0\<name>` from `desktop_for_child` (closed argv: the installed GUI with `--state-dir`), DEVNULL input, two pipes, exactly those three inheritable handles in `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, `CREATE_UNICODE_ENVIRONMENT`, `EXTENDED_STARTUPINFO_PRESENT`, `CREATE_NO_WINDOW`, the Owner's environment and root; the process handle is retained, the thread handle and child ends closed, and `poll` is Popen's. Every other child keeps the same Popen call, without the `startupinfo=None` it passed before. The capture control runs the real pumps over local pipes. `NativeLayoutTests` checks what a host without Windows can of the one native call: the three structures' amd64 sizes and offsets (104, 112 and 24 bytes, from fixed-width fields), the creation flags, the refusal to construct off Windows, and `create()` itself against a declared kernel32 that converts each argument by its declared type as ctypes does (the desktop name, the three handles in the list and as standard handles, the UTF-16 block, the flags, and the attribute list deleted after a refusal too). The RED oracle loads the whole `529cc610` Owner and lease (fixtures `owner-popen-seam.before.source`, `no-tray-handle-list.before.source`, digests in the fixture provenance): 1 failure, `started through Popen, which names no desktop`, no error; GREEN passes. The older missing-API RED keeps its own error. Native only: the call itself, on the guest. |
| A fresh private desktop's window census refused itself | `test_windows_owned_desktop.EmptyDesktopTests.test_an_empty_desktop_lists_no_window_before_red_current_green`; control `test_a_false_census_that_sets_an_error_still_refuses` | user32's `InternalEnumWindows` answers FALSE without an error when it lists no window, so the old census, which required TRUE, refused the new desktop before any GUI started (`owned-desktop-window-census`). The census now zeroes the last error first and takes FALSE with no window, no callback failure and no error as empty; a FALSE that sets an error still refuses. RED on the `529cc610` module bytes, GREEN on the current one; the user32 behaviour is read from its known source, natively unproven. |

The authentic stage controls (`windows_lifecycle_runtime/stages/controls.source`,
`DesktopCases`) now call `no_tray_close_case` with its six input fields and the
runtime stages and take the lease's `lpDesktop` from `desktop_for_child`, refusing an
`--autostart` or foreign argv; their provenance records the adjustment and keeps the
historical digests. Not proved here: whether AWT on Windows takes a tray icon on a
desktop without `Shell_TrayWnd` (`Shell_NotifyIcon` has no host there, and as the JDK
source reads, its tray peer ignores that call's result), so whether the installed
product passes this row or fails it `gui-hidden-without-usable-tray`; Java and Compose on a desktop that
never takes input; and the private desktop's `CreateProcessW`, the relaunched JVM's
inheritance of it, and the window reads and posted close from a thread of that desktop.

### Windows SSH relay row, offline build (2026-11-09)

`windows-disconnected-cli-config.ssh-relay-transfer` does what the ssh-import-routing
row left as `remainingProcedures`: a stdin key import and refreshes through a real SSH
relay, connected and disconnected (see `agent_docs/tools/visual-and-platform-evidence.md`).
The relay runs in the guest: the image has no SSH server, sing-box 1.13.4 has no SSH
inbound (`sing-box check`: "unknown inbound type: ssh") and fixtures install no Windows
feature, so `agent_tools/windows_ssh_relay_fixture.py` is a standard-library SSH server
written here. Nothing here has run natively. Before any native run the relay ran on one
Mac's loopback against the bundled sing-box revision (`d0918261`, its darwin build) with
`HomeSshRouteConfigBuilder`'s bootstrap configuration and a reduced proxy-only runtime,
and against a JDK 17 `HttpURLConnection` built as `DesktopSubscriptionDownloadClient.execute`
builds it: HOME_RELAY, the connected chain and a second HOME_RELAY fetch passed, and an
unpinned host key and a stopped relay each ended in a `SocketException` with no origin
request. The interop script and its three runs, the RED runs on `f31ab987` and the GREEN
runs are under `.runtime/ssh-rows/` of the build clone.

| Failure type | Regression | Notes |
| --- | --- | --- |
| No row did a transfer through a real SSH relay or a stdin key import, so `ssh-import-routing` mapped to no row | `test_native_scenario_windows.PackageAdmissionTests.test_the_ssh_relay_row_is_admitted_with_the_artifacts_of_the_ssh_import_row`, its `TableTests`; `test_native_scenario_windows_matrix.FailedAndUnknownTests.test_with_the_real_table_ssh_import_routing_needs_both_ssh_rows`, `TableTests.test_the_table_names_every_windows_scenario_and_only_built_rows`; `test_windows_scenario_host_job.SshRelayFamilyTests`; `test_windows_ssh_relay_cases` | The relay row adds the case module, the relay and two owner doors (below), and `MATRIX_SCENARIOS` names both SSH rows for `ssh-import-routing`. RED on `f31ab987` with these tests, Python 3.14 and 3.12 alike: `test_native_scenario_windows` `TableTests` and `PackageAdmissionTests` `Ran 16 tests`, `FAILED (failures=3, errors=2)`, the admission refusing `windows_scenario_not_allowlisted`; `test_native_scenario_windows_matrix` `Ran 33 tests`, `FAILED (failures=2)`, the scenario `unmapped`; `test_native_scenario_execution` `FAILED (failures=1)`; `test_native_scenario_bundle` `FAILED (failures=1)` (62 sources against 60); `SshRelayFamilyTests` `FAILED (errors=3)` (the row's sources absent); the new case and relay test modules fail to import. GREEN: every one passes, with the modules run listed in the build clone's batch summaries. The case module's controls: 26 product defects in `CaseTests.test_each_defect_is_caught_by_its_oracle`, each stopped by its own reason, and the owner's known-failure closing quits the serve without a park after a failure while connected, because the module turns the runtime off first (`test_a_known_failure_while_connected_is_closed_by_the_owner_without_a_park`; control `test_an_owner_left_connected_parks_the_closing_with_every_original_kept`). |
| Every child of the ordinary owner had an empty stdin, so no public call could import a key from stdin | `test_windows_owner_stdin_launch.StdinChildTests` | A public call may now take one regular, single-link file of at most 64 KiB under the operation root as its whole stdin; the owner closes its own handle once the child holds an inherited one, and the intent records only `stdinBytes`. Every other child keeps `DEVNULL` and its intent unchanged. RED on `f31ab987`: `Child.__init__() got an unexpected keyword argument 'stdin'`, the same for `Owner.invoke`, and no `STDIN_MAX_BYTES` (3 errors of `Ran 8 tests`, `FAILED (failures=2, errors=3)` with the next row). |
| A CLI case module could not scope JVM options to its serve, so the serve could not trust an in-guest HTTPS origin | `test_windows_owner_stdin_launch.LaunchHookTests` | The owner of `disconnected-cli-config` and `streaming-client-interrupt` now loads the case module before the serve; a module that defines `configure_launch` sets `JAVA_TOOL_OPTIONS` after the static probes, and the owner removes it right after starting the serve, also when the start fails. RED on `f31ab987`: the serve started without the options for both actions, `[('help', False), ('version', False), ('serve', True)] != [... ('serve', False)]` (the 2 failures of the same run). |
| The pinned HTTPS fixture's 0.25 s TLS handshake ended a JVM's first handshake through the relay | `test_windows_ssh_relay_fixture.OriginTests.test_the_pinned_fixtures_handshake_ends_after_a_quarter_second_without_a_client_hello` (the pinned fixture's own accept path) and `test_a_handshake_has_more_than_the_pinned_fixtures_quarter_second` | Found by the first interop run, whose origin was `https_subscription_relay_fixture`: the bootstrap fetch ended `SSLHandshakeException: Remote host terminated the handshake` with only the SOCKS handshake through the channel, and the connected fetch passed only on the JDK's second connection. The pinned fixture is unchanged; the relay row's origin is the relay module's `HttpsOrigin`, which gives a handshake 60 s. The control is RED by design: the pinned fixture refuses a client silent for 0.25 s. The second and third interop runs passed every step. |
| Closing the relay waited on a thread blocked in a socket another thread had shut down and closed | `test_windows_ssh_relay_fixture.LifetimeTests.test_start_binds_two_listeners_and_stop_ssh_refuses_new_sessions_while_socks_stays` | Found in the module's first offline draft, which was never committed and not kept: on macOS neither a shutdown nor a close by another thread woke a SOCKS handler waiting on a socket pair with a timeout, and a closed descriptor number was reused at once, so `close(10)` returned False. Only the thread that owns a socket closes it now, every wait polls its stop flag every 0.25 s, and `stop_ssh` returns only after the listener's own thread closed the SSH port. |

### First native query-owner row: the query's controller is its own JVM (2026-11-09)

`windows-query-owner-gui-reconnect` (direct operation `f56f4a4c`, clone `31f97559`, installed
2.2.17 built from `f31ab987`, tools of `f31ab987`) ended exit 1 with `ValueError` through its
known-failure retirement, not parked: event 85 `preboot-refusal-quit-intent`, and the quit to the
transient controller (child 27) ended GUI child 24 with 0. Evidence:
`.runtime/windows-parity-20261107/family/diag/evidence-f56f4a4c/`. Every product step passed:
`status` with no owner answered exit 2 `UNAVAILABLE` (child 20); `locations list` started the
transient controller `03e8d846` (child 21); two statuses kept it disconnected (22, 23); the GUI
(child 24, launcher 3576 with restart child JVM 1068) attached, and the next status (25) was
running, proxy-only, on `03e8d846`. The census (child 26) lists `vpn-control.exe
--headless-controller --state-dir <workspace>` pid 3676, whose parent 4780 is not in the census,
with `sing-box.exe` 2528 as its direct child and no `vpn-control.exe` under it. The case then
wanted exactly one same-image JVM child under that controller and raised
`one-query-controller-jvm` on zero. A replay of the recorded children 17 to 26 through the
`windows_postboot_action.py` of the run's bundle (sha256 `8eb8d4d6...`, the bytes of
`f31ab987` and of `529cc610`) raises exactly there, with every earlier check passing. This is a
tool defect. No contract fixes the controller's process shape, and the product's launch path
explains the recorded one: the jpackage launcher relaunches only while PATH lacks `<image>\app`
(the launcher restart entry above), and `DesktopHeadlessController.startForCliCommand` starts
the controller from the CLI's JVM with the inherited PATH (`desktopAppChildProcess` removes only
`_JPACKAGE_LAUNCHER`). That 4780 was that CLI JVM is inferred: no census ran while the query
lived. The product met DESKTOP-004 (the transient start never connected; the GUI restored the
intent once) and DESKTOP-008. The before-images and the RED, GREEN, mutation, replay and pin
logs are under `.runtime/` of the fix clone
(`.runtime/windows-parity-20261107/builders/fix-query-owner` of the recovery checkout); the patch
and its report are under `.runtime/windows-parity-20261107/evidence/query-owner/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The query-started controller had to relaunch into a JVM child | `test_windows_reboot_actions.QueryControllerCensusTests`: `test_the_recorded_native_census_reaches_the_runtime_of_a_controller_that_is_its_own_jvm` (the recorded serve and children 17 to 26, `fixtures/windows_query_owner_native/f56f4a4c-query-first.json`, each stream checked against its recorded digest), `test_the_query_row_closes_known_where_the_controller_is_its_own_jvm`, and `PrebootActionTests.test_the_query_row_starts_a_transient_owner_by_a_config_query_and_never_reboots_or_declares`, now over the native shape; controls `test_a_controller_launcher_that_relaunched_is_still_followed_to_its_jvm`, `test_a_second_relaunch_or_a_runtime_born_before_its_claimed_parent_is_never_taken` | `query_then_gui` now takes the rule `capture_proxy_actors` already follows: a controller that did not relaunch is its own JVM, at most one same-image child born after it is its relaunched JVM, and the runtime is the one `sing-box.exe` born after that JVM under it. A parent PID outlives its process, so a child born before its claimed parent is never taken. The world's transient controller is now the recorded shape: the CLI's JVM starts it and ends with the query, leaving a stale parent PID. RED on isolated copies of `529cc610`, the base of this change, and of `f31ab987`, the tools that ran, each holding only the new test module and fixture, Python 3.14 and 3.12: `Ran 17 tests`, `FAILED (failures=2, errors=2)`, each `one-query-controller-jvm` (the stale-runtime control fails there for the same reason). GREEN: 17 OK on both. Three loosenings (no birth guard, no relaunch, no relaunch bound) each turn one named control RED. Pins renewed: the owner's `_POSTBOOT_ENTRY_SOURCES` and the planner's `POSTBOOT_ROLE_HASHES` (`postbootAction`), `readiness_vm_dispatch.json` `sourcePins.windows_ordinary_task`, and the selector's `nonPythonResources` entry for that manifest; no file of `readiness_windows._source_pins()` changed. Native only: the rest of the row past the census (traffic through the runtime under 3676, explicit off, runtime exit, the quit that ends the GUI, the closing census) on a direct rerun of these tools. The closing census then waited only for the GUI child while the controller's exit raced it; the follow-up below waits for every product generation first. |

### Reboot rows' declared tree and the query row's closing census, offline (2026-11-13)

Two defects predicted from the census of `f56f4a4c` and from the product source, not yet met
natively, fixed before any reboot row runs. The GUI starts its controller through the same
`DesktopHeadlessController.startForCliCommand` (`DesktopGuiOwnerConnection.connect`) from its own
JVM, itself a relaunch (1068 under 3576 in that census), so the GUI-started controller is expected
to run its own JVM too. That shape at a reboot is inferred, not recorded: no GUI-started controller
has been censused. The product releases a transient owner's exit only once the GUI acknowledged
its quit (`DesktopOwnerExitGate.releaseQuit`) and notices it within a second
(`HeadlessLifecycle.awaitExit`), so the controller can outlive the GUI child. The RED, GREEN and
mutant logs are under `.runtime/logs/c2/` of the fix clone.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The reboot rows' declared tree required the controller to relaunch | `test_windows_reboot_actions.RebootTreeTests`: `test_a_preboot_over_the_recorded_shape_declares_its_own_jvm_controller_and_never_parks`, `test_a_postboot_over_the_recorded_shape_retires_its_own_jvm_controller`, `test_the_recorded_tree_is_declared_and_the_host_job_allows_it`, `test_the_host_job_allows_a_declared_controller_that_is_its_own_jvm`, and `PrebootActionTests.test_each_reboot_preboot_leaves_the_autostarted_app_declared_and_no_child_of_its_own` and `PostbootActionTests`, now over that shape; `test_windows_scenario_host_job.RebootFamilyTests.test_a_controller_that_is_its_own_jvm_is_declared_and_admits_its_postboot`; controls `test_a_relaunched_controller_is_still_taken_with_its_launcher_row`, `test_a_second_relaunch_or_a_child_born_before_its_claimed_parent_is_never_taken`, `test_the_host_job_refuses_a_declared_tree_out_of_shape` | The offline world's autostart tree is now `recorded_product_tree`: the four pids of the census, the GUI's one relaunch with its births, a controller with no same-image child and the runtime as its child at its recorded birth; substituted are the autostart argv, the scheduler as root and, inferred, the GUI JVM as the controller's parent, 1.144 s after it (the recorded gap from the query CLI's start to its controller). `product_tree`, through the shared `own_jvm` and `born_children` the query row now uses too, takes a controller that did not relaunch as its own JVM, at most one same-image child born after it as its relaunched JVM, and never a child born before its claimed parent; a `controllerLauncher` role exists only for a relaunched controller. `product_rows` declares 3 to 5 rows, and the host job's `product_declaration` takes the roles in `DECLARED_ROLES` order with the launcher row optional, the controller under it or under the GUI JVM, every child born at or after its parent; the idle allowance, unchanged, already follows declared parents of any role. RED on the `529cc610` bytes and on `2a1e8a1e`, each an isolated copy holding only the new test modules and fixture, Python 3.14 and 3.12: every preboot over the recorded shape parks (`preboot-product-start-unresolved-no-replay`; the offline world's park raises, so its handler re-parks as `original-preboot-effect-unknown-no-replay`), and the host job refuses the declaration (`product_declaration_refused`, `declaration_tree`). GREEN on the fix: the module and the host job test pass on both. Native only: the GUI-started controller's own shape, which the first `.pre` records in its checkpoint. |
| The query row's closing census raced the controller's exit | `QueryControllerCensusTests.test_the_closing_census_follows_a_controller_that_ends_after_the_gui`; control `test_a_product_generation_past_the_bound_is_a_known_failure_never_a_park` | After its census the case now holds, by native handle, every other product generation of that census, the controller included, and after the quit and the GUI child's end awaits each against one 60 s bound before the closing census. A generation still running at the bound is journaled (`query-first-product-exit-timeout`, naming it) and refused as a known failure; the quit's reply and the GUI's end were already observed, so it never parks. The world now lets the controller run on after the GUI ends (`controller_linger`). RED on `2a1e8a1e` (Python 3.14 and 3.12): `query-first-product-fully-retired`, and no named timeout; on `529cc610` the row fails earlier (`one-query-controller-jvm`). GREEN on the fix. |

Eight loosenings each turn a named test red: no birth guard, no relaunch, no relaunch bound, no
closing wait, a timeout that parks, a host job that needs the launcher row again, a host job
without the birth order, and `product_rows` needing four rows again. Pins renewed to a fixpoint:
the owner's and planner's `postbootAction`, the planner's `autostart`,
`readiness_vm_dispatch.json` `sourcePins.windows_ordinary_task` and
`sourcePins.windows_scenario_host_job`, and the selector's entry for that manifest. No file of
`readiness_windows._source_pins()` changed.

### An autostart GUI that runs its own JVM, offline (2026-11-13)

The tree check still required the GUI launcher the autostart task starts to relaunch exactly once.
Recorded in `f56f4a4c`: an owner-started GUI that relaunched (3576 to 1068, the same argv).
Inferred, not recorded: what the GUI the task starts does, since its PATH comes from the task's
environment. A `.pre` must not park on whichever it is. The logs are under `.runtime/logs/c3/` of
the fix clone.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The reboot tree required the autostart GUI launcher to relaunch | `test_windows_reboot_actions.AutostartGuiShapeTests`: `test_a_preboot_over_a_gui_that_is_its_own_jvm_declares_it_as_the_root_and_never_parks`, `test_a_postboot_over_a_gui_that_is_its_own_jvm_retires_it`, `test_every_gui_and_controller_shape_is_declared_with_its_row_count`; `test_windows_scenario_host_job.RebootFamilyTests.test_a_gui_that_is_its_own_jvm_is_declared_and_admits_its_postboot`; controls `test_a_second_gui_relaunch_or_a_gui_child_born_before_its_parent_is_never_taken`, `test_the_host_job_refuses_a_gui_root_out_of_shape` | `product_tree` now takes the GUI by the controller's rule: a GUI launcher that did not relaunch is its own JVM, at most one child born after it is its relaunch, and a child born before its claimed parent is never taken. `own_jvm` now takes as a relaunch only a same-image child with the launcher's own argv, as jpackage relaunches it: a GUI that runs its own JVM has its controller as a same-image child. On `5b5bca8e` that controller was taken as the GUI's JVM: a GUI and controller that both ran their own JVMs were refused (`one-gui-started-controller-launcher`, which the preboot retries and parks on), and a GUI that did not relaunch with a controller that did was declared wrongly, its controller launcher as `gui`. The `guiLauncher` role exists only for a GUI that relaunched; otherwise the GUI is the tree's root. Declared rows: `gui` and `controller` always, `runtime` exactly for reconnect, and a launcher row for each of the GUI and the controller that relaunched: `product_rows` 2 to 5, the host job reconnect 3 to 5 and explicit-off and autostart-migration 2 to 4; the root (`guiLauncher`, else `gui`) has no declared parent. The offline world gains `relaunch_gui`; `recorded_product_tree(gui_relaunch=False)` drops 1068 and hangs the controller under 3576. RED on `5b5bca8e`, an isolated copy holding only the new test modules and fixture, Python 3.14 and 3.12: the module `Ran 31 tests`, `FAILED (failures=10, errors=2)`: every preboot over a GUI that runs its own JVM parks, the shapes test fails for each such GUI, and the host job refuses (`declaration_tree`); its host-job test `FAILED (failures=2)`, `product_declaration_refused`. GREEN: 31 OK and 2 OK on both. Native only: the autostart GUI's own shape, which the first `.pre` records. |

Fourteen loosenings over the three commits each turn named tests red; the six new ones are a GUI
that must relaunch again, a relaunch matched by image alone, a host job that needs `guiLauncher`
again, no root check, no GUI-to-launcher pair, and `product_rows` needing three rows again. Pins
renewed to a fixpoint on the same chain as before; no file of `readiness_windows._source_pins()`
changed.

### Windows visual review of `f31ab987`: Material default surfaces, stale mode copy, catalog typo (2026-11-13)

The agent review of the hosted Windows capture of `f31ab987` recorded four product defects
(`.runtime/windows-parity-20261107/evidence/visual-f31ab987-verdicts.json`: scenes
`routing-import-menu-desktop`, `routing-export-menu-desktop`, `update-checking` and
`settings-app-mode`). All four predate that SHA: the 2.0.0 baselines of `602ea10d` hold the same
pixels and the same sentence, so the comparator passed them. Checking the claims against the
sources of `529cc610` widened two of them and added a fifth finding. Every `DropdownMenu` and
`AlertDialog` without a `containerColor` was affected, not only the routing menus and the update
dialog: the Locations menus, the desktop settings menu, the desktop rename-subscription dialog
(`profile-rename-dialog`, the same `#2B2930` in its Windows baseline), two desktop failure dialogs,
and on Android the import and export menus and three dialogs. The direct-domain hint is one
English sentence in all 66 catalogs, so each carried the typo. The desktop settings menu's
subtitles were `#4A6070`, which the review did not record.

Three unfixed sources are kept as `scripts/testdata/ui-theme/*.before.kt`. RED ran the tests of the
fix on the production bytes of `529cc610` (`app/src/main`, `desktopApp/src/main` and
`shared/ui/src/commonMain` checked out from it): 10 Kotlin tests, 10 failures. GREEN on the fix: 10
tests, no failure. The guard and its test ran on exports of both trees. Logs, JUnit reports, the
theme defaults Material resolves before and after, and local before/after captures of the 50 desktop
app scenes are in `.runtime/windows-parity-20261107/evidence/visual-defects/`.

Whole suites on the fix: `:shared:core:desktopTest` 238 tests, `:shared:ui:desktopTest` 54 and
`:app:testDebugUnitTest` 594 without a failure, `:app:compileDebugKotlin` and
`:app:compileDebugAndroidTestKotlin` passed, and `:desktopApp:test` 1309 tests, 111 skipped, 5
failed. The five are `DesktopAndroidAdbClientTest` cases whose fake-adb exchanges ran past their
deadlines on a host at load 17 to 25. Two reruns of the class alone failed 1 and then 3 of them, and
four of the five passed in a rerun. The fifth,
`interactiveFindBestPollsDelayedConsentForSynchronousAndAsynchronousRequests`, failed in all seven
runs on the fix and in 3 of 4 runs on the production bytes of `529cc610`, at 21 to 24 s against its
20-second deadline, so it follows the host and not this change.

| Failure type | Regression | Notes |
| --- | --- | --- |
| Dropdown menus and dialogs painted Material's default dark surfaces | `VpnControlThemeColorSchemeTest` (`:shared:ui:desktopTest`); `VisualCaptureTest.menusAndDialogsPaintTheContractSurfaces` (`:desktopApp:test`); `scripts/test_check_ui_theme.py` with the extended `scripts/check_ui_theme.py` (release hygiene) | `VpnControlColorScheme` assigned 23 of Material's 36 color roles and let `surfaceTint` follow `primary`. The other 12 kept Material's dark defaults: `surfaceContainer` `#211F26` (dropdown menus), `surfaceContainerHigh` `#2B2930` (dialogs), `surfaceContainerHighest` `#36343B` (the track of an unchecked `Switch`), the two other surface containers, `surfaceDim`, `surfaceBright`, the three inverse roles and the tertiary container pair. A menu or dialog that set no `containerColor` showed them, and `check_ui_theme.py` looked only at the palette literals. The scheme now assigns all 36 roles from `VpnControlColors`. Dropdown menus resolve to the elevated surface `#1D2B3B` and dialogs to the base surface `#141F2D`, by default and through an explicit `containerColor` at the twelve call sites that had none; UI-002 now says so. An unchecked `Switch` track becomes `#1D2B3B`. The theme test reads the scheme, `MenuDefaults`, `AlertDialogDefaults` and `SwitchDefaults` in a composition under `VpnControlTheme`, lists the color properties of `ColorScheme` by reflection and takes the defaults from Material's own `darkColorScheme()`, so a role that a later Material adds is compared too. The desktop test renders five real scenes and reads the dominant color behind a tagged element. The script refuses a surface role on the other surface, an unassigned role, and a dialog or dropdown menu that does not name its surface; its test runs it on the three before sources. RED: theme test 4 tests, 4 failures (the 12 roles; menu `#211F26` and dialog `#2B2930`; switch track `#36343B`); desktop test 1 failure (`#211F26` three times, `#2B2930` twice); script test 19 tests, 8 failures on Python 3.14 and 3.12, and the guard itself 25 findings. GREEN: all pass. Native only: the same surfaces in hosted Windows, Linux and macOS captures and in an Android capture. Nothing was rendered on Android here; Android's Material 1.3.1 has the same 36 roles and the same menu, dialog and switch tokens. |
| The mode dialog said that changing mode stops the session | `DesktopPendingConnectionCliTest.liveModeSaveKeepsTheSessionAndTheWarningSaysSo` (`:desktopApp:test`); `CatalogCopyRegressionTest.modeChangeWarningSaysTheSessionContinuesUntilARestart`, `noCatalogKeepsItsRetiredModeChangeWarning` (`:shared:ui:desktopTest`) | `APP_MODE_DESKTOP_CHANGE_WARNING` dates from `f2657326` (2026-04-30). `4d8a2e7a` (2026-09-06) made a mode save keep the live runtime, commit the next mode and leave a restart pending (STATE-005), and the sentence stayed. The desktop test starts a recording runtime through the public CLI path, saves `mode vpn` with `settings set` and asserts one start, no stop, the same runtime id, the committed VPN mode beside the active proxy-only one and `restartRequired`; then the sentence; then that `restart` applies the mode. RED on `529cc610`: every behavior assertion passes and the test fails at the sentence, "Changing mode while connected stops the current session first."; all 66 catalogs still carry their retired sentence. GREEN: both pass. Each translation is derived from that catalog's own retired sentence and its `CONNECTION_RESTART_PENDING` text; no native speaker has read them. |
| `some_stie.com` in the direct-domain hint | `CatalogCopyRegressionTest.noCatalogContainsTheDirectDomainExampleTypo` (`:shared:ui:desktopTest`) | `21804192` (2026-05-04) replaced the translated hint with one English sentence in every catalog, typo included. It now reads `some_site.com`. The test reads every generated UI and status catalog. RED: 66 entries. GREEN: none. The hint itself is still untranslated in 65 catalogs; `check_localization.py` reports the same 4987 warnings before and after. |
| Desktop settings-menu subtitles at 2.48:1 | `VisualCaptureTest.settingsMenuSubtitlesMeetNormalTextContrast` (`:desktopApp:test`) | The second line of each item was `#4A6070`, on no palette text color; the Android menu uses `#D3E3EE`. The geometry gate measures only the first text of an item, so it reported 16.3. The subtitles now use `VpnControlColors.TextSecondary`. RED on `529cc610`: all nine at 2.48. GREEN: none below 4.5 (10.95 measured in the local capture). Found while verifying the menu container, not by the review. |

Scenes expected to differ from the baselines because of these fixes, beyond the changes the review
already listed: the four import and export menus and `main-settings-menu-desktop` (menu surface;
there also the subtitles and the unchecked switch), the eight `update-*` scenes and
`profile-rename-dialog` (dialog surface), `settings-ssh-disabled`, `settings-ssh-key` and
`profile-current-locations` (unchecked switch track), `routing-domains` and `routing-desktop-note`
(the corrected example), and `settings-app-mode` (the sentence wraps to two lines and the dialog
grows). The local macOS render of the Windows scene list changed in exactly these 20 scenes and in
no other of the 50. On Android the same holds for the update dialog, the import and export menus,
the two QR-too-large dialogs and every unchecked switch; that is unproven until a capture.

### Folder pins refused other programs' renames into the user's folders (product, from 83484649, 2026-11-13)

The product finding of the second native document row. Run `83484649` (package 2.2.17 of `f31ab987`,
whose `desktopApp/src/main` equals `245b61a7`) had six renames of a direct child of the operation root
refused with `WinError` 32 while the serve retained one transfer: event 2631 of
`.runtime/windows-parity-20261107/family/diag/evidence-83484649/`, unpacked from
`.runtime/windows-scenarios/83484649-990b-44ef-a66f-cf77392eef10/evidence-1.zip`. Microsoft's file
system specification confirms the reading. A rename or hard link by path opens the folder of the new
name for `FILE_ADD_FILE` (a folder: `FILE_ADD_SUBDIRECTORY`), sharing read and write ([MS-FSA]
2.1.5.15.12 and 2.1.5.15.7 with Appendix A <185> and <183>); only `READ_DATA`, `EXECUTE`, `WRITE_DATA`,
`APPEND_DATA` and `DELETE` take part in sharing ([MS-FSA] 2.1.5.1.2.2). Every product folder pin was
`CreateFile(0x00120081, share 1)`, so it refused every such open, while creating an entry opens no folder
and was never refused. The same mode reached further than transfers: the installer's pins of
`%LOCALAPPDATA%` and its ancestors during an installation, its cleanup, the workspace registry and
exports, the installer store's `C:\` and `C:\ProgramData`, and the process admission, which every
packaged process holds until it exits over every folder down to its own image. The per-user package
lives in `%LOCALAPPDATA%\vpn-control`, so while the GUI or the serve ran, no program could rename into the
home folder (`git config --global` replaces `.gitconfig` that way), `AppData`, `%LOCALAPPDATA%`,
`C:\Users` or `C:\`. Folder pins now share writes and never delete: `WindowsInstallNative.PINNED_DIRECTORY`,
taken by the transfer pins, the installer store's ancestry and witnesses and the admission's folders
(`WindowsAdmissionNative.openDirectory`). Images, helpers and manifests (`openFile`) keep `INSPECT` and
deny writers: the coordinator's readiness probe (`TryReady`, a write open of each image) and the
elevated launch of a digest-checked helper rely on that. `READ`, `PINNED_READ` and the private transfer
folder's `DELETE` handle are unchanged. The old comment that folder pins denied reparse mutation was
half right: `FSCTL_SET_REPARSE_POINT` accepts `FILE_WRITE_ATTRIBUTES`, which takes no part in sharing,
or `FILE_WRITE_DATA` ([MS-FSA] 2.1.5.10.37), which a pin denying write sharing refused and a pin sharing
writes admits (the hardening below). A pinned folder keeps its identity because it cannot be renamed or
deleted and, kept non-empty by its retained child or witness, cannot become a junction. Logs, JUnit
reports and the RED tree are under `.runtime/transfer-pins/` of the fix clone (`builders/fix-transfer-pins`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| Folder pins denied write sharing, so other programs' renames and hard links into the pinned folders failed | `DesktopWindowsPinSharingTest` (transfer chain with a witness and the private folder, the installer's three input pin sets, the installer store's chain), `DesktopWindowsAdmissionPinSharingTest`, `DesktopWindowsVpnHelperAdmissionTest.imagesHelperAndManifestDenyWritersWhileTheirFoldersOnlyDenyDeletion` (`:desktopApp:test`); Windows-only: `DesktopWindowsTransferParentNativeTest` (three tests) and `DesktopWindowsInstallAdmissionNativeTest.admissionLetsOtherProgramsRenameIntoItsFoldersButKeepsItsImageFromWritersAndMoves` | `SharingVolume` judges every open as [MS-FSA] 2.1.5.1.2.2 does, the product's own through the real `windowsInstallOpenOptions`, and models a rename or link destination as Windows 11 opens it and a rename or deletion of a pinned object as an open with `DELETE` sharing everything. The tests require the destination admitted in every pinned folder, `DELETE` refused on every pinned folder, witness and private folder, a retained undeletable child in every pinned folder, and the running image refusing the readiness probe's write open. RED on `245b61a7`: 3 tests, 3 failures, each `refused by open(C:\, access=0, rights=0x120081, share=1)`. The admission tests need the fix's `openFile` and the `JnaWindowsInstallAdmission(pins)` seam, so their RED is the fix with the preserved unfixed mapping line (`INSPECT`) restored: 1 failure at `C:\`; and with the unfixed routing restored, images opened as folders: 2 failures. Mutants of the fix, each failing named tests: folder pins sharing delete (7), folder pins without `READ_DATA` (6), object pins sharing writes (3). GREEN: 62 focused Windows classes, 415 tests, 0 failures (96 Windows-only skipped on macOS). Native only: the OS behaviour itself, run by the Windows-only tests in the Windows package workflow's `:desktopApp:test`, and the document row on a package built from the fix. |
| The root control recorded a refused rename into the operation root and the row passed | `test_windows_document_fixture_holders.RootGateTests` (5 tests) | After a passed probe, `windows_document_native.root_rename_gate` journals the control (with the census of the root on a refusal as held) and `document-fixture-rename-gate`, whether the product's private transfer folder existed before and after it, and ends the row known with `document-race-root-rename-refused:<step>:<winerror>`, `document-race-root-control-failed:<step>:<code>` or `document-race-root-control-without-transfer`. The races stay in their stage folders. The world models the package that ran (folder pins share read) and the fix (read and write). RED on the `245b61a7` race and native module: 22 tests, 6 failures (5 tests, one with two subtests), on Python 3.14 and 3.12; the package that refused every rename into the root, and a row with no live transfer, both passed with exit 0. GREEN: 22 OK on both. Native only: the gate on a guest. |
| The native helpers' folder pins denied write sharing: while VPN mode was connected (the broker's admission), during an installation (the install helper) and for each runtime resource capture or publication (`PinParents`), other programs' renames and hard links into those folders failed | `DesktopWindowsNativeHelperPinSharingTest` (5 tests, `:desktopApp:test` on every platform); Windows-only: `DesktopWindowsNativeHelperPinSharingNativeTest` (`windows-native-pin-sharing-probe.ps1`) and the routing case of `windows-vpn-helper-admission-probe.cs` (`DesktopWindowsVpnHelperNativeAdmissionTest`, `PACKAGED_BROKER_ADMISSION_OK:17`) | There is no C# compiler on the Mac. The test reads each helper's C#, resolves the access, sharing and flags each `CreateFile` receives for the role of its call site (the admission's `PinAncestry` routing condition is evaluated per path element) and judges them with `SharingVolume`; every open compiled into the helpers that may name a folder (`FILE_FLAG_BACKUP_SEMANTICS`) must be one it judges. RED on the preserved `a3223603` sources with the final test bytes: 5 tests, 3 failures (install helper 20 problems, broker admission 6, resource folder chain 2), each a folder pin with `share=1` refusing renames and links into its folder; the broker's runtime pins and the completeness check pass on both. GREEN: 57 `DesktopWindows*` classes, 356 tests, 0 failures (95 Windows-only skipped). Nine mutants of the fix each fail the intended test: folder pins sharing delete or metadata-only, image pins sharing writes, the owner's image opened as a folder, the routing condition inverted, `PinParents` sharing delete, file reads sharing writes, the broker's runtime pins denying writers, an unjudged open that may name a folder. Native only: compilation (`csc.exe` and `Add-Type` in the Windows package workflow's `:desktopApp:test`, then the NativeAOT publish of `prepareWindowsNativeHelpers`), the OS behaviour, and a rename into the home folder of a per-user installation while VPN mode is connected. |
| `DesktopWindowsResourceAdmission`, the JVM twin of `PinParents`, pinned a resource's folder chain denying write sharing; the change above missed it because it calls `CreateFileW` directly | `DesktopWindowsPinSharingTest.aRuntimeResourceAdmissionLetsOtherProgramsRenameIntoItsFolderChain` | Its access and sharing are named (`FOLDER_PIN_ACCESS`, `FOLDER_PIN_SHARE`) and judged by `SharingVolume` over `C:\` to the workspace. RED: the fix with `a3223603`'s sharing value (1) restored, refused at `C:\` (`rights=0x81, share=1`). GREEN in the run above. Native only: the pins live only while a resource is admitted at VPN start. |

The native helpers took the same split afterwards (`builders/fix-native-pins`, logs under its
`.runtime/native-pins/`). Their folder pins also used `FILE_LIST_DIRECTORY` with read sharing only: the
elevated VPN broker's admission (`windows-vpn-helper-admission.cs`) holds every folder from `C:\` to its
owner's image and to its own image, and `C:\ProgramData`, for as long as VPN mode is connected, so renames
into the home folder of a per-user installation still failed then; the install helper held the
installation, `C:\ProgramData`, the installer store, `%LOCALAPPDATA%` with its ancestors and private input
folders, and its own image's ancestry while its original-user child started; the broker's
`windows-vpn-user-files.cs` `PinParents` held a runtime resource's folder chain for each capture and
publication. `VpnInstallNative.OpenDirectory` and `PinParents` now share read and write and never delete,
which also covers `PinNonEmptyAncestor`'s witness. The new `VpnInstallNative.OpenFile` keeps the old mode for
the broker admission's images (the owner's image, the image ending each admitted path, the broker's own
image): `PinAncestry` decides per element, and the owner's image stays the installer readiness probe's
fence. `OpenRead` (the install helper's own image, requests, packages, records), the private input deletion
handle, the private stage files and the broker's runtime `Pin` and `PinWitness`, which already shared
writes, are unchanged. No native pin relied on denied write sharing of a folder: the coordinator writes only
in the protected store, and every publication into a user folder creates its file exclusively and renames by
leaf without replacement, which opens no folder. The JVM's twin of `PinParents`,
`DesktopWindowsResourceAdmission` (missed by the change above), now shares writes as well.

The review of these changes (pins-security, confirmed by two skeptics) found the price of sharing writes
(`builders/fix-pins-hardening`, logs, JUnit reports and mutant overlays under its `.runtime/pins-hardening/`).
A pin that shares writes also admits another principal's `FILE_ADD_FILE` open of the folder, which is
`FILE_WRITE_DATA`, and `FSCTL_SET_REPARSE_POINT` accepts `FILE_WRITE_DATA` as it accepts
`FILE_WRITE_ATTRIBUTES`. The ancestor policies still took another principal's `FILE_ADD_FILE` for harmless
child creation and asked for a witness only for attribute or EA writes, and the last folder of a transfer pin
chain (the spool parent, an export's folder) holds no product child until the product creates one by path. A
local user granted `FILE_ADD_FILE` on an empty export folder (a drop box) or spool parent (`C:\Windows\Temp`
for a CLI run as SYSTEM) could make it a junction between the pins and the creation, and the transfer folder
or export partial was created, and the export published, in that user's folder; the share-read pins of
`529cc610` had refused that open. Two independent layers close it. `WindowsInstallTrust`,
`VpnInstallNative.ValidateSecurityDescriptor` and the VPN broker runtime's `VerifyDirectory` admit another
principal's `FILE_ADD_FILE`, attribute or EA writes on a pinned folder only beside a retained witness;
`FILE_ADD_SUBDIRECTORY` alone stays harmless (`C:\` grants it to Authenticated Users). A last folder that
grants them and keeps no witness fails closed (see the review below for which entries can be one), while
per-user folders (`%TEMP%`, `%LOCALAPPDATA%`, the home folder) grant no such right and keep their share-write
pins with no witness. And what the product creates by path in a pinned folder is proven by handle to be its child, the
folder still no reparse point, before it is used, or it is deleted and the operation fails:
`DesktopWindowsTransferPins.requireLinkedChild` after the private transfer folder and after an export's
partial, and `Linked` in the broker's runtime resource publication, whose `PinParents` checks no ACL. The
helpers' other creations are in folders no other principal can write (the installer store and job folders,
the broker's private stage, the original user's private input folder) or already prove their linkage
(`InspectLinkedAncestor`, the stage's final path). The review's second finding, `DesktopWindowsResourceAdmission`
denying write sharing, was fixed by `e0dcfcb9` on every folder it holds; it creates nothing by path.

The review of that hardening (three findings, `4dcad563`, logs under `.runtime/pins-hardening/followup/` of the same
clone) found the witness rule stricter than its tests and report said. A witness is opened like any product open
(`PINNED_DIRECTORY`: `READ_CONTROL`, `FILE_READ_DATA`, `FILE_READ_ATTRIBUTES`, `SYNCHRONIZE`) with no privilege
enabled, so an entry private to another user refuses it with 5: the files other users drop in a drop box are never a
witness. A drop box holding only such files was refused with the internal `Unpinned mutable transfer ancestor`, which
the GUI shows verbatim as the export's status, and only an empty one got the clear message. `SharingVolume` checked no
DACL for the product's own opens, so two tests retained another user's private entry and published the export beside
it, and neither message was asserted. The product still fails closed, as the hardening's brief asked: any last folder
that keeps no witness, empty or not, reports `Cannot use <folder>: other accounts can write to it and it holds nothing
you can open. Add a file of your own to it, or choose a folder only you can change.`, and an intermediate folder keeps
`Unpinned mutable transfer ancestor`. Open: letting an export's own partial, created by one `CREATE_NEW`, held without
delete sharing and proven linked, serve as the last folder's witness would let such exports succeed; that reverses the
brief's fail-closed decision and is the product's call. The message stays English like every pin and export failure,
which the GUI shows raw; typed, translated export failures would be their own change.

| Failure type | Regression | Notes |
| --- | --- | --- |
| Folder pins sharing writes let another principal granted `FILE_ADD_FILE` turn an empty pinned last folder (a transfer's spool parent, an export's folder) into a junction between the pins and the product's creation by path, which then landed in that principal's folder | `DesktopWindowsPinSharingTest` (`anotherUserCannotRedirectATransferOutOfAnEmptyPinnedFolderThroughAJunction`, `aFolderGrantingAnotherPrincipalAddFileIsPinnedOnlyWhileAWitnessKeepsItNonEmpty`, `aTransferFolderCreatedByPathIsProvenInsideThePinnedFolderOrDeleted`), `DesktopWindowsTransferPinsTest.aPrivateDirectoryCreatedOutsideThePinnedFolderIsDeletedAndRefused`, `DesktopWindowsInstallJobBackendTest.unrelatedAncestorChildCreationIsAllowedButProductDirectoryMutationIsNot`, `DesktopWindowsExportPinSharingTest` (3 tests); Windows-only: `DesktopWindowsPinnedFolderJunctionNativeTest` (3 tests) | `SharingVolume` models mount points: another principal's open with only the rights its DACL grants, `FSCTL_SET_REPARSE_POINT` with `FILE_WRITE_DATA` or `FILE_WRITE_ATTRIBUTES` on an empty folder, path resolution through mount points, and a hook as the product creates by path. The race is a drop box granting Users `0x1200AF` and an emptied `C:\Windows\Temp` (Users `0x100026`, the CLI as SYSTEM). RED on `480700c8`'s product bytes with the final test bytes (the two files that need the fix's `WindowsExportNative` seam set aside): 4 classes, 38 tests, 5 of these failures; the drop box race left the transfer folder in `C:\Users\mallory\hideout` while the product reported `C:\drop`. The export tests' RED is the fix with the policy and both linkage checks put back to `480700c8`'s behaviour: 34 tests, 8 failures, the export reporting success while `routing.json` was published in `C:\Users\mallory\hideout`. One layer removed at a time, each mutant fails its own tests while the race tests still pass through the other layer: `FILE_ADD_FILE` harmless again 3 failures (the witness rule, the trust policy, the drop box export's retained entry); no linkage after the private folder 2, after the export's partial 1; no recheck of the pinned folder 1; an unlinked folder kept 2. GREEN: 72 focused classes (`DesktopWindows*` and the export, transfer, endpoint, correlation and installer consumers), 473 tests, 0 failures (100 Windows-only skipped). Native only: a `FILE_WRITE_DATA` handle setting a mount point on an empty folder the product pins (32 under the old share-read pin, 145 once the folder holds an entry), `createDirectory` and an export racing a real junction, in the Windows package workflow's `:desktopApp:test`. |
| The native helpers' ancestor policies admitted another principal's `FILE_ADD_FILE` on a pinned folder without a witness, and the broker's runtime resource publication wrote its temporary, created by path in a folder `PinParents` holds sharing writes, before proving it was there | `DesktopWindowsNativeHelperPinSharingTest` (`theHelpersAdmitAnotherPrincipalsAddFileOnAPinnedFolderOnlyBesideANonEmptyWitness`, `aRuntimeResourcePublicationProvesItsTemporaryIsInThePinnedFolderBeforeWritingIt`); Windows-only: the `Linked` case of `windows-native-pin-sharing-probe.ps1` (`DesktopWindowsNativeHelperPinSharingNativeTest`) | No C# compiler on the Mac: the test evaluates both policies' ancestor rights with and without a witness, and reads `Publish` and `Linked`. RED on `480700c8`'s C# sources: 2 failures in that class (both policies admit `FILE_ADD_FILE` without a witness; `Publish` proves nothing); the same with those sources as a classpath overlay of the compiled test. Six source mutants, each failing the intended test once: either policy admitting `FILE_ADD_FILE` without a witness, the broker refusing it beside one (`C:\ProgramData`), `Publish` without `Linked`, `Linked` keeping the child or skipping the folder's recheck. `windows-install-native.cs` changed by one character: its compressed command lines keep 29224 (LF) and 29272 (CRLF) of 30000 characters. Native only: compilation and the probe's junction case in the Windows package workflow. |
| A last folder others may write that held only entries the user's token cannot open (other users' private files in a drop box) was refused with the internal ancestor message; the model let the product open any entry, so the tests and the report said the operation went on beside such an entry, and neither refusal message was asserted | `DesktopWindowsPinSharingTest.aLastFolderHoldingOnlyEntriesTheUserCannotOpenIsRefusedWithAClearMessage` and the message of `aFolderGrantingAnotherPrincipalAddFileIsPinnedOnlyWhileAWitnessKeepsItNonEmpty`, `DesktopWindowsExportPinSharingTest` (`anExportIntoAFolderOthersMayWriteIsRefusedWithAClearMessageWhenItHoldsNothingTheUserCanOpen`, and `anExportIntoADropBoxHoldingAFileOfTheUsersStaysInThePinnedFolder`, which replaces the export test that retained another user's entry); Windows-only: `DesktopWindowsPinnedFolderJunctionNativeTest.nativeFolderOthersMayWriteIsUsedOnlyBesideAnEntryTheUserCanOpen` | `SharingVolume` judges every open of an existing object, the product's included, with its token's access check: the owner's implicit rights, the DACL in order, `FILE_READ_ATTRIBUTES` and `DELETE` through the folder. Witness fixtures are entries the token can open (the user's own file; in `C:\Windows\Temp` one inheriting SYSTEM's full control); the installer store test runs elevated and the admission test's `C:\ProgramData` grants Users read, as Windows ships it. RED on `814c50aa`'s product with the final tests: 7 classes, 48 tests, 3 failures (that drop box as a transfer and as an export, `but was: Unpinned mutable transfer ancestor`; the empty folder's old wording); with only `814c50aa`'s condition kept under the new wording, the 2 behavioural failures. `814c50aa`'s own tests with only the access check added: 45 tests, 4 failures (both witness tests `Unpinned mutable transfer ancestor`, the installer store and admission fixtures 5). Mutants of the fix, judged by the new tests: the ancestor message always, `last` inverted and `last` as the first component fail 3 each, `last` always 1; the first three applied to `814c50aa` pass all 45 of its tests. GREEN: 72 focused classes, 476 tests, 0 failures (101 Windows-only skipped). Native only: the witness open's 5 on an entry only another SID may read, the message and the user's own file retained, in the Windows package workflow's `:desktopApp:test`. |

### Windows region capture, review of the offline build (2026-11-13)

The review wave of 2026-11-13 (`.runtime/windows-parity-20261107/evidence/review-wave-1113/workflow-result.json`,
dimension `capture-and-ssh`) confirmed two defects in the region capture of `8a5602e3` (branch
`region-capture`, integrated as `62507b1e`). Both were found by reading; nothing here has run
natively. They were fixed offline in the clone `builders/fix-capture-review` on branch
`capture-fixes` (`051fc195`, `96f17932`). The unfixed sources are kept in
`.runtime/windows-parity-20261107/evidence/capture-fixes/before/`. RED ran the final
`NativeRegionCaptureTest` against the four production files of `8a5602e3` (`NativeRegionCapture.kt`,
`NativeRegionCaptureEngine.kt`, `WindowsRegionDesktop.kt`, `DesktopNativeVisualCaptureTest.kt`) with
one compile shim: the test's named `enabled =` arguments of `NativeControl` are dropped, because the
unfixed census has no enabled flag (its glue read `IsWindowVisible` only). RED: 36 tests, 6 failures,
exactly the six new ones; the 30 earlier tests pass on the unfixed engine with the new fixture. A
second RED against `051fc195` (the first fix alone, no shim) failed only the three rerun regressions.
GREEN on the fix: `NativeRegionCaptureTest` 36 and `DesktopNativeVisualCaptureTest` 2, no failure.
Both run in ordinary `:desktopApp:test`. Scripts, logs and JUnit reports are in
`.runtime/windows-parity-20261107/evidence/capture-fixes/`. The earlier regressions of the
region-capture series have no rows here yet; their RED and GREEN are in
`.runtime/windows-parity-20261107/evidence/region-capture/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The installer readiness gate accepted WixUI's PrepareDlg | `NativeRegionCaptureTest.aStablePreparingWizardPageIsRefusedInsteadOfPublishedAsTheInstaller`, `theWelcomePageThatReplacesThePreparingPageIsPublished`, `aWizardPageWhoseNextIsDisabledFailsTheReadinessGate` | With `dirChooser = true` jpackage uses WixUI_InstallDir, which shows PrepareDlg before the Welcome page. It is titled `[ProductName] Setup` and shows the same visible Back, Next and Cancel, with Back and Next disabled while the installer costs. `NativeControl` had no enabled flag and `ControlRule.matches` compared class, caption and visibility, so the target rule (the started `msiexec` pid plus ` Setup`) and the readiness gate before the stable-frame loop and before publishing accepted it, and its static page gave the first stable, painted pair: `windows-msi` and `windows-update-installer` could publish the "please wait" page, or refuse once it closed under the capture. The census now records `IsWindowEnabled`, the wizard's Next must be enabled, and `placeWindow` waits past a window that lacks its role's controls (`awaitTarget` takes an `unready` reason), so the Welcome page, which MSI creates as a new window, is the one placed and published. A last census that still shows such a page refuses `target-controls-missing`, and its detail marks hidden and disabled controls. `FakeDesktop` models PrepareDlg replaced by the Welcome page after a number of censuses. RED on `8a5602e3`: the stable PrepareDlg and the page handed straight to `capture()` were published ("completed successfully"), and the replaced one was refused `target-missing` once PrepareDlg closed under the capture. GREEN: the stable PrepareDlg is refused at location with its own frame and is never placed, the Welcome page `0x2A` is published, and the gate refuses a disabled Next before the stable-frame loop. Native only: the `IsWindowEnabled` glue, the WiX captions, and how long PrepareDlg shows on a VM or hosted runner. |
| A rerun kept an earlier run's refusal and evidence | `NativeRegionCaptureTest.aRerunRefusedBeforeCaptureRecordsItsOwnReasonAndFrame`, `aRefusalIsRecordedUnlessThisRunAlreadyRecordedIt`, `aSceneKeepsNoEvidenceOfAnEarlierRunBesideItsNewOutcome` | `recordRefusal` wrote a refusal raised before `capture()` only when `<scene>.refusal.json` was absent, taking an existing file for one that `capture()` had written in this run. Nothing clears the output between runs: `captureRequestedNativeScenes`, `capture_visual_desktop.ps1` and `visual_platform.run_local_driver` only create it. So a rerun refused before capture kept the earlier run's reason and frame, a scene published on a rerun kept its earlier refusal beside the image, and one refused on a rerun kept the earlier image and region record. A refusal now carries `recorded`, set once its record and frame are written, and `recordRefusal` checks that flag. `runRegionCaptureScenes` removes a requested scene's `.png`, `.frame.png`, `.region.json` and `.refusal.json` before the scene runs, and before a session refusal names `capture-session.frame.png`; the files of scenes the run does not request stay. RED on `8a5602e3` and on `051fc195`: the rerun kept `outside-work-area` instead of its own `target-missing`, the engine kept an earlier `occluded` record instead of `target-ambiguous`, and the published rerun kept its earlier refusal. GREEN: each holds, a refused rerun keeps no earlier image or record, and a session refusal keeps no earlier scene frame. Hosted jobs start from a fresh checkout and were not affected. |

### First native no-tray close row: the GUI hid into a tray its desktop did not have (product, from 6c7250f6, 2026-11-13)

`windows-proxy-lifecycle.no-tray-close`, direct operation `6c7250f6` on the 2.2.17 package of `f31ab987`,
ended exit 1 through its known-failure closing (`dedicated-proxy-lifecycle-known-failure`, event 146) with
`gui-hidden-without-usable-tray` at stage `decision-probe`. The evidence is kept unchanged at
`.runtime/windows-scenarios/6c7250f6-7fc6-4c3f-ab0f-42a5ef1c1bef/evidence-1.zip`. The row worked up to its
decision: the GUI started on the owned desktop through `CreateProcessW` (events 102 and 103), its relaunched JVM
showed its main window there and nothing of it on Default (event 104). That desktop has no `Shell_TrayWnd`, yet the
JVM's windows there included AWT's `SunAwtTrayIcon` message window and a hidden 136x39 `SunAwtFrame`, the tray
peer's popup parent: AWT had taken the icon. After the 75 s settle `gui hide` answered OK with exit 0 (event 112) and
the main window was hidden (event 113): a live GUI with no window and no tray icon. The census of Default in
event 104 found no `Shell_TrayWnd` there either (no tray host among 69 windows).

Cause, product. `AwtTrayRegistrationTarget.install` took an icon that `SystemTray.add` accepted and
`getTrayIcons` listed for installed, and `AwtTrayHandle.installTrayIcon` marked every tray but Linux's available
at once, so `canHideToTray` turned true at the first attempt; `Main.kt`'s close and `gui hide` read nothing else.
`DesktopTray.kt` of `f31ab987` and `450b8764` are byte-identical, and `Main.kt` differs only in colours. Cause,
JDK 17, the bundled runtime: `SystemTray.isSupported` is the toolkit's `isTraySupported`, which `WToolkit` answers
true, and `SystemTray.add` fails only when `TrayIcon.addNotify` throws (`java/awt/SystemTray.java` lines 212 to 279
and `java/awt/TrayIcon.java` lines 695 to 709 of the local JDK 17.0.20.1 `src.zip`). `WTrayIconPeer`'s native
`create` (`awt_TrayIcon.cpp`, `AwtTrayIcon::Create`) sends `NIM_ADD` through `SendTrayMessage`, which returns
`Shell_NotifyIcon`'s BOOL, and drops it; `Shell_NotifyIcon` hands an icon to the `Shell_TrayWnd` window of the
caller's desktop and fails where there is none. The Windows sources are cited from OpenJDK
(`src/java.desktop/windows/`), with no local copy on this Mac; the run shows the behaviour they describe. The JDK
does read `TaskbarCreated`: `AwtTrayIcon::WmTaskbarCreated` adds every icon again when a new Explorer starts.
Linux has no such gap: X11 `isTraySupported` needs a `_NET_SYSTEM_TRAY_S<n>` owner, `XSystemTrayPeer.addTrayIcon`
throws without one, and the product waits for AWT's embedded frame to show (PLATFORM-006); the native Linux
backend keeps dorkbox's own detection, and macOS always has its status bar. Neither changed.

Fix. `WindowsNotificationArea` asks `FindWindowW` for `Shell_TrayWnd`, which searches the calling thread's
desktop, and every thread of the GUI is on the desktop it started on. On Windows `NotificationAreaTrayRegistration`
reads that window every second until it exists, without limit and reporting nothing meanwhile (the window stays
visible, a close detaches, `gui hide` is refused), and offers the icon at the first read that finds it; only AWT's
refusals count towards the 60 attempts a second apart (`unavailable` at the last). Once the icon is in it reads the
window every second again: the tray is lost while it is gone, which shows a hidden window (`withTrayLost`), and
available again once it is back, when AWT has added its icon again. The close and `gui hide` ask for it at that moment
too (`DesktopTrayWindow.closeToTray` and `guiVisibility`, through `canHideToTrayNow`): without it a close detaches and
`gui hide` answers UNSUPPORTED. The availability decision of every platform now lives in `AwtTrayRegistration`, and
`AwtTrayHandle.installTrayIcon` only starts Linux's visibility monitor. The answer to the icon itself, the BOOL AWT
drops, is still not read: `Shell_NotifyIconGetRect` needs `TrayIcon.id`, package-private, which the packaged JVM
cannot read without opening `java.awt`, and its launcher configuration is pinned by tools. `TaskbarCreated` is not
received by the product either; the one-second read sees the new taskbar instead, and AWT's own window takes the
message. DESKTOP-002 now states the Windows rule. Logs, JUnit reports and the RED patch are under
`.runtime/tray-detection/` of the fix clone (`builders/fix-tray-detection`) and in
`.runtime/windows-parity-20261107/evidence/tray-detection/` of the recovery checkout, with the beforeimages of both
Kotlin files and of the world's test module.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A Windows tray was taken for usable because AWT accepted its icon, so `gui hide` and a close hid the only window on a desktop with no notification area | `DesktopTrayNotificationAreaTest` (`:desktopApp:test`): `aGuiOnADesktopWithoutANotificationAreaNeverHidesItsWindowAndItsCloseDetaches`, `anAutostartedGuiStaysVisibleUntilTheNotificationAreaExistsAndHidesOnlyThen`, `aCloseOrAGuiHideReadsTheNotificationAreaAtThatMoment`, and `DesktopTrayWindowStateTest.closeOrHideNeedsTheTrayHostAtThatMoment`; controls `aDesktopWithANotificationAreaHasItsTrayAtTheFirstAttempt`, `anIconRefusedWhileTheNotificationAreaExistsEndsUnavailableAfterTheLastAttempt`, `stoppingTheTrayStopsTheWatchAndRemovesTheIcon`, `onMacOsTheIconAwtTakesIsTheTrayWhateverTheWindowsAreaSays`, `onLinuxTheRegistrationLeavesTheDecisionToTheVisibilityMonitor`, `DesktopTrayWindowStateTest.onlyWindowsAsksTheNotificationArea`; Windows-only `DesktopTrayNotificationAreaNativeTest` (3) | The world is that desktop on a virtual clock: AWT takes and lists every icon and the notification area is a switch. Everything between them and the window is the product's: `startDesktopTray` (DesktopTrayIcon's effect) with the installer, the AWT backend's `AwtTrayRegistration` and `DesktopTrayAvailability` (java.awt.SystemTray and Swing's timers replaced), and `Main.kt`'s `DesktopTrayWindow`, whose `closeToTray` and `guiVisibility` DesktopApplication's close and `gui hide` handlers call. The decisive test asks, every second of the row's 75 s settle, what `gui hide` and a close do. RED on the decision of `450b8764` itself: a seams-only tree, `450b8764` with those entry points added and its own decision moved into them unchanged (every platform but Linux available once AWT takes the icon; the close and `gui hide` read `canHideToTray` alone; no host asked, no lost report), made by `make_seams_only.py` from the fix by removing every part of it (diffs against `450b8764` kept as `seams-only-*.diff`): `DesktopTray*`, 38 tests, 5 failures, the decisive one `expected:<[]> but was:<[0, 1, 2, ... 75]>`. GREEN on the fix: 44 tests, 0 failures, 3 skipped (the native class). The first RED, the fix with the decision restored in its own new code (`red-unfixed-decision.patch`, 40 tests, 5 failures), is superseded: it could not fail on the decision of `450b8764`. The native class runs in the Windows package workflow's `:desktopApp:test`: on a private desktop of its own, `WindowsNotificationArea` must find nothing while a census of this thread's desktop agrees with it, and the product's AWT backend in a child JVM started there with `lpDesktop` must report nothing within 10 s (it waits for an area) with no AWT icon offered; started on the session's desktop it must be available exactly when that desktop has `Shell_TrayWnd`. Native only: a package built from the fix on the no-tray row, below. |
| A notification area that appeared more than a minute after the GUI started was never used: the absent area spent the 60 attempts, the tray was reported unavailable and left the composition for the session (found in review, not met natively; an autostart ONLOGON task does not wait for Explorer) | `DesktopTrayNotificationAreaTest.aNotificationAreaThatAppearsLongAfterTheGuiStartedStillGetsTheTray`, and `aGuiOnADesktopWithoutANotificationAreaNeverHidesItsWindowAndItsCloseDetaches` now also requiring no report and the area still read | RED on the first fix (`46e2ff09` with only the tests changed): 41 tests, 2 failures, both `expected:<[]> but was:<[(59000, unavailable)]>`. GREEN: 41 tests, 0 failures, 3 skipped. Native only: Explorer starting after an autostarted GUI. |
| A window hidden in the tray stayed hidden after the notification area went away (Explorer ended or is restarting): predicted from the same cause, not met natively | `DesktopTrayNotificationAreaTest.aWindowHiddenInTheTrayIsShownWhenTheNotificationAreaGoesAwayAndTheTrayComesBackWithIt`, `DesktopTrayBackendTest.everyBackendReportReachesTheWindowOnTheEventThreadUntilTheTrayStops`, `DesktopTrayWindowStateTest.lostTrayShowsTheWindowAndComesBackWithoutHidingIt` | Before the fix nothing read the tray again after the first attempt. RED: the seams-only run above (the first test). Each link of the lost report broken alone on the fix (`lost_mutants.py`): `DesktopTrayWindow.onTrayLost` ignoring it, `AwtTrayRegistration` dropping it or passing it as unavailable, `DesktopTrayAvailability.markLost` never reporting, `startDesktopTray` dropping it: each 44 tests with 1 failure (2 for the last). `DesktopTrayIcon` now takes the window's `DesktopTrayEvents` with no default, so `Main.kt` cannot leave a report out. Not covered by a JVM test: `AwtTrayBackend.install` handing its `onLost` to `AwtTrayRegistration` (AWT only). GREEN: all pass. Native only: an Explorer restart under a hidden GUI; nothing here ends Explorer. |

The offline world of `test_windows_no_tray_close` reads the product's decision from the source, so it was
reviewed with it: `tray_rules()` now requires the Windows rule (`Shell_TrayWnd`, the gate, the watch, `installTrayIcon`
leaving Windows alone) and the world's `Main.kt` facts the moment check; AWT taking the icon is the default answer of
the JDK switch, as the run saw it, and the decision of 2.2.17 stays the product switch `tray_decision = "awt-list"`
for the oracle's controls, whose first control now also checks the run's decision answer (OK, exit 0). Three new row
tests pass the row whatever AWT answers. On an isolated tree holding the fix's tools, Python 3.14 and 3.12 alike: the
new module on the `450b8764` Kotlin files `Ran 32 tests`, `FAILED (failures=28)`: 27 `the tray decision is not where
the fake GUI reads it` and the close's regex; on the fix's, OK. The `450b8764` module passes 29 on its own sources
and fails 25 on the fix's, which is the review this change made. `windows_no_tray_desktop.py` is unchanged, so no pin
moved; its docstring still describes the decision of 2.2.17.

What the next direct discovery run of `windows-proxy-lifecycle.no-tray-close` must show on a package built from
this fix: `no-tray-gui-desktop-observed` as in `6c7250f6`, but the private desktop lists no `SunAwtTrayIcon` window
and no hidden 136x39 `SunAwtFrame`, since no icon is offered there; the main window visible at every settle
observation; no `no-tray-decision-probe-answer` (the probe got UNSUPPORTED, exit 1, and left the window visible);
`no-tray-wm-close-posted` with `posted` true, the GUI terminal exit 0 with both EOFs within 30 s, `no-tray-lease-read`
NOT_FOUND with `secondsFromPost` under 9, the JVM's exit observed, the desktop empty, status, actors and the one
runtime unchanged, and `no-tray-close-detach-observed`, the row closing through its own off and quit with exit 0. The
same run's census found no `Shell_TrayWnd` on Default either. On such a session the fixed product also has no tray
on Default: `gui-pending`'s `hide` and `wm-close-to-tray` steps, which passed in `90dd6d45` on 2.2.16, would then get
UNSUPPORTED and a detach. Those steps need Explorer's taskbar on the fixture session's Default desktop, which no row
records yet.

### SSH Routing bootstrap files left after a refresh (product and harness, from 584d9f4c, 2026-11-13)

The first direct run of `windows-disconnected-cli-config.ssh-relay-transfer`, `584d9f4c` on package
2.2.17, ended known failure `bootstrap-files-left` right after its first HOME_RELAY refresh answered
`OK` with one location: events 237-248 of
`.runtime/windows-scenarios/584d9f4c-20c1-4e10-a485-4ae5f2c2b535/evidence-1.zip` (sha256
`1f87b003…`). The check ran after the `subscriptions list` that followed the reply (the list child
started 9.0 s after the refresh child, the next status child 2.4 s after it), so the files outlived
the product's final reply by at least a second; the serve quit with exit 0 and its stderr holds only
the JVM options notice and the readiness line. The evidence names no file. On 450b8764 `DesktopHomeSshBootstrapProxy.useProxy`
created `home-ssh-bootstrap-*.json` and `.log` in the runtime folder before it resolved sing-box and
outside its `try`, sent sing-box's output to the log, and in `finally` called `destroy()`,
`waitFor(2 s)` and, on a timeout, `destroyForcibly()` without waiting, then one
`Files.deleteIfExists` per file inside `runCatching`. The causes, read from the code and the
platform (the evidence cannot say which held): the log is the child's stdout and stderr through a
handle the JVM opens sharing read and write only, so Windows refuses its deletion while any process
holds it; the JDK's timed `waitFor`, `isAlive` and `onExit` answer from `GetExitCodeProcess`, and
by the kernel's order of process exit the exit code can be set before the child's handles are closed
(inferred, not observed; only the untimed `waitFor` waits for the process object), and after
`destroyForcibly()` nothing waited; a scanner may open a file just written or closed; and whatever
refused that one attempt, the refusal was swallowed and never retried, so the files stayed.
Separately, on every platform a missing sing-box left two empty files. The configuration names the
key by path (`private_key_path`) and holds no key material; it does hold the relay's host, port,
user and pinned host keys. sing-box starts no child process for this configuration (its ssh outbound
is Go code), so inheritance into a grandchild is not a cause.

The bootstrap (`DesktopHomeSshBootstrapProxy.kt`) now resolves sing-box before it creates a file,
discards sing-box's output (no log file), deletes the configuration as soon as sing-box listens and,
with `DesktopBootstrapCleanup`, waits for the child's process object (the untimed `waitFor` on a
daemon thread, at most 5 s after the stop) before it deletes, and retries, eight times over 3.2 s, a
deletion the file system refuses (`FileSystemException`, which carries Windows' sharing violation and
access denied) or whose name is still listed afterwards (a delete-pending name on a volume without
POSIX delete semantics). Whatever still fails is one line on the owner's stderr (the serve's stderr,
`headless.log` of an owner a CLI started) naming the file's leaf and the refusal, never a folder or
the contents. The configuration stays owner-only on POSIX (`Files.createTempFile`); on Windows it
keeps the profile's inherited ACL like the runtime's other configurations, since it holds no key.
Android was checked (PRODUCT-002): its bootstrap already sends sing-box's output to `/dev/null` and
writes its configuration to the app's private cache, where an open file never blocks an unlink, so
the cause cannot occur there; it still creates the file before `SingBoxInstaller.resolveBinary`
(a missing bundled library would leave one empty file) and ignores `delete()`'s result, recorded
here as unchanged. The desktop direct-probe proxy (`DesktopDirectProbeProxy`) and the Find Best
candidate runtime (`DesktopProxyValidationRuntime.benchmarkCandidate`) had the same pattern, worse
in the candidate: it created `validate-<remarks>-<n>.json`, which holds the candidate's
credentials, and its `.log` before it resolved sing-box and prepared the probe copy, outside its
`try`, so `sing_box_missing` and `probe_binary_failed` returned with both files left, with no
report and no later sweep (review of `1fe2ddab`). No native run has shown it; it is fixed with
the same parts below.

The row's `leftovers()` still fails at the first look after the reply: the product deletes before
the download returns and the bootstrap exists only for that one download while no runtime is active
(CONFIG-004's direct exception; an active runtime's management inbound carries it, CONFIG-005), so a
settle before the verdict would pass a product that answers before its cleanup ends. Only after the
verdict, `bootstrap_left` settles for at most 10 s and records `ssh-relay-bootstrap-leftovers`: each
left file's name, size and age by `lstat` and its hold, at the verdict and after the settle, the
live runtimes under the workspace, the settle's actual length, and the offset at which a held
file became free (`freedAfterSeconds`) or a name went away (`goneAfterSeconds`). A census that
fails keeps the verdict. The first form of this settle (`1fe2ddab`) recorded only whether the
files were still listed, and its key read "gone after the settle: a scanner past 3.2 s; still
there: a holder that never let go". Both readings were wrong for a refused deletion: nothing in
the product deletes the file again, so it stays listed whether its holder let go a moment after
the product's last retry or never did, and with POSIX delete semantics it cannot go away. The
hold tells them apart: an open for DELETE access alone sharing read, write and delete, not
following a reparse point, closed at once and never given a delete disposition, answers `held`
(a sharing violation: a holder without `FILE_SHARE_DELETE`), `denied` (access denied: a
delete-pending name or an ACL), `free` or `gone`; off Windows `unprobed`. `held` then `free` with
`freedAfterSeconds` t: a holder let go t s after the verdict, so the product's retry bound was too
short; `held` at both looks: a holder that never let go within 10 s (with `runtimes` 1, the
bootstrap's own sing-box); `free` at the verdict: nothing held it when judged (no retry, a package
before the fix, or a holder gone between the last retry and the verdict); a name in
`goneAfterSeconds`: a delete-pending name whose last handle closed.

Two more gaps of the fix's first form (`1fe2ddab`), from its review. The bootstrap was cleaned up
only by its owner's own `finally`: an owner ended any other way (SIGTERM, End task or
`taskkill /F`, SIGKILL, a crash) left its sing-box running with an authenticated SSH session
behind a loopback mixed inbound without users, which any local process could use as an egress
through the user's SSH Routing server, and before readiness also left the configuration; no
owner start ended or removed either, nor the files packages 2.2.17 and 2.2.18 already left. Each
short-lived sing-box of the owner (the SSH Routing bootstrap, a Find Best candidate, the direct
probe) is now a
`DesktopShortLivedRuntime`: registered with `DesktopShortLivedRuntimes` before its first file
exists, so one JVM shutdown hook ends every live child and removes its files and admits no new
one, and finished once, whoever comes first (the hook waits for a `finish` under way). On Windows
the child is put in a job of its own with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` right after it
starts (`tieToOwnerLifetime`, `DesktopWindowsNativeJob.assign`), so the kernel ends it when the
owner's last handle to the job closes, which an End task or `taskkill /F` does; a child that cannot
be tied is reported on stderr and still carries its download. At owner start, under the
single-instance lock (`DesktopAppServiceFactory.default`), `reapShortLivedRuntimesAtOwnerStart`
ends each sing-box of the same user whose arguments are `run -c <folder>/<prefix>*.json` in the
runtime folder (`home-ssh-bootstrap-`) or the validation folder (`validate-`, `direct-probe-`),
which Linux and macOS report, then removes those files (the pre-fix `.log` too) with the bounded
retries, one stderr line per process by pid and per file by leaf. It never matches the main
runtime's `runtime-sing-box-*.json` or `candidate-*` names. A Windows orphan of a package before
this fix is not found by its arguments (the JDK reports none there); its files are still removed.
The candidate and the direct probe now resolve sing-box and prepare the probe copy before any
file, discard sing-box's output, delete the configuration once sing-box listens, and end and
clean up through `DesktopBootstrapCleanup` labelled `Find Best validation` and `Direct probe`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The bootstrap deleted each file once, at once, and swallowed a refusal, so a file the OS still held after the child was told to end stayed | `DesktopHomeSshBootstrapCleanupTest` (`:desktopApp:test`, POSIX): `deletionsRefusedUntilShortlyAfterTheBootstrapEndedLeaveNoBootstrapFile`, `aBootstrapThatIgnoresTerminationIsKilledAndAwaitedBeforeItsFilesAreDeleted`; `DesktopBootstrapCleanupTest` (14 cleanup decisions over fake processes and file systems, all platforms); Windows-only `DesktopHomeSshBootstrapCleanupNativeTest` | The first two drive the public download client with a stand-in sing-box that makes the runtime folder read-only until 0.4 s after it is gone, while the test answers the download as its proxy. RED on `450b8764`, which this public-API class compiles against unchanged (`:desktopApp:test`, the class alone: 4 tests, 4 failures): in these two the `.json` and the `.log` were both left once the download returned, for a child that ended at the request and for one killed after the 2 s grace. GREEN on the fix: 4 of 4; `DesktopBootstrapCleanupTest` 14 of 14 (refusals and still-listed names retried eight times over 3.2 s, the process object awaited although the exit code was set at the request, a kill after the grace, a child past the bound reported, reports without folder or contents); 25 tests in seven neighbouring classes (`DesktopLoopbackListenerTest`, the SSH key and persistence tests, the subscription service, refresh and CLI tests); the four Windows-only tests skip on macOS. Eight loosenings of the fix each turn named tests red: no retry (8 tests), a wait by the exit code instead of the process object (4), a kept log (4), no early deletion (2), files created before the resolve (1), reports dropped (4), no listing check after a deletion (2), no kill after the grace (2). |
| A missing sing-box left two empty bootstrap files | `DesktopHomeSshBootstrapCleanupTest.aMissingSingBoxLeavesNoBootstrapFile` (all platforms) | RED on `450b8764` in the same run: an empty `.json` and `.log` left. GREEN: none. |
| The configuration lived, and the log existed, for the whole download | `DesktopHomeSshBootstrapCleanupTest.theConfigurationIsGoneOnceTheBootstrapListensAndNoLogIsWritten`, `DesktopBootstrapCleanupTest.theBootstrapRuntimeKeepsNoOutputOnDisk` | Also pins that the configuration names the key by path, holds no key line and is `rw-------` on POSIX (true on both trees). RED on `450b8764` in the same run: both files present while the download ran. GREEN: none. |
| `bootstrap-files-left` named no file and said nothing of its age, of a bootstrap still running or of a later release | `test_windows_ssh_relay_cases.CaseTests`: `test_left_bootstrap_files_are_named_sized_and_aged_and_the_row_fails`, `test_files_a_holder_lets_go_of_after_the_first_look_still_fail_the_row`, `test_a_bootstrap_process_left_with_its_files_is_counted_beside_them`, `test_a_census_that_fails_while_describing_keeps_the_verdict`, `test_the_description_holds_metadata_only` | RED on `450b8764`'s module with the final test bytes in an isolated `git archive` tree, Python 3.14 and 3.12 alike: `Ran 15 tests`, `FAILED (failures=5)`, each `one description of the bootstrap files left` (none was recorded); the ten earlier tests pass. GREEN: 15 OK on both. Three loosenings each turn named tests red: a settle before the verdict (5, among them the holder that lets go after the first look), no census (3), a census error that escapes (5). |
| The settle after the verdict could not tell a holder that let go from one that never did (review of `1fe2ddab`) | `test_windows_ssh_relay_cases.CaseTests`: `test_a_holder_that_lets_go_during_the_settle_is_told_from_one_that_never_does`, `test_a_holder_that_never_lets_go_stays_held_at_both_looks`, `test_a_file_nothing_held_when_judged_is_free_at_the_verdict`, `test_the_hold_is_asked_by_an_open_for_delete_alone_that_is_closed_at_once`; updated `test_left_bootstrap_files_are_named_sized_and_aged_and_the_row_fails`, `test_files_a_holder_lets_go_of_after_the_first_look_still_fail_the_row`, `test_the_description_holds_metadata_only` | The world answers each hold through the module's `HOLD` seam; the Win32 open is checked against a fake kernel (DELETE alone, every share mode, `OPEN_EXISTING`, `FILE_FLAG_OPEN_REPARSE_POINT`, closed at once; error 32 `held`, 5 `denied`, 2 and 3 `gone`). RED on `1fe2ddab`'s module with the final test bytes in an isolated `git archive` tree, Python 3.14 and 3.12 alike: `Ran 19 tests`, `FAILED (failures=6, errors=1)` (no `hold` in a row, no `freedAfterSeconds` or `goneAfterSeconds`, no `_windows_hold`); the twelve other tests pass. GREEN: 19 OK on both; `SshRelayFamilyTests` and `test_native_scenario_bundle` 18 OK on both. |
| The SSH Routing bootstrap outlived an owner ended without its `finally`, and no owner start ended it or removed its configuration (review of `1fe2ddab`) | `DesktopHomeSshBootstrapOwnerEndTest` (`:desktopApp:test`, POSIX): `anOwnerShutDownBeforeTheBootstrapListensEndsItAndRemovesItsConfiguration`, `anOwnerShutDownDuringTheDownloadEndsTheBootstrap`, `theNextOwnerStartEndsABootstrapAKilledOwnerLeftAndRemovesItsConfiguration`; `DesktopShortLivedRuntimeTest` (6 seam tests, all platforms); Windows-only `DesktopHomeSshBootstrapCleanupNativeTest.nativeAnOwnerEndedByTerminateProcessTakesItsTiedBootstrapChildWithIt` | A child JVM is the owner: it refreshes through the public download client with a stand-in sing-box that reports its pid and port, and the test sends it SIGTERM before readiness or while it holds the download's request, or SIGKILL and then starts a second child JVM through `DesktopAppServiceFactory.default()` under that workspace. RED on `1fe2ddab` (production sources and the native test as there, `DesktopShortLivedRuntimeTest` set aside; this class compiles against them unchanged): 3 of 3 fail, `the bootstrap's sing-box still ran` after each shutdown and after the next owner start. GREEN: 3 of 3, the next owner's stderr naming the pid it ended and the leaf it removed. The seam tests pin one hook for every live runtime and no admission after it, one finish whoever comes first with the tie closed after the child, a tie refusal reported, and a reaper that ends only `run -c <folder>/<prefix>*.json` of the same user (not the main runtime's `runtime-sing-box-*.json`, `candidate-*`, another folder, a `.log`, `check`, another user or itself) and removes only prefixed regular files, the pre-fix `.log` among them. |
| The Find Best candidate left its credential-bearing configuration and log when sing-box or the probe copy was missing, kept the log redirect and swallowed a refused deletion; the direct probe the same (review of `1fe2ddab`) | `DesktopValidationRuntimeCleanupTest` (`:desktopApp:test`): `aFindBestCandidateWithoutSingBoxLeavesNoCredentialFile`, `aFindBestCandidateWhoseProbeCopyFailsLeavesNoCredentialFile`, `theDirectProbeWithoutSingBoxLeavesNoFile` (all platforms), `aFindBestCandidateKeepsNoLogAndRemovesItsFilesOnceRefusalsEnd` (POSIX) | Public validation runtime and direct probe; the last uses a stand-in that lists the folder when it starts, makes it read-only until 0.4 s after it is gone and never listens. RED on `1fe2ddab` in the same run: 4 of 4 fail, each with a `validate-fixture-*.json` and `.log` (or `direct-probe-*`) left, the stand-in seeing the log beside the configuration. GREEN: 4 of 4. The focused GREEN run on the final sources: 86 tests in 19 classes, 0 failures, 5 skipped (the Windows-only native tests). |

Native only: Windows' refusal itself and its timing (sharing violation, exit code before the
handles close, a scanner), shown by the Windows-only tests in the Windows package workflow's
`:desktopApp:test` and by the row. The next direct discovery run on a package built from this
fix must end with all six groups complete and no known failure; the serve's stderr must hold
no `SSH Routing bootstrap:` line; and if a file is left again, `ssh-relay-bootstrap-leftovers`
names it with its hold at both looks, the runtimes and `freedAfterSeconds`, before
`known-failure-closing`. Also native only: the job tie (End task or `taskkill /F` ending the
child, the Windows-only test above), and the owner-start reaper on Linux (`/proc` arguments; the
POSIX tests ran on macOS). Routine suites: `:desktopApp:test` in
Fast Checks and every desktop package workflow, and `test_windows_ssh_relay_cases` in the affected
agent tier. Logs, JUnit reports, the mutant summary and the beforeimages are under
`.runtime/windows-parity-20261107/evidence/ssh-bootstrap-cleanup/`.

### A runtime candidate folder left after `off` (product and harness, from d71253c2, 2026-11-16)

A native failure. Row `windows-disconnected-cli-config.ssh-relay-transfer`, DIRECT discovery run
`d71253c2-2588-4735-8222-6d1dd0dd2e27` on the 2.2.18 MSI from `60017226` (whose product sources equal
`3e559abd`'s), evidence `.runtime/windows-scenarios/d71253c2-2588-4735-8222-6d1dd0dd2e27/evidence-1.zip`
(sha256 `63895a15...e21e2e2`, unchanged). With the bootstrap fix above the first HOME_RELAY refresh
passed, and the row reached `ssh-relay-connected`: proxy-only `on` (exit 0, `OK`), a refresh through
the runtime's session (`OK`), `status` running, `off` (child 80, exit 0, `OK`) and `status` with
`runtimeRunning` false, all within ~2.2 s calls. Then `leftovers(c, False)` found a `candidate-*`
folder in the workspace's runtime folder and raised `runtime-candidates-left`
(`windows_ssh_relay_cases.py:561` via `:680`). The serve exited 0 and its stderr (236 bytes) held only
the trust-store notice and the ready line. The evidence did not name the folder's entries, their
holds or whether sing-box still ran: the check failed before the runtime census and recorded nothing.

The check counts what the product must remove: `DesktopProxyRuntimeManager.retireLaunch` deletes the
candidate's captured SSH key copy, its configuration (the location's credentials), its log and the
folder when `off` stops the runtime, before `off` answers; nothing in the product is asynchronous
there, no restore lease is held by `on`, a refresh that keeps the active location, or `off`, and a
refused retirement is retried only at that owner's next start or stop (the owner-start reaper of
the bootstrap fix deliberately skips `candidate-*`). So the folder after `off` is a PRODUCT defect,
not a race of the check. Cause (from code and platform behaviour; the evidence cannot say which
holder refused): `DesktopRuntimeTransition.dispose` stopped the child with the timed
`Process.waitFor`, which on Windows answers from the exit code, set before the kernel closes the
child's handles, and `DesktopLocalRuntimeProcess.close` waited for nothing more; the log is the
child's output redirect, which the JVM opens without `FILE_SHARE_DELETE`; a scanner may hold a file
just closed. `retireLaunch` then tried each deletion once, threw at the first refusal (the
transition swallowed it and retried once at once in the same stop), and wrote nothing. The same
failure type as the bootstrap's `bootstrap-files-left`, on the main runtime, which that fix left
alone; it is worse here, since the key copy is key material and the configuration holds
credentials.

`DesktopLocalRuntimeProcess.close`, which the transition calls once the exit is established, now
waits for the process object (`DesktopBootstrapCleanup.awaitEnded`: the untimed `waitFor` on a
daemon thread, at most 5 s), and reports a child not seen to end. `retireLaunch` keeps the log as
`runtime-sing-box.log` when it can (a failure is reported and never keeps the credential-bearing
files), then removes the key copy, the configuration, the log and the folder with
`DesktopBootstrapCleanup.removeAll`: each pass tries every path still present, passes follow the
same 3.2 s backoff, so the set takes one bound; a folder refused only while it still holds a file
goes in the same pass as its last file; still no recursive removal. What stays is one stderr line
per leaf, `Connection runtime: <leaf> was not removed after N attempts (...)`, never a folder path
or contents, and the retirement fails, so the transition keeps the launch for its next start or
stop. `removeCounting` (the bootstrap's) shares the single-attempt decision and is unchanged in
behaviour. Android (PRODUCT-002) was not changed: its file system never refuses an unlink because a
handle is open, so this cause cannot occur there.

The harness keeps the verdict at the first look after `off`, with no settle before it. After the
verdict `candidates_left` settles for at most 10 s, like `bootstrap_left` (both now through
`describe_left`), and records `ssh-relay-runtime-candidate-leftovers`: each left `candidate-*`
folder and each entry one level down by relative name (`candidate-x/runtime.log`), size and age by
`lstat`, each regular file's hold (a folder's hold is null: an open for DELETE without backup
semantics is refused on every folder), the live runtimes at both looks, `freedAfterSeconds` and
`goneAfterSeconds`; no byte is read. `leftover_rows` gives the bootstrap's rows the same null hold
for a non-regular entry.

| Failure type | Regression | Notes |
| --- | --- | --- |
| `off` left the runtime's candidate folder (key copy, configuration, log) when a deletion was refused for a while after the runtime ended | `DesktopRuntimeRetireCleanupTest` (`:desktopApp:test`): `deletionsRefusedUntilShortlyAfterTheRuntimeEndedLeaveNoCandidateFolder` (POSIX), `theRuntimesProcessObjectIsAwaitedOnceItsExitCodeIsSet` (all platforms); controls `aRefusalThatOutlastsTheRetriesIsReportedByLeafAndRetiredAtTheNextStop` (POSIX), `aCandidateTheOsKeepsRefusingTakesOneRetryBoundAndIsReportedPerLeaf`, `aFolderRefusedOnlyUntilItsFilesAreGoneIsRemovedInTheSamePass` | The first drives the public `DesktopProxyRuntimeManager` (production preflight, launch with the log redirect, stop and retirement) with SSH Routing on and a stand-in sing-box served as the bundled resource, which makes its candidate folder read-only until 0.4 s after it is gone; the test listens on the configuration's inbound ports. The second wraps a `Process` whose exit code is set while its untimed `waitFor` blocks. RED on `3e559abd` (production sources unchanged, the first three tests added), `./gradlew --offline --continue -Pcompose.desktop.packaging.checkJdkVendor=false :desktopApp:test --tests '...DesktopRuntimeRetireCleanupTest'`: 3 of 3 fail, `runtime candidate folders left once off returned expected:<[]> but was:<[candidate-5268944738333424768]>`, `close never waited on the process object`, and no stderr line for the refusal. GREEN on the fix, the same command with 10 classes (this one, `DesktopProxyRuntimeManagerTest`, `DesktopRuntimeRestoreLeaseTest`, `DesktopRuntimeRestoreCredentialTest`, `DesktopBootstrapCleanupTest`, `DesktopHomeSshBootstrapCleanupTest`, `DesktopHomeSshBootstrapOwnerEndTest`, `DesktopValidationRuntimeCleanupTest`, `DesktopShortLivedRuntimeTest`, `DesktopHomeSshBootstrapCleanupNativeTest`): 68 tests, 0 failures, 5 skipped (the Windows-only native tests). |
| `runtime-candidates-left` named no folder or entry and said nothing of holds or of a runtime still running | `test_windows_ssh_relay_cases.CaseTests`: `test_a_left_candidate_is_described_by_folder_and_entry_and_the_row_fails`, `test_a_left_candidate_is_described_by_metadata_only`, `test_a_candidate_entry_whose_holder_lets_go_is_told_from_the_folder_that_stays`, `test_a_runtime_left_beside_its_candidate_is_counted_at_both_looks` | RED with the preserved `3e559abd` module in place, Python 3.14 and 3.12 alike: `Ran 4 tests`, `FAILED (failures=4)`, each `one description of the runtime candidate left` (none recorded). GREEN: the whole module, 23 tests, both Pythons. The existing `candidate-left` defect keeps its reason. |

Native only: Windows' refusal itself and which holder it was. The next direct discovery run on a
package built from this fix must end with all six groups complete and no known failure, and the
serve's stderr must hold no `Connection runtime:` and no `SSH Routing bootstrap:` line. If a
candidate is left again, `ssh-relay-runtime-candidate-leftovers` precedes `known-failure-closing`
and names each entry with its hold at both looks: a file `held` at the verdict (more than 2 s after
`off`, which already waited 5 s and retried for 3.2 s) is a holder that outlasts both bounds;
`free` at the verdict with the runtimes 0 means the product gave up before its holder let go or is
a package before this fix; a folder alone with no entry is a refused folder deletion. Routine
suites: `:desktopApp:test` in Fast Checks and every desktop package workflow, and
`test_windows_ssh_relay_cases` in the affected agent tier. Logs, JUnit reports and the beforeimages
are under `.runtime/windows-parity-20261107/evidence/ssh-relay-left/`.

### An unreadable saved workspace was replaced with defaults (product, offline, 2026-11-13)

Found by reviewing `DesktopStateStore.loadWorkspace` on `00d1e64b`, not by a native run. The load read
`workspace.json` and `workspace-recovery.json` newest first and, when neither decoded, wrote the defaults:
that replaced `workspace.json` and deleted the recovery file, so every subscription, location, rule and
setting was gone and neither the GUI nor `status` said so. The same path took a file that exists but cannot
be opened (an owner-only file of another account, for example after a `sudo` run) and a workspace of a newer
build that this build cannot decode, so a downgrade destroyed it (`PRODUCT-003`). A newer unreadable copy
beside an older readable one survived the load and was replaced by the next ordinary save. A first run and an
additive newer workspace were already right.

The load now keeps every copy it tried and could not read before anything is written. It renames it to
`<name>.unreadable-<UTC yyyyMMddTHHmmssZ>-<8 hex>` in the same private folder (bytes, owner and Windows ACL
unchanged; POSIX group and other bits removed, never added); when a rename is refused, as by a Windows sharing
lock, it writes an owner-only copy and the original is superseded like any older copy. If neither works,
nothing is written and the load fails with `PERSISTENCE_FAILED`, as an unwritable first run already did. Reads
are retried like writes, invalid UTF-8 counts as unreadable, and an older copy that was never tried stays
superseded as before. The loaded workspace gets the typed status `SAVED_SETTINGS_UNREADABLE_DEFAULTS_LOADED`
or `SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED` naming the kept files, as its status line and one log entry,
and is saved at once, so a GUI attaching to a later owner still shows it. Both templates are translated in all
66 status catalogs (`check_localization.py` reports the same 4987 warnings before and after, none for them).
While a kept copy remains, desktop `status` adds warning `UNREADABLE_WORKSPACE_KEPT`; every `status` lists
the folder (since the follow-up below), so later owners report it too and the warning ends when the copy is
gone. When the older copy that loads had a reconnect intent, the status line shows the pending restore instead;
the warning remains, and the GUI log shows the entry only as its raw key (open, see the follow-up).
`PRODUCT-003` now states the rule.

RED: `DesktopStateStoreUnreadableWorkspaceTest` uses only API the unfixed store had. On the production sources
of `00d1e64b` with only the new tests added, `./gradlew --offline --continue
-Pcompose.desktop.packaging.checkJdkVendor=false :desktopApp:test --tests
com.kardinal.vpncontrol.desktop.DesktopStateStoreUnreadableWorkspaceTest` ran 12 tests with 9 failures, each
"not kept", "replaced", "deleted", "destroyed" or "status warnings were []"; the 3 guards passed. GREEN on the
fix: 12 tests, no failure; with 18 neighbouring classes (store durability, service, headless session, status
clients, owner, guarded persistence failures) 120 tests, no failure; `:shared:model:desktopTest` 30 and
`:shared:ui:desktopTest` 54 tests, no failure. Logs and JUnit XML are in
`.runtime/windows-parity-20261107/evidence/workspace-corruption/` of the recovery checkout.

| Failure type | Regression | Notes |
| --- | --- | --- |
| An existing workspace that does not decode was overwritten with defaults, silently | `DesktopStateStoreUnreadableWorkspaceTest`: `undecodableWorkspaceIsKeptAsideAndReportedInsteadOfBeingReplacedWithDefaults`, `undecodableRecoveryFileIsKeptWhenNoReadableCopyExists`, `bothUnreadableCopiesAreKeptAndNamed` (`:desktopApp:test`) | The kept bytes equal the original and are owner-only; the notice survives a restart and is logged once; a readable reload keeps nothing more. |
| A newer unreadable copy beside an older readable one was replaced by the next save | `newerUnreadablePrimaryIsKeptWhileTheOlderReadableRecoveryLoads`, `newerUnreadableRecoveryIsKeptWhileTheOlderReadablePrimaryLoads` | The older copy loads with the older-copy notice; each test saves once more, as the next mutation would. |
| A workspace that exists but cannot be opened was replaced | `workspaceThatCannotBeOpenedIsKeptWithoutWideningItsPermissions` (POSIX, not root) | Mode `000` stays `000` on the kept copy. |
| A newer build's workspace that this build cannot decode was destroyed (downgrade) | `workspaceFromANewerIncompatibleBuildIsKeptForThatBuild` | An object where this build expects a list. |
| The loss was reported neither to the GUI nor to the control status | `guiPresentationCarriesTheNoticeWithTheKeptName`, `controlStatusWarnsWhileAKeptUnreadableWorkspaceRemains`; facade: `StatusMessageDomainFacadesTest.settingsDomainEncodesExpectedKeysAndArgs` (`:shared:model:desktopTest`) | The presentation carries the key with the name unredacted and English renders it; a second owner still warns, and the warning ends when the copy is gone. |

Guards that pass on both trees: `firstRunStartsFromDefaultsWithoutKeepingOrReportingAnything`,
`newerAdditiveFieldsStillLoadWithoutBeingKeptOrReported`, and
`workspaceThatCannotBeKeptIsNeitherReplacedNorReportedAsLoaded` (read-only folder: `PERSISTENCE_FAILED`, the
original unchanged, nothing else written).

Android (`PRODUCT-002`) differs and is not changed. Its DataStore (`vpn_control.preferences_pb`,
`AndroidPreferencesSerializer`) has no corruption handler, so an undecodable file fails every committed read and
write with `CorruptionException` and is never replaced:
`AndroidConfigurationStoreTest.undecodableProductionStoreFailsReadsAndWritesAndKeepsItsBytes` pins it, through
the production construction since the follow-up below (`:app:testDebugUnitTest`: that class 14 tests and
`AndroidPreferencesSerializerTest` 20, no failure). By code
reading only: `MainViewModel` collects that failing flow in `viewModelScope` without a handler, so the app is
expected to stop at launch; the legacy `ProfileStorage.state` maps the failure to empty defaults; ADB control
reads fail. Android keeps the data but neither stays usable nor says why. That is a separate Android defect
that needs its own product decision and causal regression; it is unproven natively, as no emulator was used.

Downgrade residuals, pre-existing and not changed: this build's next save drops fields it does not know and
saves the default for an enum value it does not know; a newer build's structural change is kept aside only when
that build raises `format` (follow-up below), otherwise it is read like an additive one and the next save loses
what this build cannot represent; builds before this fix ignore `format` and still overwrite a workspace they
cannot decode. Older builds ignore the kept files and cannot render this build's two new status keys (an empty
status line through the owner presentation, the raw encoded text elsewhere); nothing is lost.
Not proven natively: the Windows sharing-lock path (its decision is covered by a fault-injection regression since
the follow-up), ACL preservation, and any native or packaged run. Routine coverage: `:desktopApp:test`,
`:shared:model:desktopTest`, `:shared:ui:desktopTest` and `:app:testDebugUnitTest` in Fast Checks and the
managed pre-push tier.

### Review follow-up to the unreadable-workspace keep (product, offline, 2026-11-13)

Independent review of `5ba8efaa` found four product defects and four test gaps. Each was verified by reading
the code and by a regression with an actual RED on the production sources of `5ba8efaa`. Faults that a real
folder cannot produce on demand come from `FaultInjectingFileSystem`, a test-only view of the default file
system that fails chosen operations (a sharing lock, a full disk, a flaky mount) under the unchanged store.

Product defects, all in `DesktopStateStore`:

- Interrupted keep. The keep renames the unreadable file before the save that carries the notice. When that
  save failed (a full disk) or the process died in between, the next start found no saved copy and loaded the
  defaults as a first run, or silently loaded an older recovery file; only `status` named the kept file. The
  load now lists the kept copies first. A kept copy whose data (its modification time, which the rename keeps)
  is newer than the copy that loads, or any kept copy when the defaults load, is named in the same typed notice,
  saved at once; after that save the loaded copy is newer, so nothing is named twice.
- Unknown existence. `Files.exists` is also false when existence cannot be determined, so a brief I/O or
  stale-handle error on `workspace.json` took the first-run branch and the save atomically replaced the real
  file with defaults (the gate was unchanged from `00d1e64b`). Each saved copy is now classified with
  `readAttributes`: only `NoSuchFileException` means absent; other errors are retried like reads and then fail
  the load with `PERSISTENCE_FAILED` without writing.
- Downgrade structure. Protection held only when decoding threw; a newer structure that decodes without an
  exception was read as empty and overwritten by the next save. `workspace.json` now records `format` 1; any
  other `format` is not decoded and is kept aside with the notice, and no `format` (every earlier build) still
  loads. `PRODUCT-003` states the rule, including that a change older builds would misread raises `format`.
- Cached warning. `UNREADABLE_WORKSPACE_KEPT` was computed once per owner, so a long-running owner kept warning
  after the kept file was deleted. Every `status` now lists the folder again.

Test gaps, where `5ba8efaa` was already right but no test would notice a regression: the fail-closed keep
(the read-only-folder guard also failed the later save, so carrying on after rename and copy failed passed),
the copy fallback (never run), the save of the older-copy notice by the load itself (both tests saved
explicitly), strict UTF-8 and read retries (all fixtures ASCII, no transient failure), and the Android pin (it
built its own DataStore, not the one `ProfileStorage` builds).

| Failure type | Regression | Notes |
| --- | --- | --- |
| A kept copy whose load stopped before saving was not reported on the next start | `DesktopStateStoreUnreadableWorkspaceTest`: `keptCopyIsReportedOnTheNextStartWhenTheSaveAfterKeepingFails` (temp-file creation fails as on a full disk), `keptCopyOfAnInterruptedLoadIsReportedWhenNoSavedCopyRemains`, `keptCopyOfAnInterruptedLoadIsReportedWhenAnOlderCopyLoads` | The notice survives a reload and is logged once. |
| A saved copy whose existence could not be determined was replaced with defaults | `workspaceWhoseExistenceCannotBeDeterminedIsNeitherReplacedNorKept`, `briefMetadataFailureIsRetriedAndTheWorkspaceLoads` | Bytes unchanged; only the error class is logged. |
| A newer build's workspace that decodes without an error was misread and overwritten | `workspaceOfAnotherFormatIsKeptEvenWhenItsFieldsWouldDecode`, `savedWorkspaceRecordsItsFormatAndOneWithoutAFormatStillLoads` | `format` 2 with compatible shapes is kept byte for byte; a workspace without `format` still loads. |
| A running owner kept warning about a deleted kept copy | `runningOwnerStopsWarningOnceTheKeptCopyIsDeleted` | The same owner, before and after the delete. |
| Fail-closed keep and copy fallback were unguarded | `workspaceThatCanNeitherBeRenamedNorCopiedFailsClosedWhileTheFolderStaysWritable`, `workspaceThatCannotBeRenamedIsCopiedPrivatelyBeforeTheDefaultsReplaceIt` | The copy is byte-identical, named, and requested owner-only at creation, so a umask-dependent copy fails even under umask `077`. |
| The load's own save of the older-copy notice was unguarded | `newerUnreadablePrimaryIsKeptWhileTheOlderReadableRecoveryLoads`, `newerUnreadableRecoveryIsKeptWhileTheOlderReadablePrimaryLoads` (now check the disk and a reload before any explicit save) | |
| Strict UTF-8 and read retries were unguarded | `workspaceThatIsNotValidUtf8IsKeptByteForByte`, `briefReadFailureIsRetriedInsteadOfKeepingAReadableWorkspace` | One raw `0xFF` inside a string value. |
| The Android pin did not run the production store | `AndroidConfigurationStoreTest.undecodableProductionStoreFailsReadsAndWritesAndKeepsItsBytes` (`:app:testDebugUnitTest`) | Clears the application singleton so `ProfileStorage` builds the production DataStore, then restores it. |

RED on the production sources of `5ba8efaa` with the final tests, `./gradlew --offline --continue
-Pcompose.desktop.packaging.checkJdkVendor=false :desktopApp:test --tests
com.kardinal.vpncontrol.desktop.DesktopStateStoreUnreadableWorkspaceTest`: 24 tests, 8 failures, exactly the
four product defects ("status was not a typed notice", "expected SAVED_SETTINGS_UNREADABLE_DEFAULTS_LOADED but
was CONNECTION_READY_ON_COMPUTER", "Expected ... DesktopPersistenceException ... completed successfully", the
saved subscription replaced by `[]`, "read as this build's", "does not record its format", "still warned about a
deleted copy"); the gap tests pass there. Mutants of `5ba8efaa`, run with the 12 tests of `5ba8efaa` under
another class name: carrying on after rename and copy failed, a copy with umask permissions, an older copy not
saved, lenient UTF-8 and a single read attempt together gave 14 failures (the 8 plus each gap test); a copy
without bytes gave 9; the 12 tests of `5ba8efaa` passed on both runs. GREEN on the fix: 24 of 24, and 226 tests
in 53 store-related desktop classes with no failure. Android: with `ReplaceFileCorruptionHandler` added to the
production factory the new pin fails ("expected CorruptionException but was null") while the replica pin of
`ffa03e94` passes; on the unchanged Android sources `AndroidConfigurationStoreTest` passes 14 of 14.

Its deferred GUI half, the notice hidden by the launch restore and the GUI log's raw typed statuses, is fixed
under "Desktop unreadable-workspace notice in the GUI status and the GUI log" below.

### Windows in-guest desktop test, review of the offline build (2026-11-13)

Review findings on the build commit `89a059e6` (`windows-desktop-test-start`/`-status`,
branch `guest-desktop-test`), not native failures: nothing here has reached a VM. The RED
tree is `git archive 89a059e6` with only the three updated test modules copied in. The
before-images, `red_green.sh` and one log per failure type and interpreter
(`{red,green}{314,312}-<type>.log`) are under `.runtime/review-1113/` of the build clone
`build-guest-desktop-test`. RED and GREEN counts are the same on Python 3.14 and 3.12. The
regressions are in `test_windows_desktop_test_host_job` (`DesktopJobTests`),
`test_windows_desktop_test` and `test_windows_desktop_test_guest` (`RunnerTests`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| The worker request did not pin the worker's own source | `test_the_worker_request_pins_its_interpreter_its_own_source_and_every_input_it_reads`, `test_a_complete_run_publishes_runs_reads_back_and_cleans_in_order` | `windows_ordinary_process_owner.Owner` admits a request only if its file pins hold `sys.executable` and the worker's own `__file__` (`owner-interpreter-source-pins`). The scenario rows' module pins include the worker; the desktop job's worker request did not, so every native run would have ended `results`/`desktop_runner_summary_missing` before Gradle. The job now pins it, and the fake peer models that admission (worker and owner exit 1, no runner output). RED (2 tests): failures=2, `(1, 'owner-interpreter-source-pins')` and `desktop_runner_summary_missing`. GREEN: OK. Native only: the worker's admission itself. |
| Pushed archives stayed in the guest after a known failure | `test_a_fixture_without_the_scenario_python_refuses_before_any_archive_is_pushed`, `test_a_python_tree_past_the_worker_pin_bound_refuses_before_any_archive_is_pushed`, `test_a_run_refused_before_launch_still_deletes_the_pushed_archives`, `test_a_push_lost_inside_an_archive_deletes_every_archive_endpoint_by_its_identity` | The cleanup ran only after a finished task, but the four archives (0.5 to 1 GB, SYSTEM-owned, read-only to the user) were pushed before the Python tree and the pin bound were checked, and `planner_refused`, `refused_before_launch` and a lost push come after the push too. The tree is now listed and bounded before anything is pushed. Each archive endpoint's identity is kept as the publisher creates it, and after any known exit with no open program and no task launched (none, or refused before launch) the same identity-checked program deletes the archives: a verified one by volume, file index and size, one whose push or verification did not complete by volume and file index (`sizeKnown` false). An UNKNOWN exit keeps everything. RED (4 tests): failures=4, endpoints made before the listing, and no `desktop-cleanup` after a refused launch or a lost push. GREEN: OK. Native only: the C# delete by handle, including the `sizeKnown` branch. |
| The export task was never selected under configure-on-demand | `test_windows_desktop_test.ExportSelectionTests` | The init script registered `:desktopApp:vcdtExportResolution` in `projectsEvaluated`. With `org.gradle.configureondemand=true` (`gradle.properties`), Gradle 8.10.2 looks a requested task up before it fires that, so `prepare` always refused `dependency_export_gradle_failed`. The task is now registered as `:desktopApp` itself is evaluated (`gradle.afterProject`). The test runs the pinned distribution from the wrapper's own dists folder, offline in a fresh user home, against a two-project build with this checkout's `gradle.properties`, whose `:app` throws if configured. It skips without that distribution and a JDK: the coordinator's routine local pre-push runs it; the CI agent shards have neither. RED: exit 1, `Cannot locate tasks that match ':desktopApp:vcdtExportResolution' as task 'vcdtExportResolution' not found in project ':desktopApp'`. GREEN: OK, `:app` never configured. Native only: the real build's export with network. |
| A dependency the offline repository lacks read as the source's failing tests | `ResultTests.test_the_tool_outcome_and_the_test_outcome_are_apart`, `StatusTests.test_a_dependency_the_offline_repository_lacks_is_the_tools_failure_though_gradle_names_the_test_task`; characterization `ResultTests.test_the_console_says_what_kind_of_build_failure_it_was` | Captured from the pinned Gradle offline against a file repository without a test runtime jar, then without the module: both read `Execution failed for task ':desktopApp:test'. > Could not resolve all files for configuration ':desktopApp:testRuntimeClasspath'.`. `outcome()` tested the failing task before the resolution failure, so both were `completed`/`failed`. Failing tests still come first, then a resolution failure (`failed`/`gradle-dependencies`), then the failing test task. The console pattern already matched that header; the `Could not resolve all task dependencies` wording is not 8.10.2's, so the pattern is unchanged. RED (3 tests): failures=3, `('completed', None, 'failed')`. GREEN: OK. |
| An UNKNOWN exit's copy-back could stay cut for good, and two status reads wrote one partial file | `StatusTests.test_an_unknown_exit_whose_copy_back_was_cut_is_copied_back_by_a_later_status`, `StatusTests.test_one_copy_back_at_a_time_so_two_status_reads_never_write_one_file` | Status pulled an UNKNOWN exit's files once, swallowed any failure and still wrote `summary.json` create-only, which stopped every later pull; and that pull appended to the same `.partial` as a concurrent status. Its summary is now `summary-unknown.json`, written only once every file the receipt names is pulled and verified; until then `copyBack: incomplete` and the next status resumes. A per-operation lease (`.copy-back.lock`, non-blocking `flock`) covers the terminal collection's pull, the UNKNOWN copy-back and either summary; a held lease answers `copyBack: busy`, or leaves the executor's collection to retry. The executor's own collection lease cannot serve here: its journal admits `collectionLease` on terminal records only. RED (2 tests): failures=2, a summary frozen after one lost pull reply, and a second reader that appended its chunks into the first reader's partial (in other interleavings its create-only summary raised `FileExistsError`). GREEN: OK. |
| The guest lacks CI's .NET SDK, so its tests' failures read as the source's | `RunnerTests.test_the_build_gets_a_dotnet_that_does_not_exist_and_no_inherited_dotnet_root`, `StatusTests.test_tests_that_could_not_start_the_guests_absent_dotnet_are_reported_apart`; control `StatusTests.test_any_other_failure_to_start_a_program_still_fails_the_source` | 24 tests in 8 Windows-only classes start `VPN_CONTROL_TEST_DOTNET`, else `dotnet.exe`; CI installs SDK 10.0.403 (`toolchain.lock.json`) first, and two of them restore from nuget.org. Not provisioned here (a pending decision): the runner names a missing `dotnet.exe` in its work folder and drops an inherited `VPN_CONTROL_TEST_DOTNET_ROOT`, so the outcome is the same on every fixture and no fixture SDK reaches the network. Exactly that `java.io.IOException` (that program, `CreateProcess error=2`) is listed in `excludedTests`; `passed-except-excluded` needs Gradle's "There were failing tests" and every counted failure excluded. RED (3 tests): failures=2, the fixture's SDK reached the build and the outcome was `failed`; the control passes on both trees. GREEN: OK. Until the SDK is provisioned these 24 tests run only on CI. |

Not fixed, a decision: the exported dependency set is trust-on-first-use. `files_to_repository`
checks each file only against the SHA-1 Gradle named its cache folder by, and the manifest's
digests come from that same export; the repository has no `gradle/verification-metadata.xml`.
That is CI's own posture, so it adds no risk over CI, but no dependency has an independently
known digest. Closing it means committing Gradle dependency verification (sha256) and running
both the export and the guest build with `--dependency-verification strict`, which changes every
build of the repository, or committing a reviewed export manifest that `prepare` must match.

### Windows in-guest desktop test, CI's .NET SDK and an offline NuGet seed (2026-11-13)

The user's default decision on the row above: the 24 Windows-only .NET tests run in the guest,
offline, instead of being excluded. Built in `4aa1293f` on `guest-desktop-test`; nothing here has
reached a VM. The RED tree is `git archive dd3d30ab` with only the three updated test modules copied
in. `red_green.sh` and one log per failure type and interpreter are under `.runtime/followup2/` of
the build clone. RED and GREEN counts are the same on Python 3.14 and 3.12. The real-SDK
regression runs the osx-arm64 SDK 10.0.403, verified against the SHA-512 Microsoft's release
manifest lists, through `VPN_CONTROL_TEST_DOTNET`, and skips without it.

| Failure type | Regression | Notes |
| --- | --- | --- |
| CI's SDK was not staged | `InputTests.test_the_dotnet_pin_is_this_checkouts_toolchain_lock_and_global_json`, `ToolchainTests.test_a_publisher_sha512_is_checked_with_the_size_and_sha256`, `PrepareTests.test_prepare_keeps_cis_sdk_and_the_nuget_seed_as_the_fifth_and_sixth_archives`, `PrepareTests.test_an_sdk_zip_the_runner_could_not_use_is_refused_by_prepare`, `StartTests.test_cis_sdk_and_the_nuget_seed_are_staged_and_given_to_the_job_with_their_pins`, `DesktopJobTests.test_cis_sdk_and_the_nuget_seed_are_pushed_pinned_by_the_worker_and_named_in_the_runner_request` | `dotnet-sdk-10.0.403-win-x64.zip` (300745255 bytes) is used only after the lock's SHA-512 and the recorded size and sha256 match, and an SDK zip without its muxer, SDK or runtime is refused by `prepare`. RED (6 tests): failures=4, errors=3, no `DOTNET` and four archives staged. GREEN: OK. |
| No offline NuGet seed | `SeedTests` | `Microsoft.NET.ILLink.Tasks` 10.0.14 (1535193 bytes), the one package the probes restore from nuget.org (the SDK's `KnownILLinkPack` for net10.0 that `EnableAotAnalyzer` adds), is pinned by the `packageHash` and `packageSize` of its nuget.org catalog entry and zipped into a deterministic flat-folder seed. RED (2 tests): errors=2, no `nuget_seed`. GREEN: OK. |
| The build saw no SDK and could reach nuget.org | `RunnerTests.test_the_build_gets_cis_pinned_sdk_and_a_nuget_configuration_with_only_the_seed_folder`, `RunnerTests.test_the_users_own_nuget_folders_are_compared_before_and_after`, `OfflineRestoreTests.test_a_probe_restores_only_from_the_seed_folder_and_nothing_reaches_its_own_remote_source` | `VPN_CONTROL_TEST_DOTNET`, `DOTNET_ROOT`, the first-run, telemetry and logo switches, `RestoreConfigFile` naming a NuGet.Config whose only source is the seed folder, and refused loopback proxies. The real SDK restores a probe whose own config names a decoy feed: with the seed it succeeds and the decoy sees no request; with an empty seed it fails NU1101 against the seed source only. RED (3 tests): failures=1, errors=2, the RED runner read the probe's own config (NU1301 from the decoy). GREEN: OK. |
| An incomplete SDK or seed had no stage of its own | `RunnerTests.test_an_sdk_archive_without_its_pinned_layout_fails_its_own_stage`, `test_a_seed_that_is_not_the_requested_packages_fails_its_own_stage`, `test_an_sdk_that_does_not_run_as_the_source_pins_it_fails_the_dotnet_check`, `RequestTests.test_the_windows_request_is_closed_and_derived_from_its_operation` | `extract-dotnet`, `extract-nuget` and `dotnet-check` are tool failures before Gradle. RED (4 tests): errors=4, the request has no `dotnet`. GREEN: OK. |
| The exclusion hid real failures, and a missing package read as the source's | `StatusTests.test_a_test_that_could_not_start_dotnet_is_a_failure_like_any_other`, `StatusTests.test_a_package_the_offline_seed_lacks_is_the_tools_failure_not_the_sources`, `ResultTests.test_only_a_restore_error_naming_the_seed_marks_a_failure_as_the_tools`, `ResultTests.test_the_tool_outcome_and_the_test_outcome_are_apart`; controls `StatusTests.test_restore_words_that_do_not_name_the_seed_stay_the_sources_failure`, `test_any_other_failure_to_start_a_program_still_fails_the_source` | `excludedTests` and `passed-except-excluded` are gone. A NuGet resolution error (NU1101 to NU1103) naming the seed's source is `failedStage: dotnet-packages`, the tests' own outcome kept. RED (4 tests): failures=3, errors=2, `('completed', None, 'failed')`. Controls pass on both trees. GREEN: OK. |
| A commit pinning another SDK would run with this one | `SourceTests.test_a_commit_whose_dotnet_sdk_pin_is_not_the_tools_is_refused_before_anything_else` | The commit's own `toolchain.lock.json` and `global.json` must name the tool's SDK, url and SHA-512 (`desktop_test_dotnet_sdk_unpinned`). RED (1 test, 7 subtests): failures=7. GREEN: OK. |

Native only: extraction and `dotnet --version` on Windows, the seed restore with the win-x64 SDK,
the 24 tests' own outcome, and the user's NuGet migration folder comparison.

### Update rows never claim installed-package, offline (2026-11-13)

Built offline in the clone `build-update-counting` on `b809c279`; nothing here has run natively.
GAP-UPD of the 2026-11-13 coverage audit: `Job._finish` claimed installed-package only for a row
that was `not self.update`, and nothing read what an update task left installed, so every
`windows-public-update.*` run stayed `installed-package-unproven`. The twelve scenarios that name
update rows could never pass `matrix-status`: all eight of windows-installer-lifecycle, and
msi-installer, public-update, operation-progress-cancellation and traffic-continuity of
windows-native-cli. The 17 recorded native update runs (public-ready, download-cancelled and
checksum-rejected: eleven on S_T, six on S_T2) each passed, and before its task each matched
the registration and tree of S_B that its input's base reset recorded. None read what its task
left and none ran `--version`, so under the rule below all 17 stay unproven and need a rerun. The six S_T2 runs and the two installs they
name (base reset `c3da662a`, target install `c693352b`) are the fixture
`fixtures/windows_update_native/st2-update-runs.json`: the input byte for byte, the route and
the receipt with its context set to null. The originals are named there by digest and kept
under `.runtime/update-counting/native/` of the clone, beside the RED, GREEN, pin and selector
logs. RED ran in a worktree of `b809c279` holding only the new and changed test modules and the
fixture, one unittest process per failure type, on Python 3.14 and 3.12 with identical counts
(subtests included).

| Failure type | Regression | Notes |
| --- | --- | --- |
| Update rows never claimed installed-package | `test_windows_scenario_host_job.UpdateInstalledTests` (five tests), `UpdateFamilyTests.test_a_no_system_row_runs_the_case_with_its_fixture_and_no_collector`; `test_native_scenario_windows.PublicEvidenceTests.test_an_update_row_claims_the_package_its_variant_ends_with`, `TableTests.test_setup_rows_are_never_evidence_and_product_rows_name_their_package`, `UpdateTableTests.test_each_row_ends_with_the_package_its_case_leaves_and_reads_it_back`; `test_native_scenario_windows_matrix.UpdateRowTests.test_a_passed_update_run_counts_with_the_package_read_after_its_task`, `test_the_update_scenarios_pass_matrix_status_once_their_rows_are_proven`, `RecordedNativeUpdateTests.test_the_recorded_runs_count_with_what_the_fixed_job_writes_after_the_task`, `TableTests.test_the_update_rows_prove_their_scenarios_through_what_they_read_back` | The row table now names what a passed variant leaves (`update.ends`): the target for `update_cases.SUCCESS_VARIANTS` (success-off, success-reconnect, different-admin, wait-client-loss, installer-wait-client-loss), the base for every other. Every update row has the `installed` stage. After the task, the job reads the registration and the complete installed tree as an installer row reads what it installed (`_registration`, `_listed`, `_tree`). It names the result by the one declared install it exactly is (product code, version, package code, tree digest and count): the target install the input names, or the base install it started from. A passed row that read another package ends `update_installed_differs:<role or check>` and claims nothing. Otherwise it claims that package: the target after a granted install, whose `--version` the case asks after the update, or the base, unchanged, whose `--version` the driver now asks first. A known failure after the task was deleted, such as a grant whose prompt ended CANCELLED, is read back the same way and named beside the failure. A lost reply of that read leaves the outcome unknown with the fence open. `public_evidence` takes, for an update row, the package its variant ends with. RED (13 tests): `FAILED (failures=52)`. GREEN: OK. |
| The record did not bind the base the update started from | `RecordedNativeUpdateTests.test_the_recorded_runs_stay_unproven_and_their_record_names_the_base_they_started_from`, `UpdateRowTests.test_a_failed_update_run_names_the_package_it_left`, `test_an_update_run_without_its_bound_proof_never_counts` | The base, S_B of `32d32706`, is a package of another source, so it cannot be an artifact of the record (`_verify_artifacts` needs the record's source). `_matrix_row` binds it through the base install's own collected journal on the same clone. That journal must be a passed `windows-msi-base-install` or `-reset` whose admitted `basePackage` is the package its receipt recorded, at the input's `baseVersion`, and its recorded install must be exactly what the update found before its task. The target's install is bound the same way. Each update row's evidence entry names `baseInstall`, `basePackage`, `targetInstall` and `installedPackage`, a failed row's too. An update run counts only when the package read after its task is one of those installs, its variant's own, claimed exactly. Anything else stays `installed-package-unproven`, and so does every receipt the job wrote before this. On `b809c279` an unbound target claim passed and no entry named a base. RED (3 tests): `FAILED (failures=11)`. GREEN: OK. |
| The update route asked the base for no `--version` under the ordinary token | `test_windows_ordinary_task.DedicatedDriverControls.test_an_update_asks_the_installed_base_for_its_version_before_any_hold_or_case`, `test_an_update_whose_launcher_reports_another_version_never_arms_or_runs_its_case` | `run_update` now calls `installed_version`, the lifecycle route's `--help` and `--version` of the installed launcher, before any hold or case. The launcher here is the base, the request's `productVersion`. A launcher that reports another version ends the row 1 before the update. RED (2 tests): `FAILED (failures=13)`. GREEN: OK. |

Control: `UpdateInstalledTests.test_a_task_that_never_finished_or_never_ran_is_never_read_back`
passes before and after. A parked owner, or a job stopped at publish, is never read back.

No new collector was needed. The reads after the task are the publisher actions the installer
rows already use (`msi-registration`, `list-tree`, `read-directories`, `read-pins`), natively
proven after `msiexec` installs. Pins renewed to a fixpoint: the planner's
`DEDICATED_DRIVER_SHA`, the owner's held-driver literal, the selector's reviewed driver versions
(appended), the `readiness_vm_dispatch.json` `sourcePins` of `windows_ordinary_task`,
`windows_scenario_host_job` and `native_scenario_windows`, and the selector's entry for that
manifest. No file of `readiness_windows._source_pins()` changed.

Native only:

- The four reads after an update task.
- The base's `--version` on the update route.
- That the registration after the product's own upgrade is exactly one per-user row of the
  target.
- That the tree after that upgrade is the one a clean `msiexec` install of the target recorded
  (the case already requires the same membership and bytes).
- Every grant stage.

The next update discovery run must show, after `system-run`, the programs `after-registration`,
`after-installed-tree`, `after-installed-directories-1` and `after-installed-read-pins-1` before
`evidence-zip-1`. In its evidence, the children `help` and `version` must come before
`update-public-serve`, with the base version in the version child's stdout. In its receipt,
`update.baseInstall` and `targetInstall` must equal its input's, and `installedAfter` must be
the base install's recorded facts (role `base`) or, after a grant, the target install's (role
`target`), with `windows` claiming that package.

### Windows scoped-TUN grant, offline build (2026-11-13)

Built offline in the scratch clone `builders/build-tun-grant` on `1d9d239b`; nothing here
has run natively. The unfixed sources are the clone's `.runtime/tun-grant-before/`,
byte-identical to `1d9d239b`. RED ran in an archive of `1d9d239b`
(`.runtime/tun-grant-red`, removed after use) holding only the new and changed test
modules, one unittest process per failure type, on Python 3.14 and 3.12 with identical
counts (subtests included). The publisher type also ran in a copy of the fixed tree whose
only change is the `1d9d239b` publisher template (`.runtime/tun-grant-red-template`,
removed after use). The logs are the build clone's
`.runtime/tun-grant-logs/{red,red-template,green}-{314,312}-<type>.log`, copied to
`.runtime/windows-parity-20261107/evidence/tun-grant/test-logs/` of the recovery checkout.
The cancelled-grant driver regressions no longer patch the driver's variants, since the
grant is the driver's own now, so the "latent" notes of the grant rows in the scoped-TUN
family above no longer hold.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A restart grant had no admitted row, so no scenario could name an approved TUN | `test_native_scenario_windows.ScopedTunTableTests`: `test_the_restart_rows_are_admitted_and_each_find_best_row_names_what_it_lacks`, `test_the_grant_collector_modules_are_the_contract_roles`, `test_the_rows_are_the_stages_variants_on_the_proxy_action`, `test_the_tun_files_and_the_collector_pin_are_in_the_bundle`, `ScopedTunAdmissionTests.test_every_refused_row_is_refused_before_any_journal`; `test_native_scenario_windows_matrix.TableTests`: `test_the_table_names_every_windows_scenario_and_only_built_rows`, `test_the_document_tun_and_responsive_rows_prove_only_what_their_evidence_holds`, `test_the_update_rows_prove_their_scenarios_through_what_they_read_back`; `test_native_scenario_bundle.NativeScenarioBundleTest.test_inventory_outside_scripts_moves_every_top_level_name` | Both grant rows were refused `windows_scenario_tun_grant_unproven`, and `scoped-uac-tun-traffic`, `exact-child-stop` and `scoped-elevation` mapped to `()`. `restart-grant` now carries the direct sampler, the TUN collector (`windows_tun_native_observer`, the contract's `COLLECTORS["tun"]`), the receipts module and the update rows' collector chain, and names its one collector stage, `tun`; the driver bundle holds the observer (62 files on `1d9d239b`, 65 on the integration base). The matrix maps `scoped-uac-tun-traffic` to it, `exact-child-stop` to it beside `windows-proxy-lifecycle.sibling-off`, and `scoped-elevation` to it beside `windows-public-update.success-off`, which counts with the target its job reads back after the task (the update-row counting of the section above). `find-best-grant` and `find-best-deny` keep `windows_scenario_tun_find_best_unproven`, which now says what they lack. RED (9 tests): failures=8, errors=3: `restart-grant` refused `windows_scenario_tun_grant_unproven`, the three scenarios mapped to `()`, a bundle of 61 files, no collector roles. GREEN: OK. |
| A grant could be admitted with no reviewed broker profile, and its prompt would expire into a failed run | `test_native_scenario_windows.ScopedTunAdmissionTests.test_the_grant_is_admitted_only_with_the_deployments_reviewed_broker_profile` | Without a profile `windows-uac-decision` refuses `uac_profile_unreviewed` (native, 2026-11-09, above). A grant whose prompt expired ends `CANCELLED`, exit 1, which the matrix records as failed, and a failed record blocks every later equivalence link of its requirement and source. Admission now refuses `windows_scenario_uac_profile_unreviewed` before any journal unless `windows_uac_decision._load_profile` admits the deployment's private `vpn-broker` profile. A deny row needs none: its run is the one `windows-uac-review` captures the frame from. RED (1 test): failures=1, refused `windows_scenario_tun_grant_unproven` instead. GREEN: OK. Native only: that a profile reviewed on a denial's prompt reads the approval's prompt on the same clone. |
| A passed grant needed no decision terminal | `test_native_scenario_windows.TunGrantDecisionTests`; `ScopedTunTableTests.test_each_prompt_is_the_decision_tables_and_a_denial_joins_its_terminal` | Collect joined the decision's input terminal for deny rows only. A grant's receipt proves the approved broker, not who typed the credential. A grant row now asks exactly as a deny row does (`uac-pending:vpn-broker:approve`), and collect passes it only with that decision's own input terminal (`approve-acknowledged-prompt-closed`); a failed grant needs no join. RED (4 tests): failures=9, errors=5: no join for a grant (`a grant joins its approval too`), a pending approval read as `job_not_discovered` since the row was refused, and the driver had no grant variant. GREEN: OK. |
| The dedicated driver had no close hold and no record handoff for a grant | `test_windows_tun_grant.DriverGrantTests`; `test_windows_uac_decision.CancelledGrantDriverTests`: `test_a_tun_grant_without_its_collectors_close_hold_starts_nothing`, `test_a_known_tun_end_that_is_not_the_variants_own_closes_by_its_census_and_exits_one`, `test_a_grant_runs_only_the_reviewed_sampler_beside_the_driver`, `PacketTests.test_table_values_are_what_the_case_modules_publish`; `test_windows_tun_stages.GeneratedInputTests`: `test_only_a_grant_names_its_collectors_close_hold`, `test_a_tun_harness_names_the_stages_and_the_route_inputs_only`, `test_the_grant_sampler_expects_the_rows_own_upstream_body` | The driver refused `restart-grant` itself, and nothing could give `finish` its ready record or the off stage its off record. A grant's harness alone now names `SYSTEM_COLLECTOR_CLOSE_HOLD` (scope `tun`, stage `off`). Before any effect the driver binds it to its pinned hold protocol, contract, SYSTEM worker and `TUN_COLLECTOR_SHA`, and to the receipts module beside itself; it arms the caller hold before the request. When the stages ask for the ready record, the handoff publishes one `update-native-observation-needed` event (stage `tun`) and polls the machine-written `ProgramData\tun-evidence-<operation>\ready.json`, and after the product's own off it polls `off.json`. The driver then hands its result to the hold and requires the release. A grant that ends without its TUN retires the unused hold and exits 1; once its collector was asked, any failure parks with the hold kept. RED (15 tests): failures=2, errors=25: the harness takes no hold and writes a grant's harness without one, the driver has no `TUN_COLLECTOR_SHA`, and its variants hold the denial alone. GREEN: OK. |
| `finish` took the grant's ready record before its broker could exist | `test_windows_tun_stages.FinishTests.test_a_grant_asks_its_collector_for_the_ready_record_only_once_its_tun_came_up` | `finish(native_record=...)` required the record as an argument, before it read the operation's terminal. The collector finds the broker and its runtime only once the approval started them, so no caller had a record to give. `finish` now takes `handoff` and calls it only after the product ended the operation `OK`. RED (1 test): errors=3, `finish()` takes no `handoff`. GREEN: OK. |
| A grant's machine record joined a source the worker request never carries | `test_windows_tun_stages.NativeRecordSourceTests` | `read_native_record` compared the record's `sourceSha` with `owner.request['sourceSha']`. The ordinary worker request (the planner's common fields) has none, so every grant would have raised `KeyError` right after its collector published, and parked. The driver keeps the lifecycle inputs' `sourceSha` on the lease, and the stages join that; a record of another source is refused `scoped-tun-protected-native-operation-join`. Latent while grants were refused. RED (2 tests): errors=2, `KeyError: 'sourceSha'`. GREEN: OK. |
| No stage of the host job discovered the approved broker and its runtime | `test_windows_tun_grant`: `TunActorTests`, `VpnBrokerTests`, `TunGrantFamilyTests` (`test_the_grant_serves_its_one_collector_inside_the_run_and_releases_the_hold`, `test_the_real_observer_and_stages_take_what_this_job_builds`, `test_a_census_the_grant_cannot_take_leaves_the_owner_unknown_with_no_collector`, `test_a_need_naming_another_operation_or_no_serve_starts_no_collector`, `test_without_its_broker_or_with_another_runtime_the_grant_ends_before_its_task`, `test_the_deny_row_keeps_no_collector_hold_or_folder`) | The job served native needs for update rows only, built no TUN collector request and required one publication of every collector. Between two polls of the SYSTEM run it now serves the grant's need. `tun_actors` takes from the SYSTEM census exactly one serve (the worker's child the need names) and its controller (the one CLI process it relaunched into, or itself). It also takes exactly one broker of the image the installed `native-helpers.json` declares (`vpn_broker`), elevated as the approving administrator in the ordinary session, born after the controller, whose arguments name it, the ordinary SID and the runtime digest. Last, exactly one `sing-box.exe` that broker started from a private `ProgramData\vpn-control-vpn-<uuid>` stage, with the installed runtime's bytes, elevated the same. Each refusal names itself (`collector_tun_*`) and ends the job UNKNOWN with no collector; parents are recorded, never assumed. The contract and the observer's own `validate` check the request before it is published, the census is kept at `collectors/tun/census.json`, the TUN collector publishes two records, and the receipt keeps `tun.collectors` and `tun.broker`. A missing broker or another runtime authority ends the row at publish, before any task. RED (11 tests): failures=12, errors=36: no `tun_actors` or `vpn_broker`; in the host-job tests' fake world the old job ran the grant to its evidence with no collector served, passed a need naming another operation or no serve, and published with no broker or another runtime authority. GREEN: OK. |
| The publisher's census refused the broker and saw none of its children | `TunGrantFamilyTests.test_a_publisher_without_the_tun_observation_leaves_the_owner_unknown`, `test_the_grant_serves_its_one_collector_inside_the_run_and_releases_the_hold`; `WindowsCensusTests` (Windows only, not run) | The census took one image matching `vpn-control(-cli\|-install-helper)?.exe`, so it refused `vpn-control-vpn-broker.exe` (`PUB_CENSUS_IMAGE`) and never named a process of another image, such as the broker's staged runtime and its console. The observation read every child event, which a TUN row polling through a whole prompt may push past its 256-file bound (`PUB_OBSERVE_COUNT`), and no need; the product pin refused the workspace's `runtime-config.json` (`PUB_PRODUCT_PIN_PATH`). The census now takes a list of images, the broker with every process it started (`PUB_CENSUS_CHILDREN` for any other image), 16 rows in all. A TUN observation reads the need events in place of the child events, and the pin admits that one config. The fake peer follows the rendered template's own text. RED on the archive (3 tests, one skipped): failures=2, no collector stage at all. RED in the fixed tree with only the `1d9d239b` template (same tests): failures=2, the grant ends 3 with `collector_stage_failed:tun:publisher_refused:collector-observe-tun:PUB_CENSUS_IMAGE`, and the template carries no broker image. GREEN: OK (skipped=1). Native only: all of it; the C# census has not been compiled. |

Rebased onto the integration base `9a8db1e5` (`529cc610`, ten integrated sets and the
update-row counting of the section above) in `builders/tun-base`. The conflicts were digest
pins, both sides' entries in the selector's reviewed-version lists, the driver loader's
reason, and the bundle, scenario and unmapped lists and two sentences of the evidence doc
that the no-tray, SSH relay and update-row changes had moved; the pins were re-derived to a
fixpoint and no stale digest is left.
There the driver bundle holds 65 files, every `windows-native-cli` scenario is mapped, and
the matrix test `test_no_update_row_can_prove_a_scenario_today` is the update counting's
`test_the_update_rows_prove_their_scenarios_through_what_they_read_back`. RED re-ran in an
archive of `9a8db1e5` holding only the eight rebased test modules, and the publisher type
in the rebased tree with only the `9a8db1e5` template (the `1d9d239b` bytes): every type
gave the counts above on Python 3.14 and 3.12, the bundle now `65 != 64`. GREEN on the
rebased commit: OK for every type on both. The logs are under
`.runtime/tun-base/logs/redgreen/` of that clone, copied to
`.runtime/windows-parity-20261107/evidence/tun-grant/rebased/` of the recovery checkout.

### Windows scoped-TUN grant, review of `e65f8814`, offline (2026-11-13)

An independent review of the rebased grant commit `e65f8814` found five failure types its
regressions did not cover, and three rows of the section above whose RED never reached the
defect they name. `bcfa0322` closes them on top of `e65f8814` in `builders/tun-base`;
nothing here has run natively. RED for each new type ran in an archive of `e65f8814`
holding the final test modules (`.runtime/tun-base/red-e65f8814`). The section above's
types re-ran in the archive of `9a8db1e5` holding the final test modules
(`.runtime/tun-base/red-9a8db1e5`). Three more REDs ran in an archive of `bcfa0322` with one
unfixed rule put back at a time (`.runtime/tun-base/mixed-bcfa0322`, written by
`mixed_variants.py`). Each type ran in one unittest process, on Python 3.14 and 3.12, with
identical counts (subtests included); GREEN on `bcfa0322` was OK for every type on both.
The logs are under `.runtime/tun-base/logs/review/redgreen/` of that clone, copied to
`.runtime/windows-parity-20261107/evidence/tun-grant/review/` of the recovery checkout.
The new regressions run in the selector's pre-push agent tier and in Fast Checks; the two
Windows tests of the last row run in the Windows readiness native step.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A grant whose prompt the decision never answered was collected as the product's failure | `test_native_scenario_windows.TunGrantDecisionTests.test_a_grant_cancelled_by_its_prompt_fails_the_product_only_after_its_typed_approval`; `test_windows_tun_grant.TunGrantFamilyTests`: `test_a_failed_grant_receipt_names_the_known_end_its_owner_closed_with`, `test_the_grant_serves_its_one_collector_inside_the_run_and_releases_the_hold`; controls `TunGrantDecisionTests.test_a_failed_grant_needs_no_join`, `test_a_grant_that_failed_by_another_known_end_needs_no_join` | A final refusal of `windows-uac-decision` (a black display, a prompt later than its 30 s gate) types nothing, the prompt expires, and the product answers the restart `CANCELLED` with A kept. The stages close that as the known end `scoped-tun-grant-cancelled-known`, the driver retires the unused hold and exits 1, and collect, which read the decision only for a passed grant, settled the run `failed`: a failure of the product, which under TEST-007 blocks its requirement on that package. The receipt now names the owner's own known end, `tun.knownEnd`: the `knownFailure` of the driver's one `dedicated-proxy-lifecycle-known-closed` event in the evidence copy (`cancelled`, another code, none, or `unread`). Collect settles a grant that failed by `cancelled` only with the decision's terminal of a typed approval and a closed prompt (`approve-acknowledged-prompt-closed`); without it the run stays unsettled, as a deny row's pass does. Any other failure still needs no join. RED (3 tests): failures=12, errors=1: the cancelled grant was collected `failed` with no decision read, and no receipt named a known end. The controls pass on the unfixed source too. GREEN: OK. |
| The grant's off record took an exit that came before the product's own off | `test_windows_tun_stages.OffTests`: `test_the_off_is_asked_only_while_the_products_own_tun_runtime_runs`, `test_an_original_that_ended_before_the_off_was_asked_for_is_no_exact_off`, `test_an_exact_off_is_proven_by_both_exits_after_the_request` | The SYSTEM collector publishes the off record once both original handles signal, whatever ended them. `finish_off` checked only that they signaled and their creation times, and `begin_off` read nothing before the off, so a runtime that crashed after the last sample counted as the product's exact off. `begin_off` now requires the product's status to show its runtime running in VPN mode and takes the guest clock (`GetSystemTimePreciseAsFileTime`) just before the off. `finish_off` requires both originals' `exitFileTime` (the observer's `GetProcessTimes`) to be after it. RED (3 tests): failures=6: the off went out over a runtime that had ended, and exits before the off, or at the same instant, were accepted. GREEN: OK. Native only: both clocks on the fixture; a backward step of the guest clock between them fails closed and parks. |
| `exact-child-stop` counted a grant that has no sibling to spare | `test_native_scenario_windows_matrix.ExactChildStopTests.test_the_grant_and_sibling_off_pairs_never_pass_the_exact_child_stop`; `TableTests`: `test_the_table_names_every_windows_scenario_and_only_built_rows`, `test_the_document_tun_and_responsive_rows_prove_only_what_their_evidence_holds`; `test_windows_tun_stages.OffTests.test_the_exact_off_claims_no_sibling_it_never_had` | The matrix mapped `exact-child-stop` to `sibling-off` and the restart grant. `sibling-off` shows only that the unelevated proxy off spares a live sibling. No unrelated runtime runs beside the grant, and its closing census requires only that the runtimes left are a subset of the baseline, so an elevated broker that stopped every `sing-box.exe` by image would pass it as well; the off event's `noBroadProcessStop: True` was a constant. The scenario maps to `()` again until a grant variant keeps an owned sibling runtime alive through the product's off (T8), and the event says `siblingSurvivalObserved: false`. RED (4 tests): failures=4: passed direct and MCP pairs of the two rows passed the scenario, the table mapped it, and the event claimed no broad stop. GREEN: OK. |
| The direct sampler could reach its target through the guest's default route once the TUN was gone | `test_windows_tun_stages.DirectSamplerTests`: `test_with_the_tun_address_gone_the_real_socket_sends_nothing`, `test_every_sample_is_bound_to_the_generated_tun_address`, `test_each_sample_is_plain_http_to_the_benchmark_address_with_no_socks_step` | The only gate before the sampler's plain HTTP to `198.18.0.1:80` was the ready record, read once before it. Nothing tied a connection to the TUN, so a TUN gone after that record (a crashed runtime, a broker that ended its job) would send each sample out of the guest's default route, which on an unrestricted clone is the VM host's network. Each connection is now bound to the TUN's own address, `172.19.250.1` (`DesktopProxyConfigFactory`), before it connects. The first test runs the real sampler on real sockets: its own loopback listener as the target and an unassigned TEST-NET-1 address as the source, so nothing leaves the host. RED (3 tests): failures=3: unbound, both samples reached the listener with no TUN address to leave from (`0 != 2`), and no connection named a source. GREEN: OK; the bind fails and nothing is sent. Native only: Windows' strong host send on the fixture, under which a packet from `172.19.250.1` leaves only through the interface holding it, and that the samples still pass through the TUN with the bind. |
| No CI job compiled the publisher's observer type | `test_affected_agent_tests.WindowsNativeCausalEnrollmentTests`: `test_every_windows_test_of_the_publishers_observer_type_runs_in_windows_ci`, `test_readiness_native_step_runs_explicit_unaffected_controls` | Windows CI runs agent tests only through the explicit include lists of its native steps. None named `test_windows_tun_grant.WindowsCensusTests` or `test_windows_update_grant_collectors.WindowsReaderTests.test_the_publisher_backup_open_and_census`, the only tests that compile and run the template's `Add-ObserverType`: the census that the TUN grant and every update row load, and the update rows' backup reader. The Windows readiness native step of `.github/workflows/windows-desktop.yml` now runs both. The regression finds every test of those modules that loads the type through `observer_function` and requires the step to name it. RED (2 tests, the `e65f8814` workflow): failures=2. GREEN: OK. Neither Windows test has run yet: their first run is the next Windows Desktop Package run of a pushed SHA, and the census test's RED on the `9a8db1e5` template also needs a Windows host. |

Corrections to the section above. The driver row's RED never reached the unfixed driver:
its `DriverGrantTests` errored in `setUp` on the driver's `time` module, and the shared
peers on `TUN_COLLECTOR_SHA`, both new in the fix. The tests now take the clock and the
collector digest from what both sources have: the driver's `time` attribute, created where
it is missing, and `collector_contract.COLLECTORS["tun"]`. On `9a8db1e5` that type (15
tests) now gives failures=13, errors=25, and the causes are the unfixed driver's own:
`proxy-has-no-system-collector` for each grant that carries its hold (21 times),
`dedicated-finite-proxy-variants-only` for one without, no `tun_record` and no
`TUN_GRANT_VARIANTS` (one test each), and a harness that takes no hold (12). The
approve-join and profile-gate REDs above failed on the grant's admission refusal, not on
their own defects. In the archive of `bcfa0322` with only the `9a8db1e5` rule that a deny
row alone joins its decision, the approve-join type (4 tests) gives failures=7, errors=1: a
passed grant settled with no approval terminal in each of the seven decision cases. With
only the profile gate removed, the profile-gate test fails with `ValueError not raised`: a
grant admitted with no profile. The publisher type in the same archive with only the
`9a8db1e5` template fails as before, failures=2 (skipped=1), ending
`collector_stage_failed:tun:publisher_refused:collector-observe-tun:PUB_CENSUS_IMAGE`.
Every other type of the section above gave its recorded counts again with the final test
modules. Two notes above no longer hold: a grant whose prompt expired is not collected as a
failed run (the first row of this section), and `exact-child-stop` is not mapped to the
grant (the third).

Deferred, with what each needs:

- A product failure after the grant's TUN came up (its traffic, its off, its census) parks
  the owner. The SYSTEM collector keeps waiting on the live broker and runtime handles, and
  the job's synchronous collector program ends UNKNOWN at its 1800 s budget
  (`guest_program_deadline:collector-tun`), with no evidence copy. UNKNOWN blocks the
  requirement like a failed run, so nothing passes, but the run is not classed as the
  product's failure. A known end needs a change to the SYSTEM collector chain that the
  update rows share, whose park rule was reviewed: `caller_hold.driver_completed` accepts
  only result 0, and `system_collector_worker` waits only for both handles to signal. That
  is the coordinator's decision. What the product's own off does after each such failure,
  and how long it takes, needs native runs.
- The publisher's PowerShell observation (`Get-ProcessCensus`, `Get-CollectorObservation`
  with `tunNeed`, `Assert-ProductPin`) is no longer covered only by the fake peer that
  follows the template's text. The follow-up commit adds
  `test_windows_tun_grant.WindowsCollectorObservationTests`, which runs those template
  functions, as the template carries them, in Windows PowerShell. It uses a temporary
  operation root holding the task's two events, one need event and a child-intent event the
  observation must skip, plus a copy of `cmd.exe` named
  `<localAppData>\vpn-control\vpn-control-vpn-broker.exe` that starts `ping.exe`. The test
  requires: the need event and no child event; the broker together with its live child in
  the census; the workspace's `runtime-config.json` admitted as a product pin; and refusals
  for any other config path (`PUB_PRODUCT_PIN_PATH`) and for children of another image
  (`PUB_CENSUS_CHILDREN`). Every mutant the review ran (M1 to M4) changes one of those
  results. The readiness native step runs the test, and the enrollment regression above now
  names it. Its RED on the unfixed workflow (2 tests, both Pythons): failures=2, with the new
  test run by no step. Offline GREEN: OK. Still native: the test has never run (this Mac has
  no PowerShell). Its first run is the readiness step of the next Windows Desktop Package
  run of a pushed SHA. A Windows host also has to supply its own RED, on the `9a8db1e5`
  template and on each of M1 to M4, and its GREEN on HEAD. The product pin's `New-ReadPin`
  needs the rendered task natives, so this test only checks that the path is admitted.

### Update variants install-cancelled, participating-copy-lock, success-reconnect and its explicit-off twin, offline (2026-11-13)

Built offline in the clone `build-update-variants` on `9a8db1e5`; nothing here has run natively.
At `9a8db1e5` the three rows were refused before any journal
(`windows_scenario_update_cancel_actors_unobserved`, `_copy_lock_fixture_unavailable`,
`_reconnect_fixture_unavailable`). Building them exposed the failure types below. The unfixed
case module is preserved byte for byte as
`fixtures/windows_public_update_defects/update-cases.variants-before.source`. RED ran in a worktree
of `9a8db1e5` (`.runtime/update-variants/red-base` of the clone) holding only the new and changed
test modules and that fixture. Each failure type ran in its own unittest process, on Python 3.14
and 3.12 with identical counts. The logs are `.runtime/update-variants/logs/{red,green}{314,312}-<type>.log`.
Three reverted-fix mutants of the current sources (`.runtime/update-variants/mutants.py`, logs
`mutant{314,312}-<name>.log`) give the RED that the unfixed source cannot give. Either that source
fails earlier on another type, or the defect was found in review of this change.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A cancelled install was accepted with no observed installer actor | `test_windows_public_update_defects.UpdateVariantPairs.test_a_cancelled_install_passes_only_with_its_watched_coordinator_and_worker`, `UpdateVariantWorldTests.test_a_cancelled_install_names_its_watched_actors_and_waits_bounded`, `test_a_cancellation_the_product_never_ends_parks_with_its_reply_kept`, `test_the_watch_record_must_bind_the_job_its_tokens_and_both_exits`; `test_windows_update_grant_collectors.CancelWatchTests` (six tests); `test_windows_scenario_host_job.UpdateVariantJobTests.test_a_cancelled_install_is_watched_from_before_install_and_terminal_actors_names_the_watched_pair`, `test_a_watch_record_that_proves_less_leaves_the_owner_waiting_unknown` | The cancelled job's coordinator and worker live only from the approval to the product's own `CANCELLED`, and the product keeps no record of the coordinator. The before-install collector now publishes, then stays as a read-only SYSTEM watch of the installed helper image (`native_collector.watch_cancelled_installer`): each process is described once through its own handle; the handle of one naming the controller, or elevated, is kept, and its exit read from it. It publishes `cancel-actors` beside `before-install`. The job takes that record whole and only when it binds one job, the coordinator elevated as the approving administrator, the worker unelevated and born after it, both on the admitted helper, live and then gone, the watch armed first and no elevated helper left (`cancelled_install_actors`). Then `terminal-actors` asks for exactly those two. The case waits for `CANCELLED` at most 420 seconds and parks with the reply kept otherwise. `CancelWatchTests.test_any_other_before_install_publishes_once_and_never_watches` is a control and passes on both. RED: (12 tests) `FAILED (failures=18, errors=4)`: the job ends `collector_stage_unserved:before-install`, the unfixed case passes every watch record that proves less, and the collector has no watch (`KeyError: 'timedOut'`). GREEN: OK. |
| The owner's own `cancel-actors` need would have ended the row UNKNOWN (found in review) | `UpdateVariantJobTests.test_a_cancelled_install_is_watched_from_before_install_and_terminal_actors_names_the_watched_pair` | The case reads the watch's record through `native_evidence`, which writes an `update-native-observation-needed` event for `cancel-actors`. The system-run status lists every such event, and the job served only the row's collector stages, so the first status after the watch would have ended the row `collector_stage_unserved:cancel-actors`, UNKNOWN. The job now records `cancel-actors` as collected by the before-install request once that record has passed its checks, and the receipt names it beside `before-install`. The fake guest now asks for `cancel-actors` after its watch, as the case does. Found in review of this change before any native run, so the RED is the `cancel-need-unserved` mutant, the fix reverted in the current job: `(3, 'collector_stage_unserved:cancel-actors', 'unknown')`. RED: (1 test, mutant) `FAILED (failures=1)`. GREEN: OK. |
| success-reconnect had no connection fixture | `UpdateVariantJobTests.test_the_connected_row_publishes_the_profile_upstream_and_sampler_input_its_case_connects_through`, `test_a_disconnected_row_names_no_connection`; `UpdateVariantWorldTests.test_a_location_without_its_upstream_carries_no_traffic`; `test_windows_uac_decision.CancelledGrantUpdateTests.test_a_cancelled_connected_grant_closes_its_sampler_and_turns_off_before_it_quits` | The job passed `initialIntent` off with no profile and no traffic inputs. It now writes the loopback profile and the sampler input, and ships the in-guest SOCKS upstream (`socks_http_fixture.py`, port 41082) and the traffic worker, which the dedicated driver holds to their reviewed bytes (`upstreamFixture`, a closed input field). The case starts the upstream before any runtime names it, waits at most 30 seconds for its ready file and stops it after the returned cleanup. RED: (4 tests) `FAILED (failures=3, errors=1)`: `KeyError: 'upstreamFixture'`, `collector_stage_unserved:before-install`, and the unfixed case refuses the input (`finite-update-input-schema`). GREEN: OK. |
| The connection profile was a link the product's parser refuses | `UpdateVariantPairs.test_the_connected_case_adds_its_location_from_a_link_the_product_parser_takes` | The case demanded `socks5://127.0.0.1:<port>`, which `ProxyLinkParser` does not dispatch: the owner answers `INVALID_ARGUMENT` at `locations add`, as the proxy rows met natively. The profile is now `socks://127.0.0.1:41082#Update%20fixture`, whose port must be the upstream's. RED: (1 test) `FAILED (failures=1)`. GREEN: OK. |
| The returned owner of a connected update was read once | `UpdateVariantWorldTests.test_a_reconnected_update_restores_the_runtime_itself_after_the_owner_first_answers`, `test_a_returned_owner_that_stays_off_fails_within_its_bound` | DESKTOP-004 restores the intent at the returned owner's own start, which can follow its first answer. The case read one status and failed a reconnect still on its way. `await_reconnect` now reads it for at most 180 seconds after it first answers. It requires the same location in proxy-only mode and the whole outage within 900 seconds of the handoff, and records both times and both runtimes. On the unfixed module these tests stop earlier, at the profile, so the RED is the `one-returned-read` mutant. RED: (2 tests) `FAILED (failures=2)` on the unfixed module, at the profile. Mutant (2 tests): `FAILED (failures=2)`, the case ends `off-or-reconnect-intent-preserved` on an owner whose runtime was still on its way. GREEN: OK. |
| A participating copy had no fault inputs or `fault-ready` actor | `UpdateVariantJobTests.test_the_copy_lock_row_names_the_copy_it_started_at_fault_ready_and_ends_with_its_base`, `test_fault_ready_takes_only_the_copy_the_case_started`; `UpdateVariantWorldTests.test_the_fault_ready_record_must_name_the_copy_the_case_started`; `CancelledGrantUpdateTests.test_a_cancelled_copy_lock_grant_also_closes_its_blocking_copy` | The job passed no fault inputs, so the case refused its blocking copy, and no stage served `fault-ready`. The job now names a second workspace. `fault-ready` comes between `before-install` and `authorization` and names the copy the case started there: its pid, birth, unelevated ordinary token and the installed CLI's digest, from the SYSTEM census. `returned-cleanup` checks the case's recovery owner against the base, the package this row ends with, not the target. RED: (4 tests) `FAILED (failures=8)`: `collector_stage_unserved:before-install`, and the unfixed case ends `participating-copy-gate-native-busy` without checking the copy. GREEN: OK. |
| A participating copy was expected to end `BUSY` | `UpdateVariantPairs.test_a_participating_copy_ends_with_the_coordinators_documented_failure`; `UpdateVariantWorldTests.test_the_copy_lock_terminal_needs_its_diagnostic_and_the_copy_still_running` | The coordinator never stops a participating copy. Its inventory stage (`TryNoAdmittedInstallationCopies`, Restart Manager) never admits the copy, so the coordinator waits out its exit deadline. It then publishes `FAILED` `RUNTIME_FAILED` beside the protected `preinstall-diagnostic.json` `{"version":1,"stage":"INVENTORY","kind":"OTHER"}` (`windows-install-helper-sessions.cs`, `windows-install-helper-roles.cs`). The case demanded code `BUSY`, which no Windows coordinator publishes. It now requires that terminal, that diagnostic and the copy still running, and then closes the copy itself. RED: (2 tests) `FAILED (failures=2)`: `participating-copy-gate-native-busy`. GREEN: OK. |
| reconnect-off-preserved took its off half from a workspace with no location | `test_native_scenario_windows_matrix.TableTests.test_reconnect_off_preserved_is_proven_only_by_owners_that_had_a_location_to_reconnect_to`; `UpdateVariantWorldTests.test_an_explicit_off_survives_the_update_beside_a_location_it_could_reconnect_to`, `test_only_the_connected_explicit_off_catches_a_returned_owner_that_lost_its_off`; `UpdateVariantJobTests.test_the_explicit_off_twin_is_connected_the_same_way_with_its_intent_off`; `CancelledGrantUpdateTests.test_a_cancelled_explicit_off_grant_quits_its_off_owner_and_stops_its_upstream` | PRODUCT-005: an update keeps the prior on or off intent. `success-off` starts from a fresh workspace with no location, so no returned owner of it could run, whatever intent it restored: `test_only_the_connected_explicit_off_catches_a_returned_owner_that_lost_its_off` shows it passing a product that restores on. The new row `success-explicit-off` connects like `success-reconnect`, with traffic through its location, then turns off with the public `off` (DESKTOP-004: explicit off clears the intent). Its returned owner must stay off for the same 180 seconds, with that location still selected in proxy-only mode. `reconnect-off-preserved` now names it instead of `success-off`. RED: (5 tests) `FAILED (failures=5, errors=1)`: the matrix names `success-off`, and the unfixed case has no such row (`finite-update-input-schema`). The `one-off-read` mutant, which reads the returned owner once (2 tests): `FAILED (failures=2)`. It passes a late reconnect, and its watch lasts 1 of 180 seconds. GREEN: OK. |
| The rows stayed refused | `test_native_scenario_windows.UpdateTableTests.test_only_rows_with_a_producer_for_their_evidence_are_admitted`, `test_the_rows_agree_with_the_dedicated_driver_and_the_decision_table`, `test_only_the_connected_rows_carry_their_upstream_and_only_the_cancelled_install_watches`, `UpdateAdmissionTests.test_the_cancel_watch_copy_lock_and_connected_rows_are_admitted_before_any_journal`; `test_native_scenario_windows_matrix.TableTests.test_the_update_rows_prove_their_scenarios_through_what_they_read_back`, `test_the_document_tun_and_responsive_rows_prove_only_what_their_evidence_holds`; `test_native_scenario_execution.NativeScenarioExecutionTest.test_windows_names_are_closed` | `install-cancelled`, `participating-copy-lock`, `success-reconnect` and `success-explicit-off` are admitted, and the decision table, the dedicated driver, the execution and SSH allowlists name the new row. Their scenarios keep their matrix rows. Six of them now have no refused row: msi-uac-grant-denial, operation-progress-cancellation, traffic-continuity, ordinary-elevated-owner, participating-copy-locks and reconnect-off-preserved. RED: (7 tests) `FAILED (failures=5, errors=17)`: refused with the three old refusals, `KeyError: 'connected'`, and no `success-explicit-off` scenario. GREEN: OK. |

Pins renewed to a fixpoint (`.runtime/update-variants/renew_pins.py`, a second pass changes
nothing, and no file still names a base digest except preserved before-images and the selector's
append-only lists). The renewed pins are the SYSTEM collector chain (`hold_protocol`,
`collector_contract`, `caller_hold`, `collector_wrapper`, `system_collector_worker`), the
dedicated driver's case and module pins, the planner's `DEDICATED_DRIVER_SHA` and
`DEDICATED_CASES`, and the owner's held-driver literal. They also include the
`readiness_vm_dispatch.json` `sourcePins` of `windows_ordinary_task`, `windows_scenario_host_job`,
`native_scenario_windows`, `windows_uac_decision`, `native_scenario_execution` and
`native_scenario_ssh`, the reviewed-source rows of the updater and collector tests, and the
selector's loader lists (appended) and manifest entry.

Native only:

- The SYSTEM watch: `NtQueryInformationProcess` class 60 and `CommandLineToArgvW` through a held
  handle, and the product's coordinator and worker seen within its 50 ms polls.
- Whether the product honours a cancel sent while its prompt is up. `DesktopInstallHandoff.prepare`
  consults it only when its prepare returns not OK, so the approved coordinator may commit and end
  `FAILED` at its three-minute deadline instead. The case would then wait 420 seconds and park with
  the product's reply kept, never replayed. That would be a product finding.
- The coordinator's outcome for a participating copy, three minutes after the approval.
- The in-guest upstream on 127.0.0.1:41082, the product's reconnect after a real handoff, and a
  returned owner that stays off for 180 seconds.

The first discovery run of each row must show, in its evidence, the following:

- `install-cancelled`: `collectors/before-install/cancel-actors.json` with both actors.
- `participating-copy-lock`: a `fault-ready` record naming the `participating-installed-copy` child.
- `success-reconnect`: `update-upstream-ready` and then `update-reconnect-restored`.
- `success-explicit-off`: `update-explicit-off-before-update` and then `update-explicit-off-kept`.

### Different approving administrator and original-user worker, offline (2026-11-13)

Built offline in the clone `build-second-admin` on `9a8db1e5` (the wave of 2026-11-13 plus the
update-counting track); nothing here has run natively. Track T6 of the 2026-11-13 coverage
audit: `windows-public-update.different-admin` was refused at admission
(`windows_scenario_update_second_administrator_unavailable`). The fixture had one Administrators
account, `windows-uac-decision` typed only `final-administrator.secret` and its census expected
that account's SID in the pending event, and the job's context read only that SID. Nothing a
grant run recorded said who approved it, so no row could prove `different-approving-admin`
(`different-admin`) or `original-user-worker` (`success-off` and `different-admin`) of
windows-installer-lifecycle. RED ran in a worktree of `9a8db1e5` holding only the seven new and
changed test modules, one unittest process per failure type, on Python 3.14 and 3.12 with
identical counts (subtests included); every RED result is an assertion failure. GREEN ran on the
committed fix. Logs and scripts are under the clone's `.runtime/second-admin/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| No new clone could carry a second Administrators account | `test_windows_vm_unattend.SecondAdministratorTests` (three tests); `test_windows_vm_deploy_coordinator.SecondAdministratorStartTests` (three); `test_windows_vm_guest.SecondAdministratorQualificationTests`: `test_the_script_reads_the_second_administrator_as_it_reads_the_fixture_administrator`, `test_ready_only_with_an_enabled_administrator_of_its_own`, `test_its_facts_come_exactly_when_the_setup_names_it`, `test_secure_rotates_the_fixture_administrator_alone` | A setup may name `secondAdministrator`: a name of its own and no `purpose`. `windows_vm_deploy.start` makes `second-administrator.secret` beside the other credential files and sends it only on stdin. The clone's answer file creates the account in Administrators before the fixture administrator. A setup without it keeps its exact answer file, credentials, qualification and secure scripts. `parse_setup` and `answer_file` are compiled from source into the start and managed-create programs, so they name the key literally. A blank install refuses it (`deployment_second_administrator_clone_only`), because it becomes the next image template, and so does `generalize` of such a clone (`generalize_second_administrator`). Qualification reads the account like the fixture administrator, and `setupReady` also needs it enabled, an administrator and distinct from both fixture accounts. Secure still rotates only the fixture administrator's secret. RED (10 tests): `FAILED (failures=19)`, the setup refused `setup_fields` and the generalize program built. GREEN: OK. |
| The decision approved only as the fixture administrator | `test_windows_uac_decision.SecondAdministratorExecuteTests` (five tests) | `APPROVERS`, a closed table, names `different-admin` the one row the second administrator answers. Its decision types `second-administrator.secret`, its census expects that account's SID (read by its setup name) in the pending event, and a clone without the account refuses before contact (`uac_second_administrator_absent`). Inputs and input rules are unchanged: five fields, one reviewed frame with an empty field, the secret on stdin, then Enter. On a clone with two administrators the credential prompt offers both, so every approve profile there names its `approver` and an `account` crop (at most seven other crops, since `screen_gate` reads eight): a secret is typed only into a frame that shows its own account selected. The second administrator's profile is `install-helper.second-administrator.json`, made by `reviewed_uac_profile(..., approver="second-administrator", account=...)`. The review admits the row with the same census. RED (5 tests): `FAILED (failures=9)`: the two-administrator setup refused `uac_environment_unavailable`, the review refused, and on a one-administrator clone the row went on to open `final-administrator.secret`. GREEN: OK. |
| The job's context read and recorded only the fixture administrator | `test_windows_scenario_host_job.SecondAdministratorGrantTests` (four tests) | A plan whose row has an `approver` names `approvingAdministrator`. The context reads its SID beside the fixture administrator's, and the job grants with it: the case's `approvingAdminSid`, every collector request's, and the coordinator the authorization stage must find elevated. It ends `context_approving_administrator` before any task when that SID is the fixture administrator's or the ordinary user's, `context_unreadable` when it is unread, and refuses `approving_administrator_unplanned` when row and plan disagree. Every grant receipt records `update.approval`: `approver`, `approvingAdminSid` and the fixture `administratorSid`. RED (4 tests): `FAILED (failures=11)`, no approval in the receipt, and `different-admin` ending `collector_stage_unserved:before-install` with no grant stages. GREEN: OK. |
| `different-admin` was refused at admission | `test_native_scenario_windows.SecondAdministratorAdmissionTests` (three tests), `UpdateTableTests.test_only_rows_with_a_producer_for_their_evidence_are_admitted`, `UpdateTableTests.test_the_rows_agree_with_the_dedicated_driver_and_the_decision_table`; `test_native_scenario_windows_matrix.TableTests.test_the_update_rows_prove_their_scenarios_through_what_they_read_back` | `different-admin` takes the four grant collector stages and `approver: second-administrator`. It is admitted only on a clone whose setup names the account (`windows_scenario_update_second_administrator_absent` before any journal otherwise), and its job plan names that account beside the fixture `administrator`. The dedicated driver and the case module needed no change: both already end `different-admin` at `returned-cleanup` and hold its coordinator to the input's `approvingAdminSid`. RED (6 tests): `FAILED (failures=6)`, refused `windows_scenario_update_second_administrator_unavailable` on every clone. GREEN: OK. |
| The matrix never proved who approved a grant or as whom it installed | `test_native_scenario_windows_matrix.ApprovalTests` (three tests) | `_matrix_row` counts a grant run (a collector with an authorization stage) only with its approval proven from its own receipt (`_approval_facts`). The recorded approver must be the row's own, the coordinator ran elevated under the approving SID, and the worker ran unelevated as the ordinary user, who is neither administrator. The approving SID must differ from the fixture administrator's exactly for `different-admin`. A run whose package is proven but whose approval is not is `approval-unproven` and never counts. Each grant entry of the evidence names `approval` as the approver and those three facts. So `different-approving-admin` needs the `different-admin` pair, and `original-user-worker` needs it and the `success-off` pair. RED (3 tests): `FAILED (failures=18)`, every unproven run classed `passed` and no entry naming its approval. GREEN: OK. |

Controls: the update-counting tests pass unchanged except their run helper, which now writes the
approval a grant receipt carries; the qualification, replay and secure tests of
`GuestQualificationTests` also run on a two-administrator setup; one-administrator answer
files, qualification and secure scripts are byte for byte as before.

Mutants (`.runtime/second-admin/mutants.py`, Python 3.14, on the committed fix): 18 loosenings, each
turned red by the new tests. In the decision: typing `final-administrator.secret` for every row, the
census expecting the fixture administrator's SID, a profile without an `account` crop, never requiring
the account to be shown selected, and answering on a clone without the account. In the job: granting
with the fixture administrator's SID, accepting any approving account, no `update.approval` record, and
an approver the plan does not name. In the matrix: any administrator approving, any worker account, and
ignoring the approval altogether. Admission on any clone. Qualification ignoring the second account. The
answer file putting it in Users. A blank install allowed to carry it, start without its own secret, and
generalize of such a clone.

Pins renewed to a fixpoint (`.runtime/second-admin/renew_pins.py`; a second pass changed
nothing): the `readiness_vm_dispatch.json` `sourcePins` of `windows_vm_unattend`,
`windows_vm_deploy`, `windows_vm_guest`, `windows_uac_decision`, `native_scenario_windows` and
`windows_scenario_host_job`; the frozen `windows_vm_deploy.py` digest in
`test_windows_vm_deploy_release`; the selector's reviewed versions of the four declared loader
test modules (appended) and its entry for the dispatch manifest. `windows_vm_unattend.py` and
`windows_vm_deploy.py` are in `readiness_windows._source_pins()`, so any alias registered before
this change refuses and needs a new one.

Native only:

- That a clone's OOBE creates the account from the answer file, and that qualification reads it.
- Which account the credential prompt of a two-administrator clone offers first. The answer
  file creates the second administrator first in the hope that the prompt lists the
  Administrators members in the order they joined; the review frame shows it. If the prompt
  offers the fixture administrator first, the decision refuses `instance_uac_frame_unrecognized`
  and types nothing: a selection step, or the clone policy that makes the prompt ask for a user
  name (`EnumerateAdministrators` 0), would be a new reviewed input rule.
- That the second administrator's secret is accepted, and the coordinator then runs elevated
  under its SID while the worker runs as the original user.
- Every grant stage on that clone.

The first `different-admin` discovery run must show, on a new clone whose setup names the
second administrator, the context reading both SIDs, a review frame with that account selected,
`input-ack-only` with `promptClosed true`, the four collector stages, `update.approval` naming
`second-administrator`, the second administrator's SID and the fixture administrator's, the
installer coordinator elevated under the first and the worker unelevated as the ordinary user,
`installedAfter` role `target`, and a `passed` matrix row whose approval facts are all true.

### Windows document cache row, offline build and its review (2026-11-13)

`windows-document-cold.cache-bytes` was built in the `doc-cache` builder clone (`7e6ee369` on
`245b61a7`) and reviewed before it landed; the review's fixes are `154dae38` and `85e3aafe`. Nothing
here has run natively. The unfixed bytes are git objects: the owner at `245b61a7`, the rest at
`7e6ee369`. RED ran in isolated exports in the clone's `.runtime/followup/trees/`. The logs, the
mutants and the scripts that ran them are in `.runtime/windows-parity-20261107/evidence/doc-cache/logs/`
of the recovery checkout (`followup/` for the review). Every count is the same on Python 3.14.3 and
3.12.13.

When the review found a gap in the tests themselves, the RED is a mutant of the fix that brings back
the defect the test guards. On each such mutant the `7e6ee369` tests stayed green. GREEN on `85e3aafe`:
`test_windows_document_cache` 31 OK, and the matrix test below with `TableTests` 4 OK.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A document case's scoped trust reached every later child | `test_windows_document_cache.OwnerTrustTests.test_scoped_trust_a_document_case_gives_its_serve_reaches_no_later_child`, `CacheFlowTests.test_only_the_original_serve_trusts_the_source` | This was latent until the cache row: before it, the only document row that set `JAVA_TOOL_OPTIONS` was the responsive one, and that was the only row the owner removed them for after its serve. So the cache source's scoped trust store, meant for the original serve alone, also reached the readiness status, every public call, the cold serve and the quit. A JVM prints "Picked up JAVA_TOOL_OPTIONS" on stderr, which fails every public call's empty-stderr oracle. The owner now removes them right after the serve for every document case, and a row that sets none is unchanged. RED with the owner at `245b61a7` and the rest at `7e6ee369`: 1 failure each, `['serve'] != ['serve', 'public-cli', 'public-cli', 'public-cli', 'public-cli']`, and 22 later children under the options in the cache flow. Native only: the JVM's own stderr under the options. |
| The cache row alone closed `cache-digest-bytes`, although the product fails its truncated-bytes half | `test_native_scenario_windows_matrix.FailedAndUnknownTests.test_with_the_real_table_the_cache_row_proves_no_scenario_alone`, `TableTests`; `test_windows_document_cache.RowTests` | The row reads the committed cache back warm, closed and cold, but never changes or truncates the closed file. The scenario's Android anchor (`AndroidPreferencesSerializerTest`) decodes changed bytes and fails a read of bytes truncated by one. `DesktopStateStore.loadStoredWorkspace` instead writes the default workspace over a `workspace.json` that does not decode (read from source, not observed). A passed row would have recorded the scenario passed on a package that drops every subscription on such a file. The scenario now maps to no row, as `ssh-import-routing` does. That holds until the product keeps such a file aside and reports it, and the row corrupts the closed file and restores it before its reopen. RED on `7e6ee369`: a complete document set passed `cache-digest-bytes` (`('unmapped', 'unmapped') != ('passed', 'unmapped')`), with 2 `TableTests` failures and 1 in `RowTests`. Trade-off: until then the matrix cannot record a failure of this row; the row's own collection still reports it. |
| The cache source answered requests it never journaled | `test_windows_document_cache.SourceTests.test_a_request_the_stdlib_answers_itself_is_journaled_too_and_gets_no_body`, `test_it_serves_the_recipe_body_on_its_one_path_journals_each_answer_and_stops_on_its_record`; `CacheFlowTests.test_a_fetch_other_than_the_products_own_of_the_one_path_is_a_known_failure` (`stdlib-answer`, `not-a-get`) | Only requests that reached `do_GET` were journaled. The standard library answered other methods (501) and request lines or headers it could not parse (400, 431) itself, with no journal line. The owner's stop oracle, however, reads the journal as the complete record of who reached the source. The handler now journals those answers too, with the request's method, and sends them with no body, and the oracle accepts only the product's GET. RED on the `7e6ee369` source: an empty journal after four such requests (8 rows expected), and a request row with no method. On `7e6ee369` the oracle also accepted a journaled POST answered 200 (`not-a-get`). Native only: the guest's Python 3.13.15 was not run. |
| The flow tests' held-file pin ignored the read bound | `CacheFlowTests.test_the_cache_literal_is_read_within_the_cases_own_bound`, and every flow test | The case reads its literal input with `INPUT_LIMIT` (1 MiB), where `245b61a7` read 64 KiB, and the cache literal is about 140 KiB. The flow tests' pin returned the bytes whatever the maximum, but the owner's `Pin.digest` refuses with `held-source-bound`. So the `7e6ee369` tests stayed green with the 64 KiB read restored (24 and 20 OK), a change that would fail every native run of the row before its source starts. The fake pin now refuses as the owner's does. RED on the mutant `bound-64k`: all 18 flow tests (43 failures and 1 error, counting subtests), each `held-source-bound`. |
| No test placed the closed cache read after the original serve's exit | `CacheFlowTests.test_the_closed_read_is_of_the_file_the_original_serve_left_after_its_exit` | The "closed" moment must be read with the product closed: after the original serve's own exit and before any later owner of the workspace exists. The `7e6ee369` tests checked only the order of the three moments. RED on the mutant `closed-early`, which moves the read before the quit: 1 failure, a closed read before the serve's exit. |
| Four of the source's own refusals had no test | `CacheFlowTests.test_a_ready_record_an_oracle_refuses_ends_the_source_before_any_serve`, `test_a_stop_receipt_other_than_the_sources_clean_end_is_a_known_failure`, `test_a_journal_other_than_the_sources_own_count_and_order_is_a_known_failure`, `test_an_answer_the_source_did_not_send_whole_is_a_known_failure` | With the `7e6ee369` tests green, each of these clauses could be deleted: the ready-record check and its `refused:` code, the exit code and stderr of the stop receipt, the journal's count and ordinals, and `sent` on an answer row. Without the ready check, the serve would trust a source the record misnamed, and the refresh's TLS failure would then read as the product's. Each case now ends 1 with its code. A refused ready record also ends the live source with one termination before any serve exists. RED on one mutant each: `ready-unchecked` 6 failures, `stop-unchecked` 2 (exit 1, stderr), `count-unchecked` 2 (count, ordinal), and `sent-unchecked` 1 (an unsent answer that still names the recipe body). The other subtests check the same conditions' other clauses, which those mutants keep. |

The closed-state corruption step was added later ("Windows document cache row: the closed-state corruption
step", below); the row's first native run is still open.

### Readiness wake, budget and counter-start replies of clone 9059be98 (native, 2026-11-09)

The public MCP/CLI pass of clone `9059be98` (aliases `windows-raw9059be98-desktop-v1`
and `-lifecycle-v1`, tools `f31ab987`) ran while three new clones were built on the
same Arch host. It found five failure types and stopped at the first unlock of
section E under the unknown-outcome rule, leaving the clone locked with its display
asleep and journal record `22dbf542` open. The replies, section logs and packet
journals are under `.runtime/windows-parity-20261107/enroll-9059be98/` and
`.runtime/readiness-windows/` of the recovery checkout, the target journal under
`.rag_index/readiness-targets/4851e3fc…/`, and the native failures are `50f39815`,
`d09d630d`, `04d91d12` and `00e5bc48`. Measured on that clone that day: 70 observe
packets (median 28.2 s, p90 46.0 s, max 68.1 s), four wake packets (max 46.5 s) and
up to 22 s of admission before each packet.

The fixes were built offline on `f31ab987` and rebased onto `529cc610` after the Arch
host and the Mac had rebooted. The clone is stopped, its aliases are dead and no clone
is enrolled, so no sign-in is frozen any more. Of the 37
`readiness_windows._source_pins()` files, `readiness.py`, `readiness_windows.py`,
`readiness_windows_jobs.py` and `readiness_windows_remote.py` change (the last one for
the next section), so every Windows alias needs fresh evidence. The sign-in program
embeds the remote packet source: regenerated from the fixed tree, the clone's two
retained sign-ins (`92593d38`, `46e1189c`) no longer match, so the change has to land
before the next clone's first sign-in. Outside Windows, `readiness.py` is also pinned
by `readiness_tart_macos_registry` and `readiness_entrypoints` (the latter with
`readiness_lease_workflow.py`); `readiness_providers.py` keeps its bytes, so the
Android pins and wake proofs stay valid. `readiness.py` also travels in the child
bundle of `ssh_channel_keeper_entry`: one argv string of at most 131,072 bytes, which
`test_ssh_channel_keeper_entry` builds. That bundle takes about 129,950 bytes on
`529cc610` and about 130,700 with the fix, so the core change adds no comments; the
reasons live in this section and in `agent_tools/README.md`. A first draft with
comments reached 132,144 bytes and failed that module with `source_bundle_cap`. RED
ran on an isolated copy of `529cc610` holding only the new test modules, on Python
3.14 and 3.12. The three modules of this section: 25 tests, 16 failures and 2 errors
on both. All twelve causal tests fail with the native symptom, six fixed-only
controls fail or error because their path is absent, and seven invariant controls
pass. GREEN on the fix: 25 tests, `OK` on both. Logs are under `.runtime/logs/` of
the fix clone (`.runtime/windows-parity-20261107/builders/build-readiness-fixes`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| The readiness check refused when the display slept between its observation and its final revalidation | `test_readiness_wake_outcome.WakeOutcomeTests.test_04794d9d_display_asleep_at_revalidation_RED_refused_GREEN_woken_once`; controls `test_another_generation_during_bookkeeping_still_refuses_with_nothing_sent`, `test_fixed_a_display_that_slept_without_a_permitted_wake_refuses_with_nothing_sent` | Decision: a defect inside `ensure_ready`, and correct fail-closed behavior after an admission. Lease acquire `04794d9d` observed the display awake (35 s), and its revalidation after `reconcile_ready`, 36 s later, found it asleep: the cancel lease before it had just restored the display's own idle timer. It refused `prepared_context_stale` with nothing recorded, although `wake_display` was permitted. Inside `ensure_ready` that final check is now `revalidate(context, ready, identities_only=True)`, which returns its observation: another boot, account, session or connection still refuses `prepared_context_stale`, while the same identities that merely stopped being ready go back to the loop with that observation, which wakes the display within budget or refuses with its normal reason (`recovery_not_permitted` without a permitted wake). The route-level `revalidate` after an admission (lease acquire, counter start) stays fail-closed by design: the admission binds the ready identities, and the same operation re-prepares a proven-unsubmitted original. Native only: an acquire whose display sleeps during the check. |
| The 180 s readiness budget ran out during a wake under load, and the refused call left its delivered wake without an outcome | `test_readiness_wake_outcome`: `test_5d77b355_wake_under_measured_load_RED_deadline_GREEN_ready`, `test_5d77b355_refused_after_its_wake_RED_no_outcome_GREEN_delivery_retained`, `WindowsRetainedReplyTests.test_5dcaa820_retained_reply_RED_no_proof_GREEN_proves_the_delivered_wake`, `test_04794d9d_at_the_measured_maxima_RED_wake_budget_below_338_8_s_GREEN_ready`, `test_a_recorded_unsettled_wake_RED_costs_each_counter_start_an_observation_GREEN_none`, `RegisteredAliasAdapterTests`, and the `WindowsAdapter` check in `test_windows_managed_admission.ManagedOriginalTests`; controls `test_a_caller_cap_still_wins_over_the_wake_budget`, `test_no_input_submitted_a_refused_reply_another_recovery_or_an_altered_reply_prove_nothing`, `ProviderAcceptanceTests` | Lease acquire `5d77b355`: observe 41.9 s, wake packet `5dcaa820` 46.5 s (`submitted`, `wakeInputSubmitted: true`), then the next observe was cut at the 180 s deadline: `readiness_deadline`, and journal `22dbf542` kept a consumed dispatch without any outcome. `WAKE_BUDGET` (420 s) applies once the next action is a wake: 3 × (68.1 + 22) + (46.5 + 22) = 338.8 s measured, with about a quarter of margin. A shorter caller cap still wins, and the 180 s and 600 s budgets are unchanged. Right after a wake returns, the loop asks the provider for proof of delivery. `WindowsBackend.reconcile_recovery` reads only its own retained packet: the source's `MODE`, `OPERATION` and `RECOVERY_ID`, the callback (return code 0, source hash, sizes), the reply equal to its stdout with `state: submitted`, `guest: running`, `wakeInputSubmitted: true`, and the same machine, provider, operation and host boot. `readiness_windows.WindowsAdapter`, the `ProviderAdapter` subclass of the Windows aliases, accepts the new `RecoveryAcknowledged` only for `wake_display` and the exact dispatch (the shared `ProviderAdapter` still refuses it), and the journal records `acknowledged-<id>-<attempt>.json`, never for a proven-unsubmitted attempt; an acknowledged attempt can no longer be proven unsubmitted. `record_acknowledged` says whether it created that record, and only a new record makes the loop observe again: every later ensure proves a delivered wake again from the retained reply until it settles, and in `3f3ebd75` each such ensure paid one more observation, so a headless counter start at the measured maxima (two observations, 180.2 s) refused `readiness_deadline`. Both Windows loaders build `WindowsAdapter`; the core swallows the shared adapter's refusal of the proof, so a loader that built it would drop every acknowledgement silently, which `RegisteredAliasAdapterTests` (schema 1, through one real wake packet) and the managed check (schema 2) now catch. The maxima test pins the budget on the path it was sized by: at 260 s that path refuses `readiness_deadline` after 338.8 s. Native only: the 420 s budget under the same load. |
| An acknowledged wake whose effect had expired was never settled, so every later interactive ensure of that session ended `recovery_outcome_unknown` | `test_readiness_wake_outcome`: `test_9c93fd36_locked_and_asleep_in_the_wakes_session_RED_outcome_unknown_GREEN_settled_then_wake_and_sign_in` (the native state), `test_9c93fd36_expired_delivered_wake_RED_outcome_unknown_GREEN_new_wake_and_ready`, `test_22dbf542_pre_fix_journal_RED_outcome_unknown_GREEN_settled_from_the_retained_reply`, `test_recovery_status_RED_outcome_unknown_GREEN_acknowledged_then_settled`; controls `test_a_lost_wake_reply_is_never_settled_or_replayed`, `test_a_headless_observation_never_settles_a_delivered_wake`, `test_another_session_never_settles_the_old_sessions_wake_by_its_delivery`, `test_fixed_a_proof_for_another_dispatch_fails_closed`, `test_fixed_a_delivered_attempt_is_never_proven_unsubmitted_later` | Unlock `9c93fd36`, 35 minutes after `5d77b355`: the status right before it (`152459`) showed the session locked with its display asleep, in the boot, account and session of `22dbf542` (`1:134386955862966249`). `_next` chose the wake first for the locked, sleeping session, `22dbf542` was still a consumed dispatch without an outcome, so the call observed it to its deadline and refused `recovery_outcome_unknown` with nothing dispatched and nothing typed. The journal now settles a wake that has a retained acknowledgement when the next interactive observation of the same boot, account and session finds the display asleep again (`completed-<id>.json`, state `acknowledged`, bound to the acknowledgement), whether the session is ready or locked; an awake display still settles any wake as before (`observed`). In the native locked state the call then sends one new wake and one sign-in and ends ready; a rule limited to ready sessions would refuse `recovery_outcome_unknown` again, which the locked test catches. A later sleep then gets a new recovery generation, and the original dispatch is never replayed. A journal written before the fix, with no acknowledgement record, is settled the same way once the backend's retained reply proves the delivery. A lost or refused reply, a headless observation and another session settle nothing. `readiness_recovery_status` reports `acknowledged` (not pending) and `acknowledged_complete`, with `deliveryAcknowledged` and `completionAcknowledged`. Native only: an ensure that follows a delivered wake after the display slept again, on the next clone. Record `22dbf542` itself can no longer be settled natively: its clone is stopped and that boot is gone. A wake whose reply was lost still stays open until the display is seen awake or the fixture reboots; the host keeps that wake's own `readiness-recovery-<id>.result.json`, but no route settles the journal from it yet. |
| After its admission the counter start answered `blocked/readiness_deadline` under an internal packet operation | `test_windows_job_start_after_admission.StartAfterAdmissionTests`: `test_f4fdee43_job_start_target_ran_then_its_budget_was_spent_RED_blocked_internal_GREEN_unknown_original` (the native trigger), `test_a_refusal_raised_after_the_job_start_target_ran_RED_blocked_GREEN_unknown_original`, `test_a_refusal_of_the_submit_after_its_admission_RED_blocked_GREEN_unknown_original`, `test_a_refusal_of_the_follow_up_after_an_admitted_submit_RED_blocked_GREEN_the_admitted_answer`, `test_reconcile_after_its_packet_ran_RED_blocked_GREEN_cached_original`, `test_a_repeated_start_after_its_packet_ran_RED_blocked_GREEN_observes_the_original_like_a_reconcile`, `test_a_spent_follow_up_status_RED_blocked_internal_GREEN_the_submits_admitted_answer`, `test_reconcile_spent_RED_blocked_internal_GREEN_retained_original`; controls `test_an_identity_refusal_after_the_admission_answers_the_admitted_original_and_reconcile_still_refuses`, `test_a_refusal_before_any_admission_stays_a_refusal_with_nothing_recorded`, `test_an_identity_refusal_before_any_admission_names_the_public_operation`, `test_fixed_a_transport_timeout_of_the_follow_up_keeps_the_admitted_answer` | MCP start `f4fdee43` (467 s): its admission `intent.json` was written at 15:01:56. Inside `executor.submit`, job-start controller `2fa04c5b` (attempt `fa89f9d8`, 15:02:03) sent its 123,696-byte packet through the saved-program route (correlation `59d80918`, whose `program.source` execs exactly that packet from base64). The target ran and returned, and the transport's revalidation after the return ran out of budget (`returned-readiness-changed.json`, `readiness_deadline`, 15:03:12), so `run_ssh` raised `SubmittedResultReadinessChanged` and the route answered `blocked/readiness_deadline` under `2fa04c5b` with "original guest program admission is incomplete". No follow-up status ran: the only job-status controller (`89b26ca6`) is the later reconcile's, which found the original terminal, 80 values, exit 0. The start that wrote `intent.json` now never answers with a refusal after that record: any readiness refusal of the submit answers `windows_job_submission_unknown`, any refusal of the follow-up keeps the submit's admitted answer (`unknown`, `original_owner_ack_pending`), both with `reconcile_original`, and the answer equals what status then gives. `3f3ebd75` settled these by reason only, so a refusal raised after the target ran with another reason, for example `connection_outcome_unknown` from the transport's own observation, still answered `blocked/resolve_blocker` (review of `3f3ebd75`). A lasting refusal is not hidden: the original's reconcile still reports it under the caller's operation. A reconcile, like a repeated start of the same operation, answers a spent budget, or a refusal raised after its own packet ran, with its cached original; before the admission a refusal stays a refusal under the caller's operation with nothing recorded. |
| Cancel repeats left `*.cancelled.json.<uuid>.tmp` files | `test_lease_cancel_temporary_files`: `ExternalCancelRepeatTests.test_e78a3ca9_cancel_repeats_RED_temporary_files_GREEN_none`, `AndroidCancelRepeatTests.test_cancel_repeats_RED_temporary_files_GREEN_none` | The CLI and MCP cancel repeats of lease `e78a3ca9` answered `cancelled` and `terminal` correctly, but each left a temporary copy: `durable_remote_job._publish` writes the temporary file, and its create-only link refuses the existing marker before the unlink. Both cancel paths run under the admission lock, so a repeat now validates the retained marker and never starts another publication. The leak itself is in `durable_remote_job._publish`. That file stays unchanged on purpose, also now that no clone is frozen: its bytes ship as the remote owner module of SSH durable programs, and its hash is pinned by `readiness_tart_macos_lease_qualification` and `readiness_windows_creator_prevm_recovery`, so a change there would cost the macOS lane a new native qualification for a leftover file. Other callers that catch `FileExistsError` around `_publish` (the macOS lease bridge and registry) were not observed natively and are unchanged. |

### Idle census: a lost setup qualification and another clone's start in flight (native, 2026-11-08/09)

Two refusals of the full Windows idle census, taken up with the fixes above. Clone
`be766f0c`: its MCP setup qualification `dea00558` of 2026-11-08 ended `unknown`
(`instance_effect_or_observation_unknown`, failure class `OSError`, native failure
`80a38b34`). Nine status reads of it ended `unknown` too, with class `ValueError` and
no check name (native failure `1d5509db`), and a new qualification `383aff75` then
observed the setup. The original's `qualification-dea00558-….intent.json` stayed in
the VM root, so the full idle census of 2026-11-09 (`b01d37c6`, under
`.runtime/windows-parity-20261107/enroll-be766f0c/`) reported it as
`original_guest_work_unresolved` and the clone could never be positively idle. Clone
`9059be98`: its idle census `f1a9c53a` named the `reservations` blocker with complete
visibility at 13:40:39 and passed at 13:41:57 (`enroll-9059be98/idle-02.out`). RED
and GREEN ran with the section above. The new module on the isolated copy of
`529cc610`, on Python 3.14 and 3.12: 12 tests, 6 failures on both. Its three causal
tests fail with the native reason, three fixed-only controls fail because the rule is
absent, and six invariant controls pass. GREEN on the fix: 12 tests, `OK` on both.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A setup qualification whose reply was lost stayed `original_guest_work_unresolved` in every idle census | `test_windows_qualification_lost_reply.LostQualificationTests`: `test_dea00558_agent_forgot_the_acknowledged_qualification_RED_unresolved_GREEN_closed`, `test_census_during_an_in_flight_qualification_RED_closed_before_its_ack_GREEN_open_until_its_own_end`, `test_ended_qualification_the_agent_still_holds_RED_unresolved_GREEN_retained_as_its_owners_terminal`; controls `NeverClosedTests` (with `test_an_unacknowledged_qualification_stays_open_whether_or_not_another_shell_runs`), `ReviewedSourceTests` | `host_work` in `readiness_windows_remote.py` closed a lost read-only guest program only under a `readiness-<id>-<label>` name. A `qualification-<id>` name carries no label, and `qualify_instance` writes `readOnly: true` for every program it is given, so neither the name nor the flag proves anything. The census now also treats a qualification as read-only when its retained `.ps1` is one private file, has the hash its intent names, begins with this fixture's accounts and that operation, and continues with exactly the reviewed text of `windows_vm_guest.READ_SETUP` (sha256 `9ca4ce27…`, thirteen cmdlets, none of which writes). It then closes like the other read-only programs. An acknowledged one that the agent no longer tracks closes when its pid is absent from the same complete process census (`.orphan-closed.json`). An unacknowledged one stays open: `qualify_instance` saves its intent and `.ps1` before its guest-exec and takes no lock the census holds, and the census reads its process rows before it lists the receipts, so it cannot tell a lost reply from a guest-exec that has not started. `3f3ebd75` closed it with a marker without a pid, and once the acknowledgement appeared that marker kept the qualification open for good (review of `3f3ebd75`). An ended one that the agent still holds is collected once and retained as `<prefix>.terminal.json`, the only receipt its owner reads, so `qualify-status` still answers. A mutating program under that name (the control runs the real `secure_source` text), other accounts, another operation's program, the visual fixture's own qualification program, any added statement, an unbound or unretained source, a shared or non-private file, a live pid, a lost transport, `direct-guest-` and effectful labels all stay open. A program that is not proven read-only is never asked about, so its terminal is never consumed. A change to `READ_SETUP` fails `ReviewedSourceTests` until its new hash is reviewed into the packet. `dea00558` fits the acknowledged case: its status reads failed with a `ValueError` and no check name, as `guest-exec-status` fails for a forgotten pid, while a missing acknowledgement fails that read with an `OSError` (`read` of the absent `.ack.json`). A qualification whose guest-exec reply is lost before its acknowledgement still blocks the census; closing it needs a lock that the deploy packet shares with the census, a change to the pinned deploy sources that is not made here. Native only: a qualification whose reply is lost on the next clone, if one occurs. |
| The reservation proof blocked the idle census while another clone's start was in flight | Control, no code change: `test_readiness_reservation_observation.ReservationObservationTests.test_f1a9c53a_another_clones_start_in_flight_blocks_by_name_until_its_own_start_marks_it_running`, beside the existing `test_pending_and_unknown_competing_claims_block_dispatch` | Decision: correct fail-closed behavior. `windows_vm_deploy.start` reserves its claim as `pending`, records an `unknown` active job right before it submits, and marks the claim `running` only after its own boot observation and a fresh census; in between its VM is live. The proof named `reservations` with complete visibility, its designed answer to a competing lifecycle phase, and passed 78 s later without any repair. A pending claim does not count as settled because a VM of its size is live. The census rows carry a pid, start ticks, memory and a command hash but no deployment identity, so a match could only mean equal memory, and the claim's own record still says its outcome is unknown. A reboot must not overlap another clone's unfinished start on the same host. The refusal of the same clone at 12:10 was a different check, running claims above the live VMs' memory (`diagnose-reservations-01.out`), and `windows-vm-deploy-release` fixed it. The control replays both observations and passes before and after. Open, not changed here: `_mark_running` runs only inside `start`, so a start whose own call does not end `booted-observed` leaves its claim pending with an unknown job, `windows-vm-deploy-release` refuses a pending row, and every lifecycle census on that host then keeps this blocker. |

### Review follow-up of `3f3ebd75` (offline, 2026-11-13)

An independent review of `3f3ebd75` reported seven findings. Each was checked offline
against the code and the retained native files, and the rows of the two sections above now
carry the changes and regressions. Three findings were defects in code, three were gaps in
the regressions, and one named the wrong native path.

| Finding | Outcome | Regression |
| --- | --- | --- |
| The counter start still answered a refusal after its job-start target ran | Fixed in `readiness_windows_jobs.py`: the start that records an admission never answers a refusal after that record | `test_a_refusal_raised_after_the_job_start_target_ran_RED_blocked_GREEN_unknown_original` and the four other new `RED_blocked` tests of `test_windows_job_start_after_admission` |
| Proving a recorded wake acknowledgement again cost every later ensure one more observation | Fixed in `readiness.py` | `test_a_recorded_unsettled_wake_RED_costs_each_counter_start_an_observation_GREEN_none` |
| The idle census could close a setup qualification before its guest-exec started | Fixed in `readiness_windows_remote.py`: only an acknowledged qualification closes | `test_census_during_an_in_flight_qualification_RED_closed_before_its_ack_GREEN_open_until_its_own_end` |
| Nothing checked that both Windows loaders build `WindowsAdapter` | Test gap closed | `RegisteredAliasAdapterTests`, the managed check |
| The `9c93fd36` regression used a ready session, while the native one was locked | Test gap closed | `test_9c93fd36_locked_and_asleep_in_the_wakes_session_RED_outcome_unknown_GREEN_settled_then_wake_and_sign_in` |
| The `f4fdee43` regression replayed a follow-up status that never ran natively | Attribution corrected | `test_f4fdee43_job_start_target_ran_then_its_budget_was_spent_RED_blocked_internal_GREEN_unknown_original` |
| The measured-load tests held only for `WAKE_BUDGET` above about 258 s | Test gap closed | `test_04794d9d_at_the_measured_maxima_RED_wake_budget_below_338_8_s_GREEN_ready` |

RED ran on isolated copies of `3f3ebd75` and `529cc610` holding the changed test modules,
and GREEN on the follow-up, each on Python 3.14 and 3.12 with the same per-test outcomes.
On `3f3ebd75` the three code findings fail with their symptom:
`test_windows_job_start_after_admission` 12 tests, 14 failures (`blocked/<reason>` under the
public operation), `test_readiness_wake_outcome` 22 tests, 1 failure (`readiness_deadline`
after two observations), `test_windows_qualification_lost_reply` 13 tests, 2 failures
(closed before its acknowledgement). On `529cc610` the same modules end with 20 failures and
1 error, 14 failures and 2 errors, and 6 failures, and the managed check fails. There the
corrected `f4fdee43` replay ends with the native `blocked/readiness_deadline` under an
internal operation, and the locked `9c93fd36` case with `recovery_outcome_unknown`. The
test-gap regressions pass on `3f3ebd75` and fail on the mutant each finding names: the
`529cc610` loader line (schema 1, then schema 2), a settle rule limited to ready sessions,
and `WAKE_BUDGET = 260.0`. The `3f3ebd75` versions of those modules stay green on them.
With the submit-path handling of `3f3ebd75` deleted, the corrected `f4fdee43` replay fails;
of the old tests only the plain submit-path one did, and the old `f4fdee43` test stayed
green. GREEN: the four modules, 48 tests, `OK` on both. Logs are `.runtime/logs/followup-*`
of the fix clone.

### A UAC review reached its census past the 90 s rule (native, 2026-11-13 and 2026-11-16)

Runs `d476687a` (2026-11-13, coordinator load about 17) and `a47da155` (2026-11-16, load about 5) of
`windows-scoped-tun.restart-deny` on clone `192e5a3d` with the 2.2.17 package: the operator helper
called `windows-uac-review` on the first poll that reported `uac-pending:vpn-broker:deny`, and each
call refused `instance_uac_prompt_age` (100.7 s and 86.2 s). The local journals give the split. The
helper slept 5 s and asked status, two SSH reads with their admissions: a round took 44 s and 61 s, so
the token was seen up to that late. From the call's start: 24.6 s and 29.6 s to the review's attempt
journal (CLI, gates, the dispatch admission, the scenario driver's import and a context read over SSH);
11 s and 13 s more until the transport journaled the 115,772-byte carrier; 12 s and 13 s staging it
over a second SSH connection; 24 s and 12 s of custody checks until its execution; 28 s and 17 s for
the packet, its lock, session read and census. The census saw the prompt 90 s or older at most 100 s
and 85 s after the call began, so even a token seen at once left no time. Evidence:
`.runtime/windows-parity-20261107/family/d5D-review.out`, `d5D2-review.out`, `family/uac/`,
`.runtime/windows-uac-reviews/{0559112d,0d4926a2}-*/` and `.rag_index/ssh-automatic-program/{488a5f5c,f659737e}*/`
of the recovery checkout. The receipts were never collected (`collector_unavailable`), so the prompt's
own birth time is bounded only by the census.

Built offline on `450b8764` in `builders/fix-uac-age`; nothing below has run natively. The rule is
unchanged: 90 s at the census and again at the decision's burn. The review keeps the same bound, since
it is the decision's rehearsal and a looser bound would hide the decision's budget. RED ran in an
archive of `450b8764` holding only the changed test module, on Python 3.14 and 3.12 with identical
counts: `Ran 8 tests`, `FAILED (failures=9, errors=9)` with subtests, every test but the carrier
control. GREEN: the whole module, 162 tests, OK (2 skipped), on both. Logs: `evidence/uac-age/test-logs/` of the recovery
checkout's parity folder.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The packet was staged over a second SSH connection | `test_windows_uac_decision.InlineCarrierTests.test_every_uac_packet_goes_inline_in_one_ssh_child`; control `test_the_carrier_runs_its_packet_and_reads_stdin_as_before` | Every UAC packet is deflated into an inline carrier of 24 to 33 kB (the visual route's 28 to 30 kB), under `INLINE_CARRIER_BYTES`, so `ssh_transport.build_ssh_argv` keeps it inline. The retained attempt source and its digest are unchanged. RED on `450b8764`: the four packets take 94,183 to 125,267 argv bytes. |
| The context was read over SSH at the prompt | `RetainedContextTests.test_the_action_reads_the_kept_context_and_no_driver`, `test_without_a_kept_copy_the_action_reads_once_and_the_driver_keeps_it`; control `test_a_kept_context_is_checked_as_a_read_one_is` | The driver keeps the job's context as first read, create-only and private; the action reads that copy, checked as a read one is, with no SSH and no driver import. Each attempt that sent a packet keeps `attempt-NNNN.timing.json`. RED: the action reads the context over SSH at the prompt (`a host read at the prompt`) and keeps nothing. |
| The token was seen one status round trip late | `PromptWaitTests.test_the_token_comes_back_when_the_event_lands_not_at_the_bound`; controls `test_a_decided_prompt_or_an_ended_job_is_not_pending`, `test_the_wait_is_bounded_and_only_for_a_prompt_row` | `NativeScenarioWindowsDriver.wait_uac_pending` is one host read of at most 60 s over the job's status copy, polled every quarter second, with no lock, QMP, QGA or guest; the test runs the real host program. The private helper's change to use it is `evidence/uac-age/register_and_run.patch`. RED: the driver has no wait. |

Pins renewed: `readiness_vm_dispatch.json` `sourcePins.windows_uac_decision` and
`sourcePins.native_scenario_windows`, and the selector's `nonPythonResources` entry for that manifest.
No file of `readiness_windows._source_pins()` changed. Native only: the time each phase now takes, read
from the helper's timestamped lines and the attempt's `timing.json`; that the deflated carrier runs on
the VM host's Python; and that the census then finds the prompt well under 90 s.

### Find Best under VPN on Windows, offline (2026-11-16)

The T7 report left three gaps that refused `windows-scoped-tun.find-best-deny` and
`find-best-grant` (`windows_scenario_tun_find_best_unproven`). This change closes all three.

| Failure type | Regression | Cause and fix |
| --- | --- | --- |
| A late UAC prompt ended the decision | `test_windows_uac_decision.ExecuteInputTests.test_a_late_prompt_is_not_yet_for_a_bounded_number_of_gates`, `ReviewExecuteTests.test_a_not_yet_refusal_permits_another_review_and_any_other_ends_them` | Find Best validates every candidate before it prepares the broker, so its prompt follows `scoped-tun-awaiting-current-input` by a time that no gate bounds. A 30 s gate that found no consent prompt refused with `instance_uac_consent_absent`. That code was not a "not yet" refusal, so the decision ended and the prompt expired. Now `_final_refusal` treats it as "not yet" for `LATE_PROMPT_GATES` = 3 gates, counted over every attempt of the operation (including one learned by status), and only then as final. The 90 s prompt-age rule (`instance_uac_prompt_age`) and every other final refusal are unchanged. Reviews share the rule. |
| Find Best's denial read as a restart's | `test_windows_tun_stages.FinishTests.test_a_find_best_denial_is_its_cancelled_start_alone` | On a restart, `PERMISSION_DENIED` counted as a denial. `DesktopFindBestService` ends at its first `CANCELLED` start (the broker maps 1223 to `CANCELLED`) and restores A, but any other failed start makes it try its next candidate, which raises a prompt of its own. `windows_tun_stages.denials` now accepts only `CANCELLED` for Find Best; `PERMISSION_DENIED` is a known end. A denial still keeps A and pending B (`kept`), because Find Best starts with `commitSelectionOnSuccessOnly`. |
| A granted Find Best's selection was unchecked | `FinishTests.test_a_granted_find_best_selects_its_winner_a_or_b_and_nothing_else` | The selection moves only when the elevated start succeeds, and then to that winner: the first verified candidate by connect time. A and B reach the one owned endpoint, so either can win. If A wins, it replaces the pending selection of B. `find_best_selection` requires selected = active, which must be A or B and never a third location, and records the winner in `scoped-tun-public-outcome`. |
| Rows refused, no decision rows, unmapped | `test_native_scenario_windows.ScopedTunTableTests.test_every_tun_row_is_admitted_with_its_decision_row`, `ScopedTunAdmissionTests.test_the_find_best_rows_are_admitted_as_the_restart_rows_are`, `test_windows_tun_grant.DriverGrantTests.test_a_find_best_grant_takes_the_restart_grants_route`, `test_windows_uac_decision.PacketTests.test_table_values_are_what_the_case_modules_publish`, `test_native_scenario_windows_matrix.TableTests.test_the_document_tun_and_responsive_rows_prove_only_what_their_evidence_holds` | `windows_uac_decision.ROWS` gains `find-best-deny` and `find-best-grant`, and the planner gives both rows their `uac` block and join. The grant needs the reviewed vpn-broker profile. The driver admits both rows, with the grant on the restart grant's collector route. `windows-native-cli:find-best` now also names both TUN rows. Neither row runs Find Best while a TUN is already up, so CONFIG-011's "whether VPN is active" stays unclaimed. |

RED on `786cfda9` sources with the final tests, and GREEN on HEAD, on both Pythons: see the
find-best-tun REPORT.txt. Still native: how long Find Best validates before its prompt on the
fixture; whether three gates cover it; which candidate wins; and every TUN-route item that
T7 left native.

### Windows scoped-TUN configuration and fault variants, offline build (2026-11-16)

Built offline in the scratch clone `builders/build-tun-variants` on `786cfda9` (the settled
TUN grant); nothing here has run natively. RED ran in an archive of `786cfda9`
(`.runtime/tun-variants-red`, removed after use) holding only the new and changed test
modules, one unittest process per failure type, on Python 3.14 and 3.12 with identical
counts (subtests included). The fault and configuration regressions build the lease that
`begin` leaves rather than calling it, so each fails on its own cause on the unfixed
source and not only on `begin`'s missing document argument. The logs are the build
clone's `.runtime/tun-variants-logs/{red,green}-{314,312}-<type>.log`, copied to
`.runtime/windows-parity-20261107/evidence/tun-variants/test-logs/` of the recovery
checkout.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The TUN halves of `prepare-commit-recovery`, `generated-custom-config` and `large-config` had no row, so the three scenarios stayed unmapped | `test_windows_tun_variants.PlannerVariantTests`; `test_native_scenario_windows.ScopedTunTableTests` (`test_the_rows_are_the_stages_variants_on_the_proxy_action`, `test_the_restart_rows_are_admitted_and_each_find_best_row_names_what_it_lacks`, `test_each_prompt_is_the_decision_tables_and_a_denial_joins_its_terminal`); `test_native_scenario_windows_matrix.TableTests`; `test_windows_uac_decision.PacketTests.test_table_values_are_what_the_case_modules_publish`; `test_windows_tun_stages.GeneratedInputTests`; `test_native_scenario_windows.TableTests` (`test_the_closed_names_agree_everywhere`, `test_setup_rows_are_never_evidence_and_product_rows_name_their_package`, `test_the_worker_doors_are_constants_of_their_rows`); `test_native_scenario_execution.NativeScenarioExecutionTest.test_windows_names_are_closed` | RED failures=14, errors=18: no such variant in `TUN_VARIANTS`, the scenarios mapped to `()`, no decision row, `proxy_variant` for every new harness, no sampled set (every grant sampled), and the closed name tables of `native_scenario_execution.WINDOWS_SCENARIOS` and `native_scenario_ssh`'s artifact roles without the new rows. The planner keyed a grant, its sampler and its approval on a `-grant` suffix; it now names the grants, the sampled grants, the document variants and the one variant with no prompt. `vpn-prepare-failure` has no decision row, profile gate or join; `vpn-commit-failure` is approved and joins its approval but has no collector. |
| A TUN row could select only `Owned B`, so no TUN row could carry a configuration or fault document | `test_windows_tun_variants.VariantBeginTests` | RED errors=12: `begin()` took no document cases. The stages now publish the proxy rows' own documents through `windows_runtime_branch_cases` (generated SOCKS, CUSTOM, large CUSTOM beyond the inline limit, unsupported inbound, owned-conflict listener), add and read back the location, then select it in VPN mode. The variant with no prompt publishes `scoped-tun-request-accepted`, never the pending event a decision would wait on. |
| A preparation failure in VPN mode was a known failure, never the row's pass | `test_windows_tun_variants.PreparationFailureTests` | RED failures=1, errors=1: `RUNTIME_FAILED` went to the unexpected-terminal path (`knownFailure`), and an `OK` was taken for a grant. It now passes only with A, pending B, config bytes and census as before the request, and settles the lease. |
| A commit-readiness failure after an approval had no recovery oracle | `test_windows_tun_variants.CommitFailureTests` | RED failures=8: `kept()` refused the recovered A (`uac-denial-lost-active-a-or-pending-b`). It now requires A's location and mode with a new runtime ID, its config bytes, the original runtime gone, the recovered owner and runtime unelevated, the `owned-conflict` bind in the runtime log, and no broker, route, stage or other runtime; the row's own off and census take the recovered A. An `OK` parks. |
| A grant never compared its runtime config with its ready record, and the sampler ran for any grant | `test_windows_tun_variants.ConfigurationTests` | RED errors=8: no `configuration` stage, and `traffic` ran the sampler for `custom-grant` (`KeyError: samplerInputPath`), whose CUSTOM config has no TUN, so its address would have left the guest. `configuration` requires the bytes the ordinary user reads to be the ready record's `observations.configuration`, the generated TUN and SOCKS server, or the CUSTOM document with only the product's management and probe changes. Only `restart-grant`, `find-best-grant` and `generated-grant` sample. |
| The dedicated driver refused the variants and had no configuration step or document closing for them | `test_windows_tun_variants.DriverVariantTests`; `test_windows_tun_grant.DriverGrantTests.test_only_the_restart_grant_reaches_the_collector_route` | RED failures=3, errors=5: `dedicated-finite-proxy-variants-only`. A configuration grant now runs begin with the branch cases, finish, configuration, the sampler only for `generated-grant`, its own off and both records, the census and the documents' close under its collector's hold; a fault variant has no hold, asks no collector and closes with the recovered A. |

Still native, all of it: whether the broker's log reaches `runtime-sing-box.log` after a
failed commit, whether the broker removes its private stage then, whether a large CUSTOM
document crosses the broker channel, the configuration digest the collector reads, and
whether a CUSTOM config in VPN mode keeps the product's direct-probe rules as in proxy mode.

### Windows Desktop Package run 43877068415 on `89b2e9c6`: three desktop tests (hosted CI, 2026-11-16)

`:desktopApp:test` on the hosted Windows runner finished 1452 tests with 3 failed and 81 skipped,
so no MSI was built. The saved log is the native RED evidence:
`.runtime/windows-parity-20261107/evidence/ci-89b2e9c6/windows-43877068415-full.log`. All three
are test defects. The SSH Routing bootstrap's tie to its owner's lifetime works natively: in the
same run, `DesktopHomeSshBootstrapCleanupNativeTest` ties a real child started with the product's
launcher, and passed.

| Failure type | Regression | Cause and fix |
| --- | --- | --- |
| A fake child had no pid, so the platform tie warned on Windows only | `DesktopBootstrapCleanupTest.theBootstrapDeletesItsConfigurationBeforeTheDownloadAndEndsTheChildAfterIt` | The test gave `DesktopHomeSshBootstrapProxy` its `FakeChild`, a `Process` with no `pid()` override, and kept the default `tie`. On Windows, `tieToOwnerLifetime` calls `process.pid()`, and `Process.pid()` throws `UnsupportedOperationException` for any process that is not an OS process. Elsewhere the tie returns null before that call, so the test never failed off Windows. The test now injects a recording tie and asserts the order tied, destroy, released, untied on every platform. RED is native only (this run). The tie with a real `ProcessImpl` keeps its native coverage. |
| The probe passed Join-Path output to a reflected method (second site) | `DesktopWindowsNativeHelperPinSharingTest.theNativePinSharingProbePassesCmdletOutputToReflectedMethodsAsStrings` | The junction checks added by `4de91184` called `$method.Invoke($null,[object[]]@($empty,$null))` at line 97 of `windows-native-pin-sharing-probe.ps1`. `MethodInfo.Invoke` cannot convert the PSObject that Join-Path returns to the `string` parameter of `PinParents`. This is the same failure that `f5246b75` fixed for `$pinned` (run 43474296998). The probe now passes `[string]$empty`. The regression reads the probe on every platform and refuses any cmdlet-output variable passed uncast to `.Invoke(`. It was RED on the unfixed probe (line 97, `$empty`) and is GREEN on the fix. The probe's junction and `Linked` checks run natively for the first time on the next Windows run. |
| A failure in the witness test was replaced by its cleanup's sharing violation | `DesktopWindowsPinnedFolderJunctionNativeTest.nativeFolderOthersMayWriteIsUsedOnlyBesideAnEntryTheUserCanOpen` (native only) | The `finally` deletion of `drop\dropped.txt` threw `FileSystemException` 32 and replaced whatever happened first. Only a handle without delete sharing on that file explains 32. The test's own `assertFailsWith { native.open(dropped, PINNED_DIRECTORY) }` leaks exactly such a handle when the open succeeds, and so does the refused `DesktopWindowsTransferPins.open`, whose pins are never closed when it succeeds. Every pin opens with `FILE_FLAG_BACKUP_SEMANTICS`, so a token with `SeBackupPrivilege` enabled reads the private file despite its DACL. That is the probable cause on the hosted runner, but the run that would show it has not happened yet. The test now runs impersonating its process with backup and restore disabled, as an interactive user's process runs (it names any it disabled in its messages). It closes whatever an unexpected open returns before it fails, and it deletes the tree with bounded retries that never hide the body's own failure. Not a PLATFORM-003 defect: the pins were closed and `mine.txt` was deleted before `dropped.txt`. Open: if the next run's messages show the privilege was enabled, decide whether the product's witness search should refuse an entry that only a privilege opened. |
### The publisher observer's first Windows CI run (`89b2e9c6`, run 43877068415, 2026-11-16)

Windows Desktop Package, step `Verify Windows readiness native causal guards` (hosted runner, Python
3.12, elevated `runneradmin`) ran the observer type's Windows tests for the first time; the Mac skips
them. Two failed. The log is kept privately as
`.runtime/windows-parity-20261107/evidence/ci-89b2e9c6/windows-43877068415-full.log`. Both were the
tests' premises, not the tools: the publisher's census and backup open are unchanged.

`WindowsCensusTests` censused `sys.executable`. The census matches every process by image leaf, so it
also named the test runner itself: `agent_test_runner.py` takes one `--test-id` per test, about 50
arguments, over the 16 that `Argv` and `census_rows` both bound, hence `PUB_CENSUS_ARGV`. A guest's
census names only product images, whose argv is short (the runtime is `sing-box run -c <config>`), so
the bound stays. `test_the_publisher_backup_open_and_census` would have hit the same refusal after its
`setUp`. Both now census a copy of `cmd.exe` under a fresh name that starts `ping`, as the observation
test already did. The children test waits for `ping` before the snapshot.

`WindowsReaderTests.setUp` made the file SYSTEM's alone with `icacls /inheritance:r /grant:r
*S-1-5-18:F`, and the runner then read it. That command drops only ACEs flagged inherited. The file
was made under `tempfile.mkdtemp()`, whose mode `0o700` directory grants SYSTEM, Administrators and
OWNER RIGHTS; a grant that survived the edit let the elevated administrator read the file. Which
grant survived was not observed on the runner. `setUp` now sets the whole DACL, protected, with
`SetNamedSecurityInfoW`: SYSTEM granted and this token's own user explicitly denied. It then reads
the DACL back and checks it before it checks that an ordinary read is refused. The backup open must
still read the file past that deny, which is as strong a proof as before.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A census test over the interpreter's image named the test runner, whose argv is over the bound | `test_windows_update_grant_collectors.WindowsHarnessPremiseTests.test_no_census_runs_over_a_shared_image` (offline; RED on the `89b2e9c6` sources: 2 of 3 subtests); native: `WindowsCensusTests`, `WindowsReaderTests.test_the_publisher_backup_open_and_census` | Test premise. Only the next Windows CI run confirms the native tests. |
| An icacls edit left a grant that let the elevated runner read a file meant to be SYSTEM's alone | `WindowsHarnessPremiseTests.test_the_system_alone_file_is_set_whole_and_read_back` (offline; RED on `89b2e9c6`); native: `WindowsReaderTests` `setUp` | Test premise. The surviving grant was not observed. Only CI confirms. |
### Windows scoped-TUN reserved cases, offline build (2026-11-16)

`dns-ws-ssh-cache-resources` and `pipe-storage-races` had no row (`()` reserved) and no
case module. Five failure types close here, each with RED on an archive of `786cfda9` plus
the final test modules and GREEN on the fix, identical on Python 3.14 and 3.12
(`test_windows_tun_reserved`, with the two touched `test_windows_tun_grant` tests):

- Rows unbuilt (`TableTests`, 5 tests): RED failures=1, errors=10 (no row, decision row or
  driver role). The scenario table now maps `dns-ws-ssh-cache-resources` to
  `windows-scoped-tun.resources-grant` and `.ssh-grant`, and `pipe-storage-races` to
  `.stage-squat` and `.resources-grant`; each has its one `vpn-broker` approve decision row.
- Stages hooks (`StagesHookTests`, 6 tests): RED errors=16 (`begin` takes no case). A
  resources row's refused capture before its request, the case's journal step before the
  decision's one event, and the squat's own `CONFLICT` terminal, which alone passes.
- Case module (`Case*`, `BeforeDecision`, `Window`, `SshWindow`, `AfterOff`, 17 tests):
  RED failures=17 (no `windows_tun_reserved_cases`).
- Stage observation (`StageObservationTests` and the real-observer grant test, 5 tests): RED
  errors=13. The TUN collector's ready record now carries `observations.stage` (the runtime's
  stage, its entries, every `path` with its context, the cache, local rule-set digests, and
  each ssh outbound's key form with only the public fingerprint of an inline key) and
  `helperInvocation.pipeName` from the broker's own argv, joined to the owner and runtime.
- Driver route (`DriverReservedTests` and the variant-set test, 4 tests): RED failures=2,
  errors=3 (`dedicated-finite-proxy-variants-only`).

The collector source changed, so its contract pin and the whole SYSTEM collector chain's
pins were re-derived to a fixpoint. Nothing has run natively: the stage's ACL reads by
SYSTEM, the broker's command line through `NtQueryInformationProcess`, the product's
terminal codes for the refused capture (`UNSUPPORTED`) and the squat (`CONFLICT`), sing-box's
acceptance of the custom config (h3, `clash_api`), the cache publication, and the SSH chain
under the TUN are all for the first direct discovery run (TEST-007).

The authentic stage controls' `TunCustodyCases`
(`windows_lifecycle_runtime/stages/controls.source`) still faked a runtime at
`C:\Temp\owned-runtime.exe`, so the new stage observation refused them with
`tun-runtime-private-stage` (`test_windows_lifecycle_cases`, 1 failure;
`test_windows_lifecycle_capabilities`, 3 failures). The broker always runs the runtime as
`sing-box.exe` in its `vpn-control-vpn-<uuid>` stage under ProgramData, so the requirement
stands and the fake now models that layout and the broker's argv (pipe, owner, runtime
digest), with the stage listing and the argv read as inert seams, and asserts the ready
record's stage path and pipe. Its provenance records the adjustment and keeps the
historical digests (fixture adjustment only, no product change, no regression).
### Update fault rows: a failing MSI and a counterfeit storage root, offline (2026-11-13)

Built offline in the clone `build-update-faults` on `9a8db1e5` (the 1113 wave with T1); nothing here has run
natively. Track T5 of the 2026-11-13 coverage audit. Both rows were refused
`windows_scenario_update_fault_unavailable`, so msi-installer (windows-native-cli) and
protected-storage-adversarial (windows-installer-lifecycle) could never pass. `native-install-failed` had no
failing MSI to serve: the product's MSIs carry no LaunchCondition table (`FailingMsiProof`), and the paused
in-guest derivation (`windows_failing_msi/failing_msi_fixture.py`) refuses them. `protected-storage-rejected` had
no counterfeit root, and its case and the dedicated driver each parked it whatever the product answered, so a
run of it was always `unknown`. RED ran in a worktree of `9a8db1e5` holding only the new regression module and the
changed workflow contract test, one unittest process per failure type, on Python 3.14 and 3.12 with identical
counts (subtests included); the before-images of the seven changed sources, and the host job as `c8d69090` had it
for the last row, are under `.runtime/update-faults/before/` of the clone, beside the RED, GREEN, mutant, pin and
selector logs.

| Failure type | Regression | Notes |
| --- | --- | --- |
| `native-install-failed` had no failing-MSI producer (refused `windows_scenario_update_fault_unavailable`) | `test_windows_update_faults.FailingMsiAdmissionTests.test_the_failing_msi_row_is_admitted_with_the_package_its_pair_derived`, `test_a_failing_msi_that_is_not_this_pairs_declared_one_is_refused`; `FailingMsiJobTests.test_the_failing_msi_is_served_in_the_targets_place_and_its_grant_stages_are_tooled`, `test_a_failing_msi_receipt_that_names_another_target_or_package_stops_before_any_task`; `scripts/test_windows_update_fixture_workflow.WindowsUpdateFixtureWorkflowTest.test_the_failing_msi_is_derived_from_the_verified_pair_and_uploaded_beside_it` | The fixture workflow derives the pair's failing MSI after the pair is built and verified (`scripts/windows_native_failure_msi.py`, msi.dll's database API only). It is a copy of the target with one change set: a new LaunchCondition table whose one row has the condition `0`; its action at InstallExecuteSequence 100, after FindRelatedProducts and AppSearch and before RemoveExistingProducts (798) and InstallInitialize; and a new package code. The builder reads every table, user stream and summary property back and refuses any other difference, then uploads the MSI with `native-install-failure.json` and both snapshots. The row takes them as `faultPackage` (kind `desktop-update-fault-package`: a frozen set holds one package per kind) and `faultReceipt` (`desktop-update-fault-receipt`) of the pair's frozen set. Admission joins the receipt to the target, to the failing MSI and to the declared delta (`fault_receipt`). The job serves the pair's receipt with that one asset in the target's place and never stages the target's bytes (`served_fault_receipt`). Its stages are `before-install`, `fault-ready` (the derivation receipt, which the owner holds pinned), `authorization`, `terminal-actors` (also the worker's own `worker-result.json`) and `returned-cleanup`. The case was already written for this variant: FAILED with the worker's MSI result neither 0 nor 3010, the base in place, `--version` of the base, the next owner answering the same RUNTIME_FAILED. RED (4 tests): `FAILED (failures=11)`; workflow RED (1 test): `FAILED (failures=1)`. GREEN: OK. `scripts/test_windows_native_failure_msi.py` (10 tests) checks the producer itself against the product's real execute sequence through a database-API peer that applies the three statements as the engine does; it has no RED, since the producer did not exist. Release hygiene runs it. |
| `protected-storage-rejected` had no counterfeit-root producer (refused `windows_scenario_update_fault_unavailable`) | `FailingMsiAdmissionTests.test_the_counterfeit_root_row_is_admitted`; `CounterfeitJobTests.test_a_clone_whose_product_made_its_own_root_stops_before_any_task`; `CounterfeitCaseTests.test_a_root_that_already_exists_is_never_taken_for_the_counterfeit`, `test_the_binding_must_be_the_jobs_fixed_form` | The job binds the counterfeit: the product's machine root `ProgramData\vpn-control-install-jobs`, owned by the ordinary user with full control (`O:<user>G:<user>D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;<user>)`), and one canary file naming the operation. The case refuses any other binding with its inputs, before any effect, and plants both create-only as the ordinary user right before `fault-ready` (`plant_counterfeit_root`, `CounterfeitNative`). A root that already exists is never taken for the counterfeit. A clone whose own grant made the real root stops at publish, from a SYSTEM listing (`protected_root_present`), before any task. `fault-ready` (the unchanged pinned collector) proves the root user-owned and refused by the machine policy, and the canary's bytes; the case joins SYSTEM's openings to the objects it made. RED (4 tests): `FAILED (failures=6)`. GREEN: OK. |
| `protected-storage-rejected` parked unconditionally, in its case and again in the dedicated driver, so every run was `unknown` | `CounterfeitCaseTests.test_a_refused_counterfeit_root_settles_passed_with_proof_and_leaves_nothing`, `test_each_refusal_passes_and_any_other_definite_answer_is_a_known_failure`, `test_an_accepted_install_parks_with_the_counterfeit_kept`, `test_a_root_or_canary_that_changed_parks_and_is_never_removed`, `test_a_counterfeit_that_could_not_be_removed_parks_even_with_everything_else_closed`; `CounterfeitJobTests.test_terminal_actors_waits_for_every_helper_process_then_serves_the_counterfeit_as_system_saw_it`, `test_a_helper_process_that_never_leaves_keeps_the_outcome_unknown`, `test_a_root_still_there_or_changed_after_a_passed_task_is_this_rows_failure`, `test_a_known_failure_keeps_what_system_listed_after_the_task`; `CounterfeitDriverTests.test_a_settled_counterfeit_ends_with_its_own_result`, `test_without_its_own_proof_the_row_still_parks` | The job serves `terminal-actors` only once a SYSTEM census of the installed helper image finds no process left. From the product's code: its coordinator exits on the refused root, and its original-user worker polls until its ten-minute authorization deadline. Past 900 s the job ends UNKNOWN `counterfeit_installer_actors_live:<n>`, with the fence open. That stage proves the root and canary as `fault-ready` saw them, and the job lists the root as SYSTEM for the receipt. The case settles (`settle_counterfeit`): passed for a refusal (OUTCOME_UNKNOWN, RUNTIME_FAILED, PERMISSION_DENIED); failed for any other definite answer, an expired prompt's CANCELLED among them. Either needs SYSTEM's view and its own unchanged, the root holding the canary alone, the same owner, configuration and disconnected runtime, the base registration and pinned files, then the serve quit, the fixture closed and the counterfeit removed through handles of its recorded volume and file index. An accepted install, an unreadable reply, a changed root or canary and any failing step park, and a counterfeit made but not removed parks (`update-counterfeit-root-retained`). The driver accepts 0 or 1 only beside that settlement proof (`dedicated-counterfeit-settlement-unproven` otherwise). The row takes no close hold, which releases a driver result of 0 alone. For a pass, the job also needs the root it listed at `terminal-actors` to hold the canary alone and the root absent after the task (`counterfeit_root_changed`, `counterfeit_root_left`). RED (11 tests): `FAILED (failures=24)`; on `9a8db1e5` every outcome parked, first as `protected-storage-scenario-cannot-return-known-success` or `update-scenario-failed-with-retained-owned-resources`, and the job ended `collector_stage_unserved:before-install`. GREEN: OK. |
| A failed grant's next owner was checked against the target's files (predicted; no row reached it before) | `FailingMsiJobTests.test_the_failing_msi_is_served_in_the_targets_place_and_its_grant_stages_are_tooled` | `returned-cleanup` validated the returned owner's image against the target install's inventory. After a failed install, the next owner the case starts runs the base's CLI, so every native-install-failed run would have ended UNKNOWN at its last stage. It is now checked against the files the variant leaves. RED on `c8d69090` less this one hunk (the unfixed lines of `9a8db1e5`, `.runtime/update-faults/red-returned-owner.hunk.txt`), since on `9a8db1e5` no row reaches the stage: `FAILED (failures=1)`, the job ending `collector_stage_failed:returned-cleanup:collector_returned_actor`. GREEN: OK. |
| The counterfeit row's wait took a helper process that SYSTEM's census listed but could not open as gone (found reviewing `c8d69090`, before any run) | `CounterfeitJobTests.test_a_helper_process_the_census_could_not_open_is_waited_for`, `test_a_helper_process_the_census_never_opens_keeps_the_outcome_unknown`, `test_a_helper_process_listed_again_at_terminal_actors_leaves_the_outcome_open` | The publisher's census lists every process whose snapshot name is the helper's, and one it cannot open, or that has just exited, carries only its ids. `c8d69090` ended the wait on the opened rows alone, and accepted `terminal-actors` the same way, so a worker SYSTEM failed to open counted as gone and the case could settle while the product might still act. The wait now ends only on a census that lists no such process at all, and `terminal-actors` refuses a census that lists any: UNKNOWN `collector_stage_failed:terminal-actors:collector_counterfeit_terminal`, with the owner left waiting. A process that has exited drops out of the next census, so a pass costs at most one more poll. RED on `c8d69090` holding the final regression module: `FAILED (failures=3)`. GREEN: OK. |

Seventeen loosenings of the fix (`.runtime/update-faults/mutants.py`, a worktree of `4aeb080f`, Python 3.14) each
turn their named regression red: a settlement that passes any answer, accepts a handoff, ignores SYSTEM's view or its
own, ends known with the counterfeit kept, or never plants it; a job that serves `terminal-actors` while a helper
lives, takes a helper process SYSTEM could not open as gone (at the wait, or in that stage's own census), trusts the
case alone, skips the publish listing, serves another parent's MSI or binds no worker result; a driver that takes any
result; an admission that takes any delta; and a builder that allows an early change or takes any delta.

Changed expectations, not new failure types: `test_native_scenario_windows.UpdateTableTests` and
`TableTests.test_the_closed_names_agree_everywhere` (via `native_scenario_ssh.SCENARIO_ARTIFACT_KEYS`) admit the two
rows and name the failing MSI's two artifacts; `test_native_scenario_windows_matrix.TableTests` counts the
counterfeit row among the admitted installer-lifecycle rows; `test_windows_uac_decision.CancelledGrantUpdateTests`
and `CancelledGrantDriverTests` and `test_windows_ordinary_task.DedicatedDriverControls` keep the earlier rule that
the counterfeit row never ends known on a grant's cancellation proof, now through the settlement proof.

Why the settlement cannot hide a real failure:

- A pass needs positive proof of every safety fact, from SYSTEM and from the case: the product's answer is a
  refusal from the original controller; no process of the installed helper image is left; the root and canary are
  the very objects the case made, unchanged, the root holding the canary alone; the base registration and every
  pinned base file are in place, and SYSTEM reads the base back after the task; the counterfeit is gone. A missing
  fact keeps the owner waiting or fails a check; it never counts as a pass.
- Any other definite answer, an expired prompt's CANCELLED included, ends `failed`: the matrix records it, and a
  settled failed run on the evidence package blocks the scenario for that package (TEST-007).
- An accepted install (an installer job exists somewhere), an unreadable reply, a changed root or canary, a helper
  process that never leaves and any failing closing step still park: `unknown`, which blocks the scenario too and
  is never replayed; the fence stays open and reconciliation reads the original's status.
- The case removes only what it created alone, through handles whose volume and file index it recorded at
  creation; a root that existed before is never taken for the counterfeit, and a clone whose grant made the real
  root stops at publish from a SYSTEM listing, before any task.
- Before this change every run was `unknown` whatever the product did, so a wrong product answer could never be
  told from a right one; now each lands in the class its evidence proves.

Pins renewed to a fixpoint with `.runtime/update-faults/renew_pins_t5.py` (T1's chain plus the case module's
links): the dedicated driver's `CASE_SHA`, the planner's `DEDICATED_CASES` and `DEDICATED_DRIVER_SHA`, the
owner's held-driver literal, `test_windows_public_updater.ROWS`, the selector's reviewed versions of the driver,
the case module and the changed declared test loaders (appended), the `readiness_vm_dispatch.json` `sourcePins` of
`windows_ordinary_task`, `windows_scenario_host_job`, `native_scenario_windows` and `native_scenario_ssh`, and the
selector's entry for that manifest. No file of `readiness_windows._source_pins()` and no SYSTEM collector source
changed.

Native only:

- The msi.dll derivation runs first on the Windows fixture builder; its read-back check refuses any change beyond
  the declared one (a summary property msi.dll might stamp on commit would stop the dispatch there, before any VM).
- That Windows Installer ends the failing MSI with 1603 at LaunchConditions under UI level NONE, before
  RemoveExistingProducts, so the base stays; that the coordinator then publishes FAILED with RUNTIME_FAILED and the
  next owner answers the same.
- What the product answers to the counterfeit root (OUTCOME_UNKNOWN expected from the code: its owner can no longer
  read its job store), and that its coordinator exits and its worker leaves within its ten-minute deadline.
- That the ordinary user can create `ProgramData\vpn-control-install-jobs` (Users may create folders there by
  default) and delete its own canary and root.
- Every grant stage of both rows.

Ported onto the integrated wave (2026-11-16) in the clone `reconcile-update-faults`, on top of update-variants,
which had already made `participating-copy-lock` pass its fault through `Job._fault_inputs()`. That method is now
the one fault-input value for all three fault rows: it carries `native-install-failed`'s derivation receipt (the
published pin's path, digest and size) and `protected-storage-rejected`'s counterfeit binding, and the case's
`faultInputs`, the `fault-ready` collector's `faultBinding` and the counterfeit row's `terminal-actors` binding are
that value. No new failure type: every regression above runs unchanged against it. Changed expectations only:
`test_native_scenario_windows_matrix.GRANTS` names `native-install-failed` (its authorization stage observes the
approver), the faults case inputs carry update-variants' `upstreamFixture` key, and
`test_workflow_jdk_order.GRADLE_TEXT_ONLY` reviews `scripts/windows_native_failure_msi.py` and its test, which name
the fixture build in docstrings only.

### Fourth native document row: a sealed spool changed after its seal was run, and the row parked (native, 2026-11-16)

`windows-document-acceptance` (direct operation `ade9c4da`, package 2.2.18 of `60017226`, tools of
`3e559abd`, TEST-007 discovery) ran past the folder-pin defect (2,678 events) and ended UNKNOWN,
`job_exit_unknown:owner-parked`: `scenario-failure-with-retained-child`, `errorClass` `Refused`, frames
`windows_ordinary_process_owner.py:1336`, `:1123`, `windows_document_cli_cases.py:163`,
`windows_document_native.py:740`, `windows_document_client.py:283`, the serve (child 2) running. The last
events are `document-spool-mutated` (a same-length `control-snapshot` naming `contexts[51]` written over the
held, sealed spool) and the honest reference's `document-exchange`, which read one whole 37-byte frame and
closed its socket. Its sha256 `cc0f2ba7c0b358866473b781264fc7e7a02ae48be340c52204e4e51e1f4e6c5d` is that of
the JSON frame of `cli-response\terror\t1\tQ09ORkxJQ1Q`, `DesktopCliResponse.failure("CONFLICT")`: the
owner read the changed bytes, ran the foreign controller's snapshot and `DesktopHeadlessSession` refused
it. The original bytes would have answered the snapshot. Evidence:
`.runtime/windows-scenarios/ade9c4da-fc42-4af6-901d-910ea9ddbc2e/evidence-1.zip`; the bundle that ran,
`family/bundle-ade9c4da-fc42-4af6-901d-910ea9ddbc2e/`, holds the `3e559abd` tool bytes. The product source
of `60017226` equals `3e559abd`'s for every file on this path. Before-images, RED and GREEN logs:
`.runtime/windows-parity-20261107/evidence/doc-accept-park/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The owner ran sealed command bytes changed after their seal (PRODUCT) | `DesktopSealedSpoolIntegrityTest` (`aSealedSpoolChangedAfterItsSealIsNeverRunAndGetsNoReply`, control `theUnchangedSealedSpoolStillRuns`) | Sealed content is immutable (cli.md, transport step 3). `DesktopControlDocuments.consume` read through `ControlTransferStore.acquire`/`Consumer.read`, which return the spool's current bytes, and `DesktopControlTransferSpool.sha256()` is the running digest of what was appended, so nothing compared the seal with what was read. `consume` now hashes the bytes as it reads them and refuses, before any parser, unless their count and digest are the seal's; the server then closes without a reply. The test runs the real `DesktopActivationServer` with the headless session's controller check, uploads the native command, rewrites the payload file in place with the same-length foreign one and sends the honest reference. RED on `3e559abd`: the reply `cli-response\terror\t1\tQ09ORkxJQ1Q`, the native frame. GREEN: no reply and no command handled. The check costs one more SHA-256 pass over the command document; `DesktopLargeExportCliProcessTest` (14 MiB import) passed on the fix (import 108 s), but on a host at load 20 to 25 it also failed on both the fixed source (the 120 s import bound, and once a client `TIMEOUT`) and the unfixed one (a later step exiting 2), so its timing there is not evidence either way. Native only: that a held Windows writer can still change the spool (the harness opens it sharing read, write and delete) and that the installed owner then closes. Android's `AndroidControlDocuments.Input` streams the same unverified consumer bytes to its parsers; its spool is app-private, and it is not changed here. |
| A finished, answered mutated-spool negative parked the clone (TOOL) | `test_windows_document_spool_admission.AdmittedSpoolTests.test_an_answered_mutated_spool_closes_as_the_named_known_failure`; controls `test_the_fixed_product_closing_without_a_reply_passes_the_adversary`, `test_a_partial_reply_keeps_every_handle_for_the_park`, `test_a_release_that_cannot_close_its_handle_parks_unknown`, `test_the_reply_record_names_only_a_typed_code` | `mutate_sealed_spool` kept its writer, payload and spool-folder handles after `Client.negative` refused an answered exchange, so the CLI cases' `close_known` saw held fixtures and the owner parked, although the reply was a whole frame and its socket closed. Now only `document-negative-admitted:mutated-sealed-spool`, with the last exchange `response-complete`, its socket closed, no secondary error and no open socket, journals `document-spool-mutation-admitted` (the reply's status, exit code and typed code only, the reply frame's size and digest, the held bytes' digest and whether they are the replacement), closes exactly those three handles and re-raises, so the owner quits its serve once and ends 1 as that named failure. Nothing is sent again, discarded or deleted; the product erases its spool at the quit. `Client.negative` keeps the decoded reply on the refusal for this record. A partial frame, a timeout or any other error keeps every handle for the park, and a handle that cannot close parks `document-spool-admitted-release-unknown`. The test runs the real owner, function and client over a socket pair to a logical owner writing a real temporary spool. RED on the `3e559abd` bytes (`fixtures/windows_document_spool_admission/`): `(None, [("scenario-failure-with-retained-child", "Refused")], [])`, the native signature, on Python 3.14 and 3.12. GREEN: exit 1, one quit, the three handles closed and the reply recorded as `CONFLICT`, frame 37 bytes `cc0f2ba7...`. |

The next native run of this row on a package built from this fix must show
`document-negative` with `label` `mutated-sealed-spool` and `observed` `clean-frame-eof`, then
`document-spool-adversary-state-unchanged` passing and the segment going on. On the 2.2.18 package it must
end as the known failure `document-negative-admitted:mutated-sealed-spool` (owner exit 1, the serve quit
once), with `document-spool-mutation-admitted` naming `CONFLICT`, never as UNKNOWN.

### A run reply that did not decode left the clone UNKNOWN (harness, from 906a0bb7, 2026-11-16)

`windows-query-owner-gui-reconnect` DIRECT `906a0bb7-4879-4b91-8d53-24612b097c92` on clone NC `42d96689`,
package 2.2.18 of `60017226` (`sha256-14e0c51c...`), after reset `b6e4bf24`, tools of `93b7ac64` (bundle
`faa5e62a`). Submitted 18:45:51Z, it ended at 18:51:32Z as `job_exit_unknown:system_run_unreadable`: driver
exit 3 at stage `run`, the run's reply never decoded (task `events` 0, no state), not parked, no evidence.
Exit 3 is outside `KNOWN_EXITS`, so every later job on NC refuses `prior_job_exit_unknown` and the clone was
stopped with its disk kept. The same row passed as `30975bc9` (tools of `450b8764`).

What was unreadable is not known. `stage_run` mapped a nonzero exit, a signal, a truncated stream, any
stderr, a stdout that was not base64, gzip or one JSON object, and every actor or boot custody check of
`windows_artifact_transfer.decode_guest_result` to the one code, and the terminal that tells them apart
stayed in the VM root on the VM host (`direct-guest-249e13e6-b9d4-5b6a-a365-c204301710eb.terminal.json`, the
uuid5 of the operation and `system-run`, beside `qga.wire` in the job's data directory); it was not read
for this entry. What the evidence does rule out: an oversized reply (a finished run's result holds about
six event rows, far under the 64 KiB bound), a timeout mid-read (that ends `guest_program_deadline` or
`guest_exec_status_lost`) and a mix of bundle generations. Not a regression either: the run template,
`windows_ordinary_task_owner.ps1`, `windows_artifact_transfer.py` and `windows_postboot_action.py` of
bundle `faa5e62a` equal those of `30975bc9`'s bundle byte for byte, `git diff 60017226 93b7ac64` touches
none of them nor `stage_run`, `guest_program` or `decode_stdout`, and `faa5e62a` differs from `f0cb6a1c`
(no-tray-close `8f813bb8` passed through the same run path at 18:11Z) only in the document and SSH relay
modules and the manifest; document-acceptance `2f9fdc96` and ssh-relay-transfer `c63a36c3` then passed on
`faa5e62a`. The receipt's `guestPrograms` 23 equals `30975bc9`'s count through `system-run` and the read-only
`evidence-zip` copy, so that copy ran too and also failed (its known failure is dropped once the code is
UNKNOWN): two consecutive SYSTEM programs failed at about 18:51Z. The VM host was congested then: the NE2
create was refused `host memory pressure is not normal` at 18:45Z and NE2 booted on the same host from
about 18:49Z to 18:50:51Z. Two causes fit both failures and stay unconfirmed: a move of
`Win32_OperatingSystem.LastBootUpTime`, which Windows shifts when it corrects its clock (the run's closing
then throws `BOOTSTRAP_ACTOR_OR_BOOT_CLOSING`, and the next program's opening refuses
`GUEST_BOOT_OR_ACTOR_MISMATCH`), or a failing CIM call in `Read-ProgramBootstrap`. Original output,
journal, before-images and logs: `.runtime/windows-parity-20261107/evidence/query-unreadable/` of the
recovery checkout.

Why it stayed UNKNOWN: the run deletes its task and then reaches its boot-bound closing and its reply, and
nothing in the guest kept what it had found; the owner's journal and the status file do not prove the task
was deleted. Built offline on `9f5b1995`; nothing below has run natively. RED in an archive of `9f5b1995`
holding only the changed test module: `Ran 7 tests`, `FAILED (failures=18, errors=2)` on Python 3.14 and 3.12,
the query row ending `(3, 'system_run_unreadable')`, the native signature. GREEN: the same 7 OK on both.

| Failure type | Regression | Notes |
| --- | --- | --- |
| An ended program's undecodable reply named nothing | `test_windows_scenario_host_job.JournalRuleTests.test_an_unreadable_run_reply_names_why_in_finite_words`; `test_nonzero_system_run_exit_is_unknown_not_a_refusal` | `unreadable_reason` names the reply in finite words: `exit_<n>` or `stderr`, followed by the first code its stderr names that the rendered program holds as a literal (`RUN_*`, `BOOTSTRAP_ACTOR_OR_BOOT_CLOSING`, `GUEST_OUTPUT_BOUND`) or else the first cmdlet its error record names that the program calls (`Get-CimInstance`); `signal`; `truncated`; `output_bound`, `gzip`, `base64`, `utf8`, `json`, `shape`, `duplicate_key`; `custody:transfer_*`. No other guest text crosses (a private path in stderr stays out). The failure is `system_run_unreadable:<reason>`. RED: all nine cases and the no-result case end with the bare code. |
| A finished run whose reply did not decode blocked the clone | `RebootFamilyTests.test_the_query_row_whose_run_reply_did_not_decode_ends_known_from_its_durable_result`, `JournalRuleTests.test_an_unreadable_finished_run_is_read_back_from_its_own_result_and_ends_known`, `ClosedDoorTests.test_the_run_leaves_its_result_create_only_before_its_closing_and_reply`, `SourceTests.test_sources_are_ascii_and_within_the_largest_proven_bound`; controls `test_a_durable_result_that_is_open_or_not_this_runs_own_stays_unknown` | The run template now writes `{schemaVersion, operationId, runPid=$PID, run=$r}` create-only to `system-run-result.json` in the SYSTEM workspace (the ordinary user may only read it) after its body and before the boot-bound closing and the reply, inside its own try, so a failed write leaves the reply as it was. On an undecodable reply `Job._unreadable_run` reads that file with the guest agent's file read (no program, no boot binding), keeps it, and accepts it only when it names this operation and the run's own pid with exactly those keys and `productOperation` false. A `task-finished` result whose task was deleted and whose `sourceClosing` holds is the known failure `system_run_unreadable_settled:<reason>` (exit 1), never a pass: the closing custody is unproven, `installedPackage` stays false, the read-only evidence copy follows and the next job is admitted. Nothing is run again. An open state (`deadline`, `owner-parked`, `post-launch-unknown`), a task not deleted, another pid or operation, an extra key or no file stays UNKNOWN `system_run_unreadable:<reason>`. RED: `(3, 'system_run_unreadable')` and no write in the template. |

Pins renewed: `readiness_vm_dispatch.json` `sourcePins.windows_scenario_host_job`, and the selector's
`nonPythonResources` entry for that manifest. `affected_agent_test_dependencies.json` also takes the current
digests of `test_ssh_privileged_program.py` and `test_macos_vm_resource_monitor.py`, which `3d8dac11` changed
without renewing their loader rows (neither changed what it loads). No file of `readiness_windows._source_pins()`
changed. `906a0bb7` itself stays UNKNOWN: its run wrote no result file, and its job exit is not rewritten.

The next native run of this row (a new operation on a fresh or reset clone; never a replay of `906a0bb7`)
must show either the pass or, if a reply is again undecodable, the failure word with its reason, for example
`system_run_unreadable_settled:exit_1:BOOTSTRAP_ACTOR_OR_BOOT_CLOSING`, `system-run-result.json` kept in the
job's data directory, exit 1 and the next job on that clone admitted. A reason naming the boot closing or
`Get-CimInstance` decides between the two causes above; for the former, the evidence-zip terminal of the same
job should show `GUEST_BOOT_OR_ACTOR_MISMATCH` with a moved `lastBootUpTimeFileTimeUtc`.

### A deny decision call refused `uac_transport_unsubmitted` under host congestion (native, 2026-11-16)

`windows-scoped-tun.restart-deny` DIRECT `9be1f7a6-4b8f-4b44-802e-c8f3078b1102` on clone ND `192e5a3d`,
package 2.2.18 of `60017226`, tools of bundle `f0cb6a1c`, reset `fa1bbc48`. The token
`uac-pending:vpn-broker:deny` was seen at 18:01:40Z; decision call 1 (decision `10ce297e`) refused
`uac_transport_unsubmitted` after 159.5 s: its gates took 0.7 s and the packet reached the transport at 19.6 s,
which never submitted it by its 112 s deadline. No key was sent. The refusal is typed and permits another
submit (`submitAgain` true), but the prompt expired first; the guest job ended exit 0 with its task deleted and
not parked, and collection stayed `collector_unavailable` with no decision terminal to join: unsettled, not a
pass. The Mac was at load about 24 (qualify calls 140 to 200 s) with the NE OOBE watch and an NC row in flight.
The retry `63c2290f-62d9-4a83-b82d-1412f81cd860` (new reset `4f4496e0`, no other guest submission in flight)
had its decision call 1 answered `input-ack-only`, attempt 1, prompt closed, in 16.94 s and PASSED. Output:
`.runtime/windows-parity-20261107/family/d6D3-deny.out`, `d7D3-deny.out`, copied to `evidence/query-unreadable/failure/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A UAC decision packet was not submitted within its deadline under host congestion (ENVIRONMENT) | existing `test_windows_uac_decision.ExecuteInputTests.test_a_typed_unsubmitted_transport_refusal_permits_another_submit` | No defect: the decision refused before any effect, sent no key, and allowed another submit, as designed. Recorded so a second occurrence is recognised. Run a UAC decision row with no other guest submission, clone bring-up or qualify loop in flight on the same hosts. |
### Clone first-boot OOBE stuck, setup task result 73 (native, `db6df990` 2026-11-08 and `23824f97` 2026-11-16)

Two clones of image `637199a5` (`db6df990` regular; `23824f97`, NE, with `secondAdministrator`) never
finished their first boot: every qualification read `oobeInProgress` 1, `IMAGE_STATE_UNDEPLOYABLE`, no
console user, no `fixtureuser` profile, the guest agent running and no `ready.json`;
`VpnControlFixtureInitialize` ran from the last boot (`23824f97`: boot 17:36:38Z, result 73 by 17:52Z) and
ended 73, `install-agent.ps1`'s own 15-minute wait for setup. The agent is installed only after that gate
and the task is registered only by `SetupComplete.cmd`, which Windows runs after the machine OOBE set
`IMAGE_STATE_COMPLETE`, so both clones had completed the machine OOBE, the agent install was in flight, and
Windows then resealed to OOBE and restarted, and the restarted OOBE never completed. The preserved `ee0d45b1`
disk logs show the same sequence record by record: `COMPLETE`, `SetupComplete.cmd`, user OOBE as
`defaultuser0`, the agent service installed inside it, `CloudExperienceHostBroker` `COMPLETE ->
SPECIALIZE_RESEAL_TO_OOBE`, then a machine OOBE stopped at `UNDEPLOYABLE` after creating `defaultuser0`
again. Both start programs executed the same `INSTALL_AGENT` (sha256 in the fixture provenance); the
OneDrive policy (absent for `db6df990`), the second administrator (absent for `db6df990`), host load
(`db6df990` booted in 120 s) and the dark display (`23824f97`'s frame `4294a47a`; no input was sent) do not
separate the stuck clones from the good ones. Evidence: `clones/bring-up-5995.out`,
`tool-recovery/windows-sleep-20261106/public/{215945,222501,204209,210323}-*qualify*.stdout`, start programs
`.runtime/windows-vm-deploy/{8e0d0e2c…,d52b1d95…}/caller.py`; RED/GREEN logs and the patch in
`.runtime/windows-parity-20261107/evidence/oobe-stuck/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The agent install ran during the user OOBE, which can still reseal (TOOL) | `test_windows_first_boot_oobe.InstallerGateTests.test_windows_installer_starts_only_once_a_non_temporary_account_owns_the_console` | Windows sets `OOBEInProgress` 0 and `IMAGE_STATE_COMPLETE` before the user OOBE (clone `07831787` wrote `ready.json` while `defaultuser0` owned the console). The gate now also needs a console user that is not `defaultuserN`. A strict interpreter runs the gate on the preserved module both clones executed (RED: installer admitted before and during the user OOBE) and on the fix (GREEN), with phase values from the preserved replies. |
| A stopped OOBE had a guest agent only by accident (TOOL) | `...InstallerGateTests.test_a_stopped_machine_oobe_is_made_observable_and_never_reported_ready` | RED: the preserved gate ends 73 without an agent. A machine phase still incomplete when the wait ends now installs the agent for observation only (`ready.json` `setup-incomplete`, exit 75); a complete machine phase without a fixture logon ends 73 without installing. |
| Qualification reported a stopped OOBE only as `setupReady` false for 30 minutes (TOOL) | `test_windows_first_boot_oobe.QualifyNamedFailureTests` (stuck replies named, waiting and ready replies not, the fixed exit-75 record named) | MCP and CLI qualification add `setupFailure` (`windows_vm_guest.setup_failure`): `first_boot_oobe_stuck` when the machine phase is incomplete after the task ended 73 or 75, with `nextAction` `replace-fixture`. RED on `9f5b1995`: no field, generic `inspect-evidence`. No in-place recovery: the only nudges are input to an unreviewed OOBE page or forced setup state, neither of which leaves a faithful fixture. |

Routine suite: `agent_tools/tests/test_windows_first_boot_oobe.py` (affected selection of
`windows_vm_unattend.py`, `windows_vm_guest.py`, `mcp_server.py`, `native_next_action.py`). Native limits:
why Windows fails the user OOBE and which page the resealed OOBE waits on are not in the evidence (a
`disk-logs` read of the kept `23824f97` disk would show it); the fixed gate itself is proven only by the next
clones. The next clone created from these sources must show, in its first qualification, the console user
`…\fixtureuser` (or the visual administrator) together with `ready.json` `ready`, a `ready.json` time after
`defaultuser0` left the console, and no `ready.json` while `defaultuser0` is signed in; a clone that stops
in OOBE again must reach `setupFailure` `first_boot_oobe_stuck` within about 15 minutes of its last boot,
with the agent installed and `ready.json` `setup-incomplete`.
### Native scenario row speed (S6/QW7), offline (2026-11-16)

Built offline in the clone `builders/native-speed` on `a34e07cb`; nothing here has run natively. Not a
failure fix: 78 local rows (birth times, `.runtime/windows-parity-20261107/evidence/native-speed/breakdown.jsonl`)
spent a median 80 s before submit (the 1.2 MB program over the saved-program route every row, an admission
per call, a separate stage-check) and up to one 30-45 s status round after the job's end. Each new behaviour
keeps "recover by reading the original" and refuses before any guest contact when its proof is missing.
RED ran in a sparse worktree of `a34e07cb` holding only the two changed test modules (removed after use),
Python 3.14: 21 tests, 16 fail on their cause, failures=9 and errors=12 with subtests. The other five assert
that a caller who does not ask for the new behaviour sees none of it, so they pass on both. Logs:
`evidence/native-speed/test-logs/red-a34e07cb-py314.log` and the `green-*` logs beside it.

| Behaviour | Regression | Notes |
| --- | --- | --- |
| The 1.2 MB job body went over the saved-program route on every row | `test_native_scenario_windows.CachedBodyTests` | RED failures=1, errors=2: the body was never staged, and a submit took four calls. The body is staged once per host in the artifact cache; each row submits a 14 KB loader inline. The loader checks digest, size, owner and mode before it runs the body, and exits 2 (`host_setup:job_body_*`) otherwise. The loader over the cached body runs exactly what the single program ran. |
| Every SSH call of a row ran its own admission | `RowAdmissionTests` | RED errors=4: no `row_admission`. One admission carries a row's calls; every call still revalidates connection, boot and account when sent, and a call with no reply makes the next one admit afresh. MCP is unchanged. |
| The job's end was seen only at the next status round | `JobWaitTests` | RED errors=3: no `wait_job`. The host waits up to 110 s on the durable owner's `terminal.json` and liveness; it decides nothing, status still reads the original job, and nothing is replayed. |
| A product row after a passed row still needed a 7-minute reset | `test_windows_scenario_host_job.CleanStartTests`; `test_native_scenario_windows.CleanStartWiringTests` | RED failures=8 (subtests), errors=1. `clean_start=True` (direct route, product rows only) refuses `clean_start_unclean_job` unless every job since the install passed or was refused, then runs a read-only SYSTEM census before publish; anything left is `clean_start_drift:*`. A row right after its install records exactly what it did before. |
| Nothing measured where a row's time went | `DriverTimingTests`, `JobTimingTests` | RED errors=1 each. `timing.jsonl` (driver) and `host-timing.json` (collected) are not evidence, and a timing write that fails changes nothing. |

The private family helpers' change (no `sleep 120` between rows, `queue.py` resets only after a known failure,
drift or install-changing row, exit 3 stops a queue on an unsettled row) is a patch only:
`evidence/native-speed/family-helpers.patch`, with `helpers/simulate-{red,green}.log`. Still native, all of it:
the cache staging and inline submit on a fresh host, a second passing product row with `--clean-start` and its
census, a refused clean start after a failed row, a UAC row's job wait, and the measured row times.

### launchd relay restarted its finished job (integration, 2026-11-16)

Found while integrating the process-speed builders on `93b7ac64`: the macOS background-priority escape
(`agent_tools/launchd_escape.py`, used by `mcp_server._run` for managed agent commands and every command
bounded at 30 minutes or more) submits each command with `launchctl submit`, and launchd keeps such a job
alive: it starts `job.sh` again after every exit, immediately once a run outlasted the 10 s throttle, until the
relay removes the label. The restart truncated `out`/`err` before the relay's last read and began the
command again. Signature: `relay -- python -m unittest agent_tools.tests.test_agent_ci_shards` returned 0 with
16 bytes of stderr and no unittest summary (twice); a probe job exiting 0 restarted at +10 s and +20 s. The
same restart would have started a second SSH keeper child (`_run(..., timeout=1845)`) for a moment.
Fix: `job.sh` starts with an atomic no-clobber `started` marker, so only the first start runs the command and a
restart exits without touching its outputs.

| Behaviour | Regression | Notes |
| --- | --- | --- |
| A restarted job reran its command and replaced its outputs | `test_launchd_escape.RestartedJobTests` | Preserved `fixtures/launchd_escape/launchd_escape.before.source`: two starts of its `job.sh` run the command twice (RED); the current script runs it once and keeps out/err (GREEN). Portable POSIX, routine agent suite. |
| A relayed command longer than 10 s lost its output | `test_launchd_escape.RealLaunchdTests.test_long_command_keeps_its_complete_output_and_runs_once` | macOS only (real launchd). RED with the preserved relay installed: `(0, '', '', 2)`; GREEN: complete stdout/stderr and one run. Logs: `evidence/integrate-speed/launchd-relay-{red,green}.log`. |

### launchd relay limits, environment, selection and cleanup (review-speed 4-8, 2026-11-17)

Found by the independent review of `bf8d2da2` (`evidence/review-speed/REVIEW.md`, findings 4-8). The
`launchctl submit` job ran with launchd's soft nofile 256 (caller 1048576) and launchd's SSH_AUTH_SOCK/XPC_*;
that is the cause of the relay-only `test_tmux_public_intent_race` failures (`'submitted' != 'unknown'`,
reproduced with `ulimit -n 256`). `_run` escaped every command bounded at 30 minutes or more, including
`scripts/visual_review.py` (it posts GitHub statuses) and the SSH keeper child. A SIGKILLed relay left a job
that launchd restarted every ~10 s until logout; a lost exit status waited for the outer timeout; a non-zero
`submit` that had loaded the job could run the command both ways. Fix (`agent_tools/launchd_escape.py`,
`managed_agent_check.background_escape`, the escape line in `mcp_server._run`): a `gui/<uid>` plist job
(RunAtLoad, KeepAlive=false, ExitTimeOut, SoftResourceLimits = the caller's soft nofile/nproc/core/stack),
`env -i` plus exactly the caller's environment, a `started` marker the direct fallback must claim first,
137 for a job that ended without a status, self-bootout plus a watchdog for a vanished relay, a startup sweep
of `vpncontrol.check.*` labels past their bound or relay, and argv-only opt-in selection (private agent
runner plus a named allowlist of local pure-Python checks). Preserved unfixed sources:
`fixtures/launchd_escape/{launchd_escape,managed_agent_check,mcp_server}.bf8d2da2.before.source`.

| Behaviour | Regression | Notes |
| --- | --- | --- |
| `_run` escaped visual_review, the SSH keeper child and Gradle by timeout | `test_launchd_escape.RunSelectionRedGreenTests` | The exact unfixed `_run` + `background_escape` wrap all three (RED); the current ones run them directly and wrap only the allowlist (GREEN). `SelectionTests` enumerates native, guest, SSH, VM, release, remote, visual-review and keeper argv and every literal `_run` command and check-plan entry. Portable. |
| A failed submit after the job started ran the command twice | `FakeLaunchdTests.test_failed_bootstrap_after_the_job_started_ran_twice_RED_runs_once_GREEN` | Fake `launchctl` that starts the job and then fails: unfixed runs 2, current 1. Portable. |
| A lost exit status hung until the outer timeout | `FakeLaunchdTests.test_lost_exit_status_hung_RED_returns_137_quickly_GREEN`; `RestartedJobTests.test_restart_after_a_lost_status_left_none_RED_current_writes_137_GREEN`; `RealLaunchdTests.test_lost_exit_status_returns_137_quickly_and_leaves_no_label` | Unfixed still running after 12 s; current 137 in under 10 s (real launchd: 1.5 s). |
| A SIGKILLed relay left its job | `FakeLaunchdTests.test_sigkilled_relay_left_its_job_RED_job_stops_and_removes_itself_GREEN`; `RealLaunchdTests.test_no_label_or_process_remains_after_exit_sigterm_or_sigkill` | Unfixed job never removed; current job stops the command and boots itself out. |
| The job got launchd's limits and environment | `FakeLaunchdTests.test_job_gets_exactly_the_caller_environment_and_soft_limits`; `RealLaunchdTests.test_unfixed_relay_gave_launchd_limits_and_environment_RED`, `test_status_streams_cwd_exact_environment_and_limits` | Unfixed: nofile 256 and SSH_AUTH_SOCK/XPC_SERVICE_NAME (RED); current: the caller's soft limits and exact environment (GREEN). |
| Stale labels were never swept | `FakeLaunchdTests.test_startup_sweep_removes_labels_past_their_bound_or_relay` | Labels past their bound or with a dead relay (and legacy submit labels with a dead relay) are removed; live ones are kept. |

### Windows document cache row: the closed-state corruption step, offline (2026-11-17)

Built in the `doc-cache-b` builder clone on `efd774b0`, after the workspace-corruption product fix landed; nothing
here has run natively. `windows-document-cold.cache-bytes` read the committed cache back warm, closed and reopened
but never corrupted it, so `cache-digest-bytes` mapped to no row (above). Between the closed read and the reopen
the case now reads the committed `workspace.json` whole and, three times, with the product closed: places one
corruption (`changed-byte`: the first byte inside the first cached location string, its `{`, made `0xFF`, never
valid UTF-8; `truncated`: the closing brace cut; `trailing-byte`: one `x` appended), opens it with an independent
serve, requires the bad bytes kept whole in one `workspace.json.unreadable-<UTC>-<8 hex>`, the `status` warning
`UNREADABLE_WORKSPACE_KEPT`, exactly one log entry `SAVED_SETTINGS_UNREADABLE_DEFAULTS_LOADED(<kept name>)`, no
subscription, the defaults saved in format 1 and the serve still serving, quits it, moves the kept copy to the
operation root and puts the exact committed bytes back. A printable change inside a string is not used: it still
decodes, and the product, like the Android anchor, then uses the changed value. The matrix maps
`cache-digest-bytes` to the row again. The unfixed bytes are git objects at `efd774b0` and copies in
`.runtime/windows-parity-20261107/evidence/doc-cache-b/beforeimages/` of the recovery checkout; RED swapped those
two modules into the clone and restored the fix (sha256 recorded in `red/tree.txt` and `green/tree.txt`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| The cache row passed a product that writes its defaults over an undecodable `workspace.json` | `test_windows_document_cache.CorruptionTests` (6), `CacheFlowTests.test_the_committed_cache_is_the_recipes_bytes_and_an_independent_owner_reads_it_back_unchanged`, `test_a_cold_owner_that_reads_a_different_cache_is_a_known_failure_that_closes_it`, `RowTests`; `test_native_scenario_windows_matrix.ExactChildStopTests.test_with_the_real_table_the_cache_row_closes_cache_digest_bytes_and_only_that`, `TableTests` (2) | The inert guest's store now models `DesktopStateStore.loadWorkspace` at each serve's start: kept aside with the typed notice (`keep`), the defaults written over (`overwrite`, every build before the fix) and a decoder that ignores what follows the first value (`lenient`); defect variants keep the copy under another name or with other bytes, give no warning, the older-copy key, two entries or untyped text, a substitute subscription, or defaults without a format. Each fails with its own `document-cache-corruption-<oracle>:<kind>` and the closing quits the corruption's serve; a serve that ends on the bad bytes fails `document-cold-owner-ended-before-readiness`. RED on the `efd774b0` cold module and matrix with the new tests, on Python 3.14.3 and 3.12.13 alike: 12 tests, 19 failures (counting subtests) and 1 error (`no attribute 'CORRUPTIONS'`), e.g. `(1, [], 'document-cache-corruption-kept-aside:changed-byte') != (0, [], 'None')` for `overwrite`, `['changed-byte', 'truncated', 'trailing-byte'] != []`, `5 != 2` serves, and the matrix `('passed', 'unmapped') != ('unmapped', 'unmapped')`. GREEN: the same 12 OK on both. Native only: the installed product's keep on Windows (rename in its state folder, kept name, ACL), the `logs` text on Windows, and the file replacement while no owner runs. Expected native RED on a build before the fix: `document-cache-corruption-kept-aside:changed-byte`. |

### Desktop unreadable-workspace notice in the GUI status and the GUI log (2026-11-16)

Found by review of the workspace-corruption fix (its finding 6, deferred then), not by a native run. Two failure
types, both against `PRODUCT-003` ("reports the persistence failure in the GUI status"):

- Launch restore hid the notice. When the older copy that loads carries a reconnect intent, `DesktopAppService`
  set the first status line to `PREVIOUS_CONNECTION_RESTORE_PENDING` instead of the persisted
  `SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED` notice, and the first GUI attach's launch restore (`DESKTOP-004`)
  then replaced the line with `RESTORING_PREVIOUS_CONNECTION` and the restore's own result. The GUI status never
  showed that the latest saved settings had been kept aside.
- The GUI log showed every typed status raw. The GUI reads `logs`, whose `message` passes
  `DiagnosticsSanitizer.redactText`; that turns every typed status into `KEY(args)`, which
  `AppStrings.statusMessage` cannot decode, so the Stats screen showed the notice (and every other typed status,
  pre-existing) untranslated.

Fix. The notice outranks the launch restore in the status line, and the restore still runs once: when the loaded
workspace's status is a `SAVED_SETTINGS_UNREADABLE_*` notice (`isUnreadableWorkspaceNotice`), it is the first
status instead of the pending restore, and `DesktopConnectionActionsService.resumePreviousConnectionIfNeeded`
shows it again when the restore ends (started, failed, or previous location unavailable) without logging it a
second time; the restore's own statuses stay in the connection log. `ControlLogCursorJournal.read` adds an
additive `status` object (`key`, `args`) to each typed entry, with arguments redacted like the GUI presentation's
status (failure arguments `[redacted]`, others `redactText`); `message` is unchanged and plain entries have no
`status`. `desktopFrontendLogs` encodes that status again, so the GUI log renders it in the chosen language; an
older owner without the field still gives the old message. The field is shared code, so Android ADB `logs`
gains it identically (parity unchanged); human CLI output prints `message` as before. `PRODUCT-003` now states the
reconnect-intent case; `agent_docs/cli.md` documents the field. No status key or catalog changed.

RED: on the production sources of `efd774b0` with only the new tests added (beforeimages in
`evidence/doc-cache-b/beforeimages/`), `./gradlew --offline --continue -Pcompose.desktop.packaging.checkJdkVendor=false
:desktopApp:test --tests 'com.kardinal.vpncontrol.desktop.DesktopUnreadableWorkspaceLaunchNoticeTest'`
(2026-11-16T22:04:45Z-22:13:16Z) gave 6 tests, 5 failures:
`noticeIsTheFirstStatusWhenTheOlderCopyCarriesReconnectIntent` ("the GUI status did not report the kept workspace
first expected SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED but was PREVIOUS_CONNECTION_RESTORE_PENDING"),
`noticeReturnsAfterASuccessfulLaunchRestore` ("the restore replaced the notice: ...CONNECTION_STARTED_ON_TARGET..."),
`noticeReturnsAfterAFailedLaunchRestore` ("the failed restore replaced the notice: ...CONNECTION_START_FAILED..."),
`noticeReturnsWhenThePreviousLocationIsUnavailable` ("the unavailable location replaced the notice:
...PREVIOUS_LOCATION_UNAVAILABLE"), `guiLogRendersTheNoticeAsATranslatedStatus` ("the GUI log shows the raw status
key: SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED(workspace.json.unreadable-...)"); the guard
`launchRestoreWithoutANoticeKeepsItsOwnStatuses` passed. With the unfixed `ControlLogCursorJournal.kt` swapped
back alone, `:shared:core:desktopTest --tests '...ControlLogCursorJournalStatusTest'` gave 3 tests, 2 failures
(`typedEntryCarriesItsKeyAndRedactedArgumentsBesideTheMessage`, `argumentsAreRedactedLikeThePresentation`; the
plain-entry guard passed). GREEN on the fix (22:15:08Z, BUILD SUCCESSFUL in 3m 5s): 88 tests, 0 failures across
`DesktopUnreadableWorkspaceLaunchNoticeTest` 6, `DesktopStateStoreUnreadableWorkspaceTest` 24,
`DesktopAppServiceTest` 23, `DesktopPresentationSnapshotTest` 1, `DesktopFrontendClientTest` 3,
`DesktopConnectionActionsServiceTest` 5, `DesktopLogCursorJournalTest` 5, `DesktopCliStreamTest` 7,
`DesktopAndroidStreamTest` 5, `DesktopAndroidStreamTransportTest` 3, `ControlLogCursorJournalStatusTest` 3,
`ControlReadLogicTest` 3. Logs and JUnit XML: `evidence/doc-cache-b/red/`, `evidence/doc-cache-b/green/`.

Routine coverage: `:desktopApp:test` and `:shared:core:desktopTest` run in Fast Checks and the managed pre-push
tier; nothing to enroll by hand. Not proven: no packaged GUI run (the Stats screen and status line were checked
through the owner's presentation and `logs` read path, not a native window); Android `:app` tests were not run
(no Android source changed; the journal's API is unchanged).

### Windows GUI picker row, the GUI half of gui-cli-transfer, offline build (2026-11-17)

`windows-document-cold.gui-picker` was built in the `doc-gui` builder clone on `efd774b0`. Nothing here has run
natively, and no product failure was found: the rows below are the tool's own guards, each with a test that fails
when the guard is taken out. gui-cli-transfer, unmapped on `efd774b0` because the GUI's own file picker had no tool,
now maps to `windows-document-cold.gui-owner` (the CLI half) and the new row (the GUI half). The input route is the
no-tray row's owned private desktop (`OwnedNoTrayDesktop`, under its own child label), the input desktop switched to
it for the GUI steps only, and reviewed clicks: no generic executor, and no input reaches a window outside the GUI's
own process tree. RED ran in place, with no tree copied: `red_runner.py` loads the `efd774b0` modules (the picker
module absent) or one mutant of the built modules into `sys.modules` before the tests import them. Its logs, the
mutants and the runner are in `.runtime/windows-parity-20261107/evidence/doc-gui/` of the recovery checkout. Every
count is the same on Python 3.14.3 and 3.12.13.

RED on `efd774b0`: `test_windows_document_gui_picker` does not import (`ModuleNotFoundError`); the matrix tests
`test_with_the_real_table_gui_cli_transfer_needs_both_its_cli_and_its_gui_half`, the cache-row test and
`test_the_table_names_every_windows_scenario_and_only_built_rows` fail (3) with
`test_the_document_tun_and_responsive_rows_prove_only_what_their_evidence_holds` and the document table test erroring
(2) on the missing row; `test_windows_names_are_closed` fails on the missing name. GREEN on the build: all of them, and
`test_windows_document_gui_picker` 41 OK.

| Guard | Regression | Notes |
| --- | --- | --- |
| A click on a frame other than the reviewed one | `test_windows_document_gui_picker.ReviewedStepTests.test_a_frame_other_than_the_reviewed_one_clicks_nothing` | Each step clicks only when the sha256 of the frame's pixels inside its reviewed anchor equals the profile's. RED on the mutant `anchor-unchecked`: the routing-nav click went out on the routing screen. |
| A click with no review | `ReviewedStepTests.test_a_step_with_no_review_keeps_its_frame_and_clicks_nothing`, `PickerFlowTests.test_an_unreviewed_profile_ends_known_at_the_first_step_with_its_frame_and_no_click` | No step of `PROFILE` is reviewed yet, so the first native run ends `document-gui-picker-frame-unreviewed:routing-nav` with that frame kept and collected. RED on `unreviewed-clicked`: 2 failures. |
| A click into another process's window | `ReviewedStepTests.test_a_point_over_a_window_of_another_process_is_never_clicked`, `test_a_window_of_any_other_process_on_the_desktop_stops_the_row_before_any_click` | Every window of the owned desktop must be the launcher's or its direct child's, and the window under the point the GUI's. RED on `point-owner-unchecked` and `census-unchecked`: 1 failure each. |
| A press without its release sent again or taken as a click | `ReviewedStepTests.test_a_click_sendinput_inserted_only_in_part_parks_and_is_never_sent_again`, `test_a_click_sendinput_inserted_nothing_of_is_a_known_refusal_naming_its_error` | A partial `SendInput` parks; one that inserted nothing is a known refusal with its error. RED on `partial-input-accepted`: 1 failure. |
| A file name confirmed that the dialog does not hold | `DialogTests.test_a_file_name_that_does_not_read_back_is_never_confirmed`, `test_a_dialog_without_exactly_one_file_name_edit_is_a_known_failure_with_its_controls` | The path goes in by `WM_SETTEXT` to the dialog's one file name Edit and must read back before the one `IDOK`. RED on `readback-unchecked` and `edit-unchecked`: 1 failure each. |
| A failure that left the input desktop on the private one, or a dialog open under the GUI's quit | `DialogTests` closing tests, `PickerFlowTests.test_a_dialog_left_open_by_a_failure_is_cancelled_before_the_gui_is_quit` and the flow's known failures | The cold module's `close_known` closes the picker first: one posted `IDCANCEL` to the GUI's own open dialog, then Default restored; a cancel that does not close parks. RED on `closing-no-restore`: 6 failures; on `closing-no-cancel`: 3 failures and 1 error. |
| A GUI export taken as the CLI's when only its meaning matched | `ExportComparisonTests.test_any_other_byte_is_a_difference`, `PickerFlowTests.test_a_gui_export_that_differs_by_any_other_byte_is_a_known_failure_that_closes_the_gui` | The GUI export must be the CLI export's bytes except its one `exported_at` value. RED on `export-semantic-only`: 3 failures. |
| A GUI import read before it committed, or one whose committed state differs from the CLI's | `PickerFlowTests.test_a_gui_import_that_never_commits_is_a_known_failure`, `test_a_gui_import_whose_committed_state_differs_from_the_clis_import_of_the_same_file_is_a_known_failure` | The revision must change within 60 s, and the committed `routing_rules` must equal the CLI import's of the same file. RED on `import-not-awaited` and `import-state-unchecked`: 1 failure each. |

Native only: the switch of the input desktop, `BitBlt` of its screen, `SendInput` through a second handle with
journal playback access, `WM_SETTEXT` and `IDOK` in a real Vista-style common dialog of AWT's `FileDialog` and its
file name control IDs (1001 Save, 1148 Open), the GUI's own export and import through it, and every anchor of
`PROFILE`. The ctypes structure layouts were not checked on Windows. Still open: the reviewed profile, one native run
per step, and then the row's first full pass.

### GUI picker park refused before the first frame, with nothing recorded or kept (native, `91947c84` 2026-11-17)

Discovery run `91947c84-dbc6-4565-9450-a85e5eed82a4` of `windows-document-cold.gui-picker` on 2.2.19 ended
`task_exit_code` with the owner's known failure `document-gui-picker-park` (`windows_document_gui_picker.py:662`).
The GUI attached, the display was 1280 x 800, the input desktop switched and the window was placed at
`[140, 16, 1140, 736]`. Then the park at (4, 796) failed before the first frame capture, the desktop was restored and
the GUI quit with exit 0. No click was sent. The park asked `SetCursorPos`, `GetCursorPos` and `WindowFromPoint` and
raised one bare reason, so no event says which check failed or what it saw. Parking comes before the capture, so the
row kept no frame and the click-review loop had nothing to open. Excerpts of the original evidence (zip sha256
`91cb8412…f304`) and the unfixed module are in `.runtime/windows-parity-20261107/evidence/fix-gui-park/`.

Cause: partly known. The taskbar is ruled out. The owned desktop has no shell: the attach census (event 50) lists only
the JVM's four windows, and the step's own census just before the park passed, which refuses any window of another
process, so no Explorer `Shell_TrayWnd` was there. The placement read back exactly (event 52), so the window did not
cover the point. The evidence cannot show which of the rest failed: `SetCursorPos` refused, the pointer read back
elsewhere, or `WindowFromPoint` named no window or a window of the GUI.

Fix. The park now makes every check and names each failed one with what it saw in a `document-gui-picker-park-refused`
event, ending `document-gui-picker-park-<check>:<step>`. It keeps one unreviewable frame of the whole display
(`document-gui-picker-frame-<nn>-park-<step>.png`, kind `park-diagnostic`). `WindowFromPoint` may also name no window,
because the census of every top-level window of the desktop must now show no visible window over the point. That
census check also catches a window of the GUI that `WindowFromPoint` passes over because it is disabled, which the
old park let stand. The point moved to (70, 400), away from every edge and corner and 64 pixels or more from the
placement.

| Failure type | Regression | RED on `d0148a49` / GREEN |
| --- | --- | --- |
| A refused park records nothing and keeps no frame | `ParkTests.test_a_refused_park_names_each_failed_check_with_what_it_saw_and_keeps_one_unreviewable_frame_RED_bare_GREEN`, `PickerFlowTests.test_a_refused_park_ends_known_with_its_diagnostic_frame_collected_and_the_gui_quit`, `ReviewedStepTests.test_a_pointer_that_cannot_rest_on_the_bare_desktop_stops_before_the_steps_frame` | In-suite RED half on the beforeimage `fixtures/windows_document_gui_picker/session_park.before.source`, over primitives that answer as the `d0148a49` ones did. A refused move, a read-back elsewhere and an owned window at the point each end bare `document-gui-picker-park`, with no event and no frame. GREEN: each names its checks, its errors, the read-back position and the window at the point, and keeps the diagnostic frame. In the real owner the frame is collected and the GUI is quit. |
| A pointer under a disabled window of the GUI taken as parked | the same test, case `window-over-point` | RED: the old park let the pointer stand and the step clicked. GREEN: `window-over-point`, no click. |
| A pointer over no window at all refused | `ParkTests.test_a_park_where_window_from_point_names_no_window_is_bare_RED_refused_GREEN` | RED: `document-gui-picker-park`. GREEN: the step's own frame is kept for review. |
| The park point at an edge or near the placement | `ParkTests.test_the_park_point_is_bare_on_the_canonical_display_away_from_its_edges_and_the_placement`, `test_a_park_point_inside_the_crop_is_refused_with_every_check_it_fails`, `test_a_diagnostic_frame_that_cannot_be_taken_leaves_the_park_its_reason` | Constant and guard checks. RED on the base for the point (4, 796). |

Base-module RED and GREEN runs of these tests (`red_runner.py`, the `d0148a49` module loaded in place) gave 10 failures
and 1 error, then OK, the same on Python 3.14.3 and 3.12.13. The tests run in `test_windows_document_gui_picker`, part of
the routine agent suite. Native only: which check failed in `91947c84`, whether `WindowFromPoint` on an owned desktop
names its desktop window or no window, and the first frame at the new point. The next discovery run of the row must show
either the routing-nav step's own frame or a `park-refused` event with its diagnostic frame.

### The windows-visual matrix had no producer, and a harness failure was the product's `failed` (offline, 2026-11-17)

Coverage audit 2026-11-13 (`.runtime/windows-parity-20261107/audit/coverage-20261113.md`, GAP-VIS, section 7
items 3 and 10, tracks T12 and T13). windows-visual mapped all three scenarios to `()`, nothing turned a visual
review into an observation, and `matrix-record` accepted any hand-composed passed windows-visual record: nothing
checked its 58 scenes, verdicts, SHA or baselines. `visual_review` stored no proof of which bytes a verdict was
given on, the comparison report did not name the baseline it compared, and `visual_regression.py record` copied
any capture over the baselines with no review at all. Separately, `_matrix_row` classed every owner and terminal
exit 1 with `task_exit_code` as the product's `failed`, so DOC `83484649` (S_D), whose owner journal closed
`document-race-fixture-refused:rename-away:32` (the harness's own export-race fixture refused by the OS before the
product's export child started), counted as a product failure that `_settled_runs` then required to be recorded
before any pass of its package, where it would have blocked the requirement for that source. The fixes add
`agent_tools/windows_visual_matrix.py` (TEST-005: read-only review, `register-captures`, `observation`), the
`_visual_rule` re-derivation in `matrix_record`, the reviewed `record` of `visual_regression.py` (VISUAL-007), the
review's byte binding, and `failed-harness` (TEST-008, `MATRIX_HARNESS_FAILURES`). RED/GREEN logs and the patch are in
`.runtime/windows-parity-20261107/evidence/visual-record/`.

| Failure type | Regression | Notes |
| --- | --- | --- |
| A hand-composed passed windows-visual record was accepted (TOOL) | `test_windows_visual_matrix.RecordTests.test_matrix_record_refuses_a_windows_visual_pass_its_producer_did_not_make`, `...test_matrix_record_rederives_the_document_from_current_evidence`, `...test_a_record_that_says_more_than_its_document_is_refused` | RED on `efd774b0` with the producer module added: `matrix_record` accepts a plain JSON document. GREEN: only the producer's document, re-derived from the current receipt, report, captures, baselines and registry. |
| No producer turned an exact-SHA review into a windows-visual observation (TOOL) | `test_windows_visual_matrix.CompleteSetTests`, `RefusalTests` (missing scene, unreviewed image, verdict on other bytes, product defect, other verdicts, mixed SHAs of receipt, manifest, capture and artifact, comparison without baseline identity, evidence changed, unregistered capture), `StaleBaselineTests`, `SecureSceneTests`, `RepositoryTests` | The fixture is a real Git commit with LFS pointers, the real comparator and the real review. RED on `efd774b0`: no module; with the module alone, the base review binds no bytes, so every set is refused as unreviewed. The real manifest has 58 Windows scenes, `windows-uac` its only secure one. |
| A verdict named no bytes and the comparison no baseline (TOOL) | `test_visual_review.test_a_verdict_binds_the_bytes_the_agent_opened_until_reingest`, `test_visual_regression.test_report_binds_the_exact_baseline_and_actual_bytes_it_compared` | RED on `efd774b0`: no `reviewed_actual_sha256`, no `baseline_sha256`. |
| Baselines were re-recorded from any capture (TOOL) | `test_visual_regression.ReviewedBaselineRecordTest` (only `expected_change` written; unreviewed, product defect, infrastructure failure, pass over a failed comparison, another HEAD or capture SHA, an image changed after review all refuse), `test_the_record_command_needs_the_reviewed_sha` | RED on `efd774b0`: no reviewed record; the base CLI `record` copies the whole folder. The re-record stays an operator step (agent_docs/visual-regression.md, Baselines). |
| A harness known failure was the product's `failed` (TOOL) | `test_native_scenario_windows_matrix.HarnessFailureTests` (failed-harness from the pulled copy; it blocks its scenario beside passed twins; it does not hold a later pass of its package; the other listed codes; an oracle reason, an unlisted reason such as `no-tray-close-release-unproven`, an unpulled or changed copy, two closings, a differing closed reason and an owner exit 0 stay `failed`; a product failure beside it is still recorded at once) | RED on `efd774b0`: classed `failed`, recorded as a failed observation, and `windows_matrix_unrecorded_outcome` held the later pass. The fixture copies the event shapes and reason of `83484649`'s journal, not its bytes. |

Routine suite: `agent_tools/tests/test_windows_visual_matrix.py` and `test_native_scenario_windows_matrix.py`
(affected selection of `windows_visual_matrix.py`, `native_acceptance_matrix.py`, `native_scenario_windows.py`),
`scripts/test_visual_regression.py` and `scripts/test_visual_review.py` (Fast Checks). Native limits: no
windows-visual record exists until a hosted Visual Capture of the final SHA, the `windows-uac` capture from a
`windowsUacVisual` clone and a full Windows review of that SHA; the reviewed re-record has not run on real captures.
`f56f4a4c` (a `ValueError` in the query-owner tool, no known-failure closing) stays `failed`: no reviewed code names
it, and a bare exception class cannot tell a tool defect from a product reply the tool could not parse.

### Scoped-TUN collector root form and the reserved journal wait (native S_D4, 2.2.19, 2026-11-17)

Two tool defects stopped native scoped-TUN rows before any product verdict. Product code is not implicated. The
original evidence and excerpts are in `.runtime/windows-parity-20261107/evidence/fix-collector-root/`. RED ran on an
archive of `d0148a49` plus the final test modules; GREEN ran on the fix, on Python 3.14 and 3.12.

| Failure type | Regression | Notes |
| --- | --- | --- |
| Every collector root read back `O:SYD:P(...)` and the job demanded `PAI` alone, so all seven TUN grant rows (`ec361ea8`, `e6fbd999`, `270cacbe`, `5d686d9b`, `2d07d937`, `2fa2c4cd`, `383320bf`) and every update row with collector stages (`723417ea`, `9b1f6361`, `506b1a87`) ended at publish with `collector_root_policy`, before any task (TOOL) | `test_windows_scenario_host_job.UpdateFamilyTests.test_a_collector_root_as_the_publisher_creates_it_natively_runs_the_row`, `...test_a_collector_root_in_any_other_form_refuses_before_any_task_and_keeps_what_it_read`; `test_windows_update_grant_collectors.RootFormTests` (3 tests) | RED: the native `P` form gives `(1, 'collector_root_policy', 'failed')`, which is the native receipt. The contract refuses `P`. Neither the guard nor the release program states the forms. The read-back is the operator's decode of `723417ea`'s `qga.wire`. The publisher makes the root with `CreateDirectory` and a protected descriptor (`D:P`), which carries no auto-inherited flag. The job, `collector_contract.root_policy`, `ordinary_task_guard.ps1` and `release_template.ps1` now take `P` and `PAI` with the same SYSTEM owner and the same three explicit ACEs. Any other owner, control, inherited ACE or extra ACE is refused. The refusal names `owner:dacl-flags:aces`, and the job keeps the records in its private `collector-root-security.json`. The update fake had modelled `PAI` for collector roots and now models the native `P`. |
| The stage-squat wait parked UNKNOWN (`b50d0425`, `scoped-tun-reserved-journal-absent-no-replay`) without reading the row's own operation: the async restart was `ACCEPTED`, no journal appeared in 120 s, and the outcome was never read (TOOL) | `test_windows_tun_reserved.BeforeDecisionTests` (refused before the journal, still pending at the bound, outcome-open ends, journal before the end, refusals equal to the stages'); `StagesHookTests.test_a_request_refused_before_its_journal_closes_as_a_known_failure`, `...test_a_refusal_before_the_journal_that_left_anything_keeps_the_owner_parking` | RED: `the product's own refusal was never read: parked:scoped-tun-reserved-journal-absent-no-replay`. The park keeps no status, and the stages have no known close. The path and name match the 2.2.19 product: the state folder's `.runtime-resource-job-<job>.json`, retained before UAC in `DesktopWindowsVpnBroker.prepareCaptured`. The wait now reads `operations status` every 5 s. A definite refusal with still no journal ends as a known failure, after A, pending B, the census and the absent journal are checked. Anything else parks, and every end first records the last status. |

Routine suite: the modules above, plus the re-pinned collector chain (`test_windows_system_collector*`,
`test_windows_failing_msi_consumer`, `test_windows_tun_grant`, `test_windows_ordinary_task`). Only a native run
confirms three things. The first is that the grant rows pass publish and that the SYSTEM guard and release program
accept a `P` root on Windows. The second is the product's actual terminal for the squat restart: the next run's
`scoped-tun-reserved-journal-wait` event will show it. The third is whether that terminal is a definite refusal.
### An approval refused at an unrecognized frame, and its row left uncollected (native, 2026-11-17)

Run `c7b6562a` of `windows-scoped-tun.vpn-commit-failure` on clone `192e5a3d` with the 2.2.19 package (S_D4): the
operator helper called `windows-uac-decision` (approve, decision `4bd56d3e`) on the token at 03:15:55; the gate found
one valid `consent.exe` and then refused `instance_uac_frame_unrecognized` after its 30 s of frames (call 47.5 s;
attempt timing: sent 1.6 s, replied 36.9 s). Nothing was typed or burned. The prompt expired into the grant's
`cancelled`, the job exited 1, and collect found no input terminal to join, so the row stayed terminal and uncollected
(`collector_unavailable`), as deny `9be1f7a6` had. The profile `vpn-broker.json` (sha `06f09788`) was reviewed from the
deny review frame of `9cf1d139` (S_D3), and the same bytes passed the deny gate of `63c2290f` in 11.2 s. The approve and
the deny packets differ only in the decision, the row, the context and the operation: `UAC_SCREEN`, `UAC_FIELD` and
`UAC_PROFILE_SHA` are byte-equal, and the gate's code path before the first key is the same for both answers, so the
decision tool reads an approve's prompt exactly as a deny's. The cause is on the screen, and the two kept frames stay
in `windows-uac/4bd56d3e-.../` of the VM root, which no closed action reads (a final refusal is answered from the local
journal, so not even a status packet reaches them). Evidence, the unfixed sources and the
RED/GREEN logs: `.runtime/windows-parity-20261107/evidence/fix-uac-approve/` of the recovery checkout.

| Failure type | Regression | Notes |
| --- | --- | --- |
| The refusal could not say what its frame showed (TOOL) | `test_windows_uac_decision.RefusedFrameFactsTests` (four tests; control `test_no_other_refusal_and_no_answer_carries_frame_facts`), `ExecuteInputTests.test_a_frame_refusal_brings_its_frame_facts_into_the_reply_and_the_journal`, `test_frame_facts_cross_only_closed_and_only_with_a_frame_refusal` | `screen_gate` stops at the first crop it misses. A refusal at the bound now names, for its last frame, `cropsMatched` per reviewed crop and `fieldDarkPixels` (`_uac_frame_facts`), in the attempt terminal, the reply and the local journal. No crop shown is a screen without the prompt; one crop missed is something over that region. The gate is unchanged: every crop must match before a key. |
| A grant cancelled after a refused approval stayed uncollected (TOOL) | `test_native_scenario_windows.TunGrantDecisionTests.test_a_grant_cancelled_after_its_decision_refused_before_any_input_is_collected_with_that_refusal`; `test_windows_uac_decision.RefusedDecisionHostReadTests` (the real `_READ_DECISION` over the real owner's files); controls `test_a_refused_decision_never_completes_a_pass`, `UpdateCollectionTests.test_a_deny_whose_decision_refused_stays_unsettled`, `RefusedDecisionHostReadTests.test_nothing_that_could_have_typed_reads_as_refused`, `test_a_known_input_still_reads_as_its_terminal` | `_READ_DECISION` reads, when no input terminal exists, a decision whose every attempt ended `input-refused` with nothing attempted, with no input journal and none refused for a prompt another decision burned (`instance_uac_prompt_burned`) or whose input stays unknown. A grant's `cancelled` then joins it and is collected failed with `uacDecision` `approve-refused:<reason>`. A pass, a deny row or anything that could have typed stays unsettled. Nothing is submitted or typed again. |
| That run would have been the product's `failed` (TOOL) | `test_native_scenario_windows_matrix.UnansweredApprovalTests` (never counts or fails the requirement; does not hold a later pass; controls: a typed approval, another known end, no join, a row that is no grant) | `_matrix_row` classes it `approval-unanswered`, which never counts, like `approval-unproven`. |

RED on `d0148a49` sources with the final tests, Python 3.14 and 3.12 alike: `Ran 18 tests`, `FAILED (failures=5,
errors=6)`; the seven controls held. GREEN: OK on both. Routine suite: the affected selection of
`windows_uac_decision.py` and `native_scenario_windows.py`.

The S_D4 review frame of clone NG (`371066d7`, deny `9bdb0613`, 1280x800) then showed the same prompt 63 rows lower than
ND's reviewed frame `5cb384ac`: header rows 171..310 against 108..247, footer 675..754 against 612..691, the same x
range and size. Searched over every vertical offset that keeps the profile inside the frame, with dx 0, each of the ND
profile's eight crops matches ND's frame at offset 0 only and NG's frame at +63 only, except the computer-name crop
`[430,578,700,604]` (`DESKTOP-F9MDBBL` against `DESKTOP-G615U4N`), which is per clone. Outside the dialog both frames
are pixel-identical apart from the arrow: no taskbar, the same wallpaper and watermark, the same text rendering. So
the dialog's height on the screen varies by clone or run, and nothing else does: not DPI, wrapping, dialog size,
resolution or a taskbar. What sets it is not in the frames. ND's arrow sat at the centre after an absolute move and
its dialog was centred; NG's arrow sat in the bottom left corner after its move (a relative mouse moves one pixel) and
its dialog was lower. The pointer's place when the prompt opened, or the requesting window's place, are the leading
candidates; a census of `GetCursorPos` and the requester's window rectangle at the prompt would tell. 4bd56d3e's
frames, on ND, were most likely the prompt at another height; they stay in the VM root unread. Scripts and outputs:
`evidence/fix-uac-approve/ng-frame/` (`compare.py`, `locate_real_frames.py`).

| Failure type | Regression | Notes |
| --- | --- | --- |
| The reviewed prompt at another height was never recognized (TOOL) | `test_windows_uac_decision.OffsetSearchTests` (found at its one offset and answered; the field moves with it; crops at different offsets, a horizontal shift and two matching offsets refused; the search stays inside the frame), `ProfileTests.test_a_frame_whose_crops_match_at_two_offsets_is_not_reviewable` | `_uac_locate` searches the vertical offset only, within the frame: every crop must match its reviewed bytes at one and the same offset, two offsets refuse `instance_uac_frame_ambiguous`, and the field is read at that offset. The review refuses crops that show the prompt at more than one offset. On the real frames, ND's profile finds ND at 0 and, without its per-clone computer-name crop, NG at +63, in 6 to 46 ms. |
| A centred arrow would sit inside a shifted crop, and an arrow left over a crop hid the prompt for the whole gate (TOOL) | `test_windows_uac_decision.PointerParkTests`, `ReviewFlowTests.test_the_wake_parks_the_arrow_where_the_decision_parks_it`, `ProfileTests.test_crops_leave_the_corner_the_arrow_is_parked_in` | The one journaled move, shared by the review and the decision, parks the arrow in the top right corner (absolute jump; 16 relative steps), which no searched offset reaches; profiles keep the 32 rightmost columns free. The decision also makes that one move for the first lit frame that is not the prompt. Never a second move or a button. |
| A refused decision's frames could not be read (TOOL) | `test_windows_uac_decision.RefusedFrameKeptTests`, `ExecuteInputTests.test_a_refused_frame_is_kept_in_the_decision_journal`, `test_a_frame_that_is_not_the_one_named_is_never_kept`, `test_a_refusal_learned_by_status_keeps_its_frame_too` | A refusal at the frame bound publishes its last frame beside its terminal; the decide and status replies carry its exact bytes (`_uac_attempt_frame`), bounded as a review's reply; the client keeps `attempt-NNNN.frame.ppm` and `.frame.png` in the local decision journal. A frame that does not match its name is dropped, never the refusal. The facts gain `offsetY`. |

The gap rule holds at every accepted offset because the park no longer depends on the dialog: the arrow goes to the top
right corner, the search never moves a crop sideways, and `validate_profile` keeps every crop and the field out of the 32
rightmost columns, so no crop holds the parked arrow at any dy. The old centre gap stays a review rule, so the NG profile
(`cb846f1b`, its publisher crop split around `[636,396,664,440]`) and ND's (`06f09788`) both still load; each finds its own
clone's frame at dy 0 and the other clone's prompt at +63 or -63 with only the hostname crop missed
(`ng-frame/profiles_under_new_rules.txt`).

RED on `19bede7e` with the final tests, Python 3.14 and 3.12 alike: `Ran 63 tests`, `FAILED (failures=21, errors=6)`; the
other 36 held, among them the existing gate tests over the patterned synthetic prompt. GREEN: OK on both.

Native only: what sets the dialog's height, and whether a clone's offset is stable across boots and runs. The frames
cannot tell: ND's 06f09788 matched at offset 0 in review `9cf1d139` and deny `63c2290f`, both restored from one
snapshot boot, and NG's profile in two deny runs; 4bd56d3e on ND may have been another offset. Then: that the park reaches the corner on both mouse kinds and wakes the display;
that a frame refusal's reply carries its 3 MB frame through the transport; each clone's own profile (NG needs one: its
computer name differs); and the approval's first typed answer through a reviewed profile.

## Historical coverage rule

All older unresolved keeper/source/installer/resource/SSH/visual/protocol proposals
remain in the full archive and heading manifest. Locate the complete record before
judging supersession; omission from this compact index does not mean completed coverage.
TEST-001 requires preserved evidence/beforeimage, actual causal RED/GREEN, routine
consumers and fixed-artifact native rerun. Unknown comparison mappings refuse.
TEST-002 requires DIRECT and matching MCP. macOS deferral changes human scope
without deleting matrix or historical evidence.
