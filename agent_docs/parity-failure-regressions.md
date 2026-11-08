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

## Historical coverage rule

All older unresolved keeper/source/installer/resource/SSH/visual/protocol proposals
remain in the full archive and heading manifest. Locate the complete record before
judging supersession; omission from this compact index does not mean completed coverage.
TEST-001 requires preserved evidence/beforeimage, actual causal RED/GREEN, routine
consumers and fixed-artifact native rerun. Unknown comparison mappings refuse.
TEST-002 requires DIRECT and matching MCP. macOS deferral changes human scope
without deleting matrix or historical evidence.
