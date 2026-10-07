# Finish GUI/CLI parity: continuation handoff

Prepared on 2026-09-28 for a fresh **GPT-6 Sol, medium reasoning** coordinator.
The user paused the task **Finish GUI CLI parity**
(`01a078ac-ef7b-77a3-bb80-db170b38f882`) and will not continue it.
This document is the continuation brief; the old conversation is supporting
history, not another active owner. The user also requested review and delivery
of its inherited uncommitted changes before this handoff.

## 1. Assignment and completion boundary

Finish every supported GUI product operation's CLI equivalent across Android,
Linux, Windows and macOS, including matching validation, durable persistence,
runtime effects, progress, cancellation, recovery and truthful failures. Complete
the remaining installed-package, native and visual acceptance, fix defects,
deliver coherent checkpoints to `origin/dev`, and verify all required workflows
for the exact delivered SHA. Do not stop after writing another plan.

Use subagents for independent implementation, native verification and review.
Delegation is explicitly authorized. Keep one writer per file and one operator
per environment. The coordinator owns shared integration, local Gradle scheduling,
version metadata, commits, pushes and the final evidence decision.

This is development completion. No merge to `main`, tag, stable publisher,
release, sing-box upgrade, iOS work or TUI is authorized. Preserve the existing
EXE and MSI distribution; the earlier question about their purpose did not
authorize removing either format.

Read [contracts.md](contracts.md) as product authority, especially PRODUCT-002,
STATE-001..005, CLI-001..008, DESKTOP-001..008, TEST-001..003, ARTIFACT-001..004 and
VISUAL-001..009. This plan schedules their implementation and verification; it
does not change those contracts.

### What this review started from

- Repository: `/Users/karapsin_de/Nextcloud/projects/vpn_control`, branch `dev`.
- Starting HEAD and fetched `origin/dev`:
  `5aa882412b4a1dea614303946640351111c8ad3c`; version `2.1.19`.
- 36 inherited dirty paths: installer recovery/diagnostics, RPM orchestration,
  Android and Windows fixture admission, SSH recovery, local build environment,
  tests, changelog and maintainer docs.
- The review/delivery commit containing this plan supersedes that baseline. Get
  the actual current SHA with MCP startup and `git rev-parse HEAD`; never build
  from the old SHA merely because it appears here.
- Review evidence is under ignored
  `.runtime/parity-evidence/handoff-review/`. Earlier evidence references below
  are relative to `.runtime/parity-evidence/`.
- Full parity was incomplete. A successful review push proves delivery of this
  checkpoint, not completion of the native/visual matrix.

## 2. First session: establish current facts with MCP

1. Call `prepare_start(task="Finish remaining GUI/CLI parity from parity-continuation-plan")`
   before ordinary inspection, tests or edits. Preserve dirty work. Fetch,
   divergence, dirty non-dev or dirty-behind-dev blockers must be resolved through
   the repository workflow, never by resetting or discarding work.
2. Read the returned instructions, then the router in [README.md](README.md),
   [development.md](development.md), [test-matrix.md](test-matrix.md), and focused
   docs for the first assigned slices. Call `docs` and `change_impact` before
   broad searches. Use `workflow_status(instructions_read=true)` to record scope.
3. Inspect current `git status --short`, diff/stat, HEAD, version, prepush receipt
   and exact-SHA CI. An old test report or commit does not validate new contents.
4. Read the opening current section of [work-in-progress.md](work-in-progress.md).
   Use historical sections only to locate a named artifact, failed operation or
   evidence receipt. Several old sections still say “current”; those headings do
   not override the opening ledger or actual source.
5. Call `vm_workflow(action="matrix-status", inputs={})`. At this review's
   baseline it reported **22 open requirements and zero registered reviewed
   receipts**. That is an evidence-accounting gap, not proof that all associated
   behavior is absent. Reconcile saved evidence before planning duplicate runs.
6. Call `ssh_workflow(action="inventory")`; inspect only the relevant configured
   aliases using bounded `probe`, `android-observe`, `environment-status`,
   `job-status`, batch status or scenario status. Resolve private locations via
   the ignored inventory and receipts. Do not paste credentials or raw configs.
7. Inventory existing long-running checks, builders, VM monitors and fixture
   jobs. Pausing a Codex task does not terminate its accepted child processes.
   Preserve their sessions/identities and observe completion before assigning
   conflicting work. A stale PID or old tool handle is not current authority.
8. Replace stale WIP ownership with a compact table: slice, owner, exclusive files,
   environment, original source/artifacts, current operation identity, next action,
   exact remaining gate and cleanup owner.

### MCP availability and configuration

The server in `.codex/config.toml` is the normal repository entry point. If the
file is absent, generate it with `python3 agent_tools/configure_codex.py`.
Allow the launcher to prepare `.agent_venv`; reload the session when the client
inventory or cached server implementation is stale. If transport cannot use the
current implementation, report that limitation and invoke the equivalent
`agent_tools/mcp_tool.sh` action in a fresh process. Do not replace managed
operations with improvised SSH/shell mutations. For native acceptance on every platform,
TEST-002 requires the guarded direct native proof phase described in section
12 before MCP integration and equivalent retesting.

Toolchain paths may be supplied through ignored, owner-only
`.codex/build-env.local.json` (`JAVA_HOME`, `ANDROID_HOME`). Use the validated
loader, not tracked machine paths or shell fragments. Start macOS shell commands
with `unset DYLD_INSERT_LIBRARIES`, following the narrow output-filter guidance
in development.md. Preserve exit status and all other diagnostics.

## 3. Preserve implementation already completed

The original handoff at the start of the old task is now historical. In
particular, do not automatically reimplement its “confirmed gaps.” Current code
and recent audits already include:

- Typed registry, common command grammar/results, epoch/revision guards,
  operation tracking and request deduplication.
- Authenticated desktop controller/frontend separation and owner-scoped runtime,
  reconnect and scheduled work; Android application-owned dispatch.
- Android watch/follow and large-document transport/retained results. The latest
  CLI audit found no concrete missing handler. Routing app assignments are
  Android-only; desktop update installation is revision-guarded.
- Windows production scoped broker and preparation/commit paths. The old claim
  that the broker is disabled, all CUSTOM input is rejected, or whole-GUI
  elevation still needs wholesale replacement must not be used as current fact.
- Platform installer adapters and correlation journals, substantial native
  partial evidence, immutable fixture/artifact helpers and resumable MCP batches.
- The repeated-failure ledger and routine regression wiring.

Audit reachable GUI callbacks and public adapters against the current registry
when a scenario suggests a gap. Do not invent another command hierarchy or
replace shared controllers with CLI-only business logic.

Keep current product limits: macOS proxy-only; Android package routing remains
Android-specific; supported autostart only; empty-install data; routing transfer
version 7; input-only SSH keys; current catalog architecture and fixed theme.
Do not restore dormant editors, default subscriptions/rules or demo content.

## 4. Current evidence and immediate blockers

| Area | Established evidence and limits | First remaining outcome |
| --- | --- | --- |
| Windows public MSI | CP117 cancellation recovered with corrected complete 2.1.18 image, exit130, installed=false and cleanupCode=OK. CP176 real UAC passed, then the protected job failed before Installing/msiexec. | Build/package the new enum-only diagnostic; run one freshly admitted scenario and identify exclusive-admission versus installation-readiness failure. |
| macOS installer | Historical machine/user-local replacements and user-local rollback exist. CP174 reboot lost preauthorization with no receipt; legacy job lacks original boot token. New prior-boot recovery is implemented but needs packaged proof. | Verify future-job machine and user-local reboot/process-loss recovery; preserve legacy unknown jobs; finish machine rollback and automatic GUI return. |
| Linux | Earlier installed RPM GUI lifecycle passed 300/300 traffic frames. CP174 Find Best/scheduled refresh measured51.1ms and cleaned up, with a permitted short controlled restart; installed2.1.17 mixed-artifact evidence. | Complete strict RPM harness admission/cleanup and same-source base/target package acceptance, then current-package lifecycle/refresh. |
| Android API35 | CP174 frozen source5cebf15/2.1.18 response-loss run committed exactly once, preserved identity and restored all56,000 domains. | Register exact evidence scope; finish current-package/API29 equivalents, action/installer/process/resource scenarios. |
| Android API29 | Historical48MiB cold large-document reads, ON/OFF and consent denial exist; an interrupted consent-grant result expired and remains unknown. | Fresh admitted consent grant and remaining action/installer matrix on a nondebuggable compatible APK. |
| Documents | Many causal unit/memory/export tests and positive native slices exist; broad native failure matrix is incomplete. | Map exact current tests/receipts, then fill identified failure/resource/persistence/GUI export gaps. |
| Visuals | Six Android installer baselines had historical review. Desktop add/edit location baseline PNGs are missing on Linux, Windows and macOS; no current-SHA four-platform review receipt. | Capture the missing/changed scenes and complete current-source review through the visual tools. |

### Preserve these exact operations and artifacts

- **Windows terminal failure:** request
  `99126312-977f-4a61-a9ef-fb6884d2d26f`, operation
  `a021aae5-2235-4646-b750-01dca01441d0`, protected job
  `9107428f-9c80-4284-9f4e-926350105a59` under
  `checkpoint176/windows-msi/`. It reached WaitingForExit and failed
  RUNTIME_FAILED before msiexec. Base2.1.17 remained intact and scoped cleanup
  completed. This job is terminal; never replay it.
  The nested `checkpoint176/windows-msi/windows-msi/handoff.md` describes an
  earlier CP175 cancellation despite its directory name. For the later failure,
  use the exact-job `read-current-job.stdout`, `read-operation-status-2.stdout`
  and current WIP, checking the correlation rather than the filename alone.
- **macOS legacy unknown:** job `465a954f-cd70-45c4-896d-67e4508bae49` on the
  frozen2.1.17→2.1.18 pair. Its missing launch boot token cannot be manufactured
  after reboot. Preserve inputs, worker, DMG, correlation and other historical
  unknown jobs. Receipt absence alone cannot terminalize it.
- **Linux rejected correlation:** `a1f33191-4f6d-41dc-aa1e-cbc4c6029282` from
  CP173 is terminal/rejected. Use a new correlation only for a genuinely new,
  admitted run. CP174 evidence is under `checkpoint174/linux-refresh/`.
- **Android response recovery:** request
  `29be994c-6cd1-4e43-956d-568c1506bc03`, operation
  `2fe094a8-a29c-4603-8088-07ce68a71c35`; final restoration revision2.
  Evidence: `checkpoint174/android35-document-response-loss-rerun/`.
  The baseline contains56,000 domains and11,872,243 bytes, originally
  ignore=false. Preserve its full backup. Export timestamps are generated;
  use the canonical rules comparison for separate exports and exact bytes for
  the retained committed response.
- Frozen Windows/macOS pairs and the Android package referenced above retain
  original source5cebf15 provenance and2.1.17/2.1.18 fixture versions. Never
  relabel them2.1.19 or as the final delivery SHA. The verified Linux CLI image
  used for Android has archive hash
  `826b597754bf422de67566bead66d8640720847d35073dc09c302af92772a504`
  and tree manifest hash
  `d045410fd7351eb097057177b04ba3280b7af40cd488b63044c7ec28984ab60f`.

## 5. Subagent allocation and sequencing

Start with four independent workers plus the coordinator. Add workers only when
files, native environments and build capacity are independent. Follow current
development.md model guidance for bounded workers; preserve any explicit user
model override. The receiving coordinator is GPT-6 Sol medium.

| Worker | Exclusive initial outcome | Owned/reserved boundary |
| --- | --- | --- |
| Windows installer | Diagnose and fix current packaged pre-MSI failure, then successful public replacement/recovery | Windows installer role/session/native helper files, focused tests; one assigned AMD64 guest |
| Android acceptance | Close one API-level action/document slice, then installers | Android domain owners/tests and one identified AVD; transfer installer ownership explicitly |
| Linux acceptance | Achievable, truthful RPM cleanup and full fixed public-install batch | RPM adapters/harness/tests and one disposable Linux guest; no shared MCP registration edits |
| macOS recovery | Packaged boot recovery, rollback and GUI return | Mac recovery/installer files/native worker/tests and sole local Mac VM |
| Coordinator | Evidence matrix, common integration, artifact freeze, Gradle, metadata, delivery | Shared registry/model/protocol, mcp_server.py, workflow lists, docs, changelog |

After critical fixes stabilize, assign a bounded independent review and a visual
worker. Apply TEST-003 to run independent native scenarios in parallel, including
Windows scenarios with separately verified guests or isolated state. The sole
operator may batch independent read-only observations in one guest. Windows
runtime/broker effects serialize with MSI work when they share a guest; separate
verified guests may run them concurrently within available resources. A document
audit can run read-only in parallel, but shared codec edits require explicit
ownership transfer. Each scenario follows direct native proof, then MCP retest.

Each worker brief must contain:

1. One concrete result and measurable acceptance criteria.
2. Exact owned files and shared files it must ask the coordinator to integrate.
3. Applicable contracts and two or three focused docs.
4. Current source/artifact IDs, scenario/job identities and evidence location.
5. Environment, permission and cleanup boundaries.
6. Fast regression and native commands/gates, including expected skips.
7. Instruction to fix a causal failure and improve MCP before repeating it.
8. A compact handoff: changes, tests/counts/skips, evidence hashes, unresolved
   cases, process/job state and next safe action. “Scaffold added” or “tool
   returned successfully” is not completion of a native outcome.

Reuse an effective worker for the same subsystem. Rotate at a coherent handoff,
not midway through an accepted native operation. Do not create user-visible
Codex tasks for these workers; use subagent tools.

### Dependency order

1. Reconcile review delivery and live environment/evidence state.
2. Repair/admit the Windows diagnostic, Mac boot guard and RPM harness paths;
   run quick tests and one coherent prepush/push checkpoint.
3. Freeze complete source-matched packages and reuse verified eligible artifacts.
4. Run disjoint Windows, Android, Linux and Mac acceptance slices.
5. Convert each distinct failure to causal regression + MCP improvement, fix,
   validate, checkpoint, rebuild only invalidated artifacts, rerun that scenario.
6. Complete remaining owner lifecycle, broker, document and GUI/CLI comparisons.
7. Capture/review current visual scenes; deliver any reviewed baseline fixes.
8. Close every matrix requirement, final exact-SHA CI and final artifact/evidence
   reconciliation. Maintain checkpoint pushes without calling them full parity.

## 6. Windows work package

Read cli.md, desktop-lifecycle.md, runtime safety, native runtime artifacts and
Windows packaging sections. Primary files include
`desktopApp/src/main/resources/windows-install-helper-{roles,sessions}.cs`,
the remaining `windows-install-helper-*.cs` components, desktop Windows installer,
handoff/receipt classes, broker files, and their adjacent tests.

### MSI root cause and replacement

1. Verify full nativeAMD64 package/image identity and both packaged helpers.
   A new JAR in an older installation or ARM emulation is component evidence.
2. Reidentify the exact CP117 guest and ordinary-user interactive session.
   Probe the private credential with the fixed credential-validity workflow.
   A stored password, QMP input acknowledgement or dismissed dialog is not a
   successful login or authorization.
3. Build/freeze a same-source compatible base/target pair containing the new
   protected diagnostic. Preserve actual package signer, architecture, hash,
   version, helper/runtime hashes and source fingerprint.
4. Verify compact and expanded UAC observations independently, with the exact
   guest, operation, selected account, current screenshot and intended empty
   credential field. Keep credentials in the private approved mechanism.
   The full fixture CLI requires separate `--compact-observation` and
   `--expanded-observation` records (version1, phase, frameSha256,
   qemuIdentity, operationId and promptId). The capture owner creates them;
   the credential driver separately rechecks current prompt freshness through
   the existing `windows_prompt_observation` guard immediately before input.
5. Submit one new public CLI update; retain request/operation/protected job tuple
   before observing. Inspect the fixed enum-only stage/kind diagnostic if it
   fails before Installing. Do not infer which admission failed from the generic
   RUNTIME_FAILED code.
6. Add a quick reproducer for the established cause, improve the relevant MCP
   preflight/diagnostic, fix it, rebuild, and rerun with a new admitted operation.
7. Prove actual msiexec success, exact target installed bytes, ordinary original
   user relaunch, next-owner receipt recovery, cleanup and original OFF/reconnect
   intent. Async handoff must receive the authenticated ready acknowledgement.
8. Complete grant/denial; ordinary/elevated requesting owner; different approving
   administrator; participating-copy locks; original-user worker; protected
   storage/reparse/ACL/admission races; transport/process loss and cleanup.

Tests include `DesktopWindowsInstallHelperRoleTest`, native coordinator admission,
original-user launch and mutable broker tests, plus `test_windows_msi_fixture_preflight.py`,
`test_windows_qga_powershell_size.py` and native helper/package tests. Preserve
native-only skips on macOS; Windows CI and the owned guest supply those results.

### Scoped VPN and lifecycle

Validate the existing production broker rather than rebuilding its architecture:
ordinary GUI/config/proxy-only without whole-app elevation; UAC only for scoped
VPN preparation; exact broker/child identity and owned stop; TUN traffic; active A
and pending B across denial and preparation failure; commit/recovery; generated
and CUSTOM configuration, large configuration, DNS/WS/SSH/cache/resources;
pipe/storage races; ordinary autostart and owned legacy HIGHEST migration.
Native reboot and foreign-task rejection remain required. Task Scheduler lacks
atomic same-name compare-and-swap; repeated reads do not prove that guarantee.

## 7. macOS work package

Primary owners: `DesktopMacInstaller`, `DesktopMacBootSessionRecovery`, Mac native
admission/handoff/recovery classes, `scripts/native/macos_install_worker.c`,
`agent_tools/macos_installer_recovery.py` and tests. Use existing rollback,
process-role and resource-monitor harnesses.

1. Admit the sole task-owned local macOS VM with current memory, disk and monitor
   evidence. Confirm actual boot session and preserved installer state first.
2. Use `vm_workflow("macos-installer-recovery-status", inputs)` for the exact
   redacted legacy job observation. Its caller-supplied facts never authorize
   cancellation or replay; it only distinguishes unknown from a maintenance
   candidate. Product code must reopen authoritative inputs itself.
3. For **new** jobs, prove boot token publication before coordinator attempt,
   strict private/no-follow token reading, exact job binding, distinct kernel
   boot session and a second authority-specific receipt-absence check. Same boot,
   malformed/missing token, aliased/unsafe token path, unreadable receipt or
   existing terminal receipt must not be misclassified as not-started.
4. Run packaged reboot/process-loss cases for machine and user-local authorities.
   Verify recovered result, preserved prior app and exact scoped cleanup. Keep
   the old missing-token job unknown; use a separately admitted fresh workspace
   or disposable clone if it cannot safely host a new scenario.
5. Complete machine rollback, first-gate races, late grant/denial and interrupted
   recovery. Retain actual C copyfile/storage failure evidence; its old EIO cause
   was not established as host disk pressure.
6. Verify automatic GUI return in a real graphical login session with original
   user identity, actual frontend presence, correct target bytes and controller
   state. A receipt watcher process is not the installer coordinator or GUI.
7. Verify DMG/signature/helper admission and user-local + machine installation on
   final relevant artifact inputs. Do not use mounted-image execution as proof
   of an installed update.

Finish proxy-only owner lifecycle and traffic, Unicode/space paths and explicit
unsupported VPN behavior. No host installation, trust change or host VPN action.

## 8. Linux work package

Primary owners: `native_rpm_public_install_adapter.py`,
`native_rpm_public_install_ssh.py`, `native_scenario_batch.py`, Linux public-install
harness/driver, scheduled-refresh runner and corresponding tests.

1. The current strict cleanup observer fails closed on uninspectable same-UID
   `/proc` entries. Diagnose exact process visibility and ownership on the
   intended disposable guest. Do not make unreadable entries mean “absent.”
   Prefer a bounded exact-process identity/owned process-group observer if that
   can prove cleanup; otherwise retain unknown and improve the diagnostic.
2. Keep descriptor cleanup and journal state durable on all failure paths. A
   receipt labelled passed needs verified terminal exit0, public recovery and
   scoped cleanup; batch/node success cannot manufacture those facts.
3. Check current registered packages before admitting another build guest.
   The historical handoff needed a matching base RPM. Local review on2026-10-06
   verified build86fcac2e's d32 source-matched2.1.19→2.2.2 RPM, DEB and Arch pairs
   with full registered size/hash/generation checks; no missing-base build remains
   for that cohort. The separate bbe1aafe2.2.1→2.2.2 cohort must not mix with it.
   This is local artifact evidence, not fresh guest eligibility or final-source
   acceptance. Preserve Fedora2328's installed base and pending installer state.
   If an actually missing or source-invalidated package requires a build, use a
   separate admitted guest and verify prerequisites first: JDK17, objcopy/binutils,
   correct native architecture and required package tools.
4. Prepare/verify the immutable bundle and typed scenario inputs; register exact
   artifacts; use `batch-plan` with recipe `linux-rpm-public-install-recovery`,
   then `batch-status` with only `batchId` for verification/preflight nodes.
   The generic `fixture-preflight` route does not accept this RPM recipe.
   Call `batch-start` once after admission (it refreshes preflight), then
   status/resume/collect by immutable batch/correlation identity.
   The RPM plan fields are `batchId`, `recipe`, `host`, `environment`,
   `bundleManifestArtifactId`, `scenarioInputArtifactId`, `sourceFixtureArtifactId`,
   `targetPackageArtifactId`, `credentialHandle` and `scenarioCorrelationId`.
   Read current strict schemas rather than inventing input keys.
5. Complete RPM success, failure, cancellation, transport-loss and next-owner
   recovery. Reconcile DEB fresh-dependency/headless and Arch replacement/rollback
   historical receipts, then perform any source-invalidated final-package cases.
6. Retain terminal PTY ownership and its echo/password admission. Polkit account
   selection is a separate phase from password admission. Installer/package
   managers must not be killed to force a harness completion.
7. Revalidate scheduled refresh and Find Best using the fixed
   `linux-scheduled-refresh` preflight/batch with verified installed RPM/JAR,
   protected OFF owner, exact workspace parent, real HTTPS/TLS endpoint and
   persisted nested settings schema.
8. Separate the no-interruption GUI lifecycle criterion from a deliberate
   Find Best configuration transition. CP174's224/226 old-listener probes and
   approximately0.265s replacement recovery are a permitted controlled restart,
   not an uninterrupted-traffic pass. Refresh must not strand runtime stopped.

Finish installed headless/public CLI, static discovery without workspace creation,
missing-owner status, transient owner, persistent disconnected serve, explicit
OFF/reconnect behavior, long work after CLI loss, GUI hide/show/close/crash/reopen
with unchanged runtime and continuous measured traffic.

## 9. Android work package

Use Android owner/control services and provider/document classes already present.
Keep public control nondebuggable, authorized ADB UID2000, without root/run-as.
Only separately authorized disposable fixture trust setup may use guest privilege;
restore UID2000 before every public product action and record cleanup.

### Admission and actions on both API29 and API35

1. Start with `android-observe`: it verifies shell UID/API/AVD and returns redacted
   proxy fields, controller consistency and operation count. It does not establish
   ABI, package/signer/version, revision, reverse mappings or full operation
   history. Obtain those through existing package/device admission and public
   status/history reads before forming mutation guards. API35 AVD5682 was last
   recorded clean; serials are historical hints until verified.
2. Verify full routing backup before any mutation. APK replacement changes the
   owner epoch. Use `post_install_mutation_guard` with fresh public status and
   same-owner terminal history; never reuse pre-install guards or replay a stale
   request. Wire helpers through the reusable native driver/MCP preflight.
3. Complete authorized/unauthorized Binder and stream access, noninteractive
   rejection, consent grant/denial, ON/OFF/restart, actual traffic and stats.
4. Test Find Best success, measured benchmark, cancellation, runtime recovery,
   pending B versus actual A, candidate eligibility/CUSTOM exclusion, response
   loss after commit and truthful unknown outcome. A benchmark with null timings
   proves completion only.
5. Verify manual/connected/scheduled refresh, source removal, foreground service
   with Activity closed/recreated, GUI callbacks/pickers/stale drafts, ADB loss,
   watch/follow cursor and owner-replacement behavior.
6. Complete SSH preparation/key replacement, secure storage, failure rollback and
   committed-setting restart. Unsaved draft settings must not be applied.

### Installers on both API levels

Use a compatible signed base/target pair and inspect installed version before
choosing fixture versions. Complete noninteractive rejection; unknown-source
permission grant/denial; confirmation/cancel; success/exact receipt recovery;
loss before commit/during confirmation/after handoff; independent explicit resume
after original UI disappears; retry without duplicate sessions; terminal cleanup;
repeated-install retention; wrong signer/package/version and corrupt APK rejection.
Keep journal-before-session, AtomicFile backup/corruption behavior and required
APK/session inputs while the external installer may still need them.

Key regressions include Android Find Best/prepared plan/connection/refresh, GUI
location/SSH drafts, PackageInstaller session lifecycle/receipt recovery, settings
actions and control documents. Run native scenarios in one environment at a time
per operator; do not reset an uncertain operation to unblock another slice.

## 10. Documents, protocol and GUI/CLI equivalence

Use `document-persistence-transfer` in `native_acceptance_requirements.json` as
the scenario checklist. Do not infer it is closed from CP174's single response-
loss success or historical cold reads.

- Retain over11MiB/56,000-domain input and the required48MiB Android heap case.
  Prove consecutive add/remove persistence, first/full/cold readback, exact retry,
  new-request no-op, retained wait/result and private export.
- Test Preferences/protobuf/newline compatibility, full cache digest/bytes,
  mutable transaction inputs, failed persistence, resource exhaustion and cleanup.
  Do not relabel allocation/storage failure as invalid user input.
- Cover wrong principal/owner/context/kind, expiry, forged IDs, hash/length
  mismatch, interrupted transfers, lost acknowledgements and replacement owners.
- Preserve responsive status/cancellation and known committed results. Timeout
  never cancels accepted work or authorizes a new owner's replay.
- Test no-overwrite/private exports, existing and racing destinations, parent
  replacement, no partial final files, Unicode/surrogate behavior, and actual GUI
  picker/export paths. Keep raw exports free of envelope bytes; reject JSON plus
  raw stdout. Human errors/progress belong on stderr, streams use NDJSON.
- Check registry/help/capabilities/public dispatch using real adapters and GUI
  callbacks over identical effect fixtures. Cover each source scope, selector,
  pending settings, revision conflicts, progress/cancellation and unsupported
  platform result. Two wrappers over the same mocked result do not prove parity.

Anchors: `AndroidRoutingPipelineMemoryTest`, `AndroidPreferencesSerializerTest`,
`AndroidConfigurationStoreTest`, `DesktopAndroidDocumentClientTest`,
`DesktopLargeControlTransportTest`, `DesktopExportPublicationTest`, shared control
codec/registry tests and scripts for routing evidence/private publication.

## 11. Visual and localization completion

1. Read visual-regression.md and inspect the actual scene manifest and Git LFS
   baseline files. Canonical Android is Pixel6/API35 portrait; API29 remains a
   product/native gate, not another canonical baseline set.
2. Capture missing `locations-add-dialog` and `locations-edit-dialog` baselines
   on Linux, Windows and macOS, plus all other changed/missing required scenes.
   Verify complete installer, permission, progress/error/unknown and pending-
   restart surfaces and stress variants against current UI inventory.
3. Use `python3 scripts/visual_platform.py` for platform `plan`, `probe`,
   `bootstrap`, `start`, `capture-local`, eligible `dispatch-hosted`/
   `download-hosted`, `verify`, and scoped `stop`. There is no registered
   `visual_platform` MCP tool. MCP `visual_workflow` accepts `start`, `status`
   and `complete`; use `release=false`. MCP `visual_review` takes `target_sha`,
   `platform`, `scene_id`, `verdict` and optional `notes`. Bind exact source,
   scene and environment hashes. Capture app-owned UI deterministically; use
   full-screen native capture for OS surfaces. Open every screenshot/contact
   sheet before recording a verdict; inspect geometry and contrast reports.
4. Desktop canonical capture is1280x800 at100%. Preserve scene-specific stress
   environments. Do not mask defects or accept clipped/ANR-covered captures.
5. The old local Windows ARM visual VM and READY marker were retired in the
   authorized cleanup. Recreate/admit an owned suitable environment before secure
   UAC capture; hosted capture cannot substitute for unsupported secure surfaces.
6. Keep translations in JSON catalogs, preserve placeholders, run localization and
   typed-status checks; one owner per language file for broad changes.
7. Update intentional baselines/inventory together on dev, run checks and deliver
   them before final exact-source review. Partial reviews must remain partial and
   must not create a release approval/status. This task does not authorize release.

## 12. Native acceptance: direct proof, parallel ownership and MCP equivalence

For each distinct integration/native/fixture failure, TEST-001 already requires a
quick causal regression and a related MCP improvement. A repeated class must
trigger explicit workflow repair before another expensive attempt. Track
`failure class → cause → quick RED → fix → GREEN → routine suite → MCP action → native rerun`.

Apply `TEST-002` on Windows, Android, Linux and macOS: first get each complete
required scenario working directly through SSH, CLI, ADB or native tools outside
MCP. Verify its success, applicable failure/recovery cases and cleanup with actual
native evidence. Only then integrate the proven procedure into MCP and repeat
the same cases against matching source/artifacts. Repeated MCP failures return
the affected scenario to direct diagnosis. Both phases preserve ownership,
protected state, provenance, causal regressions and non-replay rules. Normal
repository startup and delivery still use MCP.

Apply `TEST-003` to parallelize independently owned native scenarios. Record
exact guest/emulator, source/artifacts, original process/job handle and cleanup
owner for each. Serialize interfering installer, machine-wide VPN, reboot and
recovery operations in one guest; use separate verified guests or isolated state
for concurrent effects. Batch independent read-only observations under the sole
guest operator. Resource limits and unknown outcomes remain binding.

1. Save the failing command outcome, exact source/artifacts, request/job identity,
   bounded redacted diagnostics and cleanup/uncertainty state. Distinguish product,
   fixture, transport, environment and test-portability defects.
2. Inspect `parity-failure-regressions.md` and native failure receipts under
   `.rag_index/native-failures`. Repeated identical evidence is deduplicated;
   counts alone do not prove the same root cause.
3. Reproduce the application-controlled cause deterministically before fixing.
   Compilation errors, source-text assertions and mocks that assume the desired
   result are not causal RED evidence. Use actual fake transports/processes,
   persisted schemas, descriptor/ACL logic or constrained heaps as appropriate.
4. Extend the existing narrow tool when it owns the failure. Add a new fixed
   typed MCP action only if no existing action can express the safe operation.
   Prefer strict admission, bounded observation, exact diagnostic or guarded
   reconciliation over a general shell/SSH tool.
5. Require strict keys/types, private configured aliases, immutable artifact and
   source identity, durable intent before effects, exact correlation, status/
   resume/collect, safe nextAction and replayAllowed=false for uncertainty.
   Never accept arbitrary commands, unsafe paths, secret arguments or authored
   success flags as native proof.
6. Test the public MCP route and CLI fallback in a fresh process, with script-mode
   module shadowing and actual FastMCP serialization where available. Test missing
   fields, malformed receipts, failed/missing exit codes, response loss, repeated
   correlation, foreign owner, stale observations and interrupted cleanup.
7. Run portability checks with unavailable APIs (`getuid`, `fcntl`, `getsid`),
   real supported shell/argument conventions and native CI. Do not skip a safety
   test to make Windows green. Connect every new quick test to ordinary hygiene/
   prepush and applicable package CI.
8. Document exact inputs, evidence scope and safe continuation in agent_tools/README
   and the failure ledger. Reload stale server code/inventory or use the documented
   equivalent fallback, then prove the fixed public tool route before native use.
9. Rerun the original native scenario on the fixed complete artifact. Unit green
   and “tool ok” are separate from installed-package acceptance.

Recent classes to guard: nested SSH recovery suffix/renewal/private-config route;
MCP module shadowing; missing JDK in desktop-launched tools; stale Android epoch
after install; UAC compact versus expanded frames; QGA payload length; missing
workspace parent; nested persisted settings; missing terminal exit/cleanup proof;
Linux unreadable process state; Mac boot/receipt ambiguity and unsafe token paths;
portable tests accidentally invoking POSIX APIs on Windows.

## 13. Artifact, resource and evidence discipline

- Use `artifact-register/find/verify`, `bundle-prepare/verify`,
  `artifact-set-freeze/verify` and `artifact-reuse-check`. Freeze complete packages
  from clean coherent product inputs with exact signer/architecture/runtime
  provenance. Test-version overrides are fixture metadata, not product releases.
- Reuse checks derive changed paths from Git. Eligible docs/test-only differences
  may preserve original evidence; product/build/runtime changes require rebuilding
  affected bytes. Never relabel an older artifact's source SHA.
- Use typed fixture preflight, durable `batch-plan/start/status/resume/collect`,
  exact scenario/job observation, and environment reservations. Status timeout
  is unknown; it neither cancels accepted work nor permits resubmission.
- VM baselines require actual stopped-state/access/dependency/no-pending-installer
  proof. Restore into a new clone/overlay. Never overwrite live/unknown disks or
  create readiness receipts by hand.
- On the24GiB Mac, allow at most one local test VM, reserving it for the4GiB Mac
  fixture; no overlapping local Android emulator. Use admitted owned Arch-host
  Android/Windows/Linux guests for other work. One local Gradle invocation at a
  time; reserve build memory and sparse-disk growth, not just current RSS.
- Earlier free-space observations are stale. Recheck actual disk/memory before
  admission. Preserve active guests, personal files, AI models, host VPN and all
  unknown installer inputs. Storage pressure is not permission for broad deletion.
- Preserve unrelated AVDs5580/5582/5584/5590/5592 and excluded
  `agent_docs/.Rhistory`. Exact owned fixture identity must precede any stop,
  process-loss, trust, VPN, installer or elevation operation.
- Record reviewed evidence through `matrix-record`: requirement/platform,
  originalSourceSHA, immutableArtifactIDs, evidencePath/hash, environment, result,
  scenarioResults, missingEvidence, nextFixedCommand, reviewerAttestation and
  evidenceScope. Use exact current schema; component/historical/partial receipts
  remain labelled. A generic suggested next command is not a new callable tool.

The matrix now supports immutable reviewed equivalence links through
`matrix-equivalence-record`, with separate read-only status observation. A reuse
check alone does not close a row: the link must bind the original full-native
receipt and registered artifact set to the exact committed target source and
reject product/build/runtime changes, provenance races and conflicting receipts.
Original source and artifact identities remain unchanged. Component baselines,
inert checks and incomplete native scenarios cannot become full-native evidence
through equivalence. Record an eligible reviewed link after the final source
freeze, or collect exact-final-source native evidence. Changed-tool validation
and all exact-SHA delivery gates remain required.

The22 requirement groups are: API29/API35 native CLI; Linux/Windows/macOS native
CLI; four platform visuals; final dev CI; API29/API35 installer and actions;
Linux/Windows/macOS installer lifecycle; Windows scoped VPN; three desktop owner
lifecycles; document persistence/transfer. Preserve every required scenario in
`agent_tools/native_acceptance_requirements.json` while registering evidence.

## 14. Validation, checkpoint delivery and final stop condition

During changes, run focused mapped tests and preserve causal RED/GREEN receipts.
The coordinator batches compatible Gradle selections. Inspect every skip and
record the OS-native evidence still needed. Never run a real host VPN test to
avoid creating a guest.

At each coherent delivery checkpoint:

1. Update current WIP and failure/evidence mappings, then `workflow_status` and
   review every changed path, including untracked source.
2. After final content changes, call `version_bump` with one concise new bullet.
   Preserve previously recorded change bullets; do not roll/version manually.
3. Call `run_checks(level="prepush")` after metadata. The tier covers whitespace,
   release/docs hygiene, agent-tools, visual/theme/localization checks, shared
   tests, desktop tests, Android tests/compiles/instrumentation signatures,
   desktop SDK independence and Windows packaging/diagnostic checks.
4. Do not reuse the content-bound receipt after edits. Fix failures and rerun the
   final tier; don't replace it with a historical successful command.
5. Call `git_workflow(action="commit", message=..., paths=[explicit reviewed paths])`.
   This managed action commits, pushes and begins exact-SHA verification. Its
   path list must account for all dirty scope; no generated/native runtime/private
   files. Use `push` only when the coherent commit already exists.
6. Capture full HEAD and use `git_workflow(action="checks", sha=...)` until all
   required workflows in `.github/required-workflows.json` succeed: Fast Checks,
   Android Release APK, Linux Desktop Package, Windows Desktop Package and macOS
   Desktop Package. Missing/pending/cancelled/failed is incomplete.
7. For a failure, inspect the bounded failed log, add/update a causal regression
   and MCP/tool prevention where relevant, fix, rerun prepush, commit/push and
   restart the loop for the new SHA. Advisory VPN Integration does not replace
   native parity; no stable release workflow is dispatched.

Full parity can be reported only when every required behavior/scenario has current
or explicitly eligible verified artifact evidence, required visual review is
complete, no required outcome is unknown, the final prepush receipt matches the
delivered contents, and all five required workflows are successful for the exact
delivered SHA. The final report must name the SHA/version, test results/skips,
native/visual evidence and any true residual limitation. If a gate is blocked,
report that exact gate and preserve all work; do not convert it into success.
