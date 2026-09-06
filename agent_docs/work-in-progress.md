# Work In Progress Notes

Use this file only when a large task intentionally leaves multiple buckets changed at once. If the worktree is clean or changes are small, leave this file as a template.

## Current Work: GUI/CLI Parity

Fresh-agent checkpoint map (2026-09-06; read newest notes before older history):

Development checkpoint `4d8a2e7a23ba0b805b235929574dc21a261b60cd` is committed
and pushed to `origin/dev`. Fresh full prepush752 passed before the push. Fast Checks,
Android Release APK, Linux Desktop Package and macOS Desktop Package succeeded for
that SHA; Windows Desktop Package34027258751 failed59/467 tests. Advisory VPN
Integration also succeeded. The development delivery gate is therefore NOT complete.
The next intentionally parallel dirty buckets are Android runtime-safe DELETE/IMPORT
(gui_location_reference), Android protected installer interaction (android_session),
and shared bounded chunk-transfer protocol/state (native_cli_checks). Root owns
integration, transfer adapters and CI follow-up. These are implementation assignments,
not completed functionality. Agents coordinate shared owner/adapter edit regions;
one local Gradle invocation at a time. No live VPN/installer permission tests are
authorized by this checkpoint, and the full parity goal remains open.

Next-batch evidence and findings (in progress, not pushed):

- Source frozen after final Android2682:35 app tests (planner5/destructive7/GUI6/
  runtimecommands8/observer4/legacy5) plus Android/instrumentation compilation passed.
  Public ADB16 passed21286/50649. DELETE/IMPORT now use guarded asynchronous owner
  admission, private actual-runtime capture, acknowledged pinned stop, commit and
  runtime-only recovery. Deleting pending B preserves active A and its telemetry.
  EDIT/SELECT/DELETE carry rendered raw+source scope/hash, rejecting reordered,
  disappeared or source-drifted targets. Import captures revision before picker.
  Actual runtime stop/recovery/consent denial and screenshots remain untested.
  Benchmark still uses positional GUI targeting and is a remaining parity gap.
- Final Android install21286 passed8 install regressions plus existing update/location
  union and16 ADB tests. All Android source is frozen for consolidated validation.
- Native Windows2137 passed50 tests65.369s under real elevation0;16772 passed50
  tests75.592s under linked elevation1 with the same account SID. Includes endpoint
  ownership, spool default-directory privacy, native installer IO/reparse policy,
  ADB, autostart, public Main process/Unicode and QR tests. Frozen evidence host
  /tmp/vpn-windows-ci-native.XOkCOr; guest
  C:\\Users\\visualagent\\AppData\\Local\\Temp\\vpn-ci-XOkCOr.
  Bundle SHA25647f0d09dd07098e1f4fe651a8509f425b544352795e48e36739d1dd6379aa73a.
  Microsoft OpenJDK17.0.20.1+1 x64 on WindowsARM64 (x64 emulation), not hostedx64
  package proof. Remaining previously failing Windows classes are running separately.
  Host/defaultVPN and all application runtimes were untouched. No installer was run.
- Root is applying one consolidated changelog note and fresh full prepush for this
  batch, then will push and restart all five exact-SHA required workflows. This is
  not full-goal completion; large transfer adapters, Android refresh/find-best/
  benchmark/streams, complete install recovery and desktop elevation/install work,
  native live-traffic and visual proof remain open.

- Latest combined50864 passed24s: final shared transfer11 tests and focused desktop
  ADB/bootstrap/native-platform-gated/spool/endpoint/transport/autostart union.
  It includes the single-retained-file spool refinement. JVM process bootstrap
  regression91745 passed3 tests afterward: test-only ASCII/base64 argv transport
  reaches actual Main with original Unicode args; real stdout/PNG/owner assertions
  remain. Production public-launcher Unicode behavior is still tested separately.
- Android install/update union58984 passed; next21286 includes more permission
  cases and current location work. A dispatched installer pin survives cancellation
  of its waiting owner coroutine. Installer handoff is not installed confirmation.
  IMPORTANT remaining gap: at most8 handed-off APKs are retained across owner
  lifetimes, without automatic reader-completion cleanup or installation reconciliation.
  Native permission/installer proof is not performed. Do not count this as full
  Android update installation completion/recovery.
- Native Windows agent is preparing a frozen class bundle for the already-running
  dedicated VM, ordinary and inherited elevated token cases only; no UAC policy,
  account, installer or VPN changes. No Windows result for these fixes exists yet.

- Root added DesktopControlTransferSpool: native private empty-file creation inside
  a verified private directory, then one retained no-follow FileChannel with bounded
  append/read buffers and incremental SHA256. No document-size cap or per-chunk
  in-memory index. Red42996 showed the missing implementation; initial green74817
  passed4 tests. Final single-file refinement and Windows ACL assertions need the
  next focused/native union. No public transport adapter is wired yet.
- Shared ControlTransferStore/Codec/Models/Spool were added by native_cli_checks;
  core53856 and combined99811 passed before the final chunk-response DTO addition.
  Cover UTF8 chunk boundaries, retry identity/offsets, seal/hash, private bindings,
  capacity, expiry and retained consumers. This is infrastructure, not completed
  large GUI/CLI transfer parity.
- Windows endpoint publish used ordinary temp-file owner (Administrators under
  an elevated Windows token), then required invoking-user ownership. Root switched
  creation to the existing private native writer with explicit token-user SID;
  verifier remains strict. Added direct invoking-owner regression. Local56916 and
  combined99811 passed endpoint/transport tests; native Windows proof is outstanding.
- Windows AutostartManager fixture expected only Exec argument escaping, missing
  the separate .desktop string layer. Root corrected the fixture helper and added
  explicit backslash/percent expectations; combined99811 passed. Production encoder
  already used both layers and was not relaxed.
- Windows fake-ADB fixture transported a Unicode temp path through Java17 argv;
  native_cli_checks changed only bootstrap path encoding to ASCII base64 and added
  a legacy-codepage regression. Real request content remains stdin. Native installer
  IO fixtures now exercise inherited standard or elevated tokens, explicitly assert
  actual file owner SID, and retain production-policy rejection; they never request
  elevation. Both changes await focused/native proof.
- Android DELETE/IMPORT red83582 reproduced INVALID_ARGUMENT. Runtime capture,
  pinned stop/recovery, guarded storage and dedicated executor are being integrated.
  Android INSTALL protected interaction/pinned APK path is also being integrated.
  Root requested regressions for cancellation after native stop/installer dispatch.
  These Android actions are not yet validated end to end.

| Bucket | Implemented checkpoint | Evidence still required / unfinished scope |
| --- | --- | --- |
| Shared control and desktop commands | Typed registry, authenticated sessions, guarded/retry-safe settings/subscription/location/source/routing/SSH operations, operation inspection, cursor streams, QR/export paths. | Large chunked imports/exports; final current-SHA native public CLI proof. |
| Desktop GUI ownership | Separate background owner/frontend, guarded drafts, acknowledged visibility, owner-aware shutdown, selected versus active presentation. | Live traffic across GUI crash/detach, remaining visual/error/localization cases. |
| Android protected adapter | Non-debuggable API29/API35 ADB authorization, actual runtime inspection, consent-aware connection responses, guarded settings/source/SSH, reads and exports. | Actual consent grant/denial and live VPN/SSH loading; complete GUI/worker operation coverage. |
| Android newer commands | Subscription CRUD/routing apps focused55; human output focused13; location/GUI staging+update union60; final update cancellation20 and visual fixture2; frozen release API29/API35 matrix150 calls all passed. | DELETE/IMPORT, refresh/find-best/benchmark, install and streams remain. No native live VPN, network refresh or update download/install proof. |
| Private exports | POSIX private creation plus macOS descriptor ACL rejection and Windows enforced owner-only ACL verification. | Current package proof; real non-ACL Windows volume rejection not executed (deterministic gate test exists). |
| Installer/elevation | Native protected job storage and several rollback/helper fixes. | Real helper/channel wiring, machine-wide admission, both-process handoff, typed installation/recovery; Windows operation-specific VPN elevation. No installer success claimed. |
| Development delivery | Full prepush728 passed at version2.1.1/8 notes; later edits only record evidence/design handoff and require a fresh receipt. | This is the precommit snapshot based on32de4ee. Consult Git/workflow status for subsequent checkpoint delivery; exact-SHA five-workflow CI success is not established by these notes. |

Current coordination: gui_location_reference owns location/GUI projection and
shared Android adapter integration; android_session owns the update engine/service;
native_cli_checks owns disconnected device harness/evidence and large-transfer
audit; root owns readable CLI output, docs and consolidated verification. One Gradle
invocation at a time. Freeze this batch before adding more work or building native
artifacts. Host VPN and emulator5580 remain out of runtime-test scope. iOS was
discussed as future architecture only and is not part of this implementation goal.

Android subscription/routing checkpoint (2026-09-06):

- Full prepush728 passed; build98793 produced frozen release APK and macOS app image.
  Native46735 passed75 public CLI calls on each non-debuggable API29/API35 device
  (150 total), plus readable human status on both. Covered positive subscription
  CRUD/source subscription+all, routing apps/rules/import, no-op/stale guards,
  location ADD/SELECT/selected UPDATE, client-file/raw-stdout JSON exports,
  no-overwrite, QR export and routing QR import. No product defect was found; two
  temporary harness assumptions were corrected (local argument-error owner metadata
  and localized displayed location names).
- Root macOS public packaged CLI smoke60163 passed against the same copied app:
  isolated workspaces/owners, headless commands, UTF8, NDJSON/Ctrl-C and QR paths.
  This is app-image/disconnected evidence, not DMG installation or live traffic.
  Artifacts/evidence: /tmp/vpn-android-native-728.FHNLM4/.
  APK SHA2566537051c63638e8493bcec0d67026d79eccd4d4ff18a000dda6de03bb1431eca;
  launcher SHA256f50b3a758497552365fa694ca29b3daf8ed553154207a2f8e31f83cbf7df6146.
  API29 report matrix-final/emulator-5582/report.json SHA256
  a312ed0b5e590c98f193114d941170a8a8e0f2322299aaf94d52587bc684d08e;
  API35 report matrix-final/emulator-5590/report.json SHA256
  01c3a52d72e0acc555c9b8e967f7cae7f0b7ae8950ee02a0081a2909e2d15e8e.
  Both ended runtimeRunning=false, zero starts/stops, no runtime ID/app services;
  task AVDs5582/5590 stopped,5580 and host VPN untouched. No native refresh,
  update download/install, consent or connectivity evidence is claimed.
- Source remains frozen. Root is refreshing full validation after documentation
  updates, then preparing a coherent development checkpoint and exact-SHA CI.
  Full goal remains open; remaining runtime-safe deletion/import, installation and
  bounded large-transfer design handoffs are recorded in cli.md.
- All source frozen after visual2386:2 fixture regressions and Android instrumentation
  compilation passed. MainActivity injects one immutable synthetic frame containing
  both UI and location projection, never real owner flags; locations-selected uses
  canonical row/selected-profile/benchmark references. No screenshot approval is
  claimed; pending A/B scenes, row-specific/banner tags, geometry/stress captures and
  actual review still remain. Root is applying consolidated metadata and running a
  fresh full prepush before frozen APK/launcher native matrix execution.
- Android update check/download/cancel/dismiss final61799 passed20 tests plus Android
  compilation after combined25788. Manifest-only checking is separate from download;
  exact checked asset/APK verification remains private. GUI and ADB use the owner
  ledger. Unknown VPN runtime does not block safe update operations. Progress and
  generic operations cancellation are wired; cancellation reserves the exact target
  under admission before awaiting cleanup, so it cannot cancel a replacement job.
  Immutable terminal code/data survive dismiss-before-waiter-resumes. No native
  network/download/install/permission tests performed; CLI install is unsupported.
  Update source frozen. One Android visual-fixture correction is still in progress:
  synthetic captures must not borrow real stopped-owner row flags. Full pending A/B
  screenshot cases and baseline review remain separate unfinished visual evidence.
- Location ADD/UPDATE/SELECT and real GUI staging/projection are now implemented.
  Final focused25788 passed60 tests: Android32 (planner4/owner1/frontend3/legacy5/
  settings12/updateengine4/updateowner1/updateinspection2), desktop28 (ADB15/CLI9/
  human4). GUI never reapplies live runtime for manual selection/selected-row edit;
  active-A/selected-B row flags and pending banner flow observer→ViewModel→Activity.
  Reverting to active configuration clears pending only when inputs match.
  Source preparation uses the captured planned source (not stale selected source);
  single-subscription ownership is not inferred from another subscription's cache.
  Read-only subscription editor inspection remains available. Definite final click
  rejection releases stale retry identity for the next explicit click; uncertain
  outcomes retain it. Native/screenshot proof remains outstanding, DELETE/IMPORT
  remain unsupported. Update cancellation reservation is receiving one further
  race regression/fix;25788 does not cover those subsequent edits.
- Android human output now renders readable owner/request/revision/completion,
  operation, pending restart, warnings and nested data for non-JSON responses.
  Unknown metadata remains unknown, async acceptance remains pending, and C0/C1
  terminal controls are escaped. JSON/raw exports are unchanged; file export
  summaries now preserve metadata/warnings too. Red44104 (3 failures) reproduced
  the missing human surface; green27416 passed. Additional C1 injection regression
  failed before escaping correction; final11678 passed13 tests (human4+AndroidCLI9).
  Android location add/update/select and update actions are in parallel development;
  no consolidated final prepush receipt exists for those or this output addition.
- Export ACL correction is now implemented and frozen. macOS checks the exact open
  descriptor for inherited ACLs before payload IO; Windows requires persistent ACL
  enforcement and verifies actual owner-only, noninherited file permissions before
  writing. Unsafe destinations can leave a new empty file, never exported bytes;
  existing destinations remain untouched. Real macOS regression57113 failed before
  the fix; focused20465 passed23 tests afterward. Windows native NTFS verification
  passed (3 applicable tests;2 platform skips), including the new volume-info binding.
  Evidence: /tmp/vpn-control-windows-native.aYyBpY/privacy-acl-result.txt,
  SHA256232299e6de4ab6ef5e104076a71c5b51dc66c9c823c5066b708962232a0f96b8.
  Unsupported ACL filesystems have deterministic policy coverage, not real FAT tests.
  Packaged-CLI harness8 and Windows UTF8 launcher4 tests also passed on review.
- Review continuation: changelog note5 is present and docs hygiene/diff checks pass.
  Full validation is deferred while two concrete review findings are corrected:
  private export creation must account for inherited macOS ACLs and Windows volumes
  without persistent ACL enforcement; POSIX mode0600 alone is not sufficient proof.
  Android GUI selection/selected-row updates still call a live-reapply wrapper,
  violating staged-selection semantics. Assigned location work must correct GUI
  and CLI together, not expose the existing runtime-restarting wrapper through ADB.
  DELETE/IMPORT additionally need actual-active identity and runtime-only rollback;
  mutable selected identity/persisted running flags are not adequate stop decisions.
- Implemented subscription add/update/delete with strict argument/ID handling,
  guarded atomic commits, retained retry results, async add/update, exact result IDs,
  scheduling and source-cache invalidation. GUI source cleanup now uses actual
  runtime observation: unknown/running state preserves selected runtime artifacts.
- Implemented routing set/import and apps list/set/add/remove/select-all/clear.
  Shared GUI normalization/search is retained, filtered bulk changes preserve other
  assignments, and malformed/unknown explicit packages fail before persistence.
  Owner lease/revision guards and public ADB binding cover the new mutations.
- Focused run94294 passed55 tests (Android28, desktop ADB/CLI23, shared4).
  Latest full prepush647 passed before this batch and is now historical; this batch
  needs its changelog note and a fresh complete pre-push validation receipt.
- Frozen647 public packaged CLI passed non-debuggable Android API29/API35 checks:
  settings write/no-op, source validation, SSH import/retry/stale guards, reads,
  routing/diagnostics file/stdout exports, no-overwrite, and routing PNG export.
  Evidence: /tmp/vpn-android-release-native.4FU9Am/report.json.
  APK SHA256: 5b32e609472fed5849dc037bf5e9e923e68cdbbae0a860a5a6208a16fac8098a.
  Empty location/subscription data prevented positive location-export and
  subscription/all-source verification. Frozen647 did not yet support apps list;
  this is implemented in current source, not verified by that older native run.
- Both task devices remained stopped with zero runtime starts; task emulators5582
  and5590 were stopped afterward, existing5580 untouched. No live VPN, consent,
  elevation or installer verification is claimed. No commits/pushes yet.
- Next: consolidated validation; review coherent commits; Android location commands
  and native verification of the new subscription/routing commands. Large transfers,
  update/install integration, remaining Android jobs/streams and final exact-SHA
  cross-platform CI remain required for the full goal.

Android source and complete export-command batch (2026-09-06):

- Android source set current-locations/subscriptionID/all now uses owner lease,
  strict IDs, epoch/revision guards and retry deduplication. Running selection stays
  intact; stopped out-of-scope selection invalidates legacy cache atomically without
  deleting runtime files. Cache invalidation remains permanent: valid committed
  components win, but partial restores with blank fields never revive stale files.
  Result/scheduling-failure metadata comes from the exact commit.
- Location, routing and diagnostics exports are wired end-to-end through Android
  read callbacks/shared GUI builders and the local CLI writer. Diagnostics export
  does not launch share UI. JSON destinations/report format never reach Android;
  envelope success follows writing and omits content. Raw stdout is exact UTF8/PNG
  with no appended success; errors use stderr. QR/default-no-overwrite tests added.
- Default export files are now private at creation: POSIX0600 and Windows protected
  current-token-owner ACL via CREATE_NEW. No post-write tightening or overwrite.
  Focused3670 passed; actual Windows tests verified owner-only noninherited DACL and
  preserved existing files. Evidence privacy-result.txt in the retained Windows temp
  directory, SHA2569c12c779705b69d1d4d3e9ce5122999e4373218eeca2bbedae629b0407edfcdc.
- Final focused76780 passed51 tests: source/cache3, sourceowner2, settingscontrol12,
  reader12, AndroidADB13, AndroidCLI9. Source/native device smoke remains unexecuted;
  prior Android debug durability tests are not public source/export release proof.
- All agents have frozen source. Root is updating version/docs and running the full
  consolidated tier. Latest passed full604 remains historical until this run passes.
  No commits/pushes. Next priority: remaining end-to-end Android commands and public
  native release verification, not additional speculative backend infrastructure.

Native Windows/Android proof and Android exports (2026-09-06):

- Windows native rename failed with ERROR87 despite correct packet layout. Root
  now uses the pinned directory handle's normalized volume-GUID path and a null
  RootDirectory, preserving ancestor pins and avoiding DOS drive remapping. Packet
  tests cover both pointer widths and Unicode; focused73892 passed. Actual Windows
  standard-user tests then passed2/2, including replacement and Unicode paths.
  Result: `/tmp/vpn-control-windows-native.aYyBpY/result.txt`, SHA256
  d06ce25d0b97fde6d551d743a333ea8c6a5c7535f1bd7d2633d82c129cc5fada.
  Windows11 ARM64 build26200.9168, MicrosoftJDK17.0.20.1; no elevation/installers.
  Temporary HTTP server stopped; test WindowsVM remains available.
- AndroidSshCredentialVersionsInstrumentedTest passed3/3 on both API29/5582 and
  API35/5590. Real directory fsync, atomic rename, private0600, DataStore disk-write
  failure, reopen/restart preservation and retry immutable-version skipping were
  exercised. Debug APK SHA256:
  67e9ae68c6b3e70811a594f7e393d9cf54abf73701c5cc0b0cd5477cef10793e.
  Test APK SHA256:
  f377ec300bb4a8cd5f9d29a6feada3fcf3b36e02e28cc2a20af4bd759d5ca7d4.
  Dedicated emulators stopped; existing5580 untouched. This is debug instrumentation,
  not non-debuggable public SSH command or native SSH-loading/traffic evidence.
- Root implemented Android location/routing exports through shared transfer formats
  and client-side output/QR conversion. Output/format never reach Android as paths;
  JSON success follows completed file writing and omits payload. Raw stdout is exact
  bytes with no envelope/suffix; write errors go to stderr. Focused shared/desktop/
  Android reader tests and APK builds passed26672. Two later default-no-overwrite/QR
  stdout tests await the next focused run. Initial59123 assertion compared independent
  timestamps; export helpers/tests now share the captured deterministic timestamp.
- Export review found inherited permissions could expose credential-bearing files.
  Windows agent owns a narrow private-at-creation writer helper and DesktopCli default
  writer wiring/tests. Root owns DesktopAndroidCli/export tests; no overlap.
- GUI agent is implementing guarded Android source set end-to-end, including minimal
  transactional cache invalidation needed to avoid deleting selection artifacts before
  a failed metadata commit. This work owns SettingsControl, ProfileStorage, source
  helper/tests, Owner callback and AndroidADB source binding. No VPN interruption.
- Scope remains frozen; next full check/changelog follows coherent source/export
  batch. Latest full604 is historical; no commits or pushes yet.

Android status completion and native storage verification (2026-09-06):

- SSH key status is now wired to the captured committed credential version and
  returns only presence. Update status reads the same immutable GUI update state;
  it never starts work or exposes raw errors/download URLs. Unknown or failed-check
  availability/compatibility remains explicit null instead of falsely up-to-date.
- The restart-warning regression reproduced (23940). GUI save now asks the owner
  to compare actual runtime with committed configuration: true remains pending,
  known false clears a real revert, unavailable/error conservatively retains the
  warning. It never overwrites the committed credential version.
- Focused final union 77265 passed 30 tests (settings actions9, reader11, update
  projection2, Windows backend8); two Windows-native tests compiled and correctly
  skipped on macOS. Native Android durability/loading still needs device proof.
- Actual Linux backend tests passed5/5 twice, default umask and child-only077:
  Ubuntu24.04.4 ARM64, OpenJDK17.0.20, ordinary uid1000. SecureDirectoryStream,
  symlink/writable ancestry rejection, retained cancellation, permissions and
  production untrusted-root rejection were exercised. Test-owned VM stopped.
  Store JAR SHA256: 9ce96a287cff0755f0551e06d3c53e1cddda9e1d6595e8f716eff5b8dceaec61.
- Actual Windows standard-user tests exposed C:\\ ownership by the exact Windows
  TrustedInstaller service SID, so the prior owner policy rejected legitimate
  ancestors. A regression reproduced before a narrow ancestor-only trust fix;
  final product/job/file policy and ACL write grants were not broadened. Native
  rerun is pending; fake tests are not its proof. WindowsVM remains test-owned,
  no elevation/installers/global writes/VPN actions authorized or performed.
- Previous full pre-push604 is historical. Root is adding the concise changelog
  note and rerunning consolidated checks after this frozen batch; no commits/pushes.

Checkpoint and review follow-up (2026-09-06):

- Consolidated pre-push **604 passed** at 2.1.1 / 2 Unreleased notes, covering the
  Android SSH integration/location reads and all current installer-backend sources.
  Windows-only native tests compile but skip on macOS; actual Windows execution is
  ongoing in the isolated standard-user VM. No commits or pushes.
- Review found a remaining SSH GUI warning bug: after importing a key, saving an
  unchanged SSH dialog compares against current committed settings and can erase
  restart-pending despite the older active runtime. GUI agent is adding the fastest
  regression and replacing that comparison with authoritative runtime-versus-
  committed-state observation (including conservative unknown handling). This new
  follow-up invalidates 604; it is not a reusable final receipt.

Android SSH owner integration and location reads (2026-09-06):

- Root wired immutable key staging inside the all-writer DataStore transaction;
  owner/revision checks happen before filesystem work. The selected version commits
  with configuration metadata. Payload and directory entries are synced before
  publication; failed metadata commits leave immutable unselected versions. Same
  key content is a no-op, and settings drafts cannot restore old credential versions.
- GUI import and protected ADB `ssh key import --input` now use the same owner job,
  lease, request deduplication and sanitized result path. Key bytes travel through
  stdin, never process arguments or retained operation results. GUI no longer
  writes a mutable key then optimistically increments metadata. Runtime preparation
  and subscription SSH lookups resolve the captured committed credential version.
- Focused Android SSH filesystem, real DataStore failure/guard, owner/retry,
  settings UI and reader tests, instrumentation compilation, and desktop ADB
  transport tests passed together (21468). Later edit only clarifies the conservative
  prepared-runtime comment: SSH native readiness/active-identity proof remains
  disabled pending integration evidence. Actual Android key import/native loading
  and read-only SSH status still need verification/implementation respectively.
- Android location reads are implemented: GUI and CLI share exact localized row
  names and benchmark/name sorting; indices follow visible order. List exposes no
  raw profiles, explicit show uses the same repairable configuration text as GUI.
  Four projection and ten reader tests plus Android compilation passed (67175).
- Protected installer backends passed final 15-test union (55420), including actual
  macOS temp-directory descriptor/ACL tests and seven Windows fake-native tests.
  New Windows-only native tests are being compiled before this consolidated check;
  actual standard-user VM execution is still outstanding. No installer integration.
- Root is consolidating changelog/full pre-push after this batch. No commits/pushes;
  all earlier receipts remain historical until the new unchanged-content run passes.

Immutable Android SSH prerequisite and native backend follow-up (2026-09-06):

- `AndroidSshCredentialVersions` and three temporary-filesystem tests were added;
  focused Android compilation/tests passed (7718). Staging archives the legacy key
  without replacing it, produces immutable numbered payloads, skips orphan versions
  after failed metadata commits, and never substitutes the legacy key for a missing
  version after migration. **Not production-wired yet.** Next root work must stage
  inside the serialized DataStore configuration transaction, persist the selected
  credential version atomically, migrate all runtime/subscription/validation lookups
  to that committed version, and route GUI/CLI imports through the same owner action.
  Directory-entry durability and failure-injection checks remain before wiring.
- Native common/macOS backend and Windows fake-native union passed (63735): five
  common-store and seven Windows tests. Darwin arm64 `openat` required the proper
  JNA vararg ABI; the initial native fixture exposed it. Additional permission/ACL
  checks are still in flight. This does not establish installer integration or
  privileged production-root behavior. Windows agent is now preparing actual
  isolated native tests with no elevation, global-directory writes or installer.
- GUI agent now owns extracting Android's visible localized location ordering for
  shared GUI/CLI list/show reads. Root owns SSH storage/import; keep these files
  disjoint. Full pre-push 549 remains the historical, invalidated checkpoint.

Native visibility follow-up and protected installer prerequisites (2026-09-06):

- Consolidated pre-push 549 passed at version 2.1.1 / 1 Unreleased note. New
  changes below invalidate it. No commits or pushes yet; scope remains frozen.
- Native macOS testing exposed two lifecycle bugs: workspace parsing rejected the
  internal pinned frontend launch arguments, and quitting an absent owner started
  one unnecessarily. Both were reproduced by focused regressions before narrow
  fixes; focused tests and the rebuilt app image passed (95863). The isolated VM
  then passed public text/JSON show/hide, unchanged owner identity/revision, a
  paused-frontend nonterminal timeout, recovery, and absent-owner quit/hide checks.
  Runtime remained stopped; task processes were cleaned up. This is not live-VPN
  or final exact-SHA package evidence.
- Protected installer receipt/cancel backends are being implemented independently.
  Windows fake-native security/lifetime tests passed; real Windows backend execution
  is still required. macOS Java lacks SecureDirectoryStream, so the POSIX backend
  correctly fails closed there; a native descriptor adapter is being developed.
  No production installer wiring, elevation or machine-wide directory writes have
  been performed. Existing privileged marker writes and full installer parity remain
  unresolved until the new channel and admission/handoff design are integrated.
- Root added a shared committed subscription-list/show and routing-show projection
  and wired Android reads to it. Lists omit source secrets; explicit show preserves
  the usable source URL, never cached raw profiles. Focused shared projection,
  Android snapshot/revision/encoded-transport, desktop inspection and Windows
  backend tests passed together (89817), including the Windows data-only cancel
  handle's WRITE_THROUGH regression. This is not native Windows execution.
- Keep one Gradle invocation at a time. Full checks follow coherent changes, while
  native verification and non-overlapping source work continue independently.

Acknowledged visibility, Android cancellation and routing results (2026-09-06):

- Consolidated pre-push 527 passed at 2.1.1 after the automatic 10-note roll.
  New changes below invalidate that receipt; no commits/pushes yet.
- Public text/JSON `gui show/hide` now uses a separate owner lane, strict owner/
  frontend binding, bounded launch and actual UI-thread acknowledgement. Hide never
  bootstraps and rejects no-tray hiding. Timeout/unknown replies are `final=false`;
  retries do not repeat uncertain window actions. Startup waits for window/owner
  binding. Final 73049 passed 42 desktop + 2 shared tests. Earlier macOS screenshots
  predate these commands; native show/hide evidence remains required. Windows global
  GUI elevation and explicit stale-frontend close/reopen after owner quit remain open.
- Android provider operation list and consent-wait cancellation are implemented.
  Approval/cancellation compete before preparation; no coroutine cancellation can
  interrupt native/persistence effects. Acknowledgement awaits token/lease cleanup.
  Duplicate cancellation, owner guards and bounded retention are tested. Full Android
  unit/instrumentation compilation + 10 ADB tests passed (43744); final 12 connection
  tests passed (44962). List excludes GUI/worker jobs, whose migration remains open.
  No real consent/VPN test has been approved or performed.
- Root fixed JSON-array direct-domain input being saved as literal brackets/quotes;
  JSON and GUI/plain text now share normalization. Guarded routing writes return their
  own committed normalized values, not later state. Imports return counts/public
  controls without private profile/package content, and warn about unsupported desktop
  app assignments. Strict result schemas and original retry metadata passed in 73049.
- Installer audit found privileged marker writes to replaceable user-workspace paths
  on all desktops. Captured script/private DMG do not solve this. Native/Android agents
  have only designed protected receipt/cancel backends (POSIX secure directory handles,
  Windows retained Win32 handles using already bundled JNA 5.13.0). No backend edits
  yet. Machine-wide admission, staged JVM guard, two-process waits, typed INSTALL and
  actual installer proof remain open. Do not claim installer parity complete.
- Source is frozen for root's concise changelog note/consolidated pre-push checkpoint.
  Backend/Windows implementation follows. Keep one Gradle invocation at a time and
  native testing isolated; host/default VPN and existing emulator 5580 remain untouched.

Public revision guards and disconnected native evidence (2026-09-06):

- Previous consolidated pre-push 489 passed at version 2.1.0 / 9 Unreleased
  notes. The new changes below invalidate that receipt. No commits or pushes yet.
- Public `--controller-id ID --if-revision N` now carries the same snapshot's
  owner epoch and revision through desktop and Android adapters. Bare revisions
  are rejected, and pinned desktop requests never start a replacement owner.
  Desktop capabilities list the supported guarded writes; runtime/job guards
  outside that list remain unsupported. Parser, authenticated public guard,
  JSON handling, Android forwarding and capabilities tests passed (64308);
  subsequent small rendering/capability-test edits await the consolidated run.
- Native Android API29/35 **non-debuggable release** verification passed (57190,
  8237; release build 53031). APK SHA256:
  `63cd69101fa4bd34829a9bf3e99a36f1c1ef1a6b45b55a6ea728c709bb16fd75`.
  Both exercise authorized shell transport, settings commit/retry/stale/no-op,
  unknown/null arguments, known-stopped OFF and noninteractive ON/RESTART denial.
  Separate ordinary app UIDs are denied even after an explicit DUMP grant.
  Invalid interaction token and encoded traversal are rejected. Final stats:
  stopped, zero successful starts. Task-owned emulators 5582/5590 were stopped;
  existing 5580 was untouched. Sources/probe retained under
  `/tmp/vpn-control-android-check.vw0SNR`. Actual consent grant and traffic remain
  unverified; no approval to start emulator VPN has been received.
- Android STATUS was implemented **after** that release artifact: synchronized
  actual runtime/prepared-config projection, opaque selected versus active IDs,
  pending restart, and explicit UNAVAILABLE/nulls when native knowledge is missing.
  Eleven focused status/reader tests and Android compilation passed (9152).
  Do not attribute earlier emulator evidence to this later STATUS change.
- Authenticated fixed frontend endpoint process proof now validates registration,
  actual PID/start identity, OS user and canonical executable without caller PID/path
  authority. Twenty-two identity/frontend/transport/lease/bootstrap/exit tests
  passed (10317). This is a prerequisite, **not** a completed installer fence.
- Real isolated macOS VM GUI smoke passed, including SSH and Language dialogs. Unsaved SSH
  host edits leave committed state unchanged. Language Save reaches CLI state at
  revision 1. Terminating only task frontend 6343 leaves owner 6377 alive; reopening
  creates frontend 6478 attached to the same owner epoch. Runtime stayed stopped;
  CLI quit stopped the owner; the remaining task frontend was stopped separately,
  and all recorded task processes are gone. Evidence and eight screenshots:
  `build/gui-smoke-lrIt5T/README.md`. This does not prove uninterrupted live VPN
  traffic or canonical visual approval.
- Installer prerequisite batch is source-frozen: Linux timeout does not relaunch
  without an installed receipt. macOS obtains required authorization before ready,
  captures immutable worker script bytes before the prompt, uses a clean fixed
  privileged PATH, and verifies a private DMG copy before readiness. A real temporary
  filesystem regression reproduced the failed-copy nested-backup defect (36450);
  rollback now restores the exact app target. Thirteen helper/update tests passed
  (93360). No real installer/elevation action was performed. Two-process installer
  coordination, machine-wide admission fence and typed install remain open.
- Root is applying the batch's 10th note (automatic 2.1.1 roll) and full pre-push
  checks after final content. GUI/Android agents completed read-only plans for
  public acknowledged show/hide and consent-wait operation cancellation; neither
  next implementation has begun. Do not treat those plans as completed parity.

Remote GUI and Android consent checkpoint (2026-09-06):

- Normal Main now boots/attaches to the separate headless owner through
  `DesktopGuiOwnerConnection` and uses a service-free frontend client. Preview-only
  service adaptation is isolated. Local editor/routing drafts, explicit settings,
  configuration and bounded LOGS reads preserve current UI behavior. Unknown retained
  state disables actions; visual unavailable states still need actual scene review.
- Owner leases/heartbeat, exactly-once reconnect, client-only detach and exact final
  response-flush exit gates are implemented. Root QUIT awaits durable shutdown before
  allowing exit; UPDATES_CANCEL deduplicates cancellation, awaits check/download cleanup
  then dismisses. Typed install is NOT functional yet: helpers must safely wait for both
  owner and GUI and fence competing starts across workspaces before executable replacement.
- Root guarded imports/runtime-link tests passed (78491). Combined facade/lease/bootstrap/
  exit/quit/cancel/runtime/import union passed (11112). Earlier failures were fixture errors:
  HWID alone does not advance product revision, endpoint owner must be UUID, and normalized
  settings API requires DecimalValue for custom hours. No validation was weakened.
- Android full ON/RESTART + protected consent/foreground interaction and ADB continuation
  passed final Android unit/main/instrumentation and 9 ADB tests (88984), including 8
  ON/RESTART and 2 interaction tests. No real-device consent/FGS/native traffic proof.
- Source freeze for consolidated checkpoint: root owns docs/version/full checks; GUI
  edits stopped; native agent designs multi-process installer handoff; Android agent
  inventories isolated API29/35 emulator capability read-only. Do not reuse receipt 417
  for this new content. Version remains 2.1.0 before the next 9th Unreleased bullet.

Independent frontend and runtime-control implementation (2026-09-06):

- Guarded source/subscription delete and coherent location projection integration
  passed 18 focused tests (89928). Full typed routine presentation passed 8 tests
  (40029); settings include committed autostart, and refresh/benchmark/update messages
  distinguish unsafe legacy text from an empty result.
- Root added `DesktopFrontendInstance`: independent frontend lock/endpoint, authenticated
  window-only activation/hide, workspace isolation, and idempotent cleanup that cannot
  remove a replacement frontend endpoint or stop the owner. Frontend/transport tests
  passed (58751). Native agent has since added owner frontend leases/bootstrap; that
  newer code awaits compile/test after the Main refactor is coherent.
- GUI agent is actively removing production service access from Main through a typed
  frontend client and local drafts/actions. Main is temporarily uncompilable while this
  larger coherent change is assembled. Do not mistake those transient compile errors
  for owner guard failures, or rerun desktop Gradle before its compile-ready signal.
- Root added guarded owner callbacks for ROUTING_SET/ROUTING_IMPORT/LOCATIONS_IMPORT
  and internal opaque-ID LOCATIONS_BENCHMARK dispatch. Import revalidates before effects
  and durable commit and uses runtime-only restoration. Four new owner regressions
  await Main compilation; 9483 stopped at the in-progress Main refactor. Native agent
  owns ControllerOwner frontend lifecycle additions; root constructor wiring is separate.
- Root added cached safe runtime-detail presentation (mode, local proxy port, preflight
  summary without path/raw errors or log IO) and validated public release-notes link.
  Outbound-warning availability remains explicitly false; no healthy status is invented.
  Three new runtime/link privacy tests await compilation. GUI agent consumes these fields.
- Android ON/RESTART, protected interaction registry/Activity, operation status/wait,
  native config validation before replacement and ADB interactive continuation are in
  progress. Android unit/main/instrumentation checks passed at milestone 32452; subsequent
  security/test refinements are still running. No device/runtime evidence yet. Android
  agent owns its provider/Activity/ADB files, not desktop GUI or owner lifecycle files.
- Run only one Gradle invocation at a time: simultaneous focused runs overwrite shared
  reports. Native, Android and root desktop tests are queued behind GUI compile readiness.
  Full pre-push receipt remains 417 / 2.1.0 / 8 notes and is invalid for these newer edits.
  No commit/push/release or complete-parity claim is justified yet.

Remote-GUI boundary and Android disconnect continuation (2026-09-06):

- Consolidated pre-push check 417 passed at version 2.1.0 / 8 Unreleased notes,
  covering the previous Windows/mutation batch below. Later edits invalidate that
  receipt. No commits or pushes yet; full owner-process/Android/platform plan remains
  open, not complete merely because the focused package harness is green.
- Routine location presentation now has a typed strict decoder and shared-row
  mapping with no raw profile content. Selected/active flags come from actual owner
  identities; malformed/extra private fields are rejected before replacing the last
  good remote presentation. Eight focused presentation/remote tests passed. GUI
  agent is integrating these rows while migrating source/subscription select/delete.
- Protected Android OFF now uses application-owned admission and correlated native
  cleanup, including stopped no-op, stale guards and retry retention. Five OFF tests,
  full Android unit/main/instrumentation compilation and focused ADB tests passed
  (33732). Expired receipts retain explicit unknown-outcome warnings with no retry
  redispatch. ON/RESTART and consent are still open; Android agent is designing that
  next slice. No device or host VPN actions occurred.
- Native agent's read-only architectural audit confirmed normal GUI still creates
  its service/owner. It is now implementing the remaining typed routine presentation
  boundary. Separate frontend registration, owner bootstrap and actual Main remote
  wiring remain required; do not claim GUI crash/detach survival yet.
- Current ownership: GUI agent owns Main/source/subscription services and guards;
  Android agent owns Android OFF plus the narrow ADB owner-binding change; native
  agent owns remaining frontend presentation decoding/projection. Root owns review,
  docs and consolidated metadata/checks. Avoid overlapping edits and batch full
  checks only after all source edits are final.

Windows native pass and mutation-batch continuation (2026-09-06):

- Ordinary-user Windows disconnected verification is now green: complete packaged
  harness, status/stats/log-follow with real console Ctrl-C exit 130, cursor entries,
  Unicode QR export/delete/import and unchanged disconnected owner identity. Context:
  Windows 11 ARM64 build 26200, x64 Temurin 17.0.20.1 under emulation, Medium-integrity
  visualagent, ACP1252/OEM437 unchanged. This is not MSI, signed-release, x64-hardware,
  VPN/UAC, older-Windows or final-SHA evidence. Reusable harness verification passed;
  no test-owned CLI/runtime remained, temporary bridges were stopped, and only the
  dedicated Windows VM started for this task was shut down.
- The new `--verify-only` manifest path passed natively without modifying either
  launcher or readonly flags. CLI SHA-256:
  `a8693c8a6a49e6fe06a26b50e2cf61c89dbb60634931be234f485c322ee9c6e2`;
  GUI-owner SHA-256:
  `5ef13847d786d6843f8d614b2c829e33d46fc77df4d4e89e9df55004efae6e2a`.
  Source archive `6b82b2c4da63b191d435e0d60a99eb5630e2b84dd7e4fdff22086d7e6c7fb414`,
  desktop JAR `f7cf89d475f7bb8705173569eaac68ded93db84389d531ea37ee3684056d1003`.
  MSI extraction checks now invoke read-only manifest verification before CLI smoke.
  Four fast manifest/PE tests pass. The reusable packaged CLI harness now checks
  bounded NDJSON status/stats/log-follow, cursor deduplication, Ctrl-C exit 130 with
  owner survival, and Unicode-path QR round trips. Windows console interruption is
  isolated to a helper attached only to each test-owned stream console. Eight fast
  harness tests plus native macOS and ordinary-user Windows runs passed.
- Android mode/source/language/DNS/subscription/refresh-policy/validation controller
  effects now execute sequential awaited batches within shared admission rather than
  detached per-effect jobs. Mode stop-to-save retains the same lease. Full Android
  unit/main/instrumentation compilation passed. Follow-up read-only caller audit
  found the six statistics/logging/test preference setters dormant, with no reachable
  Android GUI wiring; do not expand parity/revision scope to cover them. No additional
  reachable configuration bypass was found. Direct repository APIs remain exposed;
  callback-level exclusion regressions and optimistic persistence-failure UI handling
  remain open.
- Guarded location SELECT/DELETE now use rendered opaque IDs and owner/revision
  checks, return normalized IDs and deduplicate retries. Active-delete failure
  restores actual prior runtime without overwriting newer settings; durable rollback
  failure cannot claim successful deletion. Sixteen focused tests passed, covering
  stale/replaced/reordered targets, active versus pending deletion, concurrent settings,
  stop/persistence failure and retries.
- Previous consolidated check covered 2.1.0 / 7 Unreleased notes. Current source edits
  require a fresh final note/check. No commits/pushes; remaining full plan unchanged.

Windows Unicode fix and guarded location-save continuation (2026-09-06):

- The Windows Unicode failure was reproduced with file-backed escaped Python
  inputs: Python preserves Japanese characters, Java 17 and 21 replace them with
  question marks under ACP1252. Java charset flags do not fix native argv ingress.
  A copied native launcher with per-process UTF-8 activeCodePage passed the same
  Unicode capabilities probe without system-locale changes. Production script
  `scripts/windows_launcher_utf8.py` patches both generated CLI and GUI-owner
  manifests; the Windows AppImage Gradle task invokes it before installer creation.
  It preserves asInvoker/DPI/compatibility and all manifest languages, restores
  read-only flags, and rejects signed/truncated PE input. Three fast tests and
  exact production-script execution on a copied native app image passed. Windows before
  10 1903 remains unverified; do not silently narrow the full CLI parity objective.
- SYSTEM-account native serve tests hit a distinct identity-probe limitation:
  Java user.name is the machine account, not SYSTEM. Endpoint ACL checks were NOT
  weakened. Native agent is moving disconnected tests to the existing logged-in
  visualagent token, without account/password/global-policy changes. No VPN runs.
- Location ADD/UPDATE now have guarded typed owner commits. Internal updates use
  opaque IDs resolved under the same revision check and save monitor; public
  selectors/async behavior remain unchanged. GUI editor captures opening metadata,
  keeps conflicts local, retries the same request and no longer calls saveLocation
  directly. Results retain normalized opaque ID only. Frontend/typed/location CLI/
  operation tests passed, including reordered/replaced targets and persistence failure.
- Android routing autosave/save/import and SSH settings/key-import now use shared
  non-cancellable admission. BUSY uses the existing status path; drafts remain local.
  Full Android unit/main/instrumentation compilation passed. Controller-effect
  settings/source/subscription writes and credential-file/settings atomic rollback
  remain unfinished.
- Prior consolidated checks covered 2.1.0 / 6 Unreleased notes. Current edits need
  final metadata and fresh pre-push receipt. No commits/pushes; full plan remains open.

Frontend editor/admission and Windows-failure continuation (2026-09-06):

- Desktop tab navigation is frontend-local and no longer invokes owner openScreen.
  Location edit opens an explicit authenticated LOCATIONS_SHOW read by the rendered
  opaque configuration ID, not a freshly interpreted index/name. The owner resolves
  the ID under its commit monitor; missing/replaced identities conflict. Public
  selector syntax is unchanged. Tests cover numeric names, list shifts, deletion,
  stale epoch, ambiguous request shape and private-input exclusion from failures.
  Location save/delete/select still need full guarded typed migration.
- Subscription add/rename drafts are frontend-local, with coherent owner/revision
  and stable-ID explicit reads. Guarded owner ADD/UPDATE captures commit metadata
  and retains only normalized subscription ID in result data. Conflicts retain
  input and retries recover prior results. Existing async public CLI support is
  preserved. Frontend, subscription CLI, typed mutation and operation CLI tests passed.
- Android manual active/specific/all subscription refresh and location save/delete/
  select/import now use shared non-cancellable mutation admission through persistence
  and direct lifecycle/rollback calls. Full Android unit/main/instrumentation compile
  checks passed. Controller-effect settings/source/subscription edits, routing and
  SSH actions remain untracked; busy-rejection GUI feedback also remains incomplete.
- Windows x64 app image built under Windows ARM64 emulation. Existing packaged
  harness found a real Unicode workspace failure: capabilities with an ASCII
  state directory succeeds, the same invocation with a Japanese path fails
  INVALID_ARGUMENT before any owner starts. Native agent is isolating launcher/JVM
  conversion; do not claim Windows CLI parity or replace the failing Unicode test
  with ASCII-only evidence. Help/version passed; streams/QR not yet verified.
- Last consolidated pre-push receipt covered 2.1.0 / 5 Unreleased notes. Ongoing
  content needs a fresh final note/check. No commits or pushes; full plan remains open.

Selected/active rendering and shared Android admission continuation (2026-09-06):

- Shared location rows accept explicit immutable selected/active flags, without
  requiring raw configuration for visual matching. Desktop Main supplies actual
  owner-local selected and active IDs. Pending selection A no longer marks A in use
  while runtime B runs; Android/default callers retain the legacy fallback until
  their explicit observer integration. Shared UI and desktop mapping tests passed.
- Desktop source display now uses typed safe labels, optional subscription IDs and
  an explicit selected-outside-current flag. Routine presentation exports these
  values and the remote session validates their shape; Main uses the same typed
  derivation. Labels use custom names or parsed hostnames, never URL credentials,
  paths, query tokens or malformed raw input. Source/projection/session tests passed.
  Main still reads local service state: this is not completed remote GUI attachment.
- Android settings and tracked GUI/worker jobs now reserve one atomic identity-owned
  mutation lease. Duplicate settings waits reuse accepted work; client cancellation
  retains admission through owner cleanup; GUI Cancel cannot cancel settings.
  Job start/cancel occur outside the admission monitor to avoid ledger lock inversion.
  Full Android unit/main/instrumentation compile checks passed. Untracked GUI
  mutation entry points still require explicit migration, not a blanket launch wrapper.
- Native Windows build has reached desktop compilation under ARM64 x64 emulation;
  public launcher checks have not run yet. Prior exact limitations still apply.
- Last consolidated check covered 2.1.0 / 4 Unreleased notes. This batch needs its
  own final note and fresh pre-push check. No commits or pushes yet; full plan open.

Guarded-mode/key and Android-runtime-receipt continuation (2026-09-06):

- App-mode dialog/menu switches now use coherent owner reads and frontend-local
  guarded MODE drafts. Unsupported macOS VPN and stale saves retain local input;
  tests prove no runtime stop/start when changing pending mode, no-op revision
  stability and retry recovery.
- Desktop SSH key import now has a dedicated typed owner branch with epoch and
  revision guards, retained request identity, the shared mutation lane and exact
  commit metadata. The service checks revision before credential IO. Key contents
  are not retained in result data/history. Tests cover stale owner/revision with
  no key creation, duplicate/reused identity, unchanged keys, captured metadata,
  failed workspace persistence with credential rollback, and credential-version
  overflow. Frontend key import now captures owner/revision before the picker and
  retains a redacted transient action for Retry. Success or closing/reopening
  discards the content; no implicit settings-draft rebase. Prompt uses committed
  result metadata. Real-owner frontend tests passed; Retry visual coverage is open.
  Existing file-pair crash atomicity and credential permission hardening remain
  separate open work; guarded admission does not prove those properties.
- Android native start/stop completion now has application-owned command IDs and
  config-bound one-use claims. VpnManager no longer treats changed persisted
  status text as command completion. Prepared input is validated before replacing
  the old runtime. Claimed receipts survive waiter cancellation until completion
  or bounded expiration with an explicit unknown outcome. Six receipt tests and
  full Android unit/main/instrumentation compilation passed. These are
  adapter prerequisites, NOT implemented public ON/OFF/RESTART or consent support.
- Windows app-image build is running in the dedicated Windows 11 ARM64 VM with
  checksum-verified unpack-only Temurin x64/Python under emulation. Temporary
  public dependency fallbacks and exclusion of the MSI-only WiX download are
  infrastructure workarounds. No Windows product verification has passed yet;
  SYSTEM-user execution cannot prove ordinary-user permissions or UAC.
- Previous consolidated pre-push check passed with 2.1.0 and 3 Unreleased notes.
  The changes in this section invalidate that receipt and need a new consolidated
  version bullet/check after final content. No commits or pushes yet.

Presentation/native-verification continuation (2026-09-06):

- Authenticated internal presentation reads now return explicit whitelisted GUI
  summary values with owner/revision metadata. They never serialize MainUiState,
  private configuration inputs, credentials, or unsaved drafts. Legacy unstructured
  details/benchmark labels are omitted with explicit unavailable flags; editors
  still require explicit configuration reads. DesktopRemoteControlSession can
  opt into presentation polling and exposes retained presentation plus a separate
  failure flow. Reads serialize with runtime refresh, reject owner replacement and
  revision rollback, and do not revive a closed session. Focused presentation and
  remote-session tests passed. Main GUI is NOT yet attached to this remote model;
  complete rendering, actions and independent background-process lifecycle remain.
- Refresh-policy, validation-settings, language and SSH dialogs now use
  frontend-local guarded drafts and the shared retry identity helper, as DNS
  does. Existing shared normalization is preserved. Language selection saves
  immediately through the owner; SSH credential validation stays owner-side.
  Focused draft tests passed. Key import still lacks frontend epoch/revision and
  retry guards; importing a key makes an existing draft stale, requiring explicit
  reopen. Visual/error-state verification remains open.
- Native disconnected app-image checks passed on macOS and Linux ARM64: public
  launcher smoke, status/stats NDJSON watch, cursor logs follow, real Ctrl-C exit
  130 with owner surviving, and QR export/import through Unicode paths. These are
  dirty-source snapshots, NOT final exact-commit certification or VPN traffic,
  installers, Linux x86_64, or Windows evidence. Linux used Ubuntu 24.04.4 AArch64,
  OpenJDK 17.0.20, and a guest-only offline Maven fallback for public ZXing 3.5.4
  after guest network timeouts. Desktop JAR SHA-256:
  `a39837ffb21618208db0378970d3ab0144406955a988f40925bc011390d99323`.
  Only the dedicated Linux VM started for this task was stopped afterward.
  Windows dedicated-VM readiness is the next independent verification task.
- Android prepared connections now use bounded one-use descriptor handoffs tied
  to actual generated configuration. Unknown/legacy/expired/mismatched handoffs
  cannot claim a known active configuration; mutable SSH credentials remain an
  explicit unknown case. Prepared-handoff and Android checks passed for that batch.
  Protected provider SETTINGS_SET/APPLY are now wired through owner jobs, atomic
  epoch/revision guards and confirmed refresh scheduling. ADB binds only omitted
  settings owners from authenticated transfer creation. Rejection pending metadata
  is truthful. Unknown runtime before admission is unavailable; uncertainty at
  the atomic guard is a terminal not-committed runtime failure; after persistence
  it explicitly reports committed configuration. Final Android unit/main/androidTest
  compilation and host ADB tests exited zero (9 settings and 6 ADB client tests).
  Device/consent/runtime-action verification and remaining provider actions are
  still open, not implied by these settings tests.
- No commits or pushes yet. Latest focused session/presentation tests passed;
  a consolidated version bullet and fresh full pre-push run are required after
  the active agents finish their content edits. Previous full-check receipts do
  not cover these ongoing changes. Scope remains the entire existing parity plan.

Frontend-DNS/streaming/Android-completion continuation (2026-09-06):

- DNS is the first actual desktop frontend-local settings draft. Opening reads a
  coherent settings/owner/revision response through ControlSession; GUI edits do
  not touch service draft fields. Save uses guarded SETTINGS_APPLY, retains input
  and opening revision on conflict, and requires explicit reopen to rebase. Same
  opening/input retries have stable salted request identity and retrieve a lost
  successful response rather than applying again. Changed input/reopen gets a new
  identity. Tests cover two frontend drafts, response loss, stale owner/revision
  and invalid DNS. Other dialogs and the complete frontend model still need
  migration; inline failure/open-error visual coverage remains outstanding.
- Desktop watch/follow now uses pinned authenticated owner reads, NDJSON or human
  stderr progress, per-read timeouts, and no owner startup/rebind/cancellation.
  `DesktopLogCursorJournal` updates with every published log state, supplies a
  non-null cursor even for empty history/limit zero, and reports explicit gaps on
  buffer rollover. Live state carries owner sequence IDs so restored old history
  is not replayed as new entries. Desktop append IDs no longer collide at clock
  resolution in a full ring. Tests cover duplicate message/timestamps, rollover,
  restored history, batching/redaction, endpoint replacement, and actual public
  JVM watch clients whose exit leaves their never-connected owner alive. Native
  packaged Ctrl-C/streams and Android follow are not yet verified/implemented.
- Android's six protected reads now use one strict committed metadata/value
  snapshot. Refresh scheduling waits for WorkManager confirmation under a lane
  that reads latest committed state. The internal AndroidSettingsControl uses
  owner jobs, bounded deduplication/history, atomic settings commits, normalized
  patch results and exact commit metadata. No-op saves skip rescheduling; failures
  after durable commit explicitly report committed configuration and scheduling
  failure/unknown outcome rather than claiming rollback. Tests cover pending
  confirmation, cancelled client wait, retry, closed owner, concurrency and errors.
  Public Android settings writes remain DISABLED: authoritative pending-restart
  comparison needs an immutable prepared connection descriptor first. Runtime-
  affecting settings are mode, DNS, SSH and credential version; language, refresh
  and validation change configuration revision but not runtime configuration.

Remote-session/export/Android-transaction continuation (2026-09-06):

- `ControlSnapshotCodec` encodes an explicit runtime/operation DTO, with strict
  version/types/identity checks; it does not serialize Compose or platform services.
  Authenticated internal `ControlSnapshotRead` binds the endpoint owner epoch and
  uses a ten-second response bound. `DesktopRemoteControlSession` attaches without
  constructing an owner, polls snapshots, submits epoch-bound requests, and exposes
  connection failure separately from its last known snapshot. Close only cancels
  client observation. Tests cover two authenticated clients, settings/retry/history,
  independent detach, owner replacement without replay, polling, malformed frames
  and backwards revisions. This is NOT yet wired into the GUI, nor proof of GUI
  crash survival. Operation and runtime captures remain ordered bounded reads,
  not a full atomic all-domain snapshot transaction.
- JSON locations/routing/diagnostics exports now write client files and acknowledge
  success only after writing. Location/routing QR PNG is supported. Destinations
  and formats are not owner paths/arguments; content is removed from final stdout
  envelopes. Existing files are never overwritten. Diagnostics uses the genuine
  sanitized report and explicitly marks metadata as observed after report creation.
  Authenticated, CLI-process and QR regressions passed. Large chunked exports and
  Android exports remain incomplete.
- `AndroidConfigurationStore` now wraps all 34 legacy preference mutations in
  DataStore's serialized transaction. Shared configuration identity determines
  revision changes; telemetry/no-ops do not increment. Epoch/revision/preferences
  commit together, with stale guards checked before proposals. Six real temporary
  DataStore tests cover independent legacy facades, concurrent guarded writers,
  stale/no-op/telemetry behavior, rollback, epoch recreation and overflow. Internal
  guarded settings storage commit exists, but provider writes remain disabled until
  deduplication, completion, scheduling and credential transaction semantics exist.

Concrete next GUI migration boundary (read-only audit completed):

- Keep `DesktopControllerOwner` as sole service/runtime owner. Add an authenticated
  presentation projection: committed settings, source summaries, opaque location
  rows with benchmark/selection data, structured activity/status, bounded stats and
  updater summary. Existing generic `ControlSnapshot` lacks these fields. Do not
  serialize `MainUiState` or hydrate a second service from the workspace.
- Introduce `DesktopFrontendModel` using shared draft reducers. Move dialog/draft,
  navigation, clipboard/picker/file IO there; saves retain opening owner/revision.
  Replace `DesktopVpnControlApp`'s direct service dependency with model/actions.
  Routing setters named `*Draft` currently autosave: preserve that behavior through
  guarded owner requests instead of silently making them local-only.
- Only after bindings migrate, split controller lock from frontend registration,
  attach/start owner before GUI, route second launch to the existing frontend, and
  replace GUI exit's `shutdownForExit` with detach. Updater jobs belong to owner;
  frontend keeps operation IDs, not cancellation ownership. Installer handoff is
  separate. Current headless-to-GUI refusal and same-process lifecycle remain.
- Never put private keys, endpoint tokens, raw links/configuration, cached payloads,
  installer paths/helper commands or raw exceptions into routine projections.
  Explicit show/export may return usable configuration content.

ADB/runtime/result integration continuation (2026-09-06):

- Desktop settings JSON writes now retain the validated normalized public patch
  in `data`; arbitrary action text and private imports are not promoted to result
  data. An authenticated regression first reproduced the empty result. Commit
  metadata is captured with the settings result, so another legacy GUI/service
  write before ledger completion cannot relabel it with a later revision. Tests
  cover clamped values, partial patches, retained retry results and deterministic
  interleaving. This does not serialize every other mutation or implement their
  missing normalized results.
- Android service start/cleanup publishes application-owned runtime observations:
  actual handle identity, runtime ID, mode, start time and salted configuration
  identity. Raw runtime configuration is not retained. Provider stats distinguishes
  live observation from historical persisted counters/timestamps. Unknown startup
  or failed cleanup stays unknown; known observations update recreated GUI models.
  The GUI's legacy Boolean running field still retains persisted state while live
  state is unknown; complete tri-state presentation remains open. Provider status,
  revisions, active location identity and connection mutations remain unsupported.
  Android settings show now matches desktop NOT_FOUND for unknown typed keys.
- Host `--android [--serial SERIAL]` routes through ADB to the protected provider,
  including capabilities. Requests use descriptor stdin, never private shell
  arguments; only canonical opaque paths reach fixed `content` commands. Device
  selection, strict UTF-8/result correlation, deadlines, bounded IO and best-effort
  discard are covered by fake-ADB JVM subprocess tests. No real ADB device was
  exercised. Android currently returns JSON envelopes even without `--json`;
  human rendering, streaming, exports, writes, revision guards and interactive
  consent remain incomplete. Inspect device capabilities instead of assuming the
  desktop operation inventory applies.
- GUI/tray owner command rejections now produce frontend-local feedback rather
  than disappearing. The dialog shows allowlisted technical codes under existing
  localized STATUS/CLOSE labels, not arbitrary response text, and leaves running
  action/persisted status untouched. Tray failures show the window. Richer localized
  explanations and a visual scene/baseline for this dialog remain outstanding.

Observable-session/QR/provider continuation (2026-09-06):

- `DesktopControllerOwner` now implements shared `ControlSession`, publishing
  sanitized snapshots when service state or retained operation state changes.
  Typed submissions, operation lookup and cancellation reuse the existing owner
  session. Focused session/owner tests passed; commits
  made through the legacy service are observed, while unsaved DNS draft content
  does not enter snapshots. Further deterministic tests prove direct legacy
  RUNNING-to-terminal notifications, async completion/action cancellation and
  client cancellation leaving owner work alive. The full desktop test task also
  passed. This remains an in-process adapter, not remote GUI
  attachment or a fully atomic cross-domain snapshot/commit coordinator. Timed
  ledger expiry alone does not currently trigger a snapshot refresh.
- Desktop QR image imports decode in the client; only decoded content reaches
  the authenticated owner. Location/routing PNG exports use UTF-8, the shared
  1600-byte export policy, binary-clean stdout and new-file-only destinations.
  Image dimensions and input bytes are bounded; ambiguous/malformed images fail
  without exposing private paths. QR unit, authenticated roundtrip and JVM
  subprocess tests passed. Android now uses the same export-size policy and
  explicit ZXing UTF-8. Native packaged QR, desktop GUI gestures and JSON export
  envelopes are still outstanding.
- Android's application-owned `${applicationId}.control` provider is implemented
  with manifest DUMP permission, explicit app/shell UID authorization, strict
  opaque transfer URIs, bounded memory and proxy file descriptors. It currently
  routes only selected reads; it does not implement mutation admission, runtime
  identity, usable revision guards or consent. Unit and Android/instrumentation
  compile checks passed; instrumentation has NOT run on a device. Real external
  Binder rejection and non-debuggable API 29/35 ADB evidence remain outstanding.
  Runtime-read review reproduced a stale persisted `isVpnRunning` flag after an
  ungraceful process death: stats now returns unknown running/elapsed values until
  genuine live observation is available. Decoded request identity is preserved
  on timeout/read failure. Regression tests and Android checks passed. Host ADB
  transport and live service runtime observation are in progress in separate
  agent scopes. Do not infer complete Android CLI support from provider presence.

Parallel integration continuation (2026-09-06): the user authorized independent
subagents. Android ownership, packaged CLI checks and GUI benchmark identity work
were implemented in separate scopes and integrated with the desktop JSON writes.

- Desktop JSON mutations now cover location/source selection, subscription
  add/update/delete, location add/update/delete/import, routing set/import,
  SSH-key import and update dismissal. Typed arguments reuse the shared grammar;
  input paths are consumed in the client and only content reaches the owner.
  Supported long writes additionally accept async (subscription add/update,
  location delete/import). Existing actions still own validation, persistence,
  rollback and normalized state. Results retain operation IDs and sanitized
  completion metadata; normalized write-result data and public revision flags
  remain unfinished. Authenticated tests cover durable changes, request retry
  deduplication, async wait, imports, source eligibility and persistence failure.
  Selection failures now preserve NOT_FOUND/AMBIGUOUS_LOCATION codes and avoid
  copying untrusted selectors into persisted GUI status/log text.
- CLI output explicitly writes UTF-8 bytes, bypassing legacy Windows PrintStream
  encodings. Regression tests use a windows-1251 stream and launch actual JVM CLI
  processes with windows-1251 defaults while checking Unicode language output,
  Unicode input paths and JSON writes. Native Windows execution is still needed.
- Android now has a lazy application-owned dependency graph and command-job
  lifetime/admission. GUI factories and WorkManager reuse repository, storage,
  orchestrator, VPN manager and scheduler. Update state/service and prepared-file
  ownership survive ViewModel recreation. GUI drafts/navigation stay local;
  accepted jobs survive a destroyed frontend or cancelled worker wait. Unit and
  Android compile checks passed; a real factory recreation instrumentation test
  compiles but has not run on a device. This is NOT a complete authoritative
  ControlSession migration: some services still capture frontend controllers,
  untracked mutations are not all serialized, and typed provider/ADB/consent,
  revisions/ledger and device evidence remain open.
- GUI benchmarks capture opaque configuration IDs from the rendered list rather
  than numeric CLI selectors. Numeric names and list reordering cannot redirect
  the request; replaced/disappeared/ambiguous configurations conflict. Benchmark
  result persistence rechecks the captured configuration. Focused fake-runtime
  and service tests passed. These IDs are now internal GUI benchmark references,
  not public CLI selectors or permanent row IDs; full atomic proposal/commit
  coordination still remains open.
- `scripts/test_packaged_cli.py` now runs disconnected public-launcher smoke from
  DEB/RPM/Arch/MSI/macOS package validation; desktop workflow path filters include
  the harness. Native macOS jpackage app-image smoke passed, using a per-invocation
  Homebrew vendor-check override; no repository vendor policy changed. This proves
  native macOS launcher/headless/temp-workspace settings/read/operation behavior,
  NOT DMG/signing, Windows/Linux execution, GUI attachment, VPN traffic or Android.
  No test touched the host VPN, autostart or installer settings.

Configuration inspection continuation (2026-09-06): desktop JSON now covers
locations/subscriptions list and show, routing show, SSH-key status and update
status. The owner captures data plus commit metadata together; malformed arguments,
missing records and ambiguous location names retain explicit codes. List responses
omit raw profiles and subscription URLs; explicit show keeps usable configuration
as legacy inspection does. SSH status exposes only presence. Routing returns the
existing v7 transfer object; its generated export timestamp can differ between
reads, so regression checks compare the payload and import it back to rules.
Authenticated tests use real service state, verify visible indices and secrets
boundaries, compare legacy results and assert no state/operation changes. The
never-connected public JVM process regression includes the new no-argument reads.
Remaining: complete typed writes/export/streaming, Android adapter, owner/frontend
process separation, scoped Windows elevation and native packaged evidence.

Structured read continuation (2026-09-06): public desktop JSON now supports stats,
bounded logs, source show and settings languages. `ControlReadLogic` owns pure
state projections reusable by Android; production desktop captures data and
revision/restart metadata under the commit monitor. Legacy stats use the same
projection. Log `--limit` is transferred rather than dropped, zero yields no entries,
and messages use existing secret redaction. Unknown/wrong typed arguments fail;
watch/follow is still explicitly rejected. Shared tests cover timing, nulls,
redaction, bounds and source shape; authenticated real-service tests compare legacy
stats to typed data and confirm reads do not create ledger operations or mutations.
The public JVM CLI process test also exercises these four reads against its
never-connected temporary owner. This does not implement Android transport,
streaming, all remaining JSON commands or packaged native evidence.

GUI connection command continuation (2026-09-06): GUI/tray on/off, explicit restart
and per-location benchmark now use the same session admission and operation
history as CLI commands. On/off/restart also accept public JSON/async submission.
The shared start action preserves the GUI's missing-selection status and keeps
`on` idempotent when already connected. GUI benchmark callbacks translate storage
indices into the CLI's one-based visible positions, including duplicate names.
Focused authenticated real-service/fake-runtime tests pass for JSON restart/off,
pending selection and async on: a blocked runtime start remains queryable, a retry
retains one operation and one runtime start, changed request content conflicts,
competing writes return busy, and completion/reconnect intent are retained.
The public parser is exercised by `--json --async on`, not only direct DTO calls.
No host VPN or OS settings were touched. Connection cancellation, stable row
references across list reorder, GUI feedback for admission rejection and the
separate-process owner/frontend architecture remain open. These changes do not
prove native packaged availability or full parity.

GUI controller ownership continuation (2026-09-06): the normal GUI entry point
now constructs `DesktopControllerOwner` before Compose and binds its authenticated
server directly to the same session graph used by headless mode. CLI command
handling no longer depends on Compose installing a future handler; typed settings,
status, JSON operations and revision-aware requests reach the owner when launched
through the GUI path too. The owner holds action scope and auto-refresh scheduling;
Compose disposal does not own/cancel that scope. Startup restore shares the session
mutation lane, and listener startup failure aborts before runtime restoration.
GUI/tray Find Best and GUI subscription refresh now use session operation admission
and history. Production GUI async callbacks use the owner scope; visual-only
fixtures retain their local fallback scope. Explicit app-exit/update-install paths
still stop runtime and schedule application exit on Swing. Real-service transport
tests exercise the process-owner graph before any UI composition and verify reads
remain available while initialization rejects writes, then settings persist after
initialization. This is a process-local ownership migration, NOT separate-process
GUI attach/detach/crash survival: the headless-to-GUI refusal remains, GUI drafts
still live in the service, many GUI actions still call service methods directly,
and native GUI smoke/visual evidence is pending.

Structured status continuation (2026-09-06): `status --json` now reports actual
runtime-running state, selected/active opaque configuration identities, configured
and active modes, runtime ID/start time, and pending restart with the committed
revision. It never starts a missing owner. The lifecycle publishes one immutable
active-connection descriptor and assigns a fresh runtime UUID on successful start
or restored restart; no-op restore preserves it. Owner-local location hashes use
a private random salt and length-delimited source identity, do not retain input,
and are not persistent row IDs or accepted CLI selectors. Authenticated fake-runtime
tests cover pending selection without restart, idempotent on, explicit restart,
stop, and restored runtime identity. This is a bounded snapshot read, not the full
shared StateFlow coordinator or atomic state/effect transaction required by the plan.

Capability discovery continuation (2026-09-06): `capabilities [--json]` reports
static desktop JSON adapter support without contacting or starting an owner or
creating a workspace. The report covers every registry ID but marks unsupported
JSON handlers NOT_IMPLEMENTED; it does not mislabel working legacy commands as
unavailable. JSON/async command admission and operation cancellability now share
the same implementation support lists used by discovery. Platform support is
reported separately from explicitly unchecked runtime readiness. Unfinished
public revision guards and GUI attach/detach remain false. Typed owner queries
return the same static inventory with owner metadata. Registry/platform tests
and a real CLI-process no-workspace regression cover discovery. This is not
dynamic privilege/runtime readiness, native OS evidence or full capabilities
parity for all legacy/product operations.

Client timeout continuation (2026-09-06): supported JSON commands now accept
`--timeout-seconds` with the shared default 600 and zero for unlimited response
waiting. The local timeout is not serialized to the owner or included in request
deduplication. One monotonic deadline covers the complete response frame, including
partial reads; socket intervals are capped at the Java integer limit without
truncating longer requested waits. Local TIMEOUT/OUTCOME_UNKNOWN results have
final=false and preserve a supplied operation ID for operation inspection/wait.
An authenticated regression times out a one-second wait, verifies the owner job
is still running, then cancels it explicitly and receives exit 130. Deterministic
stream tests cover partial response deadlines, waits longer than one socket
interval, and unlimited waits. CLI tests verify timeout options stay client-side.
This is response waiting only: connection/authentication/owner startup retain
their own bounds. Non-JSON synchronous timeout options and eager cleanup of server
wait observers after client disconnect remain unfinished; owner work is unaffected.

Endpoint permission continuation (2026-09-06): descriptor reads now check current
user ownership on every platform and validate Windows-style ACLs as well as POSIX
permissions. The ACL policy requires owner read access and rejects grants to other
principals; it fails closed instead of emulating group membership/ACL ordering.
Publication verifies the resulting permissions before writing the authentication
token. Reads reject non-regular files and symlinks and consume at most 4097 bytes
to enforce the 4096-byte descriptor limit. Missing-file errors remain distinct so
normal first-command controller startup still works. Pure ACL tests and real
temporary-file/process tests pass on macOS; native Windows filesystem/provider
verification is still pending. This does not prove protection against every
hostile-directory replacement race or complete Windows privilege separation.

Owner: coding agent, started 2026-09-05 on synchronized `dev` at
`32de4ee72cc26a45e5bb8dca80c79a7a7cd76f14` (initially clean).

Goal: implement the approved complete GUI/CLI parity plan, including Linux,
Windows, macOS and Android ADB. No release is authorized. Do not interrupt the
user's runtime. This is intentionally a multi-bucket task; contract updates
describe required behavior, not a claim that all implementation is complete.

Windows autostart continuation: the scheduled-task launch command now preserves
the explicit resolved workspace through `--state-dir`. Windows argument quoting
doubles trailing backslashes so root directories remain one argument. A mocked
OS-command regression covers spaces, Unicode, shell metacharacters and trailing
separators; the full desktop test suite passed on the macOS development host.
No real login configuration was changed. Per-workspace autostart ownership and
replacement of the existing highest-privilege task remain unfinished; this is
not native Windows/reboot evidence.

Linux autostart continuation: generated XDG and managed i3 commands now retain
the explicit workspace. XDG quoting now applies both desktop-entry string and
Exec escaping, including literal percent field-code escaping; read-only launcher
inspection decodes those layers. The i3 recognizer accepts both legacy and
workspace-aware wrappers. Regression coverage checks Unicode, spaces, apostrophe,
dollar/percent/ampersand paths and executes only a disposable argument-echo script
through the generated shell command. The full desktop suite passes on macOS;
native XDG/i3 session and reboot behavior remain unverified.

Update-relaunch continuation: all three desktop helpers now pass the owner's
workspace on relaunch; the service gets that directory from its actual store.
Linux's watcher regression executes only a disposable argument-echo launcher
after a test-owned process has exited. macOS helper syntax is checked without
executing installation. Windows preserves the workspace as UTF-8 Base64 during
helper invocation, decodes it in the unelevated relauncher, and quotes native
arguments for elevation, MSI and relaunch. A regression first reproduced its
automatic `$PID` parameter collision; it now uses `ParentProcessId` and avoids
overwriting PowerShell's `$args`. A Windows-only PowerShell regression mocks
all process launches, including UAC, and checks generated relaunch/elevation
arguments. That native test does not execute on the macOS development host.
Mapped shared-core/UI, desktop, Android unit and Android compile checks passed
after the helper fix; no real installation, UAC, reconnect or native Windows
execution has been validated. Private helper staging/revalidation, installer
receipts, and the broader controller lifecycle remain unfinished.

Revision-boundary continuation: a mapper regression reproduced routing drafts
being written as committed rules during unrelated saves. Desktop persistence now
uses `routingRules`; explicit routing saves still build and commit normalized
rules through the existing service. `ControlConfigurationIdentity` provides a
shared comparison of committed settings, sources, location content and selection,
excluding runtime/measurement/refresh-status telemetry. Desktop commits serialize
the write/publication boundary and increment an internal revision only after a
successful changed-configuration save; failed writes and no-op saves do not
advance it. Tests cover mapper draft isolation, shared telemetry exclusion,
durable settings/no-op saves, and primary/recovery write failure. Shared model,
core, desktop and Android compile checks passed. This is not yet a public
revision contract: credential/autostart transactions, atomic revision-checked
proposals and unified snapshots remain unfinished. Operation result metadata is
now connected to the desktop owner, as described below.
SSH revision continuation: the existing credential-version field is included in
configuration identity, so successful changed-key imports advance the workspace
revision and failed metadata commits do not. A regression reproduced repeated
identical-key imports incrementing that version. The credential transaction now
compares normalized prior/new content privately and tells the settings action
whether it changed; identical imports preserve credential version/revision and
existing restart-dialog state, while still rewriting the key with private file
permissions. Settings proposals, state transforms and key-import orchestration
share the desktop commit monitor. Authenticated SSH CLI tests check initial
import, identical reimport and failed replacement rollback with unchanged
revision. Public revision-checked requests stay disabled.

Settings revision-guard continuation: `applyControlSettings` accepts an internal
expected revision and checks it under the same monitor as proposal construction,
durable commit and autostart effects. Stale requests, including stale no-op saves,
conflict before any OS inspection/write. Settings reads use that monitor too.
A two-thread real-service regression starts competing saves at revision 0 and
requires exactly one success, one conflict, revision 1 and the winning value;
it checks unchanged persisted bytes after a stale retry and a current-revision
no-op. Mocked autostart coverage requires zero OS calls for a stale request.
This is not public optimistic concurrency yet: the session must first validate
the controller epoch, typed settings dispatch must carry the guard, and GUI
draft saves must retain their opening revision. The typed settings adapter is now
wired as described next; public flags and GUI draft integration remain open.

Typed settings continuation: authenticated `ControlSubmit` now accepts synchronous
`settings.set` and `settings.apply`. Shared argument decoding requires exact keys
and transfers JSON content for apply, not filesystem paths. The headless session
validates the controller epoch, enters the operation ledger/mutation lane, and
passes the revision to the real settings commit boundary. Fingerprints include
operation and expected revision as well as normalized patch content. A matching
retry returns the retained versioned envelope before checking the now-stale
revision again; changing a request's revision conflicts. Synchronous typed
settings results use the shared result envelope. Authenticated real-service tests cover durable set/apply,
same-request retries, wrong epochs, stale writes, changed retry revisions,
retained completion metadata and atomic invalid batches. No OS/runtime effects
are invoked. Public `--if-revision`, other typed commands and GUI draft
ownership remain unfinished; this is not full public protocol parity.

Typed-response continuation: all handled typed submissions now return the shared
versioned envelope, including validation/unsupported/owner-conflict/busy rejections
before operation admission. Rejections include the request ID and the responding
owner's current metadata without inventing an operation ID or retaining private
input. Synchronous typed long actions now return retained result envelopes too,
including when a caller switches from async acceptance to a synchronous retry.
Legacy commands and transport-level failures still use their existing payloads;
public JSON settings support is described below. Session and authenticated transport
regressions cover malformed private input, busy rejection, owner mismatch,
metadata and cancelled completion.

Public JSON settings continuation: `settings show`, `settings set` and
`settings apply` accept `--json` before or after the command. Show reads settings
and revision/pending metadata under one service monitor; it does not create a
mutation operation. Set/apply use the typed owner path. Argument/input errors in
the CLI adapter return one sanitized INVALID_ARGUMENT envelope without starting
an owner. Transport failures are converted to sanitized unavailable/unknown or
incompatible responses; local responses explicitly have no controller identity
and warn OWNER_METADATA_UNAVAILABLE (the schema's revision field is zero, not an
authoritative snapshot). A mismatched response request ID is rejected.
The real headless JVM-process regression passes on macOS for JSON read, set,
apply from a space-containing path and unknown-key failure. Unit tests cover
private invalid input, missing files, unsupported options and transport failures.
Startup/workspace-parser errors now use the same sanitized JSON error formatter.
Public revision flags, normalized write-result data and
native packaged evidence remain open. No host runtime or OS settings were changed.

Public operation JSON continuation: JSON is also wired for Find Best, location
benchmark, subscription refresh, update check/download, and operation list/status/
wait/cancel. The supported long commands accept JSON with or without async mode.
Inspection puts the sanitized operation summary in `data` (`data.operations` for
list); the envelope describes the inspection request, and the nested summary
describes the observed operation. Wait preserves the operation's failure/cancel
exit code. Missing operation history never starts a replacement owner, including
on the JSON path. Authenticated transport tests cover async JSON admission, list,
status, missing IDs, cancellation and wait exit 130. Real process tests cover
JSON async download rejection without network and JSON startup rejection for
invalid options or a file used as a state directory, without modifying that file
or creating a workspace. Other commands, watch streams and native packages still
need work.

Autostart action continuation: GUI now calls the same validated settings action
as CLI rather than invoking the OS manager independently. Successful verified
enabled-state changes advance the internal revision once; repeated requests and
failed OS writes without changes do not. OS errors crossing the CLI boundary are
sanitized. Platform capability selection is injectable for deterministic owner
tests without changing global system properties. A real-service regression uses
mocked Windows task commands to exercise GUI enable, CLI no-op, failed GUI/CLI
disable and successful CLI disable with identical state/revision outcomes.
Shared-core and desktop tests passed; no real login settings changed. Native
verification, partial-OS-write recovery and global-entry/workspace ownership
still require work; boolean revision tracking does not yet account for command
repair/migration when the entry remains enabled.

Owner-operation continuation: `DesktopHeadlessSession` now executes Find Best,
benchmark, refresh, update-check and download in owner-scoped jobs tracked by
`ControlOperationLedger`. Cancelling the waiting coroutine does not cancel owner
effects; reads stay responsive and conflicting long mutations return busy.
Completed history retains sanitized codes, not input or arbitrary response text.
Public `operations list`, `operations status <id>` and `operations wait <id>`
now query that headless ledger through the existing authenticated CLI transport.
They never start a replacement owner when history is unavailable. Status/list
expose only identifiers, phase, nullable measured progress and sanitized result
codes; terminal summaries include the revision and pending-restart state captured
at completion. Wait propagates the terminal
outcome's exit code, and cancelling its observer does not cancel owner work.
An authenticated CLI regression checks running and retained benchmark operations;
unit coverage checks failed wait outcomes and observer cancellation. The legacy
GUI-owned executor explicitly returns UNAVAILABLE for these commands until the
shared owner migration is wired. These are transitional payloads, not the full
versioned result envelope. `operations cancel <id>` now requests cancellation of
owner update-check/download jobs without taking the mutation admission lock.
Other jobs remain non-cancellable until their rollback paths are audited.
The runner safely registers lazy jobs and retains CANCELLING until cleanup has
finished; a cancellation request is not a terminal-success claim. Authenticated
CLI coverage checks cancel during an active mutation and wait exit 130; unit
coverage delays cleanup and rejects cancellation of non-cancellable benchmarks.
Shared model/core and desktop tests passed. Update HTTP IO now uses the JDK HTTP
client inside interruptible coroutine blocks. A stalled-server regression first
reproduced delayed cancellation; header, manifest-body and package-body stalls
now cancel promptly on the development host, with partial-file cleanup before
completion and unchanged running state. Requests/transfers have a five-minute
total deadline (formerly a five-minute socket read timeout); an internal deadline
is an update failure, not user cancellation. The packaged JVM explicitly includes
`java.net.http`. Shared-core/UI, desktop and Android unit/compile checks passed;
native packaged cancellation and other long-action cancellation paths remain
unverified. Full protocol coverage, revision-checked requests and complete progress remain
unfinished.
The owner runner now accepts an explicit request ID, async admission flag and
expected controller identity internally. Matching retries reuse the ledger entry;
changed fingerprints or owner identity conflict before effects, and completed
retries return the retained sanitized outcome. Async admission returns ACCEPTED
with request/operation/controller IDs and final=false while nonterminal, rather
than waiting for effects. Desktop tests verify one effect across retries and
busy/conflict rejection. Public `--async` is now wired for Find Best, location
benchmark, subscription refresh and update check/download. The client generates
a request ID and transfers the shared typed request within the authenticated
legacy framing; it binds the request to the endpoint's controller ID. A headless
owner now creates one UUID for both endpoint and operation ledger. Matching
retries reuse the operation; mismatched expected owners conflict. CLI transport
tests cover async acceptance, request reuse, owner mismatch, cancel and wait.
Requests with revision/interactive requirements fail explicitly until wired.
Async acceptance and completed async retries now use the shared versioned result
envelope. The production owner supplies revision/pending-restart metadata under
its commit monitor; completed results retain that pair even after later edits.
A session regression covers acceptance, completion and retained-result metadata.
The real `MainKt` subprocess regression also passes on the macOS host: after a
settings commit, async download without a checked manifest fails locally with
revision 1; `operations wait` reports that terminal revision, and another settings
commit does not alter the retained status. No network, installer or runtime is
started by that operation. This is JVM-entrypoint evidence, not packaged evidence.
The ledger deliberately rejects transport/wait codes as owner terminal results.
A runner regression checks that an action incorrectly returning UNAVAILABLE or
TIMEOUT is retained as RUNTIME_FAILED, not a waiter timeout or false cancellation.
This remains a staged transport migration: legacy synchronous responses and
operation query summaries are not full versioned envelopes. Public `--json` is
currently supported for settings and the operation commands described above.
Tests cover disconnected-waiter behavior and an owner cancelled before dispatch.
Legacy synchronous requests still generate IDs on the server; async typed
requests generate them in the client. Cancellability is
limited to updates. Public watch, GUI session ownership, scheduled-refresh
ledger integration still require implementation. Transient idle-lifetime now
accounts for owned commands/operations, running connections and eligible
scheduled refresh; a full 30-second quiet interval is required before exit.
Pure-clock and headless-session regressions cover that accounting. GUI
registration and the final admission/shutdown race still need native ownership
integration; this is not evidence of complete GUI attach/detach support.

GUI bridge continuation: CLI dispatch no longer goes through Swing (window
activation still does). Handler readiness and response waits are bounded;
response timeout does not cancel the dispatched future. Interrupted or failed
dispatch reports unavailable/unknown outcome without private exception text.
GUI coroutine completion also resolves pending callers if disposal cancels a
job before it starts. Bridge regressions verify timeout, late completion and
sanitized errors. GUI service ownership is still not separated from Compose,
and these timeout responses still lack queryable client request/operation IDs.

Workspace continuation: public startup now extracts validated `--state-dir`
before service/CLI initialization, canonicalizes existing ancestors without
creating a workspace, and shares that root across store, lock, endpoint,
runtime/validation defaults and headless logs. Spawned headless and elevated GUI
launches carry the resolved directory. Tests cover relative Unicode paths,
duplicates, unsupported Android combinations, internal owner arguments and
spawned argument/log propagation. Native public-process isolation, frontend
registration, autostart and update-relaunch argument preservation still need
completion; custom state paths do not authorize host TUN/installer/autostart tests.

Public-process evidence: `DesktopCliProcessTest` launches the real `MainKt` JVM
entry point with the main runtime classpath and no DISPLAY/WAYLAND. On the current
macOS host, two test-owned `serve` processes in separate Unicode/space paths
responded to CLI queries and kept a changed setting isolated. Help, invalid input
and no-owner status created no workspace. Only never-connected test processes
were stopped afterward. This regression is part of desktop tests; it does not
prove packaged Windows console/macOS launcher behavior or native Linux/Windows
execution until those platforms run it, and it does not test traffic or GUI
attach/detach.

Read-only startup correction: desktop initialization and settings reconciliation
now use `DesktopAutostartManager.inspectEnabled`, which only reads existing
Linux/i3/systemd or Windows task/Run state. Tests verify inspection preserves
legacy files/registry entries and never issues migration commands. The older
migrating `isEnabled` entry point remains for explicit legacy migration tests;
normal service construction no longer invokes it.

Windows launcher continuation: Compose's app-image task now adds the JDK
`win-console=true` launcher `vpn-control-cli.exe`, leaving the primary launcher
windowless. Empty console invocation defaults to help. Headless child launch
selects the sibling windowless executable; argument tests cover Windows paths.
The MSI extraction check now requires the console launcher and checks real help
stdout/exit code. Installer collection excludes app-image executables. Windows
packaging/PowerShell execution has not been performed on this macOS host;
console behavior, scoped UAC helper and installation remain unverified.

Decisions already made:

- Android uses protected ADB content streams, not root, run-as, or a TCP daemon.
- One desktop background owner; GUI attach/detach leaves its connection alive.
- Current reachable routing controls only; do not resurrect dormant rule sets,
  bypass-app lists, statistics-visibility writes, or HWID writes.
- Manual selection and committed runtime settings apply on explicit restart or
  next on. Find Best retains its explicit connect/verify/rollback behavior.
- macOS stays proxy-only, Android package assignments stay Android-only,
  autostart stays Linux/Windows. Unsupported actions must fail honestly.

Delivery checklist (unchecked means unfinished, including native evidence):

Benchmark continuation: `locations benchmark` now traverses the authenticated
desktop CLI adapter into the same benchmark service used by GUI. The service
returns checked persistence results, rejects busy/missing targets, releases busy
after thrown probe failures or cancellation, and no longer publishes raw probe
exceptions as status text. Synthetic service and transport regressions cover
visible index/name targeting, success/failure, persisted results and unchanged
selection. Native direct-probe behavior, full result envelopes, progress and
operation cancellation remain unfinished; fake probes are not native evidence.

Subscription refresh continuation: the desktop CLI now dispatches
`subscriptions refresh <id|active|all>` through the GUI refresh service, returning
per-source ID/success/location-count data and nonzero partial/all-failed results.
Fetch cancellation propagates, refresh busy flags clear on cancellation/failure,
and checked workspace commits prevent false success on persistence failure.
Tests cover authenticated partial refresh with synthetic fetchers, sanitized CLI
output, failed persistence and cancellation without cache publication. Refresh
now distinguishes removed active identity from removed pending selection before
stopping runtime. Refresh now captures active runtime plus workspace/reconnect
intent before stopping. Failed stop/save attempts restore that capture, returning
`ROLLBACK_FAILED` if runtime or restored-workspace persistence fails. The effect
and commit phase is non-cancellable; fetch remains cancellable. Fake-runtime
tests verify restoration does not apply pending selection/mode. Crash-atomic
recovery, complete typed protocol
envelopes and native refresh continuity remain unfinished.

Location delete/import and subscription delete now share a non-cancellable
stop/commit/restore helper and the same active-runtime/workspace checkpoint as
refresh. Synthetic delete/import regressions exercise persistence and rollback
failures; a transaction regression cancels during stop and proves save/rollback
still finish. Subscription-delete native failure injection and crash recovery
remain unverified.

Update continuation: desktop update service now exposes a typed manifest-only
`check` result and separate `downloadChecked` action. The existing GUI combined
action composes them. A loopback HTTP fixture verifies no package fetch during
check, manifest-required download, checksum rejection, dismissal invalidation,
and unchanged running state. CLI check/download/status/dismiss are now wired;
grammar/protocol tests and authenticated status/no-update tests supplement the
HTTP service fixture. A per-update mutex rejects overlapping actions/dismissal
without blocking status reads. Full CLI check/download through the authenticated
transport, operation cancellation, Android shared
decision extraction, localized new outcomes, owner/GUI installer coordination,
and native installer evidence remain unfinished. No installer was launched.

Update preflight continuation: the installer boundary now rechecks regular-file
identity (rejecting symlinks), exact size and SHA-256 under the update action
mutex before authorization. Downloads reject bytes beyond the declared size.
Checks invalidate prior prepared packages; cancellation clears in-progress
presentation phases. Fixture tests cover tampered packages, oversized responses
and stale-ready invalidation without launching an installer. This preflight is
not a substitute for privileged-helper private staging and revalidation; native
Windows/macOS TOCTOU resistance and installer receipts are still unfinished.

- [ ] A: authoritative CLI contracts, operation inventory, regression tests.
- [ ] B: shared DTOs, codecs, validation, typed durable results, operation
  ownership/deduplication, config revisions, active-versus-selected state.
- [ ] C: authenticated desktop controller, separate GUI registration/client,
  headless scheduler, lifecycle, launch/state-directory plumbing.
- [ ] D: complete command grammar and action adapters, real desktop location
  editing, terminal file/QR transfers, localization and pending-state UI.
- [ ] E: application-scoped Android session, protected provider/streams,
  consent/foreground interaction activity and host ADB transport.
- [ ] F: Windows console launcher and scoped privileged runtime helper;
  native Linux/macOS launchers, package checks and autostart/update coordination.
- [ ] G: common/native parity tests, disposable traffic tests, targeted visual
  evidence, public docs, final version note/prepush checks, commit/push dev,
  exact-SHA success of all five required workflows.

Planned dirty buckets: agent docs/contracts and guardrails; shared model/core;
desktop runtime/lifecycle/UI; Android coordinator/provider/UI; shared UI/catalogs;
packaging and CI; public CLI documentation. No generated runtime/build artifacts.

Implemented so far (uncommitted):

- CLI session stats, bounded connection-log reads and diagnostics export now
  use the same state/report builder as the GUI. Unavailable session timing is
  null, and no traffic measurements are fabricated. Structured status arguments
  are decoded before shared redaction, with bounded nesting; more desktop report
  status/name fields are sanitized and unnamed subscriptions no longer expose
  their source host as a display-name fallback. The authenticated CLI test covers
  counters, redacted structured secrets, client-side report export and unchanged
  owner state. Watch/follow streams and full versioned result envelopes remain
  pending. After an environment transition the Gradle handle was gone, but no
  Gradle task process remained and the diagnostics CLI test report passed.
- Desktop bulk location import/export is wired through the authenticated CLI
  using the existing JSON transfer format and checked persistence. File IO stays
  on the client. Import distinguishes removed pending selection from removed
  active identity and preserves existing references for equivalent round trips.
  The new round-trip regression exposed an existing shared parser defect:
  explicit empty SNI became the server name after export/import. Explicit empty
  SNI now stays empty; omitted SNI retains the legacy default. Shared regression,
  desktop socket round-trip and pending-selection import tests cover this path.
  Android compilation was also checked after the shared parser change.
- Desktop CLI language listing and SSH key status/import now call the generated
  language model and GUI credential action. Credentials are permission-restricted
  before writing, flushed before replacement, and restored if the workspace
  metadata commit fails. Atomic-move fallback is limited to unsupported atomic
  moves. The authenticated CLI regression uses synthetic key-shaped input and
  verifies status, no key content in output/workspace, credential-version updates
  and restoration of the old key after failed persistence. This does not prove
  native SSH authentication or crash-atomic multi-file transactions.
- Desktop lifecycle commit callbacks now propagate persistence results through
  connection actions. A failed preparation commit prevents runtime start. A
  failed post-start commit restores the prior captured runtime (or stops a newly
  started runtime) and returns failure; rollback failure has its own code.
  Runtime-only publication is separate from persistence so failed stop saves do
  not leave the UI claiming that the stopped runtime is still running. `off`
  retries durable off intent even when already disconnected. Lifecycle tests
  inject pre/post-start and stop-save failures plus restoration of a prior
  active location distinct from pending selection. Native failures, complete
  operation receipts and remaining focused-service Unit callbacks need review.
- Desktop current routing show/set/import/export now use shared normalization
  and v7 transfer documents. Terminal exports write on the client and refuse to
  overwrite an existing destination; raw stdout output is supported. Desktop
  app-package actions return unsupported before controller startup. Imported
  Android package assignments remain round-trippable with an explicit warning
  that they do not function on desktop. The socket end-to-end regression covers
  GUI autosave, CLI normalization, invalid values, export/import and disk reload.
  QR transfer and full structured warning/envelope output remain pending.
- Desktop subscription list/show/add/update are wired through the authenticated
  CLI path and existing shared GUI subscription save/rename plans. CLI saves
  preserve open GUI drafts, reuse duplicate-source identity, and await durable
  commits. Default lists omit source URLs; explicit show returns configuration.
  `DesktopSubscriptionCliEndToEndTest` covers file input, GUI rename followed by
  terminal name reset, invalid updates, duplicate identity and disk reload.
  Shared grammar now permits an explicit empty subscription name, matching the
  GUI reset action, without permitting empty input/source paths. Subscription
  refresh operation results and QR input remain pending.
- Desktop subscription/location delete now return checked results through the
  CLI and reject missing/read-only targets. A shared runtime-input snapshot is
  captured on successful desktop start and cleared after successful stop.
  Deletion distinguishes that active identity from a pending selection. Fast
  deletion tests cover active versus pending, read-only records and failed
  persistence; the existing socket end-to-end tests now verify durable deletion.
  Runtime start uses committed routing rules instead of open routing drafts.
  Full active/pending GUI and JSON projection, Android adoption, and rollback when
  persistence fails after stopping an actively deleted runtime remain pending.
- CLI status now distinguishes actual active mode/location from pending selected
  configuration. Idempotent `on` reports that state without restarting. Explicit
  `restart` shares the GUI SSH restart action, requires a live connection and
  applies committed configuration. `DesktopPendingConnectionCliTest` exercises
  the authenticated terminal path with an injected fake runtime: stage/revert
  selection, no restart on `on`, explicit restart, auto-saved routing versus
  unsaved DNS dialog input, off and reconnect intent. No host runtime is used.
- Removed the Linux-only headless startup gate: Linux, Windows, macOS/Darwin
  can enter the owner path. Launch construction preserves Unicode/space paths,
  prefers the packaged launcher, and retains classpath/main class for Java dev
  launches. These are unit-tested paths, not native package certification.
  Headless owners now run scheduled refresh without Swing through
  `DesktopHeadlessSession`, sharing mutation admission with CLI writes while
  allowing reads during refresh. Its synthetic coroutine test covers changed
  refresh settings, busy writes, responsive reads and shutdown cancellation.
  Full GUI attach/detach, alternate workspace plumbing, console packaging and
  native traffic evidence are still pending. Transient owner completion is now
  notified after response framing/socket cleanup, not when the command handler
  returns. A loopback regression closes the server immediately on notification
  and verifies that a large Unicode response arrives intact. Concurrent commands
  are counted so a read cannot terminate an owner executing another command.
- Desktop settings `show`, `set`, and atomic `apply` now cross the authenticated
  CLI bridge into shared settings validation and durable workspace commits.
  `DesktopSettingsCliEndToEndTest` covers Unicode input paths, normalized DNS,
  atomic rejection, typed values and disk reload. GUI mode changes invoke that
  same settings action and no longer stop a connection; the service regression
  now requires the running flag to survive. General pending-restart UI and
  active runtime identity tracking are still unfinished. Terminal scalar parsing
  rejects extra JSON object members rather than silently ignoring them.
- Added `CLI-001` through `CLI-008`; updated product, pending-setting and desktop
  lifecycle contracts; made the contract guard require the CLI domain.
- Added `agent_docs/cli.md`: complete target command inventory, settings schema,
  action semantics, platform adapter/security/lifecycle design and test handoff.
- Added `ControlOperationId` (56 canonical actions), control DTOs/stable result
  codes, a shared session interface, operation registry, and pure CLI parser.
  The parser covers all inventory actions, globals, aliases, mutually exclusive
  inputs, native-GUI argument distinction, raw stdout/JSON conflict and safe
  errors. This parser is NOT yet the packaged entry point.
- Added a manual JSON request/result codec with UTF-8 size/nesting bounds,
  strict request fields/types, duplicate-key rejection (including escaped key
  aliases), explicit protocol mismatch, and sanitized parse failures. Framed,
  authenticated shared-DTO/provider transports remain pending. The existing
  desktop activation bridge now authenticates and frames its legacy payloads
  (see below); it is not yet the complete ControlSession transport.
- Added the pure operation ledger: deduplication by supplied request fingerprint,
  conflicting mutation admission, responsive lookup/cancellation state, progress,
  truthful terminal results, and 256-completed/30-minute retention. It requires
  a serialized platform session and a monotonic clock; no platform binds it yet.
- Added atomic shared settings proposals and inspection: flat supported keys,
  typed values including fractional refresh, shared DNS/SSH/validation
  normalization, whole-proposal validation, OS capabilities, separate autostart
  transaction, and no runtime mutation. Neither GUI nor CLI dispatch binds it yet.
- Extracted shared location selector resolution and wired existing desktop CLI
  selection to it. Fixed repeated selection of the same exact desktop record to
  avoid an unnecessary persistence write in both GUI and CLI paths.
- Added `ControlCommitCoordinator`: revision/epoch guards, no-op detection,
  telemetry-independent configuration revisions, busy mutation admission and
  publish-after-persist ordering. Cancellation during the durable section does
  not leave published memory behind disk. Platform sessions still need to bind
  it with an explicit committed-configuration identity projection.
- Desktop store writes now return `Result<Unit>` with sanitized
  `DesktopPersistenceException` failures. Recovery remains successful storage.
  Workspace replacement flushes the temporary file and no longer truncates the
  old primary as an IOException fallback. Initial/default migration writes fail
  closed. Runtime config write/delete failures are observable. The old facade
  facade now publishes only after successful storage. Location selection propagates
  failures to GUI and CLI; remaining Unit-returning action adapters still need
  typed completion and runtime rollback migration.
- Replaced desktop sample Add and append-name Edit with a real local-draft
  configuration dialog and `saveLocation` facade action. Shared validation handles
  supported links/JSON, duplicates, read-only sources, selected-reference remap,
  stale target content and durable failures. Added desktop facade regressions.
  Canonical duplicate comparison now treats direct links and editor JSON equally.
  Desktop add/edit visual scene inventory is enabled; capture, review, native
  baselines, dialog import affordances and complete revision guards remain pending.
- Existing desktop activation and five-command CLI now use a 256-bit per-owner
  credential, owner-private atomically published endpoint descriptor, bounded
  length-prefixed UTF-8/JSON-string frames, authentication before handlers, and
  a bounded daemon worker pool. Invalid clients cannot kill the listener; status
  bypasses mutation admission and the service busy guard. Old/malformed endpoint
  descriptors return protocol incompatibility rather than triggering a second
  controller. Owner close does not delete a newer owner's descriptor. Native
  Windows ACL evidence, full JSON DTO payloads, streamed large-document transfers
  and operation-aware reconnect remain pending.
- Wired desktop CLI `source show/set`, `locations list/show/add/update/select`
  through authenticated transport to the real facade. File/stdin input is read
  by the client, and save errors are sanitized. Source mutations now return checked
  persistence results. The argument-to-socket-to-service-to-reload regression
  exercises Unicode paths and interleaved GUI-action/CLI edits without a runtime.
  Basic help/version are side-effect-free and unknown leading flags cannot fall
  into GUI startup. Full global options, QR/large transfers, remaining commands,
  process-level owner/frontend separation and native packaging are not complete.

Validation already run:

- Startup MCP succeeded, switched clean `main` to synchronized `dev`.
- New no-op-selection regression failed on the original implementation, then
  passed after the fix; full desktop tests also passed.
- `./gradlew :shared:model:desktopTest :shared:core:desktopTest :desktopApp:test
  :app:compileDebugKotlin` passed with the shared settings/ledger/parser/codec
  additions (existing Kotlin/AGP and Android SDK XML compatibility warnings).
- `./scripts/check_docs_hygiene.sh` passed, including 79 contract IDs.
- Latest `workflow_status` confirmed only intended task paths. It reports the
  expected unfinished changelog/version-note and final prepush-receipt steps.

Immediate next work:

1. Continue B: bind authoritative committed-versus-active state and the new
   revision/persistence coordinator, plus runtime rollback. Desktop store now
   exposes failures and the facade publishes after storage succeeds. Location
   selection and editor actions propagate the result; other Unit-returning
   adapters still need migration. GUI local drafts must remain separate from
   the new session.
2. Wire shared operations into genuine platform sessions and GUI callbacks,
   then desktop authenticated transport/lifecycle. Do not advertise the new
   registry inventory as implemented commands until handlers are real.
3. Android ADB/provider/session, Windows helper/console packaging, native
   platform E2E, UI/localization/visual evidence and the public CLI guide remain.
4. Final content review, `version_bump`, prepush receipt, managed commit/push and
   all five exact-SHA required workflows remain. No release actions.

No task commits or pushes yet. Full parity is not implemented. The only existing
public CLI behavior changed so far is desktop location selection; the new
control foundation is deliberately not presented as a completed adapter.

## Template

When needed, replace the current-work line with:

```text
Owner:
Date:
Branch:
Goal:

Changed buckets:
- Documentation:
- Android runtime/config/UI:
- Desktop runtime/tray/lifecycle:
- Shared core/model/storage:
- Shared UI/localization:
- Packaging/CI:

Validation already run:
-

Known unfinished work:
-

Files that are intentionally dirty:
-

Files that look accidental and need classification:
-
```

## Rules

- Do not use this file as a changelog for ordinary small patches.
- Do not list generated artifacts as intentional dirty files.
- Remove stale notes once the work is committed, stashed, or abandoned.
- If a file looks accidental, classify it before deleting it.
