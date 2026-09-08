# Work In Progress

## Objective And Boundaries

Finish the complete GUI/CLI parity handoff on Android, Linux, Windows and macOS,
including native execution of applicable test launchers, current packaged behavior,
visual review, checkpoint pushes to `origin/dev` and all five required exact-SHA CI
workflows. This objective is active and incomplete. No release, main merge, tag,
publisher or native-runtime upgrade is authorized.

Product authority is [contracts.md](contracts.md), especially CLI-001..008,
STATE-001..005, DESKTOP-001..008 and TEST-001; commands are specified in [cli.md](cli.md).
For each distinct product, fixture or workflow failure, retain a causal quick
RED/GREEN regression in routine checks and rerun the native scenario. Compilation,
source-text assertions and skipped native tests do not replace causal/native evidence.

VPN, installation and elevation are limited to positively identified agent-owned
disposable VMs/emulators. Preserve the host VPN, personal workspaces, unrelated VMs,
AVDs5580/5582 and excluded `agent_docs/.Rhistory`. A timeout never authorizes a
runtime/installer restart, kill or mutation replay. Unknown installer jobs retain
inputs and correlation records until authoritative reconciliation.

## Repository And Current Validation

- Checkpoint22 is pushed as `0fc15314f9c8c7c0e05df248bb603dbf6a93ab8c`;
  all five required exact-SHA workflows succeeded, with all15 managed prepush
  commands passing. Checkpoint23 continues Windows packaged broker admission and
  native installer fixtures. Root owns component integration, shared launch/project
  wiring, fixture command construction, documentation and delivery. Windows owns
  ignored coupled-launch/fence drafts; android_terra owns
  `android_fixture_transport.py` and its test. mac_fixture_terra exclusively operates
  the fresh Tart Aqua-denial installation. Host Gradle remains root-scheduled.
- API35 benchmark-only acceptance completed on nondebuggable2.2.19: finite secondary
  timing1268.948834ms; synthetic candidate removed, original source/entries/settings/
  key presence and56000-domain digest verified. Earlier lost selection remains
  documented; final known baseline is unselected/OFF. Receipt:
  `checkpoint22/android-api35-219/benchmark-only-receipt.json`.
- Current-source Android pair2.2.19/2.3.0 is frozen under
  `checkpoint23/android-installer-pair/`, source0fc and fingerprint
  `e8aaf446190679f4a4bc548d08f0f4a3c36d086f6754b1f6490bd38897096c6e`.
  API29 independently redisplayed a hidden OS confirmation after owner loss using
  the same receipt5503e7c9…/session2010849851, then cancelled with installed=false.
  Proxy, reverse mapping and temporary namespace trust were removed; UID2000/OFF
  and base version verified. Setup-only disposable CA trust follows the original
  fixture authorization; public app control remains non-root/nondebuggable.
- API29 setup exposed adbd restart clearing reverse mappings while preserving the
  proxy. Manual route repair preceded native success; a separate causal regression
  now reproduces that missing route before the reusable transport-helper fix.
  macOS fixture incorrectly supplied Android-only `--interactive`; the app rejected
  it before installer admission. The guarded desktop argument builder now omits it;
  causal RED and27/27 fixture GREEN are recorded under checkpoint23. Native retry
  must use that builder; changing product authorization semantics is unnecessary.

- Current checkpoint21 is pushed as `be1e94f0a5c4616381acbd8685bdedc034d034e4`;
  all five required exact-SHA workflows succeeded. Managed receipt:
  `.runtime/parity-evidence/checkpoint21/ci-result.json`. Earlier checkpoint20/21
  entries below describe historical iterations, not current delivery status.
- Checkpoint22 intentionally spans Windows helper runtime binding and Android
  fixture preflight regressions. Native evidence remains separate from component
  checks. The API35 source inspection cleared an uncaptured selected configuration;
  source and saved entries were restored, but the original selection cannot be
  identified after observer salt renewal. Preserve OFF and all saved data, record
  the changed baseline, and require a preflight before further source inspection.

| Task | Agent | Owned files/subsystem | Dependencies/environment | Next handoff |
| --- | --- | --- | --- | --- |
| Windows binding | root | windows_native_helpers.py, its tests, preparation/packaging graph wiring | Existing compiled native authority; host checks serialized | Runtime-bound package verification and review |
| Android fixture | android_terra | android_fixture_preflight.py and its tests | API35/5590 read-only until concrete sequence accepted | Causal regression and preserved baseline |
| Windows native | windows | JNI native fixture and scratch admission component | Owned ARM64 Windows guest; x64 emulation labeled | Native counts/skips and admission review |
| macOS fixture | mac_fixture_terra | Frozen guest build/evidence | Owned Tart guest, immutable be1e source; preserve relay/unknown jobs | Same-source base/target packages |

- Windows runtime binding regression first failed because an unbound broker could
  be staged. The producer now records and checks the generated authority source;
  staging/inspection require the exact runtime resource hash and size. All19 helper
  tests pass, including changed bytes, duplicate runtime resources and malformed
  binding metadata. Evidence: `checkpoint22/windows-authority-{red,green}.log`.
- Android fixture source-inspection preflight rejects selected, running, unknown or
  incomplete state and returns the exact observed controller/revision guard. Its
  causal RED and3/3 GREEN receipts are under `checkpoint22/android-api35-219/`;
  `test_android_fixture_preflight.py` is included in routine release hygiene.
- Windows JNI publication native selection completed on Windows11 ARM64 with x64
  Temurin17 emulation:7 selected,6 executed,1 explicit Windows symlink skip,0 failures.
  Same-path, hardlink alias, Unicode and concurrent publication cases executed.
  This is emulation/component evidence, not native x86_64 package certification.
  DLL SHA256 `740efd3af4a9abc7c2d8573160040f2359313f7474188f4db0c611014971265f`;
  receipts under `checkpoint21/windows/android-publication-native/`.
- macOS same-source fixture sourceHead is be1e, fingerprint
  `1fa3e700d1617cf0a3a314588c5838fc7f54540af620bd479f29866dbf1366af`.
  Base2.1.19/target2.2.0 are test-only overrides; guest build uses the frozen runtime
  and preserves canonical2.1.6. Durable archive/manifest:
  `checkpoint22/macos-fixture-source/`. No installation evidence is claimed yet.

- Checkpoint20 is now pushed as `e2fa2230922683fd24651dc2dacdfffe5c231fec`.
  Exact-SHA Windows workflow34239971003 failed two native mutable-broker fixture
  cases; its other914 selected cases include57 explicit skips. Reproduction
  identifies noncanonical temporary-path aliases in synthetic bindings, not a
  reason to relax product path validation. Fast Checks, Android, Linux and macOS required workflows all succeeded for
  that exact SHA. Windows still requires a corrected push; the verification loop is incomplete.
- Checkpoint21 intentionally spans Android runtime routing memory/lifetimes,
  Windows CI fixture repair and this evidence record. Root owns Android integration,
  shared routing builder and managed delivery. android_terra completed observer and
  prepared snapshot work; mac_fixture_terra completed the asset store/builder and is
  reviewing integration. Windows owns the two completed mutable-broker fixture files.
  Host Gradle remains serialized by root. Managed checkpoint21 prepush passed all15
  commands; final documentation evidence is being revalidated before commit/push.
- The 48MiB causal runtime configuration failure is locally fixed: direct domains
  are streamed to a private content-addressed local source rule set, with a small
  main config. Actual new builder probe passed all56000 domains, complete asset SHA,
  import/status/readback/retry/no-op; main config2300 chars. Full focused union65/65
  passed plus instrumentation compile, then66/66 after empty-normalized-domain
  RED/GREEN regression. Native current-APK/libbox proof remains required.
  Lease integration acquires before runtime replacement, retains actual A through
  B/recovery, keeps uncertain native inputs, and releases confirmed stopped inputs.
  Restore/capture callers now close their references. Review found CUSTOM reserved-tag
  collision behavior; causal RED/GREEN now preserves foreign user rule sets while
  verifying generated private assets. Final focused union67/67 passes without skips.
  Android source is frozen for compatibly signed nondebuggable2.2.15 native fixture;
  fingerprint `cb9b5f7da4a518c09039f41c79f3ad082d0c5f87773ce1ec70d04954472f4aba`,
  manifest `checkpoint21/android-source-freeze.json`. Canonical product remains2.1.6.
  APK build succeeded; frozen APK SHA256
  `2bcd7873d27d96af3b24792bbf2c1eed3de90a83745dfb8f64bee8c64abce52f`,
  matching signer and nondebuggable package verified in `android-fixture-artifact.json`.
  API29 install-r succeeded and preserved56008-domain digest. Find Best operation
  `58918f0b-d0dc-4283-9a41-3347c8fe7b6a` terminally failed RUNTIME_FAILED,
  committed=false/RUNTIME_NOT_CHANGED; package and UID logcat did not expose a cause.
  Candidate cleanup completed, fixture is OFF/0locations/routing unchanged.
  This does not close the native memory/runtime gate. A message-free bounded
  failure-trace callback now has causal RED/GREEN coverage (12 Find Best and2 trace
  tests pass); the larger81 selection had only the subsequently corrected coroutine
  wrapper identity assertion failure. Non-message traces cover planning, swallowed
  probe/verify exceptions and exhausted no-winner searches. Diagnostic fixture2.2.16
  built successfully from fingerprint
  `0e9e5f46d128245af4e19b172630c700eb8c700f211e36ad7eecdfa5f086da8d`;
  APK SHA256 `b7efb918152aa7f76883a4485fd503da6cd1ade597240b1cdd5f2bcd0b0473e4`,
  code17120/nondebuggable/matching signer verified. mac_fixture_terra owns the
  controlled diagnostic native retry returned terminal RUNTIME_FAILED for operation
  `af0b3ce7-cbf4-4b87-b929-51569f2dc4f4`, no traffic, then restored the fixture baseline.
  Status logs are a separate journal and never contained the new private trace.
  Public diagnostics export then returned OUTCOME_UNKNOWN/zero bytes; source review
  found eager full-domain joining in the report. Causal2/2 RED proves both private
  domain disclosure and lazy-list materialization; count-only summary fix passed in the integrated83/83 Android selection.
  Report fixture2.2.17/code17140 is built, signer/nondebuggable verified; SHA256
  `9d109e25144ed7b401ee86cefccaf1509346b4a40ad8ce31192e7b835117bfce`, source
  `31fdc843c8d015b501520fe287a459448c2e8f2f135b204160d82bc29e8a21ec`.
  Install-r and retained-report extraction succeeded: the 25580-byte report
  identifies API29 `AccessDeniedException` at `Files.createLink` in private rule-set
  publication, before candidate planning or traffic. Baseline remains OFF with no
  locations and the unchanged56008-domain digest. The host causal regression
  `stagingDoesNotRequireHardLinkPermission` now fails at exactly that primitive
  when hard-link permission is denied (1 selected/1 failed, archived as
  `android-publication-red.{log,xml}`). Exclusive native rename is implemented
  without overwrite/copy fallback. A second causal host regression found macOS
  reports same-path rename success without moving; file-identity rejection fixes
  that result while retaining exclusive native rename for distinct files.
  Focused publication/store16/16 and integrated Android90/90 passed, zero skips,
  plus instrumentation compilation. Evidence is `android-publication-green.*`,
  `android-publication-same-path-red.*`, and `android-publication-integrated.*`.
  A test-only follow-up split hardlink aliases into their own mandatory case;
  final publication/store17/17 passed. Windows symlink coverage remains explicitly
  skipped. Linux native execution could not reach the authorized gateway on port228
  (connection timeout); Windows guest has no identified C compiler. These are
  verification limits, not native passes. Fixture2.2.18 built and its signer and
  nondebuggable status were verified; APK SHA256
  `82d732fb1cf56018945244ca57511e479b0dc064c054ba0721ac7eda179877e4`.
  API29 authenticated relay HTTPS returned200. The sole Find Best request returned
  OUTCOME_UNKNOWN/OWNER_METADATA_UNAVAILABLE, operation
  `bc047eeb-af09-4bcc-aa1e-d70eea38ef95`; subsequent operation inspection was
  NOT_FOUND after owner replacement. System/events logs establish a foreground-service
  deadline ANR: service PID21951 did not call startForeground in time, died, and
  provider PID24093 replaced it. Fresh status reports STOPPED/OFF; candidate cleanup
  restored the original routing digest. This requires a causal lifecycle regression
  and fix, then a new native run; the uncertain mutation was not replayed.
  `AndroidVpnServiceForegroundDeadlineTest` now reproduces the application-controlled
  scheduling failure:3 selected,2 failed before the fix (START dispatch precedes
  promotion and failed promotion does not prevent dispatch). Evidence is
  `android-fgs-deadline-red.{log,xml}`. The synchronous state-free notification
  admission fix now passes the full473-test Android suite with zero skips, plus
  instrumentation compilation (`android-fgs-deadline-green.*`). Retained runtime
  transitions remain separate. Independent startup review found no blocker.
  Fixture2.2.19 built with verified matching signer/nondebuggable status; APK SHA256
  `d112ad97210e951f95ee62f2d83121d68ca4a3b067414cda4b8eed210d763b84`. Its source fingerprint is
  `d8a87c9ea8a37d380470a0281c32c0c200a38a2673de606927444a1d4f830c1d`;
  API29 native acceptance passed: Find Best operation
  `04d3c63a-fa5a-4227-92a3-e145a86f7bb8` returned final OK/committed revision2,
  foreground notification preceded work, and the process survived without deadline
  or crash. Runtime was authoritatively RUNNING VPN with active=selected identity.
  Native benchmark measured TCP0.7ms, HTTP200/test=ok; authenticated relay normal TLS
  also returned200. Android byte counters remain unavailable. Public OFF and exact
  candidate deletion returned final OK; terminal STOPPED/0locations and the original
 56008-domain digest were restored. Receipt:
  `checkpoint21/android-native-acceptance-219/compact-native-receipt.json`, SHA256
  `d9dcaafcb9e3957b451f0470fee7390de25ad9f73b55eaeceb59713ecbb7d46d`.
  This closes this API29 generated-routing/FGS rerun, not the remaining API35,
  cancellation, connected recovery, installer, visual, or desktop package matrix.
  The earlier full Android unit suite passed469/469, zero skips, in `android-full-unit.*`.
  Subsequent cleanup review found that prune could delete malformed children with
  hash-shaped names. A new causal RED test precedes ownership verification before
  deletion; publication/store18/18 passed, zero skips, archived in
  `android-prune-malformed-{red,green}.*`.
  Artifact production inputs use fingerprint `cb49cc5e5f6c8a02d2ec7fcd6f5344cb4a87605b51e7759e687a20d47492643d`.
  Evidence: `checkpoint21/android-native-diagnostic-216/` and
  `android-diagnostics-domains-red.{log,xml}`. Release hygiene passed.
  Original failure and cleaned baseline: `checkpoint21/android-native-rerun/`.
  Evidence: `checkpoint21/android-runtime-assets-green.{log,json}`,
  `android-memory-full-green.xml`, `android-empty-domain-{red,green}.log`.
- Windows fixture repair now has final native6 selected/4 executed/2 explicit child
  opt-in skips/0 failures, with real short TEMP plus long-root boundary RED/GREEN.
  Archive `checkpoint21/windows/mutable-fixture-alias-final-evidence.zip`, SHA256
  `a7fcd2f4475cf27ad456094d94e280e6f35ee12c11183e2956622ddb20d82b0e`.
  Follow-up review found the exact233-character caller-root deletion boundary;
  its causal RED and corrected full6wrapper GREEN are archived in
  `checkpoint21/windows/mutable-fixture-caller-root-final-evidence.zip`, SHA256
  `844b3f1060331eb093fd078ad0cbc1ac7ddef840a8c0fa31fea184430573f2f2`.
  Final C# fixture SHA256 `ac813cb0e9fec468b80d7df009d17e51e24e7245854eddc13e2399068fbffc68`.
  The new fixed-helper broker admission is intentionally a subsequent checkpoint:
  causal five-argument-vs-PowerShell RED evidence is preserved, but implementation
  remains incomplete and factory disabled. No broker production completion is claimed.
  Its draft/test delta stays explicitly deferred; this checkpoint does not remove
  any existing broker regression or reduce required native acceptance.
- The host rebooted on2026-09-08. Host `/tmp/vpn-*` evidence and scratch helpers
  were lost; references below are historical records, not currently available
  archives. Repository source, Gradle outputs and the managed receipt survived.
  New evidence is retained in ignored `.runtime/parity-evidence/checkpoint20/`.
  Startup synchronization after reboot passed without changing the dirty `dev` tree.
- Checkpoint20's pre-reboot managed prepush passed all15
  commands:1657 JVM tests selected,1580 executed,77 explicit skips, zero failures.
  After the native owner-identity fix, the complete managed tier passed all15
  commands again:1658 selected,1581 executed,77 explicit skips, zero failures.
  The version is2.1.6 with four Unreleased bullets. Subsequent documentation or code
  edits require a fresh prepush receipt before the checkpoint push. Current results
  are retained in `.runtime/parity-evidence/checkpoint20/prepush-final.json`.
- The recovered Windows ARM64 guest completed the current full desktop JVM suite
  under x64 emulation:207 classes,915 selected,858 executed,57 assumption skips,
  **72 failures**. Native result and per-class accounting are retained under
  `.runtime/parity-evidence/checkpoint20/windows/new-batch-native/`; Java exited1,
  no Java/VPN/msiexec remained, and Installer InProgress was false. Most failures
  depend on endpoint verification using JVM `user.name`, which differs from the
  actual SYSTEM token identity. A C# fixture dependency omission and installer
  permission cases are being diagnosed separately. This is failed component-suite
  evidence, not packaged x86_64 acceptance; no failure has been waived.
- The endpoint identity defect has a portable causal regression: overriding JVM
  `user.name` reproduced `UserPrincipalNotFoundException` at credential publication.
  Verification now uses the native Windows token SID or POSIX effective UID,
  retaining private ACL/mode checks. Host endpoint/spool/activation/correlation
  selection passed25/25 without skips. Evidence is `endpoint-owner-red.{log,xml}`
  and `endpoint-owner-green-xml/` under the current evidence directory. The Windows
  compiler fixture now captures all required broker modules; its host selection
  passed9 with2 explicit native skips. Corrected native SYSTEM checks passed the
  compiler case1/1 and endpoint permissions4/4 with an intentionally nonexistent
  JVM account name; a foreign-owner endpoint was rejected. Evidence:
  `windows/system-narrow-results.json`. The ordinary-owner full suite completed:
  207 classes,916 selected,859 executed,57 explicit skips. Its only failure was
  the new test helper opening a conflicting inspection handle on a live spool.
  The assertion now resolves the native token account for a metadata-only NIO
  owner comparison. The corrected ordinary selection passed7 with1 POSIX-only
  skip; SYSTEM permissions passed4/4 with the invalid JVM name. Exactly two test
  classes changed; all product class/resource bytes match the complete native run.
  This is full-suite plus focused corrected coverage, not a single zero-failure
  full-suite rerun. See `windows/ordinary-full-native/`, `ordinary-quick-native/`,
  `system-quick-owner-result.json` and `test-owner-assertion-overlay-receipt.json`.
  The spool sharing regression remains in routine `DesktopControlTransferSpoolTest`;
  its failure/repair needs native Windows sharing semantics. The full-run preflight
  correctly refuses SYSTEM as an ordinary-owner context; reusable launcher/preflight
  source and fast fixture checks are queued for the next slice.
- Owned API29 AVD5584 and the macOS guest were restored without wiping their data.
  The authenticated Android relay passed normal TLS validation end to end; its
  processes use persistent tmux sessions. API29 GUI Find Best and exact fixture
  cleanup remain in progress. Protected AVDs and unknown installation receipts
  remain untouched. Current CLI adapter execution uses restored JVM build outputs,
  not a packaged launcher.
- API29 GUI Find Best initially reached a known `RUNTIME_FAILED`. Retained UI evidence proves
  that consent was displayed, but does not establish acceptance or the failed
  runtime phase. A separately identified diagnostic operation
  `219831a1-dca0-4ea0-a028-5124f8c16934` reproduced a14,352,392-byte allocation
  failure under the48MiB heap limit before progress. A causal memory regression
  and allocation-path diagnosis are the next Android slice; no speculative fix
  has been applied. Evidence is `android/findbest-rerun/` under the current directory.
  Exact candidate cleanup reached OFF with zero locations/subscriptions. Full
  routing readback completed with56008 suffixes and the unchanged expected digest
  `0ef2ce70d306e71d44a899d52a56a375022cb194cc534fab005934fb83bdaaa7`;
  receipt `android/final-routing-readback.json` under the current evidence directory.
  Local CLI file export into the repository
  correctly rejected a non-sticky0777 ancestor; a private home-directory control
  passed. The existing writable-ancestor regression covers that policy, and no
  host permissions were changed to bypass it.
- Branch `dev`; checkpoint19 `de9f9e4f79f7396db876f685a7f8a50969f12ed1` is pushed
  and all five required exact-SHA workflows passed. It preserves fixed Windows
  installer outcomes and fixes native-helper discovery and Android test launching.
  The approved token-saving workflow is active; acceptance/review gates are unchanged.
- Canonical product version is2.1.6 with no Unreleased bullets at checkpoint19.
  Native fixture versions are test-only Gradle overrides; canonical metadata stays intact.
- Managed checkpoint19 prepush passed:1641 JVM tests selected,1574 executed,67 explicit
  platform/opt-in skips, zero failures, plus complete script/hygiene/localization/tool
  checks. Receipt `/tmp/vpn-parity-checkpoint19-prepush.json` covers that checkpoint
  only; new content requires another full receipt.
- Checkpoint18's Windows CI failure is repaired in checkpoint19. PowerShell found two Python
  executables and joined their paths into one invalid command. Advisory VPN passed.
  Log `/tmp/vpn-2503-windows-ci-failed.log`. A native Windows PowerShell regression
  reproduces this through the actual producer after an explicit-path positive
  control. Causal RED: `/tmp/vpn-windows-finish.WhKUbn/native-helper-builder-path-20260908/red-result.json`.
  The resolver now selects the first Application candidate in PATH order for both
  Python and Dotnet. All3 native cases passed with zero skips (PowerShell5.1,
  Windows ARM64/x64 emulation): adjacent `green-result.json`, producer SHA
  `4697b2f49fe5f75f1895af108027d1ebef95896281c1597547040375c7de24ca`.
  The regression runs before expensive package builds. Current exact-SHA Windows
  CI built, inspected and launched the NativeAOT AMD64 helper from both extracted
  and installed MSI payloads. Helper SHA
  `c5e2e7c0b8b4e145bf4b64cea34d3af91a580bb9b6d4aba5e7ed7525daec03c1`,
  no CLR header, dependent-load flags2048; only validate-only is enabled.
  Log `/tmp/vpn-ci-34219519026-readonly.log`; compact five-workflow receipt
  `/tmp/vpn-parity-checkpoint19-ci.json`.
- Checkpoint17's missing-`os.getuid` Aqua-test failure is fixed in checkpoint18.
  A subprocess removes that API before launching the actual parser suite; causal
  RED `/tmp/vpn-aqua-portability-red.log`, fixed5 GREEN on host and native Windows.
  Native receipt `/tmp/vpn-windows-finish.WhKUbn/aqua-portability-20260908/native-evidence-v3.json`.
- Checkpoint16's Linux cancellation failure is repaired in checkpoint17. Root
  reproduced the cause without networking: closing a cancelled stream made
  the child throw IOException, which coroutineScope preferred over cancellation.
  Capturing the caller context outside that scope preserves cancellation identity.
  Causal RED `/tmp/vpn-manifest-cancel-io-red.{log,xml}`; all7 focused cancellation
  tests GREEN `/tmp/vpn-manifest-cancel-io-green.log`, including real stalled HTTP.
  This regression remains in ordinary desktop tests and each applicable CI suite.
- Previous checkpoint15 `7c28fe6cf04d98edb05076f835a2d049894b00a6` has all five
  required workflows successful. Its earlier local watcher ENOSPC was an
  observation failure; resumed exact-SHA checks completed successfully.
- `.codex/config.toml` is generated, local and ignored. The tracked template and
  `agent_tools/configure_codex.py` derive absolute paths; preserve local settings.

## Ownership And Build Coordination

One writer per file; root owns lifecycle tools, scope, version, documentation,
commits/push/CI, shared declarations, common integration and the host build queue.
Workers do not commit, bump versions or invoke lifecycle synchronization.
The user-approved resource-efficient defaults in `development.md` are active:
focused briefs, Terra medium for bounded work, stronger review for privileged code,
concise evidence summaries, reused native harnesses and coherent checkpoint checks.
All workers were notified; required coverage and delivery gates remain unchanged.

| Task ID | Agent | Owned subsystem | Shared reservation | Dependencies / environment | Current check | Next handoff |
| --- | --- | --- | --- | --- | --- | --- |
| B/G/H | root | Windows component integration, fixture regressions, docs and delivery | Shared models/UI, owner/factory/Main, build/version/CI | Dirty checkpoint23; checkpoint22 verified | Windows component30, helper20, desktop fixture27, Android transport11, Mac observer6 GREEN | Managed prepush and checkpoint push |
| C/D-Android | android_terra, Terra medium | Exclusive API35/5590 installer lifecycle; fixture transport | Root owns source freeze/build and integration | Immutable source0fc APK pair2.2.19/2.3.0 | API29 cancellation/resume complete; API35 in progress | Exact receipt, cleanup, evidence limits |
| F/E-Windows | windows, Astra | Broker coupled integration in ignored scratch; component review | Tracked broker integration, package/Gradle/factory/Main/autostart remain root | ARM64 Windows guest, x64 emulation | Kotlin21 and native fake-admission16/entry-fence6 GREEN | Immutable integration diff and lifetime review |
| E-Linux | root | Linux installed-package/native acceptance | Common update/build remain root | Gateway connection timeout; existing jobs preserved | Remaining installed-package scenarios incomplete | Revalidate access and supported-path rerun |
| E-Mac | mac_fixture_terra, Terra medium | Exclusive Tart guest current installer denial and relay | Root owns tracked source/build | Same-source be1 pair; exact worker3343 after prompt exit | Public outcome unknown, installed=null; no replay | Investigate reconciliation and causal regression |

Only one host Gradle invocation at a time. Android bccac4f snapshot pair2.2.15/16
built successfully in an independent frozen source directory; unrelated source edits may
continue. Snapshot fingerprint
`b41c250560e26cb0d8bd783bb8f913392c636c31749ecaed12a54c7b3655a189`, directory
`/var/folders/vq/zns5cfbd6zd64jw8hfgzzczr0000gq/T/vpn-android-bcc-pair-y7w31349`.
The driver verifies source hashes, exact signer, version/code and nondebuggable APKs.
Both APKs are nondebuggable, signer-matched and source-verified in `artifacts.json`.
Base2.2.15 SHA `9d4820b12e9cff8f517e69f2e3206170538d7f7e40e9dfd4bc5c86a12507f01e`;
target2.2.16 SHA `6bbc82296045c160700c5f295578235ddfb8e87b0b2345334876fd2eec641a61`.
API35 direct base upgrade preserved OFF intent, SSH presence and prior installation
recovery. It is not HTTPS-download/PackageInstaller acceptance. Task CA provisioning
needs a reviewed exception to the no-root constraint; no trust has been changed.

## Implemented And Locally Tested

### Shared Commands And Desktop Ownership

Typed registry/grammar/envelopes, revision/epoch guards, request deduplication,
retained operations, logical-document transport/private spools and export publication
are implemented. Desktop GUI/CLI use one authoritative controller with authenticated
frontend attachment, guarded drafts, visibility acknowledgments and owner scheduling.

Public Android streams are already dispatched before the downstream adapter's
nonempty-flag rejection. Shared cursor bookkeeping retains duplicates, limit0,
owner pinning, gaps and output-closure behavior; `DesktopAndroidStreamTest` covers
fake ADB/device/owner failures. Do not reopen the old claim that watch/follow is unwired.

Recent checkpoint fixes include cancelled manifest reads closing their IO lease,
ordinary/elevated Windows workspace startup, bounded safe CLI failure diagnostics,
Android configuration observer lifetime and safe macOS DMG smoke cleanup. The
existing script/JVM suites contain their causal regressions.

### Android Large Documents And Streams

Clean minified nondebuggable fixture2.2.14/code17080 APK SHA
`a6af10616e64dfa69cb17b6bd12c1d539da4c4f45653ca8e26a894e594c8ff84` uses signer
`a43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0`.
The permanent DataStore observer retained an obsolete large Preferences snapshot;
one-shot distinct subscriptions now release it without losing facade/gap writes.
Integrated configuration/serializer/reader/memory selection54 passed without skips.

API29 owned5584/48MiB passed same-process GUI56008→56009→56008 and independent
cold56008 readback, original digest
`0ef2ce70d306e71d44a899d52a56a375022cb194cc534fab005934fb83bdaaa7`.
Evidence `/tmp/5584-clean214-*.ndjson` and
`/tmp/vpn-android-resubscription-integrated-green.log`.

API35 owned5590 has192MiB heap growth, not48MiB. Same-process GUI add/remove,
full public cold readback and exact accepted cleanup wait passed. Operation
`cdab40f0-0259-43ae-af8f-43706c71f08d` reached terminal OK,56000 domains, digest
`5b7fcc5a4bff652c2165ff53836f01abc141df36df8705b9350f8ccfe64fe15c`.
After device loss and a data-preserving normal reboot, independent full readback
matched that count/digest. Status watch/log follow produced valid frames and client
Ctrl-C130; device-loss watch explicitly reported unknown owner outcome. A prior
116-second silent read was interrupted observation, not a demonstrated stall;
64KiB ADB frames were advancing and the complete read took about five minutes.
Evidence `/tmp/5590-cli-remove-fix235-wait.json`,
`/tmp/5590-after-device-loss-routing.json` and `/tmp/5590-reboot-cli-status.json`.

API35 SSH native import/replacement/invalid input and cold key-presence status were
exercised under `/tmp/5590-ssh-native.fVsoDj`. A further invalid import after a known task-generated credential preserved public
settings digest and key presence; private key identity is intentionally unavailable
through public readback. This does not certify
live SSH routing or active-connection preservation. No secrets belong in evidence.

### Current Coherent Follow-up Slice

The fixed Windows installer invocation/worker-ready codecs and role state machines
remain inert in production: Main still exposes validate-only and the old installer
launch path is unchanged. Review found four causal defects in the new role core:
valid commit racing owner exit, undefined receipt phase, and cancellation receipt
publication failure before/after replacement. All22 native component cases now pass;
receipt `/tmp/vpn-windows-finish.WhKUbn/fixed-installer-roles-v1/review-green-v1-native-evidence.json`.
This is Windows ARM64/x64-emulated C# execution with inert sessions, not native
installer integration. Host role/protocol selection13 selected,7 executed,6 explicit
Windows-only skips; the new role source is in the project and producer inventory.
The exact current five JUnit methods also executed natively (5/5, zero skips),
through x64 Temurin17/PowerShell5.1 on the ARM64 guest. Source/resource hashes match:
`/tmp/vpn-windows-finish.WhKUbn/fixed-installer-roles-v1/junit-wrapper-v1/summary.json`.

The following MSI adapter slice is implemented but not production-bound: fixed
read-only ProductName/UpgradeCode queries, retained handles/input on close failure,
silent per-user installation API and exact native result retention. Its19 behavioral
and2 real System32 database cases passed without installation or byte/mtime changes.
Evidence `/tmp/vpn-windows-finish.WhKUbn/fixed-installer-msi-v1-evidence.zip`.
Root reviewed the module and added its project/source inventory. Original-user
process/token/package/ancestor admission and actual install-user binding remain open.
Both exact current MSI JUnit methods also ran natively:2 executed, zero skips/failures,
using x64 Temurin17/PowerShell5.1 on the ARM64 guest. Archive
`/tmp/vpn-windows-finish.WhKUbn/fixed-installer-msi-junit-v1-evidence.zip`, SHA
`ea26b93f631b4a7ec922ae592282714782d05876c5e1a512855d358697b64e0e`.

Kotlin mutable-resource opcode5 now retains durable correlation before UAC and
decodes terminal resource evidence only after native exit. Opcode4 stays unchanged;
CACHE is an intermediate implementation and OUTPUT/cold recovery remain open.
Review caught the final-log bytes being read as the terminal envelope. The direct
decoder test reproduced that failure before correction; decoder/scoped-process/
reconciliation selection22 executed with no skips/failures. Its RED is retained in
the worker tool turn (no standalone RED receipt). The earlier broad selection39
selected/30 executed/9 platform skips is `/tmp/vpn-windows-resource-v5-focused.log`.
Native C# v5 now passes metadata7, commit/gate ordering6, configuration5 and two
real authenticated-pipe cases with an inert child: cache publication/repeated
admission and a9MiB configuration. Protected stages and gates remain retained;
cleanup=false is explicit. Main now binds its runtime digest to a constant generated
from the prepared bundled AMD64 runtime. Missing, mismatched and matching authority
passed6 native assertions; causal RED showed mismatched authority reaching only an
injected inert runner before the fix. No caller-selected digest authorizes another
runtime. Both suites ran on Windows ARM64/x64 emulation under SYSTEM, not ordinary
UAC or NativeAOT. Root verified all10 source hashes against the handoff. Archive
`/tmp/vpn-windows-finish.WhKUbn/broker-v5-authority-component-evidence.zip`, SHA
`5f487f0e433547942398901e708fb5b0963f0e91d73d7d7d9c3b9dba0d10a40e`.
Current host Windows selection196 selected/137 executed/59 platform-opt-in skips,
zero failures: `/tmp/vpn-checkpoint20-windows-focused.log`. All8 new exact JUnit
wrappers then ran natively through x64 Temurin17/PowerShell5.1, with no skips or
failures; runtime inventory stayed empty and protected stage/journal evidence was
retained. Archive `/tmp/vpn-windows-finish.WhKUbn/broker-v5-junit-v1-evidence.zip`, SHA
`aee2b502a06638c6e5c231fbc673bfa8cb300eab96895f63884297ef792d41b6`.
This remains ARM64 emulation with inert children. The production factory remains disabled.

The Windows helper tool now stages verified PE bytes/manifest into a prepared
`app/native/windows-amd64` directory and inspects the packaged result. Twelve fast
helper tests pass, including changed-byte/policy rejection. Root has now added
Windows-only Gradle producer wiring, pinned SDK CI setup, and helper validation/
nonmutating launch probes in extracted and installed MSI checks. Eight real Gradle
graph tests passed, including producer failure blocking packages and verified bytes
reaching both installer inputs: `/tmp/vpn-windows-native-package-graph.log`.
Current NativeAOT build/package execution passed in checkpoint19 Windows CI as
recorded above. The ARM guest lacks the pinned SDK/MSVC and native x64 guest access
is still unavailable; CI evidence does not enable or certify unfinished roles.
The next package slice adds the actual VpnBroker NativeAOT project and stages both
fixed executables under one verified manifest. A package missing its broker was
accepted by the old staging code: causal RED
`/tmp/vpn-native-broker-package-missing-red.log`. The verifier now requires both
reviewed helper names, hashes, PE/loader policies and copied bytes before atomic
publication. Verifier13 GREEN `/tmp/vpn-native-broker-package-green.log`; real
Gradle graph8 GREEN `/tmp/vpn-native-broker-package-graph.log`. Independent review
accepted this boundary. Synthetic PE/graph evidence does not certify actual AOT
compilation; the next exact-SHA Windows workflow must build and probe both files.
The producer now generates the compiled runtime authority from its exact prepared
runtime input. Generator/verifier15 pass; graph9 includes unchanged-input reuse
and runtime-change invalidation before both installers. Logs
`/tmp/vpn-native-broker-runtime-authority-green.log` and
`/tmp/vpn-native-broker-package-graph-final.log`.
The updated dual-helper producer's three inert executable-discovery cases also pass
on Windows PowerShell5.1, with all21 captured inputs matching current source.
Archive `/tmp/vpn-windows-finish.WhKUbn/dual-helper-builder-v1-evidence.zip`, SHA
`6d916e75339ae64a28d370c1d02d074559f79b0b928a4e26bf6e6f0922cca2ba`.

The macOS Aqua fixture observer is read-only: a single matching process/prompt is
only candidate correlation, never proof of authorization. Terminal authority uses
the successful public updates envelope and preserves unknown installed state.
Four direct tests passed on host and native macOS Python3.9; actual earlier fixture
false-positive and invalid-envelope RED logs are retained under
`/tmp/macos-aqua-correlation-prepare.ZSyEvK`. The test runs in release hygiene.
Its current five-test portable selection and Windows CI repair are recorded above.

The new single-device Android instrumentation launcher avoids AGP8.7.3's broken
`--serial` filtering by using its earlier `ANDROID_SERIAL` provider filter. Fast3
GREEN: `/tmp/vpn-android-instrumented-launcher-green.log`. Native launcher failure
and corrected launch are recorded in `/tmp/vpn-android-local-protocol-5592-launch-diagnostic.log`
and `/tmp/vpn-android-local-protocol-5592-benchmark-red.log`. The corrected launcher
ran exactly one test on owned5592. The safe greeting transcript identified two
empty preflight connections followed by native sessions offering only method2;
the old fixture incorrectly replied method0. RFC1929 fixture support now passes
7 quick tests, including unoffered methods, correct/wrong credentials and redacted
transcripts. Native auth/CONNECT passed before TLS reached the plaintext fixture:
`/tmp/vpn-android-local-protocol-5592-auth-boundary.log` and
`/tmp/vpn-terra-protocol-api35/fixture/greetings-auth-rfc2.ndjson`.

The authenticated bundled sing-box relay was restored after the host reboot.
Guest PID939 listens on loopback58181; host PID27277 forwards loopback18081 to it;
the guest reverse-dynamic SSH listener uses58183. Persistent tmux sessions are
`vpn-parity-macos-{restore,egress,relay,android-forward}-20260908`. A normal-trust
HTTPS request through the full Android-facing18081 path passed; no CA/root/host
VPN settings changed. Current evidence is retained under
`.runtime/parity-evidence/checkpoint20/macos/` in `android-facing-health.txt`,
`relay-stability.txt`, `tmux-processes.txt` and the corresponding listener receipts.
The Android native rerun reached manual/ok before an incorrect new assertion
required primary timing. Manual benchmarks intentionally keep primaryTotal=null;
testTotal is the measured proxy request. A host semantics regression now preserves
that contract; the native assertion was corrected without changing product code.
Log `/tmp/vpn-android-local-protocol-5592-trusted-https.log` retains this test defect.
The measured rerun passed exactly1 native test with no skips, test_ms844.282209 and
score1311.400334. Its source/APKs/XML/logs are recorded privately under
`/tmp/vpn-terra-protocol-api35/trusted-measurement/`. Resolved diagnostic child-replay
code was then removed. The final concise smoke passed exactly1 native test with
zero skips after correcting the JUnit signatures described below. Its debug APK
SHA `16f32483a8ad8ad4f32feed57d8571c383d2bb1363125b350eb7c0611905bb28`, test APK
SHA `941de8b06416f8f2a56d51ccb469bbc87ff10d5302f9a7557c4c6d5572a837da`, XML/log hashes
are archived in `/tmp/vpn-terra-protocol-api35/final-smoke-signature-guard`.
Test target routing has a passing quick config test that checks CIDR containment
and requires the final proxy route. This is debug instrumentation evidence; the
nondebuggable public GUI/ADB action scenarios remain separate.

The concise native smoke initially could not initialize its JUnit runner: three
expression-bodied tests returned Int, and a provider test returned Bundle.
`verifyDebugAndroidTestSignatures` reproduces all four using actual compiled
bytecode, before APK packaging or connected execution. Explicit Unit returns fix
the methods. Its isolated Gradle fixture compiles valid and invalid classes and
also catches a missing compile dependency, which had made the first verifier read
stale bytecode. Guard and fixture now pass; both are in Fast Checks and managed
prepush. Causal RED `/tmp/vpn-android-instrumentation-signatures-red.log`; native
rerun/archive above preserves the original OS scenario.

API35/5590 nondebuggable GUI Recheck reached final OK with test=ok, tcp52.6ms and
score846.62375, operation `c0333fad-af5b-4dae-9b96-0adc25ea643e`.
GUI Find Best reached final OK, operation `35ae6758-ef38-4526-8a77-90c874cbabcd`,
revision23. Explicit disconnect and guarded restoration reached final OK through
revision26: runtime OFF, no selected/active location, original source and validation
target restored. Locations match semantically after excluding regenerated exported_at;
digest `e9527d74df47fc3f8726699580572c78f7b99bfc17222cfb952303f021794909`.
Private manifest `/tmp/vpn-terra-api35-public-baseline/public5590-gui-evidence-manifest.json`
records exact APK/signer/source and operations. Production Android main/JNI/assets
and shared source closure matches the bcc fixture; only test build wiring and
canonical version metadata differ. This remains bcc2.2.15 fixture evidence, not
certification of a final delivered package or the remaining cancellation/SSH matrix.

### Desktop Installation Evidence

macOS r4 machine update from a source-matched23d base2.1.17 to target2.1.18 passed
real Aqua authorization, handoff, replacement, protected receipt and next-owner
recovery. Job `d5b9b029-36d1-495c-bdba-44d628e08a3d`, operation
`6c4c09cb-d78a-4452-b58c-1ad0a5388d3e`; protected sequence4 SUCCEEDED/OK.
New controller `45e4bcad-b270-4afb-aa60-6e613591f5bc` reports installed=true and
cleanupCode=OK; GUI show succeeds and runtime remains OFF. Target DMG SHA
`524f982e1cced9bf70a3278d33240373c82a9cdd46e11202bdf8ebbb9dd099a6`.
Root-verified redacted archive `/tmp/vpn-parity-macos-r4-evidence.hErTxE/r4-evidence.tar.gz`,
SHA `a65d83021f6d9d89088747852261d0cad920ca8ddf948b5dff925bbc95bc56f0`.
This is an earlier-source fixture and ad-hoc signing evidence, not final delivered
package/signing certification. Current full DMG smoke and18-test CLI harness passed.

The same installed r4 app preserved traffic and one controller/runtime through
seven GUI/CLI lifecycle gestures (40/40 probes each). A real Aqua close-button
action by exact frontend PID also passed40/40 with the runtime identity unchanged;
root-verified archive `/tmp/vpn-parity-macos-r4-os-close.afDvtb/r4-lifecycle-through-os-close.tar.gz`,
SHA `4087f58c2dcc71736838b7e714d791ca26852113f1018e07a78ea17174cb6b79`.
The first GUI-free scheduled-refresh fixture reported partial failure because
active refresh uses the running proxy route rather than the offline JVM fixture
proxy. A corrected isolated SOCKS/TLS fixture passed scheduled refresh with the
same active runtime and traffic10/10 before plus20/20 after. Root-verified archive
`/tmp/vpn-parity-macos-r4-active-route-refresh.tar.gz`, SHA
`f66579e3a6cba56dde4149d27c187ef7bce92d796b2003035e487dd3c99989ec`.
The intervening manual/active fixture-body mismatch has an executable local-route
RED/GREEN consistency check. The broader r4 environment and unknown jobs are preserved.

The reusable exact-PID Aqua helper passed4 quick tests and a fresh native window
close (AX1→0, exit0, owner remained OFF), final source SHA
`120a3e8bd399d314147d0bca052dc4b1b684a8f6d8ceb6d84e8a98ead9d8f54b`.
Archive `/tmp/vpn-parity-macos-r4-aqua-helper-final.tar.gz`, SHA
`77dd33314bf29e035bd4f92ffd9fd7a25b78b8c36aa4b1319fed9f6bfa773973`.
This is launcher/Aqua evidence, not installation authorization. Task owners were
publicly quit; close-to-tray frontends may remain without windows. Do not kill them
or replay a timed-out remote click based on observation alone.

Reuse the current exact-SHA CI evidence before repeating native launch checks:
macOS run34219519076 passed7 native worker gate and3 ENOSPC cases plus the newly
built2.1.6 DMG's disconnected public CLI smoke. Linux run34219519200 passed public
CLI smoke for extracted DEB/RPM payloads and an installed Arch bundle. Windows
run34219519026 passed NativeAOT production/staging/probes, the routine role wrappers,
extracted public CLI smoke and installed MSI smoke. Their logs are retained as
`/tmp/vpn-ci-<run-id>-readonly.log`. CLI smoke includes streams/Ctrl-C/QR and large
routing import/retained result/private export. These specific proofs do not replace
real update/UAC/Aqua/original-user recovery, GUI/traffic or final signing evidence.

Linux earlier same-source Ubuntu/Arch recovery and RPM scenarios have evidence;
see the historical ledger for manifests. Current7c Arch pair2.1.6/2.1.7 built with
actual JDK17; source fingerprint
`53b3c2beb2e056766ca8a523f47835691a3c8dcbbcdcd1c77c85582499e4acb7`.
Guest fixture `/home/vpnfixture/fixture-7c28fe6-5t1xfenn/fixture`, verified receipt
`/tmp/vpn-linux-fixture-7c28fe6-native-receipt.json`. The alternate-root attempt
correctly failed before handoff because the privileged adapter admits only
`/opt/vpn-control/bin/vpn-control`. Public harness now rejects that fixture setup
before owner startup/authorization: causal RED1/14, GREEN14, bundle verifier10 passed.
This fixture correction is not evidence of a supported-path product update failure.

Windows corrected immutable image passed ordinary/elevated public smoke and29
focused transfer/install/cancellation tests without skips. Archive
`/tmp/vpn-windows-finish.WhKUbn/current23d-corrected-v1-native-evidence.zip`, SHA
`10a0e9dd10b4bc793c32cc2ecf28e6c3cd763405b41465f12be09c4bba9cc914`.
Native x64 broker component evidence includes TUN traffic and UAC denial continuity;
it does not certify production broker binding or MSI replacement.

Checkpoint16 kernel-process classification retains native process handles and
matches PID/creation time around image/snapshot queries. Unknown processes fail
closed; no process-name/error-code/managed-HasExited exemption is authority.
Causal native RED rejected independently proven kernel classes3/4. Host backend13
passed; six Windows native fixture tests skipped on macOS. Exact native6+13 v4
job was launched before gateway loss; outcome remains unknown pending retrieval.
Scratch `/tmp/vpn-windows-finish.WhKUbn/kernel-inventory-v3` retains identities.

## Remaining Implementation And Native Acceptance

- Windows is the largest implementation gap: installer helper currently exposes
  only validate-only; runtime installer still launches captured PowerShell roles.
  Complete fixed native user/coordinator roles, original-user token handling,
  pinned helper launch and verified native packaging. Broker project/staging and
  Kotlin/native mutable-resource framing have component evidence; actual AOT/package
  checks remain. Finish OUTPUT/cold resource recovery and full configuration
  support, replace the PowerShell launch with retained fixed-helper admission, enable the
  production path, then remove whole-GUI elevation and HIGHEST autostart. Current
  `windowsScopedRuntimeEnabled=false` is not parity completion.
- Android: both-API installer lifecycle/cancellation/retention/confirmation recovery
  with current compatible packages; full SSH credential rollback/live routing;
  Find Best/cancellation/recovery, benchmarks, consent/foreground-service ownership,
  actual-A/pending-B connected/scheduled refresh, GUI callbacks and visuals.
- Linux: current supported-path Arch installation/recovery, remaining fresh DEB/RPM
  dependency/replacement/rollback cases, traffic and GUI/controller continuity.
- macOS: remaining local/machine authorization-denial/failure/rollback/cleanup cases,
  current-package signing/worker evidence, proxy traffic and GUI/controller continuity.
  The corrected Aqua observer and exact-PID helper have native evidence; keep using
  real receipt authority for subsequent authorization scenarios.
- Shared/public audit: capabilities/help/real handlers, equivalent human/JSON
  timeouts/errors/raw bytes, every required stream/owner-replacement case,
  document/persistence/resource/export races and GUI/CLI action equivalence.
- Visuals/localization: review changed scenes and Android installer states, update
  intended baselines/inventories, verify reachable controls and typed failures.
- Refresh the native-launcher inventory for current hashes. Earlier37/40 mapping
  is historical; changed scripts require their own native receipts and no-skip
  execution. Launcher execution alone never closes the full product matrix.

## Live Environments And Uncertain Outcomes

Revalidate current processes and public state before acting; these are last-observed
identities, never authorization to kill/restart anything.

- Remote gateway `ssh.karapsin.com:228` currently times out. Authorized route remains
  that gateway, then archlinux, then the assigned disposable guest. This is network
  access failure, not guest authentication failure or evidence of terminal jobs.
- Windows owned x64 guest2314: scheduled `vpn-parity-kernel-inventory-v4`, guest
  `C:\VpnParity\KernelInventory-v4-20260908`, setupQGA6884 terminal0; test outputs
  unretrieved. Do not duplicate/restart its run because observation timed out.
- Arch2317: earlier OFF owner12230 and alternate-root OFF owner17118 last observed.
  Alternate install job `f8de2e5a-3e62-496b-a821-8c12b4ed117b` has protected terminal
  FAILED/RUNTIME_FAILED, operation `6eed2827-740a-4003-999b-91dea7741c0c`.
  Loopback-only fixture TLS process17077/port39419 has process-only JVM trust.
  On restored access, revalidate old owner OFF/terminal, use its public quit, confirm
  exit, then install current base at the supported root. Preserve prior evidence.
- macOS owned Tart `vpn-control-visual-macos`, guest192.168.64.3. Latest read-only
  inventory observed r4 owner38207, frontend44198 and runtime44590; older r2/r3
  owners/runtimes remain present. About349MiB disk was free. Preserve the live relay
  and uncertain earlier jobs2c8…,79677cc5… and5d5a78c3…
  and their owners/watchers/input applications. Earlier authorization arrived after
  owner timeout; later cancellation is not proof of terminal recovery.
- Android owned5584/API29,5590/API35 and isolated5592/API35 protocol-test AVD.
  API29 has clean fixture2.2.14, API35/5590 has current source-pair base2.2.15;
  5592 has the debug instrumentation fixture and host loopback SOCKS server18081.
  protected5580/5582 untouched. Native scenarios use nondebuggable ADB without
  root or run-as. Frozen96f CLI manifestSHA
  `a14bdfa526c35cec734fe2b03ed4293d3eb9d2412db1d587cccaeba9042d54e6`.

## Checkpoint 23 Fixture Corrections And Component Evidence

Checkpoint23 was pushed as `749bdc38d658eec05e9e91c8644b3c67fa2a0693` after
all15 managed prepush commands passed. Windows package CI34264247437 failed
release hygiene: the macOS observer used host-specific path serialization, so its
literal POSIX fixture failed on Windows. A PureWindowsPath regression reproduced
this on the host before changing comparison to POSIX serialization. All7 observer
tests now pass locally; corrective native Windows execution and exact-SHA CI
remain delivery gates. Evidence is under local checkpoint23,
`windows-ci-failed.log` and `macos-path-portability-{red,green}.log`.


- The actual macOS `ps` output renders the installer worker path containing
  `Application Support` without shell quotes. The observer previously rejected
  that live coordinator. A literal unquoted process-tail regression failed before
  replacing shell parsing with an exact path plus terminal job/PID match; all six
  observer tests now pass. RED/GREEN logs are in local
  `.runtime/parity-evidence/checkpoint23/macos-ps-parser-{red,green}.log`.
  This corrects observation only; cancellation and public terminal recovery still
  require fresh native correlation and authoritative receipts.
- Android fixture transport regressions now run in release hygiene: all eleven
  pass, including adbd restart clearing reverse mappings, refusal to replace
  unrelated mappings, changed proxy ownership, and retryable ordered cleanup.
  The API29 manual route repair preceded the reusable regression; it was not a
  regression-first operational repair. Native callers must also check mappings
  before setup-time `adb root`, then verify UID2000 before public app commands.
- Actual Gradle execution passed the new Windows helper admission selection
  (13 tests) and existing Windows installation admission selection (14 tests),
  with no failures or skips. This is component evidence; production broker
  binding, scoped UAC and actual packaged-owner/native traffic gates remain open.

## Final Delivery Gates

Require current installed-package evidence on Linux x86_64 DEB/RPM/Arch, Windows
native x86_64, macOS actual architecture and Android API29/API35. Label Windows
ARM64 emulation/component/mixed-artifact evidence accurately. On every desktop,
prove one owner and traffic continuity through attach/hide/show/close/crash,
CLI disconnect and GUI-free scheduled refresh. Verify static commands cause no
startup, missing-owner status is unavailable, transient query-owner behavior,
serve lifetime, explicit OFF intent and later GUI reconnect initialization.

For each native run record source fingerprint, package/helper hashes, OS/architecture/
JVM/API, public launcher, fixture/workspace, safe output/exits, exact operation/job,
terminal outcome and cleanup. Match final package evidence to delivered source.

After final content, review workflow_status/scope, version_bump for non-documentation
changes, managed prepush, explicit reviewed commit/push and all five required
workflows for the exact SHA. Fix CI defects with causal regressions and repeat.
Advisory VPN Integration and passing component tests cannot replace native/visual gates.

## Preserved History

The previous contradictory checkpoint ledger is preserved verbatim in
[parity-checkpoint-history.md](parity-checkpoint-history.md). Earlier evidence is in
[parity-native-history.md](parity-native-history.md) and [parity-history.md](parity-history.md).
Those are historical retrieval aids, not current completion or process authority.
