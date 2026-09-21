# Parity Failure-to-Regression Ledger

This ledger is a maintainer index for the failure records currently referenced by
`work-in-progress.md`. It applies `TEST-001`: a quick regression is evidence of a
specific cause only when the recorded RED precedes the repair and the GREEN is
wired into a routine suite. A secure rejection, explicit unsupported result, or
environment limitation is not a product defect unless the record says otherwise.

| Failure type | Product or fixture | Cause established so far | Proven quick test and routine wiring | RED / GREEN evidence | Native evidence | Unresolved gap |
| --- | --- | --- | --- | --- | --- | --- |
| Android benchmark relay rejects the configured validation target | Obsolete ignored fixture | Retained checkpoint37 relay allowed only github.com while the APK default was chatgpt.com. Absent success-only relay transcript did not prove absence of a SOCKS attempt; SELinux messages were not causal evidence. | `test_default_allowlist_admits_android_benchmark_target_and_rejects_unlisted_egress` derives the actual shared default URL, exercises SOCKS admission with mocked upstream, and checks denial before upstream access for an unlisted host. Existing release hygiene runs this module. | checkpoint90/android/historical-policy-red.log reproduces the obsolete github-only policy's rejection; green.log passes5 tests. The tracked relay already had the correct allowlist: this is prevention coverage, not a new product/relay fix. | checkpoint89/android/discriminator-evidence.sha256: same native ARM64 candidate succeeds at1091.471209ms after public guarded URL alignment; original settings restored and relay/reverse removed. | Use the tracked fixture for new runs. This one target measurement does not close default-target, VPN, cancellation, API29 or full Android acceptance. |
| Complete installer handoff discarded by terminal EOF/reaping race | Fixture observation | Ignored driver rejected observationLost even when it retained a complete authenticated ACCEPTED/handoffReady response and eventual client exit0. | Shared routine harness terminal_install_handoff validates response and terminal client outcome; it rejects absent responses/live clients while retaining EOF metadata separately. | checkpoint83/linux/handoff-eio-red.log fails the extracted old guard; handoff-eio-green.log passes18 tests. | cp83 same EOF race retains the handoff and reconciles exact protected failure; cp82 discarded it before root independently recovered it. | Native RPM failure/recovery is proven for the frozen bundle; other package/current-source scenarios remain separate. |
| Old terminal installation failure replaces a fresh update attempt | Product recovery presentation | Every status read projected the retained failed receipt over the newer check/download/ready state; dismiss also revived it. | DesktopRecoveredUpdateStatusTest exercises retained failure, retry phases, dismiss, cleanup-only changes and a new unknown-to-installed job in routine desktop tests. | checkpoint84/linux/retry-state-red.log reproduces the old failure before the service change; retry-state-green.log passes the focused recovery/cleanup/exit selection. | checkpoint84/linux/native-retry-failure.json records successful intact RPM download followed by failed status from the prior receipt. | Rebuilt installed-package retry and final delivery remain required. |
| Linux fixture sends authorization input before the real prompt | Fixture terminal admission | Ignored checkpoint79 driver matched bare `password` in Java trust-store diagnostics before polkit's actual prompt. PTY loss and timeout are unproven. | Strict ANSI-aware current-line prompt matcher and `LinuxPublicInstallHarnessTest` causal vector reject diagnostics and partial prompts; routine release hygiene already runs the harness. | checkpoint82/linux/prompt-causal-red-replay.log substitutes the exact old predicate and fails; prompt-green.log passes17 tests. This is controlled replay, not a pre-existing tracked product defect. | Original native job remains UNKNOWN without handoff or protected receipt; no corrupt RPM execution is claimed. | Durable fixture rerun remains required; original unknown job is preserved. |
| Expired disposable HTTPS certificate advertises a ready update fixture | Fixture TLS admission | Retained Windows server certificate expired on September9 but the fixture announced ready on September20, so public update checking failed during TLS. | Desktop update fixture tests exercise actual serve admission, reject expired/not-yet-valid public validity windows before resource/TLS/bind/READY, and accept current certificates. Ordinary release hygiene runs this suite. | checkpoint80/fixture-cert/serve-expired-red-replay.log reproduces resource access with the admission call removed; final-fixture-green.log records48 passing tests including current-window acceptance and fixed-clock admission. | Windows cp78 check returned RUNTIME_FAILED and server logged TLS handshake EOF. Public certificate dates are retained. Renewed isolated certificate/trust store restored public check/download/READY under ordinary user, checkpoint80/windows-tls/results.json. | Delivery pending; no global trust or production verification was weakened. |
| macOS fault-injection probe drifts from the native cleanup interface | Test harness | Embedded C still called the old one-argument cleanup function. Ordinary local checks skipped the entire fixture class, hiding the compile failure until CI. | `MacInstallEnospcProbeCompileTest` compiles the actual generated probe on Darwin without running installer or mount actions. Existing release-hygiene wiring now exercises it locally; full fault scenarios remain guest-gated. | checkpoint79/macos-ci/compile-only-red-replay.log records clang expected2/actual1; compile-only-green passes1 with6 guest skips. guest-full-header-complete.log passes all7 in the owned Mac VM. | macOS CI35529722794 failed on c8f30e0. The fixed fixture keeps terminal-receipt cleanup enabled with `true`; no product helper semantics changed. | All five required workflows passed for replacement SHAbe009403669c0a1203c2f767b7ddf3d677a4bbfb. |
| Duplicate desktop serve pretends to supervise an existing owner | Product lifecycle | After authenticated promotion of a query-created owner, `DesktopExistingService.await` printed ready and polled indefinitely. Promotion is valid; pretending to own/supervise the existing process is not. | `DesktopHeadlessControllerTest.duplicateServePromotesExistingOwnerWithoutSupervisingIt` exercises a real held lock/authenticated server. `DesktopCliProcessTest` covers both transient and persistent existing owners; routine desktop suite. | checkpoint77/serve-supervision-red.xml records one causal failure: two requests instead of the single promotion request. The earlier no-adoption test was superseded because it incorrectly rejected valid transient-owner promotion. final-union-green passes64 tests with0 failures and1 Windows-only ACL skip. | Installed macOS2.1.14 retained both serve processes until public quit; exact owner remained44f3d6c3-c0b4-4596-a2c5-baec97bebceb. Raw evidence checkpoint77/macos-query. | Installed sourcec8f30e0 DMG proof in checkpoint81/macos passes both immediate persistent duplicate exit0 and same-epoch transient promotion with35 seconds of idle retention; all new test owners publicly quit. |
| GUI crash leaves quit blocked by a stale frontend lease | Product lifecycle | Quit required a fresh identity response from a crashed frontend even when its exact authenticated process generation had been captured at attach. | `DesktopQuitControlTest.quit_releases_only_a_captured_dead_frontend_generation` exercises owner submission with a captured, exited JVM process. Lifecycle/identity tests retain unknown, live and replacement-generation rejection; routine desktop suite. | checkpoint77/linux/frontend-quit-causal-red.xml records expected OK/actual CONFLICT. checkpoint77/integrated-focused-green includes the passing three-test quit suite using a portable stdin-gated JVM child. | Installed RPM traffic survived GUI attach, close/reopen and crash; off succeeded, old-package quit returned CONFLICT. checkpoint77/linux retains exact controller/runtime and raw manifest. | New-package crash/quit revalidation remains required. |
| Proven macOS authorization denial retains installation inputs | Product cleanup wiring | Production `DesktopUpdateService` supplies no `releaseNotStarted` callback, so the existing cleanup reconciler skips authoritative no-receipt NOT_STARTED cancellations. | `DesktopMacUpdateServiceTest.ownerMaintenanceDisposesOnlyTheExactForeignMacNotStartedInput` covers production callback composition; installer/worker tests cover exact helper admission, repeated owner cleanup and interrupted chmod recovery. Routine desktop suite. | checkpoint77/mac-cleanup-binding-red-replay.xml reproduces the omitted binding. Naming and repeated-owner defects have causal RED at cleanup-worker-name-red.xml and cleanup-idempotence-red.xml. cleanup-mode-red-replay.xml explicitly replays the prior strict-0700 guard. integrated-focused-green records60 tests,0 failures,1 unrelated platform skip. | Current DMG fixture job440b86ce-8db3-4e62-867a-3082f23a2851 is CANCELLED/final/installed=false with no live worker but retains approximately141MB. Successful job cleanup works separately; checkpoint76/macos-auth76/root-review.json. | Independent review found no blocking defect. Installed sourcec8f30e0 DMG native proof in checkpoint81/macos removes140947456 bytes, preserves exact disposition/terminal result, and fresh-owner cleanup remains OK. Original unknown owner and state were preserved. |
| Android validation subprocess crashes under ARM64 translation | Native runtime/environment, attribution unresolved | Real SOCKS forwarding works for service traffic, but `libsing-box.so run` benchmark subprocess SIGSEGVs under the remote x86_64 emulator's ARM64 translation before SOCKS negotiation. | No implementation fix made. Existing failure-path behavior preserves active A/pending B; native ARM64 comparison is required before identifying a causal application regression. | checkpoint78/android contains raw public benchmark/Find Best failures, logcat and forwarding evidence. No successful measurement or in-flight cancellation is claimed. | Nondebuggable2.1.13 API35 emulator5680; benchmark RUNTIME_FAILED/null timings, Find Best committed=false/RUNTIME_NOT_CHANGED. Public off/delete cleanup succeeded. | Compare on native ARM64; add the fastest causal regression before any product repair under TEST-001. |
| Approved ADB is rejected when executable discovery changes path spelling | Fixture preflight | Windows executable discovery may return `.EXE` for the selected `.exe`; exact string equality rejected the same file even after the test executable suffix was corrected. | `PreflightScriptTest.test_packaged_cli_adb_discovery_compares_file_identity` accepts an actual filesystem alias of the approved file and rejects different, missing, or absent discoveries. Routine release hygiene runs it. Compare file identity without weakening selected-binary validation. | checkpoint74/adb-identity-red.log records rejection of the approved alias before repair; adb-identity-green.log records33 passing preflight tests and adb-identity-driver-green.log11 driver tests. | Windows CI35524836654 exposed the second cause; its portable lowercase-PATHEXT probe passed while real Windows discovery failed. | Windows package CI35525083686 passed for94dbd58; native ADB execution remains separate. |
| Android fixture test uses a Unix executable name on Windows | Test fixture | The packaged-CLI admission test created `adb` instead of `adb.exe`, so Windows executable discovery rejected the fixture before launch. | `InstallerLifecycleTest.test_driver_pins_adb_with_windows_executable_discovery` exercises the real `shutil.which` Windows branch on every host, with only the native current-directory query stubbed; normal test uses the host executable suffix. Release hygiene includes the suite. | checkpoint74/windows-discovery-causal-red.log reproduces the CI rejection against committed code; windows-discovery-green.log records11 passing tests. The earlier probe failed due to an absent `_winapi` stub and is not causal evidence. | Windows CI35524559311 failed before packaging. | Windows package CI35525083686 passed for94dbd58; this test does not certify native ADB execution. |
| Cancelling a recovered unknown installation waits forever | Product desktop operation handling | `updates cancel` ignored a refused cancellation, then waited indefinitely for an installer with no cancellable local job. | `DesktopHeadlessSessionTest.updatesCancelReturnsUnknownWithoutWaitingForAnUncancellableRecoveredInstall`; routine desktop tests. Wait only for accepted cancellations, preserve unknown installation records and skip dismissal when cancellation cannot be acted on. | checkpoint74/cancel-recovery-red.xml records a virtual-time timeout before repair; checkpoint74/cancel-green contains31 passing tests,0 skips. | Old installed macOS package reproduced the hang after VM/owner loss. The3055e97 DMG-installed package reopened the original workspace and returned OUTCOME_UNKNOWN/exit2 in0.17 seconds, preserving the exact original job; checkpoint74/macos/current-package-cancel-root-review.json. | Original installation remains unknown; this closes bounded cancellation only, not machine replacement or authorization. |
| Android installer fixture drops file-based continuation | Fixture coordination | The driver parsed `--continue-file` but omitted it from the namespace passed to its action, which then waited on stdin. | `scripts/test_android_installer_lifecycle.py` tests real main-to-action forwarding, checkpoint ordering, artifact rejection and no replay; release hygiene runs it. The reusable driver accepts explicit artifact identities. | checkpoint74/android-driver retains the original-driver causal failure and root-green.log (10 tests). Windows permission mocking was narrowed after a separate missing-file-stat regression; the first exists-only probe passed and is not RED evidence. | The original ignored driver was used in earlier API35 runs; the corrected reusable driver still needs native use. | POSIX permission cases do not certify Windows ACLs; portable forwarding tests preserve real checkpoint writes. |
| Linux headless fixture rejects a group-writable ancestor | Ad-hoc fixture setup | Loopback bind succeeds, then private endpoint publication rejects the0775 non-sticky ancestor. A0700 leaf alone cannot repair unsafe ancestry. | Existing `DesktopControlTransferParentTest.rejectsWritableNonStickyAncestorBeforeCreatingPrivateContent` covers the rejection policy in routine desktop tests. No product fix or new causal RED is claimed. | Existing policy retained; checkpoint73/Linux includes full native trace and safe-workspace comparison. | Current installed2.1.13 query and serve/status/quit pass under private sticky-temp ancestry. Root reviewed all7 exported artifact hashes and raw bind/ancestor trace. | Use private ancestry when creating future fixtures; preserve the rejected evidence directory rather than relaxing security policy. |
| Desktop benchmark drops rendered owner/revision guard | Product GUI/owner dispatch | GUI used an unguarded legacy command while the opaque owner adapter rejected revision guards. | `DesktopHeadlessSessionTest` covers valid/stale opaque and selector requests plus revision drift after async acceptance; GUI helper captures stable retry identity. Routine desktop tests. | checkpoint69/desktop-benchmark-red.xml records expectedOK/actualUNSUPPORTED;16 focused tests pass after paired adapter/frontend fix. | Current-package GUI verification remains pending. | Mutation-lane revision and installer barriers are preserved; native scenario remains in final batch. |
| Android benchmark follows a changed row index | Product GUI dispatch | Rendered click index was resolved against latest storage order, allowing refresh to retarget a benchmark. | `AndroidLocationActionsServiceTest.renderedBenchmarkTargetDoesNotRetargetAfterRowsReorder` uses the shared rendered-row adapter; normal Android unit suite. | checkpoint69/benchmark-red.xml records First becoming Second before the fix; final service/presentation selection passes10 tests and compilation. | Current-package UI verification remains pending. | Rendered raw identity and source scope now reach owner validation; keep native reorder scenario. |
| Android selection committed but response reported failure | Product operation reconciliation | ON/RESTART persistence can commit selection then lose the response. | `AndroidConnectionControlTest.responseLossAfterExactDurableSelectionReportsCommittedSuccess`; normal Android unit suite. | checkpoint69/android-selection-red.xml records RUNTIME_FAILED after commit;15 focused tests pass. | Component evidence only for this change. | Exact selection fields, changed revision and same owner are checked while the configuration mutation lease remains held; native response-loss proof remains separate. |
| Resolved installer worker diagnostics leak into next attempt | Product installer handoff | A clean new admission retained the previous worker's late-authorization primary failure. | `DesktopInstallHandoffTest.newWorkerDoesNotInheritAResolvedLateAuthorizationFailure`; routine desktop tests. | checkpoint69/desktop-handoff-red.xml is a baseline replay after reverting only the fix, not original pre-edit RED;18 tests pass afterward. | Existing terminal worker evidence is preserved. | Reset occurs only after pending/uncertain-worker admission checks; new packaged scenario still required. |
| Windows NativeAOT output path exceeds native linker limit | Product build paths | Unnormalized parent segments made the actual linker output path264 characters; equivalent normalized243-character path succeeds. | Windows-only `test_native_aot_project_paths_are_canonicalized_before_linking` evaluates real pinned MSBuild properties; routine release hygiene now follows SDK setup in Windows CI. | checkpoint68/windows-linker-path-probe-v1-result.json retains real failing/successful linker probes; pinned-MSBuild normalized-path probe passes. Non-Windows suite explicitly skips this native check. | Ordinary-user Windows guest; no registry long-path setting changed. | Full frozen package build follows integrated source freeze. |
| Packaged Android CLI cannot discover fixture-selected ADB | Fixture child environment | Harness used absolute ADB while packaged CLI resolved bare adb in a PATH without SDK tools. | Preflight tests run a controlled executable through real baseline/update subprocesses and verify rejection before ADB construction; routine release hygiene. | Missing-ADB child fails first; selected child-only PATH succeeds;29 focused tests pass. API35 raw probes retain original failure and successful exact-SDK PATH comparison. | API35 remained before installer acceptance; no product provider defect established. | Current frozen APK lifecycle remains pending; host/global PATH is unchanged. |
| Interactive driver reached installer before discovering stdin EOF | Fixture admission | Checkpoint driver paused with input() only after accepting installation, but was launched without an interactive stdin. | `require_interactive_stdin` rejects before driver fixture mutation; focused routine module covers absent/TTY inputs. | Native137 missing-helper assertion is not causal evidence. Isolated142 driver replay proves unguarded launch/output creation versus guarded rejection without either;25 module tests pass. | Original accepted operation was preserved and reconciled, never replayed due to EOF. | Task-specific driver calls guard explicitly; noninteractive no-update paths remain supported. |
| Packaged Android CLI passed to Python by installer harness | Native fixture launcher | Baseline and no-update probes unconditionally prepended sys.executable to a Mach-O packaged launcher. | `test_public_cli_launches_packaged_executables_directly_and_keeps_python_adapters_compatible` checks baseline and update argv plus retained Python adapter compatibility; routine release hygiene. | Causal packaged-argv assertion failed before repair;24 focused module tests pass. Exact raw evidence is retained with checkpoint66. | Correct direct public status succeeds on API29; installer retry remains in progress. | This fixes fixture invocation, not Android product transport; the earlier malformed manual document-begin diagnosis was retracted. |
| macOS shell regression launched through Windows WSL shim | Test portability | Python subprocess resolved `bash` to Windows' WSL launcher, which had no distribution; POSIX fixture execution was not platform-gated. | `test_windows_does_not_launch_posix_fixture` simulates Windows and asserts explicit skip before subprocess invocation; ordinary macOS/Linux still execute both architecture fixtures. Routine release hygiene. | checkpoint62/windows-fixture-causal-red.log fails before guard; windows-fixture-green.log passes3 tests on Mac. | Windows CI35083051986 failed at the new shell fixture; full failed log retained. | Corrected Windows workflow35083667081 succeeded for2c3aae9; all five required workflows succeeded. No product failure is claimed. |
| Native macOS helper inherits build-host OS minimum | Product packaging | ARM package launcher targets11.0, but compiling the helper on macOS26 produced Mach-O minos26.0, excluding the macOS15 guest. | `test_macos_install_worker_target.py`: fake ARM/Intel compiler invocation with hostile deployment environment, plus native host compile/Mach-O inspection; routine release hygiene. | checkpoint62/mac-target-red.log: two causal failures before repair; architecture-aware suite passes. ARM pins11.0; Intel preserves package10.13 floor. | checkpoint61/macos-package-review.json and original helper retain the rejected build identity. | Corrected pair helper minos11.0 verified; public user-local update succeeded on macOS15 with exact next-owner recovery (checkpoint62/macos-update64). Machine-owned and rollback scenarios remain open. |
| GUI reopen immediately after frontend crash | Product frontend lease | Dead frontend retains a15-second registration; first GUI_SHOW reports UNAVAILABLE, later request succeeds after expiry. | `DesktopGuiVisibilityControlTest.deadRegisteredFrontendIsReplacedAndShownInTheSameRequest`; desktop routine suite. Guards cover concurrent registration and uncertain-response non-replay. | checkpoint60/frontend-crash-causal-red.xml:1 test, expectedOK/actualUNAVAILABLE before production edit; checkpoint60/frontend-final-green:24 passing,0 skips. Review found two additional causal edge failures, captured in frontend-review-causal-red.xml before correction. | Two installed macOS crashes reproduce it; controller/runtime survive, second crash has205 successful proxy samples. | Independent review complete. Corrected DMG native crash/reopen passed within1.45 seconds, same controller/runtime and32 successful forced proxy samples (checkpoint62/macos-crash63). Actual close-button and other-platform current-package cases remain separate. |
| Package downgrade retains an obsolete fixture marker | Linux native test setup | Package management correctly preserves an unowned test marker; the installed 2.1.11 JAR disagreed with the retained 2.3.1 marker. The harness correctly rejected this before any update request. | `test_same_source_recovery_rejects_stale_marker_version_before_owner_or_update_mutation` uses a real miniature JAR and checks rejection before process execution; matching metadata must reach package-ownership admission. Routine release hygiene runs the suite. | checkpoint56 native harness rejection; checkpoint58/linux-harness-green.log. The guard already worked, so this is added prevention coverage, not a claimed implementation RED/fix. | Base package and exact immutable marker identity verified; old marker preserved. Current same-source DEB recovery passed; root reviewed checkpoint60/linux-review exact receipt correlation. | Before a fixture rerun, verify installed bytes against the frozen base, preserve the previous marker and atomically install the exact frozen marker root-owned and non-writable. Never rewrite metadata merely to make arbitrary bytes pass. |
| Java version stderr mistaken for probe failure | Windows test setup | An ad-hoc PowerShell probe used Stop error policy with merged native stderr; Java normally writes version output to stderr while exiting zero. Extraction succeeded. | Existing `require_jdk17` checks exit status and both streams; `test_java26_is_rejected_and_jdk17_is_accepted` explicitly accepts stderr-only Java17. Routine fixture-environment suite covers it. | checkpoint56/windows-tools-stage.md and fixture-environment-green.log; no product implementation change. | Ordinary-user Java17, pinned .NET and WiX versions verified. | Use the existing Python build preflight; avoid the ad-hoc PowerShell probe. A real Python interpreter remains a guest prerequisite. |
| macOS fixture black screen with corrupt APFS metadata | Disposable guest disk | Read-only fsck reports zeroed object-map blocks and unreadable container keybag; original and recovery boot fail while identical clean-base configuration boots. Underlying corruption cause remains unknown. | No product fix or causal quick regression is claimed. Preserve disk-level reproduction; automated stopped-disk health admission remains a prevention gap. | checkpoint53/mac-boot-repair/fsck-repair-copy.log: standard repair on separate copy exits8; recovery-result.json records preserved backups and working replacement. | Replacement shows Finder and executes sw_vers15.7.7; original firmware restored, original disk preserved. | Original installer outcomes remain unresolved. Replacement is environment recovery, not installed-product acceptance. |
| Windows stop-routing tests reach POSIX-only reservation lock | Test isolation | Two existing command-routing tests did not mock reservation release; full suite with fcntl unavailable reproduces both errors. | Routine test_visual_platform.py now isolates release in those two tests while reservation tests retain their own assertions. | checkpoint53/vm-resource-admission/windows-fcntl-none-pre-fix-red.log:77 tests,2 errors; post-fix-green.log:77 passing; normal focused86 passing. | Windows workflow34820110453 failed; next exact-SHA workflow required. | Do not weaken actual admission or skip the command-routing tests. |
| Frontend JVM remains alive after Compose and teardown return | Product frontend lifecycle | Local software-renderer reproduction records `finallyExists=true`, `phase=returned` and non-daemon AWT threads. This contradicts the initial startup-race hypothesis. | `DesktopComposeApplicationExitTest` uses the real frontend process boundary with software rendering; teardown precedes explicit frontend-only JVM exit. Routine desktop tests also cover normal and dual-failure ordering. | checkpoint53/compose-exit-diagnostic-software-red.xml:1 causal failure; compose-exit-process-green.xml:3 passing,0 skips. | macOS workflow34817990475 failed the original exit test; exact fixed-SHA CI and installed-package lifecycle remain required. | This fixes process liveness after cleanup, not the separate macOS VM boot problem. |
| Concurrent test guests exhaust host RAM | Fixture resource admission | User reported RAM exhaustion; existing visual startup had no aggregate allocation/admission check and launched despite a low-memory snapshot. | `test_fixture_environment.py` and `test_visual_platform.py` cover capacity, reservations, native formats, low-memory no-launch and uncertain post-spawn recording; both are routine checks. | checkpoint53/vm-resource-admission/pre-fix-red.log and root-green.log;86 focused tests pass. | Current host read-only snapshot records24GiB, normal exported pressure bit1 and one4GiB local guest reservation. No OOM was deliberately induced. | Guard covers visual-platform-managed starts and discovered Tart guests. Direct shell/remote launchers still rely on coordinator capacity checks; do not claim global admission coverage. |
| Missing `objcopy` during Fedora fixture packaging | Linux immutable update fixture | `jlink` needs `objcopy`; the guest lacked binutils. This was not OOM or disk exhaustion. | `test_missing_objcopy_fails_before_creating_build_output` in `scripts/test_desktop_update_fixture.py`; the fixture suite runs it routinely. | `checkpoint51/objcopy-red.log`; `checkpoint51/objcopy-green2.log` records the fixture-suite pass. | Fedora replay after installing only binutils was live when documented. | Do not treat the live build as package/replacement acceptance; the dirty fix was not yet delivered when recorded. |
| Missing DEB/RPM tools during Fedora fixture packaging | Linux immutable update fixture | jpackage rejected DEB after compilation; dpkg-deb, fakeroot and rpmbuild were absent. | `test_missing_package_tools_fail_before_creating_build_output` rejects each missing tool before stages/builds; Arch remains exempt from DEB/RPM dependencies. Existing routine fixture suite includes it. | `checkpoint51/package-tools-red.log` has three causal failures; `package-tools-green.log` records the passing suite. | retry3 terminal failure retained; guest prerequisites installed before a new immutable retry4. | New packages and public recovery still require native proof. |
| Fedora selects DEB when dpkg is installed for building | Product update selection | `linuxPackagePreference` uses dpkg availability before recognizing Fedora; protected native request confirms DEB and absent apt-get stops preparation. | Public check/download regression `fedoraUpdateCheckSelectsRpmEvenWhenBuildPrerequisiteDpkgIsPresent` in `DesktopLinuxUpdateServiceTest`; routine desktop tests. | checkpoint51/fedora-package-selection-red2.log and XML: expected RPM, got DEB; green2.log records all11 passing after repair; native summary in fedora-package-selection-native.json. | Exact fixed-source RPM package/recovery pending. | Initial red attempt was a seam compile error; only red2 is causal evidence. |
| Windows shell safety tests fail before fake ADB | Test infrastructure | New executable capture tests fail on Windows before expected fake-ADB output; the correction explicitly selects Git Bash, uses a repository-relative wrapper path and writes fake executables with LF endings. | Existing executable safety tests retained, with byte-level LF assertions and launch diagnostics; all66 pass locally. | checkpoint51/ci98-windows-failed.log; Windows run34805892548 failed. | Exact next-SHA Windows workflow required. | Do not skip the safety requirement to obtain green CI. |
| Windows Python CRLF contaminates capture serial | Cross-platform capture infrastructure | Bash `read` retained the CR from native Python output, producing `emulator-5600\r`; exact Windows CI log proves the split fake-ADB argument. | `test_android_capture_handles_native_python_crlf_before_any_device_mutation` reproduces native output on every host; routine visual tests. | checkpoint51/visual-python-crlf-red.log: one causal failure; visual-python-crlf-green.log:67 passing after CR normalization. | Next exact-SHA Windows CI required; ff8de90 run34807483393 retained. | First portability correction removed shell/path failures but exposed this distinct line-ending failure. |
| Windows Python CRLF contaminates scene/Gradle/stamp arguments | Capture infrastructure | Unnormalized post-guard Python line producers retain CR in native scene match and Gradle/stamp IDs. | `test_android_capture_removes_native_python_crlf_from_scene_arguments_after_device_guard` runs the real wrapper/selector in an isolated miniature fixture, asserting exact arguments; routine visual suite. | Original pre-fix RED in worker tool history; checkpoint51/visual-scene-crlf-prechange-replay.log independently reproduces against exact3d70d75 wrapper; visual-all-crlf-green2.log:69pass. | Next exact-SHA Windows CI remains required. | Only known text producers normalized; binary ADB framebuffer stays untouched. |
| First-boot Android SystemUI clips status bar | Visual fixture lifecycle | API35 Pixel6 cutout/clock layout128px but WMS surface63px; same-scene framebuffer proves clipping. Normal owned-emulator reboot restored128px without profile changes. | `test_android_visual_geometry.py` primary-display parser and capture guard; routine hygiene. | checkpoint51/android-visual-geometry-red.log and android-statusbar-reboot-20260914T045131Z/comparison.txt. | Six scenes require fresh capture/review after reboot. | No alternative device profile or product-style workaround; only dedicated task AVD rebooted. |
| SystemUI ANR overlay accepted as a visual capture | Native visual infrastructure | Boot-time KeyguardService ANR under CPU contention left a primary SystemUI alert covering the dialog; geometry was healthy and instrumentation still succeeded. | Debug-only AndroidVisualWindowGuardTest rejects primary ANR before screenshot, preserves raw WindowManager dump; ordinary/secondary windows covered. | checkpoint51/android-anr-guard-red.log:3tests1 causal failure before repair; android-anr-guard-green.log passes all3 plus instrumentation compilation. | Failed six-scene capture android-installer-3d70d75 retained; normal Wait cleared alert; guarded recapture pending. | Never approve baselines from a successful instrumentation exit alone. |
| Installer abort after uncertain external commit | Shared installer handoff | Initial handoff automatically cancelled when commit acknowledgement or exit request failed, even after worker-visible commit. | Three `DesktopInstallHandoffTest` causal regressions; desktop suite. | checkpoint51/install-commit-boundary-red.log:17 tests,3 failures; install-commit-boundary-green2.log:17 passing,0skips after repair. | Observed macOS async cancellation motivates review, but its exact cause remains unproven. | Preserve explicit public cancellation; suppress only implicit failure/close cancellation after the external boundary. |
| Diagnostics export used a default owner instead of the temporary endpoint | Desktop diagnostics fixture | Normal commands used the fixture endpoint while direct export read host-default owner metadata. | Existing diagnostics regression now binds export and rejects fallback startup; included in integrated diagnostics/frontend checks. | `checkpoint48/diagnostics-prepush-failure.xml` and `diagnostics-reproduce.log`; `checkpoint48/prepush-green-result.json`. | No host workspace or product export behavior was changed. | Keep a native packaged export scenario distinct from fixture isolation. |
| Compose process exit bypassed frontend cleanup | Desktop frontend lifecycle | Compose default exit bypassed Main's `finally`, leaving endpoint/detach cleanup incomplete. | The real windowless child regression is recorded as `checkpoint49/compose-exit-causal-red.xml`; the green subprocess coverage needs its exact test filename verified before it is named here. | Causal RED above; focused GREEN is `checkpoint49/frontend-bootstrap-green.log`. | `checkpoint50/Linux` proves exact `bbb` RPM close/immediate GUI reopen in 1.3435 seconds with stable runtime and token traffic. | This closes normal-close recovery on that package only; current-source base-to-target recovery and crash reopen remain open. |
| Windows original-user helper naming mismatch | Windows installer fixture | Invocation expected `OriginalUserLaunchProbe.dll` while the generated assembly was named `vpn-control-install-helper`. | Generated-project identity/path comparison before the Windows-only probe; routine cross-host fixture coverage. | Old local mismatch RED and fixed fixture GREEN are recorded under checkpoint42. | Checkpoint49 bootstrap component ran three real native tests with zero skips/failures; it remains ARM64/x64-emulation component evidence. | Checkpoint50 `fc82` passed all five required workflows. Full adapter/MSI replacement, grant/denial, recovery, and native AMD64 acceptance remain open. |
| macOS terminal failure replaced by `CANCELLED` during cleanup | macOS installer handoff | Cancellation cleanup could overwrite the authoritative primary failure. | macOS failure-result/session-handoff regression preserves primary terminal metadata. | Causal RED and focused GREEN under `checkpoint42`. | No new native macOS acceptance was claimed. | Physical identity, manifest, failed-cleanup admission, replacement, and rollback still need native proof. |
| Linux terminal PTY closes with `EIO` after final output | Linux public-install observer | POSIX PTY closure can report `EIO` after the final receipt; replaying the action would be unsafe. | `test_terminal_observer_drains_final_output_then_records_known_exit_after_pty_eio` in `scripts/test_linux_public_install_harness.py`. | The test is the causal quick regression; WIP does not cite a current separate RED/GREEN receipt for this row. | This is observer behavior, not installer success. | The macOS copyfile EIO case is distinct; see its own row below, not this Linux PTY observer. |
| Android large routing document/cold owner loss | Android public CLI and storage | Large persisted routing content must survive app-only process reclamation on a 48 MiB heap. | `scripts/test_android_routing_evidence.py` validates unambiguous final routing envelopes; Android storage/memory tests cover the application-controlled path. | Current API29 receipt `checkpoint51/android-api29-current-20260914T0559Z/receipt.json` records public import/read/cold-read success. | API29 target2.3.12 read back all 56,000 domains after `am kill`; no VPN was started. | Same/new-request no-op, retained result, and export were not exercised by that import/read slice. Keep action, cancellation, consent, and resource-failure cases open. |
| Cold export OOM and lost acknowledgement | Desktop large export | Cold owner/resource pressure and acknowledgement loss could misstate export completion. | Exact test filename is not verified in this ledger; retain the named exported regression only after tracing it from the current source. | `checkpoint40/export-{ack,cold}-red`; `checkpoint40/export-green9.log` records selected export checks. | This is cold-owner CLI evidence, not Android package evidence. | Do not infer a current full resource matrix or export coverage count from the historical checkpoint. |
| CUSTOM wrapper and ordinary raw-URL precedence | Android profile readiness | An invented top-level-remarks CUSTOM payload was invalid; ordinary profiles carrying stored JSON plus raw URL incorrectly became pending restart. | Exact test filename is unverified here. | `checkpoint45/android-custom-red.log`, `android-ordinary-red.log`, and `android-final-focused-green.log`. | Current fixture accepted the corrected CUSTOM wrapper; plain off/cleanup succeeded. | The record does not certify tunnel traffic, cancellation, or all current-source native readiness. |
| Relay lifetime and DNS fixture assumptions | Android benchmark/cancellation fixture | A short-lived relay and obsolete direct-DNS assertion caused fixture failure before a cancellable candidate request existed. | Four routine regressions cover relay liveness, readiness, cross-process access, and forwarding; exact filenames are unverified in this ledger. | Checkpoint49 records the causal fixture correction; later API35 relay setup still rejected Android DNS before cancellation observation. | Benchmark traffic and cancellation remain separate; no active-runtime replacement recovery is proven. | A secure rejection caused by fixture prerequisites is expected and is not a product traffic defect. |
| Native fixture admission falsely attributed to external state | Android/Windows fixture work | Several historical observations were setup or attribution errors, including a current-vs-legacy CA-hash mismatch and mixed listeners. | Fixture preflight/trust and transport tests are the prevention layer; use their named focused suites, not an inferred product test. | WIP explicitly says the earlier API35 failure is unexplained and not to invent a cause. | Temporary CA/proxy/reverse resources were cleaned in the recorded Android runs. | A fixture rejection is expected when trust/identity preconditions fail; it is not proof of a product networking defect. |
| Agent execution mistake: unintended Android inventory force-stop | Agent-operated API35 fixture | An inventory action used force-stop against an emulator outside the safe runtime procedure. | No quick code regression is recorded; the prevention is the documented ownership/safety gate and incident retention. | `checkpoint43/android-inventory/force-stop-incident.txt`. | The user was informed; this does not provide product evidence. | Add a deterministic harness/command-admission regression if this operation is automated again. |
| Linux GUI evidence admitted a foreign/stale window risk | Linux GUI fixture | Duplicated X11 regex missed an owned window; an empty baseline option also caused argparse failure. | Linux GUI guard boundary tests cover process-stat parsing, PID reuse, dead frontends, X11 query failures, and failure receipts; routine release hygiene invokes them. | WIP records the causal guard work and subsequent guarded renderer launch. | Renderer crash in `libX11 XVisualIDFromVisual` remains separate. | Guard GREEN does not prove attach/hide/show/close/crash lifecycle or fix the rendering defect. |
| Resource limits and environment capacity | Android, Linux, macOS fixtures | 48 MiB Android memory, stale 2 GiB Linux guest OOM, and disposable guest storage are distinct constraints. | Android component memory regressions and fixture preflights exist, but their native coverage differs by scenario. | WIP records causal Android OOM work and the stale Linux guest OOM; it warns not to relax limits. | Current API29 receipt confirms 48 MiB for cold routing readback only. | Resource-gap closure still needs the specified native persistence/resource failures; never convert a capacity shortfall into a passing product result. |
| Transient pre-push result-writer failure | Managed validation infrastructure | Cause is not established in the current WIP. | No proven quick regression or routine wiring may be claimed yet. | Historical result paths exist, but this ledger has no causal RED/GREEN pair. | None. | Preserve the raw failure and add a deterministic writer/atomic-result regression before calling it repaired. |
| macOS native bundle copy returns EIO before rename | Native installer persistence | Exact guest worker log records copyfile output EIO; the underlying I/O cause is unproven. | `test_copyfile_eio_at_production_staging_helper_preserves_terminal_failure_evidence` in `scripts/test_macos_install_enospc.py`; actual macOS package CI executes it before packaging, with explicit skips elsewhere. | `checkpoint51/macos-eio-mutation-red.log`: ignoring the production check fails the expected error assertion. `macos-eio-green.log`:6 tests pass. Earlier surrogate probe was invalid and is superseded. | Exact job2958cf24 retained its original app, protected FAILED/PERSISTENCE_FAILED receipt and partial stage; input cleanup preserved evidence. | Successful full replacement remains unproven; partial-stage disposal policy and underlying I/O cause still need resolution. |
| Failed immutable fixture deleted during manual retry | Agent execution mistake | A worker bypassed the existing-stage rejection and removed the failed pair directory. | Existing builder admission rejects stage reuse; no additional code regression can be claimed for the manual bypass. | Remaining outer logs record failure/rejection; the pair-contained log and stage were lost. | No package had been produced. New retry3 uses a unique path and the same verified runtime/source. | Never chmod/delete frozen inputs to bypass admission. Use a new path, or a supported verified recovery/disposal operation; retain exact deletion/evidence-loss records. |

## Per-user Windows native image admission — checkpoint93

The public Windows attempt stayed unknown before worker readiness. Read-only
checkpoint92/windows/image-acl.json shows its actual helper and ancestry are
original-user-owned under AppData. JVM packaged-helper admission permits that
exact owner, but native ImageObjectPin used machine-only trust while relaunching
itself. Identical NativeAOT bytes pass protected ProgramData bootstrap and fail
from an isolated per-user layout with Installer mutation rights rejected. This
establishes the self-pin defect; it does not authoritatively resolve the original
unknown installer job, which is preserved.

`DesktopWindowsOriginalUserLaunchTest` now stages its apphost with a private
current-user ACL and calls the actual self-pin before the interactive-only test
gate. The fixture checks matching image identity and rejects an unrelated
canonical principal without launching any installer or requiring a desktop shell.
It runs in the ordinary Windows desktop suite. The exact new fixture compiled as
NativeAOT fails against unchanged product code at checkpoint93/windows/red-result.json
(exit91, image93f8aba901c4a1667999cd1fbd44983e767549c5a1b5720367e062eec71cd2d8).
After the fix green-result.json returns0/ORIGINAL_USER_IMAGE_PIN_OK with image
6a87706ee226b4181dce9403b8fc4ef29afa0b0e280a184ac47fd1e330b4b523.
Both frozen input manifests and staged ACLs are retained in that directory.

The self-pin retains the canonical SID captured from the OS original interactive
token, already checked against the authenticated owner by the coordinator. Every
ancestry/image inspection uses that same principal; file-object comparison,
retained no-write/no-delete handles, fixed helper image and child SID/session/
non-elevation checks remain. Machine receipt authority is unchanged. Independent
review found no blocking defect. Host focused checks pass17 executed tests with7
Windows-only skips. Rebuilt installed-package MSI replacement/recovery and
post-fix elevated/different-approver scenarios remain required.

## Native probe preparation and prompt guards — checkpoint91

The ignored Windows NativeAOT bootstrap probe omitted the production project's
ApplicationManifest and failed with CS1926 before any helper execution. The new
`native_install_helper_fixture_inputs` reads literal manifest/source declarations
and requires project, SDK and build properties before staging. Routine
`scripts/test_windows_native_fixture.py` covers the current project, renamed or
missing manifest, repository escape and unsupported expressions. The old staging
inventory fails checkpoint91/windows/input-red.log; input-green.log runs11 tests
with4 Windows-only skips. The replacement frozen native bundle includes all
inputs and builds successfully (build-complete-progress.json); ordinary and
same-user elevated bootstrap runs pass. This is ignored probe preparation
coverage, not a production package-builder repair or MSI installation proof.

The Linux prompt guard previously considered prompt text sufficient to send an
automated response. Polkit's text listener prints the prompt before TCSAFLUSH
disables echo. A private-PTY deterministic test now reproduces the interval and
requires `terminal_password_input_ready` before writing; closed descriptors fail
closed and polling must continue even without new output. Routine release hygiene
already executes `scripts/test_linux_public_install_harness.py`.
Checkpoint91/linux-analysis/prompt-ready-red.log replays the text-only policy;
prompt-ready-green.log passes19 tests. The isolated packaged Java authorization
probe using this guard passes with child/owner exit0 and no retained probe
processes (java-auth-ready-receipt.json). The historical checkpoint85 PAM
conversation failure remains unexplained; this race is not asserted as its cause.
Independent checkpoint92 review reproduced a false rejection when ECHOE/ECHOK
remain set while ECHO/ECHONL are disabled. The guard now checks only effective
echo flags, and the same routine PTY test retains the inert flags and separately
rejects ECHONL. checkpoint92/linux-prompt/red.json and green.json preserve
failing/passing evidence. No credential is retained in terminal logs or regression inputs.

## Windows native capture regressions — checkpoints87/88

The checkpoint85 NativeAOT probe stopped before compilation when Windows
PowerShell5.1 promoted harmless dotnet stderr into a terminating error under
ErrorActionPreference=Stop and merged redirection. The independent ordinary-user
checkpoint87 baseline reproduced the warning and zero-byte log.

The first candidate lost exit23 after a WaitForExit/Refresh sequence. A second
candidate using Start-Process -Wait passed simple exit checks but retained the
build wrapper after native publication. The final helper uses a direct
Diagnostics.Process, concurrent bounded stream-to-file copies, the direct child's
exit code, and PowerShell's selected filesystem working directory.

The Windows-only routine test in scripts/test_windows_native_fixture.py covers:
native stderr with exit0 and exit23, spaces and an empty argument, 256KiB on both
pipes, a descendant waiting for a post-return acknowledgement, and selected
working-directory preservation. Native RED/GREEN records under checkpoint88/windows
include wait-red2.json / wait-green2.json and cwd-red.json / cwd-green.json.
The first descendant fixture itself retained pipes; wait-red.json / wait-green.json
are superseded and do not prove the fix. The corrected fixture uses a separately
launched descendant, so waiting for the whole tree creates the tested causal cycle.
The exact final routine test body passes in the ordinary-user AMD64 guest.
On macOS the module runs7 tests with4 explicit Windows skips; those skips are not
native evidence. Windows package hygiene already runs this module.

The corrected capture path also completed the current-source NativeAOT admission
probe with SDK10.0.400: helper validation, owner-input admission, package preflight
and child exit0. See checkpoint88/windows/native-summary.json and probe-progress.json.
The image SHA256 is
7e6eb6db8cd1b9ad4f933360067b3a60324026345b8f8320134a880b22ba5c8e.
This is component evidence, not successful MSI replacement or original-job recovery.
The older checkpoint87 wrapper6488 is preserved pending scoped fixture cleanup;
no installer/runtime process was terminated to obtain this result.

## Expected rejections and incomplete evidence

### Android cancellation fixture — checkpoint94

The native cancellation attempt ended before cancellation because the relay's
stall branch did not complete SOCKS CONNECT and returned after receiving one
byte. This is a fixture failure, not evidence of broken product cancellation.
The causal socket-pair regression first fails against the previous source, then
proves CONNECT acknowledgement, retention after initial TLS bytes, and cleanup
on peer disconnect. The corrected branch checks the destination allowlist and
drains bounded chunks without opening an upstream connection; its socket timeout
remains bounded. `scripts.test_android_benchmark_fixture` is already included in
routine release hygiene. Checkpoint94/android-stall-fix/red.log and green.log
retain RED/GREEN evidence (six focused tests pass). Native cancellation must still
be repeated with the corrected fixture.

Checkpoint94 cleanup also reused numeric positions from before benchmark sorting
and list changes, deleting a prior task fixture. List and mutation resolution use
the same current one-based GUI ordering; stale positions do not identify stable
locations. This is fixture misuse. Preserve opening records and clean up only
created identities in their original source scope; never reuse numeric positions
across operations. Recovery and the original native receipts remain tracked in
checkpoint94/android until the opening fixture is restored and verified.

An unavailable or unsupported response, a missing build prerequisite, a rejected
unsafe fixture, and a deliberately denied installer action can be correct behavior.
Record them with their preconditions and do not count them as a defect fix. Likewise,
component, compile-only, older-source, mounted-image, or skipped-test evidence does
not close a current packaged native gate. The current WIP remains the owner and
delivery ledger; this file only maps documented failure modes to prevention evidence.


### Provider timing and TLS forwarding fixtures — checkpoints95–96

The Android document wrapper used eight separate `content` processes, each about
1.2 seconds on the owned API35 emulator. A persistent ADB shell did not remove
that guest process cost. The bounded legacy public-provider fixture exposes its
response before cleanup and retains request/controller/transfer identities after
uncertain writes. Its routine suite checks accepted-result/cancel sequencing,
strict input/result JSON, public UID attestation, bounded ADB calls and exact
cleanup acknowledgement. These deterministic checks do not promise a wall-clock
cancellation window or certify the default CLI document transport. CP96 failed
without an observed relay connection; cancellation is still unproven. Native
fixture setup must verify the actual endpoint, not infer reachability from a
READY file or an unrelated ADB reverse mapping.

The macOS scheduled refresh used the active proxy correctly, but the fixed-HTTP
SOCKS fixture responded to TLS with plaintext. The opt-in forwarding fixture now
admits only its exact loopback destination and preserves bytes in both directions.
Review exposed partial-write/backpressure, already-drained EOF, and failed-connect
socket cleanup defects. Causal tests reproduced the EOF timeout and leaked socket
before repair, then verified bounded queued bytes and full transfer under a slow
receiver. All14 fixture tests pass and remain in routine release hygiene. The
native rerun must use the permitted HTTPS endpoint for both subscription refresh
and traffic sampling; fixed-HTTP or arbitrary-target probes are not substitutes.

### Scheduled operation visibility — checkpoint96

The installed macOS scenario completed automatic subscription refresh and retained
the runtime, but source review found the scheduler invoked its refresh callback
directly under the mutation lock, bypassing DesktopOperationRunner. Consequently
the operation list could not represent this long work or its cancellation/result.
This is a product gap under CLI-003/005, independent of fixture TLS corrections.
The focused session regression first failed because the operation list was empty.
The fix tracks scheduled work and preserves typed refresh/Find Best outcomes.
Further causal tests exposed raw unknown outcomes flattened to REFRESH_FAILED in
both manual and scheduled refresh. They now retain OUTCOME_UNKNOWN/exit2.
Structured post-refresh unknowns stay nonterminal and retain committed source data;
post-refresh cancellation also retains that data after cleanup. Seventy focused
tests pass without skips (checkpoint98/refresh-final-focused-xml); rebuilt native
operation-history evidence remains required.

The combined HTTPS subscription/relay runner derives its published source URL,
subscription profile and relay target from actual bound listeners. Its routine
test fetches the advertised source using certificate-verified TLS through a SOCKS
domain request, preventing a passing IPv4-only probe from masking a hostname
mismatch. Review also corrected the profile scheme to the product-supported
socks scheme, retained loopback-only binding, and bounded handshake/HTTP waits.
Four focused tests pass, including idle TLS cleanup and no-overwrite readiness.
The CP96 native receipt still applies to its original fixture; this reusable
runner has component evidence until used in the next native scenario.

CP97 probe review separated the loopback relay port from the SOCKS destination
port, and the routine benchmark fixture suite now verifies chatgpt.com:443 framing
while connecting to a different relay port. It also exercises the actual relay
Popen context across preflight and delayed traffic. A separate short-lived shell
launch had lost its relay between preflight and work; its cause was not established.
CP98 used the persistent context and achieved native accepted/stalled/cancel/wait
CANCELLED with exact cleanup. Ten routine tests pass; raw evidence remains under
checkpoint97/android-endpoint-preflight and checkpoint98/android-cancel.


### Interrupted Android fixture observer — checkpoint99

An inline multi-read preflight crossed the outer tool observation window before
returning a live session handle. The read-only sequence did not change settings
or runtime, but its opaque transfer IDs were not surfaced for exact cleanup.
Original input and RED outputs exist only in task-tool history; the evidence
boundary is recorded in checkpoint99/android-public-control-orchestration/receipt.md.
The fixture now offers a durable opaque-identity retainer before provider write.
Routine test_android_public_control_fixture.py verifies a real child survives an
observer timeout, keeps a readable identity, and completes/cleans without replay.
Further causal tests reject zero-progress ledger writes and complete partial
writes before provider mutation. File sync is universal; directory sync is POSIX
only, with no Windows directory power-loss guarantee. Seventeen tests pass.
This tests fixture child/ledger behavior, not the outer agent-tool implementation.
Native runners must use a short initial yield, retain the live session, and poll
that same session. The API35 SSH scenario remains unexecuted; root stopped the
positively identified idle5596 emulator to restore local memory headroom.

### Scheduled-refresh traffic observation — checkpoints99–101

CP99c refreshed through the installed macOS launcher and retained its runtime,
but a wrong configuration-path search and a non-executable shell sampler left
traffic continuity unproved. Its generic shell result is not acceptance evidence.
The reusable desktop_scheduled_refresh_fixture.py observer reads the exact named
mixed inbound, invokes curl directly, rejects unavailable executables before CLI
reads, and preserves timeout output. It pins controller/runtime identity and
requires a fresh scheduled operation plus HTTP evidence bracketed by traffic.
The operation's terminal code is recorded separately: RUNTIME_FAILED can coexist
with passing traffic samples, but cannot prove successful Find Best.

Review also found that successful edge samples could mask intervening failures,
and that a wait response was not checked against the selected operation ID.
Root reran the full observer with exactly these two fixes reversed and reproduced
both false-positive failures (root-reconstructed-red.log). This is a reconstructed
pre-fix run, not a retained historical snapshot. Eight fixed-observer tests and
release hygiene pass. The
routine suite is scripts/test_desktop_scheduled_refresh_fixture.py, included in
release hygiene. Evidence lives in checkpoint100/scheduled-harness; prose case
lists are design notes, not failing test output. Sampling intervals and gaps must
remain visible; successful samples cannot prove the absence of shorter outages.
The corrected installed-package native run remains required.

Windows package CI for6298ec2 exposed a fixture-test portability failure: Windows
does not enforce POSIX executable mode bits, so a plain temporary file passed
os.access(X_OK) and the test reached the unrelated missing-config check. The raw
failure is checkpoint100/windows-ci-failure.log, run35555037549. The POSIX mode
test remains enabled on Unix and explicitly skipped on Windows; a missing-curl
test verifies fail-before-CLI behavior on every platform. Nine tests pass locally.
This changes test applicability, not product authorization or executable admission.
The Windows suite and next exact-SHA CI remain required.

### Stale Windows credential prompt — checkpoints100–102

CP100 captured UAC at05:37:17, retained a not-started marker at05:39:18, and
sent credential keystrokes at05:40:37. The native result is CANCELLED, not
successful authorization. The old ignored CP95 login.py sent input without a
freshness check. windows_prompt_observation.py now guards an injected action with
a maximum15-second reviewed observation, matching current screenshot hash,
environment and operation identity, and a nonterminal state. It contains no
credentials or UI recognition. Nine pure tests cover the decision boundaries;
the historical unconditional callback is explicitly reconstructed, not claimed
as a replay of Windows or the original full helper. Routine release hygiene runs
test_windows_prompt_observation.py. CP102 rejected a changed frame before input,
then admitted one input at8.664seconds after a new review; its installer outcome
must still be read separately. Evidence remains in checkpoint102/windows.

### Fixture certificate serial output — checkpoint102

The checkpoint101 OpenSSL fixture signing command created a serial file in the
repository working directory. The original bytes and hash were preserved before
removing that exact untracked artifact. `sign_fixture_leaf_certificate` now takes
an explicit private serial path and the routine Android trust fixture uses it.
The real OpenSSL regression signs with a dotted relative CA filename from another
working directory: omitting `-CAserial` recreates the unwanted `.srl`; the corrected
helper leaves it absent. Twelve tests pass in `test_android_fixture_trust.py`,
already included in release hygiene. Evidence: checkpoint102/certificate-scope.
This is fixture coverage, not proof of native update installation.

### Missing asynchronous install acknowledgement — checkpoint102

The macOS rollback harness polled protected WAITING_FOR_EXIT directly after an
initial public response with `handoffReady:false`. It omitted the later public
operation/update status acknowledgement required to release the owner exit gate.
Public quit correctly returned BUSY while installation was pending. Source review
and the existing exact-correlation exit tests establish the missing fixture step;
no product exit defect is established. The explicit ordering regression in
DesktopOwnerExitGateTest passes (ten tests, zero skips). Same-job public operation
status subsequently returned handoffReady and released the original owner. A
second fixture lock delayed replacement; final inspection found only the watcher
alive, with the coordinator absent and a stale nonterminal receipt. No rollback
acceptance or coordinator exit cause is established. The exact candidate flag
was cleared after identity verification; all pending inputs remain preserved.
A durable fixture driver now tracks one lock and this acknowledgement sequence;
its ten quick tests pass and run in release hygiene. Its native rollback result
is still pending. Never replace acknowledgement with a kill or a
second installation against the pending target.


### Remote stdin staging traversed the wrong source root — checkpoint106

The ignored Windows staging script was sent to Arch as `python3 -` but derived
its source directory from `__file__`. That names `<stdin>` remotely; recursive
input discovery therefore read the remote working tree instead of the frozen
local fixture. The client held QGA while its RSS grew to approximately5GiB.
The exact PID/start-time/socket were revalidated before terminating only this
owned client. QGA accepts connections again; no native fixture, product operation
or installer ran. The original script is retained under checkpoint103. The new
`native_fixture_payload.py` generator embeds explicitly enumerated, hash-validated
local bytes in a standalone remote receiver. Its quick test executes that receiver
via stdin from a foreign directory through fake QGA and verifies all26 writes.
PowerShell literals are separately escaped and parent creation is batched before
file writes. The suite passes and runs in release hygiene. Real guest staging and
Windows native admission remain separate checks.


### Evidence manifest included itself — checkpoint103

Shell redirection created the checksum output before recursive input enumeration,
so the fixture manifest included itself and a temporary output. Root rejected the
bundle before transfer. `native_fixture_manifest.py` now explicitly excludes the
output on first generation and regeneration, hashes bounded chunks, and verifies
recorded entries. `test_native_fixture_manifest.py` covers stale self-inclusion,
changed input, newline/Windows path syntax and linked input/output rejection.
The suite passes and is included in release hygiene. The originally invalid
manifest was overwritten during correction, so no retained exact-byte historical
RED is claimed; the causal self-inclusion regression is reconstructed.


### Copied update server omitted sibling modules — checkpoint105

The private macOS server failed before readiness with `ModuleNotFoundError:
fixture_environment` because only its entrypoint had been copied. The error is
retained in checkpoint105/macos/initial-server-dependency-error.txt. The new
`stage-entrypoint` command copies its three required modules and imports the
actual staged entrypoint from a foreign directory in isolated Python. The causal
incomplete-stage test and complete-stage test run in the existing routine
`test_desktop_update_fixture.py` suite (50 tests). No server or installer runs
in those tests. RED/GREEN evidence is in checkpoint106/fixture-dependencies.


### Installer observer accepted cancellation without target proof — checkpoint106

Source review found the Android lifecycle driver returned after recording status
and wait, even when the recorded terminal was CANCELLED. The worker reproduced
that behavior before editing; its RED is retained only in task tool output, not
a filesystem evidence file. The driver now has explicit installed/cancelled
expectations. Installed acceptance requires exact operation, final OK/installed,
and the target version/code/APK hash; cancelled acceptance requires exact final
cancellation. Capture mode explicitly marks itself nonacceptance. The17-test
`test_android_installer_lifecycle.py` suite covers cancellation mistaken for
success, unknown/wrong operation, wrong package/hash, version-prefix collisions
and envelope polarity. It already runs in release hygiene. Native process-loss
recovery and current API29/API35 success remain open.


### Unix QGA fixture used a Windows temporary path — checkpoint109

Windows package CI35560957259 for027fcc6 failed in the new fixture test because
its `C:\...` temporary socket path violated the receiver's intentional Arch/Unix
endpoint requirement. The raw error is checkpoint109-windows-ci.log, lines216–225.
The corrected test retains generated bytes/hashes, syntax and PowerShell quoting
on every platform using a synthetic POSIX endpoint, and explicitly skips only
the real Unix-socket transport roundtrip on Windows. Linux and macOS still run
that roundtrip through stdin from a foreign directory. Production transport
validation is unchanged; Windows-native test execution and corrected CI are
required before declaring the checkpoint verified.

### QGA observer waited for a nonexistent greeting — checkpoint106

An ignored capacity probe treated QGA like QMP and waited for a greeting before
sending a request. Its8/25-second observations therefore did not establish guest
unresponsiveness. A request-first guest-sync probe and the exact read-only query
then succeeded. The existing routine native-payload fake-QGA roundtrip deliberately
sends no greeting and responds only after a request; retain this distinction in
future observers. Evidence: checkpoint106/capacity/qga-protocol-correction.json.
The old Windows owner remains live with no protected terminal receipt, so the VM
and its unknown installation remain preserved.


### Trusted PowerShell fixture blocked before compilation — checkpoint107

The first build command omitted a process-scoped execution-policy argument; the
owned Windows guest rejected the script before compilation (guest PID2684,
UnauthorizedAccess). The same frozen script with process-scoped Bypass completed
(PID1000, exit0). `trusted_powershell_file_arguments` in windows_native_fixture.py
now constructs discrete trusted-file arguments with that explicit process option,
without changing persisted policy. Its routine test preserves spaces, Unicode and
metacharacters as argument values and excludes persistent policy commands. The
host suite passes12 tests with4 Windows-native skips. This is fixture launch
coverage, not successful MSI replacement or original-user native admission.
