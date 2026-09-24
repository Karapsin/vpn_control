# Parity Failure-to-Regression Ledger

This ledger is a maintainer index for the failure records currently referenced by
`work-in-progress.md`. It applies `TEST-001`: a quick regression is evidence of a
specific cause only when the recorded RED precedes the repair and the GREEN is
wired into a routine suite. A secure rejection, explicit unsupported result, or
environment limitation is not a product defect unless the record says otherwise.

| Failure type | Product or fixture | Cause established so far | Proven quick test and routine wiring | RED / GREEN evidence | Native evidence | Unresolved gap |
| --- | --- | --- | --- | --- | --- | --- |
| Linux fixture account cannot prepare installer inputs; setup loses public-store environment or reads private metadata as previous user | Fixture provisioning | Root setup created target `.local` as root0755; effective UID1001 cannot create `.local/state`. Earlier setup also lost an environment variable through sudo and inspected a private file as the wrong actor. | `test_linux_public_install_fixture.py` exercises target-user directory creation, rejection without permission repair, sudo environment forwarding, metadata actor/identity, path guards and CLI parsing; wired into release hygiene. | checkpoint138/linux-fixture retains deterministic replays of the unsafe privilege-boundary recipes and focused GREEN before native fixture repair. Missing-module RED is explicitly excluded as noncausal. | checkpoint137/linux-install: original public failure, ownership and effective-access proof; no authorization prompt. | Native repair/retry and full prepush remain pending; these tests do not certify RPM replacement. |
| Refresh status labels retain URL userinfo; stale and post-commit failures receive misleading reasons | Product defects caught during review | Authority-based source labels retained credentials; raw stale route exceptions became OTHER; a broad commit-stage flag remained set after a successful commit. | AndroidSubscriptionRefreshControlTest exercises the production status helper, prepared fetch failure and failed post-commit snapshot in the routine Android suite. | checkpoint137/refresh-failures/review-red.log/xml: three compiled assertion failures before repair; green.log: affected Android/shared/desktop union succeeds. | No native claim for these review findings. | New APK/native refresh remains required; the original transport failure is still unexplained. |
| Desktop refresh persistence detail disagrees with outer control code | Product public adapter integration | Validated refresh data contained PERSISTENCE_FAILED but DesktopOperationRunner mapped the JSON response text to generic RUNTIME_FAILED. | DesktopHeadlessSessionTest.validatedRefreshPersistenceFailureMapsToOuterPersistenceCode submits the actual validated adapter response through the operation runner. | checkpoint137/refresh-failures/envelope-red.log/xml reproduces expected PERSISTENCE_FAILED versus actual RUNTIME_FAILED; final-green.log and retained XML pass the full affected desktop selection. | Discovered in integration review before native retry. | Verify mapped outer result while retaining cancellation/unknown precedence. |
| Refresh loses Android failure classification and persists desktop exception details | Product observability/privacy | Android per-source catch discards cause; desktop failed status stores native exception.message, which may contain endpoint secrets. The API29 native network failure itself remains unexplained. | AndroidSubscriptionRefreshControlTest.tlsFetchFailureUsesFixedSafeReasonWithoutLeakingEndpoint and DesktopSubscriptionServiceTest.refreshSubscriptionsDoesNotPersistTlsFailureDetails, routine Android/desktop unit suites. | checkpoint137/refresh-failures/red.log and retained XML: each test compiles and fails one causal assertion before production repair. green.log/final-green.log and final-green-results:80 focused tests pass with no skips. | checkpoint136/android29-refresh-plan retains failed native lifecycle and read-only TLS/route diagnosis; no replay. | Implement safe shared classification, localized rendering and legacy-status redaction; verify GREEN and repeat on a newly frozen APK. |
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
| IPv6-first localhost fixture rejects ordinary JVM subscription client | Native HTTPS fixture | Python selected IPv6-only listener while installed JVM17 resolved IPv4 first; manual refresh persisted Connection refused without HTTP request. | `test_ipv6_first_resolver_still_serves_ipv4_clients_and_socks_forwarding` plus forward-resolution fallback/rejection test; existing routine fixture suites execute both. | checkpoint135/linux-localhost/regression-red.log: connection refused; regression-green.log: five passing; socks-regressions-final.log: sixteen passing; bundled-jvm-diagnostic.log pins actual installed JVM. | Corrected CP135 manual HTTPS refresh and VPN startup pass; scheduled-refresh traffic evidence remains pending. | No product URL/TLS validation is relaxed; all resolved forwarding addresses must remain loopback. |
| Generated routing export timestamp compared as persisted content | Native evidence harness | CP134 negative transfer checks left revision3 and all routing content unchanged; full object equality failed only on `exported_at`. | `test_android_routing_evidence.py` compares complete documents excluding only generated time, rejects incomplete evidence, and detects changed rules/version/unknown fields; routine release hygiene runs it. | checkpoint134/android-document-negative/comparison-red.log: one causal failure; comparison-green.log: six passing. | Original failed assertion is retained; read-only postflight verifies all six provider rejections, unchanged content/revision and runtime OFF. | This is a harness comparison defect, not a product persistence defect; raw export-byte checks remain separate. |
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

## Windows fixture QMP admission — checkpoint121

The ignored login bridge sent keys without QMP capability negotiation and ignored
error replies, then incorrectly printed an input-sent marker. No authentication
event or user session followed. The bridge now uses the existing repository
`capture_visual_windows_qemu.QmpClient` and completes negotiation before reading
its guest-private credential. This is fixture transport repair, not a product
login or installer change.

The new `test_capture_visual_windows_qemu.py` drives that actual client against a
bounded Unix-socket server, checking capabilities before keys, interleaved events,
and rejected-command propagation. Root replayed separate removed-handshake and
ignored-error mutations: each relevant test fails; both tests pass with the real
unchanged client. Logs: checkpoint121/windows-qmp/{handshake-red,error-red,green}.log.
Release hygiene runs the test. After transport repair the guest displayed a real
incorrect-credentials message; credential validity versus keyboard delivery is
still being distinguished. No successful login or MSI update is claimed yet.

## Linux retained PTY master — checkpoint121

A credential-free CP120 guest probe established that reopening a PTY master via
`/proc/self/fd/<master>` allocated a different PTY. Its marker never reached the
original slave. Therefore the earlier external password write could not reach the
polkit prompt; this is a fixture delivery failure, not evidence of an invalid
password or a product installer defect. The old public job was authoritatively
cancelled before a new attempt.

`test_reopening_proc_master_creates_distinct_pty_but_retained_fd_delivers` uses a
raw slave and bounded observation, rejecting reopened-master delivery and proving
delivery through the original descriptor. Root ran a causal mutation of the new
write helper in CP120: the original-slave readiness assertion failed, then the
unmodified full harness passed20 tests with no skips. Evidence is
`checkpoint121/linux/guest-suite.log`; frozen guest inputs/logs are under
`/tmp/vpn-pty-regression121.2bnrl66t`. Existing release hygiene runs the harness;
Linux executes the procfs case, while other hosts explicitly skip it.

The first retained-master driver retry exited INTERACTION_REQUIRED before any
operation was admitted: passing slave descriptors did not establish a controlling
terminal for `/dev/tty`. A second real-child regression now proves a session with
slave descriptors alone fails to open `/dev/tty`, while the tested Linux-only
setsid/TIOCSCTTY helper succeeds. Root replayed both causal mutations as failures
and ran the exact21-test harness successfully with no skips in CP120; host checks
pass with the two Linux-only cases skipped. Evidence:
checkpoint121/linux/guest-suite-ctty.log, frozen guest inputs
`/tmp/vpn-pty-regression121.cklqdek2`. No password was delivered or installer
started in the rejected attempt, retained under
`/tmp/vpn-rpm-retry121.mz47zhvs` and checkpoint121/linux/observation1.log.

The corrected persistent driver imports those tested helpers, admits the private
credential file before launch, retains its original descriptor, waits for prompt
and echo-disable admission, and keeps observing after a timeout. Native rerun
job02bf3dc0-2404-4e8c-ae66-a7d987afd7bf completed protected SUCCEEDED/OK seq4.
The replacement owner reports installed=true, cleanupCode=OK and runtime OFF;
RPM verification and public --version2.1.15 pass. The package pair is source
d27affd, base2.1.14/target2.1.15; final delivered-source and traffic scenarios
remain separate. Receipt: checkpoint121/linux/receipt.json.

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

### macOS GUI-return observer confused process roles — checkpoint111

Pre-execution review of the checkpoint108 observer found that its substring
matcher accepted only an explicit `serve` controller. Automatic GUI return
starts a `--headless-controller` child, which that matcher missed and could
misclassify as a frontend. Retained synthetic RED evidence is under
checkpoint108/macos-gui-return108. The reusable macos_fixture_processes helper
matches the four actual source-defined argument forms and rejects ambiguous
matches, unrelated substrings and reused/coarse process generations. Its five
tests run in release hygiene. It deliberately supports only fixed whitespace-free
fixture paths because `ps` command text is not an arbitrary argv API. These
checks validate the observer; automatic GUI return still requires native proof.

The first native observer attempt stopped before sending an install request:
preflight used per-directory file ordering while the driver used global ordering.
Both historical digests and the unchanged base inode/signature are retained.
The corrected attempt imports the existing MacBoundary.identity for preparation
and execution. CanonicalBundleIdentityTest in test_macos_rollback_fixture.py
checks the nested-directory digest and proves that copying the same code changes
filesystem identity while preserving the content digest. Base restoration uses
full identity; installed target comparison uses code digest plus signature/version,
not the mounted DMG inode. The suite runs in routine release hygiene.

### Fixture completion marker lost on nonzero exit — checkpoint111

A shell wrapper with `set -e` skipped its exit marker when `wait` returned a
failure. The routine test_native_fixture_run.py suite executes that failing
behavior and the reusable native_fixture_run.sh correction with real children.
The runner preserves literal arguments and exact child exit status, reserves its
PID receipt before launching, leaves the terminal marker absent while running,
and refuses existing/symlink receipts. A competing-invocation regression proves
only one child starts. Seven tests pass on POSIX; Windows explicitly skips this
POSIX runner suite. It never retries, kills or infers termination from timeout.

### macOS native return inherited the jpackage reentry marker — checkpoint112

Native108 attempt2 reached protected SUCCEEDED/OK and verified target bytes,
signature and version, but no automatic owner/GUI survived the240-second return
observation. It issued no post-terminal public bootstrap command. Source review
found the original-user native worker inherited `_JPACKAGE_LAUNCHER` from its
packaged parent, unlike the Kotlin and Linux launch paths which already clear it.
InstallLauncherEnvironmentTest in test_macos_install_gate.py compiles the exact
portable production primitive and execs a child with the inherited marker,
ordinary environment and explicit arguments. RED failed on the inherited marker
before the fix (worker tool transcript only); GREEN passes after clearing only
that marker. The actual Darwin relaunch now checks sanitization before either
GUI or headless exec. The ordinary hygiene suite runs two portable native tests;
seven Darwin gate tests remain explicitly VM-only. Root also compiled the actual
ARM64 worker without executing an installer. Fresh packaged GUI-return evidence
is still required; this regression does not establish that every relaunch cause
is resolved. The current suite has three portable native tests and seven VM-only
tests after the Launch Services regression below was added.

### macOS GUI return lacked a graphical launch session — checkpoint113

A bounded comparison on the same installed target, with the jpackage marker
absent in both cases, established a separate cause. Direct launch from SSH exited2
with the graphical-session error and created no owner. Launch Services opened
the same bundle in a new isolated workspace and produced a frontend plus its
authenticated controller; public quit cleaned up only that workspace. The retained
comparison is checkpoint108/macos-gui-return108/causal-probe-1789967867/
launchservices-causal-comparison.txt. This is a causal launch comparison, not an
update transaction or visual acceptance result.

The native worker now uses the fixed /usr/bin/open executable and discrete
bundle/workspace arguments for GUI return, while headless return retains the
captured executable and serve argument. InstallRelaunchPlanTest covers both
branches with the production C plan. The two assigned Darwin component tests
also intercepted the actual worker exec arguments and passed on the frozen
revision (gate113-two-tests.txt). Root compiled that ARM64 revision. These checks
run without launching an installer; fresh immutable packages and a complete
replacement/automatic-return scenario remain required.

### Windows fixture receipt failed on empty native output — checkpoint113

The CP112 admission RED probe correctly rejected the old image admission, but
its wrapper called Trim on the null value emitted by Get-Content -Raw for empty
stdout. This obscured the native result. The corrected attempt retained the same
native inputs and read output with IO.File.ReadAllText; RED and GREEN wrappers
then reached their expected terminal outcomes. Original failed records remain.

The reusable Read-VpnFixtureOutputReceipt helper preserves empty/nonempty streams
and the direct child exit code. Its routine Windows PowerShell regression runs
real child processes with exit codes0/7/23/31, demonstrates the old empty-file
expression failing, and checks the new receipt. Child script policy is explicitly
process-scoped. The test is skipped where Windows PowerShell is unavailable;
the macOS-host result is not Windows behavioral evidence. New native wrappers
must use the shared reader rather than copy the broken expression.

### Release-derived Android fixture omitted release sources — checkpoint113

The first assembleNativeFixture build failed Kotlin compilation on ImportTestHooks.
Gradle initWith inherits build-type options, not the release source directory.
The static fixture guard was extended and failed before adding the release Java
source directory to nativeFixture. It also guards clearing inherited ARM64 ABI
filters before selecting x86_64 and matching release library variants. The fixture
uses production release hooks, never debug-only import hooks. The guard runs in
release hygiene, but compilation and APK inspection remain separate gates.
Retained failed build: checkpoint112/android-native-fixture-build.log.

### Timed-out observation retained remote QGA and SSH sessions — checkpoint113

The unbounded makefile.readline in an ignored Windows evidence collector outlived
its55-second local SSH wrapper. Its remote Python process1600355/start6501856
still held socket3399978 to the owned CP95 QGA socket. Later read clients queued,
and the shared SSH connection refused further sessions. Root verified the exact
read-only collector and stopped that process only; the queue drained without
stopping any guest process, VM, installer or VPN. Local wrapper absence alone was
not evidence of remote termination.

native_fixture_qga.py bounds connect/send/read by one deadline, closes its socket
on every outcome and reports uncertain observations with their command identity.
Each new stream performs the QEMU guest-sync-delimited handshake before accepting
a requested result, so stale buffered replies cannot substitute for current data.
It exposes file reads and process-status observations, not guest process launch or
installer replay. Six routine Unix-socket tests reproduce the old blocked reader,
prove connection release after timeout, and cover stale, malformed, oversized and
fragmented replies. Windows skips this Unix transport suite. Root also used the
new helper against CP95 to open/read/close the583-byte terminal GREEN receipt;
its exact hash matched the independent PowerShell export. Evidence is
checkpoint113/qga-native-result.json. Future collectors must use bounded remote
I/O and preserve the underlying operation identity after local timeout.

### Fixture server staging omitted direct imports — checkpoint114

CP113 preparation copied prepare_desktop_update_fixture.py without
fixture_environment.py and macos_packaging_jdk_preflight.py. The server failed
on import before launching the app or accepting an installation. The retained
server error and isolated RED/GREEN record are under checkpoint113/macos-return113.
The production stage-entrypoint command owns the explicit bounded inventory in
prepare_desktop_update_fixture.py. Its isolated staging regression reproduces
missing imports. Checkpoint115 review removed a duplicate unused inventory and
connected a direct-local-import check to the actual staging path. An added local
import now fails admission instead of silently omitting its module. The routine
51-test desktop update fixture suite passes; dependencies remain explicit rather
than recursively discovered. Use stage-entrypoint before transferring the server.

### Bounded observation cleanup and readiness — checkpoint115

Independent review found that the new QGA context manager closed sockets but
not guest file handles after a read exception. Two causal tests failed before
repair (missing close call); all eight QGA tests pass after owned handles are
closed once. An uncertain close is retained in cleanup_errors and never replayed;
cleanup cannot replace a primary read exception. A lost open response still has
no known handle to close and remains explicitly unknown. Release hygiene runs
test_native_fixture_qga.py; native cleanup under guest loss remains separate.

The macOS readiness observer now supplies the remaining deadline to its status
runner, retains partial stdout/stderr on subprocess timeout, and rejects zero or
nonfinite timing. Three new regressions failed before repair; ten observer tests
pass. This prevents a visible PID from being treated as a ready endpoint and
preserves failed observations. The runner must honor its supplied timeout. The
original native first-read failure had discarded output: endpoint readiness is
an inference, not a recovered diagnosis. Routine release hygiene includes
test_macos_fixture_processes.py.

### RPM transaction rejection response — checkpoint116

Historical CP83 native evidence reached RPM payload-digest rejection after
public manifest verification and installer handoff. Existing pre-install hash
checks did not exercise this branch. DesktopLinuxInstallWorkerTest now executes
the production shell dispatch/result fragment with a failing rpm command and
asserts exact arguments plus FAILED/RUNTIME_FAILED. It is routine desktop-test
coverage, not proof of RPM database rollback or current-package base preservation.
The initial regression fixture accidentally omitted production set +e and exited
before receipt publication; retaining that line fixes the test, not the product.
Root's focused suite passes five tests without skips (checkpoint115/
linux-worker-test-green.log). Native RPM failure/recovery remains required.

### GitHub rejects runner context in job environment — checkpoint117

Windows push35833398572 atadd840ad234c23f0588fc1dbc0a0a68c480ecd70 failed
and fixture dispatch returnedHTTP422 before execution. YAML parsing and text
checks had accepted runner.temp in job-level env, where GitHub disallows it.
The fixed workflow computes FIXTURE_ROOT in a PowerShell step using RUNNER_TEMP
and GITHUB_ENV. The real actionlint regression reconstructs the rejected job env
and reports the same forbidden runner context; corrected workflows pass.
A checksum-pinned private cached actionlint now validates all workflows in routine
release hygiene, without requiring a global installation. Tests also detect and
repair cached executable bytes that differ from the verified archive and bound
parser execution. Whole-workflow GREEN and four parser/cache tests passed locally;
the next exact-SHA Windows push and fixture dispatch still must succeed.

### Android tools resolve a different SDK — checkpoint117

The API29 SDK listed the image, but its symlinked avdmanager resolved under
/opt/android-sdk and selected a different package root. A previous emulator
launch also omitted the private ANDROID_AVD_HOME. The quick regression executes
a representative root-deriving wrapper: the symlink fails to find the image,
while real tools within the selected SDK succeed. The read-only
android_avd_sdk_preflight.py rejects foreign avdmanager paths, checks exact image
package metadata and returns explicit SDK/AVD environment values. Shared emulator
symlinks remain supported. The tests run in release hygiene; POSIX shell execution
is explicitly skipped on Windows. This guard does not certify image bytes or boot.

Native recheck on the owned API29 private SDK returned exit0 with its actual AVD
home at /home/kardinal/.vpn-control-parity116-api29. The earlier assumed /avd
subdirectory was rejected without mutation. Evidence is checkpoint117/
android-sdk-native-correct-home.{stdout,stderr,exit}. Before creating or starting
an owned AVD, invoke the guard with --sdk-root, --avd-home and --system-image;
use the returned executable paths and all three environment values in the launch.

### Private QEMU missing VGA ROM — checkpoint118

After the host QEMU binary changed, the saved-memory guard correctly rejected
restore. A private copy of the matching QEMU executable and its common/firmware
packages passed --version and --help, but VM initialization failed before loading
saved memory because vgabios-stdvga.bin comes from the separate SeaBIOS package.
Attempt-one receipts and the parked memory/disk remain preserved. The preflight
in scripts/native_fixture_qemu_assets.py checks declared relative paths and
hashes before launch. Its filesystem regression rejects a missing VGA ROM and
then accepts matching bytes; changed bytes and escaping symlinks also fail.
Release hygiene runs the regression. Invoke --root PRIVATE_ROOT and repeated
--asset RELATIVE_PATH=SHA256 for every required binary/ROM immediately before
launch. This verifies declared assets, not complete dependency discovery or
compatibility with saved VM state; retain native device realization and restore.

### Android in-flight stream interruption — checkpoint119

The real Android document client preserves interruption while returning
OUTCOME_UNKNOWN for uncertain requests. A read-only watch forwarded that result
as exit2 instead of cancellation130. A deterministic public CLI regression blocks
the second Android document submission, interrupts it, and checks terminal
CANCELLED, no extra poll and no owner cancellation. Against the old stream code
it failed with expected130/actual2; the fixed stream checks the preserved interrupt
flag before rendering the transport result. Mutation handling is unchanged.
DesktopAndroidStreamTransportTest runs in the routine desktop test tier.
The five focused stream suites passed; evidence is checkpoint119/stream-red.xml
and the retained GREEN XML files. Native terminal SIGINT remains a separate
acceptance scenario; thread interruption alone does not prove OS signal behavior.

### Windows fixture batch-logon denial — checkpoint120

The CP117 limited Task Scheduler task returned from start but never launched its
child. Security4625/logon type4/status0xC000015B and TaskScheduler101/error
0x80070569 established missing batch-logon rights, not invalid credentials. No
MSI had started. Before scheduling a disposable guest task, dot-source
scripts/windows_task_admission.ps1 and call Test-BatchLogonAdmission with the
account and an in-memory SecureString. It uses native batch logon, closes the
token, zeroes the temporary password buffer and returns only admission/error
metadata. Never put the credential in process arguments or evidence.

The deterministic PowerShell test distinguishes rights denial from bad credentials,
checks successful admission and invalid-result token cleanup, and exercises the
privilege-right parser with PowerShell's short-name alias collision present. The
Windows package workflow runs it before packaging; absent PowerShell is a failure.
This is an injected-boundary regression, not proof of native account eligibility.
The real guest preflight reproduced1385 before repair and returned success after
adding only its disposable user's batch right while preserving other rights.
The alias collision occurred in the first repair invocation before policy changes;
that evidence was retained and the next attempt used the named parser.

A successful admission check does not authorize an installer replay. Reconcile
task instance, child and receipt before starting, preserve unknown work, and keep
MSI execution/update/recovery as separate native acceptance scenarios.

Review additionally found incorrect HRESULT_FROM_WIN32 conversion for larger
DWORD values. The added boundary fixture failed against the old helper and passed
with low16-bit masking and preservation of already-negative HRESULT values. The
final generated PowerShell test body passed on the guest; Python was absent, so
this is exact-body/component evidence rather than Python-launcher execution.
The Python launcher uses process-only ExecutionPolicy Bypass for its verified
fixture script, without changing machine policy. Hosted Windows CI must still
execute that launcher.

### Android fixture mount response loss — checkpoint124

Review of the native TLS fixture cleanup found that an ADB mount command could
execute before its response was lost. The driver then treated the mount as absent
and removed the potentially mounted certificate staging tree. Track the mount
attempt separately from acknowledgment and retain staging with `unknownMount`
until authoritative reconciliation. Do not infer that a lost response undid a
device-side effect.

The deterministic fake-ADB regression executes the lifecycle with a mount-response
failure and checks retained staging, original failure, and restored public adbd.
Against clean6ee source it failed; fixed source passed the32-test TLS selection.
Root evidence, hashes and exact exits are in
`.runtime/parity-evidence/checkpoint124/tls-mount-regression/receipt.json` and its
RED/GREEN logs. The test runs in release hygiene and therefore routine prepush.
This was a review-discovered fixture risk, not an intentionally disrupted live
mount. Keep native certificate trust and cleanup checks separately.

An earlier temporary API29 driver omitted cleanup after a failed certificate
push. The shared driver already handled that case: its added regression passes
both old and new shared code. Do not claim a new causal fix for that case. Native
API29/API35 attempts also used incompatible Mac-local files/server endpoints with
Arch-local ADB. Colocate fixture inputs, servers and ADB, and keep admission
evidence; those attempts did not accept a product refresh or installation.

### Android refresh fixture source ownership — checkpoint125

The new refresh driver initially assumed subscription add always created a new
entry. Product add intentionally upserts an existing URL, so fixture cleanup could
delete an existing subscription. Before add, inspect subscription identities and
sources under one controller/revision, reject the fixture URL if present, and bind
add to that same revision so a concurrent configuration change cannot invalidate
admission. Do not restore or delete after uncertain mutation outcomes.

The quick CLI-boundary test failed on the pre-fix driver because it attempted a
mutation despite an existing source. The fixed combined harness selection passed
92 tests, including revision drift before add. RED/GREEN logs and source hashes are
in `.runtime/parity-evidence/checkpoint125/refresh-source-admission/`. The new
`test_android_subscription_refresh_lifecycle.py` is wired into release hygiene.
This was found during review before native execution; no device subscription was
deliberately overwritten to reproduce it.

### Native installer handoff versus final receipt — checkpoint125

The API35 cancellation harness incorrectly required the original install operation
to change from successful handoff to CANCELLED. The operation intentionally retains
its immutable handoff result; subsequent installation outcomes are exposed through
the correlated receipt in `updates status`. Native operation
`b58f0a38-153d-46dd-8e37-9e76960ab043` retained OK/handed_off while receipt
`2d502ff6-5969-443e-892a-6193c7f6830c`, session1320681568, reconciled to
cancelled/installed=false after the OS Cancel action. This is a fixture expectation
defect, not proof of a product cancellation defect. Earlier queries inspected only
the historical operation, so they do not establish when the callback arrived.

Keep the original operation and independently inspect the same receipt/session
until its authoritative outcome is known; a timeout must retain identity and never
start another installer. The deterministic lifecycle test reproduces rejection of
valid handoff followed by a cancelled receipt before the harness repair. Its tests
remain in release hygiene. Native redacted evidence is under
`.runtime/parity-evidence/checkpoint125/android35-cancel/`; repeat the corrected
harness natively before claiming that complete driver path passed.

### Windows test metadata portability — checkpoint125

Windows workflow35862222810 for fd927ecc failed because a new relay test compared
Windows `stat` attributes with POSIX0600 bits (actual0666). Keep the live relay and
request-content checks on Windows; assert POSIX permission bits only on POSIX.
The refresh command test likewise compares the executable with `str(args.cli)` so
the assertion follows the host path representation. These are test portability
fixes, not Windows ACL validation or product changes. The existing failing tests
are the reproducer and remain in routine hygiene; exact-SHA Windows CI must prove
the repaired Windows branch. The bounded failure log is retained under
`.runtime/parity-evidence/checkpoint125/windows-ci-failed.log`.

### Installation replaces the operation owner — checkpoint127

The API35 installed-target run replaced the application process before the fixture
captured its handoff identity. The replacement owner's operation list correctly
returned NOT_FOUND for the old in-memory operation; its current update receipt
reported installed=true and the exact target APK hash/version were independently
verified. This was a fixture ordering defect, not loss of a persistent product job.

The installer fixture now uses two phases: after the OS confirmation is visible,
capture and fsync the accepted controller/operation/receipt/session identity before
approval; afterward poll the correlated current update receipt and verify installed
bytes. File callbacks must be distinct; TTY interaction uses two prompts. Actual
main-to-action regressions caught a dropped callback option. Additional causal
regressions reject a foreign controller before handoff and Python boolean session
IDs that would otherwise compare equal to integer1. All30 focused tests pass and
remain in release hygiene. RED/GREEN logs are retained under
`.runtime/parity-evidence/checkpoint127/android-handoff-review/`.

Native API35 cancellation passes the corrected prior reconciliation driver.
The successful target installation proves replacement and next-owner recovery,
but not complete pre-approval correlation. Keep that limitation and rerun the new
two-phase driver with an eligible base/target pair; never downgrade or replay an
already installed target merely to repeat the fixture.

### Linux fixture mount and synthetic DNS prerequisites — checkpoint127

The CP120 VPN fixture extracted its runtime beneath /tmp on a nosuid mount.
getcap reported effective/permitted NET_ADMIN and NET_RAW, but Linux ignored those
file capabilities during execution; sing-box failed TUNSETIFF with EPERM. Owner
NoNewPrivs was0, its capability bounding set included both capabilities, and
/dev/net/tun was accessible. Moving only the disposable workspace to private
home-backed btrfs resolved the prerequisite. This is a fixture setup failure,
not evidence that the product dropped process privileges.

The new linux_vpn_fixture_guard validates the exact binary's mount/options and
capabilities, retains failed admission records, and rejects foreign-path getcap
output. Its DNS-free curl probe preserves the fixture Host while explicitly
resolving to loopback for quick tests or TEST-NET for real TUN acceptance. Eight
routine tests pass; release hygiene runs test_linux_vpn_fixture_guard.py.

Evidence qualification: the worker's initial RED was only a missing-module error
and is not causal proof. Original native DNS/SOCKS failure outputs were overwritten
by its final pass and cannot be reconstructed. Root's controlled getcap-only and
missing-resolution replays fail behavioral tests; these were performed after the
fix, not before it. Their logs and exact source hashes are under
`.runtime/parity-evidence/checkpoint127/linux-regression-review/`. Preserve separate
immutable directories for each native attempt; never overwrite failed evidence.
Final current-RPM basic TUN traffic and clean off/quit are independently verified
in checkpoint126/linux-vpn/root-review.json; broader continuity/package acceptance
remains separate.

### Machine rollback fixture authority and owner detection — checkpoint127

The retained rollback fixture was written for user-local applications. Review
before machine-owned installation found it read the owner's Library receipts and
used unprivileged chflags, whereas the production machine worker uses /Library
receipts and root-owned staging. The fixture now requires explicit receipt
authority, keeps public CLI calls ordinary-user, and uses fixed privileged helper
actions only for the exact machine receipt/candidate. Machine errors never fall
back to user-local receipts. The armed candidate identity is retained through
cleanup so a replacement candidate cannot have its flag cleared.

The first native run timed out before installation because its owner predicate
counted sudo/launchctl wrappers as owners. No install operation or worker was
created in that attempt. The fixture now reuses the exact process-role parser for
readiness/liveness. Regressions cover the wrapper-plus-real-owner process table,
ambiguous real owners, machine/local receipt paths, missing authority, candidate
replacement, and helper rejection. Windows-shaped paths and mocked Unix identity
APIs exercise portability before CI. The23-test rollback suite remains in release
hygiene. Native retry evidence is under checkpoint127/macos-rollback; component
checks alone do not establish machine rollback/recovery acceptance.

### Android fixture APK architecture mismatch — checkpoint127

API29's current-source installation attempt stopped at updates check with
UNSUPPORTED before download or installer creation. The fixture advertised
arm64-v8a for an x86_64-only APK; API35 advertised both ABIs and masked the error.
Fixture metadata now derives supported ABI entries from the actual APK ZIP native
library paths, rejects symlink-only/malformed/unsupported payloads, and retains
exact hash and size checks. Multi-ABI assets reference the same verified payload.
The existing routine Android update fixture and SAN suites cover these cases.

The failed native attempt is retained in checkpoint127/android29-installed.
The quick old-code failure was replayed retrospectively in an isolated snapshot,
not run before the edit; that limitation and GREEN logs are recorded in
checkpoint127/android-abi-regression. A new immutable native fixture must prove
eligibility and full two-phase replacement before this acceptance gate closes.

The corrected immutable API29 rerun now proves full preapproval correlation and
replacement-owner installed reconciliation with exact target bytes. Root reviewed
24 export artifact hashes. Its ad-hoc export command repeated the earlier
self-including manifest mistake; preserve that failed manifest and use the existing
`scripts/native_fixture_manifest.py` writer/verifier, whose routine regressions
already reject self-inclusion, for every subsequent evidence export. Do not
replace this tested helper with shell redirection over the output directory.

### Windows execution of Android two-phase fixture tests — checkpoint128

Exact-SHA Windows CI for a27624a failed in the new two-phase flow tests, before
packaging. The existing Windows test boundary modeled private mode for probe.json
but omitted the newly introduced handoff.json; a callback-validation test also
reached real packaged-ADB PATH admission instead of its intended argument check.
This is a test portability defect, not an Android application failure on Windows.

The flow tests now model both private-file OS boundaries while retaining real
writes, handoff-before-approval ordering and replacement-owner reconciliation.
The dedicated POSIX privacy tests retain their existing platform restriction;
no flow tests were skipped and product privacy enforcement is unchanged. A host
Windows-stat simulation exercises the actual two-phase action and catches the
missing handoff boundary. RED/GREEN evidence is in checkpoint128/android-portability;
the31-test suite passes locally. Actual Windows verification remains an exact-SHA
CI gate; no guest test execution is claimed.

### Concurrent VPN continuity probes starved by serial fixture — checkpoint128

The installed-RPM continuity attempt preserved controller/runtime identity through
GUI normal close, crash and reattach, but its TUN sampler completed only83/110
requests. The reused fixture accepted one SOCKS connection at a time; a persistent
proxy echo sampler blocked subsequent HTTP probes. An unprivileged local replay
held the first tunnel and reproduced the second greeting timeout, while the
existing threaded fixture served the second request immediately. This establishes
a fixture concurrency defect; the failed native run does not certify uninterrupted
traffic or demonstrate a product runtime failure.

The routine `test_vpn_integration_fixture.py` suite now holds one open tunnel while
asserting a second SOCKS/HTTP request completes. All15 tests pass. Evidence lives
in checkpoint128/linux-fixture-causality128; the failed native bundle is preserved
in checkpoint128/linux-vpn-continuity128. Before retry, the exact corrected native
server must prove concurrent HTTP and retained echo behavior locally, because the
existing HTTP-only fixture cannot replace echo behavior implicitly.

### macOS process-row test rendered with Windows separators — checkpoint128

After the Android test repair, Windows CI for a52faf3 passed that selection and
reached a second portability defect: the macOS owner test interpolated host Path
objects into simulated guest ps output. On Windows those strings contain
backslashes, while the real Mac process matcher correctly expects POSIX paths.
The test now renders explicit POSIX guest strings and exercises both native Path
and PureWindowsPath variants on every host. The ambiguity test first recognizes
one owner before rejecting two, avoiding a false pass from malformed input.

The new variants failed twice with the old rendering before the fix; all23 tests
now pass without skips. Evidence: checkpoint128/mac-test-portability. Failed job
log: checkpoint128/windows-ci-second-job.log. Product/native installer behavior
was unchanged; exact-SHA Windows CI still must verify the correction.

### Existing Android emulator coupled to AVD creation tools — checkpoint131

The remote user SDK contains the emulator and API29 image but its avdmanager
resolves into a different shared SDK. The creation preflight correctly rejects
that manager; using it for an existing emulator unnecessarily blocked launch.
Two quick regressions reproduced missing/foreign-manager rejection before the
fix by routing the launch entry point through the prior creation preflight.
The new safe_emulator_environment function and --launch-only CLI mode validate
the emulator, private AVD home and image metadata while preserving all three
SDK/AVD environment variables. Creation still rejects foreign avdmanager paths.
Eleven focused tests pass, including launch-only CLI metadata failure and private
environment checks; the existing release-hygiene selection runs this suite.
RED/GREEN evidence: checkpoint131/sdk-launch-regression. Native boot admission
and the48MiB document scenario remain separate gates.

The preceding hand-built launch omitted ANDROID_AVD_HOME and never booted. Native
launchers must consume the helper's environment explicitly rather than recreate
it. Preserve that failed launch receipt; a stopped process is not a successful
heap-admission result.

### macOS monitor lost with its launch context — checkpoint136

The CP135 background monitor and Tart child disappeared after one normal-pressure
sample, without a terminal, pressure-stop or error receipt. Logs do not establish
the terminating actor or a guest failure. The `nohup ... &` wrapper and inherited
child process group left a concrete lifetime weakness. The foreground resource
monitor now gives its child a separate session and retains process, sample and
terminal receipts. Failed observation or an uncertain stop records that state
without another stop request or signalling the unknown child. Routine synthetic
process tests cover the lifetime and failure boundaries; retain the original
native failure in `checkpoint136/macos-monitor/original-failed-launch` (copied
from the original private temporary directory).
A new native boot/reconciliation remains required; passing these tests alone
does not establish installer recovery.

CP136 prepush also caught an empty heartbeat read between the synthetic writer's
truncate and write. This is a test-fixture publication race, not a Tart or product
failure. The failing prepush receipt is retained. Atomic synthetic heartbeat publication
and a routine missing/empty/partial/complete reader regression now pass; the
process-group survival scenario remains in the seven-test selection.

### Fixture admission and portability — checkpoint139

Windows CI35984122823 exposed a Linux fixture test that used host Windows mode
bits for its simulated Linux target. The injected Windows-stat vector failed
before repair;12 tests now pass with explicit target metadata and preserved
foreign-owner rejection. Evidence: checkpoint139/windows-ci. This is a test
portability defect; it does not establish a product installer failure.

The CP138 Windows stage receipt lacked recipient RX. The original stderr was not
retained, so SID translation failure is a hypothesis, not proven causality. The
new typed-SID generator fails on PowerShell errors and validates the exact
protected three-principal ACL. Seven routine tests reject the old receipt,
truncation, nonterminal/nonzero captures and unsafe path aliases. Native CP139
parser and one ACL application passed; all five hashes and MSI inherited RX were
verified. Subsequent review exposed missing-output and wrong-stage receipt
acceptance; causal regressions now require captured QGA output and the requested
stage path. The original CP139 receipt predates that path field: its stage identity
is supported by separate pre/post native observations, not the new validator. Evidence: checkpoint139/windows-acl. MSI acceptance is still separate.

The macOS build failed on guest TCP access to Google's repository before TLS.
The same host URL returned200 with normal certificate validation. A scoped raw
CONNECT relay restricts one private guest peer and three fixed Gradle repositories.
Thirteen routine tests cover admission, framing, forwarding and preflight failure.
Review also reproduced buffer overshoot and plaintext rejection after an accepted
tunnel before fixing both; evidence: checkpoint139/mac-relay. No TLS trust bypass
or global proxy setting is introduced. Native build retry remains outstanding.

### Polkit identity selection before password — checkpoint140

CP139's terminal driver recognized only Password and stalled at the polkit
multiple-account selector. The decision replay in checkpoint140/linux-identity-selector
fails with the former password-only decision and passes when the helper chooses
only the explicitly named fixture account from a complete, contiguous selector.
The routine Linux public-install harness covers wrong, duplicate, partial and
malformed selections; password admission still requires its separate terminal
echo-disable check. The remote PTY driver must explicitly consume this helper
before another admitted native attempt. No current unknown job is replayed or
cleared by this change, and it does not prove installation success.
