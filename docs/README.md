# VPN Control Developer Docs

This is the authoritative entry point for developer and agent documentation. Start here when you do not already know which subsystem owns a change.

## Task Router

| Task | Read First | Inspect | Minimum Checks |
| --- | --- | --- | --- |
| Low-context patch or dirty worktree | `development.md`, `test-matrix.md` | `git status --short`, owner files from `architecture.md` | `git diff --check` plus the mapped test tier |
| Unknown file or ambiguous ownership | `development.md`, `architecture.md`, `state-ownership.md` | `git diff --name-status`, nearest owner docs, existing tests beside the touched file | `git diff --check`; then use the closest owner row before editing |
| Documentation-only changes | `development.md`, `test-matrix.md` | Changed docs, links, scripts that validate docs | `git diff --check`, `./scripts/check_docs_hygiene.sh` |
| Localization, UI labels, status/log text | `localization.md`, `test-matrix.md` | `shared/ui/src/commonMain/resources/i18n/`, `shared/ui/src/commonMain/resources/i18n-status/`, status facades in `shared/model/` | `./scripts/check_localization.py`, `./scripts/status_catalog_tool.py check`, `./gradlew :shared:ui:desktopTest` |
| Translation debt or historical audit follow-up | `localization-untranslated-audit.md`, `localization.md` | Current catalogs first; use the audit only as historical context | Localization mapped check set |
| Shared UI behavior or layout, not localization | `state-ownership.md`, `test-matrix.md` | `shared/ui/`, platform call sites that pass callbacks/state | `./gradlew :shared:ui:desktopTest`; add platform compile/test if callbacks or state shape change |
| Desktop lifecycle, tray, autostart, reconnect | `desktop-lifecycle.md`, `state-ownership.md`, `desktop-runtime-troubleshooting.md` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/` | `./gradlew :desktopApp:test` |
| Desktop runtime failure, VPN stopped, proxy not ready | `runtime-troubleshooting.md`, `desktop-runtime-troubleshooting.md`, `platform-matrix.md` | Redacted desktop preflight snippets, runtime logs/configs, desktop runtime services | Read-only preflight first; then `./gradlew :desktopApp:test` if code changed |
| Android runtime failure or VPN config issue | `runtime-troubleshooting.md`, `platform-matrix.md`, `sing-box-contract.md` | Exported Android diagnostics, `app/src/main/java/com/kardinal/vpncontrol/data/`, `app/src/androidTest/` config tests | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin`; add instrumentation when config shape changes |
| Protocol, parser, subscription import | `sing-box-contract.md`, `architecture.md`, `smoke-android.md` | parsers and outbound/config builders in `shared/core/`, Android/desktop parity tests | `./gradlew :shared:core:desktopTest`; add platform config tests when shape changes |
| Android VPN, routing, app behavior | `platform-matrix.md`, `state-ownership.md`, `sing-box-contract.md` | `app/`, shared core state and config helpers | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` |
| Shared state/action boundary | `state-ownership.md`, `architecture.md`, `test-matrix.md` | `shared/core/`, `MainController`, Android ViewModel, desktop services | Shared tests plus one affected platform compile/test |
| Packaging, release, native runtime | `developer-release-checklist.md`, `native-runtime-artifacts.md`, `platform-matrix.md` | `scripts/`, `.github/workflows/`, runtime artifact paths | `./scripts/check_release_hygiene.sh` plus package-specific checks |
| CI or workflow-only changes | `developer-release-checklist.md`, `test-matrix.md` | `.github/workflows/`, scripts called by workflows, artifact names in `../README.md` | `./scripts/check_release_hygiene.sh`, `./scripts/check_docs_hygiene.sh`, `git diff --check`; run package checks only when workflow behavior needs it |
| User-facing install docs | `../README.md`, `developer-release-checklist.md` | Root `../README.md`, GitHub Release asset names | `./scripts/check_release_hygiene.sh`, `./scripts/check_docs_hygiene.sh`, `git diff --check` |

Use the smallest row that covers the change. If a patch crosses rows, run the union of their mapped check sets or state exactly what was skipped.

| Doc | Purpose |
| --- | --- |
| `development.md` | Workflow guide: source/generated boundaries, dirty worktree policy, and safe patch flow. |
| `architecture.md` | Import/subscription to parser, state, config, runtime, and diagnostics data flow. |
| `state-ownership.md` | Shared, Android, and desktop state/action ownership boundaries. |
| `test-matrix.md` | Which tests to run for each touched area. |
| `platform-matrix.md` | Android, Linux, Windows, and macOS capability/privilege matrix. |
| `runtime-troubleshooting.md` | General runtime safety and read-only diagnostics before interrupting VPN/runtime. |
| `desktop-runtime-troubleshooting.md` | Desktop state, logs, config paths, and platform-specific runtime details. |
| `desktop-lifecycle.md` | Tray, single-instance, autostart, reconnect, refresh, and direct-probe invariants. |
| `sing-box-contract.md` | Supported protocols, config-generation boundaries, routing rules, and benchmark expectations. |
| `native-runtime-artifacts.md` | Which native binaries are tracked, generated, or ignored. |
| `localization.md` | Language catalog architecture, editing rules, validation, and test-update guidance. |
| `localization-untranslated-audit.md` | Historical untranslated-string audit and known terminology exceptions. |
| `developer-release-checklist.md` | Local developer release prerequisites, checks, outputs, and failure modes. |
| `desktop-smoke-testing.md` | Linux/Windows desktop manual smoke checklist. |
| `smoke-android.md` | Android instrumentation commands and manual protocol smoke checklist. |
| `macos-release.md` | macOS signing and notarization setup. |
| `work-in-progress.md` | Optional template for intentional multi-bucket dirty work. |

User-facing install instructions stay in `../README.md`.
