# VPN Control Agent Docs

This is the authoritative entry point for developer and agent documentation. Start here when you do not already know which subsystem owns a change.

## Task Router

| Task | Read First | Inspect | Minimum Checks |
| --- | --- | --- | --- |
| Low-context patch or dirty worktree | `development.md`, `test-matrix.md` | `git status --short`, owner files from `architecture.md` | `git diff --check` plus the mapped test tier |
| Agent startup, MCP, RAG, commit, or CI finish | `../agent_tools/README.md`, `development.md`, `test-matrix.md` | `.codex/config.toml`, `agent_tools/`, `.github/required-workflows.json` | `python3 agent_tools/affected_agent_tests.py --run` plus the managed pre-push tier for lifecycle changes |
| Fresh Windows VM or reproducibility review | `tools/lifecycle-and-api.md`, current WIP | `agent_tools/native_vm_spec.py`, `agent_tools/windows_vm_deploy.py`, `agent_tools/windows_vm_setup_policy.py` | Affected agent tests; complete DIRECT creation/setup and matching MCP qualification before product acceptance |
| Unknown file or ambiguous ownership | `development.md`, `contracts.md`, `architecture.md` | `git diff --name-status`, nearest owner docs, existing tests beside the touched file | `git diff --check`; then use the closest owner row before editing |
| Documentation-only changes | `development.md`, `test-matrix.md` | Changed docs, links, scripts that validate docs | `git diff --check`, `./scripts/check_docs_hygiene.sh` |
| Localization, UI labels, status/log text | `localization.md`, `test-matrix.md` | `shared/ui/src/commonMain/resources/i18n/`, `shared/ui/src/commonMain/resources/i18n-status/`, status facades in `shared/model/` | `./scripts/check_localization.py`, `./scripts/status_catalog_tool.py check`, `./gradlew :shared:ui:desktopTest` |
| Translation debt or historical audit follow-up | `localization-untranslated-audit.md`, `localization.md` | Current catalogs first; use the audit only as historical context | Localization mapped check set |
| Shared UI behavior, layout, or theme | `contracts.md`, `state-ownership.md`, `visual-regression.md`, `test-matrix.md` | `shared/ui/`, platform roots, scene manifest, affected capture drivers | `python3 scripts/check_ui_theme.py`, `./gradlew :shared:ui:desktopTest`; add platform compile/test if callbacks or state shape change |
| Desktop lifecycle, tray, autostart, reconnect | `desktop-lifecycle.md`, `state-ownership.md`, `desktop-runtime-troubleshooting.md` | `desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/` | `./gradlew :desktopApp:test` |
| GUI/CLI parity, control protocol, headless commands, Android ADB | [Current WIP](work-in-progress.md), [active execution brief](parity-solo-plan.md), `cli.md`; then applicable contracts/state ownership | shared control DTOs/codecs, desktop CLI/controller, Android control adapters | Shared model/core tests plus affected platform tests; native public-CLI package tests for launcher/transport changes |
| Desktop runtime failure, VPN stopped, proxy not ready | `runtime-troubleshooting.md`, `desktop-runtime-troubleshooting.md`, `platform-matrix.md` | Redacted desktop preflight snippets, runtime logs/configs, desktop runtime services | Read-only preflight first; then `./gradlew :desktopApp:test` if code changed |
| Android runtime failure or VPN config issue | `contracts.md`, `runtime-troubleshooting.md`, `sing-box-development.md` | Exported Android diagnostics, `app/src/main/java/com/kardinal/vpncontrol/data/`, `app/src/androidTest/` config tests | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin`; add instrumentation when config shape changes |
| Protocol, parser, subscription import | `contracts.md`, `sing-box-development.md`, `architecture.md` | parsers and outbound/config builders in `shared/core/`, Android/desktop parity tests | `./gradlew :shared:core:desktopTest`; add platform config tests when shape changes |
| Android VPN, routing, app behavior | `contracts.md`, `state-ownership.md`, `sing-box-development.md` | `app/`, shared core state and config helpers | `./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` |
| SSH Routing and SSH relay | `contracts.md`, `../docs/ssh-routing.md`, `state-ownership.md` | shared config builders, platform credential stores, subscription clients, `scripts/install_home_relay.sh` | Shared core tests plus Android and desktop tests |
| Shared state/action boundary | `state-ownership.md`, `architecture.md`, `test-matrix.md` | `shared/core/`, `MainController`, Android ViewModel, desktop services | Shared tests plus one affected platform compile/test |
| Packaging, release, native runtime | `developer-release-checklist.md`, `native-runtime-artifacts.md`, `platform-matrix.md` | `scripts/`, `.github/workflows/`, runtime artifact paths | `./scripts/check_release_hygiene.sh` plus package-specific checks |
| CI or workflow-only changes | `developer-release-checklist.md`, `test-matrix.md` | `.github/workflows/`, scripts called by workflows, artifact names in `../README.md` | `./scripts/check_release_hygiene.sh`, `./scripts/check_docs_hygiene.sh`, `git diff --check`; run package checks only when workflow behavior needs it |
| Visual regression, agent review, or VM capture | `contracts.md`, `visual-regression.md`, `developer-release-checklist.md` | `visual-tests/`, visual platform/review scripts, hosted fallback workflow, release tool | theme, comparator, platform/review, agent tool, release hygiene, and docs hygiene checks |
| User-facing install docs | `../README.md`, `developer-release-checklist.md` | Root `../README.md`, GitHub Release asset names | `./scripts/check_release_hygiene.sh`, `./scripts/check_docs_hygiene.sh`, `git diff --check` |

Use the smallest row that covers the change. If a patch crosses rows, run the union of their mapped check sets or state exactly what was skipped.

| Doc | Purpose |
| --- | --- |
| `contracts.md` | Single authoritative source for all product invariants. |
| `development.md` | Workflow guide: source/generated boundaries, dirty worktree policy, and safe patch flow. |
| `ssh-tmux-sessions.md` | Optional fixed Linux packaging persistence, reconnect authority, immutable result collection and integration gates. |
| `architecture.md` | Import/subscription to parser, state, config, runtime, and diagnostics data flow. |
| `state-ownership.md` | Shared, Android, and desktop state/action ownership boundaries. |
| `test-matrix.md` | Which tests to run for each touched area. |
| `platform-matrix.md` | Android, Linux, Windows, and macOS capability/privilege matrix. |
| `runtime-troubleshooting.md` | General runtime safety and read-only diagnostics before interrupting VPN/runtime. |
| `desktop-runtime-troubleshooting.md` | Desktop state, logs, config paths, and platform-specific runtime details. |
| `desktop-lifecycle.md` | Tray, single-instance, autostart, reconnect, refresh, and direct-probe invariants. |
| `cli.md` | GUI/CLI operation inventory, shared control boundary, platform adapter implementation and validation. |
| `sing-box-development.md` | sing-box owner files, tests, and protocol-change procedure. |
| `native-runtime-artifacts.md` | Which native binaries are tracked, generated, or ignored. |
| `localization.md` | Language catalog architecture, editing rules, validation, and test-update guidance. |
| `localization-untranslated-audit.md` | Historical untranslated-string audit and known terminology exceptions. |
| `developer-release-checklist.md` | Local developer release prerequisites, checks, outputs, and failure modes. |
| `desktop-smoke-testing.md` | Linux/Windows desktop manual smoke checklist. |
| `smoke-android.md` | Android instrumentation commands and manual protocol smoke checklist. |
| `macos-release.md` | macOS signing and notarization setup. |
| `visual-regression.md` | Agent-owned scene capture, local VM/hosted fallback, baseline, review, receipt, and release-gate operations. |
| `work-in-progress.md` | Current intentional multi-bucket work: owners, verified checkpoint, next actions and remaining gates. |
| `parity-solo-plan.md` | Deferred parity brief; active MCP-only repair allows subagents and keeps prior environments closed. |
| `parity-continuation-plan.md` | Superseded-brief pointer; September 28 instructions remain preserved in the archive. |
| `parity-failure-regressions.md` | Compact active failure-to-test index, unresolved enrollment and links to complete causal records. |
| `parity-history.md` | Historical GUI/CLI parity evidence and design notes; superseded snapshots, not current completion claims. |
| `parity-native-history.md` | Historical native parity runs and artifact evidence; consult work-in-progress for current gates. |
| `parity-checkpoint-history.md` | Preserved intermediate checkpoint ledger through 2026-09-08; superseded by the current work-in-progress ledger. |

## Focused procedures and historical records

Current guidance is [WIP](work-in-progress.md) and [execution brief](parity-solo-plan.md).
Historical snapshots remain discoverable for explicit historical/custody questions;
old current/active headings do not supersede these routes.

| Doc | Purpose |
| --- | --- |
| `tools/lifecycle-and-api.md` | Precise startup/delivery/API and RAG procedures, reached from the compact tool guide. |
| `tools/visual-and-platform-evidence.md` | Fixed source/artifact/visual/native evidence procedures and strict custody schemas. |
| `tools/parity-worker-recipes.md` | Detailed recipes; fixed historical CP117 commands require original custody and never authorize replay. |
| `testing/agent-custody-regressions.md` | Agent-tool/source/custody regression details and source-bounded counts. |
| `testing/product-package-regressions.md` | Product/package regression details and native limits. |
| `testing/ci-shortcut.md` | Durable CI path selection and complete check gates. |
| `testing/native-acceptance.md` | DIRECT/MCP native acceptance criteria, matrix and skips. |
| `testing/native-regressions.md` | Precise routine native-harness regression procedures and OS limits. |
| `testing/migration-manifest.md` | Original test-matrix line/heading/blob custody map. |
| `archive/parity/README.md` | Historical parity index; evidence stays at original private locations. |
| `archive/parity/2026-10-14/work-in-progress-through-3944739.md` | Complete historical WIP through the investigation source. |
| `archive/parity/2026-10-14/failure-regressions-through-3944739.md` | Complete causal ledger including unresolved proposals. |
| `archive/parity/2026-10-14/september-continuation-brief.md` | Preserved superseded September brief. |
| `archive/parity/2026-10-14/test-matrix-original.md` | Preserved original validation guide/results. |
| `archive/parity/2026-10-14/tool-guide-original.md` | Preserved original full API/recipe guide. |
| `archive/parity/2026-10-14/migration-manifest.md` | Root docs: every original heading/anchor, blob and relative-link repair. |
| `archive/parity/2026-10-14/tool-migration-manifest.md` | Tool guide line ranges, snapshot/blob and preservation report. |

User-facing install and configuration instructions stay in `../README.md` and `../docs/`.

Repository-agent lifecycle, MCP, and RAG details live in `../agent_tools/README.md`.
