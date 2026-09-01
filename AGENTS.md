# AGENTS.md

Guidance for coding agents working in this repository.

## Project Overview

VPN Control is a Kotlin project with:

- Android app in `app/`.
- Compose Desktop app in `desktopApp/`.
- Shared model, storage, core logic, and UI in `shared/`.
- Packaging and helper scripts in `scripts/`.
- Release workflows in `.github/workflows/`.

The app is built around `sing-box`. Android uses Android VPN APIs and bundled native runtime. Desktop uses bundled `sing-box` and supports VPN mode on Linux and Windows.

## Repository Map

| Path | Purpose |
| --- | --- |
| `app/` | Android application and Android VPN service. |
| `desktopApp/` | Compose Desktop app for Linux, Windows, macOS. |
| `shared/model/` | Shared data models. |
| `shared/core/` | Shared parsing, selection, refresh, and config logic. |
| `shared/storage-api/` | Shared storage interfaces. |
| `shared/ui/` | Shared Compose UI. |
| `docs/` | Public user installation and configuration documentation. |
| `agent_docs/` | Maintainer and coding-agent subsystem documentation. |
| `agent_tools/` | Repository-local MCP lifecycle tools and docs RAG. |
| `scripts/` | Packaging, runtime preparation, VM, and smoke-test scripts. |
| `.github/workflows/` | Android, Linux, Windows, and macOS package workflows. |

## Mandatory Agent Startup

The project MCP configured in `.codex/config.toml` is the normal entry point for repository work. For implementation, testing, build, release, commit, or other state-changing tasks:

1. Call `prepare_start` before normal repository searches, file inspection, tests, or edits.
2. Read the instruction files returned by the tool. Use its local `docs` RAG and `change_impact` result before broad exploratory searches.
3. If MCP is not yet available, allow `agent_tools/mcp_server.sh` to create `.agent_venv/` and install `agent_tools/requirements-mcp.txt`, then restart the session if its MCP inventory is already fixed.
4. If the transport still cannot be used, run the equivalent `agent_tools/mcp_tool.sh` command and report the MCP limitation.

The only startup-sync exception is a clearly read-only request where current remote state is irrelevant. State explicitly that sync was skipped and findings may be stale. This exception does not authorize edits, tests that create meaningful repository state, commits, pushes, or releases.

`prepare_start` must preserve dirty work. It may automatically switch to `main` or fast-forward from `origin/main` only when the worktree is clean. A dirty synchronized `main`, or a dirty `main` that is only locally ahead, may proceed with a warning. Fetch failures, divergence, a dirty non-main branch, and a dirty behind-main branch are blockers.

## Important Rules

- Do not commit generated artifacts from `build/`, `dist/`, `.runtime/`, or downloaded `sing-box` binaries.
- Do not kill a currently running VPN/runtime unless the user explicitly approves it. Stopping VPN can interrupt the active connection to the coding session.
- If runtime testing needs VPN interruption, first identify the current selected/running location and explain the risk.
- Do not restore old default subscriptions, default rules, or demo data.
- Preserve unrelated local changes. The worktree may be dirty.
- Prefer small, targeted fixes with regression tests for behavior changes.
- After changes are done and validated, push completed commits to `origin main`, then complete the post-push CI verification loop before reporting success.
- If large work intentionally spans multiple dirty buckets, document the intent in `agent_docs/work-in-progress.md`.
- Start low-context repository navigation from `agent_docs/README.md`.
- Use `agent_docs/state-ownership.md` before adding cross-platform actions or moving platform side effects.
- Use `agent_docs/native-runtime-artifacts.md` before touching native runtime binaries or runtime preparation scripts.

## Mandatory Agent Finish

Before reporting a state-changing task complete:

1. Call `workflow_status` and verify the changed paths remain in the requested scope.
2. Run focused checks while iterating, then `run_checks(level="prepush")` after the final content change. Do not reuse its receipt after repository contents change.
3. Keep commits coherent and stage only explicit reviewed paths. The managed `git_workflow` rejects generated/runtime paths and uncovered dirty changes.
4. Push completed commits to `origin main` and use `git_workflow` to watch the exact pushed SHA until every workflow in `.github/required-workflows.json` succeeds.
5. If a required workflow fails, inspect its bounded failed log, fix the cause, rerun the pre-push tier, commit and push again, then restart verification for the new exact SHA.

Do not report success while any expected workflow for the pushed SHA is missing, pending, cancelled, or failed. See `agent_tools/README.md` for tool inputs, safety boundaries, CLI fallback, and RAG behavior.

## Post-Push CI Verification

After every push to `origin main`:

1. Capture the exact pushed commit with `git rev-parse HEAD`.
2. Query GitHub Actions runs for that exact `headSha`; do not rely on branch-latest status alone.
3. Wait until these expected workflows for that SHA complete:
   - Fast Checks
   - Android Release APK
   - Linux Desktop Package
   - Windows Desktop Package
   - macOS Desktop Package
4. If any expected workflow fails, inspect the failure logs, fix the cause, rerun the relevant local checks, commit the fix, push again, and repeat this verification loop for the new `headSha`.
5. Do not report the push as complete while any expected workflow for the pushed SHA is pending, missing, or failed.

The canonical expected-workflow list is `.github/required-workflows.json`; keep that manifest aligned with the names of the push workflows above.

## First-Read Docs

Use `agent_docs/README.md` as the task router. It maps common tasks to the two or three focused docs, owner files, and minimum checks.

Focused docs are the subsystem detail layer:

- Low-context workflow and dirty worktree policy: `agent_docs/development.md`.
- Path-based validation and validation tiers: `agent_docs/test-matrix.md`.
- State/action ownership: `agent_docs/state-ownership.md`.
- Runtime safety: `agent_docs/runtime-troubleshooting.md`.
- Desktop lifecycle invariants: `agent_docs/desktop-lifecycle.md`.
- Protocol and `sing-box` config contract: `agent_docs/sing-box-contract.md`.
- Localization architecture and status catalogs: `agent_docs/localization.md`.
- Release packaging and artifact policy: `agent_docs/developer-release-checklist.md`, `agent_docs/native-runtime-artifacts.md`.

## Common Commands

Android release APK:

```bash
./gradlew :app:assembleRelease
```

Android debug APK:

```bash
./gradlew :app:assembleDebug
```

Desktop tests:

```bash
./gradlew :desktopApp:test
```

Shared model Android compile check:

```bash
./gradlew :shared:model:compileDebugKotlinAndroid
```

Shared core desktop test:

```bash
./gradlew :shared:core:desktopTest
```

Linux desktop package:

```bash
./scripts/package_linux_desktop.sh
```

Arch local install:

```bash
./scripts/arch_install.sh
```

Windows package from Windows:

```powershell
.\scripts\package_windows_desktop.ps1
```

Windows package from Linux VM:

```bash
./scripts/package_windows_desktop_vm.sh
```

macOS package:

```bash
./scripts/package_macos_desktop.sh
```

## Platform Notes

Canonical platform capabilities, privilege requirements, packaging outputs, and known limitations live in `agent_docs/platform-matrix.md`.

Use platform-specific smoke docs for manual checks:

- Android: `agent_docs/smoke-android.md`.
- Linux/Windows desktop: `agent_docs/desktop-smoke-testing.md`.
- macOS release packaging: `agent_docs/macos-release.md`.

## Runtime And Logs

Desktop state and logs:

```text
~/.vpn-control-desktop/
~/.vpn-control-desktop/workspace.json
~/.vpn-control-desktop/runtime/runtime-sing-box.log
~/.vpn-control-desktop/runtime/runtime-sing-box-vpn.json
~/.vpn-control-desktop/runtime/runtime-sing-box-proxy_only.json
```

Android diagnostics are exported from inside the app.

Detailed runtime safety and troubleshooting:

- `agent_docs/runtime-troubleshooting.md`
- `agent_docs/desktop-runtime-troubleshooting.md`

Use the redacted runtime snippets in `agent_docs/runtime-troubleshooting.md` before sharing logs or config details.

## Testing Expectations

Use `agent_docs/test-matrix.md` for path-based test selection and validation tiers. If checks cannot be run, state exactly which checks were skipped and why.

Documentation-only changes should run `git diff --check` and `./scripts/check_docs_hygiene.sh`.

Agent tool or MCP changes should also run `python3 -m unittest discover -s agent_tools/tests`. Broad changes must use the complete pre-push tier in `agent_docs/test-matrix.md`.

## Localization Rules

- Keep user-facing translations in JSON catalogs, not Kotlin source.
- Do not add translated `when (AppLanguage...)` branches in Kotlin.
- Preserve placeholders and technical terms exactly.
- For broad translation changes, use one language owner per catalog file.
- Run the localization checks named in `agent_docs/test-matrix.md`.

Detailed catalog structure, typed status rules, dynamic/legacy status handling, and test-update guidance live in `agent_docs/localization.md`.

## Behavior Requirements To Preserve

- No default subscriptions should be added automatically.
- No default routing rules should be added automatically.
- Desktop default mode should remain VPN mode unless intentionally changed.
- Desktop app should be single-instance aware.
- Closing the desktop window should hide to tray instead of killing the app.
- When app autostarts after boot, it should start in tray.
- If VPN was on before shutdown/reboot, desktop should reconnect using the remembered location.
- If VPN was off before shutdown/reboot, desktop should start without connecting.
- Scheduled subscription refresh should not leave VPN stopped. A short controlled restart is acceptable only when required by config changes.
- Desktop best-location checks should use direct probes so results are not biased by whether VPN is currently on.
- Android best-location and refresh behavior should remain consistent with shared core logic.

See `agent_docs/architecture.md`, `agent_docs/state-ownership.md`, `agent_docs/desktop-lifecycle.md`, `agent_docs/platform-matrix.md`, and `agent_docs/sing-box-contract.md` before changing cross-platform runtime behavior.

## User-Facing Install Docs

README is intentionally short and user-facing. It should point users to GitHub `Actions` artifacts, not ignored local `dist/` paths.

Use local generated paths such as `dist/windows/` or `dist/windows-vm/` only when documenting developer packaging workflows, not simple user installation.

Developer release packaging details belong in `agent_docs/developer-release-checklist.md`.

Do not put coding-agent startup, commit, CI, MCP, or RAG instructions in public user docs. Keep those in `AGENTS.md`, `agent_docs/`, and `agent_tools/README.md`.
