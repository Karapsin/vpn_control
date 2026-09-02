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
| `visual-tests/` | Cross-platform visual scene inventory and Git LFS baselines. |
| `.github/workflows/` | Android, Linux, Windows, and macOS package workflows. |

## Mandatory Agent Startup

The project MCP configured in `.codex/config.toml` is the normal entry point for repository work. For implementation, testing, build, release, commit, or other state-changing tasks:

1. Call `prepare_start` before normal repository searches, file inspection, tests, or edits.
2. Read the instruction files returned by the tool. Use its local `docs` RAG and `change_impact` result before broad exploratory searches.
3. If MCP is not yet available, allow `agent_tools/mcp_server.sh` to create `.agent_venv/` and install `agent_tools/requirements-mcp.txt`, then restart the session if its MCP inventory is already fixed.
4. If the transport still cannot be used, run the equivalent `agent_tools/mcp_tool.sh` command and report the MCP limitation.

The only startup-sync exception is a clearly read-only request where current remote state is irrelevant. State explicitly that sync was skipped and findings may be stale. This exception does not authorize edits, tests that create meaningful repository state, commits, pushes, or releases.

`prepare_start` must preserve dirty work. Normal development happens on `dev`; it may automatically switch to `dev` or fast-forward from `origin/dev` only when the worktree is clean. Fetch failures, divergence, a dirty branch other than `dev`, and a dirty behind-`dev` worktree are blockers. `main` is release-only.

## Important Rules

- Do not commit generated artifacts from `build/`, `dist/`, `.runtime/`, or downloaded `sing-box` binaries.
- Do not kill a currently running VPN/runtime unless the user explicitly approves it. Stopping VPN can interrupt the active connection to the coding session.
- If runtime testing needs VPN interruption, first identify the current selected/running location and explain the risk.
- Do not restore old default subscriptions, default rules, or demo data.
- Treat `agent_docs/contracts.md` as the single authoritative product-invariant source.
- Preserve unrelated local changes. The worktree may be dirty.
- Prefer small, targeted fixes with regression tests for behavior changes.
- After changes are done and validated, push completed commits to `origin/dev`, then complete the post-push CI verification loop before reporting success.
- Never merge to `main`, publish, tag, or dispatch the stable publisher unless the user explicitly commands a release. Do not infer a release command from requests to finish, ship, implement, or push development work.
- After every non-documentation change, use `version_bump` to add one concise `Unreleased` changelog bullet. It rolls the changelog and four-part base-20 version only at 10 bullets, or when an explicitly requested release uses `force_release`.
- When VPN Integration finds a product failure, add the fastest deterministic unit or contract regression that reproduces it before fixing the integration path.
- If large work intentionally spans multiple dirty buckets, document the intent in `agent_docs/work-in-progress.md`.
- Start low-context repository navigation from `agent_docs/README.md`.
- Use `agent_docs/state-ownership.md` before adding cross-platform actions or moving platform side effects.
- Use `agent_docs/native-runtime-artifacts.md` before touching native runtime binaries or runtime preparation scripts.

## Mandatory Agent Finish

Before reporting a state-changing task complete:

1. Call `workflow_status` and verify the changed paths remain in the requested scope.
2. For non-documentation changes, call `version_bump` after the final content edit. Treat its changelog/version metadata edit as part of the task.
3. Run focused checks while iterating, then `run_checks(level="prepush")` after the final content change. Do not reuse its receipt after repository contents change.
4. Keep commits coherent and stage only explicit reviewed paths. The managed `git_workflow` rejects generated/runtime paths and uncovered dirty changes.
5. Push completed commits to `origin/dev` and use `git_workflow` to watch the exact pushed SHA until every required development workflow in `.github/required-workflows.json` succeeds.
6. If a required workflow fails, inspect its bounded failed log, add or update a fast regression when it exposed a product defect, fix the cause, rerun the pre-push tier, commit and push again, then restart verification for the new exact SHA.

Do not report success while any expected workflow for the pushed SHA is missing, pending, cancelled, or failed. See `agent_tools/README.md` for tool inputs, safety boundaries, CLI fallback, and RAG behavior.

## Post-Push CI Verification

After every push to `origin/dev`:

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

`VPN Integration` is advisory on ordinary `dev` pushes. The explicitly dispatched `all` profile is mandatory for a release. A release command follows this sequence and no other request authorizes it:

1. Roll any remaining `Unreleased` notes with `version_bump(change_type="release", force_release=true)` and validate/push `dev`.
2. Run `release_workflow(action="merge-dev")` to fast-forward `main` from the exact verified `origin/dev` SHA, dispatch exhaustive VPN integration, and start the exact-SHA agent visual review.
3. Use `visual_platform` plus `visual_workflow`/`visual_review` to capture, automatically validate, open, and record every four-platform scene. No persistent self-hosted visual runner is used.
4. Run `release_workflow(action="status")` until exact-SHA package workflows, exhaustive integration, and the matching agent visual receipt/status are successful.
5. Run `release_workflow(action="publish")` to dispatch the manual stable publisher.

## First-Read Docs

Use `agent_docs/README.md` as the task router. It maps common tasks to the two or three focused docs, owner files, and minimum checks.

Focused docs are the subsystem detail layer:

- Low-context workflow and dirty worktree policy: `agent_docs/development.md`.
- Product, UI, platform, protocol, localization, artifact, and release invariants: `agent_docs/contracts.md`.
- Path-based validation and validation tiers: `agent_docs/test-matrix.md`.
- State/action ownership: `agent_docs/state-ownership.md`.
- Runtime safety: `agent_docs/runtime-troubleshooting.md`.
- Desktop lifecycle invariants: `agent_docs/desktop-lifecycle.md`.
- Protocol and `sing-box` implementation procedure: `agent_docs/sing-box-development.md`.
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

Versions use four components `a.b.c.d`, each in `0..19`. Normal automatic rolls increment `d`, carrying at 20 (`1.3.6.19` becomes `1.3.7.0`). `gradle.properties` is canonical; README, packages, Android version code, desktop metadata, and changelog must derive from or agree with it.

## Localization Rules

- Keep user-facing translations in JSON catalogs, not Kotlin source.
- Do not add translated `when (AppLanguage...)` branches in Kotlin.
- Preserve placeholders and technical terms exactly.
- For broad translation changes, use one language owner per catalog file.
- Run the localization checks named in `agent_docs/test-matrix.md`.

Detailed catalog structure, typed status rules, dynamic/legacy status handling, and test-update guidance live in `agent_docs/localization.md`.

## Product Contracts

All behavior requirements, including defaults, cross-platform parity, desktop lifecycle, networking, UI appearance, localization, artifact policy, and release gates, live in `agent_docs/contracts.md`. Read the applicable contract IDs plus the procedural owner docs before changing product behavior.

## User-Facing Install Docs

README is intentionally short and user-facing. It should point users to GitHub `Actions` artifacts, not ignored local `dist/` paths.

Use local generated paths such as `dist/windows/` or `dist/windows-vm/` only when documenting developer packaging workflows, not simple user installation.

Developer release packaging details belong in `agent_docs/developer-release-checklist.md`.

Do not put coding-agent startup, commit, CI, MCP, or RAG instructions in public user docs. Keep those in `AGENTS.md`, `agent_docs/`, and `agent_tools/README.md`.
