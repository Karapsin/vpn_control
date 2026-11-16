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

The project `vpn_control` MCP server is the normal entry point for repository work. Codex starts it from the generated, ignored `.codex/config.toml`; Claude Code starts it from the tracked `.mcp.json` and `.claude/settings.json`, with `CLAUDE.md` importing this file. Both clients use the same launcher, tools, and rules. For implementation, testing, build, release, commit, or other state-changing tasks:

1. Call `prepare_start` before normal repository searches, file inspection, tests, or edits.
2. Read the instruction files returned by the tool. Use its local `docs` RAG and `change_impact` result before broad exploratory searches.
3. For Codex, if `.codex/config.toml` is missing, generate it with `python3 agent_tools/configure_codex.py`; it is local and ignored. For Claude Code, trust the workspace and confirm `vpn_control` with `/mcp`. If MCP is not yet available, allow `agent_tools/mcp_server.sh` to create `.agent_venv/` and install `agent_tools/requirements-mcp.txt`, then restart the session if its MCP inventory is already fixed.
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
- Workers may make reversible quick fixes and run assigned checks within explicit file and environment ownership without coordinator micro-approval. Existing scope, runtime-interruption authorization, unknown-outcome non-replay, and source/artifact provenance gates still apply.
- After changes are done, gate completed commits into `origin/dev` through the managed `ci/*` branch gate, which fast-forwards `dev` only after the exact SHA passes CI, before reporting success.
- Never merge to `main`, publish, tag, or dispatch the stable publisher unless the user explicitly commands a release. Do not infer a release command from requests to finish, ship, implement, or push development work.
- After every non-documentation change, use `version_bump` to add one concise `Unreleased` changelog bullet. It rolls the changelog and three-part base-20 product version only at 10 bullets, or when an explicitly requested release uses `force_release`.
- For every distinct failure type discovered in VM, emulator, native/package, manual, visual, or integration testing, preserve the original failure evidence and relevant unfixed beforeimages before editing. A reversible owned fix may work before its regression is constructed. After the flow works, report the encountered failure types, known or unresolved causes, and proposed coverage; then implement every required causal regression with actual RED on the preserved unfixed source and GREEN on the fix, and add it to routine checks before integration, push, or completion. Follow `TEST-001` in `agent_docs/contracts.md`; proposals alone do not satisfy it, and the original native scenario remains required.
- If large work intentionally spans multiple dirty buckets, document the intent in `agent_docs/work-in-progress.md`.
- Start low-context repository navigation from `agent_docs/README.md`.
- Follow the resource-efficient workflow in `agent_docs/development.md`: focused context and delegation, concise evidence summaries, and batched checks. Preserve every contract, causal regression, native acceptance scenario, and exact-SHA delivery gate.
- Use `agent_docs/state-ownership.md` before adding cross-platform actions or moving platform side effects.
- Use `agent_docs/native-runtime-artifacts.md` before touching native runtime binaries or runtime preparation scripts.

## Mandatory Agent Finish

Before reporting a state-changing task complete:

1. Call `workflow_status` and verify the changed paths remain in the requested scope.
2. For non-documentation changes, call `version_bump` after the final content edit. Treat its changelog/version metadata edit as part of the task.
3. Run focused checks while iterating. The complete local `run_checks(level="prepush")` tier is optional: required CI on the candidate's `ci/*` branch is the completeness gate. Every managed pass runs to completion; after a failed pass, fix all reported failures and run `run_checks(level="failed")` first (`TEST-006`).
4. Keep commits coherent and stage only explicit reviewed paths. The managed `git_workflow` rejects generated/runtime paths and uncovered dirty changes.
5. Gate completed commits with `git_workflow(action="commit"|"push")`. It pushes the exact candidate SHA to `origin/ci/<sha12>`, waits until every required workflow in `.github/required-workflows.json` has finished for that SHA, and fast-forwards `origin/dev` to the same SHA only when all succeeded and `dev` is still its ancestor; otherwise it reports that a rebase is needed. It records the result under `.rag_index/ci-gate/` and then deletes the `ci/*` branch on origin and locally, after a merge and after a red result alike. A pending run keeps its branch; resume with `action="push"` or stop with `action="abandon"`. `action="cleanup"` deletes stale `ci/*` branches (contained in `dev`, or finished and older than `max_age_days`, default 7).
6. If a required workflow fails, inspect the bounded failed logs of every failed step, add or update a fast regression when they exposed a product defect, fix every cause, rerun the failed checks first, commit and gate again, then restart verification for the new exact SHA.

Do not report success while `origin/dev` does not contain the work, or while any expected workflow for its gated SHA (or, for a documentation-only reuse, its green reference SHA) is missing, pending, cancelled, or failed. See `agent_tools/README.md` for tool inputs, safety boundaries, CLI fallback, and RAG behavior.

## Post-Push CI Verification

Candidates reach `origin/dev` only through the `ci/*` branch gate (`RELEASE-001`):

1. Capture the exact candidate commit with `git rev-parse HEAD`; `git_workflow` pushes it to `origin/ci/<sha12>`.
2. Query GitHub Actions runs for that exact `headSha`; do not rely on branch-latest status alone. Runs match by SHA, so the fast-forward of `dev` needs no second run, and a green SHA that is already on `dev` is not rerun.
3. Track these expected workflows for that SHA until they complete (in the background while other work remains; see below):
   - Fast Checks
   - Android Release APK
   - Linux Desktop Package
   - Windows Desktop Package
   - macOS Desktop Package
4. If any expected workflow fails, inspect the failure logs of every failed step, fix every cause, rerun the failed checks locally first, commit the fix, gate again, and repeat this verification loop for the new `headSha`. The red SHA never reaches `dev`.
5. Do not report the work as complete while `origin/dev` does not contain it, or while any expected workflow for its SHA is pending, missing, or failed.

A change whose difference from a SHA with successful exact runs touches only documentation (`docs/`, `agent_docs/` and the prose files that the agent-test selector classifies as documentation, excluding `README.md`, `docs/CHANGELOG.md` and `gradle.properties`) reuses that SHA's result after `git diff --check`, `./scripts/check_docs_hygiene.sh` and the source-whitespace check pass locally. A release never reuses it: `release_workflow(action="merge-dev")` requires exact-SHA runs for the `origin/dev` SHA; `git_workflow(action="push", exact=True)` produces them.

Never idle on CI while work remains. After a gate push, continue the remaining tasks while the exact-SHA verification runs in the background (`action="checkpoint"` starts the `ci/*` runs without waiting). Fix CI failures in parallel with that work as their own commits, and rebase work in progress onto the fix before its own push. Keep pushes separate so each CI failure stays attributable to one push. Only reporting completion waits for CI: the final gated SHA must pass every expected workflow and be on `origin/dev`.

The canonical expected-workflow list is `.github/required-workflows.json`; keep that manifest aligned with the names of the push workflows above.

`VPN Integration` does not run on `dev` pushes; it runs on dispatch (the advisory `core` profile), on its weekly schedule, and as the release's explicitly dispatched `all` profile, which is mandatory for a release. A release command follows this sequence and no other request authorizes it:

1. Roll any remaining `Unreleased` notes with `version_bump(change_type="release", force_release=true)` and gate the result into `dev` with exact-SHA runs (`git_workflow(action="push", exact=True)`).
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

Agent tool or MCP changes should run `python3 agent_tools/affected_agent_tests.py --run`.
Local selection is precise: it joins static imports, literal test and fixture
paths and declared scopes with the per-test footprints CI records (fetch them with
`python3 agent_tools/agent_test_footprints.py fetch`). Product or prose-only
changes do not run the agent-tool suite. A changed agent file with no selected
consumer is reported, not refused; completeness comes from CI, which runs the
complete agent suite on every agent-input change. Use
`python3 agent_tools/affected_agent_tests.py --audit --baseline HEAD --run` only
for an intentional full-suite audit. Broad changes still use the complete managed
pre-push tier in `agent_docs/test-matrix.md`; its agent-test stage uses the same
affected selection.

Versions use three components `a.b.c`; `a` is in `1..19` and `b`/`c` are in `0..19`. Normal automatic rolls increment `c`, carrying at 20 (`2.0.19` becomes `2.1.0`, and `2.19.19` becomes `3.0.0`). `gradle.properties` is canonical and the exact same product version is used on every platform. Android version code and update build number are non-displayed monotonic IDs derived from the product version.

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
