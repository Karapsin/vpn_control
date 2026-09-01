# Development Guide

This guide is the workflow guide for agents and maintainers working on VPN Control. The authoritative docs entry point is `agent_docs/README.md`.

For a complete docs index, start with `agent_docs/README.md`.

## Source And Generated Boundaries

Source files that should be edited and committed:

- Kotlin source under `app/`, `desktopApp/`, and `shared/`.
- Localization catalogs under `shared/ui/src/commonMain/resources/i18n/`.
- Status localization catalogs under `shared/ui/src/commonMain/resources/i18n-status/`.
- Language manifest at `shared/model/src/commonMain/resources/languages.json`.
- Public documentation under `README.md` and `docs/`.
- Agent documentation and tooling under `AGENTS.md`, `agent_docs/`, `agent_tools/`, and `.codex/config.toml`.
- Scripts under `scripts/`.

Generated or local files that should not be committed:

- `build/`
- `dist/`
- `.runtime/`
- downloaded or extracted `sing-box` runtime binaries
- agent-only environments and indexes under `.agent_venv/` and `.rag_index/`
- Gradle caches and IDE state

Generated Kotlin for languages/catalogs is produced during the Gradle build. Do not patch generated Kotlin directly.

## Dirty Worktree Policy

Treat a dirty worktree as unclassified work, not junk.

Before changing files in a dirty worktree:

```bash
git status --short
git diff --stat
git diff --name-status
```

Classify changes by bucket before staging:

- Public documentation: `README.md`, `docs/`.
- Agent instructions and tooling: `AGENTS.md`, `agent_docs/`, `agent_tools/`, `.codex/config.toml`.
- Android runtime/config/UI: `app/`.
- Desktop runtime/tray/lifecycle: `desktopApp/`.
- Shared model/core behavior: `shared/model/`, `shared/core/`, `shared/storage-api/`.
- Shared UI/localization: `shared/ui/`.
- Packaging/VM/release: `scripts/`, `.github/workflows/`.
- Accidental local files: marker files, caches, downloaded artifacts.

If a large task intentionally spans several buckets, document the current intent in `agent_docs/work-in-progress.md` before handing off to another agent.

Do not use broad cleanup commands such as `git reset --hard` or `git checkout -- .` unless the user explicitly approves it. Preserve unrelated local changes.

## Common Patch Workflow

1. Identify the smallest behavior or documentation unit.
2. Inspect the owner files and existing tests.
3. Patch only that unit.
4. Run the relevant tests from `agent_docs/test-matrix.md`.
5. Report exactly what was changed and what was not tested.

Keep unrelated docs, localization, Android runtime, desktop runtime, and packaging changes in separate staging units or commits.

## Low-Context Patch Workflow

When you enter the repository without fresh context, route the task before editing:

1. Start from the task router in `agent_docs/README.md`.
2. Read only the two or three focused docs named by that route.
3. Check the dirty worktree with `git status --short`, `git diff --stat`, and `git diff --name-status`.
4. Inspect the owner files named by `agent_docs/architecture.md`, `agent_docs/state-ownership.md`, or the focused subsystem doc.
5. Choose the smallest patch unit that does not mix unrelated buckets.
6. Run the minimum validation tier from `agent_docs/test-matrix.md`; expand to a boundary or full tier when the patch crosses subsystem boundaries.
7. Report changed areas, checks run, and checks skipped with the reason.

If the docs disagree, treat `AGENTS.md` as the hard-rule layer and the focused docs as the subsystem detail layer. Fix the contradiction as part of the patch when the answer is clear; otherwise call it out explicitly.

## Repository Agent Lifecycle

Use the project MCP lifecycle described in `agent_tools/README.md`. `prepare_start` performs the dirty-aware synchronization and routes the task before inspection. `docs` and `change_impact` provide focused repository context from the local documentation index. `workflow_status` makes the current dirty scope and missing actions visible.

After the final edit, the complete `run_checks(level="prepush")` tier creates a receipt tied to the repository's content fingerprint. Committing the same validated content does not invalidate that receipt, but any content or mode change does. Use managed push/checks to verify the exact commit SHA against `.github/required-workflows.json`.

The MCP server is agent-only infrastructure. Its environment and index remain ignored in `.agent_venv/` and `.rag_index/`; the application build must not depend on either directory.

## Runtime Safety

Do not stop a running VPN/runtime unless the user explicitly approves it. Stopping VPN can interrupt the active coding session.

Use read-only diagnostics first:

- Inspect `~/.vpn-control-desktop/workspace.json`.
- Inspect `~/.vpn-control-desktop/runtime/runtime-sing-box.log`.
- Inspect generated runtime config JSON under `~/.vpn-control-desktop/runtime/`.
- Use process listing commands before killing anything.

See `agent_docs/runtime-troubleshooting.md` for the safe diagnostic path.

## Where To Look Next

- Platform behavior and limitations: `agent_docs/platform-matrix.md`.
- State/action ownership: `agent_docs/state-ownership.md`.
- Test selection: `agent_docs/test-matrix.md`.
- Runtime logs and safe checks: `agent_docs/runtime-troubleshooting.md`.
- Architecture and data flow: `agent_docs/architecture.md`.
- Desktop lifecycle invariants: `agent_docs/desktop-lifecycle.md`.
- sing-box config contract: `agent_docs/sing-box-contract.md`.
- Native runtime artifact policy: `agent_docs/native-runtime-artifacts.md`.
- Large dirty-state handoff template: `agent_docs/work-in-progress.md`.
- Localization architecture: `agent_docs/localization.md`.
- Developer release packaging: `agent_docs/developer-release-checklist.md`.
- Android protocol smoke testing: `agent_docs/smoke-android.md`.
- Desktop smoke testing: `agent_docs/desktop-smoke-testing.md`.
