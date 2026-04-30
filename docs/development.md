# Development Guide

This guide is the workflow guide for agents and maintainers working on VPN Control. The authoritative docs entry point is `docs/README.md`.

For a complete docs index, start with `docs/README.md`.

## Source And Generated Boundaries

Source files that should be edited and committed:

- Kotlin source under `app/`, `desktopApp/`, and `shared/`.
- Localization catalogs under `shared/ui/src/commonMain/resources/i18n/`.
- Status localization catalogs under `shared/ui/src/commonMain/resources/i18n-status/`.
- Language manifest at `shared/model/src/commonMain/resources/languages.json`.
- Documentation under `docs/`, `README.md`, `AGENTS.md`, and root checklists.
- Scripts under `scripts/`.

Generated or local files that should not be committed:

- `build/`
- `dist/`
- `.runtime/`
- downloaded or extracted `sing-box` runtime binaries
- local marker files such as `.codex`, which is ignored by `.gitignore`
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

- Documentation: `README.md`, `AGENTS.md`, `docs/`, root checklists.
- Android runtime/config/UI: `app/`.
- Desktop runtime/tray/lifecycle: `desktopApp/`.
- Shared model/core behavior: `shared/model/`, `shared/core/`, `shared/storage-api/`.
- Shared UI/localization: `shared/ui/`.
- Packaging/VM/release: `scripts/`, `.github/workflows/`.
- Accidental local files: marker files, caches, downloaded artifacts.

If a large task intentionally spans several buckets, document the current intent in `docs/work-in-progress.md` before handing off to another agent.

Do not use broad cleanup commands such as `git reset --hard` or `git checkout -- .` unless the user explicitly approves it. Preserve unrelated local changes.

## Common Patch Workflow

1. Identify the smallest behavior or documentation unit.
2. Inspect the owner files and existing tests.
3. Patch only that unit.
4. Run the relevant tests from `docs/test-matrix.md`.
5. Report exactly what was changed and what was not tested.

Keep unrelated docs, localization, Android runtime, desktop runtime, and packaging changes in separate staging units or commits.

## Runtime Safety

Do not stop a running VPN/runtime unless the user explicitly approves it. Stopping VPN can interrupt the active coding session.

Use read-only diagnostics first:

- Inspect `~/.vpn-control-desktop/workspace.json`.
- Inspect `~/.vpn-control-desktop/runtime/runtime-sing-box.log`.
- Inspect generated runtime config JSON under `~/.vpn-control-desktop/runtime/`.
- Use process listing commands before killing anything.

See `docs/runtime-troubleshooting.md` for the safe diagnostic path.

## Where To Look Next

- Platform behavior and limitations: `docs/platform-matrix.md`.
- Test selection: `docs/test-matrix.md`.
- Runtime logs and safe checks: `docs/runtime-troubleshooting.md`.
- Architecture and data flow: `docs/architecture.md`.
- Desktop lifecycle invariants: `docs/desktop-lifecycle.md`.
- sing-box config contract: `docs/sing-box-contract.md`.
- Large dirty-state handoff template: `docs/work-in-progress.md`.
- Localization architecture: `docs/localization.md`.
- Developer release packaging: `docs/developer-release-checklist.md`.
- Android protocol smoke testing: `docs/smoke-android.md`.
- Desktop smoke testing: `docs/desktop-smoke-testing.md`.
