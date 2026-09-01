# Work In Progress Notes

Use this file only when a large task intentionally leaves multiple buckets changed at once. If the worktree is clean or changes are small, leave this file as a template.

## Current Work

No active multi-bucket work is documented here.

## Template

When needed, replace the current-work line with:

```text
Owner:
Date:
Branch:
Goal:

Changed buckets:
- Documentation:
- Android runtime/config/UI:
- Desktop runtime/tray/lifecycle:
- Shared core/model/storage:
- Shared UI/localization:
- Packaging/CI:

Validation already run:
-

Known unfinished work:
-

Files that are intentionally dirty:
-

Files that look accidental and need classification:
-
```

## Rules

- Do not use this file as a changelog for ordinary small patches.
- Do not list generated artifacts as intentional dirty files.
- Remove stale notes once the work is committed, stashed, or abandoned.
- If a file looks accidental, classify it before deleting it.
