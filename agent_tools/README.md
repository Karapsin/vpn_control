# VPN Control Agent Tools

This directory contains the repository-local MCP workflow server and its documentation RAG indexer. These tools are for coding agents and maintainers; they are not part of the VPN Control application or its user setup.

## Automatic MCP Setup

The tracked project configuration in `.codex/config.toml` starts `agent_tools/mcp_server.sh` for trusted checkouts. The launcher:

1. Locates Python 3.
2. Creates the ignored `.agent_venv/` environment when needed.
3. Installs `requirements-mcp.txt` only when the requirements hash changes or `mcp` is missing.
4. Starts the STDIO server with all operational logging on stderr so the protocol on stdout remains clean.

Do not commit `.agent_venv/` or `.rag_index/`. Restart the Codex session after changing project MCP configuration because a running session does not reload its MCP inventory.

## Mandatory Lifecycle

For implementation, testing, release, or commit work:

1. Call `prepare_start(task, area)` before normal repository inspection, edits, or tests. It fetches `origin/dev` and `origin/main`, selects and safely fast-forwards the `dev` development branch only when the worktree is clean, and rebuilds the local docs index.
2. Read the returned instruction files. Use `docs` and `change_impact` instead of broad exploratory searches when repository documentation can answer the question.
3. Use `workflow_status` while working to re-check routing, dirty paths, index freshness, and validation requirements.
4. Run `version_bump` once after the final non-documentation content change, then run `run_checks(level="prepush")`. A successful check writes a content fingerprint to `.rag_index/prepush_receipt.json`.
5. Use `git_workflow` to push `dev` or to resume checks for a full commit SHA. It queries only runs attached to that exact SHA and requires every development workflow in `.github/required-workflows.json` to succeed.
6. Use `release_workflow` only after an explicit user release command. It fast-forwards `main` from verified `dev`, gates on exhaustive VPN integration, and dispatches the manual publisher.

`prepare_start` deliberately blocks when a fetch fails, branches diverge, a dirty branch other than `dev` would need switching, or a dirty behind-`dev` worktree would need pulling. Resolve the reported condition explicitly and rerun it.

## MCP Tools

| Tool | Purpose |
| --- | --- |
| `prepare_start(task, area=None)` | Safe fetch/sync, branch verification, RAG rebuild, and task routing. |
| `docs(query, mode="search", top_k=3)` | Search or produce a grounded extractive answer with file-and-line citations. |
| `change_impact(task, area=None, paths=None)` | Combine task routing, changed paths, RAG references, safety constraints, and checks. |
| `workflow_status(task=None, area=None, instructions_read=False)` | Show worktree state, required reading, RAG freshness, and check receipt state. |
| `run_checks(area="auto", level="focused", dry_run=False)` | Run focused checks or the repository's complete pre-push tier. |
| `version_bump(summary=None, change_type="code", dry_run=False, force_release=False)` | Add the required changelog note and atomically roll four-part version metadata at 10 notes or explicit forced release. |
| `git_workflow(action, message=None, paths=None, sha=None)` | Commit explicit safe paths, push `dev`, and/or watch exact-SHA CI. |
| `release_workflow(action="status")` | Explicit-release-only `merge-dev`, readiness, and publisher dispatch gate. |

The MCP server has no root parameter: all operations are fixed to this checkout. Commit paths reject absolute paths, traversal, pathspec magic, globs, generated output, agent state, runtime state, and native runtime binaries. A commit path list must cover every current change, preventing accidental partial staging of unknown work.

## Command-Line Fallback

The same operations are available without MCP through `agent_tools/mcp_tool.sh`:

```bash
./agent_tools/mcp_tool.sh prepare-start "update settings copy" --area localization
./agent_tools/mcp_tool.sh docs "which checks cover localization?" --mode ask
./agent_tools/mcp_tool.sh change-impact "update settings copy" --area localization
./agent_tools/mcp_tool.sh workflow-status --task "update settings copy" --instructions-read
./agent_tools/mcp_tool.sh version-bump --summary "Clarified settings copy" --change-type code
./agent_tools/mcp_tool.sh run-checks --level prepush
./agent_tools/mcp_tool.sh git-workflow checks --sha <full-commit-sha>
./agent_tools/mcp_tool.sh release-workflow status
```

Use the CLI fallback only when the MCP transport is unavailable. It returns the same structured JSON and a nonzero status for blockers or failed checks.

## Documentation RAG

`docs_assistant.py` indexes `AGENTS.md`, the public `README.md` and `docs/`, all `agent_docs/`, and this file. Markdown is split under its heading hierarchy and stored with source type, relative path, and line metadata. Search uses a local BM25-style scorer plus small path/source boosts; no document content leaves the machine and no embedding service or API key is needed.

The index is rebuilt when its source hash manifest is missing or stale:

```bash
python3 agent_tools/docs_assistant.py index
python3 agent_tools/docs_assistant.py search "desktop lifecycle"
python3 agent_tools/docs_assistant.py ask "what must happen after push?"
```

The index is a navigation aid. `AGENTS.md` remains the hard-rule layer, and focused subsystem docs remain the source of detailed requirements.

## Tests

Run the stdlib-only unit suite with:

```bash
python3 -m unittest discover -s agent_tools/tests
```

The complete local pre-push tier is documented in `agent_docs/test-matrix.md` and is also encoded by `run_checks(level="prepush")`.
