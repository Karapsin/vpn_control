# CLAUDE.md

@AGENTS.md

## Claude Code Connection

- `AGENTS.md` above holds every repository rule; this file only adds Claude Code connection notes.
- The tracked `.mcp.json` starts the `vpn_control` project server through `agent_tools/mcp_server.sh`, and `.claude/settings.json` approves only that server and its `mcp__vpn_control__*` tools after you trust the workspace.
- Check the connection with `/mcp`. Restart the session after changing `.mcp.json`, `.claude/settings.json`, or the launcher; a running session does not reload its MCP inventory.
- When the transport is unavailable, use the equivalent `agent_tools/mcp_tool.sh` command and report the MCP limitation.
- Read routed documentation per task from `agent_docs/README.md`; do not import it wholesale.
- Personal overrides belong in ignored `.claude/settings.local.json` and a root CLAUDE.local.md file.
