#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The MCP server has agent-only dependencies (including cryptography).  A
# system Python can exist without them, so use the repository environment when
# it has already been created instead of silently falling through to PATH.
venv_python="$repo_root/.agent_venv/bin/python"
if [[ ! -x "$venv_python" && -x "$repo_root/.agent_venv/Scripts/python.exe" ]]; then
  venv_python="$repo_root/.agent_venv/Scripts/python.exe"
fi
if [[ -x "$venv_python" ]]; then
  if ! "$venv_python" -c 'import cryptography, mcp' >/dev/null 2>&1; then
    echo "Repository MCP environment is missing required dependencies. Run ./agent_tools/mcp_server.sh to repair .agent_venv." >&2
    exit 1
  fi
  exec "$venv_python" "$repo_root/agent_tools/mcp_server.py" "$@"
fi

for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1; then
    exec "$candidate" "$repo_root/agent_tools/mcp_server.py" "$@"
  fi
done
echo "Python 3 is required." >&2
exit 1
