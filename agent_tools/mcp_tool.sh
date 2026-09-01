#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1; then
    exec "$candidate" "$repo_root/agent_tools/mcp_server.py" "$@"
  fi
done
echo "Python 3 is required." >&2
exit 1
