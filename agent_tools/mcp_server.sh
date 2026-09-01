#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
requirements="$repo_root/agent_tools/requirements-mcp.txt"
environment="$repo_root/.agent_venv"
marker="$environment/.requirements.sha256"

bootstrap=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1; then
    bootstrap="$candidate"
    break
  fi
done
if [[ -z "$bootstrap" ]]; then
  echo "[vpn-control MCP] Python 3 is required." >&2
  exit 1
fi

venv_python="$environment/bin/python"
if [[ ! -x "$venv_python" && -x "$environment/Scripts/python.exe" ]]; then
  venv_python="$environment/Scripts/python.exe"
fi
if [[ ! -x "$venv_python" ]]; then
  echo "[vpn-control MCP] Creating .agent_venv ..." >&2
  "$bootstrap" -m venv "$environment" >&2
  venv_python="$environment/bin/python"
  if [[ ! -x "$venv_python" && -x "$environment/Scripts/python.exe" ]]; then
    venv_python="$environment/Scripts/python.exe"
  fi
fi

requirements_hash="$("$bootstrap" -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$requirements")"
installed_hash=""
if [[ -f "$marker" ]]; then
  installed_hash="$(<"$marker")"
fi
if [[ "$requirements_hash" != "$installed_hash" ]] || ! "$venv_python" -c 'import mcp' >/dev/null 2>&1; then
  echo "[vpn-control MCP] Installing agent-only dependencies ..." >&2
  "$venv_python" -m pip install --disable-pip-version-check -r "$requirements" >&2
  printf '%s\n' "$requirements_hash" >"$marker"
fi

exec "$venv_python" "$repo_root/agent_tools/mcp_server.py" serve
