#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

check_index() {
  local docs_dir="$1"
  local index_path="$2"
  local label="$3"
  local missing=()

  while IFS= read -r -d '' doc_path; do
    local rel_path="${doc_path#./}"
    local doc_name="${rel_path#${docs_dir}/}"
    if [[ "$doc_name" == "README.md" ]]; then
      continue
    fi
    if ! grep -Fq "$doc_name" "$index_path"; then
      missing+=("$rel_path")
    fi
  done < <(find "./$docs_dir" -type f -name '*.md' -print0 | sort -z)

  if (( ${#missing[@]} > 0 )); then
    {
      echo "$label files are missing from $index_path."
      printf ' - %s\n' "${missing[@]}"
    } >&2
    return 1
  fi
}

check_index "docs" "docs/README.md" "Public documentation"
check_index "agent_docs" "agent_docs/README.md" "Agent documentation"

python3 - <<'PY'
import pathlib
import re
import subprocess
import sys
from urllib.parse import unquote

repo = pathlib.Path.cwd()
tracked_markdown = subprocess.check_output(
    ["git", "ls-files", "*.md"], text=True
).splitlines()
files = {
    repo / path
    for path in tracked_markdown
    if (repo / path).is_file()
}
for pattern in ("*.md", "docs/**/*.md", "agent_docs/**/*.md", "agent_tools/**/*.md"):
    files.update(path for path in repo.glob(pattern) if path.is_file())
files = sorted(files)

link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
backtick_path_pattern = re.compile(
    r"`((?:\.\./|\./)?(?:(?:docs|agent_docs|agent_tools)/)?"
    r"[A-Za-z0-9_.-]+\.md(?:#[A-Za-z0-9_.%-]+)?)`"
)
missing = []
missing_anchors = []


def slugify(heading: str) -> str:
    heading = re.sub(r"<[^>]+>", "", heading)
    heading = re.sub(r"`([^`]*)`", r"\1", heading)
    heading = heading.strip().lower()
    heading = re.sub(r"[^\w\s-]", "", heading, flags=re.UNICODE)
    return re.sub(r"\s+", "-", heading)


def anchors_for(path: pathlib.Path) -> set[str]:
    anchors = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if match:
            anchors.add(slugify(match.group(2)))
    return anchors


for file_path in files:
    text = file_path.read_text(encoding="utf-8")
    targets = [(match.group(1).strip(), False) for match in link_pattern.finditer(text)]
    targets.extend((match.group(1).strip(), True) for match in backtick_path_pattern.finditer(text))
    for target, repo_rooted_hint in targets:
        if not target or target.startswith("#"):
            continue
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
            continue
        target = target.split()[0]
        path_target, _, anchor = target.partition("#")
        path_target = path_target.split("?", 1)[0]
        if not path_target:
            continue
        decoded = unquote(path_target)
        if repo_rooted_hint and not decoded.startswith(("./", "../")):
            sibling = file_path.parent / decoded
            base = file_path.parent if "/" not in decoded and sibling.exists() else repo
        else:
            base = file_path.parent
        resolved = (base / decoded).resolve()
        try:
            resolved.relative_to(repo)
        except ValueError:
            continue
        if not resolved.exists():
            missing.append(f"{file_path.relative_to(repo)} -> {path_target}")
            continue
        if anchor and resolved.suffix == ".md":
            expected = unquote(anchor).lower()
            if expected not in anchors_for(resolved):
                missing_anchors.append(
                    f"{file_path.relative_to(repo)} -> {path_target}#{anchor}"
                )

if missing:
    print("Markdown links point to missing local paths.", file=sys.stderr)
    for item in missing:
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)

if missing_anchors:
    print("Markdown links point to missing local anchors.", file=sys.stderr)
    for item in missing_anchors:
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)
PY

public_scan="$(mktemp)"
trap 'rm -f "$public_scan"' EXIT

if grep -nE '(^|[^[:alnum:]_])((dist|\.runtime|app/build|desktopApp/build|desktopApp/src/main/resources/bin)([/\\]|$)|shared/[^[:space:]]*/build[/\\]|build/compose|app/build/outputs)' README.md docs/*.md >"$public_scan"; then
  {
    echo "User-facing documentation contains local generated artifact paths."
    echo "Keep local build and runtime paths in agent_docs/:"
    sed 's/^/ - /' "$public_scan"
  } >&2
  exit 1
fi

echo "[vpn-control] docs hygiene passed"
