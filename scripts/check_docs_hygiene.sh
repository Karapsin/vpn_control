#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

docs_index="docs/README.md"
missing_docs=()

while IFS= read -r -d '' doc_path; do
  rel_path="${doc_path#./}"
  doc_name="${rel_path#docs/}"
  if [[ "$doc_name" == "README.md" ]]; then
    continue
  fi
  if ! grep -Eq "^[|][[:space:]]*\`$doc_name\`[[:space:]]*[|]" "$docs_index"; then
    missing_docs+=("$rel_path")
  fi
done < <(find ./docs -maxdepth 1 -type f -name '*.md' -print0 | sort -z)

if (( ${#missing_docs[@]} > 0 )); then
  {
    echo "Documentation files are missing from docs/README.md."
    echo "Add each file to the authoritative docs index or archive it outside docs/:"
    printf ' - %s\n' "${missing_docs[@]}"
  } >&2
  exit 1
fi

python3 - <<'PY'
import pathlib
import re
import subprocess
import sys
from urllib.parse import unquote

repo = pathlib.Path.cwd()
root_doc_names = set()
for path in subprocess.check_output(["git", "ls-files", "*.md"], text=True).splitlines():
    if "/" not in path:
        root_doc_names.add(path)
for path in repo.glob("*.md"):
    root_doc_names.add(path.name)
root_docs = [repo / path for path in root_doc_names]
files = sorted(root_docs) + sorted((repo / "docs").glob("*.md"))
link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
backtick_path_pattern = re.compile(r"`((?:\.\./|\.\/)?(?:docs/)?[A-Za-z0-9_.-]+\.md(?:#[A-Za-z0-9_.%-]+)?)`")
missing = []
missing_anchors = []
ambiguous_root_readme_refs = []

def slugify(heading: str) -> str:
    heading = re.sub(r"<[^>]+>", "", heading)
    heading = re.sub(r"`([^`]*)`", r"\1", heading)
    heading = heading.strip().lower()
    heading = re.sub(r"[^\w\s-]", "", heading, flags=re.UNICODE)
    heading = re.sub(r"\s+", "-", heading)
    return heading

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
        if file_path.parent == repo / "docs" and path_target == "README.md":
            ambiguous_root_readme_refs.append(str(file_path.relative_to(repo)))
            continue
        if repo_rooted_hint and not path_target.startswith(("./", "../")):
            if "/" not in path_target and (file_path.parent / unquote(path_target)).exists():
                base = file_path.parent
            else:
                base = repo
        else:
            base = file_path.parent
        resolved = (base / unquote(path_target)).resolve()
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
                missing_anchors.append(f"{file_path.relative_to(repo)} -> {path_target}#{anchor}")

if missing:
    print("Markdown links point to missing local paths.", file=sys.stderr)
    print("Fix or remove these links:", file=sys.stderr)
    for item in missing:
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)

if missing_anchors:
    print("Markdown links point to missing local anchors.", file=sys.stderr)
    print("Fix or remove these links:", file=sys.stderr)
    for item in missing_anchors:
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)

if ambiguous_root_readme_refs:
    print("Docs under docs/ must use ../README.md for the repository root README.", file=sys.stderr)
    print("Bare README.md is ambiguous with docs/README.md in:", file=sys.stderr)
    for item in sorted(set(ambiguous_root_readme_refs)):
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)
PY

readme_scan="$(mktemp)"
trap 'rm -f "$readme_scan"' EXIT

if grep -nE '(^|[^[:alnum:]_])((dist|\.runtime|app/build|desktopApp/build|desktopApp/src/main/resources/bin)([/\\]|$)|shared/[^[:space:]]*/build[/\\]|build/compose|app/build/outputs)' README.md >"$readme_scan"; then
  {
    echo "User-facing README.md contains local generated artifact paths."
    echo "Point users to GitHub Actions artifacts; keep local dist/build paths in developer docs only:"
    sed 's/^/ - /' "$readme_scan"
  } >&2
  exit 1
fi

echo "[vpn-control] docs hygiene passed"
