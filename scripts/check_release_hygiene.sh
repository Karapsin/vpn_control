#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bad_paths=()
while IFS= read -r -d '' path; do
  case "$path" in
    build/*|\
    app/build/*|\
    shared/*/build/*|\
    desktopApp/build/*|\
    desktopApp/src/main/resources/bin/*|\
    dist/*|\
    .runtime/*)
      bad_paths+=("$path")
      ;;
  esac
done < <(git ls-files -z)

if (( ${#bad_paths[@]} > 0 )); then
  {
    echo "Generated release/runtime artifacts are tracked by Git."
    echo "Remove these files from the index before packaging:"
    printf ' - %s\n' "${bad_paths[@]}"
  } >&2
  exit 1
fi

bash scripts/check_docs_hygiene.sh

echo "[vpn-control] release hygiene passed"
