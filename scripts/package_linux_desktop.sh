#!/usr/bin/env bash
set -euo pipefail

skip_tests=false
if [[ "${1:-}" == "--skip-tests" ]]; then
  skip_tests=true
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "[vpn-control] checking Java runtime"
java -version

./scripts/prepare_sing_box_desktop_runtime.sh

echo "[vpn-control] compiling desktop app"
./gradlew :desktopApp:compileKotlin

if [[ "$skip_tests" != true ]]; then
  echo "[vpn-control] running desktop tests"
  ./gradlew :desktopApp:test
fi

echo "[vpn-control] building Linux desktop packages"
./gradlew :desktopApp:packageDistributionForCurrentOS

output_root="$repo_root/desktopApp/build/compose/binaries/main"
echo "[vpn-control] packages written under: $output_root"

mapfile -t packages < <(find "$output_root" -type f \( -name '*.deb' -o -name '*.rpm' \) | sort)
if (( ${#packages[@]} == 0 )); then
  echo "No Linux package artifacts were produced under $output_root" >&2
  exit 1
fi

printf ' - %s\n' "${packages[@]}"
