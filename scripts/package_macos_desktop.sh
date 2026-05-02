#!/usr/bin/env bash
set -euo pipefail

skip_tests=false
skip_package_regression_tests=false

while (($#)); do
  case "$1" in
    --skip-tests)
      skip_tests=true
      shift
      ;;
    --skip-package-regression-tests)
      skip_package_regression_tests=true
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: scripts/package_macos_desktop.sh [options]

Options:
  --skip-tests                       skip Gradle desktop tests
  --skip-package-regression-tests    skip DMG smoke checks
  -h, --help                         show this help
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS desktop packaging must run on macOS" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

./scripts/check_release_hygiene.sh

echo "[vpn-control] checking Java runtime"
java -version

./scripts/prepare_sing_box_macos_runtime.sh
. ./scripts/setup_macos_signing.sh

echo "[vpn-control] compiling desktop app"
./gradlew :desktopApp:compileKotlin

if [[ "$skip_tests" != true ]]; then
  echo "[vpn-control] running desktop tests"
  ./gradlew :desktopApp:test
fi

echo "[vpn-control] building macOS desktop package"
./gradlew :desktopApp:packageDistributionForCurrentOS

output_root="$repo_root/desktopApp/build/compose/binaries/main"
dist_dir="$repo_root/dist/macos"
mkdir -p "$dist_dir"

packages=()
while IFS= read -r package; do
  packages+=("$package")
done < <(find "$output_root" -type f -name '*.dmg' | sort)
if (( ${#packages[@]} == 0 )); then
  echo "No macOS DMG artifacts were produced under $output_root" >&2
  exit 1
fi

for package in "${packages[@]}"; do
  cp "$package" "$dist_dir/"
done

(
  cd "$dist_dir"
  shasum -a 256 ./*.dmg > SHA256SUMS.txt
)

if [[ "$skip_package_regression_tests" != true ]]; then
  echo "[vpn-control] running macOS package regression tests"
  ./scripts/test_macos_desktop_package.sh "$dist_dir"
else
  echo "[vpn-control] skipping macOS package regression tests"
fi

echo "[vpn-control] macOS packages written under: $dist_dir"
printf ' - %s\n' "${packages[@]}"
