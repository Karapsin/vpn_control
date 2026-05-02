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
Usage: scripts/package_linux_desktop.sh [options]

Options:
  --skip-tests                       skip Gradle desktop tests
  --skip-package-regression-tests    skip extracted package smoke checks
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

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

./scripts/check_release_hygiene.sh

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

if [[ "$skip_package_regression_tests" != true ]]; then
  echo "[vpn-control] running Linux package regression tests"
  ./scripts/test_linux_desktop_package.sh "$output_root"
else
  echo "[vpn-control] skipping Linux package regression tests"
fi
