#!/usr/bin/env bash
set -euo pipefail

if (($# > 3)); then
  echo "Usage: test_linux_desktop_package.sh [package-root] [validation-root] [expected-version]" >&2
  exit 2
fi

package_root="${1:-desktopApp/build/compose/binaries/main}"
validation_root="${2:-desktopApp/build/compose/validation/linux-package}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Property-built disposable fixtures specify their expected version explicitly.
# Normal packaging keeps canonical metadata as the authority. Validate before
# clearing a previous evidence directory or invoking any packaged launcher.
expected_version="$(python3 - "$repo_root/scripts" "${3-}" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
from version_metadata import parse_version, product_version, read_version

version = sys.argv[2] or read_version(Path(sys.argv[1]).parent)
try:
    if product_version(parse_version(version)) != version:
        raise ValueError("Noncanonical version")
except ValueError:
    raise SystemExit("Expected package version must be canonical (a.b.c, each component below 20)")
print(version)
PY
)"

if [[ ! -d "$package_root" ]]; then
  echo "Package root does not exist: $package_root" >&2
  exit 1
fi
package_root="$(realpath "$package_root")"
validation_root="$(realpath -m "$validation_root")"

rm -rf "$validation_root"
mkdir -p "$validation_root"

mapfile -t deb_packages < <(find "$package_root" -type f -name '*.deb' | sort)
mapfile -t rpm_packages < <(find "$package_root" -type f -name '*.rpm' | sort)

if (( ${#deb_packages[@]} == 0 )); then
  echo "No DEB artifact was produced under $package_root" >&2
  exit 1
fi
if (( ${#rpm_packages[@]} == 0 )); then
  echo "No RPM artifact was produced under $package_root" >&2
  exit 1
fi

assert_file() {
  local path="$1"
  local message="$2"
  if [[ ! -s "$path" ]]; then
    echo "$message at $path" >&2
    exit 1
  fi
}

run_launcher_smoke() {
  local launcher="$1"
  local state_dir="$2"
  python3 "$repo_root/scripts/test_packaged_cli.py" --launcher "$launcher" \
    --expected-version "$expected_version"
  rm -rf "$state_dir"
  mkdir -p "$state_dir"
  echo "[vpn-control] running Linux package smoke test: $launcher"
  timeout 60 "$launcher" --smoke-test --smoke-test-state-dir "$state_dir"
  assert_file "$state_dir/workspace.json" "Linux package smoke test did not write workspace.json"
  assert_file "$state_dir/runtime/tools/sing-box" "Linux package smoke test did not extract bundled sing-box"
}

echo "[vpn-control] validating DEB payload: ${deb_packages[0]}"
deb_root="$validation_root/deb"
mkdir -p "$deb_root"
dpkg-deb -x "${deb_packages[0]}" "$deb_root"
deb_control="$validation_root/deb-control"
dpkg-deb -e "${deb_packages[0]}" "$deb_control"
python3 - "$repo_root/scripts" "${deb_packages[0]}" "$repo_root/desktopApp/packaging/linux/postinst" <<'PY'
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, sys.argv[1])
from package_linux_deb import verify_postinst

archive = subprocess.run(["dpkg-deb", "--ctrl-tarfile", sys.argv[2]],
                         check=True, capture_output=True).stdout
verify_postinst(archive, Path(sys.argv[3]).read_text(), "vpn-control")
PY

deb_launcher="$(find "$deb_root" -type f -path '*/bin/vpn-control' | sort | head -n 1)"
if [[ -z "$deb_launcher" ]]; then
  echo "DEB payload is missing vpn-control launcher" >&2
  exit 1
fi
assert_file "$deb_launcher" "DEB vpn-control launcher is missing"

deb_desktop="$(find "$deb_root" -type f -name '*.desktop' | sort | head -n 1)"
if [[ -z "$deb_desktop" ]]; then
  echo "DEB payload is missing a desktop entry" >&2
  exit 1
fi
assert_file "$deb_desktop" "DEB desktop entry is missing"
grep -q 'Name=.*VPN\|Name=.*vpn-control' "$deb_desktop" || {
  echo "DEB desktop entry does not describe VPN Control: $deb_desktop" >&2
  exit 1
}

run_launcher_smoke "$deb_launcher" "$validation_root/deb-smoke-state"

echo "[vpn-control] validating RPM payload: ${rpm_packages[0]}"
if command -v rpm2cpio >/dev/null 2>&1 && command -v cpio >/dev/null 2>&1; then
  rpm_root="$validation_root/rpm"
  mkdir -p "$rpm_root"
  (
    cd "$rpm_root"
    rpm2cpio "${rpm_packages[0]}" | cpio -idm --quiet
  )
  rpm_launcher="$(find "$rpm_root" -type f -path '*/bin/vpn-control' | sort | head -n 1)"
  if [[ -z "$rpm_launcher" ]]; then
    echo "RPM payload is missing vpn-control launcher" >&2
    exit 1
  fi
  assert_file "$rpm_launcher" "RPM vpn-control launcher is missing"
  run_launcher_smoke "$rpm_launcher" "$validation_root/rpm-smoke-state"
else
  echo "[vpn-control] skipping RPM extraction because rpm2cpio/cpio is unavailable"
fi

echo "[vpn-control] verified Linux package regression checks:"
echo " - deb:      ${deb_packages[0]}"
echo " - rpm:      ${rpm_packages[0]}"
echo " - launcher: $deb_launcher"
echo " - smoke:    extracted DEB launcher"
