#!/usr/bin/env bash
set -euo pipefail

skip_build=false
skip_release_hygiene=false
while (($#)); do
  case "$1" in
    --skip-build) skip_build=true ;;
    # package_linux_desktop.sh passes this after running hygiene itself.
    --skip-release-hygiene) skip_release_hygiene=true ;;
    *)
      echo "Usage: package_arch_desktop_update.sh [--skip-build] [--skip-release-hygiene]" >&2
      exit 2
      ;;
  esac
  shift
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
if [[ "$skip_release_hygiene" != true ]]; then
  ./scripts/check_release_hygiene.sh
fi

if [[ "$skip_build" != true ]]; then
  ./scripts/prepare_sing_box_desktop_runtime.sh
  ./gradlew :desktopApp:createDistributable
fi

app_image="$repo_root/desktopApp/build/compose/binaries/main/app/vpn-control"
runtime="$repo_root/desktopApp/src/main/resources/bin/linux-amd64/sing-box"
display_version="$(python3 scripts/version_metadata.py --field version)"
dist_dir="$repo_root/dist/arch"
staging_root="$repo_root/desktopApp/build/compose/arch-update/vpn-control-arch-update"
archive="$dist_dir/vpn-control-arch-x86_64-$display_version.tar.gz"

[[ -x "$app_image/bin/vpn-control" ]] || { echo "Missing app image: $app_image" >&2; exit 1; }
[[ -x "$runtime" ]] || { echo "Missing sing-box runtime: $runtime" >&2; exit 1; }

rm -rf "$(dirname "$staging_root")" "$dist_dir"
mkdir -p "$staging_root" "$dist_dir"
cp -a "$app_image" "$staging_root/app"
install -m755 "$runtime" "$staging_root/sing-box"
install -m755 "$repo_root/scripts/install_arch_desktop_update.sh" "$staging_root/install.sh"
printf '%s\n' "$display_version" > "$staging_root/VERSION"

tar -czf "$archive" -C "$(dirname "$staging_root")" "$(basename "$staging_root")"
(
  cd "$dist_dir"
  sha256sum "$(basename "$archive")" > SHA256SUMS.txt
)

echo "[vpn-control] Arch update bundle written to: $archive"
