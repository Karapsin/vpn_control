#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
THEME = ROOT / "shared/ui/src/commonMain/kotlin/com/kardinal/vpncontrol/shared/ui/VpnControlTheme.kt"
ANDROID_ROOT = ROOT / "app/src/main/java/com/kardinal/vpncontrol/MainActivity.kt"
ANDROID_APP = ROOT / "app/src/main/java/com/kardinal/vpncontrol/ui/VpnControlApp.kt"
DESKTOP_ROOT = ROOT / "desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/Main.kt"
ANDROID_THEME = ROOT / "app/src/main/res/values/themes.xml"
ANDROID_COLORS = ROOT / "app/src/main/res/values/colors.xml"


def main() -> int:
    errors: list[str] = []
    theme = THEME.read_text(encoding="utf-8")
    required = {
        "Navy950": "0xFF08111F",
        "Navy800": "0xFF12304B",
        "Navy700": "0xFF16496B",
        "Surface": "0xFF141F2D",
        "SurfaceElevated": "0xFF1D2B3B",
        "Primary": "0xFF4B7BE5",
        "Accent": "0xFF9ED6FF",
        "TextPrimary": "0xFFFFFFFF",
        "TextSecondary": "0xFFD3E3EE",
        "TextMuted": "0xFF94A9B8",
    }
    for name, literal in required.items():
        if f"val {name} = Color({literal})" not in theme:
            errors.append(f"fixed palette token {name} must remain {literal}")
    if "darkColorScheme(" not in theme or "fun VpnControlTheme" not in theme:
        errors.append("VpnControlTheme must own the fixed dark Material color scheme")
    if "lightColorScheme(" in theme or "dynamicDarkColorScheme(" in theme:
        errors.append("light and dynamic color schemes are not supported")
    android_root = ANDROID_ROOT.read_text(encoding="utf-8")
    android_app = ANDROID_APP.read_text(encoding="utf-8")
    desktop_root = DESKTOP_ROOT.read_text(encoding="utf-8")
    if "VpnControlTheme {" not in android_root:
        errors.append("Android root must use VpnControlTheme")
    if "VpnControlTheme {" not in desktop_root:
        errors.append("Desktop root must use VpnControlTheme")
    if "VpnControlColors.AppBackground" not in android_app:
        errors.append("Android app background must use the shared navy gradient")
    if "VpnControlColors.AppBackground" not in desktop_root:
        errors.append("Desktop app background must use the shared navy gradient")
    if "@color/vpn_control_navy_950" not in ANDROID_THEME.read_text(encoding="utf-8"):
        errors.append("Android navigation chrome must use the fixed navy background")
    if "#08111F" not in ANDROID_COLORS.read_text(encoding="utf-8"):
        errors.append("Android navy resource must match the shared theme")
    production_roots = [
        ROOT / "app/src/main",
        ROOT / "desktopApp/src/main",
        ROOT / "shared/ui/src/commonMain",
    ]
    for source_root in production_roots:
        for path in source_root.rglob("*.kt"):
            if "VpnControlTheme.kt" == path.name:
                continue
            source = path.read_text(encoding="utf-8")
            if "0xFF3D6B59" in source or "0x332A3E12" in source:
                errors.append(f"retired decorative green remains in {path.relative_to(ROOT)}")
    if errors:
        print("UI theme contract failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    print("[vpn-control] fixed navy/azure theme contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
