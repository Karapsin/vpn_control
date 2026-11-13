#!/usr/bin/env python3
"""Static guard for the fixed VPN Control appearance (UI-001 to UI-003)."""
from __future__ import annotations

import pathlib
import re
import sys
from typing import Iterator


ROOT = pathlib.Path(__file__).resolve().parents[1]
THEME = pathlib.Path("shared/ui/src/commonMain/kotlin/com/kardinal/vpncontrol/shared/ui/VpnControlTheme.kt")
ANDROID_ROOT = pathlib.Path("app/src/main/java/com/kardinal/vpncontrol/MainActivity.kt")
ANDROID_APP = pathlib.Path("app/src/main/java/com/kardinal/vpncontrol/ui/VpnControlApp.kt")
DESKTOP_ROOT = pathlib.Path("desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/Main.kt")
ANDROID_THEME = pathlib.Path("app/src/main/res/values/themes.xml")
ANDROID_COLORS = pathlib.Path("app/src/main/res/values/colors.xml")
PRODUCTION_ROOTS = (
    pathlib.Path("app/src/main"),
    pathlib.Path("desktopApp/src/main"),
    pathlib.Path("shared/ui/src/commonMain"),
)

PALETTE = {
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

# UI-002 names two surfaces. Each Material surface role must name one of them,
# so that no component can fall back to a Material default surface. Dropdown
# menus read surfaceContainer and dialogs read surfaceContainerHigh.
SURFACE_ROLES = {
    "surface": "Surface",
    "surfaceVariant": "SurfaceElevated",
    "surfaceDim": "Surface",
    "surfaceBright": "SurfaceElevated",
    "surfaceContainerLowest": "Surface",
    "surfaceContainerLow": "Surface",
    "surfaceContainer": "SurfaceElevated",
    "surfaceContainerHigh": "Surface",
    "surfaceContainerHighest": "SurfaceElevated",
}
# The other roles of the Material 3 color scheme. Each must be assigned from the
# palette too; VpnControlThemeColorSchemeTest compares the complete resolved
# scheme with Material's own defaults, including roles a newer Material adds.
OTHER_ROLES = (
    "primary", "onPrimary", "primaryContainer", "onPrimaryContainer", "inversePrimary",
    "secondary", "onSecondary", "secondaryContainer", "onSecondaryContainer",
    "tertiary", "onTertiary", "tertiaryContainer", "onTertiaryContainer",
    "background", "onBackground", "onSurface", "onSurfaceVariant", "surfaceTint",
    "inverseSurface", "inverseOnSurface", "error", "onError", "errorContainer",
    "onErrorContainer", "outline", "outlineVariant", "scrim",
)
# Dialogs paint the base surface and dropdown menus the elevated one (UI-002).
CONTAINER_SURFACES = {"AlertDialog": "Surface", "DropdownMenu": "SurfaceElevated"}
PALETTE_EXPRESSION = re.compile(r"VpnControlColors\.[A-Za-z0-9]+(\.copy\(alpha = [0-9.]+f\))?")
MASKED_START = re.compile(r"//|/\*|\"|'")
NOT_NEWLINE = re.compile(r"[^\n]")


def mask_kotlin(source: str) -> str:
    """Blank comments and string or character literals, keeping every offset and newline."""
    size = len(source)

    def skip_character(start: int) -> int:
        index = start + (3 if source.startswith("\\", start + 1) else 2)
        while index < size and source[index] not in "'\n":
            index += 1
        return min(index + 1, size)

    def skip_template(index: int) -> int:
        depth = 1
        while index < size and depth:
            if source.startswith('"""', index):
                index = skip_raw_string(index)
            elif source[index] == '"':
                index = skip_string(index)
            elif source[index] == "'":
                index = skip_character(index)
            else:
                depth += {"{": 1, "}": -1}.get(source[index], 0)
                index += 1
        return index

    def skip_string(start: int) -> int:
        index = start + 1
        while index < size and source[index] != "\n":
            if source[index] == "\\":
                index += 2
            elif source[index] == '"':
                return index + 1
            elif source.startswith("${", index):
                index = skip_template(index + 2)
            else:
                index += 1
        return min(index, size)

    def skip_raw_string(start: int) -> int:
        index = start + 3
        while index < size:
            if source.startswith("${", index):
                index = skip_template(index + 2)
            elif source.startswith('"""', index):
                index += 3
                while index < size and source[index] == '"':
                    index += 1
                return index
            else:
                index += 1
        return size

    def skip_block_comment(start: int) -> int:
        depth, index = 1, start + 2
        while index < size and depth:
            if source.startswith("/*", index):
                depth, index = depth + 1, index + 2
            elif source.startswith("*/", index):
                depth, index = depth - 1, index + 2
            else:
                index += 1
        return index

    parts: list[str] = []
    index = 0
    while match := MASKED_START.search(source, index):
        start = match.start()
        if match.group() == "//":
            end = source.find("\n", start)
            end = size if end < 0 else end
        elif match.group() == "/*":
            end = skip_block_comment(start)
        elif source.startswith('"""', start):
            end = skip_raw_string(start)
        elif match.group() == '"':
            end = skip_string(start)
        else:
            end = skip_character(start)
        parts.append(source[index:start])
        parts.append(NOT_NEWLINE.sub(" ", source[start:end]))
        index = end
    parts.append(source[index:])
    return "".join(parts)


def call_arguments(
    source: str, names: tuple[str, ...], masked: str | None = None,
) -> Iterator[tuple[str, int, dict[str, str]]]:
    """Yield (callee, line, named arguments) for each call; arguments of nested calls and lambdas are not included."""
    masked = mask_kotlin(source) if masked is None else masked
    callee = re.compile(r"(?<![A-Za-z0-9_])(" + "|".join(map(re.escape, names)) + r")\s*\(")
    named = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)")
    for match in callee.finditer(masked):
        if re.search(r"\bfun\s*(<[^>]*>\s*)?$", masked[:match.start()]):
            continue
        arguments: dict[str, str] = {}
        depth, start, index = 1, match.end(), match.end()
        while index < len(masked) and depth:
            character = masked[index]
            if character in "([{":
                depth += 1
            elif character in ")]}":
                depth -= 1
            if depth == 0 or (depth == 1 and character == ","):
                name = named.match(masked, start, index)
                if name:
                    arguments[name.group(1)] = source[name.end():index].strip()
                start = index + 1
            index += 1
        yield match.group(1), source.count("\n", 0, match.start()) + 1, arguments


def surface_expressions(token: str) -> tuple[str, ...]:
    return (f"VpnControlColors.{token}", f"Color({PALETTE[token]})")


def theme_errors(theme: str) -> list[str]:
    errors: list[str] = []
    for name, literal in PALETTE.items():
        if f"val {name} = Color({literal})" not in theme:
            errors.append(f"fixed palette token {name} must remain {literal}")
    if "darkColorScheme(" not in theme or "fun VpnControlTheme" not in theme:
        errors.append("VpnControlTheme must own the fixed dark Material color scheme")
    if "lightColorScheme(" in theme or "dynamicDarkColorScheme(" in theme:
        errors.append("light and dynamic color schemes are not supported")
    schemes = list(call_arguments(theme, ("darkColorScheme",)))
    if len(schemes) != 1:
        return errors + ["VpnControlTheme must build exactly one darkColorScheme"]
    roles = schemes[0][2]
    for role, token in SURFACE_ROLES.items():
        if roles.get(role) != f"VpnControlColors.{token}":
            errors.append(
                f"color scheme role {role} must be VpnControlColors.{token}, not "
                + (roles[role] if role in roles else "the Material default")
            )
    for role in OTHER_ROLES:
        if role not in roles:
            errors.append(f"color scheme role {role} must be assigned from VpnControlColors")
    for role, expression in roles.items():
        if not PALETTE_EXPRESSION.fullmatch(expression):
            errors.append(f"color scheme role {role} must come from VpnControlColors, not {expression}")
    return errors


def container_errors(label: str, source: str) -> list[str]:
    """Every dialog and dropdown menu names its UI-002 surface instead of inheriting a default."""
    errors: list[str] = []
    if not any(callee in source for callee in CONTAINER_SURFACES):
        return errors
    masked = mask_kotlin(source)
    for callee, line, arguments in call_arguments(source, tuple(CONTAINER_SURFACES), masked):
        token = CONTAINER_SURFACES[callee]
        accepted = surface_expressions(token)
        expression = arguments.get("containerColor")
        if expression is None:
            errors.append(f"{label}:{line} {callee} must set containerColor = VpnControlColors.{token}")
            continue
        if re.fullmatch(r"[a-z][A-Za-z0-9_]*", expression):
            bound = re.findall(rf"\bval\s+{expression}\s*(?::\s*Color\s*)?=\s*([^\n]+)", masked)
            expression = bound[0].strip() if len(bound) == 1 else expression
        if expression not in accepted:
            errors.append(
                f"{label}:{line} {callee} containerColor must be VpnControlColors.{token} "
                f"({PALETTE[token]}), not {expression}"
            )
    return errors


def collect_errors(root: pathlib.Path) -> list[str]:
    def read(path: pathlib.Path) -> str:
        return (root / path).read_text(encoding="utf-8")

    errors = theme_errors(read(THEME))
    android_root = read(ANDROID_ROOT)
    android_app = read(ANDROID_APP)
    desktop_root = read(DESKTOP_ROOT)
    if "VpnControlTheme {" not in android_root:
        errors.append("Android root must use VpnControlTheme")
    if "VpnControlTheme {" not in desktop_root:
        errors.append("Desktop root must use VpnControlTheme")
    if "VpnControlColors.AppBackground" not in android_app:
        errors.append("Android app background must use the shared navy gradient")
    if "VpnControlColors.AppBackground" not in desktop_root:
        errors.append("Desktop app background must use the shared navy gradient")
    if "@color/vpn_control_navy_950" not in read(ANDROID_THEME):
        errors.append("Android navigation chrome must use the fixed navy background")
    if "#08111F" not in read(ANDROID_COLORS):
        errors.append("Android navy resource must match the shared theme")
    for source_root in PRODUCTION_ROOTS:
        for path in sorted((root / source_root).rglob("*.kt")):
            if THEME.name == path.name:
                continue
            label = path.relative_to(root).as_posix()
            source = path.read_text(encoding="utf-8")
            if "0xFF3D6B59" in source or "0x332A3E12" in source:
                errors.append(f"retired decorative green remains in {label}")
            errors.extend(container_errors(label, source))
    return errors


def main() -> int:
    errors = collect_errors(ROOT)
    if errors:
        print("UI theme contract failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    print("[vpn-control] fixed navy/azure theme contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
