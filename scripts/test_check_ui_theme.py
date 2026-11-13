#!/usr/bin/env python3
"""TEST-001 RED/GREEN: no menu or dialog inherits a Material default surface."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_ui_theme", ROOT / "scripts/check_ui_theme.py")
assert SPEC is not None and SPEC.loader is not None
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

# Every source this test reads is named here, so its inputs stay a finite list.
BEFORE = ROOT / "scripts/testdata/ui-theme"
BEFORE_THEME = BEFORE / "VpnControlTheme.before.kt"
BEFORE_UPDATE_DIALOG = BEFORE / "AppUpdateDialog.before.kt"
BEFORE_ACTION_ROW = BEFORE / "DesktopActionRow.before.kt"
BEFORE_SOURCES = {
    "VpnControlTheme.before.kt": BEFORE_THEME,
    "AppUpdateDialog.before.kt": BEFORE_UPDATE_DIALOG,
    "DesktopActionRow.before.kt": BEFORE_ACTION_ROW,
}
THEME = ROOT / "shared/ui/src/commonMain/kotlin/com/kardinal/vpncontrol/shared/ui/VpnControlTheme.kt"
UPDATE_DIALOG = ROOT / "shared/ui/src/commonMain/kotlin/com/kardinal/vpncontrol/shared/ui/AppUpdateDialog.kt"
DESKTOP_MAIN = ROOT / "desktopApp/src/main/kotlin/com/kardinal/vpncontrol/desktop/Main.kt"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def dialog(arguments: str) -> str:
    return f"@Composable\nfun Sample() {{\n    AlertDialog(\n        onDismissRequest = {{}},\n{arguments}        confirmButton = {{}},\n    )\n}}\n"


def menu(arguments: str) -> str:
    return f"@Composable\nfun Sample() {{\n    DropdownMenu(\n        expanded = true,\n        onDismissRequest = {{}},\n{arguments}    ) {{\n    }}\n}}\n"


class PreservedBeforeSourceTests(unittest.TestCase):
    """The sources the visual review of f31ab987 rendered, unchanged at 529cc610."""

    def test_before_sources_are_the_recorded_bytes(self):
        recorded = json.loads((BEFORE / "before-sources.json").read_text(encoding="utf-8"))["before"]
        self.assertEqual(set(BEFORE_SOURCES), set(recorded))
        for name, path in BEFORE_SOURCES.items():
            with self.subTest(before=name):
                self.assertEqual(recorded[name]["sha256"], hashlib.sha256(text(path).encode("utf-8")).hexdigest())

    def test_before_theme_leaves_the_surface_roles_to_material_and_the_current_theme_defines_them(self):
        problems = guard.theme_errors(text(BEFORE_THEME))
        self.assertEqual(
            [
                "color scheme role surfaceDim must be VpnControlColors.Surface, not the Material default",
                "color scheme role surfaceBright must be VpnControlColors.SurfaceElevated, not the Material default",
                "color scheme role surfaceContainerLowest must be VpnControlColors.Surface, not the Material default",
                "color scheme role surfaceContainerLow must be VpnControlColors.Surface, not the Material default",
                "color scheme role surfaceContainer must be VpnControlColors.SurfaceElevated, not the Material default",
                "color scheme role surfaceContainerHigh must be VpnControlColors.Surface, not the Material default",
                "color scheme role surfaceContainerHighest must be VpnControlColors.SurfaceElevated, "
                "not the Material default",
                "color scheme role inversePrimary must be assigned from VpnControlColors",
                "color scheme role tertiaryContainer must be assigned from VpnControlColors",
                "color scheme role onTertiaryContainer must be assigned from VpnControlColors",
                "color scheme role surfaceTint must be assigned from VpnControlColors",
                "color scheme role inverseSurface must be assigned from VpnControlColors",
                "color scheme role inverseOnSurface must be assigned from VpnControlColors",
            ],
            problems,
        )
        self.assertEqual([], guard.theme_errors(text(THEME)))

    def test_before_update_dialog_inherits_its_container_and_the_current_dialog_names_the_base_surface(self):
        self.assertEqual(
            ["AppUpdateDialog.kt:38 AlertDialog must set containerColor = VpnControlColors.Surface"],
            guard.container_errors("AppUpdateDialog.kt", text(BEFORE_UPDATE_DIALOG)),
        )
        self.assertEqual([], guard.container_errors("AppUpdateDialog.kt", text(UPDATE_DIALOG)))

    def test_before_desktop_menus_inherit_their_container_and_the_current_menus_name_the_elevated_surface(self):
        self.assertEqual(
            [
                "Main.kt:24 DropdownMenu must set containerColor = VpnControlColors.SurfaceElevated",
                "Main.kt:54 DropdownMenu must set containerColor = VpnControlColors.SurfaceElevated",
            ],
            guard.container_errors("Main.kt", text(BEFORE_ACTION_ROW)),
        )
        self.assertEqual([], guard.container_errors("Main.kt", text(DESKTOP_MAIN)))

    def test_the_current_tree_passes_the_whole_guard(self):
        self.assertEqual([], guard.collect_errors(ROOT))


class ThemeRoleTests(unittest.TestCase):
    def theme(self, replacement: tuple[str, str] | None = None) -> str:
        theme = text(THEME)
        if replacement is None:
            return theme
        self.assertEqual(1, theme.count(replacement[0]), replacement[0])
        return theme.replace(*replacement)

    def test_a_surface_role_on_the_other_surface_is_refused(self):
        problems = guard.theme_errors(self.theme((
            "surfaceContainer = VpnControlColors.SurfaceElevated,",
            "surfaceContainer = VpnControlColors.Surface,",
        )))
        self.assertEqual(
            ["color scheme role surfaceContainer must be VpnControlColors.SurfaceElevated, "
             "not VpnControlColors.Surface"],
            problems,
        )

    def test_a_role_painted_with_a_literal_is_refused(self):
        problems = guard.theme_errors(self.theme((
            "inverseSurface = VpnControlColors.TextSecondary,",
            "inverseSurface = Color(0xFFE6E0E9),",
        )))
        self.assertEqual(
            ["color scheme role inverseSurface must come from VpnControlColors, not Color(0xFFE6E0E9)"],
            problems,
        )

    def test_a_removed_role_is_refused(self):
        problems = guard.theme_errors(self.theme(("    surfaceTint = VpnControlColors.Primary,\n", "")))
        self.assertEqual(["color scheme role surfaceTint must be assigned from VpnControlColors"], problems)

    def test_a_translucent_palette_color_is_still_a_palette_color(self):
        self.assertEqual([], guard.theme_errors(self.theme(("Error.copy(alpha = 0.24f)", "Error.copy(alpha = 0.5f)"))))
        self.assertEqual(
            ["color scheme role errorContainer must come from VpnControlColors, "
             "not VpnControlColors.Error.compositeOver(Color.Black)"],
            guard.theme_errors(self.theme(("Error.copy(alpha = 0.24f)", "Error.compositeOver(Color.Black)"))),
        )


class ContainerTests(unittest.TestCase):
    def assertProblems(self, expected: list[str], source: str) -> None:
        self.assertEqual(expected, guard.container_errors("Sample.kt", source))

    def test_each_component_takes_its_own_surface_as_token_or_literal(self):
        for source in (
            dialog("        containerColor = VpnControlColors.Surface,\n"),
            dialog("        containerColor = Color(0xFF141F2D),\n"),
            menu("        containerColor = VpnControlColors.SurfaceElevated,\n"),
            menu("        containerColor = Color(0xFF1D2B3B),\n"),
        ):
            with self.subTest(source=source):
                self.assertProblems([], source)

    def test_the_other_surface_is_refused(self):
        self.assertProblems(
            ["Sample.kt:3 AlertDialog containerColor must be VpnControlColors.Surface (0xFF141F2D), "
             "not VpnControlColors.SurfaceElevated"],
            dialog("        containerColor = VpnControlColors.SurfaceElevated,\n"),
        )
        self.assertProblems(
            ["Sample.kt:3 DropdownMenu containerColor must be VpnControlColors.SurfaceElevated (0xFF1D2B3B), "
             "not Color(0xFF141F2D)"],
            menu("        containerColor = Color(0xFF141F2D),\n"),
        )

    def test_the_material_defaults_and_scheme_lookups_are_refused(self):
        for expression in ("Color(0xFF2B2930)", "Color(0xFF211F26)", "MaterialTheme.colorScheme.surface"):
            with self.subTest(expression=expression):
                self.assertProblems(
                    [f"Sample.kt:3 AlertDialog containerColor must be VpnControlColors.Surface (0xFF141F2D), "
                     f"not {expression}"],
                    dialog(f"        containerColor = {expression},\n"),
                )

    def test_a_local_value_is_followed_to_its_color(self):
        bound = "private val menuSurface = Color(0xFF1D2B3B)\n"
        self.assertProblems([], bound + menu("        containerColor = menuSurface,\n"))
        self.assertProblems(
            ["Sample.kt:4 DropdownMenu containerColor must be VpnControlColors.SurfaceElevated (0xFF1D2B3B), "
             "not Color(0xFF211F26)"],
            "private val menuSurface = Color(0xFF211F26)\n" + menu("        containerColor = menuSurface,\n"),
        )
        self.assertProblems(
            ["Sample.kt:3 DropdownMenu containerColor must be VpnControlColors.SurfaceElevated (0xFF1D2B3B), "
             "not elsewhere"],
            menu("        containerColor = elsewhere,\n"),
        )

    def test_a_color_of_nested_content_does_not_name_the_container(self):
        nested = (
            "        text = {\n"
            "            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF141F2D))) {\n"
            "                DropdownMenuItem(text = { Text(\"a, b\") }, onClick = { containerColor = 1 })\n"
            "            }\n"
            "        },\n"
        )
        self.assertProblems(
            ["Sample.kt:3 AlertDialog must set containerColor = VpnControlColors.Surface"], dialog(nested))
        self.assertProblems([], dialog(nested + "        containerColor = VpnControlColors.Surface,\n"))

    def test_the_one_line_call_form_is_read(self):
        call = ("AlertDialog(onDismissRequest = { failure = null },\n"
                "    title = { Text(strings.get(UiText.STATUS)) }, text = { Text(describe(failure, 2)) },\n"
                "    confirmButton = { TextButton(onClick = { failure = null }) { Text(\"Close\") } }EXTRA)\n")
        self.assertProblems(
            ["Sample.kt:1 AlertDialog must set containerColor = VpnControlColors.Surface"], call.replace("EXTRA", ""))
        self.assertProblems([], call.replace("EXTRA", ", containerColor = VpnControlColors.Surface"))

    def test_comments_strings_declarations_and_other_callees_are_not_calls(self):
        self.assertProblems([], (
            "// AlertDialog(onDismissRequest = {})\n"
            "/* DropdownMenu(expanded = true) /* nested */ AlertDialog( */\n"
            "val label = \"AlertDialog(${describe(\"DropdownMenu(\")})\"\n"
            "val raw = \"\"\"DropdownMenu(\"quoted\")\"\"\"\n"
            "val quote = '\"'\n"
            "@Composable\nfun AlertDialog(content: @Composable () -> Unit) = content()\n"
            "fun items() { DropdownMenuItem(text = {}, onClick = {}); ExportQrDialog(title = \"\") }\n"
        ))

    def test_a_call_after_a_string_with_a_quoted_template_is_still_found(self):
        self.assertProblems(
            ["Sample.kt:2 DropdownMenu must set containerColor = VpnControlColors.SurfaceElevated"],
            "val label = \"${names.joinToString(\", \") { \"(\" + it }}\"\nDropdownMenu(expanded = true) {}\n",
        )


class KotlinScannerTests(unittest.TestCase):
    def test_masking_keeps_every_offset_and_line(self):
        source = "a = \"x(\" // y(\n/* z(\n */ call(b = 'c', d = \"\"\"e\n(\"\"\")\n"
        masked = guard.mask_kotlin(source)
        self.assertEqual(len(source), len(masked))
        self.assertEqual(source.count("\n"), masked.count("\n"))
        self.assertIn("call(b =", masked)
        self.assertEqual((1, 1), (masked.count("("), masked.count(")")))
        self.assertEqual("a=call(b=,d=)", "".join(masked.split()))

    def test_arguments_are_the_named_ones_of_that_call_only(self):
        source = "Outer(first = inner(second = 1, third = [2, 3]), fourth = { fifth = 4 }, sixth == 5, last = \"z\")"
        self.assertEqual(
            [("Outer", 1, {"first": "inner(second = 1, third = [2, 3])", "fourth": "{ fifth = 4 }", "last": '"z"'})],
            list(guard.call_arguments(source, ("Outer",))),
        )


if __name__ == "__main__":
    unittest.main()
