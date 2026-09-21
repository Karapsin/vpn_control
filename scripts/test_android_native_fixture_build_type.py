#!/usr/bin/env python3
"""Statically guard the native-acceptance build type; packaging remains separate."""

from pathlib import Path


BUILD = Path(__file__).resolve().parents[1] / "app" / "build.gradle.kts"
X86_RUNTIME = BUILD.parent / "src" / "debug" / "jniLibs" / "x86_64" / "libsing-box.so"


def block_after(text: str, marker: str) -> str:
    start = text.index(marker)
    opening = text.index("{", start)
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    raise AssertionError(f"unterminated block after {marker!r}")


def main() -> None:
    build = BUILD.read_text(encoding="utf-8")
    default = block_after(build, "    defaultConfig ")
    release = block_after(build, "        release ")
    fixture = block_after(build, '        create("nativeFixture") ')

    assert "abiFilters" not in default
    assert "x86_64" not in release
    assert 'abiFilters += listOf("arm64-v8a")' in release
    assert "isMinifyEnabled = true" in release
    assert "isShrinkResources = true" in release
    assert "signingConfig = if (hasReleaseSigning)" in release

    assert 'initWith(getByName("release"))' in fixture
    assert "isDebuggable = false" in fixture
    assert 'matchingFallbacks += listOf("release")' in fixture
    assert "abiFilters.clear()" in fixture
    assert 'abiFilters += listOf("x86_64")' in fixture
    assert fixture.index("abiFilters.clear()") < fixture.index('abiFilters += listOf("x86_64")')
    assert "signingConfig" not in fixture
    assert 'sourceSets.getByName("nativeFixture").jniLibs.srcDir("src/debug/jniLibs")' in build
    assert 'sourceSets.getByName("nativeFixture").java.srcDir("src/release/java")' in build
    assert X86_RUNTIME.is_file()

    print("[vpn-control] Android native fixture build-type contract passed")


if __name__ == "__main__":
    main()
