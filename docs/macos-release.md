# macOS Release

The macOS GitHub Actions workflow builds an unsigned DMG by default. If the
following repository secrets are configured, the same workflow imports a
Developer ID certificate, signs the app, and enables Compose notarization.

Required signing secrets:

- `MACOS_SIGNING_CERTIFICATE_BASE64`: base64-encoded `.p12` Developer ID Application certificate.
- `MACOS_SIGNING_CERTIFICATE_PASSWORD`: password for the `.p12`.
- `MACOS_SIGNING_IDENTITY`: codesigning identity, for example `Developer ID Application: Name (TEAMID)`.
- `MACOS_KEYCHAIN_PASSWORD`: temporary CI keychain password.

Required notarization secrets:

- `MACOS_NOTARIZATION_APPLE_ID`: Apple ID used for notarization.
- `MACOS_NOTARIZATION_PASSWORD`: app-specific password.
- `MACOS_NOTARIZATION_TEAM_ID`: Apple Developer Team ID.

Local unsigned build on a Mac:

```bash
./scripts/package_macos_desktop.sh
```

Secret handling:

- Do not paste real certificate material, passwords, Apple IDs, or app-specific passwords into agent-visible transcripts.
- Keep `.p12` files and temporary secret files outside the repository.
- Prefer GitHub repository secrets for shared release workflows.
- If a local signed build is needed, enter real values in your own terminal/session and redact them from logs before sharing output.

Local signed build on a Mac:

```bash
export VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_BASE64="$(base64 -i DeveloperID.p12)"
export VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_PASSWORD="..."
export VPN_CONTROL_MACOS_SIGNING_IDENTITY="Developer ID Application: Name (TEAMID)"
export VPN_CONTROL_MACOS_KEYCHAIN_PASSWORD="$(uuidgen)"
export VPN_CONTROL_MACOS_NOTARIZATION_APPLE_ID="developer@example.com"
export VPN_CONTROL_MACOS_NOTARIZATION_PASSWORD="app-specific-password"
export VPN_CONTROL_MACOS_NOTARIZATION_TEAM_ID="TEAMID"
./scripts/package_macos_desktop.sh
```
