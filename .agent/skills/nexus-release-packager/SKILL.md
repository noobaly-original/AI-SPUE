---
name: nexus-release-packager
description: >-
  Package and verify a clean, binary-free Nexus Mods release ZIP of AI-SPUE
  (dist/AI-SPUE-Nexus.zip) with empty sdk/ and tools/ while preserving
  templates/sdk/ and keeping local tools/, sdk/, and .venv/ intact. Trigger
  whenever the user asks to package AI-SPUE for Nexus Mods, build a Nexus
  release ZIP, or verify a release archive against SETUP.md Maintainer Note
  rules.
---

# AI-SPUE Nexus Release Packager Skill

Read and follow [`PACKAGE.md`](../../../PACKAGE.md) at the repository root and run [`scripts/package_nexus.py`](../../../scripts/package_nexus.py). Never delete the user's local `tools/`, `sdk/`, or `.venv/` when creating a release archive unless explicitly instructed—stage into `workspace/_nexus_stage` instead.

## Standard Packaging Commands

Run from the `AI-SPUE` repository root:

1. **Default clean build (`dist/AI-SPUE-Nexus.zip`)**:
   ```powershell
   python "scripts/package_nexus.py"
   ```
2. **Dry-run audit without writing a ZIP**:
   ```powershell
   python "scripts/package_nexus.py" --dry-run
   ```
3. **Strict release build requiring clean git working tree**:
   ```powershell
   python "scripts/package_nexus.py" --output "dist/AI-SPUE-Nexus.zip" --require-clean-git
   ```
4. **Verify an existing Nexus ZIP archive**:
   ```powershell
   python "scripts/package_nexus.py" --verify-only "dist/AI-SPUE-Nexus.zip"
   ```

## Required Verification Checks

Before reporting success to the user, confirm `scripts/package_nexus.py` exits `0` and verifies all of the following:
- `ZipFile.testzip()` CRC check passes (`None`).
- `sdk/` and `tools/` are present in the archive as empty top-level directories with zero files inside.
- `templates/sdk/` (including `templates/sdk/address_tables/se_ae_offsets.csv` and `LICENSE-se_ae_offsets.txt`) and dotfiles (`.agent/`, `.cursorrules`, `.github/copilot-instructions.md`, `.gitignore`) are preserved.
- Zero `.exe`, `.dll`, `.lib`, `.ps1`, `.bat`, `.cmd`, `.msi`, `.vbs`, `.pyc`, `.pyo`, `.bak`, `.git/`, `.venv/`, `workspace/`, `dist/`, `__pycache__/`, `.pytest_cache/`, or `.gitkeep` entries exist in the ZIP.
- Temporary staging (`workspace/_nexus_stage`) was cleaned up and local `tools/`, `sdk/`, and `.venv/` remain intact.

## Common Pitfalls

- **Never exclude `sdk` recursively**: Excluding `sdk` at arbitrary depth removes `templates/sdk/`. Top-level exclusion only.
- **Delete old `.zip` before `7z`**: `7z a` updates an existing archive rather than recreating it cleanly.
- **Keep tooling pure Python**: Never introduce `.ps1`, `.bat`, or `.cmd` helper scripts into AI-SPUE itself.
