# AI-SPUE Nexus Mods Release Packaging Guide (`PACKAGE.md`)

> **WHY THIS FILE EXISTS**: Nexus Mods flags `.exe`, `.dll`, `.lib`, and shell script extensions (`.ps1`, `.bat`, `.cmd`, `.msi`, `.vbs`) inside uploaded archives as suspicious. Instead of deleting your local populated `tools/`, `sdk/`, and `.venv/`, use [`scripts/package_nexus.py`](scripts/package_nexus.py) to stage a clean release tree in `workspace/_nexus_stage`, audit it, compress `dist/AI-SPUE-Nexus.zip`, and verify the archive automatically.

---

## Quick Start

Run from the repository root (`AI-SPUE`):

```powershell
# Default: stage, audit, compress via 7z (fallback: stdlib zipfile), verify, and clean staging
python "scripts/package_nexus.py"

# Preview & audit what would be packaged without writing a ZIP
python "scripts/package_nexus.py" --dry-run

# Enforce a clean git working tree (recommended before cutting a public Nexus release)
python "scripts/package_nexus.py" --output "dist/AI-SPUE-Nexus.zip" --require-clean-git

# Re-verify an existing Nexus release archive
python "scripts/package_nexus.py" --verify-only "dist/AI-SPUE-Nexus.zip"
```

---

## Include / Exclude Matrix

| Path / Pattern | Action | Notes |
| :--- | :--- | :--- |
| Top-level `sdk/` & `tools/` | **Contents excluded -> included empty** | Both directories exist empty (`sdk/`, `tools/`) in the ZIP so `SETUP.md` targets are ready. Local `sdk/` & `tools/` on disk stay untouched. |
| `templates/sdk/` | **Included in full** | Preserves `AddressLibrary/` (`versionlibdb.h`, `versiondb.h`), `skse64/common/`, `vcpkg-overlays/commonlibsse-ng/`, and `address_tables/` (`se_ae_offsets.csv`, `LICENSE-se_ae_offsets.txt`). |
| Top-level `.git/`, `.venv/`, `workspace/`, `dist/`, `.vs/` | **Excluded** | Repo metadata, machine-local Python venv, mod build caches, and release outputs. |
| `__pycache__/`, `.pytest_cache/` (any depth) | **Excluded** | Python cache directories skipped at every tree depth. |
| `.agent/`, `.cursorrules`, `.github/`, `*.md`, `scripts/`, `tests/`, `docs/`, `examples/`, `LICENSE`, `requirements.txt`, `.gitignore` | **Included** | All agent rules/skills, plain-text documentation, Python tooling, and examples. |
| `.gitkeep`, `*.pyc`, `*.pyo`, `*.bak` | **Excluded** | Placeholder and temp backup files stripped from staging. |
| `*.exe`, `*.dll`, `*.lib`, `*.ps1`, `*.bat`, `*.cmd`, `*.msi`, `*.vbs` | **Forbidden (audit fails)** | Any match in staged files aborts packaging before any ZIP is written. |

---

## Step-by-Step What `scripts/package_nexus.py` Performs

1. **Pre-Flight Git Check**: Runs `git status --porcelain`. Prints a `[WARN]` if modified or untracked files exist (or fails immediately if `--require-clean-git` is passed).
2. **Isolated Clean Staging (`workspace/_nexus_stage`)**:
   - Deletes any leftover `workspace/_nexus_stage`.
   - Walks the repository root, pruning `TOP_LEVEL_EXCLUDE_DIRS` (`.git`, `.venv`, `sdk`, `tools`, `workspace`, `dist`, `.vs`) at the repository root **only**, and `ANY_DEPTH_EXCLUDE_DIRS` (`__pycache__`, `.pytest_cache`) at every depth.
   - Skips `.gitkeep`, `*.pyc`, `*.pyo`, and `*.bak`.
   - Creates empty `sdk/` and `tools/` directories inside staging.
3. **Nexus Compliance Audit ([`SETUP.md`](SETUP.md#L514-L523) Maintainer Note)**:
   - Confirms `sdk/` and `tools/` exist as directories with zero files inside them.
   - Rejects any file ending in `.exe`, `.dll`, `.lib`, `.ps1`, `.bat`, `.cmd`, `.msi`, `.vbs`, `.pyc`, `.pyo`, `.bak`, or named `.gitkeep`, or containing forbidden directory segments.
4. **Fresh Archive Compression**:
   - Deletes any pre-existing `dist/AI-SPUE-Nexus.zip` first so no stale entries can survive.
   - Runs `7z a -tzip -mx=9 "<abs_output_zip>" *` inside `workspace/_nexus_stage` (or pure-Python `zipfile` with `ZIP_DEFLATED` level 9 if `7z` is unavailable / `--backend zipfile` is specified).
5. **Post-Build Archive Verification & Cleanup**:
   - Runs `ZipFile.testzip()` (full CRC check across every entry).
   - Verifies required dot-files and templates (`templates/sdk/address_tables/se_ae_offsets.csv`, `.agent/skills/nexus-release-packager/SKILL.md`, `.cursorrules`, `.github/copilot-instructions.md`, etc.), empty `sdk/` and `tools/`, and zero forbidden files or excluded folders inside the ZIP.
   - Deletes `workspace/_nexus_stage` cleanly in a `finally` block (unless `--keep-stage` is passed).

### Equivalent Manual Audit Check (PowerShell)
```powershell
Get-ChildItem -Path "workspace\_nexus_stage" -Recurse -Force -File -Include *.exe,*.dll,*.lib,*.ps1,*.bat,*.cmd,*.msi,*.vbs
```

---

## Common Pitfalls

1. **Excluding `sdk` at every depth**: Passing a global recursive exclude on `"sdk"` strips [`templates/sdk/`](templates/sdk/) alongside top-level `sdk/`. Always filter `sdk/` at root depth only.
2. **Updating an existing ZIP in place with `7z`**: Calling `7z a` when `dist/AI-SPUE-Nexus.zip` already exists merges old and new files instead of replacing deleted files. Always delete the target `.zip` before invoking `7z`.
3. **Stray untracked files at repo root**: Untracked notes or temp scripts in the repository root get staged automatically. Inspect `git status -sb` or use `--require-clean-git` before cutting a release.
4. **Wiping local `tools/`, `sdk/`, or `.venv/` unnecessarily**: You do **not** need to delete your populated working toolchain to build a clean archive—staging in `workspace/_nexus_stage` keeps local installations intact.

---

## Pre-Release Checklist (Optional)

1. Run the full test suite and confirm everything passes:
   ```powershell
   .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
   ```
2. Check git cleanliness and inspect any uncommitted changes:
   ```powershell
   git status -sb
   ```
3. Build and verify the Nexus release package:
   ```powershell
   python "scripts/package_nexus.py" --require-clean-git
   python "scripts/package_nexus.py" --verify-only "dist/AI-SPUE-Nexus.zip"
   ```
