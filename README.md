# Skyrim SE/AE SKSE64 Plugin Update Environment (AI-Ready)

This repository is a **self-contained C++ build and migration environment** designed so that **any AI coding agent** (Antigravity, Claude Code, Cursor, Codex, etc.) can automatically update, recompile, and verify outdated **Skyrim Special Edition / Anniversary Edition (SKSE64)** DLL mods for **whatever newest Skyrim runtime, SKSE64 build, and Address Library database are currently installed** (while maintaining backward compatibility with historical baselines such as `1.6.1170`, `1.6.640`, and `1.5.97` where possible).

You do **not** need any C++ knowledge to use this environment. Because Nexus Mods flags `.exe`, `.dll`, and `.lib` files inside archives as suspicious, **`tools/` and `sdk/` ship empty**—on first use, your AI agent follows [`SETUP.md`](SETUP.md) to automatically download, configure, and pre-build everything locally on your PC, and keeps it cached for all subsequent mod updates.

---

## How to Prompt Any AI Agent to Update a Mod

Open your AI agent in the root of this repository. On first run (or anytime `tools/` and `sdk/` are empty), the agent automatically runs [SETUP.md](SETUP.md) first (or you can trigger it explicitly with `Follow SETUP.md to install tools, SDKs, and .venv`), then paste one of the prompts below:

### Option A: Updating a Mod from a GitHub Link
> **Prompt:**
> `The UPDATE_INSTRUCTIONS.md file is your instructions. Auto-detect my installed Skyrim SE/AE, SKSE64, and Address Library versions and update the mod in this GitHub link: https://github.com/author/ModRepository`

### Option B: Updating a Mod from a Local Source Code Folder
> **Prompt:**
> `The UPDATE_INSTRUCTIONS.md file is your instructions. Auto-detect my installed Skyrim SE/AE, SKSE64, and Address Library versions and update the mod in this local folder: C:\path\to\mod_source_code`

### Option C: Fallback Binary Patching (Closed-Source / Unbuildable `.dll`)
> **Prompt:**
> `Follow docs/BINARY_PATCHING_GUIDE.md to auto-detect my installed Skyrim/Address Library versions and reverse-engineer, manifest-patch, and live-verify this DLL: C:\path\to\Plugin.dll`

*(Note: [SETUP.md](SETUP.md), [UPDATE_INSTRUCTIONS.md](UPDATE_INSTRUCTIONS.md), and [AGENT_INSTRUCTIONS.md](AGENT_INSTRUCTIONS.md) are provided, along with [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md), and [SKILL.md](.agent/skills/skse-plugin-updater/SKILL.md) so most AI agents will also load the instructions automatically.)*

---

## Where to Find Your Updated Mod

Once the AI agent finishes, your updated mod is automatically verified and placed in the **`dist/`** folder:

1. **Mod Manager Archive (`.zip`)**:
   * `dist/<ModName>_Updated.zip`
   * Drag and drop this `.zip` directly into **Mod Organizer 2 (MO2)** or **Vortex**, or use it to overwrite the old mod's DLL!
2. **Unpacked Folder**:
   * `dist/<ModName>/SKSE/Plugins/<ModName>.dll`

---

## What Is Included in This Environment?

| Folder / File | Description |
| :--- | :--- |
| [SETUP.md](SETUP.md) | **First-Time Setup Playbook**: Automatically populates `tools/`, `sdk/`, and `.venv/` on a fresh machine (downloads CMake, Ninja, XMake, vcpkg; clones `skse64` + `CommonLibSSE-NG`; fetches `skyrimae.rename` + `se_ae_offsets.csv`; copies local Address Library `.bin` tables; builds `CommonLibSSE.lib`). |
| `templates/sdk/` | Clean plain-text custom AI-SPUE SDK files (`versionlibdb.h`, `versiondb.h`, `commonlibsse-ng` vcpkg overlay port, `skse64` compat headers) restored into `sdk/` by `SETUP.md`. |
| [UPDATE_INSTRUCTIONS.md](UPDATE_INSTRUCTIONS.md) | Master instruction playbook for AI agents covering **Detect-First** target resolution, the 4-step source update workflow, Address Library Format v5 (`1.7.99+`), VTable shifts, and C++ compiler fixes. |
| [docs/BINARY_PATCHING_GUIDE.md](docs/BINARY_PATCHING_GUIDE.md) | Exhaustive agent reverse-engineering, manifest-driven binary patching, and live SKSE debugging playbook for closed-source or incomplete-source DLLs. |
| [scripts/skse_env.py](scripts/skse_env.py) | Shared **Detect-First** core module & CLI (`python scripts/skse_env.py`): reads installed `SkyrimSE.exe` PE `FileVersion`/`ProductVersion`, discovers `skse64_<major>_<minor>_<build>.dll` and `versionlib-*.bin`, checks SDK sync status, and provides C++ lexing + cached ID maps. |
| [scripts/env.py](scripts/env.py) | Pure-Python environment activator & runner (`python scripts/env.py -- <cmd>`): injects MSVC x64 (`cl.exe`), portable CMake/Ninja/XMake/vcpkg, `.venv`, and SDK variables. |
| [scripts/analyze_mod.py](scripts/analyze_mod.py) | Clones a GitHub repo or inspects a local folder, detects the build system & SKSE framework, verifies all Address Library IDs against the detected target runtime, and flags breaking changes. |
| [scripts/upgrade_mod.py](scripts/upgrade_mod.py) | Automatically patches outdated `vcpkg.json` baselines, `CMakeLists.txt`, `versionlibdb.h`, single-runtime `REL::ID(se)` calls, and split AE IDs. |
| [scripts/build_mod.py](scripts/build_mod.py) | Activates Visual Studio 2022 x64 MSVC + Ninja + CMake + vcpkg + XMake, compiles the `.dll` against our prebuilt `CommonLibSSE-NG`, verifies the binary for the detected runtime, and packages `dist/<ModName>_Updated.zip`. |
| [scripts/verify_dll.py](scripts/verify_dll.py) | Inspects any `.dll` binary's `SKSEPlugin_Version` metadata (`0x350` bytes) and simulates SKSE64's (`2.3.0+`) `PluginManager::CheckPluginCompatibility` without launching Skyrim. |
| [scripts/pe_inspect.py](scripts/pe_inspect.py) | PE64 & SKSE64 inspector: sections, `.text` caves, imports/exports, ASLR `.reloc` entries, `SKSEPluginVersionData`, AOB search, string xrefs, and MSVC `dumpbin.exe` disassembly. |
| [scripts/addrlib_xref.py](scripts/addrlib_xref.py) | Cross-references Address Library IDs/RVAs across game builds, diagnoses embedded DLL Address Library formats, and reads `SkyrimSE.exe` function bytes. |
| [scripts/manifest_patcher.py](scripts/manifest_patcher.py) | Deterministic `patches.json` patch engine (SHA-256 & expected-bytes checks, symbolic `{{rel32:...}}`, `.text`/`.patch` code caves, trampolines, `.reloc` guards, PE checksum). |
| [scripts/live_test_skse.py](scripts/live_test_skse.py) | Pure-Python automated live SKSE test runner: detects installed `SkyrimSE.exe` / `skse64_*.dll` / `.bin`, backs up and deploys DLL, launches `skse64_loader.exe`, streams logs, and captures Crash Logger / Trainwreck dumps. |
| [scripts/triage_modlist.py](scripts/triage_modlist.py) | Read-only scanner for `Data\SKSE\Plugins` that classifies every DLL as `OK`, `PATCHABLE-BIN`, `METADATA-ONLY`, `RECOMPILE`, or `NON-SKSE`. |
| [scripts/triage_crash.py](scripts/triage_crash.py) | Parses `skse64.log` and the latest Crash Logger / Trainwreck `crash-*.log` to pinpoint failed plugin loads, crashing DLLs, and faulting RVAs. |
| [scripts/inspect_bin.py](scripts/inspect_bin.py) | Parses Address Library `.bin` files (Formats 1, 2, and 5) from `sdk/address_tables/bin/` and Skyrim's `Data/SKSE/Plugins/`, looks up IDs/offsets, and verifies all IDs used in a mod. |
| [scripts/map_ids.py](scripts/map_ids.py) | Maps historical SE (`1.5.97`) IDs <-> AE (`1.6.x`/`1.7.x+`) IDs <-> hex offsets using `se_ae_offsets.csv`, `CommonLibSSE-NG`, and `skyrimae.rename`. |
| [scripts/extract_relib.py](scripts/extract_relib.py) | Downloads & parses `meh321/AddressLibraryDatabase` (`skyrimae.rename` symbols and `.relib` multi-version AE tables), exports multi-version CSVs, and packs Format 2 `.bin` files. |
| [scripts/add_new_runtime.py](scripts/add_new_runtime.py) | Future-proofing script: auto-detects (or accepts an explicit version for) new Skyrim patch numbers and registers them in `sdk/skse64`, `sdk/CommonLibSSE-NG`, and `sdk/address_tables/bin/`. |
| `sdk/` | Populated by `SETUP.md`: `CommonLibSSE-NG v16.9.0` (built into `CommonLibSSE-NG-Installed/`), `skse64` headers (`2.3.x`), Format-5-compatible `versionlibdb.h`, vcpkg overlay ports, `skyrimae.rename`, and Address Library `version-*.bin` / `versionlib-*.bin` databases. |
| `tools/` | Populated by `SETUP.md`: Portable `CMake`, `Ninja`, `XMake`, and `vcpkg` with portable binary caches (`tools/vcpkg/archives/`) and automatic `--clean-after-build` cleanup. |
| `.venv/` / `requirements.txt` | Project-local Python virtual environment with `pefile`, `capstone`, `keystone-engine`, and `lief` for PE inspection and x64 binary patching. |
| `examples/` | Ready-to-test sample mods (`ModA_Outdated_1_6_1170` and `ModB_RawSKSE_Legacy`) demonstrating upgrading historical source code to the active target runtime. |
| `tests/` | Pure-stdlib `unittest` suite (`python -m unittest discover -s tests -v`). |

### Running the Test Suite
```powershell
python -m unittest discover -s tests -v
```

---

## When a Future Skyrim Update Rolls Out

When Bethesda releases a new Skyrim patch and you install updated SKSE64 and Address Library files in your game folder, **all scripts automatically read the new `SkyrimSE.exe` PE version**. To also sync the local C++ SDK constants (`sdk/skse64`, `sdk/CommonLibSSE-NG`) and copy the new `versionlib-<major>-<minor>-<build>-<subbuild>.bin`:
1. Ask the AI agent:
   `Read UPDATE_INSTRUCTIONS.md, detect my newly installed Skyrim version via scripts/skse_env.py, sync with scripts/add_new_runtime.py, then update <Mod>`
2. Or run in PowerShell (zero arguments auto-detects `SkyrimSE.exe` and `Data\SKSE\Plugins\versionlib-*.bin`):
   ```powershell
   python scripts\add_new_runtime.py
   ```
   This automatically copies the matching `versionlib-<major>-<minor>-<build>-<subbuild>.bin` from your Skyrim installation into `sdk/address_tables/bin/` and adds the new runtime constants to `sdk/skse64` and `sdk/CommonLibSSE-NG`.
