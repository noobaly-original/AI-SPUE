# SKSE64 Binary-Patching & Live-Debugging Playbook (`docs/BINARY_PATCHING_GUIDE.md`)

> **TARGET AUDIENCE**: Autonomous AI software engineering and reverse-engineering agents running inside this repository.
> **WHEN TO USE THIS GUIDE**: Use this playbook **only when source recompilation is impossible** (closed-source `.dll`, deleted repo, or incomplete source missing private SDK headers such as *Immersive Equipment Displays* / `sse-build-resources`). When complete source builds are possible, always follow the primary Detect-First + 4-step workflow in [`../UPDATE_INSTRUCTIONS.md`](../UPDATE_INSTRUCTIONS.md).

> **DETECT-FIRST RULE**: Never hardcode or assume a target Skyrim version string, packed version DWORD, or `versionlib-*.bin` filename. Always resolve `<TARGET_VERSION>`, `<TARGET_VERSION_FULL>`, `<TARGET_RUNTIME_DASH>`, `<TARGET_ADDRLIB_BIN>`, and `<TARGET_VERSION_HEX>` dynamically from the user's installed `SkyrimSE.exe`, `skse64_*.dll`, and `Data\SKSE\Plugins\version*.bin` files first!

> **FIRST-TIME SETUP NOTE**: On a fresh extraction where `sdk/address_tables/` or `.venv/` are missing, read and run [`../SETUP.md`](../SETUP.md) first (or its `.venv` + `sdk/address_tables/` steps — Steps 0, 2, 5, and 6 — if you only need binary inspection/patching without C++ compilation).

---

## 0. Decision Tree & Toolset Overview

| Scenario | Recommended Action |
| :--- | :--- |
| Full C++ source compiles locally | Recompile from source (`skse_env.py` → `analyze_mod.py` → `upgrade_mod.py` → `build_mod.py`). |
| Source is missing private headers or unavailable, and plugin only needs `AddressLibraryV5` / `SKSEPlugin_Version` / Format 5 loader / targeted offset fixes | **Follow Phases 0–4 below** using the modular binary-patching toolset (`manifest_patcher.py`). |

### Active Modular Toolset (Replaces Archived `scripts/legacy/patch_binary.py`)

| Tool | Purpose |
| :--- | :--- |
| `scripts/skse_env.py` | **Phase 0 Detect-First Resolver**: Reads `SkyrimSE.exe` PE `FileVersion`/`ProductVersion`, discovers `skse64_<major>_<minor>_<build>.dll` and `versionlib-*.bin`, computes packed `MAKE_EXE_VERSION_EX` hex, and checks SDK sync status. |
| `scripts/pe_inspect.py` | Pure-stdlib PE64 inspector: sections, `.text` alignment caves, imports/exports, ASLR `.reloc` tables, `SKSEPluginVersionData` decoding, framework/risk fingerprinting, AOB search, string xrefs, and MSVC `dumpbin.exe` disassembly. |
| `scripts/addrlib_xref.py` | Address Library `.bin` cross-referencer: lists format capabilities (`v1`/`v2`/`v5`), maps IDs and RVAs/VAs across historical releases (e.g., `1.6.1170` → `<TARGET_VERSION>`), diagnoses embedded DLL format errors, and inspects `SkyrimSE.exe` function bytes. |
| `scripts/manifest_patcher.py` | Deterministic `patches.json` patch engine: validates input SHA-256 & expected bytes (with `??` wildcards), expands symbolic `{{rel32:...}}`, allocates `.text` caves or appends an executable `.patch` section, rejects `.reloc` ASLR corruption, updates `SKSEPlugin_Version`, and recalculates PE checksum. |
| `scripts/verify_dll.py` | Loads any PE64 `.dll` with `DONT_RESOLVE_DLL_REFERENCES` and runs SKSE64's (`2.3.0+`) `PluginManager::CheckPluginCompatibility` across historical baselines and the detected target runtime. |
| `scripts/live_test_skse.py` | Pure-Python automated test runner: detects installed `SkyrimSE.exe`/`skse64_*.dll`/`.bin`, backs up existing plugin, deploys patched `.dll`, clears logs, launches `skse64_loader.exe`, streams `skse64.log` & `<Plugin>.log`, detects early CTDs/hangs, collects Crash Logger / Trainwreck + Windows Event Log diagnostics, and restores backups. |
| `scripts/triage_crash.py` | Parses `skse64.log` and the newest Crash Logger / Trainwreck `crash-*.log`, printing suspect `Module.dll+0xRVA` frames with exact `pe_inspect.py disasm` commands. |

*(Note: `scripts/legacy/patch_binary.py` is archived strictly for historical reference—do not rely on its brittle regex heuristics for new work.)*

---

## Phase 0: Detect-First Target Runtime & Address Library Resolution

Before inspecting or patching any binary, establish exact values for these session placeholders from the local machine:

```powershell
python "scripts/skse_env.py"
# Or get structured JSON:
python "scripts/skse_env.py" --json
```

This dynamically populates:
* **`<TARGET_VERSION>` / `<TARGET_VERSION_FULL>`**: Read directly from `<SkyrimDir>\SkyrimSE.exe` PE `FileVersion` / `ProductVersion` (falling back to the newest mainline `versionlib-<major>-<minor>-<build>-<subbuild>.bin` / `version-*.bin` in `Data\SKSE\Plugins\` or `sdk\address_tables\bin\`, then `skse64_<major>_<minor>_<build>.dll`).
* **`<TARGET_RUNTIME_DASH>`**: Dashed form `<major>-<minor>-<build>-<subbuild>`.
* **`<TARGET_ADDRLIB_BIN>`**: Full path to `versionlib-<major>-<minor>-<build>-<subbuild>.bin` (or `version-<...>.bin`).
* **`<TARGET_VERSION_HEX>`**: Packed `MAKE_EXE_VERSION_EX(maj, min, build, sub)` uint32 (`((maj&0xFF)<<24)|((min&0xFF)<<16)|((build&0xFFF)<<4)|(sub&0xF)`).

If you ever need to check the raw files in PowerShell without Python:
```powershell
(Get-Item "<SkyrimDir>\SkyrimSE.exe").VersionInfo | Format-List FileVersion, ProductVersion
Get-ChildItem "<SkyrimDir>\skse64_*.dll" | Select-Object Name, @{N='SKSEVer';E={$_.VersionInfo.FileVersion}}
Get-ChildItem "<SkyrimDir>\Data\SKSE\Plugins\version*.bin" | Sort-Object Name -Descending | Select-Object -First 5 Name
```

*(If `skse_env.py` indicates a brand-new game build not yet cached in `sdk/`, optionally run `python "scripts/add_new_runtime.py"` so `sdk/address_tables/bin/` and C++ SDK headers also stay synced.)*

---

## Phase 1: Triage & Static Reverse-Engineering Reconnaissance

Start every binary-porting task by fingerprinting the PE64 structure, SKSE exports, and Address Library usage without guessing offsets. All tools auto-detect `<TARGET_VERSION>` (pass `--target <TARGET_VERSION>` only when intentionally testing another version):

### 1.1 Run Full PE64 & SKSE Inspection
```powershell
python "scripts/pe_inspect.py" inspect "path\to\Plugin.dll"
python "scripts/addrlib_xref.py" scan-dll "path\to\Plugin.dll"
```

Examine these fields from the output:
1. **Entry Point Type**:
   - **`SKSEPlugin_Version` present**: Modern SE/AE (`1.6+`) plugin exporting the `0x350`-byte `SKSEPluginVersionData` struct. Check `versionIndependence`, `versionIndependenceEx`, `compatibleVersions`, and `runtime_checks`.
   - **`SKSEPlugin_Query` only (no `SKSEPlugin_Version`)**: Legacy SE `1.5.97` plugin. SKSE `2.1.0+` / `2.3.0+` skips `SKSEPlugin_Query` entirely. Porting requires either recompilation or building a custom proxy/shim DLL because `SKSEPlugin_Version` data and AE/SE `SKSEInterface` layout expectations differ.
2. **Address Resolution Strategy**:
   - **Address Library (`AddressLibraryPostAE` bit `0x1`, or `versionlib-` / `version-` / `REL/ID.h` / `versiondb` strings)**: Resolves `SkyrimSE.exe` offsets dynamically from `<TARGET_ADDRLIB_BIN>` at startup.
   - **Signature Scanning (`Signatures` bit `0x2`)**: Uses runtime AOB scanning (`REL::Pattern` or custom scanner); check whether `versionIndependenceEx` / `StructsPost629` passes and whether scanned patterns still match `<SkyrimDir>\SkyrimSE.exe`.
   - **Hardcoded / Version-Locked (`versionIndependence == 0`, non-empty `compatibleVersions`)**: Resolves RVAs via hardcoded offsets or per-version `if (ver == ...)` tables; patching requires updating both `compatibleVersions` (`<TARGET_VERSION_HEX>`) and every hardcoded RVA/struct offset.
3. **CRT Linkage**:
   - **`/MD` (Dynamic CRT)**: Imports `vcruntime140.dll`, `msvcp140.dll`, `ucrtbase.dll` (`std::ifstream` calls go through CRT DLLs).
   - **`/MT` (Static CRT)**: CRT I/O (`CreateFileW` / `ReadFile`) is statically linked directly into the plugin's `.text` section.
4. **Tail Cave Availability**:
   - Note `.text` `TailCave: RVA 0x... (N bytes)`. If `N` is too small for a trampoline/cave, `manifest_patcher.py` automatically creates a new `.patch` executable section (`placement: "auto"` or `"new_section"`).

### 1.2 Locate Key Functions via Strings, AOBs & Disassembly
Built-in `pe_inspect.py` commands (using MSVC `dumpbin.exe` and `pefile`/stdlib):
```powershell
# Find ASCII/UTF-16LE strings and RIP-relative LEA instructions referencing them
python "scripts/pe_inspect.py" find-xrefs "path\to\Plugin.dll" "versionlib-"
python "scripts/pe_inspect.py" find-xrefs "path\to\Plugin.dll" "Unsupported address library format"
python "scripts/pe_inspect.py" find-xrefs "path\to\Plugin.dll" "MenuEventHandler"

# Search AOB patterns (supports ?? wildcards)
python "scripts/pe_inspect.py" find-pattern "path\to\Plugin.dll" "66 83 F8 06 0F 95 C0" --section .text

# Disassemble at an RVA (automatically adds ImageBase for dumpbin /RANGE)
python "scripts/pe_inspect.py" disasm "path\to\Plugin.dll" --rva 0x12340 --count 128

# Verify ASLR .reloc overlap before touching any instruction bytes
python "scripts/pe_inspect.py" check-reloc "path\to\Plugin.dll" --rva 0x12340 --len 10
```

**Optional External RE Tools (if installed on host)**:
- **MSVC `dumpbin.exe` directly**: `dumpbin /DISASM /RAWDATA:BYTES /RANGE:0x180012340,0x1800123C0 Plugin.dll`
- **Ghidra Headless**: `analyzeHeadless <proj_dir> <proj_name> -import Plugin.dll -postScript DumpFuncs.py`
- **Rizin / Radare2**: `rizin -q -c "aaa; s 0x180012340; pdf" Plugin.dll` or `r2 -q -c "aaa; s 0x180012340; pdf" Plugin.dll`
- **Python RE Stack (`.venv\Scripts\python.exe`)**: `pefile`, `capstone`, `keystone-engine`, and `lief` are pre-installed in the project-local `.venv/` (`requirements.txt`), enabling programmatic x64 disassembly, assembly, and PE editing alongside pure-stdlib `pe_inspect.py`.

---

## Phase 2: Diagnosing Why a `.dll` Fails on New Skyrim Builds

When a binary plugin fails to load or crashes on `1.7.99+` or newer Skyrim builds (`<TARGET_VERSION>`), check all four failure classes below.

### 2.1 `SKSEPluginVersionData` Version-Check Rejections
`SKSEPlugin_Version` exports a `0x350`-byte structure in `.rdata`:

| Offset | Size | Field | Details |
| :--- | :--- | :--- | :--- |
| `0x000` | `4` | `dataVersion` | Must be `1`. |
| `0x004` | `4` | `pluginVersion` | Packed plugin version. |
| `0x008` | `256` | `name` | Non-empty plugin name (`char[256]`). |
| `0x108` | `256` | `author` | Author string (`char[256]`). |
| `0x208` | `252` | `supportEmail` | Support email (`char[252]`). |
| `0x304` | `4` | `versionIndependenceEx` | `0x1 = NoStructUse`, **`0x2 = AddressLibraryV5`** (required on `1.7.99+`!). |
| `0x308` | `4` | `versionIndependence` | `0x1 = AddressLibraryPostAE`, `0x2 = Signatures`, `0x4 = StructsPost629`. |
| `0x30C` | `64` | `compatibleVersions[16]` | Packed `MAKE_EXE_VERSION_EX(maj, min, build, sub)` (`((maj&0xFF)<<24)\|((min&0xFF)<<16)\|((build&0xFFF)<<4)\|(sub&0xF)`), zero-terminated. Run `python "scripts/skse_env.py"` to see `<TARGET_VERSION_HEX>` for `<TARGET_VERSION_FULL>`. |
| `0x34C` | `4` | `seVersionRequired` | Minimum SE version (`0` if unused). |

**SKSE `2.3.0+` Rejection Gates**:
1. If `AddressLibraryPostAE` (`0x1`) is set and runtime `>= 1.7.99`, SKSE checks `(versionIndependenceEx & 0x2)` (`AddressLibraryV5`). If missing AND PE `TimeDateStamp` is between `520128000` and `1748217600` (`2025-05-26 UTC`), SKSE aborts with `"must be recompiled for new address library"`.
2. If version-independent and runtime `>= 1.6.629`, either `StructsPost629` (`0x4` in `versionIndependence`) or `NoStructUse` (`0x1` in `versionIndependenceEx`) must be set.
3. If `versionIndependence` has neither `AddressLibraryPostAE` nor `Signatures`, SKSE requires `<TARGET_VERSION_HEX>` in `compatibleVersions[16]`.

### 2.2 Address Library Format Mismatches (`Unsupported address library format` / `REL/ID.h`)
Even after fixing `SKSEPlugin_Version` metadata, plugins compiled before Format 5 support (`1.7.99+`) only implement Format 1/2 parsing:

| Format | Skyrim Versions | Binary Layout |
| :--- | :--- | :--- |
| **Format 1** | `1.5.x` (`version-1-5-*.bin`, historical SE) | Header + sparse delta/nibble-packed `(ID, offset)` stream. |
| **Format 2** | `1.6.318`–`1.6.1179` (`versionlib-1-6-*.bin`, historical AE) | Header (`format=2`, `ver[4]`, `nameLen`, `moduleName`, `ptrSize`, `addrCount`) + sparse delta/nibble-packed `(ID, offset)` stream. |
| **Format 5** | `1.7.99+` (`versionlib-<maj>-<min>-<build>-<subbuild>.bin`) | Fixed **96-byte header**: `format(int32=5)` + `ver[4](uint32[4])` + `moduleName[64]` + `ptrSize(int32)` + `dataFormat(int32)` + `offsetCount(int32)` — followed immediately by `offsetCount` raw `uint32_t` RVAs (`offsets[id]`, where `0` = invalid/absent ID). |

Two common CommonLibSSE/versiondb issues inside old DLLs:
1. **Format 2-only reader**: The embedded `REL::IDDatabase::load_file` + `unpack_file` (or `versiondb::Load`) checks `format != 2` and throws `"Unsupported address library format"` or returns `false`.
   - **Remediation**: Patch the format check, header skip (`0x48` bytes after `ver[4]` to reach `offsetCount` at offset `0x5C`), and read loop directly via a `patches.json` trampoline/code cave (Format 5 loop writes `(uint64_t id, uint64_t offset)` pairs into the plugin's table).
2. **`REL::Module::load_segments` `1.7.x+` SE Misclassification Bug**:
   - Old CommonLibSSE-NG checked `if (version.minor() == 6)` (`cmp ax, 6; setne al` = `66 83 F8 06 0F 95 C0`). On Skyrim `1.7.x` (or any future minor `>= 7`), `minor != 6`, misclassifying the game as **SE (`1.5.97`)**!
   - **Fix**: Patch `0F 95 C0` (`setne al`) to `0F 92 C0` (`setb al` — unsigned `< 6` is SE, `>= 6` is AE). `manifest_patcher.py init-manifest` detects this pattern automatically!

### 2.3 Hardcoded Offsets, Split Address Library IDs, Struct Offsets & VTable Shifts
1. **Cross-Referencing IDs & RVAs**:
   ```powershell
   # Inspect all local SDK & installed Skyrim .bin formats
   python "scripts/addrlib_xref.py" formats

   # Map old historical AE IDs (e.g. 1-6-1170-0) to auto-detected <TARGET_RUNTIME_DASH>
   python "scripts/addrlib_xref.py" map-id 47286 77235 13358 --from 1-6-1170-0

   # Map hardcoded RVAs or IDA VAs from historical 1.6.1170 -> enclosing ID + delta -> estimated target RVA
   python "scripts/addrlib_xref.py" map-offset 0x82e000 0x14082e018 --from 1-6-1170-0

   # Compare actual SkyrimSE.exe machine code at an ID between an old EXE and installed <SkyrimDir>\SkyrimSE.exe
   python "scripts/addrlib_xref.py" exe-bytes "path\to\old\SkyrimSE_1_6_1170.exe" --id 47286 --runtime 1-6-1170-0 --disasm
   python "scripts/addrlib_xref.py" exe-bytes "<SkyrimDir>\SkyrimSE.exe" --id <NEW_ID> --disasm
   ```
   - Never blindly trust `new_base_rva + delta` when `delta > 0`: MSVC re-inlines code across builds. Always disassemble the target function in `<SkyrimDir>\SkyrimSE.exe` (via `exe-bytes --disasm`) to confirm exact interior branch/instruction offsets.
2. **`1.7.99+` (and Future Build) VTable & Struct Shifts**:
   - In `1.7.99+`, `RE::MenuEventHandler` and `RE::PlayerInputHandler` inserted `ProcessMotionGesture` (slot `0x02`) and `ProcessSixaxis` (slot `0x03`), shifting subsequent virtual slots by **+2** (`+0x10` bytes in a 64-bit vtable!):
     - `PlayerInputHandler::ProcessButton`: `+0x20` (`0x04 * 8`) → **`+0x30`** (`0x06 * 8`)
     - `MenuEventHandler::ProcessButton`: `+0x28` (`0x05 * 8`) → **`+0x38`** (`0x07 * 8`)
   - If a plugin subclasses `MenuEventHandler` with a static `.rdata` vtable, inspect its vtable entries with `pe_inspect.py find-xrefs` + `disasm` and either insert stub virtual methods via a `.patch` vtable copy or patch vfunc hook indices (`mov qword ptr [reg+0x28], ...` → `[reg+0x38]` if slot displacement fits, or trampoline if an immediate grows from `disp8` to `disp32`).
   - `UIStringHolder`, `SkyrimVM`, and `BSGraphics::State` (`frameCount`, `insideFrame`, `useEarlyZ`) also shifted offsets in `1.7.99+` — compare the member access disassembly in the plugin against the installed `SkyrimSE.exe` or `sdk/CommonLibSSE-NG/include/RE/` headers (and always re-check vtables/structs when adapting to newer updates!).

---

## Phase 3: Safe x64 Binary Patching Rules & `patches.json` Engine

Follow these strict rules before modifying any byte in a PE64 `.dll`:

### 3.1 Five Golden Rules of Safe PE64 Binary Patching
1. **Verify Input Hash & Expected Bytes First**: Every patch in `patches.json` specifies `input_sha256` and `expected_hex` (supporting `??` for variable `rel32` displacements). `manifest_patcher.py` aborts before writing if any byte mismatches.
2. **Patch `SKSEPluginVersionData` in `.rdata` via `metadata_patches`**: Never hand-edit strings or flags with raw offsets when `metadata_patches` handles `0x304` (`versionIndependenceEx`), `0x308` (`versionIndependence`), and `0x30C` (`compatibleVersions[16]`) cleanly—for non-Address-Library plugins, add `"<TARGET_VERSION_FULL>"` in `compatible_versions_add` rather than raw hex DWORDs.
3. **Never Overwrite Past Original Instruction Boundaries Inline**:
   - If the replacement instruction sequence is **shorter or equal**, pad extra trailing bytes with `0x90` (`NOP`).
   - If the replacement is **longer** (e.g., `disp8` `[rbp+0x20]` expanding to `disp32` `[rbp+0x120]`, or inserting a Format 5 loader branch), install a **`5`-byte `E9 rel32` trampoline** (`stolen_len >= 5`, copying whole x64 instructions up to the next instruction boundary `>= 5` bytes, NOPing remaining bytes of the stolen slice) into a **code cave**.
   - **Code Cave Placement (`placement: "auto"`)**:
     - Fits inside `.text`'s trailing `0x00` / `0xCC` alignment padding (`text_padding`) when space suffices (extending `.text` `VirtualSize` within `SizeOfRawData`), **or**
     - Appends a brand-new PE64 executable section **`.patch`** (`Characteristics = 0x60000020`, `CNT_CODE | MEM_EXECUTE | MEM_READ`), updating `NumberOfSections` and `SizeOfImage`.
   - **Relocating Stolen Instructions**: Never blindly copy a `RIP`-relative (`[rip+disp32]`, `E8 call`, `E9 jmp`, `0F 8x jcc`) instruction from `hook_rva` into a code cave verbatim—recompute its `disp32` relative to the **cave RVA** using `{{rel32:<original_target_rva>}}`!
4. **Protect ASLR Base Relocations (`.reloc`)**:
   - With `DYNAMIC_BASE` enabled, Windows adds `(ActualBase - ImageBase)` to every address in `IMAGE_DIRECTORY_ENTRY_BASERELOC` (`DIR64` 8-byte pointers, `HIGHLOW` 4-byte dwords).
   - Overwriting or NOPing bytes overlapped by a `.reloc` entry causes Windows to corrupt your machine code at load time under ASLR! Always verify `pe_inspect.py check-reloc` (`manifest_patcher.py` rejects `.reloc` overlaps automatically).
5. **Recalculate PE Header Checksum**: `manifest_patcher.py` automatically writes the exact Windows PE `CheckSum` after applying all edits (`fix-checksum` is also available standalone).

### 3.2 `patches.json` Manifest Format & Workflow

Generate a starter manifest (auto-detects `<TARGET_VERSION>`, populates `input_sha256`, detects `REL::Module::load_segments` `1.7.x+` bug, and suggests `AddressLibraryV5` or `<TARGET_VERSION_FULL>` metadata):
```powershell
python "scripts/manifest_patcher.py" init-manifest "path\to\Plugin.dll" -o "workspace\Plugin\patches.json"
```

Version-agnostic `patches.json` template (note `"target_runtime": "auto"` resolves dynamically to `<TARGET_VERSION>` at apply time, or `init-manifest` fills in the detected version):
```json
{
  "schema_version": 1,
  "plugin_name": "ExamplePlugin",
  "target_runtime": "auto",
  "input_file": "ExamplePlugin.dll",
  "input_sha256": "<64-hex-sha256>",
  "symbols": {
    "VersionErrorTarget": "0x14500"
  },
  "code_caves": [],
  "trampolines": [
    {
      "name": "format5_check",
      "hook_rva": "0x12340",
      "stolen_len": 10,
      "expected_hex": "39 44 24 24 0F 85 ?? ?? ?? ??",
      "placement": "auto",
      "cave_prefix_hex": "39 44 24 24 74 0B 83 7C 24 24 05 0F 85 {{rel32:VersionErrorTarget}}",
      "append_return_jmp": true,
      "allow_reloc_overlap": false,
      "description": "Allow Format 5 in addition to Format 2"
    }
  ],
  "patches": [
    {
      "rva": "0x189A0",
      "expected_hex": "0F 95 C0",
      "patch_hex": "0F 92 C0",
      "allow_reloc_overlap": false,
      "description": "Fix REL::Module::load_segments minor==6 check so >= 1.6 (incl. 1.7.x+) is AE"
    }
  ],
  "metadata_patches": {
    "set_version_independence_ex": ["AddressLibraryV5"],
    "clear_version_independence_ex": [],
    "set_version_independence": [],
    "clear_version_independence": [],
    "compatible_versions_add": []
  }
}
```

> **Expression Syntax in `hex_bytes` / `patch_hex` / `cave_prefix_hex`**:
> - `{{rel32:0x14500}}` — 4-byte signed displacement to RVA `0x14500`.
> - `{{rel32:SymbolName+0x10}}` or `{{rel32:SymbolName-0x4}}` — displacement to a `symbols` entry or cave name plus/minus offset.
> - `{{rel32:0x14500,next=4}}` — use when `next` immediate bytes follow the `rel32` inside the same instruction (e.g., `cmp [rip+disp32], imm32` needs `next=4`).
> - For non-Address-Library version-locked DLLs, put `"compatible_versions_add": ["<TARGET_VERSION_FULL>"]` (or keep `init-manifest`'s auto-populated string) — `manifest_patcher.py` encodes it using `MAKE_EXE_VERSION_EX` automatically.

Validate, preview, apply, and package:
```powershell
python "scripts/manifest_patcher.py" verify-manifest "path\to\Plugin.dll" -m "workspace\Plugin\patches.json"
python "scripts/manifest_patcher.py" apply "path\to\Plugin.dll" -m "workspace\Plugin\patches.json" --dry-run
python "scripts/manifest_patcher.py" apply "path\to\Plugin.dll" -m "workspace\Plugin\patches.json" -o "dist\ExamplePlugin\SKSE\Plugins\ExamplePlugin.dll" --zip
```

---

## Phase 4: Automated Live-Debugging & Verification Loop

After `manifest_patcher.py apply` passes `verify_dll.py` statically, **always validate runtime loading and in-game initialization** if Skyrim is installed on the host.

### 4.1 Run the Automated Live Test Harness
```powershell
python "scripts/live_test_skse.py" `
  --plugin-dll "dist\ExamplePlugin\SKSE\Plugins\ExamplePlugin.dll" `
  --timeout 45 `
  --auto-close
```

- Automatically detects installed `SkyrimSE.exe` version, `skse64_*.dll`, and `versionlib-*.bin`, backs up any existing `<Plugin>.dll` in `Data\SKSE\Plugins`, and restores it when finished (pass `--keep-deployed` to keep the patched DLL in place once verified).
- Clears previous `skse64.log` and `<Plugin>.log`, launches `skse64_loader.exe`, streams logs live, monitors `SkyrimSE.exe` responsiveness, and checks Crash Logger / Trainwreck + Windows Application Event Log.
- **Exit Codes**:
  - `0`: Plugin loaded and SKSE reached `init complete` cleanly.
  - `1`: SKSE rejected plugin during query/load (`reported as incompatible` / `must be recompiled`).
  - `2`: Early CTD or Crash Logger / Trainwreck dump generated.
  - `3`: Hang or timeout before `init complete`.
  - `4`: Setup/launch failure (`SkyrimDir` or `skse64_loader.exe` missing).

### 4.2 Map Crash Stack RVAs Back to Disassembly & Iterate
When exit code is `1` or `2` (or run offline diagnostics with `--no-launch`):
```powershell
# Inspect latest logs and crash dumps offline
python "scripts/live_test_skse.py" --no-launch
python "scripts/triage_crash.py"
```

1. Check `PROBABLE CALL STACK` in the Crash Logger / Trainwreck report for `<Plugin>.dll+0x<RVA>` (note Crash Logger logs RVAs directly relative to the loaded module base!).
2. Disassemble the faulting neighborhood in the patched DLL:
   ```powershell
   python "scripts/pe_inspect.py" disasm "dist\ExamplePlugin\SKSE\Plugins\ExamplePlugin.dll" --rva 0x<RVA - 0x20> --count 96
   ```
3. If the crash occurred inside `SkyrimSE.exe+0x<RVA>` called by your plugin (e.g., wrong Address Library ID, wrong function signature, or shifted struct/vtable offset), map the current runtime `SkyrimSE.exe` RVA back to the historical build (`--from <TARGET_RUNTIME_DASH> --to <OLD_RUNTIME_DASH>`, e.g., `1-6-1170-0`):
   ```powershell
   python "scripts/addrlib_xref.py" map-offset 0x<SkyrimRVA> --from <TARGET_RUNTIME_DASH> --to 1-6-1170-0
   ```
4. Refine `patches.json`, re-apply with `manifest_patcher.py apply`, and re-run `live_test_skse.py` until exit code `0` is achieved.
5. Package final deliverables into `dist/<ModName>/SKSE/Plugins/<ModName>.dll` and `dist/<ModName>_Updated.zip` (pass `--zip` to `manifest_patcher.py apply`).
