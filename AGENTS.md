# Workspace Agent Instructions (`AGENTS.md`)

When operating in this workspace, always read and follow **`UPDATE_INSTRUCTIONS.md`** whenever the user asks to update, recompile, port, or fix a Skyrim Special Edition / Anniversary Edition (SKSE64) plugin or mod.

## Detect-First Rule
Never assume or hardcode a target Skyrim version string. Always detect the active target version dynamically from the user's installed `SkyrimSE.exe` PE `FileVersion` / `ProductVersion`, `Data/SKSE/Plugins/versionlib-*.bin`, and `skse64_<major>_<minor>_<build>.dll` via `python "scripts/skse_env.py"` before updating or patching any plugin.

## Quick Execution Summary
0. **Detect Active Target Runtime & Sync SDK (Required First)**:
   ```powershell
   python "scripts/skse_env.py"
   # Only if sdk_needs_registration=True (newer SkyrimSE.exe / .bin installed than cached SDK):
   python "scripts/add_new_runtime.py"
   ```
1. **Analyze** *(auto-detects target runtime; pass `--target <TARGET_RUNTIME_DASH>` only to override)*:
   ```powershell
   python "scripts/analyze_mod.py" "<GITHUB_URL_OR_LOCAL_FOLDER>"
   ```
2. **Upgrade & Patch**:
   ```powershell
   python "scripts/upgrade_mod.py" "workspace/<ModName>"
   ```
3. **Verify Address Library IDs**:
   ```powershell
   python "scripts/inspect_bin.py" verify-mod "workspace/<ModName>"
   ```
4. **Build, Binary-Verify (`SKSEPlugin_Version` / `AddressLibraryV5`), and Package to `dist/`**:
   ```powershell
   python "scripts/build_mod.py" "workspace/<ModName>"
   ```
5. **Fallback (Closed-Source / Missing Private Headers `.dll` only — see [`docs/BINARY_PATCHING_GUIDE.md`](docs/BINARY_PATCHING_GUIDE.md))**:
   ```powershell
   python "scripts/pe_inspect.py" inspect "<path_to_plugin.dll>"
   python "scripts/addrlib_xref.py" scan-dll "<path_to_plugin.dll>"
   python "scripts/manifest_patcher.py" init-manifest "<path_to_plugin.dll>" -o "workspace/<ModName>/patches.json"
   python "scripts/manifest_patcher.py" apply "<path_to_plugin.dll>" -m "workspace/<ModName>/patches.json" -o "dist/<ModName>/SKSE/Plugins/<ModName>.dll" --zip
   powershell -NoProfile -ExecutionPolicy Bypass -File "scripts/live_test_skse.ps1" -PluginDll "dist/<ModName>/SKSE/Plugins/<ModName>.dll" -AutoClose
   ```

See [`UPDATE_INSTRUCTIONS.md`](UPDATE_INSTRUCTIONS.md) for the complete cookbook of C++ fixes, `1.7.99+` VTable slot shifts (`MenuEventHandlerEx`, `REL::VersionShift`), and Address Library Format v5 details, and [`docs/BINARY_PATCHING_GUIDE.md`](docs/BINARY_PATCHING_GUIDE.md) for reverse-engineering and binary-patching instructions.
