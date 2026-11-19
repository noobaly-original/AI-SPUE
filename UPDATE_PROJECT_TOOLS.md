Perform a full-stack dependency, toolchain, and documentation upgrade across the entire workspace. Many files, manifests, scripts, and `.md` guides currently reference outdated versions of Skyrim modding libraries, build systems, and Python/CLI tools.

Act as a senior C++ / Windows build-system and SKSE modding architect. **Audit every tool, library, submodule, package manifest, build script, and `.md` file in this project and upgrade them to their newest stable versions.**

### Step 1: Full Workspace Tool & Dependency Audit
Scan the entire repository (`.md`, `CMakeLists.txt`, `CMakePresets.json`, `vcpkg.json`, `vcpkg-configuration.json`, `conanfile.*`, `xmake.lua`, `requirements.txt`, `pyproject.toml`, `.gitmodules`, `.github/workflows/*`, `.ps1`, and `.py` files) to catalog every tool and dependency currently referenced or installed, including:
- **SKSE Ecosystem:** `CommonLibSSE` / `CommonLibSSE-NG` (e.g., `alandtse/CommonLibSSE-NG` latest release/commit), SKSE64 SDK headers/loader versions, and Address Library for SKSE Plugins.
- **C++ Build & Package Toolchains:** CMake minimum/preset versions, MSVC toolset (`v143` / latest Visual Studio 2022/2026 build tools), Ninja, `vcpkg` baseline commit hashes & port versions (`fmt`, `spdlog`, `rapidcsv`, `xbyak`, `nlohmann-json`, `simpleini`, etc.), `xmake`, or `conan`.
- **Reverse-Engineering & Scripting Tools:** Python interpreter version, `.venv` packages (`pefile`, `capstone`, `keystone-engine`, `lief`, etc.), Ghidra / Rizin / x64dbg / `dumpbin` references, and PowerShell modules.

### Step 2: Upgrade Dependencies, Submodules & Build Configs
1. **Update Submodules & Package Baselines:**
   - If `CommonLibSSE-NG` (or other dependencies) are included as Git submodules, fetch and update them to their latest upstream `ng` / main release tag, and verify C++20/C++23 compiler flags match upstream requirements.
   - If `vcpkg.json` / `vcpkg-configuration.json` is used, update the `builtin-baseline` to the latest `vcpkg` commit hash and remove outdated version overrides that conflict with current ports.
   - If `xmake.lua` or `conanfile` is used, update package versions and repository definitions to current releases.
2. **Update Python & Automation Environments:**
   - Upgrade outdated packages in `requirements.txt` and the local `.venv` (`pefile`, `capstone`, `keystone-engine`, etc.), resolving any breaking API changes in project scripts.
3. **Verify Build & Script Health:**
   - Run a clean configure/check pass on the build template (CMake / vcpkg / xmake) and `--help` / syntax checks on all Python and PowerShell scripts to confirm there are no deprecated flags, broken baselines, or version mismatches.

### Step 3: Update All `.md` Files & Add a Maintenance Protocol
1. **Eliminate Stale Tool/Library References:** Update every `.md` file (`README.md`, `instructions.md`, build guides, and binary-patching docs) so all installation commands, compiler requirements, `CommonLibSSE-NG` branch/fork instructions, `vcpkg`/`CMake` presets, and reverse-engineering CLI commands reflect the upgraded toolchain.
2. **Preserve Historical Context Only Where Needed:** Keep old versions (like `1.5.97` or `1.6.1170`) strictly where explaining legacy plugin migration examples; remove all outdated tool instructions (e.g., deprecated `CharmedBaryon` archive refs if superseded by active `alandtse/CommonLibSSE-NG`, old MSVC/CMake versions, or legacy static scripts).
3. **Add a "Keeping Toolchains Current" Rule for Future Agents:** Add a concise section in `instructions.md` instructing future AI agents to check `git submodule status` / `vcpkg` baselines / installed Skyrim & SKSE versions before starting any plugin port, rather than blindly trusting cached version numbers.

### Execution Rules
- First, output a clear **Before → After Version Audit Table** listing every tool, library, baseline, and stale `.md` reference found in the workspace.
- Apply all upgrades across manifests, submodules, scripts, and `.md` documentation.
- Validate that build configurations and helper scripts execute cleanly without version or deprecation errors.