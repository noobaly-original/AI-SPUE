# AI-SPUE First-Time Setup Guide (`SETUP.md`)

> **WHY THIS FILE EXISTS**: Nexus Mods flags `.exe`, `.dll`, and `.lib` binaries inside release archives as suspicious. Therefore, AI-SPUE ships with **`tools/` and `sdk/` empty** (and without a machine-local `.venv/`), keeping all custom AI-SPUE headers and configs in plain text under [`templates/sdk/`](templates/sdk/).
>
> **FOR AI AGENTS**: Whenever you start working in this workspace, run the **First-Time Readiness Check** below **before** running [`UPDATE_INSTRUCTIONS.md`](UPDATE_INSTRUCTIONS.md) or [`docs/BINARY_PATCHING_GUIDE.md`](docs/BINARY_PATCHING_GUIDE.md). If any required item is missing, follow this guide end-to-end once. Once installed, `tools/`, `sdk/`, and `.venv/` stay cached locally for all future runs.

---

## First-Time Readiness Check (Run This First)

Run this PowerShell check from the repository root (`AI-SPUE`):

```powershell
$required = @(
    "tools\cmake\bin\cmake.exe",
    "tools\ninja\ninja.exe",
    "tools\xmake\xmake.exe",
    "tools\vcpkg\vcpkg.exe",
    "sdk\CommonLibSSE-NG\CMakeLists.txt",
    "sdk\CommonLibSSE-NG-Installed\lib\CommonLibSSE.lib",
    "sdk\CommonLibSSE-NG-Installed\lib\cmake\CommonLibSSE\CommonLibSSEConfig.cmake",
    "sdk\skse64\skse64_common\skse_version.h",
    "sdk\AddressLibrary\versionlibdb.h",
    "sdk\vcpkg-overlays\commonlibsse-ng\portfile.cmake",
    "sdk\address_tables\se_ae_offsets.csv",
    "sdk\address_tables\skyrimae.rename",
    ".venv\Scripts\python.exe"
)
$missing = $required | Where-Object { -not (Test-Path $_) }
$hasBins = (Get-ChildItem "sdk\address_tables\bin" -Filter "*.bin" -File -ErrorAction SilentlyContinue).Count -gt 0
if (-not $hasBins) { $missing += "sdk\address_tables\bin\*.bin" }
if ($missing.Count -eq 0) {
    Write-Host "[READY] All tools, SDKs, Address Library tables, and .venv are installed." -ForegroundColor Green
} else {
    Write-Host "[SETUP NEEDED] Missing:" -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host "  - $_" }
}
```

* If **`[READY]`**, skip this file and proceed straight to [`UPDATE_INSTRUCTIONS.md`](UPDATE_INSTRUCTIONS.md) (or [`docs/BINARY_PATCHING_GUIDE.md`](docs/BINARY_PATCHING_GUIDE.md)).
* **Binary-Only Fast Subset**: If you are ONLY reverse-engineering / manifest-patching a closed-source `.dll` via [`docs/BINARY_PATCHING_GUIDE.md`](docs/BINARY_PATCHING_GUIDE.md) and do not need to compile C++ mods, you only need **Step 0**, **Step 2** (`.venv`), **Step 5** (`sdk/address_tables/`), and **Step 6** (`skse_env.py`)—though running the full setup is recommended so all tools and unit tests work.

---

## Step 0: Verify Host Prerequisites

Confirm the user's machine has the required host prerequisites before downloading or building anything:

```powershell
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
} else {
    Write-Warning "vswhere.exe not found! Install Visual Studio 2022/2026 (Desktop development with C++)."
}
git --version
python --version
curl.exe --version | Select-Object -First 1
```

Requirements:
1. **Visual Studio 2022 / 2026** (Community or Build Tools) with the **"Desktop development with C++"** workload (`MSVC x64` + Windows SDK).
2. **Git for Windows** (`git`) and **Python 3.10+ (64-bit)** (`python`) on `PATH`.
3. **`curl.exe`** (built into Windows 10/11) with internet access to `github.com`, `api.github.com`, and `raw.githubusercontent.com`. *(Always invoke `curl.exe` explicitly in PowerShell because `curl` is an alias for `Invoke-WebRequest`.)*
4. **Skyrim SE/AE** with **SKSE64** and **Address Library for SKSE Plugins** installed locally (needed in Step 5/6 to copy `version*.bin` tables and auto-detect target runtime).

---

## Step 1: Install Portable Build Tools into `tools/`

Download and extract the latest stable **CMake**, **Ninja**, **XMake**, and **vcpkg** into `tools/`:

```powershell
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path "tools" | Out-Null
$ghHeaders = @{ "User-Agent" = "AI-SPUE-Setup" }

function Expand-ZipFast([string]$ZipPath, [string]$DestDir) {
    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
    if (Get-Command tar.exe -ErrorAction SilentlyContinue) {
        & tar.exe -xf $ZipPath -C $DestDir
        if ($LASTEXITCODE -eq 0) { return }
    }
    $ProgressPreference = 'SilentlyContinue'
    Expand-Archive -Path $ZipPath -DestinationPath $DestDir -Force
}

# 1a. CMake -> tools/cmake/bin/cmake.exe
if (-not (Test-Path "tools\cmake\bin\cmake.exe")) {
    $cmakeUrl = $null
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/Kitware/CMake/releases/latest" -Headers $ghHeaders
        $cmakeUrl = ($rel.assets | Where-Object { $_.name -match 'windows-x86_64\.zip$' } | Select-Object -First 1).browser_download_url
    } catch {}
    if (-not $cmakeUrl) {
        $cmakeUrl = "https://github.com/Kitware/CMake/releases/download/v4.5.1/cmake-4.5.1-windows-x86_64.zip"
    }
    Write-Host "[*] Downloading CMake: $cmakeUrl"
    & curl.exe -fsSL $cmakeUrl -o "tools\_cmake.zip"
    if ($LASTEXITCODE -ne 0) { throw "Failed to download CMake" }
    if (Test-Path "tools\_cmake_tmp") { Remove-Item -Recurse -Force "tools\_cmake_tmp" }
    Expand-ZipFast "tools\_cmake.zip" "tools\_cmake_tmp"
    $inner = Get-ChildItem "tools\_cmake_tmp" -Directory | Select-Object -First 1
    if (Test-Path "tools\cmake") { Remove-Item -Recurse -Force "tools\cmake" }
    Move-Item -Path $inner.FullName -Destination "tools\cmake"
    Remove-Item -Recurse -Force "tools\_cmake_tmp", "tools\_cmake.zip"
}

# 1b. Ninja -> tools/ninja/ninja.exe
if (-not (Test-Path "tools\ninja\ninja.exe")) {
    $ninjaUrl = $null
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/ninja-build/ninja/releases/latest" -Headers $ghHeaders
        $ninjaUrl = ($rel.assets | Where-Object { $_.name -eq 'ninja-win.zip' } | Select-Object -First 1).browser_download_url
    } catch {}
    if (-not $ninjaUrl) {
        $ninjaUrl = "https://github.com/ninja-build/ninja/releases/download/v1.13.2/ninja-win.zip"
    }
    Write-Host "[*] Downloading Ninja: $ninjaUrl"
    & curl.exe -fsSL $ninjaUrl -o "tools\_ninja.zip"
    if ($LASTEXITCODE -ne 0) { throw "Failed to download Ninja" }
    Expand-ZipFast "tools\_ninja.zip" "tools\ninja"
    Remove-Item -Force "tools\_ninja.zip"
}

# 1c. XMake -> tools/xmake/xmake.exe
if (-not (Test-Path "tools\xmake\xmake.exe")) {
    $xmakeUrl = $null
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/xmake-io/xmake/releases/latest" -Headers $ghHeaders
        $xmakeUrl = ($rel.assets | Where-Object { $_.name -match 'win64\.zip$' } | Select-Object -First 1).browser_download_url
    } catch {}
    if (-not $xmakeUrl) {
        $xmakeUrl = "https://github.com/xmake-io/xmake/releases/download/v3.1.2/xmake-master.win64.zip"
    }
    Write-Host "[*] Downloading XMake: $xmakeUrl"
    & curl.exe -fsSL $xmakeUrl -o "tools\_xmake.zip"
    if ($LASTEXITCODE -ne 0) { throw "Failed to download XMake" }
    if (Test-Path "tools\_xmake_tmp") { Remove-Item -Recurse -Force "tools\_xmake_tmp" }
    Expand-ZipFast "tools\_xmake.zip" "tools\_xmake_tmp"
    if (Test-Path "tools\xmake") { Remove-Item -Recurse -Force "tools\xmake" }
    if (Test-Path "tools\_xmake_tmp\xmake.exe") {
        Move-Item -Path "tools\_xmake_tmp" -Destination "tools\xmake"
    } else {
        $inner = Get-ChildItem "tools\_xmake_tmp" -Directory | Select-Object -First 1
        Move-Item -Path $inner.FullName -Destination "tools\xmake"
        Remove-Item -Recurse -Force "tools\_xmake_tmp" -ErrorAction SilentlyContinue
    }
    Remove-Item -Force "tools\_xmake.zip"
}

# 1d. vcpkg -> tools/vcpkg/vcpkg.exe
# IMPORTANT: Do NOT pass --depth 1! vcpkg manifest mode requires git history to resolve builtin-baseline commits.
if (-not (Test-Path "tools\vcpkg\.git")) {
    if (Test-Path "tools\vcpkg") { cmd /c rmdir /s /q "tools\vcpkg" }
    Write-Host "[*] Cloning microsoft/vcpkg (full history for manifest baselines)..."
    git clone https://github.com/microsoft/vcpkg.git tools/vcpkg
    if ($LASTEXITCODE -ne 0) { throw "Failed to clone vcpkg" }
}
if (-not (Test-Path "tools\vcpkg\vcpkg.exe")) {
    Write-Host "[*] Bootstrapping vcpkg..."
    & .\tools\vcpkg\bootstrap-vcpkg.bat -disableMetrics
    if ($LASTEXITCODE -ne 0) { throw "vcpkg bootstrap failed" }
}
New-Item -ItemType Directory -Force -Path "tools\vcpkg\archives" | Out-Null
```

---

## Step 2: Create Machine-Local Python `.venv`

Create `.venv/` and install the PE inspection / x64 RE packages from `requirements.txt` (`pefile`, `capstone`, `keystone-engine`, `lief`):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
```

*(Passing `--disable-pip-version-check` avoids pip upgrade notices on stderr.)*

---

## Step 3: Copy AI-SPUE SDK Templates (`templates/sdk/` -> `sdk/`)

Copy AI-SPUE's plain-text Format 5 `versionlibdb.h` headers and local `commonlibsse-ng` vcpkg overlay port into `sdk/`:

```powershell
New-Item -ItemType Directory -Force -Path "sdk" | Out-Null
foreach ($sub in @("AddressLibrary", "vcpkg-overlays")) {
    Copy-Item -Path "templates\sdk\$sub" -Destination "sdk\$sub" -Recurse -Force
}
```

---

## Step 4: Clone `sdk/skse64` & `sdk/CommonLibSSE-NG` + Apply Compatibility Patches

1. Clone `ianpatt/skse64` into `sdk/skse64` and the latest release tag of `alandtse/CommonLibSSE-NG` (fallback `v16.9.0`) **with submodules** (required for `extern/openvr`):

```powershell
$ghHeaders = @{ "User-Agent" = "AI-SPUE-Setup" }

if (-not (Test-Path "sdk\skse64\skse64_common\skse_version.h")) {
    if (Test-Path "sdk\skse64") { cmd /c rmdir /s /q "sdk\skse64" }
    git clone --depth 1 https://github.com/ianpatt/skse64.git sdk/skse64
    if ($LASTEXITCODE -ne 0) { throw "Failed to clone skse64" }
}
Copy-Item -Path "templates\sdk\skse64\common" -Destination "sdk\skse64\common" -Recurse -Force

$clibTag = "v16.9.0"
try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/alandtse/CommonLibSSE-NG/releases/latest" -Headers $ghHeaders
    if ($rel.tag_name) { $clibTag = $rel.tag_name }
} catch {}

if (-not (Test-Path "sdk\CommonLibSSE-NG\CMakeLists.txt")) {
    if (Test-Path "sdk\CommonLibSSE-NG") { cmd /c rmdir /s /q "sdk\CommonLibSSE-NG" }
    Write-Host "[*] Cloning alandtse/CommonLibSSE-NG ($clibTag) with submodules..."
    git clone --branch $clibTag --depth 1 --recurse-submodules --shallow-submodules https://github.com/alandtse/CommonLibSSE-NG.git sdk/CommonLibSSE-NG
    if ($LASTEXITCODE -ne 0) { throw "Failed to clone CommonLibSSE-NG" }
}
```

2. Apply AI-SPUE's idempotent backward-compatibility patches to `sdk/skse64` (`PluginAPI.h` standalone `UInt*`/`SInt*` typedefs) and `sdk/CommonLibSSE-NG` (`Version.h` legacy `RUNTIME_*` aliases, `Interfaces.h` `UsesAddressLibrary(bool)` / `UsesStructsPost629` / `HasNoStructUse` overloads, `xmake.lua` `CommonLibSSE-NG-Installed` lookup), and sync `vcpkg-configuration.json` / `vcpkg.json` baselines to local `tools/vcpkg` `HEAD` so `CommonLibSSE-NG` and all upgraded consumer mods share identical binary-cache ports:

```powershell
@'
import json
import re
import subprocess
from pathlib import Path

root = Path(".")

# 0. Patch sdk/skse64/skse64/PluginAPI.h so standalone raw SKSE plugins compile without IPrefix.h
pa = root / "sdk" / "skse64" / "skse64" / "PluginAPI.h"
pa_txt = pa.read_text(encoding="utf-8")
if "_ITYPES_H_" not in pa_txt and pa_txt.startswith("#pragma once"):
    typedef_block = (
        "#pragma once\n\n"
        "#include <cstdint>\n"
        "#ifndef _ITYPES_H_\n"
        "typedef uint8_t\t\tUInt8;\n"
        "typedef uint16_t\tUInt16;\n"
        "typedef uint32_t\tUInt32;\n"
        "typedef uint64_t\tUInt64;\n"
        "typedef int8_t\t\tSInt8;\n"
        "typedef int16_t\t\tSInt16;\n"
        "typedef int32_t\t\tSInt32;\n"
        "typedef int64_t\t\tSInt64;\n"
        "#endif"
    )
    pa.write_text(pa_txt.replace("#pragma once", typedef_block, 1), encoding="utf-8")
    print("[+] Patched sdk/skse64/skse64/PluginAPI.h with standalone integer typedefs")

# 1. Patch include/SKSE/Version.h with legacy aliases expected by older mods
vh = root / "sdk" / "CommonLibSSE-NG" / "include" / "SKSE" / "Version.h"
v_txt = vh.read_text(encoding="utf-8")
if not re.search(r"\bRUNTIME_LATEST\b", v_txt):
    anchor = "inline constexpr auto RUNTIME_SSE_LATEST = RUNTIME_SSE_LATEST_AE;"
    legacy_block = (
        anchor
        + "\n\tinline constexpr auto RUNTIME_LATEST = RUNTIME_SSE_LATEST;\n\n"
        + "\t// Backward-compatibility aliases for legacy CommonLibSSE plugins\n"
        + "\tinline constexpr auto RUNTIME_1_5_97 = RUNTIME_SSE_1_5_97;\n"
        + "\tinline constexpr auto RUNTIME_1_6_318 = RUNTIME_SSE_1_6_318;\n"
        + "\tinline constexpr auto RUNTIME_1_6_353 = RUNTIME_SSE_1_6_353;\n"
        + "\tinline constexpr auto RUNTIME_1_6_640 = RUNTIME_SSE_1_6_640;\n"
        + "\tinline constexpr auto RUNTIME_1_6_1130 = RUNTIME_SSE_1_6_1130;\n"
        + "\tinline constexpr auto RUNTIME_1_6_1170 = RUNTIME_SSE_1_6_1170;\n"
        + "\tinline constexpr auto RUNTIME_1_7_99 = RUNTIME_SSE_1_7_99;\n"
        + "\tinline constexpr auto RUNTIME_1_7_104 = RUNTIME_SSE_1_7_104;"
    )
    if anchor in v_txt:
        vh.write_text(v_txt.replace(anchor, legacy_block, 1), encoding="utf-8")
        print("[+] Patched CommonLibSSE-NG Version.h with legacy runtime aliases")

# 2. Patch include/SKSE/Interfaces.h with backward-compatible bool overloads & aliases
ih = root / "sdk" / "CommonLibSSE-NG" / "include" / "SKSE" / "Interfaces.h"
i_txt = ih.read_text(encoding="utf-8")
if "UsesStructsPost629" not in i_txt:
    old_methods = (
        "\t\tconstexpr void UsesAddressLibrary() noexcept { versionIndependence |= kVersionIndependent_AddressLibraryPostAE; }\n"
        "\t\tconstexpr void UsesSigScanning() noexcept { versionIndependence |= kVersionIndependent_Signatures; }\n"
        "\t\tconstexpr void UsesUpdatedStructs() noexcept { versionIndependence |= kVersionIndependent_StructsPost629; }\n\n"
        "\t\tconstexpr void UsesNoStructs() noexcept { versionIndependenceEx |= kVersionIndependentEx_NoStructUse; }"
    )
    new_methods = (
        "\t\tconstexpr void UsesAddressLibrary(bool a_value = true) noexcept { if (a_value) versionIndependence |= kVersionIndependent_AddressLibraryPostAE; }\n"
        "\t\tconstexpr void UsesSigScanning(bool a_value = true) noexcept { if (a_value) versionIndependence |= kVersionIndependent_Signatures; }\n"
        "\t\tconstexpr void UsesUpdatedStructs(bool a_value = true) noexcept { if (a_value) versionIndependence |= kVersionIndependent_StructsPost629; }\n"
        "\t\tconstexpr void UsesStructsPost629(bool a_value = true) noexcept { UsesUpdatedStructs(a_value); }\n\n"
        "\t\tconstexpr void UsesNoStructs(bool a_value = true) noexcept { if (a_value) versionIndependenceEx |= kVersionIndependentEx_NoStructUse; }\n"
        "\t\tconstexpr void HasNoStructUse(bool a_value = true) noexcept { UsesNoStructs(a_value); }"
    )
    if old_methods in i_txt:
        ih.write_text(i_txt.replace(old_methods, new_methods, 1), encoding="utf-8")
        print("[+] Patched CommonLibSSE-NG Interfaces.h with backward-compatible setters")

# 3. Patch sdk/CommonLibSSE-NG/xmake.lua so XMake builds also use CommonLibSSE-NG-Installed
xm = root / "sdk" / "CommonLibSSE-NG" / "xmake.lua"
if xm.exists():
    x_txt = xm.read_text(encoding="utf-8")
    x_changed = False
    if "CommonLibSSE-NG-Installed" not in x_txt:
        old_res = (
            '            if os.isfile(path.join(scriptdir, "lib", "commonlibsse-ng.lib")) then\n'
            '                return scriptdir\n'
            '            end'
        )
        new_res = (
            old_res
            + '\n            local installeddir = path.join(scriptdir, "..", "CommonLibSSE-NG-Installed")\n'
            + '            if os.isfile(path.join(installeddir, "lib", "CommonLibSSE.lib")) then\n'
            + '                return installeddir\n'
            + '            end'
        )
        if old_res in x_txt:
            x_txt = x_txt.replace(old_res, new_res, 1)
            x_changed = True
    old_lnk = '            target:add("links", "commonlibsse-ng", { public = true })'
    new_lnk = (
        '            if os.isfile(path.join(prebuiltdir, "lib", "CommonLibSSE.lib")) then\n'
        '                target:add("links", "CommonLibSSE", { public = true })\n'
        '            else\n'
        '                target:add("links", "commonlibsse-ng", { public = true })\n'
        '            end'
    )
    if old_lnk in x_txt and "CommonLibSSE.lib" not in x_txt.split("target:add(\"linkdirs\"", 1)[-1][:300]:
        x_txt = x_txt.replace(old_lnk, new_lnk, 1)
        x_changed = True
    if x_changed:
        xm.write_text(x_txt, encoding="utf-8")
        print("[+] Patched CommonLibSSE-NG xmake.lua to resolve CommonLibSSE-NG-Installed")

# 4. Sync CommonLibSSE-NG vcpkg-configuration.json & vcpkg.json to local tools/vcpkg HEAD
#    (vcpkg-configuration.json overrides vcpkg.json builtin-baseline; setting builtin registry ensures 100% cache hits)
vcpkg_head = subprocess.check_output(["git", "-C", "tools/vcpkg", "rev-parse", "HEAD"], text=True).strip()
clib_vcpkg_cfg = root / "sdk" / "CommonLibSSE-NG" / "vcpkg-configuration.json"
if clib_vcpkg_cfg.exists():
    cfg_data = json.loads(clib_vcpkg_cfg.read_text(encoding="utf-8"))
    cfg_data["default-registry"] = {"kind": "builtin", "baseline": vcpkg_head}
    clib_vcpkg_cfg.write_text(json.dumps(cfg_data, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Synced CommonLibSSE-NG/vcpkg-configuration.json builtin registry -> {vcpkg_head[:10]}")

clib_vcpkg = root / "sdk" / "CommonLibSSE-NG" / "vcpkg.json"
cv_data = json.loads(clib_vcpkg.read_text(encoding="utf-8"))
cv_changed = False
def _strip_ver_ge(dep_list):
    out = []
    changed = False
    for d in dep_list:
        if isinstance(d, dict) and "version>=" in d:
            d = {k: v for k, v in d.items() if k != "version>="}
            if set(d.keys()) == {"name"}:
                d = d["name"]
            changed = True
        out.append(d)
    return out, changed

if isinstance(cv_data.get("dependencies"), list):
    cv_data["dependencies"], ch = _strip_ver_ge(cv_data["dependencies"])
    cv_changed = cv_changed or ch
if isinstance(cv_data.get("features"), dict):
    for feat in cv_data["features"].values():
        if isinstance(feat, dict) and isinstance(feat.get("dependencies"), list):
            feat["dependencies"], ch = _strip_ver_ge(feat["dependencies"])
            cv_changed = cv_changed or ch
if clib_vcpkg_cfg.exists():
    if "builtin-baseline" in cv_data:
        cv_data.pop("builtin-baseline", None)
        cv_changed = True
elif cv_data.get("builtin-baseline") != vcpkg_head:
    cv_data["builtin-baseline"] = vcpkg_head
    cv_changed = True
    print(f"[+] Synced CommonLibSSE-NG/vcpkg.json builtin-baseline -> {vcpkg_head[:10]}")
if cv_changed:
    clib_vcpkg.write_text(json.dumps(cv_data, indent=2) + "\n", encoding="utf-8")
    print("[+] Updated CommonLibSSE-NG/vcpkg.json for local vcpkg HEAD compatibility")

# 5. Sync overlay port version-semver to match cloned CommonLibSSE-NG project VERSION
cm_txt = (root / "sdk" / "CommonLibSSE-NG" / "CMakeLists.txt").read_text(encoding="utf-8")
m = re.search(r"project\s*\([\s\S]*?VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)", cm_txt)
if m:
    clib_ver = m.group(1)
    ov_json = root / "sdk" / "vcpkg-overlays" / "commonlibsse-ng" / "vcpkg.json"
    ov_data = json.loads(ov_json.read_text(encoding="utf-8"))
    if ov_data.get("version-semver") != clib_ver:
        ov_data["version-semver"] = clib_ver
        ov_json.write_text(json.dumps(ov_data, indent=2) + "\n", encoding="utf-8")
        print(f"[+] Synced overlay commonlibsse-ng version-semver -> {clib_ver}")
'@ | python -
```

---

## Step 5: Populate `sdk/address_tables/`

Download the community SE (`1.5.97`) <-> AE (`1.6.x`) ID bridge (`se_ae_offsets.csv`), fetch the AE symbol names (`skyrimae.rename`) from `meh321/AddressLibraryDatabase`, and copy the Address Library `.bin` files from your local Skyrim installation:

```powershell
New-Item -ItemType Directory -Force -Path "sdk\address_tables\bin" | Out-Null

# Download SE <-> AE cross-reference CSV from alandtse/skyrim_vr_address_library
# (Supplies the historical 1.5.97 SE <-> 1.6.x AE ID bridge that meh321's AE-only .relib lacks)
if (-not (Test-Path "sdk\address_tables\se_ae_offsets.csv")) {
    Write-Host "[*] Downloading se_ae_offsets.csv..."
    & curl.exe -fsSL "https://raw.githubusercontent.com/alandtse/skyrim_vr_address_library/main/se_ae_offsets.csv" -o "sdk\address_tables\se_ae_offsets.csv"
    if ($LASTEXITCODE -ne 0) { throw "Failed to download se_ae_offsets.csv" }
}

# Download skyrimae.rename (~42k AE symbol names) from meh321/AddressLibraryDatabase
# (Pass --with-relib to also download skyrimae.relib ~74 MB if you need to extract historical 1.6.x Format 2 .bin files or CSV offset tables)
python "scripts/extract_relib.py" download
if ($LASTEXITCODE -ne 0) { throw "Failed to download skyrimae.rename" }

# Copy all Address Library version*.bin files from installed Skyrim Data\SKSE\Plugins\
$skyrimPlugins = python -c "import sys; sys.path.insert(0,'scripts'); import skse_env; print(skse_env.find_skyrim_plugins_dir())"
if ($skyrimPlugins -and (Test-Path $skyrimPlugins)) {
    $bins = Get-ChildItem -Path $skyrimPlugins -Filter "version*.bin" -File
    if ($bins.Count -gt 0) {
        foreach ($b in $bins) {
            Copy-Item -LiteralPath $b.FullName -Destination "sdk\address_tables\bin\$($b.Name)" -Force
        }
        Write-Host "[+] Copied $($bins.Count) Address Library .bin file(s) from $skyrimPlugins"
    } else {
        Write-Warning "No version*.bin files found in $skyrimPlugins. Install Address Library for SKSE Plugins in Skyrim!"
    }
} else {
    Write-Warning "Could not locate Skyrim Data\SKSE\Plugins automatically; copy version*.bin into sdk\address_tables\bin\ manually."
}
```

*(Note: Historical cross-referencing and the unit tests expect historical baselines `version-1-5-97-0.bin` and `versionlib-1-6-1170-0.bin` in `sdk/address_tables/bin/` alongside your active `versionlib-<major>-<minor>-<build>-<subbuild>.bin`. If your Skyrim folder only contains AE `.bin` files, install the "All in one" Address Library archives from Nexus Mods #32444 so both SE 1.5.x and AE 1.6+/1.7+ `.bin` files are present.)*

---

## Step 6: Detect Active Skyrim Runtime & Sync SDK Constants

Run **Detect-First** to inspect the user's installed `SkyrimSE.exe` / `skse64_*.dll` / `versionlib-*.bin`. If `sdk_needs_registration=True` (e.g., a brand-new Skyrim patch newer than upstream `skse64` / `CommonLibSSE-NG`), register it **before** compiling `CommonLibSSE-NG-Installed`:

```powershell
python "scripts/skse_env.py"
# If SDK Sync Status shows [!] missing registration, run:
python "scripts/add_new_runtime.py"
```

---

## Step 7: Build & Install `sdk/CommonLibSSE-NG-Installed/`

Run `cmake` inside `scripts/env.py` (which activates MSVC + portable tools automatically) and compile `CommonLibSSE.lib` once into `sdk/CommonLibSSE-NG-Installed/` (takes ~1–3 minutes depending on CPU cores; afterwards all CMake mod builds link against it in ~1 second):

```powershell
$repoFwd = ((Get-Location).Path -replace '\\', '/')
$buildDir = "sdk/CommonLibSSE-NG/build"

python "scripts/env.py" -- cmake -S "sdk/CommonLibSSE-NG" -B $buildDir -G Ninja `
    "-DCMAKE_MAKE_PROGRAM=$repoFwd/tools/ninja/ninja.exe" `
    "-DCMAKE_BUILD_TYPE=Release" `
    "-DCMAKE_TOOLCHAIN_FILE=$repoFwd/tools/vcpkg/scripts/buildsystems/vcpkg.cmake" `
    "-DVCPKG_TARGET_TRIPLET=x64-windows-static-md" `
    "-DVCPKG_MANIFEST_NO_DEFAULT_FEATURES=ON" `
    "-DVCPKG_INSTALL_OPTIONS=--clean-after-build" `
    '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>DLL' `
    "-DREX_OPTION_INI=ON" `
    "-DREX_OPTION_JSON=ON" `
    "-DREX_OPTION_TOML=ON" `
    "-DSKSE_SUPPORT_XBYAK=ON" `
    "-DSKSE_SUPPORT_PATCH_SAFETY=ON" `
    "-DENABLE_SKYRIM_SE=ON" `
    "-DENABLE_SKYRIM_AE=ON" `
    "-DENABLE_SKYRIM_VR=ON" `
    "-DBUILD_TESTS=OFF" `
    "-DCOMMONLIB_ENABLE_IPO=OFF" `
    "-DCMAKE_INSTALL_PREFIX=$repoFwd/sdk/CommonLibSSE-NG-Installed"
if ($LASTEXITCODE -ne 0) { throw "CommonLibSSE-NG CMake configure failed" }

python "scripts/env.py" -- cmake --build $buildDir
if ($LASTEXITCODE -ne 0) { throw "CommonLibSSE-NG build failed" }

python "scripts/env.py" -- cmake --install $buildDir
if ($LASTEXITCODE -ne 0) { throw "CommonLibSSE-NG install failed" }

# Clean temporary build intermediates while preserving tools/vcpkg/archives/ binary cache
foreach ($tmp in @("sdk\CommonLibSSE-NG\build", "tools\vcpkg\buildtrees", "tools\vcpkg\packages", "tools\vcpkg\downloads")) {
    if (Test-Path $tmp) { cmd /c rmdir /s /q $tmp }
}
```

*(Note: Passing `-DVCPKG_MANIFEST_NO_DEFAULT_FEATURES=ON` skips building `Catch2` since `-DBUILD_TESTS=OFF`.)*

---

## Step 8: Verify Complete Installation

Run all four verification checks to confirm the workspace is 100% operational:

```powershell
python "scripts/env.py"
python "scripts/skse_env.py"
.\.venv\Scripts\python.exe -c "import pefile, capstone, keystone, lief; print('RE stack OK')"
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Expected results:
1. `env.py` reports `[OK]` for `cl`, `cmake`, `ninja`, `vcpkg`, `xmake`, `git`, `python`, and sets `COMMONLIB_PREBUILT_DIR`.
2. `skse_env.py` reports `SDK Sync Status : skse64=True, CommonLibSSE-NG=True, bin_in_sdk=True`.
3. `.venv` imports `pefile`, `capstone`, `keystone`, and `lief` cleanly and prints `RE stack OK`.
4. All unit and end-to-end build tests (`tests/`) pass (`OK`).

---

## Maintainer Note: Packaging Clean Nexus Mods Releases (Zero `.exe`/`.dll`/`.lib`/`.ps1`)

Before zipping AI-SPUE for upload to Nexus Mods:
1. Remove `.venv/`, `tools/`, and `sdk/` contents cleanly (use `cmd /c rmdir /s /q` if `.git` read-only packfiles are present), recreate empty `tools/` and `sdk/` (with `.gitkeep` kept in git, and omitted or empty folders in the Nexus ZIP).
2. Exclude `.git/`, `.venv/`, `workspace/`, `dist/`, `__pycache__/`, and `.pytest_cache/`.
3. Verify zero binaries or shell scripts remain in the staging tree:
   ```powershell
   Get-ChildItem -Recurse -File -Include *.exe,*.dll,*.lib,*.ps1,*.bat,*.cmd,*.msi,*.vbs
   ```
   Confirm the result is empty before creating the Nexus Mods `.zip` / `.7z` archive. Keep [`templates/sdk/`](templates/sdk/) included so `SETUP.md` can restore all custom AI-SPUE files locally on the user's machine.
