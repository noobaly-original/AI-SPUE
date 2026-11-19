# ==============================================================================
# SKSE Plugin Update Environment Activator (scripts/env.ps1)
# Usage in PowerShell:
#   . ".\scripts\env.ps1"
# ==============================================================================

param(
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

# 1. Locate Visual Studio 2022 / MSVC vcvars64.bat
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = $null
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
}
if (-not $vsPath -and (Test-Path "C:\Program Files\Microsoft Visual Studio\2022\Community")) {
    $vsPath = "C:\Program Files\Microsoft Visual Studio\2022\Community"
}

if ($vsPath) {
    $vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
    if (Test-Path $vcvars) {
        # Only run vcvars64 if cl.exe is not already on PATH
        if (-not (Get-Command "cl.exe" -ErrorAction SilentlyContinue)) {
            $envDump = cmd /c "`"$vcvars`" >nul 2>&1 && set"
            foreach ($line in $envDump) {
                if ($line -match "^([^=]+)=(.*)$") {
                    [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
                }
            }
        }
    }
}

# 2. Add local portable tools (CMake, Ninja, vcpkg, XMake, .venv) to PATH
$cmakeBin = Join-Path $RepoRoot "tools\cmake\bin"
$ninjaBin = Join-Path $RepoRoot "tools\ninja"
$vcpkgRoot = Join-Path $RepoRoot "tools\vcpkg"
$xmakeBin = Join-Path $RepoRoot "tools\xmake"
$venvBin = Join-Path $RepoRoot ".venv\Scripts"
$venvSite = Join-Path $RepoRoot ".venv\Lib\site-packages"
$venvCfg = Join-Path $RepoRoot ".venv\pyvenv.cfg"

# Only prepend .venv\Scripts when its configured base Python home exists locally;
# otherwise keep host system python first and expose bundled packages via PYTHONPATH.
$venvHomeValid = $false
if (Test-Path $venvCfg) {
    $homeLine = Get-Content $venvCfg -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*home\s*=\s*(.+)$' } | Select-Object -First 1
    if ($homeLine -and ($homeLine -match '^\s*home\s*=\s*(.+)$')) {
        $venvHomeDir = $matches[1].Trim()
        if (Test-Path (Join-Path $venvHomeDir "python.exe")) {
            $venvHomeValid = $true
        }
    }
}
if (Test-Path $venvSite) {
    if (-not $env:PYTHONPATH) {
        $env:PYTHONPATH = $venvSite
    } elseif ($env:PYTHONPATH -notlike "*$venvSite*") {
        $env:PYTHONPATH = "$venvSite;$env:PYTHONPATH"
    }
}

$toolBins = @($xmakeBin, $vcpkgRoot, $ninjaBin, $cmakeBin)
if ($venvHomeValid) {
    $toolBins = @($venvBin) + $toolBins
}
foreach ($p in $toolBins) {
    if ((Test-Path $p) -and ($env:PATH -notlike "*$p*")) {
        $env:PATH = "$p;$env:PATH"
    }
}

# 3. Export environment variables for CMake, vcpkg, and CommonLibSSE-NG
$vcpkgArchives = Join-Path $vcpkgRoot "archives"
if (-not (Test-Path $vcpkgArchives)) { New-Item -ItemType Directory -Path $vcpkgArchives -Force | Out-Null }
$env:VCPKG_ROOT = $vcpkgRoot
$env:VCPKG_DEFAULT_TRIPLET = "x64-windows-static-md"
$env:VCPKG_DEFAULT_BINARY_CACHE = $vcpkgArchives
$env:SKSE_UPDATER_ROOT = $RepoRoot
$env:SKSE_SDK_ROOT = Join-Path $RepoRoot "sdk"
$env:COMMONLIB_SSE_NG_DIR = Join-Path $RepoRoot "sdk\CommonLibSSE-NG"
$env:COMMONLIB_PREBUILT = "1"

$prebuiltCmake = Join-Path $RepoRoot "sdk\CommonLibSSE-NG-Installed"
if (Test-Path (Join-Path $prebuiltCmake "lib\CommonLibSSE.lib")) {
    $env:COMMONLIB_PREBUILT_DIR = ($prebuiltCmake -replace '\\', '/')
}

# Optional Skyrim SE installation auto-detection
foreach ($regPath in @(
    "HKLM:\SOFTWARE\WOW6432Node\Bethesda Softworks\Skyrim Special Edition",
    "HKLM:\SOFTWARE\Bethesda Softworks\Skyrim Special Edition"
)) {
    if (Test-Path $regPath) {
        $installPath = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue)."Installed Path"
        if ($installPath -and (Test-Path $installPath)) {
            $env:Skyrim64Path = $installPath.TrimEnd('\')
            break
        }
    }
}
if (-not $env:Skyrim64Path) {
    foreach ($cand in @(
        "C:\Program Files (x86)\Steam\steamapps\common\Skyrim Special Edition",
        "C:\Program Files\Steam\steamapps\common\Skyrim Special Edition",
        "D:\Steam\steamapps\common\Skyrim Special Edition",
        "D:\SteamLibrary\steamapps\common\Skyrim Special Edition",
        "E:\SteamLibrary\steamapps\common\Skyrim Special Edition"
    )) {
        if (Test-Path $cand) {
            $env:Skyrim64Path = $cand
            break
        }
    }
}

$detectedExeVer = $null
$detectedSkseInfo = $null
$detectedBinName = $null
if ($env:Skyrim64Path) {
    $skyExe = Join-Path $env:Skyrim64Path "SkyrimSE.exe"
    if (Test-Path $skyExe) {
        $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($skyExe)
        $detectedExeVer = "$($fvi.FileMajorPart).$($fvi.FileMinorPart).$($fvi.FileBuildPart).$($fvi.FilePrivatePart)"
        $env:SKSE_DETECTED_RUNTIME = $detectedExeVer
    }
    $skseDll = Get-ChildItem -Path $env:Skyrim64Path -Filter "skse64_*_*_*.dll" -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($skseDll) {
        $svi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($skseDll.FullName)
        $skseVerStr = "$($svi.FileMinorPart).$($svi.FileBuildPart).$($svi.FilePrivatePart)"
        $detectedSkseInfo = "$($skseDll.Name) (SKSE v$skseVerStr)"
    }
    $plugDir = Join-Path $env:Skyrim64Path "Data\SKSE\Plugins"
    if (Test-Path $plugDir) {
        if ($detectedExeVer) {
            $dashVer = $detectedExeVer -replace '\.', '-'
            $exactBin = Join-Path $plugDir "versionlib-$dashVer.bin"
            if (Test-Path $exactBin) {
                $detectedBinName = Split-Path -Leaf $exactBin
            }
        }
        if (-not $detectedBinName) {
            $latestBin = Get-ChildItem -Path $plugDir -Filter "version*.bin" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latestBin) { $detectedBinName = $latestBin.Name }
        }
    }
}

if (-not $Quiet) {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " SKSE Plugin Update Environment Activated" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    foreach ($tool in @("cl", "cmake", "ninja", "vcpkg", "xmake", "git", "python")) {
        $cmd = Get-Command $tool -ErrorAction SilentlyContinue
        if ($cmd) {
            Write-Host ("  [OK] {0,-8} : {1}" -f $tool, $cmd.Source) -ForegroundColor Green
        } else {
            Write-Host ("  [!!] {0,-8} : NOT FOUND" -f $tool) -ForegroundColor Red
        }
    }
    Write-Host "  VCPKG_ROOT            : $env:VCPKG_ROOT"
    Write-Host "  VCPKG_BINARY_CACHE    : $env:VCPKG_DEFAULT_BINARY_CACHE"
    Write-Host "  COMMONLIB_SSE_NG_DIR  : $env:COMMONLIB_SSE_NG_DIR"
    Write-Host "  COMMONLIB_PREBUILT_DIR: $env:COMMONLIB_PREBUILT_DIR"
    if ($env:Skyrim64Path) {
        Write-Host "  Skyrim64Path          : $env:Skyrim64Path"
    }
    if ($detectedExeVer) {
        Write-Host "  Detected SkyrimSE.exe : $detectedExeVer"
    }
    if ($detectedSkseInfo) {
        Write-Host "  Detected SKSE64       : $detectedSkseInfo"
    }
    if ($detectedBinName) {
        Write-Host "  Detected AddrLib .bin : $detectedBinName"
    }
    Write-Host "============================================================" -ForegroundColor Cyan
}
