# ==============================================================================
# SKSE64 Automated Live Test & Crash Debug Runner (scripts/live_test_skse.ps1)
#
# Deploys a compiled/patched SKSE plugin DLL (with automatic backup/restore),
# clears stale logs, launches skse64_loader.exe, streams skse64.log & plugin logs
# in real time, monitors SkyrimSE.exe for early CTDs/hangs, collects Crash Logger /
# Trainwreck + Windows Event Log entries, and invokes scripts/triage_crash.py.
#
# Exit Codes:
#   0 = Success (plugin loaded & init complete, or -NoLaunch diagnostics completed)
#   1 = SKSE rejected plugin (incompatible / AddressLibraryV5 / Query mismatch)
#   2 = Crash / early CTD detected
#   3 = Timeout or hang before SKSE init complete
#   4 = Setup / launch error (missing DLL, SkyrimDir, or skse64_loader.exe)
# ==============================================================================

param(
    [string]$PluginDll = "",
    [string]$PluginsDir = "",
    [string]$SkyrimDir = "",
    [string]$LogDir = "",
    [int]$TimeoutSeconds = 45,
    [switch]$AutoClose,
    [switch]$KeepDeployed,
    [switch]$NoLaunch,
    [switch]$NoClearLogs
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Resolve-SkyrimDir {
    param([string]$ExplicitDir)
    if ($ExplicitDir -and (Test-Path $ExplicitDir)) {
        return (Resolve-Path $ExplicitDir).Path
    }
    if ($env:Skyrim64Path -and (Test-Path $env:Skyrim64Path)) {
        return $env:Skyrim64Path.TrimEnd('\')
    }
    foreach ($regPath in @(
        "HKLM:\SOFTWARE\WOW6432Node\Bethesda Softworks\Skyrim Special Edition",
        "HKLM:\SOFTWARE\Bethesda Softworks\Skyrim Special Edition"
    )) {
        if (Test-Path $regPath) {
            $val = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue)."Installed Path"
            if ($val -and (Test-Path $val)) {
                return $val.TrimEnd('\')
            }
        }
    }
    foreach ($cand in @(
        "C:\Program Files (x86)\Steam\steamapps\common\Skyrim Special Edition",
        "C:\Program Files\Steam\steamapps\common\Skyrim Special Edition",
        "D:\Steam\steamapps\common\Skyrim Special Edition",
        "D:\SteamLibrary\steamapps\common\Skyrim Special Edition",
        "E:\SteamLibrary\steamapps\common\Skyrim Special Edition"
    )) {
        if (Test-Path $cand) {
            return $cand
        }
    }
    return $null
}

function Read-NewLogLines {
    param(
        [string]$Path,
        [ref]$ByteOffset
    )
    if (-not (Test-Path $Path)) {
        return @()
    }
    $lines = @()
    $fs = $null
    $sr = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        if ($fs.Length -lt $ByteOffset.Value) {
            $ByteOffset.Value = 0
        }
        $null = $fs.Seek($ByteOffset.Value, [System.IO.SeekOrigin]::Begin)
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8, $true)
        while (-not $sr.EndOfStream) {
            $lines += $sr.ReadLine()
        }
        $ByteOffset.Value = $fs.Position
    } catch {
        # Ignore transient file locks during write
    } finally {
        if ($sr) { $sr.Dispose() }
        if ($fs) { $fs.Dispose() }
    }
    return $lines
}

$resolvedSkyrim = Resolve-SkyrimDir -ExplicitDir $SkyrimDir
if (-not $PluginsDir) {
    if ($resolvedSkyrim) {
        $PluginsDir = Join-Path $resolvedSkyrim "Data\SKSE\Plugins"
    }
}
if (-not $LogDir) {
    $LogDir = Join-Path $env:USERPROFILE "Documents\My Games\Skyrim Special Edition\SKSE"
}

$detectedSkyVer = $null
$detectedSkse = $null
$detectedBin = $null
if ($resolvedSkyrim) {
    $skyExe = Join-Path $resolvedSkyrim "SkyrimSE.exe"
    if (Test-Path $skyExe) {
        $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($skyExe)
        $detectedSkyVer = "$($fvi.FileMajorPart).$($fvi.FileMinorPart).$($fvi.FileBuildPart).$($fvi.FilePrivatePart)"
    }
    $skseDll = Get-ChildItem -Path $resolvedSkyrim -Filter "skse64_*_*_*.dll" -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($skseDll) {
        $svi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($skseDll.FullName)
        $detectedSkse = "$($skseDll.Name) (SKSE v$($svi.FileMinorPart).$($svi.FileBuildPart).$($svi.FilePrivatePart))"
    }
    if ($PluginsDir -and (Test-Path $PluginsDir)) {
        if ($detectedSkyVer) {
            $candBin = Join-Path $PluginsDir ("versionlib-" + ($detectedSkyVer -replace '\.', '-') + ".bin")
            if (Test-Path $candBin) { $detectedBin = Split-Path -Leaf $candBin }
        }
        if (-not $detectedBin) {
            $latestBin = Get-ChildItem -Path $PluginsDir -Filter "version*.bin" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latestBin) { $detectedBin = $latestBin.Name }
        }
    }
}

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host " SKSE64 Live Test & Debug Runner" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  SkyrimDir   : $(if ($resolvedSkyrim) { $resolvedSkyrim } else { '<not found>' })"
Write-Host "  SkyrimVer   : $(if ($detectedSkyVer) { $detectedSkyVer } else { '<not detected>' })"
Write-Host "  SKSE64      : $(if ($detectedSkse) { $detectedSkse } else { '<not detected>' })"
Write-Host "  AddrLibBin  : $(if ($detectedBin) { $detectedBin } else { '<not detected>' })"
Write-Host "  PluginsDir  : $(if ($PluginsDir) { $PluginsDir } else { '<not found>' })"
Write-Host "  LogDir      : $LogDir"
Write-Host "  Mode        : $(if ($NoLaunch) { 'NO-LAUNCH (Diagnostic Inspect)' } else { 'LIVE LAUNCH' })"
Write-Host "============================================================================" -ForegroundColor Cyan

$deployedDest = $null
$backupPath = $null
$deployedNewFile = $false
$pluginStem = $null
$exitCode = 0

try {
    if ($PluginDll) {
        if (-not (Test-Path $PluginDll)) {
            Write-Error "Plugin DLL not found: $PluginDll"
            $exitCode = 4
            return
        }
        if (-not $PluginsDir -or -not (Test-Path $PluginsDir)) {
            Write-Error "Target Plugins directory not found: $PluginsDir"
            $exitCode = 4
            return
        }
        $srcDll = (Resolve-Path $PluginDll).Path
        $dllName = [System.IO.Path]::GetFileName($srcDll)
        $pluginStem = [System.IO.Path]::GetFileNameWithoutExtension($srcDll)
        $deployedDest = Join-Path $PluginsDir $dllName
        $backupPath = "$deployedDest.livetest.bak"

        if ($srcDll -ne $deployedDest) {
            if (Test-Path $deployedDest) {
                Copy-Item -Path $deployedDest -Destination $backupPath -Force
                Write-Host "[*] Backed up existing $dllName -> $dllName.livetest.bak"
            } else {
                $deployedNewFile = $true
            }
            Copy-Item -Path $srcDll -Destination $deployedDest -Force
            Write-Host "[+] Deployed $dllName -> $PluginsDir" -ForegroundColor Green
        } else {
            Write-Host "[*] PluginDll is already in $PluginsDir"
        }
    }

    $skseLogPath = Join-Path $LogDir "skse64.log"
    $pluginLogPath = if ($pluginStem) { Join-Path $LogDir "$pluginStem.log" } else { $null }
    $launchTime = if ($NoLaunch) { (Get-Date).AddHours(-1) } else { Get-Date }

    if (-not $NoLaunch) {
        if (-not $resolvedSkyrim) {
            Write-Error "Could not locate Skyrim Special Edition directory. Pass -SkyrimDir."
            $exitCode = 4
            return
        }
        $loaderExe = Join-Path $resolvedSkyrim "skse64_loader.exe"
        if (-not (Test-Path $loaderExe)) {
            Write-Error "skse64_loader.exe not found at: $loaderExe"
            $exitCode = 4
            return
        }

        if (-not $NoClearLogs -and (Test-Path $LogDir)) {
            foreach ($lp in @($skseLogPath, $pluginLogPath)) {
                if ($lp -and (Test-Path $lp)) {
                    Remove-Item -Path $lp -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Host "[*] Cleared previous SKSE/plugin logs before launch."
        }

        Write-Host "[*] Launching skse64_loader.exe (timeout=${TimeoutSeconds}s, AutoClose=$AutoClose)..." -ForegroundColor Cyan
        $launchTime = Get-Date
        $loaderProc = Start-Process -FilePath $loaderExe -WorkingDirectory $resolvedSkyrim -PassThru

        $skyProc = $null
        $waitStart = Get-Date
        while (((Get-Date) - $waitStart).TotalSeconds -lt [Math]::Min(20, $TimeoutSeconds)) {
            $skyProc = Get-Process -Name "SkyrimSE" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($skyProc) { break }
            if ($loaderProc.HasExited -and $loaderProc.ExitCode -ne 0) {
                Write-Host "[!!] skse64_loader.exe exited early with code $($loaderProc.ExitCode)" -ForegroundColor Red
                $exitCode = 4
                break
            }
            Start-Sleep -Milliseconds 300
        }

        $skseOffset = [long]0
        $plugOffset = [long]0
        $rejectedPlugin = $false
        $pluginLoaded = $false
        $initComplete = $false
        $crashedEarly = $false
        $hangDetected = $false
        $initTime = $null

        if ($skyProc) {
            Write-Host "[*] SkyrimSE.exe started (PID=$($skyProc.Id)). Streaming logs..." -ForegroundColor Green
            $pollStart = Get-Date
            while (((Get-Date) - $pollStart).TotalSeconds -lt $TimeoutSeconds) {
                foreach ($line in (Read-NewLogLines -Path $skseLogPath -ByteOffset ([ref]$skseOffset))) {
                    Write-Host "  [skse64] $line"
                    if ($line -match "reported as incompatible|must be recompiled for new address library") {
                        if (-not $pluginStem -or $line -match [regex]::Escape($pluginStem)) {
                            $rejectedPlugin = $true
                        }
                    }
                    if ($pluginStem -and $line -match [regex]::Escape($pluginStem) -and $line -match "loaded correctly") {
                        $pluginLoaded = $true
                    }
                    if ($line -match "init complete|dispatch message") {
                        if (-not $initComplete) {
                            $initComplete = $true
                            $initTime = Get-Date
                        }
                    }
                }
                if ($pluginLogPath) {
                    foreach ($line in (Read-NewLogLines -Path $pluginLogPath -ByteOffset ([ref]$plugOffset))) {
                        Write-Host "  [$pluginStem] $line"
                    }
                }

                $skyProc.Refresh()
                if ($skyProc.HasExited) {
                    Write-Host "[!!] SkyrimSE.exe exited prematurely (ExitCode=$($skyProc.ExitCode))" -ForegroundColor Red
                    $crashedEarly = $true
                    break
                }
                if ($skyProc.MainWindowHandle -ne [IntPtr]::Zero -and -not $skyProc.Responding) {
                    $hangDetected = $true
                }
                if ($initComplete -and $AutoClose -and $initTime -and (((Get-Date) - $initTime).TotalSeconds -ge 3.0)) {
                    Write-Host "[OK] SKSE init complete + 3s settle window elapsed; closing SkyrimSE.exe (-AutoClose)." -ForegroundColor Green
                    Stop-Process -Id $skyProc.Id -Force -ErrorAction SilentlyContinue
                    break
                }
                Start-Sleep -Milliseconds 500
            }

            # Drain final log lines
            foreach ($line in (Read-NewLogLines -Path $skseLogPath -ByteOffset ([ref]$skseOffset))) {
                Write-Host "  [skse64] $line"
                if ($line -match "reported as incompatible|must be recompiled") { $rejectedPlugin = $true }
                if ($line -match "init complete|dispatch message") { $initComplete = $true }
            }
            if ($pluginLogPath) {
                foreach ($line in (Read-NewLogLines -Path $pluginLogPath -ByteOffset ([ref]$plugOffset))) {
                    Write-Host "  [$pluginStem] $line"
                }
            }

            $skyProc.Refresh()
            if (-not $skyProc.HasExited -and $AutoClose) {
                Stop-Process -Id $skyProc.Id -Force -ErrorAction SilentlyContinue
            }
        } elseif ($exitCode -eq 0) {
            Write-Host "[!!] Timed out waiting for SkyrimSE.exe to launch." -ForegroundColor Red
            $exitCode = 3
        }

        if ($rejectedPlugin) { $exitCode = 1 }
        elseif ($crashedEarly) { $exitCode = 2 }
        elseif (-not $initComplete -and $exitCode -eq 0) {
            if ($hangDetected) {
                Write-Host "[!!] SkyrimSE.exe stopped responding before SKSE init complete." -ForegroundColor Red
            } else {
                Write-Host "[!!] Timeout reached before SKSE init complete." -ForegroundColor Yellow
            }
            $exitCode = 3
        }
    }

    # Crash Logger + Trainwreck scan
    Write-Host "`n--- Crash & Diagnostic Summary ---" -ForegroundColor Cyan
    if (Test-Path $LogDir) {
        $crashFiles = @()
        $crashFiles += Get-ChildItem -Path $LogDir -Filter "crash-*.log" -ErrorAction SilentlyContinue
        $twDir = Join-Path $LogDir "Trainwreck"
        if (Test-Path $twDir) {
            $crashFiles += Get-ChildItem -Path $twDir -Filter "crash-*.log" -ErrorAction SilentlyContinue
        }
        $recentCrashes = $crashFiles | Where-Object { $NoLaunch -or $_.LastWriteTime -ge $launchTime } | Sort-Object LastWriteTime -Descending
        if ($recentCrashes) {
            $latestCrash = $recentCrashes[0]
            Write-Host "[!!] Crash Log Found: $($latestCrash.FullName)" -ForegroundColor Red
            Get-Content $latestCrash.FullName -TotalCount 35 | ForEach-Object { Write-Host "  $_" }
            if (-not $NoLaunch -and $exitCode -eq 0) { $exitCode = 2 }
        } else {
            Write-Host "[OK] No new Crash Logger / Trainwreck crash dumps." -ForegroundColor Green
        }
    } else {
        Write-Host "[INFO] SKSE LogDir does not exist yet: $LogDir"
    }

    # Windows Application Event Log check
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = "Application"
            ProviderName = @("Application Error", "Windows Error Reporting")
            StartTime = $launchTime
        } -MaxEvents 5 -ErrorAction SilentlyContinue
        $skyEvents = $events | Where-Object { $_.Message -match "SkyrimSE|skse64" }
        if ($skyEvents) {
            Write-Host "`n[!] Windows Application Error Events:" -ForegroundColor Yellow
            foreach ($ev in $skyEvents) {
                Write-Host "  [$($ev.TimeCreated)] $($ev.ProviderName): $($ev.Message -replace '\r?\n', ' ')"
            }
        }
    } catch {
        # No matching events or restricted log access
    }

    # Python triage_crash.py summary
    if ((Get-Command "python" -ErrorAction SilentlyContinue) -and (Test-Path $LogDir)) {
        Write-Host ""
        & python (Join-Path $RepoRoot "scripts\triage_crash.py") $LogDir
    }
}
finally {
    if ($deployedDest -and -not $KeepDeployed) {
        if ($backupPath -and (Test-Path $backupPath)) {
            Move-Item -Path $backupPath -Destination $deployedDest -Force
            Write-Host "`n[*] Restored original $([System.IO.Path]::GetFileName($deployedDest)) from backup."
        } elseif ($deployedNewFile -and (Test-Path $deployedDest)) {
            Remove-Item -Path $deployedDest -Force -ErrorAction SilentlyContinue
            Write-Host "`n[*] Removed temporary test DLL $deployedDest."
        }
    }
}

exit $exitCode
