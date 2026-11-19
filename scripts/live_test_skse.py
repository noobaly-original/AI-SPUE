#!/usr/bin/env python3
"""SKSE64 Automated Live Test & Crash Debug Runner (`scripts/live_test_skse.py`).

Pure-Python automated deployment, live launch, log monitor, and crash triage runner.
Deploys a compiled/patched SKSE plugin DLL (with automatic backup/restore),
clears stale logs, launches `skse64_loader.exe`, streams `skse64.log` and plugin
logs in real time, monitors `SkyrimSE.exe` for early CTDs/hangs, collects Crash
Logger / Trainwreck dumps + Windows Event Log entries, and invokes
`scripts/triage_crash.py`.

Exit Codes:
  0 = Success (plugin loaded & init complete, or `--no-launch` diagnostics completed)
  1 = SKSE rejected plugin (incompatible / AddressLibraryV5 / Query mismatch)
  2 = Crash / early CTD detected
  3 = Timeout or hang before SKSE init complete
  4 = Setup / launch error (missing DLL, SkyrimDir, or skse64_loader.exe)
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
import xml.etree.ElementTree as ET

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402
import triage_crash  # noqa: E402

_RE_REJECT = re.compile(r"reported as incompatible|must be recompiled for new address library", re.IGNORECASE)
_RE_REJECT_DRAIN = re.compile(r"reported as incompatible|must be recompiled", re.IGNORECASE)
_RE_LOADED = re.compile(r"loaded correctly", re.IGNORECASE)
_RE_INIT = re.compile(r"init complete|dispatch message", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Win32 ctypes helpers (only active on Windows)
# ---------------------------------------------------------------------------
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
STILL_ACTIVE = 259
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def find_process_pid(exe_name: str = "SkyrimSE.exe") -> Optional[int]:
    """Return first running PID matching `exe_name` (case-insensitive) via Toolhelp32."""
    if sys.platform != "win32":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or not snap:
        return None
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        target_low = exe_name.lower()
        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            if pe.szExeFile.lower() == target_low:
                return int(pe.th32ProcessID)
            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        kernel32.CloseHandle(snap)
    return None


def get_process_exit_code(pid: int) -> Tuple[bool, Optional[int]]:
    """Return `(has_exited, exit_code)` for `pid`."""
    if sys.platform != "win32":
        return True, None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    if not handle:
        return True, None
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True, None
        val = int(code.value)
        if val != STILL_ACTIVE:
            return True, val
        wait_res = kernel32.WaitForSingleObject(handle, 0)
        if wait_res == 0:  # WAIT_OBJECT_0
            kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            return True, int(code.value)
        return False, None
    finally:
        kernel32.CloseHandle(handle)


def is_process_window_unresponsive(pid: int) -> bool:
    """Return True when any top-level visible window of `pid` reports hung to DWM/User32."""
    if sys.platform != "win32":
        return False
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    hung = False
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _cb(hwnd: wintypes.HWND, _lparam: wintypes.LPARAM) -> bool:
        nonlocal hung
        win_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(win_pid))
        if int(win_pid.value) == pid and user32.IsWindowVisible(hwnd):
            if user32.IsHungAppWindow(hwnd):
                hung = True
                return False
        return True

    user32.EnumWindows(WNDENUMPROC(_cb), 0)
    return hung


def terminate_process(pid: int) -> None:
    """Force-terminate `pid` cleanly using Win32 `TerminateProcess`."""
    if sys.platform != "win32":
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, False, pid)
    if handle:
        try:
            if kernel32.TerminateProcess(handle, 0):
                kernel32.WaitForSingleObject(handle, 3000)
                return
        finally:
            kernel32.CloseHandle(handle)
    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, check=False)


# ---------------------------------------------------------------------------
# Log reading & Skyrim environment resolution
# ---------------------------------------------------------------------------
def resolve_skyrim_dir(explicit_dir: str = "") -> Optional[Path]:
    if explicit_dir:
        p = Path(explicit_dir)
        if p.exists():
            return p.resolve()
        return p
    env_dir = os.environ.get("Skyrim64Path", "").strip()
    if env_dir:
        p = Path(env_dir)
        if p.exists():
            return p
    detected = skse_env.find_skyrim_install_dir()
    if detected.exists():
        return detected
    return None


def read_new_log_lines(log_path: Path, byte_offset: int) -> Tuple[List[str], int]:
    """Incrementally read newly appended lines from `log_path` starting at `byte_offset`."""
    if not log_path.exists():
        return [], byte_offset
    try:
        with log_path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            length = f.tell()
            if length < byte_offset:
                byte_offset = 0
            if length == byte_offset:
                return [], byte_offset
            f.seek(byte_offset, os.SEEK_SET)
            raw = f.read(length - byte_offset)
            new_offset = f.tell()
    except OSError:
        return [], byte_offset

    encoding = "utf-8-sig" if byte_offset == 0 else "utf-8"
    text = raw.decode(encoding, errors="replace")
    return text.splitlines(), new_offset


def find_recent_crash_logs(log_dir: Path, *, since_epoch: float, include_all: bool = False) -> List[Path]:
    """Return matching Crash Logger / Trainwreck `crash-*.log` files sorted newest-first."""
    if not log_dir.exists():
        return []
    candidates: List[Path] = list(log_dir.glob("crash-*.log"))
    tw_dir = log_dir / "Trainwreck"
    if tw_dir.exists():
        candidates.extend(tw_dir.glob("crash-*.log"))
    filtered: List[Path] = []
    for p in candidates:
        try:
            mtime = p.stat().st_mtime
        except OSError:
            continue
        if include_all or mtime >= since_epoch:
            filtered.append(p)
    filtered.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return filtered


def query_windows_skyrim_crash_events(since_epoch: float, max_events: int = 5) -> List[Tuple[str, str, str]]:
    """Query Application Error / WER events mentioning SkyrimSE or skse64 via `wevtutil.exe`."""
    if sys.platform != "win32" or shutil.which("wevtutil.exe") is None:
        return []
    iso_utc = datetime.fromtimestamp(since_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    xpath = (
        "*[System[Provider[@Name='Application Error' or @Name='Windows Error Reporting'] "
        f"and TimeCreated[@SystemTime>='{iso_utc}']]]"
    )
    res = subprocess.run(
        ["wevtutil.exe", "qe", "Application", f"/c:{max_events}", "/rd:true", "/f:XML", f"/q:{xpath}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if res.returncode != 0 or not res.stdout.strip():
        return []

    xml_body = f"<Events>{res.stdout}</Events>"
    try:
        root = ET.fromstring(xml_body)
    except ET.ParseError:
        return []

    hits: List[Tuple[str, str, str]] = []
    for ev in root:
        provider = ""
        time_str = ""
        for child in ev.iter():
            tag = child.tag.rsplit("}", 1)[-1]
            if tag == "Provider" and "Name" in child.attrib:
                provider = child.attrib["Name"]
            elif tag == "TimeCreated" and "SystemTime" in child.attrib:
                time_str = child.attrib["SystemTime"]
        flat_text = " ".join(" ".join(t.split()) for t in ev.itertext() if t.strip())
        if re.search(r"SkyrimSE|skse64", flat_text, re.IGNORECASE):
            hits.append((time_str, provider, flat_text[:400]))
    return hits


def run_live_test(
    *,
    plugin_dll: str = "",
    plugins_dir: str = "",
    skyrim_dir: str = "",
    log_dir: str = "",
    timeout_seconds: int = 45,
    auto_close: bool = False,
    keep_deployed: bool = False,
    no_launch: bool = False,
    no_clear_logs: bool = False,
    process_finder: Optional[Callable[[], Optional[int]]] = None,
) -> int:
    """Execute deployment, live launch, log monitoring, crash collection, and cleanup."""
    resolved_skyrim = resolve_skyrim_dir(skyrim_dir)
    resolved_plugins = Path(plugins_dir) if plugins_dir else (resolved_skyrim / "Data" / "SKSE" / "Plugins" if resolved_skyrim else None)
    if log_dir:
        resolved_log_dir = Path(log_dir)
    else:
        resolved_log_dir = Path.home() / "Documents" / "My Games" / "Skyrim Special Edition" / "SKSE"

    detected_sky_ver: Optional[str] = None
    detected_skse: Optional[str] = None
    detected_bin: Optional[str] = None

    if resolved_skyrim and resolved_skyrim.exists():
        vt = skse_env.detect_installed_skyrim_version(resolved_skyrim)
        if vt:
            detected_sky_ver = ".".join(str(x) for x in vt)
        skse_info = skse_env.detect_installed_skse(resolved_skyrim)
        if skse_info.get("dll_name"):
            skse_ver = skse_info.get("skse_version")
            detected_skse = f"{skse_info['dll_name']} (SKSE v{skse_ver})" if skse_ver else skse_info["dll_name"]
        if resolved_plugins and resolved_plugins.exists():
            if detected_sky_ver:
                cand_bin = resolved_plugins / f"versionlib-{detected_sky_ver.replace('.', '-')}.bin"
                if cand_bin.exists():
                    detected_bin = cand_bin.name
            if not detected_bin:
                bins = sorted(resolved_plugins.glob("version*.bin"), key=lambda p: p.stat().st_mtime, reverse=True)
                if bins:
                    detected_bin = bins[0].name

    print("=" * 76)
    print(" SKSE64 Live Test & Debug Runner")
    print("=" * 76)
    print(f"  SkyrimDir   : {resolved_skyrim if resolved_skyrim else '<not found>'}")
    print(f"  SkyrimVer   : {detected_sky_ver if detected_sky_ver else '<not detected>'}")
    print(f"  SKSE64      : {detected_skse if detected_skse else '<not detected>'}")
    print(f"  AddrLibBin  : {detected_bin if detected_bin else '<not detected>'}")
    print(f"  PluginsDir  : {resolved_plugins if resolved_plugins else '<not found>'}")
    print(f"  LogDir      : {resolved_log_dir}")
    print(f"  Mode        : {'NO-LAUNCH (Diagnostic Inspect)' if no_launch else 'LIVE LAUNCH'}")
    print("=" * 76)

    deployed_dest: Optional[Path] = None
    backup_path: Optional[Path] = None
    deployed_new_file = False
    plugin_stem: Optional[str] = None
    exit_code = 0

    try:
        if plugin_dll:
            src_candidate = Path(plugin_dll)
            if not src_candidate.exists():
                print(f"ERROR: Plugin DLL not found: {plugin_dll}", file=sys.stderr)
                return 4
            if not resolved_plugins or not resolved_plugins.exists():
                print(f"ERROR: Target Plugins directory not found: {resolved_plugins}", file=sys.stderr)
                return 4

            src_dll = src_candidate.resolve()
            dll_name = src_dll.name
            plugin_stem = src_dll.stem
            deployed_dest = (resolved_plugins / dll_name).resolve()
            backup_path = resolved_plugins / f"{dll_name}.livetest.bak"

            if src_dll != deployed_dest:
                if deployed_dest.exists():
                    shutil.copy2(deployed_dest, backup_path)
                    print(f"[*] Backed up existing {dll_name} -> {backup_path.name}")
                else:
                    deployed_new_file = True
                shutil.copy2(src_dll, deployed_dest)
                print(f"[+] Deployed {dll_name} -> {resolved_plugins}")
            else:
                print(f"[*] PluginDll is already in {resolved_plugins}")

        skse_log_path = resolved_log_dir / "skse64.log"
        plugin_log_path = (resolved_log_dir / f"{plugin_stem}.log") if plugin_stem else None
        launch_epoch = time.time() - 3600.0 if no_launch else time.time()

        if not no_launch:
            if not resolved_skyrim or not resolved_skyrim.exists():
                print("ERROR: Could not locate Skyrim Special Edition directory. Pass --skyrim-dir.", file=sys.stderr)
                return 4
            loader_exe = resolved_skyrim / "skse64_loader.exe"
            if not loader_exe.exists():
                print(f"ERROR: skse64_loader.exe not found at: {loader_exe}", file=sys.stderr)
                return 4

            if not no_clear_logs and resolved_log_dir.exists():
                for lp in (skse_log_path, plugin_log_path):
                    if lp and lp.exists():
                        try:
                            lp.unlink()
                        except OSError:
                            pass
                print("[*] Cleared previous SKSE/plugin logs before launch.")

            print(f"[*] Launching skse64_loader.exe (timeout={timeout_seconds}s, AutoClose={auto_close})...")
            launch_epoch = time.time()
            loader_proc = subprocess.Popen([str(loader_exe)], cwd=str(resolved_skyrim))

            find_sky = process_finder or (lambda: find_process_pid("SkyrimSE.exe"))
            sky_pid: Optional[int] = None
            wait_deadline = time.monotonic() + min(20, max(1, timeout_seconds))
            while time.monotonic() < wait_deadline:
                sky_pid = find_sky()
                if sky_pid is not None:
                    break
                rc = loader_proc.poll()
                if rc is not None and rc != 0:
                    print(f"[!!] skse64_loader.exe exited early with code {rc}")
                    exit_code = 4
                    break
                time.sleep(0.3)

            skse_offset = 0
            plug_offset = 0
            rejected_plugin = False
            plugin_loaded = False
            init_complete = False
            crashed_early = False
            hang_detected = False
            init_monotonic: Optional[float] = None
            stem_re = re.compile(re.escape(plugin_stem), re.IGNORECASE) if plugin_stem else None

            if sky_pid is not None:
                print(f"[*] SkyrimSE.exe started (PID={sky_pid}). Streaming logs...")
                poll_deadline = time.monotonic() + timeout_seconds
                while time.monotonic() < poll_deadline:
                    new_lines, skse_offset = read_new_log_lines(skse_log_path, skse_offset)
                    for line in new_lines:
                        print(f"  [skse64] {line}")
                        if _RE_REJECT.search(line):
                            if stem_re is None or stem_re.search(line):
                                rejected_plugin = True
                        if stem_re is not None and stem_re.search(line) and _RE_LOADED.search(line):
                            plugin_loaded = True
                        if _RE_INIT.search(line) and not init_complete:
                            init_complete = True
                            init_monotonic = time.monotonic()

                    if plugin_log_path is not None:
                        p_lines, plug_offset = read_new_log_lines(plugin_log_path, plug_offset)
                        for line in p_lines:
                            print(f"  [{plugin_stem}] {line}")

                    exited, sky_rc = get_process_exit_code(sky_pid)
                    if exited:
                        print(f"[!!] SkyrimSE.exe exited prematurely (ExitCode={sky_rc})")
                        crashed_early = True
                        break

                    if is_process_window_unresponsive(sky_pid):
                        hang_detected = True

                    if init_complete and auto_close and init_monotonic is not None and (time.monotonic() - init_monotonic) >= 3.0:
                        print("[OK] SKSE init complete + 3s settle window elapsed; closing SkyrimSE.exe (--auto-close).")
                        terminate_process(sky_pid)
                        break

                    time.sleep(0.5)

                # Drain final log lines
                final_lines, skse_offset = read_new_log_lines(skse_log_path, skse_offset)
                for line in final_lines:
                    print(f"  [skse64] {line}")
                    if _RE_REJECT_DRAIN.search(line):
                        if stem_re is None or stem_re.search(line):
                            rejected_plugin = True
                    if stem_re is not None and stem_re.search(line) and _RE_LOADED.search(line):
                        plugin_loaded = True
                    if _RE_INIT.search(line):
                        init_complete = True

                if plugin_log_path is not None:
                    p_lines, plug_offset = read_new_log_lines(plugin_log_path, plug_offset)
                    for line in p_lines:
                        print(f"  [{plugin_stem}] {line}")

                exited, _ = get_process_exit_code(sky_pid)
                if not exited and auto_close:
                    terminate_process(sky_pid)
            elif exit_code == 0:
                print("[!!] Timed out waiting for SkyrimSE.exe to launch.")
                exit_code = 3

            if plugin_loaded and not rejected_plugin:
                print(f"[OK] Confirmed {plugin_stem} loaded cleanly in skse64.log.")

            if rejected_plugin:
                exit_code = 1
            elif crashed_early:
                exit_code = 2
            elif not init_complete and exit_code == 0:
                if hang_detected:
                    print("[!!] SkyrimSE.exe stopped responding before SKSE init complete.")
                else:
                    print("[!!] Timeout reached before SKSE init complete.")
                exit_code = 3

        # Crash Logger + Trainwreck scan
        print("\n--- Crash & Diagnostic Summary ---")
        if resolved_log_dir.exists():
            recent_crashes = find_recent_crash_logs(resolved_log_dir, since_epoch=launch_epoch, include_all=no_launch)
            if recent_crashes:
                latest_crash = recent_crashes[0]
                print(f"[!!] Crash Log Found: {latest_crash}")
                try:
                    preview = latest_crash.read_text(encoding="utf-8", errors="replace").splitlines()[:35]
                    for line in preview:
                        print(f"  {line}")
                except OSError:
                    pass
                if not no_launch and exit_code == 0:
                    exit_code = 2
            else:
                print("[OK] No new Crash Logger / Trainwreck crash dumps.")
        else:
            print(f"[INFO] SKSE LogDir does not exist yet: {resolved_log_dir}")

        sky_events = query_windows_skyrim_crash_events(launch_epoch)
        if sky_events:
            print("\n[!] Windows Application Error Events:")
            for time_str, provider, msg in sky_events:
                print(f"  [{time_str}] {provider}: {msg}")

        if resolved_log_dir.exists():
            print("")
            triage_crash.analyze_skse_log(resolved_log_dir / "skse64.log")
            triage_crash.analyze_crash_log(resolved_log_dir)
    finally:
        if deployed_dest is not None and not keep_deployed:
            if backup_path is not None and backup_path.exists():
                os.replace(backup_path, deployed_dest)
                print(f"\n[*] Restored original {deployed_dest.name} from backup.")
            elif deployed_new_file and deployed_dest.exists():
                try:
                    deployed_dest.unlink()
                    print(f"\n[*] Removed temporary test DLL {deployed_dest}.")
                except OSError:
                    pass

    return exit_code


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Deploy, launch, monitor, and crash-triage an SKSE64 plugin via pure Python."
    )
    parser.add_argument("--plugin-dll", default="", help="Path to built/patched SKSE plugin .dll to test")
    parser.add_argument("--plugins-dir", default="", help="Override Skyrim Data\\SKSE\\Plugins directory")
    parser.add_argument("--skyrim-dir", default="", help="Override Skyrim Special Edition install directory")
    parser.add_argument("--log-dir", default="", help="Override Documents\\My Games\\Skyrim Special Edition\\SKSE directory")
    parser.add_argument("--timeout", type=int, default=45, help="Launch + init timeout in seconds (default: 45)")
    parser.add_argument("--auto-close", action="store_true", help="Terminate SkyrimSE.exe 3s after SKSE init complete")
    parser.add_argument("--keep-deployed", action="store_true", help="Do not restore/remove deployed PluginDll on exit")
    parser.add_argument("--no-launch", action="store_true", help="Inspect environment/logs/crash dumps without launching game")
    parser.add_argument("--no-clear-logs", action="store_true", help="Keep previous skse64.log/<Plugin>.log before launching")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    return run_live_test(
        plugin_dll=args.plugin_dll,
        plugins_dir=args.plugins_dir,
        skyrim_dir=args.skyrim_dir,
        log_dir=args.log_dir,
        timeout_seconds=args.timeout,
        auto_close=args.auto_close,
        keep_deployed=args.keep_deployed,
        no_launch=args.no_launch,
        no_clear_logs=args.no_clear_logs,
    )


if __name__ == "__main__":
    sys.exit(main())
