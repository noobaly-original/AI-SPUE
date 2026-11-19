#!/usr/bin/env python3
"""
SKSE64 & Crash Log Triage Helper (scripts/triage_crash.py)

Reads `skse64.log` and the latest CrashLogger (`crash-*.log`) in
`Documents\\My Games\\Skyrim Special Edition\\SKSE` and pinpoints:
  - Plugins rejected by SKSE (`reported as incompatible during query/load`)
  - Plugins that failed mid-load (last `loading plugin "<Name>"` before exit)
  - Common runtime errors (`Failed to handle allocation request`, Address Library errors)
  - Crashing module + top DLLs in the CrashLogger callstack

Usage:
  python scripts/triage_crash.py [path_to_SKSE_log_dir]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List, Optional

DEFAULT_LOG_DIR = Path(os.environ.get("USERPROFILE", "")) / "Documents" / "My Games" / "Skyrim Special Edition" / "SKSE"


def analyze_skse_log(log_path: Path) -> None:
    print(f"=== SKSE Log Analysis: {log_path} ===")
    if not log_path.exists():
        print("  [INFO] skse64.log not found.")
        return

    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    incompatible: List[str] = []
    last_loading: Optional[str] = None
    last_loaded: Optional[str] = None
    finished = False

    for line in lines:
        if "init complete" in line.lower() or "dispatch message" in line.lower():
            finished = True
        m_load = re.match(r'^loading plugin "([^"]+)"', line.strip())
        if m_load:
            last_loading = m_load.group(1)
            continue
        if "reported as incompatible" in line:
            incompatible.append(line.strip())
        elif "registered plugin listener" in line or "allocated" in line:
            last_loaded = last_loading

    if incompatible:
        print("  [FAIL] Plugins rejected by SKSE:")
        for item in incompatible:
            print(f"    - {item}")
    else:
        print("  [OK] No plugins rejected during SKSEPlugin_Query/Load.")

    if not finished and last_loading and last_loading != last_loaded:
        print(f"  [WARN] Startup appears to have aborted while loading: `{last_loading}`")
        print("         Check if it threw a missing Address Library / AllocTrampoline popup.")


def analyze_crash_log(log_dir: Path) -> None:
    crashes = list(log_dir.glob("crash-*.log"))
    tw_dir = log_dir / "Trainwreck"
    if tw_dir.exists():
        crashes.extend(tw_dir.glob("crash-*.log"))
    crashes.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    if not crashes:
        print("\n=== Crash Log Analysis: None found ===")
        return

    latest = crashes[0]
    print(f"\n=== Latest Crash Log: {latest.name} ===")
    text = latest.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    for line in lines[:25]:
        if any(k in line for k in ("Unhandled exception", "EXCEPTION_", "SkyrimSE", " probable call stack")):
            print(f"  {line.strip()}")

    system_dlls = {
        "skyrimse.exe",
        "kernel32.dll",
        "kernelbase.dll",
        "ntdll.dll",
        "ucrtbase.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "msvcp140.dll",
    }
    stack_frames: List[tuple[str, str]] = []
    seen = set()
    in_stack = False
    for line in lines:
        if "PROBABLE CALL STACK:" in line:
            in_stack = True
            continue
        if in_stack and not line.strip():
            in_stack = False
            continue
        if in_stack or "Unhandled exception" in line:
            for m in re.finditer(r"([A-Za-z0-9_.\-]+\.dll)\+(0x[0-9A-Fa-f]+)", line):
                dll, rva_hex = m.group(1), m.group(2)
                if dll.lower() not in system_dlls:
                    key = (dll, rva_hex.lower())
                    if key not in seen:
                        seen.add(key)
                        stack_frames.append((dll, rva_hex))

    if stack_frames:
        print("  [SUSPECT DLLs + RVAs IN CALL STACK]:")
        for dll, rva_hex in stack_frames[:8]:
            print(f"    - {dll}+{rva_hex}  ==>  python scripts/pe_inspect.py disasm \"<path_to>/{dll}\" --rva {rva_hex}")
    else:
        print("  [INFO] No third-party SKSE DLLs directly named in PROBABLE CALL STACK.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze skse64.log and latest CrashLogger log.")
    parser.add_argument("log_dir", nargs="?", type=Path, default=DEFAULT_LOG_DIR, help="SKSE log directory")
    args = parser.parse_args()

    log_dir = args.log_dir.resolve()
    if not log_dir.exists():
        print(f"[ERROR] Log directory not found: {log_dir}", file=sys.stderr)
        return 1

    analyze_skse_log(log_dir / "skse64.log")
    analyze_crash_log(log_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
