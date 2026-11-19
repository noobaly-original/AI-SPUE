#!/usr/bin/env python3
"""SKSE Plugin Update Environment Activator & Runner (`scripts/env.py`).

Pure-Python environment activator and command wrapper (no shell wrapper script required).

Usage:
  python scripts/env.py                         # Inspect & print activated toolchain/SDK status
  python scripts/env.py --json                  # Emit JSON status & exported environment variables
  python scripts/env.py -- cmake --version      # Run any command inside the activated environment
  python scripts/env.py --export-ps             # Optional: emit $env:VAR statements for Invoke-Expression
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402


def _find_env_key(env: Dict[str, str], target_key: str) -> str:
    """Return existing casing for `target_key` on case-insensitive Windows envs, or `target_key`."""
    low = target_key.lower()
    for k in env:
        if k.lower() == low:
            return k
    return target_key


def _set_env(env: Dict[str, str], key: str, value: str) -> None:
    actual = _find_env_key(env, key)
    env[actual] = value


def _get_env(env: Dict[str, str], key: str, default: str = "") -> str:
    actual = _find_env_key(env, key)
    return env.get(actual, default)


def _prepend_env_path(env: Dict[str, str], key: str, entries: Sequence[str], *, sep: str = os.pathsep) -> None:
    existing_raw = _get_env(env, key, "")
    existing_parts = [p for p in existing_raw.split(sep) if p]
    existing_norm = {os.path.normcase(os.path.normpath(p)) for p in existing_parts}

    prefix: List[str] = []
    for entry in entries:
        norm = os.path.normcase(os.path.normpath(entry))
        if norm not in existing_norm:
            prefix.append(entry)
            existing_norm.add(norm)
    if prefix or existing_parts:
        _set_env(env, key, sep.join(prefix + existing_parts))


def capture_vcvars64_env(base_env: Dict[str, str]) -> Tuple[Dict[str, str], Optional[Path]]:
    """Capture MSVC x64 developer environment from `vcvars64.bat` if `cl.exe` is not on PATH."""
    updated = dict(base_env)
    existing_path = _get_env(updated, "PATH", "")
    existing_cl = shutil.which("cl.exe", path=existing_path)
    if existing_cl:
        return updated, Path(existing_cl)

    vcvars = skse_env.find_vcvars64()
    if vcvars is None or not vcvars.exists():
        return updated, None

    res = subprocess.run(
        f'call "{vcvars}" >nul 2>&1 && set',
        shell=True,
        env=updated,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k:
                _set_env(updated, k, v)

    cl_found = shutil.which("cl.exe", path=_get_env(updated, "PATH", ""))
    return updated, Path(cl_found) if cl_found else vcvars


def _is_venv_home_valid(venv_root: Path) -> bool:
    cfg = venv_root / "pyvenv.cfg"
    if not cfg.exists():
        return False
    try:
        for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^\s*home\s*=\s*(.+)$", line)
            if m:
                home_dir = Path(m.group(1).strip())
                return (home_dir / "python.exe").exists()
    except OSError:
        return False
    return False


def build_activated_env(
    base_env: Optional[Dict[str, str]] = None,
    *,
    include_vcvars: bool = True,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Build activated build/runtime environment dict for MSVC, portable tools, and SDKs."""
    env = dict(os.environ if base_env is None else base_env)

    # 1. Visual Studio / MSVC x64
    if include_vcvars:
        env, _ = capture_vcvars64_env(env)

    # 2. Local portable tools & valid .venv
    repo_root = skse_env.REPO_ROOT
    tools_dir = skse_env.TOOLS_DIR
    sdk_dir = skse_env.SDK_DIR

    cmake_bin = tools_dir / "cmake" / "bin"
    ninja_bin = tools_dir / "ninja"
    vcpkg_root = tools_dir / "vcpkg"
    xmake_bin = tools_dir / "xmake"
    sevenzip_bin = tools_dir / "7zip"
    venv_root = repo_root / ".venv"
    venv_bin = venv_root / "Scripts"
    venv_site = venv_root / "Lib" / "site-packages"

    venv_home_valid = _is_venv_home_valid(venv_root)
    if venv_site.exists():
        _prepend_env_path(env, "PYTHONPATH", [str(venv_site)])

    tool_bins: List[Path] = []
    if venv_home_valid and venv_bin.exists():
        tool_bins.append(venv_bin)
        _set_env(env, "VIRTUAL_ENV", str(venv_root))
    tool_bins.extend([xmake_bin, vcpkg_root, ninja_bin, cmake_bin])
    if sevenzip_bin.exists():
        tool_bins.append(sevenzip_bin)

    prepend_dirs = [str(p) for p in tool_bins if p.exists()]
    _prepend_env_path(env, "PATH", prepend_dirs)

    # 3. Export CMake / vcpkg / CommonLibSSE-NG variables
    vcpkg_archives = vcpkg_root / "archives"
    if vcpkg_root.exists():
        try:
            vcpkg_archives.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    exported: Dict[str, str] = {
        "VCPKG_ROOT": str(vcpkg_root),
        "VCPKG_DEFAULT_TRIPLET": "x64-windows-static-md",
        "VCPKG_DEFAULT_BINARY_CACHE": str(vcpkg_archives),
        "SKSE_UPDATER_ROOT": str(repo_root),
        "SKSE_SDK_ROOT": str(sdk_dir),
        "COMMONLIB_SSE_NG_DIR": str(sdk_dir / "CommonLibSSE-NG"),
        "COMMONLIB_PREBUILT": "1",
    }

    prebuilt_cmake = sdk_dir / "CommonLibSSE-NG-Installed"
    if (prebuilt_cmake / "lib" / "CommonLibSSE.lib").exists():
        exported["COMMONLIB_PREBUILT_DIR"] = str(prebuilt_cmake).replace("\\", "/")

    # 4. Skyrim SE installation & active runtime detection
    skyrim_dir = skse_env.find_skyrim_install_dir()
    detected_exe_ver: Optional[str] = None
    detected_skse_info: Optional[str] = None
    detected_bin_name: Optional[str] = None

    if skyrim_dir.exists():
        exported["Skyrim64Path"] = str(skyrim_dir).rstrip("\\")
        ver_tuple = skse_env.detect_installed_skyrim_version(skyrim_dir)
        if ver_tuple is not None:
            detected_exe_ver = ".".join(str(x) for x in ver_tuple)
            exported["SKSE_DETECTED_RUNTIME"] = detected_exe_ver

        skse_info = skse_env.detect_installed_skse(skyrim_dir)
        if skse_info.get("dll_name"):
            skse_ver = skse_info.get("skse_version")
            detected_skse_info = f"{skse_info['dll_name']} (SKSE v{skse_ver})" if skse_ver else skse_info["dll_name"]

        plug_dir = skyrim_dir / "Data" / "SKSE" / "Plugins"
        if plug_dir.exists():
            if detected_exe_ver:
                exact_bin = plug_dir / f"versionlib-{detected_exe_ver.replace('.', '-')}.bin"
                if exact_bin.exists():
                    detected_bin_name = exact_bin.name
            if not detected_bin_name:
                bins = sorted(plug_dir.glob("version*.bin"), key=lambda p: p.stat().st_mtime, reverse=True)
                if bins:
                    detected_bin_name = bins[0].name

    for k, v in exported.items():
        _set_env(env, k, v)

    active_path = _get_env(env, "PATH", "")
    tool_status: Dict[str, Optional[str]] = {}
    for tool in ("cl", "cmake", "ninja", "vcpkg", "xmake", "git", "python"):
        tool_status[tool] = shutil.which(tool, path=active_path)

    summary: Dict[str, Any] = {
        "repo_root": str(repo_root),
        "tools": tool_status,
        "exported": exported,
        "venv_home_valid": venv_home_valid,
        "detected_skyrim_version": detected_exe_ver,
        "detected_skse": detected_skse_info,
        "detected_addrlib_bin": detected_bin_name,
    }
    return env, summary


def _print_banner(summary: Dict[str, Any]) -> None:
    print("=" * 60)
    print(" SKSE Plugin Update Environment Activated")
    print("=" * 60)
    for tool, path in summary["tools"].items():
        if path:
            print(f"  [OK] {tool:<8} : {path}")
        else:
            print(f"  [!!] {tool:<8} : NOT FOUND")
    exp = summary["exported"]
    print(f"  VCPKG_ROOT            : {exp.get('VCPKG_ROOT', '')}")
    print(f"  VCPKG_BINARY_CACHE    : {exp.get('VCPKG_DEFAULT_BINARY_CACHE', '')}")
    print(f"  COMMONLIB_SSE_NG_DIR  : {exp.get('COMMONLIB_SSE_NG_DIR', '')}")
    print(f"  COMMONLIB_PREBUILT_DIR: {exp.get('COMMONLIB_PREBUILT_DIR', '(not built)')}")
    if exp.get("Skyrim64Path"):
        print(f"  Skyrim64Path          : {exp['Skyrim64Path']}")
    if summary.get("detected_skyrim_version"):
        print(f"  Detected SkyrimSE.exe : {summary['detected_skyrim_version']}")
    if summary.get("detected_skse"):
        print(f"  Detected SKSE64       : {summary['detected_skse']}")
    if summary.get("detected_addrlib_bin"):
        print(f"  Detected AddrLib .bin : {summary['detected_addrlib_bin']}")
    print("=" * 60)


def _format_ps_exports(env: Dict[str, str], summary: Dict[str, Any]) -> str:
    """Render PowerShell `$env:...` statements for optional `Invoke-Expression` eval."""
    keys = [
        "PATH",
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "INCLUDE",
        "LIB",
        "LIBPATH",
        "VSCMD_ARG_TGT_ARCH",
        "VCINSTALLDIR",
        "VCToolsInstallDir",
        "WindowsSdkDir",
        *summary["exported"].keys(),
    ]
    seen = set()
    lines: List[str] = []
    for key in keys:
        low = key.lower()
        if low in seen:
            continue
        seen.add(low)
        val = _get_env(env, key, "")
        if not val:
            continue
        escaped = val.replace("'", "''")
        lines.append(f"$env:{key} = '{escaped}'")
    return "\n".join(lines)


def _resolve_command(cmd: Sequence[str], env_path: str) -> List[str]:
    exe = cmd[0]
    found = shutil.which(exe, path=env_path)
    if found:
        return [found, *cmd[1:]]
    return list(cmd)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Activate AI-SPUE portable toolchain/MSVC/SDK environment and optionally run a command."
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress status banner")
    parser.add_argument("--no-vcvars", action="store_true", help="Skip invoking vcvars64.bat (faster inspection)")
    parser.add_argument("--json", action="store_true", help="Print JSON summary instead of human banner")
    parser.add_argument(
        "--export-ps",
        action="store_true",
        help="Print PowerShell $env: assignments for optional `Invoke-Expression` session persistence",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Optional command to execute inside the activated environment (after `--`)",
    )
    args = parser.parse_args(argv)

    env, summary = build_activated_env(include_vcvars=not args.no_vcvars)

    cmd = list(args.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if cmd:
        resolved = _resolve_command(cmd, _get_env(env, "PATH", ""))
        res = subprocess.run(resolved, env=env, check=False)
        return int(res.returncode)

    if args.export_ps:
        print(_format_ps_exports(env, summary))
        return 0

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    if not args.quiet:
        _print_banner(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
