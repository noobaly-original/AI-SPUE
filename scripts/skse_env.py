#!/usr/bin/env python3
"""
Shared Environment, Dynamic Runtime, C++ Lexing & Cached ID Map Helpers (scripts/skse_env.py)

Centralizes:
  - Repository / SDK / tools paths
  - Detect-First Skyrim runtime resolution (`SkyrimSE.exe` PE Version > Skyrim `Data/SKSE/Plugins/*.bin` > `sdk/address_tables/bin/*.bin` > `skse64_*.dll`)
  - Registry/env discovery for Skyrim SE installation & `vswhere.exe` MSVC `vcvars64.bat`
  - Comment/string-aware C++ scanning & span splitting
  - Disk- and memory-cached SE <-> AE <-> Symbol <-> Split-AE mapping loader

Usage (Detect-First check):
  python scripts/skse_env.py [--json]
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows fallback
    winreg = None  # type: ignore[assignment]

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
SDK_DIR = REPO_ROOT / "sdk"
TOOLS_DIR = REPO_ROOT / "tools"
DIST_DIR = REPO_ROOT / "dist"
WORKSPACE_DIR = REPO_ROOT / "workspace"
BIN_DIR = SDK_DIR / "address_tables" / "bin"
SE_AE_CSV = SDK_DIR / "address_tables" / "se_ae_offsets.csv"
SE_AE_CSV_TEMPLATE = REPO_ROOT / "templates" / "sdk" / "address_tables" / "se_ae_offsets.csv"
AE_RENAME_FILE = SDK_DIR / "address_tables" / "skyrimae.rename"
RELIB_FILE = SDK_DIR / "address_tables" / "skyrimae.relib"
CLIB_INC = SDK_DIR / "CommonLibSSE-NG" / "include" / "RE"
CLIB_SRC = SDK_DIR / "CommonLibSSE-NG" / "src" / "RE"
CLIB_VER_H = SDK_DIR / "CommonLibSSE-NG" / "include" / "SKSE" / "Version.h"
SKSE_VER_H = SDK_DIR / "skse64" / "skse64_common" / "skse_version.h"
ADDR_LIB_HEADER = SDK_DIR / "AddressLibrary" / "versionlibdb.h"
ID_MAP_CACHE_FILE = SDK_DIR / "address_tables" / ".id_map_cache.json"

_BIN_NAME_RE = re.compile(r"^(?:versionlib|version)-(\d+)-(\d+)-(\d+)-(\d+)\.bin$", re.IGNORECASE)
_SKSE_DLL_RE = re.compile(r"^skse64_(\d+)_(\d+)_(\d+)\.dll$", re.IGNORECASE)

_CPP_TOKEN_RE = re.compile(
    r"""
    (?P<line_comment>//(?:\\\r?\n|[^\r\n])*)
    | (?P<block_comment>/\*[\s\S]*?\*/)
    | (?P<raw_string>(?:u8|u|U|L)?R"(?P<raw_delim>[^\s()\\]{0,16})\([\s\S]*?\)(?P=raw_delim)")
    | (?P<string>(?:u8|u|U|L)?"(?:\\.|\\\r?\n|[^"\\\r\n])*")
    | (?P<char>(?:u8|u|U|L)?'(?:\\.|[^'\\\r\n])*')
    """,
    re.VERBOSE,
)

_ID_MAPS_MEM_CACHE: Optional[Tuple[Dict[int, int], Dict[int, int], Dict[int, str], Dict[int, int]]] = None
_AE_RENAME_MEM_CACHE: Optional[Tuple[Path, int, int, Dict[int, str]]] = None
_ID_MAP_CACHE_SCHEMA = 2


def parse_version_tuple(ver_str: str) -> Tuple[int, int, int, int]:
    """Parse dotted or dashed version strings (e.g. '1.6.1170', '1-6-1170-0') into a 4-int tuple."""
    cleaned = ver_str.strip()
    if not cleaned:
        raise ValueError("Empty version string")
    raw_parts = re.split(r"[.\-]", cleaned)
    if len(raw_parts) > 4 or any(p == "" for p in raw_parts):
        raise ValueError(f"Invalid version string: {ver_str!r}")
    parts = [int(p) for p in raw_parts]
    while len(parts) < 4:
        parts.append(0)
    return (parts[0], parts[1], parts[2], parts[3])


def format_version_dash(ver: Tuple[int, int, int, int]) -> str:
    return f"{ver[0]}-{ver[1]}-{ver[2]}-{ver[3]}"


def format_version_dot(ver: Tuple[int, int, int, int], drop_zero_sub: bool = True) -> str:
    if drop_zero_sub and ver[3] == 0:
        return f"{ver[0]}.{ver[1]}.{ver[2]}"
    return f"{ver[0]}.{ver[1]}.{ver[2]}.{ver[3]}"


def pack_skse_version(ver: Tuple[int, int, int, int]) -> int:
    """Pack a 4-part version into SKSE's `MAKE_EXE_VERSION_EX` uint32."""
    return ((ver[0] & 0xFF) << 24) | ((ver[1] & 0xFF) << 16) | ((ver[2] & 0xFFF) << 4) | (ver[3] & 0xF)


def read_pe_file_version(file_path: Path) -> Optional[Tuple[int, int, int, int]]:
    """Read Windows PE VS_FIXEDFILEINFO FileVersion (fallback ProductVersion) as a 4-int tuple."""
    if os.name != "nt" or not file_path.exists():
        return None
    try:
        from ctypes import wintypes

        vdll = ctypes.WinDLL("version", use_last_error=True)
        vdll.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        vdll.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        vdll.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
        vdll.GetFileVersionInfoW.restype = wintypes.BOOL
        vdll.VerQueryValueW.argtypes = [
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.UINT),
        ]
        vdll.VerQueryValueW.restype = wintypes.BOOL

        path_s = str(file_path)
        sz = vdll.GetFileVersionInfoSizeW(path_s, None)
        if not sz:
            return None
        buf = ctypes.create_string_buffer(sz)
        if not vdll.GetFileVersionInfoW(path_s, 0, sz, buf):
            return None
        lptr = ctypes.c_void_p()
        llen = wintypes.UINT()
        if not vdll.VerQueryValueW(buf, "\\", ctypes.byref(lptr), ctypes.byref(llen)):
            return None
        if not lptr.value or llen.value < 52:
            return None
        raw = ctypes.string_at(lptr.value, 52)
        sig, _, fv_ms, fv_ls, pv_ms, pv_ls = struct.unpack_from("<6I", raw, 0)
        if sig != 0xFEEF04BD:
            return None
        fv = (fv_ms >> 16, fv_ms & 0xFFFF, fv_ls >> 16, fv_ls & 0xFFFF)
        if any(fv):
            return fv
        pv = (pv_ms >> 16, pv_ms & 0xFFFF, pv_ls >> 16, pv_ls & 0xFFFF)
        return pv if any(pv) else None
    except Exception:
        return None


def list_available_bin_versions(bin_dir: Path = BIN_DIR) -> List[Tuple[int, int, int, int]]:
    """Return sorted unique version tuples discovered in `bin_dir`."""
    if not bin_dir.exists():
        return []
    versions = set()
    for entry in bin_dir.iterdir():
        if not entry.is_file():
            continue
        m = _BIN_NAME_RE.match(entry.name)
        if m:
            versions.add((int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))))
    return sorted(versions)


def detect_installed_skyrim_version(skyrim_dir: Optional[Path] = None) -> Optional[Tuple[int, int, int, int]]:
    """Read PE FileVersion directly from the installed `SkyrimSE.exe`."""
    install_dir = skyrim_dir if skyrim_dir is not None else find_skyrim_install_dir()
    if install_dir is None:
        return None
    exe_path = install_dir / "SkyrimSE.exe"
    return read_pe_file_version(exe_path)


def detect_installed_addrlib_bins(
    skyrim_dir: Optional[Path] = None,
) -> List[Tuple[Tuple[int, int, int, int], Path]]:
    """Return sorted `(version_tuple, path)` pairs from `<skyrim_dir>/Data/SKSE/Plugins`."""
    install_dir = skyrim_dir if skyrim_dir is not None else find_skyrim_install_dir()
    if install_dir is None:
        return []
    plugins_dir = install_dir / "Data" / "SKSE" / "Plugins"
    if not plugins_dir.exists():
        return []
    found: List[Tuple[Tuple[int, int, int, int], Path]] = []
    for entry in plugins_dir.iterdir():
        if not entry.is_file():
            continue
        m = _BIN_NAME_RE.match(entry.name)
        if m:
            ver = (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)))
            found.append((ver, entry))
    found.sort(key=lambda item: item[0])
    return found


def detect_installed_skse(skyrim_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Discover installed `skse64_<maj>_<min>_<build>.dll`, `skse64_loader.exe`, and SKSE version."""
    install_dir = skyrim_dir if skyrim_dir is not None else find_skyrim_install_dir()
    info: Dict[str, Any] = {
        "dll_path": None,
        "dll_name": None,
        "loader_path": None,
        "skse_version": None,
        "game_version_tuple": None,
        "game_version_dot": None,
    }
    if install_dir is None or not install_dir.exists():
        return info

    loader = install_dir / "skse64_loader.exe"
    if loader.exists():
        info["loader_path"] = str(loader)

    candidates: List[Tuple[Tuple[int, int, int, int], Path]] = []
    for entry in install_dir.iterdir():
        if not entry.is_file():
            continue
        m = _SKSE_DLL_RE.match(entry.name)
        if m:
            gv = (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0)
            candidates.append((gv, entry))
    if not candidates:
        return info

    skyrim_ver = detect_installed_skyrim_version(install_dir)
    selected: Optional[Tuple[Tuple[int, int, int, int], Path]] = None
    if skyrim_ver is not None:
        for gv, p in candidates:
            if gv[:3] == skyrim_ver[:3]:
                selected = (gv, p)
                break
    if selected is None:
        candidates.sort(key=lambda item: item[0])
        selected = candidates[-1]

    gv, dll_path = selected
    info["dll_path"] = str(dll_path)
    info["dll_name"] = dll_path.name
    info["game_version_tuple"] = gv
    info["game_version_dot"] = format_version_dot(gv)
    fv = read_pe_file_version(dll_path)
    if fv is not None:
        if fv[0] == 0:
            info["skse_version"] = f"{fv[1]}.{fv[2]}.{fv[3]}"
        else:
            info["skse_version"] = format_version_dot(fv, drop_zero_sub=(fv[3] == 0))
    return info


def find_addrlib_bin(
    version: Tuple[int, int, int, int],
    bin_dir: Path = BIN_DIR,
    skyrim_dir: Optional[Path] = None,
) -> Optional[Path]:
    """Locate `versionlib-*.bin` or `version-*.bin` for `version` in `bin_dir` or Skyrim plugins."""
    dash = format_version_dash(version)
    dirs: List[Path] = []
    if bin_dir is not None:
        dirs.append(bin_dir)
    install_dir = skyrim_dir if skyrim_dir is not None else find_skyrim_install_dir()
    if install_dir is not None:
        plugins_dir = install_dir / "Data" / "SKSE" / "Plugins"
        if plugins_dir not in dirs:
            dirs.append(plugins_dir)
    for d in dirs:
        if not d.exists():
            continue
        for prefix in ("versionlib", "version"):
            cand = d / f"{prefix}-{dash}.bin"
            if cand.exists():
                return cand
    return None


def check_sdk_runtime_registered(ver: Tuple[int, int, int, int]) -> Dict[str, bool]:
    """Check whether `ver` (maj.min.build) is registered in local SKSE64 and CommonLibSSE-NG headers."""
    skse_macro = f"RUNTIME_VERSION_{ver[0]}_{ver[1]}_{ver[2]}"
    clib_const = f"RUNTIME_SSE_{ver[0]}_{ver[1]}_{ver[2]}"
    skse_ok = SKSE_VER_H.exists() and skse_macro in SKSE_VER_H.read_text(encoding="utf-8", errors="replace")
    clib_ok = CLIB_VER_H.exists() and clib_const in CLIB_VER_H.read_text(encoding="utf-8", errors="replace")
    return {"skse64": skse_ok, "commonlibsse_ng": clib_ok}


def detect_target_environment(
    bin_dir: Optional[Path] = None,
    skyrim_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Detect target Skyrim runtime, SKSE build, and Address Library `.bin` paths using Detect-First rules:
      1. `SKSE_TARGET_RUNTIME` environment variable (explicit override)
      2. Isolated custom `bin_dir` (when `bin_dir` is explicitly provided and != `BIN_DIR`, for tests/sandbox)
      3. `SkyrimSE.exe` PE FileVersion / ProductVersion in local Skyrim installation
      4. Newest mainline `versionlib-*.bin` / `version-*.bin` in Skyrim's `Data/SKSE/Plugins/`
      5. Newest mainline `versionlib-*.bin` / `version-*.bin` in `sdk/address_tables/bin/`
      6. Installed `skse64_<major>_<minor>_<build>.dll` filename in Skyrim folder
    """
    env_target = os.environ.get("SKSE_TARGET_RUNTIME", "").strip()
    custom_bin_mode = bin_dir is not None and bin_dir != BIN_DIR and skyrim_dir is None

    install_dir: Optional[Path] = None
    skyrim_exe_ver: Optional[Tuple[int, int, int, int]] = None
    plugins_bins: List[Tuple[Tuple[int, int, int, int], Path]] = []
    skse_info: Dict[str, Any] = {
        "dll_path": None,
        "dll_name": None,
        "loader_path": None,
        "skse_version": None,
        "game_version_tuple": None,
        "game_version_dot": None,
    }

    if not custom_bin_mode:
        install_dir = skyrim_dir if skyrim_dir is not None else find_skyrim_install_dir()
        if install_dir is not None and install_dir.exists():
            skyrim_exe_ver = detect_installed_skyrim_version(install_dir)
            plugins_bins = detect_installed_addrlib_bins(install_dir)
            skse_info = detect_installed_skse(install_dir)

    target_tuple: Optional[Tuple[int, int, int, int]] = None
    target_source = ""

    if env_target:
        target_tuple = parse_version_tuple(env_target)
        target_source = "env:SKSE_TARGET_RUNTIME"
    elif custom_bin_mode and bin_dir is not None:
        avail = list_available_bin_versions(bin_dir)
        if not avail:
            raise RuntimeError(
                f"Could not detect target Skyrim runtime version: no .bin files in {bin_dir} and SKSE_TARGET_RUNTIME is unset."
            )
        mainline = [v for v in avail if v[3] == 0]
        target_tuple = max(mainline) if mainline else max(avail)
        target_source = "bin_dir"
    else:
        if skyrim_exe_ver is not None:
            target_tuple = skyrim_exe_ver
            target_source = "SkyrimSE.exe"
        elif plugins_bins:
            p_vers = [v for v, _ in plugins_bins]
            mainline = [v for v in p_vers if v[3] == 0]
            target_tuple = max(mainline) if mainline else max(p_vers)
            target_source = "skyrim_plugins_bin"
        else:
            sdk_vers = list_available_bin_versions(BIN_DIR)
            if sdk_vers:
                mainline = [v for v in sdk_vers if v[3] == 0]
                target_tuple = max(mainline) if mainline else max(sdk_vers)
                target_source = "sdk_bin_dir"
            elif skse_info["game_version_tuple"] is not None:
                target_tuple = skse_info["game_version_tuple"]
                target_source = "skse64_dll"
            else:
                raise RuntimeError(
                    "Could not auto-detect target Skyrim runtime version. "
                    "Install Skyrim SE / Address Library .bin files or set SKSE_TARGET_RUNTIME."
                )

    eff_bin_dir = bin_dir if bin_dir is not None else BIN_DIR
    addrlib_bin = find_addrlib_bin(
        target_tuple,
        bin_dir=eff_bin_dir,
        skyrim_dir=None if custom_bin_mode else install_dir,
    )
    in_sdk = addrlib_bin is not None and addrlib_bin.parent == BIN_DIR
    sdk_reg = check_sdk_runtime_registered(target_tuple)
    needs_reg = (not sdk_reg["skse64"]) or (not sdk_reg["commonlibsse_ng"]) or (addrlib_bin is not None and not in_sdk)

    return {
        "target_version_tuple": target_tuple,
        "target_version_dot": format_version_dot(target_tuple),
        "target_version_full": format_version_dot(target_tuple, drop_zero_sub=False),
        "target_version_dash": format_version_dash(target_tuple),
        "target_version_packed_hex": f"0x{pack_skse_version(target_tuple):08X}",
        "target_source": target_source,
        "skyrim_dir": str(install_dir) if install_dir is not None else None,
        "skyrim_exe": str(install_dir / "SkyrimSE.exe") if install_dir and (install_dir / "SkyrimSE.exe").exists() else None,
        "skyrim_exe_version": format_version_dot(skyrim_exe_ver, drop_zero_sub=False) if skyrim_exe_ver else None,
        "skse": skse_info,
        "addrlib_bin_path": str(addrlib_bin) if addrlib_bin is not None else None,
        "addrlib_in_sdk": in_sdk,
        "sdk_registered": sdk_reg,
        "sdk_needs_registration": needs_reg,
    }


def get_latest_target_version(bin_dir: Optional[Path] = None) -> Tuple[int, int, int, int]:
    """Return auto-detected target runtime version tuple via `detect_target_environment`."""
    return detect_target_environment(bin_dir=bin_dir)["target_version_tuple"]


def get_default_target_dash(bin_dir: Optional[Path] = None) -> str:
    return format_version_dash(get_latest_target_version(bin_dir))


def get_default_target_dot(bin_dir: Optional[Path] = None) -> str:
    return format_version_dot(get_latest_target_version(bin_dir))


def get_lookup_versions(bin_dir: Optional[Path] = None) -> List[str]:
    """Return representative historical baseline versions plus detected target and >= 1.7.99 mainline .bin versions."""
    eff_bin_dir = bin_dir if bin_dir is not None else BIN_DIR
    versions = {
        (1, 5, 97, 0),
        (1, 6, 640, 0),
        (1, 6, 1170, 0),
        (1, 7, 99, 0),
    }
    for v in list_available_bin_versions(eff_bin_dir):
        if v >= (1, 7, 99, 0) and v[3] == 0:
            versions.add(v)
    try:
        versions.add(get_latest_target_version(bin_dir=bin_dir))
    except RuntimeError:
        pass
    return [format_version_dash(v) for v in sorted(versions)]


def get_verification_runtimes(
    target: Optional[str] = None,
    bin_dir: Optional[Path] = None,
) -> List[Tuple[str, Tuple[int, int, int, int]]]:
    """Return sorted [(dot_label, version_tuple), ...] for SKSE compatibility checks."""
    eff_bin_dir = bin_dir if bin_dir is not None else BIN_DIR
    versions = {
        (1, 6, 640, 0),
        (1, 6, 1170, 0),
        (1, 7, 99, 0),
    }
    for v in list_available_bin_versions(eff_bin_dir):
        if v >= (1, 7, 99, 0) and v[3] == 0:
            versions.add(v)
    try:
        versions.add(get_latest_target_version(bin_dir=bin_dir))
    except RuntimeError:
        pass
    if target:
        versions.add(parse_version_tuple(target))
    return [(format_version_dot(v), v) for v in sorted(versions)]


def find_skyrim_install_dir() -> Optional[Path]:
    """Discover the local Skyrim Special Edition directory via env, Windows registry, or common paths."""
    env_path = os.environ.get("Skyrim64Path", "").strip().strip('"')
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    if winreg is not None:
        reg_keys = [
            r"SOFTWARE\WOW6432Node\Bethesda Softworks\Skyrim Special Edition",
            r"SOFTWARE\Bethesda Softworks\Skyrim Special Edition",
        ]
        for subkey in reg_keys:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                    val, _ = winreg.QueryValueEx(key, "Installed Path")
                    if isinstance(val, str) and val.strip():
                        p = Path(val.strip().rstrip("\\/"))
                        if p.exists():
                            return p
            except OSError:
                continue

    common_paths = [
        Path(r"C:\Program Files (x86)\Steam\steamapps\common\Skyrim Special Edition"),
        Path(r"C:\Program Files\Steam\steamapps\common\Skyrim Special Edition"),
        Path(r"D:\Steam\steamapps\common\Skyrim Special Edition"),
        Path(r"D:\SteamLibrary\steamapps\common\Skyrim Special Edition"),
        Path(r"E:\SteamLibrary\steamapps\common\Skyrim Special Edition"),
        Path(r"C:\GOG Games\Skyrim Special Edition"),
        Path(r"D:\GOG Games\Skyrim Special Edition"),
    ]
    for p in common_paths:
        if p.exists():
            return p
    return None


def find_skyrim_plugins_dir() -> Path:
    install_dir = find_skyrim_install_dir()
    if install_dir is not None:
        return install_dir / "Data" / "SKSE" / "Plugins"
    return Path(r"C:\Program Files (x86)\Steam\steamapps\common\Skyrim Special Edition\Data\SKSE\Plugins")


def find_vcvars64() -> Optional[Path]:
    """Locate MSVC `vcvars64.bat` via `vswhere.exe` with multi-version fallbacks."""
    pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    vswhere = Path(pf86) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if vswhere.exists():
        try:
            out = subprocess.check_output(
                [
                    str(vswhere),
                    "-latest",
                    "-products",
                    "*",
                    "-requires",
                    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                    "-property",
                    "installationPath",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            for line in out.splitlines():
                install = line.strip()
                if install:
                    cand = Path(install) / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
                    if cand.exists():
                        return cand
        except Exception:
            pass

    roots = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
        Path(pf86),
    ]
    for root in roots:
        for year in ("2022", "2026", "18"):
            for edition in ("Community", "Professional", "Enterprise", "BuildTools"):
                cand = root / "Microsoft Visual Studio" / year / edition / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
                if cand.exists():
                    return cand
    return None


def iter_cpp_code_spans(text: str) -> List[Tuple[int, int, bool]]:
    """Split C++ source into contiguous `(start, end, is_code)` spans, skipping comments and literals."""
    raw_spans: List[Tuple[int, int, bool]] = []
    pos = 0
    for m in _CPP_TOKEN_RE.finditer(text):
        start, end = m.span()
        if start > pos:
            raw_spans.append((pos, start, True))
        raw_spans.append((start, end, False))
        pos = end
    if pos < len(text):
        raw_spans.append((pos, len(text), True))

    merged: List[Tuple[int, int, bool]] = []
    for start, end, is_code in raw_spans:
        if start == end:
            continue
        if merged and merged[-1][2] == is_code:
            prev_start, _, _ = merged[-1]
            merged[-1] = (prev_start, end, is_code)
        else:
            merged.append((start, end, is_code))
    return merged


def strip_cpp_comments_preserve_lines(text: str) -> str:
    """Remove `//` and `/* */` comments while preserving string/char literals and newline positions."""
    out: List[str] = []
    pos = 0
    for m in _CPP_TOKEN_RE.finditer(text):
        start, end = m.span()
        if start > pos:
            out.append(text[pos:start])
        tok = m.group(0)
        if m.group("line_comment") is not None:
            nl_count = tok.count("\n")
            out.append("\n" * nl_count)
        elif m.group("block_comment") is not None:
            out.append(re.sub(r"[^\r\n]", " ", tok))
        else:
            out.append(tok)
        pos = end
    if pos < len(text):
        out.append(text[pos:])
    return "".join(out)


def clear_id_maps_cache() -> None:
    global _ID_MAPS_MEM_CACHE, _AE_RENAME_MEM_CACHE
    _ID_MAPS_MEM_CACHE = None
    _AE_RENAME_MEM_CACHE = None


def load_ae_rename_map(rename_path: Path = AE_RENAME_FILE) -> Dict[int, str]:
    """Load `skyrimae.rename` (`{ae_id: symbol_name}`) if present on disk."""
    global _AE_RENAME_MEM_CACHE
    if not rename_path.exists():
        return {}
    try:
        st = rename_path.stat()
    except OSError:
        return {}
    if _AE_RENAME_MEM_CACHE is not None:
        cached_path, cached_mtime, cached_size, cached_map = _AE_RENAME_MEM_CACHE
        if cached_path == rename_path and cached_mtime == st.st_mtime_ns and cached_size == st.st_size:
            return cached_map

    names: Dict[int, str] = {}
    saw_header = False
    for raw_line in rename_path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(";") or stripped.startswith("#"):
            continue
        if not saw_header and " " not in stripped and stripped.isdigit():
            saw_header = True
            continue
        saw_header = True
        sep = stripped.find(" ")
        if sep <= 0:
            continue
        sym_name = stripped[sep + 1 :].strip()
        if not sym_name:
            continue
        try:
            vid = int(stripped[:sep])
        except ValueError:
            continue
        names[vid] = sym_name

    _AE_RENAME_MEM_CACHE = (rename_path, st.st_mtime_ns, st.st_size, names)
    return names


def _resolve_se_ae_csv() -> Path:
    """Return the active `se_ae_offsets.csv` in `sdk/`, falling back to `templates/sdk/`."""
    return SE_AE_CSV if SE_AE_CSV.exists() else SE_AE_CSV_TEMPLATE


def _compute_id_map_fingerprint(
    csv_path: Optional[Path] = None,
    clib_dirs: Tuple[Path, ...] = (CLIB_INC, CLIB_SRC),
    rename_path: Path = AE_RENAME_FILE,
) -> Dict[str, Any]:
    csv_path = csv_path if csv_path is not None else _resolve_se_ae_csv()
    csv_mtime_ns = 0
    csv_size = 0
    if csv_path.exists():
        st = csv_path.stat()
        csv_mtime_ns = st.st_mtime_ns
        csv_size = st.st_size

    rename_mtime_ns = 0
    rename_size = 0
    if rename_path.exists():
        st = rename_path.stat()
        rename_mtime_ns = st.st_mtime_ns
        rename_size = st.st_size

    clib_max_mtime_ns = 0
    clib_count = 0
    exts = {".h", ".hpp", ".cpp", ".inl"}
    for folder in clib_dirs:
        if not folder.exists():
            continue
        for root, _, files in os.walk(folder):
            for fname in files:
                if Path(fname).suffix.lower() not in exts:
                    continue
                fpath = Path(root) / fname
                try:
                    st = fpath.stat()
                except OSError:
                    continue
                clib_count += 1
                if st.st_mtime_ns > clib_max_mtime_ns:
                    clib_max_mtime_ns = st.st_mtime_ns

    return {
        "schema": _ID_MAP_CACHE_SCHEMA,
        "csv_path": str(csv_path),
        "csv_mtime_ns": csv_mtime_ns,
        "csv_size": csv_size,
        "rename_mtime_ns": rename_mtime_ns,
        "rename_size": rename_size,
        "clib_max_mtime_ns": clib_max_mtime_ns,
        "clib_count": clib_count,
    }


def load_id_maps(
    use_cache: bool = True,
) -> Tuple[Dict[int, int], Dict[int, int], Dict[int, str], Dict[int, int]]:
    """
    Load combined `(se_to_ae, ae_to_se, se_to_sym, ae_split_to_new)` maps.

    Combines `sdk/address_tables/se_ae_offsets.csv` (falling back to
    `templates/sdk/address_tables/se_ae_offsets.csv`) with `sdk/CommonLibSSE-NG`
    `RE/` headers/sources (where CommonLibSSE-NG overrides stale CSV entries and
    contributes `AE_CHECK` splits).
    """
    global _ID_MAPS_MEM_CACHE
    if use_cache and _ID_MAPS_MEM_CACHE is not None:
        return _ID_MAPS_MEM_CACHE

    csv_path = _resolve_se_ae_csv()
    fingerprint = _compute_id_map_fingerprint(csv_path=csv_path)
    if use_cache and ID_MAP_CACHE_FILE.exists():
        try:
            payload = json.loads(ID_MAP_CACHE_FILE.read_text(encoding="utf-8"))
            if payload.get("fingerprint") == fingerprint:
                result = (
                    {int(k): int(v) for k, v in payload["se_to_ae"].items()},
                    {int(k): int(v) for k, v in payload["ae_to_se"].items()},
                    {int(k): str(v) for k, v in payload["se_to_sym"].items()},
                    {int(k): int(v) for k, v in payload["ae_split_to_new"].items()},
                )
                _ID_MAPS_MEM_CACHE = result
                return result
        except Exception:
            pass

    se_to_ae: Dict[int, int] = {}
    ae_to_se: Dict[int, int] = {}
    se_to_sym: Dict[int, str] = {}
    ae_split_to_new: Dict[int, int] = {}

    if csv_path.exists():
        with csv_path.open("r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                sse_s = (row.get("sseid") or "").strip()
                ae_s = (row.get("aeid") or "").strip()
                sym = (row.get("comments") or "").strip()
                if sse_s:
                    try:
                        se_id = int(float(sse_s))
                        if sym:
                            se_to_sym[se_id] = sym
                        if ae_s:
                            ae_id = int(float(ae_s))
                            if se_id > 0 and ae_id > 0:
                                se_to_ae[se_id] = ae_id
                                ae_to_se[ae_id] = se_id
                    except ValueError:
                        pass

    re_reloc = re.compile(
        r"\b(?:RELOCATION_ID|REL::RelocationID|REL::VariantID)(?:\s+\w+)?\s*\(\s*(\d+)\s*,\s*(\d+)"
    )
    re_ae_check = re.compile(
        r"\b(?:RELOCATION_ID|REL::RelocationID)\s*\(\s*(\d+)\s*,\s*AE_CHECK\s*\([^,]+,\s*(\d+)\s*,\s*(\d+)\s*\)"
    )

    for folder in (CLIB_INC, CLIB_SRC):
        if not folder.exists():
            continue
        for root, _, files in os.walk(folder):
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() not in {".h", ".hpp", ".cpp", ".inl"}:
                    continue
                try:
                    txt = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                for m in re_reloc.finditer(txt):
                    se_id, ae_id = int(m.group(1)), int(m.group(2))
                    if se_id > 0 and ae_id > 0:
                        se_to_ae[se_id] = ae_id
                        ae_to_se[ae_id] = se_id
                for m in re_ae_check.finditer(txt):
                    se_id, old_ae, new_ae = int(m.group(1)), int(m.group(2)), int(m.group(3))
                    if se_id > 0 and new_ae > 0:
                        se_to_ae[se_id] = new_ae
                        ae_to_se[old_ae] = se_id
                        ae_to_se[new_ae] = se_id
                        ae_split_to_new[old_ae] = new_ae
                        split_note = f"[AE Split: old={old_ae}, 1.7.99+/1.6.1130+={new_ae}]"
                        existing = se_to_sym.get(se_id, "")
                        if existing:
                            if split_note not in existing:
                                se_to_sym[se_id] = f"{existing} {split_note}"
                        else:
                            se_to_sym[se_id] = split_note

    ae_rename = load_ae_rename_map()
    if ae_rename:
        for se_id, ae_id in se_to_ae.items():
            sym_name = ae_rename.get(ae_id)
            if not sym_name:
                continue
            existing = se_to_sym.get(se_id, "")
            if not existing:
                se_to_sym[se_id] = sym_name
            elif existing.startswith("[AE Split:") and sym_name not in existing:
                se_to_sym[se_id] = f"{sym_name} {existing}"

    result = (se_to_ae, ae_to_se, se_to_sym, ae_split_to_new)
    if use_cache:
        _ID_MAPS_MEM_CACHE = result
        if ID_MAP_CACHE_FILE.parent.exists():
            try:
                tmp_path = ID_MAP_CACHE_FILE.with_suffix(".json.tmp")
                payload = {
                    "fingerprint": fingerprint,
                    "se_to_ae": {str(k): v for k, v in se_to_ae.items()},
                    "ae_to_se": {str(k): v for k, v in ae_to_se.items()},
                    "se_to_sym": {str(k): v for k, v in se_to_sym.items()},
                    "ae_split_to_new": {str(k): v for k, v in ae_split_to_new.items()},
                }
                tmp_path.write_text(json.dumps(payload), encoding="utf-8")
                os.replace(tmp_path, ID_MAP_CACHE_FILE)
            except OSError:
                pass

    return result


_SEC_IGNORE_DIRS = {
    "build",
    ".git",
    ".vs",
    ".xmake",
    "vcpkg_installed",
    "extern",
    "external",
    "deps",
    "submodules",
    "commonlibsse",
    "commonlibsse-ng",
}

_BUILD_HOOK_RE = re.compile(
    r"(?:\b(?:execute_process|add_custom_command|add_custom_target|os\.execv?|os\.iorun|os\.run|os\.runv|io\.popen)\b|<Exec\b)",
    re.IGNORECASE,
)
_DANGEROUS_CMD_RE = re.compile(
    r"(?:\b(?:curl(?:\.exe)?|wget(?:\.exe)?|invoke-webrequest|invoke-restmethod|invoke-expression|frombase64string|bitsadmin(?:\.exe)?|certutil(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|iwr|irm|iex)\b|cmd(?:\.exe)?\s+/c\b|-encodedcommand\b|\s-enc\s+[A-Za-z0-9+/=]{8,})",
    re.IGNORECASE,
)
_DIRECT_PAYLOAD_RE = re.compile(
    r"(?:\b(?:invoke-webrequest|invoke-restmethod|invoke-expression|frombase64string)\b|-encodedcommand\b)",
    re.IGNORECASE,
)
_PROMPT_INJECTION_RE = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|system\s+override|new\s+system\s+prompt|important\s+instruction\s+for\s+ai|\bai\s+agent\s*:)",
    re.IGNORECASE,
)


def audit_mod_security(mod_dir: Path) -> Dict[str, Any]:
    """Scan a mod directory for malicious build hooks, prompt injections, and bundled executables."""
    mod_dir = Path(mod_dir).resolve()
    dangerous_build_hooks: List[Dict[str, Any]] = []
    prompt_injection_suspects: List[Dict[str, Any]] = []
    bundled_scripts_or_exes: List[str] = []

    build_exts = {".cmake", ".lua", ".vcxproj", ".targets", ".props"}
    text_exts = {
        ".cpp", ".cxx", ".cc", ".c", ".h", ".hpp", ".hxx", ".inl",
        ".md", ".txt", ".cmake", ".lua", ".json", ".ini", ".toml", ".yml", ".yaml",
    }
    exec_exts = {".bat", ".cmd", ".ps1", ".vbs", ".hta", ".exe"}

    for root, dirs, files in os.walk(mod_dir):
        dirs[:] = [
            d for d in sorted(dirs)
            if d.lower() not in _SEC_IGNORE_DIRS and not d.lower().startswith("commonlibsse")
        ]
        for fname in sorted(files):
            fp = Path(root) / fname
            rel = fp.relative_to(mod_dir).as_posix()
            low_name = fname.lower()
            suffix = fp.suffix.lower()

            if suffix in exec_exts:
                bundled_scripts_or_exes.append(rel)

            is_build_file = low_name == "cmakelists.txt" or suffix in build_exts
            is_text_file = is_build_file or suffix in text_exts
            if not is_text_file:
                continue
            try:
                if fp.stat().st_size > 2_000_000:
                    continue
                raw = fp.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw[:4096]:
                continue

            text = raw.decode("utf-8", errors="replace")
            lines = text.splitlines()

            if is_build_file:
                hook_window = 0
                for idx, line in enumerate(lines, start=1):
                    if _BUILD_HOOK_RE.search(line):
                        hook_window = 20
                    if (hook_window > 0 and _DANGEROUS_CMD_RE.search(line)) or _DIRECT_PAYLOAD_RE.search(line):
                        dangerous_build_hooks.append({
                            "file": rel,
                            "line": idx,
                            "snippet": line.strip()[:160],
                        })
                    if hook_window > 0:
                        if ")" in line and "(" not in line and "<" not in line:
                            hook_window = max(0, hook_window - 5)
                        else:
                            hook_window -= 1

            for idx, line in enumerate(lines, start=1):
                if _PROMPT_INJECTION_RE.search(line):
                    prompt_injection_suspects.append({
                        "file": rel,
                        "line": idx,
                        "snippet": line.strip()[:160],
                    })

    return {
        "passed": len(dangerous_build_hooks) == 0,
        "dangerous_build_hooks": dangerous_build_hooks,
        "prompt_injection_suspects": prompt_injection_suspects,
        "bundled_scripts_or_exes": bundled_scripts_or_exes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect-First Target Skyrim Runtime, SKSE64, and Address Library Resolver"
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON environment summary")
    args = parser.parse_args()

    info = detect_target_environment()
    if args.json:
        print(json.dumps(info, indent=2, default=str))
        return 0

    skse = info["skse"]
    reg = info["sdk_registered"]
    print("=" * 78)
    print(" SKSE64 PLUGIN ENVIRONMENT — DETECT-FIRST TARGET SUMMARY")
    print("=" * 78)
    print(f"Detected Target       : {info['target_version_full']} (dot: {info['target_version_dot']}, dash: {info['target_version_dash']})")
    print(f"Detection Source      : {info['target_source']}")
    print(f"Packed SKSE Version   : {info['target_version_packed_hex']}")
    print(f"Skyrim Install Dir    : {info['skyrim_dir'] or '<not found>'}")
    print(f"SkyrimSE.exe Version  : {info['skyrim_exe_version'] or '<not found>'}")
    print(
        f"Installed SKSE64 DLL  : {skse['dll_name'] or '<not found>'}"
        + (f" (SKSE v{skse['skse_version']})" if skse["skse_version"] else "")
    )
    print(f"Target AddrLib .bin   : {info['addrlib_bin_path'] or '<not found>'}")
    print(
        f"SDK Sync Status       : skse64={reg['skse64']}, CommonLibSSE-NG={reg['commonlibsse_ng']}, "
        f"bin_in_sdk={info['addrlib_in_sdk']}"
    )
    if info["sdk_needs_registration"]:
        print("-" * 78)
        print(
            "[!] Local SDK headers or sdk/address_tables/bin/ are missing this runtime."
        )
        print("    Run: python \"scripts/add_new_runtime.py\"")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
