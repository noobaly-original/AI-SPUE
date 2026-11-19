#!/usr/bin/env python3
"""
SKSE64 Compiled DLL Binary Verifier (scripts/verify_dll.py)

Inspects any compiled SKSE plugin `.dll` file without needing to launch Skyrim:
  1. Verifies PE64 (x86_64) header and build timestamp.
  2. Loads the DLL with `DONT_RESOLVE_DLL_REFERENCES` (matching SKSE's `PluginManager::ScanPlugins`)
     and inspects exported symbols (`SKSEPlugin_Version`, `SKSEPlugin_Load`, `SKSEPlugin_Preload`, `SKSEPlugin_Query`).
  3. Unpacks the exact `0x350`-byte `SKSEPluginVersionData` struct (`SKSEPlugin_Version`) at binary offsets:
       0x000: dataVersion (uint32)
       0x004: pluginVersion (uint32)
       0x008: name (char[256])
       0x108: author (char[256])
       0x208: supportEmail (char[252])
       0x304: versionIndependenceEx (uint32) -> checks kVersionIndependentEx_AddressLibraryV5 (1 << 1)
       0x308: versionIndependence (uint32)   -> checks AddressLibraryPostAE (1 << 0), StructsPost629 (1 << 2)
       0x30C: compatibleVersions (uint32[16])
       0x34C: seVersionRequired (uint32)
  4. Runs the exact compatibility logic from SKSE64 (2.3.0+ rules) `PluginManager::CheckPluginCompatibility`
     across historical baselines (e.g. 1.6.640, 1.6.1170, 1.7.99) and the auto-detected target runtime.

Usage:
  python scripts/verify_dll.py <path_to_plugin.dll>
"""

import argparse
import ctypes
import datetime
import struct
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402

DONT_RESOLVE_DLL_REFERENCES = 0x00000001

# SKSEPluginVersionData flags from skse64/PluginAPI.h
kVersionIndependent_AddressLibraryPostAE = 1 << 0
kVersionIndependent_Signatures = 1 << 1
kVersionIndependent_StructsPost629 = 1 << 2

kVersionIndependentEx_NoStructUse = 1 << 0
kVersionIndependentEx_AddressLibraryV5 = 1 << 1


def unpack_skse_version(packed: int) -> str:
    major = (packed >> 24) & 0xFF
    minor = (packed >> 16) & 0xFF
    build = (packed >> 4) & 0xFFF
    sub = packed & 0xF
    return f"{major}.{minor}.{build}.{sub}"


def pack_skse_version(major: int, minor: int, build: int, sub: int = 0) -> int:
    return ((major & 0xFF) << 24) | ((minor & 0xFF) << 16) | ((build & 0xFFF) << 4) | (sub & 0xF)


def read_pe_info(dll_path: Path) -> Tuple[bool, int, str]:
    data = dll_path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False, 0, "Not a valid MZ executable"
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return False, 0, "Invalid PE signature"
    machine, _, timestamp = struct.unpack_from("<HHI", data, e_lfanew + 4)
    is_64 = machine == 0x8664
    arch = "x64 (0x8664)" if is_64 else f"Non-x64 (0x{machine:04x})"
    return is_64, timestamp, arch


def verify_dll(dll_path: Path, target_runtime: Optional[str] = None) -> Dict[str, Any]:
    dll_path = dll_path.resolve()
    if not dll_path.exists():
        raise FileNotFoundError(f"DLL not found: {dll_path}")

    target_tuple = (
        skse_env.parse_version_tuple(target_runtime)
        if target_runtime
        else skse_env.get_latest_target_version()
    )
    target_dot = skse_env.format_version_dot(target_tuple)

    is_64, timestamp, arch = read_pe_info(dll_path)
    build_dt = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    result: Dict[str, Any] = {
        "dll_path": str(dll_path),
        "size_bytes": dll_path.stat().st_size,
        "architecture": arch,
        "is_x64": is_64,
        "pe_timestamp": timestamp,
        "pe_build_time": build_dt,
        "target_runtime": target_dot,
        "exports": {},
        "version_data": None,
        "runtime_checks": {},
        "passed_target": False,
    }

    if not is_64:
        return result

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
    kernel32.LoadLibraryExW.restype = ctypes.c_void_p
    kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
    kernel32.FreeLibrary.restype = ctypes.c_int

    hmod = kernel32.LoadLibraryExW(str(dll_path), None, DONT_RESOLVE_DLL_REFERENCES)
    if not hmod:
        err = ctypes.get_last_error()
        raise RuntimeError(f"LoadLibraryExW failed on {dll_path} with Win32 error {err}")

    try:
        p_ver = kernel32.GetProcAddress(hmod, b"SKSEPlugin_Version")
        p_load = kernel32.GetProcAddress(hmod, b"SKSEPlugin_Load")
        p_preload = kernel32.GetProcAddress(hmod, b"SKSEPlugin_Preload")
        p_query = kernel32.GetProcAddress(hmod, b"SKSEPlugin_Query")

        result["exports"] = {
            "SKSEPlugin_Version": bool(p_ver),
            "SKSEPlugin_Load": bool(p_load),
            "SKSEPlugin_Preload": bool(p_preload),
            "SKSEPlugin_Query": bool(p_query),
        }

        if p_ver:
            raw_bytes = ctypes.string_at(p_ver, 0x350)
            data_ver, plugin_ver = struct.unpack_from("<II", raw_bytes, 0x000)
            name = raw_bytes[0x008:0x108].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            author = raw_bytes[0x108:0x208].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            email = raw_bytes[0x208:0x304].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            ver_ind_ex, ver_ind = struct.unpack_from("<II", raw_bytes, 0x304)
            compat_vers = struct.unpack_from("<16I", raw_bytes, 0x30C)
            se_min = struct.unpack_from("<I", raw_bytes, 0x34C)[0]

            compat_list = [unpack_skse_version(v) for v in compat_vers if v != 0]

            flags_ind = []
            if ver_ind & kVersionIndependent_AddressLibraryPostAE:
                flags_ind.append("AddressLibraryPostAE (0x1)")
            if ver_ind & kVersionIndependent_Signatures:
                flags_ind.append("Signatures (0x2)")
            if ver_ind & kVersionIndependent_StructsPost629:
                flags_ind.append("StructsPost629 (0x4)")

            flags_ex = []
            if ver_ind_ex & kVersionIndependentEx_NoStructUse:
                flags_ex.append("NoStructUse (0x1)")
            if ver_ind_ex & kVersionIndependentEx_AddressLibraryV5:
                flags_ex.append("AddressLibraryV5 (0x2)")

            result["version_data"] = {
                "dataVersion": data_ver,
                "pluginVersion_raw": plugin_ver,
                "pluginVersion": unpack_skse_version(plugin_ver) if plugin_ver > 0xFFFF else str(plugin_ver),
                "name": name,
                "author": author,
                "supportEmail": email,
                "versionIndependence": ver_ind,
                "versionIndependence_flags": flags_ind,
                "versionIndependenceEx": ver_ind_ex,
                "versionIndependenceEx_flags": flags_ex,
                "compatibleVersions": compat_list,
                "seVersionRequired": unpack_skse_version(se_min) if se_min else "0 (Any)",
            }

            # Simulate SKSE PluginManager::CheckPluginCompatibility across runtimes
            runtimes = [
                (label, pack_skse_version(*vt))
                for label, vt in skse_env.get_verification_runtimes(target_runtime)
            ]
            for rt_name, rt_val in runtimes:
                status = check_compat(
                    data_ver,
                    name,
                    ver_ind,
                    ver_ind_ex,
                    compat_vers,
                    timestamp,
                    rt_val,
                )
                result["runtime_checks"][rt_name] = status

            has_entry = bool(p_load) or bool(p_preload)
            result["passed_target"] = (
                result["runtime_checks"].get(target_dot) == "COMPATIBLE" and has_entry
            )
    finally:
        kernel32.FreeLibrary(hmod)

    return result


def check_compat(
    data_ver: int,
    name: str,
    ver_ind: int,
    ver_ind_ex: int,
    compat_vers: Tuple[int, ...],
    build_time: int,
    runtime_version: int,
) -> str:
    if not data_ver:
        return "REJECTED: disabled, bad version data"
    if not name:
        return "REJECTED: disabled, no name specified"

    known_ind = (
        kVersionIndependent_AddressLibraryPostAE
        | kVersionIndependent_Signatures
        | kVersionIndependent_StructsPost629
    )
    if ver_ind & ~known_ind:
        return "REJECTED: disabled, unsupported version independence method"

    version_independent = bool(
        ver_ind & (kVersionIndependent_AddressLibraryPostAE | kVersionIndependent_Signatures)
    )
    error_msg = "REJECTED: disabled, incompatible with current version of the game"

    if ver_ind & kVersionIndependent_AddressLibraryPostAE:
        if runtime_version >= pack_skse_version(1, 7, 99):
            if not (ver_ind_ex & kVersionIndependentEx_AddressLibraryV5):
                if 520128000 <= build_time < 1748217600:
                    error_msg = "REJECTED: must be recompiled for new address library (missing AddressLibraryV5 flag)"
                    version_independent = False
                else:
                    return "WARNING: missing kVersionIndependentEx_AddressLibraryV5 flag (passes timestamp check, but verify IDDB supports Format 5!)"

    if (
        version_independent
        and runtime_version >= pack_skse_version(1, 6, 629)
        and not (ver_ind & kVersionIndependent_StructsPost629)
    ):
        if not (ver_ind_ex & kVersionIndependentEx_NoStructUse):
            return "REJECTED: disabled, only compatible with versions earlier than 1.6.629"

    if not version_independent:
        found = False
        for cv in compat_vers:
            if cv == runtime_version:
                found = True
                break
            elif cv == 0:
                break
        if not found:
            return error_msg

    return "COMPATIBLE"


def print_verification(res: Dict[str, Any]) -> None:
    print("=" * 76)
    print(f" SKSE64 DLL BINARY VERIFICATION: {Path(res['dll_path']).name}")
    print("=" * 76)
    print(f"File Path       : {res['dll_path']}")
    print(f"File Size       : {res['size_bytes']:,} bytes")
    print(f"Architecture    : {res['architecture']}")
    print(f"PE Build Time   : {res['pe_build_time']} (epoch: {res['pe_timestamp']})")
    print(f"Exported Symbols: {res['exports']}")
    print("-" * 76)
    vd = res["version_data"]
    if not vd:
        print("[!!] FAIL: DLL does NOT export `SKSEPlugin_Version`! SKSE 2.1.0+ / 2.3.0+ will refuse to load it.")
        print("=" * 76)
        return

    print("SKSEPlugin_Version Metadata (0x350 bytes):")
    print(f"  dataVersion           : {vd['dataVersion']}")
    print(f"  pluginVersion         : {vd['pluginVersion']} (0x{vd['pluginVersion_raw']:08x})")
    print(f"  name                  : '{vd['name']}'")
    print(f"  author                : '{vd['author']}'")
    print(f"  supportEmail          : '{vd['supportEmail']}'")
    print(f"  versionIndependence   : 0x{vd['versionIndependence']:08x} -> {vd['versionIndependence_flags']}")
    print(f"  versionIndependenceEx : 0x{vd['versionIndependenceEx']:08x} -> {vd['versionIndependenceEx_flags']}")
    print(f"  compatibleVersions    : {vd['compatibleVersions'] or '[Version Independent via Address Library / SigScan]'}")
    print(f"  seVersionRequired     : {vd['seVersionRequired']}")
    print("-" * 76)
    print(f"SKSE64 PluginManager Compatibility Simulation (SKSE 2.3.0+ rules, target={res.get('target_runtime', 'auto')}):")
    for rt, status in res["runtime_checks"].items():
        tag = "[PASS]" if status == "COMPATIBLE" else "[FAIL]"
        print(f"  {tag} Skyrim SE/AE {rt:<10} : {status}")
    print("=" * 76)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a compiled SKSE64 plugin .dll binary")
    parser.add_argument("dll", help="Path to the .dll file")
    parser.add_argument(
        "--target",
        default=None,
        help="Target Skyrim runtime version (default: latest available in sdk/address_tables/bin)",
    )
    args = parser.parse_args()

    res = verify_dll(Path(args.dll), target_runtime=args.target)
    print_verification(res)
    return 0 if res["passed_target"] else 1


if __name__ == "__main__":
    sys.exit(main())
