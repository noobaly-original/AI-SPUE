#!/usr/bin/env python3
"""
SKSE64 Modlist Compatibility Triage Scanner (scripts/triage_modlist.py)

Read-only scanner that inspects all `.dll` files in a Skyrim `Data\\SKSE\\Plugins`
directory (or Vortex/MO2 mods tree) and classifies each plugin for the target Skyrim runtime:
  - [OK]              Compatible with target runtime (exports SKSEPlugin_Version + AddressLibraryV5 or compatibleVersions)
  - [PATCHABLE-BIN]   Missing AddressLibraryV5; inspect with pe_inspect.py / addrlib_xref.py and patch via manifest_patcher.py
  - [METADATA-ONLY]   Missing AddressLibraryV5, custom/unmatched loader (use pe_inspect.py + manifest_patcher.py or recompile)
  - [RECOMPILE]       Legacy SKSEPlugin_Query-only (1.5.97) or high-risk VTable/struct markers detected
  - [NON-SKSE]        Not an SKSE plugin (e.g. msdia140.dll, helper library)

Usage:
  python scripts/triage_modlist.py [path_to_SKSE_Plugins_dir]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import pe_inspect  # noqa: E402
import skse_env  # noqa: E402
import verify_dll  # noqa: E402

LEGACY_DIR = SCRIPT_DIR / "legacy"
if LEGACY_DIR.exists() and str(LEGACY_DIR) not in sys.path:
    sys.path.insert(0, str(LEGACY_DIR))
try:
    import patch_binary as _legacy_patch_binary  # type: ignore  # noqa: E402
except ImportError:
    _legacy_patch_binary = None

DEFAULT_PLUGINS_DIR = skse_env.find_skyrim_plugins_dir()


def classify_dll(dll_path: Path, target: Optional[str] = None) -> Dict[str, str]:
    try:
        res = verify_dll.verify_dll(dll_path, target_runtime=target)
    except (RuntimeError, OSError) as exc:
        return {"name": dll_path.name, "status": "NON-SKSE", "detail": f"Unreadable/invalid DLL ({exc})"}

    exports = res.get("exports", {})
    is_skse = any(exports.get(k) for k in ("SKSEPlugin_Version", "SKSEPlugin_Load", "SKSEPlugin_Preload", "SKSEPlugin_Query"))
    if not res.get("is_x64") or not is_skse:
        return {"name": dll_path.name, "status": "NON-SKSE", "detail": "Helper/non-SKSE DLL"}

    if not exports.get("SKSEPlugin_Version"):
        return {
            "name": dll_path.name,
            "status": "RECOMPILE",
            "detail": "Legacy SKSEPlugin_Query only (no SKSEPlugin_Version export)",
        }

    raw = dll_path.read_bytes()
    try:
        pe_info = pe_inspect.parse_pe64(raw)
    except pe_inspect.PEError as exc:
        return {"name": dll_path.name, "status": "RECOMPILE", "detail": f"PE error: {exc}"}

    fp = pe_inspect.fingerprint_skse_binary(raw, pe_info)
    risks = fp.get("vtable_or_struct_risks", [])

    if res.get("passed_target"):
        note = "Compatible"
        if risks:
            note += f" (strings: {', '.join(r.split(' ')[0] for r in risks)})"
        return {"name": dll_path.name, "status": "OK", "detail": note}

    if risks:
        risk_names = ", ".join(r.split(" ")[0] for r in risks)
        return {
            "name": dll_path.name,
            "status": "RECOMPILE",
            "detail": f"1.7.99+ struct/VTable risk ({risk_names}); recompile or inspect via pe_inspect.py",
        }

    if _legacy_patch_binary is not None:
        try:
            e_lf, sections, _ = _legacy_patch_binary.parse_pe64_sections_and_exports(raw)
            v5_info = _legacy_patch_binary.find_versiondb_v5_target(raw, e_lf, sections)
            clib_info = _legacy_patch_binary.find_commonlib_v5_target(raw, e_lf, sections) if v5_info is None else None
            if v5_info is not None:
                return {
                    "name": dll_path.name,
                    "status": "PATCHABLE-BIN",
                    "detail": "versiondb::Load Format 5 patchable (inspect via pe_inspect.py / manifest_patcher.py)",
                }
            if clib_info is not None:
                return {
                    "name": dll_path.name,
                    "status": "PATCHABLE-BIN",
                    "detail": "REL::IDDatabase Format 5 patchable (inspect via pe_inspect.py / manifest_patcher.py)",
                }
        except Exception:
            pass

    return {
        "name": dll_path.name,
        "status": "METADATA-ONLY",
        "detail": "Missing AddressLibraryV5; triage via pe_inspect.py & addrlib_xref.py (see docs/BINARY_PATCHING_GUIDE.md)",
    }


def main() -> int:
    default_target = skse_env.get_default_target_dot()
    parser = argparse.ArgumentParser(description="Read-only SKSE64 modlist compatibility triage scanner.")
    parser.add_argument(
        "plugins_dir",
        nargs="?",
        type=Path,
        default=DEFAULT_PLUGINS_DIR,
        help="Path to Data\\SKSE\\Plugins directory",
    )
    parser.add_argument(
        "--target",
        default=default_target,
        help=f"Target Skyrim runtime version (default: {default_target})",
    )
    args = parser.parse_args()

    target_dir = args.plugins_dir.resolve()
    if not target_dir.exists():
        print(f"[ERROR] Directory not found: {target_dir}", file=sys.stderr)
        return 1

    dlls = sorted(target_dir.glob("*.dll"))
    if not dlls:
        print(f"[INFO] No .dll files found in {target_dir}")
        return 0

    rows: List[Dict[str, str]] = [classify_dll(d, target=args.target) for d in dlls]
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    print(f"=== SKSE64 {args.target} Modlist Triage: {target_dir} ===")
    for r in rows:
        print(f"  [{r['status']:<13}] {r['name']:<42} {r['detail']}")
    print("-" * 76)
    print("Summary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
