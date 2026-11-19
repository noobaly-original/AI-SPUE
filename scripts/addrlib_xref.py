#!/usr/bin/env python3
"""
Address Library .bin Cross-Referencer & Executable Comparator (scripts/addrlib_xref.py)

Cross-references Address Library IDs, RVAs/IDA VAs, and SkyrimSE.exe functions across
runtime versions (`1.5.97` Format 1, `1.6.x` Format 2, and `1.7.99+` Format 5), and
diagnoses embedded Address Library format incompatibilities in compiled DLLs.
"""

from __future__ import annotations

import argparse
import bisect
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import inspect_bin  # noqa: E402
import pe_inspect  # noqa: E402
import skse_env  # noqa: E402
import verify_dll  # noqa: E402

IDA_IMAGE_BASE = 0x140000000
FORMAT_5_EPOCH_CUTOFF = 1748217600  # 2025-05-26 UTC


def _is_se_db(db: inspect_bin.AddressLibBin) -> bool:
    return db.version[:2] <= (1, 5)


def _resolve_target_id(
    old_id: int,
    db_from: inspect_bin.AddressLibBin,
    db_to: inspect_bin.AddressLibBin,
    se_to_ae: Dict[int, int],
    ae_to_se: Dict[int, int],
    se_to_sym: Dict[int, str],
    ae_split_to_new: Dict[int, int],
) -> Dict[str, Any]:
    in_from = old_id in db_from.id_to_offset
    old_off = db_from.id_to_offset.get(old_id)
    from_se = _is_se_db(db_from)
    to_se = _is_se_db(db_to)

    se_id = old_id if from_se else ae_to_se.get(old_id)
    sym = se_to_sym.get(se_id, "") if se_id else ""

    target_id: Optional[int] = old_id
    kind = "UNCHANGED_ID"

    if from_se and not to_se:
        mapped = se_to_ae.get(old_id)
        if mapped is not None:
            target_id = mapped
            kind = "SE_TO_AE"
    elif (not from_se) and to_se:
        mapped = ae_to_se.get(old_id)
        if mapped is not None:
            target_id = mapped
            kind = "AE_TO_SE"
    else:
        if old_id not in db_to.id_to_offset:
            split_new = ae_split_to_new.get(old_id)
            if split_new is None and se_id is not None:
                split_new = se_to_ae.get(se_id)
            if split_new is not None and split_new in db_to.id_to_offset:
                target_id = split_new
                kind = "SPLIT_ID"

    new_off = db_to.id_to_offset.get(target_id) if target_id is not None else None
    if not in_from:
        status = "MISSING_IN_SOURCE"
    elif new_off is None:
        status = "REMOVED_IN_TARGET"
    else:
        status = kind

    return {
        "source_id": old_id,
        "source_rva": f"0x{old_off:08x}" if old_off is not None else None,
        "source_va": f"0x{IDA_IMAGE_BASE + old_off:09x}" if old_off is not None else None,
        "target_id": target_id if new_off is not None else None,
        "target_rva": f"0x{new_off:08x}" if new_off is not None else None,
        "target_va": f"0x{IDA_IMAGE_BASE + new_off:09x}" if new_off is not None else None,
        "se_id": se_id,
        "symbol": sym,
        "status": status,
    }


def cmd_formats(args) -> int:
    bin_dir = args.bin_dir.resolve()
    search_items: List[Tuple[str, Path]] = []
    seen_names: set[str] = set()
    if bin_dir.exists():
        for bp in sorted(bin_dir.glob("*.bin")):
            search_items.append(("sdk_bin", bp))
            seen_names.add(bp.name.lower())
    elif args.bin_dir != skse_env.BIN_DIR:
        print(f"Error: bin directory not found: {bin_dir}", file=sys.stderr)
        return 1

    if args.bin_dir == skse_env.BIN_DIR:
        sky_plugins = skse_env.find_skyrim_plugins_dir()
        if sky_plugins.exists():
            for bp in sorted(sky_plugins.glob("version*.bin")):
                if bp.name.lower() not in seen_names:
                    search_items.append(("skyrim_plugins", bp))
                    seen_names.add(bp.name.lower())

    rows: List[Dict[str, Any]] = []
    for src_label, bp in search_items:
        try:
            db = inspect_bin.AddressLibBin(bp)
            max_id = max(db.id_to_offset.keys()) if db.id_to_offset else 0
            rows.append(
                {
                    "file": bp.name,
                    "source": src_label,
                    "version": db.version_str,
                    "format": db.format,
                    "valid_ids": len(db.id_to_offset),
                    "max_id": max_id,
                    "module": db.module_name,
                }
            )
        except Exception as exc:
            rows.append({"file": bp.name, "source": src_label, "error": str(exc)})

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    print(f"=== Address Library Databases ({bin_dir}) ===")
    print(f"{'Version':<12} | {'Fmt':<4} | {'Valid IDs':<11} | {'Max ID':<10} | {'Source':<14} | {'File'}")
    print("-" * 88)
    for r in rows:
        if "error" in r:
            print(f"{'ERROR':<12} | {'?':<4} | {'-':<11} | {'-':<10} | {r['source']:<14} | {r['file']} ({r['error']})")
        else:
            print(
                f"{r['version']:<12} | v{r['format']:<3} | {r['valid_ids']:<11,} | {r['max_id']:<10,} | "
                f"{r['source']:<14} | {r['file']}"
            )
    print("-" * 88)
    print("Format Notes:")
    print("  - Format 1 (1.5.x)   : Sparse delta-packed stream (version-*.bin)")
    print("  - Format 2 (1.6.x)   : Sparse delta-packed stream (versionlib-1-6-*.bin)")
    print("  - Format 5 (1.7.99+) : 96-byte header + dense uint32_t[] indexed by ID (mmap read-only)")
    return 0


def cmd_map_id(args) -> int:
    db_from = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path(args.src_ver))
    db_to = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path(args.dst_ver))
    se_to_ae, ae_to_se, se_to_sym, ae_split_to_new = skse_env.load_id_maps()

    results = [
        _resolve_target_id(id_val, db_from, db_to, se_to_ae, ae_to_se, se_to_sym, ae_split_to_new)
        for id_val in args.ids
    ]

    if args.json:
        print(json.dumps({"from": db_from.version_str, "to": db_to.version_str, "mappings": results}, indent=2))
        return 0

    print(f"Mapping IDs: {db_from.version_str} (v{db_from.format}) -> {db_to.version_str} (v{db_to.format})")
    print(f"{'Src ID':<10} | {'Src RVA':<12} | {'Dst ID':<10} | {'Dst RVA':<12} | {'Status':<18} | {'Symbol'}")
    print("-" * 100)
    for r in results:
        print(
            f"{r['source_id']:<10} | {r['source_rva'] or 'MISSING':<12} | "
            f"{str(r['target_id']) if r['target_id'] is not None else 'MISSING':<10} | "
            f"{r['target_rva'] or 'MISSING':<12} | {r['status']:<18} | {r['symbol']}"
        )
    return 0


def cmd_map_offset(args) -> int:
    db_from = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path(args.src_ver))
    db_to = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path(args.dst_ver))
    se_to_ae, ae_to_se, se_to_sym, ae_split_to_new = skse_env.load_id_maps()

    sorted_offs = sorted(db_from.offset_to_id.keys())
    max_search_delta = 0x4000
    results: List[Dict[str, Any]] = []

    for raw_off in args.offsets:
        rva = pe_inspect.parse_hex_or_int(raw_off)
        if rva >= IDA_IMAGE_BASE:
            rva -= IDA_IMAGE_BASE

        exact_id = db_from.offset_to_id.get(rva)
        delta = 0
        base_id: Optional[int] = exact_id
        base_rva: Optional[int] = rva if exact_id is not None else None

        if base_id is None and sorted_offs:
            pos = bisect.bisect_right(sorted_offs, rva) - 1
            if pos >= 0:
                cand_off = sorted_offs[pos]
                if 0 <= (rva - cand_off) < max_search_delta:
                    base_rva = cand_off
                    base_id = db_from.offset_to_id[cand_off]
                    delta = rva - cand_off

        if base_id is None:
            results.append(
                {
                    "input_rva": f"0x{rva:08x}",
                    "status": "NOT_FOUND_IN_SOURCE",
                    "warning": f"No Address Library entry within 0x{max_search_delta:x} bytes before 0x{rva:08x}.",
                }
            )
            continue

        id_map = _resolve_target_id(base_id, db_from, db_to, se_to_ae, ae_to_se, se_to_sym, ae_split_to_new)
        new_base_off = db_to.id_to_offset.get(id_map["target_id"]) if id_map["target_id"] is not None else None
        est_rva = (new_base_off + delta) if new_base_off is not None else None
        warning = (
            "Interior offset (+0x%x): MSVC may have shifted instructions inside this function; verify via disassembly/AOB!"
            % delta
            if delta > 0
            else None
        )
        results.append(
            {
                "input_rva": f"0x{rva:08x}",
                "source_base_id": base_id,
                "source_base_rva": f"0x{base_rva:08x}" if base_rva is not None else None,
                "delta": f"0x{delta:x}",
                "target_base_id": id_map["target_id"],
                "target_base_rva": id_map["target_rva"],
                "estimated_target_rva": f"0x{est_rva:08x}" if est_rva is not None else None,
                "estimated_target_va": f"0x{IDA_IMAGE_BASE + est_rva:09x}" if est_rva is not None else None,
                "status": id_map["status"],
                "symbol": id_map["symbol"],
                "warning": warning,
            }
        )

    if args.json:
        print(json.dumps({"from": db_from.version_str, "to": db_to.version_str, "offsets": results}, indent=2))
        return 0

    print(f"Mapping Offsets: {db_from.version_str} (v{db_from.format}) -> {db_to.version_str} (v{db_to.format})")
    for r in results:
        if r["status"] == "NOT_FOUND_IN_SOURCE":
            print(f"  {r['input_rva']} -> NOT FOUND ({r['warning']})")
            continue
        est = r["estimated_target_rva"] or "MISSING"
        print(
            f"  {r['input_rva']} = ID {r['source_base_id']} ({r['source_base_rva']}) + {r['delta']}"
            f"  ==>  ID {r['target_base_id']} ({r['target_base_rva']}) + {r['delta']} = {est} [{r['status']}]"
        )
        if r["symbol"]:
            print(f"      Symbol : {r['symbol']}")
        if r["warning"]:
            print(f"      [WARN] : {r['warning']}")
    return 0


def cmd_diff_ids(args) -> int:
    db_from = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path(args.src_ver))
    db_to = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path(args.dst_ver))
    se_to_ae, ae_to_se, se_to_sym, ae_split_to_new = skse_env.load_id_maps()

    if args.ids:
        id_list = [int(x.strip()) for x in args.ids.split(",") if x.strip()]
        rows = [
            _resolve_target_id(i, db_from, db_to, se_to_ae, ae_to_se, se_to_sym, ae_split_to_new)
            for i in id_list
        ]
        if args.json:
            print(json.dumps({"from": db_from.version_str, "to": db_to.version_str, "items": rows}, indent=2))
            return 0
        for r in rows:
            print(
                f"  ID {r['source_id']:<8} ({r['source_rva'] or 'MISSING'}) -> "
                f"ID {str(r['target_id']) if r['target_id'] is not None else 'MISSING':<8} "
                f"({r['target_rva'] or 'MISSING'}) [{r['status']}] {r['symbol']}"
            )
        return 0

    old_ids = set(db_from.id_to_offset.keys())
    new_ids = set(db_to.id_to_offset.keys())
    removed = sorted(old_ids - new_ids)
    added = sorted(new_ids - old_ids)
    common = old_ids & new_ids

    split_suggestions = [
        {"old_id": rid, "new_id": ae_split_to_new[rid]}
        for rid in removed
        if rid in ae_split_to_new and ae_split_to_new[rid] in new_ids
    ]

    summary = {
        "from": {"version": db_from.version_str, "format": db_from.format, "count": len(old_ids)},
        "to": {"version": db_to.version_str, "format": db_to.format, "count": len(new_ids)},
        "common_count": len(common),
        "added_count": len(added),
        "removed_count": len(removed),
        "known_split_replacements": split_suggestions,
        "removed_sample": removed[:25],
    }

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    print(
        f"Diff {db_from.version_str} (v{db_from.format}, {len(old_ids):,} IDs) -> "
        f"{db_to.version_str} (v{db_to.format}, {len(new_ids):,} IDs)"
    )
    print(f"  Common IDs  : {len(common):,}")
    print(f"  Added IDs   : {len(added):,}")
    print(f"  Removed IDs : {len(removed):,}")
    if split_suggestions:
        print("  Known Split ID Replacements in Removed Set:")
        for sp in split_suggestions:
            print(f"    - {sp['old_id']} => {sp['new_id']}")
    if removed:
        print(f"  Sample Removed IDs (first 25): {removed[:25]}")
    return 0


def scan_dll_address_library(dll_path: Path, target_runtime: Optional[str] = None) -> Dict[str, Any]:
    target_dash = (
        skse_env.format_version_dash(skse_env.parse_version_tuple(target_runtime))
        if target_runtime
        else skse_env.get_default_target_dash()
    )
    target_db = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path(target_dash))
    data = dll_path.resolve().read_bytes()
    pe_info = pe_inspect.parse_pe64(data)
    ver_data = pe_inspect.decode_skse_version_data(data, pe_info, target_runtime=target_db.version_str)
    fp = pe_inspect.fingerprint_skse_binary(data, pe_info, version_data=ver_data)

    findings: List[str] = []
    remediations: List[str] = []

    if ver_data is None:
        findings.append("DLL does not export SKSEPlugin_Version (legacy SKSEPlugin_Query or non-SKSE).")
        remediations.append("Recompile from source, or construct SKSEPluginVersionData if feasible (cannot simply patch metadata).")
    else:
        compat_status = ver_data["runtime_checks"].get(skse_env.format_version_dot(target_db.version), "UNKNOWN")
        if compat_status != "COMPATIBLE":
            findings.append(f"SKSEPlugin_Version rejected for {target_db.version_str}: {compat_status}")
            if not (ver_data["versionIndependenceEx"] & verify_dll.kVersionIndependentEx_AddressLibraryV5) and target_db.format >= 5:
                remediations.append("Set kVersionIndependentEx_AddressLibraryV5 (0x2) in versionIndependenceEx via manifest_patcher.py.")

    is_pre_v5_ts = pe_info["timestamp"] < FORMAT_5_EPOCH_CUTOFF
    if target_db.format >= 5 and fp["address_resolution"] == "AddressLibrary" and is_pre_v5_ts:
        findings.append(
            f"Built on {pe_info['timestamp_utc']} (pre-Format-5 epoch) while target {target_db.version_str} uses Format v{target_db.format}."
        )
        if fp["framework"] in ("CommonLibSSE", "CommonLibSSE-NG"):
            remediations.append(
                "Binary embeds a pre-v5 CommonLibSSE REL::IDDatabase loader; patch format check + unpack loop or test with AddressLibraryV5Shim.dll."
            )
        elif "versiondb" in fp["framework"].lower():
            remediations.append(
                "Binary embeds sse-build-resources versiondb::Load; inject Format 5 reader code cave via manifest_patcher.py."
            )

    if fp["rel_module_minor6_bug_rva"] is not None:
        findings.append(
            f"Detected CommonLibSSE minor-version bug (`cmp ax, 6; setne al`) at RVA 0x{fp['rel_module_minor6_bug_rva']:X} "
            "(treats 1.7.x+ as SE instead of AE)."
        )
        remediations.append(
            f"Patch 0x95 -> 0x92 (`setne al` -> `setb al`) at RVA 0x{fp['rel_module_minor6_bug_rva'] + 1:X}."
        )

    if fp["vtable_or_struct_risks"]:
        findings.append("High-risk 1.7.99+ VTable/struct symbols referenced: " + ", ".join(fp["vtable_or_struct_risks"]))
        remediations.append("Inspect call sites via `pe_inspect.py find-xrefs` / `disasm` and verify slot indices against SkyrimSE.exe.")

    return {
        "dll": str(dll_path.resolve()),
        "target_runtime": target_db.version_str,
        "target_bin_format": target_db.format,
        "pe_build_time": pe_info["timestamp_utc"],
        "pre_v5_timestamp": is_pre_v5_ts,
        "framework": fp["framework"],
        "address_resolution": fp["address_resolution"],
        "markers": fp["markers"],
        "rel_module_minor6_bug_rva": fp["rel_module_minor6_bug_rva"],
        "vtable_or_struct_risks": fp["vtable_or_struct_risks"],
        "findings": findings,
        "remediations": remediations,
    }


def cmd_scan_dll(args) -> int:
    rep = scan_dll_address_library(args.dll, target_runtime=args.target)
    if args.json:
        print(json.dumps(rep, indent=2))
        return 0

    print(f"=== Address Library Compatibility Scan: {Path(rep['dll']).name} ===")
    print(f"Target Runtime  : {rep['target_runtime']} (Address Library Format v{rep['target_bin_format']})")
    print(f"PE Build Time   : {rep['pe_build_time']} (pre-v5 epoch: {rep['pre_v5_timestamp']})")
    print(f"Framework       : {rep['framework']} | Address Mode: {rep['address_resolution']}")
    print(f"Markers         : {rep['markers'] or ['(none)']}")
    if rep["findings"]:
        print("\n[!] Findings:")
        for item in rep["findings"]:
            print(f"  - {item}")
    else:
        print("\n[OK] No Address Library format or metadata incompatibilities detected.")
    if rep["remediations"]:
        print("\n[*] Recommended Actions:")
        for r in rep["remediations"]:
            print(f"  - {r}")
    return 0


def cmd_exe_bytes(args) -> int:
    exe_path = args.skyrim_exe.resolve()
    if not exe_path.exists():
        print(f"Error: Executable not found: {exe_path}", file=sys.stderr)
        return 1

    db = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path(args.runtime))
    rva = db.id_to_offset.get(args.id)
    if rva is None:
        print(f"Error: ID {args.id} not found in {db.version_str}", file=sys.stderr)
        return 1

    data = exe_path.read_bytes()
    pe_info = pe_inspect.parse_pe64(data)
    off = pe_inspect.rva_to_file_offset(rva, pe_info["sections"])
    if off is None:
        print(f"Error: RVA 0x{rva:X} does not map to file bytes in {exe_path.name}", file=sys.stderr)
        return 1

    raw_slice = data[off : off + args.len]
    hex_str = " ".join(f"{b:02X}" for b in raw_slice)
    print(f"{exe_path.name} ({db.version_str}) | ID {args.id} -> RVA 0x{rva:08X} (FileOff 0x{off:08X})")
    print(f"Bytes ({len(raw_slice)}): {hex_str}")
    if args.disasm:
        print()
        print(pe_inspect.disassemble_range(exe_path, rva, args.len))
    return 0


def main() -> int:
    default_target = skse_env.get_default_target_dash()
    parser = argparse.ArgumentParser(description="Address Library .bin Cross-Referencer & Executable Comparator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_fmt = sub.add_parser("formats", help="List available Address Library .bin files and their binary formats")
    p_fmt.add_argument("--bin-dir", type=Path, default=skse_env.BIN_DIR)
    p_fmt.add_argument("--json", action="store_true")
    p_fmt.set_defaults(func=cmd_formats)

    p_mid = sub.add_parser("map-id", help="Cross-reference Address Library IDs between two game versions")
    p_mid.add_argument("ids", type=int, nargs="+", help="Decimal Address Library IDs")
    p_mid.add_argument("--from", dest="src_ver", default="1-6-1170-0", help="Historical source runtime baseline (default: 1-6-1170-0)")
    p_mid.add_argument("--to", dest="dst_ver", default=default_target, help=f"Target runtime (auto-detected default: {default_target})")
    p_mid.add_argument("--json", action="store_true")
    p_mid.set_defaults(func=cmd_map_id)

    p_moff = sub.add_parser("map-offset", help="Map RVA/IDA VA offsets from an old runtime to a new runtime")
    p_moff.add_argument("offsets", nargs="+", help="Hex RVAs (0x7baed0) or IDA VAs (0x1407baed0)")
    p_moff.add_argument("--from", dest="src_ver", default="1-6-1170-0", help="Historical source runtime baseline (default: 1-6-1170-0)")
    p_moff.add_argument("--to", dest="dst_ver", default=default_target, help=f"Target runtime (auto-detected default: {default_target})")
    p_moff.add_argument("--json", action="store_true")
    p_moff.set_defaults(func=cmd_map_offset)

    p_diff = sub.add_parser("diff-ids", help="Diff IDs between two Address Library .bin databases")
    p_diff.add_argument("--from", dest="src_ver", default="1-6-1170-0", help="Historical source runtime baseline (default: 1-6-1170-0)")
    p_diff.add_argument("--to", dest="dst_ver", default=default_target, help=f"Target runtime (auto-detected default: {default_target})")
    p_diff.add_argument("--ids", default=None, help="Optional comma-separated list of IDs to check")
    p_diff.add_argument("--json", action="store_true")
    p_diff.set_defaults(func=cmd_diff_ids)

    p_scan = sub.add_parser("scan-dll", help="Diagnose Address Library format compatibility for a compiled DLL")
    p_scan.add_argument("dll", type=Path)
    p_scan.add_argument("--target", default=default_target, help=f"Target runtime (auto-detected default: {default_target})")
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=cmd_scan_dll)

    p_exe = sub.add_parser("exe-bytes", help="Inspect bytes (and optional disassembly) for an ID in a SkyrimSE.exe")
    p_exe.add_argument("skyrim_exe", type=Path)
    p_exe.add_argument("--id", type=int, required=True)
    p_exe.add_argument("--runtime", default=default_target)
    p_exe.add_argument("--len", type=int, default=64)
    p_exe.add_argument("--disasm", action="store_true")
    p_exe.set_defaults(func=cmd_exe_bytes)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
