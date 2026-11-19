#!/usr/bin/env python3
"""
SE <-> AE <-> Offset Address Library Mapper & Source Code Patcher (scripts/map_ids.py)

Combines:
  1. sdk/address_tables/se_ae_offsets.csv (350,000+ SE <-> AE mappings & symbols)
  2. sdk/CommonLibSSE-NG/include/RE/ (all RELOCATION_ID / RelocationID mappings, including 1.7.99+ fixes)
  3. Address Library .bin tables discovered in `sdk/address_tables/bin/` and Skyrim's `Data/SKSE/Plugins/` (Format 1/2/5)

Usage:
  python scripts/map_ids.py se2ae 46022 75450 13212
  python scripts/map_ids.py ae2se 47286 523983
  python scripts/map_ids.py offset2id 0x7baed0 --runtime 1-5-97-0
  python scripts/map_ids.py patch-dir <mod_source_dir> [--dry-run]
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402
from inspect_bin import AddressLibBin, resolve_bin_path  # noqa: E402

REPO_ROOT = skse_env.REPO_ROOT
SE_AE_CSV = skse_env.SE_AE_CSV
CLIB_INC = skse_env.CLIB_INC
CLIB_SRC = skse_env.CLIB_SRC

RE_SINGLE_REL_ID = re.compile(r"\bREL::ID\s*(\(\s*|\{\s*)(\d+)(\s*\)|\s*\})")


def build_combined_se_ae_maps() -> Tuple[Dict[int, int], Dict[int, int], Dict[int, str]]:
    """
    Returns (se_to_ae, ae_to_se, se_to_symbol).
    CommonLibSSE-NG mappings override CSV mappings because CommonLibSSE-NG includes
    the latest 1.7.99+ ID updates (e.g. 46022 -> 523983).
    """
    se_to_ae, ae_to_se, se_to_sym, _ = skse_env.load_id_maps()
    return se_to_ae, ae_to_se, se_to_sym


def cmd_se2ae(args) -> int:
    se_to_ae, _, se_to_sym = build_combined_se_ae_maps()
    db_se = AddressLibBin(resolve_bin_path("1-5-97-0"))
    db_1170 = AddressLibBin(resolve_bin_path("1-6-1170-0"))
    db_latest = AddressLibBin(resolve_bin_path(skse_env.get_default_target_dash()))
    latest_hdr = f"{db_latest.version_str} Offset"

    print(f"{'SE ID':<10} | {'AE ID':<10} | {'1.5.97 Offset':<14} | {'1.6.1170 Offset':<15} | {latest_hdr:<15} | {'C++ Replacement / Symbol'}")
    print("-" * 110)
    for se_id in args.ids:
        ae_id = se_to_ae.get(se_id)
        sym = se_to_sym.get(se_id, "")
        off_se = db_se.id_to_offset.get(se_id)
        off_se_s = f"0x{off_se:08x}" if off_se is not None else "MISSING"

        if ae_id is not None:
            off_1170 = db_1170.id_to_offset.get(ae_id)
            off_latest = db_latest.id_to_offset.get(ae_id)
            s_1170 = f"0x{off_1170:08x}" if off_1170 is not None else "MISSING"
            s_latest = f"0x{off_latest:08x}" if off_latest is not None else "MISSING"
            cpp = f"REL::RelocationID({se_id}, {ae_id})"
            if sym:
                cpp += f" // {sym}"
            print(f"{se_id:<10} | {ae_id:<10} | {off_se_s:<14} | {s_1170:<15} | {s_latest:<15} | {cpp}")
        else:
            print(f"{se_id:<10} | {'UNKNOWN':<10} | {off_se_s:<14} | {'-':<15} | {'-':<15} | No direct AE mapping found {sym}")
    return 0


def cmd_ae2se(args) -> int:
    se_to_ae, ae_to_se, se_to_sym = build_combined_se_ae_maps()
    db_1170 = AddressLibBin(resolve_bin_path("1-6-1170-0"))
    db_latest = AddressLibBin(resolve_bin_path(skse_env.get_default_target_dash()))
    latest_hdr = f"{db_latest.version_str} Offset"

    print(f"{'AE ID':<10} | {'SE ID':<10} | {'Latest AE ID':<12} | {'1.6.1170 Offset':<15} | {latest_hdr:<15} | {'C++ Replacement / Symbol'}")
    print("-" * 115)
    for ae_id in args.ids:
        se_id = ae_to_se.get(ae_id)
        latest_ae = se_to_ae.get(se_id, ae_id) if se_id else ae_id
        sym = se_to_sym.get(se_id, "") if se_id else ""
        off_1170 = db_1170.id_to_offset.get(ae_id)
        off_latest = db_latest.id_to_offset.get(latest_ae)
        s_1170 = f"0x{off_1170:08x}" if off_1170 is not None else "MISSING"
        s_latest = f"0x{off_latest:08x}" if off_latest is not None else "MISSING"
        se_s = str(se_id) if se_id is not None else "UNKNOWN"
        cpp = f"REL::RelocationID({se_id or 0}, {latest_ae})"
        if sym:
            cpp += f" // {sym}"
        print(f"{ae_id:<10} | {se_s:<10} | {latest_ae:<12} | {s_1170:<15} | {s_latest:<15} | {cpp}")
    return 0


def cmd_offset2id(args) -> int:
    se_to_ae, ae_to_se, se_to_sym = build_combined_se_ae_maps()
    db = AddressLibBin(resolve_bin_path(args.runtime))

    for raw in args.offsets:
        q = raw.strip().lower()
        val = int(q, 16) if q.startswith("0x") else int(q, 16)
        if val >= 0x140000000:
            val -= 0x140000000

        exact_id = db.offset_to_id.get(val)
        if exact_id is not None:
            if db.version[1] <= 5:
                se_id = exact_id
                ae_id = se_to_ae.get(se_id, 0)
            else:
                ae_id = exact_id
                se_id = ae_to_se.get(ae_id, 0)
            sym = se_to_sym.get(se_id, "")
            print(f"Offset 0x{val:08x} in {db.version_str} ==> Exact ID: {exact_id} | REL::RelocationID({se_id}, {ae_id}) {sym}")
        else:
            # Find nearest function base <= val
            candidates = [off for off in db.offset_to_id.keys() if off <= val and (val - off) < 0x2000]
            if candidates:
                base_off = max(candidates)
                base_id = db.offset_to_id[base_off]
                delta = val - base_off
                if db.version[1] <= 5:
                    se_id = base_id
                    ae_id = se_to_ae.get(se_id, 0)
                else:
                    ae_id = base_id
                    se_id = ae_to_se.get(ae_id, 0)
                print(
                    f"Offset 0x{val:08x} in {db.version_str} ==> Inside ID {base_id} (0x{base_off:08x}) + 0x{delta:x} "
                    f"| REL::RelocationID({se_id}, {ae_id}), 0x{delta:x}"
                )
            else:
                print(f"Offset 0x{val:08x} in {db.version_str} ==> Not found in {db.path.name}")
    return 0


def file_uses_only_ae_single_ids(
    content: str,
    se_ids_valid: Optional[Set[int]],
    target_ids_valid: Optional[Set[int]],
) -> bool:
    """Return True when every `REL::ID(num)` in code spans is absent from SE 1.5.97 and present in target AE."""
    if not se_ids_valid or not target_ids_valid:
        return False
    nums: List[int] = []
    for start, end, is_code in skse_env.iter_cpp_code_spans(content):
        if not is_code:
            continue
        for m in RE_SINGLE_REL_ID.finditer(content[start:end]):
            nums.append(int(m.group(2)))
    if not nums:
        return False
    return all((n not in se_ids_valid) and (n in target_ids_valid) for n in nums)


def patch_single_rel_ids_in_text(
    content: str,
    se_to_ae: Dict[int, int],
    se_ids_valid: Optional[Set[int]] = None,
    target_ids_valid: Optional[Set[int]] = None,
    file_looks_ae_only: bool = False,
) -> Tuple[str, int, int]:
    """
    Convert `REL::ID(se_id)` to `REL::RelocationID(se_id, ae_id)` inside C++ code spans only.
    Returns `(new_content, converted_count, skipped_ae_only_count)`.
    """
    converted_count = 0
    skipped_ae_only_count = 0
    out_chunks: List[str] = []

    for start, end, is_code in skse_env.iter_cpp_code_spans(content):
        chunk = content[start:end]
        if not is_code:
            out_chunks.append(chunk)
            continue

        def repl(m: re.Match) -> str:
            nonlocal converted_count, skipped_ae_only_count
            num = int(m.group(2))
            if file_looks_ae_only:
                skipped_ae_only_count += 1
                return m.group(0)
            if (
                se_ids_valid is not None
                and target_ids_valid is not None
                and (num not in se_ids_valid)
                and (num in target_ids_valid)
            ):
                skipped_ae_only_count += 1
                return m.group(0)
            ae_id = se_to_ae.get(num)
            if ae_id is not None:
                converted_count += 1
                return f"REL::RelocationID({num}, {ae_id})"
            return m.group(0)

        out_chunks.append(RE_SINGLE_REL_ID.sub(repl, chunk))

    return "".join(out_chunks), converted_count, skipped_ae_only_count


def _load_valid_id_sets() -> Tuple[Optional[Set[int]], Optional[Set[int]]]:
    se_ids: Optional[Set[int]] = None
    target_ids: Optional[Set[int]] = None
    try:
        se_ids = set(AddressLibBin(resolve_bin_path("1-5-97-0")).id_to_offset.keys())
    except FileNotFoundError:
        pass
    try:
        target_ids = set(AddressLibBin(resolve_bin_path(skse_env.get_default_target_dash())).id_to_offset.keys())
    except FileNotFoundError:
        pass
    return se_ids, target_ids


def cmd_patch_dir(args) -> int:
    mod_dir = Path(args.mod_dir).resolve()
    if not mod_dir.exists():
        print(f"Error: {mod_dir} does not exist", file=sys.stderr)
        return 1

    se_to_ae, _, _ = build_combined_se_ae_maps()
    se_ids_valid, target_ids_valid = _load_valid_id_sets()

    exts = {".cpp", ".cxx", ".cc", ".h", ".hpp", ".hxx", ".inl"}
    ignore_dirs = {"build", ".git", ".xmake", "vcpkg_installed", "extern", "external", "deps"}

    total_patched = 0
    total_skipped_ae = 0
    files_modified = 0

    for root, dirs, files in os.walk(mod_dir):
        dirs[:] = [d for d in dirs if d.lower() not in ignore_dirs and not d.lower().startswith("commonlibsse")]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in exts:
                continue
            try:
                content = fpath.read_text(encoding="utf-8")
            except Exception:
                continue

            ae_only = file_uses_only_ae_single_ids(content, se_ids_valid, target_ids_valid)
            new_content, count_in_file, skipped_in_file = patch_single_rel_ids_in_text(
                content,
                se_to_ae,
                se_ids_valid=se_ids_valid,
                target_ids_valid=target_ids_valid,
                file_looks_ae_only=ae_only,
            )
            total_skipped_ae += skipped_in_file
            if count_in_file > 0:
                files_modified += 1
                total_patched += count_in_file
                rel_p = fpath.relative_to(mod_dir)
                print(f"  [{'DRY-RUN' if args.dry_run else 'PATCHED'}] {rel_p}: converted {count_in_file} REL::ID -> REL::RelocationID")
                if not args.dry_run:
                    fpath.write_text(new_content, encoding="utf-8")

    print(f"\nSummary: {total_patched} REL::ID(se_id) call(s) across {files_modified} file(s) {'would be ' if args.dry_run else ''}converted.")
    if total_skipped_ae > 0:
        print(f"Note: skipped {total_skipped_ae} AE-only REL::ID call(s) (absent from 1.5.97, valid in target AE).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SE <-> AE <-> Offset Mapper & Source Patcher")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_se2ae = sub.add_parser("se2ae", help="Convert SE (1.5.97) IDs to AE (1.6/1.7) IDs")
    p_se2ae.add_argument("ids", type=int, nargs="+", help="SE IDs")
    p_se2ae.set_defaults(func=cmd_se2ae)

    p_ae2se = sub.add_parser("ae2se", help="Convert AE IDs to SE IDs and check latest AE updates")
    p_ae2se.add_argument("ids", type=int, nargs="+", help="AE IDs")
    p_ae2se.set_defaults(func=cmd_ae2se)

    p_off = sub.add_parser("offset2id", help="Convert hex RVA/IDA offsets to Address Library IDs")
    p_off.add_argument("offsets", nargs="+", help="Hex offsets (e.g. 0x7baed0 or 0x1407baed0)")
    p_off.add_argument("--runtime", default="1-5-97-0", help="Runtime version of the offset (default: 1-5-97-0)")
    p_off.set_defaults(func=cmd_offset2id)

    p_patch = sub.add_parser("patch-dir", help="Convert single-runtime REL::ID(se_id) to REL::RelocationID(se_id, ae_id) in a mod directory")
    p_patch.add_argument("mod_dir", help="Path to mod source code")
    p_patch.add_argument("--dry-run", action="store_true", help="Preview changes without modifying files")
    p_patch.set_defaults(func=cmd_patch_dir)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
