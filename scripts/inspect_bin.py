#!/usr/bin/env python3
"""
Address Library Binary (.bin) Inspector, Lookup, Diff & Mod ID Verifier
Supports:
  - Format 1 (SE 1.5.x: version-1-5-97-0.bin)
  - Format 2 (AE 1.6.x: versionlib-1-6-1170-0.bin)
  - Format 5 (AE 1.7.99+: versionlib-<major>-<minor>-<build>-0.bin)

Usage:
  python scripts/inspect_bin.py info <major>-<minor>-<build>-0
  python scripts/inspect_bin.py lookup 47286
  python scripts/inspect_bin.py verify-mod <path_to_mod_src> [--target <major>-<minor>-<build>-0]
  python scripts/inspect_bin.py diff 1-6-1170-0 <major>-<minor>-<build>-0
"""

import argparse
import os
import re
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402

REPO_ROOT = skse_env.REPO_ROOT
BIN_DIR = skse_env.BIN_DIR
SE_AE_CSV = skse_env.SE_AE_CSV


def resolve_bin_path(version_or_path: str) -> Path:
    p = Path(version_or_path)
    if p.exists():
        return p
    norm = version_or_path.replace(".", "-")
    search_dirs: List[Path] = [BIN_DIR]
    skyrim_plugins = skse_env.find_skyrim_plugins_dir()
    if skyrim_plugins not in search_dirs:
        search_dirs.append(skyrim_plugins)

    for base_dir in search_dirs:
        if not base_dir.exists():
            continue
        for c in (
            base_dir / norm,
            base_dir / f"versionlib-{norm}.bin",
            base_dir / f"versionlib-{norm}-0.bin",
            base_dir / f"version-{norm}.bin",
            base_dir / f"version-{norm}-0.bin",
        ):
            if c.exists():
                return c

    raise FileNotFoundError(
        f"Could not find Address Library .bin for '{version_or_path}'. Checked {', '.join(str(d) for d in search_dirs)}"
    )


class AddressLibBin:
    def __init__(self, path: Path):
        self.path = path
        self.format: int = 0
        self.version: Tuple[int, int, int, int] = (0, 0, 0, 0)
        self.module_name: str = ""
        self.pointer_size: int = 8
        self.id_to_offset: Dict[int, int] = {}
        self.offset_to_id: Dict[int, int] = {}
        self._load()

    @property
    def version_str(self) -> str:
        return ".".join(str(x) for x in self.version)

    def _load(self) -> None:
        data = self.path.read_bytes()
        pos = 0

        def read_fmt(fmt: str):
            nonlocal pos
            sz = struct.calcsize(fmt)
            vals = struct.unpack_from(fmt, data, pos)
            pos += sz
            return vals[0] if len(vals) == 1 else vals

        self.format = read_fmt("<i")
        if self.format in (1, 2):
            v0, v1, v2, v3 = read_fmt("<4i")
            self.version = (v0, v1, v2, v3)
            name_len = read_fmt("<i")
            if name_len < 0 or name_len > 0x10000:
                raise ValueError(f"Invalid module name length {name_len} in {self.path}")
            self.module_name = data[pos : pos + name_len].decode("ascii", errors="replace")
            pos += name_len
            self.pointer_size = read_fmt("<i")
            addr_count = read_fmt("<i")

            pvid = 0
            poffs = 0
            psize = self.pointer_size

            for _ in range(addr_count):
                b_type = data[pos]
                pos += 1
                low = b_type & 0x0F
                high = b_type >> 4

                if low == 0:
                    q1 = read_fmt("<Q")
                elif low == 1:
                    q1 = pvid + 1
                elif low == 2:
                    q1 = pvid + data[pos]
                    pos += 1
                elif low == 3:
                    q1 = pvid - data[pos]
                    pos += 1
                elif low == 4:
                    q1 = pvid + read_fmt("<H")
                elif low == 5:
                    q1 = pvid - read_fmt("<H")
                elif low == 6:
                    q1 = read_fmt("<H")
                elif low == 7:
                    q1 = read_fmt("<I")
                else:
                    raise ValueError(f"Unhandled low nibble {low} in {self.path}")

                tpoffs = (poffs // psize) if (high & 8) != 0 else poffs
                h7 = high & 7
                if h7 == 0:
                    q2 = read_fmt("<Q")
                elif h7 == 1:
                    q2 = tpoffs + 1
                elif h7 == 2:
                    q2 = tpoffs + data[pos]
                    pos += 1
                elif h7 == 3:
                    q2 = tpoffs - data[pos]
                    pos += 1
                elif h7 == 4:
                    q2 = tpoffs + read_fmt("<H")
                elif h7 == 5:
                    q2 = tpoffs - read_fmt("<H")
                elif h7 == 6:
                    q2 = read_fmt("<H")
                elif h7 == 7:
                    q2 = read_fmt("<I")
                else:
                    raise ValueError(f"Unhandled high nibble {h7} in {self.path}")

                if (high & 8) != 0:
                    q2 *= psize

                self.id_to_offset[q1] = q2
                self.offset_to_id[q2] = q1
                pvid = q1
                poffs = q2

        elif self.format == 5:
            v0, v1, v2, v3 = read_fmt("<4I")
            self.version = (v0, v1, v2, v3)
            raw_name = data[pos : pos + 64]
            pos += 64
            self.module_name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            self.pointer_size = read_fmt("<i")
            self.data_format = read_fmt("<i")
            offset_count = read_fmt("<i")

            # Fast bulk unpack of dense uint32 array
            offsets = struct.unpack_from(f"<{offset_count}I", data, pos)
            for idx, off in enumerate(offsets):
                if off != 0:
                    self.id_to_offset[idx] = off
                    self.offset_to_id[off] = idx
        else:
            raise ValueError(f"Unsupported Address Library format {self.format} in {self.path}")


def load_se_to_ae_map() -> Tuple[Dict[int, int], Dict[int, int]]:
    se_to_ae, _, _, ae_split_to_new = skse_env.load_id_maps()
    return se_to_ae, ae_split_to_new


def scan_mod_ids(mod_dir: Path) -> Dict[str, List[Tuple[str, int, Tuple[int, ...]]]]:
    """
    Scans C++ source/header files in mod_dir for Address Library IDs:
      - single_id: REL::ID(12345), VersionDb.FindAddressById(12345)
      - dual_id: REL::RelocationID(se, ae), RELOCATION_ID(se, ae), REL::VariantID(se, ae, vr)
    """
    results = {
        "single_id": [],  # (rel_path, line_no, (id,))
        "dual_id": [],    # (rel_path, line_no, (se_id, ae_id))
    }

    re_dual = re.compile(
        r"\b(?:REL::RelocationID|RELOCATION_ID|REL::VariantID)\s*\(\s*(\d+)\s*,\s*(\d+)"
    )
    re_single = re.compile(
        r"\b(?:REL::ID|FindAddressById|FindOffsetById)\s*(?:\(\s*|\{\s*)(\d+)\s*[)\}]"
    )

    exts = {".cpp", ".cxx", ".cc", ".h", ".hpp", ".hxx", ".inl"}
    ignore_dirs = {"build", ".git", ".xmake", "vcpkg_installed", "extern", "external", "deps"}

    for root, dirs, files in os.walk(mod_dir):
        dirs[:] = [d for d in dirs if d.lower() not in ignore_dirs and not d.lower().startswith("commonlibsse")]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in exts:
                continue
            rel_p = str(fpath.relative_to(mod_dir))
            try:
                raw_text = fpath.read_text(encoding="utf-8", errors="replace")
                lines = skse_env.strip_cpp_comments_preserve_lines(raw_text).splitlines()
            except Exception:
                continue
            for idx, clean in enumerate(lines, start=1):
                for m in re_dual.finditer(clean):
                    se_id, ae_id = int(m.group(1)), int(m.group(2))
                    results["dual_id"].append((rel_p, idx, (se_id, ae_id)))
                for m in re_single.finditer(clean):
                    sid = int(m.group(1))
                    results["single_id"].append((rel_p, idx, (sid,)))

    return results


def cmd_info(args) -> int:
    bin_path = resolve_bin_path(args.bin)
    db = AddressLibBin(bin_path)
    max_id = max(db.id_to_offset.keys()) if db.id_to_offset else 0
    print(f"File          : {bin_path}")
    print(f"Binary Format : v{db.format} ({'Dense mmap array (1.7.99+)' if db.format == 5 else 'Delta-packed sparse table'})")
    print(f"Game Version  : {db.version_str}")
    print(f"Module Name   : {db.module_name}")
    print(f"Pointer Size  : {db.pointer_size} bytes")
    print(f"Valid IDs     : {len(db.id_to_offset):,}")
    print(f"Max ID        : {max_id:,}")
    return 0


def cmd_lookup(args) -> int:
    se_to_ae, ae_split_to_new = load_se_to_ae_map()
    ae_to_se = {v: k for k, v in se_to_ae.items()}

    q = args.query.strip()
    is_hex = q.lower().startswith("0x")
    val = int(q, 16) if is_hex else int(q)
    if is_hex and val >= 0x140000000:
        val -= 0x140000000

    versions = skse_env.get_lookup_versions()
    print(f"Lookup Query  : {args.query} ({'Offset 0x' + format(val, 'x') if is_hex else 'ID ' + str(val)})")
    if not is_hex:
        if val in se_to_ae:
            print(f"SE->AE Map    : SE ID {val}  ==>  AE ID {se_to_ae[val]}")
        if val in ae_to_se:
            print(f"AE->SE Map    : AE ID {val}  <==  SE ID {ae_to_se[val]}")

    print("-" * 72)
    print(f"{'Runtime':<15} | {'Format':<8} | {'ID':<12} | {'Offset (RVA)':<16} | {'IDA Address':<16}")
    print("-" * 72)
    for ver in versions:
        try:
            bp = resolve_bin_path(ver)
            db = AddressLibBin(bp)
        except Exception:
            continue
        if is_hex:
            found_id = db.offset_to_id.get(val)
            if found_id is not None:
                print(f"{db.version_str:<15} | v{db.format:<7} | {found_id:<12} | 0x{val:08x}       | 0x{0x140000000 + val:09x}")
            else:
                print(f"{db.version_str:<15} | v{db.format:<7} | {'NOT FOUND':<12} | -                | -")
        else:
            # For SE (1.5.97), check val and ae_to_se[val]; for AE, check val and se_to_ae[val]
            off = db.id_to_offset.get(val)
            if off is not None:
                print(f"{db.version_str:<15} | v{db.format:<7} | {val:<12} | 0x{off:08x}       | 0x{0x140000000 + off:09x}")
            else:
                print(f"{db.version_str:<15} | v{db.format:<7} | {val:<12} | {'MISSING (0)':<16} | -")
    return 0


def cmd_diff(args) -> int:
    db_old = AddressLibBin(resolve_bin_path(args.old_bin))
    db_new = AddressLibBin(resolve_bin_path(args.new_bin))

    old_ids = set(db_old.id_to_offset.keys())
    new_ids = set(db_new.id_to_offset.keys())

    common = old_ids & new_ids
    removed = sorted(old_ids - new_ids)
    added = sorted(new_ids - old_ids)

    print(f"Comparing {db_old.version_str} (Format v{db_old.format}, {len(old_ids):,} IDs) -> "
          f"{db_new.version_str} (Format v{db_new.format}, {len(new_ids):,} IDs)")
    print(f"  Common IDs  : {len(common):,}")
    print(f"  Added IDs   : {len(added):,}")
    print(f"  Removed IDs : {len(removed):,}")
    if removed:
        print(f"  Sample Removed IDs (first 25): {removed[:25]}")
    return 0


def cmd_verify_mod(args) -> int:
    mod_dir = Path(args.mod_dir).resolve()
    if not mod_dir.exists():
        print(f"Error: Directory {mod_dir} does not exist.", file=sys.stderr)
        return 1

    target_db = AddressLibBin(resolve_bin_path(args.target))
    se_db = None
    prev_ae_db = None
    try:
        se_db = AddressLibBin(resolve_bin_path("1-5-97-0"))
    except Exception:
        pass
    try:
        prev_ae_db = AddressLibBin(resolve_bin_path("1-6-1170-0"))
    except Exception:
        pass

    se_to_ae, ae_split_to_new = load_se_to_ae_map()
    scanned = scan_mod_ids(mod_dir)

    print(f"=== Address Library ID Verification for '{mod_dir.name}' ===")
    print(f"Target Runtime : {target_db.version_str} (Format v{target_db.format})")
    print(f"Dual IDs (SE/AE) found : {len(scanned['dual_id'])}")
    print(f"Single IDs found       : {len(scanned['single_id'])}")

    missing_in_target = []
    needs_se_to_ae = []

    for rel_p, line_no, (se_id, ae_id) in scanned["dual_id"]:
        if ae_id == 0:
            mapped = se_to_ae.get(se_id)
            missing_in_target.append((rel_p, line_no, se_id, ae_id, f"AE ID is 0 (Suggested AE ID: {mapped})"))
        elif ae_id not in target_db.id_to_offset:
            in_1170 = prev_ae_db and (ae_id in prev_ae_db.id_to_offset)
            replacement = ae_split_to_new.get(ae_id) or se_to_ae.get(se_id)
            repl_str = f" -> Suggested {target_db.version_str} AE ID: {replacement}" if replacement and replacement != ae_id else ""
            note = ("Present in 1.6.1170 but CHANGED/INLINED in " + target_db.version_str + repl_str) if in_1170 else ("Not found in target .bin" + repl_str)
            missing_in_target.append((rel_p, line_no, se_id, ae_id, note))

    for rel_p, line_no, (sid,) in scanned["single_id"]:
        in_target = sid in target_db.id_to_offset
        in_se = se_db and (sid in se_db.id_to_offset)
        mapped_ae = se_to_ae.get(sid)
        if mapped_ae and mapped_ae != sid:
            needs_se_to_ae.append((rel_p, line_no, sid, mapped_ae, mapped_ae in target_db.id_to_offset))
        elif not in_target:
            missing_in_target.append((rel_p, line_no, sid, sid, "Single ID not found in target .bin"))

    if not missing_in_target and not needs_se_to_ae:
        print("\n[OK] All scanned Address Library IDs exist in target runtime " + target_db.version_str + "!")
        return 0

    if needs_se_to_ae:
        print(f"\n[!] Found {len(needs_se_to_ae)} single-runtime ID(s) that should be converted to REL::RelocationID(se_id, ae_id):")
        for rel_p, line_no, sid, mapped_ae, ok_in_target in needs_se_to_ae[:50]:
            status = "VALID in target" if ok_in_target else "MISSING in target"
            print(f"  - {rel_p}:{line_no}: REL::ID({sid}) -> REL::RelocationID({sid}, {mapped_ae}) [{status}]")

    if missing_in_target:
        print(f"\n[!!] Found {len(missing_in_target)} ID(s) MISSING in target {target_db.version_str}:")
        for rel_p, line_no, se_id, ae_id, note in missing_in_target:
            print(f"  - {rel_p}:{line_no}: (SE={se_id}, AE={ae_id}) -> {note}")
        return 2

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Address Library .bin Inspector & Mod ID Verifier")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("info", help="Display metadata about a versionlib/version .bin file")
    p_info.add_argument("bin", help="Version string (e.g. <major>-<minor>-<build>-0) or path to .bin file")
    p_info.set_defaults(func=cmd_info)

    p_lookup = sub.add_parser("lookup", help="Look up an Address Library ID or hex RVA offset across runtimes")
    p_lookup.add_argument("query", help="Decimal ID (e.g. 47286) or Hex Offset (e.g. 0x7e2340)")
    p_lookup.set_defaults(func=cmd_lookup)

    p_diff = sub.add_parser("diff", help="Compare two Address Library .bin files")
    p_diff.add_argument("old_bin", help="Old historical version (e.g. 1-6-1170-0)")
    p_diff.add_argument("new_bin", help="New target version (e.g. <major>-<minor>-<build>-0)")
    p_diff.set_defaults(func=cmd_diff)

    p_verify = sub.add_parser("verify-mod", help="Verify all Address Library IDs used in a mod's source directory")
    p_verify.add_argument("mod_dir", help="Path to mod source code directory")
    p_verify.add_argument(
        "--target",
        default=skse_env.get_default_target_dash(),
        help="Target runtime version (default: latest available runtime)",
    )
    p_verify.set_defaults(func=cmd_verify_mod)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
