#!/usr/bin/env python3
"""Extract, inspect, and export meh321 AddressLibraryDatabase (.relib / .rename).

Supports:
  - Parsing `skyrimae.relib` binary databases (format v1 & v2) containing multi-version
    AE offsets and function hashes from `meh321/AddressLibraryDatabase`.
  - Parsing `skyrimae.rename` symbol files mapping AE Address Library IDs to names.
  - Packing extracted per-version tables into Address Library Format 2 `.bin` files
    (`versionlib-<v0>-<v1>-<v2>-<v3>[...].bin`) matching `AddressLibraryManager`'s
    delta/nibble compression.
  - Exporting multi-version CSV tables and looking up IDs, symbols, or RVAs.

Usage:
  python scripts/extract_relib.py download [--with-relib] [--force]
  python scripts/extract_relib.py info [--relib PATH] [--rename PATH] [--json]
  python scripts/extract_relib.py extract-bins [--versions 1.6.1170.0 ...] [--out-dir DIR]
  python scripts/extract_relib.py extract-csv -o out.csv [--versions ...]
  python scripts/extract_relib.py lookup <id_or_symbol_or_0xRVA> [--version 1.6.1170.0]
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import struct
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402

MEH321_RAW_BASE = "https://github.com/meh321/AddressLibraryDatabase/raw/main"
RENAME_URL = f"{MEH321_RAW_BASE}/skyrimae.rename"
RELIB_URL = f"{MEH321_RAW_BASE}/skyrimae.relib"

DEFAULT_RELIB_PATH = skse_env.SDK_DIR / "address_tables" / "skyrimae.relib"
DEFAULT_RENAME_PATH = skse_env.SDK_DIR / "address_tables" / "skyrimae.rename"


def _read_7bit_encoded_int(buf: bytes | memoryview, pos: int) -> Tuple[int, int]:
    """Decode a .NET BinaryReader 7-bit LEB128 unsigned integer."""
    count = 0
    shift = 0
    while True:
        if shift >= 35 or pos >= len(buf):
            raise ValueError(f"Corrupt 7-bit encoded integer at offset {pos}")
        b = buf[pos]
        pos += 1
        count |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            return count, pos


def _encode_7bit_encoded_int(value: int) -> bytes:
    """Encode a non-negative integer in .NET BinaryReader 7-bit LEB128 format."""
    if value < 0:
        raise ValueError(f"Negative value for 7-bit int: {value}")
    out = bytearray()
    v = value
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _read_dotnet_string(buf: bytes | memoryview, pos: int) -> Tuple[str, int]:
    byte_len, pos = _read_7bit_encoded_int(buf, pos)
    end = pos + byte_len
    if end > len(buf):
        raise ValueError(f"Truncated .NET string at offset {pos} (need {byte_len} bytes)")
    return bytes(buf[pos:end]).decode("utf-8", errors="replace"), end


def _encode_dotnet_string(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return _encode_7bit_encoded_int(len(encoded)) + encoded


def version_tuple_to_dot(ver: Sequence[int]) -> str:
    return ".".join(str(x) for x in ver)


def version_tuple_to_dash(ver: Sequence[int]) -> str:
    return "-".join(str(x) for x in ver)


def parse_flexible_version(ver_str: str) -> Tuple[int, ...]:
    """Parse 2..5 part dotted or dashed version strings (supports 5-part GOG e.g. 1.6.1170.0.1)."""
    cleaned = ver_str.strip()
    if not cleaned:
        raise ValueError("Empty version string")
    parts = [p for p in cleaned.replace("-", ".").split(".")]
    if not parts or any(not p.isdigit() for p in parts):
        raise ValueError(f"Invalid version string: {ver_str!r}")
    nums = [int(p) for p in parts]
    while len(nums) < 4:
        nums.append(0)
    return tuple(nums)


@dataclass
class RelibVersion:
    """One game executable version slice inside a `.relib` database."""

    version: Tuple[int, ...]
    overwrite_module_name: Optional[str]
    base_address: int
    val_count: int
    hash_count: int
    _vals_raw: bytes | memoryview
    _hashes_raw: bytes | memoryview

    @property
    def version_dot(self) -> str:
        return version_tuple_to_dot(self.version)

    @property
    def version_dash(self) -> str:
        return version_tuple_to_dash(self.version)

    def iter_offsets(self) -> Iterator[Tuple[int, int]]:
        """Yield `(vid, rva_offset)` pairs in stored order."""
        return struct.iter_unpack("<QI", self._vals_raw)

    def iter_hashes(self) -> Iterator[Tuple[int, int]]:
        """Yield `(vid, fn_hash)` pairs in stored order (format v2+)."""
        if not self._hashes_raw:
            return iter(())
        return struct.iter_unpack("<QQ", self._hashes_raw)

    def to_id_offset_dict(self) -> Dict[int, int]:
        """Materialize `vid -> rva_offset` dict for this version."""
        return {vid: offset for vid, offset in struct.iter_unpack("<QI", self._vals_raw)}

    def to_offset_ids_dict(self) -> Dict[int, List[int]]:
        """Materialize `rva_offset -> [vids...]` reverse lookup dict."""
        rev: Dict[int, List[int]] = {}
        for vid, offset in struct.iter_unpack("<QI", self._vals_raw):
            rev.setdefault(offset, []).append(vid)
        return rev

    def to_hash_dict(self) -> Dict[int, int]:
        """Materialize `vid -> hash` dict for this version."""
        if not self._hashes_raw:
            return {}
        return {vid: fn_hash for vid, fn_hash in struct.iter_unpack("<QQ", self._hashes_raw)}

    def lookup_id(self, target_vid: int) -> Optional[int]:
        for vid, offset in struct.iter_unpack("<QI", self._vals_raw):
            if vid == target_vid:
                return offset
        return None


@dataclass
class RelibDatabase:
    """Parsed meh321 `.relib` multi-version address library database."""

    format_version: int
    high_vid: int
    pointer_size: int
    target_module_name: Optional[str]
    versions: List[RelibVersion]

    def get_version(self, ver_spec: str) -> Optional[RelibVersion]:
        target = parse_flexible_version(ver_spec)
        for entry in self.versions:
            if entry.version == target:
                return entry
        # Retry ignoring trailing zeros when caller passed 4-part for 4-part or prefix match
        for entry in self.versions:
            padded = entry.version + (0,) * max(0, 4 - len(entry.version))
            if padded == target:
                return entry
        return None


def parse_relib_bytes(data: bytes) -> RelibDatabase:
    """Parse a meh321 `.relib` binary buffer (supports format v1 and v2)."""
    mv = memoryview(data)
    pos = 0

    def need(n: int) -> None:
        if pos + n > len(mv):
            raise ValueError(f"Unexpected EOF in .relib at offset {pos} (need {n} bytes)")

    need(17)
    fmt_ver, high_vid, ptr_size, has_name = struct.unpack_from("<iQiB", mv, pos)
    pos += 17
    if fmt_ver not in (1, 2):
        raise ValueError(f"Unsupported .relib format version: {fmt_ver} (expected 1 or 2)")

    target_module_name: Optional[str] = None
    if has_name != 0:
        target_module_name, pos = _read_dotnet_string(mv, pos)

    need(4)
    ver_count = struct.unpack_from("<i", mv, pos)[0]
    pos += 4
    if ver_count < 0 or ver_count > 10000:
        raise ValueError(f"Invalid version count {ver_count} in .relib")

    versions: List[RelibVersion] = []
    for _ in range(ver_count):
        need(4)
        part_count = struct.unpack_from("<i", mv, pos)[0]
        pos += 4
        if part_count < 0 or part_count > 16:
            raise ValueError(f"Invalid version tuple length {part_count} at offset {pos}")
        need(part_count * 4)
        ver_tuple = struct.unpack_from(f"<{part_count}I", mv, pos)
        pos += part_count * 4

        need(1)
        has_overwrite = mv[pos]
        pos += 1
        overwrite_name: Optional[str] = None
        if has_overwrite != 0:
            overwrite_name, pos = _read_dotnet_string(mv, pos)

        need(12)
        base_addr, val_count = struct.unpack_from("<qi", mv, pos)
        pos += 12
        if val_count < 0:
            raise ValueError(f"Negative value count {val_count} at offset {pos}")

        vals_bytes_len = val_count * 12
        need(vals_bytes_len)
        vals_raw = mv[pos : pos + vals_bytes_len]
        pos += vals_bytes_len

        hash_count = 0
        hashes_raw: bytes | memoryview = b""
        if fmt_ver >= 2:
            need(4)
            hash_count = struct.unpack_from("<i", mv, pos)[0]
            pos += 4
            if hash_count < 0:
                raise ValueError(f"Negative hash count {hash_count} at offset {pos}")
            hashes_len = hash_count * 16
            need(hashes_len)
            hashes_raw = mv[pos : pos + hashes_len]
            pos += hashes_len

        versions.append(
            RelibVersion(
                version=tuple(ver_tuple),
                overwrite_module_name=overwrite_name,
                base_address=base_addr,
                val_count=val_count,
                hash_count=hash_count,
                _vals_raw=vals_raw,
                _hashes_raw=hashes_raw,
            )
        )

    return RelibDatabase(
        format_version=fmt_ver,
        high_vid=high_vid,
        pointer_size=ptr_size,
        target_module_name=target_module_name,
        versions=versions,
    )


def load_relib(path: Path = DEFAULT_RELIB_PATH) -> RelibDatabase:
    if not path.exists():
        raise FileNotFoundError(
            f".relib database not found at {path}. Run: python scripts/extract_relib.py download --with-relib"
        )
    return parse_relib_bytes(path.read_bytes())


def build_relib_bytes(
    versions: Sequence[Tuple[Tuple[int, ...], Optional[str], int, Sequence[Tuple[int, int]], Sequence[Tuple[int, int]]]],
    *,
    format_version: int = 2,
    high_vid: Optional[int] = None,
    pointer_size: int = 8,
    target_module_name: Optional[str] = "SkyrimSE.exe",
) -> bytes:
    """Serialize a `.relib` database buffer (useful for tests and round-trip verification)."""
    if format_version not in (1, 2):
        raise ValueError(f"Unsupported .relib format_version {format_version}")
    if high_vid is None:
        max_vid = 0
        for _, _, _, vals, _ in versions:
            for vid, _ in vals:
                if vid > max_vid:
                    max_vid = vid
        high_vid = max_vid

    out = bytearray()
    out.extend(
        struct.pack(
            "<iQiB",
            format_version,
            high_vid,
            pointer_size,
            1 if target_module_name is not None else 0,
        )
    )
    if target_module_name is not None:
        out.extend(_encode_dotnet_string(target_module_name))

    out.extend(struct.pack("<i", len(versions)))
    for ver_tuple, overwrite_name, base_addr, vals, hashes in versions:
        out.extend(struct.pack("<i", len(ver_tuple)))
        out.extend(struct.pack(f"<{len(ver_tuple)}I", *ver_tuple))
        out.append(1 if overwrite_name is not None else 0)
        if overwrite_name is not None:
            out.extend(_encode_dotnet_string(overwrite_name))
        out.extend(struct.pack("<qi", base_addr, len(vals)))
        for vid, rva in vals:
            out.extend(struct.pack("<QI", vid, rva))
        if format_version >= 2:
            out.extend(struct.pack("<i", len(hashes)))
            for vid, fn_hash in hashes:
                out.extend(struct.pack("<QQ", vid, fn_hash))
    return bytes(out)


def parse_rename_text(text: str) -> Tuple[Optional[int], Dict[int, str]]:
    """Parse `skyrimae.rename` contents into `(format_version, {ae_id: name})`."""
    fmt_ver: Optional[int] = None
    names: Dict[int, str] = {}
    saw_header = False

    for raw_line in text.lstrip("\ufeff").splitlines():
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        if not stripped or stripped.startswith(";") or stripped.startswith("#"):
            continue
        if not saw_header and " " not in stripped and stripped.isdigit():
            fmt_ver = int(stripped)
            saw_header = True
            continue
        saw_header = True
        sep = stripped.find(" ")
        if sep <= 0:
            continue
        vid_str = stripped[:sep]
        sym_name = stripped[sep + 1 :].strip()
        if not sym_name:
            continue
        try:
            vid = int(vid_str)
        except ValueError:
            continue
        names[vid] = sym_name
    return fmt_ver, names


def load_rename_map(path: Path = DEFAULT_RENAME_PATH) -> Dict[int, str]:
    """Load `skyrimae.rename` if present, returning `{ae_id: name}` (or `{}` if absent)."""
    if not path.exists():
        return {}
    _, names = parse_rename_text(path.read_text(encoding="utf-8-sig", errors="replace"))
    return names


def encode_format2_bin(
    version: Sequence[int],
    module_name: str,
    id_offsets: Iterable[Tuple[int, int]],
    *,
    pointer_size: int = 8,
) -> bytes:
    """Encode `(vid, rva_offset)` pairs into Address Library Format 2 `.bin` bytes.

    Matches `meh321/AddressLibraryManager` (`WriteAddressLibrary` + `WritePackedPair`).
    Header stores 4 uint32 version parts (padded with trailing zeros if < 4 parts,
    or truncated to first 4 if 5-part such as GOG 1.6.1170.0.1).
    """
    ver4 = (list(version) + [0, 0, 0, 0])[:4]
    mod_bytes = (module_name or "SkyrimSE.exe").encode("utf-8")
    items = sorted(id_offsets, key=lambda pair: pair[0])

    out = bytearray()
    out.extend(struct.pack("<5ii", 2, ver4[0], ver4[1], ver4[2], ver4[3], len(mod_bytes)))
    out.extend(mod_bytes)
    out.extend(struct.pack("<ii", pointer_size, len(items)))

    if not items:
        return bytes(out)

    pvid, poffset = items[0]
    out.append(0)
    out.extend(struct.pack("<QQ", pvid, poffset))

    sz = pointer_size if pointer_size > 0 else 1
    for orig_vid, orig_offset in items[1:]:
        vid = orig_vid
        offset = orig_offset
        poff = poffset
        high = 0
        if (offset % sz == 0) and (poff % sz == 0):
            offset //= sz
            poff //= sz
            high |= 8

        vdiff = vid - pvid
        if vid == pvid + 1:
            low = 1
        elif 0 <= vdiff <= 0xFF:
            low = 2
        elif vdiff < 0 and -vdiff <= 0xFF:
            low = 3
        elif 0 <= vdiff <= 0xFFFF:
            low = 4
        elif vdiff < 0 and -vdiff <= 0xFFFF:
            low = 5
        elif 0 <= vid <= 0xFFFF:
            low = 6
        elif 0 <= vid <= 0xFFFFFFFF:
            low = 7
        else:
            low = 0

        odiff = offset - poff
        if offset == poff + 1:
            high_bits = 1
        elif 0 <= odiff <= 0xFF:
            high_bits = 2
        elif odiff < 0 and -odiff <= 0xFF:
            high_bits = 3
        elif 0 <= odiff <= 0xFFFF:
            high_bits = 4
        elif odiff < 0 and -odiff <= 0xFFFF:
            high_bits = 5
        elif 0 <= offset <= 0xFFFF:
            high_bits = 6
        elif 0 <= offset <= 0xFFFFFFFF:
            high_bits = 7
        else:
            high_bits = 0

        high |= high_bits
        out.append(((high & 0xF) << 4) | (low & 0xF))

        if low == 0:
            out.extend(struct.pack("<Q", vid))
        elif low == 1:
            pass
        elif low == 2:
            out.append(vdiff)
        elif low == 3:
            out.append(-vdiff)
        elif low == 4:
            out.extend(struct.pack("<H", vdiff))
        elif low == 5:
            out.extend(struct.pack("<H", -vdiff))
        elif low == 6:
            out.extend(struct.pack("<H", vid))
        elif low == 7:
            out.extend(struct.pack("<I", vid))

        if high_bits == 0:
            out.extend(struct.pack("<Q", offset))
        elif high_bits == 1:
            pass
        elif high_bits == 2:
            out.append(odiff)
        elif high_bits == 3:
            out.append(-odiff)
        elif high_bits == 4:
            out.extend(struct.pack("<H", odiff))
        elif high_bits == 5:
            out.extend(struct.pack("<H", -odiff))
        elif high_bits == 6:
            out.extend(struct.pack("<H", offset))
        elif high_bits == 7:
            out.extend(struct.pack("<I", offset))

        pvid = orig_vid
        poffset = orig_offset

    return bytes(out)


def default_bin_filename(version: Sequence[int]) -> str:
    prefix = "version" if (len(version) >= 2 and version[0] == 1 and version[1] < 6) else "versionlib"
    return f"{prefix}-{version_tuple_to_dash(version)}.bin"


def extract_bins_from_relib(
    relib: RelibDatabase,
    out_dir: Path,
    *,
    versions: Optional[Sequence[str]] = None,
    overwrite: bool = False,
) -> List[Path]:
    """Extract selected (or all) versions from a `RelibDatabase` to Format 2 `.bin` files."""
    if relib.format_version not in (1, 2):
        raise ValueError(f"Unsupported .relib format {relib.format_version}")

    selected: List[RelibVersion] = []
    if versions:
        for spec in versions:
            match = relib.get_version(spec)
            if match is None:
                avail = ", ".join(v.version_dot for v in relib.versions)
                raise ValueError(f"Version {spec!r} not found in .relib (available: {avail})")
            if match not in selected:
                selected.append(match)
    else:
        selected = list(relib.versions)

    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for entry in selected:
        out_path = out_dir / default_bin_filename(entry.version)
        if out_path.exists() and not overwrite:
            print(f"[SKIP] {out_path} already exists (use --overwrite to replace)")
            continue
        mod_name = entry.overwrite_module_name or relib.target_module_name or "SkyrimSE.exe"
        payload = encode_format2_bin(
            entry.version,
            mod_name,
            entry.iter_offsets(),
            pointer_size=relib.pointer_size,
        )
        tmp_path = out_path.with_suffix(".bin.tmp")
        tmp_path.write_bytes(payload)
        os.replace(tmp_path, out_path)
        print(f"[OK] Wrote {out_path} ({entry.val_count:,} IDs, {len(payload):,} bytes)")
        written.append(out_path)
    return written


def export_relib_csv(
    relib: RelibDatabase,
    out_path: Path,
    *,
    rename_map: Optional[Dict[int, str]] = None,
    versions: Optional[Sequence[str]] = None,
) -> int:
    """Export `.relib` IDs (+ optional `.rename` symbol column) and hex RVAs to CSV."""
    selected: List[RelibVersion] = []
    if versions:
        for spec in versions:
            match = relib.get_version(spec)
            if match is None:
                avail = ", ".join(v.version_dot for v in relib.versions)
                raise ValueError(f"Version {spec!r} not found in .relib (available: {avail})")
            if match not in selected:
                selected.append(match)
    else:
        selected = list(relib.versions)

    per_ver_maps = [entry.to_id_offset_dict() for entry in selected]
    all_vids = sorted({vid for m in per_ver_maps for vid in m.keys()})
    rename = rename_map or {}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(".csv.tmp")
    header = ["ae_id", "name"] + [entry.version_dot for entry in selected]
    with tmp_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for vid in all_vids:
            row = [str(vid), rename.get(vid, "")]
            for m in per_ver_maps:
                rva = m.get(vid)
                row.append(f"0x{rva:X}" if rva is not None else "")
            writer.writerow(row)
    os.replace(tmp_path, out_path)
    return len(all_vids)


def download_meh321_files(
    *,
    include_relib: bool = False,
    force: bool = False,
    rename_path: Path = DEFAULT_RENAME_PATH,
    relib_path: Path = DEFAULT_RELIB_PATH,
) -> None:
    """Download `skyrimae.rename` (and optionally `skyrimae.relib`) from meh321/AddressLibraryDatabase."""
    targets: List[Tuple[str, Path, str]] = [(RENAME_URL, rename_path, "skyrimae.rename")]
    if include_relib:
        targets.append((RELIB_URL, relib_path, "skyrimae.relib"))

    for url, dest, label in targets:
        if dest.exists() and dest.stat().st_size > 0 and not force:
            print(f"[SKIP] {label} already exists at {dest} ({dest.stat().st_size:,} bytes)")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")
        print(f"Downloading {label} from {url} ...")
        req = urllib.request.Request(url, headers={"User-Agent": "AI-SPUE/1.0"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            if getattr(resp, "status", 200) not in (200, None):
                raise RuntimeError(f"HTTP {resp.status} downloading {url}")
            with tmp.open("wb") as out_f:
                while True:
                    chunk = resp.read(1024 * 256)
                    if not chunk:
                        break
                    out_f.write(chunk)
        if tmp.stat().st_size == 0:
            tmp.unlink(missing_ok=True)
            raise RuntimeError(f"Downloaded empty file from {url}")
        os.replace(tmp, dest)
        print(f"[OK] Saved {label} to {dest} ({dest.stat().st_size:,} bytes)")


def cmd_info(args: argparse.Namespace) -> int:
    relib_path = Path(args.relib)
    rename_path = Path(args.rename)

    summary: Dict[str, object] = {
        "relib_path": str(relib_path),
        "relib_exists": relib_path.exists(),
        "rename_path": str(rename_path),
        "rename_exists": rename_path.exists(),
    }

    rename_count = 0
    if rename_path.exists():
        fmt_v, rename_map = parse_rename_text(rename_path.read_text(encoding="utf-8-sig", errors="replace"))
        rename_count = len(rename_map)
        summary["rename_format"] = fmt_v
        summary["rename_count"] = rename_count

    if relib_path.exists():
        db = load_relib(relib_path)
        summary["format_version"] = db.format_version
        summary["high_vid"] = db.high_vid
        summary["pointer_size"] = db.pointer_size
        summary["target_module_name"] = db.target_module_name
        summary["versions"] = [
            {
                "version": v.version_dot,
                "version_dash": v.version_dash,
                "overwrite_module_name": v.overwrite_module_name,
                "base_address": f"0x{v.base_address:X}",
                "val_count": v.val_count,
                "hash_count": v.hash_count,
            }
            for v in db.versions
        ]

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    print(f"Rename file : {rename_path} ({'present' if rename_path.exists() else 'missing'}, {rename_count:,} AE symbols)")
    if not relib_path.exists():
        print(f"Relib file  : {relib_path} (missing — optional; run `download --with-relib` if historical 1.6.x .bin/.csv extraction is needed)")
        return 0

    print(f"Relib file  : {relib_path}")
    print(f"Format      : v{summary['format_version']}, high_vid={summary['high_vid']:,}, ptr_size={summary['pointer_size']}, module={summary['target_module_name']}")
    print("Contained versions:")
    for v in summary["versions"]:  # type: ignore[index]
        ov = f" ({v['overwrite_module_name']})" if v["overwrite_module_name"] else ""
        print(f"  - {v['version']:<14} ids={v['val_count']:>7,}  hashes={v['hash_count']:>7,}  base={v['base_address']}{ov}")
    return 0


def cmd_extract_bins(args: argparse.Namespace) -> int:
    db = load_relib(Path(args.relib))
    out_dir = Path(args.out_dir)
    versions = args.versions if args.versions else None
    written = extract_bins_from_relib(db, out_dir, versions=versions, overwrite=args.overwrite)
    print(f"Done. Extracted {len(written)} .bin file(s) into {out_dir}")
    return 0


def cmd_extract_csv(args: argparse.Namespace) -> int:
    db = load_relib(Path(args.relib))
    rename_map = load_rename_map(Path(args.rename))
    versions = args.versions if args.versions else None
    count = export_relib_csv(db, Path(args.output), rename_map=rename_map, versions=versions)
    print(f"[OK] Exported {count:,} AE ID rows to {args.output}")
    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    query = args.query.strip()
    rename_map = load_rename_map(Path(args.rename))
    relib_path = Path(args.relib)
    db = load_relib(relib_path) if relib_path.exists() else None
    se_to_ae, ae_to_se, se_to_sym, ae_split = skse_env.load_id_maps()

    # Case 1: Hex RVA lookup (e.g. 0x62C870)
    if query.lower().startswith("0x"):
        if db is None:
            print("ERROR: Hex RVA lookup requires --relib (skyrimae.relib not present).", file=sys.stderr)
            return 1
        target_rva = int(query, 16)
        ver_entries = [db.get_version(args.version)] if args.version else db.versions
        hits = 0
        for entry in ver_entries:
            if entry is None:
                continue
            for vid, rva in entry.iter_offsets():
                if rva == target_rva:
                    hits += 1
                    sym = rename_map.get(vid, "")
                    se_id = ae_to_se.get(vid)
                    print(f"[{entry.version_dot}] RVA 0x{rva:X} -> AE {vid} (SE={se_id or '-'}) {sym}")
        if not hits:
            print(f"No matches for RVA 0x{target_rva:X}")
        return 0 if hits else 1

    # Case 2: Numeric AE ID lookup
    if query.isdigit():
        ae_id = int(query)
        se_id = ae_to_se.get(ae_id)
        sym = rename_map.get(ae_id) or (se_to_sym.get(se_id, "") if se_id else "")
        split_id = ae_split.get(ae_id)
        print(f"AE ID  : {ae_id}" + (f" (1.6.1130+/1.7.99+ split -> {split_id})" if split_id else ""))
        print(f"SE ID  : {se_id if se_id is not None else '-'}")
        print(f"Symbol : {sym or '-'}")
        if db is not None:
            ver_entries = [db.get_version(args.version)] if args.version else db.versions
            print("Offsets in .relib:")
            for entry in ver_entries:
                if entry is None:
                    continue
                rva = entry.lookup_id(ae_id)
                rva_str = f"0x{rva:07X}" if rva is not None else "-"
                print(f"  {entry.version_dot:<14} {rva_str}")
        return 0

    # Case 3: Substring symbol search against skyrimae.rename (plus SE CSV comments)
    needle = query.lower()
    matches: List[Tuple[int, str]] = []
    for vid, name in rename_map.items():
        if needle in name.lower():
            matches.append((vid, name))
    for se_id, note in se_to_sym.items():
        if needle in note.lower():
            ae_id = se_to_ae.get(se_id)
            if ae_id and ae_id not in {m[0] for m in matches}:
                matches.append((ae_id, note))

    matches.sort(key=lambda x: x[0])
    if not matches:
        print(f"No symbol matches for {query!r}")
        return 1

    limit = args.limit
    print(f"Found {len(matches)} symbol match(es) for {query!r}" + (f" (showing first {limit})" if len(matches) > limit else "") + ":")
    target_ver = db.get_version(args.version) if (db and args.version) else (db.versions[-1] if db and db.versions else None)
    ver_map = target_ver.to_id_offset_dict() if target_ver else {}
    for ae_id, name in matches[:limit]:
        se_id = ae_to_se.get(ae_id)
        rva = ver_map.get(ae_id)
        rva_part = f" [{target_ver.version_dot}=0x{rva:X}]" if (target_ver and rva is not None) else ""
        print(f"  AE {ae_id:<7} (SE {str(se_id or '-'):<7}){rva_part} {name}")
    return 0


def cmd_download(args: argparse.Namespace) -> int:
    download_meh321_files(
        include_relib=args.with_relib or args.all,
        force=args.force,
        rename_path=Path(args.rename),
        relib_path=Path(args.relib),
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect and extract meh321 AddressLibraryDatabase (.relib / .rename)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="Show .relib versions and .rename symbol count")
    p_info.add_argument("--relib", default=str(DEFAULT_RELIB_PATH), help="Path to skyrimae.relib")
    p_info.add_argument("--rename", default=str(DEFAULT_RENAME_PATH), help="Path to skyrimae.rename")
    p_info.add_argument("--json", action="store_true", help="Print JSON summary")
    p_info.set_defaults(func=cmd_info)

    p_bins = sub.add_parser("extract-bins", help="Extract Format 2 versionlib-*.bin files from .relib")
    p_bins.add_argument("--relib", default=str(DEFAULT_RELIB_PATH), help="Path to skyrimae.relib")
    p_bins.add_argument("--out-dir", default=str(skse_env.BIN_DIR), help="Output directory (default: sdk/address_tables/bin)")
    p_bins.add_argument("--versions", nargs="*", help="Specific versions to extract (e.g. 1.6.1170.0 1.6.640.0)")
    p_bins.add_argument("--overwrite", action="store_true", help="Overwrite existing .bin files")
    p_bins.set_defaults(func=cmd_extract_bins)

    p_csv = sub.add_parser("extract-csv", help="Export AE ID -> hex RVA table from .relib (+ .rename symbols)")
    p_csv.add_argument("--relib", default=str(DEFAULT_RELIB_PATH), help="Path to skyrimae.relib")
    p_csv.add_argument("--rename", default=str(DEFAULT_RENAME_PATH), help="Path to skyrimae.rename")
    p_csv.add_argument("-o", "--output", required=True, help="Output CSV path")
    p_csv.add_argument("--versions", nargs="*", help="Subset of versions to include")
    p_csv.set_defaults(func=cmd_extract_csv)

    p_lookup = sub.add_parser("lookup", help="Look up AE ID, symbol substring, or 0xRVA in .relib/.rename")
    p_lookup.add_argument("query", help="AE ID (int), hex RVA (0x...), or symbol substring")
    p_lookup.add_argument("--relib", default=str(DEFAULT_RELIB_PATH), help="Path to skyrimae.relib")
    p_lookup.add_argument("--rename", default=str(DEFAULT_RENAME_PATH), help="Path to skyrimae.rename")
    p_lookup.add_argument("--version", help="Filter or display offsets for a specific game version")
    p_lookup.add_argument("--limit", type=int, default=40, help="Max symbol search results (default: 40)")
    p_lookup.set_defaults(func=cmd_lookup)

    p_dl = sub.add_parser("download", help="Download skyrimae.rename (and optionally skyrimae.relib) from meh321/AddressLibraryDatabase")
    p_dl.add_argument("--with-relib", action="store_true", help="Also download skyrimae.relib (~74 MB)")
    p_dl.add_argument("--all", action="store_true", help="Alias for --with-relib")
    p_dl.add_argument("--force", action="store_true", help="Re-download even if files already exist")
    p_dl.add_argument("--relib", default=str(DEFAULT_RELIB_PATH), help="Destination path for skyrimae.relib")
    p_dl.add_argument("--rename", default=str(DEFAULT_RENAME_PATH), help="Destination path for skyrimae.rename")
    p_dl.set_defaults(func=cmd_download)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
