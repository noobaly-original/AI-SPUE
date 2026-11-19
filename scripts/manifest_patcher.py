#!/usr/bin/env python3
"""
Manifest-Driven PE64 Binary Patch Engine & Checksum Fixer (scripts/manifest_patcher.py)

Deterministic, safety-verified patch engine driven by a per-plugin `patches.json` manifest:
  - Verifies input SHA-256 hash and expected original bytes (with `??` wildcards) before patching.
  - Supports symbolic `{{rel32:<target>[+/-offset][,next=<k>]}}` expression expansion.
  - Allocates code caves and E9 trampolines either in `.text` alignment padding or by appending
    a new executable PE64 section (`.patch`), adjusting `NumberOfSections` and `SizeOfImage`.
  - Refuses patches that overlap ASLR `.reloc` entries unless `allow_reloc_overlap: true`.
  - Applies `SKSEPlugin_Version` metadata updates (`versionIndependence*`, `compatibleVersions`).
  - Recalculates and writes the exact Windows PE Header `CheckSum`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import pe_inspect  # noqa: E402
import skse_env  # noqa: E402
import verify_dll  # noqa: E402

_EXPR_TOKEN_RE = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")
_SYM_OFFSET_RE = re.compile(r"^(.+?)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)$")

_FLAG_IND = {
    "addresslibrarypostae": verify_dll.kVersionIndependent_AddressLibraryPostAE,
    "kversionindependent_addresslibrarypostae": verify_dll.kVersionIndependent_AddressLibraryPostAE,
    "signatures": verify_dll.kVersionIndependent_Signatures,
    "kversionindependent_signatures": verify_dll.kVersionIndependent_Signatures,
    "structspost629": verify_dll.kVersionIndependent_StructsPost629,
    "kversionindependent_structspost629": verify_dll.kVersionIndependent_StructsPost629,
}

_FLAG_IND_EX = {
    "nostructuse": verify_dll.kVersionIndependentEx_NoStructUse,
    "kversionindependentex_nostructuse": verify_dll.kVersionIndependentEx_NoStructUse,
    "addresslibraryv5": verify_dll.kVersionIndependentEx_AddressLibraryV5,
    "kversionindependentex_addresslibraryv5": verify_dll.kVersionIndependentEx_AddressLibraryV5,
}


class ManifestError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()


def _align_up(val: int, align: int) -> int:
    if align <= 1:
        return val
    return (val + align - 1) & ~(align - 1)


def _parse_version_str(ver: str) -> int:
    vt = skse_env.parse_version_tuple(ver)
    return verify_dll.pack_skse_version(*vt)


def _resolve_flag_mask(items: Any, mapping: Dict[str, int]) -> int:
    if items is None:
        return 0
    if isinstance(items, int):
        return items
    if isinstance(items, str):
        items = [items]
    mask = 0
    for item in items:
        if isinstance(item, int):
            mask |= item
        elif isinstance(item, str):
            key = item.strip().lower()
            if key in mapping:
                mask |= mapping[key]
            else:
                try:
                    mask |= int(item.strip(), 0)
                except ValueError as exc:
                    raise ManifestError(f"Unknown SKSE flag {item!r}") from exc
        else:
            raise ManifestError(f"Invalid flag entry: {item!r}")
    return mask


def _parse_expected_tokens(expected_hex: str) -> List[Optional[int]]:
    cleaned = expected_hex.strip()
    if not cleaned:
        raise ManifestError("Empty expected_hex string")
    tokens = re.split(r"[\s,]+", cleaned)
    if len(tokens) == 1 and len(tokens[0]) > 2:
        s = tokens[0]
        if len(s) % 2 != 0:
            raise ManifestError(f"Odd-length compact expected_hex: {expected_hex!r}")
        tokens = [s[i : i + 2] for i in range(0, len(s), 2)]

    out: List[Optional[int]] = []
    for tok in tokens:
        t = tok.strip()
        if not t:
            continue
        if t.lower().startswith("0x"):
            t = t[2:]
        if t in ("?", "??"):
            out.append(None)
        elif len(t) == 2 and all(c in "0123456789abcdefABCDEF" for c in t):
            out.append(int(t, 16))
        else:
            raise ManifestError(f"Invalid hex token {tok!r} in expected_hex")
    return out


def _verify_expected_bytes(data: bytes, file_offset: int, expected_hex: str, label: str) -> None:
    tokens = _parse_expected_tokens(expected_hex)
    if file_offset < 0 or file_offset + len(tokens) > len(data):
        raise ManifestError(f"{label}: expected range [0x{file_offset:X}..0x{file_offset + len(tokens):X}) out of bounds")
    for idx, exp in enumerate(tokens):
        if exp is not None and data[file_offset + idx] != exp:
            actual = data[file_offset : file_offset + len(tokens)].hex(" ").upper()
            raise ManifestError(
                f"{label}: expected_hex mismatch at +0x{idx:X} (file offset 0x{file_offset + idx:X}): "
                f"expected 0x{exp:02X}, found 0x{data[file_offset + idx]:02X}. Actual slice: {actual}"
            )


def _tokenize_hex_expr(expr: str) -> List[Tuple[str, Any]]:
    """Split `hex_bytes` / `patch_hex` into concrete byte chunks and `rel32` placeholder items."""
    items: List[Tuple[str, Any]] = []
    pos = 0
    for m in _EXPR_TOKEN_RE.finditer(expr):
        lit = expr[pos : m.start()]
        if lit.strip():
            items.append(("bytes", _parse_concrete_hex(lit)))
        items.append(("expr", m.group(1).strip()))
        pos = m.end()
    tail = expr[pos:]
    if tail.strip():
        items.append(("bytes", _parse_concrete_hex(tail)))
    return items


def _parse_concrete_hex(text: str) -> bytes:
    tokens = re.split(r"[\s,]+", text.strip())
    if len(tokens) == 1 and len(tokens[0]) > 2:
        s = tokens[0]
        if len(s) % 2 != 0:
            raise ManifestError(f"Odd-length hex string: {text!r}")
        tokens = [s[i : i + 2] for i in range(0, len(s), 2)]
    out = bytearray()
    for tok in tokens:
        t = tok.strip()
        if not t:
            continue
        if t.lower().startswith("0x"):
            t = t[2:]
        if len(t) != 2 or not all(c in "0123456789abcdefABCDEF" for c in t):
            raise ManifestError(f"Invalid concrete hex byte {tok!r} in {text!r}")
        out.append(int(t, 16))
    return bytes(out)


def _measure_hex_expr(expr: str) -> int:
    total = 0
    for kind, val in _tokenize_hex_expr(expr):
        if kind == "bytes":
            total += len(val)
        elif kind == "expr":
            if not val.lower().startswith("rel32:"):
                raise ManifestError(f"Unsupported expression {{{{{val}}}}}")
            total += 4
    return total


def _resolve_target_expr(target_str: str, symbols: Dict[str, int]) -> int:
    s = target_str.strip()
    m = _SYM_OFFSET_RE.match(s)
    delta = 0
    base_str = s
    if m:
        base_str = m.group(1).strip()
        sign = 1 if m.group(2) == "+" else -1
        delta = sign * int(m.group(3), 0)

    if base_str in symbols:
        return symbols[base_str] + delta
    try:
        return pe_inspect.parse_hex_or_int(base_str) + delta
    except ValueError as exc:
        raise ManifestError(f"Unknown symbol or invalid RVA {base_str!r} in expression {target_str!r}") from exc


def _compile_hex_expr(expr: str, base_rva: int, symbols: Dict[str, int]) -> bytes:
    out = bytearray()
    for kind, val in _tokenize_hex_expr(expr):
        if kind == "bytes":
            out.extend(val)
        elif kind == "expr":
            if not val.lower().startswith("rel32:"):
                raise ManifestError(f"Unsupported expression {{{{{val}}}}}")
            body = val[6:].strip()
            parts = [p.strip() for p in body.split(",") if p.strip()]
            target_part = parts[0]
            next_bytes = 0
            for opt in parts[1:]:
                if opt.lower().startswith("next="):
                    next_bytes = int(opt[5:].strip(), 0)
                else:
                    raise ManifestError(f"Unknown rel32 option {opt!r} in {{{{{val}}}}}")
            target_rva = _resolve_target_expr(target_part, symbols)
            cur_rva = base_rva + len(out)
            disp = target_rva - (cur_rva + 4 + next_bytes)
            if disp < -0x80000000 or disp > 0x7FFFFFFF:
                raise ManifestError(
                    f"rel32 displacement out of 32-bit range for {{{{{val}}}}}: "
                    f"target=0x{target_rva:X}, cur=0x{cur_rva:X}, disp={disp}"
                )
            out.extend(struct.pack("<i", disp))
    return bytes(out)


def _resolve_addr_entry(
    entry: Dict[str, Any],
    pe_info: Dict[str, Any],
    symbols: Dict[str, int],
    label: str,
) -> Tuple[Optional[int], int]:
    """Return `(rva_or_None, file_offset)` for a patch or trampoline entry."""
    sections = pe_info["sections"]
    if "rva" in entry and entry["rva"] is not None:
        raw_val = entry["rva"]
        rva = raw_val if isinstance(raw_val, int) else _resolve_target_expr(str(raw_val), symbols)
        off = pe_inspect.rva_to_file_offset(rva, sections)
        if off is None:
            raise ManifestError(f"{label}: RVA 0x{rva:X} does not map to raw file bytes")
        return rva, off
    if "file_offset" in entry and entry["file_offset"] is not None:
        raw_val = entry["file_offset"]
        off = raw_val if isinstance(raw_val, int) else pe_inspect.parse_hex_or_int(str(raw_val))
        rva = pe_inspect.file_offset_to_rva(off, sections)
        return rva, off
    raise ManifestError(f"{label}: must specify 'rva' or 'file_offset'")


def _plan_manifest(
    orig_data: bytes,
    manifest: Dict[str, Any],
    ignore_hash: bool = False,
) -> Dict[str, Any]:
    if manifest.get("schema_version") != 1:
        raise ManifestError(f"Unsupported manifest schema_version: {manifest.get('schema_version')!r} (expected 1)")

    actual_sha = sha256_bytes(orig_data)
    expected_sha = (manifest.get("input_sha256") or "").strip().lower()
    if expected_sha and expected_sha != actual_sha and not ignore_hash:
        raise ManifestError(
            f"Input SHA-256 mismatch: expected {expected_sha}, got {actual_sha} (pass --ignore-hash to override)"
        )

    pe_info = pe_inspect.parse_pe64(orig_data)
    sections = pe_info["sections"]
    relocations = pe_info["relocations"]

    symbols: Dict[str, int] = {}
    for sym_name, sym_val in (manifest.get("symbols") or {}).items():
        symbols[sym_name] = sym_val if isinstance(sym_val, int) else pe_inspect.parse_hex_or_int(str(sym_val))

    # Locate primary executable section (.text or first executable section) for trailing padding caves
    text_sec_idx: Optional[int] = None
    for idx, sec in enumerate(sections):
        if sec["name"] == ".text" and sec["is_executable"]:
            text_sec_idx = idx
            break
    if text_sec_idx is None:
        for idx, sec in enumerate(sections):
            if sec["is_executable"]:
                text_sec_idx = idx
                break

    text_cave_rva_base = sections[text_sec_idx]["cave_rva"] if text_sec_idx is not None else None
    text_cave_off_base = sections[text_sec_idx]["cave_file_offset"] if text_sec_idx is not None else None
    text_cave_avail = sections[text_sec_idx]["cave_avail_bytes"] if text_sec_idx is not None else 0
    text_cave_cursor = 0

    cave_specs: List[Dict[str, Any]] = []
    seen_cave_names = set()

    for idx, cave in enumerate(manifest.get("code_caves") or []):
        name = cave.get("name") or f"cave_{idx}"
        if name in seen_cave_names or name in symbols:
            raise ManifestError(f"Duplicate cave/symbol name: {name!r}")
        seen_cave_names.add(name)
        expr = cave["hex_bytes"]
        byte_len = _measure_hex_expr(expr)
        cave_specs.append(
            {
                "kind": "code_cave",
                "name": name,
                "placement": cave.get("placement", "auto"),
                "expr": expr,
                "byte_len": byte_len,
                "description": cave.get("description", ""),
            }
        )

    trampoline_specs: List[Dict[str, Any]] = []
    for idx, tramp in enumerate(manifest.get("trampolines") or []):
        name = tramp.get("name") or f"trampoline_{idx}"
        if name in seen_cave_names or name in symbols:
            raise ManifestError(f"Duplicate trampoline/symbol name: {name!r}")
        seen_cave_names.add(name)

        raw_hrva = tramp["hook_rva"]
        hook_rva = raw_hrva if isinstance(raw_hrva, int) else _resolve_target_expr(str(raw_hrva), symbols)
        hook_off = pe_inspect.rva_to_file_offset(hook_rva, sections)
        if hook_off is None:
            raise ManifestError(f"Trampoline {name!r}: hook_rva 0x{hook_rva:X} does not map to file bytes")

        stolen_len = int(tramp["stolen_len"])
        if stolen_len < 5:
            raise ManifestError(f"Trampoline {name!r}: stolen_len must be >= 5 (got {stolen_len})")

        expected_hex = tramp.get("expected_hex")
        if expected_hex:
            exp_tokens = _parse_expected_tokens(expected_hex)
            if len(exp_tokens) != stolen_len:
                raise ManifestError(
                    f"Trampoline {name!r}: expected_hex has {len(exp_tokens)} bytes, expected stolen_len={stolen_len}"
                )
            _verify_expected_bytes(orig_data, hook_off, expected_hex, f"Trampoline {name!r}")

        if not tramp.get("allow_reloc_overlap", False):
            overlaps = pe_inspect.check_reloc_overlaps(hook_rva, stolen_len, relocations)
            if overlaps:
                locs = ", ".join(f"0x{o['rva']:X} ({o['type_name']})" for o in overlaps)
                raise ManifestError(
                    f"Trampoline {name!r} at RVA 0x{hook_rva:X} ({stolen_len}B) overlaps ASLR .reloc entries: {locs}"
                )

        expr = tramp["cave_prefix_hex"]
        if tramp.get("append_return_jmp", True):
            expr = f"{expr} E9 {{{{rel32:0x{hook_rva + stolen_len:X}}}}}"
        byte_len = _measure_hex_expr(expr)

        cave_specs.append(
            {
                "kind": "trampoline",
                "name": name,
                "placement": tramp.get("placement", "auto"),
                "expr": expr,
                "byte_len": byte_len,
                "description": tramp.get("description", ""),
            }
        )
        trampoline_specs.append(
            {
                "name": name,
                "hook_rva": hook_rva,
                "hook_off": hook_off,
                "stolen_len": stolen_len,
            }
        )

    # Pass 1: assign cave placements
    new_sec_cursor = 0
    new_sec_caves: List[Dict[str, Any]] = []
    text_pad_caves: List[Dict[str, Any]] = []

    for spec in cave_specs:
        placement = spec["placement"]
        blen = spec["byte_len"]
        if placement not in ("auto", "text_padding", "new_section"):
            raise ManifestError(f"Cave {spec['name']!r}: unknown placement {placement!r}")

        placed_in_text = False
        if placement in ("auto", "text_padding") and text_cave_rva_base is not None and text_cave_off_base is not None:
            aligned_pos = _align_up(text_cave_cursor, 16)
            if aligned_pos + blen <= text_cave_avail:
                spec["resolved_placement"] = "text_padding"
                spec["rva"] = text_cave_rva_base + aligned_pos
                spec["file_offset"] = text_cave_off_base + aligned_pos
                text_cave_cursor = aligned_pos + blen
                text_pad_caves.append(spec)
                placed_in_text = True
            elif placement == "text_padding":
                raise ManifestError(
                    f"Cave {spec['name']!r} ({blen}B) does not fit in .text padding "
                    f"(remaining {max(0, text_cave_avail - aligned_pos)}B)"
                )

        if not placed_in_text:
            aligned_ns = _align_up(new_sec_cursor, 16)
            spec["resolved_placement"] = "new_section"
            spec["new_sec_rel_off"] = aligned_ns
            new_sec_cursor = aligned_ns + blen
            new_sec_caves.append(spec)

    new_section_plan: Optional[Dict[str, Any]] = None
    if new_sec_caves:
        patch_sec_name = str(manifest.get("patch_section_name", ".patch"))
        if not patch_sec_name or len(patch_sec_name.encode("ascii")) > 8:
            raise ManifestError(f"Invalid patch_section_name (must be 1..8 ASCII chars): {patch_sec_name!r}")

        first_raw_ptr = min((s["raw_ptr"] for s in sections if s["raw_ptr"] > 0), default=pe_info["size_of_headers"])
        needed_hdr_end = pe_info["sec_table_offset"] + (pe_info["num_sections"] + 1) * 40
        if needed_hdr_end > min(first_raw_ptr, pe_info["size_of_headers"]):
            raise ManifestError(
                f"PE headers have insufficient room for a new section header "
                f"(need offset 0x{needed_hdr_end:X}, limit 0x{min(first_raw_ptr, pe_info['size_of_headers']):X})"
            )

        max_va_end = max(s["virtual_addr"] + max(s["virtual_size"], s["raw_size"]) for s in sections)
        sec_va = _align_up(max_va_end, pe_info["section_alignment"])
        sec_raw_ptr = _align_up(len(orig_data), pe_info["file_alignment"])
        sec_vsize = new_sec_cursor
        sec_rsize = _align_up(max(1, sec_vsize), pe_info["file_alignment"])
        new_size_of_image = _align_up(sec_va + max(sec_vsize, sec_rsize), pe_info["section_alignment"])

        for spec in new_sec_caves:
            spec["rva"] = sec_va + spec["new_sec_rel_off"]
            spec["file_offset"] = sec_raw_ptr + spec["new_sec_rel_off"]

        new_section_plan = {
            "name": patch_sec_name,
            "virtual_addr": sec_va,
            "virtual_size": sec_vsize,
            "raw_ptr": sec_raw_ptr,
            "raw_size": sec_rsize,
            "characteristics": 0x60000020,  # CNT_CODE | MEM_EXECUTE | MEM_READ
            "new_size_of_image": new_size_of_image,
            "header_offset": pe_info["sec_table_offset"] + pe_info["num_sections"] * 40,
        }

    for spec in cave_specs:
        symbols[spec["name"]] = int(spec["rva"])

    # Validate direct patches against original bytes and .reloc
    patch_plans: List[Dict[str, Any]] = []
    for idx, p in enumerate(manifest.get("patches") or []):
        label = p.get("description") or f"Patch #{idx}"
        rva, off = _resolve_addr_entry(p, pe_info, symbols, label)
        compiled = _compile_hex_expr(p["patch_hex"], rva if rva is not None else 0, symbols)
        expected_hex = p.get("expected_hex")
        if expected_hex:
            exp_tokens = _parse_expected_tokens(expected_hex)
            if len(exp_tokens) != len(compiled):
                raise ManifestError(
                    f"{label}: expected_hex length ({len(exp_tokens)}B) != patch_hex length ({len(compiled)}B)"
                )
            _verify_expected_bytes(orig_data, off, expected_hex, label)

        if rva is not None and not p.get("allow_reloc_overlap", False):
            overlaps = pe_inspect.check_reloc_overlaps(rva, len(compiled), relocations)
            if overlaps:
                locs = ", ".join(f"0x{o['rva']:X} ({o['type_name']})" for o in overlaps)
                raise ManifestError(f"{label} at RVA 0x{rva:X} ({len(compiled)}B) overlaps ASLR .reloc entries: {locs}")

        patch_plans.append(
            {
                "label": label,
                "rva": rva,
                "file_offset": off,
                "bytes": compiled,
            }
        )

    # Compile Pass 2 cave & trampoline bytes
    for spec in cave_specs:
        spec["bytes"] = _compile_hex_expr(spec["expr"], int(spec["rva"]), symbols)

    for tr in trampoline_specs:
        jmp_bytes = _compile_hex_expr(f"E9 {{{{rel32:{tr['name']}}}}}", tr["hook_rva"], symbols)
        nop_len = tr["stolen_len"] - 5
        tr["hook_bytes"] = jmp_bytes + (b"\x90" * nop_len)

    # Plan SKSEPlugin_Version metadata patch
    meta_plan: Optional[Dict[str, Any]] = None
    meta_cfg = manifest.get("metadata_patches")
    if meta_cfg:
        ver_data = pe_inspect.decode_skse_version_data(orig_data, pe_info)
        if ver_data is None:
            raise ManifestError("metadata_patches specified, but input DLL does not export SKSEPlugin_Version")
        ver_off = ver_data["file_offset"]
        cur_ex = ver_data["versionIndependenceEx"]
        cur_ind = ver_data["versionIndependence"]
        cur_compat = list(ver_data["compatibleVersions_raw"])
        cur_se_req = struct.unpack_from("<I", orig_data, ver_off + 0x34C)[0]

        new_ex = (cur_ex & ~_resolve_flag_mask(meta_cfg.get("clear_version_independence_ex"), _FLAG_IND_EX)) | _resolve_flag_mask(
            meta_cfg.get("set_version_independence_ex"), _FLAG_IND_EX
        )
        new_ind = (cur_ind & ~_resolve_flag_mask(meta_cfg.get("clear_version_independence"), _FLAG_IND)) | _resolve_flag_mask(
            meta_cfg.get("set_version_independence"), _FLAG_IND
        )

        new_compat = list(cur_compat)
        if "compatible_versions_replace" in meta_cfg and meta_cfg["compatible_versions_replace"] is not None:
            rep_vers = [_parse_version_str(v) for v in meta_cfg["compatible_versions_replace"]]
            if len(rep_vers) > 16:
                raise ManifestError("compatible_versions_replace exceeds 16 slots")
            new_compat = rep_vers + [0] * (16 - len(rep_vers))
        for vs in meta_cfg.get("compatible_versions_add") or []:
            packed = _parse_version_str(vs)
            if packed not in new_compat:
                try:
                    slot = new_compat.index(0)
                    new_compat[slot] = packed
                except ValueError as exc:
                    raise ManifestError(f"compatibleVersions[16] is full; cannot add {vs}") from exc

        new_se_req = cur_se_req
        if "se_version_required" in meta_cfg and meta_cfg["se_version_required"] is not None:
            raw_se = meta_cfg["se_version_required"]
            new_se_req = raw_se if isinstance(raw_se, int) else _parse_version_str(str(raw_se))

        meta_plan = {
            "ver_off": ver_off,
            "old_ex": cur_ex,
            "new_ex": new_ex,
            "old_ind": cur_ind,
            "new_ind": new_ind,
            "old_compat": cur_compat,
            "new_compat": new_compat,
            "old_se_req": cur_se_req,
            "new_se_req": new_se_req,
        }

    return {
        "pe_info": pe_info,
        "text_sec_idx": text_sec_idx,
        "text_pad_caves": text_pad_caves,
        "new_section_plan": new_section_plan,
        "cave_specs": cave_specs,
        "trampoline_specs": trampoline_specs,
        "patch_plans": patch_plans,
        "meta_plan": meta_plan,
        "symbols": symbols,
    }


def apply_manifest_bytes(orig_data: bytes, manifest: Dict[str, Any], ignore_hash: bool = False) -> Tuple[bytearray, Dict[str, Any]]:
    plan = _plan_manifest(orig_data, manifest, ignore_hash=ignore_hash)
    pe_info = plan["pe_info"]
    raw = bytearray(orig_data)

    # 1. Append new .patch section if planned
    ns = plan["new_section_plan"]
    if ns is not None:
        if len(raw) < ns["raw_ptr"]:
            raw.extend(b"\x00" * (ns["raw_ptr"] - len(raw)))
        raw.extend(b"\xCC" * ns["raw_size"])

        hdr_off = ns["header_offset"]
        name_bytes = ns["name"].encode("ascii").ljust(8, b"\x00")[:8]
        raw[hdr_off : hdr_off + 8] = name_bytes
        struct.pack_into(
            "<IIIIIIHHI",
            raw,
            hdr_off + 8,
            ns["virtual_size"],
            ns["virtual_addr"],
            ns["raw_size"],
            ns["raw_ptr"],
            0,
            0,
            0,
            0,
            ns["characteristics"],
        )
        struct.pack_into("<H", raw, pe_info["e_lfanew"] + 6, pe_info["num_sections"] + 1)
        struct.pack_into("<I", raw, pe_info["opt_offset"] + 56, ns["new_size_of_image"])

    # 2. Extend .text VirtualSize if trailing padding caves were written
    if plan["text_pad_caves"] and plan["text_sec_idx"] is not None:
        sec_idx = plan["text_sec_idx"]
        tsec = pe_info["sections"][sec_idx]
        max_end_rva = max(int(c["rva"]) + len(c["bytes"]) for c in plan["text_pad_caves"])
        needed_vsize = min(tsec["raw_size"], max_end_rva - tsec["virtual_addr"])
        if needed_vsize > tsec["virtual_size"]:
            vsize_off = pe_info["sec_table_offset"] + sec_idx * 40 + 8
            struct.pack_into("<I", raw, vsize_off, needed_vsize)

    # 3. Write caves, trampolines, direct patches, and SKSE metadata
    for cave in plan["cave_specs"]:
        off = int(cave["file_offset"])
        raw[off : off + len(cave["bytes"])] = cave["bytes"]

    for tr in plan["trampoline_specs"]:
        off = tr["hook_off"]
        raw[off : off + len(tr["hook_bytes"])] = tr["hook_bytes"]

    for p in plan["patch_plans"]:
        off = p["file_offset"]
        raw[off : off + len(p["bytes"])] = p["bytes"]

    mp = plan["meta_plan"]
    if mp is not None:
        voff = mp["ver_off"]
        struct.pack_into("<II", raw, voff + 0x304, mp["new_ex"], mp["new_ind"])
        struct.pack_into("<16I", raw, voff + 0x30C, *mp["new_compat"])
        struct.pack_into("<I", raw, voff + 0x34C, mp["new_se_req"])

    # 4. Recalculate PE Header CheckSum
    cs_off = pe_info["checksum_offset"]
    checksum = pe_inspect.calculate_pe_checksum(bytes(raw), cs_off)
    struct.pack_into("<I", raw, cs_off, checksum)
    plan["computed_checksum"] = checksum
    return raw, plan


def generate_init_manifest(dll_path: Path, target_runtime: Optional[str] = None) -> Dict[str, Any]:
    dll_path = dll_path.resolve()
    data = dll_path.read_bytes()
    pe_info = pe_inspect.parse_pe64(data)
    explicit_target = (
        None
        if (target_runtime is None or str(target_runtime).strip().lower() in ("", "auto"))
        else str(target_runtime).strip()
    )
    if explicit_target is None:
        env_info = skse_env.detect_target_environment()
        target_dot = env_info["target_version_dot"]
        target_source = env_info["target_source"]
    else:
        target_tuple = skse_env.parse_version_tuple(explicit_target)
        target_dot = skse_env.format_version_dot(target_tuple)
        target_source = "cli:--target"

    ver_data = pe_inspect.decode_skse_version_data(data, pe_info, target_runtime=target_dot)
    fp = pe_inspect.fingerprint_skse_binary(data, pe_info, version_data=ver_data)

    plugin_name = ver_data["name"] if ver_data and ver_data["name"] else dll_path.stem

    patches: List[Dict[str, Any]] = []
    if fp["rel_module_minor6_bug_rva"] is not None:
        bug_rva = fp["rel_module_minor6_bug_rva"]
        patches.append(
            {
                "rva": f"0x{bug_rva:X}",
                "expected_hex": "0F 95 C0",
                "patch_hex": "0F 92 C0",
                "description": "Fix CommonLibSSE REL::Module::load_segments minor==6 (`setne al` -> `setb al`) so 1.7.x+ is treated as AE",
            }
        )

    meta: Dict[str, Any] = {}
    if ver_data is not None:
        if not (ver_data["versionIndependenceEx"] & verify_dll.kVersionIndependentEx_AddressLibraryV5):
            if ver_data["versionIndependence"] & verify_dll.kVersionIndependent_AddressLibraryPostAE:
                meta["set_version_independence_ex"] = ["AddressLibraryV5"]
            elif ver_data["compatibleVersions"]:
                meta["compatible_versions_add"] = [f"{target_dot}.0" if len(target_dot.split(".")) == 3 else target_dot]

    return {
        "schema_version": 1,
        "plugin_name": plugin_name,
        "target_runtime": target_dot,
        "target_source": target_source,
        "input_file": dll_path.name,
        "input_sha256": sha256_bytes(data),
        "symbols": {},
        "code_caves": [],
        "trampolines": [],
        "patches": patches,
        "metadata_patches": meta,
    }


def cmd_init_manifest(args) -> int:
    manifest = generate_init_manifest(args.input_dll, target_runtime=args.target)
    out_path = args.output.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"[OK] Wrote starter patches manifest to {out_path}")
    print(f"     target_rt    : {manifest['target_runtime']} (source: {manifest['target_source']})")
    print(f"     input_sha256 : {manifest['input_sha256']}")
    print(f"     auto-patches : {len(manifest['patches'])}, metadata_patches={manifest['metadata_patches']}")
    return 0


def cmd_verify_manifest(args) -> int:
    orig_data = args.input_dll.resolve().read_bytes()
    manifest = json.loads(args.manifest.resolve().read_text(encoding="utf-8"))
    plan = _plan_manifest(orig_data, manifest, ignore_hash=args.ignore_hash)
    print(f"[OK] Manifest verified against {args.input_dll.name}:")
    print(f"     code_caves  : {len(plan['cave_specs'])}")
    print(f"     trampolines : {len(plan['trampoline_specs'])}")
    print(f"     patches     : {len(plan['patch_plans'])}")
    print(f"     new_section : {plan['new_section_plan']['name'] if plan['new_section_plan'] else 'None'}")
    print(f"     metadata    : {'Yes' if plan['meta_plan'] else 'No'}")
    return 0


def cmd_apply(args) -> int:
    input_path = args.input_dll.resolve()
    orig_data = input_path.read_bytes()
    manifest = json.loads(args.manifest.resolve().read_text(encoding="utf-8"))
    patched_raw, plan = apply_manifest_bytes(orig_data, manifest, ignore_hash=args.ignore_hash)

    print(f"=== Manifest Patch Plan for {input_path.name} ===")
    for c in plan["cave_specs"]:
        print(f"  [CAVE] {c['name']} ({c['resolved_placement']}) @ RVA 0x{c['rva']:X} ({len(c['bytes'])}B)")
    for t in plan["trampoline_specs"]:
        print(f"  [HOOK] {t['name']} @ RVA 0x{t['hook_rva']:X} ({t['stolen_len']}B)")
    for p in plan["patch_plans"]:
        rva_s = f"RVA 0x{p['rva']:X}" if p["rva"] is not None else f"Off 0x{p['file_offset']:X}"
        print(f"  [BYTE] {p['label']} @ {rva_s} ({len(p['bytes'])}B)")
    if plan["new_section_plan"]:
        ns = plan["new_section_plan"]
        print(f"  [SECT] Added {ns['name']} @ RVA 0x{ns['virtual_addr']:X} (VSize=0x{ns['virtual_size']:X}, Raw=0x{ns['raw_size']:X})")
    if plan["meta_plan"]:
        mp = plan["meta_plan"]
        print(
            f"  [META] versionIndependenceEx 0x{mp['old_ex']:X} -> 0x{mp['new_ex']:X}, "
            f"versionIndependence 0x{mp['old_ind']:X} -> 0x{mp['new_ind']:X}"
        )
    print(f"  [CSUM] PE CheckSum -> 0x{plan['computed_checksum']:08X}")

    if args.dry_run:
        print("\n[DRY-RUN] Manifest validated cleanly; no files written.")
        return 0

    if args.in_place:
        bak = input_path.with_suffix(input_path.suffix + ".bak")
        if not bak.exists():
            shutil.copy2(input_path, bak)
            print(f"Backup created : {bak}")
        dest = input_path
    elif args.output is not None:
        dest = args.output.resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
    else:
        dest = input_path.with_name(f"{input_path.stem}_patched{input_path.suffix}")

    dest.write_bytes(bytes(patched_raw))
    print(f"Wrote patched DLL: {dest}\n")

    manifest_rt = str(manifest.get("target_runtime") or "").strip()
    if manifest_rt.lower() in ("", "auto", "<target_version>"):
        manifest_rt = ""
    target_rt = args.target or manifest_rt or skse_env.get_default_target_dot()
    res = verify_dll.verify_dll(dest, target_runtime=target_rt)
    verify_dll.print_verification(res)

    if args.zip and res["passed_target"]:
        mod_name = manifest.get("plugin_name") or input_path.stem
        zip_path = (skse_env.DIST_DIR / f"{mod_name}_Updated.zip").resolve()
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(dest, f"SKSE/Plugins/{dest.name}")
        print(f"Packaged ZIP archive: {zip_path}")

    return 0 if res["passed_target"] else 2


def cmd_fix_checksum(args) -> int:
    in_path = args.dll.resolve()
    raw = bytearray(in_path.read_bytes())
    pe_info = pe_inspect.parse_pe64(bytes(raw))
    cs_off = pe_info["checksum_offset"]
    checksum = pe_inspect.calculate_pe_checksum(bytes(raw), cs_off)
    struct.pack_into("<I", raw, cs_off, checksum)
    out_path = args.output.resolve() if args.output else in_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(raw))
    print(f"[OK] Updated PE CheckSum in {out_path} -> 0x{checksum:08X}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Manifest-driven PE64 binary patch engine & checksum fixer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init-manifest", help="Generate a starter patches.json manifest for a DLL")
    p_init.add_argument("input_dll", type=Path)
    p_init.add_argument("--output", "-o", type=Path, required=True)
    p_init.add_argument("--target", default=None)
    p_init.set_defaults(func=cmd_init_manifest)

    p_ver = sub.add_parser("verify-manifest", help="Validate a patches.json manifest against a DLL without writing")
    p_ver.add_argument("input_dll", type=Path)
    p_ver.add_argument("--manifest", "-m", type=Path, required=True)
    p_ver.add_argument("--ignore-hash", action="store_true")
    p_ver.set_defaults(func=cmd_verify_manifest)

    p_app = sub.add_parser("apply", help="Apply a patches.json manifest to a DLL and verify output")
    p_app.add_argument("input_dll", type=Path)
    p_app.add_argument("--manifest", "-m", type=Path, required=True)
    p_app.add_argument("--output", "-o", type=Path, default=None)
    p_app.add_argument("--in-place", action="store_true")
    p_app.add_argument("--dry-run", action="store_true")
    p_app.add_argument("--ignore-hash", action="store_true")
    p_app.add_argument("--target", default=None)
    p_app.add_argument("--zip", action="store_true")
    p_app.set_defaults(func=cmd_apply)

    p_cs = sub.add_parser("fix-checksum", help="Recalculate and write the PE header checksum")
    p_cs.add_argument("dll", type=Path)
    p_cs.add_argument("--output", "-o", type=Path, default=None)
    p_cs.set_defaults(func=cmd_fix_checksum)

    args = parser.parse_args()
    try:
        return args.func(args)
    except ManifestError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
