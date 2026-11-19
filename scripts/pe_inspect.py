#!/usr/bin/env python3
"""
PE64 & SKSE64 Reverse-Engineering Metadata Inspector (scripts/pe_inspect.py)

Pure-stdlib PE64 analyzer and disassembler wrapper for SKSE64 plugins and SkyrimSE.exe:
  - Parses DOS/NT64 headers, sections (+ trailing .text padding caves), exports,
    imports (CRT linkage), and ASLR `.reloc` base relocation tables.
  - Decodes `SKSEPlugin_Version` (`0x350` bytes) directly from disk with exact RVAs
    and file offsets, and evaluates SKSE64 (2.3.0+ rules) compatibility.
  - Fingerprints framework (`CommonLibSSE`, `CommonLibSSE-NG`, `versiondb`),
    Address Library format hints, 1.7.x `REL::Module` bug, and VTable/struct risks.
  - Searches AOB hex patterns (with `??` wildcards), ASCII/UTF-16LE string xrefs,
    and disassembles byte ranges via MSVC `dumpbin.exe`.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402
import verify_dll  # noqa: E402

SKSE_PLUGIN_VERSION_SIZE = 0x350

_RELOC_TYPE_NAMES = {
    0: "ABSOLUTE",
    3: "HIGHLOW",
    10: "DIR64",
}

_RELOC_TYPE_SIZES = {
    0: 0,
    3: 4,
    10: 8,
}

_DATA_DIR_NAMES = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "BaseReloc",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLS",
    "LoadConfig",
    "BoundImport",
    "IAT",
    "DelayImport",
    "CLRRuntime",
    "Reserved",
]

_RIP_LEA_RE = re.compile(rb"[\x48\x4C]\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]")


class PEError(RuntimeError):
    pass


def parse_hex_or_int(val: str) -> int:
    s = val.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    if any(c in s.lower() for c in "abcdef"):
        return int(s, 16)
    return int(s, 0)


def calculate_pe_checksum(data: bytes, checksum_offset: int) -> int:
    """Compute exact Windows MapFileAndCheckSum / pefile PE checksum."""
    n = len(data)
    acc = 0
    for i in range(0, n, 4):
        chunk = data[i : i + 4]
        if len(chunk) < 4:
            chunk = chunk.ljust(4, b"\x00")
        # Zero out bytes overlapping the 4-byte OptionalHeader.CheckSum field
        if i + 4 > checksum_offset and i < checksum_offset + 4:
            cb = bytearray(chunk)
            for j in range(4):
                if checksum_offset <= i + j < checksum_offset + 4:
                    cb[j] = 0
            word = int.from_bytes(cb, "little")
        else:
            word = int.from_bytes(chunk, "little")
        acc += word
        acc = (acc & 0xFFFFFFFF) + (acc >> 32)
    acc = (acc & 0xFFFF) + (acc >> 16)
    acc = (acc & 0xFFFF) + (acc >> 16)
    return (acc + n) & 0xFFFFFFFF


def rva_to_file_offset(rva: int, sections: List[Dict[str, Any]]) -> Optional[int]:
    for sec in sections:
        vaddr = sec["virtual_addr"]
        span = max(sec["virtual_size"], sec["raw_size"])
        if vaddr <= rva < vaddr + span:
            raw_off = sec["raw_ptr"] + (rva - vaddr)
            if sec["raw_size"] > 0 and raw_off < sec["raw_ptr"] + sec["raw_size"]:
                return raw_off
    return None


def file_offset_to_rva(offset: int, sections: List[Dict[str, Any]]) -> Optional[int]:
    for sec in sections:
        rptr = sec["raw_ptr"]
        rsize = sec["raw_size"]
        if rsize > 0 and rptr <= offset < rptr + rsize:
            return sec["virtual_addr"] + (offset - rptr)
    return None


def _format_sec_flags(chars: int) -> str:
    flags = ""
    if chars & 0x40000000:
        flags += "R"
    if chars & 0x80000000:
        flags += "W"
    if chars & 0x20000000:
        flags += "X"
    return flags or "-"


def _read_cstr(data: bytes, offset: int, max_len: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + max_len))
    if end == -1:
        end = min(len(data), offset + max_len)
    return data[offset:end].decode("ascii", errors="replace")


def parse_pe64(data: bytes) -> Dict[str, Any]:
    """Parse a PE64 (x86_64) binary's headers, sections, exports, imports, and ASLR relocations."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError("Not a valid MZ executable.")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise PEError("Invalid PE signature.")

    machine, num_sections, timestamp, _, _, opt_header_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, e_lfanew + 4
    )
    if machine != 0x8664:
        raise PEError(f"Not an x64 PE binary (machine=0x{machine:04x}).")

    opt_offset = e_lfanew + 0x18
    if opt_offset + opt_header_size > len(data):
        raise PEError("PE optional header extends beyond EOF.")

    magic = struct.unpack_from("<H", data, opt_offset)[0]
    if magic != 0x20B:
        raise PEError(f"Not a PE32+ (64-bit) optional header (magic=0x{magic:04x}).")

    image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
    section_alignment, file_alignment = struct.unpack_from("<II", data, opt_offset + 32)
    size_of_image, size_of_headers, checksum_stored = struct.unpack_from("<III", data, opt_offset + 56)
    dll_characteristics = struct.unpack_from("<H", data, opt_offset + 70)[0]
    num_rva_and_sizes = struct.unpack_from("<I", data, opt_offset + 108)[0]

    checksum_offset = opt_offset + 64
    checksum_computed = calculate_pe_checksum(data, checksum_offset)

    data_directories: Dict[str, Dict[str, int]] = {}
    dd_base = opt_offset + 112
    for idx in range(min(num_rva_and_sizes, 16)):
        if dd_base + (idx + 1) * 8 > opt_offset + opt_header_size:
            break
        rva, size = struct.unpack_from("<II", data, dd_base + idx * 8)
        if rva or size:
            dname = _DATA_DIR_NAMES[idx] if idx < len(_DATA_DIR_NAMES) else f"Dir{idx}"
            data_directories[dname] = {"rva": rva, "size": size}

    sec_table_offset = opt_offset + opt_header_size
    if sec_table_offset + num_sections * 40 > len(data):
        raise PEError("PE section headers extend beyond EOF.")

    sections: List[Dict[str, Any]] = []
    for i in range(num_sections):
        off = sec_table_offset + i * 40
        raw_name = data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        sec_chars = struct.unpack_from("<I", data, off + 36)[0]

        cave_rva: Optional[int] = None
        cave_file_offset: Optional[int] = None
        cave_avail_bytes = 0
        if rsize > 0 and rptr < len(data):
            sec_end = min(len(data), rptr + rsize)
            last_used = sec_end - 1
            while last_used > rptr and data[last_used] in (0x00, 0xCC):
                last_used -= 1
            if last_used == rptr and data[rptr] in (0x00, 0xCC):
                aligned_off = rptr
            else:
                aligned_off = (last_used + 16) & ~0xF
            if sec_end > aligned_off:
                cave_file_offset = aligned_off
                cave_avail_bytes = sec_end - aligned_off
                cave_rva = vaddr + (aligned_off - rptr)

        sections.append(
            {
                "name": raw_name,
                "virtual_size": vsize,
                "virtual_addr": vaddr,
                "raw_size": rsize,
                "raw_ptr": rptr,
                "characteristics": sec_chars,
                "flags": _format_sec_flags(sec_chars),
                "is_executable": bool(sec_chars & 0x20000000),
                "cave_rva": cave_rva,
                "cave_file_offset": cave_file_offset,
                "cave_avail_bytes": cave_avail_bytes,
            }
        )

    # Exports
    exports: Dict[str, Dict[str, Any]] = {}
    exp_dd = data_directories.get("Export")
    if exp_dd and exp_dd["rva"]:
        exp_rva = exp_dd["rva"]
        exp_size = exp_dd["size"]
        exp_off = rva_to_file_offset(exp_rva, sections)
        if exp_off is not None and exp_off + 40 <= len(data):
            ordinal_base = struct.unpack_from("<I", data, exp_off + 16)[0]
            num_funcs, num_names = struct.unpack_from("<II", data, exp_off + 20)
            addr_funcs_rva, addr_names_rva, addr_ords_rva = struct.unpack_from("<III", data, exp_off + 28)
            funcs_off = rva_to_file_offset(addr_funcs_rva, sections)
            names_off = rva_to_file_offset(addr_names_rva, sections)
            ords_off = rva_to_file_offset(addr_ords_rva, sections)
            if funcs_off is not None and names_off is not None and ords_off is not None:
                for i in range(num_names):
                    if names_off + (i + 1) * 4 > len(data) or ords_off + (i + 1) * 2 > len(data):
                        break
                    name_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
                    name_off = rva_to_file_offset(name_rva, sections)
                    if name_off is None:
                        continue
                    sym_name = _read_cstr(data, name_off)
                    ord_idx = struct.unpack_from("<H", data, ords_off + i * 2)[0]
                    if ord_idx >= num_funcs or funcs_off + (ord_idx + 1) * 4 > len(data):
                        continue
                    func_rva = struct.unpack_from("<I", data, funcs_off + ord_idx * 4)[0]
                    is_fwd = exp_rva <= func_rva < exp_rva + exp_size
                    func_off = None if is_fwd else rva_to_file_offset(func_rva, sections)
                    exports[sym_name] = {
                        "rva": func_rva,
                        "file_offset": func_off,
                        "ordinal": ordinal_base + ord_idx,
                        "forwarder": _read_cstr(data, rva_to_file_offset(func_rva, sections) or -1) if is_fwd else None,
                    }

    # Imports
    imports: Dict[str, List[str]] = {}
    imp_dd = data_directories.get("Import")
    if imp_dd and imp_dd["rva"]:
        imp_off = rva_to_file_offset(imp_dd["rva"], sections)
        if imp_off is not None:
            pos = imp_off
            while pos + 20 <= len(data):
                oft_rva, _, _, name_rva, ft_rva = struct.unpack_from("<IIIII", data, pos)
                pos += 20
                if oft_rva == 0 and name_rva == 0 and ft_rva == 0:
                    break
                dll_off = rva_to_file_offset(name_rva, sections)
                dll_name = _read_cstr(data, dll_off) if dll_off is not None else "<unknown>"
                thunk_rva = oft_rva or ft_rva
                thunk_off = rva_to_file_offset(thunk_rva, sections)
                funcs: List[str] = []
                if thunk_off is not None:
                    tpos = thunk_off
                    while tpos + 8 <= len(data):
                        val = struct.unpack_from("<Q", data, tpos)[0]
                        tpos += 8
                        if val == 0:
                            break
                        if val & (1 << 63):
                            funcs.append(f"Ordinal#{val & 0xFFFF}")
                        else:
                            ibn_off = rva_to_file_offset(val & 0x7FFFFFFF, sections)
                            if ibn_off is not None and ibn_off + 2 < len(data):
                                funcs.append(_read_cstr(data, ibn_off + 2))
                imports[dll_name] = funcs

    # ASLR Base Relocations
    relocations: List[Dict[str, Any]] = []
    reloc_dd = data_directories.get("BaseReloc")
    if reloc_dd and reloc_dd["rva"] and reloc_dd["size"]:
        reloc_off = rva_to_file_offset(reloc_dd["rva"], sections)
        if reloc_off is not None:
            end_off = min(len(data), reloc_off + reloc_dd["size"])
            pos = reloc_off
            while pos + 8 <= end_off:
                page_rva, block_size = struct.unpack_from("<II", data, pos)
                if block_size < 8 or pos + block_size > end_off:
                    break
                entry_count = (block_size - 8) // 2
                for k in range(entry_count):
                    entry = struct.unpack_from("<H", data, pos + 8 + k * 2)[0]
                    rtype = entry >> 12
                    if rtype == 0:
                        continue
                    roff = entry & 0x0FFF
                    relocations.append(
                        {
                            "rva": page_rva + roff,
                            "type": rtype,
                            "type_name": _RELOC_TYPE_NAMES.get(rtype, f"TYPE_{rtype}"),
                            "size": _RELOC_TYPE_SIZES.get(rtype, 0),
                        }
                    )
                pos += block_size

    reloc_by_section: Dict[str, int] = {}
    for rel in relocations:
        rrva = rel["rva"]
        sec_name = "<none>"
        for sec in sections:
            span = max(sec["virtual_size"], sec["raw_size"])
            if sec["virtual_addr"] <= rrva < sec["virtual_addr"] + span:
                sec_name = sec["name"]
                break
        reloc_by_section[sec_name] = reloc_by_section.get(sec_name, 0) + 1

    ts_utc = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return {
        "e_lfanew": e_lfanew,
        "machine": machine,
        "characteristics": characteristics,
        "timestamp": timestamp,
        "timestamp_utc": ts_utc,
        "opt_offset": opt_offset,
        "opt_header_size": opt_header_size,
        "sec_table_offset": sec_table_offset,
        "num_sections": num_sections,
        "image_base": image_base,
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "checksum_stored": checksum_stored,
        "checksum_computed": checksum_computed,
        "checksum_offset": checksum_offset,
        "dll_characteristics": dll_characteristics,
        "aslr_enabled": bool(dll_characteristics & 0x0040),
        "high_entropy_va": bool(dll_characteristics & 0x0020),
        "data_directories": data_directories,
        "sections": sections,
        "exports": exports,
        "imports": imports,
        "relocations": relocations,
        "reloc_summary": {
            "total": len(relocations),
            "by_section": reloc_by_section,
        },
    }


def check_reloc_overlaps(rva: int, length: int, relocations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return any `.reloc` entries overlapping `[rva, rva + length)`."""
    if length <= 0:
        return []
    patch_end = rva + length
    overlaps: List[Dict[str, Any]] = []
    for rel in relocations:
        sz = rel.get("size", 0)
        if sz <= 0:
            continue
        rel_start = rel["rva"]
        rel_end = rel_start + sz
        if rel_start < patch_end and rel_end > rva:
            overlaps.append(rel)
    return overlaps


def decode_skse_version_data(
    data: bytes,
    pe_info: Dict[str, Any],
    target_runtime: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Locate and decode the 0x350-byte `SKSEPlugin_Version` struct directly from PE bytes."""
    exp = pe_info["exports"].get("SKSEPlugin_Version")
    if not exp or exp.get("forwarder"):
        return None
    ver_rva = exp["rva"]
    ver_off = exp["file_offset"]
    if ver_off is None or ver_off + SKSE_PLUGIN_VERSION_SIZE > len(data):
        return None

    raw_bytes = data[ver_off : ver_off + SKSE_PLUGIN_VERSION_SIZE]
    data_ver, plugin_ver = struct.unpack_from("<II", raw_bytes, 0x000)
    name = raw_bytes[0x008:0x108].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    author = raw_bytes[0x108:0x208].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    email = raw_bytes[0x208:0x304].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    ver_ind_ex, ver_ind = struct.unpack_from("<II", raw_bytes, 0x304)
    compat_vers = struct.unpack_from("<16I", raw_bytes, 0x30C)
    se_min = struct.unpack_from("<I", raw_bytes, 0x34C)[0]

    compat_list = [verify_dll.unpack_skse_version(v) for v in compat_vers if v != 0]
    free_slots = sum(1 for v in compat_vers if v == 0)

    flags_ind = []
    if ver_ind & verify_dll.kVersionIndependent_AddressLibraryPostAE:
        flags_ind.append("AddressLibraryPostAE (0x1)")
    if ver_ind & verify_dll.kVersionIndependent_Signatures:
        flags_ind.append("Signatures (0x2)")
    if ver_ind & verify_dll.kVersionIndependent_StructsPost629:
        flags_ind.append("StructsPost629 (0x4)")

    flags_ex = []
    if ver_ind_ex & verify_dll.kVersionIndependentEx_NoStructUse:
        flags_ex.append("NoStructUse (0x1)")
    if ver_ind_ex & verify_dll.kVersionIndependentEx_AddressLibraryV5:
        flags_ex.append("AddressLibraryV5 (0x2)")

    target_tuple = (
        skse_env.parse_version_tuple(target_runtime)
        if target_runtime
        else skse_env.get_latest_target_version()
    )
    target_dot = skse_env.format_version_dot(target_tuple)
    runtime_checks: Dict[str, str] = {}
    for label, vt in skse_env.get_verification_runtimes(target_runtime):
        rt_val = verify_dll.pack_skse_version(*vt)
        runtime_checks[label] = verify_dll.check_compat(
            data_ver,
            name,
            ver_ind,
            ver_ind_ex,
            compat_vers,
            pe_info["timestamp"],
            rt_val,
        )

    has_entry = ("SKSEPlugin_Load" in pe_info["exports"]) or ("SKSEPlugin_Preload" in pe_info["exports"])
    passed_target = (runtime_checks.get(target_dot) == "COMPATIBLE") and has_entry

    return {
        "rva": ver_rva,
        "file_offset": ver_off,
        "offsets": {
            "versionIndependenceEx": {"rva": ver_rva + 0x304, "file_offset": ver_off + 0x304},
            "versionIndependence": {"rva": ver_rva + 0x308, "file_offset": ver_off + 0x308},
            "compatibleVersions": {"rva": ver_rva + 0x30C, "file_offset": ver_off + 0x30C},
            "seVersionRequired": {"rva": ver_rva + 0x34C, "file_offset": ver_off + 0x34C},
        },
        "dataVersion": data_ver,
        "pluginVersion_raw": plugin_ver,
        "pluginVersion": verify_dll.unpack_skse_version(plugin_ver) if plugin_ver > 0xFFFF else str(plugin_ver),
        "name": name,
        "author": author,
        "supportEmail": email,
        "versionIndependence": ver_ind,
        "versionIndependence_flags": flags_ind,
        "versionIndependenceEx": ver_ind_ex,
        "versionIndependenceEx_flags": flags_ex,
        "compatibleVersions": compat_list,
        "compatibleVersions_raw": list(compat_vers),
        "free_compat_slots": free_slots,
        "seVersionRequired": verify_dll.unpack_skse_version(se_min) if se_min else "0 (Any)",
        "target_runtime": target_dot,
        "runtime_checks": runtime_checks,
        "passed_target": passed_target,
    }


def _contains_ascii_or_utf16(data: bytes, needle: str) -> bool:
    b_ascii = needle.encode("ascii", errors="ignore")
    if b_ascii and b_ascii in data:
        return True
    b_utf16 = needle.encode("utf-16-le", errors="ignore")
    return bool(b_utf16 and b_utf16 in data)


def fingerprint_skse_binary(
    data: bytes,
    pe_info: Dict[str, Any],
    version_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Identify SKSE framework, CRT linkage, Address Library loader, 1.7.x bugs, and risks."""
    exports = pe_info["exports"]
    if "SKSEPlugin_Version" in exports:
        entry_point = "SKSEPlugin_Version (modern AE/SE)"
    elif "SKSEPlugin_Query" in exports:
        entry_point = "SKSEPlugin_Query (legacy SE 1.5.97)"
    elif "SKSEPlugin_Preload" in exports:
        entry_point = "SKSEPlugin_Preload"
    else:
        entry_point = "None (non-SKSE or helper DLL)"

    imp_dlls_lower = {k.lower() for k in pe_info["imports"].keys()}
    dynamic_crt_prefixes = ("vcruntime140", "msvcp140", "ucrtbase", "api-ms-win-crt-")
    is_dynamic_crt = any(any(d.startswith(p) for p in dynamic_crt_prefixes) for d in imp_dlls_lower)
    crt_linkage = "/MD (Dynamic CRT)" if is_dynamic_crt else "/MT (Static CRT)"

    markers = [
        ("CommonLibSSE-NG", "CommonLibSSE-NG"),
        ("CommonLibSSE", "CommonLibSSE"),
        ("Unsupported address library format", "CommonLibSSE REL::IDDatabase"),
        ("REL/ID.h", "REL/ID.h / IDDB"),
        ("IDDB", "REL::IDDB"),
        ("versionlib-", "versionlib-*.bin (AE/1.7+ Address Library)"),
        ("version-", "version-*.bin (SE 1.5.x Address Library)"),
        ("versiondb", "versiondb (sse-build-resources)"),
        ("sse-build-resources", "sse-build-resources"),
        ("AddressLibrary", "AddressLibrary reference"),
    ]
    found_markers: List[str] = []
    for needle, label in markers:
        if _contains_ascii_or_utf16(data, needle):
            found_markers.append(label)

    if "CommonLibSSE-NG" in found_markers:
        framework = "CommonLibSSE-NG"
    elif "CommonLibSSE" in found_markers or "CommonLibSSE REL::IDDatabase" in found_markers or "REL/ID.h / IDDB" in found_markers:
        framework = "CommonLibSSE"
    elif "versiondb (sse-build-resources)" in found_markers or "sse-build-resources" in found_markers:
        framework = "Raw SKSE64 / sse-build-resources (versiondb)"
    elif "SKSEPlugin_Version" in exports or "SKSEPlugin_Query" in exports:
        framework = "Raw SKSE64 SDK"
    else:
        framework = "Unknown / Non-SKSE"

    if version_data is None:
        version_data = decode_skse_version_data(data, pe_info)

    if version_data:
        ver_ind = version_data["versionIndependence"]
        if ver_ind & verify_dll.kVersionIndependent_AddressLibraryPostAE:
            addr_mode = "AddressLibrary"
        elif ver_ind & verify_dll.kVersionIndependent_Signatures:
            addr_mode = "Signatures"
        elif version_data["compatibleVersions"]:
            addr_mode = "Hardcoded/Version-Locked"
        else:
            addr_mode = "Unknown"
    elif any(k in found_markers for k in ("versionlib-*.bin (AE/1.7+ Address Library)", "version-*.bin (SE 1.5.x Address Library)", "AddressLibrary reference")):
        addr_mode = "AddressLibrary"
    else:
        addr_mode = "Unknown"

    # Detect REL::Module::load_segments 1.7.x AE classification bug (`cmp ax, 6; setne al`)
    minor6_bug_rva: Optional[int] = None
    for sec in pe_info["sections"]:
        if not sec["is_executable"] or sec["raw_size"] == 0:
            continue
        sec_bytes = data[sec["raw_ptr"] : sec["raw_ptr"] + sec["raw_size"]]
        m_rt = re.search(rb"\x66\x83\xF8\x06(\x0F\x95\xC0)\xFE\xC0\x88", sec_bytes)
        if m_rt:
            minor6_bug_rva = sec["virtual_addr"] + m_rt.start(1)
            break

    risks: List[str] = []
    for sym, desc in [
        ("MenuEventHandler", "MenuEventHandler (+2 VTable slot shift in 1.7.99+)"),
        ("PlayerInputHandler", "PlayerInputHandler (+2 VTable slot shift in 1.7.99+)"),
        ("UIStringHolder", "UIStringHolder (struct layout changed in 1.7.99+)"),
        ("SkyrimVM", "SkyrimVM (struct layout changed in 1.7.99+)"),
        ("BSGraphics::State", "BSGraphics::State (member offsets shifted in 1.7.99+)"),
    ]:
        if _contains_ascii_or_utf16(data, sym):
            risks.append(desc)

    return {
        "framework": framework,
        "entry_point": entry_point,
        "crt_linkage": crt_linkage,
        "address_resolution": addr_mode,
        "markers": found_markers,
        "rel_module_minor6_bug_rva": minor6_bug_rva,
        "vtable_or_struct_risks": risks,
    }


def _parse_aob_pattern(pattern_str: str) -> bytes:
    cleaned = pattern_str.strip()
    tokens = re.split(r"[\s,]+", cleaned)
    if len(tokens) == 1 and len(tokens[0]) > 2:
        s = tokens[0]
        if len(s) % 2 != 0:
            raise ValueError(f"Compact hex AOB pattern must have even length: {pattern_str!r}")
        tokens = [s[i : i + 2] for i in range(0, len(s), 2)]

    parts: List[bytes] = []
    for tok in tokens:
        t = tok.strip()
        if not t:
            continue
        if t.lower().startswith("0x"):
            t = t[2:]
        if t in ("?", "??"):
            parts.append(b".")
        elif len(t) == 2 and all(c in "0123456789abcdefABCDEF" for c in t):
            parts.append(re.escape(bytes([int(t, 16)])))
        else:
            raise ValueError(f"Invalid AOB token {tok!r} in pattern {pattern_str!r}")
    if not parts:
        raise ValueError("Empty AOB pattern")
    return b"".join(parts)


def find_aob_pattern(
    data: bytes,
    pe_info: Dict[str, Any],
    pattern_str: str,
    section_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search PE sections for an AOB hex pattern (with `??` wildcards)."""
    regex_bytes = _parse_aob_pattern(pattern_str)
    pat = re.compile(regex_bytes, re.DOTALL)
    hits: List[Dict[str, Any]] = []
    for sec in pe_info["sections"]:
        if section_name and sec["name"].lower() != section_name.lower():
            continue
        if sec["raw_size"] == 0 or sec["raw_ptr"] >= len(data):
            continue
        chunk = data[sec["raw_ptr"] : min(len(data), sec["raw_ptr"] + sec["raw_size"])]
        for m in pat.finditer(chunk):
            off = sec["raw_ptr"] + m.start()
            rva = sec["virtual_addr"] + m.start()
            hits.append(
                {
                    "rva": rva,
                    "va": pe_info["image_base"] + rva,
                    "file_offset": off,
                    "section": sec["name"],
                }
            )
    return hits


def find_string_xrefs(data: bytes, pe_info: Dict[str, Any], needle: str) -> List[Dict[str, Any]]:
    """Find ASCII and UTF-16LE string occurrences and RIP-relative `LEA` xrefs in code sections."""
    sections = pe_info["sections"]
    targets: Dict[int, Dict[str, Any]] = {}

    for encoding, raw_needle in [
        ("ascii", needle.encode("utf-8", errors="ignore")),
        ("utf-16le", needle.encode("utf-16-le", errors="ignore")),
    ]:
        if not raw_needle:
            continue
        pos = 0
        while True:
            idx = data.find(raw_needle, pos)
            if idx == -1:
                break
            rva = file_offset_to_rva(idx, sections)
            if rva is not None and rva not in targets:
                preview = _read_cstr(data, idx, 120) if encoding == "ascii" else needle
                targets[rva] = {
                    "string_rva": rva,
                    "string_offset": idx,
                    "encoding": encoding,
                    "preview": preview,
                    "xrefs": [],
                }
            pos = idx + 1

    if not targets:
        return []

    for sec in sections:
        if not sec["is_executable"] or sec["raw_size"] == 0 or sec["raw_ptr"] >= len(data):
            continue
        sec_start = sec["raw_ptr"]
        sec_end = min(len(data), sec_start + sec["raw_size"])
        chunk = data[sec_start:sec_end]
        sec_va = sec["virtual_addr"]
        for m in _RIP_LEA_RE.finditer(chunk):
            i = m.start()
            if i + 7 > len(chunk):
                continue
            disp = struct.unpack_from("<i", chunk, i + 3)[0]
            instr_rva = sec_va + i
            target_rva = instr_rva + 7 + disp
            if target_rva in targets:
                targets[target_rva]["xrefs"].append(
                    {
                        "rva": instr_rva,
                        "va": pe_info["image_base"] + instr_rva,
                        "file_offset": sec_start + i,
                        "section": sec["name"],
                    }
                )

    return sorted(targets.values(), key=lambda x: x["string_rva"])


def find_dumpbin() -> Optional[Path]:
    """Locate MSVC `dumpbin.exe` using `skse_env.find_vcvars64()` or PATH."""
    vcvars = skse_env.find_vcvars64()
    if vcvars is not None:
        # <VSRoot>\VC\Auxiliary\Build\vcvars64.bat -> <VSRoot>
        try:
            vs_root = vcvars.parents[3]
            cands = sorted(
                vs_root.glob("VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe"),
                reverse=True,
            )
            if cands:
                return cands[0]
        except IndexError:
            pass

    on_path = shutil.which("dumpbin")
    return Path(on_path) if on_path else None


def disassemble_range(pe_path: Path, rva: int, length: int = 64) -> str:
    """Disassemble `length` bytes starting at `rva` using MSVC `dumpbin.exe /DISASM`."""
    pe_path = pe_path.resolve()
    data = pe_path.read_bytes()
    pe_info = parse_pe64(data)
    dumpbin = find_dumpbin()
    if dumpbin is None:
        return "[WARN] MSVC `dumpbin.exe` not found on this machine; cannot disassemble."

    va_start = pe_info["image_base"] + rva
    va_end = va_start + max(1, length) - 1
    cmd = [
        str(dumpbin),
        "/NOLOGO",
        "/DISASM",
        "/RAWDATA:BYTES",
        f"/RANGE:0x{va_start:X},0x{va_end:X}",
        str(pe_path),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode != 0:
        raise RuntimeError(f"dumpbin failed (exit {res.returncode}): {res.stderr or res.stdout}")
    return res.stdout


def inspect_pe_file(pe_path: Path, target_runtime: Optional[str] = None) -> Dict[str, Any]:
    pe_path = pe_path.resolve()
    data = pe_path.read_bytes()
    pe_info = parse_pe64(data)
    ver_data = decode_skse_version_data(data, pe_info, target_runtime=target_runtime)
    fp = fingerprint_skse_binary(data, pe_info, version_data=ver_data)
    resolved_target = (
        ver_data["target_runtime"]
        if ver_data is not None
        else (target_runtime or skse_env.get_default_target_dot())
    )

    return {
        "file": str(pe_path),
        "size_bytes": len(data),
        "target_runtime": resolved_target,
        "header": {
            "machine": f"0x{pe_info['machine']:04X}",
            "timestamp": pe_info["timestamp"],
            "timestamp_utc": pe_info["timestamp_utc"],
            "image_base": f"0x{pe_info['image_base']:016X}",
            "size_of_image": f"0x{pe_info['size_of_image']:X}",
            "size_of_headers": f"0x{pe_info['size_of_headers']:X}",
            "section_alignment": f"0x{pe_info['section_alignment']:X}",
            "file_alignment": f"0x{pe_info['file_alignment']:X}",
            "aslr_enabled": pe_info["aslr_enabled"],
            "high_entropy_va": pe_info["high_entropy_va"],
            "checksum_stored": f"0x{pe_info['checksum_stored']:08X}",
            "checksum_computed": f"0x{pe_info['checksum_computed']:08X}",
            "checksum_valid": pe_info["checksum_stored"] in (0, pe_info["checksum_computed"]),
        },
        "sections": pe_info["sections"],
        "exports": sorted(pe_info["exports"].keys()),
        "export_details": pe_info["exports"],
        "imports": pe_info["imports"],
        "reloc_summary": pe_info["reloc_summary"],
        "skse_version_data": ver_data,
        "fingerprint": fp,
    }


def _print_inspect_report(rep: Dict[str, Any]) -> None:
    hdr = rep["header"]
    fp = rep["fingerprint"]
    print("=" * 78)
    print(f" PE64 & SKSE64 INSPECTION: {Path(rep['file']).name}")
    print("=" * 78)
    print(f"Path              : {rep['file']}")
    print(f"Size              : {rep['size_bytes']:,} bytes | Build Time: {hdr['timestamp_utc']}")
    print(f"Target Runtime    : {rep.get('target_runtime', 'auto')}")
    print(f"ImageBase / Size  : {hdr['image_base']} / {hdr['size_of_image']}")
    print(f"ASLR / EntropyVA  : {hdr['aslr_enabled']} / {hdr['high_entropy_va']}")
    print(f"PE Checksum       : stored={hdr['checksum_stored']}, computed={hdr['checksum_computed']}")
    print("-" * 78)
    print("SKSE Fingerprint:")
    print(f"  Framework       : {fp['framework']}")
    print(f"  Entry Point     : {fp['entry_point']}")
    print(f"  CRT Linkage     : {fp['crt_linkage']}")
    print(f"  Address Mode    : {fp['address_resolution']}")
    print(f"  Markers         : {fp['markers'] or ['(none)']}")
    if fp["rel_module_minor6_bug_rva"] is not None:
        print(f"  [!] 1.7.x Bug   : REL::Module::load_segments `cmp ax, 6; setne al` @ RVA 0x{fp['rel_module_minor6_bug_rva']:X}")
    if fp["vtable_or_struct_risks"]:
        print(f"  [!] Risk Symbols: {', '.join(fp['vtable_or_struct_risks'])}")
    print("-" * 78)
    print("Sections:")
    print(f"  {'Name':<10} {'RVA':<10} {'VSize':<10} {'RawPtr':<10} {'RawSize':<10} {'Flags':<6} {'TailCave'}")
    for s in rep["sections"]:
        cave_s = (
            f"RVA 0x{s['cave_rva']:X} ({s['cave_avail_bytes']}B)"
            if s["cave_rva"] is not None and s["cave_avail_bytes"] > 0
            else "-"
        )
        print(
            f"  {s['name']:<10} 0x{s['virtual_addr']:06X}   0x{s['virtual_size']:06X}   "
            f"0x{s['raw_ptr']:06X}   0x{s['raw_size']:06X}   {s['flags']:<6} {cave_s}"
        )
    print("-" * 78)
    print(f"Exports ({len(rep['exports'])}): {', '.join(rep['exports'][:25])}")
    print(f"Imports ({len(rep['imports'])} DLLs): {', '.join(sorted(rep['imports'].keys()))}")
    rs = rep["reloc_summary"]
    print(f"ASLR Relocs       : {rs['total']:,} entries ({rs['by_section']})")
    vd = rep["skse_version_data"]
    if vd:
        print("-" * 78)
        print(f"SKSEPlugin_Version @ RVA 0x{vd['rva']:X} (FileOffset 0x{vd['file_offset']:X}):")
        print(f"  name / author         : {vd['name']!r} / {vd['author']!r} (v{vd['pluginVersion']})")
        print(
            f"  versionIndependenceEx : 0x{vd['versionIndependenceEx']:08X} {vd['versionIndependenceEx_flags']} "
            f"@ RVA 0x{vd['offsets']['versionIndependenceEx']['rva']:X} (off 0x{vd['offsets']['versionIndependenceEx']['file_offset']:X})"
        )
        print(
            f"  versionIndependence   : 0x{vd['versionIndependence']:08X} {vd['versionIndependence_flags']} "
            f"@ RVA 0x{vd['offsets']['versionIndependence']['rva']:X} (off 0x{vd['offsets']['versionIndependence']['file_offset']:X})"
        )
        print(
            f"  compatibleVersions    : {vd['compatibleVersions'] or '[None / Version Independent]'} "
            f"({vd['free_compat_slots']} free slots @ RVA 0x{vd['offsets']['compatibleVersions']['rva']:X})"
        )
        print("  Compatibility Checks  :")
        for rt, st in vd["runtime_checks"].items():
            tag = "[PASS]" if st == "COMPATIBLE" else "[FAIL]"
            print(f"    {tag} {rt:<10} -> {st}")
    print("=" * 78)


def main() -> int:
    parser = argparse.ArgumentParser(description="PE64 & SKSE64 Reverse-Engineering Metadata Inspector")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_insp = sub.add_parser("inspect", help="Inspect PE headers, sections, exports, imports, relocs, and SKSE metadata")
    p_insp.add_argument("pe_file", type=Path)
    p_insp.add_argument("--target", default=None, help="Target runtime version (default: latest available)")
    p_insp.add_argument("--json", action="store_true", help="Output JSON")

    p_dis = sub.add_parser("disasm", help="Disassemble a byte range at RVA using MSVC dumpbin.exe")
    p_dis.add_argument("pe_file", type=Path)
    p_dis.add_argument("--rva", required=True, help="Start RVA (hex or int)")
    p_dis.add_argument("--count", type=int, default=64, help="Byte length to disassemble (default: 64)")

    p_pat = sub.add_parser("find-pattern", help="Search PE sections for an AOB pattern (supports ??)")
    p_pat.add_argument("pe_file", type=Path)
    p_pat.add_argument("pattern", help="Hex AOB pattern, e.g. '48 8D 0D ?? ?? ?? ??'")
    p_pat.add_argument("--section", default=None, help="Limit search to section name (e.g. .text)")
    p_pat.add_argument("--json", action="store_true")

    p_xref = sub.add_parser("find-xrefs", help="Find string literals (ASCII/UTF-16LE) and RIP-relative LEA xrefs")
    p_xref.add_argument("pe_file", type=Path)
    p_xref.add_argument("needle", help="String to search for")
    p_xref.add_argument("--json", action="store_true")

    p_rel = sub.add_parser("check-reloc", help="Check if [rva, rva + len) overlaps any .reloc entries")
    p_rel.add_argument("pe_file", type=Path)
    p_rel.add_argument("--rva", required=True, help="Start RVA (hex or int)")
    p_rel.add_argument("--len", type=int, required=True, dest="length", help="Byte length")
    p_rel.add_argument("--json", action="store_true")

    p_r2o = sub.add_parser("rva2off", help="Convert RVA to file offset")
    p_r2o.add_argument("pe_file", type=Path)
    p_r2o.add_argument("rva")

    p_o2r = sub.add_parser("off2rva", help="Convert file offset to RVA")
    p_o2r.add_argument("pe_file", type=Path)
    p_o2r.add_argument("offset")

    args = parser.parse_args()

    if args.cmd == "inspect":
        rep = inspect_pe_file(args.pe_file, target_runtime=args.target)
        if args.json:
            print(json.dumps(rep, indent=2))
        else:
            _print_inspect_report(rep)
        return 0

    if args.cmd == "disasm":
        rva = parse_hex_or_int(args.rva)
        print(disassemble_range(args.pe_file, rva, args.count))
        return 0

    data = args.pe_file.resolve().read_bytes()
    pe_info = parse_pe64(data)

    if args.cmd == "find-pattern":
        hits = find_aob_pattern(data, pe_info, args.pattern, section_name=args.section)
        if args.json:
            print(json.dumps(hits, indent=2))
        else:
            print(f"Found {len(hits)} match(es) for {args.pattern!r}:")
            for h in hits:
                print(f"  [{h['section']}] RVA=0x{h['rva']:X}  VA=0x{h['va']:X}  FileOffset=0x{h['file_offset']:X}")
        return 0

    if args.cmd == "find-xrefs":
        res = find_string_xrefs(data, pe_info, args.needle)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Found {len(res)} string match(es) for {args.needle!r}:")
            for item in res:
                print(
                    f"  String RVA=0x{item['string_rva']:X} (off=0x{item['string_offset']:X}, {item['encoding']}): "
                    f"{item['preview']!r}"
                )
                for xr in item["xrefs"]:
                    print(f"    -> LEA xref @ [{xr['section']}] RVA=0x{xr['rva']:X} (off=0x{xr['file_offset']:X})")
        return 0

    if args.cmd == "check-reloc":
        rva = parse_hex_or_int(args.rva)
        overlaps = check_reloc_overlaps(rva, args.length, pe_info["relocations"])
        if args.json:
            print(json.dumps({"rva": rva, "length": args.length, "overlaps": overlaps}, indent=2))
        else:
            if overlaps:
                print(f"[WARN] {len(overlaps)} ASLR .reloc overlap(s) in [0x{rva:X}, 0x{rva + args.length:X}):")
                for rel in overlaps:
                    print(f"  - RVA=0x{rel['rva']:X} type={rel['type_name']} size={rel['size']}")
            else:
                print(f"[OK] No .reloc entries overlap [0x{rva:X}, 0x{rva + args.length:X}).")
        return 0

    if args.cmd == "rva2off":
        rva = parse_hex_or_int(args.rva)
        off = rva_to_file_offset(rva, pe_info["sections"])
        if off is None:
            print(f"RVA 0x{rva:X} does not map to raw file bytes.", file=sys.stderr)
            return 1
        print(f"RVA 0x{rva:X} -> FileOffset 0x{off:X} ({off})")
        return 0

    if args.cmd == "off2rva":
        off = parse_hex_or_int(args.offset)
        rva = file_offset_to_rva(off, pe_info["sections"])
        if rva is None:
            print(f"FileOffset 0x{off:X} does not map to a PE section.", file=sys.stderr)
            return 1
        print(f"FileOffset 0x{off:X} -> RVA 0x{rva:X} (VA 0x{pe_info['image_base'] + rva:X})")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
