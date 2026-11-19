#!/usr/bin/env python3
"""
[ARCHIVED / DEPRECATED] Legacy SKSE64 Fallback Binary Patcher (scripts/legacy/patch_binary.py)

NOTICE: This script is archived for historical reference only. It relied on rigid
hardcoded byte regexes that break across compiler builds, game versions, and
non-trivial plugins.

It has been superseded by the modular reverse-engineering & manifest-driven
binary-patching workflow documented in `docs/BINARY_PATCHING_GUIDE.md`:
  - `scripts/pe_inspect.py`       (PE64, sections, exports/imports, .reloc, SKSE metadata, xrefs, disasm)
  - `scripts/addrlib_xref.py`     (Address Library format checks & ID/offset cross-referencing)
  - `scripts/manifest_patcher.py` (Deterministic SHA-256 + expected-bytes patches.json engine, code caves, trampolines, .reloc validation, PE checksum)
  - `scripts/live_test_skse.py`   (Automated deploy, SKSE launch, log streaming & crash triage runner)

Original description:
Best-effort fallback tool for closed-source or unbuildable SKSE64 `.dll` plugins
when source recompilation is not possible (e.g. missing private SDKs).

What this tool CAN do:
  1. Locate the exported `SKSEPlugin_Version` (0x350-byte `SKSEPluginVersionData`)
     directly in a PE64 (x86_64) `.dll` file using pure-stdlib PE parsing.
  2. Patch `versionIndependenceEx` (offset 0x304) to set
     `kVersionIndependentEx_AddressLibraryV5` (`1 << 1`), and optionally set
     `kVersionIndependent_StructsPost629` (`1 << 2`) or add runtime versions to
     `compatibleVersions`.
  3. Inject Format 5 Address Library reader code caves for BOTH:
     - `versiondb::Load` (`sse-build-resources`), preserving Format 2 support
     - `REL::IDDatabase` (`CommonLibSSE`), plus `REL::Module` 1.7.x+ AE detection
       (`cmp ax, 6; setne al` -> `setb al`)
  4. Scan `.rdata`/`.text` for Address Library strings (`versionlib-`,
     `version-`) and high-risk 1.7.99+ class names (`MenuEventHandler`,
     `UIStringHolder`, `SkyrimVM`) to warn about shifted VTables or layouts.
  5. Verify the patched `.dll` using `scripts/verify_dll.py`.

What a binary patcher CANNOT reliably do:
  - Rewrite hardcoded struct offsets or shifted VTable slot indices inside
    compiled machine code across arbitrary future Skyrim updates.
  - Replace Address Library IDs that were removed/inlined in a newer `SkyrimSE.exe`.

Usage:
  python scripts/legacy/patch_binary.py <input.dll> [--output <out.dll>] [--in-place] [--dry-run]
  python scripts/legacy/patch_binary.py <input.dll> --add-structs-post629 --add-version <TARGET_VERSION>
"""

from __future__ import annotations

import argparse
import re
import shutil
import struct
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SCRIPTS_DIR = Path(__file__).resolve().parent.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import skse_env  # noqa: E402
import verify_dll  # noqa: E402

kVersionIndependent_AddressLibraryPostAE = 1 << 0
kVersionIndependent_Signatures = 1 << 1
kVersionIndependent_StructsPost629 = 1 << 2

kVersionIndependentEx_NoStructUse = 1 << 0
kVersionIndependentEx_AddressLibraryV5 = 1 << 1

SKSE_PLUGIN_VERSION_SIZE = 0x350


class PEError(RuntimeError):
    pass


def parse_version_str(ver: str) -> int:
    parts = [int(p) for p in ver.strip().split(".")]
    while len(parts) < 4:
        parts.append(0)
    if len(parts) != 4:
        raise ValueError(f"Invalid version string: {ver}")
    return verify_dll.pack_skse_version(parts[0], parts[1], parts[2], parts[3])


def parse_pe64_sections_and_exports(data: bytes) -> Tuple[int, List[Tuple[str, int, int, int, int]], Dict[str, int]]:
    """Return (pe_offset, sections, export_rvas) for a PE64 binary.

    sections: list of (name, virtual_size, virtual_addr, raw_size, raw_ptr)
    export_rvas: dict mapping exported symbol name -> RVA
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError("Not a valid MZ executable.")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise PEError("Invalid PE signature.")

    machine, num_sections, _, _, _, opt_header_size, _ = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    if machine != 0x8664:
        raise PEError(f"Not an x64 PE binary (machine=0x{machine:04x}).")

    opt_offset = e_lfanew + 0x18
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    if magic != 0x20B:
        raise PEError(f"Not a PE32+ (64-bit) optional header (magic=0x{magic:04x}).")

    # PE32+ DataDirectory[0] (Export Table) is at opt_offset + 112
    num_rva_and_sizes = struct.unpack_from("<I", data, opt_offset + 108)[0]
    export_rva = 0
    export_size = 0
    if num_rva_and_sizes >= 1:
        export_rva, export_size = struct.unpack_from("<II", data, opt_offset + 112)

    sec_offset = opt_offset + opt_header_size
    sections: List[Tuple[str, int, int, int, int]] = []
    for i in range(num_sections):
        off = sec_offset + i * 40
        raw_name = data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append((raw_name, vsize, vaddr, rsize, rptr))

    def rva_to_offset(rva: int) -> Optional[int]:
        for _, vsize, vaddr, rsize, rptr in sections:
            span = max(vsize, rsize)
            if vaddr <= rva < vaddr + span:
                raw_off = rptr + (rva - vaddr)
                if raw_off < len(data):
                    return raw_off
        return None

    exports: Dict[str, int] = {}
    if export_rva and export_size:
        exp_off = rva_to_offset(export_rva)
        if exp_off is None:
            raise PEError("Could not map Export Directory RVA to file offset.")
        # IMAGE_EXPORT_DIRECTORY: NumberOfNames @ +24, AddressOfFunctions @ +28,
        # AddressOfNames @ +32, AddressOfNameOrdinals @ +36
        num_names, addr_funcs_rva, addr_names_rva, addr_ords_rva = struct.unpack_from("<IIII", data, exp_off + 24)
        funcs_off = rva_to_offset(addr_funcs_rva)
        names_off = rva_to_offset(addr_names_rva)
        ords_off = rva_to_offset(addr_ords_rva)
        if funcs_off is not None and names_off is not None and ords_off is not None:
            for i in range(num_names):
                name_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
                name_off = rva_to_offset(name_rva)
                if name_off is None:
                    continue
                end = data.find(b"\x00", name_off)
                if end == -1:
                    continue
                sym_name = data[name_off:end].decode("ascii", errors="replace")
                ord_idx = struct.unpack_from("<H", data, ords_off + i * 2)[0]
                func_rva = struct.unpack_from("<I", data, funcs_off + ord_idx * 4)[0]
                exports[sym_name] = func_rva

    return e_lfanew, sections, exports


def rva_to_file_offset(rva: int, sections: List[Tuple[str, int, int, int, int]]) -> Optional[int]:
    for _, vsize, vaddr, rsize, rptr in sections:
        span = max(vsize, rsize)
        if vaddr <= rva < vaddr + span:
            return rptr + (rva - vaddr)
    return None


def scan_binary_diagnostics(data: bytes) -> Dict[str, List[str]]:
    """Scan binary for Address Library indicators and 1.7.99+ risk markers."""
    al_markers = []
    for needle, label in [
        (b"versionlib-", "Address Library AE/SE database prefix (versionlib-*.bin)"),
        (b"version-", "Address Library SE legacy prefix (version-*.bin)"),
        (b"AddressLibrary", "AddressLibrary reference"),
        (b"CommonLibSSE", "CommonLibSSE signature"),
    ]:
        if needle in data:
            al_markers.append(label)

    risk_markers = []
    for needle, label in [
        (b"MenuEventHandler", "MenuEventHandler (VTable slots shifted in 1.7.99+)"),
        (b"UIStringHolder", "UIStringHolder (layout changed in 1.7.99+)"),
        (b"SkyrimVM", "SkyrimVM (layout changed in 1.7.99+)"),
    ]:
        if needle in data:
            risk_markers.append(label)

    return {"address_library": al_markers, "vtable_or_struct_risks": risk_markers}


def find_versiondb_v5_target(
    data: bytes,
    e_lfanew: int,
    sections: List[Tuple[str, int, int, int, int]],
) -> Optional[Dict[str, object]]:
    """Locate `versiondb::Load` (sse-build-resources/versiondb.h) in `.text` for Format 5 patching."""
    if not sections:
        return None
    text_name, text_vsize, text_va, text_rsize, text_rptr = sections[0]
    if text_name != ".text":
        return None

    def off_to_rva(off: int) -> Optional[int]:
        for _, vs, va, rs, rp in sections:
            if rp <= off < rp + rs:
                return va + (off - rp)
        return None

    def rva_to_off(rva: int) -> Optional[int]:
        return rva_to_file_offset(rva, sections)

    # Locate Data\SKSE\Plugins\versionlib-%d-%d-%d-%d.bin
    str_off = data.find(b"Data\\SKSE\\Plugins\\versionlib-%d-%d-%d-%d.bin")
    if str_off == -1:
        str_off = data.find(b"versionlib-%d-%d-%d-%d.bin")
    if str_off == -1:
        return None
    str_rva = off_to_rva(str_off)
    if str_rva is None:
        return None

    text = data[text_rptr : text_rptr + text_rsize]
    xref_rva = None
    for i in range(len(text) - 7):
        if text[i] in (0x48, 0x4C) and text[i + 1] == 0x8D and (text[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", text, i + 3)[0]
            if text_va + i + 7 + disp == str_rva:
                xref_rva = text_va + i
                break
    if xref_rva is None:
        return None

    # Search +0x40..+0x160 after xref for:
    #   41 B8 04 00 00 00  (mov r8d, 4)
    #   48 8D 54 24 <fmt>  (lea rdx, [rsp+fmt])
    #   48 8D 4D <file>    (lea rcx, [rbp+file])
    #   E8 <read_rel32>    (call istream::read)
    #   39 <modrm> 24 <fmt>(cmp [rsp+fmt], reg)
    #   0F 85 <fail_rel32> (jne fail_rva)
    win_start = (xref_rva - text_va) + 0x40
    win_end = min(len(text), win_start + 0x160)
    win = text[win_start:win_end]

    m1 = re.search(
        rb"\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24(.)(\x48\x8D(?:[\x4D\x4C\x54].|\x8D.{4}|\x8C\x24.{4}|[\x4C\x54]\x24.))(\xE8|\xFF\x15)(....)(\x39.\x24.)\x0F\x85(....)",
        win,
        re.DOTALL,
    )
    if not m1:
        # Check if already hooked by patch_binary.py
        if re.search(
            rb"\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24.\x48\x8D(?:[\x4D\x4C\x54].|\x8D.{4}|\x8C\x24.{4}|[\x4C\x54]\x24.)(?:\xE8|\xFF\x15).{4}\xE9.{4}\x90{5}",
            win,
            re.DOTALL,
        ):
            return {"already_patched": True, "loader": "versiondb::Load"}
        return None

    fmt_disp = m1.group(1)[0]
    file_lea = m1.group(2)
    read_is_iat = m1.group(3) == b"\xFF\x15"
    read_disp = struct.unpack("<i", m1.group(4))[0]
    cmp_bytes = m1.group(5)
    fail_rel = struct.unpack("<i", m1.group(6))[0]

    call_rva = text_va + win_start + m1.start(3)
    call_len = 6 if read_is_iat else 5
    read_fn_rva = call_rva + call_len + read_disp
    hook1_rva = text_va + win_start + m1.start(5)
    fail_rva = hook1_rva + 10 + fail_rel

    # Search +0x60..+0x160 after hook1_rva for tnLen read + seekg + ptrSize + addrCount
    w2_start = (hook1_rva - text_va) + 0x60
    w2_end = min(len(text), w2_start + 0x180)
    w2 = text[w2_start:w2_end]
    m_tn = re.search(
        rb"(\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24.)"
        + re.escape(file_lea)
        + rb"(?:\xE8|\xFF\x15).{4}.{0,16}?\x3D\xFF\xFF\x00\x00\x0F\x87.{4}.{0,16}?\x41\xB8\x01\x00\x00\x00"
        + re.escape(file_lea)
        + rb"(\xE8|\xFF\x15)(....)\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24(.)"
        + re.escape(file_lea)
        + rb"(?:\xE8|\xFF\x15).{4}.{0,16}?\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24(.)",
        w2,
        re.DOTALL,
    )
    if not m_tn:
        return None
    hook2_rva = text_va + w2_start + m_tn.start(1)
    hook2_orig = m_tn.group(1)
    tn_len_disp = hook2_orig[-1]
    seekg_is_iat = m_tn.group(2) == b"\xFF\x15"
    seekg_call_rva = text_va + w2_start + m_tn.start(2)
    seekg_len = 6 if seekg_is_iat else 5
    seekg_fn_rva = seekg_call_rva + seekg_len + struct.unpack("<i", m_tn.group(3))[0]
    ptr_size_disp = m_tn.group(4)[0]
    cnt_disp = m_tn.group(5)[0]
    scratch_disp = next((d for d in (fmt_disp, ptr_size_disp, tn_len_disp) if d != cnt_disp), 0x7C)

    # Search +0x0..+0x60 after cnt_disp for m_data.reserve(addrCount) call
    m_res = re.search(rb"\x49\x8B\xCE\xE8(....)", w2[m_tn.end() : min(len(w2), m_tn.end() + 0x60)])
    if not m_res:
        return None
    reserve_call_rva = text_va + w2_start + m_tn.end() + m_res.start() + 3
    reserve_fn_rva = reserve_call_rva + 5 + struct.unpack("<i", m_res.group(1))[0]

    # Search +0x250..+0x580 after hook1_rva for the post-loop std::sort epilogue (done_rva)
    w3_start = (hook1_rva - text_va) + 0x250
    w3_end = min(len(text), w3_start + 0x350)
    w3 = text[w3_start:w3_end]
    m3 = re.search(rb"\x49\x8B\x56\x08\x49\x8B\x0E\x4C\x8B\xC2\x4C\x2B\xC1\x49\xC1\xF8\x04", w3)
    if not m3:
        return None
    done_rva = text_va + w3_start + m3.start()

    # Find free padding at the end of .text; if < 192 bytes, use the Format 2 loop body for v5_loader
    text_end_off = text_rptr + text_rsize
    last_used = text_end_off - 1
    while last_used > text_rptr and data[last_used] in (0x00, 0xCC):
        last_used -= 1
    cave_off = (last_used + 16) & ~0xF
    avail = text_end_off - cave_off
    cave_rva = text_va + (cave_off - text_rptr)
    in_loop_cave = avail < 192
    if in_loop_cave:
        if avail < 16 or (done_rva - (reserve_call_rva + 5)) < 140:
            return None
        loop_cave_rva = reserve_call_rva + 5
    else:
        loop_cave_rva = 0

    return {
        "hook1_rva": hook1_rva,
        "cmp_bytes": cmp_bytes,
        "fmt_disp": fmt_disp,
        "file_lea": file_lea,
        "read_fn_rva": read_fn_rva,
        "read_is_iat": read_is_iat,
        "seekg_fn_rva": seekg_fn_rva,
        "seekg_is_iat": seekg_is_iat,
        "fail_rva": fail_rva,
        "hook2_rva": hook2_rva,
        "hook2_orig": hook2_orig,
        "cnt_disp": cnt_disp,
        "scratch_disp": scratch_disp,
        "reserve_fn_rva": reserve_fn_rva,
        "done_rva": done_rva,
        "cave_rva": cave_rva,
        "cave_off": cave_off,
        "avail": avail,
        "in_loop_cave": in_loop_cave,
        "loop_cave_rva": loop_cave_rva,
        "text_va": text_va,
        "text_vsize": text_vsize,
        "text_rsize": text_rsize,
        "text_rptr": text_rptr,
    }


def apply_versiondb_v5_patch(
    raw: bytearray,
    e_lfanew: int,
    info: Dict[str, object],
) -> int:
    """Assemble and inject the Format 5 loader code cave into `raw`. Returns cave byte size."""
    cave_rva = int(info["cave_rva"])
    text_va = int(info["text_va"])
    text_rptr = int(info["text_rptr"])

    def rva_to_off(rva: int) -> int:
        return text_rptr + (rva - text_va)

    def rel32(src_rva: int, dst_rva: int, instr_len: int = 5) -> bytes:
        return struct.pack("<i", dst_rva - (src_rva + instr_len))

    code = bytearray()

    def cur_rva() -> int:
        return cave_rva + len(code)

    hook1_rva = int(info["hook1_rva"])
    cmp_bytes = bytes(info["cmp_bytes"])
    fmt_disp = int(info["fmt_disp"])
    file_lea = bytes(info["file_lea"])
    read_fn_rva = int(info["read_fn_rva"])
    read_is_iat = bool(info.get("read_is_iat", False))
    seekg_fn_rva = int(info["seekg_fn_rva"])
    seekg_is_iat = bool(info.get("seekg_is_iat", False))

    def emit_call(target_rva: int, is_iat: bool) -> bytes:
        if is_iat:
            return b"\xFF\x15" + rel32(cur_rva(), target_rva, 6)
        return b"\xE8" + rel32(cur_rva(), target_rva, 5)
    fail_rva = int(info["fail_rva"])
    hook2_rva = int(info["hook2_rva"])
    hook2_orig = bytes(info["hook2_orig"])
    cnt_disp = int(info["cnt_disp"])
    scratch_disp = int(info.get("scratch_disp", 0x7C))
    reserve_fn_rva = int(info["reserve_fn_rva"])
    done_rva = int(info["done_rva"])
    in_loop_cave = bool(info.get("in_loop_cave", False))

    if in_loop_cave:
        # Compact mode: tiny 16-byte format==5 check in .text tail, Format 5 loader in Format 2 loop body
        part1_rva = cur_rva()
        code += b"\x83\x7C\x24" + bytes([fmt_disp, 5])
        jne_pos = cur_rva()
        code += b"\x0F\x85" + rel32(jne_pos, fail_rva, 6)
        jmp_back_pos = cur_rva()
        code += b"\xE9" + rel32(jmp_back_pos, hook1_rva + 10, 5)
        assert len(code) <= int(info["avail"])
        cave_off = int(info["cave_off"])
        raw[cave_off : cave_off + len(code)] = code

        h1_off = rva_to_off(hook1_rva)
        raw[h1_off : h1_off + 10] = b"\xE9" + rel32(hook1_rva, part1_rva, 5) + b"\x90" * 5

        loop_cave_rva = int(info["loop_cave_rva"])
        lc = bytearray()
        def lc_rva() -> int: return loop_cave_rva + len(lc)
        def emit_lc_call(target_rva: int, is_iat: bool) -> bytes:
            if is_iat:
                return b"\xFF\x15" + rel32(lc_rva(), target_rva, 6)
            return b"\xE8" + rel32(lc_rva(), target_rva, 5)

        # At hook2_rva (tnLen read): skip 0x48 bytes, read offsetCount, jump to loop_cave_rva
        lc += b"\xBA\x48\x00\x00\x00\x41\xB8\x01\x00\x00\x00" + file_lea + emit_lc_call(seekg_fn_rva, seekg_is_iat)
        lc += b"\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24" + bytes([cnt_disp]) + file_lea + emit_lc_call(read_fn_rva, read_is_iat)
        lc += b"\x83\x7C\x24" + bytes([cnt_disp, 0])
        jle_pos = lc_rva()
        lc += b"\x0F\x8E" + rel32(jle_pos, done_rva, 6)
        lc += b"\x48\x63\x54\x24" + bytes([cnt_disp]) + b"\x49\x8B\xCE"
        res_pos = lc_rva()
        lc += b"\xE8" + rel32(res_pos, reserve_fn_rva, 5)
        lc += b"\x33\xFF"
        l_start = lc_rva()
        lc += b"\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24" + bytes([scratch_disp]) + file_lea + emit_lc_call(read_fn_rva, read_is_iat)
        lc += b"\x8B\x44\x24" + bytes([scratch_disp]) + b"\x85\xC0"
        jz_pos = lc_rva()
        lc += b"\x74\x00\x49\x8B\x56\x08\x48\x89\x3A\x48\x89\x42\x08\x49\x83\x46\x08\x10"
        nxt_rva = lc_rva()
        lc[jz_pos - loop_cave_rva + 1] = nxt_rva - (jz_pos + 2)
        lc += b"\xFF\xC7\x3B\x7C\x24" + bytes([cnt_disp])
        jl_pos = lc_rva()
        lc += b"\x7C" + struct.pack("b", l_start - (jl_pos + 2))
        jd_pos = lc_rva()
        lc += b"\xE9" + rel32(jd_pos, done_rva, 5)
        assert len(lc) <= (done_rva - loop_cave_rva)
        raw[rva_to_off(loop_cave_rva) : rva_to_off(loop_cave_rva) + len(lc)] = lc

        h2_off = rva_to_off(hook2_rva)
        raw[h2_off : h2_off + 11] = b"\xE9" + rel32(hook2_rva, loop_cave_rva, 5) + b"\x90" * 6

        needed_vsize = (cave_rva - text_va) + len(code)
        if needed_vsize > int(info["text_vsize"]):
            opt_size = struct.unpack_from("<H", raw, e_lfanew + 20)[0]
            sec0_off = e_lfanew + 24 + opt_size
            struct.pack_into("<I", raw, sec0_off + 8, min(int(info["text_rsize"]), needed_vsize))
        return len(code) + len(lc)

    # Part 1: Format check (hooked from hook1_rva)
    part1_rva = cur_rva()
    code += b"\x45\x33\xED"                                 # xor r13d, r13d
    code += cmp_bytes                                       # cmp dword ptr [rsp+fmt], reg
    code += b"\x74\x0E"                                     # je jmp_back
    code += b"\x83\x7C\x24" + bytes([fmt_disp, 5])          # cmp dword ptr [rsp+fmt], 5
    jne_pos = cur_rva()
    code += b"\x0F\x85" + rel32(jne_pos, fail_rva, 6)       # jne fail_rva
    code += b"\x41\xB5\x01"                                 # mov r13b, 1
    jmp_back_pos = cur_rva()
    code += b"\xE9" + rel32(jmp_back_pos, hook1_rva + 10, 5)

    # Part 2: Post-tnLen dispatch (hooked from hook2_rva)
    part2_rva = cur_rva()
    code += b"\x45\x85\xED"                                 # test r13d, r13d
    jnz_v5_pos = cur_rva()
    code += b"\x75\x00"                                     # jnz v5_loader
    code += hook2_orig                                      # original mov r8d,4; lea rdx,[rsp+ptr]
    jmp_v2_pos = cur_rva()
    code += b"\xE9" + rel32(jmp_v2_pos, hook2_rva + 11, 5)

    # Format 5 loader:
    # Format 5 header after ver[0..3]: char module_name[64] + int32 ptrSize + int32 dataFormat = 72 (0x48) bytes
    v5_loader_rva = cur_rva()
    code[jnz_v5_pos - cave_rva + 1] = v5_loader_rva - (jnz_v5_pos + 2)
    code += b"\xBA\x48\x00\x00\x00"                         # mov edx, 48h (72 bytes)
    code += b"\x41\xB8\x01\x00\x00\x00"                     # mov r8d, 1 (ios::cur)
    code += file_lea                                        # lea rcx, [rbp+file]
    code += emit_call(seekg_fn_rva, seekg_is_iat)           # call istream::seekg
    code += b"\x41\xB8\x04\x00\x00\x00"                     # mov r8d, 4
    code += b"\x48\x8D\x54\x24" + bytes([cnt_disp])         # lea rdx, [rsp+cnt]
    code += file_lea                                        # lea rcx, [rbp+file]
    code += emit_call(read_fn_rva, read_is_iat)             # call istream::read
    code += b"\x83\x7C\x24" + bytes([cnt_disp, 0])          # cmp dword ptr [rsp+cnt], 0
    jle_done_pos = cur_rva()
    code += b"\x0F\x8E" + rel32(jle_done_pos, done_rva, 6)  # jle done_rva
    code += b"\x48\x63\x54\x24" + bytes([cnt_disp])         # movsxd rdx, dword ptr [rsp+cnt]
    code += b"\x49\x8B\xCE"                                 # mov rcx, r14
    call_res_pos = cur_rva()
    code += b"\xE8" + rel32(call_res_pos, reserve_fn_rva, 5)# call m_data.reserve(offsetCount)
    code += b"\x33\xFF"                                     # xor edi, edi

    loop_rva = cur_rva()
    code += b"\x41\xB8\x04\x00\x00\x00"                     # mov r8d, 4
    code += b"\x48\x8D\x54\x24" + bytes([scratch_disp])     # lea rdx, [rsp+scratch]
    code += file_lea                                        # lea rcx, [rbp+file]
    code += emit_call(read_fn_rva, read_is_iat)             # call istream::read
    code += b"\x8B\x44\x24" + bytes([scratch_disp])         # mov eax, dword ptr [rsp+scratch]
    code += b"\x85\xC0"                                     # test eax, eax
    jz_next_pos = cur_rva()
    code += b"\x74\x00"                                     # jz next_id
    code += b"\x49\x8B\x56\x08"                             # mov rdx, qword ptr [r14+8]
    code += b"\x48\x89\x3A"                                 # mov qword ptr [rdx], rdi
    code += b"\x48\x89\x42\x08"                             # mov qword ptr [rdx+8], rax
    code += b"\x49\x83\x46\x08\x10"                         # add qword ptr [r14+8], 10h

    next_rva = cur_rva()
    code[jz_next_pos - cave_rva + 1] = next_rva - (jz_next_pos + 2)
    code += b"\xFF\xC7"                                     # inc edi
    code += b"\x3B\x7C\x24" + bytes([cnt_disp])             # cmp edi, dword ptr [rsp+cnt]
    jl_loop_pos = cur_rva()
    code += b"\x7C" + struct.pack("b", loop_rva - (jl_loop_pos + 2))
    jmp_done_pos = cur_rva()
    code += b"\xE9" + rel32(jmp_done_pos, done_rva, 5)

    assert len(code) <= int(info["avail"])
    cave_off = int(info["cave_off"])
    raw[cave_off : cave_off + len(code)] = code

    h1_off = rva_to_off(hook1_rva)
    raw[h1_off : h1_off + 10] = b"\xE9" + rel32(hook1_rva, part1_rva, 5) + b"\x90" * 5

    h2_off = rva_to_off(hook2_rva)
    raw[h2_off : h2_off + 11] = b"\xE9" + rel32(hook2_rva, part2_rva, 5) + b"\x90" * 6

    # Extend .text VirtualSize to cover the code cave (within RawSize)
    needed_vsize = (cave_rva - text_va) + len(code)
    if needed_vsize > int(info["text_vsize"]):
        opt_size = struct.unpack_from("<H", raw, e_lfanew + 20)[0]
        sec0_off = e_lfanew + 24 + opt_size
        struct.pack_into("<I", raw, sec0_off + 8, min(int(info["text_rsize"]), needed_vsize))

    return len(code)


def find_commonlib_minor6_rva(
    data: bytes,
    sections: List[Tuple[str, int, int, int, int]],
) -> Optional[int]:
    """Find CommonLibSSE-NG `REL::Module::load_segments` `cmp ax, 6; setne al` bug."""
    if not sections or sections[0][0] != ".text":
        return None
    _, _, text_va, text_rsize, text_rptr = sections[0]
    text = data[text_rptr : text_rptr + text_rsize]
    m_rt = re.search(rb"\x66\x83\xF8\x06(\x0F\x95\xC0)\xFE\xC0\x88", text)
    return (text_va + m_rt.start(1)) if m_rt else None


def find_commonlib_v5_target(
    data: bytes,
    e_lfanew: int,
    sections: List[Tuple[str, int, int, int, int]],
) -> Optional[Dict[str, object]]:
    """Locate CommonLibSSE `REL::IDDatabase::load_file` & `unpack_file` in `.text`."""
    if not sections:
        return None
    text_name, text_vsize, text_va, text_rsize, text_rptr = sections[0]
    if text_name != ".text":
        return None

    def off_to_rva(off: int) -> Optional[int]:
        for _, vs, va, rs, rp in sections:
            if rp <= off < rp + rs:
                return va + (off - rp)
        return None

    str_off = data.find(b"Unsupported address library format")
    if str_off == -1:
        return None
    str_rva = off_to_rva(str_off)
    if str_rva is None:
        return None

    text = data[text_rptr : text_rptr + text_rsize]
    err_xref_rva = None
    for i in range(len(text) - 7):
        if text[i] in (0x48, 0x4C) and text[i + 1] == 0x8D and (text[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", text, i + 3)[0]
            if text_va + i + 7 + disp == str_rva:
                err_xref_rva = text_va + i
                break
    if err_xref_rva is None:
        return None

    # Search -0x780..-0x300 before err_xref_rva for format read + cmp + jne
    w1_start = max(0, (err_xref_rva - text_va) - 0x780)
    w1_end = max(0, (err_xref_rva - text_va) - 0x300)
    w1 = text[w1_start:w1_end]
    m1 = re.search(
        rb"\x41\xB8\x04\x00\x00\x00(\x48\x8D(?:[\x54]\x24.|\x94\x24.{4}))\x48\x8D(?:[\x4C\x4D].|[\x8C\x8D]\x24.{4}|[\x4C]\x24.)\xE8(....)(\x39(?:[\x44\x4C\x54\x5C\x64\x6C\x74\x7C]\x24.|[\x84\x8C\x94\x9C\xA4\xAC\xB4\xBC]\x24.{4}))\x0F\x85(....)",
        w1,
        re.DOTALL,
    )
    if not m1:
        if re.search(
            rb"\x41\xB8\x04\x00\x00\x00\x48\x8D(?:[\x54]\x24.|\x94\x24.{4})\x48\x8D(?:[\x4C\x4D].|[\x8C\x8D]\x24.{4}|[\x4C]\x24.)\xE8.{4}\xE9.{4}\x90{5}",
            w1,
            re.DOTALL,
        ) or (
            b"\x49\xC7\x47\x08\x00\x00\x00\x00\x49\x89\x3F" in text
            or b"\xC7\x45\xC0\x00\x00\x00\x00\x41\xB8\x04\x00\x00\x00\x48\x8D\x55\xC0" in text
        ):
            return {"already_patched": True, "loader": "REL::IDDatabase"}
        return None

    rdx_lea = m1.group(1)
    fmt_disp_bytes = rdx_lea[4:]
    fmt_is_disp32 = len(fmt_disp_bytes) == 4
    fmt_disp = struct.unpack("<i", fmt_disp_bytes)[0] if fmt_is_disp32 else fmt_disp_bytes[0]
    hook1_rva = text_va + w1_start + m1.start(3)
    hook1_len = m1.end(4) - m1.start(3)  # exact length of cmp + jne (0F 85 + rel32)
    jne_rel = struct.unpack("<i", m1.group(4))[0]
    err_target_rva = hook1_rva + hook1_len + jne_rel

    # Search +0x18..+0xD0 after hook1_rva for tnLen read + ignore(tnLen) + ptrSize read
    w2_start = (hook1_rva - text_va) + 0x18
    w2_end = min(len(text), w2_start + 0xC0)
    w2 = text[w2_start:w2_end]
    m2 = re.search(
        rb"(\x41\xB8\x04\x00\x00\x00\x48\x8D(?:[\x54]\x24.|\x94\x24.{4})\x48\x8D(?:[\x4C]\x24.|\x8C\x24.{4})\xE8.{4}.{0,16}?\x41\xB8\xFF\xFF\xFF\xFF(\x48\x8D(?:[\x4C]\x24.|\x8C\x24.{4}))\xE8(....)\x41\xB8\x04\x00\x00\x00\x48\x8D(?:[\x54]\x24.|\x94\x24.{4})\x48\x8D(?:[\x4C]\x24.|\x8C\x24.{4})\xE8.{4})\x41\xB8\x04\x00\x00\x00\x48\x8D(?:[\x54]\x24.|\x94\x24.{4})",
        w2,
        re.DOTALL,
    )
    if not m2:
        return None
    ptr_read_rva = text_va + w2_start + m2.start(1)
    ptr_read_len = len(m2.group(1))
    file_rcx_lea = m2.group(2)
    ignore_call_rva = text_va + w2_start + m2.start(3) - 1
    ignore_fn_rva = ignore_call_rva + 5 + struct.unpack("<i", m2.group(3))[0]

    # Search +0x2C0..+0x480 after hook1_rva for call unpack_file
    w3_start = (hook1_rva - text_va) + 0x2C0
    w3_end = min(len(text), w3_start + 0x200)
    w3 = text[w3_start:w3_end]
    m3 = re.search(
        rb"\x44\x0F\xB6\x8C\x24.{4}\x4C\x8D\x44\x24.\x48\x8D\x94\x24.{4}\x48\x8B.\xE8(....)",
        w3,
        re.DOTALL,
    )
    if not m3:
        return None
    unpack_call_rva = text_va + w3_start + m3.start(1) - 1
    unpack_rva = unpack_call_rva + 5 + struct.unpack("<i", m3.group(1))[0]

    # Inspect unpack_file for r15=[rcx+10h], r12=[rcx+18h], cmp r15,r12; je epilogue
    u_start = unpack_rva - text_va
    u_win = text[u_start : min(len(text), u_start + 0x80)]
    mu = re.search(
        rb"\x4C\x8B\x79\x10.{0,12}?\x4C\x8B\x61\x18.{0,48}?\x4D\x3B\xFC\x0F\x84(....)",
        u_win,
        re.DOTALL,
    )
    if not mu:
        return None
    epilogue_rva = unpack_rva + mu.end() + struct.unpack("<i", mu.group(1))[0]
    loop_start_rva = unpack_rva + mu.end()
    # Align loop_start_rva past optional 2-byte nop (66 90)
    if text[loop_start_rva - text_va : loop_start_rva - text_va + 2] == b"\x66\x90":
        loop_start_rva += 2

    # Find read_fn_rva inside unpack_file's first call
    ml = re.search(rb"\x41\xB8\x01\x00\x00\x00\x48\x8D\x55.\x48\x8B\xCB\xE8(....)", text[loop_start_rva - text_va : loop_start_rva - text_va + 0x30])
    if not ml:
        return None
    read_call_rva = loop_start_rva + ml.start(1) - 1
    read_fn_rva = read_call_rva + 5 + struct.unpack("<i", ml.group(1))[0]

    # Find free padding at end of .text for format==5 check cave (19 bytes for disp32, 16 for disp8)
    text_end_off = text_rptr + text_rsize
    last_used = text_end_off - 1
    while last_used > text_rptr and data[last_used] in (0x00, 0xCC):
        last_used -= 1
    cave_off = (last_used + 16) & ~0xF
    avail = text_end_off - cave_off
    needed_cave = 19 if fmt_is_disp32 else 16
    if avail < needed_cave:
        return None
    cave_rva = text_va + (cave_off - text_rptr)

    # Find REL::Module::load_segments minor-version AE check:
    #   66 83 F8 06  (cmp ax, 6)
    #   0F 95 C0     (setne al) -> patch to 0F 92 C0 (setb al) so 1.7.x+ is AE, not SE!
    #   FE C0        (inc al)
    #   88 .. 18 01 00 00 (mov [reg+118h], al)
    m_rt = re.search(rb"\x66\x83\xF8\x06(\x0F\x95\xC0)\xFE\xC0\x88", text)
    rt_setne_rva = (text_va + m_rt.start(1)) if m_rt else None

    return {
        "hook1_rva": hook1_rva,
        "hook1_len": hook1_len,
        "fmt_disp": fmt_disp,
        "fmt_is_disp32": fmt_is_disp32,
        "err_target_rva": err_target_rva,
        "ptr_read_rva": ptr_read_rva,
        "ptr_read_len": ptr_read_len,
        "file_rcx_lea": file_rcx_lea,
        "ignore_fn_rva": ignore_fn_rva,
        "loop_start_rva": loop_start_rva,
        "epilogue_rva": epilogue_rva,
        "read_fn_rva": read_fn_rva,
        "cave_rva": cave_rva,
        "cave_off": cave_off,
        "avail": avail,
        "rt_setne_rva": rt_setne_rva,
        "text_va": text_va,
        "text_vsize": text_vsize,
        "text_rsize": text_rsize,
        "text_rptr": text_rptr,
    }


def apply_commonlib_v5_patch(
    raw: bytearray,
    e_lfanew: int,
    info: Dict[str, object],
) -> int:
    """Patch CommonLibSSE `REL::IDDatabase` for Format 5. Returns total bytes patched."""
    text_va = int(info["text_va"])
    text_rptr = int(info["text_rptr"])

    def rva_to_off(rva: int) -> int:
        return text_rptr + (rva - text_va)

    def rel32(src_rva: int, dst_rva: int, instr_len: int = 5) -> bytes:
        return struct.pack("<i", dst_rva - (src_rva + instr_len))

    cave_rva = int(info["cave_rva"])
    hook1_rva = int(info["hook1_rva"])
    hook1_len = int(info["hook1_len"])
    fmt_disp = int(info["fmt_disp"])
    fmt_is_disp32 = bool(info["fmt_is_disp32"])
    err_target_rva = int(info["err_target_rva"])

    cave = bytearray()
    if fmt_is_disp32:
        cave += b"\x83\xBC\x24" + struct.pack("<i", fmt_disp) + b"\x05"  # cmp dword ptr [rsp+disp32], 5
    else:
        cave += b"\x83\x7C\x24" + bytes([fmt_disp, 5])                # cmp dword ptr [rsp+disp8], 5
    cave += b"\x0F\x85" + rel32(cave_rva + len(cave), err_target_rva, 6)
    cave += b"\xE9" + rel32(cave_rva + len(cave), hook1_rva + hook1_len, 5)
    if "avail" in info:
        assert len(cave) <= int(info["avail"])
    cave_off = int(info["cave_off"])
    raw[cave_off : cave_off + len(cave)] = cave

    h1_off = rva_to_off(hook1_rva)
    raw[h1_off : h1_off + hook1_len] = b"\xE9" + rel32(hook1_rva, cave_rva, 5) + b"\x90" * (hook1_len - 5)

    ptr_rva = int(info["ptr_read_rva"])
    ptr_off = rva_to_off(ptr_rva)
    ptr_len = int(info["ptr_read_len"])
    file_rcx_lea = bytes(info["file_rcx_lea"])
    ignore_fn_rva = int(info["ignore_fn_rva"])
    skip72 = bytearray()
    skip72 += b"\xBA\x48\x00\x00\x00"                                 # mov edx, 48h (72 bytes)
    skip72 += b"\x41\xB8\xFF\xFF\xFF\xFF"                             # mov r8d, -1
    skip72 += file_rcx_lea                                            # lea rcx, [rsp+file]
    skip72 += b"\xE8" + rel32(ptr_rva + len(skip72), ignore_fn_rva, 5)
    assert len(skip72) <= ptr_len
    raw[ptr_off : ptr_off + ptr_len] = skip72 + b"\x90" * (ptr_len - len(skip72))

    u_rva = int(info["loop_start_rva"])
    read_fn_rva = int(info["read_fn_rva"])
    epilogue_rva = int(info["epilogue_rva"])

    loop = bytearray()
    loop += b"\x49\xC7\x47\x08\x00\x00\x00\x00"                     # mov qword ptr [r15+8], 0
    loop += b"\x49\x89\x3F"                                         # mov qword ptr [r15], rdi
    loop += b"\x41\xB8\x04\x00\x00\x00"                             # mov r8d, 4
    loop += b"\x49\x8D\x57\x08"                                     # lea rdx, [r15+8]
    loop += b"\x48\x8B\xCB"                                         # mov rcx, rbx
    loop += b"\xE8" + rel32(u_rva + len(loop), read_fn_rva, 5)      # call istream::read
    loop += b"\x49\x83\xC7\x10"                                     # add r15, 10h
    loop += b"\x48\xFF\xC7"                                         # inc rdi
    loop += b"\x4D\x3B\xFC"                                         # cmp r15, r12
    loop += b"\x72" + struct.pack("b", -(len(loop) + 2))            # jb loop
    loop += b"\xE9" + rel32(u_rva + len(loop), epilogue_rva, 5)     # jmp epilogue
    assert len(loop) <= (epilogue_rva - u_rva)

    u_off = rva_to_off(u_rva)
    raw[u_off : u_off + len(loop)] = loop

    rt_setne_rva = info.get("rt_setne_rva")
    if rt_setne_rva is not None:
        rt_off = rva_to_off(int(rt_setne_rva))
        if raw[rt_off : rt_off + 3] == b"\x0F\x95\xC0":
            raw[rt_off + 1] = 0x92  # setne al -> setb al (1.7.x+ => AE)

    needed_vsize = (cave_rva - text_va) + len(cave)
    if needed_vsize > int(info["text_vsize"]):
        opt_size = struct.unpack_from("<H", raw, e_lfanew + 20)[0]
        sec0_off = e_lfanew + 24 + opt_size
        struct.pack_into("<I", raw, sec0_off + 8, min(int(info["text_rsize"]), needed_vsize))

    return len(cave) + len(loop)


def patch_dll(
    input_path: Path,
    output_path: Optional[Path] = None,
    in_place: bool = False,
    dry_run: bool = False,
    add_structs_post629: bool = False,
    add_versions: Optional[List[str]] = None,
    patch_v5_loader: bool = True,
    make_zip: bool = False,
    target_runtime: Optional[str] = None,
) -> int:
    input_path = input_path.resolve()
    if not input_path.exists():
        print(f"[ERROR] File not found: {input_path}", file=sys.stderr)
        return 1

    target_dot = target_runtime or skse_env.get_default_target_dot()
    target_tuple = skse_env.parse_version_tuple(target_dot)

    raw = bytearray(input_path.read_bytes())
    try:
        e_lfanew, sections, exports = parse_pe64_sections_and_exports(bytes(raw))
    except PEError as exc:
        print(f"[ERROR] PE parse failed: {exc}", file=sys.stderr)
        return 1

    if "SKSEPlugin_Version" not in exports:
        print("[ERROR] DLL does not export `SKSEPlugin_Version`.", file=sys.stderr)
        if "SKSEPlugin_Query" in exports:
            print(
                "        It exports legacy `SKSEPlugin_Query` (pre-AE 1.5.97 style). "
                "A binary metadata patch cannot convert `SKSEPlugin_Query` to `SKSEPlugin_Version`.",
                file=sys.stderr,
            )
        return 1

    ver_rva = exports["SKSEPlugin_Version"]
    ver_off = rva_to_file_offset(ver_rva, sections)
    if ver_off is None or ver_off + SKSE_PLUGIN_VERSION_SIZE > len(raw):
        print(f"[ERROR] Cannot map `SKSEPlugin_Version` RVA 0x{ver_rva:X} to a valid file range.", file=sys.stderr)
        return 1

    data_ver, plugin_ver = struct.unpack_from("<II", raw, ver_off)
    name = raw[ver_off + 0x008 : ver_off + 0x108].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    author = raw[ver_off + 0x108 : ver_off + 0x208].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    ver_indep_ex, ver_indep = struct.unpack_from("<II", raw, ver_off + 0x304)
    compat_versions = list(struct.unpack_from("<16I", raw, ver_off + 0x30C))
    se_req = struct.unpack_from("<I", raw, ver_off + 0x34C)[0]

    print(f"=== SKSE64 Fallback Binary Patcher ===")
    print(f"Input                 : {input_path}")
    print(f"Plugin Name           : {name!r} (v{plugin_ver}, author={author!r})")
    print(f"SKSEPlugin_Version    : RVA=0x{ver_rva:X}, FileOffset=0x{ver_off:X}, dataVersion={data_ver}")
    print(f"versionIndependence   : 0x{ver_indep:08X}")
    print(f"versionIndependenceEx : 0x{ver_indep_ex:08X}")
    print(f"seVersionRequired     : {verify_dll.unpack_skse_version(se_req)} (0x{se_req:08X})")
    nonzero_compat = [verify_dll.unpack_skse_version(v) for v in compat_versions if v != 0]
    print(f"compatibleVersions    : {nonzero_compat or '(none)'}")

    diag = scan_binary_diagnostics(bytes(raw))
    if diag["address_library"]:
        print("Address Library hints :")
        for m in diag["address_library"]:
            print(f"  - {m}")
    if diag["vtable_or_struct_risks"]:
        print("[WARN] Potential 1.7.99+ layout/VTable symbols detected in strings:")
        for m in diag["vtable_or_struct_risks"]:
            print(f"  - {m}")
        print("  Note: A metadata patch does NOT fix VTable slot shifts or struct layout changes.")

    new_ver_indep_ex = ver_indep_ex | kVersionIndependentEx_AddressLibraryV5
    new_ver_indep = ver_indep | (kVersionIndependent_StructsPost629 if add_structs_post629 else 0)
    new_compat = list(compat_versions)

    if add_versions:
        for vs in add_versions:
            packed = parse_version_str(vs)
            if packed not in new_compat:
                try:
                    slot = new_compat.index(0)
                    new_compat[slot] = packed
                except ValueError:
                    print(f"[WARN] compatibleVersions[16] is full; could not append {vs}.", file=sys.stderr)

    changed = (
        new_ver_indep_ex != ver_indep_ex
        or new_ver_indep != ver_indep
        or new_compat != compat_versions
    )

    v5_info = find_versiondb_v5_target(bytes(raw), e_lfanew, sections) if patch_v5_loader else None
    clib_v5_info = find_commonlib_v5_target(bytes(raw), e_lfanew, sections) if (patch_v5_loader and v5_info is None) else None
    minor6_rva = find_commonlib_minor6_rva(bytes(raw), sections)

    v5_already = bool(v5_info and v5_info.get("already_patched"))
    if v5_already:
        v5_info = None
    clib_already = bool(clib_v5_info and clib_v5_info.get("already_patched"))
    if clib_already:
        clib_v5_info = None

    if not changed and v5_info is None and clib_v5_info is None and minor6_rva is None:
        if v5_already or clib_already:
            print("\n[OK] Binary already has AddressLibraryV5 and Format 5 loader patch. No byte changes needed.")
        else:
            print("\n[INFO] Binary already has the requested SKSEPlugin_Version flags/versions. No byte changes needed.")
    else:
        print("\nPlanned patches:")
        if new_ver_indep_ex != ver_indep_ex:
            print(f"  - versionIndependenceEx : 0x{ver_indep_ex:08X} -> 0x{new_ver_indep_ex:08X} (+AddressLibraryV5)")
        if new_ver_indep != ver_indep:
            print(f"  - versionIndependence   : 0x{ver_indep:08X} -> 0x{new_ver_indep:08X} (+StructsPost629)")
        if new_compat != compat_versions:
            new_nonzero = [verify_dll.unpack_skse_version(v) for v in new_compat if v != 0]
            print(f"  - compatibleVersions    : {nonzero_compat} -> {new_nonzero}")
        if v5_info is not None:
            print(
                f"  - versiondb::Load       : Format 5 code cave @ RVA 0x{v5_info['cave_rva']:X} "
                f"(hooks @ 0x{v5_info['hook1_rva']:X}, 0x{v5_info['hook2_rva']:X})"
            )
        elif clib_v5_info is not None:
            print(
                f"  - REL::IDDatabase       : Format 5 patch (format @ 0x{clib_v5_info['hook1_rva']:X}, "
                f"unpack @ 0x{clib_v5_info['loop_start_rva']:X}, cave @ 0x{clib_v5_info['cave_rva']:X})"
            )
            print("                            Note: CommonLibSSE REL::IDDatabase binary patch supports Format 5 (1.7.99+) only.")
        elif v5_already or clib_already:
            print("  - Address Library loader: [OK] Already patched for Format 5")
        elif patch_v5_loader:
            print("  - Address Library loader: [SKIP] signature not found (already patched or unsupported loader)")
        if minor6_rva is not None:
            print(f"  - REL::Module::runtime  : Patch `setne al` -> `setb al` @ RVA 0x{minor6_rva:X} (1.7.x+ => AE)")

    if dry_run:
        print("\n[DRY-RUN] No files written.")
        return 0

    struct.pack_into("<II", raw, ver_off + 0x304, new_ver_indep_ex, new_ver_indep)
    struct.pack_into("<16I", raw, ver_off + 0x30C, *new_compat)
    if v5_info is not None:
        cave_bytes = apply_versiondb_v5_patch(raw, e_lfanew, v5_info)
        print(f"Injected Format 5 cave: {cave_bytes} bytes @ RVA 0x{v5_info['cave_rva']:X}")
    elif clib_v5_info is not None:
        patched_bytes = apply_commonlib_v5_patch(raw, e_lfanew, clib_v5_info)
        print(f"Patched IDDatabase v5 : {patched_bytes} bytes (Format 5 / 1.7.99+ only)")
    if minor6_rva is not None:
        rt_off = rva_to_file_offset(minor6_rva, sections)
        if rt_off is not None and raw[rt_off : rt_off + 3] == b"\x0F\x95\xC0":
            raw[rt_off + 1] = 0x92
            print(f"Patched 1.7.x AE check: RVA 0x{minor6_rva:X}")
    # Zero OptionalHeader CheckSum (opt_offset + 64) so stale checksum is never flagged
    struct.pack_into("<I", raw, e_lfanew + 0x18 + 64, 0)

    if in_place:
        backup_path = input_path.with_suffix(input_path.suffix + ".bak")
        if not backup_path.exists():
            shutil.copy2(input_path, backup_path)
            print(f"Backup created        : {backup_path}")
        dest = input_path
    elif output_path is not None:
        dest = output_path.resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
    else:
        suffix = (
            f"_{target_tuple[0]}_{target_tuple[1]}_{target_tuple[2]}"
            if target_tuple[3] == 0
            else f"_{target_tuple[0]}_{target_tuple[1]}_{target_tuple[2]}_{target_tuple[3]}"
        )
        dest = input_path.with_name(f"{input_path.stem}{suffix}{input_path.suffix}")

    dest.write_bytes(bytes(raw))
    print(f"Wrote patched DLL     : {dest}\n")

    res = verify_dll.verify_dll(dest, target_runtime=target_dot)
    verify_dll.print_verification(res)

    if make_zip and res["passed_target"]:
        mod_name = name or input_path.stem
        zip_path = (SCRIPTS_DIR.parent / "dist" / f"{mod_name}_Updated.zip").resolve()
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(dest, f"SKSE/Plugins/{dest.name}")
        print(f"Packaged ZIP archive  : {zip_path}")

    return 0 if res["passed_target"] else 2


def batch_patch(
    target_dir: Path,
    dry_run: bool = False,
    in_place: bool = False,
    add_structs_post629: bool = False,
    add_versions: Optional[List[str]] = None,
    patch_v5_loader: bool = True,
    make_zip: bool = False,
    target_runtime: Optional[str] = None,
) -> int:
    """Scan or patch all SKSE64 plugin `.dll` files in `target_dir`."""
    dlls = sorted(target_dir.rglob("*.dll"))
    if not dlls:
        print(f"[INFO] No .dll files found in {target_dir}")
        return 0
    print(f"Scanning {len(dlls)} DLL(s) in {target_dir}...\n")
    rc = 0
    for dll in dlls:
        res = patch_dll(
            input_path=dll,
            in_place=in_place,
            dry_run=dry_run,
            add_structs_post629=add_structs_post629,
            add_versions=add_versions,
            patch_v5_loader=patch_v5_loader,
            make_zip=make_zip,
            target_runtime=target_runtime,
        )
        if res != 0:
            rc = res
        print()
    return rc


def main() -> int:
    default_target = skse_env.get_default_target_dot()
    parser = argparse.ArgumentParser(
        description=f"Best-effort SKSE64 fallback binary patcher for 1.6.1170 -> {default_target}."
    )
    parser.add_argument("dll", type=Path, help="Path to a compiled SKSE64 plugin .dll (or directory with --batch)")
    parser.add_argument("--batch", action="store_true", help="Scan/patch all .dll files recursively under the given directory")
    parser.add_argument("--output", "-o", type=Path, default=None, help="Output path for the patched .dll")
    parser.add_argument("--in-place", action="store_true", help="Overwrite input .dll (creates a .bak backup)")
    parser.add_argument("--dry-run", action="store_true", help="Inspect and plan patches without writing files")
    parser.add_argument(
        "--target",
        default=default_target,
        help=f"Target Skyrim runtime version for verification (default: {default_target})",
    )
    parser.add_argument(
        "--add-structs-post629",
        action="store_true",
        help="Also set kVersionIndependent_StructsPost629 (1 << 2) in versionIndependence",
    )
    parser.add_argument(
        "--add-version",
        action="append",
        default=[],
        help="Append an explicit runtime version (e.g. <MAJOR>.<MINOR>.<BUILD>.0) to compatibleVersions[16]",
    )
    parser.add_argument(
        "--no-v5-loader",
        action="store_true",
        help="Skip automatic Format 5 Address Library loader patching (metadata only)",
    )
    parser.add_argument(
        "--zip",
        action="store_true",
        help="Also package the verified DLL into dist/<PluginName>_Updated.zip",
    )
    args = parser.parse_args()
    if args.batch or args.dll.is_dir():
        return batch_patch(
            target_dir=args.dll,
            dry_run=args.dry_run,
            in_place=args.in_place,
            add_structs_post629=args.add_structs_post629,
            add_versions=args.add_version,
            patch_v5_loader=not args.no_v5_loader,
            make_zip=args.zip,
            target_runtime=args.target,
        )
    return patch_dll(
        input_path=args.dll,
        output_path=args.output,
        in_place=args.in_place,
        dry_run=args.dry_run,
        add_structs_post629=args.add_structs_post629,
        add_versions=args.add_version,
        patch_v5_loader=not args.no_v5_loader,
        make_zip=args.zip,
        target_runtime=args.target,
    )


if __name__ == "__main__":
    raise SystemExit(main())
