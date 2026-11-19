"""Pure-Python minimal valid PE64 SKSE plugin DLL generator for unit tests.

Produces self-contained x64 PE32+ DLL binaries accepted by Windows
`LoadLibraryExW(..., DONT_RESOLVE_DLL_REFERENCES)`, `pefile`, MSVC `dumpbin.exe`,
and all AI-SPUE binary analysis/patching tools (`pe_inspect.py`, `verify_dll.py`,
`addrlib_xref.py`, `manifest_patcher.py`) without requiring prebuilt C++ fixtures.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import Sequence

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import pe_inspect  # noqa: E402


def _pack_fixed_ascii(text: str, size: int) -> bytes:
    raw = text.encode("ascii", errors="replace")[: size - 1]
    return raw + b"\x00" * (size - len(raw))


def build_test_plugin_dll_bytes(
    *,
    plugin_name: str = "FixturePlugin",
    author: str = "AI-SPUE Test",
    dll_export_name: str = "FixturePlugin.dll",
    plugin_version: int = 0x01000000,
    data_version: int = 1,
    version_independence: int = 5,     # AddressLibraryPostAE (1) | StructsPost629 (4)
    version_independence_ex: int = 2,  # AddressLibraryV5 (2)
    compatible_versions: Sequence[int] = (),
    se_version_required: int = 0,
    timestamp: int = 1760000000,       # 2025-10-09 UTC (post Format 5 epoch cutoff)
    include_minor6_bug: bool = False,
) -> bytes:
    """Build a minimal valid x64 PE DLL exporting `SKSEPlugin_Load` and `SKSEPlugin_Version`."""
    # File layout (FileAlignment = 0x200, SectionAlignment = 0x1000)
    # 0x0000..0x0400: Headers (0x200..0x400 spare room for adding .patch section headers)
    # 0x0400..0x0600: .text   (RVA 0x1000)
    # 0x0600..0x0C00: .rdata  (RVA 0x2000)
    # 0x0C00..0x0E00: .reloc  (RVA 0x3000)
    total_file_size = 0xE00
    buf = bytearray(total_file_size)

    # --- .rdata strings & data (RVA 0x2000 -> file 0x600) ---
    rdata_rva = 0x2000
    rdata_off = 0x600

    # SKSEPlugin_Version struct (0x350 = 848 bytes) at RVA 0x2000
    ver_struct_rva = rdata_rva
    compat_padded = list(compatible_versions[:16]) + [0] * max(0, 16 - len(compatible_versions))
    ver_bytes = bytearray(0x350)
    struct.pack_into("<II", ver_bytes, 0, data_version, plugin_version)
    ver_bytes[8:264] = _pack_fixed_ascii(plugin_name, 256)
    ver_bytes[264:520] = _pack_fixed_ascii(author, 256)
    ver_bytes[520:772] = _pack_fixed_ascii("", 252)
    struct.pack_into("<II", ver_bytes, 772, version_independence_ex, version_independence)
    struct.pack_into("<16I", ver_bytes, 780, *compat_padded)
    struct.pack_into("<I", ver_bytes, 844, se_version_required)
    buf[rdata_off : rdata_off + 0x350] = ver_bytes

    # Strings starting at RVA 0x2360
    str_cursor_off = rdata_off + 0x360

    def put_str(s: str) -> int:
        nonlocal str_cursor_off
        rva = rdata_rva + (str_cursor_off - rdata_off)
        raw = s.encode("ascii") + b"\x00"
        buf[str_cursor_off : str_cursor_off + len(raw)] = raw
        str_cursor_off += len(raw)
        return rva

    rva_str_framework = put_str("CommonLibSSE-NG")
    rva_str_fmt = put_str("versionlib-%d-%d-%d-%d.bin")
    rva_str_exe = put_str("SkyrimSE.exe")
    rva_dll_name = put_str(dll_export_name)
    rva_exp_load = put_str("SKSEPlugin_Load")
    rva_exp_version = put_str("SKSEPlugin_Version")
    rva_imp_dll = put_str("KERNEL32.dll")

    # Export directory at RVA 0x2420
    exp_dir_off = rdata_off + 0x420
    exp_dir_rva = rdata_rva + 0x420
    exp_funcs_rva = exp_dir_rva + 40
    exp_names_rva = exp_funcs_rva + 8
    exp_ords_rva = exp_names_rva + 8

    skse_load_rva = 0x1010
    struct.pack_into(
        "<IIHHIIIIIII",
        buf,
        exp_dir_off,
        0,                  # Characteristics
        timestamp,          # TimeDateStamp
        0, 0,               # Major/MinorVersion
        rva_dll_name,       # Name
        1,                  # Base
        2,                  # NumberOfFunctions
        2,                  # NumberOfNames
        exp_funcs_rva,      # AddressOfFunctions
        exp_names_rva,      # AddressOfNames
        exp_ords_rva,       # AddressOfNameOrdinals
    )
    struct.pack_into("<II", buf, exp_dir_off + 40, skse_load_rva, ver_struct_rva)
    # Alphabetically sorted: "SKSEPlugin_Load" (ord 0), "SKSEPlugin_Version" (ord 1)
    struct.pack_into("<II", buf, exp_dir_off + 48, rva_exp_load, rva_exp_version)
    struct.pack_into("<HH", buf, exp_dir_off + 56, 0, 1)
    exp_dir_size = 60

    # Minimal Import Directory (KERNEL32.dll -> GetCurrentProcessId) at RVA 0x2480
    imp_dir_off = rdata_off + 0x480
    imp_dir_rva = rdata_rva + 0x480
    ilt_off = imp_dir_off + 40
    ilt_rva = imp_dir_rva + 40
    iat_off = ilt_off + 16
    iat_rva = ilt_rva + 16
    hint_off = iat_off + 16
    hint_rva = iat_rva + 16

    struct.pack_into("<H", buf, hint_off, 0)
    imp_fn = b"GetCurrentProcessId\x00"
    buf[hint_off + 2 : hint_off + 2 + len(imp_fn)] = imp_fn

    struct.pack_into("<QQ", buf, ilt_off, hint_rva, 0)
    struct.pack_into("<QQ", buf, iat_off, hint_rva, 0)
    struct.pack_into("<IIIII", buf, imp_dir_off, ilt_rva, 0, 0, rva_imp_dll, iat_rva)
    imp_dir_size = 40

    # --- .text code (RVA 0x1000 -> file 0x400) ---
    text_rva = 0x1000
    text_off = 0x400

    # DllMain @ 0x1000: mov eax, 1; ret; int3 padding
    buf[text_off : text_off + 8] = bytes.fromhex("B8 01 00 00 00 C3 CC CC")

    # SKSEPlugin_Load @ 0x1010 (5 non-RIP prologue bytes + RIP-relative xrefs):
    disp_ver = rva_exp_version - 0x101C
    disp_fw = rva_str_framework - 0x1023
    disp_fmt = rva_str_fmt - 0x102A
    disp_exe = rva_str_exe - 0x1031
    code = bytearray()
    code.extend(b"\x53\x48\x83\xEC\x20")
    code.extend(b"\x48\x8D\x0D" + struct.pack("<i", disp_ver))
    code.extend(b"\x48\x8D\x15" + struct.pack("<i", disp_fw))
    code.extend(b"\x4C\x8D\x05" + struct.pack("<i", disp_fmt))
    code.extend(b"\x4C\x8D\x0D" + struct.pack("<i", disp_exe))
    code.extend(b"\xB8\x01\x00\x00\x00\x48\x83\xC4\x20\x5B\xC3")
    buf[text_off + 0x10 : text_off + 0x10 + len(code)] = code

    if include_minor6_bug:
        buf[text_off + 0x40 : text_off + 0x48] = bytes.fromhex("66 83 F8 06 0F 95 C0 C3")
    else:
        buf[text_off + 0x40 : text_off + 0x46] = bytes.fromhex("B0 01 C3 CC CC CC")

    struct.pack_into("<Q", buf, text_off + 0x60, 0x180002000)

    # --- .reloc (RVA 0x3000 -> file 0xC00) ---
    reloc_rva = 0x3000
    reloc_off = 0xC00
    struct.pack_into("<IIHH", buf, reloc_off, text_rva, 12, 0xA060, 0x0000)

    # --- DOS & PE64 Headers (0x000..0x400) ---
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    pe_off = 0x80
    buf[pe_off : pe_off + 4] = b"PE\x00\x00"

    struct.pack_into(
        "<HHIIIHH",
        buf,
        pe_off + 4,
        0x8664,     # Machine: AMD64
        3,          # NumberOfSections
        timestamp,  # TimeDateStamp
        0,          # PointerToSymbolTable
        0,          # NumberOfSymbols
        0xF0,       # SizeOfOptionalHeader
        0x2022,     # Characteristics: EXECUTABLE | LARGE_ADDRESS_AWARE | DLL
    )

    opt_off = pe_off + 24
    struct.pack_into(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        buf,
        opt_off,
        0x020B,      # Magic: PE32+
        14, 38,      # Linker major/minor
        0x200,       # SizeOfCode
        0x800,       # SizeOfInitializedData
        0,           # SizeOfUninitializedData
        0x1000,      # AddressOfEntryPoint
        0x1000,      # BaseOfCode
        0x180000000, # ImageBase
        0x1000,      # SectionAlignment
        0x200,       # FileAlignment
        6, 0,        # OS version
        1, 0,        # Image version
        6, 0,        # Subsystem version
        0,           # Win32VersionValue
        0x4000,      # SizeOfImage
        0x400,       # SizeOfHeaders (leaves space for adding sections)
        0,           # CheckSum (filled below)
        3,           # Subsystem: Windows CUI
        0x0160,      # DllCharacteristics: HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT
        0x100000,    # SizeOfStackReserve
        0x1000,      # SizeOfStackCommit
        0x100000,    # SizeOfHeapReserve
        0x1000,      # SizeOfHeapCommit
        0,           # LoaderFlags
        16,          # NumberOfRvaAndSizes
    )

    dd_off = opt_off + 112
    struct.pack_into("<II", buf, dd_off + 0 * 8, exp_dir_rva, exp_dir_size)
    struct.pack_into("<II", buf, dd_off + 1 * 8, imp_dir_rva, imp_dir_size)
    struct.pack_into("<II", buf, dd_off + 5 * 8, reloc_rva, 12)
    struct.pack_into("<II", buf, dd_off + 12 * 8, iat_rva, 16)

    sec_off = opt_off + 0xF0
    sections = [
        (b".text\x00\x00\x00", 0x200, text_rva, 0x200, text_off, 0x60000020),
        (b".rdata\x00\x00", 0x600, rdata_rva, 0x600, rdata_off, 0x40000040),
        (b".reloc\x00\x00", 0x10, reloc_rva, 0x200, reloc_off, 0x42000040),
    ]
    for idx, (name, vsize, va, raw_sz, raw_ptr, chars) in enumerate(sections):
        struct.pack_into(
            "<8sIIIIIIHHI",
            buf,
            sec_off + idx * 40,
            name,
            vsize,
            va,
            raw_sz,
            raw_ptr,
            0,
            0,
            0,
            0,
            chars,
        )

    checksum_file_off = opt_off + 64
    raw_bytes = bytes(buf)
    checksum = pe_inspect.calculate_pe_checksum(raw_bytes, checksum_file_off)
    struct.pack_into("<I", buf, checksum_file_off, checksum)
    return bytes(buf)


def write_test_plugin_dll(dest: Path, **kwargs) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(build_test_plugin_dll_bytes(**kwargs))
    return dest
