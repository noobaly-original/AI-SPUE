import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
LEGACY_DIR = SCRIPTS_DIR / "legacy"
for d in (SCRIPTS_DIR, LEGACY_DIR, TESTS_DIR):
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))

import patch_binary  # noqa: E402
import pe_fixture  # noqa: E402
import triage_modlist  # noqa: E402
import verify_dll  # noqa: E402


def _build_synthetic_pe64(text_bytes: bytes, rdata_bytes: bytes, timestamp: int = 1700000000) -> bytearray:
    """Create a minimal PE64 image with `.text` (0x1000) and `.rdata`."""
    e_lfanew = 0x80
    opt_size = 0xF0
    text_rptr = 0x400
    text_va = 0x1000
    text_rsize = len(text_bytes)
    rdata_va = text_va + (((text_rsize or 1) + 0xFFF) & ~0xFFF)
    rdata_rptr = text_rptr + text_rsize

    buf = bytearray(rdata_rptr + len(rdata_bytes))
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, e_lfanew + 4, 0x8664, 2, timestamp, 0, 0, opt_size, 0x2022)

    opt_off = e_lfanew + 0x18
    struct.pack_into("<H", buf, opt_off, 0x20B)
    struct.pack_into("<I", buf, opt_off + 64, 0x12345678)
    struct.pack_into("<I", buf, opt_off + 108, 16)

    sec0 = opt_off + opt_size
    buf[sec0 : sec0 + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", buf, sec0 + 8, text_rsize, text_va, text_rsize, text_rptr)

    sec1 = sec0 + 40
    buf[sec1 : sec1 + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", buf, sec1 + 8, len(rdata_bytes), rdata_va, len(rdata_bytes), rdata_rptr)

    buf[text_rptr : text_rptr + text_rsize] = text_bytes
    buf[rdata_rptr : rdata_rptr + len(rdata_bytes)] = rdata_bytes
    return buf


class TestVerifyAndPatchBinary(unittest.TestCase):
    def test_check_compat_branches(self) -> None:
        v99 = verify_dll.pack_skse_version(1, 7, 99)
        v185 = verify_dll.pack_skse_version(1, 8, 5)
        v1170 = verify_dll.pack_skse_version(1, 6, 1170)
        empty_compat = (0,) * 16

        self.assertIn("bad version data", verify_dll.check_compat(0, "P", 1, 0, empty_compat, 1700000000, v99))
        self.assertIn("no name specified", verify_dll.check_compat(1, "", 1, 0, empty_compat, 1700000000, v99))
        self.assertIn("unsupported", verify_dll.check_compat(1, "P", 0x80, 0, empty_compat, 1700000000, v99))

        # Missing AddressLibraryV5 on >= 1.7.99 runtimes: pre-2025-05-26 rejected, newer warns
        for rt in (v99, v185):
            self.assertIn(
                "must be recompiled",
                verify_dll.check_compat(1, "P", 1 | 4, 0, empty_compat, 1700000000, rt),
            )
            self.assertTrue(
                verify_dll.check_compat(1, "P", 1 | 4, 0, empty_compat, 1795000000, rt).startswith("WARNING:")
            )

        # Missing StructsPost629 without NoStructUse rejected on 1.6.1170; accepted with NoStructUse
        self.assertIn("earlier than 1.6.629", verify_dll.check_compat(1, "P", 1, 0, empty_compat, 1700000000, v1170))
        self.assertEqual(verify_dll.check_compat(1, "P", 1, 1, empty_compat, 1700000000, v1170), "COMPATIBLE")
        self.assertEqual(verify_dll.check_compat(1, "P", 1 | 4, 2, empty_compat, 1700000000, v185), "COMPATIBLE")

        # Non-version-independent explicit compatibleVersions
        compat_with_185 = (v99, v185) + (0,) * 14
        self.assertEqual(verify_dll.check_compat(1, "P", 0, 0, compat_with_185, 1700000000, v185), "COMPATIBLE")
        self.assertIn("incompatible", verify_dll.check_compat(1, "P", 0, 0, compat_with_185, 1700000000, v1170))

    def test_verify_fixture_dll(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dll_path = pe_fixture.write_test_plugin_dll(Path(td) / "FixturePlugin.dll")
            res_auto = verify_dll.verify_dll(dll_path)
            self.assertTrue(res_auto["is_x64"])
            self.assertTrue(res_auto["passed_target"])
            self.assertEqual([k for k in res_auto if k.startswith("passed_")], ["passed_target"])

            res = verify_dll.verify_dll(dll_path, target_runtime="1.8.5")
            self.assertTrue(res["passed_target"])
            self.assertEqual(res["runtime_checks"].get("1.8.5"), "COMPATIBLE")

            triage = triage_modlist.classify_dll(dll_path)
            self.assertEqual(triage["status"], "OK")

    def test_patch_binary_metadata_on_dll_copy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dll_copy = pe_fixture.write_test_plugin_dll(Path(td) / "LegacyCopy.dll")

            raw = bytearray(dll_copy.read_bytes())
            e_lf, sections, exports = patch_binary.parse_pe64_sections_and_exports(bytes(raw))
            ver_off = patch_binary.rva_to_file_offset(exports["SKSEPlugin_Version"], sections)
            self.assertIsNotNone(ver_off)
            # Clear AddressLibraryV5 (bit 1) and StructsPost629 (bit 2), backdate timestamp
            ver_ex, ver_ind = struct.unpack_from("<II", raw, ver_off + 0x304)
            struct.pack_into("<II", raw, ver_off + 0x304, ver_ex & ~0x2, ver_ind & ~0x4)
            struct.pack_into("<I", raw, e_lf + 8, 1700000000)
            dll_copy.write_bytes(bytes(raw))

            pre_res = verify_dll.verify_dll(dll_copy, target_runtime="1.7.120")
            self.assertFalse(pre_res["passed_target"])

            # Dry-run leaves file untouched
            before = dll_copy.read_bytes()
            rc_dry = patch_binary.patch_dll(
                dll_copy,
                dry_run=True,
                add_structs_post629=True,
                add_versions=["1.7.120.0"],
                target_runtime="1.7.120",
            )
            self.assertEqual(rc_dry, 0)
            self.assertEqual(dll_copy.read_bytes(), before)

            # Live patch writes output and passes target verification
            out_dll = Path(td) / "LegacyCopy_patched.dll"
            rc = patch_binary.patch_dll(
                dll_copy,
                output_path=out_dll,
                add_structs_post629=True,
                add_versions=["1.7.120.0"],
                target_runtime="1.7.120",
            )
            self.assertEqual(rc, 0)
            post_res = verify_dll.verify_dll(out_dll, target_runtime="1.7.120")
            self.assertTrue(post_res["passed_target"])
            self.assertIn("AddressLibraryV5 (0x2)", post_res["version_data"]["versionIndependenceEx_flags"])
            self.assertIn("StructsPost629 (0x4)", post_res["version_data"]["versionIndependence_flags"])
            self.assertIn("1.7.120.0", post_res["version_data"]["compatibleVersions"])

    def _make_synthetic_versiondb_pe(self, text_size: int) -> bytearray:
        rdata = b"Data\\SKSE\\Plugins\\versionlib-%d-%d-%d-%d.bin\x00"
        text = bytearray(b"\xCC" * text_size)
        rdata_va = 0x1000 + (((text_size or 1) + 0xFFF) & ~0xFFF)

        # xref @ 0x1020
        xref_off = 0x20
        disp_str = rdata_va - (0x1000 + xref_off + 7)
        text[xref_off : xref_off + 7] = b"\x48\x8D\x0D" + struct.pack("<i", disp_str)

        # m1 @ 0x70 (fmt_disp=0x24, cnt_disp=0x30)
        file_lea = b"\x48\x8D\x4D\xE0"
        m1_off = 0x70
        m1_bytes = (
            b"\x41\xB8\x04\x00\x00\x00"
            + b"\x48\x8D\x54\x24\x24"
            + file_lea
            + b"\xE8\x00\x00\x00\x00"
            + b"\x39\x44\x24\x24"
            + b"\x0F\x85"
            + struct.pack("<i", 0x350)
            + b"\xAA\xBB"  # sentinel right after jne
        )
        text[m1_off : m1_off + len(m1_bytes)] = m1_bytes

        # m_tn @ 0x100 (hook1_off is 0x84; +0x60 = 0xE4)
        m2_off = 0x100
        m2_bytes = (
            b"\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24\x28"
            + file_lea
            + b"\xE8\x00\x00\x00\x00"
            + b"\x3D\xFF\xFF\x00\x00\x0F\x87\x10\x00\x00\x00"
            + b"\x41\xB8\x01\x00\x00\x00"
            + file_lea
            + b"\xE8\x10\x00\x00\x00"
            + b"\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24\x2C"
            + file_lea
            + b"\xE8\x00\x00\x00\x00"
            + b"\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24\x30"
            + b"\x49\x8B\xCE\xE8\x20\x00\x00\x00"
        )
        text[m2_off : m2_off + len(m2_bytes)] = m2_bytes

        # m3 @ 0x300 (hook1_off + 0x250 = 0x2D4)
        m3_off = 0x300
        m3_bytes = b"\x49\x8B\x56\x08\x49\x8B\x0E\x4C\x8B\xC2\x4C\x2B\xC1\x49\xC1\xF8\x04"
        text[m3_off : m3_off + len(m3_bytes)] = m3_bytes
        return _build_synthetic_pe64(bytes(text), rdata)

    def test_versiondb_synthetic_full_and_compact(self) -> None:
        # Full cave mode (avail >= 192)
        raw_full = self._make_synthetic_versiondb_pe(text_size=0x500)
        e_lf, sections, _ = patch_binary.parse_pe64_sections_and_exports(bytes(raw_full))
        info = patch_binary.find_versiondb_v5_target(bytes(raw_full), e_lf, sections)
        self.assertIsNotNone(info)
        self.assertFalse(info["in_loop_cave"])
        self.assertEqual(info["scratch_disp"], 0x24)  # selected fmt_disp != cnt_disp, not hardcoded 0x7C

        patched_bytes = patch_binary.apply_versiondb_v5_patch(raw_full, e_lf, info)
        self.assertGreater(patched_bytes, 0)
        cave_slice = bytes(raw_full[info["cave_off"] : info["cave_off"] + patched_bytes])
        self.assertIn(b"\x48\x8D\x54\x24\x24", cave_slice)
        self.assertIn(b"\x8B\x44\x24\x24", cave_slice)
        self.assertNotIn(b"\x48\x8D\x54\x24\x7C", cave_slice)
        # Sentinel right after hook1 (+10) untouched
        h1_off = patch_binary.rva_to_file_offset(info["hook1_rva"], sections)
        self.assertEqual(raw_full[h1_off + 10 : h1_off + 12], b"\xAA\xBB")
        # Second scan detects already_patched
        rescan = patch_binary.find_versiondb_v5_target(bytes(raw_full), e_lf, sections)
        self.assertEqual(rescan, {"already_patched": True, "loader": "versiondb::Load"})

        # Compact cave mode (avail == 32 < 192)
        raw_compact = self._make_synthetic_versiondb_pe(text_size=0x340)
        e_lf_c, sec_c, _ = patch_binary.parse_pe64_sections_and_exports(bytes(raw_compact))
        info_c = patch_binary.find_versiondb_v5_target(bytes(raw_compact), e_lf_c, sec_c)
        self.assertIsNotNone(info_c)
        self.assertTrue(info_c["in_loop_cave"])
        self.assertEqual(info_c["scratch_disp"], 0x24)
        patch_binary.apply_versiondb_v5_patch(raw_compact, e_lf_c, info_c)
        loop_off = patch_binary.rva_to_file_offset(info_c["loop_cave_rva"], sec_c)
        loop_slice = bytes(raw_compact[loop_off : info_c["done_rva"] - 0x1000 + 0x400])
        self.assertIn(b"\x48\x8D\x54\x24\x24", loop_slice)
        self.assertNotIn(b"\x48\x8D\x54\x24\x7C", loop_slice)
        h1_off_c = patch_binary.rva_to_file_offset(info_c["hook1_rva"], sec_c)
        self.assertEqual(raw_compact[h1_off_c + 10 : h1_off_c + 12], b"\xAA\xBB")

    def _make_synthetic_commonlib_pe(self, disp32: bool, text_size: int = 0x960) -> bytearray:
        rdata = b"Unsupported address library format\x00"
        text = bytearray(b"\xCC" * text_size)
        rdata_va = 0x1000 + (((text_size or 1) + 0xFFF) & ~0xFFF)

        # err_xref @ 0x800 (rva 0x1800)
        xref_off = 0x800
        disp_str = rdata_va - (0x1000 + xref_off + 7)
        text[xref_off : xref_off + 7] = b"\x48\x8D\x0D" + struct.pack("<i", disp_str)

        # m1 @ 0x100 (inside w1 [0x80..0x500])
        m1_off = 0x100
        if disp32:
            rdx_lea = b"\x48\x8D\x94\x24" + struct.pack("<i", 0x120)
            cmp_bytes = b"\x39\x84\x24" + struct.pack("<i", 0x120)
        else:
            rdx_lea = b"\x48\x8D\x54\x24\x24"
            cmp_bytes = b"\x39\x44\x24\x24"
        m1_bytes = (
            b"\x41\xB8\x04\x00\x00\x00"
            + rdx_lea
            + b"\x48\x8D\x4C\x24\x30"
            + b"\xE8\x00\x00\x00\x00"
            + cmp_bytes
            + b"\x0F\x85"
            + struct.pack("<i", 0x50)
            + b"\xAA\xBB\xCC"  # sentinel right after jne!
        )
        text[m1_off : m1_off + len(m1_bytes)] = m1_bytes

        # m2 @ 0x160 (hook1_off + 0x18..+0xD8)
        m2_off = 0x160
        m2_bytes = (
            b"\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24\x28\x48\x8D\x4C\x24\x30\xE8\x00\x00\x00\x00"
            + b"\x41\xB8\xFF\xFF\xFF\xFF\x48\x8D\x4C\x24\x30\xE8\x10\x00\x00\x00"
            + b"\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24\x2C\x48\x8D\x4C\x24\x30\xE8\x00\x00\x00\x00"
            + b"\x41\xB8\x04\x00\x00\x00\x48\x8D\x54\x24\x30"
        )
        text[m2_off : m2_off + len(m2_bytes)] = m2_bytes

        # m3 @ 0x400 (hook1_off + 0x2C0..+0x4C0) -> unpack @ 0x1880 (.text + 0x880)
        m3_off = 0x400
        unpack_rva = 0x1880
        call_rva = 0x1000 + m3_off + 9 + 5 + 8 + 3
        m3_bytes = (
            b"\x44\x0F\xB6\x8C\x24\x00\x01\x00\x00"
            + b"\x4C\x8D\x44\x24\x40"
            + b"\x48\x8D\x94\x24\x80\x00\x00\x00"
            + b"\x48\x8B\xCD"
            + b"\xE8"
            + struct.pack("<i", unpack_rva - (call_rva + 5))
        )
        text[m3_off : m3_off + len(m3_bytes)] = m3_bytes

        # unpack_file @ 0x880
        u_off = 0x880
        u_bytes = (
            b"\x4C\x8B\x79\x10"
            + b"\x4C\x8B\x61\x18"
            + b"\x4D\x3B\xFC"
            + b"\x0F\x84"
            + struct.pack("<i", 0x60)
            + b"\x41\xB8\x01\x00\x00\x00\x48\x8D\x55\xC0\x48\x8B\xCB\xE8\x10\x00\x00\x00"
        )
        text[u_off : u_off + len(u_bytes)] = u_bytes

        # REL::Module::load_segments minor==6 check @ 0x920
        rt_off = 0x920
        text[rt_off : rt_off + 15] = b"\x66\x83\xF8\x06\x0F\x95\xC0\xFE\xC0\x88\x80\x18\x01\x00\x00"

        return _build_synthetic_pe64(bytes(text), rdata)

    def test_commonlib_synthetic_disp8_disp32_and_fixes(self) -> None:
        for disp32 in (False, True):
            raw = self._make_synthetic_commonlib_pe(disp32=disp32, text_size=0x960)
            e_lf, sections, _ = patch_binary.parse_pe64_sections_and_exports(bytes(raw))
            info = patch_binary.find_commonlib_v5_target(bytes(raw), e_lf, sections)
            self.assertIsNotNone(info)
            expected_len = 13 if disp32 else 10
            self.assertEqual(info["hook1_len"], expected_len)
            self.assertEqual(info["err_target_rva"], info["hook1_rva"] + expected_len + 0x50)
            self.assertIsNotNone(info["rt_setne_rva"])

            h1_off = patch_binary.rva_to_file_offset(info["hook1_rva"], sections)
            patched = patch_binary.apply_commonlib_v5_patch(raw, e_lf, info)
            self.assertGreater(patched, 0)

            # Verify off-by-2 bug is fixed: sentinel right after jne MUST remain untouched
            self.assertEqual(raw[h1_off + expected_len : h1_off + expected_len + 3], b"\xAA\xBB\xCC")

            # Verify stackless [r15+8] loop bytes and jb rel8 jump-back displacement (-41)
            u_off = patch_binary.rva_to_file_offset(info["loop_start_rva"], sections)
            self.assertEqual(raw[u_off : u_off + 11], b"\x49\xC7\x47\x08\x00\x00\x00\x00\x49\x89\x3F")
            self.assertEqual(raw[u_off + 39 : u_off + 41], b"\x72\xD7")  # -41 signed int8

            # Verify setne al -> setb al
            rt_off = patch_binary.rva_to_file_offset(info["rt_setne_rva"], sections)
            self.assertEqual(raw[rt_off : rt_off + 3], b"\x0F\x92\xC0")

            # Re-scan reports already_patched
            rescan = patch_binary.find_commonlib_v5_target(bytes(raw), e_lf, sections)
            self.assertEqual(rescan, {"already_patched": True, "loader": "REL::IDDatabase"})

        # When avail == 16 (< 19), disp8 succeeds and disp32 is rejected safely
        raw_tight8 = self._make_synthetic_commonlib_pe(disp32=False, text_size=0x940)
        e_lf8, sec8, _ = patch_binary.parse_pe64_sections_and_exports(bytes(raw_tight8))
        self.assertIsNotNone(patch_binary.find_commonlib_v5_target(bytes(raw_tight8), e_lf8, sec8))

        raw_tight32 = self._make_synthetic_commonlib_pe(disp32=True, text_size=0x940)
        e_lf32, sec32, _ = patch_binary.parse_pe64_sections_and_exports(bytes(raw_tight32))
        self.assertIsNone(patch_binary.find_commonlib_v5_target(bytes(raw_tight32), e_lf32, sec32))


if __name__ == "__main__":
    unittest.main()
