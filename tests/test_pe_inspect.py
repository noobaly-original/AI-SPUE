import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
for p in (SCRIPTS_DIR, TESTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import pe_fixture  # noqa: E402
import pe_inspect  # noqa: E402

try:
    import pefile
except ImportError:
    pefile = None  # type: ignore[assignment]


class TestPeInspect(unittest.TestCase):
    _tmp_dir: tempfile.TemporaryDirectory
    DLL_PATH: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp_dir = tempfile.TemporaryDirectory()
        cls.DLL_PATH = pe_fixture.write_test_plugin_dll(Path(cls._tmp_dir.name) / "FixturePlugin.dll")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp_dir.cleanup()

    def test_parse_pe64_and_checksum_parity(self) -> None:
        data = self.DLL_PATH.read_bytes()
        pe_info = pe_inspect.parse_pe64(data)
        self.assertEqual(pe_info["machine"], 0x8664)
        self.assertTrue(pe_info["aslr_enabled"])
        self.assertGreaterEqual(len(pe_info["sections"]), 3)
        self.assertIn("SKSEPlugin_Version", pe_info["exports"])
        self.assertIn("SKSEPlugin_Load", pe_info["exports"])
        self.assertGreater(len(pe_info["imports"]), 0)
        self.assertGreater(pe_info["reloc_summary"]["total"], 0)

        if pefile is not None:
            pe = pefile.PE(data=data, fast_load=True)
            self.assertEqual(pe_info["checksum_computed"], pe.generate_checksum())

    def test_decode_skse_version_and_fingerprint(self) -> None:
        data = self.DLL_PATH.read_bytes()
        pe_info = pe_inspect.parse_pe64(data)
        ver = pe_inspect.decode_skse_version_data(data, pe_info, target_runtime=None)
        self.assertIsNotNone(ver)
        self.assertEqual(ver["name"], "FixturePlugin")
        self.assertTrue(ver["passed_target"])
        self.assertEqual(ver["free_compat_slots"], 16)
        self.assertIn("AddressLibraryV5 (0x2)", ver["versionIndependenceEx_flags"])

        fp = pe_inspect.fingerprint_skse_binary(data, pe_info, version_data=ver)
        self.assertIn("SKSEPlugin_Version", fp["entry_point"])
        self.assertEqual(fp["address_resolution"], "AddressLibrary")
        self.assertIn("versionlib-*.bin (AE/1.7+ Address Library)", fp["markers"])

    def test_rva_offset_roundtrip_and_reloc_overlap(self) -> None:
        data = self.DLL_PATH.read_bytes()
        pe_info = pe_inspect.parse_pe64(data)
        exp = pe_info["exports"]["SKSEPlugin_Version"]
        rva = exp["rva"]
        off = exp["file_offset"]
        self.assertEqual(pe_inspect.rva_to_file_offset(rva, pe_info["sections"]), off)
        self.assertEqual(pe_inspect.file_offset_to_rva(off, pe_info["sections"]), rva)

        relocs = pe_info["relocations"]
        self.assertGreater(len(relocs), 0)
        sample_rel = relocs[0]
        overlaps = pe_inspect.check_reloc_overlaps(sample_rel["rva"], 4, relocs)
        self.assertIn(sample_rel, overlaps)
        # Verify SKSEPlugin_Version scalar flags do not overlap relocs
        self.assertEqual(pe_inspect.check_reloc_overlaps(rva + 0x304, 8, relocs), [])

    def test_find_aob_pattern_and_string_xrefs(self) -> None:
        data = self.DLL_PATH.read_bytes()
        pe_info = pe_inspect.parse_pe64(data)
        xrefs = pe_inspect.find_string_xrefs(data, pe_info, "SKSEPlugin_Version")
        self.assertGreater(len(xrefs), 0)
        self.assertTrue(any(len(item["xrefs"]) > 0 for item in xrefs))

        hits = pe_inspect.find_aob_pattern(data, pe_info, "48 8D 0D ?? ?? ?? ??", section_name=".text")
        self.assertGreater(len(hits), 0)

    def test_dumpbin_disasm_smoke(self) -> None:
        if pe_inspect.find_dumpbin() is None:
            self.skipTest("MSVC dumpbin.exe not installed")
        data = self.DLL_PATH.read_bytes()
        pe_info = pe_inspect.parse_pe64(data)
        load_rva = pe_info["exports"]["SKSEPlugin_Load"]["rva"]
        out = pe_inspect.disassemble_range(self.DLL_PATH, load_rva, 32)
        self.assertIn("RAW DATA", out)
        self.assertIn(f"{pe_info['image_base'] + load_rva:016X}", out.upper())


if __name__ == "__main__":
    unittest.main()
