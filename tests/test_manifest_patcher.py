import json
import shutil
import struct
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
for p in (SCRIPTS_DIR, TESTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import manifest_patcher  # noqa: E402
import pe_fixture  # noqa: E402
import pe_inspect  # noqa: E402
import skse_env  # noqa: E402
import verify_dll  # noqa: E402

try:
    import pefile
except ImportError:
    pefile = None  # type: ignore[assignment]


class TestManifestPatcher(unittest.TestCase):
    _tmp_dir: tempfile.TemporaryDirectory
    FIXTURE_DLL: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp_dir = tempfile.TemporaryDirectory()
        cls.FIXTURE_DLL = pe_fixture.write_test_plugin_dll(Path(cls._tmp_dir.name) / "FixturePlugin.dll")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp_dir.cleanup()

    def test_init_verify_dry_run_and_apply_with_new_section_and_zip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            dll_copy = root / "FixtureCopy.dll"
            shutil.copy2(self.FIXTURE_DLL, dll_copy)

            # Backdate timestamp and clear AddressLibraryV5 bit so init-manifest & metadata patching have work to do
            raw = bytearray(dll_copy.read_bytes())
            pe_info = pe_inspect.parse_pe64(bytes(raw))
            ver_off = pe_info["exports"]["SKSEPlugin_Version"]["file_offset"]
            ver_ex = struct.unpack_from("<I", raw, ver_off + 0x304)[0]
            struct.pack_into("<I", raw, ver_off + 0x304, ver_ex & ~0x2)
            struct.pack_into("<I", raw, pe_info["e_lfanew"] + 8, 1700000000)
            dll_copy.write_bytes(bytes(raw))

            manifest_path = root / "patches.json"
            self.assertEqual(
                manifest_patcher.cmd_init_manifest(
                    types.SimpleNamespace(input_dll=dll_copy, output=manifest_path, target=None)
                ),
                0,
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["target_runtime"], skse_env.get_default_target_dot())
            self.assertEqual(manifest["metadata_patches"]["set_version_independence_ex"], ["AddressLibraryV5"])

            # Add both a text-padding cave and a new executable .patch section trampoline + direct patch
            hook_rva = pe_info["exports"]["SKSEPlugin_Load"]["rva"]
            hook_off = pe_info["exports"]["SKSEPlugin_Load"]["file_offset"]
            first5 = bytes(raw[hook_off : hook_off + 5])
            first5_hex = " ".join(f"{b:02X}" for b in first5)

            manifest["symbols"]["HookTarget"] = f"0x{hook_rva + 5:X}"
            manifest["code_caves"].append(
                {
                    "name": "helper_cave",
                    "placement": "text_padding",
                    "hex_bytes": "90 90 C3",
                }
            )
            manifest["trampolines"].append(
                {
                    "name": "load_trampoline",
                    "hook_rva": f"0x{hook_rva:X}",
                    "stolen_len": 5,
                    "expected_hex": first5_hex,
                    "placement": "new_section",
                    "cave_prefix_hex": "E8 {{rel32:helper_cave}} " + first5_hex,
                    "append_return_jmp": True,
                }
            )
            manifest["target_runtime"] = "auto"
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            # Verify & dry-run do not modify dll_copy
            self.assertEqual(
                manifest_patcher.cmd_verify_manifest(
                    types.SimpleNamespace(input_dll=dll_copy, manifest=manifest_path, ignore_hash=False)
                ),
                0,
            )
            before = dll_copy.read_bytes()
            out_dll = root / "FixturePatched.dll"
            self.assertEqual(
                manifest_patcher.cmd_apply(
                    types.SimpleNamespace(
                        input_dll=dll_copy,
                        manifest=manifest_path,
                        output=out_dll,
                        in_place=False,
                        dry_run=True,
                        ignore_hash=False,
                        target=None,
                        zip=False,
                    )
                ),
                0,
            )
            self.assertEqual(dll_copy.read_bytes(), before)
            self.assertFalse(out_dll.exists())

            # Apply live with --zip into temporary dist_dir
            temp_dist = root / "dist"
            with mock.patch.object(skse_env, "DIST_DIR", temp_dist):
                rc = manifest_patcher.cmd_apply(
                    types.SimpleNamespace(
                        input_dll=dll_copy,
                        manifest=manifest_path,
                        output=out_dll,
                        in_place=False,
                        dry_run=False,
                        ignore_hash=False,
                        target=None,
                        zip=True,
                    )
                )
            self.assertEqual(rc, 0)
            self.assertTrue(out_dll.exists())

            # Validate new .patch section, checksum parity, trampoline bytes, and Windows LoadLibraryExW load
            patched_bytes = out_dll.read_bytes()
            patched_pe = pe_inspect.parse_pe64(patched_bytes)
            sec_names = [s["name"] for s in patched_pe["sections"]]
            self.assertEqual(patched_pe["num_sections"], pe_info["num_sections"] + 1)
            self.assertIn(".patch", sec_names)
            patch_sec = next(s for s in patched_pe["sections"] if s["name"] == ".patch")
            self.assertEqual(patch_sec["characteristics"], 0x60000020)

            if pefile is not None:
                pe_obj = pefile.PE(data=patched_bytes, fast_load=True)
                self.assertEqual(patched_pe["checksum_stored"], pe_obj.generate_checksum())
            self.assertEqual(patched_pe["checksum_stored"], patched_pe["checksum_computed"])

            # Verify E9 jump at hook_rva targets .patch section
            patched_hook_off = pe_inspect.rva_to_file_offset(hook_rva, patched_pe["sections"])
            self.assertEqual(patched_bytes[patched_hook_off], 0xE9)
            disp = struct.unpack_from("<i", patched_bytes, patched_hook_off + 1)[0]
            self.assertEqual(hook_rva + 5 + disp, patch_sec["virtual_addr"])

            # Verify Windows LoadLibraryExW + SKSE compatibility check passes
            vres = verify_dll.verify_dll(out_dll, target_runtime=None)
            self.assertTrue(vres["passed_target"])

            # Verify ZIP archive contents
            zip_path = temp_dist / f"{manifest['plugin_name']}_Updated.zip"
            self.assertTrue(zip_path.exists())
            with zipfile.ZipFile(zip_path, "r") as zf:
                self.assertIn("SKSE/Plugins/FixturePatched.dll", [n.replace("\\", "/") for n in zf.namelist()])

    def test_safety_rejections_sha_expected_wildcards_and_reloc(self) -> None:
        data = self.FIXTURE_DLL.read_bytes()
        pe_info = pe_inspect.parse_pe64(data)
        hook_rva = pe_info["exports"]["SKSEPlugin_Load"]["rva"]

        # 1. SHA-256 mismatch rejected
        bad_sha_manifest = {
            "schema_version": 1,
            "input_sha256": "0" * 64,
            "patches": [],
        }
        with self.assertRaises(manifest_patcher.ManifestError):
            manifest_patcher.apply_manifest_bytes(data, bad_sha_manifest)

        # 2. Expected bytes mismatch rejected, while ?? wildcard succeeds
        bad_exp_manifest = {
            "schema_version": 1,
            "input_sha256": manifest_patcher.sha256_bytes(data),
            "patches": [
                {
                    "rva": f"0x{hook_rva:X}",
                    "expected_hex": "FF FF FF",
                    "patch_hex": "90 90 90",
                }
            ],
        }
        with self.assertRaises(manifest_patcher.ManifestError):
            manifest_patcher.apply_manifest_bytes(data, bad_exp_manifest)

        ok_wildcard_manifest = {
            "schema_version": 1,
            "input_sha256": manifest_patcher.sha256_bytes(data),
            "patches": [
                {
                    "rva": f"0x{hook_rva:X}",
                    "expected_hex": "?? ?? ??",
                    "patch_hex": "90 90 90",
                }
            ],
        }
        patched_wild, _ = manifest_patcher.apply_manifest_bytes(data, ok_wildcard_manifest)
        self.assertEqual(bytes(patched_wild[pe_info["exports"]["SKSEPlugin_Load"]["file_offset"] :][:3]), b"\x90\x90\x90")

        # 3. ASLR .reloc overlap rejected unless allow_reloc_overlap=True
        rel = pe_info["relocations"][0]
        rel_rva = rel["rva"]
        rel_off = pe_inspect.rva_to_file_offset(rel_rva, pe_info["sections"])
        rel_exp = " ".join(f"{b:02X}" for b in data[rel_off : rel_off + 4])

        reloc_block_manifest = {
            "schema_version": 1,
            "input_sha256": manifest_patcher.sha256_bytes(data),
            "patches": [
                {
                    "rva": f"0x{rel_rva:X}",
                    "expected_hex": rel_exp,
                    "patch_hex": "00 00 00 00",
                }
            ],
        }
        with self.assertRaises(manifest_patcher.ManifestError):
            manifest_patcher.apply_manifest_bytes(data, reloc_block_manifest)

        reloc_block_manifest["patches"][0]["allow_reloc_overlap"] = True
        patched_rel, _ = manifest_patcher.apply_manifest_bytes(data, reloc_block_manifest)
        self.assertEqual(bytes(patched_rel[rel_off : rel_off + 4]), b"\x00\x00\x00\x00")


if __name__ == "__main__":
    unittest.main()
