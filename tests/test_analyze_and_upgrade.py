import json
import re
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import analyze_mod  # noqa: E402
import inspect_bin  # noqa: E402
import map_ids  # noqa: E402
import skse_env  # noqa: E402
import upgrade_mod  # noqa: E402


class TestAnalyzeAndUpgrade(unittest.TestCase):
    def test_analyze_examples(self) -> None:
        target_dash = skse_env.get_default_target_dash()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mod_a = root / "ModA_Outdated_1_6_1170"
            mod_b = root / "ModB_RawSKSE_Legacy"
            shutil.copytree(REPO_ROOT / "examples" / "ModA_Outdated_1_6_1170", mod_a)
            shutil.copytree(REPO_ROOT / "examples" / "ModB_RawSKSE_Legacy", mod_b)

            rep_a = analyze_mod.analyze_mod(mod_a, target_runtime=target_dash)
            issues_a = "\n".join(rep_a["issues"])
            warnings_a = "\n".join(rep_a["warnings"])
            self.assertIn("SINGLE-RUNTIME IDs", issues_a)
            self.assertIn("MISSING ADDRESS LIBRARY IDs", issues_a)
            self.assertIn("OUTDATED VCPKG REGISTRY", issues_a)
            self.assertIn("/WX", warnings_a)
            self.assertEqual(rep_a["id_summary"]["missing_in_target_count"], 1)
            self.assertEqual(rep_a["id_summary"]["missing_ids"][0]["suggested_ae_id"], 523983)

            rep_b = analyze_mod.analyze_mod(mod_b, target_runtime=target_dash)
            issues_b = "\n".join(rep_b["issues"])
            self.assertIn("Format 5", issues_b)
            self.assertIn("kVersionIndependentEx_AddressLibraryV5", issues_b)

    def test_upgrade_dry_run_and_live_examples(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mod_a = root / "ModA_Outdated_1_6_1170"
            mod_b = root / "ModB_RawSKSE_Legacy"
            shutil.copytree(REPO_ROOT / "examples" / "ModA_Outdated_1_6_1170", mod_a)
            shutil.copytree(REPO_ROOT / "examples" / "ModB_RawSKSE_Legacy", mod_b)

            orig_main_a = (mod_a / "src" / "main.cpp").read_text(encoding="utf-8")
            orig_cmake_a = (mod_a / "CMakeLists.txt").read_text(encoding="utf-8")

            # Dry-run should report changes without mutating files
            dry_changes = []
            dry_changes.extend(upgrade_mod.upgrade_versionlibdb(mod_a, dry_run=True))
            dry_changes.extend(upgrade_mod.upgrade_vcpkg_manifests(mod_a, dry_run=True))
            dry_changes.extend(upgrade_mod.upgrade_cmake(mod_a, replace_submodule=False, dry_run=True))
            dry_changes.extend(upgrade_mod.upgrade_source_code(mod_a, dry_run=True))
            self.assertTrue(len(dry_changes) > 0)
            self.assertEqual((mod_a / "src" / "main.cpp").read_text(encoding="utf-8"), orig_main_a)
            self.assertEqual((mod_a / "CMakeLists.txt").read_text(encoding="utf-8"), orig_cmake_a)

            # Live upgrade on ModA
            upgrade_mod.upgrade_versionlibdb(mod_a, dry_run=False)
            upgrade_mod.upgrade_vcpkg_manifests(mod_a, dry_run=False)
            upgrade_mod.upgrade_cmake(mod_a, replace_submodule=False, dry_run=False)
            upgrade_mod.upgrade_source_code(mod_a, dry_run=False)

            new_main_a = (mod_a / "src" / "main.cpp").read_text(encoding="utf-8")
            self.assertIn("REL::RelocationID(514287, 400447)", new_main_a)
            self.assertIn("REL::RelocationID(46022, 523983)", new_main_a)

            new_cmake_a = (mod_a / "CMakeLists.txt").read_text(encoding="utf-8")
            self.assertIn("/WX-", new_cmake_a)
            self.assertNotRegex(new_cmake_a, r"(?<![/\w])/WX(?![-\w])")
            self.assertIn("/utf-8", new_cmake_a.lower())

            vcpkg_cfg = json.loads((mod_a / "vcpkg-configuration.json").read_text(encoding="utf-8"))
            self.assertEqual(vcpkg_cfg["default-registry"]["kind"], "builtin")
            self.assertEqual(vcpkg_cfg["registries"], [])

            vcpkg_manifest = json.loads((mod_a / "vcpkg.json").read_text(encoding="utf-8"))
            self.assertEqual(vcpkg_manifest["builtin-baseline"], upgrade_mod.get_local_vcpkg_baseline())

            verify_rc = inspect_bin.cmd_verify_mod(
                types.SimpleNamespace(mod_dir=str(mod_a), target=skse_env.get_default_target_dash())
            )
            self.assertEqual(verify_rc, 0)

            # Live upgrade on ModB
            upgrade_mod.upgrade_versionlibdb(mod_b, dry_run=False)
            upgrade_mod.upgrade_cmake(mod_b, replace_submodule=False, dry_run=False)
            upgrade_mod.upgrade_source_code(mod_b, dry_run=False)

            new_vdb_b = (mod_b / "src" / "versionlibdb.h").read_text(encoding="utf-8")
            self.assertIn("format == 5", new_vdb_b)
            new_main_b = (mod_b / "src" / "main.cpp").read_text(encoding="utf-8")
            self.assertIn("kVersionIndependentEx_AddressLibraryV5", new_main_b)
            new_cmake_b = (mod_b / "CMakeLists.txt").read_text(encoding="utf-8")
            self.assertIn("/utf-8", new_cmake_b.lower())

    def test_upgrade_source_edge_cases(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            mod_dir = Path(td)
            sample = (
                "// REL::ID(514287)\n"
                "/* REL::ID(514287) */\n"
                'const char* doc = "REL::ID(514287)";\n'
                "REL::Relocation<std::uintptr_t> realPtr{ REL::ID(514287) };\n"
            )
            (mod_dir / "comments_and_strings.cpp").write_text(sample, encoding="utf-8")

            # Pure AE-only ID (10077 exists in target AE .bin, absent from 1-5-97-0.bin)
            (mod_dir / "ae_only.cpp").write_text("REL::Relocation<void> fn{ REL::ID(10077) };\n", encoding="utf-8")

            # Raw SKSEPluginVersionData brace aggregate with versionIndependenceEx = 0
            brace_cpp = (
                "__declspec(dllexport) SKSEPluginVersionData SKSEPlugin_Version = {\n"
                "    SKSEPluginVersionData::kVersion,\n"
                "    1,\n"
                '    "BraceMod",\n'
                '    "Author",\n'
                '    "",\n'
                "    0, // versionIndependenceEx\n"
                "    SKSEPluginVersionData::kVersionIndependent_AddressLibraryPostAE,\n"
                "    { 0 },\n"
                "    0,\n"
                "};\n"
            )
            (mod_dir / "brace_ver.cpp").write_text(brace_cpp, encoding="utf-8")

            # Raw SKSEPluginVersionData designated initializer with .versionIndependenceEx = 0
            desig_cpp = (
                "__declspec(dllexport) SKSEPluginVersionData SKSEPlugin_Version = {\n"
                "    .dataVersion = SKSEPluginVersionData::kVersion,\n"
                '    .name = "DesigMod",\n'
                "    .versionIndependenceEx = 0,\n"
                "    .versionIndependence = SKSEPluginVersionData::kVersionIndependent_AddressLibraryPostAE,\n"
                "};\n"
            )
            (mod_dir / "desig_ver.cpp").write_text(desig_cpp, encoding="utf-8")

            upgrade_mod.upgrade_source_code(mod_dir, dry_run=False)

            patched_sample = (mod_dir / "comments_and_strings.cpp").read_text(encoding="utf-8")
            self.assertIn("// REL::ID(514287)", patched_sample)
            self.assertIn("/* REL::ID(514287) */", patched_sample)
            self.assertIn('"REL::ID(514287)"', patched_sample)
            self.assertIn("REL::RelocationID(514287, 400447)", patched_sample)

            patched_ae = (mod_dir / "ae_only.cpp").read_text(encoding="utf-8")
            self.assertEqual(patched_ae, "REL::Relocation<void> fn{ REL::ID(10077) };\n")

            patched_brace = (mod_dir / "brace_ver.cpp").read_text(encoding="utf-8")
            self.assertIn("SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5", patched_brace)

            patched_desig = (mod_dir / "desig_ver.cpp").read_text(encoding="utf-8")
            self.assertIn(
                ".versionIndependenceEx = SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5,",
                patched_desig,
            )

        # Direct test of AE-only skip logic in map_ids.patch_single_rel_ids_in_text
        out, conv, skipped = map_ids.patch_single_rel_ids_in_text(
            "auto x = REL::ID(10077);",
            se_to_ae={10077: 999999},
            se_ids_valid={514287},
            target_ids_valid={10077, 400449},
            file_looks_ae_only=False,
        )
        self.assertEqual(out, "auto x = REL::ID(10077);")
        self.assertEqual(conv, 0)
        self.assertEqual(skipped, 1)


if __name__ == "__main__":
    unittest.main()
