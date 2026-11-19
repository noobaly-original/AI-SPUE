import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from unittest import mock

import inspect_bin  # noqa: E402
import map_ids  # noqa: E402
import skse_env  # noqa: E402


class TestInspectAndMap(unittest.TestCase):
    def test_parse_real_bins_formats_1_2_5(self) -> None:
        target_dash = skse_env.get_default_target_dash()
        target_full = skse_env.format_version_dot(skse_env.get_latest_target_version(), drop_zero_sub=False)
        db_se = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path("1-5-97-0"))
        db_1170 = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path("1-6-1170-0"))
        db_target = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path(target_dash))

        self.assertEqual(db_se.format, 1)
        self.assertEqual(db_se.version_str, "1.5.97.0")
        self.assertEqual(db_1170.format, 2)
        self.assertEqual(db_1170.version_str, "1.6.1170.0")
        self.assertEqual(db_target.format, 5)
        self.assertEqual(db_target.version_str, target_full)

        self.assertIn(514287, db_se.id_to_offset)
        self.assertIn(400449, db_1170.id_to_offset)
        self.assertIn(400449, db_target.id_to_offset)

        # 47286 existed in 1.6.1170 and moved to 523983 in 1.7.99+
        self.assertIn(47286, db_1170.id_to_offset)
        self.assertNotIn(47286, db_target.id_to_offset)
        self.assertIn(523983, db_target.id_to_offset)

    def test_resolve_bin_path_checks_skyrim_plugins_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            plug_dir = Path(td)
            fake_bin = plug_dir / "versionlib-9-9-9-0.bin"
            fake_bin.write_bytes(b"")
            with mock.patch.object(skse_env, "find_skyrim_plugins_dir", return_value=plug_dir):
                self.assertEqual(inspect_bin.resolve_bin_path("9-9-9-0"), fake_bin)

    def test_se_ae_mappings(self) -> None:
        se_to_ae, ae_to_se, _ = map_ids.build_combined_se_ae_maps()
        self.assertEqual(se_to_ae[514287], 400447)
        self.assertEqual(ae_to_se[400447], 514287)
        self.assertEqual(se_to_ae[46022], 523983)

    def test_scan_mod_ids_ignores_comments_preserves_lines(self) -> None:
        cpp = (
            "// REL::ID(11111)\n"
            "/*\n"
            "   REL::ID(22222)\n"
            "*/\n"
            "REL::RelocationID(46022, 523983);\n"
            "REL::ID(514287); // trailing REL::ID(33333)\n"
        )
        with tempfile.TemporaryDirectory() as td:
            mod_dir = Path(td)
            (mod_dir / "test.cpp").write_text(cpp, encoding="utf-8")
            scanned = inspect_bin.scan_mod_ids(mod_dir)

        self.assertEqual(scanned["dual_id"], [("test.cpp", 5, (46022, 523983))])
        self.assertEqual(scanned["single_id"], [("test.cpp", 6, (514287,))])


if __name__ == "__main__":
    unittest.main()
