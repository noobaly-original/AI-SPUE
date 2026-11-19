import contextlib
import io
import json
import sys
import types
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import addrlib_xref  # noqa: E402
import inspect_bin  # noqa: E402
import skse_env  # noqa: E402


class TestAddrLibXref(unittest.TestCase):
    def test_formats_and_map_id(self) -> None:
        target_dash = skse_env.get_default_target_dash()
        target_full = skse_env.format_version_dot(skse_env.get_latest_target_version(), drop_zero_sub=False)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = addrlib_xref.cmd_formats(types.SimpleNamespace(bin_dir=skse_env.BIN_DIR, json=True))
        self.assertEqual(rc, 0)
        rows = json.loads(buf.getvalue())
        versions = {r.get("version"): r.get("format") for r in rows}
        self.assertEqual(versions.get("1.5.97.0"), 1)
        self.assertEqual(versions.get("1.6.1170.0"), 2)
        self.assertEqual(versions.get(target_full), 5)

        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            rc2 = addrlib_xref.cmd_map_id(
                types.SimpleNamespace(ids=[47286, 400447], src_ver="1-6-1170-0", dst_ver=target_dash, json=True)
            )
        self.assertEqual(rc2, 0)
        payload = json.loads(buf2.getvalue())
        by_src = {m["source_id"]: m for m in payload["mappings"]}
        self.assertEqual(by_src[47286]["target_id"], 523983)
        self.assertEqual(by_src[47286]["status"], "SPLIT_ID")
        self.assertEqual(by_src[400447]["target_id"], 400447)
        self.assertEqual(by_src[400447]["status"], "UNCHANGED_ID")

    def test_map_offset_exact_and_interior(self) -> None:
        target_dash = skse_env.get_default_target_dash()
        db_1170 = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path("1-6-1170-0"))
        db_target = inspect_bin.AddressLibBin(inspect_bin.resolve_bin_path(target_dash))
        rva_47286_old = db_1170.id_to_offset[47286]
        rva_523983_new = db_target.id_to_offset[523983]

        interior_old_va = 0x140000000 + rva_47286_old + 0x14
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = addrlib_xref.cmd_map_offset(
                types.SimpleNamespace(
                    offsets=[f"0x{rva_47286_old:x}", f"0x{interior_old_va:x}"],
                    src_ver="1-6-1170-0",
                    dst_ver=target_dash,
                    json=True,
                )
            )
        self.assertEqual(rc, 0)
        items = json.loads(buf.getvalue())["offsets"]
        self.assertEqual(items[0]["target_base_id"], 523983)
        self.assertEqual(items[0]["estimated_target_rva"], f"0x{rva_523983_new:08x}")
        self.assertIsNone(items[0]["warning"])

        self.assertEqual(items[1]["target_base_id"], 523983)
        self.assertEqual(items[1]["delta"], "0x14")
        self.assertEqual(items[1]["estimated_target_rva"], f"0x{rva_523983_new + 0x14:08x}")
        self.assertIsNotNone(items[1]["warning"])

    def test_diff_ids_and_scan_dll(self) -> None:
        target_dash = skse_env.get_default_target_dash()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = addrlib_xref.cmd_diff_ids(
                types.SimpleNamespace(src_ver="1-6-1170-0", dst_ver=target_dash, ids="47286,400447", json=True)
            )
        self.assertEqual(rc, 0)
        diff_data = json.loads(buf.getvalue())
        self.assertEqual(len(diff_data["items"]), 2)

        shim_path = REPO_ROOT / "sdk" / "preload" / "build" / "AddressLibraryV5Shim.dll"
        rep = addrlib_xref.scan_dll_address_library(shim_path, target_runtime=target_dash)
        self.assertEqual(rep["target_bin_format"], 5)
        self.assertFalse(rep["pre_v5_timestamp"])
        self.assertEqual(rep["findings"], [])


if __name__ == "__main__":
    unittest.main()
