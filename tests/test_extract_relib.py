import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import extract_relib  # noqa: E402
import inspect_bin  # noqa: E402
import skse_env  # noqa: E402


class TestExtractRelib(unittest.TestCase):
    def test_relib_parse_and_format2_bin_roundtrip(self) -> None:
        # Exercise multiple nibble packing cases: sequential, byte diff, neg diff, ushort, uint, pointer-aligned vs unaligned
        vals_640 = [
            (100, 0x1000),
            (101, 0x1008),      # low=1 (vid+1), high aligned +1
            (150, 0x1200),      # +49 vid, aligned delta
            (140, 0x1100),      # negative vdiff (-10 -> low=3), negative aligned odiff
            (40000, 0x30005),   # large positive vdiff, unaligned offset
            (120000, 0x145678), # >65535 vid diff & unaligned >65535 offset
        ]
        vals_1170_gog = [
            (100, 0x1040),
            (101, 0x1048),
            (120000, 0x150000),
        ]
        hashes_640 = [(100, 0xDEADBEEFCAFEBABE), (120000, 0x0123456789ABCDEF)]

        relib_bytes = extract_relib.build_relib_bytes(
            [
                ((1, 6, 640, 0), None, 0x140000000, vals_640, hashes_640),
                ((1, 6, 1170, 0, 1), "SkyrimSE.exe", 0x140000000, vals_1170_gog, []),
            ],
            format_version=2,
            pointer_size=8,
            target_module_name="SkyrimSE.exe",
        )

        db = extract_relib.parse_relib_bytes(relib_bytes)
        self.assertEqual(db.format_version, 2)
        self.assertEqual(db.high_vid, 120000)
        self.assertEqual(db.pointer_size, 8)
        self.assertEqual(db.target_module_name, "SkyrimSE.exe")
        self.assertEqual(len(db.versions), 2)

        v640 = db.get_version("1.6.640.0")
        self.assertIsNotNone(v640)
        assert v640 is not None
        self.assertEqual(v640.to_id_offset_dict(), dict(vals_640))
        self.assertEqual(v640.to_hash_dict(), dict(hashes_640))

        vgog = db.get_version("1-6-1170-0-1")
        self.assertIsNotNone(vgog)
        assert vgog is not None
        self.assertEqual(vgog.to_id_offset_dict(), dict(vals_1170_gog))

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            written = extract_relib.extract_bins_from_relib(db, out_dir)
            names = sorted(p.name for p in written)
            self.assertEqual(names, ["versionlib-1-6-1170-0-1.bin", "versionlib-1-6-640-0.bin"])

            parsed_640 = inspect_bin.AddressLibBin(out_dir / "versionlib-1-6-640-0.bin")
            self.assertEqual(parsed_640.format, 2)
            self.assertEqual(parsed_640.version, (1, 6, 640, 0))
            self.assertEqual(parsed_640.module_name, "SkyrimSE.exe")
            self.assertEqual(parsed_640.id_to_offset, dict(vals_640))

            parsed_gog = inspect_bin.AddressLibBin(out_dir / "versionlib-1-6-1170-0-1.bin")
            self.assertEqual(parsed_gog.format, 2)
            self.assertEqual(parsed_gog.version, (1, 6, 1170, 0))
            self.assertEqual(parsed_gog.id_to_offset, dict(vals_1170_gog))

    def test_rename_parse_and_csv_export(self) -> None:
        rename_txt = "\ufeff1\n# comment\n; another comment\n\n100 TESForm::LookupByID\n120000 Actor::GetActorBase(bool a_base)\n"
        fmt_v, parsed = extract_relib.parse_rename_text(rename_txt)
        self.assertEqual(fmt_v, 1)
        self.assertEqual(
            parsed,
            {
                100: "TESForm::LookupByID",
                120000: "Actor::GetActorBase(bool a_base)",
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            relib_path = tmp / "test.relib"
            rename_path = tmp / "test.rename"
            csv_path = tmp / "out.csv"

            relib_path.write_bytes(
                extract_relib.build_relib_bytes(
                    [((1, 6, 640, 0), None, 0x140000000, [(100, 0x1000), (120000, 0x2000)], [])]
                )
            )
            rename_path.write_text(rename_txt, encoding="utf-8")

            loaded = skse_env.load_ae_rename_map(rename_path)
            self.assertEqual(loaded, parsed)

            db = extract_relib.load_relib(relib_path)
            rows = extract_relib.export_relib_csv(db, csv_path, rename_map=loaded)
            self.assertEqual(rows, 2)
            with csv_path.open("r", encoding="utf-8", newline="") as f:
                csv_rows = list(csv.reader(f))
            self.assertEqual(csv_rows[0], ["ae_id", "name", "1.6.640.0"])
            self.assertEqual(csv_rows[1], ["100", "TESForm::LookupByID", "0x1000"])
            self.assertEqual(csv_rows[2], ["120000", "Actor::GetActorBase(bool a_base)", "0x2000"])

    def test_extract_relib_cli_info_and_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            relib_path = tmp / "mini.relib"
            rename_path = tmp / "mini.rename"
            relib_path.write_bytes(
                extract_relib.build_relib_bytes(
                    [((1, 6, 1170, 0), None, 0x140000000, [(514167, 0x62C870)], [])]
                )
            )
            rename_path.write_text("1\n514167 TESObjectREFR::MoveTo\n", encoding="utf-8")

            res_info = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "extract_relib.py"), "info", "--relib", str(relib_path), "--rename", str(rename_path), "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_info.returncode, 0, res_info.stderr)
            self.assertIn("1.6.1170.0", res_info.stdout)

            res_lookup = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "extract_relib.py"), "lookup", "MoveTo", "--relib", str(relib_path), "--rename", str(rename_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_lookup.returncode, 0, res_lookup.stderr)
            self.assertIn("514167", res_lookup.stdout)
            self.assertIn("0x62C870", res_lookup.stdout)


if __name__ == "__main__":
    unittest.main()
