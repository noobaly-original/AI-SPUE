import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import verify_dll  # noqa: E402


class TestEndToEndBuild(unittest.TestCase):
    def _run_script(self, script_name: str, *args: str) -> subprocess.CompletedProcess:
        cmd = [sys.executable, str(SCRIPTS_DIR / script_name), *args]
        return subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )

    def test_e2e_upgrade_and_build_mod_b_raw_skse(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mod_dir = root / "ModB_RawSKSE_Legacy"
            dist_dir = root / "dist"
            shutil.copytree(REPO_ROOT / "examples" / "ModB_RawSKSE_Legacy", mod_dir)

            up = self._run_script("upgrade_mod.py", str(mod_dir))
            self.assertEqual(up.returncode, 0, up.stdout + "\n" + up.stderr)

            bld = self._run_script(
                "build_mod.py",
                str(mod_dir),
                "--clean",
                "--dist-dir",
                str(dist_dir),
            )
            self.assertEqual(bld.returncode, 0, bld.stdout + "\n" + bld.stderr)

            built_dll = dist_dir / "ModB_RawSKSE_Legacy" / "SKSE" / "Plugins" / "ModB_RawSKSE_Legacy.dll"
            self.assertTrue(built_dll.exists())
            ver = verify_dll.verify_dll(built_dll)
            self.assertTrue(ver["passed_target"])

            zip_path = dist_dir / "ModB_RawSKSE_Legacy_Updated.zip"
            self.assertTrue(zip_path.exists())
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = [n.replace("\\", "/") for n in zf.namelist()]
                self.assertIn("SKSE/Plugins/ModB_RawSKSE_Legacy.dll", names)

    def test_e2e_upgrade_and_build_mod_a_commonlibsse_ng(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mod_dir = root / "ModA_Outdated_1_6_1170"
            dist_dir = root / "dist"
            shutil.copytree(REPO_ROOT / "examples" / "ModA_Outdated_1_6_1170", mod_dir)

            up = self._run_script("upgrade_mod.py", str(mod_dir))
            self.assertEqual(up.returncode, 0, up.stdout + "\n" + up.stderr)

            bld = self._run_script(
                "build_mod.py",
                str(mod_dir),
                "--clean",
                "--dist-dir",
                str(dist_dir),
            )
            self.assertEqual(bld.returncode, 0, bld.stdout + "\n" + bld.stderr)

            built_dll = dist_dir / "ModA_Outdated_1_6_1170" / "SKSE" / "Plugins" / "ModA_Outdated_1_6_1170.dll"
            self.assertTrue(built_dll.exists())
            ver = verify_dll.verify_dll(built_dll)
            self.assertTrue(ver["passed_target"])

            zip_path = dist_dir / "ModA_Outdated_1_6_1170_Updated.zip"
            self.assertTrue(zip_path.exists())
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = [n.replace("\\", "/") for n in zf.namelist()]
                self.assertIn("SKSE/Plugins/ModA_Outdated_1_6_1170.dll", names)
                self.assertFalse(any(n.endswith("vcpkg.json") or n.endswith("vcpkg-configuration.json") for n in names))


if __name__ == "__main__":
    unittest.main()
