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

import package_nexus  # noqa: E402


def _populate_required_files(repo: Path) -> None:
    for entry in package_nexus.REQUIRED_ARCHIVE_ENTRIES:
        if entry.endswith("/"):
            (repo / entry.rstrip("/")).mkdir(parents=True, exist_ok=True)
            continue
        p = repo / entry
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"dummy content for {entry}\n", encoding="utf-8")


class TestPackageNexus(unittest.TestCase):
    def test_stage_audit_and_zipfile_backend_synthetic_repo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            out_zip = root / "out" / "AI-SPUE-Nexus.zip"
            stage_dir = root / "stage"

            _populate_required_files(repo)

            # Top-level excluded dirs & binaries/scripts that must stay untouched locally
            sdk_lib = repo / "sdk" / "Big.lib"
            sdk_lib.write_bytes(b"FAKE_LIB")
            (repo / "sdk" / ".gitkeep").write_text("", encoding="utf-8")
            tool_exe = repo / "tools" / "tool.exe"
            tool_exe.write_bytes(b"MZ_FAKE")
            venv_exe = repo / ".venv" / "python.exe"
            venv_exe.parent.mkdir(parents=True, exist_ok=True)
            venv_exe.write_bytes(b"MZ_FAKE")
            (repo / ".git" / "HEAD").parent.mkdir(parents=True, exist_ok=True)
            (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (repo / "workspace" / "tmp.txt").parent.mkdir(parents=True, exist_ok=True)
            (repo / "workspace" / "tmp.txt").write_text("scratch\n", encoding="utf-8")
            (repo / "dist" / "old.zip").parent.mkdir(parents=True, exist_ok=True)
            (repo / "dist" / "old.zip").write_bytes(b"PK")

            # Any-depth excluded dirs & temp suffixes
            (repo / "scripts" / "__pycache__" / "x.pyc").parent.mkdir(parents=True, exist_ok=True)
            (repo / "scripts" / "__pycache__" / "x.pyc").write_bytes(b"\x00")
            (repo / ".pytest_cache" / "v").parent.mkdir(parents=True, exist_ok=True)
            (repo / ".pytest_cache" / "v").write_text("1", encoding="utf-8")
            (repo / "foo.bak").write_text("backup", encoding="utf-8")

            rc = package_nexus.package_nexus_release(
                repo_root=repo,
                output_zip=out_zip,
                stage_dir=stage_dir,
                backend="zipfile",
            )
            self.assertEqual(rc, 0)
            self.assertTrue(out_zip.is_file())
            self.assertFalse(stage_dir.exists())

            report = package_nexus.verify_archive(out_zip)
            self.assertTrue(report["ok"], f"Unexpected violations: {report['violations']}")

            with zipfile.ZipFile(out_zip, "r") as zf:
                names = set(zf.namelist())

            self.assertIn("sdk/", names)
            self.assertIn("tools/", names)
            self.assertIn("templates/sdk/address_tables/se_ae_offsets.csv", names)
            self.assertIn(".agent/rules/SECURITY.md", names)
            self.assertIn(".cursorrules", names)
            self.assertNotIn("sdk/Big.lib", names)
            self.assertNotIn("sdk/.gitkeep", names)
            self.assertNotIn("tools/tool.exe", names)
            self.assertNotIn("foo.bak", names)

            # Local binaries/tools must remain completely untouched
            self.assertTrue(sdk_lib.is_file())
            self.assertTrue(tool_exe.is_file())
            self.assertTrue(venv_exe.is_file())

    def test_audit_rejects_forbidden_files_and_cleans_stage(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "repo"
            out_zip = root / "out" / "bad.zip"
            stage_dir = root / "stage"

            _populate_required_files(repo)
            (repo / "docs").mkdir(parents=True, exist_ok=True)
            (repo / "docs" / "bad.exe").write_bytes(b"MZ")
            (repo / "scripts" / "bad.ps1").write_text("Write-Host 'bad'\n", encoding="utf-8")

            # Verify audit directly catches both files cleanly before cleanup
            package_nexus.stage_release_tree(repo, stage_dir)
            violations = package_nexus.audit_staging_tree(stage_dir)
            joined = "\n".join(violations)
            self.assertIn("docs/bad.exe", joined)
            self.assertIn("scripts/bad.ps1", joined)

            rc = package_nexus.package_nexus_release(
                repo_root=repo,
                output_zip=out_zip,
                stage_dir=stage_dir,
                backend="zipfile",
            )
            self.assertNotEqual(rc, 0)
            self.assertFalse(out_zip.exists())
            self.assertFalse(stage_dir.exists())

    def test_verify_archive_catches_tampering_and_real_repo_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            # 1. File nested inside sdk/
            z1 = root / "non_empty_sdk.zip"
            with zipfile.ZipFile(z1, "w") as zf:
                for entry in package_nexus.REQUIRED_ARCHIVE_ENTRIES:
                    if entry.endswith("/"):
                        zf.writestr(entry, b"")
                    else:
                        zf.writestr(entry, b"ok")
                zf.writestr("sdk/nested.txt", b"oops")
            r1 = package_nexus.verify_archive(z1)
            self.assertFalse(r1["ok"])
            self.assertTrue(any("Non-empty sdk/" in v for v in r1["violations"]))

            # 2. Forbidden .dll extension
            z2 = root / "bad_dll.zip"
            with zipfile.ZipFile(z2, "w") as zf:
                for entry in package_nexus.REQUIRED_ARCHIVE_ENTRIES:
                    if entry.endswith("/"):
                        zf.writestr(entry, b"")
                    else:
                        zf.writestr(entry, b"ok")
                zf.writestr("scripts/evil.dll", b"MZ")
            r2 = package_nexus.verify_archive(z2)
            self.assertFalse(r2["ok"])
            self.assertTrue(any("scripts/evil.dll" in v for v in r2["violations"]))

            # 3. Missing required entry (PACKAGE.md)
            z3 = root / "missing_pkg.zip"
            with zipfile.ZipFile(z3, "w") as zf:
                for entry in package_nexus.REQUIRED_ARCHIVE_ENTRIES:
                    if entry == "PACKAGE.md":
                        continue
                    if entry.endswith("/"):
                        zf.writestr(entry, b"")
                    else:
                        zf.writestr(entry, b"ok")
            r3 = package_nexus.verify_archive(z3)
            self.assertFalse(r3["ok"])
            self.assertTrue(any("PACKAGE.md" in v for v in r3["violations"]))

            # 4. Real repository --dry-run using an isolated temp staging directory
            real_stage = root / "real_stage"
            rc = package_nexus.main(["--dry-run", "--stage-dir", str(real_stage)])
            self.assertEqual(rc, 0)
            self.assertFalse(real_stage.exists())


if __name__ == "__main__":
    unittest.main()
