import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import env as env_script  # noqa: E402
import live_test_skse  # noqa: E402


class TestEnvAndLiveTest(unittest.TestCase):
    def test_is_venv_home_valid_and_activated_env(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            vroot = Path(td) / ".venv"
            vroot.mkdir()
            (vroot / "pyvenv.cfg").write_text(f"home = {Path(sys.executable).parent}\n", encoding="utf-8")
            self.assertTrue(env_script._is_venv_home_valid(vroot))

            (vroot / "pyvenv.cfg").write_text("home = Z:\\NoSuchPythonDir\\313\n", encoding="utf-8")
            self.assertFalse(env_script._is_venv_home_valid(vroot))

        activated, summary = env_script.build_activated_env(
            base_env={"PATH": os.environ.get("PATH", "")},
            include_vcvars=False,
        )
        self.assertEqual(summary["exported"]["VCPKG_DEFAULT_TRIPLET"], "x64-windows-static-md")
        self.assertEqual(activated["COMMONLIB_PREBUILT"], "1")
        self.assertIn("COMMONLIB_SSE_NG_DIR", summary["exported"])

    def test_env_cli_json_export_and_subprocess_runner(self) -> None:
        res_json = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "env.py"), "--no-vcvars", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res_json.returncode, 0, res_json.stderr)
        data = json.loads(res_json.stdout)
        self.assertIn("exported", data)
        self.assertIn("tools", data)

        res_ps = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "env.py"), "--no-vcvars", "--export-ps"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res_ps.returncode, 0, res_ps.stderr)
        self.assertIn("$env:VCPKG_DEFAULT_TRIPLET = 'x64-windows-static-md'", res_ps.stdout)

        res_cmd = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "env.py"),
                "--no-vcvars",
                "--",
                sys.executable,
                "-c",
                "import os; print(os.environ['COMMONLIB_PREBUILT'])",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res_cmd.returncode, 0, res_cmd.stderr)
        self.assertEqual(res_cmd.stdout.strip(), "1")

        # Propagate non-zero command exit code
        res_fail = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "env.py"), "--no-vcvars", "--", sys.executable, "-c", "import sys; sys.exit(7)"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res_fail.returncode, 7)

    def test_log_reader_and_backup_restore_no_launch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            skyrim_dir = root / "Skyrim"
            plugins_dir = skyrim_dir / "Data" / "SKSE" / "Plugins"
            log_dir = root / "Logs"
            plugins_dir.mkdir(parents=True)
            log_dir.mkdir(parents=True)

            # Incremental UTF-8 BOM log streaming + shrink reset
            log_file = log_dir / "skse64.log"
            log_file.write_bytes("\ufeffline1\n".encode("utf-8"))
            lines, off = live_test_skse.read_new_log_lines(log_file, 0)
            self.assertEqual(lines, ["line1"])
            with log_file.open("ab") as f:
                f.write(b"line2\n")
            lines2, off2 = live_test_skse.read_new_log_lines(log_file, off)
            self.assertEqual(lines2, ["line2"])
            self.assertGreater(off2, off)
            log_file.write_bytes(b"reset\n")
            lines3, _ = live_test_skse.read_new_log_lines(log_file, off2)
            self.assertEqual(lines3, ["reset"])

            # Existing DLL gets backed up and restored after no_launch run
            existing_dll = plugins_dir / "MyMod.dll"
            existing_dll.write_bytes(b"ORIGINAL")
            new_src_dll = root / "staging" / "MyMod.dll"
            new_src_dll.parent.mkdir()
            new_src_dll.write_bytes(b"PATCHED")

            rc = live_test_skse.run_live_test(
                plugin_dll=str(new_src_dll),
                plugins_dir=str(plugins_dir),
                skyrim_dir=str(skyrim_dir),
                log_dir=str(log_dir),
                no_launch=True,
            )
            self.assertEqual(rc, 0)
            self.assertEqual(existing_dll.read_bytes(), b"ORIGINAL")
            self.assertFalse((plugins_dir / "MyMod.dll.livetest.bak").exists())

            # Missing DLL -> exit code 4
            rc_missing = live_test_skse.run_live_test(
                plugin_dll=str(root / "Missing.dll"),
                plugins_dir=str(plugins_dir),
                skyrim_dir=str(skyrim_dir),
                log_dir=str(log_dir),
                no_launch=True,
            )
            self.assertEqual(rc_missing, 4)

    def test_live_test_mocked_launch_success_and_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            skyrim_dir = root / "Skyrim"
            plugins_dir = skyrim_dir / "Data" / "SKSE" / "Plugins"
            log_dir = root / "Logs"
            plugins_dir.mkdir(parents=True)
            log_dir.mkdir(parents=True)
            (skyrim_dir / "skse64_loader.exe").write_bytes(b"MZ")
            test_dll = root / "Demo.dll"
            test_dll.write_bytes(b"MZ")

            class FakeProc:
                def poll(self):
                    return 0

            # Case 1: clean init + auto-close -> exit 0, temporary Demo.dll removed from plugins_dir
            def fake_sleep_ok(_sec: float) -> None:
                (log_dir / "skse64.log").write_text(
                    "plugin Demo.dll (00000001 Demo 01000000) loaded correctly (handle 1)\ninit complete\n",
                    encoding="utf-8",
                )

            mon_calls = [0]

            def fake_monotonic() -> float:
                if not (log_dir / "skse64.log").exists():
                    return 0.0
                mon_calls[0] += 1
                return 1.0 if mon_calls[0] <= 2 else 5.0

            with (
                mock.patch.object(live_test_skse.subprocess, "Popen", return_value=FakeProc()),
                mock.patch.object(live_test_skse, "get_process_exit_code", return_value=(False, None)),
                mock.patch.object(live_test_skse, "is_process_window_unresponsive", return_value=False),
                mock.patch.object(live_test_skse, "terminate_process") as mock_term,
                mock.patch.object(live_test_skse, "query_windows_skyrim_crash_events", return_value=[]),
                mock.patch.object(live_test_skse.time, "sleep", side_effect=fake_sleep_ok),
                mock.patch.object(live_test_skse.time, "monotonic", side_effect=fake_monotonic),
            ):
                rc_ok = live_test_skse.run_live_test(
                    plugin_dll=str(test_dll),
                    plugins_dir=str(plugins_dir),
                    skyrim_dir=str(skyrim_dir),
                    log_dir=str(log_dir),
                    timeout_seconds=10,
                    auto_close=True,
                    process_finder=lambda: 12345,
                )
            self.assertEqual(rc_ok, 0)
            mock_term.assert_called()
            self.assertFalse((plugins_dir / "Demo.dll").exists())

            # Case 2: SKSE reports Demo.dll incompatible -> exit 1
            def fake_sleep_rej(_sec: float) -> None:
                (log_dir / "skse64.log").write_text(
                    "plugin Demo.dll (00000001 Demo 01000000) reported as incompatible during load\n",
                    encoding="utf-8",
                )

            with (
                mock.patch.object(live_test_skse.subprocess, "Popen", return_value=FakeProc()),
                mock.patch.object(
                    live_test_skse,
                    "get_process_exit_code",
                    side_effect=[(False, None), (True, 1), (True, 1)],
                ),
                mock.patch.object(live_test_skse, "is_process_window_unresponsive", return_value=False),
                mock.patch.object(live_test_skse, "query_windows_skyrim_crash_events", return_value=[]),
                mock.patch.object(live_test_skse.time, "sleep", side_effect=fake_sleep_rej),
            ):
                rc_rej = live_test_skse.run_live_test(
                    plugin_dll=str(test_dll),
                    plugins_dir=str(plugins_dir),
                    skyrim_dir=str(skyrim_dir),
                    log_dir=str(log_dir),
                    timeout_seconds=10,
                    auto_close=True,
                    process_finder=lambda: 12345,
                )
            self.assertEqual(rc_rej, 1)


if __name__ == "__main__":
    unittest.main()
