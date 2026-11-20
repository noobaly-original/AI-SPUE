#!/usr/bin/env python3
"""Nexus Mods Clean Release Packager & Verifier (`scripts/package_nexus.py`).

Creates a binary-free, script-free Nexus Mods release archive (default:
`dist/AI-SPUE-Nexus.zip`) per `PACKAGE.md` and `SETUP.md` (Maintainer Note)
using an isolated temporary staging tree so local `tools/`, `sdk/`, and `.venv/`
remain untouched.

Usage:
  python scripts/package_nexus.py
  python scripts/package_nexus.py --dry-run
  python scripts/package_nexus.py --output dist/AI-SPUE-Nexus.zip --require-clean-git
  python scripts/package_nexus.py --verify-only dist/AI-SPUE-Nexus.zip
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "dist" / "AI-SPUE-Nexus.zip"
DEFAULT_STAGE_DIR = REPO_ROOT / "workspace" / "_nexus_stage"

TOP_LEVEL_EXCLUDE_DIRS = {".git", ".venv", "sdk", "tools", "workspace", "dist", ".vs"}
ANY_DEPTH_EXCLUDE_DIRS = {"__pycache__", ".pytest_cache"}
EXCLUDED_FILENAMES = {".gitkeep"}
EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".bak")
FORBIDDEN_EXTENSIONS = (".exe", ".dll", ".lib", ".ps1", ".bat", ".cmd", ".msi", ".vbs")
EMPTY_DIRS_TO_INCLUDE = ("sdk", "tools")

REQUIRED_ARCHIVE_ENTRIES: Tuple[str, ...] = (
    ".agent/rules/SECURITY.md",
    ".agent/skills/skse-plugin-updater/SKILL.md",
    ".agent/skills/nexus-release-packager/SKILL.md",
    ".cursorrules",
    ".github/copilot-instructions.md",
    ".gitignore",
    "AGENTS.md",
    "LICENSE",
    "PACKAGE.md",
    "README.md",
    "SETUP.md",
    "UPDATE_INSTRUCTIONS.md",
    "requirements.txt",
    "scripts/package_nexus.py",
    "sdk/",
    "tools/",
    "templates/sdk/AddressLibrary/versionlibdb.h",
    "templates/sdk/vcpkg-overlays/commonlibsse-ng/portfile.cmake",
    "templates/sdk/address_tables/se_ae_offsets.csv",
    "templates/sdk/address_tables/LICENSE-se_ae_offsets.txt",
)

_FORBIDDEN_PATH_SEGMENTS = {".git", ".venv", "__pycache__", ".pytest_cache", ".vs"}
_FORBIDDEN_TOP_SEGMENTS = {"workspace", "dist"}


def check_git_cleanliness(repo_root: Path) -> Tuple[List[str], List[str]]:
    """Return `(modified, untracked)` paths from `git status --porcelain`, or `([], [])` if unavailable."""
    if not (repo_root / ".git").exists():
        return [], []
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return [], []
    if proc.returncode != 0:
        return [], []

    modified: List[str] = []
    untracked: List[str] = []
    for raw in proc.stdout.splitlines():
        line = raw.rstrip("\r\n")
        if len(line) < 4:
            continue
        code = line[:2]
        entry = line[3:]
        if code == "??":
            untracked.append(entry)
        else:
            modified.append(entry)
    return modified, untracked


def _remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def stage_release_tree(repo_root: Path, stage_dir: Path) -> Dict[str, Any]:
    """Copy releasable project files into a clean `stage_dir` with empty `sdk/` and `tools/`."""
    repo_root = repo_root.resolve()
    stage_dir = stage_dir.resolve()
    _remove_tree(stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    stage_rel: Optional[Path] = None
    try:
        stage_rel = stage_dir.relative_to(repo_root)
    except ValueError:
        stage_rel = None

    copied_files = 0
    created_dirs = 0

    for root, dirs, files in os.walk(repo_root):
        rel_root = Path(root).relative_to(repo_root)
        is_top = rel_root == Path(".")

        pruned: List[str] = []
        for d in sorted(dirs):
            if d in ANY_DEPTH_EXCLUDE_DIRS:
                continue
            if is_top and d in TOP_LEVEL_EXCLUDE_DIRS:
                continue
            if stage_rel is not None and (rel_root / d) == stage_rel:
                continue
            pruned.append(d)
        dirs[:] = pruned

        target_dir = stage_dir / rel_root
        if not target_dir.exists():
            target_dir.mkdir(parents=True, exist_ok=True)
            created_dirs += 1

        for d in dirs:
            sub = target_dir / d
            if not sub.exists():
                sub.mkdir(parents=True, exist_ok=True)
                created_dirs += 1

        for fname in sorted(files):
            if fname in EXCLUDED_FILENAMES or fname.lower().endswith(EXCLUDED_SUFFIXES):
                continue
            shutil.copy2(Path(root) / fname, target_dir / fname)
            copied_files += 1

    for empty_dir in EMPTY_DIRS_TO_INCLUDE:
        target_empty = stage_dir / empty_dir
        if not target_empty.exists():
            target_empty.mkdir(parents=True, exist_ok=True)
            created_dirs += 1

    return {
        "stage_dir": str(stage_dir),
        "copied_files": copied_files,
        "created_dirs": created_dirs,
    }


def audit_staging_tree(stage_dir: Path) -> List[str]:
    """Audit `stage_dir` for Nexus Mods compliance; return list of violation strings."""
    stage_dir = stage_dir.resolve()
    violations: List[str] = []

    if not stage_dir.is_dir():
        return [f"Staging directory does not exist: {stage_dir}"]

    for empty_name in EMPTY_DIRS_TO_INCLUDE:
        d = stage_dir / empty_name
        if not d.is_dir():
            violations.append(f"Missing required empty directory: {empty_name}/")
        elif any(d.iterdir()):
            violations.append(f"Directory must be empty in release archive: {empty_name}/")

    forbidden_file_exts = FORBIDDEN_EXTENSIONS + EXCLUDED_SUFFIXES
    for root, dirs, files in os.walk(stage_dir):
        rel_root = Path(root).relative_to(stage_dir)
        for d in sorted(dirs):
            rel_d = (rel_root / d) if rel_root != Path(".") else Path(d)
            if any(part in _FORBIDDEN_PATH_SEGMENTS for part in rel_d.parts):
                violations.append(f"Forbidden directory in staging: {rel_d.as_posix()}/")
            if rel_d.parts and rel_d.parts[0] in _FORBIDDEN_TOP_SEGMENTS:
                violations.append(f"Forbidden top-level directory in staging: {rel_d.as_posix()}/")

        for fname in sorted(files):
            rel_f = (rel_root / fname) if rel_root != Path(".") else Path(fname)
            rel_posix = rel_f.as_posix()
            if any(part in _FORBIDDEN_PATH_SEGMENTS for part in rel_f.parts):
                violations.append(f"Forbidden path segment in staging: {rel_posix}")
            if rel_f.parts and rel_f.parts[0] in _FORBIDDEN_TOP_SEGMENTS:
                violations.append(f"Forbidden top-level file in staging: {rel_posix}")
            if fname in EXCLUDED_FILENAMES:
                violations.append(f"Excluded placeholder file in staging: {rel_posix}")
            if fname.lower().endswith(forbidden_file_exts):
                violations.append(f"Forbidden binary/script file in staging: {rel_posix}")

    return violations


def find_7z_executable() -> Optional[Path]:
    """Locate `7z` / `7z.exe` on `PATH` or standard 7-Zip install locations."""
    for candidate_name in ("7z", "7z.exe"):
        found = shutil.which(candidate_name)
        if found:
            return Path(found)
    for fixed in (
        Path(r"C:\Program Files\7-Zip\7z.exe"),
        Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
    ):
        if fixed.is_file():
            return fixed
    return None


def _write_zip_via_python(stage_dir: Path, output_zip: Path) -> None:
    rel_dirs: List[str] = []
    rel_files: List[str] = []

    for root, dirs, files in os.walk(stage_dir):
        rel_root = Path(root).relative_to(stage_dir)
        for d in dirs:
            rel_d = (rel_root / d) if rel_root != Path(".") else Path(d)
            rel_dirs.append(rel_d.as_posix() + "/")
        for f in files:
            rel_f = (rel_root / f) if rel_root != Path(".") else Path(f)
            rel_files.append(rel_f.as_posix())

    now_tuple = time.localtime()[:6]
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for d_posix in sorted(set(rel_dirs)):
            zi = zipfile.ZipInfo(d_posix, date_time=now_tuple)
            zi.external_attr = (0o40755 << 16) | 0x10
            zf.writestr(zi, b"")
        for f_posix in sorted(set(rel_files)):
            zf.write(stage_dir / f_posix, arcname=f_posix)


def create_zip_archive(stage_dir: Path, output_zip: Path, backend: str = "auto") -> str:
    """Create a fresh ZIP archive of `stage_dir` at `output_zip`; return backend used."""
    stage_dir = stage_dir.resolve()
    output_zip = output_zip.resolve()
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    if output_zip.exists():
        output_zip.unlink()

    if backend not in {"auto", "7z", "zipfile"}:
        raise ValueError(f"Unsupported backend: {backend}")

    exe = find_7z_executable() if backend in {"auto", "7z"} else None
    if backend == "7z" and exe is None:
        raise FileNotFoundError("7z executable not found on PATH or default 7-Zip install paths.")

    if exe is not None and backend in {"auto", "7z"}:
        proc = subprocess.run(
            [str(exe), "a", "-tzip", "-mx=9", str(output_zip), "*"],
            cwd=str(stage_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(f"7z failed (exit {proc.returncode}): {detail}")
        return "7z"

    _write_zip_via_python(stage_dir, output_zip)
    return "zipfile"


def verify_archive(
    zip_path: Path,
    required_entries: Tuple[str, ...] = REQUIRED_ARCHIVE_ENTRIES,
) -> Dict[str, Any]:
    """Verify ZIP integrity, required structure, empty `sdk/`/`tools/`, and zero forbidden files."""
    zip_path = zip_path.resolve()
    violations: List[str] = []

    if not zip_path.is_file():
        return {
            "ok": False,
            "violations": [f"Archive not found: {zip_path}"],
            "size_bytes": 0,
            "entry_count": 0,
            "file_count": 0,
            "dir_count": 0,
        }

    with zipfile.ZipFile(zip_path, "r") as zf:
        bad_crc = zf.testzip()
        if bad_crc is not None:
            violations.append(f"CRC check failed for entry: {bad_crc}")
        names = zf.namelist()

    name_set = set(names)
    dir_count = sum(1 for n in names if n.endswith("/"))
    file_count = len(names) - dir_count

    for empty_name in EMPTY_DIRS_TO_INCLUDE:
        prefix = f"{empty_name}/"
        if prefix not in name_set:
            violations.append(f"Missing required empty directory entry: {prefix}")
        nested = [n for n in names if n.startswith(prefix) and n != prefix]
        if nested:
            violations.append(f"Non-empty {prefix} in archive ({len(nested)} entries, e.g. {nested[0]})")

    for req in required_entries:
        if req not in name_set:
            violations.append(f"Missing required archive entry: {req}")

    forbidden_file_exts = FORBIDDEN_EXTENSIONS + EXCLUDED_SUFFIXES
    for n in names:
        pure = PurePosixPath(n.rstrip("/"))
        parts = pure.parts
        if any(seg in _FORBIDDEN_PATH_SEGMENTS for seg in parts):
            violations.append(f"Forbidden path segment in archive: {n}")
        if parts and parts[0] in _FORBIDDEN_TOP_SEGMENTS:
            violations.append(f"Forbidden top-level directory in archive: {n}")
        if pure.name in EXCLUDED_FILENAMES:
            violations.append(f"Forbidden placeholder file in archive: {n}")
        if not n.endswith("/") and n.lower().endswith(forbidden_file_exts):
            violations.append(f"Forbidden binary/script extension in archive: {n}")

    return {
        "ok": len(violations) == 0,
        "violations": violations,
        "size_bytes": zip_path.stat().st_size,
        "entry_count": len(names),
        "file_count": file_count,
        "dir_count": dir_count,
    }


def package_nexus_release(
    repo_root: Path = REPO_ROOT,
    output_zip: Path = DEFAULT_OUTPUT,
    stage_dir: Path = DEFAULT_STAGE_DIR,
    backend: str = "auto",
    dry_run: bool = False,
    require_clean_git: bool = False,
    keep_stage: bool = False,
) -> int:
    """Run the full stage -> audit -> compress -> verify -> cleanup Nexus release workflow."""
    repo_root = repo_root.resolve()
    output_zip = output_zip.resolve()
    stage_dir = stage_dir.resolve()

    modified, untracked = check_git_cleanliness(repo_root)
    if modified or untracked:
        msg = (
            f"Working tree has uncommitted changes "
            f"(modified={len(modified)}, untracked={len(untracked)})."
        )
        if require_clean_git:
            print(f"[FAIL] {msg} (--require-clean-git is set)", file=sys.stderr)
            for item in (modified + untracked)[:20]:
                print(f"  - {item}", file=sys.stderr)
            return 1
        print(f"[WARN] {msg}")

    try:
        stage_info = stage_release_tree(repo_root, stage_dir)
        print(
            f"[*] Staged {stage_info['copied_files']} files across clean tree -> {stage_dir}"
        )

        violations = audit_staging_tree(stage_dir)
        if violations:
            print("[FAIL] Staging audit failed:", file=sys.stderr)
            for v in violations:
                print(f"  - {v}", file=sys.stderr)
            return 1
        print("[OK] Staging audit passed (0 forbidden binaries/scripts, empty sdk/ & tools/)")

        if dry_run:
            print(f"[DRY-RUN] Ready to package -> {output_zip} (no ZIP written)")
            return 0

        used_backend = create_zip_archive(stage_dir, output_zip, backend=backend)
        report = verify_archive(output_zip)
        if not report["ok"]:
            print(f"[FAIL] Archive verification failed for {output_zip}:", file=sys.stderr)
            for v in report["violations"]:
                print(f"  - {v}", file=sys.stderr)
            return 1

        print(
            f"[OK] Packaged {output_zip} via {used_backend} "
            f"({report['size_bytes']:,} bytes, {report['entry_count']} entries: "
            f"{report['dir_count']} dirs, {report['file_count']} files)"
        )
        return 0
    finally:
        if not keep_stage:
            _remove_tree(stage_dir)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package AI-SPUE as a binary-free Nexus Mods release ZIP archive."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output ZIP file path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "7z", "zipfile"),
        default="auto",
        help="Compression backend (default: auto, prefers 7z then stdlib zipfile)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Stage and audit the release tree without writing an output ZIP",
    )
    parser.add_argument(
        "--verify-only",
        type=Path,
        default=None,
        help="Verify an existing Nexus release ZIP without staging or repackaging",
    )
    parser.add_argument(
        "--require-clean-git",
        action="store_true",
        help="Abort if `git status --porcelain` reports modified or untracked files",
    )
    parser.add_argument(
        "--keep-stage",
        action="store_true",
        help="Keep the temporary staging directory after packaging finishes",
    )
    parser.add_argument(
        "--stage-dir",
        type=Path,
        default=DEFAULT_STAGE_DIR,
        help=f"Temporary staging directory (default: {DEFAULT_STAGE_DIR})",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help=argparse.SUPPRESS,
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    if args.verify_only is not None:
        report = verify_archive(args.verify_only)
        if not report["ok"]:
            print(f"[FAIL] Archive verification failed for {args.verify_only}:", file=sys.stderr)
            for v in report["violations"]:
                print(f"  - {v}", file=sys.stderr)
            return 1
        print(
            f"[OK] Verified {Path(args.verify_only).resolve()} "
            f"({report['size_bytes']:,} bytes, {report['entry_count']} entries: "
            f"{report['dir_count']} dirs, {report['file_count']} files)"
        )
        return 0

    return package_nexus_release(
        repo_root=args.repo_root,
        output_zip=args.output,
        stage_dir=args.stage_dir,
        backend=args.backend,
        dry_run=args.dry_run,
        require_clean_git=args.require_clean_git,
        keep_stage=args.keep_stage,
    )


if __name__ == "__main__":
    raise SystemExit(main())
