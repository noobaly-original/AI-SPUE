#!/usr/bin/env python3
"""
Future Skyrim Update Runtime Adder (scripts/add_new_runtime.py)

When Bethesda releases a new Skyrim Special Edition update (e.g. 1.7.120 or 1.8.10)
before upstream SKSE64 / CommonLibSSE-NG has tagged a new release, run this script to:
  1. Add `RUNTIME_VERSION_<X>_<Y>_<Z>` and update `CURRENT_RELEASE_RUNTIME` in `sdk/skse64/skse64_common/skse_version.h`.
  2. Add `RUNTIME_SSE_<X>_<Y>_<Z>` and update `RUNTIME_SSE_LATEST_AE` in `sdk/CommonLibSSE-NG/include/SKSE/Version.h`
     (plus the prebuilt/installed header directories).
  3. Copy `versionlib-<X>-<Y>-<Z>-0.bin` from the local Skyrim SE installation (if available) into `sdk/address_tables/bin/`.

Usage:
  python scripts/add_new_runtime.py [version]
  python scripts/add_new_runtime.py              # Auto-detects from installed SkyrimSE.exe / Data\\SKSE\\Plugins
  python scripts/add_new_runtime.py 1.8.10       # Registers an explicit version
"""

import argparse
import re
import shutil
import sys
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402

REPO_ROOT = skse_env.REPO_ROOT
SKSE_VER_H = REPO_ROOT / "sdk" / "skse64" / "skse64_common" / "skse_version.h"
CLIB_VER_HEADERS = [
    REPO_ROOT / "sdk" / "CommonLibSSE-NG" / "include" / "SKSE" / "Version.h",
    REPO_ROOT / "sdk" / "CommonLibSSE-NG-Installed" / "include" / "SKSE" / "Version.h",
]
BIN_DIR = skse_env.BIN_DIR


def parse_ver(ver_str: str):
    return skse_env.parse_version_tuple(ver_str)


def patch_skse_version_h(major: int, minor: int, build: int) -> bool:
    if not SKSE_VER_H.exists():
        return False
    txt = SKSE_VER_H.read_text(encoding="utf-8")
    macro = f"RUNTIME_VERSION_{major}_{minor}_{build}"
    if macro in txt:
        print(f"[*] {macro} already present in {SKSE_VER_H.relative_to(REPO_ROOT)}")
        return False

    new_def = f"#define {macro}\tMAKE_EXE_VERSION({major}, {minor}, {build})"
    txt = re.sub(
        r"(#define\s+PACKED_SKSE_VERSION)",
        f"{new_def}\n\n\\1",
        txt,
        count=1,
    )
    txt = re.sub(
        r"#define\s+CURRENT_RELEASE_RUNTIME\s+\S+",
        f"#define CURRENT_RELEASE_RUNTIME\t\t{macro}",
        txt,
        count=1,
    )
    SKSE_VER_H.write_text(txt, encoding="utf-8")
    print(f"[+] Added {macro} to {SKSE_VER_H.relative_to(REPO_ROOT)}")
    return True


def patch_commonlib_version_h(major: int, minor: int, build: int, sub: int) -> None:
    const_name = f"RUNTIME_SSE_{major}_{minor}_{build}"
    legacy_alias = f"RUNTIME_{major}_{minor}_{build}"
    new_line = f"\tinline constexpr REL::Version {const_name}({major}, {minor}, {build}, {sub});"
    alias_line = f"\tinline constexpr auto {legacy_alias} = {const_name};"

    for vh in CLIB_VER_HEADERS:
        if not vh.exists():
            continue
        txt = vh.read_text(encoding="utf-8")
        changed = False

        if const_name in txt:
            print(f"[*] {const_name} already present in {vh.relative_to(REPO_ROOT)}")
        else:
            new_txt, count = re.subn(
                r"(\tinline constexpr auto RUNTIME_SSE_LATEST_AE\s*=\s*)(\w+)(;)",
                f"{new_line}\n\n\\1{const_name}\\3",
                txt,
                count=1,
            )
            if count:
                txt = new_txt
                changed = True
                print(f"[+] Added {const_name} and updated RUNTIME_SSE_LATEST_AE in {vh.relative_to(REPO_ROOT)}")

        if not re.search(rf"\b{re.escape(legacy_alias)}\b", txt):
            alias_matches = list(
                re.finditer(r"^\tinline constexpr auto RUNTIME_\d+_\d+_\d+\s*=\s*RUNTIME_SSE_\d+_\d+_\d+;", txt, re.MULTILINE)
            )
            if alias_matches:
                pos = alias_matches[-1].end()
                txt = txt[:pos] + "\n" + alias_line + txt[pos:]
                changed = True
                print(f"[+] Added legacy alias {legacy_alias} in {vh.relative_to(REPO_ROOT)}")

        if changed:
            vh.write_text(txt, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Register a new Skyrim runtime version in local SKSE64 & CommonLibSSE-NG SDKs")
    parser.add_argument(
        "version",
        nargs="?",
        default=None,
        help="New Skyrim runtime version (e.g. 1.7.120); omit to auto-detect from SkyrimSE.exe / Data\\SKSE\\Plugins",
    )
    parser.add_argument(
        "--bin-path",
        type=Path,
        default=None,
        help="Optional explicit path to versionlib-*.bin to copy into sdk/address_tables/bin/",
    )
    args = parser.parse_args()

    if args.version:
        ver_tuple = parse_ver(args.version)
        print(f"[*] Using explicit runtime version: {skse_env.format_version_dot(ver_tuple, drop_zero_sub=False)}")
    else:
        detected = skse_env.detect_installed_skyrim_version()
        if detected is not None:
            ver_tuple = detected
            print(f"[*] Auto-detected runtime from SkyrimSE.exe: {skse_env.format_version_dot(ver_tuple, drop_zero_sub=False)}")
        else:
            bins = skse_env.detect_installed_addrlib_bins()
            if not bins:
                print(
                    "[ERROR] Could not auto-detect runtime from SkyrimSE.exe or Data\\SKSE\\Plugins\\version*.bin. "
                    "Pass an explicit version argument, e.g. `python scripts/add_new_runtime.py <MAJOR>.<MINOR>.<BUILD>`.",
                    file=sys.stderr,
                )
                return 1
            ver_list = [v for v, _ in bins]
            mainline = [v for v in ver_list if v[3] == 0]
            ver_tuple = max(mainline) if mainline else max(ver_list)
            print(
                f"[*] Auto-detected runtime from Data\\SKSE\\Plugins: "
                f"{skse_env.format_version_dot(ver_tuple, drop_zero_sub=False)}"
            )

    major, minor, build, sub = ver_tuple
    patch_skse_version_h(major, minor, build)
    patch_commonlib_version_h(major, minor, build, sub)

    bin_name = f"versionlib-{major}-{minor}-{build}-{sub}.bin"
    dest_bin = BIN_DIR / bin_name
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    src_bin: Optional[Path] = None
    if args.bin_path is not None:
        src_bin = args.bin_path.resolve()
        if not src_bin.exists():
            print(f"[ERROR] Provided --bin-path does not exist: {src_bin}", file=sys.stderr)
            return 1
    else:
        cand = skse_env.find_skyrim_plugins_dir() / bin_name
        if cand.exists():
            src_bin = cand

    if src_bin is not None and src_bin != dest_bin and (args.bin_path is not None or not dest_bin.exists()):
        shutil.copy2(src_bin, dest_bin)
        print(f"[+] Copied {bin_name} from {src_bin.parent} into sdk/address_tables/bin/")

    if skse_env.ID_MAP_CACHE_FILE.exists():
        try:
            skse_env.ID_MAP_CACHE_FILE.unlink()
            print(f"[+] Cleared cached ID map: {skse_env.ID_MAP_CACHE_FILE.relative_to(REPO_ROOT)}")
        except OSError:
            pass
    skse_env.clear_id_maps_cache()

    return 0


if __name__ == "__main__":
    sys.exit(main())
