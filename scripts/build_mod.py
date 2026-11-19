#!/usr/bin/env python3
"""
One-Command SKSE64 Plugin Builder, Binary Verifier & Packager (scripts/build_mod.py)

Automatically:
  1. Loads the Visual Studio 2022 x64 MSVC (`vcvars64.bat`) environment + portable CMake,
     Ninja, vcpkg, XMake, and local prebuilt CommonLibSSE-NG (no PowerShell ExecutionPolicy issues).
  2. Builds the target mod using its native build system (CMake, XMake, or MSBuild .sln/.vcxproj).
  3. Locates all compiled `.dll` and `.pdb` outputs.
  4. Runs binary verification (`verify_dll.py`) on the compiled `.dll` to guarantee `SKSEPlugin_Version`
     (including `kVersionIndependentEx_AddressLibraryV5` for 1.7.99+) and `SKSEPlugin_Load` are exported.
  5. Packages the updated `.dll` (plus `.pdb` and any `.ini`/`.toml`/`.json` configs) into:
       - `dist/<ModName>/SKSE/Plugins/`
       - `dist/<ModName>_Updated.zip` (ready to install in Mod Organizer 2 or Vortex)

Usage:
  python scripts/build_mod.py <mod_dir> [--build-system auto|cmake|xmake|msbuild] [--clean]
"""

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402
from verify_dll import print_verification, verify_dll  # noqa: E402

REPO_ROOT = skse_env.REPO_ROOT
TOOLS_DIR = skse_env.TOOLS_DIR
SDK_DIR = skse_env.SDK_DIR
DIST_DIR = skse_env.DIST_DIR


def load_build_environment() -> Dict[str, str]:
    env = os.environ.copy()

    # 1. Load MSVC vcvars64.bat via vswhere / multi-version discovery
    vcvars = skse_env.find_vcvars64()
    env_ci = {k.upper(): k for k in env}
    if vcvars:
        cmd = f'"{vcvars}" >nul 2>&1 && set'
        out = subprocess.check_output(cmd, shell=True, text=True, encoding="utf-8", errors="replace")
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                real_k = env_ci.get(k.upper(), k)
                env[real_k] = v
                env_ci[k.upper()] = real_k

    # 2. Prepend portable CMake, Ninja, vcpkg, XMake
    cmake_bin = str(TOOLS_DIR / "cmake" / "bin")
    ninja_bin = str(TOOLS_DIR / "ninja")
    vcpkg_root = str(TOOLS_DIR / "vcpkg")
    xmake_bin = str(TOOLS_DIR / "xmake")
    vcpkg_archives = TOOLS_DIR / "vcpkg" / "archives"
    vcpkg_archives.mkdir(parents=True, exist_ok=True)

    path_key = env_ci.get("PATH", "PATH")
    path_parts = [cmake_bin, ninja_bin, vcpkg_root, xmake_bin, env.get(path_key, "")]
    env[path_key] = ";".join(p for p in path_parts if p)

    # 3. Export vcpkg & CommonLibSSE-NG variables (keeping caches portable inside tools/)
    env["VCPKG_ROOT"] = vcpkg_root
    env["VCPKG_DEFAULT_TRIPLET"] = "x64-windows-static-md"
    env["VCPKG_DEFAULT_BINARY_CACHE"] = str(vcpkg_archives)
    env["SKSE_UPDATER_ROOT"] = str(REPO_ROOT)
    env["SKSE_SDK_ROOT"] = str(SDK_DIR)
    env["COMMONLIB_SSE_NG_DIR"] = str(SDK_DIR / "CommonLibSSE-NG")
    env["COMMONLIB_PREBUILT"] = "1"

    prebuilt_cmake = SDK_DIR / "CommonLibSSE-NG-Installed"
    if (prebuilt_cmake / "lib" / "CommonLibSSE.lib").exists():
        env["COMMONLIB_PREBUILT_DIR"] = str(prebuilt_cmake).replace("\\", "/")

    return env


def build_with_cmake(mod_dir: Path, env: Dict[str, str], clean: bool) -> Path:
    build_dir = mod_dir / "build" / "skse-release"
    if clean and build_dir.exists():
        shutil.rmtree(build_dir)

    overlay_ports = str(SDK_DIR / "vcpkg-overlays").replace("\\", "/")
    installed_clib = SDK_DIR / "CommonLibSSE-NG-Installed"
    installed_prefix = str(installed_clib).replace("\\", "/")
    prebuilt_dir = env.get("COMMONLIB_PREBUILT_DIR", "")

    cmake_exe = str(TOOLS_DIR / "cmake" / "bin" / "cmake.exe")
    ninja_exe = str(TOOLS_DIR / "ninja" / "ninja.exe")
    vcpkg_toolchain = str(TOOLS_DIR / "vcpkg" / "scripts" / "buildsystems" / "vcpkg.cmake").replace("\\", "/")

    cfg_cmd = [
        cmake_exe,
        "-S",
        str(mod_dir),
        "-B",
        str(build_dir),
        "-G",
        "Ninja",
        f"-DCMAKE_MAKE_PROGRAM={ninja_exe}",
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_TOOLCHAIN_FILE={vcpkg_toolchain}",
        "-DVCPKG_TARGET_TRIPLET=x64-windows-static-md",
        f"-DVCPKG_OVERLAY_PORTS={overlay_ports}",
        "-DVCPKG_INSTALL_OPTIONS=--clean-after-build",
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
        "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>DLL",
        "-DBUILD_TESTS=OFF",
        "-DCOMMONLIB_PREBUILT=ON",
    ]
    if prebuilt_dir:
        cfg_cmd.append(f"-DCOMMONLIB_PREBUILT_DIR={prebuilt_dir}")
    if (installed_clib / "lib" / "cmake" / "CommonLibSSE" / "CommonLibSSEConfig.cmake").exists():
        cfg_cmd.append(f"-DCommonLibSSE_DIR={installed_prefix}/lib/cmake/CommonLibSSE")

    print(f"[*] Configuring CMake in {build_dir} ...")
    subprocess.run(cfg_cmd, cwd=str(mod_dir), env=env, check=True)

    print(f"[*] Building CMake target in {build_dir} ...")
    subprocess.run([cmake_exe, "--build", str(build_dir), "--config", "Release"], cwd=str(mod_dir), env=env, check=True)
    return build_dir


def build_with_xmake(mod_dir: Path, env: Dict[str, str], clean: bool) -> Path:
    if clean:
        subprocess.run(["xmake", "clean", "-a"], cwd=str(mod_dir), env=env, check=False)

    print(f"[*] Configuring XMake in {mod_dir} ...")
    subprocess.run(
        ["xmake", "f", "-p", "windows", "-a", "x64", "-m", "releasedbg", "-y"],
        cwd=str(mod_dir),
        env=env,
        check=True,
    )
    print(f"[*] Building XMake project in {mod_dir} ...")
    subprocess.run(["xmake", "build", "-y"], cwd=str(mod_dir), env=env, check=True)
    return mod_dir / "build"


def build_with_msbuild(mod_dir: Path, env: Dict[str, str], clean: bool) -> Path:
    sln_files = list(mod_dir.glob("*.sln")) + list(mod_dir.glob("*/*.sln"))
    vcxproj_files = list(mod_dir.glob("*.vcxproj")) + list(mod_dir.glob("*/*.vcxproj"))
    if not sln_files and not vcxproj_files:
        raise FileNotFoundError(
            f"No CMakeLists.txt, xmake.lua, .sln, or .vcxproj found in {mod_dir}"
        )
    target_proj = sln_files[0] if sln_files else vcxproj_files[0]

    skse_inc = str(SDK_DIR / "skse64")
    addr_inc = str(SDK_DIR / "AddressLibrary")
    env["CL"] = f'/I"{skse_inc}" /I"{addr_inc}" ' + env.get("CL", "")

    t_arg = "/t:Rebuild" if clean else "/t:Build"
    cmd = [
        "msbuild",
        str(target_proj),
        t_arg,
        "/p:Configuration=Release",
        "/p:Platform=x64",
        "/m",
    ]
    print(f"[*] Building MSBuild project {target_proj.name} ...")
    subprocess.run(cmd, cwd=str(mod_dir), env=env, check=True)
    return mod_dir


def find_built_dlls(search_dir: Path, mod_dir: Path) -> List[Path]:
    ignore_names = {"openvr_api.dll", "msdia140.dll", "d3dcompiler_47.dll"}
    candidates: List[Path] = []
    for root, dirs, files in os.walk(search_dir):
        dirs[:] = [d for d in dirs if d.lower() not in {"vcpkg_installed", ".git", "extern", "external"}]
        for f in files:
            if f.lower().endswith(".dll") and f.lower() not in ignore_names:
                candidates.append(Path(root) / f)

    if not candidates and search_dir != mod_dir:
        return find_built_dlls(mod_dir, mod_dir)

    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates


def package_mod(mod_dir: Path, dlls: List[Path], dist_dir: Path = DIST_DIR) -> Path:
    mod_name = mod_dir.name
    pkg_root = dist_dir / mod_name
    plugins_dir = pkg_root / "SKSE" / "Plugins"
    if pkg_root.exists():
        shutil.rmtree(pkg_root)
    plugins_dir.mkdir(parents=True, exist_ok=True)

    for dll in dlls:
        shutil.copy2(dll, plugins_dir / dll.name)
        pdb = dll.with_suffix(".pdb")
        if pdb.exists():
            shutil.copy2(pdb, plugins_dir / pdb.name)

    # Copy plugin configuration files without sweeping up root manifest JSONs (vcpkg.json, etc.)
    for cfg_dir in [mod_dir / "Data" / "SKSE" / "Plugins", mod_dir / "SKSE" / "Plugins"]:
        if cfg_dir.exists():
            for ext in ("*.ini", "*.toml", "*.json"):
                for cfg_f in cfg_dir.glob(ext):
                    if cfg_f.name.lower() not in ("desktop.ini", "pyproject.toml", "cargo.toml"):
                        shutil.copy2(cfg_f, plugins_dir / cfg_f.name)

    for ext in ("*.ini", "*.toml"):
        for cfg_f in mod_dir.glob(ext):
            if cfg_f.name.lower() not in ("desktop.ini", "pyproject.toml", "cargo.toml"):
                shutil.copy2(cfg_f, plugins_dir / cfg_f.name)

    zip_path = dist_dir / f"{mod_name}_Updated.zip"
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(pkg_root):
            for f in files:
                full_p = Path(root) / f
                rel_p = full_p.relative_to(pkg_root)
                zf.write(full_p, str(rel_p))

    return zip_path


def main() -> int:
    default_target = skse_env.get_default_target_dot()
    parser = argparse.ArgumentParser(description="Build, verify, and package an SKSE64 plugin")
    parser.add_argument("mod_dir", help="Path to the mod source directory")
    parser.add_argument(
        "--build-system",
        choices=["auto", "cmake", "xmake", "msbuild"],
        default="auto",
        help="Build system to use (default: auto)",
    )
    parser.add_argument("--clean", action="store_true", help="Clean build directory before building")
    parser.add_argument(
        "--target",
        default=default_target,
        help=f"Target Skyrim runtime version for verification (default: {default_target})",
    )
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=DIST_DIR,
        help=f"Output packaging directory (default: {DIST_DIR})",
    )
    args = parser.parse_args()

    mod_dir = Path(args.mod_dir).resolve()
    if not mod_dir.exists():
        print(f"Error: {mod_dir} does not exist.", file=sys.stderr)
        return 1

    dist_dir = args.dist_dir.resolve()
    env = load_build_environment()

    bs = args.build_system
    if bs == "auto":
        # Prefer CMake when CMakeLists.txt exists (fastest prebuilt/vcpkg overlay pipeline),
        # else XMake when xmake.lua exists, else MSBuild.
        has_cmake = (mod_dir / "CMakeLists.txt").exists()
        has_xmake = (mod_dir / "xmake.lua").exists()
        if has_cmake:
            bs = "cmake"
        elif has_xmake:
            bs = "xmake"
        else:
            bs = "msbuild"

    print(f"=== Building SKSE Plugin '{mod_dir.name}' using {bs.upper()} ===")
    if bs == "cmake":
        out_dir = build_with_cmake(mod_dir, env, args.clean)
    elif bs == "xmake":
        out_dir = build_with_xmake(mod_dir, env, args.clean)
    else:
        out_dir = build_with_msbuild(mod_dir, env, args.clean)

    dlls = find_built_dlls(out_dir, mod_dir)
    if not dlls:
        print("[!!] Error: Build completed, but no output .dll was found!", file=sys.stderr)
        return 1

    skse_dlls: List[Tuple[Path, Dict[str, Any]]] = []
    other_results: List[Tuple[Path, Dict[str, Any]]] = []
    for dll in dlls:
        try:
            ver_res = verify_dll(dll, target_runtime=args.target)
        except Exception as exc:
            print(f"[~] Skipping unreadable DLL {dll.name}: {exc}")
            continue
        exports = ver_res.get("exports", {})
        if any(exports.get(k) for k in ("SKSEPlugin_Version", "SKSEPlugin_Load", "SKSEPlugin_Preload", "SKSEPlugin_Query")):
            skse_dlls.append((dll, ver_res))
        else:
            other_results.append((dll, ver_res))

    if not skse_dlls:
        print(f"\n[*] Found built DLL (no SKSE plugin exports detected): {dlls[0]}")
        fallback_res = other_results[0][1] if other_results else verify_dll(dlls[0], target_runtime=args.target)
        print_verification(fallback_res)
        print(
            f"[!!] WARNING: Compiled DLL did not pass {args.target} SKSE plugin compatibility checks!",
            file=sys.stderr,
        )
        return 2

    all_passed = True
    verified_dlls: List[Path] = []
    for dll, ver_res in skse_dlls:
        print(f"\n[*] Found built SKSE plugin DLL: {dll}")
        print_verification(ver_res)
        verified_dlls.append(dll)
        if not ver_res.get("passed_target"):
            all_passed = False

    if not all_passed:
        print(
            f"[!!] WARNING: One or more compiled DLLs did not pass {args.target} compatibility checks!",
            file=sys.stderr,
        )
        return 2

    zip_path = package_mod(mod_dir, verified_dlls, dist_dir=dist_dir)
    print(f"\n[OK] Packaged updated plugin to:")
    print(f"     Folder : {dist_dir / mod_dir.name / 'SKSE' / 'Plugins'}")
    print(f"     Archive: {zip_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
