#!/usr/bin/env python3
"""
SKSE Plugin Source Code Analyzer & Update Planner (scripts/analyze_mod.py)

Clones (if given a GitHub URL) or inspects a local SKSE mod repository and diagnoses:
  1. Build System (CMake + vcpkg, CMake + Submodule, XMake, MSBuild .sln/.vcxproj)
  2. SKSE Framework (CommonLibSSE-NG, CommonLibSSE powerof3/Ryan, Raw skse64 + versionlibdb.h)
  3. Plugin Version & Entry Point (SKSEPlugin_Query, SKSEPlugin_Version, SKSEPluginLoad, AddressLibraryV5 flag)
  4. Address Library IDs & Offsets (verifies all IDs against the auto-detected target Address Library .bin & historical 1.6.1170)
  5. Skyrim 1.7.99+ & 1.6.1130+ Breaking Changes (MenuEventHandler/PlayerInputHandler +2 vtable shift, etc.)
  6. Modern MSVC 19.44+ / C++23 / fmt v12 Consteval Hazards

Usage:
  python scripts/analyze_mod.py <github_url_or_local_path> [--target <ver>]
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402
from inspect_bin import AddressLibBin, load_se_to_ae_map, resolve_bin_path, scan_mod_ids  # noqa: E402

REPO_ROOT = skse_env.REPO_ROOT
WORKSPACE_DIR = skse_env.WORKSPACE_DIR


def prepare_mod_directory(source: str) -> Path:
    if source.startswith(("http://", "https://", "git@")):
        WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
        repo_name = source.rstrip("/").split("/")[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        dest = WORKSPACE_DIR / repo_name
        if dest.exists():
            print(f"[*] Target directory already exists at: {dest}")
        else:
            print(f"[*] Cloning {source} into {dest} ...")
            subprocess.run(["git", "clone", "--recursive", source, str(dest)], check=True)
        return dest.resolve()

    p = Path(source).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Local path does not exist: {p}")
    return p


def collect_source_files(mod_dir: Path) -> List[Path]:
    exts = {".cpp", ".cxx", ".cc", ".c", ".h", ".hpp", ".hxx", ".inl"}
    ignore_dirs = {
        "build",
        ".git",
        ".vs",
        ".xmake",
        "vcpkg_installed",
        "extern",
        "external",
        "deps",
        "submodules",
        "commonlibsse",
        "commonlibsse-ng",
    }
    files_out: List[Path] = []
    for root, dirs, files in os.walk(mod_dir):
        dirs[:] = [
            d
            for d in dirs
            if d.lower() not in ignore_dirs and not d.lower().startswith("commonlibsse")
        ]
        for f in files:
            fp = Path(root) / f
            if fp.suffix.lower() in exts:
                files_out.append(fp)
    return files_out


def analyze_mod(mod_dir: Path, target_runtime: Optional[str] = None) -> Dict[str, Any]:
    if not target_runtime:
        target_runtime = skse_env.get_default_target_dash()
    report: Dict[str, Any] = {
        "mod_name": mod_dir.name,
        "mod_path": str(mod_dir),
        "target_runtime": target_runtime,
        "build_systems": [],
        "framework": "Unknown",
        "entry_point": {},
        "issues": [],
        "warnings": [],
        "id_summary": {},
        "recommended_actions": [],
    }

    # 1. Detect Build System
    cmake_file = mod_dir / "CMakeLists.txt"
    xmake_file = mod_dir / "xmake.lua"
    vcpkg_file = mod_dir / "vcpkg.json"
    vcpkg_cfg_file = mod_dir / "vcpkg-configuration.json"
    sln_files = list(mod_dir.glob("*.sln")) + list(mod_dir.glob("*/*.sln"))
    vcxproj_files = list(mod_dir.glob("*.vcxproj")) + list(mod_dir.glob("*/*.vcxproj"))

    if cmake_file.exists():
        report["build_systems"].append("CMake")
    if xmake_file.exists():
        report["build_systems"].append("XMake")
    if vcpkg_file.exists():
        report["build_systems"].append("vcpkg")
    if sln_files or vcxproj_files:
        report["build_systems"].append("MSBuild (.sln/.vcxproj)")

    cmake_text = cmake_file.read_text(encoding="utf-8", errors="replace") if cmake_file.exists() else ""
    xmake_text = xmake_file.read_text(encoding="utf-8", errors="replace") if xmake_file.exists() else ""
    vcpkg_text = vcpkg_file.read_text(encoding="utf-8", errors="replace") if vcpkg_file.exists() else ""

    # 2. Detect Framework
    src_files = collect_source_files(mod_dir)
    all_src_text = ""
    for sf in src_files:
        try:
            all_src_text += f"\n// FILE: {sf.relative_to(mod_dir)}\n" + sf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass

    has_versionlibdb = any(f.name.lower() in ("versionlibdb.h", "versiondb.h") for f in src_files) or (
        "versionlibdb.h" in all_src_text or "versiondb.h" in all_src_text
    )

    if (
        "commonlibsse-ng" in cmake_text.lower()
        or "commonlibsse-ng" in xmake_text.lower()
        or "commonlibsse-ng" in vcpkg_text.lower()
        or "REL::RelocationID" in all_src_text
        or "RELOCATION_ID" in all_src_text
        or "SKSEPluginLoad" in all_src_text
    ):
        if "commonlibsse-ng" in (cmake_text + xmake_text + vcpkg_text).lower():
            report["framework"] = "CommonLibSSE-NG"
        elif "powerof3" in (cmake_text + vcpkg_text).lower() or "RELOCATION_ID" in all_src_text:
            report["framework"] = "CommonLibSSE (powerof3 / NG compatible)"
        else:
            report["framework"] = "CommonLibSSE (Legacy / NG compatible)"
    elif "CommonLibSSE" in cmake_text or "SKSE/SKSE.h" in all_src_text or "RE/Skyrim.h" in all_src_text:
        report["framework"] = "CommonLibSSE (Legacy SE/AE)"
    elif has_versionlibdb:
        report["framework"] = "Raw SKSE64 + versionlibdb.h"
    elif "SKSEPlugin_Query" in all_src_text or "SKSEPlugin_Load" in all_src_text or "PluginAPI.h" in all_src_text:
        report["framework"] = "Raw SKSE64 SDK"

    # 3. Check Entry Point & Version Data
    has_add_plugin_cmake = "add_commonlibsse_plugin" in cmake_text
    has_xmake_plugin_rule = "commonlibsse-ng.plugin" in xmake_text or "@skyrim-commonlib" in xmake_text or "commonlibsse-ng/plugin" in xmake_text
    has_skse_plugin_version = "SKSEPlugin_Version" in all_src_text or "SKSEPluginVersion" in all_src_text or "SKSEPluginInfo" in all_src_text
    has_skse_plugin_query = "SKSEPlugin_Query" in all_src_text or "SKSEPluginQuery" in all_src_text
    has_skse_plugin_load = "SKSEPlugin_Load" in all_src_text or "SKSEPluginLoad" in all_src_text or "SKSE_PLUGIN_LOAD" in all_src_text

    report["entry_point"] = {
        "cmake_add_commonlibsse_plugin": has_add_plugin_cmake,
        "xmake_plugin_rule": has_xmake_plugin_rule,
        "manual_SKSEPlugin_Version": has_skse_plugin_version,
        "legacy_SKSEPlugin_Query": has_skse_plugin_query,
        "SKSEPlugin_Load": has_skse_plugin_load,
    }

    if has_add_plugin_cmake and has_skse_plugin_version:
        report["warnings"].append(
            "Both CMake `add_commonlibsse_plugin` (which auto-generates `__<Target>Plugin.cpp` with `SKSEPlugin_Version`) "
            "AND manual `SKSEPlugin_Version` in source files were detected. When upgrading to modern CommonLibSSE-NG, "
            "remove the manual `SKSEPlugin_Version` / `dllexport` block in C++ source to avoid duplicate symbol `LNK2005`."
        )

    if not has_add_plugin_cmake and not has_xmake_plugin_rule and not has_skse_plugin_version:
        report["issues"].append(
            f"CRITICAL (AE 1.6+ / {target_runtime}): Plugin does NOT export `SKSEPlugin_Version` (`SKSEPluginVersionData`). "
            "Legacy `SKSEPlugin_Query` is ignored by SKSE 2.1.0+ / 2.3.0+. You must either use `add_commonlibsse_plugin` "
            "or export `SKSEPlugin_Version` with `kVersionIndependentEx_AddressLibraryV5`."
        )

    overlay_ver = "v16.9.0"
    try:
        ov_json = REPO_ROOT / "sdk" / "vcpkg-overlays" / "commonlibsse-ng" / "vcpkg.json"
        if ov_json.exists():
            overlay_ver = "v" + json.loads(ov_json.read_text(encoding="utf-8")).get("version-semver", "16.9.0")
    except Exception:
        pass

    clean_src_no_comments = skse_env.strip_cpp_comments_preserve_lines(all_src_text)
    if has_skse_plugin_version and not has_add_plugin_cmake and not has_xmake_plugin_rule:
        if "kVersionIndependentEx_AddressLibraryV5" not in clean_src_no_comments:
            report["issues"].append(
                "CRITICAL (1.7.99+): Manual `SKSEPlugin_Version` declaration does not set "
                "`kVersionIndependentEx_AddressLibraryV5` (`1 << 1`) in `versionIndependenceEx`. "
                f"When linked against modern CommonLibSSE-NG {overlay_ver} (`SKSE::PluginVersionData`), this flag is set by default; "
                "if using raw `SKSEPluginVersionData`, you MUST set `versionIndependenceEx |= SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5`."
            )

    # 4. Check Raw versionlibdb.h
    if has_versionlibdb:
        for sf in src_files:
            if sf.name.lower() in ("versionlibdb.h", "versiondb.h"):
                vdb_txt = sf.read_text(encoding="utf-8", errors="replace")
                if "format == 5" not in vdb_txt:
                    report["issues"].append(
                        f"CRITICAL (1.7.99+): `{sf.relative_to(mod_dir)}` only supports Address Library Format 1/2 "
                        f"and will fail on Format 5 runtimes (`versionlib-{target_runtime}.bin`). "
                        f"Replace `{sf.relative_to(mod_dir)}` with `sdk/AddressLibrary/versionlibdb.h` (or run `upgrade_mod.py`)."
                    )

    # 5. Check 1.7.99+ Breaking VTable & API Changes
    # 5a. MenuEventHandler subclassing
    re_menu_inh = re.compile(r"class\s+\w+[^{]*:\s*[^{]*\bMenuEventHandler\b")
    if re_menu_inh.search(all_src_text):
        report["issues"].append(
            "BREAKING CHANGE (1.7.99+): Mod subclasses `RE::MenuEventHandler`. In Skyrim 1.7.99+, Bethesda inserted "
            "`ProcessMotionGesture` (slot 2) and `ProcessSixaxis` (slot 3) into `MenuEventHandler`, shifting `ProcessKinect`, "
            "`ProcessThumbstick`, `ProcessMouseMove`, and `ProcessButton` by +2 slots. In modern CommonLibSSE-NG, "
            "inherit from `RE::MenuEventHandlerEx` (`#include \"RE/M/MenuEventHandlerEx.h\"`) instead of `RE::MenuEventHandler`, "
            "and pass `handler->Handler()` to `MenuControls::RegisterHandler` / `RemoveHandler`."
        )

    # 5b. PlayerInputHandler / MenuEventHandler hardcoded write_vfunc
    input_handlers = (
        "PlayerInputHandler|AttackBlockHandler|LookHandler|MovementHandler|ReadyWeaponHandler|"
        "AutoMoveHandler|JumpHandler|ShoutHandler|SneakHandler|SprintHandler|TogglePOVHandler|ToggleRunHandler|"
        "ActivateHandler|FavoritesHandler|MenuOpenHandler|QuickSaveLoadHandler|RunHandler"
    )
    re_input_vtbl = re.compile(rf"VTABLE_(?:{input_handlers})")
    if re_input_vtbl.search(all_src_text) or "PlayerInputHandler" in all_src_text:
        if "write_vfunc" in all_src_text and "RUNTIME_SSE_1_7_99" not in all_src_text and "VersionShift" not in all_src_text:
            report["warnings"].append(
                "POTENTIAL VTABLE SHIFT (1.7.99+): Mod references `PlayerInputHandler` (or derived handler VTABLEs) "
                "and uses `write_vfunc`. In Skyrim 1.7.99+, `PlayerInputHandler` inserted `ProcessMotionGesture` (slot 0x02) "
                "and `ProcessSixaxis` (slot 0x03), shifting `ProcessThumbstick` (0x02->0x04), `ProcessMouseMove` (0x03->0x05), "
                "and `ProcessButton` (0x04->0x06) by +2 slots! Use `REL::VersionShift(old_slot, 2, SKSE::RUNTIME_SSE_1_7_99)`."
            )

    # 5c. CommonLibSSE-NG v7-v16 API renames
    if "lastKnownWeatherRegion" in all_src_text:
        report["issues"].append(
            "API RENAME (CommonLibSSE-NG v16.0.0): `RE::PlayerRegionState::lastKnownWeatherRegion` was renamed to `currentRegion`."
        )
    if "criticalDamageMult" in all_src_text:
        report["issues"].append(
            "API RENAME (CommonLibSSE-NG v9.0.0): `RE::HitData::criticalDamageMult` was renamed to `reflectedDamage` "
            "(for crits, check `HitData::Flag::kCritical`)."
        )
    if "ShaderAccumulator.h" in all_src_text or "FinishAccumulatingPreResolveDepth" in all_src_text:
        report["issues"].append(
            "API RENAME (CommonLibSSE-NG v8.0.0): Replace `#include \"RE/S/ShaderAccumulator.h\"` with "
            "`#include \"RE/B/BSShaderAccumulator.h\"` and `FinishAccumulatingPreResolveDepth` with `FinishAccumulatingDispatch`."
        )
    if re.search(r"->\s*(?:frameCount|insideFrame|useEarlyZ)\b", all_src_text):
        report["issues"].append(
            "API CHANGE (CommonLibSSE-NG v7.0.0 / 1.7.99+): Direct access to `BSGraphics::State::frameCount` / `insideFrame` / "
            "`useEarlyZ` moved in 1.7.99+; use `state->GetFrameCount()`, `state->GetInsideFrame()`, `state->GetUseEarlyZ()`."
        )

    # 6. Check Address Library IDs against target .bin & SDK registration status
    try:
        env_info = skse_env.detect_target_environment()
        if env_info.get("sdk_needs_registration"):
            report["warnings"].append(
                f"NEW SKYRIM RUNTIME DETECTED ({env_info['target_version_full']} via {env_info['target_source']}): "
                "Local SDK headers or `sdk/address_tables/bin/` do not yet include this runtime. "
                "Run `python scripts/add_new_runtime.py` to register constants and copy its `.bin` into `sdk/address_tables/bin/`."
            )
    except Exception:
        pass

    target_db = AddressLibBin(resolve_bin_path(target_runtime))
    prev_ae_db = None
    try:
        prev_ae_db = AddressLibBin(resolve_bin_path("1-6-1170-0"))
    except FileNotFoundError:
        pass
    se_to_ae, ae_split_to_new = load_se_to_ae_map()
    scanned_ids = scan_mod_ids(mod_dir)

    missing_ids = []
    single_ids_to_convert = []

    for rel_p, line_no, (se_id, ae_id) in scanned_ids["dual_id"]:
        if ae_id not in target_db.id_to_offset:
            in_1170 = bool(prev_ae_db and ae_id in prev_ae_db.id_to_offset)
            repl = ae_split_to_new.get(ae_id) or se_to_ae.get(se_id)
            missing_ids.append({
                "file": rel_p,
                "line": line_no,
                "se_id": se_id,
                "ae_id": ae_id,
                "in_1_6_1170": in_1170,
                "suggested_ae_id": repl if (repl and repl in target_db.id_to_offset) else None,
            })

    for rel_p, line_no, (sid,) in scanned_ids["single_id"]:
        mapped_ae = se_to_ae.get(sid)
        if mapped_ae and mapped_ae != sid:
            single_ids_to_convert.append({
                "file": rel_p,
                "line": line_no,
                "se_id": sid,
                "ae_id": mapped_ae,
                "valid_in_target": mapped_ae in target_db.id_to_offset,
            })
        elif sid not in target_db.id_to_offset:
            missing_ids.append({
                "file": rel_p,
                "line": line_no,
                "se_id": sid,
                "ae_id": sid,
                "in_1_6_1170": bool(prev_ae_db and sid in prev_ae_db.id_to_offset),
                "suggested_ae_id": None,
            })

    # Check hardcoded REL::Offset
    re_offset = re.compile(r"\bREL::Offset\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)")
    hardcoded_offsets = []
    for sf in src_files:
        rel_p = str(sf.relative_to(mod_dir))
        try:
            raw_txt = sf.read_text(encoding="utf-8", errors="replace")
            lines = skse_env.strip_cpp_comments_preserve_lines(raw_txt).splitlines()
        except Exception:
            continue
        for idx, clean in enumerate(lines, start=1):
            for m in re_offset.finditer(clean):
                hardcoded_offsets.append((rel_p, idx, m.group(1)))

    report["id_summary"] = {
        "dual_id_count": len(scanned_ids["dual_id"]),
        "single_id_count": len(scanned_ids["single_id"]),
        "single_ids_convertible_to_relocation_id": len(single_ids_to_convert),
        "missing_in_target_count": len(missing_ids),
        "hardcoded_rel_offset_count": len(hardcoded_offsets),
        "missing_ids": missing_ids[:30],
        "single_ids_sample": single_ids_to_convert[:30],
        "hardcoded_offsets_sample": hardcoded_offsets[:20],
    }

    if single_ids_to_convert:
        report["issues"].append(
            f"SINGLE-RUNTIME IDs: Found {len(single_ids_to_convert)} `REL::ID(se_id)` call(s) that only specify SE 1.5.97 IDs. "
            f"Run `python scripts/map_ids.py patch-dir \"{mod_dir}\"` (or `upgrade_mod.py`) to automatically convert them to "
            f"`REL::RelocationID(se_id, ae_id)`."
        )

    if missing_ids:
        report["issues"].append(
            f"MISSING ADDRESS LIBRARY IDs: Found {len(missing_ids)} ID(s) that do not exist in `{target_runtime}`. "
            f"See `id_summary.missing_ids` for exact file:line locations and suggested {target_db.version_str} replacement IDs."
        )

    if hardcoded_offsets:
        report["warnings"].append(
            f"HARDCODED OFFSETS: Found {len(hardcoded_offsets)} `REL::Offset(...)` call(s). Raw offsets break across game updates "
            f"unless they are VTable slot indices or paired with signature scanning (`REL::Pattern`). Use `python scripts/map_ids.py offset2id <hex>` "
            f"to convert raw executable offsets to `REL::RelocationID`."
        )

    # 7. Check Build / Toolchain / vcpkg / CMake Hazards
    if vcpkg_cfg_file.exists():
        cfg_txt = vcpkg_cfg_file.read_text(encoding="utf-8", errors="replace")
        if "colorglass" in cfg_txt.lower() or "charmedbaryon" in cfg_txt.lower():
            report["issues"].append(
                "OUTDATED VCPKG REGISTRY: `vcpkg-configuration.json` points to an older `colorglass` or `CharmedBaryon` registry "
                "which predates Skyrim 1.7.99+ (Address Library Format v5). `upgrade_mod.py` / `build_mod.py` will override "
                f"this with our local prebuilt `sdk/vcpkg-overlays/commonlibsse-ng` ({overlay_ver})."
            )

    if re.search(r"(?<![/\w])/WX(?![-\w])", cmake_text):
        report["warnings"].append(
            "COMPILER WARNINGS AS ERRORS (`/WX`): `CMakeLists.txt` enables `/WX`. Newer MSVC 19.44+ compilers emit additional "
            "warnings (`C4996`, `C5260`, etc.) on older C++ code. `upgrade_mod.py` changes `/WX` to `/WX-` in `CMakeLists.txt`."
        )

    # 7b. Security & Untrusted Build-Hook Audit
    sec_audit = skse_env.audit_mod_security(mod_dir)
    report["security_audit"] = sec_audit
    for hook in sec_audit["dangerous_build_hooks"]:
        report["issues"].append(
            f"SECURITY RISK (SUSPICIOUS BUILD HOOK): {hook['file']}:{hook['line']}: `{hook['snippet']}`"
        )
    if sec_audit["prompt_injection_suspects"]:
        sample = "; ".join(f"{p['file']}:{p['line']}" for p in sec_audit["prompt_injection_suspects"][:5])
        report["warnings"].append(
            f"PROMPT-INJECTION STRINGS IGNORED AS UNTRUSTED DATA ({len(sec_audit['prompt_injection_suspects'])} hit(s)): {sample}"
        )
    if sec_audit["bundled_scripts_or_exes"]:
        report["warnings"].append(
            f"BUNDLED EXECUTABLES/SCRIPTS (DO NOT EXECUTE UNREVIEWED): {', '.join(sec_audit['bundled_scripts_or_exes'][:10])}"
        )

    # 8. Build Recommended Action Plan
    report["recommended_actions"] = [
        f"1. Run automated upgrade patcher: `python scripts/upgrade_mod.py \"{mod_dir}\"`",
        f"2. Verify all Address Library IDs: `python scripts/inspect_bin.py verify-mod \"{mod_dir}\" --target {target_runtime}`",
        f"3. Compile & package the updated DLL: `python scripts/build_mod.py \"{mod_dir}\"`",
    ]

    return report


def print_report(rep: Dict[str, Any]) -> None:
    print("=" * 78)
    print(f" SKSE PLUGIN DIAGNOSTIC REPORT: {rep['mod_name']}")
    print("=" * 78)
    print(f"Mod Path        : {rep['mod_path']}")
    print(f"Target Runtime  : {rep['target_runtime']}")
    print(f"Build System(s) : {', '.join(rep['build_systems']) or 'None detected'}")
    print(f"SKSE Framework  : {rep['framework']}")
    print(f"Entry Point     : {json.dumps(rep['entry_point'])}")
    sec = rep.get("security_audit") or {}
    if sec:
        print(
            f"Security Audit  : {'PASS' if sec.get('passed') else 'BLOCKED'} "
            f"(build_hooks={len(sec.get('dangerous_build_hooks', []))}, "
            f"prompt_suspects={len(sec.get('prompt_injection_suspects', []))}, "
            f"bundled_exes={len(sec.get('bundled_scripts_or_exes', []))})"
        )
    print("-" * 78)
    ids = rep["id_summary"]
    print("Address Library ID Scan:")
    print(f"  - Dual SE/AE IDs (`RelocationID`/`RELOCATION_ID`) : {ids['dual_id_count']}")
    print(f"  - Single IDs (`REL::ID`/`FindAddressById`)        : {ids['single_id_count']} ({ids['single_ids_convertible_to_relocation_id']} auto-convertible to SE+AE)")
    print(f"  - Missing IDs in target {rep['target_runtime']:<15}       : {ids['missing_in_target_count']}")
    print(f"  - Hardcoded `REL::Offset(...)` calls              : {ids['hardcoded_rel_offset_count']}")

    if rep["issues"]:
        print("\n[!] BLOCKING ISSUES TO FIX:")
        for idx, iss in enumerate(rep["issues"], 1):
            print(f"  {idx}. {iss}")
    else:
        print("\n[OK] No blocking structural issues detected! A clean rebuild against the local SDK should succeed.")

    if rep["warnings"]:
        print("\n[~] WARNINGS / NOTES:")
        for idx, w in enumerate(rep["warnings"], 1):
            print(f"  {idx}. {w}")

    if ids["missing_ids"]:
        print("\n[!] MISSING ID DETAILS:")
        for m in ids["missing_ids"]:
            sug = f" => USE AE ID {m['suggested_ae_id']}" if m["suggested_ae_id"] else ""
            print(f"  - {m['file']}:{m['line']} (SE={m['se_id']}, AE={m['ae_id']}, in_1.6.1170={m['in_1_6_1170']}){sug}")

    print("\n[*] RECOMMENDED NEXT STEPS:")
    for step in rep["recommended_actions"]:
        print(f"  {step}")
    print("=" * 78)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze an SKSE plugin repository and generate an update plan")
    parser.add_argument("source", help="GitHub repository URL or local folder path")
    parser.add_argument(
        "--target",
        default=skse_env.get_default_target_dash(),
        help="Target Skyrim runtime version (default: latest available runtime)",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    args = parser.parse_args()

    mod_dir = prepare_mod_directory(args.source)
    rep = analyze_mod(mod_dir, args.target)

    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print_report(rep)

    return 0


if __name__ == "__main__":
    sys.exit(main())
