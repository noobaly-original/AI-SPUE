#!/usr/bin/env python3
"""
Automated SKSE Plugin Upgrader & Source Patcher (scripts/upgrade_mod.py)

Automatically upgrades an older SKSE plugin project so it compiles cleanly for the
newest installed Skyrim SE/AE runtime and Address Library Format v5:

  1. Replaces legacy `versionlibdb.h` / `versiondb.h` with our Format 1/2/5 compatible header.
  2. Upgrades `vcpkg.json` and `vcpkg-configuration.json` baselines to the local `tools/vcpkg`
     commit and routes `commonlibsse-ng` to our local prebuilt overlay port.
  3. Patches `CMakeLists.txt` (disables `/WX` warnings-as-errors for MSVC 19.44+, adds `/utf-8`,
     and routes legacy `extern/CommonLibSSE` submodules to the local modern `CommonLibSSE-NG` when requested).
  4. Converts single-runtime `REL::ID(se_id)` to multi-runtime `REL::RelocationID(se_id, ae_id)`.
  5. Updates known AE Address Library IDs that split in 1.6.1130 or 1.7.99+.
  6. Fixes CommonLibSSE-NG v7-v16 renamed fields (`lastKnownWeatherRegion` -> `currentRegion`, etc.).

Usage:
  python scripts/upgrade_mod.py <mod_dir> [--replace-submodule] [--dry-run]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import skse_env  # noqa: E402
from inspect_bin import AddressLibBin, resolve_bin_path  # noqa: E402
from map_ids import file_uses_only_ae_single_ids, patch_single_rel_ids_in_text  # noqa: E402

REPO_ROOT = skse_env.REPO_ROOT
VCPKG_ROOT = skse_env.TOOLS_DIR / "vcpkg"
ADDR_LIB_HEADER = skse_env.ADDR_LIB_HEADER


def get_local_vcpkg_baseline() -> str:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(VCPKG_ROOT), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        if len(out) == 40:
            return out
    except Exception:
        pass
    return "e1ff419d28c7f0a94abaf0a848fe0aeeb69b2de3"


def upgrade_versionlibdb(mod_dir: Path, dry_run: bool) -> List[str]:
    changes: List[str] = []
    ignore_dirs = {"build", ".git", ".xmake", "vcpkg_installed", "extern", "external", "deps"}
    for root, dirs, files in os.walk(mod_dir):
        dirs[:] = [d for d in dirs if d.lower() not in ignore_dirs]
        for f in files:
            if f.lower() in ("versionlibdb.h", "versiondb.h"):
                fp = Path(root) / f
                txt = fp.read_text(encoding="utf-8", errors="replace")
                if "format == 5" not in txt:
                    changes.append(f"Upgraded {fp.relative_to(mod_dir)} to support Address Library Format v5 (1.7.99+)")
                    if not dry_run:
                        shutil.copyfile(fp, str(fp) + ".bak")
                        shutil.copyfile(ADDR_LIB_HEADER, fp)
    return changes


def upgrade_vcpkg_manifests(mod_dir: Path, dry_run: bool) -> List[str]:
    changes: List[str] = []
    baseline = get_local_vcpkg_baseline()

    vcpkg_json = mod_dir / "vcpkg.json"
    if vcpkg_json.exists():
        try:
            data = json.loads(vcpkg_json.read_text(encoding="utf-8"))
            modified = False
            if data.get("builtin-baseline") != baseline:
                data["builtin-baseline"] = baseline
                modified = True
                changes.append(f"Updated `vcpkg.json` builtin-baseline to local vcpkg HEAD ({baseline[:10]})")
            if modified and not dry_run:
                vcpkg_json.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        except Exception as e:
            changes.append(f"Warning: Could not parse vcpkg.json ({e})")

    vcpkg_cfg = mod_dir / "vcpkg-configuration.json"
    if vcpkg_cfg.exists():
        try:
            cfg = json.loads(vcpkg_cfg.read_text(encoding="utf-8"))
            modified = False
            if "default-registry" not in cfg:
                cfg["default-registry"] = {
                    "kind": "builtin",
                    "baseline": baseline,
                }
                modified = True
                changes.append(f"Added `default-registry` (builtin {baseline[:10]}) to `vcpkg-configuration.json`")
            elif isinstance(cfg["default-registry"], dict):
                dr = cfg["default-registry"]
                if dr.get("kind") == "git" and "microsoft/vcpkg" in dr.get("repository", "").lower():
                    cfg["default-registry"] = {
                        "kind": "builtin",
                        "baseline": baseline,
                    }
                    modified = True
                    changes.append(f"Converted `vcpkg-configuration.json` default-registry from remote git to fast local `builtin` ({baseline[:10]})")
                elif dr.get("baseline") != baseline:
                    dr["baseline"] = baseline
                    modified = True
                    changes.append(f"Updated `vcpkg-configuration.json` default-registry baseline to {baseline[:10]}")
            if "registries" in cfg and isinstance(cfg["registries"], list):
                new_regs = []
                for reg in cfg["registries"]:
                    pkgs = reg.get("packages", [])
                    if isinstance(pkgs, list):
                        filtered = [
                            p for p in pkgs if not p.lower().startswith("commonlibsse")
                        ]
                        if len(filtered) != len(pkgs):
                            modified = True
                            changes.append(
                                "Removed outdated `commonlibsse*` remote registry entry from `vcpkg-configuration.json` "
                                "(will use local `sdk/vcpkg-overlays/commonlibsse-ng` v16.5.0 instead)"
                            )
                        if filtered:
                            reg["packages"] = filtered
                            new_regs.append(reg)
                    else:
                        new_regs.append(reg)
                cfg["registries"] = new_regs
            if modified and not dry_run:
                vcpkg_cfg.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        except Exception as e:
            changes.append(f"Warning: Could not parse vcpkg-configuration.json ({e})")

    return changes


def _find_cmake_command_end(txt: str, cmd_name: str) -> Optional[int]:
    """Return index right after the newline following `cmd_name(...)`, handling nested parens/quotes."""
    m = re.search(rf"(?im)^[ \t]*{re.escape(cmd_name)}\s*\(", txt)
    if not m:
        return None
    depth = 0
    in_quote = False
    escape = False
    i = m.end() - 1
    n = len(txt)
    while i < n:
        ch = txt[i]
        if in_quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_quote = False
        else:
            if ch == "#":
                nl = txt.find("\n", i)
                i = n if nl == -1 else nl
                continue
            if ch == '"':
                in_quote = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    nl = txt.find("\n", i)
                    return (nl + 1) if nl != -1 else (i + 1)
        i += 1
    return None


def upgrade_cmake(mod_dir: Path, replace_submodule: bool, dry_run: bool) -> List[str]:
    changes: List[str] = []
    cmake_file = mod_dir / "CMakeLists.txt"
    if not cmake_file.exists():
        return changes

    txt = cmake_file.read_text(encoding="utf-8", errors="replace")
    orig = txt

    # Replace /WX (warnings as errors) with /WX- so MSVC 19.44+ new warnings don't abort compilation
    if re.search(r"(?<![/\w])/WX(?![-\w])", txt):
        txt = re.sub(r"(?<![/\w])/WX(?![-\w])", "/WX-", txt)
        changes.append("Changed `/WX` to `/WX-` in `CMakeLists.txt` to prevent MSVC 19.44+ deprecation warnings from failing the build")

    # Inject /utf-8 for MSVC so spdlog/fmt v12+ compiles cleanly without C4819/fmt Unicode failures
    if "/utf-8" not in txt.lower():
        utf8_block = "\nif(MSVC)\n    add_compile_options(/utf-8)\nendif()\n"
        insert_pos = _find_cmake_command_end(txt, "project")
        if insert_pos is None:
            insert_pos = _find_cmake_command_end(txt, "cmake_minimum_required")
        if insert_pos is not None:
            txt = txt[:insert_pos] + utf8_block + txt[insert_pos:]
        else:
            txt = utf8_block.lstrip("\n") + "\n" + txt
        changes.append("Added MSVC `/utf-8` compile option in `CMakeLists.txt` for modern `fmt`/`spdlog` compatibility")

    # Optionally redirect legacy submodule add_subdirectory(extern/CommonLibSSE...) to find_package(CommonLibSSE REQUIRED)
    if replace_submodule:
        re_sub = re.compile(
            r"add_subdirectory\s*\(\s*[\"']?(?:extern|external|deps|submodules)/CommonLibSSE[^)\"']*[\"']?[^)]*\)",
            re.IGNORECASE,
        )
        if re_sub.search(txt):
            txt = re_sub.sub("find_package(CommonLibSSE CONFIG REQUIRED)", txt)
            changes.append("Redirected legacy `add_subdirectory(.../CommonLibSSE*)` in `CMakeLists.txt` to `find_package(CommonLibSSE CONFIG REQUIRED)`")

    if txt != orig and not dry_run:
        shutil.copyfile(cmake_file, str(cmake_file) + ".bak")
        cmake_file.write_text(txt, encoding="utf-8")

    return changes


def _patch_raw_skse_plugin_version(content: str) -> Tuple[str, Optional[str]]:
    """Add `kVersionIndependentEx_AddressLibraryV5` to raw `SKSEPluginVersionData` declarations."""
    clean_no_comments = skse_env.strip_cpp_comments_preserve_lines(content)
    if (
        "SKSEPluginVersionData" not in clean_no_comments
        or "SKSEPlugin_Version" not in clean_no_comments
        or "kVersionIndependent_AddressLibraryPostAE" not in clean_no_comments
        or "kVersionIndependentEx_AddressLibraryV5" in clean_no_comments
    ):
        return content, None

    # Case 1: explicit kVersionIndependentEx_NoStructUse in code spans
    re_nostruct = re.compile(r"\b(?:SKSEPluginVersionData::)?kVersionIndependentEx_NoStructUse\b")
    out_chunks: List[str] = []
    patched_case1 = False
    for start, end, is_code in skse_env.iter_cpp_code_spans(content):
        chunk = content[start:end]
        if is_code and not patched_case1 and re_nostruct.search(chunk):
            chunk = re_nostruct.sub(
                lambda m: f"{m.group(0)} | SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5",
                chunk,
                count=1,
            )
            patched_case1 = True
        out_chunks.append(chunk)
    if patched_case1:
        return "".join(out_chunks), "added `SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5` to `SKSEPlugin_Version`"

    # Case 2: designated initializer `.versionIndependenceEx = ...`
    re_desig = re.compile(r"(\.versionIndependenceEx\s*=\s*)([^,;}\n]+)")
    out_chunks = []
    patched_case2 = False
    for start, end, is_code in skse_env.iter_cpp_code_spans(content):
        chunk = content[start:end]
        if is_code and not patched_case2:
            m = re_desig.search(chunk)
            if m:
                val = m.group(2).strip()
                if re.fullmatch(r"(?:0[xX]0+|0)[uUlL]*", val):
                    repl_str = f"{m.group(1)}SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5"
                else:
                    repl_str = f"{m.group(1)}({val}) | SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5"
                chunk = chunk[: m.start()] + repl_str + chunk[m.end() :]
                patched_case2 = True
        out_chunks.append(chunk)
    if patched_case2:
        return "".join(out_chunks), "added `SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5` to `.versionIndependenceEx`"

    # Case 3: brace aggregate initializer `SKSEPlugin_Version = { ..., 0, kVersionIndependent_AddressLibraryPostAE, ... }`
    spans = skse_env.iter_cpp_code_spans(content)

    def _offset_is_code(pos: int) -> bool:
        for s, e, ic in spans:
            if s <= pos < e:
                return ic
        return False

    re_decl = re.compile(r"\bSKSEPlugin_Version\s*(?:=\s*)?\{")
    for m_decl in re_decl.finditer(content):
        if not _offset_is_code(m_decl.start()):
            continue
        depth = 0
        brace_end = None
        for s, e, ic in spans:
            if not ic or e <= m_decl.start():
                continue
            for idx in range(max(s, m_decl.end() - 1), e):
                if content[idx] == "{":
                    depth += 1
                elif content[idx] == "}":
                    depth -= 1
                    if depth == 0:
                        brace_end = idx
                        break
            if brace_end is not None:
                break
        if brace_end is None:
            continue

        block = content[m_decl.start() : brace_end + 1]
        re_zero_before_al = re.compile(
            r"\b(?P<zero>(?:0[xX]0+|0)[uUlL]*)\b"
            r"(?P<mid>(?:\s|//[^\r\n]*|/\*[\s\S]*?\*/)*,(?:\s|//[^\r\n]*|/\*[\s\S]*?\*/)*"
            r"(?:(?:SKSEPluginVersionData::)?kVersionIndependent_\w+(?:\s|\|)*)*?"
            r"(?:SKSEPluginVersionData::)?kVersionIndependent_AddressLibraryPostAE\b)"
        )
        for mz in re_zero_before_al.finditer(block):
            abs_pos = m_decl.start() + mz.start("zero")
            if _offset_is_code(abs_pos):
                abs_end = m_decl.start() + mz.end("zero")
                new_content = (
                    content[:abs_pos]
                    + "SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5"
                    + content[abs_end:]
                )
                return new_content, "added `SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5` to `SKSEPlugin_Version`"

    return (
        content,
        "NOTE: Raw `SKSEPluginVersionData` detected; ensure `versionIndependenceEx` includes "
        "`SKSEPluginVersionData::kVersionIndependentEx_AddressLibraryV5` (1 << 1)",
    )


def upgrade_source_code(mod_dir: Path, dry_run: bool) -> List[str]:
    changes: List[str] = []
    se_to_ae, _, _, ae_split_to_new = skse_env.load_id_maps()

    se_ids_valid: Optional[Set[int]] = None
    target_ids_valid: Optional[Set[int]] = None
    try:
        se_ids_valid = set(AddressLibBin(resolve_bin_path("1-5-97-0")).id_to_offset.keys())
    except FileNotFoundError:
        pass
    try:
        target_ids_valid = set(
            AddressLibBin(resolve_bin_path(skse_env.get_default_target_dash())).id_to_offset.keys()
        )
    except FileNotFoundError:
        pass

    re_dual_id = re.compile(
        r"\b(REL::RelocationID|RELOCATION_ID|REL::VariantID)\s*\(\s*(\d+)\s*,\s*(\d+)"
    )

    exts = {".cpp", ".cxx", ".cc", ".h", ".hpp", ".hxx", ".inl"}
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
    }

    for root, dirs, files in os.walk(mod_dir):
        dirs[:] = [
            d
            for d in dirs
            if d.lower() not in ignore_dirs and not d.lower().startswith("commonlibsse")
        ]
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in exts:
                continue
            try:
                content = fpath.read_text(encoding="utf-8")
            except Exception:
                continue

            orig = content
            rel_p = fpath.relative_to(mod_dir)
            file_notes: List[str] = []

            # 1. Convert REL::ID(se_id) -> REL::RelocationID(se_id, ae_id) in code spans (skipping AE-only IDs)
            ae_only = file_uses_only_ae_single_ids(content, se_ids_valid, target_ids_valid)
            content, id_conv_count, skipped_ae = patch_single_rel_ids_in_text(
                content,
                se_to_ae,
                se_ids_valid=se_ids_valid,
                target_ids_valid=target_ids_valid,
                file_looks_ae_only=ae_only,
            )
            if id_conv_count > 0:
                file_notes.append(f"converted {id_conv_count} `REL::ID` -> `REL::RelocationID`")
            if skipped_ae > 0:
                file_notes.append(f"skipped {skipped_ae} AE-only `REL::ID` call(s)")

            # 2. Update split AE IDs & CommonLibSSE-NG v7-v16 API renames inside code spans only
            split_count = 0
            renamed_region = False
            renamed_accum = False

            def repl_dual(m: re.Match) -> str:
                nonlocal split_count
                macro = m.group(1)
                se_id = int(m.group(2))
                ae_id = int(m.group(3))
                if ae_id in ae_split_to_new:
                    new_ae = ae_split_to_new[ae_id]
                    split_count += 1
                    return f"{macro}({se_id}, {new_ae}"
                elif ae_id == 0 and se_id in se_to_ae:
                    new_ae = se_to_ae[se_id]
                    split_count += 1
                    return f"{macro}({se_id}, {new_ae}"
                return m.group(0)

            code_chunks: List[str] = []
            for start, end, is_code in skse_env.iter_cpp_code_spans(content):
                chunk = content[start:end]
                if not is_code:
                    code_chunks.append(chunk)
                    continue
                chunk = re_dual_id.sub(repl_dual, chunk)
                if "lastKnownWeatherRegion" in chunk:
                    chunk = chunk.replace("lastKnownWeatherRegion", "currentRegion")
                    renamed_region = True
                if "FinishAccumulatingPreResolveDepth" in chunk:
                    chunk = chunk.replace("FinishAccumulatingPreResolveDepth", "FinishAccumulatingDispatch")
                    renamed_accum = True
                code_chunks.append(chunk)
            content = "".join(code_chunks)

            if split_count > 0:
                file_notes.append(f"updated {split_count} split/zero AE ID(s) for latest AE")
            if renamed_region:
                file_notes.append("renamed `lastKnownWeatherRegion` -> `currentRegion` (CommonLibSSE-NG v16)")
            if renamed_accum:
                file_notes.append("renamed `FinishAccumulatingPreResolveDepth` -> `FinishAccumulatingDispatch`")

            # #include string path update (outside is_code spans because it is a quoted header path)
            if "RE/S/ShaderAccumulator.h" in content:
                content = content.replace("RE/S/ShaderAccumulator.h", "RE/B/BSShaderAccumulator.h")
                file_notes.append("updated `ShaderAccumulator.h` -> `BSShaderAccumulator.h` (CommonLibSSE-NG v8)")

            # 3. Raw SKSEPluginVersionData: ensure kVersionIndependentEx_AddressLibraryV5 is set
            content, raw_note = _patch_raw_skse_plugin_version(content)
            if raw_note:
                file_notes.append(raw_note)

            if content != orig:
                changes.append(f"{rel_p}: " + ", ".join(file_notes))
                if not dry_run:
                    fpath.write_text(content, encoding="utf-8")
            elif file_notes:
                changes.append(f"{rel_p}: " + ", ".join(file_notes))

    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description="Upgrade an SKSE plugin project for the newest Skyrim runtime & Address Library")
    parser.add_argument("mod_dir", help="Path to the mod source directory")
    parser.add_argument(
        "--replace-submodule",
        action="store_true",
        help="Redirect legacy add_subdirectory(extern/CommonLibSSE) in CMakeLists.txt to find_package(CommonLibSSE CONFIG REQUIRED)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview upgrades without writing changes")
    args = parser.parse_args()

    mod_dir = Path(args.mod_dir).resolve()
    if not mod_dir.exists():
        print(f"Error: {mod_dir} does not exist.", file=sys.stderr)
        return 1

    print(f"=== Upgrading SKSE Mod: {mod_dir.name} ({'DRY-RUN' if args.dry_run else 'LIVE'}) ===")
    all_changes: List[str] = []
    all_changes.extend(upgrade_versionlibdb(mod_dir, args.dry_run))
    all_changes.extend(upgrade_vcpkg_manifests(mod_dir, args.dry_run))
    all_changes.extend(upgrade_cmake(mod_dir, args.replace_submodule, args.dry_run))
    all_changes.extend(upgrade_source_code(mod_dir, args.dry_run))

    if all_changes:
        print(f"\nApplied {len(all_changes)} upgrade action(s):")
        for c in all_changes:
            print(f"  [+] {c}")
    else:
        print("\n[OK] No source/manifest patches were needed (project is already clean/modern).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
