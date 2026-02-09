#!/usr/bin/env python3

import argparse
import os
import sys
import json
import re
from typing import Dict, List, Optional

def get_parameters() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Kernel CVE filter tool"
    )

    parser.add_argument(
        "--vulns-path",
        required=True,
        help="Path to the kernel vulns repository root"
    )

    parser.add_argument(
        "--input-cve-check",
        required=True,
        help="Path to the cve-check input file"
    )

    parser.add_argument(
        "--input-kernel-path",
        required=True,
        help="Path to the kernel source tree"
    )

    parser.add_argument(
        "--input-config-path",
        required=True,
        help="Path to a defconfig file used to generate a temporary .config"
    )

    parser.add_argument(
        "--output-path",
        required=True,
        help="Path where the output cve-check and the kernel_remaining_cves file will be written"
    )

    parser.add_argument(
        "--output-files-name",
        default="filtered_cve_check",
        help="Base name for generated output files (default: filtered_cve_check)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="If present, print extra logs details"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.input_kernel_path):
        print(f"ERROR: Kernel path is not a directory: {args.input_kernel_path}")
        sys.exit(1)

    if not os.path.isfile(args.input_cve_check):
        print(f"ERROR: CVE check input file does not exist: {args.input_cve_check}")
        sys.exit(1)

    if not os.path.isfile(args.input_config_path):
        print(f"ERROR: .config file does not exist: {args.input_config_path}")
        sys.exit(1)

    return args

def vulns_get_affected_files(
    vulns_path: str,
    unfixed_cves: List[Dict[str, Optional[str]]],
    verbose: bool = False
) -> Dict[str, List[str]]:
    """
    For each CVE ID, load its vulns JSON and extract programFiles.
    Returns:
        { cve_id: [file1, file2, ...] }
    """
    results = {}

    for entry in unfixed_cves:
        cve_id = entry.get("id")
        if not cve_id:
            continue

        year = cve_id.split("-")[1]
        cve_file = os.path.join(
            vulns_path,
            "cve",
            "published",
            year,
            f"{cve_id}.json"
        )

        if not os.path.isfile(cve_file):
            if verbose:
                print(f"WARNING: Missing vulns entry for {cve_id}")
            continue

        try:
            with open(cve_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            if verbose:
                print(f"ERROR: Failed parsing {cve_file}: {e}")
            continue

        affected_files = set()

        affected = (
            data
            .get("containers", {})
            .get("cna", {})
            .get("affected", [])
        )

        for item in affected:
            if item.get("product") != "Linux":
                continue
            for f in item.get("programFiles", []):
                affected_files.add(f)

        if affected_files:
            results[cve_id] = sorted(affected_files)

            if verbose:
                print(f"{cve_id}:")
                for f in affected_files:
                    print(f"  - {f}")

    return results

def kernel_get_cves_unfixed(path: str) -> List[Dict[str, Optional[str]]]:
    """
    Load CVE JSON input and return all CVE entries where status is 'Unpatched'.
    """

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "package" not in data:
        print("ERROR: JSON missing 'package' key")
        sys.exit(1)

    unfixed = []

    for pkg in data["package"]:
        pkg_name = pkg.get("name", "")

        if pkg_name != "linux-yocto":
            continue

        for cve in pkg.get("issue", []):
            status = cve.get("status", "").strip()

            if status != "Unpatched":
                continue

            unfixed.append({
                "package": pkg_name,
                "id": cve.get("id"),
                "status": status,
                "summary": cve.get("summary"),
                "link": cve.get("link"),
                "scorev2": cve.get("scorev2"),
                "scorev3": cve.get("scorev3"),
                "scorev4": cve.get("scorev4"),
                "detail": cve.get("detail")
            })

    return unfixed

def _parse_makefile_objects(makefile_path: str) -> Dict[str, str]:
    """
    Parse a kernel Makefile and return a reverse mapping:
        object_or_folder → CONFIG_* option

    Supports lines such as:
        obj-$(CONFIG_X) += foo.o
        obj-$(CONFIG_X) += foo/ bar.o
    """
    obj_to_config = {}
    pattern = re.compile(
        r'obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*\+=\s*(.+)'
    )
    try:
        with open(makefile_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                m = pattern.match(line)
                if not m:
                    continue
                config, rhs = m.groups()
                entries = [tok.strip() for tok in rhs.split()]
                for e in entries:
                    obj_to_config[e] = config

    except FileNotFoundError:
        return {}

    return obj_to_config

def kernel_find_defconfig_arguments(input_kernel_path: str, modified_files_results: Dict[str, List[str]]) -> Dict[str, Dict[str, Optional[str]]]:
    """
    Given a dict { cve_id: [file1, file2, ...] } and the kernel path,
    find the CONFIG_* defconfig option controlling each modified file.
    
    Returns a dict:
    {
        cve_id: {
            file1: CONFIG_XXX,
            file2: CONFIG_YYY,
            ...
        }
    }
    """
    result = {}
    for cve_id, files in modified_files_results.items():
        result[cve_id] = {}
        for f in files:
            dir_path = os.path.dirname(os.path.join(input_kernel_path, f))
            basename = os.path.basename(f).replace(".c", ".o")
            while dir_path and dir_path.startswith(input_kernel_path):
                makefile = os.path.join(dir_path, "Makefile")
                if os.path.isfile(makefile):
                    obj_map = _parse_makefile_objects(makefile)
                    found = obj_map.get(basename)
                    if found:
                        result[cve_id][f] = found
                        break
                folder_name = os.path.basename(dir_path)
                basename = folder_name + "/"
                dir_path = os.path.dirname(dir_path)
            else:
                result[cve_id][f] = None
    return result

def kernel_defconfig_comparison(
    origin_config: str,
    defconfig_affected: Dict[str, Dict[str, Optional[str]]]
) -> Dict[str, Dict[str, Optional[str]]]:
    """
    Compare the kernel .config file with the defconfig_affected mapping:
        {
            cve_id: {
                file1: CONFIG_X or None,
                file2: CONFIG_Y or None,
                ...
            }
        }
    Returns:
        {
            cve_id: {
                file1: CONFIG_X or None,
                file2: None,  # core file without CONFIG
                ...
            }
        }

    Keeps CVEs with at least one enabled CONFIG or any core (None) files.
    """
    if not os.path.isfile(origin_config):
        print(f"ERROR: Missing .config at {origin_config}")
        return {}

    # collect all CONFIGs from defconfig_affected that are not None
    configs_to_find = {cfg for file_map in defconfig_affected.values() for cfg in file_map.values() if cfg}

    enabled = set()
    if configs_to_find:
        pattern = re.compile(
            r'^(' + "|".join(re.escape(cfg) for cfg in configs_to_find) + r')=(y|m|1)'
        )
        with open(origin_config, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                m = pattern.match(line)
                if m:
                    enabled.add(m.group(1))

    result = {}
    for cve_id, file_cfg_map in defconfig_affected.items():
        new_map = {}
        for file_path, cfg in file_cfg_map.items():
            # keep core files (None) and files with enabled CONFIG
            if cfg is None or cfg in enabled:
                new_map[file_path] = cfg
        if new_map:
            result[cve_id] = new_map

    return result

def generate_kernel_filtered_cve_check(original_cve_path: str, enabled_cves: Dict[str, List[str]], output_path: str) -> Dict:
    """
    Generate a new cve-check JSON file derived from original_cve_path but
    remove only the kernel CVEs that were in the original 'unfixed' set
    (kernel_get_cves_unfixed) and are NOT present in enabled_cves.
    """

    with open(original_cve_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if "package" not in data:
        print("ERROR: Invalid CVE check input (missing 'package')")
        sys.exit(1)

    unfixed_entries = kernel_get_cves_unfixed(original_cve_path)
    unfixed_ids = {e["id"] for e in unfixed_entries if e.get("id")}

    if isinstance(enabled_cves, dict):
        enabled_set = set(enabled_cves.keys())
    elif isinstance(enabled_cves, (list, set)):
        enabled_set = set(enabled_cves)
    else:
        enabled_set = set()
    removed = 0
    kept = 0

    for pkg in data.get("package", []):
        if pkg.get("name") != "linux-yocto":
            continue
        new_issues = []
        for issue in pkg.get("issue", []):
            iid = issue.get("id")
            # Remove unfixed kernel CVEs that are not enabled
            if iid in unfixed_ids and iid not in enabled_set:
                removed += 1
                continue

            new_issues.append(issue)
            # Count only unfixed kernel CVEs that remain
            if iid in unfixed_ids:
                kept += 1
        pkg["issue"] = new_issues

    try:
        with open(output_path, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=4)
        print(f"Wrote filtered rootfs CVE report to: {output_path}")
        print(f"Kernel CVEs removed: {removed}, kept: {kept}")
    except Exception as e:
        print(f"ERROR: Failed writing {output_path}: {e}")
        sys.exit(1)
    return data

def main() -> None:
    args = get_parameters()

    unfixed = kernel_get_cves_unfixed(args.input_cve_check)
    print(f"Unpatched kernel CVEs: {len(unfixed)}")

    affected_files = vulns_get_affected_files(
        args.vulns_path,
        unfixed,
        args.verbose
    )

    print(f"CVEs with affected files from vulns repo: {len(affected_files)}")

    defconfigs = kernel_find_defconfig_arguments(
        args.input_kernel_path,
        affected_files
    )

    enabled_cves = kernel_defconfig_comparison(
        args.input_config_path,
        defconfigs
    )

    print(f"CVEs affecting this kernel config: {len(enabled_cves)}")

    removed_cves = {}

    for cve_id, file_cfgs in defconfigs.items():
        # Skip CVEs that are enabled (including core/None)
        if cve_id in enabled_cves:
            continue

        # Only consider CVEs with at least one CONFIG_* to remove
        if any(cfg is not None for cfg in file_cfgs.values()):
            removed_cves[cve_id] = file_cfgs

    print(f"CVEs removed by kernel config: {len(removed_cves)}")

    os.makedirs(args.output_path, exist_ok=True)

    enabled_cves_path = os.path.join(
        args.output_path,
        f"{args.output_files_name}.kernel_remaining_cves.json"
    )

    with open(enabled_cves_path, "w", encoding="utf-8") as f:
        json.dump(enabled_cves, f, indent=4)

    print(f"Wrote enabled CVEs to: {enabled_cves_path}")

    removed_cves_path = os.path.join(
        args.output_path,
        f"{args.output_files_name}.kernel_removed_cves.json"
    )

    with open(removed_cves_path, "w", encoding="utf-8") as f:
        json.dump(removed_cves, f, indent=4)

    print(f"Wrote removed CVEs to: {removed_cves_path}")

    filtered_rootfs_path = os.path.join(
        args.output_path,
        f"{args.output_files_name}.kernel_filtered.json"
    )

    generate_kernel_filtered_cve_check(
        args.input_cve_check,
        enabled_cves,
        filtered_rootfs_path
    )

if __name__ == "__main__":
    main()
