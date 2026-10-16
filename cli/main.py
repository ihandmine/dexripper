#!/usr/bin/env python3
"""
DexRipper - Android DEX Unpacking Toolkit

Main CLI entry point.

Usage:
    dexripper scan <package> [-o output_dir] [--mode scan|ebpf|auto]
    dexripper validate <dir_or_file>
    dexripper dedup <input_dir> [-o output_dir]
    dexripper repair <input_dir> [-o output_dir] [--level 0|1|2]
    dexripper report <input_dir> [--format json|html] [-o output]
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

# Ensure parent dir is in path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cli.binding import (
    validate, dedup, repair, get_version,
    py_validate_dex, py_dedup_dir,
    DEX_VALID, DEX_ADLER_MISMATCH, STATUS_NAMES,
)
from cli.report import generate_report
from cli.adb_helper import AdbHelper


def cmd_scan(args):
    """Scan and dump DEX files from a running app."""
    print(f"[*] DexRipper v{get_version()}")
    print(f"[*] Target: {args.package}")
    print(f"[*] Output: {args.output}")

    adb = AdbHelper()
    if not adb.check_device():
        print("[-] No ADB device connected")
        return 1

    # Resolve PID
    pid = adb.get_pid(args.package)
    if not pid:
        print(f"[-] Package {args.package} not running")
        print("[*] Tip: Start the app first, then run scan")
        return 1
    print(f"[*] PID: {pid}")

    # Push dexripper-scan to device if not exists
    device_scan = "/data/local/tmp/dexripper-scan"
    local_scan = Path(__file__).parent.parent / "bin" / "arm64" / "dexripper-scan"
    
    if not local_scan.exists():
        print(f"[-] dexripper-scan not found at {local_scan}")
        print("[*] Please ensure bin/arm64/dexripper-scan exists")
        return 1
    
    print(f"[*] Pushing dexripper-scan to device...")
    if not adb.push(str(local_scan), device_scan):
        print("[-] Failed to push dexripper-scan")
        return 1
    
    adb.shell(f"chmod +x {device_scan}")

    # Create output dir on device
    device_out = "/data/local/tmp/dexripper_out"
    adb.shell(f"rm -rf {device_out} && mkdir -p {device_out}")

    # Execute scan
    print(f"[*] Scanning {args.package}...")
    result = adb.shell(
        f"su -c '{device_scan} {args.package} {device_out}'"
    )
    print(result)

    # Pull results to local
    os.makedirs(args.output, exist_ok=True)
    print(f"\n[*] Pulling results to {args.output}...")
    adb.pull(device_out, args.output)

    # Validate pulled files
    print("\n[*] Validating results...")
    results = validate_directory(args.output)
    print_summary(results)

    return 0


def cmd_validate(args):
    """Validate DEX files in a directory."""
    print(f"[*] DexRipper v{get_version()} - Validate")
    print(f"[*] Path: {args.path}")

    if os.path.isfile(args.path):
        results = [validate_file(args.path)]
    else:
        results = validate_directory(args.path)

    print_summary(results)
    return 0


def cmd_dedup(args):
    """Deduplicate DEX files."""
    print(f"[*] DexRipper v{get_version()} - Dedup")
    print(f"[*] Input: {args.input_dir}")
    print(f"[*] Output: {args.output or args.input_dir}")

    removed = dedup(args.input_dir, args.output)
    print(f"[+] Removed {removed} duplicates")
    return 0


def cmd_repair(args):
    """Repair DEX files."""
    print(f"[*] DexRipper v{get_version()} - Repair")
    print(f"[*] Input: {args.input_dir}")
    print(f"[*] Output: {args.output or args.input_dir}")
    print(f"[*] Level: {args.level}")

    count = repair(args.input_dir, args.output, args.level)
    print(f"[+] Repaired {count} files")
    return 0


def cmd_report(args):
    """Generate report for DEX files."""
    print(f"[*] DexRipper v{get_version()} - Report")
    print(f"[*] Input: {args.input_dir}")

    results = validate_directory(args.input_dir)
    report = generate_report(results, args.format)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"[+] Report saved to {args.output}")
    else:
        print(report)

    return 0


# ========================================================================
# Helper Functions
# ========================================================================

def validate_file(path: str) -> dict:
    """Validate a single DEX file."""
    return py_validate_dex(path)


def validate_directory(dir_path: str) -> List[dict]:
    """Validate all DEX files in a directory."""
    results = []
    dex_files = sorted(Path(dir_path).glob("*.dex"))
    for f in dex_files:
        r = validate_file(str(f))
        results.append(r)
    return results


def print_summary(results: List[dict]):
    """Print validation summary."""
    if not results:
        print("[-] No DEX files found")
        return

    valid = sum(1 for r in results if r["status"] == DEX_VALID)
    mismatch = sum(1 for r in results if r["status"] == DEX_ADLER_MISMATCH)
    invalid = len(results) - valid - mismatch
    total_size = sum(r["size"] for r in results)

    print(f"\n{'='*70}")
    print(f"  Summary")
    print(f"{'='*70}")
    print(f"  Total files:   {len(results)}")
    print(f"  Valid:         {valid}")
    print(f"  Adler mismatch: {mismatch}")
    print(f"  Invalid:       {invalid}")
    print(f"  Total size:    {total_size / 1024 / 1024:.1f} MB")
    print(f"{'='*70}")

    # Per-file table
    print(f"\n  {'File':<50} {'Size':>8} {'Adler':>6} {'Classes':>8} {'Status'}")
    print(f"  {'-'*85}")
    for r in results:
        name = os.path.basename(r["path"])[:48]
        size = f"{r['size']/1024:.0f}K" if r["size"] < 1024*1024 else f"{r['size']/1024/1024:.1f}M"
        adler = "OK" if r["adler_ok"] else "FAIL"
        classes = r["class_count"]
        status = STATUS_NAMES.get(r["status"], "?")
        print(f"  {name:<50} {size:>8} {adler:>6} {classes:>8} {status}")


# ========================================================================
# Main
# ========================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="dexripper",
        description="DexRipper - Android DEX Unpacking Toolkit",
    )
    parser.add_argument("--version", action="version", version=f"DexRipper {get_version()}")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # scan
    p_scan = sub.add_parser("scan", help="Scan and dump DEX from running app")
    p_scan.add_argument("package", help="Target package name or PID")
    p_scan.add_argument("-o", "--output", default="./dexripper_output", help="Output directory")

    # validate
    p_val = sub.add_parser("validate", help="Validate DEX files")
    p_val.add_argument("path", help="File or directory to validate")

    # dedup
    p_dedup = sub.add_parser("dedup", help="Deduplicate DEX files")
    p_dedup.add_argument("input_dir", help="Input directory")
    p_dedup.add_argument("-o", "--output", help="Output directory (default: in-place)")

    # repair
    p_repair = sub.add_parser("repair", help="Repair DEX files")
    p_repair.add_argument("input_dir", help="Input directory")
    p_repair.add_argument("-o", "--output", help="Output directory (default: in-place)")
    p_repair.add_argument("--level", type=int, choices=[0, 1, 2], default=0, help="Repair level")

    # report
    p_report = sub.add_parser("report", help="Generate report")
    p_report.add_argument("input_dir", help="Input directory")
    p_report.add_argument("--format", choices=["json", "html"], default="json", help="Report format")
    p_report.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "scan": cmd_scan,
        "validate": cmd_validate,
        "dedup": cmd_dedup,
        "repair": cmd_repair,
        "report": cmd_report,
    }

    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
