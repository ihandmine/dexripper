English | [简体中文](usage.zh-CN.md)

# DexRipper Usage Guide

## Quick Start

### 1. Android App (Easiest)

#### Install
```bash
adb install dexripper.apk
```

#### Steps
1. Open the DexRipper app
2. On first use, a root authorization popup appears — tap "Allow"
3. If no popup shows up, manually grant permission in your root manager (KernelSU/SukiSU/Magisk)
4. Find the target app in the list (search supported)
5. Tap the app card to start unpacking
6. Wait for the scan to finish (usually 10-30 seconds)
7. Tap the green "Export" button
8. DEX files are saved to `/sdcard/Download/dexripper_<package>_<timestamp>/`

#### UI Overview

**List page**:
```
DexRipper
40 third-party apps
① Target app must be installed and able to launch
② Grant root permission on first use (popup allow, or manual grant)
③ Tap an app card to start unpacking
🔍 Search app name or package
[App card list]
```

**Detail page**:
```
Scanning: <app name>
[scan progress]
Done: <package> — N DEX, M valid
④ Tap the green button to export DEX files to /sdcard/Download
[📦 Export all]
[DEX file list + validation results]
[‹ Back to app list]
```

### 2. CLI Binary

#### Prepare
```bash
# Push the binary to device
adb push bin/arm64/dexripper-scan /data/local/tmp/
adb shell chmod +x /data/local/tmp/dexripper-scan
```

#### Scan
```bash
# Scan the target app (app must be running)
adb shell su -c "/data/local/tmp/dexripper-scan com.example.app /data/local/tmp/output"

# Check output
adb shell ls -lh /data/local/tmp/output/

# Pull results to local machine
adb pull /data/local/tmp/output/ ./output/
```

#### Output Format
```
dump_0000006fc1288000_OK.dex  5.8MB  ← address + validation status
dump_0000006fc1856000_OK.dex  9.5MB
dump_0000006fc21d3000_OK.dex  4.9MB
```

`_OK` means the 6-dimension validation passed; `_MISMATCH` means validation failed (likely fragment data).

### 3. Python CLI

#### Install dependencies
```bash
pip install frida frida-tools
```

#### Scan
```bash
# Scan the target app (auto-pushes dexripper-scan to device)
python cli/main.py scan com.example.app -o ./output
```

#### Validate
```bash
# Validate all DEX files
python cli/main.py validate ./output/

# Example output
dump_0000006fc1288000_OK.dex: VALID (36.1MB, classes=1234)
dump_0000006fc1856000_OK.dex: VALID (5.8MB, classes=567)
```

#### Generate report
```bash
# HTML report
python cli/main.py report ./output/ --format html --output report.html

# JSON report
python cli/main.py report ./output/ --format json --output report.json
```

## FAQ

### Q1: Scan fails with "exit 1"
**Cause**: target process does not exist or was killed.

**Fix**:
- Make sure the target app is installed and can launch
- The app auto-wakes the target (monkey cold-start), then scans after 6 seconds
- If it still fails, launch the target app manually and scan again

### Q2: Scan returns 0 DEX files
**Cause**:
1. Root permission not granted
2. Target app is not running
3. The app uses a special packer scheme

**Fix**:
- Check root grant (KernelSU/SukiSU/Magisk manager)
- Launch the target app manually and scan again

### Q3: Scan results contain MISMATCH files
**Cause**: heap scanning dumped fragment data, not complete DEX files.

**Fix**:
- Ignore MISMATCH files; only use `_OK` artifacts
- 6-dimension validation automatically filters false positives

### Q4: Exported DEX files fail to decompile
**Cause**:
1. DEX file is incomplete (MISMATCH)
2. The app uses code obfuscation or virtualization

**Fix**:
- Only use `VALID` DEX files
- Try jadx or dex2jar for decompilation
- For virtualized protection, combine with other tools (D8, dex2jar)

### Q5: App crashes or hangs
**Cause**:
1. Unsupported device (not ARM64)
2. Android version too low (< 8.0)
3. Root permission issue

**Fix**:
- Check device ABI (`adb shell getprop ro.product.cpu.abi`)
- Check Android version (`adb shell getprop ro.build.version.sdk`)
- Reinstall the app and grant root permission

## Technical Details

### Memory Scanning Principle
1. Parse `/proc/<pid>/maps` to enumerate all memory regions
2. Filter out system regions (/system, /apex, /data without the package name)
3. Scan each region for the `dex\n` magic
4. Once found, read the complete DEX file (according to its file_size field)
5. Verify DEX integrity with 6-dimension validation

### Heap Memory Coverage
Business DEX decrypted by packers usually lives in the scudo heap (large-object heap, mmap-based). DexRipper scans all heap regions, including:
- scudo:primary (small-object heap)
- scudo:secondary (large-object heap — where packer DEX resides)
- jemalloc heap
- libc malloc heap

### 6-Dimension Validation
1. **Magic**: `dex\n` + 3-digit version (035/037/039) + `\0`
2. **header_size**: must be 0x70 (112 bytes)
3. **endian_tag**: must be 0x12345678 (little-endian)
4. **file_size**: actual size must match the declared size
5. **Adler-32**: checksum must match
6. **class_defs**: class_defs_size must be > 0

## Performance Reference

| Metric | Value |
|--------|-------|
| Scan speed | ~100MB/s |
| Memory footprint | ~5MB |
| Single scan duration | 10-30s (depends on app memory size) |

## Security

- DexRipper never modifies any data of the target process
- Only reads `/proc/<pid>/maps` and `/proc/<pid>/mem`
- Uses the `process_vm_readv` syscall (requires root)
- No injection, no hooks

## License

For educational and research purposes only. Do not use for any illegal purpose. Any loss caused by using this tool is borne by the user.
