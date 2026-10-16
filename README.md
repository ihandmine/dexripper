English | [简体中文](README.zh-CN.md)

# DexRipper - Non-Invasive Android DEX Unpacker

DexRipper is a memory-scanning based Android DEX unpacker. It extracts DEX files from the memory of a running process — no code injection required — making it suitable for reverse engineering of packed/protected apps.

📖 **[Detailed Usage Guide](docs/usage.md)** — FAQ, technical details, troubleshooting

## Features

- **Non-invasive scanning**: reads `/proc/<pid>/maps` and `/proc/<pid>/mem` only; no injection, no hooks
- **6-dimension validation**: magic, header_size, endian_tag, file_size, Adler-32, class_defs
- **On-device app**: one-click unpacking right on the phone (DexRipper APK)
- **Heap scanning**: extracts business DEX decrypted by packers into the scudo heap
- **CLI toolkit**: scan / validate / dedup / repair / report (JSON & HTML)

## Downloads

| Artifact | Size | Description |
|----------|------|-------------|
| `dexripper.apk` | 340KB | Android app, one-click unpacking on device |
| `bin/arm64/dexripper-scan` | 1.2MB | Static ARM64 binary for CLI usage |

See [Releases](https://github.com/ihandmine/dexripper/releases) for prebuilt versions.

## Usage

### Option 1: Android App (Recommended)

1. Install `dexripper.apk` on a rooted Android device (ARM64, Android 8.0+)
2. Open DexRipper and grant root permission (via su popup, or manually in KernelSU/SukiSU/Magisk manager)
3. Tap an app card to start unpacking (search box supported)
4. After scanning, tap the green button to export DEX files to `/sdcard/Download/`

```
① Target app must be installed and able to launch
② Grant root permission on first use (popup allow, or manual grant)
③ Tap an app card to start unpacking
④ Tap the green button to export DEX files to /sdcard/Download
```

### Option 2: CLI Binary

```bash
# Push the scanner to device
adb push bin/arm64/dexripper-scan /data/local/tmp/
adb shell chmod +x /data/local/tmp/dexripper-scan

# Scan (target app must be running)
adb shell su -c "/data/local/tmp/dexripper-scan <package_name> /data/local/tmp/output"

# Pull results
adb pull /data/local/tmp/output/ ./output/
```

### Option 3: Python CLI

```bash
pip install frida frida-tools

# Scan (auto-pushes dexripper-scan to device)
python cli/main.py scan <package_name> -o ./output

# Validate
python cli/main.py validate ./output/

# Generate report
python cli/main.py report ./output/ --format html
```

## Requirements

- Android 8.0+ (API 26+), ARM64
- Root access (KernelSU / SukiSU / Magisk)

## How It Works

1. **Memory mapping**: parse `/proc/<pid>/maps` to enumerate memory regions
2. **DEX magic matching**: scan for `dex\n035\0` / `dex\n037\0` / `dex\n039\0`
3. **6-dimension validation**:
   - magic: `dex\n` + 3-digit version + `\0`
   - header_size: 0x70
   - endian_tag: 0x12345678
   - file_size: matches declared size
   - Adler-32: checksum verification
   - class_defs: > 0
4. **Heap coverage**: scans scudo heap regions where packer-decrypted DEX usually resides
5. **Deduplication**: SHA-256 based dedup to avoid duplicate dumps


## Notes

1. **Root permission** is required to read target process memory
2. **Target process must stay alive**; the app auto-wakes it via monkey cold-start
3. **False positives**: heap scanning may dump fragment data; 6-dim validation marks them as MISMATCH
4. **Performance**: ~100MB/s scan speed

## License

For educational and research purposes only. Do not use for any illegal purpose.

## Feedback

Issues and pull requests are welcome at [Issues](https://github.com/ihandmine/dexripper/issues).
