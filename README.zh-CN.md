[English](README.md) | 简体中文

# DexRipper - Android 无注入脱壳工具

DexRipper 是一款基于内存扫描的 Android 无注入脱壳工具，支持从运行中的进程内存提取 DEX 文件，适用于加固应用的逆向分析。

📖 **[详细使用指南](docs/usage.zh-CN.md)** —— 含 FAQ、技术原理、常见问题排查

## 特性

- **无注入扫描**：不向目标进程注入任何代码，通过 `/proc/<pid>/maps` 和 `process_vm_readv` 读取内存
- **六维校验**：魔数、header_size、endian_tag、file_size、Adler-32、class_defs 多重验证
- **APK 端侧运行**：Android App 形态，一键点击脱壳
- **堆内存扫描**：支持提取加固壳解密的业务 DEX（scudo 堆区域）
- **CLI 工具**：Python 命令行工具，支持扫描、校验、去重、修复、报告生成

## 产物说明

### 二进制文件

- `dexripper.apk` (340KB) - Android App，端侧一键脱壳
- `bin/arm64/dexripper-scan` (1.2MB) - ARM64 静态二进制，CLI 使用

### Python CLI

`cli/` 目录包含 Python 命令行工具：
- `main.py` - CLI 入口（调用 dexripper-scan 二进制）
- `binding.py` - C 库绑定 + DEX 校验
- `adb_helper.py` - ADB 辅助工具
- `report.py` - 报告生成（JSON/HTML）

## 使用方法

### 方式一：Android App（推荐）

1. 安装 `dexripper.apk` 到已 root 的 Android 设备
2. 打开 DexRipper App
3. 授予 root 权限（首次使用会弹窗，或在 root 管理器中手动授权）
4. 点击目标应用卡片开始脱壳
5. 扫描完成后点击绿色按钮导出产物到 `/sdcard/Download/`

**使用流程**：
```
① 目标应用需已安装并可启动
② 首次使用需授予 root 权限（弹窗允许或手动授权）
③ 点击应用卡片开始脱壳
④ 点击绿色按钮导出产物到 /sdcard/Download
```

### 方式二：CLI 命令行

```bash
# 推送二进制到设备
adb push bin/arm64/dexripper-scan /data/local/tmp/
adb shell chmod +x /data/local/tmp/dexripper-scan

# 执行扫描
adb shell su -c "/data/local/tmp/dexripper-scan <package_name> /data/local/tmp/output"

# 拉取产物
adb pull /data/local/tmp/output/ ./output/
```

### 方式三：Python CLI

```bash
# 安装依赖
pip install frida frida-tools

# 扫描（自动推送 dexripper-scan 到设备）
python cli/main.py scan <package_name> -o ./output

# 校验
python cli/main.py validate ./output/

# 生成报告
python cli/main.py report ./output/ --format html
```

## 设备要求

- Android 8.0+ (API 26+)
- 已 root（KernelSU / SukiSU / Magisk 等）
- ARM64 架构

## 技术原理

1. **内存映射扫描**：读取 `/proc/<pid>/maps` 获取所有内存区域
2. **DEX 特征匹配**：扫描 `dex\n035\0` / `dex\n037\0` / `dex\n039\0` 魔数
3. **六维校验**：
   - 魔数：`dex\n` + 3 位版本号 + 0
   - header_size：0x70
   - endian_tag：0x12345678
   - file_size：与声明一致
   - Adler-32：校验和
   - class_defs：> 0
4. **堆内存支持**：扫描 scudo 堆区域（加固壳解密的业务 DEX 常驻此处）
5. **去重**：SHA-256 哈希去重，避免重复产物

## 注意事项

1. **root 权限**：首次使用需授予 root 权限，否则无法读取目标进程内存
2. **进程存活**：扫描时目标进程必须存活，App 会自动唤醒（monkey 冷启动）
3. **假阳性**：堆扫描可能提取到碎片数据，六维校验会标记为 MISMATCH
4. **性能**：扫描速度约 100MB/s（C 引擎）

## 许可证

本项目仅供学习和研究使用，请勿用于非法用途。

## 下载

- [Releases](https://github.com/ihandmine/dexripper/releases) - 下载最新版本的 APK 和二进制文件

## 反馈

如有问题或建议，请提交 [Issue](https://github.com/ihandmine/dexripper/issues)。
