[English](usage.md) | 简体中文

# DexRipper 详细使用指南

## 快速开始

### 1. Android App 方式（最简单）

#### 安装
```bash
adb install dexripper.apk
```

#### 使用步骤
1. 打开 DexRipper App
2. 首次使用会弹出 root 授权弹窗，点击"允许"
3. 如果没有弹窗，手动到 root 管理器（KernelSU/SukiSU/Magisk）中授权
4. 在应用列表中找到目标应用（支持搜索）
5. 点击应用卡片开始脱壳
6. 等待扫描完成（通常 10-30 秒）
7. 点击绿色"导出全部产物"按钮
8. 产物保存在 `/sdcard/Download/dexripper_<package>_<timestamp>/`

#### 界面说明

**列表页**：
```
DexRipper
共 40 个第三方应用
① 目标应用需已安装并可启动
② 首次使用需授予 root 权限（弹窗允许或手动授权）
③ 点击应用卡片开始脱壳
🔍 搜索应用名或包名
[应用卡片列表]
```

**详情页**：
```
扫描中: <应用名>
[扫描进度]
完成: <package> — N 个 DEX, M 有效
④ 点击绿色按钮导出产物到 /sdcard/Download
[📦 导出全部产物]
[DEX 文件列表 + 校验结果]
[‹ 返回应用列表]
```

### 2. CLI 命令行方式

#### 准备工作
```bash
# 推送二进制到设备
adb push bin/arm64/dexripper-scan /data/local/tmp/
adb shell chmod +x /data/local/tmp/dexripper-scan
```

#### 执行扫描
```bash
# 扫描目标应用
adb shell su -c "/data/local/tmp/dexripper-scan com.example.app /data/local/tmp/output"

# 查看输出
adb shell ls -lh /data/local/tmp/output/

# 拉取产物到本地
adb pull /data/local/tmp/output/ ./output/
```

#### 输出格式
```
dump_0000006fc1288000_OK.dex  5.8MB  ← 地址 + 校验状态
dump_0000006fc1856000_OK.dex  9.5MB
dump_0000006fc21d3000_OK.dex  4.9MB
```

`_OK` 表示六维校验通过，`_MISMATCH` 表示校验失败（可能是碎片数据）。

### 3. Python CLI 方式

#### 安装依赖
```bash
pip install frida frida-tools
```

#### 扫描
```bash
# 扫描目标应用（自动推送 dexripper-scan 到设备）
python cli/main.py scan com.example.app -o ./output
```

#### 校验
```bash
# 校验所有 DEX
python cli/main.py validate ./output/

# 输出示例
dump_0000006fc1288000_OK.dex: VALID (36.1MB, classes=1234)
dump_0000006fc1856000_OK.dex: VALID (5.8MB, classes=567)
```

#### 生成报告
```bash
# HTML 报告
python cli/main.py report ./output/ --format html --output report.html

# JSON 报告
python cli/main.py report ./output/ --format json --output report.json
```

## 常见问题

### Q1: 扫描失败，提示 "exit 1"
**原因**：目标进程不存在或已被杀死

**解决**：
- 确保目标应用已安装并可正常启动
- App 会自动唤醒目标应用（monkey 冷启动），等待 6 秒后扫描
- 如果仍然失败，手动启动目标应用后再扫描

### Q2: 扫描结果为 0 个 DEX
**原因**：
1. 未授予 root 权限
2. 目标应用未运行
3. 应用使用了特殊的加固方案

**解决**：
- 检查 root 授权（KernelSU/SukiSU/Magisk 管理器）
- 手动启动目标应用后再扫描

### Q3: 扫描结果中有 MISMATCH
**原因**：堆扫描提取到碎片数据，不是完整的 DEX 文件

**解决**：
- MISMATCH 的文件可以忽略，只使用 `_OK` 的产物
- 六维校验会自动过滤假阳性

### Q4: 导出的 DEX 无法反编译
**原因**：
1. DEX 文件不完整（MISMATCH）
2. 应用使用了代码混淆或虚拟化

**解决**：
- 只使用 `VALID` 的 DEX 文件
- 尝试使用 jadx 或 dex2jar 反编译
- 对于虚拟化保护，需要配合其他工具（如 D8、dex2jar）

### Q5: App 闪退或无响应
**原因**：
1. 设备不支持（非 ARM64）
2. Android 版本过低（< 8.0）
3. root 权限问题

**解决**：
- 检查设备架构（`adb shell getprop ro.product.cpu.abi`）
- 检查 Android 版本（`adb shell getprop ro.build.version.sdk`）
- 重新安装 App 并授予 root 权限

## 技术细节

### 内存扫描原理
1. 读取 `/proc/<pid>/maps` 获取所有内存区域
2. 过滤系统区域（/system、/apex、/data 不含包名的区域）
3. 对每个区域扫描 `dex\n` 魔数
4. 找到魔数后读取完整 DEX 文件（根据 file_size 字段）
5. 六维校验验证 DEX 完整性

### 堆内存扫描
加固壳解密的业务 DEX 通常分配在 scudo 堆（大对象堆，mmap 实现）。DexRipper 会扫描所有堆区域，包括：
- scudo:primary（小对象堆）
- scudo:secondary（大对象堆，加固壳 DEX 常驻此处）
- jemalloc 堆
- libc malloc 堆

### 六维校验
1. **魔数**：`dex\n` + 3 位版本号（035/037/039）+ 0
2. **header_size**：必须为 0x70（112 字节）
3. **endian_tag**：必须为 0x12345678（小端序）
4. **file_size**：实际文件大小必须与声明一致
5. **Adler-32**：校验和必须匹配
6. **class_defs**：class_defs_size 必须 > 0

## 性能参考

| 指标 | 数值 |
|------|------|
| 扫描速度 | ~100MB/s |
| 内存占用 | ~5MB |
| 单次扫描耗时 | 10-30 秒（视应用内存大小） |

## 安全说明

- DexRipper 不会修改目标进程的任何数据
- 只读取 `/proc/<pid>/maps` 和 `/proc/<pid>/mem`
- 使用 `process_vm_readv` 系统调用（需要 root）
- 不会注入任何代码或 hook

## 许可证

本项目仅供学习和研究使用，请勿用于非法用途。使用本工具造成的任何损失由用户自行承担。
