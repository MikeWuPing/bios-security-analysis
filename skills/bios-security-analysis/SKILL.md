---
name: bios-security-analysis
description: |
  UEFI/BIOS 固件安全漏洞分析。当用户需要分析 BIOS ROM 镜像的安全漏洞、审计 UEFI 固件、提取和分析微码（microcode）、审计 Secure Boot 证书（PK/KEK/db/dbx）、识别 SMM 攻击面、检查 CSME 版本与 CVE 的关联、检测 CSM/遗留启动风险、或进行任何 BIOS 安全评估时使用。当用户提到 BIOS 安全、UEFI 固件分析、主板固件审计、或想要解包/解压/解析固件镜像时触发。
---

# BIOS/UEFI 固件安全分析

从初始镜像识别到深度解压、模块枚举、微码审计、证书分析、最终报告输出的完整方法论。

## 核心工作流

分析新 BIOS 镜像时按以下顺序执行：

### 1. 初步鉴定

- 识别文件类型：`file <镜像文件>` —— 预期 "Intel serial flash for PCH ROM" 或类似输出
- 大小检查：现代 UEFI BIOS 通常为 16MB 或 32MB
- 计算哈希：MD5 + SHA256 用于唯一标识
- 判断格式：UEFI Capsule（头部为 Capsule GUID）还是原始 SPI 镜像
- 原始 SPI 镜像的 Flash Descriptor 从偏移 0x10 开始

### 2. Intel Flash Descriptor 解析

Flash Descriptor 位于 SPI 镜像偏移 0x10 处：

```
签名 (0x10): 0x0FF0A55A (LE)
FLMAP0 (FD 偏移 0x00): FCBA[0:7], NC[8:9], FRBA[16:23]
FLMAP1 (偏移 0x04): 包含 FMBA 等
```

Region Descriptor 从 FRBA 开始，每条 4 字节 (Base[0:11], Limit[12:23], Access[24:27])。

区域名称: Descriptor, BIOS, ME, GbE, Platform Data, EC。

Flash Descriptor 解析是确定各区域布局（BIOS 区、ME 区等）的关键前提。

### 3. BIOS 原始供应商识别 (IBV)

确定 Independent BIOS Vendor 的方法：

```python
vendor_patterns = {
    'AMI': [b'AMI Aptio', b'AMITSESetup', b'AmiWrapperSetup', b'American Megatrends'],
    'Insyde': [b'InsydeH2O', b'Insyde Software'],
    'Phoenix': [b'Phoenix SecureCore', b'Phoenix Technologies'],
}
```

- **AMI Aptio**：`AMITSESetup`、`AmiWrapperSetup`、`AmiBoardInfo` —— 消费级主板最常见
- **InsydeH2O**：多见于笔记本
- **Phoenix SecureCore**：企业级

同时检查：ACPI OEMID/OEM Table ID、DXE/PEI 模块 GUID、Setup IFR 架构特征。

确认供应商后，检索该供应商历史上公开发布的安全公告和已知 CVE 列表，逐项比对目标 BIOS 中是否包含受影响版本的模块。

### 4. 固件卷 (FV) 枚举

使用 `uefi_firmware` 库：

```python
from uefi_firmware.uefi import FirmwareVolume, FirmwareFileSystem, EFI_FILE_TYPES, sguid, search_firmware_volumes

# search_firmware_volumes 返回 FV 偏移列表（指向 _FVH 签名位置）
fv_offsets = search_firmware_volumes(data)  # 返回 int 列表

# FV 头部在偏移 - 0x28 处（ZeroVector 在 _FVH 前 0x28 字节）
for fv_off in fv_offsets:
    fv_start = fv_off - 0x28
    fv_hdr = data[fv_start:fv_start+0x48]
    fv_len = struct.unpack_from('<Q', fv_hdr, 0x20)[0]
    ffs_guid = sguid(fv_hdr[0x10:0x20])  # FFS1/FFS2/FFS3/NVRAM 等
    fv = FirmwareVolume(data[fv_start:fv_start+fv_len])
    fv.process()  # 必须调用 process() 后才能访问 firmware_filesystems
    for ffs in fv.firmware_filesystems:
        ffs.process()
        for obj in ffs.objects:
            # obj 是 FirmwareFile: type, guid, size, sections
            type_name = EFI_FILE_TYPES.get(obj.type, ('?','?','?'))[2]
            ui_name = ''  # 从 sections 中 type=0x15 的 UI section 获取
```

**FFS 文件类型 (EFI_FILE_TYPES)**：
- 0x01: RAW, 0x02: FREEFORM, 0x03: SEC, 0x04: PEI_CORE, 0x05: DXE_CORE
- 0x06: PEIM, 0x07: DRIVER, 0x09: APPLICATION
- 0x0A: SMM, 0x0B: FV_IMAGE（嵌套压缩卷）
- 0xF0: 填充 (Padding)

**Section 类型 (EFI_SECTION_TYPES)**：
- 0x01: 压缩段, 0x02: GUID 定义段, 0x15: UI（用户界面名称，UTF-16 LE）
- 0x19: 原始数据, 0x17: FV 镜像

### 5. LZMA 自定义解压

主 DXE/SMM 卷通常以 GUID 定义段 + LZMA 压缩形式存储。

**关键 GUID**：`EE4E5898-3914-4259-9D6E-DC7BD79403CF`（LzmaCustomDecompressGuid）
LE 字节序：`98584EEE143959429D6EDC7BD79403CF`

**GUID 定义段结构**：
```
偏移 0-15:  SectionDefinitionGuid（16 字节）
偏移 16-17: DataOffset（UINT16 LE）—— 相对段起始的偏移
偏移 18-19: Attributes（UINT16 LE）
偏移 DataOffset+: 压缩数据
```

**重要**：`uefi_firmware` 的 `sec.data` 去掉了 4 字节的公共段头，数据从 GUID 位置开始。在 sec.data 中的有效偏移 = DataOffset - 4。

**LZMA 自定义头部**（位于有效偏移处）：
```
字节 0:     LZMA 属性（lc、lp、pb 编码为 lc + lp*9 + pb*45）
            标准 UEFI 使用 0x5D = lc=3, lp=0, pb=2
字节 1-4:   字典大小（UINT32 LE），通常 0x01000000（16MB）
字节 5-12:  未压缩大小（UINT64 LE），通常 20-30MB
字节 13+:   LZMA 压缩流
```

**解压代码**：
```python
import lzma, struct

# 搜索 LZMA 自定义 GUID
guid_bytes = bytes.fromhex('98584EEE143959429D6EDC7BD79403CF')
pos = data.find(guid_bytes)

# 读取 DataOffset（相对段起始，含 4 字节段头）
data_offset = struct.unpack_from('<H', data, pos + 16)[0]
eff_off = data_offset - 4  # 相对 GUID 位置的有效偏移

lzma_hdr = data[pos + eff_off:pos + eff_off + 13]
props = lzma_hdr[0]
lc = props % 9
remainder = props // 9
lp = remainder % 5
pb = remainder // 5
dict_size = struct.unpack_from('<I', lzma_hdr, 1)[0]
uncomp_size = struct.unpack_from('<Q', lzma_hdr, 5)[0]

lzma_stream = data[pos + eff_off + 13:]
filters = [{'id': lzma.FILTER_LZMA1, 'lc': lc, 'lp': lp, 'pb': pb, 'dict_size': dict_size}]
decompressed = lzma.decompress(lzma_stream, format=lzma.FORMAT_RAW, filters=filters)

# 备选：uefi_firmware 自带的 LzmaDecompress
from uefi_firmware.efi_compressor import LzmaDecompress
decompressed = bytes(LzmaDecompress(data[pos+eff_off:], uncomp_size))
```

**常见问题**：解压后的数据可能在真正的 FV 头部前有 16-32 字节的前缀。尝试从偏移 0、8、16、24、32 开始解析，直到 `_FVH` 签名与 ZeroVector 对齐。

### 6. FIT 表与微码提取

FIT (Firmware Interface Table) 包含微码补丁、ACM 等指针。

**查找 FIT 表**：搜索 `_FIT_   ` 签名（注意：后面有三个空格）。常见于 BIOS 区域边界附近。

**FIT 条目结构**（每条 16 字节，从 FIT + 0x10 开始）：
```
字节 0-7:   地址（UINT64）—— 4GB 空间中的物理地址
字节 8-10:  Size[3]
字节 11:    保留
字节 12-13: Version（UINT16）
字节 14:    Type（7 位）+ CV 标志（1 位）
字节 15:    校验和
```

**FIT 地址转换**：FIT 地址位于 4GB 内存空间。对于 16MB 闪存：
`闪存偏移 = fit_address - 0xFF000000`（或更通用的 `fit_address & 0xFFFFFFFF`）

**条目类型**：
- 0x00: Header（头部）
- 0x01: Microcode（微码 MCU）
- 0x02: Startup ACM
- 0x07: BIOS Startup Module
- 0x7F: Skip（跳过）

**Intel 微码头部**（共 96 字节）：
```
偏移 0:  HeaderVersion (UINT32) = 0x00000001
偏移 4:  UpdateRevision (UINT32)
偏移 8:  Date (UINT32) —— 0xYYYYMMDD BCD 编码
偏移 12: ProcessorSignature (UINT32) —— CPUID
偏移 28: DataSize (UINT32)
偏移 32: TotalSize (UINT32)
偏移 40: PlatformIdMask (UINT32)
```

**微码搜索代码**：
```python
def find_microcode(blob, source=''):
    patches = []
    pos = 0
    while pos < len(blob) - 48:
        idx = blob.find(b'\x01\x00\x00\x00', pos)
        if idx < 0: break
        if idx + 48 <= len(blob):
            hdr_ver = struct.unpack_from('<I', blob, idx)[0]
            if hdr_ver != 1:
                pos = idx + 4; continue
            cpuid = struct.unpack_from('<I', blob, idx + 12)[0]
            total_size = struct.unpack_from('<I', blob, idx + 32)[0]
            # 验证：合理的大小、有效的 CPUID
            if total_size >= 0x100 and total_size < 0x10000 \
               and cpuid > 0x1000 and cpuid != 0xFFFFFFFF:
                patches.append(...)
        pos = idx + 4
    return patches
```

**Raptor Lake (13/14 代) CPUID**：0x000B0670, 0x000B0671, 0x000B06E0, 0x000B06F0, 0x000B06F2, 0x000B06F5

**Alder Lake (12 代) CPUID**：0x00090671, 0x00090672, 0x00090675, 0x000906A0, 0x000906A3, 0x000906A4

**最新微码版本参考**（检查 Intel GitHub：`Intel-Linux-Processor-Microcode-Data-Files`）：
- ADL-S: 0x42E（约 2024 年末）
- RPL-S: 0x12A（约 2025 年 3 月），可能已存在更新的内部版本

### 7. Secure Boot 证书分析

#### 在解压后的 FV 中查找证书

搜索 DER 编码的 X.509 证书（以 `0x30 0x82` 开头）：

```python
pos = 0
while pos < len(fv_data) - 4:
    if fv_data[pos:pos+2] == b'\x30\x82':
        cert_len = struct.unpack_from('>H', fv_data, pos+2)[0]
        if 500 < cert_len < 0x4000:
            blob = fv_data[pos:pos+cert_len+4]
            if b'CN=' in blob[:300]:
                # 解析证书...
    pos += 1
```

#### 从原始 DER 解析 X.509 字段

**主题 CN**：`re.findall(rb'CN=([\x20-\x7e]{4,80})', blob)` —— 最后一个匹配通常是主题名称

**有效期日期**：
- UTCTime 格式：`YYMMDDHHMMSSZ`（年份 < 50 → 2000+，>= 50 → 1900+）
- GeneralizedTime 格式：`YYYYMMDDHHMMSSZ`
- 前两个连续的时间值分别是 notBefore 和 notAfter
- 验证条件：两者间隔应 < 30 字节

```python
utc_matches = re.finditer(rb'(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z', blob)
gen_matches = re.finditer(rb'(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z', blob)
```

**签名算法**：通过 OID 模式识别：
- `\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b` = sha256WithRSAEncryption
- `\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05` = sha1WithRSAEncryption

**密钥大小**：寻找 RSA 公钥指数 `\x02\x03\x01\x00\x01`（65537），然后定位模数长度。

#### 证书安全检查

1. **过期检查**：`notAfter < 当前日期` → 已过期
2. **即将过期**：`< 90 天` → 警告
3. **弱签名**：SHA-1 → 不合规
4. **弱密钥**：RSA < 2048 位 → 不合规
5. **测试证书**：blob 中包含 `b'DO NOT TRUST'`、`b'DO NOT SHIP'`、`b'TEST'` → 拒绝
6. **长有效期**：`> 5 年`（非根证书）→ 标记

#### DBX（吊销数据库）分析

搜索 `EFI_CERT_SHA256_GUID`（`C1C41626-504C-4092-ACA9-41F936934328`，LE 字节：`2616C4C14C509240ACA941F936934328`）。

DBX 条目是 `EFI_SIGNATURE_LIST` 结构，每条 48 字节（16 字节 Owner GUID + 32 字节 SHA256 哈希）。DBX 为空（< 50 条）意味着平台不阻止任何已知的已吊销引导加载程序。

**需检查的已知已吊销引导加载程序**：
- BlackLotus (2023): `77fa9abd...`
- BootHole GRUB2 (CVE-2020-10713): `e75b63d0...`
- BootHole shim (CVE-2020-14372): `36382848...`

### 8. CSME 固件版本审计

CSME 固件存储在闪存的 ME 区域。版本提取方法：

```python
# CPD (Code Partition Directory) 条目 —— 标识 ME 模块
for m in re.finditer(rb'\x24CPD', data):
    cpd_name = data[m.start()+0x18:m.start()+0x28].decode('ascii', errors='replace').strip()

# 从字符串提取版本
for m in re.finditer(rb'PCHC(\d+\.\d+\.\d+\.\d+)', data):
    pchc_ver = m.group(1).decode('ascii')

# ADL 平台 CSME 关键组件：
# - CSME ROM: 16.1.x —— ME 主内核
# - PCHC: 16.1.x —— PCH 配置
# - PMCP: 160.x —— 电源管理
# - SPHY: 13.x —— 南桥 PHY
# - ISHC: 5.x —— 集成传感器集线器控制器
```

**与 Intel PSIRT 安全公告交叉比对**：
- INTEL-SA-00847 (2024-03, CVSS 8.8): CSME 16.1 特定版本
- INTEL-SA-00783 (2023-08, CVSS 8.2): CSME 16.1.30 及更早版本
- INTEL-SA-00614 (2022-11, CVSS 7.8): 多个 CSME 16.1 版本
- CVE-2022-36392 (CVSS 8.2), CVE-2022-29871 (CVSS 7.8)

**重要提示**：静态分析无法最终确定 CSME 补丁是否已应用。必须使用 Intel CSMEVDT（CSME Version Detection Tool）进行运行时验证。

### 9. SMM 攻击面分析

从解压后的 FV 枚举 SMM 模块：

```python
# SMM 模块在 FFS 中的类型为 0x0A
# 需要关注的 SMI Handler（按 UI 名称搜索）：
smi_handlers = [
    'PchSmiDispatcher',  # PCH SMI 事件分发器
    'CrbSmi',            # Command Register Buffer SMI
    'NbSmi',             # 北桥 SMI
    'SleepSmi',          # 睡眠状态 SMI
    'TcoSmi',            # TCO 看门狗 SMI
    'SmiFlash',          # 通过 SMI 更新闪存
    'SmiVariable',       # 通过 SMI 更新变量
    'NvramSmm',          # NVRAM SMM 处理程序
]
```

**安全检查项**：
- SMM 通信缓冲区：存在 `PiSmmCommunicationSmm` → 需检查缓冲区验证
- SMRAM 锁定：`PiSmmCpuDxeSmm`、`SmmAccess`、`SmmControl`
- BIOS Guard：`BiosGuardServices` → 硬件级别的 SPI 闪存保护
- HSTI：`HstiIhvSmm` → 硬件安全测试接口
- SPI 保护：`FlashDriverSmm`、`SpiSmm`、`SpiSmmStub`

**仅可通过运行时验证的检查项**（静态分析无法验证）：
- HSFS.FLOCKDN 寄存器状态
- BIOS_CNTL.BIOSWE、BIOS_CNTL.BLE
- SMRR 配置
- SMM 通信缓冲区输入验证

### 10. CSM/遗留启动检测

CSM (Compatibility Support Module) 启用遗留 BIOS 启动，可绕过 Secure Boot。

**关键 CSM 模块**：`CsmDxe`、`CsmVideo`、`CsmBlockIo`、`LegacyRegionDxe`、`AmiLegacyInterrupt`、`TcgLegacy`

只要发现以上任一模块 → CSM 已启用 → Secure Boot 存在被绕过风险。

### 11. 安全关键词搜索分类

对模块按 UI 名进行分类时，搜索以下关键词：

```python
security_keywords = {
    'SMM': ['Smm', 'SMI', 'SMRAM', 'SmmChild', 'SmmCore', 'SmmAccess', 'SmmControl'],
    'SecureBoot': ['SecureBoot', 'ImageSecurity', 'ImageVerification'],
    'S3/睡眠': ['S3', 'BootScript', 'S3Save', 'LockBox'],
    'SPI/闪存': ['Spi', 'Flash', 'Fvb', 'FirmwareVolumeBlock', 'SpiLock', 'FlashSmm'],
    'TPM/安全': ['Tcg', 'Tpm', 'Tcg2', 'TrEE', 'Txt', 'BiosGuard', 'BootGuard'],
    'Setup/配置': ['Setup', 'AMITSE', 'AmiTse', 'HiiDatabase', 'FormBrowser'],
    '内存保护': ['Memory', 'MemTest', 'HeapGuard', 'PoolGuard', 'NullDetection', 'StackGuard'],
    'CSM/遗留': ['Csm', 'Legacy', 'LegacyBios', 'LegacyRegion', 'LegacyInterrupt'],
    '网络': ['Pxe', 'Snp', 'Mnp', 'Arp', 'Ip4', 'Ip6', 'Tcp', 'Http', 'Tls', 'UNDI'],
    'OEM/AMI': ['AmiDebug', 'AmiCpu', 'Maxsun', 'MsOc', 'OcSupport', 'AmiBoard', 'AmiTse'],
}
```

## EFI GUID 速查表

BIOS 安全分析中重要的 GUID：

```
# 证书相关
CERT_X509_GUID:     A159C0A5-E494-4AA7-87B5-AB155C2BF072
CERT_SHA256_GUID:   2616C4C1-4C50-4092-ACA9-41F936934328

# Secure Boot 变量
IMAGE_SECURITY_DATABASE (db/dbx): CBB219D7-3A3D-4596-A3BC-DAD00E67656F
GLOBAL_VARIABLE (PK/KEK):         61DFE48B-CA93-11D2-AA0D-00E098032B8C

# LZMA 压缩
LZMA_CUSTOM_DECOMPRESS: EE4E5898-3914-4259-9D6E-DC7BD79403CF

# 固件文件系统
FFS1: 7A9354D9-0468-444A-81CE-0BF617D890DF
FFS2: 8C8CE578-8A3D-4F1C-9935-896185C32DD3
FFS3: 5473C07A-3DCB-4DCA-BD6F-1E9689E7349A
NVRAM_EVSA: FFF12B8D-7696-4C8B-A985-2747075B4F50

# AMI NVRAM
NVAR: CEF5B9A3-476D-497F-9FDC-E98143E0422C
```

## 工具依赖

必需的 Python 包：
```bash
pip install uefi_firmware
```

`uefi_firmware` 提供：`FirmwareVolume`、`FirmwareFile`、`FirmwareFileSystem`、`CompressedSection`、`EFI_FILE_TYPES`、`EFI_SECTION_TYPES`、`search_firmware_volumes`、`sguid`、`LzmaDecompress`、`TianoDecompress`、`EfiDecompress`

使用的 Python 内置模块：`struct`、`lzma`、`zlib`、`re`、`hashlib`、`datetime`

## 输出目录组织

始终创建以下目录：
- `output/` —— 解压后文件、模块列表、提取的微码、证书审计结果
- `report/` —— 最终分析报告（纯文本 + Word）
- `scripts/` —— 分析脚本（可复用）

## 报告结构规范

编写最终报告时，**严格分离**两类问题：
1. **已确认的问题** —— 可通过静态扫描、版本比对、CVE 匹配验证的
2. **待运行时检验的可能问题** —— 需要运行时验证的（SMRAM 锁、SPI 寄存器状态、SMM 输入验证）

两类问题不得混写在同一个章节中。

报告章节建议：
1. 项目概述
2. 分析方法与工具链
3. BIOS 基本信息（供应商、平台、CSME 版本等）
4. 固件解包统计
5. 微码版本审计
6. 已确认的安全问题
7. 待运行时检验的可能问题
8. 附加观察
9. Secure Boot 证书与 DBX 审计
10. CSME 及其他子固件安全审计
11. 关键安全模块列表
12. 输出文件清单
13. 结语

使用严重级别：HIGH（高危）、MEDIUM（中危）、LOW（低危）
