# BIOS Security Analysis — Claude Code Skill

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-orange)](https://claude.ai/code)
[English](README_en.md)

一个为 [Claude Code](https://claude.ai/code) 定制的 UEFI/BIOS 固件安全漏洞分析技能。将资深 BIOS 安全研究者积累的经验打包为可复用的 AI 能力，覆盖从固件镜像解析、深度解压、微码提取、证书审计到最终报告输出的全流程。

## 适用场景

当你需要对任意 UEFI BIOS 固件镜像进行安全评估时，只需在 Claude Code 中说一句"分析这个 BIOS 镜像的安全漏洞"，skill 便会自动加载以下全部方法论。

## 核心能力

| 模块 | 能力 |
|------|------|
| **Flash 布局解析** | Intel Flash Descriptor 结构解析，识别 BIOS/ME/GbE 等闪存区域 |
| **供应商识别** | 通过 GUID、版权字符串、Setup IFR 架构识别原始 IBV（AMI/Insyde/Phoenix） |
| **固件卷枚举** | 基于 `uefi_firmware` 的 FV/FFS/Section 递归解析，最小粒度拆分 |
| **LZMA 深度解压** | 识别 `EE4E5898` 自定义 LZMA GUID，正确计算 DataOffset、解析 lc/lp/pb 参数，使用 Python `lzma.FORMAT_RAW` 解压 DXE/SMM 主卷 |
| **微码提取与审计** | FIT 表解析、4GB 地址空间转换、Intel 微码头部解析、版本与 Intel 最新发布比对 |
| **Secure Boot 证书分析** | X.509 DER 证书提取、UTCTime/GeneralizedTime 日期解析、过期检测、弱密钥/弱签名识别、测试证书检测 |
| **DBX 吊销库审计** | 吊销签名数据库完整性检查，比对 UEFI 论坛最新吊销列表 |
| **CSME 版本审计** | CPD 分区解析、CSME 组件版本提取、与 Intel PSIRT 安全公告交叉比对 |
| **SMM 攻击面分析** | SMI Handler 枚举、SMM 通信缓冲区、SPI 保护模块、BIOS Guard 检测 |
| **CSM 遗留启动检测** | 识别 CSM 模块，评估 Secure Boot 绕过风险 |
| **Word 报告生成** | 严格分离"已确认问题"和"待运行时检验问题"，输出结构化分析报告 |

## 文件结构

```
bios-security-analysis/
├── SKILL.md                              # 完整分析方法论（中文，~410 行）
├── scripts/
│   ├── microcode_audit.py               # FIT 表解析 + 微码版本审计
│   ├── cert_audit.py                    # X.509 证书提取 + dbx 吊销库分析
│   └── decompress_fv.py                # LZMA 自定义解压 + DXE/SMM 卷解析
└── references/
    └── csme_mc_reference.md             # CSME CVE 参考表 + 微码 CPUID 速查
```

## 快速开始

### 前置条件

- [Claude Code](https://claude.ai/code) 已安装
- Python 3.7+，安装 `uefi_firmware`：

```bash
pip install uefi_firmware
```

### 安装 Skill

将本仓库克隆到 Claude Code 的 skills 目录：

```bash
# Linux/macOS
git clone https://github.com/<your-username>/bios-security-analysis.git \
  ~/.claude/skills/bios-security-analysis

# Windows
git clone https://github.com/<your-username>/bios-security-analysis.git \
  %USERPROFILE%\.claude\skills\bios-security-analysis
```

或者直接复制整个目录到 `~/.claude/skills/bios-security-analysis/`。

### 使用

在 Claude Code 会话中，直接说：

```
分析这个 BIOS 镜像的安全漏洞：bin/some_bios.rom
```

skill 会自动触发，执行完整的分析流程并生成 Word 报告。

你也可以指定具体分析方向：

- "提取这个 BIOS 里的微码并审计版本"
- "检查这个固件的 Secure Boot 证书有没有过期的"
- "分析这个镜像的 SMM 攻击面"

## 分析流程

```
BIOS 镜像
  ├── Flash Descriptor 解析 → 确定各区域布局
  ├── 供应商识别 (IBV) → 检索已知 CVE
  ├── FV/FFS 枚举 → PEI 模块提取
  ├── LZMA 深度解压 → DXE/SMM 模块提取 (714 模块)
  ├── FIT 表解析 → 微码提取与版本比对
  ├── X.509 证书解析 → 过期/弱密钥/测试证书检测
  ├── DBX 吊销库检查 → 已知 bootkit 覆盖评估
  ├── CSME 版本审计 → Intel PSIRT 交叉比对
  ├── SMM/CSM/SPI 攻击面分析
  └── 结构化报告 → Word 文档输出
```

## 实际案例

本 skill 基于对以下固件的完整分析提炼而成：

- **铭瑄 MS-Terminator B760M D5** — BIOS E2.6D (2026-03-11)
- AMI Aptio V, Intel B760 / Alder Lake + Raptor Lake
- CSME 16.1.40.2765
- 解包得到 186 PEI + 714 DXE/SMM 模块
- 发现微码过时、CSM 启用、DBX 为空等关键问题

完整分析报告见案例仓库。

## 已知局限性

- **静态分析**：Flash 锁寄存器（BIOSWE、BLE、FLOCKDN）和 SMRAM 锁状态必须通过 chipsec 等工具在运行时验证
- **CSME 补丁状态**：无法从静态镜像确定 CSME 补丁是否已应用，需 Intel CSMEVDT 运行时检测
- **证书来源**：分析的是 DXE 模块中嵌入的默认证书，实际运行时 PK/KEK/db/dbx 存储在 NVRAM，需用 `dmpstore` 验证
- **加密区域**：CSME 区域中的部分数据可能已加密

## 贡献

欢迎提交 Issue 和 Pull Request。如果你在实际固件分析中发现新的分析技巧或漏洞模式，欢迎补充到 SKILL.md 或 scripts 中。

## 许可

MIT License — 详见 [LICENSE](LICENSE)

---

*本 skill 由 BIOS 安全分析实战经验提炼而成，旨在让 AI 辅助固件安全研究变得更高效、更系统化。*
