# Intel CSME 安全公告参考

## ADL 平台 (Alder Lake) —— CSME 16.1.x

| 公告编号 | 日期 | 影响版本 | CVSS | 描述 |
|----------|------|----------|------|------|
| INTEL-SA-00847 | 2024-03 | CSME 16.1 特定版本 | 8.8 | 多个漏洞 |
| INTEL-SA-00783 | 2023-08 | CSME 16.1.30 及更早 | 8.2 | 输入验证不足 |
| INTEL-SA-00614 | 2022-11 | 多个 CSME 16.1 版本 | 7.8 | 多个漏洞（含权限提升） |
| CVE-2023-25775 | 2023-08 | CSME 16.1 | 7.5 | 不当访问控制 |
| CVE-2023-22444 | 2023-08 | CSME 16.1 | 7.5 | 不当访问控制 |
| CVE-2022-36392 | 2022-08 | CSME 16.1 | 8.2 | 输入验证不足 |
| CVE-2022-29871 | 2022-05 | CSME 16.1 | 7.8 | 权限提升漏洞 |
| CVE-2022-38090 | 2022-11 | CSME 16.1 | 7.5 | 不当初始化 |

## CSME 组件命名

| 组件 | 典型版本范围 | 描述 |
|------|-------------|------|
| CSME ROM | 16.1.x | 管理引擎主内核 |
| PCHC | 16.1.x | PCH 配置控制器 |
| PMCP | 160.x | 电源管理控制器 |
| SPHY | 13.x | 南桥 PHY 控制器 |
| ISHC | 5.x | 集成传感器集线器控制器 |
| FTPR | 不定 | Flash Transaction Protocol Region |
| NFTP | 不定 | Non-Flash Transaction Protocol Region |

## 版本提取命令

```python
# 提取 CSME 版本字符串
for m in re.finditer(rb'PCHC(\d+\.\d+\.\d+\.\d+)', data):
    print(f"PCHC: {m.group(1).decode()}")

for m in re.finditer(rb'(16\.\d+\.\d+\.\d+)', data):
    print(f"ME 版本: {m.group(1).decode()}")
```

## 微码参考表

### Intel CPUID 家族 (12-14 代)

| CPUID | 代 | 代号 |
|-------|-----|------|
| 0x00090671 | 12 代 | Alder Lake-S (K 系列) |
| 0x00090672 | 12 代 | Alder Lake-S (非 K) |
| 0x00090675 | 12 代 | Alder Lake-S |
| 0x000906A0 | 12 代 | Alder Lake-S |
| 0x000906A3 | 12 代 | Alder Lake-S |
| 0x000906A4 | 12 代 | Alder Lake-S |
| 0x000B0670 | 13/14 代 | Raptor Lake-S B0 (8P+16E) |
| 0x000B0671 | 13/14 代 | Raptor Lake-S (8P+16E) |
| 0x000B06E0 | 13/14 代 | Raptor Lake-S |
| 0x000B06F0 | 13/14 代 | Raptor Lake-S H0 (8P+12E) |
| 0x000B06F2 | 13/14 代 | Raptor Lake-S (6P+8E) |
| 0x000B06F5 | 13/14 代 | Raptor Lake-S |

### 已知最新微码版本（截至 2025 年末）

参考：https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files

- ADL-S: Rev 0x42E（约 2024 年 11 月）
- RPL-S: Rev 0x12A（约 2025 年 3 月），可能已存在更新的内部版本
