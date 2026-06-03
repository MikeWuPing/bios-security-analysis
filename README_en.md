# BIOS Security Analysis — Claude Code Skill

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-orange)](https://claude.ai/code)
[中文](README.md)

A Claude Code skill for comprehensive UEFI/BIOS firmware security vulnerability analysis. Distills years of BIOS security research expertise into reusable AI capabilities — covering everything from firmware image parsing and deep decompression through microcode extraction, certificate auditing, to final report generation.

## When to Use

Just say "analyze this BIOS image for security vulnerabilities" in Claude Code. The skill loads automatically, bringing the complete methodology into context.

## Capabilities

| Module | What It Does |
|--------|-------------|
| **Flash Layout Parsing** | Intel Flash Descriptor structure analysis — identifies BIOS, ME, GbE, and other flash regions |
| **Vendor Identification** | Identifies the original IBV (AMI/Insyde/Phoenix) via GUIDs, copyright strings, and Setup IFR architecture |
| **Firmware Volume Enumeration** | Recursive FV/FFS/Section parsing via `uefi_firmware` — decomposes to the smallest granularity |
| **LZMA Deep Decompression** | Identifies `EE4E5898` custom LZMA GUID, correctly computes DataOffset, parses lc/lp/pb parameters, decompresses DXE/SMM main volume using Python `lzma.FORMAT_RAW` |
| **Microcode Extraction & Audit** | FIT table parsing, 4GB address space conversion, Intel microcode header parsing, version comparison against latest Intel releases |
| **Secure Boot Certificate Audit** | X.509 DER extraction, UTCTime/GeneralizedTime date parsing, expiration checking, weak key/signature detection, test certificate detection |
| **DBX Revocation Database Audit** | Signature revocation database completeness check — compares against UEFI Forum latest revocation list |
| **CSME Version Audit** | CPD partition parsing, CSME component version extraction, cross-reference with Intel PSIRT security advisories |
| **SMM Attack Surface Analysis** | SMI Handler enumeration, SMM communication buffer assessment, SPI protection module detection, BIOS Guard verification |
| **CSM Legacy Boot Detection** | Identifies CSM modules, evaluates Secure Boot bypass risk |
| **Word Report Generation** | Strictly separates "confirmed issues" from "potential issues requiring runtime validation", outputs structured analysis report |

## File Structure

```
bios-security-analysis/
├── SKILL.md                              # Complete analysis methodology (~410 lines)
├── scripts/
│   ├── microcode_audit.py               # FIT table parsing + microcode version audit
│   ├── cert_audit.py                    # X.509 certificate extraction + dbx analysis
│   └── decompress_fv.py                # LZMA custom decompression + DXE/SMM volume parsing
└── references/
    └── csme_mc_reference.md             # CSME CVE reference table + microcode CPUID quick reference
```

## Quick Start

### Prerequisites

- [Claude Code](https://claude.ai/code) installed
- Python 3.7+ with `uefi_firmware`:

```bash
pip install uefi_firmware
```

### Install the Skill

Clone this repository into your Claude Code skills directory:

```bash
# Linux/macOS
git clone https://github.com/<your-username>/bios-security-analysis.git \
  ~/.claude/skills/bios-security-analysis

# Windows
git clone https://github.com/<your-username>/bios-security-analysis.git \
  %USERPROFILE%\.claude\skills\bios-security-analysis
```

Or simply copy the entire directory to `~/.claude/skills/bios-security-analysis/`.

### Usage

In any Claude Code session, simply say:

```
Analyze this BIOS image for security vulnerabilities: bin/some_bios.rom
```

The skill triggers automatically and runs the full analysis pipeline, producing a structured Word report.

You can also target specific analysis areas:

- "Extract and audit the microcode versions in this BIOS"
- "Check if any Secure Boot certificates in this firmware are expired"
- "Analyze the SMM attack surface of this image"

## Analysis Pipeline

```
BIOS Image
  ├── Flash Descriptor → Region layout identification
  ├── Vendor Identification (IBV) → Known CVE lookup
  ├── FV/FFS Enumeration → PEI module extraction
  ├── LZMA Deep Decompression → DXE/SMM module extraction (714 modules)
  ├── FIT Table Parsing → Microcode extraction & version comparison
  ├── X.509 Certificate Parsing → Expiration / weak key / test cert detection
  ├── DBX Revocation Check → Known bootkit coverage assessment
  ├── CSME Version Audit → Intel PSIRT cross-reference
  ├── SMM / CSM / SPI Attack Surface Analysis
  └── Structured Report → Word document output
```

## Real-World Case Study

This skill was distilled from a complete analysis of the following firmware:

- **Maxsun MS-Terminator B760M D5** — BIOS E2.6D (2026-03-11)
- AMI Aptio V, Intel B760 / Alder Lake + Raptor Lake
- CSME 16.1.40.2765
- Decomposed into 186 PEI + 714 DXE/SMM modules
- Discovered outdated microcode, CSM enabled, empty DBX, and other critical issues

See the case study repository for the full analysis report.

## Known Limitations

- **Static Analysis Only**: Flash lock registers (BIOSWE, BLE, FLOCKDN) and SMRAM lock state must be verified at runtime via tools like chipsec
- **CSME Patch Status**: Cannot determine from static image whether CSME patches have been applied — requires Intel CSMEVDT at runtime
- **Certificate Source**: Analyzes default certificates embedded in DXE modules; actual runtime PK/KEK/db/dbx values stored in NVRAM require `dmpstore` verification
- **Encrypted Regions**: Some data within the CSME region may be encrypted

## Contributing

Issues and Pull Requests are welcome. If you discover new analysis techniques or vulnerability patterns during real-world firmware analysis, contributions to SKILL.md or scripts are appreciated.

## License

MIT License — see [LICENSE](LICENSE)

---

*This skill is distilled from hands-on BIOS security analysis experience, aiming to make AI-assisted firmware security research more efficient and systematic.*
