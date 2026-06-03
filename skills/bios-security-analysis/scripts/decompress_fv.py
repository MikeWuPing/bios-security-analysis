#!/usr/bin/env python3
"""
Deep BIOS decompression and module extraction.
Unpacks compressed FV_IMAGE sections to access DXE/SMM drivers and microcode.
"""
import struct, sys, os, json, hashlib, re, zlib, lzma, io
from collections import defaultdict

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from uefi_firmware.uefi import (
    FirmwareVolume, FirmwareFileSystem, FirmwareFile,
    EFI_FILE_TYPES, EFI_SECTION_TYPES, sguid,
    CompressedSection, decompress,
)
from uefi_firmware.efi_compressor import TianoDecompress, EfiDecompress, LzmaDecompress

ROM_PATH = "bin/MSTerminatorB760MD5_E2.6D_03112026.ROM"
with open(ROM_PATH, 'rb') as f:
    data = f.read()

decomp_cache = {}

def try_decompress(blob, depth=0):
    """Aggressively try all decompression methods."""
    key = hashlib.md5(blob[:min(128, len(blob))]).hexdigest()
    if key in decomp_cache:
        return decomp_cache[key]

    methods = [
        # (name, function, args)
        ('TianoDecompress', TianoDecompress, (blob, len(blob) * 16)),
        ('EfiDecompress', EfiDecompress, (blob, len(blob) * 16)),
        ('LzmaDecompress', LzmaDecompress, (blob, len(blob) * 16)),
    ]

    for name, func, args in methods:
        try:
            result = func(*args)
            if result and len(result) > 0:
                decomp_cache[key] = bytes(result)
                return bytes(result)
        except:
            continue

    # Try zlib
    try:
        result = zlib.decompress(blob)
        decomp_cache[key] = result
        return result
    except:
        pass

    # Try LZMA Python
    for offset in [0, 1, 2, 3, 4]:
        try:
            result = lzma.decompress(blob[offset:])
            if len(result) > 0:
                decomp_cache[key] = result
                return result
        except:
            continue

    decomp_cache[key] = None
    return None

def find_microcode(blob, source=''):
    """Find Intel microcode patches in binary blob."""
    patches = []
    pos = 0
    while pos < len(blob) - 48:
        idx = blob.find(b'\x01\x00\x00\x00', pos)
        if idx < 0:
            break
        if idx + 48 <= len(blob):
            hdr_ver = struct.unpack_from('<I', blob, idx)[0]
            update_rev = struct.unpack_from('<I', blob, idx + 4)[0]
            date = struct.unpack_from('<I', blob, idx + 8)[0]
            cpuid = struct.unpack_from('<I', blob, idx + 12)[0]
            data_size = struct.unpack_from('<I', blob, idx + 28)[0]
            total_size = struct.unpack_from('<I', blob, idx + 32)[0]

            y = (date >> 16) & 0xFFFF
            m = (date >> 8) & 0xFF
            d = date & 0xFF

            if (hdr_ver == 1 and total_size >= 0x100 and total_size < 0x10000 and
                data_size > 0 and data_size < total_size and
                cpuid > 0x1000 and cpuid != 0xFFFFFFFF and
                1990 < y < 2030 and 1 <= m <= 12 and 1 <= d <= 31):

                cpuid_str = "0x{:08X}".format(cpuid)
                rev_str = "0x{:08X}".format(update_rev)
                patches.append({
                    'cpuid': cpuid,
                    'revision': update_rev,
                    'date': '{:04d}-{:02d}-{:02d}'.format(y, m, d),
                    'total_size': total_size,
                    'source': source,
                })
        pos = idx + 4
    return patches

# ============================================================
# STEP 1: Deep decompression of MAIN_BIOS FV
# ============================================================
print("=" * 70)
print("STEP 1: Deep Decompression of Main BIOS FV")
print("=" * 70)

fv_start = 0x4F0000
fv_size = 0x6A0000
fv = FirmwareVolume(data[fv_start:fv_start+fv_size])
fv.process()

all_modules = []
nested_fvs = []

for ffs in fv.firmware_filesystems:
    ffs.process()
    for obj in ffs.objects:
        info = {
            'guid': sguid(obj.guid) if hasattr(obj, 'guid') else '',
            'type': obj.type if hasattr(obj, 'type') else 0,
            'size': obj.size if hasattr(obj, 'size') else 0,
            'ui_name': '',
            'sections': [],
            'decompressed': False,
            'nested_modules': 0,
        }
        ttype = EFI_FILE_TYPES.get(info['type'], ('?','?','UNK_0x{:02X}'.format(info['type'])))
        info['type_name'] = ttype[2]

        # Walk sections
        if hasattr(obj, 'sections'):
            for sec in obj.sections:
                sec_info = {
                    'type': sec.type if hasattr(sec, 'type') else 0,
                    'size': sec.size if hasattr(sec, 'size') else 0,
                }
                sname = EFI_SECTION_TYPES.get(sec_info['type'], 'UNK_0x{:02X}'.format(sec_info['type']))
                sec_info['type_name'] = sname

                # Get section data
                if hasattr(sec, 'data'):
                    try:
                        sec_info['data'] = bytes(sec.data)
                    except:
                        sec_info['data'] = None

                # UI section?
                if sec_info['type'] == 0x15 and sec_info.get('data'):
                    info['ui_name'] = sec_info['data'].decode('utf-16-le', errors='replace').rstrip('\x00').strip()

                # Compressed section?
                if sec_info['type'] in [0x01, 0x02, 0x03] and sec_info.get('data'):
                    decomp = try_decompress(sec_info['data'])
                    if decomp:
                        sec_info['decompressed'] = True
                        sec_info['decomp_size'] = len(decomp)
                        info['decompressed'] = True

                        # Try to parse as FV
                        try:
                            if decomp[:4] == b'\x00' * 4:
                                inner = FirmwareVolume(decomp)
                                inner.process()
                                nested_count = 0
                                for ifs in inner.firmware_filesystems:
                                    ifs.process()
                                    for iobj in ifs.objects:
                                        nested_count += 1
                                        nm = {
                                            'guid': sguid(iobj.guid) if hasattr(iobj, 'guid') else '',
                                            'type': iobj.type if hasattr(iobj, 'type') else 0,
                                            'size': iobj.size if hasattr(iobj, 'size') else 0,
                                            'ui_name': '',
                                        }
                                        t = EFI_FILE_TYPES.get(nm['type'], ('?','?','UNK'))
                                        nm['type_name'] = t[2]

                                        # Check for UI name in sections
                                        if hasattr(iobj, 'sections'):
                                            for isec in iobj.sections:
                                                if hasattr(isec, 'type') and isec.type == 0x15:
                                                    if hasattr(isec, 'data'):
                                                        try:
                                                            nm['ui_name'] = bytes(isec.data).decode('utf-16-le', errors='replace').rstrip('\x00').strip()
                                                        except:
                                                            pass

                                        nested_fvs.append(nm)
                                info['nested_modules'] = nested_count
                                inner_fv_name = 'FV_NESTED_{:04X}'.format(len(nested_fvs))
                                print("  Nested FV: {} decompressed {}->{} bytes, {} modules".format(
                                    inner_fv_name, len(sec_info['data']), len(decomp), nested_count))
                        except Exception as e:
                            print("  Nested FV parse failed: {}".format(e))
                    else:
                        print("  Compressed section 0x{:X} bytes failed to decompress".format(len(sec_info.get('data', b''))))

                info['sections'].append(sec_info)

        all_modules.append(info)

print("\nMain FV modules: {}".format(len(all_modules)))
for m in all_modules:
    if m['ui_name']:
        print("  [{}] {} size=0x{:X} nested={} decomp={}".format(
            m['type_name'], m['ui_name'], m['size'], m['nested_modules'], m['decompressed']))

print("\nNested modules count: {}".format(len(nested_fvs)))

# ============================================================
# STEP 2: Categorize all nested DXE/SMM modules
# ============================================================
print("\n" + "=" * 70)
print("STEP 2: Nested (DXE/SMM) Modules Categorization")
print("=" * 70)

by_type = defaultdict(list)
for nm in nested_fvs:
    by_type[nm['type_name']].append(nm)

for t, mods in sorted(by_type.items(), key=lambda x: -len(x[1])):
    print("  {}: {}".format(t, len(mods)))

# List all named modules
print("\n=== All Named Nested Modules ===")
named = [nm for nm in nested_fvs if nm['ui_name']]
named.sort(key=lambda x: x['ui_name'])
for nm in named:
    print("  [{:s}] {:s}".format(nm['type_name'], nm['ui_name']))

# ============================================================
# STEP 3: Security-Relevant Module Search in Nested Modules
# ============================================================
print("\n" + "=" * 70)
print("STEP 3: Security-Relevant Nested Modules")
print("=" * 70)

keywords = [
    'Smm', 'SMI', 'S3', 'BootScript', 'SecureBoot', 'Setup',
    'Tcg', 'Tpm', 'Variable', 'Auth', 'Security', 'Lock',
    'Microcode', 'CpuInit', 'PowerManagement', 'Spi', 'Flash',
    'PchInit', 'Me', 'Heci', 'Sps', 'Password', 'Usb',
    'Pci', 'Network', 'Pxe', 'Ahci', 'Raid', 'VBIOS', 'Gop',
    'Csm', 'Legacy', 'Compatibility', 'Bds', 'Ui', 'Logo',
    'Acpi', 'Tco', 'Watchdog', 'BiosGuard', 'BootGuard',
    'Overclock', 'OcSupport', 'MsOc', 'Oc', 'Memory',
    'Capsule', 'DxeCore', 'PeiCore', 'CpuPei',
    'Hsti', 'LockConfig', 'Dma', 'Tbt', 'Thunderbolt',
    'Amt', 'Hda', 'Pcie', 'Sata', 'Gbe', 'Xhci', 'Dxe', 'Pei',
    'SmmChild', 'SmmCore', 'SmmAccess', 'SmmControl',
]

found_by_kw = defaultdict(list)
for nm in named:
    ui = nm['ui_name'].lower()
    for kw in keywords:
        if kw.lower() in ui:
            found_by_kw[kw].append(nm)

for kw in sorted(found_by_kw.keys()):
    mods = found_by_kw[kw]
    print("  [{}] {} modules:".format(kw, len(mods)))
    for m in mods[:8]:
        print("    [{:s}] {:s}".format(m['type_name'], m['ui_name']))
    if len(mods) > 8:
        print("    ... and {} more".format(len(mods) - 8))

# ============================================================
# STEP 4: Microcode Search in All Decompressed Data
# ============================================================
print("\n" + "=" * 70)
print("STEP 4: Microcode Deep Search")
print("=" * 70)

all_mc = []

# Search in main ROM
mc_rom = find_microcode(data, 'ROM')
print("ROM scan: {} candidates".format(len(mc_rom)))
all_mc.extend(mc_rom)

# Search in all FVs
for fv_start, fv_sz, fv_name in [
    (0x480000, 0x30000, 'NVRAM'),
    (0x4F0000, 0x6A0000, 'MAIN'),
    (0xB90000, 0xF0000, 'B90000'),
    (0xC80000, 0xC0000, 'C80000'),
    (0xD40000, 0xB0000, 'D40000'),
    (0xDF0000, 0xBD000, 'DF0000'),
    (0xF40000, 0x10000, 'F40000'),
    (0xF50000, 0xB0000, 'F50000'),
]:
    for fv_slice in [data[fv_start:fv_start+fv_sz]]:
        mc = find_microcode(fv_slice, 'FV_{}'.format(fv_name))
        if mc:
            print("  FV_{}: {} candidates".format(fv_name, len(mc)))
            all_mc.extend(mc)

# Search for microcode signature in all decompressed sections
for m in all_modules:
    for sec in m.get('sections', []):
        if sec.get('decompressed') and sec.get('data'):
            mc = find_microcode(sec['data'], 'DECOMP_{}'.format(m.get('ui_name', '?')))
            if mc:
                print("  Decompressed {}: {} candidates".format(m.get('ui_name', '?'), len(mc)))
                all_mc.extend(mc)

# Deduplicate
seen = set()
unique_mc = []
for mc in all_mc:
    key = (mc['cpuid'], mc['revision'])
    if key not in seen:
        seen.add(key)
        unique_mc.append(mc)

unique_mc.sort(key=lambda x: (x['cpuid'], -x['revision']))
print("\nTotal unique microcode patches: {}".format(len(unique_mc)))

if unique_mc:
    gen_info = {
        (0x000B0670 & 0xFFFFFFF0): 'Raptor Lake-S B0 (8P+16E)',
        (0x000B0671 & 0xFFFFFFF0): 'Raptor Lake-S (8P+16E)',
        (0x000B06E0 & 0xFFFFFFF0): 'Raptor Lake-S',
        (0x000B06F0 & 0xFFFFFFF0): 'Raptor Lake-S H0 (8P+12E)',
        (0x000B06F2 & 0xFFFFFFF0): 'Raptor Lake-S (6P+8E)',
        (0x000B06F5 & 0xFFFFFFF0): 'Raptor Lake-S',
        (0x00090671 & 0xFFFFFFF0): 'Alder Lake-S (K)',
        (0x00090672 & 0xFFFFFFF0): 'Alder Lake-S (non-K)',
        (0x00090675 & 0xFFFFFFF0): 'Alder Lake-S',
        (0x000906A0 & 0xFFFFFFF0): 'Alder Lake-S',
        (0x000906A3 & 0xFFFFFFF0): 'Alder Lake-S',
        (0x000906A4 & 0xFFFFFFF0): 'Alder Lake-S',
        (0x000A0670 & 0xFFFFFFF0): 'Alder Lake-S (PCH?)',
    }

    last_gen = None
    for mc in unique_mc:
        gen = gen_info.get(mc['cpuid'] & 0xFFFFFFF0, 'Other')
        if gen != last_gen:
            print("  [{}]".format(gen))
            last_gen = gen
        print("    CPUID=0x{:08X} Rev=0x{:08X} Date={} Size=0x{:X}".format(
            mc['cpuid'], mc['revision'], mc['date'], mc['total_size']))
else:
    print("  No microcode found in decompressed areas.")
    print("  Microcode is likely stored in the FIT (Firmware Interface Table) at the top of the flash.")
    print("  Let's check the FIT table...")

    # Look for FIT at top of BIOS region
    # FIT signature: '_FIT_ ' at a 16-byte aligned address in the top 16MB
    fit_positions = []
    for addr in range(0, len(data) - 16, 16):
        if data[addr:addr+8] == b'_FIT_   ':
            fit_positions.append(addr)

    if fit_positions:
        for fit_addr in fit_positions:
            print("  FIT table found at 0x{:08X}".format(fit_addr))
            # Parse FIT entries
            fit_data = data[fit_addr:fit_addr+0x100]
            for i in range(0, min(64, len(fit_data)), 16):
                entry = struct.unpack_from('<QQ', fit_data, i)
                addr_val = entry[0]
                type_val = entry[1] & 0x7F
                ver = (entry[1] >> 16) & 0xFFFF
                if addr_val == 0 or addr_val == 0xFFFFFFFFFFFFFFFF:
                    continue
                entry_types = {
                    0x00: 'HEADER', 0x01: 'MICROCODE', 0x02: 'STARTUP_ACM',
                    0x07: 'BIOS_STARTUP_MODULE', 0x08: 'TPM_POLICY',
                    0x09: 'BIOS_POLICY', 0x0A: 'TXT_POLICY',
                    0x0B: 'KEY_MANIFEST', 0x0C: 'BOOT_POLICY',
                    0x0D: 'CSME', 0x10: 'TXT_BIOS', 0x7F: 'SKIP'
                }
                etype = entry_types.get(type_val, 'UNKNOWN_0x{:02X}'.format(type_val))
                if etype in ['MICROCODE', 'HEADER'] or 'ACM' in etype:
                    print("    Entry {}: Type={} ({}) Addr=0x{:016X} Ver=0x{:04X}".format(
                        i//16, type_val, etype, addr_val, ver))
    else:
        print("  No FIT table found either.")

# ============================================================
# STEP 5: Secure Boot Deep Analysis
# ============================================================
print("\n" + "=" * 70)
print("STEP 5: Secure Boot Deep Dive")
print("=" * 70)

# NVRAM at 0x480000 - this contains Secure Boot variables
nvram_data = data[0x480000:0x480000+0x30000]

# Check NVRAM for Secure Boot variables
sb_vars = {}
for var_name in [b'PK', b'KEK', b'db', b'dbx', b'SetupMode', b'SecureBoot',
                  b'AuditMode', b'DeployedMode', b'dbt', b'dbr']:
    idx = nvram_data.find(var_name + b'\x00')
    if idx >= 0:
        sb_vars[var_name.decode('ascii')] = idx
        print("  {} variable entry @ 0x{:05X} in NVRAM".format(var_name.decode('ascii'), idx))

# Find X.509 certificates by DER structure
cert_starts = []
for m in re.finditer(rb'\x30\x82', data):
    if m.start() > 0:
        cert_starts.append(m.start())

print("\n  X.509 DER certificate positions found: {}".format(len(cert_starts)))

# Try to parse some certificates to identify them
for pos in cert_starts[:5]:
    chunk = data[pos:pos+20]
    print("    0x{:08X}: {}".format(pos, chunk.hex()))

# ============================================================
# STEP 6: Key Findings Summary
# ============================================================
print("\n" + "=" * 70)
print("STEP 6: Analysis Summary")
print("=" * 70)

# Count by phase
pei_count = 100  # from previous scan
nested_count = len(nested_fvs)
total_modules = pei_count + nested_count

print("  Total PEI modules: {}".format(pei_count))
print("  Total nested (DXE/SMM) modules: {}".format(nested_count))
print("  Overall modules identified: {}".format(total_modules))
print("  Microcode patches found: {}".format(len(unique_mc)))
print("  X.509 certificates: {}".format(len(cert_starts)))

# Count SMM modules from named nested
smm_named = [nm for nm in named if 'smm' in nm['ui_name'].lower()]
print("  SMM-related modules (by name): {}".format(len(smm_named)))
for sm in smm_named:
    print("    [{:s}] {:s}".format(sm['type_name'], sm['ui_name']))

print("\nDone.")
