#!/usr/bin/env python3
"""Final microcode extraction and version audit from FIT table."""
import struct, sys, io, os
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

with open('bin/MSTerminatorB760MD5_E2.6D_03112026.ROM', 'rb') as f:
    data = f.read()

# FIT at 0xB90100, entries start at 0xB90110
# FIT addresses use 4GB memory map: flash_base = 0xFF000000 for 16MB flash
FLASH_BASE = 0xFF000000

def parse_date(date_raw):
    """Parse Intel microcode date field (0xYYYYMMDD format)."""
    # The date is stored as 0xYYYYMMDD in BCD, but some use plain hex
    # Standard format: YYYYMMDD
    y = (date_raw >> 16) & 0xFFFF
    m = (date_raw >> 8) & 0xFF
    d = date_raw & 0xFF
    # Some MC use high bits differently, but 0x2012 is typical for year
    return y, m, d

def read_mc(flash_off):
    """Read Intel microcode header at flash offset."""
    if flash_off + 48 > len(data):
        return None
    hdr = struct.unpack_from('<IIIII', data, flash_off)
    if hdr[0] != 1:  # Not microcode header
        return None
    # Read extended header
    data_size = struct.unpack_from('<I', data, flash_off + 28)[0]
    total_size = struct.unpack_from('<I', data, flash_off + 32)[0]
    if total_size < 0x100 or total_size > 0x100000:
        return None

    cpuid = hdr[3]
    rev = hdr[1]
    y, m, d = parse_date(hdr[2])

    # Additional CPUID from extended header
    # MC Extended header has Platform ID flags at offset 40
    platform_mask = struct.unpack_from('<I', data, flash_off + 40)[0]

    return {
        'cpuid': cpuid,
        'revision': rev,
        'year': y, 'month': m, 'day': d,
        'data_size': data_size,
        'total_size': total_size,
        'platform_mask': platform_mask,
        'flash_offset': flash_off,
    }

# Read all FIT entries
print("=" * 60)
print("FIT TABLE ENTRY ANALYSIS")
print("=" * 60)

fit_addr = 0xB90100
entry_start = fit_addr + 0x10
mc_patches = []
acm_entries = []

for i in range(0, 0x200, 16):
    off = entry_start + i
    if off + 16 > len(data):
        break
    addr_val = struct.unpack_from('<Q', data, off)[0]
    size_bytes = data[off+8:off+11]
    version = struct.unpack_from('<H', data, off+12)[0]
    type_cv = data[off+14]
    entry_type = type_cv & 0x7F
    cv = (type_cv >> 7) & 0x01
    if addr_val == 0 or addr_val == 0xFFFFFFFFFFFFFFFF:
        continue

    flash_off = addr_val - FLASH_BASE if addr_val > FLASH_BASE else addr_val

    if entry_type == 0x01:  # Microcode
        mc = read_mc(flash_off)
        if mc:
            mc_patches.append(mc)
            print("MC #{}: 0x{:06X} CPUID=0x{:08X} Rev=0x{:08X} Date={:04d}-{:02d}-{:02d} Size=0x{:X}".format(
                len(mc_patches), flash_off, mc['cpuid'], mc['revision'],
                mc['year'], mc['month'], mc['day'], mc['total_size']))

    elif entry_type == 0x02:  # Startup ACM (Authenticated Code Module)
        acm_entries.append((flash_off, version))
        print("ACM: 0x{:06X} Ver=0x{:04X}".format(flash_off, version))

# Read ACM header
print("\n" + "=" * 60)
print("ACM (BOOT GUARD) ANALYSIS")
print("=" * 60)
for acm_off, acm_ver in acm_entries:
    if acm_off + 64 > len(data):
        continue
    acm_hdr = data[acm_off:acm_off+0x80]
    # ACM header structure
    module_type = struct.unpack_from('<H', acm_hdr, 0)[0]
    module_subtype = struct.unpack_from('<H', acm_hdr, 2)[0]
    header_len = struct.unpack_from('<I', acm_hdr, 4)[0]
    acm_size = struct.unpack_from('<I', acm_hdr, 24)[0]
    flags = struct.unpack_from('<H', acm_hdr, 30)[0]

    acm_types = {0: 'BIOS ACM', 2: 'SINIT ACM'}
    acm_subtypes = {0: 'Measured Boot', 1: 'Verified Boot'}

    print("ACM @ 0x{:06X}:".format(acm_off))
    print("  ModuleType: {} ({})".format(module_type, acm_types.get(module_type, 'Unknown')))
    print("  ModuleSubType: {} ({})".format(module_subtype, acm_subtypes.get(module_subtype, 'Unknown')))
    print("  HeaderLen: 0x{:X}".format(header_len))
    print("  Size: 0x{:X} ({:.0f}KB)".format(acm_size, acm_size/1024))
    print("  Flags: 0x{:04X}".format(flags))

    # Check debug flag (bit 0 = Production, bit 1 = Pre-production)
    if flags & 0x01:
        print("  -> PRE-PRODUCTION/DEBUG ACM! (bit 0 set)")
    else:
        print("  -> Production ACM")

# Microcode version audit
print("\n" + "=" * 60)
print("MICROCODE VERSION AUDIT")
print("=" * 60)

gen_info = {
    0x00090672: ('Alder Lake-S (12th Gen, non-K)', 0x42E, '2024-11'),
    0x00090671: ('Alder Lake-S (12th Gen, K-series)', 0x42E, '2024-11'),
    0x00090675: ('Alder Lake-S (12th Gen)', 0x42E, '2024-11'),
    0x000906A0: ('Alder Lake-S (12th Gen)', 0x42E, '2024-11'),
    0x000906A3: ('Alder Lake-S (12th Gen)', 0x42E, '2024-11'),
    0x000906A4: ('Alder Lake-S (12th Gen)', 0x42E, '2024-11'),
    0x000B0670: ('Raptor Lake-S (13th/14th Gen, B0)', 0x12A, '2025-03'),
    0x000B0671: ('Raptor Lake-S (13th/14th Gen)', 0x12A, '2025-03'),
    0x000B06E0: ('Raptor Lake-S (13th/14th Gen)', 0x128, '2025-01'),
    0x000B06F0: ('Raptor Lake-S (13th/14th Gen, H0)', 0x12A, '2025-03'),
    0x000B06F2: ('Raptor Lake-S (13th/14th Gen, 6P+8E)', 0x12A, '2025-03'),
    0x000B06F5: ('Raptor Lake-S (13th/14th Gen)', 0x128, '2025-01'),
}

print("\nFound microcode patches:")
for mc in sorted(mc_patches, key=lambda x: x['cpuid']):
    cpuid = mc['cpuid']
    cpu_sig = cpuid & 0xFFFFFFF0
    info = gen_info.get(cpu_sig, ('Unknown CPU', 0, '?'))

    status = 'CURRENT'
    if info[1] > 0:
        if mc['revision'] < info[1]:
            status = 'OUTDATED - VULNERABLE'
        elif mc['revision'] > info[1]:
            status = 'NEWER than known latest'

    print("\n  CPUID: 0x{:08X} ({})".format(cpuid, info[0]))
    print("  Current Revision: 0x{:08X} (build date: {:04d}-{:02d}-{:02d})".format(
        mc['revision'], mc['year'], mc['month'], mc['day']))
    print("  Size: 0x{:X} ({}KB)".format(mc['total_size'], mc['total_size']//1024))
    print("  Platform Mask: 0x{:08X}".format(mc['platform_mask']))
    print("  Flash Offset: 0x{:06X}".format(mc['flash_offset']))

    if info[1] > 0:
        print("  Latest Known: 0x{:08X} ({})".format(info[1], info[2]))
        print("  Status: [{}]".format(status))

if not mc_patches:
    print("  No microcode found!")

# Save patches
os.makedirs('output', exist_ok=True)
for mc in mc_patches:
    if mc['flash_offset'] + mc['total_size'] <= len(data):
        patch = data[mc['flash_offset']:mc['flash_offset']+mc['total_size']]
        fname = 'output/mc_cpu{:08X}_rev{:08X}.bin'.format(mc['cpuid'], mc['revision'])
        with open(fname, 'wb') as f:
            f.write(patch)

print("\nMicrocode patches saved to output/mc_*.bin")
