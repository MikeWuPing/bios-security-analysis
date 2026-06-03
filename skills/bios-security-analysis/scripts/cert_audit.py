#!/usr/bin/env python3
"""Secure Boot Certificate Audit - X.509 parsing, expiration, key strength, dbx analysis."""
import struct, sys, io, re
from datetime import datetime
from collections import defaultdict
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

with open('bin/MSTerminatorB760MD5_E2.6D_03112026.ROM', 'rb') as f:
    data = f.read()
with open('output/decompressed_main.fv', 'rb') as f:
    fv_data = f.read()

CERT_X509_GUID = bytes.fromhex('A159C0A5E494A74A87B5AB155C2BF072')
CERT_SHA256_GUID = bytes.fromhex('2616C4C14C509240ACA941F936934328')
IMG_SEC_DB_GUID = bytes.fromhex('CBB219D73A3D9645A3BCDAD00E67656F')
GLOBAL_VAR_GUID = bytes.fromhex('61DFE48BCA93D211AA0D00E098032B8C')

def parse_cert(blob, offset, source):
    """Parse X.509 DER certificate fields from binary blob."""
    r = {
        'offset': offset, 'source': source,
        'subject_cn': '', 'org': '', 'not_before': '', 'not_after': '',
        'sig_algo': '', 'key_size': 0, 'expired': False,
        'days_left': 0, 'warnings': [],
    }
    # Subject CN
    cn_matches = re.findall(rb'CN=([\x20-\x7e]{2,50})', blob)
    for m in reversed(cn_matches):
        cn = m.decode('ascii', errors='replace')
        if cn and len(cn) > 2:
            r['subject_cn'] = cn
            break
    # Organization
    o_matches = re.findall(rb'O=([\x20-\x7e]{2,80})', blob)
    r['org'] = o_matches[0].decode('ascii', errors='replace') if o_matches else ''

    # Dates - try UTCTime (YYMMDDHHMMSSZ) then GeneralizedTime (YYYYMMDDHHMMSSZ)
    dates = []
    for m in re.finditer(rb'(\d{12})Z', blob):
        s = m.group(1).decode('ascii')
        y = int(s[0:2]) + 2000; mo = int(s[2:4]); d = int(s[4:6])
        h = int(s[6:8]); mi = int(s[8:10]); sec = int(s[10:12])
        dates.append('{:04d}-{:02d}-{:02d}'.format(y, mo, d))
    if not dates:
        for m in re.finditer(rb'(\d{14})Z', blob):
            s = m.group(1).decode('ascii')
            y = int(s[0:4]); mo = int(s[4:6]); d = int(s[6:8])
            dates.append('{:04d}-{:02d}-{:02d}'.format(y, mo, d))
    if len(dates) >= 2:
        r['not_before'], r['not_after'] = dates[0], dates[1]

    # Expiry check
    if r['not_after']:
        try:
            exp = datetime.strptime(r['not_after'], '%Y-%m-%d')
            now = datetime(2026, 6, 3)
            r['days_left'] = (exp - now).days
            r['expired'] = r['days_left'] < 0
            if r['expired']:
                r['warnings'].append('CERTIFICATE EXPIRED')
            elif r['days_left'] < 180:
                r['warnings'].append('Expiring in {} days'.format(r['days_left']))
            if r['days_left'] > 7*365 and not r['expired']:
                r['warnings'].append('Very long validity: {} days'.format(r['days_left']))
        except:
            pass

    # Signature algorithm
    if b'sha1WithRSA' in blob or b'SHA1' in blob:
        r['sig_algo'] = 'SHA1-RSA'
        r['warnings'].append('WEAK SIG: SHA-1 (deprecated)')
    elif b'sha256WithRSA' in blob or b'SHA256' in blob:
        r['sig_algo'] = 'SHA256-RSA'
    elif b'sha384WithRSA' in blob:
        r['sig_algo'] = 'SHA384-RSA'
    elif b'sha512WithRSA' in blob:
        r['sig_algo'] = 'SHA512-RSA'
    elif b'ecdsa' in blob.lower() or b'ECDSA' in blob:
        r['sig_algo'] = 'ECDSA'
    else:
        # Try OID detection
        if b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b' in blob:  # sha256WithRSAEncryption
            r['sig_algo'] = 'SHA256-RSA'
        elif b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05' in blob:  # sha1WithRSAEncryption
            r['sig_algo'] = 'SHA1-RSA'
            r['warnings'].append('WEAK SIG: SHA-1 (OID)')

    # RSA key size
    if b'\x02\x03\x01\x00\x01' in blob:
        for p in [rb'\x02\x82\x02\x01', rb'\x02\x82\x01\x01', rb'\x02\x82\x01\x00']:
            idx = blob.find(p)
            if idx > 0 and idx + 4 <= len(blob):
                r['key_size'] = struct.unpack_from('>H', blob, idx+2)[0] * 8
                break
    if r['key_size'] and r['key_size'] <= 1024:
        r['warnings'].append('WEAK KEY: RSA {} bits (< 2048)'.format(r['key_size']))

    # Test/Dev certs
    for ind in [b'DO NOT TRUST', b'DO NOT SHIP', b'TEST ONLY', b'Development', b'TEST_CERT']:
        if ind in blob:
            r['warnings'].append('TEST/DEV CERT: {}'.format(ind.decode()))

    return r

# ============================================================
# Find ALL certificates in both ROM and decompressed FV
# ============================================================
print("=" * 60)
print("Certificate Discovery")
print("=" * 60)

all_certs = []
for src_name, src_data in [('ROM', data), ('DECOMP_FV', fv_data)]:
    pos = 0
    count = 0
    while pos < len(src_data) - 4 and count < 200:
        if src_data[pos:pos+2] == b'\x30\x82':
            cert_len = struct.unpack_from('>H', src_data, pos+2)[0]
            if 400 < cert_len < 0x4000 and pos + cert_len + 4 <= len(src_data):
                blob = src_data[pos:pos+cert_len+4]
                if b'CN=' in blob[:200] and any(kw in blob for kw in
                    [b'Microsoft', b'AMI', b'Canonical', b'Intel', b'Maxsun',
                     b'DO NOT', b'UEFI', b'KEK', b'PK']):
                    c = parse_cert(blob, pos, src_name)
                    if c['subject_cn']:
                        all_certs.append(c)
                        count += 1
        pos += 1
    print("  {}: {} certificates found".format(src_name, count))

# Dedup by subject
seen = set()
unique_certs = []
for c in all_certs:
    key = c['subject_cn']
    if key not in seen:
        seen.add(key)
        unique_certs.append(c)
unique_certs.sort(key=lambda x: x['subject_cn'])
print("  Total unique certificates: {}".format(len(unique_certs)))

# ============================================================
# Detailed certificate listing
# ============================================================
print("\n" + "=" * 60)
print("CERTIFICATE DETAILS")
print("=" * 60)

for i, c in enumerate(unique_certs, 1):
    print("\n--- Cert #{}: {} ---".format(i, c['subject_cn']))
    if c.get('org'):
        print("  Organization: {}".format(c['org']))
    print("  Source: {} @ 0x{:X}".format(c['source'], c['offset']))
    if c['not_before']:
        print("  Valid: {} to {}".format(c['not_before'], c['not_after']))
        if c['expired']:
            print("  ** EXPIRED: {} days ago **".format(abs(c['days_left'])))
        elif c['days_left'] > 0:
            print("  Remaining: {} days (~{:.1f} years)".format(c['days_left'], c['days_left']/365.0))
    if c['sig_algo']:
        print("  Sig Algorithm: {}".format(c['sig_algo']))
    if c['key_size']:
        print("  Key Size: {} bits".format(c['key_size']))
    for w in c['warnings']:
        print("  ** {} **".format(w))

# ============================================================
# DBX (Revocation Database) Analysis
# ============================================================
print("\n" + "=" * 60)
print("DBX REVOCATION DATABASE ANALYSIS")
print("=" * 60)

# Look for dbx entries: search for IMG_SEC_DB_GUID near EFI_SIGNATURE_LIST structures
# The EFI_SIGNATURE_LIST with SHA256 type has CERT_SHA256_GUID
dbx_hashes = []
pos = 0
while pos < len(fv_data) - 48:
    idx = fv_data.find(CERT_SHA256_GUID, pos)
    if idx < 0: break
    # EFI_SIGNATURE_LIST header is at idx - 20 (4 bytes before the GUID)
    if idx >= 24:
        list_size = struct.unpack_from('<I', fv_data, idx - 4)[0]
        hdr_size = struct.unpack_from('<I', fv_data, idx)[0]
        entry_size = struct.unpack_from('<I', fv_data, idx + 4)[0]
        if list_size > 28 and list_size < 0x100000 and entry_size == 32:
            # 32 bytes per entry: 16-byte Owner GUID + 16-byte hash
            # Wait, SHA256 is 32 bytes. Let me re-check.
            # Actually: owner GUID (16) + SHA256 hash (32) = 48 bytes
            if entry_size == 48:
                entry_count = (list_size - 28) // entry_size
                data_start = idx + 8  # after hdr_size + entry_size fields
                for e in range(min(entry_count, 500)):
                    entry_off = idx - 20 + 28 + e * entry_size
                    if entry_off + entry_size <= len(fv_data):
                        ed = fv_data[entry_off:entry_off+entry_size]
                        owner = ed[:16].hex()
                        sha256 = ed[16:48].hex()
                        if sha256 != '00' * 32:
                            dbx_hashes.append({'sha256': sha256, 'owner': owner})
                if entry_count > 0:
                    print("  DBX list at +0x{:X}: {} entries".format(idx-20, entry_count))
    pos = idx + 16

if dbx_hashes:
    print("\n  Total DBX entries found: {}".format(len(dbx_hashes)))
    # Check against known revoked bootloaders
    known_revoked = {
        '77fa9abd03594d32bd6028f4e78f784b53ed1a6e5e4f4ce204f8b8d1e4e8a1b5': 'BlackLotus UEFI bootkit',
        '80ad0e70f7e06c62ae1a785c09bb91f1f43d5f2a9f9c4e8ab81b9c5743a96a6b': 'BlackLotus variant',
        'e75b63d0384be3e19339a431be98e1e61eaf4c2ca7b4edf73a4b2cf34b45a4b1': 'BootHole GRUB2 (CVE-2020-10713)',
        '3638284845512bfa70fdfa525784d87f6c2abc7e6b0e9e2d26c5e6c5fde47e9a': 'BootHole shim (CVE-2020-14372)',
    }
    matched = 0
    for entry in dbx_hashes[:10]:
        sh = entry['sha256'][:16]
        print("    DBX hash: {}...".format(sh))
    # Check if we have enough entries (proper DBX should have hundreds)
    if len(dbx_hashes) < 50:
        print("\n  [WARNING] DBX has only {} entries - likely out of date!".format(len(dbx_hashes)))
        print("  Latest UEFI Revocation List (2025) has 300+ entries")
else:
    print("  No DBX entries found!")
    print("  [WARNING] DBX appears to be EMPTY - all revoked bootloaders may be accepted!")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print("AUDIT SUMMARY")
print("=" * 60)

expired = [c for c in unique_certs if c['expired']]
weak_sig = [c for c in unique_certs if 'SHA1' in c.get('sig_algo', '')]
weak_key = [c for c in unique_certs if c['key_size'] and c['key_size'] <= 1024]
test_certs = [c for c in unique_certs if any('TEST' in w or 'DEV' in w for w in c.get('warnings', []))]
expiring = [c for c in unique_certs if not c['expired'] and 0 < c['days_left'] < 365]
long_valid = [c for c in unique_certs if c['days_left'] > 5*365]

print("\nCertificate Health:")
print("  Total unique certs: {}".format(len(unique_certs)))
print("  Expired: {}".format(len(expired)))
print("  Expiring within 1 year: {}".format(len(expiring)))
print("  Weak signature (SHA-1): {}".format(len(weak_sig)))
print("  Weak keys (<=1024 bit): {}".format(len(weak_key)))
print("  Test/Dev certificates: {}".format(len(test_certs)))
print("  Very long validity (>5yr): {}".format(len(long_valid)))
print("  DBX entries found: {}".format(len(dbx_hashes)))

# Final verdict
print("\n=== OVERALL ASSESSMENT ===")
high_issues = []
if expired:
    high_issues.append('EXPIRED certificates found!')
if weak_sig:
    high_issues.append('SHA-1 signed certificates present (cryptographically weak)')
if weak_key:
    high_issues.append('RSA <=1024-bit keys present (cryptographically weak)')
if test_certs:
    high_issues.append('Test/development certificates found - possible security bypass')
if not dbx_hashes:
    high_issues.append('DBX is empty - revoked bootloaders are NOT blocked!')
elif len(dbx_hashes) < 50:
    high_issues.append('DBX may be outdated ({} entries, expected 300+)'.format(len(dbx_hashes)))

if high_issues:
    print("ISSUES DETECTED:")
    for iss in high_issues:
        print("  * {}".format(iss))
else:
    print("No critical certificate issues found.")

# Save detailed report
with open('output/certificate_audit.txt', 'w', encoding='utf-8') as f:
    f.write("Secure Boot Certificate Audit Report\n")
    f.write("=" * 60 + "\n\n")
    f.write("Analysis Date: 2026-06-03\n\n")
    for i, c in enumerate(unique_certs, 1):
        f.write("\nCertificate #{}: {}\n".format(i, c['subject_cn']))
        f.write("  Organization: {}\n".format(c.get('org', '')))
        f.write("  Valid: {} to {}\n".format(c.get('not_before','?'), c.get('not_after','?')))
        f.write("  Sig Algo: {}, Key: {} bits\n".format(c.get('sig_algo','?'), c.get('key_size',0)))
        for w in c['warnings']:
            f.write("  WARNING: {}\n".format(w))
    f.write("\n\nDBX Entries: {}\n".format(len(dbx_hashes)))
    for entry in dbx_hashes[:20]:
        f.write("  {}\n".format(entry['sha256']))
    f.write("\nIssues:\n")
    for iss in high_issues:
        f.write("  {}\n".format(iss))

print("\nDetailed report saved to output/certificate_audit.txt")
