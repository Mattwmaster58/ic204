#!/usr/bin/env python3
"""
Comprehensive table of extraction differences between robust_extract.py and extract_salts_v5.py
for consequential UDS-mapped levels (1, 3, 5, 7).
"""

import os
import sys
sys.path.insert(0, '.')
from robust_extract import extract_salts_from_cff as extract_old
from extract_salts_v5 import extract_salts_from_cff as extract_new
from ic204_seedkey import SALT_TABLES

CFF_DIR = '/home/mattm/Downloads/CFF - for programming/KI/'

# UDS mapping
UDS_MAP = {1: 0x01, 3: 0x03, 5: 0x09, 7: 0x0D}
CONSEQUENTIAL_LEVELS = [1, 3, 5, 7]

cff_files = sorted([f for f in os.listdir(CFF_DIR) if f.upper().endswith('.CFF')])

print('=' * 160)
print('COMPREHENSIVE EXTRACTION DIFFERENCES - Consequential UDS Levels (1, 3, 5, 7)')
print('=' * 160)
print()
print('Legend:')
print('  FIXED:      v5 corrects a bug in robust_extract')
print('  REGRESSION:  v5 breaks something that worked in robust_extract')
print('  BOTH_FAIL:   Both scripts fail (same or different values)')
print()
print('-' * 160)
print(f'{"SW Version":<15} {"Switch":<14} {"Lvl":<4} {"UDS":<6} {"Old Salt":<20} {"New Salt":<20} {"Expected":<20} {"Status":<12}')
print('-' * 160)

detailed_diffs = []

for fname in cff_files:
    sw_version = fname.split('_')[0]
    filepath = os.path.join(CFF_DIR, fname)

    if sw_version not in SALT_TABLES:
        continue

    # Get function offset
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        func_start = data.find(bytes([0x13, 0x02, 0x06, 0xD8, 0x87, 0x00, 0x5F, 0x3A, 0x66, 0x3A]))
        func_offset = f'0x{func_start:06X}' if func_start >= 0 else 'N/A'
    except:
        func_offset = 'N/A'

    try:
        old_salts, _ = extract_old(filepath)
        new_salts, _ = extract_new(filepath)
    except Exception as e:
        continue

    for level in CONSEQUENTIAL_LEVELS:
        if level not in SALT_TABLES[sw_version]:
            continue

        expected = SALT_TABLES[sw_version][level]
        old_hex = ''.join(f'{b:02X}' for b in old_salts[level]) if level in old_salts else 'MISSING'
        new_hex = ''.join(f'{b:02X}' for b in new_salts[level]) if level in new_salts else 'MISSING'
        exp_hex = ''.join(f'{b:02X}' for b in expected)

        old_match = old_hex == exp_hex
        new_match = new_hex == exp_hex

        if old_match != new_match:
            uds = f'0x{UDS_MAP[level]:02X}' if level in UDS_MAP else 'N/A'

            if not old_match and not new_match:
                if old_hex == new_hex:
                    status = 'BOTH_FAIL_SAME'
                else:
                    status = 'BOTH_FAIL_DIFF'
            elif not old_match and new_match:
                status = 'FIXED'
            else:  # old_match and not new_match
                status = 'REGRESSION'

            detailed_diffs.append((sw_version, func_offset, level, uds, old_hex, new_hex, exp_hex, status))

# Sort by SW version
detailed_diffs.sort()

for sw, offset, level, uds, old_hex, new_hex, exp_hex, status in detailed_diffs:
    print(f'{sw:<15} {offset:<14} L{level}  {uds:<6}  {old_hex:<20}  {new_hex:<20}  {exp_hex:<20}  {status}')

print()
print('=' * 160)
print('SUMMARY')
print('=' * 160)

# Count by status
fixed_count = sum(1 for _, _, _, _, _, _, _, s in detailed_diffs if s == 'FIXED')
regression_count = sum(1 for _, _, _, _, _, _, _, s in detailed_diffs if s == 'REGRESSION')
both_fail_count = sum(1 for _, _, _, _, _, _, _, s in detailed_diffs if s.startswith('BOTH_FAIL'))

print(f'FIXED:      {fixed_count} extraction(s)')
print(f'REGRESSION:  {regression_count} extraction(s)')
print(f'BOTH FAIL:   {both_fail_count} extraction(s)')

print()
print('Details:')

for sw, offset, level, uds, old_hex, new_hex, exp_hex, status in detailed_diffs:
    if status == 'FIXED':
        print(f'  {sw} L{level} (UDS 0x{UDS_MAP[level]:02X}): {old_hex} → {new_hex} ✓')
    elif status == 'REGRESSION':
        # Find which byte differs
        diff_bytes = []
        for i in range(8):
            if old_hex[i*2:i*2+2] != new_hex[i*2:i*2+2]:
                diff_bytes.append(f'[{i}]{old_hex[i*2:i*2+2]}→{new_hex[i*2:i*2+2]}')
        print(f'  {sw} L{level} (UDS 0x{UDS_MAP[level]:02X}): {old_hex} → {new_hex} ✗')
        print(f'    Expected: {exp_hex}')
        print(f'    Diffs: {", ".join(diff_bytes)}')
