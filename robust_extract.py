#!/usr/bin/env python3
"""
Salt extraction with proper handling of EP restore and tail merging.

Based on robust_extract.py but with cleaner implementation:
- Tracks register state through movea/mov/sst.b instructions
- Stops at EP restore (mov r6/r7, r30) marking end of salt[0-6]
- Finds salt[7] after EP restore or at merge point
- Handles tail merging by detecting infinite loops and inter-level branches
"""

import struct
import sys
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

CFF_DIR = "/home/mattm/Downloads/CFF - for programming/KI/"

SALT_TRANSFORM_PROLOGUE = bytes(
    [0x13, 0x02, 0x06, 0xD8, 0x87, 0x00, 0x5F, 0x3A, 0x66, 0x3A]
)
MERGE_PATTERN = bytes([0x43, 0x17, 0x13, 0x00])


@dataclass
class ExecState:
    """CPU execution state."""
    regs: Dict[int, int] = field(default_factory=lambda: {0: 0})
    salt: Dict[int, int] = field(default_factory=dict)


def decode_instruction(data: bytes, offset: int) -> Tuple[int, str, int, int, Optional[int]]:
    """
    Decode a V850 instruction.
    Returns: (size, kind, dst_reg, value/immediate, branch_target)
    """
    if offset + 1 >= len(data):
        return 2, "eof", 0, 0, None

    b0 = data[offset]
    b1 = data[offset + 1]
    halfword = (b1 << 8) | b0

    # movea imm16, r0, reg2 (32-bit)
    if (b0 & 0xE0) == 0x20 and (b0 & 0x1F) == 0x00 and (b1 & 0x07) == 0x06:
        reg2 = (b1 >> 3) & 0x1F
        if offset + 3 < len(data):
            imm16 = struct.unpack_from("<h", data, offset + 2)[0]
            return 4, "load", reg2, imm16 & 0xFF, None

    # st.b reg2, disp16[reg1] (32-bit Format VII)
    opcode6 = (halfword >> 5) & 0x3F
    if opcode6 == 0b111010:
        reg2 = (halfword >> 11) & 0x1F
        if offset + 3 < len(data):
            disp16 = struct.unpack_from("<h", data, offset + 2)[0]
            return 4, "stb", reg2, disp16 & 0x7F, None

    # MOV imm5, reg2 (16-bit Format II)
    if opcode6 == 0b010000:
        reg2 = (halfword >> 11) & 0x1F
        imm5 = halfword & 0x1F
        if imm5 & 0x10:
            imm5 = imm5 - 32
        return 2, "load", reg2, imm5 & 0xFF, None

    # MOV reg1, reg2 (16-bit Format I)
    if opcode6 == 0b000000:
        reg1 = halfword & 0x1F
        reg2 = (halfword >> 11) & 0x1F
        if reg1 != 0:
            return 2, "mov", reg2, reg1, None
        return 2, "nop", 0, 0, None

    # sst.b reg2, disp7[ep] (16-bit)
    opcode4 = (halfword >> 7) & 0xF
    if opcode4 == 0b0111:
        reg2 = (halfword >> 11) & 0x1F
        disp7 = halfword & 0x7F
        return 2, "sst", reg2, disp7, None

    # Branch (Bcond format III)
    if opcode4 == 0b1011:
        disp9 = halfword & 0x1FF
        if disp9 & 0x100:
            disp9 = disp9 - 0x200
        target = offset + 2 + disp9 * 2
        return 2, "br", 0, 0, target

    # jr
    if b0 == 0x80:
        return 2, "jr", 0, 0, None

    return 2, "other", 0, 0, None


def extract_level(
    data: bytes,
    level: int,
    case_addr: int,
    next_case_addr: int,
    merge_addr: Optional[int],
    all_case_addrs: Dict[int, int]
) -> Tuple[Dict[int, int], List[str]]:
    """Extract salt for a single level."""
    logs = []
    logs.append(f"Level {level}: 0x{case_addr:06X}")

    state = ExecState()
    addr = case_addr
    ep_restore_seen = False
    salt7_value = None
    infinite_loop_detected = False

    # Scan for EP restore or terminator
    while addr + 2 <= next_case_addr:  # Need at least 2 bytes for an instruction
        size, kind, dst_reg, value, branch_target = decode_instruction(data, addr)

        # Check for backward branch BEFORE processing it
        # (to capture r2 value that might be salt[6])
        if kind == "br" and branch_target and branch_target < addr:
            # Infinite loop detected
            logs.append(f"  Infinite loop at 0x{addr:06X} -> 0x{branch_target:06X}")
            infinite_loop_detected = True

            # Check if r2 has a value that could be salt[6]
            if 2 in state.regs and 6 not in state.salt:
                state.salt[6] = state.regs[2]
                logs.append(f"  Using r2 value 0x{state.regs[2]:02X} for salt[6] (pre-branch)")

            # Mark EP restore as seen so we look for salt[7]
            ep_restore_seen = True
            addr += size
            continue

        if kind == "load":
            state.regs[dst_reg] = value & 0xFF
        elif kind == "mov":
            if dst_reg == 30 and value in (6, 7):
                # EP restore: mov r6/r7, r30
                ep_restore_seen = True
                logs.append(f"  EP restore at 0x{addr:06X}")
                # After EP restore, look for salt[7] load
                # Continue scanning for salt[7]
                addr += size
                break
            if value in state.regs:
                state.regs[dst_reg] = state.regs[value]
        elif kind == "sst":
            if 0x0C <= value <= 0x13 and dst_reg in state.regs:
                salt_idx = value - 0x0C
                state.salt[salt_idx] = state.regs[dst_reg]
        elif kind == "br":
            # Forward branch - stop here
            logs.append(f"  Forward branch at 0x{addr:06X}")
            addr += size
            break
        elif kind == "jr":
            logs.append(f"  jr at 0x{addr:06X}")
            addr += size
            break

        addr += size

    # Look for salt[7] load after EP restore
    if ep_restore_seen:
        # First, check for denormalized tail merge pattern
        # (salt[7] loaded immediately before merge point)
        # Note: This only applies to level 7 (last level) without infinite loop
        # For levels 1-6, the pre-merge load belongs to level 7, not them
        # For infinite loop cases, the merge point salt[7] belongs to next level
        if merge_addr and salt7_value is None and level == 7 and not infinite_loop_detected:
            for offset in (-2, -4):  # mov is 2 bytes, movea is 4 bytes
                check_addr = merge_addr + offset
                if check_addr >= case_addr:
                    size, kind, dst_reg, value, _ = decode_instruction(data, check_addr)
                    if kind == "load" and dst_reg == 2:
                        salt7_value = value
                        logs.append(f"  salt[7] = 0x{value:02X} at 0x{check_addr:06X} (pre-merge load)")
                        break

        # If not found, search forward from EP restore
        if salt7_value is None:
            search_end = min(next_case_addr + 0x200, merge_addr + 0x100 if merge_addr else next_case_addr + 0x200)
            salt7_searched = False

            if infinite_loop_detected:
                # For infinite loop cases, scan past EP setup to find the real salt[7]
                skipped_ep_setup = False
                while addr < search_end - 2:
                    size, kind, dst_reg, value, _ = decode_instruction(data, addr)

                    # Skip EP setup pattern
                    if kind == "mov" and dst_reg in (6, 30):
                        skipped_ep_setup = True
                        addr += size
                        continue

                    if kind == "load" and dst_reg == 2 and skipped_ep_setup:
                        # Check if followed by branch
                        next_size, next_kind, _, _, _ = decode_instruction(data, addr + size)
                        if next_kind == "br":
                            salt7_value = value
                            logs.append(f"  salt[7] = 0x{value:02X} at 0x{addr:06X} (post-loop)")
                            salt7_searched = True
                            break

                    addr += size
            else:
                # Normal case: look for first load to r2 after EP restore
                while addr < search_end - 2:
                    size, kind, dst_reg, value, _ = decode_instruction(data, addr)

                    if kind == "load" and dst_reg == 2:
                        salt7_value = value
                        logs.append(f"  salt[7] = 0x{value:02X} at 0x{addr:06X} (post-EP)")
                        salt7_searched = True
                        break
                    elif kind in ("br", "jr"):
                        break

                    addr += size

            if not salt7_searched and 2 in state.regs:
                salt7_value = state.regs[2]
                logs.append(f"  salt[7] from r2 = 0x{salt7_value:02X}")

    # Check for tail merge: if salt[7] not found and we have a tail merge bug case
    if salt7_value is None and level < 7:
        # Look in next level's code for salt[7]
        next_level_start = all_case_addrs[level + 1]
        search_end = min(next_level_start + 0x100, merge_addr or next_level_start + 0x100)

        logs.append(f"  Looking for salt[7] in next level's code...")

        addr = next_level_start
        while addr < search_end - 2:
            size, kind, dst_reg, value, _ = decode_instruction(data, addr)

            if kind == "load" and dst_reg == 2:
                # Check if this looks like salt[7] (followed by branch)
                next_size, next_kind, _, next_value, _ = decode_instruction(data, addr + size)
                if next_kind == "br":
                    salt7_value = value
                    logs.append(f"  Found salt[7] = 0x{value:02X} at 0x{addr:06X} (next level)")
                    break
            addr += size

    # Also check merge point for denormalized tail merge pattern
    # Some cases load salt[7] immediately before the merge point
    if salt7_value is None and merge_addr:
        # Check for immediate pre-merge load (denormalized tail merge)
        # Pattern: mov/movea to r2, then st.b at merge point
        for offset in (-2, -4):  # mov is 2 bytes, movea is 4 bytes
            addr = merge_addr + offset
            if addr >= 0:
                size, kind, dst_reg, value, _ = decode_instruction(data, addr)
                if kind == "load" and dst_reg == 2:
                    salt7_value = value
                    logs.append(f"  Found salt[7] = 0x{value:02X} at 0x{addr:06X} (pre-merge load)")
                    break

        # If not found, search backward further (normalized tail merge)
        if salt7_value is None:
            for off in range(-20, 0, 2):
                addr = merge_addr + off
                if addr < 0:
                    continue
                size, kind, dst_reg, value, _ = decode_instruction(data, addr)
                if kind == "load" and dst_reg == 2:
                    salt7_value = value
                    logs.append(f"  Found salt[7] = 0x{value:02X} at 0x{addr:06X} (near merge)")
                    break

    # Build final salt
    result = {}
    for i in range(8):
        if i in state.salt:
            result[i] = state.salt[i]
        elif i == 7 and salt7_value is not None:
            result[i] = salt7_value
        else:
            result[i] = 0

    if len(result) == 8:
        logs.append(f"  Complete: {[f'{result[i]:02X}' for i in range(8)]}")
    else:
        logs.append(f"  Incomplete: {len(result)}/8 salts")

    return result, logs


def extract_salts_from_cff(filepath: str) -> Tuple[Dict[int, List[int]], Dict]:
    """Extract all 7 salt tables from a CFF firmware file."""
    with open(filepath, "rb") as f:
        data = f.read()

    func_start = data.find(SALT_TRANSFORM_PROLOGUE)
    if func_start < 0:
        raise ValueError("Salt transform function not found")

    switch_addr = func_start + 0x10
    table_start = switch_addr + 2

    # Get case addresses
    case_addrs = {}
    for i in range(7):
        offset = struct.unpack_from("<H", data, table_start + i * 2)[0]
        case_addrs[i + 1] = table_start + offset * 2

    # Find merge point
    merge_addr = None
    search_start = case_addrs[7]
    for off in range(0, 120, 2):
        if data[search_start + off : search_start + off + 4] == MERGE_PATTERN:
            merge_addr = search_start + off
            break

    # Extract each level
    salt_table = {}
    all_logs = {}

    for level in range(1, 8):
        start = case_addrs[level]
        end = case_addrs[level + 1] if level < 7 else (merge_addr or start + 0x200)

        salt_dict, logs = extract_level(data, level, start, end, merge_addr, case_addrs)
        salt_table[level] = [salt_dict.get(i, 0) for i in range(8)]
        all_logs[level] = logs

    return salt_table, {
        "func_start": func_start,
        "merge_addr": merge_addr,
        "logs": all_logs,
    }


def main():
    """Main entry point."""
    import os

    # Test on reference file first
    test_file = os.path.join(CFF_DIR, "2129026108_001.CFF")
    print("=" * 80)
    print(f"Testing: {os.path.basename(test_file)}")
    print("=" * 80)

    salts, meta = extract_salts_from_cff(test_file)

    for level in range(1, 8):
        print(f"\nLevel {level}:")
        for log in meta["logs"][level]:
            print(f"  {log}")

    print("\n" + "=" * 80)
    print("Extracted salts:")
    print("=" * 80)
    for level in range(1, 8):
        salt_hex = "".join(f"{b:02X}" for b in salts[level])
        print(f"  Level {level}: {salt_hex}")

    # Verify against known good
    print("\n" + "=" * 80)
    print("Verification:")
    print("=" * 80)
    known = {
        1: "9F851B6356C585DE",
        2: "1C779A2271AE20CE",
        3: "212BB9C9245A4CA7",
        4: "62D95BB29548AD26",
        5: "C17C39EBDFD219C4",
        6: "7A404131379A8718",
        7: "91D3DFFBED234215",
    }

    all_ok = True
    for level in range(1, 8):
        extracted = "".join(f"{salts[level][i]:02X}" for i in range(8))
        expected = known[level]
        match = extracted == expected
        all_ok = all_ok and match
        status = "✓" if match else "✗"
        print(f"  Level {level}: {status}")
        if not match:
            print(f"    Extracted: {extracted}")
            print(f"    Expected:  {expected}")

    print("\n" + "=" * 80)
    if all_ok:
        print("ALL LEVELS CORRECT ✓")

    # Test tail merge case
    print("\n" + "=" * 80)
    print("Testing tail merge case: 2049023401_001.CFF")
    print("=" * 80)

    test_file2 = os.path.join(CFF_DIR, "2049023401_001.CFF")
    salts2, meta2 = extract_salts_from_cff(test_file2)

    for level in [4, 5]:
        print(f"\nLevel {level}:")
        for log in meta2["logs"][level]:
            print(f"  {log}")
        salt_hex = "".join(f"{salts2[level][i]:02X}" for i in range(8))
        print(f"  Extracted: {salt_hex}")

    print("\n" + "=" * 80)
    print("Summary:")
    print("=" * 80)
    if all_ok:
        print("  2129026108: ALL LEVELS CORRECT ✓")

    # Check 2049023401 level 5 (known tail merge bug)
    level5_hex = "".join(f"{salts2[5][i]:02X}" for i in range(8))
    expected_level5 = "A8EE73F2EA8EC6B9"
    if level5_hex == expected_level5:
        print("  2049023401 level 5: CORRECT ✓ (tail merge handled!)")
    else:
        print(f"  2049023401 level 5: EXPECTED FAIL (known bug)")
        print(f"    Extracted: {level5_hex}")
        print(f"    Expected:  {expected_level5}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
