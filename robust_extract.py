#!/usr/bin/env python3
"""
Robust salt extraction from IC204 CFF firmware files.

Handles all V850 compiler patterns for loading salt bytes:
1. movea imm16, r0, r2/r6 — 4 bytes, for any byte value
2. mov imm5, r2/r6 — 2 bytes, for small values (0-15)
3. Register reuse — sst.b without a preceding load (reuses r2/r6 from prior store)

The function structure for each switch case is:
  1. movea val, r0, r2       — load salt[0]
  2. MOV EP, r6/r7           — save EP
  3. MOV SP, EP              — set EP = SP for sst.b instructions
  4. sst.b r2, 0x0C[ep]      — store salt[0]
  5. 6 more load+store pairs for salt[1..6]
  6. MOV r6/r7, EP           — restore EP  <-- marks end of salt[0..6] region
  7. movea/mov val, r0, r2   — load salt[7]
  8. Branch to merge point (or fall-through for level 7)

Merge point: st.b r2, 0x13[r3] — store salt[7]
"""

import struct
import os
from collections import defaultdict

CFF_DIR = "/home/mattm/Downloads/CFF - for programming/KI/"

SALT_TRANSFORM_PROLOGUE = bytes(
    [0x13, 0x02, 0x06, 0xD8, 0x87, 0x00, 0x5F, 0x3A, 0x66, 0x3A]
)
MAIN_FUNC_PROLOGUE = bytes([0x11, 0x02, 0x06, 0xD8, 0x9B, 0x00, 0x07, 0xC8, 0x08, 0x10])

# Merge point instruction: st.b r2, 0x13[r3] (store salt[7] via SP)
MERGE_PATTERN = bytes([0x43, 0x17, 0x13, 0x00])

REFERENCE_SALTS = {
    1: [0x9F, 0x85, 0x1B, 0x63, 0x56, 0xC5, 0x85, 0xDE],
    2: [0x1C, 0x77, 0x9A, 0x22, 0x71, 0xAE, 0x20, 0xCE],
    3: [0x21, 0x2B, 0xB9, 0xC9, 0x24, 0x5A, 0x4C, 0xA7],
    4: [0x62, 0xD9, 0x5B, 0xB2, 0x95, 0x48, 0xAD, 0x26],
    5: [0xC1, 0x7C, 0x39, 0xEB, 0xDF, 0xD2, 0x19, 0xC4],
    6: [0x7A, 0x40, 0x41, 0x31, 0x37, 0x9A, 0x87, 0x18],
    7: [0x91, 0xD3, 0xDF, 0xFB, 0xED, 0x23, 0x42, 0x15],
}


def decode_instruction(data, offset):
    """
    Decode a V850 instruction at the given offset.
    Returns (size, effect) where effect is one of:
      ('load_reg', reg, value)   — register loaded with immediate
      ('store', reg, disp)       — sst.b or st.b reg to stack slot
      ('mov_reg', src, dst)      — mov reg1, reg2
      ('ep_restore',)            — MOV r6/r7, EP (restore element pointer)
      ('branch',)                — branch instruction
      ('other', description)     — anything else
    """
    if offset + 1 >= len(data):
        return 2, ("other", "EOF")
    b0 = data[offset]
    b1 = data[offset + 1]
    halfword = (b1 << 8) | b0

    # Check for movea imm16, r0, reg2 (32-bit instruction)
    # reg1=r0 means b0[4:0]=0, opcode movea: b0[7:5]=001, b1[2:0]=110
    if (b0 & 0x1F) == 0 and (b0 & 0xE0) == 0x20 and (b1 & 0x07) == 0x06:
        reg2 = (b1 >> 3) & 0x1F
        if offset + 3 < len(data):
            imm16 = struct.unpack_from("<h", data, offset + 2)[0]
            return 4, ("load_reg", reg2, imm16 & 0xFF)

    # Check for st.b reg2, disp16[reg1] (32-bit instruction, Format VII)
    # opcode bits[10:5] = 0b111010
    opcode6 = (halfword >> 5) & 0x3F
    if opcode6 == 0b111010:
        reg1 = halfword & 0x1F
        reg2 = (halfword >> 11) & 0x1F
        if offset + 3 < len(data):
            disp16 = struct.unpack_from("<h", data, offset + 2)[0]
            return 4, ("store", reg2, disp16 & 0x7F)

    # Check for MOV imm5, reg2 (16-bit Format II)
    # opcode = 010000
    if opcode6 == 0b010000:
        reg2 = (halfword >> 11) & 0x1F
        imm5 = halfword & 0x1F
        # Sign-extend (though all observed values are 0-15, i.e. positive)
        if imm5 & 0x10:
            imm5 = imm5 - 32
        return 2, ("load_reg", reg2, imm5 & 0xFF)

    # Check for MOV reg1, reg2 (16-bit Format I)
    # opcode = 000000
    if opcode6 == 0b000000:
        reg1 = halfword & 0x1F
        reg2 = (halfword >> 11) & 0x1F
        if reg1 != 0:
            # Detect EP restore: MOV r6/r7, r30 (EP)
            if reg2 == 30 and reg1 in (6, 7):
                return 2, ("ep_restore",)
            return 2, ("mov_reg", reg1, reg2)
        return 2, ("other", "nop")

    # Check for sst.b reg2, disp7[ep] (16-bit instruction)
    # bits[10:7] = 0111
    opcode4 = (halfword >> 7) & 0xF
    if opcode4 == 0b0111:
        reg2 = (halfword >> 11) & 0x1F
        disp7 = halfword & 0x7F
        return 2, ("store", reg2, disp7)

    # Check for branch instructions (conditional and unconditional)
    # Bcond format III: bits[10:7] = 1011
    if opcode4 == 0b1011:
        return 2, ("branch",)

    # Format VII (st/ld) and other 32-bit instructions
    if opcode6 >= 0b111000:
        return 4, ("other", f"fmt7_{opcode6:06b}")

    return 2, ("other", f"{b0:02X}{b1:02X}")


def extract_salt_case(data, case_addr, next_case_addr, merge_addr, is_last_case):
    """
    Extract the 8 salt bytes from a single switch case.

    There are two layout variants:

    Variant A (most common): salt[6] stored within the case block
      - salt[0] load + EP save + EP setup + salt[0] store
      - salt[1..6] load+store pairs (via sst.b to disp 0x0D..0x12)
      - EP restore
      - salt[7] load (movea or mov_imm)
      - branch to merge point (or fall-through for level 7)

    Variant B (shared epilogue): salt[6] store is shared with level 7
      - salt[0] load + EP save + EP setup + salt[0] store
      - salt[1..5] load+store pairs
      - salt[6] load into r2 (NO sst.b to 0x12, NO EP restore)
      - branch to shared epilogue at merge-8
      - shared epilogue: sst.b r2,0x12[ep] + EP restore + movea salt[7] + st.b merge

    Merge point: st.b r2, 0x13[r3] (store salt[7])

    Note: r0 is always 0 in V850. The compiler uses sst.b r0, disp[ep] for salt bytes = 0.
    """
    regs = {0: 0}  # r0 is always 0 in V850
    stores = {}  # disp -> value (byte)
    phase = 1  # 1 = scanning salt[0..6], 2 = scanning for salt[7]
    salt7_value = None

    i = 0
    max_scan = (merge_addr + 4 if is_last_case else next_case_addr) - case_addr
    while i < max_scan:
        abs_addr = case_addr + i
        size, effect = decode_instruction(data, abs_addr)

        if phase == 1:
            if effect[0] == "load_reg":
                _, reg, val = effect
                regs[reg] = val & 0xFF
            elif effect[0] == "mov_reg":
                _, src_reg, dst_reg = effect
                if src_reg in regs:
                    regs[dst_reg] = regs[src_reg]
            elif effect[0] == "store":
                _, reg, disp = effect
                if 0x0C <= disp <= 0x12 and reg in regs:
                    stores[disp] = regs[reg]
            elif effect[0] == "ep_restore":
                # Variant A: transition to phase 2
                phase = 2
            elif effect[0] == "branch":
                # Variant B: branch to shared epilogue before EP restore
                # salt[6] = current r2 (carried to shared sst.b r2, 0x12[ep])
                if 0x12 not in stores and 2 in regs:
                    stores[0x12] = regs[2]
                # salt[7] is loaded by the movea at merge_addr - 4
                _sz, eff = decode_instruction(data, merge_addr - 4)
                if eff[0] == "load_reg":
                    stores[0x13] = eff[2] & 0xFF
                break
        elif phase == 2:
            if effect[0] == "load_reg":
                _, reg, val = effect
                regs[reg] = val & 0xFF
                salt7_value = val & 0xFF
            elif effect[0] == "store":
                _, reg, disp = effect
                if disp == 0x13 and reg in regs:
                    stores[0x13] = regs[reg]
                    break
            elif effect[0] == "branch":
                if salt7_value is not None:
                    stores[0x13] = salt7_value
                break

        i += size

    # For the last case (level 7) with salt[7] == salt[6], the compiler may skip
    # the salt[7] load and just fall through to the merge point with r2 still
    # holding the salt[6] value.
    if 0x13 not in stores and 2 in regs:
        stores[0x13] = regs[2]

    # Build salt array from stores
    salt = []
    for disp in range(0x0C, 0x14):
        salt.append(stores.get(disp))

    return salt


def find_merge_point(data, func_start, case_addrs):
    """Find the merge point (st.b r2, 0x13[r3]) after the last case."""
    # Search from the last case start forward
    search_start = case_addrs[-1]
    for off in range(0, 120, 2):
        if data[search_start + off : search_start + off + 4] == MERGE_PATTERN:
            return search_start + off
    return None


def extract_salts_from_cff(filepath):
    """Extract salt table from a CFF firmware file."""
    with open(filepath, "rb") as f:
        data = f.read()

    func_start = data.find(SALT_TRANSFORM_PROLOGUE)
    if func_start < 0:
        return None, None

    # Find main function too
    main_start = data.find(MAIN_FUNC_PROLOGUE)

    switch_addr = func_start + 0x10
    table_start = switch_addr + 2

    case_addrs = []
    for i in range(7):
        off = struct.unpack_from("<H", data, table_start + i * 2)[0]
        case_addrs.append(table_start + off * 2)

    merge_addr = find_merge_point(data, func_start, case_addrs)
    if merge_addr is None:
        return None, None

    salt_table = {}
    for case_idx in range(7):
        level = case_idx + 1
        is_last = case_idx == 6
        next_case = case_addrs[case_idx + 1] if case_idx < 6 else merge_addr + 4
        salt = extract_salt_case(
            data, case_addrs[case_idx], next_case, merge_addr, is_last
        )
        salt_table[level] = salt

    # Extract function bodies for comparison
    st_body = data[func_start : func_start + 0x342]
    mf_body = data[main_start : main_start + 0x31C] if main_start >= 0 else None

    return salt_table, {
        "func_start": func_start,
        "main_start": main_start,
        "merge_addr": merge_addr,
        "st_body": st_body,
        "mf_body": mf_body,
    }


def main():
    cff_files = sorted([f for f in os.listdir(CFF_DIR) if f.upper().endswith(".CFF")])

    print(f"Scanning {len(cff_files)} CFF files with robust salt extraction")
    print("=" * 90)

    all_results = {}
    for fname in cff_files:
        filepath = os.path.join(CFF_DIR, fname)
        salt_table, meta = extract_salts_from_cff(filepath)
        if salt_table is not None:
            all_results[fname] = (salt_table, meta)

    print(f"\nFound {len(all_results)} files with the algorithm\n")

    # Verify reference file
    ref_salts = all_results.get("2129026108_001.CFF", (None, None))[0]
    if ref_salts:
        print("Reference verification (2129026108):")
        all_ok = True
        for level in range(1, 8):
            match = ref_salts[level] == REFERENCE_SALTS[level]
            status = "✓" if match else "✗"
            print(
                f"  Level {level}: {[f'0x{b:02X}' for b in ref_salts[level]]} {status}"
            )
            if not match:
                all_ok = False
                print(f"    Expected: {[f'0x{b:02X}' for b in REFERENCE_SALTS[level]]}")
        print(f"  {'ALL OK' if all_ok else 'MISMATCH!'}\n")

    # Check for any incomplete extractions (None values)
    print("Extraction completeness:")
    incomplete = []
    for fname, (salt_table, meta) in sorted(all_results.items()):
        for level in range(1, 8):
            salt = salt_table.get(level, [])
            if salt and any(b is None for b in salt):
                nones = [i for i, b in enumerate(salt) if b is None]
                incomplete.append((fname, level, nones))
                print(f"  {fname} level {level}: missing bytes at indices {nones}")

    if not incomplete:
        print("  All salt bytes successfully extracted for all files! ✓")

    # Group by salt table
    print(f"\n{'=' * 90}")
    print("SALT TABLE GROUPS")
    print(f"{'=' * 90}")

    salt_groups = defaultdict(list)
    for fname, (salt_table, meta) in all_results.items():
        key = tuple(tuple(salt_table.get(l, [])) for l in range(1, 8))
        salt_groups[key].append(fname)

    for group_idx, (salt_key, group_files) in enumerate(
        sorted(salt_groups.items(), key=lambda x: -len(x[1]))
    ):
        is_ref = all(list(salt_key[l - 1]) == REFERENCE_SALTS[l] for l in range(1, 8))
        label = " *** MATCHES 2129026108 ***" if is_ref else ""
        print(f"\n  Group {group_idx + 1} ({len(group_files)} files){label}:")
        for fname in sorted(group_files):
            print(f"    {fname}")
        # Print the salts
        for l in range(1, 8):
            s = list(salt_key[l - 1])
            print(
                f"    Level {l}: [{', '.join(f'0x{b:02X}' if b is not None else '??' for b in s)}]"
            )

    # Algorithm body comparison
    print(f"\n{'=' * 90}")
    print("ALGORITHM BODY COMPARISON (main_func)")
    print(f"{'=' * 90}")

    ref_mf = all_results.get("2129026108_001.CFF", (None, None))[1]
    if ref_mf and ref_mf["mf_body"]:
        # Compare main function bodies
        # We know the main function diffs fall into categories:
        #   - offsets 0x06a, 0x0d8, 0x13e, 0x212: likely data-dependent / address offsets
        #   - offsets 0x306+: tail of function, likely different
        # Let's categorize
        mf_groups = defaultdict(list)
        for fname, (salt_table, meta) in all_results.items():
            if meta["mf_body"]:
                mf_groups[meta["mf_body"]].append(fname)

        print(f"  Unique main function bodies: {len(mf_groups)}")
        for body, group_files in sorted(mf_groups.items(), key=lambda x: -len(x[1])):
            if body == ref_mf["mf_body"]:
                label = " (= 2129026108 reference)"
            else:
                diffs = sum(1 for a, b in zip(ref_mf["mf_body"], body) if a != b)
                label = f" ({diffs} byte diffs vs reference)"
            print(
                f"    {len(group_files)} files{label}: {', '.join(sorted(group_files)[:5])}{'...' if len(group_files) > 5 else ''}"
            )

    # Final: Check which diffs in main_func are structural vs just address relocations
    # Look at diffs at specific known offsets
    print(f"\n{'=' * 90}")
    print("MAIN FUNCTION DIFF ANALYSIS")
    print(f"{'=' * 90}")

    if ref_mf and ref_mf["mf_body"]:
        for fname, (salt_table, meta) in sorted(all_results.items()):
            if meta["mf_body"] and meta["mf_body"] != ref_mf["mf_body"]:
                diffs = []
                for i in range(min(len(ref_mf["mf_body"]), len(meta["mf_body"]))):
                    if ref_mf["mf_body"][i] != meta["mf_body"][i]:
                        diffs.append((i, ref_mf["mf_body"][i], meta["mf_body"][i]))

                if len(diffs) <= 30:
                    # Show all diffs
                    diff_summary = []
                    for off, ref_val, other_val in diffs:
                        diff_summary.append(
                            f"0x{off:03x}:{ref_val:02X}→{other_val:02X}"
                        )
                    print(f"  {fname}: {' '.join(diff_summary)}")


if __name__ == "__main__":
    main()
