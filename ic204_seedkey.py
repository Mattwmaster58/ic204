#!/usr/bin/env python3
"""
IC204 Seed-Key Algorithm
Reverse engineered from V850 assembly (NEC V850E1 firmware for Mercedes W204 instrument cluster).
Supports multiple SW versions with per-version salt tables.

Supported SW versions:
  2129026108 (default), 2129023005, 2129021909 — identical salt tables
  2049022903 — different salt tables

Firmware functions:
  FUN_00180b56 - rotate_right_array: right-rotates a byte array as a bitfield by 1 bit
  FUN_00180bd2 - salt_transform: salt-only transformation producing 8-byte LFSR initial state
  FUN_00180f14 - main entry: full seed-to-key computation

Algorithm overview:
  1. Rearrange (permute) the 8-byte seed into workspace ws[0x10..0x17]
  2. Compute LFSR iteration count from a seed byte selected by the security level
  3. Generate 8-byte LFSR state from the salt (FUN_00180bd2, level-dependent)
  4. Run LFSR: feedback XOR of specific bit taps, then rotate-right the 8-byte state
  5. Copy permuted seed to ws[0x00..0x07]
  6. Main Feistel-like loop (2 rounds, each with 2 half-rounds):
     - XOR upper half with lower half of seed workspace
     - Rotate upper half by a data-dependent count
     - Add (32-bit LE) LFSR state to upper half
     - Swap halves and copy back
  7. Reverse-permute the result to produce the 8-byte key

Test vectors from https://github.com/jglim/UnlockECU/issues/10
"""

import argparse
import sys


def rotate_right_array(buf, length):
    """
    FUN_00180b56: Right-rotate a byte array (treated as a contiguous bitfield) by 1 bit.

    The LSB of byte[i-1] becomes the MSB of byte[i], wrapping around
    so the LSB of byte[length-1] feeds into the MSB of byte[0].

    Args:
        buf: bytearray to rotate in-place (only first `length` bytes affected)
        length: number of bytes to operate on (1-8)
    """
    if length == 0 or length > 8:
        return

    carries = [buf[i] & 1 for i in range(length)]

    for i in range(length):
        carry_idx = length - 1 if i == 0 else i - 1
        shifted = (buf[i] >> 1) & 0x7F
        if carries[carry_idx]:
            shifted |= 0x80
        buf[i] = shifted


# Per-level salt tables extracted from the switch statement in FUN_00180bd2.
# Index = internal security level (1-7).
# Each entry = 8 bytes stored at local[0x0C..0x13] in the function's stack frame.
#
# Outer key = SW version string. Multiple versions can share the same table.
SALT_TABLES = {
    "2129026108": {
        1: [0x9F, 0x85, 0x1B, 0x63, 0x56, 0xC5, 0x85, 0xDE],
        2: [0x1C, 0x77, 0x9A, 0x22, 0x71, 0xAE, 0x20, 0xCE],
        3: [0x21, 0x2B, 0xB9, 0xC9, 0x24, 0x5A, 0x4C, 0xA7],
        4: [0x62, 0xD9, 0x5B, 0xB2, 0x95, 0x48, 0xAD, 0x26],
        5: [0xC1, 0x7C, 0x39, 0xEB, 0xDF, 0xD2, 0x19, 0xC4],
        6: [0x7A, 0x40, 0x41, 0x31, 0x37, 0x9A, 0x87, 0x18],
        7: [0x91, 0xD3, 0xDF, 0xFB, 0xED, 0x23, 0x42, 0x15],
    },
    "2049022903": {
        1: [0xB2, 0xAC, 0x62, 0x5D, 0x69, 0xED, 0xCC, 0xD8],
        2: [0x5C, 0x7C, 0xC3, 0x81, 0xB1, 0xB4, 0x4A, 0x2D],
        3: [
            0x52,
            0x3B,
            0x4D,
            0x02,
            0x15,
            0xAE,
            0x6E,
            0x5C,
        ],  # salt[3]=0x02 (r7=level-1)
        4: [0x93, 0xE9, 0xDE, 0xEF, 0xF5, 0x53, 0x1C, 0x75],
        5: [0xE1, 0xC9, 0x37, 0xB1, 0xF1, 0x2B, 0x71, 0x68],
        6: [0xCB, 0x56, 0xFA, 0x5D, 0x88, 0xB0, 0x50, 0x46],
        7: [0xC1, 0x15, 0x83, 0xE4, 0xDC, 0xA9, 0x74, 0x74],  # salt[7]=salt[6]=0x74
    },
}

# Aliases: these SW versions share the same salt table as 2129026108.
SW_ALIASES = {
    "2129023005": "2129026108",
    "2129021909": "2129026108",
}

DEFAULT_SW_VERSION = "2129026108"


def get_salt_table(sw_version=None):
    """Look up the salt table for a SW version, resolving aliases."""
    if sw_version is None:
        sw_version = DEFAULT_SW_VERSION
    sw_version = str(sw_version)
    resolved = SW_ALIASES.get(sw_version, sw_version)
    if resolved not in SALT_TABLES:
        raise ValueError(
            f"Unknown SW version: {sw_version}. "
            f"Supported: {', '.join(sorted(set(list(SALT_TABLES) + list(SW_ALIASES))))}"
        )
    return SALT_TABLES[resolved]


# UDS SecurityAccess sub-function to internal level mapping.
# The caller at FUN_00175af8 loads the internal level from a processed buffer
# before calling FUN_00180f14. Mapping verified by test vectors:
#   UDS 0x01 → internal 1   (salt[1])
#   UDS 0x03 → internal 3   (salt[3])
#   UDS 0x09 → internal 5   (salt[5])
#   UDS 0x0D → internal 7   (salt[7])
# Only these 4 levels are used by this ECU (matching the 32-byte salt field
# in the UnlockECU database: salts 1, 3, 5, 7 concatenated).
UDS_TO_INTERNAL = {
    0x01: 1,
    0x03: 3,
    0x09: 5,
    0x0D: 7,
}


def uds_to_internal_level(uds_level):
    """Convert UDS SecurityAccess sub-function to internal level (1-7)."""
    if uds_level in UDS_TO_INTERNAL:
        return UDS_TO_INTERNAL[uds_level]
    # Fallback for untested levels
    return (uds_level + 1) // 2


def salt_transform(level, sw_version=None):
    """
    FUN_00180bd2: Generate 8-byte LFSR initial state from salt only.

    This function has its own local stack frame (0x14 bytes) and operates
    entirely on the salt table — it does NOT read the seed or any caller data.
    The output pointer (r27) is only used for the final 8-byte copy-out.

    Algorithm:
      1. Load 8-byte salt into local[0x0C..0x13]
      2. Copy salt[4..7] → local[0x00..0x03], salt[0..3] → local[0x04..0x07]
      3. Copy local[0..3] → local[0x08..0x0B]
      4. Transpose local[0x08..0x0B] → local[0x00..0x03]
      5. Rotate-right local[0x00..0x03] by (local[0x0A] & 0xF) + 1
      6. Rotate-right local[0x08..0x0B] by (local[0x0B] & 0xF) + 1
      7. XOR local[0..3] ^= local[0x08..0x0B]
      8. Copy local[0x04..0x07] → local[0x08..0x0B]
      9. Transpose local[0x08..0x0B] → local[0x04..0x07]
     10. Rotate-right local[0x04..0x07] by (local[0x0A] & 0xF) + 1
     11. Rotate-right local[0x08..0x0B] by (local[0x0B] & 0xF) + 1
     12. XOR local[0x04..0x07] ^= local[0x08..0x0B]
     13. Rearrange into local[0x0C..0x13] and output

    Args:
        level: int, internal level 1-7
        sw_version: str, SW version (default: 2129026108)

    Returns:
        bytearray of 8 bytes (written to caller's ws[0x08..0x0F])
    """
    if level < 1 or level > 7:
        return bytearray(8)

    salt_table = get_salt_table(sw_version)
    salt = salt_table[level]
    local = bytearray(0x14)

    # Store salt at local[0x0C..0x13]
    for i in range(8):
        local[0x0C + i] = salt[i]

    # Phase 1: local[0x10..0x13] (= salt[4..7]) → local[0x00..0x03]
    for i in range(4):
        local[i] = local[0x10 + i]

    # Phase 2: local[0x0C..0x0F] (= salt[0..3]) → local[0x04..0x07]
    for i in range(4):
        local[0x04 + i] = local[0x0C + i]

    # Phase 3: local[0x00..0x03] → local[0x08..0x0B]
    for i in range(4):
        local[0x08 + i] = local[i]

    # Phase 4: Transpose local[0x08..0x0B] → local[0x00..0x03]
    t = [local[0x08], local[0x09], local[0x0A], local[0x0B]]
    local[0x02] = t[0]
    local[0x00] = t[1]
    local[0x01] = t[3]
    local[0x03] = t[2]

    # Phase 5: Rotate local[0x00..0x03] right by (t[2] & 0xF) + 1
    rotate_count = (t[2] & 0x0F) + 1
    buf = bytearray(local[0:4])
    for _ in range(rotate_count):
        rotate_right_array(buf, 4)
    local[0:4] = buf

    # Phase 6: Rotate local[0x08..0x0B] right by (local[0x0B] & 0xF) + 1
    rotate_count = (local[0x0B] & 0x0F) + 1
    buf = bytearray(local[0x08:0x0C])
    for _ in range(rotate_count):
        rotate_right_array(buf, 4)
    local[0x08:0x0C] = buf

    # Phase 7: XOR local[0..3] ^= local[0x08..0x0B]
    for i in range(4):
        local[i] ^= local[0x08 + i]

    # Phase 8: local[0x04..0x07] → local[0x08..0x0B]
    for i in range(4):
        local[0x08 + i] = local[0x04 + i]

    # Phase 9: Transpose local[0x08..0x0B] → local[0x04..0x07]
    t = [local[0x08], local[0x09], local[0x0A], local[0x0B]]
    local[0x06] = t[0]
    local[0x04] = t[1]
    local[0x05] = t[3]
    local[0x07] = t[2]

    # Phase 10: Rotate local[0x04..0x07] right by (local[0x0A] & 0xF) + 1
    rotate_count = (local[0x0A] & 0x0F) + 1
    buf = bytearray(local[0x04:0x08])
    for _ in range(rotate_count):
        rotate_right_array(buf, 4)
    local[0x04:0x08] = buf

    # Phase 11: Rotate local[0x08..0x0B] right by (local[0x0B] & 0xF) + 1
    rotate_count = (local[0x0B] & 0x0F) + 1
    buf = bytearray(local[0x08:0x0C])
    for _ in range(rotate_count):
        rotate_right_array(buf, 4)
    local[0x08:0x0C] = buf

    # Phase 12: XOR local[0x04..0x07] ^= local[0x08..0x0B]
    for i in range(4):
        local[0x04 + i] ^= local[0x08 + i]

    # Phase 13: local[0x00..0x03] → local[0x10..0x13]
    for i in range(4):
        local[0x10 + i] = local[i]

    # Phase 14: local[0x04..0x07] → local[0x0C..0x0F]
    for i in range(4):
        local[0x0C + i] = local[0x04 + i]

    # Output: local[0x0C..0x13] (8 bytes)
    return bytearray(local[0x0C:0x14])


def compute_lfsr_feedback(ws):
    """
    LFSR feedback from FUN_00180f14 at LAB_00180f82.

    XORs 8 specific bit taps from ws[0x08..0x0F], then writes the result
    into bit 7 of ws[0x0F] (keeping bits 6:0 intact).

    Taps: [0x08] bit3, [0x09] bit0, [0x0A] bit1, [0x0B] bit7,
          [0x0C] bit5, [0x0D] bit2, [0x0E] bit6, [0x0F] bit4
    """
    fb = (ws[0x08] >> 3) & 1
    fb ^= ws[0x09] & 1
    fb ^= (ws[0x0A] >> 1) & 1
    fb ^= (ws[0x0B] >> 7) & 1
    fb ^= (ws[0x0C] >> 5) & 1
    fb ^= (ws[0x0D] >> 2) & 1
    fb ^= (ws[0x0E] >> 6) & 1
    fb ^= (ws[0x0F] >> 4) & 1
    ws[0x0F] = (ws[0x0F] & 0x7F) | (fb << 7)


def le32_load(buf, offset):
    """Load a 32-bit little-endian value from buf at offset."""
    return (
        (buf[offset + 3] << 24)
        | (buf[offset + 2] << 16)
        | (buf[offset + 1] << 8)
        | buf[offset]
    )


def le32_store(buf, offset, val):
    """Store a 32-bit little-endian value to buf at offset."""
    buf[offset] = val & 0xFF
    buf[offset + 1] = (val >> 8) & 0xFF
    buf[offset + 2] = (val >> 16) & 0xFF
    buf[offset + 3] = (val >> 24) & 0xFF


def ic204_generate_key(uds_level, seed, sw_version=None):
    """
    FUN_00180f14: Main seed-to-key function for IC204.

    Args:
        uds_level: int, UDS SecurityAccess sub-function (0x01, 0x03, 0x09, 0x0D)
        seed: bytes/bytearray, 8-byte seed from ECU
        sw_version: str, SW version (default: 2129026108)

    Returns:
        bytearray, 8-byte key to send back, or None if level is invalid
    """
    assert len(seed) == 8

    level = uds_to_internal_level(uds_level)
    if level < 1 or level > 7:
        return None

    # Workspace layout (models the stack frame of FUN_00180f14):
    #   ws[0x00..0x07] = working copy / Feistel state
    #   ws[0x08..0x0F] = LFSR state (from salt_transform, then shifted)
    #   ws[0x10..0x17] = permuted seed / Feistel working data
    ws = bytearray(0x20)

    # Step 1: Permute seed bytes into ws[0x10..0x17]
    # Mapping from assembly at 00180f2c-00180f5c
    ws[0x10] = seed[7]
    ws[0x11] = seed[4]
    ws[0x12] = seed[3]
    ws[0x13] = seed[6]
    ws[0x14] = seed[5]
    ws[0x15] = seed[1]
    ws[0x16] = seed[0]
    ws[0x17] = seed[2]

    # Step 2: LFSR iteration count from seed byte at position (0x10 + level)
    lfsr_count = (ws[0x10 + level] & 0x07) + 2

    # Step 3: Generate LFSR initial state from salt
    ws[0x08:0x10] = salt_transform(level, sw_version)

    # Step 4: Run LFSR (feedback + rotate) for lfsr_count iterations
    for _ in range(lfsr_count):
        compute_lfsr_feedback(ws)
        buf = ws[0x08:0x10]
        rotate_right_array(buf, 8)
        ws[0x08:0x10] = buf

    # Step 5: Copy permuted seed to working area
    ws[0x00:0x08] = ws[0x10:0x18]

    # Step 6: Feistel-like network — 2 rounds, each with 2 half-rounds
    for _ in range(2):
        # Half-round A: uses ws[0x08..0x0B]
        for i in range(4):
            ws[0x10 + i] ^= ws[0x14 + i]
        rot_count = (ws[level] & 0x03) + 1
        buf = ws[0x10:0x14]
        for _ in range(rot_count):
            rotate_right_array(buf, 4)
        ws[0x10:0x14] = buf
        val_a = le32_load(ws, 0x10)
        val_b = le32_load(ws, 0x08)
        le32_store(ws, 0x10, (val_a + val_b) & 0xFFFFFFFF)
        ws[0x14:0x18] = ws[0x00:0x04]
        ws[0x00:0x08] = ws[0x10:0x18]

        # Half-round B: uses ws[0x0C..0x0F]
        for i in range(4):
            ws[0x10 + i] ^= ws[0x14 + i]
        rot_count = (ws[level] & 0x03) + 1
        buf = ws[0x10:0x14]
        for _ in range(rot_count):
            rotate_right_array(buf, 4)
        ws[0x10:0x14] = buf
        val_a = le32_load(ws, 0x10)
        val_b = le32_load(ws, 0x0C)
        le32_store(ws, 0x10, (val_a + val_b) & 0xFFFFFFFF)
        ws[0x14:0x18] = ws[0x00:0x04]
        ws[0x00:0x08] = ws[0x10:0x18]

    # Step 7: Reverse-permute ws[0x00..0x07] → ws[0x10..0x17] (output key)
    # Mapping from assembly at 001811c6-001811e8
    t = bytes(ws[0:8])
    ws[0x10] = t[3]
    ws[0x11] = t[5]
    ws[0x12] = t[6]
    ws[0x13] = t[1]
    ws[0x14] = t[0]
    ws[0x15] = t[7]
    ws[0x16] = t[4]
    ws[0x17] = t[2]

    return bytearray(ws[0x10:0x18])


def test():
    """Test against known vectors."""
    test_cases = [
        # (sw_version, uds_level, seed_hex, expected_key_hex)
        # --- SW 2129026108 (original UnlockECU vectors) ---
        ("2129026108", 0x01, "0000000000000000", "D632404B132FE12B"),
        ("2129026108", 0x03, "0000000000000000", "6552C46251393265"),
        ("2129026108", 0x09, "0000000000000000", "B83B5E73528197D3"),
        ("2129026108", 0x0D, "0000000000000000", "162FA93147161D00"),
        ("2129026108", 0x09, "212A2F38F98A8BD7", "775588C8850CF244"),
        ("2129026108", 0x09, "05E8242E8011F8FF", "B73353CD123F6837"),
        ("2129026108", 0x0D, "537C818A537C818A", "7FD7DCB083DCFB46"),
        ("2129026108", 0x0D, "28C1050F7B52C7CE", "AC12805D446FDF54"),
        # --- SW 2049022903 ---
        ("2049022903", 0x09, "5C97A0A552FB0205", "D8F169D68D5D17B6"),
        ("2049022903", 0x0D, "C1EBF4F94CA0A7A6", "49D4BE45A0B6DFF3"),
    ]

    all_versions = sorted(set(sw for sw, _, _, _ in test_cases))
    print("IC204 Seed-Key Algorithm Tests")
    print("=" * 78)

    all_pass = True
    for sw_version, uds_level, seed_hex, expected_hex in test_cases:
        seed = bytes.fromhex(seed_hex)
        expected = bytes.fromhex(expected_hex)
        result = ic204_generate_key(uds_level, seed, sw_version)

        if result is None:
            result_hex = "None"
            match = False
        else:
            result_hex = result.hex().upper()
            match = result == expected

        status = "PASS" if match else "FAIL"
        if not match:
            all_pass = False

        print(
            f"  SW {sw_version} | Level 0x{uds_level:02X} | Seed: {seed_hex} "
            f"| Expected: {expected_hex} | Got: {result_hex} | {status}"
        )

    print("=" * 78)
    print("ALL TESTS PASSED!" if all_pass else "SOME TESTS FAILED")
    return all_pass


def main():
    supported_versions = sorted(set(list(SALT_TABLES) + list(SW_ALIASES)))

    parser = argparse.ArgumentParser(
        description="IC204 Seed-Key Algorithm — compute UDS SecurityAccess keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Supported SW versions: {', '.join(supported_versions)}",
    )
    parser.add_argument(
        "level",
        nargs="?",
        help="UDS SecurityAccess level in hex (e.g. 09, 0x0D)",
    )
    parser.add_argument(
        "seed",
        nargs="?",
        help="8-byte seed as 16 hex chars (e.g. 5C97A0A552FB0205)",
    )
    parser.add_argument(
        "--sw",
        default=DEFAULT_SW_VERSION,
        help=f"SW version (default: {DEFAULT_SW_VERSION})",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run built-in test vectors instead of computing a key",
    )

    args = parser.parse_args()

    if args.test:
        success = test()
        sys.exit(0 if success else 1)

    if args.level is None or args.seed is None:
        parser.error("level and seed are required (or use --test)")

    # Parse level — accept hex with or without 0x prefix, or plain decimal
    level_str = args.level
    try:
        if level_str.startswith("0x") or level_str.startswith("0X"):
            uds_level = int(level_str, 16)
        else:
            uds_level = int(level_str, 16)
    except ValueError:
        parser.error(f"Invalid level: {level_str}")

    # Parse seed
    seed_hex = args.seed.replace(" ", "")
    if len(seed_hex) != 16:
        parser.error(
            f"Seed must be exactly 16 hex chars (8 bytes), got {len(seed_hex)}"
        )
    try:
        seed = bytes.fromhex(seed_hex)
    except ValueError:
        parser.error(f"Invalid hex in seed: {seed_hex}")

    try:
        result = ic204_generate_key(uds_level, seed, args.sw)
    except ValueError as e:
        parser.error(str(e))

    if result is None:
        print(f"Error: invalid level 0x{uds_level:02X}", file=sys.stderr)
        sys.exit(1)

    print(result.hex().upper())


if __name__ == "__main__":
    main()
