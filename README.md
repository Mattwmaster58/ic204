# IC204 Seed-Key Algorithm

Reverse-engineered seed-key algorithm for Mercedes-Benz W204 instrument cluster (IC204) with software part number **2129026108** (NEC V850E1 processor).

## Overview

This implementation computes the correct UDS SecurityAccess key given:
- A security level (UDS sub-function: 0x01, 0x03, 0x09, 0x0D)
- An 8-byte seed from the ECU

The algorithm was reverse-engineered from the V850 assembly of the firmware using Ghidra.

## Usage

```python
from ic204_seedkey import ic204_generate_key

# UDS level 0x09 with seed
seed = bytes.fromhex("212A2F38F98A8BD7")
key = ic204_generate_key(0x09, seed)
print(f"Key: {key.hex().upper()}")  # Output: 775588C8850CF244
```

## Running Tests

```bash
python3 ic204_seedkey.py
```

All 7 test vectors pass (from https://github.com/jglim/UnlockECU/issues/10):

| UDS Level | Seed (hex) | Expected Key (hex) |
|-----------|-----------|-------------------|
| 0x01 | 0000000000000000 | D632404B132FE12B |
| 0x03 | 0000000000000000 | 6552C46251393265 |
| 0x09 | 0000000000000000 | B83B5E73528197D3 |
| 0x0D | 0000000000000000 | 162FA93147161D00 |
| 0x09 | 212A2F38F98A8BD7 | 775588C8850CF244 |
| 0x09 | 05E8242E8011F8FF | B73353CD123F6837 |
| 0x0D | 537C818A537C818A | 7FD7DCB083DCFB46 |

## Algorithm Summary

The algorithm consists of three main firmware functions:

1. **`rotate_right_array(buf, length)`** — Right-rotates a byte array as a bitfield by 1 bit
2. **`salt_transform(level)`** — Generates 8-byte LFSR initial state from a salt table (level-dependent)
3. **`ic204_generate_key(uds_level, seed)`** — Main seed-to-key computation

### Key Steps

1. **Seed permutation** — Rearrange seed bytes into workspace
2. **LFSR generation** — Create LFSR state from salt table
3. **LFSR loop** — Run feedback XOR of 8 specific bit taps for variable iterations
4. **Feistel network** — 2 rounds, each with 2 half-rounds using rotation and 32-bit addition
5. **Reverse permutation** — Rearrange result to produce the final key

### Salt Table

7 salt entries for internal levels 1-7 (only 1, 3, 5, 7 used by this ECU):
- Level 1: 9F 85 1B 63 56 C5 85 DE
- Level 3: 21 2B B9 C9 24 5A 4C A7
- Level 5: C1 7C 39 EB DF D2 19 C4
- Level 7: 91 D3 DF FB ED 23 42 15

### UDS Level Mapping

UDS SecurityAccess sub-functions map to internal levels as:
- 0x01 → 1
- 0x03 → 3
- 0x09 → 5
- 0x0D → 7

## Files

- **`ic204_seedkey.py`** — Complete, working Python implementation
- **`disasm.txt`** — V850 disassembly of the three core firmware functions from Ghidra
- **`ic204.gpr`** — Ghidra project file (for reference)

## Reverse Engineering Notes

The firmware was analyzed in Ghidra as a V850 project. Key findings:
- Functions: `FUN_00180b56`, `FUN_00180bd2`, `FUN_00180f14`
- Critical stack frame bug: `FUN_00180bd2` uses `callt 0x13` which allocates its own local stack frame
- Caller verification at `FUN_00175af8` confirmed the UDS-to-internal level mapping

## License

This code is provided for educational and research purposes.
