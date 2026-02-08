Almost this entire thing was AI generated. The only inputs being known-good seeds provided aggregated and provided by others (a big thank you to them!) in https://github.com/jglim/UnlockECU/issues/10 and the CFF files themselves. Everything below is what AI wrote:

----

# IC204 Seed-Key Algorithm

Reverse-engineered seed-key algorithm for Mercedes-Benz instrument cluster (IC204) with NEC V850E1 processor.

**Original work was done on SW version 2129026108.** Additional SW versions are supported through automated salt table extraction from CFF firmware images.

## Supported SW Versions

31 firmware versions supported (26 unique salt tables, 5 aliases) across 6 series:

| Series | Versions |
|--------|----------|
| 197902 | 1979021501, 1979023801, 1979025200, 1979027000 |
| 204442 | 2044422521, 2044423021, 2044423621, 2044423921 |
| 204902 | 2049022403, 2049022600, 2049022602, 2049022700, 2049022702, **2049022903** (=2049026403, =2049026503, =2049028303), 2049023401, 2049024102, 2049024301, 2049024802, 2049027103, 2049027203, 2049028902 |
| 212442 | 2124420721 |
| 212902 | **2129026108** (default) (=2129021909, =2129023005) |
| 218902 | 2189020500, 2189021001, 2189028400 |

Versions prefixed with `=` are aliases sharing identical salt tables with the preceding version.

The core algorithm is bit-identical across all 31 firmware images — only the 7 per-level salt tables (8 bytes each) differ.

## Overview

This implementation computes the correct UDS SecurityAccess key given:
- A security level (UDS sub-function: 0x01, 0x03, 0x09, 0x0D)
- An 8-byte seed from the ECU
- Optional SW version (defaults to 2129026108)

The algorithm was reverse-engineered from the V850 assembly of the firmware using Ghidra.

## Usage

### Python API

```python
from ic204_seedkey import ic204_generate_key

# UDS level 0x09 with seed (default SW version: 2129026108)
seed = bytes.fromhex("212A2F38F98A8BD7")
key = ic204_generate_key(0x09, seed)
print(f"Key: {key.hex().upper()}")  # Output: 775588C8850CF244

# Specify SW version
seed = bytes.fromhex("5C97A0A552FB0205")
key = ic204_generate_key(0x09, seed, sw_version="2049022903")
print(f"Key: {key.hex().upper()}")  # Output: D8F169D68D5D17B6
```

### Command Line

```bash
# Compute key for a given level and seed (default SW version)
python3 ic204_seedkey.py 09 212A2F38F98A8BD7

# Specify SW version
python3 ic204_seedkey.py 09 5C97A0A552FB0205 --sw 2049022903

# Run test vectors
python3 ic204_seedkey.py --test
```

## Running Tests

```bash
python3 ic204_seedkey.py --test
```

All 10 test vectors pass (from https://github.com/jglim/UnlockECU/issues/10):

**SW 2129026108** (also applies to 2129023005 and 2129021909):

| UDS Level | Seed (hex) | Expected Key (hex) |
|-----------|-----------|-------------------|
| 0x01 | 0000000000000000 | D632404B132FE12B |
| 0x03 | 0000000000000000 | 6552C46251393265 |
| 0x09 | 0000000000000000 | B83B5E73528197D3 |
| 0x0D | 0000000000000000 | 162FA93147161D00 |
| 0x09 | 212A2F38F98A8BD7 | 775588C8850CF244 |
| 0x09 | 05E8242E8011F8FF | B73353CD123F6837 |
| 0x0D | 537C818A537C818A | 7FD7DCB083DCFB46 |
| 0x0D | 28C1050F7B52C7CE | AC12805D446FDF54 |

**SW 2049022903**:

| UDS Level | Seed (hex) | Expected Key (hex) |
|-----------|-----------|-------------------|
| 0x09 | 5C97A0A552FB0205 | D8F169D68D5D17B6 |
| 0x0D | C1EBF4F94CA0A7A6 | 49D4BE45A0B6DFF3 |

## Algorithm Summary

The algorithm consists of three main firmware functions:

1. **`rotate_right_array(buf, length)`** — Right-rotates a byte array as a bitfield by 1 bit
2. **`salt_transform(level, sw_version=None)`** — Generates 8-byte LFSR initial state from a salt table (level- and SW-version-dependent)
3. **`ic204_generate_key(uds_level, seed, sw_version=None)`** — Main seed-to-key computation (defaults to SW 2129026108)

### Key Steps

1. **Seed permutation** — Rearrange seed bytes into workspace
2. **LFSR generation** — Create LFSR state from salt table
3. **LFSR loop** — Run feedback XOR of 8 specific bit taps for variable iterations
4. **Feistel network** — 2 rounds, each with 2 half-rounds using rotation and 32-bit addition
5. **Reverse permutation** — Rearrange result to produce the final key

### UDS Level Mapping

UDS SecurityAccess sub-functions map to internal levels as:
- 0x01 → 1
- 0x03 → 3
- 0x09 → 5
- 0x0D → 7

## Files

- **`ic204_seedkey.py`** — Complete Python implementation with 26 unique salt tables
- **`robust_extract.py`** — Salt table extractor: decodes V850 instructions from CFF firmware images to extract per-version salt tables
- **`disasm.txt`** — V850 disassembly of the three core firmware functions from Ghidra
- **`ic204.gpr`** — Ghidra project file (for reference)

## Salt Table Extraction

The `robust_extract.py` tool extracts salt tables from CFF firmware images by:
1. Locating the `salt_transform` function via its prologue signature
2. Decoding V850 instructions (`movea`, `mov imm5`, `sst.b`, `st.b`, `mov reg,reg`)
3. Tracking register state through each switch case to handle compiler optimizations (register reuse, small immediate values, shared epilogues)

It found 31 CFF files containing the algorithm across all series in the CFF directory, producing 26 unique salt table groups.

## Reverse Engineering Notes

The firmware was analyzed in Ghidra as a V850 project. Key findings:
- Functions: `FUN_00180b56`, `FUN_00180bd2`, `FUN_00180f14`
- Critical stack frame bug: `FUN_00180bd2` uses `callt 0x13` which allocates its own local stack frame
- Caller verification at `FUN_00175af8` confirmed the UDS-to-internal level mapping
- Algorithm body is bit-identical across all 31 firmware images (only address relocations and tail padding differ)

## License

This code is provided for educational and research purposes.
