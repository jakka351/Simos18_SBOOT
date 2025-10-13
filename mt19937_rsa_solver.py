"""
  for testing
"""
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MT19937 + RSA seed/key solver 

- Reimplements the MT19937 seeding/tempering flow used in twister.c.
- Reproduces the post-processing quirks:
    * rand_data[63] high bits tweak (mask to 16-bit, add 0x0200)
    * rand_data_bytes[245] = 0
- Builds the 256-byte big-endian integer, computes RSA^e mod n,
  compares the first 32 bits of the result to the provided 32-bit match.
- Scans seeds in a window (odd-only increments like the C code).
- Parallelized with multiprocessing.

USAGE:
  python mt19937_rsa_solver.py --match 0xDEADBEEF --seed-start 0x10000000 --seed-end 0x1000FFFF --workers 8

"""
from __future__ import annotations
import argparse
import multiprocessing as mp
import os
import struct
import sys
from typing import Optional, Tuple

# ----- RSA public keys from the C code (choose with --keyset) -----
N_SA = int(
    "de5a5615fdda3b76b4ecd8754228885e7bf11fdd6c8c18ac24230f7f770006cfe60465384e6a5ab4daa3009abc65bff2"
    "abb1da1428ce7a925366a14833dcd18183bad61b2c66f0d8b9c4c90bf27fe9d1c55bf2830306a13d4559df60783f5809"
    "547ffd364dbccea7a7c2fc32a0357ceba3e932abcac6bd6398894a1a22f63bdc45b5da8b3c4e80f8c097ca7ffd18ff6c"
    "78c81e94c016c080ee6c5322e1aeb59d2123dce1e4dd20d0f1cdb017326b4fd813c060e8d2acd62e703341784dca6676"
    "32233de57db820f149964b3f4f0c785c39e2534a7ae36fd115b9f06457822f8a9b7ce7533777a4fb03610d6b4018ab33"
    "2be4e7ad2f4ac193040e5a037417bc53", 16
)
N_SI = int(
    "b21fd93ed14799a3f3f1db1db0159c385537e81397af0f1908d35a08115dabc13c5580833d82d884f9b4c09127df248e"
    "8a7ca815c952c8bbfda097d5b6e56a4072a2842713032229ae55a7307215b8e48c1b7b883a18d7f90e81c766fa8f5f21"
    "94efdcfd79fa5174f5a92f5bba5dabb4e2c138c0a5aab35032ecb90eb73ffe0c1ae3d209f421de40ab8363897c0809d9"
    "3938ebed3e7b25230fdf38795c4e467cccaca5ffb52d49b7130e13aab881fa280c6df9dd4ac7ba0038985064517b6f96"
    "d5abef5be3e21cf261068b94fb128cd98cf02a2033c0e1f57b887e401d041f8afc891727d1d04f14422eefd08c4b925e"
    "45e2446ec98acaefb42c313e2abae9d5", 16
)
E = 65537

# ----- MT19937 impl (tempering identical to C) -----
N = 624
M = 397
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff

def temper(y: int) -> int:
    y ^= (y >> 11) & 0xffffffff
    y ^= ((y << 7) & 0x9D2C5680) & 0xffffffff
    y ^= ((y << 15) & 0xEFC60000) & 0xffffffff
    y ^= (y >> 18) & 0xffffffff
    return y & 0xffffffff

def seedMT(seed: int) -> list[int]:
    # Replicates twister.c behavior exactly.
    state = [0] * (N + 1)
    x = (seed | 1) & 0xffffffff
    s_idx = 0
    state[s_idx] = x; s_idx += 1
    for _ in range(N - 1):
        x = (x * 69069) & 0xffffffff
        state[s_idx] = x; s_idx += 1

    # twist
    p0 = 0
    p2 = 2
    pM = M
    s0 = state[0]; s1 = state[1]
    # first loop
    for _ in range(N - M + 1):
        y = ((s0 & UPPER_MASK) | (s1 & LOWER_MASK)) >> 1
        if (s1 & 1) != 0:
            y ^= MATRIX_A
        state[p0] = (state[pM] ^ y) & 0xffffffff
        p0 += 1; pM += 1
        s0 = s1; s1 = state[p2]; p2 += 1
    # second loop
    pM = 0
    for _ in range(M - 1):
        y = ((s0 & UPPER_MASK) | (s1 & LOWER_MASK)) >> 1
        if (s1 & 1) != 0:
            y ^= MATRIX_A
        state[p0] = (state[pM] ^ y) & 0xffffffff
        p0 += 1; pM += 1
        s0 = s1; s1 = state[p2]; p2 += 1

    # final
    s1 = state[0]
    y = ((s0 & UPPER_MASK) | (s1 & LOWER_MASK)) >> 1
    if (s1 & 1) != 0:
        y ^= MATRIX_A
    state[p0] = (state[pM] ^ y) & 0xffffffff

    # outputs
    out = [0] * 64
    out[0] = temper(s1)
    nxt_idx = 1
    # next 63 from state[1..]
    for i in range(1, 64):
        out[i] = temper(state[nxt_idx]); nxt_idx += 1
    return out

def postprocess_rand_data(words: list[int]) -> bytes:
    # apply the two quirks described in repo/C code:
    words = list(words)
    # last int: swap behavior in C is effectively: treat as little-endian 32,
    # mask to 16, add 0x0200, then keep little-endian. Equivalently:
    w = words[63] & 0xffffffff
    lo16 = w & 0xFFFF
    lo16 = (lo16 + 0x0200) & 0xFFFF
    words[63] = (w & 0xFFFF0000) | lo16

    # pack to bytes (native little) then set byte 245 to 0, then import as BE block
    buf = bytearray()
    for w in words:
        buf += struct.pack("<I", w)
    if len(buf) != 256:
        raise ValueError("rand_data must be 256 bytes")
    buf[245] = 0
    return bytes(buf)

def rsa_first_word(seed: int, n: int, e: int) -> Tuple[int, bytes, bytes]:
    words = seedMT(seed)
    rand_bytes_le = postprocess_rand_data(words)  # 256 bytes, LE uint32 layout
    # mpz_import in C used (-1, 4, -1): big integer from blocks of 4, big-endian order
    # Our buf is 256 bytes little-chunks; convert to BE for "network" integer:
    # Interpret as big-endian integer directly:
    m = int.from_bytes(rand_bytes_le, byteorder="big", signed=False)
    c = pow(m, e, n)
    rsa_out = c.to_bytes(256, "big")
    # compare first 4 bytes (big-endian) as uint32
    first_u32 = struct.unpack(">I", rsa_out[:4])[0]
    return first_u32, rand_bytes_le, rsa_out

def _worker(args) -> Optional[Tuple[int, bytes, bytes]]:
    seed, match_u32, n = args
    got, rdb, rsa = rsa_first_word(seed, n, E)
    if got == match_u32:
        return (seed, rdb, rsa)
    return None

def scan_seeds(match_u32: int, n: int, start: int, end: int, workers: int = os.cpu_count() or 4) -> Optional[Tuple[int, bytes, bytes]]:
    # twister.c increments by 2 (odd seeds only). Mirror that.
    # Normalize to odd start.
    if (start & 1) == 0:
        start += 1
    seeds = range(start, end + 1, 2)
    with mp.Pool(processes=max(1, workers)) as pool:
        for res in pool.imap_unordered(_worker, ((s, match_u32, n) for s in seeds), chunksize=2048):
            if res is not None:
                pool.terminate()
                return res
    return None

def main():
    ap = argparse.ArgumentParser(description="Brute solver for MT19937→RSA first-word match")
    ap.add_argument("--match", required=True, help="32-bit hex (e.g. 0xDEADBEEF)")
    ap.add_argument("--seed-start", required=True, help="start seed (hex or dec)")
    ap.add_argument("--seed-end", required=True, help="end seed (hex or dec)")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 1))
    ap.add_argument("--keyset", choices=["SA","SI"], default="SA", help="which public modulus to use")
    args = ap.parse_args()

    match_u32 = int(args.match, 16 if args.match.lower().startswith("0x") else 10) & 0xffffffff
    start = int(args.seed_start, 16 if args.seed_start.lower().startswith("0x") else 10)
    end = int(args.seed_end, 16 if args.seed_end.lower().startswith("0x") else 10)
    if end < start:
        print("end must be >= start", file=sys.stderr)
        sys.exit(2)

    n = N_SA if args.keyset == "SA" else N_SI
    found = scan_seeds(match_u32, n, start, end, workers=args.workers)
    if not found:
        print("No match in range.", file=sys.stderr)
        sys.exit(1)

    seed, rand_le, rsa_out = found
    print("**** FOUND ****")
    print(f"Seed: {seed:08X}")
    # Print key data in same 32-bit chunking style as C (little-endian words)
    words = [struct.unpack_from("<I", rand_le, 4*i)[0] for i in range(64)]
    print("Key Data:")
    for w in words:
        print(f"{w:08X}", end="")
    print()
    print("Seed Data (RSA first 64 u32, BE):")
    ints = [struct.unpack_from(">I", rsa_out, 4*i)[0] for i in range(64)]
    for i, v in enumerate(ints):
        print(f" {v:08X}", end="")
        if (i % 4) == 3:
            print(" ", end="")
    print()

if __name__ == "__main__":
    main()
