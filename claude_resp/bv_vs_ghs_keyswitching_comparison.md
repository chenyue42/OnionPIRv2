# BV vs GHS Key-Switching for Query Expansion: Experimental Comparison

## Goal

Compare BV-style key-switching (no special prime, gadget decomposition) against SEAL's GHS key-switching (special prime) for OnionPIR's `fast_expand_qry` algorithm. Determine whether BV can achieve comparable or smaller Galois key sizes.

---

## Experimental Setup

### SEAL GHS Baseline (`openfhe_test/seal_baseline.cpp`)

Uses SEAL 4.1 with GHS key-switching. Three configurations tested:

| Config | Data Moduli | Special Prime | Total q |
|--------|-------------|---------------|---------|
| Two-mod | 28-bit + 28-bit | 60-bit | ~116 bits |
| Single-mod (56,60) | 56-bit | 60-bit | ~116 bits |
| Single-mod (60,61) | 60-bit | 61-bit | ~121 bits |

### Rust BV Test (`/u/yuec12/inspire_expand_test/`)

Self-contained Rust implementation of BV key-switching (InsPIRe-style) with OnionPIR's `fast_expand_qry`. Key sizes are calculated with **bit-packed coefficients** (ceil(log2(Q)) bits per coefficient, not 64 bits).

| Parameter | Value |
|-----------|-------|
| N (ring dimension) | 2048 |
| Q (ciphertext modulus) | 72057594037641217 (56-bit NTT-friendly prime) |
| P (plaintext modulus) | 65537 (17-bit) |
| T_KS (gadget digits) | 3 |
| Gadget base B | 2^19 = 524288 |
| Noise width σ | 3.2 |
| Galois keys | 9 (for 9-level expansion tree) |

**Key size formula (seed-compressed)**: `num_keys × T_KS × (N × ceil(log2(Q))/8 + 32)` = 9 × 3 × (2048 × 56/8 + 32) = 9 × 3 × 14368 = 387,936 bytes ≈ **378 KB**

### OpenFHE BV/HYBRID Test (`openfhe_test/expand_test.cpp`)

Uses OpenFHE with BFV scheme. Tested BV (various digitSize) and HYBRID (various dnum).

---

## Results

### Correctness: All Produce 512/512 Correct Expansions

All working configurations correctly expand a single BFV ciphertext into 512 selection ciphertexts using `fast_expand_qry`.

### Key Size Comparison

| System | Mode | Key Size | Seed Compressed | Correct | Time |
|--------|------|----------|-----------------|---------|------|
| **SEAL GHS** | two-mod {28,28,60} | **606 KB** | N/A (zstd) | 512/512 | 120 ms |
| **SEAL GHS** | single-mod {56,60} | **282 KB** | N/A (zstd) | 512/512 | 67 ms |
| **SEAL GHS** | single-mod {60,61} | **290 KB** | N/A (zstd) | 512/512 | 48 ms |
| **Rust BV** | t=3, 56-bit prime | **756 KB** | **378 KB** | 512/512 | 335 ms |
| OpenFHE BV | d=0, depth=0 | 290 KB | N/A | 0/512 | — |
| OpenFHE BV | d=10, depth=0 | 2025 KB | N/A | 512/512 | — |
| OpenFHE BV | d=20, depth=0 | 2893 KB | N/A | 512/512 | — |

Key sizes for the Rust BV test use bit-packed coefficients: each coefficient is stored in ceil(log2(Q)) = 56 bits, so each polynomial is N × 56 / 8 = 14,336 bytes. With seed compression, each CT is 14,336 + 32 = 14,368 bytes.

### Key Observations

1. **SEAL GHS single-mod is the smallest** at 282 KB, thanks to:
   - Only 1 CT per Galois key (decomp_mod_count = 1)
   - zstd compression of serialized keys
   - Seed compression (pseudorandom `a` replaced by short seed)

2. **Rust BV with seed compression (378 KB) is competitive** with SEAL GHS two-mod (606 KB):
   - 3 CTs per key × 9 keys = 27 CTs total
   - Each CT body = 2048 × 56 / 8 = 14,336 bytes
   - 27 × (14,336 + 32) = 387,936 bytes ≈ 378 KB

3. **OpenFHE BV is much larger (2025+ KB)** due to:
   - Auto-selected 60-bit modulus (vs our 56-bit)
   - 6 gadget digits for 60-bit modulus with digitSize=10 (vs our 3)
   - No seed compression
   - Serialization overhead

---

## Why OpenFHE BV Produced Larger Keys

| Factor | OpenFHE BV (d=10) | Rust BV (t=3) | Impact |
|--------|-------------------|---------------|--------|
| Modulus | ~60 bits (auto) | 56 bits (manual) | More digits needed |
| Digits per key | ceil(60/10) = 6 | ceil(56/19) = 3 | **2x more CTs** |
| Seed compression | No | Yes | **2x size** |
| Coefficient storage | 64 bits/coeff | 56 bits/coeff (bit-packed) | ~1.14x |
| Serialization | cereal (metadata) | Raw bytes | ~5-10% overhead |
| **Total ratio** | **2025 KB** | **378 KB** | **~5.4x** |

OpenFHE doesn't expose fine-grained modulus control for BFV (it auto-selects), and doesn't implement seed compression for evaluation keys. These are the two dominant factors.

---

## Structural Comparison: Why BV Needs More CTs but No Special Prime

### GHS (SEAL)
```
Per Galois key = decomp_mod_count CTs, each under extended modulus (data + special prime)
  - two-mod:    2 CTs × (28+28+60 bits) = 2 CTs × 3 RNS limbs
  - single-mod: 1 CT  × (56+60 bits)    = 1 CT  × 2 RNS limbs

Key-switch noise ≈ k · σ  (k = decomp_mod_count)
```

### BV (Rust/InsPIRe)
```
Per Galois key = t CTs, each under data modulus only (no special prime)
  - t=3: 3 CTs × 56 bits = 3 CTs × 1 RNS limb

Key-switch noise ≈ t · B · σ  (B = gadget base ≈ 2^19)
```

The fundamental tradeoff: GHS uses a special prime to keep noise low with fewer CTs, while BV uses more CTs (finer gadget decomposition) to control noise without any special prime. BV wins on simplicity and avoids the special prime overhead, but needs careful parameter tuning.

---

## Per-Key Polynomial Count (Apples-to-Apples)

| System | CTs/key | RNS limbs/CT | Polys/CT | Total polys/key |
|--------|---------|--------------|----------|-----------------|
| SEAL GHS two-mod | 2 | 3 (28+28+60) | 2 | 12 |
| SEAL GHS single-mod | 1 | 2 (56+60) | 2 | 4 |
| BV t=3 (raw) | 3 | 1 (56) | 2 | 6 |
| BV t=3 (seed) | 3 | 1 (56) | 1 (body only) | 3 |

With seed compression, BV t=3 has fewer polynomials per key than any GHS configuration. BV's 3 polys/key × 9 keys = 27 polys vs SEAL GHS single-mod's 4 polys/key × 9 keys = 36 polys.

---

## Bit-Packed Key Size Calculation

For a q-bit ciphertext modulus, each polynomial coefficient requires q bits of storage (not 64 bits). This gives tighter size estimates:

| Component | Formula | BV t=3, 56-bit | SEAL GHS single-mod |
|-----------|---------|----------------|---------------------|
| Bytes per poly | N × q / 8 | 2048 × 56 / 8 = 14,336 | 2048 × 56 / 8 = 14,336 (data) |
| Polys per key (seed) | t × 1 | 3 | 2 (but includes 60-bit special prime limb) |
| Seed overhead | t × 32 | 96 | 32 |
| Bytes per key (seed) | t × (N×q/8 + 32) | 43,104 | — |
| Total (9 keys) | | **378 KB** | **282 KB** (with zstd) |

The remaining gap between BV seed-compressed (378 KB) and SEAL GHS single-mod (282 KB) is due to:
- BV has 3 body polynomials per key vs GHS's 2 polynomials per key (one body + one with special prime data)
- SEAL applies zstd compression on top of seed compression

---

## Conclusion

BV key-switching with 3 gadget digits and seed compression can achieve **smaller Galois key sizes than SEAL's GHS two-mod** for OnionPIR's query expansion (378 KB vs 606 KB), while maintaining full correctness. However, it does not beat SEAL's GHS single-mod (282 KB).

Key requirements for BV to be competitive:

1. **Bit-packed serialization**: Store each coefficient in ceil(log2(Q)) bits, not 64 bits
2. **Seed compression**: Replace pseudorandom `a` polynomials with short seeds (~32 bytes each)
3. **Careful noise budget**: BV noise scales as `t · B · σ`, which must remain below `q/(2p)` after 9 levels of expansion
4. **Small digit count**: t=3 digits for a 56-bit modulus keeps key material minimal

The tradeoff is higher noise growth per key-switch (BV) vs larger key material per key-switch (GHS). For PIR applications where the expansion depth is moderate (9 levels) and the modulus budget allows it, BV with seed compression is a viable alternative to GHS, especially when avoiding the complexity of a special prime is desirable.
