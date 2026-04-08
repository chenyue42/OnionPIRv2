# CRT-Based First-Dimension Optimization Analysis

## Problem

After NTT preprocessing, database coefficients expand from ~9 bits (plaintext) to ~58 bits (mod q), causing ~8x storage expansion (256 MB -> 2 GB). The first-dimension matrix multiply is the hot path:

```
for each query coeff a_i (~9 bits, small):
  for each DB coeff b_j (~58 bits, large):
    accumulate a_i * b_j      // 64x64 multiply
```

Currently uses `uint64_t * uint64_t` multiplies. On AVX-512, `_mm512_mullo_epi64` gives 8 multiplies/cycle. Can we do better?

## What SPIRAL Does

SPIRAL (fspiral) uses a **CRT decomposition** to turn one 64x64 multiply into two 32x32->64 multiplies, doubling throughput.

### The trick

Instead of working mod a single ~56-bit prime q, SPIRAL picks two ~28-bit CRT primes p1, p2 where Q = p1 * p2 ~ 56 bits. Each NTT coefficient mod Q can be stored as two ~28-bit values (c mod p1, c mod p2), each fitting in 32 bits.

Key code from `fspiral/src/crt.h`:
```cpp
const uint64_t crtq1 = 268369921;   // ~28-bit prime
const uint64_t crtq2 = 249561089;   // ~28-bit prime
// crtMod = crtq1 * crtq2 ~ 56 bits (composite)
```

### Packed storage

Both CRT residues are packed into a single `uint64_t`:
```
packed = (c mod p1) | ((c mod p2) << 32)
```
Lower 32 bits = residue mod p1, upper 32 bits = residue mod p2.

### SIMD multiply

From `fspiral/src/crt.cpp` (`fastMultiplyQueryByDatabaseDim1InvCRT`):
```cpp
__m512i db_val = _mm512_loadu_si512(db_ptr);
__m512i query_val = ...;  // broadcast query coefficient (small, ~9 bits)

// _mm512_mul_epu32: multiplies lower 32 bits of each 64-bit lane
// Input:  [lo1|hi1] [lo2|hi2] ...
// Output: [lo1*lo2 as 64-bit] ...
__m512i prod = _mm512_mul_epu32(db_val, query_val);
```

Since both CRT residues are packed in one `uint64_t`, a single `_mm512_mul_epu32` multiplies the lower halves (mod p1), and a second call after shifting multiplies the upper halves (mod p2). This gives **16 useful multiplies per instruction** vs 8 with `_mm512_mullo_epi64`.

### Why this works

- Query coeff a_i is ~9 bits (small, fits in 32 bits trivially)
- DB coeff residues are ~28 bits each (fit in 32 bits)
- Product a_i * (c mod p1) is ~37 bits (fits in 64 bits, no overflow)
- Accumulate `fst_dim_sz` (~128) such products: sum ~ 37 + 7 = 44 bits (fits in 64 bits)
- Final reduction mod p1 (or p2) at the end

After accumulating, CRT reconstruction recovers the result mod Q.

## Two Options for OnionPIRv2

### Option A: SEAL RNS with Two 28-bit Primes (Recommended)

Use `CONFIG_TWO_MOD_56` which already sets `CoeffMods = {28, 28, 60}`:
- Two 28-bit ciphertext primes (RNS limbs) + one 60-bit special prime
- Each RNS limb's NTT coefficients are ~28 bits, fitting in `uint32_t`
- SEAL handles all the RNS arithmetic (NTT, key-switching, etc.)
- We only customize the first-dimension multiply kernel to use `_mm512_mul_epu32`

**What changes:**
1. Set `ACTIVE_CONFIG = CONFIG_TWO_MOD_56`
2. Database type becomes `uint32_t` (already handled by `db_coeff_t` conditional)
3. Accumulator type becomes `uint64_t` (already handled by `inter_coeff_t`)
4. Write AVX-512 kernel for first-dim multiply using `_mm512_mul_epu32`
5. Everything else (expansion, external products, BV key-switch) works unchanged through SEAL's RNS

**Advantages:**
- Minimal code changes (~100-150 lines for the SIMD kernel)
- SEAL handles all polynomial arithmetic, NTT, key management
- `db_coeff_t` / `inter_coeff_t` type system already supports this
- Database storage: each coeff is 32 bits instead of 64 -> **2x storage reduction** on top of the 2x compute speedup

**Challenges:**
- Two RNS limbs means some operations (NTT, external product) run twice
- Key sizes slightly larger (two limbs per polynomial in keys)
- Need to verify noise budget is sufficient with 28-bit moduli
- `rns_mod_cnt` becomes 2, and BV key-switch currently asserts `rns_mod_cnt == 1`

**Estimated effort:** ~200 lines of code changes. Low risk.

### Option B: Composite Modulus Q = p1*p2 with HEXL NTT

Use a single composite modulus Q = p1 * p2 (like SPIRAL), bypassing SEAL's prime-modulus requirement. Use HEXL for NTT on composite Q.

**What changes:**
1. Pick two ~28-bit primes p1, p2 and compute Q = p1 * p2
2. Precompute root of unity for composite Q (fspiral already has these)
3. Database NTT uses `intel::hexl::NTT(N, Q, root_of_unity)` instead of SEAL
4. First-dim multiply: custom AVX-512 kernel with CRT-packed storage
5. After first-dim: convert results from mod Q to mod q (SEAL's prime) for remaining operations
6. All post-first-dim operations (expansion, ext product, BV key-switch) stay in SEAL

HEXL already supports composite modulus NTT (confirmed in fspiral):
```cpp
intel::hexl::NTT ntts(N, crtMod, root_of_unity_crt);
// crtMod is composite (crtq1 * crtq2)
```

**What stays unchanged:**
- BV key-switching (operates on SEAL ciphertexts mod single prime q)
- Query expansion (SEAL ciphertexts mod q)
- External products (SEAL ciphertexts mod q)
- Client-side operations (encryption, decryption via SEAL)

**Difficulty breakdown:**

| Component | Effort | Risk |
|-----------|--------|------|
| HEXL NTT setup (root of unity for composite Q) | Low (borrow from fspiral) | Low |
| Database NTT preprocessing | Low (replace SEAL NTT with HEXL) | Low |
| First-dim SIMD multiply kernel | **Medium** (custom AVX-512, mod-Q reduction) | Medium |
| Format conversion (Q -> q) after first dim | Low (simple modular reduction) | Low |
| Build system (link HEXL) | Low | Low |

**Main challenge:** Modular reduction after accumulation. Accumulated sum can be up to `fst_dim_sz * Q ~ 128 * 2^56 ~ 2^63`, which fits in `uint64_t`, but the final `% Q` for composite Q needs Barrett reduction with precomputed constants (SEAL's `Modulus` class is optimized for primes only).

**Estimated effort:** ~300-400 lines of new code. Medium risk.

## Comparison

| Aspect | Option A (SEAL RNS) | Option B (HEXL Composite) |
|--------|---------------------|---------------------------|
| Code changes | ~200 lines | ~300-400 lines |
| Risk | Low | Medium |
| SIMD speedup | 2x on first-dim multiply | 2x on first-dim multiply |
| DB storage | 2x reduction (32-bit coeffs) | Same as Option A if CRT-packed |
| RNS overhead | 2x on some operations | None (single composite mod) |
| SEAL compatibility | Full (native RNS support) | Partial (custom NTT, conversion layer) |
| BV key-switch changes | Must extend to 2 RNS limbs | None needed |
| Key sizes | Slightly larger (2 limbs) | Same as current |

## Recommendation

**Option A is the clear winner for a first implementation.** It leverages SEAL's existing RNS infrastructure, requires minimal code changes, and the `db_coeff_t`/`inter_coeff_t` type system already anticipates the 32-bit coefficient case. The main work is:

1. Extend BV key-switch to handle `rns_mod_cnt == 2`
2. Write the AVX-512 first-dim multiply kernel
3. Verify noise budget under `CONFIG_TWO_MOD_56` parameters

Option B could be explored later if the RNS overhead from two limbs proves significant in profiling.

## References

- `fspiral/src/crt.h` — CRT prime definitions, packed_offset_2 = 32
- `fspiral/src/crt.cpp` — `fastMultiplyQueryByDatabaseDim1InvCRT`, AVX-512 SIMD kernel
- `fspiral/src/spiral.cpp` — `intel::hexl::NTT(N, crtMod, root_of_unity_crt)`
- `fspiral/src/utils.cpp:980-1040` — signed digit decomposition (already ported)
- OnionPIRv2 `src/includes/database_constants.h` — `CONFIG_TWO_MOD_56: CoeffMods = {28, 28, 60}`
- OnionPIRv2 `src/includes/database_constants.h:90-97` — `db_coeff_t` / `inter_coeff_t` conditional types
