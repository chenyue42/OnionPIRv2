# Fast Spiral Key-Switching Analysis

## Key-Switching Technique: Pure BV (Gadget Decomposition, No Special Prime)

Fast Spiral uses **BV-style key-switching** — gadget decomposition without any special prime. This is fundamentally different from SEAL's GHS approach.

### How `evalAuto` Works (answer.cpp:576-648)

The automorphism evaluation has two steps:

1. **Apply the automorphism permutation** to the ciphertext `(a, b)`:
   - For each coefficient `i`, compute destination `(i * index) mod 2N`
   - If destination >= N, negate (negacyclic property)
   - This transforms `(a, b)` into `(a', b')` where `a' = sigma_k(a)`, `b' = sigma_k(b)`

2. **Key-switch** to get back to the original key:
   - Decompose `a'` using gadget decomposition: `g^{-1}(a')` into `ellnum` small polynomials
   - Compute: `result.a = -sum_i (g^{-1}(a')[i] * autokey[i].a)`
   - Compute: `result.b = b' - sum_i (g^{-1}(a')[i] * autokey[i].b)`
   - This is a standard BV key-switch: no special prime, no extended modulus

### No Special Prime

The key-switching happens entirely within a **single modulus**. There is no temporary modulus enlargement or division step. The noise from key-switching scales with `ellnum * Bg * sigma`, which Fast Spiral manages by choosing appropriate gadget parameters.

---

## Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (ring dimension) | 4096 | vs OnionPIR's 2048 |
| Primary modulus | `crtMod = crtq1 * crtq2` | Composite: 268369921 × 249561089 ≈ 2^56 |
| crtq1 | 268369921 | 28 bits (2^28 - 2^16 + 1) |
| crtq2 | 249561089 | 28 bits (2^28 - 2^21 - 2^12 + 1) |
| Auxiliary modulus (bsMod) | 16760833 | 24 bits (for baby-step/giant-step) |
| Plaintext bits | 16 | p = 2^16 = 65536 |
| Gadget base (Bg) | 2^17 = 131072 | For the primary modulus (50-bit bigMod) |
| Gadget levels (ell) | 3 | For RGSW ciphertexts |
| AutoKey ellnum | 14 | For automorphism keys (default) |

### Composite Modulus via CRT

Fast Spiral represents the ~56-bit modulus as a product of two 28-bit NTT-friendly primes (`crtq1 * crtq2`). Arithmetic is done independently mod each prime and combined via CRT. This enables:
- Efficient NTT using Intel HEXL (28-bit primes fit in 64-bit words with room for lazy reduction)
- No "special prime" for key-switching — the CRT decomposition is for **computation efficiency**, not for noise management

This is a different use of multiple primes than SEAL's RNS: SEAL splits the modulus into RNS components and uses one as a special key-switching prime. Fast Spiral keeps all primes as part of the data modulus.

---

## Automorphism Key Structure

### Per Automorphism Index

Each automorphism key for index `k` consists of:
- **`ellnum` RLWE ciphertexts** `{(a_0, b_0), ..., (a_{ell-1}, b_{ell-1})}`
- Each encrypts: `Enc(sigma_k(s) * Bg^i)` for i = 0, ..., ellnum-1
- Each RLWE ciphertext: 2 polynomials × N coefficients × 8 bytes

### Key Generation (lwe.cpp:446-474)

```
For each gadget level i = 0 to ellnum-1:
    msg = sigma_k(s) * Bg^i        // automorphism of secret × gadget power
    autokey[i] = RLWE_Encrypt(msg)  // standard RLWE encryption under s
```

### Number of Automorphism Indices

For query expansion (AutoKeyRNS::keyGen, lwe.cpp:696-716):
```cpp
for k = 1 to log2(N):
    index = (N >> k << 1) + 1    // = N/2^(k-1) + 1
```
This gives **log2(4096) = 12 indices** for N=4096.

### RNS Variant (AutoKeyRNS)

For the RNS automorphism keys, each index stores **2 × ellnum** RLWE ciphertexts:
- `ellnum` ciphertexts under modulus1 (crtMod)
- `ellnum` ciphertexts under modulus2 (bsMod)

---

## Key Size Estimate

### Single-modulus AutoKey (ellnum = 14, N = 4096, 12 indices)

Per index:
- 14 RLWE CTs × 2 polynomials × 4096 coefficients × 8 bytes = **917,504 bytes** (896 KB)

Total (12 indices):
- 12 × 896 KB = **10,752 KB** (~10.5 MB)

### RNS AutoKey (2 × ellnum = 28 CTs per index)

Per index:
- 28 RLWE CTs × 2 polynomials × 4096 × 8 bytes = **1,835,008 bytes** (1,792 KB)

Total (12 indices):
- 12 × 1,792 KB = **21,504 KB** (~21 MB)

### Comparison with SEAL/OnionPIR

| System | N | Key Size | Key-Switching | Special Prime |
|--------|---|----------|---------------|---------------|
| OnionPIR (SEAL, two-mod) | 2048 | ~606 KB | GHS | Yes (60-bit) |
| OnionPIR (SEAL, single-mod) | 2048 | ~282 KB | GHS | Yes (60-bit) |
| Fast Spiral (single mod) | 4096 | ~10.5 MB | BV (gadget) | No |
| Fast Spiral (RNS) | 4096 | ~21 MB | BV (gadget) | No |

Fast Spiral's keys are **~17-35x larger** than OnionPIR's, primarily because:
1. **No seed compression**: Fast Spiral stores both `a` and `b` polynomials fully (SEAL replaces `a` with a short seed)
2. **No zstd compression**: Raw uint64_t storage
3. **Larger N**: 4096 vs 2048 (2x per polynomial)
4. **More gadget levels**: ellnum=14 vs SEAL's decomp_mod_count=2
5. **No special prime savings**: BV trades smaller per-CT size for more CTs

---

## Key-Switching Algorithm Comparison

### SEAL/OnionPIR (GHS)

```
Input: RLWE ciphertext (a, b) under key s, want to switch to s'
1. Decompose a by RNS residues: a_0 = a mod q_0, a_1 = a mod q_1
2. For each residue j:
     Compute a_j * KSKey[j] (under extended modulus q * q_k)
3. Sum results in extended space
4. Divide out special prime q_k with rounding
Output: RLWE ciphertext under s' with noise ~k * sigma
```

### Fast Spiral (BV)

```
Input: RLWE ciphertext (a, b) under key s, want to switch to s'
1. Decompose a into base-Bg digits: a = sum_i d_i * Bg^i
   (each d_i has small coefficients in [-Bg/2, Bg/2))
2. For each digit i:
     Compute d_i * KSKey[i] (under same modulus q)
3. Sum results
Output: RLWE ciphertext under s' with noise ~ell * Bg * sigma
```

Key difference: BV works in a single modulus (no enlarge-then-divide step), but needs more key material (ell CTs instead of k CTs) to keep the gadget base small enough for acceptable noise.

---

## Gadget Decomposition Details (utils.cpp)

Fast Spiral uses signed gadget decomposition:

```cpp
decompose(result, input, ellnum, base, Bg, modulus):
    offset = Bg/2 * (sum of Bg powers) + base/2   // centering offset
    for each coefficient i:
        d = (input[i] + offset) mod modulus
        d >>= log(base)
        for j = 0 to ellnum-1:
            digit = d & (Bg - 1)          // extract low bits
            digit -= Bg/2                  // center to [-Bg/2, Bg/2)
            result[j][i] = digit mod modulus
            d >>= log(Bg)
```

This is a standard signed-digit decomposition with centering, similar to what's used in TFHE/GSW literature.

---

## Summary

Fast Spiral's approach is **pure BV key-switching**: gadget decomposition in a single modulus, no special prime. The CRT representation (crtq1 × crtq2) is used purely for computational efficiency (NTT-friendly primes), not for key-switching noise reduction. This results in conceptually simpler key-switching but significantly larger key material compared to SEAL's GHS approach with seed compression and zstd.
