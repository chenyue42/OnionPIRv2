# InsPIRe Key-Switching Analysis

## Key-Switching Technique: BV (Gadget Decomposition, No Special Prime)

InsPIRe uses **BV-style key-switching** with gadget decomposition. No special prime is involved — all operations happen within the data modulus.

---

## Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| N (ring dimension) | 2048 | `poly_len` |
| Moduli | 268369921, 249561089 | Two 28-bit NTT-friendly primes |
| Composite modulus q | 268369921 × 249561089 ≈ 2^56 | CRT representation |
| Plaintext modulus p | varies (e.g., 2^15) | |
| t_exp_left | **3** | Number of gadget digits per KSK |
| t_gsw | 3 | For GSW ciphertexts |
| t_conv | 4 | For conversions |
| Noise width | 6.4 (default) | Discrete Gaussian σ |

### CRT Modulus (same primes as Fast Spiral)

The two 28-bit primes are used as a CRT composite modulus for computational efficiency (NTT-friendly), not for key-switching noise reduction. This is identical to Fast Spiral's approach.

---

## KSK Structure: (2 × 3) Matrix = 3 Ciphertexts per Key

Each key-switching key (KSK) is a `PolyMatrixNTT` of shape **(2, t_exp_left) = (2, 3)**:
- **2 rows**: the two RLWE components (row 0 = `b` part, row 1 = `a` part)
- **3 columns**: one per gadget digit

This means each KSK consists of **3 RLWE ciphertexts**, where each ciphertext is a column of the (2 × 3) matrix.

### Key Generation (client.rs:93-118, packing.rs:2820-2842)

Two equivalent generation paths exist:

**Path 1: `raw_generate_expansion_params`** (client.rs:93-118) — generates `poly_len_log2 = 11` KSKs directly:
```
For each automorphism index i = 0 to log2(N)-1:
    t = N / 2^i + 1                          // automorphism element
    tau_sk = automorph(sk, t)                 // apply automorphism to secret key
    prod = tau_sk * g                         // tensor with gadget vector g = [1, z, z^2]
    sample = fresh RLWE encryption of zero    // (2 × t_exp_left) matrix
    KSK[i] = sample + [0; prod]              // add signal to second row
```

**Path 2: `generate_ksk_body`** (packing.rs:2820-2842) — generates a single KSK for a specific automorphism:
```
tau_sk = automorph(sk, gen)
mask = random (1 × t_exp_left) matrix        // the 'a' polynomials
body = -s * mask + error + tau_sk * g         // the 'b' polynomials
KSK = (body, mask)                           // combined (2 × 3) matrix
```

Both produce the same structure: a (2, 3) matrix encrypting `tau_k(s) · g` under the original key `s`.

### Number of KSKs

For query expansion: **`poly_len_log2 = 11` KSKs** (one per level of the expansion tree, for N=2048).

For InsPIRe's packing protocol: typically **2 KSKs** (y_body and z_body), which are then expanded server-side into the full set of 11.

---

## Key-Switching Algorithm (packing.rs:46-76)

The `homomorphic_automorph` function implements BV key-switching:

```
Input: RLWE ct = (ct[0], ct[1]) under key s
       automorphism index t
       KSK W = (2 × t_exp) matrix for automorphism t

1. Apply automorphism:
   ct_auto = (sigma_t(ct[0]), sigma_t(ct[1]))

2. Gadget-decompose the 'a' component (row 1 only):
   ginv = g^{-1}(sigma_t(ct[1]))     // (t_exp × 1) column vector
   // Each entry is a polynomial with small coefficients

3. Multiply KSK by decomposed vector:
   result_ks = W * ginv               // (2 × t_exp) * (t_exp × 1) = (2 × 1)

4. Add back the 'b' component:
   result = (0, sigma_t(ct[0])) + result_ks

Output: RLWE ciphertext under key s (automorphism applied)
```

Note: only `ct[1]` (the `a` component, which is multiplied by `s`) gets decomposed. `ct[0]` (the `b` component) is simply passed through after the automorphism.

---

## Gadget Decomposition (packing.rs:20-44)

**Type**: Unsigned bit decomposition (not signed like Fast Spiral)

```
bits_per = ceil(log2(q) / t_exp_left)    // with q ≈ 2^56, t=3: bits_per = 19
mask = 2^bits_per - 1

For each coefficient:
    val = input coefficient
    For each digit k = 0 to t_exp_left-1:
        digit[k] = (val >> (k * bits_per)) & mask
```

**Gadget vector**: `g = [1, z, z^2]` where `z = 2^{bits_per} ≈ 2^19`

With t_exp_left = 3 and q ≈ 2^56: each 56-bit coefficient is split into 3 digits of ~19 bits each.

---

## Seed Compression

InsPIRe uses **seeded pseudorandom `a` polynomials** (similar to SEAL's seed compression):
- The `mask` (row 0 of KSK, the `a` polynomials) is generated from a ChaCha20 seed
- Only the `body` (row 1, the `b` polynomials) + seed needs to be transmitted
- This roughly halves the KSK communication cost

The `condense_matrix` function (packing.rs:842) packs the two CRT components of each coefficient into a single uint64 for more compact storage.

---

## Key Size Estimate

### Per KSK (2 × 3 matrix, N = 2048, 2 CRT moduli)

**In-memory (full matrix)**:
- 2 rows × 3 cols × 2048 coefficients × 2 CRT moduli × 8 bytes = **196,608 bytes** (192 KB)

**Condensed (CRT packed into single uint64)**:
- 2 × 3 × 2048 × 8 bytes = **98,304 bytes** (96 KB)

**With seed compression (only body row)**:
- 1 row × 3 cols × 2048 × 8 bytes + seed = **~49,152 bytes + 32 bytes** ≈ **48 KB**

### Total for full expansion (11 KSKs)

| Format | Per KSK | Total (11 KSKs) |
|--------|---------|-----------------|
| In-memory | 192 KB | 2,112 KB |
| Condensed | 96 KB | 1,056 KB |
| With seed compression | ~48 KB | ~528 KB |

### Comparison

| System | N | KSK Technique | #KSKs | Total Key Size | Seed Compression |
|--------|---|---------------|-------|----------------|------------------|
| OnionPIR (SEAL, two-mod) | 2048 | GHS (special prime) | 9 | 606 KB | Yes (zstd) |
| OnionPIR (SEAL, single-mod) | 2048 | GHS (special prime) | 9 | 282 KB | Yes (zstd) |
| InsPIRe (3 digits) | 2048 | BV (gadget) | 11 | ~528-1056 KB | Partial (seed) |
| Fast Spiral (14 digits) | 4096 | BV (gadget) | 12 | ~10.5 MB | No |

InsPIRe's key size is comparable to OnionPIR's two-mod config when seed compression is used. The key tradeoff:
- **OnionPIR/SEAL**: 2 CTs per key × 3 RNS limbs (including special prime) = 6 polys per key
- **InsPIRe**: 3 CTs per key × 2 CRT limbs (no special prime) = 6 polys per key (for body only)

The per-key polynomial count is similar! InsPIRe replaces the special prime with one extra gadget digit.

---

## Query Expansion Algorithm

### `pack_single_lwe` (packing.rs:629-649) — Iterative Trace-like Expansion

```
r = input_ct
For i = 0 to log2(N)-1:
    t = N / 2^i + 1                    // automorphism element
    tau_r = homomorphic_automorph(r, t, KSK[i])
    r = r + tau_r
Output: packed RLWE ciphertext
```

This computes a "trace-like" operation: iteratively applies automorphisms and accumulates, similar to computing `Tr_{N→1}(ct)` but with different automorphism elements at each step.

### `pack_lwes_inner` (packing.rs:78-119) — Recursive Binary-Tree Packing

```
pack(ell, start, cts, KSKs):
    if ell == 0: return cts[start]
    ct_even = pack(ell-1, start, cts, KSKs)
    ct_odd  = pack(ell-1, start + 2^(log2(N)-ell), cts, KSKs)

    // Scale odd part by y-constants
    ct_sum = ct_even - y * ct_odd
    ct_even = ct_even + y * ct_odd

    // Apply automorphism with key-switch
    ct_sum_auto = homomorphic_automorph(ct_sum, 2^ell + 1, KSK[...])

    return ct_even + ct_sum_auto
```

This is a recursive binary-tree expansion similar to OnionPIR's `fast_expand_qry`, but uses y-constant scaling instead of negacyclic shifts.

---

## Key Differences from OnionPIR/SEAL

1. **No special prime**: All key material lives under the data modulus (≈2^56 via CRT)
2. **3 gadget digits instead of 2 RNS decomposition components**: Similar total polynomial count
3. **Unsigned bit decomposition**: Simpler than SEAL's RNS decomposition, slightly worse noise
4. **Seed compression via ChaCha20**: The `a` polynomials are pseudorandom, regenerable from seed
5. **Same CRT primes as Fast Spiral**: 268369921 × 249561089 ≈ 2^56
6. **Written in Rust** (using spiral_rs library), not C++
