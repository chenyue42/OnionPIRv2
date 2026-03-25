# Galois Key Analysis

## Q1: Galois key structure in the fast_expand test

**Question:** How many galois keys are used, the corresponding degrees of each, the size of each, and the number of ciphertexts contained in each galois key?

**Answer (under `CONFIG_TWO_MOD_56`: CoeffMods = {28, 28, 60}):**

### (1) Number of Galois keys: 9

One per level of the expansion tree (`TREE_HEIGHT = 9`).

### (2) Galois elements (degrees)

The element for level `i` is `1 + N/2^i` where N = 2048:

| Level | Galois element | Automorphism |
|-------|---------------|--------------|
| 0 | 2049 | x -> x^2049 |
| 1 | 1025 | x -> x^1025 |
| 2 | 513 | x -> x^513 |
| 3 | 257 | x -> x^257 |
| 4 | 129 | x -> x^129 |
| 5 | 65 | x -> x^65 |
| 6 | 33 | x -> x^33 |
| 7 | 17 | x -> x^17 |
| 8 | 9 | x -> x^9 |

Generated in `client.cpp:285-287`.

### (3) Size of each Galois key: 192 KB (196,608 bytes in memory)

Each key is identical in structure:
- 2 ciphertexts x 2 polynomials x 2048 coefficients x 3 RNS moduli x 8 bytes = 196,608 bytes

Total in-memory: 9 x 192 KB = 1,728 KB.
Serialized (with seed compression): ~605 KB (620,164 bytes).

### (4) Number of BFV ciphertexts per Galois key: 2

This equals `decomp_mod_count` = `first_context_data()->parms().coeff_modulus().size()` = 2 (the two 28-bit ciphertext moduli, excluding the 60-bit special key-switching modulus). Each of these 2 ciphertexts lives under the **key context** with all 3 RNS moduli (28 + 28 + 60 bits), so each ciphertext has `ct.size()=2` polynomials with `coeff_mod_size=3`.

---

## Q2: Why 3 RNS moduli? Single-mod comparison and serialization gap

**Question:** Why do the Galois keys need 3 RNS moduli? Since the first two modulus are 28 bits, each ciphertext should compress to 65536B, giving total ~576KB. Where is the gap? Also try the single mod setting (CoeffMods = {56, 60}).

### Why the 60-bit special prime in Galois keys?

The 60-bit "special prime" is required by SEAL's key-switching algorithm. During `apply_galois`:
1. The ciphertext is decomposed into `decomp_mod_count` pieces
2. Each piece is multiplied with the corresponding Galois key ciphertext (which lives under the **key context** with all moduli including the special prime)
3. The results are summed in the extended modulus space (q0 x q1 x q_special)
4. The special prime is then divided out (and rounded), bringing the result back to the data context (q0 x q1)

This "temporarily enlarge, then scale down" trick keeps the noise from key-switching small. Without the special prime, the rounding noise would be much larger relative to q.

### Comparison: Single-mod vs Two-mod

| Property | Single-mod (56-bit) | Two-mod (28+28 bit) |
|---|---|---|
| key_coeff_modulus_size | 2 (56 + 60) | 3 (28 + 28 + 60) |
| decomp_mod_count (CTs/key) | 1 | 2 |
| Bytes per CT | 2x2048x2x8 = 64 KB | 2x2048x3x8 = 96 KB |
| In-memory per Galois key | 64 KB | 192 KB |
| In-memory total (9 keys) | 576 KB | 1,728 KB |
| Serialized total | 282 KB | 605 KB |

### Why the gap between in-memory and serialized?

The serialized size is much smaller because of **seeded ciphertexts**. When `save_seed=true` (the default in `keygenerator.cpp:180`), SEAL replaces the second polynomial (c1) of each ciphertext with a short random seed. Since c1 is pseudorandomly generated, the receiver can regenerate it from the seed. This roughly halves the serialized size:

- Single-mod: 576 KB in-memory -> ~282 KB serialized (~49%)
- Two-mod: 1,728 KB in-memory -> ~605 KB serialized (~35%)

### Why does two-mod need more Galois key material?

The `decomp_mod_count` equals the number of data-level RNS moduli. In two-mod mode there are 2 ciphertext moduli (q0, q1), so SEAL decomposes the ciphertext into 2 components (one per modulus) and needs a separate key-switching ciphertext for each. Each of those ciphertexts lives under the key context (all 3 moduli including the special prime), which is why each CT has `coeff_mod_size=3`.

In single-mod mode, there's only 1 ciphertext modulus, so only 1 decomposition component -> 1 CT per Galois key, each with `coeff_mod_size=2` (the 56-bit data mod + 60-bit special mod).

---

## Q3: Is the special prime data in the serialized Galois keys? Can we remove it?

**Question:** Is the data under the special prime also included in the serialized Galois keys? If it is deterministic, can we remove it and add it back later?

### What gets serialized

The **query ciphertext** does NOT contain the special prime — it lives under the data context only.

The **Galois keys** DO contain the special prime in their serialized form. Each Galois key ciphertext `(b, a)` is serialized as:
- `b` polynomial under ALL key moduli (q0, q1, q_k) — fully stored
- `a` polynomial — replaced by a short seed (since `a` is pseudorandom)

### Can the server reconstruct `b mod q_k`?

No, because:
1. `b mod q_k = -a*s + e mod q_k`
2. The server can regenerate `a` from the seed
3. But the server does NOT know `s` (the secret key), so it cannot compute `a*s mod q_k`
4. The error `e` is fresh randomness baked into `b`
5. The RNS components are computed independently per modulus, so `b mod q_k` cannot be derived from `b mod q0` and `b mod q1` via CRT (they don't together cover the full range `q0*q1*q_k`)

The special prime component is **non-deterministic from the server's perspective** and must be transmitted. It accounts for roughly 1/3 of the `b` polynomial data in the two-mod case.

### How `switch_key_inplace` uses the special prime (SEAL source: evaluator.cpp:2523-2820)

The key-switching algorithm works in 3 steps:

1. **Compute inner product in extended space** (lines 2616-2709): For each RNS modulus (including q_k), compute `result[I] = sum_J (c_J * KSKey_J[I])`. This produces a result under `q0 * q1 * q_k`.

2. **Extract q_k component** (lines 2762-2770, BFV case): `t_last = result mod q_k`, apply INTT, add `q_k/2` for rounding.

3. **Divide out q_k** (lines 2772-2816): For each data modulus q_i, compute `output_i = q_k^{-1} * (result_i - t_last mod q_i) mod q_i`. This computes `round(result / q_k) mod q`.

The Galois key encrypts `s' * q_k` (not just `s'`), so the inner product gives `s' * q_k + e_ks`. After dividing by q_k: `s' + e_ks/q_k + rounding_error`. The rounding error is O(1), and `e_ks/q_k` is small because the large special prime suppresses the key-switching noise.

---

## Q4: Can we avoid the special prime entirely? (BV-style key-switching)

**Question:** You mentioned digit-decomposition-based key-switching without a special prime. What is it? Does it give smaller size? What are the estimated savings?

### Two key-switching approaches

SEAL uses the **GHS key-switching** technique introduced in:

> Craig Gentry, Shai Halevi, and Nigel P. Smart. **"Homomorphic Evaluation of the AES Circuit."** CRYPTO 2012, LNCS 7417, pp. 850-867.
> - ePrint: https://eprint.iacr.org/2012/099
> - Section 2.3 introduces this key-switching variant.

The alternative is the **BV key-switching** technique from:

> Zvika Brakerski and Vinod Vaikuntanathan. **"Fully Homomorphic Encryption from Ring-LWE and Security for Key Dependent Messages."** CRYPTO 2011, LNCS 6841, pp. 505-524.

**GHS-style (what SEAL uses):**
- Decompose ciphertext by RNS residues: one component per data-level modulus
- Key CTs live under extended modulus `q * q_k` (includes special prime)
- Key-switching noise: ~k * sigma, where k = number of data moduli, sigma = error std dev
- Number of key CTs per Galois key = k (the decomp_mod_count)

**BV-style (no special prime):**
- Decompose each coefficient into base-B digits: `d = ceil(log_B(q))` digits
- Key CTs live under modulus `q` only (no special prime)
- Key-switching noise: ~d * B * sigma
- Number of key CTs per Galois key = d

### The tradeoff: it is NOT a free lunch

The special prime exists precisely because it eliminates the factor B from the noise. For the two-mod case (q ~ 2^56):

| Approach | #CTs/key | RNS mods/CT | Noise | Serialized b-poly per CT |
|---|---|---|---|---|
| GHS (SEAL) | 2 | 3 (28+28+60) | 2 * sigma | 2048 x 3 x 8 = 48 KB |
| BV, B=2^28 | 2 | 2 (28+28) | 2 * 2^28 * sigma ~ 5e8 sigma | 2048 x 2 x 8 = 32 KB |
| BV, B=2^14 | 4 | 2 (28+28) | 4 * 2^14 * sigma ~ 65536 sigma | 2048 x 2 x 8 = 32 KB |
| BV, B=2^7 | 8 | 2 (28+28) | 8 * 128 * sigma = 1024 sigma | 2048 x 2 x 8 = 32 KB |

To match GHS noise (2 * sigma), you'd need `d * B ~ 2`, which is impossible with integer B > 1. BV always has worse noise than GHS for the same q.

### Estimated size comparison (9 Galois keys, N=2048, two-mod)

**GHS (current):** Each key = 2 CTs x (48 KB b-poly + seed) ~ 96 KB/key -> 864 KB raw, **605 KB serialized** (with SEAL compression).

**BV with B=2^28 (same #CTs, terrible noise):** Each key = 2 CTs x (32 KB b-poly + seed) ~ 64 KB/key -> 576 KB raw, **~400 KB serialized**. Saves ~33%, but noise is 2^28 times worse — would destroy the ciphertext.

**BV with B=2^7 (reasonable noise ~1024 * sigma):** Each key = 8 CTs x (32 KB b-poly + seed) ~ 256 KB/key -> 2304 KB raw, **~1600 KB serialized**. Actually 2.6x LARGER to keep noise manageable.

### Bottom line

Removing the special prime saves 1/3 of the per-CT data (one RNS component). But to compensate for the noise increase, you need either:
- **More digits (larger d)** -> more key CTs -> net size increase
- **Accept more noise** -> but there are only 29-30 bits of noise budget after expansion, so there's no room

The special prime trades ~200 KB of extra key material for a ~500x reduction in key-switching noise. For PIR where noise budget is already tight, this is a very good trade.

Libraries like **Lattigo** and **OpenFHE** offer the option to disable the special prime, but it's mainly useful when parameters are large enough that the extra noise is tolerable.

---

## Q5: Serialization format — are 28-bit coefficients stored compactly?

**Question:** For the two-mod case, is the serialization saving the coefficients mod 28-bit q's in uint64_t or uint32_t? Is it really compact?

### SEAL's serialization format

SEAL stores every coefficient as a **raw uint64_t** (8 bytes), regardless of the actual modulus bit width. This is confirmed in `dynarray.h:664`:

```cpp
stream.write(reinterpret_cast<const char *>(cbegin()),
             util::safe_cast<std::streamsize>(util::mul_safe(size_, sizeof(T))));
```

where `T = uint64_t` (`ct_coeff_type`). For a 28-bit modulus, each coefficient wastes 36 zero high bits per uint64_t.

### Compression via Zstandard

SEAL compensates by applying **Zstandard (zstd)** compression on top (configured in `config.h`: `#define SEAL_USE_ZSTD`). The zero high bits compress well, which is why the serialized sizes are significantly smaller than raw:

For one seeded Galois key CT (b-poly only, two-mod case):
- Raw b-poly: 2048 coeffs x 3 RNS mods x 8 bytes = **49,152 bytes**
- Bit-exact: 2048 x (28 + 28 + 60) / 8 = **29,696 bytes** (theoretical minimum)
- Measured per CT: ~605 KB / 18 CTs ~ **33,600 bytes** (zstd gets close to theoretical)

### Size breakdown

| Layer | Per CT (b-poly) | Total (9 keys x 2 CTs) |
|---|---|---|
| In-memory (uint64_t) | 49,152 bytes | 884,736 bytes (864 KB) |
| Bit-exact (no waste) | 29,696 bytes | 534,528 bytes (522 KB) |
| Serialized (zstd) | ~33,600 bytes | ~605 KB (measured) |

So zstd recovers most of the wasted bits but adds a small overhead above theoretical bit-packing, roughly 10-15% above the ideal. A custom bit-packed format could save an additional ~80 KB over SEAL's serialization, but would require bypassing SEAL's serialization entirely.
