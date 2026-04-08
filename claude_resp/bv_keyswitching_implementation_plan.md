# Implementation Plan: Custom BV Key-Switching in OnionPIRv2

## Goal
Replace SEAL's GHS Galois key-switching with custom BV implementation, keeping everything else in OnionPIRv2 intact. The only algorithmic change is at the two `evaluator_.apply_galois_inplace` call sites in `server.cpp` (inside `expand_query` and `fast_expand_qry`).

## Design Choice: Option B — Keep `[28, 28]` CRT (drop the 60-bit special prime)

- Minimal changes to the existing PIR pipeline (DB storage, first-dim eval, GSW, mod switching already tuned for this CRT layout)
- The only complication is RNS gadget decomposition, but `gsw_eval.cpp:107-181` (`GSWEval::decomp_rlwe`) already has a reference implementation for RNS-form decomposition

---

## Phase 1: Data Structures

**New files:** `src/includes/bv_keyswitch.h` and `src/bv_keyswitch.cpp`

```cpp
// One key-switching key for one automorphism σ_k
struct BvKeySwitchKey {
  uint32_t galois_elt;
  // T_KS RLWE ciphertexts, each encrypting σ_k(s) · B^i
  // Stored in NTT form for fast key-switching
  std::vector<seal::Ciphertext> cts;
};

// Collection of 9 BvKeySwitchKey, one per expansion level
class BvGaloisKeys {
public:
  std::vector<BvKeySwitchKey> keys;
  const BvKeySwitchKey& get(uint32_t galois_elt) const;

  // Serialization with manual bit-packing
  size_t save(std::ostream &stream, bool use_seed) const;
  void load(std::istream &stream, const seal::SEALContext &ctx);

  // Manual size calculation (no SEAL serializer dependency)
  static size_t compute_size_bytes(size_t num_keys, size_t t_ks,
                                   size_t poly_degree, size_t log_q,
                                   bool use_seed);
};
```

Add `T_KS` (number of gadget digits, typically 3) to `database_constants.h`.

---

## Phase 2: Key Generation (Client-Side)

**New function:** `BvGaloisKeys PirClient::create_bv_galois_keys()`

For each of the 9 automorphisms (`galois_elt = N/k + 1` for `k = 1, 2, 4, ..., 256`):

1. Compute `σ_k(s)` — apply automorphism to secret key polynomial (coefficient permutation)
2. For gadget level `i = 0 .. T_KS-1`:
   - Sample uniform random `a` (NTT form)
   - Sample small error `e`
   - Compute `b = -(a·s) + e + σ_k(s) · B^i (mod q)`  (all NTT form)
   - Store `(b, a)` as a `seal::Ciphertext` with 2 RNS limbs
3. Bundle the T_KS ciphertexts into a `BvKeySwitchKey`

**Key primitives** (all `seal::util::*`, already used in `gsw_eval.cpp`):
- `ntt_negacyclic_harvey` / `inverse_ntt_negacyclic_harvey`
- `dyadic_product_coeffmod`, `add_poly_coeffmod`, `sub_poly_coeffmod`, `negate_poly_coeffmod`
- Error sampling: reuse SEAL's noise sampler

---

## Phase 3: Server-Side Key-Switching

**New function:** `void bv_apply_galois_inplace(seal::Ciphertext &ct, uint32_t galois_elt, const BvKeySwitchKey &key, const seal::SEALContext &ctx)`

Algorithm (direct port of Rust POC's `eval_automorph`):

1. Transform `ct` to coefficient form if in NTT form
2. Apply automorphism σ_k to `c0` and `c1` using `seal::util::apply_galois` on each RNS limb
3. Gadget-decompose `σ_k(c1)` into T_KS digit polynomials — **reuse decomposition pattern from `GSWEval::decomp_rlwe`**
4. Forward NTT each digit polynomial
5. Compute inner product with KSK (both operands in NTT form):
   - `new_c0 += Σ_i  digit_i · ksk.cts[i].c0`
   - `new_c1  = Σ_i  digit_i · ksk.cts[i].c1`
6. Add `σ_k(c0)` to `new_c0`
7. Store result back into `ct`

---

## Phase 4: Integration with fast_expand_qry

- Replace the two `evaluator_.apply_galois_inplace(...)` calls at `server.cpp:395-396,436-438`
- Replace `std::map<size_t, seal::GaloisKeys> client_galois_keys_` → `std::map<size_t, BvGaloisKeys> client_bv_galois_keys_`
- Replace client-side `create_galois_keys(stream)` → `create_bv_galois_keys(stream)`
- Replace server-side setter accordingly

---

## Phase 5: Manual Size Measurement

```cpp
size_t raw_size  = num_keys * T_KS * 2 * N * ceil(log2(q)) / 8;
size_t seed_size = num_keys * T_KS * (N * ceil(log2(q)) / 8 + 32);
```

For `[28, 28]`, N=2048, T_KS=3, 9 keys:
- Per polynomial: 2048 × 56 / 8 = 14,336 bytes
- Per KSK: 3 × (14,336 + 32) = 43,104 bytes (seed-compressed)
- **Total: ≈ 380 KB**

---

## Phase 6: Parameter Configuration

1. Add `CONFIG_BV_TWO_MOD_56` in `database_constants.h` with `coeff_modulus = [28-bit, 28-bit]` (no 60-bit special prime)
2. Verify SEAL accepts this configuration for encrypt_symmetric, NTT, decrypt
3. Verify `mod_switch_to_next_inplace` and custom `mod_switch_inplace` still work

**Risk:** SEAL may assume the last prime is special. Verify early.

---

## Phase 7: Testing & Validation

1. **Unit test — single key-switch**: encrypt known plaintext, apply BV automorphism, decrypt, verify equals expected σ_k(plaintext)
2. **Expansion test**: use BV keys in `fast_expand_qry`, verify all 512 expanded ciphertexts decrypt correctly
3. **Full PIR test**: run `test_pir.cpp` with 13 experiments, expect 13/13 success
4. **Size measurement**: print manually-calculated BV size; compare with 378 KB Rust POC target

---

## Critical Risks

1. **SEAL without special prime** — verify before any coding
2. **Noise budget** — BV has higher per-switch noise (B ≈ 2^19 vs GHS's √N·σ); may exhaust budget over 9 levels + first-dim + other-dim
3. **RNS gadget decomposition correctness** — Rust POC used single prime; write a unit test decomposing + recomposing before integration

---

## File-Level Changes

| File | Change |
|------|--------|
| `src/includes/bv_keyswitch.h` | **NEW** — `BvKeySwitchKey`, `BvGaloisKeys` |
| `src/bv_keyswitch.cpp` | **NEW** — key gen, apply_galois, serialize, size |
| `src/includes/database_constants.h` | Add `T_KS`, new config |
| `src/includes/client.h` | Add `create_bv_galois_keys` |
| `src/client.cpp` | Implement BV key gen |
| `src/includes/server.h` | Replace Galois keys map |
| `src/server.cpp` | Replace `apply_galois_inplace` calls |
| `src/tests/test_pir.cpp` | Print manually-calculated key size |
| `CMakeLists.txt` | Add new source file |
