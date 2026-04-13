# SEAL Removal Progress & Plan

Goal: replace SEAL's utility functions with self-contained alternatives, working from the outermost
leaves (pure math helpers) inward (core objects: SEALContext, Ciphertext, KeyGenerator).

---

## Completed

### Step 1 — `seal::util::try_invert_uint_mod`
**Replaced with:** `utils::try_invert_uint_mod` (extended Euclidean, ~20 lines, no dependencies)  
**Files changed:** `src/includes/utils.h`, `src/utils.cpp`, `src/client.cpp`  
**Notes:** Also added `utils::is_prime` (deterministic Miller-Rabin, 12 fixed witnesses, proven
for all 64-bit n). Test: `./Onion-PIR --test utils_arith` — 34/34 cases pass.

### Step 2 — `seal::util::CoeffIter` / `ConstCoeffIter` in `negacyclic_shift_poly_coeffmod`
**Replaced with:** raw `uint64_t *` / `const uint64_t *` pointers; `seal::Modulus` → `uint64_t`  
**Files changed:** `src/includes/utils.h`, `src/utils.cpp`  
**Notes:** The iterators were thin pointer wrappers. `set_uint` replaced with `std::memcpy`.

### Step 3 — `seal::util::dyadic_product_coeffmod` / `add_poly_coeffmod` in `decrypt_mod_q`
**Replaced with:** `intel::hexl::EltwiseMultMod`, `intel::hexl::EltwiseAddMod`  
**Files changed:** `src/client.cpp`

### Step 4 — `seal::util::is_prime` in `utils::generate_prime`
**Replaced with:** `utils::is_prime` (self-contained, see Step 1).

### Step 5 — `seal::util::ntt_negacyclic_harvey` / `inverse_ntt_negacyclic_harvey`
**Replaced with:** `utils::ntt_negacyclic_harvey(data, N, q)` wrapping `intel::hexl::NTT`  
**Files changed:** `src/includes/utils.h`, `src/utils.cpp`, `src/client.cpp`,
`src/bv_keyswitch.cpp`, `src/gsw_eval.cpp`, `src/tests/test_batch_decomp.cpp`  
**Notes:**
- HEXL and SEAL NTT outputs match byte-for-byte on the same (N, q) — verified in
  `test_hexl_ntt` Test 5 (0/2048 coeffs differ).
- Performance: SEAL 10.87µs, HEXL 10.99µs, `utils::` wrapper 11.05µs — within 2%.
- NTT objects are cached `thread_local` per (N, q), so no locking on the hot path.
- `small_ntt_tables()` calls are gone from all production code.

---

## Completed (continued)

### Step 6 — `seal::util::{dyadic_product,add_poly,sub_poly,multiply_poly_scalar}_coeffmod`

These are polyarithsmallmod helpers currently used in `bv_keyswitch.cpp` and the scalar-multiply
in the key-generation path. All take a `const seal::Modulus &mod`.

| SEAL function | HEXL equivalent | Notes |
|---|---|---|
| `dyadic_product_coeffmod(a, b, N, mod, r)` | `EltwiseMultMod(r, a, b, N, q, 1)` | Hot path in `bv_apply_galois_inplace` |
| `add_poly_coeffmod(a, b, N, mod, r)` | `EltwiseAddMod(r, a, b, N, q)` | Hot path |
| `sub_poly_coeffmod(a, b, N, mod, r)` | `EltwiseSubMod(r, a, b, N, q)` | Keygen path |
| `multiply_poly_scalar_coeffmod(a, N, s, mod, r)` | `utils::scale_poly_mod` (manual loop) | No HEXL equivalent; scalar s is uint64_t, not a poly |

`EltwiseSubMod` and `EltwiseFMAMod` are in HEXL's public API (`hexl/hexl.hpp`).
`multiply_poly_scalar_coeffmod` has no direct HEXL replacement — we add a small
`utils::scale_poly_mod(a, N, scalar, q, result)` that does a 128-bit multiply loop.

After this step, `seal/util/polyarithsmallmod.h` and `seal/util/ntt.h` removed from `bv_keyswitch.cpp`.
PIR test: 13/13. BV keyswitch unit test: PASS.

---

## In Progress

---

## Remaining (future rounds)

### Step 7 — `seal::util::CoeffIter` / `ConstCoeffIter` in `bv_keyswitch.cpp`
Still used in `galois_tool->apply_galois` and `apply_galois_ntt` calls. These are SEAL iterator
wrappers around raw pointers. Removing them requires replacing `galois_tool` (Step 9).

### Step 8 — `seal::util::RNSBase`, `right_shift_uint128`, `right_shift_uint` in `gsw_eval.cpp`
Used in the gadget decomposition (`decompose_rlwe`). `right_shift_uint128` is just `>> p`.
`RNSBase::compose_array` / `decompose_array` handle CRT combination — a larger lift.

### Step 9 — `seal::util::GaloisTool` in `bv_keyswitch.cpp`
`apply_galois` and `apply_galois_ntt` implement the automorphism x → x^k on a polynomial.
The automorphism is a coefficient permutation (no arithmetic), well-specified in the BFV paper.
Implementation: for power k and ring degree N, coefficient i maps to index (i*k) % (2N),
with sign flip if the index wrapped. ~30 lines, no SEAL needed.

### Step 10 — `seal::Modulus` struct
Currently passed by reference to all SEAL arithmetic calls. After Steps 6–8 eliminate those
calls, `seal::Modulus` survives only as a thin wrapper for `.value()`. At that point every
remaining use can be changed to `uint64_t` directly.

### Step 11 — Core SEAL objects (large lift, separate phase)
`seal::SEALContext`, `seal::Ciphertext`, `seal::Plaintext`, `seal::KeyGenerator`,
`seal::Encryptor`, `seal::Decryptor`, `seal::SecretKey`. These are the BFV scheme itself.
Replacing them means owning the full key-generation, encryption, and decryption pipeline.
Suitable after Steps 6–10 have reduced SEAL's footprint to just these objects.
