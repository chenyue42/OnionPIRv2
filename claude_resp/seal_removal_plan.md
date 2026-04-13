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
**Replaced with:** `utils::ntt_fwd` / `utils::ntt_inv` wrapping `intel::hexl::NTT`  
**Files changed:** `src/includes/utils.h`, `src/utils.cpp`, `src/client.cpp`,
`src/bv_keyswitch.cpp`, `src/gsw_eval.cpp`, `src/tests/test_batch_decomp.cpp`  
**Notes:**
- HEXL and SEAL NTT outputs match byte-for-byte on the same (N, q) — verified in
  `test_hexl_ntt` Test 5 (0/2048 coeffs differ).
- Performance: SEAL 10.87µs, HEXL 10.99µs, `utils::` wrapper 11.05µs — within 2%.
- NTT objects are cached `thread_local` per (N, q), so no locking on the hot path.

### Step 6 — `seal::util::{dyadic_product,add_poly,sub_poly,multiply_poly_scalar}_coeffmod`
**Replaced with:** `intel::hexl::EltwiseMult/Add/Sub/FMAMod`  
**Files changed:** `src/bv_keyswitch.cpp`, `src/client.cpp`, `src/gsw_eval.cpp`  
**Notes:** After this step, `seal/util/polyarithsmallmod.h` removed from all production code.

### Step 7+9 — `seal::util::GaloisTool` (`apply_galois`, `apply_galois_ntt`)
**Replaced with:** `utils::automorphism_coeff`, `utils::automorphism_ntt`  
**Files changed:** `src/includes/utils.h`, `src/utils.cpp`, `src/bv_keyswitch.cpp`  
**Notes:** σ_k maps coefficient i → (i*k) % (2N) with sign flip if wrapped.
Removed `seal/util/galois.h` from bv_keyswitch.cpp entirely.

### Step 8 — `seal::util::right_shift_uint128` / `right_shift_uint` in `gsw_eval.cpp`
**Replaced with:** `utils::right_shift_uint128` (inline in utils.h) and a self-contained
n-limb shift loop for the rns_mod_cnt > 2 path.  
**Files changed:** `src/gsw_eval.cpp`  
**Notes:** `seal::util::RNSBase` (`compose_array`/`decompose_array`) left in place — dead
code for `rns_mod_cnt == 1` (our config). CRT porting deferred.
`ConstCoeffIter` in matrix multiply loop replaced with raw `const uint64_t *`.

### Step 10 — `seal::Modulus` struct
**Replaced with:** `std::vector<uint64_t>` everywhere `get_coeff_modulus()` is used.  
**Files changed:** `src/includes/pir.h`, `src/includes/utils.h`, `src/utils.cpp`,
`src/client.cpp`, `src/gsw_eval.cpp`, `src/server.cpp`,
`src/tests/test_serial.cpp`, `src/tests/test_decrypt_mod_q.cpp`, `src/tests/test_hexl_ntt.cpp`  
**Notes:** `get_coeff_modulus()` now returns `std::vector<uint64_t>`. All `.value()` calls
removed from callers. `seal::Modulus` remains only at SEAL API boundaries
(`set_coeff_modulus`, `EncryptionParameters::coeff_modulus()`).

---

## HEXL equivalents quick reference

| SEAL function | HEXL equivalent |
|---|---|
| `dyadic_product_coeffmod(a, b, N, mod, r)` | `EltwiseMultMod(r, a, b, N, q, 1)` |
| `add_poly_coeffmod(a, b, N, mod, r)` | `EltwiseAddMod(r, a, b, N, q)` |
| `sub_poly_coeffmod(a, b, N, mod, r)` | `EltwiseSubMod(r, a, b, N, q)` |
| `multiply_poly_scalar_coeffmod(a, N, s, mod, r)` | `EltwiseFMAMod(r, a, s, nullptr, N, q, 1)` |
| `ntt_negacyclic_harvey(ptr, tables)` | `utils::ntt_fwd(ptr, N, q)` |
| `inverse_ntt_negacyclic_harvey(ptr, tables)` | `utils::ntt_inv(ptr, N, q)` |
| `right_shift_uint128(ptr, shift, ptr)` | `utils::right_shift_uint128(ptr, shift, ptr)` |
| `apply_galois(in, k, ...)` | `utils::automorphism_coeff(in, N, k, q, out)` |
| `apply_galois_ntt(in, k, ...)` | `utils::automorphism_ntt(in, N, k, q, out)` |

---

## Current State

SEAL utility functions are fully gone from production code. What remains is the **core BFV object
layer**: `seal::Ciphertext`, `seal::Plaintext`, `seal::SecretKey`, `seal::EncryptionParameters`,
`seal::SEALContext`, `seal::Encryptor`, `seal::Decryptor`, `seal::KeyGenerator`.
Also: `sample_poly_uniform` / `sample_poly_cbd` in `bv_keyswitch.cpp` (via `seal/util/rlwe.h`).

---

## Remaining — Phase 2: Core RLWE Objects

### Noise Sampling Comparison (reference codebases)

| Aspect | fspiral | SEAL-For-OnionPIR | Spiral |
|---|---|---|---|
| Algorithm | Ternary `{-1,0,1}` (misnamed sample_guass) | CBD or clipped Gaussian | Table-based discrete Gaussian |
| Real σ | ≈ 0.816 hardcoded | σ=3.2 in globals.h | σ=2.553, constexpr |
| Set σ easily? | No | Edit globals.h + recompile | No |
| PRNG | `rand()` (insecure) | SHAKE-256 (cryptographic, seed-expandable) | `mt19937_64` (not crypto) |
| Key files | `fspiral/src/samples.cpp:38-54` | `SEAL-For-OnionPIR/native/src/seal/util/rlwe.cpp:40-101` | `spiral/src/core.cpp:182-207` |

**Chosen approach:** Rounded Gaussian via `std::normal_distribution<double>` — σ is a runtime
`double` parameter, no recompile needed. `mt19937_64` seeded from `std::random_device` for now;
swap for CSPRNG (ChaCha20/SHAKE-256) for production.

---

### Step 11 — Noise samplers + `seal/util/rlwe.h` (bv_keyswitch.cpp)

**Replace:**
- `sample_poly_uniform(prng, parms, buf)` → `utils::sample_uniform_poly(buf, N, q, rng)`
- `sample_poly_cbd(prng, parms, buf)` → `utils::sample_gaussian(buf, N, q, sigma, rng)`
- SEAL PRNG object → `std::mt19937_64`

Add to `src/includes/utils.h` / `src/utils.cpp`:
```cpp
// e[i] = round(N(0,sigma)) mod q
void sample_gaussian(uint64_t *out, size_t N, uint64_t q, double sigma, std::mt19937_64 &rng);
// a[i] uniformly in [0, q)
void sample_uniform_poly(uint64_t *out, size_t N, uint64_t q, std::mt19937_64 &rng);
// s[i] in {0, 1, q-1}
void sample_ternary(uint64_t *out, size_t N, uint64_t q, std::mt19937_64 &rng);
```

Remove `#include "seal/util/rlwe.h"` from `bv_keyswitch.cpp`.  
Test: `./Onion-PIR --test bv_ks` still passes.  
Add statistical test `test_noise_sampling` (mean ≈ 0, std dev ≈ σ over 10k samples).

---

### Step 12 — `RlweCt`, `RlweSk`, `RlwePt` types (new `src/includes/rlwe.h`)

```cpp
struct RlweCt {
    std::vector<uint64_t> c0, c1;  // N * rns_mod_cnt each
    bool ntt_form = false;
    uint64_t*       data(size_t i)       { return i == 0 ? c0.data() : c1.data(); }
    const uint64_t* data(size_t i) const { return i == 0 ? c0.data() : c1.data(); }
    bool& is_ntt_form() { return ntt_form; }
    void resize(size_t n) { c0.resize(n); c1.resize(n); }
};
struct RlweSk { std::vector<uint64_t> data; };   // ternary, NTT form
struct RlwePt { std::vector<uint64_t> data; };   // plaintext polynomial
```

Matches every `ct.data(0)`, `ct.data(1)`, `ct.is_ntt_form()` call site — minimal churn.

---

### Step 13 — `encrypt_zero_symmetric`, `decrypt`, `gen_secret_key` (new `src/rlwe_enc.h/.cpp`)

Reference: `SEAL-For-OnionPIR/native/src/seal/util/rlwe.cpp:276-406` (full flow).

```cpp
RlweSk gen_secret_key(size_t N, uint64_t q, std::mt19937_64 &rng);

// c0 = -(a*s + e),  c1 = a  (both in NTT form when ntt_form=true)
void encrypt_zero(const RlweSk &sk, size_t N, uint64_t q, double sigma,
                  std::mt19937_64 &rng, RlweCt &ct, bool ntt_form = false);

// pt[i] = round((c0[i] + c1[i]*s[i]) * t / q) mod t
void decrypt(const RlweCt &ct, const RlweSk &sk, size_t N, uint64_t q, uint64_t t, RlwePt &pt);
```

Test: `./Onion-PIR --test rlwe_enc` — encrypt-then-decrypt round-trip for zero and nonzero messages.

---

### Step 14 — Replace `seal::Ciphertext` breadth-first (one file per sub-step)

Order: `gsw_eval` → `bv_keyswitch` → `client` → `server` → `pir`

- `evaluator_.transform_to_ntt_inplace(ct)` → `for (mod) utils::ntt_fwd(ct.data(i) + mod*N, N, q_mods[mod])`
- `evaluator_.transform_from_ntt_inplace(ct)` → same with `ntt_inv`
- `encryptor_.encrypt_zero_symmetric(ct)` → `encrypt_zero(sk, N, q, sigma, rng, ct)`
- `decryptor_.decrypt(ct, pt)` → `decrypt(ct, sk, N, q, t, pt)`
- `ct.resize(context, 2)` → `ct.resize(N * rns_mod_cnt)`
- `parms_id` references → removed (no longer needed)

Build + `./Onion-PIR pir` (must stay at 14/14) after each file.

---

### Step 15 — Replace `seal::EncryptionParameters` + `seal::SEALContext` in `pir.h`

`PirParams` currently holds `seal_params_` and `context_` as members. Replace with:

```cpp
struct RlweParams {
    size_t N;        // poly degree
    uint64_t q;      // ciphertext modulus (primary prime)
    uint64_t t;      // plaintext modulus
    double sigma;    // noise std dev
};
```

All `get_seal_params()` / `get_context()` callers updated to use direct accessors.

---

### Step 16 — Remove SEAL from CMakeLists.txt

```cmake
# Remove:  target_link_libraries(... SEAL::seal)
# Remove:  find_package(SEAL ...)
```

Verify: `nm build/Onion-PIR | grep -i seal` returns empty.

---

## Verification at each step

```bash
cd /u/yuec12/OnionPIRv2/build && make -j$(nproc)
./Onion-PIR pir          # 14/14 success
./Onion-PIR --test bv_ks
./Onion-PIR --test hexl_ntt   # 5/5
./Onion-PIR --test utils_arith  # 34/34
```

Final: `nm build/Onion-PIR | grep seal` → empty.

---

## Reference code locations

| File | Purpose |
|---|---|
| `/u/yuec12/SEAL-For-OnionPIR/native/src/seal/util/rlwe.cpp:276-406` | `encrypt_zero_symmetric` full flow |
| `/u/yuec12/SEAL-For-OnionPIR/native/src/seal/util/rlwe.cpp:21-38` | `sample_poly_ternary` (secret key) |
| `/u/yuec12/SEAL-For-OnionPIR/native/src/seal/util/globals.h:34-40` | σ=3.2 parameterization |
| `/u/yuec12/spiral/src/client.cpp:147-192` | `getRegevSample` + `encryptSimpleRegev` |
| `/u/yuec12/spiral/src/core.cpp:182-207` | Table-based discrete Gaussian sampler |
| `/u/yuec12/fspiral/src/samples.cpp:38-54` | Minimal ternary noise (structure reference) |
