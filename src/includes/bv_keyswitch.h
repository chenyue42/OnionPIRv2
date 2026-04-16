#pragma once

#include "pir.h"
#include "rlwe.h"
#include <vector>
#include <cstdint>
#include <iosfwd>
#include <random>

// ============================================================================
// BV-Style Galois Key-Switching (No Special Prime)
// ============================================================================
//
// This module implements Brakerski-Vaikuntanathan (BV) key-switching for
// Galois automorphisms, replacing SEAL's GHS-based key-switching in the
// query expansion step.
//
// Unlike GHS, BV does not use a special prime. Each key-switching key is a
// set of L_KS RLWE ciphertexts encrypting σ_k(s) · B^i (for i = 0..L_KS-1)
// under the *data* modulus q_data (the first rns_mod_cnt primes of the SEAL
// coeff_modulus, excluding the last "special" prime which SEAL normally uses
// for GHS).
//
// Key-switch operation:
//   σ_k(ct) = (σ_k(c0) + Σ d_i · ksk.b[i],  Σ d_i · ksk.a[i])
// where d_i = gadget_decompose(σ_k(c1))[i] and all products are in NTT form.
//
// For the currently active single-RNS-limb configuration (CONFIG_SECURE:
// coeff_modulus = {56, 60}), rns_mod_cnt == 1 and gadget decomposition is a
// straightforward bit-shift on uint64 coefficients.

namespace bvks {

// Number of gadget digits per key-switching key.
constexpr size_t L_KS = 8;

// A single RLWE ciphertext under the data modulus, stored in NTT form.
// Layout: rns_mod_cnt * N uint64s per polynomial component.
struct BvRlweCt {
  std::vector<uint64_t> a; // size = rns_mod_cnt * N
  std::vector<uint64_t> b; // size = rns_mod_cnt * N
};

// Key-switching key for one automorphism σ_k.
// Contains L_KS RLWE ciphertexts encrypting σ_k(s) · B^i.
struct BvKeySwitchKey {
  uint32_t galois_k = 0;
  std::vector<BvRlweCt> cts; // size = L_KS
};

// Collection of BV key-switching keys, one per expansion-level automorphism.
class BvGaloisKeys {
public:
  std::vector<BvKeySwitchKey> keys;

  const BvKeySwitchKey &get(uint32_t galois_k) const;
  bool has(uint32_t galois_k) const;

  // Serialize all keys to a stream.
  // If use_seed is true, store a 32-byte seed per KSK ciphertext instead of
  // the full `a` polynomial (which must then be regenerated on load).
  // Returns the total number of bytes written.
  size_t save(std::ostream &stream, bool use_seed = false) const;

  // Deserialize keys from a stream.
  void load(std::istream &stream);

  // Compute the hand-calculated serialized size (bit-packed coefficients).
  //   raw:  num_keys * L_KS * 2 * N * ceil(log2(q_data)) / 8
  //   seed: num_keys * L_KS * (N * ceil(log2(q_data)) / 8 + 32)
  static size_t compute_size_bytes(size_t num_keys, size_t poly_degree,
                                   size_t log_q_data, bool use_seed);
};

// ============================================================================
// Key generation (client side)
// ============================================================================

// Generate a single BV key-switching key for automorphism σ_{galois_k}
// under secret key `sk`. The secret key must be in NTT form.
// Error σ is read from pir_params.get_noise_std_dev().
BvKeySwitchKey gen_bv_ks_key(const PirParams &pir_params,
                             const RlweSk &sk, uint32_t galois_k,
                             std::mt19937_64 &rng);

// Generate a full set of BV key-switching keys for all expansion-level
// automorphisms. Error σ is read from pir_params.get_noise_std_dev().
BvGaloisKeys gen_bv_galois_keys(const PirParams &pir_params,
                                const RlweSk &sk);

// ============================================================================
// Gadget decomposition
// ============================================================================

// Signed (zero-centered) gadget decomposition of a single coefficient.
// Input:  val ∈ [0, q), base_log2, q, num_digits
// Output: num_digits digits (out[0]=B^0, out[num_digits-1]=most significant),
//         each stored mod q, representing a signed digit in [-B/2, B/2).
// Reconstruction: Σ out[i] · B^i ≡ val (mod q).
void signed_gadget_decompose(uint64_t val, size_t base_log2,
                             uint64_t q, uint64_t *out, size_t num_digits);

// ============================================================================
// Key-switching operation (server side)
// ============================================================================

// Apply automorphism σ_k to `ct` and key-switch back to the original secret key
// using BV. Modifies `ct` in place. `ct` must be in NTT form on entry and will
// be in NTT form on return.
//
// Only operates on the first rns_mod_cnt limbs (data modulus). Any special
// prime limbs are left untouched.
void bv_apply_galois_inplace(RlweCt &ct, uint32_t galois_k,
                             const BvKeySwitchKey &key,
                             const PirParams &pir_params);

} // namespace bvks
