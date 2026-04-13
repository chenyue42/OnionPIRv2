#include "bv_keyswitch.h"
#include "database_constants.h"
#include "utils.h"
#include "hexl/hexl.hpp"
#include "seal/seal.h"
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace bvks {

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------


// Signed (zero-centered) gadget decomposition.
// Digits are in [-B/2, B/2), stored mod q. Reconstruction: Σ out[i]·B^i ≡ val (mod q).
// out[0] = least significant digit (B^0), out[num_digits-1] = most significant.
void signed_gadget_decompose(uint64_t val, size_t base_log2,
                             uint64_t q, uint64_t *out, size_t num_digits) {
  const uint64_t half_q = q >> 1;
  const int64_t nativeSubgBits = 64 - static_cast<int64_t>(base_log2);

  // Center: [0, q) → (-q/2, q/2]
  int64_t d = (val > half_q)
      ? static_cast<int64_t>(val) - static_cast<int64_t>(q)
      : static_cast<int64_t>(val);

  // The goal here: d = r_0 B^0 + r_1 B^1 + r_2 B^2 + ... with r_i in [-B/2, B/2).

  for (size_t i = 0; i < num_digits; ++i) {
    // Extract signed digit: sign-extend the lowest base_log2 bits
    int64_t r = (d << nativeSubgBits) >> nativeSubgBits;
    d -= r;
    d >>= base_log2;
    out[i] = (r >= 0) ? static_cast<uint64_t>(r)
                      : static_cast<uint64_t>(r + static_cast<int64_t>(q));
  }
}

// Gadget base log: ceil(log_q_data / L_KS).
static inline size_t bv_base_log2(const PirParams &pir_params) {
  const size_t q_bits = pir_params.get_ct_mod_width();
  return (q_bits + L_KS - 1) / L_KS;
}

// Compute (1 << (i * base_log2)) mod q, safely.
static inline uint64_t power_of_two_mod(size_t exp_bits, uint64_t q) {
  // Use repeated doubling mod q so we never overflow.
  uint64_t result = 1 % q;
  for (size_t b = 0; b < exp_bits; ++b) {
    result = (static_cast<uint128_t>(result) << 1) % q;
  }
  return result;
}

// ----------------------------------------------------------------------------
// BvGaloisKeys: lookup, size, simple serialization
// ----------------------------------------------------------------------------

const BvKeySwitchKey &BvGaloisKeys::get(uint32_t galois_k) const {
  for (auto &k : keys) {
    if (k.galois_k == galois_k)
      return k;
  }
  throw std::out_of_range("BvGaloisKeys::get: galois_k not found");
}

bool BvGaloisKeys::has(uint32_t galois_k) const {
  for (auto &k : keys) {
    if (k.galois_k == galois_k)
      return true;
  }
  return false;
}

size_t BvGaloisKeys::compute_size_bytes(size_t num_keys, size_t poly_degree,
                                        size_t log_q_data, bool use_seed) {
  // Bit-packed polynomial size: ceil(N * log_q / 8).
  const size_t per_poly_bytes = (poly_degree * log_q_data + 7) / 8;
  if (use_seed) {
    // 1 poly (b) + 32-byte seed for a.
    return num_keys * L_KS * (per_poly_bytes + 32);
  }
  // Both a and b stored.
  return num_keys * L_KS * 2 * per_poly_bytes;
}

size_t BvGaloisKeys::save(std::ostream &stream, bool /*use_seed*/) const {
  // Simple uint64 dump — not bit-packed. Use compute_size_bytes for the
  // theoretical bit-packed size that we care about in measurements.
  size_t written = 0;
  auto wr = [&](const void *p, size_t n) {
    stream.write(reinterpret_cast<const char *>(p), n);
    written += n;
  };
  uint32_t num = static_cast<uint32_t>(keys.size());
  wr(&num, sizeof(num));
  for (auto &k : keys) {
    wr(&k.galois_k, sizeof(k.galois_k));
    uint32_t t = static_cast<uint32_t>(k.cts.size());
    wr(&t, sizeof(t));
    for (auto &ct : k.cts) {
      uint32_t n = static_cast<uint32_t>(ct.a.size());
      wr(&n, sizeof(n));
      wr(ct.a.data(), n * sizeof(uint64_t));
      wr(ct.b.data(), n * sizeof(uint64_t));
    }
  }
  return written;
}

void BvGaloisKeys::load(std::istream &stream) {
  auto rd = [&](void *p, size_t n) {
    stream.read(reinterpret_cast<char *>(p), n);
  };
  uint32_t num;
  rd(&num, sizeof(num));
  keys.clear();
  keys.resize(num);
  for (auto &k : keys) {
    rd(&k.galois_k, sizeof(k.galois_k));
    uint32_t t;
    rd(&t, sizeof(t));
    k.cts.resize(t);
    for (auto &ct : k.cts) {
      uint32_t n;
      rd(&n, sizeof(n));
      ct.a.resize(n);
      ct.b.resize(n);
      rd(ct.a.data(), n * sizeof(uint64_t));
      rd(ct.b.data(), n * sizeof(uint64_t));
    }
  }
}

// ----------------------------------------------------------------------------
// Key generation (client side)
// ----------------------------------------------------------------------------

BvKeySwitchKey gen_bv_ks_key(const PirParams &pir_params,
                             const seal::SecretKey &sk, uint32_t galois_k,
                             std::mt19937_64 &rng) {
  const double sigma = pir_params.get_noise_std_dev();
  const auto context = pir_params.get_context();
  const auto &ctx_data = *context.key_context_data();
  const auto &parms = ctx_data.parms();
  const size_t rns_mod_cnt = pir_params.get_rns_mod_cnt();
  const size_t N = parms.poly_modulus_degree();

  if (rns_mod_cnt != 1) {
    throw std::runtime_error(
        "BV key-switch currently supports only single RNS limb (rns_mod_cnt == 1)");
  }
  const uint64_t q_val = parms.coeff_modulus()[0].value();
  const size_t base_log2 = bv_base_log2(pir_params);

  // sk is stored in NTT form across all primes. First N coeffs = first limb.
  const uint64_t *sk_ptr = sk.data().data();

  // Compute sigma_k(s) = s(x^k) in NTT form under the data modulus.
  std::vector<uint64_t> sigma_s(N);
  utils::automorphism_ntt(sk_ptr, N, galois_k, q_val, sigma_s.data());

  BvKeySwitchKey ksk;
  ksk.galois_k = galois_k;
  ksk.cts.resize(L_KS);

  std::vector<uint64_t> as(N), msg(N), e(N);

  for (size_t i = 0; i < L_KS; ++i) {
    BvRlweCt &ct = ksk.cts[i];
    ct.a.assign(N, 0);
    ct.b.assign(N, 0);

    // a ← uniform [0, q),  e ← Gaussian(0, sigma)
    utils::sample_uniform_poly(ct.a.data(), N, q_val, rng);
    utils::sample_gaussian(e.data(), N, q_val, sigma, rng);

    // NTT(a), NTT(e) under the data modulus.
    utils::ntt_fwd(ct.a.data(), N, q_val);
    utils::ntt_fwd(e.data(), N, q_val);

    // a * s (pointwise in NTT form)
    intel::hexl::EltwiseMultMod(as.data(), ct.a.data(), sk_ptr, N, q_val, 1);

    // Message: sigma_k(s) * B^i (scalar multiply in NTT form)
    const uint64_t Bi = power_of_two_mod(i * base_log2, q_val);
    intel::hexl::EltwiseFMAMod(msg.data(), sigma_s.data(), Bi, nullptr, N, q_val, 1);

    // b = msg - a*s + e
    intel::hexl::EltwiseSubMod(ct.b.data(), msg.data(), as.data(), N, q_val);
    intel::hexl::EltwiseAddMod(ct.b.data(), ct.b.data(), e.data(), N, q_val);
  }

  return ksk;
}

BvGaloisKeys gen_bv_galois_keys(const PirParams &pir_params,
                                const seal::SecretKey &sk) {
  BvGaloisKeys result;
  const size_t expan_height = pir_params.get_expan_height();
  const size_t N = pir_params.get_seal_params().poly_modulus_degree();

  std::mt19937_64 rng(std::random_device{}());

  result.keys.reserve(expan_height);
  // creates 2049, 1025, 513, ... keys.
  for (size_t i = 0; i < expan_height; ++i) {
    const uint32_t galois_k = static_cast<uint32_t>((N >> i) + 1);
    result.keys.push_back(gen_bv_ks_key(pir_params, sk, galois_k, rng));
  }
  return result;
}

// ----------------------------------------------------------------------------
// Server-side apply
// ----------------------------------------------------------------------------

void bv_apply_galois_inplace(seal::Ciphertext &ct, uint32_t galois_k,
                             const BvKeySwitchKey &key,
                             const PirParams &pir_params) {
  assert(key.galois_k == galois_k);
  // BFV ciphertexts in SEAL are in coefficient form (is_ntt_form = false).
  assert(!ct.is_ntt_form());

  const auto context = pir_params.get_context();
  const auto &ctx_data = *context.get_context_data(ct.parms_id());
  const auto &parms = ctx_data.parms();
  const auto &coeff_modulus = parms.coeff_modulus();
  const size_t N = parms.poly_modulus_degree();
  const size_t rns_mod_cnt = pir_params.get_rns_mod_cnt();
  if (rns_mod_cnt != 1) {
    throw std::runtime_error(
        "bv_apply_galois_inplace currently supports only single RNS limb");
  }
  const auto &mod = coeff_modulus[0];
  const uint64_t q_val = mod.value();
  const size_t base_log2 = bv_base_log2(pir_params);

  // Step 1: apply automorphism to (c0, c1) in coefficient form.
  std::vector<uint64_t> c0_perm(N), c1_perm(N);
  utils::automorphism_coeff(ct.data(0), N, galois_k, q_val, c0_perm.data());
  utils::automorphism_coeff(ct.data(1), N, galois_k, q_val, c1_perm.data());

  // Step 2: signed gadget-decompose σ(c1). Coefficient-first loop for carry propagation.
  std::vector<std::vector<uint64_t>> digits(L_KS, std::vector<uint64_t>(N));
  for (size_t k = 0; k < N; ++k) {
    uint64_t digit_vals[L_KS];
    signed_gadget_decompose(c1_perm[k], base_log2, q_val, digit_vals, L_KS);
    for (size_t i = 0; i < L_KS; ++i) {
      digits[i][k] = digit_vals[i];
    }
  }
  // NTT each digit for the inner product with NTT-form KSK.
  for (size_t i = 0; i < L_KS; ++i) {
    utils::ntt_fwd(digits[i].data(), N, q_val);
  }

  // Step 3: inner product with KSK (NTT form).
  //   Δb = Σ digit_i · ksk.b[i]   (NTT)
  //   Δa = Σ digit_i · ksk.a[i]   (NTT)
  std::vector<uint64_t> delta_b(N, 0);
  std::vector<uint64_t> delta_a(N, 0);
  std::vector<uint64_t> tmp(N);

  for (size_t i = 0; i < L_KS; ++i) {
    const auto &ksk_ct = key.cts[i];
    intel::hexl::EltwiseMultMod(tmp.data(), digits[i].data(), ksk_ct.b.data(), N, q_val, 1);
    intel::hexl::EltwiseAddMod(delta_b.data(), delta_b.data(), tmp.data(), N, q_val);

    intel::hexl::EltwiseMultMod(tmp.data(), digits[i].data(), ksk_ct.a.data(), N, q_val, 1);
    intel::hexl::EltwiseAddMod(delta_a.data(), delta_a.data(), tmp.data(), N, q_val);
  }

  // Step 4: INTT the inner product results back to coefficient form.
  utils::ntt_inv(delta_b.data(), N, q_val);
  utils::ntt_inv(delta_a.data(), N, q_val);

  // Step 5: new_c0 = σ(c0) + Δb,  new_c1 = Δa   (coefficient form)
  intel::hexl::EltwiseAddMod(c0_perm.data(), c0_perm.data(), delta_b.data(), N, q_val);

  // Write back into ct's first RNS limb. Higher limbs left untouched.
  std::memcpy(ct.data(0), c0_perm.data(), N * sizeof(uint64_t));
  std::memcpy(ct.data(1), delta_a.data(), N * sizeof(uint64_t));
  // ct stays in coefficient form (is_ntt_form = false).
}

} // namespace bvks
