#include "bv_keyswitch.h"
#include "database_constants.h"
#include "utils.h"
#include "hexl/hexl.hpp"
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

void approx_signed_gadget_decompose(uint64_t val, size_t base_log2,
                                    uint64_t q, size_t q_bits,
                                    uint64_t *out, size_t num_digits) {
  const size_t rep_bits = num_digits * base_log2;
  assert(rep_bits <= q_bits);
  const size_t drop = q_bits - rep_bits;

  // Center to (-q/2, q/2].
  const uint64_t half_q = q >> 1;
  int64_t d = (val > half_q)
      ? static_cast<int64_t>(val) - static_cast<int64_t>(q)
      : static_cast<int64_t>(val);

  // Round to nearest multiple of 2^drop, then divide by 2^drop (sign-preserving).
  if (drop > 0) {
    const int64_t half = int64_t(1) << (drop - 1);
    d = (d >= 0) ? ((d + half) >> drop)
                 : -(((-d) + half) >> drop);
  }

  // Standard signed base-B decomposition on the (now small) rounded value.
  // |d| ≤ 2^rep_bits / 2, so all digits fit signed in int64.
  const int64_t nativeSubgBits = 64 - static_cast<int64_t>(base_log2);
  for (size_t i = 0; i < num_digits; ++i) {
    int64_t r = (d << nativeSubgBits) >> nativeSubgBits;
    d -= r;
    d >>= base_log2;
    out[i] = (r >= 0) ? static_cast<uint64_t>(r)
                      : static_cast<uint64_t>(r + static_cast<int64_t>(q));
  }
}

// Gadget base log: floor(log_q_data / L_KS) + 1.
// The +1 guarantees B^L_KS > q, giving the signed-digit decomposition
// enough headroom to absorb carries without leaving a non-zero residue in
// the discarded (L_KS-th) digit. Without it, configurations where
// base_log2 * L_KS == q_bits (e.g. L_KS=10 or 12 at q ~ 2^60) leak an
// uncompensated sigma_k(s) * (B^L_KS mod q) term into the keyswitch noise.
// Matches Spiral's convention (spiral/include/util.h:get_bits_per).
static inline size_t bv_base_log2(const PirParams &pir_params) {
  const size_t q_bits = pir_params.get_ct_mod_width();
  return q_bits / L_KS + 1;
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

// bool BvGaloisKeys::has(uint32_t galois_k) const {
//   for (auto &k : keys) {
//     if (k.galois_k == galois_k)
//       return true;
//   }
//   return false;
// }

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

// size_t BvGaloisKeys::save(std::ostream &stream, bool /*use_seed*/) const {
//   // Simple uint64 dump — not bit-packed. Use compute_size_bytes for the
//   // theoretical bit-packed size that we care about in measurements.
//   size_t written = 0;
//   auto wr = [&](const void *p, size_t n) {
//     stream.write(reinterpret_cast<const char *>(p), n);
//     written += n;
//   };
//   uint32_t num = static_cast<uint32_t>(keys.size());
//   wr(&num, sizeof(num));
//   for (auto &k : keys) {
//     wr(&k.galois_k, sizeof(k.galois_k));
//     uint32_t t = static_cast<uint32_t>(k.cts.size());
//     wr(&t, sizeof(t));
//     for (auto &ct : k.cts) {
//       uint32_t n = static_cast<uint32_t>(ct.a.size());
//       wr(&n, sizeof(n));
//       wr(ct.a.data(), n * sizeof(uint64_t));
//       wr(ct.b.data(), n * sizeof(uint64_t));
//     }
//   }
//   return written;
// }

// void BvGaloisKeys::load(std::istream &stream) {
//   auto rd = [&](void *p, size_t n) {
//     stream.read(reinterpret_cast<char *>(p), n);
//   };
//   uint32_t num;
//   rd(&num, sizeof(num));
//   keys.clear();
//   keys.resize(num);
//   for (auto &k : keys) {
//     rd(&k.galois_k, sizeof(k.galois_k));
//     uint32_t t;
//     rd(&t, sizeof(t));
//     k.cts.resize(t);
//     for (auto &ct : k.cts) {
//       uint32_t n;
//       rd(&n, sizeof(n));
//       ct.a.resize(n);
//       ct.b.resize(n);
//       rd(ct.a.data(), n * sizeof(uint64_t));
//       rd(ct.b.data(), n * sizeof(uint64_t));
//     }
//   }
// }

// ----------------------------------------------------------------------------
// Key generation (client side)
// ----------------------------------------------------------------------------

BvKeySwitchKey gen_bv_ks_key(const PirParams &pir_params,
                             const RlweSk &sk, uint32_t galois_k,
                             std::mt19937_64 &rng) {
  const double sigma = pir_params.get_noise_std_dev();
  const size_t rns_mod_cnt = pir_params.get_rns_mod_cnt();
  constexpr size_t N = DBConsts::PolyDegree;

  assert(rns_mod_cnt == 1 &&
         "BV key-switch currently supports only single RNS limb (rns_mod_cnt == 1)");
  const uint64_t q_val = pir_params.get_rns_mods()[0];
  const size_t base_log2 = bv_base_log2(pir_params);

  // sk is stored in NTT form across all primes. First N coeffs = first limb.
  const uint64_t *sk_ptr = sk.data.data();

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
                                const RlweSk &sk) {
  BvGaloisKeys result;
  const size_t expan_height = pir_params.get_expan_height();
  constexpr size_t N = DBConsts::PolyDegree;

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

// scratch reused across calls to bv_apply_galois_inplace.
namespace {
struct GaloisScratch {
  std::vector<uint64_t> c0_perm, c1_perm, delta_a, delta_b, tmp;
  std::vector<uint64_t> digits;  // L_KS contiguous N-blocks (row-major)
};
static GaloisScratch g_scratch;
}  // namespace

void bv_apply_galois_inplace(RlweCt &ct, uint32_t galois_k,
                             const BvKeySwitchKey &key,
                             const PirParams &pir_params) {
  assert(key.galois_k == galois_k);
  // BFV ciphertexts are in coefficient form (is_ntt_form = false).
  assert(!ct.ntt_form);

  constexpr size_t N = DBConsts::PolyDegree;
  const size_t rns_mod_cnt = pir_params.get_rns_mod_cnt();
  assert(rns_mod_cnt == 1 &&
         "bv_apply_galois_inplace currently supports only single RNS limb");
  const uint64_t q_val = pir_params.get_rns_mods()[0];
  const size_t base_log2 = bv_base_log2(pir_params);

  // Use a shared scratch struct to amortize heap allocations across calls.
  GaloisScratch &s = g_scratch;
  if (s.c0_perm.size() != N) {
    s.c0_perm.resize(N);
    s.c1_perm.resize(N);
    s.delta_a.resize(N);
    s.delta_b.resize(N);
    s.tmp.resize(N);
    s.digits.resize(L_KS * N);
  }
  uint64_t *const c0_perm = s.c0_perm.data();
  uint64_t *const c1_perm = s.c1_perm.data();
  uint64_t *const delta_b = s.delta_b.data();
  uint64_t *const delta_a = s.delta_a.data();
  uint64_t *const tmp = s.tmp.data();
  uint64_t *const digits = s.digits.data();

  // Step 1: apply automorphism to (c0, c1) in coefficient form.
  utils::automorphism_coeff(ct.data(0), N, galois_k, q_val, c0_perm);
  utils::automorphism_coeff(ct.data(1), N, galois_k, q_val, c1_perm);

  // Step 2: signed gadget-decompose σ(c1) into a row-major L_KS×N buffer.
  // Ultimately, we want decomp(a) \cdot ks_keys using inner product. NTT is used to speed up.
  for (size_t k = 0; k < N; ++k) {
    uint64_t digit_vals[L_KS];
    signed_gadget_decompose(c1_perm[k], base_log2, q_val, digit_vals, L_KS);
    for (size_t i = 0; i < L_KS; ++i) {
      digits[i * N + k] = digit_vals[i];
    }
  }

  // Steps 3-fused: for each digit, NTT it then multiply-accumulate into Δb, Δa.
  // Keeping the digit polynomial hot in cache between NTT and the two MultMods.
  // First iteration writes (instead of accumulating) to skip a zero-init pass.
  {
    uint64_t *digit0 = digits;
    utils::ntt_fwd(digit0, N, q_val);
    intel::hexl::EltwiseMultMod(delta_b, digit0, key.cts[0].b.data(), N, q_val, 1);
    intel::hexl::EltwiseMultMod(delta_a, digit0, key.cts[0].a.data(), N, q_val, 1);
  }
  for (size_t i = 1; i < L_KS; ++i) {
    uint64_t *digit_i = digits + i * N;
    utils::ntt_fwd(digit_i, N, q_val);
    const auto &ksk_ct = key.cts[i];
    intel::hexl::EltwiseMultMod(tmp, digit_i, ksk_ct.b.data(), N, q_val, 1);
    intel::hexl::EltwiseAddMod(delta_b, delta_b, tmp, N, q_val);
    intel::hexl::EltwiseMultMod(tmp, digit_i, ksk_ct.a.data(), N, q_val, 1);
    intel::hexl::EltwiseAddMod(delta_a, delta_a, tmp, N, q_val);
  }

  // Step 4: INTT the inner product results back to coefficient form.
  utils::ntt_inv(delta_b, N, q_val);
  utils::ntt_inv(delta_a, N, q_val);

  // Step 5: new_c0 = σ(c0) + Δb,  new_c1 = Δa   (coefficient form)
  intel::hexl::EltwiseAddMod(c0_perm, c0_perm, delta_b, N, q_val);

  // Write back into ct's first RNS limb. Higher limbs left untouched.
  std::memcpy(ct.data(0), c0_perm, N * sizeof(uint64_t));
  std::memcpy(ct.data(1), delta_a, N * sizeof(uint64_t));
  // ct stays in coefficient form (is_ntt_form = false).
}

} // namespace bvks
