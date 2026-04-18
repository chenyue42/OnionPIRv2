#include "rlwe.h"
#include "utils.h"
#include "hexl/hexl.hpp"
#include <cmath>
#include <cstring>

RlweSk gen_secret_key(size_t N, uint64_t q, std::mt19937_64 &rng) {
  RlweSk sk;
  sk.data.resize(N);
  utils::sample_ternary(sk.data.data(), N, q, rng);
  utils::ntt_fwd(sk.data.data(), N, q);
  return sk;
}

void encrypt_zero(const RlweSk &sk, size_t N, uint64_t q, double sigma,
                  std::mt19937_64 &rng, RlweCt &ct, bool ntt_form) {
  ct.resize(N);

  // Sample a ← U([0, q)) and e ← Gaussian(0, sigma²), both in coefficient form.
  utils::sample_uniform_poly(ct.c1.data(), N, q, rng);
  std::vector<uint64_t> e(N);
  utils::sample_gaussian(e.data(), N, q, sigma, rng);

  // Compute a*s in NTT form. sk is already NTT.
  std::vector<uint64_t> a_ntt(N);
  std::memcpy(a_ntt.data(), ct.c1.data(), N * sizeof(uint64_t));
  utils::ntt_fwd(a_ntt.data(), N, q);
  intel::hexl::EltwiseMultMod(ct.c0.data(), a_ntt.data(), sk.data.data(), N, q, 1);

  // Bring a*s back to coefficient form so we can add e (which is in coef).
  utils::ntt_inv(ct.c0.data(), N, q);

  // c0 = (a*s) + e, then negate: c0 = -(a*s + e).
  intel::hexl::EltwiseAddMod(ct.c0.data(), ct.c0.data(), e.data(), N, q);
  const std::vector<uint64_t> zeros(N, 0);
  intel::hexl::EltwiseSubMod(ct.c0.data(), zeros.data(), ct.c0.data(), N, q);

  if (ntt_form) {
    utils::ntt_fwd(ct.c0.data(), N, q);
    utils::ntt_fwd(ct.c1.data(), N, q);
  }
  ct.ntt_form = ntt_form;
}

void decrypt(const RlweCt &ct, const RlweSk &sk, size_t N, uint64_t q,
             uint64_t t, RlwePt &pt) {
  // We need c0 in coefficient form and c1 in NTT form (for pointwise mult with sk).
  std::vector<uint64_t> c0_coef(N), c1_ntt(N);
  std::memcpy(c0_coef.data(), ct.c0.data(), N * sizeof(uint64_t));
  std::memcpy(c1_ntt.data(),  ct.c1.data(), N * sizeof(uint64_t));

  if (ct.ntt_form) {
    utils::ntt_inv(c0_coef.data(), N, q);
  } else {
    utils::ntt_fwd(c1_ntt.data(), N, q);
  }

  // phase = c1 * s (NTT pointwise), then INTT back to coefficient form.
  std::vector<uint64_t> phase(N);
  intel::hexl::EltwiseMultMod(phase.data(), c1_ntt.data(), sk.data.data(), N, q, 1);
  utils::ntt_inv(phase.data(), N, q);

  // phase = c0 + c1*s  (coefficient form, values in [0, q)).
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), c0_coef.data(), N, q);

  // Scale-and-round q → t (centered, integer-exact). Same as round(phase*t/q) mod t.
  pt.data.resize(N);
  for (size_t i = 0; i < N; i++) {
    pt.data[i] = utils::rescale(phase[i], q, t);
  }
}

int decrypt_and_budget(const RlweCt &ct, const RlweSk &sk, size_t N,
                       uint64_t q, uint64_t t, RlwePt &pt) {
  std::vector<uint64_t> c0_coef(N), c1_ntt(N);
  std::memcpy(c0_coef.data(), ct.c0.data(), N * sizeof(uint64_t));
  std::memcpy(c1_ntt.data(),  ct.c1.data(), N * sizeof(uint64_t));
  if (ct.ntt_form) {
    utils::ntt_inv(c0_coef.data(), N, q);
  } else {
    utils::ntt_fwd(c1_ntt.data(), N, q);
  }
  std::vector<uint64_t> phase(N);
  intel::hexl::EltwiseMultMod(phase.data(), c1_ntt.data(), sk.data.data(), N, q, 1);
  utils::ntt_inv(phase.data(), N, q);
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), c0_coef.data(), N, q);

  pt.data.resize(N);
  const uint64_t delta = q / t;
  const uint64_t half_q = q / 2;
  uint64_t max_noise = 0;
  for (size_t i = 0; i < N; i++) {
    uint64_t m = utils::rescale(phase[i], q, t);
    pt.data[i] = m;
    uint64_t approx = static_cast<uint64_t>((__uint128_t)delta * m % q);
    uint64_t noise_pos = (phase[i] >= approx) ? (phase[i] - approx) : (q - approx + phase[i]);
    uint64_t noise_abs = (noise_pos > half_q) ? (q - noise_pos) : noise_pos;
    if (noise_abs > max_noise) max_noise = noise_abs;
  }
  return (max_noise > 0)
    ? static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t * max_noise)))
    : static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t)));
}

void encrypt_bfv(const std::vector<uint64_t> &m, const RlweSk &sk,
                 size_t N, uint64_t q, uint64_t t, double sigma,
                 std::mt19937_64 &rng, RlweCt &ct) {
  encrypt_zero(sk, N, q, sigma, rng, ct, /*ntt_form=*/false);
  const uint64_t delta = q / t;
  for (size_t i = 0; i < N && i < m.size(); i++) {
    const uint64_t scaled = (__uint128_t)delta * (m[i] % t) % q;
    ct.c0[i] = (ct.c0[i] + scaled) % q;
  }
}

void rlwe_add_inplace(RlweCt &a, const RlweCt &b, uint64_t q) {
  const size_t n = a.poly_size();
  intel::hexl::EltwiseAddMod(a.c0.data(), a.c0.data(), b.c0.data(), n, q);
  intel::hexl::EltwiseAddMod(a.c1.data(), a.c1.data(), b.c1.data(), n, q);
}

void rlwe_sub_inplace(RlweCt &a, const RlweCt &b, uint64_t q) {
  const size_t n = a.poly_size();
  intel::hexl::EltwiseSubMod(a.c0.data(), a.c0.data(), b.c0.data(), n, q);
  intel::hexl::EltwiseSubMod(a.c1.data(), a.c1.data(), b.c1.data(), n, q);
}

void rlwe_add(const RlweCt &a, const RlweCt &b, RlweCt &c, uint64_t q) {
  const size_t n = a.poly_size();
  c.c0.resize(n);
  c.c1.resize(n);
  intel::hexl::EltwiseAddMod(c.c0.data(), a.c0.data(), b.c0.data(), n, q);
  intel::hexl::EltwiseAddMod(c.c1.data(), a.c1.data(), b.c1.data(), n, q);
  c.ntt_form = a.ntt_form;
}

void rlwe_sub(const RlweCt &a, const RlweCt &b, RlweCt &c, uint64_t q) {
  const size_t n = a.poly_size();
  c.c0.resize(n);
  c.c1.resize(n);
  intel::hexl::EltwiseSubMod(c.c0.data(), a.c0.data(), b.c0.data(), n, q);
  intel::hexl::EltwiseSubMod(c.c1.data(), a.c1.data(), b.c1.data(), n, q);
  c.ntt_form = a.ntt_form;
}

void rlwe_ntt_fwd_inplace(RlweCt &ct, uint64_t q, size_t N) {
  utils::ntt_fwd(ct.c0.data(), N, q);
  utils::ntt_fwd(ct.c1.data(), N, q);
  ct.ntt_form = true;
}

void rlwe_ntt_inv_inplace(RlweCt &ct, uint64_t q, size_t N) {
  utils::ntt_inv(ct.c0.data(), N, q);
  utils::ntt_inv(ct.c1.data(), N, q);
  ct.ntt_form = false;
}

void rlwe_shift(const RlweCt &src, RlweCt &dst, size_t index, uint64_t q, size_t N) {
  if (&dst != &src) {
    dst.c0.resize(N);
    dst.c1.resize(N);
    dst.ntt_form = src.ntt_form;
  }
  utils::negacyclic_shift_poly_coeffmod(src.c0.data(), N, index, q, dst.c0.data());
  utils::negacyclic_shift_poly_coeffmod(src.c1.data(), N, index, q, dst.c1.data());
}
