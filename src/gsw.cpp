#include "gsw.h"
#include "utils.h"
#include "logging.h"
#include "bv_keyswitch.h"
#include "database_constants.h"
#include "hexl/hexl.hpp"
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace {

// Native RNS ↔ multi-precision conversions (CRT), replacing
// seal::util::RNSBase::compose_array / decompose_array. Only K=2 is actually
// reached by any of our configs (RnsMods contains at most 3 entries, the
// last being the "special" modulus that is excluded from the RNS base).
// A K=1 call is a no-op since the layout already matches.

// RNS → multi-precision, in-place.
// Before: buf[i*N + k] = coeff_k mod q_i, for i in [0, K), k in [0, N).
// After:  buf[k*K + i] = limb_i (little-endian) of the CRT composition.
void compose_rns_to_mp(uint64_t *buf, size_t N,
                       const std::vector<uint64_t> &moduli, size_t K,
                       const RnsTables &tables) {
  if (K <= 1) return;
  if (K != 2) {
    throw std::runtime_error("compose_rns_to_mp: only K=1 or K=2 supported");
  }
  const uint64_t q0 = moduli[0];
  const uint64_t q1 = moduli[1];
  const uint64_t q0_inv_mod_q1 = tables.q0_inv_mod_q1;

  // Snapshot the two RNS rows; transpose then overwrites buf in K=2 layout.
  std::vector<uint64_t> r0(buf + 0 * N, buf + 0 * N + N);
  std::vector<uint64_t> r1(buf + 1 * N, buf + 1 * N + N);

  for (size_t k = 0; k < N; k++) {
    const uint64_t r0k = r0[k];
    const uint64_t r1k = r1[k];
    // diff = (r1 - (r0 mod q1)) mod q1
    const uint64_t r0_mod_q1 = r0k % q1;
    const uint64_t diff = (r1k + q1 - r0_mod_q1) % q1;
    // s = diff * q0^{-1} mod q1; s ∈ [0, q1)
    const uint64_t s = static_cast<uint64_t>(
        (static_cast<uint128_t>(diff) * q0_inv_mod_q1) % q1);
    // x = r0 + q0 * s  fits in 128 bits since q0 * s < q0 * q1.
    const uint128_t x = static_cast<uint128_t>(q0) * s + r0k;
    buf[k * 2 + 0] = static_cast<uint64_t>(x);
    buf[k * 2 + 1] = static_cast<uint64_t>(x >> 64);
  }
}

// Multi-precision → RNS, in-place.
// Before: buf[k*K + i] = limb_i (little-endian) of a K-limb integer.
// After:  buf[i*N + k] = value_k mod q_i.
void decompose_mp_to_rns(uint64_t *buf, size_t N,
                         const std::vector<uint64_t> &moduli, size_t K,
                         const RnsTables &tables) {
  if (K <= 1) return;
  if (K != 2) {
    throw std::runtime_error("decompose_mp_to_rns: only K=1 or K=2 supported");
  }
  const uint64_t q0 = moduli[0];
  const uint64_t q1 = moduli[1];
  const uint64_t r64_mod_q0 = tables.r64_mod_q[0];
  const uint64_t r64_mod_q1 = tables.r64_mod_q[1];

  std::vector<uint64_t> lo(N), hi(N);
  for (size_t k = 0; k < N; k++) {
    lo[k] = buf[k * 2 + 0];
    hi[k] = buf[k * 2 + 1];
  }

  for (size_t k = 0; k < N; k++) {
    const uint64_t L = lo[k];
    const uint64_t H = hi[k];
    // x mod q = ((H mod q) * (2^64 mod q) + (L mod q)) mod q.
    const uint64_t m0 = static_cast<uint64_t>(
        (static_cast<uint128_t>(H % q0) * r64_mod_q0 + (L % q0)) % q0);
    const uint64_t m1 = static_cast<uint64_t>(
        (static_cast<uint128_t>(H % q1) * r64_mod_q1 + (L % q1)) % q1);
    buf[0 * N + k] = m0;
    buf[1 * N + k] = m1;
  }
}

} // namespace

// Here we compute a cross product between the transpose of the decomposed BFV
// (a 2l vector of polynomials) and the GSW ciphertext (a 2lx2 matrix of
// polynomials) to obtain a size-2 vector of polynomials, which is exactly our
// result ciphertext. We use an NTT multiplication to speed up polynomial
// multiplication, assuming that both the GSWCt and decomposed bfv is in
// polynomial coefficient representation.


void GSWEval::gsw_ntt_forward(GSWCt &gsw) {
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t K = pir_params_.K();
  const auto &rns_mods = pir_params_.get_rns_mods();

  // Each poly holds c0||c1, each split into K limbs of coeff_count.
  for (auto &poly : gsw) {
    for (size_t i = 0; i < 2 * K; i++) {
      utils::ntt_fwd(poly.data() + coeff_count * i, coeff_count,
                     rns_mods[i % K]);
    }
  }
}

void GSWEval::external_product(GSWCt const &gsw_enc, RlweCt const &bfv,
                              RlweCt &res_ct,
                              LogContext context) {
  const auto& log_keys = ext_log_keys(context);

  // ============================ Parameters ============================
  const size_t K = pir_params_.K();
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t coeff_val_cnt = DBConsts::PolyDegree * K; // polydegree * RNS moduli count

  // ============================ Decomposition ============================
  // MP gadget: 2 * l_ rows in either K=1 or K=2. Reuse the per-instance scratch
  // (sized once) so the thousands of external products don't each heap-allocate
  // the decomposition rows.
  const size_t gsw_rows = 2 * l_;
  if (ep_decomp_.size() != gsw_rows) ep_decomp_.assign(gsw_rows, std::vector<uint64_t>(coeff_val_cnt));
  else for (auto &row : ep_decomp_) if (row.size() != coeff_val_cnt) row.assign(coeff_val_cnt, 0);
  std::vector<std::vector<uint64_t>> &decomposed_bfv = ep_decomp_;
  TIME_START(log_keys.decomp);
  if (K == 1) {
    decomp_rlwe_single_mod(bfv, decomposed_bfv, context);
  } else {
    decomp_rlwe_mp(bfv, decomposed_bfv, context);
  }
  TIME_END(log_keys.decomp);

  // Transform decomposed coefficients to NTT form
  decomp_to_ntt(decomposed_bfv, context);

  // ============================ Polynomial Matrix Multiplication ============================
  // result = decomp(bfv) [1 x 2l] * gsw [2l x 2], accumulated per output poly and
  // per RNS limb using HEXL's vectorized modular mult/add (AVX-512), matching the
  // BV-keyswitch inner-product path. Writes straight into res_ct -- no 128-bit
  // intermediate, no scalar % reduction. res_ct may alias bfv: safe because the
  // decomposition above already captured bfv's coefficients.
  TIME_START(log_keys.matmul);
  const auto &rns_mods = pir_params_.get_rns_mods();
  if (ep_tmp_.size() != coeff_count) ep_tmp_.resize(coeff_count);
  uint64_t *const tmp = ep_tmp_.data();
  for (size_t k = 0; k < 2; ++k) {
    uint64_t *out = res_ct.data(k);
    for (size_t mod_id = 0; mod_id < K; ++mod_id) {
      const uint64_t qk = rns_mods[mod_id];
      const size_t off = mod_id * coeff_count;
      // Row 0 initialises the accumulator; subsequent rows multiply-then-add.
      intel::hexl::EltwiseMultMod(out + off, decomposed_bfv[0].data() + off,
                                  gsw_enc[0].data() + k * coeff_val_cnt + off,
                                  coeff_count, qk, 1);
      for (size_t j = 1; j < gsw_rows; ++j) {
        intel::hexl::EltwiseMultMod(tmp, decomposed_bfv[j].data() + off,
                                    gsw_enc[j].data() + k * coeff_val_cnt + off,
                                    coeff_count, qk, 1);
        intel::hexl::EltwiseAddMod(out + off, out + off, tmp, coeff_count, qk);
      }
    }
  }
  TIME_END(log_keys.matmul);
  res_ct.is_ntt_form() = true;  // the result of two NTT form polynomials is still in NTT form.
}

void GSWEval::decomp_rlwe_mp(RlweCt const &ct, std::vector<std::vector<uint64_t>> &output,
                         LogContext context) {
  const auto& log_keys = ext_log_keys(context);

  // ============================ Parameters ============================
  // `output` is the caller's reusable scratch, pre-sized to 2*l_ rows of
  // coeff_val_cnt each; we write digit rows in place (no allocation here).
  assert(output.size() == 2 * l_);
  // Setup parameters
  const uint64_t base = uint64_t(1) << base_log2_;
  const uint64_t mask = base - 1;
  const auto &rns_mods = pir_params_.get_rns_mods();
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t K = pir_params_.K();
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt();
  std::vector<uint64_t> ct_coeffs(coeff_val_cnt);

  // ============================ Decomposition ============================
  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    // we need a copy because we need to compose the array. This copy is very fast.
    memcpy(ct_coeffs.data(), ct.data(poly_id), coeff_val_cnt * sizeof(uint64_t));
    TIME_START(log_keys.compose);
    // Transform the coefficients from RNS form to multi-precision integer form
    // (little-endian limbs, K limbs per coefficient).
    // ! compose / decompose are slow when K > 1 because of the per-coeff CRT work.
    compose_rns_to_mp(ct_coeffs.data(), coeff_count, rns_mods, K,
                      pir_params_.get_rns_tables());
    TIME_END(log_keys.compose);

    // we right shift certain amount to match the GSW ciphertext. Rows are
    // MSB-first: p = l_-1 (largest shift) lands in this poly's row 0.
    for (size_t p = l_; p-- > 0;) { // loop from l_ - 1 to 0.
      std::vector<uint64_t> &res = output[poly_id * l_ + (l_ - 1 - p)];
      memcpy(res.data(), ct_coeffs.data(), coeff_val_cnt * sizeof(uint64_t));
      TIME_START(log_keys.right_shift);
      for (size_t k = 0; k < coeff_count; k++) {
        uint64_t* res_ptr = res.data() + k * K;
        if (K == 2) {
            utils::right_shift_uint128(res_ptr, p * base_log2_, res_ptr);
            res_ptr[0] &= mask;
            res_ptr[1] = 0;
        } else {
          // Generic n-limb little-endian right shift (only reached for K > 2).
          const size_t shift = p * base_log2_;
          const size_t word_shift = shift / 64;
          const size_t bit_shift  = shift % 64;
          for (size_t i = 0; i < K; i++) {
            uint64_t lo = (i + word_shift     < K) ? res_ptr[i + word_shift]     : 0;
            uint64_t hi = (i + word_shift + 1 < K) ? res_ptr[i + word_shift + 1] : 0;
            res_ptr[i] = (bit_shift == 0) ? lo : (lo >> bit_shift) | (hi << (64 - bit_shift));
          }
          res_ptr[0] &= mask;
          for (size_t i = 1; i < K; i++) {
            res_ptr[i] = 0;
          }
        }
      }
      TIME_END(log_keys.right_shift);
      TIME_START(log_keys.decomp_inner);
      decompose_mp_to_rns(res.data(), coeff_count, rns_mods, K,
                          pir_params_.get_rns_tables());
      TIME_END(log_keys.decomp_inner);
    }
  }
}

void GSWEval::decomp_rlwe_single_mod(RlweCt const &ct, std::vector<std::vector<uint64_t>> &output,
                                   LogContext /*context*/) {
  // ============================ Parameters ============================
  // `output` is the caller's reusable scratch, pre-sized to 2*l_ rows of
  // coeff_count each; we write digits in place (no allocation here).
  // Vectorized signed decomposition: instead of decomposing one coefficient at a
  // time (the bvks::signed_gadget_decompose primitive, kept for the
  // keyswitch/tests), we extract one DIGIT across the whole polynomial at a time.
  // The carry chain is serial across digits, but all N coefficients within a
  // digit are independent, so the inner loops auto-vectorize (AVX-512). The math
  // mirrors the scalar primitive exactly (balanced digits, MSB-first).
  assert(output.size() == 2 * l_);
  constexpr size_t N = DBConsts::PolyDegree;
  const uint64_t q = pir_params_.get_rns_mods()[0];
  const int64_t qi = static_cast<int64_t>(q);
  const uint64_t half_q = q >> 1;
  const int64_t native = 64 - static_cast<int64_t>(base_log2_);

  if (ep_dwork_.size() != N) ep_dwork_.resize(N);
  int64_t *const d = ep_dwork_.data();

  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    const uint64_t *poly_ptr = ct.data(poly_id);
    const size_t base_row = poly_id * l_;

    // Center [0, q) -> (-q/2, q/2].
    for (size_t k = 0; k < N; ++k) {
      const int64_t v = static_cast<int64_t>(poly_ptr[k]);
      d[k] = (poly_ptr[k] > half_q) ? v - qi : v;
    }

    // Digit i is the B^i coefficient (extracted LSB-first); store MSB-first, so
    // it lands in row (l_-1-i). Poly 0 -> rows [0,l_), poly 1 -> rows [l_,2*l_).
    for (size_t i = 0; i < l_; ++i) {
      uint64_t *const outrow = output[base_row + (l_ - 1 - i)].data();
      for (size_t k = 0; k < N; ++k) {
        const int64_t r = (d[k] << native) >> native;  // balanced low digit
        d[k] = (d[k] - r) >> static_cast<int64_t>(base_log2_);
        outrow[k] = (r >= 0) ? static_cast<uint64_t>(r)
                             : static_cast<uint64_t>(r + qi);
      }
    }
  }
}

void GSWEval::decomp_to_ntt(std::vector<std::vector<uint64_t>> &decomp_coeffs,
                           LogContext context) {
  const auto& log_keys = ext_log_keys(context);

  // ============================ Parameters ============================
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t K = pir_params_.K();
  const auto rns_mods = pir_params_.get_rns_mods();

  // ============================ NTT Transformation ============================
  TIME_START(log_keys.ntt);
  for (auto &coeffs : decomp_coeffs) {
    for (size_t i = 0; i < K; i++) {
      utils::ntt_fwd(coeffs.data() + coeff_count * i, coeff_count,
                                    rns_mods[i]);
    }
  }
  TIME_END(log_keys.ntt);
}

void GSWEval::query_to_gsw(std::vector<RlweCt> query, GSWCt gsw_key,
                           GSWCt &output) {
  const size_t curr_l = query.size();
  output.resize(curr_l);
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t K = pir_params_.K();

  // We get the first half directly from the query
  for (size_t i = 0; i < curr_l; i++) {
    for (size_t j = 0; j < coeff_count * K; j++) {
      output[i].push_back(query[i].data(0)[j]);
    }
    for (size_t j = 0; j < coeff_count * K; j++) {
      output[i].push_back(query[i].data(1)[j]);
    }
  }
  gsw_ntt_forward(output);  // And the first half should be in NTT form
  
  // The second half is computed using external product.
  output.resize(2 * curr_l);
  // We use external product to get the second half
  for (size_t i = 0; i < curr_l; i++) {
    TIME_START(CONVERT_EXTERN);
    external_product(gsw_key, query[i], query[i], LogContext::QUERY_TO_GSW);
    TIME_END(CONVERT_EXTERN);
    for (size_t j = 0; j < coeff_count * K; j++) {
      output[i + curr_l].push_back(query[i].data(0)[j]);
    }
    for (size_t j = 0; j < coeff_count * K; j++) {
      output[i + curr_l].push_back(query[i].data(1)[j]);
    }
  }
}

GSWCt GSWEval::plain_to_gsw(std::vector<uint64_t> const &plaintext,
                                    const RlweSk &sk, std::mt19937_64 &rng) {
  constexpr size_t N = DBConsts::PolyDegree;
  const size_t K = pir_params_.K();
  const auto &rns_mods_arr = pir_params_.get_rns_mods();
  const std::vector<uint64_t> qs(rns_mods_arr.begin(), rns_mods_arr.end());
  assert(plaintext.size() == N);

  const double sigma = pir_params_.get_noise_std_dev();

  // MP gadget table: gadget_table[k][p] = B^(l_-1-p) mod q_k, MSB-first
  // (p=0 = largest power B^(l_-1)).
  std::vector<std::vector<uint64_t>> gadget_table =
      utils::gsw_gadget(l_, base_log2_, rns_mods_arr);

  const size_t rows_per_half = l_;
  GSWCt output(2 * rows_per_half, std::vector<uint64_t>(2 * K * N));

  // Re-canonicalise plaintext supplied in [0, q_0) when K > 1: a value above
  // q_0/2 is logically negative and becomes q_k - |v| under limb k.
  const uint64_t q0 = qs[0];
  const uint64_t half_q0 = q0 >> 1;
  auto canon_mj = [&](size_t coef, uint64_t qk) -> uint64_t {
    if (K == 1 || plaintext[coef] <= half_q0) {
      return plaintext[coef] % qk;
    }
    const uint64_t abs_v = q0 - plaintext[coef];
    return (abs_v >= qk) ? (qk - (abs_v % qk)) % qk : (qk - abs_v);
  };

  RlweCt ct;
  for (size_t half = 0; half < 2; ++half) {
    for (size_t r = 0; r < rows_per_half; ++r) {
      // Fresh K-limb Enc_sk(0) in coefficient form.
      encrypt_zero_rns(sk, N, qs, sigma, rng, ct, /*ntt_form=*/false);

      // Add gadget * plaintext under every limb.
      for (size_t k = 0; k < K; ++k) {
        const uint64_t qk = qs[k];
        const uint64_t g  = gadget_table[k][r];
        uint64_t *target = ct.data(half) + k * N;
        for (size_t coef = 0; coef < N; ++coef) {
          const uint64_t mj = canon_mj(coef, qk);
          const uint64_t val =
              static_cast<uint64_t>(static_cast<inter_coeff_t>(mj) * g % qk);
          target[coef] = (target[coef] + val) % qk;
        }
      }

      // NTT each limb in place, then concatenate into the row.
      for (size_t k = 0; k < K; ++k) {
        utils::ntt_fwd(ct.c0.data() + k * N, N, qs[k]);
        utils::ntt_fwd(ct.c1.data() + k * N, N, qs[k]);
      }
      const size_t row = half * rows_per_half + r;
      std::memcpy(output[row].data(),           ct.c0.data(),
                  K * N * sizeof(uint64_t));
      std::memcpy(output[row].data() + K * N,   ct.c1.data(),
                  K * N * sizeof(uint64_t));
    }
  }

  return output;
}