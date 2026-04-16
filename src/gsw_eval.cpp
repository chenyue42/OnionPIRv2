#include "gsw_eval.h"
#include "utils.h"
#include "logging.h"
#include "bv_keyswitch.h"
#include <cassert>
#include <cstring>

// Here we compute a cross product between the transpose of the decomposed BFV
// (a 2l vector of polynomials) and the GSW ciphertext (a 2lx2 matrix of
// polynomials) to obtain a size-2 vector of polynomials, which is exactly our
// result ciphertext. We use an NTT multiplication to speed up polynomial
// multiplication, assuming that both the GSWCiphertext and decomposed bfv is in
// polynomial coefficient representation.


void GSWEval::gsw_ntt_forward(GSWCiphertext &gsw) {
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const auto &coeff_mods = pir_params_.get_coeff_modulus();

  // Each poly holds c0||c1, each split into rns_mod_cnt limbs of coeff_count.
  for (auto &poly : gsw) {
    for (size_t i = 0; i < 2 * rns_mod_cnt; i++) {
      utils::ntt_fwd(poly.data() + coeff_count * i, coeff_count,
                     coeff_mods[i % rns_mod_cnt]);
    }
  }
}

void GSWEval::external_product(GSWCiphertext const &gsw_enc, RlweCt const &bfv,
                              RlweCt &res_ct,
                              LogContext context) {

  // ============================ Logging ============================
  const char* decomp_rlwe_log_key;
  const char* extern_prod_mat_mult_log_key;
  if (context == LogContext::QUERY_TO_GSW) {
    decomp_rlwe_log_key = QTG_DECOMP_RLWE_TIME;
    extern_prod_mat_mult_log_key = QTG_EXTERN_PROD_MAT_MULT_TIME;
  } else if (context == LogContext::OTHER_DIM_MUX) {
    decomp_rlwe_log_key = ODM_DECOMP_RLWE_TIME;
    extern_prod_mat_mult_log_key = ODM_EXTERN_PROD_MAT_MULT_TIME;
  } else { // GENERIC or default
    decomp_rlwe_log_key = DECOMP_RLWE_TIME;
    extern_prod_mat_mult_log_key = EXTERN_PROD_MAT_MULT_TIME;
  }

  // ============================ Parameters ============================
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t coeff_val_cnt = DBConsts::PolyDegree * rns_mod_cnt; // polydegree * RNS moduli count

  // ============================ Decomposition ============================
  // Decomposing the BFV ciphertext to 2l polynomials. Transform to NTT form.
  std::vector<std::vector<uint64_t>> decomposed_bfv;
  TIME_START(decomp_rlwe_log_key);
  if (rns_mod_cnt == 1) {
    decomp_rlwe_single_mod(bfv, decomposed_bfv, context);
  } else {
    decomp_rlwe(bfv, decomposed_bfv, context);
  }
  TIME_END(decomp_rlwe_log_key);

  // Transform decomposed coefficients to NTT form
  decomp_to_ntt(decomposed_bfv, context);

  // ============================ Polynomial Matrix Multiplication ============================
  std::vector<std::vector<inter_coeff_t>> result(
      2, std::vector<inter_coeff_t>(coeff_val_cnt, 0));

  TIME_START(extern_prod_mat_mult_log_key);
  // matrix multiplication: decomp(bfv) * gsw = (1 x 2l) * (2l x 2) = (1 x 2)
  for (size_t k = 0; k < 2; ++k) {
    for (size_t j = 0; j < 2 * l_; j++) {
      const uint64_t *encrypted_gsw_ptr = gsw_enc[j].data() + k * coeff_val_cnt;
      const uint64_t *encrypted_rlwe_ptr = decomposed_bfv[j].data();
      #pragma GCC unroll 32
      for (size_t i = 0; i < coeff_val_cnt; i++) {
        result[k][i] += (inter_coeff_t)(encrypted_rlwe_ptr[i]) * encrypted_gsw_ptr[i];
      }
    }
  }
  TIME_END(extern_prod_mat_mult_log_key);

  // ============================ Modding ============================
  TIME_START("external mod");
  const auto coeff_modulus = pir_params_.get_coeff_modulus();
  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    auto ct_ptr = res_ct.data(poly_id);
    auto &pt_ptr = result[poly_id];

    for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
      auto mod_idx = (mod_id * coeff_count);
      for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        auto x = pt_ptr[coeff_id + mod_idx];
        ct_ptr[coeff_id + mod_idx] = x % coeff_modulus[mod_id];
      }
    }
  }
  TIME_END("external mod");
  res_ct.is_ntt_form() = true;  // the result of two NTT form polynomials is still in NTT form.
}

void GSWEval::decomp_rlwe(RlweCt const &ct, std::vector<std::vector<uint64_t>> &output,
                         LogContext context) {
  // ============================ Logging ============================
  const char* extern_compose_log_key;
  const char* right_shift_log_key;
  const char* extern_decomp_log_key;
  if (context == LogContext::QUERY_TO_GSW) {
    extern_compose_log_key = QTG_EXTERN_COMPOSE;
    right_shift_log_key = QTG_RIGHT_SHIFT_TIME;
    extern_decomp_log_key = QTG_EXTERN_DECOMP;
  } else if (context == LogContext::OTHER_DIM_MUX) {
    extern_compose_log_key = ODM_EXTERN_COMPOSE;
    right_shift_log_key = ODM_RIGHT_SHIFT_TIME;
    extern_decomp_log_key = ODM_EXTERN_DECOMP;
  } else { // GENERIC or default
    extern_compose_log_key = EXTERN_COMPOSE;
    right_shift_log_key = RIGHT_SHIFT_TIME;
    extern_decomp_log_key = EXTERN_DECOMP;
  }

  // ============================ Parameters ============================
  assert(output.size() == 0);
  output.reserve(2 * l_);
  // Setup parameters
  const uint64_t base = uint64_t(1) << base_log2_;
  const uint64_t mask = base - 1;
  const auto &coeff_modulus = pir_params_.get_coeff_modulus();
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt();
  const auto &context_data = pir_params_.get_context().first_context_data();
  seal::util::RNSBase *rns_base = context_data->rns_tool()->base_q();
  auto pool = seal::MemoryManager::GetPool();
  std::vector<uint64_t> ct_coeffs(coeff_val_cnt);

  // ============================ Decomposition ============================
  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    // we need a copy because we need to compose the array. This copy is very fast. 
    memcpy(ct_coeffs.data(), ct.data(poly_id), coeff_val_cnt * sizeof(uint64_t));
    TIME_START(extern_compose_log_key); 
    // the "compose_array" transform the coefficients from RNS form to multi-precision integer form. The lower bits are in the front. 
    // ! the compose and decompose functions are slow when rns_mod_cnt > 1 because mod and div operations are slow.
    rns_base->compose_array(ct_coeffs.data(), coeff_count, pool);
    TIME_END(extern_compose_log_key);

    // we right shift certain amount to match the GSW ciphertext
    for (size_t p = l_; p-- > 0;) { // loop from l_ - 1 to 0.
      std::vector<uint64_t> rshift_res(ct_coeffs);
      const size_t shift_amount = p * base_log2_;
      TIME_START(right_shift_log_key);
      for (size_t k = 0; k < coeff_count; k++) {
        uint64_t* res_ptr = rshift_res.data() + k * rns_mod_cnt;
        if (rns_mod_cnt == 2) {
            utils::right_shift_uint128(res_ptr, p * base_log2_, res_ptr);
            res_ptr[0] &= mask;
            res_ptr[1] = 0;
        } else {
          // Generic n-limb little-endian right shift (only reached for rns_mod_cnt > 2).
          const size_t shift = p * base_log2_;
          const size_t word_shift = shift / 64;
          const size_t bit_shift  = shift % 64;
          for (size_t i = 0; i < rns_mod_cnt; i++) {
            uint64_t lo = (i + word_shift     < rns_mod_cnt) ? res_ptr[i + word_shift]     : 0;
            uint64_t hi = (i + word_shift + 1 < rns_mod_cnt) ? res_ptr[i + word_shift + 1] : 0;
            res_ptr[i] = (bit_shift == 0) ? lo : (lo >> bit_shift) | (hi << (64 - bit_shift));
          }
          res_ptr[0] &= mask;
          for (size_t i = 1; i < rns_mod_cnt; i++) {
            res_ptr[i] = 0;
          }
        }
      }
      TIME_END(right_shift_log_key);
      TIME_START(extern_decomp_log_key);
      rns_base->decompose_array(rshift_res.data(), coeff_count, pool);
      TIME_END(extern_decomp_log_key);

      output.emplace_back(std::move(rshift_res));
    }
  }
}

void GSWEval::decomp_rlwe_single_mod(RlweCt const &ct, std::vector<std::vector<uint64_t>> &output,
                                   LogContext context) {
  // ============================ Logging ============================
  const char* right_shift_log_key;
  if (context == LogContext::QUERY_TO_GSW) {
    right_shift_log_key = QTG_RIGHT_SHIFT_TIME;
  } else if (context == LogContext::OTHER_DIM_MUX) {
    right_shift_log_key = ODM_RIGHT_SHIFT_TIME;
  } else { // GENERIC or default
    right_shift_log_key = RIGHT_SHIFT_TIME;
  }

  // ============================ Parameters ============================
  assert(output.size() == 0);
  output.reserve(2 * l_);
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const uint64_t q = pir_params_.get_coeff_modulus()[0];

  // ============================ Signed Decomposition ============================
  // Coefficient-first loop: carry propagates across digits within each coefficient.
  // Output order: most-significant digit first (p = l_-1..0) to match GSW gadget.
  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    const uint64_t *poly_ptr = ct.data(poly_id);

    // digit_matrix[p][k]: digit p of coefficient k (out[0]=least significant)
    std::vector<std::vector<uint64_t>> digit_matrix(l_, std::vector<uint64_t>(coeff_count));

    // signed gadget decomposition
    for (size_t k = 0; k < coeff_count; k++) {
      // Use a stack buffer; l_ is small (≤12).
      uint64_t digit_vals[16];  // ! for now we assume l_ <= 16. Reasonable for practical params. 
      bvks::signed_gadget_decompose(poly_ptr[k], base_log2_, q, digit_vals, l_);
      for (size_t p = 0; p < l_; p++) {
        digit_matrix[p][k] = digit_vals[p];
      }
    }

    // Push most-significant digit first (matches current GSW gadget ordering).
    for (size_t p = l_; p-- > 0;) {
      output.emplace_back(std::move(digit_matrix[p]));
    }
  }
}

void GSWEval::decomp_to_ntt(std::vector<std::vector<uint64_t>> &decomp_coeffs,
                           LogContext context) {
  // ============================ Logging ============================
  const char* extern_ntt_log_key;
  if (context == LogContext::QUERY_TO_GSW) {
    extern_ntt_log_key = QTG_EXTERN_NTT_TIME;
  } else if (context == LogContext::OTHER_DIM_MUX) {
    extern_ntt_log_key = ODM_EXTERN_NTT_TIME;
  } else { // GENERIC or default
    extern_ntt_log_key = EXTERN_NTT_TIME;
  }

  // ============================ Parameters ============================
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const auto coeff_mods = pir_params_.get_coeff_modulus();

  // ============================ NTT Transformation ============================
  TIME_START(extern_ntt_log_key);
  for (auto &coeffs : decomp_coeffs) {
    for (size_t i = 0; i < rns_mod_cnt; i++) {
      utils::ntt_fwd(coeffs.data() + coeff_count * i, coeff_count,
                                    coeff_mods[i]);
    }
  }
  TIME_END(extern_ntt_log_key);
}

void GSWEval::query_to_gsw(std::vector<RlweCt> query, GSWCiphertext gsw_key,
                           GSWCiphertext &output) {
  const size_t curr_l = query.size();
  output.resize(curr_l);
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();

  // We get the first half directly from the query
  for (size_t i = 0; i < curr_l; i++) {
    for (size_t j = 0; j < coeff_count * rns_mod_cnt; j++) {
      output[i].push_back(query[i].data(0)[j]);
    }
    for (size_t j = 0; j < coeff_count * rns_mod_cnt; j++) {
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
    for (size_t j = 0; j < coeff_count * rns_mod_cnt; j++) {
      output[i + curr_l].push_back(query[i].data(0)[j]);
    }
    for (size_t j = 0; j < coeff_count * rns_mod_cnt; j++) {
      output[i + curr_l].push_back(query[i].data(1)[j]);
    }
  }
}

GSWCiphertext GSWEval::plain_to_gsw(std::vector<uint64_t> const &plaintext,
                                    const RlweSk &sk, std::mt19937_64 &rng) {
  constexpr size_t N = DBConsts::PolyDegree;
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  assert(rns_mod_cnt == 1 && "plain_to_gsw currently supports only single-mod");
  assert(plaintext.size() == N);

  const uint64_t q = pir_params_.get_coeff_modulus()[0];
  const double sigma = pir_params_.get_noise_std_dev();

  // Gadget: gadget[k] = B^(l-1-k) mod q, matching utils::gsw_gadget ordering
  // (large → small, row 0 = B^(l-1), row l-1 = 1).
  const auto gadget_table = utils::gsw_gadget(l_, base_log2_, 1, pir_params_.get_coeff_modulus());
  const std::vector<uint64_t> &gadget = gadget_table[0];

  // Output layout: 2*l_ rows, each row = [c0 (N) || c1 (N)] in NTT form.
  GSWCiphertext output(2 * l_, std::vector<uint64_t>(2 * N));

  RlweCt ct;
  for (size_t half = 0; half < 2; half++) {
    for (size_t k = 0; k < l_; k++) {
      // Fresh (c0, c1) = Enc_sk(0) in coefficient form.
      encrypt_zero(sk, N, q, sigma, rng, ct, /*ntt_form=*/false);

      // Add gadget[k] * plaintext to c_{half}.
      uint64_t *target = ct.data(half);
      const uint64_t g = gadget[k];
      for (size_t j = 0; j < N; j++) {
        const uint64_t val =
            static_cast<uint64_t>(static_cast<inter_coeff_t>(plaintext[j]) * g % q);
        target[j] = (target[j] + val) % q;
      }

      // NTT both halves and write into the flat output row.
      utils::ntt_fwd(ct.c0.data(), N, q);
      utils::ntt_fwd(ct.c1.data(), N, q);
      const size_t row = half * l_ + k;
      std::memcpy(output[row].data(),     ct.c0.data(), N * sizeof(uint64_t));
      std::memcpy(output[row].data() + N, ct.c1.data(), N * sizeof(uint64_t));
    }
  }

  return output;
}