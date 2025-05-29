#include "gsw_eval.h"
#include "utils.h"
#include "seal/util/rlwe.h"
#include "logging.h"
#include <cassert>

// Here we compute a cross product between the transpose of the decomposed BFV
// (a 2l vector of polynomials) and the GSW ciphertext (a 2lx2 matrix of
// polynomials) to obtain a size-2 vector of polynomials, which is exactly our
// result ciphertext. We use an NTT multiplication to speed up polynomial
// multiplication, assuming that both the GSWCiphertext and decomposed bfv is in
// polynomial coefficient representation.


void GSWEval::gsw_ntt_negacyclic_harvey(GSWCiphertext &gsw) {
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const auto context = pir_params_.get_context();
  auto ntt_tables = context.first_context_data()->small_ntt_tables();

  for (auto &poly : gsw) {
    seal::util::CoeffIter gsw_poly_ptr(poly.data());
    for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
      seal::util::ntt_negacyclic_harvey(gsw_poly_ptr + coeff_count * mod_id, *(ntt_tables + mod_id));
    }
    seal::util::CoeffIter gsw_poly_ptr2(poly.data() + coeff_count * rns_mod_cnt);
    for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
      seal::util::ntt_negacyclic_harvey(gsw_poly_ptr2 + coeff_count * mod_id, *(ntt_tables + mod_id));
    }
  }
}

void GSWEval::external_product(GSWCiphertext const &gsw_enc, seal::Ciphertext const &bfv,
                              seal::Ciphertext &res_ct,
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
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
  const size_t coeff_val_cnt = DatabaseConstants::PolyDegree * rns_mod_cnt; // polydegree * RNS moduli count

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
  std::vector<std::vector<uint128_t>> result(
      2, std::vector<uint128_t>(coeff_val_cnt, 0));

  TIME_START(extern_prod_mat_mult_log_key);
  // matrix multiplication: decomp(bfv) * gsw = (1 x 2l) * (2l x 2) = (1 x 2)
  for (size_t k = 0; k < 2; ++k) {
    for (size_t j = 0; j < 2 * l_; j++) {
      seal::util::ConstCoeffIter encrypted_gsw_ptr(gsw_enc[j].data() + k * coeff_val_cnt);
      seal::util::ConstCoeffIter encrypted_rlwe_ptr(decomposed_bfv[j]);
      #pragma GCC unroll 32
      for (size_t i = 0; i < coeff_val_cnt; i++) {
        result[k][i] += static_cast<uint128_t>(encrypted_rlwe_ptr[i]) * encrypted_gsw_ptr[i];
      }
    }
  }
  TIME_END(extern_prod_mat_mult_log_key);

  // ============================ Modding ============================
  TIME_START("external mod");
  const auto coeff_modulus = pir_params_.get_coeff_modulus();
  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    auto ct_ptr = res_ct.data(poly_id);
    auto pt_ptr = result[poly_id];

    for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
      auto mod_idx = (mod_id * coeff_count);
      for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        auto x = pt_ptr[coeff_id + mod_idx];
        uint64_t raw[2] = {static_cast<uint64_t>(x), static_cast<uint64_t>(x >> 64)};
        ct_ptr[coeff_id + mod_idx] = util::barrett_reduce_128(raw, coeff_modulus[mod_id]);
      }
    }
  }
  TIME_END("external mod");
  res_ct.is_ntt_form() = true;  // the result of two NTT form polynomials is still in NTT form.
}

void GSWEval::decomp_rlwe(seal::Ciphertext const &ct, std::vector<std::vector<uint64_t>> &output,
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
  const uint128_t base = uint128_t(1) << base_log2_;
  const uint128_t mask = base - 1;
  const auto &coeff_modulus = pir_params_.get_coeff_modulus();
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
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
            seal::util::right_shift_uint128(res_ptr, p * base_log2_, res_ptr);
            res_ptr[0] &= mask;
            res_ptr[1] = 0;
        } else {
          // ! when we have rns_mod_cnt > 2, this function is slow. Please compare to the single mod version.
          // If in the future we want rns_mod_cnt == 3, we can use the right_shift_uint192 function.
          seal::util::right_shift_uint(res_ptr, p * base_log2_, rns_mod_cnt, res_ptr);// shift right by p * base_log2
          res_ptr[0] &= mask; // mask the first coefficient
          for (size_t i = 1; i < rns_mod_cnt; i++) {
            res_ptr[i] = 0; // set the rest to 0
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

void GSWEval::decomp_rlwe_single_mod(seal::Ciphertext const &ct, std::vector<std::vector<uint64_t>> &output,
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
  // Get parameters
  const uint64_t base = uint64_t(1) << base_log2_;
  const uint64_t mask = base - 1;
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;

  // ============================ Right Shift ============================
  // we do right shift on both polynomials
  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    const uint64_t *poly_ptr = ct.data(poly_id);
    // right shift different amount to match the GSW ciphertext
    for (size_t p = l_; p-- > 0;) { // loop from l_ - 1 to 0.
      std::vector<uint64_t> rshift_res(poly_ptr, poly_ptr + coeff_count);
      const size_t shift_amount = p * base_log2_;
      
      TIME_START(right_shift_log_key);
      #pragma GCC unroll 32
      for (size_t k = 0; k < coeff_count; k++) {
        // right shift every coefficient. This is why we need coefficient form.
        rshift_res[k] = (rshift_res[k] >> shift_amount) & mask;
      }
      TIME_END(right_shift_log_key);

      output.emplace_back(std::move(rshift_res)); // this is also fast
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
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const auto &context_data = pir_params_.get_context().first_context_data();
  const auto ntt_tables = context_data->small_ntt_tables();

  // ============================ NTT Transformation ============================
  TIME_START(extern_ntt_log_key);
  for (auto &coeffs : decomp_coeffs) {
    for (size_t i = 0; i < rns_mod_cnt; i++) {
      seal::util::ntt_negacyclic_harvey(coeffs.data() + coeff_count * i, ntt_tables[i]);
    }
  }
  TIME_END(extern_ntt_log_key);
}

void GSWEval::query_to_gsw(std::vector<seal::Ciphertext> query, GSWCiphertext gsw_key,
                           GSWCiphertext &output) {
  const size_t curr_l = query.size();
  output.resize(curr_l);
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
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
  gsw_ntt_negacyclic_harvey(output);  // And the first half should be in NTT form
  
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

void GSWEval::plain_to_gsw(std::vector<uint64_t> const &plaintext,
                  seal::Encryptor const &encryptor, seal::SecretKey const &sk,
                  std::vector<seal::Ciphertext> &output) { 
  output.clear(); 
  // when poly_id = 0, we are working on the first half of the GSWCiphertext
  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    for (size_t k = 0; k < l_; k++) {
      seal::Ciphertext cipher; 
      plain_to_gsw_one_row(plaintext, encryptor, sk, k, poly_id, cipher);
      output.push_back(cipher);
    }
  }
}

void GSWEval::plain_to_gsw_one_row(std::vector<uint64_t> const &plaintext,
                                   seal::Encryptor const &encryptor,
                                   seal::SecretKey const &sk,
                                   const size_t level, const size_t half,
                                   seal::Ciphertext &output) {

  // Accessing context data within this function instead of passing these parameters
  const auto &context = pir_params_.get_context();
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
  const auto &coeff_modulus = pir_params_.get_coeff_modulus();
  const size_t rns_mod_cnt = coeff_modulus.size();
  assert(plaintext.size() == coeff_count * rns_mod_cnt || plaintext.size() == coeff_count);

  // Create RGSW gadget.
  // We only use rns_mod_cnt many gadgets, we can save some computation here. Not a big deal though. 
  std::vector<std::vector<uint64_t>> gadget = utils::gsw_gadget(l_, base_log2_, rns_mod_cnt, coeff_modulus);

  encryptor.encrypt_zero_symmetric(output);
  auto ct = output.data(half);
  // plaintext is multiplied by the gadget and added to the ciphertext
  for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
    const size_t pad = (mod_id * coeff_count);
    const uint128_t mod = coeff_modulus[mod_id].value();
    const uint64_t gadget_coef = gadget[mod_id][level];
    auto pt = plaintext.data();
    if (plaintext.size() == coeff_count * rns_mod_cnt) {
      pt = plaintext.data() + pad;
    }
    // Loop through plaintext coefficients
    for (size_t j = 0; j < coeff_count; j++) {
      uint128_t val = (uint128_t)pt[j] * gadget_coef % mod;
      ct[j + pad] =
          static_cast<uint64_t>((ct[j + pad] + val) % mod);
    }
  }
}

void GSWEval::plain_to_half_gsw(std::vector<uint64_t> const &plaintext,
                                   seal::Encryptor const &encryptor,
                                   seal::SecretKey const &sk,
                                   std::vector<seal::Ciphertext> &output) {
  output.clear();
  // when poly_id = 0, we are working on the first half of the GSWCiphertext
  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    for (size_t k = 0; k < l_; k++) {
      seal::Ciphertext cipher; 
      plain_to_half_gsw_one_row(plaintext, encryptor, sk, poly_id, k, cipher);
      output.push_back(cipher);
    }
  }
}

void GSWEval::plain_to_half_gsw_one_row(std::vector<uint64_t> const &plaintext,
                                  seal::Encryptor const &encryptor,
                                  seal::SecretKey const &sk, const size_t half,
                                  const size_t level, seal::Ciphertext &output) {

  // Accessing context data within this function instead of passing these parameters
  const auto &context = pir_params_.get_context();
  const auto &params = context.first_context_data()->parms();
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
  const auto &coeff_modulus = pir_params_.get_coeff_modulus();
  const size_t rns_mod_cnt = coeff_modulus.size();
  assert(plaintext.size() == coeff_count * rns_mod_cnt || plaintext.size() == coeff_count);

  // Create RGSW gadget.
  std::vector<std::vector<uint64_t>> gadget = utils::gsw_gadget(l_, base_log2_, rns_mod_cnt, coeff_modulus);

  // ================== Second half of the seeded GSW ==================
  if (half == 1) {
    // extract the level column of gadget
    std::vector<uint64_t> col;
    for (size_t i = 0; i < rns_mod_cnt; i++) {
      col.push_back(gadget[i][level]);
    }
    seal::util::prepare_seeded_gsw_key(sk, col, context,
                                       params.parms_id(), false, output);
    return;
  }

  // ================== Other cases ==================
  assert(half == 0);
  // If we are at the first half of the GSW, we are adding new things to the
  // first polynomial (c0) of the given BFV ciphertext. c1 is not touched.
  encryptor.encrypt_zero_symmetric_seeded(output);
  auto ct = output.data(0);
  // Many(2) moduli are used
  for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
    size_t pad = (mod_id * coeff_count);
    uint128_t mod = coeff_modulus[mod_id].value();
    uint64_t gadget_coef = gadget[mod_id][level];
    auto pt = plaintext.data();
    if (plaintext.size() == coeff_count * rns_mod_cnt) {
      pt = plaintext.data() + pad;
    }
    // Loop through plaintext coefficients
    for (size_t j = 0; j < coeff_count; j++) {
      // TODO: We can use barret reduction here.
      uint128_t val = (uint128_t)pt[j] * gadget_coef % mod;
      ct[j + pad] =
          static_cast<uint64_t>((ct[j + pad] + val) % mod);
    }
  }
}

void GSWEval::seal_GSW_vec_to_GSW(GSWCiphertext &output, const std::vector<seal::Ciphertext> &gsw_vec) {
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();

  output.clear();
  for (auto &ct : gsw_vec) {
    std::vector<uint64_t> row;
    row.reserve(2 * coeff_count * rns_mod_cnt);
    for (size_t i = 0; i < coeff_count * rns_mod_cnt; i++) {
      row.push_back(ct.data(0)[i]);
    }
    for (size_t i = 0; i < coeff_count * rns_mod_cnt; i++) {
      row.push_back(ct.data(1)[i]);
    }
    output.push_back(row);
  }
}