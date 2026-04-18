#include "server.h"
#include "gsw.h"
#include "rlwe.h"
#include "utils.h"
#include "matrix.h"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <random>
#include <bit>
#include <cstdint>

#if defined(__AVX512F__)
    #include <immintrin.h>
#elif defined(__AVX2__)
    #include <immintrin.h>
#endif

#ifdef _DEBUG
#include <bitset>
#endif

// client_bv_galois_keys_, client_gsw_keys_, and db_ are not set yet.
PirServer::PirServer(const PirParams &pir_params)
    : pir_params_(pir_params),
      num_pt_(pir_params.get_num_pt()),
      key_gsw_(pir_params, pir_params.get_l_key(), pir_params.get_base_log2_key()),
      data_gsw_(pir_params, pir_params.get_l(), pir_params.get_base_log2()) {
  // after NTT, each database polynomial coefficient will be in mod q. Hence,
  // each pt coefficient will be represented by rns_mod_cnt many uint64_t, same as the ciphertext. 
  db_aligned_ = make_unique_aligned<db_coeff_t, 64>(num_pt_ * pir_params_.get_coeff_val_cnt());
  fill_inter_res();
}

PirServer::~PirServer() {
}

// Fills the database with random data.
// Generates, NTT-transforms, and scatters each plaintext directly into db_aligned_
// in a single pass, avoiding the 2x RAM overhead of a separate intermediate db_.
// record_indices: indices of plaintexts to save (pre-NTT) for test verification.
void PirServer::gen_data(const std::vector<size_t>& record_indices) {
  BENCH_PRINT("Generating random data for the server database...");

  // Seed a fast PRNG with OS entropy (avoids per-coefficient syscall overhead of /dev/urandom)
  std::mt19937_64 rng(std::random_device{}());

  recorded_pts_.clear();
  recorded_pts_.reserve(record_indices.size());

  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t coeff_count = DBConsts::PolyDegree;
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt();
  const uint64_t plain_mod = pir_params_.get_plain_mod();

  // Pass 1: fill random coefficients and record requested entries
  TIME_ONCE_START("DB random fill");
  const uint64_t q = pir_params_.get_coeff_modulus()[0];
  std::vector<RlwePt> plaintexts(num_pt_);
  for (size_t poly_id = 0; poly_id < num_pt_; ++poly_id) {
    plaintexts[poly_id].data.resize(coeff_count);
    uint64_t* coeffs = plaintexts[poly_id].data.data();
    for (size_t i = 0; i < coeff_count; ++i) {
      coeffs[i] = rng() % plain_mod;
    }
    if (std::find(record_indices.begin(), record_indices.end(), poly_id) != record_indices.end()) {
      recorded_pts_[poly_id] = plaintexts[poly_id];
    }
  }
  TIME_ONCE_END("DB random fill");

  // Pass 2: NTT-transform and scatter into db_aligned_.
  // Plaintext values are in [0, t) with t < q, so they lift into [0, q) directly.
  TIME_ONCE_START("DB NTT + realign");
  for (size_t poly_id = 0; poly_id < num_pt_; ++poly_id) {
    uint64_t* coeffs = plaintexts[poly_id].data.data();
    utils::ntt_fwd(coeffs, coeff_count, q);
    for (size_t coeff_idx = 0; coeff_idx < coeff_val_cnt; ++coeff_idx) {
      db_aligned_[coeff_idx * num_pt_ + poly_id] = static_cast<db_coeff_t>(coeffs[coeff_idx]);
    }
  }
  TIME_ONCE_END("DB NTT + realign");
  PRINT_ONCE("DB random fill");
  PRINT_ONCE("DB NTT + realign");
}

void PirServer::prep_query(const std::vector<RlweCt> &fst_dim_query,
                           std::vector<db_coeff_t> &query_data) {
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();       // 256
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt(); // 4096
  const size_t slice_sz = fst_dim_sz * 2;

  // Pre-fetch the data pointers to avoid repeated indirect access
  std::vector<const uint64_t *> data0_ptrs(fst_dim_sz);
  std::vector<const uint64_t *> data1_ptrs(fst_dim_sz);

  // Prefetch all pointers
  for (size_t i = 0; i < fst_dim_sz; ++i) {
    data0_ptrs[i] = fst_dim_query[i].c0.data();
    data1_ptrs[i] = fst_dim_query[i].c1.data();
  }

  // Process in blocks to improve cache locality
  const size_t BLOCK_SIZE = 8;
  // Fallback to scalar implementation if no SIMD is available
  for (size_t slice_block = 0; slice_block < coeff_val_cnt;
       slice_block += BLOCK_SIZE) {
    const size_t slice_block_end =
        std::min(slice_block + BLOCK_SIZE, coeff_val_cnt);

    for (size_t i = 0; i < fst_dim_sz; ++i) {
      const uint64_t *p0 = data0_ptrs[i];
      const uint64_t *p1 = data1_ptrs[i];

      // Process a block of slices for the same i value (improves temporal
      // locality)
      for (size_t slice_id = slice_block; slice_id < slice_block_end;
           ++slice_id) {
        const size_t idx = slice_id * slice_sz + i * 2;
        query_data[idx] = static_cast<db_coeff_t>(p0[slice_id]);
        query_data[idx + 1] = static_cast<db_coeff_t>(p1[slice_id]);
      }
    }
  }
}

// Computes a dot product between the fst_dim_query and the database for the
// first dimension with a delayed modulus optimization. fst_dim_query should
// be transformed to ntt.
std::vector<RlweCt>
PirServer::evaluate_first_dim(std::vector<RlweCt> &fst_dim_query) {
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();  // number of plaintexts in the first dimension
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();  // number of plaintexts in the other dimensions
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt(); // polydegree * RNS moduli count
  const size_t one_ct_sz = 2 * coeff_val_cnt; // Ciphertext has two polynomials
  const auto &coeff_modulus = pir_params_.get_coeff_modulus();
  constexpr size_t N = DBConsts::PolyDegree;

  // fill the intermediate result with zeros
  std::fill(inter_res_.begin(), inter_res_.end(), 0);

  // transform the selection vector to ntt form
  for (size_t i = 0; i < fst_dim_query.size(); i++) {
    RlweCt &ct = fst_dim_query[i];
    for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
      utils::ntt_fwd(ct.c0.data() + mod_id * N, N, coeff_modulus[mod_id]);
      utils::ntt_fwd(ct.c1.data() + mod_id * N, N, coeff_modulus[mod_id]);
    }
    ct.ntt_form = true;
  }

  // reallocate the query data to a continuous memory
  TIME_START(FST_DIM_PREP);
  std::vector<db_coeff_t> query_data(fst_dim_sz * one_ct_sz);
  prep_query(fst_dim_query, query_data);
  TIME_END(FST_DIM_PREP);

  /*
  Imagine DB as a (other_dim_sz * fst_dim_sz) matrix, where each element is a
  vector of size coeff_val_cnt. In OnionPIRv1, the first dimension is doing the
  component wise matrix multiplication. Further details can be found in the "matrix.h" file.
  */
  // prepare the matrices
  db_matrix_t db_mat { db_aligned_.get(), other_dim_sz, fst_dim_sz, coeff_val_cnt };
  db_matrix_t query_mat { query_data.data(), fst_dim_sz, 2, coeff_val_cnt };
  inter_matrix_t inter_res_mat { inter_res_.data(), other_dim_sz, 2, coeff_val_cnt };
  TIME_START(CORE_TIME);
  level_mat_mat(&db_mat, &query_mat, &inter_res_mat);
  // level_mat_mat_64_128(&db_mat, &query_mat, &inter_res_mat);
  TIME_END(CORE_TIME);

  // ========== transform the intermediate to coefficient form. Delay the modulus operation ==========
  TIME_START(FST_DELEY_MOD_TIME);
  std::vector<RlweCt> result; // output vector
  result.reserve(other_dim_sz);
  delay_modulus(result, inter_res_.data());
  TIME_END(FST_DELEY_MOD_TIME);

  return result;
}


void PirServer::delay_modulus(std::vector<RlweCt> &result, const inter_coeff_t *__restrict inter_res) {
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  constexpr size_t coeff_count = DBConsts::PolyDegree;
  const auto &coeff_modulus = pir_params_.get_coeff_modulus();
  const size_t coeff_val_cnt = coeff_count * rns_mod_cnt;
  const size_t inter_padding = other_dim_sz * 2;  // distance between coefficients in inter_res

  // We need to unroll the loop to process multiple ciphertexts at once.
  // Otherwise, this function is basically reading the intermediate result
  // with a stride of inter_padding, which causes many cache misses.
  constexpr size_t unroll_factor = 16;

  // Process ciphertexts in blocks of unroll_factor for the main part
  const size_t main_blocks = other_dim_sz / unroll_factor;
  for (size_t block = 0; block < main_blocks; block++) {
    const size_t j = block * unroll_factor;

    // Create an array of ciphertexts.
    std::array<RlweCt, unroll_factor> cts;
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      cts[idx].c0.assign(coeff_val_cnt, 0);
      cts[idx].c1.assign(coeff_val_cnt, 0);
    }

    // Compute the base indices for each ciphertext's two intermediate parts.
    // For ciphertext idx, poly0 uses base index: j*2 + 2*idx and poly1 uses j*2 + 2*idx + 1.
    std::array<size_t, unroll_factor> base0, base1;
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      base0[idx] = j * 2 + 2 * idx;
      base1[idx] = j * 2 + 2 * idx + 1;
    }

    // Initialize intermediate indices and ciphertext write indices.
    std::array<size_t, unroll_factor> inter_idx0 = {0};  // for poly0 of each ciphertext
    std::array<size_t, unroll_factor> inter_idx1 = {0};  // for poly1 of each ciphertext
    std::array<size_t, unroll_factor> ct_idx0    = {0};  // write index for poly0
    std::array<size_t, unroll_factor> ct_idx1    = {0};  // write index for poly1

    // Process each modulus and coefficient.
    for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
      const uint64_t modulus = coeff_modulus[mod_id];
      for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        #pragma unroll
        for (size_t idx = 0; idx < unroll_factor; idx++) {
          // Process polynomial 0 for ciphertext idx.
          inter_coeff_t x0 = inter_res[ base0[idx] + inter_idx0[idx] * inter_padding ];
          cts[idx].c0[ ct_idx0[idx]++ ] = x0 % modulus;

          // Process polynomial 1 for ciphertext idx.
          inter_coeff_t x1 = inter_res[ base1[idx] + inter_idx1[idx] * inter_padding ];
          cts[idx].c1[ ct_idx1[idx]++ ] = x1 % modulus;
          // Advance intermediate indices.
          inter_idx0[idx]++;
          inter_idx1[idx]++;
        }
      }
    }

    // Mark each ciphertext as being in NTT form and then transform back.
    #pragma unroll
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
        utils::ntt_inv(cts[idx].c0.data() + mod_id * coeff_count, coeff_count, coeff_modulus[mod_id]);
        utils::ntt_inv(cts[idx].c1.data() + mod_id * coeff_count, coeff_count, coeff_modulus[mod_id]);
      }
      cts[idx].ntt_form = false;
      result.emplace_back(std::move(cts[idx]));
    }
  }

  // Handle remaining ciphertexts individually for edge cases
  const size_t remaining_start = main_blocks * unroll_factor;
  for (size_t j = remaining_start; j < other_dim_sz; j++) {
    // Create a single ciphertext
    RlweCt ct;
    ct.c0.assign(coeff_val_cnt, 0);
    ct.c1.assign(coeff_val_cnt, 0);

    // Compute the base indices for this ciphertext's two intermediate parts
    const size_t base0 = j * 2;
    const size_t base1 = j * 2 + 1;

    // Initialize intermediate indices and ciphertext write indices
    size_t inter_idx0 = 0;  // for poly0
    size_t inter_idx1 = 0;  // for poly1
    size_t ct_idx0 = 0;     // write index for poly0
    size_t ct_idx1 = 0;     // write index for poly1

    // Process each modulus and coefficient
    for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
      const uint64_t modulus = coeff_modulus[mod_id];
      for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        // Process polynomial 0
        inter_coeff_t x0 = inter_res[base0 + inter_idx0 * inter_padding];
        ct.c0[ct_idx0++] = x0 % modulus;

        // Process polynomial 1
        inter_coeff_t x1 = inter_res[base1 + inter_idx1 * inter_padding];
        ct.c1[ct_idx1++] = x1 % modulus;

        // Advance intermediate indices
        inter_idx0++;
        inter_idx1++;
      }
    }

    // Mark ciphertext as being in NTT form and then transform back
    for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
      utils::ntt_inv(ct.c0.data() + mod_id * coeff_count, coeff_count, coeff_modulus[mod_id]);
      utils::ntt_inv(ct.c1.data() + mod_id * coeff_count, coeff_count, coeff_modulus[mod_id]);
    }
    ct.ntt_form = false;
    result.emplace_back(std::move(ct));
  }
}

RlweCt PirServer::evaluate_other_dim(std::vector<RlweCt> &mid_db, std::vector<GSWCt> &selectors) {
  // Handle single dimension case
  if (pir_params_.get_num_dims() == 1) {
    // For single dimension, we just return the first (and only) ciphertext
    return mid_db[0];
  }
  
  size_t h = pir_params_.get_num_dims() - 1;
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  // For multiple dimensions, calculate the results vector size properly
  const size_t perfect_size = (1 << (h - 1)); // second to last level size
  
  // handling the last level
  const size_t last_level_sz = 2 * other_dim_sz - (1 << h);
  const size_t offset = other_dim_sz - last_level_sz;
  
  for (size_t i = 0; i < last_level_sz; i += 2) { // i is the index within the last level.
    size_t corrected_idx = i + offset;  // index in the database.
    auto &x = mid_db[corrected_idx];
    auto &y = mid_db[corrected_idx + 1];
    ext_prod_mux(x, y, selectors[0], mid_db[i / 2 + offset]);
  }
  
  for (size_t a = 1; a < selectors.size(); a++) { // starting from the second to the last level
    const size_t level_sz = (1 << (h - a));
    const size_t half = level_sz >> 1;
    for (size_t i = 0; i < half; i++) {
      auto &x = mid_db[i];
      auto &y = mid_db[i + half];
      ext_prod_mux(x, y, selectors[a], mid_db[i]);
    }
  }
  return mid_db[0];
}


void PirServer::ext_prod_mux(RlweCt &x, RlweCt &y, GSWCt &selection_cipher, RlweCt &result) {
    /**
   * Note that we only have a single GSWCiphertext for this selection.
   * Here is the logic:
   * We want to select the correct half of the "result" vector.
   * Suppose result = [x || y], where x and y are of the same size(block_size).
   * If we have RGSW(0), then we want to set result = x,
   * If we have RGSW(1), then we want to set result = y.
   * The simple formula is:
   * result = RGSW(b) * (y - x) + x, where "*" is the external product, "+" and "-" are homomorphic operations.
   */
    const uint64_t q = pir_params_.get_coeff_modulus()[0];
    constexpr size_t N = DBConsts::PolyDegree;

    // ========== y = y - x ==========
    TIME_START(OTHER_DIM_ADD_SUB);
    rlwe_sub_inplace(y, x, q);
    TIME_END(OTHER_DIM_ADD_SUB);

    // ========== y = b * (y - x) ========== output will be in NTT form
    TIME_START(OTHER_DIM_MUX_EXTERN);
    data_gsw_.external_product(selection_cipher, y, y, LogContext::OTHER_DIM_MUX);
    TIME_END(OTHER_DIM_MUX_EXTERN);

    // ========== y = INTT(y) ==========, INTT stands for inverse NTT
    TIME_START(OTHER_DIM_INTT);
    rlwe_ntt_inv_inplace(y, q, N);
    TIME_END(OTHER_DIM_INTT);

    // ========== result = y + x ==========
    TIME_START(OTHER_DIM_ADD_SUB);
    // If result aliases x, we can add in-place to avoid an extra copy
    if (&result == &x) {
      rlwe_add_inplace(x, y, q);  // x = x + y = x + b*(y - x)
    } else {
      rlwe_add(x, y, result, q);
    }
    TIME_END(OTHER_DIM_ADD_SUB);
}

//  single-loop level-order expansion  (root index = 1)
std::vector<RlweCt>
PirServer::fast_expand_qry(std::size_t client_id, RlweCt &ciphertext) const {
  // ============== parameters
  const size_t useful_cnt = pir_params_.get_fst_dim_sz() +
                            pir_params_.get_l() * (pir_params_.get_num_dims() - 1); // u
  const size_t expan_height = pir_params_.get_expan_height(); // h
  const size_t w = size_t{1} << expan_height;                 // 2^h
  const auto &bv_galois_key = client_bv_galois_keys_.at(client_id);
  constexpr size_t N = DBConsts::PolyDegree;
  const uint64_t q = pir_params_.get_coeff_modulus()[0];

  // ============== storage   – index 0 is *unused*, root is slot 1
  std::vector<RlweCt> cts(2 * w); // slots 0 … 2w-1
  cts[1] = ciphertext;

  // ============== level-order walk, skip right-of-u sub-trees
  for (size_t i = 1; i < w; ++i) { // internal nodes only
    const int k = int{1} << (std::bit_width(i) - 1); // k = 2^{⌊log i⌋}   (span of this sub-tree)

    // left-most leaf index of this sub-tree
    const size_t left_leaf = i * w / k - w; // exact integer
    if (left_leaf >= useful_cnt)
      continue; // skip whole sub-tree

    // ============== split   c[i] ->  c[2i] , c[2i+1]
    // c' = Subs(c_i, w/k+1)
    RlweCt c_prime = cts[i];
    const uint32_t galois_k = DBConsts::PolyDegree / k + 1;
    TIME_START(APPLY_GALOIS);
    bvks::bv_apply_galois_inplace(c_prime, galois_k,
                                  bv_galois_key.get(galois_k),
                                  pir_params_);
    TIME_END(APPLY_GALOIS);
    TIME_START("add_sub");
    // c_{2i}   =  c_i + c'
    rlwe_add(cts[i], c_prime, cts[2 * i], q);

    // c_{2i+1} = (c_i − c') * x^{−k}
    rlwe_sub_inplace(cts[i], c_prime, q);
    TIME_END("add_sub");

    TIME_START("shift polynomial");
    rlwe_shift(cts[i], cts[2 * i + 1], static_cast<size_t>(-k), q, N);
    TIME_END("shift polynomial");
  }

  // ==============  return the first  u  leaves: heap slots  w … w+u−1
  return std::vector<RlweCt>(
      std::make_move_iterator(cts.begin() + w),
      std::make_move_iterator(cts.begin() + w + useful_cnt));
}

void PirServer::set_client_bv_galois_key(const size_t client_id, bvks::BvGaloisKeys bv_keys) {
  client_bv_galois_keys_[client_id] = std::move(bv_keys);
}

void PirServer::set_client_gsw_key(const size_t client_id, GSWCt gsw_key) {
  client_gsw_keys_[client_id] = std::move(gsw_key);
}


// Get original plaintext (before NTT transformation) from recorded entries
RlwePt PirServer::direct_get_original_plaintext(const size_t plaintext_idx) const {
  auto it = recorded_pts_.find(plaintext_idx);
  if (it == recorded_pts_.end()) {
    throw std::invalid_argument("Plaintext index " + std::to_string(plaintext_idx) + " was not recorded during gen_data()");
  }
  return it->second;
}


RlweCt PirServer::make_query(const size_t client_id, RlweCt &query) {
  // receive the query from the client

  // ========================== Expansion & conversion ==========================
  TIME_START(EXPAND_TIME);
  std::vector<RlweCt> query_vector = fast_expand_qry(client_id, query);
  TIME_END(EXPAND_TIME);

  // Reconstruct RGSW queries
  TIME_START(CONVERT_TIME);
  std::vector<GSWCt> gsw_vec(pir_params_.get_num_dims() - 1); // GSW ciphertexts
  if (pir_params_.get_num_dims() != 1) {  // if we do need futher dimensions
    for (size_t i = 1; i < pir_params_.get_num_dims(); i++) {
      std::vector<RlweCt> lwe_vector; // RLWE ciphertexts, size l. Reconstructed as a single RGSW ciphertext.
      for (size_t k = 0; k < DBConsts::L_EP; k++) {
        auto ptr = pir_params_.get_fst_dim_sz() + (i - 1) * DBConsts::L_EP + k;
        lwe_vector.push_back(query_vector[ptr]);
      }
      // Converting the BFV ciphertexts to GSW ciphertext by doing external product
      key_gsw_.query_to_gsw(lwe_vector, client_gsw_keys_[client_id], gsw_vec[i - 1]);
    }
  }
  TIME_END(CONVERT_TIME);

  // ========================== Evaluations ==========================
  // Evaluate the first dimension
  TIME_START(FST_DIM_TIME);
  query_vector.resize(pir_params_.get_fst_dim_sz());
  std::vector<RlweCt> mid_db = evaluate_first_dim(query_vector);
  TIME_END(FST_DIM_TIME);

  // Evaluate the other dimensions
  TIME_START(OTHER_DIM_TIME);
  RlweCt result = evaluate_other_dim(mid_db, gsw_vec);
  TIME_END(OTHER_DIM_TIME);

  // ========================== Post-processing ==========================
  TIME_START(MOD_SWITCH);
  // we can always switch to the small modulus it correctness is guaranteed.
  if (DBConsts::SmallQWidth < DBConsts::CoeffMods[0]) {
    DEBUG_PRINT("Modulus switching for a single modulus...");
    const uint64_t small_q = pir_params_.get_small_q();
    mod_switch_inplace(result, small_q);
  }

  TIME_END(MOD_SWITCH);
  DEBUG_PRINT("Modulus switching done.");

  return result;
}


size_t PirServer::save_resp_to_stream(const RlweCt &response,
                                      std::stringstream &stream) {
  // For now, we only serve the single modulus case.

  // --- 1.  Runtime parameters ------------------------------------------------
  const size_t small_q = pir_params_.get_small_q();
  const size_t small_q_width =
      static_cast<size_t>(std::ceil(std::log2(small_q)));
  constexpr size_t coeff_count = DBConsts::PolyDegree;

  // --- 2.  Bit-packing state -------------------------------------------------
  uint8_t byte_buf = 0;   // currently accumulated bits (LSB-first)
  size_t bits_filled = 0; // number of valid bits in byte_buf
  size_t total_bytes = 0; // bytes written so far

  auto flush_byte = [&]() {
    stream.put(static_cast<char>(byte_buf));
    ++total_bytes;
    byte_buf = 0;
    bits_filled = 0;
  };

  // --- 3.  Write every coefficient of the two polynomials -------------------
  for (size_t poly_id = 0; poly_id < 2; ++poly_id) {
    const uint64_t *data = response.data(poly_id);

    for (size_t i = 0; i < coeff_count; ++i) {
      uint64_t coeff = data[i] & ((1ULL << small_q_width) - 1); // keep LS bits only
      size_t bits_written = 0;

      while (bits_written < small_q_width) {
        const size_t room = 8 - bits_filled; // free bits in buffer
        const size_t bits_to_take = std::min(room, small_q_width - bits_written);

        const uint8_t chunk = static_cast<uint8_t>(
            (coeff >> bits_written) & ((1ULL << bits_to_take) - 1));

        byte_buf |= static_cast<uint8_t>(chunk << bits_filled);
        bits_filled += bits_to_take;
        bits_written += bits_to_take;

        if (bits_filled == 8)
          flush_byte();
      }
    }
  }

  // --- 4.  Flush padding byte (if any) --------------------------------------
  if (bits_filled != 0)
    flush_byte();

  return total_bytes;
}



void PirServer::fill_inter_res() {
  // We need to store 1/dim[0] many ciphertexts in the intermediate result.
  // However, in the first dimension, we want to store them in uint128_t.
  // So, we need to calculate the number of uint128_t we need to store.
  // number of rns modulus
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  // number of uint128_t we need to store in the intermediate result
  const size_t elem_cnt = other_dim_sz * DBConsts::PolyDegree * rns_mod_cnt * 2;
  // allocate memory for the intermediate result
  inter_res_.resize(elem_cnt);
}

void PirServer::mod_switch_inplace(RlweCt &ciphertext, const uint64_t q) {
  constexpr size_t coeff_count = DBConsts::PolyDegree;

  // current ciphertext modulus
  const uint64_t Q = pir_params_.get_coeff_modulus()[0];

  // mod switch: round( (ct * q) / Q) ) (mod q)
  uint64_t *data0 = ciphertext.c0.data();
  uint64_t *data1 = ciphertext.c1.data();

  for (size_t i = 0; i < coeff_count; i++) {
    data0[i] = utils::rescale(data0[i], Q, q);
    data1[i] = utils::rescale(data1[i], Q, q);
  }
}











