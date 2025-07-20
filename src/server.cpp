#include "server.h"
#include "gsw_eval.h"
#include "utils.h"
#include "matrix.h"
#include <cassert>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <fstream>
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

// copy the pir_params and set evaluator equal to the context_. 
// client_galois_keys_, client_gsw_keys_, and db_ are not set yet.
PirServer::PirServer(const PirParams &pir_params)
    : pir_params_(pir_params), context_(pir_params.get_seal_params()),
      num_pt_(pir_params.get_num_pt()), evaluator_(context_), dims_(pir_params.get_dims()),
      key_gsw_(pir_params, pir_params.get_l_key(), pir_params.get_base_log2_key()),
      data_gsw_(pir_params, pir_params.get_l(), pir_params.get_base_log2()) {
  // delete the raw_db_file if it exists
  std::remove(RAW_DB_FILE);
  // allocate enough space for the database, init with std::nullopt
  db_ = std::make_unique<std::optional<seal::Plaintext>[]>(num_pt_);
  // after NTT, each database polynomial coefficient will be in mod q. Hence,
  // each pt coefficient will be represented by rns_mod_cnt many uint64_t, same as the ciphertext. 
  db_aligned_ = std::make_unique<uint64_t[]>(num_pt_ * pir_params_.get_coeff_val_cnt());
  // db_aligned_ = (uint64_t *)std::aligned_alloc(64, num_pt_ * pir_params_.get_coeff_val_cnt() * sizeof(uint64_t));
  fill_inter_res();
}

PirServer::~PirServer() {
  // delete the raw_db_file
  std::remove(RAW_DB_FILE);
}

// Fills the database with random data
void PirServer::gen_data() {
  BENCH_PRINT("Generating random data for the server database...");
  std::ifstream random_file("/dev/urandom", std::ios::binary);
  if (!random_file.is_open()) {
    throw std::invalid_argument("Unable to open /dev/urandom");
  }

  // init the database with std::nullopt
  db_.reset(new std::optional<seal::Plaintext>[num_pt_]);
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t num_en_per_pt = pir_params_.get_num_entries_per_plaintext();
  const size_t entry_size = pir_params_.get_entry_size();
  std::cout << "entry_size: " << entry_size << std::endl;

  for (size_t row = 0; row < other_dim_sz; ++row) {
    std::vector<Entry> one_chunk(fst_dim_sz * num_en_per_pt, Entry(entry_size));
    for (size_t col = 0; col < fst_dim_sz; ++col) {
      const size_t poly_id = row * fst_dim_sz + col;
      for (size_t local_id = 0; local_id < num_en_per_pt; ++local_id) {
        const size_t entry_id = poly_id * num_en_per_pt + local_id;
        one_chunk[col * num_en_per_pt + local_id] = utils::generate_entry(entry_id, entry_size, random_file);
      }
    }
    write_one_chunk(one_chunk);
    push_database_chunk(one_chunk, row);
    utils::print_progress(row+1, other_dim_sz);
  }
  random_file.close();
  // transform the ntt_db_ from coefficient form to ntt form. db_ is not transformed.
  preprocess_ntt();
  realign_db();
}

void PirServer::prep_query(const std::vector<seal::Ciphertext> &fst_dim_query,
                           std::vector<uint64_t> &query_data) {
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();       // 256
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt(); // 4096
  const size_t slice_sz = fst_dim_sz * 2;

  // Pre-fetch the data pointers to avoid repeated indirect access
  std::vector<const uint64_t *> data0_ptrs(fst_dim_sz);
  std::vector<const uint64_t *> data1_ptrs(fst_dim_sz);

  // Prefetch all pointers
  for (size_t i = 0; i < fst_dim_sz; ++i) {
    data0_ptrs[i] = fst_dim_query[i].data(0);
    data1_ptrs[i] = fst_dim_query[i].data(1);
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
        query_data[idx] = p0[slice_id];
        query_data[idx + 1] = p1[slice_id];
      }
    }
  }
}

// Computes a dot product between the fst_dim_query and the database for the
// first dimension with a delayed modulus optimization. fst_dim_query should
// be transformed to ntt.
std::vector<seal::Ciphertext>
PirServer::evaluate_first_dim(std::vector<seal::Ciphertext> &fst_dim_query) {
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();  // number of plaintexts in the first dimension
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();  // number of plaintexts in the other dimensions
  const auto seal_params = context_.get_context_data(fst_dim_query[0].parms_id())->parms();
  const auto coeff_modulus = seal_params.coeff_modulus();
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt(); // polydegree * RNS moduli count
  const size_t one_ct_sz = 2 * coeff_val_cnt; // Ciphertext has two polynomials

  // fill the intermediate result with zeros
  std::fill(inter_res_.begin(), inter_res_.end(), 0);

  // transform the selection vector to ntt form
  for (size_t i = 0; i < fst_dim_query.size(); i++) {
    evaluator_.transform_to_ntt_inplace(fst_dim_query[i]);
  }
  
  // reallocate the query data to a continuous memory 
  TIME_START(FST_DIM_PREP);
  std::vector<uint64_t> query_data(fst_dim_sz * one_ct_sz);
  prep_query(fst_dim_query, query_data);
  TIME_END(FST_DIM_PREP);

  /*
  Imagine DB as a (other_dim_sz * fst_dim_sz) matrix, where each element is a
  vector of size coeff_val_cnt. In OnionPIRv1, the first dimension is doing the 
  component wise matrix multiplication. Further details can be found in the "matrix.h" file.
  */
  // prepare the matrices
  matrix_t db_mat { db_aligned_.get(), other_dim_sz, fst_dim_sz, coeff_val_cnt };
  matrix_t query_mat { query_data.data(), fst_dim_sz, 2, coeff_val_cnt };
  matrix128_t inter_res_mat { inter_res_.data(), other_dim_sz, 2, coeff_val_cnt };
  // TODO: should run delay_modulus more often if N_0 is large. Say N_0 = 1000, then we might need mod to avoid overflow.
  TIME_START(CORE_TIME);
  // level_mat_mult_128(&db_mat, &query_mat, &inter_res_mat);
  // TODO: optimize the mat_mat_128 inside this function.
  naive_level_mat_mat_128(&db_mat, &query_mat, &inter_res_mat);
  TIME_END(CORE_TIME);

  // ========== transform the intermediate to coefficient form. Delay the modulus operation ==========
  TIME_START(FST_DELEY_MOD_TIME);
  std::vector<seal::Ciphertext> result; // output vector
  result.reserve(other_dim_sz);
  if (other_dim_sz < 16) {
    delay_modulus_small(result, inter_res_.data());
  }
  else {
    delay_modulus(result, inter_res_.data());
  }
  TIME_END(FST_DELEY_MOD_TIME);

  return result;
}


void PirServer::delay_modulus(std::vector<seal::Ciphertext> &result, const uint128_t *__restrict inter_res) {
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
  const auto coeff_modulus = pir_params_.get_coeff_modulus();
  const size_t inter_padding = other_dim_sz * 2;  // distance between coefficients in inter_res
  
  // We need to unroll the loop to process multiple ciphertexts at once.
  // Otherwise, this function is basically reading the intermediate result 
  // with a stride of inter_padding, which causes many cache misses.
  constexpr size_t unroll_factor = 16;

  // Process ciphertexts in blocks of unroll_factor.
  for (size_t j = 0; j < other_dim_sz; j += unroll_factor) {
    // Create an array of ciphertexts.
    std::array<seal::Ciphertext, unroll_factor> cts;
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      cts[idx] = seal::Ciphertext(context_);
      cts[idx].resize(2);  // each ciphertext stores 2 polynomials
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
      const seal::Modulus &modulus = coeff_modulus[mod_id];
      for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        #pragma unroll
        for (size_t idx = 0; idx < unroll_factor; idx++) {
          // Process polynomial 0 for ciphertext idx.
          uint128_t x0 = inter_res[ base0[idx] + inter_idx0[idx] * inter_padding ];
          uint64_t raw0[2] = { static_cast<uint64_t>(x0), static_cast<uint64_t>(x0 >> 64) };
          cts[idx].data(0)[ ct_idx0[idx]++ ] = util::barrett_reduce_128(raw0, modulus);

          // Process polynomial 1 for ciphertext idx.
          uint128_t x1 = inter_res[ base1[idx] + inter_idx1[idx] * inter_padding ];
          uint64_t raw1[2] = { static_cast<uint64_t>(x1), static_cast<uint64_t>(x1 >> 64) };
          cts[idx].data(1)[ ct_idx1[idx]++ ] = util::barrett_reduce_128(raw1, modulus);
          // Advance intermediate indices.
          inter_idx0[idx]++;
          inter_idx1[idx]++;
        }
      }
    }

    // Mark each ciphertext as being in NTT form and then transform back.
    #pragma unroll
    for (size_t idx = 0; idx < unroll_factor; idx++) {
      cts[idx].is_ntt_form() = true;
      evaluator_.transform_from_ntt_inplace(cts[idx]);
      result.emplace_back(std::move(cts[idx]));
    }
  }
}

void PirServer::delay_modulus_small(std::vector<seal::Ciphertext> &result, const uint128_t *__restrict inter_res) {
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
  const auto coeff_modulus = pir_params_.get_coeff_modulus();
  const size_t inter_padding = other_dim_sz * 2;  // distance between coefficients in inter_res
  
  // Process each ciphertext individually for small cases
  for (size_t j = 0; j < other_dim_sz; j++) {
    // Create a single ciphertext
    seal::Ciphertext ct(context_);
    ct.resize(2);  // each ciphertext stores 2 polynomials

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
      const seal::Modulus &modulus = coeff_modulus[mod_id];
      for (size_t coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        // Process polynomial 0
        uint128_t x0 = inter_res[base0 + inter_idx0 * inter_padding];
        uint64_t raw0[2] = { static_cast<uint64_t>(x0), static_cast<uint64_t>(x0 >> 64) };
        ct.data(0)[ct_idx0++] = util::barrett_reduce_128(raw0, modulus);

        // Process polynomial 1
        uint128_t x1 = inter_res[base1 + inter_idx1 * inter_padding];
        uint64_t raw1[2] = { static_cast<uint64_t>(x1), static_cast<uint64_t>(x1 >> 64) };
        ct.data(1)[ct_idx1++] = util::barrett_reduce_128(raw1, modulus);
        
        // Advance intermediate indices
        inter_idx0++;
        inter_idx1++;
      }
    }

    // Mark ciphertext as being in NTT form and then transform back
    ct.is_ntt_form() = true;
    evaluator_.transform_from_ntt_inplace(ct);
    result.emplace_back(std::move(ct));
  }
}

void PirServer::other_dim_mux(std::vector<seal::Ciphertext> &result,
                              GSWCiphertext &selection_cipher) {

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
  const size_t block_size = result.size() / 2;
  for (size_t i = 0; i < block_size; i++) {
    auto &x = result[i];
    auto &y = result[i + block_size];

    // ========== y = y - x ==========
    TIME_START(OTHER_DIM_ADD_SUB);
    evaluator_.sub_inplace(y, x);
    TIME_END(OTHER_DIM_ADD_SUB);

    // ========== y = b * (y - x) ========== output will be in NTT form
    TIME_START(OTHER_DIM_MUX_EXTERN);
    data_gsw_.external_product(selection_cipher, y, y, LogContext::OTHER_DIM_MUX);
    TIME_END(OTHER_DIM_MUX_EXTERN);

    // ========== y = INTT(y) ==========, INTT stands for inverse NTT
    TIME_START(OTHER_DIM_INTT);
    evaluator_.transform_from_ntt_inplace(y);
    TIME_END(OTHER_DIM_INTT);

    // ========== result = y + x ==========
    TIME_START(OTHER_DIM_ADD_SUB); 
    evaluator_.add_inplace(result[i], y);  // x + b * (y - x)
    TIME_END(OTHER_DIM_ADD_SUB);
  }
  result.resize(block_size);
}

// This function is using the algorithm 5 in Constant-weight PIR: Single-round Keyword PIR via Constant-weight Equality Operators.
// https://www.usenix.org/conference/usenixsecurity22/presentation/mahdavi. Basically, the algorithm 3 in Onion-Ring ORAM has some typos.
// And we can save one Subs(c_b, k) operation in the algorithm 3. The notations of this function follows the constant-weight PIR paper.
std::vector<seal::Ciphertext>
PirServer::expand_query(size_t client_id, seal::Ciphertext &ciphertext) const {
  seal::EncryptionParameters params = pir_params_.get_seal_params();
  const size_t expan_height = pir_params_.get_expan_height();
  const auto& client_galois_key = client_galois_keys_.at(client_id); // used for substitution

  /*  Pseudu code:
  for a = 0 .. logN do
    k = 2^a // tree width at level a
    for b = 0 .. k - 1 do
      c' = Subs(c_b, n/k + 1)
      c_{b + k} = (c_b - c') * x^{-k}
      c_{b} = c_b + c'
    end
  end
  */

  // The access pattern to this array looks like this: https://raw.githubusercontent.com/chenyue42/images-for-notes/master/uPic/expansion.png
  // It helps me to understand this recursion :)
  std::vector<seal::Ciphertext> cts( (size_t)pow(2, expan_height) );
  cts[0] = ciphertext;   // c_0 = c in paper

  for (size_t a = 0; a < expan_height; a++) {
    // the number of ciphertexts in the current level of the expansion tree
    const size_t level_size = pow(2, a);

    for (size_t b = 0; b < level_size; b++) {
      seal::Ciphertext c_prime = cts[b];
      TIME_START(APPLY_GALOIS);
      evaluator_.apply_galois_inplace(c_prime, DatabaseConstants::PolyDegree / level_size + 1,
                                      client_galois_key); // Subs(c_b, n/k + 1)
      TIME_END(APPLY_GALOIS);
      seal::Ciphertext temp;
      evaluator_.sub(cts[b], c_prime, temp);
      utils::shift_polynomial(params, temp, cts[b + level_size], -level_size);
      evaluator_.add_inplace(cts[b], c_prime);
    }
  }

  return cts;
}

//  single-loop level-order expansion  (root index = 1)
std::vector<seal::Ciphertext>
PirServer::fast_expand_qry(std::size_t client_id,seal::Ciphertext &ciphertext) const {
  // ============== parameters
  const size_t useful_cnt = pir_params_.get_fst_dim_sz() +
                            pir_params_.get_l() * (dims_.size() - 1); // u
  const size_t expan_height = pir_params_.get_expan_height(); // h
  const size_t w = size_t{1} << expan_height;                 // 2^h
  const auto &galois_key = client_galois_keys_.at(client_id);
  seal::EncryptionParameters params = pir_params_.get_seal_params();
  
  // ============== storage   – index 0 is *unused*, root is slot 1
  std::vector<seal::Ciphertext> cts(2 * w); // slots 0 … 2w-1
  cts[1] = ciphertext;                      // c1  ←  input

  // ============== level-order walk, skip right-of-u sub-trees
  for (size_t i = 1; i < w; ++i) { // internal nodes only
    const int k = int{1} << (std::bit_width(i) - 1); // k = 2^{⌊log i⌋}   (span of this sub-tree)

    // left-most leaf index of this sub-tree
    const size_t left_leaf = i * w / k - w; // exact integer
    if (left_leaf >= useful_cnt)
      continue; // skip whole sub-tree
    
    // ============== split   c[i] ->  c[2i] , c[2i+1]
    // c' = Subs(c_i, w/k+1)
    seal::Ciphertext c_prime = cts[i];
    TIME_START(APPLY_GALOIS);
    evaluator_.apply_galois_inplace(c_prime,
                                    DatabaseConstants::PolyDegree / k + 1, 
                                    galois_key); 
    TIME_END(APPLY_GALOIS);
    TIME_START("add_sub");
    // c_{2i}   =  c_i + c'
    evaluator_.add(cts[i], c_prime, cts[2 * i]);

    // c_{2i+1} = (c_i − c') * x^{−k}
    evaluator_.sub_inplace(cts[i], c_prime);
    TIME_END("add_sub");

    TIME_START("shift polynomial");
    utils::shift_polynomial(params, cts[i], cts[2 * i + 1], -k);
    TIME_END("shift polynomial");
  }

  // ==============  return the first  u  leaves: heap slots  w … w+u−1
  return std::vector<seal::Ciphertext>(cts.begin() + w,cts.begin() + w + useful_cnt);
}

// std::vector<seal::Ciphertext>
// PirServer::fast_expand_qry(size_t client_id,
//                            seal::Ciphertext &ciphertext) const {
//   seal::EncryptionParameters params = pir_params_.get_seal_params();
//   // we want fst_dim_sz many bfv for first dimension, and l many bfv for each other dimension mux. 
//   const size_t useful_cnt = pir_params_.get_fst_dim_sz() + pir_params_.get_l() * (dims_.size() - 1);
//   const size_t expan_height = pir_params_.get_expan_height();
//   const auto& client_galois_key = client_galois_keys_.at(client_id); // used for substitution
//   std::vector<seal::Ciphertext> cts(useful_cnt + useful_cnt % 2); // just in case we have odd number of useful ciphertexts.
//   DEBUG_PRINT("expansion height: " << expan_height << ", useful count: " << useful_cnt);

//   /*  Pseudu code:
//   nonzero_cnt = fst_dim_sz + l * (dims.size() - 1)
//   for a = 0 .. logN - 1 do
//     k = 2^a // tree width at level a
//     t = nonzero_cnt / recursive_ceil_half(nonzero_cnt, expan_height - a)
//     for b = t-1 .. 0 do
//       c' = Subs(c_b, n/k + 1)
//       c_{2b + 1} = (c_b - c') * x^{-k}
//       c_{2b} = c_b + c'
//     end
//   end
//   */

//   cts[0] = ciphertext;   // c_0 = c in paper
//   for (size_t a = 0; a < expan_height; a++) {
//     // the number of ciphertexts in the current level of the expansion tree
//     const size_t level_size = pow(2, a);
//     const size_t trimed_level_sz = utils::repeated_ceil_half(useful_cnt, expan_height - a);
//     // DEBUG_PRINT("Level size: " << level_size << ", Trimed level size: " << trimed_level_sz);
    
//     for (int b = trimed_level_sz - 1; b > -1; b--) { // ! we have to reverse the order otherwise we will overwrite the cts[b] before using it.
//       seal::Ciphertext c_prime = cts[b]; 
//       TIME_START(APPLY_GALOIS);
//       evaluator_.apply_galois_inplace(c_prime, DatabaseConstants::PolyDegree / level_size + 1,
//                                       client_galois_key); // Subs(c_b, n/k + 1)
//       TIME_END(APPLY_GALOIS);
//       // ! order matters! 
//       TIME_START("expand extra");
//       seal::Ciphertext temp;
//       evaluator_.sub(cts[b], c_prime, temp);  // temp = c_b - c'
//       utils::shift_polynomial(params, temp, cts[2 * b + 1], -level_size); // temp * x^{-k}, store in c_{2b + 1}
//       evaluator_.add(cts[b], c_prime, cts[2 * b]);
//       TIME_END("expand extra");
//     }
//   }

//   return cts;
// }

void PirServer::set_client_galois_key(const size_t client_id, std::stringstream &galois_stream) {
  seal::GaloisKeys client_key;
  client_key.load(context_, galois_stream);
  BENCH_PRINT("Number of galois keys: " << client_key.data().size());
  client_galois_keys_[client_id] = client_key;
}

void PirServer::set_client_gsw_key(const size_t client_id, std::stringstream &gsw_stream) {
  std::vector<seal::Ciphertext> temp_gsw;
  // load 2l ciphertexts from the stream
  for (size_t i = 0; i < 2 * pir_params_.get_l_key(); i++) {
    seal::Ciphertext row;
    row.load(context_, gsw_stream);
    temp_gsw.push_back(row);
  }
  GSWCiphertext gsw_key;

  key_gsw_.seal_GSW_vec_to_GSW(gsw_key, temp_gsw);
  key_gsw_.gsw_ntt_negacyclic_harvey(gsw_key); // transform the GSW ciphertext to NTT form

  client_gsw_keys_[client_id] = gsw_key;
}


Entry PirServer::direct_get_entry(const size_t entry_idx) const {
  // read the entry from raw_db_file
  std::ifstream in_file(RAW_DB_FILE, std::ios::binary);
  if (!in_file.is_open()) {
    throw std::invalid_argument("Unable to open file for reading");
  }
  // Read the entry from the file
  auto entry_size = pir_params_.get_entry_size();
  in_file.seekg(entry_idx * entry_size);
  Entry entry(entry_size);
  in_file.read(reinterpret_cast<char *>(entry.data()), entry_size);
  in_file.close();

  return entry;
}


seal::Ciphertext PirServer::make_query(const size_t client_id, std::stringstream &query_stream) {
  // receive the query from the client
  seal::Ciphertext query; 
  query.load(context_, query_stream);

  // ========================== Expansion & conversion ==========================
  // Query expansion
  TIME_START(EXPAND_TIME);
  // std::vector<seal::Ciphertext> query_vector = expand_query(client_id, query);
  std::vector<seal::Ciphertext> query_vector = fast_expand_qry(client_id, query);
  TIME_END(EXPAND_TIME);

  // Reconstruct RGSW queries
  TIME_START(CONVERT_TIME);
  std::vector<GSWCiphertext> gsw_vec(dims_.size() - 1); // GSW ciphertexts
  if (dims_.size() != 1) {  // if we do need futher dimensions
    for (size_t i = 1; i < dims_.size(); i++) {
      std::vector<seal::Ciphertext> lwe_vector; // BFV ciphertext, size l * 2. This vector will be reconstructed as a single RGSW ciphertext.
      for (size_t k = 0; k < DatabaseConstants::GSW_L; k++) {
        auto ptr = dims_[0] + (i - 1) * DatabaseConstants::GSW_L + k;
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
  query_vector.resize(dims_[0]);
  std::vector<seal::Ciphertext> result = evaluate_first_dim(query_vector);
  TIME_END(FST_DIM_TIME);

  // Evaluate the other dimensions
  TIME_START(OTHER_DIM_TIME);
  if (dims_.size() != 1) {
    for (size_t i = 1; i < dims_.size(); i++) {
      other_dim_mux(result, gsw_vec[i - 1]);
    }
  }
  TIME_END(OTHER_DIM_TIME);

  // ========================== Post-processing ==========================
  TIME_START(MOD_SWITCH);
  // modulus switching so to reduce the response size by half
  if(pir_params_.get_rns_mod_cnt() > 1) {
    DEBUG_PRINT("Modulus switching to the next modulus...");
    evaluator_.mod_switch_to_next_inplace(result[0]); // result.size() == 1.
  }
  // we can always switch to the small modulus it correctness is guaranteed.
  if (DatabaseConstants::SmallQWidth < DatabaseConstants::CoeffMods[0]) {
    DEBUG_PRINT("Modulus switching for a single modulus...");
    const uint64_t small_q = pir_params_.get_small_q();
    mod_switch_inplace(result[0], small_q);
  }

  TIME_END(MOD_SWITCH);
  DEBUG_PRINT("Modulus switching done.");
  return result[0];
}


seal::Ciphertext PirServer::make_query_no_expand(std::vector<seal::Ciphertext> &bfv_vec, std::vector<GSWCiphertext> gsw_vec) {
  // ========================== Evaluations ==========================
  // Evaluate the first dimension
  TIME_START(FST_DIM_TIME);
  std::vector<seal::Ciphertext> result = evaluate_first_dim(bfv_vec);
  TIME_END(FST_DIM_TIME);

  // Evaluate the other dimensions
  TIME_START(OTHER_DIM_TIME);
  if (dims_.size() != 1) {
    for (size_t i = 1; i < dims_.size(); i++) {
      other_dim_mux(result, gsw_vec[i - 1]);
    }
  }
  TIME_END(OTHER_DIM_TIME);

  // ========================== Post-processing ==========================
  TIME_START(MOD_SWITCH);
  // modulus switching so to reduce the response size by half
  if(pir_params_.get_rns_mod_cnt() > 1) {
    DEBUG_PRINT("Modulus switching to the next modulus...");
    evaluator_.mod_switch_to_next_inplace(result[0]); // result.size() == 1.
  }
  // we can always switch to the small modulus it correctness is guaranteed.
  DEBUG_PRINT("Modulus switching for a single modulus...");
  const uint64_t small_q = pir_params_.get_small_q();
  mod_switch_inplace(result[0], small_q);

  TIME_END(MOD_SWITCH);
  DEBUG_PRINT("Modulus switching done.");
  return result[0];
}



size_t PirServer::save_resp_to_stream(const seal::Ciphertext &response,
                                      std::stringstream &stream) {
  // For now, we only serve the single modulus case.

  // --- 1.  Runtime parameters ------------------------------------------------
  const size_t small_q = pir_params_.get_small_q();
  const size_t small_q_width =
      static_cast<size_t>(std::ceil(std::log2(small_q)));
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;

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

void PirServer::push_database_chunk(std::vector<Entry> &chunk_entry, const size_t chunk_idx) {
  // Flattens data into vector of u8s and pads each entry with 0s to entry_size number of bytes.
  // This is actually resizing from entry.size() to pir_params_.get_entry_size()
  // This is redundent if the given entries uses the same pir parameters.
  for (Entry &entry : chunk_entry) {
    if (entry.size() != 0 && entry.size() <= pir_params_.get_entry_size()) {
      entry.resize(pir_params_.get_entry_size(), 0);
    }

    if (entry.size() > pir_params_.get_entry_size()) {
        std::invalid_argument("Entry size is too large");
    }
  }

  const size_t bits_per_coeff = pir_params_.get_num_bits_per_coeff();
  const size_t num_entries_per_plaintext = pir_params_.get_num_entries_per_plaintext();
  const size_t num_pt_per_chunk = chunk_entry.size() / num_entries_per_plaintext;  // number of plaintexts in the new chunk
  const uint128_t coeff_mask = (uint128_t(1) << (bits_per_coeff)) - 1;  // bits_per_coeff many 1s
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();  // number of plaintexts in the first dimension
  const size_t chunk_offset = fst_dim_sz * chunk_idx;  // offset for the current chunk

  // Now we handle plaintexts one by one.
  for (size_t i = 0; i < num_pt_per_chunk; i++) {
    seal::Plaintext plaintext(DatabaseConstants::PolyDegree);

    // Loop through the entries that corresponds to the current plaintext. 
    // Then calculate the total size (in bytes) of this plaintext.
    // NOTE: it is possible that some entry is empty, which has size 0.
    size_t additive_sum_size = 0;
    for (size_t j = num_entries_per_plaintext * i;
         j < std::min(num_entries_per_plaintext * (i + 1), chunk_entry.size()); j++) {
      additive_sum_size += chunk_entry[j].size();
    }

    if (additive_sum_size == 0) {
      continue; // leave std::nullopt in the chunk if the plaintext is empty.
    }

    size_t index = 0;  // index for the current coefficient to be filled
    uint128_t data_buffer = 0;
    size_t data_offset = 0;
    // For each entry in the current plaintext
    for (size_t j = num_entries_per_plaintext * i;
         j < std::min(num_entries_per_plaintext * (i + 1), chunk_entry.size()); j++) {
      // For each byte in this entry
      for (size_t k = 0; k < pir_params_.get_entry_size(); k++) {
        // data_buffer temporarily stores the data from entry bytes
        data_buffer += uint128_t(chunk_entry[j][k]) << data_offset;
        data_offset += 8;
        // When we have enough data to fill a coefficient
        // We will one by one fill the coefficients with the data_buffer.
        while (data_offset >= bits_per_coeff) {
          plaintext[index] = data_buffer & coeff_mask;
          index++;
          data_buffer >>= bits_per_coeff;
          data_offset -= bits_per_coeff;
        }
      }
    }
    // add remaining data to a new coefficient
    if (data_offset > 0) {
      plaintext[index] = data_buffer & coeff_mask;
      index++;
    }
    db_[i + chunk_offset] = std::move(plaintext);
  }
}

void PirServer::preprocess_ntt() {
  BENCH_PRINT("\nTransforming the database to NTT form...");
  // tutorial on Number Theoretic Transform (NTT): https://youtu.be/Pct3rS4Y0IA?si=25VrCwBJuBjtHqoN
  for (size_t i = 0; i < num_pt_; ++i) {
    if (db_[i].has_value()) {
      seal::Plaintext &pt = db_[i].value();
      evaluator_.transform_to_ntt_inplace(pt, context_.first_parms_id());
    }
  }

  // print the the first 5 coefficients of the first plaintext in uint64_t
  DEBUG_PRINT("After NTT, the coefficients look like:")
  auto temp_pt = db_[0].value();
  for (size_t i = 0; i < 5; i++) {
    DEBUG_PRINT(std::bitset<64>(temp_pt.data()[i]));
  }
}


void PirServer::realign_db() {
  BENCH_PRINT("Realigning the database...");
  // Since we are breaking each coefficient of the same plaintext into different
  // levels, I believe this realignment is unavoidable since the ntt
  // preprocessing requires the coefficients to be in continuous memory.

  // realign the database to the first dimension
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t coeff_val_cnt = pir_params_.get_coeff_val_cnt();
  const size_t num_pt = pir_params_.get_num_pt();
  constexpr size_t tile_sz = 16;

  for (size_t level_base = 0; level_base < coeff_val_cnt; level_base += tile_sz) {
    for (size_t row = 0; row < other_dim_sz; ++row) {
      for (size_t col = 0; col < fst_dim_sz; ++col) {
        uint64_t *db_ptr = db_[row * fst_dim_sz + col].value().data();  // getting the pointer to the current plaintext
        for (size_t level = 0; level < tile_sz; level++) {
          size_t idx = (level_base + level) * num_pt + row * fst_dim_sz + col;
          db_aligned_[idx] = db_ptr[level_base + level];
        }
      }
    }
  }
  // destroy the db_ to save memory
  db_.reset();
}


void PirServer::fill_inter_res() {
  // We need to store 1/dim[0] many ciphertexts in the intermediate result.
  // However, in the first dimension, we want to store them in uint128_t.
  // So, we need to calculate the number of uint128_t we need to store.
  // number of rns modulus
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  // number of uint128_t we need to store in the intermediate result
  const size_t elem_cnt = other_dim_sz * DatabaseConstants::PolyDegree * rns_mod_cnt * 2;
  // allocate memory for the intermediate result
  inter_res_.resize(elem_cnt);
}

void PirServer::write_one_chunk(std::vector<Entry> &data) {
  // write the database to a binary file in CACHE_DIR
  std::string filename = std::string(RAW_DB_FILE);
  std::ofstream out_file(filename, std::ios::binary | std::ios::app); // append to the file
  if (out_file.is_open()) {
    for (auto &entry : data) {
      out_file.write(reinterpret_cast<const char *>(entry.data()), entry.size());
    }
    out_file.close();
  } else {
    std::cerr << "Unable to open file for writing" << std::endl;
  }
}


void PirServer::mod_switch_inplace(seal::Ciphertext &ciphertext, const uint64_t q) {
  if (ciphertext.is_ntt_form()) {
    throw std::invalid_argument("Ciphertext is in NTT form, cannot mod switch.");
  }

  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;

  // current ciphertext modulus
  const size_t Q = pir_params_.get_coeff_modulus()[0].value(); 

  // mod switch: round( (ct * q) / Q) ) (mod q)
  // the multiplication and division are in rational.
  // there are two ciphertext polynomials
  auto* data0 = ciphertext.data(0);
  auto* data1 = ciphertext.data(1);
  
  const long double scale = static_cast<double>(q) / static_cast<double>(Q);
  
  for (size_t i = 0; i < DatabaseConstants::PolyDegree; i++) {
    data0[i] = (uint64_t)std::round((long double)data0[i] * scale);
    data1[i] = (uint64_t)std::round((long double)data1[i] * scale);
  }
}











