#include "client.h"
#include "pir.h"
#include "utils.h"
#include "gsw.h"
#include "rlwe.h"
#include "hexl/hexl.hpp"
#include <cassert>
#include <random>


// constructor
PirClient::PirClient(const PirParams &pir_params)
    : client_id_(rand()), pir_params_(pir_params),
      rng_(std::random_device{}()),
      rlwe_sk_(gen_secret_key(DBConsts::PolyDegree,
                              pir_params.get_coeff_modulus()[0], rng_)) {
  init_sk_small_q();
}

GSWCt PirClient::generate_gsw_from_key() {
  constexpr size_t N = DBConsts::PolyDegree;
  const uint64_t q = pir_params_.get_coeff_modulus()[0];

  // Pull sk into coefficient form (it is stored in NTT form under q).
  std::vector<uint64_t> sk_coef(rlwe_sk_.data.begin(), rlwe_sk_.data.end());
  utils::ntt_inv(sk_coef.data(), N, q);

  GSWEval key_gsw(pir_params_, pir_params_.get_l_key(), pir_params_.get_base_log2_key());
  return key_gsw.plain_to_gsw(sk_coef, rlwe_sk_, rng_);
}


std::vector<size_t> PirClient::get_query_indices(size_t pt_idx) {
  const size_t col_idx = pt_idx % pir_params_.get_fst_dim_sz();  // the first dimension
  const size_t row_idx = pt_idx / pir_params_.get_fst_dim_sz();  // the rest of the dimensions
  const size_t other_dim_sz = pir_params_.get_other_dim_sz();
  const size_t d = pir_params_.get_num_dims();
  const size_t h = d - 1; // the height of the further dimension complete binary tree.
  
  std::vector<size_t> query_indices = {col_idx};

  // Handle single dimension case
  if (d == 1) {
    // For single dimension, we only need the column index
    DEBUG_PRINT("Single dimension case - returning col_idx: " << col_idx);
    return query_indices;
  }
  
  const size_t r = 2 * other_dim_sz - (1 << h);   // the number of elements in the last level of the complete binary tree.
  const size_t sl = other_dim_sz - r;

  // the last r elements lives in the last level of the complete binary tree.
  // It is an even number but it is not a power of 2.
  // The rest sl elements lives in the second to last level of the complete binary tree.
  // Observe that other_dim_sz - r/2 = 2^(h-1), which is the number of nodes in the second to last level of the complete binary tree.
  // we use the first selection bit to compute the mux for the first r elements.
  // The rest is a normal perfect binary tree. 
  // the first selection bit is special:
  size_t perfect_idx;
  if (row_idx < other_dim_sz - r) {
    query_indices.push_back(0);
    perfect_idx = row_idx;
  } else {
    size_t corrected_idx = row_idx - sl;
    query_indices.push_back(corrected_idx % 2);
    perfect_idx = sl + corrected_idx / 2;
  }
  
  // For the remaining perfect tree levels, emit bits MSB-first
  if (h > 1) {
    // There are (h - 1) bits for the perfect subtree
    for (size_t k = h - 2; k + 1 > 0; k--) {
      query_indices.push_back((perfect_idx >> k) & 1ULL);
      if (k == 0) break;
    }
  }
  
  return query_indices;
}




RlweCt PirClient::fast_generate_query(const size_t pt_idx) {
  constexpr size_t N = DBConsts::PolyDegree;
  const uint64_t Q = pir_params_.get_coeff_modulus()[0];
  const uint64_t t = pir_params_.get_plain_mod();
  const double sigma = pir_params_.get_noise_std_dev();

  std::vector<size_t> query_indices = get_query_indices(pt_idx);
  PRINT_INT_ARRAY("\t\tquery_indices", query_indices.data(), query_indices.size());
  const size_t expan_height = pir_params_.get_expan_height();
  const size_t bits_per_ciphertext = 1 << expan_height;

  // plaintext has one nonzero coefficient = inv(bits_per_ciphertext) mod t
  uint64_t inverse = 0;
  utils::try_invert_uint_mod(bits_per_ciphertext, t, inverse);
  const size_t reversed_index = utils::bit_reverse(query_indices[0], expan_height);
  DEBUG_PRINT("reversed_index: " << reversed_index << ", query_indices[0]: " << query_indices[0]);

  // BFV encrypt under sk: c0 = -(a*s+e) + round(Q*m/t),  c1 = a  (coefficient form)
  RlweCt query;
  encrypt_zero(rlwe_sk_, N, Q, sigma, rng_, query, /*ntt_form=*/false);
  const uint64_t scaled = static_cast<uint64_t>(
      ((__uint128_t)Q * inverse + (t >> 1)) / t % Q);
  query.c0[reversed_index] = (query.c0[reversed_index] + scaled) % Q;

  add_gsw_to_query(query, query_indices);
  return query;
}


// seal::Ciphertext PirClient::gen_mult_queries(const size_t pt_idx, const size_t num_queries) {
//   std::vector<size_t> query_indices = get_query_indices(pt_idx);
//   const size_t bits_per_query = 1 << pir_params_.get_expan_height();
//   // let's assume all queries are expanded to the same size.

//   uint64_t inverse = 0;
//   const uint64_t plain_modulus = pir_params_.get_plain_mod();
//   seal::util::try_invert_uint_mod(bits_per_query, plain_modulus, inverse);  // finds bits_per_query^{-1} mod plain_modulus

//   // create a vector of ciphertexts.
//   std::vector<seal::Ciphertext> queries(num_queries);

// }



void PirClient::add_gsw_to_query(RlweCt &query, const std::vector<size_t> query_indices) {
  // no further dimensions
  if (query_indices.size() == 1) { return; }
  const size_t expan_height = pir_params_.get_expan_height();
  const size_t bits_per_ciphertext = 1 << expan_height; // padding msg_size to the next power of 2
  const size_t l = pir_params_.get_l();
  const size_t base_log2 = pir_params_.get_base_log2();
  const auto coeff_modulus = pir_params_.get_coeff_modulus();
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const size_t fst_dim_sz = pir_params_.get_fst_dim_sz();

  // The following two for-loops calculates the powers for GSW gadgets.
  std::vector<uint64_t> inv(rns_mod_cnt);
  for (size_t k = 0; k < rns_mod_cnt; k++) {
    uint64_t result;
    utils::try_invert_uint_mod(bits_per_ciphertext, coeff_modulus[k], result);
    inv[k] = result;
  }

  // rns_mod_cnt many rows, each row is B^{l-1},, ..., B^0 under different moduli
  std::vector<std::vector<uint64_t>> gadget = utils::gsw_gadget(l, base_log2, rns_mod_cnt, coeff_modulus);

  // This for-loop corresponds to the for-loop in Algorithm 1 from the OnionPIR paper
  auto q_head = query.data(0); // points to the first coefficient of the first ciphertext(c0) 
  for (size_t i = 1; i < query_indices.size(); i++) {  // dimensions
    // we use this if statement to replce the j for loop in Algorithm 1. This is because N_i = 2 for all i > 0
    // When 0 is requested, we use initial encrypted value of seal::Ciphertext query, where the coefficients decrypts to 0. 
    // When 1 is requested, we add special values to the coefficients of the query so that they decrypts to correct GSW(1) values.
    if (query_indices[i] == 1) {
      for (size_t k = 0; k < l; k++) {
        const size_t coef_pos = fst_dim_sz + (i-1) * l + k;  // the position of the coefficient in the resulting query
        const size_t reversed_idx = utils::bit_reverse(coef_pos, expan_height);  // the position of the coefficient in the query
        for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
          const size_t pad = mod_id * DBConsts::PolyDegree;   // We use two moduli for the same gadget value. They are apart by coeff_count.
          inter_coeff_t mod = coeff_modulus[mod_id];
          // the coeff is (B^{l-1}, ..., B^0) / bits_per_ciphertext
          uint64_t coef = (inter_coeff_t)gadget[mod_id][k] * inv[mod_id] % mod;
          q_head[reversed_idx + pad] = (q_head[reversed_idx + pad] + coef) % mod;
        }
      }
    }
  }
}


// size_t PirClient::write_query_to_stream(const seal::Ciphertext &query, std::stringstream &data_stream) {
//   return query.save(data_stream);
// }

// size_t PirClient::write_gsw_to_stream(const std::vector<Ciphertext> &gsw, std::stringstream &gsw_stream) {
//   size_t total_size = 0;
//   for (auto &ct : gsw) {
//     size_t size = ct.save(gsw_stream);
//     total_size += size;
//   }
//   return total_size;
// }

bvks::BvGaloisKeys PirClient::create_bv_galois_keys() {
  return bvks::gen_bv_galois_keys(pir_params_, rlwe_sk_);
}

RlwePt PirClient::decrypt_reply(const RlweCt& reply) {
  return decrypt_mod_q(reply);
}

// Shared single-mod decryption under modulus `q` using the matching sk.
// Computes phase = c0 + c1*s (mod q), recovers m = round(phase * t / q),
// and returns (plaintext, noise_budget).
static void decrypt_phase_single_mod(const RlweCt &ct,
                                     const uint64_t *sk_ntt,
                                     uint64_t q, uint64_t t,
                                     RlwePt &out_pt,
                                     int &out_budget) {
  constexpr size_t N = DBConsts::PolyDegree;

  std::vector<uint64_t> phase(N);
  std::vector<uint64_t> c0(N), c1(N);
  for (size_t i = 0; i < N; i++) {
    c0[i] = ct.c0[i] % q;
    c1[i] = ct.c1[i] % q;
  }

  if (ct.ntt_form) {
    intel::hexl::EltwiseMultMod(phase.data(), c1.data(), sk_ntt, N, q, 1);
    utils::ntt_inv(phase.data(), N, q);
    utils::ntt_inv(c0.data(), N, q);
  } else {
    utils::ntt_fwd(c1.data(), N, q);
    intel::hexl::EltwiseMultMod(phase.data(), c1.data(), sk_ntt, N, q, 1);
    utils::ntt_inv(phase.data(), N, q);
  }
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), c0.data(), N, q);

  out_pt.data.assign(N, 0);
  const uint64_t delta = q / t;
  const uint64_t half_q = q / 2;
  uint64_t max_noise = 0;

  for (size_t i = 0; i < N; i++) {
    uint128_t numerator = (uint128_t)phase[i] * t + half_q;
    uint64_t m = static_cast<uint64_t>(numerator / q) % t;
    out_pt.data[i] = m;

    uint64_t approx = static_cast<uint64_t>((uint128_t)delta * m % q);
    uint64_t noise_pos = (phase[i] >= approx) ? (phase[i] - approx) : (q - approx + phase[i]);
    uint64_t noise_abs = (noise_pos > half_q) ? (q - noise_pos) : noise_pos;
    if (noise_abs > max_noise) max_noise = noise_abs;
  }

  out_budget = (max_noise > 0)
    ? static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t * max_noise)))
    : static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t)));
}

RlwePt PirClient::decrypt_ct(const RlweCt &ct) {
  const uint64_t q = pir_params_.get_coeff_modulus()[0];
  const uint64_t t = pir_params_.get_plain_mod();
  RlwePt result;
  int budget = 0;
  decrypt_phase_single_mod(ct, rlwe_sk_.data.data(), q, t, result, budget);
  return result;
}

int PirClient::noise_budget(const RlweCt &ct) {
  const uint64_t q = pir_params_.get_coeff_modulus()[0];
  const uint64_t t = pir_params_.get_plain_mod();
  RlwePt tmp;
  int budget = 0;
  decrypt_phase_single_mod(ct, rlwe_sk_.data.data(), q, t, tmp, budget);
  return budget;
}


// =======================================================================
// Below is my previous attempt to decrypt the ciphertext using new modulus.
// However, I didn't notice that the secret key used in this method is not setup
// correctly. After we have the secret_key_mod_switch, it is easier to simply
// create new decryptor using the new secret key. 
// -- Yue
// =======================================================================

// seal::Plaintext PirClient::custom_decrypt_mod_q(const seal::Ciphertext &ct, const std::vector<seal::Modulus>& q_mod) {
//   auto params = pir_params_.get_seal_params();
//   auto context_ = pir_params_.get_context();
//   const size_t plain_mod = pir_params_.get_plain_mod();
//   auto ntt_tables = context_.get_context_data(params.parms_id())->small_ntt_tables();
//   const size_t coeff_count = DBConsts::PolyDegree;
//   MemoryPoolHandle pool_ = MemoryManager::GetPool(mm_prof_opt::mm_force_new, true);
//   seal::Plaintext phase(coeff_count), result(coeff_count);

//   // Create a new RNSTool (copied from context.cpp)
//   Pointer<RNSBase> coeff_modulus_base = allocate<RNSBase>(pool_, q_mod, pool_);
//   util::Pointer<util::RNSTool> rns_tool_ = allocate<RNSTool>(pool_, coeff_count, *coeff_modulus_base, plain_mod, pool_);

//   // =========================== Now let's try to decrypt the ciphertext. Adapted from decryptor.cpp
//   /*
//     The high-level is to compute round( (c0 * s + c1) / Delta )
//     The questions are:
//     1. how do you do polynomial multiplication and addition?
//       ANS: we transform c1 to NTT form, use dyadic_product_coeffmod to do the
//           multiplication, then INTT it back to coeff form and compute
//           add_poly_coeffmod.
//     2. What is Delta?
//       ANS: Delta = floor(new_q / plain_mod) = (new_q - new_q % plain_mod) / plain_mod
//     3. How do we calculate the division?
//       ANS: Doesn't look like a division over rationals... I am checking
//           RNSTool::decrypt_scale_and_round. It "divide scaling variant using
//           BEHZ FullRNS techniques", as introduced by comment in decryptor.cpp
//           We can use this function if we setup the RNSTool correctly.j
//   */

//   const size_t rns_mod_cnt = q_mod.size();

//   // ======================= Compute the phase = c0 + c1 * s
//   util::Pointer<std::uint64_t> secret_key_array_ = allocate_poly(coeff_count, 2, pool_);
//   set_poly(secret_key_.data().data(), coeff_count, 2, secret_key_array_.get());

//   // settingup iterators for input and the phase
//   ConstRNSIter secret_key_array(secret_key_array_.get(), coeff_count);
//   ConstRNSIter c0(ct.data(0), coeff_count);
//   ConstRNSIter c1(ct.data(1), coeff_count);
//   SEAL_ALLOCATE_ZERO_GET_RNS_ITER(phase_iter, coeff_count, rns_mod_cnt, pool_);

//   // perform the elementwise multiplication and addition
//   SEAL_ITERATE(
//     iter(c0, c1, secret_key_array, q_mod, ntt_tables, phase_iter), rns_mod_cnt,
//     [&](auto I) {
//       set_uint(get<1>(I), coeff_count, get<5>(I));
//       // Transform c_1 to NTT form
//       ntt_negacyclic_harvey_lazy(get<5>(I), get<4>(I));
//       // put < c_1 * s > mod q in destination
//       dyadic_product_coeffmod(get<5>(I), get<2>(I), coeff_count, get<3>(I), get<5>(I));
//       // Transform back
//       inverse_ntt_negacyclic_harvey(get<5>(I), get<4>(I));
//       // add c_0 to the result; note that destination should be in the same (NTT) form as encrypted
//       add_poly_coeffmod(get<5>(I), get<0>(I), coeff_count, get<3>(I), get<5>(I));
//   });

//   // ======================= scale the phase and round it to get the result.
//   rns_tool_->decrypt_scale_and_round(phase_iter, result.data(), pool_);

//   size_t plain_coeff_count = get_significant_uint64_count_uint(result.data(), coeff_count);
//   result.resize(std::max(plain_coeff_count, size_t(1)));
//   return result;
// }



RlweCt PirClient::load_resp_from_stream(std::stringstream &resp_stream) {
  // For now, we only serve the single modulus case.
  const size_t small_q = pir_params_.get_small_q();
  const size_t small_q_width =
      static_cast<size_t>(std::ceil(std::log2(small_q)));
  constexpr size_t coeff_count = DBConsts::PolyDegree;

  RlweCt result;
  result.c0.assign(coeff_count, 0);
  result.c1.assign(coeff_count, 0);

  uint8_t current_byte = 0;
  size_t bits_left = 0;
  auto next_bit = [&]() -> uint8_t {
    if (bits_left == 0) {
      int ch = resp_stream.get();
      if (ch == EOF)
        throw std::runtime_error("unexpected end of response stream");
      current_byte = static_cast<uint8_t>(ch);
      bits_left = 8;
    }
    uint8_t bit = current_byte & 1;
    current_byte >>= 1;
    --bits_left;
    return bit;
  };
  auto read_coeff = [&](uint64_t &dest) {
    dest = 0;
    for (size_t j = 0; j < small_q_width; ++j)
      dest |= static_cast<uint64_t>(next_bit()) << j;
  };

  for (size_t i = 0; i < coeff_count; ++i) read_coeff(result.c0[i]);
  for (size_t i = 0; i < coeff_count; ++i) read_coeff(result.c1[i]);
  result.ntt_form = false;
  return result;
}


RlwePt PirClient::decrypt_mod_q(const RlweCt &ct) const {
  // Custom single-mod decryption. Computes phase = c0 + c1*s (mod small_q),
  // then recovers plaintext via round(phase * t / q) and measures noise.
  constexpr size_t N = DBConsts::PolyDegree;
  const uint64_t q = pir_params_.get_small_q();
  const uint64_t t = pir_params_.get_plain_mod();

  std::vector<uint64_t> phase(N);
  std::vector<uint64_t> c0(N), c1_ntt(N);
  // Reduce mod q in case mod_switch_inplace produced values = q (from rounding)
  for (size_t i = 0; i < N; i++) {
    c0[i] = ct.c0[i] % q;
    c1_ntt[i] = ct.c1[i] % q;
  }
  utils::ntt_fwd(c1_ntt.data(), N, q);
  intel::hexl::EltwiseMultMod(phase.data(), c1_ntt.data(), sk_ntt_small_q_.data(), N, q, 1);
  utils::ntt_inv(phase.data(), N, q);
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), c0.data(), N, q);

  RlwePt result;
  result.data.assign(N, 0);
  const uint64_t delta = q / t;
  const uint64_t half_q = q / 2;
  uint64_t max_noise = 0;

  for (size_t i = 0; i < N; i++) {
    uint128_t numerator = (uint128_t)phase[i] * t + half_q;
    uint64_t m = static_cast<uint64_t>(numerator / q) % t;
    result.data[i] = m;

    uint64_t approx = static_cast<uint64_t>((uint128_t)delta * m % q);
    uint64_t noise_pos = (phase[i] >= approx) ? (phase[i] - approx) : (q - approx + phase[i]);
    uint64_t noise_abs = (noise_pos > half_q) ? (q - noise_pos) : noise_pos;
    if (noise_abs > max_noise) max_noise = noise_abs;
  }

  int budget = (max_noise > 0)
    ? static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t * max_noise)))
    : static_cast<int>(std::log2(static_cast<double>(q) / (2.0 * t)));
  BENCH_PRINT("Noise budget after decryption: " << budget
              << " (max noise: " << max_noise << ")");

  return result;
}


void PirClient::init_sk_small_q() {
  constexpr size_t N = DBConsts::PolyDegree;
  const uint64_t old_q = pir_params_.get_coeff_modulus()[0];
  const uint64_t small_q = pir_params_.get_small_q();

  // Convert rlwe_sk_ (NTT form under old_q) to coefficient form.
  std::vector<uint64_t> sk_coef(rlwe_sk_.data.begin(), rlwe_sk_.data.end());
  utils::ntt_inv(sk_coef.data(), N, old_q);

  // Rewrite -1 mod old_q as -1 mod small_q (sk is ternary: {0, 1, -1}).
  sk_ntt_small_q_.resize(N);
  for (size_t i = 0; i < N; i++) {
    sk_ntt_small_q_[i] = (sk_coef[i] > 1) ? (small_q - 1) : sk_coef[i];
  }
  utils::ntt_fwd(sk_ntt_small_q_.data(), N, small_q);
}
