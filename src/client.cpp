#include "client.h"
#include "pir.h"
#include "utils.h"
#include "gsw_eval.h"
#include "seal/util/iterator.h"
#include <cassert>


// constructor
PirClient::PirClient(const PirParams &pir_params)
    : client_id_(rand()), pir_params_(pir_params),
      context_(pir_params.get_seal_params()), keygen_(context_),
      secret_key_(keygen_.secret_key()), decryptor_(context_, secret_key_),
      encryptor_(context_, secret_key_), evaluator_(context_),
      context_mod_q_prime_(init_mod_q_prime()), dims_(pir_params.get_dims()) {}

std::vector<Ciphertext> PirClient::generate_gsw_from_key() {
  std::vector<seal::Ciphertext> gsw_enc; // temporary GSW ciphertext using seal::Ciphertext
  const auto sk_ = secret_key_.data();
  const auto ntt_tables = context_.first_context_data()->small_ntt_tables();
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const size_t coeff_count = DatabaseConstants::PolyDegree;
  std::vector<uint64_t> sk_ntt(sk_.data(), sk_.data() + coeff_count * rns_mod_cnt);

  RNSIter secret_key_iter(sk_ntt.data(), coeff_count);
  inverse_ntt_negacyclic_harvey(secret_key_iter, rns_mod_cnt, ntt_tables);

  GSWEval key_gsw(pir_params_, pir_params_.get_l_key(), pir_params_.get_base_log2_key());
  key_gsw.plain_to_half_gsw(sk_ntt, encryptor_, secret_key_, gsw_enc);
  return gsw_enc;
}


std::vector<size_t> PirClient::get_query_indices(size_t pt_idx) {
  std::vector<size_t> query_indices;
  const size_t col_idx = pt_idx % dims_[0];  // the first dimension
  size_t row_idx = pt_idx / dims_[0];  // the rest of the dimensions
  size_t remain_pt_num = pir_params_.get_num_pt() / dims_[0];

  query_indices.push_back(col_idx);
  for (size_t i = 1; i < dims_.size(); i++) {
    size_t dim_size = dims_[i];
    remain_pt_num /= dim_size;
    query_indices.push_back(row_idx / remain_pt_num);
    row_idx = row_idx % remain_pt_num;
  }

  return query_indices;
}



seal::Ciphertext PirClient::generate_query(const size_t pt_idx) {

  // ================== Setup parameters ==================
  // Get the corresponding index of the plaintext in the database
  std::vector<size_t> query_indices = get_query_indices(pt_idx);
  PRINT_INT_ARRAY("\t\tquery_indices", query_indices.data(), query_indices.size());
  const size_t bits_per_ciphertext = 1 << pir_params_.get_expan_height(); // padding msg_size to the next power of 2

  // Algorithm 1 from the OnionPIR Paper

  // empty plaintext
  seal::Plaintext plain_query(DatabaseConstants::PolyDegree); 
  // We set the corresponding coefficient to the inverse so the value of the
  // expanded ciphertext will be 1
  uint64_t inverse = 0;
  const uint64_t plain_modulus = pir_params_.get_plain_mod();
  seal::util::try_invert_uint_mod(bits_per_ciphertext, plain_modulus, inverse);

  // Add the first dimension query vector to the query
  plain_query[ query_indices[0] ] = inverse;
  
  // Encrypt plain_query first. Later we will insert the rest. $\tilde c$ in paper
  seal::Ciphertext query;
  encryptor_.encrypt_symmetric_seeded(plain_query, query);

  // no further dimensions
  if (query_indices.size() == 1) {
    DEBUG_PRINT("No further dimensions");
    return query;
  }

  // ================== Add GSW values to the query ==================
  const size_t l = pir_params_.get_l();
  const size_t base_log2 = pir_params_.get_base_log2();
  const auto coeff_modulus = pir_params_.get_coeff_modulus();
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();

  // The following two for-loops calculates the powers for GSW gadgets.
  std::vector<uint128_t> inv(rns_mod_cnt);
  for (size_t k = 0; k < rns_mod_cnt; k++) {
    uint64_t result;
    seal::util::try_invert_uint_mod(bits_per_ciphertext, coeff_modulus[k], result);
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
        for (size_t mod_id = 0; mod_id < rns_mod_cnt; mod_id++) {
          const size_t pad = mod_id * DatabaseConstants::PolyDegree;   // We use two moduli for the same gadget value. They are apart by coeff_count.
          const size_t coef_pos = dims_[0] + (i-1) * l + k + pad;  // the position of the coefficient in the query
          uint128_t mod = coeff_modulus[mod_id].value();
          // the coeff is (B^{l-1}, ..., B^0) / bits_per_ciphertext
          uint128_t coef = gadget[mod_id][k] * inv[mod_id] % mod;
          q_head[coef_pos] = (q_head[coef_pos] + coef) % mod;
        }
      }
    }
  }

  return query;
}


seal::Ciphertext PirClient::fast_generate_query(const size_t pt_idx) {
  // ================== Setup parameters ==================
  // Get the corresponding index of the plaintext in the database
  std::vector<size_t> query_indices = get_query_indices(pt_idx);
  PRINT_INT_ARRAY("\t\tquery_indices", query_indices.data(), query_indices.size());
  const size_t expan_height = pir_params_.get_expan_height();
  const size_t bits_per_ciphertext = 1 << expan_height; // padding msg_size to the next power of 2

  // Algorithm 1 from the OnionPIR Paper

  // empty plaintext
  seal::Plaintext plain_query(DatabaseConstants::PolyDegree); // we allow 4096 coefficients in the plaintext polynomial to be set as suggested in the paper.
  // We set the corresponding coefficient to the inverse so the value of the
  // expanded ciphertext will be 1
  uint64_t inverse = 0;
  const uint64_t plain_modulus = pir_params_.get_plain_mod();
  seal::util::try_invert_uint_mod(bits_per_ciphertext, plain_modulus, inverse);

  // Since we are using new expansion method, where index b is split to even
  // part and odd part, even part is stored in index 2b, and odd part is stored
  // in index 2b+1. This results in a bit-reversed order of the indices.
  const size_t reversed_index = utils::bit_reverse(query_indices[0], expan_height);
  plain_query[ reversed_index ] = inverse; // Add the first dimension query vector to the query
  DEBUG_PRINT("reversed_index: " << reversed_index << ", query_indices[0]: " << query_indices[0]);

  // Encrypt plain_query first. Later we will insert the rest. $\tilde c$ in paper
  seal::Ciphertext query;
  encryptor_.encrypt_symmetric_seeded(plain_query, query);

  // add gsw values to the query bfv 
  add_gsw_to_query(query, query_indices);

  return query;
}


void PirClient::generate_expanded_query(const size_t pt_idx, std::vector<seal::Ciphertext> &bfv_vec, std::vector<GSWCiphertext> &gsw_vec) {
  // compute the query indices
  std::vector<size_t> query_indices = get_query_indices(pt_idx);
  PRINT_INT_ARRAY("\t\tquery_indices", query_indices.data(), query_indices.size());
  assert(bfv_vec.size() == 0);
  assert(gsw_vec.size() == 0);

  // encrypt the first dimension
  for (size_t i = 0; i < dims_[0]; i++)  {
    seal::Ciphertext temp_bfv;
    seal::Plaintext plain_query(DatabaseConstants::PolyDegree);
    plain_query[0] = (i == query_indices[0]) ? 1 : 0;
    encryptor_.encrypt_symmetric(plain_query, temp_bfv);
    bfv_vec.push_back(temp_bfv); // store the first dimension in the bfv vector
  }

  // handle the rest dimensions
  GSWEval data_gsw(pir_params_, pir_params_.get_l(), pir_params_.get_base_log2());
  for (size_t i = 1; i < dims_.size(); i++) {
    std::vector<uint64_t> plain_query(DatabaseConstants::PolyDegree);
    plain_query[0] = (query_indices[i] == 1) ? 1 : 0;
    // transform plain_query to NTT form
    GSWCiphertext query_gsw = data_gsw.plain_to_gsw(plain_query, encryptor_, secret_key_); // In OnionPIR, client use a similar function to encrypt the secret key. 
    gsw_vec.push_back(query_gsw);
  }
}


void PirClient::add_gsw_to_query(seal::Ciphertext &query, const std::vector<size_t> query_indices) {
  // no further dimensions
  if (query_indices.size() == 1) { return; }
  const size_t expan_height = pir_params_.get_expan_height();
  const size_t bits_per_ciphertext = 1 << expan_height; // padding msg_size to the next power of 2
  const size_t l = pir_params_.get_l();
  const size_t base_log2 = pir_params_.get_base_log2();
  const auto coeff_modulus = pir_params_.get_coeff_modulus();
  const size_t rns_mod_cnt = pir_params_.get_rns_mod_cnt();
  const size_t fst_dim_sz = dims_[0];

  // The following two for-loops calculates the powers for GSW gadgets.
  std::vector<uint128_t> inv(rns_mod_cnt);
  for (size_t k = 0; k < rns_mod_cnt; k++) {
    uint64_t result;
    seal::util::try_invert_uint_mod(bits_per_ciphertext, coeff_modulus[k], result);
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
          const size_t pad = mod_id * DatabaseConstants::PolyDegree;   // We use two moduli for the same gadget value. They are apart by coeff_count.
          uint128_t mod = coeff_modulus[mod_id].value();
          // the coeff is (B^{l-1}, ..., B^0) / bits_per_ciphertext
          uint128_t coef = gadget[mod_id][k] * inv[mod_id] % mod;
          q_head[reversed_idx + pad] = (q_head[reversed_idx + pad] + coef) % mod;
        }
      }
    }
  }
}


size_t PirClient::write_query_to_stream(const seal::Ciphertext &query, std::stringstream &data_stream) {
  return query.save(data_stream);
}

size_t PirClient::write_gsw_to_stream(const std::vector<Ciphertext> &gsw, std::stringstream &gsw_stream) {
  size_t total_size = 0;
  for (auto &ct : gsw) {
    size_t size = ct.save(gsw_stream);
    total_size += size;
  }
  return total_size;
}

size_t PirClient::create_galois_keys(std::stringstream &galois_key_stream) {
  std::vector<uint32_t> galois_elts;

  // This is related to the unpacking algorithm.
  // expansion height is the height of the expansion tree such that
  // 2^get_expan_height() is equal to the number of packed values padded to the next power of 2.
  const size_t expan_height = pir_params_.get_expan_height();
  for (size_t i = 0; i < expan_height; i++) {
    galois_elts.push_back(1 + (DatabaseConstants::PolyDegree >> i));
  }
  // PRINT_INT_ARRAY("galois_elts: ", galois_elts, galois_elts.size());
  auto written_size = keygen_.create_galois_keys(galois_elts).save(galois_key_stream);
  return written_size;
}

seal::Plaintext PirClient::decrypt_reply(const seal::Ciphertext& reply) {
  // most likely we are going to use our own decryption since we perform single mod mod-switch
  return decrypt_mod_q(reply);
}

seal::Plaintext PirClient::decrypt_ct(const seal::Ciphertext& ct) {
  // otherwise, use the default decryptor of SEAL as follows:
  seal::Plaintext result;
  decryptor_.decrypt(ct, result);
  return result;
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
//   const size_t coeff_count = DatabaseConstants::PolyDegree;
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



seal::Ciphertext PirClient::load_resp_from_stream(std::stringstream &resp_stream) {
  // For now, we only serve the single modulus case.

  // ------------ parameter setup -------------------------------------------
  const size_t small_q = pir_params_.get_small_q();
  const size_t small_q_width =
      static_cast<size_t>(std::ceil(std::log2(small_q)));
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;

  std::vector<uint64_t> c0(coeff_count);
  std::vector<uint64_t> c1(coeff_count);

  // ------------ helper: read one bit (LSB-first in every byte) ------------
  uint8_t current_byte = 0;
  size_t bits_left = 0; // how many unread bits remain in current_byte
  auto next_bit = [&]() -> uint8_t {
    if (bits_left == 0) { // fetch the next byte
      int ch = resp_stream.get();
      if (ch == EOF)
        throw std::runtime_error("unexpected end of response stream");
      current_byte = static_cast<uint8_t>(ch);
      bits_left = 8;
    }
    uint8_t bit = current_byte & 1; // least-significant bit is next in order
    current_byte >>= 1;
    --bits_left;
    return bit;
  };

  // ------------ helper: read one coefficient ------------------------------
  auto read_coeff = [&](uint64_t &dest) {
    dest = 0;
    for (size_t j = 0; j < small_q_width; ++j)
      dest |= static_cast<uint64_t>(next_bit()) << j; // LSB-first
  };

  // ------------ fill both polynomials --------------------------------------
  for (size_t i = 0; i < coeff_count; ++i)
    read_coeff(c0[i]);
  for (size_t i = 0; i < coeff_count; ++i)
    read_coeff(c1[i]);

  // ------------ reconstruct ciphertext -------------------------------------
  seal::Ciphertext result(context_);
  result.resize(context_, 2);
  std::copy(c0.begin(), c0.end(), result.data(0));
  std::copy(c1.begin(), c1.end(), result.data(1));
  return result;
}


seal::Plaintext PirClient::decrypt_mod_q(const seal::Ciphertext &ct, const uint64_t small_q) const {
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
  const auto seal_params = pir_params_.get_seal_params();
  const auto full_mods = seal_params.coeff_modulus();
  
  // display the moduli. Notice that there is one extra modulus used by seal. 
  for (size_t i = 0; i < full_mods.size(); i++) {
    DEBUG_PRINT("full_mods[" << i << "] = " << full_mods[i].value());
  }
  DEBUG_PRINT("ct mod: " << pir_params_.get_coeff_modulus()[0].value());
  DEBUG_PRINT("small q = " << small_q);

  // create a new secret key with new modulus
  seal::EncryptionParameters new_params(seal::scheme_type::bfv);
  new_params.set_poly_modulus_degree(DatabaseConstants::PolyDegree);
  new_params.set_plain_modulus(pir_params_.get_plain_mod());
  new_params.set_coeff_modulus({small_q, full_mods.back()}); // use the same last modulus as the original one.

  seal::SecretKey new_sk = sk_mod_switch(secret_key_, new_params);
  seal::SEALContext new_context(new_params);
  seal::Decryptor new_decryptor(new_context, new_sk);
  seal::Encryptor new_encryptor(new_context, new_sk);

  // create a dummy ciphertext
  seal::Ciphertext dummy_ct(new_context);
  dummy_ct.resize(new_context, 2);

  // create a new ciphertext under new context, then copy the data from the input ct, then decrypt using the new sk.
  for (size_t i = 0; i < coeff_count; i++) {
    // copy the data from the input ct to the new ct
    dummy_ct.data(0)[i] = ct.data(0)[i];
    dummy_ct.data(1)[i] = ct.data(1)[i];
  }

  // decrypt the new ciphertext using the new sk
  seal::Plaintext result;
  new_decryptor.decrypt(dummy_ct, result);
  
  return result;
}



seal::Plaintext PirClient::decrypt_mod_q(const seal::Ciphertext &ct) const {
  // create a dummy ciphertext
  seal::Ciphertext dummy_ct(context_mod_q_prime_);
  dummy_ct.resize(context_mod_q_prime_, 2);

  // create a new ciphertext under new context, then copy the data from the input ct, then decrypt using the new sk.
  for (size_t i = 0; i < DatabaseConstants::PolyDegree; i++) {
    // copy the data from the input ct to the new ct
    dummy_ct.data(0)[i] = ct.data(0)[i];
    dummy_ct.data(1)[i] = ct.data(1)[i];
  }

  // decrypt the new ciphertext using the new sk
  seal::Plaintext result;
  decryptor_mod_q_prime_->decrypt(dummy_ct, result);

  // print the noise budget
  double noise_budget = decryptor_mod_q_prime_->invariant_noise_budget(dummy_ct);
  BENCH_PRINT("Noise budget after decryption: " << noise_budget);

  return result;
}


seal::SecretKey PirClient::sk_mod_switch(const seal::SecretKey &sk, const seal::EncryptionParameters &new_params) const {
  constexpr size_t coeff_count = DatabaseConstants::PolyDegree;
  const seal::SEALContext old_context = pir_params_.get_context();
    const seal::SEALContext new_context(new_params);
  const auto old_context_data = old_context.key_context_data();
  const auto new_context_data = new_context.key_context_data();
  const auto old_ntt_tables = old_context_data->small_ntt_tables(); 
  const auto new_ntt_tables = new_context_data->small_ntt_tables();

  auto temp_keygen = seal::KeyGenerator(new_context);
  auto new_sk = temp_keygen.secret_key(); // create non-empty secret key. will use old sk data.

  std::vector<uint64_t> sk_data(sk.data().data(), sk.data().data() + coeff_count);
  RNSIter intt_iter(sk_data.data(), coeff_count);
  inverse_ntt_negacyclic_harvey(intt_iter, 1, old_ntt_tables);
  const uint64_t new_q = new_params.coeff_modulus()[0].value();
  for (size_t i = 0; i < coeff_count; ++i) {
    // sk in coefficient form only contains 0, 1, q-1, where q-1 \equiv -1 mod q
    if (sk_data[i] > 1) {
      sk_data[i] = new_q - 1; // change it to -1 mod small_q
    }
  }
  // compute NTT forward for sk1 using new_ntt_tables
  RNSIter ntt_iter(sk_data.data(), coeff_count);
  ntt_negacyclic_harvey(ntt_iter, 1, new_ntt_tables);

  // replace the underlying data of new_sk with the data of sk
  std::copy(sk_data.begin(), sk_data.end(), new_sk.data().data());

  return new_sk;
}

seal::SEALContext PirClient::init_mod_q_prime() {
  const auto seal_params = pir_params_.get_seal_params();
  const auto full_mods = seal_params.coeff_modulus();
  const size_t small_q = pir_params_.get_small_q();

  // display the moduli. Notice that there is one extra modulus used by seal. 
  for (size_t i = 0; i < full_mods.size(); i++) {
    DEBUG_PRINT("full_mods[" << i << "] = " << full_mods[i].value());
  }
  DEBUG_PRINT("ct mod: " << pir_params_.get_coeff_modulus()[0].value());
  DEBUG_PRINT("small q = " << small_q);

  // create a new secret key with new modulus
  seal::EncryptionParameters new_params(seal::scheme_type::bfv);
  new_params.set_poly_modulus_degree(DatabaseConstants::PolyDegree);
  new_params.set_plain_modulus(pir_params_.get_plain_mod());
  new_params.set_coeff_modulus({small_q, full_mods.back()}); // use the same last modulus as the original one.

  seal::SEALContext context_mod_q_prime_ = seal::SEALContext(new_params);
  auto secret_key_mod_q_prime_ = sk_mod_switch(secret_key_, new_params);
  // create a new decryptor and encryptor with the new secret key
  decryptor_mod_q_prime_ = std::make_unique<seal::Decryptor>(context_mod_q_prime_, secret_key_mod_q_prime_);
  return context_mod_q_prime_;
}
