#include "client.h"
#include "seal/util/defines.h"
#include <bitset>

PirClient::PirClient(const PirParams &pir_params)
    : params_(pir_params.get_seal_params()), DBSize_(pir_params.get_DBSize()),
      dims_(pir_params.get_dims()), pir_params_(pir_params) {
  context_ = new seal::SEALContext(params_);
  evaluator_ = new seal::Evaluator(*context_);
  keygen_ = new seal::KeyGenerator(*context_);
  secret_key_ = &keygen_->secret_key();
  encryptor_ = new seal::Encryptor(*context_, *secret_key_);
  decryptor_ = new seal::Decryptor(*context_, *secret_key_);
}

PirClient::~PirClient() {
  delete context_;
  delete evaluator_;
  delete keygen_;
  delete encryptor_;
  delete decryptor_;
}

seal::Decryptor *PirClient::get_decryptor() { return decryptor_; }

GSWCiphertext PirClient::generate_gsw_from_key() {
  GSWCiphertext gsw_enc;
  auto sk_ = secret_key_->data();
  auto ntt_tables = context_->first_context_data()->small_ntt_tables();
  auto coeff_modulus = context_->first_context_data()->parms().coeff_modulus();
  auto coeff_mod_count = coeff_modulus.size();

  std::vector<uint64_t> sk_ntt(params_.poly_modulus_degree() * coeff_mod_count);

  memcpy(sk_ntt.data(), sk_.data(),
         params_.poly_modulus_degree() * coeff_mod_count * sizeof(uint64_t));

  RNSIter secret_key_iter(sk_ntt.data(), params_.poly_modulus_degree());
  inverse_ntt_negacyclic_harvey(secret_key_iter, coeff_mod_count, ntt_tables);

  auto l = pir_params_.get_l();
  auto base_log2 = pir_params_.get_base_log2();
  auto coeff_count = params_.poly_modulus_degree();

  for (int poly_id = 1; poly_id >= 0; poly_id--) {
    for (int i = l - 1; i >= 0; i--) {
      seal::Ciphertext cipher;
      encryptor_->encrypt_zero_symmetric(cipher);
      auto bits = (i * base_log2);
      auto ct_ptr = cipher.data(poly_id);
      for (int mod_id = 0; mod_id < coeff_mod_count; mod_id++) {
        auto mod_idx = (mod_id * coeff_count);
        __uint128_t mod = coeff_modulus[mod_id].value();
        auto coef = (mod - (1ll << bits % mod)) % mod;
        for (int coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
          ct_ptr[coeff_id + mod_idx] = static_cast<uint64_t>(
              (ct_ptr[coeff_id + mod_idx] + mod -
               ((__uint128_t)sk_ntt[coeff_id + mod_idx] * coef % mod)) %
              mod);
        }
      }
      std::vector<uint64_t> row;
      for (int i = 0; i < coeff_count * coeff_mod_count; i++) {
        row.push_back(cipher.data(0)[i]);
      }
      for (int i = 0; i < coeff_count * coeff_mod_count; i++) {
        row.push_back(cipher.data(1)[i]);
      }
      gsw_enc.push_back(row);
    }
  }

  return gsw_enc;
}

PirQuery PirClient::generate_query(std::uint64_t entry_index) {

  // Get the corresponding index of the plaintext in the database
  size_t plaintext_index = get_database_plain_index(entry_index);
  std::vector<size_t> query_indexes = get_query_indexes(plaintext_index);
  uint64_t poly_degree = params_.poly_modulus_degree();

  // The number of bits is equal to the size of the first dimension

  uint64_t msg_size = dims_[0] + pir_params_.get_l() * (dims_.size() - 1) * 2;
  uint64_t bits_per_ciphertext = 1;

  while (bits_per_ciphertext < msg_size)
    bits_per_ciphertext *= 2;

  uint64_t size_of_other_dims = DBSize_ / dims_[0];
  std::vector<seal::Plaintext> plain_query;
  plain_query.push_back(seal::Plaintext(poly_degree));

  // Algorithm 1 from the OnionPIR Paper
  // We set the corresponding coefficient to the inverse so the value of the
  // expanded ciphertext will be 1
  uint64_t inverse = 0, plain_modulus = params_.plain_modulus().value();
  seal::util::try_invert_uint_mod(bits_per_ciphertext, plain_modulus, inverse);

  int ptr = 0;
  plain_query[0][ptr + query_indexes[0]] = inverse;
  ptr += dims_[0];

  auto l = pir_params_.get_l();
  auto base_log2 = pir_params_.get_base_log2();

  for (int i = 1; i < query_indexes.size(); i++) {
    for (int j = 0; j < l; j++) {
      plain_query[0][ptr + query_indexes[i] * l + j] =
          inverse *
          (((uint128_t)1) << ((l - 1 - j) * base_log2) % plain_modulus) %
          plain_modulus;
    }
    ptr += dims_[i] * l;
  }

  PirQuery query;
  for (int i = 0; i < plain_query.size(); i++) {
    seal::Ciphertext x_encrypted;
    encryptor_->encrypt_symmetric(plain_query[i], x_encrypted);
    query.push_back(x_encrypted);
  }

  return query;
}

seal::GaloisKeys PirClient::create_galois_keys() {
  std::vector<uint32_t> galois_elts = {1};

  // Compression factor determines how many bits there are per message (and
  // hence the total query size), with bits per message = 2^compression_factor.
  // For example, with compression factor = 11 and bit length = 4096, we end up
  // with 2048 bits per message and a total query size of 2. The 2048 bits will
  // be encoded in the first 2048 coeffs of the polynomial. 2^compression_factor
  // must be less than or equal to polynomial modulus degree and bit_length.
  int compression_factor = std::log2(dims_[0]);

  size_t min_ele =
      params_.poly_modulus_degree() / pow(2, compression_factor) + 1;
  for (size_t i = min_ele; i <= params_.poly_modulus_degree() + 1;
       i = (i - 1) * 2 + 1) {
    galois_elts.push_back(i);
  }
  seal::GaloisKeys galois_keys;
  keygen_->create_galois_keys(galois_elts, galois_keys);
  return galois_keys;
}

std::vector<seal::Plaintext>
PirClient::decrypt_result(std::vector<seal::Ciphertext> reply) {
  std::vector<seal::Plaintext> result(
      reply.size(), seal::Plaintext(params_.poly_modulus_degree()));
  for (size_t i = 0; i < reply.size(); i++) {
    decryptor_->decrypt(reply[i], result[i]);
  }

  return result;
}

size_t PirClient::get_database_plain_index(size_t entry_index) {
  return entry_index / pir_params_.get_num_entries_per_plaintext();
}

std::vector<size_t> PirClient::get_query_indexes(size_t plaintext_index) {
  std::vector<size_t> query_indexes;
  size_t index = plaintext_index;
  size_t size_of_remaining_dims = DBSize_;

  for (auto dim_size : dims_) {
    size_of_remaining_dims /= dim_size;
    query_indexes.push_back(index / size_of_remaining_dims);
    index = index % size_of_remaining_dims;
  }

  return query_indexes;
}

Entry PirClient::get_entry_from_plaintext(size_t entry_index,
                                          seal::Plaintext plaintext) {
  // Offset in the plaintext in bits
  size_t start_position_in_plaintext =
      (entry_index % pir_params_.get_num_entries_per_plaintext()) *
      pir_params_.get_entry_size() * 8;

  // Offset in the plaintext by coefficient
  size_t num_bits_per_coeff = pir_params_.get_num_bits_per_coeff();
  size_t coeff_index = start_position_in_plaintext / num_bits_per_coeff;

  // Offset in the coefficient by bits
  size_t coeff_offset = start_position_in_plaintext % num_bits_per_coeff;

  // Size of entry in bits
  size_t entry_size = pir_params_.get_entry_size() * 8;
  Entry result;
  // Entry value is a buffer to handle cases where the number of bits stored by
  // the coefficients is not divisible by 8.
  uint8_t entry_value = 0;
  for (int i = 0; i < entry_size;) {
    while (coeff_offset < num_bits_per_coeff) {
      if (entry_value != 0) {
        // Num empty btis in entry_value
        uint8_t bits_needed = i % 8;
        uint8_t bitmask = (1 << (bits_needed + 1)) - 1;
        entry_value += (plaintext[coeff_index] & bitmask) << (8 - bits_needed);
        result.push_back(entry_value);
        entry_value = 0;
        i += bits_needed;
        coeff_offset += bits_needed;
      } else if (num_bits_per_coeff - coeff_offset >= 8) {
        result.push_back((plaintext[coeff_index] >> coeff_offset) & 255);
        i += 8;
        coeff_offset += 8;
      } else {
        entry_value += (plaintext[coeff_index] >> coeff_offset);
        i += (num_bits_per_coeff - coeff_offset);
        coeff_offset = num_bits_per_coeff;
      }
    }
    coeff_offset = 0;
    ++coeff_index;
  }
  return result;
}
