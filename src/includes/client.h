#pragma once

#include "pir.h"
class PirClient {
public:
  PirClient(const PirParams &pirparms);
  ~PirClient() = default;

  /**
  This is the core function for the client.
  High level steps:
  1. Compute the query indices.
  2. Creates a plain_query (pt in paper), add the first dimension, then encrypts it.
  3. For the rest dimensions, calculate required RGSW coefficients and insert
  them into the ciphertext. Result is $\tilde c$ in paper.
  @param entry_index The input to the PIR blackbox.
  @return returns a seal::Ciphertext with a a seed stored in
  c_1, which should not be touched before doing serialization.
  */
  seal::Ciphertext generate_query(const size_t entry_index);

  // similar to generate_query, but preparing query for fast_expand_qry.
  seal::Ciphertext fast_generate_query(const size_t entry_index);
  // helper function for fast_generate_query
  void add_gsw_to_query(seal::Ciphertext &query, const std::vector<size_t> query_indices);

  static size_t write_query_to_stream(const seal::Ciphertext &query, std::stringstream &data_stream);
  static size_t write_gsw_to_stream(const std::vector<Ciphertext> &gsw, std::stringstream &gsw_stream);
  size_t create_galois_keys(std::stringstream &galois_key_stream);
  seal::Plaintext decrypt_result(const seal::Ciphertext& reply);
  // Retrieves an entry from the plaintext containing the entry.
  std::vector<Ciphertext> generate_gsw_from_key();
  
  Entry get_entry_from_plaintext(const size_t entry_index, const seal::Plaintext plaintext) const;
  inline size_t get_client_id() const { return client_id_; }

  inline void test_budget(seal::Ciphertext &ct) {
    // calculate the noise budget of the ciphertext
    BENCH_PRINT("Noise budget in the query: " << decryptor_.invariant_noise_budget(ct) << " bits");
  }

  // load the response from the stream and recover the ciphertext
  seal::Ciphertext load_resp_from_stream(std::stringstream &resp_stream);

  // given a ciphertext, decrypt it using the small_q_ stored in PirParams, the
  // stored secret key, and the stored plaintext modulus.
  seal::Plaintext decrypt_mod_q(const seal::Ciphertext &ciphertext, const uint64_t small_q) const; 

  // // old definition.
  // seal::Plaintext custom_decrypt_mod_q(const seal::Ciphertext &ciphertext, const std::vector<seal::Modulus>& modulus); 


  friend class PirTest;

private:
  size_t client_id_;
  seal::SEALContext context_;
  seal::KeyGenerator keygen_;
  seal::SecretKey secret_key_;
  seal::Decryptor decryptor_;
  seal::Encryptor encryptor_;
  seal::Evaluator evaluator_;
  PirParams pir_params_;
  std::vector<size_t> dims_;
  
  // Gets the corresponding plaintext index in a database for a given entry index
  size_t get_database_plain_index(size_t entry_index);

  // Gets the query indices for a given plaintext
  std::vector<size_t> get_query_indices(size_t plaintext_index);

  // switching the secret key mod old_q to mod new_q
  // This matters since sk is a tenary polynomial, which contains -1 mod q.
  seal::SecretKey secret_key_mod_switch(const seal::SecretKey &sk, const seal::EncryptionParameters &new_params) const;



};









