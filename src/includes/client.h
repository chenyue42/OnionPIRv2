#pragma once

#include "pir.h"
#include "gsw_eval.h"
#include "bv_keyswitch.h"

class PirClient {
public:
  PirClient(const PirParams &pirparms);
  ~PirClient() = default;

  /**
  Generate a packed query ciphertext for fast_expand_qry.
  @param pt_idx The input to the PIR blackbox.
  @return returns a seal::Ciphertext with a seed stored in c_1
  (must be serialized before any further operations).
  */
  seal::Ciphertext fast_generate_query(const size_t pt_idx);


  // helper function for fast_generate_query
  void add_gsw_to_query(seal::Ciphertext &query, const std::vector<size_t> query_indices);

  static size_t write_query_to_stream(const seal::Ciphertext &query, std::stringstream &data_stream);
  static size_t write_gsw_to_stream(const std::vector<Ciphertext> &gsw, std::stringstream &gsw_stream);
  size_t create_galois_keys(std::stringstream &galois_key_stream);
  // Create custom BV-style Galois keys (no special prime).
  bvks::BvGaloisKeys create_bv_galois_keys();
  // decrypt the result returned from PIR. Assume modulus switching is applied.
  seal::Plaintext decrypt_reply(const seal::Ciphertext& reply);
  seal::Plaintext decrypt_ct(const seal::Ciphertext& ct);
  // Retrieves a plaintext from the plaintext containing the plaintext.
  std::vector<Ciphertext> generate_gsw_from_key();
  
  inline size_t get_client_id() const { return client_id_; }

  inline int noise_budget(seal::Ciphertext &ct) {
    // return the noise budget of the ciphertext
    return decryptor_.invariant_noise_budget(ct);
  }

  // load the response from the stream and recover the ciphertext
  seal::Ciphertext load_resp_from_stream(std::stringstream &resp_stream);

  // given a ciphertext, decrypt it using the given small_q_, the
  // stored secret key, and the stored plaintext modulus.
  seal::Plaintext decrypt_mod_q(const seal::Ciphertext &ciphertext, const uint64_t small_q) const; 

  // given a ciphertext, decrypt it using the decryptor associated with small_q_ stored in PirParams
  seal::Plaintext decrypt_mod_q(const seal::Ciphertext &ciphertext) const; 


  friend class PirTest;

private:
  const size_t client_id_;
  PirParams pir_params_;
  seal::SEALContext context_;
  seal::KeyGenerator keygen_;
  seal::SecretKey secret_key_;
  seal::Decryptor decryptor_;
  seal::Encryptor encryptor_;
  seal::Evaluator evaluator_;
  std::unique_ptr<seal::Decryptor> decryptor_mod_q_prime_;
  seal::SEALContext context_mod_q_prime_;
  

  // Gets the query indices for a given plaintext
  std::vector<size_t> get_query_indices(size_t pt_idx);

  // switching the secret key mod old_q to mod new_q
  // This matters since sk is a tenary polynomial, which contains -1 mod q.
  seal::SecretKey sk_mod_switch(const seal::SecretKey &sk, const seal::EncryptionParameters &new_params) const;
  
  seal::SEALContext init_mod_q_prime();

};









