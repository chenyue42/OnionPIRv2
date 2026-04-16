#pragma once

#include "pir.h"
#include "gsw_eval.h"
#include "bv_keyswitch.h"
#include "rlwe.h"
#include <random>

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


  /**
  Generate multiple queries for double-stateless version.
  In this setting, we send multiple queries to reduce the height of the expansion tree. 
  This way we save more on the KSK size.
  Here is how this function work: 
  We can send multiple queries. For now, we let each query to expand to the TREE_HEIGHT. That means we can will get 
  num_queries * (1<<TREE_HEIGHT) plaintext slots in total.
  
  */
  seal::Ciphertext gen_mult_queries(const size_t pt_idx, const size_t num_queries);

  // helper function for fast_generate_query
  void add_gsw_to_query(seal::Ciphertext &query, const std::vector<size_t> query_indices);

  static size_t write_query_to_stream(const seal::Ciphertext &query, std::stringstream &data_stream);
  size_t create_galois_keys(std::stringstream &galois_key_stream);
  // Create custom BV-style Galois keys (no special prime).
  bvks::BvGaloisKeys create_bv_galois_keys();
  // decrypt the result returned from PIR. Assume modulus switching is applied.
  seal::Plaintext decrypt_reply(const seal::Ciphertext& reply);
  seal::Plaintext decrypt_ct(const seal::Ciphertext& ct);
  // Produce the per-client GSW key (encryption of -s under the data modulus) in
  // its final flat NTT layout, ready to hand to PirServer::set_client_gsw_key.
  GSWCiphertext generate_gsw_from_key();
  
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
  RlweSk rlwe_sk_;            // ternary sk, NTT form under q (mirrors secret_key_)
  std::mt19937_64 rng_;       // per-client PRNG for noise sampling
  std::vector<uint64_t> sk_ntt_small_q_; // secret key in NTT form under small_q
  seal::SEALContext context_mod_q_prime_;
  

  // Gets the query indices for a given plaintext
  std::vector<size_t> get_query_indices(size_t pt_idx);

  // switching the secret key mod old_q to mod new_q
  // This matters since sk is a tenary polynomial, which contains -1 mod q.
  seal::SecretKey sk_mod_switch(const seal::SecretKey &sk, const seal::EncryptionParameters &new_params) const;
  
  seal::SEALContext init_mod_q_prime();

};









