#pragma once

#include "pir.h"
#include "gsw.h"
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
  */
  RlweCt fast_generate_query(const size_t pt_idx);

  // helper function for fast_generate_query
  void add_gsw_to_query(RlweCt &query, const std::vector<size_t> query_indices);

  // Create custom BV-style Galois keys (no special prime).
  bvks::BvGaloisKeys create_bv_galois_keys();
  // decrypt the result returned from PIR. Assume modulus switching is applied.
  seal::Plaintext decrypt_reply(const RlweCt& reply);
  seal::Plaintext decrypt_ct(const RlweCt &ct);
  // Produce the per-client GSW key (encryption of -s under the data modulus) in
  // its final flat NTT layout, ready to hand to PirServer::set_client_gsw_key.
  GSWCt generate_gsw_from_key();

  inline size_t get_client_id() const { return client_id_; }

  // Noise budget via a bridge to SEAL's invariant_noise_budget (debug/test only).
  int noise_budget(const RlweCt &ct);

  // load the response from the stream and recover the ciphertext
  RlweCt load_resp_from_stream(std::stringstream &resp_stream);

  // Decrypt a single-mod RlweCt under small_q using our custom decryptor.
  seal::Plaintext decrypt_mod_q(const RlweCt &ciphertext) const;


  friend class PirTest;

private:
  const size_t client_id_;
  PirParams pir_params_;
  std::mt19937_64 rng_;       // per-client PRNG for noise sampling
  RlweSk rlwe_sk_;            // ternary sk, NTT form under q
  std::vector<uint64_t> sk_ntt_small_q_; // secret key in NTT form under small_q
  seal::SEALContext context_mod_q_prime_;


  // Gets the query indices for a given plaintext
  std::vector<size_t> get_query_indices(size_t pt_idx);

  // switching the secret key mod old_q to mod new_q
  // This matters since sk is a tenary polynomial, which contains -1 mod q.
  seal::SecretKey sk_mod_switch(const seal::SecretKey &sk, const seal::EncryptionParameters &new_params) const;

  seal::SEALContext init_mod_q_prime();

};









