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

  // Generate fresh RGSW(bit) selectors for the first-dimension index of pt_idx,
  // MSB-first, for use with PirServer::dmux_expand_qry. Each selector encrypts a
  // single bit of (pt_idx % fst_dim_sz) under a gadget of length `gsw_l`
  // (base_log2 = ceil(ct_mod_width / gsw_l)). The server must expand with the
  // same gsw_l so its decomposition matches. `skip_levels` drops that many
  // leading (MSB) selectors — use it when the top bits are instead resolved by a
  // real BFV query from generate_dmux_query(pt_idx, skip_levels).
  std::vector<GSWCt> generate_dmux_selectors(const size_t pt_idx,
                                             const size_t gsw_l,
                                             const size_t skip_levels = 0);

  // Build the real BFV one-hot the DMux tree starts from when the top
  // `num_levels` first-dim bits are resolved client-side: a length-2^num_levels
  // vector where the slot at the top num_levels bits of (pt_idx % fst_dim_sz) is
  // BFV(1) and the rest are BFV(0). Real (noisy) encryptions, so the zero and
  // one ciphertexts are indistinguishable. Pairs with
  // generate_dmux_selectors(pt_idx, gsw_l, num_levels) for the remaining levels.
  std::vector<RlweCt> generate_dmux_query(const size_t pt_idx,
                                          const size_t num_levels);

  // Generate fresh RGSW(bit) selectors for the subsequent (non-first)
  // dimensions of pt_idx, under the data-gsw gadget (l_ep). In DoubleStateless
  // mode these replace the server-side query_to_gsw conversion: the server
  // feeds them straight into evaluate_other_dim. Bits and order match
  // get_query_indices()[1..].
  std::vector<GSWCt> generate_other_dim_selectors(const size_t pt_idx);

  // Create custom BV-style Galois keys (no special prime).
  inline bvks::BvGaloisKeys create_bv_galois_keys() {
    return bvks::gen_bv_galois_keys(pir_params_, rlwe_sk_);
  }

  RlwePt decrypt_ct(const RlweCt &ct);
  // Produce the per-client GSW key (encryption of s under the data modulus) in
  // its final flat NTT layout, ready to hand to PirServer::set_client_gsw_key.
  GSWCt generate_gsw_from_key();

  inline size_t get_client_id() const { return client_id_; }

  // Noise budget via a bridge to SEAL's invariant_noise_budget (debug/test only).
  int noise_budget(const RlweCt &ct);


  // Fresh encryption of zero under the data modulus Q. Testing only:
  // used to measure the baseline initial noise budget without the
  // gadget-injection artifacts of fast_generate_query.
  RlweCt fresh_zero_ct();

  // Fresh real BFV encryption of the constant `scalar` (placed at coefficient 0)
  // under the data modulus Q, in coefficient form. Unlike a trivial encoding,
  // this is a proper noisy encryption, so BFV(0) and BFV(1) are
  // indistinguishable — used to build a real DMux query that resolves the top
  // tree levels with cheap BFV ciphertexts instead of RGSW selectors.
  RlweCt fresh_bfv_ct(uint64_t scalar);

  // load the response from the stream and recover the ciphertext
  RlweCt load_resp_from_stream(std::stringstream &resp_stream);

  // Decrypt a single-mod RlweCt under small_q using our custom decryptor.
  RlwePt decrypt_mod_q(const RlweCt &ciphertext) const;


  friend class PirTest;

private:
  const size_t client_id_;
  PirParams pir_params_;
  std::mt19937_64 rng_;       // per-client PRNG for noise sampling
  RlweSk rlwe_sk_;            // ternary sk, NTT form under q

  // Gets the query indices for a given plaintext
  std::vector<size_t> get_query_indices(size_t pt_idx);

  // First-dimension index of pt_idx, as MSB-first bits (one per DMux tree level,
  // h = log2(fst_dim_sz) of them). The sibling of get_query_indices for the
  // DMux path; matches the root-to-leaf walk in PirServer::dmux_expand_qry.
  std::vector<size_t> generate_dmux_indices(size_t pt_idx) const;

  // Encrypt each bit (0/1) in `bits` as a fresh RGSW(bit) under gadget `gsw`,
  // returning one GSWCt per bit, in order. Shared by the two selector builders.
  std::vector<GSWCt> encrypt_selector_bits(const std::vector<size_t> &bits,
                                           GSWEval &gsw);

  // Populate sk_ntt_small_q_ by rewriting rlwe_sk_ from old_q to small_q
  // (ternary sk has -1 ≡ q-1; we need -1 ≡ small_q-1).
  std::vector<uint64_t> get_sk_ntt_small_q(uint64_t old_q, uint64_t small_q) const;

};








