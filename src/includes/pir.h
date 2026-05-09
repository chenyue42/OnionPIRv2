#pragma once

#include "logging.h"
#include "database_constants.h"
#include <cstdint>
#include <vector>

// Precomputed constants used by the K=2 CRT compose/decompose helpers.
struct RnsTables {
  uint64_t q0_inv_mod_q1 = 0;
  std::vector<uint64_t> r64_mod_q;
};

// Constants for the composite-mod first-dim split. Only populated when the
// active config splits the (single, logical) ciphertext modulus q into two
// CRT limbs (q = q1*q2) for the first-dimension matmul. enabled = false
// otherwise; rest of the pipeline still sees a single-mod K=1 view.
struct CompositeRnsTables {
  bool enabled = false;
  uint64_t q1 = 0;              // first RNS limb (~29 bits)
  uint64_t q2 = 0;              // second RNS limb (~29 bits)
  uint64_t w1 = 0;              // primitive 2N-th root mod q1
  uint64_t w2 = 0;              // primitive 2N-th root mod q2
  uint64_t w_crt = 0;           // CRT-combined primitive 2N-th root mod q1*q2
  uint64_t q1_inv_mod_q2 = 0;   // for CRT-compose hot path
};

// ================== CLASS DEFINITIONS ==================
class PirParams {
public:
  PirParams();
  PirParams(const PirParams &pir_params) = default;

  // ================== getters ==================
  const size_t get_ct_mod_width() const;

  inline const size_t get_uint_size() const { return sizeof(db_coeff_t); }
  inline const size_t get_num_bits_per_coeff() const { return DBConsts::PlainMod - 1; }
  inline size_t get_pt_size() const {
    return get_num_bits_per_coeff() * DBConsts::PolyDegree / 8;
  }
  inline double get_DBSize_MB() const {
    return static_cast<double>(num_pt_) * get_pt_size() / 1024 / 1024;
  }
  inline double get_physical_storage_MB() const {
    return static_cast<double>(get_coeff_val_cnt()) * num_pt_ * sizeof(db_coeff_t) / 1024 / 1024;
  }
  inline size_t get_num_pt() const { return num_pt_; }
  inline size_t get_num_dims() const { return num_dims_; }
  inline size_t get_l() const { return l_ep_; }
  // GSW queries packed into the client-side query per non-first dimension.
  // MP-gadget: l_ep_ slots (one per gadget power).
  // RNS:       K * l_ep_ slots (one per (k_src, p_idx) of the 2*K*l GSW).
  inline size_t get_query_per_dim() const {
    return DBConsts::Decomp == DBConsts::DecompVariant::RNS
               ? K() * l_ep_
               : l_ep_;
  }
  inline size_t get_l_key() const { return l_key_; }
  inline size_t get_small_q() const { return small_q_; }
  inline size_t get_base_log2() const { return base_log2_; }
  inline size_t get_base_log2_key() const { return base_log2_key_; }
  inline size_t get_fst_dim_sz() const { return fst_dim_sz_; }
  inline size_t get_other_dim_sz() const { return num_pt_ / fst_dim_sz_; }
  // Number of RNS limbs (matches DBConsts::RnsMods.size()).
  inline size_t K() const { return rns_mods_.size(); }
  inline size_t get_coeff_val_cnt() const {
    return DBConsts::PolyDegree * K();
  }
  inline uint64_t get_plain_mod() const { return plain_mod_; }
  inline const std::vector<uint64_t> &get_rns_mods() const { return rns_mods_; }
  inline const std::vector<size_t> &get_rns_mod_bits() const { return rns_mod_bits_; }
  inline const RnsTables &get_rns_tables() const { return rns_tables_; }
  inline const CompositeRnsTables &get_composite_rns() const { return composite_rns_; }
  inline size_t get_poly_degree() const { return DBConsts::PolyDegree; }
  inline const size_t get_expan_height() const { return DBConsts::TREE_HEIGHT; }
  inline size_t get_num_other_dims() const { return num_dims_ - 1; }

  // Standard deviation σ of the Gaussian error distribution used during
  // encryption and key generation. Defined in DBConsts::NoiseStdDev.
  inline double get_noise_std_dev() const { return DBConsts::NoiseStdDev; }

  inline const size_t get_BFV_size(bool use_seed = true) const {
    const size_t per_poly_bits = DBConsts::PolyDegree * get_ct_mod_width();
    if (use_seed) {
      return 32 + (get_ct_mod_width() * DBConsts::PolyDegree) / 8; // assuming 32 bytes for the seed
    } else {
      return (get_ct_mod_width() * DBConsts::PolyDegree * 2) / 8; // two polynomials per ciphertext
    }
  }

  // Number of RLWE rows in a GSW ciphertext (one for plain_to_gsw + the
  // BV-keyswitch key uses the same row-count formula at l_key_, which is why
  // the same multiplier appears in get_bv_galois_key_size below).
  // MP : 2 * l rows.  RNS : 2 * K * l rows (g_k-diagonal structure).
  inline size_t gsw_rows(size_t l) const {
    return (DBConsts::Decomp == DBConsts::DecompVariant::RNS)
               ? 2 * K() * l
               : 2 * l;
  }

  inline const size_t get_gsw_key_size(bool use_seed = true) const {
    return gsw_rows(l_key_) * get_BFV_size(use_seed);
  }

  inline const size_t get_bv_galois_key_size(bool use_seed = true) const {
    const size_t per_poly_bytes = (DBConsts::PolyDegree * get_ct_mod_width() + 7) / 8;
    const size_t num_keys = get_expan_height();
    // BvKeySwitchKey row count: L_KS for MP, K * L_KS for RNS (mirrors gen_bv_ks_key).
    const size_t rows_per_key = (DBConsts::Decomp == DBConsts::DecompVariant::RNS)
                                    ? K() * DBConsts::L_KS
                                    : DBConsts::L_KS;
    return use_seed
      ? num_keys * rows_per_key * (per_poly_bytes + 32)
      : num_keys * rows_per_key * 2 * per_poly_bytes;
  }

  void print_params() const;

private:
  static constexpr size_t l_ep_ = DBConsts::L_EP;
  static constexpr size_t l_key_ = DBConsts::L_KEY;
  uint64_t small_q_ = 0;
  size_t base_log2_;
  size_t base_log2_key_;
  size_t num_pt_;
  size_t fst_dim_sz_;
  size_t num_dims_;
  uint64_t plain_mod_ = 0;
  std::vector<size_t> rns_mod_bits_;
  std::vector<uint64_t> rns_mods_;
  RnsTables rns_tables_;
  CompositeRnsTables composite_rns_;

  // Populate rns_mods_ and composite_rns_ for the composite-first-dim path.
  // Registers the CRT-combined 2N-th root with utils so later NTT calls on the
  // composite modulus pick it up (HEXL's default ctor assumes a prime).
  void init_composite_rns();
};
