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
  inline size_t get_l_key() const { return l_key_; }
  inline size_t get_small_q() const { return small_q_; }
  inline size_t get_base_log2() const { return base_log2_; }
  inline size_t get_base_log2_key() const { return base_log2_key_; }
  inline size_t get_fst_dim_sz() const { return fst_dim_sz_; }
  inline size_t get_other_dim_sz() const { return num_pt_ / fst_dim_sz_; }
  inline size_t get_rns_mod_cnt() const { return rns_mods_.size(); }
  inline size_t get_coeff_val_cnt() const {
    return DBConsts::PolyDegree * get_rns_mod_cnt();
  }
  inline uint64_t get_plain_mod() const { return plain_mod_; }
  inline const std::vector<uint64_t> &get_rns_mods() const { return rns_mods_; }
  inline const std::vector<int> &get_rns_mod_bits() const { return rns_mod_bits_; }
  inline const RnsTables &get_rns_tables() const { return rns_tables_; }
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

  inline const size_t get_gsw_key_size(bool use_seed = true) const {
    return 2 * l_key_ * get_BFV_size(use_seed);
  }

  inline const size_t get_bv_galois_key_size(bool use_seed = true) const {
    const size_t per_poly_bytes = (DBConsts::PolyDegree * get_ct_mod_width() + 7) / 8;
    const size_t num_keys = get_expan_height();
    return use_seed
      ? num_keys * DBConsts::L_KS * (per_poly_bytes + 32)
      : num_keys * DBConsts::L_KS * 2 * per_poly_bytes;
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
  std::vector<int> rns_mod_bits_;
  std::vector<uint64_t> rns_mods_;
  RnsTables rns_tables_;
};
