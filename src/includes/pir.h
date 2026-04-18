#pragma once

#include "logging.h"
#include "database_constants.h"
#include <cstdint>
#include <vector>

// ================== CLASS DEFINITIONS ==================
class PirParams {
public:
  PirParams();
  // copy constructor
  PirParams(const PirParams &pir_params) = default;

  // ================== getters ==================
  // number of usable bits per coefficient

  const size_t get_ct_mod_width() const;

  inline const size_t get_uint_size() const {
    return sizeof(db_coeff_t);
  }
  inline const size_t get_num_bits_per_coeff() const { return DBConsts::PlainMod - 1; }
  // size of each plaintext in bytes
  inline size_t get_pt_size() const { return get_num_bits_per_coeff() * DBConsts::PolyDegree / 8; }
  inline double get_DBSize_MB() const { return static_cast<double>(num_pt_) * get_pt_size() / 1024 / 1024; }
  inline double get_physical_storage_MB() const {
    // After NTT, each coefficient fits in db_coeff_t (28-bit moduli).
    return static_cast<double>(get_coeff_val_cnt()) * num_pt_ * sizeof(db_coeff_t) / 1024 / 1024;
  }
  inline size_t get_num_pt() const { return num_pt_; }
  inline size_t get_num_dims() const { return num_dims_; }
  inline size_t get_l() const { return l_ep_; }
  inline size_t get_l_key() const { return l_key_; }
  inline size_t get_small_q() const { return small_q_; }
  inline size_t get_base_log2() const { return base_log2_; }
  inline size_t get_base_log2_key() const { return base_log2_key_; }
  // In terms of number of plaintexts
  inline size_t get_fst_dim_sz() const { return fst_dim_sz_; }
  // In terms of number of plaintexts
  // when other_dim_sz == 1, it means we only use the first dimension.
  inline size_t get_other_dim_sz() const { return num_pt_ / fst_dim_sz_; }
  // Ciphertext coeff modulus carries an extra "special" prime (last entry) that
  // is not used for RLWE arithmetic; active RNS count excludes it.
  inline size_t get_rns_mod_cnt() const { return coeff_modulus_.size() - 1; }
  inline size_t get_coeff_val_cnt() const { return DBConsts::PolyDegree * get_rns_mod_cnt(); }
  inline uint64_t get_plain_mod() const { return plain_mod_; }
  inline const std::vector<uint64_t> &get_coeff_modulus() const { return coeff_modulus_; }
  inline const std::vector<int> &get_coeff_mod_bits() const { return coeff_mod_bits_; }
  inline size_t get_poly_degree() const { return DBConsts::PolyDegree; }
  // The height of the expansion tree during packing unpacking stages
  inline const size_t get_expan_height() const { return DBConsts::TREE_HEIGHT; }

  // Standard deviation σ of the Gaussian error distribution used during
  // encryption and key generation.  This is the standard deviation in the
  // statistical sense: the distribution is N(0, σ²), i.e. samples are
  // rounded Gaussians with ≈68% of values within ±σ of zero.
  //
  // Relationship to the "width parameter" r used in Spiral/Respire:
  //   σ_std = r / sqrt(2π)  ←→  r = σ_std * sqrt(2π)
  // For example, SEAL's default σ_std = 3.2 corresponds to r ≈ 8.01.
  // Defined in DBConsts::NoiseStdDev (database_constants.h).
  inline double get_noise_std_dev() const { return DBConsts::NoiseStdDev; }

  inline const size_t get_BFV_size(bool use_seed = true) const {
    if (use_seed) {
      return (get_ct_mod_width() * get_coeff_val_cnt() + 32) / 8;
    } else {
      return (get_ct_mod_width() * get_coeff_val_cnt() * 2) / 8;
    }
  }

  inline const size_t get_gsw_key_size(bool use_seed = true) const {
    return 2 * l_key_ * get_BFV_size(use_seed);
  }

  // ================== helper functions ==================
  void print_params() const;

private:
  static constexpr size_t l_ep_ = DBConsts::L_EP;                  // l for GSW
  static constexpr size_t l_key_ = DBConsts::L_KEY;          // l for GSW key
  uint64_t small_q_ = 0; // small modulus used for modulus switching. Use only when rns_mod_cnt == 1
  size_t base_log2_;         // log of base for data RGSW
  size_t base_log2_key_;     // log of base for key RGSW
  size_t num_pt_;            // number of plaintexts in the database
  size_t fst_dim_sz_;        // first dimension size (number of plaintexts)
  size_t num_dims_;          // total number of dimensions
  uint64_t plain_mod_ = 0;   // plaintext modulus t
  std::vector<int> coeff_mod_bits_;     // bit widths of each coeff modulus limb
  std::vector<uint64_t> coeff_modulus_; // NTT-friendly primes, last entry is the "special" limb
};
