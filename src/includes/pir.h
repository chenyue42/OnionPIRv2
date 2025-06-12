#pragma once

#include "seal/seal.h"
#include "logging.h"
#include "database_constants.h"
#include <vector>

// ================== NAMESPACES  ==================
using namespace seal::util;
using namespace seal;

// ================== TYPE DEFINITIONS ==================
// Each entry is a vector of bytes
typedef std::vector<uint8_t> Entry;
typedef uint64_t Key; // key in the key-value pair. 

// ================== CLASS DEFINITIONS ==================
class PirParams {
public:
  PirParams();
  // copy constructor
  PirParams(const PirParams &pir_params) = default;

  // ================== getters ==================
  /**
    * @brief Calculates the number of entries that each plaintext can contain,
    aligning the end of an entry to the end of a plaintext.
   */
  size_t get_num_entries_per_plaintext() const;
  size_t get_num_bits_per_coeff() const;

  /**
   * @brief Calculates the number of bytes of data each plaintext contains,
   * after aligning the end of an entry to the end of a plaintext.
   */
  size_t get_num_bits_per_plaintext() const;

  inline seal::EncryptionParameters get_seal_params() const { return seal_params_; }
  inline seal::SEALContext get_context() const { return context_; }
  inline double get_DBSize_MB() const { return static_cast<double>(num_entries_) * entry_size_ / 1024 / 1024; }
  inline double get_physical_storage_MB() const {
    // After NTT, plaintext will have same size as ciphertext.
    return static_cast<double>(get_coeff_val_cnt()) * num_pt_ * 8 / 1024 / 1024;
  }
  inline size_t get_num_entries() const { return num_entries_; }
  inline size_t get_num_pt() const { return num_pt_; }
  inline size_t get_entry_size() const { return entry_size_; }
  inline std::vector<size_t> get_dims() const { return dims_; }
  inline size_t get_l() const { return l_; }
  inline size_t get_l_key() const { return l_key_; }
  inline size_t get_small_q() const { return small_q_; }
  inline size_t get_base_log2() const { return base_log2_; }
  inline size_t get_base_log2_key() const { return base_log2_key_; }
  // In terms of number of plaintexts
  // inline size_t get_fst_dim_sz() const { return dims_[0]; }
  inline size_t get_fst_dim_sz() const { return DatabaseConstants::FstDimSz; }
  // In terms of number of plaintexts
  // when other_dim_sz == 1, it means we only use the first dimension.
  inline size_t get_other_dim_sz() const { return num_pt_ / dims_[0]; }
  inline size_t get_rns_mod_cnt() const { return seal_params_.coeff_modulus().size() - 1; }
  inline size_t get_coeff_val_cnt() const { return DatabaseConstants::PolyDegree * get_rns_mod_cnt(); }
  inline uint64_t get_plain_mod() const { return seal_params_.plain_modulus().value(); }
  inline std::vector<Modulus> get_coeff_modulus() const {
    return context_.first_context_data()->parms().coeff_modulus();
  }
  // The height of the expansion tree during packing unpacking stages
  inline const size_t get_expan_height() const {
    return std::ceil(std::log2(get_fst_dim_sz() + get_l() * (dims_.size() - 1)));
  }

  // ================== helper functions ==================
  static seal::EncryptionParameters init_seal_params();
  void print_params() const;

private:
  static constexpr size_t l_ = DatabaseConstants::GSW_L;                  // l for GSW
  static constexpr size_t l_key_ = DatabaseConstants::GSW_L_KEY;          // l for GSW key
  uint64_t small_q_ = 0; // small modulus used for modulus switching. Use only when rns_mod_cnt == 1
  size_t base_log2_;         // log of base for data RGSW
  size_t base_log2_key_;     // log of base for key RGSW
  size_t num_entries_;  // number of entries in the database. Will be padded to multiples of other dimension size.
  size_t num_pt_;            // number of plaintexts in the database
  size_t entry_size_;    // size of each entry in bytes
  size_t total_dims_ = DatabaseConstants::TotalDims;        // total number of dimensions (d in paper)
  std::vector<size_t> dims_; // Number of dimensions
  seal::EncryptionParameters seal_params_;
  seal::SEALContext context_;
};