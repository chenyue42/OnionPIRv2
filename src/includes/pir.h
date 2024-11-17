#pragma once

#include "seal/seal.h"
#include "database_constants.h"
#include <vector>

// ================== MACROs ==================
#define CURR_TIME std::chrono::high_resolution_clock::now()
#define TIME_DIFF(start, end) std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()

// print for debug. Easily turn on/off by defining _DEBUG
#ifdef _DEBUG
#define DEBUG_PRINT(s) std::cout << s << std::endl;
#endif

#ifdef _BENCHMARK
#define DEBUG_PRINT(s) ; // do nothing
#endif

#define BENCH_PRINT(s) std::cout << s << std::endl;

#define PRINT_BAR DEBUG_PRINT("==============================================================");

// ================== NAMESPACES  ==================
using namespace seal::util;
using namespace seal;

// ================== TYPE DEFINITIONS ==================
// Each entry is a vector of bytes
typedef std::vector<uint8_t> Entry;
typedef Ciphertext PirQuery;
typedef uint64_t Key; // key in the key-value pair. 

// ================== CLASS DEFINITIONS ==================
class PirParams {
public:
  PirParams();

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
  seal::EncryptionParameters get_seal_params() const;
  double get_DBSize_MB() const;
  inline size_t get_num_entries() const { return num_entries_; }
  inline size_t get_num_pt() const { return num_pt_; }
  inline size_t get_entry_size() const { return entry_size_; }
  inline std::vector<size_t> get_dims() const { return dims_; }
  inline size_t get_l() const { return l_; }
  inline size_t get_l_key() const { return l_key_; }
  inline size_t get_base_log2() const { return base_log2_; }
  // In terms of number of plaintexts
  inline size_t get_fst_dim_sz() const { return dims_[0]; }
  // In terms of number of plaintexts
  // when other_dim_sz == 1, it means we only use the first dimension.
  inline size_t get_other_dim_sz() const { return num_pt_ / dims_[0]; }

  void print_params() const;

private:
  static constexpr size_t l_ = DatabaseConstants::GSW_L;                  // l for GSW
  static constexpr size_t l_key_ = DatabaseConstants::GSW_L_KEY;          // l for GSW key
  size_t num_entries_ = DatabaseConstants::NumEntries;  // number of entries in the database. Will be padded to multiples of other dimension size.
  size_t num_pt_;            // number of plaintexts in the database
  size_t entry_size_;    // size of each entry in bytes
  size_t base_log2_;         // log of base for RGSW
  std::vector<size_t> dims_; // Number of dimensions
  seal::EncryptionParameters seal_params_;
};