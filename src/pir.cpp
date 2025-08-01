#include "pir.h"
#include "database_constants.h"
#include "gsw_eval.h"
#include "utils.h"

#include <cassert>

// ================== helper functions ==================
seal::EncryptionParameters PirParams::init_seal_params() {
  // seal parameters requires at lest three parameters: poly_modulus_degree,
  // coeff_modulus, plain_modulus Then the seal context will be set properly for
  // encryption and decryption.

  seal::EncryptionParameters params(seal::scheme_type::bfv);
  params.set_poly_modulus_degree(
      DatabaseConstants::PolyDegree); // example: a_1 x^4095 + a_2 x^4094 + ...

  const uint64_t pt_mod = utils::generate_prime(DatabaseConstants::PlainMod);
  params.set_plain_modulus(pt_mod);
  std::vector<int> bit_sizes(DatabaseConstants::CoeffMods.begin(),
                             DatabaseConstants::CoeffMods.end());
  const auto coeff_modulus =
      CoeffModulus::Create(DatabaseConstants::PolyDegree, bit_sizes);
  params.set_coeff_modulus(coeff_modulus);

  return params;
}

PirParams::PirParams()
    : seal_params_(init_seal_params()), context_(seal_params_) {
  // =============== Setting modulus ===============
  const uint64_t pt_mod = seal_params_.plain_modulus().value();
  // calculate the entry size in bytes automatically.
  if (DatabaseConstants::EntrySize == 0) {
    entry_size_ = (seal::Modulus(pt_mod).bit_count() - 1) * DatabaseConstants::PolyDegree / 8;
  } else {
    entry_size_ = DatabaseConstants::EntrySize;
  }
  // setup the modulus switching mod.
  small_q_ = CoeffModulus::Create(DatabaseConstants::PolyDegree,
                                {DatabaseConstants::SmallQWidth, DatabaseConstants::CoeffMods.back()})[0].value();

  // ================== GSW related parameters ==================
  const auto coeff_modulus = seal_params_.coeff_modulus();
  size_t bits = 0; // will store log(q) in bits
  for (size_t i = 0; i < coeff_modulus.size() - 1; i++) {
    bits += coeff_modulus[i].bit_count();
  } 

  // The number of bits for representing the largest modulus possible in the
  // given context. See analysis folder. This line rounds bits/l up to the
  // nearest integer.
  base_log2_ = (bits + l_ - 1) / l_;
  base_log2_key_ = (bits + l_key_ - 1) / l_key_;

  // ================== VALIDATION ==================

  if (get_num_entries_per_plaintext() == 0) {
    std::cerr << "Entry size: " << entry_size_ << std::endl;
    std::cerr << "Poly degree: " << DatabaseConstants::PolyDegree << std::endl;
    std::cerr << "bits per coeff: " << get_num_bits_per_coeff() << std::endl;
    throw std::invalid_argument("Number of entries per plaintext is 0, "
                                "possibly due to too large entry size");
  }

  // =============== Database shape calculation ===============
  // All dimensions are fixed to 2 except the first one.
  dims_.push_back(DatabaseConstants::FstDimSz);
  for (size_t i = 1; i < DatabaseConstants::TotalDims; i++) {
    dims_.push_back(2);
  }

  auto other_dim_sz = 1 << (DatabaseConstants::TotalDims - 1);
  num_pt_ = DatabaseConstants::FstDimSz * other_dim_sz;
  num_entries_ = num_pt_ * get_num_entries_per_plaintext(); // actual number of entries after paddding.

}

size_t PirParams::get_num_bits_per_coeff() const {
  return seal_params_.plain_modulus().bit_count() - 1;
}

size_t PirParams::get_num_bits_per_plaintext() const {
  return get_num_bits_per_coeff() * seal_params_.poly_modulus_degree();
}

const size_t PirParams::get_ct_mod_width() const {
  size_t ct_mod_width = 0;
  for (size_t i = 0; i < get_rns_mod_cnt(); ++i) {
    ct_mod_width += seal_params_.coeff_modulus()[i].bit_count();
  }
  return ct_mod_width;
}

size_t PirParams::get_num_entries_per_plaintext() const {
  const size_t total_bits = get_num_bits_per_plaintext();
  if (total_bits % (entry_size_ * 8) != 0) {
    BENCH_PRINT("You have wasted some space in the plaintext. Please consider "
                "increasing the entry size.");
  }
  return total_bits / (entry_size_ * 8);
}

void PirParams::print_params() const {
  std::cout << "==============================================================" << std::endl;
  std::cout << "                       PIR PARAMETERS                         " << std::endl;
  std::cout << "==============================================================" << std::endl;
  std::cout << "  Database size (MB) \t\t\t\t= " << get_DBSize_MB() << std::endl;
  std::cout << "  Physical storage (MB)\t\t\t\t= " << get_physical_storage_MB() << std::endl;
  std::cout << "  entry_size_\t\t\t\t\t= " << entry_size_ << " B = " << static_cast<double>(entry_size_) / 1024 << " KB" <<  std::endl;
  std::cout << "  num_pt_\t\t\t\t\t= " << num_pt_ << std::endl;
  std::cout << "  num_entries_\t\t\t\t\t= " << num_entries_ << std::endl;
  std::cout << "  Num entries per plaintext\t\t\t= "
            << get_num_entries_per_plaintext() << std::endl;
  std::cout << "  expansion tree height\t\t\t\t= " << get_expan_height() << std::endl;
  std::cout << "  l_\t\t\t\t\t\t= " << l_ << std::endl;
  std::cout << "  l_key_\t\t\t\t\t= " << l_key_ << std::endl;
  std::cout << "  base_log2_\t\t\t\t\t= " << base_log2_ << std::endl;
  std::cout << "  dimensions_\t\t\t\t\t= [ ";
  for (const auto &dim : dims_) {
    std::cout << dim << " ";
  }
  std::cout << "]" << std::endl;
  std::cout << "  seal_params_.poly_modulus_degree()\t\t= "
            << seal_params_.poly_modulus_degree() << std::endl;

  size_t log_q = 0;
  std::cout << "  seal_params_.coeff_modulus().bit_count\t= [";
  for (std::size_t i = 0; i < seal_params_.coeff_modulus().size() - 1; i++) {
    log_q += seal_params_.coeff_modulus()[i].bit_count();
    std::cout << seal_params_.coeff_modulus()[i].bit_count() << " + ";
  }
  std::cout << seal_params_.coeff_modulus().back().bit_count();
  std::cout << "] = " << get_ct_mod_width() << " bits" << std::endl;

  // print the coeff_modulus
  std::cout << "  seal_params_.coeff_modulus()\t\t\t= [";
  for (std::size_t i = 0; i < seal_params_.coeff_modulus().size() - 1; i++) {
    std::cout << seal_params_.coeff_modulus()[i].value() << " + ";
  }
  std::cout << seal_params_.coeff_modulus().back().value();
  std::cout << "]" << std::endl;
  std::cout << "  log(q)\t\t\t\t\t= " << log_q << std::endl;
  std::cout << "  log(t)\t\t\t\t\t= "
            << seal_params_.plain_modulus().bit_count() << std::endl;
  if (get_rns_mod_cnt() == 1) {
    std::cout << "  log(small_q)\t\t\t\t\t= " << std::ceil(std::log2(small_q_)) << std::endl;
  }
  std::cout << "==============================================================" << std::endl;
}
