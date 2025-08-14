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
      DBConsts::PolyDegree); // example: a_1 x^4095 + a_2 x^4094 + ...

  const uint64_t pt_mod = utils::generate_prime(DBConsts::PlainMod);
  params.set_plain_modulus(pt_mod);
  std::vector<int> bit_sizes(DBConsts::CoeffMods.begin(),
                             DBConsts::CoeffMods.end());
  const auto coeff_modulus =
      CoeffModulus::Create(DBConsts::PolyDegree, bit_sizes);
  params.set_coeff_modulus(coeff_modulus);

  return params;
}

PirParams::PirParams()
    : seal_params_(init_seal_params()), context_(seal_params_) {
  // =============== Setting modulus ===============
  const uint64_t pt_mod = seal_params_.plain_modulus().value();
  // setup the modulus switching mod.
  small_q_ = CoeffModulus::Create(DBConsts::PolyDegree,
                                {DBConsts::SmallQWidth, DBConsts::CoeffMods.back()})[0].value();

  // ================== GSW related parameters ==================
  // The number of bits for representing the largest modulus possible in the
  // given context. See analysis folder. This line rounds bits/l up to the
  // nearest integer.
  size_t ct_mod_width = get_ct_mod_width();
  base_log2_ = (ct_mod_width + l_ - 1) / l_;
  base_log2_key_ = (ct_mod_width + l_key_ - 1) / l_key_;

  // =============== Database shape calculation ===============
  // calculate the target number of plaintexts
  size_t target_num_pt = DBConsts::DB_SIZE_MB * 1024 * 1024 / get_pt_size();
  DEBUG_PRINT("target_num_pt: " << target_num_pt);
  utils::calculate_db_shape(target_num_pt, l_, DBConsts::TREE_HEIGHT, dims_);
  DEBUG_PRINT("dims: ");
  for (const auto &dim : dims_) {
    DEBUG_PRINT(dim);
  }
  total_dims_ = dims_.size();
  size_t other_dim_sz = utils::roundup_div(target_num_pt, dims_[0]);
  num_pt_ = dims_[0] * other_dim_sz;
}

const size_t PirParams::get_ct_mod_width() const {
  size_t ct_mod_width = 0;
  for (size_t i = 0; i < get_rns_mod_cnt(); ++i) {
    ct_mod_width += seal_params_.coeff_modulus()[i].bit_count();
  }
  return ct_mod_width;
}

void PirParams::print_params() const {
  PRINT_BAR;
  std::cout << "                       PIR PARAMETERS                         " << std::endl;
  PRINT_BAR;
  
  // Helper function for consistent formatting
  auto print_field = [](const std::string& label, const std::string& value, int label_width = 35) {
    std::string padded_label = label;
    padded_label.resize(label_width, ' ');
    std::cout << "  " << padded_label << "= " << value << std::endl;
  };
  
  auto print_field_num = [&print_field](const std::string& label, auto value) {
    print_field(label, std::to_string(value));
  };
  
  print_field_num("Database size (MB)", get_DBSize_MB());
  print_field_num("Physical storage (MB)", get_physical_storage_MB());
  print_field_num("Plaintext size (KB)", get_pt_size() / 1024);
  print_field_num("num_pt_", num_pt_);
  print_field_num("expansion tree height", get_expan_height());
  print_field_num("l_", l_);
  print_field_num("l_key_", l_key_);
  print_field_num("base_log2_", base_log2_);
  
  // Handle dimensions array
  std::string dims_str = "[ ";
  for (const auto &dim : dims_) {
    dims_str += std::to_string(dim) + " ";
  }
  dims_str += "]";
  print_field("dimensions_", dims_str);
  
  print_field_num("seal_params_.poly_modulus_degree()", seal_params_.poly_modulus_degree());

  // Handle coeff_modulus bit count
  size_t log_q = 0;
  std::string bit_count_str = "[";
  for (std::size_t i = 0; i < seal_params_.coeff_modulus().size() - 1; i++) {
    log_q += seal_params_.coeff_modulus()[i].bit_count();
    bit_count_str += std::to_string(seal_params_.coeff_modulus()[i].bit_count()) + " + ";
  }
  bit_count_str += std::to_string(seal_params_.coeff_modulus().back().bit_count());
  bit_count_str += "] = " + std::to_string(get_ct_mod_width()) + " bits";
  print_field("seal_params_.coeff_modulus().bit_count", bit_count_str, 40);

  // Handle coeff_modulus values
  std::string coeff_mod_str = "[";
  for (std::size_t i = 0; i < seal_params_.coeff_modulus().size() - 1; i++) {
    coeff_mod_str += std::to_string(seal_params_.coeff_modulus()[i].value()) + " + ";
  }
  coeff_mod_str += std::to_string(seal_params_.coeff_modulus().back().value());
  coeff_mod_str += "]";
  print_field("seal_params_.coeff_modulus()", coeff_mod_str, 40);
  
  print_field_num("plain_modulus", seal_params_.plain_modulus().value());
  print_field_num("log(q)", log_q);
  print_field_num("log(t)", seal_params_.plain_modulus().bit_count());
  
  if (get_rns_mod_cnt() == 1) {
    print_field_num("log(small_q)", static_cast<int>(std::ceil(std::log2(small_q_))));
  }
  
  std::cout << "==============================================================" << std::endl;
}
