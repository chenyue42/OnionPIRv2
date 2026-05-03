#include "pir.h"
#include "database_constants.h"
#include "utils.h"

#include <cassert>
#include <cmath>
#include <iostream>
#include <string>

PirParams::PirParams()
    : rns_mod_bits_(DBConsts::RnsMods.begin(), DBConsts::RnsMods.end()) {
  rns_mods_ = utils::generate_ntt_friendly_primes(rns_mod_bits_,
                                                       DBConsts::PolyDegree);

  // =============== Plaintext modulus ===============
  plain_mod_ = utils::generate_prime(DBConsts::PlainMod);

  // =============== Small modulus for mod-switch ===============
  small_q_ = utils::generate_ntt_friendly_primes(
                 {static_cast<int>(DBConsts::SmallQWidth)}, DBConsts::PolyDegree)[0];

  // ================== RNS tables (two-mod CRT constants; unused at rns_cnt=1) ==================
  const size_t rns_cnt = rns_mods_.size();
  rns_tables_.r64_mod_q.resize(rns_cnt);
  for (size_t i = 0; i < rns_cnt; i++) {
    rns_tables_.r64_mod_q[i] = static_cast<uint64_t>(
        (static_cast<uint128_t>(1) << 64) % rns_mods_[i]);
  }
  if (rns_cnt == 2) {
    if (!utils::try_invert_uint_mod(rns_mods_[0] % rns_mods_[1],
                                    rns_mods_[1],
                                    rns_tables_.q0_inv_mod_q1)) {
      throw std::runtime_error("PirParams: coeff moduli not coprime");
    }
  }

  // ================== GSW related parameters ==================
  size_t ct_mod_width = get_ct_mod_width();
  base_log2_ = (ct_mod_width + l_ep_ - 1) / l_ep_;
  base_log2_key_ = (ct_mod_width + l_key_ - 1) / l_key_;

  // =============== Database shape calculation ===============
  size_t target_num_pt = DBConsts::DB_SIZE_MB * 1024 * 1024 / get_pt_size();
  DEBUG_PRINT("target_num_pt: " << target_num_pt);
  // Per-dim query slot count: l_ep_ for MP, K*l_ep_ for RNS-hybrid. The
  // variant decision is constexpr; use the helper that already encodes it.
  auto [fst_dim_sz, num_dims] = utils::calculate_db_shape(
      target_num_pt, get_query_per_dim(), DBConsts::TREE_HEIGHT);
  fst_dim_sz_ = fst_dim_sz;
  num_dims_ = num_dims;
  DEBUG_PRINT("fst_dim_sz: " << fst_dim_sz_ << ", num_dims: " << num_dims_);
  size_t other_dim_sz = utils::roundup_div(target_num_pt, fst_dim_sz_);
  num_pt_ = fst_dim_sz_ * other_dim_sz;
}

const size_t PirParams::get_ct_mod_width() const {
  size_t ct_mod_width = 0;
  for (size_t i = 0; i < K(); ++i) {
    ct_mod_width += rns_mod_bits_[i];
  }
  return ct_mod_width;
}

void PirParams::print_params() const {
  PRINT_BAR;
  std::cout << "                       PIR PARAMETERS                         " << std::endl;
  PRINT_BAR;

  auto print_field = [](const std::string& label, const std::string& value, int label_width = 35) {
    std::string padded_label = label;
    padded_label.resize(label_width, ' ');
    std::cout << "  " << padded_label << "= " << value << std::endl;
  };

  auto print_field_num = [&print_field](const std::string& label, auto value) {
    print_field(label, std::to_string(value));
  };

  print_field_num("db_coeff_t size (bytes)", get_uint_size());
  print_field_num("Database size (MB)", get_DBSize_MB());
  print_field_num("Physical storage (MB)", get_physical_storage_MB());
  print_field_num("Plaintext size (KB)", get_pt_size() / 1024);
  print_field_num("num_pt_", num_pt_);
  print_field_num("expansion tree height", get_expan_height());
  print_field_num("l_ep_", l_ep_);
  print_field_num("l_key_", l_key_);
  print_field_num("base_log2_", base_log2_);

  print_field_num("fst_dim_sz", fst_dim_sz_);
  print_field_num("num_dims", num_dims_);
  print_field_num("num_other_dims", get_num_other_dims());

  print_field_num("poly_modulus_degree", DBConsts::PolyDegree);

  std::string bit_count_str = "[";
  for (std::size_t i = 0; i + 1 < rns_mod_bits_.size(); i++) {
    bit_count_str += std::to_string(rns_mod_bits_[i]) + " + ";
  }
  bit_count_str += std::to_string(rns_mod_bits_.back());
  bit_count_str += "] = " + std::to_string(get_ct_mod_width()) + " bits";
  print_field("rns_mods bit widths", bit_count_str, 40);

  std::string coeff_mod_str = "[";
  for (std::size_t i = 0; i + 1 < rns_mods_.size(); i++) {
    coeff_mod_str += std::to_string(rns_mods_[i]) + " + ";
  }
  coeff_mod_str += std::to_string(rns_mods_.back());
  coeff_mod_str += "]";
  print_field("rns_mods", coeff_mod_str, 40);

  print_field_num("plain_modulus", plain_mod_);
  print_field_num("log(q)", get_ct_mod_width());
  print_field_num("log(t)", static_cast<int>(std::ceil(std::log2(plain_mod_))));

  if (K() == 1) {
    print_field_num("log(small_q)", static_cast<int>(std::ceil(std::log2(small_q_))));
  }

  std::cout << "==============================================================" << std::endl;
}
