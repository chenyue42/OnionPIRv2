#include "pir.h"
#include "database_constants.h"
#include "utils.h"
#include "hexl/hexl.hpp"

#include <cassert>
#include <cmath>
#include <iostream>
#include <string>

PirParams::PirParams()
    : coeff_mod_bits_(DBConsts::CoeffMods.begin(), DBConsts::CoeffMods.end()) {
  // ============ Coefficient modulus (possibly composite q = q1*q2) ============
#if ACTIVE_CONFIG == CONFIG_COMPOSITE_56
  std::vector<int> rns_bits(DBConsts::FirstDimRNSMods.begin(),
                            DBConsts::FirstDimRNSMods.end());
  auto rns_primes = utils::generate_ntt_friendly_primes(rns_bits, DBConsts::PolyDegree);
  const uint64_t q1 = rns_primes[0];
  const uint64_t q2 = rns_primes[1];
  const uint64_t crt_mod = q1 * q2;
  const uint64_t w1 = intel::hexl::MinimalPrimitiveRoot(2 * DBConsts::PolyDegree, q1);
  const uint64_t w2 = intel::hexl::MinimalPrimitiveRoot(2 * DBConsts::PolyDegree, q2);
  const uint64_t w_crt = utils::crt_combine(w1, q1, w2, q2);
  // Seed the NTT cache so every later utils::ntt_fwd/inv on (N, crt_mod) in
  // any thread uses the CRT-compatible root rather than HEXL's default search
  // (which assumes a prime modulus and would fail here).
  utils::register_ntt_root(DBConsts::PolyDegree, crt_mod, w_crt);
  coeff_modulus_ = {crt_mod};
  composite_rns_.enabled = true;
  composite_rns_.q1 = q1;
  composite_rns_.q2 = q2;
  composite_rns_.w1 = w1;
  composite_rns_.w2 = w2;
  composite_rns_.w_crt = w_crt;
  uint64_t q1_inv;
  if (!utils::try_invert_uint_mod(q1 % q2, q2, q1_inv))
    throw std::runtime_error("PirParams: q1 and q2 must be coprime");
  composite_rns_.q1_inv_mod_q2 = q1_inv;
#else
  coeff_modulus_ = utils::generate_ntt_friendly_primes(coeff_mod_bits_,
                                                       DBConsts::PolyDegree);
#endif

  // =============== Plaintext modulus ===============
  plain_mod_ = utils::generate_prime(DBConsts::PlainMod);

  // =============== Small modulus for mod-switch ===============
  small_q_ = utils::generate_ntt_friendly_primes(
                 {static_cast<int>(DBConsts::SmallQWidth)}, DBConsts::PolyDegree)[0];

  // ================== RNS tables (K=2 CRT constants) ==================
  const size_t K = coeff_modulus_.size();
  rns_tables_.r64_mod_q.resize(K);
  for (size_t i = 0; i < K; i++) {
    rns_tables_.r64_mod_q[i] = static_cast<uint64_t>(
        (static_cast<uint128_t>(1) << 64) % coeff_modulus_[i]);
  }
  if (K == 2) {
    if (!utils::try_invert_uint_mod(coeff_modulus_[0] % coeff_modulus_[1],
                                    coeff_modulus_[1],
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
  auto [fst_dim_sz, num_dims] = utils::calculate_db_shape(target_num_pt, l_ep_, DBConsts::TREE_HEIGHT);
  fst_dim_sz_ = fst_dim_sz;
  num_dims_ = num_dims;
  DEBUG_PRINT("fst_dim_sz: " << fst_dim_sz_ << ", num_dims: " << num_dims_);
  size_t other_dim_sz = utils::roundup_div(target_num_pt, fst_dim_sz_);
  num_pt_ = fst_dim_sz_ * other_dim_sz;
}

const size_t PirParams::get_ct_mod_width() const {
  size_t ct_mod_width = 0;
  for (size_t i = 0; i < get_coeff_mod_cnt(); ++i) {
    ct_mod_width += coeff_mod_bits_[i];
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
  print_field_num("num_queries", get_num_queries());
  print_field("query_mode",
              get_query_mode() == DBConsts::QueryMode::Stateful
                  ? "Stateful"
                  : "DoubleStateless");
  print_field("gsw_source",
              get_gsw_source() == DBConsts::GswSource::FromExpansion
                  ? "FromExpansion (RGSW(s))"
                  : "FromFreshSend (RGSW(b))");

  print_field_num("poly_modulus_degree", DBConsts::PolyDegree);

  // Coeff modulus bit widths
  std::string bit_count_str = "[";
  for (std::size_t i = 0; i + 1 < coeff_mod_bits_.size(); i++) {
    bit_count_str += std::to_string(coeff_mod_bits_[i]) + " + ";
  }
  bit_count_str += std::to_string(coeff_mod_bits_.back());
  bit_count_str += "] = " + std::to_string(get_ct_mod_width()) + " bits";
  print_field("coeff_modulus bit widths", bit_count_str, 40);

  // Coeff modulus values
  std::string coeff_mod_str = "[";
  for (std::size_t i = 0; i + 1 < coeff_modulus_.size(); i++) {
    coeff_mod_str += std::to_string(coeff_modulus_[i]) + " + ";
  }
  coeff_mod_str += std::to_string(coeff_modulus_.back());
  coeff_mod_str += "]";
  print_field("coeff_modulus", coeff_mod_str, 40);

  print_field_num("plain_modulus", plain_mod_);
  print_field_num("log(q)", get_ct_mod_width());
  print_field_num("log(t)", static_cast<int>(std::ceil(std::log2(plain_mod_))));

  if (get_coeff_mod_cnt() == 1) {
    print_field_num("log(small_q)", static_cast<int>(std::ceil(std::log2(small_q_))));
  }

  std::cout << "==============================================================" << std::endl;
}
