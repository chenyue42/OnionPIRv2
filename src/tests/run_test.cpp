#include "tests.h"

void PirTest::run_test(const std::string &test_name, bool use_bv) {
  std::cout << "Running test: " << test_name << std::endl;

  if (test_name == "pir")                    test_pir(use_bv);
  else if (test_name == "bfv")               bfv_example();
  else if (test_name == "serial")            serialization_example();
  else if (test_name == "ext_prod")          test_external_product();
  else if (test_name == "ext_prod_mux")      test_ext_prod_mux();
  else if (test_name == "fst_dim")           test_fst_dim_mult();
  else if (test_name == "batch_decomp")      test_batch_decomp();
  else if (test_name == "fast_expand")       test_fast_expand_query();
  else if (test_name == "raw_pt_ct")         test_raw_pt_ct_mult();
  else if (test_name == "decrypt_mod_q")     test_decrypt_mod_q();
  else if (test_name == "mod_switch")        test_mod_switch();
  else if (test_name == "sk_mod_switch")     test_sk_mod_switch();
  else if (test_name == "db_shape")          test_db_shape();
  else if (test_name == "bv_ks")             test_bv_keyswitch();
  else if (test_name == "cpu_info")          print_cpu_info();
  else {
    std::cerr << "Unknown test: " << test_name << std::endl;
    std::cerr << "Available tests: pir, bfv, serial, ext_prod, ext_prod_mux, "
              << "fst_dim, batch_decomp, fast_expand, raw_pt_ct, decrypt_mod_q, "
              << "mod_switch, sk_mod_switch, db_shape, cpu_info" << std::endl;
  }
}
