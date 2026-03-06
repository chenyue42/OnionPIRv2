#pragma once

#include <string>

class PirTest {
  public:
    void run_test(const std::string &test_name, bool use_compression);

    // ! the main test for PIR
    void test_pir(bool use_compression);

    // ======================== BFV & GSW tests ========================
    void bfv_example();
    void test_external_product(); 
    void test_decrypt_mod_q();
    void test_ext_prod_mux();

    // ======================== SEAL Serialization ========================
    void serialization_example();

    // ======================== Matrix tests ========================
    // simulation of the first dimension multiplication
    void test_fst_dim_mult();

    // ======================== System Information ========================
    void print_cpu_info();

    // ======================== Other tests ========================
    void test_prime_gen();
    void test_batch_decomp();
    void test_fast_expand_query();
    void test_raw_pt_ct_mult();
    void test_mod_switch();
    void test_sk_mod_switch();
    void test_db_shape();
};
