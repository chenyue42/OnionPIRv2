#pragma once



class PirTest {
  public:
    void run_tests();

    // ! the main test for PIR
    void test_pir();

    // ======================== BFV & GSW tests ========================
    void bfv_example();
    void test_external_product(); 
    void test_decrypt_mod_q();

    // ======================== SEAL Serialization ========================
    void serialization_example();

    // ======================== Matrix tests ========================
    // test the matrix multiplication performance when using only one level/degree
    void test_single_mat_mult();
    // simulation of the first dimension multiplication
    void test_fst_dim_mult();

    // ======================== Other tests ========================
    void test_prime_gen();
    void test_batch_decomp();
    void test_fast_expand_query();
    void test_raw_pt_ct_mult();
    void test_mod_switch();
    void test_sk_mod_switch();
};
