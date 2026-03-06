#pragma once

#include <string>

// Common includes used by most tests
#include "gsw_eval.h"
#include "pir.h"
#include "server.h"
#include "client.h"
#include "utils.h"
#include "logging.h"
#include "matrix.h"
#include "seal/util/iterator.h"

#include <cassert>
#include <iostream>
#include <bitset>

inline void print_throughput(const std::string &name, const size_t db_size) {
  double avg_time = GET_AVG_TIME(name);
  double throughput = db_size / (avg_time * 1000);
  BENCH_PRINT(name << ": " << throughput << " MB/s");
}

class PirTest {
  public:
    size_t num_experiments = 10;

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
    void test_batch_decomp();
    void test_fast_expand_query();
    void test_raw_pt_ct_mult();
    void test_mod_switch();
    void test_sk_mod_switch();
    void test_db_shape();
};
