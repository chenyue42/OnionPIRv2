#include "tests.h"

void PirTest::test_fst_dim_mult() {
  print_func_name(__FUNCTION__);
  CLEAN_TIMER();
  // for this test, I want to know if the matrix multiplication is memory bound
  // or compute bound. If possible, please re-write this test case for GPU as
  // well as it indicates the limit of the first dimension.

  // Let's write the best code we can to compute (m x n) x (n x p) matrix
  // multiplication for k times.
  constexpr size_t m = 1 << 5; // the other_dim_sz
  constexpr size_t n = 512;
  constexpr size_t p = 2; // coz we have only 2 polynomials in the ciphertext.
  constexpr size_t k = DBConsts::PolyDegree;
  constexpr size_t db_size = m * n * k * sizeof(uint64_t);  // we only care the big matrix
  PirParams pir_params;
  BENCH_PRINT("Matrix size: " << db_size / 1024 / 1024 << " MB");

  // Allocate memory for A, B, out.
  // We interpret these as stacked (k) matrices.
  std::vector<uint64_t> A_data(m * n * k);
  std::vector<uint64_t> B_data(n * p * k);
  std::vector<uint64_t> C_data(m * p * k);
  std::vector<uint128_t> C_data_128(m * p * k);
  // Fill A and B with random data
  utils::fill_rand_arr(A_data.data(), m * n * k);
  utils::fill_rand_arr(B_data.data(), n * p * k);
  // Wrap them in our matrix_t structures
  matrix_t A_mat { A_data.data(), m, n, k };
  matrix_t B_mat { B_data.data(), n, p, k };
  matrix_t C_mat { C_data.data(), m, p, k };
  matrix128_t C_mat_128 { C_data_128.data(), m, p, k };
  size_t sum = 0;
  uint128_t sum128 = 0;


  // ============= Naive level mat mat 128bits ==============
  const std::string NAIVE_MAT_MULT_128 = "Naive level mat mat 128 bits";
  TIME_START(NAIVE_MAT_MULT_128);
  // level_mat_mat_64_128(&A_mat, &B_mat, &C_mat_128);
  level_mat_mat_64(&A_mat, &B_mat, &C_mat);
  TIME_END(NAIVE_MAT_MULT_128);

  // some simple code to make sure it is not optimized out
  sum = 0;
  for (size_t i = 0; i < m * p * k; i++) { sum += C_data[i]; }
  BENCH_PRINT("Sum: " << sum);
  sum128 = 0;
  for (size_t i = 0; i < m * p * k; i++) { sum128 += C_data_128[i]; }
  BENCH_PRINT("Sum: " << utils::uint128_to_string(sum128));


  // ============= Profiling the matrix multiplication ==============
  END_EXPERIMENT();
  // PRINT_RESULTS(); // uncomment this line to see the actual time elapsed in each function.
  PRINT_BAR;

  // Let's calculate the throughput of the matrix multiplication, express in MB/s
  double naive_mat_mult_128_time = GET_LAST_TIME(NAIVE_MAT_MULT_128);
  std::cout << "Naive level mat mat 128 bits time: " << naive_mat_mult_128_time << " ms" << std::endl;

  double naive_throughput_128 = db_size / (naive_mat_mult_128_time * 1000);

  BENCH_PRINT("Matrix size: " << db_size / 1024 / 1024 << " MB");
  BENCH_PRINT("Naive level mat mat 128 throughput: \t" << (size_t)naive_throughput_128 << " MB/s");

}
