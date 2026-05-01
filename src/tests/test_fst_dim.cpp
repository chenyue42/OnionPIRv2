#include "tests.h"

void PirTest::test_fst_dim_mult() {
  print_func_name(__FUNCTION__);
  CLEAN_TIMER();
  // Small correctness check against a direct reference implementation.
  constexpr size_t ref_m = 4;
  constexpr size_t ref_n = 8;
  constexpr size_t ref_p = 2;
  constexpr size_t ref_levels = 3;
  std::vector<db_coeff_t> A_ref(ref_m * ref_n * ref_levels);
  std::vector<db_coeff_t> B_ref(ref_n * ref_p * ref_levels);
  std::vector<inter_coeff_t> C_ref(ref_m * ref_p * ref_levels, 0);
  std::vector<inter_coeff_t> C_got(ref_m * ref_p * ref_levels, 0);

  // fill random data for A and B
  for (size_t i = 0; i < A_ref.size(); ++i) {
    A_ref[i] = static_cast<db_coeff_t>(rand());
  }
  for (size_t i = 0; i < B_ref.size(); ++i) {
    B_ref[i] = static_cast<db_coeff_t>(rand());
  }
  db_matrix_t A_ref_mat{A_ref.data(), ref_m, ref_n, ref_levels};
  db_matrix_t B_ref_mat{B_ref.data(), ref_n, ref_p, ref_levels};
  inter_matrix_t C_got_mat{C_got.data(), ref_m, ref_p, ref_levels};
  level_mat_mat(&A_ref_mat, &B_ref_mat, &C_got_mat);

  for (size_t level = 0; level < ref_levels; ++level) {
    const size_t a_off = level * ref_m * ref_n;
    const size_t b_off = level * ref_n * ref_p;
    const size_t c_off = level * ref_m * ref_p;
    for (size_t i = 0; i < ref_m; ++i) {
      inter_coeff_t t0 = 0;
      inter_coeff_t t1 = 0;
      for (size_t k = 0; k < ref_n; ++k) {
        const inter_coeff_t a = A_ref[a_off + i * ref_n + k];
        t0 += a * B_ref[b_off + 2 * k];
        t1 += a * B_ref[b_off + 2 * k + 1];
      }
      C_ref[c_off + 2 * i] = t0;
      C_ref[c_off + 2 * i + 1] = t1;
    }
  }

  for (size_t i = 0; i < C_ref.size(); ++i) {
    if (C_ref[i] != C_got[i]) {
      throw std::runtime_error("level_mat_mat mismatch at index " + std::to_string(i));
    }
  }
  BENCH_PRINT("Correctness check: PASS");

  // Throughput benchmark.
  // Set USE_PIR_SHAPE=true to mirror the active PirParams first-dim shape
  // (m=other_dim_sz, n=fst_dim_sz, levels=coeff_val_cnt). Set false to use
  // the custom (m, n, levels) below — handy for sweeping shapes independently.
  constexpr bool USE_PIR_SHAPE = true;
  constexpr size_t custom_m = 1 << 5;
  constexpr size_t custom_n = 512;
  constexpr size_t custom_levels = DBConsts::PolyDegree;

  PirParams pir_params;
  const size_t m = USE_PIR_SHAPE ? pir_params.get_other_dim_sz() : custom_m;
  const size_t n = USE_PIR_SHAPE ? pir_params.get_fst_dim_sz()   : custom_n;
  constexpr size_t p = 2;
  const size_t levels = USE_PIR_SHAPE ? pir_params.get_coeff_val_cnt() : custom_levels;
  const size_t db_size = m * n * levels * sizeof(db_coeff_t);
  BENCH_PRINT("Shape: m=" << m << " n=" << n << " p=" << p << " levels=" << levels
              << (USE_PIR_SHAPE ? " (PIR)" : " (custom)"));
  BENCH_PRINT("Matrix size: " << db_size / 1024 / 1024 << " MB");

  std::vector<db_coeff_t> A_data(m * n * levels);
  std::vector<db_coeff_t> B_data(n * p * levels);
  std::vector<inter_coeff_t> C_data(m * p * levels);

  // fill randome data for A and B
  for (size_t i = 0; i < A_data.size(); ++i)
    A_data[i] = static_cast<db_coeff_t>(rand());
  for (size_t i = 0; i < B_data.size(); ++i)
    B_data[i] = static_cast<db_coeff_t>(rand());

  db_matrix_t A_mat{A_data.data(), m, n, levels};
  db_matrix_t B_mat{B_data.data(), n, p, levels};
  inter_matrix_t C_mat{C_data.data(), m, p, levels};

  const std::string MAT_MULT_128 = "level mat mat 128 bits";
  TIME_START(MAT_MULT_128);
  level_mat_mat(&A_mat, &B_mat, &C_mat);
  TIME_END(MAT_MULT_128);

  inter_coeff_t checksum = 0;
  for (size_t i = 0; i < C_data.size(); ++i) {
    checksum += C_data[i];
  }
  BENCH_PRINT("Checksum: " << utils::uint128_to_string(checksum));

  END_EXPERIMENT();
  PRINT_BAR;

  const double mat_mult_time = GET_LAST_TIME(MAT_MULT_128);
  const double throughput = db_size / (mat_mult_time * 1000);

  BENCH_PRINT("level_mat_mat time: " << mat_mult_time << " ms");
  BENCH_PRINT("level_mat_mat throughput: \t" << static_cast<size_t>(throughput) << " MB/s");
}
