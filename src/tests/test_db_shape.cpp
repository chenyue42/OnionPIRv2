#include "tests.h"

void PirTest::test_db_shape() {
  print_func_name(__FUNCTION__);
  auto [fst1, nd1] = utils::calculate_db_shape(1000000, 5, 9);
  BENCH_PRINT("fst_dim_sz: " << fst1 << ", num_dims: " << nd1);
  auto [fst2, nd2] = utils::calculate_db_shape(1000000, 6, 8);
  BENCH_PRINT("fst_dim_sz: " << fst2 << ", num_dims: " << nd2);
}
