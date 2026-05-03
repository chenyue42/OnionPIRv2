#include "matrix.h"
#include <algorithm>
#include <cstring>

typedef unsigned __int128 uint128_t;

// Pick a chunk size that keeps the unreduced accumulator inside inter_coeff_t.
// Each per-row inner loop accumulates up to `chunk` products. With a leading
// `acc < q` term carried from the prior chunk, the running sum is bounded by
//     acc + chunk · q² < q + chunk · q²,
// so chunk ≤ (MAX_ACC - q) / q².
static inline size_t pick_chunk(uint64_t q, size_t cols) {
  if (q == 0) return cols;
  const inter_coeff_t MAX_ACC = ~static_cast<inter_coeff_t>(0);
  const inter_coeff_t qi = static_cast<inter_coeff_t>(q);
  const inter_coeff_t q2 = qi * qi;
  if (q2 == 0) return cols;
  const inter_coeff_t r = (MAX_ACC - qi) / q2;
  if (r == 0) return 1;
  if (r >= static_cast<inter_coeff_t>(cols)) return cols;
  return static_cast<size_t>(r);
}

void mat_mat(const db_coeff_t *__restrict A, const db_coeff_t *__restrict B,
  inter_coeff_t *__restrict out, const size_t rows, const size_t cols,
  const uint64_t q) {

  const size_t chunk = pick_chunk(q, cols);

  if (chunk >= cols) {
    // Single-pass: caller has guaranteed accumulator can't overflow.
    for (size_t i = 0; i < rows; i++) {
      inter_coeff_t t0 = 0, t1 = 0;
      const size_t offset = i * cols;
      #pragma GCC unroll 32
      for (size_t k = 0; k < cols; k++) {
        t0 += (inter_coeff_t)A[offset + k] * B[2 * k];
        t1 += (inter_coeff_t)A[offset + k] * B[2 * k + 1];
      }
      out[2 * i] = t0;
      out[2 * i + 1] = t1;
    }
    return;
  }

  // Chunked accumulation with mod-q reduction between chunks.
  const inter_coeff_t qi = static_cast<inter_coeff_t>(q);
  for (size_t i = 0; i < rows; i++) {
    const size_t offset = i * cols;
    inter_coeff_t acc0 = 0, acc1 = 0;
    for (size_t base = 0; base < cols; base += chunk) {
      const size_t end = std::min(base + chunk, cols);
      inter_coeff_t t0 = 0, t1 = 0;
      #pragma GCC unroll 16
      for (size_t k = base; k < end; k++) {
        t0 += (inter_coeff_t)A[offset + k] * B[2 * k];
        t1 += (inter_coeff_t)A[offset + k] * B[2 * k + 1];
      }
      acc0 = (acc0 + t0) % qi;
      acc1 = (acc1 + t1) % qi;
    }
    out[2 * i] = acc0;
    out[2 * i + 1] = acc1;
  }
}

void level_mat_mat(db_matrix_t *A, db_matrix_t *B, inter_matrix_t *out,
                   const uint64_t *level_qs) {
  const size_t m = A->rows;
  const size_t n = A->cols;
  const size_t levels = A->levels;
  const db_coeff_t *A_data = A->data;
  const db_coeff_t *B_data = B->data;
  inter_coeff_t *out_data = out->data;

  for (size_t level = 0; level < levels; ++level) {
    const db_coeff_t *A_ptr = A_data + level * (m * n);
    const db_coeff_t *B_ptr = B_data + level * (n * 2);
    inter_coeff_t *C_ptr = out_data + level * (m * 2);
    mat_mat(A_ptr, B_ptr, C_ptr, m, n, level_qs[level]);
  }
}
