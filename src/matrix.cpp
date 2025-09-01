#include "matrix.h"
#include <cstring>

#ifdef ONIONPIR_USE_HEXL
#include "hexl/hexl.hpp"
#endif
#ifdef HAVE_EIGEN
#include <Eigen/Dense>
#endif

void mat_mat_64(const uint64_t *__restrict A, const uint64_t *__restrict B,
  uint64_t *__restrict out, const size_t rows, const size_t cols) {
  
  uint64_t t0, t1;
  for (size_t i = 0; i < rows; i++) {
    t0 = 0; t1 = 0;
    const size_t offset = i * cols;
    #pragma GCC unroll 32
    for (size_t k = 0; k < cols; k++) {
      t0 += A[offset + k] * B[2 * k];
      t1 += A[offset + k] * B[2 * k + 1];
    }
    out[2 * i] = t0;
    out[2 * i + 1] = t1;
  }
}

void level_mat_mat_64(matrix_t *A, matrix_t *B, matrix_t *out) {
  const size_t m = A->rows; 
  const size_t n = A->cols; 
  const size_t levels = A->levels;
  const uint64_t *A_data = A->data;
  const uint64_t *B_data = B->data;
  uint64_t *out_data = out->data;

  // For each "level," we do one standard mat-mat multiplication.
  // A(level) is m-by-n, B(level) is n-by-2, out(level) is m-by-2
  for (size_t level = 0; level < levels; ++level) {
    // Offsets into the flat arrays for this level
    const uint64_t *A_ptr = A_data + level * (m * n);
    const uint64_t *B_ptr = B_data + level * (n * 2);
    uint64_t *C_ptr = out_data + level * (m * 2);
    // TODO: optimize this function.
    mat_mat_64(A_ptr, B_ptr, C_ptr, m, n);
  }
}


void mat_mat_128(const uint64_t *__restrict A, const uint64_t *__restrict B,
  uint128_t *__restrict out, const size_t rows,
  const size_t cols) {
uint128_t t0, t1;
for (size_t i = 0; i < rows; i++) {
t0 = 0; t1 = 0;
const size_t offset = i * cols;
#pragma GCC unroll 32
for (size_t k = 0; k < cols; k++) {
t0 += A[offset + k] * (uint128_t)B[2 * k];
t1 += A[offset + k] * (uint128_t)B[2 * k + 1];
}
out[2 * i] = t0;
out[2 * i + 1] = t1;
}
}


void level_mat_mat_64_128(matrix_t *A, matrix_t *B, matrix128_t *out) {
  const size_t m = A->rows; 
  const size_t n = A->cols; 
  const size_t levels = A->levels;
  const uint64_t *A_data = A->data;
  const uint64_t *B_data = B->data;
  uint128_t *out_data = out->data;

  // For each "level," we do one standard mat-mat multiplication.
  // A(level) is m-by-n, B(level) is n-by-2, out(level) is m-by-2
  for (size_t level = 0; level < levels; ++level) {
    // Offsets into the flat arrays for this level
    const uint64_t *A_ptr = A_data + level * (m * n);
    const uint64_t *B_ptr = B_data + level * (n * 2);
    uint128_t *C_ptr = out_data + level * (m * 2);
    // TODO: optimize this function.
    mat_mat_128(A_ptr, B_ptr, C_ptr, m, n);
  }
}
