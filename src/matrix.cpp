#include "matrix.h"
#include <cstring>

typedef unsigned __int128 uint128_t;

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


void mat_mat(const db_coeff_t *__restrict A, const db_coeff_t *__restrict B,
  inter_coeff_t *__restrict out, const size_t rows, const size_t cols) {

  inter_coeff_t t0, t1;
  for (size_t i = 0; i < rows; i++) {
    t0 = 0; t1 = 0;
    const size_t offset = i * cols;
    #pragma GCC unroll 32
    for (size_t k = 0; k < cols; k++) {
      t0 += (inter_coeff_t)A[offset + k] * B[2 * k];
      t1 += (inter_coeff_t)A[offset + k] * B[2 * k + 1];
    }
    out[2 * i] = t0;
    out[2 * i + 1] = t1;
  }
}

void level_mat_mat(db_matrix_t *A, db_matrix_t *B, inter_matrix_t *out) {
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
    mat_mat(A_ptr, B_ptr, C_ptr, m, n);
  }
}