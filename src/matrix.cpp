#include "matrix.h"
#include <cstring>
#include "hexl/hexl.hpp"
#ifdef HAVE_EIGEN
#include <Eigen/Dense>
#endif



// ======================== NAIVE STUFF ========================
void naive_mat_vec(matrix_t *A, matrix_t *B, matrix_t *out) {
  // We do a naive matrix vector multiplication.
  const size_t m = A->rows; 
  const size_t n = A->cols; 
  const uint64_t *A_ptr = A->data;
  const uint64_t *B_ptr = B->data;
  uint64_t *out_ptr = out->data; 
  uint64_t temp;
  for (size_t i = 0; i < m; i++) {
    #pragma GCC unroll 128
    for (size_t k = 0; k < n; k++) {
      temp += A_ptr[i * n + k] * B_ptr[k];
    }
    out_ptr[i] = temp;
  }
}


void naive_mat_vec_128(matrix_t *A, matrix_t *B, matrix128_t *out) {
  // We do a naive matrix vector multiplication.
  const size_t m = A->rows; 
  const size_t n = A->cols; 
  const uint64_t *A_ptr = A->data;
  const uint64_t *B_ptr = B->data;
  uint128_t *out_ptr = out->data; 
  uint128_t temp;
  for (size_t i = 0; i < m; i++) {
    temp = 0;
    #pragma GCC unroll 32
    for (size_t k = 0; k < n; k++) {
      temp += (uint128_t)A_ptr[i * n + k] * B_ptr[k];
    }
    out_ptr[i] = temp;
  }
}


void naive_level_mat_mat(matrix_t *A, matrix_t *B, matrix_t *out) {
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
    uint64_t tmp0, tmp1;
    // Then we can compute a normal matrix multiplication
    for (size_t i = 0; i < m; i++) {
      tmp0 = 0; tmp1 = 0;
      #pragma GCC unroll 64
      for (size_t k = 0; k < n; k++) {
        tmp0 += A_ptr[i * n + k] * B_ptr[k * 2];
        tmp1 += A_ptr[i * n + k] * B_ptr[k * 2 + 1];
      }
      C_ptr[i * 2] = tmp0;
      C_ptr[i * 2 + 1] = tmp1;
    }
  }
}


void naive_level_mat_mat_128(matrix_t *A, matrix_t *B, matrix128_t *out) {
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


// ======================== LEVEL MAT MAT ========================

void level_mat_mat(matrix_t *A, matrix_t *B, matrix_t *out) {
  const size_t rows = A->rows; 
  const size_t cols = A->cols;
  const size_t levels = A->levels;
  const uint64_t *A_data = A->data;
  const uint64_t *B_data = B->data;
  uint64_t *out_data = out->data;

  // We always assume p=2. Because the BFV ciphertext has two polynomials. 
  // This assumption keeps the code simple.
  if (B->cols != 2) { return; } 

  // define pointers
  const uint64_t *A_ptr;
  const uint64_t *B_ptr;
  uint64_t *C_ptr;
  uint64_t db0, db1, db2, db3, db4, db5, db6, db7;
  uint64_t tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7;
  uint64_t tmp8, tmp9, tmp10, tmp11, tmp12, tmp13, tmp14, tmp15;
  size_t i, j, level; 

  // For each "level," we do one standard mat-mat multiplication.
  // A(level) is m-by-n, B(level) is n-by-2, out(level) is m-by-2
  for (level = 0; level < levels; ++level) {
    // Offsets into the flat arrays for this level
    A_ptr = A_data + level * (rows * cols);
    B_ptr = B_data + level * (cols * 2);
    C_ptr = out_data + level * (rows * 2);

    // Then we can compute a normal matrix multiplication
    // This is a slight variation of the 
    for (i = 0; i < rows; i += 8) {
      tmp0 = 0; tmp1 = 0; tmp2 = 0; tmp3 = 0;
      tmp4 = 0; tmp5 = 0; tmp6 = 0; tmp7 = 0;
      tmp8 = 0; tmp9 = 0; tmp10 = 0; tmp11 = 0;
      tmp12 = 0; tmp13 = 0; tmp14 = 0; tmp15 = 0;
      for (j = 0; j < cols; j++) {
        db0 = A_ptr[i * cols + j];
        db1 = A_ptr[(i + 1) * cols + j];
        db2 = A_ptr[(i + 2) * cols + j];
        db3 = A_ptr[(i + 3) * cols + j];
        db4 = A_ptr[(i + 4) * cols + j];
        db5 = A_ptr[(i + 5) * cols + j];
        db6 = A_ptr[(i + 6) * cols + j];
        db7 = A_ptr[(i + 7) * cols + j];
        tmp0 += db0 * B_ptr[j * 2]; tmp1 += db0 * B_ptr[j * 2 + 1];
        tmp2 += db1 * B_ptr[j * 2]; tmp3 += db1 * B_ptr[j * 2 + 1];
        tmp4 += db2 * B_ptr[j * 2]; tmp5 += db2 * B_ptr[j * 2 + 1];
        tmp6 += db3 * B_ptr[j * 2]; tmp7 += db3 * B_ptr[j * 2 + 1];
        tmp8 += db4 * B_ptr[j * 2]; tmp9 += db4 * B_ptr[j * 2 + 1];
        tmp10 += db5 * B_ptr[j * 2]; tmp11 += db5 * B_ptr[j * 2 + 1];
        tmp12 += db6 * B_ptr[j * 2]; tmp13 += db6 * B_ptr[j * 2 + 1];
        tmp14 += db7 * B_ptr[j * 2]; tmp15 += db7 * B_ptr[j * 2 + 1];
      }
      C_ptr[i * 2 + 0] += tmp0; C_ptr[i * 2 + 1] += tmp1;
      C_ptr[i * 2 + 2] += tmp2; C_ptr[i * 2 + 3] += tmp3;
      C_ptr[i * 2 + 4] += tmp4; C_ptr[i * 2 + 5] += tmp5;
      C_ptr[i * 2 + 6] += tmp6; C_ptr[i * 2 + 7] += tmp7;
      C_ptr[i * 2 + 8] += tmp8; C_ptr[i * 2 + 9] += tmp9; 
      C_ptr[i * 2 + 10] += tmp10; C_ptr[i * 2 + 11] += tmp11;
      C_ptr[i * 2 + 12] += tmp12; C_ptr[i * 2 + 13] += tmp13;
      C_ptr[i * 2 + 14] += tmp14; C_ptr[i * 2 + 15] += tmp15;
    }
  } // end for(level)
}


void level_mat_mat_128(matrix_t *A, matrix_t *B, matrix128_t *out) {
  // Using restrict qualifiers to tell the compiler there is no aliasing.
  const size_t rows   = A->rows;
  const size_t cols   = A->cols;
  const size_t levels = A->levels;
  const uint64_t * __restrict A_data = A->data;
  const uint64_t * __restrict B_data = B->data;
  uint128_t * __restrict out_data = out->data;

  // We always assume B has exactly two columns (for BFV ciphertext).
  if (B->cols != 2) { return; } 

  // Pointer variables for each level.
  const uint64_t * __restrict A_ptr;
  const uint64_t * __restrict B_ptr;
  uint128_t * __restrict C_ptr;
  uint64_t db0, db1, db2, db3;
  uint128_t tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7;
  size_t i, j, lvl;

  // Process each "level" separately.
  for (lvl = 0; lvl < levels; ++lvl) {
    A_ptr = A_data + lvl * (rows * cols);
    B_ptr = B_data + lvl * (cols * 2);
    C_ptr = out_data + lvl * (rows * 2);

    // We read multiple rows of A at a time to improve cache locality.
    // The reason is that we can save reading B and C multiple times.
    for (i = 0; i < rows; i += 2) {
      tmp0 = 0; tmp1 = 0; tmp2 = 0; tmp3 = 0;
      #pragma GCC ivdep
      for (j = 0; j < cols; j++) {
        db0 = A_ptr[i * cols + j];
        db1 = A_ptr[(i + 1) * cols + j];
        // db2 = A_ptr[(i + 2) * cols + j];
        // db3 = A_ptr[(i + 3) * cols + j];
        tmp0 += db0 * (uint128_t)B_ptr[j * 2]; tmp1 += db0 * (uint128_t)B_ptr[j * 2 + 1];
        tmp2 += db1 * (uint128_t)B_ptr[j * 2]; tmp3 += db1 * (uint128_t)B_ptr[j * 2 + 1];
        // tmp4 += (uint128_t)db2 * B_ptr[j * 2]; tmp5 += (uint128_t)db2 * B_ptr[j * 2 + 1];
        // tmp6 += (uint128_t)db3 * B_ptr[j * 2]; tmp7 += (uint128_t)db3 * B_ptr[j * 2 + 1];
      }
      // Accumulate the computed values into the output.
      C_ptr[i * 2 + 0] += tmp0; C_ptr[i * 2 + 1] += tmp1;
      C_ptr[i * 2 + 2] += tmp2; C_ptr[i * 2 + 3] += tmp3;
      // C_ptr[i * 2 + 4] += tmp4; C_ptr[i * 2 + 5] += tmp5;
      // C_ptr[i * 2 + 6] += tmp6; C_ptr[i * 2 + 7] += tmp7;
    }
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


void level_mat_mat_direct_mod(matrix_t *A, matrix_t *B, matrix_t *out, const seal::Modulus mod) {
  const size_t rows = A->rows;
  const size_t cols = A->cols;
  const size_t levels = A->levels;
  const uint64_t *A_data = A->data;
  const uint64_t *B_data = B->data;
  uint64_t *out_data = out->data;

  // We always assume B has exactly two columns. Because the BFV ciphertext has two polynomials. 
  // This assumption keeps the code simple.
  if (B->cols != 2) { return; } 

  // define pointers
  const uint64_t *A_ptr;
  const uint64_t *B_ptr;
  uint64_t *C_ptr;
  uint64_t db0, db1, db2, db3;
  uint64_t b0, b1;
  uint64_t tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7;
  size_t i, j, level; 

  // For each "level," we do one standard mat-mat multiplication.
  // A(level) is m-by-n, B(level) is n-by-2, out(level) is m-by-2
  for (level = 0; level < levels; ++level) {
    // Offsets into the flat arrays for this level
    A_ptr = A_data + level * (rows * cols);
    B_ptr = B_data + level * (cols * 2);
    C_ptr = out_data + level * (rows * 2);

    // Then we can compute a normal matrix multiplication
    // This is a slight variation of the 
    for (i = 0; i < rows; i += 4) {
      tmp0 = 0; tmp1 = 0; tmp2 = 0; tmp3 = 0;
      tmp4 = 0; tmp5 = 0; tmp6 = 0; tmp7 = 0;
      for (j = 0; j < cols; j++) {
        db0 = A_ptr[i * cols + j];
        db1 = A_ptr[(i + 1) * cols + j];
        db2 = A_ptr[(i + 2) * cols + j];
        db3 = A_ptr[(i + 3) * cols + j];
        b0 = B_ptr[j * 2];
        b1 = B_ptr[j * 2 + 1];
        mult_add_mod(db0, b1, tmp0, mod);
        mult_add_mod(db0, b0, tmp1, mod);
        mult_add_mod(db1, b1, tmp2, mod);
        mult_add_mod(db1, b0, tmp3, mod);
        mult_add_mod(db2, b1, tmp4, mod);
        mult_add_mod(db2, b0, tmp5, mod);
        mult_add_mod(db3, b1, tmp6, mod);
        mult_add_mod(db3, b0, tmp7, mod);
      }
      C_ptr[i * 2] = tmp0;
      C_ptr[i * 2 + 1] = tmp1;
      C_ptr[i * 2 + 2] = tmp2;
      C_ptr[i * 2 + 3] = tmp3;
      C_ptr[i * 2 + 4] = tmp4;
      C_ptr[i * 2 + 5] = tmp5;
      C_ptr[i * 2 + 6] = tmp6;
      C_ptr[i * 2 + 7] = tmp7;
    }
  } // end for(level)
}

// ======================== COMPONENT WISE MULTIPLICATION ========================

void component_wise_mult(matrix_t *A, matrix_t *B, matrix_t *out) {
  const size_t m = A->rows; 
  const size_t n = A->cols; 
  const size_t p = B->cols; // p=2 (assumed)
  const size_t levels = A->levels;
  uint64_t *A_data = A->data;
  uint64_t *B_data = B->data;
  uint64_t *out_data = out->data;
  // Safety check (not strictly necessary, but wise):
  if (p != 2) { return; }  
  for (size_t i = 0; i < m; i++) {
    for (size_t j = 0; j < n; j++) {
      uint64_t *db_ptr = A_data + (i * n + j) * levels;
      uint64_t *q0 = B_data + j * 2 * levels;
      uint64_t *q1 = q0 + levels;
      uint64_t *out_0 = out_data + i * 2 * levels;
      uint64_t *out_1 = out_0 + levels;
      #pragma GCC unroll 32
      for (size_t level = 0; level < levels; ++level) {
        out_0[level] += db_ptr[level] * q0[level];
        out_1[level] += db_ptr[level] * q1[level];
      }
    }
  }
}


void component_wise_mult_128(matrix_t *A, matrix_t *B, matrix128_t *out) {
  const size_t m = A->rows; 
  const size_t n = A->cols; 
  const size_t p = B->cols; // p=2 (assumed)
  const size_t levels = A->levels;
  uint64_t *A_data = A->data;
  uint64_t *B_data = B->data;
  uint128_t *out_data = out->data;
  // Safety check (not strictly necessary, but wise):
  if (p != 2) { return; }  
  for (size_t i = 0; i < m; i++) {
    for (size_t j = 0; j < n; j++) {
      uint64_t *db_ptr = A_data + (i * n + j) * levels;
      uint64_t *q0 = B_data + j * 2 * levels;
      uint64_t *q1 = q0 + levels;
      uint128_t *out_0 = out_data + i * 2 * levels;
      uint128_t *out_1 = out_0 + levels;
      #pragma GCC unroll 32
      for (size_t level = 0; level < levels; ++level) {
        out_0[level] += (uint128_t)db_ptr[level] * q0[level];
        out_1[level] += (uint128_t)db_ptr[level] * q1[level];
      }
    }
  }
}


void component_wise_mult_direct_mod(matrix_t *A, matrix_t *B, uint64_t *out, const uint64_t mod) {
  const size_t m = A->rows; 
  const size_t n = A->cols; 
  const size_t p = B->cols; // p=2 (assumed)
  const size_t levels = A->levels;
  uint64_t *A_data = A->data;
  uint64_t *B_data = B->data;

  // create a temporary output array of size levels
  uint64_t *tmp_out = new uint64_t[levels];

  // Safety check (not strictly necessary, but wise):
  if (p != 2) { return; }  
  for (size_t i = 0; i < m; i++) {
    for (size_t j = 0; j < n; j++) {
      uint64_t *db_ptr = A_data + (i * n + j) * levels;
      uint64_t *q0 = B_data + j * 2 * levels;
      uint64_t *q1 = q0 + levels;
      uint64_t *out_0 = out + i * 2 * levels;
      uint64_t *out_1 = out_0 + levels;
      intel::hexl::EltwiseMultMod(tmp_out, q0, db_ptr, levels, mod, 1);
      intel::hexl::EltwiseAddMod(out_0, out_0, tmp_out, levels, mod);
      
      intel::hexl::EltwiseMultMod(tmp_out, q1, db_ptr, levels, mod, 1);
      intel::hexl::EltwiseAddMod(out_1, out_1, tmp_out, levels, mod);
    }
  }

  // free the temporary output array
  delete[] tmp_out;
}


// ======================== THIRD PARTIES ========================

void level_mat_mult_eigen(matrix_t *A, matrix_t *B, matrix_t *out) {
    const size_t rows = A->rows;   
    const size_t cols = A->cols;   
    const size_t p = B->cols;      // p=2 (assumed)
    const size_t levels = A->levels;
    const uint64_t* A_data = A->data;
    const uint64_t* B_data = B->data;
    uint64_t* out_data = out->data;

    // We always assume p=2. Because the BFV ciphertext has two polynomials.
    // This assumption keeps the code simple.
    if (p != 2 || out->cols != 2) {
        return;
    }

    // For each "level," perform one standard matrix-matrix multiplication.
    // A(level) is rows-by-cols, B(level) is cols-by-2, out(level) is rows-by-2
    for (size_t level = 0; level < levels; ++level) {
        // Map raw data to Eigen matrices
        Eigen::Map<const Eigen::Matrix<uint64_t, Eigen::Dynamic, Eigen::Dynamic, Eigen::RowMajor>> matA(
            A_data + level * (rows * cols), rows, cols);
        Eigen::Map<const Eigen::Matrix<uint64_t, Eigen::Dynamic, Eigen::Dynamic, Eigen::RowMajor>> matB(
            B_data + level * (cols * p), cols, p);
        Eigen::Map<Eigen::Matrix<uint64_t, Eigen::Dynamic, Eigen::Dynamic, Eigen::RowMajor>> matC(
            out_data + level * (rows * p), rows, p);

        // Perform matrix multiplication
        matC.noalias() = matA * matB;
    }
}


// ======================== CRAZY AVX STUFF ========================

void avx_mat_mat_mult_128(const uint64_t *__restrict A,
                          const uint64_t *__restrict B,
                          uint128_t *__restrict out, const size_t rows,
                          const size_t cols) {
    // Ensure that cols is a multiple of 8.
    
    for (size_t i = 0; i < rows; i++) {
        uint128_t acc0 = 0;  // Accumulator for first output column.
        uint128_t acc1 = 0;  // Accumulator for second output column.
        
        for (size_t k = 0; k < cols; k += 8) {
            // Load 8 consecutive 64-bit elements from row i of A.
            const uint64_t* a_ptr = A + i * cols + k;
            __m512i vecA = _mm512_loadu_si512((const __m512i*)a_ptr);
            
            // For B, assume first 'cols' elements form column 0 and the next 'cols' form column 1.
            // Load 8 elements for column 0.
            const uint64_t* b0_ptr = B + k;
            __m512i vecB0 = _mm512_loadu_si512((const __m512i*)b0_ptr);
            // Load 8 elements for column 1.
            const uint64_t* b1_ptr = B + cols + k;
            __m512i vecB1 = _mm512_loadu_si512((const __m512i*)b1_ptr);
            
            // Compute element-wise 128-bit products for the two columns.
            __m512i lo0, hi0, lo1, hi1;
            mul_64x64_128(vecA, vecB0, &lo0, &hi0);
            mul_64x64_128(vecA, vecB1, &lo1, &hi1);
            
            // Horizontally reduce the 8 lane products to a scalar 128-bit sum.
            uint128_t block_sum0 = horizontal_reduce_128(lo0, hi0);
            uint128_t block_sum1 = horizontal_reduce_128(lo1, hi1);
            
            acc0 += block_sum0;
            acc1 += block_sum1;
        }
        // Store the two 128-bit dot products for row i.
        out[i*2]     = acc0;
        out[i*2 + 1] = acc1;
    }
}
