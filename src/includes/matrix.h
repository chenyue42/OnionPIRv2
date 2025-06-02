#pragma once
// #include "seal/seal.h"
#include "utils.h"
#include <stdint.h>
#include <stddef.h>

#if defined(__AVX512F__)
    #include <immintrin.h>
#elif defined(__AVX2__)
    #include <immintrin.h>
#endif

// define a structure for a matrix
typedef struct {
    uint64_t *data;
    size_t rows;
    size_t cols;
    size_t levels;
} matrix_t; 

typedef struct {
    uint128_t *data;
    size_t rows;
    size_t cols;
    size_t levels;
} matrix128_t; 


// ! mat_vec functions means matrix-vector multiplication. 
// It is used for testing the performance of each method. Otherwise,
// we are doing out = A * B, where A = m * n, B = n * 2, n = DatabaseConstants::MaxFstDimSz

// ======================== NAIVE STUFF ========================
void naive_mat_vec(matrix_t *A, matrix_t *B, matrix_t *out);
void naive_mat_vec_128(matrix_t *A, matrix_t *B, matrix128_t *out);
void naive_level_mat_mat(matrix_t *A, matrix_t *B, matrix_t *out);
void naive_level_mat_mat_128(matrix_t *A, matrix_t *B, matrix128_t *out);

// ======================== LEVEL MAT MAT ========================
// performing coeff_val_cnt many matrix matrix multiplications. Assumes that the B matrix has only two columns.
void level_mat_mat(matrix_t *A, matrix_t *B, matrix_t *out);

// suitable for the first dimension. The output is in uint128_t.
void level_mat_mat_128(matrix_t *A, matrix_t *B, matrix128_t *out);

// A single matrix * matrix multiplication, assuming second matrix has only two
// columns. This is a helper for level_mat_mult_128.
void mat_mat_128(const uint64_t *__restrict A, const uint64_t *__restrict B,
                 uint128_t *__restrict out, const size_t rows,
                 const size_t cols);

// calculate mod after each multiplication. Hence, output will be in uint64_t.
void level_mat_mat_direct_mod(matrix_t *A, matrix_t *B, matrix_t *out, const seal::Modulus mod);


// ======================== COMPONENT WISE MULTIPLICATION ========================

// These are examples of component wise multiplication. This demonstrates the
// first dimension multiplication of OnionPIRv1.
// In v1, we think of the database as a matrix of polynomials, where each NTT
// polynomial is stored in a vector. Then, the first dimension is doing a
// matrix-matrix multiplication where each element is a vector, and the
// multiplication is defined by component wise multiplication of the vectors.
// Hence, multiplying one "row" of database and one "column" of query is
// equivalent as doing 2*N*degree many component wise multiplications, where N
// is the first dimension size, say 256.
// ? The question is: will the entire query vector of vectors stay in the cache
// when we scan the second "row" of the database?
// Short answer: No. Bad locality.

// Perform the Matrix Multiplication over a direct product over component wise vector multiplication.
void component_wise_mult(matrix_t *A, matrix_t *B, matrix_t *out);
void component_wise_mult_128(matrix_t *A, matrix_t *B, matrix128_t *out);
#if defined(__AVX512F__)
// This is using intel::hexl::EltwiseMultMod for each component wise multiplication.
void component_wise_mult_direct_mod(matrix_t *A, matrix_t *B, uint64_t *out, const uint64_t mod);
#endif

// ======================== THIRD PARTIES ========================
// Currently, I don't know any libraries that can do 64x64->128 multiplication.
// Here we use 64*64->64 multiplications as the easier alternative.
// If you want a cleaner code, maybe you can write a genearal level_mat_mult
// wrapper, then pass the function pointer to the actual implementation.
// I am being lazy here...

#ifdef HAVE_EIGEN
void level_mat_mult_eigen(matrix_t *A, matrix_t *B, matrix_t *out);
#endif

// ======================== HELPER FUNCTIONS ========================
// calculates c = c + a * b mod m using Barrett reduction
inline void mult_add_mod(uint64_t &a, uint64_t &b, uint64_t &c, const seal::Modulus &m) {
    uint128_t tmp = (uint128_t)a * b + c;
    uint64_t raw[2] = {static_cast<uint64_t>(tmp), static_cast<uint64_t>(tmp >> 64)};
    c = util::barrett_reduce_128(raw, m);
}


#if defined(__AVX512F__)
// ======================== CRAZY AVX STUFF ========================
// ! I asked gpt to generate these AVX codes. I have no idea what they do.
// ! I only observed that they are very slow, slower than the naive implementation.
//------------------------------------------------------------------------------
// Helper: Multiply two 64-bit unsigned integers (each lane of a __m512i)
// to produce a full 128-bit product represented as two 64-bit parts (low and high).
// This routine uses the standard “schoolbook” algorithm by splitting each 64-bit integer
// into two 32-bit halves.
static inline void mul_64x64_128(__m512i a, __m512i b, __m512i* lo, __m512i* hi) {
    // Define mask = 0xFFFFFFFF (to extract lower 32 bits)
    __m512i mask = _mm512_set1_epi64(0xFFFFFFFFULL);
    // Split each 64-bit number into lower and higher 32 bits.
    __m512i a_lo = _mm512_and_si512(a, mask);
    __m512i a_hi = _mm512_srli_epi64(a, 32);
    __m512i b_lo = _mm512_and_si512(b, mask);
    __m512i b_hi = _mm512_srli_epi64(b, 32);
    
    // Compute partial products.
    // p0 = a_lo * b_lo
    __m512i p0 = _mm512_mul_epu32(a, b);         // multiplies the lower 32 bits of each 64-bit lane.
    // p1 = a_lo * b_hi
    __m512i p1 = _mm512_mul_epu32(a, b_hi);
    // p2 = a_hi * b_lo
    __m512i p2 = _mm512_mul_epu32(a_hi, b);
    // p3 = a_hi * b_hi
    __m512i p3 = _mm512_mul_epu32(a_hi, b_hi);
    
    // Sum the cross terms.
    __m512i mid = _mm512_add_epi64(p1, p2);
    
    // Lower 64 bits: p0 + (mid << 32) (mod 2^64).
    __m512i mid_lo = _mm512_slli_epi64(mid, 32);
    __m512i lower = _mm512_add_epi64(p0, mid_lo);
    
    // Determine carry from lower addition.
    // If lower < p0 then a carry occurred.
    __mmask8 carry_mask = _mm512_cmplt_epu64_mask(lower, p0);
    __m512i carry = _mm512_mask_set1_epi64(_mm512_setzero_si512(), carry_mask, 1);
    
    // Higher 64 bits: p3 + (mid >> 32) + carry.
    __m512i mid_hi = _mm512_srli_epi64(mid, 32);
    __m512i higher = _mm512_add_epi64(p3, _mm512_add_epi64(mid_hi, carry));
    
    *lo = lower;
    *hi = higher;
}
#endif


#if defined(__AVX512F__)
//------------------------------------------------------------------------------
// Horizontal reduction: given two __m512i vectors representing the low and high parts of
// eight 128-bit values, reduce them to a single uint128_t sum.
static inline uint128_t horizontal_reduce_128(__m512i lo, __m512i hi) {
    alignas(64) uint64_t arr_lo[8];
    alignas(64) uint64_t arr_hi[8];
    _mm512_store_si512((__m512i*)arr_lo, lo);
    _mm512_store_si512((__m512i*)arr_hi, hi);
    uint128_t sum = 0;
    for (int i = 0; i < 8; i++) {
        uint128_t prod = (((uint128_t)arr_hi[i]) << 64) | arr_lo[i];
        sum += prod;
    }
    return sum;
}
#endif

#if defined(__AVX512F__)
//------------------------------------------------------------------------------
// Function: avx_mat_mat_mult_128
//
// Multiply matrix A (dimensions: rows x cols) by matrix B (dimensions: cols x 2)
// and store the two resulting 128-bit dot products per row into the output array 'out'.
// We assume that:
//   - A is stored in row-major order (length = rows*cols)
//   - B is stored with two contiguous columns: the first 'cols' elements are column 0,
//     and the next 'cols' elements are column 1.
//   - 'cols' is a multiple of 8 (so that we can process 8 elements per inner-loop iteration).
void avx_mat_mat_mult_128(const uint64_t *__restrict A,
                          const uint64_t *__restrict B,
                          uint128_t *__restrict out, const size_t rows,
                          const size_t cols);
#endif