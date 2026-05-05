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

#if defined(__AVX512F__)
  // Fast path: db_coeff_t = uint32_t and inter_coeff_t = uint64_t (i.e.
  // max_ct_mod_width() ≤ 32, which is the K=2 / 28-29-bit-prime regime).
  // Inputs are NTT outputs, already reduced mod q, so the AVX-512 safe path's
  // precondition holds. Per-lane bound: ⌈n/16⌉ · q² < 2⁶⁴ requires
  //   max_ct_mod_width() · 2 + log2(⌈n/16⌉) < 64
  // which holds for the configs we ship (29-bit primes, n ≤ 1024).
  if constexpr (std::is_same_v<db_coeff_t, uint32_t> &&
                std::is_same_v<inter_coeff_t, uint64_t>) {
    // Per-lane bound: ⌈n/16⌉ · (q-1)² < 2⁶⁴. With q < 2^width, conservative
    // sufficient condition is ⌈n/16⌉ · 2^(2·width) ≤ 2⁶⁴, i.e.
    //   n ≤ 16 · 2^(64 - 2·width)
    // For width=29 → n ≤ 1024. For width=28 → n ≤ 4096. Falls back to the
    // scalar path if n exceeds the bound (defensive — current configs don't).
    constexpr size_t W = DBConsts::max_ct_mod_width();
    constexpr size_t avx_n_bound = (W * 2 < 64) ? (size_t(16) << (64 - 2 * W)) : 0;
    if (n <= avx_n_bound) {
      level_mat_mat_avx512_safe(reinterpret_cast<const uint32_t*>(A->data),
                                reinterpret_cast<const uint32_t*>(B->data),
                                reinterpret_cast<uint64_t*>(out->data),
                                m, n, levels, level_qs);
      return;
    }
  }
#endif

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

// Same shape as mat_mat but with a wide uint128 accumulator and a single
// reduction per output column (no chunked mid-loop reduction). Inputs are
// loaded as uint64; accumulator is uint128 so it can hold n·q² without
// overflow for any (q, n) we use here. Useful for isolating the cost of
// the chunked path's mid-loop `% q`.
void mat_mat_nochunk(const db_coeff_t *__restrict A,
                     const db_coeff_t *__restrict B,
                     inter_coeff_t *__restrict out, const size_t rows,
                     const size_t cols, const uint64_t q) {
  const uint128_t qi = static_cast<uint128_t>(q);
  for (size_t i = 0; i < rows; ++i) {
    const size_t offset = i * cols;
    uint128_t t0 = 0, t1 = 0;
    #pragma GCC unroll 32
    for (size_t k = 0; k < cols; ++k) {
      const uint128_t a = A[offset + k];
      t0 += a * B[2 * k];
      t1 += a * B[2 * k + 1];
    }
    out[2 * i]     = static_cast<inter_coeff_t>(q ? (t0 % qi) : t0);
    out[2 * i + 1] = static_cast<inter_coeff_t>(q ? (t1 % qi) : t1);
  }
}

void level_mat_mat_nochunk(db_matrix_t *A, db_matrix_t *B, inter_matrix_t *out,
                           const uint64_t *level_qs) {
  const size_t m = A->rows;
  const size_t n = A->cols;
  const size_t levels = A->levels;
  for (size_t level = 0; level < levels; ++level) {
    const db_coeff_t *A_ptr = A->data + level * (m * n);
    const db_coeff_t *B_ptr = B->data + level * (n * 2);
    inter_coeff_t *C_ptr = out->data + level * (m * 2);
    mat_mat_nochunk(A_ptr, B_ptr, C_ptr, m, n, level_qs[level]);
  }
}

// Diagnostic: uint64 accumulator, no chunking, single reduction at the end.
// Will WRAP on overflow when n·q² > 2^64 (e.g. K=2 with n=512, q=2^29 hits
// ~2^67) — output values are NOT correct mod q in that case. Only meaningful
// for measuring the upper bound on throughput when the accumulator stays in
// uint64. q == 0 disables the final reduction.
void mat_mat_nochunk_u64(const uint32_t *__restrict A,
                         const uint32_t *__restrict B,
                         uint64_t *__restrict out, const size_t rows,
                         const size_t cols, const uint64_t q) {
  for (size_t i = 0; i < rows; ++i) {
    const size_t offset = i * cols;
    uint64_t t0 = 0, t1 = 0;
    #pragma GCC unroll 32
    for (size_t k = 0; k < cols; ++k) {
      const uint64_t a = A[offset + k];
      t0 += a * B[2 * k];
      t1 += a * B[2 * k + 1];
    }
    out[2 * i]     = q ? (t0 % q) : t0;
    out[2 * i + 1] = q ? (t1 % q) : t1;
  }
}

void level_mat_mat_nochunk_u64(const uint32_t *A_data, const uint32_t *B_data,
                               uint64_t *out_data, size_t m, size_t n,
                               size_t levels, const uint64_t *level_qs) {
  for (size_t level = 0; level < levels; ++level) {
    const uint32_t *A_ptr = A_data + level * (m * n);
    const uint32_t *B_ptr = B_data + level * (n * 2);
    uint64_t       *C_ptr = out_data + level * (m * 2);
    mat_mat_nochunk_u64(A_ptr, B_ptr, C_ptr, m, n, level_qs[level]);
  }
}

// 32->64, B already deinterleaved into B0 (col 0) and B1 (col 1) — gives the
// auto-vectorizer a contiguous load pattern. WRAPS like mat_mat_nochunk_u64.
static inline void mat_mat_split_b_u64(const uint32_t *__restrict A,
                                       const uint32_t *__restrict B0,
                                       const uint32_t *__restrict B1,
                                       uint64_t *__restrict out,
                                       const size_t rows, const size_t cols,
                                       const uint64_t q) {
  for (size_t i = 0; i < rows; ++i) {
    const uint32_t *Ar = A + i * cols;
    uint64_t t0 = 0, t1 = 0;
    #pragma GCC ivdep
    for (size_t k = 0; k < cols; ++k) {
      const uint64_t a = Ar[k];
      t0 += a * B0[k];
      t1 += a * B1[k];
    }
    out[2 * i]     = q ? (t0 % q) : t0;
    out[2 * i + 1] = q ? (t1 % q) : t1;
  }
}

void level_mat_mat_split_b_u64(const uint32_t *A_data, const uint32_t *B_data,
                               uint64_t *out_data, size_t m, size_t n,
                               size_t levels, const uint64_t *level_qs) {
  // Per-level scratch for deinterleaved B. Cheap relative to the matmul:
  // 2·n bytes per level vs m·n·4 bytes of A read.
  std::vector<uint32_t> B0(n), B1(n);
  for (size_t level = 0; level < levels; ++level) {
    const uint32_t *B_ptr = B_data + level * (n * 2);
    for (size_t k = 0; k < n; ++k) { B0[k] = B_ptr[2*k]; B1[k] = B_ptr[2*k+1]; }
    const uint32_t *A_ptr = A_data + level * (m * n);
    uint64_t       *C_ptr = out_data + level * (m * 2);
    mat_mat_split_b_u64(A_ptr, B0.data(), B1.data(), C_ptr, m, n, levels ? level_qs[level] : 0);
  }
}

#if defined(__AVX512F__)
#include <immintrin.h>

// Explicit AVX-512 32->64. Same layout assumption as mat_mat_split_b_u64
// (B already deinterleaved into B0 and B1). Inner loop processes 16 k's per
// iteration: two vpmuludq's per output column to cover all 16 lanes (one on
// the original vectors hits even-indexed 32-bit lanes, one after a 32-bit
// shift hits odd-indexed lanes). Two uint64 accumulators per column.
// WRAPS on overflow, like the other nochunk_u64 variants.
static inline uint64_t hsum_epi64(__m512i v) {
  alignas(64) uint64_t buf[8];
  _mm512_store_si512((__m512i*)buf, v);
  uint64_t s = 0;
  for (int i = 0; i < 8; ++i) s += buf[i];
  return s;
}

static inline void mat_mat_avx512_u64(const uint32_t *__restrict A,
                                      const uint32_t *__restrict B0,
                                      const uint32_t *__restrict B1,
                                      uint64_t *__restrict out,
                                      const size_t rows, const size_t cols,
                                      const uint64_t q) {
  const size_t simd_end = cols & ~size_t(15);
  for (size_t i = 0; i < rows; ++i) {
    const uint32_t *Ar = A + i * cols;
    __m512i acc0_e = _mm512_setzero_si512();
    __m512i acc0_o = _mm512_setzero_si512();
    __m512i acc1_e = _mm512_setzero_si512();
    __m512i acc1_o = _mm512_setzero_si512();
    for (size_t k = 0; k < simd_end; k += 16) {
      __m512i a  = _mm512_loadu_si512((const __m512i*)(Ar + k));
      __m512i b0 = _mm512_loadu_si512((const __m512i*)(B0 + k));
      __m512i b1 = _mm512_loadu_si512((const __m512i*)(B1 + k));
      __m512i a_hi  = _mm512_srli_epi64(a, 32);
      __m512i b0_hi = _mm512_srli_epi64(b0, 32);
      __m512i b1_hi = _mm512_srli_epi64(b1, 32);
      acc0_e = _mm512_add_epi64(acc0_e, _mm512_mul_epu32(a, b0));
      acc0_o = _mm512_add_epi64(acc0_o, _mm512_mul_epu32(a_hi, b0_hi));
      acc1_e = _mm512_add_epi64(acc1_e, _mm512_mul_epu32(a, b1));
      acc1_o = _mm512_add_epi64(acc1_o, _mm512_mul_epu32(a_hi, b1_hi));
    }
    uint64_t t0 = hsum_epi64(_mm512_add_epi64(acc0_e, acc0_o));
    uint64_t t1 = hsum_epi64(_mm512_add_epi64(acc1_e, acc1_o));
    for (size_t k = simd_end; k < cols; ++k) {
      const uint64_t a = Ar[k];
      t0 += a * B0[k];
      t1 += a * B1[k];
    }
    out[2 * i]     = q ? (t0 % q) : t0;
    out[2 * i + 1] = q ? (t1 % q) : t1;
  }
}

void level_mat_mat_avx512_u64(const uint32_t *A_data, const uint32_t *B_data,
                              uint64_t *out_data, size_t m, size_t n,
                              size_t levels, const uint64_t *level_qs) {
  std::vector<uint32_t> B0(n), B1(n);
  for (size_t level = 0; level < levels; ++level) {
    const uint32_t *B_ptr = B_data + level * (n * 2);
    for (size_t k = 0; k < n; ++k) { B0[k] = B_ptr[2*k]; B1[k] = B_ptr[2*k+1]; }
    const uint32_t *A_ptr = A_data + level * (m * n);
    uint64_t       *C_ptr = out_data + level * (m * 2);
    mat_mat_avx512_u64(A_ptr, B0.data(), B1.data(), C_ptr, m, n, level_qs[level]);
  }
}
// CORRECT AVX-512 32->64 path (assumes inputs reduced mod q).
// Per-lane accumulator stays in uint64: each of 16 lanes sees ≤ ⌈n/16⌉
// products of magnitude < q², so we need ⌈n/16⌉ · q² < 2⁶⁴. For q < 2³⁰ and
// n ≤ 1024 (our PIR shapes) this gives lane-sum < 2⁶³.
// The 16-lane horizontal sum can still reach n·q² > 2⁶⁴, so we widen to
// uint128 only for the final reduce — one uint128 mod per output element.
static inline uint64_t hsum_to_u128_mod(__m512i v, uint64_t q) {
  alignas(64) uint64_t buf[8];
  _mm512_store_si512((__m512i*)buf, v);
  uint128_t s = 0;
  for (int i = 0; i < 8; ++i) s += buf[i];
  return static_cast<uint64_t>(s % static_cast<uint128_t>(q));
}

static inline void mat_mat_avx512_safe(const uint32_t *__restrict A,
                                       const uint32_t *__restrict B0,
                                       const uint32_t *__restrict B1,
                                       uint64_t *__restrict out,
                                       const size_t rows, const size_t cols,
                                       const uint64_t q) {
  const size_t simd_end = cols & ~size_t(15);
  for (size_t i = 0; i < rows; ++i) {
    const uint32_t *Ar = A + i * cols;
    __m512i acc0_e = _mm512_setzero_si512();
    __m512i acc0_o = _mm512_setzero_si512();
    __m512i acc1_e = _mm512_setzero_si512();
    __m512i acc1_o = _mm512_setzero_si512();
    for (size_t k = 0; k < simd_end; k += 16) {
      __m512i a  = _mm512_loadu_si512((const __m512i*)(Ar + k));
      __m512i b0 = _mm512_loadu_si512((const __m512i*)(B0 + k));
      __m512i b1 = _mm512_loadu_si512((const __m512i*)(B1 + k));
      __m512i a_hi  = _mm512_srli_epi64(a, 32);
      __m512i b0_hi = _mm512_srli_epi64(b0, 32);
      __m512i b1_hi = _mm512_srli_epi64(b1, 32);
      acc0_e = _mm512_add_epi64(acc0_e, _mm512_mul_epu32(a, b0));
      acc0_o = _mm512_add_epi64(acc0_o, _mm512_mul_epu32(a_hi, b0_hi));
      acc1_e = _mm512_add_epi64(acc1_e, _mm512_mul_epu32(a, b1));
      acc1_o = _mm512_add_epi64(acc1_o, _mm512_mul_epu32(a_hi, b1_hi));
    }
    // Combine even/odd then horizontally reduce via uint128 + mod q.
    uint64_t t0 = hsum_to_u128_mod(_mm512_add_epi64(acc0_e, acc0_o), q);
    uint64_t t1 = hsum_to_u128_mod(_mm512_add_epi64(acc1_e, acc1_o), q);
    // Tail (if cols % 16 != 0).
    for (size_t k = simd_end; k < cols; ++k) {
      const uint128_t a = Ar[k];
      t0 = static_cast<uint64_t>((t0 + a * B0[k]) % q);
      t1 = static_cast<uint64_t>((t1 + a * B1[k]) % q);
    }
    out[2 * i]     = t0;
    out[2 * i + 1] = t1;
  }
}

void level_mat_mat_avx512_safe(const uint32_t *A_data, const uint32_t *B_data,
                               uint64_t *out_data, size_t m, size_t n,
                               size_t levels, const uint64_t *level_qs) {
  std::vector<uint32_t> B0(n), B1(n);
  for (size_t level = 0; level < levels; ++level) {
    const uint32_t *B_ptr = B_data + level * (n * 2);
    for (size_t k = 0; k < n; ++k) { B0[k] = B_ptr[2*k]; B1[k] = B_ptr[2*k+1]; }
    const uint32_t *A_ptr = A_data + level * (m * n);
    uint64_t       *C_ptr = out_data + level * (m * 2);
    mat_mat_avx512_safe(A_ptr, B0.data(), B1.data(), C_ptr, m, n, level_qs[level]);
  }
}

#endif // __AVX512F__

// mat-vec analogue of mat_mat_avx512_safe: B has a single column. Compute is
// half (one vpmuludq pair per iteration instead of two), but memory traffic
// for A is identical — so if we're memory-bound on A this should match the
// mat-mat throughput.
#if defined(__AVX512F__)
static inline void mat_vec_avx512_safe(const uint32_t *__restrict A,
                                       const uint32_t *__restrict B,
                                       uint64_t *__restrict out,
                                       const size_t rows, const size_t cols,
                                       const uint64_t q) {
  const size_t simd_end = cols & ~size_t(15);
  for (size_t i = 0; i < rows; ++i) {
    const uint32_t *Ar = A + i * cols;
    __m512i acc_e = _mm512_setzero_si512();
    __m512i acc_o = _mm512_setzero_si512();
    for (size_t k = 0; k < simd_end; k += 16) {
      __m512i a = _mm512_loadu_si512((const __m512i*)(Ar + k));
      __m512i b = _mm512_loadu_si512((const __m512i*)(B + k));
      __m512i a_hi = _mm512_srli_epi64(a, 32);
      __m512i b_hi = _mm512_srli_epi64(b, 32);
      acc_e = _mm512_add_epi64(acc_e, _mm512_mul_epu32(a, b));
      acc_o = _mm512_add_epi64(acc_o, _mm512_mul_epu32(a_hi, b_hi));
    }
    uint64_t t = hsum_to_u128_mod(_mm512_add_epi64(acc_e, acc_o), q);
    for (size_t k = simd_end; k < cols; ++k) {
      const uint128_t a = Ar[k];
      t = static_cast<uint64_t>((t + a * B[k]) % q);
    }
    out[i] = t;
  }
}

void level_mat_vec_avx512_safe(const uint32_t *A_data, const uint32_t *B_data,
                               uint64_t *out_data, size_t m, size_t n,
                               size_t levels, const uint64_t *level_qs) {
  for (size_t level = 0; level < levels; ++level) {
    const uint32_t *A_ptr = A_data + level * (m * n);
    const uint32_t *B_ptr = B_data + level * n;          // n × 1
    uint64_t       *C_ptr = out_data + level * m;        // m × 1
    mat_vec_avx512_safe(A_ptr, B_ptr, C_ptr, m, n, level_qs[level]);
  }
}
#endif

// Pure A-stream baseline: same access pattern as the matmul (read each
// A[level][i][k]) but no multiplies and no B/output writes. Measures the
// single-thread memory-read ceiling for this exact data layout. The XOR
// reduction prevents the compiler from optimizing the loop away.
uint32_t level_mat_mat_stream_only(const uint32_t *A_data, size_t m,
                                   size_t n, size_t levels) {
  uint32_t sink = 0;
  for (size_t level = 0; level < levels; ++level) {
    const uint32_t *A_ptr = A_data + level * (m * n);
    for (size_t i = 0; i < m; ++i) {
      const uint32_t *Ar = A_ptr + i * n;
      uint32_t s = 0;
      for (size_t k = 0; k < n; ++k) s ^= Ar[k];
      sink ^= s;
    }
  }
  return sink;
}
