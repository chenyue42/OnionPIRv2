#include "tests.h"
#include <algorithm>

void PirTest::test_fst_dim_mult() {
  print_func_name(__FUNCTION__);
  CLEAN_TIMER();
  // Stress test against a mod-q reference. Inputs are full-width random values
  // in [0, q), and ref_n is large enough that the chunked accumulator must
  // reduce mid-loop. This is the shape that exposed the uint128 overflow at
  // fst_dim_sz ≈ 1000 with q ~ 2^60.
  constexpr size_t ref_m = 4;
  constexpr size_t ref_n = 1024;
  constexpr size_t ref_p = 2;
  constexpr size_t ref_levels = 3;
  PirParams ref_params;
  const auto &ref_qs_arr = ref_params.get_rns_mods();
  const uint64_t ref_q = ref_qs_arr[0];
  std::vector<uint64_t> ref_level_qs(ref_levels, ref_q);

  std::mt19937_64 ref_rng(0xC0FFEEULL);
  std::vector<db_coeff_t> A_ref(ref_m * ref_n * ref_levels);
  std::vector<db_coeff_t> B_ref(ref_n * ref_p * ref_levels);
  std::vector<inter_coeff_t> C_ref(ref_m * ref_p * ref_levels, 0);
  std::vector<inter_coeff_t> C_got(ref_m * ref_p * ref_levels, 0);

  for (size_t i = 0; i < A_ref.size(); ++i)
    A_ref[i] = static_cast<db_coeff_t>(ref_rng() % ref_q);
  for (size_t i = 0; i < B_ref.size(); ++i)
    B_ref[i] = static_cast<db_coeff_t>(ref_rng() % ref_q);

  db_matrix_t A_ref_mat{A_ref.data(), ref_m, ref_n, ref_levels};
  db_matrix_t B_ref_mat{B_ref.data(), ref_n, ref_p, ref_levels};
  inter_matrix_t C_got_mat{C_got.data(), ref_m, ref_p, ref_levels};
  level_mat_mat(&A_ref_mat, &B_ref_mat, &C_got_mat, ref_level_qs.data());

  const inter_coeff_t ref_qi = static_cast<inter_coeff_t>(ref_q);
  for (size_t level = 0; level < ref_levels; ++level) {
    const size_t a_off = level * ref_m * ref_n;
    const size_t b_off = level * ref_n * ref_p;
    const size_t c_off = level * ref_m * ref_p;
    for (size_t i = 0; i < ref_m; ++i) {
      inter_coeff_t t0 = 0, t1 = 0;
      for (size_t k = 0; k < ref_n; ++k) {
        const inter_coeff_t a = A_ref[a_off + i * ref_n + k];
        t0 = (t0 + a * B_ref[b_off + 2 * k]) % ref_qi;
        t1 = (t1 + a * B_ref[b_off + 2 * k + 1]) % ref_qi;
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
  BENCH_PRINT("Correctness check: PASS (full-q random, n=" << ref_n << ", q=" << ref_q << ")");

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

  // Per-level moduli matching the active PIR params: limb (lvl / N) for each level.
  const auto &qs_arr = pir_params.get_rns_mods();
  const size_t N_test = DBConsts::PolyDegree;
  std::vector<uint64_t> level_qs(levels);
  for (size_t lvl = 0; lvl < levels; ++lvl)
    level_qs[lvl] = qs_arr[(lvl / N_test) % qs_arr.size()];

  // First chunk: the production level_mat_mat. db_coeff_t / inter_coeff_t are
  // chosen at compile time from max_ct_mod_width() — uint32→uint64 for the
  // K=2 (29-bit) cell, uint64→uint128 for the K=1 (60-bit) cell.
  constexpr size_t INTER_BITS = sizeof(inter_coeff_t) * 8;
  const std::string MAT_MULT_128 = "level mat mat (build inter_coeff_t)";
  TIME_START(MAT_MULT_128);
  level_mat_mat(&A_mat, &B_mat, &C_mat, level_qs.data());
  TIME_END(MAT_MULT_128);

  // No-chunk variant: uint128 accumulator, single reduction per column.
  // Isolates the cost of the chunked path's mid-loop `% q`.
  std::vector<inter_coeff_t> C_data_nc(m * p * levels, 0);
  inter_matrix_t C_mat_nc{C_data_nc.data(), m, p, levels};
  const std::string MAT_MULT_NC = "level mat mat nochunk";
  TIME_START(MAT_MULT_NC);
  level_mat_mat_nochunk(&A_mat, &B_mat, &C_mat_nc, level_qs.data());
  TIME_END(MAT_MULT_NC);
  inter_coeff_t checksum_nc = 0;
  for (size_t i = 0; i < C_data_nc.size(); ++i) checksum_nc += C_data_nc[i];
  BENCH_PRINT("Checksum (nochunk): " << utils::uint128_to_string(checksum_nc));

  inter_coeff_t checksum = 0;
  for (size_t i = 0; i < C_data.size(); ++i) {
    checksum += C_data[i];
  }
  BENCH_PRINT("Checksum: " << utils::uint128_to_string(checksum));

  // ============================================================================
  // 32->64 chunk: same shape, but force uint32_t inputs and uint64_t accumulator.
  // Models the K=2 / 29-bit-prime regime where each limb's coefficients fit in
  // 32 bits, so the per-level matmul can stay in 64-bit arithmetic and skip
  // uint128 entirely. Reported alongside the 128-bit number above so the
  // throughput gap is directly visible from a single PIR-shape run.
  // Only meaningful when max_ct_mod_width() <= 32 (otherwise inputs would not
  // fit in uint32_t); we still execute it but check the modulus at runtime.
  // ============================================================================
  const std::string MAT_MULT_64 = "level mat mat 64 bits";
  const uint64_t max_q_test = *std::max_element(qs_arr.begin(), qs_arr.end());
  const bool can_run_32to64 = max_q_test < (uint64_t(1) << 32);
  std::vector<uint64_t> C64;
  std::vector<uint32_t> A32, B32;
  size_t db64 = 0;
  if (can_run_32to64) {
    A32.resize(m * n * levels);
    B32.resize(n * p * levels);
    C64.assign(m * p * levels, 0);
    for (size_t i = 0; i < A32.size(); ++i) A32[i] = static_cast<uint32_t>(rand());
    for (size_t i = 0; i < B32.size(); ++i) B32[i] = static_cast<uint32_t>(rand());
    db64 = m * n * levels * sizeof(uint32_t);

    // Per-level chunk so the running 64-bit accumulator never overflows.
    auto pick_chunk_64 = [](uint64_t q, size_t cols) -> size_t {
      if (q == 0) return cols;
      const uint64_t MAX_ACC = ~uint64_t(0);
      const uint64_t q2 = q * q;        // safe: q < 2^32 ⇒ q² < 2^64
      const uint64_t r  = (MAX_ACC - q) / q2;
      if (r == 0) return 1;
      return r >= cols ? cols : static_cast<size_t>(r);
    };

    TIME_START(MAT_MULT_64);
    for (size_t level = 0; level < levels; ++level) {
      const uint32_t *A_ptr = A32.data() + level * (m * n);
      const uint32_t *B_ptr = B32.data() + level * (n * p);
      uint64_t       *C_ptr = C64.data() + level * (m * p);
      const uint64_t q = level_qs[level];
      const size_t   chunk = pick_chunk_64(q, n);

      if (chunk >= n) {
        for (size_t i = 0; i < m; ++i) {
          uint64_t t0 = 0, t1 = 0;
          const size_t offset = i * n;
          #pragma GCC unroll 32
          for (size_t k = 0; k < n; ++k) {
            t0 += static_cast<uint64_t>(A_ptr[offset + k]) * B_ptr[2 * k];
            t1 += static_cast<uint64_t>(A_ptr[offset + k]) * B_ptr[2 * k + 1];
          }
          C_ptr[2 * i]     = t0;
          C_ptr[2 * i + 1] = t1;
        }
      } else {
        for (size_t i = 0; i < m; ++i) {
          const size_t offset = i * n;
          uint64_t acc0 = 0, acc1 = 0;
          for (size_t base = 0; base < n; base += chunk) {
            const size_t end = std::min(base + chunk, n);
            uint64_t t0 = 0, t1 = 0;
            #pragma GCC unroll 16
            for (size_t k = base; k < end; ++k) {
              t0 += static_cast<uint64_t>(A_ptr[offset + k]) * B_ptr[2 * k];
              t1 += static_cast<uint64_t>(A_ptr[offset + k]) * B_ptr[2 * k + 1];
            }
            acc0 = (acc0 + t0) % q;
            acc1 = (acc1 + t1) % q;
          }
          C_ptr[2 * i]     = acc0;
          C_ptr[2 * i + 1] = acc1;
        }
      }
    }
    TIME_END(MAT_MULT_64);

    uint64_t checksum64 = 0;
    for (size_t i = 0; i < C64.size(); ++i) checksum64 += C64[i];
    BENCH_PRINT("Checksum (32->64): " << checksum64);
  }

  // 32->64 with NO chunking. uint64 accumulator overflows when n·q² > 2^64
  // (true here for K=2 with n=512, q≈2^29). Output is wrong mod q; we only
  // care about the timing — establishes the upper bound for "stay in uint64,
  // skip all mid-loop reductions".
  const std::string MAT_MULT_64_NC    = "level mat mat 32->64 nochunk";
  const std::string MAT_MULT_64_SPLIT = "level mat mat 32->64 split_b";
  const std::string MAT_MULT_64_AVX   = "level mat mat 32->64 avx512";
  std::vector<uint64_t> C64_nc, C64_sp, C64_avx;
  if (can_run_32to64) {
    C64_nc.assign(m * p * levels, 0);
    TIME_START(MAT_MULT_64_NC);
    level_mat_mat_nochunk_u64(A32.data(), B32.data(), C64_nc.data(),
                              m, n, levels, level_qs.data());
    TIME_END(MAT_MULT_64_NC);
    uint64_t checksum64_nc = 0;
    for (size_t i = 0; i < C64_nc.size(); ++i) checksum64_nc += C64_nc[i];
    BENCH_PRINT("Checksum (32->64 nochunk, may wrap): " << checksum64_nc);

    // Pure A-stream ceiling.
    const std::string MAT_MULT_STREAM = "level mat mat stream only";
    TIME_START(MAT_MULT_STREAM);
    volatile uint32_t sink = level_mat_mat_stream_only(A32.data(), m, n, levels);
    (void)sink;
    TIME_END(MAT_MULT_STREAM);

    C64_sp.assign(m * p * levels, 0);
    TIME_START(MAT_MULT_64_SPLIT);
    level_mat_mat_split_b_u64(A32.data(), B32.data(), C64_sp.data(),
                              m, n, levels, level_qs.data());
    TIME_END(MAT_MULT_64_SPLIT);
    uint64_t checksum64_sp = 0;
    for (size_t i = 0; i < C64_sp.size(); ++i) checksum64_sp += C64_sp[i];
    BENCH_PRINT("Checksum (32->64 split_b, may wrap): " << checksum64_sp);

#if defined(__AVX512F__)
    C64_avx.assign(m * p * levels, 0);
    TIME_START(MAT_MULT_64_AVX);
    level_mat_mat_avx512_u64(A32.data(), B32.data(), C64_avx.data(),
                             m, n, levels, level_qs.data());
    TIME_END(MAT_MULT_64_AVX);
    uint64_t checksum64_avx = 0;
    for (size_t i = 0; i < C64_avx.size(); ++i) checksum64_avx += C64_avx[i];
    BENCH_PRINT("Checksum (32->64 avx512,  may wrap): " << checksum64_avx);

    // Correct AVX-512: inputs must be < q. Reduce A32/B32 once and rerun;
    // compare against the scalar 32->64 chunked output (also using reduced
    // inputs for a fair check).
    std::vector<uint32_t> A32r(A32.size()), B32r(B32.size());
    for (size_t lvl = 0; lvl < levels; ++lvl) {
      const uint64_t qq = level_qs[lvl];
      const uint32_t *Ain = A32.data() + lvl * (m * n);
      const uint32_t *Bin = B32.data() + lvl * (n * p);
      uint32_t *Aout = A32r.data() + lvl * (m * n);
      uint32_t *Bout = B32r.data() + lvl * (n * p);
      for (size_t k = 0; k < m * n; ++k)   Aout[k] = static_cast<uint32_t>(Ain[k] % qq);
      for (size_t k = 0; k < n * p; ++k)   Bout[k] = static_cast<uint32_t>(Bin[k] % qq);
    }

    // Scalar reference (chunked) on reduced inputs.
    std::vector<uint64_t> C_ref32(m * p * levels, 0);
    for (size_t lvl = 0; lvl < levels; ++lvl) {
      const uint64_t qq = level_qs[lvl];
      const uint32_t *Ar = A32r.data() + lvl * (m * n);
      const uint32_t *Br = B32r.data() + lvl * (n * p);
      uint64_t *Cr = C_ref32.data() + lvl * (m * p);
      for (size_t i = 0; i < m; ++i) {
        uint128_t t0 = 0, t1 = 0;
        for (size_t k = 0; k < n; ++k) {
          t0 += (uint128_t)Ar[i * n + k] * Br[2 * k];
          t1 += (uint128_t)Ar[i * n + k] * Br[2 * k + 1];
        }
        Cr[2 * i]     = static_cast<uint64_t>(t0 % qq);
        Cr[2 * i + 1] = static_cast<uint64_t>(t1 % qq);
      }
    }

    const std::string MAT_MULT_AVX_SAFE = "level mat mat 32->64 avx512 safe";
    std::vector<uint64_t> C64_avx_safe(m * p * levels, 0);
    TIME_START(MAT_MULT_AVX_SAFE);
    level_mat_mat_avx512_safe(A32r.data(), B32r.data(), C64_avx_safe.data(),
                              m, n, levels, level_qs.data());
    TIME_END(MAT_MULT_AVX_SAFE);

    // Correctness vs scalar reference.
    bool avx_safe_ok = true;
    for (size_t i = 0; i < C_ref32.size(); ++i) {
      if (C_ref32[i] != C64_avx_safe[i]) { avx_safe_ok = false; break; }
    }
    BENCH_PRINT("AVX-512 safe correctness: " << (avx_safe_ok ? "PASS" : "FAIL"));

    // Mat-vec variant: same A traffic, half the multiplies. B has 1 column.
    std::vector<uint32_t> Bv(n * levels);
    for (size_t lvl = 0; lvl < levels; ++lvl) {
      const uint64_t qq = level_qs[lvl];
      for (size_t k = 0; k < n; ++k)
        Bv[lvl * n + k] = static_cast<uint32_t>(rand() % qq);
    }
    std::vector<uint64_t> Cv(m * levels, 0);
    const std::string MAT_VEC_AVX = "level mat vec 32->64 avx512 safe";
    TIME_START(MAT_VEC_AVX);
    level_mat_vec_avx512_safe(A32r.data(), Bv.data(), Cv.data(),
                              m, n, levels, level_qs.data());
    TIME_END(MAT_VEC_AVX);
    uint64_t cv_sum = 0;
    for (size_t i = 0; i < Cv.size(); ++i) cv_sum += Cv[i];
    BENCH_PRINT("Checksum (mat-vec): " << cv_sum);
#endif
  }

  END_EXPERIMENT();
  PRINT_BAR;

  const double mat_mult_time = GET_LAST_TIME(MAT_MULT_128);
  const double throughput = db_size / (mat_mult_time * 1000);
  BENCH_PRINT("level_mat_mat (build inter=" << INTER_BITS << "-bit) time: "
              << mat_mult_time << " ms");
  BENCH_PRINT("level_mat_mat (build inter=" << INTER_BITS << "-bit) throughput: \t"
              << static_cast<size_t>(throughput) << " MB/s");

  const double t_nc = GET_LAST_TIME(MAT_MULT_NC);
  BENCH_PRINT("level_mat_mat (nochunk uint128 acc) time:  " << t_nc << " ms");
  BENCH_PRINT("level_mat_mat (nochunk uint128 acc) throughput: \t"
              << static_cast<size_t>(db_size / (t_nc * 1000)) << " MB/s");
  BENCH_PRINT("Speedup of nochunk vs build path: " << (mat_mult_time / t_nc) << "x");

  if (can_run_32to64) {
    const double t64    = GET_LAST_TIME(MAT_MULT_64);
    const double t64_nc = GET_LAST_TIME(MAT_MULT_64_NC);
    BENCH_PRINT("level_mat_mat (32->64) time:  " << t64 << " ms");
    BENCH_PRINT("level_mat_mat (32->64) throughput: \t"
                << static_cast<size_t>(db64 / (t64 * 1000)) << " MB/s");
    BENCH_PRINT("Speedup of 32->64 vs build path: " << (mat_mult_time / t64) << "x");
    BENCH_PRINT("level_mat_mat (32->64 nochunk) time:  " << t64_nc << " ms");
    BENCH_PRINT("level_mat_mat (32->64 nochunk) throughput: \t"
                << static_cast<size_t>(db64 / (t64_nc * 1000)) << " MB/s");
    BENCH_PRINT("Speedup of 32->64 nochunk vs build path: "
                << (mat_mult_time / t64_nc) << "x");

    const double t_stream = GET_LAST_TIME("level mat mat stream only");
    BENCH_PRINT("A-stream ceiling time: " << t_stream << " ms");
    BENCH_PRINT("A-stream ceiling throughput: \t"
                << static_cast<size_t>(db64 / (t_stream * 1000)) << " MB/s");

    const double t64_sp = GET_LAST_TIME(MAT_MULT_64_SPLIT);
    BENCH_PRINT("level_mat_mat (32->64 split_b) time:  " << t64_sp << " ms");
    BENCH_PRINT("level_mat_mat (32->64 split_b) throughput: \t"
                << static_cast<size_t>(db64 / (t64_sp * 1000)) << " MB/s");
    BENCH_PRINT("Speedup of 32->64 split_b vs build path: "
                << (mat_mult_time / t64_sp) << "x");

#if defined(__AVX512F__)
    const double t64_avx = GET_LAST_TIME(MAT_MULT_64_AVX);
    BENCH_PRINT("level_mat_mat (32->64 avx512)  time:  " << t64_avx << " ms");
    BENCH_PRINT("level_mat_mat (32->64 avx512)  throughput: \t"
                << static_cast<size_t>(db64 / (t64_avx * 1000)) << " MB/s");
    BENCH_PRINT("Speedup of 32->64 avx512 vs build path: "
                << (mat_mult_time / t64_avx) << "x");

    const double t64_safe = GET_LAST_TIME("level mat mat 32->64 avx512 safe");
    BENCH_PRINT("level_mat_mat (32->64 avx512 SAFE) time:  " << t64_safe << " ms");
    BENCH_PRINT("level_mat_mat (32->64 avx512 SAFE) throughput: \t"
                << static_cast<size_t>(db64 / (t64_safe * 1000)) << " MB/s");
    BENCH_PRINT("Speedup of 32->64 avx512 SAFE vs build path: "
                << (mat_mult_time / t64_safe) << "x");

    const double t_vec = GET_LAST_TIME("level mat vec 32->64 avx512 safe");
    BENCH_PRINT("level_mat_VEC (32->64 avx512 SAFE) time:  " << t_vec << " ms");
    BENCH_PRINT("level_mat_VEC (32->64 avx512 SAFE) throughput: \t"
                << static_cast<size_t>(db64 / (t_vec * 1000)) << " MB/s");
    BENCH_PRINT("mat-vec / mat-mat ratio: " << (t_vec / t64_safe)
                << " (1.0 = pure memory-bound on A)");
#endif
  } else {
    BENCH_PRINT("Skipping 32->64 chunk: max modulus " << max_q_test
                << " does not fit in 32 bits (K=1 60-bit cell).");
  }
}
