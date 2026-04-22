#include "tests.h"
#include "hexl/hexl.hpp"
#include <chrono>
#include <random>
#include <cstring>

void PirTest::test_hexl_ntt() {
  print_func_name(__FUNCTION__);

  // ===================== Parameters =====================
  constexpr size_t N = DBConsts::PolyDegree;
  PirParams pir_params;
  const uint64_t q = pir_params.get_coeff_modulus()[0];
  BENCH_PRINT("N = " << N << ", q = " << q << " (" << std::ceil(std::log2(q)) << " bits)");

  // When the active config splits q into two CRT limbs, q is composite and
  // HEXL's default ctor (which searches for a prime-only primitive root) will
  // fail. PirParams already computed the CRT-combined root w_crt and registered
  // it with utils::ntt_*; we reuse it here so tests 1/2/4/5 work in both modes.
  const auto &crt = pir_params.get_composite_rns();
  std::unique_ptr<intel::hexl::NTT> ntt_ptr = crt.enabled
      ? std::make_unique<intel::hexl::NTT>(N, q, crt.w_crt)
      : std::make_unique<intel::hexl::NTT>(N, q);
  intel::hexl::NTT &ntt = *ntt_ptr;
  BENCH_PRINT("HEXL NTT object created"
              << (crt.enabled ? " (composite q, w_crt)" : "") << ".");

  std::mt19937_64 rng(42);

  // ===================== Test 1: NTT(INTT(x)) == x =====================
  BENCH_PRINT("\n--- Test 1: NTT(INTT(x)) == x ---");
  std::vector<uint64_t> original(N), transformed(N), recovered(N);
  for (size_t i = 0; i < N; i++) original[i] = rng() % q;

  ntt.ComputeForward(transformed.data(), original.data(), 1, 1);
  ntt.ComputeInverse(recovered.data(), transformed.data(), 1, 1);

  bool match = (original == recovered);
  BENCH_PRINT("Round-trip correct: " << (match ? "YES" : "NO"));
  if (!match) {
    for (size_t i = 0; i < 5; i++) {
      BENCH_PRINT("  [" << i << "] orig=" << original[i] << "  recovered=" << recovered[i]);
    }
  }

  // ===================== Test 2: Polynomial multiplication via NTT =====================
  // a(x) = 1 + 2x + 3x^2, b(x) = 4 + 5x
  //   a*b = 4 + 13x + 22x^2 + 15x^3  (N=2048 is large enough for no wrap-around)
  BENCH_PRINT("\n--- Test 2: Polynomial multiplication via NTT ---");
  std::vector<uint64_t> a(N, 0), b(N, 0);
  a[0] = 1; a[1] = 2; a[2] = 3;
  b[0] = 4; b[1] = 5;

  std::vector<uint64_t> a_ntt(N), b_ntt(N), c_ntt(N), c(N);
  ntt.ComputeForward(a_ntt.data(), a.data(), 1, 1);
  ntt.ComputeForward(b_ntt.data(), b.data(), 1, 1);
  intel::hexl::EltwiseMultMod(c_ntt.data(), a_ntt.data(), b_ntt.data(), N, q, 1);
  ntt.ComputeInverse(c.data(), c_ntt.data(), 1, 1);

  BENCH_PRINT("a(x) = 1 + 2x + 3x^2");
  BENCH_PRINT("b(x) = 4 + 5x");
  BENCH_PRINT("c(x) = a*b coeffs: " << c[0] << ", " << c[1] << ", " << c[2] << ", " << c[3] << ", " << c[4]);
  bool mult_ok = (c[0] == 4 && c[1] == 13 && c[2] == 22 && c[3] == 15 && c[4] == 0);
  BENCH_PRINT("Multiplication correct: " << (mult_ok ? "YES" : "NO"));

  // ===================== Test 3: Polynomial addition (mod q) =====================
  BENCH_PRINT("\n--- Test 3: Polynomial addition (mod q) ---");
  std::vector<uint64_t> x(N, 0), y(N, 0), z(N);
  x[0] = q - 1;   // -1 mod q
  x[1] = 100;
  y[0] = 2;       // x[0]+y[0] = q+1 ≡ 1 mod q
  y[1] = q - 50;  // x[1]+y[1] = 100 + (q-50) ≡ 50 mod q

  intel::hexl::EltwiseAddMod(z.data(), x.data(), y.data(), N, q);
  BENCH_PRINT("x[0]=" << x[0] << " + y[0]=" << y[0] << " = " << z[0] << " (expect 1)");
  BENCH_PRINT("x[1]=" << x[1] << " + y[1]=" << y[1] << " = " << z[1] << " (expect 50)");
  bool add_ok = (z[0] == 1 && z[1] == 50);
  BENCH_PRINT("Addition correct: " << (add_ok ? "YES" : "NO"));

  // ===================== Test 4: Simulated BFV decryption (phase = c0 + c1*s) =====================
  BENCH_PRINT("\n--- Test 4: BFV-like decrypt: phase = c0 + c1*s ---");
  const uint64_t t = pir_params.get_plain_mod();
  const uint64_t delta = q / t;
  BENCH_PRINT("t=" << t << ", delta=floor(q/t)=" << delta);

  std::vector<uint64_t> sk(N, 0);
  sk[0] = 1; sk[1] = q - 1; sk[2] = 1; // s = 1 - x + x^2

  std::vector<uint64_t> a_poly(N);
  for (size_t i = 0; i < N; i++) a_poly[i] = rng() % q;

  std::vector<uint64_t> sk_ntt(N), a_ntt2(N), as_ntt(N), as_coef(N);
  ntt.ComputeForward(sk_ntt.data(), sk.data(), 1, 1);
  ntt.ComputeForward(a_ntt2.data(), a_poly.data(), 1, 1);
  intel::hexl::EltwiseMultMod(as_ntt.data(), a_ntt2.data(), sk_ntt.data(), N, q, 1);
  ntt.ComputeInverse(as_coef.data(), as_ntt.data(), 1, 1);

  uint64_t m = 7;
  std::vector<uint64_t> ct0(N, 0), ct1(N);
  std::memcpy(ct1.data(), a_poly.data(), N * sizeof(uint64_t));
  for (size_t i = 0; i < N; i++) ct0[i] = (q - as_coef[i]) % q;
  ct0[0] = (ct0[0] + (delta * m) % q) % q;

  std::vector<uint64_t> ct1_ntt(N), phase_ntt(N), phase(N);
  ntt.ComputeForward(ct1_ntt.data(), ct1.data(), 1, 1);
  intel::hexl::EltwiseMultMod(phase_ntt.data(), ct1_ntt.data(), sk_ntt.data(), N, q, 1);
  ntt.ComputeInverse(phase.data(), phase_ntt.data(), 1, 1);
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), ct0.data(), N, q);

  uint64_t m_recovered = static_cast<uint64_t>(((uint128_t)phase[0] * t + q / 2) / q) % t;
  BENCH_PRINT("Encrypted m=" << m << ", decrypted m=" << m_recovered);
  BENCH_PRINT("Decryption correct: " << ((m_recovered == m) ? "YES" : "NO"));

  // ===================== Test 5: utils:: wrapper matches direct HEXL =====================
  BENCH_PRINT("\n--- Test 5: utils::ntt_fwd/inv matches direct HEXL NTT ---");
  std::vector<uint64_t> input(N);
  for (size_t i = 0; i < N; i++) input[i] = rng() % q;

  std::vector<uint64_t> direct_fwd(N), wrap_fwd = input;
  ntt.ComputeForward(direct_fwd.data(), input.data(), 1, 1);
  utils::ntt_fwd(wrap_fwd.data(), N, q);

  size_t fwd_diffs = 0;
  for (size_t i = 0; i < N; i++) if (direct_fwd[i] != wrap_fwd[i]) ++fwd_diffs;

  std::vector<uint64_t> direct_inv(N), wrap_inv = direct_fwd;
  ntt.ComputeInverse(direct_inv.data(), direct_fwd.data(), 1, 1);
  utils::ntt_inv(wrap_inv.data(), N, q);

  size_t inv_diffs = 0;
  for (size_t i = 0; i < N; i++) if (direct_inv[i] != wrap_inv[i]) ++inv_diffs;

  bool wrap_match = (fwd_diffs == 0 && inv_diffs == 0);
  BENCH_PRINT("utils vs direct HEXL: " << (wrap_match ? "MATCH" : "DIFFER")
              << " (fwd diffs=" << fwd_diffs << ", inv diffs=" << inv_diffs << ")");

  // ===================== Test 6: Performance of utils:: wrapper =====================
  BENCH_PRINT("\n--- Test 6: utils::ntt_fwd/inv performance ---");
  constexpr int warmup = 100;
  constexpr int iters  = 10000;

  std::vector<uint64_t> perf_buf(N);
  for (size_t i = 0; i < N; i++) perf_buf[i] = rng() % q;

  {
    std::vector<uint64_t> tmp = perf_buf;
    for (int i = 0; i < warmup; i++) {
      utils::ntt_fwd(tmp.data(), N, q);
      utils::ntt_inv(tmp.data(), N, q);
    }
  }

  using clk = std::chrono::steady_clock;
  std::vector<uint64_t> util_buf = perf_buf;
  auto t0 = clk::now();
  for (int i = 0; i < iters; i++) {
    utils::ntt_fwd(util_buf.data(), N, q);
    utils::ntt_inv(util_buf.data(), N, q);
  }
  auto t1 = clk::now();
  double util_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / iters;
  BENCH_PRINT("  utils::ntt_fwd + utils::ntt_inv: " << util_us << " us / iter (" << iters << " iters)");

  // ===================== Test 7: composite NTT (q = q1*q2) =====================
  // Pick two 28-bit NTT-friendly primes, derive per-limb 2N-th roots via HEXL,
  // CRT-combine them into a 2N-th root mod q1*q2, and verify:
  //   (a) real round-trip under the composite NTT,
  //   (b) negacyclic polynomial multiplication under the composite NTT,
  //   (c) coefficient-wise reduction of the composite NTT matches independent
  //       per-limb NTTs (the property that makes the composite↔RNS split at
  //       the first-dim matmul boundary free of extra NTT calls).
  BENCH_PRINT("\n--- Test 7: Composite NTT with q = q1*q2 (28+28 bits) ---");
  const auto rns_primes = utils::generate_ntt_friendly_primes({28, 28}, N);
  const uint64_t q1 = rns_primes[0];
  const uint64_t q2 = rns_primes[1];
  const uint64_t crt_mod = static_cast<uint64_t>(q1) * q2;   // ~56 bits
  const uint64_t w1 = intel::hexl::MinimalPrimitiveRoot(2 * N, q1);
  const uint64_t w2 = intel::hexl::MinimalPrimitiveRoot(2 * N, q2);
  const uint64_t w_crt = utils::crt_combine(w1, q1, w2, q2);
  BENCH_PRINT("q1=" << q1 << ", q2=" << q2 << ", q1*q2=" << crt_mod
              << " (" << std::ceil(std::log2(crt_mod)) << " bits)");
  BENCH_PRINT("w1=" << w1 << ", w2=" << w2 << ", w_crt=" << w_crt);

  const bool root_ok = intel::hexl::IsPrimitiveRoot(w_crt, 2 * N, crt_mod);
  BENCH_PRINT("w_crt is primitive 2N-th root mod q1*q2: " << (root_ok ? "YES" : "NO"));

  intel::hexl::NTT composite_ntt(N, crt_mod, w_crt);

  // (a) true round-trip.
  std::vector<uint64_t> orig(N), buf(N);
  utils::sample_uniform_poly(orig.data(), N, crt_mod, rng);
  std::memcpy(buf.data(), orig.data(), N * sizeof(uint64_t));
  composite_ntt.ComputeForward(buf.data(), buf.data(), 1, 1);
  composite_ntt.ComputeInverse(buf.data(), buf.data(), 1, 1);
  bool round_trip_ok = (buf == orig);
  BENCH_PRINT("Round-trip NTT(INTT(x)) == x: " << (round_trip_ok ? "YES" : "NO"));

  // (b) polynomial multiplication under the composite NTT.
  //     a(x) = 1 + 2x + 3x^2, b(x) = 4 + 5x → a*b = 4 + 13x + 22x^2 + 15x^3.
  std::vector<uint64_t> ca(N, 0), cb(N, 0), cc(N);
  ca[0] = 1; ca[1] = 2; ca[2] = 3;
  cb[0] = 4; cb[1] = 5;
  std::vector<uint64_t> ca_ntt(N), cb_ntt(N), cc_ntt(N);
  composite_ntt.ComputeForward(ca_ntt.data(), ca.data(), 1, 1);
  composite_ntt.ComputeForward(cb_ntt.data(), cb.data(), 1, 1);
  intel::hexl::EltwiseMultMod(cc_ntt.data(), ca_ntt.data(), cb_ntt.data(), N, crt_mod, 1);
  composite_ntt.ComputeInverse(cc.data(), cc_ntt.data(), 1, 1);
  bool crt_mult_ok = (cc[0] == 4 && cc[1] == 13 && cc[2] == 22 && cc[3] == 15 && cc[4] == 0);
  BENCH_PRINT("Composite NTT multiplication correct: " << (crt_mult_ok ? "YES" : "NO"));

  // (c) composite NTT coefficients reduce coefficient-wise to per-limb NTT
  //     coefficients (the split invariant needed at the first-dim boundary).
  intel::hexl::NTT ntt_q1(N, q1, w1);
  intel::hexl::NTT ntt_q2(N, q2, w2);
  std::vector<uint64_t> ref(N);
  utils::sample_uniform_poly(ref.data(), N, crt_mod, rng);
  std::vector<uint64_t> ref_crt(N), ref_q1(N), ref_q2(N);
  composite_ntt.ComputeForward(ref_crt.data(), ref.data(), 1, 1);
  for (size_t i = 0; i < N; i++) {
    ref_q1[i] = ref[i] % q1;
    ref_q2[i] = ref[i] % q2;
  }
  ntt_q1.ComputeForward(ref_q1.data(), ref_q1.data(), 1, 1);
  ntt_q2.ComputeForward(ref_q2.data(), ref_q2.data(), 1, 1);
  bool split_ok = true;
  for (size_t i = 0; i < N; i++) {
    if (ref_crt[i] % q1 != ref_q1[i] || ref_crt[i] % q2 != ref_q2[i]) {
      split_ok = false; break;
    }
  }
  BENCH_PRINT("Composite-NTT coeffs ≡ per-limb NTT coeffs: " << (split_ok ? "YES" : "NO"));

 // ===================== Summary =====================
  BENCH_PRINT("\n--- Summary ---");
  int pass = match + mult_ok + add_ok + (m_recovered == m) + wrap_match
             + root_ok + round_trip_ok + crt_mult_ok + split_ok;
  BENCH_PRINT("Passed " << pass << "/9 correctness tests (Test 6 is perf-only)");
}
