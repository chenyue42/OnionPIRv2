#include "tests.h"
#include "hexl/hexl.hpp"
#include "seal/util/ntt.h"
#include <chrono>
#include <random>
#include <cstring>

void PirTest::test_hexl_ntt() {
  print_func_name(__FUNCTION__);

  // ===================== Parameters =====================
  constexpr size_t N = DBConsts::PolyDegree; // 2048
  // Use an NTT-friendly prime: q ≡ 1 (mod 2N)
  // We'll reuse the PIR ciphertext modulus which is already NTT-friendly.
  PirParams pir_params;
  const uint64_t q = pir_params.get_coeff_modulus()[0];
  BENCH_PRINT("N = " << N << ", q = " << q << " (" << std::ceil(std::log2(q)) << " bits)");

  // ===================== Create HEXL NTT object =====================
  intel::hexl::NTT ntt(N, q);
  BENCH_PRINT("HEXL NTT object created.");

  // ===================== Test 1: NTT forward + inverse = identity =====================
  BENCH_PRINT("\n--- Test 1: NTT(INTT(x)) == x ---");

  std::mt19937_64 rng(42);
  std::vector<uint64_t> original(N), transformed(N), recovered(N);
  for (size_t i = 0; i < N; i++) {
    original[i] = rng() % q;
  }

  // Forward NTT: input in [0, q), output in [0, q)
  ntt.ComputeForward(transformed.data(), original.data(), 1, 1);

  // Inverse NTT: input in [0, q), output in [0, q)
  ntt.ComputeInverse(recovered.data(), transformed.data(), 1, 1);

  // Check round-trip
  bool match = (original == recovered);
  BENCH_PRINT("Round-trip correct: " << (match ? "YES" : "NO"));
  if (!match) {
    for (size_t i = 0; i < 5; i++) {
      BENCH_PRINT("  [" << i << "] orig=" << original[i] << "  recovered=" << recovered[i]);
    }
  }

  // ===================== Test 2: Polynomial multiplication via NTT =====================
  // Compute c = a * b (mod x^N + 1, mod q) using NTT
  BENCH_PRINT("\n--- Test 2: Polynomial multiplication via NTT ---");

  // Simple test: a(x) = 1 + 2x + 3x^2, b(x) = 4 + 5x
  // a*b = 4 + 5x + 8x + 10x^2 + 12x^2 + 15x^3
  //     = 4 + 13x + 22x^2 + 15x^3  (before negacyclic reduction)
  // With N=2048, no wrap-around for these small degrees.
  std::vector<uint64_t> a(N, 0), b(N, 0);
  a[0] = 1; a[1] = 2; a[2] = 3;
  b[0] = 4; b[1] = 5;

  // NTT both
  std::vector<uint64_t> a_ntt(N), b_ntt(N), c_ntt(N), c(N);
  ntt.ComputeForward(a_ntt.data(), a.data(), 1, 1);
  ntt.ComputeForward(b_ntt.data(), b.data(), 1, 1);

  // Pointwise multiply: c_ntt = a_ntt * b_ntt (mod q)
  intel::hexl::EltwiseMultMod(c_ntt.data(), a_ntt.data(), b_ntt.data(), N, q, 1);

  // Inverse NTT to get result in coefficient form
  ntt.ComputeInverse(c.data(), c_ntt.data(), 1, 1);

  BENCH_PRINT("a(x) = 1 + 2x + 3x^2");
  BENCH_PRINT("b(x) = 4 + 5x");
  BENCH_PRINT("c(x) = a*b coeffs: " << c[0] << ", " << c[1] << ", " << c[2] << ", " << c[3] << ", " << c[4]);
  bool mult_ok = (c[0] == 4 && c[1] == 13 && c[2] == 22 && c[3] == 15 && c[4] == 0);
  BENCH_PRINT("Multiplication correct: " << (mult_ok ? "YES" : "NO"));

  // ===================== Test 3: Addition in coefficient form =====================
  BENCH_PRINT("\n--- Test 3: Polynomial addition (mod q) ---");

  std::vector<uint64_t> x(N, 0), y(N, 0), z(N);
  x[0] = q - 1;  // represents -1 mod q
  x[1] = 100;
  y[0] = 2;      // so x[0]+y[0] = q+1 ≡ 1 mod q
  y[1] = q - 50; // so x[1]+y[1] = 100 + (q-50) ≡ 50 mod q

  intel::hexl::EltwiseAddMod(z.data(), x.data(), y.data(), N, q);
  BENCH_PRINT("x[0]=" << x[0] << " + y[0]=" << y[0] << " = " << z[0] << " (expect 1)");
  BENCH_PRINT("x[1]=" << x[1] << " + y[1]=" << y[1] << " = " << z[1] << " (expect 50)");
  bool add_ok = (z[0] == 1 && z[1] == 50);
  BENCH_PRINT("Addition correct: " << (add_ok ? "YES" : "NO"));

  // ===================== Test 4: Simulated BFV decryption (phase = c0 + c1*s) =====================
  BENCH_PRINT("\n--- Test 4: BFV-like decrypt: phase = c0 + c1*s ---");

  // Simulate: encrypt m=7 at slot 0
  // c0 = -a*s + delta*m + e,  c1 = a  (all in [0, q))
  // We'll construct c0, c1, s explicitly.
  const uint64_t t = pir_params.get_plain_mod(); // plaintext mod
  const uint64_t delta = q / t;
  BENCH_PRINT("t=" << t << ", delta=floor(q/t)=" << delta);

  // Secret key: ternary {0, 1, q-1} in coefficient form
  std::vector<uint64_t> sk(N, 0);
  sk[0] = 1; sk[1] = q - 1; sk[2] = 1; // s = 1 - x + x^2

  // Random 'a' polynomial
  std::vector<uint64_t> a_poly(N);
  for (size_t i = 0; i < N; i++) a_poly[i] = rng() % q;

  // Compute a*s in NTT domain
  std::vector<uint64_t> sk_ntt(N), a_ntt2(N), as_ntt(N), as_coef(N);
  ntt.ComputeForward(sk_ntt.data(), sk.data(), 1, 1);
  ntt.ComputeForward(a_ntt2.data(), a_poly.data(), 1, 1);
  intel::hexl::EltwiseMultMod(as_ntt.data(), a_ntt2.data(), sk_ntt.data(), N, q, 1);
  ntt.ComputeInverse(as_coef.data(), as_ntt.data(), 1, 1);

  // c1 = a, c0 = -a*s + delta*m (no noise for simplicity)
  uint64_t m = 7;
  std::vector<uint64_t> ct0(N, 0), ct1(N);
  std::memcpy(ct1.data(), a_poly.data(), N * sizeof(uint64_t));
  // c0 = (q - a*s) + delta*m  at slot 0
  for (size_t i = 0; i < N; i++) {
    ct0[i] = (q - as_coef[i]) % q; // -a*s mod q
  }
  ct0[0] = (ct0[0] + (delta * m) % q) % q; // add delta*m at coeff 0

  // Decrypt: phase = c0 + c1*s
  std::vector<uint64_t> ct1_ntt(N), phase_ntt(N), phase(N);
  ntt.ComputeForward(ct1_ntt.data(), ct1.data(), 1, 1);
  intel::hexl::EltwiseMultMod(phase_ntt.data(), ct1_ntt.data(), sk_ntt.data(), N, q, 1);
  ntt.ComputeInverse(phase.data(), phase_ntt.data(), 1, 1);
  intel::hexl::EltwiseAddMod(phase.data(), phase.data(), ct0.data(), N, q);

  // Recover plaintext: m_recovered = round(phase * t / q)
  uint64_t m_recovered = static_cast<uint64_t>(((uint128_t)phase[0] * t + q / 2) / q) % t;
  BENCH_PRINT("Encrypted m=" << m << ", decrypted m=" << m_recovered);
  BENCH_PRINT("Decryption correct: " << ((m_recovered == m) ? "YES" : "NO"));

  // ===================== Test 5: HEXL vs SEAL NTT equivalence =====================
  BENCH_PRINT("\n--- Test 5: HEXL NTT output matches SEAL NTT output? ---");
  const auto seal_ctx = pir_params.get_context();
  const auto seal_ntt_tables = seal_ctx.key_context_data()->small_ntt_tables();

  std::vector<uint64_t> input(N);
  for (size_t i = 0; i < N; i++) input[i] = rng() % q;

  std::vector<uint64_t> hexl_fwd(N), seal_fwd(input.begin(), input.end());
  ntt.ComputeForward(hexl_fwd.data(), input.data(), 1, 1);
  seal::util::ntt_negacyclic_harvey(seal_fwd.data(), seal_ntt_tables[0]);

  size_t fwd_diffs = 0;
  for (size_t i = 0; i < N; i++) {
    if (hexl_fwd[i] != seal_fwd[i]) {
      if (fwd_diffs < 3) {
        BENCH_PRINT("  [fwd " << i << "] hexl=" << hexl_fwd[i] << " seal=" << seal_fwd[i]);
      }
      ++fwd_diffs;
    }
  }
  BENCH_PRINT("Forward NTT: " << (fwd_diffs == 0 ? "MATCH" : "DIFFER")
              << " (" << fwd_diffs << " / " << N << " coeffs differ)");

  std::vector<uint64_t> hexl_inv(N), seal_inv(hexl_fwd.begin(), hexl_fwd.end());
  ntt.ComputeInverse(hexl_inv.data(), hexl_fwd.data(), 1, 1);
  seal::util::inverse_ntt_negacyclic_harvey(seal_inv.data(), seal_ntt_tables[0]);

  size_t inv_diffs = 0;
  for (size_t i = 0; i < N; i++) {
    if (hexl_inv[i] != seal_inv[i]) {
      if (inv_diffs < 3) {
        BENCH_PRINT("  [inv " << i << "] hexl=" << hexl_inv[i] << " seal=" << seal_inv[i]);
      }
      ++inv_diffs;
    }
  }
  BENCH_PRINT("Inverse NTT: " << (inv_diffs == 0 ? "MATCH" : "DIFFER")
              << " (" << inv_diffs << " / " << N << " coeffs differ)");

  // ===================== Test 6: HEXL vs SEAL NTT performance =====================
  BENCH_PRINT("\n--- Test 6: Performance comparison ---");
  //
  // Measures forward + inverse NTT per iteration, warmed up, hot cache.
  // SEAL's NTT object is the one cached inside SEALContext (same path as prod code).
  // HEXL's NTT object is constructed once and reused (matches utils:: cache behavior).
  constexpr int warmup = 100;
  constexpr int iters  = 10000;

  std::vector<uint64_t> perf_buf(N);
  for (size_t i = 0; i < N; i++) perf_buf[i] = rng() % q;

  // Warmup both paths so branch predictor / caches are primed.
  {
    std::vector<uint64_t> tmp = perf_buf;
    for (int i = 0; i < warmup; i++) {
      ntt.ComputeForward(tmp.data(), tmp.data(), 1, 1);
      ntt.ComputeInverse(tmp.data(), tmp.data(), 1, 1);
    }
  }
  {
    std::vector<uint64_t> tmp = perf_buf;
    for (int i = 0; i < warmup; i++) {
      seal::util::ntt_negacyclic_harvey(tmp.data(), seal_ntt_tables[0]);
      seal::util::inverse_ntt_negacyclic_harvey(tmp.data(), seal_ntt_tables[0]);
    }
  }

  using clk = std::chrono::steady_clock;

  // --- HEXL direct ---
  std::vector<uint64_t> hexl_buf = perf_buf;
  auto t0 = clk::now();
  for (int i = 0; i < iters; i++) {
    ntt.ComputeForward(hexl_buf.data(), hexl_buf.data(), 1, 1);
    ntt.ComputeInverse(hexl_buf.data(), hexl_buf.data(), 1, 1);
  }
  auto t1 = clk::now();
  double hexl_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / iters;

  // --- SEAL ---
  std::vector<uint64_t> seal_buf = perf_buf;
  t0 = clk::now();
  for (int i = 0; i < iters; i++) {
    seal::util::ntt_negacyclic_harvey(seal_buf.data(), seal_ntt_tables[0]);
    seal::util::inverse_ntt_negacyclic_harvey(seal_buf.data(), seal_ntt_tables[0]);
  }
  t1 = clk::now();
  double seal_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / iters;

  // --- utils:: wrapper (HEXL under the hood, thread_local cache lookup) ---
  std::vector<uint64_t> util_buf = perf_buf;
  t0 = clk::now();
  for (int i = 0; i < iters; i++) {
    utils::ntt_fwd(util_buf.data(), N, q);
    utils::ntt_inv(util_buf.data(), N, q);
  }
  t1 = clk::now();
  double util_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / iters;

  BENCH_PRINT("Per iteration (forward + inverse), " << iters << " iters:");
  BENCH_PRINT("  SEAL          : " << seal_us << " us");
  BENCH_PRINT("  HEXL direct   : " << hexl_us << " us  (" << (seal_us / hexl_us) << "x vs SEAL)");
  BENCH_PRINT("  utils:: wrap  : " << util_us << " us  (" << (seal_us / util_us) << "x vs SEAL)");

  // ===================== Summary =====================
  BENCH_PRINT("\n--- Summary ---");
  bool ntt_eq = (fwd_diffs == 0 && inv_diffs == 0);
  int pass = match + mult_ok + add_ok + (m_recovered == m) + ntt_eq;
  BENCH_PRINT("Passed " << pass << "/5 correctness tests (Test 6 is perf-only)");
}
