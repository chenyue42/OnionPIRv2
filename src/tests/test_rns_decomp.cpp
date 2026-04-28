#include "tests.h"
#include "utils.h"

#include <random>
#include <sstream>
#include <stdexcept>

// Algebraic test for the RNS-hybrid gadget decomposition (no encryption).
//
// Verifies the identity from claude_resp/rns_hybrid_keyswitch.md:
//
//   x  ≡  Σ_{k,i}  d_{k,i} · (g_k · B^i)   (mod Q)
//
// where Q = q_0 * q_1, g_k is the CRT basis vector (≡ 1 mod q_k, ≡ 0 mod q_j),
// and d_{k,i} are the per-limb base-B digits of x mod q_k. Establishing this
// identity is the prerequisite for K=2 BV key-switching / GSW external-product
// to be implementable with purely per-limb hot-path arithmetic.
//
// Two 30-bit primes keep Q < 2^60 so all intermediate products fit in uint128
// without a 192-bit accumulator. The math is identical at 60-bit lanes.

namespace {

constexpr uint64_t q0 = 1073741789ULL;  // prime, ~30 bits
constexpr uint64_t q1 = 1073741783ULL;  // prime, ~30 bits, coprime to q0
constexpr size_t   b_log = 10;
constexpr uint64_t B = 1ULL << b_log;
constexpr size_t   l = 3;  // ceil(30 / b_log)

inline uint64_t mul_mod(uint64_t x, uint64_t y, uint64_t m) {
  return static_cast<uint64_t>(((uint128_t)x * y) % m);
}

inline uint64_t random_in_q(std::mt19937_64 &rng, uint64_t Q) {
  return static_cast<uint64_t>((((uint128_t)rng() << 64) | rng()) % Q);
}

// Reconstruct x ≡ Σ d_{k,i} · c_{k,i} (mod Q) using precomputed
// c_{k,i} = g_k · B^i mod Q. Returns the integer in [0, Q).
uint64_t reconstruct(uint64_t x, uint64_t Q, const uint64_t c[2][l]) {
  const uint64_t lane[2] = {x % q0, x % q1};
  uint64_t y = 0;
  for (size_t k = 0; k < 2; k++) {
    uint64_t v = lane[k];
    for (size_t i = 0; i < l; i++) {
      const uint64_t d = v & (B - 1);
      v >>= b_log;
      y = static_cast<uint64_t>((y + (uint128_t)d * c[k][i]) % Q);
    }
    if (v != 0) {
      std::ostringstream os;
      os << "digit overflow at lane " << k << ": residue " << v << " not consumed";
      throw std::runtime_error(os.str());
    }
  }
  return y;
}

}  // namespace

void PirTest::test_rns_decomp() {
  print_func_name(__FUNCTION__);

  static_assert(q0 != q1, "moduli must differ");
  const uint64_t Q = q0 * q1;
  BENCH_PRINT("q0=" << q0 << " q1=" << q1 << " Q=" << Q << " (~"
              << (64 - __builtin_clzll(Q)) << " bits)");

  // ---- Compute g_k = q_hat_k · (q_hat_k^{-1} mod q_k) ----
  uint64_t q1_inv_mod_q0;
  if (!utils::try_invert_uint_mod(q1 % q0, q0, q1_inv_mod_q0))
    throw std::runtime_error("q1 not invertible mod q0");
  uint64_t q0_inv_mod_q1;
  if (!utils::try_invert_uint_mod(q0 % q1, q1, q0_inv_mod_q1))
    throw std::runtime_error("q0 not invertible mod q1");

  const uint64_t g0 = mul_mod(q1, q1_inv_mod_q0, Q);
  const uint64_t g1 = mul_mod(q0, q0_inv_mod_q1, Q);

  // ---- Lemma 1: g_k ≡ δ_{k,j} (mod q_j) ----
  if (g0 % q0 != 1 || g0 % q1 != 0)
    throw std::runtime_error("g0 fails CRT basis identities");
  if (g1 % q0 != 0 || g1 % q1 != 1)
    throw std::runtime_error("g1 fails CRT basis identities");
  BENCH_PRINT("Lemma 1 (CRT basis identities) verified for g_0, g_1");

  // ---- Lemma 2: x ≡ x^(0)·g_0 + x^(1)·g_1  (mod Q) ----
  // Sample-based check; the Theorem subsumes this but we exercise it
  // separately to localize failures.
  std::mt19937_64 rng(0xC0FFEEULL);
  for (size_t s = 0; s < 1000; s++) {
    const uint64_t x  = random_in_q(rng, Q);
    const uint64_t y  = static_cast<uint64_t>(
        ((uint128_t)(x % q0) * g0 + (uint128_t)(x % q1) * g1) % Q);
    if (y != x) {
      std::ostringstream os;
      os << "Lemma 2 failed: x=" << x << " y=" << y;
      throw std::runtime_error(os.str());
    }
  }
  BENCH_PRINT("Lemma 2 (CRT reconstruction) verified on 1000 random x");

  // ---- Precompute c_{k,i} = g_k · B^i mod Q ----
  uint64_t c[2][l];
  c[0][0] = g0;
  c[1][0] = g1;
  for (size_t i = 1; i < l; i++) {
    c[0][i] = mul_mod(c[0][i - 1], B, Q);
    c[1][i] = mul_mod(c[1][i - 1], B, Q);
  }

  // ---- Theorem: full hybrid reconstruction on random samples ----
  constexpr size_t num_samples = 100000;
  for (size_t s = 0; s < num_samples; s++) {
    const uint64_t x = random_in_q(rng, Q);
    const uint64_t y = reconstruct(x, Q, c);
    if (y != x) {
      std::ostringstream os;
      os << "Theorem failed: x=" << x << " y=" << y;
      throw std::runtime_error(os.str());
    }
  }

  // ---- Edge cases ----
  const uint64_t edges[] = {0, 1, B - 1, B, q0 - 1, q0, q1 - 1, q1, Q - 1};
  for (uint64_t x : edges) {
    if (reconstruct(x, Q, c) != x)
      throw std::runtime_error("edge case failed");
  }

  BENCH_PRINT("Theorem (RNS-hybrid decomposition) holds for "
              << num_samples << " random samples + " << std::size(edges)
              << " edge cases");
  BENCH_PRINT("All checks passed.");
}
