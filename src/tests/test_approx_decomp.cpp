#include "tests.h"
#include "bv_keyswitch.h"
#include <cmath>
#include <random>

// Isolated test of (approximate) gadget decomposition: no encryption, no
// external product, no noise accumulation. We decompose random values v in
// [0, q), reconstruct  r = sum_i digit_i * gadget_i  mod q, and measure the
// reconstruction error |r - v| (centered). For EXACT decomposition this must be
// 0; for APPROXIMATE decomposition (drop = q_bits - ell*b low bits dropped) it
// must be <= 2^(drop-1). If the measured error blows past that bound, the cliff
// in test_fast_expand is a primitive bug (e.g. order/overflow); if it matches,
// the cliff is noise propagation in the DMux pipeline, not the primitive.
//
// ORDER CONVENTION (the thing Codex flagged):
//   bvks::(approx_)signed_gadget_decompose -> digits LSB-first: digit[i] is the
//       coefficient of B^i (digit[0] = B^0).
//   utils::gsw_gadget(_approx)             -> MSB-first by index: gadget[0] is
//       the largest power (* 2^drop * B^(l-1)), gadget[l-1] is B^0 (* 2^drop).
//   So digit[i] pairs with gadget[ell-1-i]. The production path hides this by
//   reversing the digits in decomp_rlwe_* before matching gadget rows 1:1.

namespace {
// Center a value in [0, q) to (-q/2, q/2].
int64_t center(uint64_t v, uint64_t q) {
  return (v > (q >> 1)) ? static_cast<int64_t>(v) - static_cast<int64_t>(q)
                        : static_cast<int64_t>(v);
}

// Reconstruct from LSB-first digits and an MSB-first gadget row.
// reversed=false: correct pairing digit[i] <-> gadget[ell-1-i].
// reversed=true : naive pairing digit[i] <-> gadget[i] (what you get if you
//                 forget the decomp_rlwe reversal) -- expected to be broken.
uint64_t reconstruct(const uint64_t *digits, const std::vector<uint64_t> &gadget,
                     size_t ell, uint64_t q, bool reversed) {
  __int128 acc = 0;
  for (size_t i = 0; i < ell; ++i) {
    const int64_t d = center(digits[i], q);
    const uint64_t g = reversed ? gadget[i] : gadget[ell - 1 - i];
    acc += static_cast<__int128>(d) * static_cast<__int128>(g);
  }
  int64_t m = static_cast<int64_t>(acc % static_cast<__int128>(q));
  if (m < 0) m += static_cast<int64_t>(q);
  return static_cast<uint64_t>(m);
}

double log2_or_zero(double x) { return x <= 0.0 ? 0.0 : std::log2(x); }
}  // namespace

void PirTest::test_approx_decomp() {
  print_func_name(__FUNCTION__);

  PirParams pir_params;
  const uint64_t q = pir_params.get_rns_mods()[0];
  const size_t q_bits = pir_params.get_ct_mod_width();
  const std::vector<uint64_t> qs = {q};
  const size_t ell = 4;
  const size_t trials = 200000;

  BENCH_PRINT("q_bits=" << q_bits << ", q=" << q << ", ell=" << ell
               << ", trials=" << trials);
  BENCH_PRINT("exact base_log2 = ceil(q_bits/ell) = "
               << pir_params.get_base_log2_for(ell));
  PRINT_BAR;

  std::mt19937_64 rng(0xC0FFEE);
  std::uniform_int_distribution<uint64_t> dist(0, q - 1);

  // Sweep b: b >= ceil(q_bits/ell) is exact; smaller b drops low bits (approx).
  for (size_t b : {15u, 14u, 13u, 12u, 11u, 10u, 8u}) {
    if (ell * b > 64) continue;  // keep digit math in int64
    const bool approx = ell * b < q_bits;
    const size_t drop = approx ? q_bits - ell * b : 0;

    const std::vector<uint64_t> gad =
        (approx ? utils::gsw_gadget_approx(ell, b, q_bits, qs)
                : utils::gsw_gadget(ell, b, qs))[0];

    int64_t max_err = 0;
    double sum_sq = 0.0;
    uint64_t digits[16];
    for (size_t t = 0; t < trials; ++t) {
      const uint64_t v = dist(rng);
      if (approx) {
        bvks::approx_signed_gadget_decompose(v, b, q, q_bits, digits, ell);
      } else {
        bvks::signed_gadget_decompose(v, b, q, digits, ell);
      }
      const uint64_t r = reconstruct(digits, gad, ell, q, /*reversed=*/false);
      const int64_t err = center((r + q - v) % q, q);
      const int64_t ae = std::llabs(err);
      if (ae > max_err) max_err = ae;
      sum_sq += static_cast<double>(err) * static_cast<double>(err);
    }

    const double rms = std::sqrt(sum_sq / trials);
    BENCH_PRINT((approx ? "approx" : "exact ")
                 << " b=" << b << " (cover " << ell * b << "/" << q_bits
                 << ", drop " << drop << "): max|err|=2^"
                 << log2_or_zero(static_cast<double>(max_err)) << " rms=2^"
                 << log2_or_zero(rms) << "  bound 2^"
                 << (drop > 0 ? static_cast<double>(drop) - 1.0 : 0.0)
                 << (max_err <= (drop > 0 ? (int64_t{1} << (drop - 1)) : 0)
                         ? "  [OK]"
                         : "  [OVER BOUND]"));
  }

  PRINT_BAR;
  // Demonstrate the order convention: with EXACT decomposition the correct
  // pairing reconstructs perfectly, while the reversed pairing is garbage --
  // this is why decomp_rlwe_* reverses the digits before matching gadget rows.
  {
    const size_t b = pir_params.get_base_log2_for(ell);  // exact
    const std::vector<uint64_t> gad = utils::gsw_gadget(ell, b, qs)[0];
    int64_t max_ok = 0, max_rev = 0;
    uint64_t digits[16];
    for (size_t t = 0; t < 10000; ++t) {
      const uint64_t v = dist(rng);
      bvks::signed_gadget_decompose(v, b, q, digits, ell);
      max_ok = std::max<int64_t>(
          max_ok, std::llabs(center((reconstruct(digits, gad, ell, q, false) + q - v) % q, q)));
      max_rev = std::max<int64_t>(
          max_rev, std::llabs(center((reconstruct(digits, gad, ell, q, true) + q - v) % q, q)));
    }
    BENCH_PRINT("order check (exact): correct-pairing max|err|=2^"
                 << log2_or_zero((double)max_ok) << ", reversed-pairing max|err|=2^"
                 << log2_or_zero((double)max_rev) << " (reversed should be ~q=2^"
                 << q_bits << ")");
  }
}
