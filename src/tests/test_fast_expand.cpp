#include "tests.h"
#include "bv_keyswitch.h"
#include <bit>
#include <chrono>
#include <random>

// Query-expansion comparison for the DoubleStateless mode (no server-resident
// keys -- the client ships everything fresh, per query). We expand a single root
// into a 2^r one-hot two ways and compare across depth r:
//
//   DMux : 1 real BFV(1) root + r RGSW(bit) selectors, external-product split.
//          gsw_l = 4 with APPROXIMATE decomposition (small selectors). We avoid
//          gsw_l = 8: it doubles selector size and blows the 1MB query budget.
//   KS   : 1 BFV query + r fresh BV-Galois keys, automorphism/key-switch split.
//          (Spiral-style coefficient expansion; capped at r <= log2(N) since it
//          extracts coefficients and there are only N of them.)
//
// Both cost 8 rows per level here (2*gsw_l == L_KS == 8), so the query size is
// the same; the interesting differences are noise budget, compute time, and the
// r <= log2(N) cap on KS. Output coefficients are hidden unless wrong.

namespace {
using clk = std::chrono::steady_clock;
double ms_since(clk::time_point t0) {
  return std::chrono::duration<double, std::milli>(clk::now() - t0).count();
}
}  // namespace

void PirTest::test_fast_expand_query() {
  print_func_name(__FUNCTION__);

  PirParams pir_params;
  pir_params.print_params();
  PirClient client(pir_params);
  PirServer server(pir_params);

  constexpr size_t N = DBConsts::PolyDegree;
  const size_t log2N = std::bit_width(N) - 1;           // KS cap: r <= log2N
  const uint64_t q = pir_params.get_rns_mods()[0];
  const uint64_t t = pir_params.get_plain_mod();
  const double sigma = pir_params.get_noise_std_dev();
  const std::vector<uint64_t> qs = {q};

  const double fresh_budget = client.noise_budget(client.fresh_zero_ct());

  const size_t dmux_l = 4;          // small selectors (gsw_l)
  const size_t approx_b = 11;       // optimal approx base for this q (drop 14); see approx_decomp
  const size_t bfv_seed = pir_params.get_BFV_size(/*use_seed=*/true);  // one seeded RLWE row
  auto kb = [&](size_t rows) { return (1 + rows) * bfv_seed / 1024.0; };  // +1 = root

  std::mt19937_64 rng(std::random_device{}());

  BENCH_PRINT("fresh budget = " << fresh_budget << " bits | dmux_l=" << dmux_l
               << " (approx b=" << approx_b << ") | L_KS=" << bvks::L_KS
               << " | seeded row=" << bfv_seed / 1024.0 << " KB");
  BENCH_PRINT("");
  BENCH_PRINT("   r | method | time (ms) | noise (bits) | query (KB) | <1MB | check");
  BENCH_PRINT("  ----------------------------------------------------------------------");

  for (size_t r = 8; r <= 12; ++r) {
    const size_t one_hot = size_t{1} << r;
    const size_t target = rng() % one_hot;            // randomized index
    const size_t off = (target + 1) % one_hot;
    char row[256];

    // ============================ DMux ============================
    {
      std::vector<size_t> bits(r);
      for (size_t j = 0; j < r; ++j) bits[j] = (target >> (r - 1 - j)) & 1ULL;  // MSB-first
      GSWEval gsw(pir_params, dmux_l, approx_b, /*approx=*/true);
      auto sel = client.encrypt_selector_bits(bits, gsw);
      std::vector<RlweCt> root;
      root.push_back(client.fresh_bfv_ct(1));

      const auto t0 = clk::now();
      auto out = server.dmux_expand_qry(std::move(root), sel, dmux_l, approx_b);
      const double tms = ms_since(t0);

      const int nb = client.noise_budget(out[target]);
      const double sz = kb(r * 2 * dmux_l);
      const uint64_t got = client.decrypt_ct(out[target]).data[0];
      const uint64_t bad = client.decrypt_ct(out[off]).data[0];
      char chk[64];
      if (got == 1 && bad == 0) std::snprintf(chk, sizeof(chk), "ok");
      else std::snprintf(chk, sizeof(chk), "WRONG got=%llu off=%llu",
                         (unsigned long long)got, (unsigned long long)bad);
      std::snprintf(row, sizeof(row),
                    "  %2zu | DMux   | %9.1f | %12d | %10.1f | %-4s | %s",
                    r, tms, nb, sz, sz < 1024 ? "yes" : "no", chk);
      BENCH_PRINT(row);
    }

    // ============================ KS (Galois) ============================
    if (r <= log2N) {
      // Query: a single nonzero coeff at bit_reverse(target,r), pre-scaled by
      // (2^r)^{-1} so the 2^r expansion multiplicity cancels back to BFV(1).
      uint64_t inv = 0;
      utils::try_invert_uint_mod(one_hot, t, inv);
      const uint64_t scaled = utils::round_div_u128((uint128_t)q * inv, t) % q;
      RlweCt query;
      encrypt_zero_rns(client.rlwe_sk_, N, qs, sigma, rng, query, /*ntt_form=*/false);
      const size_t rev = utils::bit_reverse(target, r);
      query.c0[rev] = (query.c0[rev] + scaled) % q;

      // Fresh BV-Galois keys for levels j=0..r-1 (galois_k = N/2^j + 1).
      std::vector<bvks::BvKeySwitchKey> gkeys(r);
      for (size_t j = 0; j < r; ++j) {
        gkeys[j] = bvks::gen_bv_ks_key(pir_params, client.rlwe_sk_,
                                       static_cast<uint32_t>((N >> j) + 1), rng);
      }

      const auto t0 = clk::now();
      std::vector<RlweCt> level;
      level.push_back(std::move(query));
      for (size_t j = 0; j < r; ++j) {
        const uint32_t gk = static_cast<uint32_t>((N >> j) + 1);
        const size_t shift = static_cast<size_t>(-(int64_t)(size_t{1} << j));
        std::vector<RlweCt> next;
        next.reserve(level.size() * 2);
        for (auto &c : level) {
          RlweCt cp = c;
          bvks::bv_apply_galois_inplace(cp, gk, gkeys[j], pir_params);
          RlweCt even;
          rlwe_add_k(c, cp, even, qs, N);            // even = c + sigma(c)
          rlwe_sub_inplace_k(c, cp, qs, N);          // c    = c - sigma(c)
          RlweCt odd;
          rlwe_shift_k(c, odd, shift, qs, N);        // odd  = X^-k (c - sigma(c))
          next.push_back(std::move(even));
          next.push_back(std::move(odd));
        }
        level = std::move(next);
      }
      const double tms = ms_since(t0);

      const int nb = client.noise_budget(level[target]);
      const double sz = kb(r * bvks::L_KS);
      const uint64_t got = client.decrypt_ct(level[target]).data[0];
      const uint64_t bad = client.decrypt_ct(level[off]).data[0];
      char chk[64];
      if (got == 1 && bad == 0) std::snprintf(chk, sizeof(chk), "ok");
      else std::snprintf(chk, sizeof(chk), "WRONG got=%llu off=%llu",
                         (unsigned long long)got, (unsigned long long)bad);
      std::snprintf(row, sizeof(row),
                    "  %2zu | KS     | %9.1f | %12d | %10.1f | %-4s | %s",
                    r, tms, nb, sz, sz < 1024 ? "yes" : "no", chk);
      BENCH_PRINT(row);
    } else {
      std::snprintf(row, sizeof(row),
                    "  %2zu | KS     | %9s | %12s | %10s | %-4s | n/a (r > log2(N)=%zu)",
                    r, "-", "-", "-", "-", log2N);
      BENCH_PRINT(row);
    }
  }
}
