#include "tests.h"
#include <cmath>

namespace {
// Shared checks for a DMux-expanded one-hot: the target slot decrypts to 1 (with
// its noise budget) and an off-target slot decrypts to 0. `label` distinguishes
// the trivial vs real-query variants.
void check_dmux_onehot(const std::string &label, PirClient &client,
                       const std::vector<RlweCt> &dmux_q, size_t col_idx,
                       size_t fst_dim_sz) {
  BENCH_PRINT(label << " target slot " << col_idx << " noise budget: "
               << client.noise_budget(dmux_q[col_idx]) << " bits");
  BENCH_PRINT(label << " target slot coeff[0]: "
               << client.decrypt_ct(dmux_q[col_idx]).data[0] << " (expected 1)");
  const size_t other = (col_idx + 1) % fst_dim_sz;
  BENCH_PRINT(label << " off-target slot " << other << " coeff[0]: "
               << client.decrypt_ct(dmux_q[other]).data[0] << " (expected 0)");
}
}  // namespace

void PirTest::test_fast_expand_query() {
  print_func_name(__FUNCTION__);

  // In this test, I want to make sure if the fast_expand_query is working as expected.
  // There are two ways to order the even and odd parts of a polynomial in the expanding process.
  // One way (the normal way) is to put the even part in it's own location, and the odd part is shifted by expansion tree level size.
  // The other way (the fast way) is to put the even part in 2b and the odd part in 2b + 1.
  // Both of them expand like a binary tree, but the order of the resulting polynomial is different.
  // Here is the access pattern of the normal expansion: https://raw.githubusercontent.com/chenyue42/images-for-notes/master/uPic/expansion.png
  // And the fast expansion will look like a noremal binary tree.


  PirParams pir_params;
  std::stringstream query_stream;
  const size_t fst_dim_sz = pir_params.get_fst_dim_sz();
  const size_t useful_cnt = fst_dim_sz + pir_params.get_l() * (pir_params.get_num_dims() - 1);

  PirClient client(pir_params);
  PirServer server(pir_params);
  const size_t client_id = client.get_client_id();

  pir_params.print_params();

  // ============= setup the server ==============
  std::stringstream gsw_stream;
  //--------------------------------------------------------------------------------
  server.set_client_bv_galois_key(client_id, client.create_bv_galois_keys());
  server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

  // ============ test initial noise ==============
  // Fresh BFV noise budget, measured (not hardcoded) so the analytic prediction
  // below adapts when q / t / sigma / N change. The DMux root is a fresh BFV, so
  // this is the budget the expansion starts from.
  const double fresh_budget = client.noise_budget(client.fresh_zero_ct());
  BENCH_PRINT("fresh zero noise budget: " << fresh_budget << " bits");

  // ============= Generate the query ==============
  const size_t query_idx = std::rand() % pir_params.get_num_pt();
  RlweCt fast_query = client.fast_generate_query(query_idx);

  {
    auto fast_decrypted = client.decrypt_ct(fast_query);
    const size_t expan_height = pir_params.get_expan_height();
    const size_t reversed = utils::bit_reverse(query_idx % fst_dim_sz, expan_height);
    BENCH_PRINT("fast query: expected nonzero at reversed=" << reversed
                 << ", got coeff[" << reversed << "]=" << fast_decrypted.data[reversed]);
  }
  PRINT_BAR;

  // ============= Expand the query ==============
  auto fast_exp_q = server.fast_expand_qry(client_id, fast_query);

  BENCH_PRINT("fast_exp_q noise budget: " << client.noise_budget(fast_exp_q[query_idx % fst_dim_sz]) << " bits");

  std::vector<RlwePt> fast_exp_pt;
  for (size_t i = 0; i < useful_cnt; i++) {
    fast_exp_pt.push_back(client.decrypt_ct(fast_exp_q[i]));
  }
  BENCH_PRINT("fast expanded query coeff[0]: " << fast_exp_pt[query_idx % fst_dim_sz].data[0]);
  PRINT_BAR;

  // ===== Timing & size: Galois (fast_expand_qry) vs DMux (external product) ===
  // DMux splits real BFV ciphertexts with fresh RGSW selectors via
  //   DMux(c, C) = (c - EP(C, c), EP(C, c)).
  // The client resolves the top `m` first-dim bits by shipping a 2^m one-hot of
  // *real* BFV ciphertexts, so only h-m selectors finish the tree. Larger m
  // saves RGSW selectors (each is 2*dmux_l BFV ciphertexts) at the cost of more
  // (but individually tiny) BFV ciphertexts. We time both routes and print the
  // DMux query size at each m so the size trade-off is visible.
  //
  // Note: fast_expand_qry expands the *whole* packed query (first dim + the
  // other-dim GSW rows); dmux_expand_qry here expands only the first dimension.
  {
    const size_t col_idx = query_idx % fst_dim_sz;
    const size_t h = std::bit_width(fst_dim_sz) - 1;  // fst_dim_sz == 2^h
    const size_t dmux_l = 4;

    // --- Galois route (expands the whole packed query) ---
    server.fast_expand_qry(client_id, fast_query);  // warm up
    TIME_ONCE_START("Galois fast_expand_qry");
    auto galois_q = server.fast_expand_qry(client_id, fast_query);
    TIME_ONCE_END("Galois fast_expand_qry");
    PRINT_ONCE("Galois fast_expand_qry");

    // --- DMux route at several skip levels m (first dimension only) ---
    // Each level skipped drops one RGSW selector (2*dmux_l BFV cts) but doubles
    // the BFV one-hot, so query size has a sweet spot before 2^m takes over.
    // Note: skipping *top* levels barely changes compute — those levels have the
    // smallest frontiers (work per level grows toward the leaves).
    const size_t bfv_bytes = pir_params.get_BFV_size(/*use_seed=*/false);
    const size_t sel_bytes = 2 * dmux_l * pir_params.get_BFV_size(/*use_seed=*/true);
    for (size_t m = 1; m <= 6 && m <= h; ++m) {
      auto query = client.generate_dmux_query(query_idx, m);
      auto sel = client.generate_dmux_selectors(query_idx, dmux_l, m);
      const std::string label = "DMux m=" + std::to_string(m) + " expand";

      server.dmux_expand_qry(query, sel, dmux_l);  // warm up
      TIME_ONCE_START(label);
      auto dmux_q = server.dmux_expand_qry(query, sel, dmux_l);
      TIME_ONCE_END(label);

      // Correctness: still a one-hot at col_idx.
      check_dmux_onehot("DMux m=" + std::to_string(m), client, dmux_q, col_idx,
                        fst_dim_sz);
      PRINT_ONCE(label);
      const double q_kb =
          ((size_t{1} << m) * bfv_bytes + sel.size() * sel_bytes) / 1024.0;
      BENCH_PRINT("  query = " << (size_t{1} << m) << " BFV + " << sel.size()
                   << " sel = " << q_kb << " KB");
    }
  }
  PRINT_BAR;

  // ===== Deep DMux expansion: noise vs number of levels r =====================
  // dmux_expand_qry doesn't depend on fst_dim_sz, so we can drive an arbitrary
  // number of levels r from a single real BFV(1) root + r RGSW(bit) selectors
  // (PirTest is a friend, so it encrypts the bit pattern directly). This tests
  // the bound from codex_resp/noise_bounds.py: DMux budget stays ~flat (noise is
  // linear in r), while a Galois route would lose ~1 bit/level (noise ~4^r) and
  // the two cross near r=10 at equal size (dmux_l=4 vs L_KS=8). We push to r=12.
  // The predicted budget = 41 - 0.5*log2(1 + r*l*N*B^2/2), B = 2^base_log2.
  // NOTE: produces 2^r ciphertexts (r=12 -> 4096).
  {
    constexpr size_t N = DBConsts::PolyDegree;
    for (size_t dmux_l : {4u, 8u}) {
      GSWEval dmux_gsw(pir_params, dmux_l, pir_params.get_base_log2_for(dmux_l));
      const double B = std::pow(2.0, (double)pir_params.get_base_log2_for(dmux_l));
      for (size_t r : {3u, 6u, 9u, 12u}) {
        // Arbitrary MSB-first target index in [0, 2^r): the 0b0101... pattern.
        const size_t target = ((size_t{1} << r) - 1) / 3;
        std::vector<size_t> bits(r);
        for (size_t j = 0; j < r; ++j) bits[j] = (target >> (r - 1 - j)) & 1ULL;

        std::vector<RlweCt> query;
        query.push_back(client.fresh_bfv_ct(1));  // single real BFV(1) root
        auto sel = client.encrypt_selector_bits(bits, dmux_gsw);
        auto dmux_q = server.dmux_expand_qry(std::move(query), sel, dmux_l);

        const double pred = fresh_budget - 0.5 * std::log2(1.0 + (double)r * dmux_l * N * B * B / 2.0);
        const size_t other = (target + 1) % dmux_q.size();
        BENCH_PRINT("DMux r=" << r << " dmux_l=" << dmux_l << " (out=" << dmux_q.size()
                     << "): budget=" << client.noise_budget(dmux_q[target])
                     << " bits (bound " << pred << "), target[0]="
                     << client.decrypt_ct(dmux_q[target]).data[0] << " off[0]="
                     << client.decrypt_ct(dmux_q[other]).data[0]);
      }
    }
  }
  PRINT_BAR;

  // ===== Approximate gadget decomposition: noise vs base b (ell=4, r=12) ======
  // Exact decomposition forces base_log2 = ceil(ct_mod_width/ell) (b=15 for
  // ell=4), and that huge B=2^15 dominates the external-product noise. Approx
  // decomposition drops the low (ct_mod_width - ell*b) bits so b can be smaller
  // -- less gadget noise (~B^2) at the cost of a rounding error. noise_bounds.py
  // predicts an optimum near b=11 giving ~+3-4 bits over exact. Validate on a
  // real 12-level expansion (single BFV(1) root + 12 RGSW(bit) selectors).
  {
    constexpr size_t ell = 4;
    constexpr size_t r = 12;
    const size_t target = ((size_t{1} << r) - 1) / 3;  // 0b0101... pattern
    std::vector<size_t> bits(r);
    for (size_t j = 0; j < r; ++j) bits[j] = (target >> (r - 1 - j)) & 1ULL;
    const size_t other = (target + 1) % (size_t{1} << r);
    const size_t q_bits = pir_params.get_ct_mod_width();

    auto run = [&](const char *tag, size_t b, bool approx) {
      const size_t base_log2 = approx ? b : pir_params.get_base_log2_for(ell);
      GSWEval gsw(pir_params, ell, base_log2, approx);  // client-side selectors
      auto sel = client.encrypt_selector_bits(bits, gsw);
      std::vector<RlweCt> query;
      query.push_back(client.fresh_bfv_ct(1));
      auto dmux_q = server.dmux_expand_qry(std::move(query), sel, ell,
                                           approx ? b : 0);
      const size_t drop = ell * base_log2 >= q_bits ? 0 : q_bits - ell * base_log2;
      BENCH_PRINT(tag << " ell=" << ell << " b=" << base_log2 << " (cover "
                   << ell * base_log2 << "/" << q_bits << " bits, drop "
                   << drop << "): budget="
                   << client.noise_budget(dmux_q[target]) << " bits, target[0]="
                   << client.decrypt_ct(dmux_q[target]).data[0] << " off[0]="
                   << client.decrypt_ct(dmux_q[other]).data[0]);
    };

    run("exact ", 0, false);
    for (size_t b : {10u, 11u, 12u, 13u, 14u}) run("approx", b, true);
  }
}
