#include "tests.h"

#include <cstdio>
#include <limits>

/**
Original prompts:
Now, I want to make some algorithmic changes. Currently, OnionPIR is in a
server-stateful model, where we store the key materials (the galois keys and the
RGSW(-s)) on the server side. Sometimes, we want to consider another model,
where the clients send the key materials together with the query. Meaning that
each query generates new key materials. We call this “double stateless” model
because the server now no longer has to store the keys. This kills the
linkability of the clients and the keys, which is another layer of privacy we
want. I want to have this option to choose the server-stateful model and this
double stateless model. Here, let me describe what we can do to improve the
performance of OnionPIR in the double-stateless model.

First of all, in the server-stateful model, we always send a single query, which
later gets expanded in the query expanding phase. This gives us the minimal
query size. This is assuming that the galois keys (key-switching keys) are
stored in the server. In the double-stateless model, we can instead send
multiple queries to reduce the height of the expanding tree, meaning that we
need less key-switching keys. By doing so, it is possible to reduce the total
communication size (query size + galois key size + RGSW(s) size).  Here are some
math I came up with previously:

Suppose the number of entries is $N$. The first dimension size is $x$, the
second dimension size is $2^y$. We have the first equation: $N = x 2^y$. Suppose
we use $k$ galois keys, then given a query, we can expand it to $2^k$ BFV
ciphertexts. Let $u$ be the nubmer of queries we send. We can expand those $u$
ciphertexts to $2^k u$ many ciphertexts. With in these many ciphertext, we have
$x$ of them left for the first dimension multiplication, and $y \cdot \ell_{ep}$
left for other dimensions. Here, we have the second equation: $x + y \cdot
\ell_{ep} = 2^k u$. I derived that $N = (2^ku - y \ell_{gsw})2^y$. Is this
correct? One objective is to minimize this $y$, or maximize this $x$. This is
because larger first dimension size means fewer external products, which are
really small. Can you help me come up with a design for these parameter
settings? Ultimately, the database size should be one important global
parameter. Then, I think the number of queries can be a parameter as well. Or is
there a clever way to auto select? The goal is to minimize the total query size.

There should be another option in this double stateless model: we can avoid
using the RGSW(sk) key. Instead, we send fresh RGSW(b) for each subsequent
dimensions. By doing so, we would have smaller noise growth for external
products in subsequent dimensions. Though this is not so important now, we
should leave design space for it so that future changes can be easier.
*/

// Prints Pareto tables over num_other_dims for the three meaningful
// (QueryMode, GswSource) combinations. The user picks a row: smaller
// num_other_dims means fewer external products (higher throughput) but
// usually larger comm / tree_height; larger num_other_dims shrinks the
// first dim and tends to reduce comm in DoubleStateless.
//
// ---------------------------------------------------------------------------
// Parameters (consistent with PirParams naming)
// ---------------------------------------------------------------------------
//   target_num_pt   N  — total plaintexts in the database. Fixed input.
//   fst_dim_sz      x  — first-dimension size, in plaintexts. The first dim
//                        is evaluated as a plaintext-ciphertext matrix-vector
//                        multiply; larger x means fewer subsequent external
//                        products (so better throughput).
//   num_other_dims  y  — number of subsequent (log-folded) dimensions, each
//                        of size 2. Equals num_dims - 1. Each contributes one
//                        GSW×RLWE external product to the server work.
//   tree_height     k  — depth of the per-query expansion tree. One packed
//                        BFV query unpacks into 2^k independent RLWE slots.
//   num_queries     u  — independent BFV queries sent per request. Stateful
//                        forces u = 1; DoubleStateless may use u > 1 to
//                        reduce k (fewer galois keys) at the cost of more
//                        query ciphertexts.
//   L_EP               — gadget length for subsequent-dim external products.
//                        Each GSW ciphertext has 2·L_EP rows.
//   L_KEY              — gadget length for RGSW(s). Each RGSW(s) has 2·L_KEY
//                        rows.
//   L_KS               — gadget length for BV key-switch / galois keys. Each
//                        galois key is L_KS RLWE ciphertexts (one per gadget
//                        level).
//   bfv_bytes          — size of one seed-compressed BFV ciphertext (bytes).
//
// ---------------------------------------------------------------------------
// Combos (QueryMode × GswSource)
// ---------------------------------------------------------------------------
//   (1) Stateful + FromExpansion        — baseline; u=1, keys server-resident
//                                         so comm is just the query.
//   (2) DoubleStateless + FromExpansion — keys+RGSW(s) shipped per-request;
//                                         server still promotes expanded
//                                         BFV bits to GSW via query_to_gsw,
//                                         which costs y·L_EP expansion slots.
//   (3) DoubleStateless + FromFreshSend — keys + fresh y·GSW(b) ciphertexts
//                                         per-request; no RGSW(s), so no
//                                         y·L_EP expansion overhead (the
//                                         expansion only needs to cover x).
//
// ---------------------------------------------------------------------------
// Constraints (u ≥ 1, integer)
// ---------------------------------------------------------------------------
//   FromExpansion:    u · 2^k ≥ x + y · L_EP   (expand covers first-dim
//                                               selectors + GSW conversion)
//   FromFreshSend: u · 2^k ≥ x              (expand only covers first-dim
//                                               selectors; GSWs sent directly)
//   x · 2^y ≥ N                                (database coverage)
//
// ---------------------------------------------------------------------------
// Cost (in BFV-ciphertext units; seed-compressed sizing via bfv_bytes)
// ---------------------------------------------------------------------------
//   Stateful           : u                                  (just the query)
//   DblStateless + SK  : u + k · L_KS + 2 · L_KEY           (query + k galois
//                                                           keys + RGSW(s))
//   DblStateless + Bit : u + k · L_KS + 2 · y · L_EP        (query + k galois
//                                                           keys + y GSW(b))

namespace {

enum class Combo { Stateful_SK, DblStateless_SK, DblStateless_Bit };

struct Row {
  size_t num_other_dims = 0;
  size_t tree_height = 0;
  size_t num_queries = 0;
  size_t fst_dim_sz = 0;
  double comm_bytes = std::numeric_limits<double>::infinity();
  bool feasible = false;
};

// For a fixed num_other_dims, find the min-cost (tree_height, num_queries).
// Stateful forces num_queries = 1 and ties on tree_height.
// DoubleStateless breaks ties on tree_height then num_queries.
Row best_for_y(Combo combo, size_t y,
               size_t target_num_pt, size_t L_EP, size_t L_KEY, size_t L_KS,
               size_t bfv_bytes) {
  constexpr size_t MAX_K = 10;
  constexpr size_t MAX_U = 64;

  const bool stateful = (combo == Combo::Stateful_SK);
  const bool from_sk  = (combo != Combo::DblStateless_Bit);
  const size_t reserved_for_gsw = from_sk ? (y * L_EP) : 0;

  Row best;
  best.num_other_dims = y;
  double best_cost = std::numeric_limits<double>::infinity();
  size_t best_k = ~size_t{0};

  for (size_t k = 1; k <= MAX_K; k++) {
    const size_t slots_per_u = size_t{1} << k;
    for (size_t u = 1; u <= (stateful ? size_t{1} : MAX_U); u++) {
      const size_t slots = u * slots_per_u;
      if (slots <= reserved_for_gsw) continue;
      const size_t fst_dim_sz = slots - reserved_for_gsw;

      if (y >= 64) continue;
      const size_t covered = fst_dim_sz << y;
      if ((covered >> y) != fst_dim_sz) continue;
      if (covered < target_num_pt) continue;

      double cost_bfv;
      switch (combo) {
        case Combo::Stateful_SK:
          cost_bfv = static_cast<double>(u);
          break;
        case Combo::DblStateless_SK:
          cost_bfv = static_cast<double>(u) + k * L_KS + 2.0 * L_KEY;
          break;
        case Combo::DblStateless_Bit:
          cost_bfv = static_cast<double>(u) + k * L_KS + 2.0 * y * L_EP;
          break;
      }

      const bool improves =
          (cost_bfv < best_cost) ||
          (cost_bfv == best_cost && k < best_k);
      if (improves) {
        best_cost = cost_bfv;
        best_k = k;
        best.feasible = true;
        best.tree_height = k;
        best.num_queries = u;
        best.fst_dim_sz = fst_dim_sz;
        best.comm_bytes = cost_bfv * bfv_bytes;
      }
    }
  }
  return best;
}

void print_table(const char *label, Combo combo,
                 size_t target_num_pt, size_t L_EP, size_t L_KEY, size_t L_KS,
                 size_t bfv_bytes) {
  constexpr size_t MAX_Y = 20;
  std::printf("  %s\n", label);
  std::printf("    %-3s  %-3s  %-3s  %-8s  %-10s\n",
              "y", "k", "u", "fst_dim", "comm (KB)");
  for (size_t y = 0; y <= MAX_Y; y++) {
    Row r = best_for_y(combo, y, target_num_pt, L_EP, L_KEY, L_KS, bfv_bytes);
    if (!r.feasible) continue;
    std::printf("    %-3zu  %-3zu  %-3zu  %-8zu  %10.2f\n",
                r.num_other_dims, r.tree_height, r.num_queries,
                r.fst_dim_sz, r.comm_bytes / 1024.0);
  }
  std::printf("\n");
}

}  // namespace

void PirTest::plan_params() {
  PirParams pir_params;
  const size_t target_num_pt = pir_params.get_num_pt();
  const size_t L_EP = pir_params.get_l();
  const size_t L_KEY = pir_params.get_l_key();
  const size_t L_KS  = DBConsts::L_KS;
  const size_t bfv_bytes = pir_params.get_BFV_size(/*use_seed=*/true);

  std::printf("plan_params: Pareto over num_other_dims (y)\n");
  std::printf("  target_num_pt = %zu, L_EP = %zu, L_KEY = %zu, L_KS = %zu, "
              "BFV size = %zu B (seed-compressed)\n",
              target_num_pt, L_EP, L_KEY, L_KS, bfv_bytes);
  std::printf("  smaller y ⇒ fewer external products (higher throughput); "
              "smaller comm ⇒ cheaper per-request\n");
  std::printf("  pick a row per combo based on your (throughput, comm) budget\n\n");

  print_table("Stateful + FromExpansion",
              Combo::Stateful_SK, target_num_pt, L_EP, L_KEY, L_KS, bfv_bytes);
  print_table("DoubleStateless + FromExpansion",
              Combo::DblStateless_SK, target_num_pt, L_EP, L_KEY, L_KS, bfv_bytes);
  print_table("DoubleStateless + FromFreshSend",
              Combo::DblStateless_Bit, target_num_pt, L_EP, L_KEY, L_KS, bfv_bytes);
}
