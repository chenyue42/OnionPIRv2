# Double-Stateless Multi-Query Client Design

**Status:** Paused — waiting on gadget-decomposition resolution before implementation.
**Scope:** Client-side query generation for the new `DoubleStateless` mode with `num_queries > 1`.
**Date:** 2026-04-21

---

## 1. Background

In the **Stateful** mode, the server already holds the client's galois keys and RGSW(s), so
each request is a single BFV query ciphertext. The client always emits exactly one
`RlweCt`.

In the **DoubleStateless** mode the client re-ships key material every request
(galois keys + either RGSW(s) or per-dim RGSW(b)). To amortize that fixed cost, we pack
`num_queries = u` independent PIR queries into a single expansion tree and share one
galois-key set across all of them. This is the knob that makes the Pareto frontier in
`plan_params` non-degenerate.

Math recap (from the earlier chat):
- `fst_dim_sz` (x) first-dim selector bits
- `num_other_dims` (y) subsequent dims
- `tree_height` (k) expansion-tree height per query
- `L_EP` gadget length for each GSW entry
- `num_queries` (u)
- Constraint: `fst_dim_sz + num_other_dims · L_EP ≤ u · 2^k`
- Database size: `num_pt = fst_dim_sz · 2^num_other_dims`

Naming is already in place in `pir.h`:
- `get_num_queries()` → `DBConsts::NumQueries`
- `get_num_other_dims()` → `num_dims_ - 1`
- `get_query_mode()`, `get_gsw_source()`
Names were chosen for consistency with the rest of the codebase; `num_queries`
does not conflict with anything in the tree (grep'd earlier).

## 2. Global-slot layout

Across the `u` queries we have `u · 2^k` total expansion slots arranged as one
contiguous address space:

```
global slot index g ∈ [0, u · 2^k)
  ├─ [0,           fst_dim_sz)                    → first-dim selector bits
  ├─ [fst_dim_sz,  fst_dim_sz + num_other_dims·L_EP) → gadget slots for GSW material
  └─ […rest…]                                     → padding (zero)
```

Mapping rule:
```
q_idx  = g / 2^k          // which of the u queries
local  = g % 2^k          // slot within that query's tree
coeff_idx = bit_reverse(local, k)   // where coefficient lands in the BFV polynomial
```

This keeps `fast_expand_qry` **unchanged per query** — each query is expanded in
isolation and the server simply concatenates the `u` expanded vectors to recover
the full selector/gadget stream.

When `u = 1` the layout collapses exactly to the current single-query behavior.

## 3. Client API changes

**`fast_generate_query`:**
```cpp
// before
RlweCt fast_generate_query(const size_t pt_idx);
// after
std::vector<RlweCt> fast_generate_query(const std::vector<size_t> &pt_idx);
```
Returns a vector of length `num_queries`. For single-query configs this is a
vector of size 1.

**`add_gsw_to_query` → `add_gsw_to_queries`:**
```cpp
void add_gsw_to_queries(std::vector<RlweCt> &queries,
                       const std::vector<std::vector<size_t>> &query_indices);
```
Per-pt `query_indices[q]` still contains `[col_idx, bit₀, bit₁, …]`; we route
each gadget slot to the correct `(q_idx, coeff_idx)` pair.

**Galois keys:** one set shared across all `u` queries (same sk, same rotations).

## 4. Server-side concatenation

`fast_expand_qry` is called `u` times, once per returned `RlweCt`. The caller
concatenates outputs:
```
expanded_bfv_vec = concat( expand(q_0), expand(q_1), …, expand(q_{u-1}) )
```
The first `fst_dim_sz` entries drive the first-dim matmul; the next
`num_other_dims · L_EP` entries are promoted to RGSW (for `FromExpansion`) or
already carry the GSW rows (for `FromFreshSend`).

## 5. Open questions (need user confirmation)

1. **Always return `std::vector<RlweCt>`?** Even in Stateful/u=1, the uniform
   API is cleaner. Alternative: keep the old single-return for u=1.
2. **Server-side concatenation — caller loop or inside `fast_expand_qry`?**
   Caller loop keeps the expansion primitive simple; the cost is a short loop
   at every call site.
3. **Path guard:** should we `assert(u == 1)` when `Mode == Stateful`, or
   silently accept u>1 in Stateful too? Current thinking: hard assert — u>1
   without double-stateless has no purpose and would only obscure misconfig.

## 6. Prerequisite: gadget decomposition

Implementation is paused until we pick the gadget-decomposition scheme.
TFHE-rs exposes an **approximate** signed decomposition
(`SignedDecomposer` in `/u/yuec12/tfhe-rs/tfhe/src/core_crypto/commons/math/decomposition/`)
where `B^l ≤ q` — the low bits drop off and noise is absorbed into the
already-noisy LSBs. That choice affects `L_EP`, `L_KEY`, and the
communication model used in `plan_params`, so we resolve it first.
