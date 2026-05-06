#pragma once
#include <cstddef>
#include <cstdint>
#include <array>

typedef unsigned __int128 uint128_t;

// ============================================================================
// Build-time configuration selectors (orthogonal axes)
// ============================================================================
// Two independent macros, each with a default and an `#error` for unknown
// values. Override on the cmake/compile line with e.g.
//   -DACTIVE_CONFIG=CONFIG_N2048_M29_29 -DVARIANT=VARIANT_MP
// ----------------------------------------------------------------------------

// --- 1) Parameter set ---
// Naming: CONFIG_N{poly_degree}_K{rns_limb_count}[_{VARIANT}]. Each config
// carries its OWN gadget lengths and PlainMod since DecompVariant changes
// both RGSW size and noise growth — the K=2 cell is split into one config
// per variant. Keep config and variant in sync via the run.py aliases.
//   CONFIG_N2048_K1        K=1, N=2048, log Q ≈ 60.   Requires VARIANT_MP.
//   CONFIG_N2048_K2_MP     K=2, N=2048, log Q ≈ 58.   Requires VARIANT_MP.
//   CONFIG_N2048_K2_RNS    K=2, N=2048, log Q ≈ 58.   Requires VARIANT_RNS.
//   CONFIG_N4096_K2_MP     K=2, N=4096, log Q ≈ 120.  Requires VARIANT_MP.
//   CONFIG_N4096_K2_RNS    K=2, N=4096, log Q ≈ 120.  Requires VARIANT_RNS.
#define CONFIG_N2048_K1          0
#define CONFIG_N2048_K2_MP       1
#define CONFIG_N2048_K2_RNS      2
#define CONFIG_N4096_K2_MP       3
#define CONFIG_N4096_K2_RNS      4
#ifndef ACTIVE_CONFIG
#define ACTIVE_CONFIG CONFIG_N2048_K1
#endif

// --- 2) Decomposition variant (covers both keyswitch and external product) ---
//
//   VARIANT_MP    "Multi-Precision" gadget. At K>1 the K RNS limbs are first
//                 CRT-composed into a single multi-precision integer per
//                 coefficient, then signed base-B decomposition is applied.
//                 Single global base B = 2^base_log2. ✓ K=1, ✓ K=2.
//
//   VARIANT_RNS   "Residue Number System" gadget. Per-limb signed digit
//                 extraction with gadget {g_k · B_k^i} (g_k = CRT lift
//                 coefficient, B_k = per-limb base). RGSW grows from 2·l rows
//                 to 2·K·l rows in exchange for smaller per-digit base, so
//                 lower noise per external product at the cost of more NTTs.
//                 NOT the BV+GHS blend SEAL/OpenFHE call "Hybrid".
//                 Required for K ≥ 3 (MP doesn't fit in uint128 there).
#define VARIANT_MP   0
#define VARIANT_RNS  1

#ifndef VARIANT
#define VARIANT VARIANT_MP
#endif

namespace DBConsts {

  enum class DecompVariant { MP, RNS };

#if VARIANT == VARIANT_MP
  constexpr DecompVariant Decomp = DecompVariant::MP;
#elif VARIANT == VARIANT_RNS
  constexpr DecompVariant Decomp = DecompVariant::RNS;
#else
  #error "Unknown VARIANT"
#endif

  // ==========================================================================
  // Constants common to all configs
  // ==========================================================================
  constexpr size_t DB_SIZE_MB = 128;
  constexpr double NoiseStdDev = 2.55;  // matches Spiral & InsPIRe. 

  // First-dimension shape policy. See utils::calculate_db_shape.
  //   true : fst_dim_sz = largest power of two ≤ slack (OnionPIRv1 hypercube).
  //   false: fst_dim_sz = slack (every leftover expansion slot; non-power-of-2).
  // Tight packing raises DB capacity at the same num_dims but ups first-dim
  // matmul work; pow-2 keeps matmul cheap at the cost of more dims.
  constexpr bool FST_DIM_POW2 = true;

  // ==========================================================================
  // Per-config constants
  // ==========================================================================

#if ACTIVE_CONFIG == CONFIG_N2048_K1
  // Production-tested cell. K=1, log Q = 60.
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 14;
  constexpr size_t SmallQWidth  = 22;
  constexpr std::array<size_t, 1> RnsMods = {60};

#elif ACTIVE_CONFIG == CONFIG_N2048_K2_MP
  // K=2 with VARIANT_MP. Single CRT-composed gadget of base B = 2^(60/l) —
  // needs more digits than the RNS variant to keep B small.
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 10;
  constexpr size_t SmallQWidth  = 22;
  constexpr std::array<size_t, 2> RnsMods = {29, 29};

#elif ACTIVE_CONFIG == CONFIG_N2048_K2_RNS
  // K=2 with VARIANT_RNS. Per-limb gadgets of base B_k = 2^(29/l) are already
  // small with l=4, leaving more room in the noise budget for t.
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 3;
  constexpr size_t L_KEY        = 4;
  constexpr size_t L_KS         = 4;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 13;
  constexpr size_t SmallQWidth  = 22;
  constexpr std::array<size_t, 2> RnsMods = {29, 29};

#elif ACTIVE_CONFIG == CONFIG_N4096_K2_MP
  // K=2 with VARIANT_MP at N=4096. Total log Q ≈ 120 — fits in uint128, so MP
  // works (compose_rns_to_mp uses uint128). With max_ct_mod_width = 60, the
  // matmul falls back to the uint64→uint128 scalar path (AVX-512 fast path
  // requires uint32→uint64).
  constexpr size_t PolyDegree   = 4096;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 40;
  constexpr size_t SmallQWidth  = 50;
  constexpr std::array<size_t, 2> RnsMods = {60, 60};

#elif ACTIVE_CONFIG == CONFIG_N4096_K2_RNS
  // K=2 with VARIANT_RNS at N=4096. Per-limb gadget B_k = 2^(60/l). Smaller l
  // than the MP cell since RNS gives 2·K·l = 16 RGSW rows at l=4, equivalent
  // to MP at l=8. PlainMod stays at 40 — RNS noise ≤ MP noise at the same
  // effective row count.
  constexpr size_t PolyDegree   = 4096;
  constexpr size_t L_EP         = 4;
  constexpr size_t L_KEY        = 4;
  constexpr size_t L_KS         = 4;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 40;
  constexpr size_t SmallQWidth  = 50;
  constexpr std::array<size_t, 2> RnsMods = {60, 60};

#else
  #error "Unknown ACTIVE_CONFIG"
#endif


  // Max bit-width among ciphertext moduli.
  constexpr size_t max_ct_mod_width() {
    size_t w = 0;
    for (size_t i = 0; i < RnsMods.size(); i++)
      if (RnsMods[i] > w) w = RnsMods[i];
    return w;
  }

  // ==========================================================================
  // Sanity guards on (config, variant) combinations
  // ==========================================================================

  // Each named config pins the variant it expects (gadget lengths and
  // PlainMod were tuned for that variant). The run.py aliases set both
  // ACTIVE_CONFIG and VARIANT consistently.
#if ACTIVE_CONFIG == CONFIG_N2048_K1
  static_assert(Decomp == DecompVariant::MP,
                "CONFIG_N2048_K1 requires VARIANT_MP (RNS is a no-op at K=1).");
#elif ACTIVE_CONFIG == CONFIG_N2048_K2_MP
  static_assert(Decomp == DecompVariant::MP,
                "CONFIG_N2048_K2_MP requires VARIANT_MP.");
#elif ACTIVE_CONFIG == CONFIG_N2048_K2_RNS
  static_assert(Decomp == DecompVariant::RNS,
                "CONFIG_N2048_K2_RNS requires VARIANT_RNS.");
#elif ACTIVE_CONFIG == CONFIG_N4096_K2_MP
  static_assert(Decomp == DecompVariant::MP,
                "CONFIG_N4096_K2_MP requires VARIANT_MP.");
#elif ACTIVE_CONFIG == CONFIG_N4096_K2_RNS
  static_assert(Decomp == DecompVariant::RNS,
                "CONFIG_N4096_K2_RNS requires VARIANT_RNS.");
#endif

  // The MP-gadget path uses 128-bit multi-precision integers per coefficient
  // (compose_rns_to_mp / decompose_mp_to_rns in gsw.cpp). That works for K ≤ 2
  // and total log Q ≤ 128 bits. K ≥ 3 would need the RNS variant.
  static_assert(!(RnsMods.size() >= 3 && Decomp == DecompVariant::MP),
                "VARIANT_MP only supports K ≤ 2; use VARIANT_RNS at K ≥ 3.");

} // namespace DBConsts

// ============================================================================
// Per-coefficient storage and accumulator types
// ============================================================================
// Each ciphertext coefficient is stored as one uint64_t per RNS limb, so
// the storage type is uint64_t regardless of K. The first-dim matmul
// accumulator needs room for a single per-limb product (≤ 2 · max(rns_mod_bits))
// summed over fst_dim_sz; uint128_t covers all four configs.
// using db_coeff_t = uint64_t;
// using inter_coeff_t = uint128_t;
//  using db_coeff_t = uint32_t;
//  using inter_coeff_t = uint64_t;


// db_coeff_t: type for each NTT coefficient stored in the aligned database.
//   ≤32-bit moduli → uint32_t,  >32-bit → uint64_t.
using db_coeff_t = std::conditional_t<DBConsts::max_ct_mod_width() <= 32,
                                      uint32_t, uint64_t>;

// inter_coeff_t: accumulator for first-dimension matrix multiply & gadget arithmetic.
//   Must be wide enough for  fst_dim_sz × (db_coeff_t × db_coeff_t)  sums.
//   ≤32-bit moduli → uint64_t,  >32-bit → uint128_t.
using inter_coeff_t = std::conditional_t<DBConsts::max_ct_mod_width() <= 32,
                                         uint64_t, uint128_t>;