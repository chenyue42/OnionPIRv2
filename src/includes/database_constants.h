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
//   -DACTIVE_CONFIG=CONFIG_N2048_M28_28 -DVARIANT=VARIANT_MP
// ----------------------------------------------------------------------------

// --- 1) Parameter set ---
// Naming: CONFIG_N{poly_degree}_M{prime_bit_widths joined by _}.
// The number of primes is K (= the RNS limb count). Total log Q is the sum
// of the prime widths. Status legend below: ✓ working end-to-end, △ partial,
// ✗ not yet implemented.
//
//   CONFIG_N2048_M60           K=1, N=2048,  log Q = 60.   ✓ PIR works (VARIANT_MP).
//   CONFIG_N2048_M28_28        K=2, N=2048,  log Q ≈ 56.   ✓ PIR works (VARIANT_MP, signed MP-gadget).
//
// N=4096 configs are commented out for now — the active draft only targets N=2048.
//   CONFIG_N4096_M60_60        K=2, N=4096,  log Q ≈ 120.  (disabled)
//   CONFIG_N4096_M28_28_28_28  K=4, N=4096,  log Q ≈ 112.  (disabled, needs RNS-hybrid)
#define CONFIG_N2048_M60          0
#define CONFIG_N2048_M28_28       1
// #define CONFIG_N4096_M60_60       2
// #define CONFIG_N4096_M28_28_28_28 3
#ifndef ACTIVE_CONFIG
#define ACTIVE_CONFIG CONFIG_N2048_M60
#endif

// --- 2) Decomposition variant (covers both keyswitch and external product) ---
// Note: "RnsHybrid" here means per-limb digit extraction with gadget
// {g_k · B_k^i}, NOT the BV+GHS blend that SEAL/OpenFHE call "Hybrid".
//
//   VARIANT_MP          MP-gadget at K>1: CRT-compose to a single MP integer,
//                       signed base-B decomposition. ✓ K=1, ✓ K=2.
//   VARIANT_RNS_HYBRID  Per-limb signed digit extraction with gadget
//                       {g_k · B_k^i}. Smaller noise, more NTTs.
#define VARIANT_MP          0
#define VARIANT_RNS_HYBRID  1

#ifndef VARIANT
#define VARIANT VARIANT_MP
#endif

namespace DBConsts {

  enum class DecompVariant { MP, RnsHybrid };

#if VARIANT == VARIANT_MP
  constexpr DecompVariant Decomp = DecompVariant::MP;
#elif VARIANT == VARIANT_RNS_HYBRID
  constexpr DecompVariant Decomp = DecompVariant::RnsHybrid;
#else
  #error "Unknown VARIANT"
#endif

  // ==========================================================================
  // Constants common to all configs
  // ==========================================================================
  constexpr size_t DB_SIZE_MB = 128;
  constexpr double NoiseStdDev = 2.55;  // matches SEAL-For-OnionPIR default

  // First-dimension shape policy. See utils::calculate_db_shape.
  //   true : fst_dim_sz = largest power of two ≤ slack (OnionPIRv1 hypercube).
  //   false: fst_dim_sz = slack (every leftover expansion slot; non-power-of-2).
  // Tight packing raises DB capacity at the same num_dims but ups first-dim
  // matmul work; pow-2 keeps matmul cheap at the cost of more dims.
  constexpr bool FST_DIM_POW2 = true;

  // ==========================================================================
  // Per-config constants
  // ==========================================================================

#if ACTIVE_CONFIG == CONFIG_N2048_M60
  // Production-tested cell. K=1.
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 14;
  constexpr size_t SmallQWidth  = 22;
  constexpr std::array<size_t, 1> RnsMods = {60};

#elif ACTIVE_CONFIG == CONFIG_N2048_M28_28
  // K=2, same total Q (~60 bits) as N2048_M60.
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 10;
  constexpr size_t SmallQWidth  = 25;
  constexpr std::array<size_t, 2> RnsMods = {28, 28};

// N=4096 configs disabled for the N=2048-only draft. Re-enable by
// uncommenting the corresponding `#define` at the top of this file.
// #elif ACTIVE_CONFIG == CONFIG_N4096_M60_60
//   constexpr size_t PolyDegree   = 4096;
//   constexpr size_t L_EP         = 5;
//   constexpr size_t L_KEY        = 8;
//   constexpr size_t L_KS         = 8;
//   constexpr size_t TREE_HEIGHT  = 10;
//   constexpr size_t PlainMod     = 40;
//   constexpr size_t SmallQWidth  = 50;
//   constexpr std::array<size_t, 2> RnsMods = {60, 60};
//
// #elif ACTIVE_CONFIG == CONFIG_N4096_M28_28_28_28
//   constexpr size_t PolyDegree   = 4096;
//   constexpr size_t L_EP         = 5;
//   constexpr size_t L_KEY        = 8;
//   constexpr size_t L_KS         = 8;
//   constexpr size_t TREE_HEIGHT  = 10;
//   constexpr size_t PlainMod     = 30;
//   constexpr size_t SmallQWidth  = 50;
//   constexpr std::array<size_t, 4> RnsMods = {28, 28, 28, 28};

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

  // K=1: VARIANT_RNS_HYBRID degenerates to MP (single limb, no g_k factor).
  // Forbid the redundant build so benchmark cells don't double-count.
  static_assert(!(RnsMods.size() == 1 && Decomp == DecompVariant::RnsHybrid),
                "VARIANT_RNS_HYBRID is a no-op at K=1; use VARIANT_MP.");

  // The MP-gadget path uses 128-bit multi-precision integers per coefficient
  // (compose_rns_to_mp / decompose_mp_to_rns in gsw.cpp). That works for K ≤ 2
  // and total log Q ≤ 128 bits. K ≥ 3 needs RNS-hybrid.
  static_assert(!(RnsMods.size() >= 3 && Decomp == DecompVariant::MP),
                "VARIANT_MP only supports K ≤ 2; use VARIANT_RNS_HYBRID at K ≥ 3.");

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