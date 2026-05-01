#pragma once
#include <cstddef>
#include <cstdint>
#include <array>

typedef unsigned __int128 uint128_t;

// ============================================================================
// Build-time configuration selectors (orthogonal axes)
// ============================================================================
// Three independent macros, each with a default and an `#error` for unknown
// values. Override on the cmake/compile line with e.g.
//   -DACTIVE_CONFIG=CONFIG_N2048_M28_28 -DKS_VARIANT=KS_BV -DEP_VARIANT=EP_VARIANT
// ----------------------------------------------------------------------------

// --- 1) Parameter set ---
// Naming: CONFIG_N{poly_degree}_M{prime_bit_widths joined by _}.
// The number of primes is K (= the RNS limb count). Total log Q is the sum
// of the prime widths. Status legend below: ✓ working end-to-end, △ partial,
// ✗ not yet implemented.
//
//   CONFIG_N2048_M60           K=1, N=2048,  log Q = 60.   ✓ PIR works (KS_BV).
//   CONFIG_N2048_M28_28        K=2, N=2048,  log Q ≈ 56.   ✓ PIR works (KS_BV, signed MP-gadget).
//   CONFIG_N4096_M60_60        K=2, N=4096,  log Q ≈ 120.  △ K-aware path runs; tighter noise budget.
//   CONFIG_N4096_M28_28_28_28  K=4, N=4096,  log Q ≈ 112.  ✗ RNS-hybrid only (per-limb math); not wired yet.
#define CONFIG_N2048_M60          0
#define CONFIG_N2048_M28_28       1
#define CONFIG_N4096_M60_60       2
#define CONFIG_N4096_M28_28_28_28 3
#ifndef ACTIVE_CONFIG
#define ACTIVE_CONFIG CONFIG_N2048_M60
#endif

// --- 2) Keyswitch variant ---
// Note: "RnsHybrid" here means per-limb digit extraction with gadget
// {g_k · B_k^i}, NOT the BV+GHS blend that SEAL/OpenFHE call "Hybrid".
//
//   KS_BV          BV-style keyswitch (MP-gadget at K>1: CRT-compose c1 to a
//                  single MP integer, signed base-B decomposition, NTT each
//                  digit per limb against the KSK). ✓ K=1, ✓ K=2.
//   KS_RNS_HYBRID  Per-limb digit extraction with gadget {g_k · B_k^i}.
//                  ✗ Not implemented yet — selecting this trips static_assert.
#define KS_BV          0
#define KS_RNS_HYBRID  1
#ifndef KS_VARIANT
#define KS_VARIANT KS_BV
#endif

// --- 3) External-product variant ---
#define EP_MP_GADGET   0   // CRT compose → global digit decomp → CRT decompose
#define EP_RNS_HYBRID  1   // per-limb digit extraction, gadget {g_k · B_k^i}
#ifndef EP_VARIANT
#define EP_VARIANT EP_MP_GADGET
#endif

namespace DBConsts {

  enum class KsVariant { BV, RnsHybrid };
  enum class EpVariant { MpGadget, RnsHybrid };

#if KS_VARIANT == KS_BV
  constexpr KsVariant Ks = KsVariant::BV;
#elif KS_VARIANT == KS_RNS_HYBRID
  constexpr KsVariant Ks = KsVariant::RnsHybrid;
#else
  #error "Unknown KS_VARIANT"
#endif

#if EP_VARIANT == EP_MP_GADGET
  constexpr EpVariant Ep = EpVariant::MpGadget;
#elif EP_VARIANT == EP_RNS_HYBRID
  constexpr EpVariant Ep = EpVariant::RnsHybrid;
#else
  #error "Unknown EP_VARIANT"
#endif

  // ==========================================================================
  // Constants common to all configs
  // ==========================================================================
  constexpr size_t DB_SIZE_MB = 128;
  constexpr double NoiseStdDev = 2.55;  // matches SEAL-For-OnionPIR default

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
  constexpr size_t PlainMod     = 13;
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

#elif ACTIVE_CONFIG == CONFIG_N4096_M60_60
  // K=2, log Q ≈ 120 bits. Larger N for matching depth budget.
  constexpr size_t PolyDegree   = 4096;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 25;
  constexpr size_t SmallQWidth  = 50;
  constexpr std::array<size_t, 2> RnsMods = {60, 60};

#elif ACTIVE_CONFIG == CONFIG_N4096_M28_28_28_28
  // K=4, total Q ≈ 120 bits. Per-limb math only — requires EP_RNS_HYBRID.
  constexpr size_t PolyDegree   = 4096;
  constexpr size_t L_EP         = 5;
  constexpr size_t L_KEY        = 8;
  constexpr size_t L_KS         = 8;
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 30;
  constexpr size_t SmallQWidth  = 50;
  constexpr std::array<size_t, 4> RnsMods = {28, 28, 28, 28};

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

  // K=1: both KS_RNS_HYBRID and EP_RNS_HYBRID degenerate to their non-hybrid
  // counterparts. Forbid the redundant builds so benchmark cells don't double-count.
  static_assert(!(RnsMods.size() == 1 && Ks == KsVariant::RnsHybrid),
                "KS_RNS_HYBRID is a no-op at K=1; use KS_BV.");
  static_assert(!(RnsMods.size() == 1 && Ep == EpVariant::RnsHybrid),
                "EP_RNS_HYBRID is a no-op at K=1; use EP_MP_GADGET.");

  // The MP-gadget path uses 128-bit multi-precision integers per coefficient
  // (compose_rns_to_mp / decompose_mp_to_rns in gsw.cpp). That works for K ≤ 2
  // and total log Q ≤ 128 bits. K ≥ 3 needs Approach B (RNS-hybrid) for both
  // KS and EP.
  static_assert(!(RnsMods.size() >= 3 && Ep == EpVariant::MpGadget),
                "EP_MP_GADGET only supports K ≤ 2; use EP_RNS_HYBRID at K ≥ 3.");
  static_assert(!(RnsMods.size() >= 3 && Ks == KsVariant::BV),
                "KS_BV (MP-gadget keyswitch) only supports K ≤ 2; use KS_RNS_HYBRID at K ≥ 3.");

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