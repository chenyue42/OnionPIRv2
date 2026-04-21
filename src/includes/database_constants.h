#pragma once
#include <cstddef>
#include <cstdint>
#include <array>
#include <type_traits>

typedef unsigned __int128 uint128_t;

// ============================================================================
// Configuration selector — change ACTIVE_CONFIG to switch parameters.
// ============================================================================
#define CONFIG_SINGLE_MOD_56  0   // 256 MB, log q = 56, single ct mod
#define CONFIG_TWO_MOD_56     1   // 256 MB, log q = 56, two ct mods
#define CONFIG_SINGLE_MOD_60  2   // 256 MB, log q = 60, single ct mod
#define CONFIG_POLY4096       3   // 256 MB, poly degree 4096

#define ACTIVE_CONFIG  CONFIG_SINGLE_MOD_60

// Primes for coeff_modulus, small_q, and plain_modulus are derived at runtime
// from the bit widths below via utils::generate_ntt_friendly_primes and
// utils::generate_prime.

namespace DBConsts {

  // ============================================================================
  // Query model selection
  // ============================================================================
  // Stateful:        galois keys + RGSW(s) sit on the server; client sends a
  //                  single BFV query per request. Minimum per-request comm.
  // DoubleStateless: every request carries its own galois keys (and either
  //                  RGSW(s) or per-dim RGSW(b)). Kills client↔key linkability
  //                  at the cost of larger per-request comm, but enables
  //                  multi-query expansion (num_queries > 1) to trade galois
  //                  keys for queries.
  enum class QueryMode { Stateful, DoubleStateless };

  // Where the GSW ciphertexts for subsequent dimensions come from:
  //   FromExpansion    — client sends RGSW(s); server uses query_to_gsw to
  //                      promote expanded BFV bits into GSW. Needs
  //                      num_other_dims * L_EP extra expansion slots.
  //   FromFreshSend — client sends fresh GSW(b_i) directly for each
  //                      subsequent dim. No RGSW(s). Expansion only produces
  //                      the first-dim query ciphertexts. Wins when
  //                      num_other_dims is small (< 2*L_KEY/L_EP).
  enum class GswSource { FromExpansion, FromFreshSend };

  constexpr size_t DB_SIZE_MB = 128;

#if ACTIVE_CONFIG == CONFIG_SINGLE_MOD_56
  // 256 MB, single ct mod, log q = 56
  constexpr size_t PolyDegree = 2048;
  constexpr size_t L_EP = 5;
  constexpr size_t L_KEY = 12;
  constexpr size_t L_KS = 8;
  constexpr size_t TREE_HEIGHT = 9;
  constexpr size_t NumQueries = 1;
  constexpr QueryMode Mode = QueryMode::Stateful;
  constexpr GswSource GswSrc = GswSource::FromExpansion;
  constexpr size_t PlainMod = 15;
  constexpr size_t SmallQWidth = 28;
  constexpr std::array<size_t, 1> CoeffMods = {56};

#elif ACTIVE_CONFIG == CONFIG_TWO_MOD_56
  // 256 MB, two ct mods, log q = 56
  constexpr size_t PolyDegree = 2048;
  constexpr size_t L_EP = 5;
  constexpr size_t L_KEY = 12;
  constexpr size_t L_KS = 8;
  constexpr size_t TREE_HEIGHT = 9;
  constexpr size_t NumQueries = 1;
  constexpr QueryMode Mode = QueryMode::Stateful;
  constexpr GswSource GswSrc = GswSource::FromExpansion;
  constexpr size_t PlainMod = 14;
  constexpr size_t SmallQWidth = 27;
  constexpr std::array<size_t, 2> CoeffMods = {28, 28};

#elif ACTIVE_CONFIG == CONFIG_SINGLE_MOD_60
  constexpr size_t PolyDegree = 2048;
  constexpr size_t L_EP = 5;
  constexpr size_t L_KEY = 12;
  constexpr size_t L_KS = 12;
  constexpr size_t TREE_HEIGHT = 9;
  constexpr size_t NumQueries = 1;
  constexpr QueryMode Mode = QueryMode::Stateful;
  constexpr GswSource GswSrc = GswSource::FromExpansion;
  constexpr size_t PlainMod = 15;
  constexpr size_t SmallQWidth = 40;
  constexpr std::array<size_t, 1> CoeffMods = {60};


#elif ACTIVE_CONFIG == CONFIG_POLY4096
  // 256 MB, poly degree 4096
  constexpr size_t PolyDegree = 4096;
  constexpr size_t L_EP = 4;
  constexpr size_t L_KEY = 10;
  constexpr size_t L_KS = 8;
  constexpr size_t TREE_HEIGHT = 9;
  constexpr size_t NumQueries = 1;
  constexpr QueryMode Mode = QueryMode::Stateful;
  constexpr GswSource GswSrc = GswSource::FromExpansion;
  constexpr size_t PlainMod = 46;
  constexpr size_t SmallQWidth = 57;
  constexpr std::array<size_t, 2> CoeffMods = {60, 60};
#else
  #error "Unknown ACTIVE_CONFIG value"
#endif

  // Max bit-width among ciphertext moduli.
  constexpr size_t max_ct_mod_width() {
    size_t w = 0;
    for (size_t i = 0; i < CoeffMods.size(); i++)
      if (CoeffMods[i] > w) w = CoeffMods[i];
    return w;
  }

  // Standard deviation σ of the Gaussian error distribution.
  // Matches SEAL-For-OnionPIR's noise_standard_deviation default.
  // Equivalent width parameter (Spiral/Respire convention): σ * sqrt(2π) ≈ 8.02.
  constexpr double NoiseStdDev = 2.55;

} // namespace DBConsts

// db_coeff_t: type for each NTT coefficient stored in the aligned database.
//   ≤32-bit moduli → uint32_t,  >32-bit → uint64_t.
using db_coeff_t = std::conditional_t<DBConsts::max_ct_mod_width() <= 32,
                                      uint32_t, uint64_t>;

// inter_coeff_t: accumulator for first-dimension matrix multiply & gadget arithmetic.
//   Must be wide enough for  fst_dim_sz × (db_coeff_t × db_coeff_t)  sums.
//   ≤32-bit moduli → uint64_t,  >32-bit → uint128_t.
using inter_coeff_t = std::conditional_t<DBConsts::max_ct_mod_width() <= 32,
                                         uint64_t, uint128_t>;