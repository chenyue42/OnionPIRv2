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
#define CONFIG_SECURE         4   // 128-bit security

#define ACTIVE_CONFIG  CONFIG_SECURE

namespace DBConsts {
  
  constexpr size_t DB_SIZE_MB = 128;

#if ACTIVE_CONFIG == CONFIG_SINGLE_MOD_56
  // 256 MB, single ct mod, log q = 56
  constexpr size_t PolyDegree = 2048;
  constexpr size_t L_EP = 5;
  constexpr size_t L_KEY = 12;
  constexpr size_t L_KS = 8;
  constexpr size_t TREE_HEIGHT = 9;
  constexpr size_t PlainMod = 15;
  constexpr size_t SmallQWidth = 28;
  constexpr std::array<size_t, 2> CoeffMods = {56, 60};

#elif ACTIVE_CONFIG == CONFIG_TWO_MOD_56
  // 256 MB, two ct mods, log q = 56
  constexpr size_t PolyDegree = 2048;
  constexpr size_t L_EP = 5;
  constexpr size_t L_KEY = 12;
  constexpr size_t L_KS = 8;
  constexpr size_t TREE_HEIGHT = 9;
  constexpr size_t PlainMod = 14;
  constexpr size_t SmallQWidth = 27;
  constexpr std::array<size_t, 3> CoeffMods = {28, 28, 60};

#elif ACTIVE_CONFIG == CONFIG_SINGLE_MOD_60
  // 256 MB, single ct mod, log q = 60
  constexpr size_t PolyDegree = 2048;
  constexpr size_t L_EP = 5;
  constexpr size_t L_KEY = 9;
  constexpr size_t L_KS = 8;
  constexpr size_t TREE_HEIGHT = 9;
  constexpr size_t PlainMod = 16;
  constexpr size_t SmallQWidth = 28;
  constexpr std::array<size_t, 2> CoeffMods = {60, 61};

#elif ACTIVE_CONFIG == CONFIG_POLY4096
  // 256 MB, poly degree 4096
  constexpr size_t PolyDegree = 4096;
  constexpr size_t L_EP = 4;
  constexpr size_t L_KEY = 10;
  constexpr size_t L_KS = 8;
  constexpr size_t TREE_HEIGHT = 9;
  constexpr size_t PlainMod = 46;
  constexpr size_t SmallQWidth = 57;
  constexpr std::array<size_t, 3> CoeffMods = {60, 60, 60};

#elif ACTIVE_CONFIG == CONFIG_SECURE
  // 256 MB, single ct mod, log q = 56
  constexpr size_t PolyDegree = 2048;
  constexpr size_t L_EP = 4;
  constexpr size_t L_KEY = 8;
  constexpr size_t L_KS = 12;
  constexpr size_t TREE_HEIGHT = 9;
  constexpr size_t PlainMod = 14;
  constexpr size_t SmallQWidth = 55;
  constexpr std::array<size_t, 2> CoeffMods = {60, 60};

#else
  #error "Unknown ACTIVE_CONFIG value"
#endif

  // Max bit-width among non-special (ciphertext) moduli.
  // The last entry in CoeffMods is the special modulus used by SEAL.
  constexpr size_t max_ct_mod_width() {
    size_t w = 0;
    for (size_t i = 0; i + 1 < CoeffMods.size(); i++)
      if (CoeffMods[i] > w) w = CoeffMods[i];
    return w;
  }

  // Standard deviation σ of the Gaussian error distribution.
  // Matches SEAL-For-OnionPIR's noise_standard_deviation default.
  // Equivalent width parameter (Spiral/Respire convention): σ * sqrt(2π) ≈ 8.02.
  constexpr double NoiseStdDev = 3.2;

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