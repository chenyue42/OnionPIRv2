#pragma once
#include <cstddef>
#include <cstdint>
#include <array>

typedef unsigned __int128 uint128_t;

// Single configuration: 256 MB database, N = 2048, log q = 60, single ct modulus.
// Primes for rns_mods, small_q, and plain_modulus are derived at runtime
// from the bit widths below via utils::generate_ntt_friendly_primes and
// utils::generate_prime.

namespace DBConsts {

  constexpr size_t DB_SIZE_MB   = 1024;
  constexpr size_t PolyDegree   = 2048;
  constexpr size_t L_EP         = 4;   // gadget length for RGSW(data)
  constexpr size_t L_KEY        = 12;  // gadget length for RGSW(sk)
  constexpr size_t L_KS         = 12;  // gadget length for BV key-switching
  constexpr size_t TREE_HEIGHT  = 10;
  constexpr size_t PlainMod     = 13;
  constexpr size_t SmallQWidth  = 40;
  constexpr std::array<size_t, 1> RnsMods = {60};

  // Standard deviation σ of the Gaussian error distribution.
  // Matches SEAL-For-OnionPIR's noise_standard_deviation default.
  constexpr double NoiseStdDev = 2.55;

} // namespace DBConsts

// Single ciphertext modulus, always fits in uint64_t at log q = 60.
using db_coeff_t = uint64_t;

// First-dim matmul accumulator: fst_dim_sz × (db_coeff_t × db_coeff_t) sums.
// At q ≈ 60 bits, needs uint128_t.
using inter_coeff_t = uint128_t;
