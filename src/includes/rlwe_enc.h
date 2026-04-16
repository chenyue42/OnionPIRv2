#pragma once
#include "rlwe.h"
#include <cstdint>
#include <random>

// ---------------------------------------------------------------------------
// Single-modulus RLWE encryption primitives.
// All functions operate on a single prime q (rns_mod_cnt == 1).
// Secret keys are always stored in NTT form.
// ---------------------------------------------------------------------------

// Sample a fresh ternary secret key and convert it to NTT form.
RlweSk gen_secret_key(size_t N, uint64_t q, std::mt19937_64 &rng);

// Symmetric encryption of zero under secret key sk:
//   c1 = a  (uniform in [0, q))
//   c0 = -(a*s + e) mod q   where e ~ N(0, sigma²)
// If ntt_form == true, both c0 and c1 are returned in NTT form; otherwise
// both are in coefficient form.
void encrypt_zero(const RlweSk &sk, size_t N, uint64_t q, double sigma,
                  std::mt19937_64 &rng, RlweCt &ct, bool ntt_form = false);

// Decrypt a single-modulus ciphertext into a plaintext polynomial modulo t.
//   phase[i] = (c0 + c1 * s)[i]          in [0, q)
//   pt[i]    = round(phase[i] * t / q)   mod t
// ct may be in either NTT or coefficient form (determined by ct.ntt_form).
void decrypt(const RlweCt &ct, const RlweSk &sk, size_t N, uint64_t q,
             uint64_t t, RlwePt &pt);

// ---------------------------------------------------------------------------
// RlweCt arithmetic (single-modulus). All operands must be the same NTT form;
// caller upholds the invariant (no runtime check on the hot path).
// ---------------------------------------------------------------------------

void rlwe_add_inplace(RlweCt &a, const RlweCt &b, uint64_t q);
void rlwe_sub_inplace(RlweCt &a, const RlweCt &b, uint64_t q);
void rlwe_add(const RlweCt &a, const RlweCt &b, RlweCt &c, uint64_t q);
void rlwe_sub(const RlweCt &a, const RlweCt &b, RlweCt &c, uint64_t q);

// NTT forward/inverse on both polynomials. Updates ct.ntt_form.
void rlwe_ntt_fwd_inplace(RlweCt &ct, uint64_t q, size_t N);
void rlwe_ntt_inv_inplace(RlweCt &ct, uint64_t q, size_t N);

// Negacyclic shift by `index` of each polynomial (coefficient form only).
// dst may alias src.
void rlwe_shift(const RlweCt &src, RlweCt &dst, size_t index, uint64_t q, size_t N);
