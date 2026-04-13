#pragma once
#include <cstdint>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal RLWE types to replace seal::Ciphertext / seal::SecretKey / seal::Plaintext.
// All polynomials are stored as flat uint64_t arrays in coefficient order.
// For RNS-multi-modulus contexts the limbs are concatenated: mod0 || mod1 || ...
// ---------------------------------------------------------------------------

struct RlweCt {
    std::vector<uint64_t> c0; // first polynomial (size = N * rns_mod_cnt)
    std::vector<uint64_t> c1; // second polynomial (size = N * rns_mod_cnt)
    bool ntt_form = false;

    uint64_t       *data(size_t i)       { return i == 0 ? c0.data() : c1.data(); }
    const uint64_t *data(size_t i) const { return i == 0 ? c0.data() : c1.data(); }
    bool &is_ntt_form() { return ntt_form; }

    // Resize both polynomials to n elements (n = N * rns_mod_cnt).
    void resize(size_t n) { c0.assign(n, 0); c1.assign(n, 0); }

    // Number of elements per polynomial (0 if not yet allocated).
    size_t poly_size() const { return c0.size(); }
};

// Ternary secret key stored in NTT form.
// data has N * rns_mod_cnt elements: values in {0, 1, q-1} reduced mod each prime.
struct RlweSk {
    std::vector<uint64_t> data;
    size_t poly_size() const { return data.size(); }
};

// Plaintext polynomial.
// data has N elements in [0, t).
struct RlwePt {
    std::vector<uint64_t> data;
    size_t coeff_count() const { return data.size(); }
};
