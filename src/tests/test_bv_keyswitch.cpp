#include "tests.h"
#include "bv_keyswitch.h"
#include <random>

// ============================================================================
// Unit test: signed gadget decomposition
// ============================================================================
static void test_signed_decompose() {
  std::cout << "--- test_signed_decompose ---\n";

  PirParams pir_params;
  const size_t q_bits = pir_params.get_ct_mod_width(); // e.g. 56
  const size_t base_log2 = (q_bits + bvks::L_KS - 1) / bvks::L_KS;
  const uint64_t B = uint64_t(1) << base_log2;

  // Get the actual modulus value from SEAL params
  auto context = pir_params.get_context();
  const auto &ctx_data = *context.key_context_data();
  const uint64_t q = ctx_data.parms().coeff_modulus()[0].value();
  const uint64_t half_q = q >> 1;

  std::mt19937_64 rng(42);
  constexpr size_t num_tests = 10000;
  size_t max_digit_mag = 0;

  for (size_t t = 0; t < num_tests; ++t) {
    uint64_t val = rng() % q;
    uint64_t digits[bvks::L_KS];
    bvks::signed_gadget_decompose(val, base_log2, q, digits, bvks::L_KS);

    // 1. Check reconstruction: Σ digits[i] * B^i ≡ val (mod q)
    uint128_t reconstructed = 0;
    uint128_t Bi = 1;
    for (size_t i = 0; i < bvks::L_KS; ++i) {
      reconstructed = (reconstructed + (static_cast<uint128_t>(digits[i]) * Bi) % q) % q;
      Bi = (Bi * B) % q;
    }
    if (static_cast<uint64_t>(reconstructed) != val) {
      std::cout << "FAIL: reconstruction mismatch at val=" << val
                << " got=" << static_cast<uint64_t>(reconstructed) << "\n";
      return;
    }

    // 2. Check that each digit is small (signed magnitude ≤ B/2)
    for (size_t i = 0; i < bvks::L_KS; ++i) {
      // Interpret digit mod q as signed: if > q/2, it's negative
      uint64_t mag = (digits[i] > half_q) ? (q - digits[i]) : digits[i];
      if (mag > max_digit_mag) max_digit_mag = mag;
      if (mag > B / 2) {
        std::cout << "FAIL: digit " << i << " has magnitude " << mag
                  << " > B/2=" << (B / 2) << " at val=" << val << "\n";
        return;
      }
    }
  }

  std::cout << "PASS: " << num_tests << " random values reconstructed correctly\n";
  std::cout << "  base_log2=" << base_log2 << ", B=" << B
            << ", max digit magnitude=" << max_digit_mag << " (B/2=" << (B / 2) << ")\n";
}

// ============================================================================
// Unit test: BV key-switching correctness
// ============================================================================
void PirTest::test_bv_keyswitch() {
  test_signed_decompose();
  print_func_name(__FUNCTION__);

  PirParams pir_params;
  auto context = pir_params.get_context();
  auto keygen = seal::KeyGenerator(context);
  auto sk = keygen.secret_key();
  seal::PublicKey pk;
  keygen.create_public_key(pk);
  auto encryptor = seal::Encryptor(context, pk);
  auto decryptor = seal::Decryptor(context, sk);
  auto evaluator = seal::Evaluator(context);
  constexpr size_t N = DBConsts::PolyDegree;

  seal::Plaintext plain(N);
  plain[0] = 1;
  plain[1] = 2;
  plain[2] = 3;
  plain[10] = 10;
  plain[11] = 11;
  plain[12] = 12;

  size_t galois_k = 513;

  seal::Ciphertext ct;
  encryptor.encrypt(plain, ct);
  std::cout << "noise budget: " << decryptor.invariant_noise_budget(ct) << " bits\n" << std::flush;

  // Decrypt to verify
  seal::Plaintext dec_plain;
  decryptor.decrypt(ct, dec_plain);
  std::cout << "Decrypted: " << dec_plain.to_string().substr(0, 50) << "\n" << std::flush;

  // Test with SEAL's apply_galois for comparison
  std::vector<uint32_t> galois_elts = {static_cast<uint32_t>(galois_k)};
  seal::GaloisKeys seal_galois_keys;
  keygen.create_galois_keys(galois_elts, seal_galois_keys);
  seal::Ciphertext ct_seal = ct;
  evaluator.apply_galois_inplace(ct_seal, galois_k, seal_galois_keys);
  std::cout << "SEAL galois noise budget: " << decryptor.invariant_noise_budget(ct_seal) << " bits\n" << std::flush;
  seal::Plaintext dec_seal;
  decryptor.decrypt(ct_seal, dec_seal);
  std::cout << "SEAL galois: " << dec_seal.to_string().substr(0, 50) << "\n" << std::flush;

  // Now test BV key-switching
  std::mt19937_64 rng(std::random_device{}());
  auto bv_ksk = bvks::gen_bv_ks_key(pir_params, sk, static_cast<uint32_t>(galois_k), rng);

  seal::Ciphertext ct_bv = ct;
  bvks::bv_apply_galois_inplace(ct_bv, galois_k, bv_ksk, pir_params);
  std::cout << "BV galois noise budget: " << decryptor.invariant_noise_budget(ct_bv) << " bits\n" << std::flush;
  seal::Plaintext dec_bv;
  decryptor.decrypt(ct_bv, dec_bv);
  std::cout << "BV galois: " << dec_bv.to_string().substr(0, 50) << "\n" << std::flush;

  // Check coefficients
  bool match = (dec_seal.to_string() == dec_bv.to_string());
  if (match) std::cout << "PASS: BV key-switch matches SEAL\n";
  else std::cout << "FAIL: BV key-switch does not match SEAL\n";
}
