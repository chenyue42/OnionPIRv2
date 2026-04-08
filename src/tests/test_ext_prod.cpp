#include "tests.h"

// This is a BFV x GSW example
void PirTest::test_external_product() {
  print_func_name(__FUNCTION__);
  PirParams pir_params;
  const auto params = pir_params.get_seal_params();
  auto context_ = seal::SEALContext(params);
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = seal::Encryptor(context_, secret_key_);
  auto decryptor_ = seal::Decryptor(context_, secret_key_);
  const size_t coeff_count = DBConsts::PolyDegree;

  // ================== Create RGSW(1) ==================
  // We need a GSWEval object. (stores gadget information for further evaluation.)
  const size_t gsw_l = pir_params.get_l();
  const size_t base_log2 = pir_params.get_base_log2();
  GSWEval data_gsw(pir_params, gsw_l, base_log2);

  // Create plaintext for 0 and 1. Each of them will be a RGSW ciphertext of 0 or 1.
  std::vector<uint64_t> one(coeff_count);
  std::vector<uint64_t> zero(coeff_count);
  one[0] = 1;
  zero[0] = 0;

  // The plain_to_gsw function gives us a shortcut to create RGSW ciphertexts.
  // In the actual PIR scheme, we do this by encoding into the packed BFV and then
  // converting them from BFV to RGSW. This conversion process is called "external product".
  // We will test this conversion process in this test.
  GSWCiphertext one_gsw = data_gsw.plain_to_gsw(one, encryptor_, secret_key_);
  GSWCiphertext zero_gsw = data_gsw.plain_to_gsw(zero, encryptor_, secret_key_);

  // ================== Create BFV(a) ==================
  seal::Plaintext a(coeff_count), result;
  const uint64_t t = pir_params.get_plain_mod();
  a[0] = t / 2 + 1; a[1] = t / 2 + 2; a[2] = t / 2 + 3;
  seal::Ciphertext a_encrypted;
  encryptor_.encrypt_symmetric(a, a_encrypted);

  // ================== Test external product ==================
  // external product: BFV(a) * RGSW(1) = BFV(a * 1) = BFV(a)
  seal::Ciphertext ext_prod_result(context_);
  ext_prod_result.resize(2);
  data_gsw.external_product(one_gsw, a_encrypted, ext_prod_result, LogContext::GENERIC);
  evaluator_.transform_from_ntt_inplace(ext_prod_result); // the output is in NTT form. Transform it back.
  decryptor_.decrypt(ext_prod_result, result);
  BENCH_PRINT("BFV(a) * RGSW(1) = " << result.to_string());
  BENCH_PRINT("Noise budget: " << decryptor_.invariant_noise_budget(ext_prod_result));
  PRINT_BAR;

  // external product: BFV(a) * RGSW(0) = BFV(a * 0) = BFV(0)
  data_gsw.external_product(zero_gsw, a_encrypted, ext_prod_result, LogContext::GENERIC);
  evaluator_.transform_from_ntt_inplace(ext_prod_result);
  decryptor_.decrypt(ext_prod_result, result);
  BENCH_PRINT("BFV(a) * RGSW(0) = " << result.to_string());
  BENCH_PRINT("Noise budget: " << decryptor_.invariant_noise_budget(ext_prod_result));
  PRINT_BAR;

  // external product: BFV(a) * RGSW(1) for 100 times
  TIME_START("External product");
  for (size_t i = 0; i < 100; i++) {
    data_gsw.external_product(one_gsw, a_encrypted, ext_prod_result, LogContext::GENERIC);
  }
  TIME_END("External product");

  END_EXPERIMENT();
  PRINT_RESULTS();
}
